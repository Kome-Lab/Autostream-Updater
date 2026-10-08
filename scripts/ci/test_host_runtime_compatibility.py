"""Exercise the real installer and release-verifier compatibility predicates."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MINIMUM_PANEL_VERSION = "v2.0.0"
JQ_INVOCATION = re.compile(r"jq -e\b[^']*'([^']+)'", re.DOTALL)


def compatibility_guards() -> list[tuple[str, str, bool]]:
    guards = []
    for installer in ("updater-agent", "local-executor"):
        path = REPOSITORY_ROOT / "authoring" / (
            "install-autostream-" + installer
        ) / "artifact-verification.sh.inc"
        programs = [
            program for program in JQ_INVOCATION.findall(path.read_text("utf-8"))
            if ".minimum_panel_version" in program
        ]
        if len(programs) != 1:
            raise AssertionError(f"expected one manifest guard in {path.name}")
        guards.append((installer, programs[0], False))
    path = REPOSITORY_ROOT / "scripts/ci/verify-release-bundles.sh"
    programs = [
        program for program in JQ_INVOCATION.findall(path.read_text("utf-8"))
        if ".minimum_panel_version" in program
    ]
    if len(programs) != 2:
        raise AssertionError("expected outer and inner release manifest guards")
    guards.append(("release-outer", programs[0], True))
    guards.append(("release-inner", programs[1], False))
    return guards


def artifact_manifest(version: str, minimum_panel: str) -> dict:
    root = f"autostream-host-agent_{version}_linux_amd64"
    return {
        "schema_version": 1,
        "component": "host-agent",
        "source_version": version,
        "commit": "a" * 40,
        "build_date": "2026-10-08T00:00:00Z",
        "platform": {"os": "linux", "arch": "amd64"},
        "archive": {"name": root + ".tar.gz", "root": root},
        "compatibility": {
            "minimum_agent_version": None,
            "minimum_panel_version": minimum_panel,
            "rollback_compatible": True,
            "database_schema": "none",
        },
    }


def release_manifest(version: str, minimum_panel: str) -> dict:
    return {
        "schema_version": 1,
        "release_id": version,
        "channel": "host-agent",
        "commit": "a" * 40,
        "agent_version": version,
        "protocol_version": 2,
        "observe_only": False,
        "local_executor_protocol_version": 2,
        "local_executor_mutation_protocol_version": 2,
        "local_executor_mutation_enabled": True,
        "local_executor_mutation_requires_root_policy": True,
        "recovery_protocol_version": 2,
        "minimum_panel_version": minimum_panel,
        "artifacts": [
            {
                "os": "linux", "arch": arch,
                "name": f"autostream-host-agent_{version}_linux_{arch}.tar.gz",
                "size": 4096, "sha256": "b" * 64,
            }
            for arch in ("amd64", "arm64")
        ],
    }


class HostRuntimeManifestCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.jq = os.environ.get("JQ_EXECUTABLE") or shutil.which("jq")
        if not cls.jq:
            raise RuntimeError("jq is required to execute the existing manifest guards")
        cls.guards = compatibility_guards()

    def evaluate(self, program: str, payload: dict, version: str) -> bool:
        root = f"autostream-host-agent_{version}_linux_amd64"
        result = subprocess.run(
            [
                self.jq, "-e", "--arg", "version", version,
                "--arg", "minimum_panel_version", MINIMUM_PANEL_VERSION,
                "--arg", "commit", "a" * 40, "--arg", "arch", "amd64",
                "--arg", "archive_name", root + ".tar.gz",
                "--arg", "artifact_id", root,
                "--arg", "archive", root + ".tar.gz", "--arg", "root", root,
                program,
            ],
            input=json.dumps(payload), capture_output=True, text=True,
            encoding="utf-8", timeout=10, check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_independent_panel_floor_is_accepted(self) -> None:
        for version in ("v2.0.0", "v2.0.1", "v2.1.0"):
            for name, program, outer in self.guards:
                with self.subTest(version=version, guard=name):
                    payload = (release_manifest if outer else artifact_manifest)(
                        version, MINIMUM_PANEL_VERSION,
                    )
                    self.assertTrue(self.evaluate(program, payload, version))

    def test_unreviewed_panel_floors_are_rejected(self) -> None:
        for floor in ("", "v1.9.11", "v2.0.0-beta", "v2.0.1", "v9.0.0"):
            for name, program, outer in self.guards:
                with self.subTest(floor=floor, guard=name):
                    payload = (release_manifest if outer else artifact_manifest)(
                        "v2.0.1", floor,
                    )
                    self.assertFalse(self.evaluate(program, payload, "v2.0.1"))

    def test_source_version_below_supported_floor_is_rejected(self) -> None:
        for name, program, outer in self.guards:
            with self.subTest(guard=name):
                payload = (release_manifest if outer else artifact_manifest)(
                    "v1.9.11", MINIMUM_PANEL_VERSION,
                )
                self.assertFalse(self.evaluate(program, payload, "v1.9.11"))

    def test_source_and_protocol_guards_remain_closed(self) -> None:
        for name, program, outer in self.guards:
            fields = (("agent_version", "v2.0.0"), ("protocol_version", 1)) if outer else (
                ("source_version", "v2.0.0"),
            )
            for field, value in fields:
                with self.subTest(guard=name, field=field):
                    payload = (release_manifest if outer else artifact_manifest)(
                        "v2.0.1", MINIMUM_PANEL_VERSION,
                    )
                    altered = copy.deepcopy(payload)
                    altered[field] = value
                    self.assertFalse(self.evaluate(program, altered, "v2.0.1"))


class HostRuntimeCompatibilitySourceTests(unittest.TestCase):
    def setUp(self) -> None:
        import host_runtime_compatibility

        self.reader = host_runtime_compatibility
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = (self.reader.AUTHORITY_PATH, *self.reader.INSTALLER_PATHS)
        for relative in self.paths:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPOSITORY_ROOT / relative).read_bytes())

    def test_single_compiled_floor_is_independent_of_source_version(self) -> None:
        for version in ("v2.0.0", "v2.0.1", "v2.1.0"):
            with self.subTest(version=version):
                self.assertEqual(
                    self.reader.minimum_panel_version(self.root, version),
                    MINIMUM_PANEL_VERSION,
                )

    def test_ambiguous_or_runtime_overridable_authority_is_rejected(self) -> None:
        path = self.root / self.reader.AUTHORITY_PATH
        original = path.read_text("utf-8")
        for alteration in (
            original.replace("const MinimumControlPanelVersion", "var MinimumControlPanelVersion"),
            original + '\nconst MinimumControlPanelVersion string = "v2.0.0"\n',
            original + '\nfunc runtimeFloor() string { return "v2.0.0" }\n',
            original.replace('"v2.0.0"', '"v2.0.0-beta"'),
            original.replace('"v2.0.0"', '"v02.0.0"'),
        ):
            path.write_text(alteration, "utf-8")
            with self.assertRaises(ValueError):
                self.reader.minimum_panel_version(self.root, "v2.0.1")
        path.write_text(original, "utf-8")

    def test_authored_floor_drift_and_unwired_guard_are_rejected(self) -> None:
        for relative in self.reader.INSTALLER_PATHS:
            path = self.root / relative
            original = path.read_text("utf-8")
            for alteration in (
                original.replace('MINIMUM_PANEL_VERSION="v2.0.0"', 'MINIMUM_PANEL_VERSION="v2.0.1"'),
                original + '\nMINIMUM_PANEL_VERSION="v2.0.0"\n',
                original.replace(".minimum_panel_version == $minimum_panel_version", ".minimum_panel_version == $version"),
            ):
                path.write_text(alteration, "utf-8")
                with self.assertRaises(ValueError):
                    self.reader.minimum_panel_version(self.root, "v2.0.1")
            path.write_text(original, "utf-8")

    def test_unsupported_or_nonstable_source_version_is_rejected(self) -> None:
        for version in ("v1.9.11", "dev", "", "v2.0.1-beta", "v02.0.1", "v2.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.reader.minimum_panel_version(self.root, version)


if __name__ == "__main__":
    unittest.main()
