#!/usr/bin/env python3
"""Assemble bounded authoring fragments without parsing or rewriting public bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ALLOWED_OUTPUTS = {
    "Autostream-Contracts": {"openapi/control-api.yaml", "schemas/discord-bot-start-job-request.schema.json"},
    "Autostream-ControlPanel": {"release/install-autostream-control-panel"},
    "Autostream-DiscordBot": {"release/install-autostream-discord-bot"},
    "Autostream-Encoder-Recorder": {"release/install-autostream-encoder-recorder"},
    "Autostream-Observability": {"release/install-autostream-observability"},
    "Autostream-Updater": {"install/install-autostream-updater-agent", "install/install-autostream-local-executor"},
    "Autostream-Worker": {"release/install-autostream-worker"},
}
MANIFEST = "authoring/artifact-layout.json"


def physical_lines(data: bytes) -> int:
    return data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))


def safe_path(path: object) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise ValueError("invalid artifact path")
    value = PurePosixPath(path)
    if value.is_absolute() or any(p in {".", "..", ""} for p in path.split("/")) or ":" in path:
        raise ValueError("artifact path must be repository relative")
    return path


class Source:
    """One immutable Git tree, or an explicit authoring working directory."""

    def __init__(self, root: Path, tree: str | None = None):
        self.root = root.resolve()
        self.tree = tree
        self.entries = None
        if tree is not None:
            if not re.fullmatch(r"[0-9a-f]{40}", tree):
                raise ValueError("a full immutable tree/commit SHA is required")
            listing = self.git("ls-tree", "-rz", "--full-tree", tree)
            self.entries = {}
            for entry in listing.split(b"\0"):
                if not entry:
                    continue
                metadata, name = entry.split(b"\t", 1)
                mode, kind, oid = metadata.decode("ascii").split()
                self.entries[name.decode("utf-8")] = (mode, kind, oid)
            if not self.entries:
                raise ValueError("empty candidate tree")

    def git(self, *args: str) -> bytes:
        process = subprocess.run(["git", "-C", str(self.root), *args],
                                 capture_output=True, timeout=60, check=False)
        if process.returncode:
            raise ValueError("candidate Git object could not be read")
        return process.stdout

    def read(self, name: str) -> bytes:
        safe_path(name)
        if self.entries is not None:
            entry = self.entries.get(name)
            if entry is None or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
                raise ValueError("missing or non-regular candidate source")
            return self.git("cat-file", "blob", entry[2])
        path = self.root / name
        if self.root not in path.resolve().parents:
            raise ValueError("source escapes repository")
        for parent in [path, *path.parents]:
            if parent == self.root:
                break
            if parent.is_symlink():
                raise ValueError("authoring source cannot be a symbolic link")
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ValueError("missing authoring source") from exc

    def fragments(self) -> set[str]:
        if self.entries is not None:
            return {path for path in self.entries if path.startswith("authoring/") and path.endswith(".inc")}
        return {path.relative_to(self.root).as_posix() for path in (self.root / "authoring").rglob("*.inc")}


def assemble(source: Source, repository: str) -> dict[str, bytes]:
    allowed = ALLOWED_OUTPUTS.get(repository)
    if allowed is None:
        raise ValueError("repository has no approved generated artifacts")
    manifest = json.loads(source.read(MANIFEST).decode("utf-8"))
    if manifest.get("format_version") != 1 or manifest.get("repository") != repository:
        raise ValueError("invalid authoring manifest identity")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("empty artifact inventory")
    results, used = {}, set()
    for artifact in artifacts:
        output = safe_path(artifact["output"])
        if output not in allowed or output in results:
            raise ValueError("unapproved or duplicate output")
        names = artifact.get("fragments")
        if not isinstance(names, list) or not names:
            raise ValueError("empty fragment inventory")
        parts = []
        for name in names:
            safe_path(name)
            if not name.startswith("authoring/") or not name.endswith(".inc"):
                raise ValueError("fragment must be an authoring source")
            if name in used or name in allowed or name == MANIFEST:
                raise ValueError("duplicate, cyclic or self-referential fragment")
            used.add(name)
            data = source.read(name)
            data.decode("utf-8-sig")
            limit = 800 if PurePosixPath(name[:-4]).suffix in {".js", ".ts", ".tsx", ".mts", ".mjs", ".cjs", ".cts", ".jsx"} else 1000
            if not data or physical_lines(data) > limit:
                raise ValueError("empty or oversized authoring source")
            parts.append(data)
        results[output] = b"".join(parts)
    if set(results) != allowed or used != source.fragments():
        raise ValueError("missing or unlisted artifact/fragment")
    return results


def verify(source: Source, repository: str) -> list[dict]:
    results = []
    for output, data in assemble(source, repository).items():
        if source.read(output) != data:
            raise ValueError("public artifact differs from raw authoring bytes: " + output)
        results.append({"path": output, "bytes": len(data), "physical_lines": physical_lines(data),
                        "sha256": hashlib.sha256(data).hexdigest(), "raw_bytes_equal": True})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, choices=sorted(ALLOWED_OUTPUTS))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--tree", help="full candidate tree or commit SHA; no worktree fallback")
    parser.add_argument("--write", action="store_true", help="regenerate public working files")
    args = parser.parse_args()
    if args.write and args.tree:
        parser.error("cannot write an immutable candidate tree")
    source = Source(args.root, args.tree)
    if args.write:
        for output, data in assemble(source, args.repository).items():
            (source.root / output).write_bytes(data)
    print(json.dumps({"repository": args.repository, "tree": args.tree,
                      "artifacts": verify(source, args.repository)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
