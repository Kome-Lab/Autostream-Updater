#!/usr/bin/env python3
"""Reproduce the fixed Docker diagnostic guard without changing GITHUB_SHA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


HISTORICAL_SHA = "ca8bc7a696f14efd7c16d5f26b7895ac56ad7262"
WORKFLOW_PATH = ".github/workflows/docker-restart-diagnostics.yml"
WORKFLOW_SHA256 = "143aa099641e53f6908debae1b60fb4ffe0fcff1cffae2bcbdec39bc3a16fa14"
CORE_CHECKS = (
    "commit_ids", "checkout_sha", "workflow_sha", "baseline_commits",
    "baseline_ancestry", "previous_ancestry", "base_ancestry", "current_ancestry",
    "current_parent", "baseline_delta", "previous_delta", "base_delta",
    "current_delta", "application_delta", "historical_ci_blob", "current_ci_blob", "worktree_clean",
)


def git(root, *args):
    process = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if process.returncode:
        raise ValueError("git_query_failed")
    return process.stdout


def historical_guard_source(root):
    workflow = git(root, "show", HISTORICAL_SHA + ":" + WORKFLOW_PATH)
    if hashlib.sha256(workflow).hexdigest() != WORKFLOW_SHA256:
        raise ValueError("historical_workflow_bytes")
    text = workflow.decode("utf-8")
    prefix = "          python3 - <<'PY'\n"
    begin = text.index(prefix) + len(prefix)
    end = text.index("          PY\n", begin)
    lines = text[begin:end].splitlines(keepends=True)
    if not lines or any(line.strip() and not line.startswith("          ") for line in lines):
        raise ValueError("historical_guard_boundary")
    return "".join(line[10:] if line.startswith("          ") else line for line in lines)


def load_historical_guard(root):
    source = historical_guard_source(root)
    namespace = {"__name__": "fixed_historical_guard"}
    exec(compile(source, WORKFLOW_PATH + "@" + HISTORICAL_SHA, "exec"), namespace)
    if namespace["CHECKS"] != CORE_CHECKS:
        raise ValueError("historical_guard_denominator")
    return namespace


def execution_identity(source_root, workflow_root, trigger_sha, workflow_sha):
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (trigger_sha, workflow_sha)):
        raise ValueError("execution_commit_ids")
    source_root, workflow_root = source_root.resolve(), workflow_root.resolve()
    if source_root == workflow_root or source_root in workflow_root.parents or workflow_root in source_root.parents:
        raise ValueError("checkout_isolation")
    if git(source_root, "rev-parse", "HEAD").strip().decode() != HISTORICAL_SHA:
        raise ValueError("historical_checkout_sha")
    if git(workflow_root, "rev-parse", "HEAD").strip().decode() != workflow_sha:
        raise ValueError("execution_workflow_checkout_sha")
    if trigger_sha != workflow_sha:
        raise ValueError("execution_trigger_workflow_sha")
    for value in (trigger_sha, workflow_sha):
        if git(workflow_root, "rev-parse", "--verify", value + "^{commit}").strip().decode() != value:
            raise ValueError("execution_commit_object")
    workflow_sources = []
    for path in (WORKFLOW_PATH, "scripts/ci/historical_diagnostic_guard.py", "scripts/ci/check_historical_diagnostic_fixtures.py"):
        expected = git(workflow_root, "show", workflow_sha + ":" + path)
        actual = workflow_root / path
        if actual.is_symlink() or actual.read_bytes() != expected:
            raise ValueError("execution_workflow_source_bytes")
        workflow_sources.append({"path": path, "sha256": hashlib.sha256(expected).hexdigest()})
    return {"source_sha": HISTORICAL_SHA, "historical_workflow_sha": HISTORICAL_SHA,
            "trigger_sha": trigger_sha, "workflow_sha": workflow_sha, "workflow_sources": workflow_sources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--workflow-root", type=Path, required=True)
    args = parser.parse_args()
    evidence = Path(os.environ["RUNNER_TEMP"]) / "docker-restart-diagnostics"
    evidence.mkdir(parents=True, exist_ok=True)
    checks = dict.fromkeys(CORE_CHECKS, "not_run")
    report = {"purpose": "fixed_historical_diagnostic_reproduction", "status": "fail", "failure": "none",
              "source_sha": HISTORICAL_SHA, "historical_workflow_sha": HISTORICAL_SHA,
              "trigger_sha": os.environ["GITHUB_SHA"], "workflow_sha": os.environ["DIAGNOSTIC_WORKFLOW_SHA"],
              "checks": checks, "execution_identity": "not_run"}
    original = Path.cwd()
    try:
        report.update(execution_identity(args.source_root, args.workflow_root,
                                         os.environ["GITHUB_SHA"], os.environ["DIAGNOSTIC_WORKFLOW_SHA"]))
        report["execution_identity"] = "pass"
        guard = load_historical_guard(args.source_root)
        os.chdir(args.source_root)
        try:
            guard["verify_source"](
                "794d0cd69dd1b3ca130101f7769aaf8ac1274ac8", "b7ea27bb503bf259abeb34652b41cce9351884d2",
                "b123456f33f0c61974bb3300dfd59b909646404a", "2cc44bcbad857a103aa58cb30e89f97dcda8ffda",
                HISTORICAL_SHA, HISTORICAL_SHA,
                "7780fa3a21e20ba304d2301f9dde3b7e97ec79d1", "1236ba11843261deec085cb7396f1276e41f83d2", checks,
            )
        except guard["GuardFailure"] as error:
            raise ValueError(str(error)) from error
        report["status"] = "pass"
    except ValueError as error:
        allowed = set(CORE_CHECKS) | {"git_query_failed", "historical_workflow_bytes", "historical_guard_boundary",
                    "historical_guard_denominator", "execution_commit_ids", "checkout_isolation",
                    "historical_checkout_sha", "execution_workflow_checkout_sha", "execution_trigger_workflow_sha",
                    "execution_commit_object", "execution_workflow_source_bytes"}
        report["failure"] = str(error) if str(error) in allowed else "guard_internal"
    except Exception:
        report["failure"] = "guard_internal"
    finally:
        os.chdir(original)
    (evidence / "source-guard.json").write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    print("historical diagnostic source guard: " + report["status"])
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
