#!/usr/bin/env python3
"""Require complete Go JSON evidence; never infer execution from source discovery."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys


TEST_ID = re.compile(r"Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_.=+-]+)*\Z")
DECLARATION = re.compile(r"^func\s+(Test[A-Za-z0-9_]+)\s*\(", re.MULTILINE)
ACTIONS = {"start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip", "build-output", "build-fail"}


def verify(evidence_directory, source_root, expected_lists, exact_subtests=False):
    errors = []
    expected = []
    for path in expected_lists:
        try:
            expected.extend(line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())
        except OSError:
            errors.append(f"expected-test list is missing or unreadable: {path.name}")
    if not expected:
        errors.append("expected-test list is empty")
    if len(set(expected)) != len(expected):
        errors.append("expected-test list contains duplicates")
    if any(not TEST_ID.fullmatch(test) for test in expected):
        errors.append("expected-test list contains an invalid exact test ID")
    expected_set = set(expected)
    required_parents = {test.split("/", 1)[0] for test in expected}
    if not required_parents.issubset(expected_set):
        errors.append("each required subtest must also declare its parent in the expected set")

    declarations = Counter()
    if not source_root.is_dir():
        errors.append("source root is missing")
    else:
        for path in source_root.rglob("*_test.go"):
            declarations.update(DECLARATION.findall(path.read_text(encoding="utf-8-sig")))
        for parent in sorted(required_parents):
            if declarations[parent] != 1:
                errors.append(f"required parent must have exactly one source declaration: {parent} ({declarations[parent]})")

    evidence_files = sorted(evidence_directory.glob("*.json")) if evidence_directory.is_dir() else []
    if not evidence_files:
        errors.append("no Go test JSON evidence files were produced")
    tests = defaultdict(Counter)
    packages = defaultdict(Counter)
    completed_packages = set()
    observed_required = set()
    for path in evidence_files:
        file_packages = set()
        try:
            with path.open(encoding="utf-8-sig") as stream:
                for line_number, line in enumerate(stream, 1):
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        errors.append(f"invalid or truncated JSON: {path.name}:{line_number}")
                        continue
                    if not isinstance(event, dict):
                        errors.append(f"invalid Go event object: {path.name}:{line_number}")
                        continue
                    action, package, test = event.get("Action"), event.get("Package"), event.get("Test", "")
                    if not isinstance(action, str) or action not in ACTIONS:
                        errors.append(f"unknown or cancelled Go action: {path.name}:{line_number}")
                        continue
                    if action in {"fail", "skip", "build-fail"}:
                        # Output can contain credentials. Report only event location/class.
                        errors.append(f"Go {action} event: {path.name}:{line_number}")
                    if action in {"build-output", "build-fail"}:
                        continue
                    if not isinstance(package, str) or not package or not isinstance(test, str):
                        errors.append(f"missing package or invalid test identity: {path.name}:{line_number}")
                        continue
                    file_packages.add(package)
                    package_run = (path.name, package)
                    if package_run in completed_packages:
                        errors.append(f"event after package completion: {path.name}:{line_number}")
                    if test:
                        tests[(package, test)][action] += 1
                        if test.split("/", 1)[0] in required_parents:
                            observed_required.add(test)
                    else:
                        packages[package_run][action] += 1
                        if action == "pass":
                            completed_packages.add(package_run)
                            if any(counts["run"] != 1 or counts["pass"] != 1 for (name, _), counts in tests.items() if name == package):
                                errors.append(f"package completed with incomplete or duplicate tests: {path.name}:{line_number}")
        except (OSError, UnicodeError):
            errors.append(f"evidence file is unreadable: {path.name}")
        if not file_packages:
            errors.append(f"no package execution was observed: {path.name}")

    for (filename, package), counts in packages.items():
        if counts["start"] != 1 or counts["pass"] != 1:
            errors.append(f"package execution is incomplete or duplicated: {filename}: {package}")
    for (package, test), counts in tests.items():
        if counts["run"] != 1 or counts["pass"] != 1:
            errors.append(f"test execution is incomplete or duplicated: {test}")
        runs = [counts for (_, name), counts in packages.items() if name == package]
        if not runs or any(counts["start"] != 1 or counts["pass"] != 1 for counts in runs):
            errors.append(f"test has no complete package execution: {test}")
    for test in sorted(expected_set):
        matches = [counts for (_, name), counts in tests.items() if name == test]
        if len(matches) != 1 or matches[0]["run"] != 1 or matches[0]["pass"] != 1:
            errors.append(f"required exact test ID did not run and pass once: {test}")
    if exact_subtests and observed_required != expected_set:
        for test in sorted(observed_required - expected_set):
            errors.append(f"unlisted subtest in a required parent: {test}")
    return sorted(set(errors)), {
        "required_ids": len(expected_set),
        "observed_required_ids": len(observed_required),
        "observed_test_ids": len(tests),
        "packages": len({package for _, package in packages}),
        "package_executions": len(packages),
        "evidence_files": len(evidence_files),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exact-subtests", action="store_true", help="require the complete ID set below each required parent, including every child")
    parser.add_argument("evidence_directory", type=Path)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("expected_lists", type=Path, nargs="+")
    args = parser.parse_args()
    errors, summary = verify(args.evidence_directory, args.source_root, args.expected_lists, args.exact_subtests)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
