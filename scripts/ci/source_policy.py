"""Physical-line census policy used for both sides of Bundle 9 revision 009.

This module reads bytes only. It never imports inspected code. A generated-file
name or comment does not itself create an exemption from the source size gate.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

POLICY_ID = "B9-009-physical-source-v2"
JS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".mjs", ".cjs", ".js", ".jsx"}
CODE_SUFFIXES = JS_SUFFIXES | {
    ".go", ".py", ".sh", ".bash", ".ps1", ".psm1", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".sql", ".yml", ".yaml", ".css", ".scss", ".sass",
}
LOCK_NAMES = {
    "go.sum", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock", "bun.lock", "bun.lockb",
}
EXTERNAL_PARTS = {"vendor", "third_party", "node_modules"}


def physical_lines(data: bytes) -> int:
    """Count LF-delimited physical lines; a terminal LF is not an extra line."""
    return data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))


def classify(path: str, data: bytes | None, mode: str) -> tuple[str, int | None, str]:
    p = PurePosixPath(path)
    suffix = p.suffix.lower()
    if mode == "160000":
        return "external-gitlink", None, "external submodule commit; not expanded"
    if mode == "120000":
        return "symlink", None, "link object not followed"
    if any(part in EXTERNAL_PARTS for part in p.parts):
        return "external-source", None, "dependency code outside first-party ownership"
    if p.name in LOCK_NAMES or suffix == ".lock":
        return "dependency-lock", None, "dependency graph, not handwritten source"
    if data is None:
        raise ValueError(f"Missing first-party input: {path}")
    if b"\0" in data:
        return "binary-asset", None, "binary data"
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Unclassified first-party encoding: {path}") from exc

    # New authoring fragments are source too. The baseline has no such files.
    fragment = "authoring" in p.parts and suffix == ".inc"
    executable = (
        suffix in CODE_SUFFIXES
        or data.removeprefix(b"\xef\xbb\xbf").startswith(b"#!")
        or p.name in {"Makefile", "Dockerfile"}
        or p.name.startswith("Dockerfile.")
        or fragment
    )
    if executable:
        test_code = (
            p.name.endswith("_test.go") or ".test." in p.name or ".spec." in p.name
            or p.name.startswith("test-")
            or any(part in {"tests", "test", "testdata", "__tests__"} for part in p.parts)
        )
        category = "test-code" if test_code else "production-code"
        if ".github/workflows/" in path:
            category = "workflow"
        elif path.startswith(("release/", "install/", "scripts/ci/", ".github/scripts/")) and not test_code:
            category = "automation-code"
        part_suffix = PurePosixPath(p.stem).suffix.lower() if fragment else suffix
        return category, 800 if part_suffix in JS_SUFFIXES else 1000, "first-party authored executable/configuration source"
    if p.name.endswith(".schema.json") or ("schemas" in p.parts and suffix == ".json"):
        return "authored-schema", 1000, "first-party JSON schema is authored contract, not generic data exemption"
    if suffix in {".md", ".rst", ".adoc", ".txt"}:
        return "documentation", None, "text documentation / immutable report fixture"
    if suffix in {".json", ".jsonl", ".csv", ".tsv", ".xml", ".toml", ".ini"}:
        return "data-configuration", None, "separately inventoried data; large rows require explicit disposition"
    return "other-text", None, "nonexecutable configuration/header retained in census"


def metrics(rows: list[dict[str, Any]]) -> dict[str, int]:
    source = [row for row in rows if row["size_limit"] is not None]
    return {
        "entries": len(rows),
        "raw_verified": sum(bool(row.get("raw_verified")) for row in rows),
        "authored_files": len(source),
        "physical_lines": sum(row["physical_lines"] for row in source),
        "nonempty_lines": sum(row["nonempty_lines"] for row in source),
        "maximum_lines": max((row["physical_lines"] for row in source), default=0),
        "over_800_js": sum(row["size_limit"] == 800 and row["physical_lines"] > 800 for row in source),
        "over_1000": sum(row["physical_lines"] > 1000 for row in source),
        "over_1500": sum(row["physical_lines"] > 1500 for row in source),
        "over_3000": sum(row["physical_lines"] > 3000 for row in source),
        "over_10000": sum(row["physical_lines"] > 10000 for row in source),
        "over_limit": sum(bool(row["over_limit"]) for row in source),
        "production_or_automation_over_limit": sum(row["over_limit"] and row["category"] != "test-code" for row in source),
        "test_over_limit": sum(row["over_limit"] and row["category"] == "test-code" for row in source),
    }
