#!/usr/bin/env python3
"""Verify the fixed Bundle 9 targets and source limits from actual Git objects."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from artifact_assembly import ALLOWED_OUTPUTS, Source, verify
from source_policy import POLICY_ID, classify, metrics, physical_lines


INDEX = Path(__file__).with_name("bundle9-target-index.json")
MAPPING = "scripts/ci/bundle9-target-map.json"
REPOSITORIES = set(ALLOWED_OUTPUTS) | {"Autostream-Docs", "Autostream-Docker"}


def check_repository(root: Path, revision: str, repository: str) -> dict:
    if repository not in REPOSITORIES:
        raise ValueError("unknown Bundle 9 repository")
    source = Source(root, revision)
    expected = [row for row in json.loads(INDEX.read_text(encoding="utf-8"))
                if row["repository"] == repository]
    inventory, rows = {}, []
    for path, (mode, kind, oid) in sorted(source.entries.items()):
        # Read symlink objects as bytes for the census; never follow their targets.
        data = source.git("cat-file", "blob", oid) if kind == "blob" else None
        category, limit, reason = classify(path, data, mode)
        row = {"path": path, "mode": mode, "blob": oid, "category": category,
               "size_limit": limit, "physical_lines": physical_lines(data or b""),
               "nonempty_lines": sum(bool(line.strip()) for line in (data or b"").split(b"\n")),
               "bytes": len(data or b""), "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
               "raw_verified": data is not None, "reason": reason}
        row["over_limit"] = limit is not None and row["physical_lines"] > limit
        inventory[path] = row
        rows.append(row)
    if not rows or not any(row["size_limit"] is not None for row in rows):
        raise ValueError("empty source census")
    artifacts = verify(source, repository) if repository in ALLOWED_OUTPUTS else []
    proved_outputs = {item["path"] for item in artifacts if item["raw_bytes_equal"]}
    violations = [row["path"] for row in rows if row["over_limit"] and row["path"] not in proved_outputs]
    if violations:
        raise ValueError("handwritten source limit exceeded: " + ", ".join(violations))
    mappings = json.loads(source.read(MAPPING)) if expected else []
    by_id = {row["target_id"]: row for row in mappings}
    if len(by_id) != len(mappings) or set(by_id) != {row["target_id"] for row in expected}:
        raise ValueError("original target denominator changed")
    for target in expected:
        mapping = by_id[target["target_id"]]
        if mapping.get("original_path") != target["path"] or not mapping.get("responsibility"):
            raise ValueError("target identity or responsibility is missing")
        if mapping.get("disposition") not in {"responsibility-split", "generated-from-bounded-authoring"}:
            raise ValueError("unresolved target disposition")
        destinations = mapping.get("destinations")
        if not isinstance(destinations, list) or not destinations:
            raise ValueError("target has no current source owners")
        if len({item["path"] for item in destinations}) != len(destinations):
            raise ValueError("duplicate target destination")
        for destination in destinations:
            actual = inventory.get(destination["path"])
            if actual is None or actual["size_limit"] is None or not actual["bytes"]:
                raise ValueError("target was lost or reclassified outside source")
            if actual["sha256"] != destination["sha256"]:
                raise ValueError("target mapping does not bind current raw source")
        if target["path"] in inventory and inventory[target["path"]]["size_limit"] is None:
            raise ValueError("original target was reclassified outside source")
    return {"repository": repository, "revision": revision,
            "tree": source.git("rev-parse", revision + "^{tree}").strip().decode(),
            "policy": POLICY_ID, "metrics": metrics(rows), "artifacts": artifacts,
            "original_targets": len(expected), "mapped_targets": len(mappings),
            "unapproved_exceptions": 0, "handwritten_over_limit": 0, "files": rows}


def check_source_set(root: Path, manifest: dict) -> list[dict]:
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 9:
        raise ValueError("exactly nine final repositories are required")
    names = [entry["repository"].removeprefix("Kome-Lab/") for entry in repositories]
    if len(set(names)) != 9 or set(names) != REPOSITORIES:
        raise ValueError("final repository set differs from Bundle 9")
    result = []
    for entry, name in zip(repositories, names):
        directory = entry["local_directory"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", directory):
            raise ValueError("repository directory escapes source set")
        result.append(check_repository(root / directory, entry["object"], name))
    if sum(item["mapped_targets"] for item in result) != 96:
        raise ValueError("all 96 original targets must be accounted for")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--repository", choices=sorted(REPOSITORIES))
    parser.add_argument("--tree")
    parser.add_argument("--source-set", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.source_set:
        if args.repository or args.tree:
            parser.error("source-set mode cannot select a single repository")
        result = check_source_set(args.root, json.loads(args.source_set.read_text(encoding="utf-8")))
    else:
        if not args.repository or not args.tree:
            parser.error("repository and immutable tree are required")
        result = [check_repository(args.root, args.tree, args.repository)]
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"policy": POLICY_ID, "repositories": len(result),
                      "targets": sum(item["mapped_targets"] for item in result),
                      "handwritten_over_limit": 0, "unapproved_exceptions": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
