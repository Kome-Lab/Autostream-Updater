#!/usr/bin/env python3
"""Resolve the caller workflow SHA separately from the eight fixed code pins."""
import argparse
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--workflow-sha", required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--github-output", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
pins = json.loads(Path(__file__).with_name("bundle9-final-source-pins.json").read_text(encoding="utf-8"))
expected = {"Autostream-ControlPanel", "Autostream-Contracts", "Autostream-Worker",
            "Autostream-Encoder-Recorder", "Autostream-DiscordBot", "Autostream-Observability",
            "Autostream-Docs", "Autostream-Docker"}
if set(pins) != expected or not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in [args.workflow_sha, *pins.values()]):
    raise SystemExit("invalid fixed final source set")
actual = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, check=True).stdout.strip().decode()
if actual != args.workflow_sha:
    raise SystemExit("measurement checker is not from the actual workflow source")
pins["Autostream-Updater"] = args.workflow_sha
manifest = {"schema_version": 1, "purpose": "exact final code set including the actual Updater workflow tree",
            "repositories": [{"repository": "Kome-Lab/" + name, "local_directory": name,
                              "object": revision, "object_kind": "commit"} for name, revision in sorted(pins.items())]}
args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
with args.github_output.open("a", encoding="utf-8") as output:
    output.write("sources=" + json.dumps(pins, separators=(",", ":")) + "\n")
