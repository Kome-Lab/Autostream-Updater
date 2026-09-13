"""Negative sensitivity of the actual target accounting and source-size gate."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import verify_bundle9_sources as gate


class Candidate:
    def __init__(self):
        expected = [row for row in json.loads(gate.INDEX.read_text(encoding="utf-8"))
                    if row["repository"] == "Autostream-Worker"]
        self.files = {row["path"]: b"#!/bin/bash\nx\n" for row in expected}
        self.mappings = [{"target_id": row["target_id"], "original_path": row["path"],
                          "disposition": "responsibility-split", "responsibility": "original domain",
                          "destinations": [{"path": row["path"],
                                            "sha256": hashlib.sha256(self.files[row["path"]]).hexdigest()}]}
                         for row in expected]
        self.extra_entries = {}

    @property
    def entries(self):
        return {**{name: ("100644", "blob", name) for name in self.files}, **self.extra_entries}

    def read(self, name):
        return json.dumps(self.mappings).encode() if name == gate.MAPPING else self.files[name]

    def git(self, *args):
        return self.files[args[2]] if args[0] == "cat-file" else b"1" * 40


class SourceGateTests(unittest.TestCase):
    def check(self, candidate):
        with patch.object(gate, "Source", return_value=candidate), patch.object(gate, "verify", return_value=[]):
            return gate.check_repository(Path("unused"), "1" * 40, "Autostream-Worker")

    def test_current_raw_source_is_required_for_every_original_target(self):
        result = self.check(Candidate())
        self.assertEqual(result["original_targets"], 4)
        self.assertEqual(result["mapped_targets"], 4)
        self.assertEqual(result["unapproved_exceptions"], 0)

    def test_mapping_and_classification_cannot_reduce_the_denominator(self):
        mutations = {
            "zero targets": lambda c: c.mappings.clear(),
            "missing target": lambda c: c.mappings.pop(),
            "duplicate target": lambda c: c.mappings.append(copy.deepcopy(c.mappings[0])),
            "invented target": lambda c: c.mappings[0].update(target_id="B9-M999"),
            "renamed original": lambda c: c.mappings[0].update(original_path="renamed.go"),
            "no responsibility": lambda c: c.mappings[0].pop("responsibility"),
            "unresolved target": lambda c: c.mappings[0].update(disposition="pending"),
            "empty owners": lambda c: c.mappings[0].update(destinations=[]),
            "duplicate owner": lambda c: c.mappings[0]["destinations"].append(copy.deepcopy(c.mappings[0]["destinations"][0])),
            "missing owner": lambda c: c.mappings[0]["destinations"][0].update(path="missing.go"),
            "changed raw hash": lambda c: c.mappings[0]["destinations"][0].update(sha256="0" * 64),
            "binary disguise": lambda c: c.files.update({c.mappings[0]["original_path"]: b"\0hidden code"}),
            "empty source": lambda c: c.files.update({c.mappings[0]["original_path"]: b""}),
            "oversized source": lambda c: c.files.update({c.mappings[0]["original_path"]: b"x\n" * 1001}),
            "oversized javascript": lambda c: c.files.update({"src/additional.ts": b"x\n" * 801}),
            "zero census": lambda c: c.files.clear(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = Candidate()
                mutate(candidate)
                with self.assertRaises((ValueError, KeyError)):
                    self.check(candidate)
        candidate = Candidate()
        candidate.files["mapping.json"] = b"{}\n"
        candidate.mappings[0]["destinations"][0].update(path="mapping.json", sha256=hashlib.sha256(b"{}\n").hexdigest())
        with self.assertRaisesRegex(ValueError, "reclassified"):
            self.check(candidate)

    def test_census_uses_lf_only_and_reads_link_objects_without_following(self):
        candidate = Candidate()
        candidate.files["src/lf-policy.py"] = b"x\vsecond\r\n\n"
        candidate.files["link"] = b"../unavailable-target"
        candidate.extra_entries["link"] = ("120000", "blob", "link")
        rows = {row["path"]: row for row in self.check(candidate)["files"]}
        self.assertEqual(rows["src/lf-policy.py"]["physical_lines"], 2)
        self.assertEqual(rows["src/lf-policy.py"]["nonempty_lines"], 1)
        self.assertEqual(rows["link"]["category"], "symlink")
        self.assertTrue(rows["link"]["raw_verified"])

    def test_aggregate_rejects_empty_missing_duplicate_or_foreign_repositories(self):
        names = sorted(gate.REPOSITORIES)
        rows = [{"repository": name, "local_directory": name, "object": "1" * 40} for name in names]
        mutations = [[], rows[:-1], [*rows[:-1], rows[0]], [*rows[:-1], {**rows[-1], "repository": "foreign"}]]
        for mutated in mutations:
            with self.subTest(repositories=[row["repository"] for row in mutated]):
                with self.assertRaises(ValueError):
                    gate.check_source_set(Path("unused"), {"repositories": mutated})


if __name__ == "__main__":
    unittest.main()
