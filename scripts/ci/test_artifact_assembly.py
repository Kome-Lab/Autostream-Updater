"""Exercise the real assembler, including reads from immutable Git objects."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from artifact_assembly import MANIFEST, Source, assemble, verify


REPOSITORY = "Autostream-Worker"
OUTPUT = "release/install-autostream-worker"
FRAGMENT = "authoring/worker/environment.sh.inc"


class Inventory:
    def __init__(self):
        self.layout = {"format_version": 1, "repository": REPOSITORY,
                       "artifacts": [{"output": OUTPUT, "fragments": [FRAGMENT]}]}
        self.files = {FRAGMENT: b"#!/bin/bash\r\nset -euo pipefail\r\n", OUTPUT: b"#!/bin/bash\r\nset -euo pipefail\r\n"}

    def read(self, path):
        if path == MANIFEST:
            return json.dumps(self.layout).encode()
        if path not in self.files:
            raise ValueError("missing fixture source")
        return self.files[path]

    def fragments(self):
        return {path for path in self.files if path.startswith("authoring/") and path.endswith(".inc")}


class ArtifactAssemblyTests(unittest.TestCase):
    def test_preserves_all_raw_bytes(self):
        source = Inventory()
        source.files[FRAGMENT] = source.files[OUTPUT] = b"\xef\xbb\xbf#!/bin/bash\r\n# raw whitespace  \r\nprintf x"
        self.assertEqual(assemble(source, REPOSITORY)[OUTPUT], source.files[OUTPUT])
        self.assertTrue(verify(source, REPOSITORY)[0]["raw_bytes_equal"])

    def test_rejects_invalid_inventory_and_public_bytes(self):
        def artifacts(source):
            return source.layout["artifacts"]

        mutations = {
            "zero outputs": lambda s: s.layout.update(artifacts=[]),
            "missing artifact inventory": lambda s: s.layout.pop("artifacts"),
            "wrong repository": lambda s: s.layout.update(repository="Autostream-Updater"),
            "wrong version": lambda s: s.layout.update(format_version=2),
            "unapproved output": lambda s: artifacts(s)[0].update(output="release/other"),
            "duplicate output": lambda s: artifacts(s).append(copy.deepcopy(artifacts(s)[0])),
            "zero fragments": lambda s: artifacts(s)[0].update(fragments=[]),
            "duplicate fragment": lambda s: artifacts(s)[0]["fragments"].append(FRAGMENT),
            "output self reference": lambda s: artifacts(s)[0].update(fragments=[OUTPUT]),
            "manifest cycle": lambda s: artifacts(s)[0].update(fragments=[MANIFEST]),
            "parent traversal": lambda s: artifacts(s)[0].update(fragments=["authoring/../escape.inc"]),
            "absolute path": lambda s: artifacts(s)[0].update(fragments=["/authoring/escape.inc"]),
            "windows path": lambda s: artifacts(s)[0].update(fragments=["C:\\escape.inc"]),
            "unlisted fragment": lambda s: s.files.update({"authoring/unlisted.sh.inc": b"x\n"}),
            "missing fragment": lambda s: s.files.pop(FRAGMENT),
            "empty fragment": lambda s: s.files.update({FRAGMENT: b""}),
            "oversized shell": lambda s: s.files.update({FRAGMENT: b"x\n" * 1001}),
            "invalid encoding": lambda s: s.files.update({FRAGMENT: b"\xff"}),
            "different public bytes": lambda s: s.files.update({OUTPUT: b"different\n"}),
            "missing public bytes": lambda s: s.files.pop(OUTPUT),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                source = Inventory()
                mutate(source)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    verify(source, REPOSITORY)

    def test_javascript_fragment_limit_is_800(self):
        source = Inventory()
        name = "authoring/worker/fixture.ts.inc"
        source.layout["artifacts"][0]["fragments"] = [name]
        del source.files[FRAGMENT]
        source.files[name] = b"x\n" * 801
        with self.assertRaisesRegex(ValueError, "oversized"):
            assemble(source, REPOSITORY)

    def test_reads_real_git_objects_without_worktree_fallback(self):
        with tempfile.TemporaryDirectory(prefix="artifact-objects-") as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)

            def git(*args, data=None):
                return subprocess.run(["git", "-C", str(root), *args], input=data,
                                      capture_output=True, check=True).stdout.strip().decode()

            source = Inventory()
            for name in [MANIFEST, *source.files]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.read(name))
            git("-c", "core.autocrlf=false", "add", "--all")
            tree = git("write-tree")
            (root / FRAGMENT).write_bytes(b"uncommitted corruption")
            (root / OUTPUT).unlink()
            self.assertTrue(verify(Source(root, tree), REPOSITORY)[0]["raw_bytes_equal"])
            with self.assertRaises(ValueError):
                verify(Source(root), REPOSITORY)
            with self.assertRaises(ValueError):
                Source(root, "HEAD")
            with self.assertRaises(ValueError):
                Source(root, "0" * 40)
            link = git("hash-object", "-w", "--stdin", data=b"../outside")
            git("update-index", "--cacheinfo", f"120000,{link},{FRAGMENT}")
            with self.assertRaisesRegex(ValueError, "non-regular"):
                verify(Source(root, git("write-tree")), REPOSITORY)


if __name__ == "__main__":
    unittest.main()
