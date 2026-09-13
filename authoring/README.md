# Distribution authoring

Edit the responsibility fragments listed in `artifact-layout.json`. Each
fragment is first-party source and is checked against its physical line limit.
The public installer or contract remains at its existing path.

From the repository root, run:

```text
python3 scripts/ci/artifact_assembly.py --repository Autostream-Updater --write
python3 -m unittest discover -s scripts/ci -p 'test_artifact_assembly.py' -v
```

The assembler concatenates raw fragment bytes in the manifest order. It does
not parse or rewrite Bash, JSON, YAML, whitespace, newlines, or references.
Published and embedded artifacts use the public output. Installer execution is
standalone and does not read these authoring fragments at runtime.

CI verifies the manifest, fragments, and public output from the same immutable
Git tree, then applies the source-size gate. A generated filename alone does
not grant an exception.
