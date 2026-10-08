#!/usr/bin/env python3
"""Read the compiled Host runtime compatibility floor and verify installer copies."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


STABLE_VERSION = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
AUTHORITY_PATH = "internal/version/release_compatibility.go"
INSTALLER_PATHS = tuple(
    f"authoring/install-autostream-{component}/artifact-verification.sh.inc"
    for component in ("updater-agent", "local-executor")
)
DECLARATION = re.compile(
    r'\A\s*package version\s+const MinimumControlPanelVersion string = "('
    + STABLE_VERSION + r')"\s*\Z'
)
INSTALLER_DECLARATION = re.compile(
    r'^readonly MINIMUM_PANEL_VERSION="(' + STABLE_VERSION + r')"$',
    re.MULTILINE,
)


def stable_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(STABLE_VERSION, value)
    if match is None:
        raise ValueError("Host runtime version must be a canonical stable vX.Y.Z")
    components = tuple(int(part) for part in match.groups())
    if any(part > 2**63 - 1 for part in components):
        raise ValueError("Host runtime version component is out of range")
    return components


def read_source(root: Path, relative: str) -> str:
    path = root / relative
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("Host runtime compatibility source must not be a symlink")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValueError("Host runtime compatibility source is missing") from error
    if not payload or len(payload) > 64 << 10:
        raise ValueError("Host runtime compatibility source has an invalid size")
    return payload.decode("utf-8").replace("\r\n", "\n")


def minimum_panel_version(root: Path, source_version: str) -> str:
    root = root.resolve(strict=True)
    source = read_source(root, AUTHORITY_PATH)
    # This intentionally accepts only one typed const in its dedicated source.
    # Comments are ignored; variables, imports, duplicate declarations, and code
    # that could introduce another source of authority are rejected.
    source = re.sub(r"(?m)^\s*//[^\n]*", "", source)
    declaration = DECLARATION.fullmatch(source)
    if declaration is None:
        raise ValueError("Host runtime minimum Panel authority is not one typed const")
    floor = declaration.group(1)
    if stable_version(source_version) < stable_version(floor):
        raise ValueError("Host runtime source version is below the reviewed Panel floor")
    for relative in INSTALLER_PATHS:
        installer = read_source(root, relative)
        declarations = INSTALLER_DECLARATION.findall(installer)
        if len(declarations) != 1 or declarations[0][0] != floor:
            raise ValueError("installer minimum Panel literal differs from compiled authority")
        assignments = re.findall(
            r"(?m)^\s*(?:readonly\s+|export\s+)?MINIMUM_PANEL_VERSION=", installer,
        )
        if len(assignments) != 1:
            raise ValueError("installer minimum Panel authority is ambiguous")
        if installer.count(".minimum_panel_version == $minimum_panel_version") != 1 or \
                installer.count('--arg minimum_panel_version "${MINIMUM_PANEL_VERSION}"') != 1:
            raise ValueError("installer manifest guard is not bound to its reviewed floor")
    return floor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--source-version", required=True)
    arguments = parser.parse_args()
    try:
        floor = minimum_panel_version(arguments.root, arguments.source_version)
    except (ValueError, OSError, UnicodeError) as error:
        parser.exit(1, f"Host runtime compatibility rejected: {error}\n")
    print(floor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
