#!/usr/bin/env python3
"""Refuse a release tag whose version does not match the package.

Used by the publish workflow before anything is built. A tag ``vX.Y.Z`` is
accepted only when ``pyproject.toml``'s ``[project] version``,
``src/shieldcortex/_version.py``'s ``__version__`` and a ``## X.Y.Z``
heading in ``CHANGELOG.md`` all name the same version.

Standard library only, and compatible with every Python the test matrix runs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional

_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.\-+]+)?)$")
_VERSION_LINE_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
_DUNDER_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', re.M)


def tag_version(tag: str) -> Optional[str]:
    """Return X.Y.Z for a ``vX.Y.Z`` tag (``refs/tags/`` prefix allowed)."""
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]
    match = _TAG_RE.match(tag)
    return match.group(1) if match else None


def pyproject_version(text: str) -> Optional[str]:
    """Return the ``version`` key of the ``[project]`` table."""
    in_project = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_project = line == "[project]"
            continue
        if in_project:
            match = _VERSION_LINE_RE.match(line)
            if match:
                return match.group(1)
    return None


def module_version(text: str) -> Optional[str]:
    match = _DUNDER_RE.search(text)
    return match.group(1) if match else None


def changelog_has(text: str, version: str) -> bool:
    """True when CHANGELOG.md has a ``## X.Y.Z`` (or ``## [X.Y.Z]``) heading."""
    pattern = re.compile(
        r"^##\s+\[?" + re.escape(version) + r"\]?(?:\s|$)", re.M
    )
    return bool(pattern.search(text))


def check(tag: str, root: Path) -> List[str]:
    """Return a list of problems; empty means the tag matches the package."""
    version = tag_version(tag)
    if version is None:
        return ["tag %r is not of the form vX.Y.Z" % tag]
    problems = []
    py = pyproject_version((root / "pyproject.toml").read_text(encoding="utf-8"))
    if py != version:
        problems.append(
            "pyproject.toml [project] version is %r, tag is %r" % (py, version)
        )
    mod = module_version(
        (root / "src" / "shieldcortex" / "_version.py").read_text(encoding="utf-8")
    )
    if mod != version:
        problems.append(
            "src/shieldcortex/_version.py __version__ is %r, tag is %r"
            % (mod, version)
        )
    if not changelog_has((root / "CHANGELOG.md").read_text(encoding="utf-8"), version):
        problems.append("CHANGELOG.md has no '## %s' heading" % version)
    return problems


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: check_release_version.py <tag>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent.parent
    problems = check(argv[1], root)
    for problem in problems:
        print("release check: " + problem, file=sys.stderr)
    if problems:
        return 1
    print("release check: %s matches pyproject, _version and CHANGELOG" % argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
