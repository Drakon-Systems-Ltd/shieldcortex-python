#!/usr/bin/env python3
"""Refuse a release tag whose version does not match the package.

Used by the publish workflow before anything is built. A tag ``vX.Y.Z`` is
accepted only when ``pyproject.toml``'s ``[project] version``,
``src/shieldcortex/_version.py``'s ``__version__`` and a ``## X.Y.Z``
heading in ``CHANGELOG.md`` all name the same version.

Standard library only. The version files are read semantically and never
imported or executed: ``pyproject.toml`` with ``tomllib`` (Python 3.11+; the
publish workflow runs 3.12) and ``_version.py`` with ``ast``. The guard does
not try to read TOML without ``tomllib``: on an older interpreter it reports
no version, so every tag is refused. ``_version.py`` must have the plain shape
the package uses (a docstring and constant assignments, ``__version__`` set
exactly once); anything else is refused rather than interpreted.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import List, Optional

try:  # Python 3.11+. The publish workflow runs 3.12.
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - exercised on the 3.9/3.10 test jobs
    _tomllib = None

_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.\-+]+)?)$")


def tag_version(tag: str) -> Optional[str]:
    """Return X.Y.Z for a ``vX.Y.Z`` tag (``refs/tags/`` prefix allowed)."""
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]
    match = _TAG_RE.match(tag)
    return match.group(1) if match else None


def pyproject_version(text: str) -> Optional[str]:
    """Return the ``version`` key of the ``[project]`` table.

    Needs ``tomllib``. Without it there is no reading, and None refuses the tag.
    """
    if _tomllib is None:
        return None
    try:
        data = _tomllib.loads(text)
    except Exception:
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    version = project.get("version")
    return version if isinstance(version, str) else None


def _constant_assignment(node: ast.stmt) -> Optional[tuple]:
    """(name, value) for ``NAME = <constant>`` or ``NAME: T = <constant>``."""
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1:
            return None
        target, value = node.targets[0], node.value
    elif isinstance(node, ast.AnnAssign):
        target, value = node.target, node.value
    else:
        return None
    if not isinstance(target, ast.Name) or not isinstance(value, ast.Constant):
        return None
    return target.id, value.value


def module_version(text: str) -> Optional[str]:
    """Return ``__version__`` from a plain version module.

    The source is parsed, not imported. Every top-level statement must be a
    docstring or a ``NAME = <constant>`` assignment, and ``__version__`` must
    be assigned exactly once, to a string. Any other statement (imports,
    conditionals, loops, ``try``, ``match``, definitions, augmented
    assignments) makes the module something this guard does not interpret,
    and the reading is None.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    found = []
    for index, node in enumerate(tree.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        assignment = _constant_assignment(node)
        if assignment is None:
            return None
        name, value = assignment
        if name == "__version__":
            found.append(value)
    if len(found) != 1 or not isinstance(found[0], str):
        return None
    return found[0]


def changelog_has(text: str, version: str) -> bool:
    """True when CHANGELOG.md has a ``## X.Y.Z`` (or ``## [X.Y.Z]``) heading.

    The version must sit on the heading line itself.
    """
    escaped = re.escape(version)
    pattern = re.compile(
        r"^##[ \t]+(?:\[" + escaped + r"\]|" + escaped + r")(?:[ \t\r]|$)", re.M
    )
    return bool(pattern.search(text))


def check(tag: str, root: Path) -> List[str]:
    """Return a list of problems; empty means the tag matches the package."""
    version = tag_version(tag)
    if version is None:
        return ["tag %r is not of the form vX.Y.Z" % tag]
    problems = []
    if _tomllib is None:
        problems.append("tomllib is unavailable (Python 3.11+ is required)")
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
