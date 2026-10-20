#!/usr/bin/env python3
"""Refuse a release tag whose version does not match the package.

Used by the publish workflow before anything is built. A tag ``vX.Y.Z`` is
accepted only when ``pyproject.toml``'s ``[project] version``,
``src/shieldcortex/_version.py``'s ``__version__`` and a ``## X.Y.Z``
heading in ``CHANGELOG.md`` all name the same version.

Standard library only, and compatible with every Python the test matrix runs.
The version files are read semantically (TOML via ``tomllib`` where the
interpreter has it, Python via ``ast``) and never imported or executed. Where
a reading would be ambiguous the guard returns no version, so the tag is
refused rather than accepted.
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
_VERSION_LINE_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')


def tag_version(tag: str) -> Optional[str]:
    """Return X.Y.Z for a ``vX.Y.Z`` tag (``refs/tags/`` prefix allowed)."""
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]
    match = _TAG_RE.match(tag)
    return match.group(1) if match else None


def _pyproject_version_toml(text: str) -> Optional[str]:
    try:
        data = _tomllib.loads(text)
    except Exception:
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    version = project.get("version")
    return version if isinstance(version, str) else None


def _pyproject_version_lines(text: str) -> Optional[str]:
    """Line reader for interpreters without ``tomllib``.

    A multi-line string can hold text that looks like a ``version`` line, so
    any triple-quote delimiter makes the reading ambiguous and returns None.
    More than one ``version`` line in ``[project]`` also returns None.
    """
    if '"""' in text or "'''" in text:
        return None
    in_project = False
    found = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_project = line == "[project]"
            continue
        if in_project:
            match = _VERSION_LINE_RE.match(line)
            if match:
                found.append(match.group(1))
    return found[0] if len(found) == 1 else None


def pyproject_version(text: str) -> Optional[str]:
    """Return the ``version`` key of the ``[project]`` table."""
    if _tomllib is not None:
        return _pyproject_version_toml(text)
    return _pyproject_version_lines(text)


def _binds_version(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "__version__" and isinstance(node.ctx, (ast.Store, ast.Del))
    if isinstance(node, ast.alias):
        bound = node.asname or node.name.split(".")[0]
        return bound == "__version__"
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == "__version__"
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return "__version__" in node.names
    return False


def module_version(text: str) -> Optional[str]:
    """Return ``__version__`` from a single top-level string assignment.

    The source is parsed, not imported. Text inside strings or comments is
    ignored. Any other binding of ``__version__`` (a second assignment, an
    augmented assignment, an import alias, a loop target) makes the reading
    ambiguous and returns None.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    if sum(1 for node in ast.walk(tree) if _binds_version(node)) != 1:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if len(targets) != 1:
            continue
        target = targets[0]
        if isinstance(target, ast.Name) and target.id == "__version__":
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            return None
    return None


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
