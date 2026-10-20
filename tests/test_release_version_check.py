"""Tests for scripts/check_release_version.py (the publish workflow's tag guard)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_release_version", ROOT / "scripts" / "check_release_version.py"
)
assert _SPEC is not None and _SPEC.loader is not None
crv = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(crv)


def _make_repo(tmp_path: Path, pyproject: str, module: str, changelog: str) -> Path:
    (tmp_path / "src" / "shieldcortex").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling"]\n\n'
        '[project]\nname = "shieldcortex"\nversion = "%s"\n\n'
        '[tool.other]\nversion = "9.9.9"\n' % pyproject,
        encoding="utf-8",
    )
    (tmp_path / "src" / "shieldcortex" / "_version.py").write_text(
        '__version__ = "%s"\n' % module, encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## 1.2.3 — 2026-10-20\n\n- x\n"

# The guard reads pyproject.toml only with tomllib (3.11+; the publish
# workflow runs 3.12). On 3.9/3.10 it refuses every tag, which
# test_without_tomllib_every_tag_is_refused pins; exact-result tests skip there.
needs_tomllib = pytest.mark.skipif(
    getattr(crv, "_tomllib", None) is None, reason="the guard needs tomllib (Python 3.11+)"
)


@needs_tomllib
def test_matching_tag_passes(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check("v1.2.3", root) == []
    assert crv.check("refs/tags/v1.2.3", root) == []


@needs_tomllib
def test_pyproject_mismatch_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.2", "1.2.3", CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "pyproject.toml" in problems[0]


def test_other_table_version_is_ignored(tmp_path: Path) -> None:
    # [tool.other] version = "9.9.9" must not be read as the project version.
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check("v9.9.9", root) != []


@needs_tomllib
def test_module_mismatch_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.0", CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "_version.py" in problems[0]


@needs_tomllib
def test_missing_changelog_entry_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", "# Changelog\n\n## 1.2.30 — x\n")
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "CHANGELOG.md" in problems[0]


@needs_tomllib
def test_bracketed_changelog_heading_accepted(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", "## [1.2.3] - 2026-10-20\n")
    assert crv.check("v1.2.3", root) == []


@pytest.mark.parametrize("tag", ["1.2.3", "v1.2", "release/python-1.2.3", "vx.y.z", ""])
def test_malformed_tag_fails(tmp_path: Path, tag: str) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check(tag, root) != []


@needs_tomllib
def test_current_repository_is_self_consistent() -> None:
    # The checked-out package must pass for its own version, so a release PR
    # that bumps one version file but not the others fails CI before tagging.
    version = crv.pyproject_version((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert version is not None
    assert crv.check("v" + version, ROOT) == []


# --- Review round 1 regressions: text inside strings must not stand in for
# the real version, and the changelog version must sit on the heading line.

MULTILINE_PYPROJECT = (
    '[project]\nname = "shieldcortex"\ndescription = """\nversion = "1.2.3"\n"""\n'
    'version = "1.2.4"\n'
)


def _write(root: Path, pyproject: str, module: str, changelog: str) -> Path:
    (root / "src" / "shieldcortex").mkdir(parents=True)
    (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    (root / "src" / "shieldcortex" / "_version.py").write_text(module, encoding="utf-8")
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return root


@needs_tomllib
def test_version_line_inside_toml_string_is_not_the_version(tmp_path: Path) -> None:
    root = _write(tmp_path, MULTILINE_PYPROJECT, '__version__ = "1.2.3"\n', CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "pyproject.toml" in problems[0]


def test_without_tomllib_every_tag_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No TOML reading without tomllib: a matching repository is still refused,
    # and the decoy line inside a multi-line string is not read either.
    monkeypatch.setattr(crv, "_tomllib", None)
    assert crv.pyproject_version(MULTILINE_PYPROJECT) is None
    assert crv.pyproject_version('[project]\nversion = "1.2.3"\n') is None
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert problems and "tomllib" in problems[0]


# Round 2: a Unicode line separator inside a TOML literal string is not a
# TOML line break, so its text cannot supply the version either.
SEPARATOR_PYPROJECT = (
    "[project]\ndescription = 'text\u2028version = \"1.2.3\"\u2028text'\nversion = '1.2.4'\n"
)


def test_separator_decoy_without_tomllib_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crv, "_tomllib", None)
    root = _write(tmp_path, SEPARATOR_PYPROJECT, '__version__ = "1.2.3"\n', CHANGELOG)
    assert crv.check("v1.2.3", root) != []


@needs_tomllib
def test_separator_decoy_with_tomllib_reads_the_real_key(tmp_path: Path) -> None:
    assert crv.pyproject_version(SEPARATOR_PYPROJECT) == "1.2.4"
    root = _write(tmp_path, SEPARATOR_PYPROJECT, '__version__ = "1.2.3"\n', CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "pyproject.toml" in problems[0]


@pytest.mark.skipif(getattr(crv, "_tomllib", None) is None, reason="tomllib needs Python 3.11+")
def test_toml_reader_returns_the_real_key() -> None:
    assert crv.pyproject_version(MULTILINE_PYPROJECT) == "1.2.4"
    assert crv.pyproject_version('project.version = "1.2.3"\n') == "1.2.3"


@needs_tomllib
def test_docstring_does_not_stand_in_for_dunder_version(tmp_path: Path) -> None:
    module = '"""\n__version__ = "1.2.3"\n"""\n__version__ = "1.2.4"\n'
    root = _write(tmp_path, '[project]\nversion = "1.2.3"\n', module, CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "_version.py" in problems[0]
    assert crv.module_version(module) == "1.2.4"


@pytest.mark.parametrize(
    "module",
    [
        '__version__ = "1.2.3"\n__version__ = "1.2.4"\n',
        '__version__ = "1.2.3"\n__version__ += ".post1"\n',
        '__version__ = "1.2.3"\nfrom x import y as __version__\n',
        '__version__ = "1.2.3"\nfor __version__ in ["1.2.4"]:\n    pass\n',
        "__version__ = VERSION\n",
        "# __version__ = \"1.2.3\"\n",
        # Round 2: bindings that live in string fields of the AST.
        '__version__ = "1.2.3"\nmatch "1.2.4":\n    case __version__:\n        pass\n',
        '__version__ = "1.2.3"\ntry:\n    raise ValueError("1.2.4")\n'
        "except ValueError as __version__:\n    pass\n",
        # Anything but a docstring and constant assignments is not interpreted.
        'import os\n__version__ = "1.2.3"\n',
        '__version__ = "1.2.3"\nif True:\n    pass\n',
        '__version__ = "1.2.3"\ndef f():\n    global __version__\n',
        '__version__ = 123\n',
        "__version__: str\n",
    ],
)
def test_ambiguous_dunder_version_is_refused(module: str) -> None:
    assert crv.module_version(module) is None


def test_plain_version_module_shapes_are_read() -> None:
    assert crv.module_version('"""Version."""\n__version__ = "1.2.3"\n') == "1.2.3"
    assert crv.module_version('__version__ = "1.2.3"\nVERSION_TUPLE = None\n') == "1.2.3"


def test_annotated_dunder_version_is_read() -> None:
    assert crv.module_version('__version__: str = "1.2.3"\n') == "1.2.3"


@pytest.mark.parametrize(
    "changelog",
    ["##\n1.2.3\n", "## \n1.2.3 - x\n", "## 1.2.3]\n", "## [1.2.3\n"],
)
def test_changelog_version_must_be_on_the_heading_line(changelog: str) -> None:
    assert not crv.changelog_has(changelog, "1.2.3")


def test_changelog_heading_with_crlf_is_accepted() -> None:
    assert crv.changelog_has("## 1.2.3\r\n", "1.2.3")
    assert crv.changelog_has("## [1.2.3]\r\n", "1.2.3")
