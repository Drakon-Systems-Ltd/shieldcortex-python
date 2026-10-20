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


def test_matching_tag_passes(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check("v1.2.3", root) == []
    assert crv.check("refs/tags/v1.2.3", root) == []


def test_pyproject_mismatch_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.2", "1.2.3", CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "pyproject.toml" in problems[0]


def test_other_table_version_is_ignored(tmp_path: Path) -> None:
    # [tool.other] version = "9.9.9" must not be read as the project version.
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check("v9.9.9", root) != []


def test_module_mismatch_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.0", CHANGELOG)
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "_version.py" in problems[0]


def test_missing_changelog_entry_fails(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", "# Changelog\n\n## 1.2.30 — x\n")
    problems = crv.check("v1.2.3", root)
    assert len(problems) == 1 and "CHANGELOG.md" in problems[0]


def test_bracketed_changelog_heading_accepted(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", "## [1.2.3] - 2026-10-20\n")
    assert crv.check("v1.2.3", root) == []


@pytest.mark.parametrize("tag", ["1.2.3", "v1.2", "release/python-1.2.3", "vx.y.z", ""])
def test_malformed_tag_fails(tmp_path: Path, tag: str) -> None:
    root = _make_repo(tmp_path, "1.2.3", "1.2.3", CHANGELOG)
    assert crv.check(tag, root) != []


def test_current_repository_is_self_consistent() -> None:
    # The checked-out package must pass for its own version, so a release PR
    # that bumps one version file but not the others fails CI before tagging.
    version = crv.pyproject_version((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert version is not None
    assert crv.check("v" + version, ROOT) == []
