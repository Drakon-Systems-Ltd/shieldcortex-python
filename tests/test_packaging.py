"""Packaging regression tests."""

from __future__ import annotations

import importlib.resources
import pathlib

import shieldcortex


def test_py_typed_marker_present() -> None:
    """PEP 561: the package must ship a ``py.typed`` marker."""
    if hasattr(importlib.resources, "files"):
        marker = importlib.resources.files("shieldcortex").joinpath("py.typed")
        assert marker.is_file()
    else:  # pragma: no cover - Python < 3.9 fallback
        assert (pathlib.Path(shieldcortex.__file__).parent / "py.typed").is_file()
