"""Shared test fixtures."""

from __future__ import annotations

import pytest

from shieldcortex import ShieldCortex


@pytest.fixture
def client() -> ShieldCortex:
    return ShieldCortex(api_key="sc_test_abc123", base_url="https://api.shieldcortex.ai")
