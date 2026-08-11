"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from shieldcortex import AsyncShieldCortex, ShieldCortex


@pytest.fixture
def client() -> ShieldCortex:
    return ShieldCortex(api_key="sc_test_abc123", base_url="https://api.shieldcortex.ai")


@pytest.fixture
async def async_client() -> AsyncIterator[AsyncShieldCortex]:
    client = AsyncShieldCortex(
        api_key="sc_test_abc123", base_url="https://api.shieldcortex.ai"
    )
    yield client
    await client.close()
