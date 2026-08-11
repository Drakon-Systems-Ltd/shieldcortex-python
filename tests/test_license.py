"""Tests for the /v1/license client surface."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.errors import ForbiddenError, ShieldCortexError

BASE = "https://api.shieldcortex.ai"

# No licence on file: last_validated_at is MISSING entirely (not null).
LICENSE_NONE_RESPONSE = {
    "tier": "free",
    "status": "none",
    "expires_at": None,
    "created_at": None,
}

LICENSE_ACTIVE_RESPONSE = {
    "tier": "enterprise",
    "status": "active",
    "expires_at": "2026-09-15T00:00:00.000Z",
    "created_at": "2026-08-11T00:00:00.000Z",
    "last_validated_at": "2026-08-10T22:00:00.000Z",
}

LICENSE_REGENERATE_RESPONSE = {
    "key": "sclic_a1b2c3d4e5",
    "tier": "enterprise",
    "expires_at": "2026-09-15T00:00:00.000Z",
    "message": "Activate with: shieldcortex license activate <key>",
}

LICENSE_FORBIDDEN_BODY = {
    "error": "Forbidden",
    "message": "Admin scope required",
    "requestId": "req_abc123def456",
}

LICENSE_PLAN_REQUIRED_BODY = {
    "error": "Plan Required",
    "message": "Licence keys require a paid plan",
}


# ── get_license ──────────────────────────────────────────────────────────────


@respx.mock
def test_get_license_active(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/license").mock(
        return_value=httpx.Response(200, json=LICENSE_ACTIVE_RESPONSE)
    )
    result = client.get_license()

    assert route.calls.last.request.method == "GET"
    assert result.tier == "enterprise"
    assert result.status == "active"
    assert result.expires_at == "2026-09-15T00:00:00.000Z"
    assert result.created_at == "2026-08-11T00:00:00.000Z"
    assert result.last_validated_at == "2026-08-10T22:00:00.000Z"


@respx.mock
def test_get_license_no_licence_branch(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/license").mock(
        return_value=httpx.Response(200, json=LICENSE_NONE_RESPONSE)
    )
    result = client.get_license()

    assert result.tier == "free"
    assert result.status == "none"
    assert result.expires_at is None
    assert result.created_at is None
    # The key is absent from the response entirely — the default kicks in.
    assert result.last_validated_at is None


@respx.mock
async def test_async_get_license(async_client: AsyncShieldCortex) -> None:
    respx.get(f"{BASE}/v1/license").mock(
        return_value=httpx.Response(200, json=LICENSE_ACTIVE_RESPONSE)
    )
    result = await async_client.get_license()

    assert result.tier == "enterprise"
    assert result.last_validated_at == "2026-08-10T22:00:00.000Z"


# ── regenerate_license ───────────────────────────────────────────────────────


@respx.mock
def test_regenerate_license(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/license/regenerate").mock(
        return_value=httpx.Response(200, json=LICENSE_REGENERATE_RESPONSE)
    )
    result = client.regenerate_license()

    assert json.loads(route.calls.last.request.read()) == {}
    assert result.key == "sclic_a1b2c3d4e5"
    assert result.tier == "enterprise"
    assert result.expires_at == "2026-09-15T00:00:00.000Z"
    assert result.message == "Activate with: shieldcortex license activate <key>"


@respx.mock
def test_regenerate_license_forbidden_without_admin(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/license/regenerate").mock(
        return_value=httpx.Response(403, json=LICENSE_FORBIDDEN_BODY)
    )
    with pytest.raises(ForbiddenError) as exc_info:
        client.regenerate_license()

    assert exc_info.value.status_code == 403
    body = json.loads(exc_info.value.body)
    assert body["error"] == "Forbidden"
    assert body["message"] == "Admin scope required"


@respx.mock
def test_regenerate_license_free_plan_402(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/license/regenerate").mock(
        return_value=httpx.Response(402, json=LICENSE_PLAN_REQUIRED_BODY)
    )
    with pytest.raises(ShieldCortexError) as exc_info:
        client.regenerate_license()

    assert exc_info.value.status_code == 402
    assert json.loads(exc_info.value.body)["error"] == "Plan Required"


@respx.mock
async def test_async_regenerate_license(async_client: AsyncShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/license/regenerate").mock(
        return_value=httpx.Response(200, json=LICENSE_REGENERATE_RESPONSE)
    )
    result = await async_client.regenerate_license()

    assert route.called is True
    assert result.key == "sclic_a1b2c3d4e5"
