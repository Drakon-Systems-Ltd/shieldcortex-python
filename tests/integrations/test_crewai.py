"""Tests for the CrewAI integration (no CrewAI dependency needed)."""

from __future__ import annotations

import httpx
import pytest
import respx

from shieldcortex import ShieldCortex
from shieldcortex.integrations.crewai import MemoryBlockedError, ShieldCortexMemoryGuard

BASE = "https://api.shieldcortex.ai"

ALLOWED_RESPONSE = {
    "allowed": True,
    "firewall": {
        "result": "ALLOW",
        "reason": "OK",
        "threatIndicators": [],
        "anomalyScore": 0.01,
        "blockedPatterns": [],
    },
    "sensitivity": {"level": "PUBLIC", "redactionRequired": False},
    "trust": {"score": 0.95},
    "auditId": 1,
}

BLOCKED_RESPONSE = {
    "allowed": False,
    "firewall": {
        "result": "BLOCK",
        "reason": "Credential leak detected",
        "threatIndicators": ["credential_leak"],
        "anomalyScore": 0.95,
        "blockedPatterns": ["AWS_KEY"],
    },
    "sensitivity": {"level": "RESTRICTED", "redactionRequired": True},
    "trust": {"score": 0.1},
    "auditId": 2,
}

QUARANTINE_RESPONSE = {
    "allowed": False,
    "firewall": {
        "result": "QUARANTINE",
        "reason": "Suspicious pattern",
        "threatIndicators": ["encoding_attack"],
        "anomalyScore": 0.7,
        "blockedPatterns": [],
    },
    "sensitivity": {"level": "INTERNAL", "redactionRequired": False},
    "trust": {"score": 0.4},
    "auditId": 3,
}


@respx.mock
def test_check_allowed() -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client)

    result = guard.check("safe content")
    assert result.allowed is True
    assert guard.audit_ids == [1]


@respx.mock
def test_check_blocked_raises() -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client)

    with pytest.raises(MemoryBlockedError) as exc_info:
        guard.check("AKIAIOSFODNN7EXAMPLE")

    assert "Credential leak" in str(exc_info.value)
    assert exc_info.value.result.firewall.result == "BLOCK"


@respx.mock
def test_check_quarantine_blocked_by_default() -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=QUARANTINE_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client, block_on_quarantine=True)

    with pytest.raises(MemoryBlockedError):
        guard.check("suspicious content")


@respx.mock
def test_check_quarantine_allowed_when_configured() -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=QUARANTINE_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client, block_on_quarantine=False)

    result = guard.check("suspicious content")
    assert result.firewall.result == "QUARANTINE"


@respx.mock
def test_check_passes_source_identifier() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client, source_identifier="custom-agent")

    guard.check("content")

    import json
    payload = json.loads(route.calls.last.request.read())
    assert payload["source"]["identifier"] == "custom-agent"
    assert payload["source"]["type"] == "agent"


@respx.mock
def test_check_uses_configured_mode() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    client = ShieldCortex(api_key="sc_test_abc")
    guard = ShieldCortexMemoryGuard(client, mode="strict")

    guard.check("content")

    import json
    payload = json.loads(route.calls.last.request.read())
    assert payload["config"]["mode"] == "strict"
