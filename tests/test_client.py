"""Tests for the synchronous ShieldCortex client."""

from __future__ import annotations

import httpx
import pytest
import respx

from shieldcortex import (
    AuditQuery,
    BatchItem,
    QuarantineQuery,
    ScanConfig,
    ScanSource,
    ShieldCortex,
)
from shieldcortex.errors import (
    AuthError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ShieldCortexError,
    ValidationError,
)

from tests.fixtures import (
    AUDIT_RESPONSE,
    AUDIT_STATS_RESPONSE,
    QUARANTINE_RESPONSE,
    SCAN_ALLOWED_RESPONSE,
    SCAN_BLOCKED_RESPONSE,
)

BASE = "https://api.shieldcortex.ai"


# ── Scan ──────────────────────────────────────────────────────────────────────


@respx.mock
def test_scan_allowed(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=SCAN_ALLOWED_RESPONSE)
    )
    result = client.scan("Hello world")

    assert result.allowed is True
    assert result.firewall.result == "ALLOW"
    assert result.trust.score == 0.95
    assert result.audit_id == 42
    assert result.usage is not None
    assert result.usage.scans_used == 10


@respx.mock
def test_scan_blocked(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=SCAN_BLOCKED_RESPONSE)
    )
    result = client.scan("'; DROP TABLE users; --")

    assert result.allowed is False
    assert result.firewall.result == "BLOCK"
    assert "sql_injection" in result.firewall.threat_indicators
    assert result.firewall.anomaly_score == 0.95


@respx.mock
def test_scan_with_options(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=SCAN_ALLOWED_RESPONSE)
    )
    client.scan(
        "Test content",
        title="My Memory",
        source=ScanSource(type="agent", identifier="crewai:research"),
        config=ScanConfig(mode="strict"),
    )

    request = route.calls.last.request
    body = request.read()
    import json

    payload = json.loads(body)
    assert payload["content"] == "Test content"
    assert payload["title"] == "My Memory"
    assert payload["source"]["type"] == "agent"
    assert payload["config"]["mode"] == "strict"


@respx.mock
def test_scan_batch(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan/batch").mock(
        return_value=httpx.Response(
            200,
            json={
                "totalScanned": 2,
                "threats": 1,
                "clean": 1,
                "results": [SCAN_ALLOWED_RESPONSE, SCAN_BLOCKED_RESPONSE],
            },
        )
    )
    result = client.scan_batch(
        [BatchItem(content="safe"), BatchItem(content="malicious")]
    )

    assert result.total_scanned == 2
    assert result.threats == 1
    assert result.clean == 1
    assert len(result.results) == 2
    assert result.results[0].allowed is True
    assert result.results[1].allowed is False


@respx.mock
def test_scan_skill(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan/skill").mock(
        return_value=httpx.Response(
            200,
            json={
                "threatScore": 0.1,
                "level": "LOW",
                "verdict": "ALLOW",
                "threats": [],
                "metadata": {"format": "skill-md", "name": "test-skill"},
            },
        )
    )
    result = client.scan_skill("# My Skill\nDo something", name="test-skill")

    assert result.threat_score == 0.1
    assert result.verdict == "ALLOW"
    assert result.metadata is not None
    assert result.metadata.format == "skill-md"


# ── Audit ─────────────────────────────────────────────────────────────────────


@respx.mock
def test_get_audit_logs(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    result = client.get_audit_logs()

    assert result.total == 2
    assert len(result.logs) == 2
    assert result.logs[0].firewall_result == "ALLOW"
    assert result.logs[1].firewall_result == "BLOCK"
    assert result.pagination.has_more is False


@respx.mock
def test_get_audit_logs_with_query(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    client.get_audit_logs(AuditQuery(level="BLOCK", limit=10))

    request = route.calls.last.request
    assert "level=BLOCK" in str(request.url)
    assert "limit=10" in str(request.url)


@respx.mock
def test_get_audit_stats(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit/stats").mock(
        return_value=httpx.Response(200, json=AUDIT_STATS_RESPONSE)
    )
    result = client.get_audit_stats(time_range="7d")

    assert result.total_operations == 1000
    assert result.allowed_count == 900
    assert len(result.top_sources) == 2
    assert result.threat_breakdown["sql_injection"] == 40


@respx.mock
def test_get_audit_trends(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit/trends").mock(
        return_value=httpx.Response(
            200,
            json={
                "buckets": [
                    {
                        "time": "2026-02-15T10:00:00.000Z",
                        "allowed": 100,
                        "blocked": 5,
                        "quarantined": 1,
                    }
                ],
                "timeRange": "24h",
            },
        )
    )
    result = client.get_audit_trends()

    assert len(result.buckets) == 1
    assert result.buckets[0].allowed == 100
    assert result.time_range == "24h"


@respx.mock
def test_export_audit_logs(client: ShieldCortex) -> None:
    csv_data = "id,timestamp,firewall_result\n1,2026-02-15,ALLOW\n"
    respx.get(f"{BASE}/v1/audit/export").mock(
        return_value=httpx.Response(200, text=csv_data)
    )
    result = client.export_audit_logs(format="csv")

    assert "id,timestamp" in result


# ── Quarantine ────────────────────────────────────────────────────────────────


@respx.mock
def test_get_quarantine(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/quarantine").mock(
        return_value=httpx.Response(200, json=QUARANTINE_RESPONSE)
    )
    result = client.get_quarantine()

    assert result.total == 1
    assert result.items[0].status == "pending"
    assert result.items[0].anomaly_score == 0.92


@respx.mock
def test_review_quarantine_item(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/quarantine/100/review").mock(
        return_value=httpx.Response(
            200, json={"success": True, "message": "Item approved"}
        )
    )
    result = client.review_quarantine_item(100, "approve")

    assert result.success is True


# ── API Keys ──────────────────────────────────────────────────────────────────


@respx.mock
def test_create_api_key(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": "API key created",
                "key": "sc_live_newkey123",
                "keyInfo": {
                    "id": 5,
                    "name": "Test Key",
                    "scopes": ["scan"],
                    "expiresAt": None,
                },
                "warning": "Save this key securely.",
            },
        )
    )
    result = client.create_api_key("Test Key", scopes=["scan"])

    assert result.key == "sc_live_newkey123"
    assert result.key_info.name == "Test Key"


@respx.mock
def test_list_api_keys(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    {
                        "id": 1,
                        "name": "Production",
                        "prefix": "sc_live_abc",
                        "scopes": ["scan", "audit"],
                        "lastUsedAt": "2026-02-15T10:00:00.000Z",
                        "createdAt": "2026-01-01T00:00:00.000Z",
                        "revoked": False,
                    }
                ],
                "total": 1,
            },
        )
    )
    result = client.list_api_keys()

    assert result.total == 1
    assert result.keys[0].prefix == "sc_live_abc"


# ── Teams ─────────────────────────────────────────────────────────────────────


@respx.mock
def test_get_team(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/teams").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 1,
                "name": "Acme Corp",
                "slug": "acme-corp",
                "plan": "pro",
                "scanLimit": 10000,
            },
        )
    )
    result = client.get_team()

    assert result.name == "Acme Corp"
    assert result.plan == "pro"
    assert result.scan_limit == 10000


@respx.mock
def test_get_usage(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/teams/usage").mock(
        return_value=httpx.Response(
            200,
            json={
                "used": 450,
                "limit": 10000,
                "breakdown": {
                    "scans": 300,
                    "batches": 150,
                    "blocked": 20,
                    "quarantined": 5,
                },
            },
        )
    )
    result = client.get_usage()

    assert result.used == 450
    assert result.breakdown.scans == 300


# ── Error handling ────────────────────────────────────────────────────────────


@respx.mock
def test_auth_error(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(401, json={"error": "Invalid API key"})
    )
    with pytest.raises(AuthError) as exc_info:
        client.scan("test")

    assert exc_info.value.status_code == 401


@respx.mock
def test_rate_limit_error(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(
            429,
            json={"error": "Rate limit exceeded"},
            headers={"Retry-After": "30"},
        )
    )
    with pytest.raises(RateLimitError) as exc_info:
        client.scan("test")

    assert exc_info.value.retry_after == 30


@respx.mock
def test_validation_error(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(400, json={"error": "Content too long"})
    )
    with pytest.raises(ValidationError):
        client.scan("test")


@respx.mock
def test_not_found_error(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit/99999").mock(
        return_value=httpx.Response(404, json={"error": "Not found"})
    )
    with pytest.raises(NotFoundError):
        client.get_audit_entry(99999)


@respx.mock
def test_forbidden_error(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/keys").mock(
        return_value=httpx.Response(403, json={"error": "Insufficient permissions"})
    )
    with pytest.raises(ForbiddenError):
        client.create_api_key("test")


@respx.mock
def test_generic_server_error(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    with pytest.raises(ShieldCortexError) as exc_info:
        client.scan("test")

    assert exc_info.value.status_code == 500


# ── Context manager ──────────────────────────────────────────────────────────


@respx.mock
def test_context_manager() -> None:
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=SCAN_ALLOWED_RESPONSE)
    )
    with ShieldCortex(api_key="sc_test_abc") as client:
        result = client.scan("test")
        assert result.allowed is True


# ── Auth header ───────────────────────────────────────────────────────────────


@respx.mock
def test_sends_auth_header(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=SCAN_ALLOWED_RESPONSE)
    )
    client.scan("test")

    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer sc_test_abc123"
    assert "shieldcortex-python" in request.headers["user-agent"]
