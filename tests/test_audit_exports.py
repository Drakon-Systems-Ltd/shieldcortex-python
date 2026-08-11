"""Tests for the audit iron dome, ingest and export-manifest surface."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.errors import ShieldCortexError
from shieldcortex.types import AuditIngestEntry

BASE = "https://api.shieldcortex.ai"
DEVICE_ID = "9a3f2c14-0000-4000-8000-000000000001"
MANIFEST_ID = "exp_0123456789abcdef0123456789abcdef"
SHA256 = "a" * 64
SIGNATURE = "b" * 64

IRON_DOME_STATS_RESPONSE = {
    "total_events": 42,
    "blocked": 30,
    "allowed": 12,
    "by_action": {"command_block": 25, "file_guard": 5, "unknown": 12},
    "top_devices": [
        {"device_name": "mac-studio", "device_id": DEVICE_ID, "count": 40},
        {
            "device_name": None,
            "device_id": "9a3f2c14-0000-4000-8000-000000000002",
            "count": 2,
        },
    ],
}

IRON_DOME_402_BODY = {
    "error": "Payment Required",
    "message": "Iron Dome Cloud Analytics requires a Pro or higher plan.",
}

IRON_DOME_EVENTS_RESPONSE = {
    "events": [
        {
            "id": 9001,
            "timestamp": "2026-08-10T09:00:00.000Z",
            "source_type": "hook",
            "source_identifier": "iron-dome",
            "trust_score": 0.1,
            "sensitivity_level": "RESTRICTED",
            "firewall_result": "BLOCK",
            "anomaly_score": 0.97,
            "threat_indicators": ["privilege_escalation"],
            "reason": "[iron-dome:command_block] sudo rm blocked",
            "pipeline_duration_ms": 4,
            "device_id": DEVICE_ID,
            "device_name": "mac-studio",
            "action_type": "command_block",
        },
        {
            "id": 9000,
            "timestamp": "2026-08-10T08:00:00.000Z",
            "source_type": "hook",
            "source_identifier": "iron-dome",
            "trust_score": 0.9,
            "sensitivity_level": "PUBLIC",
            "firewall_result": "ALLOW",
            "anomaly_score": 0.05,
            "threat_indicators": [],
            "reason": None,
            "pipeline_duration_ms": 2,
            "device_id": None,
            "device_name": None,
            "action_type": "unknown",
        },
    ],
    "pagination": {"limit": 50, "offset": 0, "hasMore": False},
}

AUDIT_INGEST_RESPONSE = {"ingested": 2}

# Monthly scan quota 402 — the `usage` sub-object is camelCase on the wire.
AUDIT_INGEST_QUOTA_BODY = {
    "error": "Quota Exceeded",
    "message": "Monthly scan limit reached for your plan",
    "usage": {"scansUsed": 500, "scansLimit": 500, "requested": 2, "remaining": 0},
}

EXPORT_MANIFEST_ROW = {
    "manifest_id": MANIFEST_ID,
    "request_id": "req_abc123def456",
    "api_key_id": 7,
    "format": "json",
    "shape": "envelope",
    "filters": {
        "from": "2026-08-01T00:00:00.000Z",
        "to": None,
        "level": "BLOCK",
        "source": None,
        "device_id": None,
        "search": None,
    },
    "entry_count": 120,
    "export_sha256": SHA256,
    "signature_algorithm": "hmac-sha256",
    "signature": SIGNATURE,
    "generated_at": "2026-08-10T09:00:00.000Z",
    "created_at": "2026-08-10T09:00:00.000Z",
}

EXPORTS_LIST_RESPONSE = {
    "manifests": [EXPORT_MANIFEST_ROW],
    "pagination": {"limit": 50, "offset": 0, "hasMore": False},
}

EXPORT_MANIFEST_DETAIL_RESPONSE = {
    "manifest": {**EXPORT_MANIFEST_ROW, "team_id": 2},
    "verification": {"signature_valid": True, "signature_algorithm": "hmac-sha256"},
}

EXPORT_VERIFY_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "verification": {
        "signature_valid": True,
        "sha256_matches": True,
        "signature_algorithm": "hmac-sha256",
    },
    "expected": {"export_sha256": SHA256, "signature": SIGNATURE},
}

# sha256_matches is null when no export_sha256 was provided (self-check).
EXPORT_VERIFY_SELF_CHECK_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "verification": {
        "signature_valid": True,
        "sha256_matches": None,
        "signature_algorithm": "hmac-sha256",
    },
    "expected": {"export_sha256": SHA256, "signature": SIGNATURE},
}

EXPORT_VERIFICATIONS_RESPONSE = {
    "events": [
        {
            "id": 31,
            "manifest_id": MANIFEST_ID,
            "request_id": "req_verify000001",
            "api_key_id": 7,
            "provided_export_sha256": SHA256,
            "provided_signature": SIGNATURE,
            "result_sha256_matches": True,
            "result_signature_valid": True,
            "created_at": "2026-08-10T10:00:00.000Z",
        },
        {
            "id": 30,
            "manifest_id": MANIFEST_ID,
            "request_id": "req_verify000000",
            "api_key_id": None,
            "provided_export_sha256": None,
            "provided_signature": None,
            "result_sha256_matches": None,
            "result_signature_valid": True,
            "created_at": "2026-08-10T09:30:00.000Z",
        },
    ],
    "pagination": {"limit": 50, "offset": 0, "hasMore": False},
}


# ── get_iron_dome_stats ──────────────────────────────────────────────────────


@respx.mock
def test_get_iron_dome_stats(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/iron-dome/stats").mock(
        return_value=httpx.Response(200, json=IRON_DOME_STATS_RESPONSE)
    )
    result = client.get_iron_dome_stats(time_range="7d", device_id=DEVICE_ID)

    params = dict(route.calls.last.request.url.params)
    # The timeRange param is camelCase on the wire (deliberate API wart).
    assert params == {"timeRange": "7d", "device_id": DEVICE_ID}

    assert result.total_events == 42
    assert result.blocked == 30
    assert result.allowed == 12
    assert result.by_action == {"command_block": 25, "file_guard": 5, "unknown": 12}
    assert result.top_devices[0].device_name == "mac-studio"
    assert result.top_devices[0].device_id == DEVICE_ID
    assert result.top_devices[0].count == 40
    assert result.top_devices[1].device_name is None


@respx.mock
def test_get_iron_dome_stats_free_tier_402(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit/iron-dome/stats").mock(
        return_value=httpx.Response(402, json=IRON_DOME_402_BODY)
    )
    with pytest.raises(ShieldCortexError) as exc_info:
        client.get_iron_dome_stats()

    assert exc_info.value.status_code == 402
    assert json.loads(exc_info.value.body)["error"] == "Payment Required"


@respx.mock
async def test_async_get_iron_dome_stats(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/iron-dome/stats").mock(
        return_value=httpx.Response(200, json=IRON_DOME_STATS_RESPONSE)
    )
    result = await async_client.get_iron_dome_stats()

    params = dict(route.calls.last.request.url.params)
    assert params == {"timeRange": "24h"}
    assert result.total_events == 42


# ── get_iron_dome_events ─────────────────────────────────────────────────────


@respx.mock
def test_get_iron_dome_events(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/iron-dome/events").mock(
        return_value=httpx.Response(200, json=IRON_DOME_EVENTS_RESPONSE)
    )
    result = client.get_iron_dome_events(
        time_range="30d", device_id=DEVICE_ID, limit=50, offset=0
    )

    params = dict(route.calls.last.request.url.params)
    assert params == {
        "timeRange": "30d",
        "device_id": DEVICE_ID,
        "limit": "50",
        "offset": "0",
    }

    assert len(result.events) == 2
    assert result.pagination.has_more is False
    # This envelope carries NO total (unlike GET /v1/audit) — not modelled.
    assert not hasattr(result, "total")
    first = result.events[0]
    assert first.id == 9001
    assert first.firewall_result == "BLOCK"
    assert first.action_type == "command_block"
    assert first.reason == "[iron-dome:command_block] sudo rm blocked"
    assert first.threat_indicators == ["privilege_escalation"]
    assert first.device_id == DEVICE_ID
    second = result.events[1]
    assert second.reason is None
    assert second.device_id is None
    assert second.action_type == "unknown"


@respx.mock
async def test_async_get_iron_dome_events(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/iron-dome/events").mock(
        return_value=httpx.Response(200, json=IRON_DOME_EVENTS_RESPONSE)
    )
    result = await async_client.get_iron_dome_events()

    params = dict(route.calls.last.request.url.params)
    assert params == {"timeRange": "24h", "limit": "50", "offset": "0"}
    assert result.events[0].pipeline_duration_ms == 4


# ── ingest_audit_events ──────────────────────────────────────────────────────


@respx.mock
def test_ingest_audit_events(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/audit/ingest").mock(
        return_value=httpx.Response(201, json=AUDIT_INGEST_RESPONSE)
    )
    entries = [
        AuditIngestEntry(
            source_type="hook",
            source_identifier="session-end",
            trust_score=0.2,
            sensitivity_level="RESTRICTED",
            firewall_result="BLOCK",
            anomaly_score=0.95,
            threat_indicators=["prompt_injection"],
            reason="Injection pattern matched",
            pipeline_duration_ms=12,
            timestamp="2026-08-10T09:00:00.000Z",
            blocked_patterns=["ignore previous instructions"],
            fragmentation_score=0.4,
            device_id=DEVICE_ID,
            device_name="mac-studio",
            platform="darwin",
        ),
        AuditIngestEntry(
            source_type="user",
            source_identifier="alice@example.com",
            trust_score=0.9,
            sensitivity_level="PUBLIC",
            firewall_result="ALLOW",
            anomaly_score=0.02,
            threat_indicators=[],
            reason="Content passed all checks",
            pipeline_duration_ms=3,
            timestamp="2026-08-10T09:01:00.000Z",
        ),
    ]
    result = client.ingest_audit_events(entries)

    payload = json.loads(route.calls.last.request.read())
    assert len(payload["entries"]) == 2
    first = payload["entries"][0]
    assert first["source_type"] == "hook"
    assert first["source_identifier"] == "session-end"
    assert first["trust_score"] == 0.2
    assert first["sensitivity_level"] == "RESTRICTED"
    assert first["firewall_result"] == "BLOCK"
    assert first["anomaly_score"] == 0.95
    assert first["threat_indicators"] == ["prompt_injection"]
    assert first["blocked_patterns"] == ["ignore previous instructions"]
    assert first["fragmentation_score"] == 0.4
    assert first["reason"] == "Injection pattern matched"
    assert first["pipeline_duration_ms"] == 12
    assert first["timestamp"] == "2026-08-10T09:00:00.000Z"
    assert first["device_id"] == DEVICE_ID
    assert first["device_name"] == "mac-studio"
    assert first["platform"] == "darwin"
    second = payload["entries"][1]
    assert "blocked_patterns" not in second
    assert "device_id" not in second

    assert result.ingested == 2


@respx.mock
def test_ingest_audit_events_quota_402_camelcase_usage(
    client: ShieldCortex,
) -> None:
    respx.post(f"{BASE}/v1/audit/ingest").mock(
        return_value=httpx.Response(402, json=AUDIT_INGEST_QUOTA_BODY)
    )
    with pytest.raises(ShieldCortexError) as exc_info:
        client.ingest_audit_events(
            [
                AuditIngestEntry(
                    source_type="hook",
                    source_identifier="session-end",
                    trust_score=0.5,
                    sensitivity_level="PUBLIC",
                    firewall_result="ALLOW",
                    anomaly_score=0.1,
                    threat_indicators=[],
                    reason="ok",
                    pipeline_duration_ms=1,
                    timestamp="2026-08-10T09:00:00.000Z",
                )
            ]
        )

    assert exc_info.value.status_code == 402
    body = json.loads(exc_info.value.body)
    assert body["error"] == "Quota Exceeded"
    # The usage sub-object is camelCase on the wire — preserved verbatim.
    assert body["usage"]["scansUsed"] == 500
    assert body["usage"]["scansLimit"] == 500
    assert body["usage"]["remaining"] == 0


@respx.mock
async def test_async_ingest_audit_events(async_client: AsyncShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/audit/ingest").mock(
        return_value=httpx.Response(201, json=AUDIT_INGEST_RESPONSE)
    )
    result = await async_client.ingest_audit_events(
        [
            AuditIngestEntry(
                source_type="hook",
                source_identifier="session-end",
                trust_score=0.5,
                sensitivity_level="PUBLIC",
                firewall_result="ALLOW",
                anomaly_score=0.1,
                threat_indicators=[],
                reason="ok",
                pipeline_duration_ms=1,
                timestamp="2026-08-10T09:00:00.000Z",
            )
        ]
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload["entries"][0]["firewall_result"] == "ALLOW"
    assert result.ingested == 2


# ── list_audit_exports ───────────────────────────────────────────────────────


@respx.mock
def test_list_audit_exports(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/exports").mock(
        return_value=httpx.Response(200, json=EXPORTS_LIST_RESPONSE)
    )
    result = client.list_audit_exports(
        limit=50, offset=0, format="json", shape="envelope", search="exp_"
    )

    params = dict(route.calls.last.request.url.params)
    assert params == {
        "limit": "50",
        "offset": "0",
        "format": "json",
        "shape": "envelope",
        "search": "exp_",
    }

    assert len(result.manifests) == 1
    assert result.pagination.has_more is False
    assert not hasattr(result, "total")  # absent from this envelope
    manifest = result.manifests[0]
    assert manifest.manifest_id == MANIFEST_ID
    assert manifest.request_id == "req_abc123def456"
    assert manifest.api_key_id == 7
    assert manifest.format == "json"
    assert manifest.shape == "envelope"
    # filters keep raw wire keys (incl. `from`, a Python keyword) as a dict.
    assert manifest.filters["from"] == "2026-08-01T00:00:00.000Z"
    assert manifest.filters["level"] == "BLOCK"
    assert manifest.filters["to"] is None
    assert manifest.entry_count == 120
    assert manifest.export_sha256 == SHA256
    assert manifest.signature_algorithm == "hmac-sha256"
    assert manifest.signature == SIGNATURE
    assert manifest.team_id is None  # list rows carry no team_id


@respx.mock
async def test_async_list_audit_exports(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/audit/exports").mock(
        return_value=httpx.Response(200, json=EXPORTS_LIST_RESPONSE)
    )
    result = await async_client.list_audit_exports()

    params = dict(route.calls.last.request.url.params)
    assert params == {"limit": "50", "offset": "0"}
    assert result.manifests[0].entry_count == 120


# ── get_audit_export_manifest ────────────────────────────────────────────────


@respx.mock
def test_get_audit_export_manifest(client: ShieldCortex) -> None:
    respx.get(f"{BASE}/v1/audit/exports/{MANIFEST_ID}").mock(
        return_value=httpx.Response(200, json=EXPORT_MANIFEST_DETAIL_RESPONSE)
    )
    result = client.get_audit_export_manifest(MANIFEST_ID)

    assert result.manifest.manifest_id == MANIFEST_ID
    assert result.manifest.team_id == 2  # detail-only key
    assert result.manifest.filters["from"] == "2026-08-01T00:00:00.000Z"
    assert result.verification.signature_valid is True
    assert result.verification.signature_algorithm == "hmac-sha256"


@respx.mock
async def test_async_get_audit_export_manifest(
    async_client: AsyncShieldCortex,
) -> None:
    respx.get(f"{BASE}/v1/audit/exports/{MANIFEST_ID}").mock(
        return_value=httpx.Response(200, json=EXPORT_MANIFEST_DETAIL_RESPONSE)
    )
    result = await async_client.get_audit_export_manifest(MANIFEST_ID)

    assert result.manifest.team_id == 2
    assert result.verification.signature_valid is True


# ── verify_audit_export ──────────────────────────────────────────────────────


@respx.mock
def test_verify_audit_export(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/audit/exports/{MANIFEST_ID}/verify").mock(
        return_value=httpx.Response(200, json=EXPORT_VERIFY_RESPONSE)
    )
    result = client.verify_audit_export(
        MANIFEST_ID, export_sha256=SHA256, signature=SIGNATURE
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload == {"export_sha256": SHA256, "signature": SIGNATURE}

    assert result.manifest_id == MANIFEST_ID
    assert result.verification.signature_valid is True
    assert result.verification.sha256_matches is True
    assert result.verification.signature_algorithm == "hmac-sha256"
    assert result.expected.export_sha256 == SHA256
    assert result.expected.signature == SIGNATURE


@respx.mock
def test_verify_audit_export_sha256_matches_null_on_self_check(
    client: ShieldCortex,
) -> None:
    route = respx.post(f"{BASE}/v1/audit/exports/{MANIFEST_ID}/verify").mock(
        return_value=httpx.Response(200, json=EXPORT_VERIFY_SELF_CHECK_RESPONSE)
    )
    result = client.verify_audit_export(MANIFEST_ID)

    # No hashes provided → empty body, server self-checks the signature.
    assert json.loads(route.calls.last.request.read()) == {}
    assert result.verification.signature_valid is True
    # sha256_matches is null when no export_sha256 was provided.
    assert result.verification.sha256_matches is None


@respx.mock
async def test_async_verify_audit_export(async_client: AsyncShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/audit/exports/{MANIFEST_ID}/verify").mock(
        return_value=httpx.Response(200, json=EXPORT_VERIFY_RESPONSE)
    )
    result = await async_client.verify_audit_export(
        MANIFEST_ID, export_sha256=SHA256
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload == {"export_sha256": SHA256}
    assert result.verification.sha256_matches is True


# ── list_audit_export_verifications ──────────────────────────────────────────


@respx.mock
def test_list_audit_export_verifications(client: ShieldCortex) -> None:
    route = respx.get(
        f"{BASE}/v1/audit/exports/{MANIFEST_ID}/verifications"
    ).mock(return_value=httpx.Response(200, json=EXPORT_VERIFICATIONS_RESPONSE))
    result = client.list_audit_export_verifications(
        MANIFEST_ID, limit=50, offset=0
    )

    params = dict(route.calls.last.request.url.params)
    assert params == {"limit": "50", "offset": "0"}

    assert len(result.events) == 2
    assert result.pagination.has_more is False
    assert not hasattr(result, "total")  # absent from this envelope
    first = result.events[0]
    assert first.id == 31
    assert first.manifest_id == MANIFEST_ID
    assert first.provided_export_sha256 == SHA256
    assert first.result_sha256_matches is True
    assert first.result_signature_valid is True
    second = result.events[1]
    assert second.api_key_id is None
    assert second.provided_export_sha256 is None
    assert second.result_sha256_matches is None
    assert second.result_signature_valid is True


@respx.mock
async def test_async_list_audit_export_verifications(
    async_client: AsyncShieldCortex,
) -> None:
    respx.get(f"{BASE}/v1/audit/exports/{MANIFEST_ID}/verifications").mock(
        return_value=httpx.Response(200, json=EXPORT_VERIFICATIONS_RESPONSE)
    )
    result = await async_client.list_audit_export_verifications(MANIFEST_ID)

    assert result.events[0].request_id == "req_verify000001"
    assert result.events[1].result_sha256_matches is None
