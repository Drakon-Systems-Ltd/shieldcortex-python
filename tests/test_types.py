"""Tests for type serialisation and deserialisation."""

from __future__ import annotations

from shieldcortex._http import deserialize, serialize
from shieldcortex.types import (
    AuditEntry,
    AuditResponse,
    FirewallResult,
    Pagination,
    ScanConfig,
    ScanResult,
    ScanSource,
    SensitivityResult,
    TeamInfo,
    TrustResult,
)


def test_serialize_scan_source() -> None:
    source = ScanSource(type="agent", identifier="crewai:research")
    result = serialize(source)
    assert result == {"type": "agent", "identifier": "crewai:research"}


def test_serialize_scan_config() -> None:
    config = ScanConfig(mode="strict", enable_fragmentation_detection=True)
    result = serialize(config)
    assert result == {"mode": "strict", "enableFragmentationDetection": True}


def test_serialize_omits_none() -> None:
    source = ScanSource(type="user")
    result = serialize(source)
    assert "identifier" not in result


def test_deserialize_scan_result_camel_case() -> None:
    """API scan results use camelCase."""
    data = {
        "allowed": True,
        "firewall": {
            "result": "ALLOW",
            "reason": "OK",
            "threatIndicators": [],
            "anomalyScore": 0.01,
            "blockedPatterns": [],
        },
        "sensitivity": {"level": "PUBLIC", "redactionRequired": False},
        "trust": {"score": 0.99},
        "auditId": 42,
    }
    result = deserialize(data, ScanResult)

    assert result.allowed is True
    assert result.firewall.result == "ALLOW"
    assert result.firewall.anomaly_score == 0.01
    assert result.sensitivity.redaction_required is False
    assert result.trust.score == 0.99
    assert result.audit_id == 42
    assert result.fragmentation is None
    assert result.usage is None


def test_deserialize_audit_entry_snake_case() -> None:
    """Audit list entries use snake_case."""
    data = {
        "id": 1,
        "timestamp": "2026-02-15T10:00:00.000Z",
        "source_type": "user",
        "source_identifier": "alice@example.com",
        "trust_score": 0.95,
        "sensitivity_level": "PUBLIC",
        "firewall_result": "ALLOW",
        "anomaly_score": 0.02,
        "threat_indicators": [],
        "reason": "OK",
        "pipeline_duration_ms": 45,
    }
    result = deserialize(data, AuditEntry)

    assert result.id == 1
    assert result.source_type == "user"
    assert result.trust_score == 0.95


def test_deserialize_audit_entry_camel_case() -> None:
    """Single audit entries (from /:id) use camelCase."""
    data = {
        "id": 1,
        "timestamp": "2026-02-15T10:00:00.000Z",
        "sourceType": "user",
        "sourceIdentifier": "alice@example.com",
        "trustScore": 0.95,
        "sensitivityLevel": "PUBLIC",
        "firewallResult": "ALLOW",
        "anomalyScore": 0.02,
        "threatIndicators": [],
        "reason": "OK",
        "pipelineDurationMs": 45,
    }
    result = deserialize(data, AuditEntry)

    assert result.id == 1
    assert result.source_type == "user"
    assert result.trust_score == 0.95


def test_deserialize_nested_list() -> None:
    """AuditResponse contains List[AuditEntry]."""
    data = {
        "logs": [
            {
                "id": 1,
                "timestamp": "2026-02-15T10:00:00.000Z",
                "source_type": "user",
                "source_identifier": "alice",
                "trust_score": 0.95,
                "sensitivity_level": "PUBLIC",
                "firewall_result": "ALLOW",
                "anomaly_score": 0.02,
                "threat_indicators": [],
                "reason": "OK",
                "pipeline_duration_ms": 45,
            }
        ],
        "total": 1,
        "pagination": {"limit": 100, "offset": 0, "hasMore": False},
    }
    result = deserialize(data, AuditResponse)

    assert len(result.logs) == 1
    assert result.logs[0].id == 1
    assert result.pagination.has_more is False


def test_deserialize_team_info_camel_case() -> None:
    data = {
        "id": 1,
        "name": "Acme",
        "slug": "acme",
        "plan": "pro",
        "scanLimit": 10000,
    }
    result = deserialize(data, TeamInfo)

    assert result.scan_limit == 10000


def test_frozen_dataclass_immutable() -> None:
    source = ScanSource(type="user", identifier="test")
    with __import__("pytest").raises(AttributeError):
        source.type = "agent"  # type: ignore[misc]
