"""Tests for the /v1/incidents/replay and /v1/recall/explain client surface."""

from __future__ import annotations

import httpx
import respx

from shieldcortex import AsyncShieldCortex, ShieldCortex

BASE = "https://api.shieldcortex.ai"

INCIDENT_REPLAY_RESPONSE = {
    "events": [
        {
            "id": "audit:9001",
            "timestamp": "2026-08-10T14:00:00.000Z",
            "stream": "audit",
            "event_type": "firewall_block",
            "severity": "critical",
            "summary": "BLOCK: prompt injection in agent output",
            "details": "Instruction override attempt",
            "device_uuid": "9a3f2c14-0000-4000-8000-000000000001",
            "device_name": "mac-studio",
            "source_identifier": "crewai:research",
            "project": "shieldcortex",
            "memory_external_id": None,
            "metadata": {"anomaly_score": 0.95},
        },
        {
            "id": "memory:ext-42",
            "timestamp": "2026-08-10T13:55:00.000Z",
            "stream": "memory",
            "event_type": "memory_synced",
            "severity": "info",
            "summary": "Memory synced",
            "details": None,
            "device_uuid": None,
            "device_name": None,
            "source_identifier": None,
            "project": None,
            "memory_external_id": "ext-42",
            "metadata": {},
        },
    ],
    "total": 2,
    "summary": {"audit": 1, "verification": 0, "sync": 0, "memory": 1},
    "coverage": {
        "sources": ["audit_logs", "synced_memories"],
        "note": "Merged timeline across audit, verification, sync and memory.",
    },
}

# Unknown device_id → well-formed empty 200 envelope with an explanatory note.
INCIDENT_REPLAY_EMPTY_RESPONSE = {
    "events": [],
    "total": 0,
    "summary": {"audit": 0, "verification": 0, "sync": 0, "memory": 0},
    "coverage": {
        "sources": [],
        "note": "Device 00000000-0000-4000-8000-999999999999 is not registered.",
    },
}

RECALL_EXPLAIN_RESPONSE = {
    "query": "release process npm",
    "project": "shieldcortex",
    "total_candidates": 37,
    "results": [
        {
            "memory": {
                "external_id": "mem-abc",
                "title": "Release alignment checklist",
                "content": "Align npm, GitHub, ClawHub before tagging.",
                "project": "shieldcortex",
                "category": "process",
                "type": "reference",
                "tags": ["release", "npm"],
                "salience": 0.82,
                "scope": "project",
                "trust_score": 0.9,
                "updated_at": "2026-08-01T10:00:00.000Z",
                "last_synced_at": "2026-08-10T09:00:00.000Z",
                "device_uuid": "9a3f2c14-0000-4000-8000-000000000001",
                "device_name": "mac-studio",
                "device_platform": "darwin",
            },
            "score": 7.4,
            "matched_terms": ["release", "npm"],
            "reasons": ["lexical match on 2 terms", "project match"],
            "linked_entities": [
                {"name": "ClawHub", "type": "service", "role": "mentioned"}
            ],
            "breakdown": {
                "lexical": 4.1,
                "exact_phrase": 0.0,
                "salience": 1.2,
                "recency": 0.8,
                "trust": 0.5,
                "project": 0.8,
            },
        }
    ],
}

RECALL_EXPLAIN_EMPTY_RESPONSE = {
    "query": "release process npm",
    "project": None,
    "total_candidates": 0,
    "results": [],
}


# ── replay_incidents ──────────────────────────────────────────────────────────


@respx.mock
def test_replay_incidents(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/incidents/replay").mock(
        return_value=httpx.Response(200, json=INCIDENT_REPLAY_RESPONSE)
    )
    result = client.replay_incidents(
        from_time="2026-08-10T00:00:00.000Z",
        to="2026-08-11T00:00:00.000Z",
        device_id="9a3f2c14-0000-4000-8000-000000000001",
        source_identifier="crewai",
        project="shieldcortex",
        search="injection",
        limit=200,
    )

    params = dict(route.calls.last.request.url.params)
    assert params["from"] == "2026-08-10T00:00:00.000Z"
    assert params["to"] == "2026-08-11T00:00:00.000Z"
    assert params["device_id"] == "9a3f2c14-0000-4000-8000-000000000001"
    assert params["source_identifier"] == "crewai"
    assert params["project"] == "shieldcortex"
    assert params["search"] == "injection"
    assert params["limit"] == "200"
    assert "from_" not in params

    assert result.total == 2
    first = result.events[0]
    assert first.id == "audit:9001"
    assert first.stream == "audit"
    assert first.severity == "critical"
    assert first.event_type == "firewall_block"
    assert first.metadata == {"anomaly_score": 0.95}
    second = result.events[1]
    assert second.stream == "memory"
    assert second.memory_external_id == "ext-42"
    assert second.device_uuid is None
    assert result.summary.audit == 1
    assert result.summary.memory == 1
    assert result.coverage.sources == ["audit_logs", "synced_memories"]


@respx.mock
def test_replay_incidents_unknown_device_returns_empty_envelope(
    client: ShieldCortex,
) -> None:
    respx.get(f"{BASE}/v1/incidents/replay").mock(
        return_value=httpx.Response(200, json=INCIDENT_REPLAY_EMPTY_RESPONSE)
    )
    result = client.replay_incidents(
        device_id="00000000-0000-4000-8000-999999999999"
    )

    assert result.events == []
    assert result.total == 0
    assert result.summary.audit == 0
    assert result.summary.verification == 0
    assert "not registered" in result.coverage.note


@respx.mock
async def test_async_replay_incidents(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/incidents/replay").mock(
        return_value=httpx.Response(200, json=INCIDENT_REPLAY_RESPONSE)
    )
    result = await async_client.replay_incidents()

    params = dict(route.calls.last.request.url.params)
    assert params == {"limit": "100"}

    assert result.total == 2
    assert result.events[0].summary == "BLOCK: prompt injection in agent output"
    assert result.coverage.note.startswith("Merged timeline")


# ── explain_recall ────────────────────────────────────────────────────────────


@respx.mock
def test_explain_recall(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/recall/explain").mock(
        return_value=httpx.Response(200, json=RECALL_EXPLAIN_RESPONSE)
    )
    result = client.explain_recall(
        "release process npm",
        project="shieldcortex",
        device_id="9a3f2c14-0000-4000-8000-000000000001",
        limit=5,
    )

    params = dict(route.calls.last.request.url.params)
    assert params["query"] == "release process npm"
    assert params["project"] == "shieldcortex"
    assert params["device_id"] == "9a3f2c14-0000-4000-8000-000000000001"
    assert params["limit"] == "5"

    assert result.query == "release process npm"
    assert result.project == "shieldcortex"
    assert result.total_candidates == 37
    top = result.results[0]
    assert top.score == 7.4
    assert top.matched_terms == ["release", "npm"]
    assert top.reasons == ["lexical match on 2 terms", "project match"]
    assert top.memory.external_id == "mem-abc"
    assert top.memory.salience == 0.82
    assert top.memory.device_platform == "darwin"
    assert top.linked_entities[0].name == "ClawHub"
    assert top.linked_entities[0].role == "mentioned"
    assert top.breakdown.lexical == 4.1
    assert top.breakdown.exact_phrase == 0.0
    assert top.breakdown.project == 0.8


@respx.mock
def test_explain_recall_unknown_device_returns_empty_envelope(
    client: ShieldCortex,
) -> None:
    respx.get(f"{BASE}/v1/recall/explain").mock(
        return_value=httpx.Response(200, json=RECALL_EXPLAIN_EMPTY_RESPONSE)
    )
    result = client.explain_recall(
        "release process npm",
        device_id="00000000-0000-4000-8000-999999999999",
    )

    assert result.total_candidates == 0
    assert result.results == []
    assert result.project is None


@respx.mock
async def test_async_explain_recall(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/recall/explain").mock(
        return_value=httpx.Response(200, json=RECALL_EXPLAIN_RESPONSE)
    )
    result = await async_client.explain_recall("release process npm")

    params = dict(route.calls.last.request.url.params)
    assert params == {"query": "release process npm", "limit": "8"}

    assert result.total_candidates == 37
    assert result.results[0].memory.title == "Release alignment checklist"
    assert result.results[0].breakdown.recency == 0.8
