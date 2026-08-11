"""Tests for the /v1/sync client surface."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.errors import ShieldCortexError
from shieldcortex.types import (
    SyncGraphEntity,
    SyncGraphTriple,
    SyncMemory,
    SyncMemoryEntityLink,
)

BASE = "https://api.shieldcortex.ai"
DEVICE_ID = "9a3f2c14-0000-4000-8000-000000000001"

SYNC_HEALTH_RESPONSE = {
    "status": "ok",
    "team_id": 2,
    "required_tables": [
        "synced_memories",
        "synced_devices",
        "synced_entities",
        "synced_triples",
        "synced_memory_entities",
        "sync_ingest_events",
    ],
    "present_tables": [
        "synced_memories",
        "synced_devices",
        "synced_entities",
        "synced_triples",
        "synced_memory_entities",
        "sync_ingest_events",
    ],
    "missing_tables": [],
}

SYNC_PUSH_RESPONSE = {
    "received": 2,
    "upserted": 1,
    "deleted": 1,
    "device_id": DEVICE_ID,
}

# 402 per-plan synced-memory cap carries a `synced` usage object.
SYNC_CAP_EXCEEDED_BODY = {
    "error": "Quota Exceeded",
    "message": "Synced memory limit reached for your plan",
    "synced": {"used": 1000, "limit": 1000},
}

SYNC_MEMORIES_RESPONSE = {
    "memories": [
        {
            "external_id": "mem-001",
            "local_id": 17,
            "type": "learning",
            "category": "project",
            "title": "Release checklist",
            "content": "Always bump the version before publishing.",
            "project": "shieldcortex",
            "tags": ["release", "npm"],
            "salience": 0.8,
            "scope": "project",
            "transferable": True,
            "trust_score": 0.9,
            "sensitivity_level": "internal",
            "source": "session-end",
            "metadata": {"extractor": "stop-hook"},
            "review_status": "canonical",
            "review_note": "Verified",
            "review_assignee": "michael",
            "reviewed_at": "2026-08-09T12:00:00.000Z",
            "reviewed_by": "michael",
            "is_canonical": True,
            "created_at": "2026-08-01T10:00:00.000Z",
            "updated_at": "2026-08-09T11:00:00.000Z",
            "deleted_at": None,
            "last_synced_at": "2026-08-10T09:00:00.000Z",
            "device_uuid": DEVICE_ID,
            "device_name": "mac-studio",
            "device_platform": "darwin",
        },
        {
            "external_id": "mem-002",
            "local_id": None,
            "type": "note",
            "category": "misc",
            "title": "Tombstoned memory",
            "content": "gone",
            "project": None,
            "tags": [],
            "salience": 0.2,
            "scope": "global",
            "transferable": False,
            "trust_score": None,
            "sensitivity_level": None,
            "source": None,
            "metadata": {},
            "review_status": None,
            "review_note": None,
            "review_assignee": None,
            "reviewed_at": None,
            "reviewed_by": None,
            "is_canonical": False,
            "created_at": None,
            "updated_at": None,
            "deleted_at": "2026-08-08T08:00:00.000Z",
            "last_synced_at": None,
            "device_uuid": DEVICE_ID,
            "device_name": None,
            "device_platform": None,
        },
    ],
    "total": 2,
    "summary": {
        "total": 2,
        "deleted": 1,
        "devices": 1,
        "projects": 1,
        "last_synced_at": "2026-08-10T09:00:00.000Z",
        "last_updated_at": "2026-08-09T11:00:00.000Z",
        "health": {
            "healthy_devices": 1,
            "stale_devices": 0,
            "offline_devices": 0,
            "latest_device_sync": {
                "device_uuid": DEVICE_ID,
                "device_name": "mac-studio",
                "last_synced_at": "2026-08-10T09:00:00.000Z",
                "platform": "darwin",
            },
            "devices": [
                {
                    "device_uuid": DEVICE_ID,
                    "device_name": "mac-studio",
                    "platform": "darwin",
                    "memory_count": 2,
                    "last_seen": "2026-08-10T09:00:00.000Z",
                    "last_synced_at": "2026-08-10T09:00:00.000Z",
                    "last_updated_at": "2026-08-09T11:00:00.000Z",
                    "status": "healthy",
                }
            ],
        },
    },
    "pagination": {"limit": 50, "offset": 0, "hasMore": False},
}

# Unknown device_id → 200 with NO `summary` key at all.
SYNC_MEMORIES_UNKNOWN_DEVICE_RESPONSE = {
    "memories": [],
    "total": 0,
    "pagination": {"limit": 50, "offset": 0, "hasMore": False},
}

SYNC_GRAPH_RESPONSE = {
    "device_id": DEVICE_ID,
    "entities": 2,
    "triples": 1,
    "memory_entities": 1,
    "pruned_memories": 1,
    "orphan_entities_pruned": 0,
}


# ── get_sync_health ──────────────────────────────────────────────────────────


@respx.mock
def test_get_sync_health(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/sync/health").mock(
        return_value=httpx.Response(200, json=SYNC_HEALTH_RESPONSE)
    )
    result = client.get_sync_health()

    assert route.calls.last.request.method == "GET"
    assert result.status == "ok"
    assert result.team_id == 2
    assert len(result.required_tables) == 6
    assert result.present_tables == result.required_tables
    assert result.missing_tables == []


@respx.mock
async def test_async_get_sync_health(async_client: AsyncShieldCortex) -> None:
    respx.get(f"{BASE}/v1/sync/health").mock(
        return_value=httpx.Response(200, json=SYNC_HEALTH_RESPONSE)
    )
    result = await async_client.get_sync_health()

    assert result.status == "ok"
    assert "sync_ingest_events" in result.required_tables


# ── push_memories ────────────────────────────────────────────────────────────


@respx.mock
def test_push_memories(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(200, json=SYNC_PUSH_RESPONSE)
    )
    memories = [
        SyncMemory(
            external_id="mem-001",
            type="learning",
            category="project",
            title="Release checklist",
            content="Always bump the version before publishing.",
            created_at="2026-08-01T10:00:00.000Z",
            updated_at="2026-08-09T11:00:00.000Z",
            local_id=17,
            project="shieldcortex",
            tags=["release", "npm"],
            salience=0.8,
            scope="project",
            transferable=True,
            trust_score=0.9,
            sensitivity_level="internal",
            source="session-end",
            metadata={"extractor": "stop-hook"},
        ),
        SyncMemory(
            external_id="mem-002",
            type="note",
            category="misc",
            title="Tombstoned memory",
            content="gone",
            created_at="2026-08-01T10:00:00.000Z",
            updated_at="2026-08-08T08:00:00.000Z",
            deleted_at="2026-08-08T08:00:00.000Z",
        ),
    ]
    result = client.push_memories(
        memories,
        device_id=DEVICE_ID,
        device_name="mac-studio",
        platform="darwin",
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload["device"] == {
        "device_id": DEVICE_ID,
        "device_name": "mac-studio",
        "platform": "darwin",
    }
    assert len(payload["memories"]) == 2
    first = payload["memories"][0]
    assert first["external_id"] == "mem-001"
    assert first["local_id"] == 17
    assert first["type"] == "learning"
    assert first["category"] == "project"
    assert first["title"] == "Release checklist"
    assert first["content"] == "Always bump the version before publishing."
    assert first["project"] == "shieldcortex"
    assert first["tags"] == ["release", "npm"]
    assert first["salience"] == 0.8
    assert first["scope"] == "project"
    assert first["transferable"] is True
    assert first["trust_score"] == 0.9
    assert first["sensitivity_level"] == "internal"
    assert first["source"] == "session-end"
    assert first["metadata"] == {"extractor": "stop-hook"}
    assert first["created_at"] == "2026-08-01T10:00:00.000Z"
    assert first["updated_at"] == "2026-08-09T11:00:00.000Z"
    assert "deleted_at" not in first
    second = payload["memories"][1]
    assert second["deleted_at"] == "2026-08-08T08:00:00.000Z"
    # Unset optionals are omitted from the wire, not sent as null.
    assert "project" not in second
    assert "local_id" not in second

    assert result.received == 2
    assert result.upserted == 1
    assert result.deleted == 1
    assert result.device_id == DEVICE_ID


@respx.mock
def test_push_memories_cap_surfaces_synced_usage(client: ShieldCortex) -> None:
    respx.post(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(402, json=SYNC_CAP_EXCEEDED_BODY)
    )
    with pytest.raises(ShieldCortexError) as exc_info:
        client.push_memories(
            [
                SyncMemory(
                    external_id="mem-003",
                    type="note",
                    category="misc",
                    title="t",
                    content="c",
                    created_at="2026-08-01T10:00:00.000Z",
                    updated_at="2026-08-01T10:00:00.000Z",
                )
            ],
            device_id=DEVICE_ID,
        )

    assert exc_info.value.status_code == 402
    body = json.loads(exc_info.value.body)
    assert body["error"] == "Quota Exceeded"
    assert body["synced"]["used"] == 1000
    assert body["synced"]["limit"] == 1000


@respx.mock
async def test_async_push_memories(async_client: AsyncShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(200, json=SYNC_PUSH_RESPONSE)
    )
    result = await async_client.push_memories(
        [
            SyncMemory(
                external_id="mem-001",
                type="learning",
                category="project",
                title="Release checklist",
                content="Always bump the version.",
                created_at="2026-08-01T10:00:00.000Z",
                updated_at="2026-08-09T11:00:00.000Z",
            )
        ],
        device_id=DEVICE_ID,
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload["device"] == {"device_id": DEVICE_ID}
    assert payload["memories"][0]["external_id"] == "mem-001"

    assert result.upserted == 1
    assert result.deleted == 1


# ── list_synced_memories ─────────────────────────────────────────────────────


@respx.mock
def test_list_synced_memories(client: ShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(200, json=SYNC_MEMORIES_RESPONSE)
    )
    result = client.list_synced_memories(
        device_id=DEVICE_ID,
        project="shieldcortex",
        search="release",
        include_deleted=True,
        limit=50,
        offset=0,
    )

    params = dict(route.calls.last.request.url.params)
    assert params["device_id"] == DEVICE_ID
    assert params["project"] == "shieldcortex"
    assert params["search"] == "release"
    assert params["include_deleted"] == "true"
    assert params["limit"] == "50"
    assert params["offset"] == "0"

    assert result.total == 2
    assert result.pagination.has_more is False
    first = result.memories[0]
    assert first.external_id == "mem-001"
    assert first.local_id == 17
    assert first.tags == ["release", "npm"]
    assert first.review_status == "canonical"
    assert first.is_canonical is True
    assert first.metadata == {"extractor": "stop-hook"}
    assert first.device_uuid == DEVICE_ID
    assert first.device_platform == "darwin"
    second = result.memories[1]
    assert second.deleted_at == "2026-08-08T08:00:00.000Z"
    assert second.local_id is None
    assert second.review_status is None

    assert result.summary is not None
    assert result.summary.total == 2
    assert result.summary.deleted == 1
    assert result.summary.devices == 1
    assert result.summary.health.healthy_devices == 1
    assert result.summary.health.latest_device_sync is not None
    assert result.summary.health.latest_device_sync.device_uuid == DEVICE_ID
    assert result.summary.health.devices[0].status == "healthy"
    assert result.summary.health.devices[0].memory_count == 2


@respx.mock
def test_list_synced_memories_unknown_device_omits_summary(
    client: ShieldCortex,
) -> None:
    respx.get(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(200, json=SYNC_MEMORIES_UNKNOWN_DEVICE_RESPONSE)
    )
    result = client.list_synced_memories(
        device_id="00000000-0000-4000-8000-000000000000"
    )

    assert result.memories == []
    assert result.total == 0
    assert result.pagination.has_more is False
    # The API omits the entire `summary` key on the unknown-device branch.
    assert result.summary is None


@respx.mock
async def test_async_list_synced_memories(async_client: AsyncShieldCortex) -> None:
    route = respx.get(f"{BASE}/v1/sync/memories").mock(
        return_value=httpx.Response(200, json=SYNC_MEMORIES_RESPONSE)
    )
    result = await async_client.list_synced_memories()

    params = dict(route.calls.last.request.url.params)
    assert params == {"limit": "50", "offset": "0"}

    assert result.total == 2
    assert result.memories[0].title == "Release checklist"
    assert result.summary is not None
    assert result.summary.health.stale_devices == 0


# ── push_memory_graph ────────────────────────────────────────────────────────


@respx.mock
def test_push_memory_graph(client: ShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/sync/graph").mock(
        return_value=httpx.Response(200, json=SYNC_GRAPH_RESPONSE)
    )
    result = client.push_memory_graph(
        device_id=DEVICE_ID,
        device_name="mac-studio",
        platform="darwin",
        entities=[
            SyncGraphEntity(
                external_id="ent-001",
                name="ShieldCortex",
                type="project",
                aliases=["SC"],
                first_seen="2026-08-01T10:00:00.000Z",
                memory_count=3,
            ),
            SyncGraphEntity(external_id="ent-002", name="Fly.io", type="service"),
        ],
        triples=[
            SyncGraphTriple(
                external_id="tri-001",
                subject_external_id="ent-001",
                predicate="deployed_on",
                object_external_id="ent-002",
                source_memory_external_id="mem-001",
                confidence=0.95,
                created_at="2026-08-09T11:00:00.000Z",
            )
        ],
        memory_entities=[
            SyncMemoryEntityLink(
                memory_external_id="mem-001",
                entity_external_id="ent-001",
                role="subject",
            )
        ],
        prune_memory_external_ids=["mem-old"],
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload["device"] == {
        "device_id": DEVICE_ID,
        "device_name": "mac-studio",
        "platform": "darwin",
    }
    assert payload["entities"][0] == {
        "external_id": "ent-001",
        "name": "ShieldCortex",
        "type": "project",
        "aliases": ["SC"],
        "first_seen": "2026-08-01T10:00:00.000Z",
        "memory_count": 3,
    }
    assert payload["entities"][1] == {
        "external_id": "ent-002",
        "name": "Fly.io",
        "type": "service",
    }
    assert payload["triples"][0] == {
        "external_id": "tri-001",
        "subject_external_id": "ent-001",
        "predicate": "deployed_on",
        "object_external_id": "ent-002",
        "source_memory_external_id": "mem-001",
        "confidence": 0.95,
        "created_at": "2026-08-09T11:00:00.000Z",
    }
    assert payload["memory_entities"][0] == {
        "memory_external_id": "mem-001",
        "entity_external_id": "ent-001",
        "role": "subject",
    }
    assert payload["prune_memory_external_ids"] == ["mem-old"]

    assert result.device_id == DEVICE_ID
    assert result.entities == 2
    assert result.triples == 1
    assert result.memory_entities == 1
    assert result.pruned_memories == 1
    assert result.orphan_entities_pruned == 0


@respx.mock
async def test_async_push_memory_graph(async_client: AsyncShieldCortex) -> None:
    route = respx.post(f"{BASE}/v1/sync/graph").mock(
        return_value=httpx.Response(200, json=SYNC_GRAPH_RESPONSE)
    )
    result = await async_client.push_memory_graph(
        device_id=DEVICE_ID,
        prune_memory_external_ids=["mem-old"],
    )

    payload = json.loads(route.calls.last.request.read())
    assert payload["device"] == {"device_id": DEVICE_ID}
    # Absent arrays are omitted (the API defaults them to empty).
    assert "entities" not in payload
    assert "triples" not in payload
    assert "memory_entities" not in payload
    assert payload["prune_memory_external_ids"] == ["mem-old"]

    assert result.pruned_memories == 1
