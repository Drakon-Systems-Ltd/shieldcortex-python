"""Tests for auto-pagination."""

from __future__ import annotations

import httpx
import respx

from shieldcortex import AuditQuery, ShieldCortex

BASE = "https://api.shieldcortex.ai"


def _make_page(entries: list, has_more: bool, offset: int = 0) -> dict:
    return {
        "logs": entries,
        "total": 5,
        "pagination": {"limit": 2, "offset": offset, "hasMore": has_more},
    }


def _make_entry(id: int) -> dict:
    return {
        "id": id,
        "timestamp": f"2026-02-15T10:0{id}:00.000Z",
        "source_type": "user",
        "source_identifier": "test",
        "trust_score": 0.95,
        "sensitivity_level": "PUBLIC",
        "firewall_result": "ALLOW",
        "anomaly_score": 0.01,
        "threat_indicators": [],
        "reason": "OK",
        "pipeline_duration_ms": 10,
    }


@respx.mock
def test_iter_audit_logs_single_page() -> None:
    """Single page with has_more=False should yield all entries and stop."""
    respx.get(f"{BASE}/v1/audit").mock(
        return_value=httpx.Response(
            200,
            json=_make_page([_make_entry(1), _make_entry(2)], has_more=False),
        )
    )
    client = ShieldCortex(api_key="sc_test_abc")
    entries = list(client.iter_audit_logs(page_size=2))

    assert len(entries) == 2
    assert entries[0].id == 1
    assert entries[1].id == 2


@respx.mock
def test_iter_audit_logs_multiple_pages() -> None:
    """Should fetch multiple pages until has_more=False."""
    route = respx.get(f"{BASE}/v1/audit")

    # First call: page 1
    route.side_effect = [
        httpx.Response(
            200,
            json=_make_page([_make_entry(1), _make_entry(2)], has_more=True, offset=0),
        ),
        httpx.Response(
            200,
            json=_make_page(
                [_make_entry(3), _make_entry(4)], has_more=True, offset=2
            ),
        ),
        httpx.Response(
            200,
            json=_make_page([_make_entry(5)], has_more=False, offset=4),
        ),
    ]

    client = ShieldCortex(api_key="sc_test_abc")
    entries = list(client.iter_audit_logs(page_size=2))

    assert len(entries) == 5
    assert [e.id for e in entries] == [1, 2, 3, 4, 5]


@respx.mock
def test_iter_audit_logs_empty() -> None:
    """Empty first page should yield nothing."""
    respx.get(f"{BASE}/v1/audit").mock(
        return_value=httpx.Response(
            200, json=_make_page([], has_more=False)
        )
    )
    client = ShieldCortex(api_key="sc_test_abc")
    entries = list(client.iter_audit_logs())

    assert entries == []


@respx.mock
def test_iter_audit_logs_preserves_query() -> None:
    """Query filters should be passed through on each page fetch."""
    route = respx.get(f"{BASE}/v1/audit").mock(
        return_value=httpx.Response(
            200, json=_make_page([_make_entry(1)], has_more=False)
        )
    )
    client = ShieldCortex(api_key="sc_test_abc")
    query = AuditQuery(level="BLOCK", source="agent")
    list(client.iter_audit_logs(query, page_size=50))

    request = route.calls.last.request
    assert "level=BLOCK" in str(request.url)
    assert "source=agent" in str(request.url)
