"""Shared request payload/param builders for the sync and async clients.

Each builder returns the exact wire dict for one endpoint, so the two client
classes stay thin transport wrappers around identical request construction
and cannot drift. Covers the lockstep-0.2.0 route groups only (verify,
skills, threats, incidents, recall) — pre-existing groups build inline.
"""

from __future__ import annotations

from typing import Any, Literal

from shieldcortex._http import serialize_snake
from shieldcortex.types import SkillScanFile

# ── Verification ──────────────────────────────────────────────────────────────


def verify_submit_payload(
    content: str,
    *,
    source_type: str,
    source_identifier: str,
    anomaly_score: float,
    pipeline_result: Literal["ALLOW", "BLOCK", "QUARANTINE"],
    title: str | None = None,
    trust_score: float | None = None,
    threat_indicators: list[str] | None = None,
    device_id: str | None = None,
    device_name: str | None = None,
    mode: Literal["sync", "async"] = "sync",
) -> dict[str, Any]:
    """Body for POST /v1/verify."""
    payload: dict[str, Any] = {
        "content": content,
        "source_type": source_type,
        "source_identifier": source_identifier,
        "anomaly_score": anomaly_score,
        "pipeline_result": pipeline_result,
        "mode": mode,
    }
    if title is not None:
        payload["title"] = title
    if trust_score is not None:
        payload["trust_score"] = trust_score
    if threat_indicators is not None:
        payload["threat_indicators"] = threat_indicators
    if device_id is not None:
        payload["device_id"] = device_id
    if device_name is not None:
        payload["device_name"] = device_name
    return payload


def verification_list_params(
    *,
    from_time: str | None = None,
    to: str | None = None,
    status: Literal["pending", "completed", "failed", "cached"] | None = None,
    verdict: Literal["SAFE", "SUSPICIOUS", "THREAT"] | None = None,
    source: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, str]:
    """Query params for GET /v1/verify (``from_time`` maps to wire ``from``)."""
    params: dict[str, str] = {"limit": str(limit), "offset": str(offset)}
    if from_time is not None:
        params["from"] = from_time
    if to is not None:
        params["to"] = to
    if status is not None:
        params["status"] = status
    if verdict is not None:
        params["verdict"] = verdict
    if source is not None:
        params["source"] = source
    if search is not None:
        params["search"] = search
    return params


# ── Skills ────────────────────────────────────────────────────────────────────


def skill_ingest_payload(
    files: list[SkillScanFile],
    *,
    device_id: str | None = None,
    device_name: str | None = None,
    platform: str | None = None,
    scanned_at: str | None = None,
) -> dict[str, Any]:
    """Body for POST /v1/skills/ingest (snake_case wire, matchedText wart)."""
    payload: dict[str, Any] = {"files": serialize_snake(files)}
    if device_id is not None:
        payload["device_id"] = device_id
    if device_name is not None:
        payload["device_name"] = device_name
    if platform is not None:
        payload["platform"] = platform
    if scanned_at is not None:
        payload["scanned_at"] = scanned_at
    return payload


def skill_list_params(*, device_id: str | None = None) -> dict[str, str]:
    """Query params for GET /v1/skills."""
    params: dict[str, str] = {}
    if device_id is not None:
        params["device_id"] = device_id
    return params


# ── Threats ───────────────────────────────────────────────────────────────────


def threat_report_payload(
    events: dict[str, Any] | list[dict[str, Any]],
) -> dict[str, Any]:
    """Body for POST /v1/threats — always the canonical events envelope."""
    if isinstance(events, dict):
        events = [events]
    return {"events": events}


# ── Incidents ─────────────────────────────────────────────────────────────────


def incident_replay_params(
    *,
    from_time: str | None = None,
    to: str | None = None,
    device_id: str | None = None,
    source_identifier: str | None = None,
    project: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> dict[str, str]:
    """Query params for GET /v1/incidents/replay (``from_time`` → wire ``from``)."""
    params: dict[str, str] = {"limit": str(limit)}
    if from_time is not None:
        params["from"] = from_time
    if to is not None:
        params["to"] = to
    if device_id is not None:
        params["device_id"] = device_id
    if source_identifier is not None:
        params["source_identifier"] = source_identifier
    if project is not None:
        params["project"] = project
    if search is not None:
        params["search"] = search
    return params


# ── Recall ────────────────────────────────────────────────────────────────────


def recall_explain_params(
    query: str,
    *,
    project: str | None = None,
    device_id: str | None = None,
    limit: int = 8,
) -> dict[str, str]:
    """Query params for GET /v1/recall/explain."""
    params: dict[str, str] = {"query": query, "limit": str(limit)}
    if project is not None:
        params["project"] = project
    if device_id is not None:
        params["device_id"] = device_id
    return params
