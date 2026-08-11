"""Synchronous ShieldCortex API client.

Usage:
    from shieldcortex import ShieldCortex

    client = ShieldCortex(api_key="sc_live_...")
    result = client.scan("user input here")
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal, TypeVar

import httpx

from shieldcortex._http import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    build_headers,
    deserialize,
    raise_for_status,
    serialize,
    serialize_query,
    serialize_snake,
)
from shieldcortex.errors import ShieldCortexError
from shieldcortex.types import (
    AlertRule,
    AuditEntry,
    AuditQuery,
    AuditResponse,
    AuditStats,
    BatchItem,
    BatchResult,
    CheckoutResponse,
    CreateKeyResponse,
    CreateWebhookResponse,
    DeleteVerificationResponse,
    Device,
    FirewallRule,
    IncidentReplayResponse,
    InjectionPattern,
    InjectionPatternsResponse,
    Invite,
    InviteListResponse,
    IronDomePoliciesResponse,
    IronDomePolicy,
    KeyListResponse,
    MembersResponse,
    PatternSyncResponse,
    PatternTestResult,
    PolicySyncResponse,
    PortalResponse,
    QuarantineItem,
    QuarantineQuery,
    QuarantineResponse,
    RecallExplainResponse,
    ReviewResponse,
    ScanConfig,
    ScanResult,
    ScanSource,
    SkillIngestResponse,
    SkillScanFile,
    SkillScanListResponse,
    SkillScanResult,
    TeamInfo,
    TestWebhookResponse,
    ThreatReportResponse,
    TrendResponse,
    UsageResponse,
    VerificationDetail,
    VerificationListResponse,
    VerificationResult,
    VerificationStats,
    Webhook,
    WebhookDelivery,
)

T = TypeVar("T")


class ShieldCortex:
    """Synchronous ShieldCortex API client.

    Example::

        from shieldcortex import ShieldCortex

        with ShieldCortex(api_key="sc_live_...") as client:
            result = client.scan("user input")
            if not result.allowed:
                print(f"Blocked: {result.firewall.reason}")
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            timeout=timeout,
            headers=build_headers(api_key),
        )

    def __enter__(self) -> ShieldCortex:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan(
        self,
        content: str,
        *,
        title: str | None = None,
        source: ScanSource | None = None,
        config: ScanConfig | None = None,
    ) -> ScanResult:
        """Scan content through the 6-layer defence pipeline."""
        payload: dict[str, Any] = {"content": content}
        if title is not None:
            payload["title"] = title
        if source is not None:
            payload["source"] = serialize(source)
        if config is not None:
            payload["config"] = serialize(config)
        return self._post("/v1/scan", payload, ScanResult)

    def scan_batch(
        self,
        items: list[BatchItem],
        *,
        source: ScanSource | None = None,
        config: ScanConfig | None = None,
    ) -> BatchResult:
        """Scan up to 100 items in a single request."""
        payload: dict[str, Any] = {"items": serialize(items)}
        if source is not None:
            payload["source"] = serialize(source)
        if config is not None:
            payload["config"] = serialize(config)
        return self._post("/v1/scan/batch", payload, BatchResult)

    def scan_skill(
        self,
        content: str,
        *,
        format: str = "skill-md",
        name: str | None = None,
        mode: Literal["strict", "balanced", "permissive"] = "balanced",
    ) -> SkillScanResult:
        """Scan an AI agent skill/instruction file for threats."""
        payload: dict[str, Any] = {"content": content, "format": format, "mode": mode}
        if name is not None:
            payload["name"] = name
        return self._post("/v1/scan/skill", payload, SkillScanResult)

    # ── Audit ─────────────────────────────────────────────────────────────────

    def get_audit_logs(
        self, query: AuditQuery | None = None
    ) -> AuditResponse:
        """Query audit logs with optional filters and pagination."""
        params = serialize_query(query) if query else {}
        return self._get("/v1/audit", params, AuditResponse)

    def get_audit_entry(self, id: int) -> AuditEntry:
        """Get a single audit log entry by ID."""
        return self._get(f"/v1/audit/{id}", {}, AuditEntry)

    def get_audit_stats(
        self,
        *,
        time_range: Literal["24h", "7d", "30d"] = "24h",
        device_id: str | None = None,
        source: str | None = None,
    ) -> AuditStats:
        """Get audit summary statistics."""
        params: dict[str, str] = {"timeRange": time_range}
        if device_id is not None:
            params["device_id"] = device_id
        if source is not None:
            params["source"] = source
        return self._get("/v1/audit/stats", params, AuditStats)

    def get_audit_trends(
        self,
        *,
        time_range: Literal["24h", "7d", "30d"] = "24h",
        device_id: str | None = None,
        source: str | None = None,
    ) -> TrendResponse:
        """Get time-bucketed audit trend data."""
        params: dict[str, str] = {"timeRange": time_range}
        if device_id is not None:
            params["device_id"] = device_id
        if source is not None:
            params["source"] = source
        return self._get("/v1/audit/trends", params, TrendResponse)

    def export_audit_logs(
        self,
        *,
        format: Literal["json", "csv"] = "json",
        query: AuditQuery | None = None,
    ) -> str:
        """Export audit logs as JSON or CSV string."""
        params: dict[str, str] = {"format": format}
        if query:
            params.update(serialize_query(query))
        response = self._raw_get("/v1/audit/export", params)
        return response.text

    def iter_audit_logs(
        self,
        query: AuditQuery | None = None,
        *,
        page_size: int = 100,
    ) -> Iterable[AuditEntry]:
        """Iterate all matching audit logs with automatic pagination.

        Example::

            for entry in client.iter_audit_logs():
                print(entry.id, entry.firewall_result)
        """
        from shieldcortex.pagination import AuditPaginator

        return AuditPaginator(self, query or AuditQuery(), page_size)

    # ── Quarantine ────────────────────────────────────────────────────────────

    def get_quarantine(
        self, query: QuarantineQuery | None = None
    ) -> QuarantineResponse:
        """List quarantined items."""
        params = serialize_query(query) if query else {}
        return self._get("/v1/quarantine", params, QuarantineResponse)

    def get_quarantine_item(self, id: int) -> QuarantineItem:
        """Get a single quarantine item (includes full content)."""
        return self._get(f"/v1/quarantine/{id}", {}, QuarantineItem)

    def review_quarantine_item(
        self, id: int, action: Literal["approve", "reject"]
    ) -> ReviewResponse:
        """Approve or reject a quarantined item."""
        return self._post(
            f"/v1/quarantine/{id}/review", {"action": action}, ReviewResponse
        )

    # ── API Keys ──────────────────────────────────────────────────────────────

    def create_api_key(
        self,
        name: str,
        *,
        scopes: list[str] | None = None,
        expires_in: int | None = None,
        is_test: bool = False,
    ) -> CreateKeyResponse:
        """Create a new API key. The raw key is only returned once."""
        payload: dict[str, Any] = {"name": name, "isTest": is_test}
        if scopes is not None:
            payload["scopes"] = scopes
        if expires_in is not None:
            payload["expiresIn"] = expires_in
        return self._post("/v1/keys", payload, CreateKeyResponse)

    def list_api_keys(self) -> KeyListResponse:
        """List all API keys for the team."""
        return self._get("/v1/keys", {}, KeyListResponse)

    def revoke_api_key(self, id: int) -> None:
        """Revoke an API key."""
        self._raw_delete(f"/v1/keys/{id}")

    # ── Teams ─────────────────────────────────────────────────────────────────

    def get_team(self) -> TeamInfo:
        """Get current team information."""
        return self._get("/v1/teams", {}, TeamInfo)

    def update_team(self, name: str) -> None:
        """Update team name."""
        self._raw_patch("/v1/teams", {"name": name})

    def get_team_members(self) -> MembersResponse:
        """List team members."""
        return self._get("/v1/teams/members", {}, MembersResponse)

    def get_usage(self) -> UsageResponse:
        """Get current billing period usage statistics."""
        return self._get("/v1/teams/usage", {}, UsageResponse)

    # ── Invites ───────────────────────────────────────────────────────────────

    def create_invite(
        self,
        email: str,
        *,
        role: Literal["admin", "member"] = "member",
    ) -> Invite:
        """Create a team invitation."""
        data = self._post_raw("/v1/invites", {"email": email, "role": role})
        return deserialize(data.get("invite", data), Invite)

    def list_invites(self) -> InviteListResponse:
        """List all team invitations."""
        return self._get("/v1/invites", {}, InviteListResponse)

    def delete_invite(self, id: int) -> None:
        """Revoke a pending team invitation."""
        self._raw_delete(f"/v1/invites/{id}")

    def resend_invite(self, id: int) -> None:
        """Resend invitation email."""
        self._raw_post(f"/v1/invites/{id}/resend", {})

    # ── Billing ───────────────────────────────────────────────────────────────

    def create_checkout_session(self) -> CheckoutResponse:
        """Create a Stripe checkout session for plan upgrade."""
        return self._post("/v1/billing/checkout", {}, CheckoutResponse)

    def create_portal_session(self) -> PortalResponse:
        """Create a Stripe billing portal session."""
        return self._post("/v1/billing/portal", {}, PortalResponse)

    # ── Devices ───────────────────────────────────────────────────────────────

    def get_devices(self) -> list[Device]:
        """List all registered devices for the team."""
        response = self._raw_get("/v1/devices", {})
        data = response.json()
        items = data.get("devices", data) if isinstance(data, dict) else data
        return [deserialize(d, Device) for d in items]

    def register_device(
        self,
        device_id: str,
        *,
        device_name: str | None = None,
        platform: str | None = None,
    ) -> None:
        """Register or update a device."""
        payload: dict[str, Any] = {"device_id": device_id}
        if device_name is not None:
            payload["device_name"] = device_name
        if platform is not None:
            payload["platform"] = platform
        self._raw_post("/v1/devices", payload)

    def update_device(self, uuid: str, name: str) -> None:
        """Rename a device."""
        self._raw_patch(f"/v1/devices/{uuid}", {"name": name})

    def device_heartbeat(
        self,
        device_id: str,
        *,
        device_name: str | None = None,
        platform: str | None = None,
    ) -> None:
        """Send a device heartbeat to keep it marked as online."""
        payload: dict[str, Any] = {"device_id": device_id}
        if device_name is not None:
            payload["device_name"] = device_name
        if platform is not None:
            payload["platform"] = platform
        self._raw_post("/v1/devices/heartbeat", payload)

    # ── Alerts ────────────────────────────────────────────────────────────────

    def get_alerts(self) -> list[AlertRule]:
        """List all alert rules."""
        response = self._raw_get("/v1/alerts", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, AlertRule) for r in items]

    def create_alert(
        self,
        name: str,
        email_recipients: list[str],
        *,
        trigger_on_block: bool = True,
        trigger_on_quarantine: bool = False,
        trigger_on_anomaly_above: float | None = None,
    ) -> AlertRule:
        """Create a new alert rule."""
        payload: dict[str, Any] = {
            "name": name,
            "trigger_on_block": trigger_on_block,
            "trigger_on_quarantine": trigger_on_quarantine,
            "email_recipients": email_recipients,
        }
        if trigger_on_anomaly_above is not None:
            payload["trigger_on_anomaly_above"] = trigger_on_anomaly_above
        return self._post("/v1/alerts", payload, AlertRule)

    def update_alert(self, id: int, **kwargs: Any) -> AlertRule:
        """Update an alert rule. Pass only the fields to change."""
        return self._patch(f"/v1/alerts/{id}", kwargs, AlertRule)

    def delete_alert(self, id: int) -> None:
        """Delete an alert rule."""
        self._raw_delete(f"/v1/alerts/{id}")

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def get_webhooks(self) -> list[Webhook]:
        """List all webhooks."""
        response = self._raw_get("/v1/webhooks", {})
        data = response.json()
        items = data.get("webhooks", [])
        return [deserialize(w, Webhook) for w in items]

    def create_webhook(
        self,
        name: str,
        url: str,
        events: list[str],
    ) -> CreateWebhookResponse:
        """Create a new webhook. The secret is only returned once."""
        return self._post(
            "/v1/webhooks",
            {"name": name, "url": url, "events": events},
            CreateWebhookResponse,
        )

    def update_webhook(self, id: int, **kwargs: Any) -> Webhook:
        """Update a webhook. Pass only the fields to change."""
        return self._patch(f"/v1/webhooks/{id}", kwargs, Webhook)

    def delete_webhook(self, id: int) -> None:
        """Delete a webhook."""
        self._raw_delete(f"/v1/webhooks/{id}")

    def test_webhook(self, id: int) -> TestWebhookResponse:
        """Send a test ping to a webhook."""
        return self._post(f"/v1/webhooks/{id}/test", {}, TestWebhookResponse)

    def get_webhook_deliveries(self, id: int) -> list[WebhookDelivery]:
        """Get recent deliveries for a webhook."""
        response = self._raw_get(f"/v1/webhooks/{id}/deliveries", {})
        data = response.json()
        items = data.get("deliveries", [])
        return [deserialize(d, WebhookDelivery) for d in items]

    # ── Firewall Rules ────────────────────────────────────────────────────────

    def get_firewall_rules(self) -> list[FirewallRule]:
        """List all custom firewall rules."""
        response = self._raw_get("/v1/firewall-rules", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, FirewallRule) for r in items]

    def get_active_firewall_rules(self) -> list[FirewallRule]:
        """List enabled firewall rules ordered by priority."""
        response = self._raw_get("/v1/firewall-rules/active", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, FirewallRule) for r in items]

    def create_firewall_rule(self, **kwargs: Any) -> FirewallRule:
        """Create a new custom firewall rule."""
        return self._post("/v1/firewall-rules", kwargs, FirewallRule)

    def update_firewall_rule(self, id: int, **kwargs: Any) -> FirewallRule:
        """Update a firewall rule. Pass only the fields to change."""
        return self._patch(
            f"/v1/firewall-rules/{id}", kwargs, FirewallRule
        )

    def delete_firewall_rule(self, id: int) -> None:
        """Delete a firewall rule."""
        self._raw_delete(f"/v1/firewall-rules/{id}")

    # ── Iron Dome Patterns (Pro+) ────────────────────────────────────────────

    def get_injection_patterns(self) -> InjectionPatternsResponse:
        """List all custom injection patterns."""
        return self._get(
            "/v1/iron-dome/patterns", {}, InjectionPatternsResponse
        )

    def get_injection_patterns_sync(self) -> PatternSyncResponse:
        """Get enabled patterns for local sync."""
        return self._get(
            "/v1/iron-dome/patterns/sync", {}, PatternSyncResponse
        )

    def create_injection_pattern(
        self,
        pattern: str,
        category: str,
        severity: Literal["critical", "high", "medium", "low"],
        description: str,
        test_string: str,
    ) -> InjectionPattern:
        """Create a custom injection pattern."""
        return self._post(
            "/v1/iron-dome/patterns",
            {
                "pattern": pattern,
                "category": category,
                "severity": severity,
                "description": description,
                "test_string": test_string,
            },
            InjectionPattern,
        )

    def update_injection_pattern(
        self, id: int, **kwargs: Any
    ) -> InjectionPattern:
        """Update a pattern. Pass only the fields to change."""
        return self._patch(
            f"/v1/iron-dome/patterns/{id}", kwargs, InjectionPattern
        )

    def test_injection_pattern(
        self, id: int, text: str
    ) -> PatternTestResult:
        """Test a pattern against sample text."""
        return self._post(
            f"/v1/iron-dome/patterns/{id}/test",
            {"text": text},
            PatternTestResult,
        )

    def delete_injection_pattern(self, id: int) -> None:
        """Delete a custom injection pattern."""
        self._raw_delete(f"/v1/iron-dome/patterns/{id}")

    # ── Iron Dome Policies (Pro+) ──────────────────────────────────────────

    def get_iron_dome_policies(self) -> IronDomePoliciesResponse:
        """List all Iron Dome policies."""
        return self._get(
            "/v1/iron-dome/policies", {}, IronDomePoliciesResponse
        )

    def get_iron_dome_policy_sync(self) -> PolicySyncResponse:
        """Get the default policy for local sync."""
        return self._get(
            "/v1/iron-dome/policies/sync", {}, PolicySyncResponse
        )

    def create_iron_dome_policy(
        self,
        name: str,
        base_profile: Literal[
            "school", "enterprise", "personal", "paranoid"
        ],
        *,
        config_overrides: dict[str, Any] | None = None,
        is_default: bool = False,
    ) -> IronDomePolicy:
        """Create an Iron Dome policy."""
        payload: dict[str, Any] = {
            "name": name,
            "base_profile": base_profile,
            "is_default": is_default,
        }
        if config_overrides is not None:
            payload["config_overrides"] = config_overrides
        return self._post(
            "/v1/iron-dome/policies", payload, IronDomePolicy
        )

    def update_iron_dome_policy(
        self, id: int, **kwargs: Any
    ) -> IronDomePolicy:
        """Update a policy. Pass only the fields to change."""
        return self._patch(
            f"/v1/iron-dome/policies/{id}", kwargs, IronDomePolicy
        )

    def set_default_iron_dome_policy(self, id: int) -> IronDomePolicy:
        """Set a policy as the team default."""
        response = self._raw_put(
            f"/v1/iron-dome/policies/{id}/default", {}
        )
        return deserialize(response.json(), IronDomePolicy)

    def delete_iron_dome_policy(self, id: int) -> None:
        """Delete an Iron Dome policy."""
        self._raw_delete(f"/v1/iron-dome/policies/{id}")

    # ── Verification (Enterprise) ─────────────────────────────────────────────

    def submit_verification(
        self,
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
    ) -> VerificationResult:
        """Submit content for LLM verification. Synchronous — the verdict
        is returned inline (200, not 201)."""
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
        return self._post("/v1/verify", payload, VerificationResult)

    def list_verifications(
        self,
        *,
        from_time: str | None = None,
        to: str | None = None,
        status: Literal["pending", "completed", "failed", "cached"] | None = None,
        verdict: Literal["SAFE", "SUSPICIOUS", "THREAT"] | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> VerificationListResponse:
        """List verification requests with optional filters and pagination."""
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
        return self._get("/v1/verify", params, VerificationListResponse)

    def get_verification_stats(self) -> VerificationStats:
        """Get today's verification counts and daily quota usage."""
        return self._get("/v1/verify/stats", {}, VerificationStats)

    def get_verification(self, id: int) -> VerificationDetail:
        """Get a single verification by ID (polling target for pending)."""
        return self._get(f"/v1/verify/{id}", {}, VerificationDetail)

    def delete_verification(self, id: int) -> DeleteVerificationResponse:
        """Delete a verification record (admin scope)."""
        response = self._raw_delete(f"/v1/verify/{id}")
        return deserialize(response.json(), DeleteVerificationResponse)

    # ── Skills ────────────────────────────────────────────────────────────────

    def ingest_skill_scans(
        self,
        files: list[SkillScanFile],
        *,
        device_id: str | None = None,
        device_name: str | None = None,
        platform: str | None = None,
        scanned_at: str | None = None,
    ) -> SkillIngestResponse:
        """Bulk ingest skill scan results (upsert keyed on device + file path)."""
        payload: dict[str, Any] = {"files": serialize_snake(files)}
        if device_id is not None:
            payload["device_id"] = device_id
        if device_name is not None:
            payload["device_name"] = device_name
        if platform is not None:
            payload["platform"] = platform
        if scanned_at is not None:
            payload["scanned_at"] = scanned_at
        return self._post("/v1/skills/ingest", payload, SkillIngestResponse)

    def list_skill_scans(
        self, *, device_id: str | None = None
    ) -> SkillScanListResponse:
        """List synced skill scans (newest first, hard cap 200 — no pagination)."""
        params: dict[str, str] = {}
        if device_id is not None:
            params["device_id"] = device_id
        return self._get("/v1/skills", params, SkillScanListResponse)

    # ── Threats ───────────────────────────────────────────────────────────────

    def report_threat(
        self, events: dict[str, Any] | list[dict[str, Any]]
    ) -> ThreatReportResponse:
        """Report realtime threat events (OpenClaw compat shim, max 100).

        Prefer POST /v1/audit/ingest for canonical audit entries; this
        endpoint best-effort maps loose event payloads.
        """
        if isinstance(events, dict):
            events = [events]
        return self._post("/v1/threats", {"events": events}, ThreatReportResponse)

    # ── Incidents ─────────────────────────────────────────────────────────────

    def replay_incidents(
        self,
        *,
        from_time: str | None = None,
        to: str | None = None,
        device_id: str | None = None,
        source_identifier: str | None = None,
        project: str | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> IncidentReplayResponse:
        """Replay a merged incident timeline across the audit, verification,
        sync and memory streams. ``from_time``/``to`` map to the API's
        ``from``/``to`` ISO datetime params."""
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
        return self._get("/v1/incidents/replay", params, IncidentReplayResponse)

    # ── Recall ────────────────────────────────────────────────────────────────

    def explain_recall(
        self,
        query: str,
        *,
        project: str | None = None,
        device_id: str | None = None,
        limit: int = 8,
    ) -> RecallExplainResponse:
        """Explain how a recall query ranks synced memories, with per-result
        score breakdowns."""
        params: dict[str, str] = {"query": query, "limit": str(limit)}
        if project is not None:
            params["project"] = project
        if device_id is not None:
            params["device_id"] = device_id
        return self._get("/v1/recall/explain", params, RecallExplainResponse)

    # ── Internal HTTP ─────────────────────────────────────────────────────────

    def _get(
        self, path: str, params: dict[str, str], cls: type[T]
    ) -> T:
        response = self._raw_get(path, params)
        return deserialize(response.json(), cls)

    def _post(
        self, path: str, payload: dict[str, Any], cls: type[T]
    ) -> T:
        response = self._raw_post(path, payload)
        return deserialize(response.json(), cls)

    def _post_raw(
        self, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        response = self._raw_post(path, payload)
        return response.json()  # type: ignore[no-any-return]

    def _patch(
        self, path: str, payload: dict[str, Any], cls: type[T]
    ) -> T:
        response = self._raw_patch(path, payload)
        return deserialize(response.json(), cls)

    def _raw_get(
        self, path: str, params: dict[str, str]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.get(url, params=params or None)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    def _raw_post(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.post(url, json=payload)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    def _raw_patch(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.patch(url, json=payload)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    def _raw_put(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.put(url, json=payload)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    def _raw_delete(self, path: str) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.delete(url)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response
