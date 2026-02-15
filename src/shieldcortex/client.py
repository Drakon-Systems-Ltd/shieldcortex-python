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
    Device,
    FirewallRule,
    Invite,
    InviteListResponse,
    KeyListResponse,
    MembersResponse,
    PortalResponse,
    QuarantineItem,
    QuarantineQuery,
    QuarantineResponse,
    ReviewResponse,
    ScanConfig,
    ScanResult,
    ScanSource,
    SkillScanResult,
    TeamInfo,
    TestWebhookResponse,
    TrendResponse,
    UsageResponse,
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

    def _raw_delete(self, path: str) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = self._client.delete(url)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response
