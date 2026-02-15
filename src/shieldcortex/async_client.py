"""Asynchronous ShieldCortex API client.

Usage:
    from shieldcortex import AsyncShieldCortex

    async with AsyncShieldCortex(api_key="sc_live_...") as client:
        result = await client.scan("user input here")
"""

from __future__ import annotations

from collections.abc import AsyncIterable
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


class AsyncShieldCortex:
    """Asynchronous ShieldCortex API client.

    Example::

        from shieldcortex import AsyncShieldCortex

        async with AsyncShieldCortex(api_key="sc_live_...") as client:
            result = await client.scan("user input")
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
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=build_headers(api_key),
        )

    async def __aenter__(self) -> AsyncShieldCortex:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # ── Scanning ──────────────────────────────────────────────────────────────

    async def scan(
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
        return await self._post("/v1/scan", payload, ScanResult)

    async def scan_batch(
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
        return await self._post("/v1/scan/batch", payload, BatchResult)

    async def scan_skill(
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
        return await self._post("/v1/scan/skill", payload, SkillScanResult)

    # ── Audit ─────────────────────────────────────────────────────────────────

    async def get_audit_logs(
        self, query: AuditQuery | None = None
    ) -> AuditResponse:
        """Query audit logs with optional filters and pagination."""
        params = serialize_query(query) if query else {}
        return await self._get("/v1/audit", params, AuditResponse)

    async def get_audit_entry(self, id: int) -> AuditEntry:
        """Get a single audit log entry by ID."""
        return await self._get(f"/v1/audit/{id}", {}, AuditEntry)

    async def get_audit_stats(
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
        return await self._get("/v1/audit/stats", params, AuditStats)

    async def get_audit_trends(
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
        return await self._get("/v1/audit/trends", params, TrendResponse)

    async def export_audit_logs(
        self,
        *,
        format: Literal["json", "csv"] = "json",
        query: AuditQuery | None = None,
    ) -> str:
        """Export audit logs as JSON or CSV string."""
        params: dict[str, str] = {"format": format}
        if query:
            params.update(serialize_query(query))
        response = await self._raw_get("/v1/audit/export", params)
        return response.text

    async def iter_audit_logs(
        self,
        query: AuditQuery | None = None,
        *,
        page_size: int = 100,
    ) -> AsyncIterable[AuditEntry]:
        """Iterate all matching audit logs with automatic pagination."""
        from shieldcortex.pagination import AsyncAuditPaginator

        return AsyncAuditPaginator(self, query or AuditQuery(), page_size)

    # ── Quarantine ────────────────────────────────────────────────────────────

    async def get_quarantine(
        self, query: QuarantineQuery | None = None
    ) -> QuarantineResponse:
        """List quarantined items."""
        params = serialize_query(query) if query else {}
        return await self._get("/v1/quarantine", params, QuarantineResponse)

    async def get_quarantine_item(self, id: int) -> QuarantineItem:
        """Get a single quarantine item (includes full content)."""
        return await self._get(f"/v1/quarantine/{id}", {}, QuarantineItem)

    async def review_quarantine_item(
        self, id: int, action: Literal["approve", "reject"]
    ) -> ReviewResponse:
        """Approve or reject a quarantined item."""
        return await self._post(
            f"/v1/quarantine/{id}/review", {"action": action}, ReviewResponse
        )

    # ── API Keys ──────────────────────────────────────────────────────────────

    async def create_api_key(
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
        return await self._post("/v1/keys", payload, CreateKeyResponse)

    async def list_api_keys(self) -> KeyListResponse:
        """List all API keys for the team."""
        return await self._get("/v1/keys", {}, KeyListResponse)

    async def revoke_api_key(self, id: int) -> None:
        """Revoke an API key."""
        await self._raw_delete(f"/v1/keys/{id}")

    # ── Teams ─────────────────────────────────────────────────────────────────

    async def get_team(self) -> TeamInfo:
        """Get current team information."""
        return await self._get("/v1/teams", {}, TeamInfo)

    async def update_team(self, name: str) -> None:
        """Update team name."""
        await self._raw_patch("/v1/teams", {"name": name})

    async def get_team_members(self) -> MembersResponse:
        """List team members."""
        return await self._get("/v1/teams/members", {}, MembersResponse)

    async def get_usage(self) -> UsageResponse:
        """Get current billing period usage statistics."""
        return await self._get("/v1/teams/usage", {}, UsageResponse)

    # ── Invites ───────────────────────────────────────────────────────────────

    async def create_invite(
        self,
        email: str,
        *,
        role: Literal["admin", "member"] = "member",
    ) -> Invite:
        """Create a team invitation."""
        data = await self._post_raw("/v1/invites", {"email": email, "role": role})
        return deserialize(data.get("invite", data), Invite)

    async def list_invites(self) -> InviteListResponse:
        """List all team invitations."""
        return await self._get("/v1/invites", {}, InviteListResponse)

    async def delete_invite(self, id: int) -> None:
        """Revoke a pending team invitation."""
        await self._raw_delete(f"/v1/invites/{id}")

    async def resend_invite(self, id: int) -> None:
        """Resend invitation email."""
        await self._raw_post(f"/v1/invites/{id}/resend", {})

    # ── Billing ───────────────────────────────────────────────────────────────

    async def create_checkout_session(self) -> CheckoutResponse:
        """Create a Stripe checkout session for plan upgrade."""
        return await self._post("/v1/billing/checkout", {}, CheckoutResponse)

    async def create_portal_session(self) -> PortalResponse:
        """Create a Stripe billing portal session."""
        return await self._post("/v1/billing/portal", {}, PortalResponse)

    # ── Devices ───────────────────────────────────────────────────────────────

    async def get_devices(self) -> list[Device]:
        """List all registered devices for the team."""
        response = await self._raw_get("/v1/devices", {})
        data = response.json()
        items = data.get("devices", data) if isinstance(data, dict) else data
        return [deserialize(d, Device) for d in items]

    async def register_device(
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
        await self._raw_post("/v1/devices", payload)

    async def update_device(self, uuid: str, name: str) -> None:
        """Rename a device."""
        await self._raw_patch(f"/v1/devices/{uuid}", {"name": name})

    async def device_heartbeat(
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
        await self._raw_post("/v1/devices/heartbeat", payload)

    # ── Alerts ────────────────────────────────────────────────────────────────

    async def get_alerts(self) -> list[AlertRule]:
        """List all alert rules."""
        response = await self._raw_get("/v1/alerts", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, AlertRule) for r in items]

    async def create_alert(
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
        return await self._post("/v1/alerts", payload, AlertRule)

    async def update_alert(self, id: int, **kwargs: Any) -> AlertRule:
        """Update an alert rule. Pass only the fields to change."""
        return await self._patch(f"/v1/alerts/{id}", kwargs, AlertRule)

    async def delete_alert(self, id: int) -> None:
        """Delete an alert rule."""
        await self._raw_delete(f"/v1/alerts/{id}")

    # ── Webhooks ──────────────────────────────────────────────────────────────

    async def get_webhooks(self) -> list[Webhook]:
        """List all webhooks."""
        response = await self._raw_get("/v1/webhooks", {})
        data = response.json()
        items = data.get("webhooks", [])
        return [deserialize(w, Webhook) for w in items]

    async def create_webhook(
        self,
        name: str,
        url: str,
        events: list[str],
    ) -> CreateWebhookResponse:
        """Create a new webhook. The secret is only returned once."""
        return await self._post(
            "/v1/webhooks",
            {"name": name, "url": url, "events": events},
            CreateWebhookResponse,
        )

    async def update_webhook(self, id: int, **kwargs: Any) -> Webhook:
        """Update a webhook. Pass only the fields to change."""
        return await self._patch(f"/v1/webhooks/{id}", kwargs, Webhook)

    async def delete_webhook(self, id: int) -> None:
        """Delete a webhook."""
        await self._raw_delete(f"/v1/webhooks/{id}")

    async def test_webhook(self, id: int) -> TestWebhookResponse:
        """Send a test ping to a webhook."""
        return await self._post(f"/v1/webhooks/{id}/test", {}, TestWebhookResponse)

    async def get_webhook_deliveries(self, id: int) -> list[WebhookDelivery]:
        """Get recent deliveries for a webhook."""
        response = await self._raw_get(f"/v1/webhooks/{id}/deliveries", {})
        data = response.json()
        items = data.get("deliveries", [])
        return [deserialize(d, WebhookDelivery) for d in items]

    # ── Firewall Rules ────────────────────────────────────────────────────────

    async def get_firewall_rules(self) -> list[FirewallRule]:
        """List all custom firewall rules."""
        response = await self._raw_get("/v1/firewall-rules", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, FirewallRule) for r in items]

    async def get_active_firewall_rules(self) -> list[FirewallRule]:
        """List enabled firewall rules ordered by priority."""
        response = await self._raw_get("/v1/firewall-rules/active", {})
        data = response.json()
        items = data.get("rules", [])
        return [deserialize(r, FirewallRule) for r in items]

    async def create_firewall_rule(self, **kwargs: Any) -> FirewallRule:
        """Create a new custom firewall rule."""
        return await self._post("/v1/firewall-rules", kwargs, FirewallRule)

    async def update_firewall_rule(self, id: int, **kwargs: Any) -> FirewallRule:
        """Update a firewall rule. Pass only the fields to change."""
        return await self._patch(
            f"/v1/firewall-rules/{id}", kwargs, FirewallRule
        )

    async def delete_firewall_rule(self, id: int) -> None:
        """Delete a firewall rule."""
        await self._raw_delete(f"/v1/firewall-rules/{id}")

    # ── Internal HTTP ─────────────────────────────────────────────────────────

    async def _get(
        self, path: str, params: dict[str, str], cls: type[T]
    ) -> T:
        response = await self._raw_get(path, params)
        return deserialize(response.json(), cls)

    async def _post(
        self, path: str, payload: dict[str, Any], cls: type[T]
    ) -> T:
        response = await self._raw_post(path, payload)
        return deserialize(response.json(), cls)

    async def _post_raw(
        self, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        response = await self._raw_post(path, payload)
        return response.json()  # type: ignore[no-any-return]

    async def _patch(
        self, path: str, payload: dict[str, Any], cls: type[T]
    ) -> T:
        response = await self._raw_patch(path, payload)
        return deserialize(response.json(), cls)

    async def _raw_get(
        self, path: str, params: dict[str, str]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = await self._client.get(url, params=params or None)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    async def _raw_post(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = await self._client.post(url, json=payload)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    async def _raw_patch(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = await self._client.patch(url, json=payload)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response

    async def _raw_delete(self, path: str) -> httpx.Response:
        url = f"{self._base_url}{path}"
        try:
            response = await self._client.delete(url)
        except httpx.TimeoutException as e:
            raise ShieldCortexError(f"Request timeout: {e}", 0, str(e))
        raise_for_status(response)
        return response
