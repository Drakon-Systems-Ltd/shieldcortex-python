"""THE canonical cross-SDK lockstep manifest.

Every ``(method, path_template)`` pair the Python client covers, path
params normalised to ``{id}`` / ``{manifestId}`` / ``{uuid}``. The TS SDK
enforces the same manifest (tests/endpoint-manifest.ts); keep the two
lists in lockstep — a divergence between them (or between a list and its
client) is a drift and must be resolved deliberately, never silently.

Wire contract reference: docs/plans/sdk-lockstep-contract.md.
"""

from __future__ import annotations

COVERED: list[tuple[str, str]] = [
    # Scanning
    ("POST", "/v1/scan"),
    ("POST", "/v1/scan/batch"),
    ("POST", "/v1/scan/skill"),
    # Audit
    ("GET", "/v1/audit"),
    ("GET", "/v1/audit/{id}"),
    ("GET", "/v1/audit/stats"),
    ("GET", "/v1/audit/trends"),
    ("GET", "/v1/audit/export"),
    ("POST", "/v1/audit/ingest"),
    ("GET", "/v1/audit/iron-dome/stats"),
    ("GET", "/v1/audit/iron-dome/events"),
    # Audit export manifests
    ("GET", "/v1/audit/exports"),
    ("GET", "/v1/audit/exports/{manifestId}"),
    ("POST", "/v1/audit/exports/{manifestId}/verify"),
    ("GET", "/v1/audit/exports/{manifestId}/verifications"),
    # Quarantine
    ("GET", "/v1/quarantine"),
    ("POST", "/v1/quarantine/{id}/review"),
    # API keys
    ("POST", "/v1/keys"),
    ("GET", "/v1/keys"),
    ("DELETE", "/v1/keys/{id}"),
    # Teams
    ("GET", "/v1/teams"),
    ("PATCH", "/v1/teams"),
    ("GET", "/v1/teams/members"),
    ("GET", "/v1/teams/usage"),
    # Invites
    ("POST", "/v1/invites"),
    ("GET", "/v1/invites"),
    ("DELETE", "/v1/invites/{id}"),
    ("POST", "/v1/invites/{id}/resend"),
    # Billing (deprecated — grandfathered licence holders only)
    ("POST", "/v1/billing/checkout"),
    ("POST", "/v1/billing/portal"),
    # Devices
    ("GET", "/v1/devices"),
    ("POST", "/v1/devices"),
    ("PATCH", "/v1/devices/{uuid}"),
    ("POST", "/v1/devices/heartbeat"),
    # Alerts
    ("GET", "/v1/alerts"),
    ("POST", "/v1/alerts"),
    ("PATCH", "/v1/alerts/{id}"),
    ("DELETE", "/v1/alerts/{id}"),
    # Webhooks
    ("GET", "/v1/webhooks"),
    ("POST", "/v1/webhooks"),
    ("PATCH", "/v1/webhooks/{id}"),
    ("DELETE", "/v1/webhooks/{id}"),
    ("POST", "/v1/webhooks/{id}/test"),
    ("GET", "/v1/webhooks/{id}/deliveries"),
    # Firewall rules
    ("GET", "/v1/firewall-rules"),
    ("GET", "/v1/firewall-rules/active"),
    ("POST", "/v1/firewall-rules"),
    ("PATCH", "/v1/firewall-rules/{id}"),
    ("DELETE", "/v1/firewall-rules/{id}"),
    # Iron Dome patterns
    ("GET", "/v1/iron-dome/patterns"),
    ("GET", "/v1/iron-dome/patterns/sync"),
    ("POST", "/v1/iron-dome/patterns"),
    ("PATCH", "/v1/iron-dome/patterns/{id}"),
    ("POST", "/v1/iron-dome/patterns/{id}/test"),
    ("DELETE", "/v1/iron-dome/patterns/{id}"),
    # Iron Dome policies
    ("GET", "/v1/iron-dome/policies"),
    ("GET", "/v1/iron-dome/policies/sync"),
    ("POST", "/v1/iron-dome/policies"),
    ("PATCH", "/v1/iron-dome/policies/{id}"),
    ("PUT", "/v1/iron-dome/policies/{id}/default"),
    ("DELETE", "/v1/iron-dome/policies/{id}"),
    # Verification
    ("POST", "/v1/verify"),
    ("GET", "/v1/verify"),
    ("GET", "/v1/verify/stats"),
    ("GET", "/v1/verify/{id}"),
    ("DELETE", "/v1/verify/{id}"),
    # Skills
    ("POST", "/v1/skills/ingest"),
    ("GET", "/v1/skills"),
    # Threats (OpenClaw realtime compat shim)
    ("POST", "/v1/threats"),
    # Incidents
    ("GET", "/v1/incidents/replay"),
    # Recall
    ("GET", "/v1/recall/explain"),
    # Sync
    ("GET", "/v1/sync/health"),
    ("POST", "/v1/sync/memories"),
    ("GET", "/v1/sync/memories"),
    ("POST", "/v1/sync/graph"),
    # Licence
    ("GET", "/v1/license"),
    ("POST", "/v1/license/regenerate"),
]

DEFERRED: list[tuple[str, str]] = [
    # Audit verification-export download sub-chain (CLI tooling, deliberately deferred):
    ("GET", "/v1/audit/exports/{manifestId}/verifications/export"),
    ("GET", "/v1/audit/exports/{manifestId}/verification-exports"),
    ("GET", "/v1/audit/exports/{manifestId}/verification-exports/{id}"),
    ("GET", "/v1/audit/exports/{manifestId}/verification-exports/{id}/download"),
]

#: Deliberate, documented cross-SDK differences. Anything not listed here is
#: expected to be identical between the TypeScript and Python SDKs.
POLICY_NOTES = """
1. Delete return values: the TS SDK returns void from every delete method;
   the Python SDK returns the typed response body where the server sends one
   (e.g. DELETE /v1/verify/{id} -> { deleted, id }). Per-language internal
   consistency was chosen over cross-SDK identity.
2. Audit export: both SDKs return { content, headers } from the audit export
   download (raw file body + parsed X-ShieldCortex-Export-* integrity
   headers). Absent sha256/signature => the export is unverifiable.
"""
