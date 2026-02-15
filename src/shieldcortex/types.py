"""Type definitions for the ShieldCortex API.

All types use frozen dataclasses with Python snake_case field names.
The HTTP layer handles conversion to/from the API's mixed casing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ── Scan ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScanSource:
    type: Literal["user", "cli", "hook", "email", "web", "agent", "file", "api"]
    identifier: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    mode: Literal["strict", "balanced", "permissive"] = "balanced"
    enable_fragmentation_detection: bool = False


@dataclass(frozen=True)
class FirewallResult:
    result: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    reason: str
    threat_indicators: list[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    blocked_patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SensitivityResult:
    level: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    redaction_required: bool = False


@dataclass(frozen=True)
class TrustResult:
    score: float


@dataclass(frozen=True)
class FragmentationResult:
    score: float
    risk_level: str | None = None


@dataclass(frozen=True)
class UsageInfo:
    scans_used: int
    scans_limit: int


@dataclass(frozen=True)
class ScanResult:
    allowed: bool
    firewall: FirewallResult
    sensitivity: SensitivityResult
    trust: TrustResult
    audit_id: int
    fragmentation: FragmentationResult | None = None
    usage: UsageInfo | None = None


# ── Batch Scan ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BatchItem:
    content: str
    title: str | None = None


@dataclass(frozen=True)
class BatchResult:
    total_scanned: int
    threats: int
    clean: int
    results: list[ScanResult] = field(default_factory=list)


# ── Skill Scan ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SkillThreat:
    category: str
    severity: str
    description: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SkillScanMetadata:
    format: str
    name: str | None = None
    scan_duration_ms: int | None = None


@dataclass(frozen=True)
class SkillScanResult:
    threat_score: float
    level: str
    verdict: str
    threats: list[SkillThreat] = field(default_factory=list)
    metadata: SkillScanMetadata | None = None


# ── Audit ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditQuery:
    """Query parameters for fetching audit logs."""

    from_time: str | None = None
    to: str | None = None
    level: Literal["ALLOW", "BLOCK", "QUARANTINE"] | None = None
    source: str | None = None
    device_id: str | None = None
    search: str | None = None
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True)
class AuditEntry:
    id: int
    timestamp: str
    source_type: str
    source_identifier: str
    trust_score: float
    sensitivity_level: str
    firewall_result: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    anomaly_score: float
    threat_indicators: list[str]
    reason: str
    pipeline_duration_ms: int
    device_id: str | None = None
    device_name: str | None = None


@dataclass(frozen=True)
class Pagination:
    limit: int
    offset: int
    has_more: bool


@dataclass(frozen=True)
class AuditResponse:
    logs: list[AuditEntry]
    total: int
    pagination: Pagination


@dataclass(frozen=True)
class SourceCount:
    source: str
    count: int


@dataclass(frozen=True)
class AuditStats:
    total_operations: int
    allowed_count: int
    blocked_count: int
    quarantined_count: int
    top_sources: list[SourceCount] = field(default_factory=list)
    threat_breakdown: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class TrendBucket:
    time: str
    allowed: int
    blocked: int
    quarantined: int


@dataclass(frozen=True)
class TrendResponse:
    buckets: list[TrendBucket]
    time_range: str


# ── Quarantine ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class QuarantineQuery:
    """Query parameters for fetching quarantine items."""

    status: Literal["pending", "approved", "rejected", "expired"] | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class QuarantineItem:
    id: int
    status: str
    reason: str
    threat_indicators: list[str]
    anomaly_score: float
    source_type: str
    source_identifier: str
    created_at: str
    content: str | None = None
    title: str | None = None
    firewall_result: str | None = None
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    device_id: str | None = None
    device_name: str | None = None
    expires_at: str | None = None


@dataclass(frozen=True)
class QuarantineResponse:
    items: list[QuarantineItem]
    total: int


@dataclass(frozen=True)
class ReviewResponse:
    success: bool
    message: str


# ── API Keys ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class KeyInfo:
    id: int
    name: str
    scopes: list[str]
    expires_at: str | None = None


@dataclass(frozen=True)
class CreateKeyResponse:
    message: str
    key: str
    key_info: KeyInfo
    warning: str | None = None


@dataclass(frozen=True)
class KeyListItem:
    id: int
    name: str
    prefix: str
    scopes: list[str]
    revoked: bool
    last_used_at: str | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class KeyListResponse:
    keys: list[KeyListItem]
    total: int


# ── Teams ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TeamInfo:
    id: int
    name: str
    slug: str
    plan: str
    scan_limit: int


@dataclass(frozen=True)
class TeamMember:
    id: int
    email: str
    role: Literal["owner", "admin", "member"]
    name: str | None = None
    joined_at: str | None = None


@dataclass(frozen=True)
class MembersResponse:
    members: list[TeamMember]
    total: int


@dataclass(frozen=True)
class UsageBreakdown:
    scans: int
    batches: int
    blocked: int
    quarantined: int


@dataclass(frozen=True)
class UsageResponse:
    used: int
    limit: int
    breakdown: UsageBreakdown


# ── Invites ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Invite:
    id: int
    email: str
    role: Literal["admin", "member"]
    status: str
    expires_at: str
    created_at: str
    invited_by: int | None = None


@dataclass(frozen=True)
class InviteListResponse:
    invites: list[Invite]
    total: int


# ── Billing ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CheckoutResponse:
    url: str


@dataclass(frozen=True)
class PortalResponse:
    url: str


# ── Devices ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    platform: str
    first_seen: str
    last_seen: str
    scan_count: int = 0


# ── Alerts ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AlertRule:
    id: int
    name: str
    enabled: bool
    trigger_on_block: bool
    trigger_on_quarantine: bool
    email_recipients: list[str]
    created_at: str
    trigger_on_anomaly_above: float | None = None
    last_triggered_at: str | None = None


# ── Webhooks ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Webhook:
    id: int
    name: str
    url: str
    enabled: bool
    events: list[str]
    consecutive_failures: int
    created_at: str
    last_delivery_at: str | None = None
    last_delivery_status: int | None = None
    auto_disabled_at: str | None = None


@dataclass(frozen=True)
class CreateWebhookResponse:
    id: int
    name: str
    url: str
    secret: str
    enabled: bool
    events: list[str]
    created_at: str


@dataclass(frozen=True)
class WebhookDelivery:
    id: int
    event: str
    response_status: int
    success: bool
    created_at: str
    duration_ms: int = 0
    payload: dict[str, Any] | None = None
    response_body: str | None = None


@dataclass(frozen=True)
class TestWebhookResponse:
    success: bool
    status: int
    duration_ms: int
    message: str


# ── Firewall Rules ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FirewallRule:
    id: int
    name: str
    enabled: bool
    priority: int
    rule_type: str
    created_at: str
    description: str | None = None
    config_overrides: dict[str, Any] | None = None
    pattern_config: dict[str, Any] | None = None
    source_config: dict[str, Any] | None = None
    updated_at: str | None = None
    created_by: int | None = None
