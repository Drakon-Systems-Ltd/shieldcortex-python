"""Type definitions for the ShieldCortex API.

All types use frozen dataclasses with Python snake_case field names.
The HTTP layer handles conversion to/from the API's mixed casing.

NOTE: We use Optional[X] instead of X | None throughout this file because
these dataclass fields are evaluated at runtime by get_type_hints(), and
the PEP 604 union syntax (X | None) is not supported on Python 3.9.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

# -- Scan ------------------------------------------------------------------


@dataclass(frozen=True)
class ScanSource:
    type: Literal["user", "cli", "hook", "email", "web", "agent", "file", "api"]
    identifier: Optional[str] = None


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
    risk_level: Optional[str] = None


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
    fragmentation: Optional[FragmentationResult] = None
    usage: Optional[UsageInfo] = None


# -- Batch Scan ------------------------------------------------------------


@dataclass(frozen=True)
class BatchItem:
    content: str
    title: Optional[str] = None


@dataclass(frozen=True)
class BatchResult:
    total_scanned: int
    threats: int
    clean: int
    results: list[ScanResult] = field(default_factory=list)


# -- Skill Scan ------------------------------------------------------------


@dataclass(frozen=True)
class SkillThreat:
    category: str
    severity: str
    description: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SkillScanMetadata:
    format: str
    name: Optional[str] = None
    scan_duration_ms: Optional[int] = None


@dataclass(frozen=True)
class SkillScanResult:
    threat_score: float
    level: str
    verdict: str
    threats: list[SkillThreat] = field(default_factory=list)
    metadata: Optional[SkillScanMetadata] = None


# -- Audit -----------------------------------------------------------------


@dataclass(frozen=True)
class AuditQuery:
    """Query parameters for fetching audit logs."""

    from_time: Optional[str] = None
    to: Optional[str] = None
    level: Optional[Literal["ALLOW", "BLOCK", "QUARANTINE"]] = None
    source: Optional[str] = None
    device_id: Optional[str] = None
    search: Optional[str] = None
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
    device_id: Optional[str] = None
    device_name: Optional[str] = None


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


# -- Quarantine ------------------------------------------------------------


@dataclass(frozen=True)
class QuarantineQuery:
    """Query parameters for fetching quarantine items."""

    status: Optional[Literal["pending", "approved", "rejected", "expired"]] = None
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
    content: Optional[str] = None
    title: Optional[str] = None
    firewall_result: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    expires_at: Optional[str] = None


@dataclass(frozen=True)
class QuarantineResponse:
    items: list[QuarantineItem]
    total: int


@dataclass(frozen=True)
class ReviewResponse:
    success: bool
    message: str


# -- API Keys --------------------------------------------------------------


@dataclass(frozen=True)
class KeyInfo:
    id: int
    name: str
    scopes: list[str]
    expires_at: Optional[str] = None


@dataclass(frozen=True)
class CreateKeyResponse:
    message: str
    key: str
    key_info: KeyInfo
    warning: Optional[str] = None


@dataclass(frozen=True)
class KeyListItem:
    id: int
    name: str
    prefix: str
    scopes: list[str]
    revoked: bool
    last_used_at: Optional[str] = None
    created_at: Optional[str] = None


@dataclass(frozen=True)
class KeyListResponse:
    keys: list[KeyListItem]
    total: int


# -- Teams -----------------------------------------------------------------


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
    name: Optional[str] = None
    joined_at: Optional[str] = None


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


# -- Invites ---------------------------------------------------------------


@dataclass(frozen=True)
class Invite:
    id: int
    email: str
    role: Literal["admin", "member"]
    status: str
    expires_at: str
    created_at: str
    invited_by: Optional[int] = None


@dataclass(frozen=True)
class InviteListResponse:
    invites: list[Invite]
    total: int


# -- Billing ---------------------------------------------------------------


@dataclass(frozen=True)
class CheckoutResponse:
    url: str


@dataclass(frozen=True)
class PortalResponse:
    url: str


# -- Devices ---------------------------------------------------------------


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    platform: str
    first_seen: str
    last_seen: str
    scan_count: int = 0


# -- Alerts ----------------------------------------------------------------


@dataclass(frozen=True)
class AlertRule:
    id: int
    name: str
    enabled: bool
    trigger_on_block: bool
    trigger_on_quarantine: bool
    email_recipients: list[str]
    created_at: str
    trigger_on_anomaly_above: Optional[float] = None
    last_triggered_at: Optional[str] = None


# -- Webhooks --------------------------------------------------------------


@dataclass(frozen=True)
class Webhook:
    id: int
    name: str
    url: str
    enabled: bool
    events: list[str]
    consecutive_failures: int
    created_at: str
    last_delivery_at: Optional[str] = None
    last_delivery_status: Optional[int] = None
    auto_disabled_at: Optional[str] = None


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
    payload: Optional[dict[str, Any]] = None
    response_body: Optional[str] = None


@dataclass(frozen=True)
class TestWebhookResponse:
    success: bool
    status: int
    duration_ms: int
    message: str


# -- Firewall Rules --------------------------------------------------------


@dataclass(frozen=True)
class FirewallRule:
    id: int
    name: str
    enabled: bool
    priority: int
    rule_type: str
    created_at: str
    description: Optional[str] = None
    config_overrides: Optional[dict[str, Any]] = None
    pattern_config: Optional[dict[str, Any]] = None
    source_config: Optional[dict[str, Any]] = None
    updated_at: Optional[str] = None
    created_by: Optional[int] = None
