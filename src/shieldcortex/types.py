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


@dataclass(frozen=True)
class AuditExportHeaders:
    """Parsed ``X-ShieldCortex-Export-*`` integrity headers.

    ``sha256`` and ``signature`` are load-bearing: when the header is
    absent the field is ``None`` (never ``""``), meaning the export CANNOT
    be verified — treat it as unverifiable rather than comparing against
    an empty string.
    """

    #: Hex SHA-256 of the exact body. None when absent — export is unverifiable.
    sha256: Optional[str]
    #: Entry count. None when the header is absent or non-numeric.
    count: Optional[int]
    generated_at: str
    manifest_id: str
    #: HMAC-SHA256 hex signature. None when absent — export is unverifiable.
    signature: Optional[str]
    signature_algorithm: str
    manifest_persisted: bool


@dataclass(frozen=True)
class AuditExportResult:
    """Raw audit export body plus its integrity headers."""

    #: CSV text, a bare JSON array, or a ``{meta, entries}`` envelope.
    content: str
    headers: AuditExportHeaders


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


# -- Iron Dome Patterns ----------------------------------------------------


@dataclass(frozen=True)
class InjectionPattern:
    id: int
    pattern: str
    category: str
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    test_string: str
    enabled: bool
    created_at: str
    updated_at: Optional[str] = None
    created_by: Optional[int] = None


@dataclass(frozen=True)
class InjectionPatternsResponse:
    patterns: list[InjectionPattern]


@dataclass(frozen=True)
class PatternSyncItem:
    pattern: str
    category: str
    severity: str


@dataclass(frozen=True)
class PatternSyncResponse:
    patterns: list[PatternSyncItem]
    updated_at: Optional[str] = None


@dataclass(frozen=True)
class PatternTestResult:
    matched: bool
    match_count: int
    matches: list[str] = field(default_factory=list)


# -- Iron Dome Policies ----------------------------------------------------


@dataclass(frozen=True)
class IronDomePolicy:
    id: int
    name: str
    base_profile: Literal["school", "enterprise", "personal", "paranoid"]
    config_overrides: dict[str, Any]
    is_default: bool
    created_at: str
    updated_at: Optional[str] = None
    created_by: Optional[int] = None


@dataclass(frozen=True)
class IronDomePoliciesResponse:
    policies: list[IronDomePolicy]


@dataclass(frozen=True)
class PolicySyncResponse:
    policy: Optional[dict[str, Any]] = None
    updated_at: Optional[str] = None


# -- Verification ----------------------------------------------------------


@dataclass(frozen=True)
class DetectedThreat:
    type: str
    description: str
    severity: str


@dataclass(frozen=True)
class VerificationResult:
    """Result of POST /v1/verify (synchronous mode).

    The API omits undefined result keys entirely (never null), so every
    optional field defaults to None.
    """

    id: int
    status: str
    cached: bool = False
    verdict: Optional[Literal["SAFE", "SUSPICIOUS", "THREAT"]] = None
    confidence: Optional[float] = None
    action: Optional[Literal["ALERT", "NONE"]] = None
    duration_ms: Optional[float] = None
    threats_detected: Optional[list[DetectedThreat]] = None


@dataclass(frozen=True)
class VerificationListItem:
    """A row from GET /v1/verify.

    NOTE: the list exposes ``duration_ms`` where the detail endpoint exposes
    the same column as ``total_duration_ms``.
    """

    id: int
    source_type: str
    source_identifier: str
    pipeline_result: str
    anomaly_score: float
    status: str
    created_at: str
    title: Optional[str] = None
    trust_score: Optional[float] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    action: Optional[str] = None
    threats_detected: Optional[list[DetectedThreat]] = None
    duration_ms: Optional[float] = None
    cost_usd: Optional[float] = None
    completed_at: Optional[str] = None


@dataclass(frozen=True)
class VerificationListResponse:
    verifications: list[VerificationListItem]
    total: int
    pagination: Pagination


@dataclass(frozen=True)
class VerificationDetail:
    """Full verification record from GET /v1/verify/:id."""

    id: int
    source_type: str
    source_identifier: str
    pipeline_result: str
    anomaly_score: float
    status: str
    created_at: str
    title: Optional[str] = None
    trust_score: Optional[float] = None
    threat_indicators: Optional[list[str]] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    threats_detected: Optional[list[DetectedThreat]] = None
    model_used: Optional[str] = None
    action: Optional[str] = None
    llm_duration_ms: Optional[int] = None
    total_duration_ms: Optional[int] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    completed_at: Optional[str] = None


@dataclass(frozen=True)
class VerificationDayStats:
    total: int
    safe: int
    suspicious: int
    threat: int
    error: int
    cost_usd: float


@dataclass(frozen=True)
class VerificationQuota:
    used: int
    limit: int


@dataclass(frozen=True)
class VerificationStats:
    today: VerificationDayStats
    quota: VerificationQuota


@dataclass(frozen=True)
class DeleteVerificationResponse:
    deleted: bool
    id: int


# -- Skills ----------------------------------------------------------------


@dataclass(frozen=True)
class SkillFinding:
    """A single finding within a skill scan.

    NOTE: serialized on the wire with camelCase ``matchedText`` (a deliberate
    API wart, declared via field metadata); the Python attribute stays
    snake_case.
    """

    pattern: str
    severity: str
    description: str
    matched_text: Optional[str] = field(default=None, metadata={"wire": "matchedText"})


@dataclass(frozen=True)
class SkillScanFile:
    """A scanned skill file to submit via POST /v1/skills/ingest."""

    file_path: str
    skill_name: str
    format: str
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
    safe: bool
    summary: Optional[str] = None
    findings: Optional[list[SkillFinding]] = None
    scan_duration_ms: Optional[int] = None
    trusted: Optional[bool] = None


@dataclass(frozen=True)
class SkillIngestResponse:
    upserted: int
    total: int


@dataclass(frozen=True)
class SyncedSkillScan:
    """A synced skill scan row from GET /v1/skills."""

    id: int
    file_path: str
    skill_name: str
    format: str
    risk_level: str
    safe: bool
    trusted: bool
    summary: Optional[str] = None
    findings: Optional[list[SkillFinding]] = None
    scan_duration_ms: Optional[int] = None
    scanned_at: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None


@dataclass(frozen=True)
class SkillScanListResponse:
    """GET /v1/skills — hard cap 200 rows, newest first, no pagination."""

    files: list[SyncedSkillScan]
    total: int


# -- Threats ---------------------------------------------------------------


@dataclass(frozen=True)
class ThreatReportResponse:
    ingested: int


# -- Incidents -------------------------------------------------------------


@dataclass(frozen=True)
class IncidentEvent:
    id: str
    timestamp: str
    stream: Literal["audit", "verification", "sync", "memory"]
    event_type: str
    severity: Literal["info", "warning", "critical"]
    summary: str
    details: Optional[str] = None
    device_uuid: Optional[str] = None
    device_name: Optional[str] = None
    source_identifier: Optional[str] = None
    project: Optional[str] = None
    memory_external_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IncidentStreamSummary:
    audit: int
    verification: int
    sync: int
    memory: int


@dataclass(frozen=True)
class IncidentCoverage:
    sources: list[str]
    note: str


@dataclass(frozen=True)
class IncidentReplayResponse:
    events: list[IncidentEvent]
    total: int
    summary: IncidentStreamSummary
    coverage: IncidentCoverage


# -- Sync ------------------------------------------------------------------


@dataclass(frozen=True)
class SyncHealth:
    """GET /v1/sync/health — sync-table presence check for the team."""

    status: Literal["ok", "degraded"]
    team_id: int
    required_tables: list[str]
    present_tables: list[str]
    missing_tables: list[str]


@dataclass(frozen=True)
class SyncMemory:
    """A memory to push via POST /v1/sync/memories.

    Unset optionals are omitted from the wire (never sent as null). Set
    ``deleted_at`` to tombstone a memory on the server.
    """

    external_id: str
    type: str
    category: str
    title: str
    content: str
    created_at: str
    updated_at: str
    local_id: Optional[int] = None
    project: Optional[str] = None
    tags: Optional[list[str]] = None
    salience: Optional[float] = None
    scope: Optional[Literal["project", "global"]] = None
    transferable: Optional[bool] = None
    trust_score: Optional[float] = None
    sensitivity_level: Optional[str] = None
    source: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    deleted_at: Optional[str] = None


@dataclass(frozen=True)
class SyncPushResponse:
    """POST /v1/sync/memories — includes the tombstone (deleted) count."""

    received: int
    upserted: int
    deleted: int
    device_id: str


@dataclass(frozen=True)
class SyncedMemory:
    """A synced memory row from GET /v1/sync/memories."""

    external_id: str
    type: str
    category: str
    title: str
    content: str
    tags: list[str]
    salience: float
    scope: str
    transferable: bool
    is_canonical: bool
    device_uuid: str
    local_id: Optional[int] = None
    project: Optional[str] = None
    trust_score: Optional[float] = None
    sensitivity_level: Optional[str] = None
    source: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    review_status: Optional[Literal["suppressed", "archived", "canonical"]] = None
    review_note: Optional[str] = None
    review_assignee: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    deleted_at: Optional[str] = None
    last_synced_at: Optional[str] = None
    device_name: Optional[str] = None
    device_platform: Optional[str] = None


@dataclass(frozen=True)
class SyncLatestDeviceSync:
    device_uuid: str
    device_name: Optional[str] = None
    last_synced_at: Optional[str] = None
    platform: Optional[str] = None


@dataclass(frozen=True)
class SyncDeviceHealth:
    device_uuid: str
    memory_count: int
    status: Literal["healthy", "stale", "offline"]
    device_name: Optional[str] = None
    platform: Optional[str] = None
    last_seen: Optional[str] = None
    last_synced_at: Optional[str] = None
    last_updated_at: Optional[str] = None


@dataclass(frozen=True)
class SyncHealthSummary:
    healthy_devices: int
    stale_devices: int
    offline_devices: int
    latest_device_sync: Optional[SyncLatestDeviceSync] = None
    devices: list[SyncDeviceHealth] = field(default_factory=list)


@dataclass(frozen=True)
class SyncMemorySummary:
    total: int
    deleted: int
    devices: int
    projects: int
    health: SyncHealthSummary
    last_synced_at: Optional[str] = None
    last_updated_at: Optional[str] = None


@dataclass(frozen=True)
class SyncedMemoriesResponse:
    """GET /v1/sync/memories.

    NOTE: the API omits the entire ``summary`` key on the unknown-device
    branch (200 with empty memories), so ``summary`` is optional here.
    """

    memories: list[SyncedMemory]
    total: int
    pagination: Pagination
    summary: Optional[SyncMemorySummary] = None


@dataclass(frozen=True)
class SyncGraphEntity:
    """An entity to push via POST /v1/sync/graph."""

    external_id: str
    name: str
    type: str
    local_id: Optional[int] = None
    aliases: Optional[list[str]] = None
    first_seen: Optional[str] = None
    memory_count: Optional[int] = None


@dataclass(frozen=True)
class SyncGraphTriple:
    """A subject–predicate–object triple to push via POST /v1/sync/graph."""

    external_id: str
    subject_external_id: str
    predicate: str
    object_external_id: str
    local_id: Optional[int] = None
    source_memory_external_id: Optional[str] = None
    confidence: Optional[float] = None
    created_at: Optional[str] = None


@dataclass(frozen=True)
class SyncMemoryEntityLink:
    """A memory ↔ entity link to push via POST /v1/sync/graph."""

    memory_external_id: str
    entity_external_id: str
    role: Optional[str] = None


@dataclass(frozen=True)
class SyncGraphResponse:
    """POST /v1/sync/graph — counts of upserted/pruned rows."""

    device_id: str
    entities: int
    triples: int
    memory_entities: int
    pruned_memories: int
    orphan_entities_pruned: int


# -- License ---------------------------------------------------------------


@dataclass(frozen=True)
class LicenseInfo:
    """GET /v1/license.

    NOTE: ``last_validated_at`` is MISSING entirely (not null) on the
    no-licence branch (``tier="free"``, ``status="none"``), so it defaults
    to None here.
    """

    tier: str
    status: str
    expires_at: Optional[str] = None
    created_at: Optional[str] = None
    last_validated_at: Optional[str] = None


@dataclass(frozen=True)
class RegenerateLicenseResponse:
    """POST /v1/license/regenerate — the new key is only returned once."""

    key: str
    tier: str
    expires_at: str
    message: str


# -- Audit Iron Dome & Exports ---------------------------------------------


@dataclass(frozen=True)
class IronDomeTopDevice:
    device_id: str
    count: int
    device_name: Optional[str] = None


@dataclass(frozen=True)
class IronDomeStats:
    """GET /v1/audit/iron-dome/stats (Pro+ — free plans get 402).

    ``by_action`` keys are the ``[iron-dome:<action>]`` reason prefixes,
    with ``"unknown"`` as the fallback bucket.
    """

    total_events: int
    blocked: int
    allowed: int
    by_action: dict[str, int] = field(default_factory=dict)
    top_devices: list[IronDomeTopDevice] = field(default_factory=list)


@dataclass(frozen=True)
class IronDomeEvent:
    """An Iron Dome audit row from GET /v1/audit/iron-dome/events.

    ``device_id`` is the device UUID (not the DB id).
    """

    id: int
    timestamp: str
    source_type: str
    source_identifier: str
    trust_score: float
    sensitivity_level: str
    firewall_result: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    anomaly_score: float
    threat_indicators: list[str]
    pipeline_duration_ms: int
    action_type: str
    reason: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None


@dataclass(frozen=True)
class IronDomeEventsResponse:
    """GET /v1/audit/iron-dome/events.

    NOTE: this envelope carries NO ``total`` (unlike GET /v1/audit);
    ``pagination.has_more`` is the page-full heuristic.
    """

    events: list[IronDomeEvent]
    pagination: Pagination


@dataclass(frozen=True)
class AuditIngestEntry:
    """A canonical audit entry to submit via POST /v1/audit/ingest.

    Unset optionals are omitted from the wire (never sent as null).
    """

    source_type: str
    source_identifier: str
    trust_score: float
    sensitivity_level: str
    firewall_result: Literal["ALLOW", "BLOCK", "QUARANTINE"]
    anomaly_score: float
    threat_indicators: list[str]
    reason: str
    pipeline_duration_ms: int
    timestamp: str
    blocked_patterns: Optional[list[str]] = None
    fragmentation_score: Optional[float] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    platform: Optional[str] = None


@dataclass(frozen=True)
class AuditIngestResponse:
    """POST /v1/audit/ingest (201).

    ``ingested`` is the submitted count — duplicate entries are silently
    deduped server-side but still counted here.
    """

    ingested: int


@dataclass(frozen=True)
class ExportManifest:
    """A signed export manifest row from GET /v1/audit/exports.

    ``filters`` is kept as a raw dict because its wire keys include
    ``from`` (a Python keyword); keys: from, to, level, source, device_id,
    search — all nullable. ``team_id`` only appears on the detail endpoint.
    """

    manifest_id: str
    request_id: str
    format: Literal["csv", "json"]
    shape: Literal["array", "envelope"]
    entry_count: int
    export_sha256: str
    signature_algorithm: str
    signature: str
    generated_at: str
    created_at: str
    api_key_id: Optional[int] = None
    filters: dict[str, Any] = field(default_factory=dict)
    team_id: Optional[int] = None


@dataclass(frozen=True)
class ExportManifestListResponse:
    """GET /v1/audit/exports.

    NOTE: this envelope carries NO ``total``.
    """

    manifests: list[ExportManifest]
    pagination: Pagination


@dataclass(frozen=True)
class ManifestVerification:
    """The server-side signature check attached to a manifest read."""

    signature_valid: bool
    signature_algorithm: str


@dataclass(frozen=True)
class ExportManifestDetail:
    """GET /v1/audit/exports/:manifestId — the HMAC is recomputed on read,
    so ``verification.signature_valid`` false signals tampering or secret
    rotation."""

    manifest: ExportManifest
    verification: ManifestVerification


@dataclass(frozen=True)
class ExportVerifyResult:
    """Verification outcome for POST /v1/audit/exports/:manifestId/verify.

    ``sha256_matches`` is null when no ``export_sha256`` was provided.
    """

    signature_valid: bool
    signature_algorithm: str
    sha256_matches: Optional[bool] = None


@dataclass(frozen=True)
class ExportVerifyExpected:
    export_sha256: str
    signature: str


@dataclass(frozen=True)
class ExportVerifyResponse:
    manifest_id: str
    verification: ExportVerifyResult
    expected: ExportVerifyExpected


@dataclass(frozen=True)
class ExportVerificationEvent:
    """A persisted verification event from
    GET /v1/audit/exports/:manifestId/verifications."""

    id: int
    manifest_id: str
    request_id: str
    result_signature_valid: bool
    created_at: str
    api_key_id: Optional[int] = None
    provided_export_sha256: Optional[str] = None
    provided_signature: Optional[str] = None
    result_sha256_matches: Optional[bool] = None


@dataclass(frozen=True)
class ExportVerificationListResponse:
    """GET /v1/audit/exports/:manifestId/verifications.

    NOTE: this envelope carries NO ``total``; an unknown manifestId
    returns 200 with empty events (no existence check), unlike the
    manifest GET which 404s.
    """

    events: list[ExportVerificationEvent]
    pagination: Pagination


# -- Recall ----------------------------------------------------------------


@dataclass(frozen=True)
class RecallMemory:
    external_id: str
    title: str
    content: str
    category: str
    type: str
    tags: list[str]
    salience: float
    scope: str
    updated_at: str
    last_synced_at: str
    device_uuid: str
    project: Optional[str] = None
    trust_score: Optional[float] = None
    device_name: Optional[str] = None
    device_platform: Optional[str] = None


@dataclass(frozen=True)
class RecallLinkedEntity:
    name: str
    type: str
    role: str


@dataclass(frozen=True)
class RecallScoreBreakdown:
    lexical: float
    exact_phrase: float
    salience: float
    recency: float
    trust: float
    project: float


@dataclass(frozen=True)
class RecallResult:
    memory: RecallMemory
    score: float
    matched_terms: list[str]
    reasons: list[str]
    breakdown: RecallScoreBreakdown
    linked_entities: list[RecallLinkedEntity] = field(default_factory=list)


@dataclass(frozen=True)
class RecallExplainResponse:
    query: str
    total_candidates: int
    results: list[RecallResult]
    project: Optional[str] = None
