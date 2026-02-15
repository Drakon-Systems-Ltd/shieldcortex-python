"""ShieldCortex Python SDK — AI memory security scanning.

Usage:
    from shieldcortex import ShieldCortex

    client = ShieldCortex(api_key="sc_live_...")
    result = client.scan("user input here")

    if not result.allowed:
        print(f"Blocked: {result.firewall.reason}")
"""

from shieldcortex._version import __version__
from shieldcortex.async_client import AsyncShieldCortex
from shieldcortex.client import ShieldCortex
from shieldcortex.errors import (
    AuthError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ShieldCortexError,
    ValidationError,
)
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
    FirewallResult,
    FirewallRule,
    FragmentationResult,
    Invite,
    InviteListResponse,
    KeyInfo,
    KeyListItem,
    KeyListResponse,
    MembersResponse,
    Pagination,
    PortalResponse,
    QuarantineItem,
    QuarantineQuery,
    QuarantineResponse,
    ReviewResponse,
    ScanConfig,
    ScanResult,
    ScanSource,
    SensitivityResult,
    SkillScanMetadata,
    SkillScanResult,
    SkillThreat,
    SourceCount,
    TeamInfo,
    TeamMember,
    TestWebhookResponse,
    TrendBucket,
    TrendResponse,
    TrustResult,
    UsageBreakdown,
    UsageInfo,
    UsageResponse,
    Webhook,
    WebhookDelivery,
)

__all__ = [
    "__version__",
    # Clients
    "ShieldCortex",
    "AsyncShieldCortex",
    # Errors
    "ShieldCortexError",
    "AuthError",
    "RateLimitError",
    "ValidationError",
    "NotFoundError",
    "ForbiddenError",
    # Scan types
    "ScanSource",
    "ScanConfig",
    "ScanResult",
    "FirewallResult",
    "SensitivityResult",
    "TrustResult",
    "FragmentationResult",
    "UsageInfo",
    "BatchItem",
    "BatchResult",
    "SkillThreat",
    "SkillScanMetadata",
    "SkillScanResult",
    # Audit types
    "AuditQuery",
    "AuditEntry",
    "AuditResponse",
    "AuditStats",
    "SourceCount",
    "TrendBucket",
    "TrendResponse",
    "Pagination",
    # Quarantine types
    "QuarantineQuery",
    "QuarantineItem",
    "QuarantineResponse",
    "ReviewResponse",
    # Key types
    "KeyInfo",
    "CreateKeyResponse",
    "KeyListItem",
    "KeyListResponse",
    # Team types
    "TeamInfo",
    "TeamMember",
    "MembersResponse",
    "UsageBreakdown",
    "UsageResponse",
    # Invite types
    "Invite",
    "InviteListResponse",
    # Billing types
    "CheckoutResponse",
    "PortalResponse",
    # Device types
    "Device",
    # Alert types
    "AlertRule",
    # Webhook types
    "Webhook",
    "CreateWebhookResponse",
    "WebhookDelivery",
    "TestWebhookResponse",
    # Firewall types
    "FirewallRule",
]
