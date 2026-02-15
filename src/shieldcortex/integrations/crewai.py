"""CrewAI integration for ShieldCortex memory security scanning.

Scans all memory writes through the ShieldCortex defence pipeline
before they reach the underlying memory store.

Install with::

    pip install shieldcortex[crewai]

Usage::

    from shieldcortex import ShieldCortex
    from shieldcortex.integrations.crewai import ShieldCortexMemoryGuard

    client = ShieldCortex(api_key="sc_live_...")
    guard = ShieldCortexMemoryGuard(client)

    # Scan content before saving to any memory store
    guard.check("user input to remember")  # raises if blocked
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from shieldcortex.types import ScanConfig, ScanResult, ScanSource

if TYPE_CHECKING:
    from shieldcortex.client import ShieldCortex


class MemoryBlockedError(Exception):
    """Raised when ShieldCortex blocks a memory write."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__(
            f"ShieldCortex blocked memory write: {result.firewall.reason}"
        )


class ShieldCortexMemoryGuard:
    """Memory security guard that scans content through ShieldCortex.

    Use this as a pre-write check in any memory pipeline (CrewAI, custom, etc.).
    Raises :class:`MemoryBlockedError` if the content is blocked or quarantined.

    Args:
        client: A :class:`~shieldcortex.ShieldCortex` instance.
        mode: Defence mode — ``"strict"``, ``"balanced"``, or ``"permissive"``.
        block_on_quarantine: Also block writes that are quarantined (not just blocked).
        source_identifier: Identifier passed as the scan source (default: ``"crewai"``).
    """

    def __init__(
        self,
        client: ShieldCortex,
        *,
        mode: Literal["strict", "balanced", "permissive"] = "balanced",
        block_on_quarantine: bool = True,
        source_identifier: str = "crewai",
    ) -> None:
        self.client = client
        self.mode = mode
        self.block_on_quarantine = block_on_quarantine
        self.source_identifier = source_identifier
        self.audit_ids: list[int] = []

    def check(self, content: str, *, title: str | None = None) -> ScanResult:
        """Scan content and raise if blocked.

        Returns the :class:`~shieldcortex.ScanResult` if allowed.

        Raises:
            MemoryBlockedError: If the content is blocked or quarantined.
        """
        result = self.client.scan(
            content,
            title=title,
            source=ScanSource(type="agent", identifier=self.source_identifier),
            config=ScanConfig(mode=self.mode),
        )
        self.audit_ids.append(result.audit_id)

        if result.firewall.result == "BLOCK":
            raise MemoryBlockedError(result)

        if self.block_on_quarantine and result.firewall.result == "QUARANTINE":
            raise MemoryBlockedError(result)

        return result
