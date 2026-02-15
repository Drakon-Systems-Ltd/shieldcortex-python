"""LangChain integration for ShieldCortex memory security scanning.

Provides a callback handler that scans LLM inputs and outputs through
the ShieldCortex defence pipeline.

Install with::

    pip install shieldcortex[langchain]

Usage::

    from shieldcortex import AsyncShieldCortex
    from shieldcortex.integrations.langchain import ShieldCortexCallbackHandler

    client = AsyncShieldCortex(api_key="sc_live_...")
    handler = ShieldCortexCallbackHandler(client)

    # Pass to any LangChain component
    llm = ChatOpenAI(callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from shieldcortex.errors import ShieldCortexError
from shieldcortex.types import ScanConfig, ScanSource

try:
    from langchain_core.callbacks import AsyncCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError(
        "LangChain is not installed. Install with: pip install shieldcortex[langchain]"
    )

from shieldcortex.async_client import AsyncShieldCortex

logger = logging.getLogger("shieldcortex.langchain")


class ShieldCortexCallbackHandler(AsyncCallbackHandler):  # type: ignore[misc]
    """LangChain async callback handler that scans content through ShieldCortex.

    Scans user inputs (chain start) and LLM outputs (LLM end) through
    the defence pipeline. Optionally raises on blocked content.

    Args:
        client: An :class:`~shieldcortex.AsyncShieldCortex` instance.
        mode: Defence mode — ``"strict"``, ``"balanced"``, or ``"permissive"``.
        scan_inputs: Scan user inputs at chain start.
        scan_outputs: Scan LLM outputs.
        raise_on_block: Raise ``ValueError`` when content is blocked
            (default: log a warning).
    """

    def __init__(
        self,
        client: AsyncShieldCortex,
        *,
        mode: Literal["strict", "balanced", "permissive"] = "balanced",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        raise_on_block: bool = False,
    ) -> None:
        self.client = client
        self.mode = mode
        self.scan_inputs = scan_inputs
        self.scan_outputs = scan_outputs
        self.raise_on_block = raise_on_block
        self.audit_ids: list[int] = []

    async def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Scan user inputs at chain start."""
        if not self.scan_inputs:
            return
        input_text = str(inputs)
        await self._scan(input_text, "chain_input")

    async def on_llm_end(
        self,
        response: LLMResult,
        **kwargs: Any,
    ) -> None:
        """Scan LLM outputs."""
        if not self.scan_outputs:
            return
        for generation_list in response.generations:
            for generation in generation_list:
                if hasattr(generation, "text") and generation.text:
                    await self._scan(generation.text, "llm_output")

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Scan tool inputs."""
        if self.scan_inputs:
            await self._scan(input_str, "tool_input")

    async def on_tool_end(
        self,
        output: Any,
        **kwargs: Any,
    ) -> None:
        """Scan tool outputs."""
        if self.scan_outputs and isinstance(output, str):
            await self._scan(output, "tool_output")

    async def _scan(self, content: str, source_identifier: str) -> None:
        """Internal: scan content and handle the result."""
        try:
            result = await self.client.scan(
                content,
                source=ScanSource(
                    type="agent", identifier=f"langchain:{source_identifier}"
                ),
                config=ScanConfig(mode=self.mode),
            )
            self.audit_ids.append(result.audit_id)

            if result.firewall.result == "BLOCK":
                msg = (
                    f"ShieldCortex blocked {source_identifier}: "
                    f"{result.firewall.reason}"
                )
                if self.raise_on_block:
                    raise ValueError(msg)
                logger.warning(msg)

        except ShieldCortexError as e:
            # Don't break the LangChain pipeline on scanning errors
            logger.warning("ShieldCortex scan error: %s", e)
