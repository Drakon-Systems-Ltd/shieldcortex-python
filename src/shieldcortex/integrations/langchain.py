"""LangChain callbacks for ShieldCortex scanning.

The async handler is for ``ainvoke``/``astream``; the sync handler is for
``invoke``. They scan chain inputs, LLM prompts, chat message text, tool inputs,
LLM outputs, and string tool outputs. Only ``BLOCK`` verdicts act today.
With ``raise_on_block=True``, a block raises :class:`ContentBlockedError`.
Scan API errors are logged and the run continues.

Install with ``pip install shieldcortex[langchain]``.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from shieldcortex.async_client import AsyncShieldCortex
from shieldcortex.client import ShieldCortex
from shieldcortex.errors import ShieldCortexError
from shieldcortex.types import ScanConfig, ScanResult, ScanSource

try:
    from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError(
        "LangChain is not installed. Install with: pip install shieldcortex[langchain]"
    )

logger = logging.getLogger("shieldcortex.langchain")
Mode = Literal["strict", "balanced", "permissive"]


class ContentBlockedError(ValueError):
    """A ``BLOCK`` verdict, with the scan result and source identifier."""

    def __init__(self, result: ScanResult, source_identifier: str) -> None:
        self.result = result
        self.source_identifier = f"langchain:{source_identifier}"
        super().__init__(f"ShieldCortex blocked {source_identifier}: {result.firewall.reason}")


def _chat_texts(messages: list[list[BaseMessage]]) -> list[str]:
    texts: list[str] = []
    for batch in messages:
        for message in batch:
            content = message.content
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, str):
                        texts.append(block)
                    elif isinstance(block, dict) and block.get("type") == "text":
                        value = block.get("text")
                        if isinstance(value, str):
                            texts.append(value)
    return texts


def _output_texts(response: LLMResult) -> list[str]:
    return [
        generation.text for group in response.generations for generation in group if generation.text
    ]


class _ScanLogic:
    """Shared source construction and verdict handling for both callback types."""

    mode: Mode
    scan_inputs: bool
    scan_outputs: bool
    raise_on_block: bool
    audit_ids: list[int]

    def _configure(
        self, mode: Mode, scan_inputs: bool, scan_outputs: bool, raise_on_block: bool
    ) -> None:
        self.mode = mode
        self.scan_inputs = scan_inputs
        self.scan_outputs = scan_outputs
        self.raise_on_block = raise_on_block
        self.audit_ids = []

    def _scan_options(self, source_identifier: str) -> dict[str, Any]:
        return {
            "source": ScanSource(type="agent", identifier=f"langchain:{source_identifier}"),
            "config": ScanConfig(mode=self.mode),
        }

    def _handle_result(self, result: ScanResult, source_identifier: str) -> None:
        self.audit_ids.append(result.audit_id)
        if result.firewall.result == "BLOCK":
            error = ContentBlockedError(result, source_identifier)
            if self.raise_on_block:
                raise error
            logger.warning("%s", error)


class ShieldCortexCallbackHandler(_ScanLogic, AsyncCallbackHandler):
    """Async LangChain handler for ``ainvoke`` and ``astream``.

    Scans chain inputs, LLM prompts, chat message text, tool inputs, LLM
    outputs, and string tool outputs. ``raise_on_block=True`` propagates
    :class:`ContentBlockedError` (a ``ValueError``). Only ``BLOCK`` acts;
    scan API errors are logged and the run continues.
    """

    def __init__(
        self,
        client: AsyncShieldCortex,
        *,
        mode: Mode = "balanced",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        raise_on_block: bool = False,
    ) -> None:
        self.client = client
        self._configure(mode, scan_inputs, scan_outputs, raise_on_block)
        self.raise_error = raise_on_block

    async def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            await self._scan(str(inputs), "chain_input")

    async def on_llm_start(
        self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            for prompt in dict.fromkeys(prompts):
                await self._scan(prompt, "llm_input")

    async def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[BaseMessage]], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            for content in dict.fromkeys(_chat_texts(messages)):
                await self._scan(content, "chat_input")

    async def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        if self.scan_outputs:
            for content in _output_texts(response):
                await self._scan(content, "llm_output")

    async def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            await self._scan(input_str, "tool_input")

    async def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        if self.scan_outputs and isinstance(output, str):
            await self._scan(output, "tool_output")

    async def _scan(self, content: str, source_identifier: str) -> None:
        if not content:
            return
        try:
            result = await self.client.scan(content, **self._scan_options(source_identifier))
        except ShieldCortexError as exc:
            logger.warning("ShieldCortex scan error: %s", exc)
            return
        self._handle_result(result, source_identifier)


class ShieldCortexSyncCallbackHandler(_ScanLogic, BaseCallbackHandler):
    """Sync LangChain handler for ``invoke`` with the same scanning options.

    ``raise_on_block=True`` propagates :class:`ContentBlockedError` (a
    ``ValueError``). Only ``BLOCK`` acts; scan API errors are logged and the
    run continues.
    """

    def __init__(
        self,
        client: ShieldCortex,
        *,
        mode: Mode = "balanced",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        raise_on_block: bool = False,
    ) -> None:
        self.client = client
        self._configure(mode, scan_inputs, scan_outputs, raise_on_block)
        self.raise_error = raise_on_block

    def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            self._scan(str(inputs), "chain_input")

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        if self.scan_inputs:
            for prompt in dict.fromkeys(prompts):
                self._scan(prompt, "llm_input")

    def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[BaseMessage]], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            for content in dict.fromkeys(_chat_texts(messages)):
                self._scan(content, "chat_input")

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        if self.scan_outputs:
            for content in _output_texts(response):
                self._scan(content, "llm_output")

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        if self.scan_inputs:
            self._scan(input_str, "tool_input")

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        if self.scan_outputs and isinstance(output, str):
            self._scan(output, "tool_output")

    def _scan(self, content: str, source_identifier: str) -> None:
        if not content:
            return
        try:
            result = self.client.scan(content, **self._scan_options(source_identifier))
        except ShieldCortexError as exc:
            logger.warning("ShieldCortex scan error: %s", exc)
            return
        self._handle_result(result, source_identifier)
