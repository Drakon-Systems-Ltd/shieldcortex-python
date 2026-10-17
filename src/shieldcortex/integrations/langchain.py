"""LangChain callbacks for ShieldCortex scanning.

The async handler is for ``ainvoke``/``astream``; the sync handler is for
``invoke``. They scan chain inputs, LLM prompts, chat message text, tool inputs,
LLM outputs, and tool outputs. Chat message text means string content, string
blocks, and dict blocks whose ``text`` is a string and whose ``type`` is
``"text"`` or absent.

Tool outputs are reduced to text before scanning: a string is scanned as is;
an object with string ``.content`` (such as a ``ToolMessage``) is scanned by
that content; a list ``.content`` is scanned as its string items and the
string ``text`` of its dict items, joined by newlines (other blocks, such as
images or dicts without a string ``text``, are dropped, not JSON-encoded);
anything else is JSON-encoded (``default=str``), falling back to ``str()``.
``None``, and non-string outputs that reduce to empty text, are not scanned.

By default only ``BLOCK`` verdicts act. ``block_on_quarantine=True`` treats
``QUARANTINE`` the same way. With ``raise_on_block=True``, a block raises
:class:`ContentBlockedError`; otherwise it is logged as a warning.

LLM output is scanned in ``on_llm_end``, after the model finishes. With
``stream``/``astream`` every chunk has already reached the caller by then, so
an output block stops the run after delivery and cannot prevent exposure.

By default a :class:`~shieldcortex.errors.ShieldCortexError` from the scan
call (any HTTP error such as 401, 429 or 5xx, or a timeout) is logged and that
scan is skipped, so the content passes (fail open). With ``fail_closed=True``
and ``raise_on_block=True``, such an error instead raises
:class:`ContentBlockedError` with ``result=None`` and the original error as
``__cause__``, stopping the run. ``fail_closed=True`` without
``raise_on_block=True`` raises ``ValueError`` at construction, because there
would be nothing to stop the run with. Other exceptions, such as connection
errors, are not caught: with ``raise_on_block=True`` they stop the run,
otherwise LangChain logs them.

Exception: with the async handler, a tool without a coroutine (a sync-only
tool) called through ``ainvoke`` runs in a worker thread, and LangChain logs
and swallows every exception the async handler raises there. Neither a block
nor a ``fail_closed`` scan error stops that tool: it runs and its output is
returned. Give such tools a coroutine, or attach the sync handler (with a
sync client) to those calls; its exceptions do propagate on that route.

Install with ``pip install shieldcortex[langchain]``.
"""

from __future__ import annotations

import json
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
    """Blocked content, with the scan result and source identifier.

    Raised for a ``BLOCK`` verdict (or ``QUARANTINE`` with
    ``block_on_quarantine=True``). With ``fail_closed=True`` it is also raised
    when the scan itself fails: then ``result`` is ``None`` and the
    :class:`~shieldcortex.errors.ShieldCortexError` is the ``__cause__``.
    """

    def __init__(
        self, result: ScanResult | None, source_identifier: str, reason: str | None = None
    ) -> None:
        self.result = result
        self.source_identifier = f"langchain:{source_identifier}"
        if reason is None:
            reason = result.firewall.reason if result is not None else "scan failed"
        super().__init__(f"ShieldCortex blocked {source_identifier}: {reason}")


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
                    elif isinstance(block, dict) and block.get("type", "text") == "text":
                        # Typed text blocks and legacy untyped ``{"text": ...}``
                        # blocks (extra keys allowed). Other block types are
                        # not text, even when they carry a ``text`` key.
                        value = block.get("text")
                        if isinstance(value, str):
                            texts.append(value)
    return texts


def _tool_output_text(output: Any) -> str | None:
    """Reduce a tool output to the text to scan, or ``None`` to skip it."""
    if output is None:
        return None
    if isinstance(output, str):
        return output
    content = getattr(output, "content", None)
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        text = "\n".join(part for part in parts if part)
    else:
        try:
            text = json.dumps(output, default=str)
        except (TypeError, ValueError):
            text = str(output)
    return text or None


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
    fail_closed: bool
    block_on_quarantine: bool
    audit_ids: list[int]

    def _configure(
        self,
        mode: Mode,
        scan_inputs: bool,
        scan_outputs: bool,
        raise_on_block: bool,
        fail_closed: bool = False,
        block_on_quarantine: bool = False,
    ) -> None:
        if fail_closed and not raise_on_block:
            raise ValueError("fail_closed=True requires raise_on_block=True")
        self.mode = mode
        self.scan_inputs = scan_inputs
        self.scan_outputs = scan_outputs
        self.raise_on_block = raise_on_block
        self.fail_closed = fail_closed
        self.block_on_quarantine = block_on_quarantine
        self.audit_ids = []

    def _scan_options(self, source_identifier: str) -> dict[str, Any]:
        return {
            "source": ScanSource(type="agent", identifier=f"langchain:{source_identifier}"),
            "config": ScanConfig(mode=self.mode),
        }

    def _handle_error(self, exc: ShieldCortexError, source_identifier: str) -> None:
        if self.fail_closed:
            raise ContentBlockedError(None, source_identifier, f"scan failed: {exc}") from exc
        logger.warning("ShieldCortex scan error: %s", exc)

    def _handle_result(self, result: ScanResult, source_identifier: str) -> None:
        self.audit_ids.append(result.audit_id)
        verdict = result.firewall.result
        if verdict == "BLOCK" or (verdict == "QUARANTINE" and self.block_on_quarantine):
            error = ContentBlockedError(result, source_identifier)
            if self.raise_on_block:
                raise error
            logger.warning("%s", error)


class ShieldCortexCallbackHandler(_ScanLogic, AsyncCallbackHandler):
    """Async LangChain handler for ``ainvoke`` and ``astream``.

    Scans chain inputs, LLM prompts, chat message text, tool inputs, LLM
    outputs, and tool outputs (structured outputs are reduced to text).
    ``raise_on_block=True`` propagates :class:`ContentBlockedError` (a
    ``ValueError``). ``BLOCK`` acts; ``block_on_quarantine=True`` (default
    ``False``) makes ``QUARANTINE`` act too. ``fail_closed=True`` (default
    ``False``, requires ``raise_on_block=True``) raises on scan errors instead
    of logging and skipping them. Streamed output is scanned after delivery,
    and nothing this handler raises stops a sync-only tool under ``ainvoke``;
    see the module docstring for both and for the reduction rules.
    """

    def __init__(
        self,
        client: AsyncShieldCortex,
        *,
        mode: Mode = "balanced",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        raise_on_block: bool = False,
        fail_closed: bool = False,
        block_on_quarantine: bool = False,
    ) -> None:
        self.client = client
        self._configure(
            mode, scan_inputs, scan_outputs, raise_on_block, fail_closed, block_on_quarantine
        )
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
            for prompt in dict.fromkeys(p for p in prompts if p):
                await self._scan(prompt, "llm_input")

    async def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[BaseMessage]], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            for content in dict.fromkeys(t for t in _chat_texts(messages) if t):
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
        if self.scan_outputs:
            text = _tool_output_text(output)
            if text is not None:
                await self._scan(text, "tool_output")

    async def _scan(self, content: str, source_identifier: str) -> None:
        try:
            result = await self.client.scan(content, **self._scan_options(source_identifier))
        except ShieldCortexError as exc:
            self._handle_error(exc, source_identifier)
            return
        self._handle_result(result, source_identifier)


class ShieldCortexSyncCallbackHandler(_ScanLogic, BaseCallbackHandler):
    """Sync LangChain handler for ``invoke`` with the same scanning options.

    ``raise_on_block=True`` propagates :class:`ContentBlockedError` (a
    ``ValueError``). ``BLOCK`` acts; ``block_on_quarantine=True`` (default
    ``False``) makes ``QUARANTINE`` act too. ``fail_closed=True`` (default
    ``False``, requires ``raise_on_block=True``) raises on scan errors instead
    of logging and skipping them. Streamed output is scanned after delivery;
    see the module docstring for that and for the reduction rules.
    """

    def __init__(
        self,
        client: ShieldCortex,
        *,
        mode: Mode = "balanced",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        raise_on_block: bool = False,
        fail_closed: bool = False,
        block_on_quarantine: bool = False,
    ) -> None:
        self.client = client
        self._configure(
            mode, scan_inputs, scan_outputs, raise_on_block, fail_closed, block_on_quarantine
        )
        self.raise_error = raise_on_block

    def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            self._scan(str(inputs), "chain_input")

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        if self.scan_inputs:
            for prompt in dict.fromkeys(p for p in prompts if p):
                self._scan(prompt, "llm_input")

    def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[BaseMessage]], **kwargs: Any
    ) -> None:
        if self.scan_inputs:
            for content in dict.fromkeys(t for t in _chat_texts(messages) if t):
                self._scan(content, "chat_input")

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        if self.scan_outputs:
            for content in _output_texts(response):
                self._scan(content, "llm_output")

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        if self.scan_inputs:
            self._scan(input_str, "tool_input")

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        if self.scan_outputs:
            text = _tool_output_text(output)
            if text is not None:
                self._scan(text, "tool_output")

    def _scan(self, content: str, source_identifier: str) -> None:
        try:
            result = self.client.scan(content, **self._scan_options(source_identifier))
        except ShieldCortexError as exc:
            self._handle_error(exc, source_identifier)
            return
        self._handle_result(result, source_identifier)
