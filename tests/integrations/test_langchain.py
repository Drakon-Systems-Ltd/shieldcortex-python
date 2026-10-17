"""Regression tests using real LangChain runnables and mocked scan HTTP calls."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest
import respx
from langchain_core.language_models.fake import FakeListLLM
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import StructuredTool

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.errors import AuthError, ShieldCortexError
from shieldcortex.integrations import langchain as integration

ShieldCortexCallbackHandler = integration.ShieldCortexCallbackHandler


BASE = "https://api.shieldcortex.ai"
ALLOWED_RESPONSE = {
    "allowed": True,
    "firewall": {
        "result": "ALLOW",
        "reason": "OK",
        "threatIndicators": [],
        "anomalyScore": 0.01,
        "blockedPatterns": [],
    },
    "sensitivity": {"level": "PUBLIC", "redactionRequired": False},
    "trust": {"score": 0.95},
    "auditId": 1,
}
BLOCKED_RESPONSE = {
    "allowed": False,
    "firewall": {
        "result": "BLOCK",
        "reason": "Credential leak detected",
        "threatIndicators": ["credential_leak"],
        "anomalyScore": 0.95,
        "blockedPatterns": ["AWS_KEY"],
    },
    "sensitivity": {"level": "RESTRICTED", "redactionRequired": True},
    "trust": {"score": 0.1},
    "auditId": 2,
}


def scan_requests(route: respx.Route) -> list[dict[str, object]]:
    return [json.loads(call.request.read()) for call in route.calls]


@pytest.mark.asyncio
@respx.mock
async def test_async_block_stops_chat_model() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, raise_on_block=True)
        with pytest.raises(integration.ContentBlockedError) as exc_info:
            await FakeListChatModel(responses=["hi"]).ainvoke(
                "prompt", config={"callbacks": [handler]}
            )
    assert isinstance(exc_info.value, ValueError)
    assert exc_info.value.result.firewall.result == "BLOCK"
    assert exc_info.value.source_identifier == "langchain:chat_input"
    assert len(route.calls) == 1


@pytest.mark.asyncio
@respx.mock
async def test_async_block_warns_and_returns(caplog: pytest.LogCaptureFixture) -> None:
    respx.post(f"{BASE}/v1/scan").mock(return_value=httpx.Response(200, json=BLOCKED_RESPONSE))
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, raise_on_block=False)
        with caplog.at_level(logging.WARNING, logger="shieldcortex.langchain"):
            result = await FakeListChatModel(responses=["hi"]).ainvoke(
                "prompt", config={"callbacks": [handler]}
            )
    assert result.content == "hi"
    assert "ShieldCortex blocked chat_input" in caplog.text


@pytest.mark.asyncio
@respx.mock
async def test_bare_chat_scans_prompt_once() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_outputs=False)
        await FakeListChatModel(responses=["hi"]).ainvoke(
            "prompt", config={"callbacks": [handler]}
        )
    assert [(item["content"], item["source"]["identifier"]) for item in scan_requests(route)] == [
        ("prompt", "langchain:chat_input")
    ]


@pytest.mark.asyncio
@respx.mock
async def test_bare_llm_scans_prompt() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_outputs=False)
        await FakeListLLM(responses=["hi"]).ainvoke("prompt", config={"callbacks": [handler]})
    assert [(item["content"], item["source"]["identifier"]) for item in scan_requests(route)] == [
        ("prompt", "langchain:llm_input")
    ]


@pytest.mark.asyncio
@respx.mock
async def test_chat_content_blocks_scan_text_only() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_outputs=False)
        await FakeListChatModel(responses=["hi"]).ainvoke(
            [
                HumanMessage(
                    content=[
                        {"type": "text", "text": "visible"},
                        {"type": "image_url", "image_url": "hidden"},
                        "plain",
                        "",
                    ]
                )
            ],
            config={"callbacks": [handler]},
        )
    assert [item["content"] for item in scan_requests(route)] == ["visible", "plain"]


@pytest.mark.asyncio
@respx.mock
async def test_scan_inputs_false() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_inputs=False)
        await FakeListChatModel(responses=["hi"]).ainvoke(
            "prompt", config={"callbacks": [handler]}
        )
    assert [item["source"]["identifier"] for item in scan_requests(route)] == [
        "langchain:llm_output"
    ]


@respx.mock
def test_sync_block_stops_model() -> None:
    respx.post(f"{BASE}/v1/scan").mock(return_value=httpx.Response(200, json=BLOCKED_RESPONSE))
    with ShieldCortex(api_key="sc_test_abc") as client:
        handler = integration.ShieldCortexSyncCallbackHandler(client, raise_on_block=True)
        with pytest.raises(integration.ContentBlockedError):
            FakeListChatModel(responses=["hi"]).invoke("prompt", config={"callbacks": [handler]})


@pytest.mark.asyncio
@respx.mock
async def test_chain_start_blocks() -> None:
    respx.post(f"{BASE}/v1/scan").mock(return_value=httpx.Response(200, json=BLOCKED_RESPONSE))
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, raise_on_block=True)
        with pytest.raises(integration.ContentBlockedError) as exc_info:
            await RunnableLambda(lambda value: value).ainvoke(
                "prompt", config={"callbacks": [handler]}
            )
    assert exc_info.value.source_identifier == "langchain:chain_input"


@pytest.mark.asyncio
@respx.mock
async def test_chat_untyped_text_block_with_extra_keys_is_scanned() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_outputs=False)
        await FakeListChatModel(responses=["hi"]).ainvoke(
            [
                HumanMessage(
                    content=[
                        {"text": "legacy", "metadata": {"k": "v"}},
                        {"type": "image_url", "text": "not text", "image_url": "x"},
                    ]
                )
            ],
            config={"callbacks": [handler]},
        )
    assert [item["content"] for item in scan_requests(route)] == ["legacy"]


@respx.mock
def test_sync_chat_untyped_text_block_with_extra_keys_blocks() -> None:
    respx.post(f"{BASE}/v1/scan").mock(return_value=httpx.Response(200, json=BLOCKED_RESPONSE))
    with ShieldCortex(api_key="sc_test_abc") as client:
        handler = integration.ShieldCortexSyncCallbackHandler(client, raise_on_block=True)
        with pytest.raises(integration.ContentBlockedError) as exc_info:
            FakeListChatModel(responses=["hi"]).invoke(
                [HumanMessage(content=[{"text": "secret", "metadata": {}}])],
                config={"callbacks": [handler]},
            )
    assert exc_info.value.source_identifier == "langchain:chat_input"


@pytest.mark.asyncio
@respx.mock
async def test_empty_tool_input_and_output_are_still_scanned() -> None:
    from langchain_core.tools import Tool

    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    tool = Tool(name="echo", description="echo", func=lambda value: "", coroutine=None)
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client)
        await tool.ainvoke("", config={"callbacks": [handler]})
    identifiers = [item["source"]["identifier"] for item in scan_requests(route)]
    assert "langchain:tool_input" in identifiers
    assert "langchain:tool_output" in identifiers


@pytest.mark.asyncio
@respx.mock
async def test_empty_llm_prompt_is_skipped() -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    async with AsyncShieldCortex(api_key="sc_test_abc") as client:
        handler = ShieldCortexCallbackHandler(client, scan_outputs=False)
        await FakeListLLM(responses=["hi"]).ainvoke("", config={"callbacks": [handler]})
    assert scan_requests(route) == []


# --- fail_closed, block_on_quarantine and structured tool outputs (#7) ---

QUARANTINE_RESPONSE = {
    **BLOCKED_RESPONSE,
    "firewall": {**BLOCKED_RESPONSE["firewall"], "result": "QUARANTINE"},  # type: ignore[dict-item]
    "auditId": 3,
}
SCAN_FAILURES = {
    "401": httpx.Response(401, json={"error": "bad key"}),
    "503": httpx.Response(503, text="unavailable"),
    "timeout": httpx.ReadTimeout("timed out"),
}


async def invoke(is_sync: bool, runnable: Any, value: Any, **options: Any) -> Any:
    """Invoke ``runnable`` with the sync or async handler built from ``options``."""
    if is_sync:
        with ShieldCortex(api_key="sc_test_abc") as client:
            handler = integration.ShieldCortexSyncCallbackHandler(client, **options)
            return runnable.invoke(value, config={"callbacks": [handler]})
    async with AsyncShieldCortex(api_key="sc_test_abc") as aclient:
        ahandler = ShieldCortexCallbackHandler(aclient, **options)
        return await runnable.ainvoke(value, config={"callbacks": [ahandler]})


def mock_failure(name: str) -> respx.Route:
    failure = SCAN_FAILURES[name]
    route = respx.post(f"{BASE}/v1/scan")
    if isinstance(failure, Exception):
        return route.mock(side_effect=failure)
    return route.mock(return_value=failure)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@pytest.mark.parametrize("failure", list(SCAN_FAILURES))
@respx.mock
async def test_fail_closed_raises_on_scan_error(is_sync: bool, failure: str) -> None:
    route = mock_failure(failure)
    with pytest.raises(integration.ContentBlockedError) as exc_info:
        await invoke(
            is_sync,
            FakeListChatModel(responses=["hi"]),
            "prompt",
            raise_on_block=True,
            fail_closed=True,
        )
    error = exc_info.value
    assert isinstance(error.__cause__, ShieldCortexError)
    assert error.result is None
    assert error.source_identifier == "langchain:chat_input"
    assert "scan failed" in str(error)
    if failure == "401":
        assert isinstance(error.__cause__, AuthError)
    elif failure == "503":
        assert error.__cause__.status_code == 503
    assert len(route.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@pytest.mark.parametrize("failure", list(SCAN_FAILURES))
@respx.mock
async def test_scan_error_fails_open_by_default(
    is_sync: bool, failure: str, caplog: pytest.LogCaptureFixture
) -> None:
    route = mock_failure(failure)
    with caplog.at_level(logging.WARNING, logger="shieldcortex.langchain"):
        result = await invoke(
            is_sync, FakeListChatModel(responses=["hi"]), "prompt", raise_on_block=True
        )
    assert result.content == "hi"
    assert "ShieldCortex scan error" in caplog.text
    assert [item["source"]["identifier"] for item in scan_requests(route)] == [
        "langchain:chat_input",
        "langchain:llm_output",
    ]


@pytest.mark.parametrize(
    "handler_class",
    [ShieldCortexCallbackHandler, integration.ShieldCortexSyncCallbackHandler],
    ids=["async", "sync"],
)
def test_fail_closed_requires_raise_on_block(handler_class: Any) -> None:
    with pytest.raises(ValueError, match="fail_closed=True requires raise_on_block=True"):
        handler_class(object(), fail_closed=True)
    with pytest.raises(ValueError):
        handler_class(object(), fail_closed=True, raise_on_block=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_block_on_quarantine_raises(is_sync: bool) -> None:
    respx.post(f"{BASE}/v1/scan").mock(return_value=httpx.Response(200, json=QUARANTINE_RESPONSE))
    with pytest.raises(integration.ContentBlockedError) as exc_info:
        await invoke(
            is_sync,
            FakeListChatModel(responses=["hi"]),
            "prompt",
            raise_on_block=True,
            block_on_quarantine=True,
        )
    assert exc_info.value.result is not None
    assert exc_info.value.result.firewall.result == "QUARANTINE"
    assert exc_info.value.__cause__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_quarantine_does_not_raise_by_default(is_sync: bool) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=QUARANTINE_RESPONSE)
    )
    result = await invoke(
        is_sync, FakeListChatModel(responses=["hi"]), "prompt", raise_on_block=True
    )
    assert result.content == "hi"
    assert len(route.calls) == 2


def make_tool(output: Any) -> StructuredTool:
    # A coroutine is needed for ``ainvoke`` to fire async callbacks on the event
    # loop. For sync-only tools LangChain runs async handlers through a helper
    # that logs and swallows their exceptions; see the sync-only tests below.
    def lookup(query: str) -> Any:
        return output

    async def alookup(query: str) -> Any:
        return output

    return StructuredTool.from_function(
        lookup, coroutine=alookup, name="lookup", description="lookup"
    )


TOOL_CALL = {"name": "lookup", "args": {"query": "q"}, "id": "call-1", "type": "tool_call"}


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_tool_message_output_is_scanned_and_blocks(is_sync: bool) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    with pytest.raises(integration.ContentBlockedError) as exc_info:
        await invoke(
            is_sync,
            make_tool("AKIA-secret"),
            TOOL_CALL,
            raise_on_block=True,
            scan_inputs=False,
        )
    assert exc_info.value.source_identifier == "langchain:tool_output"
    assert [item["content"] for item in scan_requests(route)] == ["AKIA-secret"]


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_tool_message_content_blocks_are_joined(is_sync: bool) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=ALLOWED_RESPONSE)
    )
    blocks = [{"type": "text", "text": "first"}, "second", {"type": "image", "url": "x"}]
    result = await invoke(is_sync, make_tool(blocks), TOOL_CALL, scan_inputs=False)
    assert isinstance(result, ToolMessage)
    assert [item["content"] for item in scan_requests(route)] == ["first\nsecond"]


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_dict_tool_output_is_scanned_as_json(is_sync: bool) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    with pytest.raises(integration.ContentBlockedError):
        await invoke(
            is_sync,
            make_tool({"key": "AKIA-secret", "n": 1}),
            {"query": "q"},
            raise_on_block=True,
            scan_inputs=False,
        )
    assert [item["content"] for item in scan_requests(route)] == [
        json.dumps({"key": "AKIA-secret", "n": 1})
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_none_tool_output_is_not_scanned(is_sync: bool) -> None:
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    await invoke(
        is_sync, make_tool(None), {"query": "q"}, raise_on_block=True, scan_inputs=False
    )
    assert len(route.calls) == 0


def test_tool_output_text_reduction() -> None:
    reduce = integration._tool_output_text

    class Unencodable:
        def __str__(self) -> str:
            return "unencodable"

    circular: list[Any] = []
    circular.append(circular)
    assert reduce(None) is None
    assert reduce("") == ""
    assert reduce("plain") == "plain"
    assert reduce(ToolMessage(content="", tool_call_id="c")) is None
    assert reduce(ToolMessage(content=[{"type": "image", "url": "x"}], tool_call_id="c")) is None
    assert reduce({"a": Unencodable()}) == '{"a": "unencodable"}'
    assert reduce(circular) == str(circular)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@respx.mock
async def test_tool_message_non_text_dict_block_is_dropped(is_sync: bool) -> None:
    # In a ToolMessage's list content only string blocks and string ``text``
    # fields are scanned; other dict blocks are dropped, not JSON-encoded.
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=BLOCKED_RESPONSE)
    )
    message = ToolMessage(content=[{"payload": "AKIA-secret"}], tool_call_id="call-1")
    result = await invoke(
        is_sync, make_tool(message), TOOL_CALL, raise_on_block=True, scan_inputs=False
    )
    assert result.content == [{"payload": "AKIA-secret"}]
    assert len(route.calls) == 0
    route.mock(return_value=httpx.Response(200, json=ALLOWED_RESPONSE))
    mixed = ToolMessage(
        content=[{"payload": "AKIA-secret"}, {"type": "text", "text": "visible"}],
        tool_call_id="call-1",
    )
    await invoke(is_sync, make_tool(mixed), TOOL_CALL, scan_inputs=False)
    # A bare list return is not a ToolMessage yet: LangChain stringifies a
    # list holding non-content blocks, so that string is scanned.
    await invoke(is_sync, make_tool([{"payload": "AKIA-secret"}]), TOOL_CALL, scan_inputs=False)
    assert [item["content"] for item in scan_requests(route)] == [
        "visible",
        '[{"payload": "AKIA-secret"}]',
    ]


# --- Sync-only tools under ``ainvoke`` (documented limitation) ---

SYNC_ONLY_SCAN_RESPONSES = {
    "block": httpx.Response(200, json=BLOCKED_RESPONSE),
    "fail_closed_503": httpx.Response(503, text="unavailable"),
}


def make_sync_only_tool(calls: list[str]) -> StructuredTool:
    def lookup(query: str) -> str:
        calls.append(query)
        return "tool output"

    return StructuredTool.from_function(lookup, name="lookup", description="lookup")


@pytest.mark.asyncio
@pytest.mark.parametrize("hook", ["tool_input", "tool_output"])
@pytest.mark.parametrize("response", list(SYNC_ONLY_SCAN_RESPONSES))
@respx.mock
async def test_async_handler_cannot_stop_sync_only_tool_under_ainvoke(
    hook: str, response: str, caplog: pytest.LogCaptureFixture
) -> None:
    # LangChain runs a sync-only tool's ``ainvoke`` through ``invoke`` in a
    # worker thread and logs and swallows the async handler's exceptions. If
    # this starts failing, LangChain now propagates them: update the docs.
    route = respx.post(f"{BASE}/v1/scan").mock(return_value=SYNC_ONLY_SCAN_RESPONSES[response])
    calls: list[str] = []
    with caplog.at_level(logging.WARNING):
        result = await invoke(
            False,
            make_sync_only_tool(calls),
            {"query": "q"},
            raise_on_block=True,
            fail_closed=True,
            scan_inputs=hook == "tool_input",
            scan_outputs=hook == "tool_output",
        )
    assert result == "tool output"
    assert calls == ["q"]
    assert len(route.calls) == 1
    assert f"ContentBlockedError('ShieldCortex blocked {hook}" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("hook", ["tool_input", "tool_output"])
@pytest.mark.parametrize("response", list(SYNC_ONLY_SCAN_RESPONSES))
@respx.mock
async def test_sync_handler_stops_sync_only_tool_under_ainvoke(hook: str, response: str) -> None:
    # The documented workaround: the sync handler's exceptions propagate.
    route = respx.post(f"{BASE}/v1/scan").mock(return_value=SYNC_ONLY_SCAN_RESPONSES[response])
    calls: list[str] = []
    tool = make_sync_only_tool(calls)
    with ShieldCortex(api_key="sc_test_abc") as client:
        handler = integration.ShieldCortexSyncCallbackHandler(
            client,
            raise_on_block=True,
            fail_closed=True,
            scan_inputs=hook == "tool_input",
            scan_outputs=hook == "tool_output",
        )
        with pytest.raises(integration.ContentBlockedError) as exc_info:
            await tool.ainvoke({"query": "q"}, config={"callbacks": [handler]})
    assert exc_info.value.source_identifier == f"langchain:{hook}"
    assert (exc_info.value.result is None) == (response == "fail_closed_503")
    assert calls == ([] if hook == "tool_input" else ["q"])
    assert len(route.calls) == 1


# --- fail_closed across every scanned hook ---

MATRIX_FAILURES: dict[str, Any] = {
    **SCAN_FAILURES,
    "429": httpx.Response(429, json={"error": "slow down"}),
    "base": ShieldCortexError("boom", 0, ""),
}
HOOKS: dict[str, Any] = {
    "chain_input": (lambda: RunnableLambda(lambda value: value), "x", {"scan_outputs": False}),
    "llm_input": (lambda: FakeListLLM(responses=["hi"]), "prompt", {"scan_outputs": False}),
    "llm_output": (lambda: FakeListLLM(responses=["hi"]), "prompt", {"scan_inputs": False}),
    "chat_input": (
        lambda: FakeListChatModel(responses=["hi"]),
        "prompt",
        {"scan_outputs": False},
    ),
    "tool_input": (lambda: make_tool("out"), {"query": "q"}, {"scan_outputs": False}),
    "tool_output": (lambda: make_tool("out"), {"query": "q"}, {"scan_inputs": False}),
}


def mock_matrix_failure(name: str) -> respx.Route:
    failure = MATRIX_FAILURES[name]
    route = respx.post(f"{BASE}/v1/scan")
    if isinstance(failure, Exception):
        return route.mock(side_effect=failure)
    return route.mock(return_value=failure)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@pytest.mark.parametrize("failure", list(MATRIX_FAILURES))
@pytest.mark.parametrize("hook", list(HOOKS))
@respx.mock
async def test_fail_closed_matrix(is_sync: bool, failure: str, hook: str) -> None:
    make_runnable, value, options = HOOKS[hook]
    route = mock_matrix_failure(failure)
    with pytest.raises(integration.ContentBlockedError) as exc_info:
        await invoke(
            is_sync, make_runnable(), value, raise_on_block=True, fail_closed=True, **options
        )
    error = exc_info.value
    assert error.result is None
    assert isinstance(error.__cause__, ShieldCortexError)
    assert error.source_identifier == f"langchain:{hook}"
    assert len(route.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("is_sync", [False, True], ids=["async", "sync"])
@pytest.mark.parametrize("hook", list(HOOKS))
@respx.mock
async def test_connection_error_propagates_unwrapped(is_sync: bool, hook: str) -> None:
    make_runnable, value, options = HOOKS[hook]
    route = respx.post(f"{BASE}/v1/scan").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(httpx.ConnectError):
        await invoke(
            is_sync, make_runnable(), value, raise_on_block=True, fail_closed=True, **options
        )
    assert len(route.calls) == 1
