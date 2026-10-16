"""Regression tests using real LangChain runnables and mocked scan HTTP calls."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx
from langchain_core.language_models.fake import FakeListLLM
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableLambda

from shieldcortex import AsyncShieldCortex, ShieldCortex
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
