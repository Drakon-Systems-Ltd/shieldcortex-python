"""Scan LangChain inputs and outputs with the matching callback handler.

Install with ``pip install shieldcortex[langchain]``. The handlers scan chain
inputs, LLM prompts, text in chat messages, tool inputs, LLM outputs, and
string tool outputs. Only BLOCK verdicts act; scan API errors are logged and
the run continues.
"""

import asyncio

from langchain_core.language_models.fake_chat_models import FakeListChatModel

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.integrations.langchain import (
    ContentBlockedError,
    ShieldCortexCallbackHandler,
    ShieldCortexSyncCallbackHandler,
)


async def main() -> None:
    model = FakeListChatModel(responses=["Hello!"])

    async with AsyncShieldCortex(api_key="sc_live_YOUR_KEY_HERE") as client:
        handler = ShieldCortexCallbackHandler(client, raise_on_block=True)
        try:
            print(await model.ainvoke("Hello", config={"callbacks": [handler]}))
        except ContentBlockedError as error:  # also a ValueError
            print(f"Blocked {error.source_identifier}: {error.result.firewall.reason}")

    # For invoke(), use the sync client and handler. The async handler's block
    # cannot propagate from a sync call.
    with ShieldCortex(api_key="sc_live_YOUR_KEY_HERE") as client:
        handler = ShieldCortexSyncCallbackHandler(client, raise_on_block=True)
        try:
            print(model.invoke("Hello", config={"callbacks": [handler]}))
        except ContentBlockedError as error:
            print(f"Blocked {error.source_identifier}: {error.result.firewall.reason}")


if __name__ == "__main__":
    asyncio.run(main())
