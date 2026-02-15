"""LangChain callback handler example.

Scans LLM inputs and outputs through ShieldCortex.

    pip install shieldcortex[langchain]
"""

import asyncio

from shieldcortex import AsyncShieldCortex
from shieldcortex.integrations.langchain import ShieldCortexCallbackHandler


async def main() -> None:
    async with AsyncShieldCortex(api_key="sc_live_YOUR_KEY_HERE") as client:
        handler = ShieldCortexCallbackHandler(
            client,
            mode="balanced",
            scan_inputs=True,
            scan_outputs=True,
            raise_on_block=False,  # Log warnings instead of raising
        )

        # Use with any LangChain component:
        #
        # from langchain_openai import ChatOpenAI
        # llm = ChatOpenAI(callbacks=[handler])
        # response = await llm.ainvoke("Hello!")

        print(f"Handler ready. Audit IDs so far: {handler.audit_ids}")


if __name__ == "__main__":
    asyncio.run(main())
