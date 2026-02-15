"""CrewAI memory guard example.

Scans all memory writes through ShieldCortex before storing.

    pip install shieldcortex[crewai]
"""

from shieldcortex import ShieldCortex
from shieldcortex.integrations.crewai import MemoryBlockedError, ShieldCortexMemoryGuard

client = ShieldCortex(api_key="sc_live_YOUR_KEY_HERE")
guard = ShieldCortexMemoryGuard(client, mode="strict")

# In your CrewAI agent's memory pipeline:
memories_to_save = [
    "User prefers dark mode",
    "Meeting at 3pm with the team",
    "AWS key: AKIAIOSFODNN7EXAMPLE",  # This should be blocked
]

for memory in memories_to_save:
    try:
        result = guard.check(memory)
        print(f"  SAFE: {memory[:50]}... (trust: {result.trust.score})")
        # ... save to your memory store here ...
    except MemoryBlockedError as e:
        print(f"  BLOCKED: {memory[:50]}... ({e.result.firewall.reason})")

print(f"\nAudit trail: {len(guard.audit_ids)} scans recorded")
