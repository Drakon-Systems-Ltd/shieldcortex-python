# shieldcortex

[![PyPI](https://img.shields.io/pypi/v/shieldcortex)](https://pypi.org/project/shieldcortex/)
[![Python](https://img.shields.io/pypi/pyversions/shieldcortex)](https://pypi.org/project/shieldcortex/)
[![License](https://img.shields.io/pypi/l/shieldcortex)](LICENSE)

Official Python SDK for the [ShieldCortex](https://shieldcortex.ai) API — AI memory security scanning.

## How It Works

AI agents store memories (user inputs, tool outputs, conversation history) to improve over time. But those memories are an attack surface — prompt injection, credential leaks, and encoding attacks can all be smuggled into memory stores.

ShieldCortex scans content **before** it reaches your agent's memory through a 6-layer defence pipeline:

```
Agent receives content
        │
        ▼
  ShieldCortex scan ──→ BLOCK   → reject, log threat
        │
        ▼
      ALLOW ──→ safe to store in memory
```

The SDK sends content to the ShieldCortex cloud API and returns a verdict: **ALLOW**, **BLOCK**, or **QUARANTINE** — along with trust scores, threat indicators, and sensitivity classification.

**Get an API key** at [shieldcortex.ai](https://shieldcortex.ai) (free tier: 500 scans/month).

## Installation

```bash
pip install shieldcortex
```

With framework integrations:

```bash
pip install shieldcortex[crewai]     # CrewAI memory guard
pip install shieldcortex[langchain]  # LangChain callback handler
```

## Quick Start

```python
from shieldcortex import ShieldCortex

client = ShieldCortex(api_key="sc_live_...")

# Scan content before storing in your agent's memory
result = client.scan("user input to remember")

if result.allowed:
    save_to_memory(result)  # safe — store it
else:
    print(f"Blocked: {result.firewall.reason}")
    print(f"Threats: {result.firewall.threat_indicators}")
    # don't store — content failed security checks
```

## Async Support

```python
from shieldcortex import AsyncShieldCortex

async with AsyncShieldCortex(api_key="sc_live_...") as client:
    result = await client.scan("user input here")
```

## Batch Scanning

Scan up to 100 items in a single request — useful for bulk-importing memory entries:

```python
from shieldcortex import BatchItem

result = client.scan_batch([
    BatchItem(content="memory entry 1"),
    BatchItem(content="memory entry 2"),
])
print(f"Scanned: {result.total_scanned}, Threats: {result.threats}")
```

## CrewAI Integration

Add a security gate between your CrewAI agent and its memory store. The guard scans all content before it's saved — blocking prompt injection and credential leaks:

```python
from shieldcortex import ShieldCortex
from shieldcortex.integrations.crewai import ShieldCortexMemoryGuard, MemoryBlockedError

client = ShieldCortex(api_key="sc_live_...")
guard = ShieldCortexMemoryGuard(client, mode="strict")

try:
    guard.check("content to remember")
    # Safe — save to memory store
except MemoryBlockedError as e:
    print(f"Blocked: {e.result.firewall.reason}")
```

## LangChain Integration

Automatically scan all LLM inputs and outputs as they flow through your chain — no changes to your existing code:

```python
from shieldcortex import AsyncShieldCortex
from shieldcortex.integrations.langchain import ShieldCortexCallbackHandler

client = AsyncShieldCortex(api_key="sc_live_...")
handler = ShieldCortexCallbackHandler(client, raise_on_block=True)

# Scans inputs on chain start, outputs on LLM end, and tool I/O
llm = ChatOpenAI(callbacks=[handler])
```

## Audit Logs

Every scan is logged. Query your history, export for compliance, or auto-paginate through all entries:

```python
from shieldcortex import AuditQuery

# Query with filters
logs = client.get_audit_logs(AuditQuery(level="BLOCK", limit=10))

# Auto-paginate through all entries
for entry in client.iter_audit_logs():
    print(entry.id, entry.firewall_result)

# Export as CSV
csv = client.export_audit_logs(format="csv")
```

## Error Handling

```python
from shieldcortex.errors import AuthError, RateLimitError, ValidationError

try:
    result = client.scan("content")
except AuthError:
    print("Invalid API key")
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after}s")
except ValidationError:
    print("Invalid request")
```

## Full API Coverage

The SDK covers all ShieldCortex API endpoints:

| Category | Methods |
|----------|---------|
| **Scanning** | `scan()`, `scan_batch()`, `scan_skill()` |
| **Audit** | `get_audit_logs()`, `get_audit_entry()`, `get_audit_stats()`, `get_audit_trends()`, `export_audit_logs()`, `iter_audit_logs()` |
| **Quarantine** | `get_quarantine()`, `get_quarantine_item()`, `review_quarantine_item()` |
| **API Keys** | `create_api_key()`, `list_api_keys()`, `revoke_api_key()` |
| **Teams** | `get_team()`, `update_team()`, `get_team_members()`, `get_usage()` |
| **Invites** | `create_invite()`, `list_invites()`, `delete_invite()`, `resend_invite()` |
| **Billing** | `create_checkout_session()`, `create_portal_session()` |
| **Devices** | `get_devices()`, `register_device()`, `update_device()`, `device_heartbeat()` |
| **Alerts** | `get_alerts()`, `create_alert()`, `update_alert()`, `delete_alert()` |
| **Webhooks** | `get_webhooks()`, `create_webhook()`, `update_webhook()`, `delete_webhook()`, `test_webhook()`, `get_webhook_deliveries()` |
| **Firewall Rules** | `get_firewall_rules()`, `get_active_firewall_rules()`, `create_firewall_rule()`, `update_firewall_rule()`, `delete_firewall_rule()` |

## Documentation

- [ShieldCortex Docs](https://shieldcortex.ai/docs)
- [API Reference](https://shieldcortex.ai/docs)
- [Examples](examples/)

## License

MIT
