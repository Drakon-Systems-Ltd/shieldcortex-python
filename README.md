# shieldcortex

[![PyPI](https://img.shields.io/pypi/v/shieldcortex)](https://pypi.org/project/shieldcortex/)
[![Python](https://img.shields.io/pypi/pyversions/shieldcortex)](https://pypi.org/project/shieldcortex/)
[![License](https://img.shields.io/pypi/l/shieldcortex)](LICENSE)

Official Python SDK for the [ShieldCortex](https://shieldcortex.ai) API — AI memory security scanning.

ShieldCortex is a 6-layer defence pipeline that protects AI agent memory from prompt injection, credential leaks, encoding attacks, and more.

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

# Scan user input before storing in memory
result = client.scan("user input here")

if not result.allowed:
    print(f"Blocked: {result.firewall.reason}")
    print(f"Threats: {result.firewall.threat_indicators}")
else:
    print(f"Safe (trust: {result.trust.score})")
```

## Async Support

```python
from shieldcortex import AsyncShieldCortex

async with AsyncShieldCortex(api_key="sc_live_...") as client:
    result = await client.scan("user input here")
```

## Batch Scanning

```python
from shieldcortex import BatchItem

result = client.scan_batch([
    BatchItem(content="memory entry 1"),
    BatchItem(content="memory entry 2"),
])
print(f"Scanned: {result.total_scanned}, Threats: {result.threats}")
```

## Audit Logs

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

## CrewAI Integration

Scan all memory writes before they reach your store:

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

Scan LLM inputs and outputs automatically:

```python
from shieldcortex import AsyncShieldCortex
from shieldcortex.integrations.langchain import ShieldCortexCallbackHandler

client = AsyncShieldCortex(api_key="sc_live_...")
handler = ShieldCortexCallbackHandler(client, raise_on_block=True)

# Pass to any LangChain component
llm = ChatOpenAI(callbacks=[handler])
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
