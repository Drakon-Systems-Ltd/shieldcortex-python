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
pip install shieldcortex[crewai]     # also installs CrewAI (the memory guard itself does not need it)
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

The sync client holds an `httpx` connection pool. Use it as a context manager
so the pool is closed when you are done:

```python
from shieldcortex import ShieldCortex

with ShieldCortex(api_key="sc_live_...") as client:
    result = client.scan("user input to remember")
```

In long-lived processes that keep a client around instead, call
`client.close()` when you are finished with it.

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

## Memory Guard (CrewAI and others)

`ShieldCortexMemoryGuard` is a framework-agnostic pre-write check: call `guard.check()` before writing content to any memory store — from a CrewAI agent, another framework, or your own code. It scans the content and raises `MemoryBlockedError` if it is blocked (or, by default, quarantined). It does not hook into CrewAI automatically and does not import CrewAI; the `[crewai]` extra only installs CrewAI itself.

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

The callbacks scan chain inputs, LLM prompts, text in chat messages, tool inputs,
LLM outputs, and tool outputs. Use the async handler for `ainvoke` and
`astream`, or the sync handler for `invoke`:

```python
from langchain_openai import ChatOpenAI  # or any LangChain chat model / LLM
from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex.integrations.langchain import (
    ContentBlockedError,
    ShieldCortexCallbackHandler,
    ShieldCortexSyncCallbackHandler,
)

model = ChatOpenAI()

async with AsyncShieldCortex(api_key="sc_live_...") as client:
    handler = ShieldCortexCallbackHandler(client, raise_on_block=True)
    try:
        reply = await model.ainvoke("Hello", config={"callbacks": [handler]})
    except ContentBlockedError as error:  # also a ValueError
        print(error.result.firewall.reason, error.source_identifier)

with ShieldCortex(api_key="sc_live_...") as client:
    handler = ShieldCortexSyncCallbackHandler(client, raise_on_block=True)
    reply = model.invoke("Hello", config={"callbacks": [handler]})
```

By default only `BLOCK` verdicts act. With `raise_on_block=True`, a block stops
the run with `ContentBlockedError`; otherwise it logs a warning. Use the matching
handler for the call mode: LangChain cannot propagate an async handler's block
from `invoke`.

- **Chat message text** means string content, string blocks, and dict blocks
  whose `text` is a string and whose `type` is `"text"` or absent. Images and
  other block types are not scanned. Empty prompts are skipped.
- **Streaming:** LLM output is scanned when the model finishes. With `stream`
  or `astream`, every chunk has already reached your code by then, so an
  output block stops the run after delivery and cannot prevent exposure.
  Buffer the stream yourself if blocked output must never be shown. Input
  scans still run before the model starts.
- **Tool outputs** are reduced to text before scanning: strings as is; objects
  with string `.content` (such as `ToolMessage`) by that content; a list
  `.content` by its string items and the string `text` of its dict items,
  joined by newlines; anything else as JSON (`default=str`), falling back to
  `str()`. Other blocks in a list `.content`, such as images or dicts without
  a string `text` (for example `{"payload": "..."}`), are dropped rather than
  JSON-encoded, so their contents are not scanned. `None` and non-string outputs that reduce
  to empty text are not scanned.
- **Sync-only tools under `ainvoke`:** LangChain runs a tool that has no
  coroutine in a worker thread and logs and swallows every exception the
  async handler raises there. Neither a `BLOCK` verdict nor a `fail_closed`
  scan error stops that tool: it runs and `ainvoke` returns its output. Give
  the tool an async implementation (`coroutine=` on `StructuredTool`, or
  `_arun`), or pass the sync handler with a sync client for those calls,
  e.g. `await tool.ainvoke(args, config={"callbacks": [sync_handler]})`; its
  exceptions do propagate on that route.
- **Scan errors:** by default a `ShieldCortexError` from the scan call (any
  HTTP error such as 401, 429 or 5xx, or a timeout) is logged and that scan is
  skipped, so the content passes. Other exceptions, such as connection errors,
  are not caught: with `raise_on_block=True` they stop the run, otherwise
  LangChain logs them.

Two opt-in options, available on both handlers:

| Option | Default | Effect |
|---|---|---|
| `fail_closed` | `False` | With `raise_on_block=True`, a `ShieldCortexError` from a scan raises `ContentBlockedError` instead of being logged and skipped (except for sync-only tools under `ainvoke` with the async handler, see above). `error.result` is `None` and `error.__cause__` is the original error. Requires `raise_on_block=True`; otherwise the constructor raises `ValueError`. |
| `block_on_quarantine` | `False` | Treat `QUARANTINE` verdicts exactly like `BLOCK` (warn, or raise with `raise_on_block=True`). |

```python
handler = ShieldCortexSyncCallbackHandler(
    client, raise_on_block=True, fail_closed=True, block_on_quarantine=True
)
```

`ContentBlockedError.result` is typed `ScanResult | None`. Without
`fail_closed` it is never `None` at runtime, but type checkers will still ask
you to narrow it before reading `error.result.firewall`:

```python
except ContentBlockedError as error:
    if error.result is None:  # fail_closed: the scan itself failed
        print("scan failed:", error.__cause__)
    else:
        print(error.result.firewall.reason)
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

# Export as CSV — returns the raw body plus integrity headers
export = client.export_audit_logs(format="csv")
print(export.content)
print(export.headers.sha256)  # None ⇒ export unverifiable
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

## API Coverage

The SDK covers the full customer surface documented in the SDK lockstep contract:

| Category | Methods |
|----------|---------|
| **Scanning** | `scan()`, `scan_batch()`, `scan_skill()` |
| **Audit** | `get_audit_logs()`, `get_audit_entry()`, `get_audit_stats()`, `get_audit_trends()`, `export_audit_logs()`, `iter_audit_logs()`, `ingest_audit_events()`, `get_iron_dome_stats()`, `get_iron_dome_events()` |
| **Audit Export Manifests** | `list_audit_exports()`, `get_audit_export_manifest()`, `verify_audit_export()`, `list_audit_export_verifications()` |
| **Quarantine** | `get_quarantine()`, `get_quarantine_item()`, `review_quarantine_item()` |
| **API Keys** | `create_api_key()`, `list_api_keys()`, `revoke_api_key()` |
| **Teams** | `get_team()`, `update_team()`, `get_team_members()`, `get_usage()` |
| **Invites** | `create_invite()`, `list_invites()`, `delete_invite()`, `resend_invite()` |
| **Billing** (deprecated) | `create_checkout_session()`, `create_portal_session()` — self-serve plans retired 2026-07; retained for grandfathered licence holders |
| **Devices** | `get_devices()`, `register_device()`, `update_device()`, `device_heartbeat()` |
| **Alerts** | `get_alerts()`, `create_alert()`, `update_alert()`, `delete_alert()` |
| **Webhooks** | `get_webhooks()`, `create_webhook()`, `update_webhook()`, `delete_webhook()`, `test_webhook()`, `get_webhook_deliveries()` |
| **Firewall Rules** | `get_firewall_rules()`, `get_active_firewall_rules()`, `create_firewall_rule()`, `update_firewall_rule()`, `delete_firewall_rule()` |
| **Iron Dome** | `get_injection_patterns()`, `get_injection_patterns_sync()`, `create_injection_pattern()`, `update_injection_pattern()`, `test_injection_pattern()`, `delete_injection_pattern()`, `get_iron_dome_policies()`, `get_iron_dome_policy_sync()`, `create_iron_dome_policy()`, `update_iron_dome_policy()`, `set_default_iron_dome_policy()`, `delete_iron_dome_policy()` |
| **Verification** | `submit_verification()`, `list_verifications()`, `get_verification()`, `get_verification_stats()`, `delete_verification()` |
| **Skills** | `ingest_skill_scans()`, `list_skill_scans()` |
| **Threats** | `report_threat()` |
| **Incidents** | `replay_incidents()` |
| **Recall** | `explain_recall()` |
| **Sync** | `get_sync_health()`, `push_memories()`, `list_synced_memories()`, `push_memory_graph()` |
| **Licence** | `get_license()`, `regenerate_license()` |

### Deferred endpoints

The audit **verification-export download chain** (`GET .../verifications/export`,
`GET .../verification-exports`, `GET .../verification-exports/{id}` and its
`/download`) is deliberately deferred — it serves CLI tooling rather than SDK
consumers. See `tests/endpoint_manifest.py` for the canonical list.

### Out of scope

- `/v1/platform/*` — platform-owner operations
- `/v1/auth/*` — magic-link login flows (browser/dashboard, not API-key auth)
- `/v1/customizer/*` — retired 2026-07

Additional dashboard/session-scoped `/v1` routes exist server-side; they sit
outside the SDK's API-key surface.

### Cross-SDK policy notes

The Python and TypeScript SDKs cover the same endpoint manifest, with two
deliberate differences:

1. **Deletes** — the TypeScript SDK returns `void` from every delete method;
   the Python SDK returns the typed response body where the server sends one
   (per-language internal consistency).
2. **Audit export** — both SDKs return the raw file content together with the
   parsed `X-ShieldCortex-Export-*` integrity headers. An absent `sha256` or
   `signature` header means the export is unverifiable.

## Documentation

- [ShieldCortex Docs](https://shieldcortex.ai/docs)
- [API Reference](https://shieldcortex.ai/docs)
- [Examples](examples/)

## License

MIT
