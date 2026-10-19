# Changelog

## [Unreleased]

### Documentation

- README: the introductory LangChain example now narrows
  `ContentBlockedError.result` before reading `.firewall`, matching the
  `ScanResult | None` annotation added in 0.5.0, so it passes type checking.
- README: the License badge and the Examples link now use absolute GitHub
  URLs. The README is also the PyPI project description, where repo-relative
  links do not resolve.

## 0.5.0 — 2026-10-17

Minor release: opt-in fail-closed and QUARANTINE blocking for the LangChain
handlers, structured tool outputs scanned, and path parameters URL-encoded.
0.4.0 was never tagged or published, so this is the first published release
after 0.3.0 and also carries every 0.4.0 change listed below.

Defaults are unchanged for API errors and QUARANTINE: a `ShieldCortexError`
from a scan is still logged and skipped, and QUARANTINE still does not act,
unless you opt in with the new options below.

### Added

- LangChain handlers: `fail_closed` (default `False`). With
  `raise_on_block=True`, a `ShieldCortexError` from a scan (401, 429, 5xx,
  timeout, and every other API error) raises `ContentBlockedError` with
  `result=None` and the original error as `__cause__`, so the run stops
  (except for sync-only tools under `ainvoke` with the async handler; see
  Known limitation). `fail_closed=True` without `raise_on_block=True` raises `ValueError` at
  construction.
- `ContentBlockedError.result` is now typed `ScanResult | None`. It is only
  `None` with `fail_closed=True`, so default-option callers never see `None`
  at runtime, but type checkers will ask them to narrow before reading
  `error.result.firewall`:
  `if error.result is not None: print(error.result.firewall.reason)`.
- LangChain handlers: `block_on_quarantine` (default `False`). When `True`,
  a QUARANTINE verdict is treated exactly like BLOCK.

### Fixed

- LangChain `on_tool_end` now scans structured tool outputs (ToolMessage
  content, content blocks, dicts) instead of skipping them. Non-string
  outputs are reduced to text (`.content` string, joined text parts of a
  content-block list, or JSON with a `str()` fallback); non-text blocks in a
  content list are dropped, not JSON-encoded; `None` and outputs
  that reduce to empty text are not scanned. String outputs are scanned as
  before.
- Path parameters (ids, device UUIDs, export manifest ids) are now
  percent-encoded as a single URL segment, so `/`, `?`, `#`, `%`, spaces and
  non-ASCII characters can no longer change the route. Empty, `.` and `..`
  values raise `ValueError` before any request is sent.

### Known limitation

- LangChain answers a bare (non-chat) LLM call that is fully served from its
  LLM cache without firing `on_llm_start` or `on_llm_end`, so neither the
  prompt nor the cached output is scanned and no block can stop that call.
  The 0.4.0 bare-LLM prompt scanning applies only to calls that reach the
  model. Set `cache=False` on LLMs whose calls must be scanned (the default,
  `cache=None`, uses any cache set with `set_llm_cache`), or scan outside the
  model call. Chat models fire their start callback before the cache lookup,
  so cached chat calls still have their input scanned. Regression tests pin
  this behaviour.
- With the async handler, a sync-only tool (no coroutine) called through
  `ainvoke` runs in a worker thread where LangChain logs and swallows every
  exception the handler raises. Neither BLOCK verdicts nor `fail_closed`
  scan-error raises stop that tool: it runs and `ainvoke` returns its output.
  Give the tool an async implementation, or pass the sync handler (with a
  sync client) for those calls; its exceptions propagate on that route.

## 0.4.0 — 2026-10-16

Minor release: the LangChain integration now stops the run on BLOCK, scans
bare LLM and chat prompts, and adds two public names
(`ShieldCortexSyncCallbackHandler`, `ContentBlockedError`). No breaking changes.

### Fixed

- LangChain async blocks now propagate when `raise_on_block=True`.
- Bare LLM and chat model inputs are scanned by their start callbacks.
  Chat message text covers string content, string blocks, and dict blocks
  whose `text` is a string and whose `type` is `"text"` or absent. Empty
  prompts and empty chat text are skipped; chain and tool scans are unchanged.

### Added

- `ShieldCortexSyncCallbackHandler` for synchronous LangChain calls and
  `ContentBlockedError` for catching blocked content with its scan result.
- Ship a PEP 561 `py.typed` marker so type checkers treat the installed
  package as typed (the `Typing :: Typed` classifier was already declared).

### Documentation

- LangChain: output is scanned when the model finishes, so with `stream` /
  `astream` a BLOCK on output stops the run only after the chunks were
  delivered. Only `ShieldCortexError` from the scan call is logged and
  skipped; other exceptions (for example connection errors) stop the run
  when `raise_on_block=True`.
- README: describe `ShieldCortexMemoryGuard` as a framework-agnostic
  pre-write guard (it does not import or hook into CrewAI; the `[crewai]`
  extra only installs CrewAI itself).
- README: document the sync client's context manager
  (`with ShieldCortex(...) as client:`) and `client.close()`.

## 0.3.0 — 2026-08-15

- Version-only release, coordinated with core v4.52.0. No API changes:
  only the package version (`pyproject.toml`, `_version.py`) changed
  from 0.2.0.

## 0.2.0 — 2026-08-11

SDK lockstep release: the Python SDK now covers the full customer surface
documented in the SDK lockstep contract, in lockstep with the TypeScript SDK.

### Added

- **Verification** — `submit_verification()`, `list_verifications()`,
  `get_verification()`, `get_verification_stats()`, `delete_verification()`
- **Skills** — `ingest_skill_scans()`, `list_skill_scans()`
- **Threats** — `report_threat()` (OpenClaw realtime compat shim)
- **Incidents** — `replay_incidents()`
- **Recall** — `explain_recall()`
- **Sync** — `get_sync_health()`, `push_memories()`, `list_synced_memories()`,
  `push_memory_graph()`. Note: `list_synced_memories()` omits the
  `include_deleted` param unless truthy — the server Boolean-coerces any
  present value (even `"false"`) as enabling it. Every other boolean query
  param was audited for the same coercion trap; none affected.
- **Licence** — `get_license()`, `regenerate_license()`
- **Audit** — `ingest_audit_events()`, `get_iron_dome_stats()`,
  `get_iron_dome_events()`, and the export-manifest surface
  (`list_audit_exports()`, `get_audit_export_manifest()`,
  `verify_audit_export()`, `list_audit_export_verifications()`)
- Cross-SDK endpoint parity manifest and drift guard
  (`tests/endpoint_manifest.py`, kept in lockstep with the TS SDK's
  `tests/endpoint-manifest.ts`), including a sync/async surface parity test
- Shared request builders (`_payloads.py`) so the sync and async clients
  construct identical wire payloads and cannot drift

### Changed

- **BREAKING:** `export_audit_logs()` (both clients) now returns
  `AuditExportResult` — the raw file body in `.content` plus the parsed
  `X-ShieldCortex-Export-*` integrity headers in `.headers` — instead of a
  bare `str`. Previously the integrity headers were discarded, so exports
  structurally could not be verified. An absent `sha256`/`signature` header
  is `None` (never `""`): the export is unverifiable. Migration:
  `client.export_audit_logs(...)` → `client.export_audit_logs(...).content`.

### Deprecated

- `create_checkout_session()` / `create_portal_session()` now emit
  `DeprecationWarning`: self-serve plans were retired 2026-07 (Free +
  Enterprise model); the endpoints remain for grandfathered licence holders.

## 0.1.1 — 2026-03-12

- Added Iron Dome patterns/policies client support; fixed the default-policy
  verb (PUT).

## 0.1.0 — 2026-02-15

- Initial release: scanning, audit, quarantine, keys, teams, invites,
  billing, devices, alerts, webhooks, firewall rules; sync + async clients;
  CrewAI and LangChain integrations; Python 3.9+ compatibility fixes.
