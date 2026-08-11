# Changelog

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
