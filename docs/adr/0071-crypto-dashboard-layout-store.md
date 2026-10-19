# ADR-0071: CryptoDashboardLayoutStore, a born-on-Postgres per-operator layout store

- **Status:** Proposed (feat/crypto-dashboard-widgets)
- **Date:** 2026-10-19
- **Owner:** @liamsomerville (platform block `0xxx`; see `docs/adr/README.md`)
- **Deciders:** pg workstream; architect + sre (server store), security-guardian (Gate 2)
- **Parents:** ADR-0006/0007/0008/0012 (substrate, fail-closed, store contract); ADR-0036
  (type-distinguishable reads); ADR-0070 D13 (the `/crypto` dashboard widgets this store lays
  out); ADR-1005 (REST and MCP twins)

## Context

The `/crypto` dashboard becomes a grid of widgets that an operator adds and removes. The owner
requires the layout to persist per operator, server-side, with REST and MCP twins (ADR-1005: no
UI-only capability). Browser storage cannot meet that (per-browser, invisible to MCP), and no
existing server store holds per-operator presentation state. ADR-0006 sends every new server
store to Postgres.

## Decision

1. **A new born-on-Postgres store, `CryptoDashboardLayoutStore`, schema
   `crypto_dashboard_layout_store`** (ADR-0008 naming), one table:
   `layouts(username TEXT PRIMARY KEY, widget_ids JSONB NOT NULL CHECK (jsonb_typeof(widget_ids)
   = 'array'), updated_at BIGINT NOT NULL)`. One migration (v1); no legacy SQLite predecessor, so
   there is no backfill and no detect-and-warn probe (ADR-0009 does not apply).
2. **Posture: authoritative, fail-closed construction** (ADR-0012 §1). `server.cpp` sets
   `startup_failed_` when the store cannot open; the member is declared after `pg_pool_` and
   reset in `stop()` before the pool. Runtime `get`/`put` return `std::expected`, so a lease
   timeout or query error is distinguishable from "no layout stored" (ADR-0036): the REST and MCP
   twins answer it with a retryable 503 / `kInternalError`, never by serving the catalogue default
   as if nothing were stored. No read feeds an authorization, targeting, enforcement or skip
   decision: a layout only chooses which widgets are drawn, and each widget's data read keeps its
   own gate (`Inventory:Read` through the fleet-read gate, `Security:Read` for the Yuzu-issued
   counts).
3. **Leases.** Every runtime call takes `try_acquire_for(2 s)` (an operator page load or save;
   the failure is reported to that operator, so the degrade log level is `debug`). The calls also
   hold a lease from the `/crypto` per-process read gate (`kMaxConcurrentCryptoReads`), shared with
   the library and Yuzu-issued reads, so the dashboard as a whole holds at most two pool
   connections.
4. **Write shape.** A single-statement upsert, `INSERT ... ON CONFLICT (username) DO UPDATE ...
   RETURNING username` (a returned row proves the write landed; no affected-row counting).
   Concurrent saves by one operator are last-writer-wins.
5. **Validation lives in the pure catalogue, not the store.** `crypto_widgets::layout_error`
   (at most 64 catalogue ids, no repeats) runs before `put` on both transports; the store bounds
   64 ids of 64 bytes and a 512-byte username only as defence in depth. A stored id the catalogue
   no longer knows is dropped at read time; the row is left untouched.
6. **Keying.** The session username, on both transports; neither takes a username argument, so
   no caller can read or write another operator's layout. The layout routes are
   authentication-only; MCP's `Infrastructure` `Read`/`Write` is the tool tier class (the
   owner-scoped result-set precedent). The PUT is same-site gated and writes an `attempted`
   audit row (`crypto.dashboard.layout.update`) before changing anything (ADR-0033 §9).

## Consequences

- No secret column (ADR-0010 not involved) and no retention pass: one small row per operator. A
  deleted operator's row is inert; nothing reads it unless that username authenticates again.
- A future per-operator presentation preference elsewhere in the product should get its own
  decision rather than widen this schema by default.
- Rolling upgrade: the v1 migration only creates the schema, so mixed versions are safe; an older
  binary ignores the schema.
