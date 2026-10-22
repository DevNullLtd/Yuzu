# ADR-0071: CryptoDashboardLayoutStore, a born-on-Postgres per-operator layout store

- **Status:** Proposed (feat/crypto-dashboard-widgets)
- **Date:** 2026-10-19
- **Owner:** @liamsomerville (platform block `0xxx`; see `docs/adr/README.md`)
- **Deciders:** pg workstream; architect + sre (server store), security-guardian (Gate 2);
  owner decisions of 2026-10-19 on the boot posture and on unknown-id preservation
- **Parents:** ADR-0006/0007/0008/0012 (substrate, fail-closed, store contract); ADR-0036
  (type-distinguishable reads); ADR-0070 D13 (the `/crypto` dashboard widgets this store lays
  out); ADR-1005 (REST and MCP twins); ADR-2001 (the deprovision seams the erasure hook follows)

## Context

The `/crypto` dashboard becomes a grid of widgets that an operator adds and removes. The owner
requires the layout to persist per operator, server-side, with REST and MCP twins (ADR-1005: no
UI-only capability). Browser storage cannot meet that (per-browser, invisible to MCP), and no
existing server store holds per-operator presentation state. ADR-0006 sends every new server
store to Postgres.

A layout is a user-interface preference. Losing one costs an operator a few clicks to re-arrange
a grid; nothing else reads it. That shapes two decisions below: the boot posture (decision 2) and
the backup scope (Consequences).

## Decision

1. **A new born-on-Postgres store, `CryptoDashboardLayoutStore`, schema
   `crypto_dashboard_layout_store`** (ADR-0008 naming), one table:
   `layouts(username TEXT PRIMARY KEY, widget_ids JSONB NOT NULL CHECK (jsonb_typeof(widget_ids)
   = 'array'), updated_at BIGINT NOT NULL, version BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1))`.
   Two migrations: v1 creates the table, v2 adds `version` (rows written before it read as
   version 1). No legacy SQLite predecessor, so there is no backfill and no detect-and-warn probe
   (ADR-0009 does not apply).
2. **Posture: authoritative reads, degraded boot** (owner decision 2026-10-19; a deliberate
   exception to the ADR-0007/0008/0012 §1 fail-closed construction). When the store cannot open
   at boot (no connection, or the migration fails, for example because the database role lacks
   `CREATE` on the database), `server.cpp` logs the failure at error with the pool's last error,
   resets the store pointer and **continues booting**; it never sets `startup_failed_`. Every
   other server function is unaffected. Until a restart with the store fixed:
   - the layout routes and MCP tools answer a non-retryable 503 / `kInternalError` ("dashboard
     layouts unavailable: the layout store did not open at server start; ..."), with no retry
     hint because retrying cannot succeed before a restart;
   - the dashboard draws the catalogue default, read-only, under a notice saying saved layouts are
     unavailable and changes cannot be saved;
   - `/readyz` stays `200` and lists `crypto_dashboard_layout_store` in its informational
     `degraded` array without taking the replica out of rotation (the `analytics_event_store` /
     `nvd_db` precedent);
   - each layout request it refuses is counted on
     `yuzu_inventory_read_degrade_total{source="crypto_layout", reason="store_not_open"}`.

   The reason: refusing boot would take a replica that serves everything else out of service for a
   dashboard preference. Runtime reads stay authoritative: once the store is open, `get`/`put`
   return `std::expected`, so a lease timeout or query error is distinguishable from "no layout
   stored" (ADR-0036). The REST and MCP twins answer a runtime fault with a retryable 503 /
   `kInternalError`, never by serving the catalogue default as if nothing were stored. No read
   feeds an authorization, targeting, enforcement or skip decision: a layout only chooses which
   widgets are drawn, and each widget's data read keeps its own gate (`Inventory:Read` through the
   fleet-read gate, unconfined for the Yuzu-issued counts, ADR-0070 R2; `Security:Read` for the
   certificate list behind a count).
3. **Leases.** Every runtime call takes `try_acquire_for(2 s)` from the shared pool. Layout reads
   and writes do **not** take the `/crypto` read-gate slots: a slow Yuzu-issued or library read
   must not make an operator's layout unreadable. Failures are logged at warn without the
   username, and counted on `yuzu_inventory_read_degrade_total{source="crypto_layout"}` with
   `reason` `store_not_open`, `pool_acquire_timeout` or `query_error`.
4. **Versioned rows, conditional writes.** Each row carries a `version` that starts at 1 and goes
   up by one on every replace. A save names the version it expects; the store writes in ONE
   conditional statement: `INSERT ... ON CONFLICT (username) DO NOTHING RETURNING version` when
   no row is expected (two concurrent first writes resolve to one winner), or
   `UPDATE ... SET version = version + 1 WHERE username = $1 AND version = $n RETURNING version`
   otherwise. No returned row is a **conflict**: REST `409` with the stored version in
   `X-Crypto-Layout-Version`, MCP a non-retryable `kInvalidParams`; the page reloads the newer
   layout and says so. A caller that names no `expected_version` gets a **first save only**
   (owner decision 2026-10-19): the seam reads the current version, and a stored row (a corrupt
   one included) is the same conflict naming that version, never a silent replace; with no row
   it writes the first version, and a concurrent first write still conflicts in the store. A lost connection
   after a write was sent is reported as **outcome unknown** (503 "save outcome unknown — reload
   to check", audit `outcome=unknown`), never as a failure the store did not commit. A stored row
   whose array holds a non-string is **corrupt**: reads answer a non-retryable 422 /
   `kInternalError` naming its version, and any save replaces it.
5. **Validation lives in the pure catalogue, not the store; unknown ids are preserved.**
   `crypto_widgets::layout_error` (at most 64 catalogue ids, no repeats) runs before `put` on both
   transports. The store stores and returns ids verbatim and bounds 64 ids of 64 bytes and a
   1,024-byte username (at least the 5 + 255 + 1 + 255 bytes of a linked `oidc:`/`saml:`
   principal, `static_assert`ed) as defence in depth; an oversized username is an invalid-input
   error, not a degrade. A stored id this server version does not know (a widget another version
   added, during a rolling upgrade or after a rollback) is **kept**: on read it is not drawn and
   is reported as `preserved_unknown`; on save it is appended after the caller's ids in its stored
   order, up to the 64-id bound. So no version erases another version's widgets.
6. **Keying.** The session username, on both transports; neither takes a username argument, so
   no caller can read or write another operator's layout. The REST layout routes are
   authentication-only, refuse service-scoped tokens (`403`, no `permission` field: the key would
   be the token minter's, shared by every token of that minter), and hold an MCP-tier token to
   `Infrastructure` `Read`/`Write`, matching the MCP twins (the owner-scoped result-set precedent).
   The PUT is same-site gated and writes an `attempted` audit row
   (`crypto.dashboard.layout.update`) before changing anything (ADR-0033 §9).
7. **Erasure on deprovision.** The key is personal data (below). When an operator is
   deprovisioned (SCIM `active:false`, SCIM delete, a SCIM create with `active:false`, or the
   dashboard's local user delete), the deprovision seam, after its own outcome is committed, calls
   a post-deprovision hook with the principal set it resolved (the username plus every linked
   `oidc:`/`saml:` principal), and the hook erases each principal's layout row. The hook lives
   outside the ADR-2001 revoke chokepoint: it is best-effort, runs only after a successful
   deprovision, never throws into the seam and can never change the deprovision outcome. A failed
   erasure is logged at warn with the reason only (never the principal, a hash or a token),
   counted on `yuzu_server_crypto_layout_erase_failures_total{reason}` (`store_not_open`,
   `pool_acquire_timeout`, `outcome_unknown`, `query_error`, and `link_read_failed` when an
   already-inactive SCIM user's linked identities cannot be read and only the username's row is
   erased; every reason pre-seeded at zero)
   and alerted by `YuzuCryptoLayoutEraseFailed` (any increase in an hour). The remedy is an
   operator check, not product code (no cross-schema join): list the stored usernames, compare
   them with the active operators (local and SCIM users) and delete the rows of deprovisioned
   principals (`docs/user-manual/crypto.md`, "Deprovision erasure", gives the statements). A
   SCIM `DELETE` of an already-inactive user and an `active:false` replay that finds the user
   inactive also run the erasure, with the linked identities resolved for erasure only (no
   revoke runs on that path, and a failed link read degrades to the username alone).

   **Residual: a re-insert race.** A layout save already in flight when the erasure runs (past
   authentication before the deprovision revoked the session) can re-insert the row after the
   DELETE. Closing it would need the save to re-check the principal's standing inside its own
   statement, a cross-schema read this store deliberately does not make; the periodic check
   above removes such a row. Accepted (owner, 2026-10-19).

## Consequences

- **Privacy classification.** `username` is personal data (an operator identifier). The row
  holds nothing else about the person: widget ids, a timestamp and a version. It is erased on
  deprovision (decision 7) and appears in the SOC 2 data inventory
  (`docs/enterprise-readiness-soc2-first-customer.md`). There is no retention pass: one small row
  per operator, removed with the operator.
- **No secret column** (ADR-0010 not involved). Logs never carry the username.
- **Backup scope.** The schema is in the Yuzu database, so the documented whole-database
  `pg_dump` covers it with nothing extra to do. It is loss-tolerant: a restore without it, or a
  lost row, leaves the affected operators on the default layout. **A restore can resurrect
  erased rows:** a backup taken before a deprovision still holds that operator's layout row, and
  restoring it brings the row (and its username) back. Remedy: after any restore, run the
  decision 7 check and delete the rows of principals deprovisioned since the backup.
- **Upgrade.** The server role needs `CREATE` on the database to create the schema at first boot
  (as for every born-on-Postgres store). Without it the server now boots with layouts unavailable
  (decision 2) instead of refusing to start. Every operator starts on the default layout.
- **Rolling upgrade and rollback.** The migrations only add a schema and a defaulted column, so
  mixed versions are safe; an older binary ignores the schema. With decision 5, a newer version's
  widget ids survive saves made on an older binary, and the reverse.
- A future per-operator presentation preference elsewhere in the product should get its own
  decision rather than widen this schema by default.
