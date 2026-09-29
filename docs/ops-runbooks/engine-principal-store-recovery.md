# Engine-Principal Store Recovery Runbook

Operator runbook for the `EnginePrincipalStore` — the born-on-Postgres
identity store (schema `engine_principal_store`, ADR-0006/0012) backing
autonomous **engine principals** (`docs/auth-engine-principals-design.md`
§3.1). Covers the `/readyz` probe, the client-visible 503-vs-401 split on
`get_for_auth`, and the `engine:` namespace collision-scan boot failure.

Like the auth store (`docs/ops-runbooks/auth-db-recovery.md`), this store
lives in the shared Postgres substrate — recovery is Postgres recovery, not a
local-file procedure. See `docs/postgres-store-playbook.md`
for the substrate-wide primitives (pool, migration runner, `/readyz`
conjunction) this runbook assumes.

## Detection signal

### 1. Construction failure — server refuses to start

`yuzu-server` exits with a non-zero status at startup and the log shows one
of:

```
[error] EnginePrincipalStore: no database connection at construction (...) — engine-principal identity store disabled
[error] EnginePrincipalStore: schema migration failed — engine-principal identity store disabled
[error] [PG] Refusing to start: engine-principal store migration/open failed
```

This is the same fail-CLOSED posture as every other born-on-PG store
(ADR-0012 §1): a reachable database whose schema can't migrate/open is a
**deploy error**, not a serve-degraded state. Diagnose it exactly like any
other store on the shared pool — see `docs/postgres-store-playbook.md` §
Substrate quick facts and the general Postgres-unreachable-at-boot recovery
in that doc; there is nothing engine-principal-specific about this failure
mode once you've identified which store's migration/lease failed.

### 2. `GET /readyz` is not ready

```json
{"status": "not ready", "failed_stores": ["pg_reachable"], "pg": "unreachable"}
```

`engine_principal_store` in `failed_stores` means the store did not open at
boot (§1). That cannot appear on a running server: a store's open state is
fixed at startup, and a failed open refuses to start the process at all.
What CAN appear at runtime is `pg_reachable`, with a `pg` reason
(`unreachable`, `stale`, `read_only`) — this replica cannot reach a writable
Postgres primary (HA WS-8; `docs/user-manual/server-admin.md`, "What
`/readyz` checks"). Engine-principal requests then degrade like every other
Postgres-backed path (§3). Treat it as a Postgres-reachability question:
read the `[readyz] Postgres not reachable` server-log line for the libpq
detail, and `yuzu_server_pg_reachable` / the pool metrics, before assuming
the `engine_principal_store` schema itself is the problem.

### 3. Engine-authenticated requests failing — the 503-vs-401 split

Every session synthesized from an engine-kind API token
(`AuthRoutes::synthesize_token_session`, `auth_source="engine_token"`)
routes through `EnginePrincipalStore::get_for_auth`'s **three-state**
contract before the request is admitted:

| `get_for_auth` status | Client-visible signal | Meaning | Operator action |
|---|---|---|---|
| `Active` | request proceeds | live, non-revoked principal | none |
| `MissingOrRevoked` | request denied (401-class) | **terminal** — no such principal, or its `lifecycle_state != 'active'` | Confirm intent: if the revoke was accidental, mint a **successor** principal via `transfer_owner`/re-`create` (revoke is never reversed, §3.1) and re-issue a token against the new principal. If the caller was never meant to exist, this is correct behavior — no action needed. |
| `StoreUnreachable` | request denied (503-class in spirit — currently surfaces as the generic 401 `require_auth` produces for any failed synthesis; see the noted follow-on in `auth_routes.cpp`) | **retryable** — the store never opened, or a lease/query timed out | This is a Postgres availability problem, not a credential problem. Check `/readyz`'s `engine_principal_store` row and the shared pool's health. The caller should back off and retry — do NOT revoke or re-mint the token, its referent is fine. |

**Both non-`Active` outcomes deny the request — never confuse the two.**
`MissingOrRevoked` reads as "credential problem, go fix the principal or
token." `StoreUnreachable` reads as "infrastructure problem, go fix
Postgres." Treating a transient outage as a revoked credential (or vice
versa) is exactly the failure mode the three-state split exists to prevent
(design doc §3.1/§12 decision 1) — if you see a spike of engine-token
denials, check `/readyz` and pool metrics BEFORE assuming principals were
maliciously revoked.

## The `engine:` namespace collision-scan boot failure

At every boot, after `EnginePrincipalStore` and `RbacStore` both construct,
the server runs a **fail-closed preflight** (design doc §3.1 upgrade hazard
/ decision log #3) scanning for pre-existing names inside the reserved
`engine:` namespace:

- `AuthDB::find_reserved_prefix_users("engine:")` — any `users.username`
  (active or soft-deleted) starting with `engine:`.
- `RbacStore::find_local_groups_with_prefix("engine:")` — any locally-sourced
  RBAC group name starting with `engine:`.

If **either** scan returns a non-empty result, the server logs the exact
colliding names and refuses to start:

```
[error] [auth] Refusing to start: the 'engine:' namespace is reserved for engine principals
(design doc §3.3) but pre-existing names collide with it — colliding users: [...];
colliding local RBAC groups: [...]. Rename or remove these before upgrading.
```

**Why this is fail-closed, not fail-open.** Both creation-time guards
(`is_valid_username`'s `:` ban, `is_reserved_identity_prefix`, and
`RbacStore::create_group`'s reserved-prefix rejection) only defend **new**
rows going forward — they cannot retroactively fix a database that already
had an `engine:`-named user or group before this reservation shipped. Left
uncaught, such a row would either be silently shadowed by a real engine
principal of the same name, or — worse — a stale local group could sit
inside a namespace meant to be authoritatively engine-only. Refusing to
boot is the correct posture: this is a one-time, operator-driven migration
step, not a routine failure mode.

### Recovery procedure

1. Read the colliding names out of the log line above (both lists are
   printed in full — no truncation).
2. For each colliding **user**: decide whether the row is stale (predates
   engine principals entirely, e.g. an accidental legacy `engine:` username)
   or was somehow created out-of-band. Rename or soft-delete it via the
   normal user-management path — you cannot rename in place through the
   API (`is_valid_username` rejects `:` on write), so this is typically:
   ```bash
   # Inspect first. The human-user store is Postgres — `find_reserved_prefix_users`
   # scans auth.users over the pg pool, so this is the table the preflight reads.
   psql "$YUZU_POSTGRES_DSN" -c \
     "SELECT username, is_active, identity_source FROM auth.users WHERE username LIKE 'engine:%';"

   # Stop the service and take a Postgres dump first (see
   # docs/ops-runbooks/auth-db-recovery.md for the backup rules, including
   # the KEK pairing). Then EITHER rename the colliding row out of the reserved
   # namespace (preferred — preserves the account's audit history), OR
   # hard-delete it if it is genuinely stale and unwanted.
   #
   # Rename (preferred): move it to a non-reserved username. Do the same
   # rename in any table that carries the username as a foreign key if you
   # want to keep the account usable.
   psql "$YUZU_POSTGRES_DSN" -c \
     "UPDATE auth.users SET username = 'legacy_engine_reclaimed' WHERE username = 'engine:legacy';"

   # OR hard-delete (only if the row is stale and you do not need it):
   psql "$YUZU_POSTGRES_DSN" -c \
     "DELETE FROM auth.users WHERE username = 'engine:legacy';"
   ```
   `find_reserved_prefix_users` intentionally includes soft-deleted rows
   too (it scans the `username` primary key, not active-user visibility) —
   a soft-deleted collision still occupies the reserved name, so
   `UPDATE auth.users SET is_active = 0` alone will NOT satisfy this preflight.
   Only a rename (moving the name out of the `engine:` namespace) or a hard
   `DELETE` (removing the primary-key row) actually clears the collision.
3. For each colliding **local RBAC group**: `RbacStore::create_group`
   already refuses new creates in this namespace, so a collision here is
   necessarily a pre-existing row. Inspect and delete it via
   `RbacStore::delete_group` (dashboard: Settings → RBAC → Groups) or
   direct SQL against `rbac.db`. Note the tool changes here: `RbacStore` has
   **not** migrated — it is still SQLite, per-node, so this half of the
   collision really is `sqlite3` against a file while the user half above is
   `psql` against Postgres:
   ```bash
   sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT name, source FROM groups WHERE name LIKE 'engine:%' AND source = 'local';"
   sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM groups WHERE name = 'engine:legacy-group';"
   ```
   Deleting a group cascades to its `group_members` rows
   (`ON DELETE CASCADE`); confirm the group had no members you need to
   re-home into a differently-named group first.
4. Restart the server. The preflight re-runs on every boot — it is not a
   one-shot migration flag — so a clean pass confirms the collision is
   fully resolved.

## Alert: `YuzuMcpEngineRevalidateStoreUnreachable` (#2367)

**What fired.** `yuzu_server_engine_revalidate_backoff_suppressed_total` moved.
That counter increments ONLY when a liveness re-check for an engine principal
was answered `StoreUnreachable` from the failure backoff — i.e. the store was
already found unreachable moments earlier, and the server is deliberately not
re-asking on every stream tick. It cannot move while the store is healthy, so
this is a true-positive signal about store reachability, not a cache-tuning
metric. The backoff arms only on CONFIRMED unreachability — the store closed,
a query actually ran and failed, or PgPool's own connect-failure breaker is
open (`connect_breaker_open()`, armed only by recent connect failures, never
by pool saturation alone) — so **this alert firing already rules out ordinary
pool saturation with a healthy database**; a bare lease-acquire timeout under
those conditions does not move this counter. One residual edge: if the
transport hangs rather than refusing (a silent firewall drop, a blackholed
route), the breaker only arms once a connect attempt actually times out
(bounded by the pool's `connect_timeout`, default 10s — set per-deployment
with a `connect_timeout=<seconds>` keyword in the `--postgres-dsn` connection
string, NOT a separate flag) — so the very first ~10s of that specific
failure mode can still be ambiguous and not arm the backoff; it self-corrects
once that first connect attempt fails.

**What is happening to streams meanwhile.** Held-open MCP/SSE streams
authenticated by an engine principal are being told "indeterminate", which is
NOT a revocation: each rides a bounded grace window measured from its last
authoritative credential confirmation, then closes with
`reason=auth_unavailable`. Human/API-token streams are unaffected by this
particular signal.

**Triage, in order.**

1. Is the substrate reachable at all? `curl -s localhost:8080/readyz` — the
   conjunction includes `engine_principal_store`. If `/readyz` is failing, this
   is a store-availability incident: go to "Detection signal" above and to
   `docs/postgres-store-playbook.md`.
2. Check `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use` for
   corroborating detail — but note this alert firing already means the
   confirmed-unreachable path was taken (store closed, a query ran and
   failed, or the connect-failure breaker is open), not ordinary pool
   saturation with a healthy database; see the pool-sizing guidance in
   `docs/user-manual/server-admin.md` and the boot warning about SSE stream
   capacity versus `--postgres-pool-size` if you want to rule out contention
   as a contributing factor regardless.
3. How much damage? `yuzu_mcp_stream_closes_total{reason="auth_unavailable"}`
   counts streams that already exhausted their grace window. A flat count
   means the backoff is absorbing the incident without killing sessions.
4. Is the cache doing its job either side of the incident?
   `yuzu_server_engine_revalidate_cache_hits_total` versus `..._misses_total`.
   In steady state hits should dominate; misses climbing while hits are flat
   suggests entries are being invalidated repeatedly (a revoke loop) rather
   than an availability problem.

**Recovery.** No operator action restores the streams directly — clients
reconnect and resume via `Last-Event-ID`, and durable results remain fetchable
by `execution_id`. For a transient connectivity problem (network blip, a
restart), fix it and the backoff re-probes within seconds, so streams
re-establish on their own. **This does NOT apply to a permanent condition** —
check the server log for the `get_for_auth denied` warn line: one naming a
SQLSTATE class-42 error ("NOT a transient PG-availability condition... schema
or access-rule problem") means a missing table or a revoked grant, which will
retry-fail indefinitely until an operator actually fixes the schema/grant; the
backoff re-probing changes nothing for that case.

**Do NOT** reflexively raise `--postgres-pool-size` in response to this alert.
Adding connections to an already-struggling database makes matters worse;
confirm the database is healthy first, and consider lowering SSE stream
capacity instead.

## Metric: `yuzu_server_engine_revalidate_generation_capacity_fallback_total` (#2454/#3385)

**What it means.** This counts how often the per-principal poisoning-guard
map (the TOCTOU defense behind `get_for_auth_revalidate`'s cache) was full —
even after sweeping aged-out entries — and a principal's invalidate fell back
to the coarse global epoch instead of getting its own slot. It is NOT an
availability signal: the guard stays sound either way (the fallback still
poisons every in-flight reader, just less precisely — see the field comment
on `revoke_generation_by_principal_` in `engine_principal_store.hpp`), and no
stream is dropped or denied because of this metric alone.

**Since #3385, this is a recoverable condition, not a permanent one.** The map
now sweeps entries whose `last_bumped_at` is older than
`kRevokeGenerationEntryTtl` (63s) on its own insert path — the same lazy,
capacity-triggered sweep the revalidate cache and failure-backoff maps
already use. So the fallback firing means `max_entries_` (1024 by default)
*distinct* principals had their generation entry bumped within the same
63-second window, not merely 1024 distinct principals bumped at any point
over the process's uptime (the pre-#3385 shape, where the fallback was
permanent for the rest of the process's life once tripped once).

**Triage.**

1. Is this expected load? A large batch operation that revokes or transfers
   ownership of many engine principals in a short window is the ordinary
   trigger — the fallback recovers on its own once the burst passes and
   entries age past the TTL.
2. Is it climbing steadily rather than in a burst? That suggests sustained
   churn above the ceiling (more than ~16 distinct principals/second,
   sustained) rather than a one-off batch — the guard is running at reduced
   (global-epoch, not per-principal) precision for as long as this continues,
   which is safe but coarser: an invalidate anywhere defeats every OTHER
   principal's concurrent cache-write too while the epoch keeps moving.

**Recovery.** No restart is required — the condition self-clears once the
churn rate drops back under the ceiling within a 63-second window; the next
sweep reclaims capacity automatically. If it climbs persistently in normal
operation (not a known batch job), that is a signal the ceiling itself may
need raising rather than an operational fault to clear — there is no runtime
admin surface for `max_entries_` today (it is a fixed constant,
`kAuthCacheMaxEntries`), so raising it requires a code change and a new
release, not a live toggle.

## Cross-references

- Store contract, three-state `get_for_auth`, and construction posture:
  `server/core/src/engine_principal_store.hpp` (file doc comment).
- Design doc: `docs/auth-engine-principals-design.md` §3.1 (posture),
  §3.3 (namespace reservation), §6 (session synthesis / referential
  integrity), §12 decision 1 (the StoreUnreachable/MissingOrRevoked split).
- Substrate-wide Postgres store recovery (pool exhaustion, PG down at boot,
  migration drift): `docs/postgres-store-playbook.md`.
- Auth store (`auth.*` in Postgres) recovery for the human-principal side of
  the namespace collision: `docs/ops-runbooks/auth-db-recovery.md`.
