# ADR-0047: QuarantineStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-14
- **Deciders:** pg workstream; security-guardian + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0040/0041/0044 (esp. `sanitize_pg_text`, fail-closed boot, mandatory-backfill-with-
  fingerprint-verification, the RbacStore/DiscoveryStore sourceless-fingerprint precedent this
  store ports).

## Context

`QuarantineStore` (`quarantine.db` today, `server/core/src/quarantine_store.{hpp,cpp}`, ~54 + 226
lines) holds Guardian device-quarantine records: the server-side bookkeeping of which agents are
currently network-isolated, who isolated them, why, and their full history. Single table
(`quarantine_records`), two indexes, no foreign keys, no secret-bearing columns. Postgres ladder
Wave 2, batch 2.

A quarantine record is not expendable telemetry — it is the server's only durable record of an
**active security containment**. Per the Guardian design (`docs/yuzu-guardian-design-v1.1.md`
§11.7), "Quarantine is a terminal state — once activated, it persists until an administrator
explicitly lifts it." Losing an active record on cutover silently un-quarantines a device in the
server's view (the agent-side firewall enforcement is a separate, agent-local mechanism this
migration does not touch — see "Out of scope" below) — this is Wave 2's "operator state that
cannot be lost" framing (the same framing `DiscoveryStore`/ADR-0044 used for its `managed` flag),
not purely ephemeral telemetry. Backfill is therefore mandatory.

## Decision

Migrate to PostgreSQL schema **`quarantine_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. The SQLite `shared_mutex` is retired —
Postgres's real per-connection concurrency, plus a partial unique index (see below), replaces the
single-writer serialization the mutex + check-then-insert previously provided.

### Schema

```sql
CREATE TABLE quarantine_records (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
    quarantined_by  TEXT NOT NULL DEFAULT '',
    quarantined_at  BIGINT NOT NULL DEFAULT 0,
    released_at     BIGINT NOT NULL DEFAULT 0,
    whitelist       TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_quarantine_agent ON quarantine_records(agent_id);
CREATE UNIQUE INDEX idx_quarantine_agent_active ON quarantine_records(agent_id) WHERE status = 'active';
CREATE TABLE quarantine_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

Ports column-for-column from the legacy SQLite schema (`quarantined_by` becomes `NOT NULL DEFAULT
''` instead of nullable TEXT — the read path already defaulted a NULL to `""`, so this is a
value-preserving tightening, not a behavior change). The `id` column is internal-only: no REST/MCP
response ever exposes it (verified — `rest_api_v1.cpp`'s quarantine JSON bodies emit only
`agent_id`/`status`/`quarantined_by`/`quarantined_at`/`whitelist`/`reason`), so nothing depends on
SQLite rowid semantics surviving the cutover, and Postgres is free to assign fresh `BIGSERIAL`
values on backfill. Does NOT port a plain index on `status` (gov Gate 3 architect) — the only
status-predicated query (`list_quarantined`'s `WHERE status = 'active'`) is already servable by
the partial unique index below, and a second, redundant btree on a 2-value column would be pure
write amplification on this append-only history table.

**New: a partial unique index enforces "at most one active record per agent" at the database
level** (`idx_quarantine_agent_active`), replacing the legacy check-then-insert-under-mutex
pattern with a single race-safe statement (see "Race-safe writes" below) — the legacy in-process
mutex could not protect against concurrent Postgres connections the way it protected a single
`sqlite3*` handle.

### Reads — authoritative, type-distinguishable

Per the 2026-07-25 program policy (`docs/postgres-store-playbook.md` "Authoritative reads must be
type-distinguishable"), every read is type-distinguishable from "no rows": `list_quarantined` and
`get_history` return `std::optional<std::vector<QuarantineRecord>>` (`nullopt` = degraded, empty
vector = genuinely no records); `get_status` returns
`std::expected<std::optional<QuarantineRecord>, std::string>` (`unexpected` = degraded, a value
holding `nullopt` = genuinely not quarantined). This closes the specific fail-open the kickoff
review flagged: a `get_status` that returned `nullopt` on a DB error previously read as "not
quarantined," and an empty `list_quarantined` on a degraded read previously read as "nothing
quarantined" — both masked an ACTIVE containment. `GET /api/v1/quarantine`
(`rest_api_v1.cpp`) now checks for `nullopt` and returns 503 rather than rendering an empty
quarantine list.

**The store-layer fix alone was incomplete — the SAME hazard existed one layer up (gov Gate 2
security-guardian, hardening round).** `GET /api/v1/quarantine`'s per-record admit-then-filter
loop (`scoped_perm_fn(req, probe, "Security", "Read", r.agent_id)`, pre-existing from #1788/
CDX-P1-02, untouched by this migration's first commit) calls `continue` on any `false` return —
but `require_scoped_permission` genuinely returns `false` with `probe.status == 503` (not `403`)
on an RBAC-store or tag-store degrade (its engine-principal and service-scoped-token branches,
`auth_routes.cpp`), distinct from a real per-device denial. The loop was treating a degraded
per-record authorization check identically to a denial — silently omitting the record rather
than failing the whole list closed, which is the exact fail-open this section's store-layer fix
exists to close, just moved one layer up. Fixed: a `probe.status == 503` inside the loop now
fails the WHOLE response 503 rather than continuing to filter.

### Race-safe writes (no in-process mutex)

**Neither mutator trusts a bare `PGRES_COMMAND_OK`/`PGRES_TUPLES_OK` status to mean its `WHERE`
actually matched a row** — that status is identical whether the predicate matched zero rows or
one, the same defect class the `NotificationStore` Postgres port's `mark_read`/`dismiss` shipped
(bare-status-only, no row-affected confirmation). The stakes differ in direction, not in kind, from
that store's read-adjacent case: a silent no-op `release_device` is the INVERSE of a fail-open
read — the device stays quarantined while the caller (and any automation reading the `200`
response) believes it was just freed. Both mutators here confirm via `RETURNING` +
`PQntuples()`, never a bare command-status check:

- `quarantine_device`: a single `INSERT ... ON CONFLICT (agent_id) WHERE status = 'active' DO
  NOTHING RETURNING id`, targeting the partial unique index above. `PQntuples() == 0` means the
  conflict fired (an active record already exists) → `unexpected("device is already
  quarantined")` — the playbook's generic `RETURNING` + `PQntuples() == 1` idiom for a
  first-writer-wins insert. Replaces the legacy check-then-insert-under-mutex; verified against a
  live Postgres instance (`docs/postgres-store-playbook.md`'s explicit warning that `ON CONFLICT
  ... WHERE` semantics are easy to get subtly wrong by reasoning alone).
- `release_device`: a single guarded `UPDATE ... SET status = 'released', released_at = $1 WHERE
  agent_id = $2 AND status = 'active' RETURNING id` (the `#3062`/`cancel_job` pattern this
  kickoff's lessons-learned section calls out). `PQntuples() == 0` → `unexpected("device is not
  quarantined")` — the row-confirmation check the kickoff's lessons-learned item 6 names the
  *pattern* for but does not itself spell out the verification step; named explicitly here so a
  future edit cannot regress to a bare status check without touching a comment that says why not.

Both retire `sqlite3_changes()` (#1033) in favor of `RETURNING`.

**`is_open()` checked at every entry point, not just reads.** All three surfaces —
`GET`/`POST /api/v1/quarantine`, `DELETE /api/v1/quarantine/{agent_id}`, and the MCP
`quarantine_device` tool — gate on `quarantine_store && quarantine_store->is_open()` before doing
any store work, not merely a null-pointer check. This closes the same asymmetry left as an
unresolved LOW on the `NotificationStore` Postgres port (its `POST` routes null-checked the store
pointer but skipped `is_open()`, while its `GET` route checked both) — widened here from "reads"
to every route so quarantine does not inherit that gap.

**`400` vs `503` classification (`kQuarantineDbErrorPrefix`).** Every genuine store/pool/query
failure on `quarantine_device`/`release_device` is prefixed `"db_error: "`; a business/state error
("already quarantined" / "not quarantined") is not. `rest_api_v1.cpp`'s `is_quarantine_db_error`
(and the MCP `quarantine_device` handler's equivalent check) key off this shared constant to answer
`503` (retryable) vs `400` (retrying will not help) — mirroring `DeploymentStore`'s
`kDeploymentDbErrorPrefix`/`is_deployment_db_error`, added after an adversarial-review MEDIUM
finding on that store (2026-08-12) that its write routes previously collapsed every failure,
including genuine outages, to `400`. Applied here from the start rather than shipping the same
defect class and fixing it in a later round.

**Every failure branch audits (gov Gate 2 security-guardian, hardening round).** The MCP
`quarantine_device` twin already audited its store-error branch (`mcp_audit("failure", ...)`);
the REST `POST`/`DELETE` routes' equivalent branches did not — the only quarantine failure path
with no audit row. Both now call `audit_fn(req, "quarantine.enable"/"quarantine.disable",
"failure", "Security", agent_id, result.error())` on the post-gate store/business failure branch,
matching the MCP twin and the existing scope-gate-unwired branch's own audit call.

### Backfill (ADR-0009) — MANDATORY, fingerprint-verified, single-transaction

One-time, idempotent, fail-closed backfill from the legacy `quarantine.db`, ported from the
`RbacStore`/`DiscoveryStore` sourceless-fingerprint mechanism (ADR-0040/0041/0044 shape).

**Design difference from `DiscoveryStore`: no natural per-row key.** `discovered_devices` has a
UNIQUE `ip_address` to `ON CONFLICT DO NOTHING` against, making its backfill insert loop
naturally idempotent/crash-resumable per row. `quarantine_records` is a pure append-only history
table with no such key (an agent can have many historical rows; `agent_id` alone is not unique).
Rather than synthesize an artificial per-row key (rejected — a SQLite-rowid-derived key would
collide across two independently-numbered legacy files in the pathological case of two replicas
each holding *different* real content, silently dropping one replica's real rows with no error),
the row inserts, the `backfill_complete` marker, and the `backfill_source_fingerprint` marker
(plus a fourth `quarantine_meta` key, `backfill_row_count`, stamped as completeness evidence — see
"Backfill completeness evidence" below) are committed together in **one transaction**, guarded by
a leading `pg_advisory_xact_lock(hashtextextended('quarantine_store:backfill', 0))` statement (its own
statement, strictly before the check-and-mutate work, per the playbook's `RbacStore`-derived
warning that a lock embedded via CTE in the same statement as the check does not re-evaluate a
statement's already-fixed snapshot).

This is the exception ADR-0012 §2(b) explicitly reserves: "the sole documented exception is a
fail-closed, pre-serving, one-time legacy backfill whose atomic insert-plus-completion stamp
requires one transaction while it streams a bounded row from the legacy store." Justification
required by that clause:

- **Per-row memory is capped**: the legacy file is read once into an in-memory snapshot
  (`read_legacy_snapshot`, unfiltered — the cap counts EVERY row, active and released, not just
  active ones), and the count is capped at `kMaxBackfillRows` (**5,000** — lowered from an initial
  500,000 in Gate 3 review, see "Sized against the transaction bound" below) — refused
  (fail-closed, operator remediation required) rather than silently truncated if exceeded.
  Quarantine records are manually-curated security events, not a high-volume telemetry stream,
  and this store's retention is unbounded (see "Follow-ups" — no prune pass exists), so a
  long-lived fleet accumulating full history could plausibly approach this ceiling over years;
  it is a sanity/DoS-AND-lock-hold-duration guard, not purely an expected-never-to-bind limit.
  **Sized against the transaction bound, not chosen independently of it**: `commit_backfill`'s
  row-insert loop is one round-trip PER ROW under the exclusive backfill advisory lock — every
  other replica reaching that lock (a same-boot race, or a later boot before this one's marker
  commits) blocks for the winner's full insert duration. 5,000 keeps even a pessimistic ~10ms/row
  round-trip comfortably under `kBackfillTxnTimeout` (60s) rather than racing its own bound; the
  original 500,000 would have meant potentially minutes of fleet-wide boot refusal for every
  replica but the winner.
- **Retry behavior is explicit**: under the advisory lock, the transaction re-checks the
  `backfill_complete` marker (a concurrent racer may have committed between this replica's
  earlier short-lease marker check and this transaction acquiring the lock) — if now present, the
  transaction commits as a no-op and the caller retries through the top-level marker-check path
  (bounded at 2 attempts total), which performs the same holder-side fingerprint verification the
  `DiscoveryStore` marker-present branch performs. A same-content race (two replicas backfilling
  the identical shared file) verifies clean and skips; a different-content race fails closed with
  an operator-actionable log line, exactly like `DiscoveryStore`'s HOLDER-SIDE VERIFICATION
  FAILED case.
- **The sourceless (no-local-file) stamp path reuses the same advisory-locked transaction
  helper** (with an empty row set) rather than `DiscoveryStore`'s separate lock-free
  promotable-upsert — unifying both paths through one lock removes the need to separately reason
  about a sourceless stamper racing a real-content backfiller across two different locking
  schemes.
- **Legacy `status` values are validated BEFORE any row reaches Postgres**: any row whose status
  is not `active`/`released` fails the backfill closed (never silently inserted, never silently
  dropped) — the CHECK constraint would also reject it, but validating up front produces a
  clear, actionable log line naming the offending row instead of a generic constraint-violation
  error surfacing from mid-transaction.
- **Duplicate `active` rows for the same agent are ALSO validated before any row reaches Postgres
  (gov Gate 2 security-guardian, hardening round).** The legacy SQLite schema never enforced "at
  most one active record per agent" at the database level — only the in-process mutex this
  migration retires did — so a legacy file could in principle hold two. Without this check, such
  a row would reach `commit_backfill`'s plain `INSERT` loop and abort mid-transaction on a raw
  `duplicate key value violates unique constraint "idx_quarantine_agent_active"` error instead of
  a named, actionable log line naming the `agent_id`.
- **The backfill advisory lock's wait is explicitly widened to `kBackfillTxnTimeout` (gov Gate 2
  security-guardian; corrected in Gate 3 by cpp-expert + cpp-safety + architect, who
  independently found the same gap).** The pool's connection-level `lock_timeout` GUC defaults to
  10s (ADR-0012) — far shorter than the backfill's own bound. **`with_txn_for(kBackfillTxnTimeout,
  ...)` bounds only the pool-ACQUIRE wait, never statement execution**
  (`docs/postgres-store-playbook.md`'s explicit anti-pattern — the SAME mistake #2530 and
  `AuditStore::migrate_from_sqlite` made before this store existed): a lock wait IS the statement
  executing, just blocked, so the pool's connection-level `statement_timeout` GUC (default 30s,
  not overridden by `server.cpp`'s `PgPool::Options`) ALSO bounds it — and being shorter than
  `lock_timeout`, is what actually determines the effective wait. Setting only `SET LOCAL
  lock_timeout` (the Gate 2 fix) therefore widened the wait 10s → 30s, not → `kBackfillTxnTimeout`
  (60s) as the fix intended and this ADR's Gate-2 revision claimed. The fix now sets BOTH `SET
  LOCAL statement_timeout` and `SET LOCAL lock_timeout` to `kBackfillTxnTimeout`, matching
  `NotificationStore::migrate_from_sqlite`'s identical fix for the identical hazard. This is a
  narrow, self-healing-on-restart race (documented in `upgrading.md`), but the fix removes an
  unnecessary boot failure for a legitimately-slow (not wedged) winner.
- **No IDENTITY/LIFECYCLE column-conflict partition (unlike `DeploymentStore`/#3062).** That
  partition exists to resolve a real row *already present in Postgres* (from a prior backfill or
  live traffic) disagreeing with the legacy row trying to land on top of it via `ON CONFLICT DO
  UPDATE`. `quarantine_records`' backfill never does that: the advisory lock excludes every other
  first-ever-migration attempt, and no live traffic is possible from *any* replica before *some*
  replica's backfill has committed (every replica gates serving on its own backfill success), so
  there is no window in which a legacy row could collide with an already-live-written row. Once
  a marker is present, this store's backfill never touches `quarantine_records` again — only
  fresh runtime writes do.
- **0-byte legacy file guard**: identical two-branch treatment to `DiscoveryStore` (refused
  unconditionally on a first-ever migration; safe to skip once a real migration has already
  completed for the fleet) — ported verbatim, same rationale (SQLite opens a 0-byte file as a
  valid empty database, indistinguishable from the legitimate no-`quarantine_records`-table case).
- **Backfill completeness evidence (gov Gate 6 compliance-officer C-5).** Before this fix, the
  only evidence a backfill left behind was the fact that boot succeeded — no info-level log naming
  how many records moved, nothing queryable afterward. `migrate_from_sqlite` now logs
  `backfill complete, N legacy quarantine record(s) migrated` at `info` level, and
  `commit_backfill` stamps a fourth `quarantine_meta` key, `backfill_row_count`, in the SAME
  transaction as `backfill_complete` — so an operator (or an auditor building SOC 2 evidence) can
  answer "how much did the cutover actually move" from the running database without grepping
  historical boot logs. `0` for both the no-legacy-file and no-`quarantine_records`-table
  ("fresh") paths is itself meaningful evidence, not an omission.

### Lifecycle

Construction moves inside `server.cpp`'s `if (pg_pool_ && !startup_failed_)` guard; a failed
migration or backfill sets `startup_failed_` (fail-closed boot, never serve on top of
partially-migrated quarantine data). Added to both the `/healthz` and `/readyz` check lists.

## Out of scope

This ADR covers only the server-side bookkeeping store. The agent-side quarantine firewall
enforcement (WFP/nftables/pf block-all + exceptions, §11.7 of the Guardian design) is a separate,
agent-local mechanism, untouched by this migration — `quarantine_device`/`release_device` still
dispatch the live isolation command via the same `DispatchFn` chain as before; only the
record-keeping substrate changed.

## Considered and rejected

- **A synthetic per-row backfill key** (legacy SQLite rowid as a `legacy_id UNIQUE` column,
  mirroring `DiscoveryStore`'s `ip_address` `ON CONFLICT DO NOTHING` idiom). Rejected: SQLite
  rowids restart from 1 per file, so two independently-numbered legacy files (a pathological but
  possible multi-replica state) could collide on an unrelated row and silently drop one replica's
  real data with no error — worse than the single-transaction/advisory-lock design, which either
  cleanly serializes concurrent same-content backfills or fails closed on genuinely divergent
  content.
- **Skippable backfill** (the `ResponseStore` precedent): rejected — an active quarantine record
  is live security containment state, not regenerable telemetry.
- **Plain marker-only backfill idempotency** (no fingerprint): rejected for the same reason
  `DiscoveryStore`/`RbacStore` rejected it — cannot distinguish "this replica's own completed
  migration" from "a different replica's migration this replica's data was never part of."

## Consequences

- Active quarantine records, and full quarantine history, are preserved across the cutover.
- `GET /api/v1/quarantine` gains a new 503 branch on a degraded read (previously: SQLite's
  local-file reads essentially never failed short of file corruption, so this failure mode was
  not practically reachable).
- `quarantine_device`'s "already quarantined" check moves from an in-process mutex-guarded
  check-then-insert to a database-enforced partial unique index — safe under concurrent Postgres
  connections in a way the legacy mutex, scoped to one `sqlite3*` handle, never had to be.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"quarantinestore"` `PgTestTemplate`
  (`tests/unit/server/test_quarantine_store.cpp`); construction-fail-closed and backfill tests
  use plain `YUZU_REQUIRE_PG_DB`.

## Schema v2 (#3425)

Added two columns to `quarantine_records`, migration id 2:

```sql
ALTER TABLE quarantine_records ADD COLUMN last_applied_at   BIGINT NOT NULL DEFAULT 0;
ALTER TABLE quarantine_records ADD COLUMN last_confirmed_at BIGINT NOT NULL DEFAULT 0;
```

Endpoint-containment confirmation state for `QuarantineContainmentReconciler` — see
`docs/user-manual/security-hardening.md` "Reconnect re-application (#3425)" for the mechanism.
`0` = never, matching this table's existing `released_at` never-happened sentinel rather than
introducing nullable-column plumbing this store's read path (`read_record`/`to_i64`) does not
otherwise have. Two new store APIs, `mark_endpoint_applied`/`mark_endpoint_confirmed`, share
`release_device`'s guarded-UPDATE shape, extended with a THIRD predicate (governance Gate 4,
unhappy-path Finding A, 2026-08-24): `UPDATE ... SET <col> = $1 WHERE agent_id = $2 AND id = $3
AND status = 'active' RETURNING id`. The `id` predicate is load-bearing, not defensive
redundancy — `agent_id`+`status='active'` alone is not a stable row identity across a
release-then-requarantine race: a NEW active row can exist for the same `agent_id` while a
reconcile cycle for the OLD row is still in flight, and without `id` scoping the stamp write
would silently land on the new row (misattributing "applied"/"confirmed" to a whitelist that was
never actually dispatched). Zero rows (from EITHER cause — genuinely released, or superseded by a
different active record) → the same unprefixed `"device is not quarantined"` business error (a
released or never-quarantined agent_id is a business error, not a store failure — 400 at REST,
matching `release_device`/`quarantine_device`'s existing split); every caller's handling (erase
in-memory state, let the current record re-enter fresh) is correct for either cause, so this stays
one error string rather than forking one per cause. Sole writer: the reconciler. The `ALTER TABLE`
takes a brief `ACCESS EXCLUSIVE` lock — negligible at this table's size for the same reason
`kMaxBackfillRows` above is sized the way it is (manually-curated security events, not a
high-volume telemetry stream); see `docs/user-manual/server-admin.md` for the one-line operational
note.

## Follow-ups

- `get_status` now has real callers as of #3425 (the MCP already_active retry path predates this
  ADR; `QuarantineContainmentReconciler`'s status-verify-first path is new) — this bullet
  previously said "no REST/MCP caller (confirmed by repo-wide grep)", which #3425 makes false;
  corrected rather than left to mislead a future reader. `get_history` still has none.
- **Indefinite retention is a DELIBERATE posture decision, not a deferred gap (Gate 3 architect;
  reframed Gate 6 compliance-officer C-4).** `quarantine_records` is an unbounded, append-only
  history table with **no prune pass, and this migration does not add one on purpose** —
  a quarantine record is evidence that a specific containment decision was made, by whom, and
  why; deleting that evidence after some retention window would be a REGRESSION for a SOC 2
  security-containment control, not tech debt. This store is therefore **excluded** from #2508's
  sweep by design, not merely not-yet-reached — a future author picking up #2508 should skip
  `quarantine_records` rather than treat its absence from a prune pass as an oversight to fix.
  (**gov-fix(architect, Gate 8):** `#2508`'s remaining scope, per `.claude/routed-concerns.md`'s
  "Clock-guarded retention" row as of this writing, is `app_perf_*`/`PreflightRunStore`/
  `DeploymentRunStore` — `result_set_store`/`guaranteed_state_store`/`response_store` have since
  become compliant store-by-store on their own Postgres migrations (ADR-0036/0038/0039); naming a
  fixed store list here would drift out of date as each migrates, so this ADR deliberately doesn't
  re-enumerate it — see the routed-concerns.md row for the current set.) (If a genuine
  compliance/legal requirement for bounded
  retention of containment evidence ever emerges, that is a separate, explicit, separately-reviewed
  decision — same standing rule CLAUDE.md's "Clock-guarded retention" invariant states for the
  no-prune stores that DO eventually need one — not a bare `DELETE ... WHERE ts < cutoff` added
  here.) Recorded explicitly so a future author does not read the silence as "nobody considered
  it".
- **`kQuarantineDbErrorPrefix`/`is_quarantine_db_error` duplicates `DeploymentStore`'s identical
  `kDeploymentDbErrorPrefix`/`is_deployment_db_error` shape (Gate 3 architect).** Same literal
  (`"db_error: "`), same predicate, two independent homes. Benign at 2 consumers (each keys off
  its own constant, no drift risk yet), but the ladder guarantees a third — worth centralizing
  into a shared `pg::is_store_db_error`-style helper once one lands, not before.
- **Backfilling a store with no natural per-row key (Gate 3 architect design judgment) should
  become a `docs/postgres-store-playbook.md` section**, not stay a single store's ADR: the
  single-advisory-locked-transaction shape this store uses is the right default for a small,
  security-critical, no-key dataset (all-or-nothing atomicity beats per-row resumability when N is
  small and the store is authoritative-gated), but it is premise-dependent on N staying small — a
  future store on the ladder with the same no-key shape but high expected volume (`AnalyticsEventStore`
  is flagged high-volume) should reach for a content-derived per-row key
  (a canonical-preimage hash + occurrence ordinal, `ON CONFLICT DO NOTHING`) instead, which trades
  the atomicity guarantee for real resumability. Neither this ADR nor the playbook currently states
  the choice or the crossover point explicitly.

**Gate 4 unhappy-path findings — verified real, deliberately deferred (not fixed in this PR):**

- **UP-2: `list_quarantined`'s admit-then-filter loop is O(N) per-record re-authorization with no
  pagination**, so a large active-quarantine set means N sequential auth/RBAC lookups sharing the
  same connection pool every other store also leases from. **Pre-existing, not introduced by this
  migration** — the admit-then-filter shape itself predates this PR (#1788/CDX-P1-02); this
  migration only added the store-layer degrade check above it. Fixing it (pagination, or a
  bulk/batched authorization check) is a REST-contract change disproportionate to a storage
  migration — to be filed as a follow-up issue in this run's post-merge follow-up batch (per the
  governance skill), rather than folded in here.
- **UP-6: the backfill's row-count cap is checked AFTER the full legacy snapshot is already loaded
  into memory, and the holder-side fingerprint-verification path (`legacy_quarantine_fingerprint`,
  which re-runs on every boot while a legacy file lingers) has no cap at all.** At the current
  `kMaxBackfillRows` (5,000, lowered from the original 500,000 specifically for lock-hold-duration
  reasons — see above), the realistic memory footprint is small (low single-digit MB even loaded
  uncapped), so this is a structural gap without a practical exploit path today; worth tightening
  if the cap is ever raised for a genuinely high-volume future store copying this pattern.
- **UP-7: rolling back to the pre-migration SQLite binary after a successful backfill, then
  re-upgrading, can permanently refuse to boot ("HOLDER-SIDE VERIFICATION FAILED").** The old
  binary's `CREATE TABLE IF NOT EXISTS` recreates an EMPTY `quarantine_records` table at the
  original path (the real data was renamed aside, not deleted, by the prior migration); an empty
  table still fingerprints as real (not `sourceless`) content, so it can never match the original
  real fingerprint. **This is a class-level gap in the shared ADR-0040 fingerprint-verification
  backfill pattern** (built into `RbacStore`/`DiscoveryStore`/every store using this shape, not
  unique to quarantine) — this migration faithfully follows the established, precedent-set
  pattern; fixing the pattern itself is out of this PR's scope and blast radius. Documented here so
  an operator considering rollback-then-reupgrade is warned (see `upgrading.md` and the (retired,
  #3623) `quarantine-store-backfill-recovery.md` runbook, both fixed in the Gate 6 hardening
  round). Moot for this store specifically since `migrate_from_sqlite()` itself was retired
  (2026-09-03, see this ADR's own Update) — no rollback-then-reupgrade replay path remains; the
  class-level gap in the shared ADR-0040 pattern may still apply to a sibling store that has not
  yet retired its own backfill.
- **UP-9: a connection dying after a write commits but before the client receives the
  acknowledgement is answered on retry as a business error** (`"device is already
  quarantined"`/`"device is not quarantined"`, both 400) rather than distinguished from a caller
  error — the caller cannot tell "my own write already landed" from "someone else's state".
  Solving this needs idempotency keys, which no store's write path in this codebase currently
  implements; a systemic gap, not something to solve uniquely for quarantine.
- **UP-10: the MCP `quarantine_device` tool records the quarantine before dispatching live
  isolation (#289 design D2); if dispatch fails or the agent is offline (`agents_reached: 0`), a
  retry is rejected with the SAME "already quarantined" 400 this PR did not change.** Verified
  **pre-existing and byte-identical before and after this migration** (confirmed via the Gate 4
  happy-path idempotency check against `origin/dev`) — the record-first/dispatch-second design and
  its retry semantics are unrelated to the storage-backend migration. To be filed as a follow-up
  against the MCP tool's own design in this run's post-merge follow-up batch, not this PR.
- **UP-11: genuine store/pool/query failures include raw `PQerrorMessage(...)` text (host/port,
  never credentials — `pg_pool.hpp`'s own documented guarantee) in the client-facing error body
  and, new in the Gate 2 audit-on-failure fix, the persisted audit row.** This matches the
  established convention every other migrated store's error-string construction already uses
  (`DiscoveryStore`, `DeploymentStore`, etc.) — diverging from it uniquely for quarantine would be
  inconsistent rather than more secure; a systemic tightening (if ever desired) belongs at the
  shared `pg::exec_params`/error-construction layer, not one store's migration.

**Gate 5/6 findings — deferred with reasoning (not fixed in the Gate 5/6 hardening round):**
gov-fix(sre + enterprise-readiness, Gate 8): the hardening-round commit message claimed this
reasoning was "recorded in the ADR" for these items — it was not; this subsection closes that gap.

- **S1/F6 (sre/enterprise-readiness, SHOULD): quarantine's backfill/degrade metrics
  (`yuzu_server_quarantine_backfill_total`, `yuzu_server_quarantine_read_degrade_total`) are not
  `describe()`'d/pre-seeded unlike sibling stores, and no Prometheus alert rules ship for them.**
  Deliberately deferred: fixing this correctly is a 4-site lockstep change — pre-seed code in
  `server.cpp`/wherever the metric family is constructed, `metrics.md`'s existing "Not pre-seeded
  ... absence is the normal steady state" paragraph (which would need to flip), a matching PromQL
  comment update, and new alert rules in `docs/prometheus/yuzu-alerts.yml` — and doing only part of
  it (e.g. pre-seeding without updating the doc that says "absence is normal") would create a NEW
  doc-contradicts-code finding. Judged out of scope for an already-large hardening round; to be
  filed as a follow-up in this run's post-merge follow-up batch.
- **C-6/C-7/C-8 (compliance-officer, NICE): `audit_fn`'s bool return discarded at REST quarantine
  call sites (unlike MCP's `audit_persisted` surfacing); MCP audit rows key `target_id` on the tool
  name, not `agent_id` (pre-existing MCP-wide convention, not introduced by this migration); no
  audit-integrity concern from raw `PQerrorMessage` text in audit rows (see UP-11 above — informational, not
  a defect).** All three are cross-cutting, pre-existing conventions this single store's migration
  does not own; correctly left unfixed.
- **F8 (enterprise-readiness, NICE): `docs/authz-model.md`'s admit-then-filter description is
  slightly incomplete given the Gate 4 UP-1 widening (the per-record loop now fails closed on any
  non-403 outcome, not just an explicit deny).** `docs/authz-model.md` is untouched by this
  migration; correctly left unfixed as an out-of-scope doc owned by a different surface.
- **N1 (sre, NICE): no backfill duration/heartbeat signal (start-to-finish timing) is emitted.**
  The new `spdlog::info` completion log (C-5, above) names the row count but not elapsed duration;
  correctly left unfixed as a nice-to-have observability addition, not a defect.
- **Gate 8 (quality-engineer + compliance-officer, converged, NICE): the new `is_open()==false`
  audit rows on REST POST/DELETE and MCP `quarantine_device` (C-2) have no regression test.**
  `QuarantineRouteHarness`/`McpTestServer` always construct a live, open store — there is no
  existing seam to force `is_open()==false` at request time without either restructuring the test
  harness to accept a pre-broken store or adding a store-level test-only override, either of which
  is disproportionate for one NICE-tier assertion. The audit call itself was empirically verified
  correct by direct code inspection (Gate 8 security-guardian, compliance-officer) even without a
  test exercising it; a future harness change that adds this seam should also add the assertion.

## Update (2026-09-03) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production Yuzu
fleet has ever run a pre-Postgres build of any store — the mandatory, fingerprint-verified,
advisory-locked backfill this ADR designed (including the no-natural-per-row-key transaction
shape described above) was real, working code that never had real legacy data to protect.

`QuarantineStore::migrate_from_sqlite()` and its private helpers (`kSourcelessFingerprint`,
`kMaxBackfillRows`, `kBackfillLockSql`, `sha256_hex`, `legacy_has_table`, `sqlite_text`,
`LRecord`, `read_legacy_snapshot`, `append_field`, `canonicalize_legacy_snapshot`,
`fingerprint_legacy_snapshot`, `legacy_quarantine_fingerprint`, `BackfillOutcome`,
`commit_backfill`) are removed (`chore/retire-migrate-from-sqlite-batch-a`, tracking issue
#3623). `read_record()` — which the backfill-only anonymous-namespace block sat alongside but
never used — stays: `get_status`/`list_quarantined`/`get_history` all call it on the live read
path. `quarantine_meta` — whose entire purpose was the backfill idempotency markers
(`backfill_complete`, `backfill_row_count`, `backfill_source_fingerprint`) — is dropped via a
version-bumped `{3, "DROP TABLE IF EXISTS quarantine_meta;"}` migration, appended after the
already-shipped v1/v2 rather than edited in place: this store IS constructed in production, so
v1/v2 have actually run against real dev/UAT databases. `server.cpp`'s boot path now runs
`legacy_sqlite_probe::warn_if_legacy_rows` over `quarantine_records` instead of the backfill —
WARN-only (never refuse-boot) on a real legacy row found, the same posture as every other store
in this retirement batch. This is a deliberate, explicit choice for this store despite an active
quarantine record being live security containment state: a real legacy file surviving to this
point contradicts the established program-wide fact this amendment rests on, and a boot refusal
would itself be a denial-of-service on the containment surface it exists to protect. An operator
who sees the warning should treat it as an anomaly investigation, not a routine recovery path —
the server's view of containment does not include whatever the warning names, though agent-side
firewall enforcement (§11.7, out of scope for this store) may still be independently in effect.
The ADR-0012 §2(b) documented exception for a one-time legacy backfill's atomic
insert-plus-completion stamp is no longer exercised by this store.
