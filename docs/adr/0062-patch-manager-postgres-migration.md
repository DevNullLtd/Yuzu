# ADR-0062: PatchManager → PostgreSQL

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** pg workstream (7-remaining-stores plan, PR 2)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009 (including its 2026-08-25
  fresh-start-by-default amendment), ADR-0012 (substrate/store contract);
  `docs/postgres-store-playbook.md`; `docs/postgres-migration-ladder.md` Wave 4 (the
  non-`*Store` ladder blind spot found 2026-08-27, #1328/#1325/#3653).

## Context

`PatchManager` (`server/core/src/patch_manager.{hpp,cpp}`) is the OS-patch inventory +
deployment-orchestration store behind `/api/patches/*` (`DiscoveryRoutes`, no MCP surface).
It was one of 7 production-wired SQLite components the migration ladder never gave its own row —
the ladder only ever enumerated `*Store` classes and the auth DB. It has its own SQLite file
(`patches.db`), three tables (`patch_inventory`, `patch_deployments`, `patch_deployment_targets`),
and 10 non-`execute_deployment` `TEST_CASE`s in `test_patch_manager.cpp` (a `TempDbFile` fixture) —
6 of which exercise `PatchManager` in ways not entangled with `execute_deployment` (see "Deleted:
execute_deployment" below for the count correction).

Construction was unconditional and best-effort in the SQLite era: no caller anywhere checked
`is_open()` before using the pointer, and the store was in neither `/readyz` nor `/healthz`.

## Decision

### Schema

Postgres schema `patch_manager` (non-`Store`-suffixed name — this is the extension of the
ADR-0008 naming rule the Wave-4 ladder amendment records: the schema name is the name already
passed to `MigrationRunner::run` today, not `snake_case(FullClassName) + "_store"`), three tables:

```sql
CREATE TABLE patch_inventory (
    agent_id    TEXT   NOT NULL,
    kb_id       TEXT   NOT NULL,
    title       TEXT   NOT NULL DEFAULT '',
    severity    TEXT   NOT NULL DEFAULT 'Unspecified',
    status      TEXT   NOT NULL DEFAULT 'missing',
    released_at BIGINT NOT NULL DEFAULT 0,
    scanned_at  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, kb_id)
);
CREATE TABLE patch_deployments (
    id                   TEXT    PRIMARY KEY,
    kb_id                TEXT    NOT NULL,
    title                TEXT    NOT NULL DEFAULT '',
    status               TEXT    NOT NULL DEFAULT 'pending',
    created_by           TEXT    NOT NULL DEFAULT '',
    reboot_needed        BOOLEAN NOT NULL DEFAULT FALSE,
    reboot_delay_seconds INTEGER NOT NULL DEFAULT 300,
    reboot_at            BIGINT  NOT NULL DEFAULT 0,
    created_at           BIGINT  NOT NULL DEFAULT 0,
    completed_at         BIGINT  NOT NULL DEFAULT 0,
    total_targets        INTEGER NOT NULL DEFAULT 0,
    completed_targets    INTEGER NOT NULL DEFAULT 0,
    failed_targets       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE patch_deployment_targets (
    deployment_id TEXT    NOT NULL REFERENCES patch_deployments(id) ON DELETE CASCADE,
    agent_id      TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending',
    error         TEXT    NOT NULL DEFAULT '',
    started_at    BIGINT  NOT NULL DEFAULT 0,
    completed_at  BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (deployment_id, agent_id)
);
CREATE INDEX idx_patch_inv_kb ON patch_inventory(kb_id);
CREATE INDEX idx_patch_inv_status ON patch_inventory(status);
CREATE INDEX idx_patch_inv_agent ON patch_inventory(agent_id);
CREATE INDEX idx_patch_depl_status ON patch_deployments(status);
CREATE INDEX idx_patch_depl_targets ON patch_deployment_targets(deployment_id);
```

One v1 migration — the SQLite-era ladder (v1 `CREATE TABLE IF NOT EXISTS` + an out-of-ledger
`ALTER TABLE patch_deployments ADD COLUMN reboot_delay_seconds/reboot_at` hack applied
unconditionally on every open, `patch_manager.cpp:81-87` pre-migration) flattens to one clean DDL:
`reboot_delay_seconds`/`reboot_at` are ordinary columns in the v1 `CREATE TABLE`, no ALTER step.

**New: `patch_deployment_targets.deployment_id → patch_deployments(id) ON DELETE CASCADE`.** The
SQLite schema declared no FK at all (both tables were independently created, no
`foreign_keys=ON` reference between them) — a deployment's target rows outlived deleting the
deployment row itself, though nothing in this codebase ever deletes a `patch_deployments` row
(no `DELETE` on that table exists in the SQLite-era code either), so this FK closes a latent
integrity gap without changing any observed runtime behavior.

Deployment ids stay app-generated 32-hex-character strings (`gen_id()`, unchanged) — a `TEXT`
primary key, not a Postgres `IDENTITY` column. There is no secret material and no AAD-tuple
concern here (unlike `OffloadTargetStore`/`WebhookStore`), so there was no reason to introduce
the reserve-before-encrypt sequence dance those stores need; ordinary app-side id generation
carries over unchanged.

### Posture (ADR-0012 §1)

**Fail-CLOSED construction** — a posture UPGRADE from the SQLite era, where construction was
unconditional/best-effort (no `startup_failed_` gate; `server.cpp` never even checked
`is_open()` before wiring the pointer into `DiscoveryRoutes`). A reachable database whose schema
can't migrate/open is now a fatal startup error.

**Runtime read/write signatures are UNCHANGED from the SQLite era** — this is a deliberate,
narrower posture than several sibling migrations on this ladder (e.g. `OffloadTargetStore`'s
`std::expected`/`std::optional` rework). `PatchManager` has exactly one external consumer
surface (`DiscoveryRoutes`' `/api/patches/*`, no MCP), and every read (`get_missing_patches`,
`get_installed_patches`, `get_fleet_patch_summary`, `list_deployments`) already degrades to an
empty container on failure in a route context whose own failure mode is deny-or-benign (a
missing/incomplete patch list, never a security or dispatch decision) — widening these to a
typed degrade channel was scoped out of this PR to keep the consumer-facing contract identical
and the diff to the store + its own test file. `deploy_patch`/`cancel_deployment` keep their
`std::expected<T, std::string>` shape verbatim.

### New atomicity: `deploy_patch`

**Correction to the original migration-plan inventory:** the explicit SQLite transaction
(`BEGIN TRANSACTION`/`ROLLBACK`/`COMMIT`) lives entirely inside `record_patches`
(pre-migration `patch_manager.cpp:162/166/183`), not `deploy_patch`. `deploy_patch`
(pre-migration `:281+`) inserted the deployment row and then looped an unchecked
`sqlite3_step()` per target row — no transaction, and no failure check on the per-target insert
at all (not even a log line on a failed step).

This migration wraps `deploy_patch`'s deployment-row insert, title lookup, and target-row batch
insert in ONE `pool_.with_txn_for(...)` — **new atomicity this port adds, not a straight
translation of existing behavior.** Decision: **fail the whole deploy if any statement in that
transaction fails** (all-or-nothing), replacing the SQLite era's silently-ignored per-target
insert failures. The one way a target-row insert could fail today — a caller-supplied duplicate
`agent_id` colliding on the `(deployment_id, agent_id)` primary key — is closed at the source:
`deploy_patch` de-duplicates `agent_ids` (preserving order) before any DB work, so
`total_targets` (set from the de-duplicated count) always matches the number of target rows the
transaction actually creates. The SQLite era's `total_targets` was set from the *raw*
`agent_ids.size()`, so a duplicate silently produced a `total_targets` value inconsistent with
the real row count — this closes that pre-existing accounting bug as a side effect of adding the
atomicity.

**Cap on `agent_ids` (governance sre finding, closed 2026-08-30):** an unbounded caller-supplied
`agent_ids` list would hold the shared pool connection for the duration of the `unnest()` batch
target insert, contributing to pool starvation for unrelated stores under a near-fleet-wide
deploy request. `deploy_patch` now rejects a de-duplicated list over `kMaxDeployTargets` (5000)
before any DB work — matching the DoS-cap default used for the same class of bulk
operator-supplied fleet-wide list elsewhere (fleet-viz `machines_max`).

`record_patches`'s existing SQLite transaction translates directly to one `with_txn_for`, with
its per-row prepared-statement loop replaced by a single `unnest()`-driven batch `INSERT ...
ON CONFLICT (agent_id, kb_id) DO UPDATE` (the same batching shape `PreflightRunStore::create_run`
already uses for its `run_device` seed insert) — this avoids N round trips for a scan report
carrying many patches, with no behavior change (still one atomic upsert-or-update per
`(agent_id, kb_id)` pair, still one transaction for the whole batch).

`recalculate_deployment_progress`'s two-statement SELECT-then-UPDATE (both inside the same
mutex-held scope, but not itself wrapped in an explicit SQL transaction in the SQLite era)
becomes one statement (`UPDATE ... FROM (SELECT ... ) AS counts WHERE ...`) — atomic by
construction, one round trip instead of two.

### Deleted: `execute_deployment`

`execute_deployment()` (+ its `PatchDispatchFn`/`AgentOsLookupFn` callback types) is REMOVED in
this migration, not ported. Verified directly against `origin/dev`: it has **zero production
callers** — nothing in `server.cpp`/`discovery_routes.cpp` ever constructs a `PatchDispatchFn` or
calls `execute_deployment`, and the REST `POST /api/patches/deploy` route only ever calls
`deploy_patch` (which creates the deployment + target rows; nothing then drives them through
scan → install → verify → reboot). It IS tested and documented functionality, not ordinary dead
code: 4 dedicated `TEST_CASE`s in the pre-migration `test_patch_manager.cpp` (Windows/Linux/
unknown-OS reboot orchestration + a notification-failure-is-non-fatal case) and a `docs/
capability-map.md` §8.6 entry ("Reboot Management (Post-Patch)") describing its behavior in
detail. Per the operator's explicit call: **still delete it in this PR** (zero production
callers is the operative fact for what gets ported to Postgres) — porting untested-in-production
orchestration logic to a new storage substrate is not owed just because it has unit-test
coverage — **but the tests/capability-map removal is recorded as a deliberate feature de-scope,
not a silent erasure**, tracked in dedicated follow-up issue **#3669** (filed alongside this PR)
rather than reviving it unwired or deleting the historical record with no trace.

**Correction to the original migration-plan's test count:** the plan's per-store section stated
"10 non-`execute_deployment` cases... port 1:1." Re-verified directly against
`test_patch_manager.cpp`: the file has **10 `TEST_CASE`s total**, of which **4** exercise
`execute_deployment` (Windows/Linux/unknown-OS reboot orchestration, and the
notification-failure-is-non-fatal case — all four call `execute_deployment` directly) and are
deleted with the code; **6** do not touch `execute_deployment` and are ported 1:1 to the
`PgTestTemplate` fixture (create/get deployment, `DeploymentRequest`-struct deploy, reboot-delay
clamping, kb_id validation, `cancel_deployment`, `list_deployments`).

As a direct mechanical consequence, `recalculate_deployment_progress` — a private helper whose
**only** call site was inside `execute_deployment` — is also dead code once `execute_deployment`
is removed, and is deleted along with it (it had no dedicated test coverage of its own; every
existing assertion on `completed_targets`/`failed_targets`/deployment `status` after a run
flowed through the now-deleted `execute_deployment` test cases).

### No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment)

No `migrate_from_sqlite`, no legacy-table-reading code. The legacy `patches.db` is never read
for data — same posture as `ResponseStore`/`OffloadTargetStore`. Because this store holds real
operator-initiated state (deployment records, per-target progress), the playbook's
detect-and-warn obligation applies: `server.cpp` calls the new shared
`legacy_sqlite_probe::warn_if_legacy_rows()` helper (`server/core/src/legacy_sqlite_probe.hpp`,
shared with `UpdateRegistry`'s ADR-0061 — see "Reconciled post-rebase" below)
over the legacy file's three tables after a successful open, logging a `spdlog::warn` with a
summed row count only if the legacy file actually holds rows — silence is the ordinary case (a
genuinely fresh install).

`legacy_sqlite_probe.hpp` generalizes `RuntimeConfigStore::warn_if_legacy_data_present`
(ADR-0060) from one table to a caller-supplied list, for reuse by the remaining Wave-4 PRs
(3-5). It deliberately does NOT force the legacy file to 0600 before reading — that obligation
applies only to a legacy file that may hold a plaintext secret column, and none of the 7 Wave-4
components hold secret material (`PatchManager` included — patch titles/severities/deployment
metadata are not secrets). **Reconciled post-rebase:** this PR originally authored its own
`legacy_sqlite_probe.{hpp,cpp}` (split header+impl, a caller-string-based signature, an up-front
identifier-validation loop) because the sibling `UpdateRegistry` migration (PR 1) had not yet
merged when this PR was first authored. `UpdateRegistry` landed first (PR #3695), with a
header-only, `string_view`-based, more thoroughly hardened version (adversarial-review findings:
refuses to block on a FIFO/symlink/device node at the legacy path via `is_regular_file` rather
than `exists()`, distinguishes a permission-check failure from genuine absence, binds the
existence-check identifier as a parameter rather than string-concatenating it). This PR's own
copy — implementation, header, and test file — was retired in favor of that canonical version on
rebase; `PatchManager`'s call site needed no changes (the canonical signature accepts the same
string-literal call shape).

Construction logs a one-time line: `PatchManager initialized (schema patch_manager) — fresh
start, no legacy backfill`.

### Consumers — unchanged

`DiscoveryRoutes`' `/api/patches/*` routes (`discovery_routes.cpp`) are the only consumer — no
MCP tool wraps this store. Every public method keeps its pre-migration signature (constructor
excepted — it now takes `pg::PgPool&` instead of a `std::filesystem::path`), so
`discovery_routes.cpp` needed no changes at all. `patch_manager_` is now constructed inside the
`if (pg_pool_ && !startup_failed_)` guard and added to both `/readyz`'s `StoreCheck` vector and
`/healthz`'s store-detail JSON (absent from both in the SQLite era — the store was in neither
probe, since no caller ever checked `is_open()`).

## Considered and rejected

- **Widening every read to a typed degrade channel** (`std::optional`/`std::expected`), matching
  `OffloadTargetStore`'s posture. Rejected for this PR: `PatchManager`'s reads all feed a
  deny-or-benign REST surface (a patch list rendering empty, never a targeting/authorization
  decision), and the task scope is the store + its own test file — widening the consumer-facing
  contract would touch `discovery_routes.cpp` for no closed gap. Tracked as a follow-up if a
  future consumer (a dashboard summary tile, a compliance report) starts treating an empty result
  as a decision input. **Distinguished from `DiscoveryStore`'s opposite call for a structurally
  similar read** (governance Gate 3 architect finding): `DiscoveryStore` 503s on a degraded read
  because "an operator scanning for rogue devices must not be told 'nothing found' when the real
  answer is 'could not ask'" — patch compliance is not itself a security-gating decision the way
  "is this device managed" is, so the deny-or-benign classification stands, but the next Wave-4
  author reusing this reasoning should weigh their own store against BOTH precedents, not just
  `OffloadTargetStore`'s.
- **Porting `execute_deployment` as-is.** Rejected — zero production callers, and the reboot
  orchestration it implements (PowerShell `-match` on a live Windows Update search, cross-platform
  shutdown commands) is real, security-sensitive shell-construction logic that would need its own
  review pass on a new storage substrate for no wired benefit. See "Deleted: execute_deployment"
  above.
- **Silent per-target insert failure (SQLite-era shape), kept for compatibility.** Rejected —
  wrapping the deployment + target inserts in one transaction makes "some targets silently
  missing" strictly worse than before (a caller could no longer tell from `total_targets` whether
  every target actually got a row). All-or-nothing plus up-front de-dup is simpler and closes a
  real (if minor) counting bug.

## Consequences

- **Any in-flight patch deployment recorded against a pre-Postgres build is lost on upgrade** —
  must be re-created via `POST /api/patches/deploy`. Documented in
  `docs/user-manual/upgrading.md`, same treatment as every other fresh-start cutover on this
  ladder. (Patch inventory itself does NOT self-heal on the next scan — `record_patches()`, its
  only writer, has no production caller on any build, pre- or post-migration; see "Follow-ups"
  below and #3676.)
- **`execute_deployment`'s reboot-orchestration behavior is no longer available at all** (it was
  never reachable from a production caller, so this is a documentation/tracking change, not a
  behavior change for any real deployment). See the tracking issue for the deliberate de-scope.
- **`patch_manager` joins `/readyz`/`/healthz`** — a degraded Postgres pool now visibly fails
  `/api/patches/*` instead of silently no-oping (the SQLite era's `is_open()` was checked at each
  route, but a dead store was invisible to any external health probe).

## Follow-ups

- **#3669** — decision issue tracking whether `execute_deployment`'s scan/install/verify/reboot
  orchestration should be revived (wired to a real dispatch path) or the de-scope confirmed
  permanent (filed alongside this PR).
- **#3676** — governance Gate 3 `sre` finding, independently confirmed by grep during this PR's
  own review: `record_patches()`, the only method that writes `patch_inventory`, has **zero
  production callers anywhere in this codebase** — pre-existing, predates this migration. Every
  read this store exposes (`get_missing_patches`/`get_installed_patches`/
  `get_fleet_patch_summary`) is correctly implemented over a table nothing currently populates, so
  `GET /api/patches` returns empty in any real deployment today. `docs/capability-map.md` §8.5/§8.7
  are downgraded (Done → Partial) in this same PR to reflect that; see #3676 for the wire-it-vs-
  confirm-out-of-scope decision.
- Widening `PatchManager`'s reads to a typed degrade channel, if a future consumer needs to
  distinguish "no patches" from "degraded read" (see "Considered and rejected" above).
