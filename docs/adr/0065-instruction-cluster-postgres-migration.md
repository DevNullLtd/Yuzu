# ADR-0065: Instruction Cluster (ScheduleEngine / ApprovalManager / ExecutionTracker) → PostgreSQL

- **Status:** Accepted — all three components ported, the whole binary compiles and links, and
  both the full `[pg]`-tagged suite (2933 cases, 2930 passed, 3 pre-existing unrelated skips —
  unconditional placeholders in `test_saml_routes.cpp` for coverage unreachable via a real
  HTTP-POST binding at `kMaxGroupValues=200`, unrelated to this migration) and the full non-pg
  suite (2984 cases, 2984 passed, 0 skipped on this Linux run) pass with zero failures;
  `check-pg-shard-partition.py` confirms an exact 12-pg/4-non-pg partition. (Counts as of the
  governance adversarial-review hardening round, 2026-08-31 — the trio's own regression tests
  plus a `[pg]` shard L carve and the #1398/WorkflowEngine merge-reconciliation moved these
  numbers up from this ADR's original 2888/11-shard figures; see the "Correction" sections below
  for what changed.)
- **Date:** 2026-08-30
- **Authors:** Dave Rae
- **Deciders:** pg workstream (migration-programme PR 5, the last of the 7-store SQLite→Postgres
  ladder — `WorkflowEngine`/ADR-0064 merged separately as PR 4, #1328/#1325/#3653)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009 (including its 2026-08-25
  fresh-start-by-default amendment), ADR-0012 (substrate/store contract); ADR-0063
  (`DirectorySync` → PostgreSQL — the freshest per-store template this ADR follows); ADR-0061/
  0062/0063/0064 (siblings 1/2/3/4 of this same ladder); `docs/postgres-store-playbook.md`;
  `docs/postgres-migration-ladder.md`.

## Context

`ExecutionTracker`, `ApprovalManager`, and `ScheduleEngine` (`server/core/src/{execution_tracker,
approval_manager,schedule_engine}.{hpp,cpp}`) are the last 3 of the 7 production-wired SQLite
components missed by the original migration ladder (found 2026-08-27, tracked #1328/#1325/#3653).
Unlike the four already-migrated Wave 4 components, these three do not each own a private SQLite
file — all three share one `instructions.db` connection via `InstructionDbPool`
(`server/core/src/instruction_db_pool.{hpp,cpp}`), a construct that exists ONLY because they share
that one file; each store keeps its own private, unrelated table set (no SQL-level joins between
them — every apparent relationship is stitched in C++). This ADR treats them as one cluster because
they migrate in one PR (staged as 3 commits so governance can review each store's diff separately),
and `InstructionDbPool` is deleted once all three have moved off it — the pool has exactly one
consumer, `server.cpp`, verified by a repo-wide grep before this PR started.

Each of the three moves to its own independent Postgres schema — `schedule_engine`,
`approval_manager`, `execution_tracker` — following ADR-0008's schema-per-store naming rule
extended (per the ladder's Wave 4 note) to non-`Store`-suffix class names.

## Decision

### Component 1/3: ScheduleEngine (commit 1)

`ScheduleEngine` (`schedule_engine.{hpp,cpp}`) stores recurring instruction schedules
(`schedules`, one table, 17 columns) and is polled by `ScheduleRunner`'s background tick thread
(`server.cpp`) to fire due occurrences.

**Pre-existing gap closed by this port, not a regression it introduces:** the SQLite era had NO
`is_open()`/availability flag at all — a migration failure was `spdlog::error`-only
(`schedule_engine.cpp:134-136` on `origin/dev` before this port), so `server.cpp` never checked
availability and the store was silently fail-open. This is a **posture upgrade** (ADR-0012 §1):
construction is now fail-**closed** — a reachable database whose schema can't migrate/open is a
fatal startup error (`startup_failed_`), matching every other migrated store in this ladder.

**Schema** (Postgres schema `schedule_engine`, one table, folding the SQLite-era v1+v2 ladder into
one PG v1 DDL — v2 only added the `parameter_values` column, PR1.5a):

```sql
CREATE TABLE schedules (
    id                 TEXT    PRIMARY KEY,
    name               TEXT    NOT NULL,
    definition_id      TEXT    NOT NULL,
    frequency_type     TEXT    NOT NULL DEFAULT 'once',
    interval_minutes   INTEGER NOT NULL DEFAULT 60,
    time_of_day        TEXT    NOT NULL DEFAULT '00:00',
    day_of_week        INTEGER NOT NULL DEFAULT 0,
    day_of_month       INTEGER NOT NULL DEFAULT 1,
    scope_expression   TEXT    NOT NULL DEFAULT '',
    requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    next_execution_at  BIGINT  NOT NULL DEFAULT 0,
    last_executed_at   BIGINT  NOT NULL DEFAULT 0,
    execution_count    INTEGER NOT NULL DEFAULT 0,
    created_by         TEXT    NOT NULL DEFAULT '',
    created_at         BIGINT  NOT NULL DEFAULT 0,
    parameter_values   TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_schedules_due ON schedules(next_execution_at)
  WHERE enabled AND next_execution_at > 0;
```

`idx_schedules_due` is **net new** — the SQLite era had no indexes at all, so `evaluate_due()`'s
poller-tick hot path (`WHERE enabled=1 AND next_execution_at>0 AND next_execution_at<=now ORDER BY
next_execution_at`) full-scanned every row on every tick. The partial index's predicate matches
that WHERE clause and its column matches the ORDER BY exactly.

**`advance_schedule` collapses a two-statement race into one atomic statement.** The SQLite era
performed a locked SELECT, computed the next occurrence in C++ by branching on `frequency_type`,
then issued a separate UPDATE — a read-modify-write spanning two statements, which is the actual
race an app-level `std::shared_mutex` existed to cover (`SQLITE_OPEN_FULLMUTEX` only serializes
each individual call, not the pair). The Postgres port moves the frequency arithmetic into a SQL
`CASE` inside a single `UPDATE ... RETURNING`, so the whole read-compute-write happens in one round
trip under Postgres's own per-row locking — no app-level lock needed at all. The `std::shared_mutex`
(`mtx_`) is deleted entirely, not narrowed: every method now takes a per-call bounded pool lease
instead (`kReadTimeout=1500ms` for reads via `try_acquire_for`, degrade-to-empty on lease failure;
`kWriteTimeout=2000ms` for writes via `with_txn_for`, matching `PatchManager`/`DirectorySync`'s
constants). A zero-row-affected UPDATE (unknown id) stays today's silent no-op.

**Owner-scoped mutators keep their exact SQLite-era shape**: `delete_schedule`/`set_enabled` are
`DELETE`/`UPDATE ... WHERE id=$1 AND created_by=$2 RETURNING id` — wrong-owner is indistinguishable
from missing, same as before, just against Postgres.

**Posture (ADR-0012 §1):** runtime read/write method signatures are UNCHANGED — plain
`std::vector`/`bool`/`std::expected<std::string,std::string>` shapes, matching `PatchManager`'s
precedent of not upgrading call-site contracts during a storage-backend swap. `ScheduleRunner`
needs no changes (borrowed raw pointer only).

**Consumers (unchanged public API, no signature churn):** `ScheduleRoutes`/`schedule_routes.cpp`
(REST), `mcp_server.cpp` (`list_schedules`), `ScheduleRunner`/`schedule_runner.cpp` (poller,
borrowed pointer), `workflow_routes.cpp`. Verified: no consumer touches `sqlite3` directly or
constructs `ScheduleEngine` itself — `server.cpp` is the sole construction site.

**`/readyz`/`/healthz`:** both are **net-new rows** for this store — the SQLite era had no
availability flag to key either probe on, so neither existed. `/readyz`'s `StoreCheck` gains
`schedule_engine_ && schedule_engine_->is_open()`; `/healthz` gains `schedule_engine_ok` in the
`all_stores_ok` conjunction and a `schedule_engine` entry in the `stores` JSON map, following the
exact pattern `patch_manager_ok`/`directory_sync_ok` already established.

**No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment):** no
`migrate_from_sqlite`, unconditionally — re-derived for this store, not merely cited (PR review,
2026-08-31, Doomgoose, per #1325): the amendment applies here specifically because there is no
production fleet running this store today (pre-release), so there is no live `schedules` table
whose loss would be an operational incident rather than a documented, disclosed cutover; the
`legacy_sqlite_probe::warn_if_legacy_rows()` check below is the mechanism that would catch the
premise being locally wrong. The legacy `instructions.db` (at this point in the PR's
staged commits, still shared with the not-yet-ported ExecutionTracker/ApprovalManager siblings) is
never read for data. Construction logs a one-time `ScheduleEngine initialized (schema
schedule_engine) — fresh start, no legacy backfill` line; `server.cpp` calls the shared
`legacy_sqlite_probe::warn_if_legacy_rows()` helper (already established by the earlier Wave 4
PRs) over `instructions.db`, naming only the `schedules` table this component owns, to warn
(never fail, never block boot) if the legacy file still holds rows. Each of the three components
in this cluster makes its own separate probe call over its own tables — landing with its own
commit — rather than one combined call; `server.cpp`'s per-store construction blocks were already
independent before this migration, and a probe call belongs next to the construction it guards.

### Component 2/3: ApprovalManager (commit 2)

`ApprovalManager` (`approval_manager.{hpp,cpp}`) stores one-time MCP approval tickets and REST
instruction-approval requests (`approvals`, one table, 15 columns) — a security control, not
ordinary CRUD state.

**Not a posture upgrade, unlike ScheduleEngine.** This store was ALREADY fail-closed in the
SQLite era (a failed migration nulled `db_`, and `server.cpp` never checked `is_open()` before
this migration only because it never needed to — the null-`db_` state degraded every method to a
no-op/empty-return, not a crash). Construction is fail-**closed** exactly as before; `server.cpp`
now additionally checks `is_open()` and sets `startup_failed_` on failure, matching the ladder's
uniform wiring pattern, but the store's own internal posture is unchanged.

**Schema** (Postgres schema `approval_manager`, one table, folding the SQLite-era v1..v8 ladder
into one PG v1 DDL — every column the ladder ever added is present from creation, and all six
indexes the ladder accumulated are included; v7's `origin='legacy'` back-fill has no fresh-start
equivalent — see "Considered and rejected". v8 landed on `origin/dev` as #1398's
dispatch-approval-gate hardening (`target_plugin`/`target_action`, merged after this branch
forked) and was folded into this same PG v1 DDL when the branch reconciled against it, rather
than shipping a separate v2 migration for a still-unreleased column pair):

```sql
CREATE TABLE approvals (
    id                TEXT    PRIMARY KEY,
    definition_id     TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'pending',
    submitted_by      TEXT    NOT NULL DEFAULT '',
    submitted_at      BIGINT  NOT NULL DEFAULT 0,
    reviewed_by       TEXT    NOT NULL DEFAULT '',
    reviewed_at       BIGINT  NOT NULL DEFAULT 0,
    review_comment    TEXT    NOT NULL DEFAULT '',
    scope_expression  TEXT    NOT NULL DEFAULT '',
    consumed_at       BIGINT  NOT NULL DEFAULT 0,
    consumed_by       TEXT    NOT NULL DEFAULT '',
    schedule_id       TEXT    NOT NULL DEFAULT '',
    origin            TEXT    NOT NULL DEFAULT '',
    target_plugin     TEXT    NOT NULL DEFAULT '',
    target_action     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_submitted_at ON approvals(submitted_at);
CREATE INDEX idx_approvals_definition ON approvals(definition_id);
CREATE INDEX idx_approvals_schedule_id ON approvals(schedule_id);
CREATE INDEX idx_approvals_status_submitted ON approvals(status, submitted_at);
CREATE INDEX idx_approvals_status_consumed_reviewed ON approvals(status, consumed_at, reviewed_at);
```

**`consume_ticket`'s one-time CAS ports shape-for-shape** — `UPDATE approval_manager.approvals SET
consumed_at=$1, consumed_by=$2 WHERE id=$3 AND status='approved' AND consumed_at=0 RETURNING 1`,
row-count-checked via `PQntuples` instead of a bare affected-row count — a security control
preserved exactly, not a mechanical schema translation. The `#2442` cross-surface/cross-submitter
binding check (a `get_checked` read ahead of the CAS) is unchanged; it deliberately stays
non-locking (`FOR UPDATE` was considered and rejected — the origin/submitter fields are immutable
after insert, and the CAS itself re-checks `status`/`consumed_at`, so there is no TOCTOU window a
row lock would close).

**The one genuinely non-mechanical consumer seam in the whole cluster: the SQLite-error
discriminator.** `StoreReadError`/`ConsumeError`'s `int extended_errcode` (a raw
`sqlite3_extended_errcode()`) — consumed by `mcp_approval_error.hpp::approval_store_error_body` to
pick the MCP A4 permanent-vs-transient error arm — is replaced by a `std::string sqlstate` field.
New `server/core/src/pg_error_class.hpp::is_permanent_pg_error(std::string_view)` replaces
`sqlite_error_class.hpp::is_permanent_sqlite_error` (deleted — verified single includer). Permanent
= class `42` prefix (schema drift — the closest Postgres analogue of `SQLITE_NOTADB`, and the same
family `engine_principal_store.cpp`'s own file-local `is_permanent_sqlstate` classifier matches,
#2456 UP-17), `XX001`/`XX002` (corruption, analogue of `SQLITE_CORRUPT`), `53100` (disk_full,
analogue of `SQLITE_FULL`), `25006` (read_only_sql_transaction, analogue of `SQLITE_READONLY`);
everything else — `08*` connection, `40001`/`40P01` serialization/deadlock, `55P03` lock timeout,
`57014` query canceled, `P0001` a plpgsql `RAISE EXCEPTION` — stays transient, matching this
repo's existing narrow-classifier precedent. An empty `sqlstate` (no Postgres origin — store not
open, missing argument, a pool-acquire timeout) classifies transient on its own, exactly as `0`
did for the SQLite field; the `!mgr.is_open()` disjunct in `approval_store_error_body` is what
forces the permanent arm for the store-never-opened case regardless.

**Deliberate template divergence, not an oversight:** `ApprovalManager`'s reads do NOT
degrade-to-empty the way `ScheduleEngine`/`PatchManager` do — a pool-acquire timeout on a read
surfaces as `StoreReadError{sqlstate=""}` (transient) rather than a silent empty result. This seam
exists specifically to carry fidelity into the MCP A4 error envelope; collapsing it to
degrade-to-empty would make a transient pool blip on the recall path indistinguishable from "no
such ticket."

**Contention tests ported to a Postgres-native technique.** The two SQLite `BEGIN EXCLUSIVE`
tests pinning the masked-denial classification (`test_approval_manager.cpp`) port to
`test_engine_principal_store.cpp`'s `.lock_timeout_ms` technique (#2456 precedent): a second raw
connection holds `LOCK TABLE approval_manager.approvals IN ACCESS EXCLUSIVE MODE`, and the store's
own pool is built with a short `lock_timeout_ms` so its blocked read fails deterministically with
SQLSTATE `55P03` — no sleep/retry loop needed, same determinism guarantee the SQLite
rollback-journal trick gave. A third test (the CAS-step-only fault, negative control for
`binding_check_unevaluated`) ports its SQLite `BEFORE UPDATE ... RAISE(ABORT)` trigger to a
Postgres `BEFORE UPDATE` trigger function raising a plpgsql exception (`P0001`, correctly transient
by the classifier above).

**One MCP-level integration test has NO Postgres equivalent and is deleted, not ported** (see
"Considered and rejected") — the identical mechanism it tested is pinned precisely at the store
level by the ported chaos test above.

**Expiry-sweep clock-guard adjudication (routed-concerns row 38, recorded per its part 6):** the
lazy 7-day expiry sweep inside `submit()` is a wall-clock-cutoff bulk `UPDATE` (two statements —
stale-pending and approved-unconsumed), never a `DELETE`. The clock-guard seven-part apparatus's
own trigger condition (bulk *deletes* driven by a wall clock) is not met by this store — rows are
state-transitioned to `'expired'`, never removed, and remain queryable/auditable indefinitely. This
is a deliberate reading, not a silent skip: the sweep ports shape-preserved (same two statements,
same 7-day window, same RETURNING-based counting), and `mtx_` narrows to guard only this
compound cap-check + sweep + insert sequence — `consume_ticket`'s CAS and every read method no
longer take it at all, since a single Postgres statement is already atomic under the target row's
own lock.

**Correction (adversarial review, 2026-08-31):** "ports shape-preserved" above was true of the two
`UPDATE` statements themselves but not of their ORDER relative to the pending-count cap check.
Both Kimi and Codex independently found — and cross-examination confirmed unanimously — that
`submit()` ran the cap check BEFORE the expiry sweep (inherited unchanged from the pre-migration
SQLite ordering), so a queue that reached exactly the state the sweep exists to relieve (1000
pending rows, all stale) permanently refused every subsequent `submit()` with "queue is full"
without ever running the sweep that would have cleared it — a durable denial of service across
every approval-gated surface (MCP, REST instruction-approval, schedule), recoverable only by
manual database intervention. Fixed by running both expiry `UPDATE`s before the pending-count
`SELECT COUNT(*)` inside the same transaction, so a full stale queue clears itself on the very
call that would otherwise have been refused. Two regression tests added
(`tests/unit/server/test_approval_manager.cpp`): a full stale queue accepts the next `submit()`
and clears down to just the new row, and a full queue of genuinely non-stale rows still rejects
(the cap must still bind when there is nothing for the sweep to clear). Verified empirically that
the new test fails against the pre-fix ordering and passes against the fix.

### Component 3/3: ExecutionTracker + `InstructionDbPool` deletion (commit 3)

`ExecutionTracker` (`execution_tracker.{hpp,cpp}`) stores execution history and per-agent
outcomes (`executions` + `agent_exec_status`, two tables) and is the write path for every
gRPC `CommandResponse`, all REST v1/legacy execution routes, five MCP tools, the dashboard, and
`ScheduleRunner`. It is the last of the three to move and the one whose deletion of
`InstructionDbPool` retires `instructions.db` entirely.

**Not a posture upgrade at the store level — but a probe-visibility fix.** The SQLite era kept a
`migration_ok_`/`schema_ok()` pair only because a borrowed `sqlite3*` couldn't be nulled on
failure; `/readyz` keyed on `instr_db_pool_->is_open() && execution_tracker_->schema_ok()` —
i.e. availability was reported through the POOL, not the store. Construction is now
fail-**closed** on its own new `open_`/`is_open()` (`schema_ok()` kept as an alias, unchanged
call sites); `/readyz`'s `execution_tracker` row re-keys directly to
`execution_tracker_ && execution_tracker_->is_open()` (`server.cpp:13070`), and `/healthz` gains
a net-new `execution_tracker_ok` conjunct + stores-map entry (`server.cpp:12851-12912`) — the
SQLite era had no such row in `/healthz` at all.

**Schema** (Postgres schema `execution_tracker`, two tables, folding the SQLite-era v1+v2 ladder
— v2 added `plugin_result_status` — into one PG v1 DDL, four indexes):

```sql
CREATE TABLE executions (
    id                 TEXT    PRIMARY KEY,
    definition_id      TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'pending',
    scope_expression   TEXT    NOT NULL DEFAULT '',
    parameter_values   TEXT    NOT NULL DEFAULT '',
    dispatched_by      TEXT    NOT NULL DEFAULT '',
    dispatched_at      BIGINT  NOT NULL DEFAULT 0,
    agents_targeted    INTEGER NOT NULL DEFAULT 0,
    agents_responded   INTEGER NOT NULL DEFAULT 0,
    agents_success     INTEGER NOT NULL DEFAULT 0,
    agents_failure     INTEGER NOT NULL DEFAULT 0,
    completed_at       BIGINT  NOT NULL DEFAULT 0,
    parent_id          TEXT    NOT NULL DEFAULT '',
    rerun_of           TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE agent_exec_status (
    execution_id          TEXT    NOT NULL,
    agent_id              TEXT    NOT NULL,
    status                TEXT    NOT NULL DEFAULT 'pending',
    dispatched_at         BIGINT  NOT NULL DEFAULT 0,
    first_response_at     BIGINT  NOT NULL DEFAULT 0,
    completed_at          BIGINT  NOT NULL DEFAULT 0,
    exit_code             INTEGER NOT NULL DEFAULT 0,
    error_detail          TEXT    NOT NULL DEFAULT '',
    plugin_result_status   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (execution_id, agent_id)
);
CREATE INDEX idx_executions_status ON executions(status);
CREATE INDEX idx_agent_exec_agent ON agent_exec_status(agent_id);
CREATE INDEX idx_executions_dispatched ON executions(dispatched_at);
CREATE INDEX idx_executions_definition ON executions(definition_id);
```

**Correction (PR review, 2026-08-31, Doomgoose):** the block above was rewritten to match the
actually-shipped DDL byte-for-byte (`execution_tracker.cpp`'s `migrations()`) — the version
originally committed here misstated it five ways: (1) **no FK exists** —
`agent_exec_status.execution_id` carries no `REFERENCES executions(id) ON DELETE CASCADE`; a
deleted parent orphans its child rows, tolerated by design (this store never deletes executions,
and #3728's future retention pass must not silently assume cascade cleanup it does not have —
see that issue); (2) `agent_exec_status.status` defaults to `'pending'`, not `'dispatched'`; (3)
`agent_exec_status.dispatched_at BIGINT NOT NULL DEFAULT 0` exists and was omitted entirely; (4)
`plugin_result_status` is `INTEGER`, not `TEXT` — it stores the typed CC-07 plugin-result-status
enum value, never free text; (5) the four index names and their target columns were disjoint from
the real ones — no index on `parent_id` exists (`get_children`'s query is unindexed today), and
the real DDL indexes `status` and `agent_id` instead, which the original block omitted.

**`refresh_counts` closes the #1033-class race and gains the same one-transaction consistency
`advance_schedule` gained.** The SQLite era read `sqlite3_changes(db_)` immediately after a
terminal-transition `UPDATE` on the shared FULLMUTEX connection — a read that is not atomic with
the `step()` that produced it under concurrent callers on one connection (the exact hazard issue
#1033 tracks generally). The port (`execution_tracker.cpp:448-543`) wraps the aggregate recompute,
the conditional terminal-transition `UPDATE ... WHERE status='running' RETURNING 1`, and the SSE
payload snapshot in one `pool_.with_txn_for`; the terminal transition is detected via
`PQntuples(term.get()) > 0` on the `RETURNING` result instead of a separate changes-count call —
a per-lease Postgres connection with `RETURNING` has no such race to begin with. Both SSE
publishes (`execution-progress`, then `execution-completed` when terminal) run lease-free, after
the transaction commits and the connection is released — preserving
`docs/executions-history-ladder.md`'s `first_terminal_id` contract (the terminal-flagged progress
event precedes the real terminal event) exactly, which governance re-verifies independently of
this ADR's claim.

**The `recursive_mutex` is deleted, not narrowed or replaced.** It existed only because
`refresh_counts` re-entered the public `get_execution()` on the same thread while holding the
lock. The port instead introduces a lease-free private helper, `exec_by_id_at(PGconn*, const
std::string&)` (`execution_tracker.cpp:189`), that `get_execution`/`get_summary` call after
acquiring their own lease, and that `refresh_counts` calls directly with the transaction's
already-held connection — avoiding the documented `pg_pool.hpp` nesting-deadlock hazard of
acquiring a second lease from inside an already-held `with_txn_for` callback. With no method
calling another store method while holding a lock, no mutex of any kind is needed; `open_` is a
plain `bool`, not atomic (construction-then-read-only, matching every other store in this
ladder).

**Correction (governance adversarial review, 2026-08-31 — CHAOS-01):** the mutex-deletion
analysis above establishes there is no re-entrant DEADLOCK risk, but it did not address a
different failure mode the removal introduces. The pre-migration `recursive_mutex` blocked
UNBOUNDEDLY on contention — a caller queued behind another `refresh_counts` call for the same
execution could wait arbitrarily long, but the update could never simply be dropped. Postgres's
own per-connection `lock_timeout` (10s default, `pg::PgPool::Options`) bounds the equivalent wait
on this port's row-level lock instead: under high agent-fanout, enough concurrent
`refresh_counts` calls for the SAME execution can queue behind that row lock that a caller near
the back of the queue gets its statement cancelled by Postgres, and `update_agent_status`
(`execution_tracker.cpp:435`, pre-fix) discarded that failure silently — no log, no counter, no
retry. Because `refresh_counts` is the ONLY path that advances an execution past its
all-agents-responded threshold, a dropped call for the LAST reporting agent left the execution
wedged at `status='running'` forever, with stale aggregate counts and no `execution-completed`
SSE — a state-machine wedge (derived HIGH: I5 raise (c), E1/E2 — ordinary fleet-wide-dispatch
fanout, no attacker required), independently confirmed by governance's chaos-injector,
compliance-officer (a wedged execution is also an inaccurate Processing-Integrity evidentiary
record — `completed_at` never populates), and sre (no detection path exists today: no metric, no
log, no alert distinguishes a wedged execution from a healthy in-flight one; realistic
pool-exhaustion threshold under the same contention is "tens of concurrent same-execution
completions," not hundreds — see `server.cpp`'s default `pg_pool_` size of 16, shared
server-wide).

**Fix:** `refresh_counts` retries once on failure before giving up, and logs loudly
(`spdlog::error`) if the retry also fails, rather than dropping silently
(`execution_tracker.cpp`, `refresh_counts`/`refresh_counts_once`). The retry is not a no-op: by
the time the first attempt has waited out the full `lock_timeout`, the transaction(s) that were
holding the row have almost certainly long since committed or themselves timed out, so the retry
is very likely uncontended — proven empirically by a regression test
(`test_execution_tracker.cpp`, `"refresh_counts retries and recovers from transient row-lock
contention"`) that holds a real row lock from a second connection, verified to fail against the
pre-fix single-attempt code and pass against the fix. This closes the common case but is
explicitly a MITIGATION, not a complete fix: under sustained contention both attempts could still
fail — the residual is the SAME Processing-Integrity gap this section opened with (a wedged
execution's `completed_at`/aggregate counts stay wrong with no automatic correction), just lower
probability, now logged rather than silent. A periodic reconciler sweep (re-check any execution
stuck at `running` past N minutes, sre's Gate 6 preference over pure retry) would close the
residual risk completely but is a larger architectural change — out of scope for a
storage-backend migration, filed as #3729 rather than fixed here. Governance Gate 8 re-review
(2026-08-31) additionally found, independently by sre and unhappy-path, that the retry itself
roughly doubles a losing caller's worst-case connection-hold time under row-lock contention,
narrowing (not widening) the margin before pool exhaustion in the band where the pool still
grants leases but the contended row's lock queue is saturated — folded into #3729's design note
rather than reworked here, since the reconciler sweep resolves it structurally by not holding a
request-path connection across any lock wait at all.

**Why `update_agent_status` retries but `set_agents_targeted`/`mark_cancelled` only report failure
(scoped re-review, 2026-08-31, consistency-auditor point 7):** the two failure modes are not the
same shape. A dropped `update_agent_status` upsert means the `agent_exec_status` row was never
written at all — #3729's future reconciler recomputes FROM those rows, so a missing one has
nothing to reconcile from (the agent does not re-send), which is why that path gets the retry. A
dropped `set_agents_targeted`/`mark_cancelled` instead leaves the `executions` row visibly wedged
at `running` with a stale `agents_targeted`/`status` — exactly the state #3729's reconciler is
designed to find and correct, so reporting the failure (rather than retrying in place) is
sufficient there. **One gap in that reasoning found by the same re-review (security-guardian):**
of `set_agents_targeted`'s four call sites, only `schedule_runner.cpp`'s actually recovers
(marks the execution cancelled and audits the failure) — `workflow_routes.cpp`, `rest_api_v1.cpp`,
and `mcp_server.cpp` log and then still report the overall dispatch as a success. The audit row
stays truthful (dispatch genuinely reached N agents), but the execution row itself wedges with no
operator-visible signal beyond the log line — the same class of gap #3729 already exists to close.
Folded into #3729's scope rather than reworked here.

**`InstructionDbPool` deletion.** `instruction_db_pool.{hpp,cpp}` is deleted along with its
`server.cpp` member (`instr_db_pool_`), its dedicated construction block, and its teardown line
— verified beforehand by a repo-wide grep that `server.cpp` was its only consumer. The
`execution_event_bus_` construction, previously gated inside the pool's own `is_open()` check,
relocates into the new `if (pg_pool_ && !startup_failed_)` gate, still constructed before the
tracker (`server.cpp:5114`) — the `[BUS-BEFORE-TRACKER]` destruction-order invariant
(`server.cpp`) is preserved unchanged because `pg_pool_` already precedes the trio in member
declaration order, so no member reordering was needed to keep it correct.

**Consumers (unchanged public API, no signature churn):** gRPC `AgentServiceImpl` (every
`CommandResponse`), REST v1 (8 routes) + legacy REST, 5 MCP tools, the dashboard, `ScheduleRunner`
(borrowed pointer). Verified: no consumer constructs `ExecutionTracker` itself outside test code —
`server.cpp` is the sole production construction site.

**No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment):** no
`migrate_from_sqlite`, unconditionally. This is the point at which `instructions.db` stops being
written to by any Yuzu store. `ExecutionTracker`'s own `legacy_sqlite_probe::warn_if_legacy_rows()`
call (naming `executions`, `agent_exec_status`) lands in this commit, alongside the
already-landed ScheduleEngine (`schedules`) and ApprovalManager (`approvals`) calls from commits
1 and 2 — an operator upgrading straight from a pre-PR build to the finished PR sees up to three
separate warnings, one per component that still held rows, not one combined line.

**Test blast radius (15 files, ~380 cases) converted using two shapes, chosen per call site.**
Most sites hold a raw `sqlite3*` alone and convert to the self-contained
`yuzu::test::ExecutionTrackerPg` RAII bundle (`test_execution_tracker_pg_helper.hpp`, its own
`PgTestTemplate` key `exectracker`, its own `SKIP` guard). Sites that already share a `pg::PgPool`
with another store in the same fixture (e.g. `ResponseStore` in `test_mcp_server.cpp`'s
query-responses fanout tests) construct `ExecutionTracker` directly against that same pool
instead (schema-per-store on one database) rather than opening a second ephemeral database. The
one closed-store test (`ExecutionTracker(nullptr)` in the SQLite era) ports to the
`test_engine_principal_store.cpp` #2456 precedent: a `pg::PgPool` built against an unreachable
host (`connect_timeout_s=1`) fails the store's own connect attempt deterministically, no live
database required — the same technique already used for `ApprovalManager`'s closed-store test in
commit 2.

**One MCP-level SQLite technique ($2506 F2 real-tracker payload-contract test) had no schema
change to make** — it already drove `ExecutionTracker` as a black box through its public API, so
only its construction converts (to `ExecutionTrackerPg`); the payload assertions are unchanged.

## Considered and rejected

- **Migrating the three stores as separate PRs/ADRs instead of one cluster PR.** Rejected — they
  share `InstructionDbPool`, and the pool's deletion is only safe once all three have moved off it;
  splitting the PR would leave the pool half-consumed by a mix of SQLite and Postgres stores for an
  indeterminate stretch, and the pool itself has no independent value once even one consumer moves.
  Staged as 3 commits within one PR instead, so governance can still review each store's diff in
  isolation.
- **A single fixture template covering all three stores everywhere.** Rejected for test isolation
  — see the per-commit test sections; a fixture that always builds the full trio would fail an
  approval-only test on an unrelated `ScheduleEngine` schema break, and `PgTestTemplate`'s
  replay-fingerprint guard would reject a subset-setup sharing that key from a different call site.
  Per-store templates plus one composite template (for the handful of call sites needing 2-3 stores
  together) instead.
- **Porting v7's `origin='legacy'` back-fill as a Postgres migration step.** Rejected — on a fresh
  PG v1 schema there are no pre-existing `''`-origin rows for it to rewrite (the population it
  targeted was specifically pre-v5-column and pre-v7-migration SQLite rows), so the migration would
  be dead code from creation. The DECODE-side property it protected — an unrecognised stored
  `origin` value refuses redemption, never grants it — is unaffected and still pinned directly by
  `approval_origin_from_string`'s own tests.
- **Isolating the origin-check-specific chaos fault through the full MCP handler** (mirroring the
  SQLite-era countdown-authorizer test that faulted rung 2 only, letting rung 1's identical-SQL
  lookup through first). Rejected as infeasible under Postgres's pooled-connection model: a
  table-level lock (the technique that replaces it for the lookup-rung-only case) blocks the FIRST
  read to reach the table, which is rung 1's own lookup — it cannot selectively let one read
  through and fault only the next, the way SQLite's per-connection authorizer callback could.
  Faithfully isolating rung 2 alone (not rung 1) is preserved instead at the store level, directly
  against `consume_ticket`, where the origin-check read genuinely is the first and only read for
  that call.
- **`FOR UPDATE` on the `#2442` binding-check read.** Rejected — the fields it would protect
  (origin, submitted_by) are immutable after insert, and the CAS UPDATE already re-checks
  `status`/`consumed_at` atomically; a row lock would tax every consume call for a race that does
  not exist.

## Consequences

- **Any recurring-schedule state from a pre-Postgres build is lost on upgrade** (component 1 of
  3). The operator re-creates schedules via `POST /api/schedules`. Documented in
  `docs/user-manual/upgrading.md`.
- **`/readyz` and `/healthz` now report ScheduleEngine's availability** where it was previously
  invisible (the SQLite era had no availability flag for this store at all) — a monitoring-
  visibility improvement, not a new failure mode: a broken schedule store previously failed silently
  (the poller simply never fired anything), it now fails loudly at boot.
- **Any pending/approved/consumed approval-ticket evidence from a pre-Postgres build is lost on
  upgrade** (component 2 of 3). A pending MCP recall or REST instruction-approval outstanding at
  upgrade must be re-requested; consumed-ticket audit history (the `submitted_by → reviewed_by →
  consumed_by` evidence chain) does not carry forward. Documented in `docs/user-manual/upgrading.md`.
- **The MCP A4 error envelope's permanent-vs-transient discriminator is now a Postgres SQLSTATE
  string, not a SQLite extended errcode** — mostly an internal type change (the same two response
  bodies, chosen by the same two-discriminator rule), with one deliberate exception (PR review,
  2026-08-31, Doomgoose): the old classifier (`sqlite_error_class.hpp`, deleted) had no permanent
  case for schema drift — a dropped/altered `approvals` table surfaced as a generic SQLite error
  and was classified transient ("retry unchanged"). The new classifier's class-`42` case makes
  that same fault permanent, so it now fails fast with an escalate-to-operator response instead
  of an endless retry loop — an improvement, but a real client-visible change for that edge case.
- **Any execution history and per-agent status from a pre-Postgres build is lost on upgrade**
  (component 3 of 3). The executions drawer, REST execution routes, and MCP execution-status
  tools start from empty; no gRPC `CommandResponse` in flight at the moment of upgrade has
  anywhere to land until the operator's next dispatch. Documented in
  `docs/user-manual/upgrading.md`.
- **`instructions.db` is retired.** This is the point at which no Yuzu store — server or agent —
  writes to it; `InstructionDbPool` (its sole reader/writer abstraction) is deleted along with the
  file's last three consumers. The file itself is left on disk (never deleted) so the legacy-probe
  warning can still fire on an upgrade.
- **The #1033-class `sqlite3_changes()`-after-`step()` race is closed for this store** (tracked
  generally at issue #1033; this store's specific instance, in `refresh_counts`, is the ONLY
  `sqlite3_changes()` call site the whole three-store cluster carried). The sibling stores this
  ADR ports (`ScheduleEngine`, `ApprovalManager`) never had one.
- **`/healthz` gains an `execution_tracker` row it never had under the SQLite era** (availability
  was previously only visible through `/readyz`, itself keyed on the pool rather than the store) —
  a monitoring-visibility improvement, not a new failure mode.

## Follow-ups

- `execution_tracker.cpp`'s `#1033`-class shared-connection race is CLOSED by this PR (see
  component 3's `refresh_counts` section above) — recorded here, not as an open item.
- ADR-2002 (High Availability) forward-pointers, one per component: ExecutionTracker's
  `ExecutionEventBus` stays process-local (cross-replica SSE delivery is ADR-2002's concern);
  ApprovalManager's queue-cap/expiry-sweep check-then-act is process-local (multi-replica
  coordination is ADR-2002's concern); ScheduleEngine's `SELECT ... FOR UPDATE` (now a single
  atomic UPDATE, so this specific hazard is closed) still leaves concurrent *dispatch* of the same
  due schedule across replicas unaddressed — ADR-2002 already commits to a fenced-leader +
  transactional-outbox model for exactly this class of problem. All three are irrelevant on
  today's single-server design (`docs/adr/2002-high-availability-architecture.md`).
- **Not fixed here, filed as #3728:** unbounded growth of `executions`/`agent_exec_status`
  (`execution_tracker` schema) and `approvals` (`approval_manager` schema) — a retention pass is
  its own clock-guarded change (routed-concerns row 38's seven-part apparatus), out of scope for a
  storage-backend migration. **These are two different problems, not one** (governance
  compliance-officer, 2026-08-31): `executions`/`agent_exec_status` is ordinary operational
  history a routine retention pass can prune; `approvals` is SOC 2 CC7.2 audit evidence
  (`submitted_by → reviewed_by → consumed_by`) and, per the access-review campaign precedent
  (`docs/security-reviews/access-reviews-2026-07-21.md`), any future prune of it needs its own
  explicit, separately-reviewed compliance decision — never a side effect of whatever retention
  pass `executions` gets. `ConcurrencyManager` (test-only dead code, no `server.cpp` construction
  site) — noted, not deleted in this PR (scope discipline). Deleted in ADR-1007
  (2026-08-31), which also builds the real replacement for its one live-used mode.
- **Not fixed here, filed as #3727:** none of the three migrated stores has a
  `MetricsRegistry*`/`set_metrics()` wired, so runtime Postgres degrade paths (lease timeout,
  query failure) have no `yuzu_server_<store>_{read,write}_degrade_total{reason}` counter per
  `docs/postgres-store-playbook.md`'s mandate. Verified (governance sre, 2026-08-31) to be a
  program-wide gap — `PatchManager`/`DirectorySync`/`WorkflowEngine` (Wave 4 PRs 2-4) share it;
  only `UpdateRegistry` (PR 1) has it — so it is scoped as one cross-cutting fix, not three
  piecemeal ones. Noted on #3727 (sre): the approval-queue-full refusal path (`submit()`'s
  `queue_full_error`) is a business-logic rejection, not an infra degrade, so #3727 as scoped
  will not cover it — a `yuzu_approval_manager_pending` gauge or a distinct refusal-reason counter
  is a candidate for #3727's eventual fix to also close.
- **Read-degrade posture (governance cpp-expert, 2026-08-31):** runtime Postgres read failures
  (lease-acquire timeout, query error) in all three stores' query/list/count methods degrade to
  an empty result or zero, matching the pre-migration SQLite shape exactly — this is a deliberate
  posture choice for this migration (preserve existing caller-visible behavior), not an oversight,
  though it means these reads are NOT authoritative in the ADR-0012 §1 sense for callers that
  cannot distinguish "no data" from "store degraded." `ApprovalManager::get_checked` (added for
  #2786) is the one exception, returning `std::expected<std::optional<Approval>, StoreReadError>`
  because the MCP redemption path specifically cannot afford to burn a valid ticket on a
  transient store hiccup. Generalizing that shape to the other read methods is a larger,
  cross-store API change, not appropriate mid-migration — filed as #3730 rather than fixed here.
