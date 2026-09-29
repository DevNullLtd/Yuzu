# ADR-0064: WorkflowEngine → PostgreSQL

- **Status:** Accepted
- **Date:** 2026-08-30
- **Deciders:** pg workstream (7-remaining-stores plan, PR 4); FK/cascade semantics confirmed by
  the operator after an independent `/codex opine` review (Sol, `gpt-5.6-sol`), verified directly
  against `workflow_engine.cpp`/`workflow_routes.cpp`/`product_pack_store.cpp` before acceptance.
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009 (including its 2026-08-25
  fresh-start-by-default amendment), ADR-0012 (substrate/store contract), ADR-0058
  (`std::expected`-typed store-error convention this ADR follows for reads/delete);
  `docs/postgres-store-playbook.md`; `docs/postgres-migration-ladder.md` Wave 4;
  ADR-0061 (`UpdateRegistry`), ADR-0062 (`PatchManager`) — the two prior Wave-4 PRs whose
  `legacy_sqlite_probe.hpp` and `with_txn_for` idioms this migration reuses verbatim.

## Context

`WorkflowEngine` (`server/core/src/workflow_engine.{hpp,cpp}`) is the multi-step instruction
orchestration store behind `/api/workflows*` and `/api/workflow-executions/*`
(`workflow_routes.cpp`) — the fourth of the 7 production-wired non-`*Store` SQLite components the
migration ladder never gave its own row. It has its own SQLite file (`workflows.db`), four tables
(`workflows`, `workflow_steps`, `workflow_executions`, `workflow_step_results`), and **zero
existing tests** — `test_workflow_routes.cpp` covers only the `/fragments/executions` dashboard
surface via an opt-in `ExecHarness`-constructed `WorkflowEngine`, never the store's own methods.

Construction is unconditional and best-effort in the SQLite era: `server.cpp` never checks
`is_open()` before wiring the pointer, and while `/readyz`'s `StoreCheck` vector already names
`workflow_engine` (a monitoring-signal head start the other Wave-4 stores didn't have), `/healthz`
omits it entirely — the same readyz-vs-healthz drift class `PatchManager`/`RuntimeConfigStore`
closed on their own migrations.

`ProductPackStore` installs/uninstalls workflows as one of four supported `kind`s
(`install_fn`/`uninstall_fn` in `workflow_routes.cpp`), so this store's public method signatures
are a real cross-store contract, not just a REST-layer concern.

## Decision

### Schema

Postgres schema `workflow_engine` (extension of the ADR-0008 naming rule — the name already
passed to `MigrationRunner::run("workflow_engine", ...)` today), four tables:

```sql
CREATE TABLE workflows (
    id          TEXT   PRIMARY KEY,
    name        TEXT   NOT NULL,
    description TEXT   NOT NULL DEFAULT '',
    yaml_source TEXT   NOT NULL,
    created_at  BIGINT NOT NULL DEFAULT 0,
    updated_at  BIGINT NOT NULL DEFAULT 0,
    deleted_at  BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE workflow_steps (
    workflow_id          TEXT    NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    step_index           INTEGER NOT NULL,
    instruction_id       TEXT    NOT NULL,
    condition             TEXT    NOT NULL DEFAULT '',
    retry_count           INTEGER NOT NULL DEFAULT 0,
    retry_delay_seconds   INTEGER NOT NULL DEFAULT 5,
    foreach_source         TEXT    NOT NULL DEFAULT '',
    label                  TEXT    NOT NULL DEFAULT '',
    on_failure             TEXT    NOT NULL DEFAULT 'abort',
    PRIMARY KEY (workflow_id, step_index)
);
CREATE TABLE workflow_executions (
    id             TEXT    PRIMARY KEY,
    workflow_id    TEXT    NOT NULL REFERENCES workflows(id),
    status         TEXT    NOT NULL DEFAULT 'pending',
    agent_ids_json TEXT    NOT NULL DEFAULT '[]',
    started_at     BIGINT  NOT NULL DEFAULT 0,
    completed_at   BIGINT  NOT NULL DEFAULT 0,
    current_step   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE workflow_step_results (
    execution_id   TEXT    NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    step_index     INTEGER NOT NULL,
    instruction_id TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'pending',
    result_json    TEXT    NOT NULL DEFAULT '{}',
    started_at     BIGINT  NOT NULL DEFAULT 0,
    completed_at   BIGINT  NOT NULL DEFAULT 0,
    attempt        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (execution_id, step_index)
);
CREATE INDEX idx_wf_exec_workflow ON workflow_executions(workflow_id);
CREATE INDEX idx_workflows_deleted ON workflows(deleted_at) WHERE deleted_at = 0;
```

No separate index on `workflow_step_results(execution_id)` (governance finding, architect): the
`PRIMARY KEY (execution_id, step_index)` btree already serves an `execution_id`-only equality
lookup on its leading column — a dedicated index would be pure redundant write/storage cost.

One v1 migration, flattened from the SQLite-era single `IF NOT EXISTS` ladder. `completed_at` was
nullable `INTEGER` in SQLite (unset until terminal); it becomes `BIGINT NOT NULL DEFAULT 0` here,
matching the zero-sentinel convention every other migrated store on this ladder uses (`PatchManager`
`completed_at`, `DeploymentRunStore`, etc.) — no caller reads `completed_at` before checking
`status`, so the nullable-vs-zero distinction was never observable.

`yaml_source`/`agent_ids_json`/`result_json` stay `TEXT`, not `JSONB` — byte-for-byte round-trip
with the existing `nlohmann::json::parse(..., nullptr, false)` call sites, no query today needs to
filter/index into these blobs. JSONB is rejected-for-now, same reasoning as every prior Wave-4 PR.

### Delete semantics: soft-delete, not cascade

**This is a product decision, not a mechanical FK port**, flagged during planning: the SQLite
schema declares `workflow_executions.workflow_id` with NO FK at all (unlike `workflow_steps`/
`workflow_step_results`, which do declare — inertly, since the SQLite connection never sets
`PRAGMA foreign_keys=ON` — cascading FKs). A literal `ON DELETE CASCADE` port of that declared-but-
inert intent would newly **destroy** a workflow's execution history on delete; today, delete
"succeeds" and history survives, orphaned but queryable by execution id.

**Decision: `delete_workflow` soft-deletes** (`workflows.deleted_at` stamped to the current epoch
on first delete). `workflow_executions.workflow_id` keeps a real FK but with **no `ON DELETE`
clause** (Postgres default `NO ACTION`/`RESTRICT`) — defense-in-depth against any future hard-purge
tool dropping a `workflows` row while execution history for it still exists; ordinary
`delete_workflow` never issues a `DELETE` on `workflows` at all, so this FK is never exercised in
the code this ADR ships. `workflow_steps → workflows` and `workflow_step_results →
workflow_executions` keep `ON DELETE CASCADE` — both are purge-only paths (a workflow's step
*definitions*, an execution's step *results*), exercised only by a future explicit hard-purge, never
by `delete_workflow` itself.

Reasoning, verified directly against the code before acceptance (independent `/codex opine` review,
then cross-checked line-by-line):

1. **Active-execution race.** `execute()` loads the workflow once, then dispatches steps in a loop
   with the store's lock released across each dispatch call and its retry `sleep_for` (confirmed by
   direct read of pre-migration `workflow_engine.cpp:674-833` — no step of the loop re-acquires a
   lock spanning the whole method). A concurrent **cascading** delete during that window would
   destroy the running execution's own rows out from under it; `GET /api/workflow-executions/:id`
   would then 404 an execution the caller was just told is running. Soft-delete cannot do this — the
   workflow row and every execution row for it stay physically intact.
2. **Cross-store contract.** `ProductPackStore::uninstall`'s `uninstall_fn` Workflow arm
   (`workflow_routes.cpp` — see "Consumers" below) treats `delete_workflow`'s outcome as
   tolerated-not-found on failure (pre-existing bool-only convention, matching ADR-0058's
   `InstructionDefinition` arm before ITS migration). A "reject delete-with-history" option would
   need a new, distinct failure class threaded through that callback and REST layer for no
   corresponding win; soft-delete needs none — `delete_workflow` still succeeds exactly once per
   workflow, verified directly against `workflow_routes.cpp:2206-2208`.
3. **No cascade-everything precedent.** Checked directly: `BaselineStore`, `OffloadTargetStore`,
   `ProductPackStore`, `PatchManager`'s own migrations all either preserved an already-enforced
   SQLite cascade or cascaded purely-owned catalog rows (never execution/delivery *history*).
   `PatchManager`'s ADR-0062 explicitly notes its one new cascade (`patch_deployment_targets →
   patch_deployments`) closes a latent gap with **zero observed behavior change**, because nothing
   ever deletes a `patch_deployments` row — the opposite of this store, where `delete_workflow` is
   a real, reachable, tested-by-this-PR operation.
4. The fresh-start-by-default amendment (ADR-0009) is a one-time-cutover policy, not a general
   delete-policy precedent — it does not bear on this decision.

**Recorded semantics** (binding on this store going forward, not just this PR):

1. Delete means **logical retirement**, not historical erasure.
2. A soft-deleted workflow cannot start a new execution (enforced — see "New atomicity" below).
3. An execution admitted before deletion may finish and remain queryable; deletion never touches
   `workflow_executions`/`workflow_step_results` rows.
4. Any future **hard purge** (an explicit, retention-aware, separately-authorized-and-audited
   operation) is out of scope for this PR — deletes execution history first, `workflows` row last,
   consistent with the FK direction above. Not built here; tracked as a follow-up.
5. If workflow **definitions** ever become mutable in place (they are currently create-only — no
   `update_workflow` exists), a future change should snapshot each execution's effective definition
   rather than rely on the live `workflows` row, since soft-delete alone does not protect against a
   definition being silently edited out from under a completed execution's step labels/instruction
   ids. Not needed today (no mutation path exists); noted so a future author doesn't have to
   re-derive it.

`get_workflow`/`list_workflows` treat a soft-deleted workflow as **absent** (ordinary consumers,
including `execute()`'s own admission path, never see it) — no operator-facing "show deleted" path
exists or is added by this PR; it would be a new, separate feature.

### New atomicity

`create_workflow` (insert workflow row + `store_steps`' per-row insert loop) and `execute`'s
execution-creation step (insert execution row + pre-create every step's `pending` result row) were
**non-transactional** in the SQLite era — each statement/loop iteration was its own
`sqlite3_step()`, no `BEGIN`/`COMMIT` anywhere in either method. Both are wrapped in one
`pool_.with_txn_for(...)` each — new atomicity this port adds.

**Admission guard closes the load-then-insert race** (the same race the delete-semantics decision
above is protecting against, from the write side): `execute()`'s execution-row insert is not a bare
`INSERT` — it is `INSERT ... SELECT ... FROM workflow_engine.workflows w WHERE w.id = $workflow_id
AND w.deleted_at = 0 RETURNING id`, inside the same transaction as the step-result pre-creation.
Zero rows back means either the workflow never existed or was soft-deleted since `execute()`'s
earlier `get_workflow` read (used to load `steps` for the dispatch loop) — both map to the same
`"workflow not found: " + workflow_id"` error `execute()` already returns for a plain missing id, so
this closes the race with no new error class or REST-visible change.

`store_steps`'s pre-migration per-row silent skip-on-empty-`instruction_id` (a defense-in-depth
`continue` with a `spdlog::warn`, pre-migration `workflow_engine.cpp:479-482`) becomes txn-fatal:
inside `with_txn_for`, an empty `instruction_id` making it this far (already rejected earlier in
`create_workflow`'s own step-parsing loop — this is truly defense-in-depth, unreachable in practice)
now aborts the whole workflow-creation transaction rather than silently omitting one step from a
workflow that otherwise reports success — same disclosure `PatchManager`'s ADR made for
`deploy_patch`'s tightened all-or-nothing shape.

### Typed reads/delete (ADR-0058-style split, unlike `PatchManager`'s narrower posture)

Unlike `PatchManager` (which kept plain-container reads because every consumer is deny-or-benign),
this store widens every authoritative read/delete to distinguish a genuine DB/lease failure from
"successfully read, found nothing" — governing-rules requirement, and directly load-bearing here
because of the `ProductPackStore` cross-store contract (see "Delete semantics" point 2 above):

- `list_workflows`/`list_executions` → `std::expected<std::vector<T>, std::string>`
- `get_workflow`/`get_execution` → `std::expected<std::optional<T>, std::string>`
- `delete_workflow` → `std::expected<void, std::string>`
- `create_workflow`/`execute`/`cancel_execution` keep their pre-existing
  `std::expected<std::string, std::string>` / `std::expected<void, std::string>` shapes, now with a
  genuine DB failure tagged with the shared `kDbErrorPrefix` (`store_errors.hpp`) instead of being
  indistinguishable from a validation/business-rule 400.

`workflow_routes.cpp`'s 8 call sites (list/create/get/delete/execute's pre-check/execute
itself/get-execution/the two `ProductPackStore` callback arms) are updated to classify
`kDbErrorPrefix`-tagged errors as 503 (genericized via the shared `genericize_db_error()` — never
echoing a raw `PQerrorMessage()` fragment to a caller) and leave every other error/not-found path's
REST contract byte-identical to today, including `DELETE /api/workflows/:id`'s
`{"deleted": true|false}` body shape (`false` now covers both "never existed" and "already
deleted", same tolerant meaning the bool return had pre-migration).

**Child reads (adversarial-review finding, both reviewers independently, fixed):** the parent-row
reads above were widened, but `wf_load_steps()` (backing `list_workflows`/`get_workflow`) and
`get_execution()`'s step-results query initially kept the SQLite-era fail-soft shape — a genuine
`workflow_steps`/`workflow_step_results` query failure logged a warning and returned the parent row
with an empty/silently-incomplete child collection, rather than surfacing as a typed failure. This
broke the authoritative-read contract this section claims: a caller could not distinguish "this
workflow has no steps" from "the steps table could not be read", and `execute()` could
misreport a real DB outage as the business error `"workflow has no steps"` (400) instead of 503.
Fixed: `wf_load_steps()` now returns `std::expected<std::vector<WorkflowStep>, std::string>` and
`get_workflow`/`list_workflows` propagate its failure; `get_execution()`'s step-results block
returns `unexpected(kDbErrorPrefix + ...)` on a genuine query failure instead of returning the
execution row with empty `step_results`. Proven with two PG tests that drop the child table via a
second raw connection to force a real query failure (not a mock) and assert the typed failure.

**`ProductPackStore::install()` cross-store gap (adversarial-review finding, both reviewers
independently, fixed):** `ProductPackStore::install()`'s per-item error aggregation
(`errors.push_back(kind + ": " + result.error())`, then `"no items installed: " + errors[0]` on
total failure) prepends text ahead of any `install_fn` callback's error string — which strips the
`kDbErrorPrefix`/`kProductPackDbErrorPrefix` byte-0 marker `is_generic_db_error()` and
`product_pack_error_status()` rely on, turning a genuine `WorkflowEngine` DB failure during
`POST /api/product-packs` into a misclassified 400 instead of 503. In a multi-document bundle where
an earlier item already installed successfully, the loop would continue past the DB failure
entirely and the pack could persist with the failed item silently missing. **This bug pre-dates
this migration** (verified directly: `InstructionStore::insert_definition_row` already emits a
`kInstructionStoreDbErrorPrefix`-tagged error on genuine failure today, so the identical
prefix-stripping affects the `InstructionDefinition` install arm too) — but this migration is what
first makes it reachable for the `Workflow` kind, since the pre-migration SQLite `create_workflow`
never used the `db_error:` convention at all. Fixed in `ProductPackStore::install()` (not scoped to
Workflow — the fix is kind-agnostic): a callback failure whose error `is_generic_db_error()`
immediately aborts the whole install with a `kProductPackDbErrorPrefix`-tagged error, before
aggregating validation errors or persisting any partial pack — mirrors `uninstall()`'s already-
correct identical pattern (`product_pack_store.cpp:1357-1363`, `starts_with(kProductPackDbErrorPrefix)`
→ abort). Also tightened the Workflow install arm's null/unopen-engine message to carry the
`kProductPackDbErrorPrefix` tag (matching the `InstructionDefinition` arm), closing the same gap on
that path. Proven with a REST-level test that drops `workflow_engine.workflow_steps` to force a
genuine `create_workflow()` DB failure, then asserts `POST /api/product-packs` returns 503 (not
400) and persists no pack row.

### Write-outcome metrics

`yuzu_server_workflow_engine_writes_total{op,result}` (matching `PatchManager`'s convention)
counts `create_workflow`/`delete_workflow`/`execute`/`cancel_execution` outcomes. Two deliberate
scope decisions, made explicitly rather than left as unexamined defaults: (1) `execute()`
increments only on a **completed run** (`success`/`failed` at the very end of the step loop) —
an admission failure (workflow not found, or a genuine DB failure creating the execution row)
does NOT increment this counter, so it measures "runs that actually executed", not "every call to
`execute()`" (same posture PatchManager's `deploy_patch` takes toward its own pre-transaction
validation rejections — those don't touch the write-outcome counter either). (2) `delete_workflow`
increments only on a genuine DB failure or an actual delete — a `not_found` result (a bad id, or a
legitimate double-delete) is caller input, not a store-health signal, and does not increment
`result="failed"` (a bare "every non-success increments failed" rule would conflate the two).

### Mid-execution write degradation

The private per-step helpers (`create_step_result`/`update_step_result`) stay best-effort/
log-and-continue on a lease timeout, matching their pre-migration `void`-returning,
unchecked-`sqlite3_step()` shape. **Explicit decision, not an unexamined default:** a bounded-lease
timeout mid-`execute()` degrades to unrecorded step history for that one step rather than aborting
an in-flight, already-dispatched fleet operation — aborting a workflow whose steps may have already
run on real agents would be strictly worse than a gap in the recorded history of it. This mirrors
`execute()`'s own pre-migration failure posture (dispatch failures are recorded, not fatal to the
method) and is unchanged by this migration.

**The per-step cancellation-check read shares this posture too** (governance finding,
security-guardian + cpp-expert, independently): `execute()`'s loop calls `get_execution(exec_id)`
at the top of each iteration to detect a concurrent `cancel_execution()`; a lease timeout on that
read is treated identically to "not cancelled" and the loop keeps dispatching. This is the same
degrade-and-continue posture as the write helpers above, for the same reason — aborting an
in-flight fleet operation over a transient read failure would be strictly worse than one missed
cancellation check (the loop re-checks on the very next step).

**Both the mid-loop "running" update and finalize's status write are guarded** (governance findings,
cpp-expert + security-guardian + happy-path + sre + docs-writer across two review rounds): the
per-step `UPDATE ... SET status = 'running', current_step = $1` and the terminal
`UPDATE ... SET status = 'failed'/'completed'` both carry `WHERE status = 'running'`, so neither can
clobber a status a concurrent `cancel_execution()` already moved to `'cancelled'` — mirroring
`cancel_execution()`'s own atomic transition from the other direction. Pre-migration, the
`std::unique_lock mtx_` serialized cancel against every one of `execute()`'s writes, so whichever ran
last silently won; that "last writer wins" characteristic was already present, just achieved by
serialization rather than a missing guard. The Postgres port removes the serialization, so each write
site needs its own compare-and-guard to keep the same never-overwrite-a-terminal-cancel property (the
shared `update_execution_status` helper that predated this fix was deleted once both call sites carried
their own inline guard — nothing else called it). Finalize additionally uses `RETURNING status` to
confirm what was actually written: if the guard matched zero rows (a concurrent cancel already claimed
it) or a lease timeout dropped the write, `execute()` reads back the execution's real status via
`get_execution()` before reporting the write-outcome metric and log line, rather than trusting the
in-process `execution_failed` bool — which would otherwise misreport a dropped write as success. The
LOG line distinguishes a genuine cancellation from an ordinary failure this way; the metric still
buckets both under `result="failed"` (unchanged two-value cardinality — see "Write-outcome metrics"
above).

The mid-loop write goes one step further than finalize's: it also uses `RETURNING id` to make its own
CAS **observable to the loop itself**, not just to a post-hoc metric. A confirmed zero-row result (the
guard ran and matched nothing — status was no longer `'running'`) stops the loop immediately, so a
cancel landing between the top-of-iteration cancellation check and this write can't let one extra step
dispatch to the fleet before the loop notices. This is deliberately narrower than the write-degradation
posture above: a **lease timeout or query failure** on this write is NOT treated as a CAS mismatch —
only a write that actually ran and matched zero rows is definite evidence of a concurrent cancel;
degrading an ambiguous transient failure into "stop the whole execution" would trade one missed edge
case for a strictly worse one (aborting an in-flight fleet operation on a passing connection-pool
hiccup). Currently unreachable in production — `cancel_execution()` has no REST/MCP caller today
(verified: grepped the whole tree) — but closes the gap correctly ahead of that
route eventually being wired, rather than leaving a latent trap.

### Lease discipline — the retry-loop hazard

`execute()`'s per-step retry loop calls `std::this_thread::sleep_for(retry_delay_seconds)`
(pre-migration `workflow_engine.cpp:767`) on the REST worker thread. Verified directly: every DB
touch point in `execute()`'s loop (`update_execution_status`, `create_step_result`,
`update_step_result`, the attempt-count `UPDATE`) already acquires and releases its own lease
per-statement in the pre-migration code — the sleep and the `dispatch_fn`/`step_dispatch_` call are
never inside a locked/leased scope. The port preserves this shape exactly: no method acquires a
lease that spans a `sleep_for` or a dispatch call. The hazard this note exists to flag is a future
regression (someone "simplifying" per-statement leases into one held-across-the-loop lease), not a
defect being fixed here.

**Follow-up, not fixed here:** the blocking `sleep_for` itself — a worker thread parked for up to
`retry_delay_seconds` (clamped 0-3600) per retry — is a separate, pre-existing scalability concern
independent of storage backend. Tracked as a follow-up issue, out of scope for this migration.

### `cancel_execution` atomicity (adversarial-review finding, both reviewers independently, fixed)

The pre-migration SQLite `cancel_execution` held `std::unique_lock lock(mtx_)` across a
SELECT-then-UPDATE pair, so the read-check-write was serialized in-process. The initial Postgres
port preserved the two-statement shape but dropped the mutex, opening a real race: a concurrent
`execute()` finalizing the same execution to `completed`/`failed` between `cancel_execution`'s
SELECT and its follow-up UPDATE would still be overwritten to `cancelled` by the unconditional
`UPDATE ... WHERE id = $n`. Fixed: the transition is now one atomic statement —
`UPDATE workflow_engine.workflow_executions SET status = 'cancelled', completed_at = $1 WHERE id =
$2 AND status IN ('pending', 'running') RETURNING id` — with a follow-up read only when it matches
zero rows, purely to shape the not-found-vs-already-terminal message (not to drive control flow).
This also closes a related gap: the UPDATE's own failure is now propagated as
`unexpected(kDbErrorPrefix + ...)` instead of being silently logged while `cancel_execution`
reports success.

### Posture (ADR-0012 §1)

**Fail-CLOSED construction** — a posture upgrade from the SQLite era (unconditional/best-effort,
no `startup_failed_` gate). `mtx_` (the `std::shared_mutex` serializing every method) is removed
entirely — Postgres row semantics + the connection pool's per-operation checkout replace it, same
as every other store on this ladder that drops its app-level mutex.

### No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment)

No `migrate_from_sqlite`. The legacy `workflows.db` is never read for data; `server.cpp` calls the
shared `legacy_sqlite_probe::warn_if_legacy_rows()` (ADR-0061/0062's canonical helper, reused
verbatim — no third copy) over the legacy file's four tables after a successful open. Construction
logs `WorkflowEngine initialized (schema workflow_engine) — fresh start, no legacy backfill`.

### Consumers

`workflow_routes.cpp` — `/api/workflows*`, `/api/workflow-executions/:id` (no MCP, no gRPC). Also
`ProductPackStore`'s `install_fn`/`uninstall_fn` (Workflow arm) — `install_fn` needed no signature
change (`create_workflow` keeps its shape); `uninstall_fn`'s Workflow arm is updated to mirror the
`InstructionDefinition` arm exactly (`kProductPackDbErrorPrefix`-tagged unavailability vs. a
pass-through `not_found:`-tagged `delete_workflow` failure), closing the same
degrade-treated-as-tolerated-not-found gap that arm's own comment already flags as a solved problem
for every OTHER bool-only origin store once it migrates.

`workflow_engine_` is now constructed inside `if (pg_pool_ && !startup_failed_)`; `/readyz` already
named it (no change needed there beyond the type staying `is_open()`-checkable); `/health` gains a
`workflow_engine` entry in both the `all_stores_ok` conjunction and the `stores` detail JSON — it was
in neither in the SQLite era (the same readyz-vs-healthz drift class `PatchManager`/
`RuntimeConfigStore` closed on their own migrations).

## Considered and rejected

- **Reject delete-with-history** (`delete_workflow` fails if any execution exists). Rejected —
  breaks the `ProductPackStore` uninstall contract (a workflow that ever ran becomes permanently
  un-uninstallable via the pack surface, with no purge operation to unblock it), and introduces a
  new REST precondition-failure class for a behavior change smaller than the soft-delete
  alternative already covers.
- **Cascade-delete history** (literal `ON DELETE CASCADE` port). Rejected — the active-execution
  race above; also a genuine, undocumented-as-such behavior change (today's orphaning at least
  *preserves* the rows).
- **Nullable/snapshot FK** (`ON DELETE SET NULL` or a denormalized snapshot column on execution
  rows). Rejected in favor of soft-delete: `SET NULL` still requires a physical `DELETE` on
  `workflows` (re-introducing the active-execution race at delete time, just without also losing
  history), and a snapshot column duplicates data the `workflows` row already holds for no
  behavioral gain once the row itself is preserved.
- **Keeping `delete_workflow`'s bare `bool` return.** Rejected — matches ADR-0058's precedent for
  every other bool-only origin store (`InstructionStore::delete_definition` before its own
  migration); the `ProductPackStore` cross-store contract makes the degrade-vs-not-found
  distinction load-bearing here, not cosmetic.
- **Widening `create_workflow`'s per-step validation into a business-rule/DB-error split beyond
  what's needed.** Rejected — `create_workflow`'s failure modes are already fully validation
  (malformed YAML, missing fields) except for the transaction itself, which is exactly where the
  new `kDbErrorPrefix` tagging applies; no further widening had a concrete consumer.
- **Batching `list_workflows`' per-workflow step load into one `WHERE workflow_id = ANY($1)` query**
  (adversarial-review finding, both reviewers, LOW/judgment). Deferred, not fixed — this is a
  faithful port of the pre-migration SQLite shape (N+1 there too), the route is admin-facing with a
  100-row default limit (not a heartbeat hot path), and it is a performance concern with no
  contract/ADR anchor, unlike the two HIGH findings above. Left as a follow-up rather than folded
  into this PR.

## Consequences

- **Any workflow definition or execution history recorded against a pre-Postgres build is lost on
  upgrade** — workflows must be re-created via `POST /api/workflows`. Documented in
  `docs/user-manual/upgrading.md`, same treatment as every other fresh-start cutover on this
  ladder.
- **Deleted workflows never physically shrink the table** — soft-delete has no expiry/prune pass
  (deliberately out of scope; a future hard-purge tool is the follow-up). An operator who deletes
  many workflows over time accumulates `deleted_at != 0` rows indefinitely; this is a known,
  accepted tradeoff for preserving execution history, not an oversight.
- **`workflow_engine` joins `/health`'s conjunction** — a degraded Postgres pool now visibly fails
  `/api/workflows*`/`/api/workflow-executions/*` on both probes instead of only `/readyz`.
- **`DELETE /api/workflows/:id`'s REST contract is unchanged** (`{"deleted": bool}`, 200) despite
  the internal type widening — a genuine store-unavailable condition now correctly 503s instead of
  silently reporting `{"deleted": false}` as if the workflow simply didn't exist.

## Follow-ups

- The blocking `std::this_thread::sleep_for` retry loop in `execute()` (worker-thread-per-retry
  scalability concern, independent of storage backend) — file a tracking issue alongside this PR.
- A hard-purge operation for soft-deleted workflows (explicit, retention-aware, separately
  authorized and audited) — not built in this PR; tracked as future work per "Delete semantics"
  point 4 above.
- Immutable execution-time workflow-definition snapshotting, if/when `WorkflowEngine` grows an
  `update_workflow` mutation path (none exists today) — per "Delete semantics" point 5 above.
