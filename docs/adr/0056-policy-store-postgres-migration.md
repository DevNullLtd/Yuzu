# ADR-0056: PolicyStore → PostgreSQL (Wave 2, batch 6)

- **Status:** Accepted
- **Date:** 2026-08-20
- **Deciders:** pg workstream (kickoff `.claude/plans/pg-migrate-policy-store-KICKOFF.md`); the
  multi-replica evaluator design below is the "genuinely new PG problem" the kickoff assigned this
  ADR to settle.
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, ADR-0036 (typed reads).
  Closest posture precedent: `RbacStore`/`TagStore`/`CustomPropertiesStore` (authoritative,
  dispatch/compliance-feeding reads must be degrade-distinguishable). Closest backfill-shape
  precedent: `SoftwareDeploymentStore`/ADR-0051 (multi-table-with-FKs, single fingerprint over all
  tables, IDENTITY/LIFECYCLE partition). Advisory-lease precedent: `AuditStore`/ADR-0040 (single
  reap sweeper) and `AnalyticsEventStore`/ADR-0049 (3-phase CLAIM/SEND/REVERT when a lease can't
  span external I/O) — this store needs a third variant, below.

> **Status note (2026-08-25):** the legacy-SQLite backfill this ADR specifies below (`migrate_from_sqlite`,
> "Backfill (ADR-0009)") was retired the same day this ADR's PR merged, before any release shipped it —
> no production fleet ever ran a pre-Postgres build of this store, so there was no real `policies.db` data
> to protect. See `docs/postgres-migration-ladder.md`'s `PolicyStore` row and commit `f46cefe8e`. The body
> below is preserved UNEDITED as the historical record of the original design; do not treat its "MANDATORY
> backfill" language as describing current code. See ADR-0009's amendment for the fresh-start-by-default
> policy this retirement follows.

## Context

`PolicyStore` (`server/core/src/policy_store.{hpp,cpp}`, ~190+1308 lines) is the compliance
engine's definition + status store: **six tables** — `policy_fragments` (a check/fix/postCheck
instruction bundle + CEL compliance expressions, authored as `PolicyFragment` YAML),
`policies` (binds a fragment to a scope, authored as `Policy` YAML), `policy_inputs`,
`policy_triggers`, `policy_groups` (fan-out detail tables for a policy, `ON DELETE CASCADE`), and
`policy_status` (one row per `(policy_id, agent_id)`, the evaluator's only write target).

**A load-bearing fact this migration's design leans on**: `policy_fragments` and `policies` (and
their three detail tables) have **no update path** — `store_inputs`/`store_triggers`/
`store_groups` are called exactly once, from `create_policy`. Only `policies.enabled`/
`updated_at` (via `enable_policy`/`disable_policy`) and the entire `policy_status` table mutate
after creation. This makes the backfill IDENTITY/LIFECYCLE partition unusually clean (see
Backfill below).

`PolicyEvaluator` (`policy_evaluator.{hpp,cpp}`) drives check→verdict→status on a background
thread: `tick()` = `collect_ready()` then `dispatch_due()`, cadence 10s (`server.cpp:15825`,
`for (2) sleep(5s)`), grace 15s (`Deps::grace_seconds`), an operator-interval floor of 60s
(`dispatch_due()`, `policy_evaluator.cpp:340`), default interval 3600s
(`Deps::default_interval_seconds`). `polchk-*` execution ids are minted by the evaluator and
skipped by `notify_exec_tracker` (unchanged by this migration).

### The multi-replica problem, precisely

On SQLite there is exactly one server process, so exactly one `PolicyEvaluator`. Moving
`PolicyStore`'s *data* onto a shared Postgres substrate does not, by itself, make N server
replicas' evaluators safe to run concurrently, because **`PolicyEvaluator`'s dispatch/collect
coordination state is entirely in-process memory, not in `PolicyStore` at all**:

- `last_eval_` (an `unordered_map<policy_id, int64_t>`) is the *sole* due-ness source —
  `dispatch_due()` reads and claims it under `mu_`, then dispatches lock-free. Nothing durable
  records "when was this policy last dispatched."
- `in_flight_` (a `vector<InFlight>`) is the *sole* record of "a check/fix was dispatched and is
  awaiting a response." `collect_ready()` only ever looks at this replica's own `in_flight_`.
- The constructor unconditionally resets every `policy_status` row with `status == "fixing"` to
  `"unknown"` on every construction (`policy_evaluator.cpp:206-232`, comment "gov REC-1/UP-4") —
  a boot-time-only reconciliation for the single-process case ("a restart stranded this").

Ported unmodified onto N replicas, three failures follow: (1) each replica's `last_eval_` is
independent, so N replicas each conclude a policy is due at the same tick → N× dispatch of the
same check to the same agents (the kickoff's "N× dispatch of `polchk-*` checks"). (2) Whichever
replica dispatches is the *only* replica whose `in_flight_` holds that check — if a different
replica later wins any per-tick coordination, or the dispatching replica restarts, that check's
response sits in `response_store` forever uncollected: the policy's compliance for those agents
never resolves. (3) A replica restarting (a normal rolling-deploy event, not a crash) would stomp
**every** `fixing` row fleet-wide, including ones another replica is legitimately mid-remediation
on — turning a routine deploy into spurious remediation resets.

### Design considered and rejected: session-scoped leader election

A single long-held `pg_advisory_lock` (session-scoped, not `_xact_`) electing one replica as "the"
evaluator for its entire process lifetime would preserve `in_flight_`'s validity (the same process
stays leader across many ticks). Rejected: it is a new locking primitive with no precedent in this
codebase (all 6 existing `pg_try_advisory_xact_lock` call sites are transaction-scoped, stateless,
one-shot sweeps); it needs a dedicated connection held outside the bounded-lease pool with its own
liveness/split-brain handling to build and test from scratch; and it does not even fully solve the
stranded-`in_flight_` problem — a rolling deploy still kills the leader eventually, and whatever
replica wins next still starts with an empty `in_flight_`, orphaning anything the old leader had
outstanding. Also rejected: promoting `in_flight_` itself to a durable table (a new "dispatch
ledger" tracking every outstanding check). That does fully solve the problem, but in-flight state
is inherently re-derivable — losing it costs one interval's delay on the affected agents' verdicts
(a window the system already tolerates via the crash-recovery path), so building and testing a
durable ledger is scope this migration (already the largest store in the wave) does not need.

## Decision

**Split the fix by phase, matching the two things that actually differ**: dispatch decisions need
fleet-wide dedup (single-sweeper lease, now durable in `PolicyStore`); collect/verdict-write stays
per-replica and at-least-once, made safe by `update_agent_status`'s existing UPSERT idempotency.

### Schema: `policy_store`, seven tables

The original six, migrated as-is (see per-table notes below), plus one new **operational, non-
backfilled** table:

```sql
CREATE TABLE policy_fragments (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    yaml_source            TEXT NOT NULL,
    check_instruction      TEXT,
    check_compliance       TEXT,
    check_parameters       TEXT NOT NULL DEFAULT '{}',
    fix_instruction        TEXT,
    fix_parameters         TEXT NOT NULL DEFAULT '{}',
    post_check_instruction TEXT,
    post_check_compliance  TEXT,
    post_check_parameters  TEXT NOT NULL DEFAULT '{}',
    created_at             BIGINT NOT NULL DEFAULT 0,
    updated_at             BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE policies (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    yaml_source      TEXT NOT NULL,
    fragment_id      TEXT NOT NULL REFERENCES policy_fragments(id),
    scope_expression TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       BIGINT NOT NULL DEFAULT 0,
    updated_at       BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE policy_inputs (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (policy_id, key)
);

CREATE TABLE policy_triggers (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    trigger_type TEXT NOT NULL,
    config_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE policy_groups (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL,
    PRIMARY KEY (policy_id, group_id)
);

CREATE TABLE policy_status (
    policy_id         TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'unknown',
    last_check_at     BIGINT NOT NULL DEFAULT 0,
    last_fix_at       BIGINT NOT NULL DEFAULT 0,
    check_result      TEXT NOT NULL DEFAULT '',
    fix_attempt_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_id, agent_id)
);
CREATE INDEX policy_status_status_idx ON policy_status (status);

-- Operational only — NOT backfilled, NOT operator intent (see Backfill).
CREATE TABLE policy_dispatch_state (
    policy_id          TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,
    last_dispatched_at BIGINT NOT NULL DEFAULT 0
);
```

Changes from the SQLite v1+ALTER original, each deliberate:

1. **The ALTER-wart (`fix_attempt_count`, G4-UHP-POL-003) folds straight into `policy_status`'s
   v1 `CREATE TABLE`** — PG v1 ≡ SQLite v1+ALTER. There is no PG-side equivalent of the wart
   (a fresh PG schema has no pre-v0.10 legacy state to reconcile), but the **backfill** must still
   tolerate a legacy SQLite file predating the wart (missing the column) — see Backfill.
2. **`policy_status` gains a real FK + `ON DELETE CASCADE` to `policies`** (it had none in
   SQLite — the only one of the five detail/status tables without one; `delete_policy` cleaned it
   up with a hand-written `DELETE` whose prepare/step failure was silently swallowed). The FK
   makes that cleanup declarative and unconditional; `delete_policy`'s manual second delete is
   removed.
3. **`policies.enabled`**: `INTEGER` (SQLite bool-as-int) → `BOOLEAN` (the C++ field is already
   `bool`).
4. **`policy_triggers.id`**: `AUTOINCREMENT` → `GENERATED ALWAYS AS IDENTITY` (nothing external
   references this id; safe to remap, same as `LicenseStore::license_alerts.id`).
5. **`policy_dispatch_state` is new** — see Decision below.

### Posture (ADR-0012 §1) — split by table class, not one blanket rule

- **`policy_fragments`/`policies`/`policy_inputs`/`policy_triggers`/`policy_groups`
  (operator-authored intent): AUTHORITATIVE/fail-hard.** Every mutator already returns
  `std::expected` in the SQLite original and keeps that discipline; a DB error surfaces, never a
  silent no-op. `query_fragments`/`get_fragment`/`query_policies`/`get_policy` (currently
  empty/`nullopt`-on-prepare-failure, indistinguishable from "not found") become
  degrade-distinguishable per ADR-0036: **`PolicyEvaluator::dispatch_due()`'s claim path is the
  concrete grant/skip decision these reads feed** — a degraded read must not silently resolve to
  "no policies exist," which would read as "fleet compliant" on the dashboard. REST/dashboard
  reads (`ComplianceRoutes`) 503 on a degraded read rather than rendering an empty policy list
  (matches `DiscoveryStore`/`CustomPropertiesStore`'s "an operator asking must not be told
  'nothing' when the real answer is 'could not ask'").
- **`policy_status` (evaluator-written verdicts): AUTHORITATIVE for the write path** (an
  evaluator tick that cannot write a verdict must not silently succeed — `update_agent_status`
  keeps its `std::expected` and the evaluator now logs+counts every failure, closing the
  ~11-call-site swallow inventory below), **degrade-distinguishable for reads that feed
  `get_fleet_compliance`/`get_compliance_summary`** (an operator-visible compliance percentage
  computed from a degraded read must not silently render as if every unscored agent were simply
  absent from the denominator).
- **`policy_dispatch_state` (this migration's new operational table): fail-soft, entirely
  internal.** Never read or written by anything outside `PolicyStore::claim_due_policies` (below);
  no external caller, no REST surface, no backfill obligation.

### Backfill (ADR-0009) — MANDATORY for five tables, EXCLUDED for the sixth and the new seventh

ADR-0009's own Context paragraph names "policies" explicitly as irreducible operator intent.
`policy_fragments`/`policies`/`policy_inputs`/`policy_triggers`/`policy_groups`: **mandatory**,
using the `SoftwareDeploymentStore`/ADR-0051 shape (closest sibling: multi-table with internal
FKs) — one SHA-256 fingerprint over all five tables' canonicalized+sorted rows
(`sqlite_backfill_source`), holder-side verification against a possibly-fleet-wide-stamped
sourceless marker (the `RbacStore`/post-#2703 shape every table-fingerprinted store in this wave
uses), `RETURNING id` + `PQntuples()==1` per-row landed-verification. The legacy-file-predates-
the-ALTER-wart case is handled by reading `fix_attempt_count` with a column-existence check
(`PRAGMA table_info`) before the backfill SELECT on `policy_status`, defaulting missing values to
`0` — the same value the wart's `ADD COLUMN ... DEFAULT 0` would have produced.

**`policy_status` — copied, not fresh-started.** The kickoff left this open; the default
evaluation interval is 3600s, so a fresh-empty status table is not a "brief all-unknown window" —
it is up to an hour of an operator-visible dashboard reporting 0% or "unknown" fleet compliance
immediately after an upgrade, for policies that were fully scored five minutes before. Copied with
a direction-aware LIFECYCLE merge (status/last_check_at/last_fix_at/check_result/
fix_attempt_count): Postgres-ahead-or-tied-by-`last_check_at` is a benign no-op (only possible on
an idempotent backfill re-run after PG has already accumulated fresh evaluator writes — at the
actual cutover boot PG starts empty, so this is always a straight copy then); legacy-ahead fails
closed the same as `DeploymentStore`'s IDENTITY mismatch handling.

**`policy_dispatch_state`: excluded from backfill entirely, by design.** It is pure claim-tracking
state, invented by this migration — there is no legacy value to carry forward. Starting empty
means every policy looks immediately due on the first post-cutover tick, which is the same
"re-evaluate everything once, promptly" behavior the SQLite original already had on every process
restart (nothing in the original throttled across a restart either — `last_eval_` was a fresh
in-memory map every boot).

### Secrets — none found; flagged for a security-guardian read-time-redaction pass

`policy_fragments.yaml_source`/`check_parameters`/`fix_parameters`/`post_check_parameters` and
`policy_inputs.value` are free-form operator-authored text (up to 1 MiB) with no schema
constraint distinguishing a secret from any other parameter — an operator *could* paste a
credential into a policy's `inputs:` block. Nothing in the current code treats these fields as
secret-bearing, and no `SecretCodec`/hash is applied. Not fixed here (no evidence of the pattern
`AuditStore`'s ADR-0040 found and fixed for `detail` — this is a "nothing observed" finding, not
a "found and declined" one); flagged as a follow-up for a `security-guardian` pass on whether
`policy_inputs`/`policy_fragments` need read-time redaction akin to `AuditStore::sanitized_detail`.

### The headline decision: dispatch is single-sweeper and durable; collect stays per-replica and idempotent

**CLAIM (new `PolicyStore::claim_due_policies`, one Postgres transaction, DB-only — no external
I/O, so the AuditStore/ResultSetStore single-phase lease pattern applies directly, not
AnalyticsEventStore's 3-phase split):**

```cpp
std::expected<std::vector<Policy>, std::string>
PolicyStore::claim_due_policies(int64_t now, int64_t default_interval_seconds,
                                int64_t fixing_stale_seconds);
```

1. `pg_try_advisory_xact_lock(hashtextextended('policy_store:dispatch', 0))`. Not acquired →
   `return {}` (empty, `Ok` — another replica is claiming this tick; this is the normal skip, not
   a degrade, matching every other lease call site in the codebase).
2. Acquired, same transaction:
   a. **Stranded-`fixing` staleness sweep** (replaces the evaluator constructor's unconditional
      reset — see "Design considered and rejected" and Consequences): `UPDATE policy_status SET
      status = 'unknown' WHERE status = 'fixing' AND last_fix_at < $now - $fixing_stale_seconds`.
      Runs every winning tick, not just at boot — strictly better coverage (catches a stranded fix
      whenever it happens, not just at the next restart) and, being durably last-write-time-gated
      rather than "every row, unconditionally, on construction," no longer stomps a fixing row
      that belongs to another replica's still-live remediation.
   b. **Due-policy claim**: for every enabled policy, compute
      `interval = max(60, interval_for(triggers, default_interval_seconds))` — `interval_for`'s
      trigger-parsing logic moves from `policy_evaluator.cpp`'s anonymous namespace into
      `policy_store.cpp` (nothing outside `claim_due_policies` needs it once due-ness is fully
      internal to the store) — then `UPSERT policy_dispatch_state (policy_id, last_dispatched_at)
      VALUES ($id, $now) ON CONFLICT (policy_id) DO UPDATE SET last_dispatched_at = $now WHERE
      policy_dispatch_state.last_dispatched_at <= $now - $interval RETURNING policy_id`. The
      `WHERE` on the conflict branch is the atomic check-and-claim: a policy not yet due simply
      doesn't appear in the `RETURNING` set, no separate pre-read needed.
3. Commit (releases the lock). Return the claimed policies (loaded via the same query path
   `query_policies`/`load_policy_details` already uses, inside the same transaction, so the
   caller gets full `Policy` objects — no second round trip).

**SEND**, unchanged from today, no lease held: `PolicyEvaluator::dispatch_due()` becomes

```cpp
void PolicyEvaluator::dispatch_due() {
    if (!d_.policy_store) return;
    auto claimed = d_.policy_store->claim_due_policies(now(), d_.default_interval_seconds,
                                                        d_.fixing_stale_seconds);
    if (!claimed) {
        spdlog::warn("policy_evaluator: claim_due_policies degraded: {}", claimed.error());
        return; // ADR-0036: degraded ≠ zero due — skip the tick, retry next tick, never dispatch
    }
    for (const auto& p : *claimed)
        kickoff_check(p); // unchanged: resolve targets, dispatch, record in-flight
}
```

`last_eval_` is deleted entirely (superseded by the durable claim). `Deps` gains
`fixing_stale_seconds{1800}` (30 min default — long enough that a real, slow fix instruction
(e.g. a `content_dist` software install, which can genuinely run minutes) is not false-positive
reset mid-flight; short enough that a truly stranded fix does not sit invisible indefinitely).

**COLLECT stays exactly where it is: per-replica, in-memory `in_flight_`, unconditional every
tick, no lease.** Only the replica that dispatched a check ever has an `in_flight_` entry for it,
so only that replica ever collects it — there is nothing to coordinate. `update_agent_status`'s
`ON CONFLICT ... DO UPDATE` UPSERT is naturally idempotent: a manual operator `remediate()`/
`evaluate_now()` call on one replica racing an automatic tick's collect on another can both write
a verdict for the same `(policy_id, agent_id)` with no corruption — last-write-wins, and since
both derive the verdict from the same underlying `response_store` data, they agree. This is the
"at-least-once with idempotent status writes" half of the kickoff's two named options, scoped
narrowly to the one path (manual operator actions) that still has no durable coordination — an
accepted, bounded residual, not a compromise on the dispatch-dedup guarantee above.

**`update_agent_status`'s retry-cap check folds into the UPSERT itself**, closing a TOCTOU the
SQLite original only avoided by accident (a single process-wide `mtx_` serializing all calls —
gone once calls arrive from a pooled connection across replicas): the separate pre-check
`SELECT fix_attempt_count ...` is removed; the cap decision (`fixing` requested but
`fix_attempt_count >= 3` → force `error` instead) is expressed inside the `ON CONFLICT DO UPDATE
SET` clause, reading `policy_status.fix_attempt_count` (the row's pre-update value, which Postgres
resolves under the conflicting row's lock — concurrent UPSERTs on the same key serialize, so the
second one's CASE sees the first one's already-committed count, never a stale pre-fetched value).

**Correction (found running the multi-instance regression test, 2026-08-20):** two gaps in the
first cut of `update_agent_status`/`evaluate_now`, both caught before merge, neither visible from
reading the SQL — only from running the actual claim/staleness-sweep sequence against live
Postgres.

1. **`last_fix_at` on the fresh-INSERT branch was a bare `0`**, ported unchanged from the SQLite
   original (`VALUES (?, ?, ?, ?, 0, ?, 0)`) — harmless there, because the old stranded-`fixing`
   reset was unconditional and never read `last_fix_at` to decide anything. It is not harmless
   here: `claim_due_policies`'s staleness sweep is the first consumer that relies on `last_fix_at`
   meaning "when did this row last become `fixing`." A `fixing` status landing as the very
   first-ever write for a `(policy_id, agent_id)` pair — reachable via `remediate()` naming an
   agent never checked before — got `last_fix_at = 0`, which the very next staleness sweep read as
   infinitely stale and immediately reset to `unknown`, before the FixWait's own grace window ever
   ran. Fixed: the VALUES clause now computes `last_fix_at` the same way the `ON CONFLICT`
   branch's own `CASE` does — `CASE WHEN $3 = 'fixing' THEN $4::bigint ELSE 0::bigint END` (the
   explicit `::bigint` casts are load-bearing: Postgres could not otherwise unify `$4`'s type
   between this CASE and its other use as the plain `last_check_at` value in the same statement —
   "inconsistent types deduced for parameter" — since the bare literal `0` on its own defaults to
   `integer`, not `bigint`).
2. **`evaluate_now()` never touched `policy_dispatch_state`.** The SQLite original stamped
   `last_eval_[policy_id] = now()` in-memory on every manual dispatch specifically so the
   *following* automatic tick's throttle check would see it and skip re-dispatching within the
   interval. Deleting `last_eval_` (superseded by the durable claim, per the Decision above)
   silently dropped that side effect too — `evaluate_now()` still dispatched correctly on its own,
   but left no record in `policy_dispatch_state`, so the next `claim_due_policies` call found no
   row for that policy (the fresh-INSERT branch, which always succeeds regardless of the `WHERE`
   guard) and re-claimed it immediately, producing a duplicate check seconds after the manual one
   even though the interval had not elapsed. Fixed with a new store method,
   `PolicyStore::record_dispatch(policy_id, now)` — an unconditional upsert of
   `last_dispatched_at` with no lock and no `WHERE` guard (this is a single explicit dispatch
   action, not a competing claim). Stamped from `evaluate_now()` **before** calling
   `kickoff_check`, not after — `kickoff_check`'s `dispatch_fn` is blocking gRPC/gateway I/O, and
   a real network-duration window existed between "check dispatched" and "claim recorded" during
   which a concurrent tick (this replica's own background thread, or a sibling replica) could still
   observe no row and duplicate-dispatch before the manual call's network round-trip even returned.
   Stamping unconditionally before dispatch, regardless of whether `kickoff_check` itself succeeds,
   matches the original `last_eval_` semantics: a failed manual check still consumed the interval
   slot in the pre-ADR-0056 code, by the same claim-before-dispatch ordering `claim_due_policies`
   already uses for the automatic path.

Both gaps were caught by the two-instance regression test this ADR's Consequences section
promises, not by code review — the first surfaced as a claim-staleness test flipping a `fixing`
row to `unknown` inside its own "within window" assertion; the second as a flaky-looking
dispatch-count mismatch that turned out to be fully deterministic once traced (a pre-existing
`evaluate_now()` + immediate-tick sequence in the *unrelated* `interval throttles re-dispatch`
test, not the new test itself).

**Second correction (adversarial review — Kimi + Codex, cross-examined, 2026-08-24):** three HIGH
findings, all confirmed against the code and against this ADR's own text before being fixed — the
first two are cases where the implementation shipped the OPPOSITE of what this document already
said the design was, not new design questions.

1. **Backfill never compared a stored fingerprint against the local one.** The Backfill section
   above commits to "the `RbacStore`/post-#2703 shape" for holder-side verification; the shipped
   `migrate_from_sqlite` only checked whether *its own* fingerprint was already present, never what
   fingerprint(s) were actually stored. A second replica booting with a genuinely different legacy
   `policies.db` was not rejected — its identity rows silently no-opped via `ON CONFLICT DO
   NOTHING`, and `policy_triggers` (no conflict target at all) would have appended duplicate rows
   from the second file. Fixed: before the identity-insert block, when the marker table holds any
   row for a fingerprint other than the local one, refuse and return `false` — every intent table
   here is write-once, so two different legacy files for the same store is a state divergence that
   needs an operator, never a silent merge.
2. **`policy_status` backfill overwrote Postgres on legacy-ahead instead of failing closed** — this
   directly contradicted the Backfill section above ("legacy-ahead fails closed the same as
   `DeploymentStore`'s IDENTITY mismatch handling"); the shipped `WHERE`-guarded single UPSERT
   instead updated Postgres whenever the legacy row's `last_check_at` was newer. Fixed with a
   read-before-write: an existing `(policy_id, agent_id)` row with Postgres behind the legacy row
   now fails the whole backfill call closed (needs a read first, since a WHERE-guarded UPSERT can
   only express "update" or "no-op," never "abort"); Postgres-ahead-or-tied stays the existing
   benign no-op; a genuinely absent row still inserts normally (the ordinary post-cutover case).
3. **Detail-query failures (`policy_inputs`/`policy_triggers`/`policy_groups`) were silently
   dropped**, so `query_policies()`/`get_policy()`/`claim_due_policies()` could return a "successful"
   `Policy` missing inputs, triggers, or management groups on a transient failure of just one of
   those three queries — exactly the degrade-distinguishable violation the Posture section above
   forbids for reads feeding dispatch/remediation. Fixed: the detail loader now reports failure,
   and every caller (including the now-`std::expected`-returning internal `read_policy_by_id`,
   previously a plain optional that also silently conflated its OWN top-level query failure with
   "not found") propagates `PolicyReadError::kDegraded` instead of a partial object.

None of the three needed a design change — each is the implementation not doing what the Decision
already committed to. Regression tests for both backfill fixes were added alongside them.

**Third correction (adversarial review round 2 — Kimi + Codex, fresh Phase 1 on the fix commits,
2026-08-24):** the round-2 reviewers re-verified all three round-1 fixes against the code and found
each correctly implemented (including the two new regression tests genuinely exercising the fixed
paths). Codex found one new HIGH, unrelated to the round-1 findings: `evaluate_now()`'s call to
`record_dispatch()` (the fix from the FIRST correction, above) only logged a warning on failure and
still proceeded to `kickoff_check` regardless — so a `record_dispatch` failure (a plain transient
store error, not a design gap) reproduced the exact "manual dispatch leaves the durable claim blind"
bug the first correction fixed, by a different path: the check still dispatches and returns success
to the operator, but with no `policy_dispatch_state` row, so the very next automatic tick sees
nothing claimed and re-dispatches immediately. Fixed at the time: `evaluate_now()` returned `""` (not
dispatched) instead of proceeding when `record_dispatch` fails — since superseded by the Fourth
correction below, which found that `""` was itself indistinguishable from the pre-existing legitimate
"no targets" empty return and widened the signature accordingly. Kimi found two LOW items in the same
round: no dedicated regression test existed for the second correction's detail-query-degrade fix
(added: a test that drops `policy_triggers` and asserts `get_policy`/`query_policies` degrade rather
than returning a partial policy), and `claim_due_policies`' failure branch conflated "degraded read"
with "claimed policy vanished mid-transaction" in its logging (split for clarity; not reachable
today given the transaction/FK guarantees, but cheap to make precise). A regression test for the
`record_dispatch`-failure fix was added alongside it (`test_policy_evaluator.cpp`, drops
`policy_dispatch_state` and asserts `evaluate_now()` returns empty with zero dispatch calls; later
widened — see Fourth correction — to assert the typed error instead).

**Fourth correction (self-directed, advisor-prompted, 2026-08-24 — no external reviewer has graded
this pass):** the Third correction's fix for `evaluate_now()` had its own residual: an operator
`POST /api/policies/:id/evaluate` call that hit a genuine `record_dispatch` store failure landed on
`compliance_routes.cpp`'s existing `exec_id.empty()` branch, which returns 409 with the message
"policy has no check instruction or matches no agents" — false for a degraded-store outcome, and a
regression from the pre-Third-correction behavior (a transient DB error on this path used to return
202, not a factually wrong 4xx). Root cause: `evaluate_now()`'s `""` return conflated two different
things — "legitimately nothing to dispatch" (no check instruction, no targets, a check already
in-flight) and "an internal store failure prevented the attempt" (degraded policy read,
`record_dispatch` failure) — and the caller had no way to tell them apart. Fixed by widening
`evaluate_now()`'s return type from `std::string` to `std::expected<std::string, std::string>`: `""`
keeps its original no-op meaning (the route's 409 stays correct for that case); an internal store
failure (either the initial `get_policy` re-read or `record_dispatch`) now returns `std::unexpected`,
which the route maps to a 503 "policy evaluation degraded" response instead. Checked for a third
instance of the same bug class: `remediate()` was compared against the pre-migration source
(`git show 3c0cc0ade:server/core/src/policy_evaluator.cpp`) and confirmed it never stamped
`last_eval_`/an equivalent durable marker even before this migration — no equivalent gap exists
there, nothing to fix. Also fixed in this pass: the changelog fragment's "no operator action is
required" line overclaimed past the two new refuse-to-boot backfill paths the Second correction
added (a divergent-fingerprint legacy file, a legacy-ahead status row) — both are, by design, cases
where operator reconciliation IS required; qualified. All existing `evaluate_now()` call sites
(the route, and the ten happy-path assertions in `test_policy_evaluator.cpp`) were updated for the
new return type; the round-2 regression test was widened to assert `CHECK_FALSE(result.has_value())`
instead of just `.empty()`, so it now actually distinguishes the error case it was written to catch.

**Fifth correction (`/governance`, full 8-agent Gate 2/3 pass — security-guardian, docs-writer,
architect, cpp-expert, cpp-safety, sre, quality-engineer, build-ci — 2026-08-24):** the Fourth
correction's `evaluate_now()` widening was itself incomplete — it fixed the two checks inside
`evaluate_now()` directly but missed that `evaluate_now()` calls `kickoff_check()`, which had its
OWN unfixed degrade-collapse: a `get_fragment()` store failure inside `kickoff_check` returned a
bare `""`, indistinguishable from every legitimate no-op `kickoff_check` returns (no check
instruction, no targets, a check already in flight) — so the exact false-409 bug the Fourth
correction closed for `record_dispatch` was still reachable through this second, adjacent path.
Independently found by security-guardian, corroborated by architect (both traced the code directly)
and by quality-engineer (confirmed no test exercised it). Fixed the same way: `kickoff_check` widened
to `std::expected<std::string, std::string>` (not `PolicyReadError` — `policy_evaluator.hpp` only
forward-declares `PolicyStore` to avoid a hard include, and the dominant same-class idiom for a
single success-or-error-string outcome, per cpp-expert, is already `std::expected<std::string,
std::string>` — see `record_dispatch`/`create_fragment`/`create_policy`), threaded through both
`dispatch_due()` (now logs a warning on a degraded `kickoff_check`, previously discarded silently)
and `evaluate_now()`.

Four more findings from the same pass, all fixed:

- **`kPolicyDbErrorPrefix` was defined but never consumed** (security-guardian MEDIUM, corroborated
  by architect) — every mutator route (`create_policy`/`create_fragment`/`enable`/`disable`/
  `invalidate`/`invalidate-all`) mapped a genuine store degrade to the same 400 a validation error
  gets, leaking the raw internal error string into the response body. Added `is_db_error`/
  `strip_db_error_prefix` helpers in `policy_store.hpp` (mirrors `is_conflict_error`/
  `strip_conflict_prefix` in `store_errors.hpp`) and wired all six mutator routes in
  `compliance_routes.cpp` to check the prefix and return 503 instead of 400/500 on a genuine degrade.
- **`remediate()`'s HTTP-status classifier didn't recognize its own new degraded-store error
  strings** (docs-writer code-truth finding, sharpened by quality-engineer into a concrete two-part
  defect) — the Third correction's `remediate()` degrade strings ("policy store degraded — try
  again", "policy store unavailable", etc.) all fell through the route's substring classifier to the
  400 default, AND the `!result.ok` branch unconditionally audited the outcome as `policy.remediate
  | denied` — recording an infrastructure failure as an operator business denial, corrupting the
  audit trail for exactly the kind of evidence this codebase's SOC 2 posture depends on. Fixed:
  every degrade string this store's `remediate()` produces starts with `"policy store"` (verified
  against the actual four call sites in `policy_evaluator.cpp`), so the route classifies on that
  prefix first, maps it to 503, and audits it as `policy.remediate | error` (an established
  disposition value elsewhere in this codebase, e.g. `settings_routes.cpp`'s MFA/CSRF audit calls) —
  distinct from both `success` and `denied`.
- **`legacy_has_column` fails open on a probe error** (security-guardian LOW, corroborated by
  quality-engineer) — unlike its sibling `legacy_has_table`, a `PRAGMA table_info` prepare failure
  read the same as "column absent," silently defaulting every `policy_status` row's
  `fix_attempt_count` to 0 even when the column and its real values genuinely exist. Widened to
  reuse the existing `LegacyTableStatus` tri-state (Present/Absent/Error) and made the caller fail
  the whole backfill closed on `Error`, mirroring `legacy_has_table`'s existing contract exactly.
- **`claim_due_policies` failures had no alerting surface** (sre) — a persistently-failing dispatch
  claim (the ADR's own stated worst case: compliance checks silently stop running fleet-wide) only
  ever logged at `warn`, with no counter. Bumped to `error` and added a
  `yuzu_server_policy_eval_errors_total{phase="claim"}` increment, reusing the counter
  `PolicyEvaluator::Deps` already carries for the fix/verify phases — zero new plumbing.

**Documentation gap** (docs-writer HIGH, sre SHOULD — sre's read was the more operationally serious
of the two: the "move it aside" remediation server.cpp logged at the time was technically correct but
incomplete, since it also drops per-agent status history, not just definitions, and the
`policy_status` legacy-ahead check re-runs on **every** boot for as long as the legacy file exists at
its configured path — leaving it in place post-cutover as a "backup" reproduces the refusal, as a
boot crash loop, on any later clock skew or restored-backup drift): fixed the log line itself to name
both ("policy definitions AND per-agent status history in it will NOT carry over"), and added
`docs/ops-runbooks/policy-store-backfill-recovery.md` (mirrors `tag-store-backfill-recovery.md`'s
structure) covering both refusal shapes, the status-history caveat in full (why it's dropped, not just
that it is), and the every-boot re-check caveat; linked from the `server.cpp` refusal log line and the
`docs/postgres-migration-ladder.md` ladder row. Also qualified `docs/user-manual/rest-api.md`'s
`/evaluate`, `/remediate`,
`/api/compliance`, and `/api/compliance/{policy_id}` sections, which either omitted the 503 branches
entirely or documented only one of several live 503 messages; and added a one-line pointer to the
durable dispatch claim in the `.claude/routed-concerns.md` "Compliance evaluation pipeline" row,
which still described only the tick cadence.

**Not fixed, explicitly out of scope for this round:** two SHOULD-level findings from architect are
pre-existing gaps this migration did not introduce and are tracked separately rather than folded in —
whether the REST-only mutator surface (fragment CRUD, `create_policy`, `enable`/`disable_policy`,
`delete_policy`, `invalidate[_all]_policy`) needs an MCP twin or a recorded ADR-1005 exception-ledger
entry, and whether `compliance_routes.cpp`'s hand-rolled 503 bodies should migrate onto the canonical
`error_json_a4()` helper (missing `correlation_id`/`retry_after_ms`) — both pre-date this PR and apply
file-wide, not to the lines this migration touched. **Also not fixed:** quality-engineer's structural
finding that `test_compliance_routes.cpp`'s harness hardcodes `policy_store=nullptr`, making it
incapable of exercising ANY of the store-backed branches this round fixed at the route-classifier
level — the underlying logic defects are covered by new tests in `test_policy_store.cpp`/
`test_policy_evaluator.cpp` at the store/evaluator layer, but the route-level classification code in
`compliance_routes.cpp` (the 503-vs-400 mapping, the audit-disposition choice) has no direct test
coverage and could regress silently on a future change. Retrofitting a PG-backed
`ComplianceHarness` is a genuine, separate piece of work, not a drop-in addition to this round;
tracked in Follow-ups below rather than solved here (no GitHub issue exists yet as of this writing —
"filed as a follow-up" in an earlier draft of this section overclaimed; issues are drafted,
dedupe-checked, and filed only with an explicit go, per this repo's issue-standard).

**Sixth correction (fresh Gate 4 pass — happy-path, unhappy-path, consistency-auditor — run AFTER
the Fifth correction's fixes landed, 2026-08-24):** an earlier pass of this governance run had
skipped Gate 4 entirely, going straight from Gate 2/3 findings to fixing; this is the correction,
covering the full branch. happy-path: clean, no findings beyond two NICE items already covered by
the Fifth correction. consistency-auditor: three SHOULD-level findings (all folded into this round
except one deferred — see below) plus confirmation the Fifth correction's ADR claim (exactly four
degrade strings, all `"policy store"`-prefixed) was accurate, not an overclaim. unhappy-path found
one genuinely new BLOCKING defect and several SHOULD-level residuals:

- **Superseded (2026-09) by HA WS-3 3.4:** the `remediating_`/`ReservationGuard` design described in
  this bullet, and its "cross-replica double-remediate remains possible … not fixed here" residual
  below, are historical — `PolicyStore::claim_remediation` now arbitrates each `(policy, agent)`
  target with a durable, cross-replica-safe claim, closing the cross-replica gap this bullet
  describes. See `docs/adr/2002-high-availability-architecture.md` §6. Left as-written below for the
  historical record; do not read the "not fixed here" residual as current.

  **`remediate()` had no in-flight dedup, unlike `kickoff_check`'s Check-phase guard (unhappy-path
  UP-3, BLOCKING).** Two concurrent `POST /remediate` calls for the same policy (an operator
  double-click, or a client retry racing a slow response — an ordinary occurrence, not a rare race,
  hence E3 not E5 in the derivation) had no guard preventing both from reaching the blocking dispatch
  call. Each independently calls `update_agent_status(..., "fixing")`, which increments the
  fix-attempt retry counter — so a double-click doesn't just duplicate a dispatch, it burns the
  retry budget twice as fast and can force an agent to `error` after fewer genuine attempts than the
  cap intends, on a fix instruction that may not be idempotent (e.g. a software install re-run).
  Derives HIGH (I2, state/counter corruption; no raise, no cap) — blocks.

  Fixed with a reservation, not a copy of `kickoff_check`'s dedupe shape: `kickoff_check`'s own
  pattern (scan-under-lock → blocking dispatch unlocked → push-under-lock) leaves the *entire*
  blocking-dispatch window open, which is exactly the long window that makes this hazard real — a
  mirrored dedupe would have shipped the fix and left most of the race open. Instead, `remediate()`
  now reserves the policy_id in a new `remediating_` set (guarded by the existing `mu_`) BEFORE the
  blocking dispatch call, checked atomically alongside the existing `in_flight_` FixWait scan; an RAII
  guard (`ReservationGuard`) erases the reservation on every exit path. The reservation only needs to
  cover this call's own window — once a successful call's FixWait entry lands in `in_flight_`, that
  entry itself is what a later concurrent call's scan sees, so the reservation and the `in_flight_`
  scan compose rather than duplicate. New error case `"remediation already in flight for this
  policy"` classified as 409 in the route (a business rejection, not a degrade). Residual, honestly
  scoped: the reservation is per-process — a cross-replica double-remediate (two REST calls landing
  on different replicas) remains possible, tracked below with `kickoff_check`'s equivalent
  cross-replica gap, not fixed here.

  This fix also made a `RemediateResult` header comment provably false: `update_agent_status`'s
  UPSERT being "naturally idempotent against a racing manual remediate() on another replica" is true
  for the STATUS VALUE but was never true for the retry-attempt COUNTER — amended in
  `policy_evaluator.hpp`'s class-level doc comment.

- **Folded into this round** (cheap, in files already being touched): `RemediateResult` gained an
  explicit `bool degraded` field, set at each of `remediate()`'s four degrade return points — the
  route's `starts_with("policy store")` prefix match (consistency-auditor SHOULD-2: an unshared,
  untested string contract distinct from `kPolicyDbErrorPrefix`, and a future reword of any of the
  four strings would have silently broken it with nothing to catch the break) is retired in favor of
  reading the typed field directly. `dispatch_due()`'s per-policy `kickoff_check` degrade (UP-2) now
  also increments `yuzu_server_policy_eval_errors_total{phase="dispatch"}`, symmetric with the
  `phase="claim"` counter the Fifth correction added — previously warn-log-only, same silent-skip
  consequence class the Fifth correction explicitly hardened for the claim path. The `evaluate_now()`
  claim-before-dispatch comment's "matches the original" claim (UP-1) is corrected: true for WHO
  consumes the interval slot, false for BLAST RADIUS — the old in-memory `last_eval_` was
  per-replica, so a failed dispatch cost one replica's view of the interval; the new durable stamp is
  fleet-wide, so the identical failure now costs every replica the interval, not just one (self-heals
  after one interval; not fixed, tracked below). `docs/user-manual/rest-api.md`'s six mutator routes
  (create_fragment/create_policy/enable/disable/invalidate/invalidate-all) had their error responses
  documented for the first time (consistency-auditor SHOULD-3 — a doc gap on behavior THIS round
  changed, not a pre-existing one, and so not deferrable the way the others below are).

- **Deferred, recorded in Follow-ups, not fixed this round:** `delete_fragment`/`delete_policy`
  collapsing not-found/conflict/degrade into a bare `bool` → HTTP 200 `{"deleted": false}` in all
  three cases (consistency-auditor SHOULD-1 — same defect class, needs the same `std::expected`
  widening the six mutators just got, but is a new signature change, not a fold-in); UP-1's fleet-wide
  blast-radius change (self-healing, one interval, no metric — same shape as the claim-failure gap
  the Fifth correction did instrument, arguably deserves the same treatment as a future fast-follow);
  UP-4 through UP-11 (a TOCTOU window in `kickoff_check`'s own dedupe scan, advisory-lock release
  timing under an ungraceful replica death, config-error/no-targets 409 ambiguity in
  `dispatch_instruction`, no `Retry-After` hint on any new 503, `record_dispatch`'s unconditional
  restamp on a retried no-op call, no stranded-Check sweep matching the stranded-Fix sweep, and
  rolling-deploy crash-loop UX on a persistent boot refusal) — all SHOULD/NICE-derived, none blocking,
  all genuinely new observations worth a future look rather than scope creep on an already-large
  round.

### Construction — fail-closed (this store lacked it even on SQLite)

`server.cpp:4979-4986` constructs `PolicyStore` and only logs on failure today — unlike
`ResultSetStore`/`GuaranteedStateStore` right below it, nothing sets `startup_failed_`. Given the
Wave 2 "authoritative config/reference" posture this store's ladder row already carries, this was
a pre-existing gap, not a decision — closed here: `!is_open()` → `startup_failed_ = true`, matching
every other authoritative store on the ladder.

### Teardown — `policy_store_.reset()` must now run before `pg_pool_.reset()`

Today `policy_store_` owns a standalone `sqlite3*` with no shared dependency, so implicit
declaration-order destruction in `~ServerImpl` was safe. Once it borrows `pg_pool_`, that stops
being true — the same reasoning `server.cpp`'s `custom_properties_store_` comment (immediately
above the `policy_store_.reset()` site) documents (a sibling store the evaluator also holds a raw
pointer to on its background thread) now extends to `policy_store_` itself: `stop()` already joins
`policy_eval_thread_` early (`server.cpp:7470-7474`, well ahead of every store teardown near
`server.cpp:7818-7831` — re-verified against `stop()`'s current sequence on this branch AFTER
merging origin/dev's PR #3339 shutdown-watcher rework, not the pre-merge line numbers or assumed
from memory: #3339 changed HOW `stop()` gets invoked, off the raw signal-handler context onto a
dedicated watcher thread, main.cpp/server.cpp — it did not change the join-before-teardown
ordering internal to `stop()` itself, which this store's teardown relies on), so by the time any
store is torn down the evaluator thread is provably not running. An explicit `policy_store_.reset()`
is added immediately before `pg_pool_.reset()`, matching sibling discipline (belt-and-braces, not
risk-bearing — the thread-join ordering already made this safe; the explicit reset just stops
relying on declaration order to prove it).

## Considered and rejected

- **Session-scoped leader election** and **a durable in-flight ledger** — see "Design considered
  and rejected" above.
- **Naive at-least-once dispatch (no lease at all)**: rejected — technically idempotent-safe
  (duplicate verdicts converge), but multiplies real agent-side work N-fold per tick (every
  duplicate dispatch re-runs the check plugin on every targeted endpoint), which the kickoff names
  explicitly as the failure mode to avoid.
- **Moving the stranded-`fixing` sweep to a separate standalone lease/reap pass**: rejected in
  favor of folding it into the same `claim_due_policies` transaction — it is cheap, DB-only, and
  keeping it inside the existing single-sweeper section avoids introducing a second advisory-lock
  key for no operational benefit.

## Consequences

- `PolicyEvaluator::Deps` gains `fixing_stale_seconds{1800}`; `last_eval_` and the anonymous-
  namespace `interval_for()` are deleted from `policy_evaluator.cpp` (moved into `policy_store.cpp`
  as the sole due-ness computation).
- The evaluator constructor's stranded-`fixing` reset is deleted — superseded by the per-tick
  staleness sweep inside `claim_due_policies`, which runs continuously rather than only at boot
  (strictly better coverage) and no longer stomps another replica's live remediation.
- `delete_policy` no longer hand-writes a `policy_status` cleanup `DELETE` — the new FK cascades
  it, closing the prepare-failure swallow the SQLite original had there.
- `update_agent_status`'s retry-cap check becomes race-safe under concurrent replicas (previously
  safe only by accident, via a process-wide mutex that no longer serializes cross-replica calls).
- `ComplianceRoutes` reads (fragment/policy list, fleet/policy compliance summary) 503 on a
  degraded store read instead of silently rendering an empty/zero result.
- Construction gains a fail-closed guard it never had on SQLite — a genuine (small) behavior
  change: a PolicyStore that fails to open now fails the whole server's startup, where before it
  silently ran with policy evaluation permanently broken.
- Tests move to `PostgresTestDb`/`YUZU_REQUIRE_PG_DB_TPL`; `test_policy_evaluator.cpp`'s
  `PolicyStore` construction (currently plain SQLite alongside an already-PG `ResponseStore`)
  becomes PG too, and gains the multi-instance coverage neither test file had before (two
  `PolicyEvaluator` instances sharing one `PolicyStore`/DB, asserting exactly one dispatch per
  policy per interval, and that a check dispatched by instance A is collected correctly by
  instance A while instance B's own tick claims nothing for it) — this is the concrete regression
  test for the header decision.

## Follow-ups

- `get_fleet_compliance()`'s lost-invalidation race (Ninth correction, 2026-08-24): `compute_fleet_compliance()`
  runs outside `cache_mtx_`; a reader's DB query that straddles a concurrent writer's status-change +
  cache-invalidation can store a pre-write value under a fresh timestamp on its own store-back,
  overwriting the invalidation and serving stale compliance data for up to the remaining 60s TTL. LOW
  (`I3`/`E5`) — narrow window, self-heals on the next write or TTL expiry. Fix shape: a monotonic
  generation counter, incremented by every invalidation, captured by the reader before its query and
  checked before its store-back is allowed to write (skip the store-back, not just the value, if the
  generation moved).
- `policy_inputs`/`policy_fragments` free-form-text secret exposure — flagged, not fixed (see
  Secrets above); needs a `security-guardian` assessment of whether read-time redaction is
  warranted.
- Manual `evaluate_now()`/`remediate()` calls still have no durable in-flight coordination — if
  the replica that received the REST call crashes before its own `collect_ready()` runs, that
  specific operator-triggered check/fix strands (no verdict ever recorded) until the operator
  retries. Accepted: narrow (operator-triggered only, not the routine tick path), and the operator
  already has a natural retry action (re-click evaluate/remediate).
- **`legacy_status`'s backfill materializes the whole table into a `std::vector` before writing —
  a deliberate, considered choice, not an oversight, checked directly against `DeviceTokenStore`'s
  #3398/#3399 hardening (PR #3435, merged days before this store's dev-merge) since that precedent
  is the freshest thing a reviewer would hold this backfill against.** `policy_status` is
  `(policy_id, agent_id)`-keyed — fleet size × policy count, structurally the same scale class as
  device-token's per-device rows — so the concern transfers in principle. Not ported here because
  the two backfills differ in what actually costs memory: #3399's fix was a *streaming SHA-256
  fingerprint* (a full sort-then-hash pass over a materialized copy) plus a batched copy pass;
  `legacy_status` is **never fingerprinted at all** — it's excluded from the five-table identity
  fingerprint by design (see Backfill above, direction-aware LIFECYCLE merge) — so only the
  simpler "read fully, then loop-write" cost applies, not the sort-then-hash one, and it's a
  transient one-shot boot-time allocation (freed once the loop completes), not a steady-state
  pattern. Every OTHER mandatory-backfill store on the ladder (`DeploymentStore`, `LicenseStore`,
  `CaStore`, `TagStore`, `NotificationStore`, `CustomPropertiesStore`, `ManagementGroupStore`,
  `RbacStore`) materializes its legacy tables the same way and none needed the streaming
  treatment — `DeviceTokenStore` is the one outlier so far, and its own ADR frames the fix as
  proactive hardening on a then-dormant store, not a response to an observed failure. If a real
  fleet's `policy_status` backfill memory footprint becomes a measured problem, the right fix is
  the same shape as #3399's copy pass alone (chunked `LIMIT`/`OFFSET` read + batched
  `INSERT ... SELECT FROM unnest(...)` write) without the fingerprint-streaming half, since there
  is no fingerprint pass to make streaming here.
- **`claim_due_policies`'s single-sweeper transaction is O(enabled policy count), uncapped per
  tick** (adversarial review, 2026-08-24). It holds `pg_try_advisory_xact_lock('policy_store:dispatch')`
  across a sweep, a due-policy read, and ~5 round trips per enabled policy (claim upsert + a
  4-query detail load); `with_txn_for`'s timeout bounds pool-acquire only, not execution, so
  lock-hold time grows with fleet policy count with no cap, batching, or statement-level timeout.
  At real fleet scale (thousands of policies) this risks sibling replicas skipping their claim tick
  entirely while one replica works through the full list, slipping dispatch cadence past what the
  10s-tick/15s-grace contract budgets for. Not fixed now: this is the shape the Decision above
  deliberately chose (one transaction, every enabled policy), and no measurement yet shows it's a
  real problem at this migration's actual deployed scale — recorded here so it isn't rediscovered
  from scratch. If/when fleet-scale measurement shows lock-hold time approaching the tick budget,
  the fix is a per-tick cap on policies claimed (processing the remainder on subsequent ticks) or
  batching the claim+detail loads via `unnest()`/`IN (...)`.
- `test_compliance_routes.cpp`'s `ComplianceHarness` hardcodes `policy_store=nullptr` and every
  existing test only exercises the pre-`policy_store` 403 auth-denial path — it is structurally
  incapable of exercising any store-backed branch, including every degrade-classification fix in
  the Fifth correction above. A PG-backed harness variant is a genuine piece of work (`/governance`,
  quality-engineer, 2026-08-24), not a drop-in test.
- `compliance_routes.cpp`'s REST-only mutator surface (fragment CRUD, `create_policy`, `enable`/
  `disable_policy`, `delete_policy`, `invalidate[_all]_policy`) has no MCP twin; unclear whether
  this pre-existing gap is recorded in ADR-1005's exception ledger (`/governance`, architect,
  2026-08-24).
- `compliance_routes.cpp`'s hand-rolled 503 JSON bodies (this migration added several more, matching
  the file's pre-existing convention) never call the canonical `error_json_a4()` helper
  (`rest_a4_envelope.hpp`) — missing `correlation_id` and nullable `retry_after_ms` (`/governance`,
  architect, 2026-08-24). File-wide, not specific to this migration's lines.
- `delete_fragment`/`delete_policy` (`policy_store.cpp`) collapse not-found, a genuine referenced-by
  conflict, and a real DB/lease degrade into a single bare `bool` — all three read as HTTP 200
  `{"deleted": false}` on the corresponding routes (`/governance`, consistency-auditor SHOULD-1,
  2026-08-24). Same defect class the six mutator routes were fixed for in the Fifth correction; needs
  the same `std::expected<bool, std::string>` widening (not-found vs `kPolicyDbErrorPrefix` degrade vs
  `kConflictPrefix` for the referenced-fragment case) as a separate signature change.
- `evaluate_now()`'s durable claim-before-dispatch stamp costs the WHOLE FLEET one interval on a
  `kickoff_check` degrade, where the pre-migration in-memory `last_eval_` only cost one replica
  (`/governance`, unhappy-path UP-1, 2026-08-24) — a real blast-radius change from the migration, not
  a bug, self-healing after one interval, currently unmetriced (unlike the sibling `claim`/`dispatch`
  phase counters the Fifth/Sixth corrections added). A `phase="manual"` counter on this path would be
  the same one-line shape as those two if this becomes worth instrumenting.
- Several more SHOULD/NICE-derived observations from the same unhappy-path pass, none blocking:
  a TOCTOU window in `kickoff_check`'s own Check-phase dedupe scan (the mu_-released window around
  the blocking dispatch call — the same shape UP-3 closed for remediate(), not yet closed here);
  advisory-lock release timing under an ungraceful winning-replica death (stalls dispatch fleet-wide
  for roughly the pool's keepalive+TCP-timeout window, no counter on the "lock not acquired" skip
  path); `dispatch_instruction`'s `""` return conflating "no targets" with "unknown instruction id" /
  "dispatch_fn not wired", both landing on the same misleading 409 as the legitimate no-op case; no
  `Retry-After`/backoff hint on any of the new 503s; `record_dispatch`'s UPSERT has no conditional
  `WHERE`, so a retry loop against a slow Check keeps sliding the durable stamp forward; no stranded-
  Check sweep exists to match the stranded-Fix sweep `claim_due_policies` already has; a rolling
  multi-replica deploy has no way to distinguish "wait for operator" from "keep restarting" on a
  persistent boot refusal beyond the new runbook.

**Seventh correction** (2026-08-24, Gate 5/6/8 batch — chaos-injector + compliance-officer +
enterprise-readiness + security-guardian + docs-writer re-review of the Sixth correction diff):
security-guardian gave a clean **PASS** (no CRITICAL/HIGH/MEDIUM), having verified the `ReservationGuard`/
`remediating_` mechanism's lifetime/atomicity/correctness directly; it also recommended the new
mutex-guarded reservation path get a run under `-Db_sanitize=thread` before this lands somewhere
routinely exercised at scale, as ordinary due diligence for new shared-mutable-state — not a blocking
finding. Not run standalone this round (deferred to the existing Tier 3 nightly TSan leg, which already
covers this file; no separate ad hoc run scheduled). Fixed this round: the compliance dashboard's
hardcoded "Last evaluated: just now" span asserted a freshness claim the server was not actually
tracking — an I3 (wrong result presented as correct) finding once evaluation genuinely runs and can
genuinely go stale (compliance-officer HIGH); removed rather than backed with real tracking, which
would be a separate feature (see below). All six mutator routes' new degrade-503 bodies used the flat
legacy `{"error": "<string>"}` shape instead of the nested A4 envelope the same routes already used one
branch above for the "store not open" 503 (enterprise-readiness); brought all six into that existing
nested shape, without touching the pre-existing flat 400s (tracked separately,
above). Added the missing `docs/user-manual/upgrading.md` section for this migration (enterprise-
readiness BLOCKING — every sibling Postgres-store migration has one, this didn't); a dedicated
`changelog.d/20260824-policy-store-degrade-classification.fixed.md` fragment for the 503-taxonomy
change, mirroring the `custom-properties-degrade-classification` precedent, plus cross-references from
the original migration fragment to `upgrading.md`/the runbook (enterprise-readiness SHOULD); the
`docs/user-manual/audit-log.md` `policy.remediate` row's disposition list (missing `error`, enterprise-
readiness SHOULD); the runbook's and this ADR's own stale narration of the server.cpp log line as
"correct but incomplete" in the present tense, when the log line itself was already fixed to name both
definitions and status history in the same round that added the runbook (compliance-officer HIGH,
independently corroborated by docs-writer's Gate 8 pass — 2 reporters); `policy_evaluator.hpp`'s
remediation doc paragraph and `docs/postgres-migration-ladder.md`'s `PolicyStore` row, both still
carrying the unqualified "naturally idempotent" claim after the Sixth correction had already qualified
it in one place but not the other (docs-writer); and `docs/user-manual/rest-api.md`'s `/remediate`
section, still listing only the original two 409 causes after the Sixth correction added a third
(docs-writer). Deferred, not fixed: `InstructionStore::get_definition` is not degrade-distinguishable
(compliance-officer MEDIUM) — pre-existing, out of this migration's scope, not re-opened here. A real
evaluation-health signal for the compliance dashboard (compliance-officer's underlying HIGH, once the
false freshness claim itself is removed this degrades to a MEDIUM observability gap) — done properly
this needs a REST twin per ADR-1005 (no UI-only capabilities), which is why it's feature-sized rather
than a doc/one-liner fix; not built this round. `policies.db` is never renamed aside after a verified
backfill, unlike `tags.db.migrated-<epoch>` and its siblings (enterprise-readiness SHOULD) — a real
design divergence from the established ladder pattern, not a doc gap; needs its own small PR.
PolicyStore-specific backfill Prometheus metrics (`yuzu_server_policy_store_backfill_total` or
equivalent, matching every sibling store's alerting shape) do not exist yet (enterprise-readiness
SHOULD) — feature-sized, not a doc fix. chaos-injector produced six chaos test-design scenarios
(concurrent-replica dispatch-claim races, a killed-mid-backfill restart loop, a Postgres connection
drop mid-`remediate()`, clock skew against the legacy-ahead check, a malformed `fix_attempt_count`
column mid-backfill, and a stranded-`fixing` sweep racing a live remediation) — none blocking, drafted
as candidate follow-up issues, not yet filed pending operator go-ahead and a dedupe pass against the
existing issue tracker.

**Eighth correction** (2026-08-24, external adversarial review — Kimi K2.7 + Codex GPT-5.5,
`--reasoning high`, two-phase independent review + cross-examination, both DYNAMIC (compiled +
targeted-suite-run) against `origin/dev..HEAD`, synthesized against the real code by the orchestrator):
four internal governance rounds on this exact file — including a dedicated `cpp-safety` pass —
missed a verified ADR-0012 §2(a) contract violation that both external models found independently in
Phase 1 without seeing each other's work. That is the headline result of running this review, not a
footnote. Findings, adjudicated against source (falsifier shown for each):

- **`create_policy` used an unbounded blocking pool acquire** (Kimi HIGH, confirmed independently by
  Codex in cross-exam, verdict flipped PASS→BLOCK on it) — `pool_.with_txn(...)` at
  `policy_store.cpp:704` calls `PgPool::acquire()` (blocking, no deadline; `pg_pool.cpp:93,350`) where
  every other runtime mutator in this file uses `pool_.try_acquire_for(kAcquireTimeout)` via
  `with_txn_for`. ADR-0012 §2(a): "Runtime acquires are always bounded... unbounded `acquire()` is
  permitted only at construction." Under pool exhaustion this hangs a REST/dashboard worker
  indefinitely instead of returning 503. Fixed: `pool_.with_txn_for(kAcquireTimeout, ...)`. The
  existing `!ok` fallback (`failure.empty() ? kPolicyDbErrorPrefix + "failed to create policy" :
  failure`) already produces a correctly-classified degrade message on an acquire timeout — no new
  empty-message trap, since `run_in_txn` returns `false` before invoking the callback when the lease
  is empty, and the caller's existing default handles that.
- **Invalidation left `fix_attempt_count` at the retry cap** (Kimi HIGH: "the fix is never
  dispatched" — REFUTED by cross-exam and independently verified against
  `policy_evaluator.cpp:522-535`: `remediate()` dispatches the fix instruction BEFORE marking targets
  `fixing`, specifically so a dispatch failure never burns a cap attempt — gov UP-7. Codex's MEDIUM
  reframing is correct and adopted: the fix genuinely IS dispatched; the residual defect is that
  `update_agent_status('fixing')`, called right after, sees `fix_attempt_count >= 3` from BEFORE the
  invalidation and immediately flips the row to `error` — a real remediation attempt gets recorded as
  already-failed before it has run, misleading the operator/dashboard and any code reading status as a
  proxy for "did the fix run." `docs/user-manual/policy-engine.md`'s invalidation contract ("Reset all
  agent statuses... forcing re-evaluation") implies the whole lifecycle resets, not just `status`.
  Fixed: `fix_attempt_count = 0` added to both `invalidate_policy` and `invalidate_all_policies`'s
  UPDATE statements.
- **Fleet-compliance cache (`get_fleet_compliance`, 60s TTL, pre-existing — carried over from the
  SQLite-era store, not new to this migration) never invalidated on the store's own writes** (Kimi
  MEDIUM K7, confirmed independently by Codex) — `update_agent_status`, `invalidate_policy`, and
  `invalidate_all_policies` never cleared `fleet_compliance_last_computed_`, so a status change could
  read back through the dashboard/MCP fleet-compliance aggregate as stale for up to 60s. ADR-0012 §4
  rule 2 ("invalidate synchronously on the store's own writes") now binds this store regardless of
  whether the cache code itself predates the Postgres port — the store becoming authoritative-Postgres
  is what makes the contract apply. Fixed: a `invalidate_fleet_compliance_cache()` helper, called at
  the success point of all three writers. Trades some cache-hit rate during an evaluator tick's burst
  of status writes for correctness — the tradeoff ADR-0012 §4 mandates.
- **`policy_status` backfill silently skips FK-violating rows, understating the header's "Fails closed
  on any error"** (Kimi MEDIUM K8, confirmed independently by Codex) — verified the discriminating
  fact: the five identity tables (including `policies`) insert earlier in the SAME transaction as the
  `policy_status` merge loop, so an FK violation on a status row proves that `policy_id` is absent from
  the legacy file's own `policies` table too (the SQLite original had no FK to have ever caught this) —
  orphan debris with no valid reconciliation target, not a data-integrity conflict like the
  legacy-ahead case above it. Failing the boot on unrepresentable garbage would turn an upgrade into an
  outage for nothing recoverable, so the skip itself is the right call — but it was previously silent
  (a per-row `warn`, no aggregate signal) against a header comment that unqualifiedly said "fails
  closed on any error." Fixed: skipped rows are now counted and summarized in one `warn` line at
  backfill completion (`N of M ... discarded`); `policy_store.hpp`'s doc comment now names this one
  deliberate exception; the runbook gained an "Orphan `policy_status` rows" section explaining it is
  not a refusal and needs no operator action.
- **`last_check_at`-only LIFECYCLE-merge direction check** (Kimi LOW K9: should compare the full
  `(last_check_at, last_fix_at, check_result)` tuple) — **rebutted by Codex, independently confirmed**:
  this ADR's own Backfill section (above) explicitly defines the direction check as
  "Postgres-ahead-or-tied-by-`last_check_at`" — the code implements exactly the documented, deliberate
  design. Not a defect. Withdrawn.
- **Deferred, not fixed** (all non-blocking, both reviewers converged on severity): fleet-compliance
  cache reads carry no `from_cache`/`age_seconds` provenance field (Codex C-POL-001/Kimi K11, MEDIUM,
  ADR-0012 §4 rule 3 — groups naturally with the already-deferred eval-health-signal follow-up above,
  same REST/MCP-shape-change reason); `remediate()`'s 404/409 classification still string-matches
  business-rejection reasons on `RemediateResult::error` rather than a typed code (Kimi K6, MEDIUM,
  new — the degrade/503 path already has a typed `degraded` bool from the Sixth correction, this is
  the same defect class for the 404/409 path, not yet done). `claim_due_policies`'s O(N) unbounded lock
  hold (Kimi/Codex K3, MEDIUM), `delete_fragment`/`delete_policy`'s bare-`bool` collapse (K4, MEDIUM),
  the file-wide A4-envelope gap (K5, MEDIUM), and the route-test coverage gap (K10, LOW) were all
  independently re-derived by both external reviewers with no prompting — each already exists in this
  Follow-ups section above (respectively: the `claim_due_policies` scaling entry, the
  `delete_fragment`/`delete_policy` entry, the `error_json_a4()` entry, the `ComplianceHarness` entry);
  recorded here as a second, independent confirmation, not a new item.

Merged `origin/dev` (baseline PR #3517: two doc-only conflicts — a stale Wave-2 ladder-queue stub row
each side needed removed for the other's already-Done store, and `upgrading.md` section ordering —
resolved by keeping both stores' Done rows/sections; no conflict in any code this migration touches).

**Empiricism correction, same round.** The suite runs immediately after the merge, and immediately
after this round's first pass at the three fixes, both reported 11/11 shards `OK` — but with
`YUZU_TEST_POSTGRES_DSN` unset in this segment's shell (lost across a context-compaction restart, not
re-exported before resuming the established `meson test` command pattern), every Postgres-backed test
across all three PolicyStore suites silently SKIPPED rather than ran (2,644 skip lines in that run's
`testlog.txt`, one meson `test()` reporting `OK` on zero real assertions being indistinguishable from
`OK` on a genuine pass). Both external reviewers' own Empiricism/RAN sections had already reported this
in their footers (Codex explicitly, Kimi implicitly via its first `[policy_store]`/`[policy][evaluator]`
run) — missed on first read. Caught, DSN re-exported (`postgresql://yuzu:yuzu@localhost:5456/yuzu`,
the dedicated `yuzu-policy-pg` container), and the full suite re-run for real: 11/11 shards green, 0
skip lines, 137,836 total assertions server-wide, `[policy_store]` 548/63 and `[policy][evaluator]`
225/14 (the two suite-specific counts matching the pre-compaction segment's own last verified run
exactly, modulo the two new regression tests added this round). No BLOCKING finding's closure this
session ever rested on skip-mode-only evidence: the Sixth correction's UP-3 fix was verified
pre-compaction, in a segment where the DSN was genuinely set (confirmed via that run's own
`SharedPgDbRegistry` drain lines and 13,865-assertion total); the Seventh correction's BLOCKING finding
was a documentation gap, not a code path the PG suite could exercise either way.

**Ninth correction** (2026-08-24, bounded Gate-8-style re-review of the Eighth correction's own merge
+ fix diff — `security-guardian` + `cpp-expert`, scoped to `aadc550a7` plus the three follow-up commits
that landed the adversarial-review fixes, not the whole branch): `cpp-expert` gave a clean **PASS** —
verified the merged `server.cpp` retains exactly one correct Postgres construction/teardown block for
both `PolicyStore` and the colleague's parallel `BaselineStore` (PR #3517), confirmed the `with_txn_for`
signature and the `run_in_txn`-returns-false-before-callback empty-lease behavior the K1 fix depends on,
and confirmed no lock-ordering or lifetime issue in `invalidate_fleet_compliance_cache()`'s three call
sites. Two non-blocking notes, neither requiring a code change here: `BaselineStore` has no explicit
`.reset()` in `stop()` before `pg_pool_.reset()`, unlike every sibling Postgres-backed store in this
file — confirmed pre-existing on `origin/dev` at `168d37d89`, inherited from PR #3517 unchanged, not
touched by this branch's merge or diff; worth a follow-up issue against that store (the `CaStore`
ladder-row precedent is the template), not this ADR's concern. The `create_policy` fallback message text
("failed to create policy") differing cosmetically from sibling mutators' degrade wording is
functionally correct (both share the `kPolicyDbErrorPrefix` prefix `is_db_error()` matches on) — already
recorded as a deferred nit above, not reopened.

`security-guardian` gave an overall **PASS**, no CRITICAL/HIGH, but found one real gap in the Eighth
correction's own fix: **`delete_policy()` CASCADEs into `policy_status` (this migration's new FK) —
a fourth write path into the same data `get_fleet_compliance()`'s cache aggregates — that the Eighth
correction's cache-invalidation fix missed**, having wired only the three status-writing functions
(`update_agent_status`, `invalidate_policy`, `invalidate_all_policies`). This is the same failure shape
the Follow-ups section already names elsewhere in this ADR (fix the SINK, not the enumerated instances)
recurring one level in: "the three functions that write `policy_status`" was never the actual sink —
"anything that mutates `policy_status`, including a CASCADE" was, and a fix responding to external
review reproduced the same enumeration mistake it was itself correcting. Fixed: `delete_policy()` now
calls `invalidate_fleet_compliance_cache()` on a successful delete, guarded on `deleted == true` (a
failed or no-op DELETE wrote nothing, so nothing to invalidate — not an oversight to later "fix" to
unconditional). Regression test added, same shape as the Eighth correction's K7 test: populate the
cache, delete the policy, confirm the very next read (inside the 60s TTL) reflects zero rather than the
stale cached total. Second finding: the new runbook section's summary line was labeled "info-level, not
a refusal" when the code (added by the Eighth correction) actually emits `spdlog::warn` — a doc/code
wording mismatch, fixed (the per-row line in the same section already correctly said `warn`; the mislabel
was isolated to the summary-line header).

**Residual, deferred, not fixed this round:** re-reading `get_fleet_compliance()`/`compute_fleet_compliance()`
directly while investigating the delete_policy gap surfaced one more real gap in the cache-invalidation
fix, not caught by either external reviewer or either bounded-re-review agent — the query itself
(`compute_fleet_compliance()`, `policy_store.cpp:1076-1117`) runs OUTSIDE `cache_mtx_`; only the
cache-check (before the query) and the store-back (after it) are locked. A reader that misses the cache
and begins the query can have its query observe pre-write state, then have a concurrent writer's status
change AND cache invalidation both land before the reader's store-back completes — the reader then
overwrites the just-invalidated cache with a stale value stamped with a fresh timestamp, silently
un-doing the invalidation for up to the remaining TTL window. Narrow (one DB round-trip's width,
self-heals on the next write or at 60s regardless), LOW under this ADR's severity scheme (`I3`/`E5`), and
the correct fix — a monotonic generation counter checked against the query's start generation before
the store-back is allowed to write — is a small, separable piece of work, not a one-liner alongside three
other fixes. Added to Follow-ups below rather than fixed inline, to avoid landing a fourth stacked
same-day fix on the same 60s cache this ADR has now touched three times without a chance to see whether
the simpler fixes hold up first.

Fixed this round, all PG-backed-suite-verified after a clean rebuild (DSN exported in the same command
as the test invocation, per the Empiricism-correction note above): `[policy_store]` 557 assertions / 64
cases, up from 548/63 after the Eighth correction (one new test case, nine new assertions).
