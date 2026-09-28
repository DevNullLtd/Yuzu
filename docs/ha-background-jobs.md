# Background-job replica-safety (WS-10)

ADR-2002 §Decomposition item 10. Active-active means every background pass must be
safe to run on more than one core replica. This is the operator/reviewer-facing
companion to the **authoritative source of truth**, which is code:
`server/core/src/background_jobs.hpp` (`kBackgroundJobs`). If this doc and the
table disagree, the table wins.

## The three classes

- **ReplicaSafe** — correct to run on every replica at once: read-only/local,
  idempotent, an execute-once CAS, or an advisory-lock SINGLE-WRITER retention
  pass. Some ReplicaSafe passes MUST run per-replica and must never be
  leader-gated — the event-outbox poll (`poll_event_outbox_once`) is the reference
  case (ADR-2002 §5: every replica polls its own bus, or non-leader SSE goes dark);
  the `/readyz` Postgres reachability probe (`pg_reachability_probe.tick`, HA WS-8)
  is another — each replica must measure its own path to Postgres.
- **FencedLeaderOnly** — side-effecting singleton work that double-fires across
  replicas (agent dispatch: schedule tick, policy remediation, quarantine
  reconcile; CRL numbering). Runs only on the WS-3 fenced leader. *Enforcement is
  WS-10 slice 10.3, which rides WS-3 3.2 — the classification exists now; the
  leader-gate wiring lands with the leader.*
- **DisabledUntilFixed** — not yet safe for a 2nd replica until its named fix lands
  (it still runs on the single replica today). Two passes: `nvd_sync.do_sync`
  (pending its engine-tier migration, ADR-1005 Phase 7) and
  `execution_tracker.reconcile_stale_concurrency_claims` (advisory-lock
  single-writer, but its clock authority is still replica-local — a skewed winner
  could release a live claim early; pending the `concurrency_claims` DB-clock
  migration, #4093).

## The unit is the PASS, not the thread

One thread multiplexes many passes of different classes — `result_set_maint_thread_`
runs ~11 (the per-replica poll, several advisory-locked reaps, gauge refreshes) and
`health_recompute_thread_` a cluster of read-only fleet gauges plus a fleet-wide CRL
re-publish, a per-replica stream teardown, and the two per-replica MCP maintenance
passes (bridge sweep + session gc). Classifying a thread wholesale would falsely
certify an unsafe pass riding a mostly-safe thread, so each `kBackgroundJobs` entry is
one unit of work — with the caveat that the many trivially-identical read-only gauge
passes on `health_recompute_thread_` are folded into a single
`health_store.recompute_metrics` entry (they are all ReplicaSafe; the CRL publish,
which is NOT, is enumerated separately). Passes on their own dedicated component
threads (cert reloader, catalogue rollup, provisional-MFA cleanup, OTA watchdog, MCP
projector, the two store-worker delivery pools, and — since HA WS-8 — the Postgres
reachability probe) each get their own entry too — the 2026-09-07 sweep
(methodology recorded in the `kBackgroundJobs` header) brought the table to 40 after
an earlier revision missed eight of these; later additions are recorded in that header.

## How classification is enforced — and its honest limit

- `kBackgroundJobs` is the checked-in, git-auditable, CI-compiled inventory, and
  `tests/unit/server/test_background_jobs.cpp` pins its internal consistency +
  completeness (a count tripwire) and the load-bearing per-pass classes.
- Every **catastrophic-class** site carries `YUZU_ASSERT_BACKGROUND_JOB(...)` — a
  `consteval` lookup that makes removing/renaming its table entry a **build failure**
  (the `command_capability.hpp` ExecuteGate precedent): all FencedLeaderOnly and
  DisabledUntilFixed passes (incl. the concurrency reconciler), plus the load-bearing
  ReplicaSafe ones (the event-outbox poll, the three retention prunes, the app_perf
  rollup upsert, and the must-run-per-replica / shared-PG-writing passes the sweep
  added: cert reloader, catalogue rollup, provisional-MFA cleanup, OTA watchdog, MCP
  projector, MCP bridge sweep + session gc, store-worker delivery pools, the HA WS-8
  Postgres reachability probe).
- That proves **named⇒classified** for those sites. It does **not** yet prove
  **pass⇒named** for every dispatch site — a `consteval`/CI sweep visiting *all* of
  them is a tracked follow-up (#4094) — so completeness rests on this table, the
  **recorded sweep methodology** in the `kBackgroundJobs` header (repeat it on any
  audit), and the routed-concern review (`cpp-safety` + `sre` + `compliance-officer`
  on any new background pass). A new side-effecting pass is a diff against
  `kBackgroundJobs`, never a silent addition.

## Clock-guarded retention (the #2508 residue, WS-10 10.2)

The three formerly-bare wall-clock prunes — `app_perf_fleet_store`,
`preflight_run_store`, `deployment_run_store` — now run through the shared
`pg::run_clock_guarded_prune` helper (`server/core/src/pg/pg_retention_guard.hpp`):
the full seven-part clock guard + a `pg_try_advisory_xact_lock` making it
SINGLE-WRITER-safe, reading Postgres `now()` in-SQL (the shared clock). The
`concurrency_claims` reconciler gained the same advisory lock, but **not** the shared
clock — its clock authority stays replica-local and its part-3 sanitiser is
floors-only, so it is **DisabledUntilFixed**, not ReplicaSafe, until the
`concurrency_claims` DB-clock migration (#4093). See `docs/clock-guarded-retention.md`
for the rule these satisfy and the reconciler's open caveat.
