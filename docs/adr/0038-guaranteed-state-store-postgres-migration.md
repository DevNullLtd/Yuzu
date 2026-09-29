# ADR-0038: GuaranteedStateStore → PostgreSQL (Wave 1)

- **Status:** Accepted — shipped PR #2663, merged 2026-08-08; `guaranteed_state_store.cpp` is
  PG-native (`PgPool`/`pg_exec`), zero live `sqlite3_` calls (comments only), re-verified
  2026-09-07.
- **Date:** 2026-07-31
- **Deciders:** pg workstream, security-guardian + docs-writer review (Guardian routing per CLAUDE.md)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009, ADR-0012; conventions from the
  pilot migrations ADR-0036 (ResultSetStore) and ADR-0037 (InventoryStore);
  `docs/yuzu-guardian-design-v1.1.md` §9.1 (schema) + §24 (standing invariants).

## Context

`GuaranteedStateStore` is the server-side Guardian state store (`guaranteed-state.db`
today): five tables — `guaranteed_state_rules` (operator-authored rule rows, the content
`Push` fans out), `guaranteed_state_events` (agent-reported enforcement/violation history,
TTL'd, default 30 d), `guardian_observations` (the ruleless DEX signal projection — PII
class, TTL'd in lockstep with events), `guardian_agent_rule_status` (per-agent×rule
reconcile state), and `guardian_meta` (k/v; carries `policy_generation`, the counter agent
reconciliation is keyed on). High-write (heartbeat/status + observation ingest), a
vuln-graph join input, and the `/dex` analytics substrate (~25 aggregate reads).

It is the first Wave 1 store, next in `docs/postgres-migration-ladder.md` order.

## Decision

Migrate to PostgreSQL schema **`guaranteed_state_store`** (ADR-0008 naming), construction
fail-closed (ADR-0012 §1), on the shared server `PgPool`. The agent side is untouched
(agent stays SQLite; the wire protocol and the `__guard__`/`__observation__` payloads do
not change).

### Schema

The five tables port column-for-column with SQLite idioms translated (INTEGER booleans →
`BOOLEAN`, `TEXT` timestamps stay ISO-8601 `TEXT` where the SQLite store used them —
behavior-preserving; a TIMESTAMPTZ normalisation is a separate, later decision). The
**published enum CHECK constraints must stay byte-identical to the SQLite DDL**: the
H2/G9 cross-check tests bind schema enums to the agent's per-type support arrays — add or
remove a type in both or neither (CLAUDE.md Guardian §). Indexes carry over; the DEX
aggregate reads get the same composite indexes the SQLite store maintains.

### Posture (ADR-0012 §1) — split by table family, decided by consumer blast radius

- **Rules + meta reads: AUTHORITATIVE, type-distinguishable (the catastrophic read).**
  `list_rules`/`get_rule`/`rule_names` feed `guardian_routes`' Push fan-out and the
  baseline deploy surface. A degraded read collapsing to *silent empty* would push an
  EMPTY rule set — a fleet-wide disarm, the Guardian analogue of the pilots'
  `NOT from_result_set:` inversion. These reads move to
  `std::expected<..., std::string>` / `std::optional<Container>`-nullopt-on-degrade
  (playbook "Authoritative reads must be type-distinguishable"), and every push/reconcile
  consumer aborts (503 / no-op push) on degrade — never fans out an empty set it cannot
  distinguish from "no rules configured". Single-object `get_rule` keeps
  found/absent/degraded three-state.
- **Rule/meta writes: fail-hard** (`std::expected`, surfaced to the REST caller; a lost
  rule write is operator-visible config loss). `bump_policy_generation` becomes one
  atomic `UPDATE ... RETURNING` — it is now cross-process state; the read-modify-write
  idiom does not port.
- **Event/observation ingest: FAIL-SOFT** (mirrors ADR-0037 ingest): a dropped
  enforcement-history row is re-derivable operational telemetry from the agent's next
  report cycle; ingest must never block the gRPC thread. Drops are counted
  on the existing `yuzu_server_guardian_events_{dropped,ingest_errors}_total` family —
  a dedicated ingest-dropped counter was dropped in review as a double-count, Gate 4
  consistency SHOULD-1).
- **Status upserts: fail-soft with the same counter** (reconcile heals on the next
  heartbeat), but status **reads** feeding the enforce-gate/dashboard stay
  degrade-distinguishable (empty ≠ unknown).
- **DEX analytic reads: deferred widening (explicit, playbook-sanctioned).** The ~20 DEX
  aggregate reads keep their plain `std::vector<T>` signatures THIS PR (empty-on-degrade,
  behavior-identical to the SQLite store today), because the type change fans out to ~68
  call sites across five consumer files (dashboard fragments need the htmx 200+inline-note
  convention, REST twins 503, MCP a third shape) — each an individually-reviewed decision,
  not a mechanical sweep, and none feeds an enforce/target decision (the playbook's
  deny-or-benign class; same deferral the ResultSetStore pilot recorded for
  `list_by_owner`/`members`/`lineage`). What this PR DOES land at the store seam:
  `yuzu_server_guardian_read_degrade_total{reason}` + `DegradeSampler` logging on every DEX read
  (a degrade is counted and visible even while the return stays empty). The
  `std::optional` widening + per-route degrade sweep is a tracked follow-up (issue filed
  with this PR), amendable per-file. The `kDexCohortFloor` no-singling-out flooring stays
  where it lives today (model/route layer), untouched.
  The type-distinguishable set THIS PR: `list_rules` / `get_rule` / `rule_names` /
  `rule_names_for` (Push/reconcile inputs), `agent_rule_statuses` /
  `agent_rule_statuses_for_agent` (enforce-gate/census input), and
  `current_policy_generation` (`std::optional<uint64_t>`, nullopt-on-degrade — added in
  the Gate-2 fold so a degraded generation read aborts the push/reconcile instead of
  reading as generation 0) — the catastrophic-read set — plus all write paths.

### Backfill (ADR-0009) — mandatory, all five tables, one transaction

Rules and meta are operator-authored config and the generation counter — losing them
disarms or re-arms Guardian incoherently; events/observations are *bounded* (30-day TTL)
but NOT re-derivable (agent-reported history, and the observations projection is
works-council-audited PII whose disposal evidence we keep); status is cheap and keeps
reconcile warm. So: single-transaction backfill of all five tables from the legacy
`guaranteed-state.db`, idempotent via a `sqlite_backfill` marker row (ADR-0036 shape —
never row-count-inferred), per-row SQLSTATE discrimination exactly as ADR-0037 H1 settled
it (22xxx/23xxx/54xxx = skip + persisted `skipped_bad`; anything else aborts UNSTAMPED and
the boot log carries the operator remediation line). Legacy file retained read-only for
one release. **Amended (#2663, security-guardian review):** events/observations are
copied UNCONDITIONALLY, `ttl_expires_at` included — the original design (TTL-expired
rows skipped at read time, WHERE-clause, bound to the migrating replica's own
`now_epoch()`) made a retention decision outside the clock-guard machinery entirely,
with no anchor, sanitiser, cap, or decline; a migrating host whose clock read ahead at
first boot could silently and permanently exclude a genuinely-live row. Mirrors
`AuditStore::migrate_from_sqlite`: the guarded `reap_expired()` is the sole authority on
what has expired, draining any already-expired legacy row itself, capped and counted
like any other row, rather than the migration silently deciding first. Trade-off: a
large expired legacy backlog now drains at the reaper's cap pace (~10k/pass, hourly)
instead of being excluded instantly — acceptable, since it now produces disposal
evidence (reap counters) rather than silent exclusion, better serving this section's
own works-council continuity argument.

### Retention (the part that must not port as-is)

The SQLite store's background cleanup thread issues **bare wall-clock TTL deletes** on
`guaranteed_state_events` + `guardian_observations` — on the routed-concern
"Clock-guarded retention" non-compliance list (#2508). The port adopts the **#2496
`gc_sweep` reference shape** (first PG implementation of the guard): shared
`gc_meta`-style rows (`last_pass_now`, `last_anomaly_facts`, `bootstrap_settled`) in the
store schema, one sweeping replica per pass via
`pg_try_advisory_xact_lock('guaranteed_state_store:reap',0)`, outcome probe excluding
implausibly-ahead rows — the horizon is derived from this store's own `retention_days_`
(`pg_now + retention_window_secs + kReapTtlFutureSlackSec`, matching `audit_store.cpp`'s
`datable_horizon` shape, own constant), not a fixed guess, so no accepted
`--guardian-event-retention-days` value can falsify it (#2663 review) — every DECISION
(the probe, the `gc_meta` stamp, `big_step`) reads PostgreSQL's OWN clock inside the
advisory-lock transaction, not this replica's process clock (`AuditStore::cleanup_once`'s
`#2360/1d` shape; fixed #2663, fjarvis review — the original process-clock read let a
fast/skewed replica's own reading win the shared `gc_meta` anchor and silently sweep a
row still live by every other clock, with `classify()`'s existing detectors unable to
catch a moderately-fast clock on their own) —
`audit_retention_rules::classify` + fact-set decline-once,
**unconditional per-pass cap** (substrate-tuned constant; events and observations reaped
in the same guarded pass so the PII projection never outlives its parent event — the
lockstep invariant survives). The `events_reaped_`/`observations_reaped_` counters
(compliance WS-E disposal evidence on `/metrics`) are kept as-is, unlabelled; the
`result` label lives on the separate `yuzu_server_guardian_reap_passes_total` pass
counter, per the #2634 direction, so this store does not reproduce the observability gap
#2634 tracks on ResultSetStore.

Adopts the routed-concern's part-6 missing-anchor trigger (#2579): a pass that has not
yet reached a verdict on this database, with rows already expired, declines once and
anchors rather than deleting (`result=declined_no_anchor` on the pass counter). Recorded
answer, at the `Facts` construction site: **decline**, `AuditStore`'s answer, not
`ResultSetStore`'s — a mis-timed pass here would destroy Guardian drift/remediation
events and their DEX observation projection, the non-regenerable compliance evidence this
migration exists to bring into #2508 compliance.

### Lifecycle

The in-process cleanup thread goes away; the guarded reap runs from the server maintenance
tick (like ResultSetStore's). `stop()` unwires borrowed pointers in the ingest services
before `pg_pool_.reset()` (pilot convention); `/readyz` **and `/healthz`** both carry the
store (the #2636 healthz/readyz drift class — this PR also fixes #2636's
`result_set_store` one-liner while in that conjunction).

### Concurrency

`mtx_` (the SQLite single-writer mutex) is deleted; Postgres real concurrency replaces it.
The two read-modify-write sites (`bump_policy_generation`, status upsert-with-transition)
become single-statement `UPDATE/INSERT ... ON CONFLICT ... RETURNING`. No
`sqlite3_changes()`-after-step survives (#1033): every counted mutation uses `RETURNING`
or `PQcmdTuples` on its own single-owner result.

## Considered and rejected

- **Skippable backfill for events/observations** (pure ADR-0009 reading): rejected —
  bounded but not re-derivable, and the observation rows' disposal evidence chain
  (works-council/WS-E) argues for continuity across the cutover.
- **TIMESTAMPTZ normalisation during the port**: rejected — behavior-preserving port
  first; a type change rides its own change with its own tests.
- **Keeping the dedicated cleanup thread**: rejected — a per-process thread × N replicas
  multiplies the reap rate and cannot honor the single-sweeper advisory-lock requirement
  the clock-guard invariant imposes on Postgres stores.

## Consequences

- Guardian rules/events join the vuln-graph query-owner seam (ADR-0012 §3) when scoring
  lands; the DEX dashboard reads become fleet-consistent across server replicas.
- The Push fan-out gains an explicit degraded-store abort path (503, audited) — a
  behavior change: previously a broken store could push an empty rule set; now it
  refuses. Changelog fragment + `docs/user-manual/guaranteed-state.md` note required.
- Tests: store-behaviour tests move to `YUZU_REQUIRE_PG_DB_TPL` + a file-local
  `PgTestTemplate` (`"guaranteedstate"` key); migration/fresh-DB tests keep plain
  `YUZU_REQUIRE_PG_DB`. The H2/G9 enum cross-check tests must pass unchanged against the
  PG DDL.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory 5-table,
SAVEPOINT-per-row backfill this ADR designed (ADR-0037's SQLSTATE-discrimination shape)
was real, working code that never had real legacy data to protect.

`GuaranteedStateStore::migrate_from_sqlite()`, its dedicated `SqliteConnGuard` RAII
wrapper, and its private helpers/types (`LegacyRule`, `LegacyMeta`, `LegacyStatus`,
`LegacyEvent`, `LegacyObservation`, `backfill_row`, `backfill_row_strict`, `safe`) are
removed (`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623).
`sqlite_backfill` — whose entire purpose was the backfill idempotency marker — is
dropped via a version-bumped `{2, "DROP TABLE IF EXISTS sqlite_backfill;"}` migration,
not edited into v1: this store IS constructed in production, so v1 has actually run
against real dev/UAT databases. `gc_meta` (the UNRELATED #2496 retention clock-guard
durable state) and `guardian_meta` (the UNRELATED `policy_generation` counter) are both
kept untouched — neither is backfill machinery, despite the superficially similar
naming. `server.cpp`'s boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows`
over the five legacy tables (`guaranteed_state_rules`/`guardian_meta`/
`guardian_agent_rule_status`/`guaranteed_state_events`/`guardian_observations`) instead
— silent unless real rows are found, never blocks boot.

**Consequence, specific to this store.** Most other stores in this retirement batch
lose merely operational or cosmetic state if the "no real legacy data" premise turns
out to be locally false for some install (a stray notification feed, a stale discovery
scan). This store is different: a legacy `guaranteed-state.db` genuinely holding real
Guardian rules now produces a boot-time WARN log line and nothing else — the rules are
never loaded, and enforcement silently starts from an empty rule set rather than
resuming the operator's prior policy. `BaselineStore` (also retired in this same batch,
ADR-0055) carries the identical enforcement-class consequence — a Baseline IS what a
Guardian deploy enforces (`deployed_snapshot`), so a legacy `guardian-baselines.db` with
real content is equally never resumed, only warned about. This is a strictly worse
consequence class than the rest of the batch, and it rests on the same production-fleet
premise as every other
store here; if that premise is ever locally wrong for a Guardian install specifically,
the operator's actual protection posture is what's at stake, not just convenience.

## Follow-ups

- #2634-parity counters land here from day one (this ADR's retention section).
- Keyset pagination for the heaviest DEX reads if `/dex` route budgets demand it
  (measure first).
