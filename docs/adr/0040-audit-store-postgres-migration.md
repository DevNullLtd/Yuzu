# ADR-0040: AuditStore → PostgreSQL (Wave 1.3)

- **Status:** Accepted — shipped PR #2697, merged 2026-08-07; `audit_store.cpp` is PG-native
  (`PgPool`/`pg_exec`), zero live `sqlite3_` calls (comments only), re-verified 2026-09-07.
- **Date:** 2026-08-01
- **Deciders:** pg workstream; security-guardian + docs-writer + compliance-officer (Gate 2/6)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0036 (ResultSetStore) and ADR-0037 (InventoryStore). The two conventions this store
  extends, with their actual current homes in the tree rather than an ADR number: the
  single-sweeper advisory-lease reap is implemented in `result_set_store.cpp` and
  `software_inventory_store.cpp`; `sanitize_pg_text` (UTF-8-invalid + embedded NUL → U+FFFD)
  in `management_group_store.cpp` (ADR-0042). #2360 is the retention clock guard whose
  behaviour is migration-REQUIRED here.

  (An earlier revision of this ADR cited an **ADR-0038 (GuaranteedStateStore)** and an
  **ADR-0039 (ResponseStore)** five times over as the source of both conventions. Neither
  file exists, and neither store is on PostgreSQL — `response_store.cpp` and
  `guaranteed_state_store.cpp` are both still SQLite. Corrected in the Gate 2 docs round;
  recorded here because a fabricated precedent is exactly the thing later migrations copy.)

## Context

`AuditStore` (`audit.db` today, `server/core/src/audit_store.{hpp,cpp}`) is the **SOC 2 evidence
chain**: operator actions, agent enrolment, fleet-topology events, background schedule execution,
and every behavioural-PII access. It is the highest-stakes store on the ladder — a lost or
silently-truncated audit trail is a compliance failure (CC6.6/CC7.2), not degraded telemetry.

SQLite schema (v3): `audit_events` (id, timestamp, principal, principal_role, action,
target_type, target_id, detail, source_ip, user_agent, session_id, result, `principal_class`
[schema v2], `ttl_expires_at`), the four query indexes (`idx_audit_ts` / `_principal_ts` /
`_action_ts` / `_target_ts`), the partial retention index `idx_audit_ttl_id ON
(ttl_expires_at, id) WHERE ttl_expires_at > 0`, and `audit_retention_meta` (k/v — the durable
half of the #2360 clock guard). Public API: `log()` (bool — the evidence-integrity contract),
`query()`, `total_count()`, eight metric accessors, and the retention `cleanup_once` / cleanup
thread.

Wave 1.3 on the ladder. ResponseStore has NOT migrated (`docs/postgres-migration-ladder.md`);
an earlier revision said this store followed it.

## Decision

Migrate to PostgreSQL schema **`audit_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server PgPool. `mtx_` deleted; PG concurrency + an advisory
lease replace the single-writer assumption.

### Schema

`audit_events` ports column-for-column (INTEGER id → `BIGINT GENERATED ALWAYS AS IDENTITY`;
timestamps stay BIGINT epoch; text columns TEXT). All four query indexes carry over, plus the
partial `idx_audit_ttl_id ON (ttl_expires_at, id) WHERE ttl_expires_at > 0` the reaper needs.
`audit_retention_meta` (k/v) carries over — and gains the reaper's **durable dedup** rows (see
Retention). Unlike SQLite, the partial index is created in the migration (Postgres index builds
don't take the fail-closed-on-failure hazard the SQLite `ensure_retention_index` guards against
— PG runs it inside the migration txn and a failure correctly fails the migration, which for an
evidence store is the right fail-closed posture).

### Posture (ADR-0012 §1)

- **Write (`log`): FAIL-HARD.** This is the distinguishing decision vs ResponseStore's fail-soft
  ingest — a dropped audit event is a compliance failure, not re-derivable telemetry. `log()`
  keeps its `bool` contract: a store-not-open / pool-acquire-timeout / query error returns
  `false`, and callers already fail-closed on `false` (behavioural-PII REST routes → `503` +
  `Sec-Audit-Failed`; `emit_behavioral_audit`, #1647). No fail-soft drop, no silent swallow.
  `emit_failed_` counts every `false`. The write is a single `INSERT` (fail-hard via
  `PQresultStatus`), never a SAVEPOINT-tolerant path.
- **Reads (`query` / `total_count`): degrade-distinguishable, DENY on degrade.** The audit trail
  is authoritative evidence — a store/pool failure MUST NOT read as "no audit events" (that would
  let a reviewer or a SIEM conclude an absence of activity from an infrastructure blip). `query`
  becomes degrade-distinguishable at the seam (`std::optional<std::vector<AuditEvent>>` /
  nullopt-on-degrade) and the audit-log REST/dashboard consumers surface `503`, never a
  false-empty. This is stricter than ResponseStore's deny-or-benign carve-out: the audit read is
  evidence, so degrade → deny, not degrade → render-empty.
- **Retention (`cleanup_once`): migration-REQUIRED clock guard** (see below). Fail-hard within
  its advisory-lease-held transaction; a probe/delete failure declines the pass (never a blind
  delete).

### Backfill (ADR-0009) — MANDATORY

Unlike ResponseStore (skippable TTL telemetry), the audit trail is **SOC 2 evidence retained
365 days**: pre-cutover rows MUST come across. This is the ADR-0009 **mandatory** class and the
primary new element vs the three prior migrations.

- On first boot against an empty `audit_store.audit_events` with a legacy `audit.db` present,
  stream every `audit_events` row (all columns incl. `principal_class` and `ttl_expires_at`, so
  the retention horizon is preserved exactly) into PG in **bounded batches** (memory-safe — the
  legacy table can reach tens of millions of rows / ~16 GB; a whole-table read would OOM,
  cf. #2661). `audit_retention_meta` (the clock-guard reading) is copied too.
- **Idempotent + resumable:** a one-time `backfill_complete` marker row in `audit_retention_meta`
  gates re-runs; a crash mid-backfill re-streams from `MAX(id)` already in PG (id-ordered,
  ON CONFLICT DO NOTHING) so no duplication and no loss. Reconciliation is a **whole-file
  5-aggregate fingerprint** (`COUNT`/`SUM(id)`/`SUM(timestamp)`/`MIN(timestamp)`/`MAX(timestamp)`),
  not a bare row count (Gate 3 architect F2, round 3, sharpened by Sol's diagnosis): a bare count
  is defeated by a foreign writer occupying an id this legacy file also claims — `ON CONFLICT (id)
  DO NOTHING` silently drops the legacy row, and if a native row already held that id, the total
  count comes out unchanged (one row lost, one gained, same id). `SUM(id)` doesn't catch it either
  — the id is still there, just holding different content. The timestamp components do: a native
  write's timestamp is "now", a legacy event's timestamp is historical. Logged and asserted as
  **equality** — an unexplained surplus is as much an unaccounted-for state as a shortfall. This
  fingerprint is also what gets stamped as `backfill_source_fingerprint` (below) — the value a
  later boot compares a still-present legacy file against.
  **The reconciliation query's own statement-execution deadline is explicit, not inherited (Gate 5
  chaos-injector F1, round 3).** It is an unqualified full-table aggregate scan — no `WHERE`,
  cannot use the partial retention index — on a table that can reach tens of millions of rows.
  `PgPool`'s per-operation `timeout` parameter (e.g. `kBackfillTxnTimeout`) only bounds the
  pool-ACQUIRE wait; every connection the pool hands out otherwise carries the same fixed,
  pool-wide default `statement_timeout` (30s) for actual execution, regardless. The reconciliation
  query now runs inside `pool.with_txn` with an explicit `SET LOCAL statement_timeout = '60000ms'`
  as its first statement (never a bare `SET`, which would leak the widened deadline onto the
  connection's next, unrelated caller) — closing risk of a persistent backfill failure loop at the
  documented target scale. See `docs/postgres-store-playbook.md`'s anti-patterns list for the
  general lesson (this mismatch has now recurred twice in this codebase).
- **No native audit row may be written before the marker exists.** The resume cursor and its
  prefix proof (next bullet) both assume every row in PG came from the legacy stream. A row
  this build wrote itself is not in that stream, so the proof mismatches and the backfill is
  refused on **every** later boot — permanently, on the host whose evidence the operator is
  most likely to need. This is ENFORCED, not conventional: `migrate_from_sqlite` arms a write
  gate on entry and clears it only on success, and `log()` declines while it is armed. The
  earlier revision of this bullet said the boot path satisfied the rule "by construction,
  because the backfill runs before anything can log" — Gate 3 cpp-safety disproved exactly
  that: `ServerImpl`'s constructor sets `startup_failed_` on a failed backfill and then keeps
  constructing, and several hooks it installs are guarded only on `is_open()`. The one-shot
  break-glass CLI paths (`--mfa-reset`, `--break-glass-arm`) additionally run the backfill
  themselves before logging, via `open_one_shot_audit` in `server/core/src/main.cpp`.
- **A sourceless exit may only stamp the marker over an EMPTY table, and only from a server
  boot.** The marker asserts the trail is complete; with no legacy source in hand — no file, or
  a file with no `audit_events` table — nothing on that path can establish it. Three rules,
  because the first alone was not enough (Gate 3 architect A-4):
    1. rows-present + marker-absent fails closed (a replica started while another is still
       streaming, or a partial backfill whose legacy file was moved aside);
    2. the emptiness is re-checked INSIDE the stamping transaction, so a peer streaming rows in
       between cannot slip past a check made outside it;
    3. only a boot may stamp sourcelessly at all. One-shot CLI paths pass
       `Sourceless::Refuse` and refuse instead, because a host that merely does not hold
       `audit.db` would otherwise stamp over its empty table — and the host that DOES hold the
       trail then skips the mandatory backfill on that marker and reports success. 365 days of
       evidence, silently never migrated.
  The *resume* path is unaffected throughout: it has a source, and the prefix proof licenses it.
  The sourceless stamp logs at WARN naming what it forecloses, because a genuinely fresh install
  cannot be told apart from a fileless replica at the moment of stamping.
- **Holder-side verification closes the peer-replica gap the three rules above cannot (Gate 4
  UP-2 / Sol, round 3).** No process can prove *deployment-wide* absence from its own filesystem —
  a sourceless stamp is honest about what it knows, never about what it doesn't. So the fix does
  not live on the sourceless side at all: `stamp_complete` additionally writes a
  `backfill_source_fingerprint` row in the SAME transaction as `backfill_complete` — `"sourceless"`
  for a sourceless stamp, or the five-aggregate fingerprint (the same shape as the prefix proof
  above, over the whole legacy trail) for a real backfill. A HOLDER that later boots and finds the
  marker already set, with its own legacy `audit.db` still present, does not trust the marker: it
  re-reads that file, computes its own fingerprint, and compares. A match (this host's own prior
  partial run, or an identical shared-storage sibling's) retries the move-aside that evidently
  failed; anything else — a mismatched fingerprint, a `"sourceless"` provenance, an unreadable or
  corrupt file — **refuses to serve**, file untouched at its original path, so the operator can
  investigate rather than lose the trail silently. This is what actually closes the residue the
  bullet above could not: `upgrading.md`'s boot-order guidance is now an optimization (avoids a
  refusal an operator would otherwise have to resolve by hand), not the thing preventing evidence
  loss.
  **That claim depends on `stamp_complete` itself verifying it won the write, not merely that the
  write succeeded (Gate 4 UP-1/UP-10, round 3 fix-round).** `backfill_source_fingerprint`'s INSERT
  is `ON CONFLICT (key) DO NOTHING`, and `PGRES_COMMAND_OK` is returned whether it inserted or
  silently no-opped on conflict — checking only that status, a real backfill that lost this exact
  race to a rival writer (a fileless peer's sourceless stamp, or a concurrent real backfill) would
  have reported success and proceeded to `move_legacy_aside()`, moving its own still-unverified
  legacy file out of the way while a DIFFERENT writer's value sat at the trust anchor — reaching
  the identical false-assurance state this bullet describes closing, one step earlier than
  described. `stamp_complete` now checks `PQcmdTuples` on that INSERT and fails closed (leaving
  the legacy file in place) if a real, non-sourceless backfill loses the race; a sourceless stamp
  losing the same race is not an error, since it carries no evidence claim to lose. See
  `AuditStore::stamp_complete` and the test `"AuditStore: a real backfill that loses the
  fingerprint race refuses, not silently reports someone else's value"`.
- **The `MAX(id)` resume cursor is guarded by a prefix proof.** ADR-0009's trigger is an *empty*
  schema; resuming from `MAX(id)` relaxes that so an interrupted copy can continue, and the
  relaxation is sound only while the rows already in PG *are* that interrupted copy. Before
  streaming, the migration compares five aggregates —
  `(COUNT(*), SUM(id), SUM(timestamp), MIN(timestamp), MAX(timestamp))` — over PG against the
  legacy rows at or below the cursor, and **fails closed on any mismatch**. Without it, a
  marker-absent PG table holding unrelated rows above the legacy id range skips every legacy
  row, still satisfies the count check, and stamps the mandatory backfill complete having
  migrated nothing — after which the legacy file is moved aside. A count alone does not close
  it (equal counts, disjoint ids), which is why the id sum is in the comparison; the id shape
  alone does not close it either, because ids run `1..k` in *every* deployment (an identity
  column here, `rowid` there), so a foreign table's first 50 rows carry the same count and id
  sum as this legacy file's own first 50. Event timestamps are what differ between two
  deployments, which is why three of the five aggregates are over `timestamp`.
- **Fail-closed on backfill failure** (ADR-0012 mandatory-backfill contract): a failed/partial
  backfill refuses boot with a loud diagnostic and is retried on the next start — the server
  never serves with a knowingly-incomplete evidence chain. Backfill work is RAII-guarded
  (degrade audit + `yuzu_server_audit_backfill_*` metric).
- **Read-time credential redaction (`sanitized_detail`) ports, and the backfill applies it
  too.** The migration ladder requires this to be an explicit decision rather than a default,
  so: it is applied at the PG row-materialisation point (every reader) AND during the copy, so
  the substrate never receives the plaintext. Pre-fix `config.update` rows hold an OIDC client
  secret in free-form `detail` text, and unlike an ADR-0010 `SecretCodec` column there is no
  rekey story for that — CLAUDE.md's "a secret is NEVER a plain Postgres column" binds a value
  that arrives by migration exactly as it binds one that arrives by writer. Nothing legitimately
  readable is lost (reads redact identically) and the unredacted original is not destroyed: it
  stays in the legacy file, which is moved aside rather than deleted. Operators who set the
  secret before the writer fix should still rotate it.
- The legacy `audit.db` is moved aside (not deleted) after a verified backfill, per the
  operator-managed-backup convention, so the pre-cutover evidence remains recoverable. Its
  `-wal`/`-shm` sidecars move with it when present: a clean shutdown checkpoints and removes
  them, but after an unclean stop the committed tail is in the WAL, and the main file without it
  does not open as a usable database — moving only the main file would retain a copy that cannot
  be read. (The backfill itself is unaffected: a read-only open reads through the WAL.)

### Retention (clock-guarded) — the single-writer assumption does NOT port

The #2360 clock guard (`classify` decline-once + `kMaxAuditDeletesPerPass` cap + `would_wipe`
whole-window-jump detection + `big_step` + `prev_unusable`) is **migration-REQUIRED** — dropping
it reinstates an unbounded clock-driven `DELETE` on the evidence chain.

The load-bearing port problem (ladder row): the dedup state — `last_reported_` (the previous
pass's `Facts`) and `loaded_meta_unusable_` — is a **per-PROCESS member**, while the clock
reading it pairs with (`last_pass_now`) is **durable**. On SQLite with one server that is
correct. On PG with N servers, each process holds its own `last_reported_`, so N processes each
spend the guard independently — a condition reported by server A re-reports on server B, and
worse, the dedup that stops a legitimately-all-expired store from declining forever breaks.

Fix (the advisory-lease reap pattern already shipped in `result_set_store.cpp` and
`software_inventory_store.cpp`, generalised): **single-sweeper advisory lease**
(`pg_try_advisory_xact_lock('audit_store:reap')`) so exactly one process sweeps per tick, AND
move the per-process dedup state into **durable `audit_retention_meta` rows** (`last_anomaly_facts`
alongside `last_pass_now`) so the fact-set comparison survives across processes and restarts —
the same shape `result_set_store.cpp`'s sweep uses for its own durable meta. `kMaxAuditDeletesPerPass`
(25 000) is then preserved as a per-pass drain rate for the ONE sweeping process (the advisory
lease makes "N × 25k" impossible), so the calibration stays valid.

`loaded_meta_unusable_` (the boot-time "durable reading present but unusable" flag) also becomes a
durable fact folded into the same `audit_retention_meta` state, so it is not lost when a
different replica runs the first post-boot pass.

**#2579's missing-anchor decline ports as a DURABLE, FLEET-SHARED fact.** `Facts::no_anchor` —
"no pass on this database has yet reached a verdict" — is carried by a `bootstrap_settled` row in
`audit_retention_meta`, settled at the VERDICT rather than at the re-anchor, and counted apart on
`yuzu_server_audit_retention_bootstrap_declines_total`. Both properties are load-bearing and were
missing from an earlier revision of this section, which enumerated only five of the six ported
elements (Gate 3 architect A-6). Durable-and-shared because the SQLite original used a per-process
flag, which on N replicas is spent by whichever booted first; settled-at-the-verdict because the
re-anchor happens BEFORE the probes, so deriving the trigger from the stored reading would let one
transient probe failure spend it permanently — the exact defect #2579 closes.

**Cross-replica clock divergence — closed (#2360/1d, Gate 4 unhappy-path UP-2 / Sol).** An earlier
revision of this guard compared one replica's own process `now` against the durable
`last_pass_now`, so replicas whose clocks disagreed could alternate `BadState`/`Step` fact sets
that never matched `last_anomaly_facts` and each declined forever. The decision now reads
PostgreSQL's OWN clock (`SELECT EXTRACT(EPOCH FROM now())::bigint`) inside the same advisory-lock
transaction that already serialises every sweeper, so every replica compares against the
identical reading regardless of its own process clock's accuracy. The caller-supplied `now`
remains only a liveness signal (`last_pass_unixtime_`) and the pre-txn implausibility guard; it
has no bearing on the retention verdict. PostgreSQL is authoritative for this decision.
**Not yet a codebase-wide idiom**: the single-sweeper advisory lease is precedented in
`result_set_store.cpp`/`software_inventory_store.cpp`, but reading PG's own clock to drive an
ongoing retention verdict is not — `ResultSetStore::gc_sweep` (the same `#2360`-class guard it
was copied from) still compares against its own process clock via `now_epoch()` and carries this
identical divergence. Deferred, ladder-wide follow-up; not fixed by this PR.

**Residual risk this closes divergence but not drift (Gate 6 sre, round 3).** PG-clock-authority
removes disagreement BETWEEN replicas' decisions, but nothing here alerts if PostgreSQL's own
clock is itself wrong (unsynced NTP, a misconfigured container clock) in absolute terms — every
replica would then agree, correctly by this guard's own logic, on a jointly-wrong retention
decision. The two detectors this guard has (`clock_anomaly_skips_total` for an implausible
jump, `retention_bootstrap_declines_total` for a missing/unusable anchor on first run) both
require the reading to look internally inconsistent to fire; a clock that is merely offset by a
fixed amount and otherwise monotonic satisfies neither. No alert exists for this today; it is
not new to this migration (the SQLite predecessor had the identical exposure against each
replica's own OS clock) and is not being fixed here.

**Deliberate dedup-semantics change (multi-process correctness).** The SQLite guard had an
`is_event` exemption: a clock *movement* (a `Step`, or a `BadState` accompanied by a clock event)
re-reported **every** pass even against an identical prior report, because in a single process a
second movement is a genuinely new incident. That exemption does NOT port: with the dedup state
now **durable and shared across replicas**, "always re-report an event" would make each of N
processes re-announce the *same* incident every tick — double-counting an anomaly rather than
deduplicating it. The PG guard therefore uses the ResponseStore fact-set model uniformly: report
once per distinct serialized `Facts` set, stand down when it clears. The catastrophic protection
is fully preserved — the dead-CMOS-then-NTP sequence flips `would_wipe`, which is a *different*
fact set, so it still reports (the failure the original `is_event` logic was added to stop was an
enum-collapse comparison, which the whole-fact-set string never had). The only thing lost is a
second *identical-magnitude* clock step re-emitting `clock_anomaly_skips`; that is an
alerting-granularity trade accepted in exchange for correct cross-replica deduplication, and is
called out here for the consistency/security gates.

### Untrusted byte columns (UTF-8 + NUL)

`detail`, `user_agent`, `source_ip`, `principal`, `session_id` and friends are client- or
agent-supplied free text. Following `management_group_store.cpp` (ADR-0042), they are scrubbed with
`sanitize_pg_text` (UTF-8-invalid → U+FFFD **and** embedded NUL → U+FFFD) before the `INSERT`,
so a hostile or mis-encoded value can never fail the fail-hard write (SQLSTATE 22021 / NUL
truncation) and take an audit event down. `result`/`principal_class` are sanitized too — an
earlier revision of this line called them "enum-controlled and not sanitized", which stopped
being true when `AuditStore::log` was corrected to sanitize every text column, live path
included, not just the backfill copy (Gate 3 cpp-expert F4: every current call site does pass a
literal, but the write path itself has no way to enforce that, so treating the column as trusted
was the defect). This closes the same class #1593 guards, on the evidence path.

### Lifecycle

`stop()` unwires from the writers then resets before `pg_pool_`; store in `/readyz` AND
`/healthz`. The retention pass runs on an advisory-lease-gated cadence (keeping the existing
`cleanup_interval_min`, default 60m; the lease makes a per-process thread safe — only the lease
winner sweeps). The in-process cleanup thread's join-before-store-teardown contract is preserved.

## Considered and rejected

- **Fail-soft ingest (ResponseStore's posture)**: rejected — the audit trail is evidence, not
  telemetry; a silently-dropped event is a CC6.6 failure. `log()` stays fail-hard/bool.
- **Skippable backfill**: rejected — 365-day SOC 2 retention makes pre-cutover rows mandatory
  evidence; a fresh-start would destroy the compliance record.
- **Per-process dedup kept as-is**: rejected — N-server independent guard spending is the exact
  hazard the ladder row calls out; advisory lease + durable dedup is required.
- **Whole-table backfill read**: rejected — OOM risk on a multi-GB evidence table (#2661);
  bounded batched streaming with id-resumable ON CONFLICT is required.

## Consequences

- Audit history is **preserved** across the Postgres cutover (mandatory backfill), then
  fleet-consistent across replicas. First boot after upgrade pays a one-time streamed backfill
  (and, on a large `audit.db`, a widened startup budget — `upgrading.md`).
- Retention is single-swept fleet-wide via the advisory lease; the eight retention/write metrics
  keep their names and now reflect the coordinated single-sweeper.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"auditstore"` `PgTestTemplate`; backfill /
  migration / fresh-DB tests use plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- The two conventions are now used by, in the tree today: `sanitize_pg_text` —
  `management_group_store.cpp` and `audit_store.cpp`; the advisory-lease reap with durable
  dedup — `result_set_store.cpp`, `software_inventory_store.cpp` and `audit_store.cpp`.
  Promote both to the postgres-store playbook as the canonical untrusted-column + clock-guard
  recipe, and name **EXISTS, never a counting aggregate**, as the probe form (Gate 3
  performance measured the difference on this store; `result_set_store.cpp` still carries the
  counting form and should be converted before the remaining #2508 stores copy it).

## Update (2026-09-04) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) named `AuditStore` as the sole
**permanent** exception: "audit evidence cannot be regenerated the way config or cache state
can." This ADR's "Skippable backfill: rejected" line above (Considered and rejected) recorded
the same reasoning for the mandatory backfill this document originally designed. Both are
superseded here, at the operator's explicit direction: a hard cutover with no migration path
held open, for any store, accepting permanent audit-trail loss as the failure mode if the "no
production fleet" premise is ever wrong for this store specifically. #3623 (batches A and B,
merged 2026-09-03) had already retired the other 18 stores' `migrate_from_sqlite()`;
`chore/retire-migrate-from-sqlite-auditstore` retires the 19th and last.

`AuditStore::migrate_from_sqlite()` and its private helpers (`legacy_has_column`,
`LegacyTableStatus`, `legacy_has_table`, `LegacyFingerprint`, `legacy_fingerprint`,
`parse_fingerprint`, `stamp_complete`, `move_legacy_aside`, `kBackfillTxnTimeout`,
`kBackfillBatchRows`, the `Sourceless` enum) are removed, along with the now-permanently-false
`backfill_pending_` write gate on `log()` (nothing sets it once the only caller is gone) and the
`yuzu_server_audit_backfill_total{result}` counter + its `YuzuAuditBackfillFailing` alert.
`audit_retention_meta` is NOT dropped — it also holds the clock guard's permanent durable state
(`last_pass_now`, `last_anomaly_facts`, `bootstrap_settled`, #2360/#2579) — and its two
backfill-only rows (`backfill_complete`, `backfill_source_fingerprint`) are removed via a
version-bumped v2 migration appended after the already-shipped v1, never edited in place: this
store is constructed in production, so v1 has run against real dev/UAT databases.

**DELETE, not poison — the opposite choice from `RbacStore`'s v4 (ADR-0041's own Update,
same PR family), and deliberately so.** `RbacStore`'s retired code fell through marker-absence
into an unconditional overwrite of a live security flag (`rbac_enabled`) sourced from whatever a
local legacy file held — silent and dangerous, so that migration POISONS the marker to force an
old binary rolling back down its own pre-existing safe branches instead of a bare `DELETE`.
`AuditStore::migrate_from_sqlite()` was already engineered against exactly this failure shape,
across three governance rounds (Gate 3 architect A-2/A-4, Gate 4 unhappy-path UP-1/UP-10 round
3, Gate 8 architect round 3; #2661/#2854) — verified by reading the pre-retirement code directly
(`git show 8992b5274:server/core/src/audit_store.cpp`, the `origin/dev` HEAD this PR branched
from) rather than assumed from precedent:

**Gate 4 unhappy-path UP-1 (round 4) found that the DELETE alone does not actually reach this
guarantee.** An earlier draft of this Update reasoned through the sub-cases individually — marker
absent with an empty table, marker absent with a non-empty table, marker absent with a real
legacy file, marker already present — and concluded each one refuses loudly except a narrow
empty-table window where an old binary re-stamps `backfill_complete='sourceless'` via its own
`complete_without_source`/`Sourceless::StampIfEmpty` default (pre-retirement file, line ~964).
That per-case reasoning was accurate as far as it went, but it missed the composition:
`audit_retention_meta` is never wiped again once v2 has run, so a stamp made during that one
narrow window is **permanent** — no later v2 re-run ever revisits it. Every subsequent old-binary
boot on that database, at any later time, however much data `audit_events` holds by then, now
takes the marker-**present** branch instead, which — when no legacy file remains at the
configured path, the ordinary case — returns success with **zero row-count check at all**
(pre-retirement file, lines ~928-940). One lost race permanently and silently disarms the refusal
for that database. UP-2 compounds this: the break-glass one-shot CLI (`--mfa-reset`/
`--break-glass-arm`) constructs a full `AuditStore` unconditionally on every invocation, so
running it from a freshly-built image against a fleet whose daemons haven't yet upgraded can
manufacture the empty-table window directly, on a live fleet, outside any planned rollout.

**The fix is a CHECK constraint added in the SAME v2 migration as the DELETE, DELETE ordered
first, one transaction** — closing the race rather than narrowing it:

```sql
DELETE FROM audit_retention_meta WHERE key IN ('backfill_complete', 'backfill_source_fingerprint');
ALTER TABLE audit_retention_meta ADD CONSTRAINT audit_retention_meta_no_retired_backfill_markers
    CHECK (key NOT IN ('backfill_complete', 'backfill_source_fingerprint'));
```

**Must stay one migration — an interim commit on this branch briefly split it and Gate 5
chaos-injector (round 1) found why that was worse.** The split moved the DELETE into v2 and the
ADD CONSTRAINT into a new v3, to avoid depending on checking every local/dev Postgres instance for
drift from an even earlier commit's DELETE-only v2 (see the drift-check record below — that
concern turned out to already be closed). But a crash between v2's COMMIT and v3's BEGIN is a real
durable state: `audit_retention_meta` has no marker rows and no constraint yet, and an old
binary — which does not take `PgMigrationRunner`'s advisory lock, by its own explicit design — can
land a marker `INSERT` into exactly that gap. v3's `ALTER TABLE ADD CONSTRAINT` then fails
validating the row it finds, so the **current** binary's own `AuditStore` refuses to open too, not
merely an old one — a wedge until an operator manually deletes the row, worse than the silent
UP-1 disarm this fix exists to close. Folded into one transaction, DELETE and ADD CONSTRAINT
commit together or roll back together, so no durable state exists where the marker could be
absent but the constraint not yet in force. The DELETE ordered first is also what makes a retry
**self-healing**, not merely atomic: if an old binary's insert lands and this transaction's own
`ALTER` blocks on it and then fails, the *next* attempt's `DELETE` clears that very row before its
`ALTER` validates — a split migration has no `DELETE` in its second step to do this.

Same shape as `RbacStore`'s own v2 constraint (`rbac_meta_enabled_canonical`) on the same
key/value-meta table pattern — but where RbacStore's constraint narrows the *values* a key may
hold, this one forbids the *keys* outright. With it in place, `stamp_complete`'s `INSERT` fails
(`23514 check_violation`, independent of `ON CONFLICT` arbitration — Postgres validates CHECK
constraints before conflict resolution) on two of the four sub-cases above: marker-absent with an
empty table (the UP-1 window itself) and a real local legacy file. The other two never reach an
`INSERT` at all: a non-empty `audit_events` was already refused by the pre-existing
`pg_rows_before` guard, unrelated to this fix, and marker-present is structurally unreachable,
since the marker can never be (re-)inserted. `migrate_from_sqlite` returns `false` on every one of
the four, and `server.cpp` sets `startup_failed_`, deterministically, not merely in the realistic
case. The refusal itself is the same class of guarantee the `DROP TABLE` group gets from
`42P01`/`undefined_table` — a schema-level rejection, not a live-row-count race — while still
leaving `audit_retention_meta` itself in place for the clock guard's permanent rows. One caveat
this framing does not extend to: in the legacy-file-present sub-case, the old binary's row
inserts into `audit_events` (each in their own idempotent transaction, `ON CONFLICT (id) DO
NOTHING`) run and commit *before* the final `stamp_complete` call that now fails — the refusal
here is loud and deterministic, but it is not zero-data-movement the way an `undefined_table`
error on first touch is. Nothing in the current codebase writes either backfill key any more
(`migrate_from_sqlite` and its helpers are fully deleted), so the constraint can never reject
legitimate current-binary activity.

**Drift-check record (Gate 6 security-guardian, round 1) — the concern the brief split tried to
address, resolved the safer way instead.** This SQL has been identical since its first commit on
this branch; `git merge-base --is-ancestor <that commit> origin/main` and `origin/dev` both return
false (this branch has never shipped), and a direct `schema_meta` query against the two Postgres
instances reachable from this box showed both still at v1 — no rig anywhere has run a build with a
different v2 to drift from.

`server.cpp` now runs `legacy_sqlite_probe::harden_legacy_file_0600(audit.db, "AuditStore")` (POSIX
only — a documented no-op on Windows, #3593 — `audit_events.detail` may hold plaintext secret
material from a since-fixed historical bug) followed by
`legacy_sqlite_probe::warn_if_legacy_rows(audit.db, "AuditStore", {"audit_events"})` at
construction instead — WARN-only, log-only, never blocking, the same treatment every other
retired store gets. This is a deliberate, explicit choice: "no migration
paths held open" governs the DATA path (nothing imports a legacy file's rows any more), not the
detect-and-warn smoke detector every other retired store keeps — an operator finding a real,
row-holding `audit.db` still gets a loud boot-time signal that the "no production fleet"
premise may be locally wrong, even though nothing will act on it. `open_one_shot_audit()`
(`main.cpp`, the `--mfa-reset`/`--break-glass-arm` break-glass CLI paths) drops its
`legacy_audit_db` parameter and `Sourceless::Refuse` call entirely — it now just constructs
`AuditStore` and checks `is_open()`, matching every other one-shot audit writer.
