# Clock-guarded retention

Routed doc for the **clock-guarded retention** concern in `.claude/routed-concerns.md`.
Loaded by `cpp-safety` + `sre` + `compliance-officer` on any new or modified retention/reaper/prune pass.

**The rule:** any bulk delete whose cutoff comes from a wall clock (`now - window`) must be guarded and
capped, never a bare `DELETE ... WHERE ts < cutoff`.

The rule exists because a wrong clock turns a routine retention pass into silent, unrecoverable data
loss, and every detector below was added after a real failure. **What makes any store's choices
correct is the RECORDED reasoning, not the answer — copying one without deciding is the defect.**

## The seven parts — all load-bearing

### 1. Probe by OUTCOME

Would this pass expire EVERY datable row? Exclude rows stamped implausibly far ahead — one
forward-skewed row otherwise disarms the guard forever.

The implausibility bound is **PER-STORE**, must exceed that store's own max legitimate TTL horizon,
and must **NEVER** be copied from another store's constant. A short bound copied from a short-TTL
store into a long-retention one misclassifies honest fresh TTLs as implausible and flips partial
expiry into a false would-wipe decline (ADR-0038, found in review).

### 2. Compare against a PERSISTED clock reading

The reading must survive restarts. An in-process reading is inert on the pass that matters — the
first after a boot with an already-wrong clock.

### 3. SANITISE that reading

Ahead-of-now, negative, or unparseable is an anomaly, **never a quiet reset**. On an endpoint the
user controls, a quiet reset IS the bypass.

### 4. SUPPRESS only a repeat of the SAME anomaly

Compare the **FULL FACT SET** — never a latch bool, and never a classified enum — so a legitimately
all-expired table still ages out.

A bool cannot carry anomaly IDENTITY: a DIFFERENT anomaly arriving while it is set is neither
declined nor reported, and the pass deletes. MEASURED on the pre-hardening `audit_store`: an
implausible-reading decline latched, a would-wipe arrived on the next pass, and it was swallowed —
deleted with no decline, no counter and only a routine info line. The bool design needed three
separate hand-patches for instances of this same identity problem before a fourth was found, which
is why the fix is the fact set rather than a fourth patch.

### 5. Cap every accepted pass UNCONDITIONALLY

The cap is the half that always applies; the detectors are best-effort.

### 6. Decide DELIBERATELY what a missing anchor means — and record which way you went

The retention guards that face this question **each answer it differently, ON PURPOSE.**

- **TAR** treats no-stored-reading as a decline trigger in its own right (the first pass against an
  existing store would otherwise delete under an already-wrong clock with every detector silent).
- **`audit_store`** does too since #2579, gated the SAME way — TAR short-circuits on `!has_expired`
  before it computes `no_anchor`, and `classify` returns `None` on `!has_expired` before testing it,
  so neither fires on a fresh install with nothing to lose. *(Do not describe either as narrower than
  the other: that claim was made and was false.)*

  The two differ in **SCOPE and ACCOUNTING, not in trigger**. TAR decides per warehouse table and
  deliberately never RECORDS a bootstrap NoAnchor fact set into its dedup map (#2573 TAR half) —
  unlike `audit_store`, whose durable bootstrap-settled marker commits in the SAME transaction as its
  verdict, TAR's anchor persist is a plain `set_config` independent of that map, so recording
  NoAnchor would let a persistent persist-failure turn every later identical pass into a silently
  suppressed drain. `audit_store` decides per database and gets the same non-latching property free
  from fact-set dedup; the pass declines ONCE, anchors, and counts to its own
  `..._retention_bootstrap_declines_total`, never the clock-anomaly series, because it asserts only
  that nothing can yet be ruled out and must not fire an alert that says the clock moved.

  (It formerly declined only when the pass would ALSO expire every datable row, which is exactly the
  hole #2579 closed — a forward-skewed host whose post-skew rows still survive defeats that test.)
- **`ResultSetStore::gc_sweep`** deliberately does NOT adopt it: one TTL window of scratch result sets
  is regenerable, so a decline would buy nothing.
- **`GuaranteedStateStore`** (ADR-0038) records a fourth answer at its `Facts` site: decline,
  `audit_store`'s answer — a mis-timed pass would destroy non-regenerable Guardian/DEX compliance
  evidence, not `ResultSetStore`'s reproducible scratch data.

### 7. Elapsed-time thresholds are ABSOLUTE

Never scaled to the retention window: `max(window, floor)` puts the threshold a year out on a
365-day default and the check never fires (#2360/#2361, found post-review).

## SINGLE-WRITER ONLY as written

On a Postgres store the reading and the dedup state must become SHARED rows under an ADR-0012
advisory lock, because process-local state paces at N × cap across replicas and one skewed replica
can put every replica into permanent mutual decline.

## Per-store adoption register

Siblings become compliant store-by-store as they migrate to Postgres.

### Using the guarded shape

| Store | Notes |
|---|---|
| `result_set_store` | ADR-0036; shape only: ADR-0040 |
| `guaranteed_state_store` | ADR-0038, compliant #2663 |
| `api_token_store` T12 rotation sweep | #2964 |
| `response_store` | ADR-0039, compliant #2691 — full Facts/classify + `kMaxPlausibleNow` clamp + PG-clock read via the shared `gc_meta` anchor |
| `ExecutionTracker::concurrency_claims` stale-claim reconciler | ADR-1007 — a persisted anchor + dedup fact-set in `retention_meta` survive restarts, and the whole probe-decide-act sequence is wrapped in one transaction. `would_wipe` is a DELIBERATE non-adoption of part 1 for this small ephemeral table, same reasoning as `api_token_store`'s own DELIBERATE NON-ADOPTION comment. **NOT yet fully seven-part compliant** — part 3 is floors-only (no ahead-of-now clause) and the shared-CLOCK rule is unmet (see the caveat), so it is classed **DisabledUntilFixed** in `background_jobs.hpp`, NOT ReplicaSafe. **SINGLE-WRITER as of WS-10** — a `pg_try_advisory_xact_lock('execution_tracker:concurrency_reconcile')` is now the first in-txn statement (try-and-skip; a lost race skips without advancing the liveness gauge), closing the concurrent-double-reconcile half of the shared gap the note below describes. **Clock-authority caveat (still open):** this pass's `now` is the caller's replica `system_clock`, not PG `now()` in-SQL — and the `concurrency_claims` `expires_at` it compares against is likewise written from `now_epoch()` (replica `system_clock`). So the shared-CLOCK half of the SINGLE-WRITER rule is NOT yet met for this store; a `concurrency_claims` DB-clock-authority migration (WS-1 class, #3715 shape, spanning claim write + extend + reconcile) is a prerequisite before a 2nd replica. Its part-3 sanitiser also floors-only (no ahead-of-now clause) — the same gap WS-10 fixed in the shared `pg::run_clock_guarded_prune`, tracked for this store alongside the clock-authority migration |
| `app_perf_fleet_store`, `preflight_run_store`, `deployment_run_store` retention prunes | **WS-10 (#2508)** — the three formerly-bare wall-clock deletes now run through the shared `pg::run_clock_guarded_prune` helper (`server/core/src/pg/pg_retention_guard.{hpp,cpp}`): all seven parts + a `pg_try_advisory_xact_lock` (SINGLE-WRITER), reading Postgres `now()` in-SQL (shared clock, #3715). Constants are per-store parameters (`ClockGuardedPruneSpec`), part-6 = **Decline** at each call site (non-regenerable operator/analytics history). ONE reviewed impl parameterised per store, not three hand-copies — the "copy the SHAPE, never the numbers" rule made mechanical |
| `offline_endpoint_store` endpoint prune (#5678 / #1545 UP-4) | All seven parts adopted via the shared `pg::run_clock_guarded_prune`. Timestamp = `last_seen_at` (`(EXTRACT(EPOCH FROM last_seen_at)*1000)::bigint`), which is PG-authored (`now()` in-SQL) on every upsert, so column and cutoff share the PG clock domain: a lagging replica clock cannot expire a live row and a future-stamped one cannot make a dead row immortal. The roster still reads the replica-authored `last_heartbeat_ms`, so the prune cutoff can reach a roster-visible row only under >7 d replica/PG clock disagreement. Window = the roster read window (30 d) + 7 d margin, computed as roster window + `OfflineEndpointStore::kPruneMargin` (37 d). No index on the expression (an hourly seq scan over a fleet-bounded table, bounded by the pool's 30 s statement timeout; revisit past ~5M rows). Part 6 = **Decline**: identity fields regenerate at a connected agent's next heartbeat, but a departed device's last-seen history does not. 7 d big-step floor (hourly cadence; weekend gaps must not decline), 1 d implausibility bound, advisory key `endpoint_state:endpoints_prune`. Runs PER REPLICA on `preflight_runner_thread_`: first pass on the first tick (about a minute after start; the bootstrap decline persists the anchor), then hourly, so the first real delete is the next hourly pass. Each hourly tick drains up to 12 passes of 1000 rows (12,000 rows per replica per hour; the drain stops on the first pass that returns less than the cap, a decline or an error). The xact advisory lock serialises overlapping passes only; staggered replicas each run their own pass, the shared settled marker means one bootstrap decline fleet-wide, and the first deletion can follow the first replica's decline by one stagger interval. The capped DELETE is unordered (shared guard idiom) — safe because every prunable row is already ≥ 7 d past the roster window |
| `execution_artifacts` scratch-dir sweep (agent, #4390) | Agent-side, not a store: removes orphaned `execution_artifacts-<32 hex>` scratch directories under `agent.data_dir` whose last-write time is older than one hour (`execution_artifacts_scratch_sweep_win.cpp`). **Part 5 adopted** — five unconditional caps, carried per pass in `SweepLimits` (root entries enumerated, directories removed per pass, failures per pass, wall-time deadline computed once, entries per candidate); truncation is reported as `deferred`, never as done. The walk starts at a rotating root-entry index (`pass_counter % n`, #4504), which reduces but does not eliminate the chance that a persistently failing run of early entries delays a removable orphan: the counter is process-local (it resets on restart), advances one per executed pass whatever made the pass stop, and `n` is the count of all root entries, which changes as entries are removed, so no "reached within n passes" bound holds; rotation also covers only the first `max_root_entries` entries the root enumeration returns (a larger `data_dir` reports `deferred` every pass; a resumable enumeration is the upgrade path). **Part 3 PARTIALLY adopted, in-process only (#4503):** forward wall-vs-monotonic step detection and nothing more — no ahead-of-now or negative-reading sanitisation of a stored value, and a future-dated candidate mtime still reads fresh (`agents/shared/wall_clock_step.hpp`). A wall clock that advances more than 60 s faster than the monotonic clock since the previous sample (the `init()` seed, for the first non-startup pass) quarantines sweeping for one hour of monotonic time (a backward step later restored is itself seen as a forward step when the restoration falls on a sampled pass; only the two sampled endpoints are compared, so an excursion of more than an hour that begins and ends between two passes and cumulative sub-tolerance drift are not detected, the protective handle is not held from creation, and a directory created in such an excursion could read stale in the create-to-open window, which fails closed: the creating dispatch fails, a re-dispatch succeeds, the content is a regenerable hive copy; a permanent forward correction is recovered from when the quarantine lapses, no restart), skipped passes are logged; backward steps alone are not acted on (they only make entries look fresher); the startup pass has no prior sample and is accepted as-is (this is the part-6 decision: no in-process dispatch can exist yet at `init()`, so this process has no concurrent writer; a second agent process sharing `agent.data_dir` is not excluded, and the cost there is bounded, the creating dispatch fails closed and the content is a regenerable hive copy). Nothing is persisted. **Parts 1 and 2 not adopted; part 4 not adopted separately (the quarantine window stands in for it as a fail-safe time latch: it skips, never deletes); part 6 decided for the startup pass only; all recorded here and in the header banner:** the content is a regenerable copy of a system hive that this plugin itself staged — never operator data — so a wrong wall clock can destroy nothing that cannot be re-created by the next dispatch; and liveness of an in-flight dispatch is proven by the OS (the dispatch holds the directory open without `FILE_SHARE_DELETE` and the loaded hive holds the file), not by the clock — the one-hour floor exists only to cover a concurrent dispatch's create-to-open window. Part 7 holds (absolute threshold, equality is fresh). Guard state is in-process only (a restart ends any quarantine); no persisted anchor. |
| `local_security_policy` scratch-dir sweep (agent, Windows) | Agent-side, not a store: removes orphaned `local_security_policy-<32 hex>` scratch directories (a `secedit /export` of the whole SECURITYPOLICY area that a crash left behind) under `agent.data_dir` whose last-write time is older than one hour and whose owner is the agent's own token owner (`local_security_policy_scratch_sweep.hpp`, `local_security_policy_win.cpp`). **Part 5 adopted** — five unconditional caps (root entries enumerated, directories removed per pass, failures per pass, wall-time deadline computed once, entries per candidate); truncation is reported as `deferred`, never as done. **Parts 1–4 and 6 DELIBERATELY NOT adopted, recorded here and in the header banner:** the only thing the sweep can touch is a regenerable copy of the host's own policy that this plugin staged, never operator data, so a wrong wall clock can destroy nothing the next dispatch cannot reproduce (at worst a forward step lets a concurrent sweep contend for the create-to-open window, which fails that dispatch closed as `dest_dir_open_<n>`; the next dispatch succeeds); and liveness of an in-flight dispatch is proven by the OS (the directory is held open without `FILE_SHARE_DELETE`), not by the clock — the one-hour floor only covers the create-to-open window. Part 7 holds (absolute threshold, equality is fresh); a far-future mtime (more than the threshold ahead) also counts as stale, so a clock that ran ahead when a dispatch crashed cannot hide the orphan for as long as the skew — the open handle and the owner gate, not the clock, protect a live directory. The caps are the same values as the `execution_artifacts` sweep, deliberately (identical substrate); the far-future-mtime rule is a deliberate divergence from that sibling, which still reads a future-dated mtime as fresh (the shared-extraction issue #5202 tracks that divergence). Two further divergences from the `execution_artifacts` sweep: this sweep has no in-process clock-step guard (deliberate, per the reasoning above) and no rotating start index, so its failure-capped loop still begins at the first root entry on every pass, the shape #4504 fixed there; both are recorded rather than adopted here. Single-process by construction; no persisted anchor. |
| Spark claim-lifecycle reaper and orphan-key pass (agent, `guardian_spark_runtime`, #5322) | Agent-side, not a store, and **not a clock-guarded retention pass**; listed here as a recorded disposition, not an adoption. `reap_stranded_claims_locked` pops terminal `Queued` claims and `disarm_orphan_keys_locked` queues a Disarm for a watcher whose index refcount is 0; both run under `registry_mu_` from `expire_overdue_claims()` on the heartbeat. **Parts 1-4, 6 and 7 do not apply:** the state is a monotonic in-memory claim lifecycle with no wall-clock cutoff, no persisted anchor and no age-based delete (a claim is popped because of its state, not its age), and a restart empties it, so a wrong wall clock cannot destroy anything and there is no anchor for part 6 to decide about. **SINGLE-WRITER:** n/a (agent-local, process-local state). **Part 5 (an unconditional per-pass cap) declined:** the bound is structural, not a configured cap: the number of `claims_` entries for the reaper and the number of `keys_` entries for the orphan pass, both walked under `registry_mu_`, with one index-release attempt per terminal tombstone per pass (at most two in the pass that synthesizes the outcome of a head that has none); a partial pass would only lengthen recovery. Recorded in the header banner "Not a clock-guarded retention pass" above `reap_stranded_claims_locked` and `disarm_orphan_keys_locked` in `guardian_spark_runtime.hpp`. |
| Guardian reconcile claim-map sweep (server, `GuardianReconcileGate::sweep()`, #5513) | Server-side, not a store, and **not a clock-guarded retention pass over durable data**; listed here as a recorded disposition, not an adoption. `sweep()` erases per-agent heartbeat-reconcile claims older than `2 * min_interval` (50 s, `min_interval` being the 25 s per-agent limit) from an in-memory map, called every 15 s from `health_recompute_thread_` on every replica (classified `ReplicaSafe` as `guardian_reconcile_gate.sweep` in `background_jobs.hpp`, never leader-gated). The cutoff is a `steady_clock` reading over no store and no durable data, and a restart empties the map. **Parts 1-4 and 6 do not apply:** there is no wall-clock cutoff, no persisted anchor and nothing durable to destroy, so there is no anchor for part 6 to decide about; a claim older than `min_interval` can no longer rate-limit anything, so deleting it changes no decision, and the `2x` margin only keeps an entry visible slightly longer than it is useful. A clock that jumps cannot cause a wrong bulk delete of live state: `steady_clock` is monotonic, an entry that appears older than it is is merely re-claimed on its next heartbeat, and a clock reading that moves backwards yields a negative age, which is never swept. **Part 5 adopted, as structural caps:** each call erases at most `kDefaultSweepMaxErase` (4096) entries and scans about `kDefaultSweepMaxScan` (16384) units, resuming from a persistent bucket cursor, so one call never holds the mutex for a whole 500,000-entry table; the consequence, estimated (not measured) in the gate header, is that a full cycle over about 500,000 claims takes about 90 ticks (about 20 minutes), so the sweep is a backstop and the bulk of the map is bounded by `decide()` erasing an expired claim when its agent next reports a converged generation. **Part 7 holds:** the threshold is absolute (`2 * min_interval`, never scaled) and an entry whose age is not strictly greater than it is kept. **SINGLE-WRITER:** n/a by design, because the state is per replica (each replica's claim map, budget and caches are its own, with no shared row), so the single-replica form of the rule is correct here. Reasoning recorded in the "RETENTION REASONING" block of `guardian_reconcile_gate.hpp`. |

### Recorded dispositions (not adoptions)

| Store | Notes |
|---|---|
| `CommandOutboxStore` (#6096) | No reaper exists today. Its rows are the schedule runner's SPENT-TICKET LEDGER (`approval_id`, read by `occurrences_for_approval`), so any future reaper must retain approval-bearing rows at least 7 days from creation (`kApprovalTicketTtlSeconds`), or a reaped row makes a spent ticket look unspent. Stated at the store header as well. |
| `ApprovalManager` expiry sweeps (#6061, #6096) | Status transitions to `expired`, never a DELETE. Every stamp and cutoff is Postgres `now()` in-SQL, including `submitted_at` since #6096, so the sweep clock is no longer split between the submitting process and the database. Disposition and residuals: "`ApprovalManager` ticket liveness" below. |

### Still issuing bare wall-clock deletes

The three tracked **#2508** background sweeps (`app_perf_fleet_store`,
`PreflightRunStore`, `DeploymentRunStore`) adopted the guarded shape via
`pg::run_clock_guarded_prune` in WS-10 — see the register entry above.

One lower-exposure bare wall-clock delete remains, OUT of the #2508 background-sweep
scope: `app_perf_daily_store.cpp`'s `apply_daily` does a per-agent
`DELETE ... WHERE agent_id=$1 AND day < cutoff` (cutoff from `system_clock::now()`)
INLINE during that agent's own daily-perf ingest — not a background bulk sweep. Its
blast radius is one agent's own rows, bounded by the retention window, and it is
driven by that agent's data arriving rather than a timer, so a wrong server clock
cannot wipe the fleet's history in one pass. Whether to bring it under the guard (or
a bounded per-agent variant) is a tracked follow-up, not part of WS-10's
background-sweep scope.

### `api_token_store` — first store to DECLINE part 1's would-wipe half

It declines outright rather than adopting or re-tuning it: its eligible population reaches 100%
expiry as routine drain behaviour (unlike a long-lived time series, where that can only mean the
cutoff moved), so a would-wipe verdict cannot separate a true and a false positive there at any
population size. See `api_token_store.cpp`'s DELIBERATE NON-ADOPTION comment for the recorded part-6
reasoning — not a silent omission.

Its part-6 answer for a missing anchor is `audit_store`'s (decline). Its constants (3'600s big-step
floor, 200-per-tick cap, 60s tick cadence) are substrate-tuned like every sibling's — **copy the
SHAPE from it, never the numbers, in either direction.**

### `SessionStore::reap_expired` (HA WS-1/1a, ADR-2002 §4)

The former `auth_db` in-memory-monotonic session sweep is GONE — operator sessions are now durable
Postgres rows in `SessionStore`, so its `reap_expired` IS a wall-clock retention pass and JOINS this
guarded set with parts (2)/(3) persisted+sanitised anchor, (5) unconditional cap, (6) recorded
missing-anchor decision (**PROCEED** — sessions are re-mintable via re-login, `ResultSetStore`'s
answer), plus the advisory-lock own-statement AND a backward-anomaly decline (`now < anchor`).

Since **#3715** (DB-clock authority) `reap_expired()` reads Postgres `now()` ITSELF — one in-SQL
reading for cutoff + anchor-compare + anchor-update, the same clock that authors `expires_at` — so
`clock_anomaly` is the **DB-PRIMARY** signal (`yuzu_auth_session_reap_clock_anomaly_total`),
DISTINCT from the local host-clock drift counter (`yuzu_auth_local_clock_backward_total`). **Never
split the two clock domains, and never re-add a caller-supplied `now_ms`.**

It DELIBERATELY carves out parts (1) and (4), the `api_token_store` precedent:
1. **NO would-wipe probe** — sessions reach 100% expiry as routine drain, so a would-wipe verdict
   cannot separate a true from a false positive.
4. **NO fact-set anomaly dedup** — a declined pass is `spdlog::warn`'d AND surfaced as
   `yuzu_auth_session_reap_clock_anomaly_total` (the ADR-2002 §4 mitigation-(a) monitor) rather than
   deduped by fact identity.

These two carve-outs are recorded here per part (6)'s "record which way you went" requirement, NOT
the full 7. SINGLE-WRITER today (the one server); becomes PG-shared-state under the ADR-0012
advisory lock when a 2nd replica lands.

### `GatewayRouteStore::reap_stale_routes` (HA WS-4 slice 4.2a, hardened PR #4299)

JOINS this guarded set on the `SessionStore::reap_expired` shape (`pg_try_advisory_xact_lock`
own-statement `gateway_route_store:reap` — all but the holder skip, PR #4299 round-2 external
review — in-SQL DB `now()` read once for both cutoffs + anchor-compare + anchor-update,
persisted+sanitised `route_meta` anchor, forward/backward-anomaly decline, unconditional
per-predicate cap):

1. **NO would-wipe probe** (DELIBERATE carve-out, the `api_token_store`/`SessionStore` precedent) —
   the `agent_routes` table legitimately drains toward "every lease expired" as ROUTINE behaviour (a
   fleet going offline overnight expires every lease), so a would-wipe verdict cannot separate a true
   from a false positive here.
4. **Fact-set anomaly dedup is ADOPTED** (PR #4299 review; an earlier revision carved this out too,
   the way `SessionStore` does — that was the defect this fix closes), keyed on the TRIPLE
   **(declined `reap_anchor_ms` value, anomaly DIRECTION, `first_now_ms` — the reading the anomaly
   was first observed at)** (round-2 external review added DIRECTION; the round-4 review added the
   `first_now_ms` reading-continuity window — see "Direction-keyed, not anchor-value-alone" and
   "Reading-continuity recovery window" below) rather than the full multi-field `Facts` struct
   `audit_store.cpp` uses. A forward- or backward-skew anomaly persists
   `route_meta.reap_declined_anchor_ms = "<reap_anchor_ms>:<direction>:<first_now_ms>"` and declines;
   a repeat RECOVERS — runs both sweeps under the cap, advances `reap_anchor_ms` to `now_ms`
   UNCONDITIONALLY (never `max(anchor, now_ms)`, which would leave a forward-skew-poisoned anchor
   stuck forever), and clears the declined-anchor marker — **only when ALL of**: the anchor is still
   unmoved (a decline never advances it), the direction matches, AND the anomaly has PERSISTED a
   real-time-plausible interval `delta = now_ms - first_now_ms` in
   `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]` (270s..1h). Below the floor it re-declines
   PRESERVING the original `first_now_ms`; above the ceiling, or on a negative delta (a
   further-backward step), it is a NEW distinct anomaly and re-declines against the CURRENT reading. A
   DIFFERENT-direction anomaly at the SAME frozen anchor (e.g. a backward-skew decline followed by an
   unrelated forward-skew reading) also does NOT match — it re-declines and re-arms against the new
   direction. A normal (non-anomalous) accepted pass also clears the marker, so a later transient
   glitch is judged fresh against the new anchor rather than free-riding on a stale recovery.
   **Why this mattered**: the carved-out version wedged PERMANENTLY after any routine >24h gap
   (weekend shutdown, DR failover, extended maintenance) — `now - anchor` only grows while declined,
   so every subsequent pass declined forever with no recovery path. **Corrected: a genuine gap that
   PERSISTS a plausible interval at the same (anchor, direction) recovers on the pass that clears the
   floor.** **Correcting the old "oscillates every other pass" note (round 4):** under the
   floor/ceiling window a clock stepping BACKWARD every pass, or FORWARD by more than the ceiling
   every pass, now DECLINES every pass and never recovers until it stops drifting — this is
   deliberately stricter and correct (recovery is reserved for a genuinely-persisted gap, not a
   still-drifting clock), and it is observable via `outcome="declined"`. The **operator re-anchor**
   (reset `route_meta.reap_anchor_ms` and, for cleanliness, `route_meta.reap_declined_anchor_ms` to
   the corrected current epoch-ms once the underlying clock is fixed) is an OPTIONAL escape hatch to
   force recovery early, not a requirement to un-wedge anything — see the code comment at
   `gateway_route_store.cpp`'s anomaly-detection site. Every
   decline is `spdlog::warn`'d AND counted:
   `yuzu_server_gateway_route_reap_total{outcome="declined"}` (incremented at the reap call site in
   `server.cpp`, pre-seeded across `ok`/`ok_capped`/`recovered`/`declined`/`skipped`/`error`;
   `skipped` added round-2 external review, `ok_capped` added round 4). This
   is a DEDICATED reap-outcome counter, distinct from
   `yuzu_server_gateway_route_desync_total`/`_write_failed_total`, which cover the WRITE path
   (`register_fresh`/`announce_connected`/`deregister`/`renew_leases`), not a reap pass's own outcome.
   A reap pass that fails outright (pool/query degradation, distinct from a clock-anomaly decline) is
   counted the same way under `outcome="error"`; a clean, ORDINARY accepted pass is `outcome="ok"`
   (or `outcome="ok_capped"` — see the reading-continuity + non-acceleration note below); a
   pass that ran via the recovery branch above is its own `outcome="recovered"` (PR #4299 round-2
   review, `ReapRoutesResult::recovered`) — a recovery can drain a large backlog in one go, so it is
   metric-distinguishable from a routine `ok` tick rather than reading identically to one.

   **Direction-keyed, not anchor-value-alone (PR #4299 round-2 EXTERNAL review — corrects the
   round-2 review's own "cross-type recovery is safe" conclusion above, which this fix replaces).**
   The initial round-2 fix keyed recovery on `declined_anchor == anchor` alone, blind to whether THIS
   pass's own anomaly is forward- or backward-classified, or whether it matches the classification of
   the pass that froze `declined_anchor` in the first place — so a BACKWARD-skew decline (pass 1)
   followed by a DIFFERENT, unrelated FORWARD-skew reading (pass 2) at that SAME anchor satisfied the
   match and recovered, running the sweeps against pass 2's own forward-skewed (implausibly-huge)
   `now_ms` — mass-tombstoning live leased routes and letting sweep (b) hard-delete pre-existing
   NULL-lease (in-handshake `register_fresh`'d) rows. That "only a forward-classified recovery can
   mass-reap, so keying just needs to gate the forward direction" reasoning was the defect: it treated
   the CURRENT pass's own classification as sufficient, but never checked that the CURRENT anomaly is
   the SAME anomaly as the one that froze the anchor. A single fresh forward anomaly that should
   decline-once instead drained because an unrelated prior backward decline happened to freeze the
   same anchor value. The fix compares the FULL fact set — (anchor, direction) — never a value-only
   latch: recovery requires the declined marker's direction to match THIS pass's own direction, so a
   direction change at the same anchor re-declines (and re-arms against the new direction) instead of
   recovering. Anomaly-type keying is therefore load-bearing, not unnecessary complexity — see the
   corrected "Fact-set anomaly dedup is ADOPTED" bullet above and `gateway_route_store.hpp`'s
   `reap_stale_routes` doc comment for the marker format (`"<anchor>:<direction>:<first_now_ms>"`) and
   its mixed-version-safe parse (an unparseable value — a legacy 2-field marker, this store's own
   3-field value read by an older 2-field parser, or a value with the wrong field count — is treated
   as absent and re-declines).

   **Reading-continuity recovery window (PR #4299 round 4 — corrects the "recovers on the next pass"
   reasoning above to require a plausible persistence interval).** Matching the frozen (anchor,
   direction) pair proved the anomaly REPEATED, but not that it PERSISTED: a second, unrelated,
   much-larger same-direction jump at the same frozen anchor satisfied the pair-match and recovered
   on its FIRST appearance (running the sweeps against that second reading). The fix records the
   reading the anomaly was FIRST observed at (`first_now_ms`, the marker's third field) and bounds
   recovery to `delta = now_ms - first_now_ms` in `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]`:
   below the floor it re-declines PRESERVING the original `first_now_ms` (never resetting it, or
   offset replicas ticking a few seconds apart would reset it forever = a wedge); above the ceiling
   (or a negative delta) it is a NEW distinct anomaly, re-declined once against the current reading.
   The FLOOR = `(kStaleLeaseGraceSecs + kKnownLeaseTtlSecs) * 1000` = 270'000ms — the liveness
   horizon below which a spurious forward jump's exposed routes are not yet reap-eligible — and it is
   **load-bearing for the multi-replica future this slice exists for**: without it, an ε-later
   second-replica reap pass would recover with zero persistence evidence. The CEILING = 1h
   (cadence-derived with slack), `static_assert`ed `<= kMaxPlausibleSkewMs` (the terminating
   invariant, scoped precisely: this bounds the per-pass PERSISTENCE INTERVAL a recovery may credit
   — `delta = now - first_now <= 1h` — NOT the total forward jump a recovered pass sweeps against,
   which is necessarily `> 24h` by construction since that jump is what triggered the anomaly; the
   terminating property is that the persistence evidence a recovery requires can never be widened
   past `kMaxPlausibleSkewMs`, the same horizon within which a clean pass already accepts a forward
   jump untreated, so the window cannot grow unbounded) and, of course, `>` the floor. TWO
   companion `static_assert`s at `server.cpp`'s reap-cadence constant bracket the inter-pass
   interval (`kGatewayRouteReapEveryNTicks * kMaintTickSecs`, ~300s), and they guard OPPOSITE
   failures — only the ceiling one is a true wedge: (a) the FLOOR assert (interval `>` the floor)
   is a PROMPTNESS guard — a sub-floor cadence still recovers, because `first_now_ms` is preserved
   across declines so its delta grows monotonically, just over multiple passes rather than on
   pass 2 — so a future cadence below ~135 ticks is a build failure only because prompt recovery
   is wanted, not because it would wedge; (b) the CEILING assert (interval `<` the ceiling) IS the
   wedge guard — above it every pass-to-pass delta exceeds the ceiling, so each pass re-arms as a
   brand-new anomaly and never recovers (a future cadence above ~1800 ticks is a build failure for
   this reason). A THIRD faulted-but-not-wedged regime rounds out the corrected narrative above: a
   FROZEN or sub-floor-oscillating clock leaves the delta pinned below the floor, so the pass
   declines every tick until the clock advances by at least the floor from the first reading —
   self-resolving, fail-safe (a broken clock must not drive reaping), and observed by the WS-1/1a
   DB-clock-integrity monitor rather than this reaper.

   **ACCEPTED LIMITATION — the persistence window has a single time source (PR #4299 round-5 review,
   recorded, revisit before multi-replica / 4.2b).** `delta = now - first_now` is measured entirely on
   the Postgres `now()` clock — the same clock whose step triggered the anomaly. There is NO independent
   witness, so a SECOND, unrelated clock step that happens to land inside `[floor, ceiling]` of the first
   observation is indistinguishable from a genuine, continuous persistence and would satisfy the recovery
   bar (a "compound step fusion"). This is accepted, not fixed, for three reasons: (1) on the
   single-replica deployment that exists today the reaper's own next pass cannot arrive sooner than the
   cadence (`static_assert`ed `>` the floor), during which routine heartbeats (`renew_leases`,
   `lease_until = now()+90s` in-SQL) re-lease every live route out of sweep eligibility regardless of what
   the DB clock does between passes; (2) the harmful case needs a SECOND independently-ticking replica
   (none exists — this store is single-writer today) PLUS 4.2b's dispatch-authoritative reader (deferred)
   PLUS a compound anomaly, stacked; (3) the obvious fix — a process-local `steady_clock`/monotonic
   witness — does NOT close it: a local witness can only attest THIS host's clock, never prove a SECOND
   replica's persistence, which is the only case where the gap is load-bearing. So there is no cheap fix
   available today; the honest resolution is to record the limitation and revisit it when a real
   independent time source (or a shared-clock coordination primitive) exists, before multi-replica or 4.2b
   ship.

   **Cap-backlog observability, NOT acceleration (PR #4299 round 4 — the architect OVERRODE the
   reviewer's "accelerate the re-arm on a capped sweep" suggestion; recording the reasoning is the
   requirement, per this concern).** When a sweep hits `kReapCap`, a same-txn `EXISTS` probe (the
   `audit_store.cpp` shape) checks for a genuine remainder and, if present, sets
   `ReapRoutesResult::cap_bound` — surfaced as a distinct `outcome="ok_capped"`. The cadence is
   DELIBERATELY unchanged. Acceleration is declined because: `agent_routes` is `PRIMARY KEY(agent_id)`,
   fleet-bounded and self-limiting (unlike `audit_store`'s append-only, unbounded-growth table); `is_stale`
   is computed IN-SQL at read time, so NO correctness depends on reap latency (a not-yet-reaped stale
   row still reads as stale); and accelerating would turn a mis-recovery into `kReapCap` tombstones
   every few seconds, collapsing the operator reaction window. The `ok_capped` metric is the chosen
   signal instead: a chronically cap-bound reaper is visible to an operator without a cadence change.
   ONE-TICK OBSERVABILITY NOTE (PR #4299 round-5 review, LOW): the emit cascade gives `recovered`
   precedence over `cap_bound`, so a pass that BOTH recovers AND hits `kReapCap` emits only
   `outcome="recovered"` for that tick, never `ok_capped`. This is deliberate (a recovery is the rarer,
   more operationally notable event) and not a correctness gap: `is_stale` is read-time, the backlog is
   not lost, and if it persists the next ordinary capped tick surfaces `ok_capped` as usual. It is a
   single-tick under-count of the cap signal on the exact tick a recovery also caps, nothing more.

   **The decline-once/drain-on-repeat recovery above is the SKEW path only — a corrupt PERSISTED
   anchor uses a DIFFERENT mechanism (PR #4299 round-3 review).** An unparseable or negative
   `route_meta.reap_anchor_ms` reading never reaches the skew logic at all — it is a separate guard,
   checked first, because it is a durably PERSISTED value rather than a fresh-every-pass `now()`
   reading: this method is the anchor's sole writer and always writes a sanitised non-negative i64,
   so an invalid stored value can only be external tampering/corruption. Declining it without
   repair (the pre-round-3 behaviour) wedged EVERY future pass permanently, since the skew
   recovery's (anchor, direction) match is never reached from this branch. The fix is
   SELF-HEAL, not drain-on-repeat: on a corrupt persisted anchor, re-anchor `reap_anchor_ms` to
   this pass's own already-sanitised `now_ms` (never the anchor's old value), clear
   `reap_declined_anchor_ms` (a stale skew marker must not be judged against the freshly
   re-anchored value), and decline only THIS one pass. The next pass then reads back a valid,
   now()-derived anchor and proceeds as an ordinary accepted pass. Drain-on-repeat is deliberately
   NOT used here: a corrupt/garbage anchor is not evidence of genuine elapsed downtime the way a
   persisting skew is, and auto-draining on evidence of tampering risks a mass-reap against
   garbage data. Net effect: neither anomaly class — skew or corrupt-anchor — leaves the reaper
   permanently wedged, but they recover via two distinct mechanisms (decline-once/drain-on-repeat
   vs. self-heal-and-re-anchor), and only the skew path is the "no permanent wedge either way"
   claim above.

   **Marker-obligation rule (PR #4299 round-3 — decide/apply split).** The recovery mechanisms above
   hinge on a single invariant that had THREE rounds of the same defect (one terminal/decline path
   forgetting its marker decision): **every lock-holding pass that COMMITS writes
   `reap_declined_anchor_ms` exactly once — ARM or CLEAR; LEAVE exists only for passes that never read
   `now()` (the advisory-lock skip) or that roll back.** Any DISTINCT anomaly — a skew/direction
   mismatch, a bad `now()` reading, OR a corrupt persisted anchor — CLEARs or re-ARMs the marker,
   never LEAVES a stale recovery identity a later same-direction skew could free-ride on. The
   bad-`now()` path specifically now CLEARs (the round-3 fix — it used to LEAVE the marker, so a
   distinct bad-now anomaly followed by a matching-direction skew at the same anchor could recover on
   what was really its first skew pass). The class is closed STRUCTURALLY, not by a fourth hand-patch:
   the decision is computed by the pure `decide_reap` in `server/core/src/gateway_route_reap_rules.hpp`,
   whose `ReapDecision::marker` is a `MarkerAction` with no default constructor — a reap branch that
   omits the marker decision is a COMPILE error (the `ExecuteGate` discipline). The store's
   `reap_stale_routes()` does I/O only: the lock, three reads, and ONE apply tail (the sole `return
   true` after the lock). `decide_reap`'s five-decision set is unit-tested with no Postgres in
   `tests/unit/server/test_gateway_route_reap_rules.cpp`; the `[pg]` tests in
   `test_gateway_route_store.cpp` remain the integration layer asserting the apply tail wires onto the
   right SQL.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer): a route is
regenerable by the agent's next heartbeat/`ProxyRegister`, so a from-boot skewed clock reaping a
batch of already-stale routes on the first pass is an acceptable worst case, never non-reproducible
evidence loss.

Two predicates sweep in the same pass, both capped independently (`kReapCap = 5000`, matching
`SessionStore`'s shape — never its number): (a) `lease_until` past a grace window of `2x` the 90s
lease TTL (`kStaleLeaseGraceSecs = 180`) — TOMBSTONES the row (same shape as `deregister`, retaining
`connection_epoch`) rather than deleting it, because the associated session may still be alive and
merely stopped renewing; (b) a NULL-lease row (a real tombstone, or a row stuck since
`register_fresh` that never got an `announce_connected`) whose `updated_at` is past a SHORT purge age
(`kTombstonePurgeAgeSecs = 300`) — hard-DELETEs it, since by that age a late CONNECTED/DISCONNECTED
resurrecting it is not a realistic risk and a genuine later `register_fresh` works identically
whether the row exists or not. The implausible-forward-skew bound (part 1) is this store's own,
NEVER copied from a sibling: `kMaxPlausibleSkewMs = 1 day`, sized against this store's own
sub-ten-minute liveness horizon (grace + purge-age ≈ 480s), not `SessionStore`'s 366-day bound (sized
to a human session's plausible lifetime).

SINGLE-WRITER today (one dedicated advisory-lock key, `gateway_route_store:reap`); becomes
PG-shared-state under the same ADR-0012 lock when a 2nd replica lands, matching every sibling in this
register. See `gateway_route_store.hpp`'s `reap_stale_routes` doc comment for the full record.

### `ExecutionTracker::reap_command_execution_mappings` (HA WS-1(1b))

JOINS this guarded set on the identical shape (advisory-lock own-statement, in-SQL DB `now()` read
once for cutoff/anchor-compare/anchor-update, persisted+sanitised `reap_meta` anchor,
forward/backward-anomaly decline, unconditional cap) and makes the SAME two carve-out choices
`SessionStore` made, for the SAME reason:
1. **NO would-wipe probe** — the `command_execution` table drains to 100% expiry as routine behaviour
   (every dispatch record ages out 24h after it was last written; a read never consumes or deletes
   one), so a would-wipe verdict cannot separate a true from a false positive.
4. **NO fact-set anomaly dedup** — a declined pass is `spdlog::warn`'d and surfaced via
   `yuzu_exec_correlation_reap_clock_anomaly_total` rather than deduped by fact identity.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer). What an early deletion
costs changed with #4990: a row is no longer only a correlation aid, it is the server's dispatch
record, the source of the plugin label a response is stored under (`response_provenance.hpp`). A
command whose record is deleted early answers as `~unverified`: its responses are withheld from
callers without `Forensics:Read`. That fails closed, never toward disclosure, and it is the cost this
decision accepts; it no longer rests on the record being regenerable (it is not).

**The per-pass cap is RE-DECIDED to 50,000 (#4990), recorded reasoning rather than a copied
number.** The table held one row per TRACKED execution; it now holds one row per DISPATCH, including
per-agent system pushes (`__guard__` policy pushes, `asset_tags` sync), so inflow can reach one row
per connected agent per fleet-wide event, and the old cap (5000 per pass, 120k rows/day of reclaim at
a ~60 minute cadence) would let the table grow without bound once inflow exceeded that. The sizing
assumptions are stated in the code and not measured on a fleet: a short-term target of about 5,000
agents (about 1e4 rows/day organically, a few 5,000-row bursts per fleet event) and a long-term
target of 500,000 agents (one fleet-wide per-agent event = 500,000 rows). 50,000 rows x 24 passes =
1.2M rows/day of reclaim, which is a sustained inflow of about 14 dispatch records a second. That
covers the short-term target by two orders of magnitude (240 fleet-wide events a day). At the
long-term target it covers up to two fleet-wide per-agent events a day (1.0M rows) plus about 0.2M
rows of other dispatches; a third event (1.5M rows) is above the reclaim rate. A burst is drained over
the following passes (a 500,000-row burst past the window takes ten), but a SUSTAINED inflow above
1.2M rows/day saturates the cap on every pass and the table then grows by the difference (about
210 bytes a row measured before the `execution_id` index of migration 7, roughly 250 for a tracked row with it: reasoned, not measured). The same ceiling applies to API-driven dispatch: a sustained rate
above about 14 a second saturates it, and a per-principal or per-address inflow quota is NOT part of
this bound (it is tracked as a separate follow-up).

The pass deletes with `DELETE .. WHERE ctid = ANY(ARRAY(SELECT ctid .. WHERE created_at < cutoff
ORDER BY created_at LIMIT cap)) AND created_at < cutoff`. Measured on synthetic time-ordered tables
(PostgreSQL 16, the exact statement, rolled back and repeated 5 to 6 times, cap 50,000): median 34 ms
at 1M rows and 35 ms at 10M. The earlier `IN (SELECT command_id .. LIMIT n)` form planned a Hash Semi
Join over a Seq Scan of the whole table, so its cost followed the table, not the cap (180 ms at 1M
rows, 1.74 s at 10M); the `ctid` form reads only the cap's worth of index entries, so the pass cost
follows the cap. The repeated `created_at < cutoff` test in the outer statement keeps a record that
`record_command_dispatch` refreshed between the selection and the delete (a refreshed row also
changes its `ctid` and is skipped by the match; the re-test states the same rule explicitly). A pass
holds row locks only on rows already past the window. The cap stays an UNCONDITIONAL bound on the
work one pass (and one skewed-clock pass) can do. Saturation is visible and alerted: a pass that
deletes exactly the cap moves `yuzu_exec_correlation_reap_total` by the cap every hour, and the alert
`YuzuExecCorrelationReapSaturated` fires when the counter has risen by at least 200,000 over 6 hours
for 24 hours running. The ~60 minute cadence is not shortened, because the clock-anomaly threshold is
sized against it. The sibling event-outbox reap keeps its own cap; its window and skew values stay
identical to this table's on purpose, its cap does not (`execution_tracker.cpp`, beside
`kCmdExecutionReapCap`).

### `ExecutionTracker::reap_stuck_running_executions` (#4982 Part B, fix round 2)

Diverges from this file's two DELETE-based siblings immediately above in kind, not just detail: this
sweep **MUTATES** live `execution_tracker.executions` rows (cancels a `running`/`agents_targeted=0`
row past a 30-minute window, excluding anything with a still-`pending` `command_outbox_store.outbox`
entry) rather than deleting from a regenerable observability table, so its part-1/part-4 choices
invert theirs:

1. **Would-wipe IS ADOPTED** (unlike `reap_command_execution_mappings`/`reap_event_outbox` above,
   which decline it). Their tables drain to 100% expiry as ROUTINE behaviour, so a would-wipe verdict
   there cannot separate a true positive from ordinary drain. This sweep's candidates are the
   opposite: a healthy fleet's running executions resolve `agents_targeted>0` within seconds, so
   candidates should always be a SMALL minority of the running population — a pass whose candidates
   are a LARGE fraction (`kStuckExecWouldWipeRatio = 0.5`, floored at `kStuckExecWouldWipeFloor = 20`
   total running executions below which the ratio is too noisy to mean anything) is evidence of a
   systemic bookkeeping bug (e.g. a broad regression in a synchronous dispatch call site's own
   `set_agents_targeted` call), not a genuine backlog, and acting on it risks mass-cancelling live
   work.
4. **Fact-set anomaly dedup IS ADOPTED, at a DELIBERATELY simpler width than `GatewayRouteStore`'s.**
   The original Part B implementation carved this part out entirely (matching the DELETE-based
   siblings) — and wedged PERMANENTLY after any routine >24h clock gap (a weekend, a DR failover,
   extended maintenance) as a result: a decline never advances the primary `stuck_exec_reap_anchor`,
   so `now_s - anchor` only GROWS on every later pass with no recovery path short of an operator
   hand-editing `reap_meta`. This is the identical defect class `GatewayRouteStore::reap_stale_routes`
   above was fixed for (PR #4299). The fix round 2 correction adds a SECOND persisted marker,
   `stuck_exec_reap_declined = "<anchor>:<direction>"` (direction ∈ forward|backward) — a REPEAT
   anomaly at the exact SAME (anchor, direction) as a marker armed by a full prior decline pass
   re-anchors to the CURRENT `now_s` UNCONDITIONALLY and runs the ordinary would-wipe/candidate/cancel
   logic for that pass (a genuine backlog then drains gradually across passes under the same cap,
   never trusted all at once); a DIFFERENT-direction anomaly at that frozen anchor, or the very first
   occurrence of any anomaly, still declines and arms/re-arms the marker against its own (anchor,
   direction) — mirroring GatewayRouteStore's own direction-keyed fix (a value-only match let an
   unrelated different-direction anomaly free-ride a frozen anchor and recover against a corrupted
   reading, that store's round-2 external-review defect).

   **Part-6 recovery mechanism (the doc's own "record which way you went" philosophy, applied to a
   SECOND question this row's own history raised — not just the missing-anchor one below).**
   DELIBERATELY OMITTED here: GatewayRouteStore's third marker field, `first_now_ms` (the reading an
   anomaly was FIRST observed at), which bounds recovery to a real-time-plausible PERSISTENCE INTERVAL
   rather than a bare (anchor, direction) match — without it, an ε-later second-replica pass reading
   the SAME frozen marker recovers with zero persistence evidence (that store's own round-4 fix). This
   gap is real in general but judged SAFE to omit for THIS sweep specifically: a too-eager recovery
   here can only feed a still-corrupted `now_s` into the SAME would-wipe ratio guard and the SAME
   unconditional per-pass cap (`kStuckExecReapCap = 500`) this sweep already carries for every
   accepted pass — a spuriously-huge cutoff makes candidates a LARGE fraction of all running
   executions (would-wipe's own job to catch) rather than a targeted, silent mass-cancel, and the
   blast radius is additionally capped at 500 ATOMICALLY-rechecked rows, each individually
   re-verified against LIVE state at cancel time (the fix round 2 TOCTOU close, below) — never a bare
   cutoff-matched DELETE/UPDATE the way GatewayRouteStore's own route-tombstone sweep is.
   GatewayRouteStore has neither safety net for its own sweeps, which is why ITS omission of this
   field was genuinely unsafe. If a future change ever removes any of these safety nets here, this
   omission must be re-examined against the same reasoning GatewayRouteStore's own entry above
   records.

   **Round-3 correction — the would-wipe FLOOR is not a safety net on a recovery pass.** The
   paragraph above originally claimed the blast radius was bounded "even below the would-wipe
   floor" by the per-pass cap alone — that was wrong: the floor (`kStuckExecWouldWipeFloor = 20`)
   exists to SKIP the ratio check entirely on a small running population, so on a fleet with fewer
   than 20 running executions, a corrupted recovered `now_s` could make its ENTIRE running
   population look stuck with no ratio check to decline the pass — the 500-row cap does not help
   here, since the affected population is already smaller than the cap. Fixed by bypassing the
   would-wipe FLOOR (never the ratio itself) specifically on a pass that took the recovery branch
   above (`recovering_from_clock_anomaly` in `execution_tracker.cpp`) — a recovered reading is, by
   construction, one this sweep already judged untrustworthy once, so the small-population
   noise-floor reasoning that justifies skipping the ratio check on an ORDINARY clean pass does not
   apply to it. The 50% ratio check is unchanged and still applies on every recovery pass, so the
   bound this omission now rests on is "at most a minority of the running population, of any size,
   per recovery pass" — the same bound an above-floor ordinary pass already carries.

   **Round 4/5 note — the floor-bypass residual is scoped to ONLY the recovery pass itself, recorded
   as an accepted trade-off, not fixed.** Both round-4 adversarial reviewers (graded MEDIUM,
   non-blocking) flagged that a PERSISTENT, multi-pass corrupt clock on a below-floor fleet re-enters
   the floor's ordinary ratio-skip on the pass immediately AFTER recovery (the marker is cleared once
   recovery fires, so a second bad reading right behind the first is not itself covered) — a residual
   this branch narrows relative to the pre-fix permanent wedge, not one it introduces. The
   fully-robust fix is the same GatewayRouteStore-style persisted `first_now_ms` distrust window
   `DELIBERATELY OMITTED` above, spanning multiple passes rather than one; it remains future,
   separately-scoped work rather than part of this round.

**Claim+mutate atomicity (fix round 2, not a clock-guard part but load-bearing for the SINGLE-WRITER
rule above).** The original Part B design selected candidates under the advisory lock, then cancelled
each one via a separate post-commit `mark_cancelled()` call after the lock released — a TOCTOU window
in which a candidate could receive a genuine dispatch between the select and the cancel (force-
cancelling a live, still-executing command), and a window in which two replicas could each acquire the
lock in sequence and both select overlapping candidates, exceeding the declared cap fleet-wide per
cadence. Fix round 2 moves the ENTIRE claim+mutate sequence — candidate select, would-wipe check, and
a single atomic `UPDATE ... RETURNING id` re-checking the FULL candidate predicate (not just a
terminal-status guard) — inside the SAME lock-held transaction, and switches the advisory lock itself
from blocking to `pg_try_advisory_xact_lock` (all-but-holder skip, matching this store's
`reap_event_outbox` sibling and `GatewayRouteStore`'s own idiom) so a losing replica's maintenance tick
is never stalled waiting on it.

**Clock-authority caveat (still open, PR #5226 review round 2, Doomgoose).** This sweep's cutoff is
PG `now()` read in-SQL, but `dispatched_at` — the column the cutoff is compared against — is written
from the caller's replica `system_clock` in the common case (`create_execution`'s `now` fallback,
`execution_tracker.cpp`), not PG `now()`. This is the same clock-domain split the
`concurrency_claims` reconciler's own caveat above describes, and it is NOT yet met here either —
unlike that reconciler, though, this sweep stays classed **ReplicaSafe**, not `DisabledUntilFixed`,
because its blast radius on a multi-replica deployment is independently bounded by the would-wipe
ratio/floor and the per-pass row cap regardless of which replica's clock a given `dispatched_at` came
from — a mis-cancelled row is still capped at 500 per pass and still excluded if it carries a real
agent response. A replica meaningfully behind on `system_clock` can still see a fresh dispatch as
already past the stuck-exec window sooner than a correctly-clocked replica would. Not fixed; stamping
`dispatched_at` from PG `now()` at `INSERT` time (mirroring the `concurrency_claims` migration, WS-1
class, #3715 shape, tracked #4093) is the closing move for both.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer): a dispatch that is
genuinely still stuck survives to the next pass regardless of whether this one's cutoff arithmetic
used a fresh or a from-boot-skewed clock, so acting on the first pass against an unverified clock is
an acceptable worst case, bounded by the same would-wipe/cap guards as any other pass.

**Upstream candidate-predicate race (fix round 3, #4982) — closed at the SOURCE, not by widening the
predicate.** Fix round 2's atomic `UPDATE ... RETURNING id` above re-checks `status='running' AND
agents_targeted=0 AND NOT EXISTS <pending outbox row>` at mutation time and calls that the "full
candidate predicate" (as of round 3 — a governance Gate 2 fix below adds a THIRD clause; read that
entry too before treating this round-3 description as current) — but that predicate is only trustworthy if a `'sent'` outbox row genuinely
implies its execution's `agents_targeted` bookkeeping is settled. It was not: `command_outbox_delivery.cpp`
called `CommandOutboxStore::mark_sent` (outbox `pending → sent`) and
`ExecutionTracker::set_agents_targeted` as two SEPARATE autocommit statements. Between the two
commits, a genuinely in-flight, successfully-dispatched command read `state='sent'` (excluded by the
outbox clause) with `agents_targeted` still 0 (matching the predicate's own clause) — a false
candidate for a command that was, in truth, still being delivered/executed, force-cancelled with no
kill RPC ever sent. Fixed by `CommandOutboxStore::mark_sent_with_target`
(`command_outbox_store.{hpp,cpp}`): the sent-transition and the real `agents_targeted` count now
commit in ONE cross-schema transaction on this store's own pool — the same single Postgres
instance/database this reaper's own cross-schema `NOT EXISTS command_outbox_store.outbox` read
already relies on — so no reader can ever observe the two half-applied. A DB/lease failure on either
half rolls BOTH back (the occurrence stays `pending`, re-driven next tick; the agent's `command_id`
dedup, WS-0, absorbs the harmless re-send) rather than leaving `mark_sent` committed with
`agents_targeted` unset. This is a NEW instance of the general lesson every entry in this file
teaches: a reaper's own predicate can be perfectly correctly re-checked and still race, if the WRITE
SIDE it depends on is allowed to commit as two independent halves.

**Corrupt persisted-anchor self-heal (fix round 7, #4982) — closes a permanent wedge distinct from
the skew-recovery marker above.** The skew-recovery marker (round 2, above) rescues a `now_s` that
reads implausibly against a PARSEABLE persisted anchor. It cannot rescue an anchor that is itself
unparseable or negative — that branch returned `clock_anomaly = true` without touching
`stuck_exec_reap_anchor` or `stuck_exec_reap_declined`, and precedes the skew-marker read entirely, so
an anchor corrupted by storage damage, a bad migration, or a manual repair gone wrong took that same
branch on every future pass with no recovery path short of an operator hand-editing `reap_meta` — the
identical permanent-wedge class this file's `GatewayRouteStore::reap_stale_routes` entry above already
fixed for its own sibling anchor. Fixed by mirroring that sibling's corrupt-anchor branch exactly: on
an unparseable/negative persisted anchor, clear `stuck_exec_reap_declined` and re-anchor
`stuck_exec_reap_anchor` to THIS pass's own already-sanitised `now_s`, in the same transaction,
declining only that one pass. Deliberately NOT drain-on-repeat, matching the sibling's own reasoning:
a garbage anchor is not evidence of genuine elapsed downtime the way a persisting skew is, so the
repaired pass still declines the actual sweep and the NEXT pass is the first to act on the healed
anchor.

**Real-agent-response exclusion (governance Gate 2 fix, #4982, BLOCKING, security-guardian,
empirically reproduced) — the candidate predicate gains a THIRD clause.** The round-3 fix above
closed the race against the WRITE side (`mark_sent`/`set_agents_targeted` committing as two
halves) for an OUTBOX-originated dispatch. It said nothing about a SYNCHRONOUS REST/MCP dispatch
that never touches the outbox at all: if that dispatch genuinely reached one or more agents (real
responses recorded in `agent_exec_status` via `update_agent_status`, independently of
`agents_targeted`) but the dispatcher's OWN `set_agents_targeted` bookkeeping write failed,
`agents_targeted` stayed `0` forever — `refresh_counts_once`'s terminal transition requires
`agents_targeted > 0` to ever fire — and this sweep force-cancelled that row at the 30-minute mark
regardless of how many agents actually succeeded, since nothing in the predicate checked for a
real response. Reproduced: 3 genuine `SUCCESS` responses recorded, `agents_targeted` never set,
the sweep still cancelled the row and published a terminal `execution-completed` event
misrepresenting a working execution as cancelled.

Fixed by a third shared clause, `kNoAgentResponseExistsClause` (`execution_tracker.cpp`, same
file-scope anonymous-namespace shape as the window/cap constants above): `NOT EXISTS (SELECT 1
FROM execution_tracker.agent_exec_status WHERE execution_id = executions.id)`, `AND`-ed into all
THREE predicate occurrences (the candidate-count SELECT, the candidate-select SELECT, and the
atomic cancel UPDATE's own re-check). **This does NOT narrow Part B's original scope**: a dispatch
refused BEFORE any agent was ever reached (a degraded pre-dispatch quota check, zero agents
matched the target scope, a dispatch exception, a lost `create_pending` race — Part B's actual
target population) has ZERO `agent_exec_status` rows, so the new clause is vacuously satisfied and
such a row is still recovered exactly as before. Only a row with at least one genuine per-agent
response is now additionally excluded — and that exclusion is permanent, by design: leaving a row
with a real response wedged (the pre-fix behaviour, now narrowed to exactly this population) is
strictly safer than falsely cancelling it, since there is no repair path today that re-derives
`agents_targeted` from `agent_exec_status`. Verified bidirectionally: the regression test fails
(force-cancels the row) with the clause removed from all three sites, and passes with it restored.

### `ApprovalManager` ticket liveness (#6061, #6096) - a recorded disposition, not a retention pass

Listed here because the routed trigger fires on any wall-clock cutoff in `approval_manager.cpp`, not
because the store adopts the apparatus. Every stamp this store writes (`submitted_at`, `reviewed_at`,
`consumed_at`) and every cutoff it compares against is the Postgres clock, authored in-SQL, and
`now()` (transaction start) everywhere except the liveness test in the consume CAS and its
diagnostic read, which use `clock_timestamp()` so a caller-held transaction cannot redeem past the
lifetime (#6062 sg-6; the CAS still stamps `consumed_at` from `now()`); the file reads no process
clock at all, and a source tripwire in `test_approval_manager.cpp` pins that and allows exactly
one occurrence of `clock_timestamp`. An approval ticket is "live" while it is `approved`,
unconsumed and `reviewed_at` lies within `[db_now - 7 days, db_now + 300 s]`. That test is ONE SQL
predicate (`ticket_live_sql()` in `approval_manager.cpp`, constants `kApprovalTicketTtlSeconds` and
`kApprovalReviewedAtSlackSeconds` in `approval_manager.hpp`) with one definition of the window,
used by four sites that must not drift apart about its bounds: the `consume_ticket` CAS, its
diagnostic read, `submit()`'s approved-ticket sweep, and
`ticket_is_live()`, which `ScheduleRunner` calls before it fires an approved schedule ticket.

- **Anti-fork rule.** `ticket_is_live()` answers liveness ONLY. It carries none of the #2442 origin and
  submitter binding, and `consume_ticket` stays the sole redemption chokepoint for the MCP recall:
  `ScheduleRunner` never consumes a ticket through it (it refuses `kSchedule` origins on purpose). A caller
  that needs to redeem a ticket calls `consume_ticket`, never `ticket_is_live` followed by its own write.
  `ScheduleRunner`'s retire (`retire_schedule_tickets`, below) is NOT the forbidden shape: it does not read
  liveness and then write on that answer. It is its own guarded UPDATE keyed on `consumed_at = 0`, so it is
  one atomic statement whose WHERE clause is the check; the runner's liveness read and its retire are
  independent steps, and the retire never decides authority (authority was settled by the human approval).
- **`ScheduleRunner` and a failing store (known, pre-existing, tracked in #2878).** The comment at the
  liveness check says a store failure HOLDS the occurrence. That is true only once the first read has
  succeeded: if `ticket_is_live()` itself cannot read, `fire_with_approval` holds (no advance) and logs
  a WARN. But the `query()` call that finds the approved ticket in the first place swallows a store
  error into an empty list, so with the store still failing the runner falls through to raising a fresh
  approval request; that submit fails too, `fire_with_approval` returns true ("occurrence skipped"),
  the schedule ADVANCES and the approved occurrence is dropped (a `once` schedule is lost), leaving only a failure audit row and
  `yuzu_schedule_fire_failures_total`. Do not read "holds the occurrence" as a guarantee for an outage
  that starts before the ticket lookup.
- **It is a liveness check and a state transition, not a bulk delete.** The consume is a per-row CAS
  that refuses and leaves the row untouched. The sweep is `UPDATE ... SET status = 'expired'`, never a
  `DELETE`; ADR-0065's "Expiry-sweep clock-guard adjudication" (and its 2026-10-18 amendment) records
  why the seven-part apparatus's trigger is not met for the sweep. Expired rows stay queryable and
  auditable.
- **All approval stamps are database time (#6096).** `submitted_at`, `reviewed_at`, `consumed_at` and
  both sweep cutoffs are authored by Postgres `now()` in-SQL (the SessionStore direction, #3715), so
  the stored value and the cutoff share one clock domain and nothing in the approval path depends on a
  replica's `system_clock`. `submitted_at` used to be the one process-clock stamp, kept that way for
  `ScheduleRunner`'s clock comparison; that comparison no longer exists.
- **One approval == at most one scheduled run is state plus a clock-free ledger, not a clock comparison
  (#6096).** `ScheduleRunner` treats a ticket as eligible only while its `consumed_at` is 0. Before it fires
  an eligible ticket it asks the command outbox which occurrences already used it
  (`CommandOutboxStore::occurrences_for_approval`, a lookup by `approval_id`, indexed by
  `outbox_approval_idx`); a row for a DIFFERENT occurrence means the ticket was already spent, whatever
  `consumed_at` says, and it is skipped. A row for THIS occurrence is the legitimate retry (`AlreadyEnqueued`,
  retire, advance). After the occurrence is durably enqueued (`Enqueued` or `AlreadyEnqueued`) and BEFORE the
  schedule advances, the runner calls `ApprovalManager::retire_schedule_tickets(schedule_id, occurrence_key,
  ids)`: one UPDATE (`WHERE schedule_id AND consumed_at = 0 AND status IN ('approved','rejected') AND id =
  ANY(ids)`, `consumed_at` on database time, `consumed_by = 'schedule:<occurrence key>'`, or `schedule:ledger-spent:<occurrence key>` for the
  ledger-spent site below; never empty). `ids`
  are the unsettled tickets of that schedule the runner OBSERVED in its own snapshot this tick (matched,
  mismatch-skipped, expired-unswept, outbox-spent; on a rejected skip, the rejected ones too), so an approved
  mismatch-skipped ticket is retired with the one that fired (otherwise it could fire a LATER occurrence after
  the definition is reverted) while a ticket approved after the snapshot, or a successor occurrence's ticket,
  is never touched. Pending tickets are never touched. A retire store failure or exception HOLDS the
  occurrence; the next tick re-enqueues the same occurrence key (idempotent) and retries the retire, so a
  failure between the enqueue and the retire can neither lose the fire nor run it twice. A rejected ticket is
  retired the same way after it skips its occurrence. Every retire site settles only observed ids, by a CAS
  from unsettled: the enqueue site and the already-ran site run after the outbox row exists; the ledger-spent
  site settles tickets whose outbox row belongs to an EARLIER occurrence; the rejected-skip site has no outbox
  row. When no ticket is eligible but the occurrence key is
  already in the outbox (retire ok, advance failed), the runner advances without raising a fresh ask. The
  retire is deliberately NOT epoch-fenced: the only fenced write is the outbox INSERT (`ScheduleRunner::tick`
  is FencedLeaderOnly); on the enqueue paths the retire only runs after the outbox row exists (whoever
  wrote it); on the rejected-skip path the retire is an observed-ids-only CAS from unsettled, so a stale
  leader can only settle tickets it saw (the deny direction). `ScheduleEngine`'s own stamps (`created_at`, `last_executed_at`, `next_execution_at`) stay
  process-clock due-ness bookkeeping and are informational for approvals now; `test_approval_manager.cpp`
  allow-lists the process-clock reads in `schedule_runner.cpp` (the audit timestamp) and
  `schedule_engine.cpp` (the due-ness stamps) by exact count so a new site fails loudly.
- **The outbox `approval_id` is now a spent-ticket ledger: any future outbox reaper must retain rows at least
  as long as the 7-day ticket lifetime** (`kApprovalTicketTtlSeconds`), or a reaped row makes a spent ticket
  look unspent. Today no reaper exists; the requirement is also stated at
  `CommandOutboxStore::occurrences_for_approval`. An unreadable ledger HOLDS the occurrence, and an unwired
  ledger seam fails closed.
- **Accepted LOW items (#6096), recorded so a reviewer does not re-open them.** (1) An approval can carry across
  a skipped occurrence within its 7-day life (an occurrence skipped for a disabled definition or a denied
  arming check does not settle the approved ticket waiting for it, so that ticket can fire at the next
  occurrence); it still yields at most one run per approval. (2) While a retire keeps failing, each held tick
  creates and cancels one execution row (per-tick churn). (3) Retire ok followed by a failed advance burns one
  approval: the occurrence already ran, the schedule advances on the next tick without a fresh ask, and the
  spent ticket is not reused. There is deliberately no replay eligibility keyed on `consumed_by` equalling the
  occurrence key. (4) `ScheduleEngine::advance_schedule` returns void and only logs a failure, so the runner
  cannot observe a failed advance; the outbox guard above is what makes that safe.
- **More accepted LOW items (#6096).** (i) Retired schedule tickets keep status `approved` and are never
  swept, so they count in the creator's newest-100 `query()` window, and a still-unsettled older ticket can
  fall out of that window: one wasted approval and a fresh ask (follow-up with the #6098 sweep note).
  (ii) `consumed_by` names the occurrence that SETTLED a ticket, which for a skipped or mismatched ticket is
  not the occurrence that used it (the outbox holds the truth); a ticket the outbox ledger showed was used by
  an earlier occurrence carries the `ledger-spent:` marker. (iii) A stale paused leader's unfenced advance
  only delays the next run.
- **One-time legacy migration, clock-free (#6096).** Tickets minted before this change carry no
  `consumed_at`, so they would all look unspent. Approvals schema migration v2 retires every unsettled
  approved/rejected ticket that has a `schedule_id` (`consumed_by = 'schedule:legacy-6096'`), once per
  database, with no comparison between `submitted_at` and `last_executed_at`, under a 300 s statement
  timeout (`SET LOCAL` was observed to take effect when sent as one libpq `PQexec` message inside the
  step's transaction, also over a shorter session-level timeout, in a one-off check on a throwaway PG16 by the
  implementer; it is not a repo test, and the repo tests pin only that the statement carries the prefix). It touches every unsettled approved or
  rejected scheduled ticket, including old rejected ones (rejected tickets never expire and are never swept).
  The deny direction: a legitimate approved-but-unfired ticket at upgrade time just gets a fresh ask. See the upgrade note in `docs/user-manual/upgrading.md`.
- **Parts 1, 2 and 4 DECLINED for the approved-ticket and the pending path; part 3 is not declined
  (next bullet)** (there is no per-replica clock reading to probe, persist or dedupe, and running the
  sweep on every replica is safe, so the SINGLE-WRITER caveat does not apply to it). With
  `submitted_at` on database time, a submitter's own clock no longer moves a ticket's lifetime and no
  caller supplies a timestamp (`submit()` takes none), so a skewed replica can neither pin the global
  cap of 1000 pending tickets nor have its tickets swept early (both were possible while
  `submitted_at` was process-stamped).
- **Part 3's "ahead of now" clause is satisfied for `reviewed_at`, by the upper bound; it is not
  declined.** A lower bound alone honours a far-future `reviewed_at` for as long as the skew lasts and
  the sweep never reaches it. The 300 s slack is an absolute number chosen for a healthy row (stamped
  by the database, so never ahead of `now()`) plus statement-boundary jitter; do not copy it to another
  store. `submitted_at` needs no equivalent upper bound: it is database-authored too.
- **Part 5 (cap) NOT adopted for the sweep:** it has no per-pass limit. It runs lazily inside `submit()`
  and only moves rows already past the lifetime to `expired`, which removes no data.
- **Part 6 (missing anchor): not applicable,** there is no anchor. **Part 7:** the 7-day lifetime is an
  absolute duration.
- **Premise withdrawn.** The earlier reasoning that a 7-day window makes app-clock versus database-clock
  skew immaterial was wrong (governance ledger `6061-approver-assurance.yut0p2`, UP-3): a `reviewed_at`
  stamped from a replica's clock and compared with the database's passed the lower bound while it was
  in the future. Stamping `reviewed_at` in SQL, plus the upper bound, is the fix, and #6096 applied the
  same reasoning to `submitted_at`. This follows the house rule in `docs/user-manual/server-admin.md` of never comparing an app-host clock to
  a database-host clock.
- **Residual, stated plainly.** The database host's own clock is still the authority, and a step in it
  is not harmless in either direction:
  - A **forward** step makes live tickets read as past their lifetime, and the sweep that runs while
    the clock is wrong moves them to `expired` for good. It also ages pending tickets, which expire the
    same way.
  - A **backward** step of more than 300 s makes an approved, unconsumed ticket read as ahead of the
    database clock when its `reviewed_at` is more than 300 s ahead of the NEW database time (roughly,
    the tickets reviewed within the last (step size minus 300 s) before the step; older approved
    tickets stay live), and the approved sweep expires those, **permanently** once it has run. No code path un-expires a ticket, so
    correcting the clock after an accepted `submit()` has swept them does not restore them. Before that
    first accepted `submit()`, nothing has been written: the upper bound is a pure predicate, so a held-back
    ticket is live again once the database clock catches up, and correcting the clock before any approval is
    submitted preserves it (hold submissions until the clock is right if the query below returns rows). The pending sweep is the one a backward step blunts: its cutoff moves into
    the past, so it matches fewer rows.
  - Once swept, the requester must ask again. The only trace of the approved sweep is an info log line
    ("expired N approved-but-unconsumed approval tickets"); there is no metric or audit row, the consume
    refusal for such a ticket says it is "past its 7-day lifetime" even when it was in fact ahead of the
    clock, and `submit()` logs a WARN only when the pending queue is full and the stale-pending sweep
    expired nothing. Observability for this (distinguishing aged from future-dated, and a counter) is
    tracked in #6098. This direction is fail-safe (deny), never a way to redeem more.
  - The query below finds tickets the upper bound is currently holding back (approved, unconsumed,
    `reviewed_at` ahead of the database clock by more than the slack). It returns rows only until the
    next accepted `submit()` runs, because that call sweeps them to `expired`; after that they no longer
    match this query and show as `expired`. A `submit()` refused because the pending queue is full rolls
    its sweeps back with the rest of its transaction, so the rows persist until a submission is accepted.

  ```sql
  SELECT id, definition_id, submitted_by, reviewed_at
  FROM approval_manager.approvals
  WHERE status = 'approved' AND consumed_at = 0
    AND reviewed_at > EXTRACT(EPOCH FROM now())::bigint + 300;
  ```

### `guardian_lifecycle_journal.cpp`

Satisfies parts **1/3/4/5 ONLY** — its reading is in-process and deliberately NOT persisted, so **do
not copy it for part (2)**.

## Reference implementations

**Decision rule:** `common/include/yuzu/audit_retention_rules.hpp::classify` (extracted to a shared
include root #2549 so agent stores can adopt it without a fork) + `audit_store.cpp::cleanup_once`
(fact-set).

`tar_aggregator.cpp::run_retention` adopted the shared `classify` + fact-set dedup (#2573 TAR half).
`guardian_lifecycle_journal.cpp::prune_locked_` adopted it too (#2573 GJ half, closed) —
`Facts::no_anchor` and `Facts::prev_unusable` are always false there (GJ persists no anchor across
restarts by design, and its comparison reading is never read back from an untrusted store); see the
field-mapping comment at the `prune_locked_` call site.

**The three reference impls deliberately use DIFFERENT constants** (server 2 d slack / 25 000 cap /
7 d step; agent 1 d / 5 000-per-table / 30 d) — they are substrate-tuned, so **copy the SHAPE, never
the numbers.**

## Related

- Rule and tests: #2360 / #2361 / #2549, `common/include/yuzu/audit_retention_rules.hpp` (`classify`),
  `AuditStore::cleanup_once`, `tests/unit/server/test_audit_store.cpp`
- `docs/user-manual/audit-log.md` and `docs/user-manual/tar.md` "The retention clock guard" are
  operator **RUNBOOKS** and deliberately do not state this rule.
