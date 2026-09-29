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
| `execution_artifacts` scratch-dir sweep (agent, #4390) | Agent-side, not a store: removes orphaned `execution_artifacts-<32 hex>` scratch directories under `agent.data_dir` whose last-write time is older than one hour (`execution_artifacts_scratch_sweep_win.cpp`). **Part 5 adopted** — four unconditional caps (root entries enumerated, directories removed per pass, wall-time deadline computed once, entries per candidate); truncation is reported as `deferred`, never as done. **Parts 1–4 and 6 DELIBERATELY NOT adopted, recorded here and in the header banner:** the content is a regenerable copy of a system hive that this plugin itself staged — never operator data — so a wrong wall clock can destroy nothing that cannot be re-created by the next dispatch; and liveness of an in-flight dispatch is proven by the OS (the dispatch holds the directory open without `FILE_SHARE_DELETE` and the loaded hive holds the file), not by the clock — the one-hour floor exists only to cover a concurrent dispatch's create-to-open window. Part 7 holds (absolute threshold, equality is fresh). Single-process by construction; no persisted anchor. |

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
   (every mapping is consumed once, response-side, well before the 24h window), so a would-wipe
   verdict cannot separate a true from a false positive.
4. **NO fact-set anomaly dedup** — a declined pass is `spdlog::warn`'d and surfaced via
   `yuzu_exec_correlation_reap_clock_anomaly_total` rather than deduped by fact identity.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer): a mapping is a
regenerable observability aid, not compliance evidence, so a from-boot skewed clock deleting a batch
of already-consumed mappings is an acceptable worst case.

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
