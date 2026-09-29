# C0 — relocate Guardian journal prune()/page_into_window() onto the drain worker

Status: BUILT. Base: `feat/guardian-c0-thread-reloc` stacked on #2314 (`c23836c1`).
Tracking: #2298 gate 1. Anchors are from the ORIGINAL base HEAD (`af10c272`) and have drifted.

See "As built" at the bottom for every place the implementation departed from this design.

## Goal

Today the Guardian lifecycle journal's `prune()` and `page_into_window()` run
SYNCHRONOUSLY, inline, on two latency-sensitive threads:

- the **heartbeat thread** — `journal_maintenance_tick()` phase-2 (`guardian_engine.cpp:400-411`),
  once per `heartbeat_interval`; prune every 4th tick, page every tick.
- the **reconnect / run-loop thread** — `page_journal()` from the reconnect hook
  (`agent.cpp:1734`), one full re-page after each new Subscribe stream.

Both go through KvStore's single mutex + 5s busy timeout, so a large or contended
journal can stall the heartbeat (false staleness) or delay reconnect. C0 moves that
work onto the existing `GuardianOutboxDrainWorker` (CV-wake + 5s backstop,
`guardian_outbox_drain_worker.*`), leaving ONLY the circuit-broken retry-`persist()`
(phase-1, `guardian_engine.cpp:388-392`) on the heartbeat thread.

## What moves / what stays

| Work | Today (thread) | After C0 (thread) |
|---|---|---|
| retry-`persist()` (phase-1) | heartbeat | **heartbeat (unchanged)** |
| `prune()` | heartbeat phase-2 (every 4th tick) | **drain worker** |
| `page_into_window()` | heartbeat phase-2 (every tick) + reconnect | **drain worker** |
| reconnect re-send-all | reconnect thread (`page_journal`) | **drain worker, kicked by reconnect** |
| `rt.drain()` (ship entries) | drain worker | drain worker (unchanged) |
| heartbeat tag-building, `journal_stats()` read | heartbeat | heartbeat (unchanged) |

Net: paging becomes SINGLE-THREADED on the worker (today two threads page:
heartbeat phase-2 + reconnect). Prune joins it on the same thread. This REDUCES
paging-path concurrency; it does not add a new class of it.

## Core mechanism

Extend the worker's wake cycle with a journal-maintenance step. Each wake, after
`drain_once()`:

```
if (!stopping) {
    firewall {
        if (due_for_prune()) journal_->prune(now);
        journal_->page_into_window(*rt_, now);
    }  // count throws into a maintenance-exception counter, like drain_once
}
```

The worker is constructed in `wire_spark_engine` (`guardian_engine.cpp:1182-1183`)
and only `start()`ed when `prefer_spark_` (`:1193-1196`) — so the prefer_spark gate
is handled by start() gating, NOT a per-call check.

### DECISION 1 (central) — the worker must NOT take engine `mtx_`

`GuardianEngine::stop()` holds `mtx_` across its whole body (`:303`) and at `:324`
JOINS the worker. If the worker's maintenance took `mtx_`, that is a lock-vs-join
deadlock (worker blocks on mtx_ held by stop(); stop() blocks on join(worker)).
Today safe only because `drain_once()` never touches `mtx_`.

Resolution: give the worker the `GuardianLifecycleJournal*` (raw, engine-owned) and
the `shared_ptr<GuardianSparkRuntime>` at construction, and have maintenance use them
DIRECTLY, guarded only by the journal's `stopping_` atomic — never engine `mtx_`.
This mirrors how the worker's enqueue-waker already captures only a `shared_ptr<Signal>`,
never `this` (`guardian_outbox_drain_worker.cpp:23-26`). Both `spark_runtime_` and
`lifecycle_journal_` are set once in wiring and not reassigned during operation, so a
lock-free read is sound as long as the worker is joined before they are torn down
(Invariant L below).

The per-call `stopped_ && prefer_spark_` check that phase-2 does under `mtx_`
(`guardian_engine.cpp:382-383`) is replaced by: start()-gating (prefer_spark) +
the `stopping_` atomic (stop).

## Load-bearing invariants — each must survive C0

- **A. Lock order unchanged.** WRITE chain = `mtx_` held, then `outbox_mu_` and
  `KvStore.mu_` sequentially-disjoint (never nested), persist-side
  (`guardian_engine.cpp:351-366`, `guardian_lifecycle_journal.cpp:183-188`). PAGE chain
  = `paging_mutex_` → {`KvStore.mu_`, `outbox_mu_`} sequentially, never `mtx_`
  (`guardian_lifecycle_journal.cpp:397,426,461,507`). C0 changes only the CALLING THREAD
  of the PAGE chain, not the acquisitions.
- **L. worker ↔ journal lifetime.** The worker holds a raw `journal_*`; it MUST be
  joined before the journal is destroyed. Established contract: engine::stop() joins
  the worker (`:324`) and both agent teardown paths call guardian_->stop() before
  ~GuardianEngine (ScopeExit `agent.cpp:792`, AgentImpl::stop `:2682`). SEE HAZARD 3 —
  member declaration order AT THE TIME OF WRITING destroyed `lifecycle_journal_` (declared
  last, `:373`) BEFORE `spark_drain_worker_` (`:366`), so this relied on stop() having run.
  As built this is reversed: the journal is declared FIRST, so reverse-order destruction
  joins the worker while the journal is alive without depending on stop().
- **S. stop-race.** `request_stop()` is called FIRST in engine::stop() (`:318`), before
  the worker join (`:324`). `page_into_window` checks `stopping_` between batches
  (`guardian_lifecycle_journal.cpp:492`). After C0 the worker IS the thread the join
  bounds — cleaner than today (page currently on heartbeat/reconnect). SEE HAZARD 5:
  confirm prune()/prune_locked_ also honor stopping_.
- **E. engine-home / borrow-not-own.** Journal owned by engine, borrows `kv_`; runtime
  owns no KvStore. Unchanged — the worker borrows the same engine-owned journal.
- **Freeze-at-mint / Option-A.** Untouched (C0 doesn't alter persist/replay content).

## Hazards + proposed resolutions (Sol/Fable opine targets)

1. **mtx_-under-join deadlock** — resolved by DECISION 1 (worker never takes mtx_).
   Confirm no hidden mtx_ acquisition on the prune/page path.

2. **[RESOLVED in #2314 — folded, do NOT re-address in C0.]** The prune-vs-persist gauge
   lost-update was found (Sol opine + Fable advisor) to be a real ceiling-breach → indirect
   evidence-loss bug that PRE-DATES C0 and is latent in the shipped journal. Fixed in #2314
   commit 33e329b1 via **rebase-as-delta**: gauges are atomic<int64_t> running counters
   updated by RMW only (persist fetch_add; prune rebases to scanned-actual then fetch_subs
   removals; no absolute store), clamp-at-read. Pure fetch_sub was rejected (bricks writes on
   a fail-closed boot seed). C0 rebases onto the fixed base, so the retry-persist-vs-worker-
   prune interleaving C0 adds is already covered by the RMW scheme. Original (WRONG) analysis
   kept below for history:

   ~~prune-vs-persist newly concurrent.~~ Today prune (heartbeat phase-2) and persist
   (heartbeat phase-1) are sequential on ONE thread. After C0 prune runs on the worker
   while persist stays on the heartbeat → they can interleave. Both take `KvStore.mu_`
   (serialized at the DB). The size gauges can transiently skew: persist's atomic
   `+=` can be overwritten by prune's atomic `store(survivors)` → a bounded undercount
   that self-corrects next prune, within the 2x-headroom hard ceiling. NOTE: page-vs-persist
   concurrency ALREADY exists today (reconnect page vs heartbeat persist), so only the
   prune-vs-persist gauge skew is new. Proposed: ACCEPT + document (matches the existing
   "gauges are estimates" posture, the boot-seed conservatism reviewers already accepted).
   OPEN for Sol: is the transient skew acceptable, or worth serializing?

3. **worker ↔ journal destruction order.** `lifecycle_journal_` (`:373`) destructs
   BEFORE `spark_drain_worker_` (`:366`) in ~GuardianEngine (reverse decl order). Safe
   ONLY because stop() joins the worker first (the existing `:369-372` comment). C0
   makes the worker DEPEND on the journal, so this becomes load-bearing. OPTIONS:
   (a) keep relying on the stop()-before-dtor contract (both teardown paths honor it) +
   a defensive comment; (b) reorder members so the worker destructs before the journal
   (join-in-worker-dtor happens while journal still alive), removing the reliance.
   Proposed: (b) reorder — cheap, removes a footgun. OPEN for Sol.

4. **reconnect prompt re-send-all.** Reconnect must still trigger a prompt full re-page
   (flush the journal to the freshly-connected server), not wait up to 5s for the backstop.
   Proposed: replace the `page_journal()` call at `agent.cpp:1734` with a worker KICK —
   add `GuardianOutboxDrainWorker::notify()` (bump the Signal generation + cv.notify) and
   call it from the reconnect hook (via an engine method). Preserves promptness; no paging
   on the reconnect thread. OPEN: keep `page_journal()` as a thin kick-wrapper for the
   reconnect hook, or wire the worker directly?

5. **prune stopping_ honor.** `page_into_window` checks `stopping_` mid-loop; confirm
   `prune()`/`prune_locked_` bail promptly on `stopping_` too (add a check if absent), so
   a stop during a long prune scan doesn't delay the worker join.

6. **cadence on the worker.** Prune every 4th was a heartbeat-tick count. On the worker
   (CV-wake + 5s backstop), a wake-count "every 4th" would prune too often under enqueue
   storms. Proposed: TIME-based prune cadence (e.g. >= prune_interval since last prune),
   decoupled from wake frequency. Page runs every wake (bounded by the existing
   JournalPagingBucket rate limiter, so no fleet-cost regression). OPEN for Sol: interval.

   > **WRONG, and shipped wrong in the first cut — corrected in the governance hardening
   > round.** "Bounded by the JournalPagingBucket" is false: the bucket charges a token only
   > when a batch pages NET-NEW work, so whenever the send window already holds every
   > candidate (the normal state while the link is down and the backlog is retained) it never
   > throttles and every wake re-runs a full `list_entries` + parse + `validate_record` sweep.
   > The bucket is a WIRE limiter, not a SCAN limiter. Gate 3 measured the corrected steady
   > state at one full scan per 10-20 s even after a naive fix, against one per 30 s pre-C0.
   > Page therefore got its own 30 s time cadence, exactly like prune, with the reconnect kick
   > forcing an immediate page so replay promptness is unaffected.

## Validation plan

- Preserve/extend the existing `[tsan]` concurrent persist+page+prune+drain stress
  (added in PR-Ag FR7/QE-1) — now with prune+page actually ON the worker thread.
- New: stop-race under active maintenance (request_stop mid-prune / mid-page on the
  worker; assert clean join, no late window mutation).
- New: reconnect-kick triggers a prompt page (no 5s wait).
- Chaos CH-5/CH-6 (contended KvStore) to confirm the heartbeat no longer stalls.
- Full agent suite + TSan green.

---

## As built

Every open question above is now resolved; the deltas from the design are listed here so a
reviewer diffs against reality, not the plan.

### Resolutions of the OPEN items

- **Hazard 3 (destruction order)** — took option (b). `lifecycle_journal_` is now declared
  BEFORE `spark_scheduler_`/`spark_drain_worker_` in `guardian_engine.hpp`, so reverse-order
  destruction joins the worker (in `~GuardianOutboxDrainWorker`) while the journal is still
  alive. The stop()-before-dtor contract still holds; it is no longer the ONLY thing holding.
- **Hazard 4 (reconnect prompt re-send-all)** — kept `page_journal()` as the thin kick-wrapper.
  `agent.cpp`'s reconnect hook is unchanged; `GuardianEngine::page_journal()` now takes `mtx_`
  briefly and calls the new `GuardianOutboxDrainWorker::notify()`. The worker is never exposed
  to `AgentImpl`.
- **Hazard 5 (prune stopping_)** — added. `prune_locked_` bails on entry, inside the
  per-evicted-key classification loop, and before the label-GC / quarantine-bounding scans.
  `page_into_window` gained an entry check (taken BEFORE `paging_mutex_`, so a page never
  queues behind an in-flight prune during shutdown) and a check in the candidate-build loop,
  on top of its existing per-batch gate.
- **Hazard 6 (cadence)** — `kGuardianJournalPruneInterval` (120 s), measured on `steady_clock`
  (the retention comparison itself still uses wall clock, since batch `ts_ms` is `system_clock`
  and must survive a reboot). The timers are LOCALS in `loop()` and, since the Sol review, stamped AFTER each pass so the
  cadence is a minimum GAP rather than start-to-start.

### Departures from the design

1. **No `shared_ptr<GuardianSparkRuntime>` was added to the worker.** It already holds
   `GuardianSparkRuntime& rt_` under exactly the lifetime contract the design wanted (joined
   before the runtime is torn down). Maintenance uses that reference. Only the journal pointer
   is new.
2. **The maintenance-exception counter lives ON the worker**
   (`journal_maint_exception_count()`), not as a pointer back to the engine's atomic.
   `GuardianEngine::journal_stats()` SUMS the engine's counter and the worker's into the single
   operator-facing `guardian_journal_maint_exceptions` tag, so the heartbeat contract is
   unchanged while the two failure domains stay separately inspectable in code.
3. **The send-wrapper fix went further than "pre-resolve the pointer".** It no longer captures
   `this` at all (`guardian_engine.cpp` `journaled_send`), which is what makes "the worker
   thread touches no engine state" a property you can check by reading the lambda's capture
   list rather than by auditing its body.
4. **`journal_maintenance_tick` does NOT kick the worker after a successful retry-persist.**
   Paging is already strictly more frequent than before (the worker's 5 s backstop vs the 30 s
   heartbeat), so the kick would buy no latency the backstop does not already bound, at the
   cost of an `mtx_ -> Signal.mu` lock edge on the heartbeat path.
5. **`journal_tick_count_` was deleted** from `GuardianEngine` — the every-4th-tick rule it
   served no longer exists (the worker's time cadence replaces it), and the static
   `journal_now_ms()` helper moved from `guardian_engine.cpp` to the worker's TU.

### Validation

- `[spark][guardian][drain][maint]` — new cases in
  `tests/unit/test_guardian_outbox_drain_worker.cpp`: paging + the same-wake re-drain, the
  reconnect kick's promptness, notify-after-stop inertness, the TIME-based cadence (the
  explicit regression guard against a per-wake prune), stop-during-maintenance joining cleanly,
  and the two firewalls not starving each other.
- `[tsan]` — a new checkpoint driving the POST-C0 shape: maintenance on the worker thread
  racing a persister thread (the heartbeat's surviving phase-1) and a kicker thread (reconnect).
  The pre-existing `[spark][runtime][journal][tsan]` stress is unchanged and still passes.
- `test_guardian_engine_spark_reconcile.cpp` — the `page_journal` case now asserts the
  ASYNC contract (a pass appears well inside the 5 s backstop, i.e. the kick caused it).

---

## Governance hardening round (#2298 C0)

The first cut passed a full agent suite and a TSan run, then a 7-agent governance pipeline
found two BLOCKING test defects and a set of real behavioural ones. Recorded here because
several are corrections to claims made ABOVE, not just to code.

### Behavioural corrections

- **Page got its own 30 s cadence** (`kGuardianJournalPageInterval`). The design's "the
  paging bucket already bounds it" was wrong - see the callout under hazard 6. Three
  independent reviewers reached the same fix. `notify()` now also sets a `force_page_` flag
  so the reconnect kick still pages immediately, which is what keeps the cadence from
  delaying replay.
- **The drain pass is bounded** (`kGuardianDrainBudget = 512`, via the new
  `GuardianSparkRuntime::drain_bounded()`; plain `drain()` is unchanged). Unbounded, a slow stream drains the whole 4096-entry window
  - measured at ~82 s at 20 ms/send - and post-C0 that starves retention until the journal
  hits its write ceiling and DROPS audit records. Pre-C0 prune ran on the heartbeat thread and
  was immune; this coupling is created by the relocation, so it is C0's to fix. A truncated
  pass re-drains without waiting, so throughput is unchanged.
- **The loop is reordered to maintenance-then-one-drain.** This ships anything paged in the
  SAME cycle, which is what the old conditional second drain existed for - and that second
  drain ran un-gated after `stop()` was already blocked in `join()`.
- **The first cycle runs without waiting**, so the seeded boot replay no longer sits behind a
  periodic bound or the first outbox enqueue.
- **`stopping_` now PRECEDES the heavy KvStore calls** rather than straddling them: prune's
  parse/quarantine loop (up to 2000 renames x 5 s busy timeout), its `del_keys`, and page's
  `list_entries` after the boot barrier. Without this the post-`request_stop()` exit was
  unbounded, and `stop()` holds `mtx_` across the join, so everything else blocked with it.
- **`Signal::stopping` is atomic**, making `stop_requested()` lock-free and noexcept. It was
  the only call in `loop()` outside a `try`, so a `std::system_error` from its `lock_guard`
  would have terminated the agent (the #2037 class).
- **`rollback_spark_wiring_locked` signals the journal first**, mirroring `stop()`, so a
  wiring failure cannot block BOOT on a full maintenance pass.
- **`page_journal()` regained its B4a firewall**, dropped in the first cut.

### The invariant is now enforced, not just documented

`GuardianEngine::mtx_` is a `WorkerHostileMutex` that asserts in debug/sanitizer builds that
it is never locked on the drain-worker thread. The first cut hardened the wrong half: it
removed the `this` capture from the send wrapper, but the real exposure is that `send` is an
arbitrary `std::function` injected from `agent.cpp`, and nothing structural stopped a future
PR adding a `guardian_->...` call to it. A violation now fails a test instead of hanging a
fleet. The long-term shape - `stop()` not holding `mtx_` across the join, which deletes the
invariant outright - is deliberately left to a later rung.

### Test corrections (both were BLOCKING)

- The "prune cadence is TIME-based" test asserted `batches_pruned() == 0` against an EMPTY
  journal, which is true whether prune ran once or twenty times. It proved nothing, and its
  own execution pattern was a live instance of the unbounded-rescan bug it was supposed to
  guard. Rewritten to count real scans through `set_pre_scan_hook_for_test` against a running
  worker under a 200-wake storm.
- The reconcile `page_journal` test inferred "the kick caused this page" from a 1 s window
  against a 5 s backstop - but the worker starts during fixture construction, so that backstop
  was already ticking through setup and could fire inside the window. It now pins the bound to
  an hour via a new `set_drain_worker_timing_for_test` seam, so only the kick can page.
- The stop-during-maintenance test called `request_stop()` BEFORE `stop()`, so every pass
  short-circuited at the entry gate and the mid-scan gates were never executed. It now fires
  `request_stop()` from INSIDE a scan via the pre-scan hook.
- The TSan stress persisted DIRECTLY into the journal, bypassing the real phase-1 path
  (`snapshot_pending` -> `persist` -> `erase_persisted_prefix` -> `backfill_batch_provenance`)
  - precisely the state C0 splits across two threads - and used a bare sink rather than the
  `mark_batch_sent` wrapper, so no KvStore write ever raced prune's `del_keys`. Both fixed.
- Added: maintenance-exception firewalling driven nonzero (the pre-scan hook throws straight
  out of `prune_locked_`, so no new seam was needed), and an enqueue-wake-does-not-page case.

### Filed as follow-ups, not fixed here

Deliberately out of C0's scope: building `OutboxEntry` vectors before the window-headroom
check (wasted work in the link-down state); prune and page each running their own full scan
back-to-back; `JournalPagingBucket::refill` being fed `system_clock` (a backward NTP step
freezes refill); the shutdown classification-counter under-count; `erase_persisted_prefix`'s
count-based erase racing drop-oldest; renaming `GuardianOutboxDrainWorker` /
`page_journal()` now that neither name describes what it does; handing the worker a
`shared_ptr` to delete the declaration-order dependency; and documenting
`guardian_journal_maint_exceptions` in the metrics manual.

(Of that list, the `shared_ptr` change, the metrics-manual entry, and the
build-before-headroom-check waste were subsequently FOLDED IN rather than filed — see the
later rounds below.)

---

## Second hardening round (Sol adversarial review)

An independent read of the post-governance branch found one BLOCKING defect and several
material ones that the 7-agent pipeline had missed. Recorded because the BLOCKING one was
introduced BY the first hardening round - the fix for a hazard was itself a hazard.

- **The `mtx_` tripwire was a data race and a potential use-after-free.** It held a raw
  pointer to the worker, written under `mtx_` but read BEFORE `mtx_` was acquired, and
  wiring rollback destroys the worker right after clearing it. It also could not reliably
  fire: `assert` is a no-op under `NDEBUG`, so a sanitizer-enabled release build logged the
  violation and deadlocked anyway, and the enablement macro was GCC-only. Replaced with a
  thread-local role marker plus `std::abort()`, enabled on GCC and Clang sanitizers.
- **The bounded drain starved compliance.** Lifecycle drains first, so one shared budget let
  it consume a whole pass - a rationed version of the detection blackout Gate 4 UP-3
  explicitly removed, reintroduced four lines below the comment that documents it. Now a
  reserved share with allowance transferring both ways.
- **A count bound is not a time bound**, and nothing observed shutdown mid-pass: a whole
  512-send pass could BEGIN after `stop()` was blocked in `join()`. Added a wall-clock cap
  and a per-send stop predicate.
- **A prune throw silently ate a forced page**, because prune and page shared one `try` and
  both cadence stamps were taken before the pass. Separate firewalls; a forced page that did
  not run re-arms.
- **The cadence was start-to-start, not a minimum gap**, so a pass longer than its interval
  was due again the instant it finished. Stamped after the attempt.
- **Reconnect refill hole**: with a full window the kick's page places nothing, the drain
  then empties the window, and the backlog waited a full interval. Re-armed for exactly that
  case.
- **Housekeeping stop-gates were incomplete** between the sent-label GC and quarantine
  bounding.
- **An existing test was silently invalidated** by the first-cycle-immediate change.

Two further bugs surfaced while building the fairness fix, caught by the new tests rather
than by review: the allowance rollover was one-directional, and an empty log with an
exhausted budget falsely reported truncation.

The journal also moved to `shared_ptr`, which DELETES the declaration-order dependency the
first round documented as load-bearing. Section 24's invariant is kept, since the
"never take mtx_" half still stands, but the ordering half is no longer correctness-critical.

### Cutover gaps closed after the review

All three items the Sol review left open are now covered.

- **The `WorkerHostileMutex` abort is proven.** A forked-child death test installs a send that
  takes `mtx_` from the worker thread and asserts the child dies by `SIGABRT`. Proven
  load-bearing by mutation: stub the guard and the child DEADLOCKS exactly as the production
  bug would, and the test goes red. The parent polls with a deadline rather than blocking in
  `waitpid`, because the failure under test IS a hang. Skips cleanly where the guard is
  compiled out (release without sanitizers), since there the violation deadlocks instead.
- **Production boot order is tested.** `wire_spark_engine()` before `start_local()` - what
  agent.cpp actually does, and the reverse of what every prior test including the shared
  fixture did. The worker's immediate first-cycle maintenance now races the pre-network
  re-arm on one KvStore mutex; the test asserts neither starves the other.
- **The send is exercised with real `Retain` semantics.** `StreamLikeSink` mirrors
  `send_guardian_outbox_entry` (absent stream or failed write -> `Retain`), driving a full
  link-down/backlog/reconnect cycle and a mid-drain link drop. This pins that a `Retain`
  reports `truncated == false`, so a down link does not put the worker in a hot re-drain
  loop - invisible to an always-Sent sink.

That last test also corrected a misconception of mine rather than a defect: it initially
asserted exactly-once delivery and failed at 15 sends for 12 distinct events. The durable
journal is AT-LEAST-ONCE on purpose - it replays on every reconnect and the server
de-duplicates on the `event_id` PK, counting
`yuzu_server_guardian_events_redelivered_total`, which the metrics manual documents as normal
after an outage and explicitly not a loss signal. Changing the code to satisfy the original
assertion would have broken replay.


---

## Third hardening round (PR #2345 blocking review)

A human reviewer blocked the PR; two external model reviews then found more, including in the
fixes. Recorded because three of the findings were the SAME defect classes earlier rounds had
supposedly closed.

- **The wall budget was not sliced, only the count.** `drain_log_unlocked` checks the deadline
  BEFORE the count budget, so once lifecycle consumed the single shared wall, compliance
  returned on entry without ever spending a reserved slot. The compliance reserve added in
  round 3 was therefore dead under time pressure - the Gate-4 UP-3 detection blackout reached
  through the other limit. Lifecycle now takes a slice of the wall; compliance and the
  lifecycle-retry get the full pass deadline; the ratio is normalised once for `den == 0`,
  `num > den` and the wall-only case. The guarantee is stated honestly in the code: compliance
  gets an opportunity to START, not a slice of time, because an in-flight send is
  uninterruptible.
- **The headroom precheck reintroduced B2 starvation.** It `break`'d before `page_cursor_`
  advanced, so an oversized head batch pinned the rotation and smaller newer batches never
  paged. Now `continue` with the cursor advanced. Paging a newer batch ahead of an older
  blocked one was ARGUED tolerable against the server's ingest semantics - dedup compares
  immutable fields only on an `event_id` collision, lifecycle events do not update the
  compliance census, and event queries order by event timestamp rather than arrival - rather
  than assumed. No test exercises cross-batch inversion end to end, so this is a code-reading
  argument, not evidence.
- **The refill re-arm reintroduced UP-2 amplification.** `lifecycle_headroom() > 0` fired when
  one slot opened for a batch needing up to 256, so `force_page_` re-armed every cycle and each
  forced page is a full journal scan. It now requires room for the smallest actually-blocked
  batch (`min_blocked_headroom`), and sets `skip_wait` so it acts immediately instead of after
  the periodic bound - a latency the 20 ms-bound reconnect tests had masked entirely.
- **`drain_once()`** is documented as test-only with no production caller, noting it bypasses
  every limit the worker applies.

### The test discipline that was missing

Four hollow tests across this PR shared one signature: none asserted the discriminating
observable of the mechanism it claimed to cover. The rule now applied is that **a test claiming
to cover a branch must assert that branch's own flag or counter, and must be observed red
against the unfixed code before it counts.** Each round-4 fix has such a test. The refill test
was itself hollow on the first attempt - it forced a page that was never headroom-blocked - and
was caught by exactly that rule.

`metrics.md` is now bound to the emitter by a mechanical cross-check test in the H2/G9
bind-or-drift idiom. It proves NAME PRESENCE only; it cannot catch a row whose description is
wrong, which is the other error this round fixed. That limitation is stated in the test and
should not be trimmed.

### A pattern worth naming

The false `maint_exceptions` description was corrected in `metrics.md` and one changelog
fragment while remaining false in the OTHER fragment and in this document's own flip-list -
found by governance Gate 2 after the fix commit. Prose written from intention at time T and
never reconciled at T+n is the recurring failure of this PR, and it recurred inside the commit
that fixed it. Bind doc claims to executable checks wherever possible; treat the flip-list as a
checklist to be executed, not a record of intent.

---

## Known limitation: size-biased replay loss (#2364)

Replay places a batch all-or-nothing, and rotates fairly by position, so when the send window is
nearly full a LARGE batch is skipped every pass while smaller ones are placed - and if that
persists to the 7-day retention age it is deleted having never been sent. The loss is biased
towards the biggest batches, which are mass arm/disarm bursts, i.e. the most audit-significant
records.

Four mechanisms to close it were built and reverted inside this PR (rotation pin; reservation
with a "surplus"; reservation with a progress release; that one with its defects fixed). They
fail for the same structural reason rather than through any individual bug: a batch is blocked
exactly when the window has less room than it needs, so making it fit means pausing competing
replay until the drain creates room - and in the only regime where this matters, the drain
cannot create room, so such a scheme must either release (restoring the loss) or hold (stalling
everything else). Reviewers judged the best version WORSE than doing nothing, because it added a
duty-cycled global replay pause on top of the original loss. Three successive tests for it were
proven hollow by mutation, which is its own evidence the behaviour was not well defined.

The channel is narrow - a 256-entry maximum batch against a 4096 window needs sustained
occupancy above ~94%, which is itself a delivery failure with independent signals - but it is
real. It is tracked in #2364, whose first step is telemetry (the age of the oldest
headroom-blocked batch, plus the fleet rollup this checklist already requires) rather than a
fifth mechanism, because today nobody can tell which regime an endpoint is in. It must be
resolved or explicitly risk-accepted before the `prefer_spark` flip.

**"Structural" is overstated, and two external reviewers said so independently (round 7).** The
fork above is real for the design as written, but all four reverted mechanisms only ever
SCHEDULED the window; none questioned its two fixed premises, and relaxing either escapes the
fork without pausing anything:

- **Admit an overshoot.** The 4096-entry window is a soft RAM bound, and a replayed batch is
  already durable on disk. Admitting when `size + need <= cap + kMaxJournalEntriesPerBatch`
  rather than requiring `headroom >= need` (`guardian_spark_runtime.cpp` `try_page_batch`)
  bounds the overshoot at one batch (~256 entries) and lets a large batch in after a single
  pop instead of 256. No pause, no hold, no release. (K3)
- **Stop placing batches whole.** All-or-nothing placement is an implementation choice, not a
  delivery requirement: the drain already sends one event at a time and each carries its own
  idempotency key, so replay could page a PREFIX of a durable batch under a fair per-record
  quota. A dedicated replay lane, protected from live refill, is a variant of the same idea.
  (Sol)

Neither has been prototyped or measured, and neither is being adopted here. They are recorded
because "no design escapes the fork" is not proven, and #2364 must be a real decision at the
flip rather than a default ratification of the revert. The narrowness argument is also
self-weakening, as K3 noted: a slow-but-flowing link pinning the window near full is precisely
the regime where replay matters most.

## Retention differs deliberately from every other store (Gate 8 security/consistency)

The Guardian lifecycle journal is not the only wall-clock expiry site in the codebase, and it is
not the only one with a guard: `server/core/src/app_perf_daily_store.cpp` already bounds an
implausible future timestamp (`kFutureSlackDays`) and caps rows applied per pass
(`kMaxRowsPerApply`). An earlier draft of this section claimed "the ONLY", which was simply
wrong, and named `tar_aggregator`'s SQL in the wrong file.

What is accurate: most wall-clock expiry sites issue a single uncapped `DELETE ... WHERE
expires_at < now`, with no anomaly detection and no per-pass bound. Those include
`server/core/src/audit_store.cpp`, `response_store.cpp`, `result_set_store.cpp`,
`preflight_run_store.cpp`, `deployment_run_store.cpp`, `guaranteed_state_store.cpp`'s TTL over
the server's copy of these same lifecycle events, `auth_db.cpp`'s expired-session sweep,
`app_perf_daily_store.cpp` and `app_perf_fleet_store.cpp`'s own retention deletes, and
agent-side retention driven from `agents/plugins/tar/src/tar_schema_registry.cpp`.

The asymmetry is defensible for the server stores: they run on an NTP-managed host, they are
backed up, and their clock is not one an endpoint controls. It is less comfortable for the
agent-side TAR retention, which shares exactly the clock this guard exists for, and for
`audit_store`, which holds SOC 2 evidence. Neither is in this change's scope. Follow-ups are filed for the two
that matter: **#2360** (`audit_store`, the SOC 2 evidence trail) and **#2361** (agent-side TAR
retention, which shares the endpoint clock this guard exists for). The remaining server-side
sites are recorded in #2360 rather than filed individually, since they share one fix pattern and
a lower stake.

## Governance record

Verdicts, findings and their disposition for the review rounds on this branch live in
`docs/guardian-c0-governance-ledger.md`. Standing rule from that run: **no commit may cite a gate
number that is not independently recorded there.** Two earlier rounds cited "Gate 8"/"Gate 8b"
with no verdict anywhere in the tree, which Gate 6 compliance classified as a CC7.2 traceability
failure - a reader could confirm only that the author said they ran.

## REQUIRED at the `prefer_spark` flip (Gate 6 enterprise-readiness)

Everything in this change that relocates journal maintenance is DORMANT until the Spark
detection path becomes authoritative. The changelog says so, which is the right posture for
shipping now - but it creates an obligation later, and an obligation recorded only in a review
transcript is one nobody will honour.

Whichever PR flips `prefer_spark` MUST also:

1. **Ship its own changelog entry** cross-referencing this one, stating that C0 is now live and
   what actually changes for an operator: the heartbeat and reconnect paths no longer touch the
   KvStore for journal work, and retention/paging now run on the drain worker at their own
   cadences. Without this the behaviour changes with no release note of its own, because the
   note was consumed by a release where nothing happened. Inline the concrete numbers - the
   30 s paging and ~120 s retention cadences, the 512-entry / 2 s drain budget, the compliance
   share - directly in that entry rather than cross-referencing this one: nobody re-reads a
   changelog fragment from N releases ago (Gate 6 enterprise-readiness). The flip PR should
   also add a short operator-facing paragraph to `docs/user-manual/guaranteed-state.md`, which
   today says nothing about journal cadence or the drain worker at all.
2. **Update the `yuzu.guardian_journal_maint_exceptions` row** in `docs/user-manual/metrics.md`
   to drop the dormancy framing. That counter's meaning has already shifted once during this
   branch (it aggregates the heartbeat's retry-persist and the drain worker's prune/page; convergence
   sweeps are NOT included - they have their own `yuzu.guardian_sweep_exceptions`, as does
   outbox delivery via `yuzu.guardian_drain_exceptions`) and shifts again in effect at the
   flip. All three carry dormancy framing that must be shed at the same time.
3. ~~**Close or explicitly risk-accept the shutdown-classification undercount**~~ - **DONE**
   (built, NOT risk-accepted; L3 commit 5a85fcc5) (Gate 6 compliance, CC7.2): when a stop lands
   mid-classification, the remaining evicted keys were counted in neither `evicted_sent_unacked`
   nor `evicted_no_send_evidence`, so the counter an auditor reads as "audit gap" reported a
   SMALLER gap than actually occurred. Under-counting a loss indicator is worse than
   under-counting a success one. Dormancy capped the severity while dormant; it would not once
   C0 is live. FIX: the classifier now lands every evicted key in exactly one of three buckets -
   the new `evicted_unclassified` catches the mid-pass-shutdown remainder, an unreadable-label
   fallback read, and a mid-classification throw - so `batches_pruned == evicted_sent_unacked +
   evicted_no_send_evidence + evicted_unclassified` holds every pass, making
   `evicted_no_send_evidence` a trustworthy floor. The explicit #2298 checklist entry this asked
   for is added at PR time.
4. ~~**Land the `yuzu_fleet_guardian_*` server rollup**~~ - **DONE**, merged into this branch as
   PR #2334 (`server/core/src/guardian_journal_fleet_tags.hpp`, the writer/reader bind test, 18
   Guardian journal rules in `docs/prometheus/yuzu-alerts.yml`). Gate 6 sre had this as the item
   that made every other alerting item moot, since the loss and redelivery signals existed only
   in per-agent heartbeat tags and nothing aggregated them.
   NOTE for whoever adds the next journal counter: the rollup carries a static assertion pinning
   the `GuardianJournalStats` field count to the gauge table's row count, so a counter added
   without its gauge is a BUILD failure, not a silently dead metric. Merging this branch into
   it tripped exactly that guard on four fields - fix it by adding the row, never by relaxing
   the assert.
5. ~~**Surface `gauge_underflow_`** (pre-existing #2303, self-flagged in
   `guardian_lifecycle_journal.hpp` as needing to land WITH the cutover): the accounting bug it
   detects camouflages as a healthy empty journal because `journal_batch_count` clamps to 0.~~ -
   **DONE** on branch `feat/guardian-journal-observability` (mirrors `write_capacity_rejected`:
   struct field + `journal_stats()` + emit + fleet row + metrics.md; landed pre-flip and inert).
   The same PR also delivered the ledger's **UP-4** (`send_exceptions` /
   `lifecycle_backpressure_drops` reached no heartbeat tag) as two more journal-family counters.
6. ~~**Add a "seconds since last successful page/prune pass" gauge** (Gate 6 sre). It is the only
   viable liveness signal for the two wall-clock hazards AND for a release-build deadlock,
   where the `mtx_` guard compiles out and a wedged worker is indistinguishable from an idle
   healthy one.~~ - **DONE** on branch `feat/guardian-journal-age-observability`:
   `yuzu.guardian_journal_page_stale_seconds` + `..._prune_stale_seconds`, success stamps seeded
   at worker `start()` and re-stamped only by a non-throwing pass (TIGHTENED by #2452 - see
   UP-11 below - to re-stamp only on a pass that made replay/retention progress or verified
   there was none, not merely one that did not throw), emitted every heartbeat
   INCLUDING 0 while live and absent while dormant (dormancy = `journal_age_stats()` nullopt,
   never a fabricated zero), fleet rollup as a NEW **MAX** family
   (`yuzu_fleet_guardian_journal_*_seconds_max` - the first non-SUM rollup; a fleet sum of ages
   is meaningless). This also closes item 14 (see its note).
7. **Run chaos scenario CH-5** (live-event latency under KvStore contention, UAT rig). It is
   the only scenario that measures the thing C0 was built to fix, so it is the flip's genuine
   go/no-go rather than a formality. Run it at the journal's HARD ceiling (2000 batches /
   64 MiB, `hard_max_batches_`/`hard_max_bytes_` -
   `guardian_lifecycle_journal.hpp:682-683`) - **CORRECTED 2026-08-18 (F11 #2298
   governance, architect finding): a 2026-08-18 doc edit briefly claimed this figure was
   stale text and substituted the SHIPPED soft caps (1000 batches / 32 MiB). That claim
   was wrong and is reverted here. `hard_max_batches_`/`hard_max_bytes_` are a real,
   actively-enforced write-capacity ceiling (`guardian_lifecycle_journal.cpp:207-208`,
   `write_capacity_rejected_`), deliberately set at 2x the soft retention caps
   (`agents/core/src/guardian_lifecycle_journal.hpp:224` doc comment: "Decoupled from
   the retention caps... persist refuses to cross it so a chronically-failing prune
   cannot grow the shared kv_store.db without bound") and shipped
   (`84b6cc31a`, 2026-07-19) three days BEFORE this doc's own "2000 batches" text
   (`b75e365d6`, 2026-07-22) - chronologically backwards for a "stale, pre-finalization"
   reading. This doc's own item 12 already correctly describes it as "the 2x-headroom
   hard ceiling," which the reverted edit should have caught as an internal
   contradiction before shipping.** Not at the ~900 measured so far (Gate 6 sre): a full
   scan already exceeded one second at 900, so the pass duration - not
   `kGuardianMinRefillInterval` - is what actually paces chained forced pages during a
   large-backlog recovery.
8. ~~Persist pending lifecycle records BEFORE the drain-worker join~~ - **DONE (round 6,
   commit 882e2bf5)**,
   not deferred. Gate 6 compliance and Gate 8 security both declined the "or risk-accept"
   framing this item originally offered, on the grounds that the fix has no ordering dependency
   on the join and the loss it prevents is real destruction of an audit record rather than the
   at-least-once redelivery the design otherwise guarantees. `GuardianEngine::stop()` now
   persists before signalling the workers as well as after them; the post-join flush stays,
   because `persist()` erases the durably-written prefix so a record can never land under two
   keys. They were right that offering the two as equals was the error.
9. **Resolve or explicitly risk-accept the size-biased replay loss (#2364)** - the resolve/
   risk-accept half remains OPEN (decided 2026-07-23: risk-accept at the flip, with pre-agreed
   quantitative thresholds written before CH-5). ~~and land its telemetry first: the age of the
   oldest currently headroom-blocked batch, alongside item 4's fleet rollup.~~ - **telemetry
   DONE** on branch `feat/guardian-journal-age-observability`:
   `yuzu.guardian_journal_headroom_blocked_seconds`, an EPISODE age maintained at pass
   granularity in `GuardianLifecycleJournal` (set-if-unset on any observed block; cleared only
   after accumulated block-free coverage of the full candidate set - clear-on-clean-PASS was
   rejected in review because a pass is a 128-candidate slice and the sawtooth would zero the
   gauge in exactly the starvation regime; sparse, dormant-absent, fleet rollup MAX). NOTE for
   CH-5: this gauge has never fired outside unit tests - the CH-5 record must include a
   forced-blocking sanity step, or a 0 reading is ambiguous (no-block vs gauge-broken). Four
   mechanisms for the loss itself were built and reverted in this PR; the lesson recorded there
   is that the channel needs measuring before it is engineered.

   **Quantitative thresholds (2026-08-10, written before CH-5 per the above decision;
   proposed - confirm before the external #2340 chaos run).** Derived from the shipped
   caps (`kMaxJournalEntriesPerBatch`=256, window=4096 entries -> a batch is blocked only
   above ~94% occupancy per #2364's own math) and the retention bounds (7 d /
   1000 batches / 32 MiB, `docs/yuzu-guardian-design-v1.1.md` §25):
   - **Below 94% window occupancy: zero tolerable loss.** No batch should ever be
     headroom-blocked in this regime; any `evicted_no_send_evidence` increment here is a
     defect, not an accepted risk.
   - **Sustained starvation (>=94% occupancy held for the full 7-day retention
     window):** loss is accepted ONLY when attributable to that starvation - on the
     AFFECTED AGENT, `evicted_no_send_evidence` incrementing is covered by this
     risk-acceptance only while that agent's `guardian_journal_headroom_blocked_seconds`
     episode is concurrently live (nonzero). **Attribution is per-agent, not
     per-batch**: the gauge is a single episode age per agent (it "can start from
     already-delivered batches", per its own doc comment), so it cannot name which
     specific batch a given eviction belongs to - it can only confirm the agent was,
     in fact, in a starvation episode at the time. `evicted_no_send_evidence`
     incrementing on an agent with NO concurrent headroom-blocked episode is NOT
     covered by this risk-acceptance and must be investigated as a distinct defect.
   - **Capacity-reject classes (`stage_dropped`, `write_capacity_rejected`) are
     transient-only:** must clear within one maintenance-tick cycle (30 s page /
     120 s prune, `kGuardianJournalPageInterval`/`kGuardianJournalPruneInterval`) once
     the underlying write failure or occupancy condition resolves. Sustained nonzero
     across a full retention cycle rolls into the starvation regime above.
   - **Corruption/invariant classes (`quarantined`, `quarantine_failures`,
     `key_collisions`, `gauge_underflow`) carry zero tolerance** - any nonzero reading
     on a production endpoint is an incident (hardware fault or a bug), never an
     accepted-loss statistic; #2364's risk-acceptance does not cover them.
   - **For CH-11 specifically:** because attribution is per-agent (above), "no more
     than the true loss" is testable at agent granularity in CH-11's own
     single-cause setup (a controlled 500-agent SIGKILL cohort, not mixed causes):
     every agent that shows `_evicted_no_send_evidence` incrementing must ALSO show
     a concurrent (or immediately-prior) `headroom_blocked_seconds` episode: an
     evicting agent with no corresponding episode is a defect the scenario should
     fail on. This is an agent-count check, not a batch-count equality - CH-11's
     scenario doesn't (and per the gauge's shape, can't) support asserting an exact
     per-batch count.
   ~~**Open question, flagged rather than resolved here:** item 7 above says to run
   CH-5 at "the journal's HARD ceiling (2000 batches / 64 MiB)", double the shipped
   caps this threshold section derives from (1000 batches / 32 MiB,
   `kMaxJournalBatches`/`kMaxJournalBytes`). Unclear from the code alone whether
   2000/64 MiB is a deliberate 2x stress margin for the chaos run or stale text from
   before the caps were finalized - flagging for confirmation before CH-5 runs
   rather than silently picking one reading.~~ - **RESOLVED 2026-08-18, corrected
   same day (F11 #2298 governance, architect finding): 2000/64 MiB IS the
   deliberate figure - it is `hard_max_batches_`/`hard_max_bytes_`
   (`guardian_lifecycle_journal.hpp:682-683`), a real, actively-enforced
   write-capacity ceiling at 2x the soft retention caps, decoupled from them by
   design, shipped (`84b6cc31a`, 2026-07-19) three days before this item's own
   "2000 batches" text (`b75e365d6`, 2026-07-22). An earlier pass at this
   resolution wrongly called it stale text and substituted the soft caps below -
   that was wrong and is reverted; item 7 restored to the hard ceiling.** The
   threshold derivation below (from the soft 1000/32 MiB caps) is UNAFFECTED and
   still correct on its own terms - it characterizes loss tolerance under
   sustained near-100%-occupancy starvation, a different regime from CH-5's
   write-capacity stress test. A future CH-5 run at the hard ceiling should also
   confirm `write_capacity_rejected_` behaves as a transient, self-clearing
   backstop (matching the "Capacity-reject classes... transient-only" threshold
   above) rather than a sustained rejection under load - not yet verified either
   way.

   Thresholds themselves (the occupancy-percentage-based loss tolerances derived
   from the soft 1000/32 MiB caps) stand as written and are unaffected by the
   above correction. Posted for confirmation: issue #2364 and the #2340
   chaos-campaign issue (CH-11).
10. ~~**Make the replay pass lazy-parse** (Gate 3 performance, measured). `page_into_window` and
    `prune` both parse the ENTIRE journal before applying the 128-candidate cap: ~680 ms and
    ~668 ms per pass at the byte ceiling, 97% of it in `parse_journal_batch`, with `rows` (raw)
    and `cands` (parsed) both live for a measured +162 MiB RSS on the endpoint every 30 s.
    Building candidates as `(key, ts_ms)` and parsing only the ones actually considered takes
    the pass to ~110 ms and +66 MiB. The 128 cap currently bounds 0.5% of the work.~~
    - **DONE** via #2299 perf-P-1, and further than the item asked: the batch key carries the
    timestamp (`lc:<ts13>:<nonce>:<seq12>`), so `ORDER BY key` IS `(ts_ms, key)` and both
    passes select, order and expire candidates from KEYS ALONE. Prune parses no values at
    all; page reads a value only for a candidate it actually CONSIDERS - it needs the parsed
    batch to size the request, so that is the ones it places, the ones it finds blocked, and
    the remaining slice scanned for the smallest blocked requirement when the window is full -
    memoized, bounded by the 128 cap. Three consequences are documented at the code: a corrupt
    VALUE is now discovered and quarantined by the replay pass rather than by prune (a
    malformed KEY is still prune's, on sight); a corrupt-value batch the rotation never
    reaches before it ages out is therefore counted `evicted_without_send_evidence` rather
    than `quarantined`, so on a mass-corruption endpoint that audit-loss counter no longer
    separates "never delivered" from "never deliverable" and should be read alongside
    `quarantined`; and a candidate whose value READ FAILS is not counted as block-free
    coverage, so the item-9 episode cannot clear on a pass that had one. The key
    change is migration-free ONLY while the journal is dormant, which is why it landed
    pre-flip.
11. ~~**Bound the heartbeat's retry-persist** (Gate 3 performance). It is circuit-broken on
    FAILURE but unbounded on slow SUCCESS: 4096 staged records is 16 autocommit inserts under
    `mtx_`, ~9.9 ms healthy but able to approach the 5 s busy timeout each under KvStore
    contention. A per-tick batch cap or wall deadline is what makes "cheap retry-persist on the
    heartbeat" structurally true rather than true-in-practice.~~
    - **DONE**: `persist()` takes TWO per-call bounds - a BATCH cap
    (`kJournalPersistMaxBatchesPerTick`, 4) and a RECORD cap
    (`kJournalPersistMaxRecordsPerTick`, 1024) - and stops at whichever it reaches first. Both
    are passed only by the heartbeat tick, the one cadence caller. Two bounds rather than one
    because a batch cap alone is a latency budget masquerading as a throughput budget: four
    batches is ~1024 records when records are small, but as few as ~48 when large fields make
    the byte cap split them, and since the heartbeat is the only steady-state drain the low end
    would shed records through `journal_stage_dropped` - a NEW loss channel created by a
    latency fix (governance Gate 3 performance). The record cap floors the drain rate
    independently of record size. The cap check sits at the
    very end of the Inserted case, after the sequence, gauges, written count and provenance
    have all advanced, so a capped return is indistinguishable from the existing
    circuit-broken one and the remainder simply stays staged for the next tick. Boot,
    apply_rules and both shutdown flushes pass `kJournalPersistUnbounded`; NEITHER bound is
    defaulted, so a future cadence caller cannot inherit unbounded behaviour by omission
    (governance Gate 3 architect). Caps rather than a wall
    deadline: the repo has an earned rule against wall-clock bounds in tests (#2372), and the
    cap must count KvStore round trips, which the byte limit can multiply well past the
    16 batches a records-per-tick sizing would predict.
12. ~~**Jitter the maintenance phase per agent** (Gate 3 performance).~~ **DONE** - phase
    offsets on `last_page`/`last_prune`, plus a jittered release deadline on the BOOT and
    RECONNECT forced pages, enabled explicitly by the production wiring in `agent.cpp` (never
    inferred from other config: several tests drive a live worker with no timing override,
    and the production-boot-order regression depends on the worker running immediately). The
    deadline bounds the worker's condition-variable wait, so a deferred force is a real
    scheduled wake - polling it at the 5 s backstop would have re-synchronised every agent
    onto the backstop tick and spread nothing. A deferral never drops a kick, and the
    backlog-recovery refill re-arm is deliberately exempt. Original note retained: NOTE: this item used to
    size the fleet from a SUSTAINED redelivery floor of 0.1 batch/s/agent - ~256k events/s and
    ~615 Mbit/s at 10k agents. That floor no longer exists: replay consults the durable
    sent-label and does not re-offer delivered batches on an ordinary pass (#2345 round 8), so
    the steady-state redundant term is zero. The figure survives only as a BURST bound - a
    fleet-wide snapshot restore or gateway bounce still gives every agent a forced pass with a
    full token burst in the same cycle, which is exactly what jitter is for. Phase-jitter
    `last_page`/`last_prune` by U[0,interval) and jitter the BOOT page too, since a forced pass
    bypasses the cadence. Do not treat the old sustained number as a live gate.
13. ~~**Test the loop-death firewall**~~ - **DONE** (L3 commit e4d98560) (Gate 3 QE). Nothing
    could make `loop()`'s own tail throw, so the top-level catch and its counter were
    unexercised; a one-shot test seam (`inject_loop_tail_throw_for_test`) now injects a throw
    there, and a test asserts the escape is caught, `journal_maint_exceptions_` increments
    exactly once, the success stamps freeze (item-6 liveness), and `stop()` still joins cleanly.
    Mutation-verified: removing the catch aborts the process; removing its increment times out
    the spin.
    ~~and the pre-join persist~~ - **the pre-join persist half is DONE (round 7)**: a test parks
    the drain worker inside a blocked send, calls `stop()` on another thread, and asserts the
    pending record reaches disk *while the join is still outstanding*. Asserting after `stop()`
    returns cannot distinguish the two orderings, because the post-join flush persists the same
    record either way - which is why deleting the call used to leave the suite green.
14. ~~**Give the drain worker a liveness signal that does not rely on a counter incrementing.**~~
   - **DONE, closed by item 6** (as this note always said it would be): the staleness stamps are
   seeded at worker `start()` and advanced only by a completed non-throwing pass, so a worker
   that starts and then dies - or hangs without throwing - reads as an ever-growing age from its
   first heartbeat, and the emit-including-0 posture means "fresh" is a real reading rather than
   an absence. (Historical note kept: round 5's loop-catch increment made an *exception-killed*
   worker visible; it was a partial mitigation, not a closure.)

Tracked on #2298, which is the cutover gate list.

### 15. Deferred findings from the #2299 O(work) governance run — resolve or risk-accept before the flip

The L2 run closed one BLOCKING regression and a
long list of SHOULDs, but deliberately deferred the items below. They are recorded HERE, not
only in a governance transcript, because a deferred finding with no forward pointer is a
finding that gets re-discovered at flip time instead of resolved (Gate 6
enterprise-readiness). Each needs an outcome - fixed, or explicitly risk-accepted and
attributed - before `prefer_spark` flips. File them against #2298.

Recorded here, in the FIRST PR of the three-PR #2299 stack, rather than the last: most of
these are findings against this PR's own code, and if the rest of the stack stalled they would
otherwise be undocumented on `dev`. A few belong to the later PRs (UP-9/UP-10 to the persist
bounds, UP-6 to the jitter) and are listed anyway so the set stays in one place.

- ~~**UP-11 — the page SUCCESS stamp advances on passes that did NO work.**~~ **RESOLVED by
  #2452.** A no-token return, a `stopping_` return, or a pass whose every value read failed all
  refreshed `last_page_success_steady_ms_`, so `yuzu.guardian_journal_page_stale_seconds` could
  read healthy while replay was genuinely stalled. PRE-EXISTING from L1b, not introduced by L2 -
  but L2 is the rung that makes replay real, and this is the gauge an on-call engineer will trust
  first once it is. Both compliance and SRE called this the one deferred item that should be a
  flip PREREQUISITE rather than ordinary backlog. **FIX (governance Gate 7):** an initial per-cause
  negative enumeration kept missing no-work exits (the review round found boot-barrier, then
  headroom-blocked, quarantine-only, and a worker-vs-journal stop-flag divergence), so the page
  stamp now gates on a single POSITIVE signal - `JournalPageStats::progress_or_verified_idle`, set
  true only at page_into_window's successful tail iff the pass placed records OR ran a full scan of
  a clean, unblocked, uncorrupted, readable idle backlog. Every early return (null-kv, a `stopping_`
  bail, deferred, sent-scan/candidate/value read failure, boot-barrier, headroom-blocked,
  quarantine-only) leaves it false by construction, so a future no-work exit cannot advance it by
  forgetting to opt out. Mirrors the prune stamp's positive `progress_or_verified` gate; both also carry
  `!stop_requested()`. **PAGE-side cleared, and PRUNE-side now also cleared** for the same-class
  no-work exits: the prune stamp gained the symmetric positive `JournalPruneStats::progress_or_verified`,
  true iff retention was APPLIED (`evicted > 0`) OR verified genuinely idle. It reads a growing age on a
  scan failure, a **DELETE failure (UP-7)**, a **stop BEFORE the delete (UP8-3)** (all return early,
  before the set point), a **`skip_age` clock-decline of rows that were expired (UPR-2)** - `skip_age &&
  expired > 0`, so retention was deferred and the journal is not idle, though a big_step on a genuinely
  idle journal stays fresh - and a **quarantine-rename FAILURE (UPR-1)** that left a corrupt row stuck,
  mirroring the page-side guard (the last two found by the focused re-review). A stop during the trailing
  label-GC correctly keeps it true (retention already ran), and a quarantine SUCCESS reads fresh (progress).
  ONE prune residual is TRACKED, not closed here: a forward-clock-jump wipe still advances the stamp - the
  delete genuinely succeeded, so it is not a stamp-gating problem but the L5 clock-guards' (#2360/#2361) job to
  PREVENT the wipe. Also pre-flip (SRE observability): ship draft alert rules for
  `_headroom_blocked_seconds` / `_quarantined` / `_prune_failures` so the newly-stale gauges have
  actual alerts. One thing to remember when they land: the page stamp is verified PER-SLICE (cap 128),
  so a fully-unhealthy tail on a large journal surfaces only after ceil(N/128) page cadences - worst
  case ~8 x 30 s = 240 s at N=1000, thin under a 300 s (10x) `_page_stale_seconds_max` threshold: size
  the page-stale alert `for:`/threshold with that rotation lag in mind, or alert on
  `_headroom_blocked_seconds` (which is NOT slice-capped) for the congestion case. (The prune
  quarantine-rename-FAILURE case the K3 review flagged as by-contract-fresh is now CLOSED - the focused
  re-review's UPR-1 gate makes it read stale via `quarantine_stall_this_pass`, mirroring the page side;
  a quarantine SUCCESS still reads fresh, which is correct.)
- UP-5 — a pre-planted `quarantine:` twin makes the page-side rename Conflict every pass;
  bounded by the per-pass candidate cap, but can stall the drain behind ~128 KvStore round
  trips. Tampered-DB only. The same shape applies to the size-quarantine branch, where the row
  additionally keeps counting toward the byte ceiling and can permanently block writes.
- UP-6 — the boot forced page is deferred by up to one page interval, so a crash-looping
  process may never perform its boot replay. Records stay durable; the next healthy boot
  replays them.
- UP-9 / UP-10 — the persist bounds are a deliberate trade: a slower post-outage drain, and a
  tick that can still hold `mtx_` for roughly four busy timeouts (bounded, where it was
  previously unbounded).
- UP-12 — the `sent:` label namespace has no ceiling of its own and its GC is skipped on every
  early return, so stale labels can accumulate invisibly to the byte gauge.
- UP-15 — `stopping_` is a one-way latch with no reset. Harmless today (one `run()` per
  process) but a trap for any future in-process restart: maintenance would stay off while
  persist kept writing to the ceiling.
- UP-16 — the min-blocked inner scan memoizes up to a full slice of parsed batches purely to
  compute a size, in the memory-pressure regime.
- UP-3 / UP-4 / UP-17 — a bit flip inside the key timestamp is now decisive for retention
  ordering; nothing cross-checks key-ts against the value's own `ts_ms`; two agent processes
  sharing one `kv_store.db` would each replay the other's batches.
- Test-coverage gaps: the page-side quarantine rename `Conflict` branch, and the persist
  cap x circuit-breaker interaction. (The KvStore fallible-read branches are now covered for
  a CLOSED handle and for a real `prepare` failure, both mutation-verified. The remaining
  hole is a mid-SCAN failure - `rc != SQLITE_DONE` after rows have been returned - which
  needs a VFS shim; it is shared with the pre-existing `list_entries` and predates #2299.)
