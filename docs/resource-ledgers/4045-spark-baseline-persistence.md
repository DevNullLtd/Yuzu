# Resource Ledger - #4045 Spark baseline-on-arm persistence

This ledger lists every lock, atomic, buffer, borrowed pointer, callback, thread and test seam the
#4045 change set introduces or moves, with its owner and release path, for the whole branch
(`056f01a20` to the branch tip). A Resource Ledger is a policy-floor artifact (CLAUDE.md standing
rule 2), so it is a standalone file rather than a line in a PR description or a governance
transcript. It was first written as the Gate 1 summary of the governance run, was re-derived by the
`cpp-safety` reviewer at the end of every fix round, and this file is the final form, re-checked
against the code at the tip. Format follows
`docs/resource-ledgers/spark-criterion10-timing-instrumentation.md`.

Nothing in this change adds a file descriptor, HANDLE, SOCKET, `FILE*`, `sqlite3*` or
`sqlite3_stmt*` (the persister writes through the engine's existing `KvStore`, and the busy
wait on the existing handle is now a `sqlite3_busy_handler` over a heap-owned atomic budget,
#5604, see the #5604 rows of the last table), OpenSSL or BCrypt object, allocated C string,
mapped library, temp path, subprocess or production
thread. The persister runs on three existing threads: the engine's callers (`apply_rules`, `stop()`
under `mtx_`) and the existing drain worker. A mechanical grep over the added production lines finds
no such expression in code (`new` or `delete` expressions, `malloc`, `free`, `reinterpret_cast`,
`const_cast`, `string_view` or `detach`); the words occur only in comments and in deleted special
members.

## Lock order, destruction order and publication protocol

- **Lock order.** `GuardianEngine::mtx_` -> `GuardianBaselinePersister::persist_mu_` ->
  `GuardianSparkRuntime::registry_mu_`, and `persist_mu_` -> `KvStore::mu_`. The drain worker takes
  `persist_mu_` -> `registry_mu_` and never `mtx_` (`WorkerHostileMutex` aborts a sanitizer or debug
  build that tries). `persist_mu_` is a leaf: it is never taken under a runtime lock.
  `stage_unstaged_baselines()` takes `registry_mu_` after `mtx_` with `persist_mu_` NOT held (the
  Stop pass takes `persist_mu_` afterwards), the same pair `apply_rules` -> `attach_core` takes.
- **Destruction order.** `agent.cpp` declares `kv_store_` before `guardian_`, so the engine (and the
  persister it owns, which borrows the `KvStore*`) is destroyed first; the drain worker is joined
  before either. The runtime holds no `KvStore`: its drop counter is a `shared_ptr` the persister
  copies, so it stays valid whichever of the two dies first.
- **Published persister pointer.** `GuardianEngine::baseline_persister_published_` is a
  non-owning `std::atomic<GuardianBaselinePersister*>`, stored once with release by
  `wire_spark_engine` (under `mtx_`, right after `make_shared`) and never cleared. Readers use
  acquire: the two heartbeat getters and the top of `stop()` (for `begin_stop()`).
  A `stop()` that loads null before the wire publishes is covered by a second `begin_stop()` after
  `stop()` takes `mtx_` (first call wins).

## `agents/core/src/guardian_baseline_persister.hpp`, `guardian_engine.{hpp,cpp}` (persister side)

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `GuardianBaselinePersister` (copy deleted) | Engine `shared_ptr baseline_persister_`, plus a second `shared_ptr` in the drain worker's `maint_.baselines` | `wire_spark_engine` | Worker joined first, then the last reference at engine destruction | `make_shared` throwing leaves it unpublished: the getters read 0 and `stop()` is unmarked until its post-lock `begin_stop()` finds no persister either, so nothing is staged to lose |
| `KvStore* kv_` (borrowed, may be null) | Persister member, never owned | Constructor | Never | Null is counted (`no_store_pending`) and logged once; staging is kept. Unreachable in production (both arm paths dereference `*kv_` first) |
| `persist_mu_` (`std::mutex`) and the `std::unique_lock` taken `try_to_lock` then `lock()` in `persist_staged` | Persister; the lock is a local RAII object | `persist_staged` entry, or `hold_seed_fence()` | Scope end | RAII. A pass that throws releases it. The seed fence is a move-only `unique_lock` that `reconcile_rule_locked` moves into its local `baseline_fence`, held across the KV seed read through `attach_rule` |
| `WaiterGuard` over `lock_waiters_` and `priority_waiters_` | Persister nested struct, non-copyable, noexcept | Before a blocking `lk.lock()` | Block end | Decrements on a throwing `lock()`; pinned by E50 |
| `ApplyScope` over `apply_active_` | Persister nested class, non-copyable, null-safe | `apply_rules` baseline section (`mtx_` held) | `apply_rules` exit on every path | Destructor on unwind; a Worker pass defers while any scope is alive |
| `stop_state_` (`atomic<uint8_t>` 0/1/2) and `stop_began_rep_` (`atomic<Clock::rep>`) | Persister, lock-free | `begin_stop()`: CAS 0 -> 1 (acq_rel), relaxed store of the mark, release store of 2 | Never reset; dies with the persister | A second concurrent caller returns at once; a reader trusts only state 2 (acquire), then reads the rep. A clock that reads 0 cannot disable the mark |
| `stop_store_trouble_` (`atomic<bool>`) | Persister, lock-free | `note_stop_store_trouble()` (release), called from `GuardianEngine::stop()` only, through `stop_stage_end()`, and only for a stage that took at least `kBaselineStopTroubleThreshold` (a fast failure is not evidence) | Never reset: `stop()` is terminal, so the flag can only describe the one stop that raised it | noexcept; read with acquire by the Stop pass under `persist_mu_`. Without it a late start never skips |
| `stalled_` and `stalled_at_` (read by a LATE Stop pass as slow-store evidence, #5604), `cursor_`, `backoff_`, `backoff_initial_`, `backoff_max_`, `pass_budget_`, `stop_budget_` | Persister members, guarded by `persist_mu_`; the TEST-ONLY setters take `persist_mu_` | Per attempting pass | n/a | `cursor_` assignment is inside a try/catch; a pass that attempted nothing changes none of them |
| `next_attempt_rep_` (`atomic<Clock::rep>`) | Persister; read lock-free by the Worker retry floor, written under `persist_mu_` | After a failed pass | Reset by a pass with no failure | n/a |
| `persist_failures_`, `no_store_pending_`, `persist_refusals_`, `firewalled_exceptions_` (`atomic<uint64_t>`) | Persister | `fetch_add` at the event | Never | Relaxed counters; `failure_signals()` sums them with the runtime's drop counter, lock-free |
| `staging_drops_` (`shared_ptr<const atomic<uint64_t>>`) | Persister member, never reseated | Constructor, copied from `staged_baseline_drops_source()` | Last holder | Outlives runtime teardown |
| `no_store_logs_`, `info_logs_`, `stop_skip_stalled_logs_`, `stop_skip_late_logs_`, `yields_`, `backoff_deferrals_`, `lock_waiters_`, `priority_waiters_`, `apply_active_` | Persister atomics (log latch and test observation, plus the two waiter counts the Worker pass reads) | `fetch_add` at the event | Never | Relaxed |
| `snap` and `done` vectors, `std::span<const CapturedBaseline>` over `done` | Pass-local; the span is consumed synchronously by `erase_staged_baselines_if_unchanged` and never stored | `persist_staged` | Scope end | `done` is allocated before the first write, so nothing after a write can throw; a throw before the first write loses nothing and widens the worker backoff |
| `should_stop` (`const std::function<bool()>&`) | Borrowed for one call, worker thread only | Call-expression temporary | End of the full-expression | n/a |
| `clock_`, `post_snapshot_hook_`, `post_write_hook_` (`std::function`) | Persister members, TEST-ONLY; the setters take `persist_mu_`; `begin_stop()` and `stop_stage_begin()/end()` read `clock_` unlocked, which is safe only because tests set it before threads start | Test setters | Member | Restored by `HookGuard4045` / `FakeClock4045` on every exit |
| `kKvStoreBusyTimeout`, `kBaselinePassBudget`, `kBaselineStopBudget`, `kBaselineShutdownGrace`, `kBaselineStopLatestStart`, `kBaselineStopTroubleSlack` (250 ms since #5604; 500 ms before), `kBaselineStopTroubleThreshold` (the stop busy budget minus the slack, 750 ms since #5604; 4.5 s before) | `inline constexpr` values (no resource) | Compile time | n/a | A `static_assert` in `agent.cpp` ties `kBaselineShutdownGrace` to `kShutdownDeadlineGrace`; E46, E51 and E53 pin the values; a `static_assert` keeps the threshold between 0 and the stop busy budget; `kBaselineStopLatestStart` is 18 s since #5604 (15 s before), pinned by a `static_assert` and E46 |
| `baseline_stop_flush_done_` (`bool`) | Engine, guarded by `mtx_` (only `stop()` sets it) | First `at_stop` flush, set before the stage and the pass | Never | Set before the attempt, so the destructor's second `stop()` flushes and logs nothing |
| `baseline_stop_incomplete_logs_`, `baseline_stop_unstaged_logs_`, `baseline_stop_flush_threw_logs_`, `baseline_stop_sweep_threw_logs_` (`atomic<uint64_t>`) | Engine, TEST-ONLY observation beside each ERROR call | `fetch_add` at the log site | Never | Each is inside its own try/catch(...) |
| `stop_stage_hook_for_test_` (`std::function<void(const char*)>`) | Engine, guarded by `mtx_`; the setter takes `mtx_` | Test setter | Member; cleared by `HookGuard4045` | Called from `stop_stage_hook_locked` at the START of each stage, inside a try/catch(...) |
| `stop_stage_begin_locked()` / `stop_stage_hook_locked()` / `stop_stage_end_locked()` / `stop_journal_flush_locked()` | Engine member functions, `mtx_` held, noexcept | `stop()` | n/a | No resource: read the persister's clock and report a stage that took at least `kBaselineStopTroubleThreshold` (750 ms since #5604; 4.5 s before) |

## `agents/core/src/guardian_spark_runtime.{hpp,cpp}` (staging side)

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `staged_baselines_` (`std::map<std::string, CapturedBaseline>`) | Runtime, guarded by `registry_mu_` | `stage_baseline_locked` (noexcept, returns bool), `salvage_unstaged_baseline_locked` (noexcept, returns bool, `[[nodiscard]]`), the `attach_core` pre-stage, `stage_unstaged_baselines()` at stop | `erase_staged_baselines_if_unchanged` by identity after Written or Refused | The snapshot is a COPY; a throw leaves staging intact; a failed stage leaves the generation flagged and counts one drop |
| `RuleGeneration::baseline_unstaged` (`bool`) | Runtime, guarded by `registry_mu_`, per generation | `evaluate_key` commit, `attach_core` | Dies with the generation; cleared on a successful stage (commit, attach, withdrawal salvage, the stop sweep) | A failed stage keeps it set and counts one drop per attempt; the stop sweep returns the number still set |
| `staged_baseline_drops_` (`shared_ptr<atomic<uint64_t>>`) | Runtime member, never reseated | Constructor | Last holder (runtime or persister) | `fetch_add` is noexcept. It also counts the `attach_core` read-back whose copy throws after a successful staging; that is not a staging attempt, and has no counter of its own |
| `inherited_hash` (`std::string`) in `attach_core`, and its read-back after `detach_rule_locked` | Local, `registry_mu_` held | Copy of the staged hash | Moved into `rg->assertion.expected_hash` (noexcept move) or scope end | The first read is before the detach (a throw is a plain unwind, the prior arm survives); the read-back is inside try/catch(...) with a noexcept counter bump because the prior generation is already gone |
| `stage_unstaged_baselines()` | Runtime member function; `registry_mu_` held for its span | Engine `stop()` after the worker join and the runtime's `begin_stop()` | Scope exit | Not noexcept (the lock can throw); the engine firewalls it. A per-rule `key_for_rule` throw is caught inside the loop, counted, and the loop continues |
| `fail_next_stage_baseline_` (`atomic<int>`), `fail_next_snapshot_`, `fail_next_inherit_copy_` (`atomic<bool>`), `fail_next_unstaged_sweep_` (`atomic<bool>`), `unstaged_sweep_stopping_for_test_` (`atomic<int>`) | Runtime, TEST-ONLY seams | Test setters or the sweep | Decrement or `exchange(false)`; the last records whether `stopping_` was set when the sweep ran | One-shot; relaxed. `fail_next_unstaged_sweep_` makes the sweep throw before its lock |

## `agents/core/src/guardian_outbox_drain_worker.{hpp,cpp}`, `agent.cpp`, `kv_store.{hpp,cpp}`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `maint_.baselines` (`shared_ptr<GuardianBaselinePersister>`) | The worker's maintenance struct | Copied in at construction | Worker destruction | Null means no baseline persistence runs |
| `baseline_recheck_pending`, `logged_baseline_throw` | Locals of the worker loop | Per cycle | Loop exit | The latch is local so the engine's firewall cannot suppress the worker's only log line |
| Worker baseline step | The existing joined worker thread (no new thread) | Each loop cycle, before the outbox drain | n/a | Own try/catch, counted on the persister; never takes `mtx_` |
| `kKvStoreBusyTimeout` use in `KvStore::open` (#5604) | Existing sqlite handle | `sqlite3_busy_handler(raw_db, &kv_busy_handler, busy.get())`, initial budget 5000 ms (value-preserving) | Handle close (`sqlite3_close` runs before the context is released; defensive ordering, closing runs no handler) | The install cannot fail on an open handle; a non-OK result is logged and tolerated (a locked write then fails at once), with no hand cleanup. The context is allocated BEFORE `sqlite3_open_v2`, so a `bad_alloc` has no handle to leak |
| `sqlite3*` connection (`db_`) (#5604: no new one) | `KvStore`; closed in the destructor and move-assignment | `KvStore::open` (existing) | `sqlite3_close` | Pre-existing early returns in `open()` close it by hand; #5604 adds none |
| `stop_busy_timeout_ms_` (`atomic<int64_t>`) (#5604) | `GuardianEngine` member, default `kKvStoreStopBusyTimeout`; only a test setter writes it | Constructor | Dies with the engine | Read once, relaxed, by `stop()` before `mtx_`; `KvStore::set_busy_timeout` clamps it to 0 to 1 h |
| `thread_local` wait clock in `kv_busy_handler` (start time, last count) (#5604) | The calling thread, namespace-level `constinit thread_local` | First handler call on the thread | Thread exit | No allocation or destructor; `constinit`, so constant-initialised by construction (last count -2, never a count SQLite passes). The start is re-captured when `count <= 0` or when the count does not continue the previous call's count on this thread (previous + 1); the give-up forgets the count, and every public `KvStore` method forgets it on entry (`CallLock`). A scheduler stall or SQLite's own sleep inside a continuing wait does not renew the budget. What can still continue a count is a second lock wait inside ONE statement step (rollback-journal mode): it shares the first wait's clock, so the budget is per statement step, as with `sqlite3_busy_timeout()` |
| `journal_stop_pending_logs_` (`atomic<uint64_t>`) (#5604) | `GuardianEngine`, the once-only latch for the ERROR call in `stop_journal_flush_locked` (read there before logging; tests also read it) | `fetch_add` after the log | Never | Inside try/catch(...); at most one line per engine; the gate is `prefer_spark_ && spark_runtime_ && lifecycle_journal_`, same as the persist |
| `KvBusyState` (`std::atomic<int64_t>` budget) (#5604) | `KvStore`, `unique_ptr`, heap-owned so the pointer SQLite keeps survives the `KvStore` move | `KvStore::open` | `KvStore` destruction or move-assignment, after the connection is closed | `set_busy_timeout` is a lock-free atomic store, never under `mu_`; `stop()` lowers it once to `kKvStoreStopBusyTimeout` (1 s), terminal |
| `kShutdownDeadlineGrace` mirror `static_assert` | `agent.cpp`, compile time | n/a | n/a | A drifting mirror is a build failure |

## Test seams (all `*_for_test`, no production caller)

Persister: `stop_begun_for_test`, `stop_store_trouble_for_test`, `stop_skip_logs_for_test`,
`info_logs_for_test`, `no_store_logs_for_test`, `seed_fence_held_for_test`,
`lock_waiters_for_test`, `apply_active_for_test`, `yields_for_test`,
`backoff_deferrals_for_test`, `backoff_for_test`, `set_clock_for_test`, `set_backoff_for_test`,
`set_budgets_for_test`, `set_post_write_hook_for_test`, `set_post_snapshot_hook_for_test`.
Engine: `baseline_persister_for_test`, `baseline_stop_incomplete_logs_for_test`,
`baseline_stop_unstaged_logs_for_test`, `baseline_stop_flush_threw_logs_for_test`,
`baseline_stop_sweep_threw_logs_for_test`, `set_apply_post_drain_hook_for_test`,
`set_seed_read_hook_for_test`, `set_post_attach_hook_for_test`, `set_stop_stage_hook_for_test`,
`unpublish_baseline_persister_for_test`. Runtime: `stage_baseline_for_test`,
`staged_baseline_count_for_test`, `fail_next_stage_baseline_for_test`,
`fail_next_snapshot_for_test`, `fail_next_unstaged_sweep_for_test`,
`fail_next_inherit_copy_for_test`, `unstaged_sweep_stopping_for_test`. Drain worker:
`stop_requested_for_test`. KvStore (#5604): `busy_timeout_for_test`, `busy_handler_for_test`,
`busy_retry_sleep_for_test`. Engine (#5604): `set_stop_busy_timeout_for_test`,
`journal_stop_pending_logs_for_test`. Test threads (E45, E50, E52, E53, E54, E57, `#5604 A1`)
are `std::thread`s under `Join4045` plus `ScopeExit` unpark guards declared after the join
guards, so a failing `REQUIRE` releases a parked hook before the join.

Sanitizer coverage: ThreadSanitizer and AddressSanitizer plus UBSan runs of the `#4045*` and
`[spark][guardian]` suites were run by the governance reviewers at the end of each fix round (the
committed governance record is a merge obligation, not yet written); the nightly tier
keeps both. Windows and macOS were not compiled for this change.
