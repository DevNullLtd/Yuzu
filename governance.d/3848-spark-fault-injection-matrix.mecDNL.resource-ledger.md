# Resource Ledger — `3848-spark-fault-injection-matrix.mecDNL`

Required by the Gate 1 contract on any C++ diff. Every owning boundary the C++ in
`origin/dev..HEAD` acquires, moves, or releases — recorded here rather than only in the
run narrative so a later reader can check it against the code, not against a description
of the code.

**Provenance note:** the first table below (rows 1-3) is the original Gate 1 Resource
Ledger, written at governance kickoff against `origin/dev @ 05c1d065e → HEAD @ bb8a1176d`
(11 commits, +1719/-38). It was compacted out of this session's visible context during a
later summarization and had to be recovered from the session's own JSONL transcript
rather than re-derived from memory — recorded here verbatim (reformatted only) so the
recovery itself is auditable. The second table covers every resource-relevant addition
across the eight further commits governance produced after that point (`1a2855e43`
through `1e3c1a6f7`), none of which existed when the first table was written. Current
scope: `origin/dev..HEAD`, 21 commits, 13 files, +2291/-40.

No new fd/HANDLE/SOCKET/`FILE*`/`sqlite3_stmt*`/OpenSSL/BCrypt/subprocess/mapped-library
resource appears anywhere in this diff. Every owning boundary below is either a
stack-local RAII type, an existing `std::unique_ptr<DirWatch>` whose transfer-timing (not
ownership model) changed, or a test-only `std::thread`/synchronization primitive.

## Table 1 — as of `bb8a1176d` (original Gate 1, recovered verbatim)

| Resource | Owner | Acquire | Release | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `TeardownLease` (wraps `std::atomic<uint64_t>& inflight_teardowns_`) | Stack-local in `disarm()`/`teardown_arm_race()`/`unregister_consumer()`/`arm_impl()` | Constructed at function entry (unarmed); `arm_locked()` called as the last statement under `mu_` | Destructor (`noexcept`, atomic `fetch_sub` guarded by an `armed_` bool — never double-releases) | Not transferred; strictly function-scoped | Unarmed leases (pre-built early returns before `arm_locked()`) release as a no-op; every path after arming — including exception unwind — hits the destructor |
| `std::unique_ptr<DirWatch>` (Windows) | `WindowsFileMechanism::dirs_`/`retiring_` | Existing (`push_retiring` reorders when the transfer happens, doesn't add a new owner) | Existing quarantine sweep / `drop_watch()` | `push_retiring` now takes `DirWatch&` (reference) instead of by-value `unique_ptr`, moving ownership only in the noexcept step | The allocating step (`emplace_back`) now runs *before* the caller relinquishes ownership, so a `bad_alloc` there leaves the watch fully owned by the original map entry, not freed |
| Test threads (`std::thread` — churners/evaluators/drainer/releaser/armer/killer/stopper/disarmer) | Stack-local in each `TEST_CASE` | `std::thread{...}` construction | Explicit `.join()` in every case; the Part-1 soak's `Cleanup` struct joins all of them in its destructor (covers the `REQUIRE`-throws-mid-test path too) | Not transferred | No detach anywhere in the diff at this point; verified by reading each `TEST_CASE` body |
| `BlockingGate` (test-only, mutex+cv+atomics) | `FakeBackend` member / test-local | Constructed with the backend/test fixture | Destroyed with owning object | N/A | Pure synchronization primitive, no OS handle |

## Table 2 — added `1a2855e43..HEAD` (governance rounds; not present when Table 1 was written)

| Resource | Owner | Acquire | Release | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `std::unique_ptr<DirWatch>` at `release_ancestor()` (Windows) | `WindowsFileMechanism::ancestors_` | Existing entry, resolved before this function's `push_retiring` call | `ancestors_.erase(it)`, unconditional on the SUCCESS path only | `try { push_retiring(it->second); } catch (...) { return; }` — on a caught throw the function returns WITHOUT reaching `erase(it)`, so the entry stays exactly where `push_retiring`'s own contract leaves it (untouched, still owned by `ancestors_`) rather than being destroyed while a cancelled-but-undrained kernel I/O may still reference it | The `return` (not fall-through) IS the failure-path cleanup: falling through to the unconditional `erase()` below after a caught throw was the actual defect this fix closes (a use-after-free class identical to `#2839`'s original bug, reintroduced via a naive catch-and-continue in an earlier draft, self-corrected before any reviewer flagged it) |
| Same pattern at `arm_ancestor()`'s zombie-drain block (Windows) | `WindowsFileMechanism::ancestors_` (the `slot` local reference) | Existing zombie entry (`slot && slot->removing`) | Drained via `push_retiring(slot)` before the fresh-watch branch runs | `try { push_retiring(slot); } catch (...) { return false; }` | On a caught throw, `slot` is left untouched (still a valid, if still-zombied, entry) and the caller gets an ordinary `false`/fault-reported return — no double-free, no orphaned owner |
| `ThreadJoinGuard` (test-only, `tests/unit/test_spark_mechanism.cpp`) | Stack-local in 9 `TEST_CASE`s | Constructed with a `ParkGate*`; `track(std::thread&)` stores a raw non-owning pointer to each tracked thread — does NOT extend the thread's lifetime, only records where to find it | Destructor: `gate->release()` (if non-null) then `t->join()` on every tracked thread still `joinable()` | Not transferred — a pure backstop over threads whose real ownership remains the enclosing `TEST_CASE`'s own locals | Runs on every unwind path (a `REQUIRE` throwing between spawn and the test's own explicit join), converting an unjoined-`std::thread`-triggers-`std::terminate()` policy-floor violation into a clean unwind. **Correctness here is entirely a declaration-order property, not a code-logic one**: every tracked `std::thread`, and any `std::atomic` its lambda body writes to, MUST be declared BEFORE the guard's own construction, because C++ destroys automatic-storage locals in reverse declaration order — a thread or atomic declared AFTER the guard destructs BEFORE it on any unwind, receiving none of this protection. This exact ordering mistake was made twice in this same diff's own history (a second thread declared-then-tracked-after the guard at 7 of 9 sites; that same fix's own completion-flag atomic hoisted alongside the thread but the atomic itself left un-hoisted at 6 of those 7 sites) before being caught — first by three independent Gate 8 reviewers, then by an advisor review of that fix — and corrected both times. All 9 sites currently place every tracked thread and every atomic its body writes to BEFORE the guard; independently re-traced and confirmed by a dedicated post-fix re-review. |
| `ArmerGuard` (test-only, `tests/unit/test_guardian_engine_spark_reconcile.cpp`, one site) | Stack-local | Constructed with `{f.mechanism, &armer}` immediately after `armer`'s spawn (the ONE thread it tracks is declared before it — no ordering hazard, single-thread case) | Destructor: `mech->release_hang()` (idempotent — sets an already-true flag, a redundant `notify_all` — safe to call twice) then `t->join()` if joinable | Not transferred | Same backstop shape as `ThreadJoinGuard`, a separate local type because this fixture's hang/release API differs from `ParkGate`'s |
| `Gate`/`GateOpener` (test-only "wedge idiom", `tests/unit/test_spark_mechanism.cpp`, 3 sites — 1 pre-existing `#1979/#1982` site unchanged, 2 new for the `#2839` follow-up zombie-drain tests) | `std::shared_ptr<Gate>` shared between the test and the mechanism's injected `emit_` callback; `GateOpener` is stack-local, declared immediately AFTER the real `ISparkMechanism` instance (`mech`) it protects | `Gate` — none (pure mutex+cv+atomic, no OS handle). `GateOpener` — constructed holding a copy of the `shared_ptr<Gate>`, right after `mech` | `GateOpener`'s destructor calls `gate->open()` unconditionally (idempotent — a second `open()` on an already-open gate is a no-op relock+notify) | Not transferred | Because `GateOpener` is declared AFTER `mech` in the same scope, it destructs BEFORE `mech` on any unwind (reverse declaration order, the same rule `ThreadJoinGuard` depends on, applied correctly here from the first draft) — so the mechanism's worker thread, parked inside the injected `emit_` callback via `gate->wait()`, is always released BEFORE `~WindowsFileMechanism()`'s own `stop()`/`worker_.join()` runs. Without this ordering, a failed assertion mid-test would leave the worker permanently wedged and `~WindowsFileMechanism` would hang the whole test binary joining a thread that will never return. The wedge precondition itself (`REQUIRE(eventually([&] { return gate->emit_calls.load() >= 1; }))`, promoted from `CHECK` in this same diff) is a false-green consideration, not a resource-ownership one — recorded in the findings ledger, not here. |
| `DirCleanup` (test-only, extended in this diff from one directory to two — `dir`/`trigger_dir`) | Stack-local, declared BEFORE `mech` in the same `TEST_CASE`s that use `Gate`/`GateOpener` | Constructed holding two `const fs::path&` references | Destructor: `fs::remove_all` on both paths, best-effort (`std::error_code` overload, never throws) | Not transferred | Declared BEFORE `mech`, so it destructs AFTER `~mech` has closed its real Windows kernel handles (`ReadDirectoryChangesW`/IOCP) — removing the on-disk directories only once nothing still has them open. Getting this order wrong (cleanup before the handle is actually closed) is a known Windows footgun (`ERROR_DIRECTORY_NOT_EMPTY`/sharing-violation on delete-while-open); this diff's ordering avoids it, and the two-directory extension (needed because the corrected `#2839` zombie test uses a genuinely separate ancestor/trigger directory, per the false-green fix recorded in the findings ledger) preserves the same before-`mech` placement for both paths. |
| `io_executor_stats_for_test()` accessor (`agents/core/src/guardian_spark_runtime.hpp`) | Not an owning boundary — a `[[nodiscard]]` const accessor returning `GuardianIoExecutor::Stats` BY VALUE (a plain aggregate of counters) | N/A | N/A | Copy-returned; no reference/pointer into `GuardianIoExecutor`'s internals escapes | N/A — cannot fail, no allocation beyond the trivial-copy return |
| `set_file_retire_fault_hook_for_test()` seam (`agents/core/src/spark_mechanism.hpp`/`spark_file.cpp`, Windows-only) | Not an owning boundary — a `std::function<void()>` test hook stored as a member, invoked once then left set (single-shot-on-first-use, not single-shot-on-installation — a documented test-authoring contract, not a resource-ownership one) | Set via the free function before the triggering call | Never explicitly released — lives for the mechanism's lifetime, harmless when unset (default-constructed empty `std::function`, checked before invocation) | N/A | N/A |

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists
anywhere in this diff at any point in its history. The one close call was the
`release_ancestor()` catch block's fall-through hazard (Table 2, row 1) — a logic defect
in when an existing RAII-owned resource gets released, not a missing-RAII defect — caught
and self-corrected before any reviewer flagged it, then independently re-verified sound by
cpp-safety, cpp-expert, cross-platform, and (via real hardware) DGRHP.

**Sanitizer coverage.** Both real-mechanism `DirWatch`/kernel-I/O paths (Table 1 row 2,
Table 2 rows 1-2) are Windows-only (`#ifdef _WIN32`) and were verified on real Windows
hardware (DGRHP): a genuine crash pre-fix, a clean pass post-fix, run twice per state (8
runs total), zero variance. **Not ASan-verified** — MSVC `/fsanitize=address` was
separately confirmed infeasible under this repo's current vcpkg toolchain (1266 `LNK2038`
link-time mismatches; vcpkg's binary-cache grpc/protobuf/abseil aren't ASan-instrumented,
and no triplet rebuilds them with matching instrumentation). This is a real, disclosed gap
in sanitizer coverage for these two rows specifically, not a claim of stronger coverage
than actually exists. The `TeardownLease`/engine-side rows (Table 1 row 1) ARE ASan- and
TSan-verified (Linux `build-linux-asan`/`build-linux-tsan`, `[teardown]`/`[tsan-heavy]`
tags, clean on every re-run across this diff's full history). All test-only RAII additions
(`ThreadJoinGuard`, `ArmerGuard`, `Gate`/`GateOpener`, `DirCleanup`) are exercised under
plain, TSan, and (where Windows-independent) ASan builds as part of the ordinary `[spark]`
suite — clean, 12213-12214 assertions (a pre-existing, unrelated ±1 timing variance) /
451 cases, stable across repeated runs at current HEAD.
