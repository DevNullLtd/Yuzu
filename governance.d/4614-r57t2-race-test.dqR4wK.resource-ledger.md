# Resource Ledger — `4614-r57t2-race-test.dqR4wK`

Every owning boundary the C++ in `5fd6e3f33..bc76848c6` (`feat/3990-r57-t2-remeasure`,
PR #4614) acquires. Required by the Gate 1 contract on any C++ diff; recorded
here rather than only in the run narrative so a later reader can check it
against the code. Written retroactively during the Gate 6 full-mandatory-set
pass after compliance-officer reported no ledger artifact existed for this
range (policy-floor finding, BLOCKING) — the four commits in this range are
test-only (one new `TEST_CASE` in `tests/unit/test_guardian_spark_runtime.cpp`);
no production `agents/`/`server/` C++ changed.

This diff acquires exactly one new `std::future` (via `std::async`), one new
bare `std::thread`, and one new RAII cleanup guard, all local to the single
new `TEST_CASE`. Nothing in it acquires a raw fd/HANDLE/SOCKET/`FILE*`, an
OpenSSL/BCrypt object, an allocated C string, a mapped library, or any new
production-code mutex/thread.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `fut` (`std::future<std::expected<std::uint64_t,std::string>>`, from `std::async(std::launch::async, ...)`) | local, per loop iteration, `test_guardian_spark_runtime.cpp:3568-3570` | at the `std::async` call, once per iteration (30 iterations) | `fut.get()` at `:3597`, or (on early unwind) the future's own blocking destructor when it goes out of scope at end of iteration | none — never moved out of the loop body | If a `REQUIRE` between `:3568` and `:3597` throws (only `:3583`'s `wait_entered_hang` can), unwinding runs `cleanup`'s destructor (see next row) BEFORE `fut`'s own destructor, by declaration order — `cleanup` releases the parked backend first, so `fut`'s blocking destructor then joins an `attach_rule` call that resolves via its own internal bounded wait rather than blocking on a permanently-parked worker |
| `cleanup` (`struct Cleanup { FakeBackend* backend; ~Cleanup(){ backend->release_hang(); } }`, `:3579-3582`) | local, per loop iteration, stack-declared immediately after `fut` | construction at `:3582` | destructor at end of iteration scope (normal exit) or on unwind from any throw after `:3582` | none | RAII by construction — this IS the failure-cleanup mechanism for `fut` and for the parked `FakeBackend` worker thread. `backend` is a raw, non-owning pointer into `b` (a `shared_ptr<FakeBackend>` declared at `:3546`, outliving every iteration of the loop) — no dangling-pointer risk. `release_hang()` (`test_guardian_spark_runtime.cpp:312-318`) is mutex-guarded (`gate_mu_`) and idempotent (sets an already-`true` flag, re-notifies an already-satisfied condition variable) — calling it twice in the normal path (once here, once via the explicit `releaser` thread below) is a documented, harmless no-op on the second call, never a double-free or UB |
| `releaser` (`std::thread`, `:3592`) | local, per loop iteration | constructed at `:3592`, running `[&]{ b->release_hang(); }` | `.join()` at `:3596`, unconditional, three statements later (an optional `sleep_for` at `:3594` on odd iterations, then `rt->detach_all()` at `:3595`, neither of which can throw — `detach_all()` is `noexcept`-equivalent in practice, its own internal firewalling catches and swallows the one throwing call in its body, the T0d `spdlog::info` log line) | none | Bare construct-then-join with nothing throwing in the gap, matching this file's simple-bracket idiom used elsewhere for the same shape (e.g. the `releaser`-less single-thread-join sites throughout this file) rather than the Cleanup-wrapped idiom this file reserves for gaps where a throw IS possible between spawn and join. If `detach_all()` ever became throwing in the future, `releaser` would need its own Cleanup-style join-guard — not needed today, and this row makes that a compile-time-obvious follow-up rather than a silent gap |
| Detached `GuardianIoExecutor` worker threads, spawned transitively by `attach_rule()`/`detach_all()` inside the runtime under test | owned by `rt` (`GuardianSparkRuntime`, `:3547`), not by this test directly | on demand, per `arm()`/`disarm()` dispatch | not explicitly joined by this test — matches every other `[spark][runtime]` test in this file that doesn't spin on `active_backend_op_workers()==0` before teardown; the file's own soak-test comment (`:2287-2290` region) documents this as a KNOWN, accepted scope boundary ("Executor workers are DETACHED, so joining our own threads says nothing about them") for tests that don't specifically probe worker-count draining | n/a | Out of scope for this test, same as the two sequential R5.7 tests immediately above it in the file — this test's own assertions (`rule_count`/`armed_key_count`/`claim_queue_depth_for_test`, all `spin_until`-guarded) never depend on a specific worker count, only on the runtime's own logical state converging, which they verify directly |

**Adjudications recorded:** none required — no manual (non-RAII) resource
cleanup exists anywhere in this diff. `releaser`'s bare join (row 3) was
considered for a Cleanup wrapper and judged unnecessary given `detach_all()`
cannot throw across this test's own call boundary; recorded above as a named,
reviewable judgment rather than left implicit.

**Sanitizer coverage.** No TSan leg was run against this specific test in
this session (a full TSan rebuild of the worktree was judged out of
proportion to the findings already fixed — cpp-safety's and
quality-engineer's own independent proofs that this test cannot detect a
lock-scope-splitting regression were both obtained via direct code reading
and a temporary out-of-tree mutant, not a TSan run against the shipped test).
Tracked as a follow-up candidate, not blocking — the test's own `[tsan]` tag
states intent for a future TSan CI leg to pick it up, consistent with every
other `[tsan]`-tagged test in this file.
