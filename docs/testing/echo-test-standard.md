# Echo test-writing standard

How to write a test under `tests/unit/**/test_echo*.cpp`. It applies to new and changed Echo tests,
is enforced in part by a lexical gate (see [The gate](#the-gate)), and sits on top of the general
contract in [unit-test-conventions.md](unit-test-conventions.md).

Echo tests have caused repeat Windows CI flakes and timeouts on the shared runners (#7173, #7135,
#7177, #7872), so the rules below are about two things: keeping the cost of a test
machine-independent, and keeping a test honest about the host it ran on.

## Cost and determinism

1. **Open a migrated template database, never build one per test.** Use `yuzu::test::open_echo_db`
   (`tests/unit/echo_test_db.hpp`): it migrates once per process and clones the file. Per-test
   migration DDL and per-test fsyncs are what pushed the Windows leg past its limits (f6bfa1f4d4,
   b85549dbb3).
2. **Seed cheaply.** Insert fixtures with a recursive CTE or in memory, not row-by-row through the
   store's public write path, unless the write path is what is under test. Seeding through raw
   autocommit statements was most of the v10 split's 10,774 fsyncs (f6bfa1f4d4); `insert_tier_rows`
   (`tests/unit/test_echo_aggregator.cpp`) puts N rows in with one recursive-CTE statement.
3. **No real clock, sleep or socket wait in a unit test; inject the boundary.** Take the clock
   (`EchoFold::NowFn`, `echo_fold.hpp`), the open path (`OpenSeams`, `echo_db.hpp`) and any OS reader
   as a parameter and feed fixtures. Wait on a future, `std::latch`, condition variable or callback,
   never `sleep_for` and poll. Two real-time waits are allowed, each with a reason: a **bounded
   negative wait** (a "did not happen" can only be seen by waiting, and a slow host can make it pass
   vacuously, never fail), and a **real-OS case** that exists to touch the real socket or process
   table, with its reason stated in the case comment. The CLOSE_WAIT dispatcher case read a real
   loopback socket with no receive timeout, so a missing FIN hung it until the shard timeout (#8211);
   `wait_for_peer_fin` (`tests/unit/test_echo_local_dispatcher.cpp`) now bounds the read at 5 s. The
   only `sleep_for` the Echo tests had, an idle loop in the concurrent writer of the retention-pass
   case in `test_echo_aggregator.cpp`, became a `break`.
4. **Every wait is bounded, and the thread it waits on is joined by a guard.** A failed `REQUIRE`
   unwinds; the unwind destroys what the thread captured. Declare the guard (`yuzu::test::ScopeExit`,
   `tests/unit/test_helpers.hpp`, or the local `Joiner` in `test_echo_aggregator.cpp`) after what it
   releases, so it runs first. The raw-thread rule: a `std::thread` with no throwing assertion and no
   blocking wait between its start and its join needs no guard, because nothing can unwind past it;
   add one the moment either appears. Evidence: a failed `REQUIRE(fut.wait_for(...))` unwound into a
   `std::async` future destructor that blocked on the stuck worker, hanging the run to the meson
   timeout (#8210); `test_echo_open_retry.cpp` and `test_echo_local_dispatcher.cpp` carried four such
   sites, and the GC/fold case in `test_echo_fold.cpp` now releases and joins its workers through a
   `ScopeExit`.
   - A call whose **return** is under test (`OpenRetryLoop::stop()`, a plugin's `shutdown()`) goes
     through `yuzu::test::must_return_within` (`tests/unit/test_bounded_return.hpp`), never
     `std::async` plus `wait_for`: the future's destructor blocks in the same hung call.
5. **A `CHECK` on a size that guards an index is a `REQUIRE`.** `CHECK(rows.size() == 1)` followed by
   `rows[0]` carries on into an out-of-range read when the size is wrong. (`.at()` throws, a clean
   failure.) Found at `test_echo_store.cpp` (`rows[0]` after a size `CHECK`) and
   `test_echo_netqual_nstat.cpp` (`kept[1]`) (#8212); the sweep found the same shape twice in
   `tests/unit/server/test_echo_process_tree.cpp`. An index already bounded by the same size is safe
   and takes the marker instead: a `REQUIRE` inside a data-driven loop would end the case on its
   first bad row (`tests/unit/server/test_echo_timeline_render.cpp`, where the loop bounds `i` by
   `labels.size()`).

## Host dependence and honesty

6. **Name the cause, or fail.** A case that depends on ETW, the registry or a real socket classifies
   the environment failure (`etw_skip_reason`, `require_etw_or_skip`, `test_echo_registry_source.cpp`)
   and `SKIP`s only on a named cause; any other failure fails with the OS code (47f816f27c,
   ab3e2a2cf4, fb818a2e19; #7580, #7763). The opposite shape is a failed probe read as a clean
   answer: a Windows cleanup that took a failed HKU listing for "no mount", and an `is_elevated()`
   that returned false when the token query itself failed (#8129). #8012 shows what an unnamed cause
   costs: seven Instructions commands, three of them Echo's, report `FAILURE` on a Linux lane and the
   issue records no cause.
7. **Keep real-OS cases off the shared critical path; share no global session.** The agent suite's
   shards are the bottleneck. A real-OS case lives where its cost is already budgeted, and none
   holds a session another case reads. Salt every fixed name, port or path (CLAUDE.md, "Test
   conventions"). The 14 `echo plugin:*` dispatcher cases run in agent shard C (#8244), the slowest
   agent shard, whose limit already had to be doubled (#7177). A real-time ETW session outlives its
   test process, and the four runner agents share one OS identity, so a killed test leaves state the
   next job inherits (#7175).
8. **Restore the plugin singleton on unwind, and pass under `--order rand`.** The loaded plugin is a
   process singleton. `EchoSession` (`tests/unit/test_echo_local_dispatcher.cpp`) owns init and
   shutdown, restores any source a case paused, and bounds its shutdown on every path, the
   destructor after a failed `REQUIRE` included. Run a new case with `--order rand` and several seeds
   before pushing. Evidence: several dispatcher cases started and shut the plugin down by hand, so a
   failed `REQUIRE` left it initialised or a source paused for the cases after it, and one case
   depended on declaration order (#8213). `EchoSession` now owns init and shutdown for all 14 cases;
   the source-health ledger reset the issue also asks for needs a production line and stays open there.
9. **Every timeout and bound cites a recorded measurement.** A limit is set from data and raised only
   with a new measurement recorded beside it. `tests/meson.build` carries the Echo limits with their
   figures; #8234 tracks CI keeping no per-case timing, and `must_return_within` prints the real
   elapsed seconds of every bounded call to the test log so bounds can be re-derived. A pure hang
   backstop on an in-memory wait that the code under test releases (`kBound` in
   `test_echo_open_retry.cpp`: a zero-delay loop, no I/O) is not a performance limit; it says so
   beside the constant instead of citing a measurement. Both
   directions are on record: 187cf77e83 moved the v10 migration cases into their own entry, from
   per-case times, rather than raise the 90 s limit that would also have hidden a real slowdown, and
   3fc601419b raised the echo limit to 180 s and agent shard C to 480 s (A and B stay at 240 s)
   from measured runs, writing each figure beside its `timeout:`.
10. **New Echo tests follow this standard, and the gate checks the lexical half.** The PR template
    carries the checklist line; the gate is [below](#the-gate).

### The bounded-return constant

`yuzu::test::kReturnBound` is **120 s**, derived and not guessed. The slowest single Catch2 leaf of
the 13 `echo plugin:*` dispatcher cases that existed when it was measured, on native Windows MSVC
Debug (a Windows host, 5 runs, a WSL VM active, CPU 12-31%) was **38.7 s**. A shutdown happens inside
a leaf, so that is an upper bound on any shutdown. Shared CI amplifies I/O 3-6x (the "Budget rule" in
[unit-test-conventions.md](unit-test-conventions.md)); at the lower end, 3 x 38.7 s = 116.1 s,
rounded up to **120 s**. On macOS (5 runs) the slowest case took 1.331 s and the offline-shutdown
case 0.007 s. The Windows figure is itself under investigation (#8244). Revise the constant only
with a new recorded measurement.

It is **120 s in every build**: `must_return_within` applies the bound it is given exactly. 120 s is
below each meson limit it races, 180 s (`echo unit tests`, where the `OpenRetryLoop` cases run) and
480 s (agent shard C, where the dispatcher fixture's shutdown runs). `EchoSession`'s default bound
is `kReturnBound * kSpinScale`, because a real plugin shutdown is legitimately slower under a
sanitizer: 720 s on the sanitizer legs, against shard C's 960 s there, since those legs run
`meson test --timeout-multiplier 2` (`sanitizer-tests.yml`, `nightly.yml`). The watchdog names a hang
only if the call starts early enough for its bound to expire before the meson limit does, so each
case has a window, accepted as it stands:

| Entry | Meson limit | Bound | A hang is named if it starts within |
|---|---|---|---|
| agent shard C, plain | 480 s | 120 s | the first 360 s |
| agent shard C, sanitizer | 960 s (480 s x 2) | 720 s | the first 240 s |
| `echo unit tests`, plain | 180 s | 120 s | the first 60 s |
| `echo unit tests`, sanitizer | 360 s (180 s x 2) | 120 s (`OpenRetryLoop` cases pass `kReturnBound` unscaled) | the first 240 s |

A hang later than that reaches the meson limit first and ends there with no message, as it did
before the helper. The echo unit tests measure 40-82 s on Windows, so a plain-leg hang after about
60 s of that entry is outside its window.

One case is tighter on purpose. The real-plugin offline case ("a failed v10 migration loads Echo
offline ... shuts down promptly") bounds its shutdown by **half of
`yuzu::echo::open_retry_delay(1)`** (the first retry delay, 60 s today, so the bound is 30 s), taken
from the header so it follows the schedule and passed unscaled: this bound is the property under
test, and the first back-off does not stretch under a sanitizer. A shutdown that waits out the first
back-off is exactly the regression that case exists to catch, and a 120 s bound would let it
through. Half the delay and not the whole, because the back-off began when init returned, before
`shutdown()` is called: a shutdown that waits it out returns slightly before a bound equal to the
delay expires. Measured with the `stop()` wake-up removed, 2 of 4 runs at the full delay were not
caught; at half the delay, 4 of 4 were.

### What `must_return_within` does on a hang

It runs the call on the **calling** thread (production calls `stop()` and `shutdown()` from the thread
that ran `start()` and `init()`) while a watchdog waits. If the bound passes, the watchdog flushes
stdio, prints what hung, and ends the process through `hard_exit(3)`. A hung `stop()` cannot be
unwound (the owner's destructor blocks in the same call), so a clean test failure is not available;
ending the process with a message replaces a silent hang to the meson timeout. The CI flake classifier
reports the abnormal exit as unclassifiable, which is correct for a hang. The `[echo][bounded_return]`
cases in `test_echo_open_retry.cpp` pin the rest of the contract with a recording expiry action; the
real exit code and stderr text are not covered by a retained test (a unit test never spawns a process).

## The gate

`tests/test_echo_test_standard_lexical.py` (meson suite `echo`, so it runs on the Windows, Linux and
macOS legs) scans every `tests/unit/**/test_echo*.cpp` with comments and string and char literals
blanked, and reports four flags. Other suites, header helpers (`tests/unit/echo_test_db.hpp`) and
files with Echo in the middle of the name (`test_dashboard_echo_*.cpp`, `test_rest_echo_*.cpp`
under `tests/unit/server/`) are not scanned.
`must_return_within` is available to any suite for a call whose return is under test (rule 4).

| Flag | Fires on | Instead |
|---|---|---|
| `[sleep]` | any `sleep_for` / `sleep_until` | wait on a future, latch or callback (rule 3) |
| `[async]` | any `std::async` | `must_return_within` (rule 4) |
| `[wait]` | a `wait_for` / `wait_until` with no `ScopeExit` or `Joiner` earlier in the same top-level definition | declare the guard first (rule 4) |
| `[size-check]` | a `CHECK` or `CHECK_FALSE` on `X.size()` / `X.empty()` followed within 10 lines by `X[`, `X.front()` or `X.back()`, unless a `REQUIRE` between them proves `X` non-empty by itself (`X.size() == N` or `>= N` with a literal `N` of 1 or more, `X.size() > N`, `!X.empty()`, `REQUIRE_FALSE(X.empty())`) | `REQUIRE` (rule 5) |

**Marker.** A finding is waived by `// echo-test-ok: <reason>` in a real `//` line comment, on the
same line or on the comment-only line directly above, with a non-empty reason. The same text inside a
string literal or a `/* */` block comment waives nothing. Every marker is visible in review, so
justify it in the PR. **There is no baseline file:** the tree is clean or the finding is marked.

**Known limits.** The gate is lexical. A guard token that is present but does not protect the wait
passes, and it checks presence, not order: a guard declared before what it releases (rule 4 asks for
the opposite) passes too. A marker waives every flag on its line, not only the one it justifies.
What it does not see:

- **Waits and sleeps.** An unbounded `fut.wait()` or `cv.wait()` is not flagged (`[wait]` matches
  `wait_for` / `wait_until` only), nor are `usleep`, `Sleep` and `nanosleep` (`[sleep]` matches
  `sleep_for` / `sleep_until` only). A raw thread with a throwing assertion before its join is not
  flagged.
- **Size checks.** A size `CHECK` more than 10 lines before its index, or through an alias, is
  missed. It needs a plain identifier chain directly after `CHECK(`, so a call-chain size
  (`rows_of(x).size()`, `r.value().rows.size()`), reversed operands (`2 == v.size()`) and
  `std::size(v)` never match. It does not compare the index with the asserted size either:
  `REQUIRE(v.size() >= 1)` then `v[5]` passes.

The source-health ledger, retention-guard counters and pid-name map live in the plugin singleton and
cannot be reset from a test, so a case asserts on what it changed, never on a count another case
could have moved. The gate runs its own mutation self-tests, so a pattern that goes stale fails
loudly.
