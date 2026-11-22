# Resource Ledger: result-set membership cache (run d3e45ade99-result-set-membership-cache.8zrqzB)

Branch `feat/instructions-membership-cache`, merge-base `ddb5649aba`. This file keeps the run's
Resource Ledger under `governance.d/` next to its findings fragment
(`d3e45ade99-result-set-membership-cache.8zrqzB.jsonl`). The governance session first recorded it
in a scratch Gate 1 change summary that is not in the repository. The table below is copied from
that summary, which covered fix commit `9e98085a7e`, plus its fix-5 addendum. The notes after it
record what later commits did, with the Gate 8 cpp-safety confirmation for each.

No fd, HANDLE, SOCKET, `FILE*`, OpenSSL or BCrypt object, mapped library, temp path, subprocess or
production thread is added on the branch. In production code, libpq objects are held only through
the existing `PgResult` and pool-lease RAII. The tests also hold their own libpq connections
through `PgConn` (RAII, `PQfinish` on destruction) and their own `PgPool` instances (rows below).

| resource | owner | acquire | release | transfer | failure cleanup |
|---|---|---|---|---|---|
| `std::list<MemberCacheEntry> dropped` (local in `forget_members`, `retain_members`) | the function frame | declared before `std::lock_guard` | destroyed at scope exit AFTER the guard (reverse declaration order) | nodes spliced in from `member_cache_fifo_` (no allocation, no copy); index entries erased BEFORE splice (string_view keys point into node `id`) | splice is noexcept; early `return` (same generation) leaves `dropped` empty |
| `std::shared_ptr<const MembershipIds>` in dropped entries | shared | — | last ref freed outside mutex | in-flight readers keep their copy | — |
| `std::string generation` in try block | frame | constructed in try | scope exit | moved into `CachedMembership` | bad_alloc caught; `retain_members` restores fifo on index emplace failure (pre-existing) |
| PG lease (`pool_.try_acquire_for`) | unchanged RAII lease | — | — | — | new early `return NotFound` on hit releases via RAII |

Tests add `std::thread` x6, joined in scope.

**Fix 5 addendum (from the same summary).**
- `PgResult begin` and `PgResult rollback` (x2) in the boot trigger check use block or function-frame
  RAII. They run through PQexec on the constructor's lease, are released at scope exit and are not
  transferred. ROLLBACK runs on both paths once BEGIN has been attempted.
- In the tests, `PgConn probe` is RAII: opened before the thread, closed at scope exit.
- `PgResult waiting` is RAII, one per poll iteration.
- `std::jthread fill` replaces `std::thread`, so it joins on destruction.

Gate 8 cpp-safety round 3 (`3725960929..2742185310`) found the fix-5 addendum complete.

**Fix 4 addendum** (`8766b4a7d9..3725960929`). Adopted in Gate 8 cpp-safety round 2 but left out
of the first copy of this file. Restored after the corrections-pass cpp-safety review (cpps-1).

| resource | owner | acquire | release | transfer | failure cleanup |
|---|---|---|---|---|---|
| `PgResult res` in the boot trigger check (`member_triggers_in_force`, now `query_member_triggers`) | function frame (RAII) | exec_params on the constructor's lease | scope exit | none; PQerrorMessage and PQgetvalue used only in the log call or the return expression | not OK, or not exactly one row: Unreadable, cache off |
| `PgConn oob` (test) | test frame (RAII, PQfinish) | PQconnectdb before the thread | scope exit; its transaction ends by COMMIT, or server-side on disconnect | none | a REQUIRE before the thread: RAII close, rollback |
| `PgResult r` (BEGIN plus write; COMMIT) (test) | block scope (RAII) | PQexec | block exit | none | RAII |
| `std::thread fill` (test) | test frame, joined before assertions | after the oob write is open | joined after COMMIT | none | a throw before the join would std::terminate (cs9-1); replaced by `std::jthread` in fix 5 |
| v7 SQL `std::string` (four pieces plus the constants) | function-local static `kMigrations` | first `migrations()` call | program exit | none | a throwing initialiser retries on the next call |

## Test-only objects not listed above

All of these are RAII and scoped to a test case:
- `PgPool` instances (`size` 1 to 8) declared at the top of the new test cases. A `ResultSetStore`
  declared after its pool is destroyed first.
- `PgConn locker` / `conn`.
- Pool leases (`pool.acquire()`).
- Per-statement `PgResult`.

`std::vector<std::jthread> readers` in the parallel-reader case joins before the assertions.
Each captured local outlives the vector. If a later thread cannot start, earlier threads join
during unwinding (commit `4c6b286b68`, finding `corr-2`).

## Later commits

- **`0bfddb1e17`** (gc_sweep member-row budget). The change is SQL text and two `constexpr`
  constants: no new resource, and `PgResult` RAII on the same lease. The test uses the existing
  `PgConn`/`PgResult` RAII. The Gate 8 cpp-safety (+cpp-expert) narrow review of
  `0980d0e513..0bfddb1e17` found the ledger complete.
- **`1f0c89b02e`** (another session's fix to the temp_file_limit GC test). It adds a block-scoped
  `PgPool seed_pool` with a `ResultSetStore seed` declared after it, so the store is destroyed first.
  It holds two leases from the test's `PgPool pool` at once (`a`, `b`, both RAII, released at block
  exit before the store is constructed on that pool), with one `PgResult r` per connection (RAII).
  It adds no production resource.
- **`c1f1428e2a`, `578c4514d3`, `cc986cba7d`, `3b19d0fbe3`, `0980d0e513`.** Comment-only changes under `server/`, or no `server/`/`tests/` file at all. No resource added.
- **`07eb23ab56`, `e084d7b0cf`, `d3e45ade99`, and this corrections pass.** In
  `server/core/src/result_set_store.cpp` these change comments only. `e084d7b0cf` also changes
  test data and assertions. None of them adds or changes a resource.

- **`a274e5cdd8` and `4c6b286b68`.** Each store owns its copied or moved epoch callback. Production uses a stateless function. The skew tests declare their clock variable before the stores, which destroy their callbacks before that variable leaves scope. The concurrency test at `4c6b286b68` uses `std::vector<std::jthread>` and joins before examining the results. During unwinding each constructed thread is joined before the captured inputs, expected sets, atomics, store and pool go out of scope (closing `corr-2`).

The quota check binds an owned string containing replica time. Its query result and pool
lease retain their existing RAII owners. An empty clock callback selects the stateless system
clock. The quota regression's local two-connection pool outlives the store, and its
`server_now` outlives the store's borrowed capture. The SQL helpers' `PgConn` and `PgResult`
objects release on return or unwinding. The extra trigger-shape sections use the same pool and
statement wrappers as the existing trigger fixtures.

## Review and test evidence

The historical JSONL entries that cite scratch files under `/private/tmp/yuzu-gov-fix-cache12` refer to these preserved reports. Each covers the commits identified inside it.

- [Initial run report](d3e45ade99-result-set-membership-cache.8zrqzB.evidence/run-report.md)
- [Gate 8 coverage addendum](d3e45ade99-result-set-membership-cache.8zrqzB.evidence/gate8-final-coverage-addendum-2026-11-21.md)
- [Corrections review](d3e45ade99-result-set-membership-cache.8zrqzB.evidence/final-corrections-review.md)
- [Earlier Linux PostgreSQL and Meson runs](d3e45ade99-result-set-membership-cache.8zrqzB.evidence/linux-test-evidence.md)

On 2026-11-22 Big Tam built the normal GCC 15 Meson `yuzu_server_tests` target from `580a0b8ba7` and exercised live PostgreSQL with the following commands. The database connection string was supplied via `YUZU_TEST_POSTGRES_DSN`.

```sh
ninja -C build-linux -j12 tests/yuzu_server_tests
build-linux/tests/yuzu_server_tests '[clock_skew]' --reporter compact
build-linux/tests/yuzu_server_tests --filenames-as-tags '[#test_result_set_store]' --reporter compact
meson test -C build-linux -j4 --suite server --print-errorlogs
```

| Source revision | Clock skew | Complete result-set store file | Meson server suite |
|---|---|---|---|
| `580a0b8ba7` | 1 case, 40 assertions passed | 58 cases, 1,497 assertions passed | 26 passed, 0 failed, 5 Node-dependent entries skipped |
| `4c6b286b68` | 2 cases, 74 assertions passed | 59 cases, 1,531 assertions passed | All 31 passed, zero failed or skipped, with Node available |
