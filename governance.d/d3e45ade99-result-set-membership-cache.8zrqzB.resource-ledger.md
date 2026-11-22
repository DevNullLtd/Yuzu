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

`std::vector<std::thread> readers` in the parallel-reader case is joined in a loop before the
assertions. A `std::system_error` from a later `emplace_back` would `std::terminate` while earlier
threads are still joinable. That is test-process only, in the same class as cs9-1, and recorded
in the run ledger as `corr-2`.


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
- **`07eb23ab56`, `e084d7b0cf`, `d3e45ade99`, and this corrections pass.** In
  `server/core/src/result_set_store.cpp` these change comments only. `e084d7b0cf` also changes
  test data and assertions. None of them adds or changes a resource.
