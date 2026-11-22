# Resource Ledger: result-set membership cache (run d3e45ade99-result-set-membership-cache.8zrqzB)

Branch `feat/instructions-membership-cache`, merge-base `ddb5649aba`. This file keeps the run's
Resource Ledger under `governance.d/` next to its findings fragment
(`d3e45ade99-result-set-membership-cache.8zrqzB.jsonl`). The governance session first recorded it
in a scratch Gate 1 change summary that is not in the repository. The table below is copied from
that summary, which covered fix commit `9e98085a7e`, plus its fix-5 addendum. The notes after it
record what later commits did, with the Gate 8 cpp-safety confirmation for each.

No fd, HANDLE, SOCKET, `FILE*`, OpenSSL or BCrypt object, mapped library, temp path, subprocess or
production thread is added on the branch. libpq objects are held only through the existing
`PgResult` / pool-lease RAII.

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

## Later commits

- **`0bfddb1e17`** (gc_sweep member-row budget). The change is SQL text and two `constexpr`
  constants: no new resource, and `PgResult` RAII on the same lease. The test uses the existing
  `PgConn`/`PgResult` RAII. The Gate 8 cpp-safety (+cpp-expert) narrow review of
  `0980d0e513..0bfddb1e17` found the ledger complete.
- **`07eb23ab56`, `e084d7b0cf`, `d3e45ade99`, and this corrections pass.** In
  `server/core/src/result_set_store.cpp` these change comments only. `e084d7b0cf` also changes
  test data and assertions. None of them adds or changes a resource.
