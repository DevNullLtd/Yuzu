# Resource Ledger: Echo roll-up fold substrate (`echo_fold.cpp`, `echo_fold_schema.cpp`)

New owned resources introduced by `EchoFold` and the code behind it. Nothing here is wired into
`EchoDatabase::open()`, a collector or a setting; every path (normal return, early return,
error result, exception unwind) releases exactly the resource listed.

## Resources

### `op_mu_` (operation mutex)
- **Site:** `EchoFold::op_mu_`, taken by `std::lock_guard` in every public method before its first
  cache or database access (`fold_cursor_rows` refuses a blank or NUL `record_key` first and
  touches neither).
- **Owner type:** the lock guard. Held to the method's return: cache reads, the transaction, the
  post-commit cache publication, cache invalidation.
- **Lock order:** `op_mu_` then `EchoDatabase::mu_` (taken inside `checked_transaction`). Nothing
  takes `op_mu_` while holding `mu_`; there is no second cache lock.
- **Release point:** scope exit of the public method, including a failed transaction.

### Dictionary cache
- **Site:** `EchoFold::cache_` (`unordered_map<string, int64_t>`), bounded at 50,000 entries.
- **Owner type:** the `EchoFold` object. Mutated only under `op_mu_`.
- **Publication:** new ids are staged in a per-call map during the transaction and merged into the
  cache only after COMMIT succeeds, so a rollback never leaves a cached id the database lacks.
- **Invalidation:** cleared on overflow, after any committed GC deletion, and on
  `install_fold_schema`.

### Per-transaction prepared statements
- **Site:** `StmtPtr` (`unique_ptr` with `sqlite3_finalize`) locals in the transaction callbacks,
  and the one statement inside `Interner`.
- **Release point:** a callback local is finalised at the end of the callback, before COMMIT /
  ROLLBACK, on every exit including `h.fail()` and an exception unwinding through
  `checked_transaction`. The `Interner` is built outside the callback (the ids it stages are
  published after COMMIT), so its statement is finalised when the public method returns, after
  COMMIT / ROLLBACK; both of its steps have been consumed (ROW, then DONE), so it holds no read
  cursor or lock by then.
- **Transfer:** never. A statement does not outlive the public method call that prepared it.

### Progress handler (GC only)
- **Site:** `GcProgress` in `gc_dictionary`, installed with `sqlite3_progress_handler(db, 1000, ...)`
  inside the batch transaction.
- **Owner type:** the `GcProgress` scope guard; the destructor clears the handler on every exit.
- **What the deadline covers:** statement execution between batches (the handler interrupts a
  running batch, which rolls back) and a check before each batch starts. **What it does not
  cover:** mutex acquisition, `BEGIN IMMEDIATE`'s 5 s busy wait (`echo_db.cpp`), and COMMIT I/O. It
  is a cooperative bound, not an end-to-end one.
- **Context lifetime:** the callback reads a `std::function` owned by the guard; the guard outlives
  the statement.

### `echo_fold_seen` replay ring
- **Site:** the `echo_fold_seen` table, written by `fold_cursor_rows` in the same transaction as
  the roll-up rows, the baseline writes and the cursor.
- **Bound:** newest 4096 keys per source, pruned in the same transaction.
- **Failure cleanup:** any failure rolls the ring, rows, baselines and cursor back together.

## Not introduced
No thread, socket, temp file, callback registered with the host, or library handle. The unit
tests that exercise concurrency start two `std::thread`s inside the test and join them.
