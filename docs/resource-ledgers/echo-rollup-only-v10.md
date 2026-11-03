# Resource Ledger: Echo roll-up-only storage (schema v10: `echo_db_v10_migration.cpp`, `echo_db.cpp`, `echo_usage.cpp`, `echo_plugin.cpp`)

Resources introduced or re-homed when the fold substrate became the only write path. The fold's own
resources (operation mutex, dictionary cache, per-transaction statements, GC progress handler, GC
orphan table, replay ring) are in `echo-fold-substrate.md` and are unchanged except for the ownership
and transaction changes below. Every exit path (normal, early, error result, exception unwind)
releases exactly the resource listed.

## Resources

### `EchoFold` instance (`EchoDatabase::fold_`)
- **Site:** `EchoDatabase::fold_`, a `std::unique_ptr<EchoFold>` constructed in `open()` after the
  base schema and before the first fold; moved with the database (`EchoDatabase`'s move operations).
- **Owner type:** the `EchoDatabase`. There is ONE `EchoFold` per database, as the substrate requires
  (the dictionary id cache and the replay-ring bookkeeping are per instance).
- **Lock order:** unchanged: `EchoFold::op_mu_` then `EchoDatabase::mu_`. No `EchoDatabase` method
  that holds `mu_` calls into `EchoFold`. The `fold_*` wrappers take no lock of their own; they build
  the accumulator and call the fold, which locks.
- **Release point:** the fold is destroyed with the database after the query connection closes; a
  moved-from database holds none.

### The v10 migration transaction (`EchoDatabase::migrate_to_v10`)
- **Site:** `open()` calls it once, only from schema v9 (an earlier step that failed makes `open()`
  refuse instead, so the version never skips a step).
- **Owner type:** `EchoDatabase::checked_transaction` (`BEGIN IMMEDIATE`, then COMMIT or ROLLBACK
  on every path, including an exception unwinding through the callback). The whole conversion,
  including the drops of the retired tables and the version stamp, is that one transaction.
- **Statements:** each decoder, the legacy-tier converter and the tier-to-tier fold hold `StmtPtr`
  locals that are finalised before the next statement and before COMMIT. Raw rows are read in chunks
  of 10,000 by id, so memory is bounded by a chunk, not the table.
- **Write lock:** held for the whole transaction (tens of seconds on a 250 MiB file). No collector
  writes meanwhile; the open has not returned, so none is running yet. The query connection does not
  exist yet, so no reader pins the WAL.
- **Disk:** the pre-check refuses a volume with less than twice the file free (the open fails with
  `kFreeSpaceRefusalPrefix`, nothing changed). The transaction's WAL is not bounded by the file's size
  (325.7 MB on a 241.8 MB file, 1.35 times, one measurement); the check covers that case (WAL plus
  the new file about 404 MB, under the 483 MB demanded) and no general bound is proven. The WAL is
  checkpointed to zero after the commit, before the VACUUM, whose copy and journal are the only
  transient space and are bounded by the second free-space check (else the VACUUM is deferred and the
  maintenance pass retries daily). Follow-up #6891 (the VACUUM's locks) is narrowed, not closed: the
  open-time conversion runs before any trigger exists, but the daily `maybe_vacuum_to_incremental`
  retry still runs on the trigger thread and holds the locks for its duration.
- **Failure:** a fault, crash or power loss before COMMIT leaves schema v9 and every retired table
  intact (SQLite's WAL recovery discards the unfinished transaction); the next open redoes the step.
- **After COMMIT:** the connection must be in autocommit (`sqlite3_get_autocommit`); a wedged one is
  returned as an error and `open()` closes it, never publishes it.

### The joint process and usage transaction (`fold_process_events`)
- **Site:** `EchoDatabase::fold_process_events` passes `usage_fold_in` to `EchoFold::fold_rows` as the
  `extra` callback, so it runs on the SAME `TransactionHandle` after the process tier upsert and before
  COMMIT.
- **Owner type:** `checked_transaction`. A failure of either half rolls back both: no process count
  without its usage fold, no usage fold without its process count, and the caller re-offers the same
  events (the baseline `StateWrite` is in the same transaction, so a retried tick folds both once).
- **No second connection:** `usage_fold_in` uses the passed handle only. It never calls
  `EchoDatabase::get_config` or any other method that takes `mu_` (the handle's callback runs with
  it held).
- **Baseline:** `PendingBaseline` stamps its lifecycle state and folds nothing.

### Offline plugin state (`EchoPlugin::offline_reason_`, `offline_detail_`)
- **Site:** set by `init()` when `EchoDatabase::open` returns a free-space refusal; read by
  `execute_dispatch` and the status path.
- **Owner type:** the plugin instance. Written once in `init()` before any trigger or dispatch exists,
  read-only afterwards; `shutdown()` leaves it for the process.
- **Lifecycle:** with it set, no trigger is registered and no database exists; every action answers
  `error|` first, then `storage_state|offline|free_space`. A restart with the space freed clears it.

### Budget catch-up latch and the conversion marker
- **Site:** `EchoPlugin::budget_catch_up_` (atomic armed flag plus the admitted clock reading),
  `vacuum_marker_fallback_` and `vacuum_last_attempt_` (atomics), and the `auto_vacuum_deferred_at`
  row in `echo_config`.
- **Owner type:** the plugin instance (atomics) and `echo_config` (the persisted marker).
- **Release point:** the latch is cleared by a pass the retention guard refused, by a pass that did
  not end on its deadline, and by a slice that finds the wall clock stepped back
  (`budget_slice_clock`). The marker is cleared (`clear_deferred_marker`) when a conversion succeeds;
  a non-positive reading is never stored as a marker.

### Test seams (no production caller)
- **`OpenSeams::free_bytes`, `OpenSeams::v10_after_drop`** (`echo_db.hpp`): empty in production. The
  first replaces the volume's free-space reading in the two migration checks; the second runs inside
  the v10 transaction after the drops and may fail it. Both are by-value `std::function`s in the
  caller's `OpenSeams`, owned by the test for the call of `open()`.
- **`RegistryReader::committed`** (`echo_registry_source.hpp`): null in production. When set, it is
  called with the rows of every tick whose fold and cursor committed, on the tick's own thread after
  the commit. The roll-up tier keeps no writer pid, attribution detail or source, so a test reads what
  a tick decided here. The observer owns nothing of the source's; it takes the rows by const reference
  and must not retain them.
