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
- **Rows not folded:** raw rows older than the first old tier's mark (`ts < mark`) are dropped with the
  raw tables, not folded: the old roll-up already summarised them except rows a process-event backfill
  wrote and rows its clock-gap clamp skipped, and its `GROUP BY` kept no identity to tell the two apart,
  so folding them would double-count the first group. The count is in the migration's log line. The mark
  IS a clock-derived value (a persisted reading of the old pass's clock), so the DROP's cutoff is
  clock-derived and `clock-guarded-retention.md` carries a row for it: every mark is read once and
  validated (not an integer, absent for a populated tier, or ahead of the finer tier's: the migration
  fails with the key named, never reads a damaged mark as "fold everything"), and a mark ahead of the
  clock is untrusted and replaced by the end of the newest bucket at or before the clock that the
  converted tier holds (never a bucket the excursion itself wrote), logged with the figures, and a
  converted tier with no such bucket refuses the migration with the mark named rather than fold
  every raw row on top of the upper tiers, unless the source holds no raw row and no converted
  bucket at all (a never-used source's mark bounds nothing and is ignored, logged); a sane mark is
  used exactly as stored. Second trigger of the same residual, disclosed and not closed: a
  migration clock set back from a SANE mark (a restored snapshot, an NTP step) makes the mark
  untrusted by the same rule, and the clamp to the clock then folds the raw rows between the clock
  and the mark a second time on top of the buckets that hold them.
- **Usage cursor:** the raw process rows past `usage_hwm_id` (the usage fold's own read cursor) are fed
  to `usage_fold_in` on the same handle before the cursor and `usage_lag_events` are deleted, so a
  lagging usage fold loses nothing it would have credited. The feed decision is the fold's own
  predicate (`usage_active_in`: usage enabled and the lifecycle Active, with the active generation
  parsed as `usage_lifecycle_state` parses it, so an empty or malformed value reads as it would at
  the next tick), decided once before the chunk loop, and it does NOT consult `process_enabled`:
  the pre-v10 fold left its cursor in place while process was disabled and credited the rows once
  process was re-enabled, and the migration folds the raw rows into the process tiers regardless,
  so they reach usage now or never. A usage source that is disabled or awaiting its baseline
  would not have credited them and gets nothing (the rows are counted, not fed). An Active
  lifecycle with no cursor refuses the migration; the rows past the cursor, the stored counter
  and the rows folded are in the log line (a row past the cursor but below the roll-up floor is
  not read, and is in the "older than the mark" count).
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

### Offline plugin state (`EchoPlugin::offline_detail_`)
- **Site:** set by `init()` when `EchoDatabase::open` returns a free-space refusal; read by
  `execute_dispatch` and the status path.
- **Owner type:** the plugin instance. Written once in `init()` before any trigger or dispatch exists,
  read-only afterwards; `shutdown()` leaves it for the process.
- **Lifecycle:** with it set, no trigger is registered and no database exists; every action answers
  `error|` first, then `storage_state|offline|free_space`. A restart with the space freed clears it.

### Registry baselines and the logged-off profile list (carried, not converted)
- **Site:** the per-root baselines (`echo_state`, key `registry:<root>`) and the registry cursor row
  (`echo_cursor`, source `registry`, including its `offline` list of `[sid, ProfileImagePath]`
  entries, its per-root `baselined`/`deferred`/`status` flags and any change held for its writer),
  written through `insert_registry_events_and_cursor` with the event fold.
- **Owner type:** the database; the registry source reads and writes them only inside its tick's
  transaction. The v10 migration neither reads nor rewrites either table, so an upgrade re-baselines
  no loaded or logged-off root.
- **What the tier keeps:** a change found in a logged-off user's hive folds into the same hourly and
  daily buckets as a loaded hive's (`hive`, `key_path`, `value_name`, `action` key a bucket;
  `change_count`, `last_data`, `last_data_type`, `last_actor_image`, `last_ts` are kept). The offline
  attribution marker (`source` = `offline`, `detail` = `attr:offline`), the writer's pid, the read
  time and the record key are decided with the event and are not stored; no column holds them.
- **Exposure:** `last_data` holds the newest new value (512 bytes) unmasked and the cursor row names
  each logged-off user's profile path, both readable through `echo.sql`; `purge_source("registry")`
  on the paused source erases the tiers, the baselines and the cursor row in one transaction.

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
