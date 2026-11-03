# Resource Ledger: Echo byte budget, hourly de-duplication and catalog signing lookup

New or modified owned resources introduced in `agents/plugins/echo/src/` (`echo_module_etw.cpp`,
`echo_db.cpp`, `echo_aggregator.cpp`, `echo_hour_dedup.hpp`, `echo_collectors.hpp`,
`echo_plugin.cpp`, `echo_user_collector.cpp`) and `agents/core/src/` (`process_enum.cpp`,
`agent.cpp`). Where a path is not covered, the entry says so.

## Resources

### Catalog administration context (`HCATADMIN`), Windows
- **Site:** `catalog_lookup_with` in `echo_module_etw.cpp`, called from `catalog_lookup` for the
  `SHA256` pass and, only when that pass answered `kNotFound`, again for the `SHA1` pass. One
  context per algorithm per lookup; a lookup runs once per file version (the signing cache fronts
  it).
- **Allocated by:** `CryptCATAdminAcquireContext2`.
- **Owner type:** `CatAdminGuard` (anonymous namespace, same file). Move and copy are deleted
  (`static_assert`ed), so a second owner cannot release it twice.
- **Release point:** `CatAdminGuard::~CatAdminGuard` calls `CryptCATAdminReleaseContext` on every
  exit of `catalog_lookup_with`: early returns (empty hash, no catalog, bad catalog info),
  the normal return, and a `std::bad_alloc` unwinding out of the `std::vector` / `std::wstring`
  allocations. The acquire call itself is made before the guard exists; when it fails there is
  no handle to release.
- **Transfer:** never. Only a borrowed `admin.get()` is passed to the hash, enumerate and
  `WinVerifyTrust` calls (`wci.hCatAdmin`); none of them takes ownership.
- **Failure cleanup:** `catalog_lookup` is `noexcept` and wraps both passes in `try/catch (...)`,
  so an exception is contained after the guards have run and surfaces as `kError` (an unknown
  verdict, never risky).
- **Not covered / limitation:** the guard is hand-rolled rather than the shared
  `ScopedWinHandle` (`echo_win_raii_guards.hpp`). The Windows code in this file could not be
  compiled on the Mac that authored it; it is checked by the Windows MSVC leg.

### Catalog information context (`HCATINFO`), Windows
- **Site:** `catalog_lookup_with`, one per catalog hit: `CryptCATAdminEnumCatalogFromHash` is
  called once with a null previous context, so at most one `HCATINFO` exists per algorithm pass.
- **Allocated by:** `CryptCATAdminEnumCatalogFromHash` (null means no catalog or an API error; no
  handle is owned then).
- **Owner type:** `CatInfoGuard`, copy and move deleted. It stores the admin context it came from,
  because `CryptCATAdminReleaseCatalogContext` needs it.
- **Release point:** `CatInfoGuard::~CatInfoGuard`. It is declared after `CatAdminGuard` in the same
  scope, so it is destroyed first and the admin context outlives it. Covers every return after the
  guard is built, including the `CryptCATCatalogInfoFromContext` failure and exceptions.
- **Transfer:** never. `CATALOG_INFO::wszCatalogFile` is copied into a stack buffer inside
  `catalog`; `wci.pcwszCatalogFilePath` points at that buffer, which outlives the
  `WinVerifyTrust` call in the same function.
- **Failure cleanup:** as above; the guard is the only cleanup.

### Trust state data (`WinVerifyTrust` verify/close pair), Windows
- **Site:** `catalog_lookup_with` and `verify_image_signature_win`, each calling `WinVerifyTrust`
  with `WTD_STATEACTION_VERIFY`.
- **Owner type:** `TrustStateCloser`, constructed immediately after the verify call, holding
  references to the `GUID` and `WINTRUST_DATA`.
- **Release point:** its destructor sets `WTD_STATEACTION_CLOSE` and calls `WinVerifyTrust` again.
  It runs on every path after the verify call, success or not. In `catalog_lookup_with` the signer
  name is read from `wd.hWVTStateData` before the closer is destroyed (the read is inside the
  scope the closer lives in).
- **Transfer:** never.
- **Not covered:** nothing allocating or throwing sits between the verify call and the closer's
  construction. The closer's destructor is not marked `noexcept(false)`; a failing close call is
  ignored.

### Image file handle, Windows
- **Not new.** `open_local_image_no_reparse` (`ImageHandle`, a `unique_ptr`-style owner with
  `ImageHandleCloser` calling `CloseHandle`) predates this change and is unchanged in ownership.
  The branch only lends the open handle to `catalog_lookup`: it is never closed by it and is
  never stored. `catalog_hash_of` moves the file pointer back to the start with `SetFilePointerEx`
  before hashing; the embedded-signature check that ran first had moved it. The shared pointer
  position is the only state the lookup changes on that handle.

### Database mutex per eviction batch
- **Site:** `EchoDatabase::delete_counted` (`echo_db.cpp`), called by `run_budget`
  (`echo_aggregator.cpp`) once per batch of `kBudgetBatchRows` (1000) rows, and
  `EchoDatabase::storage_bytes` (a separate short hold after each batch).
- **Allocated by:** `delete_counted` calls `checked_transaction`, which takes `mu_` with a
  `std::lock_guard` and issues `BEGIN IMMEDIATE`.
- **Owner type:** the `std::lock_guard` in `checked_transaction`; the two statements are owned by
  `StmtPtr` (the `DELETE ... RETURNING` statement and the counter bump).
- **Release point:** end of `checked_transaction`, every path. `COMMIT` on success; on a failed
  statement, exception (caught and turned into a failure) or failed `COMMIT`, `ROLLBACK` runs. If
  `ROLLBACK` itself fails and the connection is still inside a transaction, the connection is
  closed (`sqlite3_close_v2`) and the store goes offline until restart, as for every other
  `checked_transaction` caller. The delete statement is finalised (`stmt.reset()`) before the bump
  so none is pending at `COMMIT`.
- **Transfer:** never. The lock is not held between batches: the pass releases `mu_`, calls
  `storage_bytes()` (which locks it again) and checks the deadline and the WAL allowance before the
  next batch, so collectors can interleave at batch boundaries.
- **Failure cleanup:** the eviction counter bump and the delete are one transaction, so a rollback
  loses neither. `rollup_mu_` is held by the caller for the whole pass (see below).

### Database mutex across the one-off conversion VACUUM
- **Site:** `EchoDatabase::vacuum_to_incremental` (`echo_db.cpp`), called from
  `maybe_vacuum_to_incremental` (`echo_plugin.cpp`) only on a maintenance pass, only after
  `vacuum_decision` returns `kRun`.
- **Allocated by:** `std::lock_guard` on `mu_` at the top of the function; the caller already holds
  `rollup_mu_` (taken by `do_rollup`).
- **Owner type:** the `std::lock_guard`; `SqliteErrMsg` owns the error string of each `sqlite3_exec`.
- **Release point:** function return, which covers the failed pragma, the failed `VACUUM`, the
  success path and an exception. `rollup_mu_` is released when `do_rollup` returns.
- **Transfer:** never.
- **Consequence, stated plainly:** the `VACUUM` runs on the agent's single interval-trigger thread
  with `mu_` and `rollup_mu_` held for its whole duration, so every collector write and status read
  that needs `mu_` waits, and no other trigger fires in that time. `run_budget_catch_up` uses
  `try_lock` on `rollup_mu_` and returns at once, so the fast tick does not queue behind it.
  The duration follows the used data at the time, not the budget (see the status line wording and
  the upgrade notes).
- **Failure cleanup:** a failed pragma or `VACUUM` returns false with the database unchanged
  (SQLite builds the copy in a temporary database and replaces the file only on completion). The
  attempt time is recorded before the `VACUUM` and cleared on success, so a crash or a watchdog
  kill mid-run repeats the attempt at most daily, not at every start.

### Budget catch-up latch and its admitted clock reading
- **Site:** `budget_catch_up_` (`std::atomic<bool>`) and `budget_catch_up_now_`
  (`std::atomic<std::int64_t>`) in `echo_plugin.cpp`; written by `set_budget_catch_up`, read by
  `run_budget_catch_up` from the fast tick.
- **Owner type:** the plugin object; no heap allocation.
- **Acquire / release:** armed by `enforce_budget` through `budget_catch_up_after` only when a pass
  ended on its deadline with rows still eligible, data still over target and no failure. Cleared
  when a pass completes, fails or is exhausted, when `db_budget_bytes` cannot be read, and when
  `do_rollup` finds the retention clock guard has refused the pass's clock. The clock is stored
  before the flag; both are written under `rollup_mu_`, and the slice re-reads the flag after
  taking `rollup_mu_` with `try_lock`, so a slice runs with the clock reading the arming pass was
  admitted with, never a fresh one.
- **Not covered:** the lock-free peek of the flag in `run_budget_catch_up` can race with a clear;
  the re-check under the lock makes that harmless. The latch is not persisted: a restart drops it
  and the next maintenance pass re-derives it.

### Hourly de-duplication sets (`HourlySeenSet`)
- **Site:** `tcp_closing_seen_` and `module_seen_` members of the plugin (`echo_plugin.cpp`);
  type in `echo_hour_dedup.hpp`; consumed by `compute_network_events` (tcp closing sockets) and
  `apply_module_risk_filter` (module loads).
- **Owner type:** the plugin object, guarded by `collect_mu_`. Each set is an
  `std::unordered_set<std::string>` of at most `kDefaultCap` (20,000) keys.
- **Bound and clearing:** `first_this_hour` clears the set when the hour of the timestamp differs
  from the current hour in either direction, and clears it and counts one overflow when a new key
  would exceed the cap. Worst case after either is one repeated row per key, never a missed first
  row. A process restart empties it.
- **Commit rule:** each tick filters against a COPY of the set. The copy replaces the member only
  after the rows are committed: for tcp, after the `insert_network_events` / `set_state` call
  succeeds; for modules, after `insert_module_events` succeeds (on failure the filtered batch is
  re-queued, bounded by `kPendingStreamCap`, and the member keeps its old contents so the retry
  re-filters identically). The overflow counters mirrored for status are `std::atomic`.
- **Failure cleanup:** a thrown exception destroys the copy on unwind; the member is untouched.
- **Not covered:** an empty module batch (`mrows` empty) does not assign the copy back, which is
  harmless because an empty batch inserted no keys that matter.

### Pid-to-name map (`pid_name_`) and the grace window
- **Site:** `pid_name_` (`std::unordered_map<std::uint32_t, PidName>`) in `echo_plugin.cpp`, written
  by `note_pid_start`, `note_pid_names` and `yuzu::echo::note_pid_exits`; read by
  `pid_name_lookup` and `fill_process_names`.
- **Owner type:** the plugin object, guarded by `collect_mu_`.
- **Bound:** `kPidNameCap` is 65,536. At the cap a new pid first erases every entry stamped as
  exited more than `kPidNameGraceSec` (120 s) ago; only if that leaves no room is the map cleared
  wholesale (running pids are forgotten too and re-learned on their next start event or
  enumeration). A stop event or a missing pid only stamps `exited_at`; it never erases, so loads
  and sockets of a just-exited process still resolve inside the window.
- **Other clearing:** cleared when the process source is confirmed disabled; destroyed with the
  plugin.
- **Not covered:** a pid reused after a missed stop can carry the old name for the window; the name
  is a label, not an identity. The separate ETW-consumer cache (`Impl::pid_name` in
  `echo_module_etw.cpp`, 65,536 entries, wholesale clear, touched only on the serial consumer
  thread) is modified only in that it no longer caches an empty name.

### Conversion-deferral fallback copy
- **Site:** `vacuum_marker_fallback_` (`std::atomic<std::int64_t>`) in `echo_plugin.cpp`, set by
  `set_deferred_marker`, read by `deferred_marker` through `deferred_marker_reading`.
- **Owner type:** the plugin object; written under `rollup_mu_`, read lock-free by status.
- **Behaviour:** holds the attempt time only while the last write of the persisted marker failed
  (a successful write sets it to 0). While non-zero it takes precedence over the stored marker, so
  a database that cannot store the marker still retries at most daily within the process.
- **Not covered:** not persisted; a restart with a failing marker store can retry once at the next
  eligible pass.

### Temporary files from the one-off VACUUM
- **Site:** SQLite's own temporary database during `PRAGMA auto_vacuum=INCREMENTAL` followed by `VACUUM` in `vacuum_to_incremental`.
  The plugin does not create, name or delete it, and sets no `temp_store`, `SQLITE_TMPDIR` or
  `sqlite3_temp_directory` anywhere in `agents/` (checked by search).
- **Owner type:** SQLite. Its temporary files are opened delete-on-close by the library, so a
  failed or interrupted run is not expected to leave a file behind; that is library behaviour
  that was not re-verified in this repository.
- **Size and gate:** about the size of the used pages. `vacuum_decision` defers unless
  `std::filesystem::space` of the volume holding `echo.db` reports at least twice the used data
  (`kDefer`, with the attempt time recorded).
- **Limitation, stated plainly:** the gate measures the volume of the database directory, but the
  temporary database goes to SQLite's temporary directory (the platform default: the temp path on
  Windows, `TMPDIR` or `/var/tmp`, `/usr/tmp`, `/tmp` on POSIX), which can be another volume. Free
  space there is not checked. The WAL rewrite the `VACUUM` causes lands beside the database and is
  covered by the same check. An unreadable volume counts as zero free space (defer).

### Process command-line and status reads (`agents/core/src/process_enum.cpp`)
- **Site:** `detail::read_proc_bytes` (the `/proc/<pid>/cmdline` stream) and
  `detail::parse_proc_status` (the `/proc/<pid>/status` stream), both called from
  `enumerate_processes` on Linux.
- **Owner type:** the `std::ifstream` in `enumerate_processes` is a scope-bound local (closed on
  scope exit); both new functions only read a stream they are lent and own no descriptor.
- **Buffers:** `read_proc_bytes` appends to one `std::string` that is returned by value;
  `parse_proc_status` uses one line `std::string` and fixed fields in the caller's
  `ProcessInfo`. The status read no longer stops after the three fields, so the whole (small)
  kernel-generated file is read.
- **Failure cleanup:** both are `noexcept` and catch everything, keeping the bytes or fields read
  so far; the previous unbounded `istreambuf_iterator` read could throw when a process exited
  mid-read.
- **Cap:** `read_proc_bytes` stops at `kProcReadCap` (256 KiB) and keeps the prefix; a result of
  exactly the cap means possibly truncated. The display value is truncated downstream anyway.

### Snapshot pump thread (`agents/core/src/agent.cpp`)
- **Modified, not new.** The body of `snapshot_pump_thread_` now wraps one cycle in
  `try/catch (const std::exception&)` and `catch (...)`, logging and continuing. The thread, its
  join at shutdown and the `snapshot_mu_` guard are unchanged; the `std::lock_guard` on
  `snapshot_mu_` is released on every path of the cycle.

### Login-record reads (`echo_user_collector.cpp`, `echo_collectors.hpp`)
- **Site:** `enumerate_users` (Linux `setutent` / `getutent` / `endutent`; macOS `setutxent` /
  `getutxent` / `endutxent`), converting each `USER_PROCESS` record through
  `user_session_from_utmp` and `utmp_text`.
- **Owner type:** the C library's login-database state, opened by the `set*` call and closed by the
  `end*` call. A function-local `UtmpSession` / `UtmpxSession` struct owns it (constructor calls
  `setutent` / `setutxent`, destructor calls `endutent` / `endutxent`), so every exit path ends the
  session. No shared scope-exit helper exists in `agents/shared` or `agents/core` to reuse.
- **Buffers:** `utmp_text` copies at most the fixed field width (`ut_user`, `ut_line`, `ut_host`)
  with a bounded `memchr`, so a field with no terminator is not over-read. The returned strings are
  independent copies; the library's static record is not retained.

### Legacy database adoption marker (`echo_db_legacy_rename.hpp`)
- **Site:** `adopt_legacy_echo_db` writes `<data_dir>/echo.db.adopting` before the first sidecar
  move and removes it after the main-file rename.
- **Owner type:** the function itself, on the single boot-time call in agent core before any
  plugin initialises. The file is written with `yuzu::shared::write_file_atomic` (temp file,
  fsync on POSIX, rename), so no descriptor is held across the adoption. It holds one line: the
  size and mtime of `tar.db`.
- **Failure cleanup:** a failed marker write refuses the adoption before anything moves. A failed
  removal after the rename logs a warning; the next boot (no `tar.db`) deletes the spent marker.
  An interrupted adoption leaves the marker in place, which is what the resume reads.

## Not introduced
No new socket, thread, subprocess, callback context, library handle or allocated C string. The
`agents/shared/macos_socket_walk.hpp` change reorders conditional compilation around a pure,
cross-platform decoder and adds no owned resource. All new `sqlite3_stmt*` uses
(`storage_bytes_locked`, `delete_counted`) are owned by `StmtPtr`; new error strings use
`SqliteErrMsg`, with no new manual `sqlite3_free`.
