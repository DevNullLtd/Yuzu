# Resource Ledger: in-process dpkg and rpm package-database readers (SAM-45)

New or modified owned resources in `agents/shared/` (`pkgdb_budget.hpp`, `dpkg_status_parsers.hpp`,
`rpmdb_parsers.hpp`, `posix_secure_read.hpp`) and `agents/plugins/installed_apps/src/`
(`installed_apps_pkgdb_read.hpp`, `installed_apps_plugin.cpp`, `installed_apps_inventory.hpp`,
`installed_apps_parsers.hpp`). Entries name functions, types and members, never line numbers, so a later edit to a
header cannot leave one stale.
The whole read runs on one `bounded_call_ex` worker, and every handle below is created and closed on that
worker. Where a path is not covered, the entry says so.

## Resources

### Package database descriptor (rpm sqlite / ndb / bdb file)
- **Site:** `read_rpm_dir` (`installed_apps_pkgdb_read.hpp`); one per candidate file tried (the open is the
  `open_file_no_follow_at` call in its candidate loop).
- **Allocated by:** `openat_retry` inside `open_file_no_follow_at` (`posix_secure_read.hpp`), flags
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC` (`kFileFlags`). The regular-file check is an
  fstat on the descriptor.
- **Owner type:** `ScopedFile` (`posix_secure_read.hpp`, move-only), carried in `FileOpen::file`.
- **Release point:** `~ScopedFile` at the end of the loop iteration. The `continue` and every `return` in
  `read_rpm_dir` leave through it.
- **Transfer:** one move, local to `FileOpen::file`. Everything else borrows the int: `stamp_of`, the
  `fd_source` closure (captured by value) and `read_rpm_sqlite`'s 20-byte header pread. The temporary
  `ByteSource` lives to the end of the `read_blobs(...)` call.
- **Failure cleanup:** RAII only.
- **Not covered / limitation:** sqlite reopens the path with its own handle (see the `sqlite3*` entry), so the
  before/after stamp proves the inode this descriptor opened, not the one sqlite reads. Documented residual.

### rpm transaction lock file descriptor (`.rpm.lock`), ndb and Berkeley DB only
- **Site:** `rpm_transaction_refusal` (`installed_apps_pkgdb_read.hpp`), called from `read_rpm_dir`
  after the first stamp and before the first read, and only when the candidate has a byte-source reader
  (`c.read_blobs`, that is ndb and Berkeley DB; sqlite is never probed). One per ndb or bdb database read.
- **Allocated by:** `open_file_no_follow_at(dir_fd, ".rpm.lock")` through the database's own directory
  descriptor, flags `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC` (`kFileFlags`; `O_NONBLOCK` is what keeps
  a FIFO in that slot from blocking the open). Opened read-only; the file is never created.
- **Owner type:** the `ScopedFile` inside the `const auto lock` (`FileOpen`) local to the function. Move-only.
- **Release point:** function return, on every path: absent file, refused open, failed query, locked, free.
- **Transfer:** never. `lock.file.fd()` is lent as an `int` to the `lock_query` callable for the duration of that
  one call; nothing stores it.
- **Failure cleanup:** RAII only. ENOENT is "no transaction has run here" (not locked); a link, a non-regular
  file or any other open error maps to its own `PkgDbCause` (`symlink_refused`, `not_regular`, `unreadable`); a
  failed `fcntl` is `unreadable`. None of them reads as "not locked".
- **Lock behaviour:** the function NEVER takes a lock. The only fcntl call is `F_GETLK` over a stack
  `struct flock` (`F_WRLCK`, whole file), which asks whether a write lock would conflict and changes nothing. No
  `flock`, no `F_SETLK`, no `F_OFD_SETLK` in production code, so the reader cannot delay rpm. The query is
  non-blocking, so there is no `EINTR` retry path.
- **Not covered / limitation:** rpm's lock path is configurable (`%_rpmlock_path`); one moved out of the database
  directory is not seen. The probe is a write lock on purpose, so a shared holder also reads as locked.
- **Test seam:** `lock_query` (default `default_lock_query`) is overridable by a test only, so a failed
  query can be shown to read as `unreadable`.

### dpkg text files (`status`, each `status.d` file)
- **Site:** `read_dpkg` (path form) and `read_dpkg_status_d` (directory-descriptor form).
- **Allocated by:** `openat_retry` in `read_file` / `read_file_at`.
- **Owner type:** the `ScopedFile closer` in `read_open_fd` (`posix_secure_read.hpp`); the bytes are the
  `std::string` in `FileRead`, capped at `dpkg_max_bytes`.
- **Release point:** `read_open_fd` return.
- **Transfer:** `file.data` is lent to `parse_dpkg_status` as a `string_view`; the parser copies every field it
  keeps. The buffer dies at the end of the loop iteration (status.d) or of the function (status).
- **Failure cleanup:** an oversized or I/O failure clears `data`. Any failure returns no packages.
- **Not covered / limitation:** the path form applies `O_NOFOLLOW` to the leaf only; ancestors are followed.

### Directory streams (`DIR*`): rpm directory, `status.d`, and the dpkg updates directory
- **Site:** `read_rpm_dir`, `read_dpkg_status_d` and `dpkg_updates_failure` (its directory handle is the
  `open_dir_no_follow` result at the top of the function).
- **Allocated by:** `open_dir_no_follow` and `finish_dir_open` (`posix_secure_read.hpp`, `fdopendir`).
- **Owner type:** `ScopedDir` (`posix_secure_read.hpp`, move-only). The raw fd is owned by the `DIR*` or
  closed once on failure, never both.
- **Release point:** function exit.
- **Transfer:** borrowed. `dir.dir.get()` goes to `walk_dir_capped`, and `dir.dir.fd()` goes to the `_at` opens
  (including the `.rpm.lock` open above), all before the function returns. A `dirent*` is valid only inside the
  walk callback. `read_dpkg_status_d` copies `d_name` into `names`.
- **The updates directory in particular:** only NAMES are listed. `dpkg_updates_failure` opens and reads nothing
  inside `var/lib/dpkg/updates`; the callback tests each name against the digits-only rule
  (`is_dpkg_journal_record`) and stops the walk on the first journal record. It stores no name. The walk
  is bounded by `dir_entry_bound` (twice `max_packages`, then `row_cap`) and polls the deadline per entry
  through `budget.check_time()`. An absent directory is "no journal"; a link, a non-directory or a failed listing
  is a named failure (`dir_open_cause`), never "no journal".
- **Failure cleanup:** RAII.
- **Not covered / limitation:** the open and the `readdir` have no deadline of their own; the worker's wall bounds
  the caller, not the call.

### sqlite3 connection (`sqlite3*`)
- **Site:** `read_rpm_sqlite` (`installed_apps_pkgdb_read.hpp`); the open is its `sqlite3_open_v2` call.
- **Allocated by:** `sqlite3_open_v2(..., READONLY|URI|NOMUTEX)`.
- **Owner type:** `std::unique_ptr<sqlite3, SqliteCloser>` (the `db` local in `read_rpm_sqlite`). It owns the
  pointer even when the open failed.
- **Release point:** function exit, any return. `sqlite3_close` runs after the statement is finalized, because
  `stmt` is declared later and so is destroyed first.
- **Transfer:** never. The handle is used by this one worker thread (NOMUTEX).
- **Failure cleanup:** every early return goes through the owner.
- **Not covered / limitation:** the path reopen of a file the descriptor already vetted (accepted residual). A
  hostile schema can use heap within the 20 s wall; `sqlite3_hard_heap_limit64` is not set (not verified).

### sqlite3 statement (`sqlite3_stmt*`)
- **Site:** the `sqlite3_prepare_v2` call in `read_rpm_sqlite`.
- **Allocated by:** `sqlite3_prepare_v2`.
- **Owner type:** `std::unique_ptr<sqlite3_stmt, StmtFinalizer>` (the `stmt` local in `read_rpm_sqlite`).
- **Release point:** function exit, before the connection (reverse declaration order).
- **Transfer:** never.
- **Failure cleanup:** the step loop returns through the owner.

### sqlite progress-handler context (`&budget`)
- **Site:** the `sqlite3_progress_handler` registration in `read_rpm_sqlite`.
- **Owner type:** none (non-owning pointer). It targets the `budget` parameter, which refers to `read_rpm_dir`'s
  local, declared before the read call and destroyed after it.
- **Release point:** the handler dies with the connection, which closes inside `read_rpm_sqlite`. It is not
  cleared explicitly; closing the connection is the clearing.
- **Transfer:** never.
- **Failure cleanup:** the handler is `noexcept` and only runs `check_time()`. A non-zero return interrupts the
  query (`timeout`).

### sqlite blob view (`sqlite3_column_blob`) and the header string views
- **Site:** the step loop in `read_rpm_sqlite` (the `sqlite3_column_blob` read); `RpmHeader::text`
  (`rpmdb_parsers.hpp`).
- **Allocated by:** sqlite (the row's column buffer), or the ndb/bdb reader's scratch buffer. A `std::span` and,
  from `RpmHeader::text`, `std::string_view`s borrow it.
- **Owner type:** sqlite, or the reader's buffer.
- **Release point:** invalid at the next `sqlite3_step` / finalize, or when the reader reuses its buffer.
- **Transfer:** the span goes to `collect_header`, whose `RpmHeader` borrows it. `rpm_package_from_header`
  takes each string as a `string_view`, charges its length to the kept-text budget, and only then copies it into
  an owning `std::string`. No view escapes the row; the returned `RpmPackage` owns its strings.
- **Failure cleanup:** a non-blob, empty or over-cap value returns `corrupt` or `oversized` before any use; a
  refused kept-text charge fails the record with `byte_cap` before the copy.

### Read budget, the kept-text budget and the expiry closure
- **Site:** `PkgDbBudget` (`pkgdb_budget.hpp`, fields `rows_left`, `bytes_left`, `kept_left`, `max_item_bytes`,
  `expired`); `read_dpkg` (shared with status.d and the updates listing by reference); `read_rpm_dir`
  (one per candidate).
- **Kept-text budget (amended by the governance round 1 fix):** `Limits::rpm_max_kept_bytes = 8 MiB`
  (`Limits`, `installed_apps_pkgdb_read.hpp`) is set on the rpm budget as `.kept_left` in `read_rpm_dir`. It bounds
  the strings the rpm readers KEEP, apart from `bytes_left` (the bytes READ, 1 GiB). Charged by
  `PkgDbBudget::charge_kept` (`pkgdb_budget.hpp`), called once per kept string from `rpm_package_from_header`
  (`rpmdb_parsers.hpp`), before the copy, so six tags naming one stored string are each charged. A refused
  charge is `byte_cap` and fails the whole read. The value is the old inner capture cap (`kToolOutputCap`,
  `installed_apps_plugin.cpp`, 8 MiB), above the collector's 3.5 MiB outer cap.
- **Owner type:** a local value (plain counters plus a `std::function<bool()>`).
- **Release point:** end of the reader's scope.
- **Transfer:** readers take it by `PkgDbBudget&`. The ndb/bdb callback captures it by reference,
  the sqlite loop passes it to `collect_header`; it is never copied.
- **Failure cleanup:** a refused charge returns a `PkgDbCause`. No partial result is published.
- **Not covered / limitation:** the `expired` closure captures `&stop` and `deadline`. `stop` is a member of the
  worker closure (next entry), so it is valid for the worker's whole life.

### Detached bounded worker and its closure
- **Site:** `read_host_packages_bounded` (`installed_apps_pkgdb_read.hpp`), over `bounded_call_ex`
  (`bounded_wait.hpp`).
- **Allocated by:** the outstanding-call ceiling guard (64), the `State` `shared_ptr`, and
  `std::thread(...).detach()` inside `bounded_call_ex`.
- **Owner type:** the thread lambda owns the callable by move. The callable owns `root`, `lim`, `stop`, `reader`
  and `deadline` by value. `State` is shared with the caller. All handles above live on the worker stack.
- **Release point:** thread exit destroys the closure, the `shared_ptr` and the ceiling guard.
- **Transfer:** on `Completed` the result moves out of `State::value` under the mutex. On `TimedOut` or `Rejected`
  there is no value.
- **Failure cleanup:** a reader exception is caught in the closure and returned as `pkgdb:unreadable`. A
  setup failure is `Rejected`, giving `pkgdb:busy`. Timeout gives `pkgdb:timeout`.
- **Not covered / limitation:** the deadline is cooperative. A worker blocked in a syscall on a dead volume is
  abandoned, not cancelled, and may outlive plugin unload (accepted, same as `printing` and `power_health`; the
  shared shape is tracked in #8364).

### Tracked-call counter, stop flag, agent shutdown latch and shutdown quiesce
- **Site:** `installed_apps_plugin.cpp` (`g_outstanding_pkgdb_calls`, `g_pkgdb_stop`, `PkgDbCallGuard`,
  `quiesce_pkgdb_calls`), the plugin's `read_host_packages_bounded` (the guard wraps the call and the stop
  predicate), and `InstalledAppsPlugin::init` and `shutdown`.
- **Owner type:** namespace-scope atomics. `PkgDbCallGuard` is an RAII increment and decrement on the calling
  thread (its constructor and destructor).
- **Stop predicate (amended by the governance round 1 fix):** the readers' `expired` closure is now
  `g_pkgdb_stop || yuzu::agent::subprocess_cancel_requested()`. The second term is a read of the agent's sticky
  shutdown latch (an atomic load owned by agent core, set at agent stop and never cleared in production); this
  plugin owns nothing there and acquires nothing.
- **Release point:** guard destructor, on return or exception.
- **Transfer:** never.
- **Failure cleanup:** `shutdown` sets the stop flag, which ends any live worker at its next poll. It then waits
  up to 5 s (20 ms polls) and logs the residue.
- **Not covered / limitation:** the guard counts the caller's wait, not an abandoned worker. A worker blocked in
  the kernel can outlive the unload (`bounded_wait.hpp` residual).

### Reader scratch buffers (ndb, bdb)
- **Site:** `rpmdb_parsers.hpp`: `read_rpm_ndb` `page`, `blob`, `seen` (`blob.resize`) and `read_rpm_bdb` `page`,
  `opage`, `chain`, `off`, `seen` (`off.resize`, `chain.reserve`).
- **Owner type:** local `std::vector` and `std::unordered_set` of the reader.
- **Release point:** reader return.
- **Transfer:** a `span` is lent to the `RpmBlobFn` for that call only; the callback copies (through the kept-text
  charge above).
- **Failure cleanup:** RAII. Every length is checked against the file size, the item cap and the byte budget
  before `resize` or `reserve`, so peak is one header plus one or two pages.
- **Not covered / limitation:** none.

### Result vectors (`HostPackages`, `RpmPackage`, `DpkgPackage`)
- **Site:** `HostPackages` in `installed_apps_pkgdb_read.hpp`; mapped at `installed_apps_plugin.cpp`
  (`get_installed_apps_linux` and the Linux inventory collector).
- **Owner type:** `std::vector` of owning-string structs. Fields are copied out of the file or blob.
- **Release point:** `HostPackages` goes out of scope in the collector.
- **Transfer:** moved reader to `HostPackages` to `State::value` to caller, then copied into `AppInfo` /
  `InvRecord`.
- **Failure cleanup:** a failure returns no packages, and `read_dpkg` clears the status packages when status.d
  fails or a dpkg update journal is pending (`dpkg_updates:locked`). A detection that finds a database with no
  package keeps no vector from it and tries the next candidate directory.
- **Bound (amended; the round 1 pending note is closed):** the text an rpm read keeps is at most
  `rpm_max_kept_bytes` (8 MiB) in total, charged per string before the copy, plus the fixed per-row struct
  overhead (about 224 bytes per row; about 11 MB at the 50,000-row cap). A header whose six string tags alias one
  32 MiB string is refused on its first charge. The `AppInfo` / `InvRecord` copies each hold at most one more copy
  of the kept fields. dpkg kept text is at most the file text, capped at 32 MiB (`dpkg_max_bytes`).
- **Not covered / limitation:** none.

## Test code

- `tests/unit/test_installed_apps_pkgdb.cpp`: the held-lock cases (Linux only) hold an open-file-description lock
  through a `yuzu::shared::ScopedFile` (a `std::optional<ScopedFile>` where the lock is released mid-test by
  `reset()`); the temp trees are `TempDir` with the `yuzu_test_pkgdb_` prefix. No raw `::close`, no `FILE*`.
- `tests/unit/test_rpmdb_parsers.cpp`: `blobs_of_sqlite` owns the connection and the statement with `std::unique_ptr`
  (the connection first, before the `REQUIRE` on the open result, so a failed open still closes; the statement
  declared after it so it is finalized first). This closes finding `qe-6-raw-sqlite-handle-in-test`.

## Not introduced
- No new socket, thread other than the `bounded_call_ex` worker, library handle, allocated C string or `FILE*`.
- No manual `delete`, `free`, `close` or `sqlite3_free` in new production or test C++. Every handle above is owned
  by an RAII type.
- The `fstat` on the rpm directory descriptor in `read_rpm_dir` and the `lstat` and `stat` calls in
  `symlink_hides_database` open and own nothing; `read_dirs` and `link_dirs` are local value vectors.
- No lock is ever taken by the readers: the `.rpm.lock` probe is `F_GETLK` only, the updates directory is listed by
  name only, and nothing opens a file inside it.
- `refresh_local_zone` (`installed_apps_plugin.cpp`) calls `::tzset()`, which only touches process-global time-zone
  state and owns nothing. `local_tm` writes a caller-owned `std::tm`.
