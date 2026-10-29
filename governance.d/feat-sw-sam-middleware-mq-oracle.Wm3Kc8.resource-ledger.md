# Resource Ledger: feat-sw-sam-middleware-mq-oracle

Every owning boundary the diff adds or changes in C++ (the `middleware` agent plugin under `agents/plugins/middleware/`, `agents/shared/middleware_products.hpp`, the collector adapter hunks in `agents/core/src/sync_source_installed_software.{hpp,cpp}` and their unit tests).

## Owners

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Directory descriptor of the walk (the injected root, then one `openat` per path component) | `yuzu::shared::ScopedDir` inside `lnx::Opened` (`open_root`, `open_child`, both `O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC`) | `finish_dir_open`: the `open`/`openat` result is handed to `fdopendir` | `~ScopedDir` (`closedir`) at the end of the walk step that holds the `Opened`; `descend` moves the next hop in and the previous hop out | `fdopendir` takes ownership of the fd; `Opened` is moved, never copied | `fdopendir` failure closes the raw fd before returning; the optional touch-log append runs AFTER the `ScopedDir` owns the directory, so a `bad_alloc` there cannot leak the fd |
| R2 | `/proc/self/mountinfo` descriptor, once per dispatch | `yuzu::agent::ScopedFd` in `scan_mounts` (`O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC\|O_NONBLOCK`) | `scan_mounts` | scope exit of `scan_mounts` | none | every early `return` runs `~ScopedFd`; a read error, a non-regular file or more than 256 MiB yields `ok = false`, which the leg reports as `mountinfo:unreadable` |
| R3 | The enumerator file read (`mqinst.ini`) | owned entirely inside `yuzu::shared::read_file_no_follow_at` (`posix_secure_read.hpp`, unchanged) | inside the call | inside the call | the bytes come back as a `std::string` | n/a: no descriptor leaves the call |
| R4 | `lnx::t_touch_log` | `thread_local` raw pointer, null in production; a unit test points it at a vector on its own stack and restores it on scope exit | test only | n/a (not owned) | none | none needed (test seam, unowned) |
| R5 | `kActionDescriptors`, `kProducts`, `kIbmMqLinuxProbes` | `constexpr` / `inline constexpr` arrays of plain data pointing into string literals | static storage | program exit | none | none needed; `products_well_formed()` (consteval) rejects a malformed table at build time, now including a non-plain enumerator path |
| R6 | Per-dispatch row, name and listing strings | `std::vector<std::string>` / `std::string` locals of `run_leg` | built per candidate | scope exit | rows are returned by value to the leg, which hands them to `emit_read` | RAII; an exception is caught by the plugin's single `try/catch(...)` at the ABI seam and reported as `internal_error` |

No subprocess, thread, socket, temporary file, registry handle, timer or stored callback is added. `run_leg` takes its `Log` callable by forwarding reference for the duration of the call and never stores it. No new dependency.

## Bounds

| Bound | Value | On reaching it |
|---|---|---|
| `kMaxKvFileBytes` | 64 KiB | the file read is `oversized`: `mqinst_ini:oversized`, CONSTRAINED |
| `kMaxRows` | 256 stanzas / rows | stanzas past it are cut: `mqinst_ini:row_cap`; rows past it: `walk:row_cap`; CONSTRAINED |
| `kMaxRowBytes` | 1 MiB of row text (clamped through `make_row_budget`; a test can lower it, never raise it) | `walk:row_cap`, CONSTRAINED |
| `kMaxDirEntries` | 1024 per listing | that installation's version stays `-` (logged), not a token |
| `kMaxEntriesVisited` | 65536 directory entries per action across all listings | `walk:row_cap`, CONSTRAINED; no row is built past the point it ran dry |
| mountinfo | 64 KiB chunk, 64 KiB line, 256 MiB total | an over-long line is skipped; more than the total or any read error is `mountinfo:unreadable`, CONSTRAINED |
| Wall clock | NONE | the plugin sets no deadline and `LocalDispatcher::run` (`agents/core/src/local_dispatcher.hpp`: "synchronously, in this thread") adds none, so a slow or hung LOCAL filesystem is not time-bounded; network mounts named by the run-start snapshot are never opened. Recorded as a residual, not fixed here (also in the plugin README) |

## Behaviour lines recorded for reviewers

- **What constrains an answer** (owner ruling 2026-10-29, "keep valid rows on data faults"): only an ACCESS or WALK fault is a token and CONSTRAINED. A stanza lacking `Name` or `FilePath` beside a usable one is logged (`ItemReason::malformed`, one line per stanza) and the usable stanzas are kept with the answer `supported`. A file with content but no `Installation:` line, or in which no stanza is usable, is `mqinst_ini:malformed`, never an empty `supported`. The table is in the header of `middleware_runner.hpp` and in README caveat 5.
- **Escaped-pipe split.** The collector adapter splits a middleware row with the `escaped` flag (a `\|` is field text), because `safe_output_field` writes a literal pipe that way. `test_inventory_sync.cpp` round-trips `mw::format_row` output (pipes in name and path) through the adapter so the writer and the reader cannot drift.
- **`ConstrainedPolicy::drop_source`.** The `middleware.ibm_mq` collector row withholds a CONSTRAINED source's rows for the cycle (`AdaptedRows::Status::withheld`) instead of skipping the cycle. The server replaces the agent's whole inventory each cycle, so the stored IBM MQ rows are removed until a read succeeds, and it cannot tell withheld from none installed (ADR-0016 update 2026-10-29).
- **Trust.** `mqinst.ini` is trusted as written by root or the MQ installer; owner and mode are not checked (measured 644 root:root in a 755 root:root directory). The version is digits and dots read from a file name; name and path are inventory text.
- **EACCES coverage.** The tests that need an unreadable file or directory SKIP at euid 0 and under `CAP_DAC_OVERRIDE`, so a root or lane run does not exercise them. They run, and passed, as a non-root user on the macOS build host; the symlink, cap and oversize cases cover the same constrained paths when privileged.
- **Landing note.** The shared collector hunks (`escaped` split flag, `ConstrainedPolicy::drop_source`, `AdaptedRows::Status::withheld`, the `adapt_pkg_inventory` branch, the driver's `withheld` block and their header comments) are copied identically into the runtimes change that lands after this one. Edit them in both or in neither; the later change must merge with no conflict in those hunks.
- **Duplicated code.** `touches_network_mount`, `finish_dir_open`, `open_child`, `scan_mounts`, `production_config` and the `kMountinfo*` constants are private copies of the runtimes plugin's; hoisting them to `agents/shared` is an owed follow-up once both plugins are on `dev`. This copy alone carries the `t_touch_log` seam.
