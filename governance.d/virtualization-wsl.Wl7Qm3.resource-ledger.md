# Resource Ledger — virtualization wsl

Range: `origin/dev..HEAD` (branch `feat/virtualization-wsl`)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle,
mapped library or temp path**. The Windows leg opens registry keys through an RAII wrapper and, for a
profile that is not logged on, enters the shared `yuzu::win::with_user_hive` helper, which owns the
offline-hive lock, the SeBackup/SeRestore privilege scope, the default-on hive-file guard and the
`RegLoadKeyW`/`RegUnLoadKeyW` pair. The plugin takes no lock, enables no privilege and opens no second
mount path of its own.

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Registry key handles (`HKEY`): the Lxss key, one distribution key at a time, the MSI key | `ScopedKey<RealRegOps>` (closes through `RegCloseKey` in its destructor; copy deleted) | `open_key` inside `read_lxss_hive` and `read_package_version`, opened with `REG_OPTION_OPEN_LINK` (a link at the leaf is opened as the link object, never followed) | scope exit of the function-local `ScopedKey` | none | RAII on every exit path, an exception thrown by the walk included; the unit tests assert open/close balance on the stop, error and throw paths |
| R2 | Value buffer (`std::vector<std::byte>`) and the 4-byte DWORD array | `read_string_value` (function-local) | sized from the size probe, never past 4096 bytes (a larger value is `value_oversized` and never allocated); at most one in flight | scope exit | none | RAII (`std::vector`); no cleanup of its own |
| R3 | `WalkBudget` (over `RowByteBudget`) | `run_windows_wsl` (one per dispatch), passed by reference to the walk | top of `run_windows_wsl` | function exit | none (by reference) | value type, no cleanup. 1024 rows / 256 KiB (status and summary rows reserved up front, the reserve proven by a unit test) and 4096 counted `RegEnumKeyExW`/`RegQueryValueExW` calls across every hive; each hive also has its own 512-call and 128-row allowance (`hive_entry_cap` / `hive_row_cap`, per-hive counters reset at the start of each hive); profiles a dispatch-wide stop never reached are counted in `profiles_not_loaded` |
| R4 | `WslReads` and its rows | value types (`std::string`, `std::vector`) owned by `run_windows_wsl` | filled by `collect_wsl` / `read_package_version` | function exit | read by `decide_wsl`; rows move into the `Posture` | value types; values are sanitised (redacted and escaped) at collection, so the retained bytes are the bytes charged; tokens are de-duplicated at push |
| R5 | Profile list | `std::vector<ProfileInfo>` from `enumerate_profile_list()` / `build_profile_list` (function-local) | top of `run_windows_wsl`; at most `kMaxProfiles` (512) records | function exit | passed to `collect_wsl` as a `std::span` (non-owning) | value type; `enumerate_hku_subkeys()` is not called |
| R6 | `HiveAccessFn` callback context, three pieces: the captureless `access` lambda in `run_windows_wsl` (stored as a `wsl::HiveAccessFn`); per profile, the `log_unload_failed` lambda (captures `profile` and the per-profile `HiveAccessReport report` by reference); and the `[&](HKEY root) { fn(root); }` temporary handed to `with_user_hive` (captures the walk callback `fn` by reference; `&report` is passed as the helper's report argument) | `access`: the `std::function` local in `run_windows_wsl`. The other two: stack locals / a call-argument temporary of the per-profile call | `access` built once before `collect_wsl`; the other two at the start of each per-profile call | `access` at function exit; the other two when the per-profile call returns or unwinds | none: `with_user_hive` takes the callable as a forwarding reference for the duration of the call and does not retain it, and the callable never re-enters the helper | the `catch (...)` around `with_user_hive` logs `unload_failed` (when the helper recorded one) and rethrows; the helper's own scope guards have already unloaded the hive and reverted the privilege, and the plugin ABI catch is the only place the exception stops |
| R7 | `static constexpr Legs kLegs` (per-OS table of `host` and `wsl` leg function pointers) in `VirtualizationPlugin::execute` | static storage duration, constant-initialised | none (no runtime acquisition) | none (lives for the process) | none | none: two function pointers, no state |

## Table 2 — the privilege-bearing span (owned by the shared helper)

| Resource | Owner | Acquired | Released | This diff's interaction |
|---|---|---|---|---|
| `offline_hive_mutex()` (process-wide) | `with_user_hive` (`ScopedOfflineHiveLock`) | on entry to the offline arm | scope exit of the helper's guard, on every path | Held by the helper for the whole offline arm. The plugin's callback runs under it, walks only the handed root and never re-enters `with_user_hive`. At most 512 `with_user_hive` calls per dispatch (one per local profile), each possibly one `RegLoadKeyW` mount, taken serially. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | `PrivilegeScope` inside `with_user_hive` | enabled by the helper for the offline arm only | reverted on scope exit | Already held by the agent account, so no new privilege. The call passes no `OfflineHiveFileCheck`, so the default-on guard applies. |
| Mounted hive | `ScopedUserHive` inside `with_user_hive` | `RegLoadKeyW` in the offline arm | unloaded by the guard's destructor on every exit path | A failed unload is reported: a `profile` row (`unload_failed`), the token `hive_unload_failed` and an `spdlog::error` that names the mount (the log is the only place the SID-bearing mount name appears). |

## Deadlines (disclosed residual)

The lock wait, `RegLoadKeyW`, `RegUnLoadKeyW` and the individual registry reads have **no deadline**,
identical to `installed_apps.list_per_user`. The visited-entry cap (4096 per dispatch, 512 per hive), the per-value bound and the row/byte
budget bound how many registry calls run under the lock, not how long each takes. A dead profile volume
or another plugin holding the lock can hold the instruction worker. A cooperative deadline would need a
custom `OfflineHiveFileCheck`, which the default-on guard rule forbids for this action.

## Table 3 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| plugin `execute()` | `VirtualizationPlugin` | `execute_action` replaces `execute_host`: still one `try { ... } catch (...) { ... }` around the whole body; the catch writes a fixed-token status row (now named for the action) inside its own nested `try`/`catch (...)`. No new acquisition. |

## Tests

`tests/unit/test_virtualization_wsl_parsers.cpp` drives the walk and the hive-access outcomes through
a fake registry and a fake `HiveAccessFn` (no real registry, file, process or clock).
`tests/unit/test_plugin_abi_oom_containment.cpp` covers `execute_action` for `host` and `wsl`.
`tests/test_virtualization_wsl_pin_lexical.py` pins the Windows shell's wiring on source text (the one
`with_user_hive` call with the default-on guard, the open-link flag on every registry open, the
SID-bearing mount name only in the agent log), since that body cannot run in the unit suites.

## Registry links (hostile hive content)

Every key is opened with `REG_OPTION_OPEN_LINK`, so a link planted as the user's `Lxss` or as a `{GUID}`
child is opened as the link object (which holds none of the five value names read) and reads as no WSL or
an empty row. The flag covers the last component of each open only; a link planted at an ancestor of
`Lxss` is a disclosed residual (README caveat 4). No crafted-hive probe was run on a Windows host: the
remedy is applied unconditionally rather than gated on a measurement.
