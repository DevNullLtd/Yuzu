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

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| Registry key handles (`HKEY`) | `ScopedKey<RealRegOps>` (closes through `RegCloseKey` in the destructor) | `read_lxss_hive`, `read_package_version` | function-local | Lxss key, one distribution key at a time, the MSI key. Every exit path, an exception thrown by the walk included, closes them; the unit tests assert open/close balance. |
| Value buffers | `std::vector<std::byte>` | `read_string_value` | function-local | Sized from the probe, never past 4096 bytes (a larger value is `value_oversized` and never allocated); at most one in flight. DWORDs use a 4-byte array. |
| `WalkBudget` | struct over `RowByteBudget` | `run_windows_wsl` | one per dispatch | 1024 rows / 256 KiB (the status and summary rows are reserved up front, the reserve is proven by a unit test) and 4096 counted `RegEnumKeyExW`/`RegQueryValueExW` calls across every hive. |
| `WslReads` and its rows | value types (`std::string`, `std::vector`) | `run_windows_wsl` | function-local | Values are sanitised (redacted and escaped) at collection, so the retained bytes are the bytes charged. |
| Profile list | `std::vector<ProfileInfo>` from `enumerate_profile_list()` | `run_windows_wsl` | function-local | At most `kMaxProfiles` (512) records; `enumerate_hku_subkeys()` is not called. |

## Table 2 — the privilege-bearing span (owned by the shared helper)

| Resource | Owner | This diff's interaction |
|---|---|---|
| `offline_hive_mutex()` (process-wide) | `with_user_hive` (`ScopedOfflineHiveLock`) | Held by the helper for the whole offline arm. The plugin's callback runs under it, walks only the handed root and never re-enters `with_user_hive`. At most 512 `with_user_hive` calls per dispatch (one per local profile), each possibly one `RegLoadKeyW` mount, taken serially. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | `PrivilegeScope` inside `with_user_hive` | Enabled by the helper for the offline arm only and reverted on scope exit; already held by the agent account, so no new privilege. The call passes no `OfflineHiveFileCheck`, so the default-on guard applies. |
| Mounted hive | `ScopedUserHive` inside `with_user_hive` | Unloaded by the guard's destructor on every exit path. A failed unload is reported: a `profile` row (`unload_failed`), the token `hive_unload_failed` and an `spdlog::error` that names the mount (the log is the only place the SID-bearing mount name appears). |

## Deadlines (disclosed residual)

The lock wait, `RegLoadKeyW`, `RegUnLoadKeyW` and the individual registry reads have **no deadline**,
identical to `installed_apps.list_per_user`. The visited-entry cap, the per-value bound and the row/byte
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
