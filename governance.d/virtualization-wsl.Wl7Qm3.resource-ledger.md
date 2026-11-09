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
| R3 | `WalkBudget` (over `RowByteBudget`) | `run_windows_wsl` (one per dispatch), passed by reference to the walk | top of `run_windows_wsl` | function exit | none (by reference) | value type, no cleanup. 1024 rows / 256 KiB (status and summary rows reserved up front, the reserve proven by a unit test) and 4096 counted `RegEnumKeyExW`/`RegQueryValueExW` calls across every hive; each hive also has its own 512-call, 128-row and 32 KiB allowance (`hive_entry_cap` / `hive_row_cap`, the row and byte allowances sharing the one token; per-hive counters reset at the start of each hive); profiles a dispatch-wide stop never reached are counted in `profiles_not_loaded` |
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
identical to `installed_apps.list_per_user`. The visited-entry cap (4096 `RegEnumKeyExW` / `RegQueryValueExW`
calls per dispatch, the link probes included, and 512 per hive), the per-value bound and the row/byte
budget (1024 rows / 256 KiB per dispatch, 128 rows / 32 KiB per hive) bound how many registry calls run under the lock, not how long each takes. A dead profile volume
or another plugin holding the lock can hold the instruction worker. A cooperative deadline would need a
custom `OfflineHiveFileCheck`; this action deliberately uses the deadline-less default instead (the
binding decision is a default-on guard with no custom check).

The number of mounts is bounded by the profile cap alone, not by the visited-entry cap: opening the Lxss key
is not counted, so a hive with no Lxss key costs no counted call. The worst case is therefore
`kMaxProfiles` (512) serial `RegLoadKeyW` / `RegUnLoadKeyW` cycles per dispatch, each altering that hive's
sequence number and hash (#4977). Residual after an unload failure, all disclosed in the README: the
`YUZU_HIVE_<SID>_...` mount stays under `HKU` and keeps that `NTUSER.DAT` locked until `reg unload
HKU\<mount>` (found with `reg query HKU`); the user's next logon gets a temporary profile; a repeat
dispatch reports the profile as `mount_failed`; the only automatic cleanup is Echo's start-up sweep of
`YUZU_HIVE_*` mounts (`echo_registry_source.cpp`), which runs only when the Echo plugin is loaded. Retry,
caller-tag and read-audit changes belong to the shared helper and are out of scope for this diff.

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
child is opened as the link object, which holds none of the five value names read. That alone would read
as "no WSL" or a clean empty row, so each opened key (the Lxss key and every distribution key) is also
probed once for the `SymbolicLinkValue` value, one charged size-probe inside the existing budget (the
registry plugin's own link-probe marker). A hit is the token `lxss_link`: a link at Lxss leaves the profile
unread (in neither summary count), a link at a distribution key is a row with `-` / `unknown` fields and no
value is read. A plain key holding a decoy value of that name reads the same way, so the result is
constrained and never fail-open. A probe that itself fails is `value_unreadable` and the key is then read as
a plain one. The flag and the probe cover the last component of each open only; a link planted at an
ancestor of `Lxss` is a disclosed residual (README caveat 4). The unit tests drive the detection through a
fake registry (the fake cannot prove the real `REG_OPTION_OPEN_LINK` semantics).

Real-host check (planted link on a disposable local account: `REG_OPTION_CREATE_LINK` at `Lxss` and at one
child, a normal key listed alongside): pending the Gate 4 capture on the Windows host; the result is
recorded here and in the PR body. No probe source is committed.
