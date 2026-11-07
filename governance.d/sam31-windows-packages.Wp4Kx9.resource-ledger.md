# Resource Ledger — pkg_inventory Windows legs (Appx, Chocolatey, winget presence)

Range: `origin/dev..HEAD` (branch `feat/sam-31-windows-packages`)

## Summary

The Windows legs acquire three kinds of OS object, each owned by exactly one RAII type with no
path that hands a raw handle across a function boundary: registry keys, a directory-search
handle, and a file handle. No fd, `SOCKET`, `FILE*`, `sqlite3*`, OpenSSL/BCrypt object, C string,
mapped library, temp path, subprocess or thread is introduced. Every handle is acquired and
released inside one `RealOps` call (or `read_file_bounded`), so none outlives a single row's
read, and the decision layer above them (`store_package_rows`, `chocolatey_package_rows`,
`manager_rows`) sees only value types.

## Table 1 — new owned state

| Resource | Type | Owner | Scope | Release |
|---|---|---|---|---|
| Appx roster key (`...\AppxAllUserStore\<store key>`) | `HKEY` | `yuzu::win::RegKey` (`win_reg_handle.hpp`) in `RealOps::list_reg_subkeys` | function-local | `RegCloseKey` in the destructor on every return, including the enumeration-error and cap breaks. Opened `KEY_READ \| KEY_ENUMERATE_SUB_KEYS \| KEY_WOW64_64KEY`; never a predefined hive handle wrapped. |
| Appx package key (`...\<store key>\<PackageFullName>`) | `HKEY` | `yuzu::win::RegKey` in `RealOps::read_reg_string` | function-local | Same. Opened only for the one App Installer key whose `Path` value is read (winget root); at most one per `managers` call. |
| Directory search | `HANDLE` from `FindFirstFileExW` | local `Closer` in `RealOps::list_dir` | function-local | `FindClose` in the destructor; a failed `FindFirstFileExW` returns before the guard exists. At most one per `packages` call plus one per `managers` call (the chocolatey `lib` listing). |
| File read | `HANDLE` from `CreateFileW` | local `Closer` in `yuzu::win::read_file_bounded` (`agents/shared/win_bounded_file_read.hpp`) | function-local | `CloseHandle` in the destructor on every return. One per package row (a nuspec), opened with `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_FLAG_BACKUP_SEMANTICS` (so a directory opens and is refused by the attribute check as `error` rather than failing the open as `denied`; the flag uses `SeBackupPrivilege` only if the process token has it enabled, which other agent plugins do transiently, so an ACL-denied nuspec can read through during such an overlap; the reach is the same fixed root) and `FILE_SHARE_READ \| WRITE \| DELETE` so the agent never blocks an installer or uninstall. Bounded by `kMaxNuspecBytes` (64 KiB) and by `max_lib_entries` (2048) packages. |
| Name / byte buffers | `std::wstring`, `std::string`, `std::vector<std::string>` | the `RealOps` call and the leg function | function-local | Value types. Registry key names are read into a 256-`WCHAR` stack buffer; a value read is bounded at 64 KiB; the row set is bounded by `RowByteBudget` (`kMaxPackageRows` rows, `kMaxOutputBytes` bytes). |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `pkg_inventory_win.cpp` `run_windows` | the plugin TU | Replaces the placeholder that emitted `windows:planned`; the call is still wrapped by `run_guarded`, so an exception from a leg becomes the fixed `pkg_inventory:exception` status, never an unannotated throw across the plugin ABI. |
| `emit_result` / `ConstraintAccumulator` / `RowByteBudget` | shared agent headers | Used unchanged. |

## Tests

The Windows-only cases own one scratch registry key under `HKCU\SOFTWARE\YuzuTest\PkgInventoryAppx_<pid>`
(deleted by a scope guard, process-suffixed so concurrent CI jobs on the shared runner identity
cannot collide) held in `yuzu::win::RegKey`, and one `yuzu_test_`-prefixed `TempDir` (removed by its
destructor). Every other case is in-memory.
