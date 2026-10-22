# Resource Ledger -- offline-hive file guard lift

Range: `34db683fa..2ee852021` (branch `feat/registry-hive-file-guard`)

## Summary

This range introduces **no new resource owner**. It MOVES three RAII owners and the Win32 probe shell
from `privacy_permissions_win.cpp` into the Windows-only header `agents/shared/win_hive_file_probe.hpp`,
unchanged apart from `inline`, dropped namespace qualifiers and one constant's name
(`kErrorFileNotFound` -> `kHiveErrorFileNotFound`, both `long` 2, the new one `static_assert`ed against
the SDK). There is no new fd, socket, `FILE*`, `sqlite3*`, OpenSSL or BCrypt object, no thread, no
subprocess, no temp path and no manual cleanup. `CloseHandle`, `FindClose` and `LocalFree` appear only
inside the three moved destructors.

## Table 1 -- owned resources (all RAII, all moved verbatim)

| Resource | Owner | Acquired | Released | Early returns / failure |
|---|---|---|---|---|
| file `HANDLE` from `CreateFileW` | `UniqueHandle` (empty sentinel `INVALID_HANDLE_VALUE`; copy deleted, therefore non-movable) | `Win32HiveFileProbe::open_attr` (`FILE_FLAG_OPEN_REPARSE_POINT`, so a link is seen, never followed) | end of the enclosing probe method | returned as a prvalue (guaranteed elision, no move); a failed open leaves the sentinel, whose destructor does nothing, so `GetLastError` survives; no handle is held across `RegLoadKeyW` |
| search handle from `FindFirstFileExW` | `FindHandle` (`FindClose`) | `list_sidecars` | scope exit | the failed-find return, the limit return, the final return and an allocation failure in `push_back` all run the destructor |
| security descriptor from `GetSecurityInfo` | `LocalFreeGuard` (`LocalFree`, null is a no-op) | `leaf_facts`, guard built only after the call succeeds | scope exit, after `owner` (which points into it) is last used | `owner` never escapes the function |
| SID string from `ConvertSidToStringSidW` | `LocalFreeGuard` | `leaf_facts`, guard built unconditionally | scope exit, before the descriptor guard | the return expression reads `GetLastError` before any destructor runs |
| path buffer | `std::wstring` | `leaf_facts`, sized twice for `GetFinalPathNameByHandleW` | scope exit | a path that grew between the calls is reported as `ERROR_MORE_DATA`, never read |
| 128-bit file id | `std::array<uint8_t,16>` | `memcpy` from `FILE_ID_128` | member of `FileId` | copy size is `static_assert`ed equal to the SDK type; no cast |

## Table 2 -- borrowed state

| Holder | Borrows | Lifetime |
|---|---|---|
| `HiveFileGuard::probe` | `HiveFileProbe&` | the probe is declared before the guard in the `read_profile` lambda of `collect_windows_permissions` and outlives it; one probe per profile, used by one thread |
| `HiveFileGuard::expired` | a copy of a `std::function` capturing the run's budget by reference | the budget is a local of `collect_windows_permissions` and outlives every call; an empty function throws before any syscall (fails closed) |
| the `OfflineHiveFileCheck` hooks | the guard, by reference | `with_user_hive` takes a pointer to the check, calls it synchronously and does not retain it |

## What the move changed about lifetime

Six entities (`UniqueHandle`, `FindHandle`, `LocalFreeGuard`, `final_path_matches`, `failure_code`,
`Win32HiveFileProbe`) go from an anonymous namespace to external `inline` linkage in `yuzu::win`. There
are no statics or `thread_local`s; every instance is an automatic object per `read_profile` call; no
other definition of any moved name exists (the two other `UniqueHandle` types sit in anonymous
namespaces).

Independently proved by cpp-safety and security-guardian (ownership proof entry by entry) in the
governance run recorded beside this file.
</content>
