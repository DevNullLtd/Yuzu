# Resource Ledger -- offline-hive file guard lift (second run)

Range reviewed: `34db683fa..d2d2dba27`; fix delta re-reviewed: `d2d2dba27..079b7faa6` (branch `feat/registry-hive-file-guard`).

## Summary

This range introduces **no new resource owner**. It MOVES three RAII owners and the Win32 probe shell
from `privacy_permissions_win.cpp` into the Windows-only header `agents/shared/win_hive_file_probe.hpp`,
unchanged apart from `inline`, dropped namespace qualifiers and one constant's name
(`kErrorFileNotFound` -> `kHiveErrorFileNotFound`, both `long` 2, the new one `static_assert`ed against
the SDK). There is no new fd, socket, `FILE*`, `sqlite3*`, OpenSSL or BCrypt object, no thread, no
subprocess, no temp path and no manual cleanup. `CloseHandle`, `FindClose` and `LocalFree` appear only
inside the three moved destructors.

The production-code edits made after the first run are attributes, a deleted using-directive and the
spelling of type names (`yuzu::win::Win32HiveFileProbe`, `yuzu::win::HiveFileGuard`,
`::yuzu::win::kHiveTimeout`); none touches an owner, a handle, a lifetime or a cleanup path. The Windows
translation unit compiles to identical machine code before and after the move (mingw `-O2 -S`, 35,195
lines each, security-guardian; 1,343 of 1,352 functions identical, including all 119 that carry the moved
logic, cross-platform).

## Table 1 -- owned resources (all RAII, all moved verbatim)

| Resource | Owner | Copy / move | Acquired | Released | Early returns / failure |
|---|---|---|---|---|---|
| file `HANDLE` from `CreateFileW` | `UniqueHandle` (empty sentinel `INVALID_HANDLE_VALUE`) | deleted / deleted (non-movable), nothrow destructor | `Win32HiveFileProbe::open_attr` (`FILE_FLAG_OPEN_REPARSE_POINT`, so a link is seen, never followed) | end of the enclosing probe method | returned as a prvalue (guaranteed elision, no move; mingw `-fno-elide-constructors` also passes); a failed open leaves the sentinel, whose destructor does nothing, so `GetLastError` survives; no handle is held across `RegLoadKeyW` |
| search handle from `FindFirstFileExW` | `FindHandle` (`FindClose`) | deleted / deleted, nothrow destructor | `list_sidecars` | scope exit | the failed-find return, the limit return, the final return and an allocation failure in `push_back` all run the destructor |
| security descriptor from `GetSecurityInfo` | `LocalFreeGuard` (`LocalFree`, null is a no-op) | deleted / deleted, nothrow destructor | `leaf_facts`, guard built only after the call succeeds | scope exit, after `owner` (which points into it) is last used | `owner` never escapes the function |
| SID string from `ConvertSidToStringSidW` | `LocalFreeGuard` | deleted / deleted, nothrow destructor | `leaf_facts`, guard built unconditionally | scope exit, before the descriptor guard | the return expression reads `GetLastError` before any destructor runs |
| path buffer | `std::wstring` | value type | `leaf_facts`, sized twice for `GetFinalPathNameByHandleW` | scope exit | a path that grew between the calls is reported as `ERROR_MORE_DATA`, never read |
| 128-bit file id | `std::array<uint8_t,16>` | value type | `memcpy` from `FILE_ID_128` | member of `FileId` | copy size is `static_assert`ed equal to the SDK type; no cast |

## Table 2 -- borrowed state and callback contexts

| Holder | Borrows | Lifetime |
|---|---|---|
| `HiveFileGuard::probe` | `HiveFileProbe&` | the probe is declared before the guard in the `read_profile` lambda of `collect_windows_permissions` and outlives it; one probe per profile, used by one thread |
| `HiveFileGuard::expired` | a copy of a `std::function` whose lambda captures the run's `budget` by reference | `budget` is a local of `collect_windows_permissions` and outlives every call; an empty function throws `std::bad_function_call` before any probe call (fails closed) |
| the `OfflineHiveFileCheck` hooks | two lambdas capturing the guard by reference | declared after the guard; `with_user_hive` takes a pointer to the check, calls it synchronously on the calling thread inside the offline-hive lock and does not retain it |
| `&check`, `&report` passed to `with_user_hive` | stack objects of `read_profile` | the call is synchronous; locals are declared report, probe, guard, check, so destruction runs check, guard, probe, report in reverse |
| a copy of a `HiveFileGuard` | its own `snapshot` | a hook wired to a copy made before `before_load` ran has no snapshot, so its `after_load` refuses every load (fails closed); the production wiring uses the one guard by reference |

## What the move changed about lifetime

Six entities (`UniqueHandle`, `FindHandle`, `LocalFreeGuard`, `final_path_matches`, `failure_code`,
`Win32HiveFileProbe`) go from an anonymous namespace to external `inline` linkage in `yuzu::win`. There
are no statics or `thread_local`s; every instance is an automatic object per `read_profile` call; no
other definition of any moved name exists (the two other `UniqueHandle` types sit in anonymous
namespaces). The new test code holds no resource beyond in-memory maps and vectors.

Independently proved by cpp-safety and security-guardian (ownership proof entry by entry) in the
governance run recorded beside this file, and again by both on the fix delta.
