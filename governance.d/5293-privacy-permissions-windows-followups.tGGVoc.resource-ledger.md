# Resource Ledger — `5293-privacy-permissions-windows-followups.tGGVoc`

Every owning boundary the C++ in `b5b956e3e..HEAD` (fix/5293-privacy-permissions-windows-followups)
acquires. Required by the Gate 1 contract on any C++ diff; recorded here rather than only in the
run narrative so a later reader can check it against the code.

This diff adds one registry-key owner, one event-handle owner, one file-handle owner, one
directory-search-handle owner and one `LocalFree` guard, all RAII and all in the Windows shells
(`privacy_permissions_win.cpp`) or the windows.h-free seam they implement
(`privacy_permissions_win_walk.hpp`). The shared budget helper (`row_byte_budget.hpp`) owns nothing:
it is plain counters. Nothing in the diff adds a thread, a subprocess, a socket, a temp path, an
OpenSSL/BCrypt object, an allocated C string or a mapped library.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| ConsentStore subkey `HKEY` | `ScopedKey` (`privacy_permissions_win_walk.hpp`; RAII, **neither copyable nor movable**: copy is deleted and the user-declared special members suppress the implicit move) | `Win32Registry::open_key` = `RegOpenKeyExW`; `out` is assigned only on success | destructor -> `RegistryReader::close_key` = `RegCloseKey`; a second `open()` closes the held key first and leaves the owner empty if the new open fails | none | a failed open assigns nothing, so there is nothing to close |
| change-watch event `HANDLE` | `StabilityWatch` (`privacy_permissions_win.cpp`, non-copyable) held by `std::unique_ptr<ConsentStoreWatch>` | `CreateEventW` in the constructor; `RegNotifyChangeKeyValue` arms it on the (non-owned) root `HKEY` | `CloseHandle` in the destructor | none | a failed create or arm is recorded as a refusal token and the destructor still closes; ONE watch per walk attempt (the re-walk creates a fresh one) |
| hive-file `HANDLE` (leaf, ancestor and sidecar facts) | `UniqueHandle` (`privacy_permissions_win.cpp`) | `CreateFileW` in `Win32HiveFileProbe::open_attr` | `CloseHandle` in the destructor | none (scope-local) | an invalid handle returns `failure_code(GetLastError())` and nothing is closed |
| directory search handle | `FindHandle` (`privacy_permissions_win.cpp`) | `FindFirstFileExW` in `list_sidecars` | `FindClose` in the destructor | none | a listing failure returns its code; the early return at the sidecar limit closes through the destructor |
| `LocalFree` allocations (security descriptor, SID string) | `LocalFreeGuard` (`privacy_permissions_win.cpp`) | `GetSecurityInfo` / `ConvertSidToStringSidW` | `LocalFree` in the destructor | none | the guard is constructed before use; a null pointer is a no-op |
| loaded profile hive mount + live `HKU` key | `with_user_hive` (`agents/shared/win_profiles.hpp`), **unchanged except for the additive `live_open_rc` member** | live `RegOpenKeyExW(HKEY_USERS, <SID>)`, else `RegLoadKeyW` under `SeBackupPrivilege`/`SeRestorePrivilege` | RAII `RegKey` for the live key; `RegUnLoadKeyW` on every path of the offline arm, inside the process-wide offline-hive lock | none | unchanged: an unload failure is recorded in `report.unload_failed`, logged by the collector, and rethrown on an exception |
| callback contexts | `HiveFileGuard` stores a `std::function<bool()>` capturing `budget` by reference; the `OfflineHiveFileCheck` lambdas capture `guard` by reference | locals of the per-profile `read_profile` lambda in `collect_windows_permissions` | destroyed in reverse order after `with_user_hive` returns | passed to `with_user_hive` by pointer for the call only, never stored beyond it | no stored pointer outlives its owner; `budget` outlives the lambda |
| byte views | non-owning `std::span`s: over `read_one_grant`'s `std::vector<std::byte>` (value payload) and over a stack `std::uint64_t` (the last-used timestamp) | the vector via `operator new`; the integer is a local | vector destructor; the local ends with its scope | none; `Win32Registry::reg_sz_utf8` `reinterpret_cast`s the payload to `const wchar_t*` (alignment note added; the same idiom exists at five other sites in the tree) | n/a |
| threads, subprocesses, sockets, temp paths in production code | none added | | | | |
| tests | `TestKey` / `yuzu::win::RegKey` (RAII) and `TempDir` with the `yuzu_test_` prefix | | | | |

**Adjudications recorded:** none required. No manual (non-RAII) resource cleanup was added anywhere
in this diff, so the "documented impossibility" exception is not invoked.

**Corrections recorded during the governance round.** An earlier revision of this ledger called
`ScopedKey` move-only; it is neither copyable nor movable, and its `open()` did not close a key it
already held. The governance review reported that independently four times; `open()` now closes and
empties a held key before re-opening, the case is locked by a unit test (opens equal closes), and a
comment records that the parent handle must not be the key's own. The byte-views row originally
named only the vector; the stack integer view was added.

**Sanitizer coverage.** No TSan or ASan leg exists in-tree for these owners. During review,
reviewers ran standalone probes (several under ASan/UBSan) against the pure logic and found no
memory or arithmetic defect: the budget arithmetic (more than 205 million differential cases
against the arithmetic it replaced), the hive-file guard (3 million scenarios), `ScopedKey`
open/close sequences (200,000) and the profile-loop assembler (300,000 runs). The Windows-only
shells are exercised by the MSVC rig tests, as an elevated user and as `NT AUTHORITY\SYSTEM`; their
CI leg is the Windows MSVC build.
