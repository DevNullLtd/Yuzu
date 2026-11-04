# Resource Ledger — runtimes dotnet/jvm legs and hardware.drivers_inventory

Range: `origin/dev..HEAD` (branch `feat/sam-32-runtimes-drivers`)

## Summary

The new legs acquire registry keys (Windows), one file handle (Windows), directory and file
descriptors (macOS, reusing the Linux `ScopedFd`/`DIR*` helpers), one bounded WMI query
(Windows) and small `/proc` and `/sys` file reads (Linux). Each is owned by exactly one RAII
type or scope with no path that hands a raw handle across a function boundary. No socket,
`FILE*`, `sqlite3*`, OpenSSL object, mapped library, temp path, subprocess or thread is
introduced. The decision layers above (`dotnet_rows`, `jvm_rows`, `drivers_inventory_rows`) see
only value types.

## Table 1 — new owned state

| Resource | Type | Owner | Scope | Release |
|---|---|---|---|---|
| Registry keys (`HKLM\SOFTWARE\dotnet\...`, NDP v4/v3.5, JavaSoft, Adoptium, Zulu; both WOW views) | `HKEY` | `RealRegOps::open`/`close` driven by the registry walk in `runtimes_win_parsers.hpp` | one key open at a time per walk step | `RegCloseKey` on every path, including enumeration errors and cap breaks. Opened read-only; only `HKEY_LOCAL_MACHINE` roots. |
| JVM `release` file read | `HANDLE` from `CreateFileW` | local `Handle` guard in `RealRegOps::read_file_bounded` | function-local | `CloseHandle` in the destructor. Opened with `FILE_FLAG_OPEN_REPARSE_POINT`; refused on a remote drive, reparse point, directory or non-disk file; bounded by a byte cap. At most one per registered home. |
| Directory search handle (`FindFirstFileEx`) | none | not used: the Windows legs read the registry and never walk a directory | n/a | n/a |
| macOS directory and file fds | `int` (`open`/`openat`, `O_NOFOLLOW\|O_CLOEXEC`) and `DIR*` from `fdopendir` | `yuzu::agent::ScopedFd` and the Linux walk's `DIR` holder, reused unchanged | function-local per hop | Closed in the destructor on every return; each hop is opened `O_NOFOLLOW` from the previous fd; listings and reads are bounded. `Info.plist` and `release` are read via `openat` on the already-held directory fd. |
| macOS mount snapshot | heap buffer from `getmntinfo_r_np` | `yuzu::shared::read_macos_network_mounts` (pre-existing) | one per run | Freed inside the helper. |
| WMI bounded query (`Win32_PnPSignedDriver`) | COM objects (`IWbemServices`, enumerator, row objects) | `wmi::run_bounded_wmi_query` (pre-existing shared helper) | one call per run | Released by the helper; the call is deadline-bounded and row-capped (4096), so no unbounded enumerator wait. |
| `/proc/modules` and `/sys/module/<m>/{version,taint}` | `int` fd | the bounded readers in `hardware_drivers_inventory.hpp`, opened `O_NOFOLLOW` | function-local | Closed on every return; `/proc/modules` and each sysfs field are read under a byte cap, and module names containing `/` or `..` never reach a path. |
| Name / byte buffers | `std::string`, `std::vector` | the leg function | function-local | Value types; row sets bounded by `RowByteBudget` and the row caps. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `emit_result` / `ConstraintAccumulator` / `RowByteBudget` | shared agent headers | Used unchanged. |
| `run_macos` / `run_windows` plugin entry points | the runtimes plugin TU | Replace the planned placeholders; behaviour on Linux is unchanged. |

## Tests

Windows-only cases use an injected fake registry and, where a real object is needed, a
`yuzu_test_`-prefixed scratch directory removed by its destructor. The macOS and hardware cases
run over materialized `yuzu_test_` fixture trees or in-memory strings.
