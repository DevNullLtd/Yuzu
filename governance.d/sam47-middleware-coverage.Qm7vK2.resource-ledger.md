# Resource Ledger — middleware registry leg (IBM MQ on Windows) and shared zip directory reader

Range: `0c68ac5043833decce953e5cb3f45d173374d7d1..6aae12e3da` (branch `feat/sam-47-middleware-coverage`)

Run: `governance.d/sam47-middleware-coverage.Qm7vK2.jsonl`

## Summary

This diff introduces **no fd, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, allocated C
string, mapped library, temp path, subprocess, thread, callback context, stored pointer or
reference**, and no `reinterpret_cast` beyond the one standard Win32 `LPBYTE` out-buffer cast,
no `const_cast`, no `raw()` or `release()`. The only OS handle is a registry key, owned by the
existing RAII `yuzu::win::RegKey`. The Windows TU body is `_WIN32`-only and has not been compiled
on this host (syntax-checked with the mingw script); the lifetimes below are read, not run.

## Table 1 — new owned state

| Resource | Type | Owner | Acquisition | Release | Failure cleanup |
|---|---|---|---|---|---|
| `h` in `RealRegOps::list_subkeys` | `HKEY` in `yuzu::win::RegKey` | the function frame | `RegOpenKeyExW(HKEY_LOCAL_MACHINE, ..., h.put())`, opened `KEY_ENUMERATE_SUB_KEYS \| KEY_WOW64_{64,32}KEY` | `~RegKey` (`RegCloseKey`) at every return, including the three early returns | a failed open leaves `h` null (`put()` resets first); the destructor ignores null. `HKEY_LOCAL_MACHINE` is a predefined key and is never wrapped. |
| `h` in `RealRegOps::read_sz` | `HKEY` in `RegKey` | the function frame | as above, `KEY_QUERY_VALUE` | `~RegKey` | same; every early return (open, size query, `decide_value`, second query) runs the destructor. |
| `name[256]` | `wchar_t[256]` on the stack | the enumeration loop | per `RegEnumKeyExW` call | scope exit | A registry key name is at most 255 characters, so the buffer holds any name; `ERROR_MORE_DATA` would be a `failed` listing, not an overflow. The `std::string` copy is made with the explicit length the call returned. |
| `buf` | `std::wstring` of `size/2+1` | `read_sz` | sized from the first `RegQueryValueExW`, capped by `decide_value` at `kMaxRegValueBytes` (64 KiB) before allocation | scope exit | The second query passes the buffer's own byte count; a value that grew between the two queries returns `ERROR_MORE_DATA` and becomes `failed`. The one `reinterpret_cast<LPBYTE>` is the documented Win32 byte-buffer form (`unsigned char` aliasing). |
| `RealRegOps`, `WinRegFs<RealRegOps>` | stateless struct; class holding `Ops`, a budget counter and a flag | `run_windows` frame | by value | scope exit | No heap beyond `std::vector<std::string>` names and rows, all under RAII. |
| `RegListing`, `RegText`, `RegKeys`, `Read` | value structs of `std::string` / `std::vector<std::string>` | the callers | returned by value | scope exit | Default-built answers are failures, never empty successes. |
| spdlog callback in `run_windows` | captureless lambda | `run_windows` frame | passed by forwarding reference to `run_reg_leg` | scope exit | No stored copy; the lambda does not outlive the call. |
| `kIbmMqWindowsProbes`, `kMaxRegEntries`, `kMaxRegValueBytes` | `inline constexpr` | static storage | compile time | program lifetime | Constant-initialised; the table is checked at compile time by `products_well_formed()` (`leg_well_formed(leg, registry)`). |
| `agents/shared/zip_directory.hpp` | header only | n/a | n/a | n/a | Moved unchanged apart from a banner comment (99% rename, no symbol change). It holds no resource: spans and `string_view`s over caller buffers, overflow-checked arithmetic. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| Plugin ABI boundary (`execute_action` try/catch) | `middleware_legs.hpp` | `run_windows` is a new `LegFn` behind the same guard: an exception (for example `std::bad_alloc` on the value buffer) becomes `status\|<action>\|constrained\|internal_error` and never crosses the ABI. |
| Linux leg (`run_leg`, `middleware_linux.cpp`) | unchanged | Not edited. `leg_well_formed` gained a `registry` parameter; the Linux call passes `false`. |
| Installed-software sync worker | `sync_source_installed_software.cpp` | Not edited; it now receives `supported` Windows answers. The worker is the bounded detached worker (60 s), the only wall-clock bound on this plugin (see finding SAM47-S1: the merge is quadratic until fixed). |
