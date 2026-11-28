# Resource Ledger — device_ci v2 agent writer

Range: `b8585bfd014186d4b6be6559ffa06664afee02fd..HEAD`

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread**. The v2 writer
is pure value-state code over `std::string` and `std::vector`; the collection path reuses the
existing in-process `LocalDispatcher` seam unchanged, and `LocalDispatcher` ownership is not
touched.

## Table 1 — new owned state (all RAII value types)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `CiSectionInputs` / `CiActionResult` | structs of `std::string` and scalars | the `device_ci` `collect` lambda | one collect call | Filled from `LocalDispatcher::Result` (the three existing actions and the seven section actions); passed by `const&` to the writer and destroyed when `collect` returns. |
| `SectionBuild` array | `std::vector<SectionBuild>` (strings and row vectors) | `device_ci_canonical_blob_v2` | function-local | Per-section projected rows, status record and cap token; popped by the ceiling trim; moved into the returned blob and then freed. |
| `blob` | `std::string` | `device_ci_canonical_blob_v2`, then the `collect` lambda | function-local, then moved into the returned pair | Reserved once to the running total, never above the blob ceiling after the trim. |
| `trim_idx` | `std::size_t[7]` (stack) | `device_ci_canonical_blob_v2` | function-local | Registry indices in trim order. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `LocalDispatcher` | the `collect` lambda (stack) | Seven further `run` calls on the same instance, after the original abort-on-failure block; each returns a value `Result`. No new acquisition and no lifetime change. |
| plugin descriptors (`const YuzuPluginDescriptor*`) | the agent plugin host | One further non-owning pointer (`disk_actions`) is captured by value into the sync thread lambda and the source's `collect` lambda; the plugin host outlives the sync thread as before. |

## Tests

Test code adds only Catch2 locals (`std::string`, `std::vector`, `std::map`) and file-scope fake
plugin descriptors with static scripted-output maps, reset per test case; no file, socket,
process or timer is used.

## Addendum — review remediation (mount-point redaction, deferred Windows volumes, unescaped-pipe split)

Range: `b8585bfd014186d4b6be6559ffa06664afee02fd..HEAD`, which now also covers the remediation
commits. Every C++ file in the range, with what the remediation does to it:

| File | Remediation change | Resources |
|---|---|---|
| `agents/core/src/sync_source_device_ci.cpp` | `redact_mount_points` and its anonymous-namespace helper `mount_entry_is_personal`; `windows_volumes_deferred_result`; `split_pipe` gains an unescaped-only mode and `unescape_pipes` is added; `project_row`/`project_rows` carry a `bool&` redaction flag; `first_row` picks the row that sorts first; the factory skips the `volumes` dispatch under `if constexpr (kWindowsHost)`. | None acquired. Every new value is a `std::string`, `std::string_view` over the capture, or a `constexpr` table (`kPersonalMountRoots`, `kRedactedMount`, the two reason strings). No OS call is added. On Windows the change removes one dispatch (`volumes`, whose `DeviceIoControl` calls carry no deadline) from the sync thread. |
| `agents/core/src/sync_source_device_ci.hpp` | Declares `redact_mount_points` and `windows_volumes_deferred_result`, and the comment contract for the new reasons and pipes. | None. Declarations only. |
| `agents/core/src/agent.cpp` | Unchanged by the remediation; it passes the `disk_actions` descriptor to `make_device_ci_source` as in the original range. | None. |
| `tests/unit/test_device_ci_sync.cpp` | New cases for pipes, redaction, deferral and scalar order; the cross-pin fixture uses `C:/`; `wide_rows` keeps byte width and gives the mount column a path shape. | Catch2 locals only; the static fake-plugin maps are reset per case as before. |
| `tests/unit/server/test_device_inventory_store.cpp` | Test data only: the twin of the cross-pin fixture (`C:/` and the recomputed hash literal) and one parsed-row expectation. No server code changes. | None. |

`windows_volumes_deferred_result` returns a `CiActionResult` by value (a `std::string` provenance and
scalars). `redact_mount_points` returns a `std::string` and writes one caller-owned `bool`; neither
retains a reference past the call. The Windows branch of the factory is a compile-time constant, so
no runtime state selects it.
