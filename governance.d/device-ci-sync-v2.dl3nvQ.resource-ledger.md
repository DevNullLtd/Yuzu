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
