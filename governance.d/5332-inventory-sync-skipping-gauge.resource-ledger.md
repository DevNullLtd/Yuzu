# Resource Ledger - #5332 (yuzu_fleet_inventory_sync_skipping{source})

A Resource Ledger is required for a C++ diff (policy floor). Server-side only; no agent code.

## Production code (`server/core/src/inventory_sync_fleet_tags.hpp`, `agent_registry.cpp`, `server.cpp`)

No new fd, HANDLE, SOCKET, `FILE*`, sqlite handle, OpenSSL object, C string, mapped library, temp path,
subprocess or thread.

| resource | owner | acquired | released | notes |
|---|---|---|---|---|
| `std::array<int64_t, N> sync_skipping` | stack of `AgentHealthStore::recompute_metrics` | per sweep | function return | scalars, N = `std::size(kSyncSkipSources)` |
| function-static `std::array<std::string, N> kSyncSkipKeys` | the function (built once, immutable) | first sweep | process exit | same pattern as the `kKeySpark*` strings; lets `get_view` look up without a per-agent temporary key |
| `std::string_view` from `get_view` | per snapshot, loop-local | per agent | end of iteration | non-copying; points into `snap.status_tags`, stable because `mu_` (`std::lock_guard lock(mu_)` at the top of `recompute_metrics`) is held for the whole function |
| gauge `yuzu_fleet_inventory_sync_skipping{source}` | `MetricsRegistry`, as every sibling gauge | first `.gauge()` call | registry lifetime | fixed label set from the compile-time table; the agent-controlled tag value is parsed and only counted, never a label |

Published for every table row, 0 included, so no `clear_gauge_family` is needed. Precedent for an
always-published-at-0 server-owned count: `yuzu_fleet_tar_db_corruption_agents`.

`parse_sync_skip_streak` is `noexcept`, allocation-free, bounded to 6 characters.

## Test code (`tests/unit/server/test_agent_health_store.cpp`)

Stack-local `AgentHealthStore` and `MetricsRegistry` per case; no files, threads, processes or sockets.
