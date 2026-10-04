# Resource Ledger - #5332 (yuzu_fleet_inventory_sync_skipping{source})

A Resource Ledger is required for a C++ diff (policy floor). Server-side only; no agent code.

## Production code (`server/core/src/agent_registry.cpp`, `server.cpp`; doc comment only in `tar_corruption_audit.hpp`)

No new fd, HANDLE, SOCKET, `FILE*`, sqlite handle, OpenSSL object, C string, mapped library, temp path,
subprocess or thread.

| resource | owner | acquired | released | notes |
|---|---|---|---|---|
| `int sync_skipping` | stack of `AgentHealthStore::recompute_metrics` | per sweep | function return | scalar |
| function-static `std::string kKeySyncSkip` | the function (built once, immutable) | first sweep | process exit | same pattern as the `kKeySpark*` strings; lets `get_view` look up without a per-agent temporary key |
| `std::string_view` from `get_view` | per snapshot, loop-local | per agent | end of iteration | non-copying; points into `snap.status_tags`, stable because `mu_` (`std::lock_guard lock(mu_)` at the top of `recompute_metrics`) is held for the whole function |
| gauge `yuzu_fleet_inventory_sync_skipping{source}` | `MetricsRegistry`, as every sibling gauge | first `.gauge()` call | registry lifetime | fixed label set (`source="installed_software"`); the agent-controlled tag value is parsed and only counted, never a label |

Transfer: none (no resource changes owner). Failure cleanup: not applicable - nothing acquired can leak:
the only objects are a stack scalar, an immutable function-static string and a borrowed view; no BCrypt
handle, callback context or thread is created.

Published every sweep, 0 included, so no `clear_gauge_family` is needed. Precedent for an
always-published-at-0 server-owned count: `yuzu_fleet_tar_db_corruption_agents`.

The tag value is parsed by the existing `parse_tar_corruption_total` (`tar_corruption_audit.hpp`, #1567):
`noexcept`, allocation-free, bounded to 18 characters; only tested for > 0, never read, summed or used as
a label.

## Test code (`tests/unit/server/test_agent_health_store.cpp`)

Stack-local `AgentHealthStore` and `MetricsRegistry` per case; no files, threads, processes or sockets.
