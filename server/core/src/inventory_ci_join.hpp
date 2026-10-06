#pragma once

/// @file inventory_ci_join.hpp
/// Pure device-CI enrichment for the /inventory Devices-tab roster (PR2). Attaches
/// each already-visible `InventoryDeviceRow`'s CI fields (serial / model / CPU / RAM)
/// from a pre-fetched `agent_id -> DeviceCiRecord` map.
///
/// Split out of server.cpp's `build_hw_roster` so the confinement contract is
/// unit-testable without a live Postgres pool or full `ServerImpl`: the CONFINEMENT
/// itself happens downstream, in HardwareRoutes' `scoped_roster` on the FleetReadGate
/// scope (ADR-0017) — `attach_device_ci` never re-derives visibility. It only ever looks up
/// `ci_by_agent` BY the agent_id already present in `rows`; it never iterates
/// `ci_by_agent`'s keys to manufacture a row. So an out-of-scope agent's CI entry
/// riding along in the same `list_device_ci(0)` read is inert — it is looked at,
/// never attached, and never rendered.

#include "inventory_routes.hpp" // InventoryDeviceRow; DeviceCiRecord (via device_inventory_store.hpp)

#include <unordered_map>
#include <vector>

namespace yuzu::server {

/// `rows` MUST already be the operator-visible roster (post `visible_set_fn` filter).
/// `ci_by_agent` may hold entries for agents NOT present in `rows` — those are never
/// looked up, so no CI ever attaches to a row the caller didn't already deem visible.
/// A `rows` entry with no matching `ci_by_agent` key is left with its default-empty
/// `ci_*` fields (not yet synced) — never treated as an error.
void attach_device_ci(std::vector<InventoryDeviceRow>& rows,
                      const std::unordered_map<std::string, DeviceCiRecord>& ci_by_agent);

} // namespace yuzu::server
