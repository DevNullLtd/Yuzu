#pragma once

/// @file inventory_ci_join.hpp
/// Pure device-CI enrichment for the /hardware roster. Attaches each
/// `InventoryDeviceRow`'s CI fields (serial / model / CPU / RAM)
/// from a pre-fetched `agent_id -> DeviceCiRecord` map.
///
/// Split out of server.cpp's `build_hw_roster` so the confinement contract is
/// unit-testable without a live Postgres pool or full `ServerImpl`: the CONFINEMENT
/// itself happens downstream, in HardwareRoutes' `scoped_roster` on the FleetReadGate
/// scope (ADR-0017) — `attach_device_ci` never re-derives visibility. It only ever looks up
/// `ci_by_agent` BY the agent_id already present in `rows`; it never iterates
/// `ci_by_agent`'s keys to manufacture a row. So an out-of-scope agent's CI entry
/// riding along in the same keyed read is inert — it is looked at,
/// never attached, and never rendered.
///
/// `apply_ci_read` is the one place the roster-keyed read (#7549) is driven: it asks for the CI
/// of exactly the ids in the roster, so the read is bounded by the roster and cannot drop a
/// listed device to a row cap. It is a pure
/// function over an injected reader so a test can prove WHICH ids are requested and what a failed
/// read does, which the `ServerImpl` lambda that wires the real store could not show.

#include "device_inventory_store.hpp" // DeviceCiRecord
#include "inventory_routes.hpp"       // InventoryDeviceRow

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

/// `rows` is the UNFILTERED roster; confinement is HardwareRoutes' `scoped_roster`,
/// downstream — this function never adds a row. `ci_by_agent` may hold entries for
/// agents NOT present in `rows` — those are never looked up, so no CI ever attaches
/// to a row that is not already in `rows`.
/// A `rows` entry with no matching `ci_by_agent` key is left with its default-empty
/// `ci_*` fields (not yet synced) — never treated as an error.
void attach_device_ci(std::vector<InventoryDeviceRow>& rows,
                      const std::unordered_map<std::string, DeviceCiRecord>& ci_by_agent);

/// Reads the CI records of exactly the named agents. `std::nullopt` = the read failed (never a
/// silent empty). Production wires `DeviceInventoryStore::list_device_ci_for`.
using CiKeyedReadFn =
    std::function<std::optional<std::vector<DeviceCiRecord>>(const std::vector<std::string>&)>;

/// Joins device CI onto `result.rows` by asking `read` for the roster's own ids. A failed read, or
/// an empty `read` (the store was never wired), sets `result.ci_degraded` and leaves every `ci_*`
/// field blank: blank-because-unread, never blank-because-no-CI. An empty roster makes no read at
/// all and is not degraded. A record returned for an id that was not asked for is inert
/// (`attach_device_ci` only looks rows up). `rows` stays the UNFILTERED roster; confinement is
/// downstream.
void apply_ci_read(InventoryDevicesResult& result, const CiKeyedReadFn& read);

} // namespace yuzu::server
