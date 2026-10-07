/// @file test_inventory_ci_join.cpp
/// Confined-operator regression for the device-CI list-enrichment join (PR2):
/// `attach_device_ci` must NEVER attach (or otherwise surface) a CI record for an
/// agent that isn't already present in the caller's visibility-filtered `rows` —
/// proving the map can safely hold out-of-scope entries (from the same
/// `list_device_ci(0)` read) without leaking them past the roster's confinement
/// (the confinement itself is HardwareRoutes' `scoped_roster`, downstream
/// of this function — see inventory_ci_join.hpp).

#include "inventory_ci_join.hpp"

#include <catch2/catch_test_macros.hpp>

#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

DeviceCiRecord make_ci(std::string agent_id, std::string serial) {
    DeviceCiRecord r;
    r.agent_id = std::move(agent_id);
    r.serial = std::move(serial);
    return r;
}

} // namespace

TEST_CASE("attach_device_ci: fills a visible row's CI fields", "[inventory][ci-join]") {
    std::vector<InventoryDeviceRow> rows(1);
    rows[0].agent_id = "a1";

    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent;
    ci_by_agent.emplace("a1", make_ci("a1", "SN-1"));

    attach_device_ci(rows, ci_by_agent);

    REQUIRE(rows[0].ci_serial == "SN-1");
}

TEST_CASE("attach_device_ci: out-of-scope CI in the map is never attached or manufactured",
          "[inventory][ci-join]") {
    // `rows` holds only "a1" (as if the roster never contained "a2"); confinement is
    // HardwareRoutes' scoped_roster, downstream of this function.
    std::vector<InventoryDeviceRow> rows(1);
    rows[0].agent_id = "a1";

    // `ci_by_agent` covers BOTH the visible agent and an out-of-scope one — exactly
    // what one list_device_ci(0) read returns (the store has no visibility concept).
    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent;
    ci_by_agent.emplace("a1", make_ci("a1", "SN-VISIBLE"));
    ci_by_agent.emplace("a2", make_ci("a2", "SN-OUT-OF-SCOPE"));

    attach_device_ci(rows, ci_by_agent);

    // Only the pre-existing visible row is enriched — no new row is ever created for
    // the out-of-scope agent, and its CI never appears anywhere in the output.
    REQUIRE(rows.size() == 1);
    REQUIRE(rows[0].agent_id == "a1");
    REQUIRE(rows[0].ci_serial == "SN-VISIBLE");
    for (const auto& row : rows)
        REQUIRE(row.ci_serial != "SN-OUT-OF-SCOPE");
}

TEST_CASE("attach_device_ci: a row with no matching CI entry is left blank, not an error",
          "[inventory][ci-join]") {
    std::vector<InventoryDeviceRow> rows(1);
    rows[0].agent_id = "not-synced-yet";

    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent; // empty — no CI synced fleet-wide

    attach_device_ci(rows, ci_by_agent);

    REQUIRE(rows[0].ci_serial.empty());
    REQUIRE(rows[0].ci_model.empty());
}
