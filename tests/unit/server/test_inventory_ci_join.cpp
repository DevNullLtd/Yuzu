/// @file test_inventory_ci_join.cpp
/// Confined-operator regression for the device-CI list-enrichment join (PR2):
/// `attach_device_ci` must NEVER attach (or otherwise surface) a CI record for an
/// agent that isn't already present in the caller's visibility-filtered `rows` —
/// proving the map can safely hold out-of-scope entries (from the same
/// keyed read) without leaking them past the roster's confinement
/// (the confinement itself is HardwareRoutes' `scoped_roster`, downstream
/// of this function — see inventory_ci_join.hpp).

#include "inventory_ci_join.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
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

// The list search (H.7) reads these three off the row; the join is the only place they are filled.
TEST_CASE("attach_device_ci: carries the v2 identifiers the Hardware list search reads",
          "[inventory][ci-join]") {
    std::vector<InventoryDeviceRow> rows(1);
    rows[0].agent_id = "a1";
    auto ci = make_ci("a1", "SN-1");
    ci.chassis_asset_tag = "AT-7";
    ci.chassis_serial = "CHS-7";
    ci.board_serial = "BRD-7";
    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent;
    ci_by_agent.emplace("a1", ci);

    attach_device_ci(rows, ci_by_agent);

    CHECK(rows[0].ci_chassis_asset_tag == "AT-7");
    CHECK(rows[0].ci_chassis_serial == "CHS-7");
    CHECK(rows[0].ci_board_serial == "BRD-7");
}

TEST_CASE("attach_device_ci: out-of-scope CI in the map is never attached or manufactured",
          "[inventory][ci-join]") {
    // `rows` holds only "a1" (as if the roster never contained "a2"); confinement is
    // HardwareRoutes' scoped_roster, downstream of this function.
    std::vector<InventoryDeviceRow> rows(1);
    rows[0].agent_id = "a1";

    // `ci_by_agent` covers BOTH the visible agent and an out-of-scope one — exactly
    // what a keyed read can return (the store has no visibility concept).
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

namespace {

InventoryDevicesResult roster_of(std::initializer_list<const char*> ids) {
    InventoryDevicesResult result;
    for (const char* id : ids) {
        InventoryDeviceRow r;
        r.agent_id = id;
        result.rows.push_back(std::move(r));
    }
    return result;
}

} // namespace

TEST_CASE("apply_ci_read: asks for exactly the roster's ids and attaches what comes back",
          "[inventory][ci-join][keyed]") {
    auto result = roster_of({"a1", "a2", "a3"});
    std::vector<std::string> asked;
    int calls = 0;
    apply_ci_read(result, [&](const std::vector<std::string>& ids) {
        ++calls;
        asked = ids;
        // a2 has no CI yet; "stranger" was never asked for and must stay inert.
        return std::optional<std::vector<DeviceCiRecord>>{
            std::vector<DeviceCiRecord>{make_ci("a1", "SN-1"), make_ci("a3", "SN-3"),
                                        make_ci("stranger", "SN-X")}};
    });
    CHECK(calls == 1);
    CHECK(asked == std::vector<std::string>{"a1", "a2", "a3"}); // the roster, in roster order
    CHECK_FALSE(result.ci_degraded);
    REQUIRE(result.rows.size() == 3); // no row is ever manufactured for "stranger"
    CHECK(result.rows[0].ci_serial == "SN-1");
    CHECK(result.rows[1].ci_serial.empty()); // not synced: blank, and NOT degraded
    CHECK(result.rows[2].ci_serial == "SN-3");
}

TEST_CASE("apply_ci_read: a failed read is ci_degraded with every CI field blank, never a partial join",
          "[inventory][ci-join][keyed]") {
    auto result = roster_of({"a1", "a2"});
    apply_ci_read(result, [](const std::vector<std::string>&) {
        return std::optional<std::vector<DeviceCiRecord>>{}; // nullopt = the store degraded
    });
    CHECK(result.ci_degraded);
    for (const auto& row : result.rows)
        CHECK(row.ci_serial.empty());
}

TEST_CASE("apply_ci_read: an unwired reader is degraded, like a failed one", "[inventory][ci-join][keyed]") {
    auto result = roster_of({"a1"});
    apply_ci_read(result, CiKeyedReadFn{});
    CHECK(result.ci_degraded);
}

TEST_CASE("apply_ci_read: an empty roster makes no read and is not degraded", "[inventory][ci-join][keyed]") {
    InventoryDevicesResult result;
    int calls = 0;
    apply_ci_read(result, [&](const std::vector<std::string>&) {
        ++calls;
        return std::optional<std::vector<DeviceCiRecord>>{std::vector<DeviceCiRecord>{}};
    });
    CHECK(calls == 0);
    CHECK_FALSE(result.ci_degraded);
}

TEST_CASE("apply_ci_read: an unwired reader is degraded even when the roster is empty",
          "[inventory][ci-join][keyed]") {
    // The unwired check comes BEFORE the empty-roster early return (an unwired store must never
    // read as "healthy, nothing to enrich"); a wired reader on an empty roster is the case above.
    InventoryDevicesResult result;
    apply_ci_read(result, CiKeyedReadFn{});
    CHECK(result.ci_degraded);
}
