/**
 * test_echo_software.cpp -- Unit tests for the `software` source's pure
 * orchestration core (echo_software_core) and its numeric version comparator
 * (echo_version). The Windows registry enumeration in echo_software_collector.cpp
 * is platform-gated and exercised by the Windows smoke; everything that decides
 * WHAT gets emitted — cold-start seeding, corrupt-state skip, machine-only diff,
 * and version ordering — is pure and tested here so it runs on every platform.
 * The source is machine scope only (HKLM Uninstall), so there is no per-user
 * carry-forward to test (#1620).
 */

#include "echo_software_core.hpp"
#include "echo_version.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::echo;

namespace {
SoftwareInfo sw(std::string name, std::string version) {
    SoftwareInfo s;
    s.name = std::move(name);
    s.version = std::move(version);
    s.publisher = "Acme";
    s.install_date = "20260101";
    return s;
}
} // namespace

// =============================================================================
// Numeric version comparator (echo_version.hpp) — the dedup() ordering key
// =============================================================================

TEST_CASE("compare_versions: numeric segments, not lexicographic", "[echo][software][version]") {
    // The exact #1620 bug: a std::string `operator>` makes "9.0" > "10.0".
    CHECK(compare_versions("10.0", "9.0") > 0);
    CHECK(compare_versions("9.0", "10.0") < 0);
    CHECK(compare_versions("1.2.10", "1.2.9") > 0);
    CHECK(compare_versions("23.01", "24.00") < 0);
    CHECK(compare_versions("2.0.0", "2.0.0") == 0);
}

TEST_CASE("compare_versions: differing segment counts treat missing as zero",
          "[echo][software][version]") {
    CHECK(compare_versions("1.0", "1.0.0") == 0);
    CHECK(compare_versions("1.2", "1.2.0.1") < 0);
}

TEST_CASE("compare_versions: non-numeric segment falls back to lexicographic",
          "[echo][software][version]") {
    CHECK(compare_versions("1.9.5p2", "1.9.5p3") < 0);
    CHECK(compare_versions("", "") == 0);
    CHECK(compare_versions("1", "") > 0);
}

// =============================================================================
// State (de)serialisation round-trip
// =============================================================================

TEST_CASE("software_state_to_json round-trips through software_state_from_json",
          "[echo][software][serde]") {
    std::vector<SoftwareInfo> apps = {sw("7-Zip", "23.01"), sw("Slack", "4.0")};
    auto restored = software_state_from_json(software_state_to_json(apps));
    REQUIRE(restored.size() == 2);
    CHECK(restored[0].name == "7-Zip");
    CHECK(restored[0].version == "23.01");
    CHECK(restored[0].publisher == "Acme");
    CHECK(restored[1].name == "Slack");
    CHECK(restored[1].version == "4.0");
}

TEST_CASE("software_state_from_json tolerates blank / non-array / garbage",
          "[echo][software][serde]") {
    CHECK(software_state_from_json("").empty());
    CHECK(software_state_from_json("not json at all").empty());
    CHECK(software_state_from_json("{}").empty());       // object, not array
    CHECK(software_state_from_json("[1, 2, 3]").empty()); // array of non-objects
}

// =============================================================================
// software_collect_core — cold-start / corrupt / steady classification
// =============================================================================

TEST_CASE("software_collect_core: cold start seeds the baseline and emits no events",
          "[echo][software][orchestration]") {
    std::vector<SoftwareInfo> enumerated = {sw("7-Zip", "23.01"), sw("Chrome", "120")};
    auto r = software_collect_core("", enumerated, 1000, 1);

    REQUIRE(r.kind == SoftwareCollectResult::Kind::kColdStartSeed);
    CHECK(r.events.empty());
    // The seeded state is exactly what was enumerated.
    auto restored = software_state_from_json(r.new_state_json);
    REQUIRE(restored.size() == 2);
}

TEST_CASE("software_collect_core: corrupt prior state skips and preserves the baseline",
          "[echo][software][orchestration]") {
    // Non-array JSON and outright garbage both classify as corrupt — NOT cold-start
    // (would lose the baseline) and NOT a diff-against-empty (would storm).
    for (const char* bad : {"{\"oops\":true}", "not json", "42"}) {
        auto r = software_collect_core(bad, {sw("X", "1")}, 2000, 2);
        CHECK(r.kind == SoftwareCollectResult::Kind::kCorruptSkip);
        CHECK(r.events.empty());
        CHECK(r.new_state_json.empty()); // caller leaves the on-disk baseline untouched
    }
}

TEST_CASE("software_collect_core: steady detects install + remove",
          "[echo][software][orchestration]") {
    auto prev_json = software_state_to_json({sw("7-Zip", "23.01")});
    // 7-Zip removed, Chrome installed.
    std::vector<SoftwareInfo> enumerated = {sw("Chrome", "120")};

    auto r = software_collect_core(prev_json, enumerated, 3000, 3);

    REQUIRE(r.kind == SoftwareCollectResult::Kind::kSteady);
    REQUIRE(r.events.size() == 2);
    bool saw_install = false, saw_remove = false;
    for (const auto& e : r.events) {
        if (e.action == "installed" && e.name == "Chrome")
            saw_install = true;
        if (e.action == "removed" && e.name == "7-Zip")
            saw_remove = true;
    }
    CHECK(saw_install);
    CHECK(saw_remove);
    // New state is exactly the enumeration.
    auto restored = software_state_from_json(r.new_state_json);
    REQUIRE(restored.size() == 1);
    CHECK(restored[0].name == "Chrome");
}

TEST_CASE("software_collect_core: steady upgrade is one event",
          "[echo][software][orchestration]") {
    auto prev_json = software_state_to_json({sw("7-Zip", "23.01")});
    auto r = software_collect_core(prev_json, {sw("7-Zip", "24.00")}, 4000, 4);
    REQUIRE(r.kind == SoftwareCollectResult::Kind::kSteady);
    REQUIRE(r.events.size() == 1);
    CHECK(r.events[0].action == "upgraded");
    CHECK(r.events[0].version == "24.00");
    CHECK(r.events[0].prev_version == "23.01");
}
