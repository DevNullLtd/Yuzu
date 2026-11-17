/**
 * test_guardian_baseline_heartbeat.cpp -- the writer side of the #5605 baseline-persistence
 * fleet signal: the emission posture of the two new emitters in guardian_baseline_heartbeat.hpp
 * (the CURRENT unpersisted backlog, optional-gated like the arm pair: dormant is nullopt and
 * emits nothing, a present 0 emits "0"; the boot-scan count is sparse: 0 omits) plus the exact
 * key names, which the server reader pins against its own table in the same change
 * (test_guardian_baseline_fleet_tags.cpp).
 */

#include "guardian_baseline_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>

using namespace yuzu::agent;

TEST_CASE("baseline heartbeat: the unpersisted tag is dormant on nullopt and present at zero",
          "[guardian][baseline][heartbeat][5605]") {
    std::map<std::string, std::string> tags;
    emit_guardian_baseline_unpersisted_heartbeat_tag(tags, std::nullopt);
    CHECK(tags.empty()); // dormant: no tag, never a fabricated 0

    emit_guardian_baseline_unpersisted_heartbeat_tag(tags, std::optional<std::uint64_t>{0});
    REQUIRE(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_baseline_unpersisted") == "0"); // live and nothing waiting

    tags.clear();
    emit_guardian_baseline_unpersisted_heartbeat_tag(tags, std::optional<std::uint64_t>{7});
    REQUIRE(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_baseline_unpersisted") == "7");
}

TEST_CASE("baseline heartbeat: the boot-scan tag is sparse (0 omits)",
          "[guardian][baseline][heartbeat][5605]") {
    std::map<std::string, std::string> tags;
    emit_guardian_baseline_rebaselined_heartbeat_tag(tags, 0);
    CHECK(tags.empty());

    emit_guardian_baseline_rebaselined_heartbeat_tag(tags, 3);
    REQUIRE(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_baseline_rebaselined_at_boot") == "3");
}

TEST_CASE("baseline heartbeat: the three baseline emitters write three distinct keys and the "
          "key names are exact",
          "[guardian][baseline][heartbeat][5605]") {
    std::map<std::string, std::string> tags;
    emit_guardian_baseline_unpersisted_heartbeat_tag(tags, std::optional<std::uint64_t>{5});
    emit_guardian_baseline_rebaselined_heartbeat_tag(tags, 7);
    emit_guardian_baseline_persist_heartbeat_tags(tags, 11);
    REQUIRE(tags.size() == 3);
    CHECK(tags.at("yuzu.guardian_baseline_unpersisted") == "5");
    CHECK(tags.at("yuzu.guardian_baseline_rebaselined_at_boot") == "7");
    CHECK(tags.at("yuzu.guardian_baseline_persist_failures") == "11");

    CHECK(std::string{kGuardianBaselineUnpersistedTag} == "yuzu.guardian_baseline_unpersisted");
    CHECK(std::string{kGuardianBaselineRebaselinedAtBootTag} ==
          "yuzu.guardian_baseline_rebaselined_at_boot");
    CHECK(std::string{kGuardianBaselinePersistFailuresTag} ==
          "yuzu.guardian_baseline_persist_failures");
}
