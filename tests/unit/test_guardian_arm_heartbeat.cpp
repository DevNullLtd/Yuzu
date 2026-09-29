/**
 * test_guardian_arm_heartbeat.cpp -- the writer side of the rung 9c PR-3
 * arm-ledger + io-ceiling fleet telemetry: the emission posture (dormancy is
 * nullopt, a live snapshot emits including a genuine zero; the ceiling counter
 * is a plain sparse counter) + the exact key names.
 */

#include "guardian_arm_heartbeat.hpp"
#include "guardian_io_ceiling_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <optional>
#include <string>

using namespace yuzu::agent;

TEST_CASE("arm heartbeat: dormant (nullopt) emits NO tags",
          "[guardian][arm][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_arm_heartbeat_tags(tags, std::nullopt);
    CHECK(tags.empty());
}

TEST_CASE("arm heartbeat: a live snapshot at genuine zero emits BOTH keys at \"0\", "
          "not absent",
          "[guardian][arm][heartbeat]") {
    // The whole point of the age-gauge pattern this mirrors: a rule genuinely at
    // zero pending/failed must read as "checked, healthy", not "dormant" - an
    // omitted tag would read as dormant to a fleet-level consumer.
    std::map<std::string, std::string> tags;
    emit_guardian_arm_heartbeat_tags(tags, std::optional<GuardianArmStats>{GuardianArmStats{}});
    REQUIRE(tags.size() == 2);
    CHECK(tags.at("yuzu.guardian_arm_pending") == "0");
    CHECK(tags.at("yuzu.guardian_arm_failed") == "0");
}

TEST_CASE("arm heartbeat: distinct nonzero values land on the right key each "
          "(no field swap)",
          "[guardian][arm][heartbeat]") {
    std::map<std::string, std::string> tags;
    GuardianArmStats s;
    s.pending = 3;
    s.failed = 7;
    emit_guardian_arm_heartbeat_tags(tags, std::optional{s});
    REQUIRE(tags.size() == 2);
    CHECK(tags.at("yuzu.guardian_arm_pending") == "3");
    CHECK(tags.at("yuzu.guardian_arm_failed") == "7");
}

TEST_CASE("arm heartbeat: unrelated tags already on the map survive",
          "[guardian][arm][heartbeat]") {
    std::map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    GuardianArmStats s{.pending = 1, .failed = 0};
    emit_guardian_arm_heartbeat_tags(tags, std::optional{s});
    CHECK(tags.at("yuzu.os") == "linux");
    CHECK(tags.at("yuzu.guardian_arm_pending") == "1");
    CHECK(tags.at("yuzu.guardian_arm_failed") == "0");
}

// ── io-ceiling counter (Decision 3, Option B) - the ordinary sparse-counter shape ──

TEST_CASE("io ceiling heartbeat: a zero count emits NO tag (sparse)",
          "[guardian][io][ceiling][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_io_ceiling_heartbeat_tags(tags, 0);
    CHECK(tags.empty());
}

TEST_CASE("io ceiling heartbeat: a nonzero count emits the pinned key",
          "[guardian][io][ceiling][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_io_ceiling_heartbeat_tags(tags, 5);
    REQUIRE(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_io_arm_disarm_rejected_ceiling") == "5");
}
