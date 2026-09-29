/**
 * test_guardian_backend_heartbeat.cpp -- yuzu.guardian_backend (F7, #2298 rung 2):
 * which detection backend a Guardian rule is actually enforced by, derived from
 * (prefer_spark, spark_availability). The full 2x4 combination matrix, not just a
 * few representative ones - the derivation is a compile-time-exhaustive switch, but
 * its VALUES still need runtime pinning against drift.
 */

#include "guardian_backend.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::agent;
using SA = GuardianEngine::SparkAvailability;

TEST_CASE("guardian_backend_from_state: prefer_spark=false is always Legacy, "
          "regardless of availability",
          "[guardian][backend][heartbeat]") {
    CHECK(guardian_backend_from_state(false, SA::Available) == GuardianBackend::Legacy);
    CHECK(guardian_backend_from_state(false, SA::SparkDisabled) == GuardianBackend::Legacy);
    CHECK(guardian_backend_from_state(false, SA::SparkFailed) == GuardianBackend::Legacy);
    CHECK(guardian_backend_from_state(false, SA::Unwired) == GuardianBackend::Legacy);
}

TEST_CASE("guardian_backend_from_state: prefer_spark=true distinguishes all four "
          "availability states",
          "[guardian][backend][heartbeat]") {
    CHECK(guardian_backend_from_state(true, SA::Available) == GuardianBackend::Spark);
    CHECK(guardian_backend_from_state(true, SA::SparkDisabled) == GuardianBackend::Legacy);
    CHECK(guardian_backend_from_state(true, SA::SparkFailed) == GuardianBackend::SparkFailed);
    CHECK(guardian_backend_from_state(true, SA::Unwired) == GuardianBackend::Unwired);
}

TEST_CASE("guardian_backend_label: pinned string values", "[guardian][backend][heartbeat]") {
    CHECK(std::string(guardian_backend_label(GuardianBackend::Legacy)) == "legacy");
    CHECK(std::string(guardian_backend_label(GuardianBackend::Spark)) == "spark");
    CHECK(std::string(guardian_backend_label(GuardianBackend::Unwired)) == "unwired");
    CHECK(std::string(guardian_backend_label(GuardianBackend::SparkFailed)) == "spark_failed");
}

TEST_CASE("emit_guardian_backend_heartbeat_tag: always present, never sparse",
          "[guardian][backend][heartbeat]") {
    // Legacy is the "zero-looking" value (matches most other fleet-wide defaults), but
    // this tag is categorical, not a counter - it must still be emitted, unlike the
    // sparse counter families elsewhere in this file group.
    std::map<std::string, std::string> tags;
    emit_guardian_backend_heartbeat_tag(tags, /*prefer_spark=*/false, SA::Available);
    REQUIRE(tags.count(kGuardianBackendTag) == 1);
    CHECK(tags.at(kGuardianBackendTag) == "legacy");
}

TEST_CASE("emit_guardian_backend_heartbeat_tag: the pinned key + all four "
          "prefer_spark=true values",
          "[guardian][backend][heartbeat]") {
    struct Case {
        SA availability;
        const char* expected;
    };
    for (const auto& c : {Case{SA::Available, "spark"}, Case{SA::SparkDisabled, "legacy"},
                          Case{SA::SparkFailed, "spark_failed"}, Case{SA::Unwired, "unwired"}}) {
        std::map<std::string, std::string> tags; // fresh map per case
        emit_guardian_backend_heartbeat_tag(tags, /*prefer_spark=*/true, c.availability);
        REQUIRE(tags.count("yuzu.guardian_backend") == 1);
        CHECK(tags.at("yuzu.guardian_backend") == c.expected);
    }
}
