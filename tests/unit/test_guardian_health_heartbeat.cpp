/**
 * test_guardian_health_heartbeat.cpp -- the writer side of the Guardian health-stream fleet
 * telemetry (M1): the sparse-emit rule + the exact PINNED key name. A one-character drift here
 * would silently produce a zero fleet gauge at the #2298 server-side rollup, so this test locks
 * the wire key.
 */

#include "guardian_health_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::agent;

TEST_CASE("health heartbeat: all-zero stats emits NO tags (sparse / inert agent)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{});
    CHECK(tags.empty()); // nothing to report (also the prefer_spark=false case)
}

TEST_CASE("health heartbeat: non-zero suppression emits the pinned key + value",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.unhealthy_suppressed = 42});
    CHECK(tags.size() == 1);
    // Pinned wire key - the #2298 rollup reader MUST match this exact string.
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "42");
    CHECK(std::string(kGuardianUnhealthySuppressedTag) == "yuzu.guardian_unhealthy_suppressed");
}

TEST_CASE("health heartbeat: non-zero refresh emits the pinned key + value (F5 6b)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.unhealthy_refreshed = 7});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_unhealthy_refreshed") == "7");
    CHECK(std::string(kGuardianUnhealthyRefreshedTag) == "yuzu.guardian_unhealthy_refreshed");
}

TEST_CASE("health heartbeat: non-zero demotion emits the pinned key + value (F5 6c)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.priority_demoted = 3});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_priority_demoted") == "3");
    CHECK(std::string(kGuardianPriorityDemotedTag) == "yuzu.guardian_priority_demoted");
}

TEST_CASE("health heartbeat: non-zero outbox backpressure drops emits the pinned key + "
          "value (#2993)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.outbox_backpressure_drops = 11});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_outbox_backpressure_drops") == "11");
    CHECK(std::string(kGuardianOutboxBackpressureDropsTag) ==
          "yuzu.guardian_outbox_backpressure_drops");
}

TEST_CASE("health heartbeat: non-zero legacy-sink events-lost emits the pinned key + "
          "value (#4783)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags,
                                        GuardianHealthStats{.legacy_sink_events_lost = 9});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_legacy_sink_events_lost") == "9");
    CHECK(std::string(kGuardianLegacySinkEventsLostTag) ==
          "yuzu.guardian_legacy_sink_events_lost");
}

TEST_CASE("health heartbeat: non-zero legacy-sink gap-rules emits the pinned key + "
          "value (#4783)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.legacy_sink_gap_rules = 5});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_legacy_sink_gap_rules") == "5");
    CHECK(std::string(kGuardianLegacySinkGapRulesTag) == "yuzu.guardian_legacy_sink_gap_rules");
}

TEST_CASE("health heartbeat: non-zero legacy-sink dropped-unwired emits the pinned key + "
          "value (#4783 governance follow-up)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags,
                                        GuardianHealthStats{.legacy_sink_dropped_unwired = 8});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_legacy_sink_dropped_unwired") == "8");
    CHECK(std::string(kGuardianLegacySinkDroppedUnwiredTag) ==
          "yuzu.guardian_legacy_sink_dropped_unwired");
}

TEST_CASE("health heartbeat: zero legacy-sink dropped-unwired omits the tag (sparse)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags,
                                        GuardianHealthStats{.legacy_sink_dropped_unwired = 0});
    CHECK(tags.empty());
}

TEST_CASE("health heartbeat: all seven counters independent and additive",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(
        tags, GuardianHealthStats{.unhealthy_suppressed = 1, .unhealthy_refreshed = 2,
                                  .priority_demoted = 3, .outbox_backpressure_drops = 4,
                                  .legacy_sink_events_lost = 5, .legacy_sink_gap_rules = 6,
                                  .legacy_sink_dropped_unwired = 7});
    CHECK(tags.size() == 7);
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "1");
    CHECK(tags.at("yuzu.guardian_unhealthy_refreshed") == "2");
    CHECK(tags.at("yuzu.guardian_priority_demoted") == "3");
    CHECK(tags.at("yuzu.guardian_outbox_backpressure_drops") == "4");
    CHECK(tags.at("yuzu.guardian_legacy_sink_events_lost") == "5");
    CHECK(tags.at("yuzu.guardian_legacy_sink_gap_rules") == "6");
    CHECK(tags.at("yuzu.guardian_legacy_sink_dropped_unwired") == "7");
}
