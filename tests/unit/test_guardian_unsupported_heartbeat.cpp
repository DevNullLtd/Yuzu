/**
 * test_guardian_unsupported_heartbeat.cpp -- the writer side of the per-type
 * mech_unsupported_total fleet gauge (F7, #2298 rung 2). A CURRENT gauge, not a
 * cumulative counter - the sparse-emit rule + the exact PINNED key format (a
 * one-character drift here would silently produce a zero fleet gauge at the
 * server-side rollup, same class of risk as guardian_health_heartbeat.hpp's own
 * pin test).
 */

#include "guardian_unsupported_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::agent;

TEST_CASE("unsupported heartbeat: empty counts emits NO tags",
          "[guardian][unsupported][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_unsupported_heartbeat_tags(tags, {});
    CHECK(tags.empty());
}

TEST_CASE("unsupported heartbeat: a zero-count entry is still omitted (sparse, "
          "belt-and-braces)",
          "[guardian][unsupported][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_unsupported_heartbeat_tags(tags, {{SparkType::File, 0}});
    CHECK(tags.empty());
}

TEST_CASE("unsupported heartbeat: the pinned per-type key format",
          "[guardian][unsupported][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_unsupported_heartbeat_tags(
        tags, {{SparkType::File, 1}, {SparkType::Registry, 2}, {SparkType::Service, 3}});
    REQUIRE(tags.size() == 3);
    CHECK(tags.at("yuzu.spark_file_unsupported") == "1");
    CHECK(tags.at("yuzu.spark_registry_unsupported") == "2");
    CHECK(tags.at("yuzu.spark_service_unsupported") == "3");
}

TEST_CASE("unsupported heartbeat: a 2 -> 1 -> 0 shrink sequence, one fresh map per "
          "simulated heartbeat",
          "[guardian][unsupported][heartbeat]") {
    // This emitter APPENDS into the supplied map, it does not clear stale keys -
    // production always constructs a fresh status_tags map per heartbeat cycle, so
    // simulating a shrinking count needs a fresh map per call too, not one reused
    // map (which would keep a key this function never re-wrote and falsely look
    // like the count never dropped).
    {
        std::map<std::string, std::string> tags;
        emit_guardian_unsupported_heartbeat_tags(tags, {{SparkType::File, 2}});
        REQUIRE(tags.count("yuzu.spark_file_unsupported") == 1);
        CHECK(tags.at("yuzu.spark_file_unsupported") == "2");
    }
    {
        std::map<std::string, std::string> tags;
        emit_guardian_unsupported_heartbeat_tags(tags, {{SparkType::File, 1}});
        CHECK(tags.at("yuzu.spark_file_unsupported") == "1");
    }
    {
        std::map<std::string, std::string> tags;
        emit_guardian_unsupported_heartbeat_tags(tags, {{SparkType::File, 0}});
        CHECK(tags.count("yuzu.spark_file_unsupported") == 0); // absent, not "0"
    }
}
