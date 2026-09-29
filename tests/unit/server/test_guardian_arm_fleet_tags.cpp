/**
 * test_guardian_arm_fleet_tags.cpp - rung 9c PR-3 arm-ledger + io-ceiling
 * fleet-telemetry contract. Mirrors test_guardian_journal_fleet_tags.cpp's own
 * binding idiom exactly (see that file's header comment for the full
 * rationale) - the STRUCTURAL pin, the WRITER -> READER key check, the
 * READER -> WRITER key check, and the FIELD -> KEY value bind, all against the
 * agent's REAL emitters.
 */
#include "guardian_arm_fleet_tags.hpp"
#include "guardian_io_ceiling_fleet_tags.hpp"

#include "guardian_arm_heartbeat.hpp"     // agent emitter - the writer side of the arm bind
#include "guardian_io_ceiling_heartbeat.hpp" // agent emitter - the writer side of the ceiling bind

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <type_traits>

namespace detail = yuzu::server::detail;
using yuzu::agent::emit_guardian_arm_heartbeat_tags;
using yuzu::agent::emit_guardian_io_ceiling_heartbeat_tags;
using yuzu::agent::GuardianArmStats;

// STRUCTURAL PIN (same idiom as test_guardian_journal_fleet_tags.cpp): GuardianArmStats
// is an aggregate of std::uint64_t only, so sizeof/8 IS its field count. Pinning that to
// the table row count turns "added an arm-ledger field but forgot its fleet gauge" into
// a build break.
static_assert(sizeof(GuardianArmStats) == detail::kNGuardianArmMetrics * sizeof(std::uint64_t),
              "GuardianArmStats field count != kGuardianArmMetrics row count - a field was "
              "added or removed without its fleet gauge. Add/remove the matching row in "
              "server/core/src/guardian_arm_fleet_tags.hpp.");
static_assert(std::has_unique_object_representations_v<GuardianArmStats>,
              "GuardianArmStats gained padding - sizeof/8 is no longer its field count, so "
              "the size pin above silently stops counting fields.");

TEST_CASE("guardian arm: agent emit keys bind exactly to the server table",
          "[guardian][arm][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianArmMetrics)
        table_keys.insert(m.tag);
    REQUIRE(table_keys.size() == detail::kNGuardianArmMetrics);

    std::map<std::string, std::string> tags;
    GuardianArmStats s{.pending = 3, .failed = 7}; // distinct values - catches a field swap
    emit_guardian_arm_heartbeat_tags(tags, std::optional{s});

    // WRITER -> READER: nothing the agent emits may be unknown to the rollup.
    for (const auto& [key, val] : tags) {
        INFO("emitted key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }

    // FIELD -> KEY BIND: a swapped emitter value (pending's value under failed's key)
    // would leave the key SET unchanged but sum the wrong counter under the wrong gauge -
    // this catches that, the key-set checks alone cannot.
    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_arm_pending", "3"},
        {"yuzu.guardian_arm_failed", "7"},
    };
    CHECK(tags == expected);

    // READER -> WRITER: every table row must correspond to something the writer can
    // actually emit - a typo in the table looks exactly like a healthy fleet otherwise.
    for (const auto& m : detail::kGuardianArmMetrics) {
        INFO("table row never emitted by the writer: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }
}

TEST_CASE("guardian arm: dormancy (nullopt) binds to nothing - the table recognises "
          "an empty emission too",
          "[guardian][arm][fleet]") {
    std::map<std::string, std::string> tags;
    emit_guardian_arm_heartbeat_tags(tags, std::nullopt);
    CHECK(tags.empty());
}

TEST_CASE("guardian arm: gauge name rule holds for every row (yuzu_fleet_ + tag "
          "minus its yuzu. prefix)",
          "[guardian][arm][fleet]") {
    for (const auto& m : detail::kGuardianArmMetrics) {
        std::string tag(m.tag);
        REQUIRE(tag.rfind("yuzu.", 0) == 0);
        const std::string expected_gauge = "yuzu_fleet_" + tag.substr(std::string("yuzu.").size());
        CHECK(expected_gauge == m.gauge);
    }
}

TEST_CASE("guardian arm: parse_guardian_arm_count rejects garbage, negative, "
          "oversized and implausible values; accepts a plausible plain integer",
          "[guardian][arm][fleet]") {
    CHECK(detail::parse_guardian_arm_count("0") == 0.0);
    CHECK(detail::parse_guardian_arm_count("42") == 42.0);
    CHECK_FALSE(detail::parse_guardian_arm_count("").has_value());
    CHECK_FALSE(detail::parse_guardian_arm_count("-1").has_value());
    CHECK_FALSE(detail::parse_guardian_arm_count("abc").has_value());
    CHECK_FALSE(detail::parse_guardian_arm_count("12abc").has_value());
    CHECK_FALSE(detail::parse_guardian_arm_count("99999999").has_value()); // > ceiling
}

// ── io-ceiling counter (Decision 3, Option B) ──────────────────────────────────────

TEST_CASE("guardian io ceiling: agent emit key binds exactly to the server table",
          "[guardian][io][ceiling][fleet]") {
    REQUIRE(detail::kNGuardianIoCeilingMetrics == 1);

    std::map<std::string, std::string> tags;
    emit_guardian_io_ceiling_heartbeat_tags(tags, 5);
    REQUIRE(tags.size() == 1);
    CHECK(tags.count(detail::kGuardianIoCeilingMetrics[0].tag) == 1);
    CHECK(tags.at(detail::kGuardianIoCeilingMetrics[0].tag) == "5");
}

TEST_CASE("guardian io ceiling: a zero count binds to nothing (sparse writer)",
          "[guardian][io][ceiling][fleet]") {
    std::map<std::string, std::string> tags;
    emit_guardian_io_ceiling_heartbeat_tags(tags, 0);
    CHECK(tags.empty());
}

TEST_CASE("guardian io ceiling: parse_guardian_io_ceiling_count rejects garbage, "
          "negative, oversized and implausible values",
          "[guardian][io][ceiling][fleet]") {
    CHECK(detail::parse_guardian_io_ceiling_count("0") == 0.0);
    CHECK(detail::parse_guardian_io_ceiling_count("5") == 5.0);
    CHECK_FALSE(detail::parse_guardian_io_ceiling_count("").has_value());
    CHECK_FALSE(detail::parse_guardian_io_ceiling_count("-1").has_value());
    CHECK_FALSE(detail::parse_guardian_io_ceiling_count("abc").has_value());
    // 11 digits - too long for kMaxIoCeilingTokenDigits regardless of value.
    CHECK_FALSE(detail::parse_guardian_io_ceiling_count("99999999999").has_value());
}

TEST_CASE("guardian io ceiling: plausibility bound matches the sibling cumulative "
          "parsers (1e9/10-digit), governance fix CODEX-2/K4 - the original 1e6 "
          "bound was 1000x tighter than the sibling counters with no documented "
          "reason, dropping a genuinely wedged endpoint's honest count from the "
          "fleet sum exactly while the fault persisted",
          "[guardian][io][ceiling][fleet]") {
    static_assert(detail::kMaxPlausibleGuardianIoCeilingCount == 1'000'000'000ULL);
    static_assert(detail::kMaxIoCeilingTokenDigits == 10);
    // Exactly at the bound: fits the digit gate AND the plausibility check - accepted.
    CHECK(detail::parse_guardian_io_ceiling_count("1000000000") == 1'000'000'000.0);
    // One past the bound, same digit length - the plausibility check alone rejects it.
    CHECK_FALSE(detail::parse_guardian_io_ceiling_count("1000000001").has_value());
}
