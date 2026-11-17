/**
 * test_guardian_baseline_fleet_tags.cpp - #5605 baseline-persistence fleet-telemetry
 * contract. Same binding idiom as test_guardian_arm_fleet_tags.cpp: the STRUCTURAL pin, the
 * WRITER -> READER key check, the READER -> WRITER key check and the FIELD -> KEY value bind,
 * all against the agent's REAL emitters (guardian_baseline_heartbeat.hpp), with distinct
 * non-zero values so a swapped value cannot hide behind equal numbers.
 */
#include "guardian_baseline_fleet_tags.hpp"

#include "guardian_baseline_heartbeat.hpp" // agent emitters - the writer side of the bind

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>

namespace detail = yuzu::server::detail;
namespace agent = yuzu::agent;

namespace {

// Drive all three REAL emitters into one map, the way agent.cpp's heartbeat does.
std::map<std::string, std::string> emit_all(std::optional<std::uint64_t> unpersisted,
                                            std::uint64_t rebaselined,
                                            std::uint64_t persist_failures) {
    std::map<std::string, std::string> tags;
    agent::emit_guardian_baseline_unpersisted_heartbeat_tag(tags, unpersisted);
    agent::emit_guardian_baseline_rebaselined_heartbeat_tag(tags, rebaselined);
    agent::emit_guardian_baseline_persist_heartbeat_tags(tags, persist_failures);
    return tags;
}

} // namespace

// T29: writer -> reader, field -> key, reader -> writer, through the real emitters.
TEST_CASE("guardian baseline: agent emit keys bind exactly to the server table",
          "[guardian][baseline][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianBaselineMetrics)
        table_keys.insert(m.tag);
    REQUIRE(table_keys.size() == detail::kNGuardianBaselineMetrics);

    // Distinct non-zero values (5 / 7 / 11): a value swapped between two keys leaves the key SET
    // unchanged, so only the exact map comparison below catches it.
    const auto tags = emit_all(std::optional<std::uint64_t>{5}, 7, 11);

    // WRITER -> READER: nothing the agent emits may be unknown to the rollup.
    for (const auto& [key, val] : tags) {
        INFO("emitted key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }

    // FIELD -> KEY: exact map equality.
    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_baseline_unpersisted", "5"},
        {"yuzu.guardian_baseline_rebaselined_at_boot", "7"},
        {"yuzu.guardian_baseline_persist_failures", "11"},
    };
    CHECK(tags == expected);

    // READER -> WRITER: every table row must be something the writer can emit.
    for (const auto& m : detail::kGuardianBaselineMetrics) {
        INFO("table row never emitted by the writer: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }

    // The table rows are bound to the writer's named constants, not re-typed literals.
    CHECK(std::string(detail::kGuardianBaselineMetrics[0].tag) ==
          agent::kGuardianBaselineUnpersistedTag);
    CHECK(std::string(detail::kGuardianBaselineMetrics[1].tag) ==
          agent::kGuardianBaselineRebaselinedAtBootTag);
    CHECK(std::string(detail::kGuardianBaselineMetrics[2].tag) ==
          agent::kGuardianBaselinePersistFailuresTag);
}

// T30: structural pins and the gauge-name rule.
TEST_CASE("guardian baseline: table shape, index-0 pin and gauge-name rule",
          "[guardian][baseline][fleet]") {
    static_assert(detail::kNGuardianBaselineMetrics == 3);
    static_assert(detail::kGuardianBaselineUnpersistedIndex == 0);
    CHECK(std::string(detail::kGuardianBaselineMetrics[detail::kGuardianBaselineUnpersistedIndex]
                          .tag) == agent::kGuardianBaselineUnpersistedTag);

    for (const auto& m : detail::kGuardianBaselineMetrics) {
        std::string tag(m.tag);
        REQUIRE(tag.rfind("yuzu.", 0) == 0);
        const std::string expected_gauge = "yuzu_fleet_" + tag.substr(std::string("yuzu.").size());
        CHECK(expected_gauge == m.gauge);
        CHECK(std::strlen(m.help) > 0);
    }
    CHECK(std::string(detail::kGuardianBaselineReportingGauge) ==
          "yuzu_fleet_guardian_baseline_reporting");
    CHECK(std::string(detail::kGuardianBaselineTagRejectedGauge) ==
          "yuzu_fleet_guardian_baseline_tag_rejected");
}

// T31: parser bounds.
TEST_CASE("guardian baseline: parse_guardian_baseline_count rejects garbage, negative, "
          "over-long and implausible values; accepts plain integers up to 1e9",
          "[guardian][baseline][fleet]") {
    static_assert(detail::kMaxPlausibleGuardianBaselineCount == 1'000'000'000ULL);
    static_assert(detail::kMaxBaselineTokenDigits == 10);
    CHECK(detail::parse_guardian_baseline_count("0") == 0.0);
    CHECK(detail::parse_guardian_baseline_count("42") == 42.0);
    CHECK(detail::parse_guardian_baseline_count("1000000000") == 1'000'000'000.0);
    CHECK_FALSE(detail::parse_guardian_baseline_count("").has_value());
    CHECK_FALSE(detail::parse_guardian_baseline_count("-1").has_value());
    CHECK_FALSE(detail::parse_guardian_baseline_count("+1").has_value());
    CHECK_FALSE(detail::parse_guardian_baseline_count("abc").has_value());
    CHECK_FALSE(detail::parse_guardian_baseline_count("12abc").has_value());
    CHECK_FALSE(detail::parse_guardian_baseline_count("1.5").has_value());
    // One past the bound at the same digit length: the plausibility check alone rejects it.
    CHECK_FALSE(detail::parse_guardian_baseline_count("1000000001").has_value());
    // 11 digits: the length gate rejects it before any parsing.
    CHECK_FALSE(detail::parse_guardian_baseline_count("99999999999").has_value());
}

// T32: dormancy and sparseness through the real emitters.
TEST_CASE("guardian baseline: dormant and zero inputs emit nothing; an explicit 0 backlog emits \"0\"",
          "[guardian][baseline][fleet]") {
    // Fully dormant: no optional value, no boot count, no cumulative failures -> empty map.
    CHECK(emit_all(std::nullopt, 0, 0).empty());

    // A legacy agent (prefer_spark off) that carries only the cumulative counter: exactly that
    // one key, and the reader's reporting denominator must not see row 0.
    const auto legacy = emit_all(std::nullopt, 0, 5);
    const std::map<std::string, std::string> expected_legacy{
        {"yuzu.guardian_baseline_persist_failures", "5"}};
    CHECK(legacy == expected_legacy);
    CHECK(legacy.count(detail::kGuardianBaselineMetrics[detail::kGuardianBaselineUnpersistedIndex]
                           .tag) == 0);

    // A live Spark agent with nothing waiting: the present 0 IS emitted ("checked, nothing
    // waiting" reads differently from dormant), while the sparse tags stay omitted.
    const auto clean = emit_all(std::optional<std::uint64_t>{0}, 0, 0);
    const std::map<std::string, std::string> expected_clean{
        {"yuzu.guardian_baseline_unpersisted", "0"}};
    CHECK(clean == expected_clean);
    CHECK(detail::parse_guardian_baseline_count(clean.at("yuzu.guardian_baseline_unpersisted")) ==
          0.0);
}
