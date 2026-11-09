/**
 * test_guardian_backend_fleet_tags.cpp - yuzu.guardian_backend fleet-telemetry contract (#2240).
 *
 * Binds the agent's WRITER (agents/core/src/guardian_backend.hpp) to the server's READER table
 * (server/core/src/guardian_backend_fleet_tags.hpp), the same writer/reader bind the sibling
 * test_guardian_health_fleet_tags.cpp and test_spark_fleet_tags.cpp make:
 *
 *  - WRITER -> READER: drive the agent's REAL emit_guardian_backend_heartbeat_tag over every
 *    (prefer_spark, SparkAvailability) pair; the one key it writes must be the server's key and
 *    its value must be a token the server's strict parse accepts, mapping back to the same
 *    string.
 *  - READER -> WRITER: every server table token must be emitted by some agent state (a typo in
 *    the table would otherwise read as a healthy fleet that simply never reports it), and the
 *    set sizes must match.
 *  - The mechanical gauge-name rule, ASCII HELP, and the strict-parse posture (garbage is
 *    NotReported/rejected, never a token).
 *
 * The REAL-store rollup cases live in test_agent_health_store.cpp ("[guardian][backend]") and
 * the real device-path cases in test_device_api.cpp; neither can see the agent header.
 */
#include "guardian_backend_fleet_tags.hpp"

#include "guardian_backend.hpp" // agent emitter - the writer side of the bind

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace detail = yuzu::server::detail;
using yuzu::agent::emit_guardian_backend_heartbeat_tag;
using yuzu::agent::GuardianBackend;
using yuzu::agent::GuardianEngine;

// The key must be the same byte string on both sides. Compile-time: a rename on either side
// without the other is a build failure here, before any case runs.
static_assert(std::string_view{detail::kGuardianBackendTag} ==
                  std::string_view{yuzu::agent::kGuardianBackendTag},
              "the server reader key drifted from the agent writer key (guardian_backend.hpp)");

namespace {

constexpr std::array<GuardianEngine::SparkAvailability, 4> kAllAvailability = {
    GuardianEngine::SparkAvailability::Unwired,
    GuardianEngine::SparkAvailability::SparkDisabled,
    GuardianEngine::SparkAvailability::SparkFailed,
    GuardianEngine::SparkAvailability::Available,
};

constexpr std::array<GuardianBackend, 4> kAllBackends = {
    GuardianBackend::Legacy,
    GuardianBackend::Spark,
    GuardianBackend::Unwired,
    GuardianBackend::SparkFailed,
};

/// Exhaustive on purpose (no default): a new SparkAvailability enumerator is a -Wswitch warning
/// here, which is the prompt to extend kAllAvailability and the matrix below.
constexpr bool availability_is_listed(GuardianEngine::SparkAvailability a) {
    switch (a) {
    case GuardianEngine::SparkAvailability::Unwired:
    case GuardianEngine::SparkAvailability::SparkDisabled:
    case GuardianEngine::SparkAvailability::SparkFailed:
    case GuardianEngine::SparkAvailability::Available:
        return true;
    }
    return false;
}

/// Same for GuardianBackend: a 5th backend enumerator must be a compile prompt, not a silent
/// gap in the label bind.
constexpr std::size_t backend_expected_index(GuardianBackend b) {
    switch (b) {
    case GuardianBackend::Legacy:
        return detail::kGuardianBackendIdxLegacy;
    case GuardianBackend::Spark:
        return detail::kGuardianBackendIdxSpark;
    case GuardianBackend::Unwired:
        return detail::kGuardianBackendIdxUnwired;
    case GuardianBackend::SparkFailed:
        return detail::kGuardianBackendIdxSparkFailed;
    }
    return detail::kNGuardianBackendTokens; // unreachable for a listed enumerator
}

bool is_7bit_ascii(std::string_view s) {
    for (const unsigned char c : s)
        if (c >= 0x80)
            return false;
    return true;
}

} // namespace

static_assert(availability_is_listed(GuardianEngine::SparkAvailability::Available));
static_assert(kAllAvailability.size() == 4 && kAllBackends.size() == 4,
              "a new SparkAvailability or GuardianBackend enumerator needs a matrix row");
static_assert(detail::kNGuardianBackendTokens == kAllBackends.size(),
              "the server table and the agent GuardianBackend enum differ in size");

TEST_CASE("guardian backend: the agent's emitter writes the server's key and a table token",
          "[guardian][backend][fleet]") {
    std::set<std::string> emitted_values;
    for (const bool prefer_spark : {false, true}) {
        for (const auto availability : kAllAvailability) {
            INFO("prefer_spark=" << prefer_spark
                                 << " availability=" << static_cast<int>(availability));
            std::map<std::string, std::string> tags;
            emit_guardian_backend_heartbeat_tag(tags, prefer_spark, availability);

            // Exactly one key, and it is the server's key.
            REQUIRE(tags.size() == 1);
            const auto it = tags.find(detail::kGuardianBackendTag);
            REQUIRE(it != tags.end());

            // The strict parse accepts it, and the table token is the same string.
            const auto idx = detail::parse_guardian_backend_token(it->second);
            REQUIRE(idx.has_value());
            CHECK(detail::guardian_backend_token_view(*idx) == it->second);
            emitted_values.insert(it->second);
        }
    }

    // READER -> WRITER: every table token is reachable from some agent state, and nothing the
    // agent can emit is outside the table.
    std::set<std::string> table;
    for (const char* t : detail::kGuardianBackendTokens)
        table.insert(t);
    CHECK(table.size() == detail::kNGuardianBackendTokens); // no duplicates
    CHECK(emitted_values == table);
}

TEST_CASE("guardian backend: every agent label maps to its named server index",
          "[guardian][backend][fleet]") {
    for (const auto backend : kAllBackends) {
        const std::string_view label = yuzu::agent::guardian_backend_label(backend);
        const auto idx = detail::parse_guardian_backend_token(label);
        REQUIRE(idx.has_value());
        CHECK(*idx == backend_expected_index(backend));
    }
}

TEST_CASE("guardian backend: prefer_spark off is legacy whatever the availability",
          "[guardian][backend][fleet]") {
    // The pre-flip production state (agent.cpp hardcodes prefer_spark=false): every agent emits
    // legacy, including one whose SparkEngine failed to boot. That is why spark_failed and
    // unwired cannot populate yet, and why a SparkEngine boot failure shows only on
    // yuzu_fleet_spark_failed{os}. If the flip lands this case stays true; only the
    // prefer_spark=true rows of the matrix start to appear on the wire.
    for (const auto availability : kAllAvailability) {
        std::map<std::string, std::string> tags;
        emit_guardian_backend_heartbeat_tag(tags, /*prefer_spark=*/false, availability);
        CHECK(tags[detail::kGuardianBackendTag] == "legacy");
    }
}

TEST_CASE("guardian backend: metric names follow the mechanical rule and HELP is ASCII",
          "[guardian][backend][fleet]") {
    const std::string gauge = detail::kGuardianBackendGauge;
    CHECK(gauge.starts_with("yuzu_fleet_"));
    CHECK(std::string{detail::kGuardianBackendReportingGauge} == gauge + "_reporting");
    CHECK(std::string{detail::kGuardianBackendTagRejectedGauge} == gauge + "_tag_rejected");
    CHECK(std::string{detail::kGuardianBackendLabelOs} == "os");
    CHECK(std::string{detail::kGuardianBackendLabelBackend} == "backend");

    for (const char* help :
         {detail::kGuardianBackendHelp, detail::kGuardianBackendReportingHelp,
          detail::kGuardianBackendTagRejectedHelp}) {
        const std::string_view h{help};
        CHECK_FALSE(h.empty());
        CHECK(is_7bit_ascii(h));
        // A newline or backslash would need escaping in the exposition format.
        CHECK(h.find('\n') == std::string_view::npos);
        CHECK(h.find('\\') == std::string_view::npos);
    }

    // The main HELP must name every token, so a new token is a HELP edit by construction.
    for (const char* t : detail::kGuardianBackendTokens)
        CHECK(std::string_view{detail::kGuardianBackendHelp}.find(t) != std::string_view::npos);
}

TEST_CASE("guardian backend: parse is STRICT - garbage is never a token",
          "[guardian][backend][fleet]") {
    using detail::parse_guardian_backend_token;

    CHECK(parse_guardian_backend_token("legacy") == detail::kGuardianBackendIdxLegacy);
    CHECK(parse_guardian_backend_token("spark") == detail::kGuardianBackendIdxSpark);
    CHECK(parse_guardian_backend_token("spark_failed") == detail::kGuardianBackendIdxSparkFailed);
    CHECK(parse_guardian_backend_token("unwired") == detail::kGuardianBackendIdxUnwired);

    // Empty is NotReported (the caller skips it before counting a rejection); everything else
    // outside the closed, case-sensitive table is rejected. None may map to any token,
    // least of all legacy.
    for (const char* garbage :
         {"", " ", "Legacy", "LEGACY", "Spark", "SPARK_FAILED", " legacy", "legacy ", "legacy\n",
          "spark-failed", "sparkfailed", "spark_", "0", "1", "true", "none", "null",
          "legacy,spark", "a-future-backend", "unwired2"}) {
        INFO("value: '" << garbage << "'");
        CHECK_FALSE(parse_guardian_backend_token(garbage).has_value());
    }
    // An embedded NUL is not a prefix match.
    CHECK_FALSE(parse_guardian_backend_token(std::string_view{"legacy\0x", 8}).has_value());
    CHECK_FALSE(parse_guardian_backend_token(std::string_view{"legacy\0", 7}).has_value());

    // Oversize is rejected after one size compare, never scanned.
    const std::string huge(4u * 1024u * 1024u, 'l');
    CHECK_FALSE(parse_guardian_backend_token(huge).has_value());
    const std::string just_over(detail::kMaxGuardianBackendTokenBytes + 1, 'x');
    CHECK_FALSE(parse_guardian_backend_token(just_over).has_value());
}

TEST_CASE("guardian backend: the token view is static storage, not the input",
          "[guardian][backend][fleet]") {
    // The device accessors hand this view out after the health store's mutex is released, so
    // it must point into the constexpr table, never into the agent-supplied tag buffer.
    std::string input = "spark";
    const auto idx = detail::parse_guardian_backend_token(input);
    REQUIRE(idx.has_value());
    const std::string_view view = detail::guardian_backend_token_view(*idx);
    CHECK(view == "spark");
    CHECK(view.data() != input.data());
    input.assign("XXXXX");
    CHECK(view == "spark");
}
