/**
 * test_dedup_fleet_tags.cpp -- direct tests of the forged-value-safe parse behind the
 * `yuzu_fleet_agents_dedup_*` gauges (#3663).
 *
 * `server/core/src/dedup_fleet_tags.hpp` is header-only and pure, so the parse and the
 * flag-vs-counter classification can be tested without an `AgentHealthStore`. The store-level
 * behaviour (what is published for a fleet of agents) is the "REAL AgentHealthStore: dedup ..."
 * cases in test_agent_health_store.cpp; THIS file exists because those cases cannot tell which
 * guard in the parse rejected a value. The 10-character cap in particular is invisible to them:
 * an 11-digit value is rejected by the 1e9 ceiling anyway, so deleting the cap leaves every
 * store-level case green while a 20-digit value wraps `unsigned long long` and reads as a small
 * number (measured: "18446744073709551617" classifies as Counted for a flag, i.e. a forged
 * "degraded"). The wrap rows below are the ones that fail without it.
 */

#include "dedup_fleet_tags.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <string>
#include <string_view>

using namespace yuzu::server::detail;
using namespace std::string_view_literals;

TEST_CASE("dedup parse: accepts canonical decimal values up to the plausibility ceiling",
          "[dedup_fleet][parse]") {
    CHECK(parse_dedup_value("0") == 0ULL);
    CHECK(parse_dedup_value("1") == 1ULL);
    CHECK(parse_dedup_value("20512") == 20512ULL);
    CHECK(parse_dedup_value("999999999") == 999'999'999ULL);
    // Exactly the ceiling is accepted; one above is not. Mutating `> kMax` to `>= kMax` fails
    // the first line.
    CHECK(parse_dedup_value("1000000000") == 1'000'000'000ULL);
    CHECK_FALSE(parse_dedup_value("1000000001").has_value());
}

TEST_CASE("dedup parse: rejects anything that is not a bare run of 1 to 10 ASCII digits",
          "[dedup_fleet][parse]") {
    for (const std::string_view bad : std::initializer_list<std::string_view>{
             "",           // empty
             "+1",         // sign
             "-1",         // sign
             " 1",         // leading space
             "1 ",         // trailing space
             "1\n",        // trailing newline
             "0x1",        // hex
             "1e3",        // exponent
             "1.0",        // fraction
             "abc",        // text
             "\xD9\xA1",   // Arabic-Indic digit one (UTF-8)
             "1\0" "2"sv,  // embedded NUL (string_view keeps the length)
         }) {
        INFO("input bytes: " << std::string(bad));
        CHECK_FALSE(parse_dedup_value(bad).has_value());
    }
}

TEST_CASE("dedup parse: the 10 character cap stops unsigned wraparound",
          "[dedup_fleet][parse]") {
    // Without `raw.size() > 10`, 2^64 + 1 wraps to 1 and 2^64 wraps to 0: a forged value that
    // reads as a small, valid number. Each of these must be rejected BY THE CAP (they are far
    // above the ceiling, so the ceiling would also reject the ones that do not wrap -- the
    // wrapping ones are what only the cap catches).
    CHECK_FALSE(parse_dedup_value("18446744073709551617").has_value()); // 2^64 + 1 -> wraps to 1
    CHECK_FALSE(parse_dedup_value("18446744073709551616").has_value()); // 2^64     -> wraps to 0
    CHECK_FALSE(parse_dedup_value("99999999999999999999").has_value()); // 20 digits
    CHECK_FALSE(parse_dedup_value("12345678901").has_value());          // 11 digits
    // 10 digits is the longest accepted shape: it cannot overflow, and "0000000001" (leading
    // zeros) is accepted by design -- see the comment on parse_dedup_value.
    CHECK(parse_dedup_value("0000000001") == 1ULL);
    CHECK_FALSE(parse_dedup_value("00000000001").has_value()); // 11 chars, even though value 1
}

TEST_CASE("dedup classify: a flag counts only on 1, and anything above 1 is rejected",
          "[dedup_fleet][classify]") {
    using K = DedupCountKind;
    CHECK(classify_dedup_value(K::kFlag, "0") == DedupVerdict::kNotCounted);
    CHECK(classify_dedup_value(K::kFlag, "1") == DedupVerdict::kCounted);
    CHECK(classify_dedup_value(K::kFlag, "2") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kFlag, "20512") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kFlag, "") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kFlag, "18446744073709551617") == DedupVerdict::kRejected);
}

TEST_CASE("dedup classify: a counter counts on any value above 0",
          "[dedup_fleet][classify]") {
    using K = DedupCountKind;
    CHECK(classify_dedup_value(K::kPositiveCounter, "0") == DedupVerdict::kNotCounted);
    CHECK(classify_dedup_value(K::kPositiveCounter, "1") == DedupVerdict::kCounted);
    CHECK(classify_dedup_value(K::kPositiveCounter, "5") == DedupVerdict::kCounted);
    CHECK(classify_dedup_value(K::kPositiveCounter, "1000000000") == DedupVerdict::kCounted);
    CHECK(classify_dedup_value(K::kPositiveCounter, "1000000001") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kPositiveCounter, "-1") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kPositiveCounter, "garbage") == DedupVerdict::kRejected);
    CHECK(classify_dedup_value(K::kPositiveCounter, "18446744073709551617") ==
          DedupVerdict::kRejected);
}

TEST_CASE("dedup table: shape invariants the registry and server.cpp rely on",
          "[dedup_fleet][table]") {
    // Row 0 is the presence row and the only flag; every other row is a counter.
    REQUIRE(kNDedupAgentCountMetrics >= 2);
    CHECK(std::string(kDedupAgentCountMetrics[kDedupPresenceIndex].tag) == "yuzu.dedup_degraded");
    CHECK(kDedupAgentCountMetrics[kDedupPresenceIndex].kind == DedupCountKind::kFlag);
    for (std::size_t i = 0; i < kNDedupAgentCountMetrics; ++i) {
        const auto& m = kDedupAgentCountMetrics[i];
        INFO("row " << i << ": " << m.tag);
        if (i != kDedupPresenceIndex)
            CHECK(m.kind == DedupCountKind::kPositiveCounter);
        CHECK(std::string(m.tag).rfind("yuzu.dedup_", 0) == 0);
        CHECK(std::string(m.gauge).rfind("yuzu_fleet_agents_dedup_", 0) == 0);
        CHECK(std::string(m.help).size() > 40);
        for (const char c : std::string(m.help))
            CHECK(static_cast<unsigned char>(c) < 0x80); // HELP text is 7-bit ASCII
    }
}
