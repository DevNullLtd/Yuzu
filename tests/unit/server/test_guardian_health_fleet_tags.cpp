/**
 * test_guardian_health_fleet_tags.cpp - Guardian M1 health-stream fleet-telemetry
 * contract (#2298 gate 3, item 6d; #2993 added the 4th counter; #4783 commit 4 added
 * the 5th/6th - legacy-sink loss visibility, same shape, unrelated feature; a #4783
 * governance follow-up added the 7th - the pre-network-arm legacy-sink drop, wired to
 * fleet visibility for the first time; #5403 added the 8th, #4472 the 9th, #5404 the 10th to
 * 20th - the Spark claim-lifecycle counters and the retained-tombstone count).
 *
 * Mirrors test_guardian_journal_fleet_tags.cpp's four-way bind for the health family
 * (the counter table is plain sparse cumulative counters; the #5403 pending-Disarm and #4472
 * compensation-teardown ages are the exception: they live in GuardianHealthAgeStats and their
 * own MAX table, pinned by the "guardian health ages", "guardian disarm age" and "guardian
 * compensation age" cases below):
 *
 *  - STRUCTURAL: sizeof(GuardianHealthStats) pins the field count to the table row
 *    count, so adding a counter without a fleet gauge is a COMPILE error.
 *  - WRITER -> READER: emit through the agent's REAL emitter with every counter
 *    non-zero; every key it produces must be one the table recognises.
 *  - READER -> WRITER: every table row must have been emitted (else that gauge is
 *    permanently absent - a typo in the table looks exactly like a healthy fleet).
 *  - FIELD -> KEY: every emitted key carries its OWN field's value, so swapping two
 *    values in the emitter is caught, which the key-set checks alone cannot do.
 *
 * Plus the sparse-emit contract, the mechanical tag->gauge name rule, and the
 * forged-value posture of parse_guardian_health_count.
 */
#include "guardian_health_fleet_tags.hpp"

#include "guardian_health_heartbeat.hpp" // agent emitter - the writer side of the bind

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>

namespace detail = yuzu::server::detail;
using yuzu::agent::emit_guardian_health_age_tags;
using yuzu::agent::emit_guardian_health_heartbeat_tags;
using yuzu::agent::GuardianHealthAgeStats;
using yuzu::agent::GuardianHealthStats;
using yuzu::agent::kGuardianCompensationDeadlineElapsedTag;
using yuzu::agent::kGuardianCompensationPendingAgeTag;
using yuzu::agent::kGuardianDisarmDeadlineElapsedTag;
using yuzu::agent::kGuardianDisarmPendingAgeTag;

// STRUCTURAL PIN, same rationale as the guardian-journal sibling: GuardianHealthStats
// is an aggregate of std::uint64_t only (no padding), so its size divided by 8 IS its
// field count. When the NEXT health counter is added, THIS is what fails if its fleet
// row is forgotten: fix it by adding one row to kGuardianHealthMetrics, not by
// relaxing the assert.
static_assert(sizeof(GuardianHealthStats) ==
                  detail::kNGuardianHealthMetrics * sizeof(std::uint64_t),
              "GuardianHealthStats field count != kGuardianHealthMetrics row count - a "
              "health counter was added or removed without its fleet gauge. Add/remove "
              "the matching row in server/core/src/guardian_health_fleet_tags.hpp.");
// The size pin above is only a field COUNT if the struct has no padding. That premise
// was a comment; this makes the compiler check it.
static_assert(std::has_unique_object_representations_v<GuardianHealthStats>,
              "GuardianHealthStats gained padding - sizeof/8 is no longer its field "
              "count, so the size pin above silently stops counting fields.");

// The AGE family gets the SAME structural pin against ITS OWN table (mirrors the journal
// sibling's GuardianJournalAgeStats pin). The two families are deliberately separate
// structs/tables (SUM vs MAX rollup; the counters are sparse uint64s, the ages are optionals),
// so each carries its own pin: an age added to GuardianHealthAgeStats without a
// kGuardianHealthAgeMetrics row is a build break here, and it must never be "fixed" by
// squeezing the age into the SUM table. The struct is an aggregate of std::optional<uint64_t>
// only, so its size divided by the optional's size IS its field count (an optional has padding,
// so has_unique_object_representations cannot be the premise check here; the same-type
// aggregate is).
static_assert(sizeof(GuardianHealthAgeStats) ==
                  detail::kNGuardianHealthAgeMetrics * sizeof(std::optional<std::uint64_t>),
              "GuardianHealthAgeStats field count != kGuardianHealthAgeMetrics row count - an "
              "age gauge was added or removed without its fleet MAX row. Add/remove the matching "
              "row in server/core/src/guardian_health_fleet_tags.hpp.");

namespace {

/// The age family's field count, derived from the struct (never a hand-typed literal).
constexpr std::size_t kAgeStatsFieldCount =
    sizeof(GuardianHealthAgeStats) / sizeof(std::optional<std::uint64_t>);

/// Every counter distinct and non-zero, so each key the agent can emit is exercised
/// AND a field/key mix-up in the emitter shows up as a wrong value (see the
/// expected-map assertion below - the key-set checks alone cannot catch a value swap).
GuardianHealthStats all_nonzero_stats() {
    GuardianHealthStats s;
    s.unhealthy_suppressed = 1;
    s.unhealthy_refreshed = 2;
    s.priority_demoted = 3;
    s.outbox_backpressure_drops = 4;
    s.legacy_sink_events_lost = 5;     // #4783
    s.legacy_sink_gap_rules = 6;       // #4783
    s.legacy_sink_dropped_unwired = 7; // #4783 governance follow-up
    s.disarm_deadline_elapsed = 8;     // #5403
    s.compensation_deadline_elapsed = 20; // #4472
    s.orphan_disarms_started = 9;          // #5404
    s.dead_watchers_erased_on_lost = 10;   // #5404
    s.tombstones_released_by_reaper = 11;  // #5404
    s.claim_index_release_failures = 12;   // #5404
    s.claim_drain_failures = 13;           // #5404
    s.retained_tombstones = 14;            // #5404
    s.detach_sweep_left_residue = 15;      // #5404
    s.detach_claim_failures = 16;          // #5404
    s.detach_post_commit_failures = 17;    // #5404
    s.claims_dropped_at_stop = 18;         // #5404
    s.ack_maint_exceptions = 19;           // #5404
    return s;
}

} // namespace

TEST_CASE("guardian health: agent emit keys bind exactly to the server table",
          "[guardian][health][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianHealthMetrics)
        table_keys.insert(m.tag);
    // A duplicated tag in the table would make the set smaller than the row count and
    // silently shadow one signal with another's accumulator.
    REQUIRE(table_keys.size() == detail::kNGuardianHealthMetrics);

    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, all_nonzero_stats());

    // WRITER -> READER: nothing the agent emits may be unknown to the rollup.
    for (const auto& [key, val] : tags) {
        INFO("emitted key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }

    // FIELD -> KEY BIND. Swap two values in the emitter - put(<suppressed key>,
    // s.unhealthy_refreshed) - and the emitted key SET is byte-identical, so every
    // check above still passes while the server sums one counter under another
    // counter's gauge and the wrong fleet signal moves. all_nonzero_stats() gives
    // each field a distinct value precisely so that mix-up is observable.
    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_unhealthy_suppressed", "1"},
        {"yuzu.guardian_unhealthy_refreshed", "2"},
        {"yuzu.guardian_priority_demoted", "3"},
        {"yuzu.guardian_outbox_backpressure_drops", "4"},
        {"yuzu.guardian_legacy_sink_events_lost", "5"},    // #4783
        {"yuzu.guardian_legacy_sink_gap_rules", "6"},      // #4783
        {"yuzu.guardian_legacy_sink_dropped_unwired", "7"}, // #4783 governance follow-up
        {"yuzu.guardian_disarm_deadline_elapsed", "8"},     // #5403
        {"yuzu.guardian_compensation_deadline_elapsed", "20"}, // #4472
        {"yuzu.guardian_orphan_disarms_started", "9"},         // #5404
        {"yuzu.guardian_dead_watchers_erased_on_lost", "10"},  // #5404
        {"yuzu.guardian_tombstones_released_by_reaper", "11"}, // #5404
        {"yuzu.guardian_claim_index_release_failures", "12"},  // #5404
        {"yuzu.guardian_claim_drain_failures", "13"},          // #5404
        {"yuzu.guardian_retained_tombstones", "14"},           // #5404
        {"yuzu.guardian_detach_sweep_left_residue", "15"},     // #5404
        {"yuzu.guardian_detach_claim_failures", "16"},         // #5404
        {"yuzu.guardian_detach_post_commit_failures", "17"},   // #5404
        {"yuzu.guardian_claims_dropped_at_stop", "18"},        // #5404
        {"yuzu.guardian_ack_maint_exceptions", "19"},          // #5404
    };
    // Per-key, NOT `CHECK(tags == expected)` - see the guardian-journal pin test's
    // comment for why a whole-map compare hides which key drifted.
    for (const auto& [key, want] : expected) {
        INFO("tag " << key);
        REQUIRE(tags.count(key) == 1);
        CHECK(tags.at(key) == want);
    }
    CHECK(tags.size() == expected.size());
    // READER -> WRITER: no table row may reference a key the agent never emits - such
    // a gauge would be permanently absent, indistinguishable from a healthy fleet.
    for (const auto& m : detail::kGuardianHealthMetrics) {
        INFO("table key never emitted by the agent: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }
    CHECK(tags.size() == detail::kNGuardianHealthMetrics);
}

TEST_CASE("guardian health: gauge names follow the mechanical tag rule",
          "[guardian][health][fleet]") {
    // gauge == "yuzu_fleet_" + the tag with its "yuzu." heartbeat-namespace prefix
    // stripped - same mechanical rule as the guardian-journal family.
    constexpr std::string_view kTagNs = "yuzu.";
    std::set<std::string> gauges;
    for (const auto& m : detail::kGuardianHealthMetrics) {
        const std::string_view tag{m.tag};
        INFO("tag not in the yuzu. heartbeat namespace: " << m.tag);
        REQUIRE(tag.substr(0, kTagNs.size()) == kTagNs);
        const std::string expected = "yuzu_fleet_" + std::string(tag.substr(kTagNs.size()));
        INFO("tag " << m.tag << " should map to gauge " << expected);
        CHECK(std::string_view(m.gauge) == expected);

        // HELP is what an on-call operator reads at 3am; an empty one ships a metric
        // nobody can interpret. describe() is driven off this same field.
        INFO("empty HELP for " << m.gauge);
        CHECK(std::string_view(m.help).size() > 0);

        gauges.insert(m.gauge);
    }
    // A duplicated gauge name would have two accumulators fighting over one series.
    CHECK(gauges.size() == detail::kNGuardianHealthMetrics);
}

TEST_CASE("guardian health: a quiescent agent emits no tags at all",
          "[guardian][health][fleet]") {
    // The sparse-emit contract is what makes the fleet rollup's absent-not-zero
    // behaviour honest: nothing to report must produce NO tag, so the server publishes
    // no series, so a healthy/inert fleet cannot be misread as "checked, nothing lost".
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{});
    CHECK(tags.empty());

    // And a single non-zero counter emits ONLY its own tag - partial reporting stays
    // partial.
    GuardianHealthStats one;
    one.priority_demoted = 4;
    std::map<std::string, std::string> one_tag;
    emit_guardian_health_heartbeat_tags(one_tag, one);
    REQUIRE(one_tag.size() == 1);
    CHECK(one_tag.count("yuzu.guardian_priority_demoted") == 1);
}

TEST_CASE("parse_guardian_health_count enforces the forged-value posture",
          "[guardian][health][fleet]") {
    using detail::parse_guardian_health_count;

    CHECK(parse_guardian_health_count("0") == 0.0);
    CHECK(parse_guardian_health_count("42") == 42.0);
    CHECK(parse_guardian_health_count("1000000000") == 1'000'000'000.0); // exactly at the cap

    // "did not report", never 0 - the caller must be able to tell the two apart.
    CHECK_FALSE(parse_guardian_health_count("").has_value());
    CHECK_FALSE(parse_guardian_health_count("abc").has_value());
    CHECK_FALSE(parse_guardian_health_count("-1").has_value());
    CHECK_FALSE(parse_guardian_health_count("1.5").has_value());  // full-token only
    CHECK_FALSE(parse_guardian_health_count("12x").has_value());  // trailing garbage
    CHECK_FALSE(parse_guardian_health_count(" 12").has_value());  // leading space
    CHECK_FALSE(parse_guardian_health_count("inf").has_value());
    CHECK_FALSE(parse_guardian_health_count("nan").has_value());

    // Implausible -> REJECTED, not clamped. A clamped-and-counted 1.8e19 would make
    // every honest agent's contribution a no-op in the double-precision fleet sum.
    CHECK_FALSE(parse_guardian_health_count("1000000001").has_value());
    CHECK_FALSE(parse_guardian_health_count("18446744073709551615").has_value());
    // Over-long input is rejected in O(1) BEFORE being scanned (it runs under
    // AgentHealthStore::mu_, 3 times per agent per sweep).
    CHECK_FALSE(parse_guardian_health_count(std::string(4096, '9')).has_value());
}

// ---- #5403: the pending-Spark-Disarm AGE row (its own MAX-rollup table) -----------------

TEST_CASE("guardian disarm age: the agent key is pinned to the server's age table",
          "[guardian][health][fleet][disarm]") {
    // A one-sided rename of the tag string on either side leaves the fleet gauge permanently
    // absent, which reads as "no Disarm pending": this is the drift guard.
    REQUIRE(detail::kNGuardianHealthAgeMetrics == kAgeStatsFieldCount);
    CHECK(std::string_view(detail::kGuardianHealthAgeMetrics[0].tag) ==
          std::string_view(kGuardianDisarmPendingAgeTag));
    CHECK(std::string_view(kGuardianDisarmPendingAgeTag) ==
          "yuzu.guardian_disarm_pending_age_seconds");

    // WRITER -> READER and READER -> WRITER, through the agent's REAL emitter.
    std::map<std::string, std::string> tags;
    emit_guardian_health_age_tags(tags, GuardianHealthAgeStats{.disarm_pending_age_seconds = 42});
    REQUIRE(tags.size() == 1);
    CHECK(tags.count(detail::kGuardianHealthAgeMetrics[0].tag) == 1);
    CHECK(tags.at(detail::kGuardianHealthAgeMetrics[0].tag) == "42");

    // The age tag must NOT also be a row of the SUM table (it would be summed).
    for (const auto& m : detail::kGuardianHealthMetrics)
        CHECK(std::string_view(m.tag) != std::string_view(kGuardianDisarmPendingAgeTag));
    // The counter tag is the SUM table's, not the age table's.
    bool found = false;
    for (const auto& m : detail::kGuardianHealthMetrics)
        found = found || std::string_view(m.tag) == std::string_view(kGuardianDisarmDeadlineElapsedTag);
    CHECK(found);
}

TEST_CASE("guardian disarm age: gauge name follows the age-table rule, HELP states the limits",
          "[guardian][health][fleet][disarm]") {
    const auto& m = detail::kGuardianHealthAgeMetrics[0];
    CHECK(std::string_view(m.gauge) == "yuzu_fleet_guardian_disarm_pending_age_seconds_max");
    const std::string_view help{m.help};
    // The HELP is what an operator reads: it must say "too long, not proof of a hang" and
    // name what the gauge cannot see.
    CHECK(help.find("TOO LONG") != std::string_view::npos);
    CHECK(help.find("not proof") != std::string_view::npos);
    CHECK(help.find("compensating disarm") != std::string_view::npos);
    CHECK(help.find("direct disarm") != std::string_view::npos);
    CHECK(help.find("synchronous teardown fallback") != std::string_view::npos);
    CHECK(help.find("inline-type") != std::string_view::npos);
}

TEST_CASE("guardian disarm age: emitter is absent for nullopt, present (including 0) otherwise",
          "[guardian][health][fleet][disarm]") {
    std::map<std::string, std::string> none;
    emit_guardian_health_age_tags(none, GuardianHealthAgeStats{});
    CHECK(none.empty()); // "no Disarm pending" is an ABSENCE, never a 0

    std::map<std::string, std::string> young;
    emit_guardian_health_age_tags(young, GuardianHealthAgeStats{.disarm_pending_age_seconds = 0});
    REQUIRE(young.count(kGuardianDisarmPendingAgeTag) == 1);
    CHECK(young.at(kGuardianDisarmPendingAgeTag) == "0"); // pending for under a second

    // And a zero cumulative counter is sparse-omitted by the counter emitter.
    std::map<std::string, std::string> counter;
    emit_guardian_health_heartbeat_tags(counter, GuardianHealthStats{});
    CHECK(counter.count(kGuardianDisarmDeadlineElapsedTag) == 0);
}

// ---- #4472: the outstanding-compensation AGE row and its deadline count ------------------

TEST_CASE("guardian compensation age: the agent keys are pinned to the server's tables",
          "[guardian][health][fleet][compensation]") {
    // The age is the age table's SECOND row; its once-per-claim count is a row of the SUM table.
    REQUIRE(detail::kNGuardianHealthAgeMetrics == kAgeStatsFieldCount);
    const auto& age = detail::kGuardianHealthAgeMetrics[1];
    CHECK(std::string_view(age.tag) == std::string_view(kGuardianCompensationPendingAgeTag));
    CHECK(std::string_view(kGuardianCompensationPendingAgeTag) ==
          "yuzu.guardian_compensation_pending_age_seconds");
    CHECK(std::string_view(age.gauge) ==
          "yuzu_fleet_guardian_compensation_pending_age_seconds_max");

    // WRITER -> READER through the agent's REAL emitter.
    std::map<std::string, std::string> tags;
    emit_guardian_health_age_tags(tags,
                                  GuardianHealthAgeStats{.compensation_pending_age_seconds = 42});
    REQUIRE(tags.size() == 1);
    CHECK(tags.at(age.tag) == "42");

    // The age tag must not also be a SUM-table row (it would be summed), and the count tag
    // must be one.
    bool count_found = false;
    for (const auto& m : detail::kGuardianHealthMetrics) {
        CHECK(std::string_view(m.tag) != std::string_view(kGuardianCompensationPendingAgeTag));
        if (std::string_view(m.tag) == std::string_view(kGuardianCompensationDeadlineElapsedTag)) {
            count_found = true;
            CHECK(std::string_view(m.gauge) ==
                  "yuzu_fleet_guardian_compensation_deadline_elapsed");
        }
    }
    CHECK(count_found);
    // And the two age tags are distinct, so one cannot shadow the other's accumulator.
    CHECK(std::string_view(detail::kGuardianHealthAgeMetrics[0].tag) !=
          std::string_view(detail::kGuardianHealthAgeMetrics[1].tag));
}

TEST_CASE("guardian compensation age: HELP states the limits and the held-generation effect",
          "[guardian][health][fleet][compensation]") {
    const std::string_view help{detail::kGuardianHealthAgeMetrics[1].help};
    CHECK(help.find("TOO LONG") != std::string_view::npos);
    CHECK(help.find("not proof") != std::string_view::npos);
    CHECK(help.find("not from the original arm") != std::string_view::npos);
    CHECK(help.find("not acknowledged") != std::string_view::npos);
    CHECK(help.find("direct disarm fallback") != std::string_view::npos);
    CHECK(help.find("synchronous teardown fallback") != std::string_view::npos);
    CHECK(help.find("inline-type") != std::string_view::npos);
    CHECK(help.find("MONITOR-ONLY") != std::string_view::npos);
}

TEST_CASE("guardian compensation age: emitter is absent for nullopt, present (including 0) "
          "otherwise",
          "[guardian][health][fleet][compensation]") {
    std::map<std::string, std::string> none;
    emit_guardian_health_age_tags(none, GuardianHealthAgeStats{});
    CHECK(none.empty()); // "none outstanding" is an ABSENCE, never a 0

    std::map<std::string, std::string> young;
    emit_guardian_health_age_tags(
        young, GuardianHealthAgeStats{.compensation_pending_age_seconds = 0});
    REQUIRE(young.count(kGuardianCompensationPendingAgeTag) == 1);
    CHECK(young.at(kGuardianCompensationPendingAgeTag) == "0");

    std::map<std::string, std::string> counter;
    emit_guardian_health_heartbeat_tags(counter, GuardianHealthStats{});
    CHECK(counter.count(kGuardianCompensationDeadlineElapsedTag) == 0);
}

// ---- The AGE family as a whole: generic pins (mirror test_guardian_journal_fleet_tags.cpp) ----
//
// The per-age cases above pin each row by name. These loop the WHOLE table, so a third age row
// (or a third field of GuardianHealthAgeStats) is covered the moment it exists, with no test to
// remember to write: the failure modes are a tag in both tables (summed AND maxed), a gauge
// without the `_max` marker, an empty HELP, a writer/reader key mismatch, and a field/row mix-up.

TEST_CASE("guardian health ages: emit keys bind exactly to the server MAX table",
          "[guardian][health][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianHealthAgeMetrics)
        table_keys.insert(m.tag);
    REQUIRE(table_keys.size() == detail::kNGuardianHealthAgeMetrics); // no duplicated tag
    REQUIRE(detail::kNGuardianHealthAgeMetrics == kAgeStatsFieldCount);

    // Distinct values per field: the key-set checks cannot catch a disarm/compensation value
    // swap in the emitter, this can.
    std::map<std::string, std::string> tags;
    emit_guardian_health_age_tags(tags, GuardianHealthAgeStats{.disarm_pending_age_seconds = 31,
                                                               .compensation_pending_age_seconds = 62});
    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_disarm_pending_age_seconds", "31"},
        {"yuzu.guardian_compensation_pending_age_seconds", "62"},
    };
    for (const auto& [key, want] : expected) {
        INFO("tag " << key);
        REQUIRE(tags.count(key) == 1);
        CHECK(tags.at(key) == want);
    }
    CHECK(tags.size() == expected.size());

    // WRITER -> READER and READER -> WRITER over the whole table.
    for (const auto& [key, val] : tags) {
        INFO("emitted age key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }
    for (const auto& m : detail::kGuardianHealthAgeMetrics) {
        INFO("age table key never emitted by the agent: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }
    CHECK(tags.size() == detail::kNGuardianHealthAgeMetrics);
}

TEST_CASE("guardian health ages: gauge names follow the mechanical rule with _max, HELP is "
          "non-empty, and no tag or gauge is in both tables",
          "[guardian][health][fleet]") {
    constexpr std::string_view kTagNs = "yuzu.";
    constexpr std::string_view kMax = "_max";
    const auto ends_with_max = [&](std::string_view g) {
        return g.size() >= kMax.size() && g.substr(g.size() - kMax.size()) == kMax;
    };
    std::set<std::string> age_gauges;
    for (const auto& m : detail::kGuardianHealthAgeMetrics) {
        const std::string_view tag{m.tag};
        INFO("age tag not in the yuzu. heartbeat namespace: " << m.tag);
        REQUIRE(tag.substr(0, kTagNs.size()) == kTagNs);
        const std::string expected = "yuzu_fleet_" + std::string(tag.substr(kTagNs.size())) + "_max";
        INFO("age tag " << m.tag << " should map to gauge " << expected);
        CHECK(std::string_view(m.gauge) == expected);
        CHECK(ends_with_max(m.gauge)); // the visible marker that this family rolls up as MAX
        INFO("empty HELP for " << m.gauge);
        CHECK(std::string_view(m.help).size() > 0);
        age_gauges.insert(m.gauge);
    }
    CHECK(age_gauges.size() == detail::kNGuardianHealthAgeMetrics); // no duplicated gauge

    // The reverse marker rule: a SUM gauge must never end `_max` (it would read as a MAX), and
    // no tag or gauge may appear in BOTH tables (it would be both summed and maxed).
    for (const auto& m : detail::kGuardianHealthMetrics) {
        INFO("SUM gauge ends _max: " << m.gauge);
        CHECK_FALSE(ends_with_max(m.gauge));
        INFO("age gauge collides with a SUM gauge: " << m.gauge);
        CHECK(age_gauges.count(m.gauge) == 0);
        for (const auto& a : detail::kGuardianHealthAgeMetrics) {
            INFO("tag in both tables: " << m.tag);
            CHECK(std::string_view(m.tag) != std::string_view(a.tag));
        }
    }
}

TEST_CASE("guardian health ages: a quiescent agent emits no age tag, each age is independent",
          "[guardian][health][fleet]") {
    std::map<std::string, std::string> none;
    emit_guardian_health_age_tags(none, GuardianHealthAgeStats{});
    CHECK(none.empty());

    std::map<std::string, std::string> one;
    emit_guardian_health_age_tags(one, GuardianHealthAgeStats{.compensation_pending_age_seconds = 3});
    REQUIRE(one.size() == 1);
    CHECK(one.count(kGuardianCompensationPendingAgeTag) == 1);
}
