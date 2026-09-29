/**
 * test_guardian_journal_fleet_tags.cpp - Guardian durable lifecycle-journal
 * fleet-telemetry contract (#2298 gate 3).
 *
 * The server reader (server/core/src/guardian_journal_fleet_tags.hpp) re-declares the
 * heartbeat tag keys rather than including the agent's writer header, because server
 * production code must not gain an upward dependency on an agent private header (the
 * constraint is recorded in tests/meson.build). This file is what makes that safe: it
 * is the ONLY place both sides meet, and it binds them four ways -
 *
 *  - STRUCTURAL: sizeof(GuardianJournalStats) pins the field count to the table row
 *    count, so adding a counter without a fleet gauge is a COMPILE error.
 *  - WRITER -> READER: emit through the agent's REAL emitter with every counter
 *    non-zero; every key it produces must be one the table recognises (else that
 *    signal silently reports nothing).
 *  - READER -> WRITER: every table row must have been emitted (else that gauge is
 *    permanently absent - a typo in the table looks exactly like a healthy fleet).
 *  - FIELD -> KEY (the one the key-set checks cannot make): every emitted key carries
 *    its OWN field's value, so swapping two values in the emitter is caught. Without
 *    it the emitted key SET is unchanged and all three checks above still pass.
 *
 * Plus the sparse-emit contract (a quiescent journal ships NO tags, which is what
 * makes absent-not-zero honest), the mechanical tag->gauge name rule, and the
 * forged-value posture of parse_guardian_journal_count.
 */
#include "guardian_journal_fleet_tags.hpp"

#include "guardian_journal_heartbeat.hpp" // agent emitter - the writer side of the bind

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>

namespace detail = yuzu::server::detail;
using yuzu::agent::emit_guardian_journal_age_tags;
using yuzu::agent::emit_guardian_journal_heartbeat_tags;
using yuzu::agent::GuardianJournalAgeStats;
using yuzu::agent::GuardianJournalStats;

// STRUCTURAL PIN. GuardianJournalStats is an aggregate of std::uint64_t only (no
// padding), so its size divided by 8 IS its field count. Pinning that to the table
// row count turns "added a journal counter but forgot its fleet gauge" from a silently
// dead metric into a build break - the strongest bind available without server
// production code including an agent header.
//
// `gauge_underflow` was wired in exactly this way (flip item 5, #2298), and the UP-4
// send_exceptions / backpressure_drops pair followed. When the NEXT journal counter is
// added, THIS is what fails if its fleet row is forgotten: fix it by adding one row to
// kGuardianJournalMetrics, not by relaxing the assert.
static_assert(sizeof(GuardianJournalStats) ==
                  detail::kNGuardianJournalMetrics * sizeof(std::uint64_t),
              "GuardianJournalStats field count != kGuardianJournalMetrics row count - a "
              "journal counter was added or removed without its fleet gauge. Add/remove the "
              "matching row in server/core/src/guardian_journal_fleet_tags.hpp.");
// The size pin above is only a field COUNT if the struct has no padding. That premise
// was a comment; this makes the compiler check it. has_unique_object_representations_v
// holds iff there are no padding bits, so it fires if a future field breaks the
// all-uint64_t layout the count arithmetic depends on.
static_assert(std::has_unique_object_representations_v<GuardianJournalStats>,
              "GuardianJournalStats gained padding - sizeof/8 is no longer its field "
              "count, so the size pin above silently stops counting fields.");

// The AGE family gets the SAME structural pin against ITS OWN table. The two families
// are deliberately separate structs/tables (SUM vs MAX rollup, sparse vs
// emit-including-0 - see both headers), so each carries its own pin: an age added to
// GuardianJournalAgeStats without a kGuardianJournalAgeMetrics row is a build break
// here, and it must never be "fixed" by squeezing the age into the 32-counter table.
static_assert(sizeof(GuardianJournalAgeStats) ==
                  detail::kNGuardianJournalAgeMetrics * sizeof(std::uint64_t),
              "GuardianJournalAgeStats field count != kGuardianJournalAgeMetrics row count "
              "- an age gauge was added or removed without its fleet MAX row. Add/remove "
              "the matching row in server/core/src/guardian_journal_fleet_tags.hpp.");
static_assert(std::has_unique_object_representations_v<GuardianJournalAgeStats>,
              "GuardianJournalAgeStats gained padding - sizeof/8 is no longer its field "
              "count, so the age size pin above silently stops counting fields.");

namespace {

/// Every counter distinct and non-zero, so each key the agent can emit is exercised AND
/// a field/key mix-up in the emitter shows up as a wrong value (see the expected-map
/// assertion in the bind test - the key-set checks alone cannot catch a value swap).
GuardianJournalStats all_nonzero_stats() {
    GuardianJournalStats s;
    s.stage_dropped = 1;
    s.stage_failures = 2;
    s.field_rejected = 3;
    s.clock_rejected = 4;
    s.pending_depth = 5;
    s.batches_written = 6;
    s.write_failures = 7;
    s.key_collisions = 8;
    s.quarantined = 9;
    s.quarantine_failures = 10;
    s.quarantine_capacity_evicted = 11;
    s.batches_pruned = 12;
    s.prune_failures = 13;
    s.write_capacity_rejected = 14;
    s.gauge_underflow = 27;
    s.journal_bytes = 15;
    s.journal_batch_count = 16;
    s.pages = 17;
    s.records_paged = 18;
    s.sent_labels_written = 19;
    s.evicted_sent_unacked = 20;
    s.evicted_without_send_evidence = 21;
    s.maint_exceptions = 22;
    s.page_read_failures = 23;
    s.clock_jump_skips = 24;
    s.drain_exceptions = 25;
    s.sweep_exceptions = 26;
    s.send_exceptions = 28;
    s.lifecycle_backpressure_drops = 29;
    s.evicted_unclassified = 30;
    s.send_orphan_exceptions = 31;
    s.send_stalls = 32;
    return s;
}

} // namespace

TEST_CASE("guardian journal: agent emit keys bind exactly to the server table",
          "[guardian][journal][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianJournalMetrics)
        table_keys.insert(m.tag);
    // A duplicated tag in the table would make the set smaller than the row count and
    // silently shadow one signal with another's accumulator.
    REQUIRE(table_keys.size() == detail::kNGuardianJournalMetrics);

    std::map<std::string, std::string> tags;
    emit_guardian_journal_heartbeat_tags(tags, all_nonzero_stats());

    // WRITER -> READER: nothing the agent emits may be unknown to the rollup.
    for (const auto& [key, val] : tags) {
        INFO("emitted key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }

    // FIELD -> KEY BIND. The three checks around this one are all key-SET checks: they
    // prove the writer and reader agree on WHICH 32 keys exist, and nothing more. Swap
    // two values in the emitter - put(<stage_dropped key>, s.stage_failures) - and the
    // emitted key set is byte-identical, so every one of them still passes while the
    // server sums one counter under another counter's gauge and the wrong fleet alert
    // fires on the wrong signal. all_nonzero_stats() gives each field a distinct value
    // precisely so that mix-up is observable; this is the assertion that observes it.
    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_journal_stage_dropped", "1"},
        {"yuzu.guardian_journal_stage_failures", "2"},
        {"yuzu.guardian_journal_field_rejected", "3"},
        {"yuzu.guardian_journal_clock_rejected", "4"},
        {"yuzu.guardian_journal_pending", "5"},
        {"yuzu.guardian_journal_batches_written", "6"},
        {"yuzu.guardian_journal_write_failures", "7"},
        {"yuzu.guardian_journal_key_collisions", "8"},
        {"yuzu.guardian_journal_quarantined", "9"},
        {"yuzu.guardian_journal_quarantine_failures", "10"},
        {"yuzu.guardian_journal_quarantine_capacity_evicted", "11"},
        {"yuzu.guardian_journal_pruned", "12"},
        {"yuzu.guardian_journal_prune_failures", "13"},
        {"yuzu.guardian_journal_write_capacity_rejected", "14"},
        {"yuzu.guardian_journal_gauge_underflow", "27"},
        {"yuzu.guardian_journal_bytes", "15"},
        {"yuzu.guardian_journal_batch_count", "16"},
        {"yuzu.guardian_journal_pages", "17"},
        {"yuzu.guardian_journal_records_paged", "18"},
        {"yuzu.guardian_journal_sent_labels", "19"},
        {"yuzu.guardian_journal_evicted_sent_unacked", "20"},
        {"yuzu.guardian_journal_evicted_no_send_evidence", "21"},
        {"yuzu.guardian_journal_maint_exceptions", "22"},
        {"yuzu.guardian_journal_page_read_failures", "23"},
        {"yuzu.guardian_journal_clock_jump_skips", "24"},
        {"yuzu.guardian_drain_exceptions", "25"},
        {"yuzu.guardian_sweep_exceptions", "26"},
        {"yuzu.guardian_send_exceptions", "28"},
        {"yuzu.guardian_journal_backpressure_drops", "29"},
        {"yuzu.guardian_journal_evicted_unclassified", "30"},
        {"yuzu.guardian_send_orphan_exceptions", "31"},
        {"yuzu.guardian_send_stalls", "32"},
    };
    // Per-key, NOT `CHECK(tags == expected)`. Catch2 has no StringMaker for
    // std::pair and neither CATCH_CONFIG_ENABLE_PAIR_STRINGMAKER nor
    // ..._ALL_STRINGMAKERS is defined anywhere in this repo, so a whole-map compare
    // renders both operands as `{ {?}, {?}, ... }` - it tells you the drift guard
    // fired but not which key drifted, which is the one thing you need at that moment.
    for (const auto& [key, want] : expected) {
        INFO("tag " << key);
        REQUIRE(tags.count(key) == 1);
        CHECK(tags.at(key) == want);
    }
    CHECK(tags.size() == expected.size());
    // READER -> WRITER: no table row may reference a key the agent never emits - such
    // a gauge would be permanently absent, indistinguishable from a healthy fleet.
    for (const auto& m : detail::kGuardianJournalMetrics) {
        INFO("table key never emitted by the agent: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }
    CHECK(tags.size() == detail::kNGuardianJournalMetrics);
}

TEST_CASE("guardian journal: gauge names follow the mechanical tag rule",
          "[guardian][journal][fleet]") {
    // gauge == "yuzu_fleet_" + the tag with its "yuzu." heartbeat-namespace prefix
    // stripped. Mechanical, so a reviewer can check a new row by eye and the metric
    // name can be derived from the wire key (and vice versa, when reading an alert).
    constexpr std::string_view kTagNs = "yuzu.";
    std::set<std::string> gauges;
    for (const auto& m : detail::kGuardianJournalMetrics) {
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
    CHECK(gauges.size() == detail::kNGuardianJournalMetrics);
}

TEST_CASE("guardian journal: a quiescent journal emits no tags at all",
          "[guardian][journal][fleet]") {
    // The sparse-emit contract is what makes the fleet rollup's absent-not-zero
    // behaviour honest: nothing to report must produce NO tag, so the server publishes
    // no series, so a healthy/inert fleet cannot be misread as "checked, nothing lost".
    std::map<std::string, std::string> tags;
    emit_guardian_journal_heartbeat_tags(tags, GuardianJournalStats{});
    CHECK(tags.empty());

    // And a single non-zero counter emits ONLY its own tag - partial reporting stays
    // partial, it does not drag 21 fabricated zeroes along with it.
    GuardianJournalStats one;
    one.evicted_without_send_evidence = 3;
    std::map<std::string, std::string> one_tag;
    emit_guardian_journal_heartbeat_tags(one_tag, one);
    REQUIRE(one_tag.size() == 1);
    CHECK(one_tag.count("yuzu.guardian_journal_evicted_no_send_evidence") == 1);
}

TEST_CASE("guardian journal ages: emit keys bind exactly to the server MAX table",
          "[guardian][journal][fleet]") {
    std::set<std::string> table_keys;
    for (const auto& m : detail::kGuardianJournalAgeMetrics)
        table_keys.insert(m.tag);
    REQUIRE(table_keys.size() == detail::kNGuardianJournalAgeMetrics);

    // Distinct values per field, same rationale as all_nonzero_stats(): the key-set
    // checks cannot catch a page/prune value swap in the emitter, this can.
    GuardianJournalAgeStats s;
    s.page_stale_seconds = 31;
    s.prune_stale_seconds = 62;
    s.headroom_blocked_seconds = 93;
    std::map<std::string, std::string> tags;
    emit_guardian_journal_age_tags(tags, std::optional{s});

    const std::map<std::string, std::string> expected{
        {"yuzu.guardian_journal_page_stale_seconds", "31"},
        {"yuzu.guardian_journal_prune_stale_seconds", "62"},
        {"yuzu.guardian_journal_headroom_blocked_seconds", "93"},
    };
    for (const auto& [key, want] : expected) {
        INFO("tag " << key);
        REQUIRE(tags.count(key) == 1);
        CHECK(tags.at(key) == want);
    }
    CHECK(tags.size() == expected.size());

    // WRITER -> READER and READER -> WRITER, both directions, like the counter family.
    for (const auto& [key, val] : tags) {
        INFO("emitted age key not recognised by the server rollup: " << key);
        CHECK(table_keys.count(key) == 1);
    }
    for (const auto& m : detail::kGuardianJournalAgeMetrics) {
        INFO("age table key never emitted by the agent: " << m.tag);
        CHECK(tags.count(m.tag) == 1);
    }
}

TEST_CASE("guardian journal ages: gauge names follow the mechanical rule with _max",
          "[guardian][journal][fleet]") {
    // gauge == "yuzu_fleet_" + tag minus "yuzu." + "_max" - the suffix is the visible
    // marker that this family rolls up as MAX, not SUM.
    constexpr std::string_view kTagNs = "yuzu.";
    std::set<std::string> gauges;
    for (const auto& m : detail::kGuardianJournalAgeMetrics) {
        const std::string_view tag{m.tag};
        INFO("age tag not in the yuzu. heartbeat namespace: " << m.tag);
        REQUIRE(tag.substr(0, kTagNs.size()) == kTagNs);
        const std::string expected =
            "yuzu_fleet_" + std::string(tag.substr(kTagNs.size())) + "_max";
        INFO("age tag " << m.tag << " should map to gauge " << expected);
        CHECK(std::string_view(m.gauge) == expected);
        INFO("empty HELP for " << m.gauge);
        CHECK(std::string_view(m.help).size() > 0);
        gauges.insert(m.gauge);
    }
    CHECK(gauges.size() == detail::kNGuardianJournalAgeMetrics);
    // And no collision with the counter family's gauges - two tables must never fight
    // over one series.
    for (const auto& m : detail::kGuardianJournalMetrics) {
        INFO("age gauge collides with counter gauge: " << m.gauge);
        CHECK(gauges.count(m.gauge) == 0);
    }
}

TEST_CASE("guardian journal ages: emission posture - nullopt silent, zero ages emitted, "
          "blocked sparse",
          "[guardian][journal][fleet]") {
    // Dormancy is the OPTIONAL: nullopt (prefer_spark off / worker not started) ships
    // nothing - this is what keeps a pre-flip fleet from paging on a "stale" journal
    // that is deliberately inert.
    std::map<std::string, std::string> none;
    emit_guardian_journal_age_tags(none, std::optional<GuardianJournalAgeStats>{});
    CHECK(none.empty());

    // A LIVE worker with all-zero ages ships the two staleness tags AT 0 - the exact
    // opposite of the counter family's sparse rule, because a zero age is a real
    // "fresh" reading and omitting it would make a dead-idle worker read as healthy
    // idle (the item-6/item-14 gap). The blocked age stays sparse: 0 = "no episode".
    std::map<std::string, std::string> fresh;
    emit_guardian_journal_age_tags(fresh, std::optional{GuardianJournalAgeStats{}});
    REQUIRE(fresh.size() == 2);
    REQUIRE(fresh.count("yuzu.guardian_journal_page_stale_seconds") == 1);
    REQUIRE(fresh.count("yuzu.guardian_journal_prune_stale_seconds") == 1);
    CHECK(fresh.at("yuzu.guardian_journal_page_stale_seconds") == "0");
    CHECK(fresh.at("yuzu.guardian_journal_prune_stale_seconds") == "0");
    CHECK(fresh.count("yuzu.guardian_journal_headroom_blocked_seconds") == 0);

    // Blocked appears exactly when non-zero.
    GuardianJournalAgeStats blocked;
    blocked.headroom_blocked_seconds = 7;
    std::map<std::string, std::string> b;
    emit_guardian_journal_age_tags(b, std::optional{blocked});
    REQUIRE(b.size() == 3);
    CHECK(b.at("yuzu.guardian_journal_headroom_blocked_seconds") == "7");
}

TEST_CASE("parse_guardian_journal_count enforces the forged-value posture",
          "[guardian][journal][fleet]") {
    using detail::parse_guardian_journal_count;

    CHECK(parse_guardian_journal_count("0") == 0.0);
    CHECK(parse_guardian_journal_count("42") == 42.0);
    CHECK(parse_guardian_journal_count("1000000000") == 1'000'000'000.0); // exactly at the cap

    // "did not report", never 0 - the caller must be able to tell the two apart.
    CHECK_FALSE(parse_guardian_journal_count("").has_value());
    CHECK_FALSE(parse_guardian_journal_count("abc").has_value());
    CHECK_FALSE(parse_guardian_journal_count("-1").has_value());
    CHECK_FALSE(parse_guardian_journal_count("1.5").has_value());  // full-token only
    CHECK_FALSE(parse_guardian_journal_count("12x").has_value());  // trailing garbage
    CHECK_FALSE(parse_guardian_journal_count(" 12").has_value());  // leading space
    CHECK_FALSE(parse_guardian_journal_count("inf").has_value());
    CHECK_FALSE(parse_guardian_journal_count("nan").has_value());

    // Implausible -> REJECTED, not clamped. A clamped-and-counted 1.8e19 would make
    // every honest agent's contribution a no-op in the double-precision fleet sum.
    CHECK_FALSE(parse_guardian_journal_count("1000000001").has_value());
    CHECK_FALSE(parse_guardian_journal_count("18446744073709551615").has_value());
    // Over-long input is rejected in O(1) BEFORE being scanned (it runs under
    // AgentHealthStore::mu_, 22 times per agent per sweep).
    CHECK_FALSE(parse_guardian_journal_count(std::string(4096, '9')).has_value());
}
