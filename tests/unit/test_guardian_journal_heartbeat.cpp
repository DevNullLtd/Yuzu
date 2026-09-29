/**
 * test_guardian_journal_heartbeat.cpp -- the writer side of the durable lifecycle-journal
 * fleet telemetry (item 7 PR-Ag C7): the sparse-emit rule + the exact key names.
 */

#include "guardian_journal_heartbeat.hpp"

#include "guardian_arm_heartbeat.hpp"     // rung 9c PR-3: doc/emitter cross-check union
#include "guardian_backend.hpp"           // F7, #2298: doc/emitter cross-check union
#include "guardian_health_heartbeat.hpp"  // F7, #2298: doc/emitter cross-check union
#include "guardian_io_ceiling_heartbeat.hpp" // rung 9c PR-3: doc/emitter cross-check union

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>

using namespace yuzu::agent;

TEST_CASE("journal heartbeat: a quiescent journal emits NO tags (sparse)",
          "[guardian][journal][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_journal_heartbeat_tags(tags, GuardianJournalStats{});
    CHECK(tags.empty()); // every field 0 → nothing to report
}

TEST_CASE("journal heartbeat: only non-zero counters are emitted, with the pinned keys",
          "[guardian][journal][heartbeat]") {
    std::map<std::string, std::string> tags;
    GuardianJournalStats s;
    s.stage_dropped = 3;
    s.clock_rejected = 1;
    s.pending_depth = 2;
    s.evicted_without_send_evidence = 7;
    emit_guardian_journal_heartbeat_tags(tags, s);

    CHECK(tags.size() == 4);
    CHECK(tags.at("yuzu.guardian_journal_stage_dropped") == "3");
    CHECK(tags.at("yuzu.guardian_journal_clock_rejected") == "1");
    CHECK(tags.at("yuzu.guardian_journal_pending") == "2");
    CHECK(tags.at("yuzu.guardian_journal_evicted_no_send_evidence") == "7");
    // A zero field is absent, not "0".
    CHECK(tags.find("yuzu.guardian_journal_batches_written") == tags.end());
    CHECK(tags.find("yuzu.guardian_journal_write_failures") == tags.end());
}

TEST_CASE("journal heartbeat: every field has a distinct key", "[guardian][journal][heartbeat]") {
    // Every field set to a distinct non-zero value -> one distinct tag each (no key collision).
    // If a field is added without a matching put() key, or two keys collide, the size check
    // fails.
    //
    // DESIGNATED initialisers, deliberately - but be precise about what they buy. This was a
    // positional list asserting 22, and when two fields were inserted MID-STRUCT the list
    // silently stopped covering the last four - including evicted_without_send_evidence, the
    // audit-gap counter and the one field whose wire key intentionally differs from its name.
    // The test still passed while covering less than it claimed (#2345 Gate 8 consistency S1).
    //
    // Designators fix the REORDER case: a field moved within the struct can no longer silently
    // shift values onto the wrong members. They do NOT make an INSERTION a compile error - an
    // omitted designator is legal and value-initialises, with no diagnostic (Gate 8b compiled a
    // repro; an earlier version of this comment claimed otherwise). Adding a field therefore
    // still requires adding its designator here and bumping the count below by hand.
    std::map<std::string, std::string> tags;
    GuardianJournalStats s{
        .stage_dropped = 1,
        .stage_failures = 2,
        .field_rejected = 3,
        .clock_rejected = 4,
        .pending_depth = 5,
        .batches_written = 6,
        .write_failures = 7,
        .key_collisions = 8,
        .quarantined = 9,
        .quarantine_failures = 10,
        .quarantine_capacity_evicted = 11,
        .batches_pruned = 12,
        .prune_failures = 13,
        .page_read_failures = 14,
        .clock_jump_skips = 15,
        .write_capacity_rejected = 16,
        .gauge_underflow = 27,
        .journal_bytes = 17,
        .journal_batch_count = 18,
        .pages = 19,
        .records_paged = 20,
        .sent_labels_written = 21,
        .evicted_sent_unacked = 22,
        .evicted_without_send_evidence = 23,
        .evicted_unclassified = 30,
        .maint_exceptions = 24,
        .drain_exceptions = 25,
        .sweep_exceptions = 26,
        .send_exceptions = 28,
        .lifecycle_backpressure_drops = 29,
        .send_orphan_exceptions = 31,
        .send_stalls = 32,
    };
    emit_guardian_journal_heartbeat_tags(tags, s);
    CHECK(tags.size() == 32);
}

TEST_CASE("journal heartbeat: the capacity/size gauges emit under their pinned keys",
          "[guardian][journal][heartbeat]") {
    std::map<std::string, std::string> tags;
    GuardianJournalStats s;
    s.write_capacity_rejected = 4;
    s.quarantine_capacity_evicted = 5;
    s.journal_bytes = 4096;
    s.journal_batch_count = 7;
    emit_guardian_journal_heartbeat_tags(tags, s);
    CHECK(tags.size() == 4);
    CHECK(tags.at("yuzu.guardian_journal_write_capacity_rejected") == "4");
    CHECK(tags.at("yuzu.guardian_journal_quarantine_capacity_evicted") == "5");
    CHECK(tags.at("yuzu.guardian_journal_bytes") == "4096");
    CHECK(tags.at("yuzu.guardian_journal_batch_count") == "7");
}

// ---------------------------------------------------------------------------
// Doc/emitter cross-check (#2345 important-2). Same bind-or-drift idiom as the
// H2/G9 schema checks: prose written from intention and never reconciled is how
// metrics.md came to document a tag key that is never emitted, and to describe
// maint_exceptions as including convergence sweeps after they were split out.
//
// SCOPE, stated honestly: this proves NAME PRESENCE, not semantics. It cannot
// catch a row whose description is wrong - only a human can. It exists so a tag
// an operator is told to grep for is guaranteed to exist on the wire.
// ---------------------------------------------------------------------------
TEST_CASE("every documented Guardian heartbeat tag is one the emitter actually emits",
          "[guardian][journal][heartbeat][docs]") {
    // Resolve the doc without assuming the working directory: walk up from BOTH the current
    // directory and this source file's location. A cwd-dependent path here would make the
    // guard silently skip in some run configurations, which is the failure mode it exists to
    // prevent.
    const auto find_doc = []() -> std::filesystem::path {
        const std::filesystem::path rel{"docs/user-manual/metrics.md"};
        for (auto base : {std::filesystem::current_path(),
                          std::filesystem::absolute(std::filesystem::path(__FILE__))
                              .parent_path()}) {
            for (int up = 0; up < 6; ++up) {
                auto cand = base / rel;
                if (std::filesystem::exists(cand))
                    return cand;
                if (!base.has_parent_path())
                    break;
                base = base.parent_path();
            }
        }
        return {};
    };
    const std::filesystem::path doc = find_doc();
    INFO("resolved doc path: " << doc.string());
    REQUIRE_FALSE(doc.empty());

    // Everything the emitter can put on the wire, for a fully-populated stats block.
    std::map<std::string, std::string> emitted;
    GuardianJournalStats s;
    s.batches_written = s.write_failures = s.key_collisions = s.quarantined = 1;
    s.quarantine_failures = s.quarantine_capacity_evicted = s.batches_pruned = 1;
    s.prune_failures = s.write_capacity_rejected = s.pages = s.records_paged = 1;
    s.sent_labels_written = s.evicted_sent_unacked = s.evicted_without_send_evidence = 1;
    s.evicted_unclassified = 1;
    s.stage_dropped = s.stage_failures = s.field_rejected = s.clock_rejected = 1;
    s.pending_depth = s.maint_exceptions = s.drain_exceptions = s.sweep_exceptions = 1;
    s.journal_bytes = s.journal_batch_count = 1;
    s.page_read_failures = s.clock_jump_skips = s.gauge_underflow = 1;
    s.send_exceptions = s.lifecycle_backpressure_drops = 1;
    s.send_orphan_exceptions = s.send_stalls = 1;
    emit_guardian_journal_heartbeat_tags(emitted, s);
    // Union in the AGE emitter's keys (item 6 + #2364): its tags share the
    // yuzu.guardian_ namespace this check scrapes, so documenting them without this
    // union would go red here despite being correct.
    GuardianJournalAgeStats ages;
    ages.page_stale_seconds = ages.prune_stale_seconds = ages.headroom_blocked_seconds = 1;
    emit_guardian_journal_age_tags(emitted, std::optional{ages});
    // Union in the other yuzu.guardian_* heartbeat emitters too (governance finding,
    // F7/#2298): this TEST_CASE's own name promises "every documented Guardian
    // heartbeat tag", not "every documented Guardian JOURNAL heartbeat tag" - despite
    // living in this journal-focused file. Before F7, metrics.md never mentioned a
    // non-journal yuzu.guardian_* tag, so this gap was latent, never exercised; F7's
    // metrics.md edit (a yuzu.guardian_backend cross-reference in the unsupported
    // gauge's row) is what first tripped it. Closing it for the other existing
    // yuzu.guardian_*-namespaced family too, not just the one that happened to fail,
    // so a future doc edit referencing yuzu.guardian_unhealthy_* doesn't rediscover
    // the same gap.
    //
    // emit_guardian_unsupported_heartbeat_tags is deliberately NOT unioned here (Gate
    // 8 finding, F7/#2298): its wire keys are yuzu.spark_<mechanism>_unsupported, not
    // yuzu.guardian_* - this regex can never match anything it produces, so unioning
    // it would be dead code asserting a coverage claim this test cannot make. Its
    // emitter<->reader agreement is proven separately (test_spark_fleet_tags.cpp's
    // writer<->reader bind + test_guardian_unsupported_heartbeat.cpp's key pins); no
    // doc-scrape exists for yuzu.spark_* since metrics.md contains no yuzu.-prefixed
    // spark wire-key literal for a scrape to match (only the yuzu.spark_* family
    // glob; prose mentions like spark_running are unprefixed).
    emit_guardian_health_heartbeat_tags(
        emitted, GuardianHealthStats{
                     .unhealthy_suppressed = 1, .unhealthy_refreshed = 1, .priority_demoted = 1});
    emit_guardian_backend_heartbeat_tag(emitted, /*prefer_spark=*/true,
                                        GuardianEngine::SparkAvailability::SparkFailed);
    // rung 9c PR-3: union in the arm-ledger + io-ceiling emitters too - both are
    // yuzu.guardian_*-namespaced, so a future metrics.md edit referencing
    // yuzu.guardian_arm_pending or yuzu.guardian_io_arm_disarm_rejected_ceiling
    // must not rediscover this same doc/emitter gap.
    GuardianArmStats arm_s{.pending = 1, .failed = 1};
    emit_guardian_arm_heartbeat_tags(emitted, std::optional{arm_s});
    emit_guardian_io_ceiling_heartbeat_tags(emitted, 1);
    // Governance fix (Gate 8, doc-scrape false-negative): yuzu.guardian_generation is a
    // real, always-emitted heartbeat tag (agent.cpp's own inline
    // tags["yuzu.guardian_generation"] = ..., NOT one of the extracted
    // guardian_*_heartbeat.hpp emitter functions this test otherwise unions) - a
    // metrics.md doc edit mentioning it by name (the arm-gauge alerting-hazard note)
    // tripped this scrape with no way to satisfy it via an emitter call, exactly the
    // gap this test's own comments already describe closing for yuzu.guardian_backend
    // (F7/#2298). Inserted directly rather than via an emitter function since none
    // exists for this one inline tag.
    emitted["yuzu.guardian_generation"] = "1";
    REQUIRE(emitted.size() > 10); // the emitters really did populate

    std::ifstream in(doc);
    const std::string text((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());

    // Any `yuzu.guardian_*` name the DOC mentions must be one the emitter emits. This is the
    // direction that bit us: metrics.md advertised `..._evicted_without_send_evidence` (the
    // struct field) while the wire key is `..._evicted_no_send_evidence`.
    const std::regex tag_re(R"(yuzu\.guardian_[a-z_]+)");
    std::set<std::string> documented;
    for (std::sregex_iterator it(text.begin(), text.end(), tag_re), end; it != end; ++it) {
        const std::string name = it->str();
        // A trailing underscore means we captured the stem of a glob like
        // `yuzu.guardian_journal_*`, which is prose about the tag family, not a tag.
        if (!name.empty() && name.back() != '_')
            documented.insert(name);
    }
    REQUIRE_FALSE(documented.empty());

    for (const auto& name : documented) {
        INFO("metrics.md documents tag: " << name);
        CHECK(emitted.count(name) == 1);
    }
}
