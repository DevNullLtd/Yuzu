/**
 * test_guardian_health_heartbeat.cpp -- the writer side of the Guardian health-stream fleet
 * telemetry (M1): the sparse-emit rule + the exact PINNED key name. A one-character drift here
 * would silently produce a zero fleet gauge at the #2298 server-side rollup, so this test locks
 * the wire key.
 */

#include "guardian_health_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
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

TEST_CASE("health heartbeat: non-zero Disarm deadline count emits the pinned key + value (#5403)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.disarm_deadline_elapsed = 3});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_disarm_deadline_elapsed") == "3");
    CHECK(std::string(kGuardianDisarmDeadlineElapsedTag) ==
          "yuzu.guardian_disarm_deadline_elapsed");
}

TEST_CASE("health heartbeat: zero Disarm deadline count omits the tag (sparse, #5403)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.disarm_deadline_elapsed = 0});
    CHECK(tags.empty());
}

TEST_CASE("health heartbeat: non-zero compensation deadline count emits the pinned key + value "
          "(#4472)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags,
                                        GuardianHealthStats{.compensation_deadline_elapsed = 4});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_compensation_deadline_elapsed") == "4");
    CHECK(std::string(kGuardianCompensationDeadlineElapsedTag) ==
          "yuzu.guardian_compensation_deadline_elapsed");

    std::map<std::string, std::string> none;
    emit_guardian_health_heartbeat_tags(none,
                                        GuardianHealthStats{.compensation_deadline_elapsed = 0});
    CHECK(none.empty()); // sparse
}

TEST_CASE("health heartbeat: outstanding compensation age is absent for nullopt and present "
          "otherwise, floored seconds (#4472)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_compensation_pending_age_tag(tags, std::nullopt);
    CHECK(tags.empty()); // never a 0 for "none outstanding"

    emit_guardian_compensation_pending_age_tag(tags, std::optional<std::uint64_t>{23});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_compensation_pending_age_seconds") == "23");
    CHECK(std::string(kGuardianCompensationPendingAgeTag) ==
          "yuzu.guardian_compensation_pending_age_seconds");

    // Outstanding for under a second is a real reading: present, value 0.
    std::map<std::string, std::string> young;
    emit_guardian_compensation_pending_age_tag(young, std::optional<std::uint64_t>{0});
    CHECK(young.size() == 1);
    CHECK(young.at("yuzu.guardian_compensation_pending_age_seconds") == "0");

    // The two age emitters are independent: neither writes the other's key.
    std::map<std::string, std::string> disarm_only;
    emit_guardian_disarm_pending_age_tag(disarm_only, std::optional<std::uint64_t>{5});
    CHECK(disarm_only.count("yuzu.guardian_compensation_pending_age_seconds") == 0);
}

TEST_CASE("health heartbeat: pending Disarm age is absent for nullopt and present otherwise "
          "(#5403)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_disarm_pending_age_tag(tags, std::nullopt);
    CHECK(tags.empty()); // never a 0 for "none pending"

    emit_guardian_disarm_pending_age_tag(tags, std::optional<std::uint64_t>{17});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_disarm_pending_age_seconds") == "17");
    CHECK(std::string(kGuardianDisarmPendingAgeTag) == "yuzu.guardian_disarm_pending_age_seconds");

    // A pending Disarm younger than a second is a real reading: present, value 0.
    std::map<std::string, std::string> young;
    emit_guardian_disarm_pending_age_tag(young, std::optional<std::uint64_t>{0});
    CHECK(young.size() == 1);
    CHECK(young.at("yuzu.guardian_disarm_pending_age_seconds") == "0");
}

namespace {

/// #5404: every Spark claim-lifecycle field with its OWN distinct non-zero value (9..19, after
/// the eight earlier counters' 1..8; #4472's compensation count is 20), so a swapped field in
/// the emitter or in the runtime mapping shows up as a wrong value rather than a still-equal
/// key set.
GuardianHealthStats all_nineteen_stats() {
    return GuardianHealthStats{.unhealthy_suppressed = 1,
                               .unhealthy_refreshed = 2,
                               .priority_demoted = 3,
                               .outbox_backpressure_drops = 4,
                               .legacy_sink_events_lost = 5,
                               .legacy_sink_gap_rules = 6,
                               .legacy_sink_dropped_unwired = 7,
                               .disarm_deadline_elapsed = 8,
                               .compensation_deadline_elapsed = 20,
                               .orphan_disarms_started = 9,
                               .dead_watchers_erased_on_lost = 10,
                               .tombstones_released_by_reaper = 11,
                               .claim_index_release_failures = 12,
                               .claim_drain_failures = 13,
                               .retained_tombstones = 14,
                               .detach_sweep_left_residue = 15,
                               .detach_claim_failures = 16,
                               .detach_post_commit_failures = 17,
                               .claims_dropped_at_stop = 18,
                               .ack_maint_exceptions = 19};
}

/// One #5404 field: the pointer-to-member that carries it, the pinned wire key literal, and the
/// shared constant the agent and the tests both name.
struct ClaimField {
    std::uint64_t GuardianHealthStats::*member;
    const char* literal; ///< spelled out here so a constant rename cannot make the test vacuous
    const char* constant;
};

const ClaimField kClaimFields[] = {
    {&GuardianHealthStats::orphan_disarms_started, "yuzu.guardian_orphan_disarms_started",
     kGuardianOrphanDisarmsStartedTag},
    {&GuardianHealthStats::dead_watchers_erased_on_lost,
     "yuzu.guardian_dead_watchers_erased_on_lost", kGuardianDeadWatchersErasedOnLostTag},
    {&GuardianHealthStats::tombstones_released_by_reaper,
     "yuzu.guardian_tombstones_released_by_reaper", kGuardianTombstonesReleasedByReaperTag},
    {&GuardianHealthStats::claim_index_release_failures,
     "yuzu.guardian_claim_index_release_failures", kGuardianClaimIndexReleaseFailuresTag},
    {&GuardianHealthStats::claim_drain_failures, "yuzu.guardian_claim_drain_failures",
     kGuardianClaimDrainFailuresTag},
    {&GuardianHealthStats::retained_tombstones, "yuzu.guardian_retained_tombstones",
     kGuardianRetainedTombstonesTag},
    {&GuardianHealthStats::detach_sweep_left_residue, "yuzu.guardian_detach_sweep_left_residue",
     kGuardianDetachSweepLeftResidueTag},
    {&GuardianHealthStats::detach_claim_failures, "yuzu.guardian_detach_claim_failures",
     kGuardianDetachClaimFailuresTag},
    {&GuardianHealthStats::detach_post_commit_failures,
     "yuzu.guardian_detach_post_commit_failures", kGuardianDetachPostCommitFailuresTag},
    {&GuardianHealthStats::claims_dropped_at_stop, "yuzu.guardian_claims_dropped_at_stop",
     kGuardianClaimsDroppedAtStopTag},
    {&GuardianHealthStats::ack_maint_exceptions, "yuzu.guardian_ack_maint_exceptions",
     kGuardianAckMaintExceptionsTag},
};

} // namespace

TEST_CASE("health heartbeat: each #5404 claim-lifecycle field emits only its own pinned key "
          "when non-zero, and nothing when zero (sparse)",
          "[guardian][health][heartbeat][claim]") {
    for (const auto& f : kClaimFields) {
        INFO("key " << f.literal);
        CHECK(std::string(f.constant) == f.literal); // the shared constant is the pinned string

        GuardianHealthStats on;
        on.*(f.member) = 21;
        std::map<std::string, std::string> tags;
        emit_guardian_health_heartbeat_tags(tags, on);
        REQUIRE(tags.size() == 1);
        REQUIRE(tags.count(f.literal) == 1);
        CHECK(tags.at(f.literal) == "21");

        GuardianHealthStats off;
        off.*(f.member) = 0;
        std::map<std::string, std::string> none;
        emit_guardian_health_heartbeat_tags(none, off);
        CHECK(none.empty()); // sparse: 0 omits the tag, never a fabricated 0
    }
}

TEST_CASE("health heartbeat: all twenty counters independent and additive",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, all_nineteen_stats());
    CHECK(tags.size() == 20);
    CHECK(tags.at("yuzu.guardian_compensation_deadline_elapsed") == "20"); // #4472
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "1");
    CHECK(tags.at("yuzu.guardian_unhealthy_refreshed") == "2");
    CHECK(tags.at("yuzu.guardian_priority_demoted") == "3");
    CHECK(tags.at("yuzu.guardian_outbox_backpressure_drops") == "4");
    CHECK(tags.at("yuzu.guardian_legacy_sink_events_lost") == "5");
    CHECK(tags.at("yuzu.guardian_legacy_sink_gap_rules") == "6");
    CHECK(tags.at("yuzu.guardian_legacy_sink_dropped_unwired") == "7");
    CHECK(tags.at("yuzu.guardian_disarm_deadline_elapsed") == "8");
    // #5404: each carries its OWN value, so a swap between any two emitter lines is red.
    CHECK(tags.at("yuzu.guardian_orphan_disarms_started") == "9");
    CHECK(tags.at("yuzu.guardian_dead_watchers_erased_on_lost") == "10");
    CHECK(tags.at("yuzu.guardian_tombstones_released_by_reaper") == "11");
    CHECK(tags.at("yuzu.guardian_claim_index_release_failures") == "12");
    CHECK(tags.at("yuzu.guardian_claim_drain_failures") == "13");
    CHECK(tags.at("yuzu.guardian_retained_tombstones") == "14");
    CHECK(tags.at("yuzu.guardian_detach_sweep_left_residue") == "15");
    CHECK(tags.at("yuzu.guardian_detach_claim_failures") == "16");
    CHECK(tags.at("yuzu.guardian_detach_post_commit_failures") == "17");
    CHECK(tags.at("yuzu.guardian_claims_dropped_at_stop") == "18");
    CHECK(tags.at("yuzu.guardian_ack_maint_exceptions") == "19");
}

namespace {

/// A stand-in with the eleven GuardianSparkRuntime accessors guardian_spark_claim_health_stats
/// reads, each returning its own distinct value. Distinct values are the point: the mapping
/// function is the ONE place a runtime accessor is bound to a health field, so a swapped pair
/// there (detach_claim_failures reading detach_sweep_left_residue) is observable here and in no
/// other test. The real runtime's accessors are bound at compile time (the template is
/// instantiated against it by GuardianEngine::spark_claim_health_stats).
struct FakeClaimRuntime {
    std::uint64_t orphan_disarms_started() const noexcept { return 101; }
    std::uint64_t dead_watchers_erased_on_lost() const noexcept { return 102; }
    std::uint64_t tombstones_released_by_reaper() const noexcept { return 103; }
    std::uint64_t claim_index_release_failures() const noexcept { return 104; }
    std::uint64_t claim_drain_failures() const noexcept { return 105; }
    std::size_t retained_tombstones() const { return 106; }
    std::uint64_t detach_sweep_left_residue() const noexcept { return 107; }
    std::uint64_t detach_claim_failures() const noexcept { return 108; }
    std::uint64_t detach_post_commit_failures() const noexcept { return 109; }
    std::uint64_t claims_dropped_at_stop() const noexcept { return 110; }
    std::uint64_t compensation_deadline_elapsed() const noexcept { return 111; } // #4472
};

} // namespace

TEST_CASE("health heartbeat: guardian_spark_claim_health_stats binds every runtime accessor "
          "to its own field (#5404)",
          "[guardian][health][heartbeat][claim]") {
    const auto s = guardian_spark_claim_health_stats(FakeClaimRuntime{});
    CHECK(s.orphan_disarms_started == 101);
    CHECK(s.dead_watchers_erased_on_lost == 102);
    CHECK(s.tombstones_released_by_reaper == 103);
    CHECK(s.claim_index_release_failures == 104);
    CHECK(s.claim_drain_failures == 105);
    CHECK(s.retained_tombstones == 106);
    CHECK(s.detach_sweep_left_residue == 107);
    CHECK(s.detach_claim_failures == 108);
    CHECK(s.detach_post_commit_failures == 109);
    CHECK(s.claims_dropped_at_stop == 110);
    CHECK(s.compensation_deadline_elapsed == 111);
    // Only the runtime's eleven: every earlier counter and the engine-owned ack_maint_exceptions
    // stay 0, so a second emit of this struct adds nothing to the first emit's tags.
    CHECK(s.unhealthy_suppressed == 0);
    CHECK(s.unhealthy_refreshed == 0);
    CHECK(s.priority_demoted == 0);
    CHECK(s.outbox_backpressure_drops == 0);
    CHECK(s.legacy_sink_events_lost == 0);
    CHECK(s.legacy_sink_gap_rules == 0);
    CHECK(s.legacy_sink_dropped_unwired == 0);
    CHECK(s.disarm_deadline_elapsed == 0);
    CHECK(s.ack_maint_exceptions == 0);

    // Through the emitter, each lands under its own key with its own value.
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, s);
    CHECK(tags.size() == 11);
    CHECK(tags.at("yuzu.guardian_compensation_deadline_elapsed") == "111");
    CHECK(tags.at("yuzu.guardian_orphan_disarms_started") == "101");
    CHECK(tags.at("yuzu.guardian_detach_sweep_left_residue") == "107");
    CHECK(tags.at("yuzu.guardian_detach_claim_failures") == "108");
    CHECK(tags.at("yuzu.guardian_claims_dropped_at_stop") == "110");
}
