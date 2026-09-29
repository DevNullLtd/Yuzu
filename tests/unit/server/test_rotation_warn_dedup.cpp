// Cadence contract for the rotation successor-unused warning.
//
// This exists because the behaviour it pins previously lived inline in a
// thread lambda inside `ServerImpl` and was therefore untestable — which is
// how an audit row that fires every 60s forever, into the SOC 2 evidence
// store, reached review. The assertions below are about CADENCE, not about
// std::unordered_set: each one names a tick sequence and the signals that must
// come out of it.

#include "rotation_warn_dedup.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>

using yuzu::server::RotationWarnDedup;

namespace {
constexpr const char* kGroup = "successor-token-abc";
constexpr const char* kOther = "successor-token-xyz";
} // namespace

TEST_CASE("pre-elapse warning records exactly once per rotation attempt", "[rotation][warn]") {
    RotationWarnDedup d;

    const auto first = d.observe(kGroup, /*elapsed=*/false);
    CHECK(first.record_event);
    CHECK_FALSE(first.log); // nothing is logged while the pair is still on schedule

    // Nine more ticks inside the lead-time window produce nothing at all.
    for (int i = 0; i < 9; ++i) {
        const auto again = d.observe(kGroup, /*elapsed=*/false);
        CHECK_FALSE(again.record_event);
        CHECK_FALSE(again.log);
    }
}

TEST_CASE("an elapsed pair logs every tick but records only once", "[rotation][warn]") {
    RotationWarnDedup d;

    const auto first = d.observe(kGroup, /*elapsed=*/true);
    CHECK(first.log);
    CHECK(first.record_event);

    // The regression this file exists for: 1439 further ticks in a day must
    // produce 1439 log lines and ZERO further audit rows / counter increments.
    int logs = 0, records = 0;
    for (int i = 0; i < 1439; ++i) {
        const auto s = d.observe(kGroup, /*elapsed=*/true);
        logs += s.log ? 1 : 0;
        records += s.record_event ? 1 : 0;
    }
    CHECK(logs == 1439);
    CHECK(records == 0);
}

TEST_CASE("crossing into the elapsed state records a second, distinct event",
          "[rotation][warn]") {
    RotationWarnDedup d;

    CHECK(d.observe(kGroup, /*elapsed=*/false).record_event); // lead-time heads-up
    CHECK_FALSE(d.observe(kGroup, /*elapsed=*/false).record_event);

    // The window elapses. This is a genuinely new fact — the sweep has now
    // DECLINED to auto-revoke — so it must not be swallowed by the pre-elapse
    // de-dup. The two states are tracked separately for exactly this.
    const auto crossed = d.observe(kGroup, /*elapsed=*/true);
    CHECK(crossed.record_event);
    CHECK(crossed.log);
    CHECK_FALSE(d.observe(kGroup, /*elapsed=*/true).record_event);
}

TEST_CASE("resolving a pair frees it so a later rotation warns again", "[rotation][warn]") {
    RotationWarnDedup d;

    REQUIRE(d.observe(kGroup, /*elapsed=*/true).record_event);
    REQUIRE_FALSE(d.observe(kGroup, /*elapsed=*/true).record_event);

    d.resolve(kGroup); // revoked, confirmed, or the successor was finally used
    CHECK(d.tracked_elapsed() == 0);
    CHECK(d.tracked_pre_elapse() == 0);

    // A later rotation on the same principal reuses the group id and must be
    // warned about on its own merits, not silenced by the previous attempt.
    CHECK(d.observe(kGroup, /*elapsed=*/false).record_event);
}

TEST_CASE("prune drops only groups absent from the tick's live set", "[rotation][warn]") {
    RotationWarnDedup d;
    REQUIRE(d.observe(kGroup, /*elapsed=*/true).record_event);
    REQUIRE(d.observe(kOther, /*elapsed=*/false).record_event);
    REQUIRE(d.tracked_elapsed() == 1);
    REQUIRE(d.tracked_pre_elapse() == 1);

    d.prune(std::unordered_set<std::string>{kGroup}); // kOther resolved this tick
    CHECK(d.tracked_elapsed() == 1);
    CHECK(d.tracked_pre_elapse() == 0);

    // Still-tracked: no new record. Pruned: warns again.
    CHECK_FALSE(d.observe(kGroup, /*elapsed=*/true).record_event);
    CHECK(d.observe(kOther, /*elapsed=*/false).record_event);

    d.prune(std::unordered_set<std::string>{}); // both gone
    CHECK(d.tracked_elapsed() == 0);
    CHECK(d.tracked_pre_elapse() == 0);
}

TEST_CASE("two stuck pairs are de-duplicated independently", "[rotation][warn]") {
    RotationWarnDedup d;
    CHECK(d.observe(kGroup, /*elapsed=*/true).record_event);
    CHECK(d.observe(kOther, /*elapsed=*/true).record_event); // not silenced by kGroup
    CHECK_FALSE(d.observe(kGroup, /*elapsed=*/true).record_event);
    CHECK_FALSE(d.observe(kOther, /*elapsed=*/true).record_event);
    CHECK(d.tracked_elapsed() == 2);
}
