/**
 * test_audit_retention_rules.cpp -- The retention guard's decision rule (#2360)
 *
 * `classify` is five bools in, one enum out, so its behaviour can be stated
 * EXHAUSTIVELY: all 32 inputs, each with the reason it maps where it does. That
 * is the point of extracting it. The integration tests in test_audit_store.cpp
 * cover the guard end-to-end through a seeded database; this file covers the
 * rule alone, which is where two mutations previously survived -- reaching the
 * precedence order meant standing up a multi-pass fixture, so nobody did.
 *
 * A table this complete is a mutation detector by construction: any change to
 * an operator, a return value, or the order of the five tests reddens at least
 * one row.
 */

#include <yuzu/audit_retention_rules.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

using yuzu::server::audit_retention::Anomaly;
using yuzu::server::audit_retention::classify;
using yuzu::server::audit_retention::moved_at_least;

TEST_CASE("audit classify: the whole truth table", "[audit_store][audit_rules]") {
    struct Row {
        bool has_expired;
        bool would_wipe;
        bool big_step;
        bool prev_unusable;
        bool no_anchor;
        Anomaly want;
        const char* why;
    };

    // All 2^5 = 32 inputs. `prev_unusable` first (it makes the others
    // unreliable), then `!has_expired` (nothing at risk), then step over wipe
    // (the step EXPLAINS the wipe).
    static constexpr Row kRows[] = {
        // prev_unusable dominates, whatever else is true.
        {false, false, false, true, false, Anomaly::BadState, "unusable reading, nothing expired"},
        {false, false, true, true, false, Anomaly::BadState, "unusable reading beats step"},
        {false, true, false, true, false, Anomaly::BadState, "unusable reading beats wipe"},
        {false, true, true, true, false, Anomaly::BadState, "unusable reading beats both"},
        {true, false, false, true, false, Anomaly::BadState, "unusable reading with rows expired"},
        {true, false, true, true, false, Anomaly::BadState, "unusable + step"},
        {true, true, false, true, false, Anomaly::BadState, "unusable + wipe"},
        {true, true, true, true, false, Anomaly::BadState, "unusable + step + wipe"},

        // Nothing expired: nothing is at risk, so nothing is reported. Note
        // would_wipe/big_step are still passed and still ignored -- a rule that
        // reported a step on an empty table would warn every pass on a quiet
        // server whose clock legitimately moved.
        {false, false, false, false, false, Anomaly::None, "quiet pass"},
        {false, false, true, false, false, Anomaly::None, "step but nothing to delete"},
        {false, true, false, false, false, Anomaly::None, "would-wipe with nothing expired: real when retention is off"},
        {false, true, true, false, false, Anomaly::None, "neither matters with nothing expired"},

        // Rows expired: step outranks wipe.
        {true, false, false, false, false, Anomaly::None, "ordinary expiry -- the common case"},
        {true, false, true, false, false, Anomaly::Step, "step with a survivor still reports"},
        {true, true, false, false, false, Anomaly::Wipe, "wipe with no step"},
        {true, true, true, false, false, Anomaly::Step, "step EXPLAINS the wipe, so it wins"},

        // ---- the same sixteen, with no comparison point (#2579) ----
        // `no_anchor` sits last, so it changes exactly ONE outcome. That is the
        // point of the placement and this half of the table is what pins it:
        // move the test earlier and several of these redden at once.

        // prev_unusable still dominates. Reachable in production, not academic:
        // an unusable reading is DISCARDED, which leaves the pass with no
        // comparison point, so these two facts arrive together every time
        // corrupt durable state is read.
        {false, false, false, true, true, Anomaly::BadState, "corrupt state, no anchor, nothing expired"},
        {false, false, true, true, true, Anomaly::BadState, "corrupt state beats step, no anchor"},
        {false, true, false, true, true, Anomaly::BadState, "corrupt state beats wipe, no anchor"},
        {false, true, true, true, true, Anomaly::BadState, "corrupt state beats both, no anchor"},
        {true, false, false, true, true, Anomaly::BadState, "corrupt state with rows expired, no anchor"},
        {true, false, true, true, true, Anomaly::BadState, "corrupt state + step, no anchor"},
        {true, true, false, true, true, Anomaly::BadState, "corrupt state + wipe, no anchor"},
        {true, true, true, true, true, Anomaly::BadState, "corrupt state + step + wipe, no anchor"},

        // Nothing expired: a fresh install has no anchor and nothing to lose, so
        // it must stay silent. This is the whole reason `no_anchor` is tested
        // AFTER `!has_expired` -- the alternative declines on every first boot.
        {false, false, false, false, true, Anomaly::None, "fresh install: no anchor, nothing at risk"},
        {false, false, true, false, true, Anomaly::None, "no anchor, step, nothing to delete"},
        {false, true, false, false, true, Anomaly::None, "no anchor, would-wipe, nothing expired"},
        {false, true, true, false, true, Anomaly::None, "no anchor, neither matters when nothing expired"},

        // Rows expired and no comparison point. Only the first of these differs
        // from its anchored twin -- the others already had a more specific
        // verdict to report, and `no_anchor` must not mask it.
        {true, false, false, false, true, Anomaly::NoAnchor, "#2579: the shipped gap -- everything else false, and it deleted"},
        {true, false, true, false, true, Anomaly::Step, "a step outranks having no anchor (unreachable: a step needs a reading)"},
        {true, true, false, false, true, Anomaly::Wipe, "a wipe is the more specific verdict, so it still wins"},
        {true, true, true, false, true, Anomaly::Step, "step still explains the wipe, anchor or not"},
    };

    static_assert(sizeof(kRows) / sizeof(kRows[0]) == 32, "the table must stay exhaustive");

    for (const Row& r : kRows) {
        INFO(r.why << " (has_expired=" << r.has_expired << " would_wipe=" << r.would_wipe
                   << " big_step=" << r.big_step << " prev_unusable=" << r.prev_unusable
                   << " no_anchor=" << r.no_anchor << ")");
        CHECK(classify({.has_expired = r.has_expired,
                        .would_wipe = r.would_wipe,
                        .big_step = r.big_step,
                        .prev_unusable = r.prev_unusable,
                        .no_anchor = r.no_anchor}) == r.want);
    }
}

TEST_CASE("audit classify: no_anchor changes exactly one verdict (#2579)",
          "[audit_store][audit_rules]") {
    // Stated as a property rather than left implicit in the table above: adding
    // the trigger must not disturb any verdict that was already specific. If a
    // future edit moves the `no_anchor` test earlier, this fails with a count,
    // which is a clearer signal than four scattered row failures.
    int differing = 0;
    for (int bits = 0; bits < 16; ++bits) {
        const bool has_expired = bits & 1;
        const bool would_wipe = bits & 2;
        const bool big_step = bits & 4;
        const bool prev_unusable = bits & 8;

        const Anomaly anchored = classify({.has_expired = has_expired,
                                           .would_wipe = would_wipe,
                                           .big_step = big_step,
                                           .prev_unusable = prev_unusable,
                                           .no_anchor = false});
        const Anomaly orphaned = classify({.has_expired = has_expired,
                                           .would_wipe = would_wipe,
                                           .big_step = big_step,
                                           .prev_unusable = prev_unusable,
                                           .no_anchor = true});
        if (anchored != orphaned) {
            ++differing;
            INFO("bits=" << bits);
            CHECK(anchored == Anomaly::None);
            CHECK(orphaned == Anomaly::NoAnchor);
        }
    }
    CHECK(differing == 1);
}

TEST_CASE("audit moved_at_least: magnitude in either direction, overflow-free",
          "[audit_store][audit_rules]") {
    constexpr std::int64_t kFloor = 7 * 86'400;

    SECTION("symmetric: the same movement counts whichever way it went") {
        CHECK(moved_at_least(1'000'000, 1'000'000 + kFloor, kFloor));
        CHECK(moved_at_least(1'000'000 + kFloor, 1'000'000, kFloor));
        CHECK_FALSE(moved_at_least(1'000'000, 1'000'000 + kFloor - 1, kFloor));
        CHECK_FALSE(moved_at_least(1'000'000 + kFloor - 1, 1'000'000, kFloor));
    }

    SECTION("a one-second regression is NOT an event") {
        // The BLOCKING regression this floor exists to prevent: an event forces
        // the non-deleting branch, so treating sub-floor jitter as an event
        // halts retention permanently.
        CHECK_FALSE(moved_at_least(1'000'000, 999'999, kFloor));
    }

    SECTION("recovery out of negative time is an event and does not overflow") {
        // Dead CMOS reads 1969, NTP corrects to the present. The SIGNED
        // difference of these two overflows; the magnitude must not.
        CHECK(moved_at_least(-2'000'000'000, 1'700'000'000, kFloor));

        // These are the ones that matter. INT64_MIN/2 to INT64_MAX/2 does NOT
        // overflow, so an earlier version of this section passed against a
        // signed-subtraction implementation and proved nothing. The stored
        // reading is attacker- or corruption-controlled and is only sanitised
        // AFTER this helper runs, so a genuinely extreme pair is reachable.
        CHECK(moved_at_least(INT64_MIN, INT64_MAX, kFloor));
        CHECK(moved_at_least(INT64_MAX, INT64_MIN, kFloor));
        CHECK(moved_at_least(INT64_MIN, 0, kFloor));
        CHECK(moved_at_least(INT64_MIN, INT64_MAX / 4, kFloor)); // the real bound on `now`
    }

    SECTION("no movement is not an event") {
        CHECK_FALSE(moved_at_least(1'000'000, 1'000'000, kFloor));
        CHECK_FALSE(moved_at_least(-5, -5, kFloor));
    }

    static_assert(moved_at_least(-2'000'000'000, 1'700'000'000, 7 * 86'400));
    static_assert(!moved_at_least(1'000'000, 999'999, 7 * 86'400));
}

TEST_CASE("audit classify: usable at compile time", "[audit_store][audit_rules]") {
    // `constexpr` is part of the contract, not decoration: it is what lets the
    // table above be `static constexpr` and what proves the function reads no
    // state. A future edit that reaches for a clock or a member breaks this.
    static_assert(classify({.has_expired = true, .would_wipe = true, .big_step = true}) ==
                  Anomaly::Step);
    static_assert(classify({.has_expired = true, .would_wipe = true}) == Anomaly::Wipe);
    static_assert(classify({.would_wipe = true, .big_step = true}) == Anomaly::None);
    static_assert(classify({.prev_unusable = true}) == Anomaly::BadState);
    SUCCEED("compile-time evaluation asserted above");
}
