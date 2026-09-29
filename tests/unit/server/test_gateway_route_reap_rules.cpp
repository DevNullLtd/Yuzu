// test_gateway_route_reap_rules.cpp — HA WS-4 slice 4.2a, PR #4299 round-3.
//
// PURE decision-layer tests for gateway_route_reap_rules.hpp's `decide_reap`
// and the two parsers (`parse_reap_i64`, `parse_declined_marker`). NO [pg], NO
// Postgres — this is the whole point of the decide/apply split: every reap
// outcome (what to do to the sweeps, the anchor, and the decline marker) is a
// value computed from raw text, checkable without a database.
//
// The integration layer — that the apply tail in gateway_route_store.cpp wires
// these decisions onto real SQL correctly — stays in test_gateway_route_store's
// [pg] suite (raw_get_reap_declined_anchor / raw_get_reap_anchor), unchanged.

#include "gateway_route_reap_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

using namespace yuzu::server;

namespace {

// This store's own implausible-skew bound (kMaxPlausibleSkewMs = 1 day). The
// pure layer takes it as a parameter; these tests pin the production value so
// the forward-skew threshold matches what reap_stale_routes passes.
constexpr std::int64_t kSkew = 24LL * 3600 * 1000;

// A plausible "now" well clear of the skew bound from the anchors below.
constexpr std::int64_t kNow = 1'000'000'000'000; // ~2001 in epoch-ms, arbitrary but positive

// The production recovery-window bounds (gateway_route_store.hpp): FLOOR
// (kStaleLeaseGraceSecs + kKnownLeaseTtlSecs) * 1000 = 270'000, CEILING 1h.
// The pure layer takes them as parameters; pin the production values here.
constexpr std::int64_t kMinGap = 270'000;    // kMinReapRecoveryGapMs
constexpr std::int64_t kMaxGap = 3'600'000;  // kMaxReapRecoveryGapMs

std::optional<std::string_view> sv(std::string_view s) { return std::optional<std::string_view>(s); }

// Build a 3-field marker "<anchor>:<direction>:<first_now_ms>".
std::string marker3(std::int64_t anchor, std::string_view dir, std::int64_t first_now_ms) {
    return std::to_string(anchor) + ":" + std::string(dir) + ":" + std::to_string(first_now_ms);
}

} // namespace

// --- decide_reap: the five-decision set -------------------------------------

TEST_CASE("decide_reap: bad now (unparseable) -> clear marker, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap("not-a-number", sv("900000000000"),
                                       sv("900000000000:forward"), kSkew, kMinGap, kMaxGap);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    CHECK_FALSE(d.new_anchor.has_value()); // anchor untouched
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: bad now (negative) -> clear marker, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap("-5", sv("900000000000"), std::nullopt, kSkew, kMinGap, kMaxGap);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: corrupt persisted anchor -> clear + re-anchor to now, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    SECTION("unparseable anchor") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv("garbage"), sv("123:backward"), kSkew, kMinGap, kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow); // re-anchored to THIS pass's now
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("negative anchor") {
        const ReapDecision d = decide_reap(std::to_string(kNow), sv("-1"), std::nullopt, kSkew, kMinGap, kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
    }
}

TEST_CASE("decide_reap: no anchor (first pass) -> clear + anchor to now + run sweeps",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap(std::to_string(kNow), std::nullopt, std::nullopt, kSkew, kMinGap, kMaxGap);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow);
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: clean pass (valid anchor, no skew) -> clear + advance to max + run sweeps",
          "[gateway_route][reap_rules]") {
    SECTION("anchor behind now -> advance to now") {
        const std::int64_t anchor = kNow - 5000;
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew, kMinGap, kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow); // max(anchor, now) == now
        CHECK(d.run_sweeps);
        CHECK_FALSE(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("anchor equal to now -> stays") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(kNow)), std::nullopt, kSkew, kMinGap, kMaxGap);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK(d.run_sweeps);
    }
    SECTION("anchor a little ahead but within skew -> NOT a backward anomaly is false; "
            "now<anchor IS backward") {
        // now just below anchor is a backward skew, NOT a clean pass — covered
        // by the backward-skew case below. Here: anchor slightly behind within
        // plausible range stays a clean advance.
        const std::int64_t anchor = kNow - 1; // now ahead by 1ms, well under skew
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew, kMinGap, kMaxGap);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK(d.run_sweeps);
        CHECK_FALSE(d.clock_anomaly);
    }
}

TEST_CASE("decide_reap: fresh forward skew, no marker -> ARM(forward), no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // now - anchor > 1 day
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "forward");
    CHECK_FALSE(d.new_anchor.has_value()); // decline never advances the anchor
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: fresh backward skew, no marker -> ARM(backward), no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow + 3600LL * 1000; // anchor ahead of now -> backward
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "backward");
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
}

TEST_CASE("decide_reap: matched (same anchor AND direction) IN-WINDOW repeat -> RECOVER, "
          "unconditional re-anchor to now, run sweeps",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    // delta = now - first_now = 300s, inside [kMinGap, kMaxGap] -> recovers.
    const std::string m = marker3(anchor, "forward", kNow - 300'000);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow); // UNCONDITIONAL now, never max(anchor, now)
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly);
    CHECK(d.recovered);
}

// --- PR #4299 round 4: the reading-continuity recovery window --------------

TEST_CASE("decide_reap: BELOW-FLOOR repeat (delta in [0, kMin)) -> decline, RE-ARM preserving the "
          "ORIGINAL first_now_ms, not recovered",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    const std::int64_t original_first = kNow - 100'000; // delta 100s < kMinGap
    const std::string m = marker3(anchor, "forward", original_first);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "forward");
    // The ORIGINAL first_now_ms is PRESERVED, never reset to now — else offset
    // replicas ticking every few seconds would reset it forever (a wedge).
    CHECK(d.marker.first_now_ms() == original_first);
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: ABOVE-CEILING repeat (delta > kMax) -> decline as a NEW anomaly, RE-ARM "
          "with now_ms, not recovered",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    const std::int64_t original_first = kNow - (kMaxGap + 1'000'000); // delta > kMaxGap
    const std::string m = marker3(anchor, "forward", original_first);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.direction() == "forward");
    // A discontinuous jump is a NEW distinct anomaly -> re-armed with THIS
    // pass's reading (now_ms), not the stale original.
    CHECK(d.marker.first_now_ms() == kNow);
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: NEGATIVE delta (marker first_now_ms AHEAD of now — a further-backward "
          "step) -> decline as a NEW anomaly, RE-ARM with now_ms",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew this pass
    const std::int64_t original_first = kNow + 5'000; // first_now ahead of now -> delta < 0
    const std::string m = marker3(anchor, "forward", original_first);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.first_now_ms() == kNow); // re-armed against this reading
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: OFFSET-REPLICA sequence — an e-later repeat declines (floor), a genuine "
          "persist recovers",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    // Arm at first_now = T (this pass's now); the store persists (anchor, fwd, T).
    const ReapDecision armed =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew, kMinGap, kMaxGap);
    REQUIRE(armed.marker.kind() == MarkerAction::Kind::Arm);
    const std::int64_t first_now = armed.marker.first_now_ms();
    CHECK(first_now == kNow);
    const std::string m = marker3(anchor, "forward", first_now);

    // A second replica ticks ~100s later (< floor): must NOT recover — no real
    // persistence evidence yet. Preserves the original first_now.
    const std::int64_t t_plus_100 = kNow + 100'000;
    const ReapDecision eps =
        decide_reap(std::to_string(t_plus_100), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(eps.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(eps.marker.first_now_ms() == first_now); // preserved
    CHECK_FALSE(eps.recovered);
    CHECK(eps.clock_anomaly);

    // A genuine persist ~300s later (in window): recovers and drains.
    const std::int64_t t_plus_300 = kNow + 300'000;
    const ReapDecision rec =
        decide_reap(std::to_string(t_plus_300), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    CHECK(rec.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(rec.new_anchor.has_value());
    CHECK(*rec.new_anchor == t_plus_300); // unconditional re-anchor to this pass's now
    CHECK(rec.run_sweeps);
    CHECK_FALSE(rec.clock_anomaly);
    CHECK(rec.recovered);
}

TEST_CASE("decide_reap: 2-field and 4-field markers are absent -> ARM fresh (mixed-version safe)",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    SECTION("2-field (legacy/old-binary) marker") {
        const std::string m = std::to_string(anchor) + ":forward"; // no first_now_ms
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m),
                                           kSkew, kMinGap, kMaxGap);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm); // absent -> re-arm in 3-field
        CHECK(d.marker.first_now_ms() == kNow);
        CHECK_FALSE(d.recovered);
    }
    SECTION("4-field marker") {
        const std::string m = std::to_string(anchor) + ":forward:" + std::to_string(kNow - 300'000) + ":extra";
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m),
                                           kSkew, kMinGap, kMaxGap);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm); // absent -> re-arm
        CHECK_FALSE(d.recovered);
    }
}

TEST_CASE("decide_reap: different-DIRECTION marker at same anchor (r2) -> ARM, not RECOVER",
          "[gateway_route][reap_rules]") {
    // The anomaly THIS pass sees is forward-skew; the marker frozen at the same
    // anchor claims "backward". Anchor matches, direction does not -> re-decline
    // (never recover) — the round-2 external-review defect this guards.
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew this pass
    // In-window first_now, so ONLY the direction mismatch (marker says backward,
    // this pass is forward) can force the decline — not the persistence window.
    const std::string m = marker3(anchor, "backward", kNow - 300'000);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.direction() == "forward"); // re-armed with THIS pass's direction
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: different-ANCHOR marker -> ARM, not RECOVER", "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    const std::int64_t other_anchor = anchor - 777;
    // In-window first_now: only the ANCHOR mismatch can force the decline.
    const std::string m = marker3(other_anchor, "forward", kNow - 300'000);
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "forward");
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: unparseable/legacy marker under a skew -> ARM (treated as absent)",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    SECTION("legacy bare-integer marker (no :direction)") {
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                           sv(std::to_string(anchor)), kSkew, kMinGap, kMaxGap);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
        CHECK(d.marker.direction() == "forward");
        CHECK_FALSE(d.recovered);
    }
    SECTION("garbage marker") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv("total-garbage"), kSkew, kMinGap, kMaxGap);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
        CHECK_FALSE(d.recovered);
    }
}

// The r3 scenario: a valid marker "A:forward" exists, but now_raw is
// negative/junk — the bad-now guard runs FIRST and CLEARs the marker, so a
// FOLLOWING forward skew at A re-arms fresh rather than free-riding the stale
// recovery identity. (The pre-fix bad-now branch LEFT the marker.)
TEST_CASE("decide_reap: bad now with a matching-looking marker present still CLEARs it (r3 fix)",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew;
    const std::string m = marker3(anchor, "forward", kNow - 300'000); // would recover if now were valid
    SECTION("junk now") {
        const ReapDecision d = decide_reap("junk", sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear); // NOT left, NOT recovered
        CHECK_FALSE(d.new_anchor.has_value());
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("negative now") {
        const ReapDecision d = decide_reap("-1", sv(std::to_string(anchor)), sv(m), kSkew, kMinGap, kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        CHECK_FALSE(d.recovered);
    }
}

// --- parse_reap_i64: the from_chars malformed-input matrix -------------------

TEST_CASE("parse_reap_i64: canonical integers accepted", "[gateway_route][reap_rules]") {
    CHECK(parse_reap_i64("0") == std::optional<std::int64_t>(0));
    CHECK(parse_reap_i64("5") == std::optional<std::int64_t>(5));
    CHECK(parse_reap_i64("-5") == std::optional<std::int64_t>(-5));
    CHECK(parse_reap_i64("1000000000000") == std::optional<std::int64_t>(1000000000000));
}

TEST_CASE("parse_reap_i64: non-canonical / malformed rejected", "[gateway_route][reap_rules]") {
    CHECK_FALSE(parse_reap_i64("").has_value());         // empty
    CHECK_FALSE(parse_reap_i64(" 5").has_value());       // leading ws
    CHECK_FALSE(parse_reap_i64("5 ").has_value());       // trailing ws
    CHECK_FALSE(parse_reap_i64("+5").has_value());       // leading +
    CHECK_FALSE(parse_reap_i64("007").has_value());      // zero-padded (non-canonical)
    CHECK_FALSE(parse_reap_i64("-0").has_value());       // negative zero (non-canonical)
    CHECK_FALSE(parse_reap_i64("123abc").has_value());   // trailing garbage
    CHECK_FALSE(parse_reap_i64("1.5").has_value());      // not an integer
    CHECK_FALSE(parse_reap_i64("abc").has_value());      // not a number
    CHECK_FALSE(parse_reap_i64("5:forward").has_value()); // the whole marker, not a bare int
}

// --- parse_declined_marker: the marker-format matrix ------------------------

TEST_CASE("parse_declined_marker: well-formed 3-field markers accepted", "[gateway_route][reap_rules]") {
    auto f = parse_declined_marker("42:forward:1000");
    REQUIRE(f.has_value());
    CHECK(f->anchor == 42);
    CHECK(f->direction == "forward");
    CHECK(f->first_now_ms == 1000);

    auto b = parse_declined_marker("1000000000000:backward:2000000000000");
    REQUIRE(b.has_value());
    CHECK(b->anchor == 1000000000000);
    CHECK(b->direction == "backward");
    CHECK(b->first_now_ms == 2000000000000);

    auto zero = parse_declined_marker("0:forward:0");
    REQUIRE(zero.has_value());
    CHECK(zero->anchor == 0);
    CHECK(zero->first_now_ms == 0);
}

TEST_CASE("parse_declined_marker: malformed markers treated as absent",
          "[gateway_route][reap_rules]") {
    CHECK_FALSE(parse_declined_marker("").has_value());              // empty
    CHECK_FALSE(parse_declined_marker("42").has_value());            // no colon
    CHECK_FALSE(parse_declined_marker("42:forward").has_value());    // 2-field (legacy/old-binary)
    CHECK_FALSE(parse_declined_marker("42:sideways:1000").has_value()); // bad direction token
    CHECK_FALSE(parse_declined_marker("42:FORWARD:1000").has_value());  // case-sensitive
    CHECK_FALSE(parse_declined_marker("42::1000").has_value());       // empty direction
    CHECK_FALSE(parse_declined_marker(":forward:1000").has_value());  // empty anchor
    CHECK_FALSE(parse_declined_marker("-5:forward:1000").has_value()); // negative anchor rejected
    CHECK_FALSE(parse_declined_marker("42:forward:-5").has_value());  // negative first_now_ms rejected
    CHECK_FALSE(parse_declined_marker("007:forward:1000").has_value()); // non-canonical anchor
    CHECK_FALSE(parse_declined_marker("42:forward:007").has_value()); // non-canonical first_now_ms
    CHECK_FALSE(parse_declined_marker(" 5:forward:1000").has_value()); // leading ws on anchor
    CHECK_FALSE(parse_declined_marker("42:forward:1000:extra").has_value()); // 4-field
    CHECK_FALSE(parse_declined_marker("42:forward:").has_value());    // empty first_now_ms
    CHECK_FALSE(parse_declined_marker("abc:forward:1000").has_value()); // non-numeric anchor
    CHECK_FALSE(parse_declined_marker("42:forward:abc").has_value()); // non-numeric first_now_ms
}

TEST_CASE("decide_reap: a negative skew bound is clamped to 0 (cannot invert the clean path)",
          "[gateway_route][reap_rules]") {
    // Defensive clamp: an unclamped negative max_plausible_skew_ms would make
    // now==anchor read as forward-skew (0 > -1) — a spurious decline on an
    // otherwise-clean pass. The entry clamp (<0 -> 0) keeps now==anchor clean.
    // Discriminating: without the clamp these CHECK_FALSEs flip (arm + anomaly).
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(kNow)), std::nullopt, -1, kMinGap, kMaxGap);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow);
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly); // clamp present: clean pass, not a forward-skew decline
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: negative recovery-gap bounds are clamped to 0",
          "[gateway_route][reap_rules]") {
    // Parity with the skew-bound clamp above (quality-engineer governance fold):
    // the recovery-window bounds get the same entry clamp (<0 -> 0). The
    // production caller passes positive compile-time constants whose ordering a
    // static_assert enforces, but this is a public pure helper a future/mis-wired
    // caller could hand a negative bound.
    //
    // A same-(anchor, direction) forward-skew repeat whose reading has NOT
    // advanced since first observation (delta == 0) is the discriminating input.
    const std::int64_t anchor = kNow - 2 * kSkew;      // forward skew, well past kSkew
    const std::string m = marker3(anchor, "forward", kNow); // first_now_ms == now -> delta 0

    SECTION("max_recovery_gap clamp discriminates") {
        // Both bounds negative -> both clamp to 0. delta 0 is then NOT > max(0)
        // and NOT < min(0), so it lands in the (degenerate) recover window.
        // WITHOUT the max clamp (max = -1) the very same delta 0 would be
        // `> -1` and re-arm as a brand-new anomaly instead — so this flips if
        // the clamp is removed.
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                           sv(m), kSkew, /*min*/ -1, /*max*/ -1);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK(d.run_sweeps);
        CHECK_FALSE(d.clock_anomaly);
        CHECK(d.recovered); // clamped: recover, not a fresh-anomaly decline
    }

    SECTION("min_recovery_gap clamp is defense-in-depth (unobservable on delta >= 0)") {
        // The `delta < 0` case is caught by the SAME OR-clause as the ceiling, so
        // by the time `delta < min` is evaluated delta is always >= 0. A negative
        // min and a clamped-0 min therefore decide identically for every reachable
        // delta — the clamp cannot be discriminated, and this asserts the outcome
        // is the documented one rather than claiming a discrimination that does
        // not exist. delta 0 with a positive ceiling still recovers (min <= 0).
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                           sv(m), kSkew, /*min*/ -1, /*max*/ kMaxGap);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        CHECK(d.run_sweeps);
        CHECK(d.recovered);
    }
}
