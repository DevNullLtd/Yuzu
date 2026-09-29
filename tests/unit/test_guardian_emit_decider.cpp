// test_guardian_emit_decider.cpp - the shared compliant-edge + drift-debounce
// decision tail (ADR-0021 rung 2 slice 2b). Clock-injected, so fully deterministic.

#include "guardian_emit_decider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>

using yuzu::agent::decide_emit;
using yuzu::agent::EmitDeciderState;
using yuzu::agent::EmitKind;

namespace {
using clock = std::chrono::steady_clock;
constexpr clock::time_point kBase{}; // epoch of the steady clock, deterministic
clock::time_point at_ms(std::uint64_t ms) { return kBase + std::chrono::milliseconds(ms); }
} // namespace

TEST_CASE("decide_emit: first compliant observation is a compliant edge", "[spark][decider]") {
    EmitDeciderState s;
    const auto r = decide_emit(/*compliant=*/true, s, 1000, at_ms(0));
    REQUIRE(r.kind == EmitKind::CompliantEdge);
    // Steady compliant thereafter is silent.
    REQUIRE(decide_emit(true, s, 1000, at_ms(10)).kind == EmitKind::Silent);
}

TEST_CASE("decide_emit: emit_compliant_edge=false keeps compliant silent (systemd parity)",
          "[spark][decider]") {
    EmitDeciderState s;
    REQUIRE(decide_emit(true, s, 1000, at_ms(0), /*emit_compliant_edge=*/false).kind ==
            EmitKind::Silent);
    // last_compliant still commits, so a later drift is a real change.
    REQUIRE(decide_emit(false, s, 1000, at_ms(10), false).kind == EmitKind::Drift);
}

TEST_CASE("decide_emit: first drift emits immediately with zero collapsed", "[spark][decider]") {
    EmitDeciderState s;
    const auto r = decide_emit(false, s, 1000, at_ms(0));
    REQUIRE(r.kind == EmitKind::Drift);
    REQUIRE(r.collapsed_count == 0);
}

TEST_CASE("decide_emit: drifts within the debounce window fold into a collapsed count",
          "[spark][decider]") {
    EmitDeciderState s;
    REQUIRE(decide_emit(false, s, 1000, at_ms(0)).kind == EmitKind::Drift); // emit at t=0
    // Three more drifts inside the 1000ms window are folded, not emitted.
    REQUIRE(decide_emit(false, s, 1000, at_ms(200)).kind == EmitKind::Silent);
    REQUIRE(decide_emit(false, s, 1000, at_ms(400)).kind == EmitKind::Silent);
    REQUIRE(decide_emit(false, s, 1000, at_ms(600)).kind == EmitKind::Silent);
    // The next drift past the window emits, carrying the three folded ones.
    const auto r = decide_emit(false, s, 1000, at_ms(1500));
    REQUIRE(r.kind == EmitKind::Drift);
    REQUIRE(r.collapsed_count == 3);
    // And the count resets after an emit.
    REQUIRE(decide_emit(false, s, 1000, at_ms(3000)).collapsed_count == 0);
}

TEST_CASE("decide_emit: a suppressed drift does not move the debounce anchor", "[spark][decider]") {
    // Commit-rule check: last_emit stays at the last EMIT, not the last suppressed
    // drift, so the window is measured from the emit.
    EmitDeciderState s;
    REQUIRE(decide_emit(false, s, 1000, at_ms(0)).kind == EmitKind::Drift); // anchor at 0
    REQUIRE(decide_emit(false, s, 1000, at_ms(900)).kind == EmitKind::Silent); // folded (< 1000 from 0)
    // 1100 is >1000 from the ANCHOR (0), not from the suppressed 900, so it emits.
    REQUIRE(decide_emit(false, s, 1000, at_ms(1100)).kind == EmitKind::Drift);
}

TEST_CASE("decide_emit: re-drift after a compliant recovery is a fresh emit", "[spark][decider]") {
    EmitDeciderState s;
    REQUIRE(decide_emit(false, s, 1000, at_ms(0)).kind == EmitKind::Drift);
    REQUIRE(decide_emit(true, s, 1000, at_ms(5000)).kind == EmitKind::CompliantEdge); // recovered
    // A drift long after recovery emits (window measured from the old emit at 0).
    REQUIRE(decide_emit(false, s, 1000, at_ms(10000)).kind == EmitKind::Drift);
    // Recovering again re-arms the compliant edge.
    REQUIRE(decide_emit(true, s, 1000, at_ms(11000)).kind == EmitKind::CompliantEdge);
}

TEST_CASE("decide_emit: zero debounce emits every drift", "[spark][decider]") {
    EmitDeciderState s;
    REQUIRE(decide_emit(false, s, 0, at_ms(0)).kind == EmitKind::Drift);
    REQUIRE(decide_emit(false, s, 0, at_ms(0)).kind == EmitKind::Drift); // same instant, still emits
    REQUIRE(decide_emit(false, s, 0, at_ms(1)).collapsed_count == 0);
}
