/**
 * test_clock_drift_monitor.cpp -- ClockDriftMonitor (HA WS-1/1a, ADR-2002 §4
 * mitigation (a)). Pure unit tests (no PG / no maintenance thread) — this is the
 * clock-injectable seam whose absence let the round-2 stopped-clock false-negative
 * ship (adversarial-round #2/#3 C1).
 */

#include "clock_drift_monitor.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::ClockDriftMonitor;

TEST_CASE("ClockDriftMonitor: a healthy clock (wall tracks monotonic) never fires",
          "[clock][sessions]") {
    ClockDriftMonitor m{3000};
    std::int64_t wall = 1'000'000, steady = 5'000'000;
    CHECK_FALSE(m.observe(wall, steady)); // baseline seed
    for (int i = 0; i < 100; ++i) {
        wall += 2000;
        steady += 2000; // both advance equally
        CHECK_FALSE(m.observe(wall, steady));
    }
}

TEST_CASE("ClockDriftMonitor: a STOPPED wall clock accumulates and fires (the C1 falsifier)",
          "[clock][sessions]") {
    // Codex's exact falsifier: repeated 2s monotonic advances with ZERO wall
    // advance must increment the anomaly signal — a per-sample-tolerance detector
    // that re-baselined each tick would never fire here.
    ClockDriftMonitor m{3000};
    std::int64_t wall = 1'000'000, steady = 5'000'000;
    REQUIRE_FALSE(m.observe(wall, steady)); // baseline
    // steady advances 2s/tick, wall frozen. Cumulative drift crosses 3s after 2
    // ticks (4s), so it fires on the 2nd post-baseline observation, then again
    // each time another tolerance-worth accumulates.
    int fires = 0;
    for (int i = 0; i < 10; ++i) {
        steady += 2000; // wall unchanged
        if (m.observe(wall, steady))
            ++fires;
    }
    CHECK(fires > 0);          // a stopped clock is NOT silent
    CHECK(fires >= 5);         // ~once per 2 ticks of 2s over a 20s stall
}

TEST_CASE("ClockDriftMonitor: a single backward step larger than tolerance fires once",
          "[clock][sessions]") {
    ClockDriftMonitor m{3000};
    REQUIRE_FALSE(m.observe(1'000'000, 5'000'000));
    // steady +2s, wall jumps back 5s (net offset drop 7s > 3s tolerance).
    CHECK(m.observe(1'000'000 - 5000, 5'002'000));
    // Healthy afterwards (both advance equally) → no further fires.
    CHECK_FALSE(m.observe(1'000'000 - 5000 + 2000, 5'004'000));
}

TEST_CASE("ClockDriftMonitor: a slow negative slew below per-sample tolerance still fires cumulatively",
          "[clock][sessions]") {
    // Each tick wall advances 1.5s while monotonic advances 2s — a 0.5s/tick
    // negative slew, below the 3s tolerance per sample, but cumulative.
    ClockDriftMonitor m{3000};
    std::int64_t wall = 0, steady = 0;
    REQUIRE_FALSE(m.observe(wall, steady));
    int fires = 0;
    for (int i = 0; i < 40; ++i) {
        wall += 1500;
        steady += 2000; // 500ms/tick behind
        if (m.observe(wall, steady))
            ++fires;
    }
    CHECK(fires > 0); // cumulative slow slew is caught, not lost to per-sample tolerance
}

TEST_CASE("ClockDriftMonitor: a forward wall jump does not fire and rebaselines",
          "[clock][sessions]") {
    ClockDriftMonitor m{3000};
    REQUIRE_FALSE(m.observe(0, 0));
    CHECK_FALSE(m.observe(100'000, 2000)); // wall jumps forward 100s — not a hazard here
    // From the new (higher) baseline, a healthy clock still doesn't fire…
    CHECK_FALSE(m.observe(102'000, 4000));
    // …but a subsequent backward drift past tolerance, measured from the adopted
    // baseline, still fires.
    CHECK(m.observe(102'000, 10'000)); // wall frozen 6s while monotonic +6s
}
