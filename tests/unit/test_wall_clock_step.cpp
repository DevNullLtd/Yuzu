/**
 * test_wall_clock_step.cpp -- unit tests for agents/shared/wall_clock_step.hpp: the
 * consecutive-sample forward-step guard. Pure and portable: samples are injected, no
 * real clock is read, so it runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <wall_clock_step.hpp>

namespace shared = yuzu::shared;

namespace {
constexpr std::int64_t kTol = 60;
constexpr std::int64_t kQ = 3600;
} // namespace

TEST_CASE("stepped_forward: strictly greater than tolerance", "[wall_clock_step]") {
    const shared::ClockSample prev{1000, 50};
    // Wall advanced 60 s more than steady: exactly at tolerance, not a step.
    CHECK_FALSE(shared::stepped_forward(prev, {1070, 60}, kTol));
    CHECK(shared::stepped_forward(prev, {1071, 60}, kTol));
    // Backward step alone is never a forward step.
    CHECK_FALSE(shared::stepped_forward(prev, {-5000, 60}, kTol));
}

TEST_CASE("guard: backward step then restoration skips only at the restoration",
          "[wall_clock_step]") {
    shared::ClockStepGuard g{{0, 0}};
    CHECK_FALSE(shared::observe_and_should_skip(g, {-3590, 10}, kTol, kQ)); // backward
    CHECK(shared::observe_and_should_skip(g, {20, 20}, kTol, kQ));          // restored = forward step
}

TEST_CASE("guard: permanent forward step quarantines then recovers without restart",
          "[wall_clock_step]") {
    shared::ClockStepGuard g{{0, 0}};
    CHECK(shared::observe_and_should_skip(g, {3610, 10}, kTol, kQ));
    // Still inside the quarantine window: wall and steady now advance in step.
    CHECK(shared::observe_and_should_skip(g, {3610 + kQ - 1, 10 + kQ - 1}, kTol, kQ));
    CHECK_FALSE(shared::observe_and_should_skip(g, {3610 + kQ + 1, 10 + kQ + 1}, kTol, kQ));
}

TEST_CASE("guard: steady-only progression never skips", "[wall_clock_step]") {
    shared::ClockStepGuard g{{0, 0}};
    for (std::int64_t t = 1; t <= 100; ++t)
        CHECK_FALSE(shared::observe_and_should_skip(g, {t * 30, t * 30}, kTol, kQ));
}
