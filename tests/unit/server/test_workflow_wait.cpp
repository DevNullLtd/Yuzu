/**
 * test_workflow_wait.cpp -- the interruptible wait behind a workflow run's retry delay (#2146).
 * Pure: a fake clock whose sleep_for advances virtual time, so nothing here sleeps for real and
 * no Postgres is involved.
 */

#include "workflow_wait.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>

using namespace yuzu::server;
using namespace std::chrono_literals;

namespace {

/// A clock that only moves when the wait sleeps. `sleeps` records every slice requested.
struct FakeClock {
    using duration = std::chrono::steady_clock::duration;
    using time_point = std::chrono::steady_clock::time_point;
    struct State {
        time_point t{};
        std::vector<duration> sleeps;
    };
    State* st;
    [[nodiscard]] time_point now() const { return st->t; }
    void sleep_for(duration d) const {
        st->sleeps.push_back(d);
        st->t += d;
    }
};

} // namespace

TEST_CASE("interruptible_wait: with no wake it sleeps the whole duration in slices of at most 250 ms",
          "[workflow][wait]") {
    FakeClock::State st;
    const auto r = interruptible_wait(1s, [] { return false; }, FakeClock{&st});
    CHECK(r == WaitResult::kElapsed);
    CHECK(st.t - FakeClock::time_point{} == 1s);
    REQUIRE(st.sleeps.size() == 4);
    for (const auto& s : st.sleeps)
        CHECK(s <= kInterruptibleWaitSlice);
}

TEST_CASE("interruptible_wait: the last slice is the remainder, never a full slice past the end",
          "[workflow][wait]") {
    FakeClock::State st;
    const auto r = interruptible_wait(600ms, [] { return false; }, FakeClock{&st});
    CHECK(r == WaitResult::kElapsed);
    REQUIRE(st.sleeps.size() == 3);
    CHECK(st.sleeps[0] == 250ms);
    CHECK(st.sleeps[1] == 250ms);
    CHECK(st.sleeps[2] == 100ms);
    CHECK(st.t - FakeClock::time_point{} == 600ms);
}

TEST_CASE("interruptible_wait: a wake that flips mid-wait is seen within one slice, however long the "
          "total",
          "[workflow][wait]") {
    FakeClock::State st;
    // The stop flips at 1 s of virtual time; the total is an hour.
    const auto r = interruptible_wait(
        1h, [&st] { return st.t - FakeClock::time_point{} >= 1s; }, FakeClock{&st});
    CHECK(r == WaitResult::kWoken);
    const auto slept = st.t - FakeClock::time_point{};
    CHECK(slept >= 1s);
    CHECK(slept <= 1s + kInterruptibleWaitSlice);
}

TEST_CASE("interruptible_wait: a wake that is already set costs no sleep at all", "[workflow][wait]") {
    FakeClock::State st;
    CHECK(interruptible_wait(30s, [] { return true; }, FakeClock{&st}) == WaitResult::kWoken);
    CHECK(st.sleeps.empty());
}

TEST_CASE("interruptible_wait: the wake is asked at least once, even for a zero or negative total",
          "[workflow][wait]") {
    FakeClock::State st;
    int asked = 0;
    CHECK(interruptible_wait(0ms, [&asked] { ++asked; return false; }, FakeClock{&st}) ==
          WaitResult::kElapsed);
    CHECK(asked == 1);
    CHECK(interruptible_wait(-5s, [] { return true; }, FakeClock{&st}) == WaitResult::kWoken);
    CHECK(st.sleeps.empty());
}

TEST_CASE("interruptible_wait: a custom slice bounds the polling interval", "[workflow][wait]") {
    FakeClock::State st;
    int asked = 0;
    const auto r = interruptible_wait(100ms, [&asked] { ++asked; return false; }, FakeClock{&st},
                                      10ms);
    CHECK(r == WaitResult::kElapsed);
    CHECK(st.sleeps.size() == 10);
    CHECK(asked == 11); // before each of the ten slices, and once more at the end
}

TEST_CASE("interruptible_wait: the production clock really waits and really wakes",
          "[workflow][wait]") {
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(interruptible_wait(60ms, [] { return false; }) == WaitResult::kElapsed);
    CHECK(std::chrono::steady_clock::now() - t0 >= 60ms);
    const auto t1 = std::chrono::steady_clock::now();
    CHECK(interruptible_wait(1h, [] { return true; }) == WaitResult::kWoken);
    CHECK(std::chrono::steady_clock::now() - t1 < 1s);
}
