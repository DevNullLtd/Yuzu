/**
 * test_workflow_wait.cpp -- the interruptible wait behind a workflow run's retry delay (#2146).
 * Pure: a fake clock whose sleep_for advances virtual time, so nothing here sleeps for real and
 * no Postgres is involved.
 */

#include "workflow_claim_outcome.hpp"
#include "workflow_wait.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
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

// ── bounded_retry_delay (cppx2-2): the clamp bounds can never invert ─────────────────────

TEST_CASE("bounded_retry_delay: negative, zero and ordinary delays", "[workflow][wait][delay]") {
    using D = std::chrono::steady_clock::duration;
    // No deadline: the delay itself, floored at zero.
    CHECK(bounded_retry_delay(5, std::nullopt) == D(5s));
    CHECK(bounded_retry_delay(0, std::nullopt) == D::zero());
    CHECK(bounded_retry_delay(-1, std::nullopt) == D::zero());
    CHECK(bounded_retry_delay(INT64_MIN, std::nullopt) == D::zero());
    // A negative delay with time left must be ZERO, not the negative value an inverted
    // std::clamp(left, 0, negative) returns.
    CHECK(bounded_retry_delay(-3, D(5s)) == D::zero());
    CHECK(bounded_retry_delay(-3, D(-5s)) == D::zero());
    CHECK(bounded_retry_delay(0, D(5s)) == D::zero());
}

TEST_CASE("bounded_retry_delay: the deadline cuts the delay, a passed deadline zeroes it",
          "[workflow][wait][delay]") {
    using D = std::chrono::steady_clock::duration;
    CHECK(bounded_retry_delay(30, D(2s)) == D(2s));
    CHECK(bounded_retry_delay(2, D(30s)) == D(2s));
    CHECK(bounded_retry_delay(30, D::zero()) == D::zero());
    CHECK(bounded_retry_delay(30, D(-1s)) == D::zero());
    CHECK(bounded_retry_delay(30, D::min()) == D::zero());
}

TEST_CASE("bounded_retry_delay: a huge delay saturates and cannot overflow a deadline sum",
          "[workflow][wait][delay]") {
    using D = std::chrono::steady_clock::duration;
    const D day = kMaxRetryDelay;
    CHECK(bounded_retry_delay(3600, std::nullopt) == D(3600s)); // the stored maximum is untouched
    CHECK(bounded_retry_delay(INT64_MAX, std::nullopt) == day);
    CHECK(bounded_retry_delay(INT64_MAX / 1000000000, std::nullopt) == day);
    CHECK(bounded_retry_delay(INT64_MAX, D(10s)) == D(10s));
    // The result can be added to the steady clock without overflowing.
    const auto d = bounded_retry_delay(INT64_MAX, std::nullopt);
    CHECK(std::chrono::steady_clock::now() + d > std::chrono::steady_clock::now());
}

// ── acquire_within (cpps2-1, cppx2-1): the persistent lease retry never spins ────────────

namespace {
using Lease = std::optional<int>;
} // namespace

TEST_CASE("acquire_within: a pool that keeps answering empty is retried on a back-off, "
          "bounded by the budget",
          "[workflow][wait][acquire]") {
    FakeClock::State st;
    int attempts = 0;
    const auto r = acquire_within(
        10s,
        [&](std::chrono::milliseconds) -> Lease {
            ++attempts; // the open connect breaker: empty at once, no time passes
            return std::nullopt;
        },
        [] { return false; }, 3s, FakeClock{&st});
    CHECK_FALSE(r.has_value());
    CHECK(st.t - FakeClock::time_point{} == 10s); // exactly the budget, no more
    // Back-off 50, 100, 200, 250, 250 ...: 4 + (10 s - 0.35 s) / 0.25 s sleeps, nowhere near the
    // thousands of calls a loop without a sleep makes.
    CHECK(attempts == static_cast<int>(st.sleeps.size()) + 1);
    CHECK(attempts < 50);
    REQUIRE(st.sleeps.size() >= 4);
    CHECK(st.sleeps[0] == kAcquireBackoffMin);
    CHECK(st.sleeps[1] == 2 * kAcquireBackoffMin);
    for (std::size_t i = 0; i + 1 < st.sleeps.size(); ++i) {
        CHECK(st.sleeps[i] >= kAcquireBackoffMin);
        CHECK(st.sleeps[i] <= kAcquireBackoffMax); // the last may be cut short by the budget
    }
}

TEST_CASE("acquire_within: a lease that arrives ends the wait at once",
          "[workflow][wait][acquire]") {
    FakeClock::State st;
    int attempts = 0;
    const auto r = acquire_within(
        10s,
        [&](std::chrono::milliseconds) -> Lease {
            return ++attempts == 3 ? Lease{7} : Lease{};
        },
        [] { return false; }, 3s, FakeClock{&st});
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    CHECK(attempts == 3);
    CHECK(st.sleeps.size() == 2);
}

TEST_CASE("acquire_within: it always asks once, whatever the budget", "[workflow][wait][acquire]") {
    FakeClock::State st;
    int attempts = 0;
    const auto r = acquire_within(
        0s, [&](std::chrono::milliseconds) -> Lease { ++attempts; return std::nullopt; },
        [] { return false; }, 3s, FakeClock{&st});
    CHECK_FALSE(r.has_value());
    CHECK(attempts == 1);
    CHECK(st.sleeps.empty());
}

TEST_CASE("acquire_within: each ask is given the time left, never less than a millisecond",
          "[workflow][wait][acquire]") {
    FakeClock::State st;
    std::vector<std::chrono::milliseconds> asked;
    (void)acquire_within(
        1s,
        [&](std::chrono::milliseconds t) -> Lease { asked.push_back(t); return std::nullopt; },
        [] { return false; }, 3s, FakeClock{&st});
    REQUIRE(asked.size() >= 3);
    CHECK(asked.front() == 1000ms);
    for (std::size_t i = 1; i < asked.size(); ++i) {
        CHECK(asked[i] <= asked[i - 1]);
        CHECK(asked[i] >= 1ms);
    }
}

TEST_CASE("acquire_within: a stop pulls the deadline in to the stop budget, never out",
          "[workflow][wait][acquire]") {
    const auto empty = [](std::chrono::milliseconds) -> Lease { return std::nullopt; };
    SECTION("stopping from the start: the budget after the first empty answer") {
        FakeClock::State st;
        (void)acquire_within(10s, empty, [] { return true; }, 3s, FakeClock{&st});
        CHECK(st.t - FakeClock::time_point{} == 3s);
    }
    SECTION("a stop that flips mid-wait cuts the wait to the budget from the moment it is seen") {
        FakeClock::State st;
        (void)acquire_within(
            20s, empty, [&st] { return st.t - FakeClock::time_point{} >= 2s; }, 3s,
            FakeClock{&st});
        const auto elapsed = st.t - FakeClock::time_point{};
        CHECK(elapsed >= 5s);
        CHECK(elapsed <= 5s + kAcquireBackoffMax);
    }
    SECTION("a stop budget longer than what is left does not extend the wait") {
        FakeClock::State st;
        (void)acquire_within(1s, empty, [] { return true; }, 3s, FakeClock{&st});
        CHECK(st.t - FakeClock::time_point{} == 1s);
    }
}

// ── classify_xact_status (UP2-3): the lost-COMMIT-ack decision ───────────────────────────

TEST_CASE("classify_xact_status: only Postgres's own committed/aborted decide",
          "[workflow][claim_outcome]") {
    CHECK(classify_xact_status(std::string_view("committed")) == ClaimTxnOutcome::kCommitted);
    CHECK(classify_xact_status(std::string_view("aborted")) == ClaimTxnOutcome::kRolledBack);
    // In progress is unresolved, NULL is "too old for the commit log" or a check that could not
    // run, and anything else is not guessed.
    CHECK(classify_xact_status(std::string_view("in progress")) == ClaimTxnOutcome::kUnknown);
    CHECK(classify_xact_status(std::nullopt) == ClaimTxnOutcome::kUnknown);
    CHECK(classify_xact_status(std::string_view("")) == ClaimTxnOutcome::kUnknown);
    CHECK(classify_xact_status(std::string_view("Committed")) == ClaimTxnOutcome::kUnknown);
    CHECK(classify_xact_status(std::string_view("committed ")) == ClaimTxnOutcome::kUnknown);
    CHECK(classify_xact_status(std::string_view("rolled back")) == ClaimTxnOutcome::kUnknown);
}
