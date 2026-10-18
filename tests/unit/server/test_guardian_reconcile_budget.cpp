/**
 * test_guardian_reconcile_budget.cpp: GuardianReconcileBudget (#5513). Pure unit tests with an
 * injected manual clock; nothing sleeps.
 */

#include "guardian_reconcile_budget.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::GuardianReconcileBudget;
using yuzu::server::GuardianReconcileBudgetConfig;
using yuzu::server::guardian_reconcile_clamp_warnings;

namespace {

// Manual steady clock. Atomic so the thread-safety test can share it.
struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};  // arbitrary non-zero epoch
    GuardianReconcileBudget::Clock::time_point now() const {
        return GuardianReconcileBudget::Clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    GuardianReconcileBudget::ClockFn fn() {
        return [this] { return now(); };
    }
};

}  // namespace

TEST_CASE("GuardianReconcileBudget: starts full, try_admit does not debit",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    CHECK(b.balance_ms() == Catch::Approx(200.0));
    for (int i = 0; i < 10; ++i)
        CHECK(b.try_admit());
    CHECK(b.balance_ms() == Catch::Approx(200.0));
    CHECK(b.admitted_total() == 10);
    CHECK(b.shed_total() == 0);
}

TEST_CASE("GuardianReconcileBudget: debit then refill arithmetic",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    b.debit(150ms);
    CHECK(b.balance_ms() == Catch::Approx(50.0));
    clk.advance(500ms);  // +50 ms at 100 ms/s
    CHECK(b.balance_ms() == Catch::Approx(100.0));
    clk.advance(250ms);  // +25 ms
    CHECK(b.balance_ms() == Catch::Approx(125.0));
}

TEST_CASE("GuardianReconcileBudget: refill is capped at burst", "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    b.debit(100ms);
    clk.advance(3600s);
    CHECK(b.balance_ms() == Catch::Approx(200.0));
}

TEST_CASE("GuardianReconcileBudget: negative balance sheds then recovers",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    REQUIRE(b.try_admit());
    b.debit(500ms);  // one slow push: 200 - 500 = -300
    CHECK(b.balance_ms() == Catch::Approx(-300.0));
    CHECK_FALSE(b.try_admit());
    CHECK_FALSE(b.try_admit());
    CHECK(b.shed_total() == 2);

    clk.advance(2s);  // +200 -> -100, still not positive
    CHECK_FALSE(b.try_admit());
    clk.advance(1s);  // +100 -> 0, strictly positive is required
    CHECK_FALSE(b.try_admit());
    clk.advance(100ms);  // +10 -> 10
    CHECK(b.try_admit());
    CHECK(b.admitted_total() == 2);
    CHECK(b.shed_total() == 4);
}

TEST_CASE("GuardianReconcileBudget: a shed does not debit or change the balance",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    b.debit(300ms);  // -100
    const double before = b.balance_ms();
    for (int i = 0; i < 50; ++i)
        CHECK_FALSE(b.try_admit());
    CHECK(b.balance_ms() == Catch::Approx(before));
    CHECK(b.shed_total() == 50);
    CHECK(b.admitted_total() == 0);
}

TEST_CASE("GuardianReconcileBudget: count ceiling per one-second window",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 1000.0, .burst_ms = 1000.0, .max_per_s = 3},
                              clk.fn());
    CHECK(b.try_admit());
    CHECK(b.try_admit());
    CHECK(b.try_admit());
    CHECK_FALSE(b.try_admit());  // balance is full but the window ceiling is spent
    CHECK(b.balance_ms() == Catch::Approx(1000.0));

    clk.advance(999ms);
    CHECK_FALSE(b.try_admit());  // still the same window
    clk.advance(1ms);            // window elapsed
    CHECK(b.try_admit());
    CHECK(b.try_admit());
    CHECK(b.try_admit());
    CHECK_FALSE(b.try_admit());
    CHECK(b.admitted_total() == 6);
    CHECK(b.shed_total() == 3);
}

TEST_CASE("GuardianReconcileBudget: a shed does not count toward the window ceiling",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 100.0, .max_per_s = 2},
                              clk.fn());
    b.debit(300ms);  // -200
    CHECK_FALSE(b.try_admit());
    CHECK_FALSE(b.try_admit());
    CHECK_FALSE(b.try_admit());
    clk.advance(2100ms);  // +210 -> 10, and a new window
    CHECK(b.try_admit());
    CHECK(b.try_admit());
    CHECK_FALSE(b.try_admit());
}

TEST_CASE("GuardianReconcileBudget: debt is floored", "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    b.debit(std::chrono::hours(10));
    CHECK(b.balance_ms() == Catch::Approx(-GuardianReconcileBudget::kMaxDebtSeconds * 100.0));
    // Recovery is bounded: floor / rate seconds, plus a hair to go strictly positive.
    clk.advance(std::chrono::seconds(31));
    CHECK(b.try_admit());
}

TEST_CASE("GuardianReconcileBudget: non-positive debit is ignored", "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000},
                              clk.fn());
    b.debit(0ns);
    b.debit(-5s);
    CHECK(b.balance_ms() == Catch::Approx(200.0));
}

TEST_CASE("GuardianReconcileBudget: a backwards clock neither refills nor re-opens a window",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1},
                              clk.fn());
    CHECK(b.try_admit());
    b.debit(250ms);  // -50
    clk.advance(-10s);
    CHECK(b.balance_ms() == Catch::Approx(-50.0));
    CHECK_FALSE(b.try_admit());
}

TEST_CASE("GuardianReconcileBudget: invalid config is clamped, never divides by zero",
          "[guardian][reconcile_budget]") {
    ManualClock clk;
    using B = GuardianReconcileBudget;
    {
        B b({.budget_ms_per_s = 0.0, .burst_ms = -5.0, .max_per_s = 0}, clk.fn());
        const auto c = b.config();
        CHECK(c.budget_ms_per_s == B::kMinBudgetMsPerS);
        CHECK(c.burst_ms == B::kMinBurstMs);
        CHECK(c.max_per_s == B::kMinMaxPerS);
        CHECK(b.try_admit());  // the bucket starts full at the clamped burst
        CHECK(b.balance_ms() == Catch::Approx(B::kMinBurstMs));
        clk.advance(1s);
        CHECK(b.balance_ms() == Catch::Approx(B::kMinBurstMs));  // capped, no overflow
    }
    {
        const double nan = std::numeric_limits<double>::quiet_NaN();
        const double inf = std::numeric_limits<double>::infinity();
        B b({.budget_ms_per_s = nan, .burst_ms = inf, .max_per_s = 0xFFFFFFFFu}, clk.fn());
        const auto c = b.config();
        CHECK(c.budget_ms_per_s == B::kMinBudgetMsPerS);
        CHECK(c.burst_ms == B::kMaxBurstMs);
        CHECK(c.max_per_s == B::kMaxMaxPerS);
        B b2({.budget_ms_per_s = -inf, .burst_ms = nan, .max_per_s = 5}, clk.fn());
        CHECK(b2.config().budget_ms_per_s == B::kMinBudgetMsPerS);
        CHECK(b2.config().burst_ms == B::kMinBurstMs);
    }
}

TEST_CASE("GuardianReconcileBudget: null clock selects the real steady clock",
          "[guardian][reconcile_budget]") {
    GuardianReconcileBudget b;  // default config, default clock
    CHECK(b.try_admit());
    CHECK(b.admitted_total() == 1);
}

TEST_CASE("GuardianReconcileBudget: thread-safety smoke", "[guardian][reconcile_budget]") {
    ManualClock clk;  // never advances: one window, no refill
    constexpr std::uint32_t kCeiling = 50;
    GuardianReconcileBudget b({.budget_ms_per_s = 100.0, .burst_ms = 1.0e6, .max_per_s = kCeiling},
                              clk.fn());
    constexpr int kThreads = 8;
    constexpr int kIters = 2000;
    std::atomic<std::uint64_t> admitted_seen{0};
    std::atomic<std::uint64_t> shed_seen{0};
    std::vector<std::jthread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&] {
            for (int i = 0; i < kIters; ++i) {
                if (b.try_admit()) {
                    admitted_seen.fetch_add(1);
                    b.debit(1ms);
                } else {
                    shed_seen.fetch_add(1);
                }
            }
        });
    }
    for (auto& t : ts)
        t.join();
    CHECK(admitted_seen.load() == kCeiling);  // one fixed window: exactly the ceiling
    CHECK(admitted_seen.load() + shed_seen.load() == std::uint64_t{kThreads} * kIters);
    CHECK(b.admitted_total() == admitted_seen.load());
    CHECK(b.shed_total() == shed_seen.load());
    CHECK(b.balance_ms() == Catch::Approx(1.0e6 - static_cast<double>(kCeiling)));
}

TEST_CASE("guardian_reconcile_clamp_warnings: in-range values produce no warning",
          "[guardian][reconcile_budget][clamp_log]") {
    const GuardianReconcileBudgetConfig cfg{.budget_ms_per_s = 500.0, .burst_ms = 1000.0,
                                            .max_per_s = 1000};
    GuardianReconcileBudget b(cfg);
    CHECK(guardian_reconcile_clamp_warnings(cfg, b.config()).empty());
}

TEST_CASE("guardian_reconcile_clamp_warnings: each clamped flag is named with the value it was "
          "clamped from and to, exact wording",
          "[guardian][reconcile_budget][clamp_log]") {
    using B = GuardianReconcileBudget;
    // Fed the effective values the real budget enforces, not hand-written ones.
    SECTION("budget above the maximum") {
        const GuardianReconcileBudgetConfig cfg{.budget_ms_per_s = 2.0e6, .burst_ms = 1000.0,
                                                .max_per_s = 1000};
        B b(cfg);
        const auto w = guardian_reconcile_clamp_warnings(cfg, b.config());
        REQUIRE(w.size() == 1);
        CHECK(w[0] == "Guardian reconcile admission: --guardian-reconcile-budget-ms-per-s "
                      "2e+06 was outside the supported range and was clamped to 1e+06");
    }
    SECTION("burst below the minimum") {
        const GuardianReconcileBudgetConfig cfg{.budget_ms_per_s = 500.0, .burst_ms = 0.25,
                                                .max_per_s = 1000};
        B b(cfg);
        const auto w = guardian_reconcile_clamp_warnings(cfg, b.config());
        REQUIRE(w.size() == 1);
        CHECK(w[0] == "Guardian reconcile admission: --guardian-reconcile-burst-ms 0.25 "
                      "was outside the supported range and was clamped to 1");
    }
    SECTION("max per second above the cap") {
        const GuardianReconcileBudgetConfig cfg{.budget_ms_per_s = 500.0, .burst_ms = 1000.0,
                                                .max_per_s = 4'000'000};
        B b(cfg);
        const auto w = guardian_reconcile_clamp_warnings(cfg, b.config());
        REQUIRE(w.size() == 1);
        CHECK(w[0] == "Guardian reconcile admission: --guardian-reconcile-max-per-s 4000000 "
                      "was outside the supported range and was clamped to 1000000");
    }
    SECTION("all three at once, in flag order, and a NaN request is reported") {
        const GuardianReconcileBudgetConfig cfg{
            .budget_ms_per_s = std::numeric_limits<double>::quiet_NaN(), .burst_ms = 1.0e9,
            .max_per_s = 0};
        B b(cfg);
        const auto w = guardian_reconcile_clamp_warnings(cfg, b.config());
        REQUIRE(w.size() == 3);
        // The spelling of NaN differs by C library, so only the flag and tail are pinned.
        CHECK(w[0].starts_with("Guardian reconcile admission: --guardian-reconcile-budget-ms-per-s "));
        CHECK(w[0].ends_with(" was outside the supported range and was clamped to 1"));
        CHECK(w[1].find("--guardian-reconcile-burst-ms 1e+09 was outside") != std::string::npos);
        CHECK(w[2].find("--guardian-reconcile-max-per-s 0 was outside") != std::string::npos);
    }
}
