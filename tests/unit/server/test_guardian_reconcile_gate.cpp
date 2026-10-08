/**
 * test_guardian_reconcile_gate.cpp: GuardianReconcileGate (#5513, Fable opinion
 * sections C and D). Pure unit tests with an injected manual clock; nothing sleeps.
 */

#include "guardian_reconcile_gate.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::GuardianReconcileBudget;
using yuzu::server::GuardianReconcileGate;
using Decision = yuzu::server::GuardianReconcileGate::Decision;

namespace {

// Manual steady clock. Atomic so the thread-safety test can share it.
struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};  // arbitrary non-zero epoch
    GuardianReconcileBudget::Clock::time_point now() const {
        return GuardianReconcileBudget::Clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    std::function<GuardianReconcileBudget::Clock::time_point()> fn() {
        return [this] { return now(); };
    }
};

// A budget that admits freely: huge refill and burst, huge count ceiling.
GuardianReconcileBudget::Config roomy() {
    return {.budget_ms_per_s = 1'000'000.0, .burst_ms = 3'600'000.0, .max_per_s = 1'000'000};
}

// A small budget: 200 ms burst, 100 ms/s refill.
GuardianReconcileBudget::Config small_budget() {
    return {.budget_ms_per_s = 100.0, .burst_ms = 200.0, .max_per_s = 1000};
}

constexpr std::uint64_t kBehind = 1;
constexpr std::uint64_t kCurrent = 5;

}  // namespace

TEST_CASE("GuardianReconcileGate: Converged erases the claim and ignores the budget",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    REQUIRE(gate.claims_size() == 1);
    const auto admitted = budget.admitted_total();
    const auto shed = budget.shed_total();

    CHECK(gate.decide("a", kCurrent, kCurrent) == Decision::Converged);  // equal
    CHECK(gate.claims_size() == 0);
    CHECK(gate.decide("a", kCurrent + 3, kCurrent) == Decision::Converged);  // ahead
    CHECK(gate.decide("never-seen", kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == 0);
    CHECK(budget.admitted_total() == admitted);
    CHECK(budget.shed_total() == shed);

    // The erased claim no longer rate-limits a later regression of the same agent.
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
}

TEST_CASE("GuardianReconcileGate: Converged does not consult an exhausted budget",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    budget.debit(1000ms);  // balance far below zero: every try_admit would shed
    REQUIRE_FALSE(budget.balance_ms() > 0.0);

    CHECK(gate.decide("a", kCurrent, kCurrent) == Decision::Converged);
    CHECK(budget.admitted_total() == 0);
    CHECK(budget.shed_total() == 0);
}

TEST_CASE("GuardianReconcileGate: RateLimited does not touch the budget",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    REQUIRE(budget.admitted_total() == 1);

    clk.advance(5s);
    for (int i = 0; i < 10; ++i)
        CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
    CHECK(budget.admitted_total() == 1);
    CHECK(budget.shed_total() == 0);
    CHECK(gate.claims_size() == 1);
}

TEST_CASE("GuardianReconcileGate: RateLimited wins over an exhausted budget (peek precedes try)",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    budget.debit(1000ms);  // exhaust
    clk.advance(1s);
    const auto shed = budget.shed_total();
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
    CHECK(budget.shed_total() == shed);  // not counted as a shed
}

TEST_CASE("GuardianReconcileGate: Shed leaves no claim and the next decide after refill is Admit",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    budget.debit(300ms);  // balance 200 - 300 = -100

    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Shed);
    CHECK(gate.claims_size() == 0);
    CHECK(budget.shed_total() == 1);
    CHECK(budget.admitted_total() == 0);

    // Still shed until the bucket is positive again (100 ms/s; -100 needs > 1 s).
    clk.advance(500ms);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Shed);
    CHECK(gate.claims_size() == 0);

    clk.advance(2s);  // refilled to a positive balance
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);  // NOT RateLimited
    CHECK(gate.claims_size() == 1);
}

TEST_CASE("GuardianReconcileGate: Shed does not rewrite an existing expired claim",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);  // claim at t0
    budget.debit(5000ms);  // floored at -3000 ms (30 s of debt at 100 ms/s)
    clk.advance(26s);      // claim expired at t0+25; balance -3000 + 2600 = -400
    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Shed);

    // Had the shed rewritten the claim at t0+26, an attempt at t0+31 would be
    // rate-limited (5 s old). It must instead be admitted once the budget allows.
    clk.advance(5s);  // balance -400 + 500 = +100
    CHECK(budget.balance_ms() > 0.0);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
}

TEST_CASE("GuardianReconcileGate: Admit writes the claim and the immediate retry is RateLimited",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    CHECK(gate.claims_size() == 1);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
    // A different agent has its own slot.
    CHECK(gate.decide("b", kBehind, kCurrent) == Decision::Admit);
    CHECK(gate.claims_size() == 2);
}

TEST_CASE("GuardianReconcileGate: boundary exactly at min_interval", "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    clk.advance(25s - 1ns);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);  // 24.999999999 s
    clk.advance(1ns);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);  // exactly 25 s

    // The refreshed claim restarts the window.
    clk.advance(24s);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
}

TEST_CASE("GuardianReconcileGate: a custom min_interval is honoured", "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn(), 3s);

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    clk.advance(2s);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
    clk.advance(1s);
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
}

TEST_CASE("GuardianReconcileGate: a backwards clock stays rate-limited", "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    clk.advance(-10s);  // pre-extraction semantics: (now - last) < interval
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
}

TEST_CASE("GuardianReconcileGate: sweep erases only entries older than 2x min_interval",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());  // 25 s => cutoff 50 s

    REQUIRE(gate.decide("old", kBehind, kCurrent) == Decision::Admit);  // t0
    clk.advance(30s);
    REQUIRE(gate.decide("mid", kBehind, kCurrent) == Decision::Admit);  // t0+30
    clk.advance(20s);  // old is exactly 50 s, mid 20 s
    CHECK(gate.sweep() == 0);  // exactly 2x is not "older than"
    CHECK(gate.claims_size() == 2);

    clk.advance(1ns);
    CHECK(gate.sweep() == 1);  // old is now strictly older
    CHECK(gate.claims_size() == 1);
    // Surviving entry still rate-limits.
    CHECK(gate.decide("mid", kBehind, kCurrent) == Decision::RateLimited);
    // The erased one is admitted afresh.
    CHECK(gate.decide("old", kBehind, kCurrent) == Decision::Admit);

    clk.advance(100s);
    CHECK(gate.sweep() == 2);
    CHECK(gate.claims_size() == 0);
    CHECK(gate.sweep() == 0);  // empty table
}

TEST_CASE("GuardianReconcileGate: sweep leaves fresh entries and a backwards clock alone",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    for (int i = 0; i < 100; ++i)
        REQUIRE(gate.decide("agent-" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
    clk.advance(10s);
    CHECK(gate.sweep() == 0);
    clk.advance(-1000s);  // negative age is never swept
    CHECK(gate.sweep() == 0);
    CHECK(gate.claims_size() == 100);
}

TEST_CASE("GuardianReconcileGate: sweep respects max_erase and max_scan and resumes",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    constexpr std::size_t kN = 1000;
    for (std::size_t i = 0; i < kN; ++i)
        REQUIRE(gate.decide("agent-" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
    clk.advance(60s);  // all stale

    SECTION("max_erase caps the erase count per call") {
        std::size_t total = 0;
        int calls = 0;
        while (gate.claims_size() > 0 && calls < 1000) {
            const auto n = gate.sweep(/*max_erase=*/100);
            CHECK(n <= 100);
            total += n;
            ++calls;
        }
        CHECK(gate.claims_size() == 0);
        CHECK(total == kN);
        CHECK(calls >= 10);
    }
    SECTION("max_erase of zero does nothing") {
        CHECK(gate.sweep(0) == 0);
        CHECK(gate.claims_size() == kN);
    }
    SECTION("max_scan caps the work per call and the cursor resumes to cover the table") {
        const auto first = gate.sweep(kN, /*max_scan=*/50);
        CHECK(first > 0);
        CHECK(first < kN);  // one call did not cover the whole table
        std::size_t total = first;
        int calls = 1;
        while (gate.claims_size() > 0 && calls < 10'000) {
            const auto n = gate.sweep(kN, 50);
            // Each erase costs at least one scan unit; allow one bucket chain of overshoot.
            CHECK(n <= 50 + 16);
            total += n;
            ++calls;
        }
        CHECK(total == kN);
        CHECK(gate.claims_size() == 0);
    }
}

TEST_CASE("GuardianReconcileGate: claims_size stays bounded across 100k distinct-id churn",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    // 200 simulated seconds, 500 brand-new agents per second (100k distinct ids). Live
    // claims are useful for 25 s and kept for up to 50 s; with one default-bounded sweep per
    // second the table must stay well below the 100k that an unswept map would reach.
    std::size_t peak = 0;
    for (int sec = 0; sec < 200; ++sec) {
        for (int j = 0; j < 500; ++j) {
            const auto id = "churn-" + std::to_string(sec * 500 + j);
            REQUIRE(gate.decide(id, kBehind, kCurrent) == Decision::Admit);
        }
        peak = std::max(peak, gate.claims_size());
        (void)gate.sweep();
        clk.advance(1s);
    }
    CHECK(peak <= 40'000);  // ~50 s window x 500/s = 25k live + sweep lag
    CHECK(gate.claims_size() <= 40'000);

    // Once everything is stale, bounded sweeps drain the table completely.
    clk.advance(120s);
    int calls = 0;
    while (gate.claims_size() > 0 && calls < 10'000) {
        const auto n = gate.sweep();
        CHECK(n <= GuardianReconcileGate::kDefaultSweepMaxErase);
        ++calls;
    }
    CHECK(gate.claims_size() == 0);
}

TEST_CASE("GuardianReconcileGate: 100k distinct ids erased by Converged heartbeats",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    constexpr int kN = 100'000;
    for (int i = 0; i < kN; ++i)
        REQUIRE(gate.decide("c-" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
    CHECK(gate.claims_size() == static_cast<std::size_t>(kN));
    for (int i = 0; i < kN; ++i)
        REQUIRE(gate.decide("c-" + std::to_string(i), kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == 0);
}

TEST_CASE("GuardianReconcileGate: Scoped debits the elapsed time exactly once",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    budget.debit(100ms);  // balance 100
    REQUIRE(budget.balance_ms() == Catch::Approx(100.0));

    SECTION("normal scope exit") {
        {
            auto s = gate.begin_admitted();
            clk.advance(50ms);  // +5 ms refill, then -50 ms debit
        }
        CHECK(budget.balance_ms() == Catch::Approx(55.0));
    }
    SECTION("exception unwind") {
        try {
            auto s = gate.begin_admitted();
            clk.advance(50ms);
            throw std::runtime_error("reconcile failed");
        } catch (const std::runtime_error&) {
        }
        CHECK(budget.balance_ms() == Catch::Approx(55.0));
    }
    SECTION("early return path") {
        auto run = [&](bool bail) {
            auto s = gate.begin_admitted();
            clk.advance(50ms);
            if (bail)
                return 1;
            clk.advance(0ms);
            return 0;
        };
        CHECK(run(true) == 1);
        CHECK(budget.balance_ms() == Catch::Approx(55.0));
    }
    SECTION("move construction transfers the single debit") {
        {
            auto a = gate.begin_admitted();
            clk.advance(50ms);
            auto b = std::move(a);
            (void)b;
        }
        CHECK(budget.balance_ms() == Catch::Approx(55.0));
    }
    SECTION("move assignment debits the overwritten timer once and the source once") {
        {
            auto a = gate.begin_admitted();
            clk.advance(10ms);  // a: 10 ms
            auto b = gate.begin_admitted();
            clk.advance(20ms);  // a: 30 ms, b: 20 ms
            b = std::move(a);   // b's own 20 ms is debited now; a's 30 ms follows at scope end
        }
        // refill 0.1 ms/ms: 100 + 3 (30 ms elapsed) - 20 - 30 = 53
        CHECK(budget.balance_ms() == Catch::Approx(53.0));
    }
}

TEST_CASE("GuardianReconcileGate: complete debits the budget", "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    CHECK(budget.balance_ms() == Catch::Approx(200.0));  // admit does not debit
    gate.complete(75ms);
    CHECK(budget.balance_ms() == Catch::Approx(125.0));
}

TEST_CASE("GuardianReconcileGate: a debited slow push makes later agents shed",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    gate.complete(500ms);  // balance -300
    CHECK(gate.decide("b", kBehind, kCurrent) == Decision::Shed);
    CHECK(gate.claims_size() == 1);  // only "a"
}

TEST_CASE("GuardianReconcileGate: thread-safety smoke", "[guardian][reconcile_gate]") {
    ManualClock clk;
    // Tight enough that some decisions shed, loose enough that some admit.
    GuardianReconcileBudget budget(
        {.budget_ms_per_s = 1000.0, .burst_ms = 50.0, .max_per_s = 1'000'000}, clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    constexpr int kThreads = 8;
    constexpr int kIters = 4000;
    std::atomic<std::uint64_t> admits{0}, sheds{0}, limited{0}, converged{0};

    auto worker = [&](int t) {
        for (int i = 0; i < kIters; ++i) {
            const std::string id = "agent-" + std::to_string((t * 7 + i) % 64);
            const std::uint64_t gen = (i % 5 == 0) ? kCurrent : kBehind;
            const auto d = gate.decide(id, gen, kCurrent);
            switch (d) {
            case Decision::Admit: {
                admits.fetch_add(1);
                auto s = gate.begin_admitted();
                clk.advance(1ms);
                break;
            }
            case Decision::Shed:
                sheds.fetch_add(1);
                break;
            case Decision::RateLimited:
                limited.fetch_add(1);
                break;
            case Decision::Converged:
                converged.fetch_add(1);
                break;
            }
            if (i % 100 == 0) {
                clk.advance(30s);
                (void)gate.sweep();
            }
        }
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
        threads.emplace_back(worker, t);
    for (auto& th : threads)
        th.join();

    CHECK(admits + sheds + limited + converged ==
          static_cast<std::uint64_t>(kThreads) * kIters);
    CHECK(budget.admitted_total() == admits.load());
    CHECK(budget.shed_total() == sheds.load());
    CHECK(gate.claims_size() <= 64);
    CHECK(admits.load() > 0);
    CHECK(converged.load() > 0);
}
