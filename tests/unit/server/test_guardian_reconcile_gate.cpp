/**
 * test_guardian_reconcile_gate.cpp: GuardianReconcileGate (#5513). Pure unit tests with an
 * injected manual clock; nothing sleeps.
 */

#include "guardian_reconcile_gate.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::GuardianReconcileBudget;
using yuzu::server::GuardianReconcileGate;
using Decision = yuzu::server::GuardianReconcileGate::Decision;
using GateOptions = yuzu::server::GuardianReconcileGateOptions;

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

// No constructor reserve: the sweep tests reason about the bucket count tracking the table.
GateOptions small_table() {
    return {.max_reserve = 0};
}

constexpr std::uint64_t kBehind = 1;
constexpr std::uint64_t kCurrent = 5;

}  // namespace

TEST_CASE("GuardianReconcileGate: Converged erases an expired claim and ignores the budget",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    REQUIRE(gate.claims_size() == 1);
    const auto admitted = budget.admitted_total();
    const auto shed = budget.shed_total();

    clk.advance(25s);  // the claim can no longer limit anything
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

TEST_CASE("GuardianReconcileGate: Converged keeps a young claim so a regression stays limited",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
    clk.advance(24s + 999'999'999ns);  // one nanosecond short of the interval
    CHECK(gate.decide("a", kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == 1);  // kept
    CHECK(gate.decide("a", kBehind, kCurrent) == Decision::RateLimited);
    clk.advance(1ns);  // now exactly min_interval old
    CHECK(gate.decide("a", kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == 0);  // expired claims are erased on convergence
}

TEST_CASE("GuardianReconcileGate: an agent alternating generation 0 / current gets one push per interval",
          "[guardian][reconcile_gate]") {
    // The boot re-arm catch-up report makes an agent report generation 0 intermittently. If
    // a converged heartbeat erased the claim, every second heartbeat would be admitted.
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    int admits = 0;
    for (int i = 0; i < 20; ++i) {  // 20 heartbeats, 1 s apart: all inside one 25 s interval
        const std::uint64_t reported = (i % 2 == 0) ? 0 : kCurrent;
        if (gate.decide("flap", reported, kCurrent) == Decision::Admit)
            ++admits;
        clk.advance(1s);
    }
    CHECK(admits == 1);
    CHECK(budget.admitted_total() == 1);

    // After the interval the next regression is admitted once more.
    clk.advance(10s);
    CHECK(gate.decide("flap", 0, kCurrent) == Decision::Admit);
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
    GuardianReconcileGate gate(budget, clk.fn(), 25s, small_table());  // 25 s => cutoff 50 s

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
    GuardianReconcileGate gate(budget, clk.fn(), 25s, small_table());

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
    GuardianReconcileGate gate(budget, clk.fn(), 25s, small_table());

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
    GuardianReconcileGate gate(budget, clk.fn(), 25s, small_table());

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

TEST_CASE("GuardianReconcileGate: 100k distinct ids erased by Converged heartbeats once expired",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn(), 25s, small_table());
    constexpr int kN = 100'000;
    for (int i = 0; i < kN; ++i)
        REQUIRE(gate.decide("c-" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
    CHECK(gate.claims_size() == static_cast<std::size_t>(kN));

    // Young claims survive a converged heartbeat (the memory bound is the sweep's job then).
    for (int i = 0; i < kN; ++i)
        REQUIRE(gate.decide("c-" + std::to_string(i), kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == static_cast<std::size_t>(kN));

    // Once a claim is min_interval old the same converged heartbeat erases it: this is the
    // steady-state memory bound for a fleet that has caught up.
    clk.advance(25s);
    for (int i = 0; i < kN; ++i)
        REQUIRE(gate.decide("c-" + std::to_string(i), kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.claims_size() == 0);
}

TEST_CASE("GuardianReconcileGate: decide() is atomic across threads (one Admit per id)",
          "[guardian][reconcile_gate]") {
    // Frozen clock: no claim ever expires, so peek+claim must make exactly one of the eight
    // racing threads win each id.
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    constexpr int kThreads = 8;
    constexpr int kIds = 2000;
    std::mutex m;
    std::condition_variable cv;
    bool go = false;
    std::atomic<std::uint64_t> admits{0}, limited{0};
    std::vector<std::jthread> threads;
    for (int t = 0; t < kThreads; ++t)
        threads.emplace_back([&] {
            {
                std::unique_lock lk(m);
                cv.wait(lk, [&] { return go; });
            }
            for (int i = 0; i < kIds; ++i) {
                switch (gate.decide("race-" + std::to_string(i), kBehind, kCurrent)) {
                case Decision::Admit:
                    admits.fetch_add(1);
                    break;
                case Decision::RateLimited:
                    limited.fetch_add(1);
                    break;
                default:
                    FAIL_CHECK("unexpected decision under a roomy budget");
                }
            }
        });
    {
        std::lock_guard lk(m);
        go = true;
    }
    cv.notify_all();
    for (auto& th : threads)
        th.join();

    CHECK(admits.load() == static_cast<std::uint64_t>(kIds));
    CHECK(limited.load() == static_cast<std::uint64_t>(kIds) * (kThreads - 1));
    CHECK(budget.admitted_total() == static_cast<std::uint64_t>(kIds));
    CHECK(gate.claims_size() == static_cast<std::size_t>(kIds));
}

TEST_CASE("GuardianReconcileGate: the claim table is pre-sized from the budget config",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    // 200 admissions/s over a 2 * 25 s horizon = 10000 entries without a rehash.
    GuardianReconcileBudget budget(
        {.budget_ms_per_s = 1'000'000.0, .burst_ms = 3'600'000.0, .max_per_s = 200}, clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    const auto buckets = gate.claims_buckets();
    CHECK(buckets >= 10'000);
    for (int i = 0; i < 10'000; ++i) {
        REQUIRE(gate.decide("r-" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
        if (i % 200 == 199)
            clk.advance(1s);  // a fresh one-second admission window every 200 admits
    }
    CHECK(gate.claims_buckets() == buckets);  // filling it did not rehash

    // The reserve is capped, however large the configured ceiling.
    GuardianReconcileBudget huge(roomy(), clk.fn());
    GuardianReconcileGate capped(huge, clk.fn(), 25s, {.max_reserve = 5000});
    CHECK(capped.claims_buckets() >= 5000);
    CHECK(capped.claims_buckets() < 50'000);
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
    // small_table(): no constructor reserve, so the table has few buckets and the final
    // bounded sweep below can cover all of it in one call.
    GuardianReconcileGate gate(budget, clk.fn(), std::chrono::seconds(25), small_table());

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

    std::vector<std::jthread> threads;
    for (int t = 0; t < kThreads; ++t)
        threads.emplace_back(worker, t);
    for (auto& th : threads)
        th.join();

    CHECK(admits + sheds + limited + converged ==
          static_cast<std::uint64_t>(kThreads) * kIters);
    CHECK(budget.admitted_total() == admits.load());
    CHECK(budget.shed_total() == sheds.load());
    // Once the clock is past 2x min_interval a single sweep drains whatever the concurrent
    // run left behind: a table corrupted by a race (a lost erase, a torn node) shows up as a
    // count mismatch.
    const std::size_t left = gate.claims_size();
    clk.advance(60s);
    CHECK(gate.sweep() == left);
    CHECK(gate.claims_size() == 0);
    CHECK(admits.load() > 0);
    CHECK(converged.load() > 0);
}

TEST_CASE("GuardianReconcileGate: Scoped::exclude removes waited time from the debit",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    budget.debit(100ms);  // balance 100
    REQUIRE(budget.balance_ms() == Catch::Approx(100.0));

    SECTION("excluded time is not charged") {
        {
            auto s = gate.begin_admitted();
            clk.advance(50ms);   // +5 ms refill
            s.exclude(40ms);     // 50 - 40 = 10 ms charged
        }
        CHECK(budget.balance_ms() == Catch::Approx(100.0 + 5.0 - 10.0));
    }
    SECTION("excluding everything still charges the minimum cost") {
        {
            auto s = gate.begin_admitted();
            clk.advance(50ms);
            s.exclude(500ms);  // more than elapsed
        }
        CHECK(budget.balance_ms() == Catch::Approx(100.0 + 5.0 - 1.0));
    }
    SECTION("negative exclusions are ignored and exclusions accumulate") {
        {
            auto s = gate.begin_admitted();
            clk.advance(50ms);
            s.exclude(-10ms);
            s.exclude(10ms);
            s.exclude(10ms);  // 50 - 20 = 30 ms charged
        }
        CHECK(budget.balance_ms() == Catch::Approx(100.0 + 5.0 - 30.0));
    }
    SECTION("the exclusion travels with a move") {
        {
            auto a = gate.begin_admitted();
            clk.advance(50ms);
            a.exclude(40ms);
            auto b = std::move(a);
            (void)b;
        }
        CHECK(budget.balance_ms() == Catch::Approx(100.0 + 5.0 - 10.0));
    }
}

TEST_CASE("GuardianReconcileGate: a zero-duration push is charged the minimum cost",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(small_budget(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    REQUIRE(budget.balance_ms() == Catch::Approx(200.0));
    {
        auto s = gate.begin_admitted();  // the clock never advances
    }
    CHECK(budget.balance_ms() == Catch::Approx(199.0));  // 1 ms floor

    // The floor is injectable.
    GuardianReconcileBudget budget2(small_budget(), clk.fn());
    GuardianReconcileGate gate2(budget2, clk.fn(), 25s, {.min_cost = 7ms});
    {
        auto s = gate2.begin_admitted();
    }
    CHECK(budget2.balance_ms() == Catch::Approx(193.0));
}

TEST_CASE("GuardianReconcileGate: the in-flight cap sheds and recovers", "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn(), 25s, {.max_in_flight = 3});

    std::vector<GuardianReconcileGate::Scoped> held;
    for (int i = 0; i < 3; ++i) {
        REQUIRE(gate.decide("a" + std::to_string(i), kBehind, kCurrent) == Decision::Admit);
        held.push_back(gate.begin_admitted());
    }
    CHECK(gate.in_flight() == 3);

    const auto budget_admitted = budget.admitted_total();
    CHECK(gate.decide("over", kBehind, kCurrent) == Decision::Shed);
    CHECK(gate.in_flight_shed_total() == 1);
    CHECK(gate.claims_size() == 3);                       // the shed wrote no claim
    CHECK(budget.admitted_total() == budget_admitted);    // and did not touch the budget
    // A converged or rate-limited decision is unaffected by the cap.
    CHECK(gate.decide("over", kCurrent, kCurrent) == Decision::Converged);
    CHECK(gate.decide("a0", kBehind, kCurrent) == Decision::RateLimited);

    held.pop_back();  // one push finishes
    CHECK(gate.in_flight() == 2);
    CHECK(gate.decide("over", kBehind, kCurrent) == Decision::Admit);
    held.push_back(gate.begin_admitted());
    CHECK(gate.in_flight() == 3);
    held.clear();
    CHECK(gate.in_flight() == 0);
}

TEST_CASE("GuardianReconcileGate: a moved-from Scoped does not release a slot twice",
          "[guardian][reconcile_gate]") {
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn(), 25s, {.max_in_flight = 2});
    {
        auto a = gate.begin_admitted();
        auto b = std::move(a);
        CHECK(gate.in_flight() == 1);
        auto c = gate.begin_admitted();
        c = std::move(b);  // c's own slot is released, b's carries over
        CHECK(gate.in_flight() == 1);
    }
    CHECK(gate.in_flight() == 0);
}

TEST_CASE("GuardianReconcileGate: an Admit whose push never sends keeps its claim",
          "[guardian][reconcile_gate]") {
    // The no_session path: an agent whose session was removed while heartbeating generation 0 in
    // a loop. The caller is admitted, finds no session, and finishes WITHOUT pushing. The
    // claim must stay: if the gate forgot it, every such heartbeat would be a fresh admission
    // and one credential could drain the shared budget. (There is deliberately no release API.)
    ManualClock clk;
    GuardianReconcileBudget budget(roomy(), clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());

    REQUIRE(gate.decide("ghost", kBehind, kCurrent) == Decision::Admit);
    {
        auto admitted = gate.begin_admitted();  // the push runs and ends with nothing sent
    }
    const auto admissions = budget.admitted_total();
    CHECK(gate.claims_size() == 1);

    // Within the interval every further heartbeat is rate-limited, however many arrive.
    for (int i = 0; i < 1000; ++i) {
        clk.advance(10ms);
        REQUIRE(gate.decide("ghost", 0, kCurrent) == Decision::RateLimited);
    }
    CHECK(budget.admitted_total() == admissions);  // the budget was never consulted again

    clk.advance(25s);  // only after min_interval is the agent admitted again
    CHECK(gate.decide("ghost", 0, kCurrent) == Decision::Admit);
    CHECK(budget.admitted_total() == admissions + 1);
}

TEST_CASE("GuardianReconcileGate: decide reports which cause shed",
          "[guardian][reconcile_gate]") {
    using Cause = GuardianReconcileGate::ShedCause;
    ManualClock clk;

    SECTION("budget exhaustion") {
        GuardianReconcileBudget budget(small_budget(), clk.fn());
        GuardianReconcileGate gate(budget, clk.fn());
        budget.debit(300ms);
        Cause cause = Cause::InFlightCap;  // proves decide() overwrites it
        CHECK(gate.decide("a", kBehind, kCurrent, &cause) == Decision::Shed);
        CHECK(cause == Cause::Budget);
    }
    SECTION("in-flight cap") {
        GuardianReconcileBudget budget(roomy(), clk.fn());
        GuardianReconcileGate gate(budget, clk.fn(), 25s, {.max_in_flight = 1});
        REQUIRE(gate.decide("a", kBehind, kCurrent) == Decision::Admit);
        auto held = gate.begin_admitted();
        Cause cause = Cause::None;
        CHECK(gate.decide("b", kBehind, kCurrent, &cause) == Decision::Shed);
        CHECK(cause == Cause::InFlightCap);
    }
    SECTION("any other decision reports None") {
        GuardianReconcileBudget budget(roomy(), clk.fn());
        GuardianReconcileGate gate(budget, clk.fn());
        Cause cause = Cause::Budget;
        CHECK(gate.decide("a", kBehind, kCurrent, &cause) == Decision::Admit);
        CHECK(cause == Cause::None);
        cause = Cause::Budget;
        CHECK(gate.decide("a", kBehind, kCurrent, &cause) == Decision::RateLimited);
        CHECK(cause == Cause::None);
        cause = Cause::Budget;
        CHECK(gate.decide("a", kCurrent, kCurrent, &cause) == Decision::Converged);
        CHECK(cause == Cause::None);
    }
}
