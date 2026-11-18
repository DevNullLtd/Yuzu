/**
 * test_pbkdf2_budget.cpp — the lane and floor arithmetic of the process-wide PBKDF2 concurrency
 * budget (WP03 perf-F1; server/core/src/pbkdf2_budget.hpp). Header-only subject, no database.
 *
 * Numbers: cap 66 (default pool of 264): break-glass lane 4, main
 * share 62 (unauthenticated 31, authenticated 31), per-principal 3. Cap 8 (the floor): break-glass 2, main 6 (3 / 3).
 */

#include "../../../server/core/src/pbkdf2_budget.hpp"
#include "test_pbkdf2_budget_fill.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

namespace {
std::vector<Pbkdf2Budget::Slot> take_unauth(Pbkdf2Budget& b, int n, const char* tag) {
    std::vector<Pbkdf2Budget::Slot> v;
    for (int i = 0; i < n; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kUnauthenticated, std::string(tag) + std::to_string(i));
        if (!s.ok())
            break;
        v.push_back(std::move(s));
    }
    return v;
}
std::vector<Pbkdf2Budget::Slot> take_auth(Pbkdf2Budget& b, int n, const char* tag) {
    std::vector<Pbkdf2Budget::Slot> v;
    for (int i = 0; i < n; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kAuthenticated, {}, std::string(tag) + std::to_string(i));
        if (!s.ok())
            break;
        v.push_back(std::move(s));
    }
    return v;
}
} // namespace

TEST_CASE("Pbkdf2Budget sizes: cap 66 gives 4 / 62 / 31 / 31, cap 8 gives 2 / 6 / 3 / 3",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66};
    CHECK(b.break_glass_cap() == 4);
    CHECK(b.main_cap() == 62);
    CHECK(take_unauth(b, 100, "u").size() == 31);
    CHECK(take_auth(b, 100, "a").size() == 31); // the unauth slots above were freed; authenticated lane 31
    Pbkdf2Budget t{8};
    CHECK(t.break_glass_cap() == 2);
    CHECK(t.main_cap() == 6);
}

TEST_CASE("Pbkdf2Budget (a): break-glass still gets a slot with the authenticated class at its cap",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, /*per_source_cap=*/64};
    b.set_per_principal_cap(64); // isolate the class bound from the per-principal bound
    auto auth = take_auth(b, 100, "p");
    CHECK(auth.size() == 31); // the authenticated class stops at ITS half of the main share
    auto bg = b.try_acquire(Pbkdf2Class::kBreakGlass, "bg-source");
    CHECK(bg.ok());
}

TEST_CASE("Pbkdf2Budget (b): the union bound leaves break-glass its whole floor", "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, 64};
    b.set_per_principal_cap(64);
    // Fill the two shared classes to the bound: unauthenticated 31 first, then authenticated.
    auto unauth = take_unauth(b, 100, "u");
    auto auth = take_auth(b, 100, "p");
    CHECK(unauth.size() == 31);
    CHECK(auth.size() == 31);
    CHECK(unauth.size() + auth.size() == 62); // together bounded at cap - floor
    std::vector<Pbkdf2Budget::Slot> bg;
    for (int i = 0; i < 100; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kBreakGlass, "bg" + std::to_string(i));
        if (!s.ok())
            break;
        bg.push_back(std::move(s));
    }
    CHECK(bg.size() == 4); // the floor survives; the 5th is refused by the lane cap (= the gate)
    CHECK(b.in_flight() == 66);
    // Tiny pool: same property at cap 8 (floor 2, main 6).
    Pbkdf2Budget t{8, 64};
    t.set_per_principal_cap(64);
    auto tu = take_unauth(t, 100, "u");
    auto ta = take_auth(t, 100, "p");
    CHECK(tu.size() + ta.size() == 6);
    auto bx = t.try_acquire(Pbkdf2Class::kBreakGlass, "x");
    auto by = t.try_acquire(Pbkdf2Class::kBreakGlass, "y");
    CHECK(bx.ok());
    CHECK(by.ok());
    CHECK_FALSE(t.try_acquire(Pbkdf2Class::kBreakGlass, "z").ok());
}

TEST_CASE("Pbkdf2Budget (c): one principal cannot take more than its per-principal bound",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66};
    std::vector<Pbkdf2Budget::Slot> mine;
    for (int i = 0; i < 20; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kAuthenticated, {}, "u:alice");
        if (!s.ok()) {
            CHECK(s.refusal() == Pbkdf2Refusal::kPerPrincipal);
            break;
        }
        mine.push_back(std::move(s));
    }
    CHECK(mine.size() == 3);
    // Another principal still gets in: one session holder cannot fill the authenticated share.
    CHECK(b.try_acquire(Pbkdf2Class::kAuthenticated, {}, "u:bob").ok());
    mine.clear();
    CHECK(b.try_acquire(Pbkdf2Class::kAuthenticated, {}, "u:alice").ok()); // released
}

TEST_CASE("Pbkdf2Budget fairness: an unauthenticated flood cannot starve authenticated callers",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{8, /*per_source_cap=*/1}; // main 6: unauthenticated 3, authenticated 3
    auto a1 = b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.1");
    REQUIRE(a1.ok());
    auto again = b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.1");
    CHECK_FALSE(again.ok());
    CHECK(again.refusal() == Pbkdf2Refusal::kPerSource);
    auto a2 = b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.2");
    auto a3 = b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.3");
    REQUIRE(a2.ok());
    REQUIRE(a3.ok());
    auto a4 = b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.4");
    CHECK_FALSE(a4.ok());
    CHECK(a4.refusal() == Pbkdf2Refusal::kClassFull);
    auto auth = take_auth(b, 10, "p"); // the reserved half is still there
    CHECK(auth.size() == 3);
    { auto gone = std::move(a1); }
    CHECK(b.try_acquire(Pbkdf2Class::kUnauthenticated, "10.0.0.1").refusal() !=
          Pbkdf2Refusal::kPerSource); // the per-source entry was released
}

TEST_CASE("fill_pbkdf2_budget takes every slot", "[pbkdf2_budget]") {
    Pbkdf2Budget b{8};
    auto held = yuzu::test::fill_pbkdf2_budget(b);
    CHECK(held.size() == 8);
    CHECK_FALSE(b.try_acquire(Pbkdf2Class::kUnauthenticated, "x").ok());
    CHECK_FALSE(b.try_acquire(Pbkdf2Class::kBreakGlass, "x").ok());
}

TEST_CASE("Pbkdf2Budget: neither shared class can fill the main share and starve the other",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, 64};
    b.set_per_principal_cap(64);
    auto auth = take_auth(b, 100, "p");
    CHECK(auth.size() == 31);
    auto unauth = take_unauth(b, 100, "u"); // /login still has its 31 with authenticated at cap
    CHECK(unauth.size() == 31);
}

TEST_CASE("Pbkdf2Budget at the minimum cap 4: floor 1, main 3 (unauthenticated 2, authenticated 1)",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{4, 64};
    b.set_per_principal_cap(64);
    CHECK(b.break_glass_cap() == 1);
    CHECK(b.main_cap() == 3);
    CHECK(take_unauth(b, 10, "u").size() == 2);
    CHECK(take_auth(b, 10, "p").size() == 1);
    Pbkdf2Budget c{4, 64};
    c.set_per_principal_cap(64);
    auto u = take_unauth(c, 10, "u");
    auto a = take_auth(c, 10, "p");
    auto bg = c.try_acquire(Pbkdf2Class::kBreakGlass, "x");
    CHECK(bg.ok()); // the floor holds at the minimum cap
    CHECK_FALSE(c.try_acquire(Pbkdf2Class::kBreakGlass, "y").ok());
}

TEST_CASE("Pbkdf2Budget: the break-glass lane is subject to the per-source cap", "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, /*per_source_cap=*/1};
    auto first = b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.7");
    REQUIRE(first.ok());
    auto second = b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.7");
    CHECK_FALSE(second.ok());
    CHECK(second.refusal() == Pbkdf2Refusal::kPerSource);
    CHECK(b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.8").ok());
}

TEST_CASE("Pbkdf2Budget: take_peak reports the high-water mark then resets", "[pbkdf2_budget]") {
    Pbkdf2Budget b{66};
    {
        auto a = take_unauth(b, 5, "u");
        CHECK(b.in_flight() == 5);
    }
    CHECK(b.in_flight() == 0);
    CHECK(b.take_peak() == 5); // a point-in-time read would say 0
    CHECK(b.take_peak() == 0);
}

TEST_CASE("Pbkdf2Budget: concurrent acquirers never exceed the cap", "[pbkdf2_budget][concurrency]") {
    Pbkdf2Budget b{4, 64};
    b.set_per_principal_cap(64);
    std::atomic<int> peak{0}, cur{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 16; ++i)
        ts.emplace_back([&, i] {
            for (int k = 0; k < 200; ++k) {
                auto slot = (i % 2) ? b.try_acquire(Pbkdf2Class::kUnauthenticated, "s" + std::to_string(i))
                                    : b.try_acquire(Pbkdf2Class::kAuthenticated, {}, "p" + std::to_string(i));
                if (!slot.ok())
                    continue;
                const int now = ++cur;
                int p = peak.load();
                while (now > p && !peak.compare_exchange_weak(p, now)) {}
                std::this_thread::sleep_for(std::chrono::microseconds(100)); // real contention
                --cur;
            }
        });
    for (auto& t : ts)
        t.join();
    CHECK(peak.load() <= 3); // cap 4: floor 1, main 3
    CHECK(peak.load() >= 2); // and the contention was real
    CHECK(b.in_flight() == 0);
}

TEST_CASE("Pbkdf2Budget: break-glass is limited to ONE slot per source whatever the configured cap",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, /*per_source_cap=*/64};
    auto first = b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.7");
    REQUIRE(first.ok());
    auto second = b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.7");
    CHECK_FALSE(second.ok()); // mutation: honouring the configured 64 would admit it
    CHECK(second.refusal() == Pbkdf2Refusal::kPerSource);
    CHECK(b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.8").ok());
}

TEST_CASE("Pbkdf2Budget: per-source keys are per class (an unauthenticated hash never blocks "
          "the same address's break-glass attempt)",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, /*per_source_cap=*/1};
    auto unauth = b.try_acquire(Pbkdf2Class::kUnauthenticated, "198.51.100.7");
    REQUIRE(unauth.ok());
    auto bg = b.try_acquire(Pbkdf2Class::kBreakGlass, "198.51.100.7");
    CHECK(bg.ok()); // mutation: a shared key would refuse kPerSource here
    // and the break-glass slot does not consume the address's unauthenticated share either
    auto more = b.try_acquire(Pbkdf2Class::kUnauthenticated, "198.51.100.8");
    CHECK(more.ok());
}

TEST_CASE("login_sizing at the real pool sizes: caps, lanes, waiters and the boot warnings",
          "[pbkdf2_budget][sizing]") {
    struct Row {
        std::size_t pool;
        int cap, bg, unauth, auth, waiters;
        bool small, covers, crowded;
    };
    // per-source cap 4 (the default): covers the lane while the lane is <= 4.
    const Row rows[] = {
        {6, 4, 1, 2, 1, 2, true, true, true},
        {10, 5, 1, 2, 2, 2, true, true, false},
        {16, 8, 2, 3, 3, 2, true, true, false},
        {36, 9, 2, 4, 3, 4, true, true, false},
        {48, 12, 3, 5, 4, 6, true, false, false},
        {64, 16, 4, 6, 6, 8, false, false, false},
        {264, 66, 4, 31, 31, 33, false, false, false},
    };
    for (const auto& r : rows) {
        INFO("pool " << r.pool);
        const auto z = yuzu::server::login_sizing(r.pool, 4);
        CHECK(z.cap == r.cap);
        CHECK(z.break_glass_lane == r.bg);
        CHECK(z.unauthenticated_lane == r.unauth);
        CHECK(z.authenticated_lane == r.auth);
        CHECK(z.stripe_waiters == r.waiters);
        CHECK(z.small_pool == r.small);
        CHECK(z.per_source_covers_lane == r.covers);
        CHECK(z.pool_crowded == r.crowded);
        // The budget enforces exactly what the sizing reports.
        Pbkdf2Budget b{z.cap};
        CHECK(b.break_glass_cap() == z.break_glass_lane);
        CHECK(b.unauthenticated_cap() == z.unauthenticated_lane);
        CHECK(Pbkdf2Budget::lanes_for_cap(z.cap).authenticated == z.authenticated_lane);
    }
    // A per-source cap below the lane does not warn; at the lane it does.
    CHECK(yuzu::server::login_sizing(264, 31).per_source_covers_lane);
    CHECK(yuzu::server::login_sizing(264, 30).per_source_covers_lane == false);
    CHECK(yuzu::server::login_sizing(10, 1).per_source_covers_lane == false);
}
