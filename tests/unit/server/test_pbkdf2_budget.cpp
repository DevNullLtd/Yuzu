/**
 * test_pbkdf2_budget.cpp — the lane and floor arithmetic of the process-wide PBKDF2 concurrency
 * budget (WP03 perf-F1; server/core/src/pbkdf2_budget.hpp). Header-only subject, no database.
 *
 * Numbers: cap 66 (default pool of 264): break-glass floor 16, main share 50 (unauthenticated 25,
 * authenticated reserve 25), per-principal 3. Cap 8 (the floor): break-glass 2, main 6 (3 / 3).
 */

#include "../../../server/core/src/pbkdf2_budget.hpp"
#include "test_pbkdf2_budget_fill.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
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

TEST_CASE("Pbkdf2Budget sizes: cap 66 gives 16 / 50 / 25 / 25, cap 8 gives 2 / 6 / 3 / 3",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66};
    CHECK(b.break_glass_cap() == 16);
    CHECK(b.main_cap() == 50);
    CHECK(take_unauth(b, 100, "u").size() == 25);
    CHECK(take_auth(b, 100, "a").size() == 50); // the unauth slots above were freed; main share 50
    Pbkdf2Budget t{8};
    CHECK(t.break_glass_cap() == 2);
    CHECK(t.main_cap() == 6);
}

TEST_CASE("Pbkdf2Budget (a): break-glass still gets a slot with the authenticated class at its cap",
          "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, /*per_source_cap=*/64};
    b.set_per_principal_cap(64); // isolate the class bound from the per-principal bound
    auto auth = take_auth(b, 100, "p");
    CHECK(auth.size() == 50); // the authenticated class stops at the main share, not at 66
    auto bg = b.try_acquire(Pbkdf2Class::kBreakGlass, "bg-source");
    CHECK(bg.ok());
}

TEST_CASE("Pbkdf2Budget (b): the union bound leaves break-glass its whole floor", "[pbkdf2_budget]") {
    Pbkdf2Budget b{66, 64};
    b.set_per_principal_cap(64);
    // Fill the two shared classes to the bound: unauthenticated 25 first, then authenticated.
    auto unauth = take_unauth(b, 100, "u");
    auto auth = take_auth(b, 100, "p");
    CHECK(unauth.size() == 25);
    CHECK(auth.size() == 25);
    CHECK(unauth.size() + auth.size() == 50); // together bounded at cap - floor
    std::vector<Pbkdf2Budget::Slot> bg;
    for (int i = 0; i < 100; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kBreakGlass, "bg" + std::to_string(i));
        if (!s.ok())
            break;
        bg.push_back(std::move(s));
    }
    CHECK(bg.size() == 16); // the floor survives; the 17th is refused by the lane cap
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
                --cur;
            }
        });
    for (auto& t : ts)
        t.join();
    CHECK(peak.load() <= 3); // cap 4: floor 1, main 3
    CHECK(b.in_flight() == 0);
}
