/**
 * test_reregistration_audit_budget_alloc.cpp - WP01: the audit-mode budget under ALLOCATION
 * FAILURE (server/core/src/reregistration_audit_budget.hpp).
 *
 * WHY A SEPARATE EXECUTABLE. It replaces the global operator new (process-wide, cannot be scoped to
 * one test), so it is not a source of yuzu_server_tests and is absent under a sanitizer (which owns
 * the allocator), like tests/unit/test_spark_alloc_budget.cpp. Linux only.
 *
 * What it pins. For EVERY allocation point inside the closing admit() of a window that dropped 250
 * ids (a countdown of N allocations before the injected std::bad_alloc, N = 0, 1, 2, ...):
 *  - admit() never throws (an exception escaping it reaches gRPC as UNKNOWN);
 *  - the closed window is never lost uncounted: every dropped id is either NAMED in a queued chunk
 *    row or COUNTED by id (take_ids_truncated), summing to exactly 250.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <new>
#include <string>

#include "reregistration_audit_budget.hpp"

namespace {
thread_local long g_countdown = -1; // allocations left before the injected failure; -1 = off

void* injected_alloc(std::size_t n) {
    if (g_countdown >= 0 && g_countdown-- == 0)
        throw std::bad_alloc();
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc();
}

std::size_t ids_in_row(const std::string& row) {
    const auto at = row.find(" ids=");
    if (at == std::string::npos || at + 5 >= row.size())
        return 0;
    std::size_t n = 1;
    for (std::size_t i = at + 5; i < row.size(); ++i)
        n += row[i] == ',' ? 1 : 0;
    return n;
}
} // namespace

void* operator new(std::size_t n) { return injected_alloc(n); }
void* operator new[](std::size_t n) { return injected_alloc(n); }

TEST_CASE("budget: an allocation failure at ANY point of the window-closing admit() loses nothing "
          "uncounted and throws nothing",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    using B = yuzu::server::detail::UnprovenAuditBudget;
    std::size_t points_with_failure = 0;
    for (long n = 0; n < 400; ++n) {
        B b;
        std::int64_t t = 1'000'000;
        for (int i = 0; i < 400; ++i) // 400 ids become recent
            (void)b.admit("live-" + std::to_string(i), "seed-" + std::to_string(i / 40), t);
        t += B::kWindowMs + 1;
        for (int i = 0; i < 300; ++i) // one source: 50 rows, 250 dropped
            (void)b.admit("live-" + std::to_string(i), "atk", t);
        t += B::kWindowMs + 1;

        g_countdown = n;
        bool threw = false;
        try {
            (void)b.admit("closer", "x", t); // closes the window with 250 drops
        } catch (...) {
            threw = true;
        }
        const bool fired = g_countdown < 0; // the countdown reached zero inside admit()
        g_countdown = -1;
        CHECK_FALSE(threw);
        if (!fired)
            break; // n is past the last allocation point of admit(): every point was swept
        ++points_with_failure;

        // Nothing may be stranded in the open window: close it too.
        (void)b.poll_closed(t + B::kWindowMs + 1, true);
        std::size_t named = 0;
        while (auto row = b.take_pending())
            named += ids_in_row(row->text);
        const std::size_t counted = b.take_ids_truncated();
        INFO("allocation point " << n << ": named " << named << " counted " << counted);
        CHECK(named + counted == 250);
    }
    CHECK(points_with_failure > 5); // the sweep really exercised failures
}
