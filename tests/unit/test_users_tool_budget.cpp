/**
 * test_users_tool_budget.cpp -- yuzu::users::ToolBudget
 * (agents/plugins/users/src/users_tool_budget.hpp). Constructed time points only: no clock read.
 */

#include <catch2/catch_test_macros.hpp>

#include "users_tool_budget.hpp"

#include <chrono>

using namespace std::chrono_literals;
using yuzu::users::deadline_shortened;
using yuzu::users::kLocalUsersToolBudget;
using yuzu::users::ToolBudget;

TEST_CASE("ToolBudget cuts a tool deadline to what is left, then refuses", "[users][tool_budget]") {
    const std::chrono::steady_clock::time_point start{1000s};
    const ToolBudget budget{start, kLocalUsersToolBudget};
    static_assert(kLocalUsersToolBudget == 30s);

    // Plenty left: the per-call deadline.
    CHECK(budget.next_deadline(start, 10s) == 10000ms);
    CHECK(budget.next_deadline(start + 20s, 10s) == 10000ms);
    // Less than one call left: the remainder.
    CHECK(budget.next_deadline(start + 20s + 1ms, 10s) == 9999ms);
    CHECK(budget.next_deadline(start + 30s - 1ms, 10s) == 1ms);
    // Spent: do not start. A sub-millisecond remainder counts as spent.
    CHECK_FALSE(budget.next_deadline(start + 30s - 1us, 10s).has_value());
    CHECK_FALSE(budget.next_deadline(start + 30s, 10s).has_value());
    CHECK_FALSE(budget.next_deadline(start + 31s, 10s).has_value());
    // Only a deadline below the per-call one counts as shortened by the budget.
    CHECK((deadline_shortened(9999ms, 10s) && !deadline_shortened(10000ms, 10s)));
}
