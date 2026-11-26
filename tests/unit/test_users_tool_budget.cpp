/**
 * test_users_tool_budget.cpp -- the per-account tool budget of users.local_users
 * (agents/plugins/users/src/users_tool_budget.hpp). Constructed time points and tool results
 * only: no clock read, no process.
 */

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "users_tool_budget.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <utility>

using namespace std::chrono_literals;
using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;
using yuzu::users::deadline_shortened;
using yuzu::users::declare_budget_exhausted;
using yuzu::users::kLocalUsersToolBudget;
using yuzu::users::settle_account_tool;
using yuzu::users::ToolBudget;
using yuzu::users::user_shell_enabled;

namespace {

// The fake plugin behind the status cases: execute runs `g_body` on the test's thread.
std::function<void(yuzu::CommandContext&)> g_body;

int body_execute(YuzuCommandContext* raw, const char*, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw};
    g_body(ctx);
    return 0;
}

/// What `body` declared on the result seam.
yuzu::agent::LocalDispatcher::Result dispatched(std::function<void(yuzu::CommandContext&)> body) {
    g_body = std::move(body);
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &body_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(&descriptor, "probe");
}

/// A finished tool as the runner reports it.
SubprocessResult ended(TerminationReason reason, int exit_code = -1) {
    SubprocessResult res;
    res.tool_ran = reason != TerminationReason::spawn_error;
    res.exit_code = exit_code;
    res.termination_reason = reason;
    return res;
}

} // namespace

TEST_CASE("ToolBudget cuts a tool deadline to what is left, then refuses",
          "[users][tool_budget][bounded_os_call]") {
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

TEST_CASE("a tool cut off by a budget-shortened deadline is skipped and forwards nothing",
          "[users][tool_budget][bounded_os_call]") {
    std::string output = "half a line";
    bool forwarded = false;
    bool skipped = false;
    const auto r = dispatched([&](yuzu::CommandContext& ctx) {
        settle_account_tool(ctx, ended(TerminationReason::deadline), 9999ms, 10s, output, forwarded,
                            skipped);
    });
    CHECK(skipped);
    CHECK(output.empty());
    CHECK_FALSE(forwarded);
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(r.result_provenance.empty());
}

TEST_CASE("every other tool failure is forwarded, the first one winning",
          "[users][tool_budget][bounded_os_call]") {
    std::string output = "partial";
    bool forwarded = false;
    bool skipped = false;
    const auto r = dispatched([&](yuzu::CommandContext& ctx) {
        // A shortened deadline alone is not the budget: only a tool that hit it was stopped by it.
        settle_account_tool(ctx, ended(TerminationReason::exited, 0), 9999ms, 10s, output,
                            forwarded, skipped);
        CHECK_FALSE(forwarded);
        // The tool's own, full deadline: a runner failure.
        settle_account_tool(ctx, ended(TerminationReason::deadline), 10s, 10s, output, forwarded,
                            skipped);
        // A later failure does not replace it.
        settle_account_tool(ctx, ended(TerminationReason::spawn_error), 10s, 10s, output, forwarded,
                            skipped);
    });
    CHECK_FALSE(skipped);
    CHECK(output == "partial");
    CHECK(forwarded);
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "subprocess_runner:deadline");
}

TEST_CASE("the budget status needs a skipped tool and no forwarded failure",
          "[users][tool_budget][bounded_os_call]") {
    const auto declared = [](bool skipped, bool forwarded) {
        return dispatched([=](yuzu::CommandContext& ctx) {
            declare_budget_exhausted(ctx, "linux", skipped, forwarded);
        });
    };
    const auto r = declared(true, false);
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "linux:users:local_users:tool_budget_exhausted");

    CHECK(declared(false, false).result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(declared(true, true).result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(declared(false, true).result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

TEST_CASE("macOS enabled is unknown unless the UserShell read exited 0",
          "[users][tool_budget][bounded_os_call]") {
    const auto read_ok = ended(TerminationReason::exited, 0);
    CHECK(user_shell_enabled(read_ok, "UserShell: /bin/zsh") == "true");
    CHECK(user_shell_enabled(read_ok, "UserShell: /usr/bin/false") == "false");
    CHECK(user_shell_enabled(read_ok, "UserShell: /sbin/nologin") == "false");

    for (const auto& res :
         {ended(TerminationReason::exited, 1), ended(TerminationReason::deadline),
          ended(TerminationReason::signaled), ended(TerminationReason::spawn_error)}) {
        CHECK(user_shell_enabled(res, "UserShell: /bin/zsh") == "unknown");
        CHECK(user_shell_enabled(res, "") == "unknown");
    }
}
