// users_tool_budget.hpp -- the total time one local_users run may spend on its per-account tools
// (lastlog on Linux; dscl and last on macOS), and what their outcomes report. Each tool already
// has its own deadline; this bounds their sum, which otherwise grows with the number of accounts.
// Starts no process and reads no clock: the caller supplies the time and the finished results.
#pragma once

#include <algorithm>
#include <chrono>
#include <format>
#include <optional>
#include <string>
#include <string_view>

#include <yuzu/agent/runner_status.hpp> // forward_runner_failure, SubprocessResult

namespace yuzu::users {

inline constexpr std::chrono::milliseconds kLocalUsersToolBudget{30000};

/// True when the budget cut a tool's deadline below `per_call`: a tool that then hits it was
/// stopped by the budget, not by its own deadline.
[[nodiscard]] inline bool deadline_shortened(std::chrono::milliseconds deadline,
                                             std::chrono::milliseconds per_call) {
    return deadline < per_call;
}

class ToolBudget {
public:
    ToolBudget(std::chrono::steady_clock::time_point start, std::chrono::milliseconds total)
        : end_{start + total} {}

    /// The deadline for a tool started at `now`: `per_call`, cut to what is left of the budget.
    /// nullopt once the budget is spent: do not start the tool.
    [[nodiscard]] std::optional<std::chrono::milliseconds>
    next_deadline(std::chrono::steady_clock::time_point now,
                  std::chrono::milliseconds per_call) const {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - now);
        if (left <= std::chrono::milliseconds::zero())
            return std::nullopt;
        return std::min(per_call, left);
    }

private:
    std::chrono::steady_clock::time_point end_;
};

/// Settles one finished per-account tool. One stopped by the budget counts as skipped: nothing is
/// forwarded and its output is dropped, so its field stays unread. Every other runner failure is
/// forwarded, the first one winning.
inline void settle_account_tool(yuzu::CommandContext& ctx, const yuzu::agent::SubprocessResult& res,
                                std::chrono::milliseconds deadline,
                                std::chrono::milliseconds per_call, std::string& output,
                                bool& status_forwarded, bool& tool_skipped) {
    if (res.termination_reason == yuzu::agent::TerminationReason::deadline &&
        deadline_shortened(deadline, per_call)) {
        tool_skipped = true;
        output.clear();
    } else if (!status_forwarded) {
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    }
}

/// Ends a run: a tool skipped for the budget makes the answer partial, and is declared unless a
/// runner failure was already forwarded.
inline void declare_budget_exhausted(yuzu::CommandContext& ctx, std::string_view os,
                                     bool tool_skipped, bool status_forwarded) {
    if (tool_skipped && !status_forwarded)
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              std::format("{}:users:local_users:tool_budget_exhausted", os));
}

/// macOS `enabled`, from one `dscl . -read /Users/<name> UserShell`. Only a read that exited 0
/// decides ("false" for a false or nologin shell); a killed or failed one is "unknown".
[[nodiscard]] inline std::string_view user_shell_enabled(const yuzu::agent::SubprocessResult& res,
                                                         std::string_view output) {
    if (res.termination_reason != yuzu::agent::TerminationReason::exited || res.exit_code != 0)
        return "unknown";
    const auto space = output.find(' '); // "UserShell: /bin/zsh"
    if (space == std::string_view::npos)
        return "true";
    const auto shell = output.substr(space + 1);
    const bool disabled = shell.find("false") != std::string_view::npos ||
                          shell.find("nologin") != std::string_view::npos;
    return disabled ? "false" : "true";
}

} // namespace yuzu::users
