// users_tool_budget.hpp -- the total time one local_users run may spend on its per-account tools
// (lastlog on Linux; dscl and last on macOS). Each tool already has its own deadline; this bounds
// their sum, which otherwise grows with the number of accounts. Pure: the caller supplies the
// clock.
#pragma once

#include <algorithm>
#include <chrono>
#include <optional>

namespace yuzu::users {

inline constexpr std::chrono::milliseconds kLocalUsersToolBudget{30000};

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

} // namespace yuzu::users
