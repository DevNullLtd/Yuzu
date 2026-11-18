// helper_budget.hpp -- the per-action bound on bounded helpers left behind, and the distinguishable
// marker a row carries when its hash was not attempted or did not finish.
//
// An action that hashes many files on bounded helpers (bounded_wait.hpp) can leave a helper behind
// every time one times out. `HelperBudget` caps how many may be left behind PER ACTION: once the cap
// is reached no further helper is started, so one dispatch cannot burn through the plugin's helper
// ceiling. The cap must be smaller than action_budget / per_item_budget or it can never trip before
// the action budget does (4 x 30 s already equals a 120 s action budget); the plugins use 2.
//
// A hash that was skipped or timed out is NEVER reported as an empty string (which also means
// "unreadable", "not a regular file", "over the cap"): it carries `hash_unavailable:timeout` (a
// helper was started and did not finish, or was refused) or `hash_unavailable:skipped` (not started:
// the cap or the action budget was already reached). Pure; no OS calls.
#pragma once

#include "bounded_wait.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace yuzu::shared {

inline constexpr const char* kHashUnavailableTimeout = "hash_unavailable:timeout";
inline constexpr const char* kHashUnavailableSkipped = "hash_unavailable:skipped";

/// The causes a row may carry after `hash_unavailable:`: `timeout` and `skipped` come from a bounded
/// helper, `not_examined` from a policy refusal, `not_regular`, `too_large`, `access_denied` and
/// `unreadable` from the open and read. A leg emits only the causes it can tell apart (README).
inline constexpr const char* kHashUnavailablePrefix = "hash_unavailable:";
[[nodiscard]] inline std::string hash_unavailable(std::string_view cause) {
    return std::string{kHashUnavailablePrefix}.append(cause);
}

class HelperBudget {
public:
    explicit HelperBudget(int max_stuck = 2) : max_(max_stuck) {}
    [[nodiscard]] bool may_start() const noexcept { return stuck_ < max_; }
    /// A call that did not complete (timed out, was refused at the ceiling, or threw) leaves a helper
    /// behind (or none was started): count it. A completed call costs nothing.
    void note(BoundedCallStatus status) noexcept {
        if (status != BoundedCallStatus::Completed)
            ++stuck_;
    }
    [[nodiscard]] int stuck() const noexcept { return stuck_; }

private:
    int max_;
    int stuck_{0};
};

/// The `hash` field for one row: the hash itself (possibly empty: genuinely not hashable), or the
/// marker for a helper that did not finish (`status` != Completed).
[[nodiscard]] inline std::string hash_field_for(BoundedCallStatus status, std::string value) {
    return status == BoundedCallStatus::Completed ? std::move(value) : std::string{kHashUnavailableTimeout};
}

} // namespace yuzu::shared
