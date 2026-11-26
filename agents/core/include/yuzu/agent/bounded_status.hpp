#pragma once

/**
 * bounded_status.hpp -- how a bounded OS call made by agent-core ended, and the ONE mapping of
 * that outcome onto the plugin result seam. Types only and thread-free, so a plugin may include
 * it. The driver that produces these (bounded_single_flight.hpp) is for agent-core.
 */

#include <yuzu/plugin.hpp>

#include <string>
#include <string_view>

namespace yuzu::agent {

enum class BoundedStatus {
    Completed, ///< the call returned within the deadline (it may still report an OS error)
    TimedOut,  ///< deadline hit (or the call threw, or the budget was already spent): no answer
    Busy,      ///< another call is in flight and healthy; none was started by this call
    Abandoned, ///< an earlier call hit its deadline and its worker is still blocked; none started
    Rejected,  ///< the outstanding-call ceiling refused, or setup failed: the worker never ran
};

/// The cause token a result row or provenance string carries; empty for Completed.
[[nodiscard]] constexpr std::string_view bounded_cause(BoundedStatus s) noexcept {
    switch (s) {
    case BoundedStatus::Completed:
        return {};
    case BoundedStatus::TimedOut:
    case BoundedStatus::Rejected:
        return "deadline_exceeded";
    case BoundedStatus::Busy:
        return "call_in_progress";
    case BoundedStatus::Abandoned:
        return "abandoned_call_pending";
    }
    return "deadline_exceeded"; // an unlisted status fails closed
}

/// Reports a call that did not complete as CONSTRAINED + PARTIAL, provenance
/// `<source_prefix>:<cause>`. Returns true when a status was set.
inline bool forward_bounded_failure(yuzu::CommandContext& ctx, BoundedStatus status,
                                    std::string_view source_prefix) {
    if (status == BoundedStatus::Completed)
        return false;
    std::string provenance{source_prefix};
    provenance += ':';
    provenance += bounded_cause(status);
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
    return true;
}

} // namespace yuzu::agent
