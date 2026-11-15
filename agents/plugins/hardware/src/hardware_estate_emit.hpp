/**
 * hardware_estate_emit.hpp -- writes an estate Report to a CommandContext.
 *
 * The one place a leg turns the pure outcome (hardware_estate_parsers.hpp) into the wire shape:
 * the status row first, the data rows after it, and the typed result the device-record writer
 * reads its section level from. Every OS leg calls this, so the grammar cannot drift.
 *
 * Returns 0 for every outcome. (run_windows, the caller, returns 1 only when this function itself
 * throws.) A degraded read is reported through the typed result, never through the return code: a
 * non-zero rc makes the writer record the whole section as `agent:rc=<n>` unavailable and discards
 * the reason.
 *
 * `set_result_status` ASSIGNS (the last call wins), so a leg calls emit_report exactly once, with
 * the finished summary -- never per item.
 */
#pragma once

#include "hardware_estate_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <exception>

#include <string_view>

namespace yuzu::hardware::estate {

/// The typed result an outcome is reported with. A pure mapping (no context needed) so the one place
/// the status level, the typed status and the provenance rule meet is tested on every host.
struct ResultCode {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    bool carries_token; ///< true: the failure token is the provenance; false: provenance stays empty
};

[[nodiscard]] constexpr ResultCode result_code_for(Outcome o) noexcept {
    switch (o) {
    case Outcome::ok:
        // Provenance stays empty on a clean read so the writer does not record a reason for an `ok`
        // section (it falls back to the status row's token, which is "-").
        return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, false};
    case Outcome::constrained:
        return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, true};
    case Outcome::denied:
        return {YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL, true};
    case Outcome::unavailable:
        return {YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN, true};
    }
    return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, true};
}

/// Runs `fn` (returning the action's rc) and contains anything it throws: logs and returns 1. The SDK's
/// exported trampoline has no try/catch, so an exception escaping a plugin's execute() would cross the C
/// ABI and terminate the agent. Logging itself is wrapped, so this is genuinely noexcept. Pure of any
/// CommandContext so a host test can drive it with a throwing lambda.
template <class Fn> [[nodiscard]] int guarded_rc(std::string_view action, Fn&& fn) noexcept {
    try {
        return fn();
    } catch (const std::exception& e) {
        try {
            spdlog::error("hardware: action '{}' threw: {}", action, e.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            spdlog::error("hardware: action '{}' threw a non-standard exception", action);
        } catch (...) {
        }
    }
    return 1;
}

inline int emit_report(yuzu::CommandContext& ctx, std::string_view action, const Report& r) {
    ctx.write_output(status_row_for(action, r));
    for (const auto& row : r.rows)
        ctx.write_output(row);

    if (r.outcome == Outcome::constrained)
        spdlog::warn("hardware: {} degraded read ({})", action, r.token);
    else if (r.outcome == Outcome::denied)
        spdlog::warn("hardware: {} permission denied ({})", action, r.token);

    const ResultCode rc = result_code_for(r.outcome);
    ctx.set_result_status(rc.status, rc.completeness,
                          rc.carries_token ? std::string_view{r.token} : std::string_view{});
    return 0;
}

} // namespace yuzu::hardware::estate
