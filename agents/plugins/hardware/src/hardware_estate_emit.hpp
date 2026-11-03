/**
 * hardware_estate_emit.hpp -- writes an estate Report to a CommandContext.
 *
 * The one place a leg turns the pure outcome (hardware_estate_parsers.hpp) into the wire shape:
 * the status row first, the data rows after it, and the typed result the device-record writer
 * reads its section level from. Every OS leg calls this, so the grammar cannot drift.
 *
 * Always returns 0 (run_windows alone returns 1, when this function itself throws). A degraded read
 * is reported through the typed result, never through the return code: a non-zero rc makes the writer record the whole section as `agent:rc=<n>`
 * unavailable and discards the reason.
 *
 * `set_result_status` ASSIGNS (the last call wins), so a leg calls emit_report exactly once, with
 * the finished summary -- never per item.
 */
#pragma once

#include "hardware_estate_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <string_view>

namespace yuzu::hardware::estate {

inline int emit_report(yuzu::CommandContext& ctx, std::string_view action, const Report& r) {
    ctx.write_output(status_row_for(action, r));
    for (const auto& row : r.rows)
        ctx.write_output(row);

    switch (r.outcome) {
    case Outcome::ok:
        // Provenance stays empty on a clean read so the writer does not record a reason for an
        // `ok` section (it falls back to the status row's token, which is "-").
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {});
        break;
    case Outcome::constrained:
        spdlog::warn("hardware: {} degraded read ({})", action, r.token);
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              r.token);
        break;
    case Outcome::denied:
        spdlog::warn("hardware: {} permission denied ({})", action, r.token);
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED,
                              YUZU_RESULT_COMPLETENESS_PARTIAL, r.token);
        break;
    case Outcome::unavailable:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                              r.token);
        break;
    }
    return 0;
}

} // namespace yuzu::hardware::estate
