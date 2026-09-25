/**
 * firmware_posture_legs.hpp -- the seam between the plugin TU and the per-OS leg TUs. Each leg
 * defines exactly one collect_firmware_* (declared for every build, defined under its own OS #if):
 * it performs the OS read, hands bytes/strings/maps to the pure functions in
 * firmware_posture_parsers.hpp, gathers a FirmwareReport, and calls finish_report() -- the ONE
 * writer of rows and the ONE place the result status is set.
 */
#pragma once

#include <yuzu/plugin.hpp>

#include "firmware_posture_parsers.hpp"

namespace yuzu::firmware_posture {

// Each is a READ; returns 0 when no failure token was recorded, else 1 (select_verdict).
int collect_firmware_win(yuzu::CommandContext& ctx);
int collect_firmware_linux(yuzu::CommandContext& ctx);
int collect_firmware_macos(yuzu::CommandContext& ctx);

/// Writes every row, then sets the typed status (a refused read on ANY leg reports
/// PERMISSION_DENIED; absent/unavailable rows carry no token and stay OK).
inline int finish_report(yuzu::CommandContext& ctx, const FirmwareReport& report) {
    for (const auto& row : report.rows)
        ctx.write_output(format_row(row));
    const Verdict v = select_verdict(report.constraints, report.denied);
    ctx.set_result_status(v.status, v.completeness, v.reason);
    return v.rc;
}

} // namespace yuzu::firmware_posture
