/**
 * update_source_trust_legs.hpp -- shared seam between the update_source_trust
 * plugin TU and its three per-OS leg TUs.
 *
 * Holds (a) the per-OS entry-point declarations and (b) the CC-07 status
 * reporting helper every leg funnels through, so no leg can pair a status and
 * a completeness by hand. Modelled on peripherals_legs.hpp / disk_actions_legs.hpp.
 *
 * Each entry point is a READ and returns 0 unconditionally: a degraded read is
 * not a failed command, and the degradation is reported through the leading
 * `status|sources|...` row AND set_result_status (the two always agree). Only
 * the DEFINITION is self-gated (each leg .cpp wraps its own body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only the
 * host leg under the same #if -- a single-OS build never needs the other
 * symbols to link.
 */
#pragma once

#include "update_source_trust_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>

#include <string>
#include <vector>

namespace yuzu::update_source_trust {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

/// Writes the status row FIRST, then every data row, then reports the typed
/// CC-07 status. Any accumulated failure token -> constrained/partial with the
/// comma-joined tokens as the reason (each token is a string of the form
/// `<os>:<source>:<detail>`); otherwise supported/full. An empty `rows` with no
/// failure is a clean, complete "this host has none of these sources" -- it is
/// deliberately NOT a failure and NOT distinguishable from success except by
/// the absence of rows.
inline void report_sources(yuzu::CommandContext& ctx, const std::vector<std::string>& rows,
                           const yuzu::shared::ConstraintAccumulator& acc) {
    if (acc.any_failure()) {
        const std::string reason = acc.reason();
        ctx.write_output(format_status_row(StatusState::constrained, reason));
        for (const auto& r : rows)
            ctx.write_output(r);
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              reason);
        return;
    }
    ctx.write_output(format_status_row(StatusState::supported, {}));
    for (const auto& r : rows)
        ctx.write_output(r);
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

/// The Windows leg is PLANNED: a single, exact status row and an UNAVAILABLE
/// result. Kept here (not in the win TU) so the row is unit-testable on every
/// host.
inline constexpr const char* kWindowsPlannedToken = "windows:planned";

inline void report_windows_planned(yuzu::CommandContext& ctx) {
    ctx.write_output(format_status_row(StatusState::unsupported, kWindowsPlannedToken));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                          kWindowsPlannedToken);
}

} // namespace yuzu::update_source_trust
