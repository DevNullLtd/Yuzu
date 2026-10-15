/**
 * update_source_trust_legs.hpp -- shared seam between the update_source_trust
 * plugin TU and its three per-OS leg TUs.
 *
 * Holds (a) the per-OS entry-point declarations, (b) the CC-07 status
 * reporting helpers every leg funnels through, so no leg can pair a status and
 * a completeness by hand, and (c) execute_sources, the plugin's whole execute()
 * body (dispatch + ABI containment), so the plugin TU is a two-line shell and
 * the unit suite drives the body through a real CommandContext. Modelled on
 * peripherals_legs.hpp / disk_actions_legs.hpp.
 *
 * Each entry point is a READ and returns 0 unconditionally: a degraded read is
 * not a failed command, and the degradation is reported through the leading
 * `status|sources|...` row AND set_result_status, written together so they agree.
 * (If write_output itself throws mid-emission, execute_sources contains it and
 * appends an `unsupported` row + UNAVAILABLE, so the LAST status row wins.) Only
 * the DEFINITION is self-gated (each leg .cpp wraps its own body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only the
 * host leg under the same #if -- a single-OS build never needs the other
 * symbols to link.
 */
#pragma once

#include "update_source_trust_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <exception_category.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>
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
    const bool degraded = acc.any_failure();
    const std::string reason = degraded ? acc.reason() : std::string{};
    ctx.write_output(format_status_row(degraded ? StatusState::constrained : StatusState::supported,
                                       reason));
    for (const auto& r : rows)
        ctx.write_output(r);
    ctx.set_result_status(degraded ? YUZU_RESULT_STATUS_CONSTRAINED : YUZU_RESULT_STATUS_OK,
                          degraded ? YUZU_RESULT_COMPLETENESS_PARTIAL : YUZU_RESULT_COMPLETENESS_FULL,
                          reason);
}

/// A leg that reads nothing reports ONE exact `unsupported` status row and an
/// UNAVAILABLE/UNKNOWN result carrying the same token -- never an empty
/// success. Called by the Windows and macOS legs (planned; their tokens below).
/// execute_sources' catch arm (a leg that threw, `<os>:leg:exception`) does NOT use it:
/// it hand-pairs the same UNAVAILABLE/UNKNOWN under a separate guard per call, because
/// there the allocator may be failing and one throw must not skip the other report.
/// Kept here (not in the per-OS TUs) so the row is unit-testable on every host.
inline constexpr const char* kWindowsPlannedToken = "windows:planned";
inline constexpr const char* kMacosPlannedToken = "macos:planned";

inline void report_unavailable(yuzu::CommandContext& ctx, std::string_view token) {
    ctx.write_output(format_status_row(StatusState::unsupported, token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                          token);
}

/// One per-OS leg entry point (run_windows / run_linux / run_macos).
using LegFn = int (*)(yuzu::CommandContext&);

/// The WHOLE body of the plugin's execute(): action dispatch, the host leg and
/// the ABI containment. No exception may cross the plugin ABI, so everything --
/// the unknown-action write included -- sits inside the try, and the catch arm
/// reports the leg as unavailable instead of unwinding into the host. rc: 1 for an unknown
/// action; otherwise the leg's own; after a throw, 0 once the typed status landed and 1 only
/// if set_result_status itself threw. Under sustained allocation failure the status row may
/// be lost while the typed status (or rc 1) still reaches the host.
/// `leg_exception_token` is the host OS's `<os>:leg:exception`. The unit suite
/// drives this through a real CommandContext with a throwing leg and with an
/// unknown action (test_update_source_trust_local_dispatcher.cpp).
inline int execute_sources(yuzu::CommandContext& ctx, std::string_view action, LegFn leg,
                           std::string_view leg_exception_token) {
    try {
        if (action != "sources") {
            // `action` is request-supplied and lands in a pipe-delimited stream, so
            // it goes through the shared escaper like any other untrusted field.
            // Deliberately not a row (no leading kind token).
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }
        return leg(ctx);
    } catch (...) {
        // `<os>:leg:exception:<bad_alloc|std_exception|unknown>` -- what() never travels.
        // exception_category() is noexcept; everything else here can allocate and throw again
        // under sustained allocation failure, and nothing may cross the plugin ABI. The token
        // falls back to the bare `<os>:leg:exception` view, and each report is its own guard
        // (report_unavailable is not used: it pairs both calls in one unguarded body).
        std::string owned;
        std::string_view token = leg_exception_token;
        try {
            owned.reserve(leg_exception_token.size() + 14);
            owned.append(leg_exception_token).append(1, ':').append(yuzu::shared::exception_category());
            token = owned;
        } catch (...) {
        }
        try {
            ctx.write_output(format_status_row(StatusState::unsupported, token));
        } catch (...) {
        }
        try {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                                  token);
            return 0; // reported: a leg that threw is a degraded read, not a failed command
        } catch (...) {
            return 1; // the typed status never reached the host; rc is the only signal left
        }
    }
}

} // namespace yuzu::update_source_trust
