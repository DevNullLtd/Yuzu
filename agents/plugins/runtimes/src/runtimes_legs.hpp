/**
 * runtimes_legs.hpp -- shared seam between the runtimes plugin TU and its
 * three per-OS leg TUs (peripherals_legs.hpp shape).
 *
 * Holds (a) the `Action` enum and its string conversions, (b) the per-OS
 * entry-point declarations, and (c) the two result-emission helpers every
 * leg calls, so no leg picks a status/completeness pairing by hand.
 *
 * Shipped legs: Linux. macOS and Windows are PLANNED placeholders that emit
 * `status|<action>|unsupported|<macos|windows>:planned`.
 */
#pragma once

#include "runtimes_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::runtimes {

/// One value per `actions()` entry (runtimes_plugin.cpp).
enum class Action { dotnet, jvm };

[[nodiscard]] constexpr std::string_view action_name(Action a) noexcept {
    switch (a) {
    case Action::dotnet: return "dotnet";
    case Action::jvm:    return "jvm";
    }
    return "dotnet";
}

/// nullopt for an unknown action name, so execute() can tell "unknown action"
/// from a real one.
[[nodiscard]] constexpr std::optional<Action> parse_action(std::string_view s) noexcept {
    if (s == "dotnet") return Action::dotnet;
    if (s == "jvm") return Action::jvm;
    return std::nullopt;
}

// -- per-OS entry points (defined by the leg TUs) ---------------------------
//
// Each is a READ and returns 0 unconditionally: a degraded read is not a
// failed command; the degradation is reported through the status row and
// set_result_status. Declared unconditionally so every TU sees the same
// signature; only the DEFINITION is self-gated (each leg .cpp wraps its body
// in `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
// the host leg under the same #if.

int run_windows(yuzu::CommandContext& ctx, Action a);
int run_linux(yuzu::CommandContext& ctx, Action a);
int run_macos(yuzu::CommandContext& ctx, Action a);

// -- result emission ---------------------------------------------------------

/// A completed read: writes the status row FIRST, then every data row, and
/// reports OK/FULL, or CONSTRAINED/PARTIAL (reason = the accumulated tokens)
/// when the accumulator recorded any failure. Zero rows + no failure means none
/// found at the standard roots (OK/FULL, status `supported`).
inline void emit_read(yuzu::CommandContext& ctx, Action a,
                      const std::vector<std::string>& data_rows,
                      const yuzu::shared::ConstraintAccumulator& acc) {
    for (const auto& row : compose_output(action_name(a), data_rows, acc))
        ctx.write_output(row);
    if (acc.any_failure()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              acc.reason());
    } else {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    }
}

/// A leg that does not read anything on this OS (planned / not yet wired):
/// writes `status|<action>|unsupported|<os_token>` and reports
/// UNAVAILABLE/PARTIAL. `os_token` is a string literal of the form
/// `<os>:<detail>` (e.g. "macos:planned").
inline void emit_planned(yuzu::CommandContext& ctx, Action a, std::string_view os_token) {
    ctx.write_output(format_planned_status_row(action_name(a), os_token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          os_token);
}

} // namespace yuzu::runtimes
