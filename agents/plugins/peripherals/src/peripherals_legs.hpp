/**
 * peripherals_legs.hpp — shared seam between the peripherals plugin TU and
 * its three per-OS leg TUs.
 *
 * Holds (a) the `Kind` enum and its string conversions, (b) the per-OS
 * entry-point declarations, and (c) the CC-07 status-reporting helper. Wave 1
 * shipped every leg as a placeholder (`mark_result_read(ctx, k, 0,
 * "<os>:leg:not_implemented")`); Wave 2 replaced the bodies with the real
 * SetupAPI/sysfs/IOKit walks. Modelled on disk_actions_legs.hpp, the most
 * recent plugin to establish this multi-TU shape.
 */
#pragma once

#include "peripherals_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <cstddef>
#include <optional>
#include <string_view>

namespace yuzu::peripherals {

/// The three bus_inventory kinds this Wave-1 package covers. One value per
/// `actions()` entry (peripherals_plugin.cpp) — see kind_name/parse_kind for
/// the string<->enum mapping the dispatcher and the descriptor rely on.
enum class Kind { usb, pci, thunderbolt };

[[nodiscard]] constexpr std::string_view kind_name(Kind k) noexcept {
    switch (k) {
    case Kind::usb:         return "usb";
    case Kind::pci:         return "pci";
    case Kind::thunderbolt: return "thunderbolt";
    }
    return "usb";
}

/// Parses an action name into its `Kind`. nullopt for anything else --
/// callers (the plugin TU's execute(), and any future consumer) use that to
/// distinguish "unknown action" from a real kind.
[[nodiscard]] constexpr std::optional<Kind> parse_kind(std::string_view action) noexcept {
    if (action == "usb") return Kind::usb;
    if (action == "pci") return Kind::pci;
    if (action == "thunderbolt") return Kind::thunderbolt;
    return std::nullopt;
}

// ── per-OS entry points (defined by the leg TUs) ─────────────────────────
//
// Each is a READ. Each returns 0 unconditionally: a degraded read is not a
// failed command, and the degradation is reported through set_result_status
// instead (the same binding rule disk_actions/filesystem_posture follow).
// Declared unconditionally so the plugin TU and every leg TU see the same
// signature regardless of which OS built them; only the DEFINITION is
// self-gated (each leg .cpp wraps its own body in
// `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
// the host leg under that same #if -- so a single-OS build never needs the
// other two symbols to link.

int run_windows(yuzu::CommandContext& ctx, Kind k);
int run_linux(yuzu::CommandContext& ctx, Kind k);
int run_macos(yuzu::CommandContext& ctx, Kind k);

// ── CC-07 status reporting ───────────────────────────────────────────────
//
// set_result_status defaults to UNDECLARED, from which the agent derives a
// coarse SUCCESS -- so omitting this on a degraded read silently reports a
// clean run. `mark_result_read` is the ONE seam every leg calls, so a wave-2
// leg cannot pick the wrong status/completeness pairing by hand.
//
// rows > 0            -> caller already wrote the real rows; OK/FULL.
// rows == 0, no token  -> the leg attempted the read honestly and found
//                         nothing; write the `<kind>|none` placeholder,
//                         still OK/FULL (an empty result is not a failure).
// failure_token set    -> the leg could not attempt the read at all; write
//                         `<kind>|unavailable|<token>` and report
//                         CONSTRAINED/PARTIAL, reason = token. Every token is
//                         a STRING LITERAL of the form `<os>:<source>:<detail>`
//                         (e.g. "linux:sysfs:eacces", "windows:leg:not_implemented").
inline void mark_result_read(yuzu::CommandContext& ctx, Kind k, std::size_t rows,
                             std::optional<std::string_view> failure_token) {
    if (failure_token.has_value()) {
        ctx.write_output(format_unavailable_row(kind_name(k), *failure_token));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              *failure_token);
        return;
    }
    if (rows == 0) {
        ctx.write_output(format_none_row(kind_name(k)));
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

} // namespace yuzu::peripherals
