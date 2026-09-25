/**
 * browser_inventory_legs.hpp — shared seam between the browser_inventory
 * plugin TU and its three per-OS leg TUs.
 *
 * Holds (a) the `Action` enum and its string conversions, (b) the per-OS
 * entry-point declarations, and (c) the shared placeholder-row helper the
 * two FINAL placeholder legs (macOS, Windows) use this wave. Modelled on
 * agents/plugins/peripherals/src/peripherals_legs.hpp, the most recent
 * multi-TU plugin to establish this shape.
 */
#pragma once

#include "browser_inventory_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::browser_inventory {

/// The two actions this package covers. One value per `actions()` entry
/// (browser_inventory_plugin.cpp) -- see action_name/parse_action for the
/// string<->enum mapping the dispatcher and the descriptor rely on.
enum class Action { browsers, profiles };

[[nodiscard]] constexpr std::string_view action_name(Action a) noexcept {
    switch (a) {
    case Action::browsers:   return "browsers";
    case Action::profiles:   return "profiles";
    }
    return "browsers";
}

/// Parses an action name into its `Action`. nullopt for anything else --
/// callers (the plugin TU's execute()) use that to distinguish "unknown
/// action" from a real one.
[[nodiscard]] constexpr std::optional<Action> parse_action(std::string_view action) noexcept {
    if (action == "browsers") return Action::browsers;
    if (action == "profiles") return Action::profiles;
    return std::nullopt;
}

// ── per-OS entry points (defined by the leg TUs) ─────────────────────────
//
// Declared unconditionally so the plugin TU and every leg TU see the same
// signature regardless of which OS built them; only the DEFINITION is
// self-gated (each leg .cpp wraps its own body in
// `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
// the host leg under that same #if -- so a single-OS build never needs the
// other two symbols to link.
//
// This wave: run_linux is a COMPILING STUB (P2a-2 fills the real body);
// run_macos and run_windows are FINAL placeholders (their real
// implementation is a follow-up PR -- see the descriptor's PLANNED
// mechanism strings and "follows as its own PR" notes).

int run_linux(yuzu::CommandContext& ctx, Action a);
int run_macos(yuzu::CommandContext& ctx, Action a);
int run_windows(yuzu::CommandContext& ctx, Action a);

/// Shared wire shape for a PLANNED leg this wave (macOS, Windows -- and the
/// (P2a-1's Linux compiling stub reused this row shape via mark_stub_linux,
/// reporting CONSTRAINED rather than UNAVAILABLE; P2a-2 replaced the stub
/// with a real leg -- browser_inventory_linux.cpp -- and mark_stub_linux is
/// gone with it.) One row, `status|<action>|unsupported|<os_tag>:planned`,
/// plus a typed status of UNAVAILABLE/PARTIAL naming the same reason.
/// `os_tag` is one of "macos"/"windows" -- the real Linux leg reports
/// itself, never through this helper.
inline void mark_planned(yuzu::CommandContext& ctx, Action a, std::string_view os_tag) {
    ctx.write_output(std::string{"status|"} + std::string{action_name(a)} + "|unsupported|" +
                     std::string{os_tag} + ":planned");
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          std::string{os_tag} + " leg is PLANNED, not implemented in this package");
}

} // namespace yuzu::browser_inventory
