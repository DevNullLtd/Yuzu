/**
 * browser_inventory_linux.cpp — Linux leg entry point (P2a-2).
 *
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * filesystem root as a parameter -- production calls it with "/"; the unit
 * suite exercises browser_inventory_linux_parsers.hpp's walks directly
 * against a materialized fixture tree and never links or runs this TU at
 * all (it only builds on __linux__, matching peripherals_linux.cpp's
 * precedent shape).
 *
 * Replaces P2a-1's compiling stub: every action now does a real read via
 * the injected-root leg functions below, and reports through the SAME
 * `status|<action>|...` wire shape and CC-07 typed-status pairing
 * browser_inventory_legs.hpp's mark_planned already established for the
 * placeholder legs -- so a `status` row appears first for every action on
 * every OS, not just the still-PLANNED macOS/Windows legs.
 */
#include "browser_inventory_legs.hpp"
#include "browser_inventory_linux_parsers.hpp"

#if defined(__linux__)

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::browser_inventory {

namespace {

/// Writes the leg-wide status row first, then every data row, and pairs
/// the typed CC-07 status with it: `failure_token` set -> `status|<action>|
/// constrained|<reason>` + CONSTRAINED/PARTIAL; unset -> `status|<action>|
/// supported|-` + OK/FULL. A malformed/unreadable input anywhere in the
/// walk (autoruns' AC4: failure != empty) is what sets `failure_token` --
/// a genuinely absent root, home, or browser config dir never does.
void emit(yuzu::CommandContext& ctx, Action a, const std::vector<std::string>& rows,
         const std::optional<std::string>& failure_token) {
    if (failure_token.has_value()) {
        ctx.write_output(std::string{"status|"} + std::string{action_name(a)} + "|constrained|" +
                         *failure_token);
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              *failure_token);
    } else {
        ctx.write_output(std::string{"status|"} + std::string{action_name(a)} + "|supported|-");
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    }
    for (const auto& row : rows)
        ctx.write_output(row);
}

int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    std::optional<std::string> failure_token;
    std::vector<std::string> rows;
    switch (a) {
    case Action::browsers:   rows = lnx::linux_browser_rows_at(root, failure_token); break;
    case Action::profiles:   rows = lnx::linux_profile_rows_at(root, failure_token); break;
    }
    emit(ctx, a, rows, failure_token);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx, Action a) {
    return run_linux_at(ctx, a, "/");
}

} // namespace yuzu::browser_inventory

#endif // defined(__linux__)
