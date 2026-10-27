/**
 * planned_leg.hpp -- the ONE reporter for a leg that is declared but not implemented yet.
 *
 * A plugin action whose descriptor leg is YUZU_SUPPORT_PLANNED must still answer when it
 * is dispatched: never an empty success, never `unknown`. The contract, shared by every
 * plugin so the grammar cannot drift (first written for shares_legs.hpp):
 *
 *   status|<action>|unsupported|<os>:planned      (exactly one row)
 *   result status UNAVAILABLE / completeness UNKNOWN / provenance "<os>:planned"
 *
 * `<os>` is windows, linux or macos -- the OS the plugin was built for. A leg PR that
 * lands the real read replaces the CALL to report_planned in its leg TU; it never edits
 * this header. Nothing in here can fail (no I/O, no allocation beyond the row string), so
 * report_planned returns 0 unconditionally: a planned leg is not a failed command.
 */
#pragma once

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <string>
#include <string_view>

namespace yuzu::shared {

#if defined(_WIN32)
inline constexpr std::string_view kPlannedToken = "windows:planned";
#elif defined(__linux__)
inline constexpr std::string_view kPlannedToken = "linux:planned";
#elif defined(__APPLE__)
inline constexpr std::string_view kPlannedToken = "macos:planned";
#else
#error "planned_leg.hpp: unsupported host OS"
#endif

/// `status|<action>|unsupported|<os>:planned`; `action` goes through safe_output_field.
[[nodiscard]] inline std::string format_planned_status_row(std::string_view action) {
    std::string r = "status|";
    r += yuzu::util::safe_output_field(action);
    r += "|unsupported|";
    r += kPlannedToken;
    return r;
}

/// Writes the one status row and pairs it with UNAVAILABLE/UNKNOWN. Returns 0.
inline int report_planned(yuzu::CommandContext& ctx, std::string_view action) {
    ctx.write_output(format_planned_status_row(action));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                          std::string{kPlannedToken});
    return 0;
}

} // namespace yuzu::shared
