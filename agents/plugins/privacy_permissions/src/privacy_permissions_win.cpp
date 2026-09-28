/**
 * privacy_permissions_win.cpp -- Windows leg entry point.
 *
 * PLANNED -- follows as its own PR (the ConsentStore read; privacy_permissions_win_parsers.hpp
 * doesn't exist yet). Until it lands this leg reports the honest planned state -- one
 * whole-source row (category "-", state `unsupported`, `windows:planned` in `raw`) and typed
 * result status UNAVAILABLE/PARTIAL with `windows:planned` as the provenance -- rather than an
 * empty success, so a host is never read as "no grants" from a leg that did not look.
 *
 * Deliberately bypasses the shared emit_rows()/select_status(): see
 * privacy_permissions_macos.cpp's banner for why (adversarial-review finding, round 3).
 */
#include "privacy_permissions_legs.hpp"

#if defined(_WIN32)

namespace yuzu::privacy_permissions {

int collect_windows_permissions(yuzu::CommandContext& ctx) {
    const PermissionRow row{"windows", "-", "-", PermissionState::unsupported, "windows:planned",
                            "-", "-", false};
    ctx.write_output(format_row(row));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "windows:planned");
    return 0;
}

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
