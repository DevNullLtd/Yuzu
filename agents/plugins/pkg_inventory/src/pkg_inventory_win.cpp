/**
 * pkg_inventory_win.cpp — Windows leg entry point: PLANNED placeholder.
 *
 * Every action (managers, packages, store_packages) reports
 * `status|<action>|unsupported|windows:planned` and no data rows. The real legs
 * (Chocolatey lib\ walk + nuspec metadata; winget presence; the Appx store
 * roster) follow as their own PRs; no winget argv and no libxml2 dependency
 * lands here (unwired code is not committed). The descriptor declares every
 * Windows leg YUZU_SUPPORT_PLANNED to match.
 */
#include "pkg_inventory_legs.hpp"

#if defined(_WIN32)

namespace yuzu::pkg_inventory {

int run_windows(yuzu::CommandContext& ctx, Action a) {
    emit_unsupported(ctx, a, kTokenWindowsPlanned);
    return 0;
}

} // namespace yuzu::pkg_inventory

#endif // defined(_WIN32)
