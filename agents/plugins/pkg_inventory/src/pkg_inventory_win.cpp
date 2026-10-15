/**
 * pkg_inventory_win.cpp — Windows leg entry point: PLANNED placeholder.
 *
 * Both actions report `status|<action>|unsupported|windows:planned` and no data
 * rows. The real legs (Chocolatey lib\ walk + nuspec metadata; winget presence)
 * follow as their own PR; no winget argv and no libxml2 dependency lands here
 * (unwired code is not committed). The descriptor declares both Windows legs
 * YUZU_SUPPORT_PLANNED to match.
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
