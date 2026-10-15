/**
 * runtimes_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The Windows reads (the HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP
 * release-key table + dotnet InstalledVersions + a Program Files walk; the
 * JavaSoft registry keys + a Program Files\Java walk) are planned. Until they
 * ship every action reports
 * `status|<action>|unsupported|windows:planned`, matching the PLANNED Windows
 * legs the descriptor table in runtimes_plugin.cpp declares.
 */
#include "runtimes_legs.hpp"

#if defined(_WIN32)

namespace yuzu::runtimes {

int run_windows(yuzu::CommandContext& ctx, Action a) {
    emit_planned(ctx, a, "windows:planned");
    return 0;
}

} // namespace yuzu::runtimes

#endif // defined(_WIN32)
