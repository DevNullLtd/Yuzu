/**
 * runtimes_macos.cpp -- macOS leg: PLANNED placeholder.
 *
 * The macOS reads (/usr/local/share/dotnet/shared walk; the
 * /Library/Java/JavaVirtualMachines Info.plist JavaVM dictionary +
 * Contents/Home/release) are planned. Until they ship every action reports
 * `status|<action>|unsupported|macos:planned`, matching the PLANNED macOS
 * legs the descriptor table in runtimes_plugin.cpp declares.
 */
#include "runtimes_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::runtimes {

int run_macos(yuzu::CommandContext& ctx, Action a) {
    emit_planned(ctx, a, "macos:planned");
    return 0;
}

} // namespace yuzu::runtimes

#endif // defined(__APPLE__)
