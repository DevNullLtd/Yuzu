/**
 * runtimes_macos.cpp -- macOS leg entry point.
 *
 * `python` is read from the python.org framework (runtimes_macos_parsers.hpp, `mac::run_macos_at`, the
 * filesystem root and walk configuration injected: production passes "/" and `mac::production_config()`,
 * the default bounds plus the network mounts from getmntinfo_r_np). The macOS .NET and JVM reads
 * (/usr/local/share/dotnet/shared walk; the /Library/Java/JavaVirtualMachines Info.plist JavaVM
 * dictionary + Contents/Home/release) are still planned: those actions report
 * `status|<action>|unsupported|macos:planned`, matching the PLANNED macOS legs the descriptor table in
 * runtimes_plugin.cpp declares.
 */
#include "runtimes_legs.hpp"
#include "runtimes_macos_parsers.hpp"

#if defined(__APPLE__)

namespace yuzu::runtimes {

int run_macos(yuzu::CommandContext& ctx, Action a) {
    return mac::run_macos_at(ctx, a, "/", mac::production_config());
}

} // namespace yuzu::runtimes

#endif // defined(__APPLE__)
