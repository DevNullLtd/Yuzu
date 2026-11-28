/**
 * runtimes_macos.cpp -- macOS leg entry point.
 *
 * All three actions are read by runtimes_macos_parsers.hpp (`mac::run_macos_at`, the filesystem root
 * and walk configuration injected: production passes "/" and `mac::production_config()`, the default
 * bounds plus the network mounts from getmntinfo_r_np): `python` from the python.org framework,
 * `dotnet` from /usr/local/share/dotnet (and its x64 Rosetta sub-root), `jvm` from
 * /Library/Java/JavaVirtualMachines bundles (Contents/Home/release, else Contents/Info.plist). No
 * subprocess is run. Homebrew, sdkman and jenv installs are not walked.
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
