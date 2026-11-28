/**
 * pkg_inventory_win.cpp — Windows leg entry point.
 *
 * `run_windows` is a one-line wrapper over `win::run_windows_with`
 * (pkg_inventory_win_parsers.hpp), which takes its OS access as an injected ops
 * seam: production passes `win::RealOps` (HKLM Appx roster, the Chocolatey lib
 * listing and one bounded nuspec read per package); the unit suite drives the same
 * body over a FakeOps. No process is spawned: no choco.exe, no winget.exe.
 */
#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_win_parsers.hpp"

#if defined(_WIN32)

namespace yuzu::pkg_inventory {

int run_windows(yuzu::CommandContext& ctx, Action a) {
    return win::run_windows_with(ctx, a, win::RealOps{});
}

} // namespace yuzu::pkg_inventory

#endif // defined(_WIN32)
