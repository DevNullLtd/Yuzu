/**
 * runtimes_win.cpp -- Windows leg entry point.
 *
 * `python` is read from the PEP 514 registry keys (runtimes_win_parsers.hpp, `win::python_rows`,
 * templated on a registry-ops seam; production uses RealRegOps). The Windows .NET and JVM reads (the
 * HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP release-key table + dotnet InstalledVersions + a
 * Program Files walk; the JavaSoft registry keys + a Program Files\Java walk) are still planned:
 * those actions report `status|<action>|unsupported|windows:planned`, matching the PLANNED Windows
 * legs the descriptor table in runtimes_plugin.cpp declares.
 */
#include "runtimes_legs.hpp"
#include "runtimes_win_parsers.hpp"

#if defined(_WIN32)

namespace yuzu::runtimes {

int run_windows(yuzu::CommandContext& ctx, Action a) {
    return win::run_windows_with(ctx, a, win::RealRegOps{});
}

} // namespace yuzu::runtimes

#endif // defined(_WIN32)
