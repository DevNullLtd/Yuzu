/**
 * runtimes_win.cpp -- Windows leg entry point.
 *
 * All three actions are registry reads (runtimes_win_parsers.hpp, templated on a registry-ops seam;
 * production uses RealRegOps), both registry views, no subprocess and no directory walk:
 *   python  HKLM\SOFTWARE\Python\PythonCore (PEP 514), `win::python_rows`.
 *   dotnet  HKLM\SOFTWARE\dotnet\Setup\InstalledVersions (shared frameworks and SDKs) plus the
 *           .NET Framework NDP\v4\Full release table and NDP\v3.5, `win::dotnet_rows`.
 *   jvm     the JavaSoft, Eclipse Adoptium, Microsoft and Azul Zulu home registrations, then one bounded
 *           read of each home's `release` file (never through a reparse point, leaf or ancestor), `win::jvm_rows`.
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
