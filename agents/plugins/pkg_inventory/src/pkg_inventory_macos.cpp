/**
 * pkg_inventory_macos.cpp — macOS leg entry point (Homebrew).
 *
 * `run_macos` is a one-line wrapper over `mac::run_macos_guarded`
 * (pkg_inventory_macos_parsers.hpp), which takes the filesystem root as a
 * parameter: production passes "/", the unit suite drives the same body over a
 * fixture tree through a real CommandContext. It runs the walk behind a
 * single-flight slot per action, so a walk stalled on a hung mount inside the
 * tree pins at most one agent worker per action. Pure filesystem reads: no
 * process is spawned and no `brew` binary is invoked.
 */
#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_macos_parsers.hpp"

#if defined(__APPLE__)

namespace yuzu::pkg_inventory {

int run_macos(yuzu::CommandContext& ctx, Action a) {
    return mac::run_macos_guarded(ctx, a, "/");
}

} // namespace yuzu::pkg_inventory

#endif // defined(__APPLE__)
