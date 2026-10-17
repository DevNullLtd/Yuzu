/**
 * pkg_inventory_linux.cpp — Linux leg entry point.
 *
 * `managers` reports which of dpkg, apt, rpm, dnf, pacman, apk, snap and flatpak
 * are present (apt/snap/flatpak counts as facts; versions are not read).
 * `store_packages` lists installed snaps and flatpak apps/runtimes from the
 * system stores. Both are bounded, no-follow filesystem reads with no subprocess;
 * the walks live in pkg_inventory_linux_parsers.hpp over an injected root.
 *
 * `packages` reports `status|packages|unsupported|linux:owned_by_installed_apps`
 * and no data rows: installed_apps.list_inventory owns the Linux package roster,
 * and this plugin never enumerates a distro package. It reads nothing.
 */
#include "pkg_inventory_legs.hpp"

#if defined(__linux__)

#include "pkg_inventory_linux_parsers.hpp"

namespace yuzu::pkg_inventory {

int run_linux(yuzu::CommandContext& ctx, Action a) {
    return lnx::run_linux_guarded(ctx, a, "/");
}

} // namespace yuzu::pkg_inventory

#endif // defined(__linux__)
