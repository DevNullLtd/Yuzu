/**
 * pkg_inventory_linux.cpp — Linux leg entry point: `managers` is a PLANNED
 * placeholder, `packages` is UNSUPPORTED by design.
 *
 * `managers` reports `status|managers|unsupported|linux:planned` and no data
 * rows: the Linux manager identity/config leg follows as its own PR, and the
 * descriptor declares it YUZU_SUPPORT_PLANNED to match.
 *
 * `packages` reports `status|packages|unsupported|linux:owned_by_installed_apps`
 * and no data rows: installed_apps.get_inventory_linux owns the Linux package
 * roster, and this plugin never enumerates a package in any form.
 *
 * Neither action reads anything from the host.
 */
#include "pkg_inventory_legs.hpp"

#if defined(__linux__)

namespace yuzu::pkg_inventory {

int run_linux(yuzu::CommandContext& ctx, Action a) {
    switch (a) {
    case Action::managers:
        emit_unsupported(ctx, a, kTokenLinuxPlanned);
        break;
    case Action::packages:
        emit_unsupported(ctx, a, kTokenLinuxPackagesOwned);
        break;
    }
    return 0;
}

} // namespace yuzu::pkg_inventory

#endif // defined(__linux__)
