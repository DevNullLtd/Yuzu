/**
 * pkg_inventory_plugin.cpp — machine-scope package-manager inventory for Yuzu.
 *
 * Actions:
 *   "managers" — which package managers are present on this host and their
 *                manager-level configuration facts (row PR10.1-c). macOS
 *                Homebrew ships in this release; the Linux and Windows legs are
 *                PLANNED placeholders (see below).
 *   "packages" — macOS Homebrew formulae and casks (Cellar/Caskroom directory
 *                names). Linux is UNSUPPORTED by construction (see below);
 *                Windows is a PLANNED placeholder.
 *
 * SCOPE. MACHINE-SCOPE ONLY: per-user package stores (npm global-vs-user, pip
 * user installs, cargo, per-user Homebrew) are out of scope and deferred to
 * the user-context session helper (docs/adr/3003-user-session-helper.md).
 *
 * LINUX SCOPE. The Linux leg is scoped to package-manager
 * identity/presence and manager-level config facts ONLY. It never enumerates an
 * individual package in any form: installed_apps.get_inventory_linux already
 * covers dpkg + rpm + pacman + apk, so `packages` is UNSUPPORTED on Linux by
 * design rather than a second, drifting roster. That identity/config `managers`
 * leg follows as its own PR; until it lands, Linux `managers` reports the
 * PLANNED token.
 *
 * ZERO SUBPROCESSES. Every read is a filesystem read (open/openat/readdir with
 * O_NOFOLLOW); no dpkg-query / rpm / pacman / apk / brew / winget is spawned.
 *
 * Every walk takes an injected root (production passes "/") so the unit suite
 * can drive it over a fixture tree; the macOS leg TU is a one-line wrapper.
 *
 * All six per-OS legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a complete, stable shape whichever OS built the
 * plugin. The Windows legs and the Linux `managers` leg are PLANNED
 * placeholders: the Chocolatey walk and winget presence, and the Linux manager
 * identity/config walk, each follow as their own PR.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "pkg_inventory_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The six per-action per-OS legs (two actions x three OSes) are FIXED and
// never wrapped in a preprocessor conditional.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "managers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "tool presence + /var/lib/dpkg/arch, /etc/apt/sources.list.d count, /etc/yum.repos.d "
         "count, /etc/dnf/dnf.conf, /etc/pacman.conf + pacman.d/mirrorlist, "
         "/etc/apk/repositories + /etc/apk/arch",
         "follows as its own PR"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Homebrew prefix layout: Library/Taps, Cellar, Caskroom",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProgramData\\chocolatey lib/ walk + Program Files\\WindowsApps DesktopAppInstaller "
         "folder presence for winget; follows as its own PR",
         nullptr},
    },
    {
        /* .action      = */ "packages",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 1, "none by design",
         "installed_apps.get_inventory_linux owns the Linux package roster"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Cellar/<formula>/<version>, Caskroom/<cask>/<version> directory names",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "chocolatey lib/<id>/<id>.nuspec via libxml2; follows as its own PR", nullptr},
    },
};

} // namespace

class PkgInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "pkg_inventory"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Machine-scope package-manager inventory (managers and packages); per-user "
               "package stores are out of scope, deferred to the user-session helper";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"managers", "packages", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        // The WHOLE body -- the unknown-action diagnostic row included -- runs
        // under run_guarded: a walk exception thrown anywhere below must still
        // report pkg_inventory's own typed status/provenance row rather than
        // propagate past this frozen ABI seam unannotated.
        return yuzu::pkg_inventory::run_guarded(ctx, action, [&]() -> int {
            const auto parsed = yuzu::pkg_inventory::parse_action(action);
            if (!parsed) {
                // `action` is request-supplied and lands in a pipe-delimited stream, so
                // it goes through the shared escaper. Deliberately NOT a row (no
                // leading kind token): an unknown action has no status row.
                ctx.write_output(std::string{"unknown action: "} +
                                 yuzu::util::safe_output_field(action));
                return 1;
            }

            // Yuzu targets exactly windows/linux/macos (CLAUDE.md "Target
            // architecture"), so there is deliberately no fourth branch.
#if defined(_WIN32)
            return yuzu::pkg_inventory::run_windows(ctx, *parsed);
#elif defined(__linux__)
            return yuzu::pkg_inventory::run_linux(ctx, *parsed);
#elif defined(__APPLE__)
            return yuzu::pkg_inventory::run_macos(ctx, *parsed);
#endif
            return 1; // unreachable on a supported build
        });
    }
};

YUZU_PLUGIN_EXPORT(PkgInventoryPlugin)
