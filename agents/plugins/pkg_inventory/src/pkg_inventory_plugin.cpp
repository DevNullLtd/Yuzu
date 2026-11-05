/**
 * pkg_inventory_plugin.cpp — machine-scope package-manager inventory for Yuzu.
 *
 * Actions:
 *   "managers"       — which package managers are present on this host and their
 *                      manager-level configuration facts (row PR10.1-c). macOS
 *                      Homebrew, the Linux tool-presence leg (dpkg, apt, rpm,
 *                      dnf, pacman, apk, snap, flatpak) and Windows (Chocolatey
 *                      and winget presence) ship.
 *   "packages"       — macOS Homebrew formulae and casks (Cellar/Caskroom
 *                      directory names) and Windows Chocolatey packages (lib\<id>
 *                      nuspec versions). Linux is UNSUPPORTED by construction
 *                      (see below).
 *   "store_packages" — Linux snaps and flatpak apps/runtimes from the system
 *                      stores, and the Windows Appx roster registered for all
 *                      users. macOS is UNSUPPORTED by design (installed_apps owns
 *                      the application list).
 *
 * SCOPE. MACHINE-SCOPE ONLY: per-user package stores (npm global-vs-user, pip
 * user installs, cargo, per-user Homebrew) are out of scope and deferred to
 * the user-context session helper (docs/adr/3003-user-session-helper.md).
 *
 * LINUX SCOPE. `managers` is tool identity/presence plus a few capture-backed
 * counts (versions are not read); `store_packages` lists snaps and flatpaks,
 * which no distro-package roster covers. It never enumerates a dpkg/rpm/pacman/
 * apk package: installed_apps.list_inventory already covers those, so `packages`
 * is UNSUPPORTED on Linux by design rather than a second, drifting roster.
 *
 * ZERO SUBPROCESSES. Every read is a filesystem or registry read (open/openat/
 * readdir/readlinkat with O_NOFOLLOW; Reg*W and FindFirstFileExW on Windows); no
 * dpkg-query / rpm / pacman / apk / snap / flatpak / brew / choco / winget is
 * spawned.
 *
 * Every walk takes an injected root (production passes "/") so the unit suite
 * can drive it over a fixture tree; the per-OS leg TUs are one-line wrappers.
 *
 * All nine per-OS legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a complete, stable shape whichever OS built the
 * plugin. WINDOWS SCOPE: see pkg_inventory_win_parsers.hpp (machine-scope Appx
 * roster from the registry, Chocolatey lib nuspecs, winget presence through the
 * App Installer package; the WindowsApps folder is not listed).
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "pkg_inventory_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The nine per-action per-OS legs (three actions x three OSes) are FIXED and
// never wrapped in a preprocessor conditional. An unsupported-by-design leg is
// rung 0 with no mechanism (the repo idiom: antivirus_plugin.cpp,
// app_control_plugin.cpp); the note names the owner.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "managers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "tool presence by fstatat(AT_SYMLINK_NOFOLLOW) under /usr/bin, /usr/sbin, /bin, /sbin; "
         "facts: /etc/apt/sources.list.d *.list/*.sources count, /var/lib/snapd/snaps file count, "
         "/var/lib/flatpak/{app,runtime} counts",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Homebrew prefix layout: Library/Taps, Cellar, Caskroom",
         "cask rows, non-zero tap counts and the Intel prefix are exercised by synthetic in-code "
         "layouts only, never a real capture"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "C:\\ProgramData\\chocolatey\\lib directory listing (presence + directory count); winget "
         "presence and version from the HKLM Appx roster "
         "(AppxAllUserStore\\Applications\\Microsoft.DesktopAppInstaller_* key name)",
         "measured as a virtual service account (NT SERVICE\\<name>, non-admin) and as the interactive admin user, NT SERVICE\\YuzuAgent itself not used; chocolatey is "
         "found only at C:\\ProgramData\\chocolatey (ChocolateyInstall is not consulted); its own "
         "version is not read (the bootstrap package has no loose nuspec and bin\\choco.exe is a "
         "shim), so its version column is `-`"},
    },
    {
        /* .action      = */ "packages",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "installed_apps.list_inventory owns the Linux package roster"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Cellar/<formula>/<version>, Caskroom/<cask>/<version> directory names",
         "cask rows and the Intel prefix are exercised by synthetic in-code layouts only, never a "
         "real capture"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "chocolatey lib\\<id>\\<id>.nuspec, one bounded read per package, <version> by a bounded "
         "tag scan (no libxml2)",
         "measured as a virtual service account (NT SERVICE\\<name>, non-admin) and as the interactive admin user, NT SERVICE\\YuzuAgent itself not used; chocolatey is "
         "found only at C:\\ProgramData\\chocolatey (ChocolateyInstall is not consulted); a "
         "directory without a loose nuspec (the chocolatey bootstrap package) is not listed; an "
         "unreadable nuspec gives a row with an empty version"},
    },
    {
        /* .action      = */ "store_packages",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/var/lib/snapd/snaps/<name>_<rev>.snap + /snap/<name>/current readlink + "
         "<rev>/meta/snap.yaml; /var/lib/flatpak/{app,runtime}/<id>/<arch>/<branch> + active "
         "readlink",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "installed_apps owns the macOS application list"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "HKLM Appx\\AppxAllUserStore {Applications, InboxApplications, Deprovisioned} subkey names "
         "(one per PackageFullName); the WindowsApps folder is not listed and no manifest is read",
         "measured as a virtual service account (NT SERVICE\\<name>, non-admin) and as the interactive admin user, NT SERVICE\\YuzuAgent itself not used; per-user "
         "packages are not enumerated and Deprovisioned rows are not collected as software"},
    },
};

} // namespace

class PkgInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "pkg_inventory"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Machine-scope package-manager inventory (managers, packages and store_packages); "
               "per-user package stores are out of scope, deferred to the user-session helper";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"managers", "packages", "store_packages", nullptr};
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
