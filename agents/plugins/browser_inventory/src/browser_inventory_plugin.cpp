/**
 * browser_inventory_plugin.cpp — Chromium-family browser and profile
 * inventory for Yuzu agents.
 *
 * Actions:
 *   "browsers"   — which Chromium-family browsers (Chrome, Edge, ...) are
 *                  installed on this host.
 *   "profiles"   — per-browser profile directories, read from each
 *                  browser's "Local State" file. Never emits a
 *                  browsing-account identifier -- see
 *                  browser_inventory_parsers.hpp's PRIVACY CONTRACT. The
 *                  Linux leg's row does carry the LOCAL OS username, and
 *                  every leg's row carries a browser-supplied display
 *                  name that may be a real name (see below), two
 *                  deliberate, documented exceptions.
 *   The per-profile "extensions" action follows as its own PR (Secure
 *   Preferences / Preferences settings-map read).
 *
 * Securable: Forensics, default-off via the server-side kill switch
 * (PluginConfigStore::seed_kill_switch_default_off, execution_artifacts'
 * precedent) -- the seed call itself is wired by P2a-3, not this package.
 *
 * PRIVACY CONTRACT (binding for every leg, every OS): never emit gaia_id,
 * e-mail addresses, Chromium info_cache user_name/gaia_name, browsing
 * history, cookies or bookmarks in any row. The dedicated-identifier half
 * (gaia_id/user_name/gaia_name) is enforced structurally in
 * browser_inventory_parsers.hpp -- BrowserProfileRow simply has no such
 * fields. The e-mail-address half is enforced BY VALUE, not by absence:
 * `profile_dir` and `display_name` are free-text fields Chromium populates
 * from the account, so `profiles_from_local_state` redacts either field
 * WHOLE to `[redacted-email]` when it CONTAINS an e-mail-shaped substring
 * (`looks_like_email_address`/`kRedactedEmailPlaceholder`, adversarial-
 * review findings 2026-09-22/2026-09-23) before it ever reaches
 * BrowserProfileRow. TWO EXCEPTIONS (decided 2026-09-22): (1) the Linux
 * leg's wire-row builder (browser_inventory_linux_parsers.hpp) prepends the
 * LOCAL OS/home-directory username to disambiguate profiles across users
 * sharing a machine -- machine-local, not a browsing-account identifier,
 * and never a BrowserProfileRow field. (2) a NON-e-mail personal name in
 * BrowserProfileRow.display_name (sourced from info_cache[dir].name) is
 * emitted as-is -- Chromium-family browsers commonly auto-populate it from
 * the signed-in account's real name; this is an accepted residual risk,
 * not something this filter removes. No file inside a profile directory is
 * opened by any leg in this release; the per-profile `extensions` action
 * follows as its own PR.
 *
 * WAVE 1 (this package, P2a-1): plugin scaffold + descriptor (2 actions x
 * 3 OS legs, all declared unconditionally per the capability-matrix
 * generator's contract), the pure JSON parsers, and a COMPILING STUB for
 * the Linux leg. macOS and Windows legs are FINAL ~20-line placeholders
 * this wave -- their real implementation follows as its own PR (see the
 * descriptor's PLANNED mechanism strings below). No CFPropertyList copy,
 * no subprocess, no Firefox/Safari code in this package.
 * WAVE 2 (P2a-2) replaces the Linux leg's stub body with the real
 * ~/.config/{google-chrome,chromium,microsoft-edge} walk.
 * WAVE 3 (P2a-3) wires registration/README/YAML/server kill-switch seed.
 *
 * This TU is portable except for its single dispatch #if, which selects
 * the one host leg to call -- the same shape peripherals_plugin.cpp uses,
 * so a single-OS build never needs to link the other two legs' symbols.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "browser_inventory_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The six per-action per-OS legs (two actions x three OSes) are FIXED and
// never wrapped in a preprocessor conditional -- a single-OS build still
// declares the full per-OS shape, per the capability-matrix generator's
// contract (peripherals_plugin.cpp's precedent comment).
//
// Linux: "browsers" is CONSTRAINED (presence-only detection, no
// version/channel probe in this package); "profiles" is SUPPORTED (a real
// Local State JSON read, browser_inventory_linux_parsers.hpp). macOS and
// Windows: PLANNED on both actions this wave, mechanism strings name the
// follow-up PR's plan. The "extensions" action follows as its own PR and
// has no row here until it lands.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "browsers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "fixed system binary path presence "
         "(/opt/google/chrome/chrome, /opt/microsoft/msedge/msedge, "
         "/usr/lib/chromium/chromium)",
         "presence-only; no version/channel detection in this package"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application "
         "Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs",
         "follows as its own PR"},
    },
    {
        /* .action      = */ "profiles",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "~/.config/{google-chrome,chromium,microsoft-edge}/Local State JSON read", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application "
         "Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs",
         "follows as its own PR"},
    },
};

} // namespace

class BrowserInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "browser_inventory"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Chromium-family browser and profile inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"browsers", "profiles", nullptr};
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
        const auto act = yuzu::browser_inventory::parse_action(action);
        if (!act) {
            // `action` is request-supplied and lands in a pipe-delimited stream, so
            // it goes through the shared escaper like any other untrusted field.
            // This is deliberately NOT a row (no leading kind token), which is why
            // it does not use the legs.hpp formatters.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }

        // Every failure-token literal this plugin dir emits matches
        // ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$ -- Yuzu targets
        // exactly these three OSes (CLAUDE.md "Target architecture"), so
        // there is deliberately no fourth branch here.
#if defined(_WIN32)
        return yuzu::browser_inventory::run_windows(ctx, *act);
#elif defined(__linux__)
        return yuzu::browser_inventory::run_linux(ctx, *act);
#elif defined(__APPLE__)
        return yuzu::browser_inventory::run_macos(ctx, *act);
#endif
        return 1; // unreachable on a supported build (see the comment above); avoids
                  // falling off the end of a non-void function if one ever isn't.
    }
};

YUZU_PLUGIN_EXPORT(BrowserInventoryPlugin)
