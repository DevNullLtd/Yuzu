/**
 * browser_policy_plugin.cpp — enterprise-managed browser policy inventory.
 *
 * Action:
 *   "policies" — one `policy|...` row per configured Chrome/Chromium/Edge
 *                policy: browser, mandatory|recommended level, machine|user
 *                scope, name, typed value, and the file it came from (row
 *                schema: browser_policy_parsers.hpp).
 *
 * Sources (all rung 1, file/registry truth, no process spawn):
 *   Linux    /etc/opt/{chrome,edge} and /etc/chromium policies/{managed,
 *            recommended} JSON files                    [linux.cpp]
 *   Windows  PLANNED, follows as its own PR: HKLM\SOFTWARE\Policies\
 *            {Google\Chrome,Microsoft\Edge} (+ the Recommended subkeys)
 *                                                       [win.cpp]
 *   macOS    PLANNED, follows as its own PR: /Library/Managed Preferences/
 *            {,<user>/}{com.google.Chrome,com.microsoft.Edge}.plist
 *                                                       [macos.cpp]
 *
 * The Windows and macOS legs are placeholders: each reports ONE in-band
 * `status` row (`unavailable`, `<os>:planned`) and result status
 * UNAVAILABLE/PARTIAL with that provenance (mark_result_planned), never an
 * empty success. Any read that could not be completed is reported the same
 * way as `constrained` (mark_result_read).
 *
 * This is operator/IT-authored configuration, not personal data, so it is an
 * ordinary `Inventory` read with no default-OFF kill switch seeded (that gate
 * is for plugins that read user-identifying data, which this one does not; the
 * operator-settable per-plugin kill switch still applies to every plugin).
 * Policy values are reported verbatim: a value can carry a credential-bearing
 * URL or an enrollment token an administrator put in a world-readable file.
 *
 * Portable except for the single dispatch #if selecting the host leg; all
 * three descriptor legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a stable shape whichever OS built the plugin.
 */

#include <yuzu/plugin.hpp>

#include "browser_policy_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "policies",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/etc/opt/{chrome,edge} and /etc/chromium policies/{managed,recommended}/*.json "
         "(nlohmann)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Library/Managed Preferences/{,<user>/}{com.google.Chrome,com.microsoft.Edge}.plist "
         "(CFPropertyListCreateWithData)",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "HKLM\\SOFTWARE\\Policies\\{Google\\Chrome,Microsoft\\Edge} registry reads "
         "(RegKey enumerate_value_names)",
         "follows as its own PR"},
    },
};

} // namespace

class BrowserPolicyPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "browser_policy"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enterprise-managed Chrome, Chromium and Edge browser policy inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"policies", nullptr};
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
        // The whole body runs under the exception guard (browser_policy_legs.hpp
        // run_guarded): no exception may cross the plugin ABI from any path, the
        // unknown-action refusal included.
        return yuzu::browser_policy::run_guarded(ctx, [action](yuzu::CommandContext& c) -> int {
            if (action != "policies") {
                // `action` is request-supplied and lands in a pipe-delimited stream, so it
                // goes through the shared escaper. Deliberately NOT a `policy|` row.
                c.write_output(std::string{"unknown action: "} +
                               yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            return yuzu::browser_policy::run_windows(c);
#elif defined(__linux__)
            return yuzu::browser_policy::run_linux(c);
#elif defined(__APPLE__)
            return yuzu::browser_policy::run_macos(c);
#else
            return 1; // no leg for this OS (Windows, Linux and macOS only)
#endif
        });
    }
};

YUZU_PLUGIN_EXPORT(BrowserPolicyPlugin)
