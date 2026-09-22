/**
 * update_source_trust_plugin.cpp -- OS/package update-source trust posture for
 * Yuzu.
 *
 * Action:
 *   "sources" -- facts about how the device's package/update sources are
 *                configured to trust signing authorities:
 *                  Linux   apt sources (one-line and deb822) with signed-by /
 *                          trusted / allow-insecure, and apt keyrings. The
 *                          rpm/dnf .repo family is PLANNED (not read yet): a
 *                          host whose /etc/yum.repos.d has entries reports
 *                          constrained `linux:rpm_repo:planned`;
 *                  macOS   PLANNED (not read yet; the Software Update policy
 *                          in com.apple.SoftwareUpdate.plist);
 *                  Windows PLANNED (not read yet; the WSUS policy keys).
 *
 * WHY (verified 2026-09-19): there is no documented
 * customer driver for this plugin -- capability-map section 8.8 tests
 * reachability to update sources, never their trust, and every "supply chain"
 * mention in the SOC 2 doc is about Yuzu's own build pipeline. This is a pure
 * capability-gap addition: an unsigned or rogue third-party repository is a
 * common compromise vector, and nothing in the tree reads these facts today.
 *
 * FACTS ONLY. This plugin is read-only and never enforces: it reports what is
 * configured (an unsigned source is a row, not a verdict) and leaves enforcement
 * posture to the sibling posture plugins. No action here mutates host state,
 * no subprocess is spawned, and nothing is fetched over the network.
 *
 * This TU is portable except for its single dispatch #if, which selects the one
 * host leg to call (the same shape peripherals_plugin.cpp uses), so a single-OS
 * build never needs the other legs' symbols to link. All three descriptor legs
 * are declared unconditionally so the capability-matrix generator sees a
 * complete, stable shape regardless of which OS built the plugin.
 */

#include <yuzu/plugin.hpp>

#include "update_source_trust_legs.hpp"

#include <string_view>

namespace {

// The three per-OS legs of the single `sources` action are FIXED and never
// wrapped in a preprocessor conditional.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "sources",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/etc/apt/sources.list{,.d/*} (one-line + deb822), /etc/apt/trusted.gpg{,.d/*} and "
         "/etc/apt/keyrings/* config file reads",
         "rpm/dnf .repo files under /etc/yum.repos.d are not read yet; a host whose "
         "/etc/yum.repos.d has entries reports constrained linux:rpm_repo:planned"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "CFPropertyListCreateWithData over /Library/Preferences and /Library/Managed "
         "Preferences com.apple.SoftwareUpdate.plist",
         "not read yet: one unsupported status row, macos:planned"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate{,\\AU} registry values",
         "not read yet: one unsupported status row, windows:planned"},
    },
};

#if defined(_WIN32)
constexpr const char* kLegExceptionToken = "windows:leg:exception";
#elif defined(__linux__)
constexpr const char* kLegExceptionToken = "linux:leg:exception";
#else
constexpr const char* kLegExceptionToken = "macos:leg:exception";
#endif

} // namespace

class UpdateSourceTrustPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "update_source_trust"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Package and update-source trust posture (facts only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"sources", nullptr};
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
        // Every failure-token literal this plugin dir emits matches
        // ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$ -- Yuzu targets exactly
        // these three OSes, so there is deliberately no fourth branch. The body
        // (dispatch, the leg, the ABI containment) is execute_sources in
        // update_source_trust_legs.hpp, unit-tested through a real CommandContext.
#if defined(_WIN32)
        return yuzu::update_source_trust::execute_sources(
            ctx, action, &yuzu::update_source_trust::run_windows, kLegExceptionToken);
#elif defined(__linux__)
        return yuzu::update_source_trust::execute_sources(
            ctx, action, &yuzu::update_source_trust::run_linux, kLegExceptionToken);
#elif defined(__APPLE__)
        return yuzu::update_source_trust::execute_sources(
            ctx, action, &yuzu::update_source_trust::run_macos, kLegExceptionToken);
#endif
        return 1; // unreachable on a supported build
    }
};

YUZU_PLUGIN_EXPORT(UpdateSourceTrustPlugin)
