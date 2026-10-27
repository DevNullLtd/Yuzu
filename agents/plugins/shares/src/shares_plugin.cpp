/**
 * shares_plugin.cpp -- shares this host serves over SMB/NFS, for Yuzu.
 *
 * Action:
 *   "list" -- the shares this host is CONFIGURED to serve, names and paths only:
 *               Linux   /etc/exports, the /etc/exports.d snippets (*.exports) and
 *                       /etc/samba/smb.conf (bounded no-follow file reads);
 *               macOS   PLANNED (share points plus /etc/exports; not read yet);
 *               Windows the LIVE shares of the Server service through NetShareEnum
 *                       (level 2; level 1 names without paths when level 2 is refused).
 *
 * READ-ONLY and FACTS ONLY. Linux reports configured shares as written, not live nfsd/smbd
 * state; Windows reports what the Server service publishes now. ACLs, `valid users` and NFS
 * client host lists are never emitted (NFS clients are a count plus an `anonymous` flag). A
 * refused or failed read is reported as permission_denied/constrained with a token, and a
 * stopped Windows Server service as unsupported, never as an empty result.
 *
 * This TU is portable except for its single dispatch #if, which selects the platform's leg
 * function and exception token (`kLeg`, `kLegExceptionToken`) and ends in an #error. All
 * three descriptor legs are declared unconditionally so the capability-matrix generator
 * sees a stable shape on every host.
 */

#include <yuzu/plugin.hpp>

#include "shares_legs.hpp"

#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded no-follow reads of /etc/exports, /etc/exports.d/*.exports and "
         "/etc/samba/smb.conf (pure parsers); one lstat of the usershares directory",
         "configured shares as written, not live nfsd/smbd state; Samba registry backend, "
         "include= files and usershares are not read (constrained token); a symlinked config "
         "file or exports.d is refused"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 2, "share-point listing plus /etc/exports (BSD syntax)",
         "not read yet: one unsupported status row, macos:planned"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "NetShareEnum level 2 (netapi32); level 1 (names, no paths) when level 2 is refused",
         "live Server-service state, not the LanmanServer registry: a stopped Server service is "
         "unavailable (windows:shares:netshareenum:server_not_started); STYPE_SPECIAL shares "
         "(ADMIN$, C$, IPC$) are flagged special, never hidden; access and anonymous are -, ACLs "
         "and level 502 are never read"},
    },
};

// This build's leg and its exception token, defined together. The macOS leg is the PLANNED
// placeholder.
#if defined(_WIN32)
constexpr yuzu::shares::LegFn kLeg = &yuzu::shares::run_windows;
constexpr const char* kLegExceptionToken = "windows:leg:exception";
#elif defined(__linux__)
constexpr yuzu::shares::LegFn kLeg = &yuzu::shares::run_linux;
constexpr const char* kLegExceptionToken = "linux:leg:exception";
#elif defined(__APPLE__)
constexpr yuzu::shares::LegFn kLeg = &yuzu::shares::run_macos;
constexpr const char* kLegExceptionToken = "macos:leg:exception";
#else
#error "shares: unsupported platform"
#endif

} // namespace

class SharesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "shares"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Shares this host serves over SMB/NFS: names, paths and a few flags, never ACLs";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", nullptr};
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
        // Every failure-token literal matches ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$;
        // the body is execute_list.
        return yuzu::shares::execute_list(ctx, action, kLeg, kLegExceptionToken);
    }
};

YUZU_PLUGIN_EXPORT(SharesPlugin)
