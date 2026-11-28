/**
 * shares_plugin.cpp -- shares this host serves over SMB/NFS, for Yuzu.
 *
 * Action:
 *   "list" -- the shares this host is CONFIGURED to serve, names and paths only:
 *               Linux   /etc/exports, the /etc/exports.d snippets (*.exports) and
 *                       /etc/samba/smb.conf (bounded no-follow file reads);
 *               macOS   the share points `sharing -l -f json` records (bounded argv leaf)
 *                       plus /etc/exports in Apple's BSD grammar (bounded no-follow read);
 *               Windows the LIVE shares of the Server service through NetShareEnum
 *                       (level 2; level 1 names without paths when level 2 is refused).
 *
 * READ-ONLY and FACTS ONLY. Linux and macOS report configured shares as written, not live
 * nfsd/smbd state; Windows reports what the Server service publishes now. ACLs, `valid users`
 * and NFS client host lists are never emitted (NFS clients are a count plus an `anonymous`
 * flag). A refused or failed read, or a macOS `sharing` that cannot run or answers
 * unrecognisably, is reported as permission_denied/constrained with a token, and a stopped
 * Windows Server service as unsupported, never as an empty result.
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
        {YUZU_SUPPORT_SUPPORTED, 2,
         "/usr/sbin/sharing -l -f json through the bounded runner (5 s deadline, no shell) plus a "
         "byte-capped no-follow read of /etc/exports (BSD exports(5) grammar as mountd parses it)",
         "share points as recorded, not live smbd state (a record with SMB sharing off is flagged "
         "unavailable, SMB encryption required is flagged sealed; the tool never prints AFP or "
         "FTP state, so a share point enabled only for those appears as an SMB row); "
         "/etc/exports as written (mountd grammar emulated best-effort, host-dependent checks not "
         "modelled, README caveat 5), not live nfsd state, hosts counted never listed, an IPv6 "
         "network with no or a zero mask is anonymous as the kernel treats it, an IPv4 network "
         "never is (classful mask); a tool that cannot start, times out, exits nonzero (other "
         "than printing its no-records text) or prints anything but a JSON object or its "
         "no-records text fails the sharing source with a named token"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "NetShareEnum level 2 (netapi32); level 1 (names, no paths) when level 2 is refused",
         "live Server-service state, not the LanmanServer registry: a stopped Server service is "
         "unavailable (windows:shares:netshareenum:server_not_started, or "
         "windows:shares:netshareenum:server_unavailable when its RPC endpoint does not answer); "
         "STYPE_SPECIAL shares (ADMIN$, C$, IPC$) are flagged special, never hidden, and any "
         "other share whose name ends in $ is flagged hidden; access and anonymous are -, ACLs "
         "and level 502 are never read"},
    },
};

// This build's leg and its exception token, defined together.
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
