/**
 * remote_access_audit_plugin.cpp -- the SSH inbound-access audit of this host.
 *
 * "list" -- who can log in over SSH, as CONFIGURED: sshd_config (Include followed), per-account
 * authorized_keys fingerprints and the sshd service state (Linux `systemctl is-enabled`, macOS
 * `launchctl print-disabled system`). Windows is PLANNED. READ-ONLY, facts only: fingerprints
 * and option NAMES, never a comment, option value or key-file path.
 *
 * Portable except the single dispatch #if selecting the leg (`kLeg`, `kLegExceptionToken`);
 * all three descriptor legs are declared unconditionally for the capability-matrix generator.
 */

#include <yuzu/plugin.hpp>

#include "remote_access_audit_legs.hpp"

#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2,
         "bounded reads of /etc/ssh/sshd_config (Include followed, config symlinks followed as sshd "
         "does) and each account's authorized_keys (no-follow; pure parsers, SHA-256 "
         "fingerprints); one bounded systemctl is-enabled argv per sshd unit",
         "constrained: the agent runs unprivileged, so other users' homes (usually 0700) are "
         "refused, not empty, and the listing is constrained; configured access as written, not "
         "sshd's effective policy (Match is not evaluated); CA trust, key and principals "
         "commands and hostbased auth are not read; key comments, option values and key-file "
         "paths are never emitted; only homes under /home and /root are walked; a symlinked key "
         "file or .ssh is refused; network mounts are skipped"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "bounded reads of /etc/ssh/sshd_config (Include followed, config symlinks followed as sshd "
         "does) and each account's authorized_keys (no-follow; pure parsers, SHA-256 "
         "fingerprints); one bounded launchctl print-disabled system argv",
         "configured access as written, not sshd's effective policy; the launchd override is "
         "not 'running'; CA trust, key and principals commands and hostbased auth are not read; "
         "key comments, option values and key-file paths are never emitted; only homes under "
         "/Users owned by uid 500 or above, and /var/root, are walked; a symlinked key file or "
         ".ssh is refused; network mounts are skipped"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "per-profile .ssh\\authorized_keys, %ProgramData%\\ssh\\administrators_authorized_keys "
         "and sshd_config via win_profiles",
         "not read yet: one unsupported status row, windows:planned"},
    },
};

// This build's leg and its exception token, defined together. The Windows leg is the PLANNED
// placeholder.
#if defined(_WIN32)
constexpr yuzu::remote_access_audit::LegFn kLeg = &yuzu::remote_access_audit::run_windows;
constexpr const char* kLegExceptionToken = "windows:leg:exception";
#elif defined(__linux__)
constexpr yuzu::remote_access_audit::LegFn kLeg = &yuzu::remote_access_audit::run_linux;
constexpr const char* kLegExceptionToken = "linux:leg:exception";
#elif defined(__APPLE__)
constexpr yuzu::remote_access_audit::LegFn kLeg = &yuzu::remote_access_audit::run_macos;
constexpr const char* kLegExceptionToken = "macos:leg:exception";
#else
#error "remote_access_audit: unsupported platform"
#endif

} // namespace

class RemoteAccessAuditPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "remote_access_audit"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "SSH inbound-access audit: sshd_config as written, per-account authorized_keys "
               "fingerprints, sshd service state; never key comments, option values or paths";
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
        // This plugin's own failure tokens match ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$;
        // a runner failure's own `subprocess_runner:*` provenance token passes through unchanged.
        // The body is execute_list.
        return yuzu::remote_access_audit::execute_list(ctx, action, kLeg, kLegExceptionToken);
    }
};

YUZU_PLUGIN_EXPORT(RemoteAccessAuditPlugin)
