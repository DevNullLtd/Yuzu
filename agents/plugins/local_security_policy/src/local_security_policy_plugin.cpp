/**
 * local_security_policy_plugin.cpp -- password / lockout / audit policy posture (read-only).
 * Portable TU; the only target-OS #if is the dispatch to a leg (local_security_policy_{linux,
 * macos}.cpp behind local_security_policy_legs.hpp).
 * Row shapes and failure semantics: local_security_policy_parsers.hpp. File reads are
 * unprivileged except Linux /etc/audit/audit.rules (0640) and a present macOS
 * /etc/security/audit_control (root-only): a refused read is an `unreadable` row with a
 * `<source>:permission_denied` token -- PERMISSION_DENIED when nothing else was readable,
 * CONSTRAINED otherwise -- never an empty result.
 * CONTAINERS: the Linux leg reads the /etc it can see, which in the shipped
 * deploy/docker/Dockerfile.agent image (unprivileged `yuzu-agent`, no host /etc mounted)
 * is the IMAGE's -- its rows describe the container, not the host.
 *
 * The Windows leg (secedit /export) and the `sudoers` action are PLANNED, follow as their
 * own PR -- see local_security_policy_legs.hpp's banner for the full "when it lands"
 * checklist. Until then: Sudoers is treated the same as an unregistered action (its own row
 * is 7 fields, not this plugin's usual 4, so there is no honest 4-field placeholder to emit
 * for it); Windows reports one 2-field planned-state row, mirroring this function's existing
 * "no leg for this OS" idiom below rather than claiming an empty success.
 */
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include "local_security_policy_legs.hpp"

#include <string>
#include <string_view>

namespace {

// Windows legs: rung 2 (secedit /export is an argv leaf, docs/agent-privilege-model.md "Audit and review");
// the wording is finalised from the Windows leg's rig-probe banner. Every leg names each
// file it reads and, on Windows, the scratch file it stages and the sweep that removes it.
//
// Windows is PLANNED (YUZU_SUPPORT_PLANNED) for all three actions in this PR -- the real
// mechanism text below documents the design, restored to a real support level once
// local_security_policy_win.cpp lands (see local_security_policy_legs.hpp's checklist).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "password_policy",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/etc/login.defs + /etc/security/pwquality.conf + /etc/pam.d/{common-password,"
         "system-auth,password-auth} (bounded file reads)",
         "reports what the config files state, not the live PAM decision; pwquality.conf.d fragments "
         "and PAM include/substack targets are not read; a missing file is reported as absent, an "
         "unreadable one as unreadable (permission_denied/constrained)"
         "; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not "
         "the host's"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "pwpolicy -getaccountpolicies (CFPropertyList)",
         "global account policies only; rung 2 because no public OpenDirectory global-policy "
         "API exists; policy expressions are verbatim; a policyAttribute* parameter is its own key and any "
         "other is unmodelled_parameter <name>=<value>; "
         "a plist item not in the documented shape is an unreadable row and constrained. "
         "Measured on an UNMANAGED Mac: whether an MDM configuration-profile passcode payload "
         "surfaces here is unverified"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 2,
         "secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY "
         "into an agent.data_dir scratch file",
         "follows as its own PR"},
    },
    {
        /* .action      = */ "lockout_policy",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/etc/login.defs + /etc/security/faillock.conf + /etc/pam.d/{common-auth,common-account,"
         "system-auth,password-auth} (bounded file reads)",
         "reports configuration, not live lockout counters; faillock.conf drop-ins and PAM "
         "include/substack targets are not read"
         "; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not "
         "the host's"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "pwpolicy -getaccountpolicies (CFPropertyList)",
         "global account policies only; no authentication policy reports policies|none (the default); "
         "a plist item not in the documented shape is an unreadable row and constrained. "
         "Measured on an UNMANAGED Mac, so on a managed device policies|none must not be read as "
         "'no lockout enforced' -- profile-delivered policy is unverified here"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 2,
         "secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY "
         "into an agent.data_dir scratch file",
         "follows as its own PR"},
    },
    {
        /* .action      = */ "audit_policy",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/etc/audit/audit.rules (bounded file read)",
         "rule counts and -e state of the rule file only, not the live kernel rules (auditctl -l) "
         "and not /etc/audit/rules.d; the file is 0640 root, so an unprivileged agent reports "
         "permission_denied"
         "; in a container (deploy/docker/Dockerfile.agent) these are the image's files, not "
         "the host's"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/etc/security/audit_control (bounded file read)",
         "absent by default on current macOS (only audit_control.example ships), reported as absent; "
         "a present file is root-readable only"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 2,
         "secedit.exe (system directory via GetSystemDirectoryW) /export /areas SECURITYPOLICY "
         "into an agent.data_dir scratch file",
         "follows as its own PR"},
    },
};

} // namespace

class LocalSecurityPolicyPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "local_security_policy"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports local password, lockout and audit policy posture";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"password_policy", "lockout_policy", "audit_policy", nullptr};
        return acts;
    }
    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        // Copied at once: get_config's view is not guaranteed to outlive the call. Unused
        // in this PR (the Windows leg that would consume it as its scratch parent is
        // PLANNED), kept so the field/init shape needs no change when that leg lands.
        data_dir_ = std::string{ctx.get_config("agent.data_dir")};
        return {};
    }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        using yuzu::local_security_policy::LocalPolicyAction;
        // One containment for the whole body (frozen-seam rule): nothing crosses the plugin ABI,
        // including the unknown-action row and the early returns below.
        try {
            const auto which = yuzu::local_security_policy::parse_local_policy_action(action);
            // Sudoers is PLANNED, follows as its own PR (local_security_policy_legs.hpp's
            // checklist) -- treated the same as an unregistered action until then, so a caller
            // sees "unknown action", never a silent no-op or a row in the wrong shape (sudoers'
            // real row is 7 fields, not this plugin's usual 4).
            if (which == LocalPolicyAction::Unknown || which == LocalPolicyAction::Sudoers) {
                ctx.write_output(std::string{"unknown action: "} +
                                 yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            // Windows leg is PLANNED, follows as its own PR (secedit /export). Same "no leg
            // for this OS" idiom as the #else branch below, never an empty success.
            ctx.write_output("constrained|windows:planned");
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "windows:planned");
            return 1;
#elif defined(__APPLE__)
            return yuzu::local_security_policy::collect_macos_policy(ctx, action);
#elif defined(__linux__)
            return yuzu::local_security_policy::collect_linux_policy(ctx, action);
#else
            // No leg for this OS (not a supported platform): say so, never a Linux read.
            ctx.write_output("constrained|unsupported_os");
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "unsupported_os");
            return 1;
#endif
        } catch (...) {
            ctx.write_output("constrained|internal_error");
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            return 1;
        }
    }

private:
    std::string data_dir_; // unused in this PR; see init()'s comment
};

YUZU_PLUGIN_EXPORT(LocalSecurityPolicyPlugin)
