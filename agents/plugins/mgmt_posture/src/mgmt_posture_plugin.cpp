/**
 * mgmt_posture_plugin.cpp -- management-plane posture for Yuzu.
 *
 * Action:
 *   "posture" -- which management plane controls the device:
 *                  Linux   SSSD active domains (sssd.conf + conf.d), IPA default.conf
 *                          and /etc/krb5.keytab presence (bounded file reads);
 *                  macOS   MDM enrolment via `profiles status -type enrollment`;
 *                  Windows PLANNED (not read yet; follow-up after a real-host probe).
 *
 * FACTS ONLY and read-only. The AD domain / OU / joined rows belong to
 * device_identity and are never re-emitted here. A refused read (a 0600 sssd.conf run
 * unprivileged) is reported as permission_denied, never as "not joined".
 *
 * This TU is portable except for its single dispatch #if (the update_source_trust
 * shape). All three descriptor legs are declared unconditionally so the
 * capability-matrix generator sees a stable shape on every host.
 */

#include <yuzu/plugin.hpp>

#include "mgmt_posture_legs.hpp"

#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "posture",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/etc/sssd/sssd.conf + /etc/sssd/conf.d/*.conf active domains, /etc/ipa/default.conf "
         "and /etc/krb5.keytab presence (bounded file reads)",
         "configuration as written, not the live join state; sssd.conf is root 0600, so an "
         "unprivileged agent reports permission_denied (plane unknown), never not-joined; "
         "a privileged agent reads it in full"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:/usr/bin/profiles status -type enrollment",
         "MDM enrolment only; AD binding is device_identity.domain; Jamf not read"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "NetGetJoinInformation + HKLM\\SOFTWARE\\Microsoft\\Enrollments and "
         "CloudDomainJoin\\JoinInfo registry reads",
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

class MgmtPosturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "mgmt_posture"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Management-plane posture: which plane controls the device (facts only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"posture", nullptr};
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
        // Every failure-token literal matches ^(windows|macos|linux|subprocess_runner):[a-z0-9_]+
        // (:[a-z0-9_]+)*$ (subprocess_runner:* come from the shared runner classifier); the body
        // is execute_posture.
#if defined(_WIN32)
        return yuzu::mgmt_posture::execute_posture(ctx, action, &yuzu::mgmt_posture::run_windows,
                                                   kLegExceptionToken);
#elif defined(__linux__)
        return yuzu::mgmt_posture::execute_posture(ctx, action, &yuzu::mgmt_posture::run_linux,
                                                   kLegExceptionToken);
#elif defined(__APPLE__)
        return yuzu::mgmt_posture::execute_posture(ctx, action, &yuzu::mgmt_posture::run_macos,
                                                   kLegExceptionToken);
#endif
        return 1; // unreachable on a supported build
    }
};

YUZU_PLUGIN_EXPORT(MgmtPosturePlugin)
