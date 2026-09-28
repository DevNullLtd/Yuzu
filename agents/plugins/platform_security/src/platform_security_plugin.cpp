/**
 * platform_security_plugin.cpp -- Secure Boot and code-integrity enforcement
 * posture (read-only). Actions, each emitting <action>|<os>|<key>|<raw>|<state>
 * rows (states in platform_security_parsers.hpp):
 *   secure_boot    -- Linux: efivarfs SecureBoot/SetupMode (rung 1); macOS:
 *                     UNSUPPORTED; Windows: SecureBoot\State registry (rung 1)
 *   code_integrity -- Linux: securityfs lsm + lockdown (rung 1); macOS: spctl
 *                     --status + csrutil status via run_bounded_subprocess
 *                     (rung 2 argv leaves); Windows: CI\Policy, DeviceGuard and
 *                     Lsa\LsaCfgFlags registry (rung 1)
 *
 * WHY (state plainly, do not inflate): there is no documented business driver.
 * No capability-map requirement, enterprise-parity, SOC 2 or roadmap entry
 * names it; this is capability-gap reasoning, the priority is asserted, not
 * evidenced by any tracked demand. Measured boot ships as a separate plugin,
 * measured_boot.
 *
 * Portable except the dispatch #if; all three descriptor legs are declared
 * unconditionally so the capability-matrix generator sees one shape everywhere.
 */

#include <yuzu/plugin.hpp>

#include "platform_security_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {"secure_boot",
     /* linux_leg   = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "efivarfs reads of /sys/firmware/efi/efivars/SecureBoot-* and SetupMode-* "
      "(4-byte attributes + 1 data byte; errno-classified absent/unreadable)", nullptr},
     /* macos_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "no public API; SIP reported under code_integrity"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State registry (UEFISecureBootEnabled)", nullptr}},
    {"code_integrity",
     {YUZU_SUPPORT_SUPPORTED, 1,
      "securityfs reads of /sys/kernel/security/lsm and /sys/kernel/security/lockdown "
      "(errno-classified absent/unreadable)", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 2, "spctl --status + csrutil status via run_bounded_subprocess", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1,
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy, Control\\DeviceGuard and "
      "Control\\Lsa\\LsaCfgFlags registry values", nullptr}},
};

} // namespace

class PlatformSecurityPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "platform_security"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Secure Boot and code-integrity enforcement posture (read-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"secure_boot", "code_integrity", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override { return kActionDescriptors; }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        namespace ps = yuzu::platform_security;
        // Frozen seam: nothing may escape the plugin ABI (the SDK trampoline does not catch), so
        // the whole body, the unknown-action row included, sits inside the one try; every leg
        // returns 0 for a data-level outcome, so 1 means exactly this.
        try {
            const bool secure_boot = action == ps::kSecureBootAction;
            if (!secure_boot && action != ps::kCodeIntegrityAction) {
                // `action` is request-supplied and lands in a pipe-delimited stream.
                ctx.write_output("unknown action: " + yuzu::util::safe_output_field(action));
                return 1;
            }
            // Yuzu targets exactly these three OSes, so there is no fourth branch.
#if defined(_WIN32)
            return secure_boot ? ps::collect_secure_boot_win(ctx) : ps::collect_code_integrity_win(ctx);
#elif defined(__linux__)
            return secure_boot ? ps::collect_secure_boot_linux(ctx) : ps::collect_code_integrity_linux(ctx);
#elif defined(__APPLE__)
            return secure_boot ? ps::collect_secure_boot_macos(ctx) : ps::collect_code_integrity_macos(ctx);
#endif
            return 1;
        } catch (...) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            ctx.write_output("constrained|internal_error");
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(PlatformSecurityPlugin)
