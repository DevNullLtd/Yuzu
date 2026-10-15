/**
 * system_hardening_plugin.cpp -- exploit-mitigation / kernel-hardening
 * posture for Yuzu (read-only).
 *
 * Action:
 *   "posture" -- one row per allowlisted key:
 *                  posture|<os>|<key>|<raw>|<state>
 *                state is enabled | disabled | partial (Linux, macOS) or
 *                on | off | default (Windows), plus unmodelled | absent |
 *                unreadable on every OS (see system_hardening_parsers.hpp). Every key
 *                reads as a value, `absent` or `unreadable` -- one token never
 *                stands for two causes.
 *
 * Mechanisms (all rung 1, no spawn):
 *   Linux   -- allowlisted /proc/sys reads (open/read, errno-classified)
 *   macOS   -- allowlisted sysctlbyname reads
 *   Windows -- Session Manager\kernel mitigation registry + GetProcessMitigationPolicy
 *              (system_hardening_win.cpp)
 *
 * WHY (state plainly, do not inflate): there is no documented business
 * driver for this plugin. No capability-map requirement, enterprise-parity,
 * SOC 2 or roadmap entry names it as a need (the capability-map
 * plugin-inventory row is added by this change as a listing, not a driver);
 * the nearest idea (docs/roadmap.md Issue 18.2, CIS-shaped compliance
 * reporting) is a reporting layer over rules that would have to exist
 * elsewhere and is itself only Proposed. This is capability-gap reasoning,
 * not evidenced demand.
 *
 * This TU is portable except for its single dispatch #if; all three
 * descriptor legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a stable shape on every host.
 */

#include <yuzu/plugin.hpp>

#include "system_hardening_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "posture",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "allowlisted /proc/sys reads (open/read, errno-classified absent/unreadable; a missing "
         "key is absent only when statfs confirms its nearest existing directory is procfs)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "allowlisted sysctlbyname reads (kern.securelevel/coredump/sugid_coredump/bootargs)",
         nullptr},
        /* .windows_leg = */
        // 4th field (`fallback`) = the rig-verified behaviour recorded in the banner of
        // system_hardening_win.cpp (rig session A, 2026-09-21, Windows 11 Pro 10.0.26200).
        {YUZU_SUPPORT_SUPPORTED, 1,
         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel mitigation "
         "registry + GetProcessMitigationPolicy (agent process)",
         "Rig-verified 2026-09-21: MitigationOptions/MitigationAuditOptions are ABSENT on a default "
         "Windows 11 install (rows read `absent`, not a failure); a present value decodes as 16 "
         "two-bit nibbles (dep, sehop, aslr_bottom_up, aslr_high_entropy and cfg confirmed on "
         "hardware); GetProcessMitigationPolicy succeeds for DEP/ASLR/CFG on x64."},
    },
};

} // namespace

#if defined(_WIN32)
constexpr std::string_view kHostOs = "windows";
#elif defined(__APPLE__)
constexpr std::string_view kHostOs = "macos";
#else
constexpr std::string_view kHostOs = "linux";
#endif

class SystemHardeningPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "system_hardening"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Exploit-mitigation and kernel-hardening posture (read-only)";
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
        // Frozen seam: nothing may escape the plugin ABI (the SDK trampoline does not catch), so
        // the whole body, the unknown-action row included, sits inside the one try; every leg
        // returns 0 for a data-level outcome, so 1 means exactly this. The handler allocates (the
        // row, the status reason), so its own body sits in a nested try: an allocation failure
        // there drops the internal-error row and still returns 1, and nothing escapes.
        try {
            if (action != "posture") {
                // `action` is request-supplied and lands in a pipe-delimited stream.
                ctx.write_output(std::string{"unknown action: "} +
                                 yuzu::util::safe_output_field(action));
                return 1;
            }
            // Yuzu targets exactly these three OSes, so there is no fourth branch.
#if defined(_WIN32)
            return yuzu::system_hardening::collect_posture_win(ctx);
#elif defined(__linux__)
            return yuzu::system_hardening::collect_posture_linux(ctx);
#elif defined(__APPLE__)
            return yuzu::system_hardening::collect_posture_macos(ctx);
#endif
            return 1;
        } catch (...) {
            try {
                ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL, "internal_error");
                ctx.write_output(yuzu::system_hardening::format_internal_error_row(kHostOs));
            } catch (...) {
            }
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(SystemHardeningPlugin)
