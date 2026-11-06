/**
 * virtualization_plugin.cpp -- virtualization facts for Yuzu.
 *
 * Action:
 *   "host" -- is this device a VM, which hypervisor, and is the agent itself in a container:
 *               Linux   CPUID (x86), DMI, /sys/hypervisor/type, /.dockerenv,
 *                       /run/.containerenv, /proc/self/cgroup;
 *               macOS   sysctl kern.hv_vmm_present and hw.model;
 *               Windows CPUID (x86), the SMBIOS System Information table (RSMB).
 *
 * FACTS ONLY and read-only, no subprocess. A Windows machine running Hyper-V, VBS or WSL2 sets
 * the CPUID hypervisor bit but is the HOST, not a guest: the Hyper-V root-partition bit
 * separates them (kind host_with_hypervisor). An unreadable source never reads as bare metal:
 * the kind is `unknown` with the reason.
 *
 * This TU is portable except for its single dispatch #if (the mgmt_posture shape). All three
 * descriptor legs are declared unconditionally so the capability-matrix generator sees a stable
 * shape on every host.
 */

#include <yuzu/plugin.hpp>

#include "virtualization_legs.hpp"

#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "host",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CPUID leaves 1 and 0x40000000-0x40000003 (x86), /sys/class/dmi/id/{sys_vendor,"
         "product_name}, /sys/hypervisor/type, /.dockerenv, /run/.containerenv "
         "and /proc/self/cgroup (bounded reads, no subprocess)",
         "ARM has no CPUID: SMBIOS and OS hints alone decide, and a host with neither reads "
         "unknown, never bare_metal; a KVM host reads bare_metal (its own CPUID is not "
         "virtualised) but a Xen dom0 reads guest/xen; a cgroup-v2 namespace-obscured root reads "
         "container unknown"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctlbyname kern.hv_vmm_present and hw.model",
         "no CPUID on arm64: the sysctl is the readable negative; container is always no"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "CPUID leaves 1 and 0x40000000-0x40000003 (__cpuid, x86) and the SMBIOS System "
         "Information table via GetSystemFirmwareTable('RSMB')",
         "container not read: always unknown, windows:virtualization:container:not_read; ARM64 "
         "has no CPUID and reads as Linux ARM"},
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

class VirtualizationPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "virtualization"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Virtualization facts: VM or not, which hypervisor, container membership";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"host", nullptr};
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
        // Every failure-token literal matches ^(windows|macos|linux):virtualization:[a-z0-9_]+
        // (:[a-z0-9_]+)*$ (or the seam's `<os>:leg:exception`); the body is execute_host.
#if defined(_WIN32)
        return yuzu::virtualization::execute_host(ctx, action, &yuzu::virtualization::run_windows,
                                                  kLegExceptionToken);
#elif defined(__linux__)
        return yuzu::virtualization::execute_host(ctx, action, &yuzu::virtualization::run_linux,
                                                  kLegExceptionToken);
#elif defined(__APPLE__)
        return yuzu::virtualization::execute_host(ctx, action, &yuzu::virtualization::run_macos,
                                                  kLegExceptionToken);
#endif
        return 1; // unreachable on a supported build
    }
};

YUZU_PLUGIN_EXPORT(VirtualizationPlugin)
