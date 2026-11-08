/**
 * virtualization_plugin.cpp -- virtualization facts for Yuzu.
 *
 * Action:
 *   "host" -- is this device a VM, which hypervisor, and is the agent itself in a container:
 *               Linux   CPUID (x86), DMI, /sys/hypervisor/type, /.dockerenv,
 *                       /run/.containerenv, /run/systemd/container, /proc/self/cgroup;
 *               macOS   sysctl kern.hv_vmm_present and hw.model;
 *               Windows CPUID (x86), the SMBIOS System Information table (RSMB).
 *   "wsl"  -- Windows only: the WSL distributions of every local profile (account, name,
 *               version 1|2, state, default, flavor), read from each profile's
 *               Software/Microsoft/Windows/CurrentVersion/Lxss key through the shared
 *               with_user_hive ladder (loaded hive first, else the guarded offline mount).
 *               Linux and macOS answer one `unsupported` status row.
 *
 * FACTS ONLY and read-only, no subprocess. A Windows machine running Hyper-V, VBS or WSL2 sets
 * the CPUID hypervisor bit but is the HOST, not a guest: the Hyper-V root-partition bit
 * separates them (kind host_with_hypervisor). A host-decision source (SMBIOS, CPUID, OS hint) that
 * cannot be read never reads as bare metal: the kind is `unknown` with the reason.
 *
 * This TU is portable except for two #if chains: the seam's exception-token selection and the
 * per-OS dispatch in execute() (the mgmt_posture shape). All three descriptor legs are declared
 * unconditionally so the capability-matrix generator sees a stable shape on every host.
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
         "product_name}, /sys/hypervisor/type, /.dockerenv, /run/.containerenv, "
         "/run/systemd/container and /proc/self/cgroup (bounded reads, no subprocess)",
         "ARM has no CPUID: SMBIOS and OS hints alone decide, and a host with neither reads "
         "unknown, never bare_metal; a KVM host reads bare_metal (its own CPUID is not "
         "virtualised) but a Xen dom0 reads guest/xen; a cgroup-v2 namespace-obscured root reads "
         "container unknown; a container without a marker file or systemd record can read "
         "container no when its readable, non-root cgroup path has no recognised runtime "
         "signature"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctlbyname kern.hv_vmm_present and hw.model",
         "no CPUID on arm64: the sysctl is the readable negative; container is always no"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "CPUID leaves 1 and 0x40000000-0x40000003 (__cpuid, x86) and the SMBIOS System "
         "Information table via GetSystemFirmwareTable('RSMB')",
         "container not read: always unknown, windows:virtualization:container:not_read; an "
         "ARM64 build has no CPUID and reads unknown (windows:virtualization:cpuid:unavailable) "
         "unless SMBIOS names a VM vendor, and does not detect a Hyper-V or VBS host; no ARM64 "
         "build ships, and the x64 agent on a Windows-on-ARM device reads whatever CPUID the "
         "emulation presents (not measured)"},
    },
    {
        /* .action      = */ "wsl",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: WSL distributions are a Windows feature"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: WSL distributions are a Windows feature"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "Reg*W reads of HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\MSI and each "
         "local profile's Software\\Microsoft\\Windows\\CurrentVersion\\Lxss key through the shared "
         "with_user_hive ladder (loaded HKU hive first, else a guarded offline NTUSER.DAT mount "
         "under SeBackup/SeRestore and the process-wide offline-hive lock); no subprocess",
         "a profile whose hive was reached by neither arm is counted and reported on its own "
         "profile row, never read as having no distributions; wsl2 counts version-2 "
         "distributions and is not a VM count (the utility VM's running state is not read); "
         "base, VHD and shortcut paths, SIDs, uids and hive mount names are never emitted; "
         "package version - means unavailable; the offline mount calls have no deadline (the "
         "walk is bounded in work, not in time)"},
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
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Virtualization facts: VM or not, which hypervisor, container membership, WSL distributions";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"host", "wsl", nullptr};
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
        // (:[a-z0-9_]+)*$ (or the seam's `<os>:leg:exception`); the body is execute_action.
#if defined(_WIN32)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_windows,
                                                          &yuzu::virtualization::run_windows_wsl};
#elif defined(__linux__)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_linux,
                                                          &yuzu::virtualization::run_linux_wsl};
#elif defined(__APPLE__)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_macos,
                                                          &yuzu::virtualization::run_macos_wsl};
#endif
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
        return yuzu::virtualization::execute_action(ctx, action, kLegs, kLegExceptionToken);
#endif
        return 1; // unreachable on a supported build
    }
};

YUZU_PLUGIN_EXPORT(VirtualizationPlugin)
