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
 *   "runtime_posture" -- Linux only: docker, podman and containerd presence and posture (default
 *               sockets, config files, docker daemon.json through a key allow-list) and, ONLY when
 *               the operator sets agent.container_runtime_endpoint (--container-runtime-endpoint),
 *               the containers an operator-provided read-only unix socket reports, through four
 *               fixed GET requests under a 20 s deadline. Design:
 *               docs/virtualization-runtime-posture-design.md. macOS and Windows answer one
 *               `unsupported` status row.
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
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "Windows-only: WSL distributions are a Windows feature"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "Windows-only: WSL distributions are a Windows feature"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "Reg*W reads of HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\MSI, the HKLM "
         "ProfileList (profile SIDs and folder paths; no privilege) and each local profile's "
         "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss key through the shared "
         "with_user_hive ladder (loaded HKU hive first, else a guarded offline NTUSER.DAT mount "
         "under SeBackup/SeRestore and the process-wide offline-hive lock); no subprocess",
         "a profile whose hive was reached by neither arm is counted and reported on its own "
         "profile row, never read as having no distributions; a registry link planted at the "
         "Lxss key or at a distribution key is detected and reported "
         "(windows:virtualization:wsl:lxss_link), never followed; wsl2 counts version-2 "
         "distributions and is not a VM count (the utility VM's running state is not read); "
         "base, VHD and shortcut paths, SIDs, uids and hive mount names are never emitted; "
         "package version - means unavailable; the offline mount calls have no deadline (the "
         "walk is bounded in work, not in time: at most 512 profiles are mounted per dispatch)"},
    },
    {
        /* .action      = */ "runtime_posture",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "stat of the docker, podman and containerd default sockets, config files and data roots "
         "(no subprocess, no PATH walk), /etc/docker/daemon.json read through a key allow-list "
         "(nlohmann::json), /etc/containers and /etc/containerd presence only, and, only when "
         "agent.container_runtime_endpoint names an operator-provided read-only unix socket, four "
         "fixed GET requests over it (/version, /info, /containers/json?all=1, "
         "/containers/{id}/json) under "
         "a 20 s action deadline",
         "no endpoint set (the default) means no socket is ever opened and no container is listed; "
         "the runtimes' own default sockets are refused as the endpoint (by path and by inode), "
         "and the permission bits plus the operator's proxy are the enforcement, not that check; "
         "not_detected means none of a runtime's standard-path artefacts exists, which a stopped, "
         "rootless or custom-root runtime also reads; containerd is presence only (its control "
         "plane is gRPC, not read); a read failure, a cap, the deadline or an overprivileged "
         "default socket reads constrained with a typed token"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "Linux-only: container-runtime posture is read from Linux paths and a unix socket"},
        /* .windows_leg = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "Linux-only: container-runtime posture is read from Linux paths and a unix socket"},
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
    std::string_view version() const noexcept override { return "1.2.0"; }
    std::string_view description() const noexcept override {
        return "Virtualization facts: VM or not, which hypervisor, container membership, "
               "WSL distributions, container-runtime posture";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"host", "wsl", "runtime_posture", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    // Stashes the operator's agent.container_runtime_endpoint (empty = never open a socket). The
    // plugin never validates it here: parse_endpoint decides, so a rejected value surfaces as a
    // typed row.
    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        yuzu::virtualization::set_container_runtime_endpoint(
            ctx.get_config("agent.container_runtime_endpoint"));
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        // Every failure-token literal matches ^(windows|macos|linux):virtualization:[a-z0-9_]+
        // (:[a-z0-9_]+)*$ (or the seam's `<os>:leg:exception`); the body is execute_action.
#if defined(_WIN32)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_windows,
                                                          &yuzu::virtualization::run_windows_wsl,
                                                          &yuzu::virtualization::run_windows_runtime_posture};
#elif defined(__linux__)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_linux,
                                                          &yuzu::virtualization::run_linux_wsl,
                                                          &yuzu::virtualization::run_linux_runtime_posture};
#elif defined(__APPLE__)
        static constexpr yuzu::virtualization::Legs kLegs{&yuzu::virtualization::run_macos,
                                                          &yuzu::virtualization::run_macos_wsl,
                                                          &yuzu::virtualization::run_macos_runtime_posture};
#endif
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
        return yuzu::virtualization::execute_action(ctx, action, kLegs, kLegExceptionToken);
#endif
        return 1; // unreachable on a supported build
    }
};

YUZU_PLUGIN_EXPORT(VirtualizationPlugin)
