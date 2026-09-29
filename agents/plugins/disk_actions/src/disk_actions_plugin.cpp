/**
 * disk_actions_plugin.cpp — drive health and physical-to-logical volume
 * mapping for Yuzu.
 *
 * Actions:
 *   "smart"   — Per-physical-drive health: model, transport, media type and,
 *               where the OS exposes it, wear indicators.
 *   "volumes" — The mapping between physical drives and the logical volumes
 *               they back.
 *
 * SCOPE, decided deliberately (Alex ruling, Wave 6 planning). `volumes` is NOT
 * a third volume inventory. `hardware.disks` already enumerates physical
 * devices and `filesystem_posture.mounts` already enumerates mounts; this
 * action carries only the JOIN between them, which neither provides and which
 * is what lets a failing-drive alert name the affected drive letters.
 *
 * This TU is fully portable — no target-OS #if of any kind. All six descriptor
 * legs are declared unconditionally so the capability-matrix generator (#2204)
 * sees a complete, stable shape in a single-OS build, and execute() dispatches
 * to the yuzu::disk_actions::emit_* entry points the per-OS TUs define.
 *
 * Read-only: no action here mutates host state. The mutating half of the
 * original PR6.1-a row (cleanup_temp / cleanup_recycle / trim) is a separate
 * change, split at the read-only/destructive boundary so the file-deleting
 * surface gets its own security review — which is what PR6.0's confined_fs
 * primitive existed to make possible.
 */

#include <yuzu/plugin.hpp>

#include "disk_actions_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The six descriptor legs are FIXED and never wrapped in a preprocessor
// conditional -- a single-OS build still declares the full per-OS shape.
//
// EVERY mechanism string below was BOUND BY A SPIKE against real hardware on
// 2026-09-03, not taken from documentation. The full record, including the
// load-bearing negatives, is at ~/.claude/roadmaps/wave6-smart-spike.md. Two
// of those negatives are worth repeating here, because both are the kind of
// mistake that ships a leg which never works:
//
//   * IOCTL_STORAGE_PREDICT_FAILURE -- the obvious "documented health bit" --
//     FAILS with ERROR_INVALID_FUNCTION on NVMe. It is the ATA-era API. This
//     leg does not use it.
//   * On Windows the device must be opened with ZERO access rights, not
//     GENERIC_READ: GENERIC_READ is ACCESS_DENIED for an unprivileged service
//     account, while a 0-access handle serves both IOCTLs. That single detail
//     is why this leg survives the #1442 move to an unprivileged account.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "smart",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "not implemented in this change: no mechanism could be bound, because every Linux host "
         "available for the spike exposed virtualised disks only (WSL2 reports four 'Virtual "
         "Disk' SCSI nodes and no /dev/nvme* character devices), and shipping an "
         "NVME_IOCTL_ADMIN_CMD path written from documentation but never exercised is exactly how "
         "a dead leg reaches production. Binding it needs a Linux host with real storage, or a VM with disk passthrough; neither was reachable when this shipped"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "IOKit IOBlockStorageDevice device characteristics",
         "reports device identity (model, medium type) and whether the device advertises NVMe "
         "SMART, but NOT the health attributes themselves: wear, available spare and the critical-"
         "warning flag are reachable only through Apple's private IONVMeSMARTUserClient selector "
         "interface, which is undocumented and version-fragile, so health reports 'unknown' on "
         "this platform rather than a guess"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceProperty + "
         "StorageDeviceSeekPenaltyProperty + StorageDeviceProtocolSpecificProperty, "
         "NVMe log page 0x02)",
         "the device handle is opened with zero access rights, which an unprivileged service "
         "account may do; wear and spare figures come from the NVMe SMART/Health log and are "
         "therefore reported only for NVMe devices, with SATA and USB drives reporting identity "
         "and media type but 'unknown' health"},
    },
    {
        /* .action      = */ "volumes",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "not implemented in this change: the physical-to-logical join is only meaningful "
         "alongside a bound smart leg, and the Linux smart leg is deferred with it"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "IOKit IOMedia provider walk + getmntinfo_r_np(3) MNT_NOWAIT",
         "one row per IOMedia object, keyed on that object's BSD name, carrying the physical whole "
         "disk that backs it and any mount points it serves; the physical disk is resolved by "
         "walking the IOKit provider chain, so a volume inside a synthesized APFS container "
         "correctly reports the underlying drive rather than the container; a media object that maps "
         "nothing -- a whole disk serving no mount point -- is omitted, because this action "
         "carries only the physical-to-logical join and such a row has no join to carry"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "FindFirstVolumeW + IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS + "
         "GetVolumePathNamesForVolumeNameW",
         "maps volumes to the physical drives backing them; a volume spanning several drives "
         "(a spanned or striped dynamic volume) reports every drive it touches, and a volume with "
         "no assigned drive letter or mount point reports '-' for mount points rather than being "
         "omitted"},
    },
};

} // namespace

class DiskActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "disk_actions"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports physical drive health and the mapping between drives and the logical "
               "volumes they back";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"smart", "volumes", nullptr};
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
        if (action == "smart")
            return yuzu::disk_actions::emit_smart(ctx);
        if (action == "volumes")
            return yuzu::disk_actions::emit_volumes(ctx);

        // `action` is request-supplied and lands in a pipe-delimited stream, so
        // it goes through the shared escaper like any other untrusted field.
        // This is deliberately NOT a row (no leading kind token), which is why
        // it does not use the legs.hpp wrappers.
        ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(DiskActionsPlugin)
