/**
 * filesystem_posture_plugin.cpp — Filesystem posture plugin for Yuzu
 *
 * Actions:
 *   "mounts"    — Lists mounted filesystems with capacity and flags.
 *   "quotas"    — Reports per-mount quota-subsystem state.
 *   "snapshots" — Reports snapshot-capable volumes / the mounted snapshot
 *                 inventory, per OS.
 *
 * This TU is fully portable (no target-OS #if of any kind): every leg is
 * declared unconditionally in kActionDescriptors, and execute() dispatches
 * to the three yuzu::filesystem_posture::emit_* entry points the per-OS leg
 * TUs (filesystem_posture_linux.cpp / _macos.cpp / _win.cpp) define. Output
 * is pipe-delimited via the shared row formatters in
 * filesystem_posture_legs.hpp.
 */

#include <yuzu/plugin.hpp>

#include "filesystem_posture_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The nine descriptor legs are FIXED and never wrapped in a preprocessor
// conditional -- a single-OS build still declares the full per-OS shape so
// the capability-matrix generator (#2204) sees a complete, stable structure
// regardless of which OS built this plugin.
//
// ALEX RULING (plan gate, H6): the Windows legs ship CONSTRAINED, not
// PLANNED -- the code is implemented and MSVC-compilable, so PLANNED would
// misdescribe it.
//
// H6's "compile-verified only" disclaimer has been REMOVED from all three
// Windows legs, because it is no longer true: the plugin was built with real
// MSVC and its suite run on a live Windows host (the-rig, Windows SDK
// 10.0.26100.0) on 2026-09-03, and the snapshots leg was exercised against
// three live VSS shadow copies. Each Windows leg's fallback prose now states
// that leg's REAL residual limitation instead of a blanket provenance
// caveat. The quotas leg keeps an explicit unexercised-path caveat, since no
// host with quotas configured was available to assert against.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "mounts",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/proc/self/mountinfo + statvfs(3)",
         "capacity columns are omitted for network filesystems (nfs/cifs/smb/ceph/afs and "
         "network FUSE mounts) because a statvfs against an unreachable server blocks the "
         "dispatch worker indefinitely; the mount itself is still listed"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getmntinfo(3) MNT_NOWAIT", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "FindFirstVolumeW + GetVolumeInformationW + GetDriveTypeW + GetDiskFreeSpaceExW",
         "enumerates local volumes only; a mapped network drive is not a volume and is not "
         "listed, and no per-mount option string exists so that column reads '-'"},
    },
    {
        /* .action      = */ "quotas",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "quotactl(2) Q_GETFMT",
         "reports per-mount quota-subsystem state only; per-user and per-group limits are not "
         "enumerated, and a mount whose source is not a block device (overlay, tmpfs, network) "
         "reports no_block_device; a walk in which every probed device returns EPERM/EACCES "
         "reports permission_denied rather than a generic degradation"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "getattrlist(2) ATTR_VOL_QUOTA_SIZE/ATTR_VOL_RESERVED_SIZE",
         "volume-level quota and reserved size only; per-user and per-group quotas do not exist "
         "on APFS (quotactl returns ENOTSUP on every APFS mount while succeeding on HFS+), so no "
         "per-identity rows are reported; a volume the agent may not read reports "
         "permission_denied"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "IDiskQuotaControl (dskquota.h)",
         "volume quota state and default limit/threshold only, opened read-only; per-user quota "
         "entries are not enumerated; a volume that denies the query reports permission_denied; "
         "a build whose SDK lacks dskquota.h reports unavailable; "
         "compiled and linked on a live Windows host but not asserted against one with quotas "
         "configured, so the populated-quota path is unexercised"},
    },
    {
        /* .action      = */ "snapshots",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/proc/self/mountinfo btrfs subvol + device-mapper source detection",
         "reports snapshot-capable volumes and the mounted btrfs subvolume identity, not a "
         "snapshot inventory: a device-mapper source may be dm-crypt, dm-multipath or "
         "dm-integrity rather than a snapshot-capable LV, enumerating unmounted btrfs snapshots "
         "needs CAP_SYS_ADMIN via BTRFS_IOC_TREE_SEARCH, and telling an LVM snapshot LV from a "
         "linear LV needs a device-mapper DM_TABLE_STATUS ioctl -- none of which this read-only "
         "plugin performs"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "fs_snapshot_list(2)",
         "one row per (mount point, snapshot): an APFS snapshot visible under two mount points "
         "of the same volume lineage is reported under each"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "IVssBackupComponents::Query (VSS)",
         "enumerates VSS shadow copies machine-wide, one row per snapshot, reporting its snapshot "
         "ID and shadow-copy device path but no size or per-file content; REQUIRES ADMINISTRATIVE "
         "RIGHTS -- the agent runs as LocalSystem today so this succeeds; under an unprivileged "
         "service account CreateVssBackupComponents returns E_ACCESSDENIED and the action "
         "reports permission_denied rather than an empty snapshot set; any VSS "
         "failure is reported distinctly from a genuinely empty set and degrades the result "
         "status"},
    },
};

} // namespace

class FilesystemPosturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "filesystem_posture"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports mounted filesystems, per-mount quota-subsystem state, and "
               "snapshot-capable volumes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"mounts", "quotas", "snapshots", nullptr};
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
        if (action == "mounts")
            return yuzu::filesystem_posture::emit_mounts(ctx);
        if (action == "quotas")
            return yuzu::filesystem_posture::emit_quotas(ctx);
        if (action == "snapshots")
            return yuzu::filesystem_posture::emit_snapshots(ctx);

        // CDX-P2-08: `action` is request-supplied and lands in a pipe-delimited
        // stream, so it goes through the shared escaper like every other
        // untrusted field. This is a fourth ctx.write_output site: it is NOT a
        // row (no leading kind token), which is why it does not use the legs.hpp
        // wrappers -- see the corrected comment there.
        ctx.write_output(std::string{"unknown action: "} +
                         yuzu::util::safe_output_field(action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(FilesystemPosturePlugin)
