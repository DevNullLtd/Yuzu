/**
 * filesystem_posture_linux.cpp — Linux leg for the filesystem_posture plugin.
 *
 * Mechanisms (all read-only; rung 1 -- direct syscall/proc read, no
 * subprocess):
 *   mounts    — /proc/self/mountinfo (parsed by parse_proc_mountinfo) +
 *               statvfs(2) for capacity. Declared limitation: a network
 *               fstype (is_network_fstype) never gets a statvfs call --
 *               against an unreachable server that call blocks
 *               uninterruptibly and would wedge a bounded dispatch-pool
 *               worker, so those rows carry nullopt sizes instead.
 *   quotas    — quotactl(QCMD(Q_GETFMT, USRQUOTA)) probed only against
 *               /dev/-prefixed mount sources; errno classified via
 *               classify_quotactl_errno. Declared limitation: Linux has no
 *               single volume-level limit (limits are per-identity), so
 *               this leg enumerates presence/format only, never a number.
 *               All non-block-device mounts (overlay/tmpfs/proc/cgroup/
 *               network/bind) are collapsed into exactly one aggregate
 *               no_block_device row rather than one row per mount.
 *   snapshots — derived entirely from the same mountinfo read: btrfs
 *               super_options (subvol=/subvolid=) via
 *               parse_btrfs_super_options, and device-mapper source
 *               detection via is_device_mapper_source. Declared
 *               limitation: enumerating unmounted btrfs snapshots and
 *               telling an LVM snapshot LV from a plain
 *               dm-crypt/multipath/integrity target both need a
 *               privileged device/filesystem-specific query this read-only
 *               plugin does not perform (see the per-row detail text for
 *               specifics).
 *
 * All decoding lives in filesystem_posture_parsers.hpp; this TU only makes
 * the syscalls and hands raw bytes/values to those pure functions. All
 * emission goes through filesystem_posture_legs.hpp's write_*_row wrappers.
 */

#if defined(__linux__)

#include <yuzu/plugin.hpp>

#include "filesystem_posture_legs.hpp"
#include "filesystem_posture_parsers.hpp"

#include <sys/quota.h>
#include <sys/statvfs.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>

namespace yuzu::filesystem_posture {

namespace {

constexpr std::size_t kMountinfoReadCap = 4ull * 1024 * 1024; // 4 MiB

// Reads /proc/self/mountinfo into `out`, capped at kMountinfoReadCap bytes.
// Sets `truncated` when the file had more bytes than the cap (the ifstream
// read simply stops at the cap either way; this flag is what tells the
// caller a real file was longer than what got parsed).
bool read_mountinfo_capped(std::string& out, bool& truncated) {
    truncated = false;
    std::ifstream in("/proc/self/mountinfo", std::ios::binary);
    if (!in)
        return false;
    out.resize(kMountinfoReadCap);
    in.read(out.data(), static_cast<std::streamsize>(out.size()));
    const auto got = static_cast<std::size_t>(in.gcount());
    out.resize(got);
    if (got == kMountinfoReadCap) {
        // Peek one more byte to tell "exactly the cap" from "longer than
        // the cap" without reading the whole remainder.
        char probe;
        if (in.read(&probe, 1).gcount() == 1)
            truncated = true;
    }
    return true;
}

// Sizes are f_blocks/f_bfree/f_bavail * f_frsize in unsigned long long, with
// an overflow guard harmonised with the macOS leg's checked_block_bytes: a
// product that would overflow the 64-bit accumulator clamps to the max
// representable value rather than wrapping into a fabricated small number
// (peer parity -- the rule must not differ by leg).
unsigned long long checked_block_product(unsigned long long blocks, unsigned long long frsize) {
    constexpr unsigned long long kMax = std::numeric_limits<unsigned long long>::max();
    if (blocks != 0 && frsize > kMax / blocks)
        return kMax;
    return blocks * frsize;
}

} // namespace

int emit_mounts(yuzu::CommandContext& ctx) {
    std::string text;
    bool read_truncated = false;
    if (!read_mountinfo_capped(text, read_truncated)) {
        mark_result_partial(ctx, "linux:mountinfo:unreadable", std::strerror(errno));
        return 0;
    }
    if (read_truncated)
        mark_result_partial(ctx, "linux:mountinfo", "file exceeded 4 MiB read cap");

    const MountinfoParse parse = parse_proc_mountinfo(text);

    for (const auto& entry : parse.entries) {
        std::optional<unsigned long long> total_bytes;
        std::optional<unsigned long long> free_bytes;
        std::optional<unsigned long long> available_bytes;

        if (!is_network_fstype(entry.fstype)) {
            struct statvfs sv{};
            if (statvfs(entry.mount_point.c_str(), &sv) == 0) {
                const auto frsize = static_cast<unsigned long long>(sv.f_frsize);
                total_bytes = checked_block_product(static_cast<unsigned long long>(sv.f_blocks), frsize);
                free_bytes = checked_block_product(static_cast<unsigned long long>(sv.f_bfree), frsize);
                available_bytes =
                    checked_block_product(static_cast<unsigned long long>(sv.f_bavail), frsize);
            } else {
                mark_result_partial(ctx, "linux:statvfs",
                                     entry.mount_point + ": " + std::strerror(errno));
            }
        }

        write_mount_row(ctx, entry.mount_point, entry.mount_source, entry.fstype,
                         entry.mount_options, total_bytes, free_bytes, available_bytes,
                         normalize_mount_flags(entry.mount_options));
    }

    if (parse.malformed_lines > 0)
        mark_result_partial(ctx, "linux:mountinfo:malformed",
                             std::to_string(parse.malformed_lines) + " malformed line(s)");
    if (parse.truncated)
        mark_result_partial(ctx, "linux:mountinfo:entry_cap", "entry count cap reached");

    return 0;
}

int emit_quotas(yuzu::CommandContext& ctx) {
    std::string text;
    bool read_truncated = false;
    if (!read_mountinfo_capped(text, read_truncated)) {
        mark_result_partial(ctx, "linux:mountinfo:quotas", std::strerror(errno));
        return 0;
    }
    // CDX-P2-05: emit_mounts already reports this; quotas must too, or a
    // truncated mountinfo silently narrows the set of volumes probed and the
    // run still reports clean success.
    if (read_truncated) {
        mark_result_partial(ctx, "linux:mountinfo", "file exceeded 4 MiB read cap");
    }

    const MountinfoParse parse = parse_proc_mountinfo(text);

    std::size_t non_block_device_count = 0;
    bool any_dev_probed = false;
    bool any_quota_failure = false; // ANY degraded probe, not only an all-denied walk
    bool all_dev_permission_denied = true;

    for (const auto& entry : parse.entries) {
        if (entry.mount_source.rfind("/dev/", 0) != 0) {
            ++non_block_device_count;
            continue;
        }

        any_dev_probed = true;
        int fmt = 0;
        errno = 0;
        const int rc = quotactl(QCMD(Q_GETFMT, USRQUOTA), entry.mount_source.c_str(), 0,
                                 reinterpret_cast<char*>(&fmt));
        const int saved_errno = (rc == 0) ? 0 : errno;
        const QuotaState state = classify_quotactl_errno(saved_errno);
        if (state != QuotaState::PermissionDenied) {
            all_dev_permission_denied = false;
        }
        // G4-01/SG-1: all_dev_permission_denied is an ALL-or-nothing flag, so a
        // single non-EPERM volume cleared it and the whole run reported clean
        // success even when a peer volume was denied. Track failure
        // independently, exactly as the macOS leg does -- one degraded probe
        // degrades the run. NotEnabled/NoBlockDevice/UnsupportedFs are truthful
        // complete answers and are deliberately NOT failures.
        if (state == QuotaState::PermissionDenied || state == QuotaState::Unavailable) {
            any_quota_failure = true;
        }

        std::string detail;
        if (rc == 0) {
            detail =
                "quota format " + std::to_string(fmt) + " enabled; per-id limits not enumerated";
        } else {
            switch (saved_errno) {
            case ESRCH:
                detail = "ESRCH";
                break;
            case ENOSYS:
                detail = "ENOSYS";
                break;
            case ENOENT:
                detail = "ENOENT";
                break;
            case ENOTBLK:
                detail = "ENOTBLK";
                break;
            case EPERM:
                detail = "EPERM";
                break;
            case EACCES:
                detail = "EACCES";
                break;
            default:
                detail = std::strerror(saved_errno);
                break;
            }
        }

        write_quota_row(ctx, entry.mount_point, state, std::nullopt, std::nullopt, detail);
    }

    if (non_block_device_count > 0) {
        write_quota_row(ctx, "-", QuotaState::NoBlockDevice, std::nullopt, std::nullopt,
                         std::to_string(non_block_device_count) +
                             " non-block-device mounts (overlay/tmpfs/virtual/network) not "
                             "quota-capable");
    }

    if (parse.malformed_lines > 0)
        mark_result_partial(ctx, "linux:mountinfo:malformed:quotas",
                             std::to_string(parse.malformed_lines) + " malformed line(s)");
    if (parse.truncated)
        mark_result_partial(ctx, "linux:mountinfo:entry_cap:quotas", "entry count cap reached");

    // Positioned LAST so its provenance is the one that survives
    // set_result_status's last-writer-wins assignment (peer M3).
    if (any_dev_probed && all_dev_permission_denied) {
        // Positioned LAST so this more actionable provenance survives
        // last-writer-wins when both fire.
        // CP-1 (Gate 3, cross-platform): this branch has already CLASSIFIED the
        // cause -- every probed device returned EPERM/EACCES -- so it reports
        // PERMISSION_DENIED rather than generic CONSTRAINED. The sibling
        // any_quota_failure branch below deliberately does NOT: its causes are
        // mixed, and claiming a denial there would be a guess.
        mark_result_denied(ctx, "linux:quotactl", "quota query requires CAP_SYS_ADMIN");
    } else if (any_quota_failure) {
        mark_result_partial(ctx, "linux:quotactl",
                            "quota query failed on at least one volume");
    }

    return 0;
}

int emit_snapshots(yuzu::CommandContext& ctx) {
    std::string text;
    bool read_truncated = false;
    if (!read_mountinfo_capped(text, read_truncated)) {
        // BR-001: acquisition FAILED, so we cannot assert "nothing found".
        // The Windows leg keeps failure and genuine-emptiness as two
        // distinguishable literals; match that here, or an unreadable
        // /proc/self/mountinfo reads to an operator as a healthy host with
        // no snapshot-capable mounts.
        const std::string why = std::strerror(errno);
        mark_result_partial(ctx, "linux:mountinfo:snapshots", why);
        write_snapshot_row(ctx, "-", "-", "none",
                           "could not read /proc/self/mountinfo: " + why);
        return 0;
    }
    // CDX-P2-05: a truncated read means the snapshot-capability answer was
    // computed over an incomplete mount list.
    if (read_truncated) {
        mark_result_partial(ctx, "linux:mountinfo", "file exceeded 4 MiB read cap");
    }

    const MountinfoParse parse = parse_proc_mountinfo(text);

    bool any_row = false;
    for (const auto& entry : parse.entries) {
        if (entry.fstype == "btrfs") {
            const BtrfsSubvolume subvol = parse_btrfs_super_options(entry.super_options);
            std::string name;
            if (!subvol.subvol.empty())
                name = subvol.subvol;
            else if (!subvol.subvolid.empty())
                name = subvol.subvolid;
            else
                name = "-";
            write_snapshot_row(ctx, entry.mount_point, name, "btrfs_subvolume",
                                "mounted subvolume; unmounted snapshots need CAP_SYS_ADMIN via "
                                "BTRFS_IOC_TREE_SEARCH");
            any_row = true;
        } else if (is_device_mapper_source(entry.mount_source)) {
            write_snapshot_row(ctx, entry.mount_point, entry.mount_source, "device_mapper",
                                "device-mapper target (may be dm-crypt/multipath/integrity "
                                "rather than a snapshot-capable LV); distinguishing needs a "
                                "DM_TABLE_STATUS ioctl");
            any_row = true;
        }
    }

    if (!any_row)
        write_snapshot_row(ctx, "-", "-", "none", "no btrfs or device-mapper mount found");

    if (parse.malformed_lines > 0)
        mark_result_partial(ctx, "linux:mountinfo:malformed:snapshots",
                             std::to_string(parse.malformed_lines) + " malformed line(s)");
    if (parse.truncated)
        mark_result_partial(ctx, "linux:mountinfo:entry_cap:snapshots", "entry count cap reached");

    return 0;
}

} // namespace yuzu::filesystem_posture

#endif // defined(__linux__)
