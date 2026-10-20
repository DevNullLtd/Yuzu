#pragma once

/**
 * dex_linux_proc.hpp — pure parsers for the Linux /proc DEX signals (Guardian DEX).
 *
 * The Linux DEX collector (dex_linux_collector.cpp) is all-poll: it reads
 * /proc/stat, /proc/meminfo and /proc/mounts on a slow cadence and feeds the
 * derived numbers into the SAME sustained-breach hysteresis + observation
 * builders the Windows poller uses (dex_perf_breach.hpp, dex_win_poll.hpp). A
 * Linux server therefore lights up the EXISTING perf.cpu_sustained /
 * perf.memory_pressure / storage.low buckets with ZERO server change — the
 * macOS-collector parity playbook (a server is observed the same as any other OS,
 * in the same dashboard rows).
 *
 * Everything here is a PURE text parse (no syscalls, no platform guards) so the
 * fiddly /proc field handling is unit-tested on every host against captured
 * fixtures, exactly like extract_named_data and the dex_perf_breach derivations.
 * Parsers NEVER throw (std::from_chars, not stoull): a malformed /proc line must
 * not unwind out of the poll thread (the dex_observer parse_int_field rule).
 *
 * Namespace `lnx`, not `linux`: `linux` is a predefined macro (== 1) under the
 * gnu++ dialects, so `namespace linux { … }` would not compile portably.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent::lnx {

/// CPU jiffies from the aggregate `cpu` line of /proc/stat. `total` sums the
/// first EIGHT fields (user, nice, system, idle, iowait, irq, softirq, steal);
/// guest / guest_nice are deliberately excluded — the kernel already folds them
/// into user / nice, so summing them would double-count. `idle` is idle + iowait
/// (time the CPU did no work — iowait is an I/O stall, not CPU busy). Both
/// cumulative since boot.
struct CpuJiffies {
    bool valid{false};
    std::uint64_t total{0};
    std::uint64_t idle{0};
};

/// Parse the aggregate `cpu ` line out of /proc/stat. valid=false when that line
/// is absent or carries fewer than the 4 fields (user, nice, system, idle) the
/// busy% derivation needs.
YUZU_EXPORT CpuJiffies parse_proc_stat(std::string_view proc_stat);

/// PURE: busy% over the interval between two readings. nullopt when either
/// reading is invalid, a counter regressed (reboot / reset — a rate off a
/// regressed baseline is garbage), or no time elapsed (total delta 0). Clamped to
/// [0,100]. Mirrors derive_breach_sample's CPU logic, for /proc jiffies.
YUZU_EXPORT std::optional<double> cpu_busy_pct(const CpuJiffies& prev, const CpuJiffies& cur);

/// PURE: commit charge as a percentage of the commit limit, from /proc/meminfo
/// (100 * Committed_AS / CommitLimit). This is the DIRECT analogue of Windows'
/// commit-total / commit-limit, so it feeds memory_pressure_observation with the
/// SAME meaning AND wording ("commit charge avg X% of limit") — genuine parity,
/// not a relabelled metric. nullopt when CommitLimit is missing or zero, or
/// Committed_AS is missing. Clamped to [0,100] (heuristic overcommit can push the
/// raw ratio above the limit).
YUZU_EXPORT std::optional<double> parse_commit_pct(std::string_view proc_meminfo);

/// One local filesystem worth a storage.low check, from /proc/mounts.
struct MountPoint {
    std::string device; ///< backing source (the dedup key)
    std::string path;   ///< mount point to statvfs
    std::string fstype;
};

/// PURE: the real, writable, LOCAL filesystems to check for storage.low, parsed
/// from /proc/mounts. Whitelists block-backed fstypes (ext*/xfs/btrfs/zfs/f2fs)
/// and skips read-only mounts — by construction this avoids the squashfs/snap
/// "100% full by design" storm and never statvfs()'s a pseudo or network *fstype*.
/// Deduped by backing device so a bind mount of the same filesystem is not counted
/// twice. NOTE: excluding network fstypes does NOT make statvfs() hang-proof — a
/// whitelisted LOCAL fstype on remote-backed or failing block storage (iSCSI / NBD /
/// multipath / a dying disk) can still block the caller's statvfs() indefinitely; a
/// bounded/async statvfs is a tracked follow-up (the collector's poll thread owns it).
///
/// Deliberately EXCLUDED (parity with the Windows fixed-disk-only storage.low):
/// tmpfs (/run, /dev/shm, /tmp), other RAM-backed/pseudo fs (proc, sysfs, cgroup,
/// overlay), and network mounts (nfs/cifs). A full tmpfs is a MEMORY condition, not
/// disk-full — it is RAM-backed and sized by design — so it belongs to a future
/// memory/tmpfs obs_type, not storage.low; excluding network fstypes also avoids the
/// most common statvfs() stall (a hung NFS/CIFS server).
YUZU_EXPORT std::vector<MountPoint> parse_storage_mounts(std::string_view proc_mounts);

/// PURE: a stable, NON-PII storage.low subject derived from the backing DEVICE,
/// never the mount path. A mount path is *where users put files* and routinely
/// carries usernames / tenant / project names (`/home/jsmith/...`,
/// `/srv/acme-data`) — exactly the content the DEX edge-privacy contract forbids
/// leaving the device (`docs/dex-signal-catalog.md`). The backing-device
/// identifier is infrastructure config (the same class as the hostname), so it is
/// the Linux analogue of the Windows drive letter ("C:") and the macOS volume
/// label ("Macintosh HD") the other collectors emit.
///
/// For a `/dev/*` block device the label is the BASENAME ("/dev/sda1" -> "sda1",
/// "/dev/mapper/vg0-root" -> "vg0-root"). For a non-/dev source — notably a ZFS
/// dataset, whose /proc/mounts source is the dataset path and whose canonical layout
/// puts the user/tenant in the LEAF ("tank/home/alice", "rpool/USERDATA/alice_x") —
/// the label is the FIRST segment (the POOL, "tank"/"rpool"): infra config, never the
/// PII leaf. "disk" when the device is empty or reduces to nothing.
YUZU_EXPORT std::string device_label(std::string_view device);

/// PURE: true iff /proc/sys/vm/overcommit_memory selects mode 1 ("always
/// overcommit"), in which CommitLimit is advisory — the kernel never refuses an
/// allocation against it, so Committed_AS routinely exceeds it on healthy DB / Redis
/// / HPC hosts. commit% vs CommitLimit is then meaningless and must NOT drive
/// perf.memory_pressure (it would false-positive-storm). Modes 0 (heuristic, the
/// default) and 2 (strict) keep CommitLimit meaningful. Anything that is not exactly
/// the token "1" reads as not-always (so a read failure / empty file leaves the
/// signal enabled — fail-safe toward keeping the signal, not suppressing it).
YUZU_EXPORT bool overcommit_is_always(std::string_view proc_overcommit_memory);

/// Aggregate completed-I/O count + busy time over the real WHOLE disks, from
/// /proc/diskstats. The Linux analogue of the Windows IOCTL_DISK_PERFORMANCE
/// disk-latency counters: `time_ms` is read-time + write-time (already in ms,
/// fields 7 + 11), `ios` is reads-completed + writes-completed (fields 4 + 8).
struct DiskIoTotals {
    bool valid{false};
    std::uint64_t ios{0};     ///< reads + writes completed, summed over whole disks
    std::uint64_t time_ms{0}; ///< ms spent reading + writing, summed
};

/// PURE: true iff `name` is a real WHOLE physical disk worth a latency reading —
/// sd*/vd*/xvd*/hd* (a trailing letter, not a partition digit), nvmeXnY (no `p`
/// partition suffix), mmcblkN (no `p`). Excludes partitions (would double-count
/// against their parent), loop/ram/zram/sr/fd pseudo devices, and dm-*/md*/nbd*
/// aggregates (their stats roll up their members → double-count). Exposed for tests.
///
/// SCOPE: local-attached block disks only. Exotic/fabric storage — NVMe-oF connect
/// namespaces (`nvmeXcYnZ`), DRBD (`drbdN`), bcache (`bcacheN`), and device-mapper
/// multipath (`mpathN`, summed via member `sdX` paths) — is deliberately NOT classified
/// here (returns false → that host's `perf.disk_latency_high` simply does not evaluate,
/// never a false signal). Broadening to fabric storage is a tracked follow-up; the safe
/// default is to omit an unrecognised source rather than mis-aggregate it.
YUZU_EXPORT bool is_whole_disk(std::string_view name);

/// PURE: sum the completed-I/O and busy-time counters over the whole disks in
/// /proc/diskstats. valid=false only if no whole disk parsed (so a malformed file
/// re-baselines rather than reading a healthy 0 — the cpu_busy_pct contract).
YUZU_EXPORT DiskIoTotals parse_diskstats(std::string_view proc_diskstats);

/// PURE: average service time (ms per completed I/O) over the interval between two
/// readings — the iostat `await` shape. nullopt when either reading is invalid or a
/// counter regressed (reboot / disk hotplug). An interval with ZERO completed I/Os
/// derives 0.0 — an idle disk is healthy, not slow (the Windows disk-latency
/// contract). Feeds win::breach_update with win::kDiskLatBreach (same 25 ms
/// threshold + hysteresis as Windows), so a slow Linux disk renders identically.
YUZU_EXPORT std::optional<double> disk_await_ms(const DiskIoTotals& prev, const DiskIoTotals& cur);

/// PURE: uptime in seconds from /proc/uptime (its first token). nullopt when the
/// content has no leading number, or it is non-finite/negative/implausibly large
/// (≥ 1e12 s — the caller casts to int64, so an out-of-range value would be UB on the
/// cast). Uses strtod (not from_chars<double>, which is missing on some libc++) —
/// exception-free.
YUZU_EXPORT std::optional<double> parse_proc_uptime(std::string_view proc_uptime);

} // namespace yuzu::agent::lnx
