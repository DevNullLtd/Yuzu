#pragma once

/**
 * echo_perf.hpp — continuous device performance sampling for the Echo edge
 * warehouse (BRD A1, docs/dex-brd-coverage.md).
 *
 * Raw kernel counters in, one derived `perf_live` row out, every
 * perf_interval_seconds (default 30 s). Raw samples stay ON-DEVICE
 * (ADR-0004 federated model); fleet rollup and threshold-breach
 * observations are separate slices (A3/A4).
 *
 * Windows sources — deliberately NOT PDH, NOT WMI, NOT a shell-out (the
 * syscalls-over-shell-outs directive); each read is a plain kernel call:
 *   CPU     GetSystemTimes              (cumulative idle/kernel/user)
 *   Memory  GlobalMemoryStatusEx + GetPerformanceInfo (commit charge)
 *   Disk    IOCTL_DISK_PERFORMANCE      (per-physical-disk cumulative IO)
 *   Network GetIfTable2                 (per-interface cumulative octets)
 * Linux sources — the same no-shell-out posture, all read from procfs:
 *   CPU     /proc/stat                  (aggregate jiffies, DEX conventions)
 *   Memory  /proc/meminfo               (MemAvailable + Committed_AS/CommitLimit)
 *   Disk    /proc/diskstats             (whole-disk sectors + io ticks)
 *   Network /proc/net/dev               (per-interface cumulative bytes)
 * macOS (host_statistics) is kPlanned in the registry.
 *
 * The cumulative→rate/percentage derivation is PURE (derive_sample) and
 * unit-tested on every host; read_perf_counters() is the impure shell.
 * Counter regressions degrade per domain: a CPU-counter regression
 * invalidates the sample (reboot), but a disk/net regression (hotplug,
 * VPN interface vanishing) zeroes only that domain for one interval —
 * the rest of the row stays honest.
 */

#include <cstdint>
#include <string_view>

namespace yuzu::echo {

/// One instant's raw counters. CPU/disk/net are CUMULATIVE since boot;
/// memory fields are instantaneous. `valid` covers CPU+memory (the core
/// reads); `disk_valid` is separate because IOCTL_DISK_PERFORMANCE can be
/// unavailable (some virtual disks) while everything else works, and
/// `net_valid` likewise guards the network domain — a reading whose interface
/// enumeration failed must not baseline the net counters at 0, or the next
/// interval would derive a huge false since-boot spike.
struct PerfCounters {
    bool valid{false};
    bool disk_valid{false};
    bool net_valid{false};
    std::int64_t ts_epoch{0};

    // CPU, summed across cores, in a platform-consistent monotonic time unit
    // (100 ns on Windows, jiffies on Linux — derive_sample takes ratios only,
    // so the unit cancels). kernel INCLUDES idle (the GetSystemTimes contract;
    // the Linux mapping reproduces it — see parse_linux_perf_counters). Any
    // future platform (macOS host_statistics) can satisfy the contract the
    // same way: cpu_idle = cpu_kernel = idle ticks, cpu_user = busy ticks.
    std::uint64_t cpu_idle{0};
    std::uint64_t cpu_kernel{0};
    std::uint64_t cpu_user{0};

    // Memory, instantaneous, bytes.
    std::uint64_t mem_total_bytes{0};
    std::uint64_t mem_avail_bytes{0};
    std::uint64_t commit_total_bytes{0};
    std::uint64_t commit_limit_bytes{0};

    // Disk, cumulative, summed across physical disks.
    std::uint64_t disk_read_bytes{0};
    std::uint64_t disk_write_bytes{0};
    std::uint64_t disk_read_time_100ns{0};
    std::uint64_t disk_write_time_100ns{0};
    std::uint64_t disk_reads{0};
    std::uint64_t disk_writes{0};

    // Network, cumulative, summed across non-loopback interfaces.
    std::uint64_t net_rx_bytes{0};
    std::uint64_t net_tx_bytes{0};
};

/// One derived warehouse row (matches the perf_live schema minus ts/snapshot).
struct PerfSample {
    bool valid{false};
    double cpu_pct{0.0};
    double mem_used_pct{0.0};
    double commit_pct{0.0};
    std::int64_t disk_read_bps{0};
    std::int64_t disk_write_bps{0};
    std::int64_t disk_read_lat_us{0};  ///< avg per-read service time over the interval
    std::int64_t disk_write_lat_us{0};
    std::int64_t net_rx_bps{0};
    std::int64_t net_tx_bps{0};
};

/// PURE: derive one sample from two counter readings. Invalid when either
/// reading is invalid, elapsed <= 0, or a CPU counter regressed (reboot /
/// counter reset — rates from a regressed baseline would be garbage).
/// Disk/net regressions zero their own domain only (see header comment).
PerfSample derive_sample(const PerfCounters& prev, const PerfCounters& cur);

/// Impure shell: read the current counters. Windows (kernel counters) and
/// Linux (/proc) are wired; valid=false on macOS until its collector lands
/// (registry: kPlanned).
PerfCounters read_perf_counters();

/// PURE: build a PerfCounters reading from raw Linux /proc file contents.
/// Compiled on every host so the fiddly field handling is unit-tested in all
/// CI legs (the dex_linux_proc pattern); only the Linux shell feeds it real
/// files. `valid` requires CPU (/proc/stat aggregate line) + memory
/// (MemTotal); disk and net degrade per-domain, mirroring the Windows shell.
/// An empty payload for diskstats/netdev simply leaves that domain absent.
PerfCounters parse_linux_perf_counters(std::string_view proc_stat, std::string_view meminfo,
                                       std::string_view diskstats, std::string_view netdev,
                                       std::string_view overcommit_memory,
                                       std::int64_t ts_epoch);

} // namespace yuzu::echo
