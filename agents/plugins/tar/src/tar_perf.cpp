#include "tar_perf.hpp"

#include <dex_linux_proc.hpp> // shared pure /proc parsers (agents/core) — all-host

#include <algorithm>
#include <charconv>
#include <ctime>
#include <optional>
#include <string_view>

namespace yuzu::tar {

namespace {

// Saturating delta for cumulative counters: a regression reads as "no data"
// (0), never as a giant unsigned wrap.
std::uint64_t delta(std::uint64_t prev, std::uint64_t cur) {
    return cur >= prev ? cur - prev : 0;
}

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

} // namespace

PerfSample derive_sample(const PerfCounters& prev, const PerfCounters& cur) {
    PerfSample s;
    if (!prev.valid || !cur.valid)
        return s;
    const std::int64_t elapsed = cur.ts_epoch - prev.ts_epoch;
    if (elapsed <= 0)
        return s;
    // CPU counter regression = reboot/reset between samples — the whole
    // baseline is gone, so the sample is invalid (next tick re-baselines).
    if (cur.cpu_idle < prev.cpu_idle || cur.cpu_kernel < prev.cpu_kernel ||
        cur.cpu_user < prev.cpu_user)
        return s;
    s.valid = true;

    // CPU: kernel includes idle, so total = kernel + user, busy = total - idle.
    const std::uint64_t idle_d = cur.cpu_idle - prev.cpu_idle;
    const std::uint64_t total_d =
        (cur.cpu_kernel - prev.cpu_kernel) + (cur.cpu_user - prev.cpu_user);
    if (total_d > 0 && total_d >= idle_d)
        s.cpu_pct = clamp_pct(100.0 * static_cast<double>(total_d - idle_d) /
                              static_cast<double>(total_d));

    // Memory: instantaneous from the current reading.
    if (cur.mem_total_bytes > 0)
        s.mem_used_pct = clamp_pct(
            100.0 * static_cast<double>(cur.mem_total_bytes - (std::min)(cur.mem_avail_bytes,
                                                                         cur.mem_total_bytes)) /
            static_cast<double>(cur.mem_total_bytes));
    if (cur.commit_limit_bytes > 0)
        s.commit_pct = clamp_pct(100.0 * static_cast<double>(cur.commit_total_bytes) /
                                 static_cast<double>(cur.commit_limit_bytes));

    // Disk: per-domain degrade — both readings must have disk data; a
    // regression (hotplug/reset) zeroes this domain for one interval via the
    // saturating delta.
    if (prev.disk_valid && cur.disk_valid) {
        s.disk_read_bps = static_cast<std::int64_t>(
            delta(prev.disk_read_bytes, cur.disk_read_bytes) /
            static_cast<std::uint64_t>(elapsed));
        s.disk_write_bps = static_cast<std::int64_t>(
            delta(prev.disk_write_bytes, cur.disk_write_bytes) /
            static_cast<std::uint64_t>(elapsed));
        const std::uint64_t reads_d = delta(prev.disk_reads, cur.disk_reads);
        const std::uint64_t writes_d = delta(prev.disk_writes, cur.disk_writes);
        if (reads_d > 0)
            s.disk_read_lat_us = static_cast<std::int64_t>(
                delta(prev.disk_read_time_100ns, cur.disk_read_time_100ns) / reads_d / 10);
        if (writes_d > 0)
            s.disk_write_lat_us = static_cast<std::int64_t>(
                delta(prev.disk_write_time_100ns, cur.disk_write_time_100ns) / writes_d / 10);
    }

    // Network: per-domain degrade like disk — both readings must have real
    // interface data. Without the guard, a reading whose enumeration failed
    // (counters 0) would become the baseline and the NEXT interval would
    // record the entire since-boot totals as one 30 s rate — a massive false
    // spike. Interface churn (a VPN adapter vanishing) still shrinks the
    // summed counters within valid readings — the saturating delta records
    // one 0-rate interval and the next tick self-corrects, rather than
    // poisoning the whole row.
    if (prev.net_valid && cur.net_valid) {
        s.net_rx_bps = static_cast<std::int64_t>(delta(prev.net_rx_bytes, cur.net_rx_bytes) /
                                                 static_cast<std::uint64_t>(elapsed));
        s.net_tx_bps = static_cast<std::int64_t>(delta(prev.net_tx_bytes, cur.net_tx_bytes) /
                                                 static_cast<std::uint64_t>(elapsed));
    }
    return s;
}

// ── Pure Linux /proc parsing ─────────────────────────────────────────────────
// Compiled and unit-tested on every host (only the Linux shell below feeds it
// real files). Reuses the exported agents/core parsers where they encode a
// repo-wide convention (CPU busy accounting, whole-disk classification, the
// overcommit gate); the local field walks are the pieces those parsers
// deliberately do not expose (raw byte fields, read/write splits).

namespace {

namespace lnx = yuzu::agent::lnx;

// /proc/diskstats sector counts are a FIXED 512-byte kernel ABI unit,
// independent of the device's physical sector size.
constexpr std::uint64_t kDiskSectorBytes = 512;

// Exception-free integer token parse requiring FULL-token consumption — the
// same contract as the core's to_u64 and the pid-stat parser, so a corrupt
// token ("4x000") rejects the row instead of being silently truncated (the
// dex_linux_proc "parsers never throw / never half-accept" rule).
std::optional<std::uint64_t> parse_u64(std::string_view tok) {
    std::uint64_t v = 0;
    const auto [p, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
    if (ec != std::errc{} || p != tok.data() + tok.size())
        return std::nullopt;
    return v;
}

bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

// Fill `out` with up to `max` leading whitespace-separated tokens; returns the
// count (tail ignored). Zero allocation (the dex_linux_proc array idiom). CR
// counts as whitespace in BOTH loops — every byte is either skipped or
// consumed, so no input can wedge the scan (a defect here would hang the
// collect tick, strictly worse than the throw this module already forbids).
std::size_t split_ws(std::string_view line, std::string_view* out, std::size_t max) {
    std::size_t n = 0, i = 0;
    while (i < line.size() && n < max) {
        while (i < line.size() && is_ws(line[i]))
            ++i;
        const std::size_t start = i;
        while (i < line.size() && !is_ws(line[i]))
            ++i;
        if (i > start)
            out[n++] = line.substr(start, i - start);
    }
    return n;
}

template <typename Fn>
void for_each_line(std::string_view text, Fn&& fn) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        fn(text.substr(pos, nl - pos));
        pos = nl + 1;
    }
}

// First integer (kB) of an exact-key /proc/meminfo line; `key` includes the
// trailing ':' so "MemFree:" can never match "MemAvailable:"-adjacent keys.
std::optional<std::uint64_t> meminfo_kb(std::string_view meminfo, std::string_view key) {
    for (std::size_t pos = 0; pos < meminfo.size();) {
        std::size_t nl = meminfo.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = meminfo.size();
        const std::string_view line = meminfo.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.substr(0, key.size()) != key)
            continue;
        std::string_view tok;
        if (split_ws(line.substr(key.size()), &tok, 1) != 1)
            return std::nullopt;
        return parse_u64(tok);
    }
    return std::nullopt;
}

} // namespace

PerfCounters parse_linux_perf_counters(std::string_view proc_stat, std::string_view meminfo,
                                       std::string_view diskstats, std::string_view netdev,
                                       std::string_view overcommit_memory,
                                       std::int64_t ts_epoch) {
    PerfCounters c;
    c.ts_epoch = ts_epoch;

    // CPU — the aggregate `cpu ` line via the shared core parser, so TAR's
    // busy% is numerically identical to the DEX Linux collector (iowait counts
    // as idle, steal/irq/softirq as busy, guest excluded — it is already inside
    // user/nice). Mapping into the GetSystemTimes-shaped fields, whose contract
    // is "kernel INCLUDES idle" and whose derivation only ever takes
    // total = kernel + user and busy = total − idle:
    //   cpu_kernel = j.idle          (idle stands in for "kernel incl. idle" —
    //                                 no busy-kernel split is needed)
    //   cpu_user   = j.total − j.idle (busy)
    //   cpu_idle   = j.idle
    // busy is a sum of individually-monotonic jiffy fields. idle+iowait is NOT
    // strictly monotonic (aggregate iowait can tick backwards on SMP —
    // proc(5)); if it regresses across an entire interval — which needs a
    // near-zero-idle window AND an iowait revision — derive_sample's reboot
    // guard skips that one row (an honest `baseline` tick, self-healing next
    // tick) rather than recording a skewed sample. Deliberate: preferred over
    // weakening the shared, test-pinned guard or excluding iowait from the
    // ratio (which would overstate CPU% under heavy IO wait).
    const lnx::CpuJiffies j = lnx::parse_proc_stat(proc_stat);
    if (j.valid) {
        c.cpu_idle = j.idle;
        c.cpu_kernel = j.idle;
        c.cpu_user = j.total - j.idle;
    }

    // Memory — MemAvailable matches Windows ullAvailPhys semantics (reclaimable
    // pages count as available); MemFree only as the fallback for kernels
    // < 3.14 that lack the key.
    const auto mem_total = meminfo_kb(meminfo, "MemTotal:");
    if (mem_total && *mem_total > 0) {
        c.mem_total_bytes = *mem_total * 1024;
        const auto mem_avail = meminfo_kb(meminfo, "MemAvailable:");
        c.mem_avail_bytes =
            (mem_avail ? *mem_avail : meminfo_kb(meminfo, "MemFree:").value_or(0)) * 1024;
    }

    // Commit — the direct analogue of the Windows commit charge, except under
    // vm.overcommit_memory=1, where CommitLimit is advisory and the ratio is
    // meaningless (healthy DB/HPC hosts routinely exceed it): leave the fields
    // 0 so commit_pct records 0.0 — the same "unknown" the Windows shell
    // records when GetPerformanceInfo fails. Matches the DEX collector's gate.
    if (!lnx::overcommit_is_always(overcommit_memory)) {
        c.commit_total_bytes = meminfo_kb(meminfo, "Committed_AS:").value_or(0) * 1024;
        c.commit_limit_bytes = meminfo_kb(meminfo, "CommitLimit:").value_or(0) * 1024;
    }

    c.valid = j.valid && c.mem_total_bytes > 0; // CPU + memory are the core reads

    // Disk — whole physical disks only (lnx::is_whole_disk: no partitions, no
    // loop/ram/zram pseudo devices, no dm-/md aggregates — those would
    // double-count their member disks). Sectors ×512 (kDiskSectorBytes); io
    // ticks are ms, ×10'000 into the 100 ns struct fields so derive_sample's
    // Δ/ios/10 lands on exactly Δms×1000/ios µs per IO.
    for_each_line(diskstats, [&](std::string_view line) {
        std::string_view f[11];
        if (split_ws(line, f, 11) < 11 || !lnx::is_whole_disk(f[2]))
            return;
        const auto reads = parse_u64(f[3]), rd_sectors = parse_u64(f[5]), rd_ms = parse_u64(f[6]);
        const auto writes = parse_u64(f[7]), wr_sectors = parse_u64(f[9]), wr_ms = parse_u64(f[10]);
        if (!reads || !rd_sectors || !rd_ms || !writes || !wr_sectors || !wr_ms)
            return; // malformed row — skip it, never throw
        c.disk_valid = true;
        c.disk_reads += *reads;
        c.disk_writes += *writes;
        c.disk_read_bytes += *rd_sectors * kDiskSectorBytes;
        c.disk_write_bytes += *wr_sectors * kDiskSectorBytes;
        c.disk_read_time_100ns += *rd_ms * 10'000;
        c.disk_write_time_100ns += *wr_ms * 10'000;
    });

    // Net — skip only the loopback interface. Virtual interfaces are
    // deliberately INCLUDED: name-based virtual filtering is the documented
    // rejected alternative (net_quality_sampler), and the Windows shell
    // likewise excludes only IF_TYPE_SOFTWARE_LOOPBACK. Header lines carry no
    // ':' and fall out naturally. net_valid records that well-formed netdev
    // content was seen AT ALL (loopback included) — without it, a transiently
    // empty read would baseline the counters at 0 inside an otherwise valid
    // reading and the next interval would record a massive false since-boot
    // spike (see derive_sample's net guard).
    for_each_line(netdev, [&](std::string_view line) {
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            return;
        std::string_view name;
        if (split_ws(line.substr(0, colon), &name, 1) != 1)
            return;
        std::string_view f[9];
        if (split_ws(line.substr(colon + 1), f, 9) < 9)
            return;
        const auto rx = parse_u64(f[0]), tx = parse_u64(f[8]);
        if (!rx || !tx)
            return;
        c.net_valid = true;
        if (name == "lo")
            return;
        c.net_rx_bytes += *rx;
        c.net_tx_bytes += *tx;
    });

    return c;
}

} // namespace yuzu::tar

// ── Impure shell: platform counter reads ─────────────────────────────────────

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h> // must precede windows.h; netioapi.h needs its typedefs
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h> // GetIfTable2 / MIB_IF_TABLE2 (64-bit octet counters)
#include <winioctl.h> // IOCTL_DISK_PERFORMANCE, DISK_PERFORMANCE
#include <psapi.h>    // GetPerformanceInfo (commit charge)
// clang-format on

#include <string>

namespace yuzu::tar {

namespace {

std::uint64_t ft_to_u64(const FILETIME& ft) {
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// Sum IOCTL_DISK_PERFORMANCE over \\.\PhysicalDrive0..31. A missing index or
// an unsupported disk (some virtual disks) is skipped; disk_valid only when
// at least one disk responded. Open with zero access rights — the IOCTL
// needs none, so this works for the unprivileged dev agent too.
void read_disks(PerfCounters& c) {
    for (int n = 0; n < 32; ++n) {
        const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
        HANDLE h = ::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        DISK_PERFORMANCE perf{};
        DWORD bytes = 0;
        if (::DeviceIoControl(h, IOCTL_DISK_PERFORMANCE, nullptr, 0, &perf, sizeof(perf),
                              &bytes, nullptr)) {
            c.disk_valid = true;
            c.disk_read_bytes += static_cast<std::uint64_t>(perf.BytesRead.QuadPart);
            c.disk_write_bytes += static_cast<std::uint64_t>(perf.BytesWritten.QuadPart);
            c.disk_read_time_100ns += static_cast<std::uint64_t>(perf.ReadTime.QuadPart);
            c.disk_write_time_100ns += static_cast<std::uint64_t>(perf.WriteTime.QuadPart);
            c.disk_reads += perf.ReadCount;
            c.disk_writes += perf.WriteCount;
        }
        ::CloseHandle(h);
    }
}

void read_network(PerfCounters& c) {
    MIB_IF_TABLE2* table = nullptr;
    if (::GetIfTable2(&table) != NO_ERROR || !table)
        return; // net_valid stays false — the domain degrades for this reading
    c.net_valid = true;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& row = table->Table[i];
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        c.net_rx_bytes += row.InOctets;  // 64-bit — no wrap concern
        c.net_tx_bytes += row.OutOctets;
    }
    ::FreeMibTable(table);
}

} // namespace

PerfCounters read_perf_counters() {
    PerfCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));

    FILETIME idle{}, kernel{}, user{};
    if (!::GetSystemTimes(&idle, &kernel, &user))
        return c; // valid stays false
    c.cpu_idle = ft_to_u64(idle);
    c.cpu_kernel = ft_to_u64(kernel);
    c.cpu_user = ft_to_u64(user);

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (!::GlobalMemoryStatusEx(&mem))
        return c;
    c.mem_total_bytes = mem.ullTotalPhys;
    c.mem_avail_bytes = mem.ullAvailPhys;

    PERFORMANCE_INFORMATION pi{};
    pi.cb = sizeof(pi);
    if (::GetPerformanceInfo(&pi, sizeof(pi))) {
        c.commit_total_bytes = static_cast<std::uint64_t>(pi.CommitTotal) * pi.PageSize;
        c.commit_limit_bytes = static_cast<std::uint64_t>(pi.CommitLimit) * pi.PageSize;
    }

    c.valid = true; // CPU + memory are the core reads; disk/net degrade separately
    read_disks(c);
    read_network(c);
    return c;
}

} // namespace yuzu::tar

#elif defined(__linux__)

#include <fstream>

namespace yuzu::tar {

namespace {

// Whole-file slurp; "" on open failure OR a mid-read I/O error. Returning ""
// on a bad read (not just EOF) is load-bearing for the net domain: a
// truncated /proc/net/dev that still carried the `lo` line would otherwise set
// net_valid=true with the non-loopback counters baselined at 0, reproducing
// the exact one-interval false since-boot spike net_valid exists to prevent.
// Chunked read() so a short read sets eofbit (normal) while a real error sets
// badbit (rejected). Each existing /proc consumer keeps its own small reader
// (dex_linux_collector, agent.cpp) — a shared one is a bigger diff.
std::string read_proc(const char* path) {
    std::ifstream f(path);
    if (!f)
        return {};
    std::string content;
    char buf[4096];
    while (f.read(buf, sizeof buf))
        content.append(buf, static_cast<std::size_t>(f.gcount()));
    content.append(buf, static_cast<std::size_t>(f.gcount()));
    if (f.bad())
        return {}; // I/O error mid-read — treat the whole file as absent
    return content;
}

} // namespace

PerfCounters read_perf_counters() {
    // A transient /proc read failure surfaces as valid=false, which
    // do_collect_perf reports as `counters_unavailable` on a supported OS
    // (read_failure_token, #1846) and `unsupported_platform` only where the
    // registry says the OS has no perf collector. The caller advances
    // prev_perf_ only on valid readings and the counters are cumulative, so
    // the next successful tick derives correctly over the longer interval.
    return parse_linux_perf_counters(read_proc("/proc/stat"), read_proc("/proc/meminfo"),
                                     read_proc("/proc/diskstats"), read_proc("/proc/net/dev"),
                                     read_proc("/proc/sys/vm/overcommit_memory"),
                                     static_cast<std::int64_t>(std::time(nullptr)));
}

} // namespace yuzu::tar

#else // !_WIN32 && !__linux__ — macOS (host_statistics) is kPlanned

namespace yuzu::tar {

PerfCounters read_perf_counters() {
    PerfCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    return c; // valid=false — collect_perf records nothing on this platform yet
}

} // namespace yuzu::tar

#endif
