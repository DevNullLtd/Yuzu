#include "dex_perf_breach.hpp"

#include <algorithm>
#include <format>

namespace yuzu::agent::win {

// ── Pure derivation + latch (every platform — unit-tested off Windows) ──────

namespace {

// Saturating delta for cumulative counters: a regression reads as "no data"
// (0), never as a giant unsigned wrap (the echo_perf idiom).
std::uint64_t delta(std::uint64_t prev, std::uint64_t cur) {
    return cur >= prev ? cur - prev : 0;
}

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

// The sustained window in minutes, for the human-readable reason/sentence.
int window_minutes(const BreachParams& p) {
    return static_cast<int>(p.sustain * kPerfSampleIntervalSeconds / 60);
}

} // namespace

PerfBreachSample derive_breach_sample(const PerfBreachCounters& prev,
                                      const PerfBreachCounters& cur) {
    PerfBreachSample s;
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

    // Commit charge: instantaneous from the current reading. Per-domain valid
    // (gov review MEDIUM #1) — only when THIS reading's GetPerformanceInfo
    // succeeded. An intermittent failure must not feed a healthy 0% into the
    // memory latch (which would reset a building breach or clear a reported
    // one); the caller gates the memory breach on s.commit_valid.
    if (cur.commit_valid && cur.commit_limit_bytes > 0) {
        s.commit_valid = true;
        s.commit_pct = clamp_pct(100.0 * static_cast<double>(cur.commit_total_bytes) /
                                 static_cast<double>(cur.commit_limit_bytes));
    }

    // Disk: per-domain degrade — both readings must have disk data; a
    // regression zeroes the domain for one interval via the saturating delta.
    // Zero IOs in the interval derives 0 ms: an idle disk is healthy.
    if (prev.disk_valid && cur.disk_valid) {
        s.disk_valid = true;
        const std::uint64_t ops_d = delta(prev.disk_reads, cur.disk_reads) +
                                    delta(prev.disk_writes, cur.disk_writes);
        if (ops_d > 0) {
            const std::uint64_t time_d =
                delta(prev.disk_read_time_100ns, cur.disk_read_time_100ns) +
                delta(prev.disk_write_time_100ns, cur.disk_write_time_100ns);
            // 100 ns units → ms: /10 (µs) /1000 (ms), as a double for sub-ms.
            s.disk_lat_ms = static_cast<double>(time_d) / static_cast<double>(ops_d) / 10000.0;
        }
    }
    return s;
}

std::optional<double> breach_update(BreachState& st, double value, bool valid,
                                    const BreachParams& p) {
    if (!valid) {
        // A gap breaks any "sustained" claim and must not progress recovery —
        // a transient read failure never clears the latch (UP-5).
        st.bad_streak = 0;
        st.good_streak = 0;
        st.sum = 0.0;
        return std::nullopt;
    }
    if (st.reported) {
        if (value < p.exit) {
            if (++st.good_streak >= p.recover) {
                st = BreachState{}; // re-armed, healthy
            }
        } else {
            st.good_streak = 0; // still (near-)bad — hysteresis holds the latch
        }
        return std::nullopt;
    }
    if (value >= p.enter) {
        st.sum += value;
        if (++st.bad_streak >= p.sustain) {
            const double avg = st.sum / static_cast<double>(st.bad_streak);
            st = BreachState{};
            st.reported = true;
            return avg; // transition into sustained-bad — emit once
        }
    } else {
        st.bad_streak = 0;
        st.sum = 0.0;
    }
    return std::nullopt;
}

// ── Observation builders ─────────────────────────────────────────────────────

SignalObservation cpu_sustained_observation(double avg_pct) {
    SignalObservation o;
    o.obs_type = "perf.cpu_sustained";
    o.subject = "cpu";
    o.reason = std::format("avg {:.0f}% over {} min", avg_pct, window_minutes(kCpuBreach));
    o.metric = avg_pct;
    o.sentence = std::format("Sustained high CPU: {}", o.reason);
    return o;
}

SignalObservation memory_pressure_observation(double avg_pct) {
    SignalObservation o;
    o.obs_type = "perf.memory_pressure";
    o.subject = "memory";
    o.reason = std::format("commit charge avg {:.0f}% of limit over {} min", avg_pct,
                           window_minutes(kMemoryBreach));
    o.metric = avg_pct;
    o.sentence = std::format("Memory pressure: {}", o.reason);
    return o;
}

SignalObservation disk_latency_observation(double avg_ms) {
    SignalObservation o;
    o.obs_type = "perf.disk_latency_high";
    o.subject = "disk";
    o.reason =
        std::format("avg {:.1f} ms per IO over {} min", avg_ms, window_minutes(kDiskLatBreach));
    o.metric = avg_ms;
    o.sentence = std::format("Slow disk: {}", o.reason);
    return o;
}

} // namespace yuzu::agent::win

// ── Win32 mechanism ──────────────────────────────────────────────────────────

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h> // IOCTL_DISK_PERFORMANCE, DISK_PERFORMANCE
#include <psapi.h>    // GetPerformanceInfo (commit charge)

#include <ctime>
#include <string>

namespace yuzu::agent::win {

namespace {

std::uint64_t ft_to_u64(const FILETIME& ft) {
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// Sum IOCTL_DISK_PERFORMANCE over \\.\PhysicalDrive0..31 (the echo_perf
// pattern). A missing index or an unsupported disk (some virtual disks) is
// skipped; disk_valid only when at least one disk responded. Open with zero
// access rights — the IOCTL needs none (works for the unprivileged dev agent).
void read_disks(PerfBreachCounters& c) {
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
            c.disk_read_time_100ns += static_cast<std::uint64_t>(perf.ReadTime.QuadPart);
            c.disk_write_time_100ns += static_cast<std::uint64_t>(perf.WriteTime.QuadPart);
            c.disk_reads += perf.ReadCount;
            c.disk_writes += perf.WriteCount;
        }
        ::CloseHandle(h);
    }
}

} // namespace

PerfBreachCounters read_perf_breach_counters() {
    PerfBreachCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));

    FILETIME idle{}, kernel{}, user{};
    if (!::GetSystemTimes(&idle, &kernel, &user))
        return c; // valid stays false
    c.cpu_idle = ft_to_u64(idle);
    c.cpu_kernel = ft_to_u64(kernel);
    c.cpu_user = ft_to_u64(user);

    PERFORMANCE_INFORMATION pi{};
    pi.cb = sizeof(pi);
    if (::GetPerformanceInfo(&pi, sizeof(pi))) {
        c.commit_total_bytes = static_cast<std::uint64_t>(pi.CommitTotal) * pi.PageSize;
        c.commit_limit_bytes = static_cast<std::uint64_t>(pi.CommitLimit) * pi.PageSize;
        c.commit_valid = true; // memory latch is fed only when this succeeded
    }

    c.valid = true; // CPU is the core read; commit + disk degrade independently
    read_disks(c);
    return c;
}

} // namespace yuzu::agent::win

#else // !_WIN32 — the Windows state poller is the only driver of these reads

#include <ctime>

namespace yuzu::agent::win {

PerfBreachCounters read_perf_breach_counters() {
    PerfBreachCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    return c; // valid=false — never derives a sample, never breaches
}

} // namespace yuzu::agent::win

#endif
