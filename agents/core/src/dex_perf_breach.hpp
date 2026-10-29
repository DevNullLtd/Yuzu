#pragma once

/**
 * dex_perf_breach.hpp — sustained performance-breach detection (BRD A3,
 * docs/dex-brd-coverage.md rows 13–15, 124).
 *
 * The A1 Echo perf warehouse is HISTORY (every 30 s sample, on-device, raw-SQL
 * queryable); this module is ALERTS: the Windows state poller samples a minimal
 * counter set on a slow cadence and emits a ruleless DEX observation when a
 * metric stays bad for a sustained window — `perf.cpu_sustained`,
 * `perf.memory_pressure`, `perf.disk_latency_high`. Detection lives here in
 * agent core, NOT the Echo plugin: plugins have no path to the Guardian
 * observation sink, and sustained-condition semantics are exactly the
 * dex_win_poll poll-and-latch shape (see memory project-dex-brd-delivery).
 *
 * Emission is bounded by construction, no rate cap needed: a breach needs
 * `sustain` consecutive bad samples to fire once, then re-arms only after
 * `recover` consecutive VALID samples below the EXIT threshold (hysteresis —
 * a metric flapping at the enter threshold cannot re-fire), so the worst case
 * is one observation per type per (sustain + recover) samples (~4/h/type at
 * the 120 s cadence). Thresholds are hardcoded sane defaults until F1 makes
 * them operator-tunable (the D3 blast-radius precedent).
 *
 * The counter derivations mirror echo_perf.cpp (the A1 reference
 * implementation) but read only the three breach metrics; the two stay
 * separate because agent core must not compile plugin sources. Pure functions
 * compile and unit-test on every host; the Win32 reads (GetSystemTimes,
 * GetPerformanceInfo, IOCTL_DISK_PERFORMANCE — no PDH, no WMI, no shell-out)
 * live behind read_perf_breach_counters() in the _WIN32 section of the .cpp.
 * windows.h-free and proto-free by design (the dex_observer.hpp rationale).
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <cstdint>
#include <optional>

namespace yuzu::agent::win {

/// One instant's raw counters — the minimal set breach detection needs.
/// CPU and disk are CUMULATIVE since boot; commit charge is instantaneous.
/// `valid` covers the CPU core read; `commit_valid` and `disk_valid` are
/// PER-DOMAIN because GetPerformanceInfo (commit) and IOCTL_DISK_PERFORMANCE
/// (disk) can each fail independently of GetSystemTimes — mirrors the echo_perf
/// contract. A failed sub-read must NOT feed a healthy 0% into its latch (that
/// would clear a real breach / reset a building one — gov review MEDIUM #1).
struct PerfBreachCounters {
    bool valid{false};
    bool commit_valid{false};
    bool disk_valid{false};
    std::int64_t ts_epoch{0};

    // CPU, 100 ns units, summed across cores. kernel INCLUDES idle
    // (GetSystemTimes contract).
    std::uint64_t cpu_idle{0};
    std::uint64_t cpu_kernel{0};
    std::uint64_t cpu_user{0};

    // Commit charge, instantaneous, bytes. Valid only when GetPerformanceInfo
    // succeeded (commit_valid) — an intermittent failure must not masquerade as
    // a healthy 0% and defeat the memory latch.
    std::uint64_t commit_total_bytes{0};
    std::uint64_t commit_limit_bytes{0};

    // Disk, cumulative, summed across physical disks.
    std::uint64_t disk_read_time_100ns{0};
    std::uint64_t disk_write_time_100ns{0};
    std::uint64_t disk_reads{0};
    std::uint64_t disk_writes{0};
};

/// One derived breach sample. `disk_lat_ms` is the combined read+write per-IO
/// service time over the interval; an interval with zero IOs derives 0 — an
/// idle disk is a healthy disk, not a slow one.
struct PerfBreachSample {
    bool valid{false};        ///< CPU domain valid (the sample as a whole)
    bool commit_valid{false}; ///< commit_pct trustworthy (GetPerformanceInfo ok)
    bool disk_valid{false};   ///< disk_lat_ms trustworthy (IOCTL_DISK_PERFORMANCE ok)
    double cpu_pct{0.0};
    double commit_pct{0.0};
    double disk_lat_ms{0.0};
};

/// PURE: derive one sample from two counter readings. Invalid when either
/// reading is invalid, elapsed <= 0, or a CPU counter regressed (reboot /
/// counter reset — rates from a regressed baseline would be garbage). A disk
/// counter regression (hotplug/reset) invalidates only the disk domain for
/// one interval via the saturating delta — mirrors echo_perf::derive_sample.
YUZU_EXPORT PerfBreachSample derive_breach_sample(const PerfBreachCounters& prev,
                                                  const PerfBreachCounters& cur);

/// Sustained-breach hysteresis parameters for one metric.
struct BreachParams {
    double enter;  ///< sample is "bad" at value >= enter
    double exit;   ///< recovery requires value < exit (exit < enter — hysteresis)
    int sustain;   ///< consecutive bad samples required to emit
    int recover;   ///< consecutive valid healthy samples required to re-arm
};

/// Per-metric latch state. Value-initialised = armed and healthy.
struct BreachState {
    int bad_streak{0};
    int good_streak{0};
    double sum{0.0};    ///< running sum over the current bad streak (for the avg)
    bool reported{false};
};

/// PURE: feed one sample into the latch. Returns the breach-window average
/// exactly on the transition into sustained-bad (emit once), nullopt otherwise.
/// While reported, samples below `exit` build the recovery streak; a sample at
/// or above `exit` resets it. An INVALID sample resets both streaks but never
/// clears the latch — a transient read failure must not re-fire a breach
/// (the dex_win_poll UP-5 lesson), and a sustained claim must not span gaps.
YUZU_EXPORT std::optional<double> breach_update(BreachState& st, double value, bool valid,
                                                const BreachParams& p);

// ── Tuning (hardcoded sane defaults until F1) ────────────────────────────────

/// Sample cadence in the state poller. 120 s halves the wake cost of a 60 s
/// tick for identical detection latency — sustained detection wants the
/// window, not the resolution (be kind to the endpoint).
inline constexpr std::int64_t kPerfSampleIntervalSeconds = 120;

inline constexpr BreachParams kCpuBreach{90.0, 70.0, 5, 3};     // % busy
inline constexpr BreachParams kMemoryBreach{90.0, 80.0, 5, 3};  // % of commit limit
inline constexpr BreachParams kDiskLatBreach{25.0, 15.0, 5, 3}; // ms per IO

// ── Observation builders (uniform detail_json keys, like the D1 signals) ────

/// `perf.cpu_sustained` — subject "cpu", metric = breach-window avg busy %.
YUZU_EXPORT SignalObservation cpu_sustained_observation(double avg_pct);

/// `perf.memory_pressure` — subject "memory", metric = avg commit % of limit.
/// Commit charge, not physical-RAM %, is the pressure signal: high physical
/// use is normal caching; commit near the limit means allocations start
/// failing (pagefile exhaustion / OOM).
YUZU_EXPORT SignalObservation memory_pressure_observation(double avg_pct);

/// `perf.disk_latency_high` — subject "disk", metric = avg ms per IO.
YUZU_EXPORT SignalObservation disk_latency_observation(double avg_ms);

/// Impure shell: read the current counters. valid=false off Windows (the
/// poller that drives this is Windows-only; macOS has its own collector).
YUZU_EXPORT PerfBreachCounters read_perf_breach_counters();

} // namespace yuzu::agent::win
