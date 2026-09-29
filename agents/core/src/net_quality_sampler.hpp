#pragma once

/// @file net_quality_sampler.hpp
/// Device-level NETWORK-QUALITY sampler for the heartbeat (slice 4a of the
/// /network dashboard). The agent has no /metrics endpoint, so these thin,
/// fixed-cardinality facts are the ONLY channel by which the fleet network
/// gauges + the /network Overview cards exist (mirrors the yuzu.perf_* path).
///
/// Linux: per-connection smoothed RTT + retransmits via netlink SOCK_DIAG /
/// INET_DIAG (the same interface `ss -ti` uses — no packet capture, no
/// elevation: a non-root agent sees system TCP_INFO), rolled up to a device
/// p50 RTT + aggregate retransmit ratio; throughput from /proc/net/dev deltas.
/// Windows: device throughput via GetIfTable2 (non-loopback 64-bit octets) +
/// a system-wide TCP retransmit rate via GetTcpStatisticsEx (ΔΣretrans/ΔΣsegs
/// across heartbeats). RTT is omitted on Windows in v1 — per-connection smoothed
/// RTT needs ESTATS (GetPerTcpConnectionEStats: enable + admin + overhead), a
/// deferred slice. NOTE the Windows retransmit MIB is whole-stack (includes
/// loopback) and is measurement-first UNVALIDATED on Windows (the netem
/// separation test was Linux-only).
/// macOS: THROUGHPUT ONLY in v1 — device throughput via a bounds-checked
/// NET_RT_IFLIST2 routing-socket interface walk (non-loopback if_data64
/// 64-bit octets, same coarse aggregate as Linux/Windows). Retransmit is
/// DEFERRED: the global net.inet.tcp.stats OID (the only system-wide source)
/// returns an all-zero struct on current macOS, so it cannot back a
/// retransmit metric — a per-flow source (the NetworkStatistics/nstat client)
/// is the roadmap 2.x follow-up. RTT is deferred as on Windows. Both tags stay
/// absent on macOS in v1 — never shipped as zero.
///
/// THE EDGE SHIPS FACTS, NEVER A VERDICT. The retransmit fact is an INTERVAL
/// rate — ΔΣretrans / ΔΣsegs across heartbeats, smoothed over a short window —
/// NOT the connections' absolute lifetime ratio. The lifetime ratio is diluted
/// to noise by historical clean segments (empirically: 30% real loss moved it
/// 0.14%→0.37%); the interval delta cleanly recovers the real rate (4% loss →
/// 3.8%). The sampler therefore exposes raw cumulative Σretrans/Σsegs and the
/// agent differences them across heartbeats (see RetransWindow). This is a
/// device / LOCAL-LINK health measurement (a bad local link degrades every
/// path); it deliberately carries NO `degraded` verdict and NO per-destination
/// data — a hard degraded threshold needs real-fleet baseline calibration (a
/// later slice), and localization is the deferred per-destination warehouse
/// drill. Measurement-first: ship the rate, classify later.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <yuzu/plugin.h>  // YUZU_EXPORT

namespace yuzu::agent::netq {

/// Interface byte counters for the throughput delta (kept across heartbeats).
struct NetCounters {
    bool valid{false};
    uint64_t rx_bytes{0};
    uint64_t tx_bytes{0};
    std::chrono::steady_clock::time_point at{};
};

/// The thin device-level sample shipped on the heartbeat. Each metric carries
/// its own validity — a domain whose read failed is OMITTED, never shipped as 0.
/// `retrans_total`/`segs_out_total` are RAW cumulative device sums (not a rate);
/// the agent differences them across heartbeats (RetransWindow) to derive the
/// interval retransmit rate — a single sample is not enough to ship a rate.
struct NetQualitySample {
    bool rtt_valid{false};
    double rtt_p50_ms{0.0};
    bool retrans_valid{false};      ///< device retransmit COUNTERS present this cycle
    uint64_t retrans_total{0};      ///< Σ tcpi_total_retrans across active TCP conns (cumulative)
    uint64_t segs_out_total{0};     ///< Σ tcpi_segs_out across active TCP conns (cumulative)
    bool throughput_valid{false};
    double throughput_bps{0.0};     ///< device rx+tx bytes/s, non-loopback
};

/// Heartbeats of smoothing for the interval retransmit rate. ~6 keeps a single
/// noisy interval (a burst, or a connection closing) from swinging the device
/// rate, without lagging a genuinely-degrading link by more than a few cycles.
inline constexpr std::size_t kNetRetransWindow = 6;

/// Bounded ring of raw cumulative (Σretrans, Σsegs) readings — one per heartbeat
/// the sampler reported retransmit counters. The windowed delta over the
/// retained span is the heartbeat's `yuzu.net_retrans_pct`. Header-inline so it
/// links into tests without DLL export (matching the other pure helpers here).
///
/// SIGNAL DISCIPLINE: the rate is the INTERVAL delta, never the absolute ratio.
/// Per-interval Δs are CLAMPED at zero so a connection CLOSING (high-retrans conn
/// drops out → Σ falls → negative Δ) can never read as negative loss — that
/// interval simply contributes nothing. On a LOW-CHURN box (the v1 target —
/// servers, long-lived connections) the device-wide aggregate tracks the real
/// loss rate cleanly (validated on Colin: 0% → ~0, 4% → 3.8%, not diluted by
/// clean idle connections, since Δsegs counts mostly this-interval traffic).
/// KNOWN LIMITATION: a connection APPEARING injects its whole lifetime
/// retrans+segs into one interval's Σ, so on a HIGH-CHURN box (thousands of
/// short connections) the rate is noisier — acceptable for measurement-first v1,
/// revisit if the deferred classification needs high-churn robustness.
struct RetransWindow {
    struct Reading {
        uint64_t retrans_total{0};
        uint64_t segs_out_total{0};
    };
    std::vector<Reading> readings;
    std::size_t cap{kNetRetransWindow};

    explicit RetransWindow(std::size_t k = kNetRetransWindow) : cap(k == 0 ? 1 : k) {}

    void push(uint64_t retrans_total, uint64_t segs_out_total) {
        readings.push_back({retrans_total, segs_out_total});
        if (readings.size() > cap)
            readings.erase(readings.begin());
    }

    /// Smoothed, churn-robust interval retransmit ratio (percent) over the
    /// window. nullopt until ≥2 readings, or when no segments advanced across
    /// the window (idle device / churn-only) — absent, never a fabricated 0.
    [[nodiscard]] std::optional<double> rate_pct() const {
        if (readings.size() < 2)
            return std::nullopt;
        uint64_t dretr = 0, dsegs = 0;
        for (std::size_t i = 1; i < readings.size(); ++i) {
            if (readings[i].retrans_total > readings[i - 1].retrans_total)
                dretr += readings[i].retrans_total - readings[i - 1].retrans_total;
            if (readings[i].segs_out_total > readings[i - 1].segs_out_total)
                dsegs += readings[i].segs_out_total - readings[i - 1].segs_out_total;
        }
        if (dsegs == 0)
            return std::nullopt;
        return 100.0 * static_cast<double>(dretr) / static_cast<double>(dsegs);
    }
};

/// Read current non-loopback interface byte counters (Linux: /proc/net/dev;
/// Windows: GetIfTable2; macOS: NET_RT_IFLIST2).
/// Returns invalid on unsupported platforms or on read failure.
YUZU_EXPORT NetCounters read_net_counters();

/// Produce the heartbeat sample. Linux: a one-shot INET_DIAG dump for rtt/retrans
/// + throughput from prev/cur counters. Windows: throughput from prev/cur +
/// system-wide TCP retransmit counters (no rtt). macOS: throughput from
/// prev/cur only — retransmit + RTT deferred (see the header doc above).
/// `prev` invalid (first heartbeat) → throughput omitted this cycle. Other
/// platforms → all-invalid. Called only from the heartbeat thread; all state
/// is local or caller-owned (no shared state).
YUZU_EXPORT NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur);

// ── Pure helpers (header-inline so they link into tests without DLL export,
//    matching the dex_perf_breach pattern) ───────────────────────────────────

/// Median of a value list (middle element). Empty → nullopt.
inline std::optional<double> median(std::vector<double> v) {
    if (v.empty())
        return std::nullopt;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2]; // deterministic; robust to the RTT outliers `ss` shows
}

/// Throughput in bytes/s from two counter reads. nullopt unless both valid and
/// the interval is positive; counter wrap (cur < prev) yields nullopt, not a
/// negative/huge rate.
inline std::optional<double> throughput_bps(const NetCounters& prev, const NetCounters& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.rx_bytes < prev.rx_bytes || cur.tx_bytes < prev.tx_bytes)
        return std::nullopt; // counter wrap/reset — drop the sample, never a bogus rate
    const double secs = std::chrono::duration<double>(cur.at - prev.at).count();
    if (secs <= 0.0)
        return std::nullopt;
    const double bytes =
        static_cast<double>((cur.rx_bytes - prev.rx_bytes) + (cur.tx_bytes - prev.tx_bytes));
    return bytes / secs;
}

} // namespace yuzu::agent::netq
