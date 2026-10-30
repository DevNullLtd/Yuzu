#pragma once

/**
 * echo_netqual.hpp — pure, cross-platform helpers for the per-connection TCP
 * quality (netqual) warehouse tier of the /network dashboard (BRD Workstream E).
 *
 * The platform collector (Linux: netlink INET_DIAG TCP_INFO, in
 * echo_network_collector.cpp) yields raw TcpQualitySample records carrying the
 * RAW remote address. These header-inline helpers turn those into persistable
 * NetQualRow records:
 *   - remote_bucket()      — classify the destination into a coarse, privacy-safe
 *                            CLASS so the raw address never reaches the warehouse;
 *   - select_netqual_rows()— apply the bucket + a per-tick top-N cap that keeps
 *                            the MOST-DEGRADED connections first.
 *
 * Both are pure (no I/O, no platform headers) so they compile + unit-test on
 * every host, matching the net_quality_sampler header-inline-helpers pattern.
 *
 * SIGNAL DISCIPLINE (see NetQualRow in echo_db.hpp): `lost` is the CURRENT-loss
 * gauge (tcpi_lost) and the only field that moves with current conditions;
 * `retrans`/`segs_out` are lifetime-cumulative CONTEXT only — never build a
 * "current loss" signal from their ratio (it is diluted by historical clean
 * segments, which is exactly why the device-aggregate signal was disproven).
 *
 * Windows (ESTATS — ADR-0020) diverges in three documented ways:
 *   - `lost` is the per-tick DELTA of Path.PktsRetrans (wrap-clamped >= 0);
 *     Windows exposes no instantaneous lost-segment gauge, and the delta is
 *     the closest moves-with-current-conditions analogue.
 *   - `retrans`/`segs_out` count since STATS-ENABLE (the first tick the
 *     collector saw the connection), not since connection start.
 *   - `ca_state` is SYNTHESIZED from Path deltas (nq_win_ca_state below);
 *     `rtt_us`/`rtt_var_us` are ms-resolution scaled to µs (a sub-ms LAN RTT
 *     reads as 0).
 */

#include "echo_db.hpp" // NetQualRow

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility> // std::move (nq_win_build_sample)
#include <vector>

namespace yuzu::echo {

/// Raw per-connection TCP quality observation from the platform collector.
/// Carries the RAW remote address — it is the INPUT to select_netqual_rows,
/// which buckets it away. The raw address MUST NOT be persisted: only
/// remote_bucket leaves the builder.
struct TcpQualitySample {
    std::string proto;        ///< tcp, tcp6
    std::string remote_addr;  ///< raw — bucketed by the builder, never stored
    std::string process_name; ///< owning process image name (may be kernel-truncated)
    int64_t rtt_us{0};        ///< smoothed RTT (tcpi_rtt)
    int64_t rtt_var_us{0};    ///< RTT variance / jitter (tcpi_rttvar)
    int64_t lost{0};          ///< CURRENT lost segments (tcpi_lost) — instantaneous degraded driver
    int64_t retrans{0};       ///< lifetime retransmits (tcpi_total_retrans) — context
    int64_t segs_out{0};      ///< lifetime segments out (tcpi_segs_out) — context
    int64_t ca_state{0};      ///< tcpi_ca_state (0=Open..4=Loss) — holds across a recovery episode
};

/// Default per-tick top-N connection cap. The real cardinality bound (the
/// warehouse can't explode on a box opening thousands of connections); the
/// schema's row-count retention is the storage backstop behind it.
inline constexpr std::size_t kNetQualTopN = 50;

/// Classify a remote address into a coarse, privacy-safe destination CLASS:
/// "loopback" | "private" | "public" | "unknown". String-prefix only (no socket
/// headers) so it is header-safe and testable cross-platform. VPN-ness is
/// interface-derived, not address-derived, so it is deliberately NOT a class
/// here — a later slice that has interface context can add it.
inline std::string remote_bucket(const std::string& addr) {
    if (addr.empty() || addr == "*")
        return "unknown";

    // IPv6 (any colon).
    if (addr.find(':') != std::string::npos) {
        if (addr == "::1")
            return "loopback";
        // IPv4-mapped (::ffff:a.b.c.d) — classify by the embedded v4 so an
        // internal dual-stack peer isn't mislabelled "public". inet_ntop emits
        // lowercase, but accept either case defensively.
        if (addr.starts_with("::ffff:") || addr.starts_with("::FFFF:"))
            return remote_bucket(addr.substr(7));
        // link-local fe80::/10 (fe80–febf) and unique-local fc00::/7 (fc/fd).
        if (addr.starts_with("fe8") || addr.starts_with("fe9") ||
            addr.starts_with("fea") || addr.starts_with("feb") ||
            addr.starts_with("fc") || addr.starts_with("fd"))
            return "private";
        return "public";
    }

    // IPv4.
    if (addr.starts_with("127."))
        return "loopback";
    if (addr.starts_with("10.") || addr.starts_with("192.168.") ||
        addr.starts_with("169.254.")) // RFC1918 + link-local
        return "private";
    // Ranges keyed on the 2nd octet: 172.16–31 (RFC1918 /12) and
    // 100.64–127 (RFC6598 carrier-grade NAT shared space — internal, not public).
    const auto second_octet = [&](int lo, int hi) -> bool {
        const auto d1 = addr.find('.');
        const auto d2 = addr.find('.', d1 + 1);
        if (d2 == std::string::npos || d2 <= d1 + 1)
            return false;
        int oct = 0;
        for (auto i = d1 + 1; i < d2; ++i) {
            if (addr[i] < '0' || addr[i] > '9')
                return false;
            oct = oct * 10 + (addr[i] - '0');
        }
        return oct >= lo && oct <= hi;
    };
    if (addr.starts_with("172.") && second_octet(16, 31))
        return "private";
    if (addr.starts_with("100.") && second_octet(64, 127))
        return "private";
    return "public";
}

/// PURE: turn raw quality samples into persistable rows. Applies the privacy
/// bucket (DROPS the raw address) and a per-tick top-N cap that keeps the
/// MOST-DEGRADED connections first — highest current loss, then most active
/// (segs_out) — so a losing connection is never dropped in favour of an idle
/// one. `cap == 0` means no cap. Order within the cap is degraded-first.
inline std::vector<NetQualRow> select_netqual_rows(const std::vector<TcpQualitySample>& samples,
                                                   int64_t ts, int64_t snapshot_id,
                                                   std::size_t cap) {
    std::vector<const TcpQualitySample*> ordered;
    ordered.reserve(samples.size());
    for (const auto& s : samples)
        ordered.push_back(&s);
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const TcpQualitySample* a, const TcpQualitySample* b) {
                         if (a->lost != b->lost)
                             return a->lost > b->lost;       // current loss first
                         return a->segs_out > b->segs_out;   // then most active
                     });
    if (cap > 0 && ordered.size() > cap)
        ordered.resize(cap);

    std::vector<NetQualRow> rows;
    rows.reserve(ordered.size());
    for (const auto* s : ordered) {
        NetQualRow r;
        r.ts = ts;
        r.snapshot_id = snapshot_id;
        r.proto = s->proto;
        r.remote_bucket = remote_bucket(s->remote_addr); // privacy: raw addr dropped here
        r.process_name = s->process_name;
        r.rtt_us = s->rtt_us;
        r.rtt_var_us = s->rtt_var_us;
        r.lost = s->lost;
        r.retrans = s->retrans;
        r.segs_out = s->segs_out;
        r.ca_state = s->ca_state;
        rows.push_back(std::move(r));
    }
    return rows;
}

// ── Windows ESTATS derivation (pure — the platform reads stay in the collector) ──

/// PURE: build the g_nq_tracked key for a v6 connection. The scope IDs are
/// LOAD-BEARING: two link-local connections can share the same textual
/// address+port and differ only by zone (dwLocalScopeId / dwRemoteScopeId) —
/// which the MIB_TCP6ROW the collector builds also requires — so a key without
/// them would collide and attribute one connection's RTT/retransmit deltas to
/// the other. Kept pure + header-inline so the distinctness is unit-testable
/// cross-platform.
inline std::string nq_v6_key(std::string_view laddr, std::uint32_t lscope, int lport,
                             std::string_view raddr, std::uint32_t rscope, int rport) {
    return std::format("tcp6|{}%{}:{}|{}%{}:{}", laddr, lscope, lport, raddr, rscope, rport);
}

/// PURE: build the g_nq_tracked key for a v4 connection (no scope id in IPv4).
inline std::string nq_v4_key(std::string_view laddr, int lport, std::string_view raddr,
                             int rport) {
    return std::format("tcp|{}:{}|{}:{}", laddr, lport, raddr, rport);
}

/// One tick's raw Windows ESTATS counters for a connection, cumulative since
/// stats-enable (TCP_ESTATS_PATH_ROD_v0 + TCP_ESTATS_DATA_ROD_v0), copied into
/// plain integers so the derivation below stays header-pure and unit-testable
/// off Windows. RTT fields are ESTATS-native MILLISECONDS.
struct NqWinCounters {
    int64_t smoothed_rtt_ms{0};
    int64_t rtt_var_ms{0};
    int64_t pkts_retrans{0};
    int64_t timeouts{0};
    int64_t fast_retran{0};
    int64_t dup_acks_in{0};
    int64_t ecn_signals{0};
    int64_t cur_timeout_count{0}; ///< instantaneous (not cumulative)
    int64_t segs_out{0};
};

/// Per-tick deltas of the Path counters (wrap-clamped >= 0), the input to
/// nq_win_ca_state. cur_timeout_count is carried as-is: it is a live gauge of
/// outstanding RTO episodes, not a counter.
struct NqPathDeltas {
    int64_t timeouts{0};
    int64_t fast_retran{0};
    int64_t pkts_retrans{0};
    int64_t dup_acks_in{0};
    int64_t ecn_signals{0};
    int64_t cur_timeout_count{0};
};

/// Counter delta clamped at zero: ESTATS Path counters are 32-bit and another
/// ESTATS consumer disabling/re-enabling collection can reset them, so a
/// negative delta means "unknown this tick", never a real value.
inline int64_t nq_delta_clamped(int64_t cur, int64_t prev) {
    const int64_t d = cur - prev;
    return d < 0 ? 0 : d;
}

/// Synthesize a Linux tcpi_ca_state analogue (0=Open .. 4=Loss) from one tick's
/// Path deltas. Precedence mirrors severity: an RTO episode (in progress or
/// completed this tick) is Loss; any retransmission activity is Recovery; ECN
/// congestion signals are CWR; duplicate ACKs alone are Disorder; else Open.
inline int64_t nq_win_ca_state(const NqPathDeltas& d) {
    if (d.cur_timeout_count > 0 || d.timeouts > 0)
        return 4; // Loss
    if (d.fast_retran > 0 || d.pkts_retrans > 0)
        return 3; // Recovery
    if (d.ecn_signals > 0)
        return 2; // CWR
    if (d.dup_acks_in > 0)
        return 1; // Disorder
    return 0;     // Open
}

/// PURE: derive a TcpQualitySample from this tick's ESTATS counters and the
/// previous tick's (both cumulative since stats-enable). Applies the Windows
/// semantics documented in the header comment: µs scaling, delta-based `lost`,
/// synthesized `ca_state`. The collector calls this only for connections with a
/// previous baseline — the enable tick emits nothing (RODs are undefined until
/// collection is on, and a since-enable delta needs two reads).
inline TcpQualitySample nq_win_build_sample(const NqWinCounters& cur, const NqWinCounters& prev,
                                            std::string proto, std::string remote_addr,
                                            std::string process_name) {
    NqPathDeltas d;
    d.timeouts = nq_delta_clamped(cur.timeouts, prev.timeouts);
    d.fast_retran = nq_delta_clamped(cur.fast_retran, prev.fast_retran);
    d.pkts_retrans = nq_delta_clamped(cur.pkts_retrans, prev.pkts_retrans);
    d.dup_acks_in = nq_delta_clamped(cur.dup_acks_in, prev.dup_acks_in);
    d.ecn_signals = nq_delta_clamped(cur.ecn_signals, prev.ecn_signals);
    d.cur_timeout_count = cur.cur_timeout_count;

    TcpQualitySample s;
    s.proto = std::move(proto);
    s.remote_addr = std::move(remote_addr);
    s.process_name = std::move(process_name);
    s.rtt_us = cur.smoothed_rtt_ms * 1000; // ESTATS Path is ms; the schema is µs
    s.rtt_var_us = cur.rtt_var_ms * 1000;
    s.lost = d.pkts_retrans;      // current-conditions gauge (see SIGNAL DISCIPLINE)
    s.retrans = cur.pkts_retrans; // cumulative since stats-enable — context
    s.segs_out = cur.segs_out;    // cumulative since stats-enable — context
    s.ca_state = nq_win_ca_state(d);
    return s;
}

} // namespace yuzu::echo
