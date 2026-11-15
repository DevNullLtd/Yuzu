/**
 * echo_netqual_boot.cpp — since-boot network-quality baseline (ADR-0020).
 *
 * See echo_netqual_boot.hpp. Counter-read shapes mirror
 * agents/core/src/net_quality_sampler.cpp (the device heartbeat sampler):
 * GetTcpStatisticsEx[2] per address family, GetIfTable2 summed over
 * non-loopback interfaces with FreeMibTable RAII.
 */

#include "echo_netqual_boot.hpp"

#ifdef _WIN32

#include "echo_proc_etw.hpp" // boot_time_unix() — shared per-boot dedup anchor

#include <spdlog/spdlog.h>

// clang-format off
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h> // must precede windows.h; netioapi.h needs its typedefs + AF_INET*
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h> // GetTcpStatisticsEx[2] / MIB_TCPSTATS[2]
#include <netioapi.h> // GetIfTable2 / MIB_IF_TABLE2 / FreeMibTable (64-bit octets)
// clang-format on

namespace yuzu::echo {

namespace {

// RAII for GetIfTable2's heap allocation (single-owner, mirrors the
// net_quality_sampler MibIfTableGuard).
struct MibIfTableGuard {
    MIB_IF_TABLE2* t{nullptr};
    MibIfTableGuard() = default;
    MibIfTableGuard(const MibIfTableGuard&) = delete;
    MibIfTableGuard& operator=(const MibIfTableGuard&) = delete;
    ~MibIfTableGuard() {
        if (t)
            ::FreeMibTable(t);
    }
};

struct TcpTotals {
    std::int64_t retrans_segs{0};
    std::int64_t segs_out{0};
    std::int64_t estab_resets{0};
    bool valid{false};
};

/// Sum the since-boot TCP MIB over IPv4 + IPv6. Prefers GetTcpStatisticsEx2
/// (1709+, 64-bit dw64OutSegs — the 32-bit dwOutSegs wraps in hours on fast
/// links), resolved dynamically so echo.dll carries no hard import that would
/// stop it LOADING on an older Win10. dwRetransSegs is 32-bit even in the Ex2
/// struct (SDK header, not the doc page, is authoritative) — acceptable for a
/// coarse baseline; the row is context, not a gauge.
TcpTotals read_tcp_totals() {
    TcpTotals t;
    using Ex2Fn = ULONG(WINAPI*)(PMIB_TCPSTATS2, ULONG);
    static const Ex2Fn ex2 = []() -> Ex2Fn {
        HMODULE m = ::GetModuleHandleW(L"iphlpapi.dll");
        if (!m)
            m = ::LoadLibraryW(L"iphlpapi.dll");
        return m ? reinterpret_cast<Ex2Fn>(
                       ::GetProcAddress(m, "GetTcpStatisticsEx2"))
                 : nullptr;
    }();

    for (ULONG family : {static_cast<ULONG>(AF_INET), static_cast<ULONG>(AF_INET6)}) {
        if (ex2) {
            MIB_TCPSTATS2 s{};
            if (ex2(&s, family) != NO_ERROR)
                continue;
            t.retrans_segs += s.dwRetransSegs;
            t.segs_out += static_cast<std::int64_t>(s.dw64OutSegs);
            t.estab_resets += s.dwEstabResets;
            t.valid = true;
        } else {
            MIB_TCPSTATS s{};
            if (::GetTcpStatisticsEx(&s, family) != NO_ERROR)
                continue;
            t.retrans_segs += s.dwRetransSegs;
            t.segs_out += s.dwOutSegs; // 32-bit — wrap possible on long uptimes
            t.estab_resets += s.dwEstabResets;
            t.valid = true;
        }
    }
    return t;
}

} // namespace

std::optional<NetQualBootRow> collect_netqual_boot(std::int64_t now_ts) {
    const TcpTotals tcp = read_tcp_totals();
    if (!tcp.valid) {
        // Both GetTcpStatisticsEx2/Ex failed for both families — unexpected on a
        // live Windows host. Surface it rather than silently recording no boot
        // baseline (the caller only sees nullopt, which off-Windows is normal).
        spdlog::warn("Echo netqual: since-boot TCP statistics unavailable — "
                     "no boot baseline recorded this boot");
        return std::nullopt;
    }

    NetQualBootRow row;
    row.ts = now_ts;
    row.boot_ts = boot_time_unix();
    row.window_s = (row.boot_ts > 0 && now_ts > row.boot_ts) ? now_ts - row.boot_ts : 0;
    row.retrans_segs = tcp.retrans_segs;
    row.segs_out = tcp.segs_out;
    row.estab_resets = tcp.estab_resets;

    // Interface error/discard/octet totals (all ULONG64 — no wrap concern).
    // Best-effort: a GetIfTable2 failure leaves the interface columns 0 rather
    // than dropping the TCP baseline.
    MibIfTableGuard g;
    if (::GetIfTable2(&g.t) == NO_ERROR && g.t) {
        for (ULONG i = 0; i < g.t->NumEntries; ++i) {
            const MIB_IF_ROW2& r = g.t->Table[i];
            if (r.Type == IF_TYPE_SOFTWARE_LOOPBACK)
                continue;
            row.if_in_errors += static_cast<std::int64_t>(r.InErrors);
            row.if_in_discards += static_cast<std::int64_t>(r.InDiscards);
            row.if_out_errors += static_cast<std::int64_t>(r.OutErrors);
            row.if_out_discards += static_cast<std::int64_t>(r.OutDiscards);
            row.if_in_octets += static_cast<std::int64_t>(r.InOctets);
            row.if_out_octets += static_cast<std::int64_t>(r.OutOctets);
        }
    }
    return row;
}

} // namespace yuzu::echo

#else // !_WIN32

namespace yuzu::echo {

// Linux/macOS boot baselines are a follow-up (Linux: /proc/net/snmp Tcp:
// RetransSegs/OutSegs since boot — same shape).
std::optional<NetQualBootRow> collect_netqual_boot(std::int64_t) { return std::nullopt; }

} // namespace yuzu::echo

#endif
