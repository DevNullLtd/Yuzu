// tar_arp_collector.cpp — host ARP / neighbour-table enumeration for the TAR
// `arp` capture source (ADR-0015). The impure platform shell only: the snapshot
// is diffed in tar_diff.cpp (compute_arp_events) and persisted in tar_db.cpp
// (insert_arp_events). Follows the core capture-source pattern (no per-source
// header; types + decls in tar_collectors.hpp) — see docs/tar-implementer.md
// "Adding a capture source".
//
// Windows: GetIpNetTable2(AF_UNSPEC) over the kernel ARP + IPv6 neighbour cache.
// Linux: reads /proc/net/arp, parsed by tar_arp_parsers.hpp's
// parse_proc_net_arp(). macOS: reuses agents/shared/route_sysctl_arp.hpp's
// NET_RT_FLAGS/RTF_LLINFO sysctl fetch + parse (the same native mechanism
// discovery's scan_subnet already uses), mapped onto ArpEntry by this
// header's arp_entry_from_route_record().
//
// Completeness contract (mirrors tar_service_collector.cpp /
// tar_mapdrive_collector.cpp's subprocess-capture contract, tar_capture_status.hpp):
// all three platform legs THROW yuzu::tar::IncompleteCaptureError rather than
// returning a plain (possibly partial) vector when the read failed, the kernel/parser
// reported a truncated read, or the kArpEntryCap was reached before the
// whole table was consumed. A capped-or-partial vector is otherwise
// indistinguishable from a genuinely smaller neighbour table once it
// reaches the diff in tar_plugin.cpp -- diffing it against the last
// COMPLETE snapshot would fabricate durable false removed/appeared events.
// Every failure/truncation path still warns first (rate-limited where it
// repeats), so the operator sees the reason; the throw is what stops the
// partial result from being diffed and persisted as the new baseline.

#include "tar_arp_parsers.hpp"
#include "tar_capture_status.hpp" // yuzu::tar::IncompleteCaptureError, would_exceed_cap
#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <algorithm> // std::min (BR4-006 reserve cap)
#include <atomic> // rate-limited truncation warn
#include <cstddef> // std::size_t
#include <format>
#include <stdexcept> // yuzu::tar::IncompleteCaptureError derives from std::runtime_error
#include <string>
#include <utility> // std::move
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 / ConvertInterfaceLuidToAlias
#include "tar_win_raii_guards.hpp" // yuzu::tar::win_raii::MibTableGuard
#elif defined(__APPLE__)
#include <route_sysctl_arp.hpp> // agents/shared — fetch_rt_flags_llinfo / parse_rt_flags_llinfo
#include <span>
#else
#include <fstream> // /proc/net/arp read
#include <sstream>
#endif

namespace yuzu::tar {

#ifdef _WIN32

namespace {

std::string mac_to_string(const UCHAR* addr, ULONG len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    if (len == 0)
        return out; // incomplete entry — no hardware address yet
    out.reserve(len * 3 - 1);
    for (ULONG i = 0; i < len; ++i) {
        if (i)
            out += ':';
        out += kHex[addr[i] >> 4];
        out += kHex[addr[i] & 0x0F];
    }
    return out;
}

std::string sockaddr_inet_to_string(const SOCKADDR_INET& a) {
    char buf[INET6_ADDRSTRLEN]{};
    if (a.si_family == AF_INET)
        inet_ntop(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf));
    else if (a.si_family == AF_INET6)
        inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf));
    return buf;
}

// Map the Win32 NL_NEIGHBOR_STATE onto the published entry_type tokens
// (dynamic / static / incomplete / other) — see the ADR's $ARP_Live schema.
std::string entry_type_for_state(NL_NEIGHBOR_STATE st) {
    switch (st) {
    case NlnsPermanent:
        return "static";
    case NlnsReachable:
    case NlnsStale:
    case NlnsDelay:
    case NlnsProbe:
        return "dynamic";
    case NlnsIncomplete:
    case NlnsUnreachable:
        return "incomplete";
    default:
        return "other";
    }
}

std::string iface_alias(const NET_LUID& luid, NET_IFINDEX idx) {
    wchar_t alias[IF_MAX_STRING_SIZE + 1]{};
    if (ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) == NO_ERROR) {
        // (#1681) internal buffer -> shared -1 convert; keep the if<N> fallback for the
        // (unreachable) empty-conversion case to stay byte-identical to the pre-de-dup code.
        if (auto a = yuzu::win::from_wide(alias); !a.empty())
            return a;
    }
    return std::format("if{}", static_cast<unsigned long>(idx));
}

// RAII owner for the MIB_IPNET_TABLE2 allocation (round 3, B3-003): the loop
// below performs string/vector allocations (iface_alias's from_wide/format,
// sockaddr_inet_to_string, mac_to_string, out.push_back) between a successful
// GetIpNetTable2 and the table free -- a throwing allocation there used to
// skip the manual FreeMibTable(table) call entirely, leaking the table.
// Shared implementation in tar_win_raii_guards.hpp (injectable closer,
// unit-tested) -- also used by network_config_plugin.cpp's own copy.
using yuzu::tar::win_raii::MibTableGuard;

} // namespace

std::vector<ArpEntry> enumerate_arp() {
    std::vector<ArpEntry> out;

    PMIB_IPNET_TABLE2 table = nullptr;
    DWORD rc = GetIpNetTable2(AF_UNSPEC, &table);
    if (rc != NO_ERROR || table == nullptr) {
        spdlog::warn("TAR arp: GetIpNetTable2 failed (rc={}) -- skipping diff, retaining previous "
                     "baseline",
                     rc);
        throw yuzu::tar::IncompleteCaptureError(std::format("TAR: GetIpNetTable2 failed (rc={})", rc));
    }
    MibTableGuard table_guard{table}; // frees on every exit -- normal, cap throw, or a bad_alloc

    // BR4-006 (round 4): reserve only up to kArpEntryCap -- out will never
    // retain more than that regardless of how large the kernel's reported
    // NumEntries is (the would_exceed_cap loop below stops there), so
    // reserving the full kernel count needlessly risks a large allocation
    // (potential bad_alloc under memory pressure) for a bound the cap
    // already exists to enforce.
    out.reserve(std::min<std::size_t>(table->NumEntries, kArpEntryCap));
    bool truncated = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];
        ArpEntry e;
        e.iface = iface_alias(row.InterfaceLuid, row.InterfaceIndex);
        e.ip_address = sockaddr_inet_to_string(row.Address);
        e.mac_address = mac_to_string(row.PhysicalAddress, row.PhysicalAddressLength);
        e.entry_type = entry_type_for_state(row.State);
        if (e.ip_address.empty())
            continue; // address failed to format — skip defensively

        // Test capacity BEFORE appending (round 3, B3-004): the prior
        // check-AFTER-push shape appended the cap-th row, saw size == cap,
        // and declared the table truncated even when that row was the
        // table's LAST entry -- discarding an exact-cap-but-complete
        // snapshot forever. would_exceed_cap (tar_capture_status.hpp) is the
        // single shared decision every capped collector loop now applies.
        if (yuzu::tar::would_exceed_cap(out.size(), kArpEntryCap)) {
            truncated = true;
            break;
        }
        out.push_back(std::move(e));
    }

    // Rate-limit the truncation warn (UP-7): once when it begins, suppressed until
    // the table drops back under the cap.
    static std::atomic<bool> s_arp_cap_warned{false};
    if (truncated) {
        if (!s_arp_cap_warned.exchange(true))
            spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kArpEntryCap);
        // A capped table omits real neighbours -- indistinguishable from a
        // genuinely smaller one once diffed. Skip this tick's diff/state
        // advance entirely rather than diff/persist the truncated result
        // (BR-001/round 2): same contract as the failed-fetch path above.
        spdlog::warn("TAR arp: snapshot incomplete (entry cap reached) -- skipping diff, "
                     "retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError(
            std::format("TAR: arp entry cap {} reached", kArpEntryCap));
    }
    s_arp_cap_warned.store(false);
    return out;
}

#elif defined(__APPLE__) // macOS: reuse agents/shared/route_sysctl_arp.hpp

std::vector<ArpEntry> enumerate_arp() {
    const auto fetch = yuzu::shared::fetch_rt_flags_llinfo();
    if (!fetch.ok) {
        // ok=false is a FAILED sysctl read, not an empty table — same
        // distinction the Windows leg's GetIpNetTable2 failure warn above
        // preserves; throwing (rather than returning {}) is what stops this
        // failure from being diffed/persisted as a quiet, empty ARP table.
        spdlog::warn("TAR arp: NET_RT_FLAGS sysctl failed -- skipping diff, retaining previous "
                     "baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: NET_RT_FLAGS sysctl failed");
    }

    const auto parsed = yuzu::shared::parse_rt_flags_llinfo(std::span{fetch.blob});
    // classify_arp_collection + should_warn_ratelimited are pure and unit-
    // tested directly against fixture facts (tests/unit/test_tar_arp.cpp);
    // only the std::atomic latches below are impure.
    const auto status = classify_arp_collection(fetch.ok, parsed.truncated, parsed.records.size());

    // Rate-limit the partial-table warn, same pattern as the Windows leg's
    // cap warn below: once when it begins, suppressed until a subsequent
    // read comes back whole.
    static std::atomic<bool> s_arp_parse_truncated_warned{false};
    const bool was_parse_truncated_warned =
        s_arp_parse_truncated_warned.exchange(status.parse_truncated);
    if (should_warn_ratelimited(status.parse_truncated, was_parse_truncated_warned))
        spdlog::warn("TAR arp: NET_RT_FLAGS read returned a partial table (repeats "
                     "suppressed until it clears)");

    static std::atomic<bool> s_arp_cap_warned{false};
    const bool was_cap_warned = s_arp_cap_warned.exchange(status.capped);
    if (should_warn_ratelimited(status.capped, was_cap_warned))
        spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                     "clears)",
                     kArpEntryCap);

    // BR-001 (round 2): a kernel-truncated read OR an over-cap snapshot both
    // omit real neighbours -- either is indistinguishable from a genuinely
    // smaller table once diffed against the last COMPLETE baseline, and
    // would fabricate durable false removed/appeared events. Skip this
    // tick's diff/state advance entirely (the warns above already told the
    // operator why) rather than returning "the partial table is still
    // individually true" as before.
    if (status.parse_truncated || status.capped) {
        spdlog::warn("TAR arp: snapshot incomplete ({}) -- skipping diff, retaining previous "
                     "baseline",
                     status.parse_truncated ? "kernel-truncated read" : "entry cap reached");
        throw yuzu::tar::IncompleteCaptureError(
            status.parse_truncated ? "TAR: NET_RT_FLAGS read returned a partial table"
                                    : std::format("TAR: arp entry cap {} reached", kArpEntryCap));
    }

    std::vector<ArpEntry> out;
    out.reserve(parsed.records.size());
    for (const auto& rec : parsed.records)
        out.push_back(arp_entry_from_route_record(rec));
    return out;
}

#else // Linux: /proc/net/arp

std::vector<ArpEntry> enumerate_arp() {
    std::ifstream f("/proc/net/arp");
    if (!f) {
        // Parity with the Windows leg's GetIpNetTable2 failure warn above:
        // a read failure is reported, and throwing (not returning {}) is
        // what stops it from being diffed/persisted as a genuinely empty
        // table.
        spdlog::warn(
            "TAR arp: failed to read /proc/net/arp -- skipping diff, retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: failed to open /proc/net/arp");
    }
    std::ostringstream buf;
    buf << f.rdbuf();
    if (f.bad()) {
        // Parity with the discovery plugin's get_arp_table() (Linux leg,
        // discovery_plugin.cpp): a mid-stream read failure is a distinct
        // outcome from a genuinely empty table and must not feed a partial
        // snapshot into the diff as authoritative.
        spdlog::warn("TAR arp: read error mid-stream on /proc/net/arp -- skipping diff, retaining "
                     "previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: read error mid-stream on /proc/net/arp");
    }

    auto parsed = parse_proc_net_arp(buf.str(), kArpEntryCap);

    // BR4-005 (round 4): a malformed row is a missing binding relative to a
    // genuinely complete table -- diffing the surviving subset (parsed.entries
    // still holds every row around it, kept for this log line's diagnostics)
    // against the last COMPLETE snapshot would fabricate a false `removed`
    // event for it. Same collect-or-retain contract as the cap-truncation
    // throw just below.
    if (parsed.malformed) {
        spdlog::warn("TAR arp: malformed row in /proc/net/arp -- skipping diff, retaining "
                     "previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: malformed row in /proc/net/arp");
    }

    // Rate-limit the cap-truncation warn (UP-7), exactly mirroring the
    // Windows leg's s_arp_cap_warned pattern above: once when it begins,
    // reset once a subsequent read comes back under the cap.
    static std::atomic<bool> s_arp_cap_warned{false};
    if (parsed.truncated) {
        if (!s_arp_cap_warned.exchange(true))
            spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kArpEntryCap);
        // BR-001 (round 2): a capped table omits real neighbours -- diffing
        // it against the last COMPLETE snapshot would fabricate durable
        // false removed/appeared events. Skip this tick's diff/state
        // advance entirely instead of returning the truncated result.
        spdlog::warn("TAR arp: snapshot incomplete (entry cap reached) -- skipping diff, "
                     "retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError(std::format("TAR: arp entry cap {} reached", kArpEntryCap));
    }
    s_arp_cap_warned.store(false);

    return std::move(parsed.entries);
}

#endif

} // namespace yuzu::tar
