/**
 * network_config_routes_win.cpp — Windows leg of `routes`: GetIpForwardTable2
 * (IP Helper, rung 1, IPv4 and IPv6 in one call), unpacked here and reduced by the
 * portable win_route_to_row() / win_route_is_host_local() in
 * network_config_routes_parsers.hpp.
 *
 * Same call family as the arp leg's GetIpNetTable2 (network_config_plugin.cpp), the
 * same kernel-table RAII owner shape (FreeMibTable on every exit, non-copyable) and
 * the same row cap, applied AFTER the host-local filter so a normal workstation's
 * per-interface multicast/broadcast rows never count against it.
 *
 * The route `Metric` is the ROUTE metric only. Windows adds the interface metric to
 * it when ranking routes, and that sum is not reported here (the README says so).
 */
#include "network_config_routes_legs.hpp"

#if defined(_WIN32)

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
#include <netioapi.h> // GetIpForwardTable2 / MIB_IPFORWARD_ROW2 / ConvertInterfaceLuidToAlias

#include <win_str.hpp> // yuzu::win::from_wide (#1681)

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace yuzu::network_config {

namespace {

// Non-copyable owner of the kernel table: a copy would duplicate the pointer and
// both destructors would FreeMibTable it. Mirrors do_arp()'s MibTableGuard.
struct ForwardTableGuard {
    PMIB_IPFORWARD_TABLE2 t;
    explicit ForwardTableGuard(PMIB_IPFORWARD_TABLE2 tbl) : t(tbl) {}
    ~ForwardTableGuard() {
        if (t)
            ::FreeMibTable(t);
    }
    ForwardTableGuard(const ForwardTableGuard&) = delete;
    ForwardTableGuard& operator=(const ForwardTableGuard&) = delete;
};

/// Text of a SOCKADDR_INET plus whether it is the all-zero address. Returned as ONE value on
/// purpose: an earlier shape returned the text and set `unspecified` through an out-parameter, and
/// a call that also read that flag as another argument of the same call read it before it was set
/// (C++ leaves argument evaluation order unspecified; MSVC goes right to left) and every next hop
/// came out on-link.
struct SockText {
    std::string text;       // empty when the family is neither IPv4 nor IPv6 or it cannot be formatted
    bool unspecified = false; // all-zero address (0.0.0.0 / ::)
};

SockText sockaddr_text(const SOCKADDR_INET& a) {
    char buf[INET6_ADDRSTRLEN]{};
    if (a.si_family == AF_INET) {
        const bool zero = a.Ipv4.sin_addr.s_addr == 0;
        return {::InetNtopA(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf))
                    ? std::string{buf}
                    : std::string{},
                zero};
    }
    if (a.si_family == AF_INET6) {
        const bool zero = IN6_IS_ADDR_UNSPECIFIED(&a.Ipv6.sin6_addr) != 0;
        return {::InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf))
                    ? std::string{buf}
                    : std::string{},
                zero};
    }
    return {};
}

std::string interface_alias(const NET_LUID& luid, NET_IFINDEX idx) {
    wchar_t alias[IF_MAX_STRING_SIZE + 1]{};
    if (::ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) == NO_ERROR)
        return yuzu::win::from_wide(alias);
    return std::format("if{}", static_cast<unsigned long>(idx));
}

} // namespace

int collect_routes_win(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;

    PMIB_IPFORWARD_TABLE2 table = nullptr;
    const DWORD rc = ::GetIpForwardTable2(AF_UNSPEC, &table);
    if (rc != NO_ERROR || table == nullptr) {
        acc.add_failure("network_config:routes_table_unavailable");
        emit_routes(ctx, {}, acc, /*unavailable=*/true);
        return 0;
    }
    ForwardTableGuard guard{table}; // FreeMibTable on every path below

    // The cap counts KEPT routes, so the host's own entries are dropped here, before the (costly)
    // alias lookup, and unpacking stops one past the cap: a huge table bounds the work done, not
    // just the rows emitted. win_routes_to_rows() applies the same filter and reports the cap.
    std::vector<WinRoute> routes;
    routes.reserve(std::min<std::size_t>(table->NumEntries, kRoutesRowCap + 1));
    bool unformattable = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& r = table->Table[i];
        WinRoute w;
        w.destination = sockaddr_text(r.DestinationPrefix.Prefix).text;
        const auto family = r.DestinationPrefix.Prefix.si_family;
        if ((family != AF_INET && family != AF_INET6) || w.destination.empty()) {
            unformattable = true; // never emit a row with a guessed destination
            continue;
        }
        w.ipv6 = family == AF_INET6;
        w.prefix_len = r.DestinationPrefix.PrefixLength;
        // An AF_UNSPEC hop formats to empty text with `unspecified` false: still on-link.
        const SockText hop = sockaddr_text(r.NextHop);
        w.next_hop = win_next_hop(hop.text, hop.unspecified);
        w.metric = r.Metric;
        w.protocol = static_cast<int>(r.Protocol);
        if (win_route_is_host_local(w))
            continue;
        w.ifname = interface_alias(r.InterfaceLuid, r.InterfaceIndex);
        routes.push_back(std::move(w));
        if (routes.size() > kRoutesRowCap)
            break; // one past the cap is enough for win_routes_to_rows() to report it; an
                   // unformattable entry after this point goes unreported (the read is CONSTRAINED anyway)
    }

    // The host-local filter, the cap-after-filter and the row mapping are the pure
    // win_routes_to_rows() (network_config_routes_parsers.hpp), tested on every host.
    const auto result = win_routes_to_rows(routes);
    if (result.capped)
        acc.add_failure(kTokRowCap);
    if (unformattable)
        acc.add_failure("network_config:routes_row_unformattable");
    emit_routes(ctx, result.rows, acc, /*unavailable=*/false);
    return 0;
}

} // namespace yuzu::network_config

#endif // _WIN32
