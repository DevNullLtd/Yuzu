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

/// Text of a SOCKADDR_INET, or empty when the family is neither IPv4 nor IPv6 or the
/// address cannot be formatted. `unspecified` is set for an all-zero address.
std::string sockaddr_text(const SOCKADDR_INET& a, bool& unspecified) {
    char buf[INET6_ADDRSTRLEN]{};
    unspecified = false;
    if (a.si_family == AF_INET) {
        unspecified = a.Ipv4.sin_addr.s_addr == 0;
        return ::InetNtopA(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf))
                   ? std::string{buf}
                   : std::string{};
    }
    if (a.si_family == AF_INET6) {
        unspecified = IN6_IS_ADDR_UNSPECIFIED(&a.Ipv6.sin6_addr) != 0;
        return ::InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf))
                   ? std::string{buf}
                   : std::string{};
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

    std::vector<RouteRow> rows;
    bool capped = false;
    bool unformattable = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& r = table->Table[i];
        bool dest_unspecified = false;
        WinRoute w;
        w.destination = sockaddr_text(r.DestinationPrefix.Prefix, dest_unspecified);
        const auto family = r.DestinationPrefix.Prefix.si_family;
        if ((family != AF_INET && family != AF_INET6) || w.destination.empty()) {
            unformattable = true; // never emit a row with a guessed destination
            continue;
        }
        w.ipv6 = family == AF_INET6;
        w.prefix_len = r.DestinationPrefix.PrefixLength;
        bool hop_unspecified = true;
        std::string hop = sockaddr_text(r.NextHop, hop_unspecified); // AF_UNSPEC -> empty
        w.next_hop = hop_unspecified ? std::string{} : std::move(hop); // unspecified = on-link
        w.metric = r.Metric;
        w.protocol = static_cast<int>(r.Protocol);

        if (win_route_is_host_local(w))
            continue;

        w.interface = interface_alias(r.InterfaceLuid, r.InterfaceIndex);

        if (rows.size() >= kRoutesRowCap) {
            capped = true;
            break;
        }
        rows.push_back(win_route_to_row(w));
    }

    if (capped)
        acc.add_failure(kTokRowCap);
    if (unformattable)
        acc.add_failure("network_config:routes_row_unformattable");
    emit_routes(ctx, rows, acc, /*unavailable=*/false);
    return 0;
}

} // namespace yuzu::network_config

#endif // _WIN32
