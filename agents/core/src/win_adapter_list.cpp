// win_adapter_list.cpp -- bounded read of the Windows network adapter list. See
// yuzu/agent/win_adapter_list.hpp for why this lives in agent-core.

#include <yuzu/agent/win_adapter_list.hpp>

#include "win_bounded_run.hpp"

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

#include <algorithm>
#include <iterator>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_adapter_slot = detail::new_slot();

#ifdef _WIN32

/// No scope id. An address of another family, or one inet_ntop refuses, has empty text.
AdapterAddr to_addr(LPSOCKADDR sa) {
    AdapterAddr out;
    if (!sa)
        return out;
    char buf[128]{};
    if (sa->sa_family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(sa);
        ::inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf));
        out.family = 4;
    } else if (sa->sa_family == AF_INET6) {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(sa);
        ::inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf));
        out.family = 6;
    }
    out.address = buf;
    return out;
}

/// An owned copy of one record: no pointer into the API's buffer survives.
Adapter flatten(const IP_ADAPTER_ADDRESSES& a) {
    Adapter out;
    if (a.AdapterName)
        out.adapter_name = a.AdapterName;
    out.friendly_name = yuzu::win::from_wide(a.FriendlyName);
    out.description = yuzu::win::from_wide(a.Description);
    out.dns_suffix = yuzu::win::from_wide(a.DnsSuffix);
    out.if_type = a.IfType;
    out.tunnel_type = static_cast<std::uint32_t>(a.TunnelType);
    out.oper_status = static_cast<std::uint32_t>(a.OperStatus);
    out.if_index = a.IfIndex;
    out.flags = a.Flags;
    out.transmit_link_speed = a.TransmitLinkSpeed;
    out.receive_link_speed = a.ReceiveLinkSpeed;
    const std::size_t mac_len =
        std::min<std::size_t>(a.PhysicalAddressLength, std::size(a.PhysicalAddress));
    out.physical_address.assign(a.PhysicalAddress, a.PhysicalAddress + mac_len);
    for (auto* ua = a.FirstUnicastAddress; ua; ua = ua->Next) {
        AdapterAddr addr = to_addr(ua->Address.lpSockaddr);
        addr.prefix_len = ua->OnLinkPrefixLength;
        out.unicast.push_back(std::move(addr));
    }
    for (auto* gw = a.FirstGatewayAddress; gw; gw = gw->Next)
        out.gateways.push_back(to_addr(gw->Address.lpSockaddr).address);
    for (auto* dns = a.FirstDnsServerAddress; dns; dns = dns->Next)
        out.dns_servers.push_back(to_addr(dns->Address.lpSockaddr));
    return out;
}

AdapterList read_raw() {
    constexpr ULONG kFlags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    // An adapter added between the sizing call and the read grows the table, so the buffer is
    // re-sized on every ERROR_BUFFER_OVERFLOW, up to three reads in all.
    constexpr int kMaxReads = 3;

    AdapterList out;
    ULONG size = 0;
    ::GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr, nullptr, &size);
    if (size == 0) {
        out.empty_table = true;
        return out;
    }
    std::vector<unsigned char> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < kMaxReads && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(size);
        rc = ::GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc != ERROR_SUCCESS) {
        out.win_error = rc;
        return out;
    }
    for (const auto* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next)
        out.adapters.push_back(flatten(*a));
    return out;
}

#else

AdapterList read_raw() {
    AdapterList out;
    out.win_error = 120; // ERROR_CALL_NOT_IMPLEMENTED: no IP Helper API on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

AdapterList read_adapters(std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<AdapterList>(g_adapter_slot, deadline, "adapter_list",
                                                 [] { return read_raw(); });
}

AdapterList read_adapters_for_test(std::chrono::milliseconds deadline,
                                   const std::function<AdapterList()>& reader) {
    return detail::run_bounded_read<AdapterList>(g_adapter_slot, deadline, "adapter_list", reader);
}

} // namespace yuzu::agent::win
