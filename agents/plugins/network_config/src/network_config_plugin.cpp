/**
 * network_config_plugin.cpp — Network configuration plugin for Yuzu
 *
 * Actions:
 *   "adapters"     — Lists network adapters with MAC, speed, status.
 *   "ip_addresses" — Lists assigned IP addresses with subnet and gateway.
 *   "dns_servers"  — Lists configured DNS servers per adapter.
 *   "proxy"        — Returns system proxy configuration.
 *   "dns_cache"    — Returns the DNS resolver cache (Windows, Linux).
 *   "arp"          — Returns the host ARP / neighbour table:
 *                    arp|iface|ip|mac|type.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#include "network_config_parsers.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <spdlog/spdlog.h>
#endif

#if defined(__linux__)
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator> // std::make_move_iterator
#include <map>
#include <span>
#include <vector>

#include <arpa/inet.h>
#include <linux/if.h> // IFF_UP — see network_config_parsers.hpp's own include comment
#include <linux/if_addr.h> // struct ifaddrmsg — named directly in fetch_addr_dump()'s request
#include <linux/if_link.h> // struct ifinfomsg — named directly in fetch_link_dump()'s request
#include <linux/netlink.h>
#include <linux/rtnetlink.h> // struct rtmsg / RTM_GET* / NLM_F_* — named directly below
#include <sys/socket.h>
#include <unistd.h>

#include <yuzu/agent/runner_status.hpp>     // classify_runner_failure / forward_runner_failure
#include <yuzu/agent/scoped_fd.hpp>         // ScopedFd — RAII netlink socket owner
#include <yuzu/agent/subprocess_runner.hpp> // run_bounded_subprocess / probe_tool_path (dns_cache argv legs only)
#endif

#if defined(__APPLE__)
// SIOCGIFMEDIA is a native BSD socket ioctl (libc + kernel headers only, no
// framework link) used to read a real adapter link speed for do_adapters().
#include <net/if.h>
#include <net/if_dl.h>  // sockaddr_dl — getifaddrs' AF_LINK entries (adapters MAC)
#include <net/if_media.h>
#include <net/route.h>  // NET_RT_DUMP / RTF_GATEWAY — default-route sysctl (ip_addresses)
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <cstddef> // offsetof
#include <cstring>
#include <ifaddrs.h>
#include <map>
#include <netinet/in.h>
#include <span>
#include <vector>

#include "route_sysctl_arp.hpp" // yuzu::shared::{fetch,parse}_rt_flags_llinfo — reused as-is (arp leg)

#include <yuzu/agent/scoped_cfref.hpp> // ScopedCFRef — RAII CF object owner (dns_servers/proxy)

#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif
#endif

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
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <iphlpapi.h>
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 / ConvertInterfaceLuidToAlias (arp)
#include <winhttp.h>
#include <vector>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

namespace {

#if defined(__APPLE__)
// Real link speed via SIOCGIFMEDIA (a single ioctl on a throwaway datagram
// socket — no framework). Only Ethernet media subtypes are decoded to a
// numeric Mbps; Wi-Fi, virtual interfaces, or an ioctl failure/inactive link
// report the honest 0 (unknown) rather than a fabricated number.
int mac_link_speed_mbps(const std::string& name) {
    // Non-copyable scope owner for the throwaway datagram socket (RAII —
    // no manual close() on any exit path, including future early returns).
    struct SocketGuard {
        int fd;
        explicit SocketGuard(int f) : fd(f) {}
        ~SocketGuard() {
            if (fd >= 0)
                ::close(fd);
        }
        SocketGuard(const SocketGuard&) = delete;
        SocketGuard& operator=(const SocketGuard&) = delete;
    };

    SocketGuard socket_guard{::socket(AF_INET, SOCK_DGRAM, 0)};
    if (socket_guard.fd < 0)
        return 0;
    struct ifmediareq ifmr {};
    std::snprintf(ifmr.ifm_name, sizeof(ifmr.ifm_name), "%s", name.c_str());
    const int rc = ::ioctl(socket_guard.fd, SIOCGIFMEDIA, &ifmr);
    if (rc != 0)
        return 0;
    if (!(ifmr.ifm_status & IFM_AVALID) || !(ifmr.ifm_status & IFM_ACTIVE))
        return 0;
    if (IFM_TYPE(ifmr.ifm_active) != IFM_ETHER)
        return 0;
    // Every Ethernet subtype whose Mbps figure is documented directly by the
    // Darwin if_media.h constant name is grouped here — the ioctl already
    // paid for the lookup, so decoding the rest of the speed-explicit
    // subtypes is a constant-time win. Genuinely speed-ambiguous types
    // (IFM_OTHER, IFM_AUTO, HomePNA, etc.) fall through to the honest 0.
    switch (IFM_SUBTYPE(ifmr.ifm_active)) {
    case IFM_10_T:
        return 10;
    case IFM_100_TX:
    case IFM_100_T4:
    case IFM_100_T2:
    case IFM_100_T:
        return 100;
    case IFM_1000_T:
    case IFM_1000_SX:
    case IFM_1000_LX:
    case IFM_1000_CX:
    case IFM_1000_CX_SGMII:
    case IFM_1000_KX:
        return 1000;
    case IFM_2500_T:
    case IFM_2500_SX:
    case IFM_2500_KX:
    case IFM_2500_X:
        return 2500;
    case IFM_5000_T:
    case IFM_5000_KR:
    case IFM_5000_KR_S:
    case IFM_5000_KR1:
        return 5000;
    case IFM_10G_T:
    case IFM_10G_SR:
    case IFM_10G_LR:
    case IFM_10G_CX4:
    case IFM_10G_KX4:
    case IFM_10G_KR:
    case IFM_10G_CR1:
    case IFM_10G_ER:
    case IFM_10G_TWINAX:
    case IFM_10G_TWINAX_LONG:
    case IFM_10G_LRM:
    case IFM_10G_AOC:
        return 10000;
    case IFM_20G_KR2:
        return 20000;
    case IFM_25G_CR:
    case IFM_25G_KR:
    case IFM_25G_SR:
    case IFM_25G_LR:
    case IFM_25G_T:
    case IFM_25G_CR_S:
    case IFM_25G_CR1:
    case IFM_25G_KR_S:
    case IFM_25G_KR1:
    case IFM_25G_ACC:
    case IFM_25G_AOC:
        return 25000;
    case IFM_40G_CR4:
    case IFM_40G_SR4:
    case IFM_40G_LR4:
    case IFM_40G_KR4:
    case IFM_40G_XLPPI:
    case IFM_40G_XLAUI:
    case IFM_40G_ER4:
        return 40000;
    case IFM_50G_CR2:
    case IFM_50G_KR2:
    case IFM_50G_SR:
    case IFM_50G_LR:
    case IFM_50G_FR:
    case IFM_50G_CP:
    case IFM_50G_KR_PAM4:
        return 50000;
    case IFM_56G_R4:
        return 56000;
    case IFM_100G_CR4:
    case IFM_100G_SR4:
    case IFM_100G_KR4:
    case IFM_100G_LR4:
    case IFM_100G_CP2:
    case IFM_100G_SR2:
    case IFM_100G_DR:
    case IFM_100G_KR2_PAM4:
    case IFM_100G_CAUI2:
    case IFM_100G_CAUI4:
    case IFM_100G_AUI2:
    case IFM_100G_AUI4:
    case IFM_100G_CR_PAM4:
    case IFM_100G_KR_PAM4:
        return 100000;
    default:
        return 0; // unrecognised subtype — honest unknown, never fabricated
    }
}

// Default-route gateway via the PF_ROUTE sysctl dump (NET_RT_DUMP/AF_INET),
// replacing the old `route -n get default | grep gateway` shell pipe. The
// impure sysctl fetch stays here; the bounds-checked walk lives in
// network_config_parsers.hpp's parse_default_route_dump().
// RAII owner for a getifaddrs() list. cpp-conventions.md §Resource ownership
// requires an owner rather than manual cleanup for a new acquisition, and
// CommandContext::write_output / std::format / the containers below can all
// throw between acquisition and release. Mirrors agents/shared/icmp_probe.hpp's
// AddrInfoGuard; kept local because no shared ifaddrs owner exists in-tree yet
// (a shared one alongside AddrInfoGuard is a sensible later consolidation --
// there are three call sites across the repo).
struct IfAddrsGuard {
    struct ifaddrs* p{nullptr};
    IfAddrsGuard() = default;
    explicit IfAddrsGuard(struct ifaddrs* ptr) : p(ptr) {}
    ~IfAddrsGuard() {
        if (p)
            ::freeifaddrs(p);
    }
    IfAddrsGuard(const IfAddrsGuard&) = delete;
    IfAddrsGuard& operator=(const IfAddrsGuard&) = delete;
    IfAddrsGuard(IfAddrsGuard&& o) noexcept : p(o.p) { o.p = nullptr; }
    IfAddrsGuard& operator=(IfAddrsGuard&& o) noexcept {
        if (this != &o) {
            if (p)
                ::freeifaddrs(p);
            p = o.p;
            o.p = nullptr;
        }
        return *this;
    }
};

// Gateway plus the honesty bits the caller needs: a failed or truncated
// PF_ROUTE read must not be emitted as the positive assertion "this host has
// no default gateway". This was the only degradation path in the plugin that
// stayed silent.
struct MacGatewayResult {
    std::string gateway = "-";
    bool ok = false;
    bool truncated = false;
};

MacGatewayResult mac_default_gateway() {
    MacGatewayResult out;
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    std::size_t needed = 0;
    if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0 || needed == 0)
        return out;
    std::vector<unsigned char> buf(needed);
    if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) != 0)
        return out;
    buf.resize(needed);
    auto parsed = yuzu::network_config::parse_default_route_dump(buf);
    out.ok = true;
    out.truncated = parsed.truncated;
    if (parsed.truncated)
        spdlog::warn("network_config: PF_ROUTE default-route dump was truncated");
    if (parsed.found)
        out.gateway = parsed.gateway;
    return out;
}

#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
// One SCDynamicStore session per call — cheap, no persistent state, no
// change-notification callback registered (dns_servers/proxy only ever read
// a point-in-time snapshot).
yuzu::agent::ScopedCFRef<SCDynamicStoreRef> open_dynamic_store() {
    return yuzu::agent::ScopedCFRef<SCDynamicStoreRef>(
        SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("com.yuzu.agent.network_config"), nullptr,
                             nullptr));
}

std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    const CFIndex len = CFStringGetLength(s);
    if (len == 0)
        return {};
    const CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(s, buf.data(), max_size, kCFStringEncodingUTF8))
        return {};
    buf.resize(std::strlen(buf.c_str()));
    return buf;
}

// Extract the "ServerAddresses" CFArray-of-CFString from a State:/Network/
// {Global,Service/<id>}/DNS dictionary (nullptr/absent-key safe — a
// service with no configured DNS has no "ServerAddresses" entry at all).
std::vector<std::string> extract_server_addresses(CFDictionaryRef dict) {
    std::vector<std::string> out;
    if (!dict)
        return out;
    // Type-check before every CF cast. A CoreFoundation cast is an unchecked
    // pointer cast, so calling CFArray/CFString APIs on a different CF type is
    // undefined behaviour and in practice faults inside CoreFoundation. Any
    // writer to State:/Network/Service/<id>/DNS — a third-party VPN or
    // network-extension bundle, a malformed configuration profile — can put a
    // non-conforming value here, and this action runs fleet-wide. do_proxy
    // below already guards every read this way; this path did not.
    const void* servers_v = CFDictionaryGetValue(dict, CFSTR("ServerAddresses"));
    if (!servers_v || CFGetTypeID(servers_v) != CFArrayGetTypeID())
        return out;
    auto* servers = static_cast<CFArrayRef>(servers_v);
    const CFIndex count = CFArrayGetCount(servers);
    for (CFIndex i = 0; i < count; ++i) {
        const void* item_v = CFArrayGetValueAtIndex(servers, i);
        if (!item_v || CFGetTypeID(item_v) != CFStringGetTypeID())
            continue; // skip a non-string element, never fault on it
        auto server = cfstring_to_utf8(static_cast<CFStringRef>(item_v));
        if (!server.empty())
            out.push_back(std::move(server));
    }
    return out;
}
#endif // YUZU_HAVE_SYSTEMCONFIGURATION
#endif // __APPLE__

#ifdef _WIN32
// Format a MAC address from a byte array
std::string format_mac(const BYTE* addr, DWORD len) {
    if (len < 6)
        return "-";
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", addr[0], addr[1], addr[2],
                       addr[3], addr[4], addr[5]);
}

// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

// Convert a SOCKADDR to a string
std::string sockaddr_to_string(LPSOCKADDR sa) {
    char buf[128]{};
    if (sa->sa_family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(sa);
        inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(sa);
        inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}
#endif

#if defined(__linux__)

// ── rtnetlink dump helpers (adapters/ip_addresses legs) ──────────────────
//
// Thin impure shells: own the socket/send/recv mechanics only. Every byte
// of decode logic lives in network_config_parsers.hpp's pure, span-based
// parse_rtnetlink_*_chunk() functions — these loops just hand each
// recvmsg() buffer to the decoder and accumulate its records.

constexpr std::size_t kNetlinkRecvBufSize = 16384; // matches net_quality_sampler.cpp's convention

// How many non-kernel datagrams a dump will discard before giving up. Small:
// on a healthy host this is always 0, and the only thing that produces them is
// a local process writing to our netlink socket.
constexpr int kMaxForeignDatagrams = 64;

// SO_RCVTIMEO bounds each INDIVIDUAL recvmsg() call, but it resets on every
// arriving datagram -- including one this loop goes on to discard. A local
// process pacing one foreign-origin datagram just under each 2s window can
// therefore stretch the count-based budget above to kMaxForeignDatagrams *
// ~2s (~128s) of real wall-clock time before this thread ever gives up.
// This deadline bounds the WHOLE discard loop instead, independent of how
// the per-call timeout keeps resetting.
constexpr auto kNetlinkDiscardDeadline = std::chrono::seconds{4};

yuzu::agent::ScopedFd open_rtnetlink_socket() {
    yuzu::agent::ScopedFd fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (fd.get() >= 0) {
        // Bound the recvmsg wait, matching the two existing netlink sites in
        // this tree (agents/core/src/net_quality_sampler.cpp,
        // agents/plugins/tar/src/tar_network_collector.cpp). Without this a
        // dump the kernel never terminates with NLMSG_DONE wedges the agent's
        // command-execution thread forever; the drain loops below treat the
        // resulting EAGAIN as an incomplete dump and report CONSTRAINED.
        struct timeval tv {
            2, 0
        }; // 2 s
        ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

struct LinkDumpResult {
    std::vector<yuzu::network_config::RtLinkRecord> records;
    bool ok = false; // true iff the dump completed (NLMSG_DONE) without error/truncation
};

LinkDumpResult fetch_link_dump() {
    LinkDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 1;
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.ifi.ifi_family = AF_UNSPEC;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    ssize_t sent;
    do {
        sent = ::sendmsg(fd.get(), &m, 0);
    } while (sent < 0 && errno == EINTR); // symmetry with the recvmsg loop below
    if (sent <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    int foreign_datagrams = 0;
    const auto discard_deadline = std::chrono::steady_clock::now() + kNetlinkDiscardDeadline;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result; // ok stays false — an honest incomplete read
        // Netlink unicast between USER sockets is permitted, so a reply
        // arriving on this socket is not necessarily from the kernel. The
        // auto-bound portid is the agent's pid (readable from /proc) and the
        // sequence numbers below are fixed literals, so a local unprivileged
        // process could otherwise inject forged RTM_NEW* records into
        // fleet-reported adapters, addresses and the default gateway. The
        // agent runs under its own account precisely so local users cannot
        // influence it (docs/agent-privilege-model.md). Only the kernel sends
        // from portid 0.
        if (rsa.nl_pid != 0) {
            // BOUNDED discard. SO_RCVTIMEO only fires on SILENCE, so an
            // unbounded `continue` here would let the same local process the
            // origin check defends against pin this thread indefinitely by
            // simply keeping the socket busy — trading a spoofing defect for
            // an availability one. Give up after a small budget and report an
            // incomplete read.
            if (++foreign_datagrams > kMaxForeignDatagrams)
                return result; // ok stays false — honest incomplete read
            // Count alone is not enough — see kNetlinkDiscardDeadline above.
            if (std::chrono::steady_clock::now() >= discard_deadline)
                return result; // ok stays false — honest incomplete read
            continue; // not from the kernel — discard, do not parse
        }

        // MSG_TRUNC means the kernel discarded the tail of this datagram
        // because it exceeded our fixed buffer. If the retained prefix ends on
        // a valid netlink message boundary the parser cannot see the loss, and
        // a later NLMSG_DONE would then set ok=true over a short record set.
        // The syscall's own truncation signal is authoritative.
        if ((rm.msg_flags & MSG_TRUNC) != 0)
            return result; // ok stays false — records were dropped

        auto chunk = yuzu::network_config::parse_rtnetlink_link_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

struct AddrDumpResult {
    std::vector<yuzu::network_config::RtAddrRecord> records;
    bool ok = false;
};

AddrDumpResult fetch_addr_dump() {
    AddrDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 2;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.ifa.ifa_family = AF_UNSPEC;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    ssize_t sent;
    do {
        sent = ::sendmsg(fd.get(), &m, 0);
    } while (sent < 0 && errno == EINTR); // symmetry with the recvmsg loop below
    if (sent <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    int foreign_datagrams = 0;
    const auto discard_deadline = std::chrono::steady_clock::now() + kNetlinkDiscardDeadline;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result;
        // Netlink unicast between USER sockets is permitted, so a reply
        // arriving on this socket is not necessarily from the kernel. The
        // auto-bound portid is the agent's pid (readable from /proc) and the
        // sequence numbers below are fixed literals, so a local unprivileged
        // process could otherwise inject forged RTM_NEW* records into
        // fleet-reported adapters, addresses and the default gateway. The
        // agent runs under its own account precisely so local users cannot
        // influence it (docs/agent-privilege-model.md). Only the kernel sends
        // from portid 0.
        if (rsa.nl_pid != 0) {
            // BOUNDED discard. SO_RCVTIMEO only fires on SILENCE, so an
            // unbounded `continue` here would let the same local process the
            // origin check defends against pin this thread indefinitely by
            // simply keeping the socket busy — trading a spoofing defect for
            // an availability one. Give up after a small budget and report an
            // incomplete read.
            if (++foreign_datagrams > kMaxForeignDatagrams)
                return result; // ok stays false — honest incomplete read
            // Count alone is not enough — see kNetlinkDiscardDeadline above.
            if (std::chrono::steady_clock::now() >= discard_deadline)
                return result; // ok stays false — honest incomplete read
            continue; // not from the kernel — discard, do not parse
        }

        // MSG_TRUNC means the kernel discarded the tail of this datagram
        // because it exceeded our fixed buffer. If the retained prefix ends on
        // a valid netlink message boundary the parser cannot see the loss, and
        // a later NLMSG_DONE would then set ok=true over a short record set.
        // The syscall's own truncation signal is authoritative.
        if ((rm.msg_flags & MSG_TRUNC) != 0)
            return result; // ok stays false — records were dropped

        auto chunk = yuzu::network_config::parse_rtnetlink_addr_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

struct RouteDumpResult {
    std::vector<yuzu::network_config::RtRouteRecord> records;
    bool ok = false;
};

RouteDumpResult fetch_default_route_dump() {
    RouteDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 3;
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.rtm.rtm_family = AF_INET;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    ssize_t sent;
    do {
        sent = ::sendmsg(fd.get(), &m, 0);
    } while (sent < 0 && errno == EINTR); // symmetry with the recvmsg loop below
    if (sent <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    int foreign_datagrams = 0;
    const auto discard_deadline = std::chrono::steady_clock::now() + kNetlinkDiscardDeadline;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result;
        // Netlink unicast between USER sockets is permitted, so a reply
        // arriving on this socket is not necessarily from the kernel. The
        // auto-bound portid is the agent's pid (readable from /proc) and the
        // sequence numbers below are fixed literals, so a local unprivileged
        // process could otherwise inject forged RTM_NEW* records into
        // fleet-reported adapters, addresses and the default gateway. The
        // agent runs under its own account precisely so local users cannot
        // influence it (docs/agent-privilege-model.md). Only the kernel sends
        // from portid 0.
        if (rsa.nl_pid != 0) {
            // BOUNDED discard. SO_RCVTIMEO only fires on SILENCE, so an
            // unbounded `continue` here would let the same local process the
            // origin check defends against pin this thread indefinitely by
            // simply keeping the socket busy — trading a spoofing defect for
            // an availability one. Give up after a small budget and report an
            // incomplete read.
            if (++foreign_datagrams > kMaxForeignDatagrams)
                return result; // ok stays false — honest incomplete read
            // Count alone is not enough — see kNetlinkDiscardDeadline above.
            if (std::chrono::steady_clock::now() >= discard_deadline)
                return result; // ok stays false — honest incomplete read
            continue; // not from the kernel — discard, do not parse
        }

        // MSG_TRUNC means the kernel discarded the tail of this datagram
        // because it exceeded our fixed buffer. If the retained prefix ends on
        // a valid netlink message boundary the parser cannot see the loss, and
        // a later NLMSG_DONE would then set ok=true over a short record set.
        // The syscall's own truncation signal is authoritative.
        if ((rm.msg_flags & MSG_TRUNC) != 0)
            return result; // ok stays false — records were dropped

        auto chunk = yuzu::network_config::parse_rtnetlink_route_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

#endif // __linux__

// ── adapters action ───────────────────────────────────────────────────────

int do_adapters(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
    if (buf_size == 0) {
        ctx.write_output("adapter|No adapters found|-|0|unknown");
        return 0;
    }

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        ctx.write_output("adapter|Error enumerating adapters|-|0|unknown");
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        // Skip loopback and tunnel adapters
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto name = from_wide(a->FriendlyName);
        auto mac = format_mac(a->PhysicalAddress, a->PhysicalAddressLength);
        auto speed_mbps = a->TransmitLinkSpeed / 1'000'000;
        const char* status = (a->OperStatus == IfOperStatusUp) ? "up" : "down";

        ctx.write_output(std::format("adapter|{}|{}|{}|{}", name, mac, speed_mbps, status));
    }

#elif defined(__linux__)
    auto links = fetch_link_dump();
    for (const auto& rec : links.records) {
        if (rec.name.empty() || rec.name == "lo")
            continue;

        // Speed via sysfs (native file read, unrelated to the rtnetlink
        // dump above) — unchanged from the pre-migration implementation.
        std::string speed = "0";
        std::ifstream speed_file("/sys/class/net/" + rec.name + "/speed");
        if (speed_file) {
            std::getline(speed_file, speed);
            if (speed.empty() || speed[0] == '-')
                speed = "0";
        }

        const std::string mac = rec.mac.empty() ? "-" : rec.mac;
        // OPERATIONAL state, not the IFF_UP administrative flag — see
        // link_status_string()'s contract in network_config_parsers.hpp.
        ctx.write_output(std::format("adapter|{}|{}|{}|{}", rec.name, mac, speed,
                                     yuzu::network_config::link_status_string(rec)));
    }
    if (!links.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:rtnetlink_link_dump_incomplete");
    }

#elif defined(__APPLE__)
    struct ifaddrs* raw_head = nullptr;
    if (::getifaddrs(&raw_head) != 0) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:getifaddrs_failed");
        return 0;
    }
    // Adopt IMMEDIATELY — everything below allocates and can throw.
    IfAddrsGuard head_guard(raw_head);
    struct ifaddrs* const head = raw_head;

    // getifaddrs() returns one entry per (interface, address-family) pair —
    // collapse to one row per interface name, in first-seen order, matching
    // the old ifconfig-parse's per-adapter grouping. Unlike ip_addresses
    // below, loopback is NOT excluded here: the pre-migration `ifconfig -a`
    // parse reported lo0 as a real adapter row (PKG-NC fix round — live
    // before/after parity diff caught an earlier draft silently dropping it).
    //
    // NOTE the deliberate per-OS asymmetry: the Linux leg above DOES filter
    // loopback, because the pre-migration Linux leg did too (`ip -o link
    // show` parse, `if (name == "lo") continue;` at 819bf395a:296-298) while
    // the macOS leg never did. That asymmetry PREDATES this migration and is
    // preserved here on purpose — verified against both pre-migration legs.
    // Do not "align" the two without a deliberate behavior-change decision;
    // changing either side silently alters what the fleet reports.
    std::vector<std::string> order;
    std::map<std::string, std::string> mac_by_name;
    std::map<std::string, bool> up_by_name;
    for (auto* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_name)
            continue;
        const std::string name = p->ifa_name;
        if (std::find(order.begin(), order.end(), name) == order.end())
            order.push_back(name);
        const bool up = (p->ifa_flags & IFF_UP) != 0;
        auto up_it = up_by_name.find(name);
        up_by_name[name] = (up_it != up_by_name.end()) ? (up_it->second || up) : up;

        if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK) {
            // sockaddr_dl's real on-wire size (sa_len) routinely exceeds
            // sizeof(struct sockaddr_dl): sdl_data is a fixed 12-byte
            // placeholder array that only reliably holds the NAME; the
            // trailing link-layer address bytes can land past it for a
            // longer interface name. Same discipline as
            // route_sysctl_arp.hpp's RTAX_GATEWAY handling: memcpy only the
            // small fixed-offset header fields (sdl_nlen/sdl_alen) into a
            // local struct for a safe read, then read the MAC bytes
            // directly from the ORIGINAL buffer at their bounds-checked
            // offset — never from the (possibly truncated) local copy.
            const auto* raw = reinterpret_cast<const unsigned char*>(p->ifa_addr);
            const auto sa_len = static_cast<std::size_t>(p->ifa_addr->sa_len);
            struct sockaddr_dl sdl {};
            std::memcpy(&sdl, raw, std::min(sizeof(sdl), sa_len));
            const std::size_t needed = offsetof(struct sockaddr_dl, sdl_data) +
                                       static_cast<std::size_t>(sdl.sdl_nlen) +
                                       static_cast<std::size_t>(sdl.sdl_alen);
            if (sdl.sdl_alen == 6 && sa_len >= needed) {
                unsigned char mac[6];
                std::memcpy(mac, raw + offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen, 6);
                mac_by_name[name] = yuzu::network_config::format_mac(mac, 6);
            }
        }
    }

    for (const auto& name : order) {
        auto mac_it = mac_by_name.find(name);
        const std::string mac =
            (mac_it != mac_by_name.end() && !mac_it->second.empty()) ? mac_it->second : "-";
        ctx.write_output(std::format("adapter|{}|{}|{}|{}", name, mac, mac_link_speed_mbps(name),
                                     up_by_name[name] ? "up" : "down"));
    }
#endif
    return 0;
}

// ── ip_addresses action ───────────────────────────────────────────────────

int do_ip_addresses(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &buf_size);
    if (buf_size == 0)
        return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto adapter_name = from_wide(a->FriendlyName);

        // Collect first gateway
        std::string gateway = "-";
        for (auto* gw = a->FirstGatewayAddress; gw; gw = gw->Next) {
            auto addr = sockaddr_to_string(gw->Address.lpSockaddr);
            if (!addr.empty()) {
                gateway = addr;
                break;
            }
        }

        // List unicast addresses
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            auto addr = sockaddr_to_string(ua->Address.lpSockaddr);
            if (addr.empty())
                continue;
            ctx.write_output(
                std::format("ip|{}|{}|{}|{}", adapter_name, addr, ua->OnLinkPrefixLength, gateway));
        }
    }

#elif defined(__linux__)
    auto links = fetch_link_dump();
    std::map<int, std::string> name_by_index;
    for (const auto& r : links.records)
        name_by_index[r.index] = r.name;

    auto route = fetch_default_route_dump();
    std::string default_gw = "-";
    bool gateway_unresolved = false;
    for (const auto& r : route.records) {
        if (!r.gateway.empty()) {
            default_gw = r.gateway;
            break;
        }
        // A main-table default route WAS present but its gateway sits in a
        // nexthop form this leg cannot resolve. Emitting "-" unqualified would
        // claim the host has no default route.
        gateway_unresolved = true;
    }

    auto addrs = fetch_addr_dump();
    for (const auto& rec : addrs.records) {
        // DEVICE name first, IFA_LABEL only as a fallback. The pre-migration
        // leg read iproute2's second column, which is the device ("eth0"),
        // never the alias label ("eth0:1"). Preferring the label would rename
        // every aliased row and — worse — let a loopback alias ("lo:1")
        // slip past the loopback filter below, which the old leg dropped.
        std::string name;
        if (auto it = name_by_index.find(rec.index); it != name_by_index.end())
            name = it->second;
        else if (!rec.label.empty())
            name = rec.label; // link dump incomplete; best remaining signal
        else
            name = std::format("if{}", rec.index);

        // Match the old leg's loopback filter, plus two cases it never had to
        // survive: an alias label, and an unresolved name (link dump failed),
        // where the loopback address itself is the only signal left.
        if (name == "lo" || name.starts_with("lo:"))
            continue;
        if (rec.address == "127.0.0.1" || rec.address == "::1")
            continue;
        ctx.write_output(std::format("ip|{}|{}|{}|{}", name, rec.address,
                                     static_cast<unsigned int>(rec.prefix_len), default_gw));
    }
    if (!links.ok || !addrs.ok || !route.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:rtnetlink_dump_incomplete");
    } else if (gateway_unresolved) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:default_gateway_unresolved_nexthop");
    }

#elif defined(__APPLE__)
    const auto gw_result = mac_default_gateway();
    const std::string default_gw = gw_result.gateway;
    if (!gw_result.ok || gw_result.truncated) {
        // The address rows below are still valid, so this is CONSTRAINED/
        // PARTIAL rather than UNAVAILABLE — but it must not be silent: a
        // gateway of "-" reported with an OK status is the positive claim
        // "this host has no default route".
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:pf_route_default_dump_incomplete");
    }

    struct ifaddrs* raw_head = nullptr;
    if (::getifaddrs(&raw_head) != 0) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:getifaddrs_failed");
        return 0;
    }
    // Adopt IMMEDIATELY — everything below allocates and can throw.
    IfAddrsGuard head_guard(raw_head);
    struct ifaddrs* const head = raw_head;

    char text_buf[INET6_ADDRSTRLEN];
    for (auto* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_name || !p->ifa_addr)
            continue;
        const std::string name = p->ifa_name;
        if (name == "lo0")
            continue;

        // Netmasks are emitted as a CIDR prefix length ("24", "32"), NOT
        // the old macOS leg's raw hex ("0xffffff00") — a deliberate
        // cross-platform consistency fix (PKG-NC fix round): the Linux
        // rtnetlink leg already emits a prefix length (ifa_prefixlen), and
        // the two legs previously disagreed on this field's SHAPE, not just
        // its value. Dashboard-side parsers have broken on exactly this
        // kind of shape mismatch before (#3346) — called out here and in
        // the PR report's behavior-change list, not left for a reviewer to
        // discover independently.
        if (p->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in sin {};
            std::memcpy(&sin, p->ifa_addr,
                        std::min(sizeof(sin), static_cast<std::size_t>(p->ifa_addr->sa_len)));
            if (!::inet_ntop(AF_INET, &sin.sin_addr, text_buf, sizeof(text_buf)))
                continue;
            unsigned int prefix = 0;
            if (p->ifa_netmask) {
                // Clamp to the kernel's declared sa_len: an AF_INET netmask
                // sockaddr is routinely SHORTER than sizeof(sockaddr_in) --
                // measured 5 bytes (lo0), 7 (en0/en1) and 8 (utun4) on a live
                // host — because the trailing all-zero bytes are elided.
                // Copying the full 16 bytes reads past the object; getifaddrs
                // packs every sockaddr into one block so it usually goes
                // unnoticed, but for the last sockaddr in that block it runs
                // off the allocation. The zero-initialised `mask` supplies the
                // elided trailing zero bytes, which is exactly the right value.
                struct sockaddr_in mask {};
                std::memcpy(&mask, p->ifa_netmask,
                            std::min(sizeof(mask),
                                     static_cast<std::size_t>(p->ifa_netmask->sa_len)));
                prefix = yuzu::network_config::ipv4_prefix_length(ntohl(mask.sin_addr.s_addr));
            }
            ctx.write_output(std::format("ip|{}|{}|{}|{}", name, text_buf, prefix, default_gw));
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 sin6 {};
            std::memcpy(&sin6, p->ifa_addr,
                       std::min(sizeof(sin6), static_cast<std::size_t>(p->ifa_addr->sa_len)));
            if (!::inet_ntop(AF_INET6, &sin6.sin6_addr, text_buf, sizeof(text_buf)))
                continue;
            unsigned int prefix = 0;
            if (p->ifa_netmask) {
                struct sockaddr_in6 mask6 {};
                std::memcpy(&mask6, p->ifa_netmask,
                           std::min(sizeof(mask6),
                                    static_cast<std::size_t>(p->ifa_netmask->sa_len)));
                prefix = yuzu::network_config::ipv6_prefix_length(mask6.sin6_addr.s6_addr);
            }
            std::string addr = text_buf;
            const auto pct = addr.find('%');
            if (pct != std::string::npos)
                addr = addr.substr(0, pct);
            ctx.write_output(std::format("ip|{}|{}|{}|{}", name, addr, prefix, default_gw));
        }
    }
#endif
    return 0;
}

// ── dns_servers action ────────────────────────────────────────────────────

int do_dns_servers(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
    if (buf_size == 0)
        return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto adapter_name = from_wide(a->FriendlyName);

        for (auto* dns = a->FirstDnsServerAddress; dns; dns = dns->Next) {
            auto addr = sockaddr_to_string(dns->Address.lpSockaddr);
            if (addr.empty())
                continue;
            auto family = dns->Address.lpSockaddr->sa_family;
            const char* type = (family == AF_INET6) ? "IPv6" : "IPv4";
            ctx.write_output(std::format("dns|{}|{}|{}", adapter_name, addr, type));
        }
    }

#elif defined(__linux__)
    std::ifstream resolv("/etc/resolv.conf");
    if (resolv) {
        std::string line;
        while (std::getline(resolv, line)) {
            if (line.starts_with("nameserver ")) {
                auto server = line.substr(11);
                auto type = (server.find(':') != std::string::npos) ? "IPv6" : "IPv4";
                ctx.write_output(std::format("dns|system|{}|{}", server, type));
            }
        }
    } else {
        // Unreadable resolv.conf must not read as "this host has no
        // resolvers" under a SUPPORTED rung-1 descriptor.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:resolv_conf_unreadable");
    }

#elif defined(__APPLE__)
#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
    auto store = open_dynamic_store();
    if (store) {
        // State:/Network/Global/DNS alone only ever reports the primary
        // resolver — `scutil --dns` (the pre-migration mechanism) walks
        // every configured network SERVICE's own resolver list too, and a
        // host with supplemental/per-service DNS servers has them there,
        // not in the global key. Reading only the global key silently
        // dropped every supplemental resolver (PKG-NC fix round: live
        // before/after parity diff found 2 of 4 real resolvers missing).
        // Union global + every State:/Network/Service/<id>/DNS key,
        // global-first, deduped (a resolver can legitimately appear under
        // more than one service).
        // Groups in priority order: global first, then each per-service
        // list. The ordered union/dedupe is the pure half (union_dns_servers).
        std::vector<std::vector<std::string>> server_groups;
        {
            // SCDynamicStoreCopyValue returns CFPropertyListRef — type-check
            // the DICTIONARY itself, not only the ServerAddresses value inside
            // it. CFRelease is type-agnostic so ScopedCFRef stays correct
            // either way; the cast is what would be unsound.
            yuzu::agent::ScopedCFRef<CFPropertyListRef> dns_v(
                SCDynamicStoreCopyValue(store.get(), CFSTR("State:/Network/Global/DNS")));
            if (dns_v && CFGetTypeID(dns_v.get()) == CFDictionaryGetTypeID()) {
                server_groups.push_back(extract_server_addresses(
                    static_cast<CFDictionaryRef>(dns_v.get())));
            }
        }
        {
            // SCDynamicStoreCopyKeyList's `pattern` argument is ALWAYS a
            // POSIX regex match against store keys (unlike
            // SCDynamicStoreCopyValue's exact-match `key`) — no separate
            // "is this a regex" flag exists.
            yuzu::agent::ScopedCFRef<CFArrayRef> keys(static_cast<CFArrayRef>(
                SCDynamicStoreCopyKeyList(store.get(), CFSTR("State:/Network/Service/.*/DNS"))));
            if (keys) {
                const CFIndex key_count = CFArrayGetCount(keys.get());
                for (CFIndex i = 0; i < key_count; ++i) {
                    const void* key_v = CFArrayGetValueAtIndex(keys.get(), i);
                    if (!key_v || CFGetTypeID(key_v) != CFStringGetTypeID())
                        continue; // type-check every CF cast, as the rest of this file does
                    auto* key = static_cast<CFStringRef>(key_v);
                    yuzu::agent::ScopedCFRef<CFPropertyListRef> svc_v(
                        SCDynamicStoreCopyValue(store.get(), key));
                    if (!svc_v || CFGetTypeID(svc_v.get()) != CFDictionaryGetTypeID())
                        continue; // same type-identity guard as the global key
                    server_groups.push_back(extract_server_addresses(
                        static_cast<CFDictionaryRef>(svc_v.get())));
                }
            }
        }
        for (const auto& server : yuzu::network_config::union_dns_servers(server_groups)) {
            auto type = (server.find(':') != std::string::npos) ? "IPv6" : "IPv4";
            ctx.write_output(std::format("dns|system|{}|{}", server, type));
        }
    } else {
        // The store could not be opened — zero rows here would otherwise be
        // indistinguishable from "this host has no resolvers configured".
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:dynamic_store_unavailable");
    }
#else
    // Compiled without SystemConfiguration — honest gap, no fabricated list.
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "network_config:no_systemconfiguration");
#endif
#endif
    return 0;
}

// ── proxy action ──────────────────────────────────────────────────────────

int do_proxy(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy_cfg{};
    if (WinHttpGetIEProxyConfigForCurrentUser(&proxy_cfg)) {
        if (proxy_cfg.lpszAutoConfigUrl) {
            ctx.write_output(std::format("proxy_type|pac"));
            ctx.write_output(
                std::format("proxy_address|{}", from_wide(proxy_cfg.lpszAutoConfigUrl)));
            GlobalFree(proxy_cfg.lpszAutoConfigUrl);
        }
        if (proxy_cfg.lpszProxy) {
            auto proxy = from_wide(proxy_cfg.lpszProxy);
            ctx.write_output(std::format("proxy_type|http"));
            ctx.write_output(std::format("proxy_address|{}", proxy));
            GlobalFree(proxy_cfg.lpszProxy);
        }
        if (proxy_cfg.lpszProxyBypass) {
            ctx.write_output(std::format("bypass|{}", from_wide(proxy_cfg.lpszProxyBypass)));
            GlobalFree(proxy_cfg.lpszProxyBypass);
        }
        if (!proxy_cfg.lpszAutoConfigUrl && !proxy_cfg.lpszProxy) {
            if (proxy_cfg.fAutoDetect) {
                ctx.write_output("proxy_type|auto_detect");
            } else {
                ctx.write_output("proxy_type|none");
            }
        }
    } else {
        ctx.write_output("proxy_type|none");
    }

#elif defined(__linux__)
    bool found = false;
    for (const char* var : {"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy",
                            "ALL_PROXY", "no_proxy", "NO_PROXY"}) {
        const char* val = std::getenv(var);
        if (val && *val) {
            if (std::string_view(var).find("no_proxy") != std::string_view::npos ||
                std::string_view(var).find("NO_PROXY") != std::string_view::npos) {
                ctx.write_output(std::format("bypass|{}", val));
            } else {
                ctx.write_output(std::format("proxy_type|{}", var));
                ctx.write_output(std::format("proxy_address|{}", val));
            }
            found = true;
        }
    }
    if (!found) {
        ctx.write_output("proxy_type|none");
    }

#elif defined(__APPLE__)
#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
    // SCDynamicStoreCopyProxies returns the CURRENT/PRIMARY service's proxy
    // settings at the top level and puts every OTHER configured service in a
    // __SCOPED__ sub-dictionary keyed by interface. Reading only the top level
    // is NOT a superset of the pre-migration leg, which asked for the Wi-Fi
    // service BY NAME (`networksetup -getwebproxy Wi-Fi`): on a Mac whose
    // primary service is Ethernet with the proxy configured on Wi-Fi, the
    // top-level read reports `none` where the old leg reported `http`. That is
    // a silent regression on an action tagged `compliance`, so the scoped
    // services are enumerated too — the same shape the dns_servers leg above
    // already uses for its per-service resolver union.
    yuzu::agent::ScopedCFRef<CFDictionaryRef> proxies(SCDynamicStoreCopyProxies(nullptr));
    bool emitted = false;
    if (proxies) {
        // Decode one proxy dictionary (top-level or scoped) into the pure
        // ProxyServiceConfig the decision function consumes. Acquisition here,
        // decision in network_config_parsers.hpp.
        auto decode = [&](CFDictionaryRef d, std::string service) {
            auto get_bool = [&](CFStringRef key) -> bool {
                const void* v = CFDictionaryGetValue(d, key);
                if (!v)
                    return false;
                if (CFGetTypeID(v) == CFBooleanGetTypeID())
                    return CFBooleanGetValue(static_cast<CFBooleanRef>(v));
                if (CFGetTypeID(v) == CFNumberGetTypeID()) {
                    int val = 0;
                    CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberIntType, &val);
                    return val != 0;
                }
                return false;
            };
            auto get_string = [&](CFStringRef key) -> std::string {
                const void* v = CFDictionaryGetValue(d, key);
                if (!v || CFGetTypeID(v) != CFStringGetTypeID())
                    return {};
                return cfstring_to_utf8(static_cast<CFStringRef>(v));
            };
            auto get_int = [&](CFStringRef key) -> int {
                const void* v = CFDictionaryGetValue(d, key);
                if (!v || CFGetTypeID(v) != CFNumberGetTypeID())
                    return 0;
                int val = 0;
                CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberIntType, &val);
                return val;
            };
            yuzu::network_config::ProxyServiceConfig c;
            c.service = std::move(service);
            c.http_enabled = get_bool(kSCPropNetProxiesHTTPEnable);
            c.http_host = get_string(kSCPropNetProxiesHTTPProxy);
            c.http_port = get_int(kSCPropNetProxiesHTTPPort);
            c.pac_enabled = get_bool(kSCPropNetProxiesProxyAutoConfigEnable);
            c.pac_url = get_string(kSCPropNetProxiesProxyAutoConfigURLString);
            return c;
        };

        // Primary/current service FIRST so it still wins when it has a proxy;
        // scoped services are consulted only when it does not.
        std::vector<yuzu::network_config::ProxyServiceConfig> candidates;
        candidates.push_back(decode(proxies.get(), std::string{}));

        // "__SCOPED__" is an OBSERVED key, not a published one: it carries no
        // kSCPropNetProxies* constant in SCSchemaDefinitions.h on this SDK.
        // Treated strictly as best-effort enrichment — absent or wrongly
        // typed, the code falls back to exactly the top-level-only behaviour,
        // so a future OS that drops or renames it degrades to the previous
        // result rather than failing. Every value is type-checked below.
        const void* scoped_v = CFDictionaryGetValue(proxies.get(), CFSTR("__SCOPED__"));
        if (!scoped_v || CFGetTypeID(scoped_v) != CFDictionaryGetTypeID()) {
            // Falling back to top-level-only is exactly the regression the
            // scoped walk exists to fix (an Ethernet-primary Mac with a Wi-Fi
            // proxy reads as none). It is the right fallback, but it must not
            // be silent — if a future macOS drops or renames this key we want
            // a trace rather than a quiet return to the old behaviour.
            spdlog::debug("network_config: proxies dictionary has no usable __SCOPED__ entry; "
                          "reporting the primary service only");
        }
        if (scoped_v && CFGetTypeID(scoped_v) == CFDictionaryGetTypeID()) {
            auto* scoped = static_cast<CFDictionaryRef>(scoped_v);
            const CFIndex n = CFDictionaryGetCount(scoped);
            std::vector<const void*> keys(static_cast<std::size_t>(n));
            std::vector<const void*> vals(static_cast<std::size_t>(n));
            if (n > 0)
                CFDictionaryGetKeysAndValues(scoped, keys.data(), vals.data());
            for (CFIndex i = 0; i < n; ++i) {
                if (!vals[static_cast<std::size_t>(i)] ||
                    CFGetTypeID(vals[static_cast<std::size_t>(i)]) != CFDictionaryGetTypeID())
                    continue;
                std::string name;
                if (keys[static_cast<std::size_t>(i)] &&
                    CFGetTypeID(keys[static_cast<std::size_t>(i)]) == CFStringGetTypeID())
                    name = cfstring_to_utf8(
                        static_cast<CFStringRef>(keys[static_cast<std::size_t>(i)]));
                candidates.push_back(decode(
                    static_cast<CFDictionaryRef>(vals[static_cast<std::size_t>(i)]), name));
            }
        }

        const auto choice = yuzu::network_config::select_proxy(candidates);
        if (choice.found) {
            ctx.write_output(std::format("proxy_type|{}", choice.type));
            ctx.write_output(std::format("proxy_address|{}", choice.address));
            emitted = true;
        }

        const void* bypass_v =
            CFDictionaryGetValue(proxies.get(), kSCPropNetProxiesExceptionsList);
        auto* bypass_list = (bypass_v && CFGetTypeID(bypass_v) == CFArrayGetTypeID())
                                ? static_cast<CFArrayRef>(bypass_v)
                                : nullptr;
        if (bypass_list) {
            const CFIndex count = CFArrayGetCount(bypass_list);
            std::vector<std::string> entries;
            entries.reserve(static_cast<std::size_t>(count));
            for (CFIndex i = 0; i < count; ++i) {
                const void* item_v = CFArrayGetValueAtIndex(bypass_list, i);
                if (!item_v || CFGetTypeID(item_v) != CFStringGetTypeID())
                    continue; // never call CFString APIs on a non-string element
                entries.push_back(cfstring_to_utf8(static_cast<CFStringRef>(item_v)));
            }
            // Formatting is the pure half (join_bypass_list); the CF walk above
            // is the acquisition half.
            const std::string joined = yuzu::network_config::join_bypass_list(entries);
            if (!joined.empty())
                ctx.write_output(std::format("bypass|{}", joined));
        }
    } else {
        // SCDynamicStoreCopyProxies failed. Falling through to the
        // `proxy_type|none` below unqualified would turn an API failure into
        // the positive assertion "this host has no proxy configured".
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:proxy_copy_failed");
    }
    if (!emitted)
        ctx.write_output("proxy_type|none");
#else
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "network_config:no_systemconfiguration");
    ctx.write_output("proxy_type|none");
#endif
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows reads every leg through native, in-process Win32 APIs (rung 1).
// Linux reads adapters/ip_addresses via rtnetlink (RTM_GETLINK/RTM_GETADDR/
// RTM_GETROUTE, AF_NETLINK SOCK_RAW), dns_servers/proxy via direct file/env
// reads, and arp via a native /proc/net/arp read — all rung 1. dns_cache on
// Linux is the one remaining spawn site, now a direct argv invocation of
// `resolvectl`/`systemd-resolve` (no shell), rung 2. macOS reads
// adapters/ip_addresses via getifaddrs + SIOCGIFMEDIA/PF_ROUTE sysctl,
// dns_servers/proxy via SCDynamicStore, and arp via the PF_ROUTE
// NET_RT_FLAGS/RTF_LLINFO sysctl (agents/shared/route_sysctl_arp.hpp) —
// all rung 1, zero `/bin/sh` occurrences anywhere in this plugin. macOS
// dns_cache stays a permanent OS capability gap (see do_dns_cache's own
// comment): dscacheutil -cachedump was gutted upstream and there is nothing
// left to shell out to.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "adapters",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "rtnetlink (RTM_GETLINK)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getifaddrs + SIOCGIFMEDIA", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "ip_addresses",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "rtnetlink (RTM_GETADDR/RTM_GETROUTE)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getifaddrs + PF_ROUTE sysctl", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "dns_servers",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/etc/resolv.conf read", nullptr},
#if defined(__APPLE__) && !defined(YUZU_HAVE_SYSTEMCONFIGURATION)
        // Built without SystemConfiguration: the leg returns UNAVAILABLE, so
        // the descriptor must not advertise it as supported.
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "built without the SystemConfiguration framework"},
#else
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "SCDynamicStore", nullptr},
#endif
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "proxy",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "environment variables",
         "reads the *_proxy variables from the agent process's own environment only; a "
         "system-wide, desktop-session or package-manager proxy the agent did not inherit is "
         "not reported"},
#if defined(__APPLE__) && !defined(YUZU_HAVE_SYSTEMCONFIGURATION)
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "built without the SystemConfiguration framework"},
#else
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "SCDynamicStoreCopyProxies",
         "reports the HTTP proxy and PAC URL, checking the primary network service first and "
         "then each scoped per-interface service; HTTPS/SOCKS/FTP proxies are not reported, so "
         "a host configured with only those reads as none"},
#endif
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WinHttpGetIEProxyConfigForCurrentUser", nullptr},
    },
    {
        /* .action      = */ "dns_cache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "resolvectl via direct-argv runner",
         "falls back to systemd-resolve statistics, or reports unavailable, when resolvectl is "
         "absent"},
        // macOS: no shell-out is even attempted — dscacheutil -cachedump was
        // gutted upstream and can only fail, a permanent OS capability gap
        // (do_dns_cache's own comment), never a transient failure.
        /* .macos_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "DnsGetCacheDataTable (dnsapi.dll)", nullptr},
    },
    {
        /* .action      = */ "arp",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/proc/net/arp",
         "IPv4 ARP entries only; /proc/net/arp carries no IPv6 neighbours (they live in the "
         "RTM_GETNEIGH table), and non-Ethernet or incomplete entries are not reported"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "PF_ROUTE sysctl RTF_LLINFO",
         "ip and mac only; the interface name and static/dynamic type are not carried by the "
         "RTF_LLINFO dump and are emitted as '-'"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetIpNetTable2", nullptr},
    },
};

} // namespace

class NetworkConfigPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "network_config"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports network adapter configuration, IP addresses, DNS servers, and proxy "
               "settings";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"adapters", "ip_addresses", "dns_servers", "proxy",
                                     "dns_cache", "arp",         nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "adapters")
            return do_adapters(ctx);
        if (action == "ip_addresses")
            return do_ip_addresses(ctx);
        if (action == "dns_servers")
            return do_dns_servers(ctx);
        if (action == "proxy")
            return do_proxy(ctx);
        if (action == "dns_cache")
            return do_dns_cache(ctx);
        if (action == "arp")
            return do_arp(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    // arp|iface|ip|mac|type — the host ARP / IPv6-neighbour table. Windows reads the
    // kernel neighbour cache via GetIpNetTable2(AF_UNSPEC); Linux reads /proc/net/arp
    // natively; macOS reads the PF_ROUTE NET_RT_FLAGS/RTF_LLINFO sysctl via
    // agents/shared/route_sysctl_arp.hpp, reused as-is. Mirrors the proven
    // enumeration in tar_arp_collector.cpp (reimplemented here — the TAR plugin
    // internals aren't linked into network_config).
    // Cap entries so a large or forged neighbour table can't produce an
    // unbounded response (mirrors the TAR collector's posture). Shared by all
    // three platform legs -- /proc/net/arp and the PF_ROUTE RTF_LLINFO dump
    // are just as capable of an oversized or spoofed table as GetIpNetTable2.
    static constexpr std::size_t kArpEntryCap = 20000;

    static int do_arp(yuzu::CommandContext& ctx) {
#ifdef _WIN32

        auto state_to_type = [](NL_NEIGHBOR_STATE st) -> const char* {
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
        };
        auto mac_string = [](const UCHAR* addr, ULONG len) -> std::string {
            if (len == 0)
                return "-"; // incomplete entry — no hardware address yet
            std::string out;
            static const char* kHex = "0123456789abcdef";
            for (ULONG i = 0; i < len; ++i) {
                if (i)
                    out += ':';
                out += kHex[addr[i] >> 4];
                out += kHex[addr[i] & 0x0F];
            }
            return out;
        };
        auto ip_string = [](const SOCKADDR_INET& a) -> std::string {
            char buf[INET6_ADDRSTRLEN]{};
            if (a.si_family == AF_INET)
                inet_ntop(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf));
            else if (a.si_family == AF_INET6)
                inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf));
            return buf;
        };
        auto iface_name = [](const NET_LUID& luid, NET_IFINDEX idx) -> std::string {
            wchar_t alias[IF_MAX_STRING_SIZE + 1]{};
            if (ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) == NO_ERROR)
                return from_wide(alias);
            return std::format("if{}", static_cast<unsigned long>(idx));
        };

        PMIB_IPNET_TABLE2 table = nullptr;
        DWORD rc = GetIpNetTable2(AF_UNSPEC, &table);
        if (rc != NO_ERROR || table == nullptr) {
            ctx.write_output(std::format("error|GetIpNetTable2 failed (rc={})", rc));
            return 1;
        }
        // RAII owner: FreeMibTable runs on every scope exit, including an exception
        // thrown by std::format / write_output between here and the end of the loop
        // (a manual FreeMibTable would leak the kernel table on that path).
        // Non-copyable: a copy would duplicate `t` and both destructors would call
        // FreeMibTable on the same kernel table pointer (double-free). Mirrors
        // SocketGuard above (~:91-100).
        struct MibTableGuard {
            PMIB_IPNET_TABLE2 t;
            explicit MibTableGuard(PMIB_IPNET_TABLE2 tbl) : t(tbl) {}
            ~MibTableGuard() { if (t) FreeMibTable(t); }
            MibTableGuard(const MibTableGuard&) = delete;
            MibTableGuard& operator=(const MibTableGuard&) = delete;
        } table_guard{table};
        ULONG emitted = 0;
        for (ULONG i = 0; i < table->NumEntries && emitted < kArpEntryCap; ++i) {
            const MIB_IPNET_ROW2& row = table->Table[i];
            std::string ip = ip_string(row.Address);
            if (ip.empty())
                continue; // address failed to format — skip defensively
            ctx.write_output(std::format(
                "arp|{}|{}|{}|{}", iface_name(row.InterfaceLuid, row.InterfaceIndex), ip,
                mac_string(row.PhysicalAddress, row.PhysicalAddressLength),
                state_to_type(row.State)));
            ++emitted;
        }
        if (table->NumEntries > kArpEntryCap) {
            // Every other truncation path in this file reports a degraded
            // status; hitting the row cap must too, or a genuinely large (or
            // locally inflated) table silently reports as a complete small one.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:arp_row_cap_reached");
        }
        return 0; // ~MibTableGuard frees the table on every path

#elif defined(__linux__)
        std::ifstream in("/proc/net/arp");
        if (!in) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:proc_net_arp_unreadable");
            // "error|..." (matching the Windows leg), not "arp|...": the
            // documented arp row shape is 5 fields (arp|iface|ip|mac|type),
            // so a failure sentinel under the "arp|" prefix would emit a
            // 2-field row breaking that contract for any consumer that
            // trusts the prefix to imply the shape.
            ctx.write_output("error|/proc/net/arp unreadable");
            return 0;
        }
        std::ostringstream contents;
        contents << in.rdbuf();
        if (in.bad()) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:proc_net_arp_read_error");
            ctx.write_output("error|/proc/net/arp read error");
            return 0;
        }
        const auto entries = yuzu::network_config::parse_proc_net_arp(contents.str());
        std::size_t emitted = 0;
        for (const auto& e : entries) {
            if (emitted >= kArpEntryCap)
                break;
            ctx.write_output(std::format("arp|{}|{}|{}|{}", e.iface, e.ip, e.mac, e.type));
            ++emitted;
        }
        if (entries.size() > kArpEntryCap) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:arp_row_cap_reached");
        }
        return 0;

#elif defined(__APPLE__)
        auto fetched = yuzu::shared::fetch_rt_flags_llinfo();
        if (!fetched.ok) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:pf_route_arp_sysctl_failed");
            // "error|..." — see the Linux leg's identical note above.
            ctx.write_output("error|PF_ROUTE ARP sysctl failed");
            return 0;
        }
        auto parsed = yuzu::shared::parse_rt_flags_llinfo(fetched.blob);
        if (parsed.truncated) {
            // CONSTRAINED, matching every other truncation path in this file
            // (rtnetlink dumps, PF_ROUTE default route). OK+PARTIAL is legal
            // per the SDK but was the odd one out.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:pf_route_arp_truncated");
        }
        // route_sysctl_arp.hpp's ArpRecord carries only {ip, mac} — no
        // interface index and no static/dynamic distinction (RTF_LLINFO
        // mixes both without differentiating). Reused as-is (owned by an
        // earlier package); iface/type are honestly reported as unknown ("-")
        // rather than guessed.
        //
        // The NET_RT_FLAGS/RTF_LLINFO sysctl dump can report the same
        // {ip, mac} neighbour twice on a real host (PKG-NC fix round: live
        // before/after parity diff caught duplicated rows) — dedupe on the
        // formatted output line, preserving first-seen order, rather than
        // trusting the sysctl walk to be 1:1 with distinct neighbours.
        std::vector<std::string> lines;
        lines.reserve(parsed.records.size());
        for (const auto& rec : parsed.records)
            lines.push_back(std::format("arp|-|{}|{}|-", rec.ip, rec.mac));
        const auto deduped = yuzu::network_config::dedupe_preserve_order(lines);
        std::size_t emitted = 0;
        for (const auto& line : deduped) {
            if (emitted >= kArpEntryCap)
                break;
            ctx.write_output(line);
            ++emitted;
        }
        if (deduped.size() > kArpEntryCap) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:arp_row_cap_reached");
        }
        return 0;

#else
        // Honest sentinel: no ARP mechanism on this platform. "error|..." —
        // see the Linux leg's note above; keeps "arp|" reserved for real
        // 5-field rows on every leg, this one included.
        ctx.write_output("error|no ARP mechanism on this platform");
        return 0;
#endif
    }

    static int do_dns_cache(yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // Dynamically load DnsGetCacheDataTable from dnsapi.dll
        using DNS_CACHE_ENTRY = struct _DNS_CACHE_ENTRY {
            struct _DNS_CACHE_ENTRY* pNext;
            PWSTR pszName;
            WORD wType;
            WORD wDataLength;
            DWORD dwFlags;
        };
        using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DNS_CACHE_ENTRY*);

        auto hDnsApi = LoadLibraryA("dnsapi.dll");
        if (!hDnsApi) {
            ctx.write_output("dns_cache|not_available|dnsapi.dll not found");
            return 0;
        }

        auto pFunc = reinterpret_cast<DnsGetCacheDataTableFn>(
            GetProcAddress(hDnsApi, "DnsGetCacheDataTable"));
        if (!pFunc) {
            FreeLibrary(hDnsApi);
            ctx.write_output("dns_cache|not_available|DnsGetCacheDataTable not found");
            return 0;
        }

        DNS_CACHE_ENTRY root{};
        if (pFunc(&root)) {
            int count = 0;
            for (auto* entry = root.pNext; entry; entry = entry->pNext) {
                if (entry->pszName) {
                    auto name = from_wide(entry->pszName);
                    // wType: 1=A, 28=AAAA, 5=CNAME, etc.
                    const char* type = "unknown";
                    switch (entry->wType) {
                    case 1:
                        type = "A";
                        break;
                    case 28:
                        type = "AAAA";
                        break;
                    case 5:
                        type = "CNAME";
                        break;
                    case 12:
                        type = "PTR";
                        break;
                    case 15:
                        type = "MX";
                        break;
                    case 33:
                        type = "SRV";
                        break;
                    }
                    ctx.write_output(std::format("cache_entry|{}|{}|0|", name, type));
                    ++count;
                }
            }
            if (count == 0) {
                ctx.write_output("dns_cache|empty");
            }
        } else {
            ctx.write_output("dns_cache|not_available|query failed");
        }
        FreeLibrary(hDnsApi);

#elif defined(__linux__)
        // Direct argv via the bounded runner (ADR-3002 rung 2) — no `/bin/sh
        // -c`, argv[0] resolved by probe_tool_path so a missing binary is
        // caught BEFORE exec rather than sniffed from captured text.
        auto resolvectl_path =
            yuzu::agent::probe_tool_path({"/usr/bin/resolvectl", "/bin/resolvectl"});
        if (!resolvectl_path.empty()) {
            auto res = yuzu::agent::run_bounded_subprocess(
                {resolvectl_path, "cache"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
            if (yuzu::agent::forward_runner_failure(ctx, res))
                return 0; // status already set — an honest CONSTRAINED/UNAVAILABLE, not silence
            if (res.tool_ran && res.exit_code == 0) {
                int emitted = 0;
                for (const auto& line :
                    yuzu::network_config::parse_resolvectl_cache_lines(res.output)) {
                    ctx.write_output(std::format("cache_entry|{}", line));
                    ++emitted;
                }
                // Only claim the action if something was actually reported.
                // The pre-migration leg guarded this branch on non-empty
                // output, so a successful-but-empty `resolvectl cache` fell
                // through to the statistics fallback and ultimately to the
                // `dns_cache|not_available` sentinel. Returning here on zero
                // rows would instead hand back an empty, STATUS-OK response --
                // no rows, no sentinel, no degradation signal — which every
                // other dns_cache path on every other platform avoids.
                if (emitted > 0)
                    return 0;
            }
            // resolvectl ran but exited nonzero (e.g. no systemd-resolved
            // running), or produced no cache rows — fall through to the
            // systemd-resolve statistics fallback, same behaviour as the
            // pre-migration shell-out.
        }

        auto systemd_resolve_path =
            yuzu::agent::probe_tool_path({"/usr/bin/systemd-resolve", "/bin/systemd-resolve"});
        if (!systemd_resolve_path.empty()) {
            auto res = yuzu::agent::run_bounded_subprocess(
                {systemd_resolve_path, "--statistics"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
            if (yuzu::agent::forward_runner_failure(ctx, res))
                return 0;
            if (res.tool_ran && res.exit_code == 0) {
                auto lines = yuzu::network_config::parse_systemd_resolve_stats_lines(res.output);
                if (!lines.empty()) {
                    for (const auto& line : lines)
                        ctx.write_output(std::format("dns_stats|{}", line));
                    return 0;
                }
            }
        }

        // The ABI4 descriptor for this leg promises it "reports unavailable
        // when resolvectl is absent" — so it must actually set the status,
        // not just emit an in-band sentinel that leaves the result OK.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:no_resolver_cache_tool");
        ctx.write_output("dns_cache|not_available|no systemd-resolved");

#elif defined(__APPLE__)
        // macOS does not expose resolver-cache CONTENTS to userspace. dscacheutil
        // -cachedump was gutted years ago: on macOS 26 it prints "Unable to get
        // details from the cache node" to stderr and exits 0 (see darwin-compat).
        // So there is nothing to shell out to — it can only ever fail. This is a
        // permanent OS capability gap, not a transient failure, so report it as
        // such rather than the ambiguous not_available (which invites a pointless
        // retry and reads like a query that might succeed next time).
        ctx.write_output("dns_cache|unsupported|macOS does not expose DNS resolver cache contents");
#endif
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(NetworkConfigPlugin)
