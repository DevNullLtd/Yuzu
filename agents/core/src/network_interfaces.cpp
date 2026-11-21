/**
 * network_interfaces.cpp -- Cross-platform local-IP enumeration
 *
 * Linux/macOS: getifaddrs(3)
 * Windows:     GetAdaptersAddresses (iphlpapi)
 */

#include <yuzu/agent/network_interfaces.hpp>

#include <optional>
#include <set>
#include <string>
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
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::agent {

namespace {

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)

bool is_ipv4_loopback(const in_addr& addr) {
    // 127.0.0.0/8
    return (ntohl(addr.s_addr) & 0xff000000u) == 0x7f000000u;
}

bool is_ipv4_link_local(const in_addr& addr) {
    // 169.254.0.0/16
    return (ntohl(addr.s_addr) & 0xffff0000u) == 0xa9fe0000u;
}

bool is_ipv6_loopback(const in6_addr& addr) {
    return IN6_IS_ADDR_LOOPBACK(&addr) != 0;
}

bool is_ipv6_link_local(const in6_addr& addr) {
    return IN6_IS_ADDR_LINKLOCAL(&addr) != 0;
}

#endif

} // namespace

#ifdef _WIN32

namespace {

// One walk behind both public functions. include_local_scopes = false drops
// loopback and link-local (the fleet-identification view); true keeps them
// and the software-loopback adapter (every address this host answers to).
// nullopt = the OS read failed, which is not the same as "no addresses".
std::optional<std::set<std::string>> collect(bool include_local_scopes) {
    constexpr ULONG kFlags =
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
    // An adapter added between the sizing call and the read grows the table again, so
    // the buffer is re-sized on every ERROR_BUFFER_OVERFLOW, up to three reads in all.
    constexpr int kMaxReads = 3;

    ULONG bufsize = 16 * 1024;
    std::vector<unsigned char> buf(bufsize);
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < kMaxReads && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(bufsize);
        rc = GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &bufsize);
    }
    if (rc != ERROR_SUCCESS)
        return std::nullopt;

    std::set<std::string> uniq;
    char text_buf[INET6_ADDRSTRLEN];

    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp)
            continue;
        if (!include_local_scopes && adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr;
             unicast = unicast->Next) {
            const auto* sa = unicast->Address.lpSockaddr;
            if (!sa)
                continue;
            if (sa->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
                if (!include_local_scopes &&
                    (is_ipv4_loopback(sin->sin_addr) || is_ipv4_link_local(sin->sin_addr)))
                    continue;
                if (inet_ntop(AF_INET, &sin->sin_addr, text_buf, sizeof(text_buf)))
                    uniq.emplace(text_buf);
            } else if (sa->sa_family == AF_INET6) {
                const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
                if (!include_local_scopes &&
                    (is_ipv6_loopback(sin6->sin6_addr) || is_ipv6_link_local(sin6->sin6_addr)))
                    continue;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, text_buf, sizeof(text_buf)))
                    uniq.emplace(text_buf);
            }
        }
    }
    return uniq;
}

} // namespace

#elif defined(__linux__) || defined(__APPLE__)

namespace {

// See the Windows copy above: one walk, loopback and link-local kept only when asked.
std::optional<std::set<std::string>> collect(bool include_local_scopes) {
    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0)
        return std::nullopt;

    std::set<std::string> uniq;
    char text_buf[INET6_ADDRSTRLEN];

    for (ifaddrs* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_addr)
            continue;
        if (p->ifa_addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
            if (!include_local_scopes &&
                (is_ipv4_loopback(sin->sin_addr) || is_ipv4_link_local(sin->sin_addr)))
                continue;
            if (inet_ntop(AF_INET, &sin->sin_addr, text_buf, sizeof(text_buf)))
                uniq.emplace(text_buf);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(p->ifa_addr);
            if (!include_local_scopes &&
                (is_ipv6_loopback(sin6->sin6_addr) || is_ipv6_link_local(sin6->sin6_addr)))
                continue;
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, text_buf, sizeof(text_buf)))
                uniq.emplace(text_buf);
        }
    }

    freeifaddrs(head);
    return uniq;
}

} // namespace

#endif

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)

std::vector<std::string> enumerate_local_ips() {
    const auto addrs = collect(/*include_local_scopes=*/false);
    return addrs ? std::vector<std::string>(addrs->begin(), addrs->end())
                 : std::vector<std::string>{};
}

std::optional<std::vector<std::string>> enumerate_own_addresses() {
    const auto addrs = collect(/*include_local_scopes=*/true);
    if (!addrs)
        return std::nullopt;
    return std::vector<std::string>(addrs->begin(), addrs->end());
}

#else

std::vector<std::string> enumerate_local_ips() {
    return {};
}

std::optional<std::vector<std::string>> enumerate_own_addresses() {
    return std::nullopt;
}

#endif

#ifdef _WIN32

namespace {
// Process-static WSA initialiser. gethostname is a Winsock function and
// returns WSANOTINITIALISED until WSAStartup runs. cloud_identity.cpp owns
// a sibling initialiser; this one keeps network_interfaces.cpp self-contained
// so callers don't have to reason about which other module ran first.
struct WsaInitializer {
    WsaInitializer() {
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WsaInitializer() { WSACleanup(); }
};
const WsaInitializer kWsaInit;
} // namespace

std::string get_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) != 0)
        return {};
    return std::string(buf);
}

#elif defined(__linux__) || defined(__APPLE__)

std::string get_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) != 0)
        return {};
    return std::string(buf);
}

#else

std::string get_hostname() {
    return {};
}

#endif

} // namespace yuzu::agent
