/**
 * server_address_resolver.cpp -- see server_address_resolver.hpp for the
 * contract.
 */

#include <yuzu/agent/server_address_resolver.hpp>

#include <yuzu/agent/server_address_parsers.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> // getaddrinfo/inet_ntop
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h> // inet_ntop
#include <netdb.h>     // getaddrinfo
#include <sys/socket.h>
#endif

#include <bounded_wait.hpp> // yuzu::shared::bounded_call (agents/shared)
#include <icmp_probe.hpp>   // yuzu::shared::AddrInfoGuard (agents/shared)

#include <chrono>
#include <functional>
#include <vector>

namespace yuzu::agent {

namespace {

#ifdef _WIN32
// Idempotent Winsock init (getaddrinfo requires it) -- same RAII-static
// pattern as agents/core/src/cloud_identity.cpp's ensure_wsa(), duplicated
// locally rather than shared for the same reason that file's own comment
// gives: this call is self-contained and has no cross-module reason to
// route through it.
void ensure_wsa_init() {
    struct WsaInit {
        WsaInit() {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WsaInit() { WSACleanup(); }
    };
    static WsaInit init;
    (void)init;
}
#endif

// Blocking getaddrinfo() call -- run only on bounded_call()'s detached
// thread below, never directly on the caller's thread. Adopts the result
// into yuzu::shared::AddrInfoGuard IMMEDIATELY on success, before any
// allocating operation (std::string construction, vector growth) that
// could throw and leak the chain.
std::vector<std::string> getaddrinfo_literals(const std::string& host) {
    std::vector<std::string> out;
#ifdef _WIN32
    ensure_wsa_init();
#endif
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* raw = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &raw) != 0 || !raw)
        return out;
    yuzu::shared::AddrInfoGuard guard{raw};
    for (auto* p = guard.p; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        const void* addr = nullptr;
        if (p->ai_family == AF_INET)
            addr = &reinterpret_cast<struct sockaddr_in*>(p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6)
            addr = &reinterpret_cast<struct sockaddr_in6*>(p->ai_addr)->sin6_addr;
        else
            continue;
        if (::inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
            std::string lit{buf};
            bool dup = false;
            for (const auto& existing : out) {
                if (existing == lit) {
                    dup = true;
                    break;
                }
            }
            if (!dup)
                out.push_back(std::move(lit));
        }
    }
    return out;
}

} // namespace

namespace detail {

std::string
resolve_bounded(std::string_view target, std::chrono::milliseconds deadline,
                 const std::function<std::vector<std::string>(const std::string&)>& resolve) {
    const std::string host = extract_server_host(target);
    if (host.empty())
        return {};
    if (looks_like_ip_literal(host))
        return host;

    // Bounded: agent startup must never hang indefinitely on a wedged
    // resolver (an NSS module against a degraded domain controller has no
    // reliable timeout of its own to fall back on). yuzu::shared::bounded_call
    // runs `resolve` on a DETACHED thread and waits on a condition variable
    // for `deadline` -- unlike a plain std::async(std::launch::async, ...)
    // future, whose destructor blocks the calling thread until the task
    // finishes even after its own wait_for() has already timed out
    // ([futures.async]) -- that was this file's round-3 bug: the caller
    // looked bounded but still hung on a wedged resolver. `resolve` and
    // `host` are captured BY VALUE into bounded_call's lambda, not by
    // reference into this function's parameters -- the detached thread can
    // outlive this function's return past the deadline, so anything it
    // touches must not depend on this stack frame (safe here specifically
    // because this whole translation unit lives in agent-core, never
    // dlclose()'d, so a late-arriving result is simply discarded rather
    // than racing an unload -- the risk this exact shape would carry
    // inside a PLUGIN).
    auto result =
        yuzu::shared::bounded_call(deadline, [resolve, host]() { return resolve(host); });
    if (!result)
        return {};

    std::string joined;
    for (size_t i = 0; i < result->size(); ++i) {
        if (i)
            joined += ",";
        joined += (*result)[i];
    }
    return joined;
}

} // namespace detail

std::string resolve_server_address_literals(std::string_view target) {
    constexpr auto kResolveDeadline = std::chrono::seconds(5);
    return detail::resolve_bounded(target, kResolveDeadline, getaddrinfo_literals);
}

} // namespace yuzu::agent
