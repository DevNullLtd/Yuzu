// test_raw_listener.hpp -- a raw loopback TCP listener for delivery-store tests (webhook, offload):
// it accepts a connection, reads the request bytes and drops the connection without answering, so the
// client sees a READ error AFTER connecting. `accepted` counts connections, i.e. POSTs that arrived.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>

namespace yuzu::test {

// A raw TCP listener on `family` loopback. `reply_close`: accept, read the request bytes and close
// without answering (the client sees a read error AFTER connecting); counts accepted connections.
struct RawListener {
    int fd{-1};
    int port{0};
    std::atomic<int> accepted{0};
    std::atomic<bool> stop{false};
    std::thread th;
    bool open(int family, int want_port) {
        fd = ::socket(family, SOCK_STREAM, 0);
        if (fd < 0) return false;
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (family == AF_INET) {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(static_cast<uint16_t>(want_port));
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
            socklen_t len = sizeof(a);
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
            port = ntohs(a.sin_port);
        } else {
            int v6only = 1;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            sockaddr_in6 a{};
            a.sin6_family = AF_INET6;
            a.sin6_port = htons(static_cast<uint16_t>(want_port));
            a.sin6_addr = in6addr_loopback;
            if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
            socklen_t len = sizeof(a);
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
            port = ntohs(a.sin6_port);
        }
        if (::listen(fd, 8) != 0) return false;
        th = std::thread([this] {
            while (!stop.load()) {
                timeval tv{0, 100000};
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                if (::select(fd + 1, &fds, nullptr, nullptr, &tv) <= 0) continue;
                const int c = ::accept(fd, nullptr, nullptr);
                if (c < 0) continue;
                ++accepted;
                char buf[4096];
                (void)::read(c, buf, sizeof(buf)); // take the request, then drop the connection
                ::close(c);
            }
        });
        return true;
    }
    ~RawListener() {
        stop = true;
        if (th.joinable()) th.join();
        if (fd >= 0) ::close(fd);
    }
};

/// A v4 and a v6 listener on the SAME loopback port.
struct DualPair {
    std::unique_ptr<RawListener> v4, v6;
};

/// Bind both, retrying with other ports (the v6 side can find the v4 port taken). Returns nullopt
/// only when no pair could be bound after `attempts` (no IPv6 loopback in this environment): the
/// caller SKIPs with that reason; it never passes silently.
inline std::optional<DualPair> open_dual_stack_pair(int attempts = 25) {
    for (int i = 0; i < attempts; ++i) {
        auto a = std::make_unique<RawListener>();
        auto b = std::make_unique<RawListener>();
        if (a->open(AF_INET, 0) && b->open(AF_INET6, a->port))
            return DualPair{std::move(a), std::move(b)};
    }
    return std::nullopt;
}
} // namespace yuzu::test
