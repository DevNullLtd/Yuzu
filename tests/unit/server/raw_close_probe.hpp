#pragma once

/// @file raw_close_probe.hpp
/// Raw-socket probe for "did the server close the connection after this response". POSIX only
/// (the callers are already `#ifndef _WIN32`).
///
/// WHY a raw socket and not `httplib::Client`: the Client sends `Connection: close` itself by
/// default (keep-alive is off) and the server echoes it, so a header check through the Client
/// passes even when the server never adds the header, and for a declared body of 1024 bytes or
/// more it sends `Expect: 100-continue` and stops to wait for an early response before it sends
/// the body. This probe sends exactly the bytes it is given, with no `Connection` header, reads
/// the response head, then waits (5 s by default) for EOF: EOF means the server closed the
/// connection, a timeout means it is still holding it (reading the declared body, or keep-alive).

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#ifndef _WIN32
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>

namespace yuzu::test {

struct CloseProbeResult {
    std::string head;    ///< status line + headers (up to the blank line, plus whatever came with it)
    bool closed = false; ///< the server ended the connection within the wait (EOF or reset)
    /// A read failed with an errno that is neither "closed" (ECONNRESET, EPIPE, ECONNABORTED) nor
    /// a wait expiry. `closed` stays false and the probe has already recorded a failing CHECK, so
    /// an unrelated socket error is never counted as the server closing the connection.
    bool failed = false;
};

/// Request bytes: a chunked POST whose terminating 0-chunk never arrives, and a POST that declares
/// 64 MiB and sends 5 bytes. Neither carries a `Connection` header.
inline constexpr const char* kChunkedPostRequest =
    "POST /anything HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
    "5\r\nhello\r\n";
inline constexpr const char* kLengthPostRequest =
    "POST /anything HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 67108864\r\n\r\nhello";
/// An empty `Transfer-Encoding:` line followed by `chunked`: `get_header_value` reads the first
/// line (empty), httplib reads the last (chunked).
inline constexpr const char* kEmptyThenChunkedPostRequest =
    "POST /anything HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding:\r\n"
    "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";

inline CloseProbeResult probe_for_close(int port, const std::string& request,
                                        std::chrono::seconds wait = std::chrono::seconds(5)) {
    struct Fd {
        int v;
        explicit Fd(int f) : v(f) {}
        ~Fd() {
            if (v >= 0)
                ::close(v);
        }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    } sock{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(sock.v >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(wait.count());
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    REQUIRE(::send(sock.v, request.data(), request.size(), 0) ==
            static_cast<ssize_t>(request.size()));

    CloseProbeResult out;
    char buf[1024];
    // SO_RCVTIMEO bounds each recv; this deadline bounds the EINTR retries (a retried recv starts
    // a fresh SO_RCVTIMEO window) and the data path below. Same as the socket timeout.
    const auto deadline = std::chrono::steady_clock::now() + wait;
    while (out.head.find("\r\n\r\n") == std::string::npos) {
        const ssize_t n = ::recv(sock.v, buf, sizeof(buf), 0);
        if (n < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline)
            continue;
        REQUIRE(n > 0);
        out.head.append(buf, static_cast<std::size_t>(n));
    }
    for (;;) {
        const ssize_t n = ::recv(sock.v, buf, sizeof(buf), 0);
        if (n == 0) {
            out.closed = true; // FIN
            break;
        }
        if (n > 0) {
            // Data after the head (a body the server is still writing): keep reading, but not
            // past the deadline, so a server that never stops sending cannot hold the probe.
            if (std::chrono::steady_clock::now() >= deadline)
                break;
            continue;
        }
        if (n < 0) {
            const int err = errno;
            if (err == EINTR && std::chrono::steady_clock::now() < deadline)
                continue;
            // SO_RCVTIMEO expiry (EAGAIN / EWOULDBLOCK, or EINTR past the deadline) means the
            // connection is still open. ECONNRESET / EPIPE / ECONNABORTED mean the server ended it
            // (a close with unread data may reset instead of FIN on some platforms). Anything else
            // is a probe failure, not evidence about the server.
            if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
                break;
            if (err == ECONNRESET || err == EPIPE || err == ECONNABORTED) {
                out.closed = true;
                break;
            }
            out.failed = true;
            FAIL_CHECK("probe_for_close: recv failed with errno " << err << " ("
                                                                  << std::strerror(err) << ")");
            break;
        }
    }
    return out;
}

} // namespace yuzu::test
#endif // !_WIN32
