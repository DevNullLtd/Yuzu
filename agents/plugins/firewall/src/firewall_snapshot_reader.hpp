#pragma once

/**
 * firewall_snapshot_reader.hpp -- the client of the root snapshot broker's AF_UNIX socket
 * (docs/adr/3007-os-activated-read-helpers.md). Linux only.
 *
 * It lives in its own header, away from the plugin shell, so the one function that talks to the
 * socket is the same code in the plugin and in its unit and live tests: a reader the tests could
 * only reach by copy would be pinned lexically and never run. It connects, sends NOTHING and reads to
 * end of stream, with every wait bounded by one deadline; the reply is untrusted text that the pure
 * parsers in firewall_parsers.hpp frame and decide. No process is spawned.
 */

#if defined(__linux__)

#include "firewall_parsers.hpp"

#include <yuzu/agent/scoped_fd.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <expected>
#include <string>
#include <string_view>

#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace yuzu::firewall {

/// Time left until `deadline`, clamped to zero (never negative).
[[nodiscard]] inline std::chrono::milliseconds
remaining_ms(std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline)
        return std::chrono::milliseconds{0};
    return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
}

/// One read of the broker at `socket_path`: the reply text, or the token that says why there is none.
/// An EMPTY token means no broker is installed there (ENOENT) and is not reported. Tokens:
/// connect:eacces, connect:refused, connect:busy, connect:errno:<n>, peer_not_root, timeout,
/// oversized, io_error. `peer_uid` is the uid the listener must have: the plugin passes 0 (the socket
/// must have been made by root); a test that cannot be root passes its own.
[[nodiscard]] inline std::expected<std::string, std::string>
read_fw_snapshot(std::string_view socket_path, std::chrono::steady_clock::time_point deadline,
                 ::uid_t peer_uid = 0) {
    sockaddr_un addr{};
    if (socket_path.size() >= sizeof(addr.sun_path))
        return std::unexpected(std::string{"io_error"}); // the path does not fit sockaddr_un with its NUL
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());

    // Non-blocking from creation and owned by a ScopedFd: every return below closes it, and
    // nothing else closes it (the single release path).
    yuzu::agent::ScopedFd sock(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (!sock)
        return std::unexpected(std::string{"io_error"});
    // sockaddr_un is passed as a sockaddr for the call only: the kernel copies sizeof(addr) bytes
    // and nothing here reads through the cast (docs/cpp-conventions.md, aliasing).
    if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0)
        return std::unexpected(snapshot_connect_token(errno));

    // The socket must have been made by the expected uid (root): for a connected unix socket
    // SO_PEERCRED is the credentials of the process that listen()ed, so a socket file an unprivileged
    // account put at this path is refused before a byte of it is read.
    ucred cred{};
    socklen_t cred_len = sizeof(cred);
    if (::getsockopt(sock.get(), SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0 || cred_len != sizeof(cred))
        return std::unexpected(std::string{"io_error"});
    if (cred.uid != peer_uid)
        return std::unexpected(std::string{"peer_not_root"});

    std::string text;
    char buf[16 * 1024];
    for (;;) {
        const auto left = remaining_ms(deadline);
        if (left.count() <= 0)
            return std::unexpected(std::string{"timeout"});
        pollfd pfd{sock.get(), POLLIN, 0};
        // clamped: a deadline more than INT_MAX milliseconds away must not wrap to a negative poll
        // timeout, which poll() reads as unbounded
        const int ready = ::poll(&pfd, 1, static_cast<int>(std::min<std::chrono::milliseconds::rep>(left.count(), INT_MAX)));
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return std::unexpected(std::string{"io_error"});
        }
        if (ready == 0)
            return std::unexpected(std::string{"timeout"});
        const ssize_t n = ::read(sock.get(), buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return std::unexpected(std::string{"io_error"});
        }
        if (n == 0)
            return text; // end of stream: the broker has sent everything it will
        text.append(buf, static_cast<std::size_t>(n));
        if (text.size() > kFwSnapshotMaxBytes)
            return std::unexpected(std::string{"oversized"});
    }
}

} // namespace yuzu::firewall

#endif // __linux__
