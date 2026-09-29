// test_socket_walk.cpp — macos_socket_walk.hpp coverage (agents/shared).
//
// Darwin-only: the header itself is #ifdef __APPLE__-gated (a no-op TU
// elsewhere), so this file no-ops identically off Darwin via the same guard
// rather than being excluded at the meson level.
//
// Binds a real ephemeral 127.0.0.1 TCP listener in-test and walks the live
// socket table for it — the only way to prove the libproc walk actually
// finds a socket this process owns (a fixture/mock would just re-assert the
// parsing logic, not the syscall sequence).
#ifdef __APPLE__

#include <catch2/catch_test_macros.hpp>

#include <macos_socket_walk.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

using yuzu::shared::SocketInfo;
using yuzu::shared::walk_sockets;

namespace {

// RAII ephemeral TCP listener bound to 127.0.0.1:0 (kernel-assigned port).
// The socket fd is a ScopedFd assigned immediately on acquisition (gate-2
// /adversarial-review remediation): a REQUIRE below it that fails throws
// and unwinds before this constructor completes, and C++ never runs a
// not-fully-constructed object's OWN destructor -- but an already-
// constructed member subobject (this ScopedFd) IS destroyed during that
// same unwind, so the fd still gets closed instead of leaking (confirmed
// live: this exact path fires under a sandbox that denies loopback bind()).
struct EphemeralListener {
    yuzu::agent::ScopedFd fd;
    uint16_t port{0};

    EphemeralListener() {
        fd = yuzu::agent::ScopedFd(::socket(AF_INET, SOCK_STREAM, 0));
        REQUIRE(fd.valid());

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0; // ask the kernel for an ephemeral port
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        REQUIRE(::bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(fd.get(), 1) == 0);

        struct sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&bound), &len) == 0);
        port = ntohs(bound.sin_port);
        REQUIRE(port != 0);
    }

    EphemeralListener(const EphemeralListener&) = delete;
    EphemeralListener& operator=(const EphemeralListener&) = delete;
};

} // namespace

TEST_CASE("walk_sockets finds this process's own LISTEN socket", "[agent][socket_walk]") {
    EphemeralListener listener;
    const pid_t self = getpid();

    auto sockets = walk_sockets(/*dedup=*/true);
    REQUIRE_FALSE(sockets.empty());

    auto it = std::find_if(sockets.begin(), sockets.end(), [&](const SocketInfo& s) {
        return s.pid == self && s.local_port == listener.port;
    });

    REQUIRE(it != sockets.end());
    CHECK((it->proto == "tcp" || it->proto == "tcp6"));
    CHECK(it->state == "LISTEN");
}

TEST_CASE("walk_sockets dedup collapses a duplicated fd", "[agent][socket_walk]") {
    EphemeralListener listener;
    const pid_t self = getpid();

    // dup() the listening fd so the identical socket appears under two fds of
    // the same process — the shape a fork also produces (shared underlying
    // socket, distinct fd numbers). The walk keys dedup on
    // proto+local+remote, not fd, so this collapses to one row either way;
    // dup() is what the same-process test binary can control deterministically.
    // ScopedFd immediately on acquisition, same reasoning as EphemeralListener
    // above -- no throwing statement currently sits between this dup() and
    // its close, but a ScopedFd removes that as a standing precondition
    // rather than relying on it staying true across future edits.
    yuzu::agent::ScopedFd dup_fd(::dup(listener.fd.get()));
    REQUIRE(dup_fd.valid());

    auto count_matching = [&](const std::vector<SocketInfo>& v) {
        return std::count_if(v.begin(), v.end(), [&](const SocketInfo& s) {
            return s.pid == self && s.local_port == listener.port;
        });
    };

    // Without dedup, the duplicated fd is a second (pid, fd) hit on the same
    // socket -- proves the flag actually changes behaviour, not merely that
    // the walk always returns one row for this port regardless of the flag.
    auto not_deduped = walk_sockets(/*dedup=*/false);
    CHECK(count_matching(not_deduped) >= 2);

    auto deduped = walk_sockets(/*dedup=*/true);
    CHECK(count_matching(deduped) == 1);
}

#endif // __APPLE__
