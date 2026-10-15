/**
 * network_config_netlink.hpp — shared rtnetlink dump mechanics for the
 * network_config plugin's `routes` leg (Linux only).
 *
 * Thin impure shell: owns the socket / send / recvmsg mechanics and nothing
 * else. Every byte of decode logic lives in a pure, span-based
 * parse_rtnetlink_*_chunk() function that the caller passes in
 * (network_config_routes_parsers.hpp for `routes`).
 *
 * The drain loop reproduces, step for step, the three private copies that
 * network_config_plugin.cpp keeps for adapters / ip_addresses (link, addr and
 * default-route dumps): EINTR retry, non-positive read = incomplete, kernel-origin
 * check, bounded discard of foreign datagrams, MSG_TRUNC = incomplete, parse,
 * accumulate, stop on error / NLMSG_DONE. Those three copies are deliberately
 * NOT migrated onto this header — adapters and ip_addresses feed the server's
 * device views and stay byte-identical. Migrating them is a separate follow-up.
 *
 * Header-only and Linux-only. Never include it from the plugin TU: the
 * plugin's anonymous-namespace copies of these constants would not collide
 * (this header lives in yuzu::network_config::netlink) but the include would
 * invite exactly the drift the follow-up exists to remove.
 */
#pragma once

#if defined(__linux__)

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <yuzu/agent/scoped_fd.hpp>

namespace yuzu::network_config::netlink {

inline constexpr std::size_t kRecvBufSize = 16384; // matches net_quality_sampler.cpp's convention

// How many non-kernel datagrams a dump will discard before giving up. Small:
// on a healthy host this is always 0, and the only thing that produces them is
// a local process writing to our netlink socket.
inline constexpr int kMaxForeignDatagrams = 64;

// SO_RCVTIMEO bounds each INDIVIDUAL recvmsg(), but it resets on every arriving
// datagram — including one this loop goes on to discard. A local process pacing
// one foreign-origin datagram just under each 2s window could stretch the
// count-based budget above to kMaxForeignDatagrams * ~2s of wall-clock before
// this thread gave up. This deadline bounds the WHOLE discard loop instead.
inline constexpr auto kDiscardDeadline = std::chrono::seconds{4};

// Per-recvmsg wait. Without it a dump the kernel never terminates with
// NLMSG_DONE wedges the agent's command-execution thread forever; the drain
// treats the resulting EAGAIN as an incomplete dump.
inline constexpr long kRecvTimeoutSeconds = 2;

inline yuzu::agent::ScopedFd open_rtnetlink_socket() {
    yuzu::agent::ScopedFd fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (fd.get() >= 0) {
        struct timeval tv {
            kRecvTimeoutSeconds, 0
        };
        // The receive timeout is the ONLY bound on a silent recvmsg (the wall-clock deadline in
        // dump() is checked after a read returns), so a socket that cannot have it is not usable:
        // an unchecked failure here would silently restore a blocking, unbounded wait. Same rule as
        // the firewall plugin's nft socket (firewall_plugin.cpp:923-931).
        if (::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            return yuzu::agent::ScopedFd{};
    }
    return fd;
}

template <typename Record> struct DumpResult {
    std::vector<Record> records;
    bool ok = false; // true iff the dump completed (NLMSG_DONE) without error/truncation
    // true iff the dump was cut off because it held more than `max_records`
    // records. `ok` is false in that case; the kept prefix is valid, not partial
    // garbage, and the caller reports a row-cap constraint rather than a failure.
    bool capped = false;
};

/// The kernel side of a dump: a NETLINK_ROUTE socket with a bounded receive wait.
///
/// dump() is written against this four-method shape so a test can drive every branch of the
/// drain (foreign origin, flood bound, deadline, MSG_TRUNC, error, short read, cap) with
/// scripted datagrams and a scripted clock — nothing here is reachable from a unit test
/// otherwise, and the kernel-origin check is a security control.
class KernelIo {
public:
    bool open() {
        fd_ = open_rtnetlink_socket();
        return static_cast<bool>(fd_);
    }

    bool send(const void* data, std::size_t len) {
        struct sockaddr_nl sa {};
        sa.nl_family = AF_NETLINK;
        // sendmsg takes a non-const iov_base; the kernel does not write through it.
        struct iovec iov {
            const_cast<void*>(data), len
        };
        struct msghdr m {};
        m.msg_name = &sa;
        m.msg_namelen = sizeof(sa);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        ssize_t sent;
        do {
            sent = ::sendmsg(fd_.get(), &m, 0);
        } while (sent < 0 && errno == EINTR); // symmetry with the recvmsg loop
        return sent > 0;
    }

    /// One datagram into `buf`. Returns the byte count, or <= 0 on error / timeout / EOF.
    /// `from_pid` is the sender's netlink portid (0 = the kernel) and `msg_flags` the recvmsg
    /// flags (MSG_TRUNC = the datagram did not fit `cap`).
    ssize_t recv(unsigned char* buf, std::size_t cap, std::uint32_t& from_pid, int& msg_flags) {
        struct sockaddr_nl rsa {};
        struct iovec iov {
            buf, cap
        };
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &iov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd_.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        // The portid is only meaningful when the kernel actually filled the source address in.
        // A runtime that leaves msg_name untouched would read as pid 0 — the kernel — so anything
        // short of a full AF_NETLINK address is reported as a foreign sender (the same predicate
        // as the firewall plugin's nft socket). This is the one place FakeIo cannot reach.
        const bool addr_filled = rm.msg_namelen >= sizeof(rsa) && rsa.nl_family == AF_NETLINK;
        from_pid = addr_filled ? rsa.nl_pid : std::numeric_limits<std::uint32_t>::max();
        msg_flags = rm.msg_flags;
        return n;
    }

    std::chrono::steady_clock::time_point now() const { return std::chrono::steady_clock::now(); }

private:
    yuzu::agent::ScopedFd fd_;
};

/**
 * Send `req` (a standard-layout request whose first member is an nlmsghdr with
 * nlmsg_len / nlmsg_type / nlmsg_flags / nlmsg_seq already filled in) and drain
 * the kernel's multipart reply through `parse_chunk`.
 *
 * `parse_chunk(std::span<const unsigned char>, std::uint32_t expected_seq)` must
 * return a chunk exposing `records`, `done`, `error` and `truncated` — the shape
 * of yuzu::network_config::RtNetlinkParseChunk<T>. The buffer handed to it is
 * aligned to NLMSG_ALIGNTO, the precondition the rtnetlink chunk decoders state.
 *
 * Any failure (socket, send, read, foreign flood, truncation, parse error)
 * returns ok=false with whatever records were decoded so far. Callers must
 * report that as an incomplete read, never as an empty table.
 *
 * `max_records` bounds memory: a default-free-zone host can answer a route dump
 * with ~1M records, and an unbounded accumulate-then-cap would buffer them all
 * first. The check runs after each datagram is merged, so the buffer overshoots
 * the cap by at most one datagram's worth before it is trimmed to `max_records`
 * and `capped` is set.
 *
 * `io` is KernelIo in production; see that class for why it is injectable.
 */
template <typename Request, typename ParseFn, typename Io = KernelIo>
auto dump(const Request& req, std::uint32_t seq, ParseFn&& parse_chunk,
          std::size_t max_records = static_cast<std::size_t>(-1), Io io = Io{}) {
    using Chunk = std::invoke_result_t<ParseFn&, std::span<const unsigned char>, std::uint32_t>;
    using Record = typename decltype(std::declval<Chunk&>().records)::value_type;
    DumpResult<Record> result;

    if (!io.open() || !io.send(&req, sizeof(req)))
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kRecvBufSize];
    bool truncated = false;
    int foreign_datagrams = 0;
    const auto discard_deadline = io.now() + kDiscardDeadline;
    for (;;) {
        std::uint32_t from_pid = 0;
        int msg_flags = 0;
        const ssize_t n = io.recv(buf, sizeof(buf), from_pid, msg_flags);
        if (n <= 0)
            return result;

        // Netlink unicast between USER sockets is permitted, so a reply arriving
        // on this socket is not necessarily from the kernel. The auto-bound
        // portid is the agent's pid (readable from /proc) and the sequence
        // numbers are small fixed literals, so a local unprivileged process
        // could otherwise inject forged RTM_NEWROUTE records into the fleet-
        // reported routing table. Only the kernel sends from portid 0.
        if (from_pid != 0) {
            // BOUNDED discard: SO_RCVTIMEO only fires on SILENCE, so an
            // unbounded `continue` would let that same local process pin this
            // thread indefinitely by keeping the socket busy.
            if (++foreign_datagrams > kMaxForeignDatagrams)
                return result; // ok stays false — honest incomplete read
            if (io.now() >= discard_deadline)
                return result; // count alone is not enough — see kDiscardDeadline
            continue;          // not from the kernel — discard, do not parse
        }

        // MSG_TRUNC means the kernel dropped the tail of this datagram because it
        // exceeded our fixed buffer. If the retained prefix ends on a message
        // boundary the parser cannot see the loss, and a later NLMSG_DONE would
        // set ok=true over a short record set. The syscall's own signal is
        // authoritative.
        if ((msg_flags & MSG_TRUNC) != 0)
            return result; // ok stays false — records were dropped

        auto chunk = parse_chunk(std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), seq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (result.records.size() > max_records) {
            result.records.erase(result.records.begin() + static_cast<std::ptrdiff_t>(max_records),
                                 result.records.end());
            result.capped = true;
            return result; // ok stays false — the table was cut at the cap
        }
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

} // namespace yuzu::network_config::netlink

#endif // __linux__
