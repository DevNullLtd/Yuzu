// bounded_file_hash.hpp -- SHA-256 of ONE regular file with a byte cap and a wall-clock deadline.
//
// For a plugin that hashes a file named by an untrusted source (an image path any user can
// launch, an operator-supplied path): an open-by-name `std::ifstream` read has no size bound, no
// deadline, and blocks forever on a FIFO or a device node. This helper bounds the read and
// refuses anything that is not a regular file.
//
//   hash_stream_bounded -- portable core over a caller-supplied read callback.
//   hash_fd_regular     -- POSIX: fstat the OPEN descriptor (the authoritative check; the path
//                          was never re-resolved), refuse a non-regular file and an oversized
//                          one, then stream. The caller opens (`O_RDONLY | O_NONBLOCK | O_NOCTTY
//                          | O_CLOEXEC`; `O_NOFOLLOW` where the leaf must not be a link, but NOT
//                          for `/proc/<pid>/exe`, a magic link whose open IS the kernel's own
//                          reference to the running image).
//
// The deadline is checked between 64 KiB reads, so it is COOPERATIVE: a read or open that blocks
// inside the kernel (a hung network or FUSE mount) is not interruptible from here. The real bound
// is the caller's: run the whole examine/hash on a bounded helper (bounded_wait.hpp's
// bounded_call_ex) so the command worker gives up at the deadline, and refuse network paths first
// (local_path_policy.hpp) so a stall is the exception.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include "sha256.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yuzu::shared {

enum class HashStatus : std::uint8_t {
    ok,
    unreadable,
    not_regular,
    oversize,
    timeout,
    symlink_refused,
    absent ///< ENOENT/ENOTDIR: a definitive "no such file", not a coverage gap
};

struct BoundedHash {
    HashStatus status{HashStatus::unreadable};
    std::string hex; ///< lowercase hex, only when status == ok
};

using HashClock = std::chrono::steady_clock;

/// `read(buf, len)` returns bytes read, 0 at EOF, a negative value on error. EOF is the only
/// clean end; the cap and the deadline are checked as bytes arrive.
template <class ReadFn>
[[nodiscard]] BoundedHash hash_stream_bounded(ReadFn&& read, std::uint64_t max_bytes,
                                              HashClock::time_point deadline) {
    Sha256 hasher;
    unsigned char buf[64 * 1024];
    std::uint64_t total = 0;
    for (;;) {
        if (HashClock::now() >= deadline)
            return {HashStatus::timeout, {}};
        const long long n = read(buf, sizeof(buf));
        if (n < 0)
            return {HashStatus::unreadable, {}};
        if (n == 0)
            break;
        total += static_cast<std::uint64_t>(n);
        if (total > max_bytes)
            return {HashStatus::oversize, {}};
        hasher.update(buf, static_cast<std::size_t>(n));
    }
    return {HashStatus::ok, hasher.hex_digest()};
}

#ifndef _WIN32

/// Hash the open descriptor `fd` (not closed here). A non-regular file (FIFO, socket, device,
/// directory) is refused before any read, as is a file whose size already exceeds the cap; a file
/// that grows past the cap mid-read is caught by the running count.
[[nodiscard]] inline BoundedHash hash_fd_regular(int fd, std::uint64_t max_bytes,
                                                 HashClock::time_point deadline) {
    struct stat st{};
    if (::fstat(fd, &st) != 0)
        return {HashStatus::unreadable, {}};
    if (!S_ISREG(st.st_mode))
        return {HashStatus::not_regular, {}};
    if (static_cast<std::uint64_t>(st.st_size) > max_bytes)
        return {HashStatus::oversize, {}};
    return hash_stream_bounded(
        [fd](unsigned char* buf, std::size_t len) -> long long {
            return static_cast<long long>(::read(fd, buf, len));
        },
        max_bytes, deadline);
}

#endif

} // namespace yuzu::shared
