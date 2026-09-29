#pragma once

/**
 * scoped_fd.hpp -- move-only RAII owner for a POSIX file descriptor.
 *
 * close()s the owned fd on destruction unless release()d or reset() to a new
 * value first. Header-only, POSIX-only (guarded `#ifndef _WIN32` -- Windows
 * has no POSIX fd space; HANDLE lifetime is a different animal and already
 * has its own idioms, e.g. file_hash.hpp's HANDLE overload).
 *
 * Mirrors the shape of subprocess_runner.cpp's file-local `UniqueFd` (get /
 * release / reset, move-only, close-on-destruct) but lives here as a shared
 * primitive so any POSIX caller that owns a bare fd -- a kqueue/eventfd wake
 * pipe, a one-shot `open()`, a socket -- gets the same exception-safe wrapper
 * instead of hand-rolling it again. `UniqueFd` itself is left as-is (not a
 * consumer of this header): it is scoped to subprocess_runner.cpp's own
 * exception-safety story and out of bounds for this change.
 *
 * Not a `unique_ptr` alias: -1 (not nullptr/0) is the "no fd" sentinel, and
 * the deleter is a fixed `close()` call, not a template parameter -- a small
 * dedicated type reads clearer at every call site than a custom-deleter
 * `unique_ptr<int, ...>` would.
 *
 * THREE reset() contracts coexist across this codebase's RAII owners, and
 * they are NOT interchangeable -- read the relevant one before assuming any
 * of them generalizes:
 *   - THIS type (POSIX fd, close()-based): reset(fd) is a no-op when
 *     `fd == fd_` (self-reset would close a fd this instance is still
 *     supposed to own, then leave fd_ pointing at whatever the kernel
 *     recycles that number to -- see the self-reset guard below).
 *   - ScopedCFRef<T>/ScopedIOObject (scoped_cfref.hpp/scoped_ioobject.hpp,
 *     CF Create/Copy Rule): the OPPOSITE -- reset(ref) is NEVER a same-
 *     identity no-op, because a same-identity +1 reference is a genuinely
 *     DISTINCT retain obligation the caller must still discharge (CDX-004:
 *     an earlier same-identity guard there LEAKED a ref for exactly this
 *     reason). See those headers' own reset() comments for the full
 *     reasoning.
 *   - subprocess_runner.cpp's file-local `UniqueFd`/Windows `UniqueHandle`:
 *     NEITHER guard -- they are never called with their own current value in
 *     that file, so the question never arises there; do not port that
 *     shape elsewhere without re-deriving which of the two contracts above
 *     actually applies to the resource in question.
 */

#ifndef _WIN32

#include <unistd.h> // close()

namespace yuzu::agent {

/// Owns exactly one POSIX file descriptor; closes it on destruction, move, or
/// an explicit reset() -- never double-closes, never leaks past an exception.
class ScopedFd {
public:
    ScopedFd() = default;
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept : fd_(other.release()) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~ScopedFd() { reset(); }

    /// The raw fd, or -1 if this instance owns nothing. Ownership is retained.
    [[nodiscard]] int get() const noexcept { return fd_; }

    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    /// Give up ownership without closing; the caller now owns the fd.
    [[nodiscard]] int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    /// Close the currently-owned fd (if any) and take ownership of `fd`
    /// instead (default -1: own nothing).
    void reset(int fd = -1) noexcept {
        if (fd == fd_)
            return; // self-reset: closing then re-storing the same fd would
                    // leave the owner holding a closed/recycled descriptor (BR-008)
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

} // namespace yuzu::agent

#endif // !_WIN32
