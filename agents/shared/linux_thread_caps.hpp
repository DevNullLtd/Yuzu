// linux_thread_caps.hpp -- raise and drop ONE capability in the CALLING THREAD's effective set.
//
// WHY. The agent service holds CAP_DAC_READ_SEARCH in every thread's effective set (the packaged unit
// grants it, and agent-core keeps permitted and effective). A walk that needs it only to open directories
// and a matched file would otherwise hold it while it compares names and builds rows. A worker thread
// therefore drops the bit from its EFFECTIVE set when it starts (drop_effective) and raises it again only
// around the lookups that need it (ScopedCapRaise); the bit stays in its PERMITTED set the whole time.
//
// THIS IS HYGIENE, NOT A BOUNDARY. The bit is still permitted on the thread, so code running on it can
// raise it with the same two calls this header makes, and every other thread of the agent holds it
// effective throughout. It shrinks what a bug in the matching, row or cursor code can do while it runs on
// the worker; it does not stop the worker. docs/agent-privilege-model.md says the same.
//
// MECHANISM. Raw capget(2) and capset(2), header version 3, pid 0 (the calling thread: the raw system
// calls are per thread, unlike libcap's process-wide setter). Only the effective set is ever written; the
// permitted and inheritable sets are passed back exactly as read, so the kernel's rules for capset (nothing
// can be added to permitted, effective must stay inside permitted) are never in play. Ambient capabilities
// are not touched. raise is a no-op returning false when the bit is not permitted: an unprivileged agent
// (or a container that granted nothing) runs the walk exactly as before.
//
// The decisions (which bit changes, whether a raise is allowed) are pure and portable so they are unit
// tested on every host; only the two system calls are Linux.
#pragma once

#include <cstdint>
#include <optional>

namespace yuzu::shared::thread_caps {

/// CAP_DAC_READ_SEARCH: bypass the read permission on files and the search permission on directories.
inline constexpr unsigned kCapDacReadSearch = 2;

/// One capability set in the version 3 layout: two 32-bit words, capability n in bit n % 32 of word n / 32.
struct CapBits {
    std::uint32_t word[2]{};

    [[nodiscard]] constexpr bool has(unsigned cap) const noexcept {
        return cap < 64 && ((word[cap / 32] >> (cap % 32)) & 1u) != 0;
    }
    constexpr void set(unsigned cap) noexcept {
        if (cap < 64)
            word[cap / 32] |= (std::uint32_t{1} << (cap % 32));
    }
    constexpr void clear(unsigned cap) noexcept {
        if (cap < 64)
            word[cap / 32] &= ~(std::uint32_t{1} << (cap % 32));
    }
};

struct ThreadCaps {
    CapBits effective;
    CapBits permitted;
    CapBits inheritable;
};

/// Clears `cap` from the effective set. true when that changed the set; the permitted set is never touched.
[[nodiscard]] constexpr bool plan_drop(ThreadCaps& c, unsigned cap) noexcept {
    if (!c.effective.has(cap))
        return false;
    c.effective.clear(cap);
    return true;
}

/// Sets `cap` in the effective set when it is permitted and not already effective. true when that changed
/// the set; false (and nothing changed) when the bit is not permitted or is already effective.
[[nodiscard]] constexpr bool plan_raise(ThreadCaps& c, unsigned cap) noexcept {
    if (!c.permitted.has(cap) || c.effective.has(cap))
        return false;
    c.effective.set(cap);
    return true;
}

} // namespace yuzu::shared::thread_caps

#if defined(__linux__)

#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace yuzu::shared::thread_caps {

static_assert(kCapDacReadSearch == CAP_DAC_READ_SEARCH);

namespace detail {

/// The calling thread's three sets, or nothing when capget failed.
[[nodiscard]] inline std::optional<ThreadCaps> read_caps() noexcept {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (::syscall(SYS_capget, &header, data) != 0)
        return std::nullopt;
    ThreadCaps out;
    for (int i = 0; i < 2; ++i) {
        out.effective.word[i] = data[i].effective;
        out.permitted.word[i] = data[i].permitted;
        out.inheritable.word[i] = data[i].inheritable;
    }
    return out;
}

[[nodiscard]] inline bool write_caps(const ThreadCaps& c) noexcept {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    for (int i = 0; i < 2; ++i) {
        data[i].effective = c.effective.word[i];
        data[i].permitted = c.permitted.word[i];
        data[i].inheritable = c.inheritable.word[i];
    }
    return ::syscall(SYS_capset, &header, data) == 0;
}

} // namespace detail

/// Drops `cap` from the calling thread's effective set. true when the set changed.
inline bool drop_effective(unsigned cap) noexcept {
    auto c = detail::read_caps();
    return c && plan_drop(*c, cap) && detail::write_caps(*c);
}

/// Raises `cap` in the calling thread's effective set. true when the set changed; false when the bit is
/// not permitted, is already effective, or either system call failed (nothing is then raised).
inline bool raise_effective(unsigned cap) noexcept {
    auto c = detail::read_caps();
    return c && plan_raise(*c, cap) && detail::write_caps(*c);
}

/// Raises `cap` for the life of the object and drops it again only if this object raised it.
class ScopedCapRaise {
public:
    explicit ScopedCapRaise(unsigned cap = kCapDacReadSearch) noexcept : cap_(cap), raised_(raise_effective(cap)) {}
    ~ScopedCapRaise() {
        if (raised_)
            (void)drop_effective(cap_);
    }
    ScopedCapRaise(const ScopedCapRaise&) = delete;
    ScopedCapRaise& operator=(const ScopedCapRaise&) = delete;

    [[nodiscard]] bool raised() const noexcept { return raised_; }

private:
    unsigned cap_;
    bool raised_;
};

} // namespace yuzu::shared::thread_caps

#endif // defined(__linux__)
