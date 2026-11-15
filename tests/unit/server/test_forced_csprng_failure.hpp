#pragma once

/// @file test_forced_csprng_failure.hpp
///
/// Test-only guards that make the server's entropy source fail (#4763; shared by the store and
/// route tests since #6995).
///
/// 1. `ForcedCsprngFailure` -- RAII around `secure_random`'s one-shot, thread-local failure hook.
///    Arming is consumed by the FIRST `fill_random` / `random_hex` on this thread, so arm it
///    immediately before the call under test and keep anything else that draws entropy out of the
///    gap. The destructor GUARANTEES the flag is disarmed: without it, a REQUIRE that throws before
///    the hooked draw runs would leave it armed and poison the next test case's first draw.
///    It reaches only `fill_random` (the typed TOTP-secret and recovery-code draws).
///
/// 2. `FailNthSaltDraw` (POSIX only) -- fails the Nth `RAND_bytes(buf, 16)` call on this thread.
///    The per-code recovery-code SALT is drawn through `AuthManager::random_bytes`, which calls
///    OpenSSL `RAND_bytes` directly and THROWS on failure, so guard (1) cannot reach it (#6995,
///    gov UP-1/CH-1). It swaps OpenSSL's RAND method (test-only; deprecated since 3.0 but still
///    honoured by `RAND_bytes`) for one that delegates to the default method except for the
///    targeted call. 16 bytes is exactly the salt size (a recovery code is 10 bytes, the TOTP
///    secret 20), so no other draw on the regenerate path can be hit by mistake. The method swap is
///    process-global and restored by the destructor; the counter is thread-local, so a draw on
///    another thread is never failed. Windows draws through BCryptGenRandom, so it is compiled out.

#include "../../../server/core/src/secure_random.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <span>
#include <stdexcept>

#ifndef _WIN32
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/rand.h>
#endif

namespace yuzu::test {

struct ForcedCsprngFailure {
    ForcedCsprngFailure() { yuzu::server::test_hooks::force_next_failure_for_this_thread(); }
    ~ForcedCsprngFailure() {
        if (yuzu::server::test_hooks::is_failure_forced_for_this_thread()) {
            std::array<std::uint8_t, 1> drain{};
            (void)yuzu::server::fill_random(std::span<std::uint8_t>{drain}); // consumes the flag
        }
    }
    ForcedCsprngFailure(const ForcedCsprngFailure&) = delete;
    ForcedCsprngFailure& operator=(const ForcedCsprngFailure&) = delete;
};

#ifndef _WIN32
// The RAND_METHOD API is deprecated since OpenSSL 3.0. `OPENSSL_SUPPRESS_DEPRECATED` above only works if
// this is the first OpenSSL header in the translation unit, so also silence the warning locally.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
namespace rand_fault_detail {

inline thread_local bool g_armed = false;
inline thread_local int g_remaining = 0;
inline std::atomic<const RAND_METHOD*> g_default{nullptr};

inline const RAND_METHOD* dflt() {
    return g_default.load(std::memory_order_acquire);
}

inline int seed(const void* b, int n) {
    return dflt()->seed != nullptr ? dflt()->seed(b, n) : 1;
}
inline int bytes(unsigned char* buf, int num) {
    if (g_armed && num == 16 && --g_remaining == 0) {
        g_armed = false; // one-shot
        return 0;        // RAND_bytes reports failure
    }
    return dflt()->bytes(buf, num);
}
inline void cleanup() {
    if (dflt()->cleanup != nullptr)
        dflt()->cleanup();
}
inline int add(const void* b, int n, double r) {
    return dflt()->add != nullptr ? dflt()->add(b, n, r) : 1;
}
inline int pseudorand(unsigned char* buf, int num) {
    return dflt()->pseudorand != nullptr ? dflt()->pseudorand(buf, num) : bytes(buf, num);
}
inline int status() {
    return dflt()->status != nullptr ? dflt()->status() : 1;
}
inline const RAND_METHOD* method() {
    static const RAND_METHOD m{seed, bytes, cleanup, add, pseudorand, status};
    return &m;
}

} // namespace rand_fault_detail

/// Fails the `nth` (1-based) 16-byte `RAND_bytes` call on this thread, then disarms.
class FailNthSaltDraw {
public:
    explicit FailNthSaltDraw(int nth) {
        prev_ = RAND_get_rand_method();
        // One live guard per process: a second would capture THIS guard's method as its "default"
        // and `bytes()` would then recurse into itself without bound.
        if (prev_ == rand_fault_detail::method())
            throw std::logic_error("FailNthSaltDraw is not nestable: one live guard per process");
        rand_fault_detail::g_default.store(prev_, std::memory_order_release);
        RAND_set_rand_method(rand_fault_detail::method());
        rand_fault_detail::g_remaining = nth;
        rand_fault_detail::g_armed = true;
    }
    ~FailNthSaltDraw() {
        rand_fault_detail::g_armed = false;
        RAND_set_rand_method(prev_);
    }
    FailNthSaltDraw(const FailNthSaltDraw&) = delete;
    FailNthSaltDraw& operator=(const FailNthSaltDraw&) = delete;

    /// True once the targeted draw has been failed (proves the intended draw was reached).
    [[nodiscard]] bool fired() const noexcept { return !rand_fault_detail::g_armed; }

private:
    const RAND_METHOD* prev_;
};
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif // !_WIN32

} // namespace yuzu::test
