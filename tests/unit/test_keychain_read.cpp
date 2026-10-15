/**
 * test_keychain_read.cpp -- yuzu::agent::read_keychain_bounded (#3246, #2318a).
 *
 * These exist because of the same defect class covered by
 * test_passwd_lookup.cpp: a synchronous CoreFoundation/Security call
 * (SecItemCopyMatching) has no deadline or cancellation primitive of its
 * own, and an uncancellable block on the agent's bounded ThreadPool pins a
 * worker per request.
 *
 * The load-bearing case is therefore NOT "a keychain read resolves" -- it is
 * "a read that NEVER RETURNS still gives the caller its thread back inside
 * the budget". A suite that only proved the happy path would leave the
 * actual regression unobserved.
 *
 * The header-only detail::bounded_keychain_call template is also what makes
 * the per-image outstanding-call ceiling's Rejected path reachable and
 * deterministic (no threads, no timing) -- see the ceiling-saturation case
 * below, adapted from test_bounded_wait.cpp's own M3 rejection case.
 *
 * Structural guarantee this file does NOT re-verify as a Catch2 assertion:
 * the no-default-argument invariant on read_keychain_bounded_for_test is
 * enforced by this package's own grep verification, and a real dlclose()-
 * during-a-wedged-read fixture needs the actual certificates plugin binary
 * (owned by B3) and is integration-level, not a B1 unit test.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/keychain_read.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <bounded_wait.hpp> // yuzu::shared::detail::{g_outstanding_bounded_calls,kMaxOutstandingBoundedCalls,OutstandingCallGuard}

#include <cstdlib> // std::getenv

using namespace std::chrono_literals;
using yuzu::agent::classify_empty_query;
using yuzu::agent::fold_read_cap;
using yuzu::agent::KeychainReadResult;
using yuzu::agent::KeychainReadStatus;
using yuzu::agent::keychain_status_readable;
using yuzu::agent::read_keychain_bounded;
using yuzu::agent::read_keychain_bounded_for_test;
using yuzu::agent::detail::bounded_keychain_call;

namespace {

KeychainReadResult make(KeychainReadStatus st, std::vector<std::vector<unsigned char>> certs = {},
                        std::string detail = {}) {
    KeychainReadResult r;
    r.status = st;
    r.certs_der = std::move(certs);
    r.detail = std::move(detail);
    return r;
}

} // namespace

TEST_CASE("read_keychain_bounded returns a Completed result unchanged, byte-identical",
         "[keychain][agent]") {
    std::vector<unsigned char> a{0x30, 0x01, 0x02};
    std::vector<unsigned char> b{0x30, 0x03, 0x04, 0x05};
    // Captured BY VALUE, not by reference: a timeout (however unlikely at
    // 5s for a fast lambda) leaves the detached thread running past this
    // scope's return, and a reference into stack-owned `a`/`b` would then be
    // a use-after-free.
    auto res = read_keychain_bounded_for_test("/tmp/whatever.keychain", 5s,
                                               [a, b](const std::string&) {
                                                   return make(KeychainReadStatus::Completed, {a, b}, "ok");
                                               });
    REQUIRE(res.ok());
    CHECK(res.status == KeychainReadStatus::Completed);
    REQUIRE(res.certs_der.size() == 2);
    CHECK(res.certs_der[0] == a);
    CHECK(res.certs_der[1] == b);
    CHECK(res.detail == "ok");
}

TEST_CASE("read_keychain_bounded passes NotReadable/OpenFailed/Truncated through unchanged",
         "[keychain][agent]") {
    auto not_readable = read_keychain_bounded_for_test("/tmp/x", 5s, [](const std::string&) {
        return make(KeychainReadStatus::NotReadable, {}, "not readable");
    });
    CHECK_FALSE(not_readable.ok());
    CHECK(not_readable.status == KeychainReadStatus::NotReadable);
    CHECK(not_readable.detail == "not readable");

    auto open_failed = read_keychain_bounded_for_test("/tmp/x", 5s, [](const std::string&) {
        return make(KeychainReadStatus::OpenFailed, {}, "SecKeychainOpen failed (-25294)");
    });
    CHECK_FALSE(open_failed.ok());
    CHECK(open_failed.status == KeychainReadStatus::OpenFailed);
    CHECK(open_failed.detail == "SecKeychainOpen failed (-25294)");

    auto truncated = read_keychain_bounded_for_test("/tmp/x", 5s, [](const std::string&) {
        return make(KeychainReadStatus::Truncated, {{0x30, 0x01}}, "capped");
    });
    CHECK(truncated.ok());
    CHECK(truncated.status == KeychainReadStatus::Truncated);
    REQUIRE(truncated.certs_der.size() == 1);
    CHECK(truncated.certs_der[0] == std::vector<unsigned char>{0x30, 0x01});
    CHECK(truncated.detail == "capped");
}

TEST_CASE("read_keychain_bounded gives the caller its thread back when the read never returns",
         "[keychain][agent]") {
    // THE regression test. `stop` outlives this scope deliberately: the
    // detached read thread is still holding it after we stop waiting, which
    // is precisely the abandonment the primitive promises. A shared_ptr
    // captured by value keeps it alive for whoever finishes last -- a
    // stack-local flag here would be a use-after-free the moment we return.
    auto stop = std::make_shared<std::atomic<bool>>(false);
    // Discriminator: TimedOut is ALSO what a rejection at the ceiling could
    // look like if not distinguished; `entered` proves the read really ran
    // and we really waited, not that the call was refused outright.
    auto entered = std::make_shared<std::atomic<bool>>(false);

    // Budget widened from an original 200ms (code-review CXR-04): this test
    // races the caller's cv.wait_for deadline against the OS actually
    // scheduling the detached thread that sets `entered`. Under transient
    // load right after a fresh compile, 200ms was observed to occasionally
    // elapse before the detached thread got a scheduling slot at all
    // (entered still false when the caller's wait returned) -- not a defect
    // in the primitive, just too little headroom for two threads to race
    // for CPU time. 500ms/400ms keeps the same ~75% safety-margin ratio
    // while giving the scheduler enough room in practice; the upper bound
    // (waited < 10s) is the actual correctness assertion this test exists
    // to make -- the caller must get its thread back, not hang forever.
    // Captured before the read starts so we can tell, below, when the
    // abandoned thread's OutstandingCallGuard has actually released --
    // g_outstanding_bounded_calls is shared process-wide (this image's copy;
    // see the ceiling test below), so a guard this test leaves outstanding
    // past its own scope would corrupt that test's saturation count.
    auto baseline =
        yuzu::shared::detail::g_outstanding_bounded_calls.load(std::memory_order_relaxed);

    auto started = std::chrono::steady_clock::now();
    auto res = read_keychain_bounded_for_test("/tmp/wedged.keychain", 500ms,
                                               [stop, entered](const std::string&) {
                                                   entered->store(true, std::memory_order_relaxed);
                                                   while (!stop->load(std::memory_order_relaxed))
                                                       std::this_thread::sleep_for(5ms);
                                                   return make(KeychainReadStatus::Completed);
                                               });
    auto waited = std::chrono::steady_clock::now() - started;

    CHECK(res.status == KeychainReadStatus::TimedOut);
    CHECK_FALSE(res.ok());
    CHECK(entered->load(std::memory_order_relaxed)); // the read really ran
    CHECK(waited >= 400ms);                          // and we really waited the budget out
    CHECK(waited < 10s);

    stop->store(true, std::memory_order_relaxed); // let the detached thread retire

    // Wait for the retirement to actually land (fn() returns -> the guard's
    // destructor runs within microseconds, per bounded_call_ex) before this
    // TEST_CASE returns. Without this, a still-outstanding guard from this
    // test can survive into the ceiling-saturation test below and let its
    // "Rejected" call through uncontended -- a real, observed flake (a
    // quality-engineer governance pass caught it failing ~1 run in 6).
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (yuzu::shared::detail::g_outstanding_bounded_calls.load(std::memory_order_relaxed) !=
               baseline &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    REQUIRE(yuzu::shared::detail::g_outstanding_bounded_calls.load(std::memory_order_relaxed) ==
            baseline);
}

TEST_CASE("read_keychain_bounded refuses to start a read it cannot wait for",
         "[keychain][agent]") {
    std::atomic<bool> called{false};
    auto called_marker = &called;
    auto res = read_keychain_bounded_for_test("/tmp/x", 0ms, [called_marker](const std::string&) {
        called_marker->store(true);
        return make(KeychainReadStatus::Completed);
    });
    CHECK(res.status == KeychainReadStatus::TimedOut);
    CHECK_FALSE(called.load());

    std::atomic<bool> neg_called{false};
    auto neg_marker = &neg_called;
    auto neg = read_keychain_bounded_for_test("/tmp/x", -5ms, [neg_marker](const std::string&) {
        neg_marker->store(true);
        return make(KeychainReadStatus::Completed);
    });
    CHECK(neg.status == KeychainReadStatus::TimedOut);
    CHECK_FALSE(neg_called.load());
}

TEST_CASE("read_keychain_bounded reports a throwing read as a non-arrival, not a crash",
         "[keychain][agent]") {
    auto res = read_keychain_bounded_for_test("/tmp/x", 50ms, [](const std::string&) -> KeychainReadResult {
        throw std::runtime_error("securityd exploded");
    });
    CHECK(res.status == KeychainReadStatus::TimedOut);
    CHECK_FALSE(res.ok());
}

// The exported read_keychain_bounded_for_test's bounded_call_ex instantiation
// lives in the agent-core dylib and consults THAT image's own copy of
// bounded_wait.hpp's ceiling counter -- an inline variable compiled under
// -fvisibility=hidden (root meson.build), so it is not coalesced across a
// dylib/executable boundary. Held guards acquired from this test executable
// can only saturate this executable's copy, not the dylib's, so the
// Rejected mapping is exercised here by instantiating the SAME header-only
// template (detail::bounded_keychain_call) in this image instead -- see
// keychain_read.hpp's "THE OUTSTANDING-CALL CEILING IS PER IMAGE" section.
TEST_CASE("bounded_keychain_call reports Rejected, and never invokes fn, at the outstanding-call ceiling",
         "[keychain][agent]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;
    using yuzu::shared::detail::OutstandingCallGuard;

    // Ceiling-free control, in THIS image: proves the template's Completed
    // leg works here before the Rejected assertion below relies on it not
    // being vacuous (mirrors test_bounded_wait.cpp:183-188).
    {
        std::vector<unsigned char> blob{0x30, 0x01, 0x02};
        auto ok = bounded_keychain_call(2000ms, [blob]() -> KeychainReadResult {
            return make(KeychainReadStatus::Completed, {blob});
        });
        CHECK(ok.status == KeychainReadStatus::Completed);
        REQUIRE(ok.certs_der.size() == 1);
        CHECK(ok.certs_der[0] == blob);
    }

    // This test's saturation loop assumes it starts from zero outstanding
    // calls in this image. g_outstanding_bounded_calls is shared by every
    // bounded_call_ex consumer linked into this same test binary, not just
    // this file's own tests -- a sibling test elsewhere (test_bounded_wait's
    // own rejection case, test_passwd_lookup, etc.) can hold a guard for a
    // few milliseconds around the exact moment this test starts, especially
    // under heavy concurrent CPU load (observed once in practice, at a
    // ~1-in-dozens rate, coinciding with several other unrelated build/test
    // processes competing for cores on this Mac). Poll-wait for it to settle
    // rather than asserting immediately, so a transient overlap from an
    // unrelated test doesn't produce a spurious hard failure here; only a
    // genuine, permanent leak trips the REQUIRE below.
    {
        auto deadline = std::chrono::steady_clock::now() + 5s;
        while (g_outstanding_bounded_calls.load() != 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(5ms);
        }
    }
    // If it still hasn't settled, fail loudly here instead of discovering it
    // as a flaky Completed/entered mismatch three assertions down.
    REQUIRE(g_outstanding_bounded_calls.load() == 0);

    // Saturate the ceiling from THIS thread, so the next call is rejected
    // deterministically rather than by racing real work. No threads, no
    // timing -- same discipline as test_bounded_wait.cpp's M3 case.
    std::vector<OutstandingCallGuard> held;
    while (g_outstanding_bounded_calls.load() <= kMaxOutstandingBoundedCalls) {
        auto g = OutstandingCallGuard::try_acquire();
        if (!g)
            break;
        held.push_back(std::move(*g));
    }

    bool entered = false;
    auto res = bounded_keychain_call(2000ms, [&entered]() -> KeychainReadResult {
        entered = true;
        return make(KeychainReadStatus::Completed);
    });

    CHECK(res.status == KeychainReadStatus::Rejected);
    CHECK(res.certs_der.empty());
    CHECK_FALSE(entered); // the callable was never invoked

    held.clear(); // release the ceiling for later test cases
}

TEST_CASE("keychain_status_readable / classify_empty_query / fold_read_cap -- pure classification",
         "[keychain][agent]") {
    CHECK_FALSE(keychain_status_readable(0));
    CHECK(keychain_status_readable(2));
    CHECK(keychain_status_readable(3));
    CHECK_FALSE(keychain_status_readable(1));

    CHECK(classify_empty_query(true) == KeychainReadStatus::Completed);
    CHECK(classify_empty_query(false) == KeychainReadStatus::NotReadable);

    CHECK(fold_read_cap(5, 5, 2000) == KeychainReadStatus::Completed);
    CHECK(fold_read_cap(5, 4, 2000) == KeychainReadStatus::Truncated);
    CHECK(fold_read_cap(2001, 2000, 2000) == KeychainReadStatus::Truncated);
    CHECK(fold_read_cap(0, 0, 2000) == KeychainReadStatus::Completed);
}

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)

TEST_CASE("the bounded keychain read resolves a real system keychain", "[keychain][agent]") {
    // Skip ONLY on TimedOut/Rejected -- a wedged securityd or an exhausted
    // ceiling on the build host is an environment fact, not a defect. Every
    // other status is a real failure and must FAIL.
    auto res = read_keychain_bounded("/System/Library/Keychains/SystemRootCertificates.keychain", 15s);
    if (res.status == KeychainReadStatus::TimedOut || res.status == KeychainReadStatus::Rejected) {
        WARN("skipping: keychain read timed out or was rejected on this host");
        return;
    }
    REQUIRE(res.ok());
    REQUIRE_FALSE(res.certs_der.empty());
    for (const auto& der : res.certs_der) {
        REQUIRE_FALSE(der.empty());
        CHECK(der[0] == 0x30); // DER SEQUENCE tag
    }
}

TEST_CASE("the bounded keychain read reports OpenFailed for a nonexistent path", "[keychain][agent]") {
    auto res = read_keychain_bounded("/tmp/yuzu_test_no_such_keychain_zzz", 15s);
    CHECK(res.status == KeychainReadStatus::OpenFailed);
}

TEST_CASE("the bounded keychain read reports OpenFailed for a non-keychain file", "[keychain][agent]") {
    auto res = read_keychain_bounded("/etc/hosts", 15s);
    CHECK(res.status == KeychainReadStatus::OpenFailed);
}

// HIDDEN probe case: never runs in the normal suite (Catch2 `[.]` tag). The
// integrator uses this against an empty readable keychain and a chmod-000
// copy at WS-B wave-1 integration to fill in the measured-bits comment in
// keychain_read.cpp -- see the WS-B integration plan. Asserts nothing.
TEST_CASE("keychain-probe: manual read of YUZU_KEYCHAIN_PROBE_PATH", "[.][keychain-probe]") {
    const char* path = std::getenv("YUZU_KEYCHAIN_PROBE_PATH");
    if (!path) {
        WARN("YUZU_KEYCHAIN_PROBE_PATH not set -- nothing to probe");
        return;
    }
    auto res = read_keychain_bounded(path, 15s);
    const char* status_name = "?";
    switch (res.status) {
    case KeychainReadStatus::Completed: status_name = "Completed"; break;
    case KeychainReadStatus::Truncated: status_name = "Truncated"; break;
    case KeychainReadStatus::NotReadable: status_name = "NotReadable"; break;
    case KeychainReadStatus::OpenFailed: status_name = "OpenFailed"; break;
    case KeychainReadStatus::TimedOut: status_name = "TimedOut"; break;
    case KeychainReadStatus::Rejected: status_name = "Rejected"; break;
    }
    WARN("status=" << status_name << " certs=" << res.certs_der.size() << " detail=" << res.detail);
}

#endif
