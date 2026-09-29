/**
 * test_passwd_lookup.cpp -- yuzu::agent::resolve_passwd_bounded (#3406).
 *
 * These exist because of a specific defect class found in adversarial review:
 * argv-izing the certificates plugin's login-keychain read moved a
 * passwd/Directory-Services lookup out of a SIGKILL-able child process and
 * into an in-process call. On a directory-joined Mac that call can block with
 * no timeout of its own, and an uncancellable block on the agent's bounded
 * ThreadPool pins a worker per request.
 *
 * The load-bearing case is therefore NOT "a lookup resolves" -- it is
 * "a lookup that NEVER RETURNS still gives the caller its thread back inside
 * the budget". A suite that only proved the happy path would leave the actual
 * regression unobserved, which is exactly how the defect reached review.
 *
 * The injected-lookup seam these use is the same one that makes the real
 * resolver's rc/ERANGE/no-record branches reachable at all; before it, they
 * were file-local in the plugin .cpp and no test could touch them.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/passwd_lookup.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <cerrno>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using yuzu::agent::PasswdLookupResult;
using yuzu::agent::PasswdLookupStatus;
using yuzu::agent::resolve_passwd_bounded;
using yuzu::agent::resolve_passwd_bounded_for_test;

namespace {

PasswdLookupResult make(PasswdLookupStatus st, std::string uid = {}, std::string home = {}) {
    PasswdLookupResult r;
    r.status = st;
    r.record.uid = std::move(uid);
    r.record.home_dir = std::move(home);
    return r;
}

} // namespace

TEST_CASE("resolve_passwd_bounded returns a resolved record unchanged", "[passwd][agent]") {
    // Capture the argument; do NOT assert on it here. Catch2's assertion
    // macros are not thread-safe off the main thread, and this callable runs
    // on bounded_call's worker.
    auto seen = std::make_shared<std::string>();
    auto res = resolve_passwd_bounded_for_test("alice", 5s, [seen](const std::string& u) {
        *seen = u;
        return make(PasswdLookupStatus::kOk, "501", "/Users/alice");
    });
    CHECK(*seen == "alice");
    REQUIRE(res.ok());
    CHECK(res.status == PasswdLookupStatus::kOk);
    CHECK(res.record.uid == "501");
    CHECK(res.record.home_dir == "/Users/alice");
}

TEST_CASE("resolve_passwd_bounded preserves the not-found/error distinction", "[passwd][agent]") {
    // These are different answers and callers are entitled to tell them apart:
    // kNotFound is a definite negative, kError is a failed question.
    auto nf = resolve_passwd_bounded_for_test("ghost", 5s,
                                     [](const std::string&) {
                                         return make(PasswdLookupStatus::kNotFound);
                                     });
    CHECK_FALSE(nf.ok());
    CHECK(nf.status == PasswdLookupStatus::kNotFound);

    auto err = resolve_passwd_bounded_for_test("alice", 5s, [](const std::string&) {
        return make(PasswdLookupStatus::kError);
    });
    CHECK_FALSE(err.ok());
    CHECK(err.status == PasswdLookupStatus::kError);
}

TEST_CASE("resolve_passwd_bounded gives the caller its thread back when the lookup never returns",
         "[passwd][agent]") {
    // THE regression test. `stop` outlives this scope deliberately: the
    // detached lookup thread is still holding it after we stop waiting, which
    // is precisely the abandonment the primitive promises. A shared_ptr
    // captured by value keeps it alive for whoever finishes last -- a
    // stack-local flag here would be a use-after-free the moment we return.
    auto stop = std::make_shared<std::atomic<bool>>(false);
    // Discriminator: kTimeout is ALSO what bounded_call returns when it refuses
    // at its outstanding-thread ceiling, in which case the lookup never runs
    // and this test would observe nothing. Proving the lookup was entered, and
    // that we actually waited out the budget, is what makes the pass mean
    // "the bound fired" rather than "the call was refused".
    auto entered = std::make_shared<std::atomic<bool>>(false);

    auto started = std::chrono::steady_clock::now();
    auto res = resolve_passwd_bounded_for_test("wedged", 200ms, [stop, entered](const std::string&) {
        entered->store(true, std::memory_order_relaxed);
        while (!stop->load(std::memory_order_relaxed))
            std::this_thread::sleep_for(5ms);
        return make(PasswdLookupStatus::kOk, "999", "/Users/wedged");
    });
    auto waited = std::chrono::steady_clock::now() - started;

    CHECK(res.status == PasswdLookupStatus::kTimeout);
    CHECK_FALSE(res.ok());
    CHECK(entered->load(std::memory_order_relaxed)); // the lookup really ran
    CHECK(waited >= 150ms);                          // and we really waited the budget out
    // The point of the whole exercise: we did not block for the lookup's
    // duration. Generous upper bound -- this asserts "bounded", not a
    // scheduling guarantee, so it cannot flake on a loaded CI box.
    CHECK(waited < 10s);

    stop->store(true, std::memory_order_relaxed); // let the detached thread retire
}

TEST_CASE("resolve_passwd_bounded refuses to start a lookup it cannot wait for",
         "[passwd][agent]") {
    // An already-exhausted action budget must not buy one more unbounded
    // lookup -- the caller has no time left to give it.
    std::atomic<bool> called{false};
    auto called_marker = &called;
    auto res = resolve_passwd_bounded_for_test("alice", 0ms, [called_marker](const std::string&) {
        called_marker->store(true);
        return make(PasswdLookupStatus::kOk, "501", "/Users/alice");
    });
    CHECK(res.status == PasswdLookupStatus::kTimeout);
    CHECK_FALSE(called.load());

    std::atomic<bool> neg_called{false};
    auto neg_marker = &neg_called;
    auto neg = resolve_passwd_bounded_for_test("alice", -5ms, [neg_marker](const std::string&) {
        neg_marker->store(true);
        return make(PasswdLookupStatus::kOk);
    });
    CHECK(neg.status == PasswdLookupStatus::kTimeout);
    CHECK_FALSE(neg_called.load());
}

TEST_CASE("resolve_passwd_bounded reports a throwing lookup as a non-arrival, not a crash",
         "[passwd][agent]") {
    // bounded_call runs the callable on a DETACHED thread; an exception
    // escaping it uncaught would std::terminate() the whole agent.
    auto res = resolve_passwd_bounded_for_test("alice", 50ms, [](const std::string&) -> PasswdLookupResult {
        throw std::runtime_error("directory services exploded");
    });
    CHECK(res.status == PasswdLookupStatus::kTimeout);
    CHECK_FALSE(res.ok());
}

TEST_CASE("classify_getpwnam_rc maps the POSIX and glibc not-found spellings apart from errors",
         "[passwd][agent]") {
    using yuzu::agent::classify_getpwnam_rc;
    // POSIX / macOS: success and the definite negative are both rc == 0.
    CHECK(classify_getpwnam_rc(0, true) == PasswdLookupStatus::kOk);
    CHECK(classify_getpwnam_rc(0, false) == PasswdLookupStatus::kNotFound);
    // glibc also spells "no such user" as ENOENT/ESRCH. Reporting these as
    // kError would turn a definite negative into a lookup failure on Linux,
    // which is the distinction the enum exists to keep.
    CHECK(classify_getpwnam_rc(ENOENT, false) == PasswdLookupStatus::kNotFound);
    CHECK(classify_getpwnam_rc(ESRCH, false) == PasswdLookupStatus::kNotFound);
    // Genuine faults stay errors -- deliberately including EPERM/EBADF, which
    // getpwnam(3) also lists, because misreporting a fault as an authoritative
    // "no such account" is the more dangerous direction.
    CHECK(classify_getpwnam_rc(EPERM, false) == PasswdLookupStatus::kError);
    CHECK(classify_getpwnam_rc(EBADF, false) == PasswdLookupStatus::kError);
    CHECK(classify_getpwnam_rc(EIO, false) == PasswdLookupStatus::kError);
    CHECK(classify_getpwnam_rc(ERANGE, false) == PasswdLookupStatus::kError);
}

#if !defined(_WIN32)
TEST_CASE("the bounded passwd lookup resolves a real account and distinguishes a missing one",
         "[passwd][agent]") {
    // Against the host's own passwd database. root exists on every POSIX box
    // this suite runs on, so this is a stable assertion rather than a
    // machine-specific one.
    // Through the BOUNDED wrapper, never the raw lookup: on a directory-joined
    // build host the raw call is exactly the unbounded network read this whole
    // change exists to bound, and it would hang the suite rather than fail it.
    auto root = resolve_passwd_bounded("root", 5s);
    // Skip ONLY on kTimeout -- a wedged directory service on the build host is
    // an environment fact, not a defect. Every other status is a real failure
    // and must FAIL: an earlier revision skipped on any non-kOk, which would
    // have let a regression to kError pass as green and silently skipped the
    // kNotFound assertion below too.
    if (root.status == PasswdLookupStatus::kTimeout) {
        WARN("skipping: passwd lookup for 'root' timed out on this host");
        return;
    }
    REQUIRE(root.status == PasswdLookupStatus::kOk);
    CHECK(root.record.uid == "0");
    CHECK_FALSE(root.record.home_dir.empty());

    // rc == 0 with a null result pointer -- the "no such account" answer,
    // which must NOT be reported as kError.
    auto missing = resolve_passwd_bounded("yuzu_test_no_such_account_zzz", 5s);
    CHECK(missing.status == PasswdLookupStatus::kNotFound);
}
#endif
