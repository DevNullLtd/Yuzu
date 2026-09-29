// passwd_lookup.cpp -- bounded passwd-database resolution (#3406).
// See passwd_lookup.hpp for why this lives in agent-core rather than in the
// plugin that consumes it (detached-thread lifetime vs plugin dlclose()).

#include <yuzu/agent/passwd_lookup.hpp>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call (agents/shared)

#include <cerrno>
#include <cstddef>
#include <vector>

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

namespace yuzu::agent {

#ifndef _WIN32

PasswdLookupResult getpwnam_lookup(const std::string& username) {
    PasswdLookupResult out;
    struct passwd pwd {};
    struct passwd* found = nullptr;

    // _SC_GETPW_R_SIZE_MAX is a HINT and may be -1; 4096 covers any real
    // record, and the single ERANGE retry below covers a pathological one.
    long suggested = ::sysconf(_SC_GETPW_R_SIZE_MAX);
    std::vector<char> buf(suggested > 0 ? static_cast<std::size_t>(suggested) : 4096);

    for (int attempt = 0; attempt < 2; ++attempt) {
        // POSIX: the error is the RETURN VALUE, not errno. A zero return with
        // a null result pointer is the distinct "no such account" answer --
        // a definite negative, not a failure.
        int rc = ::getpwnam_r(username.c_str(), &pwd, buf.data(), buf.size(), &found);
        if (rc == ERANGE) {
            buf.resize(buf.size() * 4);
            continue;
        }
        // Classification (incl. the glibc ENOENT/ESRCH divergence) lives in the
        // header's pure classify_getpwnam_rc so it is unit-testable.
        out.status = classify_getpwnam_rc(rc, found != nullptr);
        if (out.status != PasswdLookupStatus::kOk)
            return out;
        out.record.uid = std::to_string(static_cast<unsigned long long>(found->pw_uid));
        // pw_dir may legitimately be null; the caller decides what an absent
        // home means for its own action. Copied out before `buf` dies -- the
        // struct's char* members point INTO that buffer.
        if (found->pw_dir != nullptr)
            out.record.home_dir = found->pw_dir;
        return out;
    }

    out.status = PasswdLookupStatus::kError; // still ERANGE after the retry
    return out;
}

#else // _WIN32

PasswdLookupResult getpwnam_lookup(const std::string&) {
    // No POSIX passwd database on Windows. The only consumer is macOS-only;
    // this exists so the TU compiles in the shared agent-core build.
    PasswdLookupResult out;
    out.status = PasswdLookupStatus::kError;
    return out;
}

#endif

namespace {

// The shared body. Kept in THIS translation unit so every byte the detached
// thread runs -- the lambda, its invoker, its destructor -- is agent-core text.
template <typename Fn>
PasswdLookupResult bounded_impl(std::chrono::milliseconds timeout, Fn fn) {
    PasswdLookupResult timed_out;
    timed_out.status = PasswdLookupStatus::kTimeout;
    if (timeout <= std::chrono::milliseconds::zero())
        return timed_out; // budget already spent -- don't start what we can't wait for
    auto result = yuzu::shared::bounded_call(timeout, std::move(fn));
    if (!result)
        return timed_out; // timed out, threw, or hit the outstanding-call ceiling
    return *result;
}

} // namespace

PasswdLookupResult resolve_passwd_bounded(const std::string& username,
                                          std::chrono::milliseconds timeout) {
    // No std::function anywhere on this path: the callable is a lambda whose
    // closure type is defined HERE, so its invoker/destructor are emitted here
    // too. See the header's note on why the former default argument was unsafe.
    return bounded_impl(timeout, [username]() -> PasswdLookupResult {
        return getpwnam_lookup(username);
    });
}

PasswdLookupResult resolve_passwd_bounded_for_test(const std::string& username,
                                                   std::chrono::milliseconds timeout,
                                                   const PasswdLookupFn& lookup) {
    // Test-only overload. The injected std::function is COPIED into a lambda
    // defined in this TU; a test's own target type is instantiated in the test
    // binary, which is never dlclose()'d, so this path carries no unload risk.
    return bounded_impl(timeout, [lookup, username]() -> PasswdLookupResult {
        return lookup(username);
    });
}

} // namespace yuzu::agent
