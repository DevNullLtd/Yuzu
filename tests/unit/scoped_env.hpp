#pragma once

/**
 * scoped_env.hpp -- yuzu::test::ScopedEnv, an RAII save/restore of a single
 * environment variable's value for the duration of a test.
 *
 * Promoted (per docs/testing/unit-test-conventions.md's promote-at-second-use
 * convention) from test_cert_discovery.cpp:138's locally-defined
 * `ScopedEnv` (this type's shape is copied from there verbatim, generalised
 * only to compile off-Apple): test_server_ota_options.cpp:59 and
 * server/test_auth.cpp:157 each also carry their own local, unshared
 * `ScopedEnv`, and test_script_exec_actions.cpp /
 * test_hardware_device_identity_posix_actions.cpp / test_subprocess_runner.cpp
 * all do raw inline setenv/unsetenv with no helper at all -- at least this
 * many known local duplicates exist across the suite as of this file (not
 * necessarily an exhaustive count). This header does not migrate any of
 * those existing local copies (out of scope for this package); it exists
 * so certificates' own two new TUs share one implementation rather than
 * adding a FIFTH hand-copied local struct.
 *
 * Restores whatever the variable held before construction (including "did
 * not exist", via unsetenv), unconditionally in the destructor -- so a
 * REQUIRE/SKIP/exception unwinding between construction and the end of scope
 * never leaks a mutated value into the rest of the test binary.
 *
 * PLATFORM SPLIT IS LOAD-BEARING, same reasoning as
 * test_server_ota_options.cpp:59 and test_subprocess_runner.cpp's own
 * `_WIN32` section: `setenv`/`unsetenv` are POSIX and the MSVC CRT supplies
 * neither, so an unconditional call fails to COMPILE on the Windows leg --
 * and this header is included by test_certificates_macos.cpp, which (unlike
 * its __APPLE__-gated sibling test_certificates_macos_actions.cpp) compiles
 * and runs its pure vectors on every platform, Windows included.
 */

#include <cstdlib>
#include <string>

namespace yuzu::test {

class ScopedEnv {
public:
    ScopedEnv(std::string name, const std::string& value) : name_(std::move(name)) {
        capture_prev();
        set(value);
    }

    ~ScopedEnv() {
        if (had_prev_)
            set(prev_);
        else
            unset();
    }

    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    void capture_prev() {
        if (const char* cur = std::getenv(name_.c_str())) {
            had_prev_ = true;
            prev_ = cur;
        }
    }

    void set(const std::string& value) {
#ifdef _WIN32
        (void)_putenv_s(name_.c_str(), value.c_str());
#else
        ::setenv(name_.c_str(), value.c_str(), 1);
#endif
    }

    void unset() {
#ifdef _WIN32
        // Assigning an empty value is the documented MSVC CRT way to remove
        // a variable -- there is no `_unputenv_s`.
        (void)_putenv_s(name_.c_str(), "");
#else
        ::unsetenv(name_.c_str());
#endif
    }

    std::string name_;
    bool had_prev_ = false;
    std::string prev_;
};

} // namespace yuzu::test
