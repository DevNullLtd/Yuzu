/**
 * test_printing_identity.cpp -- #4679: printing_identity.hpp resolves the effective user through a
 * reentrant getpwuid_r-shaped lookup into an owned, ERANGE-growing buffer, and reports "" (no
 * resolvable identity, the clear_queue `no_identity` branch) on every failure.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "printing_identity.hpp"

#include <cstring>
#include <string>

#include <unistd.h>

namespace {

using yuzu::printing::username_for_uid;

} // namespace

TEST_CASE("printing identity: a found record yields its name", "[printing][identity]") {
    auto fake = [](uid_t, struct passwd* pw, char* buf, size_t len, struct passwd** res) {
        std::strncpy(buf, "alice", len);
        pw->pw_name = buf;
        *res = pw;
        return 0;
    };
    CHECK(username_for_uid(1000, fake) == "alice");
}

TEST_CASE("printing identity: ERANGE grows the buffer and retries", "[printing][identity]") {
    std::size_t calls = 0;
    std::size_t last_len = 0;
    auto fake = [&](uid_t, struct passwd* pw, char* buf, size_t len, struct passwd** res) {
        ++calls;
        last_len = len;
        if (len < 16384)
            return ERANGE;
        std::strncpy(buf, "bob", len);
        pw->pw_name = buf;
        *res = pw;
        return 0;
    };
    CHECK(username_for_uid(1000, fake) == "bob");
    CHECK(calls == 3); // 4096 -> 8192 -> 16384
    CHECK(last_len == 16384);
}

TEST_CASE("printing identity: every failure is an empty name (fail closed)",
          "[printing][identity]") {
    SECTION("not found: rc 0, null result") {
        auto fake = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
            *res = nullptr;
            return 0;
        };
        CHECK(username_for_uid(1, fake).empty());
    }
    SECTION("lookup error") {
        auto fake = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
            *res = nullptr;
            return EIO;
        };
        CHECK(username_for_uid(1, fake).empty());
    }
    SECTION("ERANGE forever stops at the cap") {
        std::size_t max_len = 0;
        auto fake = [&](uid_t, struct passwd*, char*, size_t len, struct passwd** res) {
            max_len = len;
            *res = nullptr;
            return ERANGE;
        };
        CHECK(username_for_uid(1, fake).empty());
        CHECK(max_len <= yuzu::printing::kMaxPasswdBufferBytes);
    }
    SECTION("null pw_name") {
        auto fake = [](uid_t, struct passwd* pw, char*, size_t, struct passwd** res) {
            pw->pw_name = nullptr;
            *res = pw;
            return 0;
        };
        CHECK(username_for_uid(1, fake).empty());
    }
}

TEST_CASE("printing identity: the real lookup resolves the current euid", "[printing][identity]") {
    // Always present on a host that can run the suite; "" would mean the passwd db lacks it.
    CHECK_FALSE(username_for_uid(::geteuid()).empty());
}

#endif // !_WIN32
