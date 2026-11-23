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
#include <vector>

#include <pwd.h>
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

TEST_CASE("printing identity: the uid is forwarded to the lookup", "[printing][identity]") {
    uid_t seen = 0;
    auto fake = [&](uid_t uid, struct passwd* pw, char* buf, size_t len, struct passwd** res) {
        seen = uid;
        std::strncpy(buf, "carol", len);
        pw->pw_name = buf;
        *res = pw;
        return 0;
    };
    CHECK(username_for_uid(4242, fake) == "carol");
    CHECK(seen == 4242);
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
        CHECK(max_len == yuzu::printing::kMaxPasswdBufferBytes);
    }
    SECTION("error with a non-null result is still empty") {
        auto fake = [](uid_t, struct passwd* pw, char* buf, size_t len, struct passwd** res) {
            std::strncpy(buf, "mallory", len);
            pw->pw_name = buf;
            *res = pw;
            return EIO;
        };
        CHECK(username_for_uid(1, fake).empty());
    }
    SECTION("empty pw_name") {
        auto fake = [](uid_t, struct passwd* pw, char* buf, size_t len, struct passwd** res) {
            std::strncpy(buf, "", len);
            pw->pw_name = buf;
            *res = pw;
            return 0;
        };
        CHECK(username_for_uid(1, fake).empty());
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

TEST_CASE("printing identity: the real lookup matches an independent getpwuid_r",
          "[printing][identity]") {
    auto independent = [](uid_t uid) -> std::string {
        std::vector<char> buf(16384);
        struct passwd pw{};
        struct passwd* res = nullptr;
        if (::getpwuid_r(uid, &pw, buf.data(), buf.size(), &res) != 0 || res == nullptr ||
            res->pw_name == nullptr)
            return {};
        return res->pw_name;
    };

    SECTION("current euid") {
        const std::string expected = independent(::geteuid());
        if (expected.empty())
            SKIP("the effective uid has no passwd entry on this host");
        CHECK(username_for_uid(::geteuid()) == expected);
    }
    SECTION("uid 0") {
        if (independent(0) != "root")
            SKIP("no root entry for uid 0 on this host");
        CHECK(username_for_uid(0) == "root");
    }
    SECTION("an unassigned uid is empty") {
        if (!independent(4000000000u).empty())
            SKIP("uid 4000000000 is assigned on this host");
        CHECK(username_for_uid(4000000000u).empty());
    }
}

#endif // !_WIN32
