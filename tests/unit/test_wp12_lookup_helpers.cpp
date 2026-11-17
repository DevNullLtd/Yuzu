/**
 * test_wp12_lookup_helpers.cpp -- the portable helper cores behind the WP12 fixes, driven with
 * injected lookups / a fake list so every branch runs on every POSIX host without a passwd
 * database or a Windows resolver:
 *   - users_group_lookup.hpp: not-found vs error vs ERANGE growth vs ERANGE exhausted (F40);
 *   - filesystem_posix_names.hpp: numeric-id fallback (F63);
 *   - dns_cache_list.hpp: the resolver-cache list release walk, incl. a cyclic list, a shared
 *     node, a shared name and the node ceiling (F64/F66).
 */
#include <catch2/catch_test_macros.hpp>

#include "dns_cache_list.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <vector>

#ifndef _WIN32
#include "filesystem_posix_names.hpp"
#include "users_group_lookup.hpp"

namespace {

using yuzu::users::LookupStatus;

int found_group(const char*, struct group* g, char* buf, size_t len, struct group** res) {
    // buf holds: "alice\0bob\0" then a NULL-terminated pointer vector placed after it.
    const char* names[] = {"alice", "bob"};
    size_t off = 0;
    char** vec = reinterpret_cast<char**>((reinterpret_cast<uintptr_t>(buf) + 7) & ~uintptr_t{7});
    for (int i = 0; i < 2; ++i) {
        (void)len;
        char* dst = buf + 64 + off;
        std::strcpy(dst, names[i]);
        vec[i] = dst;
        off += std::strlen(names[i]) + 1;
    }
    vec[2] = nullptr;
    g->gr_gid = 27;
    g->gr_mem = vec;
    *res = g;
    return 0;
}

} // namespace

TEST_CASE("users lookup: found copies gid and members", "[wp12][users_lookup]") {
    const auto r = yuzu::users::lookup_group_copy("sudo", found_group);
    REQUIRE(r.status == LookupStatus::kOk);
    CHECK(r.group.gid == 27);
    CHECK(r.group.members == std::vector<std::string>{"alice", "bob"});
}

TEST_CASE("users lookup: not found is distinct from error", "[wp12][users_lookup]") {
    SECTION("rc 0, null result is NOT FOUND") {
        auto fn = [](const char*, struct group*, char*, size_t, struct group** res) {
            *res = nullptr;
            return 0;
        };
        CHECK(yuzu::users::lookup_group_copy("x", fn).status == LookupStatus::kNotFound);
    }
    SECTION("ENOENT and ESRCH are NOT FOUND") {
        for (int e : {ENOENT, ESRCH}) {
            auto fn = [e](const char*, struct group*, char*, size_t, struct group** res) {
                *res = nullptr;
                return e;
            };
            CHECK(yuzu::users::lookup_group_copy("x", fn).status == LookupStatus::kNotFound);
        }
    }
    SECTION("a hard error is ERROR, never not-found") {
        for (int e : {EIO, EPERM, EBADF, EMFILE}) {
            auto fn = [e](const char*, struct group*, char*, size_t, struct group** res) {
                *res = nullptr;
                return e;
            };
            CHECK(yuzu::users::lookup_group_copy("x", fn).status == LookupStatus::kError);
        }
    }
}

TEST_CASE("users lookup: ERANGE grows the buffer, exhaustion is an error", "[wp12][users_lookup]") {
    SECTION("grows until it fits") {
        size_t calls = 0;
        auto fn = [&](const char*, struct group* g, char*, size_t len, struct group** res) {
            ++calls;
            if (len < 16384)
                return ERANGE;
            static char* none[] = {nullptr};
            g->gr_gid = 5;
            g->gr_mem = none;
            *res = g;
            return 0;
        };
        const auto r = yuzu::users::lookup_group_copy("x", fn);
        CHECK(r.status == LookupStatus::kOk);
        CHECK(calls == 3);
    }
    SECTION("ERANGE forever stops at the cap and is an ERROR") {
        size_t max_len = 0;
        auto fn = [&](const char*, struct group*, char*, size_t len, struct group** res) {
            max_len = len;
            *res = nullptr;
            return ERANGE;
        };
        CHECK(yuzu::users::lookup_group_copy("x", fn).status == LookupStatus::kError);
        CHECK(max_len == yuzu::users::kMaxLookupBufferBytes);
    }
}

TEST_CASE("users lookup: user-name not found vs error", "[wp12][users_lookup]") {
    auto nf = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
        *res = nullptr;
        return 0;
    };
    auto err = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
        *res = nullptr;
        return EIO;
    };
    CHECK(yuzu::users::lookup_user_name(0, nf).status == LookupStatus::kNotFound);
    CHECK(yuzu::users::lookup_user_name(0, err).status == LookupStatus::kError);
    const auto real = yuzu::users::lookup_user_name(0); // root exists on every supported host
    CHECK(real.status == LookupStatus::kOk);
    CHECK(real.name == "root");
}

TEST_CASE("filesystem names: an unresolved id falls back to the numeric id",
          "[wp12][fs_names]") {
    auto pw_none = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
        *res = nullptr;
        return 0;
    };
    auto gr_err = [](gid_t, struct group*, char*, size_t, struct group** res) {
        *res = nullptr;
        return EIO;
    };
    auto pw_range = [](uid_t, struct passwd*, char*, size_t, struct passwd** res) {
        *res = nullptr;
        return ERANGE;
    };
    CHECK(yuzu::filesystem::owner_name_or_numeric(4242424, pw_none) == "4242424");
    CHECK(yuzu::filesystem::group_name_or_numeric(4242425, gr_err) == "4242425");
    CHECK(yuzu::filesystem::owner_name_or_numeric(7, pw_range) == "7"); // cap exhausted
    CHECK(yuzu::filesystem::owner_name_or_numeric(0) == "root");
}
#endif // !_WIN32

namespace {

struct FakeNode {
    FakeNode* pNext = nullptr;
    wchar_t* pszName = nullptr;
};

struct FreeLog {
    std::vector<const void*> order;
    std::multiset<const void*> seen;
    void operator()(void* p) {
        order.push_back(p);
        seen.insert(p);
    }
    bool any_double_free() const {
        for (const void* p : seen)
            if (seen.count(p) > 1)
                return true;
        return false;
    }
};

} // namespace

TEST_CASE("dns cache list release: frees every node and name once", "[wp12][dns_cache_list]") {
    wchar_t names[3][2] = {{L'a', 0}, {L'b', 0}, {L'c', 0}};
    FakeNode n[3];
    for (int i = 0; i < 3; ++i) {
        n[i].pszName = names[i];
        n[i].pNext = i < 2 ? &n[i + 1] : nullptr;
    }
    FreeLog log;
    CHECK(yuzu::shared::release_dns_cache_list(&n[0], std::ref(log)) == 3);
    CHECK(log.order.size() == 6);
    CHECK_FALSE(log.any_double_free());
    CHECK(yuzu::shared::release_dns_cache_list<FakeNode>(nullptr, std::ref(log)) == 0);
}

TEST_CASE("dns cache list release: a cyclic list is never freed twice", "[wp12][dns_cache_list]") {
    wchar_t names[3][2] = {{L'a', 0}, {L'b', 0}, {L'c', 0}};
    FakeNode n[3];
    for (int i = 0; i < 3; ++i) {
        n[i].pszName = names[i];
        n[i].pNext = &n[(i + 1) % 3]; // 0 -> 1 -> 2 -> 0
    }
    FreeLog log;
    CHECK(yuzu::shared::release_dns_cache_list(&n[0], std::ref(log)) == 3);
    CHECK_FALSE(log.any_double_free());
}

TEST_CASE("dns cache list release: a shared node or a shared name stops the walk",
          "[wp12][dns_cache_list]") {
    SECTION("two names alias one buffer") {
        wchar_t shared_name[2] = {L'a', 0};
        FakeNode n[3];
        for (int i = 0; i < 3; ++i) {
            n[i].pszName = shared_name;
            n[i].pNext = i < 2 ? &n[i + 1] : nullptr;
        }
        FreeLog log;
        yuzu::shared::release_dns_cache_list(&n[0], std::ref(log));
        CHECK_FALSE(log.any_double_free());
    }
    SECTION("one node reachable twice") {
        wchar_t a[2] = {L'a', 0}, b[2] = {L'b', 0};
        FakeNode x, y;
        x.pszName = a;
        y.pszName = b;
        x.pNext = &y;
        y.pNext = &y; // self loop
        FreeLog log;
        yuzu::shared::release_dns_cache_list(&x, std::ref(log));
        CHECK_FALSE(log.any_double_free());
    }
}

TEST_CASE("dns cache list release: the node ceiling bounds a long list", "[wp12][dns_cache_list]") {
    const std::size_t total = yuzu::shared::kDnsCacheNodeWalkCap + 100;
    std::vector<FakeNode> nodes(total);
    for (std::size_t i = 0; i + 1 < total; ++i)
        nodes[i].pNext = &nodes[i + 1];
    FreeLog log;
    CHECK(yuzu::shared::release_dns_cache_list(&nodes[0], std::ref(log)) ==
          yuzu::shared::kDnsCacheNodeWalkCap);
}
