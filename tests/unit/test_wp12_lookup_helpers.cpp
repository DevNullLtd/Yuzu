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
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <new>
#include <unordered_set>
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
    CHECK(yuzu::shared::release_dns_cache_list(static_cast<FakeNode*>(nullptr), std::ref(log)) == 0);
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

TEST_CASE("dns cache list release: a shared name is freed once and the walk continues",
          "[wp12][dns_cache_list]") {
    wchar_t shared_name[2] = {L'a', 0};
    FakeNode n[3];
    for (int i = 0; i < 3; ++i) {
        n[i].pszName = shared_name;
        n[i].pNext = i < 2 ? &n[i + 1] : nullptr;
    }
    FreeLog log;
    // Two healthy nodes aliasing one name buffer is not corruption: all three nodes are freed
    // (not a leaked tail) and the shared buffer exactly once.
    CHECK(yuzu::shared::release_dns_cache_list(&n[0], std::ref(log)) == 3);
    CHECK_FALSE(log.any_double_free());
    CHECK(log.order.size() == 4); // 3 nodes + 1 name
}

TEST_CASE("dns cache list release: a self-looping node stops the walk", "[wp12][dns_cache_list]") {
    wchar_t a[2] = {L'a', 0}, b[2] = {L'b', 0};
    FakeNode x, y;
    x.pszName = a;
    y.pszName = b;
    x.pNext = &y;
    y.pNext = &y; // self loop
    FreeLog log;
    CHECK(yuzu::shared::release_dns_cache_list(&x, std::ref(log)) == 2);
    CHECK_FALSE(log.any_double_free());
}

namespace {

// Real heap blocks, so an ASan/UBSan build turns a double free or a use-after-free into an abort.
// A "block" is freed through `release` exactly like the production free callback (std::free), and
// the harness frees only what the walk did NOT (tracked in `live`), so the test itself never frees
// twice and a leak is the allowed outcome of a stopped walk.
struct HeapList {
    std::vector<FakeNode*> nodes;
    std::set<void*> live; // blocks not yet freed
    FakeNode* make(wchar_t* name = nullptr) {
        auto* n = static_cast<FakeNode*>(std::calloc(1, sizeof(FakeNode)));
        n->pszName = name;
        nodes.push_back(n);
        live.insert(n);
        return n;
    }
    wchar_t* buf() {
        auto* b = static_cast<wchar_t*>(std::calloc(4, sizeof(wchar_t)));
        live.insert(b);
        return b;
    }
    void link() {
        for (std::size_t i = 0; i + 1 < nodes.size(); ++i)
            nodes[i]->pNext = nodes[i + 1];
    }
    // Returns the number of nodes the walk freed; asserts nothing was freed twice.
    std::size_t release(bool& double_freed) {
        double_freed = false;
        const auto n = yuzu::shared::release_dns_cache_list(nodes[0], [&](void* p) {
            if (live.erase(p) == 0) {
                double_freed = true; // not live: a second free (do NOT actually free again)
                return;
            }
            std::free(p);
        });
        for (void* p : live) // what the stopped walk leaked
            std::free(p);
        return n;
    }
};

} // namespace

// The four aliasing shapes below are the round-3 regression (N3-1): with the node and name sets
// split they were a double free or a use-after-free. They are only MEANINGFUL under
// -fsanitize=address (the use-after-free is a read of a freed node); the double_freed flag also
// catches the double free in a plain build.
TEST_CASE("dns cache list release: a name equal to a LATER node stops the walk",
          "[wp12][dns_cache_list][asan]") {
    HeapList h;
    auto* n0 = h.make();
    auto* n1 = h.make(h.buf());
    n0->pszName = reinterpret_cast<wchar_t*>(n1); // n0's "name" is node n1
    h.link();
    bool dbl = false;
    const auto freed = h.release(dbl);
    CHECK_FALSE(dbl);
    CHECK(freed == 1); // n0 freed (and n1 as its name); the walk stopped on reaching n1
}

TEST_CASE("dns cache list release: a name equal to its OWN node stops the walk",
          "[wp12][dns_cache_list][asan]") {
    HeapList h;
    auto* n0 = h.make();
    n0->pszName = reinterpret_cast<wchar_t*>(n0);
    h.make(h.buf());
    h.link();
    bool dbl = false;
    CHECK(h.release(dbl) == 0);
    CHECK_FALSE(dbl);
}

TEST_CASE("dns cache list release: a later node's name equal to the earlier-freed node stops the walk",
          "[wp12][dns_cache_list][asan]") {
    HeapList h;
    h.make(h.buf());
    auto* n1 = h.make();
    n1->pszName = reinterpret_cast<wchar_t*>(h.nodes[0]); // aliases n0, already freed
    h.link();
    bool dbl = false;
    CHECK(h.release(dbl) == 1);
    CHECK_FALSE(dbl);
}

TEST_CASE("dns cache list release: a name equal to an earlier VISITED node stops the walk",
          "[wp12][dns_cache_list][asan]") {
    HeapList h;
    h.make(h.buf());
    h.make(h.buf());
    auto* n2 = h.make();
    n2->pszName = reinterpret_cast<wchar_t*>(h.nodes[0]); // aliases n0, visited two nodes ago
    h.link();
    bool dbl = false;
    CHECK(h.release(dbl) == 2);
    CHECK_FALSE(dbl);
}

namespace {

// A visited-set whose allocator throws bad_alloc after `budget` allocations (g8-1).
struct Budget {
    static inline int remaining = 0;
};
template <typename T>
struct ThrowingAlloc {
    using value_type = T;
    ThrowingAlloc() = default;
    template <typename U>
    ThrowingAlloc(const ThrowingAlloc<U>&) {}
    T* allocate(std::size_t n) {
        if (Budget::remaining-- <= 0)
            throw std::bad_alloc();
        return std::allocator<T>{}.allocate(n);
    }
    void deallocate(T* p, std::size_t n) { std::allocator<T>{}.deallocate(p, n); }
    template <typename U>
    bool operator==(const ThrowingAlloc<U>&) const { return true; }
};
using ThrowingSet = std::unordered_set<const void*, std::hash<const void*>,
                                       std::equal_to<const void*>, ThrowingAlloc<const void*>>;

} // namespace

TEST_CASE("dns cache list release: an allocation failure leaks the rest and never throws",
          "[wp12][dns_cache_list]") {
    std::vector<FakeNode> nodes(50);
    std::vector<wchar_t> names(50);
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        nodes[i].pszName = &names[i];
        nodes[i].pNext = i + 1 < nodes.size() ? &nodes[i + 1] : nullptr;
    }
    Budget::remaining = 6; // enough for a few nodes, then bad_alloc inside the walk
    FreeLog log;
    std::size_t freed = 0;
    REQUIRE_NOTHROW(freed = yuzu::shared::release_dns_cache_list<ThrowingSet>(&nodes[0], std::ref(log)));
    CHECK(freed < nodes.size()); // stopped early: the remainder leaks
    CHECK_FALSE(log.any_double_free());
    Budget::remaining = 0; // immediately failing allocator: nothing freed, still no throw
    FreeLog none;
    REQUIRE_NOTHROW(freed = yuzu::shared::release_dns_cache_list<ThrowingSet>(&nodes[0], std::ref(none)));
    CHECK(freed == 0);
    CHECK(none.order.empty());
}

namespace {
// A set whose CONSTRUCTOR throws (MSVC's containers allocate in the constructor).
struct CtorThrowsSet {
    CtorThrowsSet() { throw std::bad_alloc(); }
    struct R { bool second; };
    R insert(const void*) { return {true}; }
    const void* const* find(const void*) { return nullptr; }
    const void* const* end() { return nullptr; }
};
} // namespace

TEST_CASE("dns cache list release: a throwing set constructor leaks the list and never throws",
          "[wp12][dns_cache_list]") {
    FakeNode n;
    FreeLog log;
    std::size_t freed = 99;
    REQUIRE_NOTHROW(freed = yuzu::shared::release_dns_cache_list<CtorThrowsSet>(&n, std::ref(log)));
    CHECK(freed == 0);
    CHECK(log.order.empty());
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
