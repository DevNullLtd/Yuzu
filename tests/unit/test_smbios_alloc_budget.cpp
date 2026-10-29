/**
 * test_smbios_alloc_budget.cpp -- agents/shared/smbios_parsers.hpp: a structure past the per-type
 * entry cap (kMaxEntriesPerType) is never DECODED, so it allocates nothing.
 *
 * Separate executable: counting replaces the global operator new/delete, which is process-wide
 * (as in test_spark_alloc_budget.cpp). Built on Linux and macOS; not under sanitizers (they own the
 * allocator) and not on Windows (the replacement is unmeasured under MSVC).
 * Pins what result-level asserts cannot see: over-decoding copies the strings, then discards them.
 * Positive control: a counter that never ran reads zero and would make the equality vacuous.
 */
#include <smbios_parsers.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace sm = yuzu::shared::smbios;
using Bytes = std::vector<std::uint8_t>;

namespace {
// thread_local and constant-initialised: no static-init ordering, and Catch2's own allocations on
// other threads cannot perturb a measurement taken on the arming thread.
thread_local std::uint64_t g_allocs = 0;
thread_local bool g_counting = false;
} // namespace

// Plain pair only: libstdc++/libc++ route the nothrow, array and sized forms through these, and
// nothing the walker builds is over-aligned.
void* operator new(std::size_t n) {
    if (g_counting)
        ++g_allocs;
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {

/// Deliberately long: a string must exceed every standard library's SSO threshold, or the copies
/// this case counts would be free and the pin inert.
const std::string kLong(80, 'x');

/// One structure: `len` formatted bytes (type/length set, `idx` = {offset, string index} pairs
/// patched in) followed by `nstr` copies of kLong and the closing NUL.
Bytes structure(unsigned type, std::size_t len,
                std::vector<std::pair<std::size_t, unsigned>> idx, unsigned nstr) {
    Bytes b(len, 0);
    b[0] = static_cast<std::uint8_t>(type);
    b[1] = static_cast<std::uint8_t>(len);
    for (const auto& [off, i] : idx)
        b[off] = static_cast<std::uint8_t>(i);
    for (unsigned s = 0; s < nstr; ++s) {
        b.insert(b.end(), kLong.begin(), kLong.end());
        b.push_back(0);
    }
    b.push_back(0);
    return b;
}

struct Probe {
    std::uint64_t allocs;
    std::size_t kept;
    bool cap_hit;
};

/// Allocations of ONE parse_table over `n` identical string-rich structures of `type` (4 or 17).
Probe probe(unsigned type, int n) {
    const Bytes one = type == 4
                          ? structure(4, 0x30, {{4, 1}}, 1) // socket designation
                          : structure(17, 0x5C, {{0x0C, 1}, {0x10, 1}, {0x11, 2}, {0x17, 3}, {0x18, 4}, {0x1A, 5}}, 5);
    Bytes t;
    for (int i = 0; i < n; ++i)
        t.insert(t.end(), one.begin(), one.end());
    g_allocs = 0;
    g_counting = true;
    const sm::SmbiosTable r = sm::parse_table(t);
    g_counting = false;
    return {g_allocs, type == 4 ? r.processors.size() : r.memory_devices.size(), r.entry_cap_hit};
}

} // namespace

TEST_CASE("smbios walker: structures past the entry cap allocate nothing", "[smbios][alloc]") {
    for (const unsigned type : {4u, 17u}) {
        INFO("structure type " << type);
        const std::uint64_t strings_per_entry = type == 4 ? 1 : 5;
        const Probe at_cap = probe(type, static_cast<int>(sm::kMaxEntriesPerType));
        REQUIRE(at_cap.kept == sm::kMaxEntriesPerType);
        REQUIRE_FALSE(at_cap.cap_hit);
        REQUIRE(at_cap.allocs >= sm::kMaxEntriesPerType * strings_per_entry); // positive control

        for (const int n : {257, 300}) {
            INFO("structures " << n);
            const Probe over = probe(type, n);
            CHECK(over.kept == sm::kMaxEntriesPerType);
            CHECK(over.cap_hit);
            CHECK(over.allocs == at_cap.allocs);
        }
    }
}
