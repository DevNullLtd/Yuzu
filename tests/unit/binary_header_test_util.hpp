/**
 * binary_header_test_util.hpp -- scaffolding the PE, ELF and Mach-O header-reader tests share: a
 * recording Source, the fixture loader and one xorshift generator. Test-only; included by quoted
 * relative path.
 */

#pragma once

#include <binary_header_reader.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

namespace bhtest {

namespace bh = yuzu::shared::binary_header;

// A Source over `bytes` that records every read_at call. `visible` bounds the file to its first
// `visible` bytes without copying them, so one Probe serves every prefix of a truncation sweep
// (set `visible`, call reset()). A call at index `fail_at` answers nullopt (an I/O error).
struct Probe {
    std::string bytes;
    std::uint64_t visible{std::numeric_limits<std::uint64_t>::max()};
    std::size_t fail_at{std::numeric_limits<std::size_t>::max()};
    std::size_t calls{0};                                  // every read_at call, failed or not
    std::uint64_t total{0};                                // sum of the len of the answered calls
    std::uint64_t max_end{0};                              // highest off + len requested (saturating)
    std::vector<std::pair<std::uint64_t, std::size_t>> reads; // answered calls: offset, len

    Probe() = default;
    explicit Probe(std::string b, std::uint64_t vis = std::numeric_limits<std::uint64_t>::max())
        : bytes(std::move(b)), visible(vis) {}
    explicit Probe(const std::vector<std::uint8_t>& b, std::uint64_t vis = std::numeric_limits<std::uint64_t>::max())
        : bytes(b.begin(), b.end()), visible(vis) {}

    std::uint64_t end() const { return std::min<std::uint64_t>(visible, bytes.size()); }
    // Some request reached past the visible bytes.
    bool beyond_visible() const { return max_end > end(); }
    bool touched(std::uint64_t pos) const {
        return std::any_of(reads.begin(), reads.end(), [pos](const auto& r) {
            return pos >= r.first && pos - r.first < r.second;
        });
    }
    void reset() {
        calls = 0;
        total = 0;
        max_end = 0;
        reads.clear();
    }

    bh::Source source() {
        const std::uint64_t e = end();
        return bh::Source{[this, e](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
                              if (calls++ == fail_at)
                                  return std::nullopt;
                              reads.emplace_back(off, len);
                              total += len;
                              max_end = std::max<std::uint64_t>(
                                  max_end,
                                  len > std::numeric_limits<std::uint64_t>::max() - off
                                      ? std::numeric_limits<std::uint64_t>::max()
                                      : off + len);
                              if (off >= e)
                                  return std::string{};
                              return bytes.substr(static_cast<std::size_t>(off),
                                                  static_cast<std::size_t>(std::min<std::uint64_t>(len, e - off)));
                          },
                          e};
    }
};

// A real capture under tests/unit/fixtures/binary_headers/. A missing or empty file FAILS the
// test; it never skips.
inline std::string load_fixture(const char* name) {
    const auto path = std::filesystem::path{YUZU_TEST_FIXTURE_DIR} / "binary_headers" / name;
    INFO("fixture path: " << path.string());
    REQUIRE(std::filesystem::exists(path));
    std::ifstream in(path, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    REQUIRE_FALSE(data.empty());
    return data;
}

inline std::uint64_t xorshift(std::uint64_t& s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

} // namespace bhtest
