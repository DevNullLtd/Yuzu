/**
 * test_binary_header_reader.cpp -- the bounds, budget and endian rules of
 * agents/shared/binary_header_reader.hpp, the leaf the PE, ELF and Mach-O header readers share.
 * Pure logic over in-memory bytes: no file, no process.
 */

#include <catch2/catch_test_macros.hpp>

#include <binary_header_reader.hpp>

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

using namespace yuzu::shared::binary_header;

namespace {

constexpr std::uint64_t kMax64 = std::numeric_limits<std::uint64_t>::max();
// A copy would carry its own counters and fork the budget, so there is none.
static_assert(!std::copy_constructible<Reader> && !std::assignable_from<Reader&, const Reader&>);

std::array<std::byte, 16> sixteen_bytes() {
    std::array<std::byte, 16> a{};
    for (std::size_t i = 0; i < a.size(); ++i)
        a[i] = static_cast<std::byte>(i + 1);
    return a;
}

// A Source of `size` bytes whose read_at counts its calls and answers with `answer`.
struct Counting {
    int calls{0};
    std::function<std::optional<std::string>(std::uint64_t, std::size_t)> answer;
    Source source(std::uint64_t size) {
        return Source{[this](std::uint64_t o, std::size_t l) {
                          ++calls;
                          return answer(o, l);
                      },
                      size};
    }
};

Counting zero_filled() {
    Counting c;
    c.answer = [](std::uint64_t, std::size_t l) { return std::optional<std::string>(std::string(l, 'z')); };
    return c;
}

} // namespace

TEST_CASE("binary_header: to_token names every error", "[binary_header][reader]") {
    CHECK(to_token(ParseError::io) == "io");
    CHECK(to_token(ParseError::truncated) == "truncated");
    CHECK(to_token(ParseError::not_this_format) == "not_this_format");
    CHECK(to_token(ParseError::malformed) == "malformed");
    CHECK(to_token(ParseError::limit_exceeded) == "limit_exceeded");
}

TEST_CASE("binary_header: read serves in-range bytes from a span source", "[binary_header][reader]") {
    const auto bytes = sixteen_bytes();
    Reader r(span_source(bytes));
    CHECK(r.size() == 16);
    const auto head = r.read(0, 4);
    REQUIRE(head.has_value());
    CHECK(*head == std::string("\x01\x02\x03\x04", 4));
    const auto tail = r.read(12, 4);
    REQUIRE(tail.has_value());
    CHECK(*tail == std::string("\x0d\x0e\x0f\x10", 4));
}

TEST_CASE("binary_header: read never calls read_at for overflow, past-size or over-budget requests",
          "[binary_header][reader]") {
    SECTION("offset + len overflows") {
        auto c = zero_filled();
        Reader r(c.source(kMax64));
        const auto got = r.read(kMax64, 1);
        REQUIRE_FALSE(got.has_value());
        CHECK(got.error() == ParseError::truncated);
        CHECK(r.read(kMax64 - 3, 8).error() == ParseError::truncated);
        CHECK(c.calls == 0);
    }
    SECTION("offset + len passes the size, by one byte and by a lot") {
        auto c = zero_filled();
        Reader r(c.source(100));
        CHECK(r.read(99, 2).error() == ParseError::truncated);
        CHECK(r.read(101, 0).error() == ParseError::truncated);
        CHECK(r.read(0, 101).error() == ParseError::truncated);
        CHECK(r.read(1000, 1).error() == ParseError::truncated);
        CHECK(c.calls == 0);
    }
    SECTION("the exact end of the source is readable") {
        auto c = zero_filled();
        Reader r(c.source(100));
        REQUIRE(r.read(96, 4).has_value());
        REQUIRE(r.read(100, 0).has_value());
        CHECK(c.calls == 2);
    }
    SECTION("max_bytes would be passed") {
        auto c = zero_filled();
        Reader r(c.source(1000), ReadBudget{.max_bytes = 10, .max_reads = 100});
        CHECK(r.read(0, 11).error() == ParseError::limit_exceeded);
        CHECK(c.calls == 0);
        REQUIRE(r.read(0, 6).has_value());
        CHECK(r.read(0, 5).error() == ParseError::limit_exceeded); // 6 + 5 > 10
        CHECK(c.calls == 1);
        REQUIRE(r.read(0, 4).has_value()); // 6 + 4 == 10 is allowed
        CHECK(r.read(0, 1).error() == ParseError::limit_exceeded);
        CHECK(c.calls == 2);
    }
    SECTION("max_reads would be passed") {
        auto c = zero_filled();
        Reader r(c.source(1000), ReadBudget{.max_bytes = 1000, .max_reads = 2});
        REQUIRE(r.read(0, 1).has_value());
        REQUIRE(r.read(1, 1).has_value());
        CHECK(r.read(2, 1).error() == ParseError::limit_exceeded);
        CHECK(c.calls == 2);
    }
    SECTION("a size_t-sized len over a huge size is bounded by the byte budget, not allocated") {
        auto c = zero_filled();
        Reader r(c.source(kMax64));
        CHECK(r.read(0, std::numeric_limits<std::size_t>::max() / 2).error() ==
              ParseError::limit_exceeded);
        CHECK(c.calls == 0);
    }
}

TEST_CASE("binary_header: read maps what read_at answers", "[binary_header][reader]") {
    Counting c;
    SECTION("nullopt is io") {
        c.answer = [](std::uint64_t, std::size_t) { return std::optional<std::string>{}; };
        Reader r(c.source(10));
        CHECK(r.read(0, 4).error() == ParseError::io);
    }
    SECTION("a short answer is truncated") {
        c.answer = [](std::uint64_t, std::size_t l) {
            return std::optional<std::string>(std::string(l - 1, 'x'));
        };
        Reader r(c.source(10));
        CHECK(r.read(0, 4).error() == ParseError::truncated);
    }
    SECTION("an over-long answer is malformed") {
        c.answer = [](std::uint64_t, std::size_t l) {
            return std::optional<std::string>(std::string(l + 1, 'x'));
        };
        Reader r(c.source(10));
        CHECK(r.read(0, 4).error() == ParseError::malformed);
    }
    SECTION("an empty read_at function is io, not an exception") {
        Reader r(Source{ReadAt{}, 10});
        CHECK(r.read(0, 4).error() == ParseError::io);
    }
}

TEST_CASE("binary_header: span_source over an empty span is size 0 and every read truncates",
          "[binary_header][reader]") {
    const Source s = span_source({});
    CHECK(s.size == 0);
    Reader r(s);
    CHECK(r.size() == 0);
    CHECK(r.read(0, 1).error() == ParseError::truncated);
    CHECK(r.read(5, 1).error() == ParseError::truncated);
    CHECK(r.read(0, 64).error() == ParseError::truncated);
}

TEST_CASE("binary_header: span_source answers short only at the end of data", "[binary_header][reader]") {
    const auto bytes = sixteen_bytes();
    const Source s = span_source(bytes);
    CHECK(s.read_at(0, 16)->size() == 16);
    CHECK(s.read_at(10, 100)->size() == 6);
    CHECK(s.read_at(16, 4)->empty());
    CHECK(s.read_at(1000, 4)->empty());
}

TEST_CASE("binary_header: read_c_string cuts at the first NUL", "[binary_header][reader]") {
    const std::string raw("abc\0def\0", 8);
    const auto* p = reinterpret_cast<const std::byte*>(raw.data());
    Reader r(span_source({p, raw.size()}));

    SECTION("string at the start") {
        const auto s = r.read_c_string(0, 8);
        REQUIRE(s.has_value());
        CHECK(*s == "abc");
    }
    SECTION("string at an offset, the NUL being the last byte read") {
        const auto s = r.read_c_string(4, 4);
        REQUIRE(s.has_value());
        CHECK(*s == "def");
    }
    SECTION("an empty string") {
        const auto s = r.read_c_string(3, 8);
        REQUIRE(s.has_value());
        CHECK(s->empty());
    }
    SECTION("no NUL inside max_len is limit_exceeded") {
        CHECK(r.read_c_string(0, 3).error() == ParseError::limit_exceeded);
        CHECK(r.read_c_string(4, 3).error() == ParseError::limit_exceeded);
        CHECK(r.read_c_string(0, 0).error() == ParseError::limit_exceeded);
    }
    SECTION("max_len past the end reads only what is there") {
        const auto s = r.read_c_string(4, 1000);
        REQUIRE(s.has_value());
        CHECK(*s == "def");
    }
    SECTION("offset past the size is truncated; at the size there is no NUL") {
        CHECK(r.read_c_string(9, 4).error() == ParseError::truncated);
        CHECK(r.read_c_string(8, 4).error() == ParseError::limit_exceeded);
    }
}

TEST_CASE("binary_header: read_c_string obeys the read budget", "[binary_header][reader]") {
    auto c = zero_filled();
    Reader r(c.source(1000), ReadBudget{.max_bytes = 8, .max_reads = 4});
    CHECK(r.read_c_string(0, 9).error() == ParseError::limit_exceeded);
    CHECK(c.calls == 0);
}

TEST_CASE("binary_header: checked_add returns nullopt exactly on overflow", "[binary_header][reader]") {
    CHECK(checked_add(0, 0) == 0);
    CHECK(checked_add(1, 2) == 3);
    CHECK(checked_add(kMax64, 0) == kMax64);
    CHECK(checked_add(0, kMax64) == kMax64);
    CHECK(checked_add(kMax64 - 1, 1) == kMax64);
    CHECK(checked_add(1, kMax64 - 1) == kMax64);
    CHECK_FALSE(checked_add(kMax64, 1).has_value());
    CHECK_FALSE(checked_add(1, kMax64).has_value());
    CHECK_FALSE(checked_add(kMax64 / 2 + 1, kMax64 / 2 + 1).has_value());
    CHECK(checked_add(kMax64 / 2, kMax64 / 2 + 1) == kMax64);
    CHECK_FALSE(checked_add(kMax64, kMax64).has_value());
}

TEST_CASE("binary_header: checked_mul returns nullopt exactly on overflow", "[binary_header][reader]") {
    CHECK(checked_mul(0, 0) == 0);
    CHECK(checked_mul(0, kMax64) == 0);
    CHECK(checked_mul(kMax64, 0) == 0);
    CHECK(checked_mul(1, kMax64) == kMax64);
    CHECK(checked_mul(kMax64, 1) == kMax64);
    CHECK(checked_mul(3, 7) == 21);
    CHECK(checked_mul(1ull << 32, (1ull << 32) - 1) == (1ull << 32) * ((1ull << 32) - 1));
    CHECK_FALSE(checked_mul(1ull << 32, 1ull << 32).has_value());
    CHECK_FALSE(checked_mul(2, kMax64).has_value());
    CHECK_FALSE(checked_mul(kMax64, 2).has_value());
    CHECK_FALSE(checked_mul(kMax64, kMax64).has_value());
    CHECK(checked_mul(kMax64 / 2, 2) == kMax64 - 1);
    CHECK_FALSE(checked_mul(kMax64 / 2 + 1, 2).has_value());
}

TEST_CASE("binary_header: load reads 8/16/32/64-bit values in both byte orders",
          "[binary_header][reader]") {
    const std::string b("\x01\x02\x03\x04\x05\x06\x07\x08\xff", 9);
    CHECK(load<std::uint8_t>(b, 0, std::endian::little) == 0x01);
    CHECK(load<std::uint8_t>(b, 8, std::endian::big) == 0xff);
    CHECK(load<std::uint16_t>(b, 0, std::endian::little) == 0x0201);
    CHECK(load<std::uint16_t>(b, 0, std::endian::big) == 0x0102);
    CHECK(load<std::uint16_t>(b, 7, std::endian::little) == 0xff08);
    CHECK(load<std::uint32_t>(b, 0, std::endian::little) == 0x04030201u);
    CHECK(load<std::uint32_t>(b, 0, std::endian::big) == 0x01020304u);
    CHECK(load<std::uint32_t>(b, 4, std::endian::big) == 0x05060708u);
    CHECK(load<std::uint64_t>(b, 0, std::endian::little) == 0x0807060504030201ull);
    CHECK(load<std::uint64_t>(b, 0, std::endian::big) == 0x0102030405060708ull);
    CHECK(load<std::uint64_t>(b, 1, std::endian::big) == 0x02030405060708ffull);
    const std::string hi("\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    CHECK(load<std::uint64_t>(hi, 0, std::endian::little) == kMax64);
    CHECK(load<std::uint32_t>(hi, 4, std::endian::big) == 0xffffffffu);
}

TEST_CASE("binary_header: load is nullopt at every out-of-range offset", "[binary_header][reader]") {
    const std::string b("\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    for (std::size_t off = 0; off <= 10; ++off) {
        CAPTURE(off);
        CHECK(load<std::uint8_t>(b, off, std::endian::little).has_value() == (off <= 7));
        CHECK(load<std::uint16_t>(b, off, std::endian::big).has_value() == (off <= 6));
        CHECK(load<std::uint32_t>(b, off, std::endian::little).has_value() == (off <= 4));
        CHECK(load<std::uint64_t>(b, off, std::endian::big).has_value() == (off == 0));
    }
    constexpr std::size_t kMaxSize = std::numeric_limits<std::size_t>::max();
    for (const std::size_t off : {kMaxSize, kMaxSize - 1, kMaxSize - 7, kMaxSize - 8, kMaxSize / 2}) {
        CAPTURE(off);
        CHECK_FALSE(load<std::uint8_t>(b, off, std::endian::little).has_value());
        CHECK_FALSE(load<std::uint16_t>(b, off, std::endian::big).has_value());
        CHECK_FALSE(load<std::uint32_t>(b, off, std::endian::little).has_value());
        CHECK_FALSE(load<std::uint64_t>(b, off, std::endian::big).has_value());
    }
    CHECK_FALSE(load<std::uint8_t>(std::string_view{}, 0, std::endian::little).has_value());
    CHECK_FALSE(load<std::uint64_t>(std::string_view{}, 0, std::endian::little).has_value());
}
