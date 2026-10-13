/**
 * test_list_keyset.cpp -- pure keyset cursor and bounded-int primitives (list_keyset.hpp), the
 * position token behind the workflow-execution list. No database, no transport.
 */

#include "list_keyset.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

using yuzu::server::keyset::decode_cursor;
using yuzu::server::keyset::encode_cursor;
using yuzu::server::keyset::kCursorMaxBytes;
using yuzu::server::keyset::kIdMaxBytes;
using yuzu::server::keyset::parse_int;
using yuzu::server::keyset::Position;

namespace {
constexpr const char* kPrefix = "w1:";
constexpr std::int64_t kI64Max = std::numeric_limits<std::int64_t>::max();
} // namespace

TEST_CASE("keyset cursor: encode then decode round trips every position shape",
          "[keyset][workflow][executions]") {
    const std::vector<Position> positions{
        {0, "a"},
        {1735689600, "0123456789abcdef0123456789abcdef"},
        {kI64Max, "x"},
        {42, std::string(kIdMaxBytes, 'z')},
        // ids are opaque bytes: separators, base64 look-alikes and high bytes must survive
        {7, "a:b:c"},
        {7, "w1:9:abc"},
        {7, std::string("\xff\xfe\x01", 3)},
    };
    for (const auto& p : positions) {
        const auto token = encode_cursor(kPrefix, p);
        INFO(token);
        const auto back = decode_cursor(kPrefix, token);
        REQUIRE(back.has_value());
        CHECK(*back == p);
        CHECK(token.size() <= kCursorMaxBytes);
    }
}

TEST_CASE("keyset cursor: the wire form is pinned", "[keyset][workflow][executions]") {
    // `w1:<key>:<base64url(id)>` -- a drift in this literal breaks every cursor in flight.
    CHECK(encode_cursor(kPrefix, {1735689600, "abc"}) == "w1:1735689600:YWJj");
    CHECK(encode_cursor(kPrefix, {0, "a"}) == "w1:0:YQ");
    CHECK(encode_cursor(kPrefix, {5, std::string("\xfb\xff", 2)}) == "w1:5:-_8");
}

TEST_CASE("keyset cursor: wrong or missing prefix is refused", "[keyset][workflow][executions]") {
    const auto good = encode_cursor(kPrefix, {10, "abc"});
    CHECK(decode_cursor(kPrefix, good).has_value());
    CHECK_FALSE(decode_cursor("w2:", good).has_value());
    CHECK_FALSE(decode_cursor(kPrefix, "10:YWJj").has_value());
    CHECK_FALSE(decode_cursor(kPrefix, "c1:10:YWJj").has_value());
    CHECK_FALSE(decode_cursor(kPrefix, "W1:10:YWJj").has_value());
    CHECK_FALSE(decode_cursor(kPrefix, "").has_value());
    CHECK_FALSE(decode_cursor(kPrefix, "w1:").has_value());
}

TEST_CASE("keyset cursor: malformed bodies are refused", "[keyset][workflow][executions]") {
    const std::vector<std::string> bad{
        "w1:10",             // no id part
        "w1:10:",            // empty id
        "w1::YWJj",          // empty key
        "w1:abc:YWJj",       // non-numeric key
        "w1:-1:YWJj",        // negative key
        "w1:+1:YWJj",        // explicit plus
        "w1: 1:YWJj",        // whitespace in key
        "w1:1 :YWJj",        // trailing whitespace in key
        "w1:01:YWJj",        // non-canonical leading zero
        "w1:00:YWJj",        // non-canonical zero
        "w1:1.5:YWJj",       // fraction
        "w1:1e3:YWJj",       // exponent
        "w1:9223372036854775808:YWJj", // int64 max + 1
        "w1:99999999999999999999:YWJj",
        "w1:10:YWJj=",       // padding
        "w1:10:YW Jj",       // whitespace in id
        "w1:10:YWJj\n",      // trailing newline
        "w1:10:Y+Jj",        // standard-alphabet '+'
        "w1:10:Y/Jj",        // standard-alphabet '/'
        "w1:10:Y",           // impossible length (1 mod 4)
        "w1:10:YR",          // non-canonical trailing bits (decodes to "a" but spelled wrong)
        "w1:10:YWJj:extra",  // trailing field
        std::string("w1:10:YWJj\0x", 12),
    };
    for (const auto& b : bad) {
        INFO(b);
        CHECK_FALSE(decode_cursor(kPrefix, b).has_value());
    }
}

TEST_CASE("keyset cursor: id bounds", "[keyset][workflow][executions]") {
    // An id at the bound decodes; one byte over is refused even though it re-encodes canonically.
    CHECK(decode_cursor(kPrefix, encode_cursor(kPrefix, {1, std::string(kIdMaxBytes, 'a')}))
              .has_value());
    CHECK_FALSE(decode_cursor(kPrefix, encode_cursor(kPrefix, {1, std::string(kIdMaxBytes + 1, 'a')}))
                    .has_value());
    // A NUL byte can never be bound as a text parameter, so a token naming one is refused.
    CHECK_FALSE(decode_cursor(kPrefix, encode_cursor(kPrefix, {1, std::string("a\0b", 3)}))
                    .has_value());
}

TEST_CASE("keyset cursor: total length is capped before anything is decoded",
          "[keyset][workflow][executions]") {
    // 2048 bytes is the cap: build a token of exactly that size, then one over.
    const std::string head = "w1:1:";
    std::string at_cap = head + std::string(kCursorMaxBytes - head.size(), 'A');
    CHECK(at_cap.size() == kCursorMaxBytes);
    // (over the id bound so it is refused for that reason -- the point is it is not a crash)
    CHECK_FALSE(decode_cursor(kPrefix, at_cap).has_value());
    CHECK_FALSE(decode_cursor(kPrefix, at_cap + "A").has_value());
    CHECK_FALSE(decode_cursor(kPrefix, std::string(1 << 20, 'A')).has_value());
}

TEST_CASE("keyset parse_int: accepts only whole-string decimals inside the bounds",
          "[keyset][workflow][executions]") {
    CHECK(parse_int("0", 0, 10) == 0);
    CHECK(parse_int("10", 0, 10) == 10);
    CHECK(parse_int("007", 0, 10) == 7); // leniency is the cursor's job to refuse, not this parse
    CHECK(parse_int("-5", -10, 10) == -5);
    CHECK(parse_int("9223372036854775807", 0, kI64Max) == kI64Max);

    CHECK_FALSE(parse_int("", 0, 10).has_value());
    CHECK_FALSE(parse_int("11", 0, 10).has_value());
    CHECK_FALSE(parse_int("-1", 0, 10).has_value());
    CHECK_FALSE(parse_int("+1", 0, 10).has_value());
    CHECK_FALSE(parse_int(" 1", 0, 10).has_value());
    CHECK_FALSE(parse_int("1 ", 0, 10).has_value());
    CHECK_FALSE(parse_int("1x", 0, 10).has_value());
    CHECK_FALSE(parse_int("1.0", 0, 10).has_value());
    CHECK_FALSE(parse_int("0x1", 0, 10).has_value());
    CHECK_FALSE(parse_int("abc", 0, 10).has_value());
    CHECK_FALSE(parse_int("9223372036854775808", 0, kI64Max).has_value());
    CHECK_FALSE(parse_int("-9223372036854775809", std::numeric_limits<std::int64_t>::min(), kI64Max)
                    .has_value());
}
