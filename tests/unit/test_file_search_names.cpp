/**
 * test_file_search_names.cpp -- unit tests for agents/shared/file_search_names.hpp: the reversible
 * name encoding, file identity and match row of the on-demand file search. Pure and portable: no
 * filesystem, process or clock, so it runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <file_search_names.hpp>
#include <wire_utf8.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <random>
#include <string>
#include <string_view>

namespace fs = yuzu::shared::file_search;

namespace {

bool round_trips(std::string_view raw) {
    const auto d = fs::decode_name(fs::encode_name(raw));
    return d && *d == raw;
}

bool encoding_is_clean(std::string_view enc) {
    for (const char ch : enc) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7F || c == '|' || c == '\\')
            return false;
    }
    return yuzu::shared::count_invalid_wire_bytes(enc) == 0;
}

} // namespace

TEST_CASE("encode_name/decode_name: every single byte round-trips and encodes cleanly", "[file_search]") {
    int bad = 0;
    for (int b = 0; b < 256; ++b) {
        const std::string raw(1, static_cast<char>(b));
        if (!round_trips(raw) || !encoding_is_clean(fs::encode_name(raw)))
            ++bad;
    }
    CHECK(bad == 0);
}

TEST_CASE("encode_name/decode_name: every pair over a hostile alphabet round-trips", "[file_search]") {
    const std::array<unsigned char, 24> alphabet = {0x00, 0x01, 0x1F, 0x20, '%',  '|',  '\\', 0x7F,
                                                    '/',  '.',  0x80, 0xBF, 0xC0, 0xC2, 0xDF, 0xE0,
                                                    0xE2, 0xED, 0xF0, 0xF4, 0xF5, 0xFF, 'A',  '4'};
    int bad = 0;
    for (const auto a : alphabet)
        for (const auto b : alphabet) {
            std::string raw;
            raw += static_cast<char>(a);
            raw += static_cast<char>(b);
            if (!round_trips(raw) || !encoding_is_clean(fs::encode_name(raw)))
                ++bad;
        }
    CHECK(bad == 0);
}

TEST_CASE("encode_name/decode_name: 20000 fixed-seed random strings round-trip", "[file_search]") {
    std::mt19937_64 rng(0x5EED'F11E'5EA2'C400ULL);
    // Odd strings lean on well-formed scalars of every length, so 3- and 4-byte ones reach encode_name.
    static constexpr std::string_view kScalars[] = {"a",        "%",          "|",
                                                     "\\",       "/",          "\xc3\xa9",
                                                     "\xe2\x82\xac", "\xf0\x9f\x98\x80", "\x7f",
                                                     "\xff"};
    int bad = 0;
    for (int i = 0; i < 20000; ++i) {
        std::string raw;
        for (const std::size_t len = rng() % 301; raw.size() < len;) {
            if ((i & 1) != 0)
                raw += kScalars[rng() % std::size(kScalars)];
            else
                raw += static_cast<char>(rng() & 0xFF);
        }
        if (!round_trips(raw) || !encoding_is_clean(fs::encode_name(raw)))
            ++bad;
    }
    CHECK(bad == 0);
}

TEST_CASE("encode_name: concrete spellings", "[file_search]") {
    CHECK(fs::encode_name("src/main.cpp") == "src/main.cpp");
    CHECK(fs::encode_name("caf\xc3\xa9") == "caf\xc3\xa9"); // well-formed scalar stays verbatim
    CHECK(fs::encode_name("a|b") == "a%7Cb");
    CHECK(fs::encode_name("100%") == "100%25");
    CHECK(fs::encode_name("a\\b") == "a%5Cb");
    CHECK(fs::encode_name("a\tb\x7f") == "a%09b%7F");
    CHECK(fs::encode_name(std::string_view("a\0b", 3)) == "a%00b");
    CHECK(fs::encode_name("bad\xff") == "bad%FF");
    CHECK(fs::encode_name("trunc\xe2\x82") == "trunc%E2%82"); // truncated scalar: each byte escaped
    CHECK(fs::encode_name("") == "");
}

TEST_CASE("decode_name: refuses every non-canonical or malformed encoding", "[file_search]") {
    CHECK_FALSE(fs::decode_name("a%7cb")); // lowercase hex
    CHECK_FALSE(fs::decode_name("100%"));  // lone '%'
    CHECK_FALSE(fs::decode_name("a%"));
    CHECK_FALSE(fs::decode_name("a%4"));   // truncated escape
    CHECK_FALSE(fs::decode_name("%4G"));   // non-hex
    CHECK_FALSE(fs::decode_name("%41"));   // 'A' must be spelled "A"
    CHECK_FALSE(fs::decode_name("%2F"));   // '/' must be spelled "/"
    CHECK_FALSE(fs::decode_name("a|b"));   // raw delimiter
    CHECK_FALSE(fs::decode_name("a\\b"));  // raw backslash
    CHECK_FALSE(fs::decode_name("a\tb"));  // raw control byte
    CHECK_FALSE(fs::decode_name(std::string_view("a\0b", 3))); // raw NUL
    CHECK_FALSE(fs::decode_name("bad\xff")); // raw invalid UTF-8
    CHECK_FALSE(fs::decode_name("%C3%A9"));  // a well-formed scalar must be spelled verbatim
    CHECK(fs::decode_name("%C3") == std::string("\xc3"));
    CHECK(fs::decode_name("a%7Cb") == std::string("a|b"));
    CHECK(fs::decode_name("") == std::string());
}

TEST_CASE("file identity: exact spellings, zero is '-'", "[file_search]") {
    CHECK(fs::format_file_identity({}) == "-");
    CHECK(fs::format_file_identity({1, 2}) == "0000000000000001:0000000000000002");
    CHECK(fs::format_file_identity({0xFEDCBA9876543210ULL, 0xABCDEF0123456789ULL}) ==
          "fedcba9876543210:abcdef0123456789");
    // A half-known identity is not the unknown one.
    CHECK(fs::format_file_identity({0, 1}) == "0000000000000000:0000000000000001");
    CHECK(fs::format_file_identity({1, 0}) == "0000000000000001:0000000000000000");
}

TEST_CASE("format_match_row: encodes the path component-wise and names the identity", "[file_search]") {
    CHECK(fs::format_match_row("a/b|c/d.txt", fs::EntryKind::file, {1, 2}) ==
          "match|a/b%7Cc/d.txt|file|0000000000000001:0000000000000002");
    CHECK(fs::format_match_row("dir", fs::EntryKind::directory, {}) == "match|dir|directory|-");
    // Whatever the path holds, the row has exactly three delimiters.
    const std::string row = fs::format_match_row(std::string_view("x|y\0z\xff", 6), fs::EntryKind::file, {});
    CHECK(std::count(row.begin(), row.end(), '|') == 3);
}
