/**
 * test_string_utils.cpp — Unit tests for shared string utility functions
 *
 * Covers: icontains, sanitize_utf8, escape_pipes, safe_output_field,
 *         sanitize_input, format_uptime, split_args, chargen_line
 */

#include <yuzu/string_utils.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::util;

// ── icontains ───────────────────────────────────────────────────────────────

TEST_CASE("icontains: empty needle matches anything", "[string_utils][icontains]") {
    CHECK(icontains("anything", ""));
    CHECK(icontains("", ""));
}

TEST_CASE("icontains: exact match", "[string_utils][icontains]") {
    CHECK(icontains("hello", "hello"));
}

TEST_CASE("icontains: case-insensitive match", "[string_utils][icontains]") {
    CHECK(icontains("Hello World", "hello"));
    CHECK(icontains("FOOBAR", "foobar"));
    CHECK(icontains("foobar", "FOOBAR"));
    CHECK(icontains("MiXeD", "mixed"));
}

TEST_CASE("icontains: substring match", "[string_utils][icontains]") {
    CHECK(icontains("OpenSSL 3.0.7", "openssl"));
    CHECK(icontains("Microsoft Visual C++", "visual"));
    CHECK(icontains("prefix-MATCH-suffix", "match"));
}

TEST_CASE("icontains: no match", "[string_utils][icontains]") {
    CHECK_FALSE(icontains("hello", "world"));
    CHECK_FALSE(icontains("short", "this is longer than the haystack"));
    CHECK_FALSE(icontains("abc", "abcd"));
}

TEST_CASE("icontains: empty haystack with non-empty needle", "[string_utils][icontains]") {
    CHECK_FALSE(icontains("", "something"));
}

// ── sanitize_utf8 ───────────────────────────────────────────────────────────

TEST_CASE("sanitize_utf8: pure ASCII passes through unchanged", "[string_utils][utf8]") {
    std::string ascii = "Hello, World! 123 @#$%";
    REQUIRE(sanitize_utf8(ascii) == ascii);
}

TEST_CASE("sanitize_utf8: empty string", "[string_utils][utf8]") {
    REQUIRE(sanitize_utf8("") == "");
}

TEST_CASE("sanitize_utf8: valid 2-byte UTF-8 (e.g. e with accent)", "[string_utils][utf8]") {
    // U+00E9 (e with acute) = 0xC3 0xA9
    std::string valid_2byte = "caf\xC3\xA9";
    REQUIRE(sanitize_utf8(valid_2byte) == valid_2byte);
}

TEST_CASE("sanitize_utf8: valid 3-byte UTF-8 (e.g. euro sign)", "[string_utils][utf8]") {
    // U+20AC (euro sign) = 0xE2 0x82 0xAC
    std::string valid_3byte = "price: \xE2\x82\xAC"
                              "10";
    REQUIRE(sanitize_utf8(valid_3byte) == valid_3byte);
}

TEST_CASE("sanitize_utf8: valid 4-byte UTF-8 (e.g. emoji)", "[string_utils][utf8]") {
    // U+1F600 (grinning face) = 0xF0 0x9F 0x98 0x80
    std::string valid_4byte = "hi \xF0\x9F\x98\x80";
    REQUIRE(sanitize_utf8(valid_4byte) == valid_4byte);
}

TEST_CASE("sanitize_utf8: invalid lone continuation byte replaced", "[string_utils][utf8]") {
    // 0x80 is a continuation byte, invalid as a start byte
    std::string invalid = "hello\x80world";
    REQUIRE(sanitize_utf8(invalid) == "hello?world");
}

TEST_CASE("sanitize_utf8: truncated 2-byte sequence replaced", "[string_utils][utf8]") {
    // 0xC3 alone (missing continuation byte at end of string)
    std::string truncated = "abc\xC3";
    REQUIRE(sanitize_utf8(truncated) == "abc?");
}

TEST_CASE("sanitize_utf8: truncated 3-byte sequence replaced", "[string_utils][utf8]") {
    // 0xE2 0x82 alone (missing third byte)
    std::string truncated = "x\xE2\x82";
    REQUIRE(sanitize_utf8(truncated) == "x??");
}

TEST_CASE("sanitize_utf8: Latin-1 byte replaced", "[string_utils][utf8]") {
    // 0xFC is not a valid UTF-8 start byte
    std::string latin1 = "test\xFC"
                         "data";
    REQUIRE(sanitize_utf8(latin1) == "test?data");
}

TEST_CASE("sanitize_utf8: multiple invalid bytes in a row", "[string_utils][utf8]") {
    std::string multi_invalid = "\x80\x81\x82";
    REQUIRE(sanitize_utf8(multi_invalid) == "???");
}

// ── escape_pipes ────────────────────────────────────────────────────────────

TEST_CASE("escape_pipes: no pipes unchanged", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("hello world") == "hello world");
}

TEST_CASE("escape_pipes: single pipe escaped", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("key|value") == "key\\|value");
}

TEST_CASE("escape_pipes: multiple pipes escaped", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("a|b|c|d") == "a\\|b\\|c\\|d");
}

TEST_CASE("escape_pipes: pipe at start and end", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("|test|") == "\\|test\\|");
}

TEST_CASE("escape_pipes: empty string", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("") == "");
}

TEST_CASE("escape_pipes: only pipes", "[string_utils][pipes]") {
    REQUIRE(escape_pipes("|||") == "\\|\\|\\|");
}

// ── safe_output_field ───────────────────────────────────────────────────────

namespace {
// Mirrors server/core/src/result_parsing.hpp's find_unescaped_pipe /
// unescape_pipes exactly (kept local to this test -- the server file lives
// in a different build target/suite) so the tests below assert against the
// real consumer-side parsing semantics: a '|' is a real separator iff
// preceded by a single backslash (base decoder, not parity-aware).
size_t test_find_unescaped_pipe(const std::string& s, size_t pos) {
    while (pos < s.size()) {
        auto p = s.find('|', pos);
        if (p == std::string::npos)
            return std::string::npos;
        if (p > 0 && s[p - 1] == '\\') {
            pos = p + 1;
            continue;
        }
        return p;
    }
    return std::string::npos;
}

std::string test_unescape_pipes(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '|')
            continue;
        out += s[i];
    }
    return out;
}

std::vector<std::string> test_split_fields(const std::string& line) {
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= line.size()) {
        auto p = test_find_unescaped_pipe(line, pos);
        if (p == std::string::npos) {
            parts.push_back(test_unescape_pipes(line.substr(pos)));
            break;
        }
        parts.push_back(test_unescape_pipes(line.substr(pos, p - pos)));
        pos = p + 1;
    }
    return parts;
}
} // namespace

TEST_CASE("safe_output_field: literal backslash folds to '/'", "[string_utils][safe_output_field]") {
    REQUIRE(safe_output_field("value ending in\\") == "value ending in/");
    REQUIRE(safe_output_field("a\\b\\c") == "a/b/c");
}

TEST_CASE("safe_output_field: CR/LF fold to spaces", "[string_utils][safe_output_field]") {
    REQUIRE(safe_output_field("line1\nline2") == "line1 line2");
    REQUIRE(safe_output_field("line1\r\nline2") == "line1  line2");
}

TEST_CASE("safe_output_field: pipe is escaped", "[string_utils][safe_output_field]") {
    REQUIRE(safe_output_field("a|b") == "a\\|b");
}

TEST_CASE("safe_output_field: plain value with no special bytes is unchanged",
          "[string_utils][safe_output_field]") {
    REQUIRE(safe_output_field("plain value") == "plain value");
}

TEST_CASE("safe_output_field: a value with a trailing backslash stays inside a "
          "single field under the base decoder",
          "[string_utils][safe_output_field]") {
    std::string field1 = safe_output_field("value ending in\\");
    std::string line = field1 + "|" + "next";

    auto parts = test_split_fields(line);
    REQUIRE(parts.size() == 2);
    CHECK(parts[0] == "value ending in/");
    CHECK(parts[1] == "next");
}

TEST_CASE("safe_output_field: a value with an embedded pipe stays inside a "
          "single field under the base decoder",
          "[string_utils][safe_output_field]") {
    std::string field1 = safe_output_field("contains | inside");
    std::string line = field1 + "|" + "next";

    auto parts = test_split_fields(line);
    REQUIRE(parts.size() == 2);
    CHECK(parts[0] == "contains | inside");
    CHECK(parts[1] == "next");
}

// ── sanitize_input ──────────────────────────────────────────────────────────

TEST_CASE("sanitize_input: alphanumeric passes through", "[string_utils][sanitize]") {
    REQUIRE(sanitize_input("Hello123") == "Hello123");
}

TEST_CASE("sanitize_input: allowed special chars pass through", "[string_utils][sanitize]") {
    REQUIRE(sanitize_input("my-log_file.txt") == "my-log_file.txt");
    REQUIRE(sanitize_input("path/to/thing") == "path/to/thing");
    REQUIRE(sanitize_input("with spaces") == "with spaces");
}

TEST_CASE("sanitize_input: dangerous chars stripped", "[string_utils][sanitize]") {
    REQUIRE(sanitize_input("$(rm -rf /)") == "rm -rf /");
    REQUIRE(sanitize_input("test;drop table") == "testdrop table");
    REQUIRE(sanitize_input("hello'world\"test") == "helloworldtest");
    REQUIRE(sanitize_input("pipe|char") == "pipechar");
    REQUIRE(sanitize_input("back\\slash") == "backslash");
}

TEST_CASE("sanitize_input: empty string", "[string_utils][sanitize]") {
    REQUIRE(sanitize_input("") == "");
}

TEST_CASE("sanitize_input: all dangerous chars stripped", "[string_utils][sanitize]") {
    REQUIRE(sanitize_input("!@#$%^&*()+=[]{}|\\:;'\"<>,?`~") == "");
}

// ── format_uptime ───────────────────────────────────────────────────────────

TEST_CASE("format_uptime: zero seconds", "[string_utils][uptime]") {
    REQUIRE(format_uptime(0) == "0d 0h 0m");
}

TEST_CASE("format_uptime: one minute", "[string_utils][uptime]") {
    REQUIRE(format_uptime(60) == "0d 0h 1m");
}

TEST_CASE("format_uptime: one hour", "[string_utils][uptime]") {
    REQUIRE(format_uptime(3600) == "0d 1h 0m");
}

TEST_CASE("format_uptime: one day", "[string_utils][uptime]") {
    REQUIRE(format_uptime(86400) == "1d 0h 0m");
}

TEST_CASE("format_uptime: mixed duration", "[string_utils][uptime]") {
    // 2 days, 5 hours, 30 minutes = 2*86400 + 5*3600 + 30*60 = 172800 + 18000 + 1800 = 192600
    REQUIRE(format_uptime(192600) == "2d 5h 30m");
}

TEST_CASE("format_uptime: large uptime (365 days)", "[string_utils][uptime]") {
    long long year = 365LL * 86400;
    REQUIRE(format_uptime(year) == "365d 0h 0m");
}

TEST_CASE("format_uptime: 59 seconds rounds to 0m", "[string_utils][uptime]") {
    REQUIRE(format_uptime(59) == "0d 0h 0m");
}

TEST_CASE("format_uptime: exactly 1d 23h 59m", "[string_utils][uptime]") {
    long long secs = 1 * 86400 + 23 * 3600 + 59 * 60;
    REQUIRE(format_uptime(secs) == "1d 23h 59m");
}

// ── split_args ──────────────────────────────────────────────────────────────

TEST_CASE("split_args: empty string", "[string_utils][args]") {
    auto result = split_args("");
    REQUIRE(result.empty());
}

TEST_CASE("split_args: single arg", "[string_utils][args]") {
    auto result = split_args("hello");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "hello");
}

TEST_CASE("split_args: multiple args with spaces", "[string_utils][args]") {
    auto result = split_args("one two three");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "one");
    CHECK(result[1] == "two");
    CHECK(result[2] == "three");
}

TEST_CASE("split_args: multiple spaces between args", "[string_utils][args]") {
    auto result = split_args("one   two    three");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "one");
    CHECK(result[1] == "two");
    CHECK(result[2] == "three");
}

TEST_CASE("split_args: tabs as separators", "[string_utils][args]") {
    auto result = split_args("one\ttwo\tthree");
    REQUIRE(result.size() == 3);
}

TEST_CASE("split_args: double-quoted string kept as one arg", "[string_utils][args]") {
    auto result = split_args(R"(hello "world foo" bar)");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "hello");
    CHECK(result[1] == "world foo");
    CHECK(result[2] == "bar");
}

TEST_CASE("split_args: single-quoted string kept as one arg", "[string_utils][args]") {
    auto result = split_args("hello 'world foo' bar");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "hello");
    CHECK(result[1] == "world foo");
    CHECK(result[2] == "bar");
}

TEST_CASE("split_args: mixed quotes", "[string_utils][args]") {
    auto result = split_args(R"("hello world" 'foo bar')");
    REQUIRE(result.size() == 2);
    CHECK(result[0] == "hello world");
    CHECK(result[1] == "foo bar");
}

TEST_CASE("split_args: leading and trailing whitespace", "[string_utils][args]") {
    auto result = split_args("  hello  ");
    REQUIRE(result.size() == 1);
    CHECK(result[0] == "hello");
}

TEST_CASE("split_args: only whitespace", "[string_utils][args]") {
    auto result = split_args("   ");
    REQUIRE(result.empty());
}

TEST_CASE("split_args: quotes preserve empty-like content", "[string_utils][args]") {
    auto result = split_args(R"(arg1 "has spaces" arg3)");
    REQUIRE(result.size() == 3);
    CHECK(result[1] == "has spaces");
}

// ── chargen_line ────────────────────────────────────────────────────────────

TEST_CASE("chargen_line: produces 72-character line", "[string_utils][chargen]") {
    auto line = chargen_line(0);
    REQUIRE(line.size() == 72);
}

TEST_CASE("chargen_line: offset 0 starts with space (ASCII 32)", "[string_utils][chargen]") {
    auto line = chargen_line(0);
    REQUIRE(line[0] == ' ');
}

TEST_CASE("chargen_line: all chars are printable ASCII", "[string_utils][chargen]") {
    for (int offset = 0; offset < 95; ++offset) {
        auto line = chargen_line(offset);
        for (char c : line) {
            CHECK(c >= 32);
            CHECK(c <= 126);
        }
    }
}

TEST_CASE("chargen_line: offset 1 starts one position later", "[string_utils][chargen]") {
    auto line0 = chargen_line(0);
    auto line1 = chargen_line(1);
    REQUIRE(line0[0] == ' '); // ASCII 32
    REQUIRE(line1[0] == '!'); // ASCII 33
}

TEST_CASE("chargen_line: wraps around the character set", "[string_utils][chargen]") {
    // At offset 94 (last char in range), the line should start with '~' (ASCII 126)
    auto line = chargen_line(94);
    REQUIRE(line[0] == '~');
    // Next char should wrap to ' ' (ASCII 32)
    REQUIRE(line[1] == ' ');
}

TEST_CASE("chargen_line: offset 95 wraps back to offset 0", "[string_utils][chargen]") {
    auto line0 = chargen_line(0);
    auto line95 = chargen_line(95);
    REQUIRE(line0 == line95);
}

TEST_CASE("chargen_line: successive lines differ by one character shift",
          "[string_utils][chargen]") {
    auto line0 = chargen_line(0);
    auto line1 = chargen_line(1);
    // line1 should be line0 shifted left by 1, with a new char appended
    for (int i = 0; i < 71; ++i) {
        CHECK(line0[i + 1] == line1[i]);
    }
}
