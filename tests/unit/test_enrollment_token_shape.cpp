// test_enrollment_token_shape.cpp -- pure tests of
// common/include/yuzu/enrollment_token_shape.hpp.
//
// Registered in the AGENT test executable, not the server one: server
// shards are the bottleneck (CLAUDE.md test-efficiency discipline) and this
// header touches no server/agent state at all — same precedent as
// unit/test_tls_policy.cpp.

#include <yuzu/enrollment_token_shape.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace {
std::string make_hex(char c, std::size_t n = 64) {
    return std::string(n, c);
}
} // namespace

TEST_CASE("enrollment_token_shape_valid: 64 lowercase hex is accepted",
          "[enrollment][enrollment_token_shape]") {
    CHECK(yuzu::enrollment_token_shape_valid(make_hex('a')));
    CHECK(yuzu::enrollment_token_shape_valid(make_hex('0')));
    CHECK(yuzu::enrollment_token_shape_valid(make_hex('f')));
    CHECK(yuzu::enrollment_token_shape_valid(
        "0123456789abcdef" "0123456789abcdef" "0123456789abcdef" "0123456789abcdef")); // 4x16=64
}

TEST_CASE("enrollment_token_shape_valid: wrong length, charset or empty are rejected",
          "[enrollment][enrollment_token_shape]") {
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(make_hex('a', 63)));
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(make_hex('a', 65)));
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(make_hex('A'))); // uppercase hex
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(std::string(63, 'a') + "g")); // non-hex byte
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(""));
}

TEST_CASE("enrollment_token_from_file_text: a bare token on the only line is accepted",
          "[enrollment][enrollment_token_shape]") {
    const std::string tok = make_hex('a');
    auto got = yuzu::enrollment_token_from_file_text(tok);
    REQUIRE(got.has_value());
    CHECK(*got == tok);
}

TEST_CASE("enrollment_token_from_file_text: trailing newline / CRLF / whitespace / BOM / a "
          "second line",
          "[enrollment][enrollment_token_shape]") {
    const std::string tok = make_hex('b');
    CHECK(yuzu::enrollment_token_from_file_text(tok + "\n") == tok);
    CHECK(yuzu::enrollment_token_from_file_text(tok + "\r\n") == tok);
    CHECK(yuzu::enrollment_token_from_file_text("  " + tok + "  ") == tok);
    CHECK(yuzu::enrollment_token_from_file_text("\t" + tok + "\t\n") == tok);
    CHECK(yuzu::enrollment_token_from_file_text("\xEF\xBB\xBF" + tok) == tok);
    CHECK(yuzu::enrollment_token_from_file_text(tok + "\nsome other line") == tok);
}

TEST_CASE("enrollment_token_from_file_text: not a token returns nullopt",
          "[enrollment][enrollment_token_shape]") {
    CHECK_FALSE(yuzu::enrollment_token_from_file_text("").has_value());
    CHECK_FALSE(yuzu::enrollment_token_from_file_text("   \t  ").has_value());
    CHECK_FALSE(
        yuzu::enrollment_token_from_file_text(make_hex('a') + " " + make_hex('b')).has_value());
    CHECK_FALSE(
        yuzu::enrollment_token_from_file_text(make_hex('a') + std::string(1, '\0')).has_value());
    CHECK_FALSE(yuzu::enrollment_token_from_file_text(std::string(4096, 'z')).has_value());
    CHECK_FALSE(yuzu::enrollment_token_from_file_text("yuzu_enroll_notarealtoken").has_value());
}

TEST_CASE("enrollment_token_from_file_text: never returns a value that fails the shape check",
          "[enrollment][enrollment_token_shape]") {
    const std::vector<std::string> inputs = {
        "",
        "   ",
        make_hex('a'),
        make_hex('a') + "\n",
        make_hex('a') + "\r\n",
        "  " + make_hex('a') + "  ",
        "\xEF\xBB\xBF" + make_hex('a'),
        make_hex('a') + "\nextra",
        make_hex('a', 63),
        make_hex('A'),
        make_hex('a') + " " + make_hex('b'),
        std::string(4096, 'z'),
        "yuzu_enroll_notarealtoken",
    };
    for (const auto& in : inputs) {
        if (auto got = yuzu::enrollment_token_from_file_text(in)) {
            CHECK(yuzu::enrollment_token_shape_valid(*got));
        }
    }
}
