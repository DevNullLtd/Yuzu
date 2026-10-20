// test_enrollment_token_file.cpp -- tests of the agent's --enrollment-token-file
// support: the pure shape predicate and token-file text parser
// (common/include/yuzu/enrollment_token_shape.hpp), the no-follow reader
// (agents/core/include/yuzu/agent/enrollment_token_file.hpp) and the
// token-source precedence rule.
//
// Registered in the AGENT test executable, not the server one: server
// shards are the bottleneck (CLAUDE.md test-efficiency discipline) and the
// reader touches no server state -- same precedent as unit/test_tls_policy.cpp.
//
// The reader cases use a few tiny files under a yuzu_test_ TempDir: the
// never-follow-a-link, the bounded-read and the "no token unless ok" behaviour
// are kernel/filesystem boundary logic a pure string parser cannot observe.
// No sleeps, no process spawn, no network.

#include <yuzu/agent/enrollment_token_file.hpp>
#include <yuzu/enrollment_token_shape.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

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
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(std::string(63, 'a') + " ")); // trailing space
    std::string with_nul = make_hex('a');
    with_nul[10] = '\0';
    CHECK_FALSE(yuzu::enrollment_token_shape_valid(with_nul)); // embedded NUL
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

// ── read_enrollment_token_file: the opened-object reader ────────────────────

namespace {

using yuzu::agent::EnrollmentTokenFileRead;
using yuzu::agent::read_enrollment_token_file;
using yuzu::agent::TokenFileOutcome;

struct TokenDir {
    yuzu::test::TempDir dir{"yuzu_test_enroll_token_"};
    TokenDir() { std::filesystem::create_directories(dir.path); }
    std::filesystem::path at(const std::string& name) const { return dir.path / name; }
    std::filesystem::path write(const std::string& name, const std::string& text) const {
        const auto p = at(name);
        std::ofstream(p, std::ios::binary) << text;
        return p;
    }
};

// The reader's contract: a token is present if and only if the outcome is ok,
// and then it passed the shape predicate. main() clears the cleanup path on
// every other outcome, so this invariant is what keeps the agent from ever
// deleting a file it did not consume a token from.
void check_token_iff_ok(const EnrollmentTokenFileRead& r) {
    CHECK(r.token.has_value() == (r.outcome == TokenFileOutcome::ok));
    if (r.token)
        CHECK(yuzu::enrollment_token_shape_valid(*r.token));
}

} // namespace

TEST_CASE("read_enrollment_token_file: a regular file holding a token is read",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    const std::string tok = make_hex('c');
    const auto r = read_enrollment_token_file(t.write("token", tok + "\r\n"));
    CHECK(r.outcome == TokenFileOutcome::ok);
    REQUIRE(r.token.has_value());
    CHECK(*r.token == tok);
    CHECK(r.detail.empty());
    check_token_iff_ok(r);
}

TEST_CASE("read_enrollment_token_file: no file at the path is absent, not an error",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    const auto r = read_enrollment_token_file(t.at("missing"));
    CHECK(r.outcome == TokenFileOutcome::absent);
    check_token_iff_ok(r);
    // A missing parent directory is also just "no file there".
    const auto deeper = read_enrollment_token_file(t.at("no-such-dir") / "token");
    CHECK(deeper.outcome == TokenFileOutcome::absent);
    check_token_iff_ok(deeper);
}

TEST_CASE("read_enrollment_token_file: a directory is never read",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    std::filesystem::create_directories(t.at("a-directory"));
    const auto r = read_enrollment_token_file(t.at("a-directory"));
    CHECK(r.outcome != TokenFileOutcome::ok);
    check_token_iff_ok(r);
#if !defined(_WIN32)
    CHECK(r.outcome == TokenFileOutcome::not_regular);
#endif
}

TEST_CASE("read_enrollment_token_file: a file past the cap is rejected, not truncated and parsed",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    // A valid token on the first line, then padding that takes the file one byte
    // over the 4 KiB cap: a truncating reader would accept the first line.
    std::string big = make_hex('d') + "\n";
    big.resize(yuzu::agent::kEnrollmentTokenFileCap + 1, 'x');
    const auto r = read_enrollment_token_file(t.write("big", big));
    CHECK(r.outcome == TokenFileOutcome::too_large);
    check_token_iff_ok(r);

    // Exactly at the cap is accepted.
    std::string at_cap = make_hex('d') + "\n";
    at_cap.resize(yuzu::agent::kEnrollmentTokenFileCap, ' ');
    const auto ok = read_enrollment_token_file(t.write("at_cap", at_cap));
    CHECK(ok.outcome == TokenFileOutcome::ok);
    check_token_iff_ok(ok);

    // The cap is a parameter: a token plus its newline is one byte over a 64-byte cap.
    const auto tight = read_enrollment_token_file(t.write("tight", make_hex('e') + "\n"), 64);
    CHECK(tight.outcome == TokenFileOutcome::too_large);
    check_token_iff_ok(tight);
}

TEST_CASE("read_enrollment_token_file: a regular file that is not a token is no_token",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    for (const std::string& text : {std::string{}, std::string{"not a token\n"},
                                    make_hex('A'), make_hex('a', 63),
                                    std::string{"yuzu_enroll_notarealtoken"}}) {
        CAPTURE(text);
        const auto r = read_enrollment_token_file(t.write("junk", text));
        CHECK(r.outcome == TokenFileOutcome::no_token);
        check_token_iff_ok(r);
    }
}

#if !defined(_WIN32)

TEST_CASE("read_enrollment_token_file: a symlink leaf is refused and never followed",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    const std::string tok = make_hex('b');
    const auto target = t.write("target", tok + "\n");
    std::filesystem::create_symlink(target, t.at("link"));

    const auto r = read_enrollment_token_file(t.at("link"));
    CHECK(r.outcome == TokenFileOutcome::not_regular);
    check_token_iff_ok(r);

    // A dangling link is a link too, not "absent": main() warns about it.
    std::filesystem::create_symlink(t.at("gone"), t.at("dangling"));
    const auto d = read_enrollment_token_file(t.at("dangling"));
    CHECK(d.outcome == TokenFileOutcome::not_regular);
    check_token_iff_ok(d);
}

TEST_CASE("read_enrollment_token_file: a path the open refuses is unreadable with a reason",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    t.write("token", make_hex('a'));
    // A trailing separator would make the kernel follow a link leaf, so the
    // no-follow primitive refuses it (EINVAL) before opening anything.
    const auto r = read_enrollment_token_file(t.at("token").string() + "/");
    CHECK(r.outcome == TokenFileOutcome::unreadable);
    CHECK_FALSE(r.detail.empty());
    check_token_iff_ok(r);
}

#endif

// ── resolve_enrollment_token_source: file wins, else the option/env value ───

TEST_CASE("resolve_enrollment_token_source: a token from the file wins over the option",
          "[enrollment][enrollment_token_file]") {
    const auto [token, source] =
        yuzu::agent::resolve_enrollment_token_source("from-option", std::string{"from-file"});
    CHECK(token == "from-file");
    CHECK(source == "file");
}

TEST_CASE("resolve_enrollment_token_source: without a file token the option or env value stands",
          "[enrollment][enrollment_token_file]") {
    // The upgrade case: the service binPath always carries --enrollment-token-file,
    // and a machine environment may still carry YUZU_ENROLLMENT_TOKEN; with the
    // file absent or unusable the agent must keep starting with the env token.
    const auto [token, source] =
        yuzu::agent::resolve_enrollment_token_source("from-env", std::nullopt);
    CHECK(token == "from-env");
    CHECK(source == "option");
}

TEST_CASE("resolve_enrollment_token_source: no source at all is none",
          "[enrollment][enrollment_token_file]") {
    const auto [token, source] = yuzu::agent::resolve_enrollment_token_source("", std::nullopt);
    CHECK(token.empty());
    CHECK(source == "none");

    // A token read from the file still wins over an empty option.
    const auto [file_token, file_source] =
        yuzu::agent::resolve_enrollment_token_source("", std::string{"from-file"});
    CHECK(file_token == "from-file");
    CHECK(file_source == "file");
}
