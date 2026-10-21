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
// never-follow-a-link, the bounded-read, the owner/mode policy and the "no token
// unless ok" behaviour are kernel/filesystem boundary logic a pure string parser
// cannot observe. The owner/mode policy itself is a pure function with its own
// matrix (a foreign owner cannot be created without privilege). The deadline case
// injects a reader that cannot return until the test lets it, so the deadline
// always fires first. No sleeps, no process spawn, no network.

#include <yuzu/agent/enrollment_token_file.hpp>
#include <yuzu/enrollment_token_shape.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <optional>
#include <string>
#include <string_view>
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

TEST_CASE("enrollment_token_shape_valid: wrong length or charset or empty are rejected",
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

// A Windows runner whose TEMP is not on a fixed drive (a RAM disk, a mapped share)
// cannot exercise the reader at all -- it refuses any non-fixed-drive path without
// opening it -- so the file cases skip rather than fail there.
void skip_unless_fixed_drive([[maybe_unused]] const std::filesystem::path& p) {
#ifdef _WIN32
    const auto abs = std::filesystem::absolute(p);
    const auto drive = yuzu::agent::detail::token_file_drive_letter(abs.native());
    const wchar_t root[] = {drive.value_or(L'?'), L':', L'\\', L'\0'};
    if (!drive || GetDriveTypeW(root) != DRIVE_FIXED)
        SKIP("the temp directory is not on a fixed drive; the reader refuses such a path");
#endif
}

struct TokenDir {
    yuzu::test::TempDir dir{"yuzu_test_enroll_token_"};
    TokenDir() {
        std::filesystem::create_directories(dir.path);
        skip_unless_fixed_drive(dir.path);
    }
    std::filesystem::path at(const std::string& name) const { return dir.path / name; }
    // The file is the current user's and, on POSIX, 0600 whatever the umask: the
    // reader refuses a group/other-writable file, and a CI shell with umask 002
    // would otherwise create these 0664.
    std::filesystem::path write(const std::string& name, const std::string& text) const {
        const auto p = at(name);
        std::ofstream(p, std::ios::binary) << text;
#if !defined(_WIN32)
        std::filesystem::permissions(p,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
#endif
        return p;
    }
};

// The reader's contract: a token is present if and only if the outcome is ok,
// and then it passed the shape predicate. resolve_enrollment_token clears the
// cleanup path on every other outcome, so this invariant is what keeps the
// agent from ever deleting a file it did not consume a token from.
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

TEST_CASE("read_enrollment_token_file: no file at the path is absent and not an error",
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
    CHECK(r.outcome == TokenFileOutcome::not_regular);
    check_token_iff_ok(r);
}

TEST_CASE("read_enrollment_token_file: a file past the cap is rejected rather than "
          "truncated and parsed",
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

TEST_CASE("read_enrollment_token_file: a path the open refuses is unreadable with a reason",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    t.write("token", make_hex('a'));
    // A path with a trailing separator naming a regular file is refused by the open on
    // every host (POSIX: the no-follow primitive answers EINVAL before opening anything,
    // since the kernel would follow a link leaf named that way; Windows: the name is
    // invalid for a file), and it is neither "absent" nor a read.
    const auto r = read_enrollment_token_file(t.at("token").string() + "/");
    CHECK(r.outcome == TokenFileOutcome::unreadable);
    CHECK_FALSE(r.detail.empty());
    check_token_iff_ok(r);
}

// ── the owner / mode policy ─────────────────────────────────────────────────
//
// A foreign-owned file cannot be created without privilege, so the policy is a
// pure function over the opened file's facts and carries the whole refuse matrix.

TEST_CASE("token_file_posix_trusted: owned by root or this user, not group/other-writable",
          "[enrollment][enrollment_token_file]") {
    using yuzu::agent::detail::token_file_posix_trusted;
    constexpr std::uint32_t me = 1000;
    constexpr std::uint32_t someone_else = 2000;
    constexpr std::uint32_t unset = static_cast<std::uint32_t>(-1);

    // Trusted: this user's own 0600 / 0640 / 0644, and root's.
    CHECK(token_file_posix_trusted(me, 0600, me));
    CHECK(token_file_posix_trusted(me, 0640, me));
    CHECK(token_file_posix_trusted(me, 0644, me));
    CHECK(token_file_posix_trusted(0, 0644, me));
    CHECK(token_file_posix_trusted(0, 0600, 0));

    // Refused: group- or other-writable, whoever owns it.
    CHECK_FALSE(token_file_posix_trusted(me, 0660, me));
    CHECK_FALSE(token_file_posix_trusted(me, 0666, me));
    CHECK_FALSE(token_file_posix_trusted(me, 0620, me));
    CHECK_FALSE(token_file_posix_trusted(me, 0602, me));
    CHECK_FALSE(token_file_posix_trusted(0, 0666, me));

    // Refused: owned by another account, however tight the mode.
    CHECK_FALSE(token_file_posix_trusted(someone_else, 0600, me));
    CHECK_FALSE(token_file_posix_trusted(someone_else, 0400, 0));

    // Refused: an owner that was never read (FileRead's default) is nobody's.
    CHECK_FALSE(token_file_posix_trusted(unset, 0600, me));
}

TEST_CASE("read_enrollment_token_file: the current user's own file is trusted",
          "[enrollment][enrollment_token_file]") {
    // On Windows the owner is this account or Administrators (an elevated token owns
    // what it creates), both accepted; on POSIX t.write() makes it this user's 0600.
    TokenDir t;
    const std::string tok = make_hex('6');
    const auto r = read_enrollment_token_file(t.write("token", tok));
    CHECK(r.outcome == TokenFileOutcome::ok);
    REQUIRE(r.token.has_value());
    CHECK(*r.token == tok);
}

#if !defined(_WIN32)

TEST_CASE("read_enrollment_token_file: a group- or other-writable file is untrusted_owner",
          "[enrollment][enrollment_token_file]") {
    namespace fs = std::filesystem;
    TokenDir t;
    const std::string tok = make_hex('7');
    struct Mode {
        const char* what;
        fs::perms perms;
        TokenFileOutcome expected;
    };
    const fs::perms rw = fs::perms::owner_read | fs::perms::owner_write;
    for (const auto& m : {
             Mode{"0600", rw, TokenFileOutcome::ok},
             Mode{"0640", rw | fs::perms::group_read, TokenFileOutcome::ok},
             Mode{"0644", rw | fs::perms::group_read | fs::perms::others_read,
                  TokenFileOutcome::ok},
             Mode{"0660", rw | fs::perms::group_read | fs::perms::group_write,
                  TokenFileOutcome::untrusted_owner},
             Mode{"0666",
                  rw | fs::perms::group_read | fs::perms::group_write | fs::perms::others_read |
                      fs::perms::others_write,
                  TokenFileOutcome::untrusted_owner},
         }) {
        CAPTURE(m.what);
        const auto p = t.write("token", tok + "\n");
        fs::permissions(p, m.perms, fs::perm_options::replace);
        const auto r = read_enrollment_token_file(p);
        CHECK(r.outcome == m.expected);
        check_token_iff_ok(r);
        if (m.expected == TokenFileOutcome::untrusted_owner)
            CHECK_FALSE(r.detail.empty());
    }
}

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

#endif

// ── token_file_drive_letter: the Windows leg's pure path gate ───────────────

TEST_CASE("token_file_drive_letter: only a drive-letter root passes",
          "[enrollment][enrollment_token_file]") {
    // Pure string logic that the Windows reader applies before it opens anything,
    // so it is checked here on every host.
    const auto letter = [](std::wstring_view path) {
        const auto drive = yuzu::agent::detail::token_file_drive_letter(path);
        return drive ? static_cast<char>(*drive) : '\0';
    };
    CHECK(letter(LR"(C:\ProgramData\Yuzu\enrollment-token)") == 'C');
    CHECK(letter(L"d:/x") == 'd');

    CHECK(letter(LR"(\\?\C:\x)") == '\0');                  // extended-length prefix: refused
    CHECK(letter(LR"(\\host\share\token)") == '\0');        // UNC share
    CHECK(letter(LR"(\\?\UNC\host\share\token)") == '\0');  // extended-length UNC
    CHECK(letter(LR"(\\.\pipe\token)") == '\0');            // device / pipe
    CHECK(letter(L"//host/share/token") == '\0');           // UNC, forward slashes
    CHECK(letter(L"token") == '\0');                        // relative
    CHECK(letter(L"C:token") == '\0');                      // drive-relative
    CHECK(letter(L"1:\\x") == '\0');                        // not a letter
    CHECK(letter(L"") == '\0');
}

// ── is_enrollment_token_refusal: which Register replies delete the token file ─
//
// Fed the server's own strings: the uniform message is the shared constant the server
// sends, and "enrollment denied by administrator" / "awaiting admin approval" are the
// replies that must NOT match (agent_service_impl.cpp, gateway_service_impl.cpp).

TEST_CASE("is_enrollment_token_refusal: only the uniform refusal with status denied matches",
          "[enrollment][enrollment_token_file]") {
    using yuzu::agent::is_enrollment_token_refusal;
    const std::string uniform{yuzu::kEnrollmentTokenRejectionPublicMessage};

    CHECK(is_enrollment_token_refusal("denied", uniform));

    // An administrator's denial: the token may have been valid and its use rolled back.
    CHECK_FALSE(is_enrollment_token_refusal("denied", "enrollment denied by administrator"));
    // Pending approval is not a refusal.
    CHECK_FALSE(is_enrollment_token_refusal("pending", "awaiting admin approval"));
    CHECK_FALSE(is_enrollment_token_refusal("pending", "still awaiting admin approval"));
    // Exact equality on both fields.
    CHECK_FALSE(is_enrollment_token_refusal("", uniform));
    CHECK_FALSE(is_enrollment_token_refusal("pending", uniform));
    CHECK_FALSE(is_enrollment_token_refusal("denied", uniform + " "));
    CHECK_FALSE(
        is_enrollment_token_refusal("denied", "Invalid, expired, or exhausted enrollment token"));
    CHECK_FALSE(is_enrollment_token_refusal("denied", "x " + uniform));
    CHECK_FALSE(is_enrollment_token_refusal("denied", ""));
}

// ── resolve_enrollment_token: the whole decision main() makes ───────────────
//
// main() is never linked into a test target, so this function IS the tested
// behaviour of the startup wiring: which token wins, and whether the path stays
// a deletion target. A path survives only when a token was consumed from it.

namespace {

using yuzu::agent::resolve_enrollment_token;

// The outcome of a resolve that read a file, or fails the test when none was read.
TokenFileOutcome file_outcome_of(const yuzu::agent::EnrollmentTokenResolution& r) {
    REQUIRE(r.file_outcome.has_value());
    return *r.file_outcome;
}

} // namespace

TEST_CASE("resolve_enrollment_token: a token read from the file wins and the path is kept",
          "[enrollment][enrollment_token_file]") {
    // Whether the option carried a token or was empty, the file's token is the one used.
    for (const char* initial : {"from-option", ""}) {
        CAPTURE(initial);
        TokenDir t;
        const std::string file_token = make_hex('1');
        std::string token = initial;
        auto path = t.write("token", file_token + "\n");
        const auto r = resolve_enrollment_token(token, path);
        CHECK(file_outcome_of(r) == TokenFileOutcome::ok);
        CHECK(token == file_token);
        CHECK(r.source == "file");
        // Kept: the agent removes this file after the first accepted registration.
        CHECK(path == t.at("token"));
    }
}

TEST_CASE("resolve_enrollment_token: any outcome but ok clears the path and the option stands",
          "[enrollment][enrollment_token_file]") {
    // Deleting this clear re-opens the agent deleting a file it never took a token
    // from; main() is not linked into a test, so this is the pin on that behaviour.
    TokenDir t;
    std::filesystem::create_directories(t.at("a-directory"));
    std::string oversize = make_hex('3') + "\n";
    oversize.resize(yuzu::agent::kEnrollmentTokenFileCap + 1, 'x');

    struct Case {
        const char* what;
        std::filesystem::path path;
        TokenFileOutcome expected;
    };
    std::vector<Case> cases = {
        {"absent", t.at("missing"), TokenFileOutcome::absent},
        {"junk", t.write("junk", "not a token\n"), TokenFileOutcome::no_token},
        {"empty file", t.write("empty", ""), TokenFileOutcome::no_token},
        {"oversize", t.write("big", oversize), TokenFileOutcome::too_large},
        {"directory", t.at("a-directory"), TokenFileOutcome::not_regular},
        // A trailing separator on a regular file is refused by the open itself.
        {"unreadable", t.at("junk").string() + "/", TokenFileOutcome::unreadable},
    };
#if !defined(_WIN32)
    // A link to a file that DOES hold a valid token is still refused, and neither the
    // link nor its target is left as a deletion target.
    const auto target = t.write("target", make_hex('4') + "\n");
    std::filesystem::create_symlink(target, t.at("link"));
    cases.push_back({"symlink leaf", t.at("link"), TokenFileOutcome::not_regular});
    // A well-formed token in a file another account could have written is not used.
    const auto writable = t.write("writable", make_hex('5') + "\n");
    std::filesystem::permissions(writable,
                                 std::filesystem::perms::group_write |
                                     std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::add);
    cases.push_back({"group/other-writable", writable, TokenFileOutcome::untrusted_owner});
#endif

    for (auto& c : cases) {
        CAPTURE(c.what);
        std::string token = "from-option";
        auto path = c.path;
        const auto r = resolve_enrollment_token(token, path);
        CHECK(file_outcome_of(r) == c.expected);
        CHECK(path.empty());
        CHECK(token == "from-option");
        CHECK(r.source == "option");
    }
}

TEST_CASE("resolve_enrollment_token: an unusable file with no option leaves no token at all",
          "[enrollment][enrollment_token_file]") {
    TokenDir t;
    std::string token;
    auto path = t.at("missing");
    const auto r = resolve_enrollment_token(token, path);
    CHECK(file_outcome_of(r) == TokenFileOutcome::absent);
    CHECK(path.empty());
    CHECK(token.empty());
    CHECK(r.source == "none");
}

TEST_CASE("resolve_enrollment_token: with no path configured nothing is read",
          "[enrollment][enrollment_token_file]") {
    // The upgrade case: a service whose machine environment still carries
    // YUZU_ENROLLMENT_TOKEN and has no token file keeps registering with it.
    std::string env_token = "from-env";
    std::filesystem::path none;
    const auto with_env = resolve_enrollment_token(env_token, none);
    CHECK_FALSE(with_env.file_outcome.has_value());
    CHECK(env_token == "from-env");
    CHECK(none.empty());
    CHECK(with_env.source == "option");

    std::string no_token;
    const auto nothing = resolve_enrollment_token(no_token, none);
    CHECK_FALSE(nothing.file_outcome.has_value());
    CHECK(no_token.empty());
    CHECK(nothing.source == "none");
}

// ── resolve_enrollment_token_with: the read is bounded ──────────────────────
//
// main() runs the read before the Windows SCM hand-off, so a read that never
// returns must cost the start a bounded wait and a tokenless run, not the
// START_PENDING deadline. The injected reader below blocks until the test opens
// its gate, so it CANNOT finish before the deadline whatever the deadline is: the
// timeout is asserted without any timing assumption.

TEST_CASE("resolve_enrollment_token_with: a read that outlasts the deadline is unreadable, "
          "clears the path and leaves the option token",
          "[enrollment][enrollment_token_file]") {
    std::promise<void> gate;
    const auto blocked = [opened = gate.get_future().share()](const std::filesystem::path&) {
        opened.wait();
        // What a late-arriving read would have said; nobody may observe it.
        EnrollmentTokenFileRead late;
        late.token = make_hex('9');
        late.outcome = TokenFileOutcome::ok;
        return late;
    };
    std::string token = "from-option";
    std::filesystem::path path = "ignored-by-the-injected-reader";
    const auto r = yuzu::agent::resolve_enrollment_token_with(token, path, blocked,
                                                              std::chrono::milliseconds{1});
    gate.set_value(); // let the abandoned worker finish; its result is discarded
    REQUIRE(r.file_outcome.has_value());
    CHECK(*r.file_outcome == TokenFileOutcome::unreadable);
    CHECK(r.file_detail == "timed out");
    CHECK(path.empty());
    CHECK(token == "from-option");
    CHECK(r.source == "option");
}

TEST_CASE("resolve_enrollment_token_with: a read that returns in time is used as read",
          "[enrollment][enrollment_token_file]") {
    const std::string file_token = make_hex('8');
    const auto ok_reader = [file_token](const std::filesystem::path&) {
        EnrollmentTokenFileRead read;
        read.token = file_token;
        read.outcome = TokenFileOutcome::ok;
        return read;
    };
    std::string token;
    std::filesystem::path path = "kept";
    const auto r = yuzu::agent::resolve_enrollment_token_with(
        token, path, ok_reader, yuzu::agent::kEnrollmentTokenReadDeadline);
    CHECK(file_outcome_of(r) == TokenFileOutcome::ok);
    CHECK(token == file_token);
    CHECK(path == "kept");
    CHECK(r.source == "file");

    // A non-ok outcome and its detail pass through untouched, and the path is cleared.
    const auto untrusted = [](const std::filesystem::path&) {
        EnrollmentTokenFileRead read;
        read.outcome = TokenFileOutcome::untrusted_owner;
        read.detail = "owned by someone else";
        return read;
    };
    std::string option = "from-option";
    std::filesystem::path other = "cleared";
    const auto u = yuzu::agent::resolve_enrollment_token_with(
        option, other, untrusted, yuzu::agent::kEnrollmentTokenReadDeadline);
    CHECK(file_outcome_of(u) == TokenFileOutcome::untrusted_owner);
    CHECK(u.file_detail == "owned by someone else");
    CHECK(other.empty());
    CHECK(option == "from-option");
    CHECK(u.source == "option");
}
