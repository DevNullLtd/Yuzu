/**
 * test_update_source_trust_parsers.cpp -- pure parser + row-formatter tests for
 * update_source_trust (update_source_trust_parsers.hpp). The parser cases build
 * and run on every OS, unguarded: nothing in them touches the filesystem, a
 * process or a clock. The final POSIX-only section (`#if !defined(_WIN32)`)
 * drives the injected-root walk shell (update_source_trust_linux_parsers.hpp)
 * over the REAL CAPTURE trees in fixtures/wave10/update_source_trust/linux/ and
 * over `yuzu_test_update_source_trust_walk_*` temp roots for the filesystem fault cases (FIFO,
 * symlink leaf, oversized file, directory cap, EACCES).
 *
 * Inputs are labelled. The apt texts in the parser cases are RECONSTRUCTIONS
 * written from sources.list(5) / apt's deb822 documentation; the walk section
 * reads the REAL CAPTURES (debian:bookworm, ubuntu:22.04 containers -- see
 * linux/provenance.txt). test_update_source_trust_linux_parsers.cpp layers
 * manifest-described trees on top. Every behaviour asserted here is
 * a value flowing from input text to an emitted wire row, so removing the
 * wiring (the parse, the tri mapping, the redaction, the escape) fails a test:
 * see the "MUTATION" notes on the individual cases.
 */
#include <catch2/catch_test_macros.hpp>

#include "update_source_trust_legs.hpp" // kWindowsPlannedToken, kMacosPlannedToken
#include "update_source_trust_parsers.hpp"

#include <cerrno>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include "update_source_trust_linux_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <constraint_accumulator.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#endif

namespace ust = yuzu::update_source_trust;

namespace {

/// Splits a wire row the way the shared server decoder does
/// (server/core/src/result_parsing.hpp): a backslash immediately before a pipe
/// is an ESCAPED pipe, not a delimiter.
std::vector<std::string> split_wire(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

} // namespace

// ── tri mapping ──────────────────────────────────────────────────────────

TEST_CASE("tri_from_value: absent is unset, known tokens map, the rest is unmodelled",
          "[update_source_trust][parsers]") {
    CHECK(ust::tri_from_value(std::nullopt) == ust::Tri::unset);
    for (std::string_view v : {"yes", "YES", "true", "1", "on", "enabled", " 1 "})
        CHECK(ust::tri_from_value(v) == ust::Tri::yes);
    for (std::string_view v : {"no", "No", "false", "0", "off", "disabled"})
        CHECK(ust::tri_from_value(v) == ust::Tri::no);
    // Present-but-unrecognised is NOT absent and is NOT coerced.
    for (std::string_view v : {"maybe", "", "2", "ye"})
        CHECK(ust::tri_from_value(v) == ust::Tri::unmodelled);
    CHECK(ust::tri_token(ust::Tri::unmodelled) == "unmodelled");
    CHECK(ust::tri_token(ust::Tri::unset) == "unset");
}

// ── redaction / escaping ─────────────────────────────────────────────────

TEST_CASE("redact_url_userinfo strips credentials from every URL in a list",
          "[update_source_trust][parsers]") {
    CHECK(ust::redact_url_userinfo("https://user:s3cret@repo.example/x") ==
          "https://REDACTED@repo.example/x");
    CHECK(ust::redact_url_userinfo("https://tok@a.example/p https://b.example/q") ==
          "https://REDACTED@a.example/p https://b.example/q");
    // No userinfo, and an '@' in the PATH (not the authority), are untouched.
    CHECK(ust::redact_url_userinfo("http://h.example/a@b") == "http://h.example/a@b");
    CHECK(ust::redact_url_userinfo("file:///etc/pki/key") == "file:///etc/pki/key");
    CHECK(ust::redact_url_userinfo("plain text") == "plain text");
}

// ── apt one-line ─────────────────────────────────────────────────────────

TEST_CASE("parse_apt_one_line: types, options, comments, unknown options tolerated",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line(
        "# a comment\n"
        "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"
        "deb-src http://archive.ubuntu.com/ubuntu jammy main\n"
        "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] "
        "https://download.docker.com/linux/ubuntu jammy stable\n"
        "deb [trusted=yes allow-insecure=no] http://repo.local/ ./\n"
        "deb [ arch+=i386 weird lang=en ] http://x.example/ y main # trailing comment\n"
        "\n");
    REQUIRE(r.sources.size() == 5);
    CHECK(r.malformed == 0);

    CHECK(r.sources[0].types == "deb");
    CHECK(r.sources[0].uris == "http://archive.ubuntu.com/ubuntu");
    CHECK(r.sources[0].suites == "jammy");
    CHECK(r.sources[0].components == "main restricted");
    CHECK(r.sources[0].signed_by.empty());
    CHECK(r.sources[0].trusted == ust::Tri::unset);
    CHECK(r.sources[0].enabled == ust::Tri::yes);

    CHECK(r.sources[1].types == "deb-src");

    CHECK(r.sources[2].signed_by == "/usr/share/keyrings/docker.gpg");
    CHECK(r.sources[2].components == "stable");
    CHECK(r.sources[2].trusted == ust::Tri::unset);

    CHECK(r.sources[3].trusted == ust::Tri::yes);
    CHECK(r.sources[3].allow_insecure == ust::Tri::no);
    CHECK(r.sources[3].suites == "./");
    CHECK(r.sources[3].components.empty());

    // Unknown option keys, a bare option token and a `key+=` operator are
    // tolerated; the trailing comment is not part of the components.
    CHECK(r.sources[4].uris == "http://x.example/");
    CHECK(r.sources[4].suites == "y");
    CHECK(r.sources[4].components == "main");
    CHECK(r.sources[4].signed_by.empty());
}

TEST_CASE("parse_apt_one_line: unterminated options and short lines are malformed, not absent",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line("deb [arch=amd64 http://x.example/ y main\n"
                                           "deb http://only-a-uri.example/\n"
                                           "deb http://ok.example/ suite main\n");
    REQUIRE(r.sources.size() == 1);
    CHECK(r.malformed == 2);
    CHECK(r.sources[0].uris == "http://ok.example/");
}

TEST_CASE("parse_apt_one_line: an unrecognised type and a garbled trusted value are unmodelled",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line("rpm http://x.example/ y main\n"
                                           "deb [trusted=maybe] http://y.example/ z main\n");
    REQUIRE(r.sources.size() == 2);
    CHECK(r.sources[0].types == "unmodelled");
    CHECK(r.sources[1].trusted == ust::Tri::unmodelled);
}

// ── apt deb822 ───────────────────────────────────────────────────────────

TEST_CASE("parse_apt_deb822: multi-stanza file with Signed-By (bookworm-shaped)",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_deb822(
        "Types: deb\n"
        "URIs: http://deb.debian.org/debian\n"
        "Suites: bookworm bookworm-updates\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        "\n"
        "Types: deb\n"
        "URIs: http://deb.debian.org/debian-security\n"
        "Suites: bookworm-security\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n");
    REQUIRE(r.sources.size() == 2);
    CHECK(r.malformed == 0);
    CHECK(r.sources[0].types == "deb");
    CHECK(r.sources[0].uris == "http://deb.debian.org/debian");
    CHECK(r.sources[0].suites == "bookworm bookworm-updates");
    CHECK(r.sources[0].components == "main");
    CHECK(r.sources[0].signed_by == "/usr/share/keyrings/debian-archive-keyring.gpg");
    CHECK(r.sources[0].trusted == ust::Tri::unset);
    CHECK(r.sources[0].enabled == ust::Tri::yes); // deb822 default
    CHECK(r.sources[1].suites == "bookworm-security");
}

TEST_CASE("parse_apt_deb822: inline key is never echoed; Enabled/Trusted/unknown fields",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_deb822("# comment\r\n"
                                         "Types: deb deb-src\r\n"
                                         "URIs: https://a.example/ https://b.example/\r\n"
                                         "Suites: stable\r\n"
                                         "Components: main contrib\r\n"
                                         "Signed-By:\r\n"
                                         " -----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
                                         " .\r\n"
                                         " mQINBFxxxxxxxx\r\n"
                                         " -----END PGP PUBLIC KEY BLOCK-----\r\n"
                                         "Enabled: no\r\n"
                                         "Trusted: yes\r\n"
                                         "X-Unknown-Field: whatever\r\n");
    REQUIRE(r.sources.size() == 1);
    CHECK(r.malformed == 0);
    CHECK(r.sources[0].types == "deb deb-src");
    CHECK(r.sources[0].uris == "https://a.example/ https://b.example/");
    CHECK(r.sources[0].components == "main contrib");
    CHECK(r.sources[0].signed_by == "inline_key");
    CHECK(r.sources[0].enabled == ust::Tri::no);
    CHECK(r.sources[0].trusted == ust::Tri::yes);
}

TEST_CASE("parse_apt_deb822: field names are case-insensitive; Components is optional",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_deb822("types: deb rpm\nuris: http://x.example/\nsuites: ./\n");
    REQUIRE(r.sources.size() == 1);
    CHECK(r.sources[0].types == "deb unmodelled");
    CHECK(r.sources[0].components.empty());
    CHECK(r.sources[0].signed_by.empty());
}

TEST_CASE("parse_apt_deb822: a stanza missing a required field, and stray lines, are malformed",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_deb822(" orphan continuation\n"
                                         "garbage without a colon\n"
                                         "\n"
                                         "Types: deb\n"
                                         "URIs: http://x.example/\n"
                                         "\n"
                                         "Types: deb\n"
                                         "URIs: http://ok.example/\n"
                                         "Suites: s\n");
    REQUIRE(r.sources.size() == 1);
    CHECK(r.sources[0].uris == "http://ok.example/");
    CHECK(r.malformed == 3); // orphan, garbage line, and the Suites-less stanza
}

// ── rows: exact wire text ────────────────────────────────────────────────

TEST_CASE("apt_rows_from_text emits the exact apt_source wire row (one-line)",
          "[update_source_trust][parsers][apt]") {
    std::vector<std::string> rows;
    const auto malformed = ust::apt_rows_from_text(
        "/etc/apt/sources.list.d/docker.list", ust::AptFormat::one_line,
        "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] "
        "https://download.docker.com/linux/ubuntu jammy stable\n",
        rows);
    CHECK(malformed == 0);
    REQUIRE(rows.size() == 1);
    // MUTATION: dropping the signed-by wiring, the file path or the format
    // token changes this exact string.
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list.d/docker.list|one_line|deb|"
                     "https://download.docker.com/linux/ubuntu|jammy|stable|"
                     "/usr/share/keyrings/docker.gpg|unset|unset|yes");
}

TEST_CASE("apt_rows_from_text emits the exact apt_source wire row (deb822) and counts malformed",
          "[update_source_trust][parsers][apt]") {
    std::vector<std::string> rows;
    const auto malformed = ust::apt_rows_from_text(
        "/etc/apt/sources.list.d/debian.sources", ust::AptFormat::deb822,
        "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm\nComponents: main\n"
        "Trusted: yes\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        "\nnot a stanza field\n",
        rows);
    CHECK(malformed == 1);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list.d/debian.sources|deb822|deb|"
                     "http://deb.debian.org/debian|bookworm|main|"
                     "/usr/share/keyrings/debian-archive-keyring.gpg|yes|unset|yes");
}

TEST_CASE("apt_source row: credentials are redacted; pipes and backslashes cannot shift fields",
          "[update_source_trust][parsers][wire]") {
    ust::AptSourceFacts f;
    f.types = "deb";
    f.uris = "https://user:s3cret@repo.example/x";
    f.suites = "stable";
    f.components = "a|b";                 // pipe inside a value
    f.signed_by = "C:\\keys\\";           // trailing backslash (would read as an escaped pipe)
    const std::string row = ust::format_apt_source_row("/etc/apt/x.list", ust::AptFormat::one_line, f);

    CHECK(row.find("s3cret") == std::string::npos);
    CHECK(row.find("REDACTED@repo.example") != std::string::npos);

    // Escape-aware split (the server decoder's grammar) sees EXACTLY 11
    // fields, and the trailing-backslash value cannot swallow the delimiter.
    const auto fields = split_wire(row);
    REQUIRE(fields.size() == 11);
    CHECK(fields[0] == "apt_source");
    CHECK(fields[4] == "https://REDACTED@repo.example/x");
    CHECK(fields[6] == "a|b");        // escaped on the wire, decoded back
    CHECK(fields[7] == "C:/keys/");   // safe_output_field folds '\' to '/'
    CHECK(fields[8] == "unset");
}

TEST_CASE("apt_source row: a credential in the suite, component or signed_by field is redacted too",
          "[update_source_trust][parsers][wire]") {
    // Redaction is per field (a whole-row pass would scan across the `|`
    // separators). MUTATION: plain field() on suites/components/signed_by emits
    // the credential verbatim (an adversarial-review probe confirmed it).
    ust::AptSourceFacts f;
    f.types = "deb";
    f.uris = "https://a.example/x";
    f.suites = "https://suiteuser:pw1@evil.example/";
    f.components = "https://compuser:pw2@evil.example/ main";
    f.signed_by = "https://keyuser:pw3@evil.example/k.gpg";
    const std::string row = ust::format_apt_source_row("/etc/apt/x.list", ust::AptFormat::one_line, f);

    for (const char* secret : {"suiteuser", "pw1", "compuser", "pw2", "keyuser", "pw3"})
        CHECK(row.find(secret) == std::string::npos);
    const auto fields = split_wire(row);
    REQUIRE(fields.size() == 11);
    CHECK(fields[4] == "https://a.example/x"); // a URI without userinfo is untouched
    CHECK(fields[5] == "https://REDACTED@evil.example/");
    CHECK(fields[6] == "https://REDACTED@evil.example/ main");
    CHECK(fields[7] == "https://REDACTED@evil.example/k.gpg");
}

// ── keyrings ─────────────────────────────────────────────────────────────

TEST_CASE("sniff_keyring classifies armored, binary, empty and unmodelled heads",
          "[update_source_trust][parsers][apt]") {
    CHECK(ust::sniff_keyring("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: x\n") ==
          ust::KeyFormat::armored);
    CHECK(ust::sniff_keyring("\n\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n") == ust::KeyFormat::armored);
    CHECK(ust::sniff_keyring(std::string_view("\x99\x01\x0d\x04", 4)) == ust::KeyFormat::binary);
    CHECK(ust::sniff_keyring("") == ust::KeyFormat::empty);
    CHECK(ust::sniff_keyring("this is not a key") == ust::KeyFormat::unmodelled);
}

TEST_CASE("apt_keyring row is exact", "[update_source_trust][parsers][apt]") {
    CHECK(ust::format_apt_keyring_row("/etc/apt/trusted.gpg.d/ubuntu-keyring.gpg", "trusted_gpg_d",
                                      ust::KeyFormat::binary, 2794) ==
          "apt_keyring|/etc/apt/trusted.gpg.d/ubuntu-keyring.gpg|trusted_gpg_d|binary|2794");
}

// ── status rows / tokens ─────────────────────────────────────────────────

TEST_CASE("status rows: supported, constrained (reason), and the Windows and macOS planned rows",
          "[update_source_trust][parsers]") {
    CHECK(ust::format_status_row(ust::StatusState::supported, {}) == "status|sources|supported|-");
    CHECK(ust::format_status_row(
              ust::StatusState::constrained,
              "linux:apt_sources:permission_denied,linux:apt_keyring:oversized") ==
          "status|sources|constrained|linux:apt_sources:permission_denied,linux:apt_keyring:oversized");
    // The exact rows the Windows and macOS placeholder legs emit.
    CHECK(ust::format_status_row(ust::StatusState::unsupported, ust::kWindowsPlannedToken) ==
          "status|sources|unsupported|windows:planned");
    CHECK(ust::format_status_row(ust::StatusState::unsupported, ust::kMacosPlannedToken) ==
          "status|sources|unsupported|macos:planned");
}

TEST_CASE("errno_detail maps real failures to stable tokens and never invents 'absent'",
          "[update_source_trust][parsers]") {
    using ust::IoStage;
    CHECK(ust::errno_detail(EACCES, IoStage::open_file) == "permission_denied");
    CHECK(ust::errno_detail(EPERM, IoStage::open_dir) == "permission_denied");
    CHECK(ust::errno_detail(ELOOP, IoStage::open_file) == "symlink_refused");
    CHECK(ust::errno_detail(ENOTDIR, IoStage::open_dir) == "not_a_directory");
    CHECK(ust::errno_detail(EISDIR, IoStage::open_file) == "not_regular");
    CHECK(ust::errno_detail(EIO, IoStage::read_file) == "io_error");
    CHECK(ust::errno_detail(ENOSPC, IoStage::open_file) == "open_failed");
    CHECK(ust::errno_detail(ENOSPC, IoStage::read_file) == "read_failed");
    CHECK(ust::errno_detail(ENOSPC, IoStage::open_dir) == "dir_open_failed");
}

// ── injected-root walk shell (POSIX only) ────────────────────────────────

#if !defined(_WIN32)

namespace {

namespace fs = std::filesystem;
namespace lnx = yuzu::update_source_trust::lnx;
namespace pio = yuzu::update_source_trust::posix_io;

fs::path linux_fixture_root(const char* distro) {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "update_source_trust" / "linux" / distro;
#else
    return fs::path("tests/unit/fixtures/wave10/update_source_trust/linux") / distro;
#endif
}

/// A scratch injected root: a yuzu::test::TempDir (the `yuzu_test_` prefix) that
/// exists from construction (TempDir only names the path), plus two path helpers.
struct TempRoot {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_walk_"};
    fs::path path;
    TempRoot() : path(dir.path) { fs::create_directories(path); }
    fs::path apt() const { return path / "etc/apt"; }
    void write(const fs::path& rel, std::string_view text) const {
        fs::create_directories((path / rel).parent_path());
        std::ofstream f(path / rel, std::ios::binary);
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
    }
};

bool reason_has(const yuzu::shared::ConstraintAccumulator& acc, std::string_view token) {
    return acc.reason().find(token) != std::string::npos;
}

} // namespace

TEST_CASE("apt_rows_at over the real debian:bookworm tree: deb822 rows + armored keyring",
          "[update_source_trust][walk][apt]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::apt_rows_at(linux_fixture_root("debian-bookworm"), acc);
    // No sources.list, no legacy trusted.gpg, empty /etc/apt/keyrings: all absent,
    // none of them a failure.
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    REQUIRE(rows.size() == 3);
    // MUTATION: the deb822 dispatch by `.sources` suffix, the logical (not
    // root-prefixed) path, the comment skip and the .asc keyring scan each change
    // one of these strings.
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list.d/debian.sources|deb822|deb|"
                     "http://deb.debian.org/debian|bookworm bookworm-updates|main|"
                     "/usr/share/keyrings/debian-archive-keyring.gpg|unset|unset|yes");
    CHECK(rows[1] == "apt_source|/etc/apt/sources.list.d/debian.sources|deb822|deb|"
                     "http://deb.debian.org/debian-security|bookworm-security|main|"
                     "/usr/share/keyrings/debian-archive-keyring.gpg|unset|unset|yes");
    CHECK(rows[2] == "apt_keyring|/etc/apt/trusted.gpg.d/debian-archive-bookworm-stable.asc|"
                     "trusted_gpg_d|armored|461");

    // The WHOLE leg (apt + the rpm-family tripwire) is clean on this real capture:
    // /etc/yum.repos.d is absent on the image, so nothing was skipped and the leg
    // reports supported. MUTATION: an unconditional `planned` token fails here.
    yuzu::shared::ConstraintAccumulator leg_acc;
    CHECK(lnx::linux_rows_at(linux_fixture_root("debian-bookworm"), leg_acc) == rows);
    CHECK_FALSE(leg_acc.any_failure());
    CHECK_FALSE(leg_acc.incomplete());
}

TEST_CASE("apt_rows_at over the real ubuntu:22.04 tree: one-line rows + binary keyring",
          "[update_source_trust][walk][apt]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::apt_rows_at(linux_fixture_root("ubuntu-2204"), acc);
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    REQUIRE(rows.size() == 11); // 10 active `deb` lines + the 2018 archive keyring
    CHECK(rows.front() == "apt_source|/etc/apt/sources.list|one_line|deb|"
                          "http://ports.ubuntu.com/ubuntu-ports/|jammy|main restricted|-|"
                          "unset|unset|yes");
    CHECK(rows[6] == "apt_source|/etc/apt/sources.list|one_line|deb|"
                     "http://ports.ubuntu.com/ubuntu-ports/|jammy-backports|"
                     "main restricted universe multiverse|-|unset|unset|yes");
    CHECK(rows.back() == "apt_keyring|/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg|"
                         "trusted_gpg_d|binary|1733");

    // No /etc/yum.repos.d on this image either: the whole leg stays supported.
    yuzu::shared::ConstraintAccumulator leg_acc;
    CHECK(lnx::linux_rows_at(linux_fixture_root("ubuntu-2204"), leg_acc) == rows);
    CHECK_FALSE(leg_acc.any_failure());
}

TEST_CASE("an empty root is absent for every family: zero rows, no failure token",
          "[update_source_trust][walk]") {
    const TempRoot root;
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::linux_rows_at(root.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
}

TEST_CASE("a FIFO at a scanned path is rejected promptly, never blocks in open()",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    fs::create_directories(root.apt());
    REQUIRE(::mkfifo((root.apt() / "sources.list").c_str(), 0600) == 0);

    // No writer ever opens the FIFO. A blocking open() would hang the suite, so the
    // walk runs on a worker with a generous hang guard (a deadlock guard, not a
    // timing assumption: the healthy path returns in microseconds).
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    auto fut = std::async(std::launch::async, [&] { rows = lnx::apt_rows_at(root.path, acc); });
    if (fut.wait_for(std::chrono::seconds(20)) != std::future_status::ready) {
        // Release the blocked open() so the worker (and this process) can exit.
        const int rel = ::open((root.apt() / "sources.list").c_str(), O_RDWR | O_NONBLOCK);
        fut.wait();
        if (rel >= 0)
            ::close(rel);
        FAIL("apt_rows_at blocked in open() on a writer-less FIFO");
    }
    // MUTATION: dropping O_NONBLOCK hangs (guard above); dropping the S_ISREG check
    // would try to read the FIFO and lose this token.
    CHECK(rows.empty());
    CHECK(acc.incomplete());
    CHECK(reason_has(acc, "linux:apt_sources:not_regular"));
}

TEST_CASE("a symlink leaf is refused, not followed", "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/real.list", "deb http://x.example/ y main\n");
    fs::create_symlink("real.list", root.apt() / "sources.list");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::apt_rows_at(root.path, acc);
    // MUTATION: removing O_NOFOLLOW makes sources.list parse and drops the token.
    CHECK(rows.empty());
    CHECK(reason_has(acc, "linux:apt_sources:symlink_refused"));
    CHECK(acc.incomplete());
}

TEST_CASE("a malformed apt entry is unparsed_entry, never silently absent (one-line and deb822)",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    // One malformed entry per format beside a well-formed one: the good entry
    // still yields its row; the bad one becomes a constraint, not silence.
    root.write("etc/apt/sources.list",
               "deb [arch=amd64 http://x.example/ y main\n" // unterminated `[`
               "deb http://ok.example/ suite main\n");
    root.write("etc/apt/sources.list.d/bad.sources",
               "Types: deb\nURIs: http://x.example/\n\n" // stanza without Suites
               "Types: deb\nURIs: http://ok.example/\nSuites: s\n");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::apt_rows_at(root.path, acc);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list|one_line|deb|http://ok.example/|suite|main|-|"
                     "unset|unset|yes");
    CHECK(rows[1] == "apt_source|/etc/apt/sources.list.d/bad.sources|deb822|deb|http://ok.example/|s|"
                     "-|-|unset|unset|yes");
    // MUTATION (an orchestrator probe confirmed it survived before this case
    // existed): deleting the unparsed_entry note_failure in add_apt_file leaves
    // the accumulator clean and the host reads `supported` with a source missing.
    CHECK(acc.any_failure());
    CHECK(acc.incomplete());
    CHECK(acc.reason() == "linux:apt_sources:unparsed_entry"); // one token for both files (exact-string dedupe)
}

TEST_CASE("a file over 1 MiB is oversized, never silently truncated",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/sources.list", "deb http://x.example/ y main\n");
    fs::resize_file(root.apt() / "sources.list", pio::kMaxFileBytes + 1); // sparse
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::apt_rows_at(root.path, acc).empty());
    // MUTATION: removing the size guard parses (or truncates) the file instead.
    CHECK(reason_has(acc, "linux:apt_sources:oversized"));
    CHECK(acc.incomplete());
}

TEST_CASE("a directory over the entry cap reports entry_cap but keeps the names read",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    fs::create_directories(root.apt() / "sources.list.d");
    for (std::size_t i = 0; i <= pio::kMaxDirEntries; ++i) // cap + 1 empty files
        std::ofstream(root.apt() / "sources.list.d" / ("f" + std::to_string(1000000 + i) + ".list"));
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::apt_rows_at(root.path, acc).empty()); // empty files: no sources
    // MUTATION: ignoring walk.truncated loses this token.
    CHECK(reason_has(acc, "linux:apt_sources:entry_cap"));
    CHECK(acc.incomplete());
}

TEST_CASE("the rows of one walk share a budget: output_cap, newest rows dropped, no further file read",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    // Three sources of ~400 KiB each (one giant, legal URI token per file): two fit
    // the 1 MiB budget, the third does not. Files are read in sorted order.
    const std::string big(400000, 'a');
    for (const char* name : {"a.list", "b.list", "c.list"})
        root.write(std::string("etc/apt/sources.list.d/") + name,
                   "deb http://" + big + "/ suite main\n");
    // d.list is over the per-file cap: if the walk kept reading past the spent
    // budget it would add an `oversized` token.
    root.write("etc/apt/sources.list.d/d.list", "deb http://x.example/ y main\n");
    fs::resize_file(root.apt() / "sources.list.d" / "d.list", pio::kMaxFileBytes + 1); // sparse

    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::apt_rows_at(root.path, acc);
    // MUTATIONS: no budget -> 3 rows and no token; a budget that does not trim ->
    // 3 rows; a budget that does not stop the walk -> the `oversized` token below.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].find("/etc/apt/sources.list.d/a.list") != std::string::npos);
    CHECK(rows[1].find("/etc/apt/sources.list.d/b.list") != std::string::npos);
    CHECK(reason_has(acc, "linux:apt_sources:output_cap"));
    CHECK_FALSE(reason_has(acc, "oversized"));
    CHECK(acc.incomplete());
}

TEST_CASE("an unreadable file is constrained with permission_denied, never absent",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/sources.list", "deb http://x.example/ y main\n");
    std::error_code ec;
    fs::permissions(root.apt() / "sources.list", fs::perms::none, fs::perm_options::replace, ec);
    REQUIRE_FALSE(ec);
    if (const int probe = ::open((root.apt() / "sources.list").c_str(), O_RDONLY); probe >= 0) {
        ::close(probe);
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    }
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::apt_rows_at(root.path, acc).empty());
    // MUTATION: mapping EACCES to `absent` drops this token.
    CHECK(reason_has(acc, "linux:apt_sources:permission_denied"));
    CHECK(acc.incomplete());
}

#endif // !defined(_WIN32)
