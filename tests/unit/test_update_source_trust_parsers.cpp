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

TEST_CASE("tri_from_apt_value is apt's vocabulary: the yum words are not apt tokens",
          "[update_source_trust][parsers]") {
    CHECK(ust::tri_from_apt_value(std::nullopt) == ust::Tri::unset);
    for (std::string_view v : {"yes", "YES", "true", "1", "on", "enable", "with", " 1 "})
        CHECK(ust::tri_from_apt_value(v) == ust::Tri::yes);
    for (std::string_view v : {"no", "No", "false", "0", "off", "disable", "without"})
        CHECK(ust::tri_from_apt_value(v) == ust::Tri::no);
    // apt ignores `Trusted: enabled` and keeps an `Enabled: disabled` source active
    // (both verified on apt 3.0.3), so neither is a yes/no here. MUTATION: the
    // yum vocabulary reads them as yes and no.
    for (std::string_view v : {"enabled", "disabled", "maybe", "", "2", "ye"})
        CHECK(ust::tri_from_apt_value(v) == ust::Tri::unmodelled);
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
    // The authority ends at the first '/' or whitespace only, as in apt: a '?' or
    // '#' in the password (apt resolves both) and a second '@' must not leak the
    // tail. MUTATION: ending the authority at '?' / '#' leaves `ss` and `pw` visible.
    CHECK(ust::redact_url_userinfo("http://bob:pa?ss@127.0.0.2:9/apt") ==
          "http://REDACTED@127.0.0.2:9/apt");
    CHECK(ust::redact_url_userinfo("http://carol:pa#ss@127.0.0.3:9/apt") ==
          "http://REDACTED@127.0.0.3:9/apt");
    CHECK(ust::redact_url_userinfo("http://u:p@ss@h.example/x") == "http://REDACTED@h.example/x");
    // A '@' in a query string over-redacts (the safe direction).
    CHECK(ust::redact_url_userinfo("http://h.example?x=a@b") == "http://REDACTED@b");
    // apt's own URI split (URI::CopyFrom), verified on apt 2.6-3.0: a scheme with no
    // "//", a '/' inside `[...]` (the authority ends at the first '/' OUTSIDE it), a
    // backslash, and a percent-encoded scheme all resolve the host after the LAST
    // '@'. MUTATION: requiring "://" or ending the authority at any '/' leaks each.
    CHECK(ust::redact_url_userinfo("http:bob:SEKRET@127.0.0.9:9/apt") ==
          "http:REDACTED@127.0.0.9:9/apt");
    CHECK(ust::redact_url_userinfo("http://u:p[/]SEKRET@127.0.0.20:9/apt") ==
          "http://REDACTED@127.0.0.20:9/apt");
    CHECK(ust::redact_url_userinfo("http://user:[s3/cr3t]@h.example/y") ==
          "http://REDACTED@h.example/y");
    CHECK(ust::redact_url_userinfo("http:\\u:SEKRET@127.0.0.9:9/apt") ==
          "http:REDACTED@127.0.0.9:9/apt");
    // The scheme's own %3a is recognised structurally (to find the authority) but
    // never decoded for DISPLAY: the literal bytes the admin wrote are kept, only
    // the credential span is replaced.
    CHECK(ust::redact_url_userinfo("http%3a//u:SEKRET@h.example/x") ==
          "http%3a//REDACTED@h.example/x");
    // A DOUBLE-encoded "//" (the scheme's %3A is recognised, but the slashes after
    // it are not) is over-redacted into the authority span rather than risking a
    // miss: the secret still never appears on the wire.
    CHECK(ust::redact_url_userinfo("http%3A%2F%2Fu:secretpw@h.example/x").find("secretpw") ==
          std::string::npos);
    // Not userinfo: a cdrom label, an IPv6 authority and an '@' in a path stay.
    CHECK(ust::redact_url_userinfo("cdrom:[Debian GNU/Linux 12 DVD 1]/") ==
          "cdrom:[Debian GNU/Linux 12 DVD 1]/");
    CHECK(ust::redact_url_userinfo("http://[::1]:8080/x") == "http://[::1]:8080/x");
    CHECK(ust::redact_url_userinfo("http://h.example/a@b") == "http://h.example/a@b");
    // Each word of a list is split on its own; the credential may sit in a LATER
    // word after a URL that has no '/' (only the whitespace ends its authority).
    CHECK(ust::redact_url_userinfo("http://a.example http://u:p@b.example/x") ==
          "http://a.example http://REDACTED@b.example/x");
    // A replaced byte can create a URL shape apt never saw (`http:<NUL>//u:pw@h/`),
    // so url_field drops everything up to the last '@' of any word it had to scrub.
    const std::string poisoned("http:\0//u:pw@h.example/x", sizeof("http:\0//u:pw@h.example/x") - 1);
    std::size_t n = 0;
    CHECK(ust::url_field(poisoned, n).find("pw") == std::string::npos);
    CHECK(ust::url_field(std::string("http://a.example/x\xff"), n) == "http://a.example/x?");
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
        "deb [ arch+=i386 lang=en ] http://x.example/ y main # trailing comment\n"
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

    // Unknown option keys and a `key+=` operator are tolerated; the trailing
    // comment is not part of the components.
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

TEST_CASE("parse_apt_one_line: a garbled trusted value is unmodelled; entries apt refuses are malformed",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line(
        "deb [trusted=maybe] http://y.example/ z main\n" // one source
        "rpm http://a.example/ y main\n"                 // unknown type
        "DEB http://b.example/ y main\n"                 // type is case-sensitive
        "deb[arch=amd64] http://c.example/ y main\n"     // glued option block
        "deb [foo] http://d.example/ y main\n"           // option without '='
        "deb [trusted = yes] http://e.example/ y main\n" // spaces around '='
        "deb [a=b] [c=d] http://f.example/ y main\n"     // a second block
        "\xef\xbb\xbf" "deb http://i.example/ y main\n");  // a BOM before the type
    REQUIRE(r.sources.size() == 1);
    CHECK(r.sources[0].trusted == ust::Tri::unmodelled);
    // apt refuses each of these (verified on apt 3.0.3); reporting a row for one
    // would show a source apt does not use. MUTATION: dropping a refuse rule emits it.
    CHECK(r.malformed == 7);
}

TEST_CASE("parse_apt_one_line: apt reads a %-encoded or quoted option value, and even a quoted URI word",
          "[update_source_trust][parsers][apt]") {
    // Real apt accepts every line below (verified on apt 2.0.10-3.2.0): a '%' or a
    // '\"' anywhere in the entry must not refuse it on its own (round-2 regression,
    // hp8r2-1/hp8r2-2). An OPTION KEY is never decoded (apt does not either for the
    // keys this plugin cares about), so a percent-encoded key is simply unrecognised
    // and tolerated, not the surfaced option it spells out.
    const auto r = ust::parse_apt_one_line(
        "deb [%74rusted=yes] http://g.example/ y main\n"    // key stays literal, unrecognised
        "deb \"http://h.example/a b\" y main\n");           // apt de-quotes the whole word
    REQUIRE(r.malformed == 0);
    REQUIRE(r.sources.size() == 2);
    CHECK(r.sources[0].trusted == ust::Tri::unset); // "%74rusted" is not "trusted"
    // MUTATION: a quote or '%' anywhere refusing the entry drops this row entirely,
    // hiding a source apt actually uses; this plugin does not re-tokenise a quoted
    // word (a rare shape), so the space inside it still splits the fields.
    CHECK(r.sources[1].uris == "\"http://h.example/a");
}

TEST_CASE("parse_apt_one_line: an option VALUE is de-quoted and %XX-decoded, matching apt",
          "[update_source_trust][parsers][apt]") {
    // Verified on apt 3.0.3: [signed-by="/a b.gpg"] and [signed-by=%2Fa%2Fb.gpg] are
    // both read; MUTATION: skipping either step reports the raw quoted/encoded text.
    const auto r = ust::parse_apt_one_line(
        "deb [signed-by=\"/etc/apt/a b.gpg\"] http://x.example/ s main\n"
        "deb [signed-by=%2Fetc%2Fapt%2Fk.gpg] http://y.example/ s main\n"
        "deb [trusted=\"yes\"] http://z.example/ s main\n");
    REQUIRE(r.malformed == 0);
    REQUIRE(r.sources.size() == 3);
    CHECK(r.sources[0].signed_by == "/etc/apt/a b.gpg");
    CHECK(r.sources[1].signed_by == "/etc/apt/k.gpg");
    CHECK(r.sources[2].trusted == ust::Tri::yes);
}

TEST_CASE("percent_decoded: exactly two hex digits decode, anything else stays as written",
          "[update_source_trust][parsers][apt]") {
    // percent_decoded feeds signed-by / trusted / allow-insecure, so a divergence changes the
    // reported trust posture. MUTATION: a signed from_chars accepts "%-1", one that skips
    // whitespace or a "0x" prefix accepts "% 1" / "%0x", an off-by-one bound leaves a trailing
    // "%41" undecoded.
    CHECK(ust::percent_decoded("%41") == "A"); // at the very end of the string
    CHECK(ust::percent_decoded("%6a%6A%2f") == "jj/"); // either case of hex digit
    CHECK(ust::percent_decoded("%ff%FF") == "\xff\xff");
    CHECK(ust::percent_decoded("%00") == std::string("\0", 1));
    CHECK(ust::percent_decoded("%%41") == "%A");
    CHECK(ust::percent_decoded("%4%41") == "%4A");
    for (const char* literal : {"", "%", "a%", "%4", "%zz", "%4g", "%g4", "%+1", "%-1", "% 1", "%0x"})
        CHECK(ust::percent_decoded(literal) == literal);
    // The encoded value is decoded before the trust word is read (the percent-encoded KEY case is above).
    const auto r = ust::parse_apt_one_line("deb [trusted=%79es] http://a.example/ s main\n"
                                           "deb [trusted=%-1es] http://b.example/ s main\n");
    REQUIRE(r.sources.size() == 2);
    CHECK(r.sources[0].trusted == ust::Tri::yes);
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

TEST_CASE("parse_apt_one_line follows apt: bracket words, comments, option keys, vocabulary",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line(
        "deb cdrom:[Debian GNU/Linux 12.0.0 _Bookworm_ - DVD 1]/ bookworm contrib main\n" // 0
        "deb http://a.example/d stable main#glued\n"                                        // 1
        "deb http://b.example/d#frag stable main\n"                                         // malformed
        "deb [Trusted=yes Signed-By=/k.gpg] http://c.example/d stable main\n"               // 2
        "deb [trusted=enabled] http://d.example/d stable main\n"                            // 3
        "deb [signed-by=/a.gpg signed-by+=/b.gpg trusted-=yes] http://e.example/d s main\n" // 4
        "deb [arch=amd64] http://f.example/d stable main\n");                               // 5
    REQUIRE(r.sources.size() == 6);
    CHECK(r.malformed == 1); // a '#' ends the line, so the URI-with-fragment entry has no suite
    // MUTATION: splitting on whitespace inside `[...]` shifts uris/suites/components.
    CHECK(r.sources[0].uris == "cdrom:[Debian GNU/Linux 12.0.0 _Bookworm_ - DVD 1]/");
    CHECK(r.sources[0].suites == "bookworm");
    CHECK(r.sources[0].components == "contrib main");
    CHECK(r.sources[1].components == "main"); // `main#glued`: apt strips '#' anywhere
    // Option KEYS are case-sensitive: apt ignores [Trusted=yes] and [Signed-By=...].
    CHECK(r.sources[2].trusted == ust::Tri::unset);
    CHECK(r.sources[2].signed_by.empty());
    CHECK(r.sources[3].trusted == ust::Tri::unmodelled); // `enabled` is not an apt word
    // `+=` / `-=` on a surfaced key depends on earlier options: reported, not guessed.
    CHECK(r.sources[4].signed_by == "unmodelled");
    CHECK(r.sources[4].trusted == ust::Tri::unmodelled);
    CHECK(r.sources[5].types == "deb");
}

TEST_CASE("parse_apt_deb822 follows apt: whitespace-only line, Allow-Insecure, vocabulary, last wins",
          "[update_source_trust][parsers][apt]") {
    // A line of only whitespace is a CONTINUATION line for apt (apt 2.4-3.2), so the
    // two stanzas merge and the repeated fields keep their last value.
    // MUTATION: ending a stanza at a whitespace-only line yields one.example (a
    // complete first stanza) plus a Suites-less second stanza that is malformed.
    const auto merged = ust::parse_apt_deb822("Types: deb\nURIs: http://one.example/d\nSuites: stable\n \n"
                                              "Types: deb\nURIs: http://two.example/d\n"
                                              "Components: main\n");
    REQUIRE(merged.sources.size() == 1);
    CHECK(merged.malformed == 0);
    CHECK(merged.sources[0].uris == "http://two.example/d");
    CHECK(merged.sources[0].suites == "stable");

    // Allow-Insecure is ignored by apt in deb822; Trusted/Enabled use apt's words;
    // a repeated field is last-wins; a Signed-By list may span continuation lines.
    const auto r = ust::parse_apt_deb822("Types: deb\nURIs: http://a.example/d\nSuites: stable\n"
                                         "Allow-Insecure: yes\nTrusted: enabled\n"
                                         "Enabled: yes\nEnabled: disabled\n"
                                         "Signed-By: /k1.gpg,\n /k2.gpg\n");
    REQUIRE(r.sources.size() == 1);
    CHECK(r.sources[0].allow_insecure == ust::Tri::unset); // present, ignored by apt
    CHECK(r.sources[0].trusted == ust::Tri::unmodelled);
    CHECK(r.sources[0].enabled == ust::Tri::unmodelled); // last value wins, and it is not apt vocabulary
    CHECK(r.sources[0].signed_by == "/k1.gpg, /k2.gpg");
}

TEST_CASE("apt_dir_name_ok is apt's own file-name rule for its *.d directories",
          "[update_source_trust][parsers][apt]") {
    // apt reads exactly [A-Za-z0-9_.:-] here (an all-bytes sweep on apt 2.2-3.2):
    // the colon is legal, so `docker:ce.list` is a source.
    for (std::string_view ok : {"debian.sources", "docker.list", "a_b-c.1.list", "X9.list", "zZ0.list",
                                "a.list", "9.list", "docker:ce.list", "a:.list"})
        CHECK(ust::apt_dir_name_ok(ok));
    // Hidden, spaces, '+', '~', '@', brackets, backtick, DEL, control bytes,
    // non-ASCII and the empty name are skipped. MUTATION: suffix-only selection
    // reports them; a range off by one in the alphanumeric test admits `a@`/`a[`.
    for (std::string_view bad : {"", ".hidden.list", "my repo.list", "plus+.list", "tilde~.list",
                                 "caf\xc3\xa9.list", "back\\slash.list", "a@.list", "a[.list",
                                 "a`.list", "a{.list", "a/b.list", "a\x7f.list", "a\x01.list"})
        CHECK_FALSE(ust::apt_dir_name_ok(bad));
}

TEST_CASE("field: NUL and non-UTF-8 never reach the wire",
          "[update_source_trust][parsers][wire]") {
    // MUTATION: a field() that only escapes leaves the NUL, and the host's strlen
    // then cuts the row (a 7-of-11-field apt_source row that still says `supported`).
    CHECK(ust::field(std::string_view("a\0b", 3)) == "a?b");
    CHECK(ust::field("\xff") == "?");
    ust::AptSourceFacts f;
    f.types = "deb";
    f.uris = std::string("http://a.example/x\0y", 20);
    f.suites = "stable";
    f.trusted = ust::Tri::yes;
    const auto fields = split_wire(ust::format_apt_source_row("/etc/apt/x.list", ust::AptFormat::one_line, f));
    REQUIRE(fields.size() == 11);
    CHECK(fields[4] == "http://a.example/x?y");
    CHECK(fields[8] == "yes"); // the trust columns behind the NUL survive
}

TEST_CASE("parse_apt_one_line: '#' inside [...] is not a comment, a stray ']' is a plain character, allow-insecure follows trusted",
          "[update_source_trust][parsers][apt]") {
    const auto r = ust::parse_apt_one_line(
        "deb [signed-by=/etc/apt/k#1.gpg] http://a.example/ s main\n"
        "deb cdrom:[Disc #1]/ bookworm main\n"
        "deb http://c.example/d] stable main\n"
        "deb [allow-insecure+=yes] http://d.example/ s main\n"
        "deb [allow-insecure=enabled] http://e.example/ s main\n"
        "deb [Allow-Insecure=yes] http://f.example/ s main\n"
        "deb [allow-insecure=YES] http://g.example/ s main\n");
    CHECK(r.malformed == 0);
    REQUIRE(r.sources.size() == 7);
    CHECK(r.sources[0].signed_by == "/etc/apt/k#1.gpg");
    CHECK(r.sources[1].uris == "cdrom:[Disc #1]/");
    CHECK(r.sources[2].uris == "http://c.example/d]");
    CHECK(r.sources[3].allow_insecure == ust::Tri::unmodelled); // `+=`
    CHECK(r.sources[4].allow_insecure == ust::Tri::unmodelled); // a yum word
    CHECK(r.sources[5].allow_insecure == ust::Tri::unset);      // option keys are case-sensitive
    CHECK(r.sources[6].allow_insecure == ust::Tri::yes);
}

TEST_CASE("parse_apt_deb822: CRLF stanzas separate on the empty line, and a whitespace-only line before any field is not an entry",
          "[update_source_trust][parsers][apt]") {
    // Since only an EMPTY line ends a stanza, the CR strip is what makes "\r\n" one.
    const auto r = ust::parse_apt_deb822("Types: deb\r\nURIs: http://a.example/\r\nSuites: s\r\n\r\n"
                                         "Types: deb\r\nURIs: http://b.example/\r\nSuites: t\r\n");
    CHECK(r.malformed == 0);
    REQUIRE(r.sources.size() == 2);
    CHECK(r.sources[1].suites == "t");
    // apt reads these cleanly (verified on apt 3.0.3), so they are not malformed entries.
    const auto lead = ust::parse_apt_deb822("   \nTypes: deb\nURIs: http://a.example/\nSuites: s\n"
                                            "\n \t \nTypes: deb\nURIs: http://b.example/\nSuites: t\n \n");
    CHECK(lead.malformed == 0);
    CHECK(lead.sources.size() == 2);
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

TEST_CASE("altered counts only replaced bytes that reach the wire (after redaction)",
          "[update_source_trust][parsers][wire]") {
    // A bad byte INSIDE the userinfo is redacted away before the scrub: not counted.
    // MUTATION: counting the raw parsed facts (the old pre-count) reports altered 1.
    {
        std::vector<std::string> rows;
        std::size_t altered = 0;
        const std::string text = "deb http://user:pa\xff" "ss@host.example/debian bookworm main\n";
        CHECK(ust::apt_rows_from_text("/etc/apt/sources.list", ust::AptFormat::one_line, text,
                                      rows, &altered) == 0);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].find("http://REDACTED@host.example/debian") != std::string::npos);
        CHECK(rows[0].find('?') == std::string::npos);
        CHECK(altered == 0);
    }
    // The same byte AFTER the '@' survives redaction, is replaced and is counted once.
    {
        std::vector<std::string> rows;
        std::size_t altered = 0;
        const std::string text = "deb http://user:pass@host\xff.example/debian bookworm main\n";
        CHECK(ust::apt_rows_from_text("/etc/apt/sources.list", ust::AptFormat::one_line, text,
                                      rows, &altered) == 0);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].find("host?.example/debian") != std::string::npos);
        CHECK(altered == 1);
    }
    // A NUL in an emitted field (components) is replaced and counted.
    {
        std::vector<std::string> rows;
        std::size_t altered = 0;
        std::string text = "Types: deb\nURIs: http://h.example/\nSuites: s\nComponents: ma";
        text += '\0';
        text += "in\n";
        CHECK(ust::apt_rows_from_text("/etc/apt/x.sources", ust::AptFormat::deb822, text, rows,
                                      &altered) == 0);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].find("|ma?in|") != std::string::npos);
        CHECK(altered == 1);
    }
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
    // the credential verbatim.
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

// The walk entry points take the walk's InputBudget; these cases do not exercise it.
std::vector<std::string> fresh_apt_rows(const fs::path& root,
                                        yuzu::shared::ConstraintAccumulator& acc) {
    pio::InputBudget budget;
    return lnx::apt_rows_at(root, acc, budget);
}
std::vector<std::string> fresh_linux_rows(const fs::path& root,
                                          yuzu::shared::ConstraintAccumulator& acc) {
    pio::InputBudget budget;
    return lnx::linux_rows_at(root, acc, budget);
}

} // namespace

TEST_CASE("apt_rows_at over the real debian:bookworm tree: deb822 rows + armored keyring",
          "[update_source_trust][walk][apt]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(linux_fixture_root("debian-bookworm"), acc);
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
    CHECK(fresh_linux_rows(linux_fixture_root("debian-bookworm"), leg_acc) == rows);
    CHECK_FALSE(leg_acc.any_failure());
    CHECK_FALSE(leg_acc.incomplete());
}

TEST_CASE("apt_rows_at over the real ubuntu:22.04 tree: one-line rows + binary keyring",
          "[update_source_trust][walk][apt]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(linux_fixture_root("ubuntu-2204"), acc);
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
    CHECK(fresh_linux_rows(linux_fixture_root("ubuntu-2204"), leg_acc) == rows);
    CHECK_FALSE(leg_acc.any_failure());
}

TEST_CASE("an empty root is absent for every family: zero rows, no failure token",
          "[update_source_trust][walk]") {
    const TempRoot root;
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(fresh_linux_rows(root.path, acc).empty());
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
    auto fut = std::async(std::launch::async, [&] { rows = fresh_apt_rows(root.path, acc); });
    if (fut.wait_for(std::chrono::seconds(20)) != std::future_status::ready) {
        // Release the blocked open() so the worker (and this process) can exit.
        const yuzu::agent::ScopedFd rel(
            ::open((root.apt() / "sources.list").c_str(), O_RDWR | O_NONBLOCK));
        fut.wait();
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
    const auto rows = fresh_apt_rows(root.path, acc);
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
    const auto rows = fresh_apt_rows(root.path, acc);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list|one_line|deb|http://ok.example/|suite|main|-|"
                     "unset|unset|yes");
    CHECK(rows[1] == "apt_source|/etc/apt/sources.list.d/bad.sources|deb822|deb|http://ok.example/|s|"
                     "-|-|unset|unset|yes");
    // MUTATION: deleting the unparsed_entry note_failure in add_apt_file leaves
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
    CHECK(fresh_apt_rows(root.path, acc).empty());
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
    CHECK(fresh_apt_rows(root.path, acc).empty()); // empty files: no sources
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
    const auto rows = fresh_apt_rows(root.path, acc);
    // MUTATIONS: no budget -> 3 rows and no token; a budget that does not trim ->
    // 3 rows; a budget that does not stop the walk -> the `oversized` token below.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].find("/etc/apt/sources.list.d/a.list") != std::string::npos);
    CHECK(rows[1].find("/etc/apt/sources.list.d/b.list") != std::string::npos);
    CHECK(reason_has(acc, "linux:apt_sources:output_cap"));
    CHECK_FALSE(reason_has(acc, "oversized"));
    CHECK(acc.incomplete());
}

TEST_CASE("sources are the files apt itself reads; keyrings are selected by suffix, never by name",
          "[update_source_trust][walk][apt]") {
    const TempRoot root;
    const std::string src = "deb http://x.example/ y main\n";
    const std::string deb822 = "Types: deb\nURIs: http://y.example/\nSuites: z\n";
    // sources.list.d: names apt reads (`ok`, and `a:b` because ':' is legal) versus names
    // it skips (hidden, space, '+', '~', non-ASCII), in BOTH formats (verified on apt 3.0.3).
    for (const char* name : {"ok.list", "a:b.list", ".hidden.list", "my repo.list", "plus+.list",
                             "tilde~.list", "caf\xc3\xa9.list", "notes.txt"})
        root.write(std::string("etc/apt/sources.list.d/") + name, src);
    for (const char* name : {"ok.sources", ".hidden.sources", "my repo.sources", "plus+.sources"})
        root.write(std::string("etc/apt/sources.list.d/") + name, deb822);
    // trusted.gpg.d: apt before 3.0 trusts a key under ANY name ending .gpg/.asc
    // (verified against real signed repos on apt 2.0-2.8), so nothing is filtered by name.
    for (const char* name : {"good.gpg", ".hid.gpg", "b ad.gpg", "we+ird.asc"})
        root.write(std::string("etc/apt/trusted.gpg.d/") + name, "\x99\x01");
    root.write("etc/apt/keyrings/any name.txt", "text");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    // MUTATION: suffix-only source selection reports the seven phantom sources; a name
    // filter on trusted.gpg.d hides three global trust anchors; a filter without ':' hides a:b.
    REQUIRE(rows.size() == 8);
    CHECK(rows[0].find("/etc/apt/sources.list.d/a:b.list|") != std::string::npos);
    CHECK(rows[1].find("/etc/apt/sources.list.d/ok.list|") != std::string::npos);
    CHECK(rows[2].find("/etc/apt/sources.list.d/ok.sources|") != std::string::npos);
    CHECK(rows[3] == "apt_keyring|/etc/apt/trusted.gpg.d/.hid.gpg|trusted_gpg_d|binary|2");
    CHECK(rows[4] == "apt_keyring|/etc/apt/trusted.gpg.d/b ad.gpg|trusted_gpg_d|binary|2");
    CHECK(rows[5] == "apt_keyring|/etc/apt/trusted.gpg.d/good.gpg|trusted_gpg_d|binary|2");
    CHECK(rows[6] == "apt_keyring|/etc/apt/trusted.gpg.d/we+ird.asc|trusted_gpg_d|binary|2");
    CHECK(rows[7] == "apt_keyring|/etc/apt/keyrings/any name.txt|etc_apt_keyrings|unmodelled|4");
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("the legacy /etc/apt/trusted.gpg is a keyring row",
          "[update_source_trust][walk][apt]") {
    const TempRoot root;
    root.write("etc/apt/trusted.gpg", "\x99\x01\x0d");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    // MUTATION: dropping the legacy read (or its scope name) leaves no row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "apt_keyring|/etc/apt/trusted.gpg|legacy_trusted_gpg|binary|3");
}

TEST_CASE("a symlinked directory is refused, not followed",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("real.d/x.list", "deb http://x.example/ y main\n");
    fs::create_directories(root.apt());
    fs::create_directory_symlink(root.path / "real.d", root.apt() / "sources.list.d");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    // MUTATION: removing O_NOFOLLOW from the directory open follows the link and
    // reports x.list. The token differs by OS (ENOTDIR vs ELOOP); both are refusals.
    CHECK(rows.empty());
    CHECK((reason_has(acc, "linux:apt_sources:not_a_directory") ||
           reason_has(acc, "linux:apt_sources:symlink_refused")));
}

TEST_CASE("NUL and invalid UTF-8 in a sources file are replaced and reported, the row keeps its shape",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/sources.list",
               std::string("deb [trusted=yes] http://a.example/x stable ma\0in universe\n",
                           sizeof("deb [trusted=yes] http://a.example/x stable ma\0in universe\n") - 1));
    root.write("etc/apt/sources.list.d/b.list", "deb http://b.example/\xff stable main\n");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    REQUIRE(rows.size() == 2);
    for (const auto& r : rows) {
        CHECK(r.find('\0') == std::string::npos);
        CHECK(split_wire(r).size() == 11); // MUTATION: an unscrubbed NUL cuts the row at strlen
    }
    const auto first = split_wire(rows[0]);
    CHECK(first[6] == "ma?in universe");
    CHECK(first[8] == "yes"); // the trust column behind the NUL survives
    CHECK(reason_has(acc, "linux:apt_sources:invalid_bytes"));
    CHECK(acc.incomplete());
}

TEST_CASE("a file rewritten while it is read is modified_during_read, never a clean (maybe empty) read",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/sources.list", "deb http://ok.example/ suite main\n");
    const auto path = root.apt() / "sources.list";
    yuzu::shared::ConstraintAccumulator acc;
    std::string data;
    std::uint64_t size = 0;
    // The hook is an in-place writer: it truncates the file after the bytes were
    // read and before the closing fstat. MUTATION: dropping the closing fstat
    // comparison returns ok with the pre-truncate text, an empty sources.list
    // being normal on a host with no apt sources.
    pio::InputBudget budget;
    const auto rc = pio::read_file(path, pio::kMaxFileBytes, false, data, size, acc,
                                   "linux:apt_sources", budget, {},
                                   [&] { std::ofstream(path, std::ios::binary | std::ios::trunc); });
    CHECK(rc == pio::Outcome::failed);
    CHECK(reason_has(acc, "linux:apt_sources:modified_during_read"));
    CHECK(acc.incomplete());
}

TEST_CASE("the output budget trims to fit: many small rows from one file, not just the last",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    std::string text;
    for (int i = 0; i < 20000; ++i) // ~1.5 MB of rows from ~300 KB of text
        text += "deb http://a b\n";
    root.write("etc/apt/sources.list", text);
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    std::size_t total = 0;
    for (const auto& r : rows)
        total += r.size() + 1;
    // MUTATION: trimming a single row (`while` -> `if`) leaves the total over budget.
    CHECK(total <= pio::kMaxOutputBytes);
    CHECK(total + 200 > pio::kMaxOutputBytes); // trimmed to just fit, not emptied
    CHECK(rows.size() < 20000);
    CHECK(reason_has(acc, "linux:apt_sources:output_cap"));
}

TEST_CASE("invalid_bytes names a replaced byte that reached a field, not bytes in comments or ignored fields",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    // A legacy-encoded comment and an unsurfaced deb822 field: nothing reaches the wire.
    root.write("etc/apt/sources.list", "# Miroir fran\xe7" "ais\ndeb http://ok.example/ s main\n");
    root.write("etc/apt/sources.list.d/x.sources",
               std::string("Types: deb\nURIs: http://y.example/\nSuites: z\nX-Repolib-Name: caf\xe9\n"));
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    CHECK(rows.size() == 2);
    // MUTATION: scrubbing the whole file (or counting every replaced byte) makes every
    // legacy-encoded comment a constrained result on a healthy host.
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("a keyring name with invalid bytes is invalid_bytes under the keyring source",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    const std::string name = "k\xff" "y.gpg";
    fs::create_directories(root.apt() / "keyrings");
    {
        std::ofstream f(root.apt() / "keyrings" / name, std::ios::binary);
        f << "\x99\x01";
        if (!f)
            SKIP("this filesystem refuses a non-UTF-8 file name (APFS)");
    }
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = fresh_apt_rows(root.path, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("k?y.gpg") != std::string::npos);
    CHECK(reason_has(acc, "linux:apt_keyring:invalid_bytes")); // MUTATION: dropping it, or the wrong prefix
}

TEST_CASE("a same-size rewrite is caught by the mtime, and a just-emptied text file is not a clean empty read",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    const std::string body = "deb http://ok.example/ suite main\n";
    root.write("etc/apt/sources.list", body);
    const auto path = root.apt() / "sources.list";
    const auto orig = fs::last_write_time(path);
    yuzu::shared::ConstraintAccumulator acc;
    std::string data;
    std::uint64_t size = 0;
    // The hook rewrites the SAME bytes (the size is unchanged) and moves the mtime, the
    // real shape of an in-place writer. MUTATION: comparing sizes only misses it.
    pio::InputBudget budget;
    auto rc = pio::read_file(path, pio::kMaxFileBytes, false, data, size, acc, "linux:apt_sources", budget, {}, [&] {
        { std::ofstream f(path, std::ios::binary | std::ios::trunc); f << body; }
        fs::last_write_time(path, orig + std::chrono::milliseconds(1500));
    });
    CHECK(rc == pio::Outcome::failed);
    CHECK(reason_has(acc, "linux:apt_sources:modified_during_read"));

    // An empty text file touched within the last two seconds may be mid-rewrite (the
    // truncate bumped its mtime); one that has been empty for longer is genuinely empty.
    // MUTATION: dropping the guard reads the fresh empty file as `ok`.
    root.write("etc/apt/empty.list", "");
    const auto empty = root.apt() / "empty.list";
    yuzu::shared::ConstraintAccumulator fresh;
    CHECK(pio::read_file(empty, pio::kMaxFileBytes, false, data, size, fresh, "linux:apt_sources", budget) ==
          pio::Outcome::failed);
    CHECK(reason_has(fresh, "linux:apt_sources:modified_during_read"));
    fs::last_write_time(empty, fs::file_time_type::clock::now() - std::chrono::hours(1));
    yuzu::shared::ConstraintAccumulator old;
    CHECK(pio::read_file(empty, pio::kMaxFileBytes, false, data, size, old, "linux:apt_sources", budget) ==
          pio::Outcome::ok);
    CHECK_FALSE(old.any_failure());
}

TEST_CASE("an unreadable file is constrained with permission_denied, never absent",
          "[update_source_trust][walk][fault]") {
    const TempRoot root;
    root.write("etc/apt/sources.list", "deb http://x.example/ y main\n");
    std::error_code ec;
    fs::permissions(root.apt() / "sources.list", fs::perms::none, fs::perm_options::replace, ec);
    REQUIRE_FALSE(ec);
    if (const yuzu::agent::ScopedFd probe(::open((root.apt() / "sources.list").c_str(), O_RDONLY));
        probe.valid()) {
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    }
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(fresh_apt_rows(root.path, acc).empty());
    // MUTATION: mapping EACCES to `absent` drops this token.
    CHECK(reason_has(acc, "linux:apt_sources:permission_denied"));
    CHECK(acc.incomplete());
}

#endif // !defined(_WIN32)
