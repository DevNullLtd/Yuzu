/**
 * test_update_source_trust_ini.cpp -- DEDICATED tests for parse_ini, the private
 * INI grammar update_source_trust uses for yum/dnf .repo files
 * (update_source_trust_parsers.hpp). Its own TU on purpose: there is no reusable
 * INI parser library in the tree, so the grammar's edge cases (CRLF, comments,
 * continuation lines, malformed headers) are pinned here, not folded into the
 * apt/plist tests as an afterthought.
 *
 * Builds and runs on every OS; nothing here touches the filesystem. The inputs
 * are RECONSTRUCTIONS of the grammar rules documented on parse_ini (the real
 * rockylinux:9 .repo capture is exercised, through the walk, in P1d-2's tree
 * suite); each case names the rule it pins.
 */
#include <catch2/catch_test_macros.hpp>

#include "update_source_trust_parsers.hpp"

#include <string>

using yuzu::update_source_trust::IniDocument;
using yuzu::update_source_trust::parse_ini;

TEST_CASE("parse_ini: sections, keys and last-occurrence lookup", "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[baseos]\n"
                                      "name=Rocky Linux $releasever - BaseOS\n"
                                      "baseurl=http://mirror.example/pub/baseos/\n"
                                      "gpgcheck=1\n"
                                      "\n"
                                      "[appstream]\n"
                                      "name=AppStream\n"
                                      "enabled=0\n");
    REQUIRE(doc.sections.size() == 2);
    CHECK(doc.malformed_lines == 0);
    CHECK(doc.sections[0].name == "baseos");
    CHECK(doc.sections[0].get("name") == "Rocky Linux $releasever - BaseOS");
    CHECK(doc.sections[0].get("gpgcheck") == "1");
    CHECK(doc.sections[1].name == "appstream");
    CHECK(doc.sections[1].get("enabled") == "0");
    CHECK_FALSE(doc.sections[1].get("gpgcheck").has_value()); // absent, not "0"
}

TEST_CASE("parse_ini: CRLF line endings and surrounding whitespace", "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\r\nk=v\r\n  \r\nj = w \r\n[b]\r\nz=1\r\n");
    REQUIRE(doc.sections.size() == 2);
    CHECK(doc.malformed_lines == 0);
    CHECK(doc.sections[0].get("k") == "v"); // no trailing '\r'
    CHECK(doc.sections[0].get("j") == "w"); // key and value both trimmed
    CHECK(doc.sections[1].get("z") == "1");
}

TEST_CASE("parse_ini: '#' and ';' comments, including indented ones, are skipped",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("# top comment\n"
                                      "; another\n"
                                      "[a]\n"
                                      "# c1\n"
                                      "k=v\n"
                                      "   # indented comment does not end or extend k\n"
                                      "; c2\n"
                                      "j=w\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.malformed_lines == 0);
    REQUIRE(doc.sections[0].entries.size() == 2);
    CHECK(doc.sections[0].get("k") == "v");
    CHECK(doc.sections[0].get("j") == "w");
}

TEST_CASE("parse_ini: a comment marker inside a value is data (no inline comments)",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\nk=v # kept\nu=http://h/p#frag\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.sections[0].get("k") == "v # kept");
    CHECK(doc.sections[0].get("u") == "http://h/p#frag");
}

TEST_CASE("parse_ini: a leading UTF-8 BOM is ignored", "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("\xEF\xBB\xBF[a]\nk=v\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.malformed_lines == 0);
    CHECK(doc.sections[0].name == "a");
    CHECK(doc.sections[0].get("k") == "v");
}

TEST_CASE("parse_ini: indented lines continue the previous value (multi-URL form)",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\n"
                                      "baseurl=http://one.example/x\n"
                                      "    http://two.example/x\n"
                                      "\thttp://three.example/x\n"
                                      "gpgcheck=1\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.malformed_lines == 0);
    CHECK(doc.sections[0].get("baseurl") ==
          "http://one.example/x http://two.example/x http://three.example/x");
    CHECK(doc.sections[0].get("gpgcheck") == "1"); // the next key is not swallowed
}

TEST_CASE("parse_ini: a blank line ends a continuation; an orphan indented line is malformed",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\nk=v\n\n   orphan\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.sections[0].get("k") == "v"); // orphan not appended
    CHECK(doc.malformed_lines == 1);
}

TEST_CASE("parse_ini: a key before any section is malformed, not attributed",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("stray=1\n[a]\nk=v\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.malformed_lines == 1);
    CHECK(doc.sections[0].entries.size() == 1);
    CHECK(doc.sections[0].get("stray") == std::nullopt);
}

TEST_CASE("parse_ini: a header without ']' drops its keys instead of leaking them upward",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\nk=v\n[broken\nx=1\ny=2\n[b]\nz=3\n");
    REQUIRE(doc.sections.size() == 2);
    CHECK(doc.malformed_lines == 1);
    CHECK(doc.sections[0].name == "a");
    CHECK(doc.sections[0].entries.size() == 1); // x and y did NOT land in [a]
    CHECK(doc.sections[0].get("x") == std::nullopt);
    CHECK(doc.sections[1].name == "b");
    CHECK(doc.sections[1].get("z") == "3"); // parsing recovers at the next valid header
}

TEST_CASE("parse_ini: empty section name and empty key are malformed", "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\n=novalue\nk=v\n[]\nlost=1\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.malformed_lines == 2);
    CHECK(doc.sections[0].entries.size() == 1);
    CHECK(doc.sections[0].get("k") == "v");
}

TEST_CASE("parse_ini: duplicate keys keep every entry and the LAST one wins",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\ngpgcheck=0\ngpgcheck=1\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.sections[0].entries.size() == 2);
    CHECK(doc.sections[0].get("gpgcheck") == "1");
}

TEST_CASE("parse_ini: split at the first '=', empty values allowed, ':' is not a delimiter",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[a]\n"
                                      "url=http://h/?a=b&c=d\n"
                                      "empty=\n"
                                      "colon: not a key\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.sections[0].get("url") == "http://h/?a=b&c=d");
    REQUIRE(doc.sections[0].get("empty").has_value());
    CHECK(doc.sections[0].get("empty")->empty());
    CHECK(doc.malformed_lines == 1); // "colon: not a key" has no '='
}

TEST_CASE("parse_ini: keys are case-sensitive; section names are trimmed and trailing junk ignored",
          "[update_source_trust][ini]") {
    const IniDocument doc = parse_ini("[ my repo ] trailing junk\nGPGCHECK=1\n");
    REQUIRE(doc.sections.size() == 1);
    CHECK(doc.sections[0].name == "my repo");
    CHECK(doc.sections[0].get("gpgcheck") == std::nullopt);
    CHECK(doc.sections[0].get("GPGCHECK") == "1");
    CHECK(doc.malformed_lines == 0);
}

TEST_CASE("parse_ini: empty input and a final line without a newline", "[update_source_trust][ini]") {
    const IniDocument empty = parse_ini("");
    CHECK(empty.sections.empty());
    CHECK(empty.malformed_lines == 0);

    const IniDocument no_nl = parse_ini("[a]\nk=v");
    REQUIRE(no_nl.sections.size() == 1);
    CHECK(no_nl.sections[0].get("k") == "v");
}
