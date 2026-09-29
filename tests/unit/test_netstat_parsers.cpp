/**
 * test_netstat_parsers.cpp -- netstat_parsers.hpp's escape_pipes() (pure,
 * no I/O, no platform dependency -- portable and unguarded, runs on every
 * host).
 *
 * gate-2 (/adversarial-review) NICE finding: escape_pipes()'s CR/LF handling
 * was previously exercised only indirectly, through real process names in
 * test_netstat_attribution.cpp's macOS LocalDispatcher tests (which can
 * never force a process name containing a literal control character). This
 * file pins the '|'-escape and CR/LF-strip behavior directly, hoisted out of
 * netstat_plugin.cpp's former anonymous-namespace copy into
 * netstat_parsers.hpp so it is reachable from a test TU (same shape as
 * test_quarantine_parsers.cpp / test_discovery_parsers.cpp).
 */
#include "netstat_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::netstat;

TEST_CASE("escape_pipes: no special characters unchanged", "[agent][netstat_parsers]") {
    CHECK(escape_pipes("chrome") == "chrome");
    CHECK(escape_pipes("") == "");
}

TEST_CASE("escape_pipes: pipe escaped with a backslash", "[agent][netstat_parsers]") {
    CHECK(escape_pipes("a|b") == "a\\|b");
    CHECK(escape_pipes("|||") == "\\|\\|\\|");
}

TEST_CASE("escape_pipes: CR and LF replaced with underscore, not passed through or escaped",
         "[agent][netstat_parsers]") {
    // The adversarial-review gate-2 finding this test exists to pin: a
    // process name/path containing a raw '\n' would otherwise split one
    // attribution row into extra server-visible lines
    // (split_output_lines() trims a trailing '\r' but has no unescape for
    // either control character -- see netstat_parsers.hpp's escape_pipes
    // doc comment).
    CHECK(escape_pipes("evil\nname") == "evil_name");
    CHECK(escape_pipes("evil\rname") == "evil_name");
    CHECK(escape_pipes("evil\r\nname") == "evil__name");
    CHECK(escape_pipes("\n") == "_");
    CHECK(escape_pipes("\r") == "_");
}

TEST_CASE("escape_pipes: pipes and control characters combined in one field",
         "[agent][netstat_parsers]") {
    CHECK(escape_pipes("a|b\nc\rd|e") == "a\\|b_c_d\\|e");
}
