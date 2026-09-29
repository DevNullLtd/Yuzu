/**
 * test_services_macos.cpp -- fixture-driven vectors for the macOS services
 * leg's pure `launchctl print-disabled` parser (services_macos_launchd.hpp,
 * C-1.12, P8/P15).
 *
 * Everything here runs against captured/synthetic launchctl text -- no
 * `launchctl` subprocess, no real launchd domain -- because the parser is
 * pure by design (same header-for-testability pattern as
 * installed_apps_inventory.hpp). Pins the P15 honesty contract: a label with
 * no explicit override in the map must resolve to "unknown", never a
 * fabricated "automatic"/"disabled" guess.
 */

#include <catch2/catch_test_macros.hpp>

#include <services_macos_launchd.hpp>

#include <string>

using namespace yuzu::services_macos;

// ── parse_print_disabled ──────────────────────────────────────────────────

TEST_CASE("parse_print_disabled parses a realistic launchctl print-disabled block",
          "[services][macos]") {
    // Live-verified token spelling (see the header): the literal words
    // "enabled"/"disabled", tab-indented, inside a braces block.
    const std::string output = "disabled services = {\n"
                                "\t\"com.apple.foo\" => disabled\n"
                                "\t\"com.apple.bar\" => enabled\n"
                                "}\n";

    const DisabledMap map = parse_print_disabled(output);

    REQUIRE(map.size() == 2);
    CHECK(map.at("com.apple.foo") == true);
    CHECK(map.at("com.apple.bar") == false);
}

TEST_CASE("parse_print_disabled tolerates CRLF line endings", "[services][macos]") {
    const std::string output = "disabled services = {\r\n"
                                "\t\"com.apple.foo\" => disabled\r\n"
                                "\t\"com.apple.bar\" => enabled\r\n"
                                "}\r\n";

    const DisabledMap map = parse_print_disabled(output);

    REQUIRE(map.size() == 2);
    CHECK(map.at("com.apple.foo") == true);
    CHECK(map.at("com.apple.bar") == false);
}

TEST_CASE("parse_print_disabled rejects exact-token mismatches, not prefix matches",
          "[services][macos]") {
    // "enabled-junk" must NOT be accepted as "enabled" -- the parser trims
    // whitespace but still requires an exact token match.
    const std::string output = "\t\"com.apple.junk\" => enabled-junk\n";

    const DisabledMap map = parse_print_disabled(output);

    CHECK(map.empty());
}

TEST_CASE("parse_print_disabled drops labels that fail is_safe_launchd_label",
          "[services][macos]") {
    // A label containing characters outside [A-Za-z0-9._@-] must never reach
    // the map, however well-formed the enabled/disabled token is -- it's the
    // proxy for "never trust an unsanitized value into pipe-delimited plugin
    // output."
    const std::string output = "\t\"com.apple.ok\" => disabled\n"
                                "\t\"unsafe label; rm -rf\" => enabled\n";

    const DisabledMap map = parse_print_disabled(output);

    REQUIRE(map.size() == 1);
    CHECK(map.count("com.apple.ok") == 1);
    CHECK(map.count("unsafe label; rm -rf") == 0);
}

TEST_CASE("parse_print_disabled on empty/garbled input yields an empty map, never a crash",
          "[services][macos]") {
    CHECK(parse_print_disabled("").empty());
    CHECK(parse_print_disabled("not launchctl output at all\nrandom garbage\n").empty());
    CHECK(parse_print_disabled("disabled services = {\n}\n").empty());
}

TEST_CASE("is_safe_launchd_label boundary cases", "[services][macos]") {
    CHECK(is_safe_launchd_label("com.apple.foo") == true);
    CHECK(is_safe_launchd_label("com.apple-foo_bar@baz") == true);
    CHECK(is_safe_launchd_label("") == false);
    CHECK(is_safe_launchd_label("has space") == false);
    CHECK(is_safe_launchd_label("has;semicolon") == false);
    CHECK(is_safe_launchd_label(std::string(257, 'a')) == false); // over the 256 cap
}

// ── startup_type_for ──────────────────────────────────────────────────────

TEST_CASE("startup_type_for joins a label against the disabled map honestly",
          "[services][macos]") {
    DisabledMap map;
    map["com.apple.foo"] = true;  // disabled
    map["com.apple.bar"] = false; // explicitly enabled

    CHECK(startup_type_for(map, "com.apple.foo") == "disabled");
    CHECK(startup_type_for(map, "com.apple.bar") == "automatic");
    // No entry in the map at all -- honestly "unknown", never defaulted.
    CHECK(startup_type_for(map, "com.apple.baz") == "unknown");
}

TEST_CASE("startup_type_for never looks up an unsafe label", "[services][macos]") {
    DisabledMap map;
    // Even if a malicious/malformed value somehow ended up as a map key,
    // startup_type_for must still refuse to use it as a lookup key.
    map["unsafe label"] = true;

    CHECK(startup_type_for(map, "unsafe label") == "unknown");
}

TEST_CASE("startup_type_for on an empty map is always unknown", "[services][macos]") {
    const DisabledMap empty_map;
    CHECK(startup_type_for(empty_map, "com.apple.anything") == "unknown");
}
