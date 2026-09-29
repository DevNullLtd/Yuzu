/**
 * test_antivirus_parsers.cpp — pure antivirus parse/render helpers
 * (antivirus_parsers.hpp).
 *
 * The subprocess/WMI/registry acquisition is the impure shell; the
 * decision-shaped parsing of PlistBuddy version output, `systemextensionsctl
 * list`, the Windows Security Center productState bit layout, and the WMI
 * row / registry value-name to output-line mapping are all header-pure and
 * pinned here on every host (the licensing_parsers.hpp pattern) — including
 * the Windows-only legs, since none of these functions touch WMI/COM/the
 * registry directly; they take plain synthetic maps/vectors. Fixture
 * strings marked "real capture" were taken verbatim from a macOS 26 host;
 * older macOS releases are not yet fixture-verified — capture and add when
 * such hardware is available.
 */

#include "antivirus_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <vector>

using namespace yuzu::antivirus;

TEST_CASE("plist version: real captures parse verbatim", "[antivirus]") {
    CHECK(parse_plist_version("5351") == "5351");   // XProtect.bundle (real capture)
    CHECK(parse_plist_version("157") == "157");     // XProtect.app Remediator (real capture)
    CHECK(parse_plist_version("1.93") == "1.93");   // MRT.app (real capture)
    CHECK(parse_plist_version("5351\n") == "5351"); // pre-strip newline tolerated
}

TEST_CASE("plist version: error prose and garbage are rejected", "[antivirus]") {
    CHECK(parse_plist_version("").empty());
    CHECK(parse_plist_version(
              R"(Print: Entry, ":CFBundleShortVersionString", Does Not Exist)")
              .empty());
    CHECK(parse_plist_version("File Doesn't Exist, Will Create: /nope").empty());
    CHECK(parse_plist_version("sh: /usr/libexec/PlistBuddy: No such file or directory").empty());
}

// Real capture, this Mac (Tailscale network extension; note the literal tabs).
static constexpr const char* kRealSysextList =
    "1 extension(s)\n"
    "--- com.apple.system_extension.network_extension (Go to 'System Settings > General > "
    "Login Items & Extensions > Network Extensions' to modify these system extension(s))\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.98.5/101.98.5)\tTailscale "
    "Network Extension\t[activated enabled]\n";

TEST_CASE("sysext: real capture parses fully", "[antivirus]") {
    auto exts = parse_sysext_list(kRealSysextList);
    REQUIRE(exts.size() == 1);
    const auto& e = exts[0];
    CHECK(e.category == "network_extension");
    CHECK(e.team_id == "W5364U7YZB");
    CHECK(e.bundle_id == "io.tailscale.ipn.macsys.network-extension");
    CHECK(e.version == "1.98.5/101.98.5");
    CHECK(e.name == "Tailscale Network Extension");
    CHECK(e.state == "activated enabled");
    CHECK(e.enabled);
    CHECK(e.active);
    CHECK_FALSE(is_endpoint_security(e));
}

// Synthetic but format-faithful endpoint-security section (EDR shape).
static constexpr const char* kEdrSysextList =
    "2 extension(s)\n"
    "--- com.apple.system_extension.endpoint_security\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "*\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent (7.16.0/507.16.0)\tCrowdStrike Falcon\t"
    "[activated enabled]\n"
    "\t\t2107VB2A4L\tcom.sophos.endpoint.scanextension (10.7.8/1)\tSophos Scan Extension\t"
    "[activated waiting for user]\n";

TEST_CASE("sysext: endpoint-security section, enabled and pending rows", "[antivirus]") {
    auto exts = parse_sysext_list(kEdrSysextList);
    REQUIRE(exts.size() == 2);

    CHECK(is_endpoint_security(exts[0]));
    CHECK(exts[0].bundle_id == "com.crowdstrike.falcon.Agent");
    CHECK(exts[0].version == "7.16.0/507.16.0");
    CHECK(exts[0].name == "CrowdStrike Falcon");
    CHECK(sysext_av_state(exts[0]) == "active");

    // Not enabled/active (empty leading cells) → present but not protecting.
    CHECK(is_endpoint_security(exts[1]));
    CHECK_FALSE(exts[1].enabled);
    CHECK_FALSE(exts[1].active);
    CHECK(exts[1].state == "activated waiting for user");
    CHECK(sysext_av_state(exts[1]) == "installed");
}

TEST_CASE("sysext: empty, none, and garbage inputs yield no rows", "[antivirus]") {
    CHECK(parse_sysext_list("").empty());
    CHECK(parse_sysext_list("0 extension(s)\n").empty());
    CHECK(parse_sysext_list("sh: systemextensionsctl: command not found").empty());
}

TEST_CASE("sysext: malformed rows are skipped without throwing", "[antivirus]") {
    // Too few columns, header-only, stray tabs — none may produce a row.
    auto exts = parse_sysext_list("--- com.apple.system_extension.endpoint_security\n"
                                  "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
                                  "*\t*\tonly-three-cols\n"
                                  "\t\n");
    CHECK(exts.empty());
    // A bundle column without a version parenthesis keeps the whole token.
    auto no_ver = parse_sysext_list("--- com.apple.system_extension.endpoint_security\n"
                                    "*\t\tTEAM\tcom.vendor.thing\tVendor Thing\t[activated]\n");
    REQUIRE(no_ver.size() == 1);
    CHECK(no_ver[0].bundle_id == "com.vendor.thing");
    CHECK(no_ver[0].version.empty());
    CHECK(sysext_av_state(no_ver[0]) == "installed"); // enabled but not active
}

TEST_CASE("sanitize_field: neutralises pipe/CR/LF that would shift wire-format fields",
          "[antivirus]") {
    CHECK(sanitize_field("normal name") == "normal name");
    CHECK(sanitize_field("evil|injected") == "evil injected");
    CHECK(sanitize_field("evil\r\ninjected") == "evil  injected");
    CHECK(sanitize_field("") == "");
}

TEST_CASE("contains_insensitive: dedupe helper", "[antivirus]") {
    CHECK(contains_insensitive("CrowdStrike Falcon", "falcon"));
    CHECK(contains_insensitive("com.crowdstrike.falcon.Agent", "CROWDSTRIKE"));
    CHECK_FALSE(contains_insensitive("Sophos Scan Extension", "falcon"));
    CHECK(contains_insensitive("anything", ""));
    CHECK_FALSE(contains_insensitive("", "x"));
}

// ── decode_wsc_product_state ────────────────────────────────────────────────

TEST_CASE("decode_wsc_product_state: enabled + current definitions", "[antivirus]") {
    // mid byte 0x10 (on), low byte 0x00 (current).
    const auto d = decode_wsc_product_state(0x001000);
    CHECK(d.enabled);
    CHECK_FALSE(d.snoozed);
    CHECK(d.definitions_up_to_date);
}

TEST_CASE("decode_wsc_product_state: enabled + stale definitions", "[antivirus]") {
    // mid byte 0x10 (on), low byte 0x01 (nonzero -> stale).
    const auto d = decode_wsc_product_state(0x001001);
    CHECK(d.enabled);
    CHECK_FALSE(d.snoozed);
    CHECK_FALSE(d.definitions_up_to_date);
}

TEST_CASE("decode_wsc_product_state: disabled", "[antivirus]") {
    // mid byte 0x00 (off), low byte 0x00.
    const auto d = decode_wsc_product_state(0x000000);
    CHECK_FALSE(d.enabled);
    CHECK_FALSE(d.snoozed);
    CHECK(d.definitions_up_to_date);
}

TEST_CASE("decode_wsc_product_state: enabled but snoozed", "[antivirus]") {
    // mid byte 0x11 (on, snoozed), low byte 0x00.
    const auto d = decode_wsc_product_state(0x001100);
    CHECK(d.enabled);
    CHECK(d.snoozed);
    CHECK(d.definitions_up_to_date);
}

TEST_CASE("decode_wsc_product_state: high byte (product-type code) is ignored", "[antivirus]") {
    // Same mid/low bytes as the first case, arbitrary high byte -- must not
    // change the decode.
    const auto d = decode_wsc_product_state(0x391000);
    CHECK(d.enabled);
    CHECK(d.definitions_up_to_date);
}

// ── render_wsc_product_line / render_wsc_products ───────────────────────────

TEST_CASE("render_wsc_product_line: enabled and current", "[antivirus]") {
    std::map<std::string, std::string> row{{"displayName", "Windows Defender"},
                                           {"productState", "397568"}}; // 0x061100
    CHECK(render_wsc_product_line(row) == "av|Windows Defender|snoozed|current");
}

TEST_CASE("render_wsc_product_line: missing displayName renders unknown, not blank",
          "[antivirus]") {
    std::map<std::string, std::string> row{{"productState", "266240"}}; // 0x041000
    CHECK(render_wsc_product_line(row) == "av|unknown|enabled|current");
}

TEST_CASE("render_wsc_product_line: missing productState is honest, not guessed", "[antivirus]") {
    std::map<std::string, std::string> row{{"displayName", "Some AV"}};
    CHECK(render_wsc_product_line(row) == "av|Some AV|unknown|unknown");
}

TEST_CASE("render_wsc_product_line: non-numeric productState is honest, not guessed",
          "[antivirus]") {
    std::map<std::string, std::string> row{{"displayName", "Some AV"},
                                           {"productState", "not-a-number"}};
    CHECK(render_wsc_product_line(row) == "av|Some AV|unknown|unknown");
}

TEST_CASE("render_wsc_product_line: name containing '|' is sanitized", "[antivirus]") {
    std::map<std::string, std::string> row{{"displayName", "Evil|AV"}, {"productState", "0"}};
    CHECK(render_wsc_product_line(row) == "av|Evil AV|disabled|current");
}

TEST_CASE("render_wsc_products: maps every row, empty input yields empty output",
          "[antivirus]") {
    CHECK(render_wsc_products({}).empty());

    std::vector<std::map<std::string, std::string>> rows{
        {{"displayName", "A"}, {"productState", "266240"}},  // 0x041000, enabled/current
        {{"displayName", "B"}, {"productState", "262144"}}}; // 0x040000, disabled/current
    auto lines = render_wsc_products(rows);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "av|A|enabled|current");
    CHECK(lines[1] == "av|B|disabled|current");
}

// ── render_defender_status ──────────────────────────────────────────────────

TEST_CASE("render_defender_status: full row maps every key", "[antivirus]") {
    std::map<std::string, std::string> row{
        {"RealTimeProtectionEnabled", "True"},
        {"AntivirusSignatureVersion", "1.417.123.0"},
        {"AntivirusSignatureLastUpdated", "20260817120000.000000+000"},
        {"QuickScanEndTime", "20260816083000.000000+000"}};
    auto lines = render_defender_status(row);
    REQUIRE(lines.size() == 4);
    CHECK(lines[0] == "realtime_protection|enabled");
    CHECK(lines[1] == "definition_version|1.417.123.0");
    CHECK(lines[2] == "last_update|20260817120000.000000+000");
    CHECK(lines[3] == "last_quick_scan|20260816083000.000000+000");
}

TEST_CASE("render_defender_status: RealTimeProtectionEnabled false/0 both read disabled",
          "[antivirus]") {
    CHECK(render_defender_status({{"RealTimeProtectionEnabled", "False"}})[0] ==
          "realtime_protection|disabled");
    CHECK(render_defender_status({{"RealTimeProtectionEnabled", "0"}})[0] ==
          "realtime_protection|disabled");
    CHECK(render_defender_status({{"RealTimeProtectionEnabled", "1"}})[0] ==
          "realtime_protection|enabled");
}

TEST_CASE("render_defender_status: missing keys are omitted, not fabricated", "[antivirus]") {
    CHECK(render_defender_status({}).empty());
    auto lines = render_defender_status({{"AntivirusSignatureVersion", "1.0"}});
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == "definition_version|1.0");
}

// ── merge_exclusion_sources / render_exclusion_lines ────────────────────────

TEST_CASE("merge_exclusion_sources: local-only names are tagged local", "[antivirus]") {
    auto merged = merge_exclusion_sources({"C:\\Temp", "D:\\Data\\app.exe"}, {});
    REQUIRE(merged.size() == 2);
    CHECK(merged[0].source == "local");
    CHECK(merged[1].source == "local");
}

TEST_CASE("merge_exclusion_sources: policy-only names are tagged policy", "[antivirus]") {
    auto merged = merge_exclusion_sources({}, {"C:\\Program Files\\App"});
    REQUIRE(merged.size() == 1);
    CHECK(merged[0].value == "C:\\Program Files\\App");
    CHECK(merged[0].source == "policy");
}

TEST_CASE("merge_exclusion_sources: a name in both hives is reported once, tagged both",
          "[antivirus]") {
    auto merged = merge_exclusion_sources({"C:\\Temp"}, {"C:\\Temp"});
    REQUIRE(merged.size() == 1);
    CHECK(merged[0].value == "C:\\Temp");
    CHECK(merged[0].source == "both");
}

TEST_CASE("merge_exclusion_sources: empty inputs yield empty output", "[antivirus]") {
    CHECK(merge_exclusion_sources({}, {}).empty());
}

TEST_CASE("render_exclusion_lines: maps every entry with its kind and source", "[antivirus]") {
    auto lines = render_exclusion_lines(
        {{"C:\\Temp", "local"}, {"D:\\Data\\app.exe", "policy"}}, "path");
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "exclusion|path|local|C:\\Temp");
    CHECK(lines[1] == "exclusion|path|policy|D:\\Data\\app.exe");
}

TEST_CASE("render_exclusion_lines: empty input yields empty output", "[antivirus]") {
    CHECK(render_exclusion_lines({}, "process").empty());
}

TEST_CASE("render_exclusion_lines: a value name containing '|' is sanitized", "[antivirus]") {
    auto lines = render_exclusion_lines({{"evil|name.exe", "local"}}, "process");
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == "exclusion|process|local|evil name.exe");
}
