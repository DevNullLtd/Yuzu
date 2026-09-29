/**
 * test_wifi_parsers.cpp — pure wifi parse/format helpers (wifi_parsers.hpp,
 * PKG-WIFI).
 *
 * The bounded argv runner (nmcli/iw/iwlist/iwconfig/airport/
 * system_profiler) and the bounded sd-bus NetworkManager session are the
 * impure shells, both living in wifi_plugin.cpp; every parser/formatter
 * here is header-pure and pinned on every host regardless of platform or
 * libsystemd availability (the netprobe_stats.hpp / firewall_parsers.hpp
 * pattern).
 *
 * None of the fixtures below are a literal capture from a live host (no
 * Linux/NetworkManager/nmcli/iw host was available while writing this
 * package) -- they are hand-constructed but format-accurate, built from the
 * documented nmcli -t / iwconfig / airport -s / system_profiler column
 * layouts and the published NetworkManager D-Bus property types, the same
 * disclosure services_parsers.hpp's own fixtures carry.
 */

#include "wifi_parsers.hpp"

// wifi_parsers.hpp stays pure (wifi_tool_answered is a template over the
// result's own termination_reason type, so the header takes no runner
// dependency). The TEST pulls the real enum in deliberately, so a rename or
// a reordering of TerminationReason breaks here rather than silently
// re-tuning the honest-degradation decision against a local copy.
#include <yuzu/agent/subprocess_runner.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace yuzu::wifi;

// ── split_nmcli_terse_line / parse_nmcli_wifi_list ─────────────────────

TEST_CASE("wifi: split_nmcli_terse_line honours backslash-escaped colons", "[wifi]") {
    auto fields = split_nmcli_terse_line(R"(My\:Network:80:WPA2:6:AA\:BB\:CC\:DD\:EE\:FF)");
    REQUIRE(fields.size() == 5);
    CHECK(fields[0] == "My:Network"); // escaped colon unescaped, real separator kept
    CHECK(fields[1] == "80");
    CHECK(fields[2] == "WPA2");
    CHECK(fields[3] == "6");
    CHECK(fields[4] == "AA:BB:CC:DD:EE:FF"); // every colon here was escaped
}

TEST_CASE("wifi: split_nmcli_terse_line without any escapes matches a plain split", "[wifi]") {
    auto fields = split_nmcli_terse_line("MyWifi:80:WPA2:6:AA:BB:CC:DD:EE:FF");
    REQUIRE(fields.size() == 10);
    CHECK(fields[0] == "MyWifi");
    CHECK(fields[9] == "FF");
}

TEST_CASE("wifi: split_nmcli_terse_line keeps a trailing lone backslash literal", "[wifi]") {
    auto fields = split_nmcli_terse_line(R"(abc\)");
    REQUIRE(fields.size() == 1);
    CHECK(fields[0] == "abc\\");
}

TEST_CASE("wifi: parse_nmcli_wifi_list on empty input yields no rows", "[wifi]") {
    CHECK(parse_nmcli_wifi_list("").empty());
}

TEST_CASE("wifi: parse_nmcli_wifi_list — ordinary rows", "[wifi]") {
    // A real nmcli -t escapes ':' inside every field value, BSSID included
    // (its own colons would otherwise be misread as column separators).
    auto rows = parse_nmcli_wifi_list(
        R"(HomeNet:78:WPA2:6:AA\:BB\:CC\:DD\:EE\:FF)" "\n"
        R"(Guest:45:--:11:11\:22\:33\:44\:55\:66)" "\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "HomeNet");
    CHECK(rows[0].signal == "78");
    CHECK(rows[0].security == "WPA2");
    CHECK(rows[0].channel == "6");
    CHECK(rows[0].bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(rows[1].security == "--");
    CHECK(rows[1].bssid == "11:22:33:44:55:66");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — escaped-colon SSID stays intact", "[wifi]") {
    // A real nmcli -t escapes ':' inside a field value; an SSID literally
    // named "Coffee:Shop" is emitted as "Coffee\:Shop" in the SSID column.
    auto rows = parse_nmcli_wifi_list(R"(Coffee\:Shop:60:WPA2:1:AA\:BB\:CC\:DD\:EE\:FF)");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].ssid == "Coffee:Shop");
    CHECK(rows[0].signal == "60");
    CHECK(rows[0].security == "WPA2");
    CHECK(rows[0].bssid == "AA:BB:CC:DD:EE:FF");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — missing trailing fields default honestly", "[wifi]") {
    auto rows = parse_nmcli_wifi_list(":::::\n::::\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "<hidden>");
    CHECK(rows[0].security == "Open");
    CHECK(rows[0].signal == "0");
    CHECK(rows[0].channel == "0");
    CHECK(rows[0].bssid == "-");
    // A line short even of the trailing bssid column defaults the same way.
    CHECK(rows[1].bssid == "-");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — blank lines are skipped", "[wifi]") {
    auto rows = parse_nmcli_wifi_list("HomeNet:78:WPA2:6:AA\n\n\nGuest:45:Open:1:BB\n");
    CHECK(rows.size() == 2);
}

// ── parse_nmcli_wifi_list_active ────────────────────────────────────────
//
// Replaces the parse_nmcli_device_show tests. The command they covered
// (`nmcli ... device show` asking for WIFI.SSID etc.) does not exist:
// verified against live nmcli 1.52.1, it exits 2 with
//   Error: 'device show': invalid field 'WIFI.SSID'
// so that leg never produced a single row on any host. Those tests passed
// only because they fed the parser hand-written text nmcli would never emit
// -- a fixture that encodes a command's output must correspond to a command
// that actually accepts those fields.

TEST_CASE("wifi: parse_nmcli_wifi_list_active — picks the ACTIVE row", "[wifi]") {
    auto row = parse_nmcli_wifi_list_active(
        "no:Neighbour:44:WPA2:AA\\:BB\\:CC\\:DD\\:EE\\:01:wlan0\n"
        "yes:HomeNet:82:WPA2:AA\\:BB\\:CC\\:DD\\:EE\\:FF:wlan0\n"
        "no:Other:20:WPA3:AA\\:BB\\:CC\\:DD\\:EE\\:02:wlan0\n");
    REQUIRE(row.has_value());
    CHECK(row->ssid == "HomeNet");
    CHECK(row->signal == "82");
    CHECK(row->security == "WPA2");
    CHECK(row->bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(row->connection == "wlan0");
}

TEST_CASE("wifi: parse_nmcli_wifi_list_active — no active row means not connected", "[wifi]") {
    CHECK_FALSE(parse_nmcli_wifi_list_active("no:Neighbour:44:WPA2:AA:wlan0\n").has_value());
    CHECK_FALSE(parse_nmcli_wifi_list_active("").has_value());
}

// Regression guard: a line with FEWER than the six requested fields is a
// truncated read (nmcli killed mid-write, or the runner's line cap cutting
// the last line), not an observation. Completing it from defaults would
// fabricate an open access point in an operator's security audit -- this is
// exactly the class the truncation guard exists to stop.
TEST_CASE("wifi: parse_nmcli_wifi_list_active — a truncated line is dropped, never completed",
          "[wifi]") {
    CHECK_FALSE(parse_nmcli_wifi_list_active("yes::::\n").has_value());   // 5 fields
    CHECK_FALSE(parse_nmcli_wifi_list_active("yes:HomeNet\n").has_value()); // 2 fields
    CHECK_FALSE(parse_nmcli_wifi_list_active("yes\n").has_value());         // 1 field
}

// Same rule, list-scan side: parse_nmcli_wifi_list requests five fields.
TEST_CASE("wifi: parse_nmcli_wifi_list drops a truncated row instead of completing it",
          "[wifi]") {
    auto rows = parse_nmcli_wifi_list("HomeNet:78:WPA2\n"); // 3 of 5 fields
    CHECK(rows.empty());
}

TEST_CASE("wifi: parse_nmcli_wifi_list_active — IN-USE '*' glyph also selects", "[wifi]") {
    auto row = parse_nmcli_wifi_list_active("*:HomeNet:70:WPA2:AA:wlan0\n");
    REQUIRE(row.has_value());
    CHECK(row->ssid == "HomeNet");
}

TEST_CASE("wifi: parse_nmcli_wifi_list_active — missing optional fields default honestly",
          "[wifi]") {
    // All SIX requested fields present but empty -- distinct from a TRUNCATED
    // line (fewer than six fields), which is now rejected outright (see the
    // truncation-guard test below): a genuinely empty field is an
    // observation, a missing one is not.
    auto row = parse_nmcli_wifi_list_active("yes:::::\n");
    REQUIRE(row.has_value());
    CHECK(row->ssid == "<hidden>");
    CHECK(row->signal == "0");
    CHECK(row->security == "Open");
    CHECK(row->bssid == "-");
    CHECK(row->connection == "-");
}

// ── argv builders: the zero-shell invariant, pinned ─────────────────────
//
// The repo's lexical CI gate scans for raw spawn TOKENS, so a
// {"/bin/sh","-c",...} payload handed to the shared bounded runner passes it
// -- confirmed by injecting exactly that shape and watching the gate report
// clean. These assertions are the actual guard.

TEST_CASE("wifi: no argv vector invokes a command interpreter", "[wifi]") {
    CHECK_FALSE(argv_invokes_interpreter(nmcli_wifi_list_argv("/usr/bin/nmcli")));
    CHECK_FALSE(argv_invokes_interpreter(nmcli_connected_argv("/usr/bin/nmcli")));
    CHECK_FALSE(argv_invokes_interpreter(iw_dev_argv("/usr/sbin/iw")));
    CHECK_FALSE(argv_invokes_interpreter(iwlist_scan_argv("/usr/sbin/iwlist", "wlan0")));
    CHECK_FALSE(argv_invokes_interpreter(iwconfig_argv("/usr/sbin/iwconfig")));

    // The detector must actually detect -- otherwise the checks above are
    // vacuously true and the guard is theatre.
    CHECK(argv_invokes_interpreter({"/bin/sh", "-c", "nmcli device wifi list"}));
    CHECK(argv_invokes_interpreter({"/bin/bash", "-c", "iw dev"}));
    CHECK(argv_invokes_interpreter({"/usr/bin/env", "nmcli"}));
}

TEST_CASE("wifi: connected argv asks device wifi list, never the invalid device show fields",
          "[wifi]") {
    auto argv = nmcli_connected_argv("/usr/bin/nmcli");
    // The exact regression: `device show` rejects WIFI.* outright (live
    // nmcli 1.52.1, exit 2), which left this fallback dead on every host.
    REQUIRE(argv.size() >= 4);
    CHECK(argv[argv.size() - 2] == "wifi");
    CHECK(argv.back() == "list");
    for (const auto& a : argv)
        CHECK(a.find("WIFI.") == std::string::npos);
    CHECK(std::find(argv.begin(), argv.end(), "show") == argv.end());
    // ACTIVE must be requested or no row can ever be selected.
    bool has_active = false;
    for (const auto& a : argv)
        if (a.find("ACTIVE") != std::string::npos)
            has_active = true;
    CHECK(has_active);
}

// ADR-3002 Decision 6 is an explicit MUST: every migrated site handles option
// injection, by `--` where the tool supports it or by rejecting leading-`-`
// values. iwlist takes no `--`, so rejection is the mechanism and this is its
// regression guard. The iface is the ONLY non-literal element in any wifi argv.
TEST_CASE("wifi: iwlist argv rejects an interface name that could be read as a flag",
          "[wifi]") {
    CHECK(is_safe_iface_name("wlan0"));
    CHECK(is_safe_iface_name("wlp3s0"));
    CHECK(is_safe_iface_name("wlan0.100"));

    // A leading '-' is the whole point: iwlist would read these as options.
    CHECK_FALSE(is_safe_iface_name("-i"));
    CHECK_FALSE(is_safe_iface_name("--help"));
    // Shell/path metacharacters and whitespace have no place in an iface name.
    CHECK_FALSE(is_safe_iface_name("wlan0;reboot"));
    CHECK_FALSE(is_safe_iface_name("wlan0 scan"));
    CHECK_FALSE(is_safe_iface_name("../../etc/passwd"));
    CHECK_FALSE(is_safe_iface_name(""));
    // IFNAMSIZ-1 = 15.
    CHECK_FALSE(is_safe_iface_name("0123456789abcdef"));

    // A rejected name yields an EMPTY argv, which run_tool() treats as a
    // spawn_error -- so it degrades through the honest path rather than
    // scanning something unintended.
    CHECK(iwlist_scan_argv("/usr/sbin/iwlist", "-i").empty());
    CHECK(iwlist_scan_argv("/usr/sbin/iwlist", "wlan0;reboot").empty());
    CHECK_FALSE(iwlist_scan_argv("/usr/sbin/iwlist", "wlan0").empty());
}

TEST_CASE("wifi: iwlist scan argv carries the discovered interface", "[wifi]") {
    auto argv = iwlist_scan_argv("/usr/sbin/iwlist", "wlan1");
    REQUIRE(argv.size() == 3);
    CHECK(argv[0] == "/usr/sbin/iwlist");
    CHECK(argv[1] == "wlan1");
    CHECK(argv[2] == "scan");
}

// ── iw / iwlist / iwconfig text filtering ───────────────────────────────

TEST_CASE("wifi: parse_iw_dev_interfaces extracts the interface token", "[wifi]") {
    auto ifaces = parse_iw_dev_interfaces(
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 3\n"
        "\t\taddr aa:bb:cc:dd:ee:ff\n");
    REQUIRE(ifaces.size() == 1);
    CHECK(ifaces[0] == "wlan0");
}

TEST_CASE("wifi: parse_iw_dev_interfaces on output with no interfaces", "[wifi]") {
    CHECK(parse_iw_dev_interfaces("phy#0\n\t\tifindex 3\n").empty());
}

TEST_CASE("wifi: filter_iwlist_scan_lines keeps only ESSID/Quality/Encryption lines",
          "[wifi]") {
    auto out = filter_iwlist_scan_lines(
        "wlan0     Scan completed :\n"
        "          Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
        "                    ESSID:\"HomeNet\"\n"
        "                    Quality=70/70  Signal level=-40 dBm\n"
        "                    Encryption key:on\n"
        "                    Bit Rates:1 Mb/s\n");
    CHECK(out.find("ESSID:\"HomeNet\"") != std::string::npos);
    CHECK(out.find("Quality=70/70") != std::string::npos);
    CHECK(out.find("Encryption key:on") != std::string::npos);
    CHECK(out.find("Bit Rates") == std::string::npos);
    CHECK(out.find("Scan completed") == std::string::npos);
}

TEST_CASE("wifi: filter_iwconfig_essid_signal_lines keeps only ESSID/Signal lines", "[wifi]") {
    auto out = filter_iwconfig_essid_signal_lines(
        "wlan0     IEEE 802.11  ESSID:\"HomeNet\"\n"
        "          Mode:Managed  Frequency:2.437 GHz\n"
        "          Signal level=-45 dBm\n");
    CHECK(out.find("ESSID:\"HomeNet\"") != std::string::npos);
    CHECK(out.find("Signal level=-45 dBm") != std::string::npos);
    CHECK(out.find("Mode:Managed") == std::string::npos);
}

TEST_CASE("wifi: parse_iwconfig_essid_blob — associated blob passes through", "[wifi]") {
    auto blob = parse_iwconfig_essid_blob("ESSID:\"HomeNet\"\nSignal level=-45 dBm");
    REQUIRE(blob.has_value());
    CHECK(blob->find("HomeNet") != std::string::npos);
}

TEST_CASE("wifi: parse_iwconfig_essid_blob — ESSID:off means not connected", "[wifi]") {
    CHECK_FALSE(parse_iwconfig_essid_blob("wlan0     ESSID:off/any").has_value());
}

TEST_CASE("wifi: parse_iwconfig_essid_blob on empty input", "[wifi]") {
    CHECK_FALSE(parse_iwconfig_essid_blob("").has_value());
}

// ── macOS airport / system_profiler parsing ─────────────────────────────

TEST_CASE("wifi: parse_airport_scan on empty input yields no rows", "[wifi]") {
    CHECK(parse_airport_scan("").empty());
}

TEST_CASE("wifi: parse_airport_scan parses a fixed-width row", "[wifi]") {
    // Header line, then one network row: SSID BSSID RSSI CHANNEL HT CC SECURITY.
    std::string blob =
        "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
        "                         HomeNet aa:bb:cc:dd:ee:ff  -40       6  Y  US WPA2(PSK/AES/AES)\n";
    auto rows = parse_airport_scan(blob);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].ssid == "HomeNet");
    CHECK(rows[0].bssid == "aa:bb:cc:dd:ee:ff");
    CHECK(rows[0].signal == "-40");
    CHECK(rows[0].channel == "6");
}

TEST_CASE("wifi: parse_system_profiler_wifi extracts networks under the section header",
          "[wifi]") {
    // Indentation CAPTURED from a live `system_profiler SPAirPortDataType`
    // run (Darwin 25.5): the section header sits at 10 spaces, each network
    // NAME at 12, and its sub-fields at 14. The previous fixture put names at
    // 14 to match a fixed-column check in the parser -- so it pinned the
    // parser's own constant instead of the tool's real output, and hid the
    // fact that the parser matched nothing on any real host.
    std::string blob =
        "          Other Local Wi-Fi Networks:\n"
        "            HomeNet:\n"
        "              PHY Mode: 802.11ax\n"
        "              Channel: 6 (2GHz, 20MHz)\n"
        "              Network Type: Infrastructure\n"
        "              Security: WPA2 Personal\n"
        "              Signal / Noise: -40 dBm / -90 dBm\n"
        "            Guest:\n"
        "              Channel: 149 (5GHz, 80MHz)\n";
    auto rows = parse_system_profiler_wifi(blob);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "HomeNet");
    // "6 (2GHz, 20MHz)" -> "6": the other legs emit a bare channel number, so
    // the column has to mean the same thing on all of them.
    CHECK(rows[0].channel == "6");
    CHECK(rows[0].signal == "-40 dBm / -90 dBm");
    CHECK(rows[0].security == "WPA2 Personal");
    CHECK(rows[1].ssid == "Guest");
    CHECK(rows[1].channel == "149");
    CHECK(rows[1].security == "Unknown"); // no Security line for this entry
}

// Regression guard for the indent bug specifically: a name at 12 must parse.
// Under the old fixed 14-column rule this returned zero rows on every real
// macOS host, and do_list_networks then blamed Location Services for it.
TEST_CASE("wifi: parse_system_profiler_wifi does not depend on a fixed indent column",
          "[wifi]") {
    std::string shallow =
        "      Other Local Wi-Fi Networks:\n"
        "        NetA:\n"
        "          Channel: 1\n";
    std::string deep =
        "            Other Local Wi-Fi Networks:\n"
        "              NetA:\n"
        "                Channel: 1\n";
    auto a = parse_system_profiler_wifi(shallow);
    auto b = parse_system_profiler_wifi(deep);
    REQUIRE(a.size() == 1);
    REQUIRE(b.size() == 1);
    CHECK(a[0].ssid == "NetA");
    CHECK(b[0].ssid == "NetA");
}

TEST_CASE("wifi: parse_system_profiler_wifi with no section header yields no rows", "[wifi]") {
    CHECK(parse_system_profiler_wifi("Wi-Fi:\n    Card Type: AirPort\n").empty());
}

// ── NetworkManager D-Bus AP-tuple -> record helpers ─────────────────────

TEST_CASE("wifi: ssid_bytes_to_display — empty means hidden", "[wifi]") {
    CHECK(ssid_bytes_to_display({}) == "<hidden>");
}

TEST_CASE("wifi: ssid_bytes_to_display — valid printable UTF-8 passes through", "[wifi]") {
    std::vector<std::uint8_t> bytes = {'H', 'o', 'm', 'e', 0xC3, 0xA9}; // "Home" + U+00E9 (é)
    CHECK(ssid_bytes_to_display(bytes) == "Home\xC3\xA9");
}

TEST_CASE("wifi: ssid_bytes_to_display — non-UTF8/non-printable becomes a hex marker",
          "[wifi]") {
    std::vector<std::uint8_t> bytes = {0xFF, 0x00, 0x01, 0xC0, 0x80};
    auto out = ssid_bytes_to_display(bytes);
    CHECK(out == "<hex:ff0001c080>");
}

TEST_CASE("wifi: ssid_bytes_to_display — a C0 control byte is rejected as printable",
          "[wifi]") {
    std::vector<std::uint8_t> bytes = {'a', 'b', 0x07, 'c'}; // embedded BEL
    auto out = ssid_bytes_to_display(bytes);
    CHECK(out == "<hex:61620763>");
}

TEST_CASE("wifi: frequency_to_channel — 2.4GHz band", "[wifi]") {
    CHECK(frequency_to_channel(2412) == "1");
    CHECK(frequency_to_channel(2437) == "6");
    CHECK(frequency_to_channel(2472) == "13");
    CHECK(frequency_to_channel(2484) == "14");
}

TEST_CASE("wifi: frequency_to_channel — 5GHz and 6GHz bands", "[wifi]") {
    CHECK(frequency_to_channel(5180) == "36");
    CHECK(frequency_to_channel(5955) == "1");
    CHECK(frequency_to_channel(5935) == "2");
}

TEST_CASE("wifi: frequency_to_channel — unrecognised frequency is honestly 0", "[wifi]") {
    CHECK(frequency_to_channel(0) == "0");
    CHECK(frequency_to_channel(999999) == "0");
    CHECK(frequency_to_channel(2413) == "0"); // off the 5MHz grid
}

// "Open", not "NONE": the nmcli, airport and system_profiler legs all render
// an unsecured AP as "Open". If the D-Bus leg disagreed, the SAME access point
// would change its reported security string purely because the host degraded
// from D-Bus to nmcli.
TEST_CASE("wifi: an open network reads the same on every acquisition rung", "[wifi]") {
    // The whole point: the SAME access point must not change its reported
    // security because the host degraded from D-Bus to nmcli to airport.
    const std::string dbus = nm_security_flags_to_string(0, 0);
    CHECK(dbus == "Open");

    auto nmcli_rows = parse_nmcli_wifi_list("OpenNet:70::6:AA");
    REQUIRE(nmcli_rows.size() == 1);
    CHECK(nmcli_rows[0].security == dbus);

    // airport prints the literal "NONE" for an unsecured AP -- the leg the
    // previous version of this test never touched, and the one that disagreed.
    auto airport_rows = parse_airport_scan(
        "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
        "                         OpenNet aa:bb:cc:dd:ee:ff  -40       6  Y  US NONE\n");
    REQUIRE(airport_rows.size() == 1);
    CHECK(airport_rows[0].security == dbus);
}

TEST_CASE("wifi: nm_security_flags_to_string — WPA1 only", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x100, 0) == "WPA1");
}

TEST_CASE("wifi: nm_security_flags_to_string — WPA2 (non-zero RsnFlags)", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x100, 0x100) == "WPA2");
}

TEST_CASE("wifi: nm_security_flags_to_string — 802.1X takes priority", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x200, 0) == "802.1X");
    CHECK(nm_security_flags_to_string(0, 0x300) == "802.1X");
}

// Bit values transcribed from NetworkManager's shipped libnm/nm-dbus-interface.h
// (NM 1.52): SAE = 0x400, OWE = 0x800. Before this, a WPA3-Personal AP was
// reported as "WPA2" -- a security downgrade in the operator's audit view and a
// disagreement with the nmcli rung-2 fallback, which prints WPA3.
TEST_CASE("wifi: nm_security_flags_to_string — WPA3/SAE is not reported as WPA2", "[wifi]") {
    // RSN word carrying PSK+SAE, as a WPA2/WPA3 transition-mode AP advertises.
    CHECK(nm_security_flags_to_string(0, 0x400) == "WPA3");
    CHECK(nm_security_flags_to_string(0, 0x100 | 0x400) == "WPA3");
    // Enterprise still outranks SAE (WPA3-Enterprise reports 802.1X).
    CHECK(nm_security_flags_to_string(0, 0x200 | 0x400) == "802.1X");
}

TEST_CASE("wifi: nm_security_flags_to_string — OWE enhanced-open is distinct from open",
          "[wifi]") {
    CHECK(nm_security_flags_to_string(0, 0x800) == "OWE");
    // OWE transition mode (0x1000) must not fall through to the bare
    // "non-zero RsnFlags implies WPA2" branch.
    CHECK(nm_security_flags_to_string(0, 0x1000) == "OWE");
    // ...and a genuinely open AP is still Open, not OWE.
    CHECK(nm_security_flags_to_string(0, 0) == "Open");
}

// ── honest degradation: a failed query is never a negative answer ──────────
//
// Regression guard for the fabricated-success class that shipped twice in
// Wave 3. `classify_runner_failure` deliberately returns nullopt for a normal
// exit, so a nonzero-exiting nmcli/iwconfig is invisible to the ABI status
// seam; without wifi_tool_answered(), `connected` reported a confident
// "Not connected" when in fact nothing had been determined.
namespace {
struct FakeResult {
    yuzu::agent::TerminationReason termination_reason =
        yuzu::agent::TerminationReason::exited;
    int exit_code = 0;
};
} // namespace

TEST_CASE("wifi: wifi_tool_answered — only a clean successful exit answers the question",
          "[wifi]") {
    using TR = yuzu::agent::TerminationReason;

    // The one outcome that is a real answer.
    CHECK(wifi_tool_answered(FakeResult{TR::exited, 0}).answered);

    // A tool that ran but FAILED has told us nothing -- this is the exact
    // case that produced a fabricated "Not connected".
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 7}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 127}).answered);

    // Nor has a tool that never ran, was killed, or timed out.
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::spawn_error, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::deadline, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::cancelled, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::signaled, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::line_limit, -1}).answered);
}

TEST_CASE("wifi: nm_ap_to_row assembles a list_networks row from raw AP properties",
          "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'H', 'o', 'm', 'e', 'N', 'e', 't'};
    ap.strength = 82;
    ap.hw_address = "AA:BB:CC:DD:EE:FF";
    ap.frequency_mhz = 2437;
    ap.wpa_flags = 0x100;
    ap.rsn_flags = 0x100;

    auto row = nm_ap_to_row(ap);
    CHECK(row.ssid == "HomeNet");
    CHECK(row.signal == "82");
    CHECK(row.security == "WPA2");
    CHECK(row.channel == "6");
    CHECK(row.bssid == "AA:BB:CC:DD:EE:FF");
}

TEST_CASE("wifi: nm_ap_to_row — an empty HwAddress defaults to '-'", "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'X'};
    auto row = nm_ap_to_row(ap);
    CHECK(row.bssid == "-");
}

TEST_CASE("wifi: nm_ap_to_connected_row assembles a connected row and uses the interface name",
          "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'H', 'o', 'm', 'e', 'N', 'e', 't'};
    ap.strength = 90;
    ap.hw_address = "AA:BB:CC:DD:EE:FF";
    ap.wpa_flags = 0;
    ap.rsn_flags = 0x100;

    auto row = nm_ap_to_connected_row(ap, "wlan0");
    CHECK(row.ssid == "HomeNet");
    CHECK(row.signal == "90");
    CHECK(row.security == "WPA2");
    CHECK(row.bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(row.connection == "wlan0");
}

TEST_CASE("wifi: nm_ap_to_connected_row — an empty interface name defaults to '-'", "[wifi]") {
    NmAccessPointProps ap;
    auto row = nm_ap_to_connected_row(ap, "");
    CHECK(row.connection == "-");
}
