/**
 * test_wifi_corewlan.cpp — deterministic coverage of the macOS `wifi connected`
 * output contract. The CoreWLAN collection itself (wifi_corewlan.mm) needs live
 * hardware + Location Services and is verified on-device; the pure
 * WifiConnection → record formatter is exercised here on every CI leg so a
 * later refactor of the field order, security mapping, association signal, or
 * the "<ssid-withheld>" fallback cannot silently regress.
 */
#include "wifi_corewlan.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::wifi::format_connected_record;
using yuzu::wifi::WifiConnection;

TEST_CASE("wifi connected: not associated → honest Not connected", "[wifi]") {
    // Default-constructed (no Wi-Fi interface, radio off, or unassociated) all
    // collapse to the same honest line — never a partial/garbage record.
    CHECK(format_connected_record(WifiConnection{}) == "connected|none|Not connected|0|none|none");

    WifiConnection powered_but_idle;
    powered_but_idle.power_on = true; // radio on, not joined to a network
    CHECK(format_connected_record(powered_but_idle) == "connected|none|Not connected|0|none|none");
}

TEST_CASE("wifi connected: associated with SSID withheld by Location Services", "[wifi]") {
    WifiConnection c;
    c.power_on = true;
    c.associated = true;
    c.ssid_available = false; // withheld → marker, NOT a false "Not connected"
    c.rssi = -44;
    c.channel = 6;
    c.security = "WPA2-Personal";
    // bssid also withheld → "-"
    CHECK(format_connected_record(c) == "connected|<ssid-withheld>|-44|WPA2-Personal|-|6");
}

TEST_CASE("wifi connected: associated with SSID/BSSID visible", "[wifi]") {
    WifiConnection c;
    c.power_on = true;
    c.associated = true;
    c.ssid_available = true;
    c.ssid = "MyNet";
    c.bssid = "aa:bb:cc:dd:ee:ff";
    c.rssi = -50;
    c.channel = 11;
    c.security = "WPA3-Personal";
    CHECK(format_connected_record(c) == "connected|MyNet|-50|WPA3-Personal|aa:bb:cc:dd:ee:ff|11");
}

TEST_CASE("wifi connected: a pipe/newline in the SSID cannot shift columns or inject a row (plg-H1)",
          "[wifi]") {
    // `wifi` is NOT a key|value plugin server-side (result_parsing splits it on
    // ALL pipes), and an AP can broadcast an SSID containing '|' (a legal 802.11
    // octet) or, via a crafted beacon, an embedded newline. Both must be
    // neutralised by safe_output_field: '|' -> "\|", '\n' -> ' '. Otherwise the
    // security-posture row is corrupted or a fabricated row is injected.
    WifiConnection c;
    c.power_on = true;
    c.associated = true;
    c.ssid_available = true;
    c.ssid = "Corp|Net\nEvil";
    c.bssid = "aa:bb:cc:dd:ee:ff";
    c.rssi = -50;
    c.channel = 11;
    c.security = "WPA2|x";
    const std::string row = format_connected_record(c);
    // Exactly six fields once the escaped pipe is accounted for -- the SSID's
    // literal '|' is now "\|" (not a delimiter) and the newline is a space.
    CHECK(row == "connected|Corp\\|Net Evil|-50|WPA2\\|x|aa:bb:cc:dd:ee:ff|11");
    CHECK(row.find('\n') == std::string::npos); // no injected row
}

TEST_CASE("wifi connected: rssi 0 while associated is a real connection, not Not-connected",
          "[wifi]") {
    // A driver can momentarily report 0 dBm on a genuinely-associated link; that
    // must render as a connection (rssi 0), distinct from the not-connected line.
    WifiConnection c;
    c.associated = true;
    c.ssid_available = true;
    c.ssid = "MyNet";
    c.rssi = 0;
    c.channel = 6;
    c.security = "WPA2-Personal";
    CHECK(format_connected_record(c) == "connected|MyNet|0|WPA2-Personal|-|6");
}

TEST_CASE("wifi connected: unknown security falls back to Unknown", "[wifi]") {
    WifiConnection c;
    c.associated = true;
    c.ssid_available = true;
    c.ssid = "Cafe";
    c.rssi = -60;
    c.channel = 1;
    c.security = ""; // kCWSecurityUnknown / newer-than-SDK maps to empty
    CHECK(format_connected_record(c) == "connected|Cafe|-60|Unknown|-|1");
}
