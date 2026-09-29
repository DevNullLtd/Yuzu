/**
 * wifi_corewlan.hpp — macOS current-Wi-Fi-connection query via CoreWLAN, plus
 * the pure `connected`-record formatter shared by the plugin and its unit test.
 *
 * CoreWLAN is an Objective-C framework, so `corewlan_current_connection()` is
 * implemented in the sibling Objective-C++ TU `wifi_corewlan.mm` (the first
 * `.mm` TU in the tree) and is only declared on Apple. The `WifiConnection`
 * struct and `format_connected_record()` are plain, platform-neutral C++ so the
 * output contract can be unit-tested on every CI leg without CoreWLAN or live
 * Wi-Fi hardware (tests/unit/test_wifi_corewlan.cpp).
 *
 * Replaces the dead `airport -I` shell-out: the private `airport` binary was
 * removed in macOS 14 (Sonoma), so the old path returned nothing and the agent
 * always reported "Not connected" even while associated.
 *
 * Location Services caveat (macOS 14+): `ssid` and `bssid` are gated behind
 * Location Services authorisation. A background LaunchDaemon has no practical
 * way to obtain it, so on modern macOS those two fields are typically withheld
 * (returned nil) even for a live association. Everything else — power state,
 * association, RSSI, channel, security, interface name — is returned without
 * authorisation, so we can honestly report a connection and mark SSID/BSSID as
 * withheld rather than falsely claiming "Not connected". See docs/darwin-compat.md.
 */
#pragma once

#include <format>
#include <string>

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-H1)

namespace yuzu::wifi {

struct WifiConnection {
    bool power_on = false;        // Wi-Fi radio powered on
    bool associated = false;      // joined to a network (has a live channel)
    bool ssid_available = false;  // false → name unavailable (usually Location
                                  // Services withholding on 14+; also a hidden
                                  // SSID or non-UTF8 name — indistinguishable here)
    std::string ssid;             // valid only when ssid_available
    std::string bssid;            // empty when name unavailable / not associated
    int rssi = 0;                 // dBm; 0 when not associated
    int channel = 0;              // 0 when not associated
    std::string security;         // human-readable; empty when unknown
    std::string interface;        // e.g. "en0"; empty when no Wi-Fi hardware
};

// Formats the macOS `connected` action output line from a WifiConnection.
// Single source of truth for the record contract, in the established macOS field
// order: SSID | RSSI | Security | BSSID | Channel. An associated link whose SSID
// name is unavailable (usually Location Services withholding on 14+, sometimes a
// hidden SSID) reports "<ssid-withheld>" (an honest connection), never a false
// "Not connected". Pure — unit-tested cross-platform.
//
// SSID/security/BSSID are the most attacker-controllable fields in the plugin
// set (an AP can broadcast an SSID containing '|' — a legal 802.11 octet — or,
// via a crafted beacon, an embedded newline), and `wifi` is NOT a key|value
// plugin (server-side result_parsing splits it on ALL pipes), so an unescaped
// '|' shifts every later column and a '\n' injects a fabricated row. Route each
// through safe_output_field (plg-H1) — the same discipline the rest of this
// branch applies (users desc, certificates subject/issuer, event_logs message).
inline std::string format_connected_record(const WifiConnection& c) {
    if (!c.associated)
        return "connected|none|Not connected|0|none|none";
    const std::string ssid =
        c.ssid_available ? yuzu::util::safe_output_field(c.ssid) : "<ssid-withheld>";
    return std::format("connected|{}|{}|{}|{}|{}", ssid, c.rssi,
                       c.security.empty() ? "Unknown" : yuzu::util::safe_output_field(c.security),
                       c.bssid.empty() ? "-" : yuzu::util::safe_output_field(c.bssid), c.channel);
}

#ifdef __APPLE__
// Populates `out` from the default Wi-Fi interface via CoreWLAN.
// Returns false only when the host has no Wi-Fi interface at all; a powered-off
// or unassociated radio still returns true (with associated == false).
bool corewlan_current_connection(WifiConnection& out);
#endif // __APPLE__

} // namespace yuzu::wifi
