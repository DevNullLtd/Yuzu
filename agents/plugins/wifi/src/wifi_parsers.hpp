#pragma once

/**
 * wifi_parsers.hpp — pure parse/format helpers for the wifi plugin's
 * list_networks/connected records.
 *
 * Header-only, no I/O, no spdlog (services_parsers.hpp discipline): every
 * function here takes already-captured tool text (nmcli/iw/iwlist/iwconfig/
 * airport/system_profiler) or already-unwrapped NetworkManager D-Bus
 * property values, and returns a structured/pure result. wifi_plugin.cpp
 * owns every I/O boundary — the bounded argv runner AND the sd-bus reads —
 * and hands this header only plain data, so all of it is fixture-testable
 * (tests/unit/test_wifi_parsers.cpp) without a subprocess, a live
 * NetworkManager host, or Wi-Fi hardware.
 *
 * Two record shapes:
 *   WifiNetworkRow    — one `wifi|SSID|SIGNAL|SECURITY|CHANNEL|BSSID` row
 *                       (list_networks).
 *   WifiConnectedRow  — one `connected|SSID|SIGNAL|SECURITY|BSSID|<col5>`
 *                       row (connected). On Linux <col5> is historically the
 *                       nmcli GENERAL.CONNECTION profile name; the D-Bus leg
 *                       uses the device's Interface name instead (see
 *                       nm_ap_to_connected_row) — a deliberate, documented
 *                       deviation, not an oversight (see the package report).
 *
 * Every field returned here is still RAW (not yet run through
 * yuzu::util::safe_output_field) — wifi_plugin.cpp applies sof() once, at
 * the single emission site, exactly as it does today for every source
 * (nmcli/airport/CoreWLAN alike), so this header never needs to know about
 * the plugin wire-safety helper.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::wifi {

// One row of the `wifi|SSID|SIGNAL|SECURITY|CHANNEL|BSSID` list_networks
// record.
struct WifiNetworkRow {
    std::string ssid;
    std::string signal;
    std::string security;
    std::string channel;
    std::string bssid;
};

// One row of the `connected|SSID|SIGNAL|SECURITY|BSSID|<col5>` record.
struct WifiConnectedRow {
    std::string ssid;
    std::string signal;
    std::string security;
    std::string bssid;
    std::string connection; // nmcli: GENERAL.CONNECTION; D-Bus leg: Device.Interface
};

// ── nmcli -t terse-output parsing ───────────────────────────────────────

// Splits one nmcli -t (terse) line on ':' honouring nmcli's own backslash
// escaping (`\:` is a literal colon inside a field, `\\` a literal
// backslash) -- a naive split on every ':' truncates any SSID/value that
// legitimately contains a colon. A trailing lone backslash (nmcli never
// emits one) is kept as a literal backslash rather than dropped.
inline std::vector<std::string> split_nmcli_terse_line(std::string_view line) {
    std::vector<std::string> fields;
    std::string cur;
    bool escaped = false;
    for (char c : line) {
        if (escaped) {
            cur += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == ':') {
            fields.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (escaped)
        cur += '\\';
    fields.push_back(std::move(cur));
    return fields;
}

// Parses `nmcli -t -f SSID,SIGNAL,SECURITY,CHAN,BSSID device wifi list`
// output into rows, applying the same "<hidden>"/"Open"/"0"/"-" defaults
// the plugin has always applied to blank fields. Blank lines are skipped;
// a short line (missing trailing fields) leaves the missing columns blank
// and defaults them the same way.
inline std::vector<WifiNetworkRow> parse_nmcli_wifi_list(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty())
            continue;
        auto fields = split_nmcli_terse_line(line);
        // A COMPLETE row has exactly the five fields the argv requested. A
        // shorter one is a TRUNCATION -- nmcli killed mid-write, or the
        // runner's line cap cutting the final line -- and must never be
        // completed from defaults: doing so invents `<hidden>|0|Open|0|-`,
        // i.e. a FABRICATED OPEN ACCESS POINT in an operator's security audit.
        // An unsecured AP is signalled by a PRESENT-but-empty SECURITY field,
        // which is a real observation; a MISSING field is not an observation
        // at all. Drop the partial line rather than guess at it.
        if (fields.size() < 5)
            continue;
        WifiNetworkRow row;
        row.ssid = fields[0];
        row.signal = fields[1];
        row.security = fields[2];
        row.channel = fields[3];
        row.bssid = fields[4];
        if (row.ssid.empty())
            row.ssid = "<hidden>";
        if (row.security.empty())
            row.security = "Open";
        if (row.signal.empty())
            row.signal = "0";
        if (row.channel.empty())
            row.channel = "0";
        if (row.bssid.empty())
            row.bssid = "-";
        rows.push_back(std::move(row));
    }
    return rows;
}

// Parses `nmcli -t -f ACTIVE,SSID,SIGNAL,SECURITY,BSSID,DEVICE device wifi
// list` and returns the row nmcli marks ACTIVE (the association this host
// currently holds), or nullopt when no row is active.
//
// WHY NOT `device show`: the previous implementation asked
// `device show` for GENERAL.CONNECTION,WIFI.SSID,WIFI.SIGNAL,WIFI.SECURITY,
// WIFI.BSSID. Those WIFI.* fields DO NOT EXIST on that command. Verified
// against a live nmcli 1.52.1:
//
//   $ nmcli -t -f GENERAL.CONNECTION,WIFI.SSID,... device show
//   Error: 'device show': invalid field 'WIFI.SSID'; allowed fields:
//   GENERAL,CAPABILITIES,INTERFACE-FLAGS,WIFI-PROPERTIES,AP,
//   WIRED-PROPERTIES,...                                    (exit 2)
//
// So the whole declared rung-2 fallback for `connected` exited 2 with empty
// output on EVERY host -- the argv was inherited verbatim from the
// pre-migration shell string, which is why byte-parity against the base was
// preserved while the leg had never once worked. `device wifi list` is the
// command that really carries AP fields; the field names below are the ones
// that live probe reported as valid.
//
// ACTIVE (yes/no) is preferred over IN-USE, whose terse value is the glyph
// "*"/empty and is far easier to mis-parse.
//
// Column 5 carries DEVICE (the interface, e.g. wlan0), NOT the connection
// profile name the old GENERAL.CONNECTION supplied. That is deliberate and
// now CONSISTENT: the D-Bus rung-1 leg emits Device.Interface in the same
// column, so a host degrading from D-Bus to nmcli no longer changes the
// meaning of the field -- the same reasoning applied to the security
// vocabulary. Recorded as a disclosed behaviour change.
inline std::optional<WifiConnectedRow> parse_nmcli_wifi_list_active(std::string_view raw) {
    std::istringstream ss{std::string{raw}};
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty())
            continue;
        auto fields = split_nmcli_terse_line(line);
        if (fields.empty())
            continue;
        // nmcli prints the localised "yes"/"no"; match case-insensitively on
        // the ASCII form and also accept the IN-USE "*" glyph so a field-set
        // change does not silently select nothing.
        auto& active = fields[0];
        const bool is_active =
            active == "*" || (active.size() == 3 && (active[0] == 'y' || active[0] == 'Y'));
        if (!is_active)
            continue;
        // Same truncation rule as parse_nmcli_wifi_list: six fields were
        // requested, so fewer than six is a cut line, not an observation.
        if (fields.size() < 6)
            continue;
        WifiConnectedRow row;
        row.ssid = fields[1];
        row.signal = fields[2];
        row.security = fields[3];
        row.bssid = fields[4];
        row.connection = fields[5];
        if (row.ssid.empty())
            row.ssid = "<hidden>";
        if (row.signal.empty())
            row.signal = "0";
        if (row.security.empty())
            row.security = "Open";
        if (row.bssid.empty())
            row.bssid = "-";
        if (row.connection.empty())
            row.connection = "-";
        return row;
    }
    return std::nullopt;
}

// ── iw / iwlist / iwconfig text filtering (replaces the deleted
// `| grep ... | awk ...` shell pipelines) ───────────────────────────────

// ADR-3002 Decision 6 (an explicit MUST): "Every migrated site must handle
// option injection (pass `--` before positional values where supported, or
// reject leading-`-` values)". `iwlist` accepts no `--`, so the alternative
// applies and this is where it lives.
//
// `iface` is the ONLY non-literal element in any wifi argv vector. It comes
// from this host's own `iw dev` output rather than from an operator, but that
// is a statement about today's caller, not a property of the value: an
// interface named `-i` or `--help` would be read by iwlist as a FLAG, not as
// the positional it is passed as. Validating in the pure builder means the
// guard cannot be bypassed by a future second caller, and can be unit-tested
// without spawning anything.
//
// Linux caps interface names at IFNAMSIZ-1 = 15 bytes; the kernel also
// forbids '/' and whitespace. This accepts the conservative portable subset
// and rejects everything else, including any leading '-'.
inline bool is_safe_iface_name(std::string_view iface) {
    if (iface.empty() || iface.size() > 15)
        return false;
    if (iface.front() == '-')
        return false;
    for (char c : iface) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == ':';
        if (!ok)
            return false;
    }
    return true;
}

// Returns an EMPTY vector for a rejected interface name. An empty argv is what
// run_tool() already treats as a runtime-reject (spawn_error, tool_ran=false),
// so a rejected name degrades through the same honest path as a missing tool
// rather than silently scanning the wrong thing.
// Extracts interface names from `iw dev` output -- replaces
// `iw dev | grep Interface | awk '{print $2}'`. Matches any line
// containing "Interface" and takes that line's second whitespace-separated
// token, same as the deleted awk expression.
inline std::vector<std::string> parse_iw_dev_interfaces(std::string_view raw) {
    std::vector<std::string> ifaces;
    std::istringstream ss{std::string{raw}};
    std::string line;
    while (std::getline(ss, line)) {
        std::istringstream ls(line);
        std::vector<std::string> tokens;
        std::string tok;
        while (ls >> tok)
            tokens.push_back(tok);
        // `iw dev` emits exactly "\tInterface <name>". Requiring the FIRST
        // token to be the literal keyword, and the line to hold exactly two
        // tokens, stops a line that merely CONTAINS the word from being read
        // as an interface -- e.g. an SSID echoed in the same output. Each
        // bogus name would otherwise cost a real 20s `iwlist` spawn.
        if (tokens.size() != 2 || tokens[0] != "Interface")
            continue;
        // Belt and braces: never hand an unusable name downstream.
        if (is_safe_iface_name(tokens[1]))
            ifaces.push_back(tokens[1]);
    }
    return ifaces;
}

// Filters `iwlist <iface> scan` output down to the ESSID/Quality/Encryption
// lines -- replaces `| grep -E 'ESSID|Quality|Encryption'`. Matching lines
// are joined with '\n', preserving the grep-piped shape the plugin still
// emits as one opaque `wifi|scan_output|...` field.
inline std::string filter_iwlist_scan_lines(std::string_view raw) {
    std::string out;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (line.find("ESSID") == std::string::npos && line.find("Quality") == std::string::npos &&
            line.find("Encryption") == std::string::npos)
            continue;
        if (!first)
            out += '\n';
        out += line;
        first = false;
    }
    return out;
}

// Filters `iwconfig` output down to the ESSID/Signal lines -- replaces
// `| grep -E 'ESSID|Signal'`. Same join shape as filter_iwlist_scan_lines.
inline std::string filter_iwconfig_essid_signal_lines(std::string_view raw) {
    std::string out;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (line.find("ESSID") == std::string::npos && line.find("Signal") == std::string::npos)
            continue;
        if (!first)
            out += '\n';
        out += line;
        first = false;
    }
    return out;
}

// Applies the plugin's existing iwconfig connected-fallback rule to an
// already ESSID/Signal-filtered blob: empty, or reporting "ESSID:off"
// (not associated), means std::nullopt (-> "Not connected"); anything else
// is returned as-is (the plugin embeds it as one opaque field, unchanged
// from today -- this fallback has never parsed individual ESSID/Signal
// values out of the blob).
inline std::optional<std::string> parse_iwconfig_essid_blob(std::string_view raw) {
    if (raw.empty())
        return std::nullopt;
    if (raw.find("ESSID:off") != std::string_view::npos)
        return std::nullopt;
    return std::string{raw};
}

// ── macOS airport / system_profiler text parsing ────────────────────────

// Parses `airport -s` fixed-width output into rows. A straight move of the
// plugin's existing token-based reconstruction (SSID can contain spaces, so
// the columns are recovered by walking back from the known-fixed tail:
// SECURITY, CC, HT, CHANNEL, RSSI, BSSID, with everything before BSSID
// re-joined as the SSID) -- unchanged from today, byte-for-byte.
inline std::vector<WifiNetworkRow> parse_airport_scan(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    if (raw.empty())
        return rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool header_skipped = false;
    while (std::getline(ss, line)) {
        if (!header_skipped) {
            header_skipped = true;
            continue; // header line
        }
        if (line.empty())
            continue;
        if (line.size() < 40)
            continue;

        std::string ssid, bssid, rssi, channel, security;
        std::istringstream ls(line);
        std::string token;
        std::vector<std::string> tokens;
        while (ls >> token)
            tokens.push_back(token);

        if (tokens.size() >= 7) {
            security = tokens.back();
            std::size_t sec_start = tokens.size() - 1;
            while (sec_start > 0 && (tokens[sec_start - 1].find("WPA") != std::string::npos ||
                                     tokens[sec_start - 1].find("WEP") != std::string::npos ||
                                     tokens[sec_start - 1] == "--")) {
                security = tokens[sec_start - 1] + " " + security;
                --sec_start;
            }
            if (sec_start >= 6) {
                channel = tokens[sec_start - 3];
                rssi = tokens[sec_start - 4];
                bssid = tokens[sec_start - 5];
                ssid = tokens[0];
                for (std::size_t k = 1; k < sec_start - 5; ++k) {
                    ssid += " " + tokens[k];
                }
            }
        }

        if (ssid.empty())
            ssid = "<hidden>";
        // airport prints the literal "NONE" for an unsecured AP where the
        // nmcli, system_profiler and D-Bus legs all say "Open". Normalise, so
        // the same AP does not change its reported security with the rung.
        if (security.empty() || security == "NONE" || security == "none")
            security = "Open";

        WifiNetworkRow row;
        row.ssid = ssid;
        row.signal = rssi.empty() ? "0" : rssi;
        row.security = security;
        row.channel = channel.empty() ? "0" : channel;
        row.bssid = bssid.empty() ? "-" : bssid;
        rows.push_back(std::move(row));
    }
    return rows;
}

// Parses `system_profiler SPAirPortDataType -detailLevel basic` output's
// "Other Local Wi-Fi Networks:" section into rows. A straight move of the
// plugin's existing indented-section state machine, unchanged from today.
// A network is only emitted once a non-empty SSID has been seen (matches
// the original `flush()`'s early return on an empty ssid), so malformed or
// header-only input yields an empty vector rather than a garbage row.
inline std::vector<WifiNetworkRow> parse_system_profiler_wifi(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    if (raw.empty())
        return rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool in_others = false;
    std::string ssid, channel, rssi, security;
    auto flush = [&]() {
        if (ssid.empty())
            return;
        WifiNetworkRow row;
        row.ssid = ssid;
        row.signal = rssi.empty() ? "0" : rssi;
        row.security = security.empty() ? "Unknown" : security;
        row.channel = channel.empty() ? "0" : channel;
        row.bssid = "-";
        rows.push_back(std::move(row));
        ssid.clear();
        channel.clear();
        rssi.clear();
        security.clear();
    };
    while (std::getline(ss, line)) {
        if (line.find("Other Local Wi-Fi Networks:") != std::string::npos) {
            in_others = true;
            continue;
        }
        if (!in_others)
            continue;
        // A network NAME is a line that is nothing but "<name>:" -- no value
        // after the colon. Sub-fields ("Channel: 124 (5GHz, 80MHz)") always
        // carry one, so the two are distinguishable without hardcoding a column.
        //
        // The previous rule required EXACTLY 14 leading spaces. Real
        // system_profiler output (verified live on Darwin 25.5) indents the
        // section at 10, the network NAME at 12 and its sub-fields at 14 -- so
        // that rule matched no name on any real host, this parser returned zero
        // rows every time, and do_list_networks then blamed Location Services
        // in its sentinel. The bug PREDATES this change (base
        // wifi_plugin.cpp:335 carried the identical constant); what this change
        // added was a fixture that PINNED the wrong column, which is how it
        // survived a rewrite. Indent is now relative -- only ordering matters.
        const auto indent = line.find_first_not_of(' ');
        if (indent != std::string::npos && line.back() == ':' && line.size() > indent + 1) {
            const std::string body = line.substr(indent, line.size() - indent - 1);
            if (body.find(':') == std::string::npos) {
                flush();
                ssid = body;
                continue;
            }
        }
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        while (!key.empty() && key.front() == ' ')
            key.erase(0, 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(0, 1);
        if (key == "Channel") {
            // Real output is "124 (5GHz, 80MHz)"; every other leg emits a bare
            // channel number, so trim at the first space to keep the column
            // meaning the same across rungs.
            channel = val.substr(0, val.find(' '));
        }
        else if (key == "Signal / Noise")
            rssi = val;
        else if (key == "Security")
            security = val;
    }
    flush();
    return rows;
}

// ── NetworkManager D-Bus AP-tuple -> record helpers (pure, no sd-bus;
// fixture-testable without a bus connection) ────────────────────────────

// Raw property values as read off one org.freedesktop.NetworkManager.
// AccessPoint object, already unwrapped from their sd-bus variants by the
// caller (wifi_plugin.cpp). `ssid_bytes` is the RAW Ssid 'ay' payload, NOT
// UTF-8 validated -- see ssid_bytes_to_display.
struct NmAccessPointProps {
    std::vector<std::uint8_t> ssid_bytes; // Ssid, 'v'->'ay'
    std::uint8_t strength = 0;            // Strength, 'v'->'y' (percent)
    std::string hw_address;               // HwAddress, 'v'->'s'
    std::uint32_t frequency_mhz = 0;      // Frequency, 'v'->'u' (MHz)
    std::uint32_t wpa_flags = 0;          // WpaFlags, 'v'->'u'
    std::uint32_t rsn_flags = 0;          // RsnFlags, 'v'->'u'
};

namespace detail {
// Validates `bytes` as UTF-8 with no C0 control characters (a printable
// SSID). Overlong encodings, surrogate codepoints, and truncated sequences
// all fail -- deliberately conservative, since anything it accepts is
// embedded verbatim into a pipe-delimited output field (post-sof()).
inline bool is_valid_utf8_printable(const std::vector<std::uint8_t>& bytes) {
    std::size_t i = 0;
    while (i < bytes.size()) {
        const std::uint8_t c = bytes[i];
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f)
                return false; // C0 control / DEL
            ++i;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x1F) << 6) |
                                     (bytes[i + 1] & 0x3F);
            if (cp < 0x80)
                return false; // overlong
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80 ||
                (bytes[i + 2] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x0F) << 12) |
                                     (static_cast<std::uint32_t>(bytes[i + 1] & 0x3F) << 6) |
                                     (bytes[i + 2] & 0x3F);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
                return false; // overlong or surrogate
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80 ||
                (bytes[i + 2] & 0xC0) != 0x80 || (bytes[i + 3] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x07) << 18) |
                                     (static_cast<std::uint32_t>(bytes[i + 1] & 0x3F) << 12) |
                                     (static_cast<std::uint32_t>(bytes[i + 2] & 0x3F) << 6) |
                                     (bytes[i + 3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF)
                return false; // overlong or out of range
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}
} // namespace detail

// Converts a raw Ssid 'ay' byte vector to a display string: empty -> the
// same "<hidden>" marker the nmcli/airport legs use; valid printable UTF-8
// passes through as-is; anything else (a binary or non-printable SSID is
// legal 802.11) becomes a lossless `<hex:...>` marker rather than mangling
// raw bytes into the pipe-delimited record.
inline std::string ssid_bytes_to_display(const std::vector<std::uint8_t>& ssid_bytes) {
    if (ssid_bytes.empty())
        return "<hidden>";
    if (detail::is_valid_utf8_printable(ssid_bytes))
        return std::string(ssid_bytes.begin(), ssid_bytes.end());
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex = "<hex:";
    hex.reserve(5 + ssid_bytes.size() * 2 + 1);
    for (auto b : ssid_bytes) {
        hex += kHexDigits[(b >> 4) & 0xF];
        hex += kHexDigits[b & 0xF];
    }
    hex += '>';
    return hex;
}

// 2.4GHz / 5GHz / 6GHz centre frequency (MHz) -> 802.11 channel number,
// same mapping nmcli's own CHAN column encodes. Returns "0" when the
// frequency doesn't land on a known band/step -- never fabricates a
// channel number for an unrecognised value.
inline std::string frequency_to_channel(std::uint32_t frequency_mhz) {
    if (frequency_mhz == 2484)
        return "14"; // 2.4GHz channel 14 (Japan-only; off the regular 5MHz grid)
    if (frequency_mhz >= 2412 && frequency_mhz <= 2472 && (frequency_mhz - 2407) % 5 == 0)
        return std::to_string((frequency_mhz - 2407) / 5); // 2.4GHz channels 1-13
    if (frequency_mhz == 5935)
        return "2"; // 6GHz preferred-scanning-channel edge case (not on the 5955+ grid)
    if (frequency_mhz >= 5955 && frequency_mhz <= 7115 && (frequency_mhz - 5950) % 5 == 0)
        return std::to_string((frequency_mhz - 5950) / 5); // 6GHz
    if (frequency_mhz >= 5000 && frequency_mhz <= 5895 && (frequency_mhz - 5000) % 5 == 0)
        return std::to_string((frequency_mhz - 5000) / 5); // 5GHz
    return "0";
}

// NM80211ApSecurityFlags WpaFlags/RsnFlags -> the plugin's SECURITY column
// vocabulary. The bit values below are transcribed from NetworkManager's own
// shipped `libnm/nm-dbus-interface.h` (NM 1.52), not inferred.
//
// Ordering is most-specific-first, and deliberately matches what the nmcli
// rung-2 fallback prints in the same column, so a host that degrades from
// D-Bus to nmcli does not silently change an AP's reported security:
//   802.1X (enterprise, either flag word) > SAE/WPA3 > OWE > WPA2 > WPA1 > NONE.
//
// Known limit, unchanged: this cannot distinguish a WEP-only AP from a
// genuinely open one -- WEP is signalled by the AP's `Flags`/PRIVACY bit, a
// property this plugin does not read (out of the spec's requested property
// list). An open AP and a WEP AP both report NONE.
inline std::string nm_security_flags_to_string(std::uint32_t wpa_flags, std::uint32_t rsn_flags) {
    constexpr std::uint32_t kKeyMgmt8021X = 0x200; // NM_802_11_AP_SEC_KEY_MGMT_802_1X
    constexpr std::uint32_t kKeyMgmtSae = 0x400;   // NM_802_11_AP_SEC_KEY_MGMT_SAE (WPA3-Personal)
    constexpr std::uint32_t kKeyMgmtOwe = 0x800;   // NM_802_11_AP_SEC_KEY_MGMT_OWE (enhanced open)
    constexpr std::uint32_t kKeyMgmtOweTm = 0x1000; // NM_802_11_AP_SEC_KEY_MGMT_OWE_TM
    const std::uint32_t either = wpa_flags | rsn_flags;
    if ((either & kKeyMgmt8021X) != 0)
        return "802.1X";
    // Without this, a WPA3-Personal AP reported as "WPA2" -- a security
    // downgrade in the operator's own audit view, and a disagreement with
    // the nmcli leg, which prints WPA3.
    if ((either & kKeyMgmtSae) != 0)
        return "WPA3";
    if ((either & (kKeyMgmtOwe | kKeyMgmtOweTm)) != 0)
        return "OWE";
    if (rsn_flags != 0)
        return "WPA2";
    if (wpa_flags != 0)
        return "WPA1";
    // "Open", NOT "NONE": the nmcli, airport and system_profiler legs all
    // render an unsecured AP as "Open" (see parse_nmcli_wifi_list,
    // parse_airport_scan, parse_system_profiler_wifi). Emitting "NONE" here
    // would mean the SAME access point changed its reported security string
    // purely because the host degraded from D-Bus to nmcli -- exactly the
    // cross-rung inconsistency the ordering above exists to prevent.
    return "Open";
}

// ── argv vectors, as pure data ────────────────────────────────────────────
//
// The exact command lines are built here rather than inline at the call
// sites so a unit test can assert them without spawning anything. Two
// invariants this buys, both of which were previously unguarded:
//
//   1. NO INTERPRETER. The whole point of this migration is that wifi
//      reaches rung 2 (direct argv) and never rung 3 (a shell). The repo's
//      lexical CI gate does NOT catch a regression here: it scans for raw
//      spawn TOKENS (popen/system/fork/CreateProcess), and a
//      {"/bin/sh","-c",...} payload handed to the shared bounded runner
//      sails straight past it -- confirmed by deliberately injecting that
//      exact shape and watching the gate report clean. A test over these
//      builders is the guard.
//   2. FIELD NAMES THAT REALLY EXIST. The `connected` fallback shipped an
//      argv whose fields `nmcli device show` rejects outright, and nothing
//      caught it because no test ever looked at the argv. Pinning the
//      vector makes the field set reviewable and diffable.
//
// `tool` is the absolute path resolved by probe_tool_path (empty when the
// tool is absent -- the runner rejects that as a spawn_error, which the
// caller then reports honestly).
inline std::vector<std::string> nmcli_wifi_list_argv(std::string_view tool) {
    return {std::string{tool}, "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN,BSSID",
            "device",          "wifi", "list"};
}

// Field set verified valid against live nmcli 1.52.1; see
// parse_nmcli_wifi_list_active for why `device show` cannot be used.
inline std::vector<std::string> nmcli_connected_argv(std::string_view tool) {
    return {std::string{tool}, "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY,BSSID,DEVICE",
            "device",          "wifi", "list"};
}

inline std::vector<std::string> iw_dev_argv(std::string_view tool) {
    return {std::string{tool}, "dev"};
}

inline std::vector<std::string> iwlist_scan_argv(std::string_view tool, std::string_view iface) {
    if (!is_safe_iface_name(iface))
        return {};
    return {std::string{tool}, std::string{iface}, "scan"};
}

inline std::vector<std::string> iwconfig_argv(std::string_view tool) {
    return {std::string{tool}};
}

// True when argv[0] names a command interpreter, i.e. the vector would be
// rung 3 under ADR-3002 Decision 5 rather than the rung 2 this plugin
// declares. Used by the tests to pin the zero-shell invariant.
inline bool argv_invokes_interpreter(const std::vector<std::string>& argv) {
    if (argv.empty())
        return false;
    std::string_view exe = argv[0];
    if (auto slash = exe.find_last_of('/'); slash != std::string_view::npos)
        exe = exe.substr(slash + 1);
    for (std::string_view shell : {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
                                   "powershell", "pwsh", "cmd", "cmd.exe", "osascript", "python",
                                   "python3", "perl", "ruby", "env"}) {
        if (exe == shell)
            return true;
    }
    // A `-c` payload is the other half of the rung-3 signature.
    for (const auto& a : argv) {
        if (a == "-c" || a == "-Command" || a == "/c")
            return true;
    }
    return false;
}

// Did an argv rung actually ANSWER the question, or did it merely fail?
//
// This is the difference between "the tool ran and told us there is no Wi-Fi
// connection" and "no tool ever produced an answer". Only the first justifies
// emitting a definitive `connected|none|Not connected` / empty-scan record.
//
// The distinction cannot be read off `forward_runner_failure` alone:
// `classify_runner_failure` deliberately returns nullopt for
// TerminationReason::exited, because whether a nonzero exit is an error is the
// caller's domain (ADR-3002 leaves exit-code semantics to the plugin). For
// wifi, a nonzero exit from nmcli/iw/iwlist/iwconfig means the query FAILED --
// it is never evidence of an absent network. Without this, a host where nmcli
// and iwconfig both exit nonzero reports a confident "Not connected" while
// nothing was actually determined: the fabricated-success class that shipped
// twice in Wave 3 (BitLocker encryption state, firewall false-safe "inactive").
//
// `exited` + exit_code == 0 is the only outcome that answers the question.
// spawn_error (tool absent), deadline, cancelled, signaled and any nonzero
// exit are all "unknown", never "negative".
struct WifiToolVerdict {
    bool answered = false; // the tool ran to completion and succeeded
};

template <typename SubprocessResultT>
inline WifiToolVerdict wifi_tool_answered(const SubprocessResultT& r) {
    using RT = decltype(r.termination_reason);
    return WifiToolVerdict{r.termination_reason == RT::exited && r.exit_code == 0};
}

// Assembles a list_networks row from one AP's raw properties, applying the
// same "<hidden>"/"-" defaults the nmcli/airport legs use so all three
// list_networks sources emit byte-compatible records.
inline WifiNetworkRow nm_ap_to_row(const NmAccessPointProps& ap) {
    WifiNetworkRow row;
    row.ssid = ssid_bytes_to_display(ap.ssid_bytes);
    row.signal = std::to_string(ap.strength);
    row.security = nm_security_flags_to_string(ap.wpa_flags, ap.rsn_flags);
    row.channel = frequency_to_channel(ap.frequency_mhz);
    row.bssid = ap.hw_address.empty() ? "-" : ap.hw_address;
    return row;
}

// Assembles a connected row from the active AP's raw properties plus the
// owning device's Interface name. `interface_name` fills the column nmcli's
// leg sources from GENERAL.CONNECTION (the connection profile's display
// name) -- the D-Bus leg uses the device's Interface property instead
// (e.g. "wlan0"), a deliberate scope decision: the spec's D-Bus property
// list for `connected` never named an ActiveConnection/Id hop, and adding
// one would grow the bounded call sequence beyond what's in the
// type-signature table. See the package report's deviations section.
inline WifiConnectedRow nm_ap_to_connected_row(const NmAccessPointProps& ap,
                                               const std::string& interface_name) {
    WifiConnectedRow row;
    row.ssid = ssid_bytes_to_display(ap.ssid_bytes);
    row.signal = std::to_string(ap.strength);
    row.security = nm_security_flags_to_string(ap.wpa_flags, ap.rsn_flags);
    row.bssid = ap.hw_address.empty() ? "-" : ap.hw_address;
    row.connection = interface_name.empty() ? "-" : interface_name;
    return row;
}

} // namespace yuzu::wifi
