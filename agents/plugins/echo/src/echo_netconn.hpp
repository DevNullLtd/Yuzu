#pragma once

/**
 * echo_netconn.hpp — pure helpers for the `netconn` connectivity-transition
 * source (ADR-0020).
 *
 * The Windows reader (echo_netconn_win.cpp) renders OS-retained event-log
 * records to XML and hands each one to parse_netconn_event_xml(), which maps
 * the (channel, event id) pair to a closed action token and extracts ONLY the
 * allow-listed enum/numeric fields. Everything here is pure (no platform
 * headers, no I/O) so the whole derivation unit-tests on every host against
 * captured event-XML fixtures.
 *
 * PRIVACY INVARIANT — the parser is an ALLOW-LIST: the only <Data> fields it
 * ever reads are Category, Capability, CapabilityChangeReason and ReasonCode
 * (all numeric enums). SSID, BSSID, profile Name/Description, InterfaceGuid,
 * IfLuid and every other free-text field are structurally unreachable — there
 * is no generic "copy all fields" path — and the raw XML never leaves the
 * reader. Pinned by test_echo_netconn.cpp's fixture tests.
 */

#include "echo_db.hpp" // NetConnRow

#include <charconv>
#include <cstdint>
#include <cstdio> // std::snprintf (format_event_systemtime)
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::echo {

/// Per-channel cap on backfilled events per read (a Wi-Fi flap storm or NCSI
/// chatter must bound the work; row-count retention is the storage backstop).
inline constexpr std::size_t kNetConnPerChannelCap = 5000;
/// First-run backfill lookback DEFAULT (netconn_lookback_seconds). The OS
/// channels are ~1MB circular, so this is an upper bound on intent, not a
/// promise of depth. Operator-configurable; 0 = forward-only (no pre-enablement
/// read) for jurisdictions/works-councils where retrospective collection is not
/// permitted (ADR-0020 privacy note).
inline constexpr std::int64_t kNetConnLookbackS = 7 * 24 * 3600;
/// Ceiling for netconn_lookback_seconds (90 days). A configured value is clamped
/// to [0, this] so a fat-fingered bound can neither request an unbounded window
/// nor go negative.
inline constexpr std::int64_t kNetConnLookbackMaxS = 90LL * 24 * 3600;

/// PURE: clamp a configured lookback to [0, kNetConnLookbackMaxS]. The single
/// home for the bound — both do_configure (persist) and the read helper
/// (defensive re-clamp) route through here so a stored value and its effect
/// always agree.
inline std::int64_t nq_clamp_lookback(std::int64_t seconds) {
    if (seconds < 0)
        return 0;
    if (seconds > kNetConnLookbackMaxS)
        return kNetConnLookbackMaxS;
    return seconds;
}

/// What the netconn leg should read this tick.
struct NetConnReadPlan {
    bool read{false};    ///< true => call backfill_netconn_events(from, to)
    std::int64_t from{0};
    std::int64_t to{0};
    std::int64_t hwm{0}; ///< high-water mark to persist (immediately when !read;
                         ///< after a successful read otherwise)
};

/// PURE: decide the netconn read window.
///  - No hwm yet (first read): retrospective window [now - lookback, now).
///    lookback == 0 makes it empty (FORWARD-ONLY — the documented privacy mode):
///    read nothing, but still seed hwm = now so forward reads begin next tick.
///  - Hwm present: incremental forward window [hwm, now).
/// An empty or backward window (from >= now — lookback 0, or a backward clock
/// step) reads nothing yet ALWAYS advances the hwm to now, so the source can
/// never wedge itself re-reading an empty window forever. This is the guard the
/// forward-only mode depends on: a persisted netconn_lookback_seconds=0 skips
/// the retrospective read entirely and the source records only forward.
inline NetConnReadPlan nq_netconn_plan(bool have_hwm, std::int64_t hwm, std::int64_t lookback,
                                       std::int64_t now) {
    NetConnReadPlan p;
    p.to = now;
    // NEVER move an established mark backward. A backward wall-clock step (NTP
    // step, VM snapshot restore, manual clock change) can make `hwm > now`; if
    // we then persisted `now` we would rewind the mark and, once the clock
    // advanced past the old hwm, re-read and re-INSERT events already stored
    // (netconn_live has no dedup) — duplicating the very presence signal the
    // table is analysed for. So the seeded mark is max(hwm, now) when a mark
    // exists; a fresh source (no hwm) seeds `now`.
    p.hwm = (have_hwm && hwm > now) ? hwm : now;
    const std::int64_t from = have_hwm ? hwm : now - nq_clamp_lookback(lookback);
    if (from < now) {
        p.read = true;
        p.from = from;
    }
    return p;
}

namespace netconn_detail {

/// Value of the first XML attribute named `attr` inside the first element
/// named `elem` (EvtRender XML uses single-quoted attributes). Empty on miss.
inline std::string_view xml_elem_attr(std::string_view xml, std::string_view elem,
                                      std::string_view attr) {
    const auto epos = xml.find("<" + std::string(elem));
    if (epos == std::string_view::npos)
        return {};
    const auto close = xml.find('>', epos);
    if (close == std::string_view::npos)
        return {};
    auto tag = xml.substr(epos, close - epos);
    const auto apos = tag.find(std::string(attr) + "='");
    if (apos == std::string_view::npos)
        return {};
    tag.remove_prefix(apos + attr.size() + 2);
    const auto end = tag.find('\'');
    return end == std::string_view::npos ? std::string_view{} : tag.substr(0, end);
}

/// Text content of the first element named `elem` (e.g. <EventID>4042</EventID>).
inline std::string_view xml_elem_text(std::string_view xml, std::string_view elem) {
    const auto open = "<" + std::string(elem) + ">";
    const auto opos = xml.find(open);
    if (opos == std::string_view::npos)
        return {};
    const auto start = opos + open.size();
    const auto end = xml.find("</" + std::string(elem) + ">", start);
    return end == std::string_view::npos ? std::string_view{} : xml.substr(start, end - start);
}

/// Text content of <Data Name='name'>...</Data>. THE allow-list gate: parse
/// call sites only ever pass the four numeric-enum field names.
inline std::string_view xml_data_value(std::string_view xml, std::string_view name) {
    const auto open = "<Data Name='" + std::string(name) + "'>";
    const auto opos = xml.find(open);
    if (opos == std::string_view::npos)
        return {};
    const auto start = opos + open.size();
    const auto end = xml.find("</Data>", start);
    return end == std::string_view::npos ? std::string_view{} : xml.substr(start, end - start);
}

inline std::int64_t to_i64(std::string_view s, std::int64_t fallback = 0) {
    std::int64_t v = fallback;
    std::from_chars(s.data(), s.data() + s.size(), v);
    return v;
}

/// Days-from-civil (Howard Hinnant's algorithm) — pure UTC calendar → epoch
/// days, valid for the whole event-log era.
inline std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);              // [0, 399]
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;    // [0, 365]
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;             // [0, 146096]
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

} // namespace netconn_detail

/// Parse an ISO-8601 UTC timestamp as rendered by EvtRender / wevtutil
/// ('2026-07-03T13:35:23.8124269Z') into Unix epoch seconds (fraction
/// truncated). Returns 0 on any shape mismatch — a zero ts fails every
/// `ts >= from && ts < before` window check, so a malformed record is dropped,
/// never mis-filed.
inline std::int64_t parse_event_systemtime(std::string_view s) {
    // Minimal fixed shape: YYYY-MM-DDTHH:MM:SS
    if (s.size() < 19 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':')
        return 0;
    using netconn_detail::to_i64;
    const auto y = to_i64(s.substr(0, 4), -1);
    const auto mo = to_i64(s.substr(5, 2), -1);
    const auto d = to_i64(s.substr(8, 2), -1);
    const auto h = to_i64(s.substr(11, 2), -1);
    const auto mi = to_i64(s.substr(14, 2), -1);
    const auto sec = to_i64(s.substr(17, 2), -1);
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 ||
        mi > 59 || sec < 0 || sec > 60)
        return 0;
    return netconn_detail::days_from_civil(y, static_cast<unsigned>(mo),
                                           static_cast<unsigned>(d)) *
               86400 +
           h * 3600 + mi * 60 + sec;
}

/// Format epoch seconds as the ISO-8601 UTC literal EvtQuery XPath compares
/// @SystemTime against ('2026-07-03T13:35:23.000Z'). Inverse of the parser
/// (fraction fixed at .000) — round-trip pinned in tests.
inline std::string format_event_systemtime(std::int64_t epoch_s) {
    if (epoch_s < 0)
        epoch_s = 0;
    std::int64_t days = epoch_s / 86400;
    std::int64_t rem = epoch_s % 86400;
    // Civil-from-days (inverse of days_from_civil).
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp + (mp < 10 ? 3 : -9);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02lld:%02lld:%02lld.000Z",
                  static_cast<long long>(y + (m <= 2)), m, d,
                  static_cast<long long>(rem / 3600), static_cast<long long>((rem % 3600) / 60),
                  static_cast<long long>(rem % 60));
    return buf;
}

/// PURE: one rendered event XML → one NetConnRow (snapshot_id left 0 for the
/// caller). nullopt for any (channel, event id) pair outside the mapping table
/// or an unparsable timestamp. `channel_tag` is the reader's own token
/// (networkprofile/ncsi/wlan) — trusted, not parsed out of the XML.
inline std::optional<NetConnRow> parse_netconn_event_xml(std::string_view channel_tag,
                                                         std::string_view xml) {
    using namespace netconn_detail;

    const auto id = to_i64(xml_elem_text(xml, "EventID"), -1);
    const auto ts = parse_event_systemtime(xml_elem_attr(xml, "TimeCreated", "SystemTime"));
    if (ts == 0)
        return std::nullopt;

    NetConnRow row;
    row.ts = ts;
    row.channel = std::string(channel_tag);

    if (channel_tag == "networkprofile") {
        if (id == 10000)
            row.action = "connected";
        else if (id == 10001)
            row.action = "disconnected";
        else
            return std::nullopt;
        // NLM_NETWORK_CATEGORY: 0=public, 1=private, 2=domain.
        switch (to_i64(xml_data_value(xml, "Category"), -1)) {
        case 0: row.category = "public"; break;
        case 1: row.category = "private"; break;
        case 2: row.category = "domain"; break;
        default: break; // absent/unknown -> ""
        }
        return row;
    }

    if (channel_tag == "ncsi") {
        if (id != 4042)
            return std::nullopt;
        row.action = "capability_changed";
        // Capability enum pinned against a live 4042 capture (2 on an
        // internet-connected box); out-of-range values degrade to "".
        switch (to_i64(xml_data_value(xml, "Capability"), -1)) {
        case 0: row.capability = "none"; break;
        case 1: row.capability = "local"; break;
        case 2: row.capability = "internet"; break;
        default: break;
        }
        row.reason_code = to_i64(xml_data_value(xml, "CapabilityChangeReason"));
        return row;
    }

    if (channel_tag == "wlan") {
        if (id == 8001)
            row.action = "wifi_connected";
        else if (id == 8002)
            row.action = "wifi_connect_failed";
        else if (id == 8003)
            row.action = "wifi_disconnected";
        else
            return std::nullopt;
        row.iface_kind = "wifi";
        row.reason_code = to_i64(xml_data_value(xml, "ReasonCode"));
        return row;
    }

    return std::nullopt;
}

/// Windows reader (echo_netconn_win.cpp): EvtQuery the three operational
/// channels for events in [from_ts, before_ts) and parse them. `cap` bounds
/// rows PER CHANNEL; a missing/denied channel is warn+skip (fewer rows, never
/// an error). Empty vector off Windows. snapshot_id is the caller's to fill.
std::vector<NetConnRow> backfill_netconn_events(std::int64_t from_ts, std::int64_t before_ts,
                                                std::size_t cap = kNetConnPerChannelCap);

} // namespace yuzu::echo
