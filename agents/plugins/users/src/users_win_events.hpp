// users_win_events.hpp -- pure parsers for the Windows Security-channel
// (wevtapi) logon/logoff event XML (4624/4632... 4624/4634), and the two
// decisions built on top of it: which account is the "primary user" (most
// frequent interactive TargetUserName) and the session-history row
// projection.
//
// Windows-headers-free and I/O-free by design (mirrors users_macos_last.hpp /
// tar_netconn.hpp's split): the Win32 shell (users_plugin.cpp) owns EvtQuery/
// EvtNext/EvtRender against the Security channel and hands this header the
// rendered UTF-8 XML string; every parsing and selection decision lives here
// so it is independently unit-testable on every host (test_users_win_events.cpp),
// without linking wevtapi.
//
// The XML shape parsed is EvtRender(..., EvtRenderEventXml, ...)'s per-event
// document, e.g.:
//   <Event ...><System>...<EventID>4624</EventID>...
//     <TimeCreated SystemTime='2026-08-14T20:10:49.4173297Z'/>...</System>
//   <EventData><Data Name='TargetUserName'>Alex</Data>...</EventData></Event>
// one-or-more such blocks concatenated (as wevtutil's `/f:xml` capture -- and
// a batch of individually-rendered EvtRender events fed through this parser
// one at a time -- both produce).
#pragma once

#include <algorithm>
#include <cstdlib>
#include <format>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

namespace yuzu::users_win {

struct LogonEvent {
    std::string event_id;
    std::string time_created;
    std::string target_user;
    std::string target_domain;
    std::string logon_type_raw;
    std::string workstation;
    std::string ip_address;
};

namespace detail {

// Finds `open` at-or-after `from` (and strictly before `limit`), then `close`
// after it (also before `limit`); on success sets [val_begin, val_end) to the
// text between them. Returns false -- leaving the out-params untouched -- on
// any miss, so every extractor below is total over malformed/truncated input.
inline bool find_between(std::string_view s, std::string_view open, std::string_view close,
                         std::size_t from, std::size_t limit, std::size_t& val_begin,
                         std::size_t& val_end) {
    if (from > limit || limit > s.size())
        return false;
    auto p = s.find(open, from);
    if (p == std::string_view::npos || p >= limit)
        return false;
    p += open.size();
    auto q = s.find(close, p);
    if (q == std::string_view::npos || q > limit)
        return false;
    val_begin = p;
    val_end = q;
    return true;
}

// XML is a transport, not the value: a rendered field containing `&`, `<`,
// `>`, `'`, or `"` comes back entity-escaped (e.g. a `TargetUserName` of
// "R&D" renders as "R&amp;D"), so every extractor below decodes before
// handing text to a caller. Decodes the five predefined entities plus
// numeric character references (&#NN; and &#xHH;); anything else (an
// unrecognised/malformed entity) passes through byte-for-byte rather than
// being dropped, so a decode miss degrades to "still readable", not silent
// data loss.
inline std::string decode_xml_entities(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] != '&') {
            out.push_back(s[i++]);
            continue;
        }
        // Bound the search: the longest legal entity is a numeric hex ref
        // like "&#x10FFFF;" (11 chars incl. delimiters), so a ';' beyond
        // that can't start a real entity -- capping here avoids an
        // unbounded scan (and the resulting large substr/append) on a
        // stray/malformed '&' followed eventually by an unrelated ';'.
        constexpr std::size_t kMaxEntityLen = 12;
        const std::size_t window_end = std::min(s.size(), i + kMaxEntityLen);
        auto semi = s.find(';', i);
        if (semi == std::string_view::npos || semi >= window_end) {
            out.push_back(s[i++]);
            continue;
        }
        const std::string_view entity = s.substr(i + 1, semi - i - 1);
        if (entity == "amp") {
            out.push_back('&');
        } else if (entity == "lt") {
            out.push_back('<');
        } else if (entity == "gt") {
            out.push_back('>');
        } else if (entity == "quot") {
            out.push_back('"');
        } else if (entity == "apos") {
            out.push_back('\'');
        } else if (entity.size() > 1 && entity.front() == '#') {
            const bool is_hex = entity.size() > 2 && (entity[1] == 'x' || entity[1] == 'X');
            const std::string_view digits = entity.substr(is_hex ? 2 : 1);
            char* end = nullptr;
            const std::string digits_str(digits);
            const long code = std::strtol(digits_str.c_str(), &end, is_hex ? 16 : 10);
            if (!digits.empty() && end == digits_str.c_str() + digits_str.size() && code > 0 &&
                code < 0x80) {
                // ASCII-range only: every field this parser extracts (account/
                // domain/workstation/IP names) is ASCII, and a full UTF-8
                // encoder is unneeded complexity for a range this parser never
                // sees in practice.
                out.push_back(static_cast<char>(code));
            } else {
                out.append(s.substr(i, semi - i + 1)); // unrecognised: pass through
            }
        } else {
            out.append(s.substr(i, semi - i + 1)); // unrecognised: pass through
        }
        i = semi + 1;
    }
    return out;
}

// Tolerant of an attribute-bearing open tag (e.g. some providers emit
// <EventID Qualifiers='...'>4624</EventID>, not just the bare <EventID>) --
// locates the tag's start, then its own '>' before searching for the value,
// same shape as extract_time_created's empty-element handling below.
inline std::string extract_tag_text(std::string_view s, std::string_view tag, std::size_t from,
                                    std::size_t limit) {
    const std::string open_prefix = std::format("<{}", tag);
    const std::string close_tag = std::format("</{}>", tag);
    auto tag_start = s.find(open_prefix, from);
    if (tag_start == std::string_view::npos || tag_start >= limit)
        return {};
    // Reject a longer tag name sharing this prefix (e.g. "<EventIDFoo") --
    // the byte right after the prefix must be '>' or whitespace/attribute.
    if (const auto after = tag_start + open_prefix.size();
        after >= s.size() || !(s[after] == '>' || s[after] == ' '))
        return {};
    auto tag_end = s.find('>', tag_start);
    if (tag_end == std::string_view::npos || tag_end > limit)
        return {};
    std::size_t vb = 0, ve = 0;
    if (!find_between(s, ">", close_tag, tag_end, limit, vb, ve))
        return {};
    return decode_xml_entities(s.substr(vb, ve - vb));
}

// <TimeCreated SystemTime='...'/> -- an empty-element tag, not open/close, so
// this doesn't reuse extract_tag_text: it locates the tag, bounds the search
// to that one tag's '>' (so a later, unrelated SystemTime-shaped text can't
// be matched), then reads the single-quoted attribute value inside it.
inline std::string extract_time_created(std::string_view s, std::size_t from, std::size_t limit) {
    auto tc = s.find("<TimeCreated", from);
    if (tc == std::string_view::npos || tc >= limit)
        return {};
    auto tag_end = s.find('>', tc);
    if (tag_end == std::string_view::npos || tag_end > limit)
        return {};
    std::size_t vb = 0, ve = 0;
    if (!find_between(s, "SystemTime='", "'", tc, tag_end, vb, ve))
        return {};
    return std::string(s.substr(vb, ve - vb));
}

// <Data Name='key'>value</Data> -- returns "" (not found, same as a genuinely
// empty value) when this event carries no Data element with that Name; the
// caller can't and doesn't need to tell the two apart (e.g. a 4634 event
// carries no IpAddress element at all, and formats identically to one that
// did but was blank).
inline std::string extract_data_field(std::string_view s, std::string_view name, std::size_t from,
                                      std::size_t limit) {
    const std::string open_tag = std::format("Data Name='{}'>", name);
    std::size_t vb = 0, ve = 0;
    if (!find_between(s, open_tag, "</Data>", from, limit, vb, ve))
        return {};
    return decode_xml_entities(s.substr(vb, ve - vb));
}

} // namespace detail

// Walks one-or-more <Event>...</Event> blocks in `xml`, extracting the
// System/EventData fields this plugin needs. A block that never closes (a
// truncated capture / a cut-short EvtRender buffer) simply ends the walk --
// any COMPLETE events already found are still returned, and if there are
// none, an empty vector comes back. Never throws: every field extractor
// above is a bounded, index-checked scan, not an exception-throwing parse.
inline std::vector<LogonEvent> parse_logon_events(std::string_view xml) {
    std::vector<LogonEvent> out;
    std::size_t pos = 0;
    while (true) {
        auto ev_start = xml.find("<Event", pos);
        if (ev_start == std::string_view::npos)
            break;
        auto ev_close = xml.find("</Event>", ev_start);
        if (ev_close == std::string_view::npos)
            break; // truncated mid-event -- stop, keep whatever was already parsed
        const std::size_t ev_end = ev_close + std::string_view("</Event>").size();

        LogonEvent ev;
        ev.event_id = detail::extract_tag_text(xml, "EventID", ev_start, ev_close);
        ev.time_created = detail::extract_time_created(xml, ev_start, ev_close);
        ev.target_user = detail::extract_data_field(xml, "TargetUserName", ev_start, ev_close);
        ev.target_domain = detail::extract_data_field(xml, "TargetDomainName", ev_start, ev_close);
        ev.logon_type_raw = detail::extract_data_field(xml, "LogonType", ev_start, ev_close);
        ev.workstation = detail::extract_data_field(xml, "WorkstationName", ev_start, ev_close);
        ev.ip_address = detail::extract_data_field(xml, "IpAddress", ev_start, ev_close);

        // A block with no recognisable EventID is not a usable logon record
        // (malformed/foreign content between two "<Event"/"</Event>"
        // markers) -- drop it rather than emit an all-empty row.
        if (!ev.event_id.empty())
            out.push_back(std::move(ev));

        pos = ev_end;
    }
    return out;
}

namespace detail {

// A TargetUserName this pair of functions never counts/emits: empty, the
// literal sentinels "-"/"SYSTEM", or a machine account (trailing '$').
// Verified against the prestage fixture (DESKTOP-04DNSIG$ is exactly the
// SubjectUserName the OLD text parser's identical filter was written
// against) -- TargetUserName is the field this filter belongs on now.
inline bool is_excluded_user(const std::string& name) {
    return name.empty() || name == "-" || name == "SYSTEM" || name.back() == '$';
}

} // namespace detail

// Reproduces today's primary_user selection exactly: count TargetUserName
// occurrences (excluding the sentinels above) into an ORDERED map, then pick
// via a strict `count > max_count` scan over that map. On a count TIE this
// yields the lexicographically SMALLEST name -- the ordered-map scan order,
// not first-seen order -- matching the pre-migration text parser's
// std::map<std::string,int> + linear-scan behaviour byte for byte. Returns
// {"", 0} when no event contributes a countable name.
inline std::pair<std::string, int> primary_user_from_events(
    const std::vector<LogonEvent>& events) {
    std::map<std::string, int> counts;
    for (const auto& ev : events) {
        if (detail::is_excluded_user(ev.target_user))
            continue;
        ++counts[ev.target_user];
    }

    std::string primary;
    int max_count = 0;
    for (const auto& [user, count] : counts) {
        if (count > max_count) {
            max_count = count;
            primary = user;
        }
    }
    return {primary, max_count};
}

// Projects each event to a `session_history|...` row, in query order,
// skipping events whose TargetUserName is excluded (see is_excluded_user).
// Field mapping (ENUMERATED, not inferred -- see users_win_events.hpp's
// spec companion, WP-A):
//   user        = target_user
//   event_type  = "logon" when event_id == "4624", else "logoff"
//   logon_type  = LogonType mapped to its name (2/3/4/5/7/8/9/10/11); any
//                 OTHER numeric value is passed through verbatim; an ABSENT
//                 LogonType (event carried no such Data element) formats as
//                 the EMPTY string -- not "-" -- matching the pre-migration
//                 parser's uninitialised current_logon_type field.
//   source      = ip_address ("Source Network Address" in wevtutil's text
//                 mode IS the IpAddress Data element, not WorkstationName);
//                 empty/absent -> "-"
//   time        = the TimeCreated SystemTime attribute verbatim; empty -> "-"
//   event_id    = the <EventID> text
inline std::vector<std::string> session_history_rows(const std::vector<LogonEvent>& events) {
    std::vector<std::string> out;
    out.reserve(events.size());

    for (const auto& ev : events) {
        if (detail::is_excluded_user(ev.target_user))
            continue;

        const std::string event_type = (ev.event_id == "4624") ? "logon" : "logoff";

        std::string logon_type;
        const auto& lt = ev.logon_type_raw;
        if (lt == "2")
            logon_type = "interactive";
        else if (lt == "3")
            logon_type = "network";
        else if (lt == "4")
            logon_type = "batch";
        else if (lt == "5")
            logon_type = "service";
        else if (lt == "7")
            logon_type = "unlock";
        else if (lt == "8")
            logon_type = "network_cleartext";
        else if (lt == "9")
            logon_type = "new_credentials";
        else if (lt == "10")
            logon_type = "remote_interactive";
        else if (lt == "11")
            logon_type = "cached_interactive";
        else
            logon_type = lt; // any other value verbatim; absent -> "" (lt is empty)

        const std::string source = ev.ip_address.empty() ? "-" : ev.ip_address;
        const std::string time = ev.time_created.empty() ? "-" : ev.time_created;

        // target_user/logon_type(fallback branch)/source/time/event_id all
        // originate from Security-channel event XML -- a numeric entity
        // reference (e.g. "&#124;") decodes to a literal '|'/CR/LF that would
        // otherwise corrupt this row's pipe-delimited framing, and time is raw
        // (never entity-decoded) attribute text that could itself carry an
        // unescaped '|' in malformed/adversarial input. safe_output_field is
        // the same escape this codebase already applies to other externally-
        // sourced row fields (e.g. users_plugin.cpp's macOS RealName).
        out.push_back(std::format(
            "session_history|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(ev.target_user),
            event_type, yuzu::util::safe_output_field(logon_type),
            yuzu::util::safe_output_field(source), yuzu::util::safe_output_field(time),
            yuzu::util::safe_output_field(ev.event_id)));
    }
    return out;
}

} // namespace yuzu::users_win
