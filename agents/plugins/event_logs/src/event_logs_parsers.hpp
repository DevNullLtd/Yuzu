#pragma once

// event_logs_parsers.hpp -- pure parsing/formatting core for the event_logs
// plugin (Wave-4 PR4.2 native-acquisition migration).
//
// Everything here is a free function over strings: no I/O, no Windows or
// systemd headers, no subprocess calls -- so the whole surface is
// fixture-testable on every CI host (the users plugin's
// users_win_events.hpp precedent, Wave-2 WP-A). The OS-facing shells live in
// event_logs_plugin.cpp (wevtapi / journalctl argv / `log show`) and
// event_logs_journal.hpp (sd_journal); they hand captured text to this
// header and emit whatever it returns.
//
// Two halves:
//   * Windows rendered-event XML  -- EvtRenderEventXml output -> WinEvent
//     structs -> the plugin's existing pipe-delimited rows.
//   * journal rows                -- field/line values from sd_journal or
//     `journalctl -o short-iso` -> the existing Linux pipe rows.
//
// Every untrusted field (provider names, unit names, log messages) is routed
// through yuzu::util::safe_output_field before joining a pipe-delimited row
// (PR1.2 sanitizer) -- the previous shell-out implementation emitted raw
// message text, so an event whose message contained '|' or a newline could
// forge extra fields/rows. That hardening is a deliberate, disclosed
// behaviour change of this migration.

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field, yuzu::util::icontains

namespace yuzu::event_logs_parsers {

// ── numeric parameter clamp ─────────────────────────────────────────────────

// Parses `raw` as a base-10 integer; empty/invalid input yields `def`, and
// the result is clamped to [lo, hi]. Replaces the previous std::stoi +
// catch(...) blocks with an exception-free parse whose edge cases are
// fixture-tested. Trailing garbage after digits ("12x") counts as invalid,
// matching what the old stoi paths accepted only by accident.
inline int clamp_int_param(std::string_view raw, int def, int lo, int hi) {
    int value = def;
    if (!raw.empty()) {
        int parsed = 0;
        const char* first = raw.data();
        const char* last = raw.data() + raw.size();
        auto [ptr, ec] = std::from_chars(first, last, parsed, 10);
        if (ec == std::errc{} && ptr == last)
            value = parsed;
    }
    return std::clamp(value, lo, hi);
}

// ── shared field helpers ────────────────────────────────────────────────────

// The plugin's long-standing per-field display bound: messages are capped at
// 200 characters (the PowerShell leg's [Math]::Min(200, ...) and the Linux
// leg's substr(0, 200) both enforced it before this migration).
inline constexpr std::size_t kMessageDisplayCap = 200;

inline std::string truncate_field(std::string_view value,
                                  std::size_t cap = kMessageDisplayCap) {
    if (value.size() <= cap)
        return std::string(value);
    // Back off to a UTF-8 character boundary. `cap` is a BYTE index, and log
    // messages are routinely non-ASCII (Windows event parameters are
    // provider-localized; journal MESSAGE is arbitrary UTF-8), so cutting at a
    // raw byte can split a multi-byte sequence and emit invalid UTF-8 —
    // which the server's Postgres-backed response store rejects, losing the
    // whole result rather than one character. The PowerShell leg this replaces
    // capped at 200 CHARACTERS ([Math]::Min on a .NET string). This is still a
    // BYTE cap, merely backed off to a character boundary, so a non-ASCII
    // message yields fewer than 200 characters -- a deliberate, disclosed
    // difference from the PowerShell leg, not character parity.
    // Continuation bytes are 10xxxxxx; walk back off them to the lead byte.
    std::size_t end = cap;
    while (end > 0 && (static_cast<unsigned char>(value[end]) & 0xC0) == 0x80)
        --end;
    return std::string(value.substr(0, end));
}

// ASCII case-insensitive substring test (needle empty -> true). The
// PowerShell `-like '*f*'` filter this replaces was case-insensitive, so the
// native filter stays case-insensitive too. This is the SHARED
// yuzu::util::icontains (sdk/include/yuzu/string_utils.hpp) rather than a
// fourth hand-rolled copy — same semantics on all three edge cases (empty
// needle -> true, needle longer than haystack -> false, ASCII tolower
// comparison).
using yuzu::util::icontains;

// Empty display fields render as "-" so a missing provider/timestamp cannot
// silently collapse two pipe delimiters together.
inline std::string field_or_dash(std::string_view value) {
    return value.empty() ? std::string("-") : std::string(value);
}

// ── Windows rendered-event XML ──────────────────────────────────────────────

// One parsed <Event> block from EvtRenderEventXml output.
struct WinEvent {
    std::string time_created; // <TimeCreated SystemTime='...'/> attribute (UTC ISO-8601)
    std::string provider;     // <Provider Name='...'/> attribute
    int event_id = 0;         // <EventID> text
    int level = 4;            // <Level> text; 4 (Information) when absent
    std::string message;      // space-joined <Data> values (see parse_win_events)
};

namespace detail {

// The extractor primitives below intentionally mirror
// users_win_events.hpp::detail (Wave-2 WP-A) -- same bounded, total-over-
// malformed-input scans, kept file-local per the plugin-isolation precedent
// (tar and users each carry their own EvtGuard/extractor copies; a shared
// consolidation is a follow-up decision, not this PR's).

// Finds `open` at-or-after `from` (strictly before `limit`), then `close`
// after it (also before `limit`); on success sets [val_begin, val_end) to
// the text between them. Returns false -- out-params untouched -- on any
// miss, so every extractor below is total over malformed/truncated input.
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

// XML is a transport, not the value: rendered fields come back
// entity-escaped. Decodes the five predefined entities plus numeric
// character references (&#NN; / &#xHH;, ASCII range only); anything
// unrecognised passes through byte-for-byte rather than being dropped.
inline std::string decode_xml_entities(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] != '&') {
            out.push_back(s[i++]);
            continue;
        }
        // Longest legal entity is a numeric hex ref like "&#x10FFFF;"
        // (10 chars incl. delimiters) -- capping the ';' search avoids an
        // unbounded scan on a stray '&'.
        constexpr std::size_t kMaxEntityLen = 12;
        const std::size_t window_end = std::min(s.size(), i + kMaxEntityLen);
        // Search only INSIDE the window. A bare s.find(';', i) scans to the end
        // of the buffer and merely discards an out-of-window hit afterwards,
        // which makes a value full of stray '&' quadratic: a ~30 KB EventData
        // parameter of '&' with no ';' costs ~5e8 byte-scans per event, times
        // the 100-event cap. Bounded here, it is O(12) per '&'.
        auto semi = s.substr(0, window_end).find(';', i);
        if (semi == std::string_view::npos) {
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
                // ASCII-range only, matching the users precedent: a full
                // UTF-8 encoder is unneeded complexity here, and an
                // out-of-range ref passes through readable instead of being
                // silently dropped.
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

// Tolerant of an attribute-bearing open tag (e.g. <EventID Qualifiers='..'>)
// -- locates the tag's start, then its own '>' before searching for the
// value.
inline std::string extract_tag_text(std::string_view s, std::string_view tag, std::size_t from,
                                    std::size_t limit) {
    const std::string open_prefix = std::format("<{}", tag);
    const std::string close_tag = std::format("</{}>", tag);
    auto tag_start = s.find(open_prefix, from);
    if (tag_start == std::string_view::npos || tag_start >= limit)
        return {};
    // Reject a longer tag name sharing this prefix ("<EventIDFoo") -- the
    // byte after the prefix must be '>' or an attribute separator.
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

// Single-quoted attribute value inside one empty-element-or-open tag, e.g.
// <TimeCreated SystemTime='...'/> or <Provider Name='...' Guid='...'/>.
// Locates `tag_open`, bounds the search to that one tag's '>' so a later,
// unrelated attribute can't be matched.
inline std::string extract_attr_value(std::string_view s, std::string_view tag_open,
                                      std::string_view attr_open, std::size_t from,
                                      std::size_t limit) {
    auto tag_start = s.find(tag_open, from);
    if (tag_start == std::string_view::npos || tag_start >= limit)
        return {};
    auto tag_end = s.find('>', tag_start);
    if (tag_end == std::string_view::npos || tag_end > limit)
        return {};
    std::size_t vb = 0, ve = 0;
    if (!find_between(s, attr_open, "'", tag_start, tag_end, vb, ve))
        return {};
    return decode_xml_entities(s.substr(vb, ve - vb));
}

// Space-joins the text values of every <Data ...>...</Data> element between
// [from, limit), decoding entities, skipping empty values, and stopping once
// `byte_cap` joined bytes have been collected (a rendered event can carry
// arbitrarily large EventData; the display row is capped at 200 chars anyway,
// so collecting more than ~1 KiB here is waste). Handles the named
// (<Data Name='k'>v</Data>), bare (<Data>v</Data>), and empty-element
// (<Data/>) forms.
inline std::string collect_data_values(std::string_view s, std::size_t from, std::size_t limit,
                                       std::size_t byte_cap = 1024) {
    std::string out;
    std::size_t cursor = from;
    while (cursor < limit && out.size() < byte_cap) {
        auto d = s.find("<Data", cursor);
        if (d == std::string_view::npos || d >= limit)
            break;
        const auto after = d + 5; // past "<Data"
        if (after >= s.size() || !(s[after] == '>' || s[after] == ' ' || s[after] == '/')) {
            cursor = after; // "<DataSomething" -- not a Data element
            continue;
        }
        auto tag_end = s.find('>', d);
        if (tag_end == std::string_view::npos || tag_end > limit)
            break;
        if (s[tag_end - 1] == '/') { // <Data .../> empty element
            cursor = tag_end + 1;
            continue;
        }
        auto close = s.find("</Data>", tag_end);
        if (close == std::string_view::npos || close > limit)
            break;
        std::string value = decode_xml_entities(s.substr(tag_end + 1, close - tag_end - 1));
        if (!value.empty()) {
            if (!out.empty())
                out.push_back(' ');
            const std::size_t room = byte_cap - std::min(out.size(), byte_cap);
            out.append(value.substr(0, room));
        }
        cursor = close + 7; // past "</Data>"
    }
    return out;
}

} // namespace detail

// Walks one-or-more <Event>...</Event> blocks (EvtRenderEventXml output,
// possibly concatenated), extracting the System/EventData fields this plugin
// emits. A block that never closes (truncated capture) ends the walk keeping
// the complete events already found; a block with no <EventID> is skipped
// (users precedent). Never throws.
//
// The message field is the space-joined <Data> parameter values, NOT the
// provider-formatted message string: EvtFormatMessage/publisher-metadata
// rendering has no repo precedent (the users wevtapi leg made the same
// call), and the raw parameters are the stable, provider-registration-
// independent part of the event. Disclosed as a behaviour change vs the old
// PowerShell $_.Message output.
inline std::vector<WinEvent> parse_win_events(std::string_view xml) {
    std::vector<WinEvent> out;
    constexpr std::string_view kClose = "</Event>";
    std::size_t pos = 0;
    while (true) {
        auto ev_start = xml.find("<Event", pos);
        if (ev_start == std::string_view::npos)
            break;
        // "<EventData"/"<EventID" share the prefix -- require '>' or ' '.
        if (const auto after = ev_start + 6;
            after >= xml.size() || !(xml[after] == '>' || xml[after] == ' ')) {
            pos = ev_start + 6;
            continue;
        }
        auto limit = xml.find(kClose, ev_start);
        if (limit == std::string_view::npos)
            break; // truncated block: keep what we have
        const std::string id_text = detail::extract_tag_text(xml, "EventID", ev_start, limit);
        if (!id_text.empty()) {
            WinEvent ev;
            ev.event_id = clamp_int_param(id_text, 0, 0, 1'000'000);
            ev.level = clamp_int_param(detail::extract_tag_text(xml, "Level", ev_start, limit),
                                       4, 0, 255);
            ev.time_created = detail::extract_attr_value(xml, "<TimeCreated", "SystemTime='",
                                                         ev_start, limit);
            ev.provider =
                detail::extract_attr_value(xml, "<Provider", "Name='", ev_start, limit);
            ev.message = detail::collect_data_values(xml, ev_start, limit);
            out.push_back(std::move(ev));
        }
        pos = limit + kClose.size();
    }
    return out;
}

// Display name for the numeric <Level>, matching Get-WinEvent's
// LevelDisplayName for the values it actually shows (0/LogAlways and 4 both
// display as "Information").
inline std::string win_level_display(int level) {
    switch (level) {
    case 1:
        return "Critical";
    case 2:
        return "Error";
    case 3:
        return "Warning";
    case 0:
    case 4:
        return "Information";
    case 5:
        return "Verbose";
    default:
        return std::format("Level{}", level);
    }
}

// Case-insensitive keyword filter over the derived message AND the provider
// name. The old PowerShell filter matched only $_.Message -- but that was
// the provider-formatted template text, which usually embeds the provider's
// vocabulary; with the native message being the bare parameter values, the
// provider name is matched too so an operator's "query filter=AppName"
// keeps finding that provider's events. Disclosed in the changelog.
inline bool win_event_matches(const WinEvent& ev, std::string_view filter) {
    return icontains(ev.message, filter) || icontains(ev.provider, filter);
}

// error|timestamp|event_id|source|message  (the plugin's documented shape)
inline std::string win_error_row(const WinEvent& ev) {
    return std::format("error|{}|{}|{}|{}",
                       yuzu::util::safe_output_field(field_or_dash(ev.time_created)),
                       ev.event_id,
                       yuzu::util::safe_output_field(field_or_dash(ev.provider)),
                       yuzu::util::safe_output_field(
                           field_or_dash(truncate_field(ev.message))));
}

// event|timestamp|level|event_id|source|message
inline std::string win_event_row(const WinEvent& ev) {
    return std::format("event|{}|{}|{}|{}|{}",
                       yuzu::util::safe_output_field(field_or_dash(ev.time_created)),
                       win_level_display(ev.level), ev.event_id,
                       yuzu::util::safe_output_field(field_or_dash(ev.provider)),
                       yuzu::util::safe_output_field(
                           field_or_dash(truncate_field(ev.message))));
}

// ── journal rows (sd_journal leg + journalctl argv fallback) ────────────────

struct JournalRow {
    std::string timestamp;
    std::string unit;
    std::string message;
};

// Composes the display "unit" column from journal fields, preserving the
// shape the old short-iso text parse produced ("ident[pid]" -- the
// "unit[pid]:" prefix of syslog-style lines): SYSLOG_IDENTIFIER (with [pid]
// when _PID is known) wins, then _SYSTEMD_UNIT, then "-".
inline std::string journal_unit_string(std::string_view identifier, std::string_view pid,
                                       std::string_view systemd_unit) {
    if (!identifier.empty()) {
        if (!pid.empty())
            return std::format("{}[{}]", identifier, pid);
        return std::string(identifier);
    }
    if (!systemd_unit.empty())
        return std::string(systemd_unit);
    return "-";
}

// {prefix}|timestamp|unit|message -- the plugin's existing Linux row shape.
inline std::string journal_row(std::string_view prefix, const JournalRow& row) {
    return std::format("{}|{}|{}|{}", prefix,
                       yuzu::util::safe_output_field(field_or_dash(row.timestamp)),
                       yuzu::util::safe_output_field(field_or_dash(row.unit)),
                       yuzu::util::safe_output_field(
                           field_or_dash(truncate_field(row.message))));
}

// Parses one `journalctl -o short-iso` line:
//   "YYYY-MM-DDTHH:MM:SS+ZZZZ hostname unit[pid]: message"
// Byte-compatible with the inline logic this replaces (event_logs_plugin.cpp
// pre-PR4.2): no space -> the whole line is both timestamp and message;
// hostname (second token) is skipped; "unit: message" splits on the first
// ": "; a line with no ": " keeps unit "-". Message display-capping happens
// in journal_row, not here.
inline JournalRow parse_short_iso_line(std::string_view line) {
    JournalRow row;
    auto first_space = line.find(' ');
    if (first_space == std::string_view::npos) {
        row.timestamp = std::string(line);
        row.unit = "-";
        row.message = std::string(line);
        return row;
    }
    row.timestamp = std::string(line.substr(0, first_space));
    std::string_view rest = line.substr(first_space + 1);
    auto second_space = rest.find(' ');
    if (second_space != std::string_view::npos)
        rest = rest.substr(second_space + 1); // skip hostname
    auto colon = rest.find(": ");
    if (colon != std::string_view::npos) {
        row.unit = std::string(rest.substr(0, colon));
        row.message = std::string(rest.substr(colon + 2));
    } else {
        row.unit = "-";
        row.message = std::string(rest);
    }
    return row;
}

// Case-insensitive keyword filter for journal entries (native leg's
// equivalent of `journalctl --grep`, deliberately substring -- not regex --
// semantics over the already-allowlist-sanitized filter parameter; disclosed
// in the changelog).
inline bool journal_message_matches(std::string_view message, std::string_view filter) {
    return icontains(message, filter);
}

// True when `line` starts a NEW `journalctl -o short-iso` record, i.e. it
// begins with a "YYYY-MM-DDTHH:MM:SS" timestamp.
//
// This exists because journalctl renders an entry whose MESSAGE contains a
// newline as ONE record line followed by CONTINUATION lines indented to the
// message column (verified against systemd 257 in a container: four logged
// entries, one with an embedded newline, produce five physical lines, the
// fifth indented). Treating every physical line as its own record lets any
// local process that can write to the journal forge rows: a MESSAGE of
// "start\n2026-01-01T00:00:00+0000 host sshd[1]: Accepted password for root"
// becomes a second, entirely synthetic row that an operator cannot tell from
// a real one. safe_output_field cannot prevent this — it escapes WITHIN a
// field, while the row boundary is decided by the line split upstream of it.
// The native sd_journal leg is immune (one MESSAGE is one field), so this
// only ever affected the rung-2 fallback.
inline bool is_short_iso_record_start(std::string_view line) {
    // "2026-08-24T14:53:11" — 19 chars before the zone/space.
    constexpr std::size_t kStampLen = 19;
    if (line.size() < kStampLen)
        return false;
    auto digit = [&](std::size_t i) { return line[i] >= '0' && line[i] <= '9'; };
    for (std::size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u, 11u, 12u, 14u, 15u, 17u, 18u})
        if (!digit(i))
            return false;
    return line[4] == '-' && line[7] == '-' && line[10] == 'T' && line[13] == ':' &&
           line[16] == ':';
}

// The rung-2 fallback's whole row-selection decision, as a pure function so it
// is fixture-testable — the previous inline version in the plugin shell hid
// both an ordering inversion and a false-absence bug through a full review
// round, which is exactly the argument event_logs_journalctl.hpp makes for its
// own classifier.
struct JournalSelection {
    std::vector<std::string> rows; // composed, OLDEST-first, ready to emit
    std::size_t matches = 0;       // records that passed the filter (may exceed rows.size())
};

// `newest_first_lines` is `journalctl --reverse -o short-iso` output: newest
// record first, each record's continuation lines immediately after it.
//
// Returns at most `cap` rows (0 = uncapped), selected NEWEST-first and then
// reversed so the caller emits oldest-first — matching both the native
// sd_journal leg and the pre-migration `journalctl -n N` ordering. Selecting
// newest-first is the point: taking the first `cap` matches out of a
// forward-ordered window silently returns the STALEST matches and hides the
// recent ones the query was run to find.
inline JournalSelection select_journal_rows(const std::vector<std::string>& newest_first_lines,
                                            std::string_view prefix, std::string_view filter,
                                            std::size_t cap) {
    JournalSelection sel;
    JournalRow current;
    bool have_current = false;

    auto flush = [&]() {
        if (!have_current)
            return;
        if (filter.empty() || journal_message_matches(current.message, filter)) {
            ++sel.matches;
            if (cap == 0 || sel.rows.size() < cap)
                sel.rows.push_back(journal_row(prefix, current));
        }
        have_current = false;
    };

    for (const auto& line : newest_first_lines) {
        if (line.empty())
            continue;
        if (is_short_iso_record_start(line)) {
            flush();
            current = parse_short_iso_line(line);
            have_current = true;
            continue;
        }
        // A continuation of the record above it. Fold it into that record's
        // message rather than emitting it as a row of its own; if we somehow
        // have no open record (a capture that begins mid-entry), drop it —
        // never promote it to a row.
        if (have_current) {
            std::string_view trimmed{line};
            while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
                trimmed.remove_prefix(1);
            if (!trimmed.empty()) {
                current.message.push_back(' ');
                current.message.append(trimmed);
            }
        }
    }
    flush();

    // Collected newest-first; emit oldest-first.
    std::reverse(sel.rows.begin(), sel.rows.end());
    return sel;
}


} // namespace yuzu::event_logs_parsers
