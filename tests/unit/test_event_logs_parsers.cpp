/**
 * test_event_logs_parsers.cpp -- pure parse/format helpers
 * (event_logs_parsers.hpp, Wave-4 PR4.2 native-acquisition migration).
 *
 * Every OS-facing acquisition leg (wevtapi, sd_journal, the journalctl argv
 * fallback, `log show`) hands captured text to this header and emits
 * whatever it returns -- so the decision-shaped work (XML walking, entity
 * decoding, row formatting, sanitization) is pinned here on every host, the
 * firewall_parsers.hpp/users_win_events.hpp precedent. No OS headers, no
 * I/O, no subprocess calls: this file compiles and runs unconditionally.
 */

#include "event_logs_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <format>
#include <string>
#include <vector>

using namespace yuzu::event_logs_parsers;

namespace {

// Hand-builds one <Event>...</Event> XML block matching the shape
// EvtRenderEventXml produces, trimmed to the elements parse_win_events
// reads. Passing an empty string for event_id/level/system_time/provider
// OMITS that element entirely (absence, not an empty value) so
// absence-handling cases (e.g. "Level missing -> defaults to 4", "no
// EventID -> block skipped") are directly expressible. data_fragments are
// caller-supplied raw <Data ...>...</Data> / <Data/> fragments, so every
// Data shape (named/bare/empty-element) can be exercised per test.
//
// Provenance: synthetic -- hand-built from the EvtRenderEventXml schema; no
// wevtutil-captured event_logs fixture exists yet (unlike
// users_win_events.hpp's Security-channel captures via SSH to the-rig) --
// real captures to be folded in from the-rig.
std::string make_event(std::string_view event_id, std::string_view level,
                       std::string_view system_time, std::string_view provider,
                       std::vector<std::string> data_fragments = {}) {
    std::string out = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>";
    out += "<System>";
    if (!provider.empty())
        out += std::format("<Provider Name='{}'/>", provider);
    if (!event_id.empty())
        out += std::format("<EventID>{}</EventID>", event_id);
    if (!level.empty())
        out += std::format("<Level>{}</Level>", level);
    if (!system_time.empty())
        out += std::format("<TimeCreated SystemTime='{}'/>", system_time);
    out += "</System><EventData>";
    for (const auto& d : data_fragments)
        out += d;
    out += "</EventData></Event>";
    return out;
}

// Two-event fixture standing in for a real capture (see make_event's
// provenance note above): a disk-controller error followed by a
// Service-Control-Manager warning, each shaped like a genuine System-channel
// event -- exercises EventID/Level/TimeCreated/Provider extraction and all
// three <Data> forms (named, bare, empty-element/empty-content) together.
const std::string kRealisticFixture =
    make_event("7", "2", "2026-08-14T20:10:49.1234567Z", "disk",
               {"<Data Name='ErrorCode'>0x8007045D</Data>",
                "<Data Name='Device'>\\Device\\Harddisk0</Data>"}) +
    make_event("1000", "", "2026-08-14T20:11:03.0000000Z", "Service Control Manager",
               {"<Data>Spooler &amp; Fax</Data>", "<Data/>", "<Data Name='Reason'></Data>",
                "<Data Name='Detail'>timed &lt;out&gt;</Data>"});

// Counts pipe-delimited fields in a safe_output_field-sanitized row: an
// UNESCAPED '|' (not preceded by '\') is a real field delimiter; an escaped
// "\|" is data. Mirrors the split rule the shared server decoder
// (result_parsing.hpp) applies, and test_users_win_events.cpp's own check.
int unescaped_field_count(std::string_view row) {
    int fields = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\'))
            ++fields;
    }
    return fields;
}

} // namespace

// ---------------------------------------------------------------------------
// clamp_int_param
// ---------------------------------------------------------------------------

TEST_CASE("clamp_int_param: empty/invalid/trailing-garbage input yields the default",
          "[event_logs][parsers]") {
    CHECK(clamp_int_param("", 24, 1, 720) == 24);
    CHECK(clamp_int_param("abc", 24, 1, 720) == 24);
    CHECK(clamp_int_param("12x", 24, 1, 720) == 24); // trailing garbage after valid digits
    CHECK(clamp_int_param("  5", 24, 1, 720) == 24); // leading whitespace is also invalid
}

TEST_CASE("clamp_int_param: clamps below lo and above hi", "[event_logs][parsers]") {
    CHECK(clamp_int_param("-100", 24, 1, 720) == 1);
    CHECK(clamp_int_param("0", 24, 1, 720) == 1);
    CHECK(clamp_int_param("99999", 24, 1, 720) == 720);
}

TEST_CASE("clamp_int_param: exact bounds pass through unchanged", "[event_logs][parsers]") {
    CHECK(clamp_int_param("1", 24, 1, 720) == 1);
    CHECK(clamp_int_param("720", 24, 1, 720) == 720);
    CHECK(clamp_int_param("50", 24, 1, 720) == 50);
}

// ---------------------------------------------------------------------------
// icontains (shared yuzu::util helper, re-exported by the parsers header)
// ---------------------------------------------------------------------------

TEST_CASE("icontains: case-insensitive substring match", "[event_logs][parsers]") {
    CHECK(icontains("Hello World", "world"));
    CHECK(icontains("Hello World", "WORLD"));
    CHECK(icontains("Hello World", "Hello"));
}

TEST_CASE("icontains: empty needle always matches", "[event_logs][parsers]") {
    CHECK(icontains("anything", ""));
    CHECK(icontains("", ""));
}

TEST_CASE("icontains: needle longer than haystack never matches", "[event_logs][parsers]") {
    CHECK_FALSE(icontains("ab", "abc"));
    CHECK_FALSE(icontains("", "x"));
}

TEST_CASE("icontains: a genuine miss returns false", "[event_logs][parsers]") {
    CHECK_FALSE(icontains("Hello World", "xyz"));
}

// ---------------------------------------------------------------------------
// parse_win_events
// ---------------------------------------------------------------------------

TEST_CASE("parse_win_events: empty/non-XML input yields an empty vector, never throws",
          "[event_logs][parsers]") {
    CHECK(parse_win_events("").empty());
    CHECK(parse_win_events("not xml at all").empty());
}

TEST_CASE("parse_win_events: a realistic two-event fixture extracts every field",
          "[event_logs][parsers]") {
    auto events = parse_win_events(kRealisticFixture);
    REQUIRE(events.size() == 2);

    const auto& disk = events[0];
    CHECK(disk.event_id == 7);
    CHECK(disk.level == 2);
    CHECK(disk.time_created == "2026-08-14T20:10:49.1234567Z");
    CHECK(disk.provider == "disk");
    CHECK(disk.message == "0x8007045D \\Device\\Harddisk0");

    const auto& scm = events[1];
    CHECK(scm.event_id == 1000);
    CHECK(scm.level == 4); // <Level> absent -> defaults to Information
    CHECK(scm.time_created == "2026-08-14T20:11:03.0000000Z");
    CHECK(scm.provider == "Service Control Manager");
    // bare (kept) + empty-element (skipped) + empty-content named (skipped)
    // + named entity-bearing (kept), space-joined, entity-decoded.
    CHECK(scm.message == "Spooler & Fax timed <out>");
}

TEST_CASE("parse_win_events: an attribute-bearing <EventID Qualifiers='...'> tag is parsed",
          "[event_logs][parsers]") {
    const std::string xml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='disk'/>"
        "<EventID Qualifiers='16384'>7</EventID>"
        "<TimeCreated SystemTime='t'/></System>"
        "<EventData><Data Name='Msg'>controller error</Data></EventData></Event>";
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 7);
    CHECK(events[0].message == "controller error");
}

TEST_CASE("parse_win_events: an absent <Level> defaults to 4 (Information)",
          "[event_logs][parsers]") {
    auto events = parse_win_events(make_event("1", "", "t", "prov"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].level == 4);
}

TEST_CASE("parse_win_events: space-joins named/bare/empty-element <Data> forms, skipping empties",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("1", "4", "t", "prov",
                   {"<Data Name='k'>named</Data>", "<Data>bare</Data>", "<Data/>",
                    "<Data Name='empty'></Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "named bare");
}

TEST_CASE("parse_win_events: entity decoding covers all five predefined entities + numeric refs",
          "[event_logs][parsers]") {
    const std::string xml = make_event(
        "1", "4", "t", "prov",
        {"<Data>&lt;a&gt;&amp;&apos;b&apos;&quot;c&quot;&#65;&#x42;</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "<a>&'b'\"c\"AB");
}

TEST_CASE("parse_win_events: an unrecognised entity passes through unchanged",
          "[event_logs][parsers]") {
    auto events = parse_win_events(make_event("1", "4", "t", "prov", {"<Data>weird&nbsp;name</Data>"}));
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "weird&nbsp;name");
}

TEST_CASE("parse_win_events: a truncated final block keeps the earlier complete event",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("42", "2", "t", "disk", {"<Data>complete</Data>"}) +
        "<Event xmlns='...'><System><EventID>99"; // never closes
    std::vector<WinEvent> events;
    CHECK_NOTHROW(events = parse_win_events(xml));
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 42);
}

TEST_CASE("parse_win_events: a block with no <EventID> is skipped, not fabricated",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("", "2", "t", "disk", {"<Data>orphan</Data>"}) + // no EventID at all
        make_event("42", "2", "t2", "disk", {"<Data>real</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 42);
}

TEST_CASE("parse_win_events: a leading '<EventData' text is not mistaken for the next '<Event'",
          "[event_logs][parsers]") {
    // "<EventData" shares the "<Event" prefix that the top-level block scan
    // matches on; the after-prefix guard (next byte must be '>' or ' ') must
    // reject this false match and keep scanning to find the real event.
    const std::string xml = "<EventData>stray text, not a real block</EventData>" +
                            make_event("5", "3", "t", "app", {"<Data>real</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 5);
}

// ---------------------------------------------------------------------------
// detail::collect_data_values -- byte cap
// ---------------------------------------------------------------------------

TEST_CASE("collect_data_values: stops growing at the byte cap, never exceeds it",
          "[event_logs][parsers]") {
    const std::string xml = "<EventData><Data>abcde</Data><Data>fghij</Data><Data>klmno</Data>"
                            "</EventData>";
    // cap (8) < the full joined length (17) but > one 5-byte value, so the
    // second value is partially collected and the third never reached.
    auto joined = detail::collect_data_values(xml, 0, xml.size(), /*byte_cap=*/8);
    CHECK(joined.size() == 8);
    CHECK(joined == "abcde fg");
}

TEST_CASE("collect_data_values: the default cap truncates a single oversized value",
          "[event_logs][parsers]") {
    const std::string big_value(2000, 'x');
    const std::string xml = std::format("<EventData><Data>{}</Data></EventData>", big_value);
    auto joined = detail::collect_data_values(xml, 0, xml.size()); // default byte_cap = 1024
    CHECK(joined.size() == 1024);
    // A second value after the cap is already exhausted must add nothing.
    const std::string xml_two =
        std::format("<EventData><Data>{}</Data><Data>more</Data></EventData>", big_value);
    auto joined_two = detail::collect_data_values(xml_two, 0, xml_two.size());
    CHECK(joined_two.size() == 1024);
}

// ---------------------------------------------------------------------------
// win_level_display
// ---------------------------------------------------------------------------

TEST_CASE("win_level_display: 0 and 4 both map to Information", "[event_logs][parsers]") {
    CHECK(win_level_display(0) == "Information");
    CHECK(win_level_display(4) == "Information");
}

TEST_CASE("win_level_display: documented levels 1/2/3/5", "[event_logs][parsers]") {
    CHECK(win_level_display(1) == "Critical");
    CHECK(win_level_display(2) == "Error");
    CHECK(win_level_display(3) == "Warning");
    CHECK(win_level_display(5) == "Verbose");
}

TEST_CASE("win_level_display: an unknown value formats as LevelN", "[event_logs][parsers]") {
    CHECK(win_level_display(6) == "Level6");
    CHECK(win_level_display(255) == "Level255");
}

// ---------------------------------------------------------------------------
// win_event_matches
// ---------------------------------------------------------------------------

TEST_CASE("win_event_matches: message hit, provider hit, miss, case-insensitive",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.provider = "Service Control Manager";
    ev.message = "The Spooler service entered the stopped state";
    CHECK(win_event_matches(ev, "spooler"));          // message hit, case-insensitive
    CHECK(win_event_matches(ev, "SERVICE CONTROL"));  // provider hit, case-insensitive
    CHECK_FALSE(win_event_matches(ev, "nonexistent"));
}

// ---------------------------------------------------------------------------
// win_error_row / win_event_row
// ---------------------------------------------------------------------------

TEST_CASE("win_error_row: exact shape, dashes for empty fields", "[event_logs][parsers]") {
    WinEvent ev;
    ev.event_id = 1002;
    CHECK(win_error_row(ev) == "error|-|1002|-|-");
}

TEST_CASE("win_error_row: populated fields render verbatim", "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "2026-08-14T20:10:49Z";
    ev.provider = "Disk";
    ev.event_id = 7;
    ev.message = "disk failure";
    CHECK(win_error_row(ev) == "error|2026-08-14T20:10:49Z|7|Disk|disk failure");
}

TEST_CASE("win_event_row: exact shape, dashes for empty fields (level defaults to Information)",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.event_id = 55;
    CHECK(win_event_row(ev) == "event|-|Information|55|-|-");
}

TEST_CASE("win_event_row: populated fields render verbatim", "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 9;
    ev.level = 2; // Error
    ev.message = "boom";
    CHECK(win_event_row(ev) == "event|t|Error|9|Prov|boom");
}

TEST_CASE("win_event_row: message truncated at the 200-char display cap",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.message = std::string(250, 'x');
    auto row = win_event_row(ev);
    auto last_pipe = row.rfind('|');
    REQUIRE(last_pipe != std::string::npos);
    std::string msg_field = row.substr(last_pipe + 1);
    CHECK(msg_field.size() == kMessageDisplayCap);
    CHECK(msg_field == std::string(200, 'x'));
}

TEST_CASE("truncate_field: the cap never splits a multi-byte UTF-8 character",
          "[event_logs][parsers]") {
    // The cap is a BYTE index but log text is routinely non-ASCII (Windows
    // event parameters are provider-localized; journal MESSAGE is arbitrary
    // UTF-8). Cutting mid-sequence emits invalid UTF-8, which the server's
    // Postgres-backed response store rejects -- losing the WHOLE result rather
    // than one character. The PowerShell leg this replaces capped at 200
    // CHARACTERS, so a byte cut is also a silent behaviour regression.
    //
    // 'é' is 2 bytes (0xC3 0xA9). 199 ASCII bytes + 'é' puts the character
    // astride the 200-byte boundary: a naive cut keeps the lead byte 0xC3 and
    // drops its continuation byte.
    const std::string msg = std::string(199, 'a') + "\xC3\xA9" + std::string(50, 'b');
    const std::string out = truncate_field(msg, kMessageDisplayCap);

    CHECK(out.size() == 199); // backed off the split character entirely
    CHECK(out == std::string(199, 'a'));
    // No trailing lead byte left dangling.
    CHECK(static_cast<unsigned char>(out.back()) < 0x80);

    // A character that ENDS exactly on the boundary is kept whole.
    const std::string aligned = std::string(198, 'a') + "\xC3\xA9" + std::string(50, 'b');
    const std::string aligned_out = truncate_field(aligned, kMessageDisplayCap);
    CHECK(aligned_out.size() == kMessageDisplayCap);
    CHECK(aligned_out == std::string(198, 'a') + "\xC3\xA9");

    // A 3-byte character (U+20AC EURO, 0xE2 0x82 0xAC) straddling the cap.
    const std::string three = std::string(198, 'a') + "\xE2\x82\xAC" + std::string(50, 'b');
    const std::string three_out = truncate_field(three, kMessageDisplayCap);
    CHECK(three_out.size() == 198);
    CHECK(three_out == std::string(198, 'a'));
}

TEST_CASE("decode_xml_entities: a stray '&' run is bounded, not a full-buffer rescan",
          "[event_logs][parsers]") {
    // A value of '&' with no ';' anywhere: the ';' search must stay inside the
    // 12-byte entity window. Correctness pin for the bounded search (the
    // unbounded version was quadratic on attacker-influenceable event text).
    const std::string amps(4096, '&');
    const std::string decoded = yuzu::event_logs_parsers::detail::decode_xml_entities(amps);
    CHECK(decoded == amps); // every '&' passes through byte-for-byte

    // A legal entity still decodes when it sits inside the window.
    CHECK(yuzu::event_logs_parsers::detail::decode_xml_entities("a&amp;b") == "a&b");
    // A ';' beyond the window is NOT treated as an entity terminator.
    const std::string far = "&" + std::string(40, 'x') + ";";
    CHECK(yuzu::event_logs_parsers::detail::decode_xml_entities(far) == far);
}

TEST_CASE("win_event_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 3;
    ev.message = "bad|value\r\nwith newline";
    auto row = win_event_row(ev);
    // safe_output_field folds CR and LF INDIVIDUALLY to a space each (not
    // the "\r\n" pair to one), so this leaves two spaces; '|' pipe-escapes
    // to "\|".
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find("bad\\|value  with newline") != std::string::npos);
    CHECK(unescaped_field_count(row) == 6); // event|ts|level|id|provider|message
}

TEST_CASE("win_error_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 3;
    ev.message = "bad|value\r\nwith newline";
    auto row = win_error_row(ev);
    // See win_event_row's identical case above: CR and LF fold individually,
    // leaving two spaces where "\r\n" was.
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find("bad\\|value  with newline") != std::string::npos);
    CHECK(unescaped_field_count(row) == 5); // error|ts|id|provider|message
}

// ---------------------------------------------------------------------------
// journal_unit_string
// ---------------------------------------------------------------------------

TEST_CASE("journal_unit_string: ident+pid, ident-only, unit fallback, dash",
          "[event_logs][parsers]") {
    CHECK(journal_unit_string("sshd", "123", "") == "sshd[123]");
    CHECK(journal_unit_string("sshd", "", "") == "sshd");
    CHECK(journal_unit_string("", "", "cron.service") == "cron.service");
    CHECK(journal_unit_string("", "", "") == "-");
    // A pid with no identifier carries no meaning on its own -- falls
    // through to the systemd_unit / "-" tiers exactly as if pid were absent.
    CHECK(journal_unit_string("", "123", "cron.service") == "cron.service");
}

// ---------------------------------------------------------------------------
// journal_row
// ---------------------------------------------------------------------------

TEST_CASE("journal_row: exact shape, dashes for empty fields", "[event_logs][parsers]") {
    JournalRow row;
    CHECK(journal_row("error", row) == "error|-|-|-");
}

TEST_CASE("journal_row: populated fields render verbatim", "[event_logs][parsers]") {
    JournalRow row{"2026-08-14T20:10:49+0000", "sshd[123]", "session opened"};
    CHECK(journal_row("event", row) == "event|2026-08-14T20:10:49+0000|sshd[123]|session opened");
}

TEST_CASE("journal_row: message truncated at the 200-char display cap",
          "[event_logs][parsers]") {
    JournalRow row{"t", "u", std::string(250, 'y')};
    auto r = journal_row("event", row);
    auto last_pipe = r.rfind('|');
    REQUIRE(last_pipe != std::string::npos);
    CHECK(r.substr(last_pipe + 1).size() == kMessageDisplayCap);
}

TEST_CASE("journal_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    JournalRow row{"t", "u", "m|sg\r\nwith break"};
    auto r = journal_row("error", row);
    // safe_output_field folds CR and LF INDIVIDUALLY (not the "\r\n" pair to
    // one space), so this leaves two spaces; '|' pipe-escapes to "\|".
    CHECK(r.find('\r') == std::string::npos);
    CHECK(r.find('\n') == std::string::npos);
    CHECK(r.find("m\\|sg  with break") != std::string::npos);
    CHECK(unescaped_field_count(r) == 4); // error|ts|unit|message
}

// ---------------------------------------------------------------------------
// parse_short_iso_line
// ---------------------------------------------------------------------------

TEST_CASE("parse_short_iso_line: full 'ts host unit[pid]: msg' line", "[event_logs][parsers]") {
    auto row = parse_short_iso_line("2026-08-14T20:10:49+0000 myhost sshd[123]: session opened");
    CHECK(row.timestamp == "2026-08-14T20:10:49+0000");
    CHECK(row.unit == "sshd[123]");
    CHECK(row.message == "session opened");
}

TEST_CASE("parse_short_iso_line: no space -- the whole line is both timestamp and message",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("nospacehere");
    CHECK(row.timestamp == "nospacehere");
    CHECK(row.message == "nospacehere");
    CHECK(row.unit == "-");
}

TEST_CASE("parse_short_iso_line: no ': ' after the hostname leaves unit at '-'",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("2026-08-14T20:10:49+0000 myhost message with no colon-space");
    CHECK(row.timestamp == "2026-08-14T20:10:49+0000");
    CHECK(row.unit == "-");
    CHECK(row.message == "message with no colon-space");
}

TEST_CASE("parse_short_iso_line: hostname (second token) is always skipped",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("ts hostA unit[1]: msg");
    CHECK(row.timestamp == "ts");
    CHECK(row.unit == "unit[1]");
    CHECK(row.message == "msg");
    CHECK(row.unit.find("hostA") == std::string::npos);
    CHECK(row.message.find("hostA") == std::string::npos);
}

// ---------------------------------------------------------------------------
// journal_message_matches
// ---------------------------------------------------------------------------

TEST_CASE("journal_message_matches: hit, case-insensitive hit, and miss",
          "[event_logs][parsers]") {
    CHECK(journal_message_matches("Connection refused", "refused"));
    CHECK(journal_message_matches("Connection REFUSED", "refused"));
    CHECK_FALSE(journal_message_matches("all good", "refused"));
}

// ---------------------------------------------------------------------------
// Real-capture fixture
// ---------------------------------------------------------------------------

TEST_CASE("parse_win_events: real wevtutil System-channel capture round-trips "
          "- real capture (wevtutil qe System /f:xml, Windows 10 host, 2026-08-24)",
          "[event_logs][parsers]") {
    // First two events of a live `wevtutil qe System /c:3 /f:xml /rd:true`
    // capture, byte-for-byte as rendered (single-quoted attributes, named
    // <Data> values, blocks concatenated with NO separator between them --
    // the exact shape EvtRenderEventXml hands the plugin).
    constexpr std::string_view kCapture =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-IsolatedUserMode' "
        "Guid='{73a33ab2-1966-4999-8add-868c41415269}'/><EventID>2</EventID>"
        "<Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>"
        "<Keywords>0x8000400000000000</Keywords>"
        "<TimeCreated SystemTime='2026-08-24T08:40:49.8306253Z'/>"
        "<EventRecordID>22300</EventRecordID><Correlation/>"
        "<Execution ProcessID='1808' ThreadID='9944'/><Channel>System</Channel>"
        "<Computer>DESKTOP-04DNSIG</Computer><Security UserID='S-1-5-19'/></System>"
        "<EventData><Data Name='TrustletIdentity'>6</Data>"
        "<Data Name='NormalProcessId'>1808</Data><Data Name='Status'>0</Data>"
        "</EventData></Event>"
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-WindowsUpdateClient' "
        "Guid='{945a8954-c147-4acd-923f-40c45405a658}'/><EventID>19</EventID>"
        "<Version>1</Version><Level>4</Level><Task>1</Task><Opcode>13</Opcode>"
        "<Keywords>0x8000000000000018</Keywords>"
        "<TimeCreated SystemTime='2026-08-24T08:39:45.5505034Z'/>"
        "<EventRecordID>22299</EventRecordID><Correlation/>"
        "<Execution ProcessID='2788' ThreadID='13056'/><Channel>System</Channel>"
        "<Computer>DESKTOP-04DNSIG</Computer><Security UserID='S-1-5-18'/></System>"
        "<EventData><Data Name='updateTitle'>Security Intelligence Update for "
        "Microsoft Defender Antivirus - KB2267602 (Version 1.457.316.0) - Current "
        "Channel (Broad)</Data>"
        "<Data Name='updateGuid'>{b9516b54-3e40-4e0d-a7c7-875960bd737a}</Data>"
        "<Data Name='updateRevisionNumber'>200</Data>"
        "<Data Name='serviceGuid'>{9482f4b4-e343-43b6-b170-9a65bc822c77}</Data>"
        "</EventData></Event>";

    const auto events = parse_win_events(kCapture);
    REQUIRE(events.size() == 2);

    CHECK(events[0].event_id == 2);
    CHECK(events[0].level == 4);
    CHECK(events[0].provider == "Microsoft-Windows-IsolatedUserMode");
    CHECK(events[0].time_created == "2026-08-24T08:40:49.8306253Z");
    CHECK(events[0].message == "6 1808 0"); // space-joined Data values

    CHECK(events[1].event_id == 19);
    CHECK(events[1].provider == "Microsoft-Windows-WindowsUpdateClient");
    CHECK(events[1].time_created == "2026-08-24T08:39:45.5505034Z");
    CHECK(events[1].message.find("Security Intelligence Update for Microsoft Defender "
                                 "Antivirus") == 0);
    CHECK(events[1].message.find("{b9516b54-3e40-4e0d-a7c7-875960bd737a}") !=
          std::string::npos);

    // Row shape from a real event: level 4 renders as Information.
    const auto row = win_event_row(events[1]);
    CHECK(row.find("event|2026-08-24T08:39:45.5505034Z|Information|19|"
                   "Microsoft-Windows-WindowsUpdateClient|") == 0);

    // The real capture also answers the keyword-filter question an operator
    // would actually ask of it.
    CHECK(win_event_matches(events[1], "defender"));
    CHECK_FALSE(win_event_matches(events[0], "defender"));
}

// ── rung-2 fallback row selection (select_journal_rows) ─────────────────────
//
// This surface exists because the equivalent logic previously sat inline in the
// plugin's anonymous namespace, unreachable from any suite — and that untested
// inline version shipped BOTH an ordering inversion (it returned the oldest
// matches, not the newest) and a false-absence bug, through a full review round.

namespace {

// `journalctl --reverse -o short-iso` shape: newest record first. A record
// whose MESSAGE contains a newline is rendered as one record line plus
// continuation lines INDENTED to the message column (verified against
// systemd 257).
std::vector<std::string> reverse_journal_fixture() {
    return {
        "2026-08-24T14:53:14+00:00 host svc[4]: DDD last",
        "2026-08-24T14:53:13+00:00 host svc[3]: CCC start",
        "                                       2026-01-01T00:00:00+0000 evil sshd[1]: FORGED",
        "2026-08-24T14:53:12+00:00 host svc[2]: BBB second",
        "2026-08-24T14:53:11+00:00 host svc[1]: AAA first",
    };
}

} // namespace

TEST_CASE("is_short_iso_record_start: only a real timestamp starts a record",
          "[event_logs][parsers]") {
    CHECK(is_short_iso_record_start("2026-08-24T14:53:11+00:00 host svc[1]: hi"));
    // journalctl indents continuation lines under the message column.
    CHECK_FALSE(is_short_iso_record_start("            2026-01-01T00:00:00+0000 evil x[1]: no"));
    CHECK_FALSE(is_short_iso_record_start(""));
    CHECK_FALSE(is_short_iso_record_start("short"));
    CHECK_FALSE(is_short_iso_record_start("2026-08-24 14:53:11 host svc: wrong separator"));
    CHECK_FALSE(is_short_iso_record_start("20X6-08-24T14:53:11+00:00 host svc: nondigit"));
}

TEST_CASE("select_journal_rows: a multi-line message cannot forge an extra row",
          "[event_logs][parsers]") {
    // The forgery this guards: any local process can write a MESSAGE containing
    // a newline shaped like a real journal line. safe_output_field escapes
    // WITHIN a field, but the row boundary is decided by the line split above
    // it — so without continuation folding the operator sees a plausible,
    // entirely synthetic row. Four logged records must yield four rows.
    auto sel = select_journal_rows(reverse_journal_fixture(), "error", "", 0);
    REQUIRE(sel.rows.size() == 4);
    for (const auto& row : sel.rows)
        CHECK(row.rfind("error|", 0) == 0);
    // The forged text survives only as part of its real parent's message.
    std::string joined;
    for (const auto& r : sel.rows)
        joined += r + "\n";
    CHECK(joined.find("FORGED") != std::string::npos);
    // ...and never as a row of its own with the attacker's chosen timestamp.
    CHECK(joined.find("error|2026-01-01T00:00:00+0000|") == std::string::npos);
}

TEST_CASE("select_journal_rows: emits oldest-first from newest-first input",
          "[event_logs][parsers]") {
    auto sel = select_journal_rows(reverse_journal_fixture(), "error", "", 0);
    REQUIRE(sel.rows.size() == 4);
    CHECK(sel.rows.front().find("AAA first") != std::string::npos);
    CHECK(sel.rows.back().find("DDD last") != std::string::npos);
}

TEST_CASE("select_journal_rows: the cap keeps the NEWEST matches, not the oldest",
          "[event_logs][parsers]") {
    // The regression this pins: taking the first `cap` matches out of a
    // forward-ordered window returns the STALEST matches and silently discards
    // the recent ones the query was run to find.
    auto sel = select_journal_rows(reverse_journal_fixture(), "event", "", 2);
    REQUIRE(sel.rows.size() == 2);
    CHECK(sel.rows[0].find("CCC start") != std::string::npos); // oldest-first display...
    CHECK(sel.rows[1].find("DDD last") != std::string::npos);  // ...of the two NEWEST records
    CHECK(sel.matches == 4); // all four were candidates
}

TEST_CASE("select_journal_rows: the filter is a case-insensitive substring over the message",
          "[event_logs][parsers]") {
    auto sel = select_journal_rows(reverse_journal_fixture(), "event", "bbb", 0);
    REQUIRE(sel.rows.size() == 1);
    CHECK(sel.rows[0].find("BBB second") != std::string::npos);
    CHECK(sel.matches == 1);

    // A folded continuation is part of its parent's message and so is searchable.
    auto folded = select_journal_rows(reverse_journal_fixture(), "event", "FORGED", 0);
    REQUIRE(folded.rows.size() == 1);
    CHECK(folded.rows[0].find("CCC start") != std::string::npos);
}

TEST_CASE("select_journal_rows: no match yields no rows, and matches reports zero",
          "[event_logs][parsers]") {
    auto sel = select_journal_rows(reverse_journal_fixture(), "event", "nosuchtoken", 0);
    CHECK(sel.rows.empty());
    CHECK(sel.matches == 0);
}

TEST_CASE("select_journal_rows: a leading orphan continuation is dropped, never promoted",
          "[event_logs][parsers]") {
    // A capture that begins mid-entry has no open record to fold into. The
    // orphan must not become a row of its own — that is the forgery again.
    std::vector<std::string> lines{
        "        2026-01-01T00:00:00+0000 evil sshd[1]: FORGED orphan",
        "2026-08-24T14:53:11+00:00 host svc[1]: real",
    };
    auto sel = select_journal_rows(lines, "error", "", 0);
    REQUIRE(sel.rows.size() == 1);
    CHECK(sel.rows[0].find("real") != std::string::npos);
    CHECK(sel.rows[0].find("FORGED") == std::string::npos);
}

TEST_CASE("select_journal_rows: empty input is empty output, not a crash",
          "[event_logs][parsers]") {
    auto sel = select_journal_rows({}, "error", "x", 5);
    CHECK(sel.rows.empty());
    CHECK(sel.matches == 0);
}
