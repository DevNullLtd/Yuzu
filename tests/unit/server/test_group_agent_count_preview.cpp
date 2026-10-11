// test_group_agent_count_preview.cpp — pure-function coverage for #4033's
// shared create-group agent-count preview model (group_agent_count_preview.hpp),
// the builder REST (GET /api/v1/management-groups/agent-count-preview) and MCP
// (preview_management_group_agent_count) share (recipe Rule 1 — those two
// cannot drift from each other by construction). Fixed by adversarial review
// (#4033 follow-up): an earlier version of this comment claimed the
// /fragments/create-group-form dashboard fragment shares it too — false; the
// fragment keeps its own separate, behaviourally-equivalent inline
// implementation (dashboard_routes.cpp); it also refuses an unmatchable filter value (#5623).
//
// No httplib, no MCP, no Postgres: these are direct calls against the pure
// functions. The real facet_agent_count store-backed count is
// ResponseStore's own tested contract, not re-tested here.

#include "group_agent_count_preview.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <regex>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

TEST_CASE("mangle_column_key: lowercase, space/dash -> underscore", "[server][devices]") {
    CHECK(mangle_column_key("PID") == "pid");
    CHECK(mangle_column_key("Local Addr") == "local_addr");
    CHECK(mangle_column_key("SHA-1") == "sha_1");
    CHECK(mangle_column_key("already_lower") == "already_lower");
}

TEST_CASE("resolve_group_preview_filters: known plugin columns match by mangled key",
          "[server][devices]") {
    // procfetch's columns_for_plugin schema: Agent, PID, Name, Path, SHA-1.
    std::vector<std::pair<std::string, std::string>> fields{
        {"pid", "1234"}, {"sha_1", "deadbeef"}};
    auto filters = resolve_group_preview_filters("procfetch", fields);
    REQUIRE(filters.size() == 2);
    // col_idx is 0-based EXCLUDING the Agent column: PID is column 1 in the
    // schema (index 0 after excluding Agent), SHA-1 is column 4 (index 3).
    CHECK(filters[0].col_idx == 0);
    CHECK(filters[0].value == "1234");
    CHECK(filters[1].col_idx == 3);
    CHECK(filters[1].value == "deadbeef");
}

TEST_CASE("resolve_group_preview_filters: unrecognised key is silently skipped",
          "[server][devices]") {
    std::vector<std::pair<std::string, std::string>> fields{{"not_a_real_column", "x"}};
    auto filters = resolve_group_preview_filters("procfetch", fields);
    CHECK(filters.empty());
}

TEST_CASE("resolve_group_preview_filters: an empty value is skipped (not a real filter)",
          "[server][devices]") {
    std::vector<std::pair<std::string, std::string>> fields{{"pid", ""}};
    auto filters = resolve_group_preview_filters("procfetch", fields);
    CHECK(filters.empty());
}

TEST_CASE("group_agent_count_preview: empty filters is a genuine 0, never touches the store",
          "[server][devices]") {
    // store == nullptr would crash if the empty-filter short-circuit didn't
    // fire before any store call — the absence of a crash IS the assertion.
    auto count = group_agent_count_preview(nullptr, "cmd-1", {}, std::nullopt);
    REQUIRE(count.has_value());
    CHECK(*count == 0);
}

TEST_CASE("group_agent_count_preview: non-empty filters against an unconfigured store degrade",
          "[server][devices]") {
    std::vector<FacetFilter> filters{{0, "1234"}};
    auto count = group_agent_count_preview(nullptr, "cmd-1", filters, std::nullopt);
    CHECK_FALSE(count.has_value()); // nullopt — never a false 0
}

// #5623: the reader-side twin of the ingest exclusion (response_store.hpp). The literal
// 2048 pins the shipped bound; the helpers must agree with the constant itself.
TEST_CASE("facet_filter_value_unmatchable: strictly over 2048 bytes", "[server][devices]") {
    static_assert(kMaxFacetValueBytes == 2048);
    CHECK_FALSE(facet_filter_value_unmatchable(""));
    CHECK_FALSE(facet_filter_value_unmatchable(std::string(2047, 'a')));
    CHECK_FALSE(facet_filter_value_unmatchable(std::string(2048, 'a')));
    CHECK(facet_filter_value_unmatchable(std::string(2049, 'a')));
    // Bytes, not characters: 1025 two-byte code points is 2050 bytes.
    std::string wide;
    for (int i = 0; i < 1025; ++i)
        wide += "\xC3\xA9";
    CHECK(facet_filter_value_unmatchable(wide));
}

// A filter value no stored facet can equal because ingest rewrote the byte or split on it:
// sanitize_pg_text turns each NUL and each invalid UTF-8 byte into the 3-byte U+FFFD and
// split_output_lines splits on every LF, so a stored value never has any of the three, and
// the length ingest bounds is the SANITIZED length. A reader that measured the
// raw bytes accepted a 683-byte all-NUL value (2049 bytes sanitized, so excluded at ingest) and
// answered an exact 0; the libpq bind also C-string-truncates a NUL and matched the prefix.
TEST_CASE("facet_filter_value_unmatchable: NUL / line feed / invalid UTF-8 are unmatchable",
          "[server][devices]") {
    using namespace std::string_literals;
    // NUL in the middle, and NUL as the only content.
    CHECK(facet_filter_value_unmatchable("short\0zzz"s));
    CHECK(facet_filter_value_unmatchable("\0"s));
    CHECK(facet_filter_value_unmatchable("\0tail"s));
    CHECK(facet_filter_value_unmatchable("head\0"s));
    // 683 NULs: well under 2048 raw bytes, 2049 once ingest widens each to U+FFFD.
    CHECK(facet_filter_value_unmatchable(std::string(683, '\0')));
    // 683 x 0xFF: the same sizes through the invalid-UTF-8 route.
    CHECK(facet_filter_value_unmatchable(std::string(683, '\xFF')));
    // Invalid lead byte, stray continuation byte.
    CHECK(facet_filter_value_unmatchable("a\xFFz"s));
    CHECK(facet_filter_value_unmatchable("\x80"s));
    // Overlong encodings (C0 80 is an overlong NUL; E0 80 80 an overlong NUL; C1 BF).
    CHECK(facet_filter_value_unmatchable("\xC0\x80"s));
    CHECK(facet_filter_value_unmatchable("\xE0\x80\x80"s));
    CHECK(facet_filter_value_unmatchable("\xC1\xBF"s));
    // Surrogate code point U+D800 encoded as ED A0 80.
    CHECK(facet_filter_value_unmatchable("\xED\xA0\x80"s));
    // Above U+10FFFF (F4 90 80 80) and a bare F5 lead byte.
    CHECK(facet_filter_value_unmatchable("\xF4\x90\x80\x80"s));
    CHECK(facet_filter_value_unmatchable("\xF5\x80\x80\x80"s));
    // Truncated multibyte sequence at the end (2, 3 and 4 byte leads).
    CHECK(facet_filter_value_unmatchable("ok\xC3"s));
    CHECK(facet_filter_value_unmatchable("ok\xE2\x82"s));
    CHECK(facet_filter_value_unmatchable("ok\xF0\x9F\x98"s));
}

TEST_CASE("facet_filter_value_unmatchable: valid UTF-8 (incl. multibyte) is matchable",
          "[server][devices]") {
    CHECK_FALSE(facet_filter_value_unmatchable("plain ascii"));
    CHECK_FALSE(facet_filter_value_unmatchable("caf\xC3\xA9"));         // U+00E9
    CHECK_FALSE(facet_filter_value_unmatchable("\xE2\x82\xAC"));       // U+20AC
    CHECK_FALSE(facet_filter_value_unmatchable("\xF0\x9F\x98\x80"));  // U+1F600
    CHECK_FALSE(facet_filter_value_unmatchable("\xEF\xBF\xBD"));       // U+FFFD itself
    CHECK_FALSE(facet_filter_value_unmatchable("\xF4\x8F\xBF\xBF"));  // U+10FFFF
    // Accept-side edges (pinned to ingest by the store roundtrip in test_response_store.cpp).
    // The noncharacters and the BOM are valid UTF-8 and PostgreSQL stores them as is, so
    // ingest keeps them and a filter on one is matchable.
    CHECK_FALSE(facet_filter_value_unmatchable("\xEF\xBF\xBE"));   // U+FFFE
    CHECK_FALSE(facet_filter_value_unmatchable("\xEF\xBF\xBF"));   // U+FFFF
    CHECK_FALSE(facet_filter_value_unmatchable("\xEF\xBB\xBF"));   // BOM, U+FEFF
    CHECK_FALSE(facet_filter_value_unmatchable("a\tb"));            // TAB
    // Smallest and largest values at the boundaries of the multibyte ranges.
    CHECK_FALSE(facet_filter_value_unmatchable("\xE0\xA0\x80"));   // U+0800
    CHECK_FALSE(facet_filter_value_unmatchable("\xED\x9F\xBF"));   // U+D7FF
    CHECK_FALSE(facet_filter_value_unmatchable("\xF0\x90\x80\x80")); // U+10000
    // CR is ACCEPTED: a CR inside a value IS storable (only a trailing CR of a line's last
    // column is stripped, and the predicate judges one value without its column position).
    CHECK_FALSE(facet_filter_value_unmatchable("a\rb"));
    CHECK_FALSE(facet_filter_value_unmatchable("a\r"));
    // LF is REFUSED: ingest splits the output on '\n' before taking any value, so no stored
    // value can contain one (see the store roundtrip in test_response_store.cpp).
    CHECK(facet_filter_value_unmatchable("a\nb"));
    CHECK(facet_filter_value_unmatchable("\n"));
    CHECK(facet_filter_value_unmatchable("tail\n"));
    // A valid multibyte value of EXACTLY 2048 bytes is accepted: 1024 x U+00E9 (2 bytes
    // each), and 682 x U+20AC (3 bytes) + 2 ASCII = 2048.
    std::string two_byte;
    for (int i = 0; i < 1024; ++i)
        two_byte += "\xC3\xA9";
    REQUIRE(two_byte.size() == 2048);
    CHECK_FALSE(facet_filter_value_unmatchable(two_byte));
    std::string three_byte;
    for (int i = 0; i < 682; ++i)
        three_byte += "\xE2\x82\xAC";
    three_byte += "ab";
    REQUIRE(three_byte.size() == 2048);
    CHECK_FALSE(facet_filter_value_unmatchable(three_byte));
    CHECK(facet_filter_value_unmatchable(three_byte + "c")); // 2049
}

TEST_CASE("any_facet_filter_unmatchable: one over-bound value among valid ones refuses",
          "[server][devices]") {
    std::vector<FacetFilter> ok{{0, "1234"}, {1, std::string(2048, 'a')}};
    CHECK_FALSE(any_facet_filter_unmatchable(ok));
    CHECK_FALSE(any_facet_filter_unmatchable({}));
    std::vector<FacetFilter> bad{{0, "1234"}, {1, std::string(2049, 'a')}};
    CHECK(any_facet_filter_unmatchable(bad));
    // Position must not matter: first, middle and last of three.
    const std::string over(2049, 'a');
    std::vector<FacetFilter> first{{0, over}, {1, "x"}, {2, "y"}};
    std::vector<FacetFilter> middle{{0, "x"}, {1, over}, {2, "y"}};
    std::vector<FacetFilter> last{{0, "x"}, {1, "y"}, {2, over}};
    CHECK(any_facet_filter_unmatchable(first));
    CHECK(any_facet_filter_unmatchable(middle));
    CHECK(any_facet_filter_unmatchable(last));
    // Every value exactly at the bound: nothing to refuse.
    std::vector<FacetFilter> all_at{
        {0, std::string(2048, 'a')}, {1, std::string(2048, 'b')}, {2, std::string(2048, 'c')}};
    CHECK_FALSE(any_facet_filter_unmatchable(all_at));
    // A NUL / line feed / invalid UTF-8 value refuses just like an over-bound one, in any position.
    CHECK(any_facet_filter_unmatchable({{0, "x"}, {1, std::string("a\0b", 3)}}));
    CHECK(any_facet_filter_unmatchable({{0, "\xFF"}, {1, "y"}}));
    CHECK(any_facet_filter_unmatchable({{0, "x"}, {1, "a\nb"}}));
}

TEST_CASE("facet filter refusal text names every cause and takes no value", "[server][devices]") {
    CHECK(facet_filter_value_refusal_message().find("2048 bytes") != std::string::npos);
    CHECK(facet_filter_value_refusal_message().find("NUL") != std::string::npos);
    CHECK(facet_filter_value_refusal_message().find("line feed") != std::string::npos);
    CHECK(facet_filter_value_refusal_message().find("UTF-8") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("2048 bytes") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("NUL") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("line feed") != std::string::npos);
}

// The predicate refuses LF only (a CR is accepted), and a stored value holding a CR picked
// from the dashboard dropdown reaches the server with an LF: an agent HAS that value, so the
// text must not claim otherwise, and must not say "line break" (CR is not refused).
TEST_CASE("facet filter refusal text does not claim no agent has the value", "[server][devices]") {
    for (const auto& text : {facet_filter_value_refusal_message(),
                             facet_filter_value_refusal_remediation()}) {
        INFO(text);
        CHECK(text.find("line break") == std::string::npos);
        CHECK(text.find("cannot be matched") == std::string::npos);
        CHECK(text.find("can never") == std::string::npos);
        CHECK(text.find("never match") == std::string::npos);
        CHECK(text.find("no agent") == std::string::npos);
        CHECK(text.find("response template") == std::string::npos);
        CHECK(text.find("View") == std::string::npos); // REST/MCP text names no dashboard concept
    }
    CHECK(facet_filter_value_refusal_message().find("not supported") != std::string::npos);
    CHECK(facet_filter_value_refusal_message().find("not evaluated") != std::string::npos);
}

// Both halves start a sentence (upper case): REST and MCP carry them in separate fields, and
// the dashboard joins the message with its own provenance sentence.
TEST_CASE("facet filter refusal text reads as sentences", "[server][devices]") {
    const auto message = facet_filter_value_refusal_message();
    const auto remediation = facet_filter_value_refusal_remediation();
    REQUIRE_FALSE(message.empty());
    REQUIRE_FALSE(remediation.empty());
    CHECK(std::isupper(static_cast<unsigned char>(message.front())));
    CHECK(std::isupper(static_cast<unsigned char>(remediation.front())));
    CHECK(message.back() != '.'); // the dashboard appends ". <provenance sentence>"
}

// The REST and MCP previews check the RAW values, before the resolver skips an unknown key:
// a check on the resolved filters would let a misspelled key turn an over-bound value into an
// empty filter set and an exact 0.
TEST_CASE("any_raw_filter_value_unmatchable: independent of whether the key resolves",
          "[server][devices]") {
    const std::string over(2049, 'a');
    const std::string at(2048, 'a');
    using Fields = std::vector<std::pair<std::string, std::string>>;
    // "no_such_column" matches nothing, so the resolver drops it: the resolved set is empty.
    Fields misspelled{{"no_such_column", over}};
    CHECK(resolve_group_preview_filters("procfetch", misspelled).empty());
    CHECK_FALSE(
        any_facet_filter_unmatchable(resolve_group_preview_filters("procfetch", misspelled)));
    CHECK(any_raw_filter_value_unmatchable(misspelled));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"name", "x"}, {"no_such_column", over}}));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"name", over}}));
    CHECK_FALSE(any_raw_filter_value_unmatchable(Fields{{"no_such_column", at}, {"name", "x"}}));
    CHECK_FALSE(any_raw_filter_value_unmatchable(Fields{}));
    // NUL / line feed / invalid UTF-8 under an unrecognised key are refused the same way.
    CHECK(any_raw_filter_value_unmatchable(Fields{{"no_such_column", std::string("a\0b", 3)}}));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"no_such_column", "\xC0\x80"}}));
}

// ---------------------------------------------------------------------------
// Tripwires (#5623): the facet-filter refusal is a CALLER obligation, so two source scans keep
// a future caller from silently skipping it.
// ---------------------------------------------------------------------------

namespace {

std::string read_text(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.is_open());
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Production units (one .cpp or .hpp, plus its same-stem sibling, as one unit: a .cpp that
// calls a reader may rely on the predicate its own header supplies) that call a ResponseStore
// facet reader (`->facet_agent_count(` and friends) without referencing any of the three
// predicate entry points. response_store.{hpp,cpp} define the readers and the predicate and
// are exempt. A reader returns the exact-match answer for the value it is given, so a caller
// that skips the refusal answers an unmatchable value (over the bound, NUL, line feed, invalid
// UTF-8) with a plausible exact 0 or a prefix match. Pure over (stem -> text), so the
// self-test below can drive it with synthetic sources.
std::vector<std::string>
units_calling_facet_reader_without_refusal(const std::map<std::string, std::string>& units) {
    static const std::regex reader_call{
        R"((->|\.)facet_(agent_count|agent_ids|response_ids|line_count)\()"};
    std::vector<std::string> bad;
    for (const auto& [stem, text] : units) {
        if (stem == "response_store")
            continue;
        if (!std::regex_search(text, reader_call))
            continue;
        if (text.find("facet_filter_value_unmatchable") != std::string::npos ||
            text.find("any_facet_filter_unmatchable") != std::string::npos ||
            text.find("any_raw_filter_value_unmatchable") != std::string::npos)
            continue;
        bad.push_back(stem);
    }
    return bad;
}

} // namespace

TEST_CASE("facet reader tripwire: the scan flags a unit with no refusal and passes one with it",
          "[server][devices]") {
    CHECK(units_calling_facet_reader_without_refusal(
              {{"a", "auto n = store->facet_agent_count(id, f);"}}) ==
          std::vector<std::string>{"a"});
    CHECK(units_calling_facet_reader_without_refusal(
              {{"b", "auto n = rs.facet_line_count(id, f);"}}) == std::vector<std::string>{"b"});
    CHECK(units_calling_facet_reader_without_refusal(
              {{"c", "if (any_facet_filter_unmatchable(f)) return; store->facet_agent_ids(f);"}})
              .empty());
    CHECK(units_calling_facet_reader_without_refusal(
              {{"d", "// facet_agent_count(...) is mentioned in a comment only"}})
              .empty());
    CHECK(units_calling_facet_reader_without_refusal(
              {{"response_store", "return conn->facet_agent_count(id, f);"}})
              .empty());
}

TEST_CASE("facet reader tripwire: every production caller of a ResponseStore facet reader refuses "
          "an unmatchable value",
          "[server][devices]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::map<std::string, std::string> units;
    for (const auto& entry : std::filesystem::directory_iterator(YUZU_SERVER_SRC_DIR)) {
        const auto ext = entry.path().extension();
        if (!entry.is_regular_file() || (ext != ".cpp" && ext != ".hpp"))
            continue;
        units[entry.path().stem().string()] += read_text(entry.path());
    }
    REQUIRE(units.size() > 100); // the scan found the real tree, not an empty directory
    REQUIRE(units.count("dashboard_routes") == 1);
    // Positive control: the three call sites known today are really being scanned.
    for (const char* stem : {"dashboard_routes", "group_agent_count_preview"})
        CHECK(std::regex_search(units[stem], std::regex{R"((->|\.)facet_agent_count\()"}));
    CHECK(units_calling_facet_reader_without_refusal(units).empty());
}

// ResponseStore's counters are only exported if server.cpp seeds them; nothing else reads
// server.cpp, so a dropped seeding call would leave every metric test green while an idle
// server exported no `yuzu_server_response_facets_dropped_total` or
// `yuzu_server_response_facet_filter_refused_total` series.
TEST_CASE("response facet metrics: server.cpp still calls seed_response_facet_metrics",
          "[server][devices]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    const auto src = read_text(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    bool called = false;
    std::size_t pos = 0;
    while ((pos = src.find("seed_response_facet_metrics(", pos)) != std::string::npos) {
        const auto line_start = src.rfind('\n', pos);
        const auto first = src.find_first_not_of(" \t", line_start + 1);
        if (src.compare(first, 2, "//") != 0) {
            called = true; // a real call, not a mention in a comment
            break;
        }
        ++pos;
    }
    CHECK(called);
}
