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
TEST_CASE("facet_filter_value_unmatchable: NUL / line break / invalid UTF-8 are unmatchable",
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
    CHECK(facet_filter_value_refusal_message().find("line break") != std::string::npos);
    CHECK(facet_filter_value_refusal_message().find("UTF-8") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("2048 bytes") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("NUL") != std::string::npos);
    CHECK(facet_filter_value_refusal_remediation().find("line break") != std::string::npos);
}

// The dashboard shows "<message>. <remediation>." as visible text, so both halves must start
// a sentence (upper case) and the remediation must cover a template-supplied default value.
TEST_CASE("facet filter refusal text reads as sentences and covers a template default",
          "[server][devices]") {
    const auto message = facet_filter_value_refusal_message();
    const auto remediation = facet_filter_value_refusal_remediation();
    REQUIRE_FALSE(message.empty());
    REQUIRE_FALSE(remediation.empty());
    CHECK(std::isupper(static_cast<unsigned char>(message.front())));
    CHECK(std::isupper(static_cast<unsigned char>(remediation.front())));
    CHECK(remediation.find("response template") != std::string::npos);
    CHECK(facet_filter_value_refusal_text() == message + ". " + remediation + ".");
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
    CHECK_FALSE(any_facet_filter_unmatchable(resolve_group_preview_filters("procfetch", misspelled)));
    CHECK(any_raw_filter_value_unmatchable(misspelled));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"name", "x"}, {"no_such_column", over}}));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"name", over}}));
    CHECK_FALSE(any_raw_filter_value_unmatchable(Fields{{"no_such_column", at}, {"name", "x"}}));
    CHECK_FALSE(any_raw_filter_value_unmatchable(Fields{}));
    // NUL / line feed / invalid UTF-8 under an unrecognised key are refused the same way.
    CHECK(any_raw_filter_value_unmatchable(Fields{{"no_such_column", std::string("a\0b", 3)}}));
    CHECK(any_raw_filter_value_unmatchable(Fields{{"no_such_column", "\xC0\x80"}}));
}
