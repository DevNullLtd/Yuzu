// test_group_agent_count_preview.cpp — pure-function coverage for #4033's
// shared create-group agent-count preview model (group_agent_count_preview.hpp),
// the builder REST (GET /api/v1/management-groups/agent-count-preview) and MCP
// (preview_management_group_agent_count) share (recipe Rule 1 — those two
// cannot drift from each other by construction). Fixed by adversarial review
// (#4033 follow-up): an earlier version of this comment claimed the
// /fragments/create-group-form dashboard fragment shares it too — false; the
// fragment keeps its own separate, behaviourally-equivalent inline
// implementation (dashboard_routes.cpp); it also refuses an over-bound filter value (#5623).
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
TEST_CASE("facet_value_exceeds_bound: strictly over 2048 bytes", "[server][devices]") {
    static_assert(kMaxFacetValueBytes == 2048);
    CHECK_FALSE(facet_value_exceeds_bound(""));
    CHECK_FALSE(facet_value_exceeds_bound(std::string(2048, 'a')));
    CHECK(facet_value_exceeds_bound(std::string(2049, 'a')));
    // Bytes, not characters: 1025 two-byte code points is 2050 bytes.
    std::string wide;
    for (int i = 0; i < 1025; ++i)
        wide += "\xC3\xA9";
    CHECK(facet_value_exceeds_bound(wide));
}

TEST_CASE("any_facet_filter_exceeds_bound: one over-bound value among valid ones refuses",
          "[server][devices]") {
    std::vector<FacetFilter> ok{{0, "1234"}, {1, std::string(2048, 'a')}};
    CHECK_FALSE(any_facet_filter_exceeds_bound(ok));
    CHECK_FALSE(any_facet_filter_exceeds_bound({}));
    std::vector<FacetFilter> bad{{0, "1234"}, {1, std::string(2049, 'a')}};
    CHECK(any_facet_filter_exceeds_bound(bad));
    // Position must not matter: first, middle and last of three.
    const std::string over(2049, 'a');
    std::vector<FacetFilter> first{{0, over}, {1, "x"}, {2, "y"}};
    std::vector<FacetFilter> middle{{0, "x"}, {1, over}, {2, "y"}};
    std::vector<FacetFilter> last{{0, "x"}, {1, "y"}, {2, over}};
    CHECK(any_facet_filter_exceeds_bound(first));
    CHECK(any_facet_filter_exceeds_bound(middle));
    CHECK(any_facet_filter_exceeds_bound(last));
    // Every value exactly at the bound: nothing to refuse.
    std::vector<FacetFilter> all_at{
        {0, std::string(2048, 'a')}, {1, std::string(2048, 'b')}, {2, std::string(2048, 'c')}};
    CHECK_FALSE(any_facet_filter_exceeds_bound(all_at));
}

TEST_CASE("facet filter refusal text names the bound and takes no value", "[server][devices]") {
    CHECK(facet_filter_value_bound_message().find("2048 bytes") != std::string::npos);
    CHECK(facet_filter_value_bound_remediation().find("2048 bytes") != std::string::npos);
}

// The dashboard shows "<message>. <remediation>." as visible text, so both halves must start
// a sentence (upper case) and the remediation must cover a template-supplied default value.
TEST_CASE("facet filter refusal text reads as sentences and covers a template default",
          "[server][devices]") {
    const auto message = facet_filter_value_bound_message();
    const auto remediation = facet_filter_value_bound_remediation();
    REQUIRE_FALSE(message.empty());
    REQUIRE_FALSE(remediation.empty());
    CHECK(std::isupper(static_cast<unsigned char>(message.front())));
    CHECK(std::isupper(static_cast<unsigned char>(remediation.front())));
    CHECK(remediation.find("response template") != std::string::npos);
    CHECK(facet_filter_value_bound_text() == message + ". " + remediation + ".");
}

// The REST and MCP previews check the RAW values, before the resolver skips an unknown key:
// a check on the resolved filters would let a misspelled key turn an over-bound value into an
// empty filter set and an exact 0.
TEST_CASE("any_raw_filter_value_exceeds_bound: independent of whether the key resolves",
          "[server][devices]") {
    const std::string over(2049, 'a');
    const std::string at(2048, 'a');
    using Fields = std::vector<std::pair<std::string, std::string>>;
    // "no_such_column" matches nothing, so the resolver drops it: the resolved set is empty.
    Fields misspelled{{"no_such_column", over}};
    CHECK(resolve_group_preview_filters("procfetch", misspelled).empty());
    CHECK_FALSE(any_facet_filter_exceeds_bound(resolve_group_preview_filters("procfetch", misspelled)));
    CHECK(any_raw_filter_value_exceeds_bound(misspelled));
    CHECK(any_raw_filter_value_exceeds_bound(Fields{{"name", "x"}, {"no_such_column", over}}));
    CHECK(any_raw_filter_value_exceeds_bound(Fields{{"name", over}}));
    CHECK_FALSE(any_raw_filter_value_exceeds_bound(Fields{{"no_such_column", at}, {"name", "x"}}));
    CHECK_FALSE(any_raw_filter_value_exceeds_bound(Fields{}));
}
