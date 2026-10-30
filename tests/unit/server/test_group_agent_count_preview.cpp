// test_group_agent_count_preview.cpp — pure-function coverage for #4033's
// shared create-group agent-count preview model (group_agent_count_preview.hpp),
// the builder REST (GET /api/v1/management-groups/agent-count-preview) and MCP
// (preview_management_group_agent_count) share (recipe Rule 1 — those two
// cannot drift from each other by construction). Fixed by adversarial review
// (#4033 follow-up): an earlier version of this comment claimed the
// /fragments/create-group-form dashboard fragment shares it too — false; the
// fragment keeps its own separate, behaviourally-equivalent inline
// implementation (dashboard_routes.cpp), unchanged by this PR.
//
// No httplib, no MCP, no Postgres: these are direct calls against the pure
// functions. The real facet_agent_count store-backed count is
// ResponseStore's own tested contract, not re-tested here.

#include "group_agent_count_preview.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

// #4990: reads in this file are test oracles, not an operator surface, so they take no tier
// restriction (the tier itself is pinned in test_response_store.cpp / test_response_tier_filter.cpp).
namespace {
const auto kAllRows = yuzu::server::ResponseTierFilter::unrestricted_internal_consumer();
} // namespace

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
    auto count = group_agent_count_preview(nullptr, kAllRows, "cmd-1", {}, std::nullopt);
    REQUIRE(count.has_value());
    CHECK(*count == 0);
}

TEST_CASE("group_agent_count_preview: non-empty filters against an unconfigured store degrade",
          "[server][devices]") {
    std::vector<FacetFilter> filters{{0, "1234"}};
    auto count = group_agent_count_preview(nullptr, kAllRows, "cmd-1", filters, std::nullopt);
    CHECK_FALSE(count.has_value()); // nullopt — never a false 0
}

// -- unindexed_filter_keys (#5623) ------------------------------------------

TEST_CASE("unindexed_filter_keys: 2048 bytes is indexed, 2049 is not",
          "[server][devices][facets]") {
    // procfetch columns: Agent, PID, Name, Path, SHA-1 -> col_idx 0..3 map to pid..sha_1.
    const std::string at_bound(kMaxFacetValueBytes, 'z');
    const std::string over(kMaxFacetValueBytes + 1, 'z');
    REQUIRE(at_bound.size() == 2048);
    REQUIRE(over.size() == 2049);

    CHECK(unindexed_filter_keys("procfetch", {{2, at_bound}}).empty());
    const auto keys = unindexed_filter_keys("procfetch", {{2, over}});
    REQUIRE(keys.size() == 1);
    CHECK(keys[0] == "path");
    // Key names only, never the value.
    CHECK(keys[0].find("zzzz") == std::string::npos);
}

TEST_CASE("unindexed_filter_keys: no filters, or only short ones, is empty", "[server][devices][facets]") {
    CHECK(unindexed_filter_keys("procfetch", {}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{0, "1234"}, {3, "deadbeef"}}).empty());
}

TEST_CASE("unindexed_filter_keys: mangled keys, input order, de-duplicated",
          "[server][devices][facets]") {
    const std::string over(kMaxFacetValueBytes + 1, 'z');
    // SHA-1 (col_idx 3) mangles to sha_1; listed first, then pid, then sha_1 again.
    const auto keys =
        unindexed_filter_keys("procfetch", {{3, over}, {0, over}, {3, over + "y"}, {1, "short"}});
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "sha_1");
    CHECK(keys[1] == "pid");
}

TEST_CASE("unindexed_filter_keys: an unknown plugin or an out-of-range column is skipped",
          "[server][devices][facets]") {
    const std::string over(kMaxFacetValueBytes + 1, 'z');
    // An index past the end of the layout, or a negative one, resolves to no key.
    CHECK(unindexed_filter_keys("procfetch", {{99, over}}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{-1, over}}).empty());
    // An unknown plugin uses columns_for_plugin's default (Agent, Output) layout: column 0 is
    // "output", and column 1 does not exist.
    CHECK(unindexed_filter_keys("no_such_plugin", {{0, over}}) ==
          std::vector<std::string>{"output"});
    CHECK(unindexed_filter_keys("no_such_plugin", {{1, over}}).empty());
}

TEST_CASE("unindexed_filter_keys: the bound is measured on the stored (sanitized) form",
          "[server][devices][facets]") {
    // Ingest rewrites each NUL and each invalid UTF-8 byte to the 3-byte U+FFFD before it
    // measures, so 683 of them are 2049 stored bytes (excluded) and 682 are 2046 (indexed).
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(683, '\0')}}) ==
          std::vector<std::string>{"pid"});
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(683, '\xFF')}}) ==
          std::vector<std::string>{"pid"});
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(682, '\0')}}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(682, '\xFF')}}).empty());
    // Mixed: one NUL (3 stored bytes) plus 1024 two-byte characters (2048) is 2051 stored bytes.
    std::string mixed(1, '\0');
    for (int i = 0; i < 1024; ++i)
        mixed += "\xC3\xA9";
    CHECK(unindexed_filter_keys("procfetch", {{0, mixed}}) == std::vector<std::string>{"pid"});
    // Exactly on the bound with a sanitized part: 682 NULs are 2046 stored bytes, so two more
    // plain bytes make 2048 (indexed) and three make 2049 (not).
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(682, '\0') + "ab"}}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{0, std::string(682, '\0') + "abc"}}) ==
          std::vector<std::string>{"pid"});
    // A truncated multibyte lead (lone E2 82) is two invalid bytes: 6 stored bytes, so 341 of them
    // are 2046 (indexed) and 342 are 2052 (not).
    const auto trunc = [](int n) {
        std::string out;
        for (int i = 0; i < n; ++i)
            out += "\xE2\x82";
        return out;
    };
    CHECK(unindexed_filter_keys("procfetch", {{0, trunc(341)}}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{0, trunc(342)}}) == std::vector<std::string>{"pid"});
    // The raw-size shortcut: nothing at or under a third of the bound can reach it.
    CHECK_FALSE(facet_filter_value_over_bound(std::string(kMaxFacetValueBytes / 3, '\0')));
    CHECK(facet_filter_value_over_bound(std::string(kMaxFacetValueBytes / 3 + 1, '\0')));
    // A value over the bound raw stays over it (the scrub never shrinks plain ASCII).
    CHECK(facet_filter_value_over_bound(std::string(kMaxFacetValueBytes + 1, 'a')));
    CHECK_FALSE(facet_filter_value_over_bound(std::string(kMaxFacetValueBytes, 'a')));
}

TEST_CASE("unindexed_filter_keys: the bound is bytes, not characters", "[server][devices][facets]") {
    std::string over; // U+00E9 is two bytes: 1025 of them are 2050 bytes
    std::string at_bound;
    for (std::size_t i = 0; i < kMaxFacetValueBytes / 2 + 1; ++i)
        over += "\xC3\xA9";
    for (std::size_t i = 0; i < kMaxFacetValueBytes / 2; ++i)
        at_bound += "\xC3\xA9";
    REQUIRE(over.size() == kMaxFacetValueBytes + 2);
    REQUIRE(at_bound.size() == kMaxFacetValueBytes);
    CHECK(unindexed_filter_keys("procfetch", {{0, at_bound}}).empty());
    CHECK(unindexed_filter_keys("procfetch", {{0, over}}) == std::vector<std::string>{"pid"});
}

TEST_CASE("unindexed_filter_keys: composes with resolve_group_preview_filters (an unknown "
          "key never reaches it)",
          "[server][devices][facets]") {
    const std::string over(kMaxFacetValueBytes + 1, 'z');
    auto filters = resolve_group_preview_filters(
        "procfetch", {{"not_a_real_column", over}, {"name", over}, {"pid", "1"}});
    CHECK(unindexed_filter_keys("procfetch", filters) == std::vector<std::string>{"name"});
}
