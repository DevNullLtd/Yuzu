/**
 * test_software_hosts_model.cpp - pure coverage for software_hosts_model.hpp (SAM-33): the hosts
 * parameters, the scope-first search, the h1 cursor and its filter binding, the scoped page and
 * the row/response shaping. No store, no libpq, no clock, no network: every store read is a fake.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_hosts_model.hpp"

#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::software_hosts;
using yuzu::server::authz::VisibleSet;

namespace {

Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return Params(kv);
}

SoftwareHostRow host_row(std::string id) {
    SoftwareHostRow r;
    r.agent_id = std::move(id);
    r.last_seen = 1700000000;
    return r;
}

VisibleSet set_of(std::initializer_list<const char*> ids) {
    return VisibleSet{std::unordered_set<std::string>(ids.begin(), ids.end())};
}

} // namespace

TEST_CASE("parse_hosts_params: defaults, clamps and refusals", "[server][software_hosts_model]") {
    auto r = parse_hosts_params(params({}));
    REQUIRE(r);
    CHECK(r->limit == swc::kCatalogueDefaultLimit);
    CHECK(r->last_synced_before == 0);
    CHECK(r->q.empty());

    r = parse_hosts_params(params({{"limit", "999999"}, {"last_synced_before", "1700000000"}}));
    REQUIRE(r);
    CHECK(r->limit == swc::kCataloguePageMax);
    CHECK(r->last_synced_before == 1700000000);

    r = parse_hosts_params(params({{"q", std::string(500, 'a')}}));
    REQUIRE(r);
    CHECK(r->q.size() == software_catalog::kSearchMaxBytes);

    for (const char* bad : {"-1", "abc", "1.5", "1e3", " 5"})
        CHECK_FALSE(parse_hosts_params(params({{"last_synced_before", bad}})));
    CHECK_FALSE(parse_hosts_params(params({{"limit", "x"}})));
    const auto long_cursor = parse_hosts_params(params({{"cursor", std::string(swc::kCursorMaxBytes + 1, 'a')}}));
    REQUIRE_FALSE(long_cursor);
    CHECK(long_cursor.error() == "invalid cursor");
    CHECK_FALSE(parse_hosts_params(params({{"q", std::string("a\0b", 3)}})));
}

TEST_CASE("parse_hosts_params: a repeated key keeps the first value", "[server][software_hosts_model]") {
    const Params p{{"limit", "5"}, {"limit", "7"}, {"q", "alpha"}, {"q", "beta"}};
    const auto r = parse_hosts_params(p);
    REQUIRE(r);
    CHECK(r->limit == 5);
    CHECK(r->q == "alpha");
}

TEST_CASE("resolve_host_search: case-insensitive literal substring over hostname and id",
          "[server][software_hosts_model]") {
    const Roster roster{{"a1", "Web-Server_01"}, {"a2", "db%host"}, {"b-xyz", ""}, {"a4", "other"}};
    auto r = resolve_host_search("WEB-server", roster, std::nullopt);
    REQUIRE(r);
    REQUIRE(*r);
    CHECK(**r == std::unordered_set<std::string>{"a1"});

    r = resolve_host_search("XYZ", roster, std::nullopt); // matches the agent id
    REQUIRE(r);
    CHECK(**r == std::unordered_set<std::string>{"b-xyz"});

    r = resolve_host_search("%", roster, std::nullopt); // literal, not a wildcard
    REQUIRE(r);
    CHECK(**r == std::unordered_set<std::string>{"a2"});
    r = resolve_host_search("_", roster, std::nullopt);
    REQUIRE(r);
    CHECK(**r == std::unordered_set<std::string>{"a1"});

    r = resolve_host_search("nomatch", roster, std::nullopt);
    REQUIRE(r);
    REQUIRE(*r);
    CHECK((*r)->empty()); // engaged-empty, not TOP
}

TEST_CASE("resolve_host_search: empty q returns the scope unchanged", "[server][software_hosts_model]") {
    const Roster roster{{"a1", "x"}};
    auto r = resolve_host_search("", roster, std::nullopt);
    REQUIRE(r);
    CHECK_FALSE(*r);
    r = resolve_host_search("", roster, set_of({"a1"}));
    REQUIRE(r);
    CHECK(**r == std::unordered_set<std::string>{"a1"});
}

TEST_CASE("resolve_host_search: the roster is cut to scope before the cap", "[server][software_hosts_model]") {
    Roster roster;
    for (std::size_t i = 0; i <= swc::kScopePushdownMaxIds; ++i)
        roster.emplace("fleet-" + std::to_string(i), "host");
    // A confined caller with three in-scope matches gets those three though the fleet is over the cap.
    auto r = resolve_host_search("host", roster, set_of({"fleet-1", "fleet-2", "fleet-3"}));
    REQUIRE(r);
    CHECK(**r == std::unordered_set<std::string>{"fleet-1", "fleet-2", "fleet-3"});

    // A global caller's matches exceed the cap: refused.
    const auto over = resolve_host_search("host", roster, std::nullopt);
    REQUIRE_FALSE(over);
    CHECK(over.error() == "search matches too many devices; narrow q");

    // Exactly the cap is accepted; one more inside the caller's OWN scope is refused.
    std::unordered_set<std::string> own;
    for (std::size_t i = 0; i < swc::kScopePushdownMaxIds; ++i)
        own.insert("fleet-" + std::to_string(i));
    CHECK(resolve_host_search("host", roster, VisibleSet{own}));
    own.insert("fleet-" + std::to_string(swc::kScopePushdownMaxIds));
    CHECK_FALSE(resolve_host_search("host", roster, VisibleSet{own}));
}

TEST_CASE("hosts cursor: round trip and refusals", "[server][software_hosts_model]") {
    const auto rq = *parse_hosts_params(params({{"q", "web"}}));
    const auto fp = hosts_fingerprint(rq);
    const auto tok = encode_hosts_cursor("agent-9", 3, fp);
    CHECK(tok.starts_with("h1:"));
    const auto d = decode_hosts_cursor(tok, fp);
    REQUIRE(d);
    CHECK(d->first == "agent-9");
    CHECK(d->second == 3);

    CHECK(decode_hosts_cursor("d2:abc", fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_hosts_cursor("h1:zz:zz", fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_hosts_cursor(encode_hosts_cursor("a", swc::kWideScopeMaxSkip + 1, fp), fp).error() ==
          swc::CursorError::kScanLimit);
}

TEST_CASE("hosts cursor: bound to q and last_synced_before", "[server][software_hosts_model]") {
    const auto a = *parse_hosts_params(params({{"q", "web"}}));
    const auto b = *parse_hosts_params(params({{"q", "db"}}));
    const auto c = *parse_hosts_params(params({{"q", "web"}, {"last_synced_before", "5"}}));
    const auto tok = encode_hosts_cursor("x", 0, hosts_fingerprint(a));
    CHECK(decode_hosts_cursor(tok, hosts_fingerprint(b)).error() == swc::CursorError::kFilterMismatch);
    CHECK(decode_hosts_cursor(tok, hosts_fingerprint(c)).error() == swc::CursorError::kFilterMismatch);
    // limit is not part of the filter set
    auto d = a;
    d.limit = 7;
    CHECK(hosts_fingerprint(d) == hosts_fingerprint(a));

    // through the page reader too
    auto rq = b;
    rq.cursor = tok;
    const HostsReader read = [](const HostsQuery&) { return std::vector<SoftwareHostRow>{}; };
    const auto page = read_hosts_page(read, rq, std::nullopt);
    REQUIRE_FALSE(page);
    REQUIRE(page.error());
    CHECK(*page.error() == swc::CursorError::kFilterMismatch);
}

TEST_CASE("read_hosts_page: pages by agent_id and mints an h1 cursor", "[server][software_hosts_model]") {
    auto rq = *parse_hosts_params(params({{"limit", "2"}}));
    HostsQuery seen;
    const HostsReader read = [&](const HostsQuery& q) {
        seen = q;
        return std::vector<SoftwareHostRow>{host_row("a"), host_row("b")};
    };
    auto page = read_hosts_page(read, rq, std::nullopt);
    REQUIRE(page);
    CHECK(page->rows.size() == 2);
    CHECK(page->next_cursor.starts_with("h1:"));
    CHECK_FALSE(seen.agent_ids);

    rq.cursor = page->next_cursor;
    page = read_hosts_page(read, rq, set_of({"a", "b", "c"}));
    REQUIRE(page);
    CHECK(seen.after == "b");
    REQUIRE(seen.agent_ids);
    CHECK(seen.agent_ids->size() == 3);
    CHECK(store_query(seen).after_agent_id == "b");
    CHECK(store_query(seen).limit == 2);
}

TEST_CASE("host_row_json: nulls and facet fields", "[server][software_hosts_model]") {
    auto r = host_row("a1");
    SoftwareHostFacet f;
    f.facet = "installed_apps";
    f.status = "full";
    f.token = "t";
    f.last_confirmed_at = 0;
    f.duration_ms = 12;
    f.bytes_read = 34;
    r.facets.push_back(f);
    software_list::DeviceFacts facts;
    auto j = host_row_json(r, facts);
    CHECK(j["hostname"].is_null());
    CHECK(j["last_seen"] == 1700000000);
    REQUIRE(j["facets"].size() == 1);
    CHECK(j["facets"][0]["last_confirmed_at"].is_null());
    CHECK(j["facets"][0]["status"] == "full");
    CHECK(j["facets"][0]["row_status"] == "current");
    CHECK(j["facets"][0]["duration_ms"] == 12);
    CHECK(j["facets"][0]["bytes_read"] == 34);

    facts.hostname["a1"] = "";
    CHECK(host_row_json(r, facts)["hostname"].is_null()); // blank is unknown, not ""
    facts.hostname["a1"] = "web";
    CHECK(host_row_json(r, facts)["hostname"] == "web");
    r.facets[0].last_confirmed_at = 99;
    CHECK(host_row_json(r, facts)["facets"][0]["last_confirmed_at"] == 99);
}

TEST_CASE("host_row_json: row_status equals derive_status for every combination",
          "[server][software_hosts_model]") {
    for (const char* status : {"", "full", "delta", "disabled", "stale", "error"})
        for (const bool enabled : {true, false}) {
            auto r = host_row("a");
            r.facets.push_back({.facet = "x", .status = status, .enabled = enabled});
            const auto j = host_row_json(r, {});
            CHECK(j["facets"][0]["row_status"] == software_list::derive_status(status, enabled));
            CHECK(j["facets"][0]["enabled"] == enabled);
        }
}

TEST_CASE("hosts_response_json and host_detail_json shapes", "[server][software_hosts_model]") {
    const std::vector<SoftwareHostRow> rows{host_row("a"), host_row("b")};
    auto j = hosts_response_json(rows, {}, "", 4);
    CHECK(j["count"] == 2);
    CHECK(j["hosts"].size() == 2);
    CHECK(j["next_cursor"].is_null());
    CHECK(j["devices_omitted"] == 4);
    CHECK(hosts_response_json(rows, {}, "h1:x", 0)["next_cursor"] == "h1:x");

    SoftwareFleetRow inst;
    inst.agent_id = "a";
    inst.entry.name = "git";
    const auto page = software_list::list_response_json({inst}, {}, "d2:next", 0, false);
    const auto d = host_detail_json(host_row_json(rows[0], {}), page);
    CHECK(d["host"]["agent_id"] == "a");
    CHECK(d["software"].size() == 1);
    CHECK(d["count"] == 1);
    CHECK(d["next_cursor"] == "d2:next");
}

TEST_CASE("audit targets", "[server][software_hosts_model]") {
    CHECK(audit_target(*parse_hosts_params(params({}))) == "hosts:fleet");
    const auto t = audit_target(*parse_hosts_params(params({{"q", "web"}, {"last_synced_before", "9"}})));
    CHECK(t.find("q=web") != std::string::npos);
    CHECK(t.find("last_synced_before=9") != std::string::npos);
    CHECK(audit_target_host("a1") == "host=a1");
}
