/**
 * test_software_changes_model.cpp - pure coverage for software_changes_model.hpp (SAM-33): the
 * feed parameters and settle bound, the (observed_at, change_id) cursor, a paging walk over a
 * fake reader with an advancing stable_before, and the summary's null-never-zero rule. No store,
 * no libpq, no clock, no network.
 */

#include <catch2/catch_test_macros.hpp>

#include "list_keyset.hpp"
#include "model_param_helpers.hpp"
#include "software_changes_model.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::software_changes;
using yuzu::server::authz::VisibleSet;
namespace swc = yuzu::server::software_catalogue;

namespace {

Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return Params(kv);
}

SoftwareChangeRow change(std::int64_t id, std::int64_t at, std::string agent = "a1") {
    SoftwareChangeRow r;
    r.change_id = id;
    r.observed_at = at;
    r.agent_id = std::move(agent);
    r.kind = "install";
    r.name = "app";
    return r;
}

// Honours the store contract: eligibility observed_at < stable_before, since, the row-value keyset
// (observed_at, change_id) > after, the agent_ids push-down (nullopt = unfiltered, present-empty =
// nothing), order (observed_at, change_id), limit.
ChangesReader fake_reader(std::vector<SoftwareChangeRow> all) {
    return [all = std::move(all)](const ChangesQuery& q) {
        std::vector<SoftwareChangeRow> out;
        for (const auto& r : all) {
            if (r.observed_at >= q.stable_before || r.observed_at < q.since)
                continue;
            if (std::tuple(r.observed_at, r.change_id) <=
                std::tuple(q.after.observed_at, q.after.change_id))
                continue;
            if (!q.agent_id.empty() && r.agent_id != q.agent_id)
                continue;
            if (q.agent_ids && std::ranges::find(*q.agent_ids, r.agent_id) == q.agent_ids->end())
                continue;
            out.push_back(r);
        }
        std::ranges::sort(out, [](const auto& a, const auto& b) {
            return std::tuple(a.observed_at, a.change_id) < std::tuple(b.observed_at, b.change_id);
        });
        if (out.size() > static_cast<std::size_t>(q.limit))
            out.resize(static_cast<std::size_t>(q.limit));
        return std::optional(std::move(out));
    };
}

} // namespace

TEST_CASE("changes params: defaults, settle bound, validation", "[software][changes]") {
    auto r = parse_changes_params(params({}), 10000);
    REQUIRE(r);
    CHECK(r->query.stable_before == 10000 - kSettleSecs);
    CHECK(r->query.since == 0);
    CHECK(r->query.limit == swc::kCatalogueDefaultLimit);

    r = parse_changes_params(params({{"kind", "upgrade"}, {"since", "55"}, {"agent_id", "a1"},
                                     {"limit", "7"}}),
                             100);
    REQUIRE(r);
    CHECK(r->query.kind == "upgrade");
    CHECK(r->query.since == 55);
    CHECK(r->query.agent_id == "a1");
    CHECK(r->query.limit == 7);

    auto bad = parse_changes_params(params({{"kind", "update"}}), 100);
    REQUIRE_FALSE(bad);
    CHECK(bad.error() == "invalid kind");
    CHECK_FALSE(parse_changes_params(params({{"since", "-1"}}), 100));
    CHECK_FALSE(parse_changes_params(params({{"since", "x"}}), 100));
    CHECK_FALSE(parse_changes_params(params({{"limit", "x"}}), 100));
    CHECK_FALSE(parse_changes_params(params({{"agent_id", std::string("a\0b", 3)}}), 100));
    CHECK_FALSE(parse_changes_params(params({{"cursor", std::string(swc::kCursorMaxBytes + 1, 'x')}}), 100));
}

TEST_CASE("changes cursor: round trip, fingerprint, refusals", "[software][changes]") {
    const std::string fp = changes_fingerprint(parse_changes_params(params({}), 1000)->query);
    const auto tok = encode_changes_cursor({1000, 100}, 0, fp);
    CHECK(tok.starts_with("g1:"));
    const auto dec = decode_changes_cursor(tok, fp);
    REQUIRE(dec);
    CHECK(dec->first.observed_at == 1000);
    CHECK(dec->first.change_id == 100);

    // Not bound to stable_before: requests at different times share a fingerprint.
    CHECK(changes_fingerprint(parse_changes_params(params({}), 5000)->query) == fp);
    // Bound to since, agent_id and kind.
    for (const auto& kv : {std::pair<std::string, std::string>{"since", "5"},
                           {"agent_id", "a2"}, {"kind", "remove"}}) {
        const auto other = changes_fingerprint(parse_changes_params(params({kv}), 1000)->query);
        CHECK(other != fp);
        const auto mism = decode_changes_cursor(tok, other);
        REQUIRE_FALSE(mism);
        CHECK(mism.error() == swc::CursorError::kFilterMismatch);
    }
    CHECK(decode_changes_cursor("d2:" + tok.substr(3), fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_changes_cursor("g1:zz", fp).error() == swc::CursorError::kMalformed);
}

TEST_CASE("changes cursor: missing or negative anchor is malformed", "[software][changes]") {
    const std::string fp = "0123456789abcdef";
    const auto forge = [&](std::initializer_list<const std::string*> f) {
        return "g1:" + fp + ":" + keyset::b64url_encode(model_detail::length_prefixed(f));
    };
    const std::string ok = "5", neg = "-1", empty, zero = "0";
    CHECK(decode_changes_cursor(forge({&ok, &ok, &zero}), fp));
    CHECK(decode_changes_cursor(forge({&empty, &ok, &zero}), fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_changes_cursor(forge({&ok, &empty, &zero}), fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_changes_cursor(forge({&neg, &ok, &zero}), fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_changes_cursor(forge({&ok, &neg, &zero}), fp).error() == swc::CursorError::kMalformed);
    CHECK(decode_changes_cursor(forge({&ok, &ok}), fp).error() == swc::CursorError::kMalformed);
}

TEST_CASE("changes paging: out-of-order ids and an advancing stable_before", "[software][changes]") {
    // change 100 stamped 1000, change 101 stamped 999 (lower id, later stamp inverted).
    const auto read = fake_reader({change(100, 1000), change(101, 999)});
    std::multiset<std::int64_t> seen;
    std::string cursor;
    std::int64_t now = 1000 + kSettleSecs + 1; // both eligible from the first request
    for (int guard = 0; guard < 10; ++guard, now += 5) {
        auto rq = parse_changes_params(params({{"limit", "1"}}), now);
        REQUIRE(rq);
        rq->cursor = cursor;
        auto page = read_changes_page(read, *rq, std::nullopt);
        REQUIRE(page);
        for (const auto& r : page->rows)
            seen.insert(r.change_id);
        cursor = page->next_cursor;
        if (cursor.empty())
            break;
    }
    CHECK(seen == std::multiset<std::int64_t>{100, 101});

    // Row 101 (stamp 999) becomes eligible first; 100 appears after stable_before advances, and the
    // cursor minted at the earlier time is still accepted.
    seen.clear();
    cursor.clear();
    auto rq = parse_changes_params(params({{"limit", "1"}}), 999 + kSettleSecs + 1);
    REQUIRE(rq);
    auto page = read_changes_page(read, *rq, std::nullopt);
    REQUIRE(page);
    REQUIRE(page->rows.size() == 1);
    CHECK(page->rows[0].change_id == 101);
    seen.insert(101);
    rq = parse_changes_params(params({{"limit", "1"}}), 1000 + kSettleSecs + 1);
    REQUIRE(rq);
    rq->cursor = page->next_cursor;
    page = read_changes_page(read, *rq, std::nullopt);
    REQUIRE(page);
    REQUIRE(page->rows.size() == 1);
    CHECK(page->rows[0].change_id == 100);
}

TEST_CASE("changes paging: since composes with the cursor", "[software][changes]") {
    const auto read = fake_reader({change(1, 100), change(2, 200), change(3, 300), change(4, 400)});
    auto rq = parse_changes_params(params({{"since", "200"}, {"limit", "2"}}), 10000);
    REQUIRE(rq);
    auto page = read_changes_page(read, *rq, std::nullopt);
    REQUIRE(page);
    REQUIRE(page->rows.size() == 2);
    CHECK(page->rows[0].change_id == 2);
    CHECK(page->rows[1].change_id == 3);
    rq->cursor = page->next_cursor;
    page = read_changes_page(read, *rq, std::nullopt);
    REQUIRE(page);
    REQUIRE(page->rows.size() == 1);
    CHECK(page->rows[0].change_id == 4);
    // A cursor from a request with another `since` is refused.
    auto other = parse_changes_params(params({{"since", "100"}, {"cursor", rq->cursor}}), 10000);
    REQUIRE(other);
    auto refused = read_changes_page(read, *other, std::nullopt);
    REQUIRE_FALSE(refused);
    CHECK(refused.error() == swc::CursorError::kFilterMismatch);
}

TEST_CASE("changes paging: caller confinement reaches the reader", "[software][changes]") {
    const auto read = fake_reader({change(1, 100, "a1"), change(2, 200, "a2"), change(3, 300, "a1")});
    const auto ids = [](const ChangesPage& p) {
        std::vector<std::string> out;
        for (const auto& r : p.rows)
            out.push_back(r.agent_id);
        return out;
    };
    auto rq = parse_changes_params(params({}), 10000);
    REQUIRE(rq);

    // Unrestricted: every device's rows.
    auto page = read_changes_page(read, *rq, std::nullopt);
    REQUIRE(page);
    CHECK(page->rows.size() == 3);

    // Bounded scope: only a1's rows, never a2's.
    page = read_changes_page(read, *rq, VisibleSet{std::unordered_set<std::string>{"a1"}});
    REQUIRE(page);
    CHECK(ids(*page) == std::vector<std::string>{"a1", "a1"});

    // Deny-all: nothing.
    page = read_changes_page(read, *rq, authz::deny_all());
    REQUIRE(page);
    CHECK(page->rows.empty());

    // Naming a device outside the scope is flagged and returns nothing.
    auto other = parse_changes_params(params({{"agent_id", "a2"}}), 10000);
    REQUIRE(other);
    page = read_changes_page(read, *other, VisibleSet{std::unordered_set<std::string>{"a1"}});
    REQUIRE(page);
    CHECK(page->target_denied);
    CHECK(page->rows.empty());
}

TEST_CASE("changes JSON shape", "[software][changes]") {
    software_list::DeviceFacts facts;
    facts.hostname["a1"] = "host-1";
    auto r = change(7, 900);
    r.facet = "installed_apps";
    r.from_version = "1";
    r.to_version = "2";
    const auto j = changes_response_json({r, change(8, 901, "a2")}, facts, "", 3, 940);
    CHECK(j["count"] == 2);
    CHECK(j["next_cursor"].is_null());
    CHECK(j["devices_omitted"] == 3);
    CHECK(j["stable_before"] == 940);
    CHECK(j["changes"][0]["hostname"] == "host-1");
    CHECK(j["changes"][1]["hostname"].is_null());
    for (const char* k : {"change_id", "agent_id", "facet", "kind", "name", "publisher",
                          "from_version", "to_version", "instance_key", "observed_at"})
        CHECK(j["changes"][0].contains(k));
    CHECK(changes_response_json({}, facts, "g1:x", 0, 1)["next_cursor"] == "g1:x");
}

TEST_CASE("summary: null plus a reason, never zero", "[software][changes]") {
    SoftwareSummary s;
    s.devices_reporting = 5;
    s.devices_stale = 1;
    s.changes_24h = {1, 2, 3};
    s.changes_7d = {4, 5, 6};
    CatalogRollupMeta c;
    c.refreshed_at = 50;
    c.total_titles = 9;
    c.total_installs = 20;
    c.total_devices = 5;

    auto j = summary_json(s, c, 77, "");
    CHECK(j["devices"]["reporting"] == 5);
    CHECK(j["devices"]["stale"] == 1);
    CHECK(j["changes"]["last_24h"]["upgrade"] == 3);
    CHECK(j["changes"]["last_7d"]["install"] == 4);
    CHECK(j["catalogue"]["titles"] == 9);
    CHECK(j["catalogue"]["installs"] == 20);
    CHECK(j["catalogue"]["devices"] == 5);
    CHECK(j["as_of"] == 77);
    CHECK(j["omitted"].is_null());

    j = summary_json(s, std::nullopt, 77, "scope");
    CHECK(j["catalogue"].is_null());
    CHECK(j["devices"]["reporting"] == 5);
    CHECK(j["omitted"] == "scope");

    c.refreshed_at = 0;
    j = summary_json(s, c, 77, "scope");
    CHECK(j["catalogue"].is_null());
    CHECK(j["omitted"] == "building");

    j = summary_json(std::nullopt, std::nullopt, 77, "building");
    CHECK(j["devices"].is_null());
    CHECK(j["changes"].is_null());
    CHECK(j["catalogue"].is_null());
    CHECK(j["omitted"] == "building");
}
