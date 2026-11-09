/// @file test_bulk_ci_page_model.cpp
/// The pure model behind GET /api/v1/hardware/ci and the MCP list_hardware_ci_records tool:
/// parameter parsing (REST clamps, MCP refuses), the cursor codec (tamper, filter binding), the
/// keyset walk under every scope shape (TOP, engaged-empty, pushed-down, wide post-filter) with
/// the EXACT returned set asserted against an in-memory fake store, and the JSON row shape.
/// No Postgres: the store is reached through the Reader closure.

#include "hardware_ci_page_model.hpp"

#include "hardware_list_model.hpp"
#include "list_keyset.hpp"
#include "test_fake_ci_keyset_store.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace hcp = yuzu::server::hardware_ci_page;
using nlohmann::json;

namespace {

using yuzu::server::test::FakeCiKeysetStore;
using FakeStore = FakeCiKeysetStore;
using yuzu::server::test::make_ci_record;

DeviceCiRecord make_record(std::string id) {
    return make_ci_record(std::move(id));
}

std::vector<std::string> ids_of(const hcp::Page& p) {
    std::vector<std::string> out;
    for (const auto& r : p.rows)
        out.push_back(r.agent_id);
    return out;
}

// Walks every page by following next_cursor; returns the concatenated ids.
std::vector<std::string> walk(FakeStore& store, hcp::Request rq, const authz::VisibleSet& scope,
                              int* pages = nullptr, std::int64_t* omitted = nullptr) {
    std::vector<std::string> all;
    int n = 0;
    for (;;) {
        const auto page = hcp::read_page(store.reader(), rq, scope);
        REQUIRE(page.has_value());
        ++n;
        REQUIRE(n < 1000); // a runaway walk is a defect, not a long test
        for (const auto& id : ids_of(*page))
            all.push_back(id);
        if (omitted)
            *omitted += page->devices_omitted;
        if (page->next_cursor.empty())
            break;
        rq.cursor = page->next_cursor;
    }
    if (pages)
        *pages = n;
    return all;
}

hcp::Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return hcp::Params(kv.begin(), kv.end());
}

} // namespace

// ── parameters ───────────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: REST parameters default, clamp and refuse", "[hardware_ci_page][params]") {
    SECTION("defaults") {
        const auto r = hcp::parse_params({});
        REQUIRE(r.has_value());
        CHECK(r->limit == 100);
        CHECK(r->agent_id.empty());
        CHECK(r->cursor.empty());
    }
    SECTION("limit is clamped into [1, 1000]") {
        CHECK(hcp::parse_params(params({{"limit", "0"}}))->limit == 1);
        CHECK(hcp::parse_params(params({{"limit", "-7"}}))->limit == 1);
        CHECK(hcp::parse_params(params({{"limit", "1000"}}))->limit == 1000);
        CHECK(hcp::parse_params(params({{"limit", "1001"}}))->limit == 1000);
        CHECK(hcp::parse_params(params({{"limit", "99999999999"}}))->limit == 1000);
    }
    SECTION("a limit that is not one decimal integer is refused") {
        for (const char* bad : {"abc", "1.5", "10x", "+5", " 5", "99999999999999999999"})
            CHECK_FALSE(hcp::parse_params(params({{"limit", bad}})).has_value());
    }
    SECTION("a repeated key keeps its first value; an unknown key is ignored") {
        const auto r = hcp::parse_params(
            params({{"limit", "7"}, {"limit", "9"}, {"agent_id", "a"}, {"agent_id", "b"}, {"zzz", "1"}}));
        REQUIRE(r.has_value());
        CHECK(r->limit == 7);
        CHECK(r->agent_id == "a");
    }
    SECTION("agent_id and cursor hygiene") {
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", "a\nb"}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", std::string(257, 'x')}})).has_value());
        CHECK(hcp::parse_params(params({{"agent_id", std::string(256, 'x')}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", "bad\xFF"}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", std::string("a\0b", 3)}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"cursor", std::string(2049, 'c')}})).has_value());
        // present-empty means "not given"
        const auto r = hcp::parse_params(params({{"agent_id", ""}, {"cursor", ""}, {"limit", ""}}));
        REQUIRE(r.has_value());
        CHECK(r->agent_id.empty());
        CHECK(r->limit == 100);
    }
}

TEST_CASE("hardware ci page: MCP arguments are refused, not clamped", "[hardware_ci_page][params]") {
    CHECK(hcp::request_from_args(json::object())->limit == 100);
    CHECK(hcp::request_from_args(json{{"limit", 1}})->limit == 1);
    CHECK(hcp::request_from_args(json{{"limit", 1000}})->limit == 1000);
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 0}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 1001}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", -1}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 1.5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", "5"}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", UINT64_MAX}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", 5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", ""}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", "a\tb"}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"cursor", 5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"cursor", std::string(2049, 'c')}}).has_value());
    CHECK(hcp::request_from_args(json{{"unknown", true}}).has_value());
}

// ── cursors ──────────────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: cursor round-trips and refuses tampering", "[hardware_ci_page][cursor]") {
    const hcp::Request rq;
    const std::string fp = hcp::filter_fingerprint(rq);
    const hcp::Position at{"agent-42", 0};
    const std::string tok = hcp::encode_cursor(at, fp);

    const auto back = hcp::decode_cursor(tok, fp);
    REQUIRE(back.has_value());
    CHECK(back->after == "agent-42");
    CHECK(back->skip == 0);

    const auto wide = hcp::decode_cursor(hcp::encode_cursor({"", 7}, fp), fp);
    REQUIRE(wide.has_value());
    CHECK(wide->after.empty());
    CHECK(wide->skip == 7);

    SECTION("malformed tokens") {
        for (const std::string bad :
             {std::string("garbage"), std::string(""), std::string("h1:"), std::string("h1::"),
              std::string("h2:") + tok.substr(3), std::string("d2:") + tok.substr(3),
              tok + "A", tok + "=", tok.substr(0, tok.size() - 1), tok + ":x",
              std::string("h1:ZZZZZZZZZZZZZZZZ:") + tok.substr(20), tok.substr(0, 20) + "!" + tok.substr(21)}) {
            const auto r = hcp::decode_cursor(bad, fp);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == hcp::CursorError::kMalformed);
        }
    }
    SECTION("a payload that lies about a field length, or carries a bad skip or id") {
        const auto forge = [&](const std::string& payload) {
            return "h1:" + fp + ":" + yuzu::server::keyset::b64url_encode(payload);
        };
        const char sep = '\x1f';
        const std::string ok_id = "5:agent";
        // length longer than what remains
        CHECK(hcp::decode_cursor(forge("99:agent" + std::string(1, sep) + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        // skip not a number
        CHECK(hcp::decode_cursor(forge(ok_id + sep + "1:x" + sep), fp).error() == hcp::CursorError::kMalformed);
        // negative skip
        CHECK(hcp::decode_cursor(forge(ok_id + sep + "2:-1" + sep), fp).error() == hcp::CursorError::kMalformed);
        // control byte in the id
        CHECK(hcp::decode_cursor(forge("3:a\nb" + std::string(1, sep) + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        // invalid UTF-8 in the id
        CHECK(hcp::decode_cursor(forge("3:a\xFF" "b" + std::string(1, sep) + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        // a third field
        CHECK(hcp::decode_cursor(forge(ok_id + sep + "1:0" + sep + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        // non-canonical (leading-zero) length is a second spelling of the same position
        CHECK(hcp::decode_cursor(forge("05:agent" + std::string(1, sep) + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
    }
    SECTION("a cursor is bound to the agent_id filter") {
        hcp::Request other;
        other.agent_id = "agent-42";
        const auto r = hcp::decode_cursor(tok, hcp::filter_fingerprint(other));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == hcp::CursorError::kFilterMismatch);
        // a different limit is not a different filter
        hcp::Request lim;
        lim.limit = 5;
        CHECK(hcp::filter_fingerprint(lim) == fp);
    }
}

// ── the keyset walk ──────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: an unfiltered walk visits every device exactly once, in order",
          "[hardware_ci_page][walk]") {
    FakeStore store;
    for (int i = 0; i < 7; ++i)
        store.add("dev-" + std::to_string(i));

    SECTION("pages of 3 over 7 devices") {
        hcp::Request rq;
        rq.limit = 3;
        int pages = 0;
        const auto all = walk(store, rq, std::nullopt, &pages);
        CHECK(pages == 3);
        CHECK(all == std::vector<std::string>{"dev-0", "dev-1", "dev-2", "dev-3", "dev-4", "dev-5", "dev-6"});
    }
    SECTION("an exact multiple ends on a page with no cursor, not on an empty extra page") {
        FakeStore six;
        for (int i = 0; i < 6; ++i)
            six.add("d" + std::to_string(i));
        hcp::Request rq;
        rq.limit = 3;
        int pages = 0;
        const auto all = walk(six, rq, std::nullopt, &pages);
        CHECK(pages == 2);
        CHECK(all.size() == 6);
    }
    SECTION("one page larger than the data carries no cursor") {
        hcp::Request rq;
        rq.limit = 1000;
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 7);
        CHECK(page->next_cursor.empty());
    }
    SECTION("an empty store is an empty page") {
        FakeStore none;
        const auto page = hcp::read_page(none.reader(), {}, std::nullopt);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->next_cursor.empty());
    }
    SECTION("the cursor resumes after a row inserted behind it, without a duplicate") {
        hcp::Request rq;
        rq.limit = 3;
        auto first = hcp::read_page(store.reader(), rq, std::nullopt);
        REQUIRE(first.has_value());
        store.add("dev-05"); // sorts between dev-0 and dev-1: behind the cursor
        rq.cursor = first->next_cursor;
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt);
        REQUIRE(second.has_value());
        const auto served = ids_of(*first);
        for (const auto& id : ids_of(*second))
            CHECK(std::ranges::find(served, id) == served.end());
    }
}

TEST_CASE("hardware ci page: the agent_id filter reads one device", "[hardware_ci_page][walk]") {
    FakeStore store;
    for (const char* id : {"a", "b", "c"})
        store.add(id);
    hcp::Request rq;
    rq.agent_id = "b";
    const auto page = hcp::read_page(store.reader(), rq, std::nullopt);
    REQUIRE(page.has_value());
    CHECK(ids_of(*page) == std::vector<std::string>{"b"});
    CHECK(page->next_cursor.empty());

    rq.agent_id = "nope";
    const auto none = hcp::read_page(store.reader(), rq, std::nullopt);
    REQUIRE(none.has_value());
    CHECK(none->rows.empty());
    CHECK_FALSE(none->target_denied);
}

TEST_CASE("hardware ci page: scope confines the exact set returned", "[hardware_ci_page][scope]") {
    FakeStore store;
    for (const char* id : {"a", "b", "c", "d", "e", "f"})
        store.add(id);

    SECTION("a pushed-down scope returns exactly the in-scope devices that exist") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"a", "c", "e", "ghost"};
        hcp::Request rq;
        rq.limit = 2;
        std::int64_t omitted = 0;
        const auto all = walk(store, rq, scope, nullptr, &omitted);
        CHECK(all == std::vector<std::string>{"a", "c", "e"});
        CHECK(omitted == 0); // push-down hides nothing
        // the scope reached SQL as agent_ids on every read
        for (const auto& q : store.queries) {
            REQUIRE(q.agent_ids.has_value());
            CHECK(std::set<std::string>(q.agent_ids->begin(), q.agent_ids->end()) ==
                  std::set<std::string>{"a", "c", "e", "ghost"});
        }
    }
    SECTION("an engaged-empty scope returns nothing") {
        const auto page = hcp::read_page(store.reader(), {}, authz::deny_all());
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->next_cursor.empty());
        REQUIRE(store.queries.size() == 1);
        CHECK(store.queries[0].agent_ids.has_value());
        CHECK(store.queries[0].agent_ids->empty());
    }
    SECTION("a named device outside the scope is answered without a store read") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"a"};
        hcp::Request rq;
        rq.agent_id = "b";
        const auto page = hcp::read_page(store.reader(), rq, scope);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->target_denied);
        CHECK(store.reads == 0);
    }
    SECTION("a named device inside the scope is served") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"b"};
        hcp::Request rq;
        rq.agent_id = "b";
        const auto page = hcp::read_page(store.reader(), rq, scope);
        REQUIRE(page.has_value());
        CHECK(ids_of(*page) == std::vector<std::string>{"b"});
        CHECK_FALSE(page->target_denied);
    }
}

TEST_CASE("hardware ci page: a scope wider than the push-down ceiling is post-filtered with no leak",
          "[hardware_ci_page][scope][wide]") {
    FakeStore store;
    std::set<std::string> in_scope_real;
    for (int i = 0; i < 40; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "dev-%03d", i);
        store.add(buf);
        if (i % 3 == 0)
            in_scope_real.insert(buf);
    }
    // 10001 ids: just over software_catalogue::kScopePushdownMaxIds.
    std::unordered_set<std::string> ids(in_scope_real.begin(), in_scope_real.end());
    for (int i = 0; ids.size() <= 10000; ++i)
        ids.insert("pad-" + std::to_string(i));
    const authz::VisibleSet scope = ids;

    hcp::Request rq;
    rq.limit = 4;
    const std::string fp = hcp::filter_fingerprint(rq);

    std::vector<std::string> all;
    std::int64_t omitted = 0;
    int pages = 0;
    for (;;) {
        const auto page = hcp::read_page(store.reader(), rq, scope);
        REQUIRE(page.has_value());
        REQUIRE(++pages < 100);
        omitted += page->devices_omitted;
        for (const auto& id : ids_of(*page)) {
            CHECK(in_scope_real.contains(id));
            all.push_back(id);
        }
        if (page->next_cursor.empty())
            break;
        // The token names only an in-scope device (or the head), never a dropped one.
        const auto pos = hcp::decode_cursor(page->next_cursor, fp);
        REQUIRE(pos.has_value());
        CHECK((pos->after.empty() || in_scope_real.contains(pos->after)));
        rq.cursor = page->next_cursor;
    }
    // every in-scope device exactly once, in order; nothing else
    CHECK(all == std::vector<std::string>(in_scope_real.begin(), in_scope_real.end()));
    CHECK(omitted > 0);
    // the wide path never sends an id set to the store
    for (const auto& q : store.queries)
        CHECK_FALSE(q.agent_ids.has_value());
}

TEST_CASE("hardware ci page: a degraded store read is an error, never an empty page",
          "[hardware_ci_page][degrade]") {
    FakeStore store;
    store.add("a");
    store.degraded = true;
    const auto page = hcp::read_page(store.reader(), {}, std::nullopt);
    REQUIRE_FALSE(page.has_value());
    CHECK_FALSE(page.error().has_value()); // not a cursor error

    const authz::VisibleSet scope = std::unordered_set<std::string>{"a"};
    CHECK_FALSE(hcp::read_page(store.reader(), {}, scope).has_value());
}

TEST_CASE("hardware ci page: a refused cursor surfaces its reason", "[hardware_ci_page][cursor]") {
    FakeStore store;
    store.add("a");
    hcp::Request rq;
    rq.cursor = "nonsense";
    const auto bad = hcp::read_page(store.reader(), rq, std::nullopt);
    REQUIRE_FALSE(bad.has_value());
    REQUIRE(bad.error().has_value());
    CHECK(*bad.error() == hcp::CursorError::kMalformed);
    CHECK(store.reads == 0);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: row JSON carries the per-id ci block byte for byte, plus hash and version",
          "[hardware_ci_page][json]") {
    DeviceCiRecord rec = make_record("agent-1");
    rec.chassis_type = "Laptop";
    rec.board_serial = "BSN-1";
    rec.disks_summary = "unknown"; // a sentinel renders null, as on the per-id route

    HardwareCiDetail detail;
    detail.ci = std::optional<DeviceCiRecord>{rec};
    detail.ci_sections = std::vector<DeviceCiSection>{};
    const json per_id_ci = hardware_ci_json(detail, 0)["ci"];

    const json row = hcp::row_json(rec);
    json expected_ci = per_id_ci;
    expected_ci.erase("sections"); // the bulk page never carries sections
    CHECK(row["ci"] == expected_ci);
    CHECK_FALSE(row["ci"].contains("sections"));
    CHECK(row["agent_id"] == "agent-1");
    CHECK(row["hostname"] == "host-agent-1");
    CHECK(row["content_hash"] == "hash-agent-1");
    CHECK(row["blob_version"] == 2);
    CHECK(row["ci"]["disks_summary"].is_null());
    CHECK(row["ci"]["chassis_type"] == "Laptop");
}

TEST_CASE("hardware ci page: a v1-only record renders nulls for the v2 scalars, never defaults",
          "[hardware_ci_page][json]") {
    DeviceCiRecord rec = make_record("old-agent");
    rec.blob_version = 1;
    rec.content_hash.clear();
    rec.hostname.clear();
    const json row = hcp::row_json(rec);
    for (const char* k : {"chassis_type", "chassis_serial", "chassis_asset_tag", "chassis_source",
                          "board_vendor", "board_product", "board_serial", "board_source",
                          "machine_id_hash", "machine_id_algorithm", "machine_id_source"}) {
        INFO(k);
        REQUIRE(row["ci"].contains(k));
        CHECK(row["ci"][k].is_null());
    }
    CHECK(row["blob_version"] == 1);
    CHECK(row["content_hash"].is_null());
    CHECK(row["hostname"].is_null());
}

TEST_CASE("hardware ci page: page JSON shape and audit text", "[hardware_ci_page][json]") {
    hcp::Page page;
    page.rows.push_back(make_record("a"));
    page.next_cursor = "tok";
    page.devices_omitted = 3;
    const json j = hcp::page_json(page);
    CHECK(j.size() == 3);
    CHECK(j["devices"].size() == 1);
    CHECK(j["next_cursor"] == "tok");
    CHECK(j["devices_omitted"] == 3);

    hcp::Page last;
    CHECK(hcp::page_json(last)["next_cursor"] == "");

    hcp::Request rq;
    CHECK(hcp::audit_target_type(rq) == "Inventory");
    CHECK(hcp::audit_target_id(rq) == "fleet");
    CHECK(hcp::audit_detail(page, rq, "REST", false) ==
          "hardware CI records (REST): rows=1 omitted=3 scope=fleet");
    CHECK(hcp::audit_detail(page, rq, "MCP", true) ==
          "hardware CI records (MCP): rows=1 scope=confined");
    rq.agent_id = "dev-9";
    rq.cursor = "c";
    CHECK(hcp::audit_target_type(rq) == "Agent");
    CHECK(hcp::audit_target_id(rq) == "dev-9");
    CHECK(hcp::audit_detail(page, rq, "REST", false).find("page=continuation") != std::string::npos);
}

TEST_CASE("hardware ci page: a confined caller's body carries scope_basis and never the omitted count",
          "[hardware_ci_page][json][security]") {
    hcp::Page page;
    page.rows.push_back(make_record("a"));
    page.devices_omitted = 7;

    json confined = hcp::page_json(page);
    hcp::apply_scope_disclosure(confined, /*confined=*/true);
    CHECK(confined.size() == 3);
    CHECK_FALSE(confined.contains("devices_omitted"));
    CHECK(confined["scope_basis"] == "authority_scoped");
    CHECK(confined["devices"].size() == 1);
    CHECK(confined["next_cursor"] == "");

    json global = hcp::page_json(page);
    hcp::apply_scope_disclosure(global, /*confined=*/false);
    CHECK(global == hcp::page_json(page)); // untouched
    CHECK(global["devices_omitted"] == 7);
    CHECK_FALSE(global.contains("scope_basis"));

    // and neither does the confined audit detail
    const hcp::Request rq;
    CHECK(hcp::audit_detail(page, rq, "REST", true).find("omitted") == std::string::npos);
    CHECK(hcp::audit_detail(page, rq, "REST", false).find("omitted=7") != std::string::npos);
}
