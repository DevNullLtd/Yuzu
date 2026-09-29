/// @file test_data_inventory_routes.cpp
/// HTTP-level coverage for the 3-route generic plugin-data Inventory API
/// (Issue 7.17, #2542 PR-11) — driven in-process through TestRouteSink (no
/// httplib acceptor, #438), mirroring test_custom_properties_routes.cpp's /
/// test_schedule_routes.cpp's Harness shape.
///
/// Split by whether a case needs a live Postgres-backed `InventoryStore` (it
/// has no virtual seam — `Deps::store` is a concrete pointer): every
/// gate-denial pin and the null/closed-store 503 degrade run WITHOUT
/// Postgres (each returns before the handler would dereference
/// `deps.store`); the happy-path round-trips for all 3 routes are `[pg]`,
/// against the shared `"inventory"` PgTestTemplate (same key/schema as
/// test_inventory_store.cpp — the registry replay-verifies the resulting
/// schema, not the setup lambda's literal text).

#include "data_inventory_routes.hpp"
#include "test_route_sink.hpp"

#include "inventory_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// All providers injected and re-read per call, mirroring
/// test_custom_properties_routes.cpp's Harness shape. `store` defaults to
/// null — every case that must NOT need Postgres leaves it null and relies
/// on the route returning 503 before it would be dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    InventoryStore* store{nullptr};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        data_inventory::Deps deps;
        deps.store = store;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        data_inventory::register_data_inventory_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("data_inventory_routes: registers exactly 3 routes",
          "[server][routes][data_inventory_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────────

TEST_CASE("data_inventory_routes: all 3 routes gate on Inventory:Read",
          "[server][routes][data_inventory_routes]") {
    {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/api/inventory/tables");
        REQUIRE(r);
        CHECK(h.last_perm_type == "Inventory");
        CHECK(h.last_perm_op == "Read");
    }
    {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/api/inventory/agent-1/some_plugin");
        REQUIRE(r);
        CHECK(h.last_perm_type == "Inventory");
        CHECK(h.last_perm_op == "Read");
    }
    {
        Harness h;
        h.wire();
        auto r = h.sink.Post("/api/inventory/query", "{}");
        REQUIRE(r);
        CHECK(h.last_perm_type == "Inventory");
        CHECK(h.last_perm_op == "Read");
    }
}

TEST_CASE("data_inventory_routes: a perm_fn denial 403s before the store is touched "
          "(null store, no crash)",
          "[server][routes][data_inventory_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r1 = h.sink.Get("/api/inventory/tables");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Get("/api/inventory/agent-1/some_plugin");
    REQUIRE(r2);
    CHECK(r2->status == 403);

    auto r3 = h.sink.Post("/api/inventory/query", "{}");
    REQUIRE(r3);
    CHECK(r3->status == 403);
}

TEST_CASE("data_inventory_routes: a null store answers 503 on every route without crashing",
          "[server][routes][data_inventory_routes]") {
    Harness h; // store stays null
    h.wire();

    auto r1 = h.sink.Get("/api/inventory/tables");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Get("/api/inventory/agent-1/some_plugin");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Post("/api/inventory/query", "{}");
    REQUIRE(r3);
    CHECK(r3->status == 503);
}

// ── PG-backed: real InventoryStore ──────────────────────────────────────────

namespace {

// Shares the "inventory" key with test_inventory_store.cpp's own template
// (identical resulting schema — the registry replay-verifies against the
// fingerprint, not the setup lambda's literal text).
yuzu::test::PgTestTemplate data_inventory_tpl{
    "inventory", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InventoryStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("inventory template: store failed to migrate");
    }};

struct PgHarness {
    std::optional<yuzu::test::PostgresTestDb> db;
    std::optional<yuzu::server::pg::PgPool> pool;
    std::unique_ptr<InventoryStore> store;

    bool perm_allow{true};

    yuzu::server::test::TestRouteSink sink; // LAST — see file header.

    PgHarness() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db.emplace(data_inventory_tpl);
        REQUIRE(db->available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db->dsn(), .size = 4});
        REQUIRE(pool->valid());
        store = std::make_unique<InventoryStore>(*pool);
        REQUIRE(store->is_open());

        data_inventory::Deps deps;
        deps.store = store.get();
        deps.perm_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) { return perm_allow; };
        data_inventory::register_data_inventory_routes(sink, deps);
    }
};

} // namespace

TEST_CASE("GET /api/inventory/tables: happy path lists a reported plugin",
          "[server][routes][data_inventory_routes][rest][pg]") {
    PgHarness h;
    h.store->upsert("agent-1", "software_inventory", R"({"a":1})", 100);

    auto res = h.sink.Get("/api/inventory/tables");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["tables"].size() == 1);
    CHECK(body["tables"][0]["plugin"] == "software_inventory");
    CHECK(body["tables"][0]["agent_count"] == 1);
}

TEST_CASE("GET /api/inventory/:agent_id/:plugin: happy path returns the stored blob, "
          "and a genuinely-absent pair is 404",
          "[server][routes][data_inventory_routes][rest][pg]") {
    PgHarness h;
    h.store->upsert("agent-2", "device_ci", R"({"serial":"abc123"})", 200);

    auto res = h.sink.Get("/api/inventory/agent-2/device_ci");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["agent_id"] == "agent-2");
    CHECK(body["plugin"] == "device_ci");
    CHECK(body["data"]["serial"] == "abc123");

    auto missing = h.sink.Get("/api/inventory/agent-nope/device_ci");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("POST /api/inventory/query: happy path filters by agent_id",
          "[server][routes][data_inventory_routes][rest][pg]") {
    PgHarness h;
    h.store->upsert("agent-3", "software_inventory", R"({"x":1})", 300);
    h.store->upsert("agent-4", "software_inventory", R"({"y":2})", 301);

    auto res = h.sink.Post("/api/inventory/query", R"({"agent_id":"agent-3"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["results"].size() == 1);
    CHECK(body["results"][0]["agent_id"] == "agent-3");
    CHECK(body["result_truncated_by_cap"] == false);
    // #4496: emitted unconditionally (0 when nothing was excluded), same
    // convention as `count`/`result_truncated_by_cap` on this route.
    CHECK(body["results_excluded_by_poison"] == 0);
}

TEST_CASE("POST /api/inventory/query: invalid JSON body is a 400",
          "[server][routes][data_inventory_routes][rest][pg]") {
    PgHarness h;
    auto res = h.sink.Post("/api/inventory/query", "not json");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ── #2437-class depth guard (C7/C8) ─────────────────────────────────────────
//
// data_json is a generic ADR-0016 sync-framework blob written verbatim off
// the wire (see the write-side guard, gateway_service_impl.cpp's
// ProxyInventory) with no depth check until that fix shipped - a row seeded
// directly (as here, bypassing the now-guarded write path, matching this
// branch's established pattern for proving a read-side guard independently)
// or written before that fix, still reaches these reads. Reachability-proxy
// depth (35 > kMcpMaxJsonDepth's 32), never the real ~100,000-level attack
// depth.

namespace {
const std::string kPoisonedJson = std::string(35, '[') + std::string(35, ']');
} // namespace

TEST_CASE("GET /api/inventory/:agent_id/:plugin: a poisoned data_json is excluded as a clean "
          "404, never a 200 with a poisoned dump",
          "[server][routes][data_inventory_routes][rest][pg][security]") {
    PgHarness h;
    h.store->upsert("agent-poisoned", "custom_source", kPoisonedJson, 400);

    // Confirm the seed actually landed with the poisoned bytes intact before
    // exercising the route below - otherwise a skipped/failed upsert would
    // let this test pass for the wrong reason (a genuinely-absent row is
    // also a 404).
    auto seeded = h.store->get("agent-poisoned", "custom_source");
    REQUIRE(seeded.has_value());
    REQUIRE(seeded->has_value());
    CHECK((*seeded)->data_json == kPoisonedJson);

    auto res = h.sink.Get("/api/inventory/agent-poisoned/custom_source");
    REQUIRE(res);
    CHECK(res->status == 404); // same shape as a genuinely-absent record, never a crash/200
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["code"] == 404);
}

// #4496: this test predates the `results_excluded_by_poison` signal - it
// originally only proved the exclusion was silent-but-safe (no crash, `count`
// consistent). It now also proves the caller can TELL a record was excluded,
// which #4496 exists to fix (the response otherwise looks identical to "no
// poisoned records existed").
TEST_CASE("POST /api/inventory/query: a poisoned record is excluded, a healthy matching "
          "record is still returned, and count stays consistent with the exclusion",
          "[server][routes][data_inventory_routes][rest][pg][security]") {
    PgHarness h;
    h.store->upsert("agent-poisoned2", "custom_source", kPoisonedJson, 500);
    h.store->upsert("agent-healthy", "custom_source", R"({"ok":true})", 501);

    // Same false-green trap as the GET test above: confirm both rows actually
    // seeded with their intended bytes before relying on the query route's
    // count/exclusion behavior to prove anything.
    auto poisoned_seed = h.store->get("agent-poisoned2", "custom_source");
    REQUIRE(poisoned_seed.has_value());
    REQUIRE(poisoned_seed->has_value());
    CHECK((*poisoned_seed)->data_json == kPoisonedJson);
    auto healthy_seed = h.store->get("agent-healthy", "custom_source");
    REQUIRE(healthy_seed.has_value());
    REQUIRE(healthy_seed->has_value());
    CHECK((*healthy_seed)->data_json == R"({"ok":true})");

    auto res = h.sink.Post("/api/inventory/query", R"({"plugin":"custom_source"})");
    REQUIRE(res);
    CHECK(res->status == 200); // no crash, no 5xx from the poisoned row
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["results"].size() == 1);
    CHECK(body["results"][0]["agent_id"] == "agent-healthy");
    CHECK(body["count"] == 1); // consistent with the exclusion, not silently wrong
    // #4496: the signal this test was missing before - without it, this
    // response is byte-for-byte identical to "no poisoned record existed".
    CHECK(body["results_excluded_by_poison"] == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_data_inventory_routes'
// OWN handlers are correct, but nothing above reads server.cpp — a future
// edit that drops the production `register_data_inventory_routes(...)` call
// at server.cpp's registration site would leave every case above green
// while the real server 404s all 3 routes. Mirrors
// test_schedule_routes.cpp's tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("data_inventory_routes: wiring -- server.cpp still calls "
          "register_data_inventory_routes",
          "[server][routes][data_inventory_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_data_inventory_routes(") != std::string::npos);
}
