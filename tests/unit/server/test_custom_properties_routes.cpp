/// @file test_custom_properties_routes.cpp
/// HTTP-level coverage for the 5-route Custom Properties API (7.6, #2542
/// PR-4) — driven in-process through TestRouteSink (no httplib acceptor,
/// #438), mirroring test_page_routes.cpp's / test_plugin_config_routes.cpp's
/// Harness shape.
///
/// Split by whether a case needs a live Postgres-backed `CustomPropertiesStore`
/// (it has no virtual seam — `Deps::store` is a concrete pointer per this
/// package's spec — so anything past the gate that touches a real store
/// needs Postgres):
///   - Every gate-denial pin (which securable/operation/agent_id each route
///     passes), the null/closed-store 503 degrade, and the two body-shape
///     400s (missing 'value', invalid JSON) all run WITHOUT Postgres — each
///     returns before the handler would dereference `deps.store`.
///   - The CRUD round-trip, the audit-row shapes (including the AUDIT
///     ASYMMETRIES this module preserves verbatim from the pre-extraction
///     inline code — see custom_properties_routes.hpp's file header for the
///     full per-route breakdown: both GET routes are unaudited; PUT audits
///     its store-level failure/success but NOT its own body-validation
///     400s; DELETE (no body-validation stage) audits both not_found and
///     success; POST /api/property-schemas audits ONLY success, unaudited
///     on both its body-validation 400s AND its store-level failure), and
///     the GET-properties store-degrade 503 (forced via a DROP TABLE,
///     mirroring test_props_scope_authz.cpp's technique) are `[pg]`, gated
///     behind YUZU_TEST_POSTGRES_DSN via a pre-migrated PgTestTemplate.
///
/// #3700 regression coverage: this file's gate-pinning TEST_CASEs are also
/// the wiring-regression tripwire that used to live in
/// test_agent_properties_scope_authz.cpp as a source-text scan of
/// server.cpp — see that file's header comment. A real dispatch through the
/// actual registered handler is strictly stronger evidence that the route
/// still calls `scoped_perm_fn` with the right operation than a regex over
/// source text ever was.

#include "custom_properties_routes.hpp"
#include "test_route_sink.hpp"

#include "custom_properties_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

/// All providers injected and re-read per call, mirroring
/// test_page_routes.cpp's / test_plugin_config_routes.cpp's Harness shape.
/// `store` defaults to null — every case that must NOT need Postgres leaves
/// it null and relies on the route returning (403/503) before it would be
/// dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    CustomPropertiesStore* store{nullptr};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    bool scoped_perm_allow{true};
    std::string last_scoped_type, last_scoped_op, last_scoped_agent_id;

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        custom_properties::Deps deps;
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
        deps.scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string& type, const std::string& op,
                                     const std::string& agent_id) {
            last_scoped_type = type;
            last_scoped_op = op;
            last_scoped_agent_id = agent_id;
            if (!scoped_perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        custom_properties::register_custom_properties_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("custom_properties_routes: registers exactly 5 routes",
          "[server][routes][custom_properties_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 5);
}

// ── Gate pinning (no Postgres needed — every route returns before touching
//    a null store) ─────────────────────────────────────────────────────────

TEST_CASE("custom_properties_routes: the 3 per-agent routes gate on scoped_perm_fn "
          "(Infrastructure, Read/Write, agent_id) -- never a bare perm_fn",
          "[server][routes][custom_properties_routes]") {
    Harness h;
    h.wire();

    h.sink.Get("/api/agents/agent-1/properties");
    CHECK(h.last_scoped_type == "Infrastructure");
    CHECK(h.last_scoped_op == "Read");
    CHECK(h.last_scoped_agent_id == "agent-1");
    CHECK(h.last_perm_type.empty()); // never touched perm_fn

    h.sink.Put("/api/agents/agent-2/properties/role", R"({"value":"web"})");
    CHECK(h.last_scoped_type == "Infrastructure");
    CHECK(h.last_scoped_op == "Write");
    CHECK(h.last_scoped_agent_id == "agent-2");
    CHECK(h.last_perm_type.empty()); // never touched perm_fn

    h.sink.Delete("/api/agents/agent-3/properties/role");
    CHECK(h.last_scoped_type == "Infrastructure");
    CHECK(h.last_scoped_op == "Write");
    CHECK(h.last_scoped_agent_id == "agent-3");
    CHECK(h.last_perm_type.empty()); // never touched perm_fn
}

TEST_CASE("custom_properties_routes: the 2 schema routes gate on the plain global "
          "perm_fn (Infrastructure, Read/Write) -- not per-target",
          "[server][routes][custom_properties_routes]") {
    Harness h;
    h.wire();

    h.sink.Get("/api/property-schemas");
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
    CHECK(h.last_scoped_type.empty()); // never touched scoped_perm_fn

    h.sink.Post("/api/property-schemas", R"({"key":"role"})");
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Write");
    CHECK(h.last_scoped_type.empty()); // never touched scoped_perm_fn
}

TEST_CASE("custom_properties_routes: a scoped_perm_fn denial 403s before the store is "
          "touched (GET/PUT/DELETE properties)",
          "[server][routes][custom_properties_routes]") {
    Harness h; // store stays null -- a dereference would crash; 403 must win first
    h.scoped_perm_allow = false;
    h.wire();

    auto r1 = h.sink.Get("/api/agents/agent-1/properties");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Put("/api/agents/agent-1/properties/role", R"({"value":"web"})");
    REQUIRE(r2);
    CHECK(r2->status == 403);

    auto r3 = h.sink.Delete("/api/agents/agent-1/properties/role");
    REQUIRE(r3);
    CHECK(r3->status == 403);
}

TEST_CASE("custom_properties_routes: a perm_fn denial 403s before the store is touched "
          "(GET/POST property-schemas)",
          "[server][routes][custom_properties_routes]") {
    Harness h; // store stays null
    h.perm_allow = false;
    h.wire();

    auto r1 = h.sink.Get("/api/property-schemas");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Post("/api/property-schemas", R"({"key":"role"})");
    REQUIRE(r2);
    CHECK(r2->status == 403);
}

TEST_CASE("custom_properties_routes: a null/closed store answers 503 on every route "
          "without crashing",
          "[server][routes][custom_properties_routes]") {
    Harness h;
    h.wire();

    auto r1 = h.sink.Get("/api/agents/agent-1/properties");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Put("/api/agents/agent-1/properties/role", R"({"value":"web"})");
    REQUIRE(r2);
    CHECK(r2->status == 503);
    CHECK(h.audits.empty()); // the store-unavailable branch returns before any audit call

    auto r3 = h.sink.Delete("/api/agents/agent-1/properties/role");
    REQUIRE(r3);
    CHECK(r3->status == 503);
    CHECK(h.audits.empty());

    auto r4 = h.sink.Get("/api/property-schemas");
    REQUIRE(r4);
    CHECK(r4->status == 503);

    auto r5 = h.sink.Post("/api/property-schemas", R"({"key":"role"})");
    REQUIRE(r5);
    CHECK(r5->status == 503);
    CHECK(h.audits.empty());
}

// ── Body-shape validation runs AFTER the store-open check (no Postgres
//    needed to prove the ordering -- both bodies below would otherwise
//    surface a 400, so a 503 here is the evidence) ─────────────────────────

TEST_CASE("custom_properties_routes: body-shape validation (missing 'value', invalid JSON) "
          "runs AFTER the store-open check, not before",
          "[server][routes][custom_properties_routes]") {
    // Documents the exact order verified by reading server.cpp during PR-4's
    // pre-analysis: scoped_perm_fn/perm_fn gate FIRST, then the store-open
    // check, THEN body parsing -- so a malformed/incomplete body against a
    // null/closed store is masked by the 503, never surfaced as a 400. This
    // is the pre-existing behaviour (unchanged by the #2542 PR-4 move); the
    // corresponding 400s ARE reachable and covered below, with a real store
    // wired ([pg] section).
    Harness h; // store stays null
    h.wire();

    auto put_missing_value = h.sink.Put("/api/agents/agent-1/properties/role", R"({"x":1})");
    REQUIRE(put_missing_value);
    CHECK(put_missing_value->status == 503); // store-open check wins, not the 400

    auto put_bad_json = h.sink.Put("/api/agents/agent-1/properties/role", "not json");
    REQUIRE(put_bad_json);
    CHECK(put_bad_json->status == 503);

    auto post_bad_json = h.sink.Post("/api/property-schemas", "not json");
    REQUIRE(post_bad_json);
    CHECK(post_bad_json->status == 503);
}

// ── [pg] cases: real CustomPropertiesStore ─────────────────────────────────

namespace {

// Shares the "customprops" template key with test_custom_properties_store.cpp
// / test_props_scope_authz.cpp (same store set, same migration) — the
// registry builds the named template once per process regardless of which
// file's PgTestTemplate instance triggers it first.
yuzu::test::PgTestTemplate route_props_tpl{
    "customprops", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        CustomPropertiesStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("customprops routes template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    CustomPropertiesStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
    }
};

} // namespace

TEST_CASE("custom_properties_routes: PUT/GET/DELETE property round-trip over HTTP, with the "
          "documented audit shape (both writes audited, both reads are not)",
          "[pg][server][routes][custom_properties_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto put = h.sink.Put("/api/agents/agent-1/properties/role", R"({"value":"web"})");
    REQUIRE(put);
    CHECK(put->status == 200);
    auto put_body = body(put->body);
    CHECK(put_body["agent_id"] == "agent-1");
    CHECK(put_body["key"] == "role");
    CHECK(put_body["value"] == "web");
    CHECK(put_body["type"] == "string");
    REQUIRE(h.audits.size() == 1); // one row, not a pre/post pair -- unlike plugin_config_routes
    CHECK(h.audits[0].action == "custom_property.set");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Agent");
    CHECK(h.audits[0].target_id == "agent-1");
    CHECK(h.audits[0].detail == "role=web");

    auto get = h.sink.Get("/api/agents/agent-1/properties");
    REQUIRE(get);
    CHECK(get->status == 200);
    auto get_body = body(get->body);
    CHECK(get_body["agent_id"] == "agent-1");
    REQUIRE(get_body["properties"].size() == 1);
    CHECK(get_body["properties"][0]["key"] == "role");
    CHECK(get_body["properties"][0]["value"] == "web");
    CHECK(h.audits.size() == 1); // GET is unaudited -- no new row

    auto del = h.sink.Delete("/api/agents/agent-1/properties/role");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(body(del->body)["deleted"] == true);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "custom_property.delete");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == "key=role");

    auto redelete = h.sink.Delete("/api/agents/agent-1/properties/role");
    REQUIRE(redelete);
    CHECK(redelete->status == 404);
    REQUIRE(h.audits.size() == 3);
    CHECK(h.audits[2].result == "not_found");
}

TEST_CASE("custom_properties_routes: PUT body-shape 400s (missing 'value', invalid JSON) "
          "are reachable past a real store, with no audit call",
          "[pg][server][routes][custom_properties_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto missing_value = h.sink.Put("/api/agents/agent-1/properties/role", R"({"x":1})");
    REQUIRE(missing_value);
    CHECK(missing_value->status == 400);
    CHECK(h.audits.empty());

    auto bad_json = h.sink.Put("/api/agents/agent-1/properties/role", "not json");
    REQUIRE(bad_json);
    CHECK(bad_json->status == 400);
    CHECK(h.audits.empty());
}

// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. This body is an otherwise-VALID request ("value" is
// present) nested past the depth limit - the exact field this handler calls
// .dump() on when it is not a string - so on unguarded code the request
// proceeds to the store write, and only the new depth check tells fixed and
// unfixed code apart. depth 40 is trivially safe to build/dump directly in
// this test process; the real attack depth this guard exists for is many
// orders of magnitude higher (~100,000 levels).
TEST_CASE("custom_properties_routes: PUT a value nested past the depth limit is a 400 "
          "with no audit and no store write",
          "[pg][server][routes][custom_properties_routes][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string put_body = R"({"value":)" + deep_array + "}";
    auto res = h.sink.Put("/api/agents/agent-1/properties/role", put_body);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audits.empty());

    auto get = h.sink.Get("/api/agents/agent-1/properties");
    REQUIRE(get);
    CHECK(get->status == 200);
    CHECK(body(get->body)["properties"].empty());
}

TEST_CASE("custom_properties_routes: PUT with a value failing store-side validation is a "
          "400 with a 'failure' audit row (not the db-error 503 branch)",
          "[pg][server][routes][custom_properties_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // CustomPropertiesStore::validate_value caps at 1024 bytes -- a genuine
    // caller-input validation error, distinct from kCustomPropertiesDbErrorPrefix.
    const std::string oversized(1025, 'x');
    auto r = h.sink.Put("/api/agents/agent-1/properties/role", json{{"value", oversized}}.dump());
    REQUIRE(r);
    CHECK(r->status == 400); // NOT 503 -- is_custom_properties_db_error must say false here
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "custom_property.set");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].detail.starts_with("role: "));
}

TEST_CASE("custom_properties_routes: property-schema create/list round-trip, with the "
          "documented audit ASYMMETRY -- success is audited, a validation failure is NOT",
          "[pg][server][routes][custom_properties_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Invalid type -> upsert_schema's own validation rejects it with a plain
    // (non-db-error) message -> 400, and the pre-extraction inline code
    // never called audit_log on this branch. Preserved verbatim: no
    // "hardening" of this asymmetry belongs in a mechanical move.
    auto bad = h.sink.Post("/api/property-schemas", json{{"key", "role"}, {"type", "bogus"}}.dump());
    REQUIRE(bad);
    CHECK(bad->status == 400);
    CHECK(h.audits.empty());

    auto missing_key = h.sink.Post("/api/property-schemas", json{{"display_name", "Role"}}.dump());
    REQUIRE(missing_key);
    CHECK(missing_key->status == 400);
    CHECK(h.audits.empty());

    auto ok = h.sink.Post("/api/property-schemas",
                          json{{"key", "role"}, {"display_name", "Role"}, {"type", "string"}}
                              .dump());
    REQUIRE(ok);
    CHECK(ok->status == 201);
    auto ok_body = body(ok->body);
    CHECK(ok_body["key"] == "role");
    CHECK(ok_body["display_name"] == "Role");
    REQUIRE(h.audits.size() == 1); // only the success path audits
    CHECK(h.audits[0].action == "property_schema.create");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "PropertySchema");
    CHECK(h.audits[0].target_id == "role");
    CHECK(h.audits[0].detail.empty()); // 5-arg original call -- detail defaulted to ""

    auto list = h.sink.Get("/api/property-schemas");
    REQUIRE(list);
    CHECK(list->status == 200);
    auto list_body = body(list->body);
    REQUIRE(list_body["schemas"].size() == 1);
    CHECK(list_body["schemas"][0]["key"] == "role");
    CHECK(h.audits.size() == 1); // GET is unaudited -- no new row
}

TEST_CASE("custom_properties_routes: GET properties degrades to 503 (never a false-empty "
          "200) when the underlying table is unreachable",
          "[pg][server][routes][custom_properties_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_props_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Simulate a Postgres-side degrade the same way test_props_scope_authz.cpp
    // does: drop the table out from under the live store (a reproducible
    // stand-in for a transient connection loss), without killing the whole
    // pool (which would also fail the is_open()-style check upstream and
    // hide the specific regression this test targets -- a QUERY failure
    // once the store believes it is open).
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(conn.get(), "DROP TABLE custom_properties_store.custom_properties CASCADE")};
        REQUIRE(r.ok());
    }

    auto r = h.sink.Get("/api/agents/agent-1/properties");
    REQUIRE(r);
    CHECK(r->status == 503);
    auto j = body(r->body);
    CHECK(j["error"]["message"] == "custom properties store degraded");
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_custom_properties_routes'
// OWN handlers are correct, but nothing above reads server.cpp — a future
// edit that drops the production `register_custom_properties_routes(...)`
// call at server.cpp's registration site would leave every case above green
// while the real server 404s all 5 routes. The deleted source-text tripwire
// in test_agent_properties_scope_authz.cpp (this module's pre-extraction
// home) had exactly this side effect; this is its narrower replacement,
// scoped only to "the call still exists somewhere in server.cpp" (adversarial
// review finding, #2542 PR-4).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("custom_properties_routes: wiring -- server.cpp still calls "
          "register_custom_properties_routes",
          "[server][routes][custom_properties_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_custom_properties_routes(") != std::string::npos);
}
