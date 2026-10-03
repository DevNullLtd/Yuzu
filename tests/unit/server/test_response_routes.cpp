/// @file test_response_routes.cpp
/// HTTP-level coverage for the 3-route legacy pre-v1 Responses API (#2542
/// PR-11) — driven in-process through TestRouteSink (no httplib acceptor,
/// #438), mirroring test_execution_routes.cpp's / test_schedule_routes.cpp's
/// Harness shape.
///
/// The REGISTRATION-ORDER invariant response_routes.hpp documents (aggregate,
/// then export, then the `(.+)` catch-all — httplib::Server::Get dispatches
/// to the FIRST matching pattern, and the catch-all's `.+` capture also
/// matches a `/`-containing tail like `abc/aggregate`) is pinned directly
/// against `sink.registered_routes()`, plus an end-to-end PG-backed dispatch
/// to each of the two specific routes confirming their OWN response shape
/// comes back (never the catch-all's).
///
/// Split by whether a case needs a live Postgres-backed `ResponseStore` (it
/// has no virtual seam — `Deps::store` is a concrete pointer): every
/// gate-denial pin and the null/closed-store 503 degrade run WITHOUT
/// Postgres; the happy-path round-trips and the #1634 scope-drop audit are
/// `[pg]`, against the shared `"responsestore"` PgTestTemplate (same
/// key/schema as test_response_store.cpp — the registry replay-verifies the
/// resulting schema, not the setup lambda's literal text).

#include "response_query_params.hpp"
#include "response_routes.hpp"
#include "test_route_sink.hpp"

#include "authz_model.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

/// All providers injected and re-read per call, mirroring
/// test_execution_routes.cpp's Harness shape. `store` defaults to null —
/// every case that must NOT need Postgres leaves it null and relies on the
/// route returning 503 before it would be dereferenced. `fleet_admitted`/
/// `fleet_scope` drive the `deps.fleet_read_fn` stub the same way
/// test_execution_routes.cpp's does.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    ResponseStore* store{nullptr};

    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope; // nullopt = unconfined
    std::string last_fleet_type, last_fleet_op;
    int fleet_read_fn_calls{0};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        response::Deps deps;
        deps.store = store;
        deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string& type,
                                    const std::string& op) -> authz::FleetReadGate {
            ++fleet_read_fn_calls;
            last_fleet_type = type;
            last_fleet_op = op;
            if (!fleet_admitted) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return authz::FleetReadGate{}; // admitted=false, scope=deny_all()
            }
            authz::FleetReadGate g;
            g.admitted = true;
            g.scope = fleet_scope;
            return g;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        response::register_response_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape + the load-bearing order ─────────────────────────────

TEST_CASE("response_routes: registers exactly 3 routes", "[server][routes][response_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);
}

TEST_CASE("response_routes: registration order is aggregate, export, then the catch-all "
          "(load-bearing -- httplib dispatches to the FIRST matching GET pattern)",
          "[server][routes][response_routes]") {
    Harness h;
    h.wire();
    auto routes = h.sink.registered_routes();
    REQUIRE(routes.size() == 3);
    CHECK(routes[0].first == "GET");
    CHECK(routes[0].second == R"(/api/responses/([^/]+)/aggregate)");
    CHECK(routes[1].first == "GET");
    CHECK(routes[1].second == R"(/api/responses/([^/]+)/export)");
    CHECK(routes[2].first == "GET");
    CHECK(routes[2].second == R"(/api/responses/(.+))");
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────────

TEST_CASE("response_routes: all 3 routes gate on fleet_read_fn(Response, Read) alone",
          "[server][routes][response_routes]") {
    {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/api/responses/instr-1/aggregate");
        REQUIRE(r);
        CHECK(h.last_fleet_type == "Response");
        CHECK(h.last_fleet_op == "Read");
        CHECK(h.fleet_read_fn_calls == 1);
    }
    {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/api/responses/instr-1/export");
        REQUIRE(r);
        CHECK(h.last_fleet_type == "Response");
        CHECK(h.last_fleet_op == "Read");
        CHECK(h.fleet_read_fn_calls == 1);
    }
    {
        Harness h;
        h.wire();
        auto r = h.sink.Get("/api/responses/instr-1");
        REQUIRE(r);
        CHECK(h.last_fleet_type == "Response");
        CHECK(h.last_fleet_op == "Read");
        CHECK(h.fleet_read_fn_calls == 1);
    }
}

TEST_CASE("response_routes: a fleet_read_fn denial 403s before the store is touched "
          "(null store, no crash)",
          "[server][routes][response_routes]") {
    Harness h;
    h.fleet_admitted = false;
    h.wire();

    auto r1 = h.sink.Get("/api/responses/instr-1/aggregate");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Get("/api/responses/instr-1/export");
    REQUIRE(r2);
    CHECK(r2->status == 403);

    auto r3 = h.sink.Get("/api/responses/instr-1");
    REQUIRE(r3);
    CHECK(r3->status == 403);
}

TEST_CASE("response_routes: a null store answers 503 on every route without crashing, unaudited",
          "[server][routes][response_routes]") {
    Harness h; // store stays null
    h.wire();

    auto r1 = h.sink.Get("/api/responses/instr-1/aggregate");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Get("/api/responses/instr-1/export");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Get("/api/responses/instr-1");
    REQUIRE(r3);
    CHECK(r3->status == 503);

    CHECK(h.audits.empty());
}

// ── PG-backed: real ResponseStore ───────────────────────────────────────────

namespace {

// Shares the "responsestore" key with test_response_store.cpp's own template
// (identical resulting schema — the registry replay-verifies against the
// fingerprint, not the setup lambda's literal text).
yuzu::test::PgTestTemplate response_routes_tpl{
    "responsestore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("responsestore template: store failed to migrate");
    }};

struct PgHarness {
    std::optional<yuzu::test::PostgresTestDb> db;
    std::optional<yuzu::server::pg::PgPool> pool;
    std::unique_ptr<ResponseStore> store;

    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope; // nullopt = unconfined

    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink; // LAST — see file header.

    PgHarness() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db.emplace(response_routes_tpl);
        REQUIRE(db->available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db->dsn(), .size = 4});
        REQUIRE(pool->valid());
        store = std::make_unique<ResponseStore>(*pool);
        REQUIRE(store->is_open());

        response::Deps deps;
        deps.store = store.get();
        deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response&,
                                    const std::string&, const std::string&) -> authz::FleetReadGate {
            authz::FleetReadGate g;
            g.admitted = fleet_admitted;
            g.scope = fleet_scope;
            return g;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        response::register_response_routes(sink, deps);
    }

    void seed(const std::string& instruction_id, const std::string& agent_id, int status = 1) {
        StoredResponse resp;
        resp.instruction_id = instruction_id;
        resp.agent_id = agent_id;
        resp.status = status;
        resp.output = "ok";
        store->store(resp);
    }
};

} // namespace

TEST_CASE("GET /api/responses/:id/aggregate: happy path returns its own shape, not the "
          "catch-all's -- proving the registration order actually works end-to-end",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-agg", "agent-1", 1);
    h.seed("instr-agg", "agent-2", 0);

    auto res = h.sink.Get("/api/responses/instr-agg/aggregate");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    // Only the aggregate handler produces this shape -- the catch-all
    // produces {"responses":[...],"count":N} instead, with no "groups" key.
    CHECK(body.contains("groups"));
    CHECK(body.contains("total_groups"));
    CHECK(body.contains("total_rows"));
    CHECK(body["instruction_id"] == "instr-agg");
}

TEST_CASE("GET /api/responses/:id/export: happy path returns its own shape (a "
          "Content-Disposition attachment header), not the catch-all's",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-exp", "agent-1", 1);

    auto res = h.sink.Get("/api/responses/instr-exp/export");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Only the export handler sets this header -- the catch-all never does.
    CHECK(res->has_header("Content-Disposition"));
    CHECK(res->get_header_value("Content-Disposition").find("responses-instr-exp") !=
          std::string::npos);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["responses"].size() == 1);
}

TEST_CASE("GET /api/responses/:id/export: format=csv returns a CSV body",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-csv", "agent-1", 1);

    auto res = h.sink.Get("/api/responses/instr-csv/export?format=csv");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.starts_with("id,instruction_id,agent_id,timestamp,status,output,error_detail"));
}

TEST_CASE("GET /api/responses/:id (catch-all): happy path lists responses for an id "
          "with no /aggregate or /export suffix",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-get", "agent-1", 1);
    h.seed("instr-get", "agent-2", 1);

    auto res = h.sink.Get("/api/responses/instr-get");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["responses"].size() == 2);
    CHECK(body["count"] == 2);
}

// ── #1634 scope-drop audit (CC7.2 evidence) ─────────────────────────────────

TEST_CASE("GET /api/responses/:id (catch-all): an engaged scope that drops a responding "
          "agent audits response.read/denied with surface=get",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-scoped", "in-scope-agent", 1);
    h.seed("instr-scoped", "out-of-scope-agent", 1);
    h.fleet_scope = authz::VisibleSet{std::unordered_set<std::string>{"in-scope-agent"}};

    auto res = h.sink.Get("/api/responses/instr-scoped");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["responses"].size() == 1);
    CHECK(body["responses"][0]["agent_id"] == "in-scope-agent");

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "response.read");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail.find("surface=get") != std::string::npos);
}

TEST_CASE("GET /api/responses/:id (catch-all): an unconfined caller's genuinely-empty "
          "result is NOT audited (no scope engaged, nothing dropped)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h; // fleet_scope stays nullopt -- unconfined
    auto res = h.sink.Get("/api/responses/instr-nonexistent");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.audits.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// #4644 / #4703: strict numeric parameters, export limit ceiling, export byte cap
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("legacy response routes: a malformed numeric query parameter is a 400, not a "
          "different valid-looking filter (#4644)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-strict", "agent-1", 1);

    const std::string route = GENERATE(as<std::string>{}, "", "/aggregate", "/export");
    const std::string query = GENERATE(as<std::string>{}, "status=0x1", "status=1e0",
                                       "status=-5", "status=", "since=1e9", "since=100abc",
                                       "until=0x10", "status=99999999999");
    INFO("route=" << route << " query=" << query);
    auto res = h.sink.Get("/api/responses/instr-strict" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["message"] == "invalid numeric query parameter");
}

TEST_CASE("legacy response routes: limit/offset reject trailing garbage where accepted (#4644)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-strict-lim", "agent-1", 1);

    const std::string route = GENERATE(as<std::string>{}, "", "/export");
    const std::string query =
        GENERATE(as<std::string>{}, "limit=100abc", "limit=1e3", "limit=0x10", "limit=",
                 "offset=1e1", "offset=2abc");
    INFO("route=" << route << " query=" << query);
    // /export has no offset param (it ignores it); only assert the 400 where it is read.
    if (route == "/export" && query.starts_with("offset"))
        return;
    auto res = h.sink.Get("/api/responses/instr-strict-lim" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("legacy response catch-all: a valid offset still paginates (#4644 must not break it)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-offset", "agent-1", 1);
    h.seed("instr-offset", "agent-2", 1);
    h.seed("instr-offset", "agent-3", 1);

    auto count_for = [&](const std::string& query) {
        auto res = h.sink.Get("/api/responses/instr-offset" + query);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        return json::parse(res->body)["responses"].size();
    };
    // offset skips rows (3 stored): a regression that rejects or ignores a valid offset
    // changes one of these counts.
    CHECK(count_for("") == 3);
    CHECK(count_for("?offset=1") == 2);
    CHECK(count_for("?offset=2") == 1);
    CHECK(count_for("?offset=3") == 0);
}

TEST_CASE("export limit normalisation: the ceiling is exactly 10000, the floor 1, omitted = ceiling",
          "[server][routes][response_routes]") {
    using yuzu::server::kExportRowLimitCap;
    using yuzu::server::normalize_export_limit;
    CHECK(kExportRowLimitCap == 10000);
    CHECK(normalize_export_limit(true, 999999999) == 10000);
    CHECK(normalize_export_limit(true, 10001) == 10000);
    CHECK(normalize_export_limit(true, 10000) == 10000);
    CHECK(normalize_export_limit(true, 9999) == 9999);
    CHECK(normalize_export_limit(true, 1) == 1);
    CHECK(normalize_export_limit(true, 0) == 1);
    CHECK(normalize_export_limit(true, -5) == 1);
    CHECK(normalize_export_limit(false, 12345) == 10000);
}

TEST_CASE("legacy response routes: well-formed numerics still pass, incl. zero-padding and "
          "the -1 'any' sentinel (#4644)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-strict-ok", "agent-1", 1);

    const std::string route = GENERATE(as<std::string>{}, "", "/aggregate", "/export");
    const std::string query = GENERATE(as<std::string>{}, "status=007", "status=-1", "status=1",
                                       "since=0&until=0");
    INFO("route=" << route << " query=" << query);
    auto res = h.sink.Get("/api/responses/instr-strict-ok" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("GET /api/responses/:id/export: a caller-supplied limit is clamped to [1,10000], "
          "like the v1 twin (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-exp-lim", "agent-1", 1);
    h.seed("instr-exp-lim", "agent-2", 1);

    // 999999999 used to reach ResponseStore::query as-is; now it is pinned to the route's
    // own ceiling and still serves the two rows.
    auto big = h.sink.Get("/api/responses/instr-exp-lim/export?limit=999999999");
    REQUIRE(big);
    CHECK(big->status == 200);
    CHECK(json::parse(big->body)["responses"].size() == 2);

    // A non-positive limit is raised to 1 (never the store's "unbounded" reading).
    auto neg = h.sink.Get("/api/responses/instr-exp-lim/export?limit=-5");
    REQUIRE(neg);
    CHECK(neg->status == 200);
    auto neg_body = json::parse(neg->body);
    CHECK(neg_body["responses"].size() == 1);
    // limit=1 against two rows is a row-cap truncation, signalled like the byte cap.
    CHECK(neg_body.value("result_truncated_by_cap", false) == true);

    auto all = h.sink.Get("/api/responses/instr-exp-lim/export");
    REQUIRE(all);
    CHECK_FALSE(json::parse(all->body).contains("result_truncated_by_cap"));
}

TEST_CASE("GET /api/responses/:id/export: the total-byte cap truncates JSON and CSV and "
          "signals it (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    for (int i = 0; i < 5; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-bytecap";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = std::string(400, 'x');
        r.timestamp = 100 + i;
        h.store->store(r);
    }

    struct CapGuard {
        std::size_t saved;
        explicit CapGuard(std::size_t cap) : saved(export_body_byte_cap().exchange(cap)) {}
        ~CapGuard() { export_body_byte_cap().store(saved); }
    };
    {
        CapGuard cap(600);
        auto res_json = h.sink.Get("/api/responses/instr-bytecap/export");
        REQUIRE(res_json);
        REQUIRE(res_json->status == 200);
        auto body = json::parse(res_json->body);
        CHECK(body["responses"].size() >= 1);
        CHECK(body["responses"].size() < 5);
        CHECK(body["count"] == body["responses"].size()); // count reports what was served
        CHECK(body.value("result_truncated_by_cap", false) == true);
        // UP-3: the signal also survives `curl -o` as a renamed download.
        CHECK(res_json->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-bytecap-truncated.json\"");

        auto res_csv = h.sink.Get("/api/responses/instr-bytecap/export?format=csv");
        REQUIRE(res_csv);
        CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
        CHECK(res_csv->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-bytecap-truncated.csv\"");
    }
    auto res_full = h.sink.Get("/api/responses/instr-bytecap/export");
    REQUIRE(res_full);
    auto full = json::parse(res_full->body);
    CHECK(full["responses"].size() == 5);
    CHECK_FALSE(full.contains("result_truncated_by_cap"));
    CHECK(res_full->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-bytecap.json\"");

    auto res_full_csv = h.sink.Get("/api/responses/instr-bytecap/export?format=csv");
    REQUIRE(res_full_csv);
    CHECK(res_full_csv->get_header_value("X-Result-Truncated-By-Cap").empty());
    CHECK(res_full_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-bytecap.csv\"");
}

TEST_CASE("GET /api/responses/:id/export: a ROW-cap cut renames the download and an exactly-full "
          "export does not (#4703 UP-3)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    for (int i = 0; i < 3; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-rowcut";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = "o";
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    for (const char* fmt : {"json", "csv"}) {
        const std::string f = fmt;
        // limit=2 of 3 rows: cut by row count.
        auto cut = h.sink.Get("/api/responses/instr-rowcut/export?limit=2&format=" + f);
        REQUIRE(cut);
        CHECK(cut->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-rowcut-truncated." + f + "\"");
        // limit == row count: exact crossing, nothing dropped, so nothing is flagged.
        auto exact = h.sink.Get("/api/responses/instr-rowcut/export?limit=3&format=" + f);
        REQUIRE(exact);
        CHECK(exact->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-rowcut." + f + "\"");
        CHECK(exact->get_header_value("X-Result-Truncated-By-Cap").empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_response_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_response_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 3 routes. Mirrors test_schedule_routes.cpp's
// tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("response_routes: wiring -- server.cpp still calls register_response_routes",
          "[server][routes][response_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_response_routes(") != std::string::npos);
}
