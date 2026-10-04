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

#include "response_export_metrics.hpp"
#include "response_query_params.hpp"
#include "response_routes.hpp"
#include "test_export_cap_guard.hpp"
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
#include <utility>

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
    bool audit_succeeds{true}; // audit_fn's persist outcome (false = row not durably written)
    bool audit_throws{false};  // audit_fn throws (emission pipeline fault)

    yuzu::MetricsRegistry metrics; // #4644/#4703 counters; outlives the sink's handlers

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
        deps.metrics = &metrics;
        yuzu::server::seed_response_metrics(metrics);
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
            if (audit_throws)
                throw std::runtime_error("audit pipeline fault");
            return audit_succeeds;
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

namespace {
constexpr const char* kCsvTrailerPrefix = "# result_truncated_by_cap";

// The in-band truncation record of a CUT CSV export, or "" when the body has none. It is
// the last CRLF-terminated record.
std::string csv_trailer(const std::string& body) {
    if (body.size() < 2 || body.compare(body.size() - 2, 2, "\r\n") != 0)
        return {};
    const auto start = body.rfind("\r\n", body.size() - 3);
    const std::size_t from = start == std::string::npos ? 0 : start + 2;
    const std::string last = body.substr(from, body.size() - 2 - from);
    return last.rfind(kCsvTrailerPrefix, 0) == 0 ? last : std::string{};
}

// Data rows in a CSV export body: every record ends CRLF, the header is one of them and a
// cut export's trailer is another, neither counted. The seeded payloads contain no CR/LF,
// so a line count is a row count plus the header (plus the trailer when present).
std::size_t csv_data_rows(const std::string& body) {
    std::size_t lines = 0;
    for (std::size_t pos = body.find("\r\n"); pos != std::string::npos;
         pos = body.find("\r\n", pos + 2))
        ++lines;
    if (!csv_trailer(body).empty() && lines > 0)
        --lines;
    return lines == 0 ? 0 : lines - 1;
}
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

TEST_CASE("legacy response routes: a malformed numeric query parameter is a 400 not a "
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

TEST_CASE("legacy response routes: limit and offset reject trailing garbage where accepted (#4644)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    h.seed("instr-strict-lim", "agent-1", 1);

    // Explicit (route, query) pairs rather than a cross product: /export reads limit but
    // has no offset parameter, so offset garbage there is not a pair worth asserting.
    const auto [route, query] = GENERATE(
        std::pair<std::string, std::string>{"", "limit=100abc"},
        std::pair<std::string, std::string>{"", "limit=1e3"},
        std::pair<std::string, std::string>{"", "limit=0x10"},
        std::pair<std::string, std::string>{"", "limit="},
        std::pair<std::string, std::string>{"", "offset=1e1"},
        std::pair<std::string, std::string>{"", "offset=2abc"},
        std::pair<std::string, std::string>{"/export", "limit=100abc"},
        std::pair<std::string, std::string>{"/export", "limit=1e3"},
        std::pair<std::string, std::string>{"/export", "limit=0x10"},
        std::pair<std::string, std::string>{"/export", "limit="});
    INFO("route=" << route << " query=" << query);
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

TEST_CASE("export limit normalisation: the ceiling is exactly 10000 the floor 1 omitted = ceiling",
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

    // The plain-list ceiling (legacy GET /api/responses/{id}): exactly 1000, and a
    // non-positive value is left alone on purpose (the store maps it to its default).
    using yuzu::server::cap_query_limit;
    using yuzu::server::kQueryRowLimitCap;
    CHECK(kQueryRowLimitCap == 1000);
    CHECK(cap_query_limit(2147483647) == 1000);
    CHECK(cap_query_limit(1001) == 1000);
    CHECK(cap_query_limit(1000) == 1000);
    CHECK(cap_query_limit(999) == 999);
    CHECK(cap_query_limit(0) == 0);
    CHECK(cap_query_limit(-5) == -5);
}

TEST_CASE("legacy response routes: well-formed numerics still pass incl. zero-padding and "
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

TEST_CASE("GET /api/responses/:id/export: a caller-supplied limit is clamped to 1 to 10000 "
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

    {
        yuzu::test::ExportByteCapGuard cap(600);
        auto res_json = h.sink.Get("/api/responses/instr-bytecap/export");
        REQUIRE(res_json);
        REQUIRE(res_json->status == 200);
        auto body = json::parse(res_json->body);
        CHECK(body["responses"].size() >= 1);
        CHECK(body["responses"].size() < 5);
        CHECK(body["count"] == body["responses"].size()); // count reports what was served
        CHECK(body.value("result_truncated_by_cap", false) == true);
        // Second out-of-body signal: a renamed download (kept by `curl -OJ` and a browser,
        // not by a plain `curl -o`; the CSV body carries its own trailer record instead).
        CHECK(res_json->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-bytecap-truncated.json\"");

        auto res_csv = h.sink.Get("/api/responses/instr-bytecap/export?format=csv");
        REQUIRE(res_csv);
        CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
        // In-band signal: the cut CSV ends with one 7-field trailer record naming the cause.
        CHECK(csv_trailer(res_csv->body) == "# result_truncated_by_cap cause=byte_cap,,,,,,");
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
    CHECK(csv_trailer(res_full_csv->body).empty());
    CHECK(res_full_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-bytecap.csv\"");
}

TEST_CASE("GET /api/responses/:id/export: the SERIALIZATION backstop alone flags a byte-cap cut "
          "when the SQL cut kept every row (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    // Quote-heavy payload: 100 raw bytes per row, but CSV doubles each quote and JSON
    // escapes each one, so the serialized row is about twice its raw payload.
    for (int i = 0; i < 2; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-backstop";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 1;
        r.output = std::string(100, '"');
        r.timestamp = 100 + i;
        h.store->store(r);
    }

    // Cap 150 sits between the raw payload of one row (100) and its serialized size (>150).
    // Precondition, so this test can only pass through the backstop: the SQL cut keeps both
    // rows (the rows BEFORE the second total 100 < 150) and reports no cut of its own.
    {
        ResponseQuery q;
        q.limit = 10000;
        auto sql_only = h.store->query_bounded("instr-backstop", q, std::nullopt, 150);
        REQUIRE(sql_only.has_value());
        REQUIRE(sql_only->rows.size() == 2);
        REQUIRE_FALSE(sql_only->byte_cap_hit);
        REQUIRE_FALSE(sql_only->row_cap_hit);
    }

    yuzu::test::ExportByteCapGuard cap(150);

    auto res_json = h.sink.Get("/api/responses/instr-backstop/export");
    REQUIRE(res_json);
    REQUIRE(res_json->status == 200);
    auto body = json::parse(res_json->body);
    CHECK(body["responses"].size() == 1); // the backstop stopped before the second row
    CHECK(body["count"] == 1);
    CHECK(body.value("result_truncated_by_cap", false) == true);
    CHECK(res_json->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-backstop-truncated.json\"");

    auto res_csv = h.sink.Get("/api/responses/instr-backstop/export?format=csv");
    REQUIRE(res_csv);
    REQUIRE(res_csv->status == 200);
    CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(csv_trailer(res_csv->body) == "# result_truncated_by_cap cause=byte_cap,,,,,,");
    CHECK(csv_data_rows(res_csv->body) == 1);
    CHECK(res_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-backstop-truncated.csv\"");
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
        if (f == "csv") {
            CHECK(csv_trailer(cut->body) == "# result_truncated_by_cap cause=row_cap,,,,,,");
            CHECK(csv_data_rows(cut->body) == 2); // the trailer is not a data row
        }
        // limit == row count: exact crossing, nothing dropped, so nothing is flagged.
        auto exact = h.sink.Get("/api/responses/instr-rowcut/export?limit=3&format=" + f);
        REQUIRE(exact);
        CHECK(exact->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-rowcut." + f + "\"");
        CHECK(exact->get_header_value("X-Result-Truncated-By-Cap").empty());
        if (f == "csv") {
            CHECK(csv_trailer(exact->body).empty());
            CHECK(csv_data_rows(exact->body) == 3);
        }
    }
}

TEST_CASE("GET /api/responses/:id/export: no limit serves every row up to the ceiling and "
          "limit 0 serves exactly one (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    // 101 rows: more than the plain-list default of 100, so a handler that fell back to
    // the store default instead of the export ceiling would serve 100 and fail here.
    for (int i = 0; i < 101; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-default";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = "o";
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    auto all_json = h.sink.Get("/api/responses/instr-default/export");
    REQUIRE(all_json);
    auto body = json::parse(all_json->body);
    CHECK(body["responses"].size() == 101);
    CHECK(body["count"] == 101);
    CHECK_FALSE(body.contains("result_truncated_by_cap"));
    auto all_csv = h.sink.Get("/api/responses/instr-default/export?format=csv");
    REQUIRE(all_csv);
    CHECK(csv_data_rows(all_csv->body) == 101);

    // limit=0 is clamped UP to one row (never "no rows") and, with 100 more matching,
    // is a row-cap cut.
    auto zero = h.sink.Get("/api/responses/instr-default/export?limit=0");
    REQUIRE(zero);
    auto zero_body = json::parse(zero->body);
    CHECK(zero_body["responses"].size() == 1);
    CHECK(zero_body.value("result_truncated_by_cap", false) == true);
}

TEST_CASE("GET /api/responses/:id/export: the byte cap always serves one row and never flags "
          "a last row that merely crosses it (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    {
        StoredResponse r;
        r.instruction_id = "instr-lastcross";
        r.agent_id = "agent-0";
        r.status = 0;
        r.output = std::string(400, 'y');
        r.timestamp = 100;
        h.store->store(r);
    }
    for (int i = 0; i < 3; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-progress";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = std::string(400, 'z');
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    yuzu::test::ExportByteCapGuard cap(1); // every row alone exceeds this

    // One row, and it crosses the cap: nothing was dropped, so nothing is flagged.
    auto one_json = h.sink.Get("/api/responses/instr-lastcross/export");
    REQUIRE(one_json);
    auto one = json::parse(one_json->body);
    CHECK(one["responses"].size() == 1);
    CHECK_FALSE(one.contains("result_truncated_by_cap"));
    CHECK(one_json->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-lastcross.json\"");
    auto one_csv = h.sink.Get("/api/responses/instr-lastcross/export?format=csv");
    REQUIRE(one_csv);
    CHECK(csv_data_rows(one_csv->body) == 1);
    CHECK(one_csv->get_header_value("X-Result-Truncated-By-Cap").empty());
    CHECK(csv_trailer(one_csv->body).empty());
    CHECK(one_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-lastcross.csv\"");

    // Three rows: progress is guaranteed (exactly one served) and the cut is flagged.
    auto many_json = h.sink.Get("/api/responses/instr-progress/export");
    REQUIRE(many_json);
    auto many = json::parse(many_json->body);
    CHECK(many["responses"].size() == 1);
    CHECK(many.value("result_truncated_by_cap", false) == true);
    auto many_csv = h.sink.Get("/api/responses/instr-progress/export?format=csv");
    REQUIRE(many_csv);
    CHECK(csv_data_rows(many_csv->body) == 1);
    CHECK(many_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(csv_trailer(many_csv->body) == "# result_truncated_by_cap cause=byte_cap,,,,,,");
}

TEST_CASE("legacy response routes: since and until of zero mean unbounded, a negative one is a "
          "400 (#4644)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    for (int i = 0; i < 3; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-window";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = "o";
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    // Zero is the documented "no bound on that side" sentinel (ResponseQuery defaults both
    // to 0, so the store cannot tell an omitted bound from a literal 0): pinned.
    for (const char* q : {"since=0", "until=0", "since=0&until=0", "since=000"}) {
        INFO(q);
        auto res = h.sink.Get(std::string("/api/responses/instr-window/export?") + q);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        CHECK(json::parse(res->body)["responses"].size() == 3);
    }
    // A negative epoch is no timestamp: it used to widen to "unbounded", so a computed window
    // that underflowed silently returned the whole result. Every route sharing the parser.
    for (const char* route : {"/api/responses/instr-window", "/api/responses/instr-window/export",
                              "/api/responses/instr-window/aggregate"}) {
        for (const char* q : {"since=-5", "until=-5", "since=-1&until=0", "since=0&until=-9"}) {
            INFO(route << "?" << q);
            auto res = h.sink.Get(std::string(route) + "?" + q);
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(json::parse(res->body)["error"]["message"] == "invalid numeric query parameter");
        }
    }
}

TEST_CASE("legacy response routes count rejected numeric params and cut exports by surface "
          "(#4644 #4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    for (int i = 0; i < 3; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-metric";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 0;
        r.output = std::string(400, 'x');
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    using yuzu::server::kResponseExportTruncatedMetric;
    using yuzu::server::kResponseParamRejectedMetric;
    auto rejected = [&](const char* surface) {
        return h.metrics.counter(kResponseParamRejectedMetric, {{"surface", surface}}).value();
    };
    auto cut = [&](const char* surface, const char* cause) {
        return h.metrics
            .counter(kResponseExportTruncatedMetric, {{"surface", surface}, {"cause", cause}})
            .value();
    };

    // One rejection per legacy handler (list, aggregate, export): three increments.
    CHECK(h.sink.Get("/api/responses/instr-metric?limit=100abc")->status == 400);
    CHECK(h.sink.Get("/api/responses/instr-metric/aggregate?since=1e9")->status == 400);
    CHECK(h.sink.Get("/api/responses/instr-metric/export?status=0x1")->status == 400);
    CHECK(rejected("rest") == 3.0);
    CHECK(rejected("rest_v1") == 0.0);
    CHECK(rejected("mcp") == 0.0);
    // A valid request does not count.
    CHECK(h.sink.Get("/api/responses/instr-metric?limit=2")->status == 200);
    CHECK(rejected("rest") == 3.0);

    // Row-cap cut (limit 2 of 3), then a complete export, then a byte-cap cut.
    CHECK(h.sink.Get("/api/responses/instr-metric/export?limit=2")->status == 200);
    CHECK(cut("rest", "row_cap") == 1.0);
    CHECK(h.sink.Get("/api/responses/instr-metric/export")->status == 200);
    CHECK(cut("rest", "row_cap") == 1.0);
    CHECK(cut("rest", "byte_cap") == 0.0);
    {
        yuzu::test::ExportByteCapGuard cap(500);
        CHECK(h.sink.Get("/api/responses/instr-metric/export?format=csv")->status == 200);
    }
    CHECK(cut("rest", "byte_cap") == 1.0);
    CHECK(cut("rest_v1", "byte_cap") == 0.0);
}

TEST_CASE("GET /api/responses/:id/export: an UNCUT CSV is byte-identical to the plain header + "
          "rows body, with no trailer record (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    for (int i = 0; i < 2; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-ident";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 1;
        r.output = "out," + std::to_string(i); // forces CSV quoting
        r.error_detail = "";
        r.timestamp = 100 + i;
        h.store->store(r);
    }
    // The ids are store-assigned, so read them back through the JSON export.
    auto js = json::parse(h.sink.Get("/api/responses/instr-ident/export")->body);
    REQUIRE(js["responses"].size() == 2);
    std::string expected = "id,instruction_id,agent_id,timestamp,status,output,error_detail\r\n";
    for (const auto& row : js["responses"])
        expected += std::to_string(row["id"].get<long long>()) + ",instr-ident," +
                    row["agent_id"].get<std::string>() + "," +
                    std::to_string(row["timestamp"].get<long long>()) + ",1,\"" +
                    row["output"].get<std::string>() + "\",\r\n";
    auto csv = h.sink.Get("/api/responses/instr-ident/export?format=csv");
    REQUIRE(csv);
    CHECK(csv->body == expected);
    CHECK(csv_trailer(csv->body).empty());
}

TEST_CASE("GET /api/responses/:id (catch-all): a limit above the 1000 ceiling is clamped AND "
          "signalled; a request that never exceeded it gets a byte-identical body (#4703)",
          "[server][routes][response_routes][rest][pg]") {
    PgHarness h;
    // 1001 rows: one more than the ceiling, so a clamped page is genuinely incomplete.
    for (int i = 0; i < 1001; ++i) {
        StoredResponse r;
        r.instruction_id = "instr-ceiling";
        r.agent_id = "agent-" + std::to_string(i);
        r.status = 1;
        r.output = "o";
        r.timestamp = 1000 + i;
        h.store->store(r);
    }
    {
        auto over = h.sink.Get("/api/responses/instr-ceiling?limit=999999999");
        REQUIRE(over);
        REQUIRE(over->status == 200);
        auto body = json::parse(over->body);
        CHECK(body["responses"].size() == 1000);
        CHECK(body["count"] == 1000);
        CHECK(body.value("result_truncated_by_cap", false) == true);
    }
    {
        // At the ceiling exactly: the caller asked for what it got, nothing was clamped.
        auto at = h.sink.Get("/api/responses/instr-ceiling?limit=1000");
        REQUIRE(at);
        auto body = json::parse(at->body);
        CHECK(body["responses"].size() == 1000);
        CHECK_FALSE(body.contains("result_truncated_by_cap"));
    }
    {
        // No limit: the store default, never flagged (the route has always paged by offset).
        auto dflt = h.sink.Get("/api/responses/instr-ceiling");
        REQUIRE(dflt);
        auto body = json::parse(dflt->body);
        CHECK(body["responses"].size() == 100);
        CHECK_FALSE(body.contains("result_truncated_by_cap"));
    }
    // Clamped request, short result: the page did not come back full, so no flag.
    h.seed("instr-few", "agent-1", 1);
    h.seed("instr-few", "agent-2", 1);
    auto few = h.sink.Get("/api/responses/instr-few?limit=999999999");
    REQUIRE(few);
    auto few_body = json::parse(few->body);
    CHECK(few_body["responses"].size() == 2);
    CHECK_FALSE(few_body.contains("result_truncated_by_cap"));
}

TEST_CASE("export helpers: filename sanitisation, trailer record shape and cut cause "
          "precedence (#4703)",
          "[server][routes][response_routes]") {
    using yuzu::server::ExportCut;
    using yuzu::server::export_csv_truncation_row;
    using yuzu::server::export_filename;

    // Characters outside [A-Za-z0-9._-] cannot reach the quoted header value.
    CHECK(export_filename("a\"b\r\n/../\xC3\xA9", "csv", true) ==
          "responses-a_b___..___-truncated.csv");
    CHECK(export_filename("instr-1.v2_x", "json", false) == "responses-instr-1.v2_x.json");

    // The trailer is one record with `columns` fields: columns-1 commas, CRLF-terminated.
    CHECK(export_csv_truncation_row(ExportCut{true, false}, 7) ==
          "# result_truncated_by_cap cause=row_cap,,,,,,\r\n");
    CHECK(export_csv_truncation_row(ExportCut{false, true}, 10) ==
          "# result_truncated_by_cap cause=byte_cap,,,,,,,,,\r\n");

    // byte_cap names the tighter bound when both fired; none fired = not a cut.
    CHECK(ExportCut{true, true}.cause() == std::string("byte_cap"));
    CHECK(ExportCut{true, false}.cause() == std::string("row_cap"));
    CHECK(ExportCut{false, true}.cause() == std::string("byte_cap"));
    CHECK_FALSE(ExportCut{false, false}.any());
    CHECK(ExportCut{true, true}.any());
}

TEST_CASE("seed_response_metrics pre-seeds every closed series at zero (#4644 #4703)",
          "[server][routes][response_routes]") {
    yuzu::MetricsRegistry m;
    yuzu::server::seed_response_metrics(m);
    const auto text = m.serialize();
    for (const char* s : {"rest", "rest_v1", "mcp"})
        CHECK(text.find(std::string("yuzu_server_response_param_rejected_total{surface=\"") + s +
                        "\"} 0") != std::string::npos);
    for (const char* s : {"rest", "rest_v1"})
        for (const char* c : {"row_cap", "byte_cap"})
            CHECK(text.find(std::string("yuzu_server_response_export_truncated_total{surface=\"") +
                            s + "\",cause=\"" + c + "\"} 0") != std::string::npos);
    CHECK(text.find("# HELP yuzu_server_response_export_truncated_total") != std::string::npos);
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

// ── #4644 Gate 7: the legacy export writes a fail-closed success audit row ───

TEST_CASE("GET /api/responses/:id/export: every served export writes ONE response.read success "
          "row, CSV and JSON, before any body",
          "[server][routes][response_routes][rest][pg][audit]") {
    PgHarness h;
    h.seed("instr-audited", "agent-a");
    h.seed("instr-audited", "agent-b");

    for (const char* format : {"json", "csv"}) {
        INFO(format);
        h.audits.clear();
        auto res = h.sink.Get(std::string("/api/responses/instr-audited/export?format=") + format);
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "response.read");
        CHECK(h.audits[0].result == "success");
        CHECK(h.audits[0].target_type == "Execution");
        CHECK(h.audits[0].target_id == "instr-audited");
        CHECK(h.audits[0].detail.rfind("legacy response export cid=", 0) == 0);
        // The cid in the row is the one the response carries.
        CHECK(h.audits[0].detail ==
              "legacy response export cid=" + res->get_header_value("X-Correlation-Id"));
        CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    }
}

TEST_CASE("GET /api/responses/:id/export: a scope drop writes the denied row THEN the success "
          "row, once each",
          "[server][routes][response_routes][rest][pg][audit]") {
    PgHarness h;
    h.seed("instr-audited-scope", "in-scope-agent");
    h.seed("instr-audited-scope", "out-of-scope-agent");
    h.fleet_scope = authz::VisibleSet{std::unordered_set<std::string>{"in-scope-agent"}};

    auto res = h.sink.Get("/api/responses/instr-audited-scope/export");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail == "scope_dropped=1 surface=export");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail.rfind("legacy response export cid=", 0) == 0);
}

TEST_CASE("GET /api/responses/:id/export: an audit row that does not persist, or an audit "
          "pipeline that throws, is a 503 with no data and no cut counter",
          "[server][routes][response_routes][rest][pg][audit]") {
    PgHarness h;
    h.seed("instr-audit-fail", "agent-a");

    for (const bool throws : {false, true}) {
        for (const char* format : {"json", "csv"}) {
            INFO((throws ? "throws " : "returns false ") << format);
            h.audits.clear();
            h.audit_succeeds = false;
            h.audit_throws = throws;
            auto res =
                h.sink.Get(std::string("/api/responses/instr-audit-fail/export?format=") + format);
            REQUIRE(res);
            CHECK(res->status == 503);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            auto body = json::parse(res->body, nullptr, false);
            REQUIRE_FALSE(body.is_discarded());
            CHECK(body["error"]["code"] == 503);
            CHECK(body["error"]["retry_after_ms"] == 5000);
            CHECK(body["error"]["message"].get<std::string>().find("audit subsystem unavailable") !=
                  std::string::npos);
            // No export data and no download name: nothing was served.
            CHECK(res->body.find("agent-a") == std::string::npos);
            CHECK(res->get_header_value("Content-Disposition").empty());
            REQUIRE(h.audits.size() == 1); // the one attempted row, not retried
        }
    }
}
