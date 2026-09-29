/**
 * test_dashboard_results_fragment.cpp -- route-handler coverage for the
 * GET /fragments/results dashboard fragment's fleet-read gate (#1712,
 * #3290 Phase 2 continuation).
 *
 * `/fragments/results` previously gated on a flat `perm_fn_(req, res,
 * "Response", "Read")` with no per-agent filter at all -- any operator
 * holding Response:Read could see response data for agents outside their
 * management-group confinement (the ADR-0017 "World A" gap). This file
 * pins the route-level wiring of its replacement, `require_fleet_read`
 * (via the injected `fleet_read_fn_`):
 *   - unwired fleet_read_fn_ -> 503, fail closed (never falls through to
 *     an unfiltered read),
 *   - a real gate deny -> the gate's own status/body, no dispatch to
 *     render_results at all,
 *   - an admitted-but-scoped gate -> only in-scope agents' rows render,
 *     and the "N agents" summary count reflects the FILTERED set, not the
 *     pre-filter fleet-wide total (a confined caller must not learn an
 *     out-of-scope agent exists via the count even with its row hidden).
 *
 * The filter LOGIC itself (render_results' scope param) is pinned more
 * directly, without an HTTP round-trip, in
 * test_dashboard_results_columns.cpp's "scope filter drops out-of-scope
 * agents" test; this file proves the ROUTE wires the gate correctly, same
 * division of labour as test_dashboard_tar_fragments.cpp (route wiring)
 * vs. test_dashboard_tar_retention.cpp (render-time logic) for the TAR
 * fragments.
 */

#include "dashboard_routes.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResponseStore is a migrated Postgres store (ADR-0039) -- shares the
// "responsestore" template key with test_dashboard_results_columns.cpp and
// test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

struct FragmentResultsHarness {
    // MEMBER ORDER IS LOAD-BEARING (mirrors test_dashboard_tar_fragments.cpp):
    // `sink` is declared LAST so it is destroyed FIRST, while the
    // `DashboardRoutes` whose `this` its handlers captured is still alive.
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    explicit FragmentResultsHarness(ResponseStore* response_store) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "frag-op";
            s.role = auth::Role::admin;
            return s;
        };
        // Never actually called by /fragments/results post-migration --
        // present only because register_routes requires a PermFn for the
        // routes in this file it did NOT migrate (e.g. filter-bar).
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {};

        // fleet_read_fn_ is deliberately left UNWIRED here -- `routes` reads
        // it live per-request (the handler captures `this`, not a snapshot
        // at registration time), so a test wires it via
        // `routes.set_fleet_read_fn(...)` directly, at any point before its
        // `get()` call. Leaving it unset (as the "unwired" test does) pins
        // production's genuine fail-closed contract, not a stand-in for it.

        routes.register_routes(
            sink, auth_fn, perm_fn, audit_fn, response_store,
            /*mgmt_group_store=*/nullptr, /*registry=*/nullptr, /*tag_store=*/nullptr,
            /*event_bus=*/nullptr,
            /*agents_json_fn=*/[] { return std::string{"[]"}; },
            /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
            /*caller_fn=*/DashboardRoutes::CallerFn{},
            /*resolve_fn=*/[](const std::string&) { return std::pair<std::string, std::string>{}; },
            &metrics, /*instruction_store=*/nullptr);
    }

    std::unique_ptr<httplib::Response> get(const std::string& path) { return sink.Get(path); }
};

} // namespace

TEST_CASE("/fragments/results: unwired fleet_read_fn_ -> 503, fail closed",
          "[server][dashboard][fragment][auth]") {
    FragmentResultsHarness h(/*response_store=*/nullptr);
    // set_fleet_read_fn is never called -- mirrors production's genuinely-
    // unwired DashboardRoutes::fleet_read_fn_ state (a misconfigured call
    // site, not a real deny).
    auto res = h.get("/fragments/results?command_id=cmd-1&plugin=registry");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(contains(res->body, "Service unavailable"));
}

TEST_CASE("/fragments/results: a real gate deny is never reached by render_results",
          "[server][dashboard][fragment][auth]") {
    FragmentResultsHarness h(/*response_store=*/nullptr);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response& res, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            res.status = 403;
            res.set_content(R"({"error":"permission denied"})", "application/json");
            return {false, yuzu::server::authz::deny_all()};
        });
    auto res = h.get("/fragments/results?command_id=cmd-1&plugin=registry");
    REQUIRE(res);
    // The gate's own response is passed through untouched -- same content-type
    // (JSON) perm_fn_'s require_permission already wrote on this route
    // pre-migration, not a behavior change for an HTMX consumer.
    CHECK(res->status == 403);
    CHECK(contains(res->body, "permission denied"));
}

TEST_CASE("/fragments/results: admitted + scoped gate hides out-of-scope rows "
          "AND narrows the agent count",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-scope-1";
    StoredResponse in_resp;
    in_resp.instruction_id = command_id;
    in_resp.agent_id = "agent-in";
    in_resp.received_at_ms = 1000;
    in_resp.status = 0;
    in_resp.output = "in-scope fragment output";
    rs.store(in_resp);
    StoredResponse out_resp;
    out_resp.instruction_id = command_id;
    out_resp.agent_id = "agent-out";
    out_resp.received_at_ms = 1000;
    out_resp.status = 0;
    out_resp.output = "out-of-scope fragment output";
    rs.store(out_resp);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::unordered_set<std::string>{"agent-in"}};
        });
    auto res = h.get("/fragments/results?command_id=" + command_id + "&plugin=registry");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "in-scope fragment output"));
    CHECK_FALSE(contains(res->body, "out-of-scope fragment output"));
    // The out-of-band #result-summary count must be recomputed from the
    // filtered set, not the pre-filter fleet-wide total.
    CHECK(contains(res->body, "1 agent"));
    CHECK_FALSE(contains(res->body, "2 agents"));
}

// #4027 fix round 2 (adversarial review CDX-P2-08): GET /api/v1/tar/retention-paused's
// explicit service-scoped-token 403 (dashboard_routes.cpp, ahead of fleet_read_fn_)
// must emit a durable audit row, not just a metric — this is the exact regression the
// finding caught (the check replaced perm_fn_/require_permission's service-scope
// default-deny branch, which DID audit via AuthRoutes::audit_log). Lives here rather
// than test_dashboard_tar_fragments.cpp because the path under test returns before
// gather_tar_retention_paused/response_store/mgmt_group_store are ever touched, so it
// needs none of that file's real-Postgres ManagementGroupStorePg fixture — same
// minimal-registration pattern as the /fragments/results tests above, self-contained
// rather than reusing FragmentResultsHarness (whose auth_fn has no service-scope hook).
TEST_CASE("GET /api/v1/tar/retention-paused: service-scoped token denial is audited, "
          "not just counted",
          "[server][dashboard][tar][auth]") {
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    struct AuditRow {
        std::string action, result, target_type, target_id, detail;
    };
    std::vector<AuditRow> audits;

    auto auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "svc-op";
        s.role = auth::Role::admin;
        s.token_scope_service = "printers"; // non-empty -> service-scoped token
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [&audits](const httplib::Request&, const std::string& action,
                              const std::string& result, const std::string& target_type,
                              const std::string& target_id, const std::string& detail) {
        audits.push_back({action, result, target_type, target_id, detail});
    };

    routes.register_routes(
        sink, auth_fn, perm_fn, audit_fn,
        /*response_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
        /*tag_store=*/nullptr, /*event_bus=*/nullptr,
        /*agents_json_fn=*/[] { return std::string{"[]"}; },
        /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
        /*caller_fn=*/DashboardRoutes::CallerFn{},
        /*resolve_fn=*/[](const std::string&) { return std::pair<std::string, std::string>{}; },
        &metrics, /*instruction_store=*/nullptr);
    // fleet_read_fn_ deliberately left UNWIRED — the service-scope check must
    // deny (and audit) BEFORE the route ever reaches it; if this test somehow
    // needed a wired gate to pass, that would itself prove the ordering broke.

    auto res = sink.Get("/api/v1/tar/retention-paused");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(contains(res->body, "service-scoped"));

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "tar.retention_paused.view");
    CHECK(audits[0].result == "denied");
    CHECK(audits[0].target_type == "Infrastructure");
}

// #3565: this codebase has a documented prior incident (authz_model.hpp's
// own doc comment on VisibleSet{}) of an engaged-empty scope (deny_all())
// being mishandled as unfiltered/nullopt, serving the whole fleet to a
// caller with no grants at all. Pin the distinction directly.
TEST_CASE("/fragments/results: admitted-but-deny_all() scope shows nothing",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-deny-all-1";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-x";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "should never render";
    rs.store(r);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, yuzu::server::authz::deny_all()}; // admitted, engaged-empty scope
        });
    auto res = h.get("/fragments/results?command_id=" + command_id + "&plugin=registry");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(contains(res->body, "should never render"));
    CHECK_FALSE(contains(res->body, "agent-x"));
    // Zero rows post-filter renders the same "no results" empty-state a
    // genuinely-empty command_id would -- never a count (there is nothing
    // to count for this caller, and "0 agents" would still be more
    // information than a deny_all() caller is owed).
    CHECK(contains(res->body, "No results match your filters"));
}

TEST_CASE("/fragments/results: admitted + unfiltered (TOP) gate shows every agent",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-unfiltered-1";
    StoredResponse r1;
    r1.instruction_id = command_id;
    r1.agent_id = "agent-a";
    r1.received_at_ms = 1000;
    r1.status = 0;
    r1.output = "output a";
    rs.store(r1);
    StoredResponse r2;
    r2.instruction_id = command_id;
    r2.agent_id = "agent-b";
    r2.received_at_ms = 1000;
    r2.status = 0;
    r2.output = "output b";
    rs.store(r2);

    FragmentResultsHarness h(&rs);
    // nullopt scope == TOP == unfiltered -- a global grant or RBAC-off,
    // byte-identical to the pre-#1712 path for that caller class.
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    auto res = h.get("/fragments/results?command_id=" + command_id + "&plugin=registry");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "output a"));
    CHECK(contains(res->body, "output b"));
    CHECK(contains(res->body, "2 agents"));
}

// Gate 6 enterprise-readiness finding (this round): "Create Group from N
// Agents" hx-gets /fragments/create-group-form and POSTs to
// /api/dashboard/group-from-results, both gated on ManagementGroup:Write
// only (a securable unrelated to this caller's Response:Read confinement)
// and unscoped to the caller's fleet-read visibility -- a confined caller
// who couldn't reach /fragments/results at all before #1712 (the old flat
// gate structurally denied an AdmitScoped-class caller) can now reach this
// page and, if they separately hold ManagementGroup:Write, see a confined
// N here but an unscoped M on the create-group-form/submit flow. Withhold
// the button entirely when scope is engaged, deferring the underlying
// sidecar-route gap to its own tracked fix (#3489).
TEST_CASE("/fragments/results: Create Group button withheld for a scoped caller",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-create-group-scoped-1";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-in";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "in-scope output";
    // plugin must be set for ResponseStore::store() to populate
    // response_facets at all -- the f_output filter below queries that
    // table, not a substring match on the raw output.
    r.plugin = "registry";
    rs.store(r);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::unordered_set<std::string>{"agent-in"}};
        });
    // f_output is a real filter (plugin "registry" falls back to the
    // default {Agent, Output} schema) -- the button's own render condition
    // is `!filters.empty() && total_agent_count > 0 && !scope`, so a
    // filter-less request would never exercise the branch under test.
    auto res = h.get("/fragments/results?command_id=" + command_id +
                      "&plugin=registry&f_output=in-scope+output");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "in-scope output"));
    // Gate 8 quality-engineer finding (this round): the assertion above is
    // reachable via the thead sort-link's raw f_output echo even at zero
    // matching rows (render_results' base_url() re-embeds every active
    // filter regardless of match count) -- assert an actual result row
    // rendered so a facet-population regression (the earlier draft's
    // false-pass class) can't silently zero out this test's positive half.
    CHECK(contains(res->body, "class=\"result-row\""));
    CHECK_FALSE(contains(res->body, "btn-create-group"));
    CHECK_FALSE(contains(res->body, "Create Group from"));
}

TEST_CASE("/fragments/results: Create Group button still renders for an "
          "unscoped (TOP) caller",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-create-group-unscoped-1";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "unscoped output";
    r.plugin = "registry";
    rs.store(r);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    auto res = h.get("/fragments/results?command_id=" + command_id +
                      "&plugin=registry&f_output=unscoped+output");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "btn-create-group"));
    CHECK(contains(res->body, "Create Group from 1 Agent"));
}
