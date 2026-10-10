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
#include "test_export_cap_guard.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// Defined in dashboard_ui.cpp (the served dashboard shell, CSS included).
extern const char* const kDashboardIndexHtml;

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

// InstructionStore is a migrated Postgres store (ADR-0058).
yuzu::test::PgTestTemplate fragment_instr_tpl{"fragresinstr", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    InstructionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("fragment_instr template: store failed to migrate");
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

    explicit FragmentResultsHarness(ResponseStore* response_store,
                                    InstructionStore* instruction_store = nullptr) {
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
            &metrics, instruction_store);
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

// The refusal replaces only #results-tbody, so it must also emit the OOB clears for the rest of
// the previous render's chrome (sort headers, pagination, result count + "Create Group" button,
// chart deck); otherwise they stay on screen beside the refusal. render_results emits the same
// four ids on every normal render (zero-match included), so these asserts are the same contract.
static void check_results_chrome_cleared(const std::string& body) {
    CHECK(contains(body, "<tbody id=\"results-tbody\""));
    CHECK(contains(body, "<thead id=\"results-thead\" hx-swap-oob=\"true\">"));
    CHECK(contains(body, "<nav id=\"result-pagination\" hx-swap-oob=\"true\"></nav>"));
    CHECK(contains(body, "<div id=\"result-summary\" hx-swap-oob=\"true\"></div>"));
    CHECK(contains(body, "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\"></div>"));
    // An open "Create Static Group" form would keep saying "N agents will be added" for rows
    // that are no longer shown.
    CHECK(contains(body, "<div id=\"group-form-slot\" hx-swap-oob=\"innerHTML\"></div>"));
    CHECK_FALSE(contains(body, "btn-create-group"));
    // The refusal cell wraps and spans the (emptied-header) row: `tbody td` clips every cell
    // to one 300px line, which hid everything after the first words of the message.
    CHECK(contains(body, "<td class=\"empty-state filter-refused\" colspan=\"99\" "
                         "data-filter-refused=\"true\">"));
}

// The cell class above is only useful if the served dashboard stylesheet overrides the generic
// `tbody td` clipping for it (specificity: td.filter-refused beats tbody td).
TEST_CASE("dashboard stylesheet: the facet refusal cell is allowed to wrap and use the row width",
          "[server][dashboard][fragment]") {
    const std::string css = kDashboardIndexHtml;
    const auto rule = css.find("td.filter-refused {");
    REQUIRE(rule != std::string::npos);
    const auto end = css.find('}', rule);
    REQUIRE(end != std::string::npos);
    const std::string body = css.substr(rule, end - rule);
    CHECK(contains(body, "white-space: normal"));
    CHECK(contains(body, "overflow: visible"));
    CHECK(contains(body, "max-width: none"));
    // And the generic clip it overrides still exists, so the override is what makes it readable.
    CHECK(contains(css, "tbody td {"));
}

// #5623: a facet value over kMaxFacetValueBytes (2048) is never stored, so a filter on it
// matches no agent. The fragment must say so instead of rendering a plausible empty table.
// The response store is nullptr here: reaching render_results would answer "Response store
// not available", so the refusal text proves the check ran before any store access.
// Literal sizes pin the shipped bound.
TEST_CASE("/fragments/results: a filter value over the facet bound is refused, not rendered "
          "as an empty result",
          "[server][dashboard][fragment]") {
    FragmentResultsHarness h(/*response_store=*/nullptr);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string over(2049, 'v');
    auto res = h.get("/fragments/results?command_id=cmd-bound-1&plugin=registry&f_output=" + over);
    REQUIRE(res);
    // 200, not 4xx: the dashboard htmx config drops 4xx bodies, which would leave stale rows.
    CHECK(res->status == 200);
    CHECK(contains(res->body, "data-filter-refused=\"true\""));
    CHECK(contains(res->body, "2048 bytes"));
    CHECK_FALSE(contains(res->body, "Response store not available"));
    CHECK_FALSE(contains(res->body, over)); // the value is never echoed
    check_results_chrome_cleared(res->body);
}

// A NUL, line feed or invalid UTF-8 byte in a filter value can never equal a stored value
// (ingest rewrites each NUL / bad byte to U+FFFD and splits on every LF), and a NUL is
// C-string-truncated by the libpq bind, which matched the prefix (`short%00zzz` showed the
// rows of `short`). Refused like an over-bound value, before any store access (the store is
// nullptr: "Response store not available" would mean it was reached).
TEST_CASE("/fragments/results: a filter value with a NUL / a line feed / invalid UTF-8 is "
          "refused, not matched as a prefix or rendered as an empty result",
          "[server][dashboard][fragment]") {
    FragmentResultsHarness h(/*response_store=*/nullptr);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    std::string nuls; // 683 NULs: 2049 bytes once ingest widens each to U+FFFD
    for (int i = 0; i < 683; ++i)
        nuls += "%00";
    for (const std::string& value : {std::string("short%00zzz"), std::string("%00"), nuls,
                                    std::string("%FF"), std::string("%C0%80"),
                                    std::string("%ED%A0%80"), std::string("ok%C3"),
                                    std::string("a%0Ab")}) {
        INFO(value.substr(0, 40));
        auto res = h.get("/fragments/results?command_id=cmd-nul-1&plugin=registry&f_output=" +
                          value);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(contains(res->body, "data-filter-refused=\"true\""));
        CHECK(contains(res->body, "NUL byte, a line feed or invalid UTF-8"));
        CHECK(contains(res->body, "The filter you set is not supported"));
        CHECK_FALSE(contains(res->body, "selected View"));
        CHECK_FALSE(contains(res->body, "line break"));
        CHECK_FALSE(contains(res->body, "no agent"));
        CHECK_FALSE(contains(res->body, "Response store not available"));
        check_results_chrome_cleared(res->body);
    }
}

TEST_CASE("/fragments/results: a filter value exactly at the facet bound still matches its "
          "stored facet",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-at-bound-1";
    const std::string at(2048, 'v');
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = at;
    r.plugin = "registry";
    rs.store(r);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    auto res = h.get("/fragments/results?command_id=" + command_id +
                      "&plugin=registry&f_output=" + at);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(contains(res->body, "data-filter-refused"));
    CHECK(contains(res->body, "class=\"result-row\""));

    // A normal zero-match render (no refusal) emits the same OOB ids the refusal path now
    // mirrors, so the two cannot drift apart unnoticed.
    auto none = h.get("/fragments/results?command_id=" + command_id +
                       "&plugin=registry&f_output=no-such-value");
    REQUIRE(none);
    CHECK(none->status == 200);
    CHECK_FALSE(contains(none->body, "data-filter-refused"));
    CHECK_FALSE(contains(none->body, "class=\"result-row\""));
    CHECK(contains(none->body, "<thead id=\"results-thead\" hx-swap-oob=\"true\">"));
    CHECK(contains(none->body, "<nav id=\"result-pagination\" hx-swap-oob=\"true\">"));
    CHECK(contains(none->body, "<div id=\"result-summary\" hx-swap-oob=\"true\">"));
    CHECK(contains(none->body, "<div id=\"chart-deck-host\" hx-swap-oob=\"innerHTML\">"));
}

// The template `equals` default is a second route into the same filter vector (no f_* params
// at all), resolved from the stored definition's response template. The refusal must cover
// it: the operator typed nothing over-bound, so the bound is hit only after the template
// resolves. The response store is nullptr, so "Response store not available" is the proof the
// at-bound request reached render_results while the over-bound one did not.
TEST_CASE("/fragments/results: a response-template equals default over the facet bound is "
          "refused, and one at the bound is not",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    const auto make_definition = [&](const std::string& name, std::size_t equals_bytes) {
        nlohmann::json tpl = {
            {"id", "tplbound"},
            {"name", "bounded"},
            {"columns", nlohmann::json::array({"Name"})},
            {"filters", nlohmann::json::array({{{"column", "Name"},
                                                {"op", "equals"},
                                                {"value", std::string(equals_bytes, 'v')}}})}};
        InstructionDefinition def;
        def.name = name;
        def.version = "1.0.0";
        def.plugin = "registry";
        def.action = "list";
        def.type = "question";
        def.enabled = true;
        def.result_schema = R"([{"name":"Name","type":"string"}])";
        def.response_templates_spec = nlohmann::json::array({tpl}).dump();
        auto created = is.create_definition(def);
        REQUIRE(created.has_value());
        return *created;
    };
    const auto over_id = make_definition("tpl-equals-over", 2049);
    const auto at_id = make_definition("tpl-equals-at", 2048);

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });

    auto over = h.get("/fragments/results?command_id=cmd-tpl-1&plugin=registry&definition_id=" +
                      over_id + "&template_id=tplbound");
    REQUIRE(over);
    CHECK(over->status == 200);
    CHECK(contains(over->body, "data-filter-refused=\"true\""));
    CHECK(contains(over->body, "2048 bytes"));
    CHECK_FALSE(contains(over->body, "Response store not available"));
    CHECK_FALSE(contains(over->body, std::string(2049, 'v'))); // the value is never echoed

    auto at = h.get("/fragments/results?command_id=cmd-tpl-1&plugin=registry&definition_id=" +
                    at_id + "&template_id=tplbound");
    REQUIRE(at);
    CHECK(at->status == 200);
    CHECK_FALSE(contains(at->body, "data-filter-refused"));
    CHECK(contains(at->body, "Response store not available")); // reached render_results
}

// Provenance of a refused filter (#5623): the dashboard says WHICH source of the filter is at
// fault. The operator's own f_* filter -> "the filter you set"; the selected View's saved
// `equals` default -> "the selected View's saved filter on <column>" with the two real
// remedies. The column name is template-author text, so it must appear html-escaped; the
// value must never be echoed. The response store is nullptr, so "Response store not
// available" proves a request reached render_results.
namespace {
constexpr const char* kProvenanceColumn = "A<b>&D"; // escapes to A&lt;b&gt;&amp;D

std::string make_provenance_definition(InstructionStore& is, const std::string& name,
                                       const nlohmann::json& equals_value) {
    nlohmann::json tpl = {
        {"id", "tplprov"},
        {"name", "provenance"},
        {"columns", nlohmann::json::array({"Name"})},
        {"filters", nlohmann::json::array({{{"column", kProvenanceColumn},
                                            {"op", "equals"},
                                            {"value", equals_value}}})}};
    InstructionDefinition def;
    def.name = name;
    def.version = "1.0.0";
    def.plugin = "registry";
    def.action = "list";
    def.type = "question";
    def.enabled = true;
    def.result_schema = nlohmann::json::array({{{"name", "Name"}, {"type", "string"}},
                                               {{"name", kProvenanceColumn}, {"type", "string"}}})
                            .dump();
    def.response_templates_spec = nlohmann::json::array({tpl}).dump();
    auto created = is.create_definition(def);
    REQUIRE(created.has_value());
    return *created;
}
} // namespace

TEST_CASE("/fragments/results: a refused filter says whether it is the operator's filter or "
          "the selected View's saved filter",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const std::string over_value(2049, 'v');
    const auto over_id =
        make_provenance_definition(is, "tpl-prov-over", nlohmann::json(over_value));
    const auto nul_id =
        make_provenance_definition(is, "tpl-prov-nul", nlohmann::json(std::string("a\0b", 3)));

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base = "/fragments/results?command_id=cmd-prov-1&plugin=registry&";

    // View variant: a template equals default (no f_* param) that is unsupported.
    for (const auto& id : {over_id, nul_id}) {
        auto res = h.get(base + "definition_id=" + id + "&template_id=tplprov");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(contains(res->body, "data-filter-refused=\"true\""));
        CHECK(contains(res->body, "The selected View&#39;s saved filter on A&lt;b&gt;&amp;D"));
        CHECK(contains(res->body, "is not supported"));
        CHECK(contains(res->body, "choose another View"));
        CHECK(contains(res->body, "bypasses the View"));
        CHECK(contains(res->body, "should correct it"));
        CHECK(contains(res->body, "a line feed"));
        CHECK_FALSE(contains(res->body, "you set"));
        CHECK_FALSE(contains(res->body, "A<b>&D")); // the column name is escaped
        CHECK_FALSE(contains(res->body, over_value)); // the value is never echoed
        CHECK_FALSE(contains(res->body, "Response store not available"));
        check_results_chrome_cleared(res->body);
    }

    // Operator variant: an unsupported f_* filter. The View's default is bypassed (an
    // explicit filter replaces it), so the message must blame the operator's filter even
    // though the same View is selected.
    auto op = h.get(base + "definition_id=" + over_id + "&template_id=tplprov&f_output=a%0Ab");
    REQUIRE(op);
    CHECK(op->status == 200);
    CHECK(contains(op->body, "data-filter-refused=\"true\""));
    CHECK(contains(op->body, "The filter you set is not supported"));
    CHECK_FALSE(contains(op->body, "selected View"));
    CHECK_FALSE(contains(op->body, "A&lt;b&gt;"));
    CHECK_FALSE(contains(op->body, "Response store not available"));

    // A supported operator filter bypasses the View's unsupported default: not refused.
    auto bypass = h.get(base + "definition_id=" + over_id + "&template_id=tplprov&f_output=ok");
    REQUIRE(bypass);
    CHECK(bypass->status == 200);
    CHECK_FALSE(contains(bypass->body, "data-filter-refused"));
    CHECK(contains(bypass->body, "Response store not available"));
}

// A View `equals` default with an EMPTY value used to be pushed as a filter; ingest never
// stores an empty field, so the table silently emptied. Dashboard-results only: an explicit
// empty f_* value still means "All" (parse_filters drops it), and a non-empty equals at the
// bound still renders.
TEST_CASE("/fragments/results: a View equals default with an empty value is refused, an "
          "explicit empty operator filter is not",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const auto empty_id = make_provenance_definition(is, "tpl-prov-empty", nlohmann::json(""));
    const auto at_id = make_provenance_definition(is, "tpl-prov-at", nlohmann::json(std::string(2048, 'v')));

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base = "/fragments/results?command_id=cmd-prov-2&plugin=registry&";

    auto empty = h.get(base + "definition_id=" + empty_id + "&template_id=tplprov");
    REQUIRE(empty);
    CHECK(empty->status == 200);
    CHECK(contains(empty->body, "data-filter-refused=\"true\""));
    CHECK(contains(empty->body, "The selected View&#39;s saved filter on A&lt;b&gt;&amp;D has no value"));
    CHECK(contains(empty->body, "Choose another View"));
    CHECK(contains(empty->body, "should correct it"));
    CHECK_FALSE(contains(empty->body, "A<b>&D"));
    CHECK_FALSE(contains(empty->body, "Response store not available"));
    check_results_chrome_cleared(empty->body);

    // A non-empty operator filter replaces the View's defaults, so the empty one is moot.
    auto explicit_ok =
        h.get(base + "definition_id=" + empty_id + "&template_id=tplprov&f_output=ok");
    REQUIRE(explicit_ok);
    CHECK_FALSE(contains(explicit_ok->body, "data-filter-refused"));
    CHECK(contains(explicit_ok->body, "Response store not available"));

    // No View at all: an explicit empty f_* value is "All", not a refusal.
    auto all = h.get(base + "f_output=");
    REQUIRE(all);
    CHECK(all->status == 200);
    CHECK_FALSE(contains(all->body, "data-filter-refused"));
    CHECK(contains(all->body, "Response store not available"));

    // A non-empty equals exactly at the bound still reaches render_results.
    auto at = h.get(base + "definition_id=" + at_id + "&template_id=tplprov");
    REQUIRE(at);
    CHECK_FALSE(contains(at->body, "data-filter-refused"));
    CHECK(contains(at->body, "Response store not available"));
}

// View-filter provenance INDEXING (#5623): the refusal names the column of the filter that is
// actually bad, so view_filter_cols must stay index-aligned with the filters the View added.
// A definition with several result columns and several `equals` defaults (name, value).
namespace {
std::string make_multi_filter_definition(
    InstructionStore& is, const std::string& name, const std::vector<std::string>& columns,
    const std::vector<std::pair<std::string, nlohmann::json>>& equals_defaults) {
    nlohmann::json schema = nlohmann::json::array();
    for (const auto& c : columns) schema.push_back({{"name", c}, {"type", "string"}});
    nlohmann::json filters = nlohmann::json::array();
    for (const auto& [col, val] : equals_defaults)
        filters.push_back({{"column", col}, {"op", "equals"}, {"value", val}});
    nlohmann::json tpl = {{"id", "tplmulti"},
                          {"name", "multi"},
                          {"columns", nlohmann::json::array({columns.front()})},
                          {"filters", filters}};
    InstructionDefinition def;
    def.name = name;
    def.version = "1.0.0";
    def.plugin = "registry";
    def.action = "list";
    def.type = "question";
    def.enabled = true;
    def.result_schema = schema.dump();
    def.response_templates_spec = nlohmann::json::array({tpl}).dump();
    auto created = is.create_definition(def);
    REQUIRE(created.has_value());
    return *created;
}
} // namespace

TEST_CASE("/fragments/results: a refusal names the View column that is bad, not the first one",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const std::vector<std::string> cols{"Name", "Alpha", "Beta", "Gamma"};
    const nlohmann::json over(std::string(2049, 'v'));
    const nlohmann::json nul(std::string("a\0b", 3));
    const nlohmann::json good("ok");
    const nlohmann::json empty("");

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base = "/fragments/results?command_id=cmd-multi-1&plugin=registry&";
    const auto fetch = [&](const std::string& id) {
        auto res = h.get(base + "definition_id=" + id + "&template_id=tplmulti");
        REQUIRE(res);
        CHECK(res->status == 200);
        return res->body;
    };

    SECTION("a supported first default then a bad second names the SECOND (not [0])") {
        int n = 0;
        for (const auto& bad : {over, nul}) {
            const auto id = make_multi_filter_definition(
                is, "tpl-multi-second-" + std::to_string(n++), cols,
                {{"Alpha", good}, {"Beta", bad}});
            const auto body = fetch(id);
            CHECK(contains(body, "data-filter-refused=\"true\""));
            CHECK(contains(body, "The selected View&#39;s saved filter on Beta is not supported"));
            CHECK_FALSE(contains(body, "saved filter on Alpha"));
            CHECK_FALSE(contains(body, "Response store not available"));
        }
    }

    SECTION("a first default on a column that does not resolve is skipped, the second is named") {
        const auto id = make_multi_filter_definition(
            is, "tpl-multi-unknown", cols, {{"NoSuchColumn", good}, {"Beta", over}});
        const auto body = fetch(id);
        CHECK(contains(body, "data-filter-refused=\"true\""));
        CHECK(contains(body, "The selected View&#39;s saved filter on Beta is not supported"));
        CHECK_FALSE(contains(body, "NoSuchColumn"));
    }

    SECTION("two bad defaults: the first bad one in the View's order is named") {
        // Pins observed behaviour: the unsupported-value loop stops at the first bad filter.
        const auto id = make_multi_filter_definition(is, "tpl-multi-two-bad", cols,
                                                     {{"Alpha", over}, {"Beta", nul}});
        const auto body = fetch(id);
        CHECK(contains(body, "The selected View&#39;s saved filter on Alpha is not supported"));
        CHECK_FALSE(contains(body, "saved filter on Beta"));
    }

    SECTION("an empty default is refused before an unsupported one, whatever the order") {
        // Pins observed behaviour: view_empty_col is checked before the unsupported-value
        // loop, so the EMPTY default's column is named even when it comes second.
        const auto id = make_multi_filter_definition(is, "tpl-multi-empty-second", cols,
                                                     {{"Alpha", over}, {"Beta", empty}});
        const auto body = fetch(id);
        CHECK(contains(body, "data-filter-refused=\"true\""));
        CHECK(contains(body, "The selected View&#39;s saved filter on Beta has no value"));
        CHECK_FALSE(contains(body, "saved filter on Alpha"));
        CHECK_FALSE(contains(body, "is not supported"));
    }

    SECTION("two empty defaults: the first empty one is named") {
        const auto id = make_multi_filter_definition(is, "tpl-multi-two-empty", cols,
                                                     {{"Alpha", empty}, {"Beta", empty}});
        const auto body = fetch(id);
        CHECK(contains(body, "The selected View&#39;s saved filter on Alpha has no value"));
        CHECK_FALSE(contains(body, "saved filter on Beta"));
    }
}

// An explicit EMPTY f_* value is dropped by parse_filters, so it does not count as an operator
// filter: a View whose `equals` default is also empty is still refused. A NON-empty explicit
// filter on the same column replaces the View's defaults and is not refused. The View's column
// is "Output", the one column the plugin's f_* params can address.
TEST_CASE("/fragments/results: an explicit empty f_ value does not bypass an empty View default, "
          "a non-empty one does",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const auto id = make_multi_filter_definition(is, "tpl-multi-output-empty",
                                                 {"Name", "Output"}, {{"Output", nlohmann::json("")}});

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base = "/fragments/results?command_id=cmd-multi-2&plugin=registry&definition_id=" +
                             id + "&template_id=tplmulti";

    auto empty = h.get(base + "&f_output=");
    REQUIRE(empty);
    CHECK(empty->status == 200);
    CHECK(contains(empty->body, "data-filter-refused=\"true\""));
    CHECK(contains(empty->body, "The selected View&#39;s saved filter on Output has no value"));
    CHECK(contains(empty->body, "set any filter of your own"));
    CHECK_FALSE(contains(empty->body, "Response store not available"));

    auto explicit_ok = h.get(base + "&f_output=ok");
    REQUIRE(explicit_ok);
    CHECK(explicit_ok->status == 200);
    CHECK_FALSE(contains(explicit_ok->body, "data-filter-refused"));
    CHECK(contains(explicit_ok->body, "Response store not available")); // reached render_results
}

// ── #4644 Gate 7 (row 6a): the unfiltered read is byte-bounded and a cut is visible ──

TEST_CASE("/fragments/results: an unfiltered read cut by the payload cap shows a truncation "
          "notice an uncut one does not",
          "[pg][server][dashboard][fragment][cap]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-capped-1";
    for (const char* agent : {"agent-a", "agent-b", "agent-c"}) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent;
        r.received_at_ms = 1000;
        r.status = 0;
        r.output = std::string("output from ") + agent + " " + std::string(200, 'x');
        rs.store(r);
    }

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string url = "/fragments/results?command_id=" + command_id + "&plugin=registry";

    auto uncut = h.get(url);
    REQUIRE(uncut);
    CHECK(uncut->status == 200);
    CHECK(contains(uncut->body, "3 agents"));
    CHECK_FALSE(contains(uncut->body, "data-result-truncated"));

    // A 300-byte cap keeps two ~215-byte rows (a row is kept while the rows before it are under
    // the cap) and drops the third: the page must say its rows and counts are partial.
    yuzu::test::ExportByteCapGuard guard(300);
    auto cut = h.get(url);
    REQUIRE(cut);
    CHECK(cut->status == 200);
    CHECK(contains(cut->body, "data-result-truncated=\"true\""));
    CHECK(contains(cut->body, "2 agents"));
    CHECK_FALSE(contains(cut->body, "3 agents"));
}

// The cut can leave nothing that parses into a visible line (here: every kept response is a
// failure with an empty output). The summary must still say the read was cut, not read as
// "complete, no results".
TEST_CASE("/fragments/results: a cut read that parses to zero lines still says it was cut",
          "[pg][server][dashboard][fragment][cap]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    const std::string command_id = "cmd-frag-capped-empty";
    for (const char* agent : {"agent-a", "agent-b", "agent-c"}) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent;
        r.received_at_ms = 1000;
        r.status = 1;
        r.output = "";                       // nothing to parse into a result line
        r.error_detail = std::string(200, 'e'); // but it counts against the payload cap
        rs.store(r);
    }

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string url = "/fragments/results?command_id=" + command_id + "&plugin=registry";

    // Control: uncut, no parsed lines, no truncation notice.
    auto uncut = h.get(url);
    REQUIRE(uncut);
    CHECK(uncut->status == 200);
    CHECK_FALSE(contains(uncut->body, "data-result-truncated"));

    // A 300-byte cap keeps two 200-byte rows and drops the third.
    yuzu::test::ExportByteCapGuard guard(300);
    auto cut = h.get(url);
    REQUIRE(cut);
    CHECK(cut->status == 200);
    CHECK(contains(cut->body, "data-result-truncated=\"true\""));
    CHECK(contains(cut->body, "so these rows and counts are partial"));
    CHECK_FALSE(contains(cut->body, " results across "));
}
