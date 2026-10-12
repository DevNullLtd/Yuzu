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
#include "test_real_capability_registry.hpp"
#include "test_route_sink.hpp"
#include "test_export_cap_guard.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
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

// The dashboard refusal wording is plain language (#5623): none of the REST/MCP technical
// jargon may reach an operator. Case-sensitive on purpose ("NUL" the byte name).
void check_plain_refusal_wording(const std::string& body) {
    for (const char* jargon :
         {"exact-match", "NUL", "UTF-8", "line feed", "not evaluated", "bypass"}) {
        INFO(jargon);
        CHECK_FALSE(contains(body, jargon));
    }
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
    // #5669: every successful results response clears an open Create Static Group form, which would
    // otherwise keep the filters and agent count of the render that opened it.
    CHECK(contains(res->body, "<div id=\"group-form-slot\" hx-swap-oob=\"innerHTML\"></div>"));

    // A text-filtered response clears it too (a filter change is the case that matters).
    auto filtered = h.get("/fragments/results?command_id=" + command_id +
                          "&plugin=registry&q=output+a");
    REQUIRE(filtered);
    CHECK(contains(filtered->body, "output a"));
    CHECK_FALSE(contains(filtered->body, "output b"));
    CHECK(contains(filtered->body,
                   "<div id=\"group-form-slot\" hx-swap-oob=\"innerHTML\"></div>"));
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
    // Gate 8 quality-engineer finding (earlier round): assert an actual result row
    // rendered so a facet-population regression (the earlier draft's false-pass class) can't
    // silently zero out this test's positive half. (Historically the sort links also echoed
    // the raw f_output value, which made the string above reachable at zero matching rows;
    // #5623 G8-2 removed that echo, so the row is now the only source.)
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

// A request target over httplib's 8192-byte limit gets an empty-body 414 before any handler runs,
// and htmx does not swap a 4xx, so the stale table would stay on screen (#5668). The served
// dashboard carries a client-side listener that shows the same refusal row instead. This pins the
// served script text (present, what it touches, no innerHTML); its behaviour was checked in a
// headless browser during the #5623 review, not by this test.
TEST_CASE("dashboard script: a 414 on /fragments/results shows a refusal row, built with textContent",
          "[server][dashboard][fragment]") {
    const std::string html = kDashboardIndexHtml;
    const auto at = html.find("xhr.status !== 414");
    REQUIRE(at != std::string::npos);
    const auto end = html.find("</script>", at);
    REQUIRE(end != std::string::npos);
    const std::string body = html.substr(at, end - at);
    CHECK(contains(body, "split('?')[0] !== '/fragments/results'"));
    CHECK(contains(body, "td.className = 'empty-state filter-refused'"));
    CHECK(contains(body, "data-filter-refused"));
    for (const char* id : {"results-thead", "result-pagination", "result-summary",
                           "chart-deck-host", "group-form-slot"}) {
        INFO(id);
        CHECK(contains(body, std::string("'") + id + "'"));
    }
    // No innerHTML with dynamic data: the message is a literal set through textContent.
    CHECK_FALSE(contains(body, "innerHTML"));
    CHECK_FALSE(contains(body, "hx-on"));
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
    // A refusal is read, not skimmed: it must not inherit .empty-state's low-contrast colour.
    CHECK(contains(body, "color: var(--yellow"));
    // The group-form refusal span gets padding and its own line (it sat flush against the edge).
    const auto fb = css.find(".feedback-error[data-filter-refused] {");
    REQUIRE(fb != std::string::npos);
    const std::string fbody = css.substr(fb, css.find('}', fb) - fb);
    CHECK(contains(fbody, "display: block"));
    CHECK(contains(fbody, "padding:"));
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
    CHECK(contains(res->body, "That filter value can&#39;t be searched."));
    CHECK_FALSE(contains(res->body, "2048")); // the technical bound is left to REST/MCP
    check_plain_refusal_wording(res->body);
    CHECK_FALSE(contains(res->body, "Response store not available"));
    CHECK_FALSE(contains(res->body, over)); // the value is never echoed
    check_results_chrome_cleared(res->body);
}

// A NUL, line feed or invalid UTF-8 byte in a filter value can never equal a stored value
// (ingest rewrites each NUL / bad byte to U+FFFD, and separately splits the output on every
// LF, so no LF is ever stored), and a NUL is C-string-truncated by the libpq bind, which
// matched the prefix (`short%00zzz` showed the rows of `short`). Refused like an over-bound
// value, before any store access (the store is nullptr: "Response store not available"
// would mean it was reached).
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
        CHECK(contains(res->body, "That filter value can&#39;t be searched."));
        CHECK(contains(res->body, "It may be too long, or contain a line break."));
        CHECK(contains(res->body, "Shorten it or clear the filter."));
        check_plain_refusal_wording(res->body);
        CHECK_FALSE(contains(res->body, "This View"));
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
    CHECK(contains(over->body, "This View has a built-in filter on Name that can&#39;t be used"));
    CHECK_FALSE(contains(over->body, "2048"));
    check_plain_refusal_wording(over->body);
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
// fault. The operator's own f_* filter -> "That filter value can't be searched ..."; the
// selected View's saved `equals` default -> "This View has a built-in filter on <column> that
// can't be used ... Pick another View." (plain wording, no jargon). The column name is
// template-author text, so it must appear html-escaped; the
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
        CHECK(contains(res->body,
                       "This View has a built-in filter on A&lt;b&gt;&amp;D that can&#39;t be "
                       "used, so no results are shown. Pick another View."));
        check_plain_refusal_wording(res->body);
        CHECK_FALSE(contains(res->body, "That filter value"));
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
    CHECK(contains(op->body, "That filter value can&#39;t be searched."));
    check_plain_refusal_wording(op->body);
    CHECK_FALSE(contains(op->body, "This View"));
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
    const auto at_id = make_provenance_definition(is, "tpl-prov-at",
                                                  nlohmann::json(std::string(2048, 'v')));

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
    CHECK(contains(empty->body,
                   "This View has a built-in filter on A&lt;b&gt;&amp;D with no value, so no "
                   "results are shown. Pick another View."));
    check_plain_refusal_wording(empty->body);
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
            CHECK(contains(body, "This View has a built-in filter on Beta that can&#39;t be used"));
            CHECK_FALSE(contains(body, "built-in filter on Alpha"));
            CHECK_FALSE(contains(body, "Response store not available"));
        }
    }

    SECTION("a first default on a column that does not resolve is skipped, the second is named") {
        const auto id = make_multi_filter_definition(
            is, "tpl-multi-unknown", cols, {{"NoSuchColumn", good}, {"Beta", over}});
        const auto body = fetch(id);
        CHECK(contains(body, "data-filter-refused=\"true\""));
        CHECK(contains(body, "This View has a built-in filter on Beta that can&#39;t be used"));
        CHECK_FALSE(contains(body, "NoSuchColumn"));
    }

    SECTION("two bad defaults: the first bad one in the View's order is named") {
        // Pins observed behaviour: the unsupported-value loop stops at the first bad filter.
        const auto id = make_multi_filter_definition(is, "tpl-multi-two-bad", cols,
                                                     {{"Alpha", over}, {"Beta", nul}});
        const auto body = fetch(id);
        CHECK(contains(body, "This View has a built-in filter on Alpha that can&#39;t be used"));
        CHECK_FALSE(contains(body, "built-in filter on Beta"));
    }

    SECTION("an empty default is refused before an unsupported one, whatever the order") {
        // Pins observed behaviour: view_empty_col is checked before the unsupported-value
        // loop, so the EMPTY default's column is named even when it comes second.
        const auto id = make_multi_filter_definition(is, "tpl-multi-empty-second", cols,
                                                     {{"Alpha", over}, {"Beta", empty}});
        const auto body = fetch(id);
        CHECK(contains(body, "data-filter-refused=\"true\""));
        CHECK(contains(body, "This View has a built-in filter on Beta with no value"));
        CHECK_FALSE(contains(body, "built-in filter on Alpha"));
        CHECK_FALSE(contains(body, "that can&#39;t be used"));
    }

    SECTION("two empty defaults: the first empty one is named") {
        const auto id = make_multi_filter_definition(is, "tpl-multi-two-empty", cols,
                                                     {{"Alpha", empty}, {"Beta", empty}});
        const auto body = fetch(id);
        CHECK(contains(body, "This View has a built-in filter on Alpha with no value"));
        CHECK_FALSE(contains(body, "built-in filter on Beta"));
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
    const auto id = make_multi_filter_definition(is, "tpl-multi-output-empty", {"Name", "Output"},
                                                 {{"Output", nlohmann::json("")}});

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base =
        "/fragments/results?command_id=cmd-multi-2&plugin=registry&definition_id=" + id +
        "&template_id=tplmulti";

    auto empty = h.get(base + "&f_output=");
    REQUIRE(empty);
    CHECK(empty->status == 200);
    CHECK(contains(empty->body, "data-filter-refused=\"true\""));
    CHECK(contains(empty->body, "This View has a built-in filter on Output with no value"));
    check_plain_refusal_wording(empty->body);
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

// -- #5623: every /fragments/results request shares ONE replacing hx-sync scope ------------------
// The filter bar used `closest form:abort` (drops the NEWEST request) while th / pagination used
// `this:abort`, so a correction typed during a refused or slow response was never sent, and a
// late sort/page response could land after another response's OOB swap had detached its issuer.
// Every element whose hx-get targets /fragments/results (filter-bar controls, the View select,
// th sort links, Prev/Next) carries the same `#filter-bar:replace`. The deck refresh trigger lives
// in the filter-bar form (render_filter_bar; its test is in test_dashboard_results_columns.cpp).
// The replacing semantics were verified in headless Chromium during the #5623 review, not by
// this test: it pins the exact scope string and that no element is left behind.
namespace {
// Number of elements whose hx-get is /fragments/results[?...] (not /filter-bar), failing the
// calling test for any one of them whose tag lacks the shared scope or carries a second hx-sync.
std::size_t count_results_requests_sharing_scope(const std::string& html) {
    const std::string needle = "hx-get=\"/fragments/results";
    const std::string scope = std::string("hx-sync=\"") + kResultsSyncScope + "\"";
    std::size_t found = 0;
    for (auto pos = html.find(needle); pos != std::string::npos;
         pos = html.find(needle, pos + 1)) {
        if (html.compare(pos + needle.size(), 11, "/filter-bar") == 0)
            continue;
        const auto open = html.rfind('<', pos);
        const auto close = html.find('>', pos);
        REQUIRE(open != std::string::npos);
        REQUIRE(close != std::string::npos);
        const std::string tag = html.substr(open, close - open + 1);
        INFO(tag);
        CHECK(contains(tag, scope));
        CHECK(tag.find("hx-sync=", tag.find("hx-sync=") + 1) == std::string::npos);
        ++found;
    }
    return found;
}
} // namespace

TEST_CASE("kResultsSyncScope is the replacing scope, not a dropping or queueing one",
          "[server][dashboard][fragment]") {
    // `:drop` / `:abort` / `:queue` would drop or defer the newest request (the #5623 defect).
    CHECK(std::string(kResultsSyncScope) == "#filter-bar:replace");
}

TEST_CASE("/fragments/results: filter bar, sort headers and pagination share one replacing "
          "hx-sync scope",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    // 25 distinct lines of one column: more than 20 facet values (a text input in the bar) and
    // three pages at per_page=10 (page 2 has both Prev and Next).
    const auto store_lines = [&](const std::string& command_id, int lines) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = "agent-a";
        r.received_at_ms = 1000;
        r.status = 0;
        r.plugin = "registry";
        for (int i = 0; i < lines; ++i)
            r.output += std::format("line-{:02}\n", i);
        rs.store(r);
    };
    store_lines("cmd-sync-many", 25);
    store_lines("cmd-sync-few", 3);
    const auto def_id = make_multi_filter_definition(is, "tpl-sync", {"Output"}, {});

    FragmentResultsHarness h(&rs, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });

    // Filter bar, high cardinality: View select + text input + free-text search + the hidden
    // deck-refresh trigger (a fourth /fragments/results request, on the same scope).
    auto many_bar = h.get("/fragments/results/filter-bar?command_id=cmd-sync-many&plugin=registry"
                          "&definition_id=" + def_id);
    REQUIRE(many_bar);
    CHECK(contains(many_bar->body, "<select name=\"template_id\""));
    CHECK(contains(many_bar->body, "<input type=\"text\" name=\"f_output\""));
    CHECK(contains(many_bar->body, "<input type=\"search\" name=\"q\""));
    CHECK(count_results_requests_sharing_scope(many_bar->body) == 4);
    CHECK(contains(many_bar->body,
                   std::string("<form id=\"filter-bar\" class=\"filter-bar\" hx-sync=\"") +
                       kResultsSyncScope + "\">"));

    // Filter bar, low cardinality: the column is a select instead of a text input.
    auto few_bar = h.get("/fragments/results/filter-bar?command_id=cmd-sync-few&plugin=registry"
                         "&definition_id=" + def_id);
    REQUIRE(few_bar);
    CHECK(contains(few_bar->body, "<select name=\"f_output\""));
    CHECK_FALSE(contains(few_bar->body, "<input type=\"text\" name=\"f_output\""));
    CHECK(count_results_requests_sharing_scope(few_bar->body) == 4);

    // Results page 2 of 3: Agent + Output sort headers, Prev and Next.
    auto page = h.get("/fragments/results?command_id=cmd-sync-many&plugin=registry&per_page=10"
                      "&page=2");
    REQUIRE(page);
    CHECK(contains(page->body, "<th class=\"col-agent sortable\""));
    CHECK(contains(page->body, ">Prev</button>"));
    CHECK(contains(page->body, ">Next</button>"));
    CHECK(count_results_requests_sharing_scope(page->body) == 4);

    // No results request anywhere still uses a dropping/aborting scope.
    for (const auto* body : {&many_bar->body, &few_bar->body, &page->body}) {
        CHECK_FALSE(contains(*body, ":abort"));
        CHECK_FALSE(contains(*body, "closest form"));
        CHECK_FALSE(contains(*body, "hx-sync=\"this"));
    }
}

// -- #5623 (governance G8-2): sort headers and Prev/Next read the LIVE filter bar -----------------
// base_url() used to bake the LAST render's command_id / plugin / definition_id / template_id /
// f_* / q into every th and pager hx-get. With the shared replacing scope, a click during a
// filter change's flight aborted that request and then landed its own stale-filter request, so
// the controls and the rows disagreed. The links now carry hx-include="#filter-bar" and ONLY
// sort / dir / page / per_page. httplib's get_param_value takes the FIRST occurrence, so a baked
// duplicate would beat the live value: nothing but those four may appear.
namespace {
// Every opening tag that carries a results hx-get and is a sort header or a pager button.
std::vector<std::string> sort_and_pager_tags(const std::string& html) {
    std::vector<std::string> tags;
    const std::string needle = "hx-get=\"/fragments/results?";
    for (auto pos = html.find(needle); pos != std::string::npos;
         pos = html.find(needle, pos + 1)) {
        const auto open = html.rfind('<', pos);
        const auto close = html.find('>', pos);
        REQUIRE(open != std::string::npos);
        REQUIRE(close != std::string::npos);
        std::string tag = html.substr(open, close - open + 1);
        if (contains(tag, "class=\"btn-page\"") || contains(tag, "sortable"))
            tags.push_back(std::move(tag));
    }
    return tags;
}

// The hx-get URL of one tag, query string only (HTML-escaped ampersands left as-is).
std::string hx_get_query(const std::string& tag) {
    const std::string needle = "hx-get=\"/fragments/results?";
    const auto b = tag.find(needle);
    REQUIRE(b != std::string::npos);
    const auto start = b + needle.size();
    const auto end = tag.find('"', start);
    REQUIRE(end != std::string::npos);
    return tag.substr(start, end - start);
}
} // namespace

TEST_CASE("/fragments/results: sort headers and Prev/Next include the live filter bar and bake "
          "no filter params",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    // 25 identical lines: an exact-match f_output filter keeps all of them, so a FILTERED
    // request still spans three pages at per_page=10 (page 2 has both Prev and Next).
    StoredResponse r;
    r.instruction_id = "cmd-live-filter";
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    for (int i = 0; i < 25; ++i)
        r.output += "same\n";
    rs.store(r);
    const auto def_id = make_multi_filter_definition(is, "tpl-live", {"Output"}, {});

    FragmentResultsHarness h(&rs, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });

    // Every param the form owns is present on the request, so the pre-fix base_url would have
    // baked all of them.
    auto page = h.get("/fragments/results?command_id=cmd-live-filter&plugin=registry"
                      "&definition_id=" + def_id + "&template_id=tplmulti&f_output=same&q=sam"
                      "&per_page=10&page=2");
    REQUIRE(page);
    REQUIRE(page->status == 200);
    // Not vacuous: the filter really applied and the page really has both pager buttons.
    CHECK(contains(page->body, "Showing 11-20 of 25"));
    CHECK(contains(page->body, ">Prev</button>"));
    CHECK(contains(page->body, ">Next</button>"));

    const auto tags = sort_and_pager_tags(page->body);
    // The Agent column is always shown: Agent + Output sort headers, Prev and Next make 4.
    REQUIRE(tags.size() == 4);
    for (const auto& tag : tags) {
        INFO(tag);
        CHECK(contains(tag, "hx-include=\"#filter-bar\""));
        const auto q = hx_get_query(tag);
        INFO(q);
        for (const char* baked : {"command_id=", "plugin=", "definition_id=", "template_id=",
                                  "f_", "q="}) {
            CHECK_FALSE(contains(q, baked));
        }
        CHECK(contains(q, "sort="));
        CHECK(contains(q, "&amp;dir="));
        CHECK(contains(q, "&amp;page="));
        CHECK(contains(q, "&amp;per_page=10"));
        // Exact key set: no extra param of any name may be baked in.
        std::set<std::string> keys;
        std::size_t pos = 0;
        while (pos <= q.size()) {
            auto end = q.find("&amp;", pos);
            if (end == std::string::npos) end = q.size();
            const std::string pair = q.substr(pos, end - pos);
            keys.insert(pair.substr(0, pair.find('=')));
            pos = end + 5;
        }
        CHECK(keys == std::set<std::string>{"sort", "dir", "page", "per_page"});
    }

    // The Create Group button is NOT a sort/page link and must keep its own command_id +
    // filters (the create-group form reads only those, not the filter bar).
    const auto cg = page->body.find("class=\"btn-create-group\"");
    REQUIRE(cg != std::string::npos);
    const auto cg_open = page->body.rfind('<', cg);
    const auto cg_close = page->body.find('>', cg);
    const std::string cg_tag = page->body.substr(cg_open, cg_close - cg_open + 1);
    CHECK(contains(cg_tag, "command_id=cmd-live-filter"));
    CHECK(contains(cg_tag, "&amp;f_output=same"));
    CHECK_FALSE(contains(cg_tag, "hx-include"));
}

// The Create Group button names its filter params from the plugin's columns (the list
// parse_filters and the create-group form use), not from the definition-resolved display list. A
// definition whose columns are named differently from the plugin's used to produce a button URL
// the form could not parse: no filters, "0 agents will be added", and a submit that answered 422.
TEST_CASE("/fragments/results: the Create Group button names filters by the plugin's columns, "
          "not the definition's",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    StoredResponse r;
    r.instruction_id = "cmd-cg-names";
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    r.output = "same\n";
    rs.store(r);
    // "Zeta" is not a column of the registry plugin, so the display list names index 0 "Zeta"
    // while the filter parameter the page was requested with is the plugin's f_output.
    const auto def_id = make_multi_filter_definition(is, "tpl-cg-names", {"Zeta"}, {});

    FragmentResultsHarness h(&rs, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    auto page = h.get("/fragments/results?command_id=cmd-cg-names&plugin=registry"
                      "&definition_id=" + def_id + "&f_output=same");
    REQUIRE(page);
    REQUIRE(page->status == 200);
    const auto cg = page->body.find("class=\"btn-create-group\"");
    REQUIRE(cg != std::string::npos);
    const auto cg_open = page->body.rfind('<', cg);
    const auto cg_close = page->body.find('>', cg);
    const std::string cg_tag = page->body.substr(cg_open, cg_close - cg_open + 1);
    INFO(cg_tag);
    CHECK(contains(cg_tag, "&amp;f_output=same"));
    CHECK_FALSE(contains(cg_tag, "f_zeta"));
}

// The Create Group button puts the filter value in a query string. A value with `+`, `&`, `#`
// or `%` (a package version, "Tom & Jerry") used to be only HTML-escaped, so `+` reached the form
// as a space and `&` ended the value: the preview matched nothing ("0 agents"). It is now
// percent-encoded; the HTML separators between parameters stay `&amp;`.
TEST_CASE("/fragments/results: the Create Group button percent-encodes the filter value",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());

    const std::string value = "a+b&c#d%e f";
    StoredResponse r;
    r.instruction_id = "cmd-cg-encode";
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    r.output = value + "\n";
    rs.store(r);

    FragmentResultsHarness h(&rs);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    // The request carries the value percent-encoded, as the browser sends it.
    auto page = h.get("/fragments/results?command_id=cmd-cg-encode&plugin=registry"
                      "&f_output=a%2Bb%26c%23d%25e%20f");
    REQUIRE(page);
    REQUIRE(page->status == 200);
    const auto cg = page->body.find("class=\"btn-create-group\"");
    REQUIRE(cg != std::string::npos);
    const auto cg_open = page->body.rfind('<', cg);
    const auto cg_close = page->body.find('>', cg);
    const std::string cg_tag = page->body.substr(cg_open, cg_close - cg_open + 1);
    INFO(cg_tag);
    CHECK(contains(cg_tag, "&amp;f_output=a%2Bb%26c%23d%25e%20f\""));
    CHECK_FALSE(contains(cg_tag, "a+b"));
}

// -- #5623 (governance G8-3): a dispatch aborts any in-flight results request --------------------
// The dispatch response replaces #filter-bar with a fresh element, discarding the hx-sync
// registry attached to the OLD form / thead / pager. A /fragments/results request in flight at
// Send time would then survive, and its late response would swap the OLD command's rows and
// Create-Group chrome (carrying the OLD command_id) over the NEW command's table. The response's
// HX-Trigger therefore ends with an `htmx:abort` addressed at the scope's selector half. Read from
// the bundled htmx 2.0.4 (static_js_bundle.cpp), not run in a browser by this test: the trigger
// header handler reassigns the dispatch target on a key's `target` and that reassignment persists
// for every LATER key, so `htmx:abort` must be the LAST key, with showToast first on the issuer.
namespace {
struct ExecDispatchHarness {
    // `routes` and `metrics`, which the registered handlers reference, must outlive the sink's
    // last dispatch (see the other harnesses in this file). `sent` is a trivial std::size_t only
    // read by the dispatch lambda while post() runs, so its destruction order does not matter.
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::size_t sent{2};

    explicit ExecDispatchHarness(InstructionStore* instruction_store = nullptr) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "exec-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {};
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string&, const std::string&, const std::vector<std::string>&,
                   const std::string&, const std::unordered_map<std::string, std::string>&,
                   const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
            return {.sent = sent, .command_id = "cmd-exec-abort"};
        };
        routes.register_routes(
            sink, auth_fn, perm_fn, audit_fn, /*response_store=*/nullptr,
            /*mgmt_group_store=*/nullptr, /*registry=*/nullptr, /*tag_store=*/nullptr,
            /*event_bus=*/nullptr, /*agents_json_fn=*/[] { return std::string{"[]"}; }, dispatch,
            /*caller_fn=*/
            [](const httplib::Request&) -> yuzu::server::DispatchCaller {
                return yuzu::server::DispatchCaller{.principal = "exec-op",
                                                    .exec_visible = std::nullopt};
            },
            /*resolve_fn=*/
            [](const std::string&) {
                return std::pair<std::string, std::string>{"os_info", "os_version"};
            },
            &metrics, instruction_store);
        routes.set_capability_classify_fn(yuzu::test::real_classify_fn());
    }

    std::unique_ptr<httplib::Response> post(const std::string& body) {
        const std::unordered_map<std::string, std::string> headers{
            {"Host", "yuzu.example:8080"}, {"Origin", "https://yuzu.example:8080"}};
        auto res = sink.dispatch("POST", "/api/dashboard/execute", body,
                                 "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }
};
} // namespace

TEST_CASE("dashboard execute: the HX-Trigger ends with an htmx:abort at the results sync scope",
          "[server][dashboard][fragment][execute]") {
    ExecDispatchHarness h;
    auto res = h.post("instruction=run&scope=__all__");
    REQUIRE(res->status == 200);
    // Not vacuous: this is the success arm that replaces #filter-bar.
    CHECK(contains(res->body, "<div id=\"filter-bar\" hx-swap-oob=\"true\""));

    REQUIRE(res->has_header("HX-Trigger"));
    const std::string raw = res->get_header_value("HX-Trigger");
    INFO(raw);
    const auto j = nlohmann::json::parse(raw, nullptr, /*allow_exceptions=*/false);
    REQUIRE(j.is_object());
    REQUIRE(j.contains("showToast"));
    REQUIRE(j.contains("htmx:abort"));
    REQUIRE(j["htmx:abort"].is_object());

    // The abort addresses the selector half of the shared scope (the part before ':').
    const std::string scope = kResultsSyncScope;
    const std::string selector = scope.substr(0, scope.find(':'));
    CHECK(selector == "#filter-bar");
    CHECK(j["htmx:abort"].value("target", "") == selector);

    // Order is load-bearing (nlohmann sorts keys, so read the raw header): showToast first,
    // htmx:abort the LAST key, so the target reassignment cannot redirect the toast.
    const auto toast_at = raw.find("\"showToast\"");
    const auto abort_at = raw.find("\"htmx:abort\"");
    REQUIRE(toast_at != std::string::npos);
    REQUIRE(abort_at != std::string::npos);
    CHECK(toast_at < abort_at);
    CHECK(raw.rfind("\"showToast\"") < abort_at);
    REQUIRE(raw.size() >= 2);
    CHECK(raw.substr(raw.size() - 2) == "}}");
    // No second top-level key after htmx:abort: exactly two top-level keys, and the toast does
    // not carry a `target` of its own.
    CHECK(j.size() == 2);
    CHECK_FALSE(j["showToast"].contains("target"));
}

// -- #5623: the dispatch response only CLEARS the chart-deck host --------------------------------
// The deck refresh (one request, no polling) used to be emitted here as a `load delay:2s` host
// queued behind the placeholder (`queue last`); a real browser showed htmx discards the
// placeholder's queue when its outerHTML swap removes it, so the request was never sent. The
// trigger now lives in the filter-bar form (render_filter_bar). This response must not carry an
// hx-get on the host again.
TEST_CASE("dashboard execute: the chart-deck host is cleared, never a refresh request",
          "[pg][server][dashboard][fragment][execute]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    // The harness's resolve_fn maps every instruction to os_info / os_version; a definition for
    // that pair with a result schema is what used to make the dispatch emit a deck host with an
    // hx-get, so this is not vacuous.
    InstructionDefinition def;
    def.name = "deck-host-cleared";
    def.version = "1.0.0";
    def.plugin = "os_info";
    def.action = "os_version";
    def.type = "question";
    def.enabled = true;
    def.result_schema = R"([{"name":"Name","type":"string"}])";
    auto created = is.create_definition(def);
    REQUIRE(created.has_value());

    ExecDispatchHarness h(&is);
    auto res = h.post("instruction=run&scope=__all__");
    REQUIRE(res->status == 200);
    const std::string& body = res->body;
    INFO(body);

    // The filter-bar placeholder still carries the definition id (the form fetched from it renders
    // the deck trigger), and the deck host is the bare clearing div.
    CHECK(contains(body, "<div id=\"filter-bar\" hx-swap-oob=\"true\""
                         " hx-get=\"/fragments/results/filter-bar?"));
    CHECK(contains(body, "definition_id="));
    CHECK(contains(body, "<div id=\"chart-deck-host\" hx-swap-oob=\"true\"></div>"));
    const auto deck_at = body.find("id=\"chart-deck-host\"");
    REQUIRE(deck_at != std::string::npos);
    const auto deck_close = body.find('>', deck_at);
    REQUIRE(deck_close != std::string::npos);
    CHECK_FALSE(contains(body.substr(deck_at, deck_close - deck_at), "hx-get"));
    // Nothing else in the dispatch response may fetch /fragments/results on its own.
    CHECK_FALSE(contains(body, "hx-get=\"/fragments/results?"));
}

// -- #5623: authorization runs before the refusal, and a refusal is counted ---------------------
TEST_CASE("/fragments/results: a denied caller gets the gate's response, not a facet refusal",
          "[server][dashboard][fragment][auth]") {
    FragmentResultsHarness h(/*response_store=*/nullptr);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response& res, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            res.status = 403;
            res.set_content(R"({"error":"permission denied"})", "application/json");
            return {false, yuzu::server::authz::deny_all()};
        });
    // Each value would be refused for an admitted caller (tests above).
    for (const std::string value : {std::string(2049, 'v'), std::string("a%00b"),
                                    std::string("a%0Ab"), std::string("%FF")}) {
        INFO(value.substr(0, 20));
        auto res = h.get("/fragments/results?command_id=cmd-deny-1&plugin=registry&f_output=" +
                         value);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(contains(res->body, "permission denied"));
        CHECK_FALSE(contains(res->body, "data-filter-refused"));
        CHECK_FALSE(contains(res->body, "can&#39;t be searched"));
    }
    CHECK(h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "dashboard"}})
              .value() == 0.0);
}

// The same ordering with a stored View whose own saved default is unmatchable: the View is
// resolved from a real InstructionStore, but a denied caller still gets only the gate's response.
TEST_CASE("/fragments/results: a denied caller with a bad View gets the gate's response, "
          "not a facet refusal",
          "[pg][server][dashboard][fragment][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const auto empty_view = make_provenance_definition(is, "tpl-deny-empty", nlohmann::json(""));
    const auto over_view = make_provenance_definition(is, "tpl-deny-over",
                                                      nlohmann::json(std::string(2049, 'v')));

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response& res, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            res.status = 403;
            res.set_content(R"({"error":"permission denied"})", "application/json");
            return {false, yuzu::server::authz::deny_all()};
        });
    for (const auto& def_id : {empty_view, over_view}) {
        INFO(def_id);
        auto res = h.get("/fragments/results?command_id=cmd-deny-view&plugin=registry"
                         "&definition_id=" + def_id + "&template_id=tplprov");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(contains(res->body, "permission denied"));
        CHECK_FALSE(contains(res->body, "data-filter-refused"));
        CHECK_FALSE(contains(res->body, "can&#39;t be searched"));
    }
    CHECK(h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "dashboard"}})
              .value() == 0.0);
}

TEST_CASE("/fragments/results: each refused request increments "
          "yuzu_server_response_facet_filter_refused_total{surface=dashboard} once",
          "[pg][server][dashboard][fragment][metrics]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    const auto empty_view = make_provenance_definition(is, "tpl-cnt-empty", nlohmann::json(""));
    const auto over_view = make_provenance_definition(is, "tpl-cnt-over",
                                                      nlohmann::json(std::string(2049, 'v')));
    const auto at_view = make_provenance_definition(is, "tpl-cnt-at",
                                                    nlohmann::json(std::string(2048, 'v')));

    FragmentResultsHarness h(/*response_store=*/nullptr, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const auto refused = [&] {
        return h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "dashboard"}})
            .value();
    };
    const std::string base = "/fragments/results?command_id=cmd-cnt-1&plugin=registry&";
    REQUIRE(refused() == 0.0);

    // Not refused: an at-bound View value and a valid operator filter (both reach the store,
    // which is absent here: "Response store not available" proves the refusal did not run).
    auto ok_view = h.get(base + "definition_id=" + at_view + "&template_id=tplprov");
    REQUIRE(ok_view);
    CHECK(contains(ok_view->body, "Response store not available"));
    auto ok_filter = h.get(base + "f_output=fine");
    REQUIRE(ok_filter);
    CHECK(contains(ok_filter->body, "Response store not available"));
    CHECK(refused() == 0.0);

    auto operator_filter = h.get(base + "f_output=" + std::string(2049, 'v'));
    REQUIRE(operator_filter);
    CHECK(contains(operator_filter->body, "data-filter-refused"));
    CHECK(refused() == 1.0);

    auto view_over = h.get(base + "definition_id=" + over_view + "&template_id=tplprov");
    REQUIRE(view_over);
    CHECK(contains(view_over->body, "data-filter-refused"));
    CHECK(refused() == 2.0);

    auto view_empty = h.get(base + "definition_id=" + empty_view + "&template_id=tplprov");
    REQUIRE(view_empty);
    CHECK(contains(view_empty->body, "data-filter-refused"));
    CHECK(refused() == 3.0);

    // The other surfaces did not move.
    CHECK(h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "rest"}}).value() ==
          0.0);
    CHECK(h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "mcp"}}).value() ==
          0.0);
}

// -- #5623: a VALID View `equals` default still filters, through a real store -------------------
// The refusal tests above run with no response store; this one proves the happy path is
// unchanged: a View whose saved `equals` value is storable returns just the matching rows, and
// the same request without the View returns them all.
TEST_CASE("/fragments/results: a valid View equals default filters the rows through a real store",
          "[pg][server][dashboard][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    REQUIRE(rs.is_open());
    YUZU_REQUIRE_PG_DB_TPL(db_instr, fragment_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    StoredResponse r;
    r.instruction_id = "cmd-view-valid-1";
    r.agent_id = "agent-a";
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    r.output = "line-03\nline-07\nline-09\n";
    rs.store(r);
    const auto def_id = make_multi_filter_definition(is, "tpl-view-valid", {"Output"},
                                                     {{"Output", nlohmann::json("line-07")}});

    FragmentResultsHarness h(&rs, &is);
    h.routes.set_fleet_read_fn(
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) -> yuzu::server::authz::FleetReadGate {
            return {true, std::nullopt};
        });
    const std::string base = "/fragments/results?command_id=cmd-view-valid-1&plugin=registry";

    auto unfiltered = h.get(base);
    REQUIRE(unfiltered);
    CHECK(contains(unfiltered->body, "line-03"));
    CHECK(contains(unfiltered->body, "line-07"));
    CHECK(contains(unfiltered->body, "line-09"));

    auto viewed = h.get(base + "&definition_id=" + def_id + "&template_id=tplmulti");
    REQUIRE(viewed);
    CHECK(viewed->status == 200);
    CHECK_FALSE(contains(viewed->body, "data-filter-refused"));
    CHECK(contains(viewed->body, "line-07"));
    CHECK_FALSE(contains(viewed->body, "line-03"));
    CHECK_FALSE(contains(viewed->body, "line-09"));
    CHECK(h.metrics.counter(kResponseFacetFilterRefusedMetric, {{"surface", "dashboard"}})
              .value() == 0.0);
}
