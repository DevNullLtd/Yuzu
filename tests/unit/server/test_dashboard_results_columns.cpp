/**
 * test_dashboard_results_columns.cpp -- render harness for
 * DashboardRoutes::resolve_render_columns / render_results (PR1.7
 * remediation).
 *
 * `columns_for_plugin` (result_parsing.hpp) resolves a fixed column schema
 * per PLUGIN name, with no notion of ACTION. registry's `list_profiles`
 * action has no entry there, so before this fix its rows (4 named fields:
 * sid, profile_name, profile_path, hive_state) rendered under the 2-column
 * default {"Agent","Output"} -- and once a response-template resolved, the
 * header/data mismatch became total suppression: every profile field was
 * hidden, leaving only the Agent column. The fix adds
 * `resolve_render_columns`, which derives columns from a resolved
 * InstructionDefinition's `result_schema` via
 * `ResponseTemplatesEngine::synthesise_default` when one is available,
 * falling back to `columns_for_plugin` otherwise.
 *
 * Only `ResponseTemplatesEngine::synthesise_default` itself was previously
 * pinned (test_response_templates_engine.cpp) -- this file closes the gap at
 * the layer the actual bug lived: render_results' header AND row-visibility
 * logic (`is_visible()`), which is what the pre-fix `is_visible()` check
 * actually suppressed against.
 *
 * render_results and its inputs (instruction_store_, response_store_) are
 * private; the DashboardResultsColumnsTestAccess friend seam
 * (dashboard_routes.hpp) wires them without standing up an HTTP server, same
 * shape as test_dashboard_tar_retention.cpp's seam.
 */

#include "dashboard_routes.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <set>
#include <string>
#include <unordered_set>

namespace yuzu::server {

using yuzu::server::pg::PgPool;

namespace {
// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};
// InstructionStore is now a migrated Postgres store (ADR-0058).
yuzu::test::PgTestTemplate dashboard_cols_instr_tpl{
    "dashcolsinstr", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("dashboard_cols_instr template: store failed to migrate");
    }};
} // namespace

// Test-only accessor for the private schema-aware column resolution +
// render_results, and their store inputs (PR1.7 remediation, Gate 3).
//
// Extended (dashboard facet-scope confinement) with a visible_set_fn_ setter
// and a username-taking render_filter_bar wrapper, so the renderer-level
// confinement states (confined / deny-all / degraded / unwired-legacy-open)
// can be driven directly without standing up a route sink. See the
// SINK-DISPATCHED CONFINEMENT case below for the complementary
// through-the-route dispatch, which wires visible_set_fn via
// register_routes' own parameter instead of this friend seam.
struct DashboardResultsColumnsTestAccess {
    DashboardRoutes routes;

    void set_stores(InstructionStore* is, ResponseStore* rs) {
        routes.instruction_store_ = is;
        routes.response_store_ = rs;
    }
    void set_visible_set_fn(DashboardRoutes::VisibleSetFn fn) {
        routes.visible_set_fn_ = std::move(fn);
    }
    std::string render(const std::string& command_id, const std::string& plugin,
                       const std::string& definition_id = {}) {
        return routes.render_results(command_id, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", definition_id);
    }
    std::string render_filter_bar(const std::string& command_id, const std::string& plugin,
                                   const std::string& username = {}) {
        return routes.render_filter_bar(command_id, plugin, /*definition_id=*/{},
                                        /*template_id=*/{}, username);
    }
    // #1712 / #3290 Phase 2 — the fleet-read gate's composed
    // meet(management-group, service-scope) VisibleSet.
    std::string render_scoped(const std::string& command_id, const std::string& plugin,
                              const yuzu::server::authz::VisibleSet& scope) {
        return routes.render_results(command_id, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", /*definition_id=*/"",
                                     /*template_id=*/"", /*visible_columns=*/{}, scope);
    }
};

namespace {

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

// registry.yaml's list_profiles result_schema, byte-shaped as
// embed_content.py's `json.dumps(spec["result"])` actually emits it: an
// object with a top-level "columns" key, not the bare array
// legacy_shim.cpp's auto-generated definitions use.
constexpr const char* kListProfilesSchema = R"({"columns":[
    {"name":"sid","type":"string"},
    {"name":"profile_name","type":"string"},
    {"name":"profile_path","type":"string"},
    {"name":"hive_state","type":"string"}
]})";

InstructionDefinition make_list_profiles_definition() {
    InstructionDefinition def;
    def.name = "List User Profiles";
    def.version = "1.0.0";
    def.plugin = "registry";
    def.action = "list_profiles";
    def.type = "question";
    def.description = "Enumerate local Windows user profiles.";
    def.enabled = true;
    def.result_schema = kListProfilesSchema;
    return def;
}

constexpr const char* kAliceSid = "S-1-5-21-1-2-3-1001";

StoredResponse mk_list_profiles_response(const std::string& command_id) {
    StoredResponse r;
    r.instruction_id = command_id; // render_results queries the store by this
    r.agent_id = "agent-1";
    r.received_at_ms = 1000;
    r.status = 0;
    // render_profile_row's real wire shape (user_profile_model.hpp): raw
    // pipe-joined fields, no leading discriminator tag.
    r.output = std::string{kAliceSid} + "|alice|C:\\Users\\alice|loaded";
    return r;
}

std::size_t count_occurrences(const std::string& hay, std::string_view needle) {
    std::size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

// Facet-scope fixture: two agents with DISTINCT values in the SAME column,
// so a fleet-wide (unscoped) read is detectable against a confined one.
// "registry" has no columns_for_plugin entry (falls back to kDefaultColumns
// {"Agent","Output"}), and split_fields' default branch for a
// no-pipe-delimiter output line yields a single field -- col_idx 0, which is
// exactly what render_filter_bar's per-column loop resolves for the sole
// non-Agent column ("Output").
void store_two_agent_facet_responses(ResponseStore& rs, const std::string& command_id) {
    StoredResponse r1;
    r1.instruction_id = command_id;
    r1.agent_id = "agent-1";
    r1.received_at_ms = 1000;
    r1.status = 0;
    r1.plugin = "registry";
    r1.output = "loaded";
    rs.store(r1);

    StoredResponse r2;
    r2.instruction_id = command_id;
    r2.agent_id = "agent-2";
    r2.received_at_ms = 1000;
    r2.status = 0;
    r2.plugin = "registry";
    r2.output = "unloaded";
    rs.store(r2);
}

} // namespace

TEST_CASE("render_results: a schema-only definition (no visualization) resolves "
          "real columns instead of the plugin-only fallback (PR1.7 remediation)",
          "[pg][server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    auto created = is.create_definition(make_list_profiles_definition());
    REQUIRE(created.has_value());
    const std::string definition_id = *created;

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-list-profiles-1";
    rs.store(mk_list_profiles_response(command_id));

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    const std::string html = acc.render(command_id, "registry", definition_id);

    // Header: the real schema-derived column names, not "Output".
    CHECK(contains(html, "sid"));
    CHECK(contains(html, "profile_name"));
    CHECK(contains(html, "profile_path"));
    CHECK(contains(html, "hive_state"));
    CHECK_FALSE(contains(html, ">Output<"));

    // Data: every real field value renders in its OWN correctly-formed
    // <td>, not shifted into the wrong column. A substring-containment
    // check alone (contains(html, "alice")) would pass even if the row
    // were column-shifted -- this pins the exact cell markup instead
    // (Gate 4 happy-path finding: a since-removed leading tag on
    // render_profile_row's wire format shifted every field one column
    // right, and a weaker version of this test did not catch it).
    CHECK(contains(html, "<td title=\"" + std::string{kAliceSid} + "\">" +
                             kAliceSid + "</td>"));
    CHECK(contains(html, "<td title=\"alice\">alice</td>"));
    CHECK(contains(html, "<td title=\"loaded\">loaded</td>"));
    // "profile" must never appear as a rendered cell value now that the
    // tag is gone.
    CHECK_FALSE(contains(html, "<td title=\"profile\">profile</td>"));

    // Column count: Agent + 4 real fields == 5 <td> in the primary row, plus
    // 1 more for the detail-drawer row's own single colspan <td> wrapper
    // (its contents use <div>, but the wrapper itself is a <td>).
    CHECK(count_occurrences(html, "<td ") == 6);
}

TEST_CASE("render_results: no definition_id falls back to columns_for_plugin "
          "unchanged (regression pin for every other plugin/action)",
          "[pg][server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-no-def-1";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-1";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "some plain output line";
    rs.store(r);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    // No definition_id -- resolve_render_columns must fall back to
    // columns_for_plugin("registry"), which has no entry for "registry" and
    // resolves kDefaultColumns {"Agent","Output"}.
    const std::string html = acc.render(command_id, "registry");

    CHECK(contains(html, ">Output<"));
    CHECK_FALSE(contains(html, "profile_name"));
}

// #1712 / #3290 Phase 2: the fleet-read gate's scope filter is applied
// BEFORE total_agent_count is computed — a confined caller must see neither
// the out-of-scope agent's row NOR a fleet-wide count that reveals it exists.
TEST_CASE("render_results: scope filter drops out-of-scope agents from both "
          "the rows and the agent count",
          "[pg][server][dashboard][render_results]") {
    // Rebase hazard, found via /governance re-review (quality-engineer):
    // this test was written when InstructionStore(":memory:") was still a
    // valid SQLite-backed constructor; ADR-0058 (migrated to PostgreSQL)
    // removed it upstream while this branch was rebasing, and since this
    // test is a pure ADDITION (not a modification of pre-existing lines),
    // git found no textual conflict to flag the break. Same
    // dashboard_cols_instr_tpl pattern the sibling tests in this file
    // already use.
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-scope-filter-1";
    StoredResponse in_resp;
    in_resp.instruction_id = command_id;
    in_resp.agent_id = "agent-in";
    in_resp.received_at_ms = 1000;
    in_resp.status = 0;
    in_resp.output = "in-scope output line";
    rs.store(in_resp);
    StoredResponse out_resp;
    out_resp.instruction_id = command_id;
    out_resp.agent_id = "agent-out";
    out_resp.received_at_ms = 1000;
    out_resp.status = 0;
    out_resp.output = "out-of-scope output line";
    rs.store(out_resp);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);

    // Unfiltered (nullopt = TOP) — both agents visible, sanity baseline.
    const std::string unfiltered = acc.render_scoped(command_id, "registry", std::nullopt);
    CHECK(contains(unfiltered, "agent-in"));
    CHECK(contains(unfiltered, "agent-out"));
    CHECK(contains(unfiltered, "2 agents"));

    // Scoped to agent-in only.
    const std::string scoped = acc.render_scoped(
        command_id, "registry",
        yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}});
    CHECK(contains(scoped, "agent-in"));
    CHECK_FALSE(contains(scoped, "agent-out"));
    CHECK_FALSE(contains(scoped, "out-of-scope output line"));
    // The count must be recomputed from the filtered set, not the pre-filter
    // fleet-wide total — else a confined caller learns an out-of-scope agent
    // exists via the "N agents" summary even with its row hidden.
    CHECK(contains(scoped, "1 agent"));
    CHECK_FALSE(contains(scoped, "2 agents"));
}

// #2691 (Doomgoose finding #7): a degraded response-store read must render
// distinguishably from a genuine zero-match answer — "No results match your
// filters" is a false claim when the store just couldn't be read.
TEST_CASE("render_results: a degraded store read renders the degrade banner "
          "not \"no results match your filters\"",
          "[server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &bad_rs);
    const std::string html = acc.render("cmd-degraded", "registry");

    CHECK(contains(html, "result-degrade-banner"));
    CHECK(contains(html, "Results unavailable"));
    CHECK_FALSE(contains(html, "No results match your filters"));
}

// #2691 (Gate 4 consistency-auditor): the per-column filter dropdown must not
// silently render "All" with zero options on a degraded facet_values() read —
// indistinguishable from "this column genuinely has no other values", right
// next to a results table that correctly banners the same degrade.
TEST_CASE("render_filter_bar: a degraded facet read disables the dropdown "
          "instead of rendering an empty All",
          "[server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &bad_rs);
    const std::string html = acc.render_filter_bar("cmd-degraded", "registry");

    CHECK(contains(html, "disabled"));
    CHECK(contains(html, "(unavailable)"));
    CHECK(contains(html, "response store degraded"));
}

// -- Filter-bar facet scoping (dashboard facet-scope confinement) -----------
//
// #2691's degrade-vs-empty distinguishability contract gets a THIRD state
// here: deny-all (an operator whose Response:Read-visible agent set is
// engaged-but-empty) must be its own genuinely-empty UI, never conflated
// with the pre-existing degraded-store disabled state. Four seam-level cases
// cover the renderer directly; a fifth dispatches through TestRouteSink to
// pin that the route handler actually resolves the session and threads its
// username into visible_set_fn -- a seam-only suite cannot detect a handler
// that stopped doing either.

TEST_CASE("render_filter_bar: visible_set_fn_ confines facet options to the "
          "scoped agent's values only (CONFINED)",
          "[pg][server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-filter-confined";
    store_two_agent_facet_responses(rs, command_id);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.set_visible_set_fn([](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-1"};
    });
    const std::string html = acc.render_filter_bar(command_id, "registry", "op-confined");

    CHECK(contains(html, "value=\"loaded\""));
    CHECK_FALSE(contains(html, "value=\"unloaded\""));
    CHECK_FALSE(contains(html, "disabled"));
    CHECK_FALSE(contains(html, "unavailable"));
}

TEST_CASE("render_filter_bar: visible_set_fn_ returning an engaged-empty set "
          "denies all agents and renders a genuinely-empty dropdown, never "
          "the degraded-store rendering (DENY-ALL != DEGRADE)",
          "[pg][server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-filter-deny-all";
    store_two_agent_facet_responses(rs, command_id);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.set_visible_set_fn([](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{}; // engaged-empty: deny-all
    });
    const std::string html = acc.render_filter_bar(command_id, "registry", "op-deny-all");

    // Genuinely empty: only "All", neither agent's value, select enabled.
    CHECK(contains(html, "<option value=\"\">All</option>"));
    CHECK_FALSE(contains(html, "value=\"loaded\""));
    CHECK_FALSE(contains(html, "value=\"unloaded\""));
    // NOT the degraded-store rendering (:2099-2101) -- deny-all and degrade
    // are different UI states and must never be conflated.
    CHECK_FALSE(contains(html, "disabled"));
    CHECK_FALSE(contains(html, "(unavailable)"));
    CHECK_FALSE(contains(html, "unavailable — response store degraded"));
}

TEST_CASE("render_filter_bar: a degraded store still renders the disabled "
          "unavailable state even under a wired non-empty visible_set_fn_ "
          "(regression pin: scoping must not swallow the #2691 degrade "
          "rendering)",
          "[server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &bad_rs);
    acc.set_visible_set_fn([](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-1"}; // non-empty: not the deny-all short-circuit
    });
    const std::string html = acc.render_filter_bar("cmd-degraded-scoped", "registry",
                                                    "op-degraded");

    CHECK(contains(html, "disabled"));
    CHECK(contains(html, "(unavailable)"));
    CHECK(contains(html, "response store degraded"));
}

TEST_CASE("render_filter_bar: visible_set_fn_ left unwired renders every "
          "agent's facet values (UNWIRED LEGACY-OPEN)",
          "[pg][server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-filter-unwired";
    store_two_agent_facet_responses(rs, command_id);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    // visible_set_fn_ left default-constructed (unwired) -- legacy-open,
    // even though a username is supplied.
    const std::string html = acc.render_filter_bar(command_id, "registry", "op-unwired");

    CHECK(contains(html, "value=\"loaded\""));
    CHECK(contains(html, "value=\"unloaded\""));
}

// -- Through-the-sink dispatch: the handler must resolve + thread the
// -- session, not just the renderer honour a directly-set field ------------

TEST_CASE("render_filter_bar route: dispatched through TestRouteSink, the "
          "handler resolves the session and threads its username into "
          "visible_set_fn (SINK-DISPATCHED CONFINEMENT)",
          "[pg][server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-filter-sink-confined";
    store_two_agent_facet_responses(rs, command_id);

    yuzu::MetricsRegistry metrics;

    // Confined to "agent-1" ONLY when the resolved session's username is
    // exactly "testuser"; an empty or wrong username (a handler that stopped
    // calling auth_fn_, or stopped threading session->username through)
    // hits this engaged-EMPTY branch instead, and agent-1's option vanishes.
    DashboardRoutes::VisibleSetFn visible_set_fn =
        [](const std::string& username) -> std::optional<std::set<std::string>> {
        if (username == "testuser") return std::set<std::string>{"agent-1"};
        return std::set<std::string>{};
    };
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "testuser";
        s.role = auth::Role::admin;
        return s;
    };
    DashboardRoutes::PermFn perm_fn =
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn =
        [](const httplib::Request&, const std::string&, const std::string&,
          const std::string&, const std::string&, const std::string&) {};

    // MEMBER ORDER IS LOAD-BEARING (mirrors FragmentHarness,
    // test_dashboard_tar_fragments.cpp:106-180): `sink` declared LAST so it
    // is destroyed FIRST, while `routes` -- whose `this` its handlers
    // captured -- is still alive.
    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;

    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn,
                             &rs, /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
                             /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
                             /*caller_fn=*/DashboardRoutes::CallerFn{},
                             /*resolve_fn=*/DashboardRoutes::ResolveFn{},
                             &metrics, /*instruction_store=*/nullptr,
                             visible_set_fn);

    auto res = h.sink.Get("/fragments/results/filter-bar?command_id=" + command_id +
                          "&plugin=registry");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "value=\"loaded\""));
    CHECK_FALSE(contains(res->body, "value=\"unloaded\""));
    // BR-002: the body is now principal-specific -- a shared cache must
    // never be allowed to key/replay it across operators.
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Vary") == "Cookie");
}

// -- Branch-review finding BR-004: create-group-form had no route-dispatch
// -- test, so a later refactor that drops the username resolution or reverts
// -- to the legacy 2-arg facet_agent_count call would pass every existing
// -- test while the displayed count silently became fleet-wide again. -------

TEST_CASE("create-group-form route: dispatched through TestRouteSink, the "
          "matching-agent count is confined to the resolved session's "
          "visible scope",
          "[pg][server][dashboard][create_group_form]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-create-group-sink";

    // Both agents share the SAME Output value so one filter (f_output=match)
    // matches both -- unscoped count is 2, confined-to-agent-1 count is 1.
    StoredResponse r1;
    r1.instruction_id = command_id;
    r1.agent_id = "agent-1";
    r1.received_at_ms = 1000;
    r1.status = 0;
    r1.plugin = "registry";
    r1.output = "match";
    rs.store(r1);
    StoredResponse r2;
    r2.instruction_id = command_id;
    r2.agent_id = "agent-2";
    r2.received_at_ms = 1000;
    r2.status = 0;
    r2.plugin = "registry";
    r2.output = "match";
    rs.store(r2);

    yuzu::MetricsRegistry metrics;

    DashboardRoutes::VisibleSetFn visible_set_fn =
        [](const std::string& username) -> std::optional<std::set<std::string>> {
        if (username == "testuser") return std::set<std::string>{"agent-1"};
        return std::set<std::string>{};
    };
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "testuser";
        s.role = auth::Role::admin;
        return s;
    };
    DashboardRoutes::PermFn perm_fn =
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn =
        [](const httplib::Request&, const std::string&, const std::string&,
          const std::string&, const std::string&, const std::string&) {};

    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;

    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn,
                             &rs, /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
                             /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
                             /*caller_fn=*/DashboardRoutes::CallerFn{},
                             /*resolve_fn=*/DashboardRoutes::ResolveFn{},
                             &metrics, /*instruction_store=*/nullptr,
                             visible_set_fn);

    auto res = h.sink.Get("/fragments/create-group-form?command_id=" + command_id +
                          "&plugin=registry&f_output=match");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "1 agent will be added"));
    CHECK_FALSE(contains(res->body, "2 agents will be added"));
    // BR-002: same cross-operator shared-cache concern as filter-bar.
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Vary") == "Cookie");
}

// Branch-review finding (Functional CDX-FV-02, MEDIUM): only filter-bar had
// an elevated-session test; create-group-form's identical elevation bypass
// (dashboard_routes.cpp) was unexercised -- a deny-all visible_set_fn could
// have silently applied to an elevated admin too, without any test noticing.
TEST_CASE("create-group-form route: a JIT-elevated session sees the "
          "fleet-wide matching-agent count despite a deny-all visible scope",
          "[pg][server][dashboard][create_group_form][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-create-group-elevated";

    StoredResponse r1;
    r1.instruction_id = command_id;
    r1.agent_id = "agent-1";
    r1.received_at_ms = 1000;
    r1.status = 0;
    r1.plugin = "registry";
    r1.output = "match";
    rs.store(r1);
    StoredResponse r2;
    r2.instruction_id = command_id;
    r2.agent_id = "agent-2";
    r2.received_at_ms = 1000;
    r2.status = 0;
    r2.plugin = "registry";
    r2.output = "match";
    rs.store(r2);

    yuzu::MetricsRegistry metrics;

    // Deny-all for every username -- an elevated caller must bypass this
    // entirely, exactly as render_filter_bar's elevation test does.
    DashboardRoutes::VisibleSetFn visible_set_fn =
        [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{};
    };
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "elevated-admin";
        s.role = auth::Role::user;
        {
            // Since HA WS-1/1a DB-clock authority (ADR-2002 §4), is_elevated
            // adjudicates against the local monotonic steady_elevated_until
            // derived by AuthManager::derive_session_deadlines -- hand-stamping
            // elevated_until/elevation_issued_at alone no longer elevates
            // (those wall fields are now only a suspend backstop).
            const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
            const std::int64_t life_ms = now_ms + 8LL * 3600 * 1000;
            REQUIRE(auth::AuthManager::derive_session_deadlines(
                s, now_ms, life_ms, now_ms, /*mfa_verified_ms=*/0,
                /*elevated_until_ms=*/now_ms + 5 * 60000, /*elevation_issued_ms=*/now_ms, now_ms));
        }
        return s;
    };
    DashboardRoutes::PermFn perm_fn =
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn =
        [](const httplib::Request&, const std::string&, const std::string&,
          const std::string&, const std::string&, const std::string&) {};

    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;

    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn,
                             &rs, /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
                             /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
                             /*caller_fn=*/DashboardRoutes::CallerFn{},
                             /*resolve_fn=*/DashboardRoutes::ResolveFn{},
                             &metrics, /*instruction_store=*/nullptr,
                             visible_set_fn);

    auto res = h.sink.Get("/fragments/create-group-form?command_id=" + command_id +
                          "&plugin=registry&f_output=match");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "2 agents will be added"));
}

// -- Branch-review finding BR-001: a JIT-elevated session must get the
// -- full-fleet view, not a username-derived RBAC re-check that cannot see
// -- the session's live (in-memory) elevation. -------------------------------

TEST_CASE("render_filter_bar route: a JIT-elevated session sees every agent's "
          "facet values even though it holds no visible-scope grant",
          "[pg][server][dashboard][render_filter_bar][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-filter-sink-elevated";
    store_two_agent_facet_responses(rs, command_id);

    yuzu::MetricsRegistry metrics;

    // Deny-all for every username -- an elevated caller must bypass this
    // entirely, not merely resolve to an empty visible set through it.
    DashboardRoutes::VisibleSetFn visible_set_fn =
        [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{};
    };
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "elevated-admin";
        s.role = auth::Role::user; // base role holds nothing; elevation carries it
        {
            // Since HA WS-1/1a DB-clock authority (ADR-2002 §4), is_elevated
            // adjudicates against the local monotonic steady_elevated_until
            // derived by AuthManager::derive_session_deadlines -- hand-stamping
            // elevated_until/elevation_issued_at alone no longer elevates
            // (those wall fields are now only a suspend backstop).
            const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
            const std::int64_t life_ms = now_ms + 8LL * 3600 * 1000;
            REQUIRE(auth::AuthManager::derive_session_deadlines(
                s, now_ms, life_ms, now_ms, /*mfa_verified_ms=*/0,
                /*elevated_until_ms=*/now_ms + 5 * 60000, /*elevation_issued_ms=*/now_ms, now_ms));
        }
        return s;
    };
    DashboardRoutes::PermFn perm_fn =
        [](const httplib::Request&, httplib::Response&, const std::string&,
          const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn =
        [](const httplib::Request&, const std::string&, const std::string&,
          const std::string&, const std::string&, const std::string&) {};

    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;

    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn,
                             &rs, /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
                             /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
                             /*caller_fn=*/DashboardRoutes::CallerFn{},
                             /*resolve_fn=*/DashboardRoutes::ResolveFn{},
                             &metrics, /*instruction_store=*/nullptr,
                             visible_set_fn);

    auto res = h.sink.Get("/fragments/results/filter-bar?command_id=" + command_id +
                          "&plugin=registry");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "value=\"loaded\""));
    CHECK(contains(res->body, "value=\"unloaded\""));
}

} // namespace yuzu::server
