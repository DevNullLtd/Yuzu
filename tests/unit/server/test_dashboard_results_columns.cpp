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
 * shape as test_dashboard_echo_retention.cpp's seam.
 */

#include "dashboard_routes.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "test_export_cap_guard.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_route_sink.hpp"
#include "url_attr_scan.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
    // #4990: these renderer-level cases are not about the Forensics tier (the route-level cases in
    // test_dashboard_results_fragment.cpp are), so the default reads every row; a tier case sets it.
    ResponseTierFilter tier = ResponseTierFilter::unrestricted_internal_consumer();

    void set_stores(InstructionStore* is, ResponseStore* rs) {
        routes.instruction_store_ = is;
        routes.response_store_ = rs;
    }
    void set_visible_set_fn(DashboardRoutes::VisibleSetFn fn) {
        routes.visible_set_fn_ = std::move(fn);
    }
    std::string render(const std::string& command_id, const std::string& plugin,
                       const std::string& definition_id = {}) {
        return routes.render_results(command_id, tier, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", definition_id);
    }
    // URL-encoding pins: lets a test supply the request-reflected values
    // (text query, definition id) that end up in the sort/page links.
    std::string render_reflected(const std::string& command_id, const std::string& plugin,
                                 const std::string& text_query,
                                 const std::string& definition_id) {
        return routes.render_results(command_id, tier, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, text_query, definition_id);
    }
    std::string render_filtered(const std::string& command_id, const std::string& plugin,
                                const std::vector<FacetFilter>& filters,
                                const std::string& definition_id = {}) {
        return routes.render_results(command_id, tier, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50, filters,
                                     /*text_query=*/"", definition_id);
    }
    std::string render_filter_bar(const std::string& command_id, const std::string& plugin,
                                   const std::string& username = {},
                                   const std::string& definition_id = {}) {
        return routes.render_filter_bar(command_id, tier, plugin, definition_id,
                                        /*template_id=*/{}, username);
    }
    // Full view control: sort/page/per_page/filters/Search/template, for the sync, count and
    // pagination-stamp pins (#5677 / #5700 / #6075).
    std::string render_view(const std::string& command_id, const std::string& plugin,
                            const std::string& sort_col, const std::string& sort_dir, int page,
                            int per_page, const std::vector<FacetFilter>& filters,
                            const std::string& text_query, const std::string& template_id = {}) {
        return routes.render_results(command_id, tier, plugin, sort_col, sort_dir, page, per_page,
                                     filters, text_query, /*definition_id=*/"", template_id);
    }
    std::optional<std::vector<std::string>>
    agents_matching(const std::string& command_id, const std::string& plugin,
                    const std::string& text_query, bool* truncated) {
        return routes.agents_matching_text(command_id, tier, plugin, {}, text_query, truncated);
    }
    DashboardRoutes::MatchingResponses load(const std::string& command_id,
                                            const std::vector<FacetFilter>& filters) {
        return routes.load_matching_responses(command_id, tier, filters);
    }
    // #1712 / #3290 Phase 2 — the fleet-read gate's composed
    // meet(management-group, service-scope) VisibleSet.
    std::string render_scoped(const std::string& command_id, const std::string& plugin,
                              const yuzu::server::authz::VisibleSet& scope) {
        return routes.render_results(command_id, tier, plugin, /*sort_col=*/"agent",
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
    // test_dashboard_echo_fragments.cpp:106-180): `sink` declared LAST so it
    // is destroyed FIRST, while `routes` -- whose `this` its handlers
    // captured -- is still alive.
    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case

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
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case

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

// #4990: an Unknown Forensics decision must not show a number computed over a partial row set.
TEST_CASE("create-group-form route: an Unknown Forensics decision shows the count as unavailable, "
          "not a number",
          "[pg][server][dashboard][create_group_form][security][forensics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-create-group-unknown";
    for (const char* agent : {"agent-1", "agent-2"}) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent;
        r.received_at_ms = 1000;
        r.status = 0;
        r.plugin = "registry";
        r.output = "match";
        rs.store(r);
    }
    yuzu::MetricsRegistry metrics;
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "testuser";
        s.role = auth::Role::admin;
        return s;
    };
    DashboardRoutes::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                         const std::string&, const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                           const std::string&, const std::string&,
                                           const std::string&, const std::string&) {};
    struct SinkHarness {
        yuzu::server::test::ForensicsCaller forensics;
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;
    yuzu::server::test::wire_forensics(h.routes, h.forensics);
    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn, &rs, /*mgmt_group_store=*/nullptr,
                             /*registry=*/nullptr, /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
                             /*caller_fn=*/DashboardRoutes::CallerFn{},
                             /*resolve_fn=*/DashboardRoutes::ResolveFn{}, &metrics,
                             /*instruction_store=*/nullptr);
    const std::string url =
        "/fragments/create-group-form?command_id=" + command_id + "&plugin=registry&f_output=match";

    h.forensics.unknown();
    auto unk = h.sink.Get(url);
    REQUIRE(unk != nullptr);
    CHECK(unk->status == 200);
    CHECK(contains(unk->body, "agent count unavailable"));
    CHECK_FALSE(contains(unk->body, "agents will be added"));

    h.forensics.admin(); // control: a resolved decision shows the real count
    auto ok = h.sink.Get(url);
    REQUIRE(ok != nullptr);
    CHECK(contains(ok->body, "2 agents will be added"));
}

// #5623: a filter value over the ingest bound is not indexed in newly stored responses, so the
// form must not present its count as the answer. Static sentence, never the value.
TEST_CASE("create-group-form route: a filter value over kMaxFacetValueBytes replaces the "
          "count with a static sentence",
          "[pg][server][dashboard][create_group_form][facets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-create-group-too-long";

    StoredResponse r1;
    r1.instruction_id = command_id;
    r1.agent_id = "agent-1";
    r1.received_at_ms = 1000;
    r1.status = 0;
    r1.plugin = "registry";
    r1.output = "match";
    rs.store(r1);

    yuzu::MetricsRegistry metrics;
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "testuser";
        s.role = auth::Role::admin;
        return s;
    };
    DashboardRoutes::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                         const std::string&, const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                           const std::string&, const std::string&,
                                           const std::string&, const std::string&) {};
    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case
    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn, &rs, /*mgmt_group_store=*/nullptr,
                             /*registry=*/nullptr, /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             DashboardRoutes::DispatchFn{}, DashboardRoutes::CallerFn{},
                             DashboardRoutes::ResolveFn{}, &metrics, /*instruction_store=*/nullptr,
                             /*visible_set_fn=*/{});

    const std::string base = "/fragments/create-group-form?command_id=" + command_id +
                             "&plugin=registry&f_output=";
    const std::string sentence =
        "A filter value is longer than " + std::to_string(kMaxFacetValueBytes) +
        " bytes. Newly stored responses do not index values that long, so the agent count may "
        "be wrong.";

    SECTION("one byte over the bound: the static sentence, no count, no value echo") {
        const std::string value(kMaxFacetValueBytes + 1, 'z');
        auto res = h.sink.Get(base + value);
        REQUIRE(res != nullptr);
        CHECK(res->status == 200);
        CHECK(contains(res->body, "<span class=\"form-hint\">" + sentence + "</span>"));
        CHECK_FALSE(contains(res->body, "will be added"));
        CHECK_FALSE(contains(res->body, "agent count unavailable"));
        // The submit wiring is as before: the hidden filter field still rides the POST.
        CHECK(contains(res->body, "hx-post=\"/api/dashboard/group-from-results\""));
        CHECK(contains(res->body, "name=\"f_output\""));
        CHECK(contains(res->body, "Create Static Group"));
    }

    SECTION("short raw, over the bound once stored (683 NUL bytes): the static sentence") {
        // NOTE: an undecoded "%00" is also 3 bytes, so this reads the same if the request decoder
        // stopped producing real NUL bytes; the real-byte helper case in
        // test_group_agent_count_preview.cpp pins the rule itself.
        std::string nuls;
        for (std::size_t i = 0; i < 683; ++i)
            nuls += "%00";
        auto res = h.sink.Get(base + nuls);
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "<span class=\"form-hint\">" + sentence + "</span>"));
        CHECK_FALSE(contains(res->body, "will be added"));
    }

    SECTION("exactly the bound: the ordinary count") {
        const std::string value(kMaxFacetValueBytes, 'z');
        auto res = h.sink.Get(base + value);
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "0 agents will be added"));
        CHECK_FALSE(contains(res->body, sentence));
    }

    SECTION("a short matching filter: the ordinary count") {
        auto res = h.sink.Get(base + "match");
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "1 agent will be added"));
        CHECK_FALSE(contains(res->body, sentence));
    }
}

// The degrade text wins over the over-bound sentence: with the store unreadable there is no count
// to qualify, so the form keeps its existing "unavailable" hint (an over-bound sentence would
// claim a read that did not happen), and it must never show a count.
TEST_CASE("create-group-form route: an over-bound filter on a degraded store shows the "
          "unavailable text, not the over-bound sentence or a count",
          "[server][dashboard][create_group_form][facets]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    yuzu::MetricsRegistry metrics;
    DashboardRoutes::AuthFn auth_fn =
        [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "testuser";
        s.role = auth::Role::admin;
        return s;
    };
    DashboardRoutes::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                         const std::string&, const std::string&) { return true; };
    DashboardRoutes::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                           const std::string&, const std::string&,
                                           const std::string&, const std::string&) {};
    struct SinkHarness {
        DashboardRoutes routes;
        yuzu::server::test::TestRouteSink sink;
    } h;
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case
    h.routes.register_routes(h.sink, auth_fn, perm_fn, audit_fn, &bad_rs,
                             /*mgmt_group_store=*/nullptr, /*registry=*/nullptr,
                             /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                             /*agents_json_fn=*/[] { return std::string{"[]"}; },
                             DashboardRoutes::DispatchFn{}, DashboardRoutes::CallerFn{},
                             DashboardRoutes::ResolveFn{}, &metrics, /*instruction_store=*/nullptr,
                             /*visible_set_fn=*/{});

    const std::string value(kMaxFacetValueBytes + 1, 'z');
    auto res = h.sink.Get("/fragments/create-group-form?command_id=cmd-degraded-long"
                          "&plugin=registry&f_output=" + value);
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "agent count unavailable (store degraded)"));
    CHECK_FALSE(contains(res->body, "A filter value is longer than"));
    CHECK_FALSE(contains(res->body, "will be added"));
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
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case

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
    yuzu::server::test::wire_forensics_permissive(h.routes); // #4990: not a tier case

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


TEST_CASE("render_results: request-reflected values are query-encoded in the sort link, once",
          "[pg][server][dashboard][render_results][url_path_segment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    const std::string q = "a&dir=desc#x\"><b>";
    const std::string plugin = "reg&per_page=1";
    const std::string html = acc.render_reflected("cmd 1", plugin, q, "d/../e");
    const auto urls = yuzu::test::url_attr_values(html);

    // #5677: the Search term is NOT baked into the link; the live filter bar supplies it through
    // hx-include, so the link names only the identity of the view.
    const std::string want =
        "/fragments/results?command_id=cmd%201&plugin=" + yuzu::server::url_query_value(plugin) +
        "&sort=agent&dir=desc&page=1&per_page=50&definition_id=d%2F..%2Fe";
    CHECK(yuzu::test::has_url(urls, want));
    // The raw reflected markup never reaches the page, and nothing was escaped twice.
    CHECK_FALSE(contains(html, "<b>"));
    CHECK_FALSE(contains(html, "%26amp"));
    CHECK_FALSE(contains(html, "&amp;amp;"));
    for (const auto& u : urls) {
        CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
        if (u.rfind("/fragments/results?", 0) == 0) {
            // one query string, exactly the parameters the renderer itself appended
            CHECK(std::count(u.begin(), u.end(), '#') == 0);
            CHECK(std::count(u.begin(), u.end(), '&') == 6);
            CHECK_FALSE(contains(u, "&q="));
        }
    }
}


TEST_CASE("render_results: the Create Group link carries each filter value as one encoded value",
          "[pg][server][dashboard][render_results][url_path_segment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string hostile = "a&b=c#d/../e";
    StoredResponse r;
    r.instruction_id = "cmd-fg-1";
    r.agent_id = "agent-1";
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    r.output = hostile;
    rs.store(r);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);
    const std::string html =
        acc.render_filtered("cmd-fg-1", "registry", {FacetFilter{.col_idx = 0, .value = hostile}});
    const auto urls = yuzu::test::url_attr_values(html);

    const std::string want = "/fragments/create-group-form?command_id=cmd-fg-1&plugin=registry"
                             "&f_output=" +
                             yuzu::server::url_query_value(hostile);
    CHECK(yuzu::test::has_url(urls, want));
    for (const auto& u : urls) {
        CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
        if (u.rfind("/fragments/create-group-form", 0) == 0)
            CHECK(std::count(u.begin(), u.end(), '&') == 2);
    }
}

TEST_CASE("render_results: the chart URL encodes the command id and is omitted for a dot-only one",
          "[pg][server][dashboard][render_results][url_path_segment]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    auto def = make_list_profiles_definition();
    def.visualization_spec = R"([{"type":"bar","processor":"count_by"}])";
    auto created = is.create_definition(def);
    REQUIRE(created.has_value());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);

    {
        const auto html = acc.render_filtered("cmd 1/x", "registry", {}, *created);
        const auto urls = yuzu::test::url_attr_values(html);
        CHECK(yuzu::test::has_url(urls, "/api/v1/executions/cmd%201%2Fx/visualization?definition_id=" +
                                            yuzu::server::url_query_value(*created) + "&index=0"));
    }
    for (const std::string id : {std::string(".."), std::string("."), std::string("%2e%2e")}) {
        const auto html = acc.render_filtered(id, "registry", {}, *created);
        CHECK(html.find("yuzu-chart-card") == std::string::npos);
    }
}

namespace {

// One stored frame for `agent` (ResponseStore::store is a plain INSERT per frame, so calling
// this twice for one agent leaves TWO rows owned by that agent).
void store_frame(ResponseStore& rs, const std::string& command_id, const std::string& agent,
                 const std::string& output) {
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = agent;
    r.received_at_ms = 1000;
    r.status = 0;
    r.plugin = "registry";
    r.output = output;
    rs.store(r);
}

} // namespace

// #5677 items 1+2: one newest-wins scope for every results control, and the links name only the
// identity of the view -- the live filters come from the filter bar, never from a baked URL.
TEST_CASE("render_results: sort and pager controls share the filter-bar sync scope and bake no "
          "filter state into their links",
          "[pg][server][dashboard][render_results][sync]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-sync-1";
    store_frame(rs, cmd, "agent-1", "same");
    store_frame(rs, cmd, "agent-2", "same");
    store_frame(rs, cmd, "agent-3", "same");
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    // Page 2 of 3 at one line per page: Prev and Next both render. A column filter, a Search term
    // and a template are all in play, and none may reach a sort/pager URL.
    const std::string html =
        acc.render_view(cmd, "registry", "agent", "asc", /*page=*/2, /*per_page=*/1,
                        {FacetFilter{.col_idx = 0, .value = "same"}}, "sam", "tpl1");

    // Agent + Output headers, Prev, Next; the Create Group button (a filter is applied) joins the
    // same scope but is not a sort/pager link.
    constexpr std::size_t kControls = 4;
    CHECK(count_occurrences(html, "hx-sync=\"#filter-bar:replace\"") == kControls + 1);
    CHECK(count_occurrences(html, "hx-include=\"#filter-bar\"") == kControls);
    CHECK_FALSE(contains(html, "this:abort"));
    CHECK(contains(html, ">Prev</button>"));
    CHECK(contains(html, ">Next</button>"));

    std::size_t results_urls = 0;
    for (const auto& u : yuzu::test::url_attr_values(html)) {
        if (u.rfind("/fragments/results?", 0) != 0)
            continue;
        ++results_urls;
        CHECK_FALSE(contains(u, "f_"));
        CHECK_FALSE(contains(u, "q="));
        CHECK_FALSE(contains(u, "template_id"));
    }
    CHECK(results_urls == kControls);
}

// #5700: the Search term is part of the group definition and of the agent count.
TEST_CASE("render_results: a Search term alone offers Create Group over exactly the agents it "
          "matches",
          "[pg][server][dashboard][render_results][group]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-q-1";
    store_frame(rs, cmd, "agent-1", "alpha");
    store_frame(rs, cmd, "agent-2", "beta");
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    SECTION("a matching Search term: one result, one agent, a button carrying q and the sync scope") {
        const auto html = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, {}, "alp");
        CHECK(contains(html, "1 result across 1 agent"));
        CHECK(contains(html, "Create Group from 1 Agent</button>"));
        const auto urls = yuzu::test::url_attr_values(html);
        CHECK(yuzu::test::has_url(
            urls, "/fragments/create-group-form?command_id=" + cmd + "&plugin=registry&q=alp"));
        for (const auto& u : urls) {
            if (u.rfind("/fragments/create-group-form", 0) == 0)
                CHECK_FALSE(contains(u, "f_"));
        }
        CHECK(contains(html, "class=\"btn-create-group\""));
        // The button is a results-page control: it joins the newest-wins scope.
        const auto btn = html.find("class=\"btn-create-group\"");
        REQUIRE(btn != std::string::npos);
        CHECK(html.find("hx-sync=\"#filter-bar:replace\"", btn) != std::string::npos);
    }
    SECTION("a Search term with no hit offers no button") {
        const auto html = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, {}, "zzz");
        CHECK_FALSE(contains(html, "btn-create-group"));
    }
    SECTION("no filter and no Search term offers no button") {
        const auto html = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, {}, "");
        CHECK(contains(html, "2 results across 2 agents"));
        CHECK_FALSE(contains(html, "btn-create-group"));
    }
}

// A stored row is one frame, so one agent can own several. "across N agents" counts agents.
TEST_CASE("render_results: the agent count is distinct agents, not stored rows",
          "[pg][server][dashboard][render_results][group]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-distinct-1";
    store_frame(rs, cmd, "agent-1", "one");
    store_frame(rs, cmd, "agent-1", "two");
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    const auto unfiltered = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, {}, "");
    CHECK(contains(unfiltered, "2 results across 1 agent"));
    const auto searched = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, {}, "o");
    CHECK(contains(searched, "2 results across 1 agent"));
}

// #6075 / the client summary refresh reads these stamps.
TEST_CASE("render_results: #result-pagination carries the view, also when empty",
          "[pg][server][dashboard][render_results][sync]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    const auto html =
        acc.render_view("cmd-stamp-1", "registry", "output", "desc", 1, 25, {}, "");
    CHECK(contains(html, "<nav id=\"result-pagination\" hx-swap-oob=\"true\" "
                         "data-sort=\"output\" data-dir=\"desc\" "
                         "data-page=\"1\" data-per-page=\"25\">"));
}

// A filtered read longer than the row cap used to be silently cut at 10,000 rows.
TEST_CASE("load_matching_responses: the filtered read reports a cut at the row cap",
          "[pg][server][dashboard][render_results][truncation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-trunc-1";
    store_frame(rs, cmd, "agent-1", "same");
    store_frame(rs, cmd, "agent-2", "same");
    store_frame(rs, cmd, "agent-3", "same");
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);
    const std::vector<FacetFilter> filters{FacetFilter{.col_idx = 0, .value = "same"}};

    SECTION("cap below the match count: truncated, one row fewer than the matches") {
        yuzu::test::ResultsRowCapGuard cap{2};
        const auto loaded = acc.load(cmd, filters);
        CHECK_FALSE(loaded.store_degraded);
        CHECK(loaded.result_truncated);
        CHECK(loaded.responses.size() == 2);
        const auto html = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, filters, "");
        CHECK(contains(html, "data-result-truncated=\"true\""));
    }
    SECTION("cap equal to the match count: complete") {
        yuzu::test::ResultsRowCapGuard cap{3};
        const auto loaded = acc.load(cmd, filters);
        CHECK_FALSE(loaded.result_truncated);
        CHECK(loaded.responses.size() == 3);
        const auto html = acc.render_view(cmd, "registry", "agent", "asc", 1, 50, filters, "");
        CHECK_FALSE(contains(html, "data-result-truncated"));
    }
}

TEST_CASE("agents_matching_text: one entry per matching agent, however many rows match",
          "[pg][server][dashboard][render_results][truncation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-amt-1";
    store_frame(rs, cmd, "agent-1", "alpha");
    store_frame(rs, cmd, "agent-1", "alpine");
    store_frame(rs, cmd, "agent-2", "beta");
    store_frame(rs, cmd, "agent-3", "alpha");
    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(nullptr, &rs);

    bool truncated = true;
    const auto ids = acc.agents_matching(cmd, "registry", "alp", &truncated);
    REQUIRE(ids.has_value());
    CHECK_FALSE(truncated);
    CHECK(std::set<std::string>(ids->begin(), ids->end()) ==
          std::set<std::string>{"agent-1", "agent-3"});
    CHECK(ids->size() == 2); // agent-1 owns two matching rows but appears once
}

TEST_CASE("render_filter_bar: every control joins the newest-wins scope; the form drops a "
          "refresh issued mid-request; the View switch appears only with an equals default",
          "[pg][server][dashboard][render_results][sync]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string cmd = "cmd-bar-1";
    store_frame(rs, cmd, "agent-1", "alpha");
    store_frame(rs, cmd, "agent-2", "beta");

    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    auto make_def = [&](const std::string& name, const std::string& op) {
        auto def = make_list_profiles_definition();
        def.name = name;
        def.response_templates_spec =
            R"([{"id":"vw1","name":"v","default":false,"filters":[{"column":"Output","op":")" +
            op + R"(","value":"x"}]}])";
        auto id = is.create_definition(def);
        REQUIRE(id.has_value());
        return *id;
    };
    const auto equals_def = make_def("bar-equals", "equals");
    const auto contains_def = make_def("bar-contains", "contains");

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);

    SECTION("no definition: no View select, no switch; Output + Search controls use the scope") {
        const auto html = acc.render_filter_bar(cmd, "registry");
        CHECK(contains(html, "<form id=\"filter-bar\" class=\"filter-bar\" hx-sync=\"this:drop\">"));
        CHECK_FALSE(contains(html, "queue"));
        CHECK_FALSE(contains(html, "closest form:abort"));
        CHECK_FALSE(contains(html, "view_filters"));
        // Output dropdown + Search box.
        CHECK(count_occurrences(html, "hx-sync=\"#filter-bar:replace\"") == 2);
        CHECK(count_occurrences(html, "hx-get=\"/fragments/results\"") == 2);
    }
    SECTION("an equals default renders the per-request switch, itself in the scope") {
        const auto html = acc.render_filter_bar(cmd, "registry", "", equals_def);
        CHECK(contains(html, "name=\"view_filters\" value=\"off\""));
        CHECK(contains(html, "View without saved filters"));
        // View select + switch + Output dropdown + Search box.
        CHECK(count_occurrences(html, "hx-sync=\"#filter-bar:replace\"") == 4);
        CHECK(count_occurrences(html, "hx-get=\"/fragments/results\"") == 4);
        CHECK_FALSE(contains(html, "closest form:abort"));
    }
    SECTION("a non-equals default offers no switch (nothing it could switch off)") {
        const auto html = acc.render_filter_bar(cmd, "registry", "", contains_def);
        CHECK_FALSE(contains(html, "view_filters"));
    }
}

} // namespace yuzu::server
