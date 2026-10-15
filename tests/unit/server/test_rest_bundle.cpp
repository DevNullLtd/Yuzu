/**
 * test_rest_bundle.cpp — HTTP-level coverage for the live-query bundle REST
 * routes (ADR-0011, slice 2b):
 *
 *   POST /api/v1/bundles                 -> dispatch (async), 202 + execution_id
 *   GET  /api/v1/bundles/{correlation}   -> collate, server-grouped result
 *
 * Driven via the TestRouteSink in-process pattern (#438) with a REAL
 * ResponseStore and a FAKE command-dispatch closure that records its args and
 * returns deterministic command_ids. Asserts the route contract: 202 dispatch
 * shape + per-command fan-out + per-step audit verbs, the collated GET result,
 * the ownership (IDOR) 404, the validation 400s, and the 503 when dispatch is
 * unwired. The orchestration logic itself is covered in
 * test_bundle_orchestrator.cpp; this file asserts the REST wiring.
 */

#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
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

struct DispatchCall {
    std::string plugin, action, scope_expr, execution_id;
    std::vector<std::string> agent_ids;
    yuzu::server::DispatchCaller caller;
};

struct AuditRow {
    std::string verb, result, type, id;
};

struct BundleHarness {
    ResponseStore store;
    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::string principal = "alice";
    bool is_admin = true;
    int dispatch_sent = 1;
    bool wire_dispatch = true;
    // K-R6-01: the REST bundle route now gates per-target on scoped_perm_fn.
    // Default permissive so existing tests dispatch; a confinement test flips
    // scope_allow=false to assert an out-of-scope target is denied.
    bool scope_allow = true;
    std::string last_scoped_agent;
    // Gate-3-architect-F1: the SECOND, independent VisibleSet confinement
    // check threaded into BundleOrchestrator::dispatch. std::nullopt (default)
    // = unfiltered, matching every pre-existing test's expectation; a
    // defense-in-depth test sets an explicit set that excludes the bundle's
    // target to prove the adapter refuses dispatch even when scoped_perm_fn
    // (the primary gate) would have allowed it.
    std::optional<std::unordered_set<std::string>> exec_visible_override;
    /// Leave `exec_visible_fn` EMPTY at registration, modelling a deployment
    /// that never wired the derivation. Distinct from `exec_visible_override`
    /// being nullopt: that is a callback ANSWERING "unfiltered", this is no
    /// callback at all, which fails CLOSED (present-empty). See the case pair
    /// at the bottom of this file.
    bool wire_exec_visible{true};

    explicit BundleHarness(pg::PgPool& pool, bool with_dispatch = true, bool with_scope = true,
                           bool with_exec_visible = true)
        : store(pool), wire_dispatch(with_dispatch), wire_exec_visible(with_exec_visible) {
        REQUIRE(store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = principal;
            s.role = is_admin ? auth::Role::admin : auth::Role::user;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& verb,
                               const std::string& result, const std::string& type,
                               const std::string& id, const std::string&) -> bool {
            audits.push_back({verb, result, type, id});
            return true;
        };

        RestApiV1::CommandDispatchFn dispatch_fn;
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids,
                                 const std::string& scope_expr,
                                 const std::unordered_map<std::string, std::string>&,
                                 const std::string& exec_id,
                                 const yuzu::server::DispatchCaller& caller)
                -> yuzu::server::ConfinedDispatchOutcome {
                calls.push_back({plugin, action, scope_expr, exec_id, agent_ids, caller});
                return {.sent = dispatch_sent, .command_id = "cmd-" + plugin + "-" + action};
            };
        }

        RestApiV1::ScopedPermFn scoped_perm_fn;  // left EMPTY when with_scope=false
        if (with_scope) {
            scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string&, const std::string&,
                                    const std::string& agent_id) -> bool {
                last_scoped_agent = agent_id;
                if (scope_allow)
                    return true;
                res.status = 403;
                return false;
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, store.is_open() ? &store : nullptr,
                            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            dispatch_fn, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/scoped_perm_fn,
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            wire_exec_visible
                                ? RestApiV1::ExecVisibleFn{[this](const auth::Session&)
                                                               -> yuzu::server::authz::VisibleSet {
                                      return exec_visible_override;
                                  }}
                                : RestApiV1::ExecVisibleFn{});
    }

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    nlohmann::json get(const std::string& path, int& status) {
        auto res = sink.dispatch("GET", path, "");
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }

    void put_response(const std::string& correlation, const std::string& command_id, int st,
                      const std::string& output) {
        StoredResponse r;
        r.execution_id = correlation;
        r.instruction_id = command_id;
        r.agent_id = "agent-1";
        r.status = st;
        r.output = output;
        r.timestamp = 100;
        store.store(r);
    }
};

bool has_audit(const std::vector<AuditRow>& a, const std::string& verb, const std::string& type) {
    for (const auto& r : a)
        if (r.verb == verb && r.type == type)
            return true;
    return false;
}

} // namespace

TEST_CASE("POST /api/v1/bundles dispatches each step and returns 202 + execution_id, "
          "carrying the caller's principal (PLAN-006 parity)",
          "[pg][bundle][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]})",
        status);
    REQUIRE(status == 202);
    auto data = j["data"];
    auto exec_id = data["bundle_id"].get<std::string>();
    CHECK(exec_id.rfind("bundle-", 0) == 0); // bundle- prefix → notify_exec_tracker skips it
    CHECK(data["expected"] == 2);

    REQUIRE(h.calls.size() == 2);
    CHECK(h.calls[0].plugin == "os_info");
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"agent-1"});
    CHECK(h.calls[0].execution_id == exec_id); // all steps share the correlation id
    CHECK(h.calls[1].execution_id == exec_id);

    // M11 (review finding, post-merge round): sibling dispatch surfaces
    // (workflow, dashboard, REST purge) each have an explicit PLAN-006 case
    // asserting the authenticated caller's PRINCIPAL reaches dispatch — the
    // bundle surface, one of the two paths the original CRITICAL fix
    // repaired, did not. The harness's dispatch_fn now captures `caller`
    // (was previously an unnamed, ignored parameter), so a future
    // regression that silently drops the principal on this surface fails
    // here.
    CHECK(h.calls[0].caller.principal == h.principal);
    CHECK_FALSE(h.calls[0].caller.system);
    CHECK(h.calls[1].caller.principal == h.principal);

    // Per-step audit verbs, device-scoped (governance F1), + the dispatch envelope.
    CHECK(has_audit(h.audits, "bundle.os_info.uptime", "Agent"));
    CHECK(has_audit(h.audits, "bundle.os_info.os_name", "Agent"));
    CHECK(has_audit(h.audits, "bundle.dispatch", "Execution"));
    CHECK(h.last_scoped_agent == "agent-1"); // per-target scoped gate ran on the parsed agent
}

// #1398 (quality-engineer, governance Gate 3): the MCP twin of this test
// (test_mcp_server.cpp, "MCP execute_bundle threads the caller's
// principal_is_admin into DispatchFn") was added when the adversarial review
// caught BundleOrchestrator::dispatch() silently dropping principal_is_admin/
// approval_provenance per step. The REST handler got the same fix
// (rest_api_v1.cpp:1761/1830) but had no test of its own — same defect
// class, same surface pair (REST/MCP) as #1398's own PLAN-006 precedent
// (principal-threading), just caught on only one twin. This is that missing
// falsifier: an admin caller's bundle step must carry
// caller.principal_is_admin == true all the way to DispatchFn, and a
// non-admin caller's must carry false — either polarity silently reverting
// would readmit the original bug (admin refused) or open the gate for
// everyone (non-admin admitted) on every AdminOrApproval-gated bundle step.
TEST_CASE("POST /api/v1/bundles threads the caller's principal_is_admin into DispatchFn (#1398)",
          "[pg][bundle][rest][1398]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    h.is_admin = true;
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].caller.principal_is_admin);
    (void)j;
}

TEST_CASE("POST /api/v1/bundles: a non-admin caller's principal_is_admin stays false (#1398)",
          "[pg][bundle][rest][1398]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    h.is_admin = false;
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK_FALSE(h.calls[0].caller.principal_is_admin);
    (void)j;
}

TEST_CASE("POST /api/v1/bundles denies an out-of-scope target agent, no dispatch (K-R6-01)",
          "[pg][bundle][rest][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    h.scope_allow = false; // the per-target scoped gate denies this agent
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-B","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 403);                        // denied by the scoped gate
    CHECK(h.last_scoped_agent == "agent-B");     // scoped on the PARSED target
    CHECK(h.calls.empty());                      // never dispatched
    (void)j;
}

TEST_CASE("POST /api/v1/bundles fails CLOSED (500) when the scope gate is unwired (K-R6-01/B4)",
          "[pg][bundle][rest][scope]") {
    // Register the route WITHOUT scoped_perm_fn (genuinely unwired) -> the route
    // must 500 and NEVER dispatch, never falling back to a global gate.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool, /*with_dispatch=*/true, /*with_scope=*/false);
    int status = 0;
    h.post("/api/v1/bundles",
           R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 500);       // "scope gate not configured", not a silent global fallback
    CHECK(h.calls.empty());     // never dispatched
}

TEST_CASE("POST /api/v1/bundles: the derived VisibleSet is a SECOND, independent confinement "
          "check even when scoped_perm_fn admits the target (Gate-3-architect-F1)",
          "[pg][bundle][rest][scope]") {
    // scoped_perm_fn (the PRIMARY gate) admits agent-B, but the derived
    // exec_visible excludes it -- proving the orchestrator adapter's in_scope
    // check is a real, independent enforcement point (defense-in-depth to
    // match the MCP execute_bundle twin), not decorative plumbing.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    h.scope_allow = true; // primary gate would admit
    h.exec_visible_override = std::unordered_set<std::string>{"agent-other"}; // agent-B NOT in it
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-B","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 202);       // the handler still accepts (async correlation id minted)
    CHECK(h.calls.empty());    // but the adapter refused to reach command_dispatch_fn
    (void)j;
}

TEST_CASE("POST /api/v1/bundles: an unfiltered (nullopt) VisibleSet still dispatches normally "
          "(Gate-3-architect-F1 non-regression)",
          "[pg][bundle][rest][scope]") {
    // A wired callback ANSWERING nullopt: a genuine global administrator, whose
    // full-fleet reach is their actual authority rather than a bypass.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool); // exec_visible_override defaults to nullopt (unfiltered)
    int status = 0;
    h.post("/api/v1/bundles",
           R"({"agent_id":"agent-B","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"agent-B"});
}

TEST_CASE("POST /api/v1/bundles: an UNWIRED ExecVisibleFn fails CLOSED, it does not fall back to "
          "unfiltered",
          "[pg][bundle][rest][scope][fail-closed][1788]") {
    // This case previously asserted the OPPOSITE, and asserting it is how the
    // defect held: the route's fallback was `VisibleSet{}`, which
    // default-constructs the optional to NULLOPT — i.e. UNFILTERED — so a
    // deployment that never wired the derivation silently lost the whole
    // defense-in-depth layer while a green test said the behaviour was intended.
    //
    // ADR-0033 §1 is explicit that the two states are not interchangeable:
    // nullopt means unfiltered, a present-empty set means deny-all, and a
    // MISSING derivation must never be read as "no filter applies". Every
    // sibling confined surface (dashboard execute, MCP execute_instruction /
    // execute_bundle) already substituted present-empty here; this route was
    // the one that inverted it.
    //
    // The per-target scoped_perm_fn gate is left ADMITTING on purpose, so the
    // only thing that can refuse this dispatch is the fallback under test.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool, /*with_dispatch=*/true, /*with_scope=*/true, /*with_exec_visible=*/false);
    h.scope_allow = true;
    int status = 0;
    h.post("/api/v1/bundles",
           R"({"agent_id":"agent-B","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 202);   // handler still mints the async correlation id
    CHECK(h.calls.empty()); // THE assertion: deny-all, so nothing was reached
}

TEST_CASE("GET /api/v1/bundles/{id} collates the responses", "[pg][bundle][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    auto disp = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]})",
        status);
    auto exec_id = disp["data"]["bundle_id"].get<std::string>();

    // Before responses: complete=false.
    auto a0 = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200);
    CHECK(a0["data"]["complete"] == false);

    h.put_response(exec_id, "cmd-os_info-os_name", 1, "os_name|Win");
    h.put_response(exec_id, "cmd-os_info-uptime", 1, "up 3d");

    auto a1 = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200);
    auto data = a1["data"];
    CHECK(data["complete"] == true);
    CHECK(data["received"] == 2);
    REQUIRE(data["steps"].size() == 2);
    CHECK(data["steps"][0]["action"] == "uptime"); // request order
    CHECK(data["steps"][0]["output"] == "up 3d");
}

TEST_CASE("GET collate is 404 for a non-owner (IDOR guard)", "[pg][bundle][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    auto disp = h.post("/api/v1/bundles",
                       R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}]})",
                       status);
    auto exec_id = disp["data"]["bundle_id"].get<std::string>();

    // Collate as a different, non-admin principal → 404 (same as not-found).
    h.principal = "mallory";
    h.is_admin = false;
    h.get("/api/v1/bundles/" + exec_id, status);
    CHECK(status == 404);

    // Owner still gets it.
    h.principal = "alice";
    h.is_admin = true;
    h.get("/api/v1/bundles/" + exec_id, status);
    CHECK(status == 200);
}

TEST_CASE("POST /api/v1/bundles validation 400s", "[pg][bundle][rest][unhappy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    h.post("/api/v1/bundles", "not json", status);
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"steps":[{"plugin":"p","action":"a"}]})", status); // no agent_id
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"agent_id":"a","steps":[]})", status); // empty steps
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"agent_id":"a","steps":[{"plugin":"p p","action":"a"}]})",
           status); // unsafe identifier
    CHECK(status == 400);
}

TEST_CASE("bundle routes 503 when dispatch is unwired", "[pg][bundle][rest][unhappy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool, /*with_dispatch=*/false);
    int status = 0;
    h.post("/api/v1/bundles",
           R"({"agent_id":"a","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 503);
}

TEST_CASE("REST collate surfaces dispatch_failed when a step reached no agent",
          "[pg][bundle][rest]") {
    // governance QE-S2: the dispatch-failed path through the HTTP wrapper.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    h.dispatch_sent = 0; // every step reaches 0 agents
    int status = 0;
    auto disp = h.post("/api/v1/bundles",
                       R"({"agent_id":"a","steps":[{"plugin":"os_info","action":"uptime"}]})",
                       status);
    REQUIRE(status == 202);
    auto exec_id = disp["data"]["bundle_id"].get<std::string>();

    auto a = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200);
    CHECK(a["data"]["complete"] == true); // dispatch-failed is terminal
    CHECK(a["data"]["received"] == 0);
    CHECK(a["data"]["succeeded"] == 0); // complete != success
    REQUIRE(a["data"]["steps"].size() == 1);
    CHECK(a["data"]["steps"][0]["state"] == "dispatch_failed");
}

TEST_CASE("REST collate tolerates non-UTF-8 plugin output (no 500)", "[pg][bundle][rest]") {
    // governance review #1593 blocker 1: a 0xff byte in plugin output must not
    // make aggregate_to_json's dump() throw → 500; collate must return 200.
    //
    // ADR-0039 addendum (Postgres cutover): TEXT columns require valid
    // server-encoding, unlike SQLite's permissive TEXT affinity — ResponseStore
    // sanitizes untrusted output/error_detail to U+FFFD (sanitize_utf8_strict,
    // utf8_sanitize.hpp) BEFORE the insert, so the row still LANDS (never
    // silently dropped by a fail-soft encoding rejection) — preserving, not
    // narrowing, the #1593 guarantee: the malformed-but-real result surfaces to
    // the operator, defanged.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    auto disp = h.post("/api/v1/bundles",
                       R"({"agent_id":"a","steps":[{"plugin":"files","action":"read"}]})", status);
    REQUIRE(status == 202);
    auto exec_id = disp["data"]["bundle_id"].get<std::string>();
    h.put_response(exec_id, "cmd-files-read", 1, std::string(1, '\xff') + "binary");
    auto a = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200); // NOT 500
    CHECK(a["data"]["complete"] == true);
    CHECK(a["data"]["steps"][0]["state"] == "responded"); // row present, not dropped
    // The 0xff byte is replaced with U+FFFD (EF BF BD); "binary" survives
    // untouched. The round-trip through nlohmann::json succeeding at all is
    // itself proof the stored bytes are valid UTF-8 (invalid input would have
    // thrown on dump/parse well before this assertion).
    const std::string output = a["data"]["steps"][0]["output"].get<std::string>();
    CHECK(output == "\xEF\xBF\xBD" "binary");
}

TEST_CASE("REST bundle routes are in the OpenAPI spec (A1 discoverability)", "[pg][bundle][rest]") {
    // governance review #1593 should-fix: REST surface must be machine-discoverable.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    auto spec = h.get("/api/v1/openapi.json", status);
    REQUIRE(status == 200);
    REQUIRE(spec.contains("paths"));
    CHECK(spec["paths"].contains("/bundles"));
    CHECK(spec["paths"]["/bundles"].contains("post"));
    CHECK(spec["paths"].contains("/bundles/{id}"));
    CHECK(spec["paths"]["/bundles/{id}"].contains("get"));
}

TEST_CASE("REST POST rejects empty agent_id", "[pg][bundle][rest][unhappy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    h.post("/api/v1/bundles", R"({"agent_id":"","steps":[{"plugin":"os_info","action":"uptime"}]})",
           status);
    CHECK(status == 400);
}

// ═══════════════════════════════════════════════════════════════════════════
// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. The REST handler's OWN guard checks the RAW body
// as a whole BEFORE any parse - this test's deep structure sits in a decoy
// top-level field, deliberately NOT inside "steps", so it isolates THIS
// guard from validate_bundle_steps's own independent depth check
// (bundle_service.cpp, covered directly in test_bundle_service.cpp): with
// only this route-level guard removed, "steps" itself stays shallow and
// valid, so the request would proceed all the way to a real dispatch rather
// than being caught a second time downstream. depth 40 is trivially safe to
// build/dump directly in this test process; the real attack depth this
// guard exists for is many orders of magnitude higher (~100,000 levels).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST /api/v1/bundles: a body nested past the depth limit is rejected "
          "before dispatch",
          "[pg][bundle][rest][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BundleHarness h(pool);
    int status = 0;
    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string body =
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}],"junk":)" +
        deep_array + "}";
    h.post("/api/v1/bundles", body, status);
    CHECK(status == 400);
    CHECK(h.calls.empty()); // never reached command_dispatch_fn
}
