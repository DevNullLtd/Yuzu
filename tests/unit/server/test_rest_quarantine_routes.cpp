/**
 * test_rest_quarantine_routes.cpp -- route-level regression tests for the REST
 * v1 quarantine surface (POST /api/v1/quarantine, DELETE
 * /api/v1/quarantine/{id}) after the CDX-P1-02 hardening. Mirrors
 * test_rest_tag_routes.cpp's harness shape: these dispatch synthesized
 * requests through the captured route closures against an in-process
 * TestRouteSink, proving the LAMBDA WIRING -- authenticate-first,
 * scoped-gate-as-sole-authorization, fail-closed-when-unwired -- not just the
 * shared require_scoped_permission logic the MCP quarantine_device twin
 * already covers (this route wiring previously had zero tests at all).
 */

#include "quarantine_store.hpp"
#include "agent_registry.hpp"
#include "response_store.hpp"
#include "authz_gates.hpp"
#include "command_capability.hpp"
#include "openapi_spec_access.hpp"
#include "rest_api_v1.hpp"

#include <yuzu/metrics.hpp>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <nlohmann/json.hpp>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

// QuarantineStore migrated to Postgres (ADR-0006/0047) — SAME key as
// test_quarantine_store.cpp's own template ("quarantinestore"); the registry
// builds it once and replay-verifies this file's setup lambda produces the
// identical structural fingerprint (test_helpers.hpp PgTestTemplate
// contract).
yuzu::test::PgTestTemplate quarantine_route_tpl{"quarantinestore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantinestore template: store failed to migrate");
}};

yuzu::test::PgTestTemplate responsestore_route_tpl{"responsestore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// The DELETE route reads the device's reply for a bounded number of polls: no sleeping between
// them, and a small budget, so a "no reply" case costs two reads and no wall time. Process-global
// test seams (detail::live_poll_interval_ms / release_confirm_max_polls), restored on exit.
struct ReleasePollSeams {
    int saved_interval{detail::live_poll_interval_ms().load()};
    int saved_polls{detail::release_confirm_max_polls().load()};
    std::function<void()> saved_pause_hook{detail::release_confirm_pause_hook()};
    explicit ReleasePollSeams(int polls) {
        detail::live_poll_interval_ms().store(0);
        detail::release_confirm_max_polls().store(polls);
        detail::release_confirm_pause_hook() = {}; // a case installs its own, restored on exit
    }
    ~ReleasePollSeams() {
        detail::live_poll_interval_ms().store(saved_interval);
        detail::release_confirm_max_polls().store(saved_polls);
        detail::release_confirm_pause_hook() = saved_pause_hook;
    }
};

struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

// A harness that registers ONLY the quarantine routes against a TestRouteSink,
// with a real QuarantineStore and injectable auth / scoped-permission
// behaviour.
struct QuarantineRouteHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    QuarantineStore quarantine_store;

    // auth: empty session_user => require_auth writes 401 and returns nullopt.
    std::string session_user{"alice"};
    // scope decision the stub returns; when `wire_scope` is false the route is
    // registered with an UNWIRED scoped fn (the fail-closed 500 case).
    bool scope_allow{true};
    bool scope_fn_called{false};
    std::string scoped_target;
    // Per-agent override for the GET list-scoping tests, where different
    // records in the same response must resolve to DIFFERENT scope
    // decisions -- the single `scope_allow` bool can't express that. Checked
    // before falling back to `scope_allow`.
    std::unordered_map<std::string, bool> scope_allow_for;
    // Per-agent DEGRADE simulation, keyed to the STATUS a real
    // require_scoped_permission genuinely returns on a degrade -- distinct
    // from a 403 denial. 503 on an RBAC/tag-store outage (engine-principal /
    // service-scoped-token branches, auth_routes.cpp). 401 (gov Gate 4
    // unhappy-path, UP-1) when its INTERNAL require_auth re-check hits an
    // engine-principal store outage mid-request -- EngineLookupStatus::
    // StoreUnreachable collapses to the same nullopt/401 as a genuinely
    // absent session (auth_routes.cpp's own comment: distinguishing the two
    // end-to-end is a "noted follow-on, not required by this slice"), even
    // though the SAME caller already authenticated successfully once via
    // auth_fn above. Checked before scope_allow_for/scope_allow.
    std::unordered_map<std::string, int> scope_degrade_for;
    std::vector<AuditCall> audit_calls;
    // Audit seam control: `audit_fail_result` makes a row whose RESULT equals it report a
    // persist failure (the row is then NOT recorded); "" = every row persists.
    std::string audit_fail_result;
    // The GET list's ADR-0017 gate (fleet_read_fn = require_fleet_read): ONE decision per
    // request. `gate_status` 0 = admit with `list_scope` (nullopt = TOP); else the status the
    // gate writes (401/403/503). `wire_fleet` false registers it unwired (the 500 case).
    int gate_status{0};
    authz::VisibleSet list_scope;
    int gate_calls{0};
    std::string gate_type_op;

    // #6065 PR-Q: the dispatch chokepoint pre-check (RestApiV1::AuthorizeDispatchFn).
    // The default stub ADMITS with a benign capability row so the pre-existing cases keep
    // their intent; a case injects a denial (or leaves `wire_authorize` false for the unwired
    // 500). `authorize_calls`/`authorize_plugin`/`authorize_action`/`authorize_caller` record
    // what the route handed the chokepoint. `order` interleaves the scoped gate and the
    // chokepoint so a case can prove which ran first.
    using AuthorizeResult = std::expected<CommandCapability, detail::DispatchDenial>;
    std::function<AuthorizeResult(const DispatchCaller&, std::string_view, std::string_view)>
        authorize_fn;
    int authorize_calls{0};
    std::string authorize_plugin;
    std::string authorize_action;
    DispatchCaller authorize_caller;
    std::vector<std::string> order;
    // The caller's exec_visible derivation. Default: a present-empty set (deny-all), the
    // production-safe shape; a case may replace it.
    std::function<authz::VisibleSet(const auth::Session&)> exec_visible_fn;
    // Auth seam: the Nth auth_fn call (1-based) and every later one ends in a 401 when
    // `auth_fail_from_call` > 0. 0 = never. The quarantine POST and DELETE each resolve the session twice.
    int auth_calls{0};
    int auth_fail_from_call{0};
    // The counter the denial path increments; a real registry so a case reads it back.
    yuzu::MetricsRegistry metrics;

    // The release the DELETE route sends (firewall.release) and what the device answers.
    // `release_reply` is stored under the command id the moment the dispatch is made ("" = the
    // device never answers); `dispatch_sent` is the agents-reached count; `wire_dispatch` false
    // registers no dispatch function at all.
    struct DispatchCall {
        std::string plugin;
        std::string action;
        std::vector<std::string> agent_ids;
        DispatchCaller caller;
    };
    std::vector<DispatchCall> dispatch_calls;
    int dispatch_sent{1};
    bool dispatch_throws{false};
    std::string release_reply;
    // Runs inside the dispatch, after the reply is stored: the deterministic way to land a
    // concurrent change (the reconciler ending the record, a store outage) between the route's
    // release request and its own follow-up write.
    std::function<void()> on_dispatch;
    ResponseStore* response_store{nullptr};
    ReleasePollSeams poll_seams{2};

    static AuthorizeResult admitted_capability() {
        return CommandCapability{.plugin = "firewall",
                                 .action = "quarantine",
                                 .dispatch_class = DispatchClass::Destructive,
                                 .mutability = Mutability::Irreversible,
                                 .securable = "Security",
                                 .operation = authz::Operation::Execute,
                                 .risk_tier = authz::RiskTier::Critical,
                                 .system_reserved = false,
                                 .execute_gate = ExecuteGate::AdminOrApproval};
    }

    explicit QuarantineRouteHarness(pg::PgPool& pool, bool wire_scope = true, bool wire_fleet = true,
                                    bool wire_authorize = true, ResponseStore* rstore = nullptr,
                                    bool wire_dispatch = true)
        : quarantine_store(pool), response_store(rstore) {
        REQUIRE(quarantine_store.is_open());
        api.set_forensics_plugin_set(&yuzu::server::test::forensics_plugin_set());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            ++auth_calls;
            if (session_user.empty() ||
                (auth_fail_from_call > 0 && auth_calls >= auth_fail_from_call)) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            return s;
        };
        // Global perm_fn is intentionally permissive: after the CDX-P1-02
        // change the quarantine routes do NOT call it -- if a regression
        // re-introduced a global pre-gate, these tests would still pass, but
        // the scope-deny case below would then fail (proving the scoped gate
        // is the one in force).
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            // The quarantine routes write through the session writer below; the one row
            // that may reach this re-resolving writer is the unwired-writer failure row, and
            // this harness always wires a writer. Any quarantine row here is the defect
            // (rest-audit-principal-reresolution) that every scenario in this file guards.
            if (action == "quarantine.enable" || action == "quarantine.disable")
                FAIL_CHECK("a quarantine row went through the re-resolving audit_fn: "
                           << action << "/" << result);
            if (!audit_fail_result.empty() && result == audit_fail_result)
                return false;
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        // The session writer server.cpp binds (#6065 PR-Q): same recording, same failure
        // injection, so every existing row assertion holds through it.
        api.set_audit_as_session_fn([this](const httplib::Request&, const auth::Session&,
                                           const std::string&, const std::string& action,
                                           const std::string& result,
                                           const std::string& target_type,
                                           const std::string& target_id,
                                           const std::string& detail) -> bool {
            if (!audit_fail_result.empty() && result == audit_fail_result)
                return false;
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        });

        RestApiV1::ScopedPermFn scoped_fn{};
        if (wire_scope) {
            scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                               const std::string&, const std::string&,
                               const std::string& agent_id) -> bool {
                scope_fn_called = true;
                scoped_target = agent_id;
                order.push_back("scope");
                if (auto it = scope_degrade_for.find(agent_id); it != scope_degrade_for.end()) {
                    res.status = it->second;
                    return false;
                }
                auto it = scope_allow_for.find(agent_id);
                bool allow = it != scope_allow_for.end() ? it->second : scope_allow;
                if (allow)
                    return true;
                res.status = 403;
                return false;
            };
        }

        RestApiV1::FleetReadFn fleet_fn{};
        if (wire_fleet) {
            fleet_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                              const std::string& op) -> authz::FleetReadGate {
                ++gate_calls;
                gate_type_op = t + ":" + op;
                if (gate_status != 0) {
                    res.status = gate_status;
                    return {};
                }
                return {true, list_scope};
            };
        }

        authorize_fn = [](const DispatchCaller&, std::string_view,
                          std::string_view) -> AuthorizeResult {
            return admitted_capability();
        };
        exec_visible_fn = [](const auth::Session&) { return authz::deny_all(); };
        RestApiV1::AuthorizeDispatchFn authorize_dispatch_fn{};
        if (wire_authorize) {
            authorize_dispatch_fn = [this](const DispatchCaller& caller, std::string_view plugin,
                                           std::string_view action) -> AuthorizeResult {
                ++authorize_calls;
                order.push_back("authorize");
                authorize_plugin = std::string(plugin);
                authorize_action = std::string(action);
                authorize_caller = caller;
                return authorize_fn(caller, plugin, action);
            };
        }
        RestApiV1::ExecVisibleFn exec_visible_wired =
            [this](const auth::Session& s) { return exec_visible_fn(s); };
        RestApiV1::CommandDispatchFn dispatch_fn{};
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids, const std::string&,
                                 const std::unordered_map<std::string, std::string>&,
                                 const std::string&,
                                 const DispatchCaller& caller) -> ConfinedDispatchOutcome {
                dispatch_calls.push_back({plugin, action, agent_ids, caller});
                if (dispatch_throws)
                    throw std::runtime_error("dispatch failed");
                const std::string command_id = "cmd-" + std::to_string(dispatch_calls.size());
                if (response_store && dispatch_sent > 0 && !release_reply.empty()) {
                    StoredResponse sr;
                    sr.instruction_id = command_id;
                    sr.agent_id = agent_ids.front();
                    sr.status = 1;
                    sr.output = release_reply;
                    sr.plugin = plugin;
                    response_store->store(sr);
                }
                if (on_dispatch)
                    on_dispatch();
                return ConfinedDispatchOutcome{.sent = dispatch_sent, .command_id = command_id};
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, &quarantine_store,
                            response_store, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr, dispatch_fn,
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, scoped_fn,
                            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, exec_visible_wired,
                            /*list_read_fn=*/{}, fleet_fn,
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{},
                            /*verify_api=*/nullptr, /*device_api=*/nullptr,
                            /*dex_api=*/nullptr, /*dex_perf_api=*/nullptr,
                            /*guardian_api=*/nullptr, /*tier_policy_fn=*/{},
                            authorize_dispatch_fn);
    }

    auto post(const std::string& body) {
        return sink.Post("/api/v1/quarantine", body, "application/json");
    }
    auto del(const std::string& agent, const std::string& query = "") {
        return sink.Delete("/api/v1/quarantine/" + agent + query);
    }
    auto get() {
        return sink.Get("/api/v1/quarantine");
    }

    bool is_quarantined(const std::string& agent_id) {
        // AUTHORITATIVE read (ADR-0047): never silently treat a degraded
        // read as "not found" — that would mask a real store/pool failure
        // as a passing assertion.
        auto list = quarantine_store.list_quarantined();
        REQUIRE(list.has_value());
        for (const auto& r : *list)
            if (r.agent_id == agent_id)
                return true;
        return false;
    }
};

const std::string kBody = R"({"agent_id":"agent-B","reason":"test"})";

} // namespace

TEST_CASE("REST POST /api/v1/quarantine requires authentication before any store/body work "
          "(CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.session_user = ""; // no session
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.scope_fn_called);
    CHECK_FALSE(h.is_quarantined("agent-B")); // no write
}

// ADR-0033 §9: no audit row, no mutation. Kills: the store write moving back before the
// attempt row, or the result of the attempt row being ignored.
TEST_CASE("REST POST/DELETE /api/v1/quarantine fail closed when the attempt audit row cannot be "
          "written (503, Sec-Audit-Failed, containment unchanged)",
          "[rest][quarantine][audit][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.audit_fail_result = "attempt";
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(h.is_quarantined("agent-B")); // no row, no mutation

    // DELETE: a device that IS quarantined stays quarantined.
    REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "r", ""));
    auto del = h.del("agent-B");
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(del->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.is_quarantined("agent-B")); // still contained
}

TEST_CASE("REST POST/DELETE /api/v1/quarantine write an attempt row first, then the outcome",
          "[rest][quarantine][audit][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);
    pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());
    QuarantineRouteHarness h(qpool, true, true, true, &rstore);
    h.release_reply = "status|inactive";
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "quarantine.enable");
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].result == "success");
    // A rejected change leaves attempt + failure, never a "success" that did not happen.
    h.audit_calls.clear();
    auto dup = h.post(kBody);
    REQUIRE(dup);
    CHECK(dup->status == 400);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].result == "failure");
    // Release: attempt then success (the device answered inactive).
    h.audit_calls.clear();
    auto del = h.del("agent-B");
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "quarantine.disable");
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].result == "success");
}

// A lost OUTCOME row after the change was made is signalled, not hidden.
TEST_CASE("REST POST /api/v1/quarantine flags a lost outcome row with Sec-Audit-Failed",
          "[rest][quarantine][audit][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);
    pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());
    QuarantineRouteHarness h(qpool, true, true, true, &rstore);
    h.release_reply = "status|inactive";
    h.audit_fail_result = "success";
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201); // the attempt row recorded who asked; the change applied
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.is_quarantined("agent-B"));

    // DELETE: the release applied, and its lost outcome row is flagged the same way.
    auto del = h.del("agent-B");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(del->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine is denied per-target by the scoped gate (403, no write) "
          "(CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.scope_allow = false;
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.scope_fn_called);
    CHECK(h.scoped_target == "agent-B"); // scoped on the PARSED target
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine passes an OMITTED agent_id through to the scope gate "
          "unmodified — no route-level default/early-return that could diverge from "
          "require_scoped_permission's own empty-agent_id 400 (#2298 PR 3 §3b)",
          "[rest][quarantine][authz][pg][service_scope]") {
    // security-guardian (Gate 4, this PR's own governance round) found that a
    // pre-fix `require_scoped_permission` empty-agent_id degenerate would
    // have unconditionally admitted a service-scoped token HERE — this
    // route's `agent_id = body.value("agent_id", "")` has no upstream empty
    // check of its own. The real 400 is proven at the function level in
    // test_auth_routes.cpp; this test proves the ROUTE's wiring doesn't
    // silently special-case an empty agent_id before reaching that gate
    // (the fake `scoped_perm_fn` here can't itself enforce the 400 — it
    // stands in for require_scoped_permission, which production wires in).
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.scope_allow = true; // the fake would admit — proves the route itself adds no guard
    auto res = h.post(R"({"reason":"test"})"); // no agent_id key at all
    REQUIRE(res);
    CHECK(h.scope_fn_called);
    CHECK(h.scoped_target.empty()); // reached the gate with the raw empty value, unmodified
}

TEST_CASE("REST POST /api/v1/quarantine admits an in-scope caller and quarantines the device "
          "(201) (CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.scope_allow = true;
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.scope_fn_called);
    CHECK(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine fails CLOSED (500) when the scope gate is unwired "
          "(CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool, /*wire_scope=*/false);
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 500); // never a silent global fallback
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine rejects a malformed JSON body (400, no dispatch) "
          "(gov-fix)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    // Not a JSON object at all -- must NOT reach scoped_perm_fn/.value() and
    // must NOT throw (this is the exact shape that, absent the is_discarded()/
    // is_object() guard, previously reached `body.value("agent_id","")` on a
    // discarded parse result and threw nlohmann::json::type_error uncaught).
    auto res = h.post("not json");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(h.scope_fn_called);
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine rejects an unsafe whitelist (400, no write) "
          "(#3425 gate3-rest-whitelist-validation-gap)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.scope_allow = true;
    SECTION("unsafe charset (a CIDR slash)") {
        auto res = h.post(R"({"agent_id":"agent-B","reason":"test","whitelist":"10.0.0.0/24"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("whitelist must be comma-separated IPv4 or IPv6 addresses, at most 32") !=
              std::string::npos);
        CHECK(h.scope_fn_called); // scope gate runs before the validator, same order as agent_id
        CHECK_FALSE(h.is_quarantined("agent-B")); // rejected, never written
    }
    SECTION("oversized (over kQuarantineWhitelistMaxLen)") {
        const std::string oversized(600, '1');
        const std::string body = R"({"agent_id":"agent-B","reason":"test","whitelist":")" +
                                 oversized + R"("})";
        auto res = h.post(body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("513 characters is a 400 that names the 512 limit; 512 passes the length check (#7639)") {
        auto res = h.post(std::string(R"({"agent_id":"agent-B","reason":"test","whitelist":")") +
                          std::string(513, '1') + R"("})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("whitelist exceeds 512 characters") != std::string::npos);
        CHECK_FALSE(h.is_quarantined("agent-B"));
        // exactly 512 characters of address list is not refused for its length: it fails (or passes)
        // on the grammar, with the other message
        std::string at_limit;
        while (at_limit.size() + 9 <= 512)
            at_limit += (at_limit.empty() ? "" : ",") + std::string("10.0.0.1");
        at_limit.resize(512, ' ');
        auto edge = h.post(std::string(R"({"agent_id":"agent-B","reason":"test","whitelist":")") +
                           at_limit + R"("})");
        REQUIRE(edge);
        CHECK(edge->body.find("whitelist exceeds") == std::string::npos);
    }
    SECTION("33 addresses name the count in the message") {
        std::string many;
        for (int i = 1; i <= 33; ++i)
            many += (i > 1 ? "," : "") + std::string("10.0.0.") + std::to_string(i);
        REQUIRE(many.size() <= 512);
        auto res = h.post(std::string(R"({"agent_id":"agent-B","reason":"test","whitelist":")") +
                          many + R"("})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("at most 32 and 512 characters in total") != std::string::npos);
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("a port, a leading-zero octet and 33 addresses are refused too") {
        for (const char* wl : {"10.0.0.5:443", "010.0.0.1", "::ffff:1.2.3.4"}) {
            auto res = h.post(std::string(R"({"agent_id":"agent-B","reason":"test","whitelist":")") +
                              wl + R"("})");
            REQUIRE(res);
            CAPTURE(wl);
            CHECK(res->status == 400);
        }
        std::string many;
        for (int i = 1; i <= 33; ++i)
            many += (i > 1 ? "," : "") + std::string("10.0.0.") + std::to_string(i);
        auto res = h.post(std::string(R"({"agent_id":"agent-B","reason":"test","whitelist":")") +
                          many + R"("})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_FALSE(h.is_quarantined("agent-B"));
        // a refused whitelist writes a failure row and no attempt row, and nothing is dispatched
        for (const auto& a : h.audit_calls)
            CHECK(a.result != "attempt");
        CHECK(h.dispatch_calls.empty());
    }
    SECTION("a valid whitelist still succeeds (201) and POST dispatches nothing") {
        auto res = h.post(
            R"({"agent_id":"agent-B","reason":"test","whitelist":"10.0.0.1,10.0.0.2"})");
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(h.is_quarantined("agent-B"));
        CHECK(h.dispatch_calls.empty()); // record-only: the reconciler applies it on its next tick
    }
}

TEST_CASE("REST POST/DELETE /api/v1/quarantine audit the unwired-scope-gate 500 (gov-fix)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("POST") {
        QuarantineRouteHarness h(qpool, /*wire_scope=*/false);
        auto res = h.post(kBody);
        REQUIRE(res);
        CHECK(res->status == 500);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == "quarantine.enable");
        CHECK(h.audit_calls[0].result == "failure");
        CHECK(h.audit_calls[0].target_id == "agent-B");
    }
    SECTION("DELETE") {
        QuarantineRouteHarness h(qpool, /*wire_scope=*/false);
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 500);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == "quarantine.disable");
        CHECK(h.audit_calls[0].result == "failure");
        CHECK(h.audit_calls[0].target_id == "agent-B");
    }
}

TEST_CASE("REST GET /api/v1/quarantine resolves ONE list-gate decision and pushes its scope into "
          "the store query (ADR-0017)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("an out-of-scope record is dropped, an in-scope record is kept, with no per-record "
            "probe") {
        QuarantineRouteHarness h(qpool);
        REQUIRE(h.quarantine_store.quarantine_device("agent-visible", "seed", "r1", ""));
        REQUIRE(h.quarantine_store.quarantine_device("agent-hidden", "seed", "r2", ""));
        h.list_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-visible"}};
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("agent-visible") != std::string::npos);
        CHECK(res->body.find("agent-hidden") == std::string::npos);
        CHECK(h.gate_calls == 1);
        CHECK(h.gate_type_op == "Security:Read");
        CHECK_FALSE(h.scope_fn_called); // the per-device probe is for POST/DELETE only
    }
    SECTION("an unrestricted (TOP) scope lists every active record") {
        QuarantineRouteHarness h(qpool);
        REQUIRE(h.quarantine_store.quarantine_device("agent-1", "seed", "r1", ""));
        REQUIRE(h.quarantine_store.quarantine_device("agent-2", "seed", "r2", ""));
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("agent-1") != std::string::npos);
        CHECK(res->body.find("agent-2") != std::string::npos);
    }
    SECTION("an empty (deny-all) scope lists nothing") {
        QuarantineRouteHarness h(qpool);
        REQUIRE(h.quarantine_store.quarantine_device("agent-1", "seed", "r1", ""));
        h.list_scope = authz::VisibleSet{std::unordered_set<std::string>{}};
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("agent-1") == std::string::npos);
    }
    SECTION("unwired list gate fails closed (500), not an unfiltered list") {
        QuarantineRouteHarness h(qpool, /*wire_scope=*/true, /*wire_fleet=*/false);
        REQUIRE(h.quarantine_store.quarantine_device("agent-visible", "seed", "r1", ""));
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->body.find("agent-visible") == std::string::npos);
    }
    // A refused or degraded gate writes its own status; the store is never read for it.
    SECTION("a refused or unavailable gate answers with its own status and lists nothing") {
        for (int status : {401, 403, 503}) {
            CAPTURE(status);
            QuarantineRouteHarness h(qpool);
            const std::string id = "agent-visible-" + std::to_string(status);
            REQUIRE(h.quarantine_store.quarantine_device(id, "seed", "r1", ""));
            h.gate_status = status;
            auto res = h.get();
            REQUIRE(res);
            CHECK(res->status == status);
            CHECK(res->body.find(id) == std::string::npos);
        }
    }
    SECTION("no session is refused before any gate or store work") {
        QuarantineRouteHarness h(qpool);
        h.session_user = "";
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(h.gate_calls == 0);
    }
}

// Seam PR2 commit 4: the GET body is built by the shared quarantine_read_model.hpp
// (ordered_json). The expected strings below were captured from the pre-change handler
// (the TU-local JObj builder) and are the byte contract: key order, number formatting
// and control-character escaping must not move. Only quarantined_at is store-assigned,
// so it is spliced in from the stored record.
TEST_CASE("REST GET /api/v1/quarantine body bytes are pinned (key order and escaping)",
          "[rest][quarantine][pg][byte_pin]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("an empty list is an empty array") {
        QuarantineRouteHarness h(qpool);
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body == R"({"data":[],"pagination":{"total":0,"start":0,"page_size":50},)"
                           R"("meta":{"api_version":"v1"}})");
    }
    SECTION("one record with escapes in reason and whitelist") {
        QuarantineRouteHarness h(qpool);
        REQUIRE(h.quarantine_store.quarantine_device(
            "agent-1", "seed", "line1\nq\"b\\s\tt\x01" "x\xc3\xa9/", "10.0.0.1,10.0.0.2"));
        auto list = h.quarantine_store.list_quarantined();
        REQUIRE(list.has_value());
        REQUIRE(list->size() == 1);
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        const std::string expected =
            R"({"data":[{"agent_id":"agent-1","status":"active","quarantined_by":"seed",)"
            R"("quarantined_at":)" +
            std::to_string((*list)[0].quarantined_at) +
            R"(,"whitelist":"10.0.0.1,10.0.0.2",)"
            R"("reason":"line1\nq\"b\\s\tt\u0001x)" "\xc3\xa9" R"(/",)"
            R"("last_applied_at":0,"last_confirmed_at":0}],)"
            R"("pagination":{"total":1,"start":0,"page_size":50},"meta":{"api_version":"v1"}})";
        CHECK(res->body == expected);
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine admits in-scope and fails closed when unwired "
          "(CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("in-scope delete releases the device once it confirms") {
        YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);
        pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
        ResponseStore rstore{rpool};
        REQUIRE(rstore.is_open());
        QuarantineRouteHarness h(qpool, true, true, true, &rstore);
        h.release_reply = "status|inactive";
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.scoped_target == "agent-B");
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("out-of-scope delete is denied (403), device stays quarantined") {
        QuarantineRouteHarness h(qpool);
        h.scope_allow = false;
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.is_quarantined("agent-B")); // untouched
    }
    SECTION("unwired scope gate fails closed, device untouched") {
        QuarantineRouteHarness h(qpool, /*wire_scope=*/false);
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(h.is_quarantined("agent-B")); // untouched
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine runs the dispatch chokepoint for (firewall, "
          "release): the pair, the ordering, the unwired 500 and the second-session 401 "
          "(#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("consults the chokepoint for the release pair with the resolved session") {
        YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);
        pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
        ResponseStore rstore{rpool};
        REQUIRE(rstore.is_open());
        QuarantineRouteHarness h(qpool, true, true, true, &rstore);
        h.release_reply = "status|inactive";
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.authorize_calls == 1);
        CHECK(h.authorize_plugin == "firewall");
        CHECK(h.authorize_action == "release");
        CHECK(h.authorize_caller.principal == "alice");
        CHECK_FALSE(h.authorize_caller.system);
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("a scoped-gate denial never reaches the chokepoint") {
        QuarantineRouteHarness h(qpool);
        h.scope_allow = false;
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.authorize_calls == 0);
        CHECK(h.is_quarantined("agent-B"));
    }
    SECTION("an unwired authorizer fails CLOSED (500, audited failure, record untouched)") {
        QuarantineRouteHarness h(qpool, /*wire_scope=*/true, /*wire_fleet=*/true,
                                 /*wire_authorize=*/false);
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->body.find("dispatch authorizer not configured") != std::string::npos);
        CHECK(h.is_quarantined("agent-B"));
        REQUIRE(h.audit_calls.size() == 1); // the failure row only: no attempt row
        CHECK(h.audit_calls[0].action == "quarantine.disable");
        CHECK(h.audit_calls[0].result == "failure");
        CHECK(h.audit_calls[0].target_id == "agent-B");
    }
    SECTION("a session that no longer resolves at the second auth call ends at 401") {
        QuarantineRouteHarness h(qpool);
        h.auth_fail_from_call = 2; // succeeds once (route entry), then fails (re-resolution)
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(h.auth_calls == 2);
        CHECK(h.scope_fn_called);
        CHECK(h.authorize_calls == 0);
        CHECK(h.is_quarantined("agent-B"));
        CHECK(h.audit_calls.empty()); // no attempt row, no failure row
    }
}

// gov Gate 3 (quality-engineer): a store-level test proving
// quarantine_device()/request_release() return a db_error:-prefixed message
// on a genuine failure does NOT prove the ROUTE actually maps that to 503 --
// the whole is_quarantine_db_error/kQuarantineDbErrorPrefix classification
// chain, plus the is_open()-guard and audit-on-failure fixes from this same
// governance round, had ZERO REST-layer coverage. Force a genuine store
// failure (not a business error) by dropping the schema out from under an
// already-open store: open_ is cached at construction (never re-verified),
// so the route's is_open() guard passes and the query fails live.
TEST_CASE("REST routes answer 503 (not 400) on a genuine store failure, and audit it "
          "(gov Gate 3)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", "").has_value());

    {
        pg::PgConn conn{PQconnectdb(qdb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(), "DROP SCHEMA quarantine_store CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("POST") {
        auto res = h.post(R"({"agent_id":"agent-new","reason":"test"})");
        REQUIRE(res);
        CHECK(res->status == 503);
        REQUIRE(h.audit_calls.size() == 2); // attempt (before the write), then the failure
        CHECK(h.audit_calls[0].result == "attempt");
        CHECK(h.audit_calls[1].action == "quarantine.enable");
        CHECK(h.audit_calls[1].result == "failure");
        CHECK(h.audit_calls[1].detail.starts_with("db_error: "));
        // gov-fix(consistency-auditor, Gate 8.2): the retry_after_ms:5000
        // addition itself had zero wire-level assertions, even though this
        // SECTION already forces the exact failure it targets.
        CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
    }
    SECTION("DELETE") {
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 503);
        REQUIRE(h.audit_calls.size() == 2); // attempt (before the write), then the failure
        CHECK(h.audit_calls[0].result == "attempt");
        CHECK(h.audit_calls[1].action == "quarantine.disable");
        CHECK(h.audit_calls[1].result == "failure");
        CHECK(h.audit_calls[1].detail.starts_with("db_error: "));
        CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
    }
    SECTION("GET") {
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("agent-B") == std::string::npos);
    }
}

// gov Gate 3 (quality-engineer): the audit-on-failure fix (this governance
// round) has no test proving the BUSINESS-error (400) branch audits too --
// only the unwired-scope-gate (500) branch had coverage before this.
TEST_CASE("REST POST/DELETE audit a business-error (400) failure, not just success/500 "
          "(gov Gate 3)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("POST: already quarantined") {
        QuarantineRouteHarness h(qpool);
        REQUIRE(h.post(kBody)->status == 201);
        auto res = h.post(kBody);
        REQUIRE(res);
        CHECK(res->status == 400);
        // first request: attempt + success; this one: attempt + failure
        REQUIRE(h.audit_calls.size() == 4);
        CHECK(h.audit_calls[3].action == "quarantine.enable");
        CHECK(h.audit_calls[3].result == "failure");
        CHECK(h.audit_calls[3].detail == "device is already quarantined");
        // gov-fix(consistency-auditor, Gate 8.2): a business/state error is
        // non-retryable — must stay null, never a fabricated retry hint.
        CHECK(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
    }
    SECTION("DELETE: not quarantined") {
        QuarantineRouteHarness h(qpool);
        auto res = h.del("agent-never-quarantined");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(h.audit_calls.size() == 2); // attempt, then the failure
        CHECK(h.audit_calls[1].action == "quarantine.disable");
        CHECK(h.audit_calls[1].result == "failure");
        CHECK(h.audit_calls[1].detail == "device is not quarantined");
        CHECK(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// #6065 PR-Q: POST /api/v1/quarantine runs the shared dispatch chokepoint
// pre-check ("firewall","quarantine") AFTER the scoped gate and the whitelist
// validation and BEFORE the attempt audit and the store write. These cases pin
// the route wiring; the composed exact-recipient cases (real registry, real
// RbacStore, real reconciler) live in test_rest_quarantine_create_gate.cpp.
// ---------------------------------------------------------------------------

namespace {

nlohmann::json parse_body(const std::string& body) {
    auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(j.is_discarded());
    return j;
}

// The A4 error object, wherever the envelope nests it: either the body itself or its "error"
// member.
const nlohmann::json& error_obj(const nlohmann::json& j) {
    return j.contains("error") && j["error"].is_object() ? j["error"] : j;
}

bool has_audit(const QuarantineRouteHarness& h, const std::string& result) {
    for (const auto& a : h.audit_calls)
        if (a.action == "quarantine.enable" && a.result == result)
            return true;
    return false;
}

} // namespace

TEST_CASE("REST POST /api/v1/quarantine consults the chokepoint for (firewall, quarantine) "
          "with the resolved session as the caller (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.exec_visible_fn = [](const auth::Session&) {
        return authz::VisibleSet{std::unordered_set<std::string>{"agent-B"}};
    };
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.authorize_calls == 1);
    CHECK(h.authorize_plugin == "firewall");
    CHECK(h.authorize_action == "quarantine");
    CHECK(h.authorize_caller.principal == "alice");
    CHECK_FALSE(h.authorize_caller.system);
    // The caller carries the route's own exec_visible derivation, never an unfiltered default.
    REQUIRE(h.authorize_caller.exec_visible.has_value());
    CHECK(h.authorize_caller.exec_visible->contains("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine hands the chokepoint a present-empty exec_visible when "
          "the derivation is the deny-all default (never nullopt)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201);
    REQUIRE(h.authorize_calls == 1);
    REQUIRE(h.authorize_caller.exec_visible.has_value());
    CHECK(h.authorize_caller.exec_visible->empty());
}

TEST_CASE("REST POST /api/v1/quarantine orders the scoped gate and whitelist validation BEFORE "
          "the chokepoint (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("scoped gate false: 403 and the chokepoint is never consulted") {
        QuarantineRouteHarness h(qpool);
        h.scope_allow = false;
        auto res = h.post(kBody);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.authorize_calls == 0);
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("invalid whitelist: 400 and the chokepoint is never consulted") {
        QuarantineRouteHarness h(qpool);
        auto res = h.post(R"({"agent_id":"agent-B","reason":"test","whitelist":"10.0.0.0/24"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.scope_fn_called);
        CHECK(h.authorize_calls == 0);
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("an admitted request consults the scope gate first, then the chokepoint") {
        QuarantineRouteHarness h(qpool);
        auto res = h.post(kBody);
        REQUIRE(res);
        CHECK(res->status == 201);
        REQUIRE(h.order.size() == 2);
        CHECK(h.order[0] == "scope");
        CHECK(h.order[1] == "authorize");
    }
}

TEST_CASE("REST POST /api/v1/quarantine fails CLOSED (500, audited failure, no row) when the "
          "dispatch authorizer is unwired (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool, /*wire_scope=*/true, /*wire_fleet=*/true,
                             /*wire_authorize=*/false);
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(res->body.find("dispatch authorizer not configured") != std::string::npos);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    REQUIRE(h.audit_calls.size() == 1); // the failure row only: no attempt row
    CHECK(h.audit_calls[0].action == "quarantine.enable");
    CHECK(h.audit_calls[0].result == "failure");
    CHECK(h.audit_calls[0].target_id == "agent-B");
}

TEST_CASE("REST POST /api/v1/quarantine ends the request at 401 when the session no longer "
          "resolves at the second auth call (no row, no attempt audit, never 'system') "
          "(#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.auth_fail_from_call = 2; // succeeds once (route entry), then fails (re-resolution)
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.auth_calls == 2);
    CHECK(h.scope_fn_called); // the first session resolved and the scoped gate ran
    CHECK(h.authorize_calls == 0);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    CHECK_FALSE(h.is_quarantined("system"));
    CHECK(h.audit_calls.empty()); // no attempt row, no failure row
    auto list = h.quarantine_store.list_quarantined();
    REQUIRE(list.has_value());
    CHECK(list->empty());
}

TEST_CASE("REST POST /api/v1/quarantine: a chokepoint ApprovalRequired denial is a 403 with an "
          "actionable message + remediation, no `permission`, a denied audit row, the denial "
          "counter, no store row and no attempt row (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.authorize_fn = [](const DispatchCaller&, std::string_view,
                        std::string_view) -> QuarantineRouteHarness::AuthorizeResult {
        return std::unexpected(detail::DispatchDenial{detail::DispatchDenialReason::ApprovalRequired,
                                                      "Security", authz::Operation::Execute});
    };
    auto& ctr = h.metrics.counter("yuzu_server_dispatch_denied_total",
                                  {{"reason", "approval_required"}});
    const auto before = ctr.value();

    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto j = parse_body(res->body);
    const auto& err = error_obj(j);
    REQUIRE(err.contains("message"));
    const std::string message = err.value("message", std::string());
    CHECK(message.find("approval required for firewall.quarantine") != std::string::npos);
    CHECK(message.find("admin caller or a redeemed approval ticket") != std::string::npos);
    REQUIRE(err.contains("remediation"));
    CHECK_FALSE(err.value("remediation", std::string()).empty());
    // A chokepoint denial is not "granting this one permission would admit the caller".
    CHECK_FALSE(err.contains("permission"));
    CHECK_FALSE(j.contains("permission"));
    CHECK(res->body.find("\"permission\"") == std::string::npos);

    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].action == "quarantine.enable");
    CHECK(h.audit_calls[0].result == "denied");
    CHECK(h.audit_calls[0].target_type == "Security");
    CHECK(h.audit_calls[0].target_id == "agent-B");
    CHECK(h.audit_calls[0].detail == "reason=approval_required securable=Security");
    CHECK_FALSE(has_audit(h, "attempt"));

    CHECK(ctr.value() == before + 1);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    auto list = h.quarantine_store.list_quarantined();
    REQUIRE(list.has_value());
    CHECK(list->empty());
}

TEST_CASE("REST POST /api/v1/quarantine: a chokepoint Forbidden denial is a 403 with today's "
          "permission-denied wording and no `permission` field (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    h.authorize_fn = [](const DispatchCaller&, std::string_view,
                        std::string_view) -> QuarantineRouteHarness::AuthorizeResult {
        return std::unexpected(detail::DispatchDenial{detail::DispatchDenialReason::Forbidden,
                                                      "Security", authz::Operation::Execute});
    };
    auto& ctr = h.metrics.counter("yuzu_server_dispatch_denied_total", {{"reason", "forbidden"}});
    const auto before = ctr.value();
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto j = parse_body(res->body);
    const auto& err = error_obj(j);
    CHECK(err.value("message", std::string()) == "permission denied: Security:Execute");
    CHECK_FALSE(err.contains("permission"));
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].result == "denied");
    CHECK(h.audit_calls[0].detail == "reason=forbidden securable=Security");
    CHECK(ctr.value() == before + 1);
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine: a chokepoint Unclassified/Ambiguous denial is a 400, "
          "and a KillSwitched or AnonymousOperator denial is a 403, none writes a row "
          "(#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    using Reason = detail::DispatchDenialReason;
    const auto [reason, status] = GENERATE(std::pair{Reason::Unclassified, 400},
                                           std::pair{Reason::Ambiguous, 400},
                                           std::pair{Reason::KillSwitched, 403},
                                           std::pair{Reason::AnonymousOperator, 403});
    CAPTURE(detail::to_string(reason), status);
    QuarantineRouteHarness h(qpool);
    h.authorize_fn = [reason = reason](const DispatchCaller&, std::string_view,
                                       std::string_view) -> QuarantineRouteHarness::AuthorizeResult {
        return std::unexpected(detail::DispatchDenial{reason, "Security", authz::Operation::Execute});
    };
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == status);
    CHECK(res->body.find("\"permission\"") == std::string::npos);
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].result == "denied");
    CHECK(h.audit_calls[0].detail ==
          "reason=" + std::string(detail::to_string(reason)) + " securable=Security");
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine: an admitted chokepoint decision writes the row with an "
          "attempt then a success audit and increments no denial counter (#6065 PR-Q)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    auto res = h.post(R"({"agent_id":"agent-B","reason":"test","whitelist":"10.0.0.1"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.is_quarantined("agent-B"));
    CHECK_FALSE(has_audit(h, "denied"));
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].result == "success");
    for (const char* label : {"approval_required", "forbidden", "unclassified"})
        CHECK(h.metrics.counter("yuzu_server_dispatch_denied_total", {{"reason", label}})
                  .value() == 0);
}

// ---------------------------------------------------------------------------
// PRQ.2: DELETE /api/v1/quarantine/{agent_id} is a real release. It asks the device to lift its
// firewall rules (firewall.release) and ends the record only on the DEVICE's `status|inactive`
// (200); anything else leaves the record releasing (202) for the reconciler. `?force=true` ends it
// without the device's word and says so.
// ---------------------------------------------------------------------------

namespace {

std::optional<QuarantineRecord> active_record(QuarantineStore& store, const std::string& agent) {
    auto st = store.get_status(agent);
    REQUIRE(st.has_value());
    return *st;
}

std::vector<QuarantineRecord> owed_list(QuarantineStore& store) {
    auto owed = store.list_release_owed();
    REQUIRE(owed.has_value());
    return *owed;
}

const AuditCall* find_audit(const QuarantineRouteHarness& h, const std::string& result) {
    for (const auto& a : h.audit_calls)
        if (a.action == "quarantine.disable" && a.result == result)
            return &a;
    return nullptr;
}

bool has_attempt_row(const QuarantineRouteHarness& h) {
    return find_audit(h, "attempt") != nullptr;
}

// Ends the active record the way `end` says: `device_confirmed` as the reconciler does once it
// reads `inactive`; `forced` as a concurrent forced DELETE does (no device answer, the device
// still owed a release).
void end_record_as(QuarantineStore& store, const std::string& agent, ReleaseEnd end) {
    auto rec = store.get_status(agent);
    REQUIRE(rec.has_value());
    REQUIRE(rec->has_value());
    // A confirmed end presents the apply generation, read now with no claim live (#7613).
    std::optional<std::int64_t> fence;
    if (end == ReleaseEnd::device_confirmed) {
        auto token = store.apply_fence_token(agent, (*rec)->id);
        REQUIRE(token.has_value());
        fence = *token;
    }
    REQUIRE(store.mark_released(agent, (*rec)->id, end, fence).has_value());
}

// Runs one statement on a fresh connection to the test database, for the races that need the
// store's own table changed underneath a request.
void exec_sql(const std::string& dsn, const char* sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql)};
    REQUIRE(r.ok());
}

} // namespace

#define RELEASE_RIG(h, scripted_reply)                                                             \
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);                                             \
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};                                          \
    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);                                          \
    pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};                                          \
    ResponseStore rstore{rpool};                                                                   \
    REQUIRE(rstore.is_open());                                                                     \
    QuarantineRouteHarness h(qpool, true, true, true, &rstore);                                    \
    h.release_reply = scripted_reply;                                                              \
    REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", "10.0.0.1"))

TEST_CASE("REST DELETE /api/v1/quarantine: the device answers status|inactive within the wait -> 200 "
          "released, the record ends, attempt + success rows",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive");
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["released"] == true);
    CHECK(body["data"]["state"] == "released");
    CHECK(body["data"]["forced"] == false);
    CHECK(body["data"]["device_confirmed"] == true);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    CHECK(owed_list(h.quarantine_store).empty());
    // exactly one firewall.release, to the device, as the operator, no parameters
    REQUIRE(h.dispatch_calls.size() == 1);
    CHECK(h.dispatch_calls[0].plugin == "firewall");
    CHECK(h.dispatch_calls[0].action == "release");
    CHECK(h.dispatch_calls[0].agent_ids == std::vector<std::string>{"agent-B"});
    CHECK(h.dispatch_calls[0].caller.principal == "alice");
    CHECK_FALSE(h.dispatch_calls[0].caller.system);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].action == "quarantine.disable");
    CHECK(h.audit_calls[1].result == "success");
    CHECK(h.audit_calls[1].detail.find("state=released record_id=") == 0);
    CHECK(h.audit_calls[1].detail.find("command_id=cmd-1") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/quarantine: a device that is offline -> 202 releasing, the record stays "
          "listed, attempt + pending rows",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "");
    h.dispatch_sent = 0; // nobody reached
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["released"] == false);
    CHECK(body["data"]["state"] == "releasing");
    // The published 202 schema describes this body: every required name is served and every
    // served name is declared.
    const auto spec = nlohmann::json::parse(openapi_spec_json());
    const auto& schema = spec.at("paths")
                             .at("/quarantine/{agent_id}")
                             .at("delete")
                             .at("responses")
                             .at("202")
                             .at("content")
                             .at("application/json")
                             .at("schema")
                             .at("properties")
                             .at("data");
    for (const auto& name : schema.at("required"))
        CHECK(body["data"].contains(name.get<std::string>()));
    for (const auto& served : body["data"].items())
        CHECK(schema.at("properties").contains(served.key()));
    CHECK(h.is_quarantined("agent-B"));
    const auto rec = active_record(h.quarantine_store, "agent-B");
    REQUIRE(rec.has_value());
    CHECK(rec->status == "releasing");
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].result == "attempt");
    CHECK(h.audit_calls[1].result == "pending");
    CHECK(h.audit_calls[1].detail.find("state=releasing") == 0);
}

TEST_CASE("REST DELETE /api/v1/quarantine: a privilege refusal, a partial release and no reply all "
          "leave the record releasing (202), never released",
          "[rest][quarantine][release][pg]") {
    const std::string reply = GENERATE(std::string{"status|refused|privilege_unavailable"},
                                       std::string{"status|partial|release_failed"},
                                       std::string{"status|active"}, std::string{""});
    // The record has either never been confirmed or was confirmed once before the release began:
    // a failed release leaves both kinds releasing.
    const bool once_confirmed = GENERATE(false, true);
    CAPTURE(reply, once_confirmed);
    RELEASE_RIG(h, reply);
    if (once_confirmed) {
        const auto seeded = active_record(h.quarantine_store, "agent-B");
        REQUIRE(seeded.has_value());
        REQUIRE(h.quarantine_store.mark_endpoint_confirmed("agent-B", seeded->id, /*at=*/1000)
                    .has_value());
    }
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(parse_body(res->body)["data"]["state"] == "releasing");
    const auto rec = active_record(h.quarantine_store, "agent-B");
    REQUIRE(rec.has_value());
    CHECK(rec->status == "releasing"); // listed, with the dispatch refusal in force
    CHECK(owed_list(h.quarantine_store).empty());
    CHECK(find_audit(h, "pending") != nullptr);
    CHECK(find_audit(h, "success") == nullptr);
}

TEST_CASE("REST DELETE /api/v1/quarantine: a reply of inactive for a record another writer ended first is "
          "also 200, and the success row says it was already ended",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive");
    h.on_dispatch = [&h] {
        end_record_as(h.quarantine_store, "agent-B", ReleaseEnd::device_confirmed);
    };
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(parse_body(res->body)["data"]["released"] == true);
    const auto* success = find_audit(h, "success");
    REQUIRE(success != nullptr);
    CHECK(success->detail.find("already_ended device_confirmed=true") != std::string::npos);
    CHECK(success->detail.find("ended_by=") == std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/quarantine: with no in-flight slot the release is dispatched, nothing is "
          "waited for, and the answer is 202",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive"); // a reply IS stored; it must not be read
    struct CapGuard {
        int saved{detail::live_max_inflight().load()};
        CapGuard() { detail::live_max_inflight().store(0); }
        ~CapGuard() { detail::live_max_inflight().store(saved); }
    } cap;
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls.size() == 1);
    const auto rec = active_record(h.quarantine_store, "agent-B");
    REQUIRE(rec.has_value());
    CHECK(rec->status == "releasing");
}

TEST_CASE("REST DELETE /api/v1/quarantine: with no dispatch or response store wired the answer is 202 "
          "(the reconciler finishes it)",
          "[rest][quarantine][release][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool, true, true, true, nullptr, /*wire_dispatch=*/false);
    REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls.empty());
    CHECK(h.is_quarantined("agent-B"));
}

TEST_CASE("REST DELETE /api/v1/quarantine: a throwing dispatch is 202, not a 500",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive");
    h.dispatch_throws = true;
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto rec = active_record(h.quarantine_store, "agent-B");
    REQUIRE(rec.has_value());
    CHECK(rec->status == "releasing");
}

TEST_CASE("REST DELETE /api/v1/quarantine: repeated on a releasing record re-dispatches and is not a 400",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "");
    auto first = h.del("agent-B");
    REQUIRE(first);
    CHECK(first->status == 202);
    auto second = h.del("agent-B");
    REQUIRE(second);
    CHECK(second->status == 202);
    CHECK(h.dispatch_calls.size() == 2);
    // and now the device answers: the same call ends it
    h.release_reply = "status|inactive";
    auto third = h.del("agent-B");
    REQUIRE(third);
    CHECK(third->status == 200);
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST DELETE /api/v1/quarantine: no record -> 400, store failure -> 503, chokepoint denial -> "
          "403 with the record still active (not releasing) and no attempt row",
          "[rest][quarantine][release][pg]") {
    SECTION("no record") {
        RELEASE_RIG(h, "status|inactive");
        auto res = h.del("agent-never");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls.empty());
    }
    SECTION("denied at the chokepoint") {
        RELEASE_RIG(h, "status|inactive");
        h.authorize_fn = [](const DispatchCaller&, std::string_view,
                            std::string_view) -> QuarantineRouteHarness::AuthorizeResult {
            return std::unexpected(detail::DispatchDenial{detail::DispatchDenialReason::ApprovalRequired,
                                                          "Security", authz::Operation::Execute});
        };
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto rec = active_record(h.quarantine_store, "agent-B");
        REQUIRE(rec.has_value());
        CHECK(rec->status == "active"); // not releasing: nothing was requested
        CHECK(h.dispatch_calls.empty());
        CHECK_FALSE(has_attempt_row(h));
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].result == "denied");
        CHECK(h.audit_calls[0].detail == "reason=approval_required securable=Security");
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: the device offline -> 200 forced, device_confirmed "
          "false, 'may still be contained'; the record ends and the device is owed a release",
          "[rest][quarantine][release][force][pg]") {
    RELEASE_RIG(h, "");
    h.dispatch_sent = 0;
    auto res = h.del("agent-B", "?force=true");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = parse_body(res->body);
    // `released` is the device's word, not the record's: a forced end answers false (#7642),
    // while `state` still says the record ended.
    CHECK(body["data"]["released"] == false);
    CHECK(body["data"]["state"] == "released");
    CHECK(body["data"]["forced"] == true);
    CHECK(body["data"]["device_confirmed"] == false);
    const std::string message = body["data"]["message"].get<std::string>();
    CHECK(message.find("may still be contained") != std::string::npos);
    CHECK(message.find("without the device's confirmation") != std::string::npos);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    const auto owed = owed_list(h.quarantine_store);
    REQUIRE(owed.size() == 1);
    CHECK(owed[0].agent_id == "agent-B");
    // the attempt row names the force, the success row the reason, both under the operator
    const auto* attempt = find_audit(h, "attempt");
    REQUIRE(attempt != nullptr);
    CHECK(attempt->detail == "force=true");
    const auto* success = find_audit(h, "success");
    REQUIRE(success != nullptr);
    CHECK(success->detail.find("state=released reason=forced device_confirmed=false record_id=") == 0);
    // nothing in the answer says the device was released
    CHECK(res->body.find("\"released\":true") == std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: a reachable device that answers inactive is "
          "released for real (forced false, device_confirmed true), nothing owed",
          "[rest][quarantine][release][force][pg]") {
    RELEASE_RIG(h, "status|inactive");
    auto res = h.del("agent-B", "?force=true");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["forced"] == false);
    CHECK(body["data"]["device_confirmed"] == true);
    CHECK(owed_list(h.quarantine_store).empty());
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: a privilege refusal is forced, and the success row "
          "carries last_status and the command id",
          "[rest][quarantine][release][force][pg]") {
    RELEASE_RIG(h, "status|refused|privilege_unavailable");
    auto res = h.del("agent-B", "?force=true");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["forced"] == true);
    CHECK(body["data"]["device_confirmed"] == false);
    CHECK(body["data"]["command_id"] == "cmd-1");
    const auto* success = find_audit(h, "success");
    REQUIRE(success != nullptr);
    CHECK(success->detail.find("reason=forced") != std::string::npos);
    CHECK(success->detail.find("command_id=cmd-1") != std::string::npos);
    CHECK(success->detail.find("last_status=unconfirmed") != std::string::npos);
    CHECK(owed_list(h.quarantine_store).size() == 1);
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: ends a record already releasing; a record another "
          "writer ended first answers with that record's real end, never a device-confirmed guess",
          "[rest][quarantine][release][force][pg]") {
    SECTION("already releasing") {
        RELEASE_RIG(h, "");
        auto plain = h.del("agent-B");
        REQUIRE(plain);
        CHECK(plain->status == 202);
        auto forced = h.del("agent-B", "?force=true");
        REQUIRE(forced);
        CHECK(forced->status == 200);
        CHECK(parse_body(forced->body)["data"]["forced"] == true);
        CHECK_FALSE(h.is_quarantined("agent-B"));
        CHECK(owed_list(h.quarantine_store).size() == 1);
    }
    SECTION("ended by the reconciler first") {
        RELEASE_RIG(h, "");
        h.on_dispatch = [&h] {
            end_record_as(h.quarantine_store, "agent-B", ReleaseEnd::device_confirmed);
        };
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = parse_body(res->body);
        CHECK(body["data"]["forced"] == false);
        CHECK(body["data"]["device_confirmed"] == true);
        const auto* success = find_audit(h, "success");
        REQUIRE(success != nullptr);
        CHECK(success->detail.find("already_ended device_confirmed=true") != std::string::npos);
        CHECK(success->detail.find("ended_by=") == std::string::npos);
        CHECK(owed_list(h.quarantine_store).empty()); // the device confirmed: nothing owed
    }
    SECTION("ended by a concurrent forced end first") {
        // The losing call of two forced DELETEs: its guarded mark touches no row, but the device
        // was never confirmed and is still owed a release, so it must not read as a release.
        RELEASE_RIG(h, "");
        h.on_dispatch = [&h] { end_record_as(h.quarantine_store, "agent-B", ReleaseEnd::forced); };
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = parse_body(res->body);
        CHECK(body["data"]["forced"] == true);
        CHECK(body["data"]["device_confirmed"] == false);
        CHECK(body["data"]["message"].get<std::string>().find("may still be contained") !=
              std::string::npos);
        const auto* success = find_audit(h, "success");
        REQUIRE(success != nullptr);
        CHECK(success->detail.find("already_ended device_confirmed=false") != std::string::npos);
        CHECK(success->detail.find("ended_by=") == std::string::npos);
        const auto owed = owed_list(h.quarantine_store); // still owed: only the device can clear it
        REQUIRE(owed.size() == 1);
        CHECK(owed[0].agent_id == "agent-B");
    }
    SECTION("the record's row is gone when the losing call reads its history") {
        // A zero-row mark proves the record ended, but a row that is not there cannot show how:
        // a missing row is "not confirmed", never a confirmed release.
        RELEASE_RIG(h, "");
        h.on_dispatch = [&h, &qdb] {
            end_record_as(h.quarantine_store, "agent-B", ReleaseEnd::forced);
            exec_sql(qdb.dsn(), "DELETE FROM quarantine_store.quarantine_records");
        };
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = parse_body(res->body);
        CHECK(body["data"]["forced"] == true);
        CHECK(body["data"]["device_confirmed"] == false);
        const auto* success = find_audit(h, "success");
        REQUIRE(success != nullptr);
        CHECK(success->detail.find("already_ended device_confirmed=false") != std::string::npos);
        CHECK(success->detail.find("ended_by=") == std::string::npos);
        const auto history = h.quarantine_store.get_history("agent-B");
        REQUIRE(history.has_value());
        CHECK(history->empty()); // the read worked; it just found nothing
    }
    SECTION("the history cannot be read when the losing call looks up its record") {
        // Fail ONLY the history read, after the winning forced end: its CASE compares
        // release_requested_at with 0, which no longer type-checks once the column is text. The
        // guarded mark never reads that column, so it still answers "device is not quarantined"
        // and the handler reaches the history read. An unreadable history is "not confirmed".
        RELEASE_RIG(h, "");
        h.on_dispatch = [&h, &qdb] {
            end_record_as(h.quarantine_store, "agent-B", ReleaseEnd::forced);
            exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                                "ALTER COLUMN release_requested_at DROP DEFAULT, "
                                "ALTER COLUMN release_requested_at TYPE text "
                                "USING release_requested_at::text");
        };
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = parse_body(res->body);
        CHECK(body["data"]["forced"] == true);
        CHECK(body["data"]["device_confirmed"] == false);
        const auto* success = find_audit(h, "success");
        REQUIRE(success != nullptr);
        CHECK(success->detail.find("already_ended device_confirmed=false") != std::string::npos);
        CHECK(success->detail.find("ended_by=") == std::string::npos);
        CHECK(find_audit(h, "failure") == nullptr);
        CHECK_FALSE(h.quarantine_store.get_history("agent-B").has_value()); // the read is degraded
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine?force: no record -> 400; any value but true or false -> 400 "
          "with a failure row, nothing dispatched and the record unchanged; force=false is the plain call",
          "[rest][quarantine][release][force][pg]") {
    SECTION("force=true with no record") {
        RELEASE_RIG(h, "");
        auto res = h.del("agent-never", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls.empty());
    }
    SECTION("a value that is not exactly true or false") {
        const std::string q = GENERATE(std::string{"?force=1"}, std::string{"?force=yes"},
                                       std::string{"?force="}, std::string{"?force=TRUE"});
        CAPTURE(q);
        RELEASE_RIG(h, "status|inactive");
        auto res = h.del("agent-B", q);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("force must be true or false") != std::string::npos);
        CHECK(h.dispatch_calls.empty());
        const auto rec = active_record(h.quarantine_store, "agent-B");
        REQUIRE(rec.has_value());
        CHECK(rec->status == "active"); // no release was requested
        CHECK_FALSE(has_attempt_row(h));
        const auto* failure = find_audit(h, "failure");
        REQUIRE(failure != nullptr);
        CHECK(failure->target_id == "agent-B");
        CHECK(owed_list(h.quarantine_store).empty());
    }
    SECTION("force=false behaves as the plain call") {
        RELEASE_RIG(h, "");
        h.dispatch_sent = 0;
        auto res = h.del("agent-B", "?force=false");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(h.is_quarantined("agent-B"));
        const auto* attempt = find_audit(h, "attempt");
        REQUIRE(attempt != nullptr);
        CHECK(attempt->detail.empty());
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: refused by the scoped gate or the chokepoint (403) "
          "leaves the record active, dispatches nothing and writes no attempt row",
          "[rest][quarantine][release][force][pg]") {
    SECTION("scoped gate") {
        RELEASE_RIG(h, "status|inactive");
        h.scope_allow = false;
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto rec = active_record(h.quarantine_store, "agent-B");
        REQUIRE(rec.has_value());
        CHECK(rec->status == "active");
        CHECK(h.dispatch_calls.empty());
        CHECK_FALSE(has_attempt_row(h));
        CHECK(owed_list(h.quarantine_store).empty());
    }
    SECTION("chokepoint") {
        RELEASE_RIG(h, "status|inactive");
        h.authorize_fn = [](const DispatchCaller&, std::string_view,
                            std::string_view) -> QuarantineRouteHarness::AuthorizeResult {
            return std::unexpected(detail::DispatchDenial{detail::DispatchDenialReason::Forbidden,
                                                          "Security", authz::Operation::Execute});
        };
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto rec = active_record(h.quarantine_store, "agent-B");
        REQUIRE(rec.has_value());
        CHECK(rec->status == "active");
        CHECK(h.dispatch_calls.empty());
        CHECK_FALSE(has_attempt_row(h));
        CHECK(owed_list(h.quarantine_store).empty());
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine?force=true: a store failure in the forced mark is a retryable "
          "503 with a failure row, never a 202 that hides it",
          "[rest][quarantine][release][force][pg]") {
    RELEASE_RIG(h, "");
    // The release request has landed by the time the dispatch runs; the schema then disappears, so
    // the forced mark itself fails with a genuine store error.
    h.on_dispatch = [&qdb] {
        pg::PgConn conn{PQconnectdb(qdb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(), "DROP SCHEMA quarantine_store CASCADE")};
        REQUIRE(r.ok());
    };
    auto res = h.del("agent-B", "?force=true");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
    const auto* failure = find_audit(h, "failure");
    REQUIRE(failure != nullptr);
    CHECK(failure->detail.starts_with("db_error: "));
    CHECK(find_audit(h, "success") == nullptr);
    CHECK(find_audit(h, "pending") == nullptr);
}

// ── #7584a: a confirmation that lands BETWEEN the polls ─────────────────────

TEST_CASE("REST DELETE /api/v1/quarantine: a device reply stored after the first empty poll is read by "
          "the second -> 200 released, and the wait paused exactly once",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, ""); // nothing is stored at dispatch time
    int pauses = 0;
    detail::release_confirm_pause_hook() = [&] {
        ++pauses;
        // the late confirmation: the device answers while the route waits
        StoredResponse sr;
        sr.instruction_id = "cmd-1";
        sr.agent_id = "agent-B";
        sr.status = 1;
        sr.output = "status|inactive";
        sr.plugin = "firewall";
        rstore.store(sr);
    };
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["released"] == true);
    CHECK(body["data"]["device_confirmed"] == true);
    CHECK(pauses == 1);
    CHECK_FALSE(h.is_quarantined("agent-B"));
    CHECK(owed_list(h.quarantine_store).empty());
}

TEST_CASE("REST DELETE /api/v1/quarantine: a device that answers inactive while the confirming mark hits a "
          "store error is 202, never a 200 over a record that did not end",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive");
    h.on_dispatch = [&qdb] {
        // The token was read before the dispatch; the schema disappearing now fails the mark.
        exec_sql(qdb.dsn(), "DROP SCHEMA quarantine_store CASCADE");
    };
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["released"] == false);
    CHECK(body["data"]["state"] == "releasing");
    CHECK(find_audit(h, "success") == nullptr);
    const auto* pending = find_audit(h, "pending");
    REQUIRE(pending != nullptr);
    CHECK(pending->detail.find("state=releasing") == 0);
    // a store error is not the fence: neither note is added
    CHECK(pending->detail.find("apply_in_flight=1") == std::string::npos);
    CHECK(pending->detail.find("fence_unread=1") == std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/quarantine: when the apply fence token cannot be read, a device that "
          "answers inactive does not end the record: 202, still releasing, and the pending row says "
          "fence_unread=1",
          "[rest][quarantine][release][pg]") {
    RELEASE_RIG(h, "status|inactive");
    // Fail ONLY the token read: its WHERE compares apply_claimed_at with 0 and with the database
    // clock, which stops type-checking once the column is text. request_release and the release
    // dispatch never touch the column. A failed read treated as a token (generation 0, say) would
    // present it to the confirming mark, so the note on the pending row is what tells the two apart.
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                        "ALTER COLUMN apply_claimed_at DROP DEFAULT, "
                        "ALTER COLUMN apply_claimed_at TYPE text USING apply_claimed_at::text");
    REQUIRE_FALSE(h.quarantine_store.apply_fence_token("agent-B", 1).has_value()); // the read is degraded
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto body = parse_body(res->body);
    CHECK(body["data"]["released"] == false);
    CHECK(body["data"]["state"] == "releasing");
    CHECK(find_audit(h, "success") == nullptr);
    const auto* pending = find_audit(h, "pending");
    REQUIRE(pending != nullptr);
    CHECK(pending->detail.find("state=releasing") == 0);
    CHECK(pending->detail.ends_with(" fence_unread=1"));
    CHECK(pending->detail.find("apply_in_flight=1") == std::string::npos);
    // the release itself went out, and the record is still there, releasing
    CHECK(h.dispatch_calls.size() == 1);
    const auto record = h.quarantine_store.get_status("agent-B");
    REQUIRE(record.has_value());
    REQUIRE(record->has_value());
    CHECK((*record)->status == "releasing"); // listed, and keeping the dispatch refusal
    CHECK((*record)->release_requested_at != 0);
}

// ── #7628: the enable and disable rows name the same record ───────────────────

TEST_CASE("REST POST then DELETE /api/v1/quarantine: the record_id on the quarantine.enable success row "
          "equals the one on the quarantine.disable success row",
          "[rest][quarantine][audit][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_route_tpl);
    pg::PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());
    QuarantineRouteHarness h(qpool, true, true, true, &rstore);
    h.release_reply = "status|inactive";

    auto created = h.post(R"({"agent_id":"agent-B","reason":"seeded by the route"})");
    REQUIRE(created);
    REQUIRE(created->status == 201);
    std::string enable_detail;
    for (const auto& a : h.audit_calls)
        if (a.action == "quarantine.enable" && a.result == "success")
            enable_detail = a.detail;
    REQUIRE_FALSE(enable_detail.empty());
    REQUIRE(enable_detail.rfind("record_id=", 0) == 0);
    const auto space = enable_detail.find(' ');
    REQUIRE(space != std::string::npos);
    const std::string enable_ref = enable_detail.substr(0, space);
    CHECK(enable_detail.substr(space + 1) == "seeded by the route"); // the reason follows, unchanged

    auto released = h.del("agent-B");
    REQUIRE(released);
    REQUIRE(released->status == 200);
    const auto* disable = find_audit(h, "success");
    REQUIRE(disable != nullptr);
    CHECK(disable->detail.find("state=released " + enable_ref + " ") == 0);
}

// ── #7624: the owed records, on request ───────────────────────────────────────

TEST_CASE("REST GET /api/v1/quarantine?include=release_owed: owed rows follow the active rows with status "
          "release_owed; the caller's scope applies; any other include is a 400; a degraded owed read "
          "is a 503",
          "[rest][quarantine][release_owed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineRouteHarness h(qpool);
    REQUIRE(h.quarantine_store.quarantine_device("agent-active", "seed", "contained", "10.0.0.1"));
    const auto owed_id = h.quarantine_store.quarantine_device("agent-owed", "seed", "ended by force", "");
    REQUIRE(owed_id.has_value());
    REQUIRE(h.quarantine_store.mark_released("agent-owed", *owed_id, ReleaseEnd::forced).has_value());
    const auto hidden_id = h.quarantine_store.quarantine_device("agent-hidden", "seed", "x", "");
    REQUIRE(hidden_id.has_value());
    REQUIRE(h.quarantine_store.mark_released("agent-hidden", *hidden_id, ReleaseEnd::forced).has_value());

    const auto get = [&](const std::string& q) { return h.sink.Get("/api/v1/quarantine" + q); };
    const auto agents = [](const std::string& body) {
        std::vector<std::pair<std::string, std::string>> out;
        for (const auto& row : parse_body(body)["data"])
            out.emplace_back(row["agent_id"].get<std::string>(), row["status"].get<std::string>());
        return out;
    };

    SECTION("the default body is the active rows only") {
        auto res = get("");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(agents(res->body) ==
              std::vector<std::pair<std::string, std::string>>{{"agent-active", "active"}});
        CHECK(res->body.find("release_owed") == std::string::npos);
    }
    SECTION("with include, the owed rows follow, newest first, with the two extra keys") {
        auto res = get("?include=release_owed");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto rows = agents(res->body);
        REQUIRE(rows.size() == 3);
        CHECK(rows[0] == std::make_pair(std::string{"agent-active"}, std::string{"active"}));
        CHECK(rows[1].second == "release_owed");
        CHECK(rows[2].second == "release_owed");
        const auto data = parse_body(res->body)["data"];
        CHECK(data[0].size() == 8); // an active row keeps its eight keys
        CHECK(data[1].contains("released_at"));
        CHECK(data[1].contains("release_owed_since"));
        CHECK(parse_body(res->body)["pagination"]["total"] == 3);
    }
    SECTION("the caller's scope is pushed into both reads") {
        h.list_scope = std::unordered_set<std::string>{"agent-active", "agent-owed"};
        auto res = get("?include=release_owed");
        REQUIRE(res);
        const auto rows = agents(res->body);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].first == "agent-active");
        CHECK(rows[1].first == "agent-owed");
        CHECK(res->body.find("agent-hidden") == std::string::npos);
    }
    SECTION("any other include value is a 400 before any read") {
        for (const char* q : {"?include=all", "?include=", "?include=release_owed,x", "?include=RELEASE_OWED"}) {
            CAPTURE(q);
            auto res = get(q);
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.find("include must be release_owed") != std::string::npos);
            CHECK(res->body.find("agent-active") == std::string::npos);
        }
    }
    SECTION("a degraded owed read is a 503, never a list that leaves the owed devices out") {
        // Fail ONLY the owed read: its WHERE compares device_release_owed_at with 0, which stops
        // type-checking once the column is text (the active read never compares it).
        exec_sql(qdb.dsn(), "DROP INDEX quarantine_store.idx_quarantine_release_owed");
        exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                            "ALTER COLUMN device_release_owed_at DROP DEFAULT, "
                            "ALTER COLUMN device_release_owed_at TYPE text "
                            "USING device_release_owed_at::text");
        auto res = get("?include=release_owed");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("agent-active") == std::string::npos);
        // the plain list still works
        auto plain = get("");
        REQUIRE(plain);
        CHECK(plain->status == 200);
    }
}

// ── #7613: an apply that is in flight when the DELETE starts ─────────────────

TEST_CASE("REST DELETE /api/v1/quarantine: an apply's claim is live when the DELETE starts and the device "
          "answers inactive -> 202 with apply_in_flight=1, the record stays releasing; with force it "
          "ends by force and is owed",
          "[rest][quarantine][release][fence][pg]") {
    RELEASE_RIG(h, "status|inactive");
    const auto seeded = active_record(h.quarantine_store, "agent-B");
    REQUIRE(seeded.has_value());
    auto claim = h.quarantine_store.claim_apply("agent-B", seeded->id); // an apply is dispatching
    REQUIRE(claim.has_value());

    SECTION("without force: the device's answer cannot end the record") {
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(parse_body(res->body)["data"]["state"] == "releasing");
        const auto* pending = find_audit(h, "pending");
        REQUIRE(pending != nullptr);
        CHECK(pending->detail.find(" apply_in_flight=1") != std::string::npos);
        CHECK(find_audit(h, "success") == nullptr);
        const auto rec = active_record(h.quarantine_store, "agent-B");
        REQUIRE(rec.has_value());
        CHECK(rec->status == "releasing");
        CHECK(owed_list(h.quarantine_store).empty());
    }
    SECTION("with force: the operator's own end goes through and the device is owed a release") {
        auto res = h.del("agent-B", "?force=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = parse_body(res->body);
        CHECK(body["data"]["released"] == false);
        CHECK(body["data"]["forced"] == true);
        CHECK_FALSE(h.is_quarantined("agent-B"));
        CHECK(owed_list(h.quarantine_store).size() == 1);
        const auto* success = find_audit(h, "success");
        REQUIRE(success != nullptr);
        CHECK(success->detail.find(" apply_in_flight=1") != std::string::npos);
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine: an apply claimed AFTER the route read its token ends nothing on "
          "the device's earlier answer",
          "[rest][quarantine][release][fence][pg]") {
    RELEASE_RIG(h, "status|inactive");
    // The apply is claimed and returns while the release is on its way: the route's token (read
    // before the release went out) is stale by the time it marks.
    h.on_dispatch = [&qdb] {
        // a releasing record is not claimable, so the apply that "followed" is stood in for by the
        // generation moving, which is exactly what a claim does
        exec_sql(qdb.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_gen = apply_gen + 1 "
                            "WHERE agent_id = 'agent-B'");
    };
    auto res = h.del("agent-B");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto* pending = find_audit(h, "pending");
    REQUIRE(pending != nullptr);
    CHECK(pending->detail.find(" apply_in_flight=1") != std::string::npos);
    CHECK(active_record(h.quarantine_store, "agent-B").has_value());
}

#undef RELEASE_RIG
