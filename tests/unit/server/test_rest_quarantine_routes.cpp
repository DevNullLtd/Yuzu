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
#include "authz_gates.hpp"
#include "command_capability.hpp"
#include "rest_api_v1.hpp"

#include <yuzu/metrics.hpp>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
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
    // `auth_fail_from_call` > 0. 0 = never. The quarantine POST resolves the session twice.
    int auth_calls{0};
    int auth_fail_from_call{0};
    // The counter the denial path increments; a real registry so a case reads it back.
    yuzu::MetricsRegistry metrics;

    static AuthorizeResult admitted_capability() {
        return CommandCapability{.plugin = "quarantine",
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
                                    bool wire_authorize = true)
        : quarantine_store(pool) {
        REQUIRE(quarantine_store.is_open());

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
            if (!audit_fail_result.empty() && result == audit_fail_result)
                return false;
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };

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

        authorize_fn = [this](const DispatchCaller&, std::string_view,
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

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, &quarantine_store,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr, /*command_dispatch_fn=*/{},
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
    auto del(const std::string& agent) {
        return sink.Delete("/api/v1/quarantine/" + agent);
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
    QuarantineRouteHarness h(qpool);
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
    // Release: attempt then success.
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
    QuarantineRouteHarness h(qpool);
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
    SECTION("a valid whitelist still succeeds (201)") {
        auto res = h.post(
            R"({"agent_id":"agent-B","reason":"test","whitelist":"10.0.0.1,10.0.0.2"})");
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(h.is_quarantined("agent-B"));
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

TEST_CASE("REST DELETE /api/v1/quarantine admits in-scope and fails closed when unwired "
          "(CDX-P1-02)",
          "[rest][quarantine][authz][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_route_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    SECTION("in-scope delete releases the device") {
        QuarantineRouteHarness h(qpool);
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

// gov Gate 3 (quality-engineer): a store-level test proving
// quarantine_device()/release_device() return a db_error:-prefixed message
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
// pre-check ("quarantine","quarantine") AFTER the scoped gate and the whitelist
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

TEST_CASE("REST POST /api/v1/quarantine consults the chokepoint for (quarantine, quarantine) "
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
    CHECK(h.authorize_plugin == "quarantine");
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
    CHECK(message.find("approval required for quarantine.quarantine") != std::string::npos);
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
