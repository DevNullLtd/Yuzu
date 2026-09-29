/**
 * test_schedule_routes.cpp — route-handler coverage for the 4-route
 * Schedules API (#2542 PR-8), driven in-process through TestRouteSink (no
 * httplib acceptor, #438), mirroring test_custom_properties_routes.cpp's /
 * test_result_set_routes.cpp's Harness shape.
 *
 * Split into two Harnesses:
 *   - `MockHarness` (no Postgres needed): registration shape + gate-pinning
 *     — which (type, op) pair(s) each route passes to `perm_fn`, IN ORDER,
 *     including POST create's double-gate (Schedule:Write AND
 *     Execution:Execute — H-01, #1806) and POST enable's CONDITIONAL second
 *     gate (Execution:Execute iff the parsed body requests enabled=true) —
 *     plus the null-`schedule_engine` 503 degrade on every route, unaudited.
 *   - `ScheduleRouteHarness` (real `RbacStore` + real `AuthRoutes` + real
 *     `ScheduleEngine`, all Postgres-backed, `[pg]`): `perm_fn` and
 *     `resolve_session_fn` are wired to the REAL `AuthRoutes` (not a bool
 *     mock) so the H-01/M-01/guardian-confinement-2298 assertions below
 *     exercise the actual RBAC engine end-to-end — a stubbed perm_fn could
 *     pass regardless of what `require_permission` actually enforces.
 *     `audit_fn` stays a local recording mock (matches every other #2542
 *     module's convention; the real `AuthRoutes` in this harness is built
 *     with `audit_store=nullptr`, so `audit_log` itself is a silent no-op —
 *     recording locally is the only way to assert on audit rows here).
 *     Covers the create-route's original H-01 gate-ordering pin (a
 *     principal with Schedule:Write but WITHOUT Execution:Execute is denied
 *     403 and creates NO row, and the symmetric case), the PR1.5a typed
 *     `parameters` round-trip/validation, a genuine happy-path success case
 *     for EVERY one of the 4 routes (GET list, POST create, DELETE,
 *     POST enable — including both the enable=true and enable=false
 *     directions), the pre-existing audit asymmetry (GET unaudited; POST
 *     create/DELETE/POST enable audit only their own success outcome), and
 *     the service-scoped-token 403 this module's PG-backed coverage has
 *     pinned since PR #1806 (guardian-confinement-2298) — now produced by
 *     `require_permission`'s own service-scope branch alone (see
 *     schedule_routes.hpp's "SERVICE-SCOPED TOKEN NOTE").
 *
 * PRE-EXISTING PARTIAL EXTRACTION FOLDED IN: this file used to drive
 * `handle_create_schedule` (a standalone `AuthRoutes&`-taking free function,
 * PR #1806's interim H-01 extraction) via direct calls, not TestRouteSink.
 * #2542 PR-8 folded that function's logic into
 * `register_schedule_routes`'s POST handler (see schedule_routes.hpp); every
 * assertion the old direct-call TEST_CASEs made is preserved below, now
 * driven through the sink instead.
 */

#include "schedule_routes.hpp"
#include "test_route_sink.hpp"

#include "auth_routes.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "schedule_engine.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// ── MockHarness: no Postgres needed — registration shape + gate pinning ────

/// All providers mocked, mirroring test_custom_properties_routes.cpp's
/// Harness shape. `schedule_engine` defaults to null — every case that must
/// NOT need Postgres leaves it null and relies on the route returning
/// (403/503) before it would be dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct MockHarness {
    ScheduleEngine* schedule_engine{nullptr};

    /// "Type:Op" pairs perm_fn denies; everything else is allowed. Empty ==
    /// every gate passes.
    std::set<std::string> denied_perms;
    std::vector<std::pair<std::string, std::string>> perm_calls;

    std::optional<auth::Session> session_to_return;

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        schedule::Deps deps;
        deps.schedule_engine = schedule_engine;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            perm_calls.push_back({type, op});
            if (denied_perms.contains(type + ":" + op)) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.resolve_session_fn = [this](const httplib::Request&) { return session_to_return; };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        schedule::register_schedule_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("schedule_routes: registers exactly 4 routes", "[server][routes][schedule_routes]") {
    MockHarness h;
    h.wire();
    CHECK(h.sink.route_count() == 4);
}

// ── Gate pinning (no Postgres needed — every case below returns before a
//    null schedule_engine would be dereferenced) ────────────────────────────

TEST_CASE("schedule_routes: GET /api/schedules gates on Schedule:Read",
          "[server][routes][schedule_routes]") {
    MockHarness h;
    h.wire();

    auto r = h.sink.Get("/api/schedules");
    REQUIRE(r);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Read"});
}

TEST_CASE("schedule_routes: POST /api/schedules gates on Schedule:Write THEN "
          "Execution:Execute, in that order (H-01, #1806)",
          "[server][routes][schedule_routes]") {
    {
        // Schedule:Write denied -> short-circuits before Execution:Execute
        // is ever checked.
        MockHarness h;
        h.denied_perms = {"Schedule:Write"};
        h.wire();
        auto r = h.sink.Post("/api/schedules", "{}");
        REQUIRE(r);
        CHECK(r->status == 403);
        REQUIRE(h.perm_calls.size() == 1);
        CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Write"});
    }
    {
        // Schedule:Write allowed, Execution:Execute denied -> both gates
        // are reached, in order, and the second one wins the 403.
        MockHarness h;
        h.denied_perms = {"Execution:Execute"};
        h.wire();
        auto r = h.sink.Post("/api/schedules", "{}");
        REQUIRE(r);
        CHECK(r->status == 403);
        REQUIRE(h.perm_calls.size() == 2);
        CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Write"});
        CHECK(h.perm_calls[1] == std::pair<std::string, std::string>{"Execution", "Execute"});
    }
}

TEST_CASE("schedule_routes: DELETE /api/schedules/:id gates on Schedule:Delete",
          "[server][routes][schedule_routes]") {
    MockHarness h;
    h.wire();

    auto r = h.sink.Delete("/api/schedules/sched-1");
    REQUIRE(r);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Delete"});
}

TEST_CASE("schedule_routes: POST /api/schedules/:id/enable — with a null schedule_engine, "
          "ONLY Schedule:Write is ever checked, regardless of the requested enabled value "
          "(the null-engine 503 sits BEFORE the body is parsed / the conditional "
          "Execution:Execute gate — see schedule_routes.cpp's handler ordering)",
          "[server][routes][schedule_routes]") {
    MockHarness h; // schedule_engine stays null -> a 503 after the single gate proves no crash
    h.wire();

    auto r_disable = h.sink.dispatch("POST", "/api/schedules/sched-1/enable",
                                     R"({"enabled":false})");
    REQUIRE(r_disable);
    CHECK(r_disable->status == 503);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Write"});

    h.perm_calls.clear();
    auto r_enable = h.sink.dispatch("POST", "/api/schedules/sched-1/enable",
                                    R"({"enabled":true})");
    REQUIRE(r_enable);
    CHECK(r_enable->status == 503); // same 503, same single gate -- Execution:Execute never reached
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Schedule", "Write"});
}

// The conditional Execution:Execute gate (H-01) genuinely firing only when
// enabled=true, and NOT when enabled=false, needs a real (non-null, non-mockable)
// ScheduleEngine to observe past the null-engine check above -- see the
// `[pg]`-tagged "POST /api/schedules/:id/enable" happy-path cases below,
// which dispatch both directions through a real engine and pin the gate
// difference end-to-end.

TEST_CASE("schedule_routes: a null schedule_engine answers 503 on every route without "
          "crashing or auditing",
          "[server][routes][schedule_routes]") {
    MockHarness h;
    h.wire();

    auto r1 = h.sink.Get("/api/schedules");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Post("/api/schedules", "{}");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Delete("/api/schedules/sched-1");
    REQUIRE(r3);
    CHECK(r3->status == 503);

    // enabled=false: only Schedule:Write is checked; still hits the same
    // null-engine 503 as every other route.
    auto r4 = h.sink.dispatch("POST", "/api/schedules/sched-1/enable", R"({"enabled":false})");
    REQUIRE(r4);
    CHECK(r4->status == 503);

    CHECK(h.audits.empty()); // every 503 branch returns before any audit call
}

// ── PG-backed: real RbacStore + real AuthRoutes + real ScheduleEngine ──────

namespace {

// Shares the "rbacstore" key with test_rbac_store.cpp's own template
// (identical setup, replay-verified — docs/postgres-store-playbook.md
// step 7). ScheduleRouteHarness needs a REAL RbacStore (not just an open
// one) — the H-01/M-01/guardian-confinement assertions below exercise
// create_role/set_permission/assign_role for real.
yuzu::test::PgTestTemplate schedule_rbac_tpl{
    "rbacstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac template: store failed to migrate/seed");
    }};

/// Real AuthRoutes + real RbacStore + real ScheduleEngine, wired through
/// `schedule::Deps` and dispatched via `sink` — `perm_fn`/`resolve_session_fn`
/// forward to the real `AuthRoutes` (so the permission-gate/session-identity
/// assertions below have genuine end-to-end coverage — no stubbed perm_fn
/// that could pass regardless of what schedule_routes.cpp actually wires up
/// to `require_permission`), while `audit_fn` stays a local recording mock
/// (this harness's `AuthRoutes` is built with `audit_store=nullptr`, so
/// `audit_log` itself is a silent success no-op — recording locally is the
/// only way to observe audit rows here, matching every other #2542 module's
/// convention).
struct ScheduleRouteHarness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    // rbac_db/rbac_pool must outlive rbac (declaration order = destruction
    // order); std::optional so the PG SKIP-if-no-DSN check can run before
    // any of them are constructed (RbacStore is neither movable nor
    // copyable, so they can't be built as locals and moved in).
    std::optional<yuzu::test::PostgresTestDb> rbac_db;
    std::optional<yuzu::server::pg::PgPool> rbac_pool;
    std::optional<RbacStore> rbac;
    // ADR-0065 (migration-programme PR 5, 1/3): ScheduleEngine now migrated
    // to Postgres. Built on the SAME rbac_pool below (ADR-0008's
    // schema-per-store-on-one-connection model), not a second ephemeral
    // database — same pattern as `analytics` just below.
    std::unique_ptr<ScheduleEngine> schedule_engine;
    yuzu::test::TempDir tmp;
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current
    // TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but
    // broken. Needed by the service-scoped-token deny tests below: a
    // service-scoped session only exists via a REAL Bearer token
    // (AuthRoutes::resolve_session's Bearer path calls through
    // api_token_store_ — there is no injectable AuthFn stub on this class).
    yuzu::test::ApiTokenStorePg api_tokens;
    std::unique_ptr<AnalyticsEventStore> analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink; // LAST — see file header.

    ScheduleRouteHarness() {
        // Manual equivalent of YUZU_REQUIRE_PG_DB_TPL (test_helpers.hpp) —
        // the macro declares a local, non-movable PostgresTestDb, so it
        // can't be used directly to populate a data member; emplace()
        // constructs rbac_db/rbac_pool/rbac in place instead.
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        rbac_db.emplace(schedule_rbac_tpl);
        INFO("[ScheduleRouteHarness rbac fixture] status (blank == came up OK): "
             << rbac_db->error());
        REQUIRE(rbac_db->available());
        rbac_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = rbac_db->dsn(), .size = 4});
        REQUIRE(rbac_pool->valid());
        rbac.emplace(*rbac_pool);
        REQUIRE(rbac->is_open());

        schedule_engine = std::make_unique<ScheduleEngine>(*rbac_pool);
        REQUIRE(schedule_engine->is_open());
        rbac->set_rbac_enabled(true);

        // TempDir only computes a unique path; it does not create the
        // directory (see test_helpers.hpp), so create it before any store
        // tries to open a file underneath it.
        std::filesystem::create_directories(tmp.path);

        // AnalyticsEventStore ported to Postgres (ADR-0049): schema-per-store
        // on the same shared pool as rbac above (ADR-0008's production
        // model) rather than a second ephemeral database.
        analytics = std::make_unique<AnalyticsEventStore>(*rbac_pool);
        REQUIRE(analytics->is_open());

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr, &*rbac, api_tokens.get(),
            /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr, analytics.get(), oidc_mu, oidc_provider);

        schedule::Deps deps;
        deps.perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            return auth_routes->require_permission(req, res, type, op);
        };
        deps.resolve_session_fn = [this](const httplib::Request& req) {
            return auth_routes->resolve_session(req);
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        deps.schedule_engine = schedule_engine.get();
        schedule::register_schedule_routes(sink, deps);
    }

    /// Create a user, a role granting exactly `perms`
    /// ({securable_type, operation} pairs), assign the role, and return the
    /// Cookie header for a valid session for that user.
    std::unordered_map<std::string, std::string>
    session_headers_for(const std::string& username, const std::string& role_name,
                        const std::vector<std::pair<std::string, std::string>>& perms) {
        REQUIRE(auth_mgr.upsert_user(username, username + "-password1", auth::Role::user));
        REQUIRE(rbac->create_role({.name = role_name}).has_value());
        for (const auto& [type, op] : perms) {
            REQUIRE(rbac->set_permission({.role_name = role_name,
                                         .securable_type = type,
                                         .operation = op,
                                         .effect = "allow"})
                        .has_value());
        }
        REQUIRE(rbac->assign_role({.principal_type = "user",
                                   .principal_id = username,
                                   .role_name = role_name})
                    .has_value());

        auto cookie = auth_mgr.authenticate(username, username + "-password1");
        REQUIRE(cookie.has_value());
        return {{"Cookie", "yuzu_session=" + *cookie}};
    }

    /// Same role/permission setup as session_headers_for, but authenticates
    /// via a REAL service-scoped API token (Bearer) instead of a cookie — no
    /// auth_mgr user needed, since AuthRoutes::resolve_session's Bearer path
    /// never touches auth_mgr_. `principal_id` is `username`, matching
    /// production (ApiToken::principal_id, api_token_store.hpp:160), so this
    /// reproduces the exact sub-pattern the interim deny used to close: a
    /// token whose session shares its creating principal's username with an
    /// ordinary session for that same user.
    std::unordered_map<std::string, std::string>
    service_scoped_headers_for(const std::string& username, const std::string& role_name,
                               const std::vector<std::pair<std::string, std::string>>& perms,
                               const std::string& scope_service) {
        REQUIRE(rbac->create_role({.name = role_name}).has_value());
        for (const auto& [type, op] : perms) {
            REQUIRE(rbac->set_permission({.role_name = role_name,
                                         .securable_type = type,
                                         .operation = op,
                                         .effect = "allow"})
                        .has_value());
        }
        REQUIRE(rbac->assign_role({.principal_type = "user",
                                   .principal_id = username,
                                   .role_name = role_name})
                    .has_value());

        // Service-scoped tokens must carry an expiration (api_token_store.cpp
        // validate_human_mint) — an hour out is plenty for a single test run.
        auto expires_at = static_cast<int64_t>(std::time(nullptr)) + 3600;
        auto raw =
            api_tokens->create_token("svc-token", username, expires_at, scope_service);
        REQUIRE(raw.has_value());
        return {{"Authorization", "Bearer " + *raw}};
    }
};

} // namespace

// ── H-01 (#1806): create-route gate ordering ────────────────────────────────

TEST_CASE("POST /api/schedules: Schedule:Write alone is rejected without Execution:Execute (H-01)",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers =
        h.session_headers_for("sched-writer", "ScheduleOnly", {{"Schedule", "Write"}});

    auto res = h.sink.dispatch("POST", "/api/schedules",
                               R"({"name":"nightly-scan","definition_id":"def-1",)"
                               R"("frequency_type":"daily"})",
                               "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.schedule_engine->query_schedules().empty());
}

TEST_CASE("POST /api/schedules: Execution:Execute alone is rejected without Schedule:Write",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers =
        h.session_headers_for("exec-only", "ExecuteOnly", {{"Execution", "Execute"}});

    auto res = h.sink.dispatch("POST", "/api/schedules",
                               R"({"name":"nightly-scan","definition_id":"def-1",)"
                               R"("frequency_type":"daily"})",
                               "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.schedule_engine->query_schedules().empty());
}

TEST_CASE("POST /api/schedules: Schedule:Write + Execution:Execute together create the schedule",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers = h.session_headers_for("sched-op", "ScheduleAndExecute",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});

    auto res = h.sink.dispatch("POST", "/api/schedules",
                               R"({"name":"nightly-scan","definition_id":"def-1",)"
                               R"("frequency_type":"daily"})",
                               "application/json", headers);
    REQUIRE(res);
    CHECK(res->status != 403);
    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].name == "nightly-scan");
    CHECK(scheds[0].created_by == "sched-op");

    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.value("id", "") == scheds[0].id);

    // AUDIT ASYMMETRY: success is audited; body/param-validation 400s and
    // store-level failures are not (see schedule_routes.hpp file header).
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "schedule.create");
    CHECK(h.audits[0].result == "success");
}

// ── PR1.5a: typed schedule parameters ───────────────────────────────────────

TEST_CASE("POST /api/schedules: parameters round-trip to the stored canonical form",
          "[server][routes][schedule_routes][params][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers = h.session_headers_for("sched-op", "ScheduleAndExecute",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});

    auto res = h.sink.dispatch(
        "POST", "/api/schedules",
        R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily",)"
        R"("parameters":{"zeta":"1","alpha":2}})",
        "application/json", headers);
    REQUIRE(res);
    CHECK(res->status != 400);
    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    // Canonical: sorted keys, regardless of the caller's JSON key order.
    CHECK(scheds[0].parameter_values == R"({"alpha":2,"zeta":"1"})");
}

TEST_CASE("POST /api/schedules: invalid parameters are rejected with 400 and create no row",
          "[server][routes][schedule_routes][params][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers = h.session_headers_for("sched-op", "ScheduleAndExecute",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});

    auto res = h.sink.dispatch(
        "POST", "/api/schedules",
        R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily",)"
        R"("parameters":{"nested":{"a":1}}})",
        "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.schedule_engine->query_schedules().empty());
    CHECK(h.audits.empty()); // body/param-validation 400s are unaudited
}

// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. This body is an otherwise-VALID request (name,
// definition_id, frequency_type all present) with "parameters" nested past
// the depth limit - the exact field this handler calls .dump() on
// (params_raw = j["parameters"].dump()). Both status AND message are
// asserted deliberately: validate_and_canonicalize_schedule_params has its
// OWN, entirely independent scalar-value check downstream that ALSO 400s a
// non-scalar "deep" field regardless of nesting depth ("parameter values
// must be a string, number, or boolean") - so status alone cannot tell this
// guard apart from that unrelated check. Only the specific depth-guard
// message proves THIS check fired first, before params_raw was ever built.
// depth 40 is trivially safe to build/dump directly in this test process;
// the real attack depth this guard exists for is many orders of magnitude
// higher (~100,000 levels).
TEST_CASE("POST /api/schedules: a parameters value nested past the depth limit is "
          "rejected, no row created",
          "[server][routes][schedule_routes][params][rest][pg][security][depth]") {
    ScheduleRouteHarness h;
    auto headers = h.session_headers_for("sched-op", "ScheduleAndExecute",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});

    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string body =
        R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily",)"
        R"("parameters":{"deep":)" + deep_array + "}}";
    auto res = h.sink.dispatch("POST", "/api/schedules", body, "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    CHECK(j["error"].get<std::string>().find("nests too deeply") != std::string::npos);
    CHECK(h.schedule_engine->query_schedules().empty());
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/schedules: an omitted parameters field defaults to the canonical empty "
          "object",
          "[server][routes][schedule_routes][params][rest][pg]") {
    ScheduleRouteHarness h;
    auto headers = h.session_headers_for("sched-op", "ScheduleAndExecute",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});

    auto res = h.sink.dispatch("POST", "/api/schedules",
                               R"({"name":"nightly-scan","definition_id":"def-1",)"
                               R"("frequency_type":"daily"})",
                               "application/json", headers);
    REQUIRE(res);
    CHECK(res->status != 400);
    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].parameter_values == "{}");
}

// ── GET /api/schedules: happy path ──────────────────────────────────────────

TEST_CASE("GET /api/schedules: happy path lists the seeded schedules, unaudited",
          "[server][routes][schedule_routes][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.created_by = "seed-user";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers = h.session_headers_for("reader", "ScheduleReader", {{"Schedule", "Read"}});
    auto res = h.sink.Get("/api/schedules", headers);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["schedules"].size() == 1);
    CHECK(body["schedules"][0]["id"] == *created);
    CHECK(body["schedules"][0]["name"] == "nightly-scan");
    CHECK(body["schedules"][0]["definition_id"] == "def-1");
    CHECK(body["schedules"][0]["frequency_type"] == "daily");
    CHECK(h.audits.empty()); // GET is unaudited
}

// ── DELETE /api/schedules/:id: happy path + owner scoping (M-01) ───────────

TEST_CASE("DELETE /api/schedules/:id: happy path deletes an owned schedule and audits success",
          "[server][routes][schedule_routes][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.created_by = "sched-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers =
        h.session_headers_for("sched-owner", "ScheduleDeleter", {{"Schedule", "Delete"}});
    auto res = h.sink.dispatch("DELETE", "/api/schedules/" + *created, "", "application/json",
                               headers);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["deleted"] == true);
    CHECK(h.schedule_engine->query_schedules().empty());

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "schedule.delete");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_id == *created);
}

TEST_CASE("DELETE /api/schedules/:id: a non-owner's Schedule:Delete grant does NOT delete "
          "another principal's schedule (M-01), and the no-op is unaudited",
          "[server][routes][schedule_routes][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.created_by = "original-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers =
        h.session_headers_for("other-user", "ScheduleDeleter2", {{"Schedule", "Delete"}});
    auto res = h.sink.dispatch("DELETE", "/api/schedules/" + *created, "", "application/json",
                               headers);
    REQUIRE(res);
    CHECK(res->status == 200); // route itself never 403s here -- delete_schedule just no-ops
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["deleted"] == false);
    REQUIRE(h.schedule_engine->query_schedules().size() == 1); // still there
    CHECK(h.audits.empty()); // no-op delete is unaudited
}

// ── POST /api/schedules/:id/enable: happy path both directions (H-01/M-01) ──

TEST_CASE("POST /api/schedules/:id/enable: enabling (true) requires Execution:Execute too "
          "and audits success",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.enabled = false;
    sched.created_by = "sched-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers = h.session_headers_for("sched-owner", "ScheduleEnabler",
                                         {{"Schedule", "Write"}, {"Execution", "Execute"}});
    auto res = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                               R"({"enabled":true})", "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["enabled"] == true);

    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].enabled == true);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "schedule.enable");
    CHECK(h.audits[0].result == "success");
}

TEST_CASE("POST /api/schedules/:id/enable: enabling (true) WITHOUT Execution:Execute is "
          "denied 403 and the schedule stays disabled (H-01)",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.enabled = false;
    sched.created_by = "sched-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers =
        h.session_headers_for("sched-owner", "ScheduleWriteOnly", {{"Schedule", "Write"}});
    auto res = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                               R"({"enabled":true})", "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 403);

    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].enabled == false); // unchanged
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/schedules/:id/enable: disabling (false) needs ONLY Schedule:Write — "
          "the kill switch stays reachable without Execution:Execute — and audits success",
          "[server][routes][schedule_routes][h01][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.enabled = true;
    sched.created_by = "sched-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers =
        h.session_headers_for("sched-owner", "ScheduleWriteOnly2", {{"Schedule", "Write"}});
    auto res = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                               R"({"enabled":false})", "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["enabled"] == false);

    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].enabled == false);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "schedule.disable");
    CHECK(h.audits[0].result == "success");
}

TEST_CASE("POST /api/schedules/:id/enable: a non-owner's Schedule:Write grant does NOT "
          "enable/disable another principal's schedule (M-01 parity with DELETE), and the "
          "no-op is unaudited",
          "[server][routes][schedule_routes][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.enabled = false;
    sched.created_by = "original-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    auto headers = h.session_headers_for(
        "other-user", "ScheduleEnabler2", {{"Schedule", "Write"}, {"Execution", "Execute"}});
    auto res = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                               R"({"enabled":true})", "application/json", headers);
    REQUIRE(res);
    CHECK(res->status == 200); // route itself never 403s here -- set_enabled just no-ops
    auto body = json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    // The body unconditionally echoes the REQUESTED value (parse_schedule_enabled's
    // result), not the actual post-state -- confirm the store itself was untouched
    // instead of trusting the response body for that.
    CHECK(body["enabled"] == true);

    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].enabled == false); // still disabled -- the non-owner's request was a no-op
    CHECK(h.audits.empty()); // no-op enable is unaudited, matching DELETE's M-01 shape
}

// ── Interim service-scoped-token deny (guardian-confinement-2298) ─────────
//
// A created/enabled schedule fires unattended through ScheduleRunner with NO
// per-fire confinement (exec_visible=std::nullopt) — worse than a one-shot
// mutating read. Bundled: DELETE/enable are also username-owner-scoped
// (ApiToken::principal_id), so a service-scoped token sharing its creating
// principal's username could otherwise arm recurring fleet-wide dispatch or
// destroy another principal's schedule. See schedule_routes.hpp's
// "SERVICE-SCOPED TOKEN NOTE" — there is no explicit deny call left in any
// of the 4 routes; every 403 below is produced by require_permission's own
// service-scope branch alone (kServiceScopeGlobalSafe is compile-time-empty
// for every securable type).

TEST_CASE("schedule routes: a service-scoped token is denied on all 4 routes even holding "
          "otherwise-sufficient grants",
          "[server][routes][schedule_routes][guardian-confinement][rest][pg]") {
    ScheduleRouteHarness h;
    InstructionSchedule sched;
    sched.name = "nightly-scan";
    sched.definition_id = "def-1";
    sched.frequency_type = "daily";
    sched.created_by = "svc-owner";
    auto created = h.schedule_engine->create_schedule(sched);
    REQUIRE(created.has_value());

    // ITServiceOwner-shaped grant: the role alone would pass every gate
    // below, same as production.
    auto headers = h.service_scoped_headers_for(
        "svc-owner", "ServiceScheduleAll",
        {{"Schedule", "Read"}, {"Schedule", "Write"}, {"Schedule", "Delete"},
         {"Execution", "Execute"}},
        "printers");

    auto get = h.sink.Get("/api/schedules", headers);
    REQUIRE(get);
    CHECK(get->status == 403);

    auto post = h.sink.dispatch("POST", "/api/schedules",
                                R"({"name":"x","definition_id":"def-1",)"
                                R"("frequency_type":"daily"})",
                                "application/json", headers);
    REQUIRE(post);
    CHECK(post->status == 403);

    auto del = h.sink.dispatch("DELETE", "/api/schedules/" + *created, "", "application/json",
                               headers);
    REQUIRE(del);
    CHECK(del->status == 403);

    auto enable = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                                  R"({"enabled":true})", "application/json", headers);
    REQUIRE(enable);
    CHECK(enable->status == 403);

    // #3378: the specific, concerning direction — even DISABLE (the
    // documented "always reachable" kill switch) is denied for a
    // service-scoped token, because Schedule:Write is gated unconditionally
    // before the body is parsed, so the enable route never distinguishes
    // enabled=true from enabled=false for this token class. Pre-existing,
    // not introduced or fixed by this extraction; see #3378.
    auto disable = h.sink.dispatch("POST", "/api/schedules/" + *created + "/enable",
                                   R"({"enabled":false})", "application/json", headers);
    REQUIRE(disable);
    CHECK(disable->status == 403);

    // Nothing above actually mutated the fleet-wide row.
    auto scheds = h.schedule_engine->query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].id == *created);

    // Gate 8 (#2298 PR 3 hardening round, supersedes the prior GC-7 fix this
    // test pinned): `.permission` is omitted entirely, not renamed to the
    // "correct" grant — kServiceScopeGlobalSafe is compile-time-empty, so no
    // grant, correctly-named or not, actually admits a service-scoped caller
    // here (routed-concern MUST clause 5).
    auto post_body = json::parse(post->body, nullptr, false);
    REQUIRE_FALSE(post_body.is_discarded());
    CHECK_FALSE(post_body["error"].contains("permission"));
}

// deny_service_scoped_schedule and its direct unit-test block used to sit
// here — retired together (#3290 Phase 2 bucket 1a): the function's only
// four call sites (the interim handle_create_schedule extraction, and three
// inline server.cpp schedule routes) all fired after their route's own
// require_permission gate, which guardian-confinement-2298 PR 3 ("the
// flip") made provably dead — a service-scoped session can never reach any
// of them. The route-level regression test above still proves the
// observable 403 behavior is unchanged; it's produced by require_permission
// directly instead of this retired helper.

// guardian-confinement-2298 hardening sweep: extract_json_string only
// matches a JSON *string*, so a real JSON boolean {"enabled":false} — the
// standards-compliant encoding every JSON client library produces for a
// boolean field — used to silently fall through to the "absent" default
// (true), inverting the request and defeating the disable-always-reachable
// kill switch (H-01). Pure function, no harness needed.
TEST_CASE("parse_schedule_enabled: accepts real JSON booleans, not just strings",
          "[server][routes][schedule_routes][guardian-confinement]") {
    CHECK(schedule::parse_schedule_enabled(R"({"enabled":true})") == true);
    CHECK(schedule::parse_schedule_enabled(R"({"enabled":false})") == false); // the inversion bug
    CHECK(schedule::parse_schedule_enabled(R"({"enabled":"true"})") == true);
    CHECK(schedule::parse_schedule_enabled(R"({"enabled":"false"})") == false);
    CHECK(schedule::parse_schedule_enabled(R"({})") == true);           // missing key -> default
    CHECK(schedule::parse_schedule_enabled("not json") == true);        // malformed -> default
    CHECK(schedule::parse_schedule_enabled(R"({"enabled":null})") == true); // non-bool/string -> default
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_schedule_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_schedule_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 4 routes. Mirrors
// test_custom_properties_routes.cpp's tripwire (adversarial review finding,
// #4078 tracks generalizing this pattern across the campaign).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("schedule_routes: wiring -- server.cpp still calls register_schedule_routes",
          "[server][routes][schedule_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_schedule_routes(") != std::string::npos);
}
