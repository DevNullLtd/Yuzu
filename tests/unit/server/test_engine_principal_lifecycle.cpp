/**
 * test_engine_principal_lifecycle.cpp — PR 4.3 (T13) integration coverage
 * for the WIRED engine-principal lifecycle surface: RestApiV1's
 * the engine-principals REST routes + SettingsRoutes' owner-delete guard,
 * exercised the way server.cpp actually wires them (set_engine_principal_store
 * / set_user_exists_fn called BEFORE register_routes — see rest_api_v1.hpp's
 * doc comments on both setters). Unit coverage for each store in isolation
 * lives in test_engine_principal_store.cpp / test_api_token_store.cpp; PR 4.2's
 * cross-store wiring (AuthRoutes session synthesis, RBAC resolution, the
 * namespace collision-scan preflight) lives in
 * test_engine_principal_integration.cpp. This file is the T13 integrator's
 * own seam: the REAL REST route shapes (read from rest_api_v1.cpp, not
 * assumed) plus the T12 background sweep at the store level.
 *
 * Pattern: register RestApiV1 (and, in one TEST_CASE, SettingsRoutes)
 * against an in-process TestRouteSink and dispatch synthesized
 * httplib::Request objects through the captured handlers — the same
 * TSan-safe pattern test_rest_api_tokens.cpp / test_settings_routes_users.cpp
 * use (a real httplib::Server + acceptor thread crashes deterministically
 * under TSan with no report, #438).
 *
 * PG-gated where PG stores are involved (EnginePrincipalStore, ApiTokenStore):
 * SKIPs when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken
 * (test_helpers.hpp skip-vs-fail contract). The SettingsRoutes owner-delete
 * guard tests are also [pg] for the same reason (they wire the real store).
 */

#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — shared PG-backed ApiTokenStore helper
#include "engine_principal_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "settings_routes.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>
#include <libpq-fe.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// ── shared PG-backed EnginePrincipalStore helper (mirrors
//    test_engine_principal_integration.cpp's local class; distinct
//    PgTestTemplate name — "engineprincipal_lc" — from that file's
//    "engineprincipal_integ" and test_engine_principal_store.cpp's
//    "engineprincipal", so the three files' template registrations never
//    collide). ──────────────────────────────────────────────────────────

void setup_engine_principal_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("engine_principal (lifecycle) template: store failed to migrate");
}

yuzu::test::PgTestTemplate engine_principal_lifecycle_template{
    "engineprincipal_lc", &setup_engine_principal_store_pg_template};

// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test (the
// dominant Windows [pg]-shard cost, #2354 — see test_software_inventory_store
// .cpp's SwinvShared, the reference conversion). Built lazily; at testRunEnded
// the pool is drained and the clone dropped (keep_until_run_end). Every test
// in this file is CRUD-only against the store (the fail-closed arms build
// their own garbage-DSN pools and never touch the shared clone), so there are
// no per-case-database carve-outs.
struct EpLcShared {
    yuzu::test::PostgresTestDb db{engine_principal_lifecycle_template};
    std::optional<yuzu::server::pg::PgPool> pool;
    EpLcShared() {
        INFO("[EpLcShared] bundle status (blank == database came up OK): " << db.error());
        REQUIRE(db.available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
EpLcShared& ep_lc_shared() {
    static EpLcShared s;
    return s;
}

/// Same call-site interface as before; now a fresh store per fixture over the
/// file-wide shared clone/pool, TRUNCATE-restored at construction (the ctor's
/// migration check is a no-op on the already-migrated clone).
class EnginePrincipalStorePg {
public:
    EnginePrincipalStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        {
            // Scoped: released before the store ctor takes its own lease.
            auto lease = ep_lc_shared().pool->acquire();
            REQUIRE(lease);
            auto trunc = yuzu::server::pg::exec_params(
                lease.get(),
                "TRUNCATE engine_principal_store.engine_principals RESTART IDENTITY CASCADE",
                std::vector<std::string>{});
            INFO("[EpLcShared] reset: " << PQresultErrorMessage(trunc.get()));
            REQUIRE(trunc.status() == PGRES_COMMAND_OK);
        }
        store_ = std::make_unique<EnginePrincipalStore>(*ep_lc_shared().pool);
        REQUIRE(store_->is_open());
    }

    EnginePrincipalStorePg(const EnginePrincipalStorePg&) = delete;
    EnginePrincipalStorePg& operator=(const EnginePrincipalStorePg&) = delete;

    [[nodiscard]] EnginePrincipalStore* get() const noexcept { return store_.get(); }
    EnginePrincipalStore* operator->() const noexcept { return store_.get(); }

    void reset() noexcept { store_.reset(); }

private:
    std::unique_ptr<EnginePrincipalStore> store_;
};

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── RbacStore PgTestTemplate for RestEngineHarness — a fresh clone per
// harness instance (one per TEST_CASE), NOT the file's shared
// EnginePrincipalStore/ApiTokenStore pools: those are process-wide
// singletons TRUNCATE-reset only for their OWN tables, and several TEST_CASEs
// below create the SAME custom role name ("EngineReader") on a fresh
// RbacStore, which would collide if the rbac_store schema's rows persisted
// across TEST_CASEs.
void setup_rbac_store_pg_lifecycle_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (lifecycle) template: store failed to migrate/seed");
}

// Distinct name from test_rbac_store.cpp's "rbacstore" and
// test_engine_principal_integration.cpp's "rbacstore_integ" — separate
// PgTestTemplate registry entries, no shared-state risk.
yuzu::test::PgTestTemplate rbac_store_lifecycle_template{"rbacstore_lc",
                                                         &setup_rbac_store_pg_lifecycle_template};

// #2964: PostgreSQL's OWN clock, queried directly. Since the clock-guarded
// rotation sweep (`ApiTokenStore::sweep_expired_rotations`) reads PG's own
// `now()` for its eligibility decision rather than trusting the `now`
// argument a caller passes, a sweep test can no longer "time-travel" a
// pair's overlap window into the past by simply passing a large future
// `now` to `sweep_expired_rotations` itself — mirrors
// `AuditStore::cleanup_once`'s identical divergence (`test_audit_store.cpp`
// carries the same helper). Tests below force a predecessor's
// `overlap_expires_at` directly, relative to a `pg_now(dsn)` reading, rather
// than relying on wall-clock elapse.
std::int64_t pg_now(const std::string& dsn) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), "SELECT EXTRACT(EPOCH FROM now())::bigint")};
    REQUIRE(r.ok());
    return std::stoll(PQgetvalue(r.get(), 0, 0));
}

// Force an EXISTING predecessor row's overlap window to a specific instant
// (typically already-elapsed relative to `pg_now`) via a direct UPDATE —
// simulates "the window has now elapsed" without an actual wall-clock wait,
// which a PG-authoritative eligibility decision cannot otherwise fast-
// forward through in a test. Direct-SQL precedent: `wire_manual_rotation_
// pair` (test_api_token_store.cpp).
void force_overlap_expires_at(const std::string& dsn, const std::string& token_id,
                              std::int64_t overlap_expires_at) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r = pg::exec_params(
        conn.get(), "UPDATE api_token_store.api_tokens SET overlap_expires_at = $1 WHERE token_id = $2",
        std::vector<std::string>{std::to_string(overlap_expires_at), token_id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

// ── Main REST harness ───────────────────────────────────────────────────
//
// Wires RestApiV1 the way server.cpp does: set_engine_principal_store +
// set_user_exists_fn called BEFORE register_routes(). auth_fn/perm_fn/
// step_up_fn are mocks driven by public toggles so a single harness
// instance can act as different principals / permission states across
// SECTIONs without rebuilding the fixture. A real (Postgres-backed) RbacStore
// is wired too — its own fresh clone per harness instance (see
// rbac_store_lifecycle_template above) — and the no-admin auditor route needs
// one.
struct RestEngineHarness {
    // Declared BEFORE rbac_store so it destructs AFTER (reverse declaration
    // order): the store must close before its pool, and the pool before the
    // ephemeral database is dropped.
    std::optional<yuzu::test::PostgresTestDb> rbac_db;
    std::optional<yuzu::server::pg::PgPool> rbac_pool;

    EnginePrincipalStorePg engine_store;
    yuzu::test::ApiTokenStorePgShared token_store;
    std::unique_ptr<RbacStore> rbac_store;

    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Mock session/permission/step-up state — set before each dispatch.
    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};
    std::string session_principal_kind; // "" (human) by default
    std::string session_auth_source{"local"};
    bool session_present{true};
    bool perm_allow{true};
    bool step_up_allow{true};
    // #2466/#2406: drive an audit-store persist failure. When false, the audit_fn
    // returns false (row NOT persisted) exactly as AuditStore::log does on a
    // degraded store — the routes must then fail closed (503 + Sec-Audit-Failed)
    // on a mutation and set the header on a read/denial.
    bool audit_allow{true};

    std::unordered_set<std::string> existing_users{"alice", "bob"};

    std::vector<AuditCall> audit_log;

    RestEngineHarness() {
        // By this point every member above (engine_store, in particular) has
        // already constructed, so the "PG DSN unset -> SKIP" gate has already
        // fired if needed — no separate guard required here.
        rbac_db.emplace(rbac_store_lifecycle_template);
        INFO("[RestEngineHarness] rbac db status (blank == database came up OK): "
             << rbac_db->error());
        REQUIRE(rbac_db->available());
        rbac_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = rbac_db->dsn(), .size = 4});
        REQUIRE(rbac_pool->valid());
        rbac_store = std::make_unique<RbacStore>(*rbac_pool);
        REQUIRE(rbac_store->is_open());

        // Wire the SAME referential-integrity resolver server.cpp installs
        // (deliverable A) — without it, ApiTokenStore::create_token's
        // engine block fails closed on every mint/rotate ("engine referent
        // check unavailable" -> 503), regardless of engine_principal_store
        // being wired on the RestApiV1 side.
        token_store->set_engine_referent_check(
            [this](const std::string& id) { return engine_store->get_for_auth(id).status; });

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            return s;
        };

        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_allow) {
                res.status = 403;
                return false;
            }
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            return audit_allow;
        };

        auto step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                                 const auth::Session&, const std::string&) -> bool {
            if (!step_up_allow) {
                res.status = 401;
                return false;
            }
            return true;
        };

        auto user_exists_fn = [this](const std::string& u) -> bool {
            return existing_users.contains(u);
        };

        api.set_engine_principal_store(engine_store.get());
        api.set_user_exists_fn(user_exists_fn);

        // Every other store is nullptr — every engine-principal handler
        // null-checks its own dependencies and 503s cleanly if hit.
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, rbac_store.get(),
                            /*mgmt_store=*/nullptr, token_store.get(),
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, step_up_fn);
    }

    // ── Convenience wrappers over the real route shapes (rest_api_v1.cpp) ──

    auto create(const std::string& slug, const std::string& owner = "alice",
               const std::string& classification = "internal") {
        nlohmann::json body{{"slug", slug},
                            {"display_name", slug + " engine"},
                            {"owner_username", owner},
                            {"justification", "test"},
                            {"classification", classification}};
        return sink.Post("/api/v1/engine-principals", body.dump());
    }

    auto mint(const std::string& principal_id, int64_t ttl_days = 90) {
        nlohmann::json body{{"ttl_days", ttl_days}};
        return sink.Post("/api/v1/engine-principals/" + principal_id + "/credentials",
                         body.dump());
    }

    auto rotate(const std::string& principal_id, int64_t overlap_secs = 86400) {
        nlohmann::json body{{"overlap_secs", overlap_secs}};
        return sink.Post(
            "/api/v1/engine-principals/" + principal_id + "/credentials/rotate", body.dump());
    }

    auto transfer(const std::string& principal_id, const std::string& new_owner) {
        nlohmann::json body{{"new_owner", new_owner}};
        return sink.Post("/api/v1/engine-principals/" + principal_id + "/transfer-owner",
                         body.dump());
    }

    auto revoke(const std::string& principal_id, const std::string& superseded_by = "") {
        nlohmann::json body = nlohmann::json::object();
        if (!superseded_by.empty())
            body["superseded_by"] = superseded_by;
        return sink.dispatch("DELETE", "/api/v1/engine-principals/" + principal_id, body.dump());
    }

    auto get(const std::string& principal_id) {
        return sink.Get("/api/v1/engine-principals/" + principal_id);
    }

    auto list() { return sink.Get("/api/v1/engine-principals"); }

    /// No-body variant kept deliberately: the 403/engine-deny/step-up order
    /// tests post "{}" to prove the denial belt fires BEFORE body validation
    /// (#2384 added the required token_id, parsed after the belt).
    auto confirm(const std::string& principal_id) {
        return sink.Post(
            "/api/v1/engine-principals/" + principal_id + "/credentials/confirm", "{}");
    }

    auto confirm(const std::string& principal_id, const std::string& token_id,
                 const std::string& secret) {
        nlohmann::json body{{"token_id", token_id}, {"secret", secret}};
        return sink.Post(
            "/api/v1/engine-principals/" + principal_id + "/credentials/confirm", body.dump());
    }

    auto no_admin_audit() { return sink.Get("/api/v1/engine-principals/audit/no-admin"); }

    /// Create+mint in one step for tests that just need a live principal
    /// with one active credential. Returns {principal_id, raw_secret}.
    std::pair<std::string, std::string> create_and_mint(const std::string& slug) {
        auto cres = create(slug);
        REQUIRE(cres);
        REQUIRE(cres->status == 201);
        auto principal_id =
            nlohmann::json::parse(cres->body)["data"]["principal_id"].get<std::string>();
        auto mres = mint(principal_id);
        REQUIRE(mres);
        REQUIRE(mres->status == 201);
        auto raw = nlohmann::json::parse(mres->body)["data"]["token"].get<std::string>();
        return {principal_id, raw};
    }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Gate coverage: 401 (no session) / 403 (no Security:Write) / 401 (no
// step-up) / §9 deny-belt 403 (engine-classed session, both keys).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: 401 without a session", "[pg][rest][engine_principal][gate]") {
    RestEngineHarness h;
    h.session_present = false;

    auto res = h.create("gate-test");
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("Engine-principal REST: 403 without Security:Write on a mutating route",
          "[pg][rest][engine_principal][gate]") {
    RestEngineHarness h;
    h.perm_allow = false;

    auto res = h.create("gate-test");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("Engine-principal REST: 401 without step-up on a mutating route",
          "[pg][rest][engine_principal][gate]") {
    RestEngineHarness h;
    h.step_up_allow = false;

    auto res = h.create("gate-test");
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("Engine-principal REST: confirm's step-up denial precedes body validation — "
          "an empty body still 401s, never a 400 oracle (#2384)",
          "[pg][rest][engine_principal][gate][confirm]") {
    RestEngineHarness h;
    h.step_up_allow = false;

    // "{}" body is missing the now-required token_id, but the step-up gate
    // must fire FIRST — body validation is parsed after the full denial belt.
    auto res = h.confirm("engine:whatever");
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("Engine-principal REST: §9 deny-belt rejects an engine-classed caller "
          "(principal_kind key)",
          "[pg][rest][engine_principal][gate][deny_belt]") {
    RestEngineHarness h;
    h.session_principal_kind = "engine";
    h.session_auth_source = "local"; // deliberately NOT engine_token — principal_kind alone
                                      // must be enough to trip the belt (design §9 primary key)

    auto res = h.create("gate-test");
    REQUIRE(res);
    CHECK(res->status == 403);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "engine_session_denied");
}

TEST_CASE("Engine-principal REST: §9 deny-belt rejects an engine-classed caller "
          "(auth_source key)",
          "[pg][rest][engine_principal][gate][deny_belt]") {
    RestEngineHarness h;
    h.session_principal_kind = ""; // deliberately human-shaped principal_kind — auth_source
                                    // alone must ALSO be enough to trip the belt (§9 second belt)
    h.session_auth_source = "engine_token";

    auto res = h.create("gate-test");
    REQUIRE(res);
    CHECK(res->status == 403);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("Engine-principal REST: §9 deny-belt rejects an engine-classed caller "
          "on EVERY route, not just create (principal_kind key)",
          "[pg][rest][engine_principal][gate][deny_belt]") {
    // The pre-existing deny-belt tests above only ever dispatch through
    // create() — this is the per-route companion the governance review
    // flagged as missing: every one of the 8 REST engine-principal routes
    // wraps its own `deny_engine_session` call (rest_api_v1.cpp), so each
    // one needs its own proof, not just create's. A placeholder principal id
    // is enough for every route below: `deny_engine_session` runs BEFORE
    // any existence/store lookup (read the route bodies in rest_api_v1.cpp),
    // so a nonexistent id still reaches — and is rejected by — the belt.
    RestEngineHarness h;
    h.session_principal_kind = "engine";

    const std::string placeholder_id = "engine:deny-belt-placeholder";

    {
        INFO("route: GET /api/v1/engine-principals (list)");
        auto res = h.list();
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: GET /api/v1/engine-principals/{id}");
        auto res = h.get(placeholder_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: DELETE /api/v1/engine-principals/{id}");
        auto res = h.revoke(placeholder_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: POST /api/v1/engine-principals/{id}/credentials (mint)");
        auto res = h.mint(placeholder_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: POST /api/v1/engine-principals/{id}/credentials/rotate");
        auto res = h.rotate(placeholder_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: POST /api/v1/engine-principals/{id}/credentials/confirm");
        auto res = h.confirm(placeholder_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: POST /api/v1/engine-principals/{id}/transfer-owner");
        auto res = h.transfer(placeholder_id, "bob");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        INFO("route: GET /api/v1/engine-principals/audit/no-admin");
        auto res = h.no_admin_audit();
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    // One denial per route above, each attributed to that route's own
    // action name — proves the belt is wired per-route, not a single shared
    // guard that happens to run once.
    REQUIRE(h.audit_log.size() == 8);
    std::unordered_set<std::string> seen_actions;
    for (const auto& a : h.audit_log) {
        CHECK(a.result == "denied");
        CHECK(a.detail == "engine_session_denied");
        seen_actions.insert(a.action);
    }
    CHECK(seen_actions ==
         std::unordered_set<std::string>{
             "engine_principal.list", "engine_principal.get", "engine_principal.revoke",
             "engine_principal.credential.mint", "engine_principal.credential.rotate",
             "engine_principal.credential.confirm", "engine_principal.transfer_owner",
             "engine_principal.audit.no_admin"});
}

TEST_CASE("Engine-principal REST: §9 deny-belt rejects an engine-classed caller "
          "on EVERY route (auth_source key)",
          "[pg][rest][engine_principal][gate][deny_belt]") {
    // Companion to the principal_kind-keyed sweep above — the SAME 8 routes,
    // tripped via the second belt key instead (§9 second belt).
    RestEngineHarness h;
    h.session_principal_kind = "";
    h.session_auth_source = "engine_token";

    const std::string placeholder_id = "engine:deny-belt-placeholder-2";

    CHECK(h.list()->status == 403);
    CHECK(h.get(placeholder_id)->status == 403);
    CHECK(h.revoke(placeholder_id)->status == 403);
    CHECK(h.mint(placeholder_id)->status == 403);
    CHECK(h.rotate(placeholder_id)->status == 403);
    CHECK(h.confirm(placeholder_id)->status == 403);
    CHECK(h.transfer(placeholder_id, "bob")->status == 403);
    CHECK(h.no_admin_audit()->status == 403);

    REQUIRE(h.audit_log.size() == 8);
    for (const auto& a : h.audit_log)
        CHECK(a.result == "denied");
}

// ═══════════════════════════════════════════════════════════════════════════
// Owner-FK validation.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: owner-FK 400 on a bogus owner (create)",
          "[pg][rest][engine_principal][owner_fk]") {
    RestEngineHarness h;

    auto res = h.create("bad-owner", /*owner=*/"nonexistent-user");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("owner_username") != std::string::npos);
}

TEST_CASE("Engine-principal REST: owner-FK 400 on a bogus owner (transfer-owner)",
          "[pg][rest][engine_principal][owner_fk]") {
    RestEngineHarness h;
    auto [principal_id, raw] = h.create_and_mint("xfer-bad-owner");
    (void)raw;

    auto res = h.transfer(principal_id, "nonexistent-user");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("new_owner") != std::string::npos);
}

TEST_CASE("Engine-principal REST: 404 on a bogus principal id (GET)",
          "[pg][rest][engine_principal][owner_fk]") {
    RestEngineHarness h;

    auto res = h.get("engine:does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}

// ═══════════════════════════════════════════════════════════════════════════
// create -> mint -> rotate -> re-serve(same raw) -> grace-lapsed flow.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: create -> mint -> rotate -> re-serve returns the "
          "SAME successor secret within the grace window",
          "[pg][rest][engine_principal][rotation]") {
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("rotation-flow");

    auto r1 = h.rotate(principal_id);
    REQUIRE(r1);
    REQUIRE(r1->status == 200);
    auto raw2 = nlohmann::json::parse(r1->body)["data"]["token"].get<std::string>();
    CHECK(raw2 != raw1); // successor is a genuinely new secret

    // Immediate re-serve (well within the 120s grace window) — idempotent
    // retry (design doc §7 bullet 1): same raw value, not a fresh mint.
    auto r2 = h.rotate(principal_id);
    REQUIRE(r2);
    REQUIRE(r2->status == 200);
    auto raw2_again = nlohmann::json::parse(r2->body)["data"]["token"].get<std::string>();
    CHECK(raw2_again == raw2);

    // Both credentials are active until the predecessor's overlap window
    // ends (T12's job, not this route's) — confirms the overlap-pair shape
    // landed, not a hard cutover.
    auto active = h.token_store->list_active_for_principal(principal_id);
    CHECK(active.size() == 2);

    // Every successful reveal (mint, rotate, AND the re-serve) is its own
    // audited disclosure event — design doc §7: "every individual reveal ...
    // is its own audited secret-disclosure event, not folded into one
    // 'rotation succeeded' row".
    int reveal_count = 0;
    for (const auto& a : h.audit_log)
        if (a.action == "engine_principal.credential.reveal")
            ++reveal_count;
    CHECK(reveal_count == 2); // one per rotate() call above
}

TEST_CASE("Engine-principal REST: rotate on a lapsed grace window is rejected as a "
          "state conflict (409, design doc §7)",
          "[pg][rest][engine_principal][rotation]") {
    // The REST route itself always evaluates `now` from the real wall
    // clock (`std::time(nullptr)` in rest_api_v1.cpp), so forcing the
    // grace-elapsed branch through the REST surface deterministically
    // would mean a real 120s+ sleep (ApiTokenStore's kRotationGraceSecs).
    // Exercised instead at the store `rotate_engine_credential` accepts
    // an explicit `now` for exactly this reason — the SAME store instance
    // the REST route above calls into, just invoked with an
    // artificially-advanced epoch so the check is deterministic and fast.
    // `engine_store_error_status` (rest_api_v1.cpp) maps this exact
    // "grace window elapsed" substring to HTTP 409 — verified by reading
    // the route's status-mapping helper, not re-asserted here via a real
    // sleep.
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("rotation-lapse");
    (void)raw1;

    auto r1 = h.rotate(principal_id);
    REQUIRE(r1);
    REQUIRE(r1->status == 200);

    // Advance well past the 120s grace window on the SAME store the route
    // wraps (h.token_store.get() == the pointer registered above).
    const auto far_future = now_epoch() + 10 * 60; // +10 minutes
    auto lapsed =
        h.token_store->rotate_engine_credential(principal_id, 86400, far_future, "alice");
    REQUIRE_FALSE(lapsed.has_value());
    CHECK(lapsed.error().find("grace window elapsed") != std::string::npos);
}

TEST_CASE("Engine-principal REST: a re-serve rotate by a DIFFERENT operator than "
          "who initiated it is rejected as a 409 conflict, through the route",
          "[pg][rest][engine_principal][rotation]") {
    // Store-level "different operator" behavior is exercised directly in
    // api_token_store tests; this proves the SAME condition maps to 409
    // through the actual REST dispatch (engine_store_error_status's
    // "different operator" branch) — no time-travel needed, unlike the
    // grace-window-elapsed case above: both rotate() calls land well within
    // the grace window, just as two different session users.
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("rotate-diff-operator");
    (void)raw1;

    h.session_user = "alice";
    auto r1 = h.rotate(principal_id);
    REQUIRE(r1);
    REQUIRE(r1->status == 200);

    // A second rotate call, same in-flight rotation, dispatched as a
    // DIFFERENT operator — the grace-cache binding (Hermes F4) rejects it.
    h.session_user = "bob";
    auto r2 = h.rotate(principal_id);
    REQUIRE(r2);
    CHECK(r2->status == 409);
    CHECK(r2->body.find("different operator") != std::string::npos);
}

TEST_CASE("Engine-principal REST: rotate with an overlap window under the 24h "
          "floor is rejected as a 400, through the route",
          "[pg][rest][engine_principal][rotation]") {
    // Store-level floor enforcement is exercised directly in
    // api_token_store tests; this proves the route's overlap_secs body
    // field actually reaches the store unmodified and the store's rejection
    // maps to 400 (engine_store_error_status's default branch — the message
    // doesn't match any of the specific conflict/retryable substrings).
    RestEngineHarness h;
    auto [principal_id, raw] = h.create_and_mint("rotate-under-floor");
    (void)raw;

    auto res = h.rotate(principal_id, /*overlap_secs=*/3600); // 1h, well under the 24h floor
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("24h floor") != std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// No-admin auditor query (§4.2).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: no-admin auditor query returns clean for a "
          "normally-permissioned engine principal",
          "[pg][rest][engine_principal][no_admin]") {
    RestEngineHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store->set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());

    auto [principal_id, raw] = h.create_and_mint("clean-audit");
    (void)raw;
    REQUIRE(h.rbac_store->assign_role({"engine", principal_id, "EngineReader"}).has_value());

    auto res = h.no_admin_audit();
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["ok"].get<bool>() == true);
    CHECK(body["data"]["violations"].size() == 0);
}

TEST_CASE("Engine-principal REST: no-admin auditor query flags a seeded admin "
          "role assignment",
          "[pg][rest][engine_principal][no_admin]") {
    // `RbacStore::assign_role` itself REJECTS granting 'Administrator' (or
    // any is_system role) to an engine principal (F1/the literal admin bar
    // — see test_engine_principal_integration.cpp) — there is no live
    // write path that could produce this row today. The no-admin auditor
    // query exists precisely as the defense-in-depth catch for a row that
    // predates that bar, or a future write path that doesn't route through
    // assign_role's validation (a direct migration/backfill, a corrupted
    // restore). Simulate that shape the same way the T8 collision-scan test
    // (test_engine_principal_integration.cpp) seeds a pre-existing row: a
    // raw INSERT via a second lease on the harness's own rbac_pool — the
    // schema already exists (RbacStore's ctor migrated it), so this landing
    // directly in the table is exactly the "predates the write-path bar"
    // shape being simulated.
    RestEngineHarness h;
    auto [principal_id, raw] = h.create_and_mint("admin-audit");
    (void)raw;

    // Direct INSERT bypassing assign_role's F1 bar — see the comment above.
    {
        auto lease = h.rbac_pool->acquire();
        REQUIRE(lease);
        auto ins = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
            "VALUES ('engine', $1, 'Administrator')",
            std::vector<std::string>{principal_id});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
    }

    auto res = h.no_admin_audit();
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["ok"].get<bool>() == false);
    REQUIRE(body["data"]["violations"].size() == 1);
    CHECK(body["data"]["violations"][0]["principal_id"].get<std::string>() == principal_id);
    CHECK(body["data"]["violations"][0]["reason"].get<std::string>() == "admin_role");
}

TEST_CASE("Engine-principal REST: no-admin auditor fails CLOSED (503) when the "
          "RBAC reference tables are empty rather than reporting ok:true",
          "[pg][rest][engine_principal][no_admin][fail_closed]") {
    // rest_api_v1.cpp's route comment is explicit: `list_securable_types()`/
    // `list_operations()` read reference tables RBAC bootstrap seeds
    // UNCONDITIONALLY at DB creation — a live deployment never legitimately
    // has zero rows in either, so empty means resolution failed, and the
    // route must report "cannot verify" (503), NEVER a silently-vacuous
    // {"ok":true}. Simulate that degraded state the SAME way the
    // seeded-admin test above simulates a pre-existing row: a raw DELETE,
    // via a second lease on the harness's own rbac_pool, against the schema
    // the harness's already-open RbacStore migrated.
    RestEngineHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());

    auto [principal_id, raw] = h.create_and_mint("no-admin-degraded");
    (void)raw;
    REQUIRE(h.rbac_store->assign_role({"engine", principal_id, "EngineReader"}).has_value());

    {
        auto lease = h.rbac_pool->acquire();
        REQUIRE(lease);
        // pg::exec_params is single-statement (PQexecParams) — several calls.
        // role_permissions REFERENCES securable_types(name) AND operations(id),
        // so under PG's enforced FKs the referenced rows cannot be deleted until
        // role_permissions is cleared first (unlike the old raw-SQLite path).
        auto del0 = yuzu::server::pg::exec_params(
            lease.get(), "DELETE FROM rbac_store.role_permissions", std::vector<std::string>{});
        REQUIRE(del0.status() == PGRES_COMMAND_OK);
        auto del1 = yuzu::server::pg::exec_params(
            lease.get(), "DELETE FROM rbac_store.securable_types", std::vector<std::string>{});
        REQUIRE(del1.status() == PGRES_COMMAND_OK);
        auto del2 = yuzu::server::pg::exec_params(lease.get(), "DELETE FROM rbac_store.operations",
                                                  std::vector<std::string>{});
        REQUIRE(del2.status() == PGRES_COMMAND_OK);
    }

    // Sanity: the degrade actually took — list_securable_types()/
    // list_operations() now read back empty on the harness's own (already-
    // open) RbacStore handle.
    REQUIRE(h.rbac_store->list_securable_types().empty());
    REQUIRE(h.rbac_store->list_operations().empty());

    auto res = h.no_admin_audit();
    REQUIRE(res);
    CHECK(res->status == 503);
    // Must NOT be the ok:true shape — a plain a4_error body, not the
    // {"data":{"ok":true,...}} success envelope.
    CHECK(res->body.find("\"ok\":true") == std::string::npos);
    CHECK(res->body.find("cannot verify") != std::string::npos);

    bool found_failure = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.audit.no_admin" && a.result == "failure" &&
            a.detail == "rbac_resolution_failed")
            found_failure = true;
    }
    CHECK(found_failure);
}

// ═══════════════════════════════════════════════════════════════════════════
// DELETE kills both identity + credentials.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: DELETE revokes both the identity AND every "
          "active credential",
          "[pg][rest][engine_principal][revoke]") {
    RestEngineHarness h;
    auto [principal_id, raw] = h.create_and_mint("revoke-cascade");
    (void)raw;
    REQUIRE(h.token_store->list_active_for_principal(principal_id).size() == 1);

    auto res = h.revoke(principal_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["revoked"].get<bool>() == true);
    CHECK(body["data"]["credentials_revoked"].get<int64_t>() == 1);

    // Identity: lifecycle_state flips to revoked (GET-by-id still returns
    // the row — revoke is soft-retain, never a hard delete).
    auto get_res = h.get(principal_id);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    auto get_body = nlohmann::json::parse(get_res->body);
    CHECK(get_body["data"]["lifecycle_state"].get<std::string>() == "revoked");

    // Credentials: zero active afterwards.
    CHECK(h.token_store->list_active_for_principal(principal_id).empty());

    // A second DELETE is idempotent-shaped (already-revoked identity, no
    // active credentials left) — must not error or double-count.
    auto res2 = h.revoke(principal_id);
    REQUIRE(res2);
    CHECK(res2->status == 200);
}

// ═══════════════════════════════════════════════════════════════════════════
// list / confirm dispatched through the real REST handler (previously only
// exercised at the store level, per the governance review), plus the
// transfer-owner 200 success path (previously only the bogus-owner 400 was
// covered).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: GET /api/v1/engine-principals (list) dispatched "
          "through the handler — auth->perm->deny-belt->store->audit",
          "[pg][rest][engine_principal][list]") {
    RestEngineHarness h;
    auto [id1, raw1] = h.create_and_mint("list-flow-one");
    (void)raw1;
    auto cres2 = h.create("list-flow-two");
    REQUIRE(cres2);
    REQUIRE(cres2->status == 201);
    auto id2 = nlohmann::json::parse(cres2->body)["data"]["principal_id"].get<std::string>();

    auto res = h.list();
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    CHECK(body["data"].size() == 2);
    CHECK(body["pagination"]["total"].get<int64_t>() == 2);

    std::unordered_map<std::string, nlohmann::json> by_id;
    for (const auto& row : body["data"])
        by_id[row["principal_id"].get<std::string>()] = row;

    REQUIRE(by_id.contains(id1));
    CHECK(by_id[id1]["active_credential_count"].get<int64_t>() == 1); // create_and_mint minted one
    CHECK(by_id[id1]["lifecycle_state"].get<std::string>() == "active");
    REQUIRE(by_id.contains(id2));
    CHECK(by_id[id2]["active_credential_count"].get<int64_t>() == 0); // create() alone, no mint

    bool found_audit = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.list" && a.result == "success")
            found_audit = true;
    }
    CHECK(found_audit);
}

TEST_CASE("Engine-principal REST: POST .../credentials/confirm dispatched through "
          "the handler resolves an in-flight rotation the SAME operator initiated",
          "[pg][rest][engine_principal][confirm]") {
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("confirm-flow");
    (void)raw1;
    h.session_user = "alice";

    auto rot = h.rotate(principal_id);
    REQUIRE(rot);
    REQUIRE(rot->status == 200);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2); // overlap pair live

    // The rotate response returns the successor token_id — the value the
    // #2384 pin requires the confirm caller to pass back.
    const auto successor_token_id =
        nlohmann::json::parse(rot->body)["data"]["token_id"].get<std::string>();
    REQUIRE_FALSE(successor_token_id.empty());

    // Same operator ("alice") who initiated the rotation confirms it,
    // pinning the exact rotation with the successor id AND proving possession
    // of the successor secret from the response (#3015).
    const auto successor_secret =
        nlohmann::json::parse(rot->body)["data"]["token"].get<std::string>();
    auto res = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["confirmed"].get<bool>() == true);

    // Confirm resolves the rotation: predecessor revoked, successor's
    // rotation state cleared, exactly one active credential remains (design
    // §7's "confirm closes the loop" contract, same as the T12 sweep test
    // above but reached via confirm instead of the elapsed-window sweep).
    auto active = h.token_store->list_active_for_principal(principal_id);
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());
    CHECK(active[0].token_id == successor_token_id); // rotate returned the REAL successor

    bool found_audit = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.credential.confirm" && a.result == "success" &&
            a.detail.find("token_id=" + successor_token_id) != std::string::npos)
            found_audit = true;
    }
    CHECK(found_audit);
}

TEST_CASE("Engine-principal REST: confirm replayed after success is a terminal 409 (A4) with a "
          "conflict metric, not a retryable 503 (#2404)",
          "[pg][rest][engine_principal][confirm]") {
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("confirm-replay");
    (void)raw1;
    h.session_user = "alice";

    auto rot = h.rotate(principal_id);
    REQUIRE(rot);
    REQUIRE(rot->status == 200);
    const auto successor_token_id =
        nlohmann::json::parse(rot->body)["data"]["token_id"].get<std::string>();
    REQUIRE_FALSE(successor_token_id.empty());

    const auto confirm_metric = [&](const char* result) {
        return h.metrics
            .counter("yuzu_engine_principal_confirm_total",
                     {{"surface", "rest"}, {"result", result}})
            .value();
    };

    // First confirm succeeds (the real cutover) — proving possession of the
    // successor secret from the rotate response (#3015).
    const auto successor_secret =
        nlohmann::json::parse(rot->body)["data"]["token"].get<std::string>();
    auto first = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(first);
    REQUIRE(first->status == 200);
    CHECK(confirm_metric("success") == 1.0);

    // The replay (network-dropped 200 / double-submit): SAME args. Terminal
    // 409, NOT 503 — an agentic client honouring idempotentHint must stop, not
    // loop. The A4 envelope carries a correlation_id and the terminal message.
    auto replay = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(replay);
    CHECK(replay->status == 409);
    CHECK(replay->body.find("rotation already confirmed") != std::string::npos);
    CHECK(replay->body.find("correlation_id") != std::string::npos); // A4 envelope
    CHECK(confirm_metric("conflict") == 1.0);
    CHECK(confirm_metric("success") == 1.0); // unchanged by the replay

    // The replay is audited as a failure row — the forensic evidence.
    bool found_fail_audit = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.credential.confirm" && a.result == "failure" &&
            a.detail.find("rotation already confirmed") != std::string::npos)
            found_fail_audit = true;
    }
    CHECK(found_fail_audit);
}

TEST_CASE("Engine-principal REST: confirm with a mismatched or missing token_id is "
          "rejected without touching the rotation (#2384 pin)",
          "[pg][rest][engine_principal][confirm]") {
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("confirm-pin");
    (void)raw1;
    h.session_user = "alice";

    auto rot = h.rotate(principal_id);
    REQUIRE(rot);
    REQUIRE(rot->status == 200);
    const auto successor_token_id =
        nlohmann::json::parse(rot->body)["data"]["token_id"].get<std::string>();
    REQUIRE_FALSE(successor_token_id.empty());

    // Regression (#2384): the rotate response must return the STRUCTURAL
    // successor (supersedes_token_id links to the predecessor), never the
    // newest-created_at row — mint→rotate in this test runs within one
    // second, so created_at ties and the old newest-scan could return the
    // predecessor's id, which would break the confirm pin below.
    std::string structural_successor_id;
    for (const auto& t : h.token_store->list_active_for_principal(principal_id))
        if (!t.supersedes_token_id.empty())
            structural_successor_id = t.token_id;
    CHECK(successor_token_id == structural_successor_id);

    // Mismatched id → 409 Conflict + failure audit; both credentials intact.
    // A valid secret is presented so the pin check (which fires BEFORE the
    // #3015 PoP check) is what rejects it — proving order, not just outcome.
    const auto successor_secret =
        nlohmann::json::parse(rot->body)["data"]["token"].get<std::string>();
    auto mismatch = h.confirm(principal_id, "feedfacefeedfacefeedface", successor_secret);
    REQUIRE(mismatch);
    CHECK(mismatch->status == 409);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2);
    bool found_fail_audit = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.credential.confirm" && a.result == "failure" &&
            a.detail.find("does not match the pending rotation") != std::string::npos)
            found_fail_audit = true;
    }
    CHECK(found_fail_audit);

    // Missing token_id ("{}" body) → 400; malformed / non-object / wrong-typed
    // bodies take the same 400 path (parse hardening, never a throw).
    auto missing = h.confirm(principal_id);
    REQUIRE(missing);
    CHECK(missing->status == 400);
    auto malformed = h.sink.Post(
        "/api/v1/engine-principals/" + principal_id + "/credentials/confirm", "not json{");
    REQUIRE(malformed);
    CHECK(malformed->status == 400);
    auto non_object = h.sink.Post(
        "/api/v1/engine-principals/" + principal_id + "/credentials/confirm", R"(["x"])");
    REQUIRE(non_object);
    CHECK(non_object->status == 400);
    auto wrong_type = h.sink.Post(
        "/api/v1/engine-principals/" + principal_id + "/credentials/confirm",
        R"({"token_id": 5})");
    REQUIRE(wrong_type);
    CHECK(wrong_type->status == 400);

    // The rotation is untouched by all of the above — the correct id + secret
    // still confirms it.
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2);
    auto res = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("Engine-principal REST: confirm requires proof-of-possession of the "
          "successor secret; wrong-secret is 403 and is NOT an oracle (#3015)",
          "[pg][rest][engine_principal][confirm]") {
    RestEngineHarness h;
    auto [principal_id, raw1] = h.create_and_mint("confirm-pop");
    (void)raw1;
    h.session_user = "alice";

    auto rot = h.rotate(principal_id);
    REQUIRE(rot);
    REQUIRE(rot->status == 200);
    const auto rot_json = nlohmann::json::parse(rot->body);
    const auto successor_token_id = rot_json["data"]["token_id"].get<std::string>();
    const auto successor_secret = rot_json["data"]["token"].get<std::string>();
    REQUIRE_FALSE(successor_token_id.empty());
    REQUIRE_FALSE(successor_secret.empty());

    // Wrong secret (correct id, correct initiator) → 403 SecretMismatch; the
    // rotation is untouched. This outcome is reachable ONLY by a caller who has
    // already cleared every authz gate, because PoP is verified LAST.
    auto wrong = h.confirm(principal_id, successor_token_id, "not-the-real-secret");
    REQUIRE(wrong);
    CHECK(wrong->status == 403);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2);

    // Empty secret → 400 input validation, before any authz gate.
    auto empty_secret = h.confirm(principal_id, successor_token_id, "");
    REQUIRE(empty_secret);
    CHECK(empty_secret->status == 400);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2);

    // Oracle-freedom (the architect's engine-arm concern): a DIFFERENT operator
    // ("bob") presenting the CORRECT secret must be rejected by the initiator
    // gate that fires BEFORE PoP — so bob can never distinguish "valid secret"
    // from "wrong secret" (never 200, never the 403 wrong-secret code), and the
    // rotation stays intact.
    h.session_user = "bob";
    auto other = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(other);
    CHECK(other->status == 409); // "rotation in progress by a different operator"
                                 // → Conflict, deterministically — the initiator
                                 // gate fires BEFORE PoP, so it is never 200 and
                                 // never the 403 wrong-secret code.
    // Oracle-freedom proof: bob presenting a WRONG secret must land on the SAME
    // outcome as bob presenting the correct one — if they differed, the code
    // itself would be an oracle over secret validity to a non-initiator.
    auto other_wrong = h.confirm(principal_id, successor_token_id, "not-the-real-secret");
    REQUIRE(other_wrong);
    CHECK(other_wrong->status == other->status);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 2);

    // The real initiator with the real secret still confirms.
    h.session_user = "alice";
    auto ok = h.confirm(principal_id, successor_token_id, successor_secret);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.token_store->list_active_for_principal(principal_id).size() == 1);
}

TEST_CASE("Engine-principal REST: transfer-owner 200 success path (previously "
          "only the bogus-owner 400 was covered)",
          "[pg][rest][engine_principal][transfer]") {
    RestEngineHarness h;
    auto [principal_id, raw] = h.create_and_mint("transfer-success");
    (void)raw;

    auto get_before = h.get(principal_id);
    REQUIRE(get_before);
    REQUIRE(get_before->status == 200);
    CHECK(nlohmann::json::parse(get_before->body)["data"]["owner_username"].get<std::string>() ==
         "alice"); // create()'s default owner

    auto res = h.transfer(principal_id, "bob");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["transferred"].get<bool>() == true);

    auto get_after = h.get(principal_id);
    REQUIRE(get_after);
    REQUIRE(get_after->status == 200);
    CHECK(nlohmann::json::parse(get_after->body)["data"]["owner_username"].get<std::string>() ==
         "bob");

    bool found_audit = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "engine_principal.transfer_owner" && a.result == "success" &&
            a.detail.find("old_owner=alice") != std::string::npos &&
            a.detail.find("new_owner=bob") != std::string::npos)
            found_audit = true;
    }
    CHECK(found_audit);
}

// ═══════════════════════════════════════════════════════════════════════════
// #2466/#2406: audit-store persist-failure handling. A privileged engine-
// principal MUTATION whose audit row does not persist FAILS CLOSED (503 +
// Sec-Audit-Failed) — never success on an unrecorded mutation (ADR-1005
// "mutations fail closed on audit failure"). A READ / DENIAL commits no state,
// so it PROCEEDS but still sets Sec-Audit-Failed (parity with the MCP twins'
// audit_persisted:false). Driven by RestEngineHarness::audit_allow=false, which
// makes audit_fn return false exactly as AuditStore::log does on a degraded
// store. (assign/unassign role live on the RolesHarness — see that file's
// [audit_failclose] cases.)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine-principal REST: a mutation whose audit write drops fails CLOSED "
          "(503 + Sec-Audit-Failed)",
          "[pg][rest][engine_principal][audit_failclose]") {
    RestEngineHarness h;

    SECTION("create") {
        h.audit_allow = false;
        auto r = h.create("audit-create");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->has_header("Sec-Audit-Failed"));
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Attribution (qe-SHOULD-1): the 503 is the DROPPED AUDIT, not a failed
        // create — the principal committed to the store before the (failed) audit.
        auto committed = h.engine_store->get("engine:audit-create");
        REQUIRE(committed);
        CHECK(committed->has_value());
    }

    SECTION("mint withholds the one-time secret") {
        auto cres = h.create("audit-mint");
        REQUIRE(cres);
        REQUIRE(cres->status == 201);
        auto pid = nlohmann::json::parse(cres->body)["data"]["principal_id"].get<std::string>();
        h.audit_allow = false;
        auto r = h.mint(pid);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // The one-time secret must NEVER appear in the fail-closed body.
        CHECK(r->body.find("\"token\"") == std::string::npos);
        // Attribution (qe-SHOULD-1): the credential committed (count 1) though its audit dropped.
        CHECK(h.token_store->list_active_for_principal(pid).size() == 1);
    }

    SECTION("rotate withholds the one-time secret") {
        auto [pid, raw1] = h.create_and_mint("audit-rotate");
        (void)raw1;
        h.audit_allow = false;
        auto r = h.rotate(pid);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("\"token\"") == std::string::npos);
        // Attribution (qe-SHOULD-1): the successor was minted (overlap pair live)
        // though the reveal audit dropped.
        CHECK(h.token_store->list_active_for_principal(pid).size() == 2);
    }

    SECTION("confirm") {
        auto [pid, raw1] = h.create_and_mint("audit-confirm");
        (void)raw1;
        auto rot = h.rotate(pid);
        REQUIRE(rot);
        REQUIRE(rot->status == 200);
        auto tid = nlohmann::json::parse(rot->body)["data"]["token_id"].get<std::string>();
        auto sec = nlohmann::json::parse(rot->body)["data"]["token"].get<std::string>();
        h.audit_allow = false;
        auto r = h.confirm(pid, tid, sec);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Attribution (qe-SHOULD-1): the confirm committed — predecessor retired,
        // the successor is now the sole active credential — though its audit dropped.
        auto active = h.token_store->list_active_for_principal(pid);
        REQUIRE(active.size() == 1);
        CHECK(active[0].token_id == tid);
    }

    SECTION("revoke") {
        // Mint a credential first, so the post-revoke "no active credentials"
        // check is meaningful (a create-only principal has none to begin with).
        auto [pid, raw1] = h.create_and_mint("audit-revoke");
        (void)raw1;
        REQUIRE(h.token_store->list_active_for_principal(pid).size() == 1);
        h.audit_allow = false;
        auto r = h.revoke(pid);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Attribution (qe-SHOULD-1): the revoke committed — the principal is now
        // revoked AND its credential was killed — though its audit dropped.
        auto committed = h.engine_store->get(pid);
        REQUIRE(committed);
        REQUIRE(committed->has_value());
        CHECK((*committed)->lifecycle_state == "revoked");
        CHECK(h.token_store->list_active_for_principal(pid).empty());
    }

    SECTION("transfer-owner") {
        auto cres = h.create("audit-transfer");
        REQUIRE(cres);
        REQUIRE(cres->status == 201);
        auto pid = nlohmann::json::parse(cres->body)["data"]["principal_id"].get<std::string>();
        h.audit_allow = false;
        auto r = h.transfer(pid, "bob");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Attribution (qe-SHOULD-1): ownership committed to "bob" though the transfer audit dropped.
        auto committed = h.engine_store->get(pid);
        REQUIRE(committed);
        REQUIRE(committed->has_value());
        CHECK((*committed)->owner_username == "bob");
    }
}

TEST_CASE("Engine-principal REST: a READ whose audit write drops PROCEEDS (200) but "
          "sets Sec-Audit-Failed",
          "[pg][rest][engine_principal][audit_failclose]") {
    RestEngineHarness h;
    auto cres = h.create("audit-read");
    REQUIRE(cres);
    REQUIRE(cres->status == 201);
    auto pid = nlohmann::json::parse(cres->body)["data"]["principal_id"].get<std::string>();
    h.audit_allow = false;

    SECTION("list") {
        auto r = h.list();
        REQUIRE(r);
        CHECK(r->status == 200); // data still served
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }

    SECTION("get") {
        auto r = h.get(pid);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }

    SECTION("no-admin auditor") {
        auto r = h.no_admin_audit();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("Engine-principal REST: the §9 engine-session denial surfaces a dropped "
          "denial audit via Sec-Audit-Failed (the 403 stands)",
          "[pg][rest][engine_principal][audit_failclose]") {
    RestEngineHarness h;
    // A denial commits no mutation, so the 403 stays; a dropped denial audit
    // must not be silent — the header carries it.
    h.session_principal_kind = "engine";
    h.audit_allow = false;
    auto r = h.rotate("engine:whatever"); // deny belt fires before any store lookup
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
}

// ═══════════════════════════════════════════════════════════════════════════
// SettingsRoutes owner-delete guard (409, incl. the nullopt fail-closed path).
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// Minimal SettingsRoutes harness for the owner-delete guard only — mirrors
/// test_settings_routes_users.cpp's fixture shape but adds the
/// EnginePrincipalStore wiring that file predates. Local to this file
/// rather than promoted to a shared header: only this one guard needs it.
struct SettingsOwnerDeleteHarness {
    yuzu::test::TempDir tmp{"yuzu_test_engine_lifecycle_settings-"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    // Governance Gate 7 BLOCKING fix (UP-7): settings_routes.cpp's DELETE
    // handler now FAILS CLOSED (503) on a null ApiTokenStore rather than
    // skip-and-proceed — this harness's owner-delete-guard tests exercise
    // the delete actually SUCCEEDING past the guard, so they need a real
    // (PG-backed, shared/TRUNCATE-reset) store wired, same as
    // SettingsAdr2001Harness in test_settings_routes_users.cpp.
    yuzu::test::ApiTokenStorePgShared token_store;
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};

    std::vector<AuditCall> audit_calls;

    explicit SettingsOwnerDeleteHarness(EnginePrincipalStore* engine_store) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));

        if (engine_store)
            routes.set_engine_principal_store(engine_store);

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, token_store.get(),
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }

    auto delete_user(const std::string& username) {
        return sink.Delete("/api/settings/users/" + username);
    }
};

} // namespace

TEST_CASE("SettingsRoutes owner-delete guard: blocks deleting a user who owns an "
          "active engine principal (409)",
          "[pg][settings][engine_principal][owner_delete]") {
    EnginePrincipalStorePg engine_store;
    REQUIRE(
        engine_store->create("Vuln Sync", "bob", "j", "internal", "admin", "engine:owned-by-bob")
            .has_value());

    SettingsOwnerDeleteHarness h(engine_store.get());
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 409);

    // The user must still exist — the block took effect before any mutation.
    CHECK(h.auth_mgr.get_user_role("bob").has_value());

    // SOC 2 evidence: the denied attempt is on the audit chain.
    bool found_denied = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "user.delete" && a.result == "denied" && a.target_id == "bob")
            found_denied = true;
    }
    CHECK(found_denied);
}

TEST_CASE("SettingsRoutes owner-delete guard: allows deleting a user with zero "
          "active engine principals",
          "[pg][settings][engine_principal][owner_delete]") {
    EnginePrincipalStorePg engine_store;
    // bob owns nothing — a principal owned by someone else must not block him.
    REQUIRE(engine_store
               ->create("Vuln Sync", "admin", "j", "internal", "admin", "engine:owned-by-admin")
               .has_value());

    SettingsOwnerDeleteHarness h(engine_store.get());
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 200);

    CHECK_FALSE(h.auth_mgr.get_user_role("bob").has_value());
}

TEST_CASE("SettingsRoutes owner-delete guard: a revoked (not active) engine "
          "principal does not block deletion",
          "[pg][settings][engine_principal][owner_delete]") {
    EnginePrincipalStorePg engine_store;
    REQUIRE(
        engine_store->create("Vuln Sync", "bob", "j", "internal", "admin", "engine:revoked-owner")
            .has_value());
    REQUIRE(engine_store->revoke("engine:revoked-owner"));

    SettingsOwnerDeleteHarness h(engine_store.get());
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("SettingsRoutes owner-delete guard: an unreachable engine-principal "
          "store fails CLOSED (409, nullopt path) rather than admitting the delete",
          "[pg][settings][engine_principal][owner_delete][fail_closed]") {
    // A store that never opened — count_active_owned_by returns nullopt
    // (see engine_principal_store.cpp: `if (!open_) return std::nullopt`),
    // and the guard's contract (settings_routes.cpp) is explicit: "there is
    // no downgrade path from 'cannot verify' to 'safe to delete'".
    yuzu::server::pg::PgPool broken_pool{
        {.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    EnginePrincipalStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    SettingsOwnerDeleteHarness h(&broken_store);
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 409);

    CHECK(h.auth_mgr.get_user_role("bob").has_value()); // never deleted

    bool found_unreachable = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "user.delete" && a.detail == "engine_store_unreachable")
            found_unreachable = true;
    }
    CHECK(found_unreachable);
}

TEST_CASE("SettingsRoutes owner-delete guard: an unwired (null) store does not "
          "block deletion — feature simply not active",
          "[pg][settings][engine_principal][owner_delete]") {
    SettingsOwnerDeleteHarness h(/*engine_store=*/nullptr);
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// ═══════════════════════════════════════════════════════════════════════════
// T12 store-level sweep: auto-revoke at overlap_expires_at + surviving-
// rotation-state cleared.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ApiTokenStore::sweep_expired_rotations: auto-revokes an elapsed "
          "predecessor and clears the surviving successor's rotation state",
          "[pg][token][rotation][sweep]") {
    yuzu::test::ApiTokenStorePgShared tokens;
    EnginePrincipalStorePg engine_store;
    REQUIRE(engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:sweep")
               .has_value());
    tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store->get_for_auth(id).status; });

    const auto now = now_epoch();

    // #2964: settle the clock-guard bootstrap marker on an empty table
    // BEFORE minting anything (mirrors `AuditStore`'s own `anchor_guard` —
    // nothing eligible yet, so the pass short-circuits to `Anomaly::None`
    // without ever declining — `ApiTokenStorePgShared` TRUNCATEs
    // `rotation_retention_meta` alongside `api_tokens` between fixtures, so
    // every test on this shared bundle starts unanchored), and seed a
    // harmless HUMAN companion pair whose overlap window stays comfortably
    // in the future — without it, THIS test's own single in-flight pair
    // elapsing is indistinguishable from a genuine would-wipe clock jump
    // (the guard's own probe: "would this pass expire EVERY eligible row,
    // with none left surviving?").
    {
        auto anchor = tokens->sweep_expired_rotations(now);
        REQUIRE(anchor.outcome == ApiTokenStore::SweepOutcome::Ok);
        REQUIRE(anchor.revoked.empty());
        REQUIRE(tokens->create_token("survivor-pred", "sweep-test-survivor", now + 90 * 24 * 3600)
                   .has_value());
        const std::string survivor_pred_id =
            tokens->list_active_for_principal("sweep-test-survivor")[0].token_id;
        auto survivor_rotated = tokens->rotate_token(survivor_pred_id, 24 * 3600, now,
                                                      "sweep-test-survivor", "", "");
        REQUIRE(survivor_rotated.has_value());
        REQUIRE(tokens->validate_token(*survivor_rotated).has_value());
    }

    // rotate_engine_credential's 0-active arm rejects outright ("mint one
    // first") — the identity alone (engine_store->create above) is not a
    // credential. Mint the first one directly, the same shape the REST
    // mint route (POST .../credentials) produces.
    REQUIRE(tokens
               ->create_token("Vuln Sync", "engine:sweep", now + 90 * 24 * 3600, "", "readonly",
                              "engine")
               .has_value());
    auto rotated = tokens->rotate_engine_credential("engine:sweep", 24 * 3600, now, "admin");
    REQUIRE(rotated.has_value());

    auto active_before = tokens->list_active_for_principal("engine:sweep");
    REQUIRE(active_before.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : active_before) {
        if (t.supersedes_token_id.empty())
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);
    REQUIRE(predecessor->overlap_expires_at == now + 24 * 3600);
    const std::string predecessor_id = predecessor->token_id;
    const std::string successor_id = successor->token_id;
    const std::string rotation_group = successor->rotation_group;
    REQUIRE_FALSE(rotation_group.empty());

    // UP-5: the sweep now only auto-revokes when the successor has been
    // PRESENTED at least once (a never-used successor is left alone —
    // see the dedicated test below) — present it here so this test keeps
    // exercising the auto-revoke path it is named for.
    REQUIRE(tokens->validate_token(*rotated).has_value());

    // BEFORE the window elapses: a sweep finds nothing to do — idempotent,
    // no early revoke. `overlap_expires_at` (`now + 24h`, set at mint above)
    // is genuinely in the future relative to PostgreSQL's own clock, which
    // is what the sweep's eligibility decision reads (#2964) — no synthetic
    // future `now` argument can fast-forward past it.
    auto too_early = tokens->sweep_expired_rotations(now + 10);
    REQUIRE(too_early.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(too_early.revoked.empty());
    auto predecessor_before = tokens->get_token(predecessor_id).value();
    REQUIRE(predecessor_before.has_value());
    CHECK_FALSE(predecessor_before->revoked);

    // AFTER the window elapses: force the predecessor's overlap window into
    // the past relative to PostgreSQL's own clock (a real wall-clock wait
    // is not available to a test) — the predecessor is revoked...
    force_overlap_expires_at(tokens.dsn(), predecessor_id, pg_now(tokens.dsn()) - 1);
    const auto after_window = now + 24 * 3600 + 1;
    auto swept = tokens->sweep_expired_rotations(after_window);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(swept.revoked.size() == 1);
    CHECK(swept.revoked[0].token_id == predecessor_id);

    auto predecessor_row = tokens->get_token(predecessor_id).value();
    REQUIRE(predecessor_row.has_value());
    CHECK(predecessor_row->revoked);

    // ...and the SURVIVING successor's rotation state is cleared (design
    // doc §7: "revocation during overlap ... resolves the rotation state" —
    // a fresh rotation may now begin).
    auto successor_row = tokens->get_token(successor_id).value();
    REQUIRE(successor_row.has_value());
    CHECK_FALSE(successor_row->revoked);
    CHECK(successor_row->rotation_group.empty());
    CHECK(successor_row->supersedes_token_id.empty());
    CHECK(successor_row->overlap_expires_at == 0);

    // Exactly one active credential remains — the survivor.
    auto active_after = tokens->list_active_for_principal("engine:sweep");
    REQUIRE(active_after.size() == 1);
    CHECK(active_after[0].token_id == successor_id);

    // Idempotent: re-running the sweep at the same (or a later) instant
    // finds nothing left to revoke.
    auto second_sweep = tokens->sweep_expired_rotations(after_window + 100);
    CHECK(second_sweep.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(second_sweep.revoked.empty());

    (void)rotation_group;
}

TEST_CASE("ApiTokenStore::list_rotations_nearing_expiry_unused: flags an unused "
          "successor near window end, clears once used or resolved",
          "[pg][token][rotation][sweep]") {
    yuzu::test::ApiTokenStorePgShared tokens;
    EnginePrincipalStorePg engine_store;
    REQUIRE(
        engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:sweepwarn")
            .has_value());
    tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store->get_for_auth(id).status; });

    const auto now = now_epoch();
    // Mint the first credential directly (rotate_engine_credential's
    // 0-active arm rejects — "mint one first").
    REQUIRE(tokens
               ->create_token("Vuln Sync", "engine:sweepwarn", now + 90 * 24 * 3600, "",
                              "readonly", "engine")
               .has_value());
    auto rotated = tokens->rotate_engine_credential("engine:sweepwarn", 24 * 3600, now, "admin");
    REQUIRE(rotated.has_value());
    const std::string raw_successor = *rotated;

    // #2964 fix round finding 7: no longer takes a caller `now` (reads
    // PostgreSQL's own clock internally) — `now` above is real wall-clock
    // time, so this is equivalent.
    //
    // Far from the window end: not yet in the warn set.
    auto too_early = tokens->list_rotations_nearing_expiry_unused(3600);
    CHECK(too_early.pairs.empty());

    // Within the warn lead time, successor unused: flagged.
    auto nearing = tokens->list_rotations_nearing_expiry_unused(24 * 3600 + 10);
    REQUIRE(nearing.pairs.size() == 1);
    CHECK(nearing.pairs[0].predecessor.principal_id == "engine:sweepwarn");
    CHECK(nearing.pairs[0].successor.last_used_at == 0);

    // Once the successor is presented (validate_token bumps last_used_at),
    // it drops out of the "unused" set.
    auto validated = tokens->validate_token(raw_successor);
    REQUIRE(validated.has_value());
    auto nearing_after_use = tokens->list_rotations_nearing_expiry_unused(24 * 3600 + 10);
    CHECK(nearing_after_use.pairs.empty());
}
