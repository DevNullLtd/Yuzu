/**
 * test_engine_principal_integration.cpp — PR 4.2 (T8) cross-task integration
 * coverage for engine principals: the seams T1 (EnginePrincipalStore),
 * T2/T3 (ApiTokenStore referent check + AuthRoutes session synthesis), and
 * T4/T5 (RbacStore/AuthDB namespace reservation + collision scan) leave for
 * the integrator to wire and verify together. Unit coverage for each store
 * in isolation lives in test_engine_principal_store.cpp / test_api_token_store.cpp /
 * test_rbac_store.cpp / test_auth_db*.cpp — this file exercises them wired
 * together the way server.cpp actually wires them.
 *
 * PG-gated where PG stores are involved (ApiTokenStore, EnginePrincipalStore,
 * AuthDB, and — since the RbacStore Postgres port — RbacStore itself): skips
 * when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken
 * (test_helpers.hpp skip-vs-fail contract).
 */

#include "auth_routes.hpp"
#include "engine_principal_store.hpp"

#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — shared PG-backed ApiTokenStore helper
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "test_rbac_store_pg_helper.hpp" // RbacStorePg — RbacStore is PG-only (ADR-0041)

#include "test_auth_db_pg_helper.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <libpq-fe.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// ── shared PG-backed EnginePrincipalStore helper (mirrors test_api_token_pg_helper.hpp) ──

void setup_engine_principal_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("engine_principal (integration) template: store failed to migrate");
}

// Distinct name from test_engine_principal_store.cpp's own "engineprincipal"
// template — separate PgTestTemplate registry entries, no shared-state risk.
yuzu::test::PgTestTemplate engine_principal_integ_template{
    "engineprincipal_integ", &setup_engine_principal_store_pg_template};

// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test (the
// dominant Windows [pg]-shard cost, #2354 — see test_software_inventory_store
// .cpp's SwinvShared, the reference conversion). Built lazily; at testRunEnded
// the pool is drained and the clone dropped (keep_until_run_end). CARVE-OUT
// note: the T8 collision-scan TEST_CASE below deliberately stays on per-case
// AuthDbPg (NOT the shared sibling) — it needs a seeded and a clean AuthDB
// database to coexist in one Catch2 leaf.
struct EpIntegShared {
    yuzu::test::PostgresTestDb db{engine_principal_integ_template};
    std::optional<yuzu::server::pg::PgPool> pool;
    EpIntegShared() {
        INFO("[EpIntegShared] bundle status (blank == database came up OK): " << db.error());
        REQUIRE(db.available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
EpIntegShared& ep_integ_shared() {
    static EpIntegShared s;
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
            auto lease = ep_integ_shared().pool->acquire();
            REQUIRE(lease);
            auto trunc = yuzu::server::pg::exec_params(
                lease.get(),
                "TRUNCATE engine_principal_store.engine_principals RESTART IDENTITY CASCADE",
                std::vector<std::string>{});
            INFO("[EpIntegShared] reset: " << PQresultErrorMessage(trunc.get()));
            REQUIRE(trunc.status() == PGRES_COMMAND_OK);
        }
        store_ = std::make_unique<EnginePrincipalStore>(*ep_integ_shared().pool);
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

// ── file-local RbacStore fixture, mirroring test_rbac_store.cpp's RBAC_STORE
// macro exactly. Every TEST_CASE below that needs an RbacStore isolated from
// the shared EnginePrincipalStore/ApiTokenStore pools gets its own fresh
// clone via this template — those shared pools (ep_integ_shared() above,
// ApiTokenStorePgShared) are process-wide singletons with no per-test
// RBAC-table reset, so reusing them here would leak custom roles/assignments
// across TEST_CASEs.
void setup_rbac_store_pg_integ_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (integration) template: store failed to migrate/seed");
}

// Distinct name from test_rbac_store.cpp's own "rbacstore" template — separate
// PgTestTemplate registry entries, no shared-state risk (mirrors this file's
// own "engineprincipal_integ" vs "engineprincipal" precedent above).
yuzu::test::PgTestTemplate rbac_store_integ_template{"rbacstore_integ",
                                                      &setup_rbac_store_pg_integ_template};

// Seed a group row DIRECTLY (bypassing create_group's reserved-prefix guard)
// on an already-migrated pool, to reproduce a legacy artifact that predates
// the guard — copied from test_rbac_store.cpp's seed_group_raw.
void seed_group_raw(yuzu::server::pg::PgPool& pool, const std::string& name,
                    const std::string& description, const std::string& source,
                    const std::string& external_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
        lease.get(),
        "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
        "VALUES ($1, $2, $3, $4, 0)",
        std::vector<std::string>{name, description, source, external_id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

} // namespace

// Fresh-clone RbacStore fixture macro (file scope — macros aren't namespace-
// scoped). Must lead a block: expands to statements incl. the SKIP-if-no-DSN
// guard, mirroring test_rbac_store.cpp's RBAC_STORE macro.
#define RBAC_STORE(store_var)                                                                     \
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_fx_, rbac_store_integ_template);                                \
    yuzu::server::pg::PgPool rbac_pool_fx_{{.conninfo = rbac_db_fx_.dsn(), .size = 4}};            \
    REQUIRE(rbac_pool_fx_.valid());                                                                \
    RbacStore store_var{rbac_pool_fx_};                                                            \
    REQUIRE(store_var.is_open())

// ═══════════════════════════════════════════════════════════════════════════
// 1. Engine session synthesis (AuthRoutes + wired EnginePrincipalStore + an
//    engine ApiToken) — design doc §6.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine session synthesis: active principal + engine token -> engine session",
          "[pg][engine_principal][integration][auth_routes]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePgShared api_tokens;
    EnginePrincipalStorePg engine_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty

    // Register a human user too, for the regression case below.
    REQUIRE(auth_mgr.upsert_user("alice", "correct-horse-battery-staple", auth::Role::admin));

    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    ar.set_engine_principal_store(engine_store.get());

    // Wire the referent-integrity resolver the same way server.cpp does.
    api_tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store->get_for_auth(id).status; });

    REQUIRE(engine_store->create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                                 "engine:vuln")
               .has_value());

    auto raw = api_tokens->create_token("engine-token", "engine:vuln", now_epoch() + 3600, "",
                                        "readonly", "engine");
    REQUIRE(raw.has_value());
    auto engine_token = api_tokens->validate_token(*raw);
    REQUIRE(engine_token.has_value());
    REQUIRE(engine_token->principal_kind == "engine");

    SECTION("active engine principal -> a session with the design §6 field shape") {
        auto session = ar.synthesize_token_session(*engine_token);
        REQUIRE(session.has_value());
        CHECK(session->username == "engine:vuln");
        CHECK(session->auth_source == "engine_token");
        CHECK(session->role == auth::Role::user);
        CHECK(session->principal_kind == "engine");
    }

    SECTION("revoked engine principal -> no session (fail-closed, terminal)") {
        auto revoked = engine_store->revoke("engine:vuln");
        REQUIRE(revoked.has_value());
        REQUIRE(*revoked);
        auto session = ar.synthesize_token_session(*engine_token);
        CHECK_FALSE(session.has_value());
    }

    SECTION("unreachable engine-principal store -> no session (fail-closed, retryable)") {
        // Point AuthRoutes at a store that never opened — mirrors the
        // !engine_principal_store_->is_open() branch server.cpp guards
        // against at construction.
        yuzu::server::pg::PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        REQUIRE_FALSE(broken_pool.valid());
        EnginePrincipalStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        ar.set_engine_principal_store(&broken_store);
        auto session = ar.synthesize_token_session(*engine_token);
        CHECK_FALSE(session.has_value());
        ar.set_engine_principal_store(engine_store.get()); // restore for fixture teardown safety
    }

    SECTION("human token regression — unaffected by the engine branch") {
        auto human_raw = api_tokens->create_token("human-token", "alice");
        REQUIRE(human_raw.has_value());
        auto human_token = api_tokens->validate_token(*human_raw);
        REQUIRE(human_token.has_value());
        REQUIRE(human_token->principal_kind == "human");

        auto session = ar.synthesize_token_session(*human_token);
        REQUIRE(session.has_value());
        CHECK(session->username == "alice");
        CHECK(session->principal_kind == "human");
        CHECK(session->role == auth::Role::admin); // resolved fresh via get_user_role
        CHECK(session->auth_source == "api_token");
    }

    // F4 (Hermes pass-2 HIGH H3): an out-of-allowlist principal_kind (never
    // producible via create_token — this crafts the struct directly, the
    // way a NULL cell / a bypassed CHECK constraint / a corrupted row would
    // surface it) must fail closed, never silently fall through to the
    // human branch with full human-session attribution.
    SECTION("out-of-allowlist principal_kind (e.g. an empty/NULL-cell value) fails closed") {
        ApiToken bogus;
        bogus.token_id = "bogus-id";
        bogus.token_hash = "irrelevant";
        bogus.name = "bogus-token";
        bogus.principal_id = "alice";
        bogus.expires_at = now_epoch() + 3600;
        bogus.principal_kind = ""; // out-of-allowlist — never "human" nor "engine"

        auto session = ar.synthesize_token_session(bogus);
        CHECK_FALSE(session.has_value());
    }

    SECTION("out-of-allowlist principal_kind (garbage string) fails closed") {
        ApiToken bogus;
        bogus.token_id = "bogus-id-2";
        bogus.token_hash = "irrelevant";
        bogus.name = "bogus-token-2";
        bogus.principal_id = "engine:vuln";
        bogus.expires_at = now_epoch() + 3600;
        bogus.principal_kind = "robot"; // out-of-allowlist

        auto session = ar.synthesize_token_session(bogus);
        CHECK_FALSE(session.has_value());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1b. Engine STREAM RE-VALIDATION end-to-end (#2367) — a real engine token
//     through revalidate_stream -> engine_credential_state -> the cached
//     get_for_auth_revalidate, exercising the production seam rather than a
//     synthetic pump verdict. The store-level and pump-level halves are tested
//     in isolation elsewhere; this is the wiring in between, which nothing else
//     covered.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine stream re-validation end-to-end: first tick authoritative, next cached, "
          "revoke cuts it (#2367)",
          "[pg][engine_principal][integration][auth_routes][cache]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePgShared api_tokens;
    EnginePrincipalStorePg engine_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;

    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    ar.set_engine_principal_store(engine_store.get());
    api_tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store->get_for_auth(id).status; });

    REQUIRE(engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:reval")
               .has_value());
    auto raw = api_tokens->create_token("engine-token", "engine:reval", now_epoch() + 3600, "",
                                        "readonly", "engine");
    REQUIRE(raw.has_value());

    // The exact shape revalidate_stream reads: a Bearer credential and the
    // principal the stream was opened under.
    httplib::Request req;
    req.headers.emplace("Authorization", "Bearer " + *raw);
    const std::string expected = "engine:reval";

    using R = auth::CredentialCheck;

    // First tick: cold cache, so the engine gate reads through to Postgres.
    // An authoritative confirmation is plain kValid — NOT kValidStale. This is
    // what lets a stream pump reset its grace budget.
    CHECK(ar.revalidate_stream(req, expected) == R::kValid);

    // Later ticks within the TTL are served from the liveness cache, and the
    // caller MUST see kValidStale so the pump does not treat a cached answer as
    // a fresh confirmation. This is the seam quality-engineer flagged as
    // untested: kValidStale reaching a consumer through the real auth path
    // rather than a hand-written verdict lambda.
    for (int i = 0; i < 4; ++i)
        CHECK(ar.revalidate_stream(req, expected) == R::kValidStale);

    SECTION("a revoke cuts the stream on the next tick, cache notwithstanding") {
        auto revoked = engine_store->revoke("engine:reval");
        REQUIRE(revoked.has_value());
        REQUIRE(*revoked);
        // revoke() invalidated the cache synchronously, so the very next tick
        // reads through and sees the dead principal — not a stale cached Active.
        CHECK(ar.revalidate_stream(req, expected) == R::kRevoked);
    }

    SECTION("an expired entry reverts to an authoritative kValid") {
        // The outer body already warmed the entry under the real clock, so the
        // entry's expiry is stamped in real time. Pin a fake clock at ~now and
        // step it PAST that entry's TTL: the next tick must miss and read
        // through (kValid), and the tick after that is cached again
        // (kValidStale). Stepping past a real-stamped entry is what makes this
        // an expiry test rather than a still-live-hit test.
        auto fake_now = std::chrono::steady_clock::now();
        engine_store->set_clock_for_test([&] { return fake_now; });
        fake_now += std::chrono::seconds(30); // well past the ~12-15 s TTL
        CHECK(ar.revalidate_stream(req, expected) == R::kValid);      // expired -> read through
        CHECK(ar.revalidate_stream(req, expected) == R::kValidStale); // re-warmed under fake clock
        // fake_now is a SECTION-scoped local captured by-ref in the store's
        // clock_; restore the default before it dies so the borrowed reference
        // can never dangle (the store outlives this scope).
        engine_store->set_clock_for_test({});
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. RBAC engine resolution — design §4.1/§4.2.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("RBAC engine resolution: assignment, default-deny, and the admin bar",
          "[pg][engine_principal][integration][rbac]") {
    RBAC_STORE(store);

    REQUIRE(store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());

    SECTION("engine principal with an assignment resolves the granted permission") {
        REQUIRE(store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());
        CHECK(store.check_permission("engine:vuln", "Inventory", "Read"));
    }

    SECTION("a human user is unaffected by the engine assignment (regression)") {
        REQUIRE(store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());
        CHECK_FALSE(store.check_permission("alice", "Inventory", "Read"));
    }

    SECTION("an engine principal with no assignment default-denies") {
        CHECK_FALSE(store.check_permission("engine:noperm", "Inventory", "Read"));
    }

    SECTION("assigning the built-in Administrator role to an engine principal is rejected") {
        auto r = store.assign_role({"engine", "engine:admin-try", "Administrator"});
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_principal_roles("engine", "engine:admin-try").empty());
    }

    SECTION("assigning the literal 'admin' role name to an engine principal is rejected") {
        auto r = store.assign_role({"engine", "engine:admin-try2", "admin"});
        REQUIRE_FALSE(r.has_value());
    }

    // F1 (Hermes pass-1 H1, downgraded MEDIUM by architect): the generalized
    // "no built-in role, ever" bar. "Viewer" is a seeded is_system=1 role
    // that is NOT in the literal kEngineDisallowedRoles list — before F1 this
    // assignment would have SUCCEEDED (the manual-extend footgun the fix
    // closes). Any is_system role, not just admin/Administrator, must now be
    // rejected for an engine target.
    SECTION("assigning a built-in system role outside the literal admin bar (Viewer) is "
            "rejected") {
        auto r = store.assign_role({"engine", "engine:viewer-try", "Viewer"});
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_principal_roles("engine", "engine:viewer-try").empty());
    }

    // A CUSTOM (is_system=0) role stays assignable — F1 only bars built-ins;
    // the holistic "did we just grant something dangerous" catch is the
    // separate PR 4.3/4.4 auditor query, not this write-path bar.
    SECTION("assigning a custom (non-system) role to an engine principal is still allowed") {
        auto r = store.assign_role({"engine", "engine:custom-try", "EngineReader"});
        CHECK(r.has_value());
    }

    // F2 (Hermes pass-2 MEDIUM, worst finding): an 'engine:'-prefixed
    // principal_id must only ever be assigned under principal_type=="engine"
    // — otherwise a caller could mint a shadow ('user','engine:x',role) row
    // that collect_roles_locked's user arm would match, silently attributing
    // an engine identity's permissions to a "user" lookup.
    SECTION("assign_role rejects an 'engine:'-prefixed principal_id under principal_type=='user'") {
        auto r = store.assign_role({"user", "engine:vuln", "EngineReader"});
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_principal_roles("user", "engine:vuln").empty());
    }

    SECTION("assign_role rejects an 'engine:'-prefixed principal_id under principal_type=='group'") {
        auto r = store.assign_role({"group", "engine:vuln", "EngineReader"});
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("assign_role rejects an unrecognized principal_type") {
        auto r = store.assign_role({"robot", "some-id", "EngineReader"});
        REQUIRE_FALSE(r.has_value());
    }

    // G5 (governance hardening, UP-5): add_group_member has zero route callers
    // today, but the group-resolution arm of role lookup would hand an
    // `engine:`-named member any role the group holds — the same
    // shadow-attribution hazard F2 closes for direct role assignment.
    // Defense-in-depth per UP-11: reject the write at this surface too.
    SECTION("add_group_member rejects an 'engine:'-prefixed username") {
        REQUIRE(store.create_group({.name = "engineers", .description = "", .source = "local",
                                    .external_id = ""})
                   .has_value());
        auto r = store.add_group_member("engineers", "engine:vuln");
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_group_members("engineers").empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Namespace reservation + the T8 collision-scan preflight — design §3.3 /
//    decision log #3.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Engine namespace: local group create inside 'engine:' is rejected",
          "[pg][engine_principal][integration][rbac]") {
    RBAC_STORE(store);

    RbacGroup g{.name = "engine:x", .description = "", .source = "local", .external_id = ""};
    auto r = store.create_group(g);
    REQUIRE_FALSE(r.has_value());
    auto scan = store.find_local_groups_with_prefix("engine:");
    REQUIRE(scan.has_value());
    CHECK(scan->empty());
}

TEST_CASE("Engine namespace: the T8 startup collision-scan preflight finds pre-existing rows",
          "[pg][engine_principal][integration][collision_scan]") {
    // ── AuthDB side: seed a users row that predates the 'engine:' reservation.
    // `upsert_sso_identity` now rejects an 'engine:'-shaped principal outright
    // (the write surface itself guards the reserved namespace per design
    // §3.3 — a dedicated `[auth_db]` test proves the rejection), so a
    // pre-existing colliding row can no longer be produced through the API.
    // Simulate "a row that predates the reservation" the same way the RBAC
    // side does below, but over a SECOND libpq connection (AuthDB is now
    // Postgres-backed, ADR-0006) rather than a raw sqlite3 handle.
    yuzu::test::AuthDbPg auth_db;
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult res{PQexec(
            conn.get(),
            "INSERT INTO auth.users (username, password_hash, salt_hex, role, "
            "identity_source, external_iss, external_sub, display_name) "
            "VALUES ('engine:legacy', '', '', 'user', 'oidc', "
            "'https://issuer.example', 'sub-1', 'Legacy Engine-Named Row')")};
        REQUIRE(res.ok());
    }

    // ── RbacStore side: seed a local group row that predates the reservation.
    // create_group() now rejects this shape outright (previous TEST_CASE), so
    // simulate a pre-existing row the same way test_rbac_store.cpp's
    // seed_group_raw does: construct the store FIRST — on the SAME pool as
    // auth_db above, so RbacStore's own `rbac_store` schema coexists with
    // `auth.*` in one database, no second database needed — then insert the
    // row directly via a second lease on that pool.
    RbacStore rbac_store{auth_db.pool()};
    REQUIRE(rbac_store.is_open());
    seed_group_raw(auth_db.pool(), "engine:legacy-group", "", "local", "");

    SECTION("both scanners individually find the seeded collisions") {
        auto colliding_users = auth_db->find_reserved_prefix_users("engine:");
        REQUIRE(colliding_users.has_value());
        REQUIRE(colliding_users->size() == 1);
        CHECK((*colliding_users)[0] == "engine:legacy");

        auto colliding_groups = rbac_store.find_local_groups_with_prefix("engine:");
        REQUIRE(colliding_groups.has_value());
        REQUIRE(colliding_groups->size() == 1);
        CHECK((*colliding_groups)[0] == "engine:legacy-group");
    }

    SECTION("simulated server.cpp preflight: either non-empty scan means fail-closed") {
        auto colliding_users = auth_db->find_reserved_prefix_users("engine:");
        auto colliding_groups = rbac_store.find_local_groups_with_prefix("engine:");
        // A scan error (nullopt) on EITHER half must read as fail-closed (G3 + symmetric users half).
        bool would_refuse_to_start =
            !colliding_users.has_value() || !colliding_users->empty() ||
            !colliding_groups.has_value() || !colliding_groups->empty();
        CHECK(would_refuse_to_start);
    }

    SECTION("a clean database has no collisions and would NOT fail closed") {
        yuzu::test::AuthDbPg clean_auth_db;

        RbacStore clean_rbac{clean_auth_db.pool()};
        REQUIRE(clean_rbac.is_open());

        auto colliding_users = clean_auth_db->find_reserved_prefix_users("engine:");
        auto colliding_groups = clean_rbac.find_local_groups_with_prefix("engine:");
        bool would_refuse_to_start =
            !colliding_users.has_value() || !colliding_users->empty() ||
            !colliding_groups.has_value() || !colliding_groups->empty();
        CHECK_FALSE(would_refuse_to_start);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Governance hardening round — G1: ManagementGroupStore::assign_role must
//    reject principal_type=="engine" outright. `validate_assignment` (shared
//    with RbacStore::assign_role) is a name-based bar only; RbacStore layers
//    an additional `is_system` DB lookup on top that this store has no
//    equivalent for. PR 4.2 ships FLEET-WIDE engine grants only (design
//    §4.3) — scoped engine role assignment is a Phase-5 deliverable, so a
//    scoped engine grant must be rejected here rather than stored.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ManagementGroupStore::assign_role rejects principal_type=='engine' outright",
          "[pg][engine_principal][integration][management_group]") {
    static yuzu::test::PgTestTemplate mgmt_role_tpl{"enginemgmtrole", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ManagementGroupStore s{pool};
        if (!s.is_open())
            throw std::runtime_error("enginemgmtrole template: mgmt store failed to migrate");
    }};
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_role_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};
    REQUIRE(store.is_open());

    auto group_id = store.create_group({.name = "g1",
                                        .description = "",
                                        .parent_id = "",
                                        .membership_type = "static",
                                        .scope_expression = "",
                                        .created_by = "admin"});
    REQUIRE(group_id.has_value());

    SECTION("a scoped engine grant to a non-system role is rejected") {
        auto r = store.assign_role({*group_id, "engine", "engine:vuln", "EngineReader"});
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_group_roles(*group_id).empty());
    }

    // The specific hazard G1 closes: without the outright rejection, this
    // would fall through to the shared name-based `validate_assignment`
    // only, which does not know about `roles.is_system` and would let a
    // scoped grant to a built-in role land undetected.
    SECTION("a scoped engine grant to a built-in system role name is rejected the same way") {
        auto r = store.assign_role({*group_id, "engine", "engine:vuln", "Administrator"});
        REQUIRE_FALSE(r.has_value());
        CHECK(store.get_group_roles(*group_id).empty());
    }

    SECTION("user/group scoped assignment is unaffected (regression)") {
        auto r = store.assign_role({*group_id, "user", "alice", "SomeRole"});
        CHECK(r.has_value());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Referential integrity + locks — ApiTokenStore's engine block (design §6/
//    §7/§8), exercised against a real EnginePrincipalStore resolver.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ApiTokenStore engine block: referential integrity against a real EnginePrincipalStore",
          "[pg][engine_principal][integration][token]") {
    yuzu::test::ApiTokenStorePgShared api_tokens;
    EnginePrincipalStorePg engine_store;

    REQUIRE(engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    REQUIRE(engine_store->create("Retired Sync", "alice", "j", "internal", "admin",
                                 "engine:retired")
               .has_value());
    {
        auto revoked = engine_store->revoke("engine:retired");
        REQUIRE(revoked.has_value());
        REQUIRE(*revoked);
    }

    const auto now = now_epoch();

    SECTION("resolver unset -> every engine mint fails closed") {
        auto r = api_tokens->create_token("t", "engine:vuln", now + 3600, "", "readonly", "engine");
        REQUIRE_FALSE(r.has_value());
    }

    api_tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store->get_for_auth(id).status; });

    SECTION("Active referent -> mint succeeds") {
        auto r = api_tokens->create_token("t", "engine:vuln", now + 3600, "", "readonly", "engine");
        CHECK(r.has_value());
    }

    SECTION("MissingOrRevoked referent (revoked principal) -> mint rejected") {
        auto r =
            api_tokens->create_token("t", "engine:retired", now + 3600, "", "readonly", "engine");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("MissingOrRevoked referent (never existed) -> mint rejected") {
        auto r = api_tokens->create_token("t", "engine:no-such-principal", now + 3600, "",
                                          "readonly", "engine");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("mcp_tier != readonly -> rejected regardless of referent") {
        auto r1 = api_tokens->create_token("t", "engine:vuln", now + 3600, "", "operator",
                                           "engine");
        REQUIRE_FALSE(r1.has_value());
        auto r2 = api_tokens->create_token("t", "engine:vuln", now + 3600, "", "", "engine");
        REQUIRE_FALSE(r2.has_value());
    }

    SECTION("expires_at == 0 (perpetual) -> rejected") {
        auto r = api_tokens->create_token("t", "engine:vuln", 0, "", "readonly", "engine");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("expires_at beyond the 90-day ceiling -> rejected") {
        constexpr std::int64_t k91Days = 91 * 24 * 3600;
        auto r = api_tokens->create_token("t", "engine:vuln", now + k91Days, "", "readonly",
                                          "engine");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("expires_at just within the 90-day ceiling -> accepted") {
        constexpr std::int64_t k89Days = 89 * 24 * 3600;
        auto r = api_tokens->create_token("t", "engine:vuln", now + k89Days, "", "readonly",
                                          "engine");
        CHECK(r.has_value());
    }

    // F6 (Hermes pass-2 MEDIUM M3): engine principals are fleet-wide only
    // (§4.3) — a non-empty scope_service on an engine token is not a valid
    // combination and must be blocked at creation.
    SECTION("non-empty scope_service on an engine token -> rejected") {
        auto r = api_tokens->create_token("t", "engine:vuln", now + 3600, "some-service",
                                          "readonly", "engine");
        REQUIRE_FALSE(r.has_value());
    }
}

// G2 (governance hardening, security LOW / UP-1): the `engine:` namespace
// guarantee must be structural — a human-kind token can never carry an
// `engine:`-namespaced principal_id, regardless of whether the caller
// remembered to also pass principal_kind=="engine". No EnginePrincipalStore
// resolver is needed here: the guard runs before the principal_kind=="engine"
// block and applies unconditionally.
TEST_CASE("ApiTokenStore::create_token rejects an 'engine:'-namespaced principal_id under "
          "principal_kind=='human'",
          "[pg][engine_principal][integration][token]") {
    yuzu::test::ApiTokenStorePgShared api_tokens;
    const auto now = now_epoch();

    SECTION("default (unspecified) principal_kind is rejected") {
        auto r = api_tokens->create_token("t", "engine:vuln", now + 3600);
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("explicit principal_kind=='human' is rejected") {
        auto r = api_tokens->create_token("t", "engine:vuln", now + 3600, "", "", "human");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("a non-'engine:'-namespaced human token is unaffected (regression)") {
        auto r = api_tokens->create_token("t", "alice", now + 3600, "", "", "human");
        CHECK(r.has_value());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. External-review Blocker 1 — engine principals must be RBAC-only. Both
//    require_permission and require_scoped_permission resolve an engine
//    session immediately after the is_elevated short-circuit and BEFORE the
//    pre-RBAC legacy fallback (design §4.2 default-deny: "an engine
//    principal with no assignments can do nothing"). Without this gate, an
//    engine credential with zero RBAC assignments gets fleet-wide Read the
//    moment RBAC is off — the default deployment posture.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// Wires a real (PG-backed) engine principal + a mintable engine API token so
/// each RBAC-gate test below only has to construct the AuthRoutes/RbacStore
/// combination it wants to exercise.
struct EngineRbacGateFixture {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePgShared api_tokens;
    EnginePrincipalStorePg engine_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::string raw_token;

    EngineRbacGateFixture() {
        REQUIRE(engine_store->create("Vuln Sync", "alice", "cloud IAM parity", "internal",
                                     "admin", "engine:vuln")
                   .has_value());
        api_tokens->set_engine_referent_check(
            [&](const std::string& id) { return engine_store->get_for_auth(id).status; });
        auto raw = api_tokens->create_token("engine-token", "engine:vuln", now_epoch() + 3600, "",
                                            "readonly", "engine");
        REQUIRE(raw.has_value());
        raw_token = *raw;
    }

    httplib::Request request() const {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + raw_token);
        return req;
    }
};

} // namespace

TEST_CASE("require_permission — engine principal denied Read when RBAC is disabled "
          "(no legacy fallback, Blocker 1)",
          "[pg][engine_principal][integration][auth_routes][rbac]") {
    EngineRbacGateFixture fix;
    RBAC_STORE(rbac_store);
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    bool ok = ar.require_permission(req, res, "Inventory", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
}

// Belt-and-braces regression for Blocker 1's CLASS (retro action, #2202):
// the pre-RBAC legacy fallback admitted EVERY Read, so the carve-out must
// deny an engine session Read across the WHOLE spread of general securables
// when RBAC is off (the DEFAULT deployment posture) — not just Inventory.
// If any general read securable slips through here, an engine credential
// regains fleet-wide read the moment an operator leaves RBAC at its default.
TEST_CASE("require_permission — engine principal denied Read on EVERY general securable when "
          "RBAC is off (Blocker 1 class, default posture)",
          "[pg][engine_principal][integration][auth_routes][rbac]") {
    EngineRbacGateFixture fix;
    RBAC_STORE(rbac_store);
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                  /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    // A representative spread of the general (non-per-agent) read securables
    // that real REST read routes gate on. Every one must 403 for an engine
    // session with zero RBAC assignments and RBAC off.
    for (const std::string securable :
         {"Infrastructure", "Response", "ManagementGroup", "AuditLog", "Execution", "Schedule",
          "InstructionDefinition", "SoftwareDeployment", "GuaranteedState", "License", "Inventory"}) {
        auto req = fix.request();
        httplib::Response res;
        INFO("securable=" << securable);
        CHECK_FALSE(ar.require_permission(req, res, securable, "Read"));
        CHECK(res.status == 403);
    }
}

TEST_CASE("require_permission — engine principal denied (503) when the RBAC store is "
          "unavailable (Blocker 1)",
          "[pg][engine_principal][integration][auth_routes][rbac]") {
    EngineRbacGateFixture fix;

    // rbac_store_ == nullptr models "RBAC store unavailable" — auth_routes.cpp's
    // engine gate takes the identical `!rbac_store_ || !rbac_store_->is_open()`
    // branch (both conditions produce the same 503 response) for a store that
    // failed to open (e.g. a corrupt file). Constructing a genuinely-unopened
    // RbacStore needs a corrupted/locked SQLite fixture this suite has no
    // existing harness for; that half of the OR is reviewed by code instead —
    // see auth_routes.cpp's engine block in require_permission/
    // require_scoped_permission.
    AuthRoutes ar(fix.cfg, fix.auth_mgr, /*rbac_store=*/nullptr, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    bool ok = ar.require_permission(req, res, "Inventory", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 503);
}

TEST_CASE("require_permission — engine principal with an explicit RBAC assignment is "
          "allowed (Blocker 1)",
          "[pg][engine_principal][integration][auth_routes][rbac]") {
    EngineRbacGateFixture fix;
    RBAC_STORE(rbac_store);
    rbac_store.set_rbac_enabled(true);
    REQUIRE(rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    CHECK(ar.require_permission(req, res, "Inventory", "Read"));

    // Regression: an operation the assignment does NOT grant is still denied —
    // proves this isn't silently falling through to the fleet-wide legacy path.
    httplib::Response res2;
    CHECK_FALSE(ar.require_permission(req, res2, "Inventory", "Write"));
    CHECK(res2.status == 403);
}

TEST_CASE("require_scoped_permission — engine principal is RBAC-only too (mirrors "
          "require_permission, Blocker 1)",
          "[pg][engine_principal][integration][auth_routes][rbac]") {
    EngineRbacGateFixture fix;
    RBAC_STORE(rbac_store);

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();

    SECTION("RBAC disabled -> denied, no legacy fallback") {
        httplib::Response res;
        bool ok = ar.require_scoped_permission(req, res, "Inventory", "Read", "");
        CHECK_FALSE(ok);
        CHECK(res.status == 403);
    }

    SECTION("RBAC enabled + a global (fleet-wide) assignment -> allowed") {
        rbac_store.set_rbac_enabled(true);
        REQUIRE(rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
        REQUIRE(
            rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
        REQUIRE(rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());

        httplib::Response res;
        CHECK(ar.require_scoped_permission(req, res, "Inventory", "Read", ""));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6b. require_list_read (ADR-0017, #3038 fix) — engine principals must be
//     RBAC-only through this gate too, same posture as require_permission/
//     require_scoped_permission above (Blocker 1 class). authorize_list_read's
//     own legacy-open branch would otherwise hand an engine credential with
//     zero RBAC assignments a fleet-wide unfiltered read the moment RBAC is
//     off — require_list_read special-cases engine sessions BEFORE delegating
//     to authorize_list_read, exactly as require_permission does.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("require_list_read — engine principal denied Read when RBAC is disabled "
          "(no legacy-open, mirrors Blocker 1)",
          "[pg][engine_principal][integration][auth_routes][rbac][adr0017]") {
    EngineRbacGateFixture fix;
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    REQUIRE(rbac_store.is_open());
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto gate = ar.require_list_read(req, res, "GuaranteedState", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
}

TEST_CASE("require_list_read — engine principal denied (503) when the RBAC store is "
          "unavailable",
          "[pg][engine_principal][integration][auth_routes][rbac][adr0017]") {
    EngineRbacGateFixture fix;

    // rbac_store_ == nullptr models "RBAC store unavailable" — mirrors the
    // require_permission 503 test above; see its comment for why the
    // genuinely-unopened-store half of the OR is reviewed by code instead.
    AuthRoutes ar(fix.cfg, fix.auth_mgr, /*rbac_store=*/nullptr, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto gate = ar.require_list_read(req, res, "GuaranteedState", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 503);
}

TEST_CASE("require_list_read — engine principal with an explicit global RBAC assignment "
          "is admitted unfiltered (current engine grants are fleet-wide only)",
          "[pg][engine_principal][integration][auth_routes][rbac][adr0017]") {
    EngineRbacGateFixture fix;
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    REQUIRE(rbac_store.is_open());
    rbac_store.set_rbac_enabled(true);
    REQUIRE(rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        rbac_store.set_permission({"EngineReader", "GuaranteedState", "Read", "allow"}).has_value());
    REQUIRE(rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto gate = ar.require_list_read(req, res, "GuaranteedState", "Read");
    CHECK(gate.admitted);
    CHECK_FALSE(gate.scope.has_value()); // unfiltered — nullopt, not engaged-empty

    // Regression: an operation the assignment does NOT grant is still denied —
    // proves this isn't silently falling through to a legacy-open path.
    httplib::Response res2;
    auto gate2 = ar.require_list_read(req, res2, "GuaranteedState", "Write");
    CHECK_FALSE(gate2.admitted); // Write is denied structurally (Read-only gate)
    CHECK(res2.status == 403);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6c. require_fleet_read (#3290 Phase 2, D1) — this gate was Phase-0-only
//     (zero route callers, no caller-class branches) when 6a/6b above were
//     written; #3290 gave it the same engine special-case require_permission
//     and require_list_read already have, for the identical reason: its own
//     management-group axis (authorize_list_read) has a legacy-open branch
//     that would otherwise hand an engine credential with zero RBAC
//     assignments a fleet-wide unfiltered read the moment RBAC is off.
//     Mirrors 6b's three cases exactly, on require_fleet_read's
//     std::expected<ListAuthority, GateFailure> return shape instead of
//     ListReadGate's bool+scope shape.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("require_fleet_read — engine principal denied Read when RBAC is disabled "
          "(no legacy-open, mirrors require_list_read's 6b coverage)",
          "[pg][engine_principal][integration][auth_routes][rbac][service_scope]") {
    EngineRbacGateFixture fix;
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    REQUIRE(rbac_store.is_open());
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto result = ar.require_fleet_read(req, res, "GuaranteedState", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
}

TEST_CASE("require_fleet_read — engine principal denied (503) when the RBAC store is "
          "unavailable",
          "[pg][engine_principal][integration][auth_routes][rbac][service_scope]") {
    EngineRbacGateFixture fix;

    // rbac_store_ == nullptr models "RBAC store unavailable" — session
    // synthesis succeeds independently (engine_principal_store_, not
    // rbac_store_), isolating require_fleet_read's OWN null-store check
    // inside its engine branch.
    AuthRoutes ar(fix.cfg, fix.auth_mgr, /*rbac_store=*/nullptr, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto result = ar.require_fleet_read(req, res, "GuaranteedState", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Degraded);
    CHECK(res.status == 503);
}

TEST_CASE("require_fleet_read — engine principal with an explicit global RBAC assignment "
          "is admitted TOP (current engine grants are fleet-wide only, no per-tag "
          "scoping concept)",
          "[pg][engine_principal][integration][auth_routes][rbac][service_scope]") {
    EngineRbacGateFixture fix;
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    REQUIRE(rbac_store.is_open());
    rbac_store.set_rbac_enabled(true);
    REQUIRE(rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        rbac_store.set_permission({"EngineReader", "GuaranteedState", "Read", "allow"}).has_value());
    REQUIRE(rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());

    AuthRoutes ar(fix.cfg, fix.auth_mgr, &rbac_store, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    httplib::Response res;
    auto result = ar.require_fleet_read(req, res, "GuaranteedState", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered()); // TOP — never routed through meet(mgmt, service)

    // Regression: an operation the assignment does NOT grant is still denied —
    // proves this isn't silently falling through to a legacy-open path.
    httplib::Response res2;
    auto result2 = ar.require_fleet_read(req, res2, "GuaranteedState", "Write");
    REQUIRE_FALSE(result2.has_value());
    CHECK(result2.error() == authz::GateFailure::Forbidden); // Write denied structurally (Read-only gate)
    CHECK(res2.status == 403);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. External-review Blocker 3 — engine actions must audit as
//    principal_class=="engine", not the credential-presentation-only "agent"
//    that principal_class_of(req) infers for every bearer token.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("make_audit_event — engine session stamps principal_class=='engine' (Blocker 3)",
          "[pg][engine_principal][integration][auth_routes][audit]") {
    EngineRbacGateFixture fix;
    AuthRoutes ar(fix.cfg, fix.auth_mgr, /*rbac_store=*/nullptr, fix.api_tokens.get(),
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, fix.oidc_mu, fix.oidc_provider);
    ar.set_engine_principal_store(fix.engine_store.get());

    auto req = fix.request();
    auto event = ar.make_audit_event(req, "vuln.sync.query", "success");
    CHECK(event.principal == "engine:vuln");
    CHECK(event.principal_class == "engine");

    // Regression coverage for the other two principal_class values (bearer-token
    // "agent" and session-cookie "human") already lives in test_auth_routes.cpp's
    // make_audit_event suite — unaffected by this fix, since the re-stamp only
    // fires when the resolved session's principal_kind == "engine".
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Session::is_engine() — the two-predicate engine-session discriminator
//    (governance round: this was the one untested inline copy, at the
//    principal_class stash site in server.cpp's pre-routing chokepoint).
//    Plain struct, no store/fixture needed.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("Session::is_engine() — all four predicate-branch combinations",
          "[engine_principal][session]") {
    auth::Session s;

    SECTION("principal_kind==engine, auth_source==engine_token -> true (both predicates)") {
        s.principal_kind = "engine";
        s.auth_source = "engine_token";
        CHECK(s.is_engine());
    }

    SECTION("principal_kind==engine, auth_source==local -> true (kind alone)") {
        s.principal_kind = "engine";
        s.auth_source = "local";
        CHECK(s.is_engine());
    }

    SECTION("principal_kind==human, auth_source==engine_token -> true (source alone)") {
        s.principal_kind = "human";
        s.auth_source = "engine_token";
        CHECK(s.is_engine());
    }

    SECTION("principal_kind==human, auth_source==local -> false (neither)") {
        s.principal_kind = "human";
        s.auth_source = "local";
        CHECK_FALSE(s.is_engine());
    }

    SECTION("principal_kind==human, auth_source==password -> false (neither, non-default source)") {
        s.principal_kind = "human";
        s.auth_source = "password";
        CHECK_FALSE(s.is_engine());
    }
}
