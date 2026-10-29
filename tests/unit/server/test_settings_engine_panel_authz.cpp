/**
 * @file test_settings_engine_panel_authz.cpp
 * @brief [pg] Settings > Engine Principals panel (`GET /fragments/settings/engine-principals`)
 *        against its REST twin (`GET /api/v1/engine-principals`), both driven through the REAL
 *        AuthRoutes gates over a real RbacStore, EnginePrincipalStore, ApiTokenStore and
 *        AuditStore (#5882). The two surfaces must admit and refuse the same callers: the panel
 *        gates on EnginePrincipal:Read with the quiet probe, the twin with the loud
 *        `require_permission`, and server.cpp binds exactly these functions.
 *
 * Classification rule: a status of 401 or 403 is "refused at the gate"; anything else (200, or
 * the twin's 503 for a closed store) is "admitted at the gate". Raw statuses are NOT compared
 * for an admitted caller whose store is unavailable: the twin answers 503 before it reads the
 * session, the panel answers its in-page "store unavailable" note with 200 (htmx does not swap
 * a 4xx/5xx, so the degraded note must ride a 200). That is the one deliberate difference, and
 * it is pinned here for a human cookie only.
 *
 * Personas, each with RBAC off and on: an account administrator WITHOUT the grant; a
 * non-administrator WITH EnginePrincipal:Read (Viewer); an account administrator holding the
 * Administrator grant; a plain user; an administrator's MCP-tier bearer; an engine session; an
 * unauthenticated caller.
 *
 * Audit: a refused interactive cookie session leaves no auth.permission_required row on the
 * panel (it auto-loads) but does on the twin; a refused token keeps its row on both.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "engine_principal_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "settings_routes.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

// One database holding both the RBAC and the engine-principal schemas (the production stores
// share a pool). Cloned once per test from this template.
yuzu::test::PgTestTemplate engine_panel_tpl{"rbac_engine_panel_authz", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    if (!rbac.is_open())
        throw std::runtime_error("engine panel authz template: rbac store failed to migrate/seed");
    EnginePrincipalStore eps{pool};
    if (!eps.is_open())
        throw std::runtime_error("engine panel authz template: engine store failed to migrate");
}};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr const char* kFragment = "/fragments/settings/engine-principals";
constexpr const char* kTwin = "/api/v1/engine-principals";
constexpr const char* kSlug = "engine:epanel"; // seeded; its slug is the leak marker in the body

bool refused(int status) { return status == 401 || status == 403; }

struct Rig {
    yuzu::test::TempDir tmp{"yuzu_test_engine_panel_authz_"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    PgPool pool;
    RbacStore rbac;
    EnginePrincipalStore engine_store;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    SettingsRoutes settings;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink; // LAST: handlers capture `this`

    /// `wire_engine_store == false` models a deployment whose engine-principal store is absent.
    explicit Rig(const std::string& dsn, bool wire_engine_store = true)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, engine_store{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(engine_store.is_open());
        REQUIRE(audit_store.is_open());
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("root", "correct-horse-battery-staple", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("alice", "correct-horse-battery-staple", auth::Role::user));
        REQUIRE(engine_store.create("Panel Engine", "root", "j", "internal", "admin", kSlug)
                    .has_value());
        // The engine bearer resolves only while its referent is Active.
        api_tokens->set_engine_referent_check(
            [](const std::string&) { return EngineLookupStatus::Active; });

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);

        // Exactly the bindings server.cpp makes for the panel and for the twin.
        auto auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        auto admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_admin(q, r);
        };
        auto perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                              const std::string& o) { return ar->require_permission(q, r, t, o); };
        auto audit_fn = [this](const httplib::Request& q, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            (void)q;
            (void)action;
            (void)result;
            (void)target_type;
            (void)target_id;
            (void)detail;
            return true;
        };
        if (wire_engine_store)
            settings.set_engine_principal_store(&engine_store);
        // The quiet probe, as server.cpp binds it beside set_read_admin_fn.
        settings.set_read_perm_fn([this](const httplib::Request& q, httplib::Response& r,
                                         const std::string& t, const std::string& o) {
            return ar->probe_permission(q, r, t, o);
        });
        auto settings_audit = [](const httplib::Request&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&) {};
        settings.register_routes(sink, auth_fn, admin_fn, perm_fn, settings_audit, cfg, auth_mgr,
                                 auto_approve, api_tokens.get(), &*mgmt_bundle,
                                 /*tag_store=*/nullptr, /*update_registry=*/nullptr,
                                 /*runtime_config_store=*/nullptr, &audit_store,
                                 /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                                 []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);

        // The twin reads the store from this member (the trailing register_routes parameter is
        // a legacy slot it ignores).
        if (wire_engine_store)
            api.set_engine_principal_store(&engine_store);
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, &rbac,
                            /*mgmt_store=*/nullptr, api_tokens.get(),
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, &audit_store,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr);
    }

    std::unique_ptr<httplib::Response> cookie_get(const std::string& path,
                                                  const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }
    std::unique_ptr<httplib::Response> bearer_get(const std::string& path,
                                                  const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Authorization", "Bearer " + token}});
    }
    std::unique_ptr<httplib::Response> anon_get(const std::string& path) {
        return sink.dispatch("GET", path, {}, "application/json", {});
    }
    std::string cookie(const char* user, auth::Role role) {
        return auth_mgr.create_local_session_for_test(user, role, true);
    }
    std::string token(const char* name, const char* owner, const std::string& tier = "readonly",
                      const std::string& kind = "human") {
        auto raw = kind == "engine"
                       ? api_tokens->create_token(name, owner, now_epoch() + 3600, "", tier, kind)
                       : api_tokens->create_token(name, owner, now_epoch() + 3600, "", tier);
        REQUIRE(raw.has_value());
        return *raw;
    }
    void grant(const char* user, const char* role) {
        REQUIRE(rbac.assign_role({"user", user, role}).has_value());
    }
    void rbac_on() {
        rbac.set_rbac_enabled(true);
        REQUIRE(rbac.is_rbac_enabled()); // a vacuous pass here would be the RBAC-off case again
    }
    int denied_rows(const std::string& action) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.result == "denied" && (action.empty() || r.action == action))
                ++n;
        return n;
    }

    /// Drive both surfaces with the same credential and assert they agree with `expect_admit`.
    /// `how`: 'c' cookie, 'b' bearer, 'a' anonymous.
    void expect_same(char how, const std::string& cred, bool expect_admit) {
        auto call = [&](const char* path) {
            return how == 'c'   ? cookie_get(path, cred)
                   : how == 'b' ? bearer_get(path, cred)
                                : anon_get(path);
        };
        const auto frag = call(kFragment);
        const auto twin = call(kTwin);
        REQUIRE(frag);
        REQUIRE(twin);
        INFO("fragment=" << frag->status << " twin=" << twin->status << " twin body: " << twin->body);
        CHECK(refused(frag->status) == !expect_admit);
        CHECK(refused(twin->status) == !expect_admit);
        if (expect_admit) {
            CHECK(frag->status == 200);
            CHECK(twin->status == 200);
            CHECK_THAT(frag->body, ContainsSubstring(kSlug));
        } else {
            CHECK(frag->status == twin->status); // same gate, same 401/403
            CHECK_THAT(frag->body, !ContainsSubstring(kSlug)); // nothing of the roster leaks
        }
    }
};

} // namespace

// ---- RBAC off (the shipped default): the topology floor holds the read at administrator ------

TEST_CASE("engine panel authz, RBAC off: the account administrator is admitted by both surfaces",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    REQUIRE_FALSE(r.rbac.is_rbac_enabled());
    r.expect_same('c', r.cookie("root", auth::Role::admin), true);
}

TEST_CASE("engine panel authz, RBAC off: a plain user, even one holding Viewer, is refused by both",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    const auto c = r.cookie("alice", auth::Role::user);
    r.expect_same('c', c, false);
    r.grant("alice", "Viewer"); // inert while enforcement is off: the floor still wants administrator
    r.expect_same('c', c, false);
}

TEST_CASE("engine panel authz, RBAC off: an administrator's MCP-tier bearer is admitted by both "
          "(twin parity), a non-administrator's is not",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.expect_same('b', r.token("root-mcp", "root"), true);
    r.expect_same('b', r.token("alice-mcp", "alice"), false);
}

TEST_CASE("engine panel authz, RBAC off: an engine session and an unauthenticated caller are "
          "refused by both",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.expect_same('b', r.token("engine-bearer", kSlug, "readonly", "engine"), false);
    r.expect_same('a', "", false);
}

// ---- RBAC on: the grant decides, not the account role --------------------------------------

TEST_CASE("engine panel authz, RBAC on: an account administrator WITHOUT the grant is refused by "
          "both (the old admin_fn_ gate admitted it)",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.rbac_on();
    r.expect_same('c', r.cookie("root", auth::Role::admin), false);
}

TEST_CASE("engine panel authz, RBAC on: a non-administrator WITH EnginePrincipal:Read is admitted "
          "by both (the old admin_fn_ gate refused it)",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("alice", "Viewer"); // Viewer holds EnginePrincipal:Read
    r.rbac_on();
    r.expect_same('c', r.cookie("alice", auth::Role::user), true);
}

TEST_CASE("engine panel authz, RBAC on: an administrator holding the Administrator grant is "
          "admitted; a user holding nothing is refused",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("root", "Administrator");
    r.rbac_on();
    r.expect_same('c', r.cookie("root", auth::Role::admin), true);
    r.expect_same('c', r.cookie("alice", auth::Role::user), false);
}

TEST_CASE("engine panel authz, RBAC on: an MCP-tier bearer follows its creator's grant on both",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("root", "Administrator");
    r.rbac_on();
    r.expect_same('b', r.token("root-mcp", "root"), true);
    r.expect_same('b', r.token("alice-mcp", "alice"), false);
}

TEST_CASE("engine panel authz, RBAC on: an engine session and an unauthenticated caller are "
          "refused by both, whatever the grants",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("root", "Administrator");
    r.rbac_on();
    r.expect_same('b', r.token("engine-bearer", kSlug, "readonly", "engine"), false);
    r.expect_same('a', "", false);
}

// ---- store unavailable ----------------------------------------------------------------------

TEST_CASE("engine panel authz: with the engine-principal store absent an admitted caller gets the "
          "in-page note (200) where the twin answers 503; a refused caller is still refused",
          "[pg][settings][engine_principal][authz][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn(), /*wire_engine_store=*/false};
    const auto root = r.cookie("root", auth::Role::admin);

    const auto frag = r.cookie_get(kFragment, root);
    const auto twin = r.cookie_get(kTwin, root);
    REQUIRE(frag);
    REQUIRE(twin);
    CHECK(frag->status == 200); // htmx swaps only 2xx: the note must ride a 200
    CHECK_THAT(frag->body, ContainsSubstring("Engine Principals store unavailable"));
    CHECK(twin->status == 503);
    CHECK_FALSE(refused(frag->status)); // both are "admitted at the gate"
    CHECK_FALSE(refused(twin->status));

    const auto alice = r.cookie("alice", auth::Role::user);
    const auto frag_alice = r.cookie_get(kFragment, alice);
    const auto twin_alice = r.cookie_get(kTwin, alice);
    REQUIRE(frag_alice);
    REQUIRE(twin_alice);
    CHECK(frag_alice->status == 403);
    CHECK(twin_alice->status == 403);
    CHECK_THAT(frag_alice->body, !ContainsSubstring("Engine Principals store unavailable"));
}

// ---- audit evidence --------------------------------------------------------------------------

TEST_CASE("engine panel authz: a refused cookie session leaves no denial row on the auto-loading "
          "panel (the twin's loud gate does); a refused token keeps its row on both",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.rbac_on(); // the account administrator holds no grant

    const auto c = r.cookie("root", auth::Role::admin);
    const auto frag = r.cookie_get(kFragment, c);
    REQUIRE(frag);
    CHECK(frag->status == 403);
    CHECK(r.denied_rows("auth.permission_required") == 0); // nobody attempted anything

    const auto twin = r.cookie_get(kTwin, c);
    REQUIRE(twin);
    CHECK(twin->status == 403);
    CHECK(r.denied_rows("auth.permission_required") == 1); // an API call is an attempt

    const auto raw = r.token("root-token", "root");
    const auto frag_tok = r.bearer_get(kFragment, raw);
    REQUIRE(frag_tok);
    CHECK(frag_tok->status == 403);
    CHECK(r.denied_rows("auth.permission_required") == 2); // a token is on the record
    const auto twin_tok = r.bearer_get(kTwin, raw);
    REQUIRE(twin_tok);
    CHECK(twin_tok->status == 403);
    CHECK(r.denied_rows("auth.permission_required") == 3);
}

TEST_CASE("engine panel authz: an engine session refused at the gate leaves a denial row on the "
          "panel as on the twin",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    const auto raw = r.token("engine-bearer", kSlug, "readonly", "engine");
    const auto frag = r.bearer_get(kFragment, raw);
    REQUIRE(frag);
    CHECK(frag->status == 403);
    CHECK(r.denied_rows("") >= 1); // an engine caller is never given the quiet treatment
}

// ---- the page itself is unchanged -------------------------------------------------------------

TEST_CASE("engine panel authz: GET /settings itself stays admin-gated, so a Viewer reaches the "
          "panel URL but not the page",
          "[pg][settings][engine_principal][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("alice", "Viewer");
    r.rbac_on();
    const auto c = r.cookie("alice", auth::Role::user);

    const auto page = r.cookie_get("/settings", c);
    REQUIRE(page);
    CHECK(page->status == 302);
    CHECK(page->get_header_value("Location") == "/");
    const auto frag = r.cookie_get(kFragment, c);
    REQUIRE(frag);
    CHECK(frag->status == 200);
}
