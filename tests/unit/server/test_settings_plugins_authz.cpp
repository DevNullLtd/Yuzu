/**
 * @file test_settings_plugins_authz.cpp
 * @brief [pg] System > Plugins and updates: the three auto-loading read fragments driven through
 *        the REAL AuthRoutes gates (`probe_admin`, `has_permission`, `probe_list_read`) over a
 *        real RbacStore and AuditStore, with the REST list twin bound to the real
 *        `require_list_read` beside them. test_settings_plugins_page.cpp fakes the gates; this
 *        file proves the production wiring server.cpp binds writes and withholds the right
 *        audit evidence, and that fragment and twin agree for every principal.
 *
 * The property under test (docs/observability-conventions.md, "Denied operations MUST emit an
 * audit event ... the one deliberate exception: an interactive cookie session refused on an
 * auto-loading dashboard panel fragment; token and engine callers always do"): a refusal on a
 * fragment leaves NO row for a cookie session and a row for an API-token caller, at the admin
 * gate and at every inner permission check, while the navigation (`GET /settings/plugins`) keeps
 * the loud `require_admin`.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "key_provider.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_routes.hpp"
#include "plugin_config_store.hpp"
#include "rbac_store.hpp"
#include "settings_plugins_routes.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

yuzu::test::PgTestTemplate plugins_page_tpl{"rbacstore_pluginspage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (plugins page) template: store failed to migrate/seed");
}};

// Identical setup and key to test_plugin_config_routes.cpp: the registry's replay check needs it.
yuzu::test::PgTestTemplate plugins_authz_store_tpl{"pluginroutes", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("pluginroutes template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("pluginroutes template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("pluginroutes template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("pluginroutes template: kek_meta reset failed");
}};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct Rig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    yuzu::server::test::TestRouteSink sink; // LAST: handlers capture `this`

    explicit Rig(const std::string& dsn, PluginConfigStore* config_store = nullptr)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, audit_pool{{.conninfo = dsn, .size = 2}},
          audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(audit_store.is_open());
        REQUIRE(auth_mgr.upsert_user("root", "correct-horse-battery-staple", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("alice", "correct-horse-battery-staple", auth::Role::user));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);

        // Exactly the bindings server.cpp makes. Unless a test hands in a config store, the stores
        // behind the fragments stay unset: a fragment that is ADMITTED answers a degraded note,
        // one that is REFUSED answers a denied note, and the audit trail tells the two paths'
        // evidence apart.
        settings_plugins::Deps d;
        d.config_store = config_store;
        d.admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_admin(q, r);
        };
        d.probe_admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->probe_admin(q, r);
        };
        d.probe_perm_fn = [this](const httplib::Request& q, const std::string& t,
                                 const std::string& o) { return ar->has_permission(q, t, o); };
        d.probe_list_read_fn = [this](const httplib::Request& q, httplib::Response& r,
                                      const std::string& t, const std::string& o) {
            return ar->probe_list_read(q, r, t, o);
        };
        settings_plugins::register_settings_plugins_routes(sink, std::move(d));

        // The REST list twin, bound to the loud gate as server.cpp binds it. Its store is unset,
        // so an ADMITTED call answers 503 (store unavailable) and a REFUSED one 401/403: the
        // status alone says which side of the gate the principal landed on.
        plugin_config::Deps twin;
        twin.list_read_fn = [this](const httplib::Request& q, httplib::Response& r,
                                   const std::string& t, const std::string& o) {
            return ar->require_list_read(q, r, t, o);
        };
        twin.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        twin.perm_fn = [this](const httplib::Request& q, httplib::Response& r,
                              const std::string& t, const std::string& o) {
            return ar->require_permission(q, r, t, o);
        };
        twin.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        plugin_config::register_plugin_config_routes(sink, std::move(twin));
    }

    std::unique_ptr<httplib::Response> cookie_get(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }
    std::unique_ptr<httplib::Response> bearer_get(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Authorization", "Bearer " + token}});
    }
    std::string cookie(const char* user, auth::Role role) {
        return auth_mgr.create_local_session_for_test(user, role, true);
    }
    int rows_of(const std::string& action) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.action == action && r.result == "denied")
                ++n;
        return n;
    }
    /// Denied rows whose detail mentions `needle` (the stage a refusal happened at).
    int denied_rows_mentioning(const std::string& needle) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.result == "denied" && r.detail.find(needle) != std::string::npos)
                ++n;
        return n;
    }
    int denied_rows() {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.result == "denied")
                ++n;
        return n;
    }
};

constexpr const char* kFragments[] = {"/fragments/settings/plugin-config",
                                      "/fragments/settings/kill-switch?plugin=processes",
                                      "/fragments/settings/product-packs"};

bool is_denied_note(const httplib::Response& r) {
    return r.body.find("data-denied=\"1\"") != std::string::npos;
}

} // namespace

TEST_CASE("plugins authz: a cookie admin holding no grant is refused the fragments quietly",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled()); // a vacuous pass here would be the RBAC-off case again
    const auto c = r.cookie("root", auth::Role::admin);

    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.cookie_get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200); // a 403 would leave htmx on "Loading..."
        CHECK(is_denied_note(*res));
    }
    // The admin probe passed (an administrator account); each INNER permission refused and, for
    // an interactive cookie session, wrote nothing.
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("plugins authz: an API token holding no grant keeps a denial row for every refused fragment",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    // An administrator account's token: it passes the outer admin gate, then fails every inner
    // permission (the exact shape the review reproduced: no row for a token before this fix).
    const auto raw = r.api_tokens.get()->create_token("plugins-page-token", "root", now_epoch() + 3600);
    REQUIRE(raw.has_value());

    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.bearer_get(p, *raw);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(is_denied_note(*res));
    }
    CHECK(r.rows_of("auth.permission_required") == 3); // PluginConfig, PluginConfig, ProductPack
    CHECK(r.rows_of("auth.admin_required") == 0);
    // The plugin-config row is the LIST gate's own (require_list_read), the one its REST and MCP
    // twins write, not a bare-permission row.
    CHECK(r.denied_rows_mentioning("RBAC denied list read PluginConfig:Read") == 1);
}

TEST_CASE("plugins authz: a non-administrator token keeps the admin denial row; a cookie does not",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    const auto raw = r.api_tokens.get()->create_token("plugins-page-user", "alice", now_epoch() + 3600);
    REQUIRE(raw.has_value());
    const auto c = r.cookie("alice", auth::Role::user);

    // RBAC off (the shipped default), a plain user: refused at the admin probe.
    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.cookie_get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(is_denied_note(*res));
    }
    CHECK(r.denied_rows() == 0); // interactive cookie: nobody attempted anything

    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.bearer_get(p, *raw);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(is_denied_note(*res));
    }
    CHECK(r.rows_of("auth.admin_required") == 3); // a token is on the record
}

TEST_CASE("plugins authz: the page itself keeps the loud admin gate and redirects home",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    const auto c = r.cookie("alice", auth::Role::user);

    const auto page = r.cookie_get("/settings/plugins", c);
    REQUIRE(page);
    CHECK(page->status == 302);
    CHECK(page->get_header_value("Location") == "/");
    CHECK(r.rows_of("auth.admin_required") == 1); // a navigation to an admin page is an attempt

    const auto admin = r.cookie_get("/settings/plugins", r.cookie("root", auth::Role::admin));
    REQUIRE(admin);
    CHECK(admin->status == 200);
}

TEST_CASE("plugins authz: an administrator holding the grants is admitted past every gate",
          "[pg][plugins_page][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "root", "Administrator"}).has_value());
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    const auto c = r.cookie("root", auth::Role::admin);

    // Admitted: the stores behind the fragments are unset in this rig, so each answers a
    // degraded note (never an empty list) rather than a denied one.
    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.cookie_get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_FALSE(is_denied_note(*res));
        CHECK_THAT(res->body, ContainsSubstring("not an empty list"));
    }
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("plugins authz: the fragment and the REST list twin agree for an elevated session",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    // An ordinary user with no grant, holding an active JIT elevation: full admin for its window.
    const auto c = r.cookie("alice", auth::Role::user);

    // Not elevated: refused at the admin probe and by the twin's list gate.
    {
        const auto frag = r.cookie_get("/fragments/settings/plugin-config", c);
        REQUIRE(frag);
        CHECK(is_denied_note(*frag));
        const auto rest = r.cookie_get("/api/v1/plugin-config", c);
        REQUIRE(rest);
        CHECK(rest->status == 403);
    }
    // The REST twin is the loud gate: its refusal is on the record. The fragment's was not.
    const int rows_before = r.denied_rows();
    CHECK(rows_before == 1);
    CHECK(r.denied_rows_mentioning("RBAC denied list read PluginConfig:Read") == 1);

    REQUIRE(r.auth_mgr.elevate_session(c, std::chrono::seconds{300}).has_value());

    // Elevated: `require_list_read` admits unfiltered before any grant is consulted, and both
    // surfaces use it, so neither refuses: the page is never wider or narrower than the API.
    for (const char* p : kFragments) {
        INFO(p);
        const auto res = r.cookie_get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_FALSE(is_denied_note(*res));
    }
    const auto rest = r.cookie_get("/api/v1/plugin-config", c);
    REQUIRE(rest);
    CHECK(rest->status == 503); // admitted; this rig's store is unset
    CHECK(r.denied_rows() == rows_before); // an admitted request writes no denial
}

TEST_CASE("plugins authz: a token that holds the list grant but not Infrastructure:Read keeps the "
          "secondary denial row; a cookie does not",
          "[pg][plugins_page][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, plugins_page_tpl);
    YUZU_REQUIRE_PG_DB_TPL(cfg_db_, plugins_authz_store_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider{keys.path};
    pg::SecretCodec codec{provider};
    PgPool cfg_pool{{.conninfo = cfg_db_.dsn(), .size = 2}};
    PluginConfigStore config_store{cfg_pool, codec};
    REQUIRE(config_store.is_open());
    {
        pg::PgConn conn{PQconnectdb(cfg_db_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(codec.init(conn.get()).has_value());
    }

    Rig r{db_.dsn(), &config_store};
    // PluginConfig:Read (global) and nothing else: the kill-switch lookup is admitted, the
    // fleet-observed catalogue (Infrastructure:Read) is not drawn, and that probe's refusal is
    // an inner permission denial.
    REQUIRE(r.rbac.create_role({"PluginReader", "reads plugin config only", false, 0}).has_value());
    REQUIRE(r.rbac.set_permission({"PluginReader", "PluginConfig", "Read", "allow"}).has_value());
    REQUIRE(r.rbac.assign_role({"user", "root", "PluginReader"}).has_value());
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());

    const auto c = r.cookie("root", auth::Role::admin);
    const auto cookie_res = r.cookie_get("/fragments/settings/kill-switch", c);
    REQUIRE(cookie_res);
    CHECK(cookie_res->status == 200);
    CHECK_FALSE(is_denied_note(*cookie_res)); // the lookup itself is admitted
    CHECK(r.denied_rows() == 0);              // and the catalogue refusal left nothing behind

    const auto raw = r.api_tokens.get()->create_token("plugins-page-reader", "root", now_epoch() + 3600);
    REQUIRE(raw.has_value());
    const auto token_res = r.bearer_get("/fragments/settings/kill-switch", *raw);
    REQUIRE(token_res);
    CHECK(token_res->status == 200);
    CHECK_FALSE(is_denied_note(*token_res));
    CHECK(r.rows_of("auth.permission_required") == 1);
    CHECK(r.denied_rows_mentioning("Infrastructure:Read") == 1);
}
