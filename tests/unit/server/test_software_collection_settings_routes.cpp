/**
 * test_software_collection_settings_routes.cpp - SoftwareCollectionSettingsRoutes.
 *
 * Two layers:
 *   - unwired-dependency shapes (no Postgres): every route answers a 503 A4 envelope;
 *   - [pg][routes] over a REAL AuthRoutes gate (RbacStorePg, ManagementGroupStorePg, ApiTokenStorePg)
 *     and the real settings and plugin-config stores: the global grant, the group-scoped
 *     ITServiceOwner fallback (parent grant reaches the child, never a sibling or the root), the
 *     503-versus-403 split on an unavailable RBAC read, the MCP-tier and service-scoped token
 *     exclusions, audit ordering, 409 bodies, and the host route over the pure resolver.
 */

#include "auth_routes.hpp"
#include "api_token_store.hpp"
#include "key_provider.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"
#include "rbac_store.hpp"
#include "software_collection_settings_routes.hpp"
#include "software_collection_settings_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace cs = yuzu::server::collection_settings;
using json = nlohmann::json;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate routes_settings_tpl{"collectionsettingsroutes", [](const std::string& dsn) {
                                                   PgPool pool{{.conninfo = dsn, .size = 1}};
                                                   SoftwareCollectionSettingsStore store{pool};
                                                   if (!store.is_open())
                                                       throw std::runtime_error(
                                                           "collection settings routes template: "
                                                           "store failed to migrate");
                                               }};

// The kill-switch table needs the plugin-config schema; the codec is never initialised (no secret
// is read or written here).
yuzu::test::PgTestTemplate routes_plugincfg_tpl{"plugincfgcs", [](const std::string& dsn) {
                                                    yuzu::test::TempDir keys{"yuzu_test_keys_"};
                                                    FileKeyProvider provider(keys.path);
                                                    pg::SecretCodec codec(provider);
                                                    PgPool pool{{.conninfo = dsn, .size = 1}};
                                                    PluginConfigStore store{pool, codec};
                                                    if (!store.is_open())
                                                        throw std::runtime_error(
                                                            "plugincfgcs template: store failed to "
                                                            "migrate");
                                                }};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string put_body(int interval = 86400, int priority = 0,
                     const std::string& expected = "none", const std::string& tz = "",
                     const std::string& window = "null") {
    return R"({"interval_s":)" + std::to_string(interval) + R"(,"window":)" + window +
           R"(,"timezone":")" + tz + R"(","priority":)" + std::to_string(priority) +
           R"(,"expected_version":")" + expected +
           R"(","plugins":{"installed_apps":true,"middleware":true,"msi_packages":true,)"
           R"("pkg_inventory":true,"runtimes":true,"windows_optional_features":true}})";
}

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQerrorMessage(conn.get()));
    REQUIRE(r.ok());
}

// A table moved aside and back: the read it serves genuinely fails.
struct TableFault {
    std::string dsn, qualified;
    bool armed{false};
    TableFault(std::string d, std::string q) : dsn(std::move(d)), qualified(std::move(q)) {}
    void arm() {
        const auto dot = qualified.find('.');
        exec_sql(dsn, "ALTER TABLE " + qualified + " RENAME TO " + qualified.substr(dot + 1) +
                          "_gone");
        armed = true;
    }
    void repair() noexcept {
        if (!armed)
            return;
        try {
            PgConn conn{PQconnectdb(dsn.c_str())};
            if (PQstatus(conn.get()) == CONNECTION_OK) {
                const auto dot = qualified.find('.');
                const std::string sql = "ALTER TABLE " + qualified + "_gone RENAME TO " +
                                        qualified.substr(dot + 1);
                PgResult r{PQexec(conn.get(), sql.c_str())};
                if (r.ok())
                    armed = false;
            }
        } catch (...) {
        }
    }
    ~TableFault() { repair(); }
};

// Real authority stack + both real stores, routes registered on an in-process sink.
struct RoutesRig {
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac = *rbac_bundle;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    yuzu::test::PostgresTestDb settings_db{routes_settings_tpl};
    std::optional<PgPool> settings_pool;
    std::unique_ptr<SoftwareCollectionSettingsStore> store;
    yuzu::test::PostgresTestDb plugin_db{routes_plugincfg_tpl};
    std::optional<PgPool> plugin_pool;
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    std::unique_ptr<FileKeyProvider> provider;
    std::unique_ptr<pg::SecretCodec> codec;
    std::unique_ptr<PluginConfigStore> plugins;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    std::vector<AuditRow> audit;
    bool audit_ok{true};
    SoftwareCollectionSettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::string root{ManagementGroupStore::kRootGroupId};
    std::string group_p, group_c, group_s; // P top-level, C child of P, S top-level sibling

    RoutesRig() {
        REQUIRE(rbac.is_open());
        REQUIRE(settings_db.available());
        settings_pool.emplace(PgPool::Options{.conninfo = settings_db.dsn(), .size = 2});
        store = std::make_unique<SoftwareCollectionSettingsStore>(*settings_pool);
        REQUIRE(store->is_open());
        REQUIRE(plugin_db.available());
        plugin_pool.emplace(PgPool::Options{.conninfo = plugin_db.dsn(), .size = 2});
        provider = std::make_unique<FileKeyProvider>(keys.path);
        codec = std::make_unique<pg::SecretCodec>(*provider);
        plugins = std::make_unique<PluginConfigStore>(*plugin_pool, *codec);
        REQUIRE(plugins->is_open());
        auth_mgr.set_metrics_registry(&metrics);
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                          /*audit_store=*/nullptr, &mgmt, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
        rbac.set_rbac_enabled(true);

        const auto make_group = [&](const std::string& name, const std::string& parent) {
            ManagementGroup g;
            g.name = name;
            g.parent_id = parent;
            g.membership_type = "static";
            auto id = mgmt.create_group(g);
            REQUIRE(id.has_value());
            return *id;
        };
        // The server creates the root group at boot; the rig does the same.
        ManagementGroup root_group;
        root_group.id = ManagementGroupStore::kRootGroupId;
        root_group.name = "All Devices";
        root_group.membership_type = "dynamic";
        root_group.scope_expression = "*";
        REQUIRE(mgmt.create_group(root_group).has_value());
        group_p = make_group("P", "");
        group_c = make_group("C", group_p);
        group_s = make_group("S", "");

        register_routes([this](const httplib::Request& req, httplib::Response& res,
                               const std::string& type, const std::string& op) {
            return ar->probe_permission_unavailable_aware(req, res, type, op);
        });
    }

    void register_routes(SoftwareCollectionSettingsRoutes::ProbePermFn probe) {
        routes.register_routes(
            sink,
            SoftwareCollectionSettingsRoutes::Deps{
                .auth_fn = [this](const httplib::Request& req,
                                  httplib::Response& res) { return ar->require_auth(req, res); },
                .perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                                  const std::string& t,
                                  const std::string& o) { return ar->require_permission(req, res, t, o); },
                .probe_perm_fn = std::move(probe),
                .scoped_perm_fn =
                    [this](const httplib::Request& req, httplib::Response& res, const std::string& t,
                           const std::string& o, const std::string& agent) {
                        return ar->require_scoped_permission(req, res, t, o, agent);
                    },
                .audit_fn = [this](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& tt,
                                   const std::string& tid, const std::string& detail) {
                    if (!audit_ok)
                        return false;
                    audit.push_back({action, result, tt, tid, detail});
                    return true;
                },
                .store = store.get(),
                .mgmt_store = &mgmt,
                .plugin_config_store = plugins.get(),
            });
    }

    std::unordered_map<std::string, std::string> cookie(const std::string& user,
                                                         auth::Role role = auth::Role::user) {
        REQUIRE(auth_mgr.upsert_user(user, "password1234", role));
        const auto token = auth_mgr.create_local_session_for_test(user, role, true);
        return {{"Cookie", "yuzu_session=" + token}};
    }
    std::unordered_map<std::string, std::string> bearer(const std::string& raw) {
        return {{"Authorization", "Bearer " + raw}};
    }

    std::unordered_map<std::string, std::string> global_admin() {
        auto h = cookie("boss", auth::Role::user);
        REQUIRE(rbac.assign_role({"user", "boss", "Administrator"}).has_value());
        return h;
    }
    // A user whose only authority is an ITServiceOwner row on `group`.
    std::unordered_map<std::string, std::string> group_owner(const std::string& user,
                                                              const std::string& group) {
        auto h = cookie(user);
        REQUIRE(mgmt.assign_role({group, "user", user, "ITServiceOwner"}).has_value());
        return h;
    }

    std::unique_ptr<httplib::Response>
    call(const std::string& method, const std::string& path,
         const std::unordered_map<std::string, std::string>& headers, const std::string& body = {}) {
        auto res = sink.dispatch(method, path, body, "application/json", headers);
        REQUIRE(res != nullptr);
        return res;
    }
    std::string doc_path(const std::string& group) {
        return "/api/v1/inventory/software/collection-settings/" + group;
    }
    json parse(const httplib::Response& res) { return json::parse(res.body); }
    std::size_t audit_count(const std::string& result) const {
        std::size_t n = 0;
        for (const auto& a : audit)
            n += a.result == result ? 1 : 0;
        return n;
    }
};

} // namespace

// -- no Postgres: unwired shapes ------------------------------------------------------------

TEST_CASE("collection settings routes: a missing store, mgmt store or plugin store answers 503",
          "[collection_settings][routes]") {
    yuzu::server::test::TestRouteSink sink;
    SoftwareCollectionSettingsRoutes routes;
    const auto allow = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
    routes.register_routes(
        sink, SoftwareCollectionSettingsRoutes::Deps{
                  .auth_fn = [](const httplib::Request&,
                                httplib::Response&) -> std::optional<auth::Session> {
                      auth::Session s;
                      s.username = "tester";
                      return s;
                  },
                  .perm_fn = allow,
                  .probe_perm_fn = allow,
                  .scoped_perm_fn = [](const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&,
                                       const std::string&) { return true; },
                  .audit_fn = {},
              });
    const std::string gid = "aaaa11112222";
    for (const auto& [method, path] :
         std::vector<std::pair<std::string, std::string>>{
             {"GET", "/api/v1/inventory/software/collection-settings"},
             {"GET", "/api/v1/inventory/software/collection-settings/" + gid},
             {"PUT", "/api/v1/inventory/software/collection-settings/" + gid},
             {"GET", "/api/v1/inventory/software/hosts/agent-1/collection-settings"}}) {
        INFO(method << " " << path);
        auto res = sink.dispatch(method, path, put_body());
        REQUIRE(res != nullptr);
        CHECK(res->status == 503);
        const auto body = json::parse(res->body);
        CHECK(body["error"]["code"] == 503);
        CHECK(body["meta"]["api_version"] == "v1");
    }
}

TEST_CASE("collection settings routes: an unwired gate fails closed", "[collection_settings][routes]") {
    yuzu::server::test::TestRouteSink sink;
    SoftwareCollectionSettingsRoutes routes;
    routes.register_routes(sink, SoftwareCollectionSettingsRoutes::Deps{});
    auto res = sink.dispatch("GET", "/api/v1/inventory/software/collection-settings");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}

TEST_CASE("collection settings routes: the registration order beats the generic inventory GET",
          "[collection_settings][routes]") {
    // The sink matches in registration order like httplib: the bare list path is a 2-segment path
    // below /inventory/software/ and the generic GET /api/v1/inventory/{a}/{b} would take it, so
    // the wiring must register this class first (pinned lexically for server.cpp).
    yuzu::server::test::TestRouteSink sink;
    bool generic_hit = false;
    SoftwareCollectionSettingsRoutes routes;
    routes.register_routes(sink, SoftwareCollectionSettingsRoutes::Deps{});
    sink.Get(R"(/api/v1/inventory/([^/]+)/([^/]+))",
             [&](const httplib::Request&, httplib::Response&) { generic_hit = true; });
    auto res = sink.dispatch("GET", "/api/v1/inventory/software/collection-settings");
    REQUIRE(res != nullptr);
    CHECK_FALSE(generic_hit);
}

// -- [pg][routes]: the real gate -----------------------------------------------------------

TEST_CASE("collection settings PUT: body validation answers 400 and writes nothing",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto boss = rig.global_admin();
    const auto path = rig.doc_path(rig.group_p);
    const auto expect_400 = [&](const std::string& body) {
        auto res = rig.call("PUT", path, boss, body);
        INFO(body);
        CHECK(res->status == 400);
        CHECK_FALSE(rig.store->get(rig.group_p)->has_value());
    };
    SECTION("an unknown top-level key") {
        auto b = json::parse(put_body());
        b["surprise"] = 1;
        expect_400(b.dump());
    }
    SECTION("an unknown plugin key") {
        auto b = json::parse(put_body());
        b["plugins"]["evidence"] = true;
        expect_400(b.dump());
    }
    SECTION("a hostile key name is neutralised in the audit detail") {
        auto top = json::parse(put_body());
        top["x\ny=1 z"] = 1;
        expect_400(top.dump());
        auto plug = json::parse(put_body());
        plug["plugins"]["evil\r\nkey=1"] = true;
        expect_400(plug.dump());
        REQUIRE(rig.audit.size() == 2);
        for (const auto& a : rig.audit) {
            CHECK(a.result == "denied");
            CHECK(a.detail.find_first_of("\r\n") == std::string::npos);
            CHECK(a.detail.find("=1") == std::string::npos);
        }
    }
    SECTION("registered apps off") {
        auto b = json::parse(put_body());
        b["plugins"]["installed_apps"] = false;
        expect_400(b.dump());
    }
    SECTION("a missing plugin key") {
        auto b = json::parse(put_body());
        b["plugins"].erase("runtimes");
        expect_400(b.dump());
    }
    SECTION("a bad expected_version") {
        expect_400(put_body(86400, 0, "not-a-version"));
    }
    SECTION("a window on a 25 h interval") {
        expect_400(put_body(90000, 0, "none", "", R"({"start_min":60,"end_min":300})"));
    }
    SECTION("not an object, and invalid JSON") {
        expect_400("[1,2]");
        expect_400("{nope");
    }
    SECTION("the root group with a priority") {
        auto res = rig.call("PUT", rig.doc_path(rig.root), boss, put_body(86400, 1));
        CHECK(res->status == 400);
        CHECK_FALSE(rig.store->get(rig.root)->has_value());
    }
    SECTION("an unknown zone is a 400 from the store") {
        auto res = rig.call("PUT", path, boss, put_body(86400, 0, "none", "Mars/Olympus"));
        CHECK(res->status == 400);
        CHECK_FALSE(rig.store->get(rig.group_p)->has_value());
    }
    SECTION("a group that does not exist is a 404") {
        auto res = rig.call("PUT", rig.doc_path("ffffffffffff"), boss, put_body());
        CHECK(res->status == 404);
    }
}

TEST_CASE("collection settings PUT: audit ordering, success body, conflict body",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto boss = rig.global_admin();
    const auto path = rig.doc_path(rig.group_p);

    SECTION("a refused requested row writes nothing and answers 503") {
        rig.audit_ok = false;
        auto res = rig.call("PUT", path, boss, put_body());
        CHECK(res->status == 503);
        CHECK(res->has_header("Sec-Audit-Failed"));
        CHECK_FALSE(rig.store->get(rig.group_p)->has_value());
    }
    SECTION("create, replace, stale replace") {
        auto created = rig.call("PUT", path, boss, put_body(7200));
        REQUIRE(created->status == 200);
        const auto c = rig.parse(*created);
        const std::string v1 = c["data"]["version"];
        CHECK(c["data"]["previous_version"].is_null());
        CHECK(c["data"]["interval_s"] == 7200);
        // requested precedes success, both one line, before=none on create.
        REQUIRE(rig.audit.size() == 2);
        CHECK(rig.audit[0].action == "software_estate.collection_settings.update");
        CHECK(rig.audit[0].result == "requested");
        CHECK(rig.audit[0].target_type == "ManagementGroup");
        CHECK(rig.audit[0].target_id == rig.group_p);
        CHECK(rig.audit[0].detail.rfind("before=none after=", 0) == 0);
        CHECK(rig.audit[1].result == "success");
        for (const auto& a : rig.audit)
            CHECK(a.detail.find('\n') == std::string::npos);
        CHECK(rig.audit[1].detail.find("version=" + v1) != std::string::npos);

        auto replaced = rig.call("PUT", path, boss, put_body(10800, 0, v1));
        REQUIRE(replaced->status == 200);
        const auto r = rig.parse(*replaced);
        CHECK(r["data"]["previous_version"] == v1);
        // The success row's prior document is built from the row the transaction replaced.
        CHECK(rig.audit.back().detail.find("before=v1;interval=7200;") != std::string::npos);

        rig.audit.clear();
        auto stale = rig.call("PUT", path, boss, put_body(14400, 0, v1));
        CHECK(stale->status == 409);
        const auto s = rig.parse(*stale);
        CHECK(s["error"]["current"]["interval_s"] == 10800);
        CHECK(s["error"]["current"]["version"] == r["data"]["version"]);
        REQUIRE(rig.audit.size() == 2);
        CHECK(rig.audit[1].result == "failure");
        CHECK(rig.audit[1].detail == "version mismatch");
        // A second create-only is also a conflict that names the stored row.
        auto again = rig.call("PUT", path, boss, put_body(14400));
        CHECK(again->status == 409);
        CHECK(rig.parse(*again)["error"]["current"]["interval_s"] == 10800);
    }
}

TEST_CASE("collection settings PUT: a COMMIT that does not confirm is a 503 outcome unknown",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto boss = rig.global_admin();
    // A deferred constraint trigger raises at COMMIT: every statement of the write ran and the
    // COMMIT fails. The fault lives in the test database; the store code is unchanged.
    exec_sql(rig.settings_db.dsn(),
             "CREATE FUNCTION software_collection_settings_store.fail_at_commit() RETURNS trigger "
             "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit fault'; END $$; "
             "CREATE CONSTRAINT TRIGGER fail_at_commit AFTER INSERT OR UPDATE ON "
             "software_collection_settings_store.settings DEFERRABLE INITIALLY DEFERRED "
             "FOR EACH ROW EXECUTE FUNCTION software_collection_settings_store.fail_at_commit()");
    auto res = rig.call("PUT", rig.doc_path(rig.group_p), boss, put_body(7200));
    CHECK(res->status == 503);
    CHECK(res->body.find("outcome unknown") != std::string::npos);
    REQUIRE(rig.audit.size() == 2);
    CHECK(rig.audit[0].result == "requested");
    CHECK(rig.audit[1].result == "failure");
    CHECK(rig.audit[1].detail == "outcome unknown; the write may have landed; verify with GET");
    // This COMMIT failed outright, so the GET the answer asks for finds nothing.
    CHECK_FALSE(rig.store->get(rig.group_p)->has_value());
}

TEST_CASE("collection settings PUT: an engine session never gets the group fallback",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    rig.group_owner("gowner", rig.group_p);
    bool engine = false;
    yuzu::server::test::TestRouteSink sink;
    SoftwareCollectionSettingsRoutes routes;
    routes.register_routes(
        sink,
        SoftwareCollectionSettingsRoutes::Deps{
            .auth_fn = [&](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
                auth::Session s;
                s.username = "gowner";
                if (engine)
                    s.principal_kind = "engine";
                return s;
            },
            .perm_fn = [](const httplib::Request&, httplib::Response& res, const std::string&,
                          const std::string&) {
                res.status = 403;
                return false;
            },
            // The global probe refuses (no grant), as the real gate does for this identity.
            .probe_perm_fn = [](const httplib::Request&, httplib::Response& res,
                                const std::string&, const std::string&) {
                res.status = 403;
                return false;
            },
            .scoped_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                 const std::string&, const std::string&) { return true; },
            .audit_fn = {},
            .store = rig.store.get(),
            .mgmt_store = &rig.mgmt,
            .plugin_config_store = rig.plugins.get(),
        });
    const auto path = rig.doc_path(rig.group_c);
    // Control: the same identity as a human session is admitted by the ancestor walk.
    auto human = sink.dispatch("PUT", path, put_body(7200));
    REQUIRE(human != nullptr);
    CHECK(human->status == 200);
    const auto cv = rig.store->get(rig.group_c)->value().version;
    engine = true;
    auto eng = sink.dispatch("PUT", path, put_body(9000, 0, cv));
    REQUIRE(eng != nullptr);
    CHECK(eng->status == 403);
    CHECK(rig.store->get(rig.group_c)->value().settings.interval_s == 7200);
}

TEST_CASE("collection settings PUT: the real gate admits a group owner on the group and below only",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto owner = rig.group_owner("gadmin", rig.group_p);
    const auto boss = rig.global_admin();

    // Control: a parent grant reaches the parent and its child through the walk.
    auto on_parent = rig.call("PUT", rig.doc_path(rig.group_p), owner, put_body(7200));
    CHECK(on_parent->status == 200);
    CHECK_FALSE(rig.parse(*on_parent).contains("error")); // the throwaway probe left no body behind
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), owner, put_body(7200))->status == 200);
    // Never a sibling branch and never the root.
    rig.audit.clear();
    CHECK(rig.call("PUT", rig.doc_path(rig.group_s), owner, put_body(7200))->status == 403);
    CHECK(rig.call("PUT", rig.doc_path(rig.root), owner, put_body(7200))->status == 403);
    CHECK(rig.audit_count("denied") == 2);
    CHECK_FALSE(rig.store->get(rig.group_s)->has_value());
    CHECK_FALSE(rig.store->get(rig.root)->has_value());
    // A priority change needs the global grant, whatever the expected version says.
    const auto cv = rig.store->get(rig.group_c)->value().version;
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), owner, put_body(7200, 5, "none"))->status ==
          403);
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), owner, put_body(7200, 5, cv))->status == 403);
    CHECK(rig.store->get(rig.group_c)->value().settings.priority == 0);

    // The global grant is admitted everywhere, including the root and a priority.
    CHECK(rig.call("PUT", rig.doc_path(rig.group_s), boss, put_body(7200))->status == 200);
    CHECK(rig.call("PUT", rig.doc_path(rig.root), boss, put_body(7200))->status == 200);
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), boss, put_body(7200, 5, cv))->status == 200);
    // A user with no authority at all.
    const auto nobody = rig.cookie("nobody");
    CHECK(rig.call("PUT", rig.doc_path(rig.group_p), nobody, put_body(9000))->status == 403);
}

TEST_CASE("collection settings PUT: an omitted priority keeps the stored one for a group owner",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto owner = rig.group_owner("gadmin", rig.group_p);
    const auto boss = rig.global_admin();
    const auto path = rig.doc_path(rig.group_c);
    const auto no_priority = [](const std::string& expected) {
        auto b = json::parse(put_body(9000, 0, expected));
        b.erase("priority");
        return b.dump();
    };
    REQUIRE(rig.call("PUT", path, boss, put_body(7200, 5))->status == 200);
    auto cv = rig.store->get(rig.group_c)->value().version;

    SECTION("omitted: the owner's write lands with the stored priority") {
        auto res = rig.call("PUT", path, owner, no_priority(cv));
        REQUIRE(res->status == 200);
        CHECK(rig.parse(*res)["data"]["priority"] == 5);
        const auto stored = rig.store->get(rig.group_c)->value();
        CHECK(stored.settings.priority == 5);
        CHECK(stored.settings.interval_s == 9000);
    }
    SECTION("the same value echoed back is admitted") {
        CHECK(rig.call("PUT", path, owner, put_body(9000, 5, cv))->status == 200);
        CHECK(rig.store->get(rig.group_c)->value().settings.priority == 5);
    }
    SECTION("an explicit different value is a 403 that says how to keep it") {
        auto res = rig.call("PUT", path, owner, put_body(9000, 0, cv));
        CHECK(res->status == 403);
        CHECK(res->body.find("omit priority to keep the stored value") != std::string::npos);
        CHECK(rig.audit.back().result == "denied");
        CHECK(rig.audit.back().detail == "priority change needs the global grant");
        CHECK(rig.store->get(rig.group_c)->value().settings.interval_s == 7200);
    }
    SECTION("omitted on a group with no document: priority 0") {
        const auto pv = rig.call("PUT", rig.doc_path(rig.group_p), owner, no_priority("none"));
        REQUIRE(pv->status == 200);
        CHECK(rig.store->get(rig.group_p)->value().settings.priority == 0);
    }
    SECTION("the global grant replaces the whole document: omitted is 0") {
        REQUIRE(rig.call("PUT", path, boss, no_priority(cv))->status == 200);
        CHECK(rig.store->get(rig.group_c)->value().settings.priority == 0);
    }
}

TEST_CASE("collection settings PUT: tokens the permission gate refuses never get the group fallback",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    rig.group_owner("gowner", rig.group_p);
    const auto expiry = now_secs() + 3600;

    auto plain = rig.api_tokens->create_token("plain", "gowner", expiry);
    REQUIRE(plain.has_value());
    // Control: an ordinary token of the same user is admitted by the walk.
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), rig.bearer(*plain), put_body(7200))->status ==
          200);

    auto mcp = rig.api_tokens->create_token("mcp", "gowner", expiry, "", "readonly");
    REQUIRE(mcp.has_value());
    const auto mcp_session = rig.ar->resolve_session([&] {
        httplib::Request r;
        r.headers.emplace("Authorization", "Bearer " + *mcp);
        return r;
    }());
    REQUIRE(mcp_session.has_value());
    REQUIRE_FALSE(mcp_session->mcp_tier.empty());
    const auto cv = rig.store->get(rig.group_c)->value().version;
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), rig.bearer(*mcp), put_body(9000, 0, cv))
              ->status == 403);

    auto svc = rig.api_tokens->create_token("svc", "gowner", expiry, "billing");
    REQUIRE(svc.has_value());
    CHECK(rig.call("PUT", rig.doc_path(rig.group_c), rig.bearer(*svc), put_body(9000, 0, cv))
              ->status == 403);
    CHECK(rig.store->get(rig.group_c)->value().settings.interval_s == 7200);
}

TEST_CASE("collection settings PUT: an unavailable authority read is a 503, never a 403 or an admit",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    rig.group_owner("gadmin", rig.group_p);

    SECTION("the group hierarchy read") {
        TableFault fault{rig.mgmt_bundle.dsn(), "management_group_store.management_groups"};
        fault.arm();
        rig.audit.clear();
        auto res = rig.call("PUT", rig.doc_path(rig.group_c), rig.cookie("gadmin2"), put_body());
        CHECK(res->status == 503);
        CHECK(rig.audit_count("denied") == 1);
        CHECK(rig.audit_count("requested") == 0);
    }
    SECTION("the role assignment read") {
        // The ancestor read works; the batched assignments read fails.
        TableFault fault{rig.mgmt_bundle.dsn(), "management_group_store.management_group_roles"};
        fault.arm();
        auto res = rig.call("PUT", rig.doc_path(rig.group_c), rig.cookie("gadmin3"), put_body());
        CHECK(res->status == 503);
        fault.repair();
        CHECK_FALSE(rig.store->get(rig.group_c)->has_value());
    }
    SECTION("an unavailable RBAC read answers 503 from the unavailable-aware probe") {
        // A cold replica of the RBAC store whose role read is broken.
        PgPool replica_pool{{.conninfo = rig.rbac_bundle.dsn(), .size = 1}};
        yuzu::MetricsRegistry replica_metrics;
        RbacStore replica_store{replica_pool};
        replica_store.set_metrics(&replica_metrics);
        REQUIRE(replica_store.is_open());
        AuthRoutes replica_ar{rig.cfg, rig.auth_mgr, &replica_store, rig.api_tokens.get(),
                              /*audit_store=*/nullptr, &rig.mgmt, /*tag_store=*/nullptr,
                              /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider};
        yuzu::server::test::TestRouteSink degraded_sink;
        SoftwareCollectionSettingsRoutes degraded_routes;
        degraded_routes.register_routes(
            degraded_sink,
            SoftwareCollectionSettingsRoutes::Deps{
                .auth_fn = [&](const httplib::Request& req,
                               httplib::Response& res) { return rig.ar->require_auth(req, res); },
                .perm_fn = [&](const httplib::Request& req, httplib::Response& res,
                               const std::string& t, const std::string& o) {
                    return rig.ar->require_permission(req, res, t, o);
                },
                .probe_perm_fn = [&](const httplib::Request& req, httplib::Response& res,
                                     const std::string& t, const std::string& o) {
                    return replica_ar.probe_permission_unavailable_aware(req, res, t, o);
                },
                .scoped_perm_fn = [](const httplib::Request&, httplib::Response&,
                                     const std::string&, const std::string&,
                                     const std::string&) { return true; },
                .audit_fn = {},
                .store = rig.store.get(),
                .mgmt_store = &rig.mgmt,
                .plugin_config_store = rig.plugins.get(),
            });
        TableFault fault{rig.rbac_bundle.dsn(), "rbac_store.principal_roles"};
        fault.arm();
        const auto headers = rig.cookie("gadmin4");
        auto res = degraded_sink.dispatch("PUT", rig.doc_path(rig.group_c), put_body(),
                                          "application/json", headers);
        REQUIRE(res != nullptr);
        CHECK(res->status == 503);
        CHECK_FALSE(rig.store->get(rig.group_c).value().has_value());
    }
}

TEST_CASE("collection settings GET: list and per-group reads", "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto boss = rig.global_admin();
    const auto owner = rig.group_owner("gadmin", rig.group_p);
    REQUIRE(rig.call("PUT", rig.doc_path(rig.group_p), boss, put_body(7200))->status == 200);
    const std::string list_path = "/api/v1/inventory/software/collection-settings";

    SECTION("the fleet list is global-only and carries the built-in default with its version") {
        auto res = rig.call("GET", list_path, boss);
        REQUIRE(res->status == 200);
        const auto body = rig.parse(*res);
        CHECK(body["data"]["fleet_default"]["interval_s"] == 86400);
        CHECK(body["data"]["fleet_default"]["version"] ==
              "e27b0298c4ad0aabc3963e6dfa2ca5a3d60b687fa15315557385a020816d1696");
        REQUIRE(body["data"]["documents"].size() == 1);
        CHECK(body["data"]["documents"][0]["group_id"] == rig.group_p);
        CHECK(rig.call("GET", list_path, owner)->status == 403);
    }
    SECTION("a group owner reads the branch they govern, an outsider does not") {
        CHECK(rig.call("GET", rig.doc_path(rig.group_p), owner)->status == 200);
        CHECK(rig.call("GET", rig.doc_path(rig.group_s), owner)->status == 403);
        CHECK(rig.call("GET", rig.doc_path(rig.group_p), rig.cookie("nobody"))->status == 403);
        // A governed group with no document is a 404, not an empty 200.
        CHECK(rig.call("GET", rig.doc_path(rig.group_c), owner)->status == 404);
        // An unknown group the caller is globally entitled to read is a 404.
        CHECK(rig.call("GET", rig.doc_path("ffffffffffff"), boss)->status == 404);
        const auto doc = rig.parse(*rig.call("GET", rig.doc_path(rig.group_p), boss));
        CHECK(doc["data"]["interval_s"] == 7200);
        CHECK(doc["data"]["window"].is_null());
    }
}

TEST_CASE("collection settings host route: effective settings over the pure resolver",
          "[pg][routes][collection_settings]") {
    RoutesRig rig;
    const auto boss = rig.global_admin();
    REQUIRE(rig.mgmt.add_member(rig.group_c, "agent-1").has_value());
    REQUIRE(rig.mgmt.add_member(rig.root, "agent-2").has_value());
    const std::string host1 = "/api/v1/inventory/software/hosts/agent-1/collection-settings";
    const std::string host2 = "/api/v1/inventory/software/hosts/agent-2/collection-settings";
    const std::string host_unknown = "/api/v1/inventory/software/hosts/agent-9/collection-settings";

    SECTION("no documents: the fleet default, source empty") {
        auto res = rig.call("GET", host_unknown, boss);
        REQUIRE(res->status == 200);
        const auto b = rig.parse(*res);
        CHECK(b["data"]["source_group_id"] == "");
        CHECK(b["data"]["version"] ==
              "e27b0298c4ad0aabc3963e6dfa2ca5a3d60b687fa15315557385a020816d1696");
        CHECK(b["data"]["kill_switched"].empty());
    }
    SECTION("the answer matches the pure resolver on the same inputs") {
        REQUIRE(rig.call("PUT", rig.doc_path(rig.group_p), boss, put_body(7200))->status == 200);
        const auto b = rig.parse(*rig.call("GET", host1, boss));
        CHECK(b["data"]["source_group_id"] == rig.group_p); // inherited by member C
        CHECK(b["data"]["effective"]["interval_s"] == 7200);
        const auto stored = rig.store->get(rig.group_p)->value();
        auto expected = stored.settings.effective();
        CHECK(b["data"]["version"] == *cs::effective_version(expected));
    }
    SECTION("a member of root only resolves the root document, named by the root id") {
        REQUIRE(rig.call("PUT", rig.doc_path(rig.root), boss, put_body(10800))->status == 200);
        const auto b = rig.parse(*rig.call("GET", host2, boss));
        CHECK(b["data"]["source_group_id"] == rig.root);
        CHECK(b["data"]["effective"]["interval_s"] == 10800);
    }
    SECTION("a kill switch turns the plugin off in the effective settings and names it") {
        REQUIRE(rig.plugins->set_kill_switch("runtimes", "", false, "test", "tester").has_value());
        const auto b = rig.parse(*rig.call("GET", host1, boss));
        CHECK(b["data"]["effective"]["plugins"]["runtimes"] == false);
        CHECK(b["data"]["effective"]["plugins"]["middleware"] == true);
        REQUIRE(b["data"]["kill_switched"].size() == 1);
        CHECK(b["data"]["kill_switched"][0] == "runtimes");
    }
    SECTION("a degraded kill-switch read is a 503, never a document with everything off") {
        TableFault fault{rig.plugin_db.dsn(), "plugin_config_store.kill_switches"};
        fault.arm();
        CHECK(rig.call("GET", host1, boss)->status == 503);
    }
    SECTION("a degraded membership read is a 503") {
        TableFault fault{rig.mgmt_bundle.dsn(), "management_group_store.management_group_members"};
        fault.arm();
        CHECK(rig.call("GET", host1, boss)->status == 503);
    }
    SECTION("the device-scoped gate refuses a caller without Inventory:Read") {
        CHECK(rig.call("GET", host1, rig.cookie("nobody"))->status == 403);
    }
}
