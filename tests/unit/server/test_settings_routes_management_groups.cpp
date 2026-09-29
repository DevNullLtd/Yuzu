/**
 * test_settings_routes_management_groups.cpp — regression test for the F1
 * stored-XSS finding: a management-group name is stored verbatim
 * (ManagementGroupStore::create_group only rejects an empty name) and was
 * concatenated unescaped into the Settings "management-groups" fragment —
 * both as element text and inside the `hx-confirm` attribute, and again in
 * the "Create group" form's parent <option> list — while a sibling render
 * path elsewhere in this same file already escapes group names correctly.
 * Fixed by routing every render of a group's name/id through html_escape().
 *
 * PG-gated (ManagementGroupStore is a migrated Postgres store, ADR-0042):
 * skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but
 * broken. See test_management_group_store.cpp for the store-level template.
 */

#include "settings_routes.hpp"

#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template — see test_management_group_store.cpp's identical
// `mgmt_tpl` (a separate template key ("mgmtgroupstoreroutes") because
// PgTestTemplate replay-verifies a shared key's setup by structural
// fingerprint — an identical-looking lambda in a different TU is a
// different setup, not guaranteed to replay identically).
yuzu::test::PgTestTemplate mgmt_routes_tpl{"mgmtgroupstoreroutes", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("mgmtgroupstoreroutes template: store failed to migrate");
}};

struct MgmtGroupsHarness {
    PgPool pool;
    ManagementGroupStore mgmt_group_store;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    explicit MgmtGroupsHarness(const std::string& dsn)
        : pool({.conninfo = dsn, .size = 4}), mgmt_group_store(pool) {
        REQUIRE(mgmt_group_store.is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr, &mgmt_group_store,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }
};

} // namespace

TEST_CASE("management-groups fragment escapes a name containing markup",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    g.name = "<script>alert(1)</script>";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The raw payload must never reach the response body verbatim.
    CHECK(res->body.find("<script>alert(1)</script>") == std::string::npos);
    // It must appear in its escaped form as element text.
    CHECK(res->body.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
}

TEST_CASE("management-groups fragment escapes a name that breaks out of an HTML attribute",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    // A double-quote breaks out of the hx-confirm="..." attribute; the
    // payload after it would otherwise land as a new, attacker-controlled
    // attribute/tag in the button's opening tag.
    g.name = "x\" onmouseover=\"alert(1)";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("onmouseover=\"alert(1)") == std::string::npos);
    // Pin the specific escaped payload, not just any "&quot;" in the
    // fragment — a bare substring check would trivially pass once any
    // other markup in the page emits one.
    CHECK(res->body.find("x&quot; onmouseover=&quot;alert(1)") != std::string::npos);
}

TEST_CASE("create-group form's parent <option> list escapes group names",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    g.name = "<b>evil</b>";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("<option value=\"" + *created + "\"><b>evil</b></option>") ==
          std::string::npos);
    // Pin the escaped payload to this specific <option>, not just anywhere
    // in the fragment — the tree-row text (test above) also escapes the
    // same name, so a bare substring check wouldn't discriminate the two
    // render sites.
    CHECK(res->body.find("<option value=\"" + *created +
                          "\">&lt;b&gt;evil&lt;/b&gt;</option>") != std::string::npos);
}
