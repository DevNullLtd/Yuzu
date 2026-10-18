/**
 * @file test_access_reviews_authz.cpp
 * @brief [pg] persona matrix for the Access reviews fragments, driven through the REAL
 *        AuthRoutes gates over a real RbacStore, AccessReviewStore and AuditStore.
 *        test_access_reviews_routes.cpp stubs the gate; this file proves the production wiring
 *        admits and refuses the right callers.
 *
 * What it proves that the stubbed tests cannot:
 *   - `AuditLog:Read` does NOT satisfy the reviews fragments (routed Periodic Access Reviews
 *     clause 1): an Operator, who holds the audit trail, is refused the campaigns;
 *   - with RBAC off, a plain user is refused (`AccessReview:Read` is in the topology floor);
 *   - a Reviewer is admitted and is offered controls only because the real Attest probe passes;
 *   - a refused caller costs no store read.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_review_store.hpp"
#include "access_reviews_routes.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

yuzu::test::PgTestTemplate reviews_page_tpl{"rbacstore_reviewspage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    AccessReviewStore reviews{pool};
    if (!rbac.is_open() || !reviews.is_open())
        throw std::runtime_error("reviews page template: a store failed to migrate/seed");
}};

struct Rig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    AccessReviewStore reviews;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    std::string campaign_id;
    int reads{0};
    std::vector<std::string> audit_actions;
    yuzu::server::test::TestRouteSink sink;  // LAST: handlers capture `this`

    explicit Rig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, reviews{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(reviews.is_open());
        REQUIRE(audit_store.is_open());
        for (const char* u : {"root", "alice", "bob"})
            REQUIRE(auth_mgr.upsert_user(u, "correct-horse-battery-staple",
                                         std::string(u) == "root" ? auth::Role::admin
                                                                  : auth::Role::user));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);
        auto id = reviews.open_campaign("Q4 admin access", "root",
                                        {GrantRef{"user", "alice", "Operator", "{}"}}, "enabled");
        REQUIRE(id.has_value());
        campaign_id = *id;

        access_reviews::ReviewsDeps d;
        d.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        d.perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                           const std::string& o) { return ar->require_permission(q, r, t, o); };
        // The production binding: the loud gate on a scratch Response.
        d.probe_perm_fn = [this](const httplib::Request& q, const std::string& t, const std::string& o) {
            httplib::Response scratch;
            return ar->require_permission(q, scratch, t, o);
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
            audit_actions.push_back(a);
            return true;
        };
        d.list_campaigns_fn = [this] {
            ++reads;
            return reviews.list_campaigns();
        };
        d.get_campaign_fn = [this](const std::string& id) {
            ++reads;
            return reviews.get_campaign(id);
        };
        d.grants_fn = [this]() -> std::expected<access_reviews::GrantsView, std::string> {
            ++reads;
            return access_reviews::GrantsView{{}, "disabled"};
        };
        access_reviews::register_access_reviews_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }
    std::string session(const char* user, auth::Role role) {
        return auth_mgr.create_local_session_for_test(user, role, true);
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
    std::string campaign_path() const { return "/fragments/access/reviews/campaign?id=" + campaign_id; }
};

constexpr const char* kCampaigns = "/fragments/access/reviews/campaigns";
constexpr const char* kGrants = "/fragments/access/reviews/grants";

} // namespace

TEST_CASE("reviews authz: Administrator with RBAC off reads all three and is offered the controls",
          "[pg][access-reviews][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, reviews_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.session("root", auth::Role::admin);

    auto res = r.get(kCampaigns, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("Q4 admin access"));
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-open\""));

    res = r.get(r.campaign_path(), cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-attest\""));

    res = r.get(kGrants, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.audit_actions ==
          std::vector<std::string>{"access_review.list", "access_review.get", "access_review.exported"});
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("reviews authz: a plain user with RBAC off is refused by the floor and nothing is read",
          "[pg][access-reviews][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, reviews_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.session("alice", auth::Role::user);
    for (const std::string& p : {std::string(kCampaigns), r.campaign_path(), std::string(kGrants)}) {
        INFO(p);
        const auto res = r.get(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring("Q4 admin access"));
    }
    CHECK(r.reads == 0);
    CHECK(r.audit_actions.empty());
    CHECK(r.denied_rows() == 3);
}

TEST_CASE("reviews authz: AuditLog:Read does not satisfy the reviews fragments (Operator is refused)",
          "[pg][access-reviews][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, reviews_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Operator"}).has_value());
    const auto cookie = r.session("alice", auth::Role::user);
    for (const std::string& p : {std::string(kCampaigns), r.campaign_path(), std::string(kGrants)}) {
        INFO(p);
        const auto res = r.get(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    CHECK(r.reads == 0);
    CHECK(r.denied_rows() == 3);
}

TEST_CASE("reviews authz: RBAC on, a Reviewer is admitted and the real Attest probe offers controls",
          "[pg][access-reviews][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, reviews_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "bob", "Reviewer"}).has_value());
    const auto cookie = r.session("bob", auth::Role::user);

    auto res = r.get(kCampaigns, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-open\""));
    res = r.get(r.campaign_path(), cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-attest\""));
    res = r.get(kGrants, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.denied_rows() == 0);
}
