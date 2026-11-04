/**
 * @file test_settings_access_review_engine_authz.cpp
 * @brief [pg] #6744: the Settings Access reviews fragments (`GET /fragments/settings/access-reviews`
 *        and `.../campaign`) refuse an engine-class session, as every `/api/v1/access-reviews`
 *        twin does through `deny_engine_session`, driven through the REAL AuthRoutes gates over a
 *        real RbacStore, EnginePrincipalStore, ApiTokenStore, AccessReviewStore and AuditStore.
 *
 * The persona that matters: an engine principal holding a CUSTOM role with `AccessReview:Read`
 * (an engine may never hold a built-in role, but a narrow custom role is permitted). The
 * permission gate admits it; only the engine-session belt (`SettingsRoutes::refuse_engine_session`,
 * the one helper the Engine Principals panel shares) refuses it. A human holding the same grant
 * must still be admitted, and a caller without the grant is refused at the gate as before.
 *
 * It also pins: RBAC off (the default), a dropped, throwing or unwired audit sink (the 403 stands),
 * an RBAC switch or an engine revoke between the permission gate and the belt (never a 200), and a
 * plain API token.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_review_store.hpp"
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
#include <functional>
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

yuzu::test::PgTestTemplate ar_engine_tpl{"rbacstore_ar_engine", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    AccessReviewStore reviews{pool};
    EnginePrincipalStore eps{pool};
    if (!rbac.is_open() || !reviews.is_open() || !eps.is_open())
        throw std::runtime_error("access-review engine authz template: a store failed to migrate");
}};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr const char* kListFragment = "/fragments/settings/access-reviews";
constexpr const char* kGetFragment = "/fragments/settings/access-reviews/campaign";
constexpr const char* kListTwin = "/api/v1/access-reviews";
constexpr const char* kEngineSlug = "engine:arreader";
constexpr const char* kCampaignTitle = "Q4 ENGINE-LEAK-MARKER review";
constexpr const char* kRole = "ReviewReader";

bool refused(int status) { return status == 401 || status == 403; }

struct Rig {
    yuzu::test::TempDir tmp{"yuzu_test_ar_engine_authz_"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    PgPool pool;
    RbacStore rbac;
    EnginePrincipalStore engine_store;
    AccessReviewStore reviews;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    std::string campaign_id;
    std::vector<std::string> fragment_audits; // "action/result/detail|target" of the belt's rows
    /// What the fail-closed audit hook does with a row: persist it, report a dropped write
    /// (`false`), or throw (an audit sink that blows up). Both failures must leave the 403 intact.
    enum class AuditMode { Normal, Drop, Throw } audit_mode{AuditMode::Normal};
    /// Runs after the permission gate admitted the caller and before the handler goes on: the
    /// window in which the regime or the credential can change under the request.
    std::function<void()> after_perm;
    SettingsRoutes settings;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink; // LAST: handlers capture `this`

    /// `rbac_enabled == false` is the DEFAULT deployment (RBAC off): the permission gate decides.
    /// `wire_audit_read == false` models a deployment that wires no fail-closed audit hook.
    explicit Rig(const std::string& dsn, bool rbac_enabled = true, bool wire_audit_read = true)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, engine_store{pool}, reviews{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(engine_store.is_open());
        REQUIRE(reviews.is_open());
        REQUIRE(audit_store.is_open());
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        for (const char* u : {"root", "alice", "bob"})
            REQUIRE(auth_mgr.upsert_user(u, "correct-horse-battery-staple",
                                         std::string(u) == "root" ? auth::Role::admin
                                                                  : auth::Role::user));
        REQUIRE(engine_store.create("AR Engine", "root", "j", "internal", "admin", kEngineSlug)
                    .has_value());
        api_tokens->set_engine_referent_check(
            [](const std::string&) { return EngineLookupStatus::Active; });

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);
        // Without this an engine bearer never authenticates (401) and the persona would pass the
        // refusal checks vacuously instead of reaching the permission gate and the belt.
        ar->set_engine_principal_store(&engine_store);

        auto id = reviews.open_campaign(kCampaignTitle, "root",
                                        {GrantRef{"user", "alice", "Operator", "{}"}}, "enabled");
        REQUIRE(id.has_value());
        campaign_id = *id;

        // The custom role: AccessReview:Read and nothing else. Both a human (bob) and the engine
        // principal hold it, so the ONLY difference between them is the session class.
        REQUIRE(rbac.create_role({kRole, "reads access reviews", false, 0}).has_value());
        REQUIRE(rbac.set_permission({kRole, "AccessReview", "Read", "allow"}).has_value());
        REQUIRE(rbac.assign_role({"user", "bob", kRole}).has_value());
        REQUIRE(rbac.assign_role({"engine", kEngineSlug, kRole}).has_value());
        if (rbac_enabled) {
            rbac.set_rbac_enabled(true);
            REQUIRE(rbac.is_rbac_enabled()); // a vacuous pass would be the RBAC-off case
        } else {
            REQUIRE_FALSE(rbac.is_rbac_enabled()); // the default; the grant above is inert
        }

        auto auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        auto admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_admin(q, r);
        };
        auto perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                              const std::string& o) {
            const bool ok = ar->require_permission(q, r, t, o);
            if (ok && after_perm)
                after_perm();
            return ok;
        };
        // The REST twin's audit hook: persisted through the real AuditStore.
        auto audit_fn = [this](const httplib::Request& req, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            return ar->audit_log(req, action, result, target_type, target_id, detail);
        };
        // The fail-closed hook server.cpp binds for the fragments' belts.
        auto settings_audit_read = [this](const httplib::Request& req, const std::string& action,
                                          const std::string& result,
                                          const std::string& target_type,
                                          const std::string& target_id,
                                          const std::string& detail) -> bool {
            fragment_audits.push_back(action + "/" + result + "/" + detail + "|" + target_type +
                                      ":" + target_id);
            if (audit_mode == AuditMode::Throw)
                throw std::runtime_error("audit sink failed");
            if (audit_mode == AuditMode::Drop)
                return false;
            return ar->audit_log(req, action, result, target_type, target_id, detail);
        };
        auto settings_audit = [](const httplib::Request&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&) {};

        settings.set_rbac_store(&rbac);
        settings.set_access_review_store(&reviews);
        settings.set_engine_principal_store(&engine_store);
        settings.register_routes(sink, auth_fn, admin_fn, perm_fn, settings_audit, cfg, auth_mgr,
                                 auto_approve, api_tokens.get(), &*mgmt_bundle,
                                 /*tag_store=*/nullptr, /*update_registry=*/nullptr,
                                 /*runtime_config_store=*/nullptr, &audit_store,
                                 /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                                 []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                                 /*metrics_registry=*/nullptr, /*step_up_fn=*/{},
                                 wire_audit_read ? SettingsRoutes::AuditReadFn{settings_audit_read}
                                                 : SettingsRoutes::AuditReadFn{});

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
                            /*engine_principal_store=*/&engine_store,
                            /*access_review_store=*/&reviews);
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
    std::string engine_bearer() {
        auto raw = api_tokens->create_token("ar-engine-bearer", kEngineSlug, now_epoch() + 3600, "",
                                            "readonly", "engine");
        REQUIRE(raw.has_value());
        return *raw;
    }
    /// An ordinary human API token (no MCP tier).
    std::string plain_token(const char* name, const char* owner) {
        auto raw = api_tokens->create_token(name, owner, now_epoch() + 3600, "", "");
        REQUIRE(raw.has_value());
        return *raw;
    }
    std::string campaign_path() const { return std::string(kGetFragment) + "?id=" + campaign_id; }

    /// The persisted `denied` rows of `action`, as their `detail` strings, newest first.
    std::vector<std::string> denied_details(const std::string& action) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        std::vector<std::string> out;
        for (const auto& r : *rows)
            if (r.result == "denied" && r.action == action)
                out.push_back(r.detail);
        return out;
    }
    /// Any success row for the read verbs: a refused caller must cost no store read.
    int success_rows(const std::string& action) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.result == "success" && r.action == action)
                ++n;
        return n;
    }
};

} // namespace

TEST_CASE("access-review fragments: an engine session holding AccessReview:Read through a custom "
          "role is refused by both fragments AND the REST twin, with the twin's audit verbs",
          "[pg][settings][engine_principal][access_review][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);
    Rig r{db_.dsn()};
    const auto raw = r.engine_bearer();

    SECTION("the list fragment") {
        const auto res = r.bearer_get(kListFragment, raw);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle)); // nothing of the store leaks
        CHECK_THAT(res->body, ContainsSubstring("engine principals cannot access this endpoint"));
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(r.denied_details("access_review.list") ==
              std::vector<std::string>{"engine_session_denied"});
        CHECK(r.fragment_audits ==
              std::vector<std::string>{"access_review.list/denied/engine_session_denied|"
                                       "AccessReview:"});
    }
    SECTION("the campaign fragment, named by id") {
        const auto res = r.bearer_get(r.campaign_path(), raw);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
        CHECK_THAT(res->body, !ContainsSubstring("alice")); // no attestation row
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(r.denied_details("access_review.get") ==
              std::vector<std::string>{"engine_session_denied"});
        // The twin and the Access page write an EMPTY target on a denial; the caller-supplied id
        // is never echoed into the audit row.
        CHECK(r.fragment_audits ==
              std::vector<std::string>{"access_review.get/denied/engine_session_denied|"
                                       "AccessReview:"});
    }
    SECTION("the main fragment's ?campaign_id= deep link does not reach the renderer either") {
        const auto res =
            r.bearer_get(std::string(kListFragment) + "?campaign_id=" + r.campaign_id, raw);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
    }
    SECTION("the REST twin refuses the same session") {
        const auto res = r.bearer_get(kListTwin, raw);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
        const auto get = r.bearer_get(std::string(kListTwin) + "/" + r.campaign_id, raw);
        REQUIRE(get);
        CHECK(get->status == 403);
        CHECK_THAT(get->body, !ContainsSubstring(kCampaignTitle));
        // The 403 came from the twin's own engine belt (not a closed store, which answers 503),
        // and the twin served nothing: no success row for either verb.
        CHECK(r.denied_details("access_review.list") ==
              std::vector<std::string>{"engine_session_denied"});
        CHECK(r.denied_details("access_review.get") ==
              std::vector<std::string>{"engine_session_denied"});
        CHECK(r.success_rows("access_review.list") == 0);
        CHECK(r.success_rows("access_review.get") == 0);
    }
}

TEST_CASE("access-review fragments: a human holding the same custom role is still admitted by both "
          "fragments and the REST twin",
          "[pg][settings][engine_principal][access_review][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);
    Rig r{db_.dsn()};
    const auto bob = r.cookie("bob", auth::Role::user);

    const auto list = r.cookie_get(kListFragment, bob);
    REQUIRE(list);
    CHECK(list->status == 200);

    const auto get = r.cookie_get(r.campaign_path(), bob);
    REQUIRE(get);
    CHECK(get->status == 200);
    CHECK_THAT(get->body, ContainsSubstring(kCampaignTitle));

    const auto twin = r.cookie_get(kListTwin, bob);
    REQUIRE(twin);
    CHECK(twin->status == 200);
    CHECK_THAT(twin->body, ContainsSubstring(kCampaignTitle));

    // A human API token (no MCP tier) holding the same role is admitted too.
    const auto tok = r.plain_token("bob-plain", "bob");
    const auto tok_list = r.bearer_get(kListFragment, tok);
    REQUIRE(tok_list);
    CHECK(tok_list->status == 200);
    const auto tok_get = r.bearer_get(r.campaign_path(), tok);
    REQUIRE(tok_get);
    CHECK(tok_get->status == 200);
    CHECK_THAT(tok_get->body, ContainsSubstring(kCampaignTitle));

    CHECK(r.denied_details("access_review.list").empty());
    CHECK(r.denied_details("access_review.get").empty());
    CHECK(r.fragment_audits.empty()); // the belt writes only on a refusal
}

TEST_CASE("access-review campaign fragment: a malformed or unknown id shows a plain notice, never "
          "the store's classification prefix",
          "[pg][settings][access_review][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);
    Rig r{db_.dsn()};
    const auto bob = r.cookie("bob", auth::Role::user);
    const std::string base = std::string(kGetFragment) + "?id=";

    // "has space" and "a%00b" fail the shared validator; "nosuchcampaign" passes it and is unknown.
    for (const char* id : {"has%20space", "a%00b", "nosuchcampaign"}) {
        INFO("id=" << id);
        const auto res = r.cookie_get(base + id, bob);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("No campaign with that id."));
        CHECK_THAT(res->body, !ContainsSubstring("bad_request"));
        CHECK_THAT(res->body, !ContainsSubstring("not_found"));
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
    }
}

TEST_CASE("access-review fragments: a caller without the grant and an unauthenticated caller are "
          "still refused at the gate, before the belt",
          "[pg][settings][engine_principal][access_review][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);
    Rig r{db_.dsn()};

    // alice holds no grant; an unauthenticated caller holds no session.
    for (const char* path : {kListFragment, kGetFragment}) {
        INFO("path=" << path);
        const auto alice = r.cookie_get(path, r.cookie("alice", auth::Role::user));
        REQUIRE(alice);
        CHECK(refused(alice->status));
        const auto anon = r.anon_get(path);
        REQUIRE(anon);
        CHECK(refused(anon->status));
    }
    // The belt never ran for either: it would have written an engine_session_denied row.
    CHECK(r.fragment_audits.empty());
}

TEST_CASE("access-review fragments, RBAC OFF (the default): an engine session is refused by both "
          "fragments and the twin at the permission gate, before the belt",
          "[pg][settings][engine_principal][access_review][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);
    Rig r{db_.dsn(), /*rbac_enabled=*/false};
    const auto raw = r.engine_bearer();

    for (const std::string& path : {std::string(kListFragment), r.campaign_path(),
                                   std::string(kListTwin)}) {
        INFO("path=" << path);
        const auto res = r.bearer_get(path, raw);
        REQUIRE(res);
        CHECK(refused(res->status));
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
    }
    // Engine principals are default-deny with RBAC off: the gate refuses, the belt never runs.
    CHECK(r.fragment_audits.empty());
}

TEST_CASE("access-review fragments: a failing audit sink never turns the engine refusal into a "
          "200, a 500 or a leak (dropped write, throwing sink, no hook wired)",
          "[pg][settings][engine_principal][access_review][authz][security][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);

    const auto check = [](Rig& r, bool expect_audit_failed_header) {
        const auto raw = r.engine_bearer();
        for (const std::string& path : {std::string(kListFragment), r.campaign_path()}) {
            INFO("path=" << path);
            const auto res = r.bearer_get(path, raw);
            REQUIRE(res);
            CHECK(res->status == 403); // the refusal stands whatever the audit sink does
            CHECK_THAT(res->body, ContainsSubstring("engine principals cannot access this endpoint"));
            CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
            CHECK(res->has_header("Sec-Audit-Failed") == expect_audit_failed_header);
        }
    };

    SECTION("the denial row cannot be written: Sec-Audit-Failed rides the 403") {
        Rig r{db_.dsn()};
        r.audit_mode = Rig::AuditMode::Drop;
        check(r, true);
        CHECK(r.fragment_audits.size() == 2); // the belt did try to write both rows
        // The Drop hook reports failure BEFORE persisting: no denial row reached the store.
        CHECK(r.denied_details("access_review.list").empty());
        CHECK(r.denied_details("access_review.get").empty());
    }
    SECTION("the audit sink throws: caught, reported the same way") {
        Rig r{db_.dsn()};
        r.audit_mode = Rig::AuditMode::Throw;
        check(r, true);
        CHECK(r.fragment_audits.size() == 2); // the sink was reached (and threw) for both rows
    }
    SECTION("no fail-closed audit hook wired (audit off): refused, no row, no header") {
        Rig r{db_.dsn(), /*rbac_enabled=*/true, /*wire_audit_read=*/false};
        check(r, false);
        CHECK(r.fragment_audits.empty());
    }
}

TEST_CASE("access-review fragments: the regime or the credential changing between the permission "
          "gate and the belt never yields a 200 for an engine session",
          "[pg][settings][engine_principal][access_review][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, ar_engine_tpl);

    SECTION("RBAC switched off in the window: the belt keys on the session, not the regime") {
        Rig r{db_.dsn()};
        const auto raw = r.engine_bearer();
        r.after_perm = [&r] { r.rbac.set_rbac_enabled(false); };
        const auto res = r.bearer_get(kListFragment, raw);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
        CHECK(r.denied_details("access_review.list") ==
              std::vector<std::string>{"engine_session_denied"});
    }
    SECTION("engine principal revoked in the window: auth_fn_ refuses it before the belt") {
        Rig r{db_.dsn()};
        const auto raw = r.engine_bearer();
        bool fired = false;
        bool revoked = false;
        // The REAL referent: request-time authentication reads the engine principal store on
        // every request (AuthRoutes::synthesize_token_session -> get_for_auth); the token
        // store's referent check is consulted only when minting or rotating a credential.
        r.after_perm = [&] {
            fired = true;
            revoked = r.engine_store.revoke(kEngineSlug).has_value();
        };
        const auto res = r.bearer_get(kListFragment, raw);
        REQUIRE(res);
        CHECK(fired);   // the hook ran after the permission gate admitted the caller
        CHECK(revoked); // and it really revoked the principal
        CHECK(res->status == 401);
        CHECK_THAT(res->body, !ContainsSubstring(kCampaignTitle));
        // Refused by the session re-resolution, not by the belt: no belt row, no belt call.
        CHECK(r.fragment_audits.empty());
        CHECK(r.denied_details("access_review.list").empty());
    }
}
