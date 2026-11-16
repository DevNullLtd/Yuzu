/**
 * @file test_settings_engine_panel_authz.cpp
 * @brief [pg] Settings > Engine Principals panel (`GET /fragments/settings/engine-principals`)
 *        against its REST route (`GET /api/v1/engine-principals`), both driven through the REAL
 *        AuthRoutes gates over a real RbacStore, EnginePrincipalStore, ApiTokenStore and
 *        AuditStore (#5882). The panel applies the same permission test as the route: it gates on
 *        EnginePrincipal:Read with the quiet probe, the route with the loud `require_permission`,
 *        and server.cpp binds exactly these functions. Each difference is stricter, a different
 *        refusal, a different rendering of a store failure, or a different audit record; none
 *        admits a caller the route refuses. They are SEVEN, numbered from 1 in the handler
 *        comment in settings_routes.cpp and listed once, with rationale, in
 *        docs/user-manual/upgrading.md.
 *
 * Classification rule: a status of 401 or 403 is "refused at the gate"; anything else (200, or
 * the route's 503 for a closed store) is "admitted at the gate". Raw statuses are NOT compared
 * for an admitted caller whose store is unavailable: the route answers 503 before it reads the
 * session, the panel answers its in-page "store unavailable" note with 200 (htmx does not swap
 * a 4xx/5xx, so the degraded note must ride a 200). That is difference one, pinned here for a
 * human cookie only. Difference two: an engine session with the store absent gets 403 from the
 * fragment, whose engine-session belt runs after the permission gate and before the store
 * note, but 503 from the route, whose store check precedes its session read. Difference three
 * (owner ruling, 2026-10-29): the panel refuses an MCP-tier token (403, audited as
 * `mcp_session_denied`, like the Access tokens panel and the pre-#5882 administrator gate,
 * #520) where the route admits an administrator's MCP token on its creator's authority.
 * `expect_same`'s `mcp_panel_refuses` argument names it at every call site that meets it.
 * Difference four, in two cases ((a) a credential count that cannot be read; (b) no token store
 * wired, a test or embedding seam, which renders as (a) with a Retry that cannot help while the
 * route answers 200 with every count 0) and difference five (the roster that cannot be read)
 * are render cases: the render is pinned in test_engine_principal_lifecycle.cpp and the audit
 * rows (roster unreadable writes none, credential unreadable still writes the count=N success
 * row) by the "engine panel audit" cases here. Difference six (the revoke Detail needs
 * AuditLog:Read, the route returns no audit text; separately, a revoked row also shows
 * revoked_at and superseded_by, which the list route omits and GET /{id} returns under the same
 * permission) and difference seven (a refused cookie session writes no denial row on the panel,
 * a token lacking AuditLog:Read writes one extra on a view that lists a revoked principal) are
 * pinned by the "engine panel audit" cases, except the revoked_at and superseded_by clause of
 * six, which no case here asserts.
 *
 * Personas, each with RBAC off and on: an account administrator WITHOUT the grant; a
 * non-administrator WITH EnginePrincipal:Read (Viewer); an account administrator holding the
 * Administrator grant; a plain user; an administrator's MCP-tier bearer; an engine session; an
 * unauthenticated caller; a JIT-elevated user; a service-scoped token.
 *
 * Audit: a refused interactive cookie session leaves no auth.permission_required row on the
 * panel (it auto-loads) but does on the route; a refused token keeps its row on both.
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
#include <yuzu/metrics.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <libpq-fe.h>

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

extern const char* const kSettingsHtml; // settings_ui.cpp: the /settings page shell

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
constexpr const char* kRevokedId = "engine:revoked1";
// The target both surfaces name on every engine_principal.list row: the securable, no id (a list).
const std::vector<std::string> kListTarget{"EnginePrincipal:"};
// The three rows of a revoked principal's history (Rig::seed_revoked_principal).
constexpr const char* kRevokeMarker = "credentials_revoked=1; REVOKE-DETAIL-MARKER";
constexpr const char* kFailedRevokeText = "FAILED-REVOKE-STORE-ERROR connection refused";
constexpr const char* kLaterRetryText = "LATER-RETRY-credentials_revoked=0";
// The revoke cell's label. The text beneath it is the EARLIEST success the panel's bounded read
// retained, which is the revocation's record only when nothing older was pruned or lost.
constexpr const char* kDetailLabel = "Detail (earliest retained record): ";
// The Access panel's caveats, appended by the shared revoke_truncation_hint (same words).
constexpr const char* kTruncatedWithDetail =
    " <span class=\"hint\">(more than 200 revoke events: this is the oldest success among the "
    "newest 200, not necessarily the original)</span>";
constexpr const char* kTruncatedNoSuccess =
    " <span class=\"hint\">(more than 200 revoke events and none of the newest 200 "
    "succeeded)</span>";

// The in-page Retry's explanation, shared in words by kEngineRetryControl (settings_routes.cpp) and
// the page script's 5xx/429 note (settings_ui.cpp).
constexpr const char* kRetrySentence =
    "Retry here instead of reloading the page, which would discard a credential secret shown "
    "above.";

bool refused(int status) { return status == 401 || status == 403; }

std::size_t count_occurrences(const std::string& haystack, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t at = 0; (at = haystack.find(needle, at)) != std::string::npos; ++at)
        ++n;
    return n;
}

/// The whole Detail cell markup for `escaped_text` (already HTML-escaped) and an optional
/// truncation caveat, so a test pins the cell and not a substring of it.
std::string detail_cell(const std::string& escaped_text, const char* caveat = "") {
    return std::string("<br><span class=\"hint\">") + kDetailLabel + escaped_text + caveat +
           "</span>";
}

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
    yuzu::MetricsRegistry audit_metrics; // BEFORE audit_store: it keeps a pointer to this
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    std::vector<std::string> fragment_audits; // "action/result/detail" from the panel's own rows
    std::vector<std::string> twin_audits;     // the same shape, from the REST twin's audit_fn
    // "target_type:target_id" of each row above, index for index: a row is only the twin's row if
    // it names the same target as well as the same action/result/detail.
    std::vector<std::string> fragment_targets;
    std::vector<std::string> twin_targets;
    bool drop_audit_writes{false};            // both hooks report a dropped row (set-and-proceed)
    // Both hooks ALSO write the row into the real AuditStore through the same
    // `AuthRoutes::audit_log` server.cpp binds, so a test can read back what is PERSISTED (the
    // string captures above hold only action/result/detail/target). Off by default: it adds rows
    // that the denied-row counts of other cases would see.
    bool persist_audits{false};
    SettingsRoutes settings;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink; // LAST: handlers capture `this`

    /// `wire_engine_store == false` models a deployment whose engine-principal store is absent.
    /// `audit_timeout_ms` is the AUDIT pool's statement timeout: the default (the production
    /// 30 s) except in the cases that lock the audit table and need a lookup to give up quickly.
    explicit Rig(const std::string& dsn, bool wire_engine_store = true,
                 int audit_timeout_ms = 30000)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, engine_store{pool},
          audit_pool{{.conninfo = dsn, .size = 2, .statement_timeout_ms = audit_timeout_ms}},
          audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(engine_store.is_open());
        REQUIRE(audit_store.is_open());
        // The degrade counter is the deterministic observable for "how many audit reads failed".
        audit_store.set_metrics(&audit_metrics);
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
        // Without this an engine bearer never authenticates (401): the persona would pass the
        // refusal checks vacuously instead of reaching the permission gate and the belt.
        ar->set_engine_principal_store(&engine_store);

        // Exactly the bindings server.cpp makes for the panel and for the twin.
        auto auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        auto admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_admin(q, r);
        };
        auto perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                              const std::string& o) { return ar->require_permission(q, r, t, o); };
        auto audit_fn = [this](const httplib::Request& req, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            twin_audits.push_back(action + "/" + result + "/" + detail);
            twin_targets.push_back(target_type + ":" + target_id);
            if (persist_audits)
                return ar->audit_log(req, action, result, target_type, target_id, detail) &&
                       !drop_audit_writes;
            return !drop_audit_writes;
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
        // The fail-closed audit hook server.cpp binds (the engine-session belt writes through it).
        auto settings_audit_read = [this](const httplib::Request& req, const std::string& action,
                                          const std::string& result,
                                          const std::string& target_type,
                                          const std::string& target_id,
                                          const std::string& detail) -> bool {
            fragment_audits.push_back(action + "/" + result + "/" + detail);
            fragment_targets.push_back(target_type + ":" + target_id);
            if (persist_audits)
                return ar->audit_log(req, action, result, target_type, target_id, detail) &&
                       !drop_audit_writes;
            return !drop_audit_writes;
        };
        settings.register_routes(sink, auth_fn, admin_fn, perm_fn, settings_audit, cfg, auth_mgr,
                                 auto_approve, api_tokens.get(), &*mgmt_bundle,
                                 /*tag_store=*/nullptr, /*update_registry=*/nullptr,
                                 /*runtime_config_store=*/nullptr, &audit_store,
                                 /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                                 []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                                 /*metrics_registry=*/nullptr, /*step_up_fn=*/{},
                                 settings_audit_read);

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
    /// An ordinary API token (NO MCP tier): it clears the panel's MCP-tier belt, so a persona
    /// built from it reaches the gates beneath it (the permission gate the panel shares with the
    /// twin), where an MCP-tier token never would.
    std::string plain_token(const char* name, const char* owner,
                            const std::string& scope_service = {}) {
        auto raw = api_tokens->create_token(name, owner, now_epoch() + 3600, scope_service, "");
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
    /// The `detail` of every denied row of `action`, newest first.
    std::vector<std::string> denied_details(const std::string& action) {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        std::vector<std::string> out;
        for (const auto& r : *rows)
            if (r.result == "denied" && r.action == action)
                out.push_back(r.detail);
        return out;
    }

    /// `yuzu_server_audit_read_degrade_total{reason="query_error"}` as of now: one per failed
    /// audit read, whatever the wall clock did.
    long long audit_query_error_degrades() {
        const std::string key = "yuzu_server_audit_read_degrade_total{reason=\"query_error\"} ";
        const auto text = audit_metrics.serialize();
        const auto at = text.find(key);
        REQUIRE(at != std::string::npos); // set_metrics pre-seeds the series to 0
        return std::stoll(text.substr(at + key.size()));
    }

    /// A custom role holding EnginePrincipal:Read, plus AuditLog:Read when `with_audit_read`.
    void custom_reader_role(const char* role, bool with_audit_read) {
        REQUIRE(rbac.create_role({role, "reads engine principals", false, 0}).has_value());
        REQUIRE(rbac.set_permission({role, "EnginePrincipal", "Read", "allow"}).has_value());
        if (with_audit_read)
            REQUIRE(rbac.set_permission({role, "AuditLog", "Read", "allow"}).has_value());
    }
    void account(const char* user, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(user, "correct-horse-battery-staple", role));
    }
    struct RevokeRow {
        int64_t age; // seconds before now; the newest row has the smallest age
        const char* result;
        std::string detail;
    };
    /// A revoked principal (revoked in the engine store) with exactly the given
    /// `engine_principal.revoke` audit rows.
    void seed_revoked(const std::string& id, const std::vector<RevokeRow>& rows) {
        REQUIRE(engine_store.create("Revoked Engine", "root", "j", "internal", "admin", id)
                    .has_value());
        REQUIRE(engine_store.revoke(id).has_value());
        for (const auto& row : rows) {
            AuditEvent e;
            e.timestamp = now_epoch() - row.age;
            e.principal = "root";
            e.action = "engine_principal.revoke";
            e.target_type = "EnginePrincipal";
            e.target_id = id;
            e.result = row.result;
            e.detail = row.detail;
            REQUIRE(audit_store.log(e));
        }
    }
    /// A revoked principal whose revoke history is: the ORIGINAL committed revoke (carrying
    /// `kRevokeMarker`), then a FAILED retry whose detail is raw store text, then a LATER
    /// successful retry (`credentials_revoked=0`). Only the first is the revocation's record.
    void seed_revoked_principal(const char* id) {
        seed_revoked(id, {{300, "success", kRevokeMarker},
                          {200, "failure", kFailedRevokeText},
                          {100, "success", kLaterRetryText}});
    }
    /// `n` consecutive rows of one result and detail, newest first from 1000 s ago.
    static std::vector<RevokeRow> repeated(int n, const char* result, const char* detail) {
        std::vector<RevokeRow> out;
        for (int i = 0; i < n; ++i)
            out.push_back({1000 - i, result, detail});
        return out;
    }
    void clear_audits() {
        fragment_audits.clear();
        twin_audits.clear();
        fragment_targets.clear();
        twin_targets.clear();
    }
    std::size_t roster_size() {
        auto all = engine_store.list_all_checked();
        REQUIRE(all.has_value());
        return all->size();
    }

    /// Drive both surfaces with the same credential and assert they agree with `expect_admit`.
    /// `how`: 'c' cookie, 'b' bearer, 'a' anonymous. `mcp_panel_refuses` names difference three
    /// (header): the credential is an MCP-tier bearer the twin ADMITS (`expect_admit`) and the
    /// panel REFUSES with its own 403, so only the twin is held to the admit expectation.
    void expect_same(char how, const std::string& cred, bool expect_admit,
                     bool mcp_panel_refuses = false) {
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
        CHECK(refused(frag->status) == (!expect_admit || mcp_panel_refuses));
        CHECK(refused(twin->status) == !expect_admit);
        if (expect_admit && mcp_panel_refuses) {
            CHECK(how == 'b'); // only a bearer carries an MCP tier
            CHECK(frag->status == 403);
            CHECK(twin->status == 200);
            CHECK_THAT(twin->body, ContainsSubstring(kSlug));
            CHECK_THAT(frag->body, !ContainsSubstring(kSlug));
        } else if (expect_admit) {
            CHECK(frag->status == 200);
            CHECK(twin->status == 200);
            CHECK_THAT(frag->body, ContainsSubstring(kSlug));
        } else {
            CHECK(frag->status == twin->status); // same gate, same 401/403
            // 403 for any credential that authenticated, 401 only for no credential: a 401 for a
            // bearer would mean it never authenticated and the persona proved nothing.
            CHECK(frag->status == (how == 'a' ? 401 : 403));
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

TEST_CASE("engine panel authz, RBAC off: an administrator's MCP-tier bearer is admitted by the twin "
          "and refused by the panel (#520), a non-administrator's is refused by both",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.expect_same('b', r.token("root-mcp", "root"), true, /*mcp_panel_refuses=*/true);
    r.expect_same('b', r.token("alice-mcp", "alice"), false);
    // Plain API tokens (no MCP tier) reach the gates beneath the belt, so these two discriminate
    // the permission gate itself: an administrator's is admitted by both, a user's refused by both.
    r.expect_same('b', r.plain_token("root-plain", "root"), true);
    r.expect_same('b', r.plain_token("alice-plain", "alice"), false);
}

TEST_CASE("engine panel authz, RBAC off: an engine session and an unauthenticated caller are "
          "refused by both",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.expect_same('b', r.token("engine-bearer", kSlug, "readonly", "engine"), false);
    r.expect_same('a', "", false);
}

TEST_CASE("engine panel authz, both regimes: a JIT-elevated user is admitted by both (the "
          "elevation short-circuit), and a user who is not elevated is not",
          "[pg][settings][engine_principal][authz][security]") {
    for (const bool rbac_enabled : {false, true}) {
        INFO("rbac_on=" << rbac_enabled);
        YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
        Rig r{db_.dsn()};
        if (rbac_enabled)
            r.rbac_on();
        const auto elevated = r.cookie("alice", auth::Role::user);
        REQUIRE(r.auth_mgr.elevate_session(elevated, std::chrono::seconds(300)).has_value());
        r.expect_same('c', elevated, true);
        // A second, never-elevated session of the same account stays refused: the admission
        // above came from the elevation, not from the account.
        r.expect_same('c', r.cookie("alice", auth::Role::user), false);
    }
}

TEST_CASE("engine panel authz, both regimes: a service-scoped token is refused by both, even one "
          "minted by an administrator (its unscoped twin shows the MCP-tier difference)",
          "[pg][settings][engine_principal][authz][security]") {
    for (const bool rbac_enabled : {false, true}) {
        INFO("rbac_on=" << rbac_enabled);
        YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
        Rig r{db_.dsn()};
        r.grant("root", "Administrator");
        if (rbac_enabled)
            r.rbac_on();
        // The unscoped twin of the same creator is admitted, so the refusal below is the
        // service scope (kServiceScopeGlobalSafe is empty), not a missing grant or a dead token.
        r.expect_same('b', r.token("root-unscoped", "root"), true, /*mcp_panel_refuses=*/true);
        // A PLAIN scoped token, so the refusal below is the service scope and not the MCP-tier
        // belt that would refuse a "readonly"-tier token whatever the scope; its plain unscoped
        // twin is admitted by both.
        r.expect_same('b', r.plain_token("root-plain-unscoped", "root"), true);
        r.expect_same('b', r.plain_token("root-scoped", "root", "payments"), false);
    }
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

TEST_CASE("engine panel authz, RBAC on: an MCP-tier bearer follows its creator's grant on the twin "
          "and is refused by the panel whatever the grant (#520)",
          "[pg][settings][engine_principal][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.grant("root", "Administrator");
    r.rbac_on();
    r.expect_same('b', r.token("root-mcp", "root"), true, /*mcp_panel_refuses=*/true);
    r.expect_same('b', r.token("alice-mcp", "alice"), false);
    r.expect_same('b', r.plain_token("root-plain", "root"), true);
    r.expect_same('b', r.plain_token("alice-plain", "alice"), false);
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

TEST_CASE("engine panel authz: an engine session refused at the permission gate leaves the gate's "
          "denial row, as on the twin",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    const auto raw = r.token("engine-bearer", kSlug, "readonly", "engine");
    const auto frag = r.bearer_get(kFragment, raw);
    REQUIRE(frag);
    CHECK(frag->status == 403);
    CHECK(r.denied_rows("") >= 1); // an engine caller is never given the quiet treatment
}

TEST_CASE("engine panel authz: an engine session that DOES hold EnginePrincipal:Read is still "
          "refused by the belt, with the twin's audit verb",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    // A custom role granting only the read (an engine principal may never hold admin/built-in
    // roles; a narrow custom role is permitted).
    REQUIRE(r.rbac.create_role({"EngineLister", "reads engine principals", false, 0}).has_value());
    REQUIRE(r.rbac.set_permission({"EngineLister", "EnginePrincipal", "Read", "allow"}).has_value());
    REQUIRE(r.rbac.assign_role({"engine", kSlug, "EngineLister"}).has_value());
    r.rbac_on();
    r.persist_audits = true; // read the PERSISTED rows back below
    const auto raw = r.token("engine-bearer", kSlug, "readonly", "engine");

    const auto frag = r.bearer_get(kFragment, raw);
    const auto twin = r.bearer_get(kTwin, raw);
    REQUIRE(frag);
    REQUIRE(twin);
    INFO("twin body: " << twin->body);
    CHECK(frag->status == 403);
    CHECK(twin->status == 403); // the permission is held; the belt is what refuses
    CHECK_THAT(frag->body, !ContainsSubstring(kSlug));
    REQUIRE(r.fragment_audits.size() == 1);
    CHECK(r.fragment_audits[0] == "engine_principal.list/denied/engine_session_denied");
    CHECK(r.fragment_targets == kListTarget);

    // The PERSISTED rows (the panel's and the twin's): attributed to an engine actor, not "human"
    // or "agent", with the denial's target.
    AuditQuery q;
    q.action = "engine_principal.list";
    q.limit = 100;
    const auto stored = r.audit_store.query(q);
    REQUIRE(stored.has_value());
    REQUIRE(stored->size() == 2);
    for (const auto& row : *stored) {
        INFO("persisted row detail=" << row.detail << " principal=" << row.principal);
        CHECK(row.result == "denied");
        CHECK(row.detail == "engine_session_denied");
        CHECK(row.target_type == "EnginePrincipal");
        CHECK(row.principal_class == "engine");
    }
}

TEST_CASE("engine panel authz: the panel's own belt 403s (engine session, MCP-tier token) are "
          "Cache-Control: no-store, as the Access tokens panel's",
          "[pg][settings][engine_principal][authz][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    // An engine session that HOLDS the read reaches the engine arm of the belt.
    REQUIRE(r.rbac.create_role({"EngineLister", "reads engine principals", false, 0}).has_value());
    REQUIRE(r.rbac.set_permission({"EngineLister", "EnginePrincipal", "Read", "allow"}).has_value());
    REQUIRE(r.rbac.assign_role({"engine", kSlug, "EngineLister"}).has_value());
    r.rbac_on();
    r.grant("root", "Administrator");

    // The recorded denial names the arm that refused, so each 403 below is proven to come from the
    // belt arm its test line names and not from the permission gate (which writes its own row).
    const auto engine = r.bearer_get(kFragment, r.token("engine-bearer", kSlug, "readonly", "engine"));
    REQUIRE(engine);
    CHECK(engine->status == 403);
    CHECK(engine->get_header_value("Cache-Control") == "no-store");
    CHECK(r.fragment_audits ==
          std::vector<std::string>{"engine_principal.list/denied/engine_session_denied"});

    // An administrator's MCP-tier token clears the permission gate and reaches the MCP arm.
    r.clear_audits();
    const auto mcp = r.bearer_get(kFragment, r.token("root-mcp", "root"));
    REQUIRE(mcp);
    CHECK(mcp->status == 403);
    CHECK(mcp->get_header_value("Cache-Control") == "no-store");
    CHECK(r.fragment_audits ==
          std::vector<std::string>{"engine_principal.list/denied/mcp_session_denied"});
}

TEST_CASE("engine panel authz: the panel's roster 200 is Cache-Control: no-store, private with "
          "Vary: Cookie, exactly as the Access principals list's",
          "[pg][settings][engine_principal][authz][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    const auto frag = r.cookie_get(kFragment, r.cookie("root", auth::Role::admin));
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    CHECK_THAT(frag->body, ContainsSubstring(kSlug)); // the roster itself, not a note
    CHECK(frag->get_header_value("Cache-Control") == "no-store, private");
    CHECK(frag->get_header_value("Vary") == "Cookie");
}

TEST_CASE("engine panel authz: the in-page store-unavailable note (a 200) is no-store, private too",
          "[pg][settings][engine_principal][authz][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn(), /*wire_engine_store=*/false};
    const auto frag = r.cookie_get(kFragment, r.cookie("root", auth::Role::admin));
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    CHECK_THAT(frag->body, ContainsSubstring("Engine Principals store unavailable"));
    CHECK(frag->get_header_value("Cache-Control") == "no-store, private");
    CHECK(frag->get_header_value("Vary") == "Cookie");
}

// ---- revoke detail (sec-1) and the success audit row (sec-2): the CH-3 matrix ---------------

namespace {

/// Holds `LOCK TABLE audit_store.audit_events` from a raw connection until released (or until
/// the guard dies, so a failed REQUIRE still lets the clone drop).
class AuditTableLock {
public:
    explicit AuditTableLock(const std::string& dsn) : conn_{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn_.get()) == CONNECTION_OK);
        // A LOCK blocked behind another session's lock fails the test after 5 s instead of
        // hanging it.
        REQUIRE(pg::exec_params(conn_.get(), "SET lock_timeout = '5s'", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(conn_.get(), "BEGIN", std::vector<std::string>{}).status() ==
                PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(conn_.get(),
                                "LOCK TABLE audit_store.audit_events IN ACCESS EXCLUSIVE MODE",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        held_ = true;
    }
    ~AuditTableLock() { release(); }
    AuditTableLock(const AuditTableLock&) = delete;
    AuditTableLock& operator=(const AuditTableLock&) = delete;
    void release() {
        if (!held_)
            return;
        held_ = false;
        (void)pg::exec_params(conn_.get(), "ROLLBACK", std::vector<std::string>{});
    }

private:
    pg::PgConn conn_;
    bool held_{false};
};

} // namespace

TEST_CASE("engine panel audit: the revoke Detail shows only to a caller who also passes "
          "AuditLog:Read, and is the earliest retained committed revoke, never a failed or "
          "later row",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.seed_revoked_principal(kRevokedId);
    r.custom_reader_role("EngineReader", /*with_audit_read=*/false);
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("carol", auth::Role::user);
    r.account("dave", auth::Role::user);
    r.grant("carol", "EngineReader");
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();

    // (b) EnginePrincipal:Read + AuditLog:Read: the committed revoke's detail, nothing else,
    // under the label that says it is the earliest RETAINED record.
    const std::string committed = detail_cell(kRevokeMarker);
    const auto b = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(b);
    REQUIRE(b->status == 200);
    CHECK_THAT(b->body, ContainsSubstring(kRevokedId));
    CHECK_THAT(b->body, ContainsSubstring(committed));
    CHECK_THAT(b->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR"));
    CHECK_THAT(b->body, !ContainsSubstring("LATER-RETRY"));
    // A short history is complete: neither truncation caveat.
    CHECK_THAT(b->body, !ContainsSubstring("not necessarily the original"));
    CHECK_THAT(b->body, !ContainsSubstring("more than 200 revoke events"));
    CHECK_THAT(b->body, !ContainsSubstring("none of the newest 200 succeeded"));

    // (a) EnginePrincipal:Read only: the panel is admitted (it is the twin's gate) but the
    // audit trail's text is not hers to read.
    const auto before = r.denied_rows("");
    const auto a = r.cookie_get(kFragment, r.cookie("carol", auth::Role::user));
    REQUIRE(a);
    REQUIRE(a->status == 200);
    CHECK_THAT(a->body, ContainsSubstring(kRevokedId));
    CHECK_THAT(a->body, !ContainsSubstring("REVOKE-DETAIL-MARKER"));
    CHECK_THAT(a->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR"));
    CHECK_THAT(a->body, !ContainsSubstring("LATER-RETRY"));
    // The AuditLog:Read check is the QUIET probe: a cookie session without it leaves no row.
    CHECK(r.denied_rows("") == before);
}

TEST_CASE("engine panel audit: with RBAC off the administrator, who holds both reads by the "
          "topology floor, sees the committed revoke detail",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.seed_revoked_principal(kRevokedId);
    const auto resp = r.cookie_get(kFragment, r.cookie("root", auth::Role::admin));
    REQUIRE(resp);
    REQUIRE(resp->status == 200);
    CHECK_THAT(resp->body, ContainsSubstring("REVOKE-DETAIL-MARKER"));
    CHECK_THAT(resp->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR"));
    CHECK_THAT(resp->body, !ContainsSubstring("LATER-RETRY"));
}

TEST_CASE("engine panel audit: per caller class the panel leaves the evidence the twin leaves, "
          "one engine_principal.list row per admitted view",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.seed_revoked_principal(kRevokedId);
    REQUIRE(r.engine_store.create("No Grant", "root", "j", "internal", "admin", "engine:nogrant")
                .has_value());
    r.custom_reader_role("EngineReader", /*with_audit_read=*/false);
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.custom_reader_role("EngineLister", /*with_audit_read=*/false);
    r.account("carol", auth::Role::user);
    r.account("dave", auth::Role::user);
    r.account("erin", auth::Role::admin); // an account administrator holding NO grant
    r.grant("root", "Administrator");
    r.grant("carol", "EngineReader");
    r.grant("dave", "EngineAuditReader");
    REQUIRE(r.rbac.assign_role({"engine", kSlug, "EngineLister"}).has_value());
    r.rbac_on();
    const std::string success_row =
        "engine_principal.list/success/count=" + std::to_string(r.roster_size());

    constexpr int kViews = 50;
    const auto admitted_cookie = [&](const char* label, const std::string& cred) {
        INFO("caller " << label);
        int frag_ok = 0, twin_ok = 0, rows_equal = 0, targets_ok = 0;
        for (int i = 0; i < kViews; ++i) {
            r.clear_audits();
            const auto frag = r.cookie_get(kFragment, cred);
            const auto twin = r.cookie_get(kTwin, cred);
            REQUIRE(frag);
            REQUIRE(twin);
            frag_ok += (frag->status == 200 && r.fragment_audits ==
                                                   std::vector<std::string>{success_row});
            twin_ok += (twin->status == 200 && r.twin_audits ==
                                                   std::vector<std::string>{success_row});
            rows_equal += (r.fragment_audits == r.twin_audits);
            targets_ok += (r.fragment_targets == kListTarget && r.twin_targets == kListTarget);
        }
        CHECK(frag_ok == kViews);  // exactly one success row per view, with the twin's detail
        CHECK(twin_ok == kViews);
        CHECK(rows_equal == kViews);
        CHECK(targets_ok == kViews); // and the twin's row names the same target, not just the text
    };
    // (a) EnginePrincipal:Read only, (b) that plus AuditLog:Read.
    admitted_cookie("(a) EnginePrincipal:Read only", r.cookie("carol", auth::Role::user));
    admitted_cookie("(b) EnginePrincipal:Read + AuditLog:Read", r.cookie("dave", auth::Role::user));
    admitted_cookie("(g) durable Administrator", r.cookie("root", auth::Role::admin));

    {   // (c) an administrator's MCP-tier bearer: the twin admits and audits, the panel refuses
        // and audits the refusal (difference three).
        const auto raw = r.token("root-mcp", "root");
        r.clear_audits();
        const auto frag = r.bearer_get(kFragment, raw);
        const auto twin = r.bearer_get(kTwin, raw);
        REQUIRE(frag);
        REQUIRE(twin);
        CHECK(frag->status == 403);
        CHECK_THAT(frag->body, !ContainsSubstring(kSlug));
        CHECK(r.fragment_audits ==
              std::vector<std::string>{"engine_principal.list/denied/mcp_session_denied"});
        CHECK(r.fragment_targets == kListTarget);
        CHECK(twin->status == 200);
        CHECK(r.twin_audits == std::vector<std::string>{success_row});
        CHECK(r.twin_targets == kListTarget);
    }
    {   // (d) an account administrator WITHOUT the grant, cookie session: the panel's quiet probe
        // leaves NO row (it auto-loads, nobody attempted anything); the twin's loud gate does.
        // Asserted so that a later change is deliberate.
        const auto erin = r.cookie("erin", auth::Role::admin);
        const auto denied_before = r.denied_rows("auth.permission_required");
        r.clear_audits();
        const auto frag = r.cookie_get(kFragment, erin);
        REQUIRE(frag);
        CHECK(frag->status == 403);
        CHECK(r.fragment_audits.empty());
        CHECK(r.denied_rows("auth.permission_required") == denied_before);
        const auto twin = r.cookie_get(kTwin, erin);
        REQUIRE(twin);
        CHECK(twin->status == 403);
        CHECK(r.twin_audits.empty());
        CHECK(r.denied_rows("auth.permission_required") == denied_before + 1);
    }
    {   // (e) an engine session that HOLDS the read: one denied row on each surface, the same one.
        const auto raw = r.token("engine-bearer", kSlug, "readonly", "engine");
        r.clear_audits();
        const auto frag = r.bearer_get(kFragment, raw);
        const auto twin = r.bearer_get(kTwin, raw);
        REQUIRE(frag);
        REQUIRE(twin);
        CHECK(frag->status == 403);
        CHECK(twin->status == 403);
        CHECK(r.fragment_audits ==
              std::vector<std::string>{"engine_principal.list/denied/engine_session_denied"});
        CHECK(r.twin_audits == r.fragment_audits);
        CHECK(r.fragment_targets == kListTarget);
        CHECK(r.twin_targets == r.fragment_targets); // the same row, target and all
    }
    {   // (f) an engine session WITHOUT the read: the permission gate refuses, loudly on both
        // (an engine caller is never given the quiet treatment); no panel row, no twin row.
        const auto raw = r.token("nogrant-bearer", "engine:nogrant", "readonly", "engine");
        const auto denied_before = r.denied_rows("auth.permission_required");
        r.clear_audits();
        const auto frag = r.bearer_get(kFragment, raw);
        const auto twin = r.bearer_get(kTwin, raw);
        REQUIRE(frag);
        REQUIRE(twin);
        CHECK(frag->status == 403);
        CHECK(twin->status == 403);
        CHECK(r.fragment_audits.empty());
        CHECK(r.twin_audits.empty());
        CHECK(r.denied_rows("auth.permission_required") == denied_before + 2);
    }
}

TEST_CASE("engine panel audit: the in-page 'store unavailable' note is not a successful read and "
          "writes no success row",
          "[pg][settings][engine_principal][authz][audit][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn(), /*wire_engine_store=*/false};
    const auto frag = r.cookie_get(kFragment, r.cookie("root", auth::Role::admin));
    REQUIRE(frag);
    CHECK(frag->status == 200);
    CHECK_THAT(frag->body, ContainsSubstring("Engine Principals store unavailable"));
    CHECK(r.fragment_audits.empty());
}

namespace {
/// Runs one DDL statement on a fresh connection (the clone database is dropped with the test).
void exec_ddl(const std::string& dsn, const char* sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(conn.get(), sql, std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}
} // namespace

TEST_CASE("engine panel audit: an unreadable roster writes no success row, an unreadable "
          "credential count still writes the count=N one (the route answers 503 on both)",
          "[pg][settings][engine_principal][authz][audit][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.seed_revoked_principal(kRevokedId);
    const auto root = r.cookie("root", auth::Role::admin);

    SECTION("the roster cannot be read") {
        exec_ddl(db_.dsn(), "ALTER TABLE engine_principal_store.engine_principals "
                            "RENAME TO engine_principals_gone");
        r.clear_audits();
        const auto resp = r.cookie_get(kFragment, root);
        REQUIRE(resp);
        CHECK(resp->status == 200); // htmx swaps only a 2xx, so the note rides a 200
        CHECK_THAT(resp->body, ContainsSubstring("Engine principals unavailable"));
        CHECK_THAT(resp->body, !ContainsSubstring("<table"));
        CHECK(r.fragment_audits.empty()); // a view that read nothing is not a successful read
        CHECK(resp->get_header_value("Sec-Audit-Failed").empty());
    }

    SECTION("a credential count cannot be read") {
        exec_ddl(r.api_tokens.dsn(),
                 "ALTER TABLE api_token_store.api_tokens RENAME TO api_tokens_gone");
        r.clear_audits();
        const auto resp = r.cookie_get(kFragment, root);
        REQUIRE(resp);
        CHECK(resp->status == 200);
        CHECK_THAT(resp->body, ContainsSubstring("<span class=\"muted\">unavailable</span>"));
        // The roster WAS read, so the success row is written with the count the page shows; the
        // revoked row's Detail was not looked up, and says so.
        CHECK(r.fragment_audits ==
              std::vector<std::string>{"engine_principal.list/success/count=" +
                                       std::to_string(r.roster_size())});
        CHECK_THAT(resp->body, ContainsSubstring(detail_cell("(unavailable)")));
        // A failed credential read, unlike an audit-only failure, draws the Retry control (and
        // proves the audit-only case's "no Retry" assertion is looking for the right words).
        CHECK_THAT(resp->body, ContainsSubstring("Retry</button>"));
        // The Retry's sentence, whole: this C++ copy (kEngineRetryControl) and the page script's
        // (settings_ui.cpp, pinned in test_settings_page_ui.cpp) are hand copies of one sentence,
        // so each is pinned against the same literal and drift between them is a failing test.
        CHECK_THAT(resp->body, ContainsSubstring(std::string("<span class=\"hint\">") +
                                                 kRetrySentence + "</span>"));
        CHECK_THAT(std::string(kSettingsHtml), ContainsSubstring(kRetrySentence));
    }
}

TEST_CASE("engine panel audit: a dropped audit row and a locked audit table degrade the panel, "
          "they do not break it, and never widen what a caller without AuditLog:Read sees",
          "[pg][settings][engine_principal][authz][audit][chaos]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn(), /*wire_engine_store=*/true, /*audit_timeout_ms=*/500};
    r.seed_revoked_principal(kRevokedId);
    r.custom_reader_role("EngineReader", /*with_audit_read=*/false);
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("carol", auth::Role::user);
    r.account("dave", auth::Role::user);
    r.grant("carol", "EngineReader");
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    const auto carol = r.cookie("carol", auth::Role::user);
    const auto dave = r.cookie("dave", auth::Role::user);

    // Set-and-proceed: the success row is dropped, the panel still serves and says so in the
    // header (the twin's convention).
    r.drop_audit_writes = true;
    const auto dropped = r.cookie_get(kFragment, dave);
    REQUIRE(dropped);
    CHECK(dropped->status == 200);
    CHECK(dropped->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_THAT(dropped->body, ContainsSubstring(detail_cell(kRevokeMarker)));
    r.drop_audit_writes = false;

    // The audit table is locked: the revoke-detail lookup cannot answer (its pool statement
    // timeout is 500 ms in this rig), the panel is still a 200, and the marker is never shown.
    AuditTableLock lock{db_.dsn()};
    int served = 0, marker_leaks_a = 0;
    for (int i = 0; i < 3; ++i) {
        const auto a = r.cookie_get(kFragment, carol);
        const auto b = r.cookie_get(kFragment, dave);
        REQUIRE(a);
        REQUIRE(b);
        served += (a->status == 200) + (b->status == 200);
        marker_leaks_a += a->body.find("REVOKE-DETAIL-MARKER") != std::string::npos;
        // "(not recorded)" here would state a fact the failed read never established.
        CHECK_THAT(b->body, ContainsSubstring(detail_cell("(unavailable)")));
        CHECK_THAT(b->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR"));
        CHECK_THAT(b->body, !ContainsSubstring("LATER-RETRY"));
    }
    CHECK(served == 6);
    CHECK(marker_leaks_a == 0);
    lock.release();

    // Recovered without a restart.
    const auto after = r.cookie_get(kFragment, dave);
    REQUIRE(after);
    CHECK(after->status == 200);
    CHECK_THAT(after->body, ContainsSubstring(detail_cell(kRevokeMarker)));
}

TEST_CASE("engine panel audit: more than 200 revoke events never present a retry as the "
          "revocation's record without the Access panel's caveat",
          "[pg][settings][engine_principal][authz][audit][truncation]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    const auto dave = r.cookie("dave", auth::Role::user);

    // The REST DELETE is idempotent: every retry on a revoked principal writes a newer success
    // row `credentials_revoked=0`. Past the 200-event window the oldest success the panel can
    // see is a retry, not the revocation.
    auto retried = Rig::repeated(205, "success", kLaterRetryText);
    retried.push_back({100000, "success", kRevokeMarker}); // the original, beyond the window
    r.seed_revoked("engine:retried", retried);

    const auto a = r.cookie_get(kFragment, dave);
    REQUIRE(a);
    REQUIRE(a->status == 200);
    // The whole cell: the retry's text under the label, then the Access panel's caveat in the
    // same words and the same markup, inside the cell's span.
    CHECK_THAT(a->body, ContainsSubstring(detail_cell(kLaterRetryText, kTruncatedWithDetail)));
    CHECK_THAT(a->body, !ContainsSubstring("REVOKE-DETAIL-MARKER"));
    CHECK_THAT(a->body, !ContainsSubstring("none of the newest 200 succeeded"));
}

TEST_CASE("engine panel audit: the 200 vs 201 event boundary: 200 events are a complete history, "
          "201 drop the oldest and say so",
          "[pg][settings][engine_principal][authz][audit][truncation]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    const auto dave = r.cookie("dave", auth::Role::user);

    // Exactly 200 events (199 retries and the original, the oldest): nothing is dropped, so the
    // oldest success IS the original and no caveat is drawn.
    auto complete = Rig::repeated(199, "success", kLaterRetryText);
    complete.push_back({100000, "success", kRevokeMarker});
    r.seed_revoked("engine:events200", complete);
    const auto a = r.cookie_get(kFragment, dave);
    REQUIRE(a);
    REQUIRE(a->status == 200);
    CHECK_THAT(a->body, ContainsSubstring(detail_cell(kRevokeMarker)));
    CHECK_THAT(a->body, !ContainsSubstring("more than 200 revoke events"));
    CHECK_THAT(a->body, !ContainsSubstring("LATER-RETRY"));

    // 201 events (200 retries and the older original): the read fetches the 201st, drops it from
    // the window, and the caveat variant that implies truncation is drawn over a retry's text.
    // Without the drop the original would show here and no caveat would be needed.
    auto over = Rig::repeated(200, "success", kLaterRetryText);
    over.push_back({100000, "success", kRevokeMarker});
    r.seed_revoked("engine:events201", over);
    const auto b = r.cookie_get(kFragment, dave);
    REQUIRE(b);
    REQUIRE(b->status == 200);
    CHECK_THAT(b->body, ContainsSubstring(detail_cell(kLaterRetryText, kTruncatedWithDetail)));
    // The 200-event principal's row still reads complete beside it.
    CHECK_THAT(b->body, ContainsSubstring(detail_cell(kRevokeMarker)));
}

TEST_CASE("engine panel audit: more than 200 revoke events none of the newest 200 succeeded is not "
          "reported as 'not recorded' without a caveat",
          "[pg][settings][engine_principal][authz][audit][truncation]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();

    auto failing = Rig::repeated(205, "failure", kFailedRevokeText);
    failing.push_back({100000, "success", kRevokeMarker});
    r.seed_revoked("engine:failing", failing);

    const auto a = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(a);
    REQUIRE(a->status == 200);
    CHECK_THAT(a->body, ContainsSubstring(detail_cell("(not recorded)", kTruncatedNoSuccess)));
    CHECK_THAT(a->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR")); // store text never shown
    CHECK_THAT(a->body, !ContainsSubstring("not necessarily the original"));
}

TEST_CASE("engine panel audit: once the audit store fails the remaining revoked rows are not "
          "queried, and every row reads unavailable",
          "[pg][settings][engine_principal][authz][audit][chaos]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    // The pool's statement timeout is fixed when the pool is built, so the 12 seed INSERTs below
    // run under it too (a PgPool has no per-phase timeout); they are single-row inserts into an
    // unlocked table, and the lock is taken only after seeding.
    constexpr int kTimeoutMs = 400;
    constexpr int kRevoked = 4;
    Rig r{db_.dsn(), /*wire_engine_store=*/true, kTimeoutMs};
    for (int i = 0; i < kRevoked; ++i)
        r.seed_revoked_principal(("engine:revoked-latch" + std::to_string(i)).c_str());
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    const auto dave = r.cookie("dave", auth::Role::user);
    REQUIRE(r.audit_query_error_degrades() == 0);

    AuditTableLock lock{db_.dsn()};
    // Each lookup against the locked table waits out the pool's statement timeout and counts one
    // degrade, so without the latch this request holds a worker for kRevoked x kTimeoutMs and
    // counts kRevoked. The degrade counter is the deterministic observable: exactly ONE failed
    // read, however slow the box. The wall clock is only a loose sanity bound beside it.
    const auto t0 = std::chrono::steady_clock::now();
    const auto resp = r.cookie_get(kFragment, dave);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    lock.release();
    REQUIRE(resp);
    CHECK(resp->status == 200);
    INFO("elapsed " << elapsed << " ms for " << kRevoked << " revoked rows");
    CHECK(r.audit_query_error_degrades() == 1);
    CHECK(elapsed >= kTimeoutMs * 3 / 4);            // the one lookup did wait out its timeout
    CHECK(elapsed < (kRevoked - 1) * kTimeoutMs);    // generous: no per-row wait on a shared box
    CHECK(count_occurrences(resp->body, detail_cell("(unavailable)")) ==
          static_cast<std::size_t>(kRevoked));
    // Only the audit lookup failed, so the credential reads are fine and the page draws no Retry
    // control: the documented recovery is a reload (after copying any secret shown on the page).
    CHECK_THAT(resp->body, !ContainsSubstring("Retry"));
    CHECK_THAT(resp->body, !ContainsSubstring("Detail (earliest retained record): (not recorded)"));
    CHECK_THAT(resp->body, !ContainsSubstring("REVOKE-DETAIL-MARKER"));

    // Recovered without a restart: the next view looks every row up again.
    const auto after = r.cookie_get(kFragment, dave);
    REQUIRE(after);
    CHECK(after->status == 200);
    CHECK(count_occurrences(after->body, detail_cell(kRevokeMarker)) ==
          static_cast<std::size_t>(kRevoked));
    CHECK_THAT(after->body, !ContainsSubstring("(unavailable)"));
}

TEST_CASE("engine panel audit: the AuditLog:Read probe is issued only when a revoked row exists; a "
          "plain bearer without it writes a denial row only then",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineReader", /*with_audit_read=*/false);
    r.account("carol", auth::Role::user);
    r.grant("carol", "EngineReader");
    r.rbac_on();
    const auto raw = r.plain_token("carol-plain", "carol");

    // No revoked row: nothing needs the audit trail, so the probe is not issued and a token that
    // lacks AuditLog:Read leaves no auth.permission_required row for a view it was admitted to.
    const auto before = r.denied_rows("auth.permission_required");
    const auto none = r.bearer_get(kFragment, raw);
    REQUIRE(none);
    CHECK(none->status == 200);
    CHECK_THAT(none->body, ContainsSubstring(kSlug));
    CHECK(r.denied_rows("auth.permission_required") == before);

    // Revoked rows exist: the probe is issued, ONCE per view however many there are (three here,
    // so a per-row probe would write three). CHARACTERISATION, not a desired property: a token
    // (unlike an interactive cookie session) keeps the probe's denial row on a 200 view, and
    // documentation says so (audit-log.md). Asserted so that a later change is deliberate.
    r.seed_revoked_principal(kRevokedId);
    r.seed_revoked_principal("engine:revoked2");
    r.seed_revoked_principal("engine:revoked3");
    const auto some = r.bearer_get(kFragment, raw);
    REQUIRE(some);
    CHECK(some->status == 200);
    // Every revoked row reads the withheld text (the probe's answer is memoised, not re-asked
    // and not read as "admitted" for rows 2..N), and none of the audit text leaks.
    CHECK(count_occurrences(some->body,
                            detail_cell("(withheld: needs AuditLog:Read, or it could not be "
                                        "confirmed)")) == 3);
    CHECK_THAT(some->body, !ContainsSubstring("REVOKE-DETAIL-MARKER"));
    CHECK_THAT(some->body, !ContainsSubstring("FAILED-REVOKE-STORE-ERROR"));
    CHECK_THAT(some->body, !ContainsSubstring("LATER-RETRY"));
    CHECK(r.denied_rows("auth.permission_required") == before + 1);
    // The served-but-denied row names the permission it lacked (RBAC-on wording,
    // auth_routes.cpp `require_permission`/`probe_permission`).
    CHECK(std::ranges::count(r.denied_details("auth.permission_required"),
                             std::string("RBAC denied AuditLog:Read")) == 1);

    // The same caller as a cookie session: the probe is quiet, no row.
    const auto cookie = r.cookie_get(kFragment, r.cookie("carol", auth::Role::user));
    REQUIRE(cookie);
    CHECK(cookie->status == 200);
    CHECK(r.denied_rows("auth.permission_required") == before + 1);
}

TEST_CASE("engine panel audit: markup in a revoke row's detail is escaped, never rendered",
          "[pg][settings][engine_principal][authz][audit][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    // An MCP operator's typed reason is the committed detail, so it is attacker-influenced text.
    r.seed_revoked("engine:markup1", {{300, "success", "<img src=x onerror=1>&\"'"}});

    const auto resp = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(resp);
    REQUIRE(resp->status == 200);
    // Every metacharacter of the seed, escaped in order, inside the cell.
    CHECK_THAT(resp->body, ContainsSubstring(detail_cell(
                               "&lt;img src=x onerror=1&gt;&amp;&quot;&#39;")));
    CHECK_THAT(resp->body, !ContainsSubstring("<img"));
}

TEST_CASE("engine panel audit: the three Detail cell states read as their exact literals",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    // Revoked in the engine store with NO committed revoke row in the audit trail.
    r.seed_revoked("engine:norow", {});
    r.custom_reader_role("EngineReader", /*with_audit_read=*/false);
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("carol", auth::Role::user);
    r.account("dave", auth::Role::user);
    r.grant("carol", "EngineReader");
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();

    const auto dave = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(dave);
    REQUIRE(dave->status == 200);
    CHECK_THAT(dave->body, ContainsSubstring(detail_cell("(not recorded)")));
    // No truncation caveat without truncation, in either wording.
    CHECK_THAT(dave->body, !ContainsSubstring("more than 200 revoke events"));
    CHECK_THAT(dave->body, !ContainsSubstring("none of the newest 200 succeeded"));

    // Hedged like the Access tokens panel: the probe failing for any reason reads the same.
    const auto carol = r.cookie_get(kFragment, r.cookie("carol", auth::Role::user));
    REQUIRE(carol);
    REQUIRE(carol->status == 200);
    CHECK_THAT(carol->body, ContainsSubstring(detail_cell(
                                "(withheld: needs AuditLog:Read, or it could not be confirmed)")));
    CHECK_THAT(carol->body, !ContainsSubstring("(not recorded)"));
}

TEST_CASE("engine panel audit: a committed revoke with an empty detail (an MCP revoke given no "
          "reason) reads '(not recorded)', and a later retry's text is not shown in its place",
          "[pg][settings][engine_principal][authz][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    // The MCP tool's `reason` is optional, so its committed success row can carry no detail. The
    // oldest success is still that row, whatever a later retry wrote.
    r.seed_revoked("engine:noreason", {{300, "success", ""}});
    r.seed_revoked("engine:noreason-retried",
                   {{300, "success", ""}, {100, "success", kLaterRetryText}});

    const auto resp = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(resp);
    REQUIRE(resp->status == 200);
    CHECK(count_occurrences(resp->body, detail_cell("(not recorded)")) == 2);
    CHECK_THAT(resp->body, !ContainsSubstring("LATER-RETRY"));
    // A short history: no truncation caveat in either wording.
    CHECK_THAT(resp->body, !ContainsSubstring("more than 200 revoke events"));
}

namespace {
/// Makes the credential read of exactly ONE principal (`engine:poison`) fail in the token
/// store's clone database while every other principal's read answers: the table is renamed
/// behind a view whose filter raises, at a cost that orders it after the other filters, for a
/// row of that principal only. (The credential row must exist before this runs.)
void poison_credential_read_for(const std::string& token_dsn) {
    exec_ddl(token_dsn,
             "CREATE FUNCTION public.yuzu_test_poison(p text) RETURNS boolean LANGUAGE plpgsql "
             "COST 1000000 AS $f$ BEGIN IF p = 'engine:poison' THEN "
             "RAISE EXCEPTION 'yuzu test poison'; END IF; RETURN TRUE; END $f$");
    exec_ddl(token_dsn, "ALTER TABLE api_token_store.api_tokens RENAME TO api_tokens_real");
    exec_ddl(token_dsn, "CREATE VIEW api_token_store.api_tokens AS SELECT * FROM "
                        "api_token_store.api_tokens_real "
                        "WHERE public.yuzu_test_poison(principal_id)");
}
} // namespace

TEST_CASE("engine panel audit: rows rendered before a credential-read failure keep their real "
          "Detail, the row that failed and those after it read unavailable",
          "[pg][settings][engine_principal][authz][audit][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, engine_panel_tpl);
    Rig r{db_.dsn()};
    r.custom_reader_role("EngineAuditReader", /*with_audit_read=*/true);
    r.account("dave", auth::Role::user);
    r.grant("dave", "EngineAuditReader");
    r.rbac_on();
    r.seed_revoked_principal("engine:okfirst");
    r.seed_revoked_principal("engine:poison");
    r.seed_revoked_principal("engine:after");
    // The roster is ordered by created_at; pin the order so the failing row is the second
    // revoked row, not whichever the clock ties happened to give.
    int64_t at = 100;
    for (const char* id : {kSlug, "engine:okfirst", "engine:poison", "engine:after"})
        exec_ddl(db_.dsn(), ("UPDATE engine_principal_store.engine_principals SET created_at = " +
                             std::to_string(at++) + " WHERE principal_id = '" + id + "'")
                                .c_str());
    // A live credential for the poisoned principal, so its credential read has a row to trip on.
    (void)r.token("poison-cred", "engine:poison", "readonly", "engine");
    poison_credential_read_for(r.api_tokens.dsn());

    const auto resp = r.cookie_get(kFragment, r.cookie("dave", auth::Role::user));
    REQUIRE(resp);
    REQUIRE(resp->status == 200);
    // Rendered before the failure: the real audit text. At and after it: not looked up.
    CHECK(count_occurrences(resp->body, detail_cell(kRevokeMarker)) == 1);
    CHECK(count_occurrences(resp->body, detail_cell("(unavailable)")) == 2);
    CHECK(count_occurrences(resp->body, "<span class=\"muted\">unavailable</span>") == 2);
    CHECK_THAT(resp->body, ContainsSubstring("Retry</button>"));
    CHECK_THAT(resp->body, !ContainsSubstring("(not recorded)"));
    // POSITION, not just counts: the committed text sits in the row BEFORE the failing one, and
    // the first "(unavailable)" cell is at or after the failing row (rows render in roster order).
    const auto ok_id = resp->body.find("engine:okfirst");
    const auto marker = resp->body.find(detail_cell(kRevokeMarker));
    const auto poison_id = resp->body.find("engine:poison");
    const auto first_unavailable = resp->body.find(detail_cell("(unavailable)"));
    const auto after_id = resp->body.find("engine:after");
    REQUIRE(ok_id != std::string::npos);
    REQUIRE(marker != std::string::npos);
    REQUIRE(poison_id != std::string::npos);
    REQUIRE(first_unavailable != std::string::npos);
    REQUIRE(after_id != std::string::npos);
    CHECK(ok_id < marker);
    CHECK(marker < poison_id);
    CHECK(poison_id < first_unavailable);
    CHECK(first_unavailable < after_id);
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
