/**
 * test_auth_routes.cpp — Unit tests for AuthRoutes session resolution and audit
 * event construction.
 *
 * Regression coverage for the audit-trail bug where AuthRoutes::make_audit_event
 * resolved the principal from session cookies only, leaving `principal=""` on
 * every audit row written by an API-token-authenticated request (REST automation
 * and every MCP tool call). The fix extracted resolve_session(req), used by
 * require_auth, make_audit_event, and emit_event alike. These tests lock that
 * helper's three-branch contract (cookie / Bearer / X-Yuzu-Token) so future
 * refactors cannot silently re-introduce the gap.
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "test_tag_store_pg_helper.hpp" // TagStorePg — ADR-0050 PG port
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp" // PgConn/PgResult — the CH-4 saboteur's second connection
#include "rbac_store.hpp"
#include "service_scope_policy.hpp"
#include "tag_store.hpp"
#include "../test_helpers.hpp" // YUZU_REQUIRE_PG_DB_TPL / PgTestTemplate / TempDbFile
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;

namespace {

/// Holds every store + ref AuthRoutes needs so the test body stays compact.
/// Stores that the methods under test do not dereference (RbacStore,
/// ManagementGroupStore, TagStore, AuditStore) are passed as nullptr to keep
/// setup minimal — see auth_routes.cpp:289-344 for the read set.
struct AuthRoutesFixture {
    Config cfg{};
    yuzu::MetricsRegistry metrics; // wired so synthesize_token_session's counters fire (review #DG-5)
    auth::AuthManager auth_mgr{};
    fs::path tmp_dir;
    // ApiTokenStore ported to Postgres (PR 4.1) — clones an ephemeral database
    // via the shared ApiTokenStorePg helper. Constructing this fixture now
    // SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset, and
    // FAILs when it is set but broken (same posture as every other [pg] test).
    yuzu::test::ApiTokenStorePg api_tokens;
    yuzu::test::AnalyticsEventStorePg analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;  // empty
    std::unique_ptr<AuthRoutes> ar;

    AuthRoutesFixture() {
        // Per-fixture unique tmp dir so concurrent Catch2 runs (`-j`) cannot
        // race on shared SQLite files. PID alone is not enough — every test
        // case in the same process shares it.
        static std::atomic<unsigned> seq{0};
        tmp_dir = fs::temp_directory_path() /
                  ("yuzu_auth_routes_test_" + std::to_string(::getpid()) + "_" +
                   std::to_string(seq.fetch_add(1)));
        fs::create_directories(tmp_dir);

        // Register a known user so synthesize_token_session resolves a real role.
        REQUIRE(auth_mgr.upsert_user("test_user", "test_password", auth::Role::admin));
        auth_mgr.set_metrics_registry(&metrics);

        ar = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            /*rbac_store=*/nullptr,
            api_tokens.get(),
            /*audit_store=*/nullptr,
            /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr,
            analytics.get(),
            oidc_mu, oidc_provider);
    }

    ~AuthRoutesFixture() {
        std::error_code ec;
        // Drop stores before removing the directory so file handles close cleanly.
        ar.reset();
        analytics.reset();
        api_tokens.reset();
        fs::remove_all(tmp_dir, ec);
    }

    std::string mint_token() {
        auto raw = api_tokens->create_token("unit-test", "test_user");
        REQUIRE(raw.has_value());
        return *raw;
    }

    // Read a metric counter value (matches HardenedHarness::counter,
    // test_auth_routes_hardened.cpp — same review-#1735-derived pattern).
    double counter(const std::string& name, const yuzu::Labels& labels = {}) {
        return labels.empty() ? metrics.counter(name).value()
                              : metrics.counter(name, labels).value();
    }
};

httplib::Request request_with_header(const std::string& name, const std::string& value) {
    httplib::Request req;
    req.headers.emplace(name, value);
    return req;
}

int64_t service_scope_flip_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Distinct template name from every other file's "rbacstore*" registrations
// (test_authz_gates.cpp's "rbacstore_authzgates", test_list_read_confinement.cpp's
// "rbacstore", test_engine_principal_integration.cpp's "rbacstore_integ") —
// same registry, no shared-state risk.
yuzu::test::PgTestTemplate service_scope_flip_rbac_tpl{
    "rbacstore_svcscopeflip", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac (svc scope flip) template: store failed to migrate/seed");
    }};

/// Minimal real-RBAC rig for `AuthRoutes::require_permission`'s and
/// `require_scoped_permission`'s service-scoped branches (#2298 PR 3 — the
/// flip). `mgmt_group_store_` stays nullptr (neither function under test
/// consults it directly; `confine_agent_target` does, and `GatesRig` in
/// test_authz_gates.cpp is the fuller rig for that). Grants are set on real,
/// catalogued (securable, operation) pairs (role_permissions FK-references
/// securable_types/operations, so a synthetic name is rejected outright, not
/// merely untested) — always set EXPLICITLY within each test so the
/// precondition is that test's own, not incidental to ITServiceOwner's real
/// default seed.
struct ServiceScopeFlipRig {
    Config cfg{};
    yuzu::MetricsRegistry metrics; // wired so the default-deny counter fires
    auth::AuthManager auth_mgr{};
    pg::PgPool pool;
    RbacStore rbac;
    yuzu::test::ApiTokenStorePg api_tokens;
    // ADR-0050 (TagStore -> Postgres): declaration order load-bearing —
    // tag_bundle must construct before the `tags` reference binds to it.
    yuzu::test::TagStorePg tag_bundle;
    TagStore& tags = *tag_bundle;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    explicit ServiceScopeFlipRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 2}}, rbac{pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        rbac.set_rbac_enabled(true); // enforcement in effect, not legacy-open
        auth_mgr.set_metrics_registry(&metrics);
        REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                          /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr,
                                          &tags, /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    /// Mint a token as "minter" — empty `scope_service` ⇒ a non-service token.
    /// `mcp_tier` defaults empty; pass it non-empty to mint a token carrying
    /// BOTH attributes (UP-1: no mutual-exclusivity check exists at mint
    /// time, so this combination is a real mintable input, not a
    /// hypothetical).
    std::string mint(const std::string& scope_service = {}, const std::string& mcp_tier = {}) {
        auto raw = api_tokens->create_token("svc-flip-test", "minter",
                                            service_scope_flip_now_epoch() + 3600, scope_service,
                                            mcp_tier);
        REQUIRE(raw.has_value());
        return *raw;
    }

    double counter(const std::string& name, const yuzu::Labels& labels = {}) {
        return labels.empty() ? metrics.counter(name).value()
                              : metrics.counter(name, labels).value();
    }
};

}  // namespace

TEST_CASE("AuthRoutes::resolve_session — Bearer token populates principal",
          "[pg][auth_routes]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
    CHECK(session->mcp_tier.empty());
}

TEST_CASE("AuthRoutes::resolve_session — X-Yuzu-Token populates principal",
          "[pg][auth_routes]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("X-Yuzu-Token", raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
}

TEST_CASE("AuthRoutes::resolve_session — session cookie populates principal",
          "[pg][auth_routes]") {
    AuthRoutesFixture fix;
    auto cookie = fix.auth_mgr.authenticate("test_user", "test_password");
    REQUIRE(cookie.has_value());
    auto req = request_with_header("Cookie", "yuzu_session=" + *cookie);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
}

TEST_CASE("AuthRoutes::resolve_session — no auth returns nullopt",
          "[pg][auth_routes]") {
    AuthRoutesFixture fix;
    httplib::Request req;
    auto session = fix.ar->resolve_session(req);
    CHECK_FALSE(session.has_value());
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from Bearer token "
          "(regression: mcp.* audit rows had empty principal)",
          "[pg][auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    auto event = fix.ar->make_audit_event(req, "mcp.list_agents", "success");
    CHECK(event.action == "mcp.list_agents");
    CHECK(event.result == "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
    CHECK(event.principal_class == "agent"); // bearer token (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from X-Yuzu-Token",
          "[pg][auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("X-Yuzu-Token", raw);

    auto event = fix.ar->make_audit_event(req, "rest.api.call", "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
    CHECK(event.principal_class == "agent"); // X-Yuzu-Token (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from session cookie",
          "[pg][auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto cookie = fix.auth_mgr.authenticate("test_user", "test_password");
    REQUIRE(cookie.has_value());
    auto req = request_with_header("Cookie", "yuzu_session=" + *cookie);

    auto event = fix.ar->make_audit_event(req, "dashboard.action", "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
    CHECK(event.session_id == *cookie);
    CHECK(event.principal_class == "human"); // session cookie (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::make_audit_event — empty principal when no auth present",
          "[pg][auth_routes][audit]") {
    AuthRoutesFixture fix;
    httplib::Request req;
    auto event = fix.ar->make_audit_event(req, "anonymous", "success");
    CHECK(event.principal.empty());
    CHECK(event.principal_role.empty());
    CHECK(event.principal_class == "none"); // no credential (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::emit_event — analytics event records principal from "
          "Bearer token (regression: same shape as audit_event bug)",
          "[pg][auth_routes][analytics]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    fix.ar->emit_event("test.event", req);

    // Drain the buffer (the store flushes on demand via query_recent).
    auto events = fix.analytics->query_recent(10);
    REQUIRE(events.has_value()); // degrade-distinguishable seam: not nullopt
    REQUIRE_FALSE(events->empty());
    bool found = false;
    for (const auto& e : *events) {
        if (e.event_type == "test.event") {
            CHECK(e.principal == "test_user");
            CHECK(e.principal_role == "admin");
            found = true;
            break;
        }
    }
    CHECK(found);
}

// ---------------------------------------------------------------------------
// require_admin scope-enforcement tests (#520)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_admin — service-scoped token from admin is rejected",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // Mint a token scoped to "finance-svc"; creator is an admin.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("scoped", "test_user",
                                            now + 3600, "finance-svc", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("service-scoped tokens cannot perform admin operations") !=
          std::string::npos);
    // #1470: the require_admin denial now emits the unified A4 envelope with a
    // correlation_id echoed on the header. require_admin gates a whole route,
    // not a securable:operation, so there is deliberately NO `permission` field.
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"].contains("retry_after_ms")); // A4: always present (null here)
    CHECK_FALSE(j["error"].contains("permission"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

// ---------------------------------------------------------------------------
// synthesize_token_session role cap for service-scoped tokens
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::resolve_session — a service-scoped token from an admin "
          "resolves to the user floor, not the minter's live role",
          "[pg][auth_routes][scope]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "finance-svc", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->token_scope_service == "finance-svc");
    // The token's minter ("test_user") is admin — before the cap this would
    // have inherited role == admin. require_admin() already independently
    // denies any service-scoped token on token_scope_service alone (see the
    // test above), so this specifically proves the OTHER consumers — the
    // inline effective_role(*session) == admin checks that have no such
    // independent guard (e.g. workflow/instruction role-gated step approval,
    // MCP bundle-ownership checks) — no longer see admin authority either.
    CHECK(session->role == auth::Role::user);
    // DG-5: the debuggability counter fires exactly once for this capped session.
    CHECK(fix.counter("yuzu_auth_service_token_role_capped_total") == 1.0);
}

TEST_CASE("AuthRoutes::resolve_session — a non-scoped token from an admin still "
          "carries the minter's live admin role (regression)",
          "[pg][auth_routes][scope]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token(); // no scope_service — plain token minted by test_user (admin)
    auto req = request_with_header("Authorization", "Bearer " + raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->token_scope_service.empty());
    CHECK(session->role == auth::Role::admin);
    // Negative control: an uncapped session must never increment the counter.
    CHECK(fix.counter("yuzu_auth_service_token_role_capped_total") == 0.0);
}

TEST_CASE("AuthRoutes::resolve_session — a service-scoped token from a plain "
          "user-role creator resolves to the user floor (no double-application)",
          "[pg][auth_routes][scope]") {
    AuthRoutesFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("plain_user", "password1234", auth::Role::user));
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw =
        fix.api_tokens->create_token("scoped", "plain_user", now + 3600, "finance-svc", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->token_scope_service == "finance-svc");
    CHECK(session->role == auth::Role::user);
}

TEST_CASE("AuthRoutes::resolve_session — a token carrying BOTH scope_service and "
          "mcp_tier still resolves to the user floor (the cap does not consult "
          "mcp_tier)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw = fix.api_tokens->create_token("scoped-and-tiered", "test_user", now + 3600,
                                            "finance-svc", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->token_scope_service == "finance-svc");
    CHECK(session->mcp_tier == "supervised");
    CHECK(session->role == auth::Role::user);
    // The counter fires regardless of mcp_tier, matching the cap's own condition.
    CHECK(fix.counter("yuzu_auth_service_token_role_capped_total") == 1.0);
}

TEST_CASE("AuthRoutes::require_admin — MCP token from admin is rejected",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-tok", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP tokens cannot perform admin operations") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_admin — unscoped admin token is accepted (regression guard)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto raw = fix.api_tokens->create_token("plain", "test_user");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK(ok);
    CHECK(res.status != 403);
}

// ---------------------------------------------------------------------------
// require_permission MCP-tier enforcement tests (#520)
// The tier (readonly/operator/supervised) is the primary boundary; the creator's
// actual role is the secondary RBAC boundary. RBAC-disabled deployments still work.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — readonly MCP tier blocks Execute regardless of RBAC",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // Fixture has rbac_store=nullptr (RBAC disabled). test_user is admin.
    // Tier enforcement must fire regardless of RBAC state.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rp", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP token tier does not allow Execution:Execute") != std::string::npos);
    // #1470: require_permission's MCP-tier denial now emits the unified A4
    // envelope — a correlation_id (echoed on the header) and the structured
    // securable_type:operation permission field (kPermissionDenied §A4).
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["permission"].get<std::string>() == "Execution:Execute");
    CHECK(j["error"].contains("retry_after_ms"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("AuthRoutes::require_permission — readonly MCP tier allows Read without RBAC",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // readonly tier permits Read; creator is admin; RBAC disabled → should pass.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rp2", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Infrastructure", "Read");
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// P2 #11 security regression guard: operator-tier ApiToken:Write must stay
// blocked on `AuthRoutes::require_permission` — the exact chokepoint POST
// /api/v1/tokens (create_token) and its settings twin POST
// /api/settings/api-tokens both call with nothing else downstream, so one
// test here covers both routes. Full narrative (two abandoned fix attempts
// + why the shipped ApiToken:Rotate split is correct) lives ONCE, at
// mcp_policy.hpp's tier_allows() operator-tier comment. See "operator MCP
// tier IS allowed ApiToken:Rotate" below for the positive half.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — operator MCP tier is BLOCKED from ApiToken:Write "
          "(round-3 security regression guard — gates both POST /api/v1/tokens and its "
          "settings twin POST /api/settings/api-tokens)",
          "[pg][auth_routes][scope][mcp][security]") {
    AuthRoutesFixture fix;
    // Creator (test_user) is admin and RBAC is disabled on this fixture — if
    // tier_allows() did not stop this token first, the legacy RBAC-off
    // fallback would pass it straight through on the creator's admin role,
    // which is precisely the second half of the escalation this test guards
    // against (a caller-chosen mcp_tier does not narrow the token's
    // inherited authority once past the tier gate).
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-atw-op", "test_user",
                                            now + 3600, "", "operator");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Write");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP token tier does not allow ApiToken:Write") != std::string::npos);
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK(j["error"]["permission"].get<std::string>() == "ApiToken:Write");
}

// gov security-guardian fix round (#2146 B4): ApiToken:Write joined the
// supervised-tier requires_approval() list (mcp_policy.hpp) to close a real
// self-mint-a-fresh-untiered-token gap shared by REST and MCP. This test
// used to assert the OLD (pre-fix) behavior -- tier_allows passing supervised
// straight through with no approval check at all. tier_allows() itself is
// STILL untouched (supervised still passes it, unlike operator -- see the
// sibling test above); what changed is requires_approval() now also fires,
// so a plain REST-transport require_permission() call correctly denies
// pending a ticket, same shape as the Execution:Execute case below.
TEST_CASE("AuthRoutes::require_permission - supervised MCP token blocked from approval-gated "
          "ApiToken:Write on a REST transport (control: tier_allows itself is untouched, only "
          "requires_approval changed)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-atw-sup", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/api/v1/tokens"; // a REST (non-MCP) transport
    httplib::Response res;

    // tier_allows("supervised", ApiToken, Write) -> true (unchanged)
    // requires_approval("supervised", ApiToken, Write) -> true (this fix round)
    // -> on a REST transport the approval gate is enforced here so a
    //    supervised token cannot self-mint a fresh credential by calling
    //    POST /api/v1/tokens directly, bypassing the MCP ticket flow (#520
    //    class: a tier cannot be bypassed by switching endpoints).
    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Write");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

// Complement of the above: on the MCP JSON-RPC transport the C8 gate in
// mcp_server.cpp is the authoritative approval gate for create_api_token
// (ticket-then-recall, #289), so require_permission must NOT re-deny it here.
TEST_CASE("AuthRoutes::require_permission - ApiToken:Write approval gate is skipped on the "
          "MCP transport (create_api_token's own C8 gate is authoritative)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-atw-mcp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/mcp/v1/"; // the MCP transport -- C8 governs approval
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Write");
    CHECK(ok);
    CHECK(res.body.find("approval") == std::string::npos); // the approval gate did not fire
}

// ---------------------------------------------------------------------------
// #4031/#520 security regression guard: a MINTED, REAL MCP token must be
// blocked from Enrollment/OidcConfig through the actual production
// chokepoint (require_permission -> tier_allows), not just at the
// tier_allows() unit level (see mcp_policy.hpp's TEST_CASEs in
// test_mcp_server.cpp for that). This is the same class of gap the
// ApiToken:Write regression guards above exist to close: with RBAC
// disabled (this fixture's default) and an admin creator, the legacy
// RBAC-off fallback would pass the request straight through on the
// creator's role if tier_allows() did not stop it first. supervised tier
// is the sharpest case — it is the one tier that otherwise allows
// everything, so it is the tier where an unguarded Enrollment/OidcConfig
// read would have been most reachable.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — supervised MCP tier is BLOCKED from "
          "Enrollment:Read and OidcConfig:Read (#4031/#520 server-administration deny, "
          "verified through the real minted-token chokepoint, not just tier_allows() in "
          "isolation)",
          "[pg][auth_routes][scope][mcp][security]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-enr-sup", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());

    {
        auto req = request_with_header("Authorization", "Bearer " + *raw);
        httplib::Response res;
        bool ok = fix.ar->require_permission(req, res, "Enrollment", "Read");
        CHECK_FALSE(ok);
        CHECK(res.status == 403);
        CHECK(res.body.find("MCP token tier does not allow Enrollment:Read") !=
              std::string::npos);
    }
    {
        auto req = request_with_header("Authorization", "Bearer " + *raw);
        httplib::Response res;
        bool ok = fix.ar->require_permission(req, res, "OidcConfig", "Read");
        CHECK_FALSE(ok);
        CHECK(res.status == 403);
        CHECK(res.body.find("MCP token tier does not allow OidcConfig:Read") !=
              std::string::npos);
    }
}

TEST_CASE("AuthRoutes::require_permission — operator MCP tier IS allowed ApiToken:Rotate "
          "(the actual fix: a DISTINCT operation from ApiToken:Write, giving REST rotate/"
          "confirm true parity with the MCP tools without touching ApiToken:Write at all)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-atr-op", "test_user",
                                            now + 3600, "", "operator");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Rotate");
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// #2963 legacy (RBAC-off) self-service allowlist: ApiToken:Rotate must be
// reachable by a plain non-admin, non-MCP-tier caller (a cookie session or an
// untiered PAT) — composed with the legacy "non-Read needs admin" rule this
// was previously admin-only for everyone else in the shipped default (RBAC
// disabled) configuration, defeating the reason the feature exists. Safe
// because ApiTokenStore::rotate_token/confirm_token_rotation independently
// refuse any requesting_user other than the resolved row's own
// principal_id — this gate only decides "may attempt".
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — a plain non-admin, untiered caller IS allowed "
          "ApiToken:Rotate under RBAC-off (legacy self-service allowlist, #2963)",
          "[pg][auth_routes][legacy][self_service]") {
    AuthRoutesFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("plain_user", "password1234", auth::Role::user));
    auto raw = fix.api_tokens->create_token("plain-user-pat", "plain_user");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Rotate");
    CHECK(ok);
}

TEST_CASE("AuthRoutes::require_permission — the #2963 self-service allowlist does NOT widen "
          "to a sibling non-Read operation — a plain non-admin caller is still denied "
          "ApiToken:Write under RBAC-off",
          "[pg][auth_routes][legacy][self_service]") {
    AuthRoutesFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("plain_user", "password1234", auth::Role::user));
    auto raw = fix.api_tokens->create_token("plain-user-pat-2", "plain_user");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Write");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
}

TEST_CASE("AuthRoutes::require_scoped_permission — the #2963 self-service allowlist applies "
          "identically to the scoped variant (kept in sync, per its own comment)",
          "[pg][auth_routes][legacy][self_service]") {
    AuthRoutesFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("plain_user", "password1234", auth::Role::user));
    auto raw = fix.api_tokens->create_token("plain-user-pat-3", "plain_user");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "ApiToken", "Rotate", "agent-1");
    CHECK(ok);
}

TEST_CASE("AuthRoutes::require_permission — an operator-tier MCP token minted by a "
          "NON-ADMIN creator now passes ApiToken:Rotate under RBAC-off (#2963's legacy "
          "allowlist has live effect on MCP too, not just REST — the mcp_tier branch "
          "falls through to legacy on a passing tier check, it does not return true)",
          "[pg][auth_routes][legacy][self_service][mcp]") {
    AuthRoutesFixture fix;
    // Deliberately NON-admin creator — the pre-existing sibling test at
    // "operator MCP tier IS allowed ApiToken:Rotate" above uses `test_user`,
    // which the fixture registers as admin, so it cannot distinguish "the
    // mcp_tier branch alone admits this" from "it fell through and the
    // legacy branch's OWN admin-role check admitted it separately" — both
    // would pass that test. This one pins the actual claim: before #2963,
    // this exact token (operator tier, non-admin creator, RBAC-off) was
    // DENIED at the legacy branch after tier_allows() let it fall through;
    // #2963's legacy self-service allowlist is what makes it pass now.
    REQUIRE(fix.auth_mgr.upsert_user("plain_operator_user", "password1234", auth::Role::user));
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-atr-op-nonadmin", "plain_operator_user",
                                            now + 3600, "", "operator");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "ApiToken", "Rotate");
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// #4028/#520 security regression guard: an admin-owned MCP token (any tier)
// must still be blocked from the new settings read-twins' securables, even
// though those routes gate via require_permission (not require_admin) and
// even though topology-floor's legacy-role fallback would otherwise admit
// an admin-owned MCP session (see auth_routes.cpp's "an admin's MCP token
// passes the floor here ... that is intended" note, and the AccessReview/
// UserManagement/EnginePrincipal routes that deliberately rely on it). The
// fix lives at the tier_allows() chokepoint (mcp_policy.hpp), not here —
// this test exercises the real end-to-end require_permission() path so a
// future change to either layer can't silently reopen it. Companion
// tier_allows()-only tests: test_mcp_server.cpp "no tier admits the #4028
// server-administration securables".
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — no MCP tier (incl. readonly, admin-owned) "
          "reaches the #4028 settings-administration securables",
          "[pg][auth_routes][scope][mcp][security]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    for (const std::string_view securable :
         {"TlsConfig", "PluginSigning", "ServerConfig", "AnalyticsConfig"}) {
        CAPTURE(securable);
        // test_user is admin and RBAC is disabled on this fixture — the exact
        // combination that lets an admin-owned MCP token fall through the
        // legacy topology-floor branch for securables that don't carry this
        // tier-level deny.
        auto raw = fix.api_tokens->create_token(
            "mcp-settings-ro-" + std::string(securable), "test_user", now + 3600, "", "readonly");
        REQUIRE(raw.has_value());
        auto req = request_with_header("Authorization", "Bearer " + *raw);
        httplib::Response res;

        bool ok = fix.ar->require_permission(req, res, std::string(securable), "Read");
        CHECK_FALSE(ok);
        CHECK(res.status == 403);
        CHECK(res.body.find("MCP token tier does not allow") != std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// require_scoped_permission MCP-tier enforcement tests (#520)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_scoped_permission — operator MCP tier allows Execute without RBAC",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // operator tier permits Execution:Execute; creator is admin; RBAC disabled → pass.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rsp", "test_user",
                                            now + 3600, "", "operator");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Execution", "Execute", "agent-1");
    CHECK(ok);
}

TEST_CASE("AuthRoutes::require_scoped_permission — readonly MCP tier blocks Execute",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rsp2", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Execution", "Execute", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP token tier does not allow Execution:Execute") != std::string::npos);
    // #1549 review MEDIUM: the scoped-gate denial now carries the A4 envelope —
    // a correlation_id and a structured securable_type:operation permission field.
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["permission"].get<std::string>() == "Execution:Execute");
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    // The body's correlation_id is echoed on the X-Correlation-Id header so a caller
    // can correlate without parsing the body.
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

// ---------------------------------------------------------------------------
// supervised-tier approval enforcement on REST transport (sec-H1 / CH-1)
// The MCP server DENIES supervised+destructive ops (kTierDenied) because Phase 2
// re-dispatch is not built — it deliberately does NOT return kApprovalRequired,
// which the A4 contract reserves for a pollable approval (approval_id +
// status_url) it cannot honestly produce. The REST transport must mirror that
// denial — a supervised MCP token must not bypass the approval gate by switching
// endpoints.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — supervised MCP token blocked from approval-gated Execute",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-rp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/api/v1/executions"; // a REST (non-MCP) transport
    httplib::Response res;

    // tier_allows("supervised", Execution, Execute) → true
    // requires_approval("supervised", Execution, Execute) → true
    // → on a REST transport the approval gate is enforced here so an MCP token
    //   cannot bypass the ticket flow by switching endpoints (#520).
    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

// Complement of the above: on the MCP JSON-RPC transport (`/mcp/v1/`) the C8 gate
// in mcp_server.cpp is the authoritative approval gate (ticket-then-recall, #289),
// so require_permission must NOT re-deny an approval-gated op here — otherwise the
// recall consumes the ticket then dies at the auth layer. This is the exact
// integration bug the UAT smoke caught (the MCP unit harness mocks perm_fn).
TEST_CASE("AuthRoutes::require_permission — approval gate is skipped on the MCP transport",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-mcp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/mcp/v1/"; // the MCP transport — C8 governs approval
    httplib::Response res;

    // Same (supervised, Execution:Execute) that the REST case above denies — here
    // the approval denial must NOT fire. RBAC is permissive in this fixture (the
    // "allows Read" case returns true), so this passes through to true.
    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK(ok);
    CHECK(res.body.find("approval") == std::string::npos); // the approval gate did not fire
}

// PR #1796 review C2: quarantine is Security:Execute on BOTH transports. The
// kToolSecurity mapping and requires_approval("supervised","Security","Execute")
// move together (see the invariant note above kToolSecurity in mcp_server.cpp),
// so the REST POST/DELETE /api/v1/quarantine routes — which gate on
// perm_fn("Security","Execute") — are mirror-denied here for a supervised token.
// Before the fix the mapping said Security:Write while the routes checked
// Execute, so requires_approval() was false for the REST pair and a supervised
// MCP token could quarantine (and release) via REST with NO approval (#520).
TEST_CASE("AuthRoutes::require_permission — supervised token mirror-denied on REST quarantine POST",
          "[pg][auth_routes][scope][mcp][quarantine]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-quar-post", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.method = "POST";
    req.path = "/api/v1/quarantine"; // the exact route the REST quarantine gate runs on
    httplib::Response res;

    // tier_allows("supervised", Security, Execute) → true
    // requires_approval("supervised", Security, Execute) → true (the C2 rule)
    // → non-MCP transport ⇒ the approval mirror-denial fires (#520).
    bool ok = fix.ar->require_permission(req, res, "Security", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_permission — supervised token mirror-denied on REST quarantine DELETE",
          "[pg][auth_routes][scope][mcp][quarantine]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-quar-del", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.method = "DELETE";
    req.path = "/api/v1/quarantine/agent-1"; // release route — same Security:Execute gate
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Security", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_scoped_permission — supervised MCP token blocked from approval-gated Delete",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-rsp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Tag", "Delete", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_permission — supervised MCP token allows Read (not approval-gated)",
          "[pg][auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-read", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Infrastructure", "Read");
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// require_permission — service-scoped token default-deny flip (#2298 PR 3,
// "the flip"). ITServiceOwner remains the authority CEILING (checked first,
// unchanged) but is no longer sufficient on its own — a pair also has to
// clear the seeded-EMPTY `kServiceScopeGlobalSafe` allow-list. Swept every
// service-scoped-token test in the suite before writing these: every
// existing one either drives a FAKE perm_fn/scoped_perm_fn (route-level and
// MCP harnesses — test_rest_guaranteed_state.cpp, test_guardian_routes.cpp,
// test_mcp_server.cpp, test_schedule_routes.cpp, etc. — none call the real
// AuthRoutes gate) or already expects deny via an interim
// deny_service_scoped_*/deny_fleet_wide_service_scoped helper that fires
// BEFORE perm_fn is ever reached. None pinned the OLD "ITServiceOwner holds
// it ⇒ admit" shape this flip removes, so none needed updating.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — service-scoped token: ITServiceOwner "
          "ceiling holds but the default-deny allow-list still denies (the flip)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    // "Response"/"Read" is a real, catalogued (securable_type, operation)
    // pair — role_permissions FK-references securable_types/operations, so a
    // synthetic name is rejected by the store, not just untested. Granted
    // EXPLICITLY here so the precondition is this test's own, not incidental
    // to whatever ITServiceOwner's real seed happens to already grant.
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "allow"}).has_value());
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_permission(req, res, "Response", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("global-safe allow-list") != std::string::npos);
    auto j = nlohmann::json::parse(res.body);
    // No `.permission` field: the allow-list is compile-time-empty, so no
    // RBAC grant would admit this caller — naming one would be a false
    // self-remediation claim (routed-concern MUST, enterprise-readiness
    // Finding A).
    CHECK_FALSE(j["error"].contains("permission"));

    // The metric drives Phase 2 prioritization — path_class="default" since
    // this request never sets req.path (resolve_body_cap's catch-all row).
    CHECK(r.counter("yuzu_auth_service_scope_default_denied_total",
                     {{"permission", "Response:Read"}, {"path_class", "default"}}) == 1);
}

TEST_CASE("AuthRoutes::require_permission — service-scoped token lacking the "
          "ITServiceOwner ceiling denies with the ceiling message, never reaching "
          "the default-deny check (ceiling still enforced FIRST)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    // Explicit DENY, not merely "not granted" — makes the precondition this
    // test's own regardless of ITServiceOwner's real default seed.
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "deny"}).has_value());
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_permission(req, res, "Response", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("requires ITServiceOwner AND an explicit service-scope "
                        "allow-list entry") != std::string::npos);
    auto j = nlohmann::json::parse(res.body);
    // No `.permission` field: post-flip, ITServiceOwner alone is necessary
    // but no longer sufficient (the allow-list check still applies below).
    CHECK_FALSE(j["error"].contains("permission"));
    // Never reached the default-deny check for this pair.
    CHECK(r.counter("yuzu_auth_service_scope_default_denied_total",
                     {{"permission", "Response:Read"}, {"path_class", "default"}}) == 0);
}

TEST_CASE("AuthRoutes::require_permission — service-scoped token hard-403s when "
          "RBAC enforcement is not in effect (decision: preserve hard-403, do NOT "
          "let require_fleet_read's narrowed-not-denied posture leak in here)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "allow"}).has_value());
    r.rbac.set_rbac_enabled(false); // genuinely, freshly disabled
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_permission(req, res, "Response", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("require RBAC to be enabled") != std::string::npos);
    // No `.permission` field: granting `perm` does not fix "RBAC disabled".
    auto j = nlohmann::json::parse(res.body);
    CHECK_FALSE(j["error"].contains("permission"));
}

TEST_CASE("AuthRoutes::require_permission — the seeded-empty allow-list's admit "
          "path via the testonly override seam (kServiceScopeGlobalSafe is "
          "constexpr-empty in production, so this wiring has no real-table path "
          "to exercise otherwise)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "allow"}).has_value());
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    r.ar->set_service_scope_global_safe_override_for_test(
        std::vector<authz::PermPair>{{"Response", "Read"}});
    bool ok = r.ar->require_permission(req, res, "Response", "Read");
    CHECK(ok);
    CHECK(r.counter("yuzu_auth_service_scope_default_denied_total",
                     {{"permission", "Response:Read"}, {"path_class", "default"}}) == 0);

    // Clearing the override reverts to the real, empty, production table.
    r.ar->set_service_scope_global_safe_override_for_test(std::nullopt);
    httplib::Response res2;
    bool ok2 = r.ar->require_permission(req, res2, "Response", "Read");
    CHECK_FALSE(ok2);
    CHECK(res2.status == 403);
}

// ---------------------------------------------------------------------------
// require_scoped_permission — empty-agent_id hole (#2298 PR 3 §3b). An empty
// agent_id used to skip the ONLY comparison that could deny the service
// branch and fall through to an unconditional `return true` — an "allow
// everything" degenerate for any service-scoped caller who omits the target.
// Latent, not live, at every one of AuthRoutes's own callers — but real for
// at least one *_routes.cpp `scoped_perm_fn_` consumer that derives its id
// from an optional query param with no upstream empty-check
// (device_routes.cpp's /fragments/device/page: `req.has_param("id") ? ... :
// ""`) — swept and confirmed those route-level tests all inject a FAKE
// scoped_perm_fn (test_device_routes.cpp:852 passes `{}`), so none exercise
// this real function and none need updating for this fix.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_scoped_permission — service-scoped token with "
          "empty agent_id now 400s instead of falling through to an "
          "unconditional admit",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Write", "allow"}).has_value());
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Write", /*agent_id=*/"");
    CHECK_FALSE(ok);
    CHECK(res.status == 400);
    CHECK(res.body.find("agent_id is required") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_scoped_permission — service-scoped token with a "
          "matching non-empty agent_id still admits (regression: only the "
          "empty-id degenerate path changed)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Write", "allow"}).has_value());
    r.tags.set_tag("agent-1", "service", "printers");
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Write", "agent-1");
    CHECK(ok);
}

TEST_CASE("AuthRoutes::require_scoped_permission — service-scoped token with a "
          "non-matching agent_id still 403s (regression)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Write", "allow"}).has_value());
    r.tags.set_tag("agent-2", "service", "other-service");
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Write", "agent-2");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("not in service") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_scoped_permission — service-scoped token hard-403s "
          "when RBAC enforcement is not in effect (same standardized predicate "
          "as require_permission, #2298 PR 3)",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Write", "allow"}).has_value());
    r.rbac.set_rbac_enabled(false);
    r.tags.set_tag("agent-1", "service", "printers");
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Write", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("require RBAC to be enabled") != std::string::npos);
    // No `.permission` field: granting `perm` does not fix "RBAC disabled".
    auto j = nlohmann::json::parse(res.body);
    CHECK_FALSE(j["error"].contains("permission"));
}

TEST_CASE("AuthRoutes::require_scoped_permission — service-scoped token lacking "
          "the ITServiceOwner ceiling denies with the ceiling message, never "
          "reaching the per-agent service-tag check",
          "[pg][auth_routes][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Write", "deny"}).has_value());
    r.tags.set_tag("agent-1", "service", "printers");
    auto token = r.mint("printers");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Write", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("requires ITServiceOwner AND the target agent's service tag "
                        "to match the token's scope") != std::string::npos);
    // No `.permission` field: post-flip, ITServiceOwner alone is necessary
    // but no longer sufficient (the agent's service tag must still match).
    auto j = nlohmann::json::parse(res.body);
    CHECK_FALSE(j["error"].contains("permission"));
}

// ---------------------------------------------------------------------------
// Dual-attribute tokens (UP-1, Gate 4/5 governance): a token can carry BOTH
// `scope_service` and `mcp_tier` — `validate_human_mint` (api_token_store.cpp)
// has no mutual-exclusivity check, so this is a real mintable input, not a
// hypothetical. Every mcp_tier block in this file checks-and-continues on an
// allowed tier, then unconditionally FALLS THROUGH into the service-scoped
// branch below it — it never returns `true` itself. These tests pin that
// fall-through property directly: a dual-attribute token, on a tier-allowed
// operation, must still be default-denied by the service branch exactly like
// a scope_service-only token. A single added `return true;` inside any
// mcp_tier block would flip these green->red.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — a dual-attribute token (scope_service "
          "+ mcp_tier=readonly, tier-allowed op) still hits the service-scoped "
          "default-deny, not an mcp_tier fall-through admit",
          "[pg][auth_routes][service_scope][mcp]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "allow"}).has_value());
    auto token = r.mint("printers", "readonly"); // readonly tier allows Read
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_permission(req, res, "Response", "Read");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("global-safe allow-list") != std::string::npos);
    // Reached the default-deny check (and its metric) — proof the mcp_tier
    // block fell through rather than returning true on its own.
    CHECK(r.counter("yuzu_auth_service_scope_default_denied_total",
                     {{"permission", "Response:Read"}, {"path_class", "default"}}) == 1);
}

TEST_CASE("AuthRoutes::require_scoped_permission — a dual-attribute token "
          "(scope_service + mcp_tier=readonly, tier-allowed op, matching agent) "
          "still resolves via the service-scoped agent-tag check, not an "
          "mcp_tier fall-through admit",
          "[pg][auth_routes][service_scope][mcp]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Tag", "Read", "allow"}).has_value());
    r.tags.set_tag("agent-2", "service", "other-service"); // deliberately non-matching
    auto token = r.mint("printers", "readonly");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    bool ok = r.ar->require_scoped_permission(req, res, "Tag", "Read", "agent-2");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    // Reached the per-agent service-tag comparison (not an mcp_tier
    // fall-through admit that would have skipped it).
    CHECK(res.body.find("not in service") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_list_read — a dual-attribute token "
          "(scope_service + mcp_tier=readonly) is still refused outright: this "
          "gate has no fall-through-to-admit path for service-scoped tokens to "
          "begin with (unlike require_permission/require_scoped_permission), "
          "so mcp_tier cannot open one",
          "[pg][auth_routes][service_scope][mcp]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, service_scope_flip_rbac_tpl);
    ServiceScopeFlipRig r{rbac_db_.dsn()};
    auto token = r.mint("printers", "readonly");
    auto req = request_with_header("Authorization", "Bearer " + token);
    httplib::Response res;

    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
    CHECK(res.body.find("cannot read the fleet-wide status rollup") != std::string::npos);
}

// ---------------------------------------------------------------------------
// authz::is_service_tag_key / authz::service_scope_may_mutate_tag_key (#3289)
// — pure predicates in service_scope_policy.hpp. No fixture, no store.
// ---------------------------------------------------------------------------

TEST_CASE("authz::is_service_tag_key — matches the canonical key and common case "
          "variants, rejects everything else",
          "[auth_routes][service_scope][tag_write]") {
    using yuzu::server::authz::is_service_tag_key;
    CHECK(is_service_tag_key("service"));
    CHECK(is_service_tag_key("Service"));
    CHECK(is_service_tag_key("SERVICE"));
    CHECK(is_service_tag_key("SeRviCe"));
    CHECK_FALSE(is_service_tag_key("environment"));
    CHECK_FALSE(is_service_tag_key("service2"));
    CHECK_FALSE(is_service_tag_key("servic"));
    CHECK_FALSE(is_service_tag_key(""));
}

TEST_CASE("authz::service_scope_may_mutate_tag_key — denies a service-scoped "
          "session mutating the service key, value-blind; admits every other "
          "combination (#3289)",
          "[auth_routes][service_scope][tag_write]") {
    using yuzu::server::authz::service_scope_may_mutate_tag_key;
    // Service-scoped session, service key: DENY. Value-blind — the function
    // does not take a value parameter at all, so a would-be no-op rewrite of
    // the token's own current value is denied identically to any other.
    CHECK_FALSE(service_scope_may_mutate_tag_key("printers", "service"));
    CHECK_FALSE(service_scope_may_mutate_tag_key("printers", "Service"));
    // Service-scoped session, non-service key: ADMIT.
    CHECK(service_scope_may_mutate_tag_key("printers", "environment"));
    CHECK(service_scope_may_mutate_tag_key("printers", "owner"));
    // Non-scoped session (empty token_scope_service): ADMIT regardless of key —
    // this predicate only confines service-scoped sessions.
    CHECK(service_scope_may_mutate_tag_key("", "service"));
    CHECK(service_scope_may_mutate_tag_key("", "environment"));
}

// ---------------------------------------------------------------------------
// AuthRoutes::deny_service_scoped_session (#2298 PR 3 §3e) — the shared gate
// server.cpp's require_auth-only fragment/stream routes call directly, since
// they never reach require_permission/require_scoped_permission at all (so
// §3a/§3b's flip never runs for them). Needs no RBAC store — the fixture
// leaves it nullptr, matching the function's own dependency (require_auth +
// audit_log only).
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::deny_service_scoped_session — a service-scoped token is denied",
          "[pg][auth_routes][service_scope]") {
    AuthRoutesFixture fix;
    auto now = service_scope_flip_now_epoch();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "printers", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_session(
        req, res, "health.fragment.access_denied",
        "service-scoped tokens may not read the fleet-wide health summary", "Health", "svc-1",
        "Inventory:Read");
    CHECK(must_return);
    CHECK(res.status == 403);
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped tokens may not read") !=
          std::string::npos);
    CHECK(j["error"]["permission"].get<std::string>() == "Inventory:Read");
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("AuthRoutes::deny_service_scoped_session — default call (no explicit "
          "permission) omits the A4 permission field",
          "[pg][auth_routes][service_scope]") {
    // Matches production's actual call shape — every server.cpp site calls
    // this with 4 args, relying on the default. `permission` defaults empty
    // (not a securable pair): every route this gate covers is a blanket
    // deny with no grant that would admit a service-scoped token, so naming
    // one would be a false self-remediation claim in the A4 body.
    AuthRoutesFixture fix;
    auto now = service_scope_flip_now_epoch();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "printers", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_session(
        req, res, "health.fragment.access_denied",
        "service-scoped tokens may not read the fleet-wide health summary");
    CHECK(must_return);
    CHECK(res.status == 403);
    auto j = nlohmann::json::parse(res.body);
    CHECK_FALSE(j["error"].contains("permission"));
}

TEST_CASE("AuthRoutes::deny_service_scoped_session — an ordinary (non-scoped) "
          "session is unaffected (regression)",
          "[pg][auth_routes][service_scope]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token(); // no scope_service
    auto req = request_with_header("Authorization", "Bearer " + raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_session(
        req, res, "health.fragment.access_denied",
        "service-scoped tokens may not read the fleet-wide health summary");
    CHECK_FALSE(must_return);
    // res is untouched — httplib::Response defaults status to -1.
    CHECK(res.status == -1);
    CHECK(res.body.empty());
}

TEST_CASE("AuthRoutes::deny_service_scoped_session — no session at all defers to "
          "require_auth's own 401 (defence-in-depth, unreachable behind the "
          "pre-routing chokepoint today)",
          "[pg][auth_routes][service_scope]") {
    AuthRoutesFixture fix;
    httplib::Request req; // no credential of any kind
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_session(
        req, res, "health.fragment.access_denied",
        "service-scoped tokens may not read the fleet-wide health summary");
    CHECK(must_return);
    CHECK(res.status == 401);
}

// ---------------------------------------------------------------------------
// AuthRoutes::deny_service_scoped_service_tag_mutation (#3289) — the legacy
// dashboard's tag-mutation guard, tested directly against the helper the
// same way deny_service_scoped_session is above (no httplib route harness
// exists for server.cpp's /api/tags/set|delete, matching every sibling
// server.cpp handler; the shared predicate + this direct call together
// cover the decision logic the route wiring only forwards to).
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::deny_service_scoped_service_tag_mutation — a "
          "service-scoped session mutating the service key is denied (#3289)",
          "[pg][auth_routes][service_scope][tag_write]") {
    AuthRoutesFixture fix;
    auto now = service_scope_flip_now_epoch();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "printers", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_service_tag_mutation(
        req, res, "tag.set", "agent-1", "service");
    CHECK(must_return);
    CHECK(res.status == 403);
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped token may not modify") !=
          std::string::npos);
    CHECK_FALSE(j["error"].contains("permission"));
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("AuthRoutes::deny_service_scoped_service_tag_mutation — case-insensitive "
          "('Service') (#3289)",
          "[pg][auth_routes][service_scope][tag_write]") {
    AuthRoutesFixture fix;
    auto now = service_scope_flip_now_epoch();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "printers", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_service_tag_mutation(
        req, res, "tag.delete", "agent-1", "Service");
    CHECK(must_return);
    CHECK(res.status == 403);
}

TEST_CASE("AuthRoutes::deny_service_scoped_service_tag_mutation — a "
          "service-scoped session mutating a NON-service key is admitted "
          "(#3289 regression)",
          "[pg][auth_routes][service_scope][tag_write]") {
    AuthRoutesFixture fix;
    auto now = service_scope_flip_now_epoch();
    auto raw = fix.api_tokens->create_token("scoped", "test_user", now + 3600, "printers", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_service_tag_mutation(
        req, res, "tag.set", "agent-1", "environment");
    CHECK_FALSE(must_return);
    CHECK(res.status == -1); // untouched
}

TEST_CASE("AuthRoutes::deny_service_scoped_service_tag_mutation — an "
          "ordinary (non-scoped) session is unaffected (#3289 regression)",
          "[pg][auth_routes][service_scope][tag_write]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token(); // no scope_service
    auto req = request_with_header("Authorization", "Bearer " + raw);
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_service_tag_mutation(
        req, res, "tag.set", "agent-1", "service");
    CHECK_FALSE(must_return);
    CHECK(res.status == -1);
}

TEST_CASE("AuthRoutes::deny_service_scoped_service_tag_mutation — no session "
          "at all defers to require_auth's own 401 (#3289)",
          "[pg][auth_routes][service_scope][tag_write]") {
    AuthRoutesFixture fix;
    httplib::Request req; // no credential of any kind
    httplib::Response res;

    bool must_return = fix.ar->deny_service_scoped_service_tag_mutation(
        req, res, "tag.set", "agent-1", "service");
    CHECK(must_return);
    CHECK(res.status == 401);
}

// ---------------------------------------------------------------------------
// Bearer token length guard tests (#630 — Claude review F4/F6)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_auth — oversized Bearer token is rejected (DoS protection #630)",
          "[pg][auth_routes][dos]") {
    AuthRoutesFixture fix;
    std::string big_token(1000, 'a');
    auto req = request_with_header("Authorization", "Bearer " + big_token);
    httplib::Response res;

    auto session = fix.ar->require_auth(req, res);
    CHECK_FALSE(session.has_value());
    CHECK(res.status == 401); // Rejected before reaching ApiTokenStore
}

TEST_CASE("AuthRoutes::require_auth — oversized X-Yuzu-Token is rejected (DoS protection #630)",
          "[pg][auth_routes][dos]") {
    AuthRoutesFixture fix;
    std::string big_token(1000, 'b');
    auto req = request_with_header("X-Yuzu-Token", big_token);
    httplib::Response res;

    auto session = fix.ar->require_auth(req, res);
    CHECK_FALSE(session.has_value());
    CHECK(res.status == 401);
}

// ---------------------------------------------------------------------------
// AuthRoutes::url_decode — malformed percent-sequence safety (H-A)
//
// Prior to this fix, AuthRoutes::url_decode called std::stoul on any two
// characters that followed a '%', throwing std::invalid_argument for non-hex
// sequences such as "%GH" or a bare "%" and causing a 500 on form-encoded
// POST handlers (login, MFA, SAML ACS).
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::url_decode — valid percent-encoded sequences decode correctly",
          "[auth_routes][url_decode]") {
    CHECK(AuthRoutes::url_decode("hello%20world") == "hello world");
    CHECK(AuthRoutes::url_decode("%26")            == "&");
    CHECK(AuthRoutes::url_decode("%3D")            == "=");
    CHECK(AuthRoutes::url_decode("%41")            == "A"); // 0x41 = 'A'
    CHECK(AuthRoutes::url_decode("key%3Dvalue")    == "key=value");
}

TEST_CASE("AuthRoutes::url_decode — plus sign decoded to space", "[auth_routes][url_decode]") {
    CHECK(AuthRoutes::url_decode("hello+world") == "hello world");
}

TEST_CASE("AuthRoutes::url_decode — bare percent passed through literally (H-A)",
          "[auth_routes][url_decode]") {
    // A bare '%' at end of string — no two chars follow → emit literally.
    CHECK(AuthRoutes::url_decode("%")        == "%");
    CHECK(AuthRoutes::url_decode("test%")    == "test%");
}

TEST_CASE("AuthRoutes::url_decode — single hex digit after percent passed through (H-A)",
          "[auth_routes][url_decode]") {
    // '%' followed by exactly one char (truncated) → emit literally.
    CHECK(AuthRoutes::url_decode("%2")       == "%2");
    CHECK(AuthRoutes::url_decode("abc%2")    == "abc%2");
}

TEST_CASE("AuthRoutes::url_decode — non-hex chars after percent passed through (H-A)",
          "[auth_routes][url_decode]") {
    // '%GH' — 'G' is not a hex digit in the first nibble → emit '%' literally.
    CHECK(AuthRoutes::url_decode("%GH")      == "%GH");
    // '%1G' — second nibble non-hex.
    CHECK(AuthRoutes::url_decode("%1G")      == "%1G");
    // Mid-string malformed, rest is plain text.
    CHECK(AuthRoutes::url_decode("a%GHb")    == "a%GHb");
}

TEST_CASE("AuthRoutes::url_decode — mixed valid and malformed sequences (H-A)",
          "[auth_routes][url_decode]") {
    // The malformed '%GH' is passed through; the valid '%41' decodes to 'A'.
    CHECK(AuthRoutes::url_decode("%GH%41")   == "%GHA");
    CHECK(AuthRoutes::url_decode("ok%41")    == "okA");
}

// ── revalidate_stream: the tri-state a HELD-OPEN stream needs ────────────────
//
// This is the production implementation of ADR-1005 Decision 15(c)/(i) — the code
// that decides, every heartbeat tick, whether a live MCP SSE stream keeps running.
// The distinction it draws is the whole point: a REVOKED credential must cut the
// stream on the spot, while an auth store that merely cannot be REACHED must not cut
// every stream on the fleet at the same instant (chaos CH-4).

TEST_CASE("revalidate_stream: a live token for the stream's principal is valid",
          "[pg][auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: a revoked token DEFINITIVELY ends the stream",
          "[pg][auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto live = f.api_tokens->validate_token(token);
    REQUIRE(live.has_value());
    REQUIRE(f.api_tokens->revoke_token(live->token_id));

    auto req = request_with_header("Authorization", "Bearer " + token);
    // kRevoked, NOT kIndeterminate: an indeterminate answer would buy the revoked
    // credential a full grace window of extra life on a live stream.
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: a valid token for ANOTHER principal is not authority",
          "[pg][auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token(); // belongs to test_user
    auto req = request_with_header("Authorization", "Bearer " + token);
    // The stream carries test_user's messages. A credential that authenticates as
    // somebody else does not entitle the holder to keep reading them.
    CHECK(f.ar->revalidate_stream(req, "someone_else") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: no credential at all is a definitive no", "[pg][auth][stream][ch4]") {
    AuthRoutesFixture f;
    httplib::Request bare;
    CHECK(f.ar->revalidate_stream(bare, "test_user") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: a dead cookie FALLS THROUGH to a live token",
          "[pg][auth][stream][ch4]") {
    // The invariant: a stream lives iff a fresh request with these headers would still
    // authenticate as this principal — so this must mirror resolve_session's
    // fall-through exactly. An earlier version returned kRevoked as soon as the cookie
    // failed, which killed a perfectly good token-authenticated stream every 3 s (in a
    // reconnect loop) whenever the client also carried a stale cookie from a browser
    // jar or a cookie-injecting proxy.
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    httplib::Request req;
    req.set_header("Cookie", "yuzu_session=dead-and-gone");
    req.set_header("Authorization", "Bearer " + token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: X-Yuzu-Token is honoured alongside a dead Bearer",
          "[pg][auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    httplib::Request req;
    req.set_header("Authorization", "Bearer yuzu_not_a_real_token_000000000000");
    req.set_header("X-Yuzu-Token", token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: an unreachable token store is INDETERMINATE, not revoked",
          "[pg][auth][stream][ch4]") {
    // CH-4's second half. If the store cannot answer, we do not KNOW the credential is
    // gone — and treating "cannot tell" as "revoked" would cut every stream on the
    // fleet the moment the auth store hiccupped. The pump rides out a bounded grace
    // window on kIndeterminate instead.
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + token);
    // NOTE: deliberately do NOT validate the token first — a successful validation
    // would populate the 60 s token cache, and the cached answer would sail straight
    // past the broken store, testing nothing.

    // Break the store underneath the token, from a SECOND connection — no test-only
    // hook on the production store, and this is what a real corruption/ops accident
    // looks like from the reader's side: the query it needs will not run.
    {
        yuzu::server::pg::PgConn saboteur{PQconnectdb(f.api_tokens.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(saboteur.get(), "DROP TABLE api_token_store.api_tokens")};
        REQUIRE(r.ok());
    }

    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kIndeterminate);
}
