/**
 * test_auth_sso_identity.cpp — durable SSO identity (#1852).
 *
 * `create_oidc_session` mints a stable `oidc:<iss>#<sub>` principal but
 * historically wrote NO row to `auth.users`, so JIT admin elevation
 * (which reads `users.elevation_eligible`) had nothing to key on for an
 * SSO operator — OIDC elevation was unreachable (#1837 fallout). This
 * covers the durable-identity slice restoring it:
 *
 *   - AuthDB::upsert_sso_identity round-trips with set/is_elevation_eligible,
 *     and preserves role/eligibility across re-login (re-upsert).
 *   - mfa_status stays strict — still rejects an SSO principal.
 *   - POST /api/v1/elevate end-to-end for an OIDC session: eligible +
 *     provisioned succeeds; eligible-in-intent-but-unprovisioned (no row)
 *     is denied fail-closed; a local elevation flow is unaffected.
 *
 * AuthDB is now Postgres-backed (ADR-0006), born-on-PG (no
 * `migrate_from_sqlite()`) — the former "migration v6: identity columns
 * added, existing v5 rows survive" SQLite-upgrade-path test was removed
 * along with it; there is no legacy schema to upgrade from any more.
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but
 * broken (test_helpers.hpp skip-vs-fail contract).
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "saml_principal.hpp" // saml_principal_id — ADR-2001 PR4a
#include "test_route_sink.hpp"
#include "test_auth_db_pg_helper.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

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
using yuzu::server::auth::Role;

namespace {
// AuditStore migrated to Postgres (ADR-0006) — the harness below now clones
// this pre-migrated template instead of opening a SQLite path. Self-contained
// (mirrors yuzu::test::AuthDbPg, already embedded in this harness): SKIPs the
// enclosing TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset (via auth_db's own
// ctor, constructed first), FAILs when set but broken.
yuzu::test::PgTestTemplate sso_audit_tpl{"ssoaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("ssoaudit template: store failed to migrate");
}};
} // namespace

// ── AuthDB::upsert_sso_identity ─────────────────────────────────────────────

TEST_CASE("AuthDB::upsert_sso_identity round-trips with elevation eligibility",
          "[pg][sso][authdb]") {
    yuzu::test::AuthDbPg db;

    const std::string principal = "oidc:https://idp.example.com/#sub-42";

    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-42",
                                   "Ada Lovelace", "oidc")
                .has_value());

    // Default is not-eligible (same fail-closed default as a local row).
    CHECK(db->is_elevation_eligible(principal).value() == false);

    // Grant, then read back — this is the exact operation #1852 restores.
    REQUIRE(db->set_elevation_eligible(principal, true).has_value());
    CHECK(db->is_elevation_eligible(principal).value() == true);
    REQUIRE(db->set_elevation_eligible(principal, false).has_value());
    CHECK(db->is_elevation_eligible(principal).value() == false);
}

TEST_CASE("AuthDB::upsert_sso_identity re-upsert preserves role and elevation_eligible",
          "[pg][sso][authdb]") {
    yuzu::test::AuthDbPg db;

    const std::string principal = "oidc:https://idp.example.com/#sub-99";

    // First login: provision, an admin grants elevation eligibility. Note:
    // `AuthDB::update_role` deliberately stays on the STRICT
    // `is_valid_username` gate (#1852 item 5 — it is NOT one of the moved
    // call sites), so there is no standing-role-grant path for an SSO
    // principal in this slice; the row's `role` column stays at the
    // INSERT-time default ('user') for the lifetime of the identity. The
    // CRITICAL invariant this test pins is `elevation_eligible` survival —
    // the field an admin actually can and does set for an SSO principal.
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-99", "Bob", "oidc")
                .has_value());
    REQUIRE(db->set_elevation_eligible(principal, true).has_value());

    // Second login (re-upsert with a changed display name — an IdP-side
    // profile edit): eligibility (and role) must survive UNTOUCHED — the
    // ON CONFLICT arm touches ONLY display_name/last_seen_at/is_active.
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-99",
                                   "Bob Renamed", "oidc")
                .has_value());
    auto entry = db->get_user(principal);
    REQUIRE(entry.has_value());
    CHECK(entry->role == Role::user); // ON CONFLICT never touches role — unchanged from INSERT
    CHECK(db->is_elevation_eligible(principal).value() == true); // eligibility preserved
}

TEST_CASE("AuthDB::upsert_sso_identity rejects a non-principal, non-username string",
          "[pg][sso][authdb]") {
    yuzu::test::AuthDbPg db;

    // No reserved prefix and fails the strict local charset (':').
    CHECK_FALSE(db->upsert_sso_identity("not:reserved", "https://idp/", "sub", "x", "oidc")
                    .has_value());
}

TEST_CASE("AuthDB::upsert_sso_identity rejects an 'engine:'-prefixed principal",
          "[pg][sso][authdb][engine_principal]") {
    // Security review finding on PR #2202 (engine principals 4.2): the write
    // surface itself must reject a reserved `engine:` principal (design
    // §3.3), not merely rely on the OIDC/SAML/AD caller's own construction
    // convention (`source` is always a literal in {"oidc","saml","ad"}, never
    // "engine") to keep it from happening. `is_valid_principal`'s format
    // check alone is NOT sufficient here — it structurally accepts an
    // `engine:`-shaped string (see `is_reserved_identity_prefix`), so this
    // proves the dedicated guard added directly in `upsert_sso_identity`.
    yuzu::test::AuthDbPg db;

    CHECK_FALSE(db->upsert_sso_identity("engine:vuln-scanner", "https://issuer.example", "sub-1",
                                       "Impersonating Row", "oidc")
                    .has_value());
    CHECK_FALSE(db->get_user("engine:vuln-scanner").has_value());

    // A normal SSO principal (no reserved prefix collision) is unaffected.
    const std::string principal = "oidc:https://idp.example.com/#sub-engine-guard";
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-engine-guard",
                                   "Dave", "oidc")
                .has_value());
    CHECK(db->get_user(principal).has_value());
}

TEST_CASE("AuthDB::mfa_status stays strict — rejects an SSO principal", "[pg][sso][authdb]") {
    yuzu::test::AuthDbPg db;

    const std::string principal = "oidc:https://idp.example.com/#sub-7";
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-7", "Carol", "oidc")
                .has_value());

    // mfa_status is deliberately NOT moved to is_valid_principal (#1852 item
    // 5) — a local TOTP secret is meaningless for an external identity, and
    // the elevate handler's `auth_source == "local"` gate is what actually
    // skips this check for OIDC sessions (see auth_routes.cpp), not a
    // loosened validator here.
    CHECK_FALSE(db->mfa_status(principal).has_value());
}

// ── POST /api/v1/elevate — OIDC session end-to-end ──────────────────────────

namespace {
/// Mirrors JitHarness (test_auth_jit_elevation.cpp) but adds an OIDC-session
/// helper. Kept separate rather than extending the shared harness so the
/// two files stay independently reviewable.
struct SsoJitHarness {
    yuzu::test::TempDir tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::AuthDbPg auth_db;
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current TEST_CASE
    // when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
    // api_tokens removed (PR 4.1 review #3): this fixture never calls a token
    // store method, and AuthRoutes null-guards the pointer, so it gets nullptr
    // below — embedding the PG fixture only made every case skip without a DSN.
    // AuditStore ported to Postgres (ADR-0006): a template-cloned ephemeral
    // database + pool, mirroring auth_db's own self-contained skip/fail
    // posture above (auth_db constructs first, so an unset DSN never reaches
    // this member at all).
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    // AnalyticsEventStore ported to Postgres (ADR-0049) — own ephemeral
    // clone, matching audit_store's pattern above.
    yuzu::test::AnalyticsEventStorePg analytics_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> auth_routes;
    yuzu::server::test::TestRouteSink sink;

    SsoJitHarness() {
        fs::create_directories(tmp.path);
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false;
        cfg.jit_max_elevation_secs = 3600;
        auth_mgr.load_config(cfg.auth_config_path);
        auth_mgr.set_auth_db(auth_db.get());

        audit_db.emplace(sso_audit_tpl);
        INFO("[SsoJitHarness] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   /*api_token_store=*/nullptr, audit_store.get(), nullptr,
                                                   nullptr, analytics_store.get(), oidc_mu,
                                                   oidc_provider);
        auth_routes->register_routes(sink);
    }

    // Mints an OIDC cookie session exactly as /auth/callback would, with a
    // fresh amr-attested MFA proof (mfa_verified_at = now). Returns
    // {token, stable principal}.
    std::pair<std::string, std::string> oidc_session(const std::string& sub,
                                                      const std::string& iss =
                                                          "https://idp.example.com/",
                                                      bool amr_mfa = true) {
        auto mfa_at = amr_mfa ? std::chrono::system_clock::now()
                              : std::chrono::system_clock::time_point{};
        auto token = auth_mgr.create_oidc_session("Display Name", "user@example.com", sub, iss,
                                                   /*groups=*/{}, /*admin_group_id=*/{}, mfa_at);
        return {token, "oidc:" + iss + "#" + sub};
    }

    auto post(const std::string& path, const std::string& token, const std::string& body) {
        return sink.dispatch("POST", path, body, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }

    // A fresh-MFA admin cookie session, for tests exercising the
    // admin-gated elevation-eligibility-grant route on THIS harness (which
    // otherwise only sets up OIDC identities, never a local admin). Mirrors
    // JitHarness::seed + session_for, collapsed to what the step-up gate
    // needs: a `users` row to key `mfa_status` on (unenrolled — the gate's
    // not-enrolled branch passes unconditionally) plus a session-level
    // fresh MFA proof. Unlike JitHarness (which seeds before
    // `set_auth_db`), this harness's constructor already wired `auth_db`
    // into `auth_mgr` — so `upsert_user` alone persists the row; a second
    // explicit `auth_db.upsert_user` call would double-insert and fail
    // with `UserAlreadyExists`.
    std::string admin_session() {
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", Role::admin));
        return auth_mgr.create_local_session("admin", Role::admin, /*mfa_verified=*/true);
    }
};
} // namespace

TEST_CASE("POST /api/v1/elevate: a provisioned, eligible OIDC session elevates",
          "[pg][sso][jit][routes]") {
    SsoJitHarness h;
    auto [token, principal] = h.oidc_session("sub-alice");

    // Provisioning + eligibility grant — exactly what /auth/callback now does
    // (provision_sso_identity) plus an admin's elevation-eligibility grant.
    REQUIRE(h.auth_db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-alice",
                                          "Display Name", "oidc")
                .has_value());
    REQUIRE(h.auth_db->set_elevation_eligible(principal, true).has_value());

    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"prod incident","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(nlohmann::json::parse(res->body).value("expires_in", 0) == 600);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::admin);
}

TEST_CASE("POST /api/v1/elevate: an OIDC session with no durable row is denied fail-closed",
          "[pg][sso][jit][routes]") {
    SsoJitHarness h;
    // No upsert_sso_identity call — simulates a provisioning miss (or simply
    // no admin having granted eligibility, since a never-provisioned
    // principal has no row to grant it on in the first place).
    auto [token, principal] = h.oidc_session("sub-bob");

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

TEST_CASE("POST /api/v1/elevate: an OIDC session with no amr-attested MFA is denied "
          "unconditionally (even under the default --mfa-enforcement=optional)",
          "[pg][sso][jit][routes]") {
    SsoJitHarness h;
    // Provisioned + eligible, but the IdP never attested MFA (amr_mfa=false)
    // — mfa_verified_at is unset (epoch sentinel).
    //
    // Config::mfa_enforcement defaults to "optional" (server.hpp), under
    // which the SHARED require_mfa_step_up gate's OIDC-no-proof branch
    // deliberately PASSES a proof-free session through (PR #1199 HIGH —
    // avoids locking out every non-MFA IdP at lower-risk step-up sites).
    // The elevate route's OWN unconditional amr-proof-exists gate (added
    // alongside this restoration, #1852 security core) is what must deny
    // this session — NOT elevation_step_up, and NOT dependent on the
    // enforcement-mode default. This pins that regression: without the
    // dedicated gate, a non-MFA'd OIDC login could elevate to full admin
    // under the out-of-the-box config.
    REQUIRE(h.cfg.mfa_enforcement == "optional");
    auto [token, principal] = h.oidc_session("sub-carol", "https://idp.example.com/",
                                             /*amr_mfa=*/false);
    REQUIRE(h.auth_db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-carol",
                                          "Carol", "oidc")
                .has_value());
    REQUIRE(h.auth_db->set_elevation_eligible(principal, true).has_value());

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

// ── governance round: source-scope the elevation eligibility (UP-6/UP-7/cons-N2) ──

TEST_CASE("POST /api/v1/elevate: an OIDC session cannot borrow a legacy identity_source='local' "
          "row's eligibility grant even when the principal strings collide",
          "[pg][sso][jit][routes]") {
    SsoJitHarness h;
    // Simulate the exact landmine cons-N2 describes: a row named exactly
    // like a durable OIDC principal, but whose identity_source is 'local'
    // (a legacy row from before #1852, or one an admin somehow created
    // with this shape) — and that row happens to carry
    // elevation_eligible=1. `upsert_sso_identity`'s `source` parameter
    // writes straight into `identity_source`, so passing "local" here
    // constructs exactly that shape via the public API.
    auto [token, principal] = h.oidc_session("sub-mallory");
    REQUIRE(h.auth_db
                ->upsert_sso_identity(principal, "https://idp.example.com/", "sub-mallory",
                                      "Legacy Row", "local")
                .has_value());
    REQUIRE(h.auth_db->set_elevation_eligible(principal, true).has_value());

    // Without the source-scope guard, is_elevation_eligible(principal) alone
    // would report true (it only reads the flag, not identity_source) and
    // the OIDC session would elevate on a grant that was never actually
    // made against an OIDC-sourced row.
    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"prod incident","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("not authorized to elevate") != std::string::npos);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

TEST_CASE("POST /api/v1/elevate: a SAML session whose stable principal collides with a "
          "provisioned OIDC-sourced row is denied (identity-source mismatch, not just the "
          "no-amr gate)",
          "[pg][sso][jit][routes][saml]") {
    SsoJitHarness h;
    // ADR-2001 PR4a re-key: a SAML session's stable principal is now
    // `saml:<entity_id>#<name_id>` (saml_principal.hpp), so a crafted raw
    // NameID can no longer collide with an `oidc:<iss>#<sub>` row at the
    // STRING level — the "saml:" prefix makes the two principal spaces
    // disjoint by construction (a strictly stronger guarantee than the
    // guard this test originally pinned). This test instead seeds an
    // AuthDB row keyed on the SAML session's OWN stable principal but
    // sourced as `identity_source="oidc"` (modelling a row that could
    // otherwise exist), so the request still reaches the
    // identity-source-MISMATCH branch specifically (never the amr/no-such-
    // row branches) — SAML sessions already fail closed at the amr-proof/
    // MFA gates further down this handler (SAML carries no amr claim), but
    // this pins that the identity-source guard denies it FIRST and
    // independently.
    const std::string entity_id = "https://idp.example.com/";
    const std::string name_id = "mallory@example.com";
    const std::string principal = saml::saml_principal_id(entity_id, name_id);

    REQUIRE(h.auth_db
                ->upsert_sso_identity(principal, "https://other-idp.example.com/", "sub-x",
                                      "Real OIDC User", "oidc")
                .has_value());
    REQUIRE(h.auth_db->set_elevation_eligible(principal, true).has_value());

    auto token = h.auth_mgr.create_saml_session(name_id, entity_id);

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

// ── governance round: don't resurrect a disabled SSO row (UP-3) ────────────

TEST_CASE("AuthDB::upsert_sso_identity does not reactivate a deprovisioned row on re-login",
          "[pg][sso][authdb]") {
    yuzu::test::AuthDbPg db;

    const std::string principal = "oidc:https://idp.example.com/#sub-deprovisioned";
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-deprovisioned",
                                    "Dave", "oidc")
                .has_value());

    // Simulate a future deprovisioning sweep (#1859) soft-deleting the row.
    // remove_user takes no is_valid_username gate (it's a target-lookup
    // UPDATE, like set_elevation_eligible/is_elevation_eligible), so it
    // works against the durable SSO principal string directly.
    auto removed = db->remove_user(principal);
    REQUIRE(removed.has_value());
    CHECK(*removed == true);
    CHECK_FALSE(db->get_user(principal).has_value()); // is_active=false now

    // Re-login (the IdP still asserts this identity — there is no push
    // signal into Yuzu on an IdP-side removal) must NOT resurrect the
    // deactivated row. Before this fix the ON CONFLICT arm unconditionally
    // set is_active=true, silently undoing the deprovisioning.
    REQUIRE(db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-deprovisioned",
                                    "Dave", "oidc")
                .has_value());
    CHECK_FALSE(db->get_user(principal).has_value()); // still inactive
}

// governance-round "SSO force-logout audit fidelity (cons-S1)" coverage
// (`AuthManager::invalidate_user_sessions` accepting a durable SSO principal
// without AuthDBError::InvalidUsername, and the direct
// `AuthDB::invalidate_all_sessions` pin) is RETIRED along with the session
// surface it exercised: AuthDB carries no session methods any more (sessions
// are AuthManager's in-memory `sessions_` map only, never persisted —
// see auth_db.hpp's file header), so `invalidate_user_sessions` no longer
// makes any AuthDB call at all and `AuthDB::invalidate_all_sessions` does
// not exist. Nothing here to test against AuthDB any more.

// ── review round: elevation-eligibility grant route reachability for SSO ────

TEST_CASE("POST /api/v1/users/elevation-eligibility?username=: the query form reaches "
          "a durable SSO principal that the path form can never carry",
          "[pg][sso][routes]") {
    SsoJitHarness h;
    // A realistic OIDC principal — contains '/' (in the issuer URL) and '#'
    // (the iss/sub separator). httplib percent-decodes the path (%2F -> '/',
    // %23 -> '#') and strips the literal '#' fragment BEFORE route-regex
    // matching, so a `([^/]+)` PATH SEGMENT can never carry this shape — the
    // path-only route 404s for every real IdP identity (this is exactly what
    // this test must observe against the pre-fix route below).
    const std::string principal = "oidc:https://idp.example.com/#sub-4821";
    REQUIRE(h.auth_db->upsert_sso_identity(principal, "https://idp.example.com/", "sub-4821",
                                          "Test SSO", "oidc")
                .has_value());
    CHECK(h.auth_db->is_elevation_eligible(principal).value() == false);

    auto admin = h.admin_session();
    // Query value: '#' percent-encoded (%23) so it survives to the handler
    // as part of the query string rather than being parsed as a URL
    // fragment; the '/' in the issuer is passed through literal (query
    // values don't need '/' escaped).
    auto res = h.post(
        "/api/v1/users/elevation-eligibility?username=oidc:https://idp.example.com/%23sub-4821",
        admin, R"({"eligible":true})");

    // Against the OLD path-only route
    // (`/api/v1/users/([^/]+)/elevation-eligibility`), this fixed two-segment
    // path (`/api/v1/users/elevation-eligibility`) never matches the
    // three-segment pattern — TestRouteSink::dispatch returns nullptr,
    // mirroring httplib's 404. This REQUIRE is the fail-without/pass-with
    // pin: it fails on the pre-fix route registration and passes once the
    // query-form route is registered.
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.auth_db->is_elevation_eligible(principal).value() == true);
}
