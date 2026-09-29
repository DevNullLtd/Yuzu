/**
 * test_settings_routes_users.cpp — HTTP-level tests for the Users section of
 * the Settings page, covering the self-deletion lockout guard added for
 * issues #397 and #403, the sibling self-demotion guard added in the Gate 4
 * ca-B1 hardening round, and the SOC 2 CC7.2 audit chain (CO-1).
 *
 * The bugs:
 *  - #397 (handler): DELETE /api/settings/users/:name did not reject self-
 *    targeted deletes. Confirming the hx-confirm dialog dropped the only
 *    usable credential on the running server.
 *  - #403 (UI): Settings > Users rendered a Remove button next to the
 *    operator's own row.
 *  - ca-B1 (sibling, found in governance Gate 4): POST /api/settings/users
 *    let an admin demote themselves to role=user — the same lockout class
 *    via a different route. Closed in the same hardening round.
 *  - CO-1 (compliance, found in governance Gate 6): the rejected and
 *    successful user lifecycle ops did not emit audit_fn_ events, breaking
 *    SOC 2 CC7.2 evidence chain. Closed in the hardening round.
 *
 * Pattern: register SettingsRoutes against an in-process TestRouteSink
 * and dispatch synthesized httplib::Request objects through the captured
 * handlers. The audit_fn mock captures every call into a vector so tests
 * can assert the SOC 2 evidence chain is intact on each guarded path.
 *
 * Why in-process and not a real httplib::Server: the prior fixture spun
 * up a listening server behind a std::thread acceptor, which crashes
 * deterministically under TSan with no TSan report (#438).
 */

#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_principal.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/scim_store.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

/// Shim: callers below pass a "prefix" string; route through the canonical
/// helper in tests/unit/test_helpers.hpp so we don't recreate the
/// hash<thread::id>+chrono+getpid pattern that drove flake #473.
static fs::path unique_temp_path(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

/// RAII wrapper around a temp directory. Constructing it creates the
/// directory; destruction removes it. Declared as the FIRST member of the
/// harness so that even if a later REQUIRE inside the harness constructor
/// throws (port allocation, server bind, etc.) the directory is still
/// cleaned up — fully-constructed members of a partially-constructed object
/// have their destructors invoked, but the object's own destructor does
/// not. Governance Gate 3 qe-B1.
struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) {
        fs::create_directories(path);
    }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// Single audit call captured by the mock audit_fn.
struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

/// Harness that stands up a real httplib::Server with SettingsRoutes bound
/// to an AuthManager seeded with two accounts ("admin" + "bob"). The mock
/// auth/admin callbacks read `session_user` / `session_role` so individual
/// tests can switch perspective between calls without rebuilding the server.
/// The mock audit_fn appends every call into `audit_calls` so tests can
/// verify the SOC 2 evidence chain (CO-1).
struct SettingsRoutesHarness {
    // tmp must come first — its destructor handles cleanup if any of the
    // REQUIREs in the constructor body throw.
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    // Mock session state — the auth_fn / admin_fn closures read this so
    // tests can act as different principals against the same harness.
    std::string session_user;
    auth::Role session_role{auth::Role::admin};

    // Audit capture — each audit_fn_ call from the routes layer appends an
    // entry. Tests assert on this to verify CC7.2 evidence emission.
    std::vector<AuditCall> audit_calls;

    SettingsRoutesHarness() : tmp(unique_temp_path("settings-routes-users")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));

        auto auth_fn =
            [this](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };

        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string&, const std::string&) {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn,
                               cfg, auth_mgr, auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false,
                               gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }
    // No destructor — TmpDirGuard cleans the temp dir on its own; nothing
    // else owns OS resources. The previous fixture had to stop() the
    // httplib::Server and join the acceptor thread; both are gone (#438).

    /// Dispatch a request through the registered routes. Returns
    /// std::unique_ptr<httplib::Response> so existing test sites that
    /// access res->status / res->body / res->get_header_value(...) keep
    /// working unchanged.
    auto Get(const std::string& path) { return sink.Get(path); }
    auto Delete(const std::string& path) { return sink.Delete(path); }
    auto Post(const std::string& path, const std::string& body,
              const std::string& ct = "application/json") {
        return sink.Post(path, body, ct);
    }
    auto Put(const std::string& path, const std::string& body,
             const std::string& ct = "application/json") {
        return sink.Put(path, body, ct);
    }

    /// True if `auth_mgr` currently lists a user with the given name.
    bool has_user(std::string_view name) const {
        for (const auto& u : auth_mgr.list_users()) {
            if (u.username == name)
                return true;
        }
        return false;
    }

    /// Current role of `name`, or std::nullopt if no such user.
    std::optional<auth::Role> role_of(std::string_view name) const {
        for (const auto& u : auth_mgr.list_users()) {
            if (u.username == name)
                return u.role;
        }
        return std::nullopt;
    }

    /// True if any captured audit call matches all four fields.
    bool has_audit(std::string_view action, std::string_view result,
                   std::string_view target_type, std::string_view target_id) const {
        for (const auto& a : audit_calls) {
            if (a.action == action && a.result == result &&
                a.target_type == target_type && a.target_id == target_id)
                return true;
        }
        return false;
    }
};

// Exact toast payloads — must stay in sync with settings_routes.cpp,
// docs/user-manual/server-admin.md, and the CHANGELOG entries.
constexpr std::string_view kSelfDeleteToast =
    R"({"showToast":{"message":"Cannot delete your own account","level":"error"}})";
constexpr std::string_view kSelfDemoteToast =
    R"({"showToast":{"message":"Cannot change your own role","level":"error"}})";
constexpr std::string_view kDuplicateUsernameToast =
    R"({"showToast":{"message":"Username already exists","level":"error"}})";
constexpr std::string_view kShortPasswordToast =
    R"({"showToast":{"message":"Password must be at least 12 characters","level":"error"}})";

} // namespace

// ── ADR-2001 Task 3: dashboard DELETE deprovision revoke ────────────────────
//
// `SettingsRoutesHarness` above is config-file-only (no AuthDB/ScimStore/
// ApiTokenStore) — the pre-existing shape this file predates, and DELETE's
// null-`api_token_store_` path (settings_routes.cpp) FAILS CLOSED (503,
// governance Gate 7 BLOCKING fix, UP-7) rather than skip-and-proceed, so any
// assertion that a delete actually SUCCEEDS needs the REAL PG-backed stores.
// Declared here (ahead of the plain-harness test cases below) so both the
// "admin can delete other users" / "unknown user" cases further down and the
// dedicated credential-revoke assertions at the end of this file can use it.

namespace {

/// PG-gated SettingsRoutes harness wiring a real AuthDB (yuzu::test::
/// AuthDbPg) + ScimStore + ApiTokenStore sharing one PgPool — the same
/// "one PgPool, independent connections" pattern test_scim_routes.cpp's
/// Fixture uses — so the ADR-2001 credentials-first revoke actually runs
/// (SettingsRoutesHarness above passes `api_token_store=nullptr`, which
/// deliberately fails closed on delete). Local to these ADR-2001 cases only.
struct SettingsAdr2001Harness {
    yuzu::test::AuthDbPg auth_db;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<ScimStore> scim_store;
    std::unique_ptr<ApiTokenStore> token_store;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};
    std::vector<AuditCall> audit_calls;

    SettingsAdr2001Harness() {
        auth_mgr.set_auth_db(auth_db.get());
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));

        scim_store = std::make_unique<ScimStore>(auth_db.pool());
        REQUIRE(scim_store->is_open());
        token_store = std::make_unique<ApiTokenStore>(auth_db.pool());
        REQUIRE(token_store->is_open());
        routes.set_scim_store(scim_store.get());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, token_store.get(),
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }

    auto delete_user(const std::string& username) {
        return sink.Delete("/api/settings/users/" + username);
    }

    /// True if any captured audit call matches all four fields — mirrors
    /// `SettingsRoutesHarness::has_audit` above.
    bool has_audit(std::string_view action, std::string_view result,
                   std::string_view target_type, std::string_view target_id) const {
        for (const auto& a : audit_calls) {
            if (a.action == action && a.result == result &&
                a.target_type == target_type && a.target_id == target_id)
                return true;
        }
        return false;
    }
};

} // namespace

// ── Self-deletion guard — handler side (#397) ────────────────────────────────

TEST_CASE("SettingsRoutes DELETE /api/settings/users: admin cannot delete self",
          "[settings][users][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    CHECK(res->status == 403);
    // Full-payload assertion: a substring match would tolerate a regression
    // that drops the level field or injects an extra key.
    CHECK(res->get_header_value("HX-Trigger") == kSelfDeleteToast);
    CHECK(h.has_user("admin"));
    // SOC 2 CC7.2 evidence emission — denied destructive ops must reach
    // audit_store, not just spdlog (governance Gate 6 CO-1).
    CHECK(h.has_audit("user.delete", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: admin can delete other users",
          "[pg][settings][users]") {
    // Governance Gate 7 BLOCKING fix (UP-7): a null ApiTokenStore now fails
    // CLOSED (503), so a plain `SettingsRoutesHarness` (which wires
    // `api_token_store=nullptr`) can no longer exercise a successful
    // delete — this needs the PG-backed harness so the credentials-first
    // revoke actually runs and the delete completes.
    SettingsAdr2001Harness h;
    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.auth_mgr.get_user_role("bob").has_value());
    // Successful destructive op also requires an audit entry (CO-1).
    CHECK(h.has_audit("user.delete", "success", "User", "bob"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: a null ApiTokenStore fails CLOSED "
         "(503) rather than skip-and-proceed — MUTATION-CHECK target, see the comment below",
         "[settings][users][adr2001][failclosed]") {
    // SettingsRoutesHarness deliberately wires api_token_store=nullptr
    // (config-file-only, no PG) — governance Gate 7 BLOCKING fix (UP-7):
    // this null branch used to spdlog::warn and proceed straight to
    // remove_user, silently skipping the credentials-first revoke. It must
    // now refuse instead, mirroring the SCIM seam's
    // `api_token_store_unavailable` fail-closed branch.
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Delete("/api/settings/users/bob");
    REQUIRE(res);
    CHECK(res->status == 503);
    // MUTATION-CHECK (manually verified during development): reverting the
    // null-`api_token_store_` branch in settings_routes.cpp back to
    // spdlog::warn-and-proceed makes this assertion fail — bob is deleted
    // (has_user returns false) and the response is 200, not 503.
    CHECK(h.has_user("bob"));
    CHECK(h.has_audit("user.delete", "failure", "User", "bob"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: non-admin session rejected",
          "[settings][users]") {
    SettingsRoutesHarness h;
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    // admin_fn_ rejects with 403 before the self-delete guard is even reached.
    CHECK(res->status == 403);
    CHECK(h.has_user("admin"));
    // No audit emission expected — the request never reached the handler
    // body, so no user-level audit event should be recorded.
    CHECK_FALSE(h.has_audit("user.delete", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: unauthenticated session rejected",
          "[settings][users][auth]") {
    SettingsRoutesHarness h;
    // Empty session_user → mock auth_fn returns nullopt and admin_fn
    // returns false; admin_fn_ gate fires before either of the handler's
    // own defensive branches. Verifies the unauthenticated path does not
    // accidentally permit a destructive op (governance Gate 3 qe-S3).
    h.session_user = "";

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.has_user("admin"));
    CHECK(h.audit_calls.empty());
}

// ── Self-demotion guard — POST upsert sibling (ca-B1) ────────────────────────

TEST_CASE("SettingsRoutes POST /api/settings/users: role parameter ignored on create",
          "[settings][users][c1-fix]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // C1 FIX: The role parameter is IGNORED on user creation. New users are
    // always created as 'user' role regardless of what the form sends.
    // Role changes must go through the dedicated POST /api/settings/users/:username/role endpoint.
    auto res = h.Post("/api/settings/users",
                        "username=newadmin&password=newadminpass1&role=admin",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Role must be 'user' — the role=admin parameter was ignored (C1 fix).
    auto role = h.role_of("newadmin");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    // Audit chain captures the creation.
    CHECK(h.has_audit("user.create", "success", "User", "newadmin"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: admin self-password-change allowed",
          "[settings][users]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Self-password-change via the POST create endpoint is now a duplicate
    // username rejection (C1 fix: creation always uses 'user' role, duplicates blocked).
    // Self-password-change should use a dedicated endpoint in future.
    // For now, creating with an existing username returns 409.
    auto res = h.Post("/api/settings/users",
                        "username=admin&password=anotherpass12&role=admin",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(h.has_audit("user.create", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: success path renders self-row guard",
          "[settings][users][ui]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Add a new user. Response body is the re-rendered fragment; verify
    // (a) the new user shows up with a Remove button and (b) the operator's
    // own row still has the Current user badge — the self_name threading
    // through the success path matters because the dashboard swaps this
    // body into #user-section.
    auto res = h.Post("/api/settings/users",
                        "username=carol&password=carolpassword1&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.has_user("carol"));
    CHECK(res->body.find("hx-delete=\"/api/settings/users/carol\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
    CHECK(res->body.find("Current user") != std::string::npos);
    CHECK(h.has_audit("user.create", "success", "User", "carol"));
}

// ── Duplicate-username guard (#399) ──────────────────────────────────────────

TEST_CASE("SettingsRoutes POST /api/settings/users: duplicate username rejected",
          "[settings][users][duplicate]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // 'bob' is pre-seeded by the harness with role=user. Re-creating must
    // fail with 409 + duplicate-username toast — the prior behavior was a
    // silent password overwrite via upsert_user (#399).
    auto res = h.Post("/api/settings/users",
                        "username=bob&password=newbobpassword&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->get_header_value("HX-Trigger") == kDuplicateUsernameToast);
    CHECK(h.has_audit("user.create", "denied", "User", "bob"));
    // The original password must still authenticate — the rejection must
    // not have run upsert_user under the hood.
    CHECK(h.auth_mgr.authenticate("bob", "bobpassword12").has_value());
}

// ── Reserved SSO-principal prefix guard (#1837 governance follow-up) ───────
//
// A local user literally named `oidc:<iss>#<sub>` would re-open the severed
// elevation-borrow (that local `users` row would supply the eligibility/TOTP
// the SSO principal lacks). `is_valid_username`'s pre-existing ':' rejection
// already makes the exact stable-principal string unconstructable as a local
// username — this test exercises that outcome end-to-end through the create
// route (colon survives URL-decoding intact, exercising the same branch as
// the "$bogus" invalid-username test above).

TEST_CASE("SettingsRoutes POST /api/settings/users: oidc-namespaced username rejected",
          "[settings][users][reserved-prefix]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // "oidc:x#y" percent-encoded so url_decode reconstructs the literal
    // colon/hash bytes in the handler.
    auto res = h.Post("/api/settings/users",
                        "username=oidc%3Ax%23y&password=newuserpassword&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(h.has_user("oidc:x#y"));
}

// Direct unit coverage of the new reserved-prefix helper itself: the route-
// level test above is preempted by is_valid_username's ':' rejection before
// ever reaching is_reserved_identity_prefix, so it does not exercise the new
// logic. These pin the helper's contract directly (case-insensitivity,
// prefix-only matching, and that it does not false-positive on ordinary
// usernames that merely start with the same letters).
TEST_CASE("is_reserved_identity_prefix: rejects oidc:/saml:/ad: case-insensitively",
          "[settings][users][reserved-prefix]") {
    CHECK(is_reserved_identity_prefix("oidc:whatever"));
    CHECK(is_reserved_identity_prefix("OIDC:Whatever"));
    CHECK(is_reserved_identity_prefix("saml:whatever"));
    CHECK(is_reserved_identity_prefix("SaMl:whatever"));
    CHECK(is_reserved_identity_prefix("ad:whatever"));
    CHECK(is_reserved_identity_prefix("AD:whatever"));
}

TEST_CASE("is_reserved_identity_prefix: does not false-positive on ordinary usernames",
          "[settings][users][reserved-prefix]") {
    CHECK_FALSE(is_reserved_identity_prefix("bob"));
    CHECK_FALSE(is_reserved_identity_prefix("admin"));
    // Starts with the same letters but no colon — not a namespaced principal.
    CHECK_FALSE(is_reserved_identity_prefix("adam"));
    CHECK_FALSE(is_reserved_identity_prefix("oidcuser"));
    CHECK_FALSE(is_reserved_identity_prefix(""));
}

// ── is_valid_principal (#1852 durable SSO identity) ─────────────────────────
//
// A strict superset of is_valid_username: every string the strict validator
// accepts is accepted unchanged, and a reserved-prefixed SSO principal is
// ADDITIONALLY accepted after a narrow control-byte/metacharacter blocklist.
// Used ONLY at target-lookup chokepoints for an EXISTING user (elevation
// eligibility, session revoke) — never at user-creation, which stays on
// is_valid_username (+ is_reserved_identity_prefix).

TEST_CASE("is_valid_principal: accepts a well-formed OIDC/SAML stable principal",
          "[settings][users][principal]") {
    CHECK(is_valid_principal("oidc:https://idp.example.com/#sub-123"));
    CHECK(is_valid_principal("saml:https://idp.example.com/metadata#user@example.com"));
    CHECK(is_valid_principal("ad:corp.example.com#S-1-5-21-123"));
    // Opaque sub alphabets a real IdP may emit: URL path segments, tildes,
    // percent-encoding, pipe-separated composite subs.
    CHECK(is_valid_principal("oidc:https://idp/#a~b%20c|d"));
}

TEST_CASE("is_valid_principal: still accepts a strict local username unchanged",
          "[settings][users][principal]") {
    CHECK(is_valid_principal("bob"));
    CHECK(is_valid_principal("admin"));
    CHECK(is_valid_principal("alice.smith-1_2"));
    CHECK_FALSE(is_valid_principal("")); // is_valid_username already rejects; no prefix either
}

TEST_CASE("is_valid_principal: rejects a bad-prefix string that is also not a strict username",
          "[settings][users][principal]") {
    // Contains ':' (fails is_valid_username) but not a reserved prefix.
    CHECK_FALSE(is_valid_principal("notreserved:whatever"));
    CHECK_FALSE(is_valid_principal("http://evil.example/#sub"));
}

TEST_CASE("is_valid_principal: rejects control bytes, injection metacharacters, and space",
          "[settings][users][principal]") {
    CHECK_FALSE(is_valid_principal(std::string("oidc:https://idp/#sub\x01")));
    CHECK_FALSE(is_valid_principal(std::string("oidc:https://idp/#sub\x7F")));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub\nwith-newline"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub;DROP TABLE users"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub=malicious"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub\\backslash"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub'quote"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub\"dquote"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub`backtick"));
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#sub with space"));
}

TEST_CASE("is_valid_principal: rejects an embedded NUL in every position "
          "(#4020/#2755e3871 Gate 2/4 re-review follow-up)",
          "[settings][users][principal][security]") {
    // A plain string literal truncates at an embedded '\0', so every case
    // here is built by concatenating clean literal pieces around a single
    // explicit '\0' char, avoiding any error-prone manual byte-counting -
    // std::string::operator+ computes each piece's length correctly. Mirrors
    // the exact attack shape (a NUL-mangled username reaching
    // AuthDB::get_user via url_decode).
    CHECK_FALSE(is_valid_principal(std::string(1, '\0') + "admin"));   // leading
    CHECK_FALSE(is_valid_principal(std::string("admin") + '\0'));      // trailing
    CHECK_FALSE(is_valid_principal(std::string("adm") + '\0' + "in")); // mid, non-prefixed
    // Inside a reserved-prefix (SSO) principal, both before and after the
    // colon - proves the reserved-prefix branch's c<0x20 scan covers the
    // WHOLE string, not just the portion after the prefix.
    CHECK_FALSE(is_valid_principal(std::string("oi") + '\0' + "dc:https://idp#sub"));
    CHECK_FALSE(is_valid_principal(std::string("oidc:https://idp#su") + '\0' + "b"));
}

TEST_CASE("is_valid_principal: rejects an over-255-byte principal", "[settings][users][principal]") {
    std::string long_sub(300, 'a');
    CHECK_FALSE(is_valid_principal("oidc:https://idp/#" + long_sub));
}

// ── Weak-password guard — UAT-reported silent fail ─────────────────────────
//
// Before this fix, POSTing a new user with a password shorter than 12 chars
// (the G2-SEC-A1-003 minimum enforced inside AuthManager::upsert_user) caused
// the handler to fire-and-forget the bool return value, then log
// "User added/updated", write a SUCCESS audit row, and emit the
// "User created" success toast — while nothing was persisted. UAT observed
// this as "setting a password less than 12 characters silently fails."
//
// The guard must: (1) return 400, (2) emit the short-password error toast,
// (3) audit the attempt as denied with detail="weak_password", (4) leave
// the user NOT persisted.

TEST_CASE("SettingsRoutes POST /api/settings/users: short password rejected with toast",
          "[settings][users][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // "shortpw" = 7 chars, below the 12-char minimum. Must be rejected
    // before any persistence or success audit occurs.
    auto res = h.Post("/api/settings/users",
                        "username=charlie&password=shortpw&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("HX-Trigger") == kShortPasswordToast);
    // User must NOT have been persisted.
    CHECK_FALSE(h.has_user("charlie"));
    // Audit chain must capture the denial with the weak_password reason.
    CHECK(h.has_audit("user.create", "denied", "User", "charlie"));
    // And must NOT show a success row for the same target.
    CHECK_FALSE(h.has_audit("user.upsert", "success", "User", "charlie"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: exactly-11-char password rejected",
          "[settings][users][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Boundary: 11 chars (one below the minimum). 12 chars must pass, 11
    // must fail — this pins the inclusive-lower-bound on 12, not 11.
    auto res = h.Post("/api/settings/users",
                        "username=dave&password=elevenchars&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("HX-Trigger") == kShortPasswordToast);
    CHECK_FALSE(h.has_user("dave"));
}

TEST_CASE("SettingsRoutes /fragments/settings/users: add-user form carries minlength=12 hint",
          "[settings][users][ui][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // The rendered fragment must carry the HTML5 minlength hint so the
    // browser surfaces the rule natively before a short password even
    // reaches the server. Defence-in-UX, not a security control — the
    // server-side check above is canonical.
    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(res->body.find("minlength=\"12\"") != std::string::npos);
    CHECK(res->body.find("min 12 chars") != std::string::npos);
}

// ── Self-deletion guard — UI side (#403) ─────────────────────────────────────

TEST_CASE("SettingsRoutes GET /fragments/settings/users: Remove button hidden for self",
          "[settings][users][ui][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // The admin's own row must not carry a DELETE action; the other user's
    // row must. Searching for the hx-delete URL is the most surgical check —
    // presence of the text "Remove" alone would miss a future button rename.
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/bob\"") != std::string::npos);
    CHECK(res->body.find("Current user") != std::string::npos);
}

TEST_CASE("SettingsRoutes GET /fragments/settings/users: non-self rows all get Remove",
          "[settings][users][ui]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    REQUIRE(h.auth_mgr.upsert_user("carol", "carolpassword1", auth::Role::user));

    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    CHECK(res->body.find("hx-delete=\"/api/settings/users/bob\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/carol\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
}

// ── DELETE /api/settings/users — invalid_username + user_not_found audit ─────
//
// PR 4 closed two evidence-chain holes on DELETE: (1) a hand-crafted DELETE
// against an invalid username reached remove_user() with bytes that should
// never have entered the user-store path, and (2) DELETE on an unknown user
// silently re-rendered the fragment without auditing the privileged-mutation
// attempt. Both are SOC 2 CC7.2 evidence-chain failures.

TEST_CASE("SettingsRoutes DELETE /api/settings/users: invalid username audited and 400",
          "[settings][users][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // is_valid_username rejects anything outside [A-Za-z0-9._-]; a literal
    // `$` survives URL canonicalisation and reaches the handler with
    // exactly that byte, exercising the username-validation branch.
    auto res = h.Delete("/api/settings/users/$bogus");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.has_audit("user.delete", "denied", "User", "$bogus"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: unknown user audited and 404",
          "[pg][settings][users][audit]") {
    // Governance Gate 7 BLOCKING fix (UP-7): the credentials-first revoke
    // (which now fails closed on a null ApiTokenStore) runs BEFORE the
    // `remove_user` not-found check below it, so this needs the PG-backed
    // harness to reach that 404 at all — see the comment on "admin can
    // delete other users" above.
    SettingsAdr2001Harness h;

    auto res = h.delete_user("nosuchuser");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.has_audit("user.delete", "denied", "User", "nosuchuser"));
}

// ── POST /api/settings/users/:username/role — success + audit ────────────────

TEST_CASE("SettingsRoutes POST role: admin promotes user to admin",
          "[settings][users][role]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/bob/role", R"({"role":"admin"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto role = h.role_of("bob");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::admin);
    CHECK(h.has_audit("user.role_change", "success", "User", "bob"));
}

TEST_CASE("SettingsRoutes POST role: self-target denied and audited",
          "[settings][users][role][self]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/admin/role", R"({"role":"user"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->get_header_value("HX-Trigger") == kSelfDemoteToast);
    auto role = h.role_of("admin");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::admin);
    CHECK(h.has_audit("user.role_change", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes POST role: invalid username audited and 400",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/$evil/role", R"({"role":"user"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.has_audit("user.role_change", "denied", "User", "$evil"));
}

TEST_CASE("SettingsRoutes POST role: invalid JSON audited and 400",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/bob/role", "not-json-at-all");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.has_audit("user.role_change", "denied", "User", "bob"));
}

TEST_CASE("SettingsRoutes POST role: missing role field audited and 400",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/bob/role", R"({"foo":"bar"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.has_audit("user.role_change", "denied", "User", "bob"));
}

TEST_CASE("SettingsRoutes POST role: invalid role value audited and 400",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/bob/role", R"({"role":"superadmin"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.has_audit("user.role_change", "denied", "User", "bob"));
}

TEST_CASE("SettingsRoutes POST role: unknown user audited and 404",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Post("/api/settings/users/nosuchuser/role",
                      R"({"role":"admin"})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.has_audit("user.role_change", "denied", "User", "nosuchuser"));
}

TEST_CASE("SettingsRoutes POST role: same-role no-op audited as no_op",
          "[settings][users][role][audit]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // bob is seeded as Role::user; setting role=user is a no-op. The handler
    // returns 200 and does not invoke update_role(), but the operator's
    // intent is captured as a `no_op` audit so compliance review can
    // distinguish "tried to set already-current role" from "no request was
    // made at all."
    auto res = h.Post("/api/settings/users/bob/role", R"({"role":"user"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.has_audit("user.role_change", "no_op", "User", "bob"));
    auto role = h.role_of("bob");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
}

TEST_CASE("SettingsRoutes POST role: non-admin session rejected by admin_fn",
          "[settings][users][role]") {
    SettingsRoutesHarness h;
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.Post("/api/settings/users/admin/role", R"({"role":"user"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    // The handler is gated by admin_fn_ which fires before the body even
    // executes, so no user.role_change audit is emitted.
    CHECK_FALSE(h.has_audit("user.role_change", "denied", "User", "admin"));
}

// ── ADR-2001 Task 3: dashboard DELETE deprovision revoke ────────────────────
//
// `SettingsAdr2001Harness` (declared above, ahead of the plain-harness cases)
// wires the REAL PG-backed stores so these credential-revoke assertions
// actually exercise the credentials-first revoke.

TEST_CASE("SettingsRoutes DELETE /api/settings/users: revokes a slug-keyed API token before "
         "the account is removed (ADR-2001)",
         "[pg][settings][users][adr2001]") {
    SettingsAdr2001Harness h;
    auto token = h.token_store->create_token("bob-token", "bob");
    REQUIRE(token.has_value());

    auto res = h.delete_user("bob");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.auth_mgr.get_user_role("bob").has_value());
    CHECK_FALSE(h.token_store->validate_token(*token).has_value());
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: revokes a SCIM-linked OIDC identity's "
         "tokens too, not just the deleted username's own (the linkage this seam exists to "
         "close)",
         "[pg][settings][users][adr2001]") {
    SettingsAdr2001Harness h;
    REQUIRE(h.auth_mgr.upsert_user("carol", "carolpassword1", auth::Role::user));

    auto resource = h.scim_store->create_resource("carol");
    REQUIRE(resource.has_value());
    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-carol-1";
    REQUIRE(h.scim_store->upsert_link(iss, sub, resource->scim_id));
    const std::string oidc_principal = oidc::oidc_principal_id(iss, sub);

    auto slug_token = h.token_store->create_token("slug-token", "carol");
    REQUIRE(slug_token.has_value());
    auto oidc_token = h.token_store->create_token("oidc-token", oidc_principal);
    REQUIRE(oidc_token.has_value());

    auto res = h.delete_user("carol");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.token_store->validate_token(*slug_token).has_value());
    CHECK_FALSE(h.token_store->validate_token(*oidc_token).has_value());

    bool found_success = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "user.delete" && a.result == "success" && a.target_id == "carol" &&
            a.detail.find("api_tokens_revoked=2") != std::string::npos)
            found_success = true;
    }
    CHECK(found_success);
}
