/**
 * test_rest_password_routes.cpp — the #5342 REST v1 password routes:
 *
 *   POST /api/v1/users/me/password      {current_password, new_password}
 *   POST /api/v1/users/{name}/password  {new_password}
 *
 * Wiring under test is the production shape: RestApiV1 over a TestRouteSink,
 * a REAL AuthManager over a real (PG) AuthDB for the writes, and a REAL
 * AuthRoutes supplying the lockout-accounted current-password check
 * (`password_change_verify_fn`, the same section POST /login runs) and the
 * replacement-session cookie minter. Only auth_fn / perm_fn / audit_fn /
 * step_up_fn are harness-controlled, so each gate can be driven directly.
 *
 * Audit `detail` tokens are asserted EXACTLY — they are the SOC 2 CC6.3
 * evidence vocabulary a SIEM rule keys on. No assertion here (or anywhere in
 * the routes) may see a password, its length, or the request body: the
 * "never echoed" cases check the response and every audit row for the
 * submitted secret.
 */

#include "auth_routes.hpp"
#include "rest_api_v1.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "web_utils.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

constexpr const char* kOld = "old-password-123";
constexpr const char* kNew = "new-password-456";

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct PasswordRoutesHarness {
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    yuzu::test::AuthDbPg db;
    AuthManager auth_mgr;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    // Harness-controlled session (what auth_fn returns).
    std::string session_user;
    Role session_role{Role::user};
    std::string session_auth_source{"local"};
    std::string session_mcp_tier;
    std::string session_scope;
    std::string session_principal_kind{"human"};
    bool session_mfa_verified{false};
    bool perm_grant{true};
    bool step_up_pass{true};
    int step_up_calls{0};

    // Audit fault injection: `audit_fail_on(action, result)` makes the FIRST
    // matching row report a persist failure (and run `on_fail` first, so a
    // test can race the rollback).
    std::vector<AuditRow> audits;
    std::optional<std::pair<std::string, std::string>> audit_fail_match;
    bool audit_fail_all_after_first{false};
    std::function<void()> on_audit_fail;
    bool audit_failing{false};

    ApiTokenStore* token_store{nullptr};
    std::vector<std::string> trusted_origins;
    bool wire_deps{true};

    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    explicit PasswordRoutesHarness(int lockout_threshold = 0) {
        cfg.auth_lockout_threshold = lockout_threshold;
        cfg.auth_lockout_window_secs = 3600;
        cfg.https_enabled = false;
        auth_mgr.set_auth_db(db.get());
        auth_mgr.set_metrics_registry(&metrics);
        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   /*api_token_store=*/nullptr,
                                                   /*audit_store=*/nullptr,
                                                   /*mgmt_group_store=*/nullptr,
                                                   /*tag_store=*/nullptr,
                                                   /*analytics_store=*/nullptr, oidc_mu,
                                                   oidc_provider);
    }

    /// Register the routes. Separate from the ctor so a test can adjust the
    /// wiring knobs (token_store, trusted_origins, wire_deps) first.
    void wire() {
        if (wire_deps) {
            api.set_password_change_deps(RestApiV1::PasswordChangeDeps{
                &auth_mgr, auth_routes->password_change_verify_fn(),
                auth_routes->session_cookie_mint_fn()});
        }
        api.set_csrf_trusted_origins(trusted_origins);

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.display_name = session_user;
            s.role = session_role;
            s.auth_source = session_auth_source;
            s.mcp_tier = session_mcp_tier;
            s.token_scope_service = session_scope;
            s.principal_kind = session_principal_kind;
            if (session_mfa_verified)
                s.mfa_verified_at = std::chrono::system_clock::now();
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (perm_grant)
                return true;
            res.status = 403;
            return false;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            if (audit_failing && audit_fail_all_after_first)
                return false;
            if (audit_fail_match && audit_fail_match->first == action &&
                audit_fail_match->second == result) {
                audit_fail_match.reset();
                audit_failing = true;
                if (on_audit_fail)
                    on_audit_fail();
                return false;
            }
            return true;
        };
        StepUpFn step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const auth::Session&, const std::string&) -> bool {
            ++step_up_calls;
            if (step_up_pass)
                return true;
            res.status = 401;
            res.set_content(R"({"error":{"code":401,"message":"MFA step-up required"}})",
                            "application/json");
            return false;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, token_store,
                            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr,
                            /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, step_up_fn);
    }

    void seed(const std::string& user, const std::string& pw, Role role) {
        auto salt = AuthManager::random_bytes(16);
        REQUIRE(db->upsert_user(user,
                                AuthManager::pbkdf2_sha256(pw, salt, AuthManager::kPbkdf2Iterations),
                                AuthManager::bytes_to_hex(salt), role)
                    .has_value());
    }

    std::unordered_map<std::string, std::string>
    browser_headers(const std::string& origin = "http://yuzu.local:8080") const {
        std::unordered_map<std::string, std::string> h{{"Host", "yuzu.local:8080"}};
        if (!origin.empty())
            h["Origin"] = origin;
        return h;
    }

    std::unique_ptr<httplib::Response>
    post(const std::string& path, const nlohmann::json& body,
         std::unordered_map<std::string, std::string> headers = {},
         const std::string& ct = "application/json") {
        if (headers.empty())
            headers = browser_headers();
        return sink.dispatch("POST", path, body.dump(), ct, headers);
    }

    std::unique_ptr<httplib::Response> change(const std::string& current,
                                              const std::string& next) {
        return post("/api/v1/users/me/password",
                    {{"current_password", current}, {"new_password", next}});
    }

    std::unique_ptr<httplib::Response> reset(const std::string& target, const std::string& next) {
        return post("/api/v1/users/" + target + "/password", {{"new_password", next}});
    }

    bool has_audit(const std::string& action, const std::string& result,
                   const std::string& detail_prefix = {}) const {
        for (const auto& a : audits)
            if (a.action == action && a.result == result && a.target_type == "User" &&
                a.detail.starts_with(detail_prefix))
                return true;
        return false;
    }

    double changes(const std::string& kind, const std::string& result) {
        return metrics.counter("yuzu_auth_password_changes_total",
                               {{"kind", kind}, {"result", result}})
            .value();
    }

    std::string stored_hash(const std::string& user) { return db->get_user(user)->hash_hex; }

    /// No response body or audit row may carry the submitted secret.
    void check_never_echoed(const httplib::Response& res, const std::string& secret) const {
        CHECK(res.body.find(secret) == std::string::npos);
        for (const auto& a : audits)
            CHECK(a.detail.find(secret) == std::string::npos);
    }
};

nlohmann::json data_of(const httplib::Response& res) {
    auto j = nlohmann::json::parse(res.body);
    REQUIRE(j.contains("data"));
    return j["data"];
}

std::string error_message_of(const httplib::Response& res) {
    auto j = nlohmann::json::parse(res.body, nullptr, false);
    if (!j.is_object() || !j.contains("error"))
        return {};
    return j["error"].value("message", std::string{});
}

/// "yuzu_session=<tok>; Path=..." → "<tok>".
std::string token_from_set_cookie(const std::string& set_cookie) {
    const std::string prefix = "yuzu_session=";
    if (!set_cookie.starts_with(prefix))
        return {};
    auto end = set_cookie.find(';');
    return set_cookie.substr(prefix.size(), end - prefix.size());
}

} // namespace

// ── Self-service: POST /api/v1/users/me/password ────────────────────────────

TEST_CASE("password routes: self change succeeds, revokes sessions, re-mints the caller's",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("alice", kOld, Role::admin);
    h.session_user = "alice";
    h.session_role = Role::admin;
    h.session_mfa_verified = true;
    auto old_token = h.auth_mgr.authenticate("alice", kOld);
    REQUIRE(old_token.has_value());

    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["password_changed"] == true);
    CHECK(d["session_reissued"] == true);
    CHECK(d["sessions_db_persisted"] == true);
    CHECK(d["sessions_revoked"].get<int64_t>() >= 1);
    CHECK(d["audit_emitted"] == true);

    // Old session dead; replacement cookie valid, MFA proof carried, not elevated.
    CHECK_FALSE(h.auth_mgr.validate_session(*old_token).has_value());
    const auto set_cookie = res->get_header_value("Set-Cookie");
    CHECK(set_cookie.find("HttpOnly") != std::string::npos);
    CHECK(set_cookie.find("SameSite=Lax") != std::string::npos);
    const auto new_token = token_from_set_cookie(set_cookie);
    REQUIRE_FALSE(new_token.empty());
    auto fresh = h.auth_mgr.validate_session(new_token);
    REQUIRE(fresh.has_value());
    CHECK(fresh->username == "alice");
    CHECK(fresh->role == Role::admin);
    CHECK(fresh->mfa_verified_at.time_since_epoch().count() != 0);
    CHECK_FALSE(auth::is_elevated(*fresh));

    // Credential swapped durably.
    CHECK_FALSE(h.auth_mgr.verify_password("alice", kOld).has_value());
    CHECK(h.auth_mgr.verify_password("alice", kNew) == Role::admin);

    CHECK(h.has_audit("user.password_change", "ok", "self_service"));
    CHECK(h.has_audit("session.revoke_all.self", "success", "count="));
    CHECK(h.changes("self", "ok") == 1.0);
    h.check_never_echoed(*res, kOld);
    h.check_never_echoed(*res, kNew);
    CHECK(h.step_up_calls == 1);
}

TEST_CASE("password routes: self change refuses every non-interactive or non-local session",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("bob", kOld, Role::user);
    h.session_user = "bob";
    const auto before = h.stored_hash("bob");

    SECTION("MCP token") {
        h.session_auth_source = "mcp_token";
        h.session_mcp_tier = "supervised";
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "token_session"));
    }
    SECTION("API token") {
        h.session_auth_source = "api_token";
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "token_session"));
    }
    SECTION("service-scoped token") {
        h.session_auth_source = "api_token";
        h.session_scope = "payments";
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "token_session"));
    }
    SECTION("engine token") {
        h.session_auth_source = "engine_token";
        h.session_principal_kind = "engine";
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "token_session"));
    }
    SECTION("SSO (OIDC) session — no local password") {
        h.session_auth_source = "oidc";
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 409);
        CHECK(h.has_audit("user.password_change", "denied", "not_local"));
    }
    CHECK(h.stored_hash("bob") == before);
    CHECK(h.changes("self", "denied") == 1.0);
}

TEST_CASE("password routes: CSRF and Content-Type gates", "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("carl", kOld, Role::user);
    h.session_user = "carl";
    const nlohmann::json body = {{"current_password", kOld}, {"new_password", kNew}};
    const auto before = h.stored_hash("carl");

    SECTION("cross-origin Origin refused") {
        auto res = h.post("/api/v1/users/me/password", body,
                          h.browser_headers("https://evil.example"));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "csrf"));
    }
    SECTION("neither Origin nor Referer refused") {
        auto res = h.post("/api/v1/users/me/password", body, {{"Host", "yuzu.local:8080"}});
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "csrf"));
    }
    SECTION("sibling subdomain refused (same-site, different origin)") {
        auto res = h.post("/api/v1/users/me/password", body,
                          h.browser_headers("http://evil.yuzu.local:8080"));
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    SECTION("form-encoded body refused with 415, not parsed") {
        auto res = h.sink.dispatch("POST", "/api/v1/users/me/password",
                                   "current_password=x&new_password=y",
                                   "application/x-www-form-urlencoded", h.browser_headers());
        REQUIRE(res);
        CHECK(res->status == 415);
        CHECK(h.audits.empty());
    }
    SECTION("text/plain refused with 415") {
        auto res = h.post("/api/v1/users/me/password", body, h.browser_headers(), "text/plain");
        REQUIRE(res);
        CHECK(res->status == 415);
    }
    CHECK(h.stored_hash("carl") == before);
}

TEST_CASE("password routes: Referer-only and trusted-origin requests pass the CSRF gate",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    // A reverse proxy that rewrites Host: the browser Origin is the external
    // name, Host is internal — admitted only via the operator allowlist.
    h.trusted_origins = normalise_trusted_origins(std::vector<std::string>{"https://yuzu.example"});
    h.wire();
    h.seed("dina", kOld, Role::user);
    h.session_user = "dina";

    auto via_proxy = h.post("/api/v1/users/me/password",
                            {{"current_password", kOld}, {"new_password", kNew}},
                            {{"Host", "10.0.0.5:8080"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(via_proxy);
    CHECK(via_proxy->status == 200);

    auto referer_only = h.post("/api/v1/users/me/password",
                               {{"current_password", kNew}, {"new_password", "third-password-789"}},
                               {{"Host", "yuzu.local:8080"},
                                {"Referer", "http://yuzu.local:8080/settings"}});
    REQUIRE(referer_only);
    CHECK(referer_only->status == 200);
}

TEST_CASE("password routes: self change body + policy validation never echoes the body",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("eve", kOld, Role::user);
    h.session_user = "eve";
    const auto before = h.stored_hash("eve");

    SECTION("malformed JSON") {
        auto res = h.sink.dispatch("POST", "/api/v1/users/me/password",
                                   "{\"current_password\": \"secret-in-a-broken-body", "application/json",
                                   h.browser_headers());
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("secret-in-a-broken-body") == std::string::npos);
    }
    SECTION("wrong-typed field") {
        auto res = h.post("/api/v1/users/me/password",
                          {{"current_password", 12345}, {"new_password", kNew}});
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("too short") {
        auto res = h.change(kOld, "short");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.has_audit("user.password_change", "denied", "weak_password"));
        h.check_never_echoed(*res, "short");
    }
    SECTION("too long") {
        auto res = h.change(kOld, std::string(1025, 'z'));
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.has_audit("user.password_change", "denied", "too_long"));
        // The length itself is never reported.
        CHECK(res->body.find("1025") == std::string::npos);
        for (const auto& a : h.audits)
            CHECK(a.detail.find("1025") == std::string::npos);
    }
    CHECK(h.stored_hash("eve") == before);
}

TEST_CASE("password routes: a wrong current password is lockout-accounted like /login",
          "[pg][rest][password][lockout]") {
    PasswordRoutesHarness h(/*lockout_threshold=*/3);
    h.wire();
    h.seed("fred", kOld, Role::user);
    h.session_user = "fred";
    const auto before = h.stored_hash("fred");

    for (int i = 0; i < 3; ++i) {
        auto res = h.change("not-the-password", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(error_message_of(*res) == "current password is incorrect");
    }
    CHECK(h.has_audit("user.password_change", "denied", "wrong_current"));
    auto st = h.db->lockout_status("fred");
    REQUIRE(st.has_value());
    CHECK(st->locked);
    CHECK(h.metrics.counter("yuzu_auth_lockout_applied_total").value() == 1.0);

    // Locked: even the CORRECT current password is refused, with the same
    // wire answer (no lock-state oracle) and PBKDF2 skipped.
    auto locked = h.change(kOld, kNew);
    REQUIRE(locked);
    CHECK(locked->status == 403);
    CHECK(error_message_of(*locked) == "current password is incorrect");
    CHECK(h.has_audit("user.password_change", "denied", "account_locked"));
    CHECK(h.metrics.counter("yuzu_auth_lockout_blocked_total").value() == 1.0);
    CHECK(h.stored_hash("fred") == before);

    // An admin unlock (lockout cleared) lets the right password through, and
    // the successful change itself also clears the counter.
    REQUIRE(h.db->clear_failed_logins("fred").has_value());
    REQUIRE(h.db->record_failed_login("fred", 3, 3600).has_value()); // one stale slip
    auto ok = h.change(kOld, kNew);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.db->lockout_status("fred")->failed_count == 0);
}

TEST_CASE("password routes: step-up refusal stops the self change before any write",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("gina", kOld, Role::user);
    h.session_user = "gina";
    h.step_up_pass = false;
    const auto before = h.stored_hash("gina");
    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.stored_hash("gina") == before);
}

TEST_CASE("password routes: unwired deps answer 503, never a partial write",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire_deps = false;
    h.wire();
    h.seed("hank", kOld, Role::user);
    h.session_user = "hank";
    const auto before = h.stored_hash("hank");
    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["retry_after_ms"].is_number());
    CHECK(h.stored_hash("hank") == before);

    h.session_role = Role::admin;
    auto reset = h.reset("someone", kNew);
    REQUIRE(reset);
    CHECK(reset->status == 503);
}

TEST_CASE("password routes: audit failure rolls the self change back (fail-closed)",
          "[pg][rest][password][audit]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("ivy", kOld, Role::user);
    h.session_user = "ivy";
    auto old_token = h.auth_mgr.authenticate("ivy", kOld);
    REQUIRE(old_token.has_value());
    h.audit_fail_match = std::make_pair(std::string("user.password_change"), std::string("ok"));

    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(error_message_of(*res) == "could not record the password change; it was not applied");
    // Rolled back: the OLD password still works, the old session survives.
    CHECK(h.auth_mgr.verify_password("ivy", kOld) == Role::user);
    CHECK_FALSE(h.auth_mgr.verify_password("ivy", kNew).has_value());
    CHECK(h.auth_mgr.validate_session(*old_token).has_value());
    CHECK(h.has_audit("user.password_change", "error", "audit_failed_rolled_back"));
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.changes("self", "error") == 1.0);
}

TEST_CASE("password routes: audit failure whose rollback also fails is disclosed",
          "[pg][rest][password][audit]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("jack", kOld, Role::user);
    h.session_user = "jack";
    h.audit_fail_match = std::make_pair(std::string("user.password_change"), std::string("ok"));
    // A concurrent writer lands between the write and the compensation, so
    // the rollback's CAS (WHERE password_hash = <the hash we wrote>) misses.
    auto salt = AuthManager::random_bytes(16);
    const auto other_hash =
        AuthManager::pbkdf2_sha256("someone-else-pw1", salt, AuthManager::kPbkdf2Iterations);
    const auto other_salt = AuthManager::bytes_to_hex(salt);
    h.on_audit_fail = [&] {
        REQUIRE(h.db->set_password("jack", other_hash, other_salt).has_value());
    };

    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(error_message_of(*res).find("could neither be recorded nor rolled back") !=
          std::string::npos);
    CHECK(h.has_audit("user.password_change", "error", "audit_failed_rollback_failed"));
    // The concurrent writer's credential was never clobbered by the stale
    // compensation.
    CHECK(h.stored_hash("jack") == other_hash);
}

TEST_CASE("password routes: self change for an account with no row answers wrong_current",
          "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.session_user = "kim"; // a session whose account no longer exists
    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    // The lockout-accounted check finds no such user → wrong_current (no
    // account-existence oracle on this path).
    CHECK(res->status == 403);
    CHECK(h.has_audit("user.password_change", "denied", "wrong_current"));
}

// ── Admin reset: POST /api/v1/users/{name}/password ────────────────────────

TEST_CASE("password routes: admin reset succeeds, revokes the target's sessions, reports tokens",
          "[pg][rest][password]") {
    yuzu::test::ApiTokenStorePg tokens;
    PasswordRoutesHarness h;
    h.token_store = tokens.get();
    h.wire();
    h.seed("root", kOld, Role::admin);
    h.seed("lena", kOld, Role::user);
    REQUIRE(tokens->create_token("lena-ci", "lena").has_value());
    h.session_user = "root";
    h.session_role = Role::admin;
    // Arm a lock on the target first — a reset must clear it.
    for (int i = 0; i < 3; ++i)
        REQUIRE(h.db->record_failed_login("lena", 3, 3600).has_value());
    auto lena_session = h.auth_mgr.create_local_session("lena", Role::user, false);
    REQUIRE_FALSE(lena_session.empty());

    auto res = h.reset("lena", kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["username"] == "lena");
    CHECK(d["password_reset"] == true);
    CHECK(d["sessions_revoked"].get<int64_t>() >= 1);
    CHECK(d["api_tokens_active"].get<int64_t>() == 1);
    CHECK(d["remediation"].get<std::string>().find("NOT revoked") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty()); // the CALLER's cookie is untouched

    CHECK_FALSE(h.auth_mgr.validate_session(lena_session).has_value());
    CHECK(h.auth_mgr.verify_password("lena", kNew) == Role::user);
    CHECK_FALSE(h.db->lockout_status("lena")->locked);
    CHECK(h.has_audit("user.password_reset", "ok", "admin_reset target_role=user"));
    CHECK(h.has_audit("session.revoke_all", "success", "count="));
    CHECK(h.changes("admin", "ok") == 1.0);
    h.check_never_echoed(*res, kNew);
}

TEST_CASE("password routes: admin reset refusals", "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("root", kOld, Role::admin);
    h.seed("max", kOld, Role::user);
    h.seed("other_admin", kOld, Role::admin);
    h.session_user = "root";
    h.session_role = Role::admin;

    SECTION("no UserManagement:Write") {
        h.perm_grant = false;
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audits.empty()); // perm_fn owns its own denial evidence
    }
    SECTION("self-target refused — use /me") {
        auto res = h.reset("root", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "self_target"));
        CHECK(h.auth_mgr.verify_password("root", kOld) == Role::admin);
    }
    SECTION("admin target needs a DURABLE admin caller (JIT-elevated user refused)") {
        h.session_role = Role::user; // standing role user; perm_fn admits (elevated)
        auto res = h.reset("other_admin", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "admin_target_requires_durable_admin"));
        CHECK(h.auth_mgr.verify_password("other_admin", kOld) == Role::admin);
    }
    SECTION("admin target with a durable admin caller is allowed") {
        auto res = h.reset("other_admin", kNew);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.has_audit("user.password_reset", "ok", "admin_reset target_role=admin"));
    }
    SECTION("absent account is 404") {
        auto res = h.reset("nobody", kNew);
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(h.has_audit("user.password_reset", "denied", "not_found"));
    }
    SECTION("SCIM-managed account is 409") {
        REQUIRE(h.db->set_provisioning_source("max", "scim").has_value());
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 409);
        CHECK(h.has_audit("user.password_reset", "denied", "not_local"));
    }
    SECTION("SSO principal-shaped name is 409") {
        auto res = h.reset("oidc:idp-sub-1", kNew);
        REQUIRE(res);
        CHECK(res->status == 409);
        CHECK(h.has_audit("user.password_reset", "denied", "not_local"));
    }
    SECTION("token sessions refused") {
        h.session_auth_source = "mcp_token";
        h.session_mcp_tier = "supervised";
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "token_session"));
    }
    SECTION("SSO admin cookie session may reset a local account") {
        h.session_auth_source = "oidc";
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    SECTION("cross-origin refused") {
        auto res = h.post("/api/v1/users/max/password", {{"new_password", kNew}},
                          h.browser_headers("https://evil.example"));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "csrf"));
    }
    SECTION("step-up refusal") {
        h.step_up_pass = false;
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(h.auth_mgr.verify_password("max", kOld) == Role::user);
    }
    SECTION("weak password") {
        auto res = h.reset("max", "short");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.has_audit("user.password_reset", "denied", "weak_password"));
    }
}

TEST_CASE("password routes: admin reset audit failure rolls back; rollback failure disclosed",
          "[pg][rest][password][audit]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("root", kOld, Role::admin);
    h.seed("nora", kOld, Role::user);
    h.session_user = "root";
    h.session_role = Role::admin;
    auto nora_session = h.auth_mgr.create_local_session("nora", Role::user, false);
    REQUIRE_FALSE(nora_session.empty());

    SECTION("rollback succeeds") {
        h.audit_fail_match = std::make_pair(std::string("user.password_reset"), std::string("ok"));
        auto res = h.reset("nora", kNew);
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.auth_mgr.verify_password("nora", kOld) == Role::user);
        CHECK(h.auth_mgr.validate_session(nora_session).has_value()); // nothing revoked
        CHECK(h.has_audit("user.password_reset", "error", "audit_failed_rolled_back"));
    }
    SECTION("rollback fails") {
        h.audit_fail_match = std::make_pair(std::string("user.password_reset"), std::string("ok"));
        h.audit_fail_all_after_first = true; // the best-effort error row is lost too
        h.on_audit_fail = [&] {
            REQUIRE(h.db->set_password("nora", "deadbeef", "cafe").has_value());
        };
        auto res = h.reset("nora", kNew);
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(error_message_of(*res).find("NEW password is now in effect") != std::string::npos);
        CHECK(h.stored_hash("nora") == "deadbeef");
    }
    CHECK(h.changes("admin", "error") == 1.0);
}

TEST_CASE("password routes: the literal /me route wins over the {name} regex",
          "[pg][rest][password]") {
    // httplib dispatches the FIRST matching registration; ([^/]+) also matches
    // "me". A self change must never be routed to the admin reset handler
    // (which would demand UserManagement:Write and skip the current-password
    // proof).
    PasswordRoutesHarness h;
    h.wire();
    h.seed("olga", kOld, Role::user);
    h.session_user = "olga";
    h.perm_grant = false; // the admin route would 403 here
    auto res = h.post("/api/v1/users/me/password", {{"new_password", kNew}}); // no current
    REQUIRE(res);
    CHECK(res->status == 400); // the SELF handler's body validation, not the admin perm gate
    CHECK(h.auth_mgr.verify_password("olga", kOld) == Role::user);
}
