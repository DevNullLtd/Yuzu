/**
 * test_rest_password_routes.cpp — the #5342 REST v1 password routes:
 *
 *   POST /api/v1/users/me/password      {current_password, new_password}
 *   POST /api/v1/users/{name}/password  {new_password}
 *
 * Wiring under test is the production shape: RestApiV1 over a TestRouteSink,
 * a REAL AuthManager over a real (PG) AuthDB for the writes, a REAL AuthRoutes
 * supplying the lockout-accounted current-password check
 * (`password_change_verify_fn`, the same section POST /login runs, incl. the
 * sso-only gate) and the principal-explicit audit writer
 * (`audit_log_for_principal`), and a REAL RbacStore co-located on the AuthDB's
 * own pool (`RbacStoreOnAuthPool`, test_rbac_admin_surface_harness.hpp — the
 * production same-database shape `check_caller_authorized_under_current_regime`
 * JOINs across) for the canonical durable-Administrator gate. Only auth_fn and
 * step_up_fn are harness-controlled, so each gate can be driven directly.
 *
 * #5342 Gate 8 (the class fix): the credential, the account's sessions, its
 * provisional MFA secret, its lockout (admin) and the success audit row(s)
 * commit or abort TOGETHER in one transaction (`CredentialChangeOwner`), so
 * the harness wires a REAL SessionStore + AuditStore + owner on the AuthDB's
 * own pool (the production one-pool shape). Audit-failure cases inject REAL
 * statement faults inside the throwaway database (a renamed table, or a
 * trigger that raises for one principal) — never a fake writer returning
 * false. Concurrency cases (the chaos R5/R5b/M2 repros, inverted) race real
 * requests through the owner's pre-commit hook.
 *
 * Audit `detail` tokens are asserted EXACTLY — they are the SOC 2 CC6.3
 * evidence vocabulary a SIEM rule keys on. REFUSAL rows go through the
 * principal-explicit writer (captured here WITH their principal); SUCCESS
 * rows are read back from the real audit_store. The harness's legacy
 * `audit_fn` records an EMPTY principal on purpose, so any row written
 * through it fails `check_every_row_names()`. No assertion here (or anywhere
 * in the routes) may see a password, its length, or the request body: the
 * "never echoed" cases check the response and every audit row.
 */

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "credential_change_owner.hpp"
#include "rest_api_v1.hpp"
#include "session_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_rbac_admin_surface_harness.hpp" // RbacStoreOnAuthPool
#include "test_route_sink.hpp"
#include "web_utils.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

constexpr const char* kOld = "old-password-123";
constexpr const char* kNew = "new-password-456";

struct AuditRow {
    std::string action, result, principal, target_type, target_id, detail;
};

struct PasswordRoutesHarness {
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    yuzu::test::AuthDbPg db;
    RbacStoreOnAuthPool rbac{db.pool()}; // after db: borrows its pool
    // The production one-pool shape the credential-change transaction needs:
    // durable sessions, the audit store and the owner, all on the AuthDB's pool.
    SessionStore sessions{db.pool()};
    AuditStore audit_store{db.pool()};
    CredentialChangeOwner owner{db.pool(), &audit_store};
    AuthManager auth_mgr;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    // Harness-controlled session (what auth_fn returns when the request
    // carries no yuzu_session cookie). A request WITH a cookie is resolved
    // through the real AuthManager, so revocation is observable end-to-end.
    std::string session_user;
    Role session_role{Role::user};
    std::string session_auth_source{"local"};
    std::string session_mcp_tier;
    std::string session_scope;
    std::string session_principal_kind{"human"};
    bool session_mfa_verified{false};
    bool session_elevated{false};
    bool step_up_pass{true};
    int step_up_calls{0};

    // REFUSAL rows (the principal-explicit writer). Guarded: the concurrency
    // cases write refusal rows from a second request thread.
    std::mutex audits_mu;
    std::vector<AuditRow> audits;

    // Fired by the wrapped verify_current_fn AFTER the real lockout-accounted
    // check returns — i.e. between the self route's step 9 and its
    // transaction (the PBKDF2 window), where a concurrent writer can land.
    std::function<void()> after_verify;

    ApiTokenStore* token_store{nullptr};
    std::vector<std::string> trusted_origins;
    bool wire_deps{true};

    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    /// `login_audit_to_store`: wire the REAL audit_store into AuthRoutes too, so
    /// a /login refusal row (e.g. `mfa.enroll.failed credential_changed`) is
    /// readable through store_rows(). Off by default — the other cases count the
    /// store's rows as the owner's alone.
    explicit PasswordRoutesHarness(int lockout_threshold = 0, bool login_audit_to_store = false) {
        cfg.auth_lockout_threshold = lockout_threshold;
        cfg.auth_lockout_window_secs = 3600;
        cfg.https_enabled = false;
        REQUIRE(sessions.is_open());
        REQUIRE(audit_store.is_open());
        auth_mgr.set_auth_db(db.get());
        auth_mgr.set_session_store(&sessions);
        auth_mgr.set_credential_change_owner(&owner);
        auth_mgr.set_metrics_registry(&metrics);
        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   /*api_token_store=*/nullptr,
                                                   login_audit_to_store ? &audit_store : nullptr,
                                                   /*mgmt_group_store=*/nullptr,
                                                   /*tag_store=*/nullptr,
                                                   /*analytics_store=*/nullptr, oidc_mu,
                                                   oidc_provider);
    }

    /// Register the routes. Separate from the ctor so a test can adjust the
    /// wiring knobs (token_store, trusted_origins, wire_deps, cfg) first.
    void wire() {
        if (wire_deps) {
            // The production wiring (server.cpp): the principal-explicit audit
            // writer, here capturing every row with its principal.
            auto real_verify = auth_routes->password_change_verify_fn();
            api.set_password_change_deps(RestApiV1::PasswordChangeDeps{
                &auth_mgr,
                [this, real_verify](const std::string& user, const std::string& pw,
                                    const httplib::Request& req) {
                    auto r = real_verify(user, pw, req);
                    if (after_verify)
                        after_verify();
                    return r;
                },
                [this](const httplib::Request&, const std::string& action,
                       const std::string& result, const std::string& principal,
                       const std::string&, const std::string& target_type,
                       const std::string& target_id, const std::string& detail) {
                    return record(action, result, principal, target_type, target_id, detail);
                },
                cfg.break_glass_user,
                // The production builder (server.cpp wires the same method).
                [this](const httplib::Request& req, const std::string& principal,
                       const std::string& principal_role, const std::string& target_type,
                       const std::string& target_id) {
                    return auth_routes->make_audit_event_for_principal(
                        req, {}, {}, principal, principal_role, target_type, target_id);
                }});
        }
        api.set_csrf_trusted_origins(trusted_origins);

        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response& res) -> std::optional<auth::Session> {
            const auto cookie = req.get_header_value("Cookie");
            if (cookie.starts_with("yuzu_session=")) {
                auto s = auth_mgr.validate_session(cookie.substr(13));
                if (!s)
                    res.status = 401;
                return s;
            }
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
            if (session_elevated)
                s.elevated_until = std::chrono::system_clock::now() + std::chrono::minutes(10);
            return s;
        };
        // Permissive on purpose: the admin reset no longer consults perm_fn
        // (the canonical is_rbac_administrator predicate replaces it), so a
        // caller this admits must STILL be refused unless it is a durable
        // Administrator — which is what the A1 cases below prove.
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        // The session-RESOLVING audit writer: records an EMPTY principal, the
        // way production's would after the caller's session was revoked.
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            return record(action, result, /*principal=*/"", target_type, target_id, detail);
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
        RestApiV1::LockoutClearFn lockout_clear_fn = [this](const std::string& user) {
            return db->clear_failed_logins(user).has_value();
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn, rbac.get(), /*mgmt_store=*/nullptr,
                            token_store, /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr,
                            /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, step_up_fn,
                            /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{}, /*network_api=*/{},
                            lockout_clear_fn, /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{}, /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{}, /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr, db.get());
    }

    bool record(const std::string& action, const std::string& result, const std::string& principal,
                const std::string& target_type, const std::string& target_id,
                const std::string& detail) {
        std::lock_guard lk(audits_mu);
        audits.push_back({action, result, principal, target_type, target_id, detail});
        return true;
    }

    /// The SUCCESS rows the owner committed to the real audit_store.
    std::vector<AuditRow> store_rows() {
        auto rows = audit_store.query(AuditQuery{.limit = 1000});
        REQUIRE(rows.has_value());
        std::vector<AuditRow> out;
        for (const auto& r : *rows)
            out.push_back({r.action, r.result, r.principal, r.target_type, r.target_id, r.detail});
        return out;
    }

    /// Committed audit rows for one action + target (the real store).
    int committed(const std::string& action, const std::string& target) {
        int n = 0;
        for (const auto& r : store_rows())
            n += (r.action == action && r.target_id == target) ? 1 : 0;
        return n;
    }

    /// Run `sql` against the throwaway database.
    void exec(const std::string& sql) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
        INFO(sql << " -> " << PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
    }

    /// First column of the first row of `sql` ("<null>" for SQL NULL / no row).
    std::string scalar(const std::string& sql) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
        INFO(sql << " -> " << PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) == 0 || PQgetisnull(r.get(), 0, 0))
            return "<null>";
        return PQgetvalue(r.get(), 0, 0);
    }

    /// True iff `user` has no TOTP secret at all (provisional or enrolled).
    bool secret_is_null(const std::string& user) {
        return scalar("SELECT (mfa_totp_secret IS NULL)::text FROM auth.users WHERE username = '" +
                      user + "'") == "true";
    }

    /// REAL statement fault: every audit INSERT fails (42P01) until restored.
    void break_audit_table() {
        exec("ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone");
    }
    void restore_audit_table() {
        exec("ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    }
    /// REAL statement fault for ONE principal: a BEFORE INSERT trigger raises
    /// for that principal's audit rows only (another admin's still commit).
    void fault_audit_for(const std::string& principal) {
        exec("CREATE FUNCTION public.yuzu_test_audit_fault() RETURNS trigger LANGUAGE plpgsql AS "
             "$$ BEGIN IF NEW.principal = '" + principal +
             "' THEN RAISE EXCEPTION 'injected audit fault'; END IF; RETURN NEW; END $$");
        exec("CREATE TRIGGER yuzu_test_audit_fault BEFORE INSERT ON audit_store.audit_events "
             "FOR EACH ROW EXECUTE FUNCTION public.yuzu_test_audit_fault()");
    }

    /// REAL statement fault for ONE audit action: a BEFORE INSERT trigger
    /// raises only when NEW.action matches, so every other audit row commits.
    /// Faulting just the SECOND in-transaction row (auth.lockout.cleared)
    /// proves it shares the credential change's transaction — a fault on the
    /// table as a whole (break_audit_table) cannot tell the two rows apart.
    void fault_audit_for_action(const std::string& action) {
        exec("CREATE FUNCTION public.yuzu_test_audit_action_fault() RETURNS trigger LANGUAGE "
             "plpgsql AS $$ BEGIN IF NEW.action = '" + action +
             "' THEN RAISE EXCEPTION 'injected audit fault'; END IF; RETURN NEW; END $$");
        exec("CREATE TRIGGER yuzu_test_audit_action_fault BEFORE INSERT ON "
             "audit_store.audit_events FOR EACH ROW EXECUTE FUNCTION "
             "public.yuzu_test_audit_action_fault()");
    }

    int sessions_of(const std::string& user) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(
            conn.get(),
            ("SELECT count(*) FROM session_store.sessions WHERE username = '" + user + "'")
                .c_str())};
        REQUIRE(r.ok());
        return std::stoi(PQgetvalue(r.get(), 0, 0));
    }

    void seed(const std::string& user, const std::string& pw, Role role) {
        auto salt = AuthManager::random_bytes(16);
        REQUIRE(db->upsert_user(user,
                                AuthManager::pbkdf2_sha256(pw, salt, AuthManager::kPbkdf2Iterations),
                                AuthManager::bytes_to_hex(salt), role)
                    .has_value());
    }

    /// The default caller: a durable (RBAC-off, local role=admin) administrator.
    void as_admin(const std::string& user = "root") {
        seed(user, kOld, Role::admin);
        session_user = user;
        session_role = Role::admin;
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

    std::unique_ptr<httplib::Response> change_with_cookie(const std::string& token,
                                                          const std::string& current,
                                                          const std::string& next) {
        auto h = browser_headers();
        h["Cookie"] = "yuzu_session=" + token;
        return post("/api/v1/users/me/password",
                    {{"current_password", current}, {"new_password", next}}, h);
    }

    std::unique_ptr<httplib::Response> reset(const std::string& target, const std::string& next) {
        return post("/api/v1/users/" + target + "/password", {{"new_password", next}});
    }

    std::unique_ptr<httplib::Response> reset_with_cookie(const std::string& token,
                                                         const std::string& target,
                                                         const std::string& next) {
        auto h = browser_headers();
        h["Cookie"] = "yuzu_session=" + token;
        return post("/api/v1/users/" + target + "/password", {{"new_password", next}}, h);
    }

    /// Refusal rows (principal-explicit writer) AND committed success rows.
    std::vector<AuditRow> all_rows() {
        std::vector<AuditRow> out;
        {
            std::lock_guard lk(audits_mu);
            out = audits;
        }
        for (auto& r : store_rows())
            out.push_back(std::move(r));
        return out;
    }

    bool has_audit(const std::string& action, const std::string& result,
                   const std::string& detail_prefix = {}) {
        for (const auto& a : all_rows())
            if (a.action == action && a.result == result && a.target_type == "User" &&
                a.detail.starts_with(detail_prefix))
                return true;
        return false;
    }

    /// C5: every row these routes wrote names `principal` (never empty).
    void check_every_row_names(const std::string& principal) {
        const auto rows = all_rows();
        REQUIRE_FALSE(rows.empty());
        for (const auto& a : rows) {
            INFO("action=" << a.action << " result=" << a.result << " detail=" << a.detail);
            CHECK(a.principal == principal);
        }
    }

    double changes(const std::string& kind, const std::string& result) {
        return metrics.counter("yuzu_auth_password_changes_total",
                               {{"kind", kind}, {"result", result}})
            .value();
    }

    /// PBKDF2 verifications run so far (both verdicts of verify_password's
    /// hashing path observe this histogram; a refused-before-hashing attempt
    /// observes neither).
    std::uint64_t pbkdf2_runs() {
        return metrics
                   .histogram("yuzu_auth_login_duration_seconds",
                              {{"method", "password"}, {"result", "bad_password"}})
                   .snapshot()
                   .count +
               metrics
                   .histogram("yuzu_auth_login_duration_seconds",
                              {{"method", "password"}, {"result", "success"}})
                   .snapshot()
                   .count;
    }

    std::string stored_hash(const std::string& user) { return db->get_user(user)->hash_hex; }

    bool password_works(const std::string& user, const std::string& pw) {
        return auth_mgr.verify_password(user, pw).has_value();
    }

    /// No response body or audit row may carry the submitted secret.
    void check_never_echoed(const httplib::Response& res, const std::string& secret) {
        CHECK(res.body.find(secret) == std::string::npos);
        for (const auto& a : all_rows())
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

constexpr const char* kClearCookie = "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";

/// A TOTP code for the current step (+offset) from a base32 secret.
std::string totp_now(const std::string& secret_b32, int offset = 0) {
    auto bytes = yuzu::server::mfa::base32_decode(secret_b32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return yuzu::server::mfa::generate(
        raw, yuzu::server::mfa::current_counter(std::chrono::system_clock::now()) + offset);
}

/// Drop the durable session schema so the next SessionStore op fails (the
/// test_auth_session_store.cpp fault-inject).
void drop_session_schema(yuzu::test::AuthDbPg& db) {
    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult d{PQexec(conn.get(), "DROP SCHEMA session_store CASCADE")};
    REQUIRE(d.ok());
}

/// Break ONLY AuthDB::get_user's SELECT (it reads identity_source).
void break_get_user(yuzu::test::AuthDbPg& db) {
    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult d{
        PQexec(conn.get(), "ALTER TABLE auth.users DROP COLUMN identity_source")};
    REQUIRE(d.ok());
}

} // namespace

// ── Self-service: POST /api/v1/users/me/password ────────────────────────────

TEST_CASE("password routes: self change revokes EVERY session incl. the caller's, no re-mint",
          "[pg][rest][password]") {
    // #5342 Gate 7 (C6): the route revokes first and never re-issues a
    // session — the caller signs in again with the new password.
    PasswordRoutesHarness h;
    h.wire();
    h.seed("alice", kOld, Role::admin);
    auto mine = h.auth_mgr.authenticate("alice", kOld); // the caller's own cookie
    auto other = h.auth_mgr.authenticate("alice", kOld); // a second device
    REQUIRE(mine.has_value());
    REQUIRE(other.has_value());

    auto res = h.change_with_cookie(*mine, kOld, kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["username"] == "alice");
    CHECK(d["password_changed"] == true);
    CHECK(d["session_reissued"] == false);
    CHECK(d["audit_emitted"] == true);
    CHECK(d["provisional_mfa_cleared"] == false);
    CHECK(d["sessions_revoked"].get<int64_t>() >= 2);
    CHECK_FALSE(d.contains("sessions_db_persisted"));
    CHECK(res->get_header_value("Set-Cookie") == kClearCookie);

    // Both sessions are dead — including the one that made the request.
    CHECK_FALSE(h.auth_mgr.validate_session(*mine).has_value());
    CHECK_FALSE(h.auth_mgr.validate_session(*other).has_value());
    auto again = h.change_with_cookie(*mine, kNew, "third-password-789");
    REQUIRE(again);
    CHECK(again->status == 401);

    CHECK_FALSE(h.password_works("alice", kOld));
    CHECK(h.password_works("alice", kNew));
    CHECK(h.has_audit("user.password_change", "ok", "self_service sessions_revoked="));
    // No separate session.revoke_all rows: the success row carries the count.
    for (const auto& a : h.audits)
        CHECK(a.action.rfind("session.revoke_all", 0) == std::string::npos);
    h.check_every_row_names("alice");
    CHECK(h.changes("self", "ok") == 1.0);
    h.check_never_echoed(*res, kOld);
    h.check_never_echoed(*res, kNew);
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
    h.check_every_row_names("bob");
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

TEST_CASE("password routes: self change body + policy validation is unaudited and never echoes",
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
        h.check_never_echoed(*res, "short");
    }
    SECTION("too long") {
        auto res = h.change(kOld, std::string(1025, 'z'));
        REQUIRE(res);
        CHECK(res->status == 400);
        // The length itself is never reported.
        CHECK(res->body.find("1025") == std::string::npos);
    }
    // #5342 Gate 7: body/policy 400s carry no security signal — no audit row.
    CHECK(h.audits.empty());
    CHECK(h.changes("self", "denied") == 1.0);
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

TEST_CASE("password routes: a store fault or mid-verify credential change is a 503, never a strike",
          "[pg][rest][password][lockout]") {
    // #5342 Gate 7 (B3): a password that could not be VERIFIED is not a guess.
    PasswordRoutesHarness h(/*lockout_threshold=*/3);
    h.wire();
    h.seed("tess", kOld, Role::user);
    h.session_user = "tess";

    SECTION("AuthDB read failure") {
        break_get_user(h.db);
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.has_audit("user.password_change", "error", "verify_transient"));
        CHECK_FALSE(h.has_audit("user.password_change", "denied", "wrong_current"));
        CHECK(h.metrics
                  .counter("yuzu_auth_read_degrade_total",
                           {{"route", "password_change"}, {"reason", "query_error"}})
                  .value() == 1.0);
    }
    SECTION("the credential changes under the row lock") {
        auto salt = AuthManager::random_bytes(16);
        const auto racer = AuthManager::pbkdf2_sha256("racer-password-1", salt,
                                                      AuthManager::kPbkdf2Iterations);
        const auto racer_salt = AuthManager::bytes_to_hex(salt);
        bool fired = false;
        h.auth_mgr.set_role_recheck_race_hook_for_test([&] {
            if (fired)
                return;
            fired = true;
            h.exec("UPDATE auth.users SET password_hash = '" + racer + "', salt_hex = '" +
                   racer_salt + "' WHERE username = 'tess'");
        });
        auto res = h.change(kOld, kNew);
        h.auth_mgr.set_role_recheck_race_hook_for_test(nullptr);
        REQUIRE(res);
        CHECK(fired);
        CHECK(res->status == 503);
        CHECK(h.has_audit("user.password_change", "error", "verify_transient"));
        CHECK(h.stored_hash("tess") == racer); // never overwritten
    }
    auto st = h.db->lockout_status("tess");
    REQUIRE(st.has_value());
    CHECK(st->failed_count == 0); // no strike either way
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

TEST_CASE("password routes: a REAL audit fault makes NO change — the caller keeps their session",
          "[pg][rest][password][audit]") {
    // #5342 Gate 8 T1(ii)/T3: the success row is INSERTed inside the
    // credential transaction; the audit table is renamed in the throwaway DB,
    // so that INSERT genuinely fails and the WHOLE change rolls back. No
    // rollback write, no revoke-first: the credential, the sessions and the
    // caller's cookie are exactly as they were.
    PasswordRoutesHarness h;
    h.wire();
    h.seed("ivy", kOld, Role::user);
    auto token = h.auth_mgr.authenticate("ivy", kOld);
    REQUIRE(token.has_value());
    const auto before = h.stored_hash("ivy");
    h.break_audit_table();

    auto res = h.change_with_cookie(*token, kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["retry_after_ms"].is_number());
    CHECK(error_message_of(*res).find("nothing was changed unless the server lost contact with "
                                      "the database at commit") != std::string::npos);
    CHECK(error_message_of(*res).find("rolled back") == std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty()); // refusal: the cookie is NOT cleared
    // Nothing changed: same hash, the session still validates, old pw works.
    CHECK(h.stored_hash("ivy") == before);
    CHECK(h.auth_mgr.validate_session(*token).has_value());
    CHECK(h.sessions_of("ivy") == 1);
    CHECK(h.password_works("ivy", kOld));
    CHECK_FALSE(h.password_works("ivy", kNew));
    {
        std::lock_guard lk(h.audits_mu);
        bool saw = false;
        for (const auto& a : h.audits)
            saw = saw || (a.action == "user.password_change" && a.detail == "audit_unavailable");
        CHECK(saw);
    }
    CHECK(h.changes("self", "error") == 1.0);
    CHECK(h.changes("self", "ok") == 0.0);
    h.restore_audit_table();
    CHECK(h.committed("user.password_change", "ivy") == 0);
}

TEST_CASE("password routes: a session-store fault inside the transaction makes NO change",
          "[pg][rest][password]") {
    // The DELETE of the account's sessions is a statement of the same
    // transaction: if it fails, the credential write rolls back with it.
    PasswordRoutesHarness h;
    h.wire();
    h.seed("kurt", kOld, Role::user);
    h.as_admin();

    SECTION("self route") {
        h.session_user = "kurt";
        h.session_role = Role::user;
        const auto before = h.stored_hash("kurt");
        drop_session_schema(h.db);
        auto res = h.change(kOld, kNew);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(nlohmann::json::parse(res->body)["error"]["retry_after_ms"].is_number());
        CHECK(h.has_audit("user.password_change", "error", "store_unavailable"));
        CHECK(h.stored_hash("kurt") == before);
        CHECK(h.committed("user.password_change", "kurt") == 0);
        h.check_every_row_names("kurt");
    }
    SECTION("admin route") {
        const auto before = h.stored_hash("kurt");
        drop_session_schema(h.db);
        auto res = h.reset("kurt", kNew);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.has_audit("user.password_reset", "error", "store_unavailable"));
        CHECK(h.stored_hash("kurt") == before);
        CHECK(h.committed("user.password_reset", "kurt") == 0);
        h.check_every_row_names("root");
    }
}

TEST_CASE("password routes: a refusal under the row lock changes nothing — sessions stay valid",
          "[pg][rest][password]") {
    // T1(i)/T3: classification happens UNDER the lock, inside the transaction
    // that would write; a refusal writes nothing at all — in particular it no
    // longer revokes the target's sessions first.
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("lara", kOld, Role::user);
    auto lara_session = h.auth_mgr.create_local_session_for_test("lara", Role::user, false);
    REQUIRE_FALSE(lara_session.empty());
    const auto before = h.stored_hash("lara");
    REQUIRE(h.db->set_provisioning_source("lara", "scim").has_value());

    auto res = h.reset("lara", kNew);
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(error_message_of(*res).find("sessions were revoked") == std::string::npos);
    CHECK(h.has_audit("user.password_reset", "denied", "not_local"));
    CHECK(h.auth_mgr.validate_session(lara_session).has_value());
    CHECK(h.sessions_of("lara") == 1);
    CHECK(h.stored_hash("lara") == before);
    CHECK(h.committed("user.password_reset", "lara") == 0);
    h.check_every_row_names("root");
}

TEST_CASE("password routes: an admin reset landing after the self route's verify is a 409 conflict",
          "[pg][rest][password]") {
    // The verified anchor is compared UNDER the row lock: an admin reset that
    // commits in the self route's PBKDF2 window wins, and the self change
    // writes nothing (409 conflict, the caller's cookie is not cleared).
    PasswordRoutesHarness h;
    h.wire();
    h.seed("vera", kOld, Role::user);
    h.session_user = "vera";
    std::string admin_hash;
    h.after_verify = [&] {
        h.after_verify = nullptr;
        CredentialChangeRequest r;
        r.kind = CredentialChangeRequest::Kind::kAdminReset;
        r.username = "vera";
        const auto salt = AuthManager::random_bytes(16);
        r.new_salt_hex = AuthManager::bytes_to_hex(salt);
        r.new_hash_hex =
            AuthManager::pbkdf2_sha256("admin-set-pw-123", salt, AuthManager::kPbkdf2Iterations);
        r.audit_template.principal = "root";
        r.audit_template.target_type = "User";
        r.audit_template.target_id = "vera";
        REQUIRE(h.auth_mgr.commit_password_change(r).result == CredentialChangeResult::kOk);
        admin_hash = r.new_hash_hex;
    };
    auto res = h.change(kOld, kNew);
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(h.has_audit("user.password_change", "denied", "conflict"));
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.stored_hash("vera") == admin_hash);
    CHECK(h.committed("user.password_change", "vera") == 0);
    CHECK(h.committed("user.password_reset", "vera") == 1);
}

TEST_CASE("password routes: a session minted with the OLD credential during the change never "
          "survives (M2)",
          "[pg][rest][password]") {
    // #5342 Gate 8 M2 (g8-security-guardian-1 inverted). The owner's
    // pre-commit hook fires with every lock held; a racing mint for the OLD
    // credential is started there and allowed to proceed once the hook
    // returns. Whatever it manages, after the route returns no session minted
    // with the old credential is valid and no durable row for the account
    // remains.
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("vic", kOld, Role::user);
    const auto old_anchor = h.auth_mgr.verify_password("vic", kOld)->hash_hex;

    std::string minted = "unset";
    // jthread: joined on every exit path (a throwing request or a failed
    // REQUIRE never leaves a joinable std::thread to std::terminate).
    std::jthread racer;
    std::atomic<bool> fired{false};
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        racer = std::jthread(
            [&] { minted = h.auth_mgr.create_local_session("vic", Role::user, false, old_anchor); });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    });
    auto res = h.reset("vic", kNew);
    if (racer.joinable())
        racer.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join: nothing can still fire it
    REQUIRE(fired);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK((minted.empty() || !h.auth_mgr.validate_session(minted).has_value()));
    CHECK(h.sessions_of("vic") == 0);
    CHECK(h.password_works("vic", kNew));
}

TEST_CASE("password routes: an old-password MFA login challenge completed during the change is "
          "denied (M2)",
          "[pg][rest][password][mfa]") {
    // The /login/mfa completion of a pending token proven with the OLD
    // password races the reset's transaction: its TOTP consume blocks on the
    // held auth.users row, and the mint's locking post-mint re-read then sees
    // the new hash — 401, no session.
    PasswordRoutesHarness h;
    h.wire();
    h.auth_routes->register_routes(h.sink);
    h.as_admin();
    h.seed("mfa_vic", kOld, Role::user);
    auto init = h.db->mfa_init_enrollment("mfa_vic", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    REQUIRE(h.db->mfa_verify_enrollment("mfa_vic", totp_now(init->secret_base32), std::nullopt)
                .has_value());
    auto step1 = h.sink.Post("/login", "username=mfa_vic&password=" + std::string(kOld),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1);
    REQUIRE(step1->status == 202);
    const std::string pending = nlohmann::json::parse(step1->body).at("mfa_pending_token");

    std::unique_ptr<httplib::Response> step2;
    std::jthread racer; // joined on every exit path
    std::atomic<bool> fired{false};
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        racer = std::jthread([&] {
            step2 = h.sink.Post("/login/mfa",
                                "mfa_pending_token=" + pending +
                                    "&code=" + totp_now(init->secret_base32, 1),
                                "application/x-www-form-urlencoded");
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    });
    auto res = h.reset("mfa_vic", kNew);
    if (racer.joinable())
        racer.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(step2);
    CHECK(step2->status == 401);
    CHECK(step2->get_header_value("Set-Cookie").empty());
    CHECK(h.sessions_of("mfa_vic") == 0);
}

// ── #5342 Gate 8 iteration 3 (F4): every MFA enrolment write is anchored ────
//
// The credential change holds the account's auth.users row lock for its whole
// transaction (and wipes a provisional secret). An enrolment write that read
// the row before the change and then queued on that lock re-evaluates its
// guarded WHERE against the committed row; the password_hash anchor makes it
// match nothing → CredentialChanged. Every case below rendezvouses on the REAL
// lock wait (wait_for_pg_lock_waiter), never a sleep.

TEST_CASE("password routes: an MFA init queued behind a reset lands as CredentialChanged, never a "
          "post-reset secret (chaos R4b inverted)",
          "[pg][rest][password][mfa]") {
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin("rootA");
    h.seed("vic", kOld, Role::user);
    const auto old_hash = h.stored_hash("vic");

    std::optional<std::expected<AuthDB::MfaEnrollmentInit, AuthDBError>> racing_result;
    std::atomic<bool> init_returned{false};
    std::atomic<bool> fired{false};
    bool waiter_seen = false;
    bool returned_before_commit = true;
    std::jthread racer; // joined on every exit path
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        // Settings shape (no proven hash): the store anchors to its own read.
        racer = std::jthread([&] {
            racing_result = h.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
            init_returned = true;
        });
        waiter_seen = yuzu::test::wait_for_pg_lock_waiter(
            h.db.dsn(), "%UPDATE auth.users SET mfa_totp_secret%");
        returned_before_commit = init_returned.load();
    });
    auto res = h.reset("vic", kNew);
    if (racer.joinable())
        racer.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(waiter_seen);                  // the racing mint really queued on the row lock
    CHECK_FALSE(returned_before_commit); // ...and resolved only after COMMIT
    REQUIRE(racing_result.has_value());
    REQUIRE_FALSE(racing_result->has_value()); // no secret was minted for the racer
    CHECK(racing_result->error() == AuthDBError::CredentialChanged);
    CHECK(h.secret_is_null("vic")); // no provisional secret survives the reset

    // The victim's own enrolment works normally afterwards (no false refusal)...
    auto victim = h.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
    REQUIRE(victim.has_value());
    const auto code = totp_now(victim->secret_base32);
    // ...but not under the RETIRED credential (the login-bootstrap anchor).
    // Checked first: once enrolled, every verify answers MfaAlreadyEnrolled.
    auto via_old = h.db->mfa_verify_enrollment("vic", code, old_hash);
    REQUIRE_FALSE(via_old.has_value());
    CHECK(via_old.error() == AuthDBError::CredentialChanged);
    auto via_settings = h.db->mfa_verify_enrollment("vic", code, std::nullopt);
    REQUIRE(via_settings.has_value());
    CHECK(h.db->mfa_status("vic")->enrolled);
}

TEST_CASE("password routes: a Settings MFA verify queued behind a reset is CredentialChanged, "
          "never an enrolment (F4)",
          "[pg][rest][password][mfa]") {
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin("rootA");
    h.seed("vic", kOld, Role::user);
    auto init = h.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    const auto code = totp_now(init->secret_base32);

    std::optional<std::expected<std::vector<std::string>, AuthDBError>> during;
    std::atomic<bool> fired{false};
    bool waiter_seen = false;
    std::jthread racer; // joined on every exit path
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        racer = std::jthread(
            [&] { during = h.db->mfa_verify_enrollment("vic", code, std::nullopt); });
        waiter_seen = yuzu::test::wait_for_pg_lock_waiter(
            h.db.dsn(), "%UPDATE auth.users SET mfa_enrolled_at%");
    });
    auto res = h.reset("vic", kNew);
    if (racer.joinable())
        racer.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(waiter_seen);
    REQUIRE(during.has_value());
    REQUIRE_FALSE(during->has_value());
    CHECK(during->error() == AuthDBError::CredentialChanged); // not a WriteFailed/503
    CHECK_FALSE(h.db->mfa_status("vic")->enrolled);
    CHECK(h.scalar("SELECT count(*) FROM auth.mfa_recovery_codes WHERE username = 'vic'") == "0");
}

TEST_CASE("password routes: a /login enrolment bootstrap queued behind a reset of its password is "
          "a uniform 401 with no secret and no pending token (F4)",
          "[pg][rest][password][mfa]") {
    // mfa_enforcement=required, an un-enrolled victim, /login with the OLD
    // password. To land the bootstrap's mint INSIDE the reset's transaction the
    // login is first parked AFTER its password check (incl. the row-locked
    // re-check) on a table lock only its MFA status read touches
    // (auth.mfa_recovery_codes); the reset's pre-commit hook releases it and
    // waits until the mint queues on the reset's row lock.
    PasswordRoutesHarness h(/*lockout_threshold=*/0, /*login_audit_to_store=*/true);
    h.wire();
    h.auth_routes->register_routes(h.sink);
    h.cfg.mfa_enforcement = "required"; // cfg_ is held by reference
    h.auth_routes->set_mfa_pending_cap_for_test(1); // a leftover pending entry is observable
    h.as_admin("rootA");
    h.seed("vic", kOld, Role::user);
    h.seed("probe", kOld, Role::user);

    yuzu::server::pg::PgConn locker{PQconnectdb(h.db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    auto run = [&](const char* sql) {
        yuzu::server::pg::PgResult r{PQexec(locker.get(), sql)};
        return r.ok();
    };
    REQUIRE(run("BEGIN"));
    REQUIRE(run("LOCK TABLE auth.mfa_recovery_codes IN ACCESS EXCLUSIVE MODE"));

    std::unique_ptr<httplib::Response> login;
    std::atomic<bool> fired{false};
    bool released = false;
    bool mint_waiter_seen = false;
    std::jthread racer([&] {
        login = h.sink.Post("/login", "username=vic&password=" + std::string(kOld),
                            "application/x-www-form-urlencoded");
    });
    const bool parked = yuzu::test::wait_for_pg_lock_waiter(h.db.dsn(), "%mfa_recovery_codes%");
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        released = run("ROLLBACK");
        mint_waiter_seen = yuzu::test::wait_for_pg_lock_waiter(
            h.db.dsn(), "%UPDATE auth.users SET mfa_totp_secret%");
    });
    auto res = h.reset("vic", kNew);
    if (!fired)
        (void)run("ROLLBACK"); // never leave the login parked
    if (racer.joinable())
        racer.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(parked);
    CHECK(released);
    CHECK(mint_waiter_seen);

    // END STATE: the uniform /login 401, nothing revealed, nothing stored.
    REQUIRE(login);
    INFO("login=" << login->status << " " << login->body);
    CHECK(login->status == 401);
    CHECK(login->body.find("mfa_pending_token") == std::string::npos);
    CHECK(login->body.find("secret_base32") == std::string::npos);
    CHECK(login->get_header_value("Set-Cookie").empty());
    CHECK(h.secret_is_null("vic"));
    const bool login_failed = h.committed("auth.login_failed", "vic") > 0;
    bool enroll_cc = false;
    for (const auto& r : h.store_rows())
        enroll_cc = enroll_cc || (r.action == "mfa.enroll.failed" && r.result == "error" &&
                                  r.target_id == "vic" && r.detail == "credential_changed");
    CHECK((login_failed || enroll_cc));
    // The rendezvous above is deterministic, so it is the F4 refusal that fired.
    CHECK(enroll_cc);
    // mfa_pending_ is empty: with the cap at 1, another enforced login still
    // gets its enrolment challenge (a leftover entry would load-shed it, 503).
    auto probe = h.sink.Post("/login", "username=probe&password=" + std::string(kOld),
                             "application/x-www-form-urlencoded");
    REQUIRE(probe);
    CHECK(probe->status == 202);
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

TEST_CASE("password routes: under sso-only a DISARMED break-glass session cannot guess or lock",
          "[pg][rest][password][lockout]") {
    // #5342 Gate 7 (C8): the self route runs /login's sso-only gate. Arm,
    // sign in, disarm: the still-live session must get 403
    // sso_only_local_disabled for every attempt, with zero PBKDF2 and no
    // lockout strike — it is not a guessing oracle once the window closes.
    PasswordRoutesHarness h(/*lockout_threshold=*/3);
    h.cfg.auth_mode = "sso-only";
    h.cfg.break_glass_user = "bg";
    h.wire();
    h.seed("bg", kOld, Role::admin);
    REQUIRE(h.db->arm_break_glass("bg", 600).has_value());
    h.session_user = "bg"; // signed in while armed
    h.session_role = Role::admin;
    REQUIRE(h.db->disarm_break_glass("bg").has_value());

    const auto pbkdf2_before = h.pbkdf2_runs();
    for (int i = 0; i < 20; ++i) {
        auto res = h.change("wrong-guess-" + std::to_string(i), kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_change", "denied", "sso_only_local_disabled"));
    }
    CHECK(h.pbkdf2_runs() == pbkdf2_before);
    CHECK_FALSE(h.has_audit("user.password_change", "denied", "wrong_current"));
    auto st = h.db->lockout_status("bg");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);
    CHECK(st->failed_count == 0);
    CHECK(h.password_works("bg", kOld));

    // Re-armed: the route behaves normally again.
    REQUIRE(h.db->arm_break_glass("bg", 600).has_value());
    auto wrong = h.change("still-not-it-123", kNew);
    REQUIRE(wrong);
    CHECK(wrong->status == 403);
    CHECK(h.has_audit("user.password_change", "denied", "wrong_current"));
    auto ok = h.change(kOld, kNew);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

// ── Admin reset: POST /api/v1/users/{name}/password ────────────────────────

TEST_CASE("password routes: admin reset succeeds, revokes the target's sessions, clears its lock",
          "[pg][rest][password]") {
    yuzu::test::ApiTokenStorePg tokens;
    PasswordRoutesHarness h;
    h.token_store = tokens.get();
    h.wire();
    h.as_admin();
    h.seed("lena", kOld, Role::user);
    REQUIRE(tokens->create_token("lena-ci", "lena").has_value());
    REQUIRE(tokens->create_token("lena-backup", "lena").has_value());
    // Arm a lock on the target first — a reset must clear it (audited).
    for (int i = 0; i < 3; ++i)
        REQUIRE(h.db->record_failed_login("lena", 3, 3600).has_value());
    auto lena_session = h.auth_mgr.create_local_session_for_test("lena", Role::user, false);
    REQUIRE_FALSE(lena_session.empty());

    auto res = h.reset("lena", kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["username"] == "lena");
    CHECK(d["password_reset"] == true);
    CHECK(d["sessions_revoked"].get<int64_t>() >= 1);
    CHECK(d["lockout_cleared"] == true); // a lockout existed and was cleared, in-transaction
    CHECK(d["provisional_mfa_cleared"] == false);
    CHECK(d["api_tokens_active"].get<int64_t>() == 2);
    CHECK_FALSE(d.contains("api_tokens_unknown"));
    CHECK_FALSE(d.contains("sessions_db_persisted"));
    CHECK(d["remediation"].get<std::string>().find("NOT revoked") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty()); // the CALLER's cookie is untouched

    CHECK_FALSE(h.auth_mgr.validate_session(lena_session).has_value());
    CHECK(h.password_works("lena", kNew));
    CHECK_FALSE(h.db->lockout_status("lena")->locked);
    CHECK(h.has_audit("user.password_reset", "ok", "admin_reset target_role=user sessions_revoked="));
    CHECK(h.has_audit("auth.lockout.cleared", "ok", "password_reset"));
    for (const auto& a : h.audits)
        CHECK(a.action.rfind("session.revoke_all", 0) == std::string::npos);
    h.check_every_row_names("root");
    CHECK(h.changes("admin", "ok") == 1.0);
    h.check_never_echoed(*res, kNew);
}

TEST_CASE("password routes: admin reset of a never-locked account reports lockout_cleared:false "
          "and writes NO auth.lockout.cleared row",
          "[pg][rest][password][lockout]") {
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("calm", kOld, Role::user);
    auto res = h.reset("calm", kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["lockout_cleared"] == false);
    CHECK(d["remediation"].get<std::string>().find("/unlock") == std::string::npos);
    CHECK(h.committed("auth.lockout.cleared", "calm") == 0);
    CHECK(h.committed("user.password_reset", "calm") == 1);
}

TEST_CASE("password routes: admin reset wipes a provisional TOTP secret (F1)",
          "[pg][rest][password][mfa]") {
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("pend", kOld, Role::user);
    auto s1 = h.db->mfa_init_enrollment("pend", "Yuzu", std::nullopt);
    REQUIRE(s1.has_value());
    auto res = h.reset("pend", kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(data_of(*res)["provisional_mfa_cleared"] == true);
    CHECK_FALSE(h.db->mfa_status("pend")->enrolled);
    auto s2 = h.db->mfa_init_enrollment("pend", "Yuzu", std::nullopt);
    REQUIRE(s2.has_value());
    CHECK(s1->secret_base32 != s2->secret_base32);
}

TEST_CASE("password routes: admin reset reports unknown API tokens as null, never 0",
          "[pg][rest][password]") {
    // #5342 Gate 7 (D9): a token-store read failure is "could not confirm".
    yuzu::test::ApiTokenStorePg tokens;
    PasswordRoutesHarness h;
    h.token_store = tokens.get();
    h.wire();
    h.as_admin();
    h.seed("noel", kOld, Role::user);
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(tokens.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE api_token_store.api_tokens CASCADE")};
        REQUIRE(d.ok());
    }
    auto res = h.reset("noel", kNew);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto d = data_of(*res);
    CHECK(d["api_tokens_active"].is_null());
    CHECK(d["api_tokens_unknown"] == true);
    CHECK(d["remediation"].get<std::string>().find("could not confirm") != std::string::npos);

    SECTION("no token store wired at all") {
        PasswordRoutesHarness h2;
        h2.wire();
        h2.as_admin();
        h2.seed("nina", kOld, Role::user);
        auto r2 = h2.reset("nina", kNew);
        REQUIRE(r2);
        REQUIRE(r2->status == 200);
        CHECK(data_of(*r2)["api_tokens_active"].is_null());
        CHECK(data_of(*r2)["api_tokens_unknown"] == true);
    }
}

TEST_CASE("password routes: the admin gate is the canonical durable-Administrator predicate",
          "[pg][rest][password]") {
    // #5342 Gate 7 (A1): is_rbac_administrator(kRest) + the fresh regime
    // re-read gate EVERY target; perm_fn (here permissive) plays no part.
    PasswordRoutesHarness h;
    h.wire();
    h.seed("max", kOld, Role::user);
    const auto before = h.stored_hash("max");

    SECTION("RBAC off: a durable local admin may reset") {
        h.as_admin();
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    SECTION("RBAC off: a JIT-elevated user is refused") {
        h.seed("jit", kOld, Role::user);
        h.session_user = "jit";
        h.session_role = Role::user;
        h.session_elevated = true; // effective role admin; durable role user
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "durable_admin_required"));
        CHECK(h.stored_hash("max") == before);
    }
    SECTION("RBAC off: an OIDC session with an IdP-group-derived admin role is refused") {
        const std::string principal = "oidc:https://idp.example#grp-admin";
        REQUIRE(h.db->upsert_sso_identity(principal, "https://idp.example", "grp-admin", "G",
                                          "oidc")
                    .has_value()); // auth.users.role stays 'user'
        h.session_user = principal;
        h.session_role = Role::admin; // what resolve_role_from_groups stamps
        h.session_auth_source = "oidc";
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "durable_admin_required"));
        CHECK(h.stored_hash("max") == before);
    }
    SECTION("RBAC on: an Administrator grant holder may reset") {
        h.seed("rbacadm", kOld, Role::user);
        REQUIRE(h.rbac->set_rbac_enabled(true).has_value());
        REQUIRE(h.rbac->assign_role({"user", "rbacadm", "Administrator"}).has_value());
        h.session_user = "rbacadm";
        h.session_role = Role::user;
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.password_works("max", kNew));
    }
    SECTION("RBAC on: a custom role holding UserManagement:Write is not enough") {
        h.seed("helpdesk", kOld, Role::user);
        REQUIRE(h.rbac->set_rbac_enabled(true).has_value());
        REQUIRE(h.rbac->create_role({"PwHelpdesk", "test role", false, 0}).has_value());
        REQUIRE(h.rbac->set_permission({"PwHelpdesk", "UserManagement", "Write", "allow"})
                    .has_value());
        REQUIRE(h.rbac->assign_role({"user", "helpdesk", "PwHelpdesk"}).has_value());
        h.session_user = "helpdesk";
        h.session_role = Role::user;
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "durable_admin_required"));
        CHECK(h.stored_hash("max") == before);
    }
    SECTION("RBAC on + a degraded RBAC store: 503, never a denial or an admit") {
        h.seed("rbacadm", kOld, Role::user);
        REQUIRE(h.rbac->set_rbac_enabled(true).has_value());
        REQUIRE(h.rbac->assign_role({"user", "rbacadm", "Administrator"}).has_value());
        h.session_user = "rbacadm";
        {
            yuzu::server::pg::PgConn conn{PQconnectdb(h.db.dsn().c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            yuzu::server::pg::PgResult d{
                PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
            REQUIRE(d.ok());
        }
        auto res = h.reset("max", kNew);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.has_audit("user.password_reset", "error", "admin_gate_unavailable"));
        CHECK(h.stored_hash("max") == before);
    }
}

TEST_CASE("password routes: admin reset refusals", "[pg][rest][password]") {
    PasswordRoutesHarness h;
    h.cfg.break_glass_user = "bg";
    h.wire();
    h.as_admin();
    h.seed("max", kOld, Role::user);
    h.seed("other_admin", kOld, Role::admin);
    h.seed("bg", kOld, Role::admin);

    SECTION("self-target refused — use /me") {
        auto res = h.reset("root", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "self_target"));
        CHECK(h.password_works("root", kOld));
    }
    SECTION("the break-glass account is never a reset target") {
        auto res = h.reset("bg", kNew);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.has_audit("user.password_reset", "denied", "break_glass_target"));
        CHECK(h.step_up_calls == 0); // refused BEFORE step-up
        CHECK(h.password_works("bg", kOld));
    }
    SECTION("an admin target is just another target for a durable admin") {
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
        CHECK(h.password_works("max", kOld));
    }
    SECTION("weak password is a 400 with no audit row") {
        auto res = h.reset("max", "short");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.audits.empty());
    }
    for (const auto& a : h.audits)
        CHECK(a.principal == "root");
}

TEST_CASE("password routes: admin reset under a REAL audit fault makes no change at all",
          "[pg][rest][password][audit]") {
    // T1(ii) for the admin route: the lockout stays armed, the target's
    // session stays valid, the credential is untouched, and no
    // auth.lockout.cleared row exists — one transaction, nothing half-done.
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("nora", kOld, Role::user);
    auto nora_session = h.auth_mgr.create_local_session_for_test("nora", Role::user, false);
    REQUIRE_FALSE(nora_session.empty());
    for (int i = 0; i < 3; ++i)
        REQUIRE(h.db->record_failed_login("nora", 3, 3600).has_value());
    const auto armed = h.db->lockout_status("nora");
    REQUIRE(armed->locked);
    const auto before = h.stored_hash("nora");
    h.break_audit_table();

    auto res = h.reset("nora", kNew);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(nlohmann::json::parse(res->body)["error"]["retry_after_ms"].is_number());
    CHECK(h.stored_hash("nora") == before);
    CHECK(h.password_works("nora", kOld));
    CHECK(h.auth_mgr.validate_session(nora_session).has_value());
    auto st = h.db->lockout_status("nora");
    REQUIRE(st.has_value());
    CHECK(st->locked);
    CHECK(st->failed_count == armed->failed_count);
    CHECK(h.changes("admin", "error") == 1.0);
    h.restore_audit_table();
    CHECK(h.committed("user.password_reset", "nora") == 0);
    CHECK(h.committed("auth.lockout.cleared", "nora") == 0);
}

TEST_CASE("password routes: a fault on ONLY the auth.lockout.cleared row rolls the whole reset back",
          "[pg][rest][password][audit][lockout]") {
    // The SECOND in-transaction audit row is atomic with the credential
    // change too: the user.password_reset INSERT succeeds, the
    // auth.lockout.cleared INSERT alone faults, and nothing at all commits —
    // not the hash, not the lockout clear, not the session revoke, not the
    // first audit row. A lockout row written post-commit would leave the reset
    // standing here.
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin();
    h.seed("lockd", kOld, Role::user);
    auto lockd_session = h.auth_mgr.create_local_session_for_test("lockd", Role::user, false);
    REQUIRE_FALSE(lockd_session.empty());
    for (int i = 0; i < 3; ++i)
        REQUIRE(h.db->record_failed_login("lockd", 3, 3600).has_value());
    const auto armed = h.db->lockout_status("lockd");
    REQUIRE(armed->locked);
    const auto before = h.stored_hash("lockd");
    h.fault_audit_for_action("auth.lockout.cleared");

    auto res = h.reset("lockd", kNew);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.stored_hash("lockd") == before);
    CHECK(h.password_works("lockd", kOld));
    CHECK(h.auth_mgr.validate_session(lockd_session).has_value());
    auto st = h.db->lockout_status("lockd");
    REQUIRE(st.has_value());
    CHECK(st->locked);
    CHECK(st->failed_count == armed->failed_count);
    CHECK(h.committed("user.password_reset", "lockd") == 0);
    CHECK(h.committed("auth.lockout.cleared", "lockd") == 0);
}

TEST_CASE("password routes: two concurrent admin resets, the second's audit faulted — the first "
          "stands (chaos R5 inverted)",
          "[pg][rest][password][audit]") {
    // Admin B's reset holds the row lock (pre-commit hook); admin A's reset of
    // the same account starts in a second thread and queues on that lock. B
    // commits; A then writes and its audit INSERT hits a REAL fault (a trigger
    // raising for rootA's rows) — A's whole transaction rolls back. Before the
    // class fix, A's stale-snapshot ROLLBACK resurrected H0 over B's audited
    // reset.
    PasswordRoutesHarness h;
    h.wire();
    h.seed("rootA", kOld, Role::admin);
    h.seed("rootB", kOld, Role::admin);
    h.seed("vic", kOld, Role::user);
    const auto h0 = h.stored_hash("vic");
    const auto tokA = h.auth_mgr.create_local_session_for_test("rootA", Role::admin, true);
    const auto tokB = h.auth_mgr.create_local_session_for_test("rootB", Role::admin, true);
    REQUIRE_FALSE(tokA.empty());
    REQUIRE_FALSE(tokB.empty());
    h.fault_audit_for("rootA");
    constexpr const char* kA = "admin-a-password-012";
    constexpr const char* kB = "admin-b-password-789";

    std::unique_ptr<httplib::Response> resA;
    std::atomic<bool> fired{false};
    std::jthread admin_a; // joined on every exit path
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        admin_a = std::jthread([&] { resA = h.reset_with_cookie(tokA, "vic", kA); });
        std::this_thread::sleep_for(std::chrono::milliseconds(400)); // A queues on the row lock
    });
    auto resB = h.reset_with_cookie(tokB, "vic", kB);
    if (admin_a.joinable())
        admin_a.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(resB);
    REQUIRE(resA);
    INFO("B=" << resB->status << " " << resB->body);
    INFO("A=" << resA->status << " " << resA->body);
    CHECK(resB->status == 200);
    CHECK(resA->status == 503);
    CHECK(resA->get_header_value("Sec-Audit-Failed") == "true");
    const auto final_hash = h.stored_hash("vic");
    CHECK(final_hash != h0);
    CHECK(h.password_works("vic", kB));
    CHECK_FALSE(h.password_works("vic", kA));
    CHECK_FALSE(h.password_works("vic", kOld));
    CHECK(h.committed("user.password_reset", "vic") == 1); // B's row, exactly one
}

TEST_CASE("password routes: a victim's self-change then a faulted admin reset — the victim's "
          "rotation stands (chaos R5b inverted)",
          "[pg][rest][password][audit]") {
    PasswordRoutesHarness h;
    h.wire();
    h.seed("rootA", kOld, Role::admin);
    h.seed("vic", kOld, Role::user);
    const auto tokA = h.auth_mgr.create_local_session_for_test("rootA", Role::admin, true);
    auto tokVic = h.auth_mgr.authenticate("vic", kOld);
    REQUIRE(tokVic.has_value());
    h.fault_audit_for("rootA");
    constexpr const char* kSelf = "victim-self-new-345";
    constexpr const char* kA = "admin-a-password-012";

    std::unique_ptr<httplib::Response> resA;
    std::atomic<bool> fired{false};
    std::jthread admin_a; // joined on every exit path
    h.owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        admin_a = std::jthread([&] { resA = h.reset_with_cookie(tokA, "vic", kA); });
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    });
    auto resSelf = h.change_with_cookie(*tokVic, kOld, kSelf);
    if (admin_a.joinable())
        admin_a.join();
    h.owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(resSelf);
    REQUIRE(resA);
    INFO("self=" << resSelf->status << " " << resSelf->body);
    INFO("A=" << resA->status << " " << resA->body);
    CHECK(resSelf->status == 200);
    CHECK(resA->status == 503);
    CHECK(h.password_works("vic", kSelf));
    CHECK_FALSE(h.password_works("vic", kOld));
    CHECK_FALSE(h.password_works("vic", kA));
    CHECK(h.committed("user.password_change", "vic") == 1);
    CHECK(h.committed("user.password_reset", "vic") == 0);
}

TEST_CASE("password routes: a lock held on the audit table never stalls unrelated session writes "
          "(chaos R18 inverted, T1')",
          "[pg][rest][password][audit]") {
    // #5342 Gate 8 iteration 3 (T1'). A second connection holds ACCESS
    // EXCLUSIVE on audit_store.audit_events, so the reset's audit INSERT waits
    // (and finally times out). The owner takes the fleet-shared
    // session_store.session_meta row only AFTER that INSERT, so an UNRELATED
    // account's session create and revoke complete promptly meanwhile. Before
    // T1' the bump preceded the INSERT and both stalled for the owner's whole
    // lock_timeout (~1.5 s).
    PasswordRoutesHarness h;
    h.wire();
    h.as_admin("rootA");
    h.seed("vic", kOld, Role::user);
    h.seed("other", kOld, Role::user);
    REQUIRE_FALSE(h.auth_mgr.create_local_session_for_test("other", Role::user, false).empty());
    const auto h0 = h.stored_hash("vic");

    yuzu::server::pg::PgConn locker{PQconnectdb(h.db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    auto run = [&](const char* sql) {
        yuzu::server::pg::PgResult r{PQexec(locker.get(), sql)};
        return r.ok();
    };
    REQUIRE(run("BEGIN"));
    REQUIRE(run("LOCK TABLE audit_store.audit_events IN ACCESS EXCLUSIVE MODE"));

    using Clock = std::chrono::steady_clock;
    std::unique_ptr<httplib::Response> resV;
    bool owner_waiting = false;
    std::int64_t create_ms = -1;
    std::int64_t revoke_ms = -1;
    std::string tok2;
    bool revoked_ok = false;
    {
        std::jthread tv([&] { resV = h.reset("vic", kNew); }); // joined on every exit path
        owner_waiting = yuzu::test::wait_for_pg_lock_waiter(h.db.dsn(), "%INSERT INTO audit_store%");
        auto t0 = Clock::now();
        tok2 = h.auth_mgr.create_local_session_for_test("other", Role::user, false);
        create_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        t0 = Clock::now();
        revoked_ok = h.auth_mgr.invalidate_user_sessions("other").db_persisted;
        revoke_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        // Keep the audit table locked until the reset gives up on it.
        tv.join();
    }
    CHECK(run("ROLLBACK"));

    INFO("create_ms=" << create_ms << " revoke_ms=" << revoke_ms);
    CHECK(owner_waiting);
    CHECK_FALSE(tok2.empty());
    CHECK(revoked_ok);
    CHECK(create_ms < 500);
    CHECK(revoke_ms < 500);
    REQUIRE(resV);
    INFO("reset=" << resV->status << " " << resV->body);
    CHECK(resV->status == 503);
    CHECK(resV->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.has_audit("user.password_reset", "error", "audit_unavailable"));
    CHECK(h.stored_hash("vic") == h0);
    CHECK(h.committed("user.password_reset", "vic") == 0);
    CHECK(h.password_works("vic", kOld));
}

TEST_CASE("password routes: a same-account recovery-code sign-in during an audit-table stall "
          "succeeds and keeps every session (chaos R22e inverted)",
          "[pg][rest][password][mfa][audit]") {
    // #5342 Gate 8 iteration 5. A second connection holds ACCESS EXCLUSIVE on
    // audit_store.audit_events, so the reset's audit INSERT waits while the
    // owner holds vic's auth.users row. vic's /login/mfa second leg (recovery
    // code) queues on that row; the owner's lock_timeout (1.5 s) is strictly
    // below the sign-in recheck's (2 s), so the owner aborts first and the
    // sign-in completes. Before the fix the owner waited 4 s, the recheck
    // timed out first and failed closed — 401, every vic session swept.
    PasswordRoutesHarness h;
    h.wire();
    h.auth_routes->register_routes(h.sink);
    h.as_admin("rootA");
    h.seed("vic", kOld, Role::user);
    auto init = h.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto codes =
        h.db->mfa_verify_enrollment("vic", totp_now(init->secret_base32, -1), std::nullopt);
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    const auto h0 = h.stored_hash("vic");
    const auto prior = h.auth_mgr.create_local_session_for_test("vic", Role::user, true);
    REQUIRE_FALSE(prior.empty());
    auto step1 = h.sink.Post("/login", "username=vic&password=" + std::string(kOld),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1);
    INFO("step1=" << step1->status << " " << step1->body);
    REQUIRE(step1->status == 202);
    const std::string pending = nlohmann::json::parse(step1->body).at("mfa_pending_token");

    yuzu::server::pg::PgConn locker{PQconnectdb(h.db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    auto run = [&](const char* sql) {
        yuzu::server::pg::PgResult r{PQexec(locker.get(), sql)};
        return r.ok();
    };
    REQUIRE(run("BEGIN"));
    REQUIRE(run("LOCK TABLE audit_store.audit_events IN ACCESS EXCLUSIVE MODE"));

    std::unique_ptr<httplib::Response> resV;
    std::unique_ptr<httplib::Response> step2;
    bool owner_waiting = false;
    {
        std::jthread tv([&] { resV = h.reset("vic", kNew); }); // joined on every exit path
        owner_waiting = yuzu::test::wait_for_pg_lock_waiter(h.db.dsn(), "%INSERT INTO audit_store%");
        step2 = h.sink.Post("/login/mfa",
                            "mfa_pending_token=" + pending + "&code=" + codes->front(),
                            "application/x-www-form-urlencoded");
        tv.join();
    }
    CHECK(run("ROLLBACK"));

    CHECK(owner_waiting);
    REQUIRE(resV);
    INFO("reset=" << resV->status << " " << resV->body);
    CHECK(resV->status == 503);
    CHECK(resV->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.has_audit("user.password_reset", "error", "audit_unavailable"));
    CHECK(h.stored_hash("vic") == h0);
    REQUIRE(step2);
    INFO("step2=" << step2->status << " " << step2->body);
    CHECK(step2->status == 200);
    CHECK_FALSE(step2->get_header_value("Set-Cookie").empty());
    CHECK(h.auth_mgr.validate_session(prior).has_value());
    CHECK(h.sessions_of("vic") == 2);
    CHECK(h.scalar("SELECT count(*) FROM auth.mfa_recovery_codes WHERE username = 'vic' AND "
                   "consumed_at IS NOT NULL") == "1");
}

TEST_CASE("password routes: the literal /me route wins over the {name} regex",
          "[pg][rest][password]") {
    // httplib dispatches the FIRST matching registration; ([^/]+) also matches
    // "me". A self change must never be routed to the admin reset handler
    // (which would demand a durable Administrator and skip the
    // current-password proof).
    PasswordRoutesHarness h;
    h.wire();
    h.seed("olga", kOld, Role::user);
    h.session_user = "olga"; // not an administrator: the admin route would 403
    auto res = h.post("/api/v1/users/me/password", {{"new_password", kNew}}); // no current
    REQUIRE(res);
    CHECK(res->status == 400); // the SELF handler's body validation, not the admin gate
    CHECK(h.password_works("olga", kOld));
}
