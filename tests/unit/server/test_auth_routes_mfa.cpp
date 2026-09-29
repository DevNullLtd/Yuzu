/**
 * test_auth_routes_mfa.cpp — Route-level coverage for the MFA login flow
 * added by PR1 of the TOTP MFA ladder (SOC 2 CC6.6).
 *
 * Closes the quality-engineer Gate 3 SHOULD-FIX that PR1 deferred. The
 * internal governance pipeline missed Hermes Agent's CRITICAL finding
 * (`/login/mfa` was unreachable behind the pre-routing auth gate at
 * `server.cpp:2393`) because the review never exercised the wire path
 * end-to-end. Hermes hit it within 30 seconds of live `curl` probing.
 * This file is the regression net for that class of bug — every
 * MFA-related handler is dispatched through a real `TestRouteSink` so a
 * future contributor narrowing the exemption list or breaking the
 * pending-token contract trips a test instead of shipping.
 *
 * Pattern: same as `test_settings_routes_users.cpp` — register AuthRoutes
 * against an in-process TestRouteSink, dispatch synthesized requests,
 * assert on response status / cookie / body and on the audit chain via
 * the real AuditStore.
 *
 * Why in-process and not a real `httplib::Server`: the prior fixture
 * pattern spun up a listening server behind a `std::thread` acceptor,
 * which crashes under TSan with no TSan report (#438).
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"
#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "pg/pg_raii.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — the harness below clones this
// pre-migrated template instead of opening a SQLite path. Self-contained
// (mirrors yuzu::test::AuthDbPg, already embedded in the harness): SKIPs the
// enclosing TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset (via auth_db's own
// ctor, constructed first), FAILs when set but broken.
yuzu::test::PgTestTemplate auth_routes_mfa_audit_tpl{"mfaaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("mfaaudit template: store failed to migrate");
}};

/// RAII temp-dir guard. Must be the first member so the directory is
/// cleaned up even when a later REQUIRE in the harness constructor
/// throws.
struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) { fs::create_directories(path); }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// Harness that wires AuthRoutes against an in-process TestRouteSink,
/// seeds an admin and a regular user, and exposes Get/Post helpers.
///
/// `auth_mgr` has AuthDB attached so the MFA accessors (`mfa_status`,
/// `mfa_init_enrollment`, `mfa_verify_login_code`, etc.) work. AuthDB
/// is constructed with `cleanup_interval_secs=0` to skip the background
/// reaper jthread (per PR #1199's macOS-arm64 SIGSEGV fix).
struct AuthRoutesHarness {
    TmpDirGuard tmp;
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
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    yuzu::server::test::TestRouteSink sink;

    AuthRoutesHarness() : tmp(yuzu::test::unique_temp_path("auth-routes-mfa-")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        // Tight pending-token TTL so we can assert expiry without
        // sleeping minutes in tests.
        cfg.mfa_login_pending_secs = 2;
        cfg.https_enabled = false; // no Secure cookie suffix

        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("alice", "alicepassword1", auth::Role::user));
        // Mirror users into AuthDB so verify_password's "still active in
        // AuthDB" check succeeds (auth.cpp:443).
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db
                    ->upsert_user("admin", auth::AuthManager::pbkdf2_sha256("adminpassword1", salt,
                                                                             100'000),
                                  salt_hex, auth::Role::admin)
                    .has_value());
        salt = auth::AuthManager::random_bytes(16);
        salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db
                    ->upsert_user("alice", auth::AuthManager::pbkdf2_sha256("alicepassword1", salt,
                                                                             100'000),
                                  salt_hex, auth::Role::user)
                    .has_value());

        // Connect AuthDB to AuthManager so mfa_status / verify_password
        // / create_local_session can find each other.
        auth_mgr.set_auth_db(auth_db.get());

        // Force AuthManager's in-memory users_ to use the DB-side salt
        // by re-loading "admin"/"alice" through upsert_user (which
        // stores its own salt). We rebuild AuthManager's view with
        // PBKDF2-matching salts so `verify_password` succeeds end-to-end.
        // (This is a quirk of the dual-store layout: AuthManager keeps
        // the in-memory users_ map for verify; AuthDB is the persisted
        // mirror used by mfa_* and the post-soft-delete is_active gate.)
        // The simplest fix is to use the same password through
        // AuthManager and AuthDB.
        // No-op here — auth_mgr.upsert_user already hashed with its own
        // salt and wrote the in-memory entry. AuthDB's row is for the
        // is_active check only.

        audit_db.emplace(auth_routes_mfa_audit_tpl);
        INFO("[AuthRoutesHarness] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            /*rbac_store=*/nullptr, /*api_token_store=*/nullptr, audit_store.get(),
            /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, analytics_store.get(), oidc_mu,
            oidc_provider);
        auth_routes->register_routes(sink);
    }

    /// Compute a TOTP code for the given base32 secret at a counter
    /// `offset` steps from now. Default `offset=1` puts the code one
    /// step in the future, safely past the `mfa_last_counter` floor
    /// that mfa_verify_enrollment wrote during enroll_mfa() — without
    /// this, enrollment-verify and the immediately-following /login/mfa
    /// land in the same 30 s window and the login code is rejected as
    /// replay. verify_window accepts ±1 step skew so counter+1 still
    /// lands within the acceptance window for both N=E and N=E+1.
    std::string totp_at(const std::string& secret_b32, int offset = 1) {
        auto bytes = mfa::base32_decode(secret_b32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto counter = mfa::current_counter(std::chrono::system_clock::now()) + offset;
        return mfa::generate(raw, counter);
    }

    /// Enroll `username` (defaults to admin) in MFA. Returns the base32
    /// secret so the test can compute fresh TOTP codes against it.
    std::string enroll_mfa(const std::string& username = "admin") {
        auto init = auth_db->mfa_init_enrollment(username, "Yuzu");
        REQUIRE(init.has_value());
        auto code = totp_at(init->secret_base32, 0);
        REQUIRE(auth_db->mfa_verify_enrollment(username, code).has_value());
        return init->secret_base32;
    }

    /// Count audit rows that match action + principal.
    int count_audits(const std::string& action, const std::string& principal = {}) {
        AuditQuery q;
        q.action = action;
        if (!principal.empty())
            q.principal = principal;
        auto res = audit_store->query(q);
        REQUIRE(res.has_value());
        return static_cast<int>(res->size());
    }
};

/// Build a form-encoded body from `key=value` pairs.
std::string form(std::initializer_list<std::pair<std::string, std::string>> kv) {
    std::string out;
    bool first = true;
    for (const auto& [k, v] : kv) {
        if (!first)
            out += "&";
        first = false;
        out += k + "=" + v;
    }
    return out;
}

/// Corrupt `username`'s stored `mfa_totp_secret` envelope in place with
/// garbage bytes that cannot possibly decrypt (wrong length + no valid GCM
/// tag) — simulates tamper / a wrong-KEK-version blob without needing a
/// second KEK. Mirrors test_auth_db_pg.cpp's `corrupt_secret`. Used to
/// prove the Section 3 architect-BLOCK fix (SecretUnavailable -> 503/deny,
/// never a fall-through to a password-only or MFA-satisfied session) through
/// the auth_routes HTTP layer, not just the store layer.
void corrupt_secret(const std::string& dsn, const std::string& username) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const char* values[] = {username.c_str()};
    yuzu::server::pg::PgResult res{PQexecParams(
        conn.get(),
        "UPDATE auth.users SET mfa_totp_secret = decode('deadbeefcafebabe0011223344','hex') "
        "WHERE username = $1",
        1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.ok());
}

} // namespace

TEST_CASE("POST /login no-MFA success returns 200 + session cookie + auth.login audit",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body == R"({"status":"ok"})");
    auto cookie = res->get_header_value("Set-Cookie");
    CHECK(cookie.find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
    // 202 path was NOT taken — no mfa.login.required row.
    CHECK(h.count_audits("mfa.login.required", "admin") == 0);
}

TEST_CASE("POST /login bad password returns 401 + auth.login_failed audit",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "wrong"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->body.find(R"("code":401)") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.login_failed") >= 1);
}

TEST_CASE("POST /login MFA-enrolled returns 202 + mfa_pending_token, no cookie",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find(R"("status":"mfa_required")") != std::string::npos);
    CHECK(res->body.find(R"("mfa_pending_token")") != std::string::npos);
    CHECK(res->body.find(R"("expires_in":2)") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("mfa.login.required", "admin") >= 1);
    // Crucially, auth.login is NOT emitted yet — only the .required
    // verb. The terminal auth.login lands on the /login/mfa success
    // path.
    CHECK(h.count_audits("auth.login", "admin") == 0);
}

// ── Section 6: architect-BLOCK fail-closed proof, through auth_routes ──────
//
// ★ SECURITY: an ENROLLED user whose MFA secret is unreadable/undecryptable
// (SecretUnavailable) must NEVER fall through to a password-only session —
// the store-layer contract (test_auth_db_pg.cpp) proves `mfa_status`/
// `mfa_verify_login_code` surface `SecretUnavailable` distinctly; THIS test
// proves the auth_routes consumer honours it end-to-end: /login returns
// 503 (not 200, not 202-then-bypass) and mints NO session cookie.
TEST_CASE("POST /login for an ENROLLED user with an unreadable MFA secret fails CLOSED "
         "(503, no session) — architect-BLOCK proof",
         "[pg][mfa][routes][auth_routes][fail-closed]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    corrupt_secret(h.auth_db.dsn(), "admin");

    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    // Fail-closed 503 — NEVER 200 (password-only session) and NEVER a 202
    // MFA challenge that could be sidestepped; no session cookie either way.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(res->body.find(R"("code":503)") != std::string::npos);
    // #2396: the fail-closed 503 now carries an honest, machine-readable
    // backoff hint — a Retry-After header AND a retry_after_ms body field — so
    // a client/LB backs off instead of hammering a degraded store. (The
    // reason-labelled yuzu_auth_read_degrade_total counter is exercised at the
    // store layer + server metric wiring; this harness wires no
    // MetricsRegistry, so the handler's null-guarded increment is inert here.)
    CHECK(res->get_header_value("Retry-After") == "2");
    CHECK(res->body.find(R"("retry_after_ms":2000)") != std::string::npos);
    // No session was minted on ANY path — the terminal auth.login row never
    // fires for this login attempt.
    CHECK(h.count_audits("auth.login", "admin") == 0);
    // A distinct, honest audit row records the store failure (never
    // conflated with "not enrolled" or "wrong password").
    CHECK(h.count_audits("mfa.status.unavailable", "admin") >= 1);
}

// ── is_store_unavailable / WriteFailed proof (governance hardening round) ──
//
// ★ SECURITY: fix #1's `is_store_unavailable` (auth_db.hpp) folds
// `AuthDBError::WriteFailed` into the same store-outage predicate as
// `SecretUnavailable`/`QueryFailed` — `mfa_verify_login_code`'s own
// replay-protection write (persisting `mfa_last_counter`) surfaces a PG
// write failure as `WriteFailed`, not `SecretUnavailable`/`QueryFailed`.
// Before the fix that outage fell through to a uniform 401 "wrong code" —
// burning one of the account's limited MFA attempts against a transient
// outage — instead of the intended fail-closed 503.
//
// Fault injection: a BEFORE UPDATE trigger on auth.users that always raises,
// so the UPDATE mfa_verify_login_code issues fails deterministically while
// the SELECT `load_mfa_row` issues beforehand is completely unaffected (pool
// exhaustion was rejected here — the read and write leases are sequential,
// not concurrent, on one request thread, so starving the pool can't target
// the write without also starving the read and getting a spurious 401 from
// an entirely different, untested code path). The TOTP code presented is
// the GENUINE current code (would otherwise verify successfully), so a 401
// here can only be explained by the outage being mishandled as "wrong
// code" — this test locks in that it is NOT.
TEST_CASE("POST /login/mfa returns 503 (not 401) when the mfa_last_counter write fails",
         "[pg][mfa][routes][auth_routes][fail-closed]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto pending_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending_end = body.find('"', pending_start);
    auto pending = body.substr(pending_start, pending_end - pending_start);
    REQUIRE(pending.size() == 64);

    auto code = h.totp_at(secret_b32);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult fn{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION test_block_users_update() RETURNS trigger AS $$ "
            "BEGIN RAISE EXCEPTION 'test-induced write failure'; END; $$ LANGUAGE plpgsql")};
        REQUIRE(fn.ok());
        yuzu::server::pg::PgResult trg{PQexec(
            conn.get(), "CREATE TRIGGER test_block_users_update_trg BEFORE UPDATE ON auth.users "
                       "FOR EACH ROW EXECUTE FUNCTION test_block_users_update()")};
        REQUIRE(trg.ok());
    }

    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");

    REQUIRE(step2);
    CHECK(step2->status == 503); // NOT 401 "wrong code" — locks in fix #1
    CHECK(step2->get_header_value("Set-Cookie").empty());
    CHECK(step2->body.find(R"("code":503)") != std::string::npos);
    // No session was minted and no attempt was burned as "wrong code" —
    // the terminal auth.login/mfa.login.verified rows never fire.
    CHECK(h.count_audits("auth.login", "admin") == 0);
    CHECK(h.count_audits("mfa.login.verified", "admin") == 0);
}

TEST_CASE("POST /login/mfa with valid TOTP mints session and emits dual audit (mfa.login.verified "
          "+ auth.login)",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");
    // First leg: /login → 202 + pending token
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto pending_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending_end = body.find('"', pending_start);
    auto pending = body.substr(pending_start, pending_end - pending_start);
    REQUIRE(pending.size() == 64);

    auto code = h.totp_at(secret_b32);
    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 200);
    CHECK(step2->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    // Dual audit emission per the Gate 4 architect S2 fix.
    CHECK(h.count_audits("mfa.login.verified", "admin") >= 1);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
}

// #4107 Gate 8 (security-guardian + authdb): the AuthManager-level tests for
// post_mint_role_recheck (test_auth.cpp) only exercise authenticate() and a
// direct create_local_session() call with a hand-supplied stale role - not
// the actual fixed code, the 3 token.empty() deny blocks in auth_routes.cpp.
// This drives the real gap through the real wire path with NO test hook:
// the pending entry's role is captured by verify_password() at step 1 and
// held unread until create_local_session() at step 2, a genuine two-request
// window (unlike plain /login's single-request authenticate()/verify_
// password() call, which has no such gap to reproduce without a hook) - a
// real demote landing in that window is exactly the #4107 scenario.
TEST_CASE("POST /login/mfa denies the mint (401, no cookie, honest audit) when the account "
          "is demoted between the pending /login and the TOTP verify - the real wire-path "
          "reproduction of the #4107 route-layer gap (Gate 8 coverage, no test hook needed)",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto pending_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending_end = body.find('"', pending_start);
    auto pending = body.substr(pending_start, pending_end - pending_start);
    REQUIRE(pending.size() == 64);
    auto code = h.totp_at(secret_b32);

    // The pending entry captured role=admin at step 1. Demote strictly
    // between the two requests - update_role() writes AuthDB durably
    // before this call returns (auth.cpp), so create_local_session()'s
    // post_mint_role_recheck is guaranteed to observe "user", not "admin".
    REQUIRE(h.auth_mgr.update_role("admin", auth::Role::user));

    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 401);
    CHECK(step2->get_header_value("Set-Cookie").empty());
    // The TOTP code itself was genuinely correct and consumed - proves the
    // fix (auth_routes.cpp's token.empty() check) denies the MINT, not the
    // code verification; the false "auth.login ok" this used to produce is
    // gone, replaced by an honest failure row that doesn't overclaim which
    // of create_local_session's two internal causes fired.
    CHECK(h.count_audits("mfa.login.verified", "admin") >= 1);
    CHECK(h.count_audits("auth.login", "admin") >= 1); // the new failure row, never a false "ok"
    AuditQuery q;
    q.action = "auth.login";
    q.principal = "admin";
    auto res = h.audit_store->query(q);
    REQUIRE(res.has_value());
    bool found_failure_row = false;
    for (const auto& row : *res) {
        // cpp-expert Gate 8 NICE: the count_audits check above only proves a
        // row exists, not that it isn't a false "ok" sitting alongside a
        // failure row - assert directly on every row's result here instead.
        CHECK(row.result != "ok");
        if (row.result == "failure") {
            found_failure_row = true;
            CHECK(row.detail.find("session_mint_failed") != std::string::npos);
            CHECK(row.detail.find("post_mint_recheck=true") == std::string::npos);
        }
    }
    CHECK(found_failure_row);
}

TEST_CASE("POST /login/mfa with valid recovery code emits mfa.recovery_code.used + auth.login",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    // Pull a freshly minted recovery code by regenerating (init's reveal
    // is consumed inside enroll_mfa via mfa_verify_enrollment which
    // returned them, but we discarded the return — regenerate gives a
    // clean batch we own).
    auto codes = h.auth_db->mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    auto recovery = codes->front();

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto step2 =
        h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", recovery}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 200);
    CHECK(step2->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("mfa.recovery_code.used", "admin") >= 1);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
    // The recovery-code branch must NOT also emit mfa.login.verified —
    // that verb belongs to the TOTP branch (otherwise the count of
    // "TOTP logins" is double-attributed).
    CHECK(h.count_audits("mfa.login.verified", "admin") == 0);
}

// security-guardian Gate 8 SHOULD (1b4d041ff review): the audit-row-
// suppression regression this fix round closed (Finding 3 - a burned
// recovery code's TRUE audit row was silently dropped alongside the old
// false "auth.login ok") lived specifically in this recovery-code branch,
// but the route-level test added for that fix round only exercised the
// TOTP arm. This covers the recovery-code arm directly: the code is a
// genuine one-time credential, irreversibly consumed in AuthDB regardless
// of the later mint outcome, so its audit row must survive a denied mint.
TEST_CASE("POST /login/mfa recovery-code path still audits mfa.recovery_code.used "
          "(a burned one-time credential) even when the mint is denied by a "
          "demote landing before the verify completes",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto codes = h.auth_db->mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    auto recovery = codes->front();

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    REQUIRE(h.auth_mgr.update_role("admin", auth::Role::user));

    auto step2 =
        h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", recovery}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 401);
    CHECK(step2->get_header_value("Set-Cookie").empty());
    // The recovery code was genuinely consumed - its TRUE audit row must
    // survive the denied mint, unlike before this fix round. Exact count
    // (security-guardian Gate 8 NICE) - nothing else in this fixture emits
    // this action, so == 1 also catches a future duplicate-emission bug.
    CHECK(h.count_audits("mfa.recovery_code.used", "admin") == 1);
    AuditQuery rq;
    rq.action = "auth.login";
    rq.principal = "admin";
    auto rres = h.audit_store->query(rq);
    REQUIRE(rres.has_value());
    bool found_failure_row = false;
    for (const auto& row : *rres) {
        CHECK(row.result != "ok");
        if (row.result == "failure")
            found_failure_row = true;
    }
    CHECK(found_failure_row);
}

TEST_CASE("POST /login/mfa with invalid pending token returns 401 + audit",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post(
        "/login/mfa",
        form({{"mfa_pending_token", std::string(64, 'a')}, {"code", "123456"}}),
        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    // Field-level, not exact-body: the A4 envelope (#1552 sweep) now stamps
    // a fresh per-request `correlation_id`, so the anti-enumeration
    // `message`/`code` pair stays uniform while the body as a whole
    // legitimately varies request to request.
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"] == 401);
    CHECK(body["error"]["message"] == "Invalid verification code");
    CHECK(body["error"].contains("correlation_id"));
    CHECK(h.count_audits("mfa.login.failed") >= 1);
}

TEST_CASE("POST /login/mfa attempts cap erases pending after 5 failures",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // First 5 attempts return 401 but the token survives (attempts
    // counter increments).
    for (int i = 0; i < 5; ++i) {
        auto r = h.sink.Post("/login/mfa",
                             form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 401);
    }
    // 6th attempt: same token, would have been valid TOTP — but the
    // entry is gone after the 5th failure, so it returns the "pending
    // invalid" branch (same 401 body, indistinguishable on the wire).
    auto r6 = h.sink.Post("/login/mfa",
                          form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                          "application/x-www-form-urlencoded");
    REQUIRE(r6);
    CHECK(r6->status == 401);
    // Audit detail distinguishes attempts-exhausted from per-attempt
    // failures.
    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw_exhausted = false;
    for (const auto& r : *rows) {
        if (r.detail.find("attempts exhausted") != std::string::npos) {
            saw_exhausted = true;
            break;
        }
    }
    CHECK(saw_exhausted);
}

TEST_CASE("POST /login/mfa strict shape gate routes non-6-digit to recovery path",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto codes = h.auth_db->mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // "12345A" is 6 chars but contains a non-digit → routed to recovery.
    // No matching recovery code → 401, detail says "recovery code
    // rejected" (NOT "totp code rejected").
    auto r = h.sink.Post("/login/mfa",
                         form({{"mfa_pending_token", pending}, {"code", "12345A"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 401);

    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw_recovery = false;
    for (const auto& r : *rows) {
        if (r.detail.find("recovery") != std::string::npos) {
            saw_recovery = true;
            break;
        }
    }
    CHECK(saw_recovery);
}

TEST_CASE("POST /login/mfa pending token expires after TTL", "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // Sleep past the TTL (configured to 2 s in the harness). reap_mfa_
    // pending_locked fires on the next access via /login/mfa.
    //
    // 5000 ms = 2.5x the TTL — the conventional multiplier for wall-
    // clock-gated tests on a nightly sanitizer runner where ASan + UBSan
    // add 2-3x CPU overhead and scheduler preemption under load is
    // unbounded. Earlier iterations of this test used 2200 ms (10 %
    // margin) and 2800 ms (40 % margin); cpp-safety + qe both flagged
    // anything below 2x as fragile. Test now takes ~3 s extra but is
    // robust on the slowest runner in the matrix.
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    auto r = h.sink.Post("/login/mfa",
                         form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 401);
    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw_expired = false;
    for (const auto& r : *rows) {
        if (r.detail.find("expired") != std::string::npos) {
            saw_expired = true;
            break;
        }
    }
    CHECK(saw_expired);
}

// ── /login/mfa/stepup tests (PR2) ─────────────────────────────────────────

namespace {

/// Helper: full PR1 login dance (password → 202 → TOTP → 200) and return
/// the session cookie value so step-up tests can authenticate. Drives the
/// real routes end-to-end so any future change that breaks the cookie
/// shape or the dual-audit trips a test in `[mfa][stepup]` as well as
/// `[mfa][routes][auth_routes]`.
std::string login_with_mfa(AuthRoutesHarness& h, const std::string& username,
                           const std::string& password, const std::string& secret_b32) {
    auto step1 =
        h.sink.Post("/login", form({{"username", username}, {"password", password}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1);
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto code = h.totp_at(secret_b32, 1);
    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    REQUIRE(step2->status == 200);
    auto cookie_hdr = step2->get_header_value("Set-Cookie");
    auto eq = cookie_hdr.find("yuzu_session=");
    REQUIRE(eq != std::string::npos);
    auto sc = cookie_hdr.find(';', eq);
    return cookie_hdr.substr(eq, sc == std::string::npos ? cookie_hdr.size() - eq : sc - eq);
}

} // namespace

TEST_CASE(
    "POST /login/mfa/stepup with valid fresh TOTP succeeds and emits mfa.step_up.passed",
    "[pg][mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    // verify_window is ±1 step (PR1) and login_with_mfa consumed counter+1,
    // so the next code we could verify in this 30 s window is counter+2 —
    // which is OUT of window. Without sleeping 30 s, the only way to test
    // a TOTP-path step-up success deterministically is to disable + re-
    // enroll, which resets `mfa_last_counter` to 0. The session cookie
    // remains valid because the session row is keyed by token, not by the
    // user's MFA state.
    REQUIRE(h.auth_db->mfa_disable("admin").has_value());
    auto fresh_secret = h.enroll_mfa("admin");
    auto stepup_code = h.totp_at(fresh_secret, 1);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", stepup_code}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find(R"("status":"ok")") != std::string::npos);
    CHECK(h.count_audits("mfa.step_up.passed", "admin") >= 1);
    CHECK(h.count_audits("mfa.step_up.failed") == 0);
}

TEST_CASE(
    "POST /login/mfa/stepup with a recovery code succeeds and emits mfa.step_up.passed",
    "[pg][mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto codes = h.auth_db->mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    auto recovery = codes->front();

    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", recovery}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.count_audits("mfa.step_up.passed", "admin") >= 1);
    // Recovery codes are single-use — second attempt must fail.
    auto res2 = h.sink.dispatch("POST", "/login/mfa/stepup",
                                form({{"code", recovery}}),
                                "application/x-www-form-urlencoded",
                                {{"Cookie", cookie}});
    REQUIRE(res2);
    CHECK(res2->status == 401);
    CHECK(h.count_audits("mfa.step_up.failed", "admin") >= 1);
}

TEST_CASE("POST /login/mfa/stepup without a session returns 401 (require_auth gate)",
          "[pg][mfa][stepup][routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto res = h.sink.Post("/login/mfa/stepup", form({{"code", "123456"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    // No session → no principal → no mfa.step_up audit at all.
    CHECK(h.count_audits("mfa.step_up.passed") == 0);
    CHECK(h.count_audits("mfa.step_up.failed") == 0);
}

TEST_CASE("POST /login/mfa/stepup with empty code body returns 400 + audit",
          "[pg][mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup", "",
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.count_audits("mfa.step_up.failed", "admin") >= 1);
}

TEST_CASE("POST /login/mfa/stepup with wrong TOTP returns 401 + mfa.step_up.failed",
          "[pg][mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", "000000"}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->body.find("MFA step-up failed") != std::string::npos);

    AuditQuery q;
    q.action = "mfa.step_up.failed";
    q.principal = "admin";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    bool saw_totp_reject = false;
    for (const auto& r : *rows) {
        if (r.detail.find("totp code rejected") != std::string::npos) {
            saw_totp_reject = true;
            break;
        }
    }
    CHECK(saw_totp_reject);
}

// ── /login/mfa/enroll + enforcement bootstrap tests (PR3) ─────────────────

TEST_CASE("POST /login load-sheds with 503 when the pending-token map is at capacity (H-2)",
          "[pg][mfa][routes][auth_routes]") {
    // Hermes H-2 / governance qe-B: the pending-map cap is exercised via the
    // test-only seam (the production 50k is impractical to fill). The login
    // challenge and enrollment issuance sites share byte-identical cap logic
    // (consistency-auditor verified), so the challenge path covers both.
    AuthRoutesHarness h;
    h.auth_routes->set_mfa_pending_cap_for_test(2);
    h.enroll_mfa("admin");
    for (int i = 0; i < 2; ++i) {
        auto r = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 202); // fills the map to the cap
    }
    auto shed = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                            "application/x-www-form-urlencoded");
    REQUIRE(shed);
    CHECK(shed->status == 503);
    CHECK(shed->body.find("too many pending authentications") != std::string::npos);
    CHECK(shed->get_header_value("Set-Cookie").empty());
}

TEST_CASE("POST /login under mfa_enforcement=required: un-enrolled user gets 202 enrollment "
          "challenge, no cookie",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required"; // cfg_ is held by reference
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find(R"("status":"mfa_enrollment_required")") != std::string::npos);
    CHECK(res->body.find(R"("otpauth_uri")") != std::string::npos);
    CHECK(res->body.find(R"("secret_base32")") != std::string::npos);
    // The server-rendered QR SVG rides along in the 202 body (#1232 wiring).
    CHECK(res->body.find(R"("qr_svg":"<svg)") != std::string::npos);
    // No session is minted until the operator confirms the first code.
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("mfa.enroll.required", "alice") >= 1);
    CHECK(h.count_audits("auth.login", "alice") == 0);
}

TEST_CASE("POST /login/mfa/enroll completes enforced enrollment: 200 + cookie + recovery codes",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string secret = body.at("secret_base32");

    auto code = h.totp_at(secret, 0);
    auto step2 = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 200);
    CHECK(step2->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    auto rbody = nlohmann::json::parse(step2->body);
    CHECK(rbody.at("status") == "ok");
    REQUIRE(rbody.contains("recovery_codes"));
    CHECK(rbody.at("recovery_codes").size() == 10);
    CHECK(h.count_audits("mfa.enroll.verified", "alice") >= 1);
    CHECK(h.count_audits("mfa.recovery_codes.generated", "alice") >= 1);
    CHECK(h.count_audits("auth.login", "alice") >= 1);
    // The user is now genuinely enrolled.
    auto status = h.auth_db->mfa_status("alice");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

// security-guardian Gate 8 SHOULD (1b4d041ff review): same coverage gap as
// the recovery-code test above, for the enrollment-verify branch, where
// Finding 3's regression also lived (mfa.enroll.verified /
// mfa.recovery_codes.generated rows describe a TOTP-secret confirmation and
// a recovery-code generation already durably committed in AuthDB - both
// must survive a denied mint, and the codes' one-time VALUE must still be
// withheld).
TEST_CASE("POST /login/mfa/enroll still audits mfa.enroll.verified + "
          "mfa.recovery_codes.generated (already-committed enrollment) even when the mint "
          "is denied by a demote landing before the verify completes, and withholds the "
          "recovery codes themselves",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    REQUIRE(h.auth_mgr.update_role("alice", auth::Role::admin));
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string secret = body.at("secret_base32");

    REQUIRE(h.auth_mgr.update_role("alice", auth::Role::user));

    auto code = h.totp_at(secret, 0);
    auto step2 = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 401);
    CHECK(step2->get_header_value("Set-Cookie").empty());
    // The one-time recovery-codes VALUE reveal stays withheld on deny -
    // only the fact that enrollment/codes were generated is unconditional.
    // Field-level, not exact-body (#1552 sweep): the handler's kFailureBody
    // is now `detail::a4_error`-backed, so the body carries a fresh
    // per-request `correlation_id` the old literal didn't - code/message are
    // still asserted exactly, which is the substantive claim this test
    // makes (see the sibling fix in this file for the same reasoning:
    // "POST /login/mfa with invalid pending token returns 401 + audit").
    auto step2_json = nlohmann::json::parse(step2->body);
    CHECK(step2_json["error"]["code"] == 401);
    CHECK(step2_json["error"]["message"] == "Invalid verification code");
    CHECK(step2_json["error"].contains("correlation_id"));
    // Exact counts (security-guardian Gate 8 NICE) - nothing else in this
    // fixture emits these actions, so == 1 also catches a future
    // duplicate-emission bug.
    CHECK(h.count_audits("mfa.enroll.verified", "alice") == 1);
    CHECK(h.count_audits("mfa.recovery_codes.generated", "alice") == 1);
    AuditQuery eq;
    eq.action = "auth.login";
    eq.principal = "alice";
    auto eres = h.audit_store->query(eq);
    REQUIRE(eres.has_value());
    bool found_failure_row = false;
    for (const auto& row : *eres) {
        CHECK(row.result != "ok");
        if (row.result == "failure")
            found_failure_row = true;
    }
    CHECK(found_failure_row);
    // The account really is enrolled now, regardless of the denied login.
    auto status = h.auth_db->mfa_status("alice");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

TEST_CASE("POST /login/mfa/enroll for an already-enrolled account audits mfa.enroll.race, "
          "not a rejected code (#3777)",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // A concurrent verify can enrol the account between this pending token's
    // mint and its verify — mfa_verify_enrollment then returns
    // MfaAlreadyEnrolled. That benign race must be audited distinctly
    // (CC7.2), never as a rejected code or a store outage, and must not mint a
    // session. Simulate the concurrent winner by enrolling alice out-of-band.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string secret = body.at("secret_base32");

    h.enroll_mfa("alice"); // the concurrent winner enrols the account

    auto step2 = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", h.totp_at(secret, 0)}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 409); // distinct benign outcome — not 401 "wrong code", not 503
    CHECK(step2->body.find("already enrolled") != std::string::npos);
    CHECK(step2->get_header_value("Set-Cookie").empty()); // no session minted
    // Audited as a race, NOT mislabelled as a rejected-code attempt or an outage.
    CHECK(h.count_audits("mfa.enroll.race", "alice") >= 1);
    CHECK(h.count_audits("mfa.enroll.failed", "alice") == 0);
}

TEST_CASE("POST /login under mfa_enforcement=admin-only: admin enrolls, regular user logs in "
          "normally",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "admin-only";

    // Un-enrolled admin → enrollment challenge, no cookie.
    auto a = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(a);
    CHECK(a->status == 202);
    CHECK(a->body.find(R"("status":"mfa_enrollment_required")") != std::string::npos);
    CHECK(a->get_header_value("Set-Cookie").empty());

    // Un-enrolled regular user → normal session, enforcement does not apply.
    auto u = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(u);
    CHECK(u->status == 200);
    CHECK(u->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("mfa.enroll.required", "alice") == 0);
}

TEST_CASE("POST /login under enforcement: already-enrolled user gets the login challenge, not "
          "enrollment",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    h.enroll_mfa("alice");
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find(R"("status":"mfa_required")") != std::string::npos);
    CHECK(res->body.find("mfa_enrollment_required") == std::string::npos);
}

TEST_CASE("enrollment token replayed at /login/mfa is rejected",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto e1 = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                          "application/x-www-form-urlencoded");
    REQUIRE(e1->status == 202);
    auto ebody = nlohmann::json::parse(e1->body);
    std::string enroll_token = ebody.at("mfa_pending_token");
    std::string secret = ebody.at("secret_base32");
    auto code = h.totp_at(secret, 0);

    auto bad = h.sink.Post("/login/mfa",
                           form({{"mfa_pending_token", enroll_token}, {"code", code}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 401);
    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw = false;
    for (const auto& r : *rows) {
        if (r.detail.find("enrollment token used at login-challenge endpoint") !=
            std::string::npos) {
            saw = true;
            break;
        }
    }
    CHECK(saw);
}

TEST_CASE("login-challenge token replayed at /login/mfa/enroll is rejected",
          "[pg][mfa][enroll][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string login_token = body.at("mfa_pending_token");
    auto code = h.totp_at(secret, 1);

    auto bad = h.sink.Post("/login/mfa/enroll",
                           form({{"mfa_pending_token", login_token}, {"code", code}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 401);
    AuditQuery q;
    q.action = "mfa.enroll.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw = false;
    for (const auto& r : *rows) {
        if (r.detail.find("login-challenge token used at enrollment endpoint") !=
            std::string::npos) {
            saw = true;
            break;
        }
    }
    CHECK(saw);
}

TEST_CASE("POST /login enforced + auth_db unavailable fails CLOSED with 503",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // GOVERNANCE qe-B1 / SOC 2 CC6.6 fail-closed. Under enforcement, if the
    // store that holds TOTP secrets is unavailable, /login must refuse to
    // mint a session (503) rather than silently mint an unprotected one.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    h.auth_mgr.set_auth_db(nullptr); // verify_password still works (in-memory users_)
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("mfa.enroll.required", "alice") >= 1);
}

TEST_CASE("POST /login/mfa/enroll + auth_db unavailable fails closed with uniform 401",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // qe-B1 + Hermes L-1: the enroll db-null branch fails closed with the
    // uniform 401 body (matching /login/mfa), not a distinct 503 that would
    // leak pending-token validity during a store outage. No session minted.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");

    h.auth_mgr.set_auth_db(nullptr); // store drops out before the confirm
    auto step2 = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", "123456"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 401);
    CHECK(step2->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("mfa.enroll.failed", "alice") >= 1);
}

TEST_CASE("POST /login/mfa/enroll attempts cap erases pending after 5 failures",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // qe-B2: enrollment-bootstrap brute-force cap parity with /login/mfa.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string secret = body.at("secret_base32");

    for (int i = 0; i < 5; ++i) {
        auto r = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 401);
    }
    // 6th attempt with the CORRECT code — entry was erased after the 5th
    // failure, so it still 401s (token gone).
    auto good = h.sink.Post("/login/mfa/enroll",
                            form({{"mfa_pending_token", pending}, {"code", h.totp_at(secret, 0)}}),
                            "application/x-www-form-urlencoded");
    REQUIRE(good);
    CHECK(good->status == 401);
    AuditQuery q;
    q.action = "mfa.enroll.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw_exhausted = false;
    for (const auto& r : *rows) {
        if (r.detail.find("attempts exhausted") != std::string::npos) {
            saw_exhausted = true;
            break;
        }
    }
    CHECK(saw_exhausted);
}

TEST_CASE("POST /login/mfa/enroll non-6-digit code is rejected as malformed, token survives",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // qe-S1: shape gate. Recovery codes don't exist at enroll time, so a
    // non-6-digit code is "malformed", not routed to recovery.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string secret = body.at("secret_base32");

    auto bad = h.sink.Post("/login/mfa/enroll",
                           form({{"mfa_pending_token", pending}, {"code", "12345"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 401);
    AuditQuery q;
    q.action = "mfa.enroll.failed";
    auto rows = h.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool saw_malformed = false;
    for (const auto& r : *rows) {
        if (r.detail.find("malformed") != std::string::npos)
            saw_malformed = true;
    }
    CHECK(saw_malformed);
    // Token survived (attempts < cap) — the correct code now completes.
    auto good = h.sink.Post("/login/mfa/enroll",
                            form({{"mfa_pending_token", pending}, {"code", h.totp_at(secret, 0)}}),
                            "application/x-www-form-urlencoded");
    REQUIRE(good);
    CHECK(good->status == 200);
}

TEST_CASE("POST /login/mfa/enroll concurrent submit with same token: exactly one wins",
          "[pg][mfa][enroll][routes][auth_routes]") {
    // qe-S2: the enroll endpoint's atomic move-out-on-lookup must mint
    // exactly one session under a same-token race, like /login/mfa.
    AuthRoutesHarness h;
    h.cfg.mfa_enforcement = "required";
    auto step1 =
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = nlohmann::json::parse(step1->body);
    std::string pending = body.at("mfa_pending_token");
    std::string code = h.totp_at(body.at("secret_base32"), 0);

    std::atomic<int> successes{0};
    std::atomic<int> failures{0};
    auto worker = [&]() {
        auto r = h.sink.Post("/login/mfa/enroll",
                             form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
        if (r && r->status == 200)
            ++successes;
        else
            ++failures;
    };
    std::thread t1(worker);
    std::thread t2(worker);
    t1.join();
    t2.join();
    CHECK(successes.load() == 1);
    CHECK(failures.load() == 1);
}

TEST_CASE("POST /login/mfa concurrent submit with same token: exactly one wins",
          "[pg][mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto code = h.totp_at(secret_b32);

    // Race two threads through /login/mfa with the same pending token +
    // same code. The atomic erase-on-lookup guarantees exactly one
    // succeeds.
    std::atomic<int> successes{0};
    std::atomic<int> failures{0};
    auto worker = [&]() {
        auto r = h.sink.Post("/login/mfa",
                             form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
        if (r && r->status == 200) {
            ++successes;
        } else {
            ++failures;
        }
    };
    std::thread t1(worker);
    std::thread t2(worker);
    t1.join();
    t2.join();
    CHECK(successes.load() == 1);
    CHECK(failures.load() == 1);
}

// ── POST /login account lockout (SOC 2 CC6.3) ────────────────────────────
//
// The AuthRoutesHarness wires a real AuthDB + cfg; cfg is held by reference
// so a per-test `h.cfg.auth_lockout_threshold` override takes effect. These
// tests assert the HTTP-boundary CC6.3 evidence the AuthDB unit tests can't:
// the generic-401 (no enumeration/lock-state oracle), the applied-audit-once
// invariant, and the success-clears-the-counter path.

TEST_CASE("POST /login: N bad passwords locks the account, applied audit fires once",
          "[pg][mfa][routes][auth_routes][lockout]") {
    AuthRoutesHarness h;
    h.cfg.auth_lockout_threshold = 3;
    h.cfg.auth_lockout_window_secs = 900;

    // Three bad-password attempts — the third crosses the threshold.
    for (int i = 0; i < 3; ++i) {
        auto r = h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 401);
    }
    // Exactly one applied audit row at the crossing — NOT one per failure.
    CHECK(h.count_audits("auth.lockout.applied", "alice") == 1);

    // A subsequent attempt with the CORRECT password is rejected while locked
    // (the brute-force throttle does not yield to a correct guess mid-lock) and
    // no session is minted.
    auto locked = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                              "application/x-www-form-urlencoded");
    REQUIRE(locked);
    CHECK(locked->status == 401);
    CHECK(locked->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.login", "alice") == 0);
    // Still exactly one applied row — the blocked attempt does not re-audit.
    CHECK(h.count_audits("auth.lockout.applied", "alice") == 1);
}

TEST_CASE("POST /login: locked-account 401 body is shape-identical to a bad-password 401 (no oracle)",
          "[pg][mfa][routes][auth_routes][lockout]") {
    AuthRoutesHarness h;
    h.cfg.auth_lockout_threshold = 2;

    // A bad-password 401 from a NOT-yet-locked account (attempt 1).
    auto bad = h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 401);

    // Attempt 2 crosses the threshold → account locked.
    h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                "application/x-www-form-urlencoded");

    // Attempt 3 is blocked by the pre-check (locked) with a correct password.
    auto locked = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                              "application/x-www-form-urlencoded");
    REQUIRE(locked);
    CHECK(locked->status == 401);
    // The whole point: a locked account is indistinguishable from a wrong
    // password — same status AND same code/message shape, no Retry-After,
    // no "locked" word. NOT byte-identical bodies any more: the A4 envelope
    // (#1552 sweep) stamps a fresh per-request `correlation_id` on every
    // response, so `bad` and `locked` legitimately carry DIFFERENT
    // correlation ids — that is itself evidence there is no shared-object
    // artifact, not a new oracle (a correlation id is minted identically on
    // every failure path regardless of WHY it failed).
    auto bad_json = nlohmann::json::parse(bad->body);
    auto locked_json = nlohmann::json::parse(locked->body);
    CHECK(locked_json["error"]["code"] == bad_json["error"]["code"]);
    CHECK(locked_json["error"]["message"] == bad_json["error"]["message"]);
    CHECK(locked_json["error"]["correlation_id"] != bad_json["error"]["correlation_id"]);
    CHECK(locked->body.find("locked") == std::string::npos);
    CHECK(locked->get_header_value("Retry-After").empty());
}

TEST_CASE("POST /login: a successful login clears a non-zero failure counter",
          "[pg][mfa][routes][auth_routes][lockout]") {
    AuthRoutesHarness h;
    h.cfg.auth_lockout_threshold = 3;

    // Two failures — below the threshold, account not locked.
    for (int i = 0; i < 2; ++i) {
        h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                    "application/x-www-form-urlencoded");
    }
    CHECK(h.count_audits("auth.lockout.applied", "alice") == 0);

    // Correct password succeeds (alice has no MFA) and clears the counter.
    auto ok = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                          "application/x-www-form-urlencoded");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    // The reset emits a cleared audit (only because the counter was non-zero).
    CHECK(h.count_audits("auth.lockout.cleared", "alice") == 1);

    // The counter is back to zero — a single fresh failure does not re-lock.
    auto st = h.auth_db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK(st->failed_count == 0);
    CHECK_FALSE(st->locked);
}

TEST_CASE("POST /login: lockout disabled (threshold=0) never locks",
          "[pg][mfa][routes][auth_routes][lockout]") {
    AuthRoutesHarness h;
    h.cfg.auth_lockout_threshold = 0; // disabled

    for (int i = 0; i < 8; ++i) {
        auto r = h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 401);
    }
    CHECK(h.count_audits("auth.lockout.applied", "alice") == 0);
    // Correct password still succeeds — never locked.
    auto ok = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                          "application/x-www-form-urlencoded");
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("POST /login: concurrent burst for one user cannot exceed the threshold (C1 race close)",
          "[pg][mfa][routes][auth_routes][lockout][concurrency]") {
    // Adversarial C1: without per-username serialization, a synchronized burst
    // of attempts for ONE username could all pass the stale lockout pre-check
    // and each verify a password before any failure was recorded, so the
    // effective guess budget was the in-flight concurrency, not the threshold.
    // The striped login lock serializes the check → verify → record sequence
    // per username, so at most `threshold` attempts reach verification before
    // the lock arms — failed_count ends EXACTLY at the threshold.
    AuthRoutesHarness h;
    const int threshold = 3;
    h.cfg.auth_lockout_threshold = threshold;
    h.cfg.auth_lockout_window_secs = 900;

    constexpr int kThreads = 16;
    // Per-thread result slots (distinct indices → no synchronization needed;
    // Catch2 assertion macros are NOT thread-safe, so we assert after join on
    // the main thread only).
    std::vector<int> statuses(kThreads, 0);
    std::vector<char> got_cookie(kThreads, 0);
    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        ts.emplace_back([&h, &statuses, &got_cookie, i] {
            auto r = h.sink.Post("/login", form({{"username", "alice"}, {"password", "wrong"}}),
                                 "application/x-www-form-urlencoded");
            if (r) {
                statuses[i] = r->status;
                got_cookie[i] = r->get_header_value("Set-Cookie").empty() ? 0 : 1;
            }
        });
    }
    for (auto& t : ts)
        t.join();

    // Every burst request was rejected (bad password OR locked) — never a
    // session minted for an out-of-budget guess.
    for (int i = 0; i < kThreads; ++i) {
        CHECK(statuses[i] == 401);
        CHECK(got_cookie[i] == 0);
    }

    // The serialization capped verifications at exactly the threshold (without
    // it, the racy count would exceed `threshold`).
    auto st = h.auth_db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK(st->locked);
    CHECK(st->failed_count == threshold);

    // The correct password is now rejected — the account is locked.
    auto locked = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                              "application/x-www-form-urlencoded");
    REQUIRE(locked);
    CHECK(locked->status == 401);
    CHECK(locked->get_header_value("Set-Cookie").empty());
}
