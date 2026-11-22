/**
 * test_auth_routes_hardened.cpp — Route-level coverage for hardened mode
 * (--auth-mode=sso-only) + the break-glass login exemption. SOC 2 CC6.3
 * (disable local-password fallback) + CC6.6 (constrained break-glass).
 * `/auth-and-authz` skill gap matrix P0 #3.
 *
 * Dispatches synthesized POST /login requests through a real TestRouteSink
 * (same in-process pattern as test_auth_routes_mfa.cpp — no listening socket,
 * which crashes under TSan, #438) and asserts on status / body / cookie and the
 * audit chain via the real AuditStore. The MFA-PR lesson (a route was
 * unreachable behind the auth gate and only live `curl` caught it) is why this
 * exercises the wire path, not just the AuthDB primitives.
 *
 * Wire contract under test:
 *   - standard mode: local login unaffected (regression guard)
 *   - sso-only, non-break-glass user: generic 401 (no mode/enumeration oracle),
 *     no session cookie, and NO per-attempt audit row (UP-2: metric-only)
 *   - sso-only, break-glass user but NOT armed: same generic 401
 *   - sso-only, break-glass user ARMED + MFA enrolled: proceeds to the MFA
 *     challenge (202) + `auth.breakglass.login` audit — never a bare session
 *   - sso-only, break-glass user ARMED but NOT enrolled: HARD-DENIED 403 +
 *     `auth.breakglass.denied` — enrollment is never offered (UP-1)
 *   - sso-only, wrong password vs armed break-glass: normal auth.login_failed,
 *     never a spurious break-glass "ok" row
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "session_store.hpp"
#include "test_route_sink.hpp"
#include "password_policy.hpp" // kMaxPasswordBytes
#include "test_pbkdf2_budget_fill.hpp"
#include "test_joining_thread.hpp"
#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include "pg/pg_raii.hpp"
#include <libpq-fe.h>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <filesystem>
#include <future>
#include <memory>
#include <vector>
#include <thread>
#include <tuple>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — the harness below clones this
// pre-migrated template instead of opening a SQLite path. Self-contained
// (mirrors yuzu::test::AuthDbPg, already embedded in the harness): SKIPs the
// enclosing TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset (via auth_db's own
// ctor, constructed first), FAILs when set but broken.
yuzu::test::PgTestTemplate auth_routes_hardened_audit_tpl{"hardaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("hardaudit template: store failed to migrate");
}};

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

/// AuthRoutes wired against an in-process sink, parameterised by the hardened
/// auth mode + break-glass user so each test fixes the deployment posture
/// before the routes are registered (cfg is read by the login handler).
struct HardenedHarness {
    TmpDirGuard tmp;
    Config cfg{};
    yuzu::MetricsRegistry metrics; // wired so the CC6.3/CC6.6 SIEM counters fire (review #1735 LOW)
    auth::AuthManager auth_mgr{};
    yuzu::test::AuthDbPg auth_db;
    // The durable session store on the shared pool, the production shape: the MFA gates judge a
    // local enrolled caller on the STORED proof (#6079), so a harness that drives one needs it.
    yuzu::server::SessionStore sessions{auth_db.pool()};
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
    // clone, matching audit_store's pattern above rather than sharing
    // auth_db's pool (this fixture keeps each additional store isolated).
    yuzu::test::AnalyticsEventStorePg analytics_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    yuzu::server::test::TestRouteSink sink;

    HardenedHarness(const std::string& auth_mode, const std::string& break_glass_user)
        : tmp(yuzu::test::unique_temp_path("auth-hardened-")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false; // no Secure cookie suffix
        cfg.auth_mode = auth_mode;
        cfg.break_glass_user = break_glass_user;

        auth_mgr.load_config(cfg.auth_config_path);
        seed_user("admin", "adminpassword1", auth::Role::admin);
        seed_user("alice", "alicepassword1", auth::Role::user);
        auth_mgr.set_auth_db(auth_db.get());
        REQUIRE(sessions.is_open());
        auth_mgr.set_session_store(&sessions);
        auth_mgr.set_metrics_registry(&metrics);

        audit_db.emplace(auth_routes_hardened_audit_tpl);
        INFO("[HardenedHarness] audit db status (blank == ok): " << audit_db->error());
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

    ~HardenedHarness() { auth_mgr.set_session_store(nullptr); }
    HardenedHarness(const HardenedHarness&) = delete;
    HardenedHarness& operator=(const HardenedHarness&) = delete;

    // Seed a user into BOTH AuthManager (in-memory verify) and AuthDB (the
    // is_active gate + mfa/break-glass state) — mirrors test_auth_routes_mfa.
    void seed_user(const std::string& name, const std::string& pw, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(name, pw, role));
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db
                    ->upsert_user(name, auth::AuthManager::pbkdf2_sha256(pw, salt, 100'000), salt_hex,
                                  role)
                    .has_value());
    }

    std::string enroll_mfa(const std::string& name) {
        auto init = auth_db->mfa_init_enrollment(name, "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        // Complete enrollment with a code at the current counter. These tests
        // stop at the 202 challenge — they never submit a login TOTP — so the
        // secret is not retained.
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(auth_db->mfa_verify_enrollment(name, code, std::nullopt).has_value());
        return init->secret_base32;
    }

    /// A TOTP code for the secret one step after the enrolment code.
    static std::string totp_next(const std::string& secret_b32) {
        auto bytes = mfa::base32_decode(secret_b32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        return mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()) + 1);
    }

    void arm(const std::string& name, int window_secs = 3600) {
        REQUIRE(auth_db->arm_break_glass(name, window_secs).has_value());
        auth_routes->reset_break_glass_arm_cache_for_test(); // the gate caches the arm state
    }

    int count_audits(const std::string& action, const std::string& principal = {}) {
        AuditQuery q;
        q.action = action;
        if (!principal.empty())
            q.principal = principal;
        auto res = audit_store->query(q);
        REQUIRE(res.has_value());
        return static_cast<int>(res->size());
    }

    // Read a metric counter value (review #1735 LOW). The label set must match
    // the production emission exactly, or counter(name, labels) returns a fresh
    // 0-valued series.
    double counter(const std::string& name, const yuzu::Labels& labels = {}) {
        return labels.empty() ? metrics.counter(name).value()
                              : metrics.counter(name, labels).value();
    }
};

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

constexpr const char* kFormCt = "application/x-www-form-urlencoded";

} // namespace

TEST_CASE("standard mode: local login still works (regression guard)",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("standard", "");
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("auth.local_disabled") == 0);
}

TEST_CASE("sso-only: non-break-glass local login is rejected with a generic 401",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("sso-only", "");
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    // SAME body as a bad password — no "disabled"/"sso-only" wording (no oracle).
    CHECK(res->body.find("Invalid username or password") != std::string::npos);
    CHECK(res->body.find("sso") == std::string::npos);
    CHECK(res->body.find("disabled") == std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    // UP-2: the sso-only denial is metric-only (yuzu_auth_local_disabled_total),
    // NEVER a per-attempt audit row — assert no audit row is written, but the
    // CC6.3 SIEM counter DID increment (review #1735 LOW).
    CHECK(h.count_audits("auth.local_disabled") == 0);
    CHECK(h.counter("yuzu_auth_local_disabled_total", {{"target", "other"}}) == 1.0);
}

TEST_CASE("sso-only: a valid password is still rejected when local login is disabled",
          "[pg][auth][hardened][routes]") {
    // Even the correct credential must not mint a session in sso-only mode for a
    // non-exempt user — the disable is unconditional, not a password check.
    HardenedHarness h("sso-only", "");
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    // UP-2: the sso-only denial is metric-only (yuzu_auth_local_disabled_total),
    // NEVER a per-attempt audit row — assert no audit row is written.
    CHECK(h.count_audits("auth.local_disabled") == 0);
}

TEST_CASE("sso-only: break-glass user is still rejected when NOT armed",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("sso-only", "admin");
    // admin is the configured break-glass user but has not been armed.
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    // UP-2: the sso-only denial is metric-only (yuzu_auth_local_disabled_total),
    // NEVER a per-attempt audit row — assert no audit row is written.
    CHECK(h.count_audits("auth.local_disabled") == 0);
    CHECK(h.count_audits("auth.breakglass.login", "admin") == 0);
}

TEST_CASE("sso-only: armed break-glass user with MFA proceeds to the MFA challenge",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           kFormCt);
    REQUIRE(res);
    // Enrolled → 202 challenge, NOT a 200 bare session.
    CHECK(res->status == 202);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.value("status", "") == "mfa_required");
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.breakglass.login", "admin") == 1);
    CHECK(h.count_audits("auth.local_disabled") == 0);
    // The CC6.6 break-glass-use SIEM counter incremented (review #1735 LOW).
    CHECK(h.counter("yuzu_auth_break_glass_login_total") == 1.0);
}

TEST_CASE("sso-only: a non-break-glass user is rejected even while another is armed",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    // UP-2: the sso-only denial is metric-only (yuzu_auth_local_disabled_total),
    // NEVER a per-attempt audit row — assert no audit row is written.
    CHECK(h.count_audits("auth.local_disabled") == 0);
}

TEST_CASE("sso-only: armed break-glass user WITHOUT MFA is HARD-DENIED, not offered enrollment",
          "[pg][auth][hardened][routes]") {
    // Governance UP-1 (BLOCKING fix). The boot guard normally refuses to start
    // with an MFA-less break-glass user; if one slips through (MFA cleared
    // out-of-band after boot), the login handler must HARD-DENY — never offer
    // enrollment, which would hand a fresh TOTP secret to whoever proved the
    // password and let a password-only adversary break the glass with no real
    // second factor.
    HardenedHarness h("sso-only", "alice");
    h.arm("alice"); // alice has no MFA enrolled
    auto res = h.sink.Post("/login", form({{"username", "alice"}, {"password", "alicepassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 403); // hard deny — NOT 202 enrollment, NOT 200 session
    CHECK(res->body.find("second factor") != std::string::npos);
    CHECK(res->body.find("mfa_enrollment_required") == std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.breakglass.denied", "alice") == 1);
    CHECK(h.count_audits("auth.breakglass.login", "alice") == 0);
}

TEST_CASE("sso-only: the break-glass account is exempt from failed-login lockout",
          "[pg][auth][hardened][routes]") {
    // Governance Hermes-F / UP-13: without the exemption an attacker who learns
    // the break-glass username could spray wrong passwords to keep it locked and
    // render the escape hatch unreachable during the very IdP outage it exists
    // for. The harness runs with the default lockout threshold (5), so spraying
    // > 5 wrong passwords would lock a normal account; the break-glass account
    // must remain reachable.
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    for (int i = 0; i < 8; ++i) {
        auto bad = h.sink.Post(
            "/login", form({{"username", "admin"}, {"password", "WRONGpassword1"}}), kFormCt);
        REQUIRE(bad);
        CHECK(bad->status == 401); // normal login failure, not a "locked" 401 (same body anyway)
    }
    // A correct-password break-glass login still reaches the MFA challenge — the
    // account was NOT locked out by the spray.
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 202); // MFA challenge, NOT a lockout 401
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.value("status", "") == "mfa_required");
    CHECK(h.count_audits("auth.breakglass.login", "admin") == 1);
    // The wrong attempts are still audited (evidence kept, lock dropped).
    CHECK(h.count_audits("auth.login_failed") >= 8);
}

TEST_CASE("sso-only: wrong password against an armed break-glass user is a normal login failure",
          "[pg][auth][hardened][routes]") {
    // The break-glass success row (auth.breakglass.login) must fire only AFTER
    // verify_password succeeds — a wrong password takes the standard
    // auth.login_failed path and never produces a spurious "ok" break-glass row.
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "WRONGpassword1"}}),
                           kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.breakglass.login", "admin") == 0);
    CHECK(h.count_audits("auth.login_failed") >= 1);
}

TEST_CASE("sso-only: with every lane full the break-glass name and every other name answer the same 401",
          "[pg][auth][hardened][routes][concurrency]") {
    HardenedHarness h("sso-only", "admin"); // admin is the break-glass name, NOT armed
    h.enroll_mfa("admin");
    auto& budget = h.auth_routes->pbkdf2_budget();
    budget.set_cap(8);
    auto held = yuzu::test::fill_pbkdf2_budget(budget);
    REQUIRE(held.size() == 8);
    for (const char* user : {"alice", "admin", "no-such-user-xyz"}) {
        auto res = h.sink.Post("/login", form({{"username", user}, {"password", "whatever-123456"}}),
                               kFormCt);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(res->get_header_value("Retry-After").empty());
    }
}

namespace {
/// Takes the whole break-glass lane through the budget, one slot per distinct source: the real
/// production state of "n break-glass attempts in flight".
std::vector<Pbkdf2Budget::Slot> hold_break_glass_lane(Pbkdf2Budget& b, int n, const char* tag) {
    std::vector<Pbkdf2Budget::Slot> held;
    for (int i = 0; i < n; ++i) {
        held.push_back(b.try_acquire(Pbkdf2Class::kBreakGlass, std::string(tag) + std::to_string(i)));
        REQUIRE(held.back().ok());
    }
    return held;
}
} // namespace

TEST_CASE("sso-only: break-glass guesses are bounded by the lane (exact numbers), without a lockout",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto& budget = h.auth_routes->pbkdf2_budget();
    budget.set_cap(66); // the default pool of 264: break-glass lane 4
    REQUIRE(budget.break_glass_cap() == 4);
    auto login = [&](const char* pw) {
        auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", pw}}), kFormCt);
        return res ? res->status : -1;
    };
    {
        auto three = hold_break_glass_lane(budget, 3, "attacker-"); // three attackers in flight
        CHECK(login("adminpassword1") == 202); // the operator, another source, still gets in
    }
    {
        auto four = hold_break_glass_lane(budget, 4, "attacker-"); // the lane is full
        const auto t0 = std::chrono::steady_clock::now();
        // Refused at once, right password or wrong, with the SAME generic 401 as any bad
        // credential (never a distinguishable 429: no name oracle).
        CHECK(login("WRONGpassword1") == 401);
        CHECK(login("adminpassword1") == 401);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        CHECK(ms < std::chrono::milliseconds(500)); // no waiting: the slot is non-blocking
    }
    CHECK(h.count_audits("auth.lockout.applied") == 0); // nothing was locked
    CHECK(login("adminpassword1") == 202);              // the operator is back in at once
}

TEST_CASE("sso-only: a full break-glass lane answers the break-glass name exactly like a decoy "
          "(status, body, headers), armed or not",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    auto answer = [](HardenedHarness& h, const char* user) {
        auto res = h.sink.Post("/login", form({{"username", user}, {"password", "whatever-123456"}}),
                               kFormCt);
        REQUIRE(res);
        const auto body = nlohmann::json::parse(res->body, nullptr, false);
        std::string msg = body.is_discarded() ? res->body
                                              : body["error"].value("message", std::string{});
        return std::tuple{res->status, msg, res->get_header_value("Retry-After"),
                          res->get_header_value("Set-Cookie")};
    };
    for (const bool armed : {false, true}) {
        HardenedHarness h("sso-only", "admin");
        h.enroll_mfa("admin");
        if (armed)
            h.arm("admin");
        auto& budget = h.auth_routes->pbkdf2_budget();
        budget.set_cap(66);
        auto held = hold_break_glass_lane(budget, budget.break_glass_cap(), "attacker-");
        // LANE FULL: the break-glass name and decoys answer identically. (Mutation: a 429 for the
        // busy lane -> the armed row differs from the decoy.)
        const auto decoy = answer(h, "alice");
        CHECK(std::get<0>(decoy) == 401);
        CHECK(answer(h, "admin") == decoy);
        CHECK(answer(h, "no-such-user-xyz") == decoy);
        held.clear();
        // LANE FREE: still the same for the break-glass name (armed: a wrong password is the
        // ordinary 401 of a failed credential; unarmed: the gate's 401).
        CHECK(std::get<0>(answer(h, "admin")) == 401);
        CHECK(std::get<2>(answer(h, "admin")).empty());
    }
}

TEST_CASE("break-glass: one slot per source address, taken without waiting",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto& budget = h.auth_routes->pbkdf2_budget();
    budget.set_cap(66);
    auto a_inflight = budget.try_acquire(Pbkdf2Class::kBreakGlass, "203.0.113.5");
    REQUIRE(a_inflight.ok());
    auto attempt = [&](const char* addr) {
        httplib::Request req;
        req.remote_addr = addr;
        PasswordCheckOptions opts;
        opts.lockout_exempt = true;
        opts.metric_route = "login";
        return h.auth_routes->verify_password_with_lockout("admin", "WRONGpassword1", req, opts).outcome;
    };
    CHECK(attempt("203.0.113.5") == PasswordCheckOutcome::kBusy); // A's second request: per source
    CHECK(attempt("198.51.100.9") == PasswordCheckOutcome::kBadCredential); // another source: served
}

TEST_CASE("break-glass: an over-length password takes the lane too (no flood bypass)",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto& budget = h.auth_routes->pbkdf2_budget();
    budget.set_cap(66);
    auto held = hold_break_glass_lane(budget, budget.break_glass_cap(), "attacker-");
    httplib::Request req;
    req.remote_addr = "198.51.100.77";
    PasswordCheckOptions opts;
    opts.lockout_exempt = true;
    opts.metric_route = "login";
    const std::string over(yuzu::server::auth::kMaxPasswordBytes + 1, 'x');
    // Without the fix the over-length shortcut skipped the lane and answered a normal bad
    // credential (kBadCredential) however many of these were in flight.
    CHECK(h.auth_routes->verify_password_with_lockout("admin", over, req, opts).outcome ==
          PasswordCheckOutcome::kBusy);
}

TEST_CASE("break-glass arm-state gate: one request reads the database, the rest are served from the "
          "cache (a flood naming the break-glass user cannot park workers)",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    h.auth_routes->reset_break_glass_arm_cache_for_test();
    REQUIRE(h.auth_routes->sso_only_local_password_gate("admin").state ==
            SsoOnlyLocalGate::kBreakGlassArmed); // warm the cache
    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // past the 1 s TTL
    // Make the arm-state read SLOW: another connection holds an exclusive lock on auth.users.
    yuzu::server::pg::PgConn locker{PQconnectdb(h.auth_db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::PgResult{PQexec(locker.get(), "BEGIN")}.ok());
    REQUIRE(yuzu::server::pg::PgResult{
        PQexec(locker.get(), "LOCK TABLE auth.users IN ACCESS EXCLUSIVE MODE")}.ok());
    constexpr int kCallers = 8;
    std::atomic<int> done{0};
    std::vector<yuzu::test::JoiningThread> callers;
    for (int i = 0; i < kCallers; ++i)
        callers.emplace_back([&] {
            (void)h.auth_routes->sso_only_local_password_gate("admin");
            ++done;
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    const int finished_while_locked = done.load();
    (void)yuzu::server::pg::PgResult{PQexec(locker.get(), "COMMIT")};
    callers.clear(); // join
    // Exactly the single-flight refresher is parked on the locked table; the other seven answered
    // from the stale value at once. (Mutation: no single flight -> all eight park, 0 finished.)
    CHECK(finished_while_locked == kCallers - 1);
}

namespace {
/// Holds an exclusive lock on auth.users from a second connection (a stuck arm-state read).
struct UsersTableLock {
    yuzu::server::pg::PgConn conn;
    explicit UsersTableLock(const std::string& dsn) : conn{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::PgResult{PQexec(conn.get(), "BEGIN")}.ok());
        REQUIRE(yuzu::server::pg::PgResult{
            PQexec(conn.get(), "LOCK TABLE auth.users IN ACCESS EXCLUSIVE MODE")}.ok());
    }
    void release() { (void)yuzu::server::pg::PgResult{PQexec(conn.get(), "COMMIT")}; }
};
} // namespace

TEST_CASE("break-glass gate: a stale armed value is never served past the TTL while a refresh is stuck",
          "[pg][auth][hardened][routes][concurrency][stripe][fail-closed]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin", 4); // a 4 s arm window
    REQUIRE(h.auth_routes->sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    std::this_thread::sleep_for(std::chrono::milliseconds(4300)); // the window has ended
    UsersTableLock lock(h.auth_db.dsn()); // the refresh will be stuck on this lock
    std::vector<SsoOnlyLocalGate> results(4, SsoOnlyLocalGate::kBreakGlassArmed);
    std::atomic<int> done{0};
    std::vector<yuzu::test::JoiningThread> callers;
    for (int i = 0; i < 4; ++i)
        callers.emplace_back([&, i] {
            results[i] = h.auth_routes->sso_only_local_password_gate("admin").state;
            ++done;
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    const int finished = done.load(); // everyone except the stuck refresher
    lock.release();
    callers.clear();
    // The three non-refreshers answer at once and are NOT admitted (mutation: serving the stale
    // armed value -> they answer kBreakGlassArmed past the end of the window). Their answer is
    // kTransient (the arm state could not be established); the refresher, once its read
    // completes, has a definitive kRefused (the window ended).
    CHECK(finished == 3);
    CHECK(std::count(results.begin(), results.end(), SsoOnlyLocalGate::kTransient) == 3);
    CHECK(std::count(results.begin(), results.end(), SsoOnlyLocalGate::kRefused) == 1);
    // The refusals for "a refresh is in flight and the cache is stale" are counted.
    CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "refresh_busy"}}) == 3.0);
}

TEST_CASE("break-glass gate: a stuck refresh fails closed within the bound, never parks",
          "[pg][auth][hardened][routes][concurrency][stripe][fail-closed]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    UsersTableLock lock(h.auth_db.dsn());
    std::promise<SsoOnlyLocalGate> p;
    auto f = p.get_future();
    yuzu::test::JoiningThread t([&] { p.set_value(h.auth_routes->sso_only_local_password_gate("admin").state); });
    // The read is bounded (lock and statement timeouts), so the gate answers on its own, REFUSING
    // although the account is armed. (Mutation: no timeouts -> it parks until the lock ends.)
    const bool in_time = f.wait_for(std::chrono::milliseconds(2000)) == std::future_status::ready;
    lock.release();
    t.join();
    CHECK(in_time);
    if (in_time) {
        CHECK(f.get() == SsoOnlyLocalGate::kTransient); // not a definitive "not armed"
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "read_failed"}}) == 1.0);
    }
}

TEST_CASE("break-glass gate: the arm window ends locally, with no refresh, from the database clock",
          "[pg][auth][hardened][routes][stripe][fail-closed]") {
    HardenedHarness h("sso-only", "admin");
    h.arm("admin", 4);
    std::this_thread::sleep_for(std::chrono::milliseconds(3300)); // ~0.7 s of the window left
    h.auth_routes->reset_break_glass_arm_cache_for_test();
    CHECK(h.auth_routes->sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    std::this_thread::sleep_for(std::chrono::milliseconds(900)); // cache still fresh (< 1 s), window over
    // Mutation: no local deadline check -> still armed from the fresh cache.
    CHECK(h.auth_routes->sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
}

TEST_CASE("break-glass gate: a disarm propagates within the cache TTL",
          "[pg][auth][hardened][routes][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.arm("admin");
    CHECK(h.auth_routes->sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    REQUIRE(h.auth_db->disarm_break_glass("admin").has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // past the 1 s TTL
    CHECK(h.auth_routes->sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
}

TEST_CASE("break-glass: a disarm or the end of the arm window between the password step and the "
          "MFA step ends the login (uniform 401, no session)",
          "[pg][auth][hardened][routes][fail-closed]") {
    for (const bool window_ends : {false, true}) {
        INFO(std::string(window_ends ? "the arm window ends" : "an operator disarms"));
        HardenedHarness h("sso-only", "admin");
        const auto secret = h.enroll_mfa("admin");
        h.arm("admin", window_ends ? 4 : 3600);
        auto step1 = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                                 kFormCt);
        REQUIRE(step1);
        REQUIRE(step1->status == 202);
        const auto body = nlohmann::json::parse(step1->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        const std::string pending = body.value("mfa_pending_token", "");
        REQUIRE_FALSE(pending.empty());
        if (window_ends) {
            std::this_thread::sleep_for(std::chrono::milliseconds(4300)); // past the 4 s window
        } else {
            REQUIRE(h.auth_db->disarm_break_glass("admin").has_value());
        }
        h.auth_routes->reset_break_glass_arm_cache_for_test();
        auto step2 = h.sink.Post(
            "/login/mfa",
            form({{"mfa_pending_token", pending}, {"code", HardenedHarness::totp_next(secret)}}),
            kFormCt);
        REQUIRE(step2);
        // The pending token + a VALID code must not mint once the account is no longer armed.
        // (Mutation: no re-check -> 200 with a session cookie.)
        CHECK(step2->status == 401);
        CHECK(step2->get_header_value("Set-Cookie").empty());
        CHECK(step2->get_header_value("Retry-After").empty());
        // The refusal is labelled by what the DATABASE said: a window that ended keeps its
        // armed_until text (window_ended); an un-arm writes NULL (disarmed).
        const yuzu::Labels want{{"reason", window_ends ? "window_ended" : "disarmed"},
                                {"stage", "pre_verify"}};
        const yuzu::Labels other{{"reason", window_ends ? "disarmed" : "window_ended"},
                                 {"stage", "pre_verify"}};
        CHECK(h.counter("yuzu_auth_break_glass_pending_refused_total", want) == 1.0);
        CHECK(h.counter("yuzu_auth_break_glass_pending_refused_total", other) == 0.0);
        AuditQuery q;
        q.action = "mfa.login.failed";
        auto rows = h.audit_store->query(q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK(rows->front().detail == (window_ends ? "break-glass no longer armed: window ended"
                                                   : "break-glass no longer armed: disarmed"));
    }
}

TEST_CASE("break-glass: the MFA step still mints while the account stays armed",
          "[pg][auth][hardened][routes]") {
    HardenedHarness h("sso-only", "admin");
    const auto secret = h.enroll_mfa("admin");
    h.arm("admin");
    auto step1 = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             kFormCt);
    REQUIRE(step1);
    REQUIRE(step1->status == 202);
    const auto body = nlohmann::json::parse(step1->body, nullptr, false);
    auto step2 = h.sink.Post(
        "/login/mfa",
        form({{"mfa_pending_token", body.value("mfa_pending_token", "")},
              {"code", HardenedHarness::totp_next(secret)}}),
        kFormCt);
    REQUIRE(step2);
    CHECK(step2->status == 200);
}

// ── WP03: the tri-state arm gate at the MFA step ─────────────────────────────────────────────
// These cases drive the gate's ONE database read through `set_break_glass_status_hook_for_test`
// and its clock through `set_arm_clock_for_test`, so no case depends on a sleep or on how fast
// the machine is. The clock is frozen at kT0 and moved by hand.
namespace {

constexpr std::int64_t kT0 = 1'000'000; // ms on the frozen arm clock
constexpr std::int64_t kW0 = 2'000'000'000'000; // ms on the frozen WALL clock (about year 2033)

/// What the hooked arm-state read answers. All fields are atomics so a request thread and the
/// test thread may touch them.
struct ArmCtl {
    enum Mode : int { kArmed = 0, kNotArmed = 1, kFail = 2 };
    std::atomic<int> mode{kArmed};
    std::atomic<int> id{1};                         // armed_until text is "arm-<id>"
    std::atomic<bool> empty_id{false};              // an armed read whose armed_until text is empty
    std::atomic<std::int64_t> remaining_ms{3'600'000};
    std::atomic<std::int64_t> advance_in_read_ms{0}; // the read itself takes this long
    std::atomic<bool> window_ended_in_db{false};     // a not-armed read keeps the ended window's text
    std::atomic<int> real_sleep_in_read_ms{0};       // the read blocks this long in REAL time
    std::atomic<int> reads{0};
    std::atomic<bool> block{false}; // the NEXT read to arrive is held until release() (one-shot)
    /// Run once, on the reading thread, at the start of the next read (single-threaded cases only).
    std::function<void()> before_answer;
    std::atomic<int> blocked{0};
    std::mutex mu;
    std::condition_variable cv;
    bool released{false};

    void release() {
        {
            std::lock_guard lk(mu);
            released = true;
        }
        cv.notify_all();
    }
};

void install_arm_hook(HardenedHarness& h, ArmCtl& ctl) {
    h.auth_routes->set_arm_clock_for_test(kT0);
    AuthRoutes* routes = h.auth_routes.get();
    h.auth_routes->set_break_glass_status_hook_for_test([routes, &ctl]() {
        ++ctl.reads;
        if (const auto adv = ctl.advance_in_read_ms.load(); adv > 0)
            routes->advance_arm_clock_for_test(adv);
        if (const int ms = ctl.real_sleep_in_read_ms.load(); ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        if (ctl.before_answer) {
            auto step = std::move(ctl.before_answer);
            ctl.before_answer = nullptr;
            step();
        }
        if (ctl.block.exchange(false)) {
            ++ctl.blocked;
            std::unique_lock lk(ctl.mu);
            ctl.cv.wait(lk, [&] { return ctl.released; });
        }
        BreakGlassArmRead r;
        const int mode = ctl.mode.load();
        r.ok = mode != ArmCtl::kFail;
        r.armed = mode == ArmCtl::kArmed;
        if (r.armed) {
            r.armed_until = ctl.empty_id.load() ? std::string{} : "arm-" + std::to_string(ctl.id.load());
            r.remaining_ms = ctl.remaining_ms.load();
        } else if (mode == ArmCtl::kNotArmed && ctl.window_ended_in_db.load()) {
            // What the database returns once a window has ended: not armed, the text kept.
            r.armed_until = "arm-" + std::to_string(ctl.id.load());
        }
        return r;
    });
    h.auth_routes->reset_break_glass_arm_cache_for_test();
}

struct Enrolled {
    std::string secret;
    std::vector<std::string> codes;
};

Enrolled enroll_with_codes(HardenedHarness& h, const std::string& name) {
    auto init = h.auth_db->mfa_init_enrollment(name, "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    auto done = h.auth_db->mfa_verify_enrollment(name, code, std::nullopt);
    REQUIRE(done.has_value());
    REQUIRE(done->recovery_codes.size() >= 4);
    return {init->secret_base32, done->recovery_codes};
}

/// A 6-digit code that is NOT the valid next code.
std::string wrong_totp(const std::string& secret) {
    std::string c = HardenedHarness::totp_next(secret);
    c.back() = c.back() == '9' ? '0' : static_cast<char>(c.back() + 1);
    return c;
}

std::string login_step1(HardenedHarness& h) {
    auto step1 =
        h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}), kFormCt);
    REQUIRE(step1);
    REQUIRE(step1->status == 202);
    const auto body = nlohmann::json::parse(step1->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    const std::string pending = body.value("mfa_pending_token", "");
    REQUIRE_FALSE(pending.empty());
    return pending;
}

auto login_step2(HardenedHarness& h, const std::string& pending, const std::string& code) {
    auto r = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                         kFormCt);
    REQUIRE(r);
    return r;
}

double refused(HardenedHarness& h, const char* reason, const char* stage) {
    return h.counter("yuzu_auth_break_glass_pending_refused_total",
                     {{"reason", reason}, {"stage", stage}});
}
double refused_total(HardenedHarness& h) {
    double n = 0;
    for (const char* reason : {"disarmed", "window_ended", "transient"})
        for (const char* stage : {"pre_verify", "pre_mint"})
            n += refused(h, reason, stage);
    return n;
}
double transient_admitted(HardenedHarness& h) {
    return h.counter("yuzu_auth_break_glass_pending_transient_admitted_total");
}

/// "result|detail" of every audit row for `action`.
std::vector<std::string> audit_rows(HardenedHarness& h, const std::string& action) {
    AuditQuery q;
    q.action = action;
    auto res = h.audit_store->query(q);
    REQUIRE(res.has_value());
    std::vector<std::string> out;
    for (const auto& e : *res)
        out.push_back(e.result + "|" + e.detail);
    return out;
}
int rows_containing(const std::vector<std::string>& rows, const std::string& needle) {
    int n = 0;
    for (const auto& r : rows)
        n += r.find(needle) != std::string::npos ? 1 : 0;
    return n;
}

/// Body with every correlation id removed, so two refusals can be compared byte for byte.
std::string masked_body(const std::string& body) {
    auto j = nlohmann::json::parse(body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    std::function<void(nlohmann::json&)> strip = [&](nlohmann::json& n) {
        if (n.is_object()) {
            for (auto it = n.begin(); it != n.end();) {
                if (it.key().find("correlation") != std::string::npos)
                    it = n.erase(it);
                else {
                    strip(it.value());
                    ++it;
                }
            }
        } else if (n.is_array()) {
            for (auto& e : n)
                strip(e);
        }
    };
    strip(j);
    return j.dump();
}
/// Header names and values, minus any that carry a correlation id.
template <class Res> std::vector<std::pair<std::string, std::string>> masked_headers(const Res& r) {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& [k, v] : r->headers) {
        std::string lk = k;
        for (auto& c : lk)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lk.find("correlation") != std::string::npos)
            continue;
        out.emplace_back(lk, v);
    }
    std::sort(out.begin(), out.end());
    return out;
}

int mfa_failed_count(HardenedHarness& h, const std::string& name) {
    auto st = h.auth_db->mfa_lockout_status(name);
    REQUIRE(st.has_value());
    return st->failed_count;
}

} // namespace

// T10
TEST_CASE("break-glass gate: a definitive answer is kRefused and an unreadable arm state is kTransient",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;

    SECTION("another name is refused with no read") {
        const auto g = r.sso_only_local_password_gate("alice");
        CHECK(g.state == SsoOnlyLocalGate::kRefused);
        CHECK(g.why == SsoOnlyRefusedWhy::kNotBreakGlass);
        CHECK(ctl.reads == 0);
    }
    SECTION("armed: the id, the deadline and the START of the read") {
        ctl.advance_in_read_ms = 200; // the read takes 200 ms
        ctl.remaining_ms = 60'000;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kBreakGlassArmed);
        CHECK(g.arm_id == "arm-1");
        // read_at is the clock BEFORE the read (mutation: sampled after -> kT0 + 200).
        CHECK(g.read_at == std::chrono::steady_clock::time_point(std::chrono::milliseconds(kT0)));
        CHECK(g.deadline ==
              std::chrono::steady_clock::time_point(std::chrono::milliseconds(kT0 + 60'000)));
        CHECK_FALSE(g.last_not_armed_at.has_value());
    }
    SECTION("a read that says not armed is definitive") {
        ctl.mode = ArmCtl::kNotArmed;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kRefused);
        CHECK(g.why == SsoOnlyRefusedWhy::kDisarmed);
        REQUIRE(g.last_not_armed_at.has_value());
        CHECK(*g.last_not_armed_at ==
              std::chrono::steady_clock::time_point(std::chrono::milliseconds(kT0)));
    }
    SECTION("the local deadline passing is a definitive window end, with no read") {
        ctl.remaining_ms = 500;
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
        r.advance_arm_clock_for_test(600); // inside the 1 s cache, past the window
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kRefused);
        CHECK(g.why == SsoOnlyRefusedWhy::kWindowEnded);
        CHECK(ctl.reads == 1);
    }
    SECTION("a failed read is transient, caches nothing and keeps what was last seen") {
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
        r.advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK(g.cause == SsoOnlyTransientCause::kReadFailed);
        CHECK(g.arm_id == "arm-1"); // the last definitive armed id survives the failed read
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "read_failed"}}) == 1.0);
        // Nothing was cached: the next call reads again.
        const int before = ctl.reads;
        (void)r.sso_only_local_password_gate("admin");
        CHECK(ctl.reads == before + 1);
    }
    SECTION("a not-armed read sets the last-not-armed time and leaves the last armed id") {
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
        r.advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kNotArmed;
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
        r.advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK(g.arm_id == "arm-1");
        REQUIRE(g.last_not_armed_at.has_value()); // survives the failed read too
        CHECK(*g.last_not_armed_at ==
              std::chrono::steady_clock::time_point(std::chrono::milliseconds(kT0 + 1100)));
    }
    SECTION("an old cache while another request refreshes is transient") {
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
        r.advance_arm_clock_for_test(1100);
        ctl.block = true;
        yuzu::test::JoiningThread refresher([&] { (void)r.sso_only_local_password_gate("admin"); });
        while (ctl.blocked.load() == 0)
            std::this_thread::yield();
        const auto g = r.sso_only_local_password_gate("admin");
        ctl.release();
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK(g.cause == SsoOnlyTransientCause::kRefreshBusy);
        CHECK(g.arm_id == "arm-1");
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "refresh_busy"}}) == 1.0);
    }
    SECTION("admits_password_evaluation is true for open and armed only") {
        SsoOnlyGateResult g;
        g.state = SsoOnlyLocalGate::kOpen;
        CHECK(g.admits_password_evaluation());
        g.state = SsoOnlyLocalGate::kBreakGlassArmed;
        CHECK(g.admits_password_evaluation());
        g.state = SsoOnlyLocalGate::kRefused;
        CHECK_FALSE(g.admits_password_evaluation());
        g.state = SsoOnlyLocalGate::kTransient;
        CHECK_FALSE(g.admits_password_evaluation());
    }
}

TEST_CASE("break-glass gate: with no auth store the arm state is transient (read_failed)",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    h.auth_mgr.set_auth_db(nullptr);
    h.auth_routes->reset_break_glass_arm_cache_for_test();
    const auto g = h.auth_routes->sso_only_local_password_gate("admin");
    h.auth_mgr.set_auth_db(h.auth_db.get());
    CHECK(g.state == SsoOnlyLocalGate::kTransient);
    CHECK(g.cause == SsoOnlyTransientCause::kReadFailed);
    CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "read_failed"}}) == 1.0);
}

// T17: the gate-level cap
TEST_CASE("break-glass gate: an armed read is never honoured more than 4.5 s after it started",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;

    SECTION("a read that itself took 4.6 s is transient, on the gate and at /login") {
        ctl.advance_in_read_ms = 4600;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK(g.cause == SsoOnlyTransientCause::kStaleRead);
        // Not a not-armed observation (mutation: the cap records one -> has_value()).
        CHECK_FALSE(g.last_not_armed_at.has_value());
        CHECK(g.arm_id.empty()); // an over-age armed read is not recorded as the last armed id
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "stale_read"}}) == 1.0);
        auto res = h.sink.Post("/login",
                               form({{"username", "admin"}, {"password", "adminpassword1"}}), kFormCt);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(res->get_header_value("Set-Cookie").empty());
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "stale_read"}}) == 2.0);
    }
    SECTION("a read that took 4.4 s is honoured") {
        ctl.advance_in_read_ms = 4400;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(g.state == SsoOnlyLocalGate::kBreakGlassArmed);
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "stale_read"}}) == 0.0);
    }
    SECTION("a cache hit is held to the same bound") {
        // The read took 4.0 s, so the cache is 0 s old by the time it was stored but the
        // observation is already 4.0 s old. 0.6 s later the cache is still inside its 1 s life.
        ctl.advance_in_read_ms = 4000;
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
        ctl.advance_in_read_ms = 0;
        r.advance_arm_clock_for_test(600);
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(ctl.reads == 1); // answered from the cache, not by a new read
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK(g.cause == SsoOnlyTransientCause::kStaleRead);
        CHECK_FALSE(g.last_not_armed_at.has_value());
    }
}

// T1 (and T7: both code shapes)
TEST_CASE("break-glass MFA step: an unreadable arm state at the second re-check admits inside the bound",
          "[pg][auth][hardened][routes][wp03]") {
    const bool recovery = GENERATE(false, true);
    INFO((recovery ? "recovery code" : "TOTP"));
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    int barrier_calls = 0;
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        ++barrier_calls;
        h.auth_routes->advance_arm_clock_for_test(1100); // past the 1 s cache
        ctl.mode = ArmCtl::kFail;                         // the re-read fails
    });
    auto res = login_step2(h, pending, recovery ? mfa.codes[0] : HardenedHarness::totp_next(mfa.secret));
    CHECK(barrier_calls == 1);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    CHECK(transient_admitted(h) == 1.0);
    CHECK(refused_total(h) == 0.0);
    const auto rows = audit_rows(h, "auth.login");
    CHECK(rows_containing(rows, std::string("method=password+") + (recovery ? "recovery" : "totp") +
                                    ";arm_recheck=transient_admitted") == 1);
}

// T1 control
TEST_CASE("break-glass MFA step: a definitive disarm at the second re-check refuses, and says so",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        h.auth_routes->advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kNotArmed;
    });
    auto res = login_step2(h, pending, mfa.codes[0]);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(refused(h, "disarmed", "pre_mint") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(transient_admitted(h) == 0.0);
    CHECK(rows_containing(audit_rows(h, "auth.login"),
                          "reason=break_glass_disarmed_before_mint;method=password+recovery") == 1);
    // The recovery code WAS consumed (the refusal is honest about a spent code).
    h.auth_routes->set_mfa_verify_barrier_for_test(nullptr);
    ctl.mode = ArmCtl::kArmed;
    h.auth_routes->advance_arm_clock_for_test(1100);
    auto again = login_step2(h, login_step1(h), mfa.codes[0]);
    CHECK(again->status == 401);
}

// UP-1 (governance round 11). `steady_clock` does not advance while the host is suspended, so after a
// suspend of any length a failed read at the second check looks, on the monotonic clock, like the
// few hundred milliseconds the bound allows. The wall clock is read only to notice that, and only to
// REFUSE: a wall clock that moved backward changes nothing.
TEST_CASE("break-glass MFA step: a suspend between the two checks refuses an unreadable arm state at the second",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    // Wall time that passes between the two checks while the monotonic clock moves 1.1 s.
    const std::int64_t wall_ms = GENERATE(1100, -60000, 4400, 4500, 4600, 60000);
    const bool refuses = wall_ms > 4500;
    INFO("wall clock moved " << wall_ms << " ms, monotonic 1100 ms");
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    h.auth_routes->set_arm_wall_clock_for_test(kW0);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        h.auth_routes->advance_arm_clock_for_test(1100); // past the 1 s cache, well inside 4.5 s
        h.auth_routes->advance_arm_wall_clock_for_test(wall_ms);
        ctl.mode = ArmCtl::kFail; // the re-read fails
    });
    auto res = login_step2(h, pending, mfa.codes[0]);
    if (refuses) {
        CHECK(res->status == 401);
        CHECK(res->get_header_value("Set-Cookie").empty());
        CHECK(refused(h, "transient", "pre_mint") == 1.0);
        CHECK(refused_total(h) == 1.0);
        CHECK(transient_admitted(h) == 0.0);
        CHECK(rows_containing(audit_rows(h, "auth.login"),
                              "reason=break_glass_arm_state_unreadable_before_mint;method=password+recovery") == 1);
        CHECK(rows_containing(audit_rows(h, "auth.login"), "arm_recheck=transient_admitted") == 0);
    } else {
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
        CHECK(transient_admitted(h) == 1.0);
        CHECK(refused_total(h) == 0.0);
    }
}

// T2 (and T7)
TEST_CASE("break-glass MFA step: an unreadable arm state after the window's end refuses as window_ended",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    const bool recovery = GENERATE(false, true);
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    ctl.remaining_ms = 3000;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        // 3.5 s: past the 3 s window, INSIDE the 4.5 s age bound, so the deadline is the only
        // clause that can refuse (mutation: deadline clause removed -> 200).
        h.auth_routes->advance_arm_clock_for_test(3500);
        ctl.mode = ArmCtl::kFail;
    });
    auto res = login_step2(h, pending, recovery ? mfa.codes[0] : HardenedHarness::totp_next(mfa.secret));
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(refused(h, "window_ended", "pre_mint") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(rows_containing(audit_rows(h, "auth.login"),
                          std::string("reason=break_glass_window_ended_before_mint;method=password+") +
                              (recovery ? "recovery" : "totp")) == 1);
}

// T16
TEST_CASE("break-glass MFA step: a definitive window end at the second re-check is labelled window_ended",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        // The window ends while the code is being verified: the second re-check's own read finds
        // it ended (not armed, the window's text kept).
        ctl.mode = ArmCtl::kNotArmed;
        ctl.window_ended_in_db = true;
    });
    const int reads_before = ctl.reads;
    auto res = login_step2(h, pending, HardenedHarness::totp_next(mfa.secret));
    CHECK(ctl.reads == reads_before + 1); // the second re-check read the arm state itself
    CHECK(res->status == 401);
    CHECK(refused(h, "window_ended", "pre_mint") == 1.0);
    CHECK(refused_total(h) == 1.0);
}

// T3
TEST_CASE("break-glass MFA step: an unreadable arm state after a re-arm with another window refuses",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        ctl.id = 2; // a new arm window
        h.auth_routes->advance_arm_clock_for_test(1100);
        REQUIRE(h.auth_routes->sso_only_local_password_gate("admin").arm_id == "arm-2");
        h.auth_routes->advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
    });
    auto res = login_step2(h, pending, mfa.codes[0]);
    CHECK(res->status == 401);
    CHECK(refused(h, "transient", "pre_mint") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(rows_containing(
              audit_rows(h, "auth.login"),
              "reason=break_glass_arm_state_unreadable_before_mint;method=password+recovery") == 1);
}

// T11 (F1)
TEST_CASE("break-glass MFA step: an unreadable arm state after this server saw the arm removed refuses",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        auto& r = *h.auth_routes;
        // Another request reads the arm state after it was removed: a definitive not-armed.
        ctl.mode = ArmCtl::kNotArmed;
        r.advance_arm_clock_for_test(1100);
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
        // The second re-check's own read then fails.
        r.advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
    });
    auto res = login_step2(h, pending, mfa.codes[0]);
    // 2.2 s after the read behind the first re-check: inside the age bound, before the deadline,
    // and the last armed id is still the one the first re-check saw. Only the "this server has
    // seen the arm removed since" clause can refuse (mutation: clause removed -> 200).
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(refused(h, "disarmed", "pre_mint") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(transient_admitted(h) == 0.0);
    h.auth_routes->set_mfa_verify_barrier_for_test(nullptr);
    ctl.mode = ArmCtl::kFail;
    h.auth_routes->advance_arm_clock_for_test(1100);
    const auto g = h.auth_routes->sso_only_local_password_gate("admin");
    CHECK(g.state == SsoOnlyLocalGate::kTransient);
    CHECK(g.arm_id == "arm-1"); // the id equality could not have been the refusing clause
}

// T12
TEST_CASE("break-glass MFA step: an unreadable arm state is admitted only inside the 4.5 s bound",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);

    SECTION("4.6 s after the read behind the first re-check: refused, labelled transient") {
        const auto pending = login_step1(h);
        h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            h.auth_routes->advance_arm_clock_for_test(4600);
            ctl.mode = ArmCtl::kFail;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        CHECK(res->status == 401);
        CHECK(refused(h, "transient", "pre_mint") == 1.0);
        CHECK(refused_total(h) == 1.0);
    }
    SECTION("4.4 s: admitted") {
        const auto pending = login_step1(h);
        h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            h.auth_routes->advance_arm_clock_for_test(4400);
            ctl.mode = ArmCtl::kFail;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        CHECK(res->status == 200);
        CHECK(transient_admitted(h) == 1.0);
    }
    SECTION("the bound counts from the START of the read: a 0.2 s read plus 4.4 s is refused") {
        ctl.advance_in_read_ms = 200; // the password step's read takes 0.2 s
        const auto pending = login_step1(h);
        ctl.advance_in_read_ms = 0;
        h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            h.auth_routes->advance_arm_clock_for_test(4400);
            ctl.mode = ArmCtl::kFail;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        // Mutation: read_at sampled after the read -> the age is 4.4 s -> 200.
        CHECK(res->status == 401);
        CHECK(refused(h, "transient", "pre_mint") == 1.0);
    }
}

// T4 (and T7)
TEST_CASE("break-glass MFA step: an unreadable arm state at the first re-check spends nothing and keeps the token",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    const bool recovery = GENERATE(false, true);
    INFO((recovery ? "recovery code" : "TOTP"));
    // The reference: a wrong TOTP on an armed account, in its own harness.
    std::string ref_body;
    std::vector<std::pair<std::string, std::string>> ref_headers;
    int ref_status = 0;
    {
        HardenedHarness ref("sso-only", "admin");
        const auto m = enroll_with_codes(ref, "admin");
        ArmCtl c;
        install_arm_hook(ref, c);
        auto wrong = login_step2(ref, login_step1(ref), wrong_totp(m.secret));
        ref_status = wrong->status;
        ref_body = masked_body(wrong->body);
        ref_headers = masked_headers(wrong);
    }
    REQUIRE(ref_status == 401);

    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    const std::string code = recovery ? mfa.codes[0] : HardenedHarness::totp_next(mfa.secret);
    const int failed_before = mfa_failed_count(h, "admin");
    h.auth_routes->advance_arm_clock_for_test(1100);
    ctl.mode = ArmCtl::kFail;
    auto res = login_step2(h, pending, code);
    CHECK(res->status == 401);
    CHECK(masked_body(res->body) == ref_body);
    CHECK(masked_headers(res) == ref_headers);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(res->get_header_value("Retry-After").empty());
    CHECK(refused(h, "transient", "pre_verify") == 1.0);
    CHECK(refused_total(h) == 1.0); // in particular no "disarmed" series moved
    CHECK(mfa_failed_count(h, "admin") == failed_before);
    const auto rows = audit_rows(h, "mfa.login.failed");
    CHECK(rows.size() == 1);
    CHECK(rows_containing(rows, "break-glass arm state unreadable") == 1);
    CHECK(h.counter("yuzu_auth_mfa_logins_total",
                    {{"method", recovery ? "recovery" : "totp"}, {"result", "failure"}}) == 0.0);
    // The pending token is back and the code was neither consumed nor marked as used: the same
    // token and the same code complete the login once the arm state reads again.
    ctl.mode = ArmCtl::kArmed;
    auto ok = login_step2(h, pending, code);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
}

// T5 (and T7), T8
TEST_CASE("break-glass MFA step: a definitive refusal at the first re-check spends nothing and ends the token",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    const bool recovery = GENERATE(false, true);
    const bool window_ended = GENERATE(false, true);
    INFO((recovery ? "recovery code" : "TOTP") << (window_ended ? ", window ended" : ", arm removed"));
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    if (window_ended)
        ctl.remaining_ms = 500;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    const std::string code = recovery ? mfa.codes[0] : HardenedHarness::totp_next(mfa.secret);
    const int failed_before = mfa_failed_count(h, "admin");
    if (window_ended) {
        h.auth_routes->advance_arm_clock_for_test(600); // the cached window is over
    } else {
        h.auth_routes->advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kNotArmed;
    }
    auto res = login_step2(h, pending, code);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(res->get_header_value("Retry-After").empty());
    CHECK(refused(h, window_ended ? "window_ended" : "disarmed", "pre_verify") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(mfa_failed_count(h, "admin") == failed_before);
    const auto rows = audit_rows(h, "mfa.login.failed");
    CHECK(rows.size() == 1);
    CHECK(rows_containing(rows, window_ended ? "break-glass no longer armed: window ended"
                                             : "break-glass no longer armed: disarmed") == 1);
    // The token stays consumed: the same token is now unknown.
    ctl.mode = ArmCtl::kArmed;
    ctl.remaining_ms = 3'600'000;
    h.auth_routes->advance_arm_clock_for_test(1100);
    auto gone = login_step2(h, pending, code);
    CHECK(gone->status == 401);
    CHECK(rows_containing(audit_rows(h, "mfa.login.failed"), "pending token invalid or expired") == 1);
    // Nothing was spent: no verifier ran, so the SAME code completes a fresh login.
    auto ok = login_step2(h, login_step1(h), code);
    CHECK(ok->status == 200);
}

// T6
TEST_CASE("break-glass MFA step: a recovery-code login completes while a refresh is held in flight",
          "[pg][auth][hardened][routes][concurrency][wp03]") {
    const bool window_over = GENERATE(false, true);
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    std::optional<yuzu::test::JoiningThread> refresher;
    std::vector<SsoOnlyLocalGate> others(8, SsoOnlyLocalGate::kOpen);
    int reads_at_recheck = 0;
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        auto& r = *h.auth_routes;
        r.advance_arm_clock_for_test(1100); // the cache is now older than its 1 s life
        // ONE request takes the refresh and is held inside the read.
        ctl.block = true;
        refresher.emplace([&] { (void)r.sso_only_local_password_gate("admin"); });
        while (ctl.blocked.load() == 0)
            std::this_thread::yield();
        // Eight more requests naming the user arrive and RETURN while it is held.
        std::vector<yuzu::test::JoiningThread> flood;
        for (int i = 0; i < 8; ++i)
            flood.emplace_back([&, i] { others[i] = r.sso_only_local_password_gate("admin").state; });
        flood.clear(); // joined
        if (window_over) {
            ctl.mode = ArmCtl::kNotArmed; // what the database now says: the window ended
            ctl.window_ended_in_db = true;
        }
        reads_at_recheck = ctl.reads;
    });
    auto res = login_step2(h, pending, mfa.codes[0]); // re-check #2 runs while the refresh is held
    ctl.release();
    refresher.reset();
    for (const auto s : others)
        CHECK(s == SsoOnlyLocalGate::kTransient);
    // Only the eight waiting requests found the refresh busy: the second re-check did not wait
    // for it and did not answer from the old cache; it read the arm state itself.
    CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "refresh_busy"}}) == 8.0);
    CHECK(ctl.reads == reads_at_recheck + 1);
    if (window_over) {
        CHECK(res->status == 401);
        CHECK(refused(h, "window_ended", "pre_mint") == 1.0);
    } else {
        // The code was consumed AND the session was minted, on a definitive armed answer.
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
        CHECK(transient_admitted(h) == 0.0);
        CHECK(refused_total(h) == 0.0);
    }
}

// T13: the armed control (real database, real clock, no hooks)
TEST_CASE("break-glass MFA step: an armed login spends for real and mints",
          "[pg][auth][hardened][routes][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    h.arm("admin");
    // A wrong code is counted against the account's second-factor budget.
    const int failed_before = mfa_failed_count(h, "admin");
    auto wrong = login_step2(h, login_step1(h), wrong_totp(mfa.secret));
    CHECK(wrong->status == 401);
    CHECK(mfa_failed_count(h, "admin") == failed_before + 1);
    // A recovery code works once.
    auto rec = login_step2(h, login_step1(h), mfa.codes[0]);
    CHECK(rec->status == 200);
    CHECK(rec->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    auto rec_again = login_step2(h, login_step1(h), mfa.codes[0]);
    CHECK(rec_again->status == 401);
    // A TOTP code works once.
    const auto totp = HardenedHarness::totp_next(mfa.secret);
    auto ok = login_step2(h, login_step1(h), totp);
    CHECK(ok->status == 200);
    auto replay = login_step2(h, login_step1(h), totp);
    CHECK(replay->status == 401);
    // No break-glass refusal or transient series moved, and the success row has the plain detail.
    CHECK(refused_total(h) == 0.0);
    CHECK(transient_admitted(h) == 0.0);
    for (const char* r : {"read_failed", "refresh_busy", "stale_read"})
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", r}}) == 0.0);
    CHECK(rows_containing(audit_rows(h, "auth.login"), "arm_recheck") == 0);
}

// T15
TEST_CASE("sso-only: an unreadable arm state at /login is the same generic 401 as a not-armed account",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    std::string ref_body;
    std::vector<std::pair<std::string, std::string>> ref_headers;
    {
        HardenedHarness ref("sso-only", "admin");
        ref.enroll_mfa("admin");
        ArmCtl c;
        c.mode = ArmCtl::kNotArmed;
        install_arm_hook(ref, c);
        auto r = ref.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                               kFormCt);
        REQUIRE(r);
        REQUIRE(r->status == 401);
        ref_body = masked_body(r->body);
        ref_headers = masked_headers(r);
    }
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    ArmCtl ctl;
    ctl.mode = ArmCtl::kFail;
    install_arm_hook(h, ctl);
    auto res =
        h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}), kFormCt);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(masked_body(res->body) == ref_body);
    CHECK(masked_headers(res) == ref_headers);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.counter("yuzu_auth_local_disabled_total", {{"target", "break_glass"}}) == 1.0);
    CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "read_failed"}}) == 1.0);
    CHECK(h.counter("yuzu_auth_break_glass_login_total") == 0.0);
}

// Code review F1: a refresh_busy answer carries the "last" facts as they are when it is given,
// not as they were when this request looked at the cache. Between those two moments another
// request can complete a whole refresh that records "not armed".
TEST_CASE("break-glass gate: a refresh_busy answer carries a not-armed read recorded after its cache check",
          "[pg][auth][hardened][routes][concurrency][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;
    REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    r.advance_arm_clock_for_test(1100); // the cache is now older than its 1 s life

    std::optional<yuzu::test::JoiningThread> second_refresher;
    bool in_gap = false;
    r.set_break_glass_after_cache_miss_hook_for_test([&] {
        if (in_gap)
            return; // only the outer call's gap is used
        in_gap = true;
        // (A) Another request refreshes inside the gap and reads "not armed".
        ctl.mode = ArmCtl::kNotArmed;
        REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
        // (B) That answer ages out and a third request takes the next refresh and is held in it.
        r.advance_arm_clock_for_test(1100);
        ctl.block = true;
        second_refresher.emplace([&] { (void)r.sso_only_local_password_gate("admin"); });
        while (ctl.blocked.load() == 0)
            std::this_thread::yield();
    });
    // (X) This call saw the old cache before (A) and finds the refresh taken by (B).
    const auto x = r.sso_only_local_password_gate("admin");
    ctl.release();
    second_refresher.reset();
    r.set_break_glass_after_cache_miss_hook_for_test(nullptr);
    REQUIRE(x.state == SsoOnlyLocalGate::kTransient);
    REQUIRE(x.cause == SsoOnlyTransientCause::kRefreshBusy);
    // (A)'s read started at kT0 + 1100 and was recorded before (X) answered.
    REQUIRE(x.last_not_armed_at.has_value());
    CHECK(*x.last_not_armed_at ==
          std::chrono::steady_clock::time_point(std::chrono::milliseconds(kT0 + 1100)));
    CHECK(x.arm_id == "arm-1");
}

// Code review F5: "window ended" as the DATABASE reports it (not armed, the window's text kept),
// as opposed to the local deadline passing.
TEST_CASE("break-glass: a read that finds an ended window is labelled window_ended, an un-arm disarmed",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    const bool ended = GENERATE(true, false);
    INFO((ended ? "the database keeps the ended window's text" : "the database holds no window"));
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    // The local deadline is an hour away, so only the database's answer can end this login.
    h.auth_routes->advance_arm_clock_for_test(1100);
    ctl.mode = ArmCtl::kNotArmed;
    ctl.window_ended_in_db = ended;
    const auto g = h.auth_routes->sso_only_local_password_gate("admin");
    CHECK(g.state == SsoOnlyLocalGate::kRefused);
    CHECK(g.why == (ended ? SsoOnlyRefusedWhy::kWindowEnded : SsoOnlyRefusedWhy::kDisarmed));
    // The cached answer keeps the same reason.
    const auto cached = h.auth_routes->sso_only_local_password_gate("admin");
    CHECK(cached.why == g.why);
    auto res = login_step2(h, pending, HardenedHarness::totp_next(mfa.secret));
    CHECK(res->status == 401);
    CHECK(refused(h, ended ? "window_ended" : "disarmed", "pre_verify") == 1.0);
    CHECK(refused_total(h) == 1.0);
    CHECK(rows_containing(audit_rows(h, "mfa.login.failed"),
                          ended ? "break-glass no longer armed: window ended"
                                : "break-glass no longer armed: disarmed") == 1);
}

// Code review F6: the pending token is put back on an unreadable arm state only while it is
// inside its lifetime.
TEST_CASE("break-glass MFA step: an unreadable arm state does not revive a pending token past its lifetime",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    // 2 s of the token's life are left, and the failing arm-state read takes 2.3 s of real time:
    // the token is looked up alive and is past its lifetime when the refusal is written.
    h.auth_routes->expire_mfa_pending_for_test(pending, std::chrono::milliseconds(118'000));
    REQUIRE(h.auth_routes->mfa_pending_count_for_test() == 1);
    h.auth_routes->advance_arm_clock_for_test(1100);
    ctl.mode = ArmCtl::kFail;
    ctl.real_sleep_in_read_ms = 2300;
    auto res = login_step2(h, pending, HardenedHarness::totp_next(mfa.secret));
    ctl.real_sleep_in_read_ms = 0;
    CHECK(res->status == 401);
    // The first re-check was reached (so the token was alive at lookup) ...
    REQUIRE(rows_containing(audit_rows(h, "mfa.login.failed"), "break-glass arm state unreadable") == 1);
    CHECK(refused(h, "transient", "pre_verify") == 1.0);
    // ... and the token was NOT put back. A later lookup would reap an expired entry before
    // using it, so the map itself is read (mutation: put back unconditionally -> 1 here).
    CHECK(h.auth_routes->mfa_pending_count_for_test() == 0);
    ctl.mode = ArmCtl::kArmed;
    auto again = login_step2(h, pending, HardenedHarness::totp_next(mfa.secret));
    CHECK(again->status == 401);
    CHECK(rows_containing(audit_rows(h, "mfa.login.failed"), "pending token invalid or expired") == 1);
}

// Code review F6: "attempts unchanged", observed through the per-token cap of 5.
TEST_CASE("break-glass MFA step: an unreadable arm state does not use up one of the token's attempts",
          "[pg][auth][hardened][routes][wp03]") {
    HardenedHarness h("sso-only", "admin");
    h.cfg.auth_lockout_threshold = 50; // keep the account's own budget out of the way
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    const auto wrong = wrong_totp(mfa.secret);
    for (int i = 0; i < 3; ++i)
        CHECK(login_step2(h, pending, wrong)->status == 401); // attempts 1, 2, 3
    // Two unreadable answers in between: neither is an attempt.
    for (int i = 0; i < 2; ++i) {
        h.auth_routes->advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
        CHECK(login_step2(h, pending, wrong)->status == 401);
        ctl.mode = ArmCtl::kArmed;
    }
    CHECK(refused(h, "transient", "pre_verify") == 2.0);
    // The fourth wrong code is still an ordinary rejection; the fifth exhausts the token.
    // (Mutation: the unreadable answer counts as an attempt -> the fourth is already "exhausted".)
    CHECK(login_step2(h, pending, wrong)->status == 401);
    auto rows = audit_rows(h, "mfa.login.failed");
    CHECK(rows_containing(rows, "totp code rejected") == 4);
    CHECK(rows_containing(rows, "attempts exhausted") == 0);
    CHECK(login_step2(h, pending, wrong)->status == 401);
    rows = audit_rows(h, "mfa.login.failed");
    CHECK(rows_containing(rows, "totp code rejected") == 4);
    CHECK(rows_containing(rows, "attempts exhausted") == 1);
}

// Code review F6: the transient admit compares arm ids, and an EMPTY id is never a match. An
// armed read always carries the window's text in production; if one ever did not, two empty ids
// must not be read as "the same arm window".
TEST_CASE("break-glass MFA step: an unreadable arm state never admits on an empty arm id",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    ctl.empty_id = true;
    install_arm_hook(h, ctl);
    const auto pending = login_step1(h);
    h.auth_routes->set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
        h.auth_routes->advance_arm_clock_for_test(1100);
        ctl.mode = ArmCtl::kFail;
    });
    auto res = login_step2(h, pending, mfa.codes[0]);
    // Inside the age bound, before the deadline, no not-armed read, and the two ids are EQUAL
    // (both empty): only the non-empty requirement can refuse (mutation: clause removed -> 200).
    CHECK(res->status == 401);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(refused(h, "transient", "pre_mint") == 1.0);
    CHECK(transient_admitted(h) == 0.0);
}

// UP-2 (governance round 11). A shared refresh that STARTED before this server's own read saw "not
// armed" can finish "armed" after it and put that older snapshot in the cache. Once this server
// holds a not-armed read at or after the cached snapshot's start, the cache must not serve it.
TEST_CASE("break-glass gate: an armed snapshot older than a not-armed read this server holds is not served",
          "[pg][auth][hardened][routes][concurrency][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;
    SsoOnlyGateResult refresher_answer;
    std::optional<yuzu::test::JoiningThread> refresher;
    // Declared AFTER `refresher`, so it is destroyed first: a failing REQUIRE cannot leave the
    // refresher blocked on the condition variable with its join waiting for it.
    struct ReleaseFirst {
        ArmCtl& c;
        ~ReleaseFirst() { c.release(); }
    } release_first{ctl};

    // 1. A shared refresh starts at T0 and blocks inside its database read.
    ctl.block = true;
    refresher.emplace([&] { refresher_answer = r.sso_only_local_password_gate("admin"); });
    const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5); // real time
    while (ctl.blocked.load() == 0 && std::chrono::steady_clock::now() < give_up)
        std::this_thread::yield();
    REQUIRE(ctl.blocked.load() == 1);

    // 2. 10 ms later this server's own read (the MFA step's second check) sees "not armed".
    r.advance_arm_clock_for_test(10);
    ctl.mode = ArmCtl::kNotArmed;
    const auto own = r.sso_only_local_password_gate("admin", SsoOnlyArmRead::kOwnFreshRead);
    REQUIRE(own.state == SsoOnlyLocalGate::kRefused);

    // 3. The older refresh finishes and answers "armed" (its snapshot predates the disarm). Its own
    //    caller is told so: that is the disclosed lag. It caches that answer.
    ctl.mode = ArmCtl::kArmed;
    ctl.release();
    refresher->join();
    CHECK(refresher_answer.state == SsoOnlyLocalGate::kBreakGlassArmed);

    // 4. The next request, 100 ms later and inside the 1 s cache life, must NOT be answered from
    //    that older snapshot: this server holds a newer not-armed read. It reads again.
    r.advance_arm_clock_for_test(100);
    ctl.mode = ArmCtl::kNotArmed;
    const int reads_before = ctl.reads;
    const auto g = r.sso_only_local_password_gate("admin");
    CHECK(g.state == SsoOnlyLocalGate::kRefused);
    CHECK(g.why == SsoOnlyRefusedWhy::kDisarmed);
    CHECK(ctl.reads == reads_before + 1);
}

TEST_CASE("break-glass gate: an armed snapshot newer than the last not-armed read is still served from the cache",
          "[pg][auth][hardened][routes][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;
    ctl.mode = ArmCtl::kNotArmed;
    REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
    // The account is armed afterwards: a later read says so, and that snapshot started AFTER the
    // not-armed read, so it is the newest evidence and is cached normally.
    r.advance_arm_clock_for_test(1100);
    ctl.mode = ArmCtl::kArmed;
    REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    const int reads = ctl.reads;
    r.advance_arm_clock_for_test(100);
    CHECK(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kBreakGlassArmed);
    CHECK(ctl.reads == reads); // answered from the cache: no extra database read
}

// Round 10 (r10-recovery-code-burn-slow-database-shared-single-flight): the second re-check reads
// the arm state itself. It does not answer from the shared cache and does not wait behind, or
// give up on, a refresh another request holds.
TEST_CASE("break-glass MFA step: the second re-check reads the arm state itself",
          "[pg][auth][hardened][routes][concurrency][fail-closed][wp03]") {
    HardenedHarness h("sso-only", "admin");
    const auto mfa = enroll_with_codes(h, "admin");
    ArmCtl ctl;
    install_arm_hook(h, ctl);
    auto& r = *h.auth_routes;
    std::optional<yuzu::test::JoiningThread> refresher;
    const auto hold_a_refresh = [&] {
        ctl.block = true;
        refresher.emplace([&] { (void)r.sso_only_local_password_gate("admin"); });
        while (ctl.blocked.load() == 0)
            std::this_thread::yield();
    };

    SECTION("a slow login with a refresh held by another request still completes") {
        const auto pending = login_step1(h);
        int reads_at_recheck = 0;
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            // 4.6 s after the read behind the first re-check (a slow database), and another
            // request naming the user holds the refresh.
            r.advance_arm_clock_for_test(4600);
            hold_a_refresh();
            reads_at_recheck = ctl.reads;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        ctl.release();
        refresher.reset();
        // The recovery code was consumed, so the login must not be refused for a busy refresh
        // and an old snapshot: the arm IS armed, and the second re-check can see that itself.
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
        CHECK(ctl.reads == reads_at_recheck + 1);
        CHECK(transient_admitted(h) == 0.0); // a definitive armed answer, not the transient rule
        CHECK(refused_total(h) == 0.0);
    }
    SECTION("the same, but the arm was removed: the own read refuses") {
        const auto pending = login_step1(h);
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            r.advance_arm_clock_for_test(4600);
            hold_a_refresh();
            ctl.mode = ArmCtl::kNotArmed;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        ctl.release();
        refresher.reset();
        CHECK(res->status == 401);
        CHECK(refused(h, "disarmed", "pre_mint") == 1.0);
        CHECK(refused_total(h) == 1.0);
    }
    SECTION("a first re-check served from a 4 s old cache entry does not doom the login") {
        ctl.advance_in_read_ms = 4000; // the password step's read takes 4 s
        const auto pending = login_step1(h);
        ctl.advance_in_read_ms = 0;
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            r.advance_arm_clock_for_test(600); // 4.6 s after that read started
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        CHECK(res->status == 200);
        CHECK(refused_total(h) == 0.0);
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "stale_read"}}) == 0.0);
    }
    SECTION("a wrong code with a refresh held does no read of its own") {
        const auto pending = login_step1(h);
        r.advance_arm_clock_for_test(500); // the first re-check is a cache hit
        const int before = ctl.reads;
        auto res = login_step2(h, pending, wrong_totp(mfa.secret));
        CHECK(res->status == 401);
        CHECK(ctl.reads == before); // the second re-check is never reached
    }
    SECTION("an own read that says armed but took longer than the cap is not honoured") {
        const auto pending = login_step1(h);
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            ctl.advance_in_read_ms = 4600; // the second re-check's read takes 4.6 s
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        // Too old to honour, so only the bounded rule is left, and the first check's snapshot is
        // by then 4.6 s old too (mutation: no cap on the own read -> 200).
        CHECK(res->status == 401);
        CHECK(refused(h, "transient", "pre_mint") == 1.0);
        CHECK(h.counter("yuzu_auth_break_glass_arm_gate_total", {{"result", "stale_read"}}) == 1.0);
        CHECK(transient_admitted(h) == 0.0);
    }
    SECTION("an own read that fails inside the bound still admits, and records nothing as not armed") {
        const auto pending = login_step1(h);
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            r.advance_arm_clock_for_test(500); // the shared cache is still fresh; it is not used
            ctl.mode = ArmCtl::kFail;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        // (Mutation: the failed own read records "not armed" -> the bounded rule refuses -> 401.)
        CHECK(res->status == 200);
        CHECK(transient_admitted(h) == 1.0);
        r.set_mfa_verify_barrier_for_test(nullptr);
        r.advance_arm_clock_for_test(1100);
        const auto g = r.sso_only_local_password_gate("admin"); // still failing
        CHECK(g.state == SsoOnlyLocalGate::kTransient);
        CHECK_FALSE(g.last_not_armed_at.has_value());
    }
    SECTION("a not-armed read recorded while the own read is in flight is in its answer") {
        const auto pending = login_step1(h);
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            r.advance_arm_clock_for_test(1100);
            // Inside the second re-check's own read: another request refreshes and reads "not
            // armed"; then the own read itself fails.
            ctl.before_answer = [&] {
                ctl.mode = ArmCtl::kNotArmed;
                REQUIRE(r.sso_only_local_password_gate("admin").state == SsoOnlyLocalGate::kRefused);
                ctl.mode = ArmCtl::kFail;
            };
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        // The answer carries the facts as they are when it is given (mutation: copied before the
        // read -> the not-armed record is missed -> 200).
        CHECK(res->status == 401);
        CHECK(refused(h, "disarmed", "pre_mint") == 1.0);
        CHECK(transient_admitted(h) == 0.0);
    }
    SECTION("an own read that says not armed makes the next request read again") {
        const auto pending = login_step1(h);
        r.set_mfa_verify_barrier_for_test([&](std::string_view, const auto&) {
            r.advance_arm_clock_for_test(200); // the shared cache still says armed and is fresh
            ctl.mode = ArmCtl::kNotArmed;
        });
        auto res = login_step2(h, pending, mfa.codes[0]);
        CHECK(res->status == 401);
        r.set_mfa_verify_barrier_for_test(nullptr);
        const int before = ctl.reads;
        const auto g = r.sso_only_local_password_gate("admin");
        CHECK(ctl.reads == before + 1); // not answered "armed" from the cache
        CHECK(g.state == SsoOnlyLocalGate::kRefused);
    }
}
