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
#include "test_pbkdf2_budget_fill.hpp"
#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <vector>
#include <thread>
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

    void enroll_mfa(const std::string& name) {
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
    }

    void arm(const std::string& name, int window_secs = 3600) {
        REQUIRE(auth_db->arm_break_glass(name, window_secs).has_value());
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

TEST_CASE("sso-only: a saturated PBKDF2 budget does not tell the break-glass name apart (429 vs 401)",
          "[pg][auth][hardened][routes][concurrency]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    // Fill every slot: the whole process-wide budget is in use.
    auto& budget = h.auth_routes->pbkdf2_budget();
    budget.set_cap(8);
    auto held = yuzu::test::fill_pbkdf2_budget(budget);
    REQUIRE(held.size() == 8);
    // UNARMED break-glass name and any other name: the same generic 401, never a 429, because
    // the sso-only gate refuses before a slot is taken. This pins that order: with the gate run
    // AFTER the slot, `alice` would answer 429 here while the break-glass name answered 401,
    // an oracle for the name (mutation-checked: moving the gate after the slot turns it RED).
    for (const char* user : {"alice", "admin", "no-such-user-xyz"}) {
        auto res = h.sink.Post("/login", form({{"username", user}, {"password", "whatever-123456"}}),
                               kFormCt);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(res->get_header_value("Retry-After").empty());
    }
}

TEST_CASE("sso-only: the armed break-glass login is not denied by a flood of its own name (stripe skipped)",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    h.cfg.auth_lockout_threshold = 5;
    // A same-name flood (or a name colliding onto admin's stripe) keeps the stripe held. The
    // break-glass account keeps no lockout counter, so it never takes the stripe.
    auto& stripe = h.auth_routes->login_lock_for_test("admin");
    stripe.lock();
    int status = 0;
    std::promise<void> done;
    auto finished = done.get_future();
    std::thread t([&] {
        auto res = h.sink.Post("/login",
                               form({{"username", "admin"}, {"password", "adminpassword1"}}),
                               kFormCt);
        status = res ? res->status : -1;
        done.set_value();
    });
    const bool in_time = finished.wait_for(std::chrono::milliseconds(700)) ==
                         std::future_status::ready;
    stripe.unlock();
    t.join();
    CHECK(in_time);
    CHECK(status == 202); // the MFA challenge, never the stripe-timeout 429 (mutation: RED)
}

TEST_CASE("sso-only: break-glass guesses are bounded at 4 concurrent (exact numbers), without a lockout",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto& gate = h.auth_routes->break_glass_gate_for_test();
    REQUIRE(gate.capacity() == 4);
    auto login = [&](const char* pw) {
        auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", pw}}), kFormCt);
        return res ? res->status : -1;
    };
    std::vector<BoundedGate::Permit> held;
    auto hold = [&](int n) {
        for (int i = 0; i < n; ++i) {
            held.push_back(gate.try_acquire_for(std::chrono::milliseconds(10)));
            REQUIRE(held.back().ok());
        }
    };
    hold(3); // three attacker attempts in flight: the legitimate operator still gets in
    CHECK(login("adminpassword1") == 202);
    hold(1); // four in flight (the bound): a fifth is refused 429 within the bounded wait
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(login("WRONGpassword1") == 429);
    CHECK(login("adminpassword1") == 429);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    CHECK(ms < std::chrono::milliseconds(800)); // two bounded waits of 150 ms, never a hang
    held.clear();
    CHECK(h.count_audits("auth.lockout.applied") == 0); // nothing was locked
    CHECK(login("adminpassword1") == 202);              // the operator is back in at once
}

TEST_CASE("sso-only: a saturated break-glass gate does not tell names or arm state apart",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin"); // admin is the break-glass name, NOT armed
    auto& gate = h.auth_routes->break_glass_gate_for_test();
    std::vector<BoundedGate::Permit> held;
    for (int i = 0; i < gate.capacity(); ++i) {
        held.push_back(gate.try_acquire_for(std::chrono::milliseconds(10)));
        REQUIRE(held.back().ok());
    }
    // The sso-only gate runs before the break-glass gate, so unarmed, other and unknown names
    // never touch it: the same generic 401, no Retry-After (mutation: gate first -> 429 for admin).
    for (const char* user : {"alice", "admin", "no-such-user-xyz"}) {
        auto res = h.sink.Post("/login", form({{"username", user}, {"password", "whatever-123456"}}),
                               kFormCt);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(res->get_header_value("Retry-After").empty());
    }
}

TEST_CASE("break-glass: per-source limits sit in FRONT of the shared gate (a source never queues)",
          "[pg][auth][hardened][routes][concurrency][stripe]") {
    HardenedHarness h("sso-only", "admin");
    h.enroll_mfa("admin");
    h.arm("admin");
    auto& budget = h.auth_routes->pbkdf2_budget();
    auto& gate = h.auth_routes->break_glass_gate_for_test();
    // Source A already has its one break-glass attempt in flight (its per-source slot)...
    auto a_inflight = budget.try_acquire(Pbkdf2Class::kBreakGlass, "203.0.113.5");
    REQUIRE(a_inflight.ok());
    // ...and other attackers hold every permit of the shared gate.
    std::vector<BoundedGate::Permit> held;
    for (int i = 0; i < gate.capacity(); ++i) {
        held.push_back(gate.try_acquire_for(std::chrono::milliseconds(10)));
        REQUIRE(held.back().ok());
    }
    auto attempt = [&](const char* addr) {
        httplib::Request req;
        req.remote_addr = addr;
        PasswordCheckOptions opts;
        opts.lockout_exempt = true;
        opts.metric_route = "login";
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = h.auth_routes->verify_password_with_lockout("admin", "WRONGpassword1", req, opts);
        return std::pair{r.outcome, std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - t0)};
    };
    // A's SECOND request fails fast on its own per-source slot: it never waits for the gate
    // (mutation: the shared gate first -> it waits the full bounded 150 ms before the refusal).
    auto [a_outcome, a_ms] = attempt("203.0.113.5");
    CHECK(a_outcome == PasswordCheckOutcome::kBusy);
    CHECK(a_ms < std::chrono::milliseconds(100));
    // With only three permits held, another source's attempt is served (a normal wrong-password
    // verdict), while A's slot stays held: one source never queues ahead of another.
    held.pop_back();
    auto [b_outcome, b_ms] = attempt("198.51.100.9");
    CHECK(b_outcome == PasswordCheckOutcome::kBadCredential);
}
