/**
 * test_auth_session_store.cpp -- AuthManager ↔ durable SessionStore integration
 * (HA WS-1/1a, ADR-2002 §4).
 *
 * Exercises the store-backed AuthManager path: sessions written through to
 * Postgres, validated against it, and surviving on a FRESH AuthManager that
 * shares the same store — the stand-in for a second core replica / a restart
 * (the in-memory cache is cold there, so validation reads the durable row).
 *
 * A separate AuthManager with no store wired keeps the legacy in-memory path;
 * that is covered by test_auth_jit_elevation / test_mfa_step_up. Behind
 * YUZU_TEST_ENABLE_PG (server suite only) — skipped when the DSN is unset.
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp> // Config (for the /logout route-sink harness)

#include "auth_routes.hpp"    // AuthRoutes — the /logout route under test (#3716)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "session_store.hpp"
#include "test_route_sink.hpp" // in-process HttpRouteSink (no socket — TSan-safe, #438)

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

using yuzu::server::AuthRoutes;
using yuzu::server::Config;
using yuzu::server::SessionStore;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::effective_role;
using yuzu::server::auth::is_elevated;
using yuzu::server::auth::Role;
using yuzu::server::pg::PgPool;

namespace {

// Setup constructs the store (runs the migration), then closes all conns.
yuzu::test::PgTestTemplate authsess_tpl{"authsess", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SessionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("authsess template: store failed to migrate");
}};

// A store-backed AuthManager with no config file / AuthDB — just the session
// store, which is all the session lifecycle needs.
std::unique_ptr<AuthManager> make_mgr(SessionStore& store) {
    auto mgr = std::make_unique<AuthManager>();
    mgr->set_session_store(&store);
    return mgr;
}

// A store-backed AuthManager with a config file behind it, so user-management
// methods (upsert_user/update_role/remove_user) work in the config-file path.
std::unique_ptr<AuthManager> make_mgr_with_config(SessionStore& store) {
    auto mgr = std::make_unique<AuthManager>();
    auto cfg = yuzu::test::unique_temp_path("yuzu_test_authsess_");
    cfg += ".cfg";
    std::filesystem::create_directories(cfg.parent_path());
    std::filesystem::remove(cfg);
    mgr->load_config(cfg);
    mgr->set_session_store(&store);
    return mgr;
}

// A minimal AuthRoutes wired against a store-backed AuthManager and an
// in-process TestRouteSink, for the /logout route-sink test (#3716). Only the
// session store is real (so a fault-inject can force invalidate_session to
// fail); every other store is null — audit_log and emit_event both null-guard
// their store, and /logout dereferences nothing else. Member order is
// load-bearing: `routes` is declared BEFORE `sink` so the handlers the sink
// captures (which hold `routes`' `this`) outlive the sink on teardown
// (test_route_sink.hpp invariant #1).
struct LogoutHarness {
    Config cfg{};
    std::unique_ptr<AuthManager> mgr;
    std::shared_mutex oidc_mu;
    std::unique_ptr<yuzu::server::oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> routes;
    yuzu::server::test::TestRouteSink sink;

    explicit LogoutHarness(SessionStore& store) : mgr(make_mgr(store)) {
        cfg.https_enabled = false; // no `Secure` cookie suffix to reason about
        routes = std::make_unique<AuthRoutes>(cfg, *mgr, /*rbac=*/nullptr,
                                              /*api_token=*/nullptr, /*audit=*/nullptr,
                                              /*mgmt_group=*/nullptr, /*tag=*/nullptr,
                                              /*analytics=*/nullptr, oidc_mu, oidc_provider);
        routes->register_routes(sink);
    }
};

// A Cookie header carrying the session token; add HX-Request for the HTMX arm.
std::unordered_map<std::string, std::string> cookie_hdrs(const std::string& token, bool htmx) {
    std::unordered_map<std::string, std::string> h{{"Cookie", "yuzu_session=" + token}};
    if (htmx)
        h["HX-Request"] = "true";
    return h;
}

// Fault-inject: drop the durable schema so the next store op (DELETE / find /
// read_generation) fails — the standing pattern in this file's revoke tests.
void drop_session_schema(PgPool& pool) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                  std::vector<std::string>{});
}

} // namespace

TEST_CASE("AuthManager+SessionStore: create_local_session → validate round-trips",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto mgr = make_mgr(store);
    REQUIRE(mgr->is_session_store_ok());

    auto token = mgr->create_local_session("alice", Role::admin, /*mfa_verified=*/true);
    REQUIRE_FALSE(token.empty());

    auto s = mgr->validate_session(token);
    REQUIRE(s.has_value());
    CHECK(s->username == "alice");
    CHECK(s->role == Role::admin);
    CHECK(effective_role(*s) == Role::admin);
    CHECK(s->auth_source == "local");
    // MFA proof was seeded — the wall-clock timestamp round-trips as non-sentinel.
    CHECK(s->mfa_verified_at.time_since_epoch().count() != 0);

    // The raw token is NEVER the store row key (secret-at-rest): the durable row
    // is keyed by the SHA-256 hash, so a find on the raw token misses.
    auto by_raw = store.find(token);
    REQUIRE(by_raw.has_value());
    CHECK_FALSE(by_raw->has_value());
}

TEST_CASE("AuthManager+SessionStore: a session survives on a fresh replica",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("bob", Role::user, /*mfa_verified=*/false);
    REQUIRE_FALSE(token.empty());

    // A fresh AuthManager sharing the same store = a second replica / a restart:
    // its cache is cold, so validation must read the durable row.
    auto b = make_mgr(store);
    auto s = b->validate_session(token);
    REQUIRE(s.has_value());
    CHECK(s->username == "bob");
    CHECK(s->role == Role::user);
}

TEST_CASE("AuthManager+SessionStore: elevation persists and is honored on a fresh replica",
          "[auth][session_store][pg][jit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("carol", Role::user, /*mfa_verified=*/true);
    REQUIRE_FALSE(token.empty());

    // Base role is user until elevated.
    CHECK(effective_role(*a->validate_session(token)) == Role::user);

    auto until = a->elevate_session(token, std::chrono::seconds(120));
    REQUIRE(until.has_value());

    // Reflected on the SAME manager…
    {
        auto s = a->validate_session(token);
        REQUIRE(s.has_value());
        CHECK(is_elevated(*s));
        CHECK(effective_role(*s) == Role::admin);
    }
    // …and on a FRESH replica: the elevation + its issued-at anchor round-trip
    // through the durable row, so the kMaxElevationWindow ceiling still admits
    // the (120s) window and is_elevated holds.
    {
        auto b = make_mgr(store);
        auto s = b->validate_session(token);
        REQUIRE(s.has_value());
        CHECK(is_elevated(*s));
        CHECK(effective_role(*s) == Role::admin);
    }

    // Revoke on A → the fresh replica no longer sees an elevation.
    CHECK(a->revoke_elevation(token).value_or(false));
    {
        auto c = make_mgr(store);
        auto s = c->validate_session(token);
        REQUIRE(s.has_value());
        CHECK_FALSE(is_elevated(*s));
        CHECK(effective_role(*s) == Role::user);
    }
}

TEST_CASE("AuthManager+SessionStore: invalidate deletes the durable session",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("dave", Role::admin, /*mfa_verified=*/true);
    REQUIRE(a->validate_session(token).has_value());

    CHECK(a->invalidate_session(token)); // happy path: durable delete persisted
    // Gone on A (local cache + durable row erased)…
    CHECK_FALSE(a->validate_session(token).has_value());
    // …and on a fresh replica (the durable row is deleted).
    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(token).has_value());
}

TEST_CASE("AuthManager+SessionStore: invalidate_user_sessions kills every device",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto t1 = a->create_local_session("erin", Role::user, false);
    auto t2 = a->create_local_session("erin", Role::user, false);
    auto other = a->create_local_session("frank", Role::user, false);

    auto res = a->invalidate_user_sessions("erin");
    CHECK(res.db_persisted);
    CHECK(res.count == 2);

    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(t1).has_value());
    CHECK_FALSE(b->validate_session(t2).has_value());
    CHECK(b->validate_session(other).has_value()); // frank untouched
}

TEST_CASE("AuthManager+SessionStore: a role change durably wipes the user's sessions",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr_with_config(store);
    REQUIRE(a->upsert_user("gina", "secret123456", Role::user));
    auto token = a->create_local_session("gina", Role::user, false);
    REQUIRE(a->validate_session(token).has_value());

    // Promote gina → the stale-role session must not survive on any replica:
    // wipe_user_sessions_durable deletes the durable rows (fail-closed on error).
    REQUIRE(a->update_role("gina", Role::admin));
    CHECK_FALSE(a->validate_session(token).has_value());
    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(token).has_value()); // gone fleet-wide
}

TEST_CASE("AuthManager+SessionStore: a durable-clear failure fails revoke CLOSED, not false-ok",
          "[auth][session_store][pg][jit]") {
    // Adversarial C2: a durable elevation-clear that fails must be
    // type-distinguishable from a legitimate no-op, so the route fails closed
    // instead of auditing a false revocation while the elevation stays live.
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("jack", Role::user, /*mfa_verified=*/true);
    REQUIRE(a->elevate_session(token, std::chrono::seconds(120)).has_value());
    REQUIRE(is_elevated(*a->validate_session(token))); // live elevation, cached on `a`

    // Fault-inject: drop the schema so the durable clear_elevation UPDATE fails.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                      std::vector<std::string>{});
    }

    // revoke_elevation must return `unexpected` (a store error), NOT expected(false)
    // (a successful no-op). value_or(false) would mask it; assert on has_value().
    auto rev = a->revoke_elevation(token);
    CHECK_FALSE(rev.has_value()); // fail closed — the elevation is still live durably

    // revoke_user_elevations likewise surfaces the failure, not a false "0 cleared".
    auto rvu = a->revoke_user_elevations("jack");
    CHECK_FALSE(rvu.has_value());
}

TEST_CASE("AuthManager+SessionStore: a failed single-session invalidate reports db_persisted=false",
          "[auth][session_store][pg]") {
    // Adversarial-round #2 C2/C3 / PR #3702 blocker #3: a logout whose durable
    // delete fails must NOT report a clean logout — invalidate_session returns
    // false so /logout can fail closed (keep the cookie, 503) rather than clear
    // the cookie over a still-valid durable session.
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("kate", Role::user, /*mfa_verified=*/false);
    REQUIRE(a->validate_session(token).has_value());

    // Fault-inject: drop the schema so the durable DELETE fails.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                      std::vector<std::string>{});
    }
    CHECK_FALSE(a->invalidate_session(token)); // db_persisted=false — logout must fail closed
}

// ── #3716 deferred coverage ───────────────────────────────────────────────────

TEST_CASE("AuthRoutes /logout: success clears the cookie; a durable-delete failure fails CLOSED "
          "on BOTH HTMX and non-HTMX (#3716)",
          "[auth][session_store][pg][logout]") {
    // The route wrapper for the invalidate_session()==false fail-closed fix
    // (adversarial-round #2, C2): on a durable-delete failure /logout must keep
    // the cookie (still signed in), NOT emit an HX-Redirect, and return 503 on
    // BOTH surfaces — never a clean 200 that clears the cookie over a session
    // that still rehydrates on another replica. test_auth_session_store's
    // db_persisted=false case covers the AuthManager return; this covers the
    // HTTP handler that consumes it.
    //
    // Content-type is irrelevant here (the handler reads the Cookie + HX-Request
    // headers, not a form body), so the #1786 urlencoded-vs-json trap does not
    // arise; the branch is selected by the HX-Request header alone.
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    LogoutHarness h{store};

    SECTION("success — HTMX: cookie cleared + HX-Redirect to /login") {
        auto tok = h.mgr->create_local_session("htmx-ok", Role::user, /*mfa=*/false);
        auto res = h.sink.dispatch("POST", "/logout", "", "application/json", cookie_hdrs(tok, true));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("HX-Redirect") == "/login");
        CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") != std::string::npos);
        CHECK_FALSE(h.mgr->validate_session(tok).has_value()); // durable row gone
    }

    SECTION("success — non-HTMX: cookie cleared + {\"status\":\"ok\"}") {
        auto tok = h.mgr->create_local_session("json-ok", Role::user, /*mfa=*/false);
        auto res = h.sink.dispatch("POST", "/logout", "", "application/json", cookie_hdrs(tok, false));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("\"status\":\"ok\"") != std::string::npos);
        CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") != std::string::npos);
        CHECK_FALSE(h.mgr->validate_session(tok).has_value());
    }

    SECTION("durable-delete failure — HTMX fails CLOSED (503, cookie kept, no redirect)") {
        auto tok = h.mgr->create_local_session("htmx-degrade", Role::user, /*mfa=*/false);
        REQUIRE(h.mgr->validate_session(tok).has_value());
        drop_session_schema(pool); // the DELETE inside invalidate_session now fails
        auto res = h.sink.dispatch("POST", "/logout", "", "application/json", cookie_hdrs(tok, true));
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("HX-Redirect").empty());  // no false clean-logout redirect
        CHECK(res->get_header_value("Set-Cookie").empty());   // cookie KEPT — still signed in
        CHECK(res->body.find("still signed in") != std::string::npos);
    }

    SECTION("durable-delete failure — non-HTMX fails CLOSED (503, cookie kept, partial)") {
        auto tok = h.mgr->create_local_session("json-degrade", Role::user, /*mfa=*/false);
        REQUIRE(h.mgr->validate_session(tok).has_value());
        drop_session_schema(pool);
        auto res = h.sink.dispatch("POST", "/logout", "", "application/json", cookie_hdrs(tok, false));
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Set-Cookie").empty()); // cookie KEPT
        CHECK(res->body.find("\"status\":\"partial\"") != std::string::npos);
    }
}

TEST_CASE("AuthManager+SessionStore: the validate cache is trusted only after the generation view "
          "is confirmed — unconfirmed fails CLOSED; confirmed rides a brownout (#3716)",
          "[auth][session_store][pg]") {
    // The generation-gated validate cache (mirrors rbac_store). Two halves of
    // the stale-serve trust gate, both deterministic without a wall-clock sleep:
    //   * a CONFIRMED generation view keeps serving the cached session through a
    //     PG brownout (up to kSessionGenStaleServeBoundMs) — the whole point of
    //     the bounded cache;
    //   * an UNCONFIRMED view (no successful read_generation yet) is NEVER
    //     trusted, so a cached session is withheld and validate fails closed on
    //     the authoritative path.
    // The numeric 30s ELAPSED bound (a confirmed view going stale purely by time
    // passing) needs an injectable clock to test without a real sleep; that leg
    // is deferred (see #3716 / #3715) — the security-relevant trust gate is the
    // pair below.
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    SECTION("confirmed view rides a PG brownout within the stale-serve bound") {
        auto a = make_mgr(store);
        auto tok = a->create_local_session("kate", Role::user, /*mfa=*/false);
        // First validate on a healthy store CONFIRMS the generation view and
        // re-caches the row (session_gen_valid_ = true, anchor = now).
        REQUIRE(a->validate_session(tok).has_value());
        // Brownout: the durable store vanishes. Well within the stale-serve
        // bound the confirmed view is still trusted, so the cached session is
        // served WITHOUT the store — a cache hit, not an authoritative read.
        drop_session_schema(pool);
        // Self-verify the fault-inject actually took effect. This is the ONE
        // section a silently no-op DROP (schema rename, permission drift) would
        // false-green: with the store still healthy the second validate would
        // succeed via an AUTHORITATIVE read rather than the cache, so without
        // this the section could pass without exercising stale-serve at all (the
        // degrade/unconfirmed sections instead go RED on a no-op DROP, so they
        // self-report). Timing note: a >30s STEADY-clock stall between the two
        // validates (an oversubscribed shared runner, a sanitizer pause) can
        // legitimately age the confirmed view past kSessionGenStaleServeBoundMs
        // and turn this into the authoritative path — a bounded, low-probability
        // false-red inherent to testing a 30s bound without an injectable clock
        // (that numeric leg is deferred with #3716 / #3715).
        REQUIRE_FALSE(store.read_generation().has_value()); // schema is really gone
        CHECK(a->validate_session(tok).has_value());
    }

    SECTION("unconfirmed view is never trusted — a cached session fails closed") {
        auto a = make_mgr(store);
        // create_local_session caches the row but does NOT confirm the
        // generation view (no read_generation), so session_gen_valid_ stays
        // false. The row sits in this manager's cache.
        auto tok = a->create_local_session("nick", Role::user, /*mfa=*/false);
        // Degrade before any validate confirms the view. An unconfirmed view is
        // distrusted, so validate bypasses the (populated) cache, goes
        // authoritative, and fails closed on the degraded store — proving the
        // cache is not served under an unconfirmed generation view (a trusted
        // cache would have returned the session without touching the store).
        drop_session_schema(pool);
        CHECK_FALSE(a->validate_session(tok).has_value());
    }
}
