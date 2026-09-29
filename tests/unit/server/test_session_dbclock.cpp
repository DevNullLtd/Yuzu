/**
 * test_session_dbclock.cpp -- HA WS-1/1a DB-clock authority (ADR-2002 §4, #3715).
 *
 * Proves the security properties the pre-implementation design review fixed:
 *   - H2: the elevation/MFA/base ceilings CLAMP the DERIVED remaining, so a
 *     backward authority clock cannot inflate the LIVED duration past the
 *     authored maximum (a stored-width check alone would pass while the session
 *     lived far beyond it).
 *   - H4: an already-expired-at-populate session fails closed (no near-infinite
 *     deadline from signed underflow).
 *   - §4(b): an over-kMaxElevationWindow authored width, or a future-dated MFA
 *     proof (a backward step below the grant/proof instant), is REJECTED.
 *   - Cross-replica: a session's timestamps are authored from the ONE DB clock
 *     (Postgres now()), so any replica dates and adjudicates it identically.
 *
 * The derive_session_deadlines cases are pure (no PG). The authorship case is
 * behind YUZU_TEST_ENABLE_PG (server suite only) — skipped when the DSN is unset.
 */

#include "session_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

using yuzu::server::pg::PgPool;
using yuzu::server::SessionStore;
using yuzu::server::SessionWriteParams;
using Mgr = yuzu::server::auth::AuthManager;
using yuzu::server::auth::is_elevated;
using yuzu::server::auth::kMaxElevationWindow;
using yuzu::server::auth::Session;

namespace {

std::int64_t wall_ms_now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t steady_ms_now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::int64_t steady_ms(std::chrono::steady_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

constexpr std::int64_t kHourMs = 3600LL * 1000;
constexpr std::int64_t k8hMs = 8 * kHourMs;

} // namespace

TEST_CASE("dbclock: base lifetime clamps a backward authority clock (H2/H4)", "[session_dbclock]") {
    // A session created at T0 with an 8h lifetime, adjudicated at an authority
    // clock that has stepped BACKWARD below creation. remaining must be the
    // authored lifetime (clamped by max(now, created)), NOT expires - now (which
    // a lower `now` would inflate).
    const std::int64_t created = wall_ms_now();
    const std::int64_t expires = created + k8hMs;

    Session s;
    // now stepped 2h BELOW creation.
    REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0, 0, 0,
                                           created - 2 * kHourMs));
    const std::int64_t rem = steady_ms(s.steady_expires) - steady_ms_now();
    // Clamped to the authored 8h, never expires-now (= 10h under the backward step).
    CHECK(rem <= k8hMs);
    CHECK(rem > k8hMs - 5000); // ~8h, within a few seconds of scheduling slack
}

TEST_CASE("dbclock: a corrupted far-future base lifetime is REJECTED (K1/UP-12 ceiling)",
          "[session_dbclock]") {
    // A durable expires_at corrupted far past the fixed 8h authored lifetime (the
    // partial-row-corruption class the elevation §4b width-reject also defends) is
    // REJECTED outright, not honored — and the wall backstop cannot catch it (it
    // is anchored to the same corrupted instant). Mirrors is_elevated's ceiling.
    const std::int64_t created = wall_ms_now();
    Session s;
    // width = 100 days >> the 7d kMaxSessionLifetime bound.
    const std::int64_t corrupt_expires = created + 100LL * 24 * kHourMs;
    CHECK_FALSE(Mgr::derive_session_deadlines(s, created, corrupt_expires, created, 0, 0, 0, created));
    CHECK(s.steady_expires.time_since_epoch().count() == 0); // fail-closed sentinel
    // A legitimate 8h session at the same instant is honored.
    Session ok;
    REQUIRE(Mgr::derive_session_deadlines(ok, created, created + k8hMs, created, 0, 0, 0, created));
    CHECK(ok.steady_expires.time_since_epoch().count() != 0);
}

TEST_CASE("dbclock: an already-expired session fails closed (H4 underflow guard)",
          "[session_dbclock]") {
    const std::int64_t created = wall_ms_now();
    const std::int64_t expires = created + k8hMs;
    Session s;
    // Authority clock is PAST the absolute expiry.
    CHECK_FALSE(Mgr::derive_session_deadlines(s, created, expires, created, 0, 0, 0,
                                               expires + 1000));
    // {} steady_expires reads as expired (never a near-infinite deadline).
    CHECK(s.steady_expires.time_since_epoch().count() == 0);
}

TEST_CASE("dbclock: elevation ceiling rejects over-width, clamps the derived remaining (H2/§4b)",
          "[session_dbclock]") {
    const std::int64_t created = wall_ms_now();
    const std::int64_t expires = created + k8hMs;
    const std::int64_t kMaxMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(kMaxElevationWindow).count();

    SECTION("a normal 10-min grant is elevated") {
        Session s;
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0,
                                               created + 600'000, created, created));
        CHECK(is_elevated(s));
        CHECK(steady_ms(s.steady_elevated_until) - steady_ms_now() <= 600'000);
    }
    SECTION("an authored width wider than kMaxElevationWindow is REJECTED, not clamped") {
        Session s;
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0,
                                               created + kMaxMs + kHourMs, created, created));
        CHECK_FALSE(is_elevated(s)); // zero admin, not a capped 24h
    }
    SECTION("a future-issued grant (backward step below the grant instant) is REJECTED") {
        Session s;
        // now is BEFORE elevation_issued → not elevated.
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0,
                                               created + 600'000, created, created - 60'000));
        CHECK_FALSE(is_elevated(s));
    }
    SECTION("a backward now (>= issued) cannot inflate the lived window past the authored width") {
        Session s;
        // Grant issued at created for 10 min; authority clock stepped back to
        // created (below the real 'now'). remaining is bounded by the width.
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0,
                                               created + 600'000, created, created));
        CHECK(steady_ms(s.steady_elevated_until) - steady_ms_now() <= 600'000);
    }
}

TEST_CASE("dbclock: a future-dated MFA proof is treated as no proof (backward step)",
          "[session_dbclock]") {
    const std::int64_t created = wall_ms_now();
    const std::int64_t expires = created + k8hMs;

    SECTION("a proof stamped AFTER the authority clock → {} (no usable proof)") {
        Session s;
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created,
                                               /*mfa*/ created + 60'000, 0, 0, /*now*/ created));
        CHECK(s.steady_mfa_verified.time_since_epoch().count() == 0);
    }
    SECTION("a normal past proof → an aged steady anchor") {
        Session s;
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created,
                                               /*mfa*/ created - 300'000, 0, 0, /*now*/ created));
        CHECK(s.steady_mfa_verified.time_since_epoch().count() != 0);
        // ~5 min of age already accrued at populate.
        CHECK(steady_ms_now() - steady_ms(s.steady_mfa_verified) >= 300'000 - 5000);
    }
    SECTION("no proof (mfa=0) → {}") {
        Session s;
        REQUIRE(Mgr::derive_session_deadlines(s, created, expires, created, 0, 0, 0, created));
        CHECK(s.steady_mfa_verified.time_since_epoch().count() == 0);
    }
}

TEST_CASE("dbclock: create authors every timestamp from the ONE DB clock (cross-replica)",
          "[session_dbclock][pg]") {
    // The cross-host-skew fix: expires/created/last_activity are authored from
    // Postgres now(), so they are in the DB clock domain regardless of which
    // replica issued the login — the RETURNED db_now_ms is that single clock.
    YUZU_REQUIRE_PG_DB(dbh);
    PgPool pool{{.conninfo = dbh.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    SessionWriteParams p;
    p.token_hash = "dbclock-hash";
    p.username = "alice";
    p.role = "admin";
    p.session_lifetime_ms = k8hMs;

    auto created = store.create(p);
    REQUIRE(created.has_value());
    // Authored, not caller-supplied: every stamp is the DB now() (± the lifetime).
    CHECK(created->created_at_ms == created->db_now_ms);
    CHECK(created->last_activity_ms == created->db_now_ms);
    CHECK(created->expires_at_ms == created->db_now_ms + k8hMs);

    // A second replica (a fresh find) reads the SAME authored absolutes and its
    // own db_now — the read clock is monotonic-forward vs the author clock.
    auto found = store.find("dbclock-hash");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->row.expires_at_ms == created->expires_at_ms);
    CHECK((*found)->db_now_ms >= created->db_now_ms);
}
