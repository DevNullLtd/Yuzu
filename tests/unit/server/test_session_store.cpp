/**
 * test_session_store.cpp -- SessionStore (HA WS-1/1a) behaviour tests.
 *
 * Since the WS-1/1a DB-clock-authority completion (ADR-2002 §4), the store
 * AUTHORS every timestamp from Postgres now() (create takes a DURATION, not an
 * absolute; set_elevation/mark_mfa/touch stamp now()) and find() returns db_now_ms
 * in the same SELECT. These tests assert against the store-RETURNED authored
 * values (never a test-computed wall clock), and the reap clock-anomaly cases
 * poison the persisted anchor directly (reap reads the DB clock itself now).
 *
 * Behind YUZU_TEST_ENABLE_PG (server suite only) — skipped when the DSN is unset.
 */

#include "session_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <cstdlib>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

constexpr std::int64_t k8hMs = 8LL * 3600 * 1000;

SessionWriteParams make_params(std::string hash, std::string user,
                               std::int64_t lifetime_ms = k8hMs) {
    SessionWriteParams p;
    p.token_hash = std::move(hash);
    p.username = std::move(user);
    p.display_name = "Test User";
    p.role = "admin";
    p.auth_source = "local";
    p.principal_kind = "human";
    p.session_lifetime_ms = lifetime_ms;
    return p;
}

// The DB clock in wall-clock epoch-millis (the same expression the store uses).
std::int64_t db_now_ms(PgPool& pool) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(lease.get(), "SELECT (extract(epoch from now())*1000)::bigint",
                             std::vector<std::string>{});
    return std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
}

void set_meta(PgPool& pool, const std::string& key, std::int64_t value) {
    auto lease = pool.acquire();
    pg::exec_params(lease.get(),
                    "INSERT INTO session_store.session_meta (key, value) VALUES ($1, $2) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    std::vector<std::string>{key, std::to_string(value)});
}

// Write a RAW (un-sanitised) string into session_meta — models a hand-edited row,
// a bad migration, or storage corruption writing a non-numeric/negative/overflowed
// anchor. The typed set_meta above cannot express these (#3785).
void set_meta_raw(PgPool& pool, const std::string& key, const std::string& raw_value) {
    auto lease = pool.acquire();
    pg::exec_params(lease.get(),
                    "INSERT INTO session_store.session_meta (key, value) VALUES ($1, $2) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    std::vector<std::string>{key, raw_value});
}

void set_last_activity(PgPool& pool, const std::string& hash, std::int64_t ms) {
    auto lease = pool.acquire();
    pg::exec_params(lease.get(),
                    "UPDATE session_store.sessions SET last_activity_ms=$2::bigint "
                    "WHERE token_hash=$1",
                    std::vector<std::string>{hash, std::to_string(ms)});
}

// Setup constructs the store (runs the migration), then closes all conns.
yuzu::test::PgTestTemplate session_store_tpl{"sessstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SessionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("session_store template: store failed to migrate");
}};

} // namespace

TEST_CASE("SessionStore: create authors from now() and find round-trips every field",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto p = make_params("hash-abc", "alice");
    p.oidc_sub = "sub-123";
    p.mcp_tier = "operator";
    p.mfa_verified_now = true; // local step-up → mfa_verified authored = now()

    auto created = store.create(p);
    REQUIRE(created.has_value());
    // Timestamps are DB-authored: expires = now() + lifetime; mfa/last_activity = now().
    CHECK(created->expires_at_ms == created->db_now_ms + k8hMs);
    CHECK(created->mfa_verified_ms == created->db_now_ms);
    CHECK(created->last_activity_ms == created->db_now_ms);
    CHECK(created->created_at_ms == created->db_now_ms);

    auto got = store.find("hash-abc");
    REQUIRE(got.has_value());  // no DB error
    REQUIRE(got->has_value()); // present
    CHECK((*got)->row.username == "alice");
    CHECK((*got)->row.role == "admin");
    CHECK((*got)->row.oidc_sub == "sub-123");
    CHECK((*got)->row.mcp_tier == "operator");
    CHECK((*got)->row.expires_at_ms == created->expires_at_ms);
    CHECK((*got)->row.mfa_verified_ms == created->mfa_verified_ms);
    CHECK((*got)->db_now_ms >= created->db_now_ms); // the read clock is at/after authoring

    // A definitively-absent read is nullopt, NOT an error (type-distinguishable).
    auto missing = store.find("nope");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());
}

TEST_CASE("SessionStore: mutations bump the durable generation; touch does not",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto g0 = store.read_generation();
    REQUIRE(g0.has_value());

    REQUIRE(store.create(make_params("h1", "bob")).has_value());
    auto g1 = store.read_generation();
    REQUIRE(g1.has_value());
    CHECK(*g1 > *g0); // create bumped

    auto mfa = store.mark_mfa("h1");
    REQUIRE(mfa.has_value());
    REQUIRE(mfa->has_value()); // session existed
    auto g2 = store.read_generation();
    CHECK(*g2 > *g1); // mfa bumped

    // touch_activity is a sliding update — must NOT bump the generation.
    auto touched = store.touch_activity("h1");
    REQUIRE(touched.has_value());
    CHECK(*touched); // existed
    auto g3 = store.read_generation();
    REQUIRE(g3.has_value());
    CHECK(*g3 == *g2);
}

TEST_CASE("SessionStore: elevation authored from now(), clamped to expiry, cleared per-user",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("h1", "carol")).has_value());
    REQUIRE(store.create(make_params("h2", "carol")).has_value());

    auto set = store.set_elevation("h1", 600'000); // 10 min
    REQUIRE(set.has_value());
    REQUIRE(set->has_value()); // a row was updated
    CHECK((*set)->elevation_issued_ms == (*set)->db_now_ms);
    CHECK((*set)->elevated_until_ms == (*set)->db_now_ms + 600'000); // < expiry (+8h): unclamped
    auto row = store.find("h1");
    CHECK((*row)->row.elevated_until_ms == (*set)->elevated_until_ms);
    CHECK((*row)->row.elevation_issued_ms == (*set)->elevation_issued_ms);

    // A duration LONGER than the remaining lifetime is CLAMPED to expires_at (SQL LEAST).
    auto over = store.set_elevation("h2", 100LL * 3600 * 1000); // 100h >> 8h lifetime
    REQUIRE(over.has_value());
    REQUIRE(over->has_value());
    CHECK((*over)->elevated_until_ms == (*over)->expires_at_ms); // clamped to absolute expiry

    // set on a missing session → nullopt (no row updated), not an error.
    auto missing = store.set_elevation("nope", 1000);
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());

    // A grant on an ALREADY-EXPIRED session hits the SQL dead-window guard → nullopt.
    REQUIRE(store.create(make_params("h3", "carol", -1000)).has_value()); // expired at birth
    auto dead = store.set_elevation("h3", 600'000);
    REQUIRE(dead.has_value());
    CHECK_FALSE(dead->has_value());

    // per-user clear clears every elevated session for that user.
    auto cleared = store.clear_user_elevations("carol");
    REQUIRE(cleared.has_value());
    CHECK(*cleared == 2); // h1 + h2 (h3 never elevated)
    CHECK((*store.find("h1"))->row.elevated_until_ms == 0);
}

TEST_CASE("SessionStore: invalidate one and per-user", "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("h1", "dave")).has_value());
    REQUIRE(store.create(make_params("h2", "dave")).has_value());
    REQUIRE(store.create(make_params("h3", "erin")).has_value());

    auto one = store.invalidate("h1");
    REQUIRE(one.has_value());
    CHECK(*one);
    CHECK_FALSE(store.find("h1")->has_value()); // gone

    auto n = store.invalidate_user("dave");
    REQUIRE(n.has_value());
    CHECK(*n == 1);                       // only h2 remained for dave
    CHECK(store.find("h3")->has_value()); // erin untouched
}

TEST_CASE("SessionStore: reap deletes only absolutely-expired sessions",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("live", "frank")).has_value());        // +8h
    REQUIRE(store.create(make_params("dead", "frank", -1000)).has_value()); // already expired

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 1);
    CHECK_FALSE(reaped->clock_anomaly); // a normal accepted pass is not an anomaly
    CHECK(store.find("live")->has_value());
    CHECK_FALSE(store.find("dead")->has_value());
}

TEST_CASE("SessionStore: reap declines an anchor implausibly BEHIND the DB clock (forward skew)",
          "[session_store][pg][retention]") {
    // reap reads the DB clock itself now, so a forward-skew is modelled by a
    // POISONED anchor far in the past: DB now() > anchor + kMaxPlausibleSkewMs.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead2", "gina", -1000)).has_value());
    // Anchor ~2 years behind the DB clock (kMaxPlausibleSkewMs is ~1y).
    set_meta(pool, "reap_anchor_ms", db_now_ms(pool) - 2LL * 366 * 24 * 3600 * 1000);

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly);            // forward-skew decline is a clock anomaly
    CHECK(store.find("dead2")->has_value()); // survived the declined pass
}

TEST_CASE("SessionStore: reap declines an anchor AHEAD of the DB clock (backward/poisoned)",
          "[session_store][pg][retention]") {
    // A DB now() below the highest accepted anchor = the clock moved backward (or
    // the anchor was poisoned forward); the pass must decline, never mass-delete.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead2", "hank", -1000)).has_value());
    // Anchor 1h AHEAD of the DB clock → now_ms < anchor → backward decline.
    set_meta(pool, "reap_anchor_ms", db_now_ms(pool) + 3600LL * 1000);

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly); // backward-skew decline is a clock anomaly
    CHECK(store.find("dead2")->has_value());
}

// #3785: the persisted anchor is a plain key/value string a hand-edit, a bad
// migration, or storage corruption can write anything into. An unparseable,
// negative, or overflowed anchor must be REJECTED as a clock anomaly (decline,
// delete nothing), never parsed by an unchecked strtoll into 0/garbage — on an
// endpoint the user controls, a quiet reset IS the bypass (clock-guarded-
// retention part 3). Each case seeds an already-expired session and asserts the
// pass declines and leaves it intact.
TEST_CASE("SessionStore: reap declines a non-numeric (junk) persisted anchor",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead3", "ivy", -1000)).has_value());
    set_meta_raw(pool, "reap_anchor_ms", "123junk"); // strtoll parses 123, trailing 'junk'

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly);            // unparseable anchor → decline
    CHECK(store.find("dead3")->has_value()); // survived — no delete under a bad anchor
}

TEST_CASE("SessionStore: reap declines a negative persisted anchor",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead4", "jon", -1000)).has_value());
    set_meta_raw(pool, "reap_anchor_ms", "-1000"); // parses cleanly, but negative

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly);            // negative anchor → decline
    CHECK(store.find("dead4")->has_value());
}

TEST_CASE("SessionStore: reap declines an overflowed (out-of-int64) persisted anchor",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead5", "kim", -1000)).has_value());
    // 25 nines > INT64_MAX (~9.2e18): strtoll sets errno=ERANGE. Without the
    // checked parse, `anchor + kMaxPlausibleSkewMs` on this value is signed-
    // overflow UB — this case is the regression net for that fix.
    set_meta_raw(pool, "reap_anchor_ms", "9999999999999999999999999");

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly);            // overflowed anchor → decline
    CHECK(store.find("dead5")->has_value());
}

TEST_CASE("SessionStore: reap declines an empty-string persisted anchor (NULL-column analogue)",
          "[session_store][pg][retention]") {
    // An empty value is what libpq surfaces for a SQL NULL column, and what a
    // botched write can leave behind. `has_anchor` is true (the row exists) but
    // parse_reap_i64("") rejects it → decline, never a quiet fallback to 0.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("dead6", "leo", -1000)).has_value());
    set_meta_raw(pool, "reap_anchor_ms", ""); // empty value present under the key

    auto reaped = store.reap_expired();
    REQUIRE(reaped.has_value());
    CHECK(reaped->deleted == 0);
    CHECK(reaped->clock_anomaly);            // empty anchor → decline
    CHECK(store.find("dead6")->has_value());
}

TEST_CASE("SessionStore: touch_activity is monotonic — a now() stamp never regresses last_activity",
          "[session_store][pg]") {
    // GREATEST() so a now()-stamp on this replica cannot move the idle anchor
    // backward past a newer value written by another (forward) writer.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create(make_params("h", "ivy")).has_value());

    // Force last_activity to the FUTURE (as if a forward writer stamped it), then
    // touch (which stamps the DB clock, i.e. ~now, well below the future value):
    // GREATEST must keep the future value, not regress to now().
    const std::int64_t future = db_now_ms(pool) + 60'000;
    set_last_activity(pool, "h", future);
    REQUIRE(store.touch_activity("h").has_value());
    CHECK((*store.find("h"))->row.last_activity_ms == future); // NOT regressed
}

// ── #2343: the v2 migration and the principal_kind CHECK ─────────────────────────────────────

namespace {
// A raw row insert that bypasses SessionStore::create (which only ever writes the values its
// callers pass), modelling a hand-edited or foreign-written durable row. Returns the SQLSTATE
// of a failed insert, or "" on success, so a rejection is attributable to the CHECK (23514)
// and not to any other failure.
std::string insert_raw_session(PgPool& pool, const std::string& hash,
                               const std::string& auth_source, const std::string& kind) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(
        lease.get(),
        "INSERT INTO session_store.sessions (token_hash, username, role, auth_source, "
        "principal_kind, created_at_ms, expires_at_ms, last_activity_ms) "
        "VALUES ($1, 'raw-user', 'admin', $2, $3, 1, 9999999999999, 1)",
        std::vector<std::string>{hash, auth_source, kind});
    if (r.status() == PGRES_COMMAND_OK)
        return "";
    const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return state ? state : "no-sqlstate";
}

std::int64_t write_generation(PgPool& pool) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(lease.get(),
                             "SELECT value FROM session_store.session_meta "
                             "WHERE key = 'write_generation'",
                             std::vector<std::string>{});
    return PQntuples(r.get()) == 1 ? std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10) : -1;
}
constexpr const char* kCheckViolation = "23514";
} // namespace

TEST_CASE("SessionStore v2: the CHECK admits exactly a human session or an engine_token engine "
          "session",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    SessionStore store{pool};
    REQUIRE(store.is_open());

    // The split state the constraint exists to make unrepresentable, and its mirror.
    CHECK(insert_raw_session(pool, "split", "engine_token", "human") == kCheckViolation);
    CHECK(insert_raw_session(pool, "cookie-engine", "local", "engine") == kCheckViolation);
    // Kinds outside {human, engine}, including a case variant a string compare would miss.
    CHECK(insert_raw_session(pool, "empty", "local", "") == kCheckViolation);
    CHECK(insert_raw_session(pool, "case", "local", "Engine") == kCheckViolation);
    CHECK(insert_raw_session(pool, "unknown", "oidc", "service") == kCheckViolation);
    // What the server really writes, plus the one consistent engine pairing.
    CHECK(insert_raw_session(pool, "ok-local", "local", "human").empty());
    CHECK(insert_raw_session(pool, "ok-oidc", "oidc", "human").empty());
    CHECK(insert_raw_session(pool, "ok-saml", "saml", "human").empty());
    CHECK(insert_raw_session(pool, "ok-engine", "engine_token", "engine").empty());
}

TEST_CASE("SessionStore v2: upgrading a v1 database removes the inconsistent rows, keeps the rest, "
          "replaces a hand-applied constraint, bumps the generation and leaves the constraint in "
          "force",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        SessionStore fresh{pool};
        REQUIRE(fresh.is_open());
        REQUIRE(fresh.create(make_params("keep-human", "alice")).has_value());
    }
    // Rewind to a v1 database: schema_meta at 1 and no constraint, then plant the rows only a
    // hand edit could produce, and a constraint of the SAME NAME with a weaker body, as an
    // operator who applied it by hand would leave behind (without DROP ... IF EXISTS the v2
    // ADD would fail with 42710 and refuse boot on every restart).
    {
        auto lease = pool.acquire();
        REQUIRE(pg::exec_params(lease.get(),
                                "ALTER TABLE session_store.sessions DROP CONSTRAINT "
                                "sessions_principal_kind_consistent",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(lease.get(),
                                "UPDATE public.schema_meta SET version = 1 "
                                "WHERE store = 'session_store'",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    REQUIRE(insert_raw_session(pool, "bad-split", "engine_token", "human").empty());
    REQUIRE(insert_raw_session(pool, "bad-kind", "local", "Engine").empty());
    REQUIRE(insert_raw_session(pool, "bad-cookie-engine", "oidc", "engine").empty());
    REQUIRE(insert_raw_session(pool, "keep-engine", "engine_token", "engine").empty());
    {
        auto lease = pool.acquire();
        REQUIRE(pg::exec_params(lease.get(),
                                "ALTER TABLE session_store.sessions ADD CONSTRAINT "
                                "sessions_principal_kind_consistent CHECK (true)",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    const std::int64_t gen_before = write_generation(pool);

    SessionStore upgraded{pool}; // runs v2
    REQUIRE(upgraded.is_open());

    auto present = [&](const char* hash) {
        auto got = upgraded.find(hash);
        REQUIRE(got.has_value());
        return got->has_value();
    };
    CHECK_FALSE(present("bad-split"));
    CHECK_FALSE(present("bad-kind"));
    CHECK_FALSE(present("bad-cookie-engine"));
    CHECK(present("keep-human"));
    CHECK(present("keep-engine"));
    // The weaker same-name constraint was replaced, so the same hand edit is refused now.
    CHECK(insert_raw_session(pool, "again", "engine_token", "human") == kCheckViolation);
    // A peer replica's validate cache drops the deleted rows on its next generation poll.
    CHECK(write_generation(pool) > gen_before);
}
