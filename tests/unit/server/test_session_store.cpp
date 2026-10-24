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
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

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

// One statement on a pooled lease; true on COMMAND_OK / TUPLES_OK.
bool exec_ok(PgPool& pool, const std::string& sql, std::vector<std::string> params = {}) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(lease.get(), sql.c_str(), params);
    return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
}

std::string scalar(PgPool& pool, const std::string& sql, std::vector<std::string> params = {}) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(lease.get(), sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return "<err>";
    return PQgetvalue(r.get(), 0, 0);
}

// The stored proof columns of one row, read straight from the table.
struct StoredProof {
    std::int64_t ms{-1};
    std::int64_t gen{-1};
    std::int64_t seq{-1};
};
StoredProof stored_proof(PgPool& pool, const std::string& hash) {
    auto lease = pool.acquire();
    auto r = pg::exec_params(lease.get(),
                             "SELECT mfa_verified_ms, mfa_factor_gen, mfa_bind_seq "
                             "FROM session_store.sessions WHERE token_hash=$1",
                             std::vector<std::string>{hash});
    StoredProof p;
    if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1) {
        p.ms = std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
        p.gen = std::strtoll(PQgetvalue(r.get(), 0, 1), nullptr, 10);
        p.seq = std::strtoll(PQgetvalue(r.get(), 0, 2), nullptr, 10);
    }
    return p;
}

// origin/dev's (pre-binding) statement texts, verbatim: what a legacy binary sharing the
// schema during a rolling upgrade or rollback still runs. They name none of the v3
// columns, so they exercise the rebind guard exactly as that binary would.
constexpr const char* kLegacyInsert =
    "INSERT INTO session_store.sessions ("
    "token_hash, username, display_name, role, auth_source, oidc_sub, token_scope_service, "
    "mcp_tier, principal_kind, created_at_ms, expires_at_ms, last_activity_ms, "
    "mfa_verified_ms, elevated_until_ms, elevation_issued_ms) "
    "SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9, n.ms, n.ms + $10::bigint, n.ms, "
    "CASE WHEN $11::bool THEN n.ms ELSE $12::bigint END, 0, 0 "
    "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
    "ON CONFLICT (token_hash) DO UPDATE SET "
    "username=EXCLUDED.username, display_name=EXCLUDED.display_name, role=EXCLUDED.role, "
    "auth_source=EXCLUDED.auth_source, oidc_sub=EXCLUDED.oidc_sub, "
    "token_scope_service=EXCLUDED.token_scope_service, mcp_tier=EXCLUDED.mcp_tier, "
    "principal_kind=EXCLUDED.principal_kind, created_at_ms=EXCLUDED.created_at_ms, "
    "expires_at_ms=EXCLUDED.expires_at_ms, last_activity_ms=EXCLUDED.last_activity_ms, "
    "mfa_verified_ms=EXCLUDED.mfa_verified_ms, elevated_until_ms=EXCLUDED.elevated_until_ms, "
    "elevation_issued_ms=EXCLUDED.elevation_issued_ms "
    "RETURNING created_at_ms";
constexpr const char* kLegacyMarkMfa =
    "UPDATE session_store.sessions s SET mfa_verified_ms = n.ms "
    "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
    "WHERE s.token_hash = $1 RETURNING s.mfa_verified_ms";

std::vector<std::string> legacy_insert_params(const std::string& hash, const std::string& user,
                                              bool stamp_now, std::int64_t abs_ms,
                                              const std::string& auth_source = "local") {
    return {hash,
            user,
            "Legacy",
            "admin",
            auth_source,
            "",
            "",
            "",
            "human",
            std::to_string(k8hMs),
            stamp_now ? "true" : "false",
            std::to_string(abs_ms)};
}

// The rebind-guard trigger exactly as migration v3 defines it (an independent copy of
// the pinned body: the validation compares the catalog against the store's constant, so
// if the two ever drift this repair stops matching and the open checks below fail).
constexpr const char* kGuardBody = "\nBEGIN\n"
                                   "  IF NOT (NEW.mfa_bind_seq > OLD.mfa_bind_seq) THEN\n"
                                   "    NEW.mfa_factor_gen := 0;\n"
                                   "  END IF;\n"
                                   "  RETURN NEW;\n"
                                   "END ";

// Put the guard back exactly as the migration made it.
bool repair_guard(PgPool& pool) {
    return exec_ok(pool,
                   "DROP TRIGGER IF EXISTS sessions_mfa_rebind_guard ON session_store.sessions") &&
           exec_ok(pool, std::string(
                             "CREATE OR REPLACE FUNCTION session_store.sessions_mfa_rebind_guard() "
                             "RETURNS trigger LANGUAGE plpgsql AS $$") +
                             kGuardBody + "$$") &&
           exec_ok(pool,
                   "CREATE TRIGGER sessions_mfa_rebind_guard BEFORE UPDATE OF mfa_verified_ms, "
                   "mfa_factor_gen, username, auth_source, principal_kind ON "
                   "session_store.sessions FOR EACH ROW EXECUTE FUNCTION "
                   "session_store.sessions_mfa_rebind_guard()") &&
           exec_ok(pool, "ALTER TABLE session_store.sessions ENABLE ALWAYS TRIGGER "
                         "sessions_mfa_rebind_guard");
}

std::string guard_tgenabled(PgPool& pool) {
    return scalar(pool,
                  "SELECT t.tgenabled FROM pg_trigger t WHERE t.tgrelid = "
                  "'session_store.sessions'::regclass AND t.tgname = 'sessions_mfa_rebind_guard'");
}

bool role_is_superuser(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        return false;
    PgResult r{PQexec(conn.get(), "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")};
    return r.ok() && PQntuples(r.get()) == 1 && std::string(PQgetvalue(r.get(), 0, 0)) == "t";
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
    const std::int64_t proof_ms = db_now_ms(pool) - 1'000;
    p.local_mfa = {0, proof_ms}; // local step-up: the carried instant is stored as given

    auto created = store.create(p);
    REQUIRE(created.has_value());
    // Timestamps are DB-authored: expires = now() + lifetime; last_activity = now(); the MFA
    // instant is the carried one.
    CHECK(created->expires_at_ms == created->db_now_ms + k8hMs);
    CHECK(created->mfa_verified_ms == proof_ms);
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

    auto mfa = store.mark_mfa("h1", {0, db_now_ms(pool) - 1'000});
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

TEST_CASE("SessionStore v2: a clean upgrade deletes nothing and leaves the write generation alone",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        SessionStore fresh{pool};
        REQUIRE(fresh.is_open());
        REQUIRE(fresh.create(make_params("keep-human", "alice")).has_value());
    }
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
    const std::int64_t gen_before = write_generation(pool);

    SessionStore upgraded{pool}; // runs v2 over a table with only consistent rows
    REQUIRE(upgraded.is_open());
    auto got = upgraded.find("keep-human");
    REQUIRE(got.has_value());
    CHECK(got->has_value());
    CHECK(write_generation(pool) == gen_before); // no rows deleted, so peers keep their caches
    CHECK(insert_raw_session(pool, "again", "engine_token", "human") == kCheckViolation);
// ── #6079: factor-generation binding (schema v3) ─────────────────────────────

TEST_CASE("SessionStore v3: create and mark_mfa round-trip factor generation and bind sequence",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.rebind_guard_ok());
    CHECK(guard_tgenabled(pool) == "A"); // ENABLE ALWAYS
    // kSessionRowColumns drift detector: sessions has exactly the 17 columns find() reads.
    CHECK(scalar(pool, "SELECT count(*) FROM information_schema.columns WHERE "
                       "table_schema='session_store' AND table_name='sessions'") == "17");

    // create with a carried bound proof.
    auto p = make_params("h1", "alice");
    const std::int64_t t0 = db_now_ms(pool) - 5'000;
    p.local_mfa = {7, t0};
    auto created = store.create(p);
    REQUIRE(created.has_value());
    CHECK(created->mfa_verified_ms == t0); // the carried instant, never the write's now()
    CHECK(created->mfa_factor_gen == 7);
    auto found = store.find("h1");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->row.mfa_verified_ms == t0);
    CHECK((*found)->row.mfa_factor_gen == 7);
    CHECK((*found)->row.mfa_bind_seq == 1);

    // mark_mfa(hash, proof) rebinds to a new generation and advances the sequence.
    const std::int64_t t1 = db_now_ms(pool) - 1'000;
    auto marked = store.mark_mfa("h1", {9, t1});
    REQUIRE(marked.has_value());
    REQUIRE(marked->has_value());
    CHECK((*marked)->mfa_verified_ms == t1);
    CHECK((*marked)->mfa_factor_gen == 9);
    auto sp = stored_proof(pool, "h1");
    CHECK(sp.ms == t1);
    CHECK(sp.gen == 9);
    CHECK(sp.seq == 2);

    // The SAME proof written again (the same millisecond case for an UPGRADED writer)
    // stays bound: the writer advances the sequence in the same statement.
    REQUIRE(store.mark_mfa("h1", {9, t1}).has_value());
    sp = stored_proof(pool, "h1");
    CHECK(sp.gen == 9);
    CHECK(sp.seq == 3);

    // An upgraded ON CONFLICT rewrite keeps the binding it carries.
    auto again = make_params("h1", "alice");
    again.local_mfa = {11, t1};
    REQUIRE(store.create(again).has_value());
    sp = stored_proof(pool, "h1");
    CHECK(sp.gen == 11);
    CHECK(sp.seq == 4);

    // Sliding activity and elevation name none of the guarded columns: binding intact.
    REQUIRE(store.touch_activity("h1").has_value());
    auto elev = store.set_elevation("h1", 60'000);
    REQUIRE(elev.has_value());
    REQUIRE(elev->has_value());
    CHECK((*elev)->mfa_factor_gen == 11); // RETURNING carries the generation for the cache
    REQUIRE(store.clear_elevation("h1").has_value());
    sp = stored_proof(pool, "h1");
    CHECK(sp.gen == 11);
    CHECK(sp.seq == 4);
}

TEST_CASE("SessionStore v3: an unbound proof {0, instant} is stored unbound and re-stamps over a "
          "bound one",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    const std::int64_t t0 = db_now_ms(pool) - 2'000;
    auto p = make_params("h1", "bob");
    p.local_mfa = {0, t0};
    auto created = store.create(p);
    REQUIRE(created.has_value());
    CHECK(created->mfa_verified_ms == t0);
    CHECK(created->mfa_factor_gen == 0);

    // Bind it, then an unbound stamp restamps the instant and drops the binding.
    REQUIRE(store.mark_mfa("h1", {5, db_now_ms(pool) - 1'500}).has_value());
    CHECK(stored_proof(pool, "h1").gen == 5);
    const std::int64_t t1 = db_now_ms(pool) - 1'000;
    auto m = store.mark_mfa("h1", {0, t1});
    REQUIRE(m.has_value());
    REQUIRE(m->has_value());
    CHECK((*m)->mfa_verified_ms == t1);
    CHECK((*m)->mfa_factor_gen == 0);
    auto sp = stored_proof(pool, "h1");
    CHECK(sp.gen == 0);
    CHECK(sp.ms == t1);
    CHECK(sp.seq == 3); // create 1, bound stamp 2, unbound stamp 3

    // A missing session is nullopt on every stamp, not an error.
    auto none = store.mark_mfa("nope", {5, db_now_ms(pool) - 1});
    REQUIRE(none.has_value());
    CHECK_FALSE(none->has_value());
}

TEST_CASE("SessionStore v3: a future-dated proof instant is refused, never clamped",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t future = db_now_ms(pool) + 60'000;

    // create: no proof and no binding is stored; the caller reads 0 back.
    auto p = make_params("h1", "carol");
    p.local_mfa = {7, future};
    auto created = store.create(p);
    REQUIRE(created.has_value());
    CHECK(created->mfa_verified_ms == 0);
    CHECK(created->mfa_factor_gen == 0);
    CHECK(stored_proof(pool, "h1").ms == 0);

    // mark_mfa: a good proof first, then the future-dated stamp REMOVES it (no age-zero
    // clamp, and the earlier proof does not survive a refused re-prove).
    REQUIRE(store.mark_mfa("h1", {7, db_now_ms(pool) - 1'000}).has_value());
    CHECK(stored_proof(pool, "h1").gen == 7);
    auto refused = store.mark_mfa("h1", {7, future});
    REQUIRE(refused.has_value());
    REQUIRE(refused->has_value());
    CHECK((*refused)->mfa_verified_ms == 0);
    CHECK((*refused)->mfa_factor_gen == 0);
    auto sp = stored_proof(pool, "h1");
    CHECK(sp.ms == 0);
    CHECK(sp.gen == 0);
}

TEST_CASE("SessionStore v3: writer errors are refused, not stored",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t t = db_now_ms(pool) - 1'000;

    auto binding_without_instant = make_params("e1", "dan");
    binding_without_instant.local_mfa = {5, 0};
    CHECK_FALSE(store.create(binding_without_instant).has_value());
    auto negative = make_params("e2", "dan");
    negative.local_mfa = {-1, t};
    CHECK_FALSE(store.create(negative).has_value());
    auto with_abs = make_params("e4", "dan");
    with_abs.local_mfa = {5, t};
    with_abs.mfa_verified_ms_abs = t;
    CHECK_FALSE(store.create(with_abs).has_value());
    CHECK(scalar(pool, "SELECT count(*) FROM session_store.sessions") == "0");

    REQUIRE(store.create(make_params("ok", "dan")).has_value());
    CHECK_FALSE(store.mark_mfa("ok", {5, 0}).has_value()); // binding without an instant
    CHECK_FALSE(store.mark_mfa("ok", {0, 0}).has_value()); // no proof: use clear_mfa_proof
    CHECK_FALSE(store.mark_mfa("ok", {-1, t}).has_value());
    // {0, t} is a legal UNBOUND proof.
    auto unbound = store.mark_mfa("ok", {0, t});
    REQUIRE(unbound.has_value());
    CHECK((*unbound)->mfa_verified_ms == t);
    CHECK((*unbound)->mfa_factor_gen == 0);
}

TEST_CASE("SessionStore v3: clear_mfa_proof zeroes the proof, advances the sequence and bumps the "
          "generation",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create(make_params("h1", "erin")).has_value());
    REQUIRE(store.mark_mfa("h1", {4, db_now_ms(pool) - 1'000}).has_value());
    auto before = stored_proof(pool, "h1");
    REQUIRE(before.gen == 4);
    auto g0 = store.read_generation();
    REQUIRE(g0.has_value());

    auto cleared = store.clear_mfa_proof("h1");
    REQUIRE(cleared.has_value());
    REQUIRE(cleared->has_value());
    CHECK((*cleared)->mfa_verified_ms == 0);
    CHECK((*cleared)->mfa_factor_gen == 0);
    auto after = stored_proof(pool, "h1");
    CHECK(after.ms == 0);
    CHECK(after.gen == 0);
    CHECK(after.seq == before.seq + 1);
    auto g1 = store.read_generation();
    REQUIRE(g1.has_value());
    CHECK(*g1 > *g0);

    // A missing session is nullopt and does not bump the generation.
    auto none = store.clear_mfa_proof("nope");
    REQUIRE(none.has_value());
    CHECK_FALSE(none->has_value());
    CHECK(*store.read_generation() == *g1);

    // A clear then a fresh bound stamp rebinds cleanly.
    REQUIRE(store.mark_mfa("h1", {6, db_now_ms(pool) - 500}).has_value());
    CHECK(stored_proof(pool, "h1").gen == 6);
}

TEST_CASE("SessionStore v3: a legacy writer can never carry a binding (guard trigger)",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    // A legacy-shaped INSERT omits the new columns: it lands 0/0 (seq default 0).
    {
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(), kLegacyInsert,
                                 legacy_insert_params("L0", "frank", true, 0));
        REQUIRE(r.status() == PGRES_TUPLES_OK);
    }
    auto sp = stored_proof(pool, "L0");
    CHECK(sp.ms > 0);
    CHECK(sp.gen == 0);
    CHECK(sp.seq == 0);

    auto bind = [&](const std::string& hash) {
        REQUIRE(store.mark_mfa(hash, {8, db_now_ms(pool) - 2'000}).has_value());
        REQUIRE(stored_proof(pool, hash).gen == 8);
    };
    REQUIRE(store.create(make_params("L1", "frank")).has_value());

    SECTION("origin/dev mark_mfa text on a bound row leaves generation 0") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(), kLegacyMarkMfa, std::vector<std::string>{"L1"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("the same instant value (same millisecond) is unbound all the same") {
        bind("L1");
        const auto ms = stored_proof(pool, "L1").ms;
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(),
                                 "UPDATE session_store.sessions SET mfa_verified_ms = $2::bigint "
                                 "WHERE token_hash = $1 RETURNING mfa_verified_ms",
                                 std::vector<std::string>{"L1", std::to_string(ms)});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").ms == ms); // unchanged value ...
        CHECK(stored_proof(pool, "L1").gen == 0); // ... still unbound
    }
    SECTION("legacy ON CONFLICT with identity replacement and a changed instant") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(), kLegacyInsert,
                                 legacy_insert_params("L1", "mallory", true, 0));
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("legacy ON CONFLICT with identity replacement and the SAME instant") {
        bind("L1");
        const auto ms = stored_proof(pool, "L1").ms;
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(), kLegacyInsert,
                                 legacy_insert_params("L1", "mallory", false, ms));
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").ms == ms);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("ON CONFLICT rewriting the instant only (no identity fields)") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(
            lease.get(),
            "INSERT INTO session_store.sessions (token_hash, username, role, created_at_ms, "
            "expires_at_ms, last_activity_ms, mfa_verified_ms) VALUES "
            "($1,'frank','admin',1,2,3,$2::bigint) "
            "ON CONFLICT (token_hash) DO UPDATE SET mfa_verified_ms = EXCLUDED.mfa_verified_ms "
            "RETURNING token_hash",
            std::vector<std::string>{"L1", std::to_string(db_now_ms(pool))});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("ON CONFLICT rewriting identity fields only (instant not in the SET list)") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(
            lease.get(),
            "INSERT INTO session_store.sessions (token_hash, username, role, created_at_ms, "
            "expires_at_ms, last_activity_ms) VALUES ($1,'mallory','admin',1,2,3) "
            "ON CONFLICT (token_hash) DO UPDATE SET username = EXCLUDED.username, "
            "auth_source = EXCLUDED.auth_source, principal_kind = EXCLUDED.principal_kind "
            "RETURNING token_hash",
            std::vector<std::string>{"L1"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("a direct write of the generation column is unbound") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(),
                                 "UPDATE session_store.sessions SET mfa_factor_gen = 99 "
                                 "WHERE token_hash = $1 RETURNING token_hash",
                                 std::vector<std::string>{"L1"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("a legacy writer that also names the sequence but does not advance it") {
        bind("L1");
        const auto seq = stored_proof(pool, "L1").seq;
        auto lease = pool.acquire();
        auto r =
            pg::exec_params(lease.get(),
                            "UPDATE session_store.sessions SET mfa_verified_ms = 5, "
                            "mfa_bind_seq = $2::bigint WHERE token_hash = $1 RETURNING token_hash",
                            std::vector<std::string>{"L1", std::to_string(seq)});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 0);
    }
    SECTION("after a legacy unbind the upgraded stamp rebinds") {
        bind("L1");
        {
            auto lease = pool.acquire();
            auto r = pg::exec_params(lease.get(), kLegacyMarkMfa, std::vector<std::string>{"L1"});
            REQUIRE(r.status() == PGRES_TUPLES_OK);
        }
        CHECK(stored_proof(pool, "L1").gen == 0);
        bind("L1");
        CHECK(stored_proof(pool, "L1").gen == 8);
    }
    SECTION("an UPDATE naming none of the guarded columns leaves the binding alone") {
        bind("L1");
        auto lease = pool.acquire();
        auto r = pg::exec_params(lease.get(),
                                 "UPDATE session_store.sessions SET display_name = 'x', "
                                 "last_activity_ms = 1 WHERE token_hash = $1 RETURNING token_hash",
                                 std::vector<std::string>{"L1"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(stored_proof(pool, "L1").gen == 8);
    }
}

TEST_CASE("SessionStore v3: the store refuses to open when the guard is not provably in force",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        SessionStore intact{pool};
        REQUIRE(intact.is_open());
    }

    struct Tamper {
        const char* name;
        std::vector<std::string> sql;
    };
    const std::vector<Tamper> tampers = {
        {"trigger dropped", {"DROP TRIGGER sessions_mfa_rebind_guard ON session_store.sessions"}},
        {"trigger disabled",
         {"ALTER TABLE session_store.sessions DISABLE TRIGGER sessions_mfa_rebind_guard"}},
        {"trigger ENABLE REPLICA (skipped under the default origin role)",
         {"ALTER TABLE session_store.sessions ENABLE REPLICA TRIGGER sessions_mfa_rebind_guard"}},
        {"trigger ENABLE (origin only, skipped under replica)",
         {"ALTER TABLE session_store.sessions ENABLE TRIGGER sessions_mfa_rebind_guard"}},
        {"function body replaced",
         {"CREATE OR REPLACE FUNCTION session_store.sessions_mfa_rebind_guard() RETURNS trigger "
          "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"}},
        {"trigger recreated with a narrower column list",
         {"DROP TRIGGER sessions_mfa_rebind_guard ON session_store.sessions",
          "CREATE TRIGGER sessions_mfa_rebind_guard BEFORE UPDATE OF mfa_verified_ms ON "
          "session_store.sessions FOR EACH ROW EXECUTE FUNCTION "
          "session_store.sessions_mfa_rebind_guard()",
          "ALTER TABLE session_store.sessions ENABLE ALWAYS TRIGGER sessions_mfa_rebind_guard"}},
        {"trigger recreated with a WHEN clause that never holds",
         {"DROP TRIGGER sessions_mfa_rebind_guard ON session_store.sessions",
          "CREATE TRIGGER sessions_mfa_rebind_guard BEFORE UPDATE OF mfa_verified_ms, "
          "mfa_factor_gen, "
          "username, auth_source, principal_kind ON session_store.sessions FOR EACH ROW WHEN "
          "(false) "
          "EXECUTE FUNCTION session_store.sessions_mfa_rebind_guard()",
          "ALTER TABLE session_store.sessions ENABLE ALWAYS TRIGGER sessions_mfa_rebind_guard"}},
        {"trigger recreated as AFTER",
         {"DROP TRIGGER sessions_mfa_rebind_guard ON session_store.sessions",
          "CREATE TRIGGER sessions_mfa_rebind_guard AFTER UPDATE OF mfa_verified_ms, "
          "mfa_factor_gen, "
          "username, auth_source, principal_kind ON session_store.sessions FOR EACH ROW "
          "EXECUTE FUNCTION session_store.sessions_mfa_rebind_guard()",
          "ALTER TABLE session_store.sessions ENABLE ALWAYS TRIGGER sessions_mfa_rebind_guard"}},
    };
    for (const auto& t : tampers) {
        INFO(t.name);
        for (const auto& stmt : t.sql)
            REQUIRE(exec_ok(pool, stmt));
        SessionStore refused{pool};
        CHECK_FALSE(refused.is_open());
        REQUIRE(repair_guard(pool)); // restore exactly; the next iteration starts intact
        SessionStore reopened{pool};
        CHECK(reopened.is_open());
    }
}

TEST_CASE("SessionStore v3: the recovery bypass opens past a tampered guard and never reports it "
          "in force",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        SessionStore intact{pool};
        REQUIRE(intact.is_open());
    }
    REQUIRE(exec_ok(
        pool, "ALTER TABLE session_store.sessions DISABLE TRIGGER sessions_mfa_rebind_guard"));

    // The default refuses; the bypass opens, serves, and reports the guard NOT in force.
    SessionStore refused{pool};
    CHECK_FALSE(refused.is_open());
    SessionStore bypassed{pool, MfaBindingCheck::kBypassForRecovery};
    REQUIRE(bypassed.is_open());
    CHECK_FALSE(bypassed.rebind_guard_ok());
    REQUIRE(bypassed.create(make_params("r1", "ned")).has_value());
    auto inv = bypassed.invalidate_user("ned"); // what --mfa-reset does with it
    REQUIRE(inv.has_value());
    CHECK(*inv == 1);
    CHECK_FALSE(bypassed.rebind_guard_ok()); // find()'s re-validation never re-admits it
    REQUIRE(bypassed.find("r1").has_value());
    CHECK_FALSE(bypassed.rebind_guard_ok());

    // Intact guard: the bypass still never vouches for it; the default is unchanged.
    REQUIRE(repair_guard(pool));
    SessionStore bypassed_intact{pool, MfaBindingCheck::kBypassForRecovery};
    REQUIRE(bypassed_intact.is_open());
    CHECK_FALSE(bypassed_intact.rebind_guard_ok());
    SessionStore normal{pool};
    REQUIRE(normal.is_open());
    CHECK(normal.rebind_guard_ok());
}

TEST_CASE("SessionStore v3: a failure observed by find is sticky until restart",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create(make_params("h1", "gina")).has_value());

    // Within the memo the tampering is not yet observed (validation is request-driven
    // and memoised: the default memo is 60 s and boot just validated).
    REQUIRE(exec_ok(
        pool, "ALTER TABLE session_store.sessions DISABLE TRIGGER sessions_mfa_rebind_guard"));
    REQUIRE(store.find("h1").has_value());
    CHECK(store.rebind_guard_ok());

    // Memo expired: the next find observes it, flips the flag and still serves the row.
    store.set_binding_validation_memo_for_test(std::chrono::milliseconds{0});
    auto found = store.find("h1");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK_FALSE(store.rebind_guard_ok());

    // Re-enabling does NOT re-admit: the writes it missed cannot be reconstructed.
    REQUIRE(repair_guard(pool));
    REQUIRE(store.find("h1").has_value());
    CHECK_FALSE(store.rebind_guard_ok());

    // A new instance is the gate back in (the boot check passes on the repaired schema).
    SessionStore fresh{pool};
    REQUIRE(fresh.is_open());
    CHECK(fresh.rebind_guard_ok());
}

TEST_CASE("SessionStore v3: concurrent validation with the trigger disabled half-way latches the "
          "flag and never un-latches",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    constexpr int kThreads = 8;
    constexpr int kCalls = 50;
    PgPool pool{{.conninfo = db.dsn(), .size = kThreads + 2}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    store.set_binding_validation_memo_for_test(std::chrono::milliseconds{0}); // every find validates

    std::barrier start(kThreads);
    std::atomic<int> calls{0};
    std::atomic<int> find_failures{0};
    std::atomic<int> unlatched_after_seen_false{0};
    std::atomic<bool> disable_failed{false};
    {
        std::vector<std::jthread> threads;
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&] {
                start.arrive_and_wait();
                bool seen_false = false;
                for (int i = 0; i < kCalls; ++i) {
                    // Exactly one call, the middle one, takes the trigger away.
                    if (calls.fetch_add(1) + 1 == kThreads * kCalls / 2 &&
                        !exec_ok(pool, "ALTER TABLE session_store.sessions DISABLE TRIGGER "
                                       "sessions_mfa_rebind_guard"))
                        disable_failed = true;
                    if (!store.find("none").has_value())
                        ++find_failures;
                    const bool ok = store.rebind_guard_ok();
                    if (!ok)
                        seen_false = true;
                    else if (seen_false)
                        ++unlatched_after_seen_false; // a latched flag must never read true again
                }
            });
        }
    } // jthreads join here
    REQUIRE_FALSE(disable_failed.load());
    CHECK(find_failures.load() == 0);
    CHECK(unlatched_after_seen_false.load() == 0);
    // Every call that starts after the join sees the same answer.
    CHECK_FALSE(store.rebind_guard_ok());
    REQUIRE(store.find("none").has_value());
    CHECK_FALSE(store.rebind_guard_ok());
}

TEST_CASE("SessionStore v3: a validation that cannot run is not sticky, and the row is still "
          "served",
          "[session_store][pg][mfa_binding]") {
    // The documented asymmetry: BOOT refuses on an inconclusive check, a RUNNING store does not
    // flip the flag on one (the query failing is not evidence about the trigger) and retries on
    // the next find rather than waiting out the memo.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create(make_params("h1", "mia")).has_value());
    store.set_binding_validation_memo_for_test(std::chrono::milliseconds{0});

    // The catalog join finds no sessions table: inconclusive. (find itself fails on the missing
    // table, so the sticky flag is the observable here.)
    REQUIRE(exec_ok(pool, "ALTER TABLE session_store.sessions RENAME TO sessions_moved"));
    CHECK_FALSE(store.find("h1").has_value()); // the row read fails: not "absent", not "invalid"
    CHECK(store.rebind_guard_ok());            // not latched by an inconclusive check
    REQUIRE(exec_ok(pool, "ALTER TABLE session_store.sessions_moved RENAME TO sessions"));

    // Repaired: the next find validates afresh (the memo was cleared, not consumed), passes, and
    // serves the row.
    auto found = store.find("h1");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK(store.rebind_guard_ok());
}

TEST_CASE("SessionStore v3: a tamper that is undone between two validations is not observable",
          "[session_store][pg][mfa_binding][known-limitation]") {
    // Documented so the docs cannot overclaim: validation reads the catalog at an
    // instant. Disable, rewrite and re-enable that completes between two validations
    // leaves the flag true, and the writes made while disabled stay unbound only if a
    // legacy writer made them. The control's trust boundary is the database role.
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    store.set_binding_validation_memo_for_test(std::chrono::milliseconds{0});
    REQUIRE(store.create(make_params("h1", "hal")).has_value());

    REQUIRE(exec_ok(
        pool, "ALTER TABLE session_store.sessions DISABLE TRIGGER sessions_mfa_rebind_guard"));
    // Forge a binding while the trigger is off, then put the trigger back.
    REQUIRE(exec_ok(pool,
                    "UPDATE session_store.sessions SET mfa_verified_ms = 1, mfa_factor_gen = 5 "
                    "WHERE token_hash = 'h1'"));
    REQUIRE(repair_guard(pool));
    REQUIRE(store.find("h1").has_value());
    CHECK(store.rebind_guard_ok());           // not observable ...
    CHECK(stored_proof(pool, "h1").gen == 5); // ... and the forged binding stays
}

TEST_CASE("SessionStore v3: the guard fires under session_replication_role = replica",
          "[session_store][pg][mfa_binding]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    if (!role_is_superuser(db.dsn()))
        SKIP("test role is not a superuser: session_replication_role cannot be set");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create(make_params("h1", "ivy")).has_value());
    REQUIRE(store.mark_mfa("h1", {3, db_now_ms(pool) - 1'000}).has_value());
    REQUIRE(stored_proof(pool, "h1").gen == 3);

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(conn.get(), "SET session_replication_role = replica")}.ok());

    // Negative control: a plain ('O') trigger on a scratch table does NOT fire under the
    // replica role, which is exactly why the guard is ENABLE ALWAYS.
    REQUIRE(PgResult{PQexec(conn.get(), "CREATE TABLE public.yuzu_test_trg_ctl (v int, hit bool "
                                        "DEFAULT false)")}
                .ok());
    REQUIRE(PgResult{
        PQexec(conn.get(), "CREATE FUNCTION public.yuzu_test_trg_ctl_fn() RETURNS trigger LANGUAGE "
                           "plpgsql AS $$ BEGIN NEW.hit := true; RETURN NEW; END $$")}
                .ok());
    REQUIRE(PgResult{PQexec(conn.get(), "CREATE TRIGGER yuzu_test_trg_ctl_trg BEFORE INSERT ON "
                                        "public.yuzu_test_trg_ctl FOR EACH ROW EXECUTE FUNCTION "
                                        "public.yuzu_test_trg_ctl_fn()")}
                .ok());
    REQUIRE(
        PgResult{PQexec(conn.get(), "INSERT INTO public.yuzu_test_trg_ctl (v) VALUES (1)")}.ok());
    REQUIRE(
        PgResult{PQexec(conn.get(), "ALTER TABLE public.yuzu_test_trg_ctl ENABLE ALWAYS TRIGGER "
                                    "yuzu_test_trg_ctl_trg")}
            .ok());
    REQUIRE(
        PgResult{PQexec(conn.get(), "INSERT INTO public.yuzu_test_trg_ctl (v) VALUES (2)")}.ok());
    PgResult hits{PQexec(conn.get(), "SELECT v, hit FROM public.yuzu_test_trg_ctl ORDER BY v")};
    REQUIRE(hits.ok());
    REQUIRE(PQntuples(hits.get()) == 2);
    CHECK(std::string(PQgetvalue(hits.get(), 0, 1)) == "f"); // 'O': skipped under replica
    CHECK(std::string(PQgetvalue(hits.get(), 1, 1)) == "t"); // 'A': fires

    // The real guard fires: a legacy-shaped restamp under the replica role is unbound.
    PgResult upd{PQexec(conn.get(), "UPDATE session_store.sessions SET mfa_verified_ms = "
                                    "mfa_verified_ms WHERE token_hash = 'h1'")};
    REQUIRE(upd.ok());
    CHECK(stored_proof(pool, "h1").gen == 0);
}

TEST_CASE("SessionStore v3: the validation flags a trigger that would be skipped under replica",
          "[session_store][pg][mfa_binding]") {
    // The 'O' / 'R' tgenabled states are the ones a session_replication_role switch skips;
    // the validation must refuse both (covered as open failures above, asserted here
    // against the observed catalog state so the two cannot silently diverge).
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    CHECK(guard_tgenabled(pool) == "A");
    REQUIRE(exec_ok(pool,
                    "ALTER TABLE session_store.sessions ENABLE TRIGGER sessions_mfa_rebind_guard"));
    CHECK(guard_tgenabled(pool) == "O");
    store.set_binding_validation_memo_for_test(std::chrono::milliseconds{0});
    REQUIRE(store.find("none").has_value());
    CHECK_FALSE(store.rebind_guard_ok());
}

TEST_CASE("SessionStore v3: migration lands at v3 and survives a rollback to legacy writers",
          "[session_store][pg][migration][mfa_binding]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        SessionStore store{pool};
        REQUIRE(store.is_open());
        CHECK(
            scalar(pool, "SELECT version FROM public.schema_meta WHERE store = 'session_store'") ==
            "3");
        CHECK(guard_tgenabled(pool) == "A");

        // Run the legacy statement texts against the migrated schema (a rolled-back binary).
        REQUIRE(store.create(make_params("b1", "jo")).has_value());
        REQUIRE(store.mark_mfa("b1", {6, db_now_ms(pool) - 1'000}).has_value());
        REQUIRE(stored_proof(pool, "b1").gen == 6);
        {
            auto lease = pool.acquire();
            REQUIRE(pg::exec_params(lease.get(), kLegacyMarkMfa, std::vector<std::string>{"b1"})
                        .status() == PGRES_TUPLES_OK);
            REQUIRE(pg::exec_params(lease.get(), kLegacyInsert,
                                    legacy_insert_params("b2", "kay", true, 0))
                        .status() == PGRES_TUPLES_OK);
        }
        CHECK(stored_proof(pool, "b1").gen == 0);
        CHECK(stored_proof(pool, "b2").gen == 0);
    }

    // Re-upgrade: constructing the store again is a no-op migration; the triggers are still
    // 'A', nothing was reseeded, and an upgraded stamp binds again.
    SessionStore again{pool};
    REQUIRE(again.is_open());
    CHECK(scalar(pool, "SELECT version FROM public.schema_meta WHERE store = 'session_store'") ==
          "3");
    CHECK(guard_tgenabled(pool) == "A");
    CHECK(stored_proof(pool, "b1").gen == 0);
    REQUIRE(again.mark_mfa("b1", {10, db_now_ms(pool) - 500}).has_value());
    CHECK(stored_proof(pool, "b1").gen == 10);
}

TEST_CASE("SessionStore v3: upgrading a v2 schema keeps its rows, unbound",
          "[session_store][pg][migration][mfa_binding]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        SessionStore store{pool};
        REQUIRE(store.is_open());
    }
    // Put the schema back to the state the previous release left it in.
    REQUIRE(exec_ok(pool, "DROP TRIGGER sessions_mfa_rebind_guard ON session_store.sessions"));
    REQUIRE(exec_ok(pool, "DROP FUNCTION session_store.sessions_mfa_rebind_guard()"));
    REQUIRE(exec_ok(pool, "ALTER TABLE session_store.sessions DROP COLUMN mfa_factor_gen, "
                          "DROP COLUMN mfa_bind_seq"));
    REQUIRE(
        exec_ok(pool, "UPDATE public.schema_meta SET version = 2 WHERE store = 'session_store'"));
    {
        auto lease = pool.acquire();
        REQUIRE(pg::exec_params(lease.get(), kLegacyInsert,
                                legacy_insert_params("old1", "lee", true, 0))
                    .status() == PGRES_TUPLES_OK);
    }

    SessionStore upgraded{pool};
    REQUIRE(upgraded.is_open());
    CHECK(scalar(pool, "SELECT version FROM public.schema_meta WHERE store = 'session_store'") ==
          "3");
    CHECK(guard_tgenabled(pool) == "A");
    auto found = upgraded.find("old1");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->row.username == "lee");
    CHECK((*found)->row.mfa_verified_ms > 0);
    CHECK((*found)->row.mfa_factor_gen == 0); // the previous release's proof re-proves once
    CHECK((*found)->row.mfa_bind_seq == 0);
}
