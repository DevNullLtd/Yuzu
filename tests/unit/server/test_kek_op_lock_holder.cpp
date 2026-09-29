// test_kek_op_lock_holder.cpp — #2530 B6/T5: the `secrets_kek_op`
// advisory-lock holder-observer query in kek_op_lock.hpp
// (`kek_op_lock_holder`).
//
// Split into its own file (rather than extending test_secret_codec.cpp,
// which already carries [pg] coverage for `try_lock_kek_op`/`KekOpLockGuard`)
// so this task's B6 work does not collide with concurrent SecretCodec work
// on the same file.
//
// WHY THE OBJID CAST MATTERS (see kek_op_lock.hpp's doc comment on
// `kek_op_lock_holder` for the full writeup): `pg_locks.objid` is `oid`
// (unsigned), while `hashtext()` returns a signed `int4` that is NEGATIVE
// for `hashtext('secrets_kek_op')`. This file proves empirically — against a
// real backend, not by reasoning — that:
//   (a) the naive predicate `objid = hashtext('secrets_kek_op')` ALSO
//       matches in practice, because Postgres's oid-from-integer cast
//       reinterprets the 32-bit pattern modulo 2^32 rather than doing a
//       value-range check; AND
//   (b) the explicit bigint-mask-and-cast form the production code actually
//       uses matches identically.
// Both forms are pinned here so a future Postgres version that changes the
// implicit-cast behaviour only breaks (a), never silently breaks (b), which
// is the one shipped in kek_op_lock.hpp.
//
// #2530 T5 also pins the query-FAILURE case: `kek_op_lock_holder` now
// returns a tri-state `KekOpLockHolder{determined, pid}` rather than
// collapsing "genuinely unheld" and "the query failed" into the same
// `nullopt` — see the type's doc comment for why that collapse was a
// fabricated-negative bug on `GET /status`'s `lock_held` field.

#include <catch2/catch_test_macros.hpp>

#include "kek_op_lock.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <thread>

using namespace std::chrono_literals;

using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::detail::KekOpLockAttempt;
using yuzu::server::detail::KekOpLockGuard;
using yuzu::server::detail::KekOpLockHolder;
using yuzu::server::detail::kek_op_lock_holder;
using yuzu::server::detail::try_lock_kek_op;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

/// The naive predicate from the #2530 contract, run directly (not via
/// production code). #2530 G8-S10 (corrected — an earlier version of this
/// comment claimed this helper was independent of kek_op_lock.hpp's chosen
/// implementation; that stopped being true the moment the `AND database =
/// ...` filter below was added, per the G7-B3 note that follows). This
/// helper is independent of production code on the ONE question it exists
/// to cross-check — the objid cast/sign-conversion behaviour for
/// `hashtext('secrets_kek_op')` — but it deliberately SHARES the database
/// filter with `kek_op_lock.hpp`'s query, because without it this cross-check
/// would only be valid in a single-database cluster (see the G7-B3 note).
///

/// #2530 G7-B3: this now carries the SAME `AND database = ...` filter as the
/// shipped query. Without it, this helper's "proven empirically" claim only
/// held in a single-database cluster: `pg_locks` is a CLUSTER-WIDE view, and
/// the 4 server test shards share one Postgres container (one database per
/// shard) — an unfiltered query here could observe a SIBLING SHARD's held
/// lock and either flake the "no lock held" case or, worse, report the wrong
/// pid for the "held" case. The database filter is exactly the fix under
/// test, so this comparison helper must carry it too or it stops being a
/// meaningful cross-check of the production predicate.
std::optional<int> naive_holder_pid(PGconn* conn) {
    PgResult res{PQexec(conn,
                        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' "
                        "AND classid = 2037545589 AND objid = hashtext('secrets_kek_op') "
                        "AND granted "
                        "AND database = (SELECT oid FROM pg_database WHERE datname = "
                        "current_database())")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    if (PQntuples(res.get()) < 1 || PQgetisnull(res.get(), 0, 0))
        return std::nullopt;
    // #2530 H2 (Hermes round 2): std::from_chars, not std::atoi — atoi
    // silently returns 0 on a parse failure, which is a PLAUSIBLE-LOOKING
    // pid that would let this helper pass vacuously against a malformed
    // value instead of failing loudly. Matches the production fix in
    // kek_op_lock.hpp's `kek_op_lock_holder` (#2530 G7-S2), which this test
    // helper cross-checks and must not silently diverge from.
    const char* raw = PQgetvalue(res.get(), 0, 0);
    const char* end = raw + std::strlen(raw);
    int pid = 0;
    const auto parsed = std::from_chars(raw, end, pid);
    REQUIRE(parsed.ec == std::errc{});
    REQUIRE(parsed.ptr == end);
    return pid;
}

/// Raw, UNFILTERED query (no `AND database = ...`) — used ONLY to
/// demonstrate the #2530 G7-B3 vulnerability directly, never as a
/// cross-check of correct behaviour. Deliberately separate from
/// `naive_holder_pid` above (which now carries the fix) so this file keeps
/// one place that still reproduces the bug for the negative-proof test
/// below.
bool unfiltered_query_sees_any_granted_holder(PGconn* conn) {
    PgResult res{PQexec(conn, "SELECT pid FROM pg_locks WHERE locktype = 'advisory' "
                              "AND classid = 2037545589 AND objid = hashtext('secrets_kek_op') "
                              "AND granted")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    return PQntuples(res.get()) >= 1;
}

} // namespace

TEST_CASE("hashtext('secrets_kek_op') is negative, proving the objid trap is real",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn conn = connect(db.dsn());
    PgResult res{PQexec(conn.get(), "SELECT hashtext('secrets_kek_op')")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    const long long h = std::atoll(PQgetvalue(res.get(), 0, 0));
    // This is the whole premise of B6: if this ever stopped being negative on
    // some future Postgres, the naive-vs-cast distinction this file exists to
    // pin would be moot for this specific key (still worth keeping the cast
    // form, since it does not rely on the sign one way or the other).
    INFO("hashtext('secrets_kek_op') = " << h);
    CHECK(h < 0);
}

TEST_CASE("KEK op lock holder query: both the naive and the cast objid predicate match a real "
          "held lock (proven empirically, not by reasoning)",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn holder = connect(db.dsn());
    PgConn observer = connect(db.dsn());

    REQUIRE(try_lock_kek_op(holder.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard guard{holder.get()};

    const int holder_pid = PQbackendPID(holder.get());

    // (a) naive predicate — empirically matches on this Postgres build.
    auto naive = naive_holder_pid(observer.get());
    REQUIRE(naive.has_value());
    CHECK(*naive == holder_pid);

    // (b) the production function (explicit bigint-mask cast) — also matches,
    // and is what kek_op_lock.hpp actually ships.
    auto shipped = kek_op_lock_holder(observer.get());
    REQUIRE(shipped.determined);
    REQUIRE(shipped.pid.has_value());
    CHECK(*shipped.pid == holder_pid);

    CHECK(*naive == *shipped.pid);
}

TEST_CASE("KEK op lock holder query: determined + nullopt pid when no lock is held",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn observer = connect(db.dsn());

    // Nothing has taken `secrets_kek_op` on this fresh database. The query
    // itself succeeds — this is a TRUTHFUL "not held", distinct from the
    // query-failure case below.
    auto result = kek_op_lock_holder(observer.get());
    CHECK(result.determined);
    CHECK_FALSE(result.pid.has_value());
}

TEST_CASE("KEK op lock holder query: reflects release — held then not-held on the same "
          "observer connection",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn holder = connect(db.dsn());
    PgConn observer = connect(db.dsn());

    REQUIRE(try_lock_kek_op(holder.get()) == KekOpLockAttempt::kAcquired);
    const int holder_pid = PQbackendPID(holder.get());
    {
        KekOpLockGuard guard{holder.get()};
        auto held = kek_op_lock_holder(observer.get());
        REQUIRE(held.determined);
        REQUIRE(held.pid.has_value());
        CHECK(*held.pid == holder_pid);
    } // guard releases here

    auto after = kek_op_lock_holder(observer.get());
    CHECK(after.determined);
    CHECK_FALSE(after.pid.has_value());
}

TEST_CASE("KEK op lock holder query: exclude_pid treats the caller's own pid as unheld",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn holder = connect(db.dsn());

    REQUIRE(try_lock_kek_op(holder.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard guard{holder.get()};

    // Querying from the SAME connection that holds the lock, excluding its
    // own backend pid, must report "no (foreign) holder" — this is the
    // "does anyone ELSE hold it" mode documented on the function. The query
    // still succeeded (`determined`), so this is a truthful "not held",
    // never to be confused with the query-failure case below.
    const int own_pid = PQbackendPID(holder.get());
    auto excluded = kek_op_lock_holder(holder.get(), own_pid);
    CHECK(excluded.determined);
    CHECK_FALSE(excluded.pid.has_value());

    // Without exclusion, the same query reports the (self) holder honestly.
    auto unfiltered = kek_op_lock_holder(holder.get());
    REQUIRE(unfiltered.determined);
    REQUIRE(unfiltered.pid.has_value());
    CHECK(*unfiltered.pid == own_pid);
}

// #2530 T5 — the case the two truthful-negative tests above must never be
// confused with: a genuine query FAILURE reports `determined == false`, not
// a fabricated "not held". Severs the observer connection server-side
// (mirrors test_pg_pool.cpp's "PgPool discards a connection lost mid-use"
// idiom) so PQexec fails for a real reason, not a hand-built stub.
TEST_CASE("KEK op lock holder query: determined == false on a genuine query failure, never a "
          "fabricated \"not held\"",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn holder = connect(db.dsn());
    PgConn observer = connect(db.dsn());
    PgConn axe = connect(db.dsn());

    // A real granted holder exists throughout — if the tri-state collapsed
    // back to a bare optional, this scenario is exactly the one that would
    // silently read as "not held" (#2530 T5's motivating bug).
    REQUIRE(try_lock_kek_op(holder.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard guard{holder.get()};

    const int observer_pid = PQbackendPID(observer.get());
    REQUIRE(observer_pid > 0);
    const std::string kill =
        "SELECT pg_terminate_backend(" + std::to_string(observer_pid) + ")";
    PgResult kill_res{PQexec(axe.get(), kill.c_str())};
    REQUIRE(kill_res.status() == PGRES_TUPLES_OK);

    // pg_terminate_backend returns when the signal is SENT, not when the
    // backend has exited — poll until the client side observes the loss.
    bool severed = false;
    for (int i = 0; i < 100 && !severed; ++i) {
        PgResult ping{PQexec(observer.get(), "SELECT 1")};
        severed = ping.status() != PGRES_TUPLES_OK && PQstatus(observer.get()) != CONNECTION_OK;
        if (!severed)
            std::this_thread::sleep_for(50ms);
    }
    REQUIRE(severed);

    auto result = kek_op_lock_holder(observer.get());
    CHECK_FALSE(result.determined);
    // `pid` is documented as meaningless when undetermined; still must not
    // spuriously carry a value.
    CHECK_FALSE(result.pid.has_value());
}

// #2530 G7-B3 — empirically proves the database-scoping fix, using two REAL,
// independently-created ephemeral databases on the same cluster (exactly the
// topology `pg_try_advisory_lock` is scoped by, and exactly the topology the
// 4-shard CI Postgres container has today). Before this fix, a lock held in
// database A was reported to an observer connected to database B — `/status`
// would say `lock_held: true` with a FOREIGN pid while rotation was actually
// free in B, pinning the gauge/alert forever and pointing a runbook at
// terminating another tenant's backend.
TEST_CASE("KEK op lock holder query: a lock held in database A is NOT reported to an observer "
          "in database B",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB(db_a);
    YUZU_REQUIRE_PG_DB(db_b);

    PgConn holder_a = connect(db_a.dsn());
    PgConn observer_b = connect(db_b.dsn());

    // Take the lock in database A.
    REQUIRE(try_lock_kek_op(holder_a.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard guard{holder_a.get()};
    const int holder_pid = PQbackendPID(holder_a.get());

    // First, prove the vulnerability is REAL against the unfiltered query —
    // otherwise this test would only be proving something the fixture never
    // exercised. `pg_locks` is cluster-wide, so an observer in B sees A's
    // granted row when nothing filters by database.
    REQUIRE(unfiltered_query_sees_any_granted_holder(observer_b.get()));

    // Now prove the SHIPPED, database-filtered query from database B does
    // NOT see it: determined (the query itself succeeded) but genuinely
    // unheld from B's perspective.
    auto from_b = kek_op_lock_holder(observer_b.get());
    CHECK(from_b.determined);
    CHECK_FALSE(from_b.lock_held);
    CHECK_FALSE(from_b.pid.has_value());

    // And, as a positive control, an observer actually connected to A sees
    // it correctly.
    PgConn observer_a = connect(db_a.dsn());
    auto from_a = kek_op_lock_holder(observer_a.get());
    CHECK(from_a.determined);
    CHECK(from_a.lock_held);
    REQUIRE(from_a.pid.has_value());
    CHECK(*from_a.pid == holder_pid);
}
