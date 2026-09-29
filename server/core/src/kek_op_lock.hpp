#pragma once

/// @file kek_op_lock.hpp
/// The cluster-wide KEK-operation advisory lock (#2395).
///
/// Extracted from server.cpp so it can be exercised directly by tests: this is
/// the highest-consequence resource in the KEK surface. A leaked session-scoped
/// advisory lock is not a transient error — it wedges every future KEK
/// operation across the whole cluster until the holding backend dies, and
/// because session advisory locks are RE-ENTRANT per backend, the wedge is
/// asymmetric: whichever request next draws the poisoned pooled connection
/// succeeds while every other connection gets 409 (gov unhappy-path UP-1).
/// Governance cpp-safety flagged that this had zero test coverage; it now has
/// a [pg] test that takes two real connections.
///
/// `KekOpLockGuard`'s release protocol is `pg::PgSessionAdvisoryLockGuard`
/// (`pg/pg_session_advisory_lock.hpp`) — the ONE reusable session-advisory-
/// lock release guard in this codebase; a second store needing a
/// session-scoped lock (e.g. the T12 rotation sweep's store-wide sweep lock,
/// `api_token_store.cpp`) reuses it rather than hand-rolling its own, exactly
/// the drift `dispatch_confined_arms`/`authz_topology_floor` exist to prevent
/// for their own chokepoints. See that header's own doc comment for the
/// aborted-transaction wedge this design closes.

#include "pg/pg_raii.hpp"
#include "pg/pg_session_advisory_lock.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstring>
#include <optional>

namespace yuzu::server::detail {

constexpr std::chrono::milliseconds kKekOpAcquireTimeout{5000};

// ONE definition of the `secrets_kek_op` lock's key, generating matching
// try-lock/unlock SQL (`pg::PgAdvisoryLockKey`, #2964 round 3 review finding
// 3) — replaces the former hand-written `kKekOpTryLockSql`/`kKekOpUnlockSql`
// pair of string constants, which could drift (a drift unlocks a key never
// locked; Postgres reports `false`, and the release guard treats `false` as
// "released" — a silent leak of the key actually held).
inline const pg::PgAdvisoryLockKey& kek_op_lock_key() {
    static const pg::PgAdvisoryLockKey key =
        pg::PgAdvisoryLockKey::pair("2037545589", "hashtext('secrets_kek_op')");
    return key;
}

enum class KekOpLockAttempt { kAcquired, kConflict, kError };

/// Non-blocking try-lock on `conn`. `kConflict` means another KEK operation
/// (rotate/rewrap/status, on this server or another pointed at the same
/// database) currently holds it — the caller must NOT wait, just report
/// Conflict immediately (rule from #2395: KEK ops never queue behind each
/// other).
[[nodiscard]] inline KekOpLockAttempt try_lock_kek_op(PGconn* conn) {
    const std::string try_lock_sql = kek_op_lock_key().try_lock_sql();
    pg::PgResult res{PQexec(conn, try_lock_sql.c_str())};
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("KEK op: advisory-lock attempt failed: {}", PQerrorMessage(conn));
        return KekOpLockAttempt::kError;
    }
    // Guard the row read by construction, not by assumption: PQgetvalue
    // returns nullptr out-of-range, so a future edit to the SQL would turn
    // this into a null deref on a privileged path (gov cpp-safety NICE).
    if (PQntuples(res.get()) != 1 || PQgetisnull(res.get(), 0, 0)) {
        spdlog::error("KEK op: advisory-lock attempt returned an unexpected result shape");
        return KekOpLockAttempt::kError;
    }
    return (PQgetvalue(res.get(), 0, 0)[0] == 't') ? KekOpLockAttempt::kAcquired
                                                    : KekOpLockAttempt::kConflict;
}

/// RAII release of the `secrets_kek_op` session advisory lock taken via
/// `try_lock_kek_op`. Fires on EVERY exit path, including an exception
/// unwind — a leaked session-scoped advisory lock wedges every future KEK
/// operation across the whole cluster against this one backend connection
/// until that backend process dies, so this is the single highest-risk line
/// in the KEK seam (#2395). Construct it only after a `kAcquired` result, and
/// declare it AFTER the pool `Lease` in the same scope so it destructs
/// (releases) BEFORE the lease returns the connection to the pool — a
/// session advisory lock outlives the statement, so releasing it is not
/// optional cleanup, it is the only way to unlock at all.
///
/// Thin, KEK-specific wrapper around the reusable
/// `pg::PgSessionAdvisoryLockGuard` (`pg/pg_session_advisory_lock.hpp`) —
/// this class's whole job is pinning `kek_op_lock_key()` and a log label so
/// every existing call site (`explicit KekOpLockGuard{conn}`) keeps working
/// unchanged. See the generic guard's own doc comment for the release
/// protocol (dead-connection vs live-connection discrimination, rollback +
/// retry, backend self-termination as the last resort on a live-connection
/// failure that recovery could not fix).
class KekOpLockGuard {
public:
    // Deliberately NOT `noexcept` — see `PgSessionAdvisoryLockGuard`'s own
    // constructor doc comment (`pg/pg_session_advisory_lock.hpp`) for why:
    // `inner_`'s mem-initializer heap-allocates a fresh unlock-SQL string.
    explicit KekOpLockGuard(PGconn* conn) : inner_(conn, kek_op_lock_key(), "KEK op") {}

    KekOpLockGuard(const KekOpLockGuard&) = delete;
    KekOpLockGuard& operator=(const KekOpLockGuard&) = delete;
    KekOpLockGuard(KekOpLockGuard&&) = delete;
    KekOpLockGuard& operator=(KekOpLockGuard&&) = delete;

private:
    pg::PgSessionAdvisoryLockGuard inner_;
};

/// #2530 B6 — diagnostic-only observer of the `secrets_kek_op` advisory
/// lock's current holder. Does NOT take the lock itself: this is the query
/// behind `KekOpResult::lock_held`/`lock_holder_pid` (kek_routes.hpp), and
/// `GET /status` deliberately never takes this lock (see the status route in
/// kek_routes.cpp) — this function is how it observes cluster state instead.
/// Read lock-free, like every #2530 B2 diagnostic snapshot: the `pg_locks`
/// row this reads can change between the SELECT and the caller reading the
/// return value, so treat the result as a point-in-time snapshot, never as a
/// synchronization primitive, and never derive a "safe to retire" conclusion
/// from it (#2525).
///
/// TRAP (proven by `test_kek_op_lock_holder.cpp` against a real backend, not
/// by reasoning): `pg_locks.objid` is `oid` — internally an unsigned 32-bit
/// value — while `hashtext()` returns a SIGNED `int4` that is negative for
/// `hashtext('secrets_kek_op')` on every Postgres build observed so far
/// (`hashtext('secrets_kek_op') = -1189576286`). Empirically, Postgres's
/// `oid`-from-`integer` cast reinterprets the 32-bit pattern modulo 2^32
/// (`(-1189576286)::oid = 3105391010`, exactly matching what `pg_locks`
/// stores for this lock's `objid`), so comparing `objid = hashtext(...)`
/// directly DOES match in practice. We still spell out the explicit
/// bigint-mask-and-cast below rather than lean on that implicit
/// comparison-operator resolution: it makes the 32-bit-wraparound intent
/// obvious at the call site, and does not depend on Postgres continuing to
/// resolve a bare `oid = integer` comparison via that particular implicit
/// cast on every future version.
///
/// #2530 T5 — result of `kek_op_lock_holder`: distinguishes "the query told
/// us no one holds the lock" from "we could not ask the question". Before
/// this type existed the two collapsed to the same `nullopt`, which meant a
/// failed query and a genuinely unheld lock were indistinguishable to every
/// caller — including `GET /status`'s `lock_held` field, which derived
/// straight from `has_value()` and so reported `false` ("not held") on a
/// query failure. That is the one scenario this observability exists to
/// diagnose: an operator hitting 409s because the lock is wedged calls
/// `/status` during exactly the failure that makes the holder query itself
/// fail, and a fabricated `false` tells them the opposite of the truth.
///
/// #2530 G7-S1: `lock_held` is a field of its OWN, not derived by callers
/// from `pid.has_value()`. A granted holder row with a NULL `pid` (possible
/// in `pg_locks` — a lock can be granted to a backend whose pid column is
/// unreadable at read time) is a HELD lock; collapsing that into "no holder"
/// would fabricate `lock_held: false`, the one thing this whole design
/// forbids (see `GET /status`'s `lock_held` contract, kek_routes.hpp). Only
/// "no granted row at all" is genuinely unheld.
struct KekOpLockHolder {
    bool determined{false};   ///< false = the pg_locks query itself failed; `lock_held`/`pid` meaningless
    bool lock_held{false};    ///< meaningful only when `determined`; true iff a granted holder row exists (even with a NULL pid)
    std::optional<int> pid{}; ///< meaningful only when `determined && lock_held`; nullopt = unheld, or held with an unreported pid

    /// #2530 H1 (Hermes round 2) — wall-clock instant this observation was
    /// taken (captured before the `SELECT` fires, so it reflects "as of
    /// when we asked", not "as of when the answer arrived"). This exists
    /// because `pid` alone is a snapshot with no visible age: a DBA acting
    /// on a `/status` response minutes after it was generated has no way to
    /// tell a fresh reading from a stale one, and Postgres backend pids are
    /// REUSED — an OS pid that genuinely held the lock a minute ago can
    /// belong to an entirely unrelated backend by the time someone reads it.
    /// Surfaced on every determination (even a failed one, so a caller can
    /// tell how stale the failed attempt itself was) — never treat this as
    /// a substitute for re-confirming the pid against `pg_locks` at the
    /// moment of any consequential action (see the runbook's termination
    /// step, docs/user-manual/server-admin.md).
    std::chrono::system_clock::time_point captured_at{};
};

/// `exclude_pid`: when non-negative, a holder whose pid equals `exclude_pid`
/// is reported as "no (foreign) holder" -> `pid == nullopt` (still
/// `determined == true`, since the query itself succeeded). Pass
/// `PQbackendPID(conn)` when a caller wants "does anyone ELSE hold it" rather
/// than "who holds it right now" — today's only caller (`GET /status`) never
/// takes this lock itself, so exclusion is a no-op there; the parameter
/// exists for a future caller that queries from inside its own held lock.
[[nodiscard]] inline KekOpLockHolder kek_op_lock_holder(PGconn* conn, int exclude_pid = -1) {
    // #2530 H1: captured BEFORE the round trip, so it reflects "as of when
    // we asked" — the instant this observation is anchored to for staleness
    // purposes, not the (later, and unknowable from here) instant the
    // caller eventually reads the result.
    const auto captured_at = std::chrono::system_clock::now();
    // #2530 G7-B3: `AND database = ...` is load-bearing, not defensive
    // polish. `pg_try_advisory_lock`/`pg_advisory_unlock` are
    // DATABASE-scoped (the same (classid, objid) pair is a distinct lock per
    // database on the same cluster), but `pg_locks` is a CLUSTER-WIDE view —
    // without this predicate, a lock held by an entirely unrelated tenant
    // database on the same Postgres instance is reported as OUR lock:
    // `/status` says `lock_held: true` with a foreign pid while rotation is
    // actually free, the gauge pins to 1, the alert fires forever, and the
    // runbook then walks a DBA toward terminating another tenant's backend.
    // This also matters in THIS repo's own test topology: the 4 server test
    // shards share one Postgres container (different databases), so an
    // unfiltered query could observe a sibling shard's lock — see
    // test_kek_op_lock_holder.cpp's cross-database isolation case.
    constexpr const char* kSql =
        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 2037545589 "
        "AND objid = (hashtext('secrets_kek_op')::bigint & 4294967295)::oid AND granted "
        "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())";
    pg::PgResult res{PQexec(conn, kSql)};
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("KEK op: lock-holder query failed: {}", PQerrorMessage(conn));
        return KekOpLockHolder{
            .determined = false, .lock_held = false, .pid = std::nullopt, .captured_at = captured_at};
    }
    // No granted holder row at all -> determined, genuinely unheld.
    if (PQntuples(res.get()) < 1)
        return KekOpLockHolder{
            .determined = true, .lock_held = false, .pid = std::nullopt, .captured_at = captured_at};
    // #2530 G7-S1: a granted row with a NULL pid is still a HELD lock — see
    // the struct doc comment above for why this must not collapse into "no
    // holder".
    if (PQgetisnull(res.get(), 0, 0))
        return KekOpLockHolder{
            .determined = true, .lock_held = true, .pid = std::nullopt, .captured_at = captured_at};
    // #2530 G7-S2: std::from_chars instead of std::atoi — atoi silently
    // returns 0 on a parse failure, which is a PLAUSIBLE-LOOKING pid; a
    // malformed value here must surface as "could not determine", never as
    // a confident (and wrong) pid 0.
    const char* raw = PQgetvalue(res.get(), 0, 0);
    const char* end = raw + std::strlen(raw);
    int pid = 0;
    const auto parsed = std::from_chars(raw, end, pid);
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        spdlog::error("KEK op: lock-holder query returned an unparseable pid: '{}'", raw);
        return KekOpLockHolder{
            .determined = false, .lock_held = false, .pid = std::nullopt, .captured_at = captured_at};
    }
    if (exclude_pid >= 0 && pid == exclude_pid)
        return KekOpLockHolder{
            .determined = true, .lock_held = false, .pid = std::nullopt, .captured_at = captured_at};
    return KekOpLockHolder{
        .determined = true, .lock_held = true, .pid = pid, .captured_at = captured_at};
}

} // namespace yuzu::server::detail
