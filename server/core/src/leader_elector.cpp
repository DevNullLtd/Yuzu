#include "leader_elector.hpp"

#include "pg/pg_exec.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace yuzu::server {

namespace {

/// True if the DSN (or the PGOPTIONS env) already sets libpq `options` — the only
/// route to a server-side statement_timeout/lock_timeout. Mirrors pg_pool's
/// operator-wins rule (PR #4134): when the operator set their own, the elector does
/// not override them.
bool dsn_sets_options(const std::string& dsn) {
    bool has = false;
    char* errmsg = nullptr;
    if (PQconninfoOption* parsed = PQconninfoParse(dsn.c_str(), &errmsg)) {
        for (PQconninfoOption* o = parsed; o && o->keyword; ++o) {
            if (std::strcmp(o->keyword, "options") == 0 && o->val && o->val[0] != '\0') {
                has = true;
                break;
            }
        }
        PQconninfoFree(parsed);
    }
    if (errmsg != nullptr)
        PQfreemem(errmsg);
    const char* env = std::getenv("PGOPTIONS");
    return has || (env != nullptr && env[0] != '\0');
}

/// A leadership lock name must be a strict lowercase identifier so it can be
/// embedded in the advisory-key SQL expression without an injection risk (the
/// key SQL is a literal handed to Postgres' `hashtext`, not a bound parameter).
bool is_valid_lock_name(const std::string& name) {
    if (name.empty() || name.size() > 48)
        return false;
    if (!(name[0] >= 'a' && name[0] <= 'z'))
        return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

/// Derive the session advisory-lock key for a leadership name. `classid` is a
/// fixed constant naming the leader-elector key namespace (distinct from the
/// KEK-op lock's `2037545589`); `objid` is `hashtext('leader:<name>')`. An
/// invalid name falls back to the default key so the embedded SQL literal is
/// always a validated identifier — the elector refuses to open on an invalid
/// name anyway, so the fallback key is never actually used to lead.
pg::PgAdvisoryLockKey make_lock_key(const std::string& name) {
    const std::string safe = is_valid_lock_name(name) ? name : kServerBackgroundLeaderLock;
    return pg::PgAdvisoryLockKey::pair("1735291205", "hashtext('leader:" + safe + "')");
}

/// Parse a Postgres bigint text value. Returns nullopt on any parse failure.
std::optional<std::int64_t> parse_i64(const char* s) {
    if (s == nullptr)
        return std::nullopt;
    std::int64_t v = 0;
    const char* end = s + std::strlen(s);
    auto [p, ec] = std::from_chars(s, end, v);
    if (ec != std::errc{} || p != end)
        return std::nullopt;
    return v;
}

// The epoch packs the timeline above the low 32 bits (#6535).
constexpr std::int64_t kEpochTimelineUnit = std::int64_t{1} << 32;
constexpr std::int64_t kEpochCountMask = kEpochTimelineUnit - 1;

// The Postgres WAL timeline of the primary this connection is writing to (#6535).
// The first 8 hex digits of the current WAL file name ARE the insertion timeline,
// and unlike pg_control_checkpoint().timeline_id (the control file lags a fast
// promotion until the post-promotion checkpoint completes) it is already the NEW
// timeline when the first write after a promotion runs. On a standby
// pg_current_wal_lsn() raises, so a mint against a standby fails closed. Both
// functions are PUBLIC-execute; the 8 hex digits zero-extend through bit(32).
// A LITERAL, never built from input: it is spliced into the mint statement below.
constexpr const char* kTimelineSql =
    "('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::bigint";

/// The epoch mint (#6535):
///   epoch = GREATEST((GREATEST(timeline, prev_row_epoch >> 32) << 32) + nextval(seq),
///                    prev_row_epoch + 1)
///
/// Why the timeline is in the epoch: a lossy (asynchronous, or degraded
/// non-strict-quorum) promotion can lose the latest mint -- the sequence advance
/// AND the leader_state row -- so a bare sequence re-mints the value a paused
/// ex-leader still holds and the equality fence admits both. Every promotion
/// starts a NEW timeline whatever WAL was lost, so the re-minted epoch differs.
///
/// Why the surviving row is read TWICE (it is the same schema, read under the advisory
/// lock): the enablement store orders epochs (`issuer_epoch <= epoch`), and a logical
/// restore / pg_upgrade / logical-replication cutover lands on a cluster whose timeline
/// restarted at 1 while the restored row and issuer_epoch still carry the old, higher
/// timeline; a restored sequence can also be older than the row (`ALTER SEQUENCE ...
/// RESTART` is the cap remedy). (1) `prev + 1` is a FLOOR: every mint is strictly above
/// the surviving row. (2) `GREATEST(timeline, prev >> 32)` in the packed term keeps the
/// sequence part live while the row pins a higher timeline than the real one: with the
/// floor alone every mint there would be exactly `prev + 1`, deterministic, and a lossy
/// promotion that loses the latest mint would re-mint the very value the paused
/// ex-leader holds (a window worse than the pre-#6535 bare sequence, which Postgres
/// pre-logs 32 values ahead). The row alone cannot repair a lossy promotion (the
/// promoted standby may have lost the row too), which is why the REAL timeline stays.
/// A row of INT64_MAX makes `prev + 1` raise (bigint out of range): a loud epoch_record
/// failure, never a wrap. The floor assumes no writer other than the lock holder
/// (a manual UPDATE racing a mint can still be overwritten, as before #6535).
///
/// `+`, never `|` for the pack (defence in depth: with the sequence capped at
/// 2^32-1 they agree, but an OR aliases the timeline bits if the cap is ever
/// raised). The range test runs INSIDE the CTE that holds nextval(), so a refused
/// mint burns no sequence value. The range keeps the result positive
/// (`live_epoch_` reads 0 as "not leader") and below 2^63. $3 is the test-only
/// timeline override as text ('' = none, read the real timeline). The statement
/// also returns the REAL timeline so a minted timeline part above it (a pinned
/// timeline after a restore) can be reported.
const std::string& epoch_mint_sql() {
    static const std::string kSql =
        std::string("WITH t AS (SELECT COALESCE(NULLIF($3, '')::bigint, ") + kTimelineSql +
        ") AS tl), "
        "p AS (SELECT COALESCE((SELECT current_leader_epoch FROM leader_elector.leader_state "
        "      WHERE lock_key = $1), 0) AS prev), "
        "e AS (SELECT GREATEST((GREATEST(t.tl, p.prev >> 32) << 32) + "
        "                      nextval('leader_elector.leader_epoch_seq'), p.prev + 1) AS ep "
        "      FROM t, p WHERE t.tl BETWEEN 1 AND 2147483647), "
        "ins AS (INSERT INTO leader_elector.leader_state "
        "  (lock_key, current_leader_epoch, holder_id, acquired_at) "
        "SELECT $1, e.ep, $2, now() FROM e "
        "ON CONFLICT (lock_key) DO UPDATE "
        "  SET current_leader_epoch = EXCLUDED.current_leader_epoch, "
        "      holder_id = EXCLUDED.holder_id, acquired_at = now() "
        "RETURNING current_leader_epoch) "
        "SELECT ins.current_leader_epoch, (SELECT tl FROM t) FROM ins";
    return kSql;
}

const std::string& timeline_probe_sql() {
    static const std::string kSql = std::string("SELECT ") + kTimelineSql;
    return kSql;
}

} // namespace

const std::vector<pg::PgMigration>& LeaderElector::migrations() {
    // Slice 3.1: the fenced-leadership registry only. The transactional command
    // outbox (slice 3.3) is deliberately NOT created here — its column set must
    // be designed against ADR-1007's `ConfinedDispatchOutcome`/`not_sent`, so
    // freezing its schema now would risk a needless re-migration.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE SEQUENCE IF NOT EXISTS leader_epoch_seq AS bigint;"
         "CREATE TABLE IF NOT EXISTS leader_state ("
         "  lock_key             TEXT PRIMARY KEY,"
         "  current_leader_epoch BIGINT NOT NULL,"
         "  holder_id            TEXT NOT NULL,"
         "  acquired_at          TIMESTAMPTZ NOT NULL DEFAULT now()"
         ");"},
        // v2 (#6535): the epoch packs the sequence into its low 32 bits (see
        // epoch_mint_sql). Cap the sequence so nextval() ERRORS at the boundary
        // (the existing epoch_record acquire failure, fail closed) instead of a
        // 33rd bit ever reaching the timeline. NO CYCLE is the default. Idempotent.
        {2, "ALTER SEQUENCE leader_epoch_seq MAXVALUE 4294967295;"},
    };
    return kMigrations;
}

LeaderElector::LeaderElector(Config cfg)
    : cfg_(std::move(cfg)),
      name_valid_(is_valid_lock_name(cfg_.lock_name)),
      lock_key_(make_lock_key(cfg_.lock_name)),
      mint_params_{cfg_.lock_name, cfg_.holder_id,
                   cfg_.timeline_override_for_test ? std::to_string(*cfg_.timeline_override_for_test)
                                                   : std::string{}} {
    // Force the first-call static init of the mint SQL here, so it cannot throw between the
    // advisory-lock grant and the mint in try_acquire (cpp-safety C-1). exec_params still
    // copies the parameters per call: a bad_alloc there is caught by the election loop and
    // the next attempt re-grants the re-entrant lock (one guard owns it), a ~1 interval
    // leaderless window, LOW.
    (void)epoch_mint_sql();
    if (!name_valid_) {
        spdlog::error("leader_elector: invalid lock_name; elector stays non-open (fail-closed)");
        return;
    }
    // Fail closed on an empty DSN or holder_id rather than connecting: an empty
    // DSN makes PQconnectdb silently fall back to libpq env/socket defaults, so
    // two replicas could resolve DIFFERENT databases and each hold "the" leader
    // lock — a silent split-brain of the leadership row (UP-3). An empty
    // holder_id would satisfy the NOT NULL column but leave leadership
    // unattributable (UP-7).
    if (cfg_.dsn.empty() || cfg_.holder_id.empty()) {
        spdlog::error("leader_elector: empty dsn or holder_id; elector stays non-open (fail-closed)");
        return;
    }
    std::lock_guard<std::mutex> lk(mu_);
    connect_locked();
    if (open_) {
        // #4013: log the RESOLVED coordination endpoint (never the DSN, which may
        // carry a password) so an operator can confirm the elector is on a
        // dedicated, direct-to-primary connection — not the app pool, not a
        // transaction-mode pooler (§10). PQhost/PQport/PQdb read the connection's
        // own resolved parameters.
        const char* host = PQhost(conn_.get());
        const char* port = PQport(conn_.get());
        const char* dbn = PQdb(conn_.get());
        spdlog::info("leader_elector: coordination connection established "
                     "(host={} port={} dbname={}; dedicated, never-recycled)",
                     host && *host ? host : "?", port && *port ? port : "?",
                     dbn && *dbn ? dbn : "?");
    }
}

LeaderElector::~LeaderElector() {
    std::lock_guard<std::mutex> lk(mu_);
    // Release the advisory lock (via the guard) BEFORE the dedicated connection
    // is finished. lock_guard_ is declared after conn_, so member destruction
    // would already run in this order; reset explicitly for clarity.
    drop_leadership_locked();
}

bool LeaderElector::connect_locked() {
    // Never reassign the connection while a lock guard still references it.
    drop_leadership_locked();
    open_ = false;
    // Fail closed on any invalid config on every (re)connect, not just at
    // construction — heartbeat's failure path calls back in here (UP-3/UP-7).
    if (!name_valid_ || cfg_.dsn.empty() || cfg_.holder_id.empty())
        return false;

    conn_ = pg::PgConn{PQconnectdb(cfg_.dsn.c_str())};
    if (conn_.get() == nullptr || PQstatus(conn_.get()) != CONNECTION_OK) {
        spdlog::warn("leader_elector: dedicated connection failed: {}",
                     conn_.get() != nullptr ? PQerrorMessage(conn_.get()) : "null conn");
        return false;
    }
    // Bound this dedicated connection server-side so a wedged lock-holder or a
    // stalled-but-LIVE backend (TCP healthy — the connect_timeout/keepalive/
    // tcp_user_timeout knobs never fire) fails fast instead of hanging the election
    // loop and stop() indefinitely (PR #4134 review; the pg_pool statement/
    // lock-timeout pattern, same constants). SET as SESSION GUCs BEFORE the schema
    // migration below, so its blocking pg_advisory_xact_lock inherits lock_timeout.
    // Best-effort. Skipped when the operator set their own options=/PGOPTIONS —
    // their GUCs win, matching pg_pool's operator-override rule.
    if (dsn_sets_options(cfg_.dsn)) {
        // The operator set options=/PGOPTIONS; leave the timeouts to their config
        // (matching pg_pool), but say so — otherwise the absence of the bound is
        // invisible if they did NOT set statement_timeout/lock_timeout (K3).
        spdlog::debug("leader_elector: operator options=/PGOPTIONS present; not injecting "
                      "statement/lock timeouts on the coordination connection");
    } else {
        // Best-effort but OBSERVABLE (K4): a swallowed SET failure would silently
        // leave this connection UNBOUNDED, re-opening the very wedge fix #2 closes.
        for (const char* stmt : {"SET statement_timeout = 30000", "SET lock_timeout = 10000"}) {
            pg::PgResult r = pg::exec_params(conn_.get(), stmt, std::vector<std::string>{});
            if (r.status() != PGRES_COMMAND_OK)
                spdlog::warn("leader_elector: '{}' failed ({}); the coordination connection is "
                             "UNBOUNDED — a wedged lock-holder could stall the election loop + stop()",
                             stmt, r.get() != nullptr ? PQresultErrorMessage(r.get()) : "no result");
        }
    }
    if (!pg::PgMigrationRunner::run(conn_.get(), kLeaderElectorStore, migrations())) {
        spdlog::error("leader_elector: schema migration failed; elector non-open");
        return false;
    }
    // Probe the timeline the epoch mint will read (#6535). A platform whose WAL
    // functions differ, or a DSN that resolved to a standby, would otherwise show up
    // only as a rising epoch_record failure count; refusing to open here makes it an
    // attributable error. It is counted as acquire_failures{cause="connect"} (the log
    // line is the attribution). Skipped under the test override (the mint never reads
    // the real timeline then).
    if (!cfg_.timeline_override_for_test.has_value()) {
        pg::PgResult tl = pg::exec_params(conn_.get(), timeline_probe_sql().c_str(),
                                          std::vector<std::string>{});
        const std::optional<std::int64_t> observed =
            (tl.status() == PGRES_TUPLES_OK && PQntuples(tl.get()) == 1 &&
             !PQgetisnull(tl.get(), 0, 0))
                ? parse_i64(PQgetvalue(tl.get(), 0, 0))
                : std::nullopt;
        if (!observed) {
            std::string why = tl.get() != nullptr ? PQresultErrorMessage(tl.get()) : "no result";
            while (!why.empty() && (why.back() == '\n' || why.back() == '\r'))
                why.pop_back(); // libpq messages end in a newline
            spdlog::error("leader_elector: cannot read the Postgres timeline "
                          "(pg_walfile_name(pg_current_wal_lsn()) failed: {}); the fenced epoch "
                          "needs it, so the elector stays non-open. Is the DSN pointing at a "
                          "standby, or is this a Postgres platform without WAL functions?",
                          why);
            // Do not keep an idle, connected-but-closed connection between retries.
            conn_ = pg::PgConn{};
            return false;
        }
        // Info only when the timeline changes (every reconnect would otherwise repeat it).
        if (*observed != last_logged_timeline_) {
            spdlog::info("leader_elector: coordination timeline={}", *observed);
            last_logged_timeline_ = *observed;
        } else {
            spdlog::debug("leader_elector: coordination timeline={}", *observed);
        }
    }
    open_ = true;
    return true;
}

void LeaderElector::drop_leadership_locked(std::optional<LeadershipLoss> cause) {
    // Count a loss only when leadership was really held (epoch_ is the writer's
    // authoritative state under mu_); read BEFORE the reset below.
    if (cause.has_value() && epoch_.has_value())
        lost_[static_cast<std::size_t>(*cause)].fetch_add(1, std::memory_order_relaxed);
    lock_guard_.reset(); // runs pg_advisory_unlock on conn_ if it was held
    epoch_.reset();
    // Publish "not leader" (slice 3.2, #4013). Release-ordered so a reader that
    // observes 0 has seen every write the drop performed; ordered BEFORE any
    // subsequent reconnect so a live follower never reads a stale leader epoch.
    live_epoch_.store(0, std::memory_order_release);
}

std::int64_t LeaderElector::steady_now_ns() noexcept {
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count();
    return ns > 0 ? ns : 1; // 0 is the "never answered" sentinel
}

void LeaderElector::note_ok_locked() noexcept {
    last_ok_steady_ns_.store(steady_now_ns(), std::memory_order_relaxed);
}

LeaderElector::Stats LeaderElector::stats() const noexcept {
    Stats s;
    const std::int64_t live = live_epoch_.load(std::memory_order_acquire);
    s.leader = live > 0;
    s.epoch = live > 0 ? live : 0;
    s.acquired = acquired_.load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < kAcquireFailureCount; ++i)
        s.acquire_failed[i] = acquire_failed_[i].load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < kLeadershipLossCount; ++i)
        s.lost[i] = lost_[i].load(std::memory_order_relaxed);
    s.last_ok_steady_ns = last_ok_steady_ns_.load(std::memory_order_relaxed);
    return s;
}

bool LeaderElector::is_open() const {
    std::lock_guard<std::mutex> lk(mu_);
    return open_;
}

bool LeaderElector::try_acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!open_ && !connect_locked()) {
        acquire_failed_[static_cast<std::size_t>(AcquireFailure::Connect)].fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    // Already leader: confirm the connection is live and keep the epoch.
    if (epoch_.has_value()) {
        pg::PgResult live = pg::exec_params(conn_.get(), "SELECT 1", std::vector<std::string>{});
        if (live.status() == PGRES_TUPLES_OK) {
            note_ok_locked();
            return true;
        }
        spdlog::warn("leader_elector: liveness check failed while leading; dropping and reconnecting");
        drop_leadership_locked(LeadershipLoss::LivenessFailed);
        if (!connect_locked()) {
            acquire_failed_[static_cast<std::size_t>(AcquireFailure::Connect)].fetch_add(
                1, std::memory_order_relaxed);
            return false;
        }
    }

    // Attempt the session advisory lock on the owned connection.
    pg::PgResult lock_res =
        pg::exec_params(conn_.get(), lock_key_.try_lock_sql().c_str(), std::vector<std::string>{});
    if (lock_res.status() != PGRES_TUPLES_OK || PQntuples(lock_res.get()) != 1 ||
        PQgetisnull(lock_res.get(), 0, 0)) {
        // A failed try-lock QUERY (a transport error, as opposed to a 't'/'f'
        // result) means the dedicated connection is unhealthy. Reconnect so a
        // later try_acquire() can heal, mirroring the already-leader liveness
        // branch above. Without this a FOLLOWER (epoch_ == nullopt, so the
        // liveness branch is skipped) whose connection blipped would be
        // permanently, silently excluded from failover: open_ stays true, so
        // the reconnect at the top of try_acquire is never re-entered, and every
        // subsequent call retries the same dead PGconn. [self-adversarial F1]
        spdlog::warn("leader_elector: try-lock query failed; reconnecting");
        acquire_failed_[static_cast<std::size_t>(AcquireFailure::LockQuery)].fetch_add(
            1, std::memory_order_relaxed);
        drop_leadership_locked();
        connect_locked(); // best-effort; on failure open_ becomes false. NOT counted as a
                          // Connect failure here: the next try_acquire() re-hits the
                          // `!open_` check above and counts it there.
        return false;
    }
    // The try-lock was ANSWERED (either verdict): the connection is healthy.
    note_ok_locked();
    if (PQgetvalue(lock_res.get(), 0, 0)[0] != 't')
        return false; // another replica holds leadership -- the NORMAL follower
                      // outcome, deliberately not an acquire failure (WS-11)

    // Lock granted: emplace the release guard IMMEDIATELY so the lock cannot
    // leak on any subsequent failure path, then mint + record the new epoch.
    //
    // If the guard's constructor THROWS (it is deliberately non-noexcept and can
    // throw bad_alloc), the advisory lock is held on conn_ but UNTRACKED. PostgreSQL
    // session advisory locks are RE-ENTRANT, so a later try_acquire() on this same
    // never-recycled connection would re-grant a SECOND stacked hold that a single
    // guard can only half-release — a DURABLE leadership wedge locking out every
    // other process until the connection dies (PR #4134 review). So on any throw
    // here, CLOSE the connection: the backend's death releases every stacked hold,
    // and open_=false forces a fresh reconnect on the next attempt (no re-entrancy).
    try {
        lock_guard_.emplace(conn_.get(), lock_key_, "server background leader");
    } catch (...) {
        spdlog::error("leader_elector: lock-guard construction threw after the advisory lock was "
                      "granted; closing the coordination connection to release the untracked hold");
        acquire_failed_[static_cast<std::size_t>(AcquireFailure::LockGuard)].fetch_add(
            1, std::memory_order_relaxed);
        drop_leadership_locked(); // guard not emplaced (no-op reset) + clears epoch_ + publishes 0
        conn_ = pg::PgConn{};     // finish the connection → session death releases ALL stacked holds
        open_ = false;            // fail closed; next try_acquire() reconnects fresh
        return false;
    }

    pg::PgResult ep = pg::exec_params(conn_.get(), epoch_mint_sql().c_str(), mint_params_);
    if (ep.status() != PGRES_TUPLES_OK || PQntuples(ep.get()) != 1 || PQgetisnull(ep.get(), 0, 0) ||
        PQnfields(ep.get()) != 2 || PQgetisnull(ep.get(), 0, 1)) {
        spdlog::error("leader_elector: acquired lock but failed to record epoch; releasing");
        acquire_failed_[static_cast<std::size_t>(AcquireFailure::EpochRecord)].fetch_add(
            1, std::memory_order_relaxed);
        drop_leadership_locked();
        return false;
    }
    auto parsed = parse_i64(PQgetvalue(ep.get(), 0, 0));
    auto real_tl = parse_i64(PQgetvalue(ep.get(), 0, 1));
    // The SQL guarantees epoch >= (1 << 32) + 1; re-check here so a statement that ever
    // stopped guaranteeing it cannot leave epoch_ set while live_epoch_ publishes a
    // value the not-leader sentinel logic mishandles (cpp-safety C-3).
    if (!parsed || !real_tl || *parsed <= kEpochTimelineUnit) {
        spdlog::error("leader_elector: unparseable or out-of-range epoch; releasing");
        acquire_failed_[static_cast<std::size_t>(AcquireFailure::EpochRecord)].fetch_add(
            1, std::memory_order_relaxed);
        drop_leadership_locked();
        return false;
    }
    epoch_ = *parsed;
    // Publish the minted epoch (slice 3.2, #4013). A minted epoch is above 2^32 (the timeline
    // is >= 1 and in the high bits, #6535), so a non-zero value unambiguously means "leader
    // at this epoch" to a lock-free reader. Release-ordered to pair with the acquire loads
    // in is_leader/epoch. The acquisition is counted and the answer stamped BEFORE the
    // publish, so a lock-free reader that observes the new leadership also observes
    // acquired >= 1 and a non-zero last_ok (never is_leader=1 with acquired=0).
    acquired_.fetch_add(1, std::memory_order_relaxed);
    note_ok_locked();
    live_epoch_.store(*epoch_, std::memory_order_release);
    // A minted timeline part ABOVE the real timeline means the surviving leader_state row
    // (restored / copied from a higher timeline) is pinning the epoch: the lossy-promotion
    // protection (the timeline) is reduced until the real timeline passes it (#6535).
    if ((*parsed >> 32) > *real_tl) {
        spdlog::warn("leader_elector: minted epoch's timeline part {} is above the real "
                     "Postgres timeline {}: the surviving leader_state row carries a higher "
                     "timeline (restore / pg_upgrade / cutover). Fencing within this timeline "
                     "is unaffected, but the timeline protection against a lossy promotion is "
                     "absent (only the sequence separates epochs) until the real timeline "
                     "reaches {} (docs/user-manual/ha-postgres.md)",
                     *parsed >> 32, *real_tl, *parsed >> 32);
    }
    // holder_id (boot-random, not a secret) is logged once per acquire so a
    // `leader_state.holder_id` row is attributable to a process from its logs
    // (WS-11: it is deliberately NOT a metric label -- a per-boot value would be
    // unbounded series churn).
    spdlog::info("leader_elector: acquired leadership '{}' at epoch {} (timeline_part={} count_part={}, "
                 "holder_id={})",
                 cfg_.lock_name, *epoch_, *epoch_ >> 32, *epoch_ & kEpochCountMask, cfg_.holder_id);
    return true;
}

bool LeaderElector::is_leader() const {
    // Lock-free (slice 3.2, #4013): see the header note. A libpq probe stalled
    // under mu_ in the election loop must never block this reader.
    return live_epoch_.load(std::memory_order_acquire) > 0;
}

std::optional<std::int64_t> LeaderElector::epoch() const {
    const std::int64_t v = live_epoch_.load(std::memory_order_acquire);
    if (v <= 0)
        return std::nullopt;
    return v;
}

bool LeaderElector::heartbeat() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!epoch_.has_value())
        return false;
    pg::PgResult live = pg::exec_params(conn_.get(), "SELECT 1", std::vector<std::string>{});
    if (live.status() == PGRES_TUPLES_OK) {
        note_ok_locked();
        return true;
    }
    spdlog::warn("leader_elector: heartbeat failed; dropping leadership");
    drop_leadership_locked(LeadershipLoss::LivenessFailed);
    connect_locked(); // best-effort reconnect so a later try_acquire can re-lead
    return false;
}

void LeaderElector::resign() {
    std::lock_guard<std::mutex> lk(mu_);
    if (epoch_.has_value())
        spdlog::info("leader_elector: resigning leadership '{}'", cfg_.lock_name);
    drop_leadership_locked(LeadershipLoss::Resigned); // counts only if leadership was held
}

std::string LeaderElector::epoch_fence_sql(const std::string& lock_name, std::int64_t epoch) {
    // Fail closed: an invalid lock name fences everything out rather than
    // producing SQL that could admit a claim. is_valid_lock_name constrains
    // lock_name to [a-z][a-z0-9_]{0,47}, so the value below cannot break out of
    // the single-quoted literal; epoch is rendered from an integer.
    if (!is_valid_lock_name(lock_name)) {
        // An invalid lock_name is a programming error (the caller passed an
        // unvalidated name); mark it before slice 3.3 wires a real consumer.
        spdlog::warn("leader_elector: epoch_fence_sql got an invalid lock_name; fencing closed");
        return "(1=0)";
    }
    return "((SELECT current_leader_epoch FROM leader_elector.leader_state "
           "WHERE lock_key = '" +
           lock_name + "') = " + std::to_string(epoch) + ")";
}

} // namespace yuzu::server
