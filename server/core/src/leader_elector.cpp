#include "leader_elector.hpp"

#include "pg/pg_exec.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <charconv>
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
    };
    return kMigrations;
}

LeaderElector::LeaderElector(Config cfg)
    : cfg_(std::move(cfg)),
      name_valid_(is_valid_lock_name(cfg_.lock_name)),
      lock_key_(make_lock_key(cfg_.lock_name)) {
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
    open_ = true;
    return true;
}

void LeaderElector::drop_leadership_locked() {
    lock_guard_.reset(); // runs pg_advisory_unlock on conn_ if it was held
    epoch_.reset();
    // Publish "not leader" (slice 3.2, #4013). Release-ordered so a reader that
    // observes 0 has seen every write the drop performed; ordered BEFORE any
    // subsequent reconnect so a live follower never reads a stale leader epoch.
    live_epoch_.store(0, std::memory_order_release);
}

bool LeaderElector::is_open() const {
    std::lock_guard<std::mutex> lk(mu_);
    return open_;
}

bool LeaderElector::try_acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!open_ && !connect_locked())
        return false;

    // Already leader: confirm the connection is live and keep the epoch.
    if (epoch_.has_value()) {
        pg::PgResult live = pg::exec_params(conn_.get(), "SELECT 1", std::vector<std::string>{});
        if (live.status() == PGRES_TUPLES_OK)
            return true;
        spdlog::warn("leader_elector: liveness check failed while leading; dropping and reconnecting");
        drop_leadership_locked();
        if (!connect_locked())
            return false;
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
        drop_leadership_locked();
        connect_locked(); // best-effort; on failure open_ becomes false
        return false;
    }
    if (PQgetvalue(lock_res.get(), 0, 0)[0] != 't')
        return false; // another replica holds leadership

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
        drop_leadership_locked(); // guard not emplaced (no-op reset) + clears epoch_ + publishes 0
        conn_ = pg::PgConn{};     // finish the connection → session death releases ALL stacked holds
        open_ = false;            // fail closed; next try_acquire() reconnects fresh
        return false;
    }

    pg::PgResult ep = pg::exec_params(
        conn_.get(),
        "WITH e AS (SELECT nextval('leader_elector.leader_epoch_seq') AS ep) "
        "INSERT INTO leader_elector.leader_state "
        "  (lock_key, current_leader_epoch, holder_id, acquired_at) "
        "SELECT $1, e.ep, $2, now() FROM e "
        "ON CONFLICT (lock_key) DO UPDATE "
        "  SET current_leader_epoch = EXCLUDED.current_leader_epoch, "
        "      holder_id = EXCLUDED.holder_id, acquired_at = now() "
        "RETURNING current_leader_epoch",
        std::vector<std::string>{cfg_.lock_name, cfg_.holder_id});
    if (ep.status() != PGRES_TUPLES_OK || PQntuples(ep.get()) != 1 || PQgetisnull(ep.get(), 0, 0)) {
        spdlog::error("leader_elector: acquired lock but failed to record epoch; releasing");
        drop_leadership_locked();
        return false;
    }
    auto parsed = parse_i64(PQgetvalue(ep.get(), 0, 0));
    if (!parsed) {
        spdlog::error("leader_elector: unparseable epoch; releasing");
        drop_leadership_locked();
        return false;
    }
    epoch_ = *parsed;
    // Publish the minted epoch (slice 3.2, #4013). Minted epochs are >= 1, so a
    // non-zero value unambiguously means "leader at this epoch" to a lock-free
    // reader. Release-ordered to pair with the acquire loads in is_leader/epoch.
    live_epoch_.store(*epoch_, std::memory_order_release);
    spdlog::info("leader_elector: acquired leadership '{}' at epoch {}", cfg_.lock_name, *epoch_);
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
    if (live.status() == PGRES_TUPLES_OK)
        return true;
    spdlog::warn("leader_elector: heartbeat failed; dropping leadership");
    drop_leadership_locked();
    connect_locked(); // best-effort reconnect so a later try_acquire can re-lead
    return false;
}

void LeaderElector::resign() {
    std::lock_guard<std::mutex> lk(mu_);
    if (epoch_.has_value())
        spdlog::info("leader_elector: resigning leadership '{}'", cfg_.lock_name);
    drop_leadership_locked();
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
