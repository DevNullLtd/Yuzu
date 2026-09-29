#include "command_outbox_store.hpp"

#include "leader_elector.hpp" // LeaderElector::epoch_fence_sql — the embeddable epoch predicate
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

// Schema == snake_case(ClassName) with the Store suffix (ADR-0008 Update):
// CommandOutboxStore -> command_outbox_store. One schema, one table (`outbox`).
constexpr const char* kStoreName = "command_outbox_store";

// Lease-acquire deadlines (ADR-0012 §2). This store is a leader-driven
// background surface (a scheduler tick, a delivery loop) with no operator
// waiting on a request, so the deadlines are modest and the caller always has
// its own next tick to retry — a degrade is logged at `warn` + counted, never
// silently swallowed (posture is authoritative, but the CALLER, not this
// store, decides fail-closed on the typed error it returns).
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kReadTimeout{2000};

// Interpret the result of the fenced idempotent INSERT ... RETURNING plus its
// disambiguating existence read. `conn` is inside the caller's transaction.
OutboxEnqueueOutcome interpret_enqueue(PGconn* conn, const OutboxEnqueueRequest& req,
                                       const std::string& insert_sql,
                                       const std::vector<std::string>& params) {
    pg::PgResult res = pg::exec_params(conn, insert_sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("CommandOutboxStore: enqueue insert failed (occurrence {}): {}",
                     req.occurrence_id, PQresultErrorMessage(res.get()));
        return OutboxEnqueueOutcome::Degraded;
    }
    if (PQntuples(res.get()) == 1)
        return OutboxEnqueueOutcome::Enqueued;

    // Zero rows returned means EITHER the epoch fence rejected the write (a
    // stale ex-leader) OR the unique key (occurrence_id PK) already held the
    // row (an idempotency race another attempt/leader already won). `INSERT ...
    // ON CONFLICT DO NOTHING RETURNING` cannot tell the two apart on its own
    // (the playbook's PQ-tuples pitfall), so a disambiguating existence read
    // decides — and the two mean OPPOSITE things to the producer: AlreadyEnqueued
    // is an idempotent SUCCESS (advance), FencedOut is "not ours" (do not advance).
    pg::PgResult exists = pg::exec_params(
        conn, "SELECT 1 FROM command_outbox_store.outbox WHERE occurrence_id=$1 LIMIT 1",
        std::vector<std::string>{req.occurrence_id});
    if (exists.status() != PGRES_TUPLES_OK) {
        spdlog::warn("CommandOutboxStore: enqueue disambiguation read failed (occurrence {}): {}",
                     req.occurrence_id, PQresultErrorMessage(exists.get()));
        return OutboxEnqueueOutcome::Degraded;
    }
    return PQntuples(exists.get()) > 0 ? OutboxEnqueueOutcome::AlreadyEnqueued
                                       : OutboxEnqueueOutcome::FencedOut;
}

} // namespace

const std::vector<pg::PgMigration>& CommandOutboxStore::migrations() {
    // DDL is UNQUALIFIED — the runner sets search_path to this store's schema
    // for the migration transaction (playbook §2). `occurrence_id` is the
    // PRIMARY KEY: the structural idempotency guard (file-header guarantee 1).
    // The partial index serves the delivery loop's `list_pending` hot query
    // (`state='pending'` ordered by `next_attempt_at`) — a `pending` row is an
    // in-flight claim and is NEVER reap-eligible (WS-0 command-dedup shape).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         R"(
CREATE TABLE outbox (
    occurrence_id   TEXT        PRIMARY KEY,
    command_id      TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    plugin          TEXT        NOT NULL,
    action          TEXT        NOT NULL,
    scope_expr      TEXT        NOT NULL DEFAULT '',
    agent_ids       TEXT        NOT NULL DEFAULT '',
    parameters      TEXT        NOT NULL DEFAULT '',
    execution_id    TEXT        NOT NULL DEFAULT '',
    principal       TEXT        NOT NULL DEFAULT '',
    approval_id     TEXT        NOT NULL DEFAULT '',
    state           TEXT        NOT NULL DEFAULT 'pending',
    attempts        INTEGER     NOT NULL DEFAULT 0,
    note            TEXT        NOT NULL DEFAULT '',
    claimed_epoch   BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT outbox_state_ck CHECK (state IN ('pending','sent','failed'))
);
CREATE INDEX outbox_ready_idx ON outbox (next_attempt_at) WHERE state = 'pending';
)"},
    };
    return kMigrations;
}

CommandOutboxStore::CommandOutboxStore(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2); every runtime acquire
    // below is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CommandOutboxStore: no database connection at construction ({}) — "
                      "command outbox disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CommandOutboxStore: schema migration failed — command outbox disabled");
        return;
    }
    open_ = true;
    // ADR-0009 fresh-start-by-default: born on Postgres, no legacy SQLite file,
    // no backfill (this store never existed before WS-3).
    spdlog::info("CommandOutboxStore initialized (schema {}) — born on Postgres, no legacy "
                 "backfill",
                 kStoreName);
}

void CommandOutboxStore::count_degrade(const char* op, const char* reason) const {
    if (metrics_)
        metrics_->counter("yuzu_server_command_outbox_degrade_total",
                          {{"op", op}, {"reason", reason}})
            .increment();
}

OutboxEnqueueOutcome CommandOutboxStore::claim_and_enqueue_on(PGconn* conn,
                                                             const OutboxEnqueueRequest& req,
                                                             const std::string& leader_lock_name,
                                                             std::int64_t leader_epoch) {
    if (!open_) {
        count_degrade("enqueue", "not_open");
        return OutboxEnqueueOutcome::Degraded;
    }
    // The epoch fence is inlined into the writing statement (guarantee 2 +
    // the isolation contract): `epoch_fence_sql` renders a validated lock name
    // and an integer epoch as SQL literals, safe to splice beside the $N
    // placeholders. This is the FIRST data statement of the caller's txn.
    const std::string fence = LeaderElector::epoch_fence_sql(leader_lock_name, leader_epoch);
    const std::string sql =
        "INSERT INTO command_outbox_store.outbox "
        "(occurrence_id, command_id, source, plugin, action, scope_expr, agent_ids, "
        " parameters, execution_id, principal, approval_id, state, attempts, claimed_epoch) "
        "SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',0,$12 "
        "WHERE " + fence + " "
        "ON CONFLICT (occurrence_id) DO NOTHING "
        "RETURNING occurrence_id";
    const std::vector<std::string> params{
        req.occurrence_id, req.command_id, req.source,        req.plugin,   req.action,
        req.scope_expr,    req.agent_ids,  req.parameters,    req.execution_id, req.principal,
        req.approval_id,   std::to_string(leader_epoch)};
    OutboxEnqueueOutcome outcome = interpret_enqueue(conn, req, sql, params);
    if (outcome == OutboxEnqueueOutcome::Degraded)
        count_degrade("enqueue", "db_error");
    return outcome;
}

OutboxEnqueueOutcome CommandOutboxStore::claim_and_enqueue(const OutboxEnqueueRequest& req,
                                                           const std::string& leader_lock_name,
                                                           std::int64_t leader_epoch) {
    if (!open_) {
        count_degrade("enqueue", "not_open");
        return OutboxEnqueueOutcome::Degraded;
    }
    OutboxEnqueueOutcome outcome = OutboxEnqueueOutcome::Degraded;
    const bool committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) {
        outcome = claim_and_enqueue_on(c, req, leader_lock_name, leader_epoch);
        // Commit for every non-degraded outcome (Enqueued inserts a row;
        // AlreadyEnqueued/FencedOut commit an empty txn, which is harmless).
        // Roll back on Degraded so a query error leaves no partial state.
        return outcome != OutboxEnqueueOutcome::Degraded;
    });
    if (!committed) {
        // Either the acquire timed out (lambda never ran), the body degraded and
        // rolled back, or the COMMIT itself failed — all fail closed for the
        // producer.
        if (outcome != OutboxEnqueueOutcome::Degraded)
            count_degrade("enqueue", "commit_failed");
        return OutboxEnqueueOutcome::Degraded;
    }
    return outcome;
}

std::expected<std::vector<OutboxCommand>, CommandOutboxError>
CommandOutboxStore::list_pending(int limit) const {
    if (!open_) {
        count_degrade("list_pending", "not_open");
        return std::unexpected(CommandOutboxError::store_unavailable);
    }
    if (limit < 1)
        limit = 1;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("CommandOutboxStore::list_pending: lease timeout — degraded");
        count_degrade("list_pending", "lease_timeout");
        return std::unexpected(CommandOutboxError::store_unavailable);
    }
    // Oldest first; `next_attempt_at <= now()` so a rescheduled (backed-off) row
    // is not re-driven early. The partial index (`state='pending'`) serves this.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT occurrence_id, command_id, source, plugin, action, scope_expr, agent_ids, "
        "       parameters, execution_id, principal, approval_id, attempts "
        "FROM command_outbox_store.outbox "
        "WHERE state = 'pending' AND next_attempt_at <= now() "
        "ORDER BY next_attempt_at ASC, created_at ASC "
        "LIMIT $1",
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("CommandOutboxStore::list_pending: query failed: {}",
                      PQresultErrorMessage(res.get()));
        count_degrade("list_pending", "db_error");
        return std::unexpected(CommandOutboxError::db_error);
    }
    const int rows = PQntuples(res.get());
    std::vector<OutboxCommand> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        OutboxCommand c;
        c.occurrence_id = PQgetvalue(res.get(), i, 0);
        c.command_id = PQgetvalue(res.get(), i, 1);
        c.source = PQgetvalue(res.get(), i, 2);
        c.plugin = PQgetvalue(res.get(), i, 3);
        c.action = PQgetvalue(res.get(), i, 4);
        c.scope_expr = PQgetvalue(res.get(), i, 5);
        c.agent_ids = PQgetvalue(res.get(), i, 6);
        c.parameters = PQgetvalue(res.get(), i, 7);
        c.execution_id = PQgetvalue(res.get(), i, 8);
        c.principal = PQgetvalue(res.get(), i, 9);
        c.approval_id = PQgetvalue(res.get(), i, 10);
        // Parse attempts with from_chars (house idiom — sibling leader_elector.cpp
        // avoids atoi/<cstdlib>); a malformed value leaves attempts=0, harmless.
        const char* av = PQgetvalue(res.get(), i, 11);
        std::from_chars(av, av + std::char_traits<char>::length(av), c.attempts);
        out.push_back(std::move(c));
    }
    return out;
}

std::optional<std::int64_t> CommandOutboxStore::count_pending() const {
    if (!open_) {
        count_degrade("count_pending", "not_open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        count_degrade("count_pending", "lease_timeout");
        return std::nullopt;
    }
    // COUNT over the partial `outbox_ready_idx` (WHERE state='pending'). Not
    // due-gated (`next_attempt_at`) on purpose: the gauge is total pending
    // backlog, including rows currently backed off, so a stuck-and-growing queue
    // is visible even when nothing is due this instant.
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT count(*) FROM command_outbox_store.outbox WHERE state='pending'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        count_degrade("count_pending", "db_error");
        return std::nullopt;
    }
    std::int64_t n = 0;
    const char* v = PQgetvalue(res.get(), 0, 0);
    std::from_chars(v, v + std::char_traits<char>::length(v), n);
    return n;
}

std::expected<bool, CommandOutboxError>
CommandOutboxStore::fenced_transition(const char* sql, const std::vector<std::string>& params,
                                      const char* op_label) {
    if (!open_) {
        count_degrade(op_label, "not_open");
        return std::unexpected(CommandOutboxError::store_unavailable);
    }
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("CommandOutboxStore::{}: lease timeout — degraded", op_label);
        count_degrade(op_label, "lease_timeout");
        return std::unexpected(CommandOutboxError::store_unavailable);
    }
    // Single autocommit statement — atomic on its own, so the embedded epoch
    // fence is the first (and only) data statement of its implicit transaction.
    pg::PgResult res = pg::exec_params(lease.get(), sql, params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("CommandOutboxStore::{}: query failed: {}", op_label,
                      PQresultErrorMessage(res.get()));
        count_degrade(op_label, "db_error");
        return std::unexpected(CommandOutboxError::db_error);
    }
    // Zero rows == already terminal, no such row, OR fenced out (a stale
    // ex-leader). All three are "did not transition" to the caller; the row, if
    // it exists, stays pending for the true leader to re-drive.
    return PQntuples(res.get()) > 0;
}

std::expected<bool, CommandOutboxError>
CommandOutboxStore::mark_sent(const std::string& occurrence_id, const std::string& leader_lock_name,
                              std::int64_t leader_epoch) {
    const std::string fence = LeaderElector::epoch_fence_sql(leader_lock_name, leader_epoch);
    const std::string sql =
        "UPDATE command_outbox_store.outbox SET state='sent', updated_at=now() "
        "WHERE occurrence_id=$1 AND state='pending' AND " + fence + " RETURNING occurrence_id";
    return fenced_transition(sql.c_str(), std::vector<std::string>{occurrence_id}, "mark_sent");
}

std::expected<bool, CommandOutboxError>
CommandOutboxStore::mark_failed(const std::string& occurrence_id,
                                const std::string& leader_lock_name, std::int64_t leader_epoch,
                                const std::string& reason) {
    const std::string fence = LeaderElector::epoch_fence_sql(leader_lock_name, leader_epoch);
    const std::string sql =
        "UPDATE command_outbox_store.outbox SET state='failed', note=$2, updated_at=now() "
        "WHERE occurrence_id=$1 AND state='pending' AND " + fence + " RETURNING occurrence_id";
    return fenced_transition(sql.c_str(), std::vector<std::string>{occurrence_id, reason},
                             "mark_failed");
}

std::expected<bool, CommandOutboxError>
CommandOutboxStore::reschedule(const std::string& occurrence_id,
                               const std::string& leader_lock_name, std::int64_t leader_epoch,
                               std::chrono::seconds delay) {
    const std::string fence = LeaderElector::epoch_fence_sql(leader_lock_name, leader_epoch);
    // Stay pending; bump attempts; push the retry out by `delay` so a transient
    // delivery failure backs off instead of hot-looping the delivery tick.
    const std::string sql =
        "UPDATE command_outbox_store.outbox "
        "SET attempts = attempts + 1, updated_at = now(), "
        "    next_attempt_at = now() + ($2 || ' seconds')::interval "
        "WHERE occurrence_id=$1 AND state='pending' AND " + fence + " RETURNING occurrence_id";
    return fenced_transition(
        sql.c_str(),
        std::vector<std::string>{occurrence_id, std::to_string(delay.count())}, "reschedule");
}

} // namespace yuzu::server
