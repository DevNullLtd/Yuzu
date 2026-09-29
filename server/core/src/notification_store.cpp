#include "notification_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "notification_store";

// Bounded acquires (ADR-0012 §2). create() is called from agent-facing
// gRPC/response-handling code (agent_service_impl.cpp) on enrollment and
// execution-failure events — not a tight per-heartbeat hot path, but still
// short enough that a saturated pool never stalls that thread. Reads/other
// writes are dashboard HTTP handlers and can wait a little longer.
constexpr std::chrono::milliseconds kCreateAcquireTimeout{500};
constexpr std::chrono::milliseconds kReadAcquireTimeout{2000};
constexpr std::chrono::milliseconds kWriteAcquireTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so both tables land in `notification_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE notifications ("
         "  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  ts_ms     BIGINT NOT NULL,"
         "  level     TEXT NOT NULL DEFAULT 'info',"
         "  title     TEXT NOT NULL,"
         "  message   TEXT NOT NULL DEFAULT '',"
         "  read      BOOLEAN NOT NULL DEFAULT FALSE,"
         "  dismissed BOOLEAN NOT NULL DEFAULT FALSE);"
         "CREATE INDEX notifications_read_ts_idx ON notifications (read, ts_ms);"
         "CREATE INDEX notifications_ts_id_idx ON notifications (ts_ms DESC, id DESC);"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // notification_meta's sole purpose was the backfill idempotency marker,
        // which no longer has a writer. Version-bumped (not edited into v1)
        // because v1 has actually run against real dev/UAT databases.
        {2, "DROP TABLE IF EXISTS notification_meta;"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

Notification row_to_notification(PGresult* res, int row) {
    Notification n;
    int c = 0;
    n.id = to_i64(PQgetvalue(res, row, c++));
    n.timestamp = to_i64(PQgetvalue(res, row, c++));
    n.level = PQgetvalue(res, row, c++);
    n.title = PQgetvalue(res, row, c++);
    n.message = PQgetvalue(res, row, c++);
    n.read = to_bool(PQgetvalue(res, row, c++));
    n.dismissed = to_bool(PQgetvalue(res, row, c++));
    return n;
}

} // namespace

NotificationStore::NotificationStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("NotificationStore: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("NotificationStore: schema migration failed");
        return;
    }
    open_ = true;
}

int64_t NotificationStore::create(const std::string& level, const std::string& title,
                                  const std::string& message) {
    if (!open_)
        return -1;
    auto lease = pool_.try_acquire_for(kCreateAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: create skipped, no connection in time ({})",
                      pool_.last_error());
        return -1;
    }
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO notification_store.notifications (ts_ms, level, title, message) "
        "VALUES ($1::bigint, $2, $3, $4) RETURNING id",
        std::vector<std::string>{std::to_string(now_ms), level, title, message});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::debug("NotificationStore: create failed: {}", PQerrorMessage(lease.get()));
        return -1;
    }
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::vector<Notification> NotificationStore::list_unread(int limit) {
    std::vector<Notification> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: list_unread skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, ts_ms, level, title, message, read, dismissed "
        "FROM notification_store.notifications WHERE read = FALSE AND dismissed = FALSE "
        "ORDER BY ts_ms DESC LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: list_unread failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(row_to_notification(res.get(), i));
    return out;
}

std::vector<Notification> NotificationStore::list_all(int limit, int offset) {
    std::vector<Notification> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: list_all skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, ts_ms, level, title, message, read, dismissed "
        "FROM notification_store.notifications ORDER BY ts_ms DESC, id DESC "
        "LIMIT $1::bigint OFFSET $2::bigint",
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: list_all failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(row_to_notification(res.get(), i));
    return out;
}

bool NotificationStore::mark_read(int64_t id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: mark_read skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "UPDATE notification_store.notifications SET read = TRUE WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("NotificationStore: mark_read({}) failed: {}", id, PQerrorMessage(lease.get()));
        return false;
    }
    // PQcmdTuples(), not the bare PGRES_COMMAND_OK check above: that status
    // is identical whether the WHERE clause matched a row or not — the
    // #1033-class mutate-then-count trap this codebase's sqlite3_changes()
    // ban exists to close on the Postgres side too.
    return std::string_view(PQcmdTuples(res.get())) != "0";
}

bool NotificationStore::dismiss(int64_t id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: dismiss skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE notification_store.notifications SET dismissed = TRUE WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("NotificationStore: dismiss({}) failed: {}", id, PQerrorMessage(lease.get()));
        return false;
    }
    return std::string_view(PQcmdTuples(res.get())) != "0";
}

std::size_t NotificationStore::count_unread() {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: count_unread skipped, no connection in time ({})",
                      pool_.last_error());
        return 0;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM notification_store.notifications WHERE read = FALSE AND "
        "dismissed = FALSE",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: count_unread failed: {}", PQerrorMessage(lease.get()));
        return 0;
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

} // namespace yuzu::server
