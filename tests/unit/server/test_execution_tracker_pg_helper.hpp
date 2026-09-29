#pragma once

// test_execution_tracker_pg_helper.hpp — shared PG-backed ExecutionTracker
// construction helper (ADR-0065, migration-programme PR 5 commit 3/3) for
// every execution-tracker fixture that used to open a SQLite
// `ExecutionTracker(sqlite3*)`.
//
// Mirrors test_directory_sync_pg_helper.hpp's shape.
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "execution_tracker.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_execution_tracker_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::ExecutionTracker store{pool}; // migrates execution_tracker's two tables
    if (!store.is_open())
        throw std::runtime_error("exectracker template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate execution_tracker_pg_template{"exectracker",
                                                     &detail::setup_execution_tracker_pg_template};

/// RAII bundle: ephemeral database + PgPool + ExecutionTracker, in
/// destruction-safe member order (declared last, so it destructs first) —
/// the same shape server.cpp uses. Behaves like a
/// `std::unique_ptr<ExecutionTracker>` at call sites (`get()`/`operator->`/
/// `operator*`).
class ExecutionTrackerPg {
public:
    explicit ExecutionTrackerPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(execution_tracker_pg_template);
        INFO("[ExecutionTrackerPg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::ExecutionTracker>(*pool_);
        REQUIRE(store_->is_open());
    }

    ExecutionTrackerPg(const ExecutionTrackerPg&) = delete;
    ExecutionTrackerPg& operator=(const ExecutionTrackerPg&) = delete;
    ExecutionTrackerPg(ExecutionTrackerPg&&) = delete;
    ExecutionTrackerPg& operator=(ExecutionTrackerPg&&) = delete;

    /// Connection string of the ephemeral database backing this store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::ExecutionTracker* get() const noexcept { return store_.get(); }
    yuzu::server::ExecutionTracker* operator->() const noexcept { return store_.get(); }
    yuzu::server::ExecutionTracker& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Direct access to the pool for tests that need a second connection.
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::ExecutionTracker> store_;
};

} // namespace yuzu::test
