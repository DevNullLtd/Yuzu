#pragma once

// test_approval_manager_pg_helper.hpp — shared PG-backed ApprovalManager
// construction helper (ADR-0065, migration-programme PR 5 commit 2/3) for
// every approval-manager fixture that used to open a SQLite
// `ApprovalManager(sqlite3*)`.
//
// Mirrors test_directory_sync_pg_helper.hpp's shape.
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "approval_manager.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_approval_manager_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::ApprovalManager store{pool}; // migrates approval_manager's one table
    if (!store.is_open())
        throw std::runtime_error("approvalmgr template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate approval_manager_pg_template{"approvalmgr",
                                                    &detail::setup_approval_manager_pg_template};

/// RAII bundle: ephemeral database + PgPool + ApprovalManager, in
/// destruction-safe member order (declared last, so it destructs first) —
/// the same shape server.cpp uses. Behaves like a
/// `std::unique_ptr<ApprovalManager>` at call sites (`get()`/`operator->`/
/// `operator*`).
class ApprovalManagerPg {
public:
    explicit ApprovalManagerPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(approval_manager_pg_template);
        INFO("[ApprovalManagerPg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::ApprovalManager>(*pool_);
        REQUIRE(store_->is_open());
    }

    ApprovalManagerPg(const ApprovalManagerPg&) = delete;
    ApprovalManagerPg& operator=(const ApprovalManagerPg&) = delete;
    ApprovalManagerPg(ApprovalManagerPg&&) = delete;
    ApprovalManagerPg& operator=(ApprovalManagerPg&&) = delete;

    /// Connection string of the ephemeral database backing this store — the
    /// seam a fault-injection test uses to open its OWN second connection
    /// or pool against the SAME database (e.g. holding the sole connection
    /// of a size-1 pool, or a raw libpq connection running a fault-
    /// injecting trigger DDL).
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::ApprovalManager* get() const noexcept { return store_.get(); }
    yuzu::server::ApprovalManager* operator->() const noexcept { return store_.get(); }
    yuzu::server::ApprovalManager& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Direct access to the pool for tests that need a second connection.
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::ApprovalManager> store_;
};

} // namespace yuzu::test
