#pragma once

// test_directory_sync_pg_helper.hpp — shared PG-backed DirectorySync
// construction helper (ADR-0063, migration-programme PR 3) for every
// directory-sync fixture that used to open a SQLite
// `DirectorySync(":memory:")`.
//
// Mirrors test_offload_target_store_pg_helper.hpp's shape (no secrets seam
// here — DirectorySync has no ADR-0010 column, so no FileKeyProvider/
// SecretCodec chain is needed).
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "directory_sync.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_directory_sync_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::DirectorySync store{pool}; // migrates directory_sync's five tables
    if (!store.is_open())
        throw std::runtime_error("directorysync template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate directory_sync_pg_template{"directorysync",
                                                 &detail::setup_directory_sync_pg_template};

/// RAII bundle: ephemeral database + PgPool + DirectorySync, in
/// destruction-safe member order (declared last, so it destructs first) —
/// the same shape server.cpp uses. Behaves like a
/// `std::unique_ptr<DirectorySync>` at call sites (`get()`/`operator->`/
/// `operator*`).
class DirectorySyncPg {
public:
    explicit DirectorySyncPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(directory_sync_pg_template);
        INFO("[DirectorySyncPg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::DirectorySync>(*pool_);
        REQUIRE(store_->is_open());
    }

    DirectorySyncPg(const DirectorySyncPg&) = delete;
    DirectorySyncPg& operator=(const DirectorySyncPg&) = delete;
    DirectorySyncPg(DirectorySyncPg&&) = delete;
    DirectorySyncPg& operator=(DirectorySyncPg&&) = delete;

    /// Connection string of the ephemeral database backing this store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::DirectorySync* get() const noexcept { return store_.get(); }
    yuzu::server::DirectorySync* operator->() const noexcept { return store_.get(); }
    yuzu::server::DirectorySync& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Direct access to the pool for tests that need a second connection
    /// (e.g. asserting FK cascade behavior with a raw statement).
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::DirectorySync> store_;
};

} // namespace yuzu::test
