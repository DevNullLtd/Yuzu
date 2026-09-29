#pragma once

// test_result_set_store_pg_helper.hpp — shared PG-backed ResultSetStore
// construction helper (#2146 Batch B2), for the MCP result-set tool tests.
//
// Mirrors test_execution_tracker_pg_helper.hpp's shape exactly. Reuses the
// "resultset" PgTestTemplate key already shared by test_result_set_store.cpp
// and test_rest_result_sets_async.cpp (identical migration setup — see those
// files' own comments on the shared key).
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "result_set_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_result_set_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::ResultSetStore store{pool}; // migrates result_set_store's tables
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header — same "resultset" key as
/// test_result_set_store.cpp / test_rest_result_sets_async.cpp.
inline PgTestTemplate result_set_store_pg_template{"resultset",
                                                    &detail::setup_result_set_store_pg_template};

/// RAII bundle: ephemeral database + PgPool + ResultSetStore, in
/// destruction-safe member order (declared last, so it destructs first) —
/// the same shape server.cpp uses. Behaves like a
/// `std::unique_ptr<ResultSetStore>` at call sites (`get()`/`operator->`/
/// `operator*`).
class ResultSetStorePg {
public:
    explicit ResultSetStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(result_set_store_pg_template);
        INFO("[ResultSetStorePg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::ResultSetStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    ResultSetStorePg(const ResultSetStorePg&) = delete;
    ResultSetStorePg& operator=(const ResultSetStorePg&) = delete;
    ResultSetStorePg(ResultSetStorePg&&) = delete;
    ResultSetStorePg& operator=(ResultSetStorePg&&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::ResultSetStore* get() const noexcept { return store_.get(); }
    yuzu::server::ResultSetStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::ResultSetStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::ResultSetStore> store_;
};

} // namespace yuzu::test
