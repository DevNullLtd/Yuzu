#pragma once

// test_workflow_engine_pg_helper.hpp — shared PG-backed WorkflowEngine
// construction helper (ADR-0064/0009), mirroring
// test_schedule_engine_pg_helper.hpp's shape for the ADR-0031 WS-A4 eighth
// family's own wiring test (test_workflow_api.cpp).
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "pg/pg_pool.hpp"
#include "workflow_engine.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_workflow_engine_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::WorkflowEngine store{pool}; // migrates workflow_engine's four tables
    if (!store.is_open())
        throw std::runtime_error("wfengine_api template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate workflow_engine_api_pg_template{"wfengineapi",
                                                       &detail::setup_workflow_engine_pg_template};

/// RAII bundle: ephemeral database + PgPool + WorkflowEngine, in
/// destruction-safe member order (declared last, so it destructs first) —
/// the same shape server.cpp uses. Behaves like a
/// `std::unique_ptr<WorkflowEngine>` at call sites (`get()`/`operator->`/
/// `operator*`).
class WorkflowEnginePg {
public:
    explicit WorkflowEnginePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(workflow_engine_api_pg_template);
        INFO("[WorkflowEnginePg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::WorkflowEngine>(*pool_);
        REQUIRE(store_->is_open());
    }

    WorkflowEnginePg(const WorkflowEnginePg&) = delete;
    WorkflowEnginePg& operator=(const WorkflowEnginePg&) = delete;
    WorkflowEnginePg(WorkflowEnginePg&&) = delete;
    WorkflowEnginePg& operator=(WorkflowEnginePg&&) = delete;

    /// Connection string of the ephemeral database backing this store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::WorkflowEngine* get() const noexcept { return store_.get(); }
    yuzu::server::WorkflowEngine* operator->() const noexcept { return store_.get(); }
    yuzu::server::WorkflowEngine& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Direct access to the pool for tests that need a second connection.
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::WorkflowEngine> store_;
};

} // namespace yuzu::test
