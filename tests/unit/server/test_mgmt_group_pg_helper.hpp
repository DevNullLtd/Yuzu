#pragma once

// test_mgmt_group_pg_helper.hpp — shared PG-backed ManagementGroupStore
// construction helper for the fixtures that used to open it against a per-test
// SQLite temp file (test_list_read_confinement.cpp, test_dashboard_tar_*.cpp,
// test_policy_evaluator.cpp, test_rbac_store.cpp scoped tests).
//
// ManagementGroupStore ported to Postgres (ADR-0042, schema
// `management_group_store`): every fixture that used to build
// `ManagementGroupStore mg{tmp.path}` now needs a live database.
// ManagementGroupStorePg bundles the ephemeral clone database (from a shared
// "mgmtgroupstore" PgTestTemplate — one migration paid across the suite), the
// PgPool, and the store itself in destruction-safe order, so a fixture stays a
// one-liner and existing `mg.` / `&mg` call sites port by binding a reference:
//
//     yuzu::test::ManagementGroupStorePg mg_bundle;
//     ManagementGroupStore& mg = *mg_bundle;   // all `mg.` / `&mg` unchanged
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset
// and REQUIREs a working database when it is set but broken — the same skip-vs-
// fail posture as every other [pg] test. Tests using this helper MUST carry the
// `[pg]` tag.

#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_mgmt_group_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("mgmtgroupstore template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header. Keyed by name in PgTestTemplate's
/// registry, so it is the SAME "mgmtgroupstore" template the store's own unit
/// test declares.
inline PgTestTemplate mgmt_group_pg_template{"mgmtgroupstore",
                                             &detail::setup_mgmt_group_store_pg_template};

/// RAII bundle: ephemeral database + pool + ManagementGroupStore, in
/// destruction-safe member order (store closes before the pool, the pool before
/// the database is dropped). Behaves like a `std::unique_ptr<ManagementGroupStore>`
/// at call sites (`get()`/`operator->`/`operator*`).
class ManagementGroupStorePg {
public:
    ManagementGroupStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(mgmt_group_pg_template);
        INFO("[ManagementGroupStorePg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<yuzu::server::ManagementGroupStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    ManagementGroupStorePg(const ManagementGroupStorePg&) = delete;
    ManagementGroupStorePg& operator=(const ManagementGroupStorePg&) = delete;
    ManagementGroupStorePg(ManagementGroupStorePg&&) = delete;
    ManagementGroupStorePg& operator=(ManagementGroupStorePg&&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::ManagementGroupStore* get() const noexcept { return store_.get(); }
    yuzu::server::ManagementGroupStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::ManagementGroupStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    void reset() noexcept {
        store_.reset();
        pool_.reset();
        db_.reset();
    }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::ManagementGroupStore> store_;
};

} // namespace yuzu::test
