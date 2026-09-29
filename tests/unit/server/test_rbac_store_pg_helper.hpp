#pragma once

// test_rbac_store_pg_helper.hpp — shared PG-backed RbacStore construction
// helper for fixtures that used to open RbacStore against a per-test SQLite
// path or ":memory:" (test_authz_topology_floor.cpp, test_authz_model.cpp,
// test_rest_mgmt_group_roles_floor.cpp).
//
// RbacStore is PG-only on this branch (ADR-0041, schema `rbac_store`) — there
// is no path/":memory:" constructor. RbacStorePg bundles the ephemeral clone
// database (from the shared "rbacstore" PgTestTemplate — the SAME template
// test_rbac_store.cpp / test_discovery_routes.cpp / test_mcp_server.cpp
// declare, one migration+seed paid across the suite), the PgPool, and the
// store itself in destruction-safe order, so a fixture stays a one-liner and
// existing `store.` / `&store` call sites port by binding a reference:
//
//     yuzu::test::RbacStorePg rbac_bundle;
//     RbacStore& rbac = *rbac_bundle;   // all `rbac.` / `&rbac` unchanged
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset and REQUIREs a working database when it is set but broken — the same
// skip-vs-fail posture as every other [pg] test. Tests using this helper MUST
// carry the `[pg]` tag.

#include "rbac_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_rbac_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbacstore template: store failed to migrate/seed");
}
} // namespace detail

/// Process-wide template (one migration+seed run, cloned per fixture) shared
/// by every TU that includes this header. Keyed by name in PgTestTemplate's
/// registry, so it is the SAME "rbacstore" template test_rbac_store.cpp /
/// test_discovery_routes.cpp / test_mcp_server.cpp declare — the setup lambda
/// must stay behaviorally identical to those (registry replay-verifies).
inline PgTestTemplate rbac_store_pg_template{"rbacstore", &detail::setup_rbac_store_pg_template};

/// RAII bundle: ephemeral database + pool + RbacStore, in destruction-safe
/// member order (store closes before the pool, the pool before the database
/// is dropped). Behaves like a `std::unique_ptr<RbacStore>` at call sites
/// (`get()`/`operator->`/`operator*`).
class RbacStorePg {
public:
    RbacStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(rbac_store_pg_template);
        INFO("[RbacStorePg] fixture status (blank == database came up OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<yuzu::server::RbacStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    RbacStorePg(const RbacStorePg&) = delete;
    RbacStorePg& operator=(const RbacStorePg&) = delete;
    RbacStorePg(RbacStorePg&&) = delete;
    RbacStorePg& operator=(RbacStorePg&&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::RbacStore* get() const noexcept { return store_.get(); }
    yuzu::server::RbacStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::RbacStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    void reset() noexcept {
        store_.reset();
        pool_.reset();
        db_.reset();
    }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::RbacStore> store_;
};

} // namespace yuzu::test
