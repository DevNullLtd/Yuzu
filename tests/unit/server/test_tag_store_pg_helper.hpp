#pragma once

// test_tag_store_pg_helper.hpp — shared PG-backed TagStore construction
// helper for fixtures that used to open TagStore against a per-test SQLite
// path or ":memory:" (test_tag_store.cpp, test_mcp_server.cpp,
// test_authz_model.cpp, test_rest_tag_routes.cpp, test_tag_scope_authz.cpp).
//
// TagStore is PG-only on this branch (ADR-0050, schema `tag_store`) — there
// is no path/":memory:" constructor. TagStorePg bundles the ephemeral clone
// database (from the shared "tagstore" PgTestTemplate), the PgPool, and the
// store itself in destruction-safe order, so a fixture stays a one-liner and
// existing `store.` / `&store` call sites port by binding a reference:
//
//     yuzu::test::TagStorePg tag_bundle;
//     TagStore& tags = *tag_bundle;   // all `tags.` / `&tags` unchanged
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset and REQUIREs a working database when it is set but broken — the same
// skip-vs-fail posture as every other [pg] test (mirrors RbacStorePg,
// test_rbac_store_pg_helper.hpp). Tests using this helper MUST carry the
// `[pg]` tag.

#include "tag_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_tag_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::TagStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("tagstore template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header. Keyed by name in PgTestTemplate's
/// registry — the setup lambda must stay behaviorally identical across every
/// declarer (the registry replay-verifies).
inline PgTestTemplate tag_store_pg_template{"tagstore", &detail::setup_tag_store_pg_template};

/// RAII bundle: ephemeral database + pool + TagStore, in destruction-safe
/// member order (store closes before the pool, the pool before the database
/// is dropped). Behaves like a `std::unique_ptr<TagStore>` at call sites
/// (`get()`/`operator->`/`operator*`).
class TagStorePg {
public:
    TagStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(tag_store_pg_template);
        INFO("[TagStorePg] fixture status (blank == database came up OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<yuzu::server::TagStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    TagStorePg(const TagStorePg&) = delete;
    TagStorePg& operator=(const TagStorePg&) = delete;
    TagStorePg(TagStorePg&&) = delete;
    TagStorePg& operator=(TagStorePg&&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::TagStore* get() const noexcept { return store_.get(); }
    yuzu::server::TagStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::TagStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    void reset() noexcept {
        store_.reset();
        pool_.reset();
        db_.reset();
    }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::TagStore> store_;
};

} // namespace yuzu::test
