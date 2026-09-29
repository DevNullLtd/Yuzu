#pragma once

// test_analytics_pg_helper.hpp — shared PG-backed AnalyticsEventStore
// construction helper for fixtures that need it only as a secondary
// dependency (test_auth_routes*.cpp, test_auth_sso_identity.cpp,
// test_auth_jit_elevation.cpp, test_saml_routes.cpp, test_oidc_routes.cpp,
// test_mcp_server.cpp). Mirrors test_api_token_pg_helper.hpp's
// ApiTokenStorePg shape exactly. NOT used by test_schedule_routes.cpp or
// test_scim_routes.cpp — both of those construct AnalyticsEventStore
// directly against a pool an earlier fixture member already owns
// (rbac_pool / auth_db.pool()) rather than a second ephemeral database
// (governance Gate 4 consistency-auditor finding, 2026-08-16 — this
// comment previously claimed test_schedule_routes.cpp as a consumer).
//
// AnalyticsEventStore ported to Postgres (ADR-0049, schema
// `analytics_event_store`): every fixture that used to open it against a
// per-test SQLite temp file (or `:memory:`) now needs a live database.
// AnalyticsEventStorePg bundles the ephemeral clone database (from the
// shared "analytics" PgTestTemplate — one migration paid across the whole
// suite, not per test), the PgPool, and the store itself in
// destruction-safe order, so a fixture's constructor stays a one-liner:
//
//     yuzu::test::AnalyticsEventStorePg analytics_store;
//     ...
//     analytics_store->emit(...);   // AnalyticsEventStore* via operator->
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).
//
// The "analytics" template key is shared with test_analytics_event.cpp's own
// direct PgTestTemplate declaration (identical single-store setup), so the
// migration is paid once per suite run regardless of which TU asks first.

#include "analytics_event_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_analytics_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AnalyticsEventStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("analytics template: store failed to migrate");
}
} // namespace detail

inline PgTestTemplate analytics_pg_template{"analytics",
                                            &detail::setup_analytics_store_pg_template};

/// RAII bundle: ephemeral database + pool + AnalyticsEventStore, in
/// destruction-safe member order. Behaves like a
/// `std::unique_ptr<AnalyticsEventStore>` at call sites
/// (`get()`/`operator->`/`operator*`) so existing `analytics_store.get()` /
/// `analytics_store->emit(...)` fixture call sites port with only a type
/// change on the member declaration — no call-site rewrite needed.
class AnalyticsEventStorePg {
public:
    AnalyticsEventStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(analytics_pg_template);
        INFO("[AnalyticsEventStorePg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<yuzu::server::AnalyticsEventStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    AnalyticsEventStorePg(const AnalyticsEventStorePg&) = delete;
    AnalyticsEventStorePg& operator=(const AnalyticsEventStorePg&) = delete;
    AnalyticsEventStorePg(AnalyticsEventStorePg&&) = delete;
    AnalyticsEventStorePg& operator=(AnalyticsEventStorePg&&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::AnalyticsEventStore* get() const noexcept { return store_.get(); }
    yuzu::server::AnalyticsEventStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::AnalyticsEventStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Tear down early (store, then pool, then database) — mirrors
    /// `std::unique_ptr::reset()` for fixtures that sequence teardown
    /// explicitly.
    void reset() noexcept {
        store_.reset();
        pool_.reset();
        db_.reset();
    }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::AnalyticsEventStore> store_;
};

} // namespace yuzu::test
