#pragma once

// test_offload_target_store_pg_helper.hpp — shared PG-backed
// OffloadTargetStore (+ its FileKeyProvider/SecretCodec dependency chain,
// ADR-0010/ADR-0059) construction helper for every offload-target-store/
// route fixture that used to open a SQLite `OffloadTargetStore(":memory:")`
// (test_offload_target_store.cpp, test_rest_offload_targets.cpp,
// test_agent_service_impl.cpp's EventSinkScope).
//
// Mirrors test_auth_db_pg_helper.hpp's shared-fixture shape exactly.
//
// Construction order mirrors server.cpp's ServerImpl OffloadTargetStore
// block EXACTLY (load-bearing — see offload_target_store.hpp's ctor doc
// comment): FileKeyProvider -> SecretCodec (constructed, NOT init'd yet) ->
// OffloadTargetStore (this migrates `offload_target_store.offload_targets`
// AND registers `auth_credential` as a secret column) -> SecretCodec::init()
// (runs AFTER the store so the column it validates already exists).
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "key_provider.hpp"
#include "offload_target_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_offload_target_store_pg_template(const std::string& dsn) {
    yuzu::test::TempDir keys;
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("offloadtarget template: connect failed");

    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::OffloadTargetStore store{pool, codec}; // migrates + registers the secret column
    if (!store.is_open())
        throw std::runtime_error("offloadtarget template: store failed to migrate");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("offloadtarget template: secret codec init failed");

    // Reset the fingerprint table — see test_auth_db_pg_helper.hpp's header
    // for why: the KEK lives on the template-build process's LOCAL keys
    // dir, which is gone by the time a clone runs; every clone mints its
    // own KEK into its own fresh TempDir instead.
    yuzu::server::pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("offloadtarget template: kek_meta reset failed");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate offload_target_store_pg_template{
    "offloadtarget", &detail::setup_offload_target_store_pg_template};

/// RAII bundle: ephemeral database + a fresh per-fixture keys dir +
/// FileKeyProvider + SecretCodec + PgPool + OffloadTargetStore, in
/// destruction-safe member order (declared last, so it destructs FIRST —
/// the store's delivery pool is quiesced by this class's own destructor
/// before that, and both the store and the pool close before the ephemeral
/// database is dropped) — the exact ordering server.cpp uses. Behaves like
/// a `std::unique_ptr<OffloadTargetStore>` at call sites (`get()`/
/// `operator->`/`operator*`).
class OffloadTargetStorePg {
public:
    explicit OffloadTargetStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(offload_target_store_pg_template);
        INFO("[OffloadTargetStorePg] fixture status (blank == database came up OK): "
             << db_->error());
        REQUIRE(db_->available());

        provider_ = std::make_unique<yuzu::server::FileKeyProvider>(keys_.path);
        codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*provider_);
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::OffloadTargetStore>(*pool_, *codec_);
        REQUIRE(store_->is_open());

        // Per-clone first-boot KEK generation (see file header) — needs a
        // connection of its own; the store's ctor above already released
        // its construction-only lease.
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto init_res = codec_->init(conn.get());
        INFO("[OffloadTargetStorePg] SecretCodec::init status (blank == ok): "
             << (init_res.has_value()
                     ? ""
                     : std::string(
                           yuzu::server::pg::SecretCodec::to_string(init_res.error().kind))));
        REQUIRE(init_res.has_value());
    }

    ~OffloadTargetStorePg() {
        // #3261-shaped safety: quiesce the delivery pool before the store
        // (and the secret_codec_/provider_ it borrows) tear down, exactly
        // like test_agent_service_impl.cpp's EventSinkScope destructor —
        // most tests never fire a real delivery, but the ones that do must
        // not race a worker-pool thread against this fixture's destruction.
        if (store_)
            store_->quiesce(std::chrono::seconds(5));
    }

    OffloadTargetStorePg(const OffloadTargetStorePg&) = delete;
    OffloadTargetStorePg& operator=(const OffloadTargetStorePg&) = delete;
    OffloadTargetStorePg(OffloadTargetStorePg&&) = delete;
    OffloadTargetStorePg& operator=(OffloadTargetStorePg&&) = delete;

    /// Connection string of the ephemeral database backing this store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::OffloadTargetStore* get() const noexcept { return store_.get(); }
    yuzu::server::OffloadTargetStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::OffloadTargetStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Direct access to the codec/pool for tests that need to reach in
    /// (e.g. corrupting a stored credential blob on a second connection).
    [[nodiscard]] yuzu::server::pg::SecretCodec& codec() noexcept { return *codec_; }
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    yuzu::test::TempDir keys_;
    std::unique_ptr<yuzu::server::FileKeyProvider> provider_;
    std::unique_ptr<yuzu::server::pg::SecretCodec> codec_;
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::OffloadTargetStore> store_;
};

} // namespace yuzu::test
