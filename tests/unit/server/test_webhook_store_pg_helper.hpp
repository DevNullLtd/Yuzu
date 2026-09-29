#pragma once

// test_webhook_store_pg_helper.hpp — shared PG-backed WebhookStore (+ its
// FileKeyProvider/SecretCodec dependency chain, ADR-0006/ADR-0010/ADR-0057)
// construction helper. Mirrors test_auth_db_pg_helper.hpp's AuthDbPg shape
// exactly (that file's own header explains why — the same reasons apply
// here verbatim): construct-and-scope-destruct a self-contained bundle so
// every consumer (test_webhook_store.cpp, test_agent_service_impl.cpp, ...)
// gets one migration/KEK-mint per PgTestTemplate clone instead of
// re-deriving the FileKeyProvider/SecretCodec/WebhookStore wiring per file
// (docs/postgres-store-playbook.md's test-file-drift note — a second,
// diverging copy of this wiring is exactly the class of bug that note
// warns about).
//
// Construction order mirrors server.cpp's ServerImpl WebhookStore block
// EXACTLY: FileKeyProvider -> SecretCodec (constructed, NOT init'd yet) ->
// WebhookStore (this migrates `webhook_store.webhooks` AND registers
// `secret` as a secret column) -> SecretCodec::init() (runs AFTER
// WebhookStore so the column it validates already exists).
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "key_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "webhook_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_webhook_store_pg_template(const std::string& dsn) {
    yuzu::test::TempDir keys;
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("webhookstore template: connect failed");

    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::WebhookStore store{pool, codec}; // migrates + registers the secret column
    if (!store.is_open())
        throw std::runtime_error("webhookstore template: store failed to migrate");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("webhookstore template: secret codec init failed");

    // Every clone mints its own KEK against its own (fresh, per-fixture)
    // keys dir — see the file header.
    yuzu::server::pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("webhookstore template: kek_meta reset failed");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header.
inline PgTestTemplate webhook_store_pg_template{"webhookstorewire",
                                                &detail::setup_webhook_store_pg_template};

/// RAII bundle: ephemeral database + a fresh per-fixture keys dir +
/// FileKeyProvider + SecretCodec + PgPool + WebhookStore, in
/// destruction-safe member order — mirrors AuthDbPg
/// (test_auth_db_pg_helper.hpp). Behaves like a `std::unique_ptr<WebhookStore>`
/// at call sites (`get()`/`operator->`/`operator*`). Self-contained: no
/// caller-supplied pool/codec needed, so it drops straight into a plain
/// value member of another test fixture.
class WebhookStorePg {
public:
    WebhookStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(webhook_store_pg_template);
        INFO("[WebhookStorePg] fixture status (blank == database came up OK): " << db_->error());
        REQUIRE(db_->available());

        provider_ = std::make_unique<yuzu::server::FileKeyProvider>(keys_.path);
        codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*provider_);
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        store_ = std::make_unique<yuzu::server::WebhookStore>(*pool_, *codec_);
        REQUIRE(store_->is_open());

        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto init_res = codec_->init(conn.get());
        INFO("[WebhookStorePg] SecretCodec::init status (blank == ok): "
             << (init_res.has_value() ? "" : std::string(yuzu::server::pg::SecretCodec::to_string(
                                                  init_res.error().kind))));
        REQUIRE(init_res.has_value());
    }

    WebhookStorePg(const WebhookStorePg&) = delete;
    WebhookStorePg& operator=(const WebhookStorePg&) = delete;

    [[nodiscard]] std::string dsn() const { return db_->dsn(); }
    [[nodiscard]] yuzu::server::WebhookStore* get() const noexcept { return store_.get(); }
    yuzu::server::WebhookStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::WebhookStore& operator*() const noexcept { return *store_; }

    /// Direct access to the codec/pool for tests that need to reach in
    /// (e.g. corrupting a secret blob on a second connection).
    [[nodiscard]] yuzu::server::pg::SecretCodec& codec() noexcept { return *codec_; }
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    yuzu::test::TempDir keys_;
    std::unique_ptr<yuzu::server::FileKeyProvider> provider_;
    std::unique_ptr<yuzu::server::pg::SecretCodec> codec_;
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::WebhookStore> store_;
};

} // namespace yuzu::test
