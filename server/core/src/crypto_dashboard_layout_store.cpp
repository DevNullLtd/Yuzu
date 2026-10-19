#include "crypto_dashboard_layout_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "crypto_dashboard_layout_store";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly. `widget_ids` is a JSONB
    // array of strings in display order; `updated_at` is epoch seconds of the last save;
    // `version` is the optimistic-concurrency counter (1 on first write, +1 per replace).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, "CREATE TABLE layouts ("
            "  username   TEXT PRIMARY KEY,"
            "  widget_ids JSONB NOT NULL,"
            "  updated_at BIGINT NOT NULL,"
            "  CONSTRAINT layouts_widget_ids_array CHECK (jsonb_typeof(widget_ids) = 'array'));"},
        // Appended, never folded into v1 (the runner applies only version > current). Rows
        // written before it read as version 1.
        {2, "ALTER TABLE layouts ADD COLUMN version BIGINT NOT NULL DEFAULT 1 "
            "CONSTRAINT layouts_version_positive CHECK (version >= 1);"},
    };
    return kMigrations;
}

// Strict UTF-8, no NUL: anything else cannot bind as TEXT (SQLSTATE 22021) and would read as a
// store fault rather than the caller's bad argument.
bool bindable(std::string_view v) {
    return v.find('\0') == std::string_view::npos && sanitize_utf8_strict(v) == v;
}

using Kind = CryptoLayoutStoreError::Kind;

std::unexpected<CryptoLayoutStoreError> fail(Kind kind, std::string message) {
    return std::unexpected(CryptoLayoutStoreError{kind, std::move(message)});
}

// The username check every call shares. An oversized name is logged by its LENGTH only.
std::optional<CryptoLayoutStoreError> username_error(std::string_view op, std::string_view user) {
    if (user.size() > CryptoDashboardLayoutStore::kMaxUsernameBytes) {
        spdlog::warn("CryptoDashboardLayoutStore: {} refused, username of {} bytes exceeds {}", op,
                     user.size(), CryptoDashboardLayoutStore::kMaxUsernameBytes);
        return CryptoLayoutStoreError{Kind::kInvalidInput, "username too long"};
    }
    if (user.empty() || !bindable(user))
        return CryptoLayoutStoreError{Kind::kInvalidInput, "invalid username"};
    return std::nullopt;
}

// A statement that did not answer as expected. A lost connection after a WRITE was sent is
// kOutcomeUnknown — Postgres may have committed it before the link dropped (autocommit, one
// statement) — while any failure on a live connection is a definite rollback (kQueryError).
// A read is never ambiguous: nothing was written either way.
CryptoLayoutStoreError statement_error(std::string_view op, PGconn* conn, bool write) {
    const bool lost = PQstatus(conn) == CONNECTION_BAD;
    spdlog::warn("CryptoDashboardLayoutStore: {} failed{}: {}", op,
                 lost ? " (connection lost)" : "", PQerrorMessage(conn));
    if (lost && write)
        return {Kind::kOutcomeUnknown, std::string(op) + ": connection lost, outcome unknown"};
    return {Kind::kQueryError, std::string(op) + ": query failed"};
}

} // namespace

CryptoDashboardLayoutStore::CryptoDashboardLayoutStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CryptoDashboardLayoutStore: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CryptoDashboardLayoutStore: schema migration failed");
        return;
    }
    open_ = true;
}

std::expected<std::optional<StoredCryptoLayout>, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::get(const std::string& username) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("get", username))
        return std::unexpected(std::move(*bad));
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        spdlog::warn("CryptoDashboardLayoutStore: get skipped, no connection within {} ms ({})",
                     timeout_.count(), pool_.last_error());
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT widget_ids::text, version FROM "
                                       "crypto_dashboard_layout_store.layouts WHERE username = $1",
                                       std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("get", lease.get(), /*write=*/false));
    if (PQntuples(res.get()) == 0)
        return std::optional<StoredCryptoLayout>{std::nullopt};
    const std::int64_t version = std::strtoll(PQgetvalue(res.get(), 0, 1), nullptr, 10);
    const auto j = nlohmann::json::parse(PQgetvalue(res.get(), 0, 0), nullptr,
                                         /*allow_exceptions=*/false);
    // The CHECK constraint keeps a non-array out; a non-string element can still be written by
    // hand or by a future build. Either is reported as corrupt, never served or dropped.
    if (j.is_discarded() || !j.is_array() ||
        !std::ranges::all_of(j, [](const nlohmann::json& v) { return v.is_string(); })) {
        spdlog::warn("CryptoDashboardLayoutStore: get found a stored layout that is not a JSON "
                     "array of strings");
        return std::unexpected(CryptoLayoutStoreError{
            Kind::kCorrupt, "stored layout is not a JSON array of strings", version});
    }
    StoredCryptoLayout out;
    out.version = version;
    out.widget_ids.reserve(j.size());
    for (const auto& v : j)
        out.widget_ids.push_back(v.get<std::string>());
    return std::optional<StoredCryptoLayout>{std::move(out)};
}

std::expected<std::int64_t, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::put(const std::string& username,
                                const std::vector<std::string>& widget_ids,
                                std::optional<std::int64_t> expected_version) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("put", username))
        return std::unexpected(std::move(*bad));
    if (widget_ids.size() > kMaxIds)
        return fail(Kind::kInvalidInput, "too many widget ids");
    if (expected_version && *expected_version < 1)
        return fail(Kind::kInvalidInput, "expected_version must be at least 1");
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& id : widget_ids) {
        if (id.empty() || id.size() > kMaxIdBytes || !bindable(id))
            return fail(Kind::kInvalidInput, "invalid widget id");
        arr.push_back(id);
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        spdlog::warn("CryptoDashboardLayoutStore: put skipped, no connection within {} ms ({})",
                     timeout_.count(), pool_.last_error());
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    std::vector<std::string> params{username, arr.dump(), std::to_string(now)};
    // ONE conditional statement either way, so the version check and the write are atomic.
    // A first write inserts only when no row exists (a concurrent first write waits on the
    // primary key, then does nothing); a replace updates only the expected version. No row
    // returned = the condition failed = kConflict.
    const char* sql =
        "INSERT INTO crypto_dashboard_layout_store.layouts (username, widget_ids, updated_at, "
        "version) VALUES ($1, $2::jsonb, $3::bigint, 1) ON CONFLICT (username) DO NOTHING "
        "RETURNING version";
    if (expected_version) {
        sql = "UPDATE crypto_dashboard_layout_store.layouts SET widget_ids = $2::jsonb, "
              "updated_at = $3::bigint, version = version + 1 WHERE username = $1 AND "
              "version = $4::bigint RETURNING version";
        params.push_back(std::to_string(*expected_version));
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql, params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("put", lease.get(), /*write=*/true));
    if (PQntuples(res.get()) != 1) {
        spdlog::info("CryptoDashboardLayoutStore: put refused, the stored layout changed since "
                     "it was read");
        return fail(Kind::kConflict, "the stored layout changed since it was read");
    }
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(res.get(), 0, 0), nullptr, 10));
}

std::expected<bool, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::erase(const std::string& username) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("erase", username))
        return std::unexpected(std::move(*bad));
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        spdlog::warn("CryptoDashboardLayoutStore: erase skipped, no connection within {} ms ({})",
                     timeout_.count(), pool_.last_error());
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    // RETURNING carries the outcome — never a changes()-style count (#1033 idiom).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM crypto_dashboard_layout_store.layouts WHERE username = $1 RETURNING 1",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("erase", lease.get(), /*write=*/true));
    return PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
