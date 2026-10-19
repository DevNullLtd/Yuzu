#include "crypto_dashboard_layout_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "crypto_dashboard_layout_store";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly. `widget_ids` is a JSONB
    // array of strings in display order; `updated_at` is epoch seconds of the last save.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, "CREATE TABLE layouts ("
            "  username   TEXT PRIMARY KEY,"
            "  widget_ids JSONB NOT NULL,"
            "  updated_at BIGINT NOT NULL,"
            "  CONSTRAINT layouts_widget_ids_array CHECK (jsonb_typeof(widget_ids) = 'array'));"},
    };
    return kMigrations;
}

// Strict UTF-8, no NUL: anything else cannot bind as TEXT (SQLSTATE 22021) and would read as a
// store fault rather than the caller's bad argument.
bool bindable(std::string_view v) {
    return v.find('\0') == std::string_view::npos && sanitize_utf8_strict(v) == v;
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

std::expected<std::optional<std::vector<std::string>>, std::string>
CryptoDashboardLayoutStore::get(const std::string& username) {
    if (!open_)
        return std::unexpected("dashboard layout store is not open");
    if (username.empty() || username.size() > kMaxUsernameBytes || !bindable(username))
        return std::unexpected("invalid username");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        spdlog::debug("CryptoDashboardLayoutStore: get skipped, no connection in time ({})",
                      pool_.last_error());
        return std::unexpected("no database connection in time");
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT widget_ids::text FROM crypto_dashboard_layout_store.layouts WHERE username = $1",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CryptoDashboardLayoutStore: get failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected("query failed");
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::vector<std::string>>{std::nullopt};
    const auto j = nlohmann::json::parse(PQgetvalue(res.get(), 0, 0), nullptr,
                                         /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_array())
        return std::unexpected("stored layout is not a JSON array");
    std::vector<std::string> ids;
    ids.reserve(j.size());
    for (const auto& v : j) {
        if (!v.is_string())
            return std::unexpected("stored layout holds a non-string id");
        ids.push_back(v.get<std::string>());
    }
    return std::optional<std::vector<std::string>>{std::move(ids)};
}

std::expected<void, std::string>
CryptoDashboardLayoutStore::put(const std::string& username,
                                const std::vector<std::string>& widget_ids) {
    if (!open_)
        return std::unexpected("dashboard layout store is not open");
    if (username.empty() || username.size() > kMaxUsernameBytes || !bindable(username))
        return std::unexpected("invalid username");
    if (widget_ids.size() > kMaxIds)
        return std::unexpected("too many widget ids");
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& id : widget_ids) {
        if (id.empty() || id.size() > kMaxIdBytes || !bindable(id))
            return std::unexpected("invalid widget id");
        arr.push_back(id);
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        spdlog::debug("CryptoDashboardLayoutStore: put skipped, no connection in time ({})",
                      pool_.last_error());
        return std::unexpected("no database connection in time");
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    // RETURNING, not a bare PGRES_COMMAND_OK: a returned row proves the upsert landed.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO crypto_dashboard_layout_store.layouts (username, widget_ids, updated_at) "
        "VALUES ($1, $2::jsonb, $3::bigint) ON CONFLICT (username) DO UPDATE SET "
        "widget_ids = EXCLUDED.widget_ids, updated_at = EXCLUDED.updated_at RETURNING username",
        std::vector<std::string>{username, arr.dump(), std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::debug("CryptoDashboardLayoutStore: put failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected("query failed");
    }
    return {};
}

} // namespace yuzu::server
