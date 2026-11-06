#include "software_collection_settings_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdlib>

namespace yuzu::server {

namespace {

namespace cs = collection_settings;
using Kind = SoftwareCollectionSettingsStore::Error::Kind;
using Error = SoftwareCollectionSettingsStore::Error;

constexpr const char* kStoreName = "software_collection_settings_store";

constexpr const char* kCols = "group_id, interval_s, window_start_min, window_end_min, timezone, "
                              "plugins_json, priority, version, updated_at, updated_by";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE settings ("
         "  group_id         TEXT PRIMARY KEY,"
         "  interval_s       INT NOT NULL CHECK (interval_s BETWEEN 3600 AND 604800),"
         "  window_start_min INT,"
         "  window_end_min   INT,"
         "  timezone         TEXT NOT NULL DEFAULT '',"
         "  plugins_json     TEXT NOT NULL,"
         "  priority         INT NOT NULL DEFAULT 0 CHECK (priority BETWEEN 0 AND 1000),"
         "  version          TEXT NOT NULL,"
         "  updated_at       BIGINT NOT NULL,"
         "  updated_by       TEXT NOT NULL DEFAULT '',"
         "  CHECK ((window_start_min IS NULL) = (window_end_min IS NULL)));"
         "CREATE TABLE settings_history ("
         "  id          BIGSERIAL PRIMARY KEY,"
         "  group_id    TEXT NOT NULL,"
         "  before_json TEXT,"
         "  after_json  TEXT NOT NULL,"
         "  actor       TEXT NOT NULL DEFAULT '',"
         "  at          BIGINT NOT NULL);"
         "CREATE INDEX settings_history_group_idx ON settings_history (group_id, id DESC);"},
    };
    return kMigrations;
}

// Strict UTF-8, no NUL: anything else cannot bind as TEXT (SQLSTATE 22021) and would read as a
// store fault rather than the caller's bad argument.
bool bindable(std::string_view v) {
    return v.find('\0') == std::string_view::npos && sanitize_utf8_strict(v) == v;
}

bool valid_group_id(std::string_view id) {
    return !id.empty() && id.size() <= SoftwareCollectionSettingsStore::kMaxGroupIdBytes &&
           cs::is_lower_hex(id);
}

std::unexpected<Error> fail(Kind kind, std::string message) {
    return std::unexpected(Error{kind, std::move(message), std::nullopt});
}

// The SQLSTATE only: a libpq message can quote the failing row.
std::string_view sqlstate(const pg::PgResult& res) {
    const char* code = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return code ? std::string_view(code) : std::string_view("none");
}

Error statement_error(std::string_view op, const pg::PgResult& res, Kind kind) {
    spdlog::warn("SoftwareCollectionSettingsStore: {} failed (SQLSTATE {})", op, sqlstate(res));
    return Error{kind, std::string(op) + ": query failed", std::nullopt};
}

// One audit/history rendering of a settings document.
std::string settings_text(const cs::CollectionSettings& s) {
    nlohmann::json j = nlohmann::json::object();
    j["interval_s"] = s.interval_s;
    j["window"] = s.window ? nlohmann::json{{"start_min", s.window->start_min},
                                            {"end_min", s.window->end_min}}
                           : nlohmann::json(nullptr);
    j["timezone"] = s.timezone;
    j["plugins"] = s.plugins;
    j["priority"] = s.priority;
    return j.dump();
}

std::optional<std::string> cell(const pg::PgResult& res, int row, int col) {
    if (PQgetisnull(res.get(), row, col))
        return std::nullopt;
    return std::string(PQgetvalue(res.get(), row, col));
}

std::int64_t cell_i64(const pg::PgResult& res, int row, int col) {
    return std::strtoll(PQgetvalue(res.get(), row, col), nullptr, 10);
}

// Row -> document under the read rule in the header. nullopt = Corrupt.
std::optional<cs::StoredDocument> parse_row(const pg::PgResult& res, int row) {
    cs::StoredDocument d;
    d.group_id = PQgetvalue(res.get(), row, 0);
    d.settings.interval_s = static_cast<int>(cell_i64(res, row, 1));
    const auto ws = cell(res, row, 2);
    const auto we = cell(res, row, 3);
    if (ws.has_value() != we.has_value())
        return std::nullopt;
    if (ws)
        d.settings.window = cs::Window{static_cast<int>(std::strtol(ws->c_str(), nullptr, 10)),
                                       static_cast<int>(std::strtol(we->c_str(), nullptr, 10))};
    d.settings.timezone = PQgetvalue(res.get(), row, 4);
    const auto j = nlohmann::json::parse(PQgetvalue(res.get(), row, 5), nullptr,
                                         /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return std::nullopt;
    for (const auto& [name, v] : j.items()) {
        if (!cs::is_collection_plugin(name) || !v.is_boolean())
            return std::nullopt;
        d.settings.plugins[name] = v.get<bool>();
    }
    // A known key absent from the row reads as the fleet default (on); registered apps is on.
    for (const auto p : cs::kCollectionPlugins)
        d.settings.plugins.emplace(std::string{p}, true);
    d.settings.plugins[std::string{cs::kRegisteredAppsPlugin}] = true;
    d.settings.priority = static_cast<int>(cell_i64(res, row, 6));
    d.version = PQgetvalue(res.get(), row, 7);
    d.updated_at = cell_i64(res, row, 8);
    d.updated_by = PQgetvalue(res.get(), row, 9);
    if (!cs::validate(d.settings, d.group_id == cs::kRootGroupId))
        return std::nullopt;
    return d;
}

constexpr const char* kCorruptMessage = "a stored collection settings row failed the read rule";

} // namespace

SoftwareCollectionSettingsStore::SoftwareCollectionSettingsStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareCollectionSettingsStore: no database connection at construction "
                      "({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareCollectionSettingsStore: schema migration failed");
        return;
    }
    open_ = true;
}

std::expected<std::optional<cs::StoredDocument>, Error>
SoftwareCollectionSettingsStore::get(const std::string& group_id) {
    if (!open_)
        return fail(Kind::Unavailable, "collection settings store is not open");
    if (!valid_group_id(group_id))
        return fail(Kind::InvalidInput, "invalid group id");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease)
        return fail(Kind::Unavailable, "no database connection in time");
    const std::string sql = std::string("SELECT ") + kCols +
                            " FROM software_collection_settings_store.settings WHERE group_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{group_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("get", res, Kind::Unavailable));
    if (PQntuples(res.get()) == 0)
        return std::optional<cs::StoredDocument>{std::nullopt};
    auto doc = parse_row(res, 0);
    if (!doc) {
        spdlog::warn("SoftwareCollectionSettingsStore: get found a corrupt row");
        return fail(Kind::Corrupt, kCorruptMessage);
    }
    return std::optional<cs::StoredDocument>{std::move(*doc)};
}

std::expected<std::vector<cs::StoredDocument>, Error> SoftwareCollectionSettingsStore::list_all() {
    if (!open_)
        return fail(Kind::Unavailable, "collection settings store is not open");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease)
        return fail(Kind::Unavailable, "no database connection in time");
    const std::string sql = std::string("SELECT ") + kCols +
                            " FROM software_collection_settings_store.settings ORDER BY group_id "
                            "LIMIT " +
                            std::to_string(kListRowCap + 1);
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("list_all", res, Kind::Unavailable));
    const int n = PQntuples(res.get());
    if (n > kListRowCap)
        return fail(Kind::TooMany, "more collection settings rows than the list cap");
    std::vector<cs::StoredDocument> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        auto doc = parse_row(res, i);
        if (!doc) {
            spdlog::warn("SoftwareCollectionSettingsStore: list_all found a corrupt row");
            return fail(Kind::Corrupt, kCorruptMessage);
        }
        out.push_back(std::move(*doc));
    }
    return out;
}

std::expected<SoftwareCollectionSettingsStore::PutResult, Error>
SoftwareCollectionSettingsStore::put(const std::string& group_id,
                                     const cs::CollectionSettings& settings,
                                     const std::optional<std::string>& expected_version,
                                     std::string_view actor) {
    if (!open_)
        return fail(Kind::Unavailable, "collection settings store is not open");
    if (!valid_group_id(group_id))
        return fail(Kind::InvalidInput, "invalid group id");
    if (!bindable(actor) || actor.size() > 1024)
        return fail(Kind::InvalidInput, "invalid actor");
    if (expected_version && !cs::is_version_text(*expected_version))
        return fail(Kind::InvalidInput, "expected_version must be 64 lowercase hex characters");
    if (auto ok = cs::validate(settings, group_id == cs::kRootGroupId); !ok)
        return fail(Kind::InvalidInput, ok.error());
    const auto version = cs::document_version(settings);
    if (!version)
        return fail(Kind::WriteFailed, "digest provider failed");

    const std::string plugins = nlohmann::json(settings.plugins).dump();
    const std::string after_json = settings_text(settings);
    const std::vector<std::optional<std::string>> write_params{
        group_id,
        std::to_string(settings.interval_s),
        settings.window ? std::optional<std::string>{std::to_string(settings.window->start_min)}
                        : std::nullopt,
        settings.window ? std::optional<std::string>{std::to_string(settings.window->end_min)}
                        : std::nullopt,
        settings.timezone,
        plugins,
        std::to_string(settings.priority),
        *version,
        std::string(actor),
    };

    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease)
        return fail(Kind::Unavailable, "no database connection in time");

    std::optional<Error> error;
    std::optional<PutResult> result;
    bool body_done = false;

    const bool committed = pool_.with_txn_on(std::move(lease), [&](PGconn* c) -> bool {
        const auto fail_stmt = [&](std::string_view op, const pg::PgResult& r) {
            error = statement_error(op, r, Kind::WriteFailed);
            return false;
        };
        if (!settings.timezone.empty()) {
            pg::PgResult tz = pg::exec_params(
                c, "SELECT 1 FROM pg_timezone_names WHERE name = $1",
                std::vector<std::string>{settings.timezone});
            if (tz.status() != PGRES_TUPLES_OK) {
                // The check could not run: refuse the save, never skip the check.
                error = statement_error("timezone check", tz, Kind::Unavailable);
                return false;
            }
            if (PQntuples(tz.get()) == 0) {
                error = Error{Kind::InvalidTimezone, "timezone is not a known IANA zone",
                              std::nullopt};
                return false;
            }
        }

        const std::string cols = kCols;
        std::optional<cs::StoredDocument> previous;
        pg::PgResult written;
        if (!expected_version) {
            const std::string sql =
                "INSERT INTO software_collection_settings_store.settings (group_id, interval_s, "
                "window_start_min, window_end_min, timezone, plugins_json, priority, version, "
                "updated_at, updated_by) VALUES ($1, $2::int, $3::int, $4::int, $5, $6, $7::int, "
                "$8, EXTRACT(EPOCH FROM now())::bigint, $9) ON CONFLICT (group_id) DO NOTHING "
                "RETURNING " +
                cols;
            written = pg::exec_params(c, sql.c_str(), write_params);
            if (written.status() != PGRES_TUPLES_OK)
                return fail_stmt("create", written);
            if (PQntuples(written.get()) == 0) {
                // A concurrent create won the unique index: report the winner.
                const std::string sel = "SELECT " + cols +
                                        " FROM software_collection_settings_store.settings "
                                        "WHERE group_id = $1";
                pg::PgResult cur =
                    pg::exec_params(c, sel.c_str(), std::vector<std::string>{group_id});
                if (cur.status() != PGRES_TUPLES_OK)
                    return fail_stmt("create conflict read", cur);
                Error conflict{Kind::Conflict, "a document exists for this group",
                               std::nullopt};
                if (PQntuples(cur.get()) == 1) {
                    conflict.current = parse_row(cur, 0);
                    // A row that fails the read rule is Corrupt, never a 409 whose `current`
                    // reads as "no document exists".
                    if (!conflict.current) {
                        error = Error{Kind::Corrupt, kCorruptMessage, std::nullopt};
                        return false;
                    }
                }
                error = std::move(conflict);
                return false;
            }
        } else {
            const std::string sel = "SELECT " + cols +
                                    " FROM software_collection_settings_store.settings "
                                    "WHERE group_id = $1 FOR UPDATE";
            pg::PgResult cur = pg::exec_params(c, sel.c_str(), std::vector<std::string>{group_id});
            if (cur.status() != PGRES_TUPLES_OK)
                return fail_stmt("update read", cur);
            if (PQntuples(cur.get()) == 0) {
                error = Error{Kind::Conflict, "no document exists for this group", std::nullopt};
                return false;
            }
            previous = parse_row(cur, 0);
            // Corrupt first: a 409 carrying `current: null` would read as "no document exists".
            if (!previous) {
                error = Error{Kind::Corrupt, kCorruptMessage, std::nullopt};
                return false;
            }
            if (previous->version != *expected_version) {
                error = Error{Kind::Conflict, "the stored document changed since the caller read it",
                              previous};
                return false;
            }
            std::vector<std::optional<std::string>> params = write_params;
            params.emplace_back(*expected_version);
            const std::string sql =
                "UPDATE software_collection_settings_store.settings SET interval_s = $2::int, "
                "window_start_min = $3::int, window_end_min = $4::int, timezone = $5, "
                "plugins_json = $6, priority = $7::int, version = $8, "
                "updated_at = EXTRACT(EPOCH FROM now())::bigint, updated_by = $9 "
                "WHERE group_id = $1 AND version = $10 RETURNING " +
                cols;
            written = pg::exec_params(c, sql.c_str(), params);
            if (written.status() != PGRES_TUPLES_OK)
                return fail_stmt("update", written);
            if (PQntuples(written.get()) != 1) {
                // Defensive: the row lock makes this unreachable.
                error = Error{Kind::Conflict, "the stored document changed since the caller read it",
                              previous};
                return false;
            }
        }

        auto stored = parse_row(written, 0);
        if (!stored) {
            error = Error{Kind::Corrupt, kCorruptMessage, std::nullopt};
            return false;
        }

        pg::PgResult hist = pg::exec_params(
            c,
            "INSERT INTO software_collection_settings_store.settings_history (group_id, "
            "before_json, after_json, actor, at) VALUES ($1, $2, $3, $4, "
            "EXTRACT(EPOCH FROM now())::bigint)",
            std::vector<std::optional<std::string>>{
                group_id,
                previous ? std::optional<std::string>{settings_text(previous->settings)}
                         : std::nullopt,
                after_json, std::string(actor)});
        if (hist.status() != PGRES_COMMAND_OK)
            return fail_stmt("history insert", hist);

        pg::PgResult trim = pg::exec_params(
            c,
            ("DELETE FROM software_collection_settings_store.settings_history WHERE group_id = $1 "
             "AND id NOT IN (SELECT id FROM software_collection_settings_store.settings_history "
             "WHERE group_id = $1 ORDER BY id DESC LIMIT " +
             std::to_string(kHistoryKeep) + ")")
                .c_str(),
            std::vector<std::string>{group_id});
        if (trim.status() != PGRES_COMMAND_OK)
            return fail_stmt("history trim", trim);

        result = PutResult{std::move(*stored), std::move(previous)};
        body_done = true;
        return true;
    });

    if (committed && result)
        return std::move(*result);
    if (error)
        return std::unexpected(std::move(*error));
    if (body_done) {
        // Every statement ran; the COMMIT did not confirm. The write may be live.
        spdlog::warn("SoftwareCollectionSettingsStore: put commit unconfirmed (outcome unknown)");
        return fail(Kind::OutcomeUnknown, "commit unconfirmed, outcome unknown");
    }
    return fail(Kind::Unavailable, "transaction could not start");
}

std::expected<std::vector<SoftwareCollectionSettingsStore::HistoryRow>, Error>
SoftwareCollectionSettingsStore::list_history(const std::string& group_id, int limit) {
    if (!open_)
        return fail(Kind::Unavailable, "collection settings store is not open");
    if (!valid_group_id(group_id))
        return fail(Kind::InvalidInput, "invalid group id");
    limit = std::clamp(limit, 1, kHistoryKeep);
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease)
        return fail(Kind::Unavailable, "no database connection in time");
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, group_id, before_json, after_json, actor, at FROM "
        "software_collection_settings_store.settings_history WHERE group_id = $1 "
        "ORDER BY id DESC LIMIT $2::int",
        std::vector<std::string>{group_id, std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("list_history", res, Kind::Unavailable));
    std::vector<HistoryRow> out;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        out.push_back(HistoryRow{cell_i64(res, i, 0), PQgetvalue(res.get(), i, 1),
                                 cell(res, i, 2), PQgetvalue(res.get(), i, 3),
                                 PQgetvalue(res.get(), i, 4), cell_i64(res, i, 5)});
    }
    return out;
}

} // namespace yuzu::server
