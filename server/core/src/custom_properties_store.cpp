#include "custom_properties_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <re2/re2.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "custom_properties_store";

// Bounded acquires (ADR-0012 §2(a)). Nothing here runs the gRPC heartbeat hot
// path — writes come from operator/REST calls, reads back both REST and the
// props.<key> scope resolver's bulk preload (agent_registry.cpp). All can
// wait a little; none may block unboundedly on a saturated pool.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// Same treatment as RbacStore/ManagementGroupStore (ADR-0041/0042): scrub
// invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub leaves
// behind (a valid ASCII byte the scrub doesn't touch) — PostgreSQL TEXT can't
// store NUL and libpq's text-format bind C-string-truncates at the first one.
// Applied to every free-text column INCLUDING the backfill path (a bad byte
// at-rest in a legacy custom-properties.db must not brick the MANDATORY
// backfill).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (#1675 convention, mirrors ProductRegistryStore) ──
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_custom_properties_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// One sampler per distinct read call site (a shared sampler would let a
// hot get_value degrade mask a cold get_properties one from ever logging).
DegradeSampler g_props_sampler;
DegradeSampler g_prop_sampler;
DegradeSampler g_map_sampler;
DegradeSampler g_values_for_keys_sampler;

// Unqualified DDL: the runner sets search_path to `custom_properties_store`
// for the migration transaction; runtime statements below schema-qualify
// explicitly. Two independent tables, no FK between them (header comment —
// cross-table validation stays application-layer, matching the SQLite
// original's behavior).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE custom_properties (
                agent_id    TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                type        TEXT NOT NULL DEFAULT 'string',
                updated_at  BIGINT NOT NULL,
                PRIMARY KEY (agent_id, key)
            );
            CREATE INDEX custom_props_agent_idx ON custom_properties (agent_id);
            -- Supports get_values_for_keys' WHERE key = ANY($1::text[]) —
            -- the props.<key> scope-DSL bulk preload, a hot path (every
            -- evaluate_scope call referencing props.<key>, including the
            -- background policy-evaluator tick). Without this index that
            -- query sequential-scans the whole table (gov Gate 6 sre).
            CREATE INDEX custom_props_key_idx ON custom_properties (key);

            CREATE TABLE custom_property_schemas (
                key               TEXT PRIMARY KEY,
                display_name      TEXT NOT NULL DEFAULT '',
                type              TEXT NOT NULL DEFAULT 'string',
                description       TEXT NOT NULL DEFAULT '',
                validation_regex  TEXT NOT NULL DEFAULT ''
            );

        )"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // custom_properties_meta's sole purpose was the backfill idempotency
        // marker, which no longer has a writer. Version-bumped (not edited into
        // v1) because v1 has actually run against real dev/UAT databases.
        {2, "DROP TABLE IF EXISTS custom_properties_meta;"},
    };
    return kMigrations;
}

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────

CustomPropertiesStore::CustomPropertiesStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CustomPropertiesStore: no database connection at construction ({}) — "
                      "custom-properties persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CustomPropertiesStore: schema migration failed — custom-properties "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

// ── Validation ───────────────────────────────────────────────────────────────
// Pure C++ — unchanged by the substrate migration.

bool CustomPropertiesStore::validate_key(const std::string& key) {
    if (key.empty() || key.size() > 64)
        return false;
    for (char c : key) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':')) {
            return false;
        }
    }
    return true;
}

bool CustomPropertiesStore::validate_value(const std::string& value) {
    return value.size() <= 1024;
}

std::expected<std::optional<std::string>, std::string>
CustomPropertiesStore::validate_against_schema(PGconn* conn, const std::string& key,
                                               const std::string& value) const {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT type, validation_regex FROM custom_properties_store.custom_property_schemas "
        "WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        // A genuine query failure, NOT "no schema" — the SQLite original
        // conflated the two (a prepare failure silently fell through to "no
        // validation"), which is a validation bypass now that this runs
        // against a real network connection with real failure modes instead
        // of a local file read. Surface it as a write failure so the whole
        // with_txn_for callback aborts (the same "database write failed"
        // shape the INSERT already produces on its own failure) rather than
        // silently accepting an unvalidated write.
        return std::unexpected(std::string(kCustomPropertiesDbErrorPrefix) + "database error");
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{std::nullopt}; // genuinely no schema for this key

    const std::string schema_type = text_col(res.get(), 0, 0);
    const std::string validation_regex = text_col(res.get(), 0, 1);

    if (schema_type.empty())
        return std::optional<std::string>{std::nullopt};

    if (schema_type == "int") {
        try {
            (void)std::stoll(value);
        } catch (...) {
            return std::unexpected("value must be a valid integer for property '" + key + "'");
        }
    } else if (schema_type == "bool") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false' for property '" + key + "'");
    }
    // "string" and "datetime" accept any text.

    if (!validation_regex.empty()) {
        RE2 re(validation_regex, RE2::Quiet);
        if (!re.ok()) {
            spdlog::warn("CustomPropertiesStore: invalid regex for schema key '{}': {}", key,
                        validation_regex);
        } else if (!RE2::FullMatch(value, re)) {
            return std::unexpected("value does not match validation pattern for '" + key + "'");
        }
    }

    return std::optional<std::string>{schema_type};
}

// ── Property CRUD ────────────────────────────────────────────────────────────

std::expected<std::vector<CustomProperty>, CustomPropertiesReadError>
CustomPropertiesStore::get_properties(const std::string& agent_id) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value, type, updated_at FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 ORDER BY key",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::vector<CustomProperty> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        CustomProperty p;
        p.agent_id = agent_id;
        p.key = text_col(res.get(), i, 0);
        p.value = text_col(res.get(), i, 1);
        p.type = text_col(res.get(), i, 2);
        p.updated_at = to_i64(PQgetvalue(res.get(), i, 3));
        results.push_back(std::move(p));
    }
    return results;
}

std::expected<std::optional<CustomProperty>, CustomPropertiesReadError>
CustomPropertiesStore::get_property(const std::string& agent_id, const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value, type, updated_at FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 AND key = $2",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<CustomProperty>{std::nullopt};
    CustomProperty p;
    p.agent_id = agent_id;
    p.key = key;
    p.value = text_col(res.get(), 0, 0);
    p.type = text_col(res.get(), 0, 1);
    p.updated_at = to_i64(PQgetvalue(res.get(), 0, 2));
    return std::optional<CustomProperty>{std::move(p)};
}

std::expected<std::optional<std::string>, CustomPropertiesReadError>
CustomPropertiesStore::get_value(const std::string& agent_id, const std::string& key) const {
    auto prop = get_property(agent_id, key);
    if (!prop)
        return std::unexpected(prop.error());
    if (!*prop)
        return std::optional<std::string>{std::nullopt};
    return std::optional<std::string>{(*prop)->value};
}

std::expected<std::unordered_map<std::string, std::string>, CustomPropertiesReadError>
CustomPropertiesStore::get_property_map(const std::string& agent_id) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value FROM custom_properties_store.custom_properties WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::unordered_map<std::string, std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return result;
}

std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
              CustomPropertiesReadError>
CustomPropertiesStore::get_values_for_keys(const std::vector<std::string>& keys) const {
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> result;
    if (keys.empty())
        return result;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_values_for_keys_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_values_for_keys_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::vector<std::string_view> key_views(keys.begin(), keys.end());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, key, value FROM custom_properties_store.custom_properties "
        "WHERE key = ANY($1::text[])",
        std::vector<std::string>{pg::to_text_array(key_views)});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_values_for_keys_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        result[text_col(res.get(), i, 0)].emplace(text_col(res.get(), i, 1),
                                                   text_col(res.get(), i, 2));
    }
    return result;
}

std::expected<void, std::string>
CustomPropertiesStore::set_property(const std::string& agent_id, const std::string& key,
                                    const std::string& value, const std::string& type) {
    if (!open_)
        return std::unexpected(std::string(kCustomPropertiesDbErrorPrefix) + "store not open");
    if (!validate_key(key))
        return std::unexpected("invalid property key (1-64 chars, alphanumeric/._:-)");
    if (!validate_value(value))
        return std::unexpected("property value exceeds maximum length (1024 bytes)");

    // ADR-0012 §2(c): schema-check + upsert as ONE logical operation on ONE
    // lease (a single with_txn), not two separate acquires — the SQLite
    // original held one mutex across both under the same lock for the same
    // reason (a schema landing between the check and the write must not be
    // able to observe a partially-validated write).
    const std::string sanitized_value = sanitize_pg_text(value);
    std::string effective_type = type;
    std::string schema_error;
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
        auto schema_result = validate_against_schema(c, key, sanitized_value);
        if (!schema_result) {
            schema_error = schema_result.error();
            return false;
        }
        // Use the schema's type if validate_against_schema found one,
        // otherwise the caller-provided type (matches SQLite original's
        // effective-type resolution) — read from the SAME query
        // validate_against_schema already ran, never a second SELECT (see
        // its header doc comment for why a second query would be a fresh
        // READ COMMITTED snapshot, not a guarantee of the same row).
        if (*schema_result)
            effective_type = **schema_result;

        pg::PgResult res = pg::exec_params(
            c,
            "INSERT INTO custom_properties_store.custom_properties "
            "(agent_id, key, value, type, updated_at) VALUES ($1, $2, $3, $4, $5::bigint) "
            "ON CONFLICT (agent_id, key) DO UPDATE SET "
            "  value = EXCLUDED.value, type = EXCLUDED.type, updated_at = EXCLUDED.updated_at "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id, key, sanitized_value, effective_type,
                                     std::to_string(now_secs())});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
            schema_error = std::string(kCustomPropertiesDbErrorPrefix) + "database write failed";
            return false;
        }
        return true;
    });
    if (!ok) {
        if (schema_error.empty())
            schema_error = std::string(kCustomPropertiesDbErrorPrefix) + "database error";
        return std::unexpected(schema_error);
    }
    return {};
}

bool CustomPropertiesStore::delete_property(const std::string& agent_id, const std::string& key) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_property: no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 AND key = $2 RETURNING agent_id",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::delete_property: query failed: {}",
                      PQerrorMessage(lease.get()));
        return false;
    }
    return PQntuples(res.get()) > 0;
}

void CustomPropertiesStore::delete_all_properties(const std::string& agent_id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_all_properties: no connection in time ({})",
                      pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM custom_properties_store.custom_properties WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("CustomPropertiesStore::delete_all_properties: delete failed for agent={}: {}",
                    agent_id, PQerrorMessage(lease.get()));
    }
}

// ── Schema CRUD ──────────────────────────────────────────────────────────────

std::vector<CustomPropertySchema> CustomPropertiesStore::list_schemas() const {
    std::vector<CustomPropertySchema> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::list_schemas: no connection in time ({})",
                      pool_.last_error());
        return results;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, display_name, type, description, validation_regex "
        "FROM custom_properties_store.custom_property_schemas ORDER BY key",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::list_schemas: query failed: {}",
                      PQerrorMessage(lease.get()));
        return results;
    }
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        CustomPropertySchema s;
        s.key = text_col(res.get(), i, 0);
        s.display_name = text_col(res.get(), i, 1);
        s.type = text_col(res.get(), i, 2);
        s.description = text_col(res.get(), i, 3);
        s.validation_regex = text_col(res.get(), i, 4);
        results.push_back(std::move(s));
    }
    return results;
}

std::expected<std::optional<CustomPropertySchema>, CustomPropertiesReadError>
CustomPropertiesStore::get_schema(const std::string& key) const {
    if (!open_) {
        spdlog::debug("CustomPropertiesStore::get_schema: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::get_schema: no connection in time ({})",
                      pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, display_name, type, description, validation_regex "
        "FROM custom_properties_store.custom_property_schemas WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::get_schema: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<CustomPropertySchema>{std::nullopt};
    CustomPropertySchema s;
    s.key = text_col(res.get(), 0, 0);
    s.display_name = text_col(res.get(), 0, 1);
    s.type = text_col(res.get(), 0, 2);
    s.description = text_col(res.get(), 0, 3);
    s.validation_regex = text_col(res.get(), 0, 4);
    return std::optional<CustomPropertySchema>{std::move(s)};
}

std::expected<void, std::string>
CustomPropertiesStore::upsert_schema(const CustomPropertySchema& schema) {
    if (!open_)
        return std::unexpected(std::string(kCustomPropertiesDbErrorPrefix) + "store not open");
    if (!validate_key(schema.key))
        return std::unexpected("invalid schema key");

    static const std::array<const char*, 4> kValidTypes = {"string", "int", "bool", "datetime"};
    if (std::find(kValidTypes.begin(), kValidTypes.end(), schema.type) == kValidTypes.end())
        return std::unexpected("type must be one of: string, int, bool, datetime");

    if (!schema.validation_regex.empty()) {
        // L10: limit regex length to prevent ReDoS.
        constexpr std::size_t kMaxRegexLength = 256;
        if (schema.validation_regex.size() > kMaxRegexLength)
            return std::unexpected("validation regex exceeds maximum length of 256 characters");
        RE2 re(schema.validation_regex, RE2::Quiet);
        if (!re.ok())
            return std::unexpected(std::string("invalid validation regex: ") + re.error());
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kCustomPropertiesDbErrorPrefix) + "database error");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO custom_properties_store.custom_property_schemas "
        "(key, display_name, type, description, validation_regex) VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (key) DO UPDATE SET "
        "  display_name = EXCLUDED.display_name, type = EXCLUDED.type, "
        "  description = EXCLUDED.description, validation_regex = EXCLUDED.validation_regex "
        "RETURNING key",
        std::vector<std::string>{schema.key, sanitize_pg_text(schema.display_name), schema.type,
                                 sanitize_pg_text(schema.description), schema.validation_regex});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return std::unexpected(std::string(kCustomPropertiesDbErrorPrefix) + "database write failed");
    return {};
}

std::expected<bool, CustomPropertiesReadError>
CustomPropertiesStore::delete_schema(const std::string& key) {
    if (!open_) {
        spdlog::debug("CustomPropertiesStore::delete_schema: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_schema: no connection in time ({})",
                      pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM custom_properties_store.custom_property_schemas WHERE key = $1 RETURNING key",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::delete_schema: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    return PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
