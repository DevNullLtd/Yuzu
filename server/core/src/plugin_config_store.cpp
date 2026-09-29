#include "plugin_config_store.hpp"

#include "plugin_config_parsers.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <span>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "plugin_config_store";

// Bounded acquires (ADR-0012 §2). Reads/writes get the ordinary CRUD budget;
// the kill-switch evaluation entrypoint gets a SHORTER one — its own doc
// comment names it as a dispatch-gating hot path (mirrors
// OfflineEndpointStore's kUpsertAcquireTimeout rationale), and a fail-closed
// posture means giving up fast is always safe here (a timeout just means
// "disabled", never "enabled"). Construction is the only unbounded acquire.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kKillSwitchCheckTimeout{300};

// Hard cap on rows materialised by list_config (mirrors
// OfflineEndpointStore::kQueryRowCap — defensive, not expected to bind in
// practice for a config/secret plane).
constexpr int kListRowCap = 5000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE configs ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  plugin TEXT NOT NULL,"
         "  key TEXT NOT NULL,"
         "  value TEXT NOT NULL DEFAULT '',"
         "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  updated_by TEXT NOT NULL DEFAULT '',"
         "  UNIQUE (plugin, key));"
         "CREATE INDEX configs_plugin_idx ON configs (plugin);"

         "CREATE TABLE secrets ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         // scope_key is the SecretCodec AAD identity (canonical
         // `<plugin>.<key>`, deterministic from the request — see
         // set_secret's doc comment for why this replaces the numeric `id`
         // as the registered pk_column).
         "  scope_key TEXT NOT NULL UNIQUE,"
         "  plugin TEXT NOT NULL,"
         "  key TEXT NOT NULL,"
         "  sealed_value BYTEA NOT NULL DEFAULT ''::bytea,"
         "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  updated_by TEXT NOT NULL DEFAULT '',"
         "  UNIQUE (plugin, key));"
         "CREATE INDEX secrets_plugin_idx ON secrets (plugin);"

         "CREATE TABLE kill_switches ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  scope_key TEXT NOT NULL UNIQUE,"
         "  plugin TEXT NOT NULL,"
         "  action TEXT NOT NULL DEFAULT '',"
         "  enabled BOOLEAN NOT NULL DEFAULT TRUE,"
         "  reason TEXT NOT NULL DEFAULT '',"
         "  set_by TEXT NOT NULL DEFAULT '',"
         "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now());"
         "CREATE INDEX kill_switches_plugin_idx ON kill_switches (plugin);"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    auth_db.cpp / offline_endpoint_store.cpp's own file-local copies) ─────

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

// ── Row builders ─────────────────────────────────────────────────────────

PluginConfigStore::ConfigEntry config_row(PGresult* r, int i) {
    PluginConfigStore::ConfigEntry e;
    e.plugin = col_str(r, i, 0);
    e.key = col_str(r, i, 1);
    e.value = col_str(r, i, 2);
    e.updated_at_ms = to_i64(col(r, i, 3));
    e.updated_by = col_str(r, i, 4);
    return e;
}

PluginConfigStore::KillSwitchEntry kill_switch_row(PGresult* r, int i) {
    PluginConfigStore::KillSwitchEntry e;
    e.plugin = col_str(r, i, 0);
    e.action = col_str(r, i, 1);
    e.enabled = to_bool(col(r, i, 2));
    e.reason = col_str(r, i, 3);
    e.set_by = col_str(r, i, 4);
    e.updated_at_ms = to_i64(col(r, i, 5));
    return e;
}

} // namespace

std::string_view PluginConfigStore::to_string(Error err) {
    switch (err) {
    case Error::Unavailable: return "unavailable";
    case Error::NotFound: return "not_found";
    case Error::InvalidInput: return "invalid_input";
    case Error::WriteFailed: return "write_failed";
    case Error::SecretUnavailable: return "secret_unavailable";
    }
    return "unknown";
}

PluginConfigStore::PluginConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    //
    // The playbook names this sequence "the `open_with_migrations` helper"
    // (postgres-store-playbook.md §"Recipe" step 3), but no such helper is
    // defined anywhere in the tree — every existing store, including the
    // playbook's own worked reference (`offline_endpoint_store.cpp`) and
    // `auth_db.cpp`, hand-rolls exactly this acquire/run/release sequence
    // too. This mirrors that established (if undocumented-as-hand-rolled)
    // precedent rather than inventing a divergent construction path; adding
    // the actual shared helper is a substrate-level (pg/) change outside
    // this package's owned files.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("PluginConfigStore: no database connection at construction ({}) — "
                      "plugin config plane disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("PluginConfigStore: schema migration failed — plugin config plane disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010 register-before-init sequencing (playbook §3 / AuthDB
    // precedent): this ctor registers the column; the CALLER runs
    // secret_codec.init() immediately after this ctor returns. pk_column is
    // `scope_key` (TEXT), not the numeric `id` — see set_secret's doc
    // comment.
    if (!secret_codec_.register_secret_column({kStoreName, "secrets", "sealed_value", "scope_key"})) {
        spdlog::error("PluginConfigStore: failed to register secrets.sealed_value as a secret "
                      "column — plugin config plane disabled");
        return;
    }

    open_ = true;
    spdlog::info("PluginConfigStore: opened (schema {})", kStoreName);
}

// ── Config ───────────────────────────────────────────────────────────────

std::expected<std::vector<PluginConfigStore::ConfigEntry>, PluginConfigStore::Error>
PluginConfigStore::list_config(std::string_view plugin, bool* truncated) const {
    if (truncated != nullptr)
        *truncated = false;
    if (!open_)
        return std::unexpected(Error::Unavailable);
    if (!plugin.empty() && !plugin_config::is_valid_identifier(plugin))
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);

    // Fetch one row PAST the cap so a full page is distinguishable from an
    // exactly-kListRowCap-sized result — the extra row (if any) is dropped
    // below and never returned, it only flips `truncated`.
    const std::string fetch_limit = std::to_string(kListRowCap + 1);
    pg::PgResult res =
        plugin.empty()
            ? pg::exec_params(lease.get(),
                              "SELECT plugin, key, value, "
                              "(EXTRACT(EPOCH FROM updated_at) * 1000)::bigint, updated_by "
                              "FROM plugin_config_store.configs ORDER BY plugin, key LIMIT $1",
                              std::vector<std::string>{fetch_limit})
            : pg::exec_params(lease.get(),
                              "SELECT plugin, key, value, "
                              "(EXTRACT(EPOCH FROM updated_at) * 1000)::bigint, updated_by "
                              "FROM plugin_config_store.configs WHERE plugin = $1 ORDER BY key "
                              "LIMIT $2",
                              std::vector<std::string>{std::string(plugin), fetch_limit});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::Unavailable);

    int rows = PQntuples(res.get());
    if (rows > kListRowCap) {
        rows = kListRowCap;
        if (truncated != nullptr)
            *truncated = true;
    }
    std::vector<ConfigEntry> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(config_row(res.get(), i));
    return out;
}

std::expected<PluginConfigStore::ConfigEntry, PluginConfigStore::Error>
PluginConfigStore::get_config(std::string_view plugin, std::string_view key) const {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto pk = plugin_config::parse_plugin_key(plugin, key);
    if (!pk)
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT plugin, key, value, (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint, updated_by "
        "FROM plugin_config_store.configs WHERE plugin = $1 AND key = $2",
        std::vector<std::string>{pk->plugin, pk->key});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::Unavailable);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(Error::NotFound);
    return config_row(res.get(), 0);
}

std::expected<PluginConfigStore::ConfigEntry, PluginConfigStore::Error>
PluginConfigStore::set_config(std::string_view plugin, std::string_view key,
                              std::string_view value, std::string_view updated_by) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto pk = plugin_config::parse_plugin_key(plugin, key);
    if (!pk || !plugin_config::is_valid_config_value(value) ||
        !plugin_config::is_valid_actor(updated_by))
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO plugin_config_store.configs (plugin, key, value, updated_by) "
        "VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (plugin, key) DO UPDATE SET "
        "  value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by "
        "RETURNING plugin, key, value, (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint, updated_by",
        std::vector<std::string>{pk->plugin, pk->key, std::string(value), std::string(updated_by)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(Error::WriteFailed);
    return config_row(res.get(), 0);
}

std::expected<void, PluginConfigStore::Error> PluginConfigStore::delete_config(
    std::string_view plugin, std::string_view key) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto pk = plugin_config::parse_plugin_key(plugin, key);
    if (!pk)
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM plugin_config_store.configs WHERE plugin = $1 AND key = $2 RETURNING id",
        std::vector<std::string>{pk->plugin, pk->key});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(Error::NotFound);
    return {};
}

// ── Secrets ──────────────────────────────────────────────────────────────

std::expected<PluginConfigStore::SecretMeta, PluginConfigStore::Error>
PluginConfigStore::set_secret(std::string_view plugin, std::string_view key,
                              std::string_view plaintext_value, std::string_view updated_by) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto pk = plugin_config::parse_plugin_key(plugin, key);
    if (!pk || !plugin_config::is_valid_secret_value(plaintext_value) ||
        !plugin_config::is_valid_actor(updated_by))
        return std::unexpected(Error::InvalidInput);

    // AAD identity is the deterministic scope_key (`<plugin>.<key>`), never
    // a DB-assigned row id — so it is known immediately, with NO get-or-
    // create round trip before encrypting. This closes two hazards the
    // id-based version had: a brand-new secret never briefly exists as a
    // committed row with an empty/invalid `sealed_value` (there is no
    // "create the row first" statement at all — the ONLY write below is the
    // one that carries the real ciphertext), and an existing secret's
    // `updated_by`/`updated_at` metadata is never touched unless encryption
    // has already succeeded (no separate pre-encrypt UPDATE exists to touch
    // it). Two concurrent writers for the SAME (plugin, key) compute the
    // IDENTICAL AAD deterministically, so — unlike a reserved-then-raced
    // numeric id — there is no window where a writer's ciphertext ends up
    // bound to an AAD identity different from the row it lands in.
    const std::string scope_key = plugin_config::canonical_plugin_key(*pk);

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(plaintext_value.data());
    auto enc = secret_codec_.encrypt(
        pg::SecretCodec::SecretId{kStoreName, "secrets", "sealed_value", scope_key},
        std::span<const std::uint8_t>{bytes, plaintext_value.size()});
    if (!enc.has_value()) {
        // Encrypt failure aborts here — never write plaintext, never write
        // anything at all (ADR-0010 encrypt-failure semantics). No row of
        // any kind has been touched yet, so there is nothing to roll back.
        spdlog::error("PluginConfigStore::set_secret: encrypt failed ({})",
                      plugin_config::redact_secret_for_log(*pk));
        return std::unexpected(Error::SecretUnavailable);
    }

    // Single atomic mutate-and-return, executed only now that the sealed
    // blob is in hand — no placeholder row, no early metadata write.
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO plugin_config_store.secrets (scope_key, plugin, key, sealed_value, updated_by) "
        "VALUES ($1, $2, $3, decode($4, 'hex'), $5) "
        "ON CONFLICT (scope_key) DO UPDATE SET "
        "  sealed_value = EXCLUDED.sealed_value, updated_at = now(), updated_by = EXCLUDED.updated_by "
        "RETURNING plugin, key, (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint, updated_by",
        std::vector<std::string>{scope_key, pk->plugin, pk->key, bytes_to_hex(*enc),
                                 std::string(updated_by)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(Error::WriteFailed);

    SecretMeta meta;
    meta.plugin = col_str(res.get(), 0, 0);
    meta.key = col_str(res.get(), 0, 1);
    meta.updated_at_ms = to_i64(col(res.get(), 0, 2));
    meta.updated_by = col_str(res.get(), 0, 3);
    return meta;
}

std::expected<void, PluginConfigStore::Error> PluginConfigStore::delete_secret(
    std::string_view plugin, std::string_view key) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto pk = plugin_config::parse_plugin_key(plugin, key);
    if (!pk)
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM plugin_config_store.secrets WHERE plugin = $1 AND key = $2 RETURNING id",
        std::vector<std::string>{pk->plugin, pk->key});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(Error::NotFound);
    return {};
}

// ── Kill switch ──────────────────────────────────────────────────────────

std::expected<PluginConfigStore::KillSwitchEntry, PluginConfigStore::Error>
PluginConfigStore::get_kill_switch(std::string_view plugin, std::string_view action) const {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto scope = plugin_config::parse_kill_switch_scope(plugin, action);
    if (!scope)
        return std::unexpected(Error::InvalidInput);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);

    const std::string plugin_key =
        plugin_config::kill_switch_scope_key({scope->plugin, ""});

    if (!scope->action.empty()) {
        const std::string action_key = plugin_config::kill_switch_scope_key(*scope);
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT plugin, action, enabled, reason, set_by, "
            "(EXTRACT(EPOCH FROM updated_at) * 1000)::bigint "
            "FROM plugin_config_store.kill_switches WHERE scope_key = $1",
            std::vector<std::string>{action_key});
        if (res.status() != PGRES_TUPLES_OK)
            return std::unexpected(Error::Unavailable);
        if (PQntuples(res.get()) > 0) {
            auto entry = kill_switch_row(res.get(), 0);
            entry.action = scope->action; // echo the requested action
            return entry;
        }
    }

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT plugin, action, enabled, reason, set_by, "
        "(EXTRACT(EPOCH FROM updated_at) * 1000)::bigint "
        "FROM plugin_config_store.kill_switches WHERE scope_key = $1",
        std::vector<std::string>{plugin_key});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::Unavailable);
    if (PQntuples(res.get()) > 0) {
        auto entry = kill_switch_row(res.get(), 0);
        entry.action = scope->action; // echo the requested action, not "" from the inherited row
        return entry;
    }

    // No row at either level — the legitimate default state.
    KillSwitchEntry def;
    def.plugin = scope->plugin;
    def.action = scope->action;
    def.enabled = true;
    return def;
}

std::expected<PluginConfigStore::KillSwitchEntry, PluginConfigStore::Error>
PluginConfigStore::set_kill_switch(std::string_view plugin, std::string_view action, bool enabled,
                                   std::string_view reason, std::string_view set_by) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    auto scope = plugin_config::parse_kill_switch_scope(plugin, action);
    if (!scope || !plugin_config::is_valid_reason(reason) ||
        !plugin_config::is_valid_actor(set_by))
        return std::unexpected(Error::InvalidInput);
    const std::string scope_key = plugin_config::kill_switch_scope_key(*scope);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO plugin_config_store.kill_switches "
        "  (scope_key, plugin, action, enabled, reason, set_by) "
        "VALUES ($1, $2, $3, $4::boolean, $5, $6) "
        "ON CONFLICT (scope_key) DO UPDATE SET "
        "  enabled = EXCLUDED.enabled, reason = EXCLUDED.reason, set_by = EXCLUDED.set_by, "
        "  updated_at = now() "
        "RETURNING plugin, action, enabled, reason, set_by, "
        "  (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint",
        std::vector<std::string>{scope_key, scope->plugin, scope->action,
                                 enabled ? "true" : "false", std::string(reason),
                                 std::string(set_by)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(Error::WriteFailed);
    return kill_switch_row(res.get(), 0);
}

bool PluginConfigStore::seed_kill_switch_default_off(std::string_view plugin,
                                                      std::string_view reason) {
    if (!open_)
        return false;
    auto scope = plugin_config::parse_kill_switch_scope(plugin, "");
    if (!scope || !plugin_config::is_valid_reason(reason) ||
        !plugin_config::is_valid_actor("system"))
        return false;
    const std::string scope_key = plugin_config::kill_switch_scope_key(*scope);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("PluginConfigStore: kill-switch seed for {} failed: no connection lease ({})",
                      plugin, pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO plugin_config_store.kill_switches "
        "  (scope_key, plugin, action, enabled, reason, set_by) "
        "VALUES ($1, $2, $3, FALSE, $4, 'system') "
        "ON CONFLICT (scope_key) DO NOTHING",
        std::vector<std::string>{scope_key, scope->plugin, scope->action, std::string(reason)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("PluginConfigStore: kill-switch seed for {} failed: {}", plugin,
                      PQresultErrorMessage(res.get()));
        return false;
    }
    return true;
}

bool PluginConfigStore::action_allowed(std::string_view plugin, std::string_view action) const {
    if (!open_)
        return false; // degraded/unopened — fail closed, never "enabled"
    auto scope = plugin_config::parse_kill_switch_scope(plugin, action);
    if (!scope)
        return false; // an unresolvable scope must never resolve to "allowed"

    auto lease = pool_.try_acquire_for(kKillSwitchCheckTimeout);
    if (!lease)
        return false; // lease timeout — fail closed

    const std::string plugin_key = plugin_config::kill_switch_scope_key({scope->plugin, ""});

    if (!scope->action.empty()) {
        // ONE statement covering both scope levels (not two sequential
        // ones) — a single SELECT reads a single MVCC snapshot, so a
        // concurrently-committed action-level disable can never land in a
        // gap between "checked the action row" and "fell back to the
        // plugin row" the way two separate autocommitted statements could
        // (the TOCTOU this function exists to close).
        const std::string action_key = plugin_config::kill_switch_scope_key(*scope);
        pg::PgResult res = pg::exec_params(lease.get(),
                                           "SELECT scope_key, enabled FROM "
                                           "plugin_config_store.kill_switches "
                                           "WHERE scope_key = $1 OR scope_key = $2",
                                           std::vector<std::string>{action_key, plugin_key});
        if (res.status() != PGRES_TUPLES_OK)
            return false; // query failure — fail closed
        bool have_action = false, action_enabled = false;
        bool have_plugin = false, plugin_enabled = false;
        const int rows = PQntuples(res.get());
        for (int i = 0; i < rows; ++i) {
            const std::string sk = col_str(res.get(), i, 0);
            const bool enabled = to_bool(col(res.get(), i, 1));
            if (sk == action_key) {
                have_action = true;
                action_enabled = enabled;
            } else if (sk == plugin_key) {
                have_plugin = true;
                plugin_enabled = enabled;
            }
        }
        if (have_action)
            return action_enabled; // action-level row wins
        if (have_plugin)
            return plugin_enabled;
        return true; // no row at either level — default "not killed"
    }

    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT enabled FROM plugin_config_store.kill_switches "
                        "WHERE scope_key = $1",
                        std::vector<std::string>{plugin_key});
    if (res.status() != PGRES_TUPLES_OK)
        return false; // query failure — fail closed
    if (PQntuples(res.get()) > 0)
        return to_bool(col(res.get(), 0, 0));

    return true; // no row at either level — default "not killed"
}

} // namespace yuzu::server
