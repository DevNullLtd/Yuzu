#include "instruction_store.hpp"
#include "instruction_definition_model.hpp" // #4029: export_definition_json delegates to the shared builder
#include "instruction_yaml.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "reserved_definition_id.hpp" // the ONE reserved-namespace rule (#2442)
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "product_pack_store.hpp" // ProductPackStore::verify_signature (#1073)
#include "response_templates_engine.hpp"
#include "scope_yaml.hpp"
#include "store_errors.hpp"
#include "utf8_sanitize.hpp"
#include "yaml_scan.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <format>
#include <random>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "instruction_store";

// Bounded acquires (ADR-0012 §2(a)): authoritative store, so reads/writes wait a little longer
// than a fail-soft store's hot-path budget, but every runtime acquire is still bounded.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// Preserves the pre-migration SQLite behavior ("generous default, effectively no hard cap") in a
// form Postgres accepts — SQLite treats a non-positive LIMIT as "no limit"; Postgres errors on a
// negative LIMIT. A hostile/mistaken non-positive limit clamps to the default rather than 503ing.
constexpr int kDefaultListLimit = 100;
constexpr int kMaxListLimit = 10000;

// ADR-0058 seed-vs-live coordination lock. Serializes every writer of the
// (instruction_definitions/instruction_sets, deleted_seed_content) pair against every other —
// the trusted-reseed insert path, create_set_seed, delete_definition, and delete_set. MUST be
// acquired in its own statement, strictly BEFORE the statement that checks-and-mutates (a
// single statement's READ COMMITTED snapshot is fixed before any of its own function calls
// run — embedding the lock via CTE in the same statement does NOT work;
// docs/postgres-store-playbook.md lines 309-329). Coarse-grained (one fixed key):
// instruction-content seeding/deletion is boot-time/operator-driven, never a hot path, so
// store-wide serialization is cheap — same reasoning as RbacStore's kRevokeCoordLockSql /
// ProductPackStore's kErasureCoordLockSql, whose shared two-int32 form + "yuzu" namespace
// constant (2037545589) this reuses; the hashtext string is this store's own key. Plain
// create_definition/update_definition/create_set/the SIGNED import_definition_json path never
// touch deleted_seed_content and take NO lock (docs/adr/0058-...md "Locking").
constexpr const char* kSeedCoordLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext('instruction_store:seed_coordination'))";

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string generate_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

// Applied to every free-text column reaching Postgres, mirroring
// product_pack_store.cpp/license_store.cpp/discovery_store.cpp's sanitize_pg_text — libpq binds
// text parameters as C-strings, so an embedded NUL would otherwise silently TRUNCATE the stored
// value at that point (the pre-migration sqlite3_bind_text(..., -1, ...) had this exact
// truncation behavior too, so U+FFFD replacement here is a strict improvement, not a new risk).
// yaml_source's own NUL rejection (validate_definition_scope, below) makes this a defense-in-
// depth belt-and-braces for every OTHER free-text column, not the primary guard for yaml_source
// itself.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

std::string text_col(PGresult* res, int row, int col) {
    return PQgetisnull(res, row, col) ? std::string{} : std::string(PQgetvalue(res, row, col));
}
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) {
    return s != nullptr && s[0] == 't';
}

/// Issue #587: visualization_spec is stored as a JSON array of chart
/// objects so the engine sees one shape. This helper takes whatever the
/// caller supplied (object, array, or anything else) and emits a JSON
/// array string suitable for the column.
std::string normalize_to_array_helper(const nlohmann::json& v) {
    if (v.is_array()) {
        // Filter to keep only object entries; non-object array entries
        // (null, scalar, nested array) are dropped silently. The engine
        // does strict validation on the chart objects themselves.
        nlohmann::json out = nlohmann::json::array();
        for (const auto& el : v) {
            if (el.is_object())
                out.push_back(el);
        }
        return out.dump();
    }
    if (v.is_object()) {
        // Singular spec.visualization YAML form — wrap as a 1-element array.
        nlohmann::json out = nlohmann::json::array();
        out.push_back(v);
        return out.dump();
    }
    // Anything else (null, scalar): treat as "no visualization configured".
    return "[]";
}

// ── Migration DDL (ADR-0058) ─────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly. The pre-migration SQLite store's ~9
    // compat `legacy_alters[]` ALTER statements plus its v2/v3 MigrationRunner steps
    // (visualization_spec, response_templates_spec) are all folded into this single v1 — the
    // Postgres schema is born fresh, matching every other migrated store's "no ALTER-wart
    // machinery on PG" precedent.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE instruction_definitions ("
         "  id                      TEXT PRIMARY KEY,"
         "  name                    TEXT NOT NULL,"
         "  version                 TEXT NOT NULL DEFAULT '1.0',"
         "  type                    TEXT NOT NULL,"
         "  plugin                  TEXT NOT NULL,"
         "  action                  TEXT NOT NULL DEFAULT '',"
         "  description             TEXT NOT NULL DEFAULT '',"
         "  enabled                 BOOLEAN NOT NULL DEFAULT TRUE,"
         "  instruction_set_id      TEXT NOT NULL DEFAULT '',"
         "  gather_ttl_seconds      INTEGER NOT NULL DEFAULT 300,"
         "  response_ttl_days       INTEGER NOT NULL DEFAULT 90,"
         "  created_by              TEXT NOT NULL DEFAULT '',"
         "  created_at              BIGINT NOT NULL DEFAULT 0,"
         "  updated_at              BIGINT NOT NULL DEFAULT 0,"
         "  yaml_source             TEXT NOT NULL DEFAULT '',"
         "  parameter_schema        TEXT NOT NULL DEFAULT '{}',"
         "  result_schema           TEXT NOT NULL DEFAULT '{}',"
         "  approval_mode           TEXT NOT NULL DEFAULT 'auto',"
         "  concurrency_mode        TEXT NOT NULL DEFAULT 'per-device',"
         "  platforms               TEXT NOT NULL DEFAULT '',"
         "  min_agent_version       TEXT NOT NULL DEFAULT '',"
         "  required_plugins        TEXT NOT NULL DEFAULT '',"
         "  readable_payload        TEXT NOT NULL DEFAULT '',"
         "  visualization_spec      TEXT NOT NULL DEFAULT '{}',"
         "  response_templates_spec TEXT NOT NULL DEFAULT '[]');"
         "CREATE TABLE instruction_sets ("
         "  id          TEXT PRIMARY KEY,"
         "  name        TEXT NOT NULL,"
         "  description TEXT NOT NULL DEFAULT '',"
         "  created_by  TEXT NOT NULL DEFAULT '',"
         "  created_at  BIGINT NOT NULL DEFAULT 0);"
         // ADR-0058 seed-vs-live: a dedicated suppression table (RbacStore's
         // revoked_seed_defaults shape, extended with a kind discriminator rather than two
         // tables) — never a plain DELETE the every-boot reseed loop would silently undo, never
         // a same-effect tombstone value a read path could see. Consulted ONLY by the
         // seed-aware insert paths. Never pruned, by design (mirrors
         // deleted_pack_ids/revoked_seed_defaults) — low-cardinality operator-driven
         // content-catalog deletes make unbounded retention a non-issue at realistic scale.
         "CREATE TABLE deleted_seed_content ("
         "  kind       TEXT NOT NULL,"
         "  id         TEXT NOT NULL,"
         "  deleted_at BIGINT NOT NULL,"
         "  PRIMARY KEY (kind, id));"},
        // Gate 4 UP-3: the original v1 briefly included a sqlite_backfill_source table
        // (for the backfill mechanism retired in full before this store shipped, see
        // ADR-0058's "Backfill — none" section) and had it edited out of v1 in place —
        // PgMigrationRunner tracks by version number only, so any dev/UAT database that
        // ran a migration during that narrow window keeps the orphan table forever.
        // Harmless (nothing references it) but permanent schema drift; drop it
        // idempotently for the databases that have it, no-op for the ones that don't.
        {2, "DROP TABLE IF EXISTS sqlite_backfill_source;"},
    };
    return kMigrations;
}

constexpr const char* kDefinitionCols =
    "id, name, version, type, plugin, action, description, enabled, instruction_set_id, "
    "gather_ttl_seconds, response_ttl_days, created_by, created_at, updated_at, yaml_source, "
    "parameter_schema, result_schema, approval_mode, concurrency_mode, platforms, "
    "min_agent_version, required_plugins, readable_payload, visualization_spec, "
    "response_templates_spec";

InstructionDefinition read_definition_row(PGresult* res, int row) {
    InstructionDefinition d;
    int c = 0;
    d.id = text_col(res, row, c++);
    d.name = text_col(res, row, c++);
    d.version = text_col(res, row, c++);
    d.type = text_col(res, row, c++);
    d.plugin = text_col(res, row, c++);
    d.action = text_col(res, row, c++);
    d.description = text_col(res, row, c++);
    d.enabled = to_bool(PQgetvalue(res, row, c++));
    d.instruction_set_id = text_col(res, row, c++);
    d.gather_ttl_seconds = static_cast<int>(to_i64(PQgetvalue(res, row, c++)));
    d.response_ttl_days = static_cast<int>(to_i64(PQgetvalue(res, row, c++)));
    d.created_by = text_col(res, row, c++);
    d.created_at = to_i64(PQgetvalue(res, row, c++));
    d.updated_at = to_i64(PQgetvalue(res, row, c++));
    d.yaml_source = text_col(res, row, c++);
    d.parameter_schema = text_col(res, row, c++);
    d.result_schema = text_col(res, row, c++);
    d.approval_mode = text_col(res, row, c++);
    d.concurrency_mode = text_col(res, row, c++);
    d.platforms = text_col(res, row, c++);
    d.min_agent_version = text_col(res, row, c++);
    d.required_plugins = text_col(res, row, c++);
    d.readable_payload = text_col(res, row, c++);
    d.visualization_spec = text_col(res, row, c++);
    d.response_templates_spec = text_col(res, row, c++);
    return d;
}

constexpr const char* kSetCols = "id, name, description, created_by, created_at";

InstructionSet read_set_row(PGresult* res, int row) {
    InstructionSet s;
    int c = 0;
    s.id = text_col(res, row, c++);
    s.name = text_col(res, row, c++);
    s.description = text_col(res, row, c++);
    s.created_by = text_col(res, row, c++);
    s.created_at = to_i64(PQgetvalue(res, row, c++));
    return s;
}

// ── Read-degrade observability (#1675 convention, mirrors ProductPackStore) ────
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";

void note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_instruction_read_degrade_total", {{"reason", reason}})
            .increment();
}

// Write-side counterpart (gov Gate 3 sre finding): pre-migration write paths had no
// store-layer failure signal at all — a genuine DB error on create/update/delete surfaced
// only as an unlabelled 503 at whichever REST route happened to call it, with no aggregate
// InstructionStore-specific trace for an on-call engineer to key an alert on.
void note_write_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_instruction_write_degrade_total", {{"reason", reason}})
            .increment();
}

} // namespace

// ---------------------------------------------------------------------------
// spec.scope validation (pure logic, shared by create+update; unaffected by storage substrate)
// ---------------------------------------------------------------------------

// Store-level yaml_source gates shared by create AND update (size cap, scope-walking
// fromResultSet combos, inline flow-mapping rejection). Only errors when spec.scope.fromResultSet
// is present with a forbidden combo; scope-less and selector-only definitions (incl. all bundled
// content) pass. Also caps oversize input (UP-3) and rejects the inline flow-mapping form the
// block-form line-scanners cannot see (UP-6).
std::optional<std::string> validate_definition_scope(const std::string& yaml_source) {
    if (yaml_source.empty())
        return std::nullopt;
    // A NUL truncates any libpq text-format binding of this value, so the persisted yaml_source
    // would silently diverge from the extracted columns and, on the signed-import path, from
    // the signature-verified bytes. Reject at this shared create+update chokepoint so every
    // surface (dashboard Save, JSON create/PUT, signed import) is covered.
    if (yaml_source.find('\0') != std::string::npos)
        return "yaml_source contains a NUL byte";
    if (yaml_source.size() > 1048576)
        return "yaml_source too large (max 1MB)";
    auto raw_scope = yaml_scan::extract_yaml_value(yaml_source, "scope");
    if (!raw_scope.empty() && raw_scope.front() == '{')
        return "inline flow-mapping scope is not supported; use the block form "
               "(scope: <newline> indented fromResultSet: <id-or-alias>)";
    auto sb = parse_scope_block(yaml_source);
    auto asn = yaml_scan::extract_yaml_section(yaml_source, "spec.assignment");
    return validate_scope_block(sb, yaml_scan::extract_yaml_value(asn, "mode"),
                                !yaml_scan::extract_yaml_list(asn, "managementGroups").empty());
}

// #2542 PR-7: promoted verbatim from ServerImpl::validate_yaml_source
// (server.cpp) — see instruction_store.hpp's doc comment for why this is a
// promotion, not a duplication (a #2557 json_extract.hpp-style call site
// straddling an extraction boundary: /fragments/instructions/yaml-preview,
// now in instruction_fragment_routes.cpp (#2542 PR-12), shares this exact
// function).
std::vector<std::string> validate_yaml_source(const std::string& yaml_source) {
    // Shared with the POST /api/instructions/yaml save path so validate
    // and save can never diverge on what a complete definition is (#1993).
    auto errors = instruction_yaml::validate_definition_yaml(yaml_source);
    // Also run the store-level gates (scope-walking combos, flow-mapping
    // scope) that create/update enforce — same contract, one verdict
    // (governance UP-3). Skip when byte-level errors already fired.
    if (errors.empty()) {
        if (auto err = validate_definition_scope(yaml_source))
            errors.push_back(*err);
    }
    return errors;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

InstructionStore::InstructionStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("InstructionStore: no database connection at construction ({}) — "
                      "instruction persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("InstructionStore: schema migration failed — instruction persistence "
                      "disabled");
        return;
    }
    // Second, independent line of defence behind the migration runner's own version guard
    // (ApiTokenStore's #3013/#2964 / ProductPackStore's Gate 8 F035 precedent) — fails CLOSED
    // (ADR-0012 §1) rather than surfacing a raw "relation does not exist" on the first call.
    pg::PgResult smoke = pg::exec_params(
        lease.get(), "SELECT 1 FROM instruction_store.deleted_seed_content LIMIT 0",
        std::vector<std::string>{});
    if (smoke.status() != PGRES_TUPLES_OK) {
        spdlog::error("InstructionStore: post-migration smoke-read of deleted_seed_content "
                      "failed ({}) — refusing to open (ADR-0012 §1 fail-closed)",
                      PQerrorMessage(lease.get()));
        return;
    }
    open_ = true;
    spdlog::info("InstructionStore: opened (schema {})", kStoreName);
}

// ---------------------------------------------------------------------------
// Definitions — reads
// ---------------------------------------------------------------------------

std::expected<std::vector<InstructionDefinition>, std::string>
InstructionStore::query_definitions(const InstructionQuery& q) const {
    if (!open_) {
        note_read_degrade(metrics_, kReasonStoreNotOpen);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        note_read_degrade(metrics_, kReasonPoolTimeout);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "pool acquire timeout");
    }

    std::string sql = std::string("SELECT ") + kDefinitionCols +
                      " FROM instruction_store.instruction_definitions WHERE TRUE";
    std::vector<std::string> binds;
    int n = 0;
    auto add_clause = [&](const char* clause, const std::string& val) {
        sql += " AND " + std::string(clause) + " $" + std::to_string(++n);
        binds.push_back(val);
    };
    if (!q.name_filter.empty())
        // Gate 4 happy-path finding 2: SQLite's LIKE is case-insensitive for ASCII by
        // default; plain Postgres LIKE is case-sensitive. Using ILIKE here restores the
        // pre-migration behaviour instead of silently returning zero rows for a query
        // that differs from an existing name only by case.
        add_clause("name ILIKE", "%" + q.name_filter + "%");
    if (!q.plugin_filter.empty())
        add_clause("plugin =", q.plugin_filter);
    if (!q.type_filter.empty())
        add_clause("type =", q.type_filter);
    if (!q.set_id_filter.empty())
        add_clause("instruction_set_id =", q.set_id_filter);
    if (q.enabled_only)
        sql += " AND enabled = TRUE";

    int limit = q.limit;
    if (limit <= 0)
        limit = kDefaultListLimit;
    limit = std::min(limit, kMaxListLimit);
    sql += " ORDER BY name ASC LIMIT $" + std::to_string(++n);
    binds.push_back(std::to_string(limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK) {
        note_read_degrade(metrics_, kReasonQueryError);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               PQerrorMessage(lease.get()));
    }
    std::vector<InstructionDefinition> out;
    out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i)
        out.push_back(read_definition_row(res.get(), i));
    return out;
}

std::expected<std::optional<InstructionDefinition>, std::string>
InstructionStore::get_definition(const std::string& id) const {
    if (!open_) {
        note_read_degrade(metrics_, kReasonStoreNotOpen);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        note_read_degrade(metrics_, kReasonPoolTimeout);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "pool acquire timeout");
    }
    std::string sql = std::string("SELECT ") + kDefinitionCols +
                      " FROM instruction_store.instruction_definitions WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        note_read_degrade(metrics_, kReasonQueryError);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               PQerrorMessage(lease.get()));
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<InstructionDefinition>{};
    return std::optional<InstructionDefinition>{read_definition_row(res.get(), 0)};
}

// ---------------------------------------------------------------------------
// Definitions — validation + create
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
InstructionStore::validate_and_prepare(InstructionDefinition& def) const {
    if (def.name.empty())
        return std::unexpected("name is required");
    if (def.type != "question" && def.type != "action")
        return std::unexpected("type must be 'question' or 'action'");
    if (def.plugin.empty())
        return std::unexpected("plugin is required");
    // #1398: reject an approval_mode outside the vocabulary the governed
    // execute path (workflow_routes.cpp) and the dispatch-chokepoint
    // ExecuteGate derivation both understand. An unvalidated value here
    // reached the runtime import path (import_definition_json_impl, the
    // ONLY caller besides create_definition) with zero enforcement — every
    // other create/update surface already checks this inline at the route
    // layer, but the store itself, which both the trusted boot-content
    // reseed loop and any future JSON-import caller go through, did not.
    if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
        def.approval_mode != "always" && !def.approval_mode.empty())
        return std::unexpected("invalid approval_mode: " + def.approval_mode +
                               " (must be auto, role-gated, or always)");

    if (auto err = validate_definition_scope(def.yaml_source))
        return std::unexpected(*err);

    // Explicit ids are operator-controlled (JSON create #402, YAML Save honouring metadata.id,
    // product-pack install). Bound them to a safe charset before they reach HTML fragments,
    // route paths, and audit rows (governance sec-M1: an unconstrained id is an
    // attribute-breakout / unroutable-record vector). Store-generated ids are hex — always pass.
    if (!def.id.empty()) {
        if (def.id.size() > 128)
            return std::unexpected("definition id too long (max 128 characters)");
        for (char c : def.id) {
            const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
            if (!ok)
                return std::unexpected(
                    "definition id may only contain letters, digits, '.', '_', and '-'");
        }
        // Reserved namespace (#2442): mcp.<tool> ids belong to the MCP approval-ticket gate.
        // Create-path only, deliberately: an update cannot originate an id, so an id that
        // predates the reservation stays editable and executable rather than becoming
        // uneditable on upgrade.
        if (is_reserved_definition_id(def.id))
            return std::unexpected(std::string(kReservedDefinitionIdError));
    } else {
        def.id = generate_id();
    }
    return def.id;
}

std::expected<std::string, std::string>
InstructionStore::insert_definition_row(const InstructionDefinition& def, bool is_seed) {
    if (!open_) {
        note_write_degrade(metrics_, "insert_definition_row");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }

    const auto now = now_epoch();
    const std::string created_at = std::to_string(def.created_at > 0 ? def.created_at : now);
    const std::string ps = def.parameter_schema.empty() ? "{}" : def.parameter_schema;
    const std::string rs = def.result_schema.empty() ? "{}" : def.result_schema;
    const std::string am = def.approval_mode.empty() ? "auto" : def.approval_mode;
    const std::string cm = def.concurrency_mode.empty() ? "per-device" : def.concurrency_mode;
    const std::string vs = def.visualization_spec.empty() ? "{}" : def.visualization_spec;
    const std::string rts =
        def.response_templates_spec.empty() ? "[]" : def.response_templates_spec;

    const char* insert_sql = R"(
        INSERT INTO instruction_store.instruction_definitions
        (id, name, version, type, plugin, action, description, enabled,
         instruction_set_id, gather_ttl_seconds, response_ttl_days,
         created_by, created_at, updated_at,
         yaml_source, parameter_schema, result_schema, approval_mode,
         concurrency_mode, platforms, min_agent_version, required_plugins,
         readable_payload, visualization_spec, response_templates_spec)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8::boolean,$9,$10::int,$11::int,$12,$13::bigint,$14::bigint,
                $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
        ON CONFLICT (id) DO NOTHING RETURNING id
    )";
    std::vector<std::string> binds{def.id,
                                   sanitize_pg_text(def.name),
                                   sanitize_pg_text(def.version),
                                   def.type,
                                   sanitize_pg_text(def.plugin),
                                   sanitize_pg_text(def.action),
                                   sanitize_pg_text(def.description),
                                   def.enabled ? "true" : "false",
                                   sanitize_pg_text(def.instruction_set_id),
                                   std::to_string(def.gather_ttl_seconds),
                                   std::to_string(def.response_ttl_days),
                                   sanitize_pg_text(def.created_by),
                                   created_at,
                                   std::to_string(now),
                                   def.yaml_source, // already NUL/size-gated by validate_definition_scope
                                   ps,
                                   rs,
                                   am,
                                   cm,
                                   sanitize_pg_text(def.platforms),
                                   sanitize_pg_text(def.min_agent_version),
                                   sanitize_pg_text(def.required_plugins),
                                   sanitize_pg_text(def.readable_payload),
                                   vs,
                                   rts};

    const std::string conflict_msg =
        std::string(kConflictPrefix) + " instruction definition '" + def.id + "' already exists";

    if (!is_seed) {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease) {
            note_write_degrade(metrics_, "insert_definition_row");
            return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                                   "pool acquire timeout");
        }
        pg::PgResult res = pg::exec_params(lease.get(), insert_sql, binds);
        if (res.status() != PGRES_TUPLES_OK) {
            note_write_degrade(metrics_, "insert_definition_row");
            return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                                   PQerrorMessage(lease.get()));
        }
        if (PQntuples(res.get()) == 0)
            return std::unexpected(conflict_msg);
        return def.id;
    }

    // Seed-aware path (ADR-0058): lock -> tombstone check -> insert, one transaction.
    std::string failure;
    bool tombstoned = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // MUST be the first statement — see kSeedCoordLockSql's comment.
        pg::PgResult lk = pg::exec_params(conn, kSeedCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            failure = std::format("seed-coordination lock: {}", PQerrorMessage(conn));
            return false;
        }
        pg::PgResult tomb = pg::exec_params(
            conn,
            "SELECT 1 FROM instruction_store.deleted_seed_content WHERE kind='definition' AND "
            "id=$1",
            std::vector<std::string>{def.id});
        if (tomb.status() != PGRES_TUPLES_OK) {
            failure = std::format("tombstone check: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(tomb.get()) > 0) {
            tombstoned = true;
            return true; // nothing to insert; commits an empty no-op txn
        }
        pg::PgResult res = pg::exec_params(conn, insert_sql, binds);
        if (res.status() != PGRES_TUPLES_OK) {
            failure = std::format("insert: {}", PQerrorMessage(conn));
            return false;
        }
        tombstoned = PQntuples(res.get()) == 0; // reuse the flag: "did not land" either way
        return true;
    });
    if (!ok) {
        note_write_degrade(metrics_, "insert_definition_row");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + failure);
    }
    if (tombstoned)
        return std::unexpected(conflict_msg);
    return def.id;
}

std::expected<std::string, std::string>
InstructionStore::create_definition(const InstructionDefinition& def) {
    InstructionDefinition d = def;
    auto prep = validate_and_prepare(d);
    if (!prep)
        return std::unexpected(prep.error());
    return insert_definition_row(d, /*is_seed=*/false);
}

// ---------------------------------------------------------------------------
// Definitions — update + delete
// ---------------------------------------------------------------------------

std::expected<void, std::string> InstructionStore::update_definition(const InstructionDefinition& def) {
    if (!open_) {
        note_write_degrade(metrics_, "update_definition");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }
    if (def.id.empty())
        return std::unexpected("id is required for update");

    // arch-B1/UP-4: the same scope-block validation the create path enforces — update must not
    // be a bypass for the fromResultSet rules.
    if (auto err = validate_definition_scope(def.yaml_source))
        return std::unexpected(*err);

    // #1398: mirror validate_and_prepare's approval_mode check — this function
    // does not call validate_and_prepare (unlike create_definition), and one
    // of its two REST callers (the YAML-paste dashboard editor route) sets
    // approval_mode from parsed content with no inline validation of its own.
    if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
        def.approval_mode != "always" && !def.approval_mode.empty())
        return std::unexpected("invalid approval_mode: " + def.approval_mode +
                               " (must be auto, role-gated, or always)");

    const char* sql = R"(
        UPDATE instruction_store.instruction_definitions SET
            name=$1, version=$2, type=$3, plugin=$4, action=$5, description=$6,
            enabled=$7::boolean, instruction_set_id=$8, gather_ttl_seconds=$9::int,
            response_ttl_days=$10::int, updated_at=$11::bigint,
            yaml_source=$12, parameter_schema=$13, result_schema=$14, approval_mode=$15,
            concurrency_mode=$16, platforms=$17, min_agent_version=$18, required_plugins=$19,
            readable_payload=$20, visualization_spec=$21, response_templates_spec=$22
        WHERE id=$23 RETURNING id
    )";
    const std::string ps = def.parameter_schema.empty() ? "{}" : def.parameter_schema;
    const std::string rs = def.result_schema.empty() ? "{}" : def.result_schema;
    const std::string am = def.approval_mode.empty() ? "auto" : def.approval_mode;
    const std::string cm = def.concurrency_mode.empty() ? "per-device" : def.concurrency_mode;
    const std::string vs = def.visualization_spec.empty() ? "{}" : def.visualization_spec;
    const std::string rts =
        def.response_templates_spec.empty() ? "[]" : def.response_templates_spec;
    std::vector<std::string> binds{sanitize_pg_text(def.name),
                                   sanitize_pg_text(def.version),
                                   def.type,
                                   sanitize_pg_text(def.plugin),
                                   sanitize_pg_text(def.action),
                                   sanitize_pg_text(def.description),
                                   def.enabled ? "true" : "false",
                                   sanitize_pg_text(def.instruction_set_id),
                                   std::to_string(def.gather_ttl_seconds),
                                   std::to_string(def.response_ttl_days),
                                   std::to_string(now_epoch()),
                                   def.yaml_source,
                                   ps,
                                   rs,
                                   am,
                                   cm,
                                   sanitize_pg_text(def.platforms),
                                   sanitize_pg_text(def.min_agent_version),
                                   sanitize_pg_text(def.required_plugins),
                                   sanitize_pg_text(def.readable_payload),
                                   vs,
                                   rts,
                                   def.id};

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        note_write_degrade(metrics_, "update_definition");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "pool acquire timeout");
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql, binds);
    if (res.status() != PGRES_TUPLES_OK) {
        note_write_degrade(metrics_, "update_definition");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               PQerrorMessage(lease.get()));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: definition not found: " + def.id);
    return {};
}

std::expected<void, std::string> InstructionStore::delete_definition(const std::string& id) {
    if (!open_) {
        note_write_degrade(metrics_, "delete_definition");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }

    std::string failure;
    bool deleted = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // MUST be the first statement — see kSeedCoordLockSql's comment.
        pg::PgResult lk = pg::exec_params(conn, kSeedCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            failure = std::format("seed-coordination lock: {}", PQerrorMessage(conn));
            return false;
        }
        pg::PgResult del = pg::exec_params(
            conn, "DELETE FROM instruction_store.instruction_definitions WHERE id=$1 RETURNING id",
            std::vector<std::string>{id});
        if (del.status() != PGRES_TUPLES_OK) {
            failure = std::format("delete: {}", PQerrorMessage(conn));
            return false;
        }
        deleted = PQntuples(del.get()) > 0;
        if (!deleted)
            return true; // nothing to tombstone; commits an empty no-op txn
        // ADR-0058: stamp the tombstone in the SAME transaction as the delete, so the
        // seed-aware insert path can never observe a deletion without also observing its
        // suppression marker.
        pg::PgResult tomb = pg::exec_params(
            conn,
            "INSERT INTO instruction_store.deleted_seed_content (kind, id, deleted_at) "
            "VALUES ('definition', $1, $2::bigint) ON CONFLICT (kind, id) DO NOTHING",
            std::vector<std::string>{id, std::to_string(now_epoch())});
        if (tomb.status() != PGRES_COMMAND_OK) {
            failure = std::format("tombstone stamp: {}", PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        note_write_degrade(metrics_, "delete_definition");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + failure);
    }
    if (!deleted)
        return std::unexpected("not_found: instruction definition not found: " + id);
    return {};
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
InstructionStore::export_definition_json(const std::string& id) const {
    auto def = get_definition(id);
    if (!def)
        return std::unexpected(def.error());
    if (!*def)
        return std::string("{}");

    // #4029: delegates to the shared pure builder (instruction_definition_model.hpp)
    // so this store's export format, GET /api/v1/instructions/{id}/export, and MCP
    // export_definition are the same shape by construction — nlohmann::json's
    // default (map-backed, key-sorted) container makes this dump(2) byte-identical
    // to the field-by-field construction it replaces.
    return instruction_definition_export_json(**def).dump(2);
}

std::expected<std::string, std::string>
InstructionStore::import_definition_json(const std::string& json_str) {
    return import_definition_json_impl(json_str, /*check_signature=*/true);
}

std::expected<std::string, std::string>
InstructionStore::import_definition_json_trusted(const std::string& json_str) {
    return import_definition_json_impl(json_str, /*check_signature=*/false);
}

std::expected<std::string, std::string>
InstructionStore::import_definition_json_impl(const std::string& json_str, bool check_signature) {
    // #2437-class guard: check nesting on the RAW body text BEFORE any parse
    // of it runs. Two sub-trees copied verbatim from this body reach
    // nlohmann::json::dump() below: visualization_spec via
    // normalize_to_array_helper and response_templates_spec via
    // normalise_templates_array. Rejecting here means the deep tree is never
    // even parsed, closing both sinks at once (mirrors the guaranteed-state
    // rule create/update guard's ordering in rest_api_v1.cpp). The
    // JSON-encoded-STRING form of either field is a SEPARATE admission
    // boundary (see the dedicated checks at their own re-parse sites below),
    // because a string literal's bracket characters are invisible to this
    // whole-body text scan by design (it must not count structure inside a
    // string value).
    if (mcp::json_exceeds_depth(json_str, mcp::kMcpMaxJsonDepth))
        return std::unexpected(std::format(
            "instruction-import request body nests too deeply (flatten to at most {} levels)",
            mcp::kMcpMaxJsonDepth));

    auto parsed = nlohmann::json::parse(json_str, nullptr, false);
    if (parsed.is_discarded())
        return std::unexpected("invalid JSON");

    // ── Ed25519 signature verification (#1073 / W7.4 sibling-gap closure) ──
    // Wire format mirrors ProductPack: optional top-level `signature` + `publicKey` fields,
    // hex-encoded. The signed content is the `yaml_source` field's bytes verbatim.
    //
    // This gates the IMPORT surface. Authoring surfaces (POST /api/instructions,
    // POST /api/instructions/yaml, PUT /api/instructions/{id}) trust the
    // InstructionDefinition:Write RBAC permission as the author trust boundary — see SECURITY
    // SCOPE comment on the public method in the .hpp.
    //
    // The trusted boot-content path (import_definition_json_trusted) skips this gate by passing
    // check_signature=false — bundled content authenticity comes from build-time binary linkage,
    // not runtime signature. It ALSO means "this is the reseed loop" (no REST/MCP/network
    // surface reaches this path by design) — routed to the seed-aware insert below (ADR-0058).
    if (check_signature) {
        // Round 1 governance unhappy-path R5: distinguish "field absent" from "field present but
        // wrong JSON type". Returning empty-string silently for both made attacker-corrupted
        // payloads ({"signature": 42}) reject with the misleading "unsigned" error. Use a
        // tri-state so we can emit a precise rejection reason.
        enum class FieldState { Absent, WrongType, Present };
        auto extract_str = [&](const char* key, std::string& out) -> FieldState {
            if (!parsed.contains(key))
                return FieldState::Absent;
            const auto& v = parsed[key];
            if (v.is_null())
                return FieldState::Absent; // null treated as absent
            if (!v.is_string())
                return FieldState::WrongType;
            out = v.get<std::string>();
            return out.empty() ? FieldState::Absent : FieldState::Present;
        };
        std::string sig_hex, pub_hex, yaml_source;
        const auto sig_state = extract_str("signature", sig_hex);
        const auto pub_state = extract_str("publicKey", pub_hex);
        const auto yaml_state = extract_str("yaml_source", yaml_source);

        if (sig_state == FieldState::WrongType || pub_state == FieldState::WrongType ||
            yaml_state == FieldState::WrongType) {
            return std::unexpected(
                "instruction-import has signing field of wrong JSON type — "
                "signature, publicKey, and yaml_source must be strings when present");
        }

        // R6 (unhappy-path): length-validate hex strings BEFORE handing to
        // ProductPackStore::verify_signature so an attacker can't post a multi-MB sig_hex and
        // trigger a server-side allocation peak. Ed25519: signature = 64 bytes (128 hex chars),
        // public key = 32 bytes (64 hex chars). Reject any other length.
        constexpr std::size_t kEd25519SigHexLen = 128;
        constexpr std::size_t kEd25519PubHexLen = 64;
        if (sig_state == FieldState::Present && sig_hex.size() != kEd25519SigHexLen) {
            return std::unexpected("signature length invalid — Ed25519 signature must be "
                                   "exactly 128 hex chars (64 bytes)");
        }
        if (pub_state == FieldState::Present && pub_hex.size() != kEd25519PubHexLen) {
            return std::unexpected("publicKey length invalid — Ed25519 public key must be "
                                   "exactly 64 hex chars (32 bytes)");
        }

        if (sig_state == FieldState::Present && pub_state == FieldState::Present) {
            // Both fields present → verify. Failure rejects unconditionally regardless of
            // require_signed_definitions_ (a failed signature is evidence of tampering, not a
            // policy question).
            if (yaml_state != FieldState::Present) {
                return std::unexpected(
                    "instruction-import has signature + publicKey but no yaml_source — "
                    "yaml_source is the signed content carrier; cannot verify");
            }
            if (!ProductPackStore::verify_signature(yaml_source, sig_hex, pub_hex)) {
                spdlog::error("InstructionStore::import_definition_json: signature verification "
                              "FAILED — rejecting definition (content may be tampered)");
                return std::unexpected(
                    "signature verification failed for instruction — content may "
                    "have been tampered with");
            }
            spdlog::info("InstructionStore::import_definition_json: signature verified");
        } else if (sig_state == FieldState::Present || pub_state == FieldState::Present) {
            // Exactly one field present — incomplete signing metadata, reject.
            return std::unexpected(
                "instruction-import has incomplete signing metadata — both "
                "signature and publicKey must be present together (or both absent)");
        } else {
            // No signature → unsigned import; gated by require_signed_definitions_.
            if (require_signed_definitions_.load(std::memory_order_relaxed)) {
                spdlog::error("InstructionStore::import_definition_json: definition is unsigned "
                              "but signature enforcement is enabled — rejecting");
                return std::unexpected(
                    "instruction-import is unsigned and signature enforcement is enabled "
                    "(set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 "
                    "to bypass)");
            }
            spdlog::info("InstructionStore::import_definition_json: definition has no signature "
                         "— importing as unverified");
        }
    }

    InstructionDefinition def;
    if (parsed.contains("id"))
        def.id = parsed["id"].get<std::string>();
    if (parsed.contains("name"))
        def.name = parsed["name"].get<std::string>();
    if (parsed.contains("version"))
        def.version = parsed.value("version", "1.0");
    if (parsed.contains("type"))
        def.type = parsed["type"].get<std::string>();
    if (parsed.contains("plugin"))
        def.plugin = parsed["plugin"].get<std::string>();
    if (parsed.contains("action"))
        def.action = parsed.value("action", "");
    if (parsed.contains("description"))
        def.description = parsed.value("description", "");
    if (parsed.contains("enabled"))
        def.enabled = parsed.value("enabled", true);
    if (parsed.contains("instruction_set_id"))
        def.instruction_set_id = parsed.value("instruction_set_id", "");
    if (parsed.contains("gather_ttl_seconds"))
        def.gather_ttl_seconds = parsed.value("gather_ttl_seconds", 300);
    if (parsed.contains("response_ttl_days"))
        def.response_ttl_days = parsed.value("response_ttl_days", 90);
    if (parsed.contains("created_by"))
        def.created_by = parsed.value("created_by", "");
    if (parsed.contains("yaml_source"))
        def.yaml_source = parsed.value("yaml_source", "");
    if (parsed.contains("parameter_schema")) {
        def.parameter_schema = parsed.value("parameter_schema", "{}");
        // #2437-class guard: parameter_schema is stored VERBATIM as a
        // caller-supplied string, with no re-serialization or validation at
        // write time otherwise - unlike visualization_spec/
        // response_templates_spec above, nothing here would ever dump() it
        // at import time. The crash lands later, on the discover-catalog
        // READ side (discover_routes.cpp), reached by a completely different
        // caller than whoever imported it. Rejecting the too-deep string
        // here at write time prevents new poison; discover_routes.cpp's own
        // guard protects rows already written before this check shipped.
        if (mcp::json_exceeds_depth(def.parameter_schema, mcp::kMcpMaxJsonDepth))
            return std::unexpected(std::format(
                "instruction-import parameter_schema nests too deeply (flatten to at most {} "
                "levels)",
                mcp::kMcpMaxJsonDepth));
    }
    if (parsed.contains("result_schema"))
        def.result_schema = parsed.value("result_schema", "{}");
    if (parsed.contains("approval_mode"))
        def.approval_mode = parsed.value("approval_mode", "auto");
    if (parsed.contains("concurrency_mode"))
        def.concurrency_mode = parsed.value("concurrency_mode", "per-device");
    if (parsed.contains("platforms"))
        def.platforms = parsed.value("platforms", "");
    if (parsed.contains("min_agent_version"))
        def.min_agent_version = parsed.value("min_agent_version", "");
    if (parsed.contains("required_plugins"))
        def.required_plugins = parsed.value("required_plugins", "");
    if (parsed.contains("readable_payload"))
        def.readable_payload = parsed.value("readable_payload", "");
    // Issue #587: visualization_spec is stored as a JSON ARRAY of chart objects so the engine
    // and routes only have to handle one shape. All accepted wire forms normalise to
    // "[{...}, {...}, ...]" before storage. Invalid/non-object array entries are silently
    // dropped at this point — strict validation lives in the engine.
    auto normalize_to_array = [](const nlohmann::json& v) -> std::string {
        if (v.is_string()) {
            auto inner = nlohmann::json::parse(v.get<std::string>(), nullptr, false);
            if (inner.is_discarded())
                return v.get<std::string>(); // pass through
            return normalize_to_array_helper(inner);
        }
        return normalize_to_array_helper(v);
    };
    auto pick_spec_field = [&]() -> std::optional<nlohmann::json> {
        if (parsed.contains("visualization_spec") && !parsed["visualization_spec"].is_null())
            return parsed["visualization_spec"];
        if (parsed.contains("visualizations") && !parsed["visualizations"].is_null())
            return parsed["visualizations"];
        if (parsed.contains("visualization") && !parsed["visualization"].is_null())
            return parsed["visualization"];
        return std::nullopt;
    };
    if (auto v = pick_spec_field(); v) {
        // #2437-class guard, string-form companion: the whole-body guard
        // above scans raw text and correctly does NOT count brackets inside
        // a string literal as structure, so a visualization_spec supplied as
        // a JSON-ENCODED STRING reads as an ordinary shallow field there
        // while its own decoded content, re-parsed by normalize_to_array
        // just below, can nest arbitrarily deep. This is a SEPARATE
        // admission boundary on the string's own text, checked before its
        // internal re-parse.
        if (v->is_string() &&
            mcp::json_exceeds_depth(v->get_ref<const std::string&>(), mcp::kMcpMaxJsonDepth)) {
            return std::unexpected(std::format(
                "instruction-import visualization_spec nests too deeply (flatten to at most "
                "{} levels)",
                mcp::kMcpMaxJsonDepth));
        }
        def.visualization_spec = normalize_to_array(*v);
    }

    // Issue #254 (8.2): spec.responseTemplates — accept canonical responseTemplates (camelCase
    // YAML), the snake-case storage column name response_templates_spec, and the explicit
    // pre-serialised string form. Always normalises to a JSON array string at rest.
    auto pick_templates_field = [&]() -> std::optional<nlohmann::json> {
        if (parsed.contains("response_templates_spec") &&
            !parsed["response_templates_spec"].is_null())
            return parsed["response_templates_spec"];
        if (parsed.contains("responseTemplates") && !parsed["responseTemplates"].is_null())
            return parsed["responseTemplates"];
        if (parsed.contains("response_templates") && !parsed["response_templates"].is_null())
            return parsed["response_templates"];
        return std::nullopt;
    };
    static constexpr size_t kMaxImportTemplateStringBytes = 256 * 1024; // 256 KiB
    auto strip_reserved_id = [](const nlohmann::json& el) -> bool {
        if (!el.is_object())
            return true; // drop non-objects entirely
        if (el.contains("id") && el["id"].is_string() &&
            el["id"].get<std::string>() ==
                std::string(::yuzu::server::ResponseTemplatesEngine::kDefaultId)) {
            return true; // drop reserved id
        }
        return false;
    };
    auto normalise_templates_array = [&](const nlohmann::json& src) -> nlohmann::json {
        nlohmann::json out = nlohmann::json::array();
        if (src.is_array()) {
            for (const auto& el : src) {
                if (strip_reserved_id(el))
                    continue;
                out.push_back(el);
            }
        } else if (src.is_object()) {
            if (!strip_reserved_id(src))
                out.push_back(src);
        }
        return out;
    };
    if (auto v = pick_templates_field(); v) {
        if (v->is_string()) {
            const std::string& s = v->get_ref<const std::string&>();
            if (s.size() > kMaxImportTemplateStringBytes) {
                spdlog::warn("InstructionStore::import_definition_json: responseTemplates "
                             "string exceeds {} bytes; dropped (governance sec-M4 / UP-15)",
                             kMaxImportTemplateStringBytes);
                def.response_templates_spec = "[]";
            } else if (mcp::json_exceeds_depth(s, mcp::kMcpMaxJsonDepth)) {
                // #2437-class guard, string-form companion (see the
                // visualization_spec sibling check above): the 256 KiB cap
                // just above leaves comfortably enough room for well over
                // 100,000 levels of nesting, and this string's own decoded
                // content is re-parsed just below. Rejects the WHOLE import
                // outright - unlike the oversized/invalid-JSON siblings
                // here, which drop the field and let the import proceed, a
                // too-deep string is evidence of a hostile payload, not a
                // benign-but-oversized one.
                return std::unexpected(std::format(
                    "instruction-import response_templates_spec nests too deeply (flatten to "
                    "at most {} levels)",
                    mcp::kMcpMaxJsonDepth));
            } else {
                auto inner = nlohmann::json::parse(s, nullptr, /*allow_exceptions=*/false);
                if (inner.is_discarded()) {
                    spdlog::warn("InstructionStore::import_definition_json: responseTemplates "
                                 "string is not valid JSON; dropped (governance UP-15)");
                    def.response_templates_spec = "[]";
                } else {
                    def.response_templates_spec = normalise_templates_array(inner).dump();
                }
            }
        } else {
            def.response_templates_spec = normalise_templates_array(*v).dump();
        }
    }

    auto prep = validate_and_prepare(def);
    if (!prep)
        return std::unexpected(prep.error());
    return insert_definition_row(def, /*is_seed=*/!check_signature);
}

// ---------------------------------------------------------------------------
// Instruction Sets
// ---------------------------------------------------------------------------

std::expected<std::vector<InstructionSet>, std::string> InstructionStore::list_sets() const {
    if (!open_) {
        note_read_degrade(metrics_, kReasonStoreNotOpen);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        note_read_degrade(metrics_, kReasonPoolTimeout);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "pool acquire timeout");
    }
    std::string sql =
        std::string("SELECT ") + kSetCols + " FROM instruction_store.instruction_sets ORDER BY name";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        note_read_degrade(metrics_, kReasonQueryError);
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               PQerrorMessage(lease.get()));
    }
    std::vector<InstructionSet> out;
    out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i)
        out.push_back(read_set_row(res.get(), i));
    return out;
}

std::expected<std::string, std::string> InstructionStore::insert_set_row(const InstructionSet& s,
                                                                         bool is_seed) {
    if (!open_) {
        note_write_degrade(metrics_, "insert_set_row");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }
    const std::string id = s.id.empty() ? generate_id() : s.id;
    const std::string created_at = std::to_string(s.created_at > 0 ? s.created_at : now_epoch());
    const char* insert_sql =
        "INSERT INTO instruction_store.instruction_sets (id, name, description, created_by, "
        "created_at) VALUES ($1,$2,$3,$4,$5::bigint) ON CONFLICT (id) DO NOTHING RETURNING id";
    std::vector<std::string> binds{id, sanitize_pg_text(s.name), sanitize_pg_text(s.description),
                                   sanitize_pg_text(s.created_by), created_at};
    const std::string conflict_msg =
        std::string(kConflictPrefix) + " instruction set '" + id + "' already exists";

    if (!is_seed) {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease) {
            note_write_degrade(metrics_, "insert_set_row");
            return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                                   "pool acquire timeout");
        }
        pg::PgResult res = pg::exec_params(lease.get(), insert_sql, binds);
        if (res.status() != PGRES_TUPLES_OK) {
            note_write_degrade(metrics_, "insert_set_row");
            return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                                   PQerrorMessage(lease.get()));
        }
        if (PQntuples(res.get()) == 0)
            return std::unexpected(conflict_msg);
        return id;
    }

    std::string failure;
    bool tombstoned = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lk = pg::exec_params(conn, kSeedCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            failure = std::format("seed-coordination lock: {}", PQerrorMessage(conn));
            return false;
        }
        pg::PgResult tomb = pg::exec_params(
            conn,
            "SELECT 1 FROM instruction_store.deleted_seed_content WHERE kind='set' AND id=$1",
            std::vector<std::string>{id});
        if (tomb.status() != PGRES_TUPLES_OK) {
            failure = std::format("tombstone check: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(tomb.get()) > 0) {
            tombstoned = true;
            return true;
        }
        pg::PgResult res = pg::exec_params(conn, insert_sql, binds);
        if (res.status() != PGRES_TUPLES_OK) {
            failure = std::format("insert: {}", PQerrorMessage(conn));
            return false;
        }
        tombstoned = PQntuples(res.get()) == 0;
        return true;
    });
    if (!ok) {
        note_write_degrade(metrics_, "insert_set_row");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + failure);
    }
    if (tombstoned)
        return std::unexpected(conflict_msg);
    return id;
}

std::expected<std::string, std::string> InstructionStore::create_set(const InstructionSet& s) {
    if (s.name.empty())
        return std::unexpected("name is required");
    return insert_set_row(s, /*is_seed=*/false);
}

std::expected<std::string, std::string> InstructionStore::create_set_seed(const InstructionSet& s) {
    if (s.name.empty())
        return std::unexpected("name is required");
    return insert_set_row(s, /*is_seed=*/true);
}

std::expected<void, std::string> InstructionStore::delete_set(const std::string& id) {
    if (!open_) {
        note_write_degrade(metrics_, "delete_set");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + "store not open");
    }

    std::string failure;
    bool deleted = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lk = pg::exec_params(conn, kSeedCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            failure = std::format("seed-coordination lock: {}", PQerrorMessage(conn));
            return false;
        }
        // Check existence BEFORE unlinking anything — a not-found delete_set must be a pure
        // no-op, never a partial mutation (a coincidental/typo'd id must not silently strip
        // instruction_set_id off unrelated definitions on a call that reports "not found").
        pg::PgResult del = pg::exec_params(
            conn, "DELETE FROM instruction_store.instruction_sets WHERE id=$1 RETURNING id",
            std::vector<std::string>{id});
        if (del.status() != PGRES_TUPLES_OK) {
            failure = std::format("delete: {}", PQerrorMessage(conn));
            return false;
        }
        deleted = PQntuples(del.get()) > 0;
        if (!deleted)
            return true;
        // Unset instruction_set_id on definitions that reference this set — matches the
        // pre-migration behaviour exactly.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE instruction_store.instruction_definitions SET instruction_set_id='' WHERE "
            "instruction_set_id=$1",
            std::vector<std::string>{id});
        if (upd.status() != PGRES_COMMAND_OK) {
            failure = std::format("unlink referencing definitions: {}", PQerrorMessage(conn));
            return false;
        }
        pg::PgResult tomb = pg::exec_params(
            conn,
            "INSERT INTO instruction_store.deleted_seed_content (kind, id, deleted_at) VALUES "
            "('set', $1, $2::bigint) ON CONFLICT (kind, id) DO NOTHING",
            std::vector<std::string>{id, std::to_string(now_epoch())});
        if (tomb.status() != PGRES_COMMAND_OK) {
            failure = std::format("tombstone stamp: {}", PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        note_write_degrade(metrics_, "delete_set");
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) + failure);
    }
    if (!deleted)
        return std::unexpected("not_found: instruction set not found: " + id);
    return {};
}

} // namespace yuzu::server
