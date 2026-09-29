#include "policy_store.hpp"

#include "cel_eval.hpp"
#include "compliance_eval.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_raii.hpp"
#include "scope_yaml.hpp"
#include "store_errors.hpp"
#include "utf8_sanitize.hpp"
#include "yaml_scan.hpp"

#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

constexpr const char* kStoreName = "policy_store";
constexpr auto kAcquireTimeout = std::chrono::milliseconds(3000);
constexpr auto kClaimTimeout = std::chrono::milliseconds(5000);
constexpr int64_t kStalenessTtl = 24 * 3600; // fleet-compliance freshness window
constexpr int kMaxFixAttempts = 3;

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// Mirrors DeploymentRunStore's identically-named helpers — bind a
// vector<string> as a text[] literal (pg::to_text_array wants string_views),
// and collect a RETURNING-column result back into a vector<string>.
std::vector<std::string_view> as_views(const std::vector<std::string>& v) {
    std::vector<std::string_view> out;
    out.reserve(v.size());
    for (const auto& s : v)
        out.emplace_back(s);
    return out;
}

std::vector<std::string> returned_ids(const pg::PgResult& res) {
    std::vector<std::string> out;
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    out.reserve(static_cast<size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i)
        out.push_back(text_col(res.get(), i, 0));
    return out;
}

bool is_fk_violation(const pg::PgResult& res) {
    const char* sqlstate = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return sqlstate != nullptr && std::string_view(sqlstate) == "23503";
}

// PG bind text must not carry a raw NUL — an agent-influenced field
// (check_result is built from an agent's plugin output) could otherwise hit
// a truncation error mid-insert. Mirrors AuditStore's PG-local wrapper.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

using yaml_scan::extract_yaml_list;
using yaml_scan::extract_yaml_mapping;
using yaml_scan::extract_yaml_section;
using yaml_scan::extract_yaml_value;

// ── Column lists + row readers ───────────────────────────────────────────────

constexpr const char* kFragmentCols =
    "id, name, description, yaml_source, check_instruction, check_compliance, "
    "check_parameters, fix_instruction, fix_parameters, post_check_instruction, "
    "post_check_compliance, post_check_parameters, created_at, updated_at";

PolicyFragment read_fragment(PGresult* res, int row) {
    PolicyFragment f;
    int c = 0;
    f.id = text_col(res, row, c++);
    f.name = text_col(res, row, c++);
    f.description = text_col(res, row, c++);
    f.yaml_source = text_col(res, row, c++);
    f.check_instruction = text_col(res, row, c++);
    f.check_compliance = text_col(res, row, c++);
    f.check_parameters = text_col(res, row, c++);
    f.fix_instruction = text_col(res, row, c++);
    f.fix_parameters = text_col(res, row, c++);
    f.post_check_instruction = text_col(res, row, c++);
    f.post_check_compliance = text_col(res, row, c++);
    f.post_check_parameters = text_col(res, row, c++);
    f.created_at = to_i64(PQgetvalue(res, row, c++));
    f.updated_at = to_i64(PQgetvalue(res, row, c++));
    return f;
}

constexpr const char* kPolicyCols = "id, name, description, yaml_source, fragment_id, "
                                    "scope_expression, enabled, created_at, updated_at";

Policy read_policy_row(PGresult* res, int row) {
    Policy p;
    int c = 0;
    p.id = text_col(res, row, c++);
    p.name = text_col(res, row, c++);
    p.description = text_col(res, row, c++);
    p.yaml_source = text_col(res, row, c++);
    p.fragment_id = text_col(res, row, c++);
    p.scope_expression = text_col(res, row, c++);
    p.enabled = to_bool(PQgetvalue(res, row, c++));
    p.created_at = to_i64(PQgetvalue(res, row, c++));
    p.updated_at = to_i64(PQgetvalue(res, row, c++));
    return p;
}

constexpr const char* kAgentStatusCols =
    "policy_id, agent_id, status, last_check_at, last_fix_at, check_result";

PolicyAgentStatus read_agent_status(PGresult* res, int row) {
    PolicyAgentStatus s;
    int c = 0;
    s.policy_id = text_col(res, row, c++);
    s.agent_id = text_col(res, row, c++);
    s.status = text_col(res, row, c++);
    s.last_check_at = to_i64(PQgetvalue(res, row, c++));
    s.last_fix_at = to_i64(PQgetvalue(res, row, c++));
    s.check_result = text_col(res, row, c++);
    return s;
}

// Loads a policy's inputs/triggers/management-groups on the SAME connection
// (shared by the public get_policy()/query_policies() lease and
// claim_due_policies()'s in-transaction conn). Returns false if ANY detail
// query fails — these reads feed dispatch/remediation targeting decisions,
// so a partial load must never be indistinguishable from a genuinely
// detail-less policy (adversarial review, 2026-08-24: previously silently
// left the affected vector empty and returned success regardless).
bool load_policy_details(PGconn* conn, Policy& p) {
    pg::PgResult inputs = pg::exec_params(
        conn, "SELECT key, value FROM policy_store.policy_inputs WHERE policy_id = $1",
        std::vector<std::string>{p.id});
    if (inputs.status() != PGRES_TUPLES_OK)
        return false;
    for (int i = 0; i < PQntuples(inputs.get()); ++i) {
        PolicyInput inp;
        inp.policy_id = p.id;
        inp.key = text_col(inputs.get(), i, 0);
        inp.value = text_col(inputs.get(), i, 1);
        p.inputs.push_back(std::move(inp));
    }
    pg::PgResult triggers = pg::exec_params(
        conn,
        "SELECT id, trigger_type, config_json FROM policy_store.policy_triggers "
        "WHERE policy_id = $1",
        std::vector<std::string>{p.id});
    if (triggers.status() != PGRES_TUPLES_OK)
        return false;
    for (int i = 0; i < PQntuples(triggers.get()); ++i) {
        PolicyTrigger t;
        t.id = to_i64(PQgetvalue(triggers.get(), i, 0));
        t.policy_id = p.id;
        t.trigger_type = text_col(triggers.get(), i, 1);
        t.config_json = text_col(triggers.get(), i, 2);
        p.triggers.push_back(std::move(t));
    }
    pg::PgResult groups = pg::exec_params(
        conn, "SELECT group_id FROM policy_store.policy_groups WHERE policy_id = $1",
        std::vector<std::string>{p.id});
    if (groups.status() != PGRES_TUPLES_OK)
        return false;
    for (int i = 0; i < PQntuples(groups.get()); ++i)
        p.management_groups.push_back(text_col(groups.get(), i, 0));
    return true;
}

// Distinguishes "not found" (nullopt, success) from a DB error (unexpected)
// at BOTH the top-level policies query and the detail-table loads — a
// caller must never see a present-but-partial Policy on a detail-query
// failure (adversarial review, 2026-08-24: the top-level query already had
// this distinction; the detail loader silently swallowed its own failures
// and this function returned a plain optional that erased even the
// top-level distinction on the way out through get_policy()).
std::expected<std::optional<Policy>, PolicyReadError> read_policy_by_id(PGconn* conn,
                                                                        const std::string& id) {
    std::string sql = std::string("SELECT ") + kPolicyCols +
                      " FROM policy_store.policies WHERE id = $1";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(PolicyReadError::kDegraded);
    if (PQntuples(res.get()) == 0)
        return std::optional<Policy>{std::nullopt};
    Policy p = read_policy_row(res.get(), 0);
    if (!load_policy_details(conn, p))
        return std::unexpected(PolicyReadError::kDegraded);
    return std::optional<Policy>{std::move(p)};
}

/// Moved from policy_evaluator.cpp (ADR-0056): due-ness is now fully internal
/// to the store, so nothing outside claim_due_policies needs this anymore.
int64_t interval_from_config_json(const std::string& config_json, int64_t default_seconds) {
    if (config_json.empty())
        return default_seconds;
    auto cfg = nlohmann::json::parse(config_json, nullptr, false);
    if (cfg.is_discarded() || !cfg.is_object() || !cfg.contains("interval_seconds"))
        return default_seconds;
    const auto& v = cfg["interval_seconds"];
    if (v.is_number())
        return v.get<int64_t>();
    if (v.is_string()) {
        try {
            return std::stoll(v.get<std::string>());
        } catch (...) {
        }
    }
    return default_seconds;
}

// ── Migrations ───────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the
    // migration transaction. Runtime statements below schema-qualify
    // explicitly. PG v1 == SQLite v1 + the ALTER-wart (G4-UHP-POL-003) folded
    // straight in — fix_attempt_count was never a separate migration step.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE policy_fragments ("
         "  id                     TEXT PRIMARY KEY,"
         "  name                   TEXT NOT NULL,"
         "  description            TEXT NOT NULL DEFAULT '',"
         "  yaml_source            TEXT NOT NULL,"
         "  check_instruction      TEXT,"
         "  check_compliance       TEXT,"
         "  check_parameters       TEXT NOT NULL DEFAULT '{}',"
         "  fix_instruction        TEXT,"
         "  fix_parameters         TEXT NOT NULL DEFAULT '{}',"
         "  post_check_instruction TEXT,"
         "  post_check_compliance  TEXT,"
         "  post_check_parameters  TEXT NOT NULL DEFAULT '{}',"
         "  created_at             BIGINT NOT NULL DEFAULT 0,"
         "  updated_at             BIGINT NOT NULL DEFAULT 0"
         ");"
         "CREATE TABLE policies ("
         "  id               TEXT PRIMARY KEY,"
         "  name             TEXT NOT NULL,"
         "  description      TEXT NOT NULL DEFAULT '',"
         "  yaml_source      TEXT NOT NULL,"
         "  fragment_id      TEXT NOT NULL REFERENCES policy_fragments(id),"
         "  scope_expression TEXT,"
         "  enabled          BOOLEAN NOT NULL DEFAULT TRUE,"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  updated_at       BIGINT NOT NULL DEFAULT 0"
         ");"
         "CREATE INDEX idx_policies_fragment ON policies(fragment_id);"
         "CREATE INDEX idx_policies_enabled ON policies(enabled);"
         "CREATE TABLE policy_inputs ("
         "  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
         "  key       TEXT NOT NULL,"
         "  value     TEXT NOT NULL,"
         "  PRIMARY KEY (policy_id, key)"
         ");"
         "CREATE TABLE policy_triggers ("
         "  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  policy_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
         "  trigger_type TEXT NOT NULL,"
         "  config_json  TEXT NOT NULL DEFAULT '{}'"
         ");"
         "CREATE INDEX idx_policy_triggers_policy ON policy_triggers(policy_id);"
         "CREATE TABLE policy_groups ("
         "  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
         "  group_id  TEXT NOT NULL,"
         "  PRIMARY KEY (policy_id, group_id)"
         ");"
         // policy_status gains a real FK (SQLite had none — delete_policy hand-
         // wrote a second DELETE whose failure was silently swallowed; the
         // cascade now makes that cleanup declarative and unconditional).
         "CREATE TABLE policy_status ("
         "  policy_id         TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
         "  agent_id          TEXT NOT NULL,"
         "  status            TEXT NOT NULL DEFAULT 'unknown',"
         "  last_check_at     BIGINT NOT NULL DEFAULT 0,"
         "  last_fix_at       BIGINT NOT NULL DEFAULT 0,"
         "  check_result      TEXT NOT NULL DEFAULT '',"
         "  fix_attempt_count INTEGER NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (policy_id, agent_id)"
         ");"
         "CREATE INDEX idx_policy_status_status ON policy_status(status);"
         // New, operational only (ADR-0056) — never backfilled, never read
         // outside claim_due_policies.
         "CREATE TABLE policy_dispatch_state ("
         "  policy_id          TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,"
         "  last_dispatched_at BIGINT NOT NULL DEFAULT 0"
         ");"},
        // HA WS-3 3.4: durable per-(policy,agent) remediation claim, closing
        // the gap left by the evaluator's old process-local `remediating_`
        // guard under active-active HA (two replicas each independently
        // dispatching the same fix and each incrementing fix_attempt_count —
        // a real double-fire, not an idempotent race). 0 = unclaimed; a
        // non-zero value is the claiming replica's epoch-seconds `now()` at
        // claim time, aged out by `claim_remediation`'s own WHERE guard
        // (never a separate reaper — see that method's doc comment).
        {2, "ALTER TABLE policy_status ADD COLUMN remediation_claim_at BIGINT NOT NULL DEFAULT 0;"},
        // HA WS-3 3.4 (review B3): the per-(policy,agent) claim's owner/occurrence
        // token. Minted per claim CALL from remediation_claim_seq; fences
        // release and remediation-owned status writes against ABA (a stale
        // holder releasing/overwriting a row a sibling has reclaimed). DEFAULT 0
        // is the "no claim / pre-v3 row" sentinel — a value nextval never mints,
        // so an old binary's rows are one-directionally distinguishable.
        {3, "ALTER TABLE policy_status ADD COLUMN remediation_claim_gen BIGINT NOT NULL DEFAULT 0;"},
        {4, "CREATE SEQUENCE IF NOT EXISTS remediation_claim_seq;"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

PolicyStore::PolicyStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire(); // unbounded — construction-only (ADR-0012 §2a)
    if (!lease) {
        spdlog::error("PolicyStore: no database connection at construction ({}) — "
                      "policy engine persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("PolicyStore: schema migration failed — policy engine persistence disabled");
        return;
    }
    open_ = true;
    spdlog::info("PolicyStore: opened on Postgres (schema {})", kStoreName);
}

std::string PolicyStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                 static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

std::string PolicyStore::peek_fragment_name(const std::string& yaml_source) {
    auto display = extract_yaml_value(yaml_source, "displayName");
    if (!display.empty())
        return display;
    auto name = extract_yaml_value(yaml_source, "name");
    if (!name.empty())
        return name;
    return extract_yaml_value(yaml_source, "id");
}

// ── Fragment CRUD ────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
PolicyStore::create_fragment(const std::string& yaml_source) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (yaml_source.empty())
        return std::unexpected("yaml_source is required");
    if (yaml_source.size() > 1048576)
        return std::unexpected("YAML too large (max 1MB)");

    auto kind = extract_yaml_value(yaml_source, "kind");
    if (kind != "PolicyFragment")
        return std::unexpected(kind_mismatch_error(
            "PolicyFragment", kind,
            "  apiVersion: yuzu.io/v1alpha1\n"
            "  kind: PolicyFragment\n"
            "  metadata:\n"
            "    name: my-fragment\n"
            "  spec:\n"
            "    check:\n"
            "      plugin: <plugin>\n"
            "      action: <action>\n"
            "      compliance: <CEL expression>\n",
            "docs/user-manual/policy-engine.md"));

    auto id_val = extract_yaml_value(yaml_source, "id");
    auto id = id_val.empty() ? generate_id() : id_val;
    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        name = id;
    auto description = extract_yaml_value(yaml_source, "description");

    auto check_section = extract_yaml_section(yaml_source, "spec.check");
    auto check_instruction = extract_yaml_value(check_section, "instruction");
    auto check_compliance = extract_yaml_value(check_section, "compliance");
    auto check_params_map = extract_yaml_mapping(check_section, "parameters");
    nlohmann::json check_params_json = nlohmann::json::object();
    for (const auto& [k, v] : check_params_map)
        check_params_json[k] = v;

    auto fix_section = extract_yaml_section(yaml_source, "spec.fix");
    auto fix_instruction = extract_yaml_value(fix_section, "instruction");
    auto fix_params_map = extract_yaml_mapping(fix_section, "parameters");
    nlohmann::json fix_params_json = nlohmann::json::object();
    for (const auto& [k, v] : fix_params_map)
        fix_params_json[k] = v;

    auto post_section = extract_yaml_section(yaml_source, "spec.postCheck");
    auto post_instruction = extract_yaml_value(post_section, "instruction");
    auto post_compliance = extract_yaml_value(post_section, "compliance");
    auto post_params_map = extract_yaml_mapping(post_section, "parameters");
    nlohmann::json post_params_json = nlohmann::json::object();
    for (const auto& [k, v] : post_params_map)
        post_params_json[k] = v;

    if (!check_compliance.empty()) {
        check_compliance = cel::migrate_expression(check_compliance);
        auto err = validate_compliance_expression(check_compliance);
        if (!err.empty())
            return std::unexpected("invalid check compliance expression: " + err);
    }
    if (!post_compliance.empty()) {
        post_compliance = cel::migrate_expression(post_compliance);
        auto err = validate_compliance_expression(post_compliance);
        if (!err.empty())
            return std::unexpected("invalid postCheck compliance expression: " + err);
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    // #396: duplicate-name pre-check. NOT unique-constraint-enforced (no
    // UNIQUE(name) — see the header note on write-once tables; adding one
    // now would need backfill to tolerate legacy duplicate names, out of
    // scope here). A concurrent create on two replicas racing the identical
    // name is a narrow, accepted residual — same class as the evaluator's
    // manual-remediate residual in ADR-0056.
    pg::PgResult exists = pg::exec_params(
        lease.get(), "SELECT EXISTS(SELECT 1 FROM policy_store.policy_fragments WHERE name = $1)",
        std::vector<std::string>{name});
    if (exists.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: duplicate-name check failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "internal: duplicate-name check failed");
    }
    if (to_bool(PQgetvalue(exists.get(), 0, 0)))
        return std::unexpected(std::string(kConflictPrefix) + " policy fragment named '" + name +
                               "' already exists");

    auto now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO policy_store.policy_fragments "
        "(id, name, description, yaml_source, check_instruction, check_compliance, "
        " check_parameters, fix_instruction, fix_parameters, post_check_instruction, "
        " post_check_compliance, post_check_parameters, created_at, updated_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id",
        std::vector<std::string>{id, name, description, yaml_source, check_instruction,
                                 check_compliance, check_params_json.dump(), fix_instruction,
                                 fix_params_json.dump(), post_instruction, post_compliance,
                                 post_params_json.dump(), std::to_string(now),
                                 std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("PolicyStore: insert failed in create_fragment: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to create fragment");
    }

    spdlog::info("PolicyStore: created fragment '{}' ({})", name, id);
    return id;
}

std::expected<std::vector<PolicyFragment>, PolicyReadError>
PolicyStore::query_fragments(const FragmentQuery& q) const {
    if (!open_) {
        spdlog::warn("PolicyStore::query_fragments: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::query_fragments: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::string sql = std::string("SELECT ") + kFragmentCols +
                      " FROM policy_store.policy_fragments WHERE 1=1";
    std::vector<std::string> binds;
    if (!q.name_filter.empty()) {
        binds.push_back("%" + q.name_filter + "%");
        sql += " AND name LIKE $" + std::to_string(binds.size());
    }
    sql += " ORDER BY name ASC LIMIT $" + std::to_string(binds.size() + 1);
    binds.push_back(std::to_string(q.limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::query_fragments: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::vector<PolicyFragment> results;
    results.reserve(static_cast<size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i)
        results.push_back(read_fragment(res.get(), i));
    return results;
}

std::expected<std::optional<PolicyFragment>, PolicyReadError>
PolicyStore::get_fragment(const std::string& id) const {
    if (!open_) {
        spdlog::warn("PolicyStore::get_fragment: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::get_fragment: no connection in time ({})", pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::string sql =
        std::string("SELECT ") + kFragmentCols + " FROM policy_store.policy_fragments WHERE id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::get_fragment: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<PolicyFragment>{std::nullopt};
    return std::optional<PolicyFragment>{read_fragment(res.get(), 0)};
}

bool PolicyStore::delete_fragment(const std::string& id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return false;

    pg::PgResult referenced = pg::exec_params(
        lease.get(), "SELECT EXISTS(SELECT 1 FROM policy_store.policies WHERE fragment_id = $1)",
        std::vector<std::string>{id});
    if (referenced.status() != PGRES_TUPLES_OK)
        return false;
    if (to_bool(PQgetvalue(referenced.get(), 0, 0))) {
        spdlog::warn("PolicyStore: cannot delete fragment {} — referenced by policies", id);
        return false;
    }

    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM policy_store.policy_fragments WHERE id = $1 RETURNING id",
        std::vector<std::string>{id});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

// ── Policy CRUD ──────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
PolicyStore::create_policy(const std::string& yaml_source) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (yaml_source.empty())
        return std::unexpected("yaml_source is required");
    if (yaml_source.size() > 1048576)
        return std::unexpected("YAML too large (max 1MB)");

    auto kind = extract_yaml_value(yaml_source, "kind");
    if (kind != "Policy")
        return std::unexpected(kind_mismatch_error(
            "Policy", kind,
            "  apiVersion: yuzu.io/v1alpha1\n"
            "  kind: Policy\n"
            "  metadata:\n"
            "    name: my-policy\n"
            "  spec:\n"
            "    fragment: <fragment-name-or-id>\n"
            "    scope: <scope-expression>\n"
            "    triggers:\n"
            "      - type: interval\n"
            "        interval_seconds: 3600\n",
            "docs/user-manual/policy-engine.md"));

    auto id_val = extract_yaml_value(yaml_source, "id");
    auto id = id_val.empty() ? generate_id() : id_val;
    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        name = id;
    auto description = extract_yaml_value(yaml_source, "description");

    auto fragment_id = extract_yaml_value(yaml_source, "fragment");
    if (fragment_id.empty())
        return std::unexpected("spec.fragment is required");

    auto scope = extract_yaml_value(yaml_source, "scope");
    if (!scope.empty() && scope.front() == '{')
        return std::unexpected(
            "inline flow-mapping scope is not supported; use the block form "
            "(scope: <newline> indented selector:/fromResultSet:)");
    if (scope.find("from_result_set:") != std::string::npos)
        return std::unexpected(
            "spec.scope.fromResultSet is not yet supported for policies (follow-up "
            "PR-E2): a result set's 1h TTL does not match a continuously-evaluated "
            "policy. Use a selector or a scope expression.");
    if (scope.empty()) {
        auto sb = parse_scope_block(yaml_source);
        if (sb.has_from_result_set)
            return std::unexpected(
                "spec.scope.fromResultSet is not yet supported for policies (follow-up "
                "PR-E2): a result set's 1h TTL does not match a continuously-evaluated "
                "policy. Use a selector or a scope expression.");
        auto asn = extract_yaml_section(yaml_source, "spec.assignment");
        if (auto err = validate_scope_block(sb, extract_yaml_value(asn, "mode"),
                                            !extract_yaml_list(asn, "managementGroups").empty()))
            return std::unexpected(*err);
        scope = lower_scope_block(sb);
    }

    auto inputs_map = extract_yaml_mapping(yaml_source, "inputs");
    std::vector<PolicyInput> inputs;
    for (const auto& [k, v] : inputs_map) {
        PolicyInput inp;
        inp.policy_id = id;
        inp.key = k;
        inp.value = v;
        inputs.push_back(std::move(inp));
    }

    std::vector<PolicyTrigger> triggers;
    auto triggers_section = extract_yaml_section(yaml_source, "triggers");
    if (!triggers_section.empty()) {
        std::vector<size_t> dash_positions;
        {
            auto first_dash = triggers_section.find('-');
            if (first_dash != std::string::npos) {
                auto line_start = triggers_section.rfind('\n', first_dash);
                size_t dash_indent =
                    (line_start == std::string::npos) ? first_dash : first_dash - line_start - 1;
                size_t scan = 0;
                while (scan < triggers_section.size()) {
                    auto nl = triggers_section.find('\n', scan);
                    if (nl == std::string::npos)
                        nl = triggers_section.size();
                    auto line = triggers_section.substr(scan, nl - scan);
                    auto fc = line.find_first_not_of(" \t");
                    if (fc != std::string::npos && line[fc] == '-' && fc == dash_indent)
                        dash_positions.push_back(scan + fc);
                    scan = nl + 1;
                }
            }
        }
        for (size_t di = 0; di < dash_positions.size(); ++di) {
            auto dash = dash_positions[di];
            size_t item_end =
                (di + 1 < dash_positions.size()) ? dash_positions[di + 1] : triggers_section.size();
            auto item_block = triggers_section.substr(dash + 2, item_end - dash - 2);

            PolicyTrigger t;
            t.policy_id = id;
            t.trigger_type = extract_yaml_value(item_block, "type");

            nlohmann::json config;
            auto interval = extract_yaml_value(item_block, "interval_seconds");
            if (!interval.empty()) {
                try {
                    config["interval_seconds"] = std::stoi(interval);
                } catch (...) {
                    config["interval_seconds"] = interval;
                }
            }
            auto path = extract_yaml_value(item_block, "path");
            if (!path.empty())
                config["path"] = path;
            auto event_source = extract_yaml_value(item_block, "event_source");
            if (!event_source.empty())
                config["event_source"] = event_source;
            auto event_id = extract_yaml_value(item_block, "event_id");
            if (!event_id.empty())
                config["event_id"] = event_id;
            auto expression = extract_yaml_value(item_block, "expression");
            if (!expression.empty())
                config["expression"] = expression;

            t.config_json = config.dump();
            if (!t.trigger_type.empty())
                triggers.push_back(std::move(t));
        }
    }

    auto groups = extract_yaml_list(yaml_source, "managementGroups");
    auto now = now_epoch();

    // Whole write is one transaction (improvement over the SQLite original's
    // four independent autocommit statements — a mid-way failure here rolls
    // back cleanly instead of leaving a policy row with partial/missing
    // inputs/triggers/groups).
    std::string failure;
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult exists = pg::exec_params(
            conn, "SELECT EXISTS(SELECT 1 FROM policy_store.policy_fragments WHERE id = $1)",
            std::vector<std::string>{fragment_id});
        if (exists.status() != PGRES_TUPLES_OK) {
            failure = std::string(kPolicyDbErrorPrefix) + "fragment-exists check failed";
            return false;
        }
        if (!to_bool(PQgetvalue(exists.get(), 0, 0))) {
            failure = "fragment '" + fragment_id + "' not found";
            return false;
        }

        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO policy_store.policies "
            "(id, name, description, yaml_source, fragment_id, scope_expression, enabled, "
            " created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$8) RETURNING id",
            std::vector<std::string>{id, name, description, yaml_source, fragment_id, scope,
                                     std::to_string(now), std::to_string(now)});
        if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0) {
            spdlog::error("PolicyStore: insert failed in create_policy: {}", PQerrorMessage(conn));
            failure = std::string(kPolicyDbErrorPrefix) + "failed to create policy";
            return false;
        }

        for (const auto& inp : inputs) {
            pg::PgResult r = pg::exec_params(
                conn, "INSERT INTO policy_store.policy_inputs (policy_id, key, value) VALUES ($1,$2,$3)",
                std::vector<std::string>{id, inp.key, inp.value});
            if (r.status() != PGRES_COMMAND_OK) {
                failure = std::string(kPolicyDbErrorPrefix) + "failed to store policy input";
                return false;
            }
        }
        for (const auto& t : triggers) {
            pg::PgResult r = pg::exec_params(
                conn,
                "INSERT INTO policy_store.policy_triggers (policy_id, trigger_type, config_json) "
                "VALUES ($1,$2,$3)",
                std::vector<std::string>{id, t.trigger_type, t.config_json});
            if (r.status() != PGRES_COMMAND_OK) {
                failure = std::string(kPolicyDbErrorPrefix) + "failed to store policy trigger";
                return false;
            }
        }
        for (const auto& gid : groups) {
            pg::PgResult r = pg::exec_params(
                conn, "INSERT INTO policy_store.policy_groups (policy_id, group_id) VALUES ($1,$2)",
                std::vector<std::string>{id, gid});
            if (r.status() != PGRES_COMMAND_OK) {
                failure = std::string(kPolicyDbErrorPrefix) + "failed to store policy group";
                return false;
            }
        }
        return true;
    });

    if (!ok)
        return std::unexpected(failure.empty() ? std::string(kPolicyDbErrorPrefix) +
                                                      "failed to create policy"
                                                : failure);

    spdlog::info("PolicyStore: created policy '{}' ({}) -> fragment '{}'", name, id, fragment_id);
    return id;
}

std::expected<std::vector<Policy>, PolicyReadError>
PolicyStore::query_policies(const PolicyQuery& q) const {
    if (!open_) {
        spdlog::warn("PolicyStore::query_policies: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::query_policies: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::string sql = std::string("SELECT ") + kPolicyCols + " FROM policy_store.policies WHERE 1=1";
    std::vector<std::string> binds;
    if (!q.name_filter.empty()) {
        binds.push_back("%" + q.name_filter + "%");
        sql += " AND name LIKE $" + std::to_string(binds.size());
    }
    if (!q.fragment_filter.empty()) {
        binds.push_back(q.fragment_filter);
        sql += " AND fragment_id = $" + std::to_string(binds.size());
    }
    if (q.enabled_only)
        sql += " AND enabled = TRUE";
    sql += " ORDER BY name ASC LIMIT $" + std::to_string(binds.size() + 1);
    binds.push_back(std::to_string(q.limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::query_policies: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::vector<Policy> results;
    results.reserve(static_cast<size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        Policy p = read_policy_row(res.get(), i);
        if (!load_policy_details(lease.get(), p)) {
            spdlog::warn("PolicyStore::query_policies: detail load failed for policy {}", p.id);
            return std::unexpected(PolicyReadError::kDegraded);
        }
        results.push_back(std::move(p));
    }
    return results;
}

std::expected<std::optional<Policy>, PolicyReadError>
PolicyStore::get_policy(const std::string& id) const {
    if (!open_) {
        spdlog::warn("PolicyStore::get_policy: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::get_policy: no connection in time ({})", pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }
    return read_policy_by_id(lease.get(), id);
}

std::expected<void, std::string> PolicyStore::enable_policy(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policies SET enabled = TRUE, updated_at = $1 WHERE id = $2 "
        "RETURNING id",
        std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: update failed in enable_policy: {}", PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to enable policy");
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("policy not found");
    spdlog::info("PolicyStore: enabled policy {}", id);
    return {};
}

std::expected<void, std::string> PolicyStore::disable_policy(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policies SET enabled = FALSE, updated_at = $1 WHERE id = $2 "
        "RETURNING id",
        std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: update failed in disable_policy: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to disable policy");
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("policy not found");
    spdlog::info("PolicyStore: disabled policy {}", id);
    return {};
}

bool PolicyStore::delete_policy(const std::string& id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return false;

    // CASCADE now handles policy_inputs/policy_triggers/policy_groups/
    // policy_status/policy_dispatch_state — no manual second DELETE (the
    // SQLite original's hand-written policy_status cleanup, whose
    // prepare/step failure was silently swallowed, is gone).
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM policy_store.policies WHERE id = $1 RETURNING id",
        std::vector<std::string>{id});
    const bool deleted = res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
    if (deleted)
        // The CASCADE above removes this policy's policy_status rows too —
        // the fleet-compliance aggregate must not keep counting them for up
        // to 60s (adversarial review, 2026-08-24: the other three
        // policy_status writers were fixed for this, this one was missed).
        invalidate_fleet_compliance_cache();
    return deleted;
}

// ── Compliance tracking ──────────────────────────────────────────────────────

std::expected<bool, std::string>
PolicyStore::update_agent_status(const std::string& policy_id, const std::string& agent_id,
                                 const std::string& status, const std::string& check_result,
                                 std::optional<int64_t> expected_gen) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (policy_id.empty() || agent_id.empty())
        return std::unexpected("policy_id and agent_id are required");
    if (status != "compliant" && status != "non_compliant" && status != "unknown" &&
        status != "fixing" && status != "error")
        return std::unexpected("invalid status: " + status);

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string kMax = std::to_string(kMaxFixAttempts);
    // ADR-0056: the retry-cap check folds into the write itself (closing a
    // TOCTOU the SQLite original only avoided by accident, via a process-wide
    // mutex that no longer serializes calls arriving from different replicas).
    // `fix_attempt_count` on the RHS of each CASE is the row's value as of THIS
    // write's lock acquisition — concurrent writes on the same key serialize,
    // so the second sees the first's already-committed count.
    //
    // last_check_at / last_fix_at are authored from POSTGRES NOW() (review B2),
    // never a replica clock: the stranded-fixing sweep compares last_fix_at
    // against its own pg-NOW() cutoff, so a lagging replica can no longer
    // author a last_fix_at the sweep misreads as already-stale and un-fix a
    // live claim. NOW() is constant within one statement, so every EXTRACT
    // here is the same instant. last_fix_at on a 'fixing' write is that instant
    // (not 0), so a first-ever 'fixing' write for a never-checked pair is not
    // immediately swept as ancient before its FixWait grace runs.
    //
    // Two shapes, chosen by `expected_gen` (review B3):
    //  - FENCED (expected_gen set): a plain UPDATE guarded by
    //    remediation_claim_gen = $5. A stale claim-holder whose row a sibling
    //    reclaimed (bumping the gen) matches ZERO rows → benign no-op (returns
    //    false, counted by the caller), never a stomp. It must be an UPDATE,
    //    NOT the UPSERT — the UPSERT's INSERT branch is unconditional, so a
    //    fenced call against a vanished row would silently create a gen-0 row
    //    that bypasses the fence entirely.
    //  - UNFENCED (expected_gen unset): the ordinary detection write, which may
    //    be the FIRST-ever write for a pair, so it stays the UPSERT.
    std::string sql;
    if (expected_gen) {
        sql = "UPDATE policy_store.policy_status SET "
              "  status = CASE WHEN $3 = 'fixing' AND fix_attempt_count >= " + kMax +
              "                  THEN 'error' ELSE $3 END, "
              "  last_check_at = EXTRACT(EPOCH FROM NOW())::bigint, "
              "  check_result = $4, "
              "  last_fix_at = CASE WHEN $3 = 'fixing' AND fix_attempt_count < " + kMax +
              "                       THEN EXTRACT(EPOCH FROM NOW())::bigint ELSE last_fix_at END, "
              "  fix_attempt_count = CASE "
              "    WHEN $3 = 'fixing' AND fix_attempt_count < " + kMax +
              "      THEN fix_attempt_count + 1 "
              "    WHEN $3 = 'compliant' THEN 0 "
              "    ELSE fix_attempt_count END "
              "WHERE policy_id = $1 AND agent_id = $2 AND remediation_claim_gen = $5::bigint "
              "RETURNING policy_id";
    } else {
        sql = "INSERT INTO policy_store.policy_status "
              "(policy_id, agent_id, status, last_check_at, last_fix_at, check_result, "
              " fix_attempt_count) "
              "VALUES ($1,$2,$3,EXTRACT(EPOCH FROM NOW())::bigint,"
              "CASE WHEN $3 = 'fixing' THEN EXTRACT(EPOCH FROM NOW())::bigint ELSE 0::bigint END,"
              "$4,0) "
              "ON CONFLICT (policy_id, agent_id) DO UPDATE SET "
              "  status = CASE WHEN EXCLUDED.status = 'fixing' "
              "                  AND policy_status.fix_attempt_count >= " + kMax +
              " THEN 'error' ELSE EXCLUDED.status END, "
              "  last_check_at = EXCLUDED.last_check_at, "
              "  check_result = EXCLUDED.check_result, "
              "  last_fix_at = CASE WHEN EXCLUDED.status = 'fixing' "
              "                       AND policy_status.fix_attempt_count < " + kMax +
              " THEN EXCLUDED.last_check_at ELSE policy_status.last_fix_at END, "
              "  fix_attempt_count = CASE "
              "    WHEN EXCLUDED.status = 'fixing' AND policy_status.fix_attempt_count < " + kMax +
              "      THEN policy_status.fix_attempt_count + 1 "
              "    WHEN EXCLUDED.status = 'compliant' THEN 0 "
              "    ELSE policy_status.fix_attempt_count END "
              "RETURNING policy_id";
    }
    std::vector<std::string> params{policy_id, agent_id, status, sanitize_pg_text(check_result)};
    if (expected_gen)
        params.push_back(std::to_string(*expected_gen));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: write failed in update_agent_status: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "failed to update compliance status");
    }
    const bool wrote = PQntuples(res.get()) > 0;
    if (expected_gen && !wrote) {
        // Benign fenced no-op: the caller's claim generation no longer owns
        // this row (a sibling reclaimed it, or it was released). Never an
        // error; the caller counts it so a MIS-THREADED gen (which would make
        // every remediation write silently vanish) is visible.
        spdlog::warn("PolicyStore: fenced status write for {}/{} (gen {}) matched no row — "
                     "the claim was reclaimed or released; skipped",
                     policy_id, agent_id, *expected_gen);
        return false;
    }
    if (!wrote) {
        // Unfenced UPSERT must always write a row.
        spdlog::error("PolicyStore: upsert wrote no row in update_agent_status: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "failed to update compliance status");
    }
    invalidate_fleet_compliance_cache();
    return true;
}

std::expected<std::optional<PolicyAgentStatus>, PolicyReadError>
PolicyStore::get_agent_status(const std::string& policy_id, const std::string& agent_id) const {
    if (!open_) {
        spdlog::warn("PolicyStore::get_agent_status: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::get_agent_status: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::string sql = std::string("SELECT ") + kAgentStatusCols +
                      " FROM policy_store.policy_status WHERE policy_id = $1 AND agent_id = $2";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{policy_id, agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::get_agent_status: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<PolicyAgentStatus>{std::nullopt};
    return std::optional<PolicyAgentStatus>{read_agent_status(res.get(), 0)};
}

std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
PolicyStore::get_policy_agent_statuses(const std::string& policy_id) const {
    if (!open_) {
        spdlog::warn("PolicyStore::get_policy_agent_statuses: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::get_policy_agent_statuses: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::string sql = std::string("SELECT ") + kAgentStatusCols +
                      " FROM policy_store.policy_status WHERE policy_id = $1 ORDER BY agent_id";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{policy_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::get_policy_agent_statuses: query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }

    std::vector<PolicyAgentStatus> results;
    results.reserve(static_cast<size_t>(PQntuples(res.get())));
    for (int i = 0; i < PQntuples(res.get()); ++i)
        results.push_back(read_agent_status(res.get(), i));
    return results;
}

std::expected<ComplianceSummary, PolicyReadError>
PolicyStore::get_compliance_summary(const std::string& policy_id) const {
    ComplianceSummary cs;
    cs.policy_id = policy_id;
    if (!open_) {
        spdlog::warn("PolicyStore::get_compliance_summary: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::get_compliance_summary: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT status, COUNT(*) FROM policy_store.policy_status WHERE policy_id = $1 "
        "GROUP BY status",
        std::vector<std::string>{policy_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::get_compliance_summary: query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }

    for (int i = 0; i < PQntuples(res.get()); ++i) {
        auto status = text_col(res.get(), i, 0);
        auto count = to_i64(PQgetvalue(res.get(), i, 1));
        if (status == "compliant")
            cs.compliant = count;
        else if (status == "non_compliant")
            cs.non_compliant = count;
        else if (status == "unknown")
            cs.unknown = count;
        else if (status == "fixing")
            cs.fixing = count;
        else if (status == "error")
            cs.error = count;
        cs.total += count;
    }
    return cs;
}

std::expected<FleetCompliance, PolicyReadError> PolicyStore::compute_fleet_compliance() const {
    FleetCompliance fc;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("PolicyStore::compute_fleet_compliance: no connection in time ({})",
                     pool_.last_error());
        return std::unexpected(PolicyReadError::kDegraded);
    }

    auto cutoff = now_epoch() - kStalenessTtl;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT CASE WHEN last_check_at >= $1 THEN status ELSE 'unknown' END AS effective_status, "
        "COUNT(*) FROM policy_store.policy_status GROUP BY effective_status",
        std::vector<std::string>{std::to_string(cutoff)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("PolicyStore::compute_fleet_compliance: query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::unexpected(PolicyReadError::kDegraded);
    }

    for (int i = 0; i < PQntuples(res.get()); ++i) {
        auto status = text_col(res.get(), i, 0);
        auto count = to_i64(PQgetvalue(res.get(), i, 1));
        if (status == "compliant")
            fc.compliant = count;
        else if (status == "non_compliant")
            fc.non_compliant = count;
        else if (status == "unknown")
            fc.unknown = count;
        else if (status == "fixing")
            fc.fixing = count;
        else if (status == "error")
            fc.error = count;
        fc.total_checks += count;
    }
    if (fc.total_checks > 0)
        fc.compliance_pct =
            static_cast<double>(fc.compliant) / static_cast<double>(fc.total_checks) * 100.0;
    return fc;
}

std::expected<FleetCompliance, PolicyReadError> PolicyStore::get_fleet_compliance() const {
    if (!open_) {
        spdlog::warn("PolicyStore::get_fleet_compliance: store not open");
        return std::unexpected(PolicyReadError::kDegraded);
    }

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(cache_mtx_);
        if (fleet_compliance_last_computed_.time_since_epoch().count() > 0 &&
            (now - fleet_compliance_last_computed_) < kFleetComplianceCacheTtl)
            return cached_fleet_compliance_;
    }

    // Recompute OUTSIDE the cache lock — the pool provides real concurrency
    // now (unlike the single SQLite connection this cache pattern originally
    // serialized), so blocking every cache reader behind one mutex for the
    // duration of a query would waste that. A burst of concurrent callers
    // right after expiry may each fire one redundant query; harmless (all
    // converge on the same answer) and self-limiting (the first to finish
    // repopulates the cache for the rest).
    auto fc = compute_fleet_compliance();
    if (!fc)
        return std::unexpected(fc.error());

    {
        std::lock_guard<std::mutex> lock(cache_mtx_);
        cached_fleet_compliance_ = *fc;
        fleet_compliance_last_computed_ = std::chrono::steady_clock::now();
    }
    return *fc;
}

void PolicyStore::invalidate_fleet_compliance_cache() const {
    std::lock_guard<std::mutex> lock(cache_mtx_);
    fleet_compliance_last_computed_ = {};
}

// ── Cache invalidation ───────────────────────────────────────────────────────

std::expected<int64_t, std::string> PolicyStore::invalidate_policy(const std::string& policy_id) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (policy_id.empty())
        return std::unexpected("policy_id is required");

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policy_status SET status = 'unknown', fix_attempt_count = 0 "
        "WHERE policy_id = $1 RETURNING policy_id",
        std::vector<std::string>{policy_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: update failed in invalidate_policy: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to invalidate policy");
    }
    auto changes = static_cast<int64_t>(PQntuples(res.get()));
    spdlog::info("PolicyStore: invalidated {} agent statuses for policy '{}'", changes, policy_id);
    invalidate_fleet_compliance_cache();
    return changes;
}

std::expected<int64_t, std::string> PolicyStore::invalidate_all_policies() {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policy_status SET status = 'unknown', fix_attempt_count = 0 "
        "RETURNING policy_id",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: update failed in invalidate_all_policies: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to invalidate policies");
    }
    auto changes = static_cast<int64_t>(PQntuples(res.get()));
    spdlog::info("PolicyStore: invalidated ALL agent statuses ({} rows)", changes);
    invalidate_fleet_compliance_cache();
    return changes;
}

// ── Multi-replica dispatch claim (ADR-0056) ──────────────────────────────────

std::expected<std::vector<Policy>, std::string>
PolicyStore::claim_due_policies(int64_t now, int64_t default_interval_seconds,
                                int64_t fixing_stale_seconds) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");

    std::vector<Policy> claimed;
    std::string failure;
    bool degraded = false;

    const bool ok = pool_.with_txn_for(kClaimTimeout, [&](PGconn* conn) -> bool {
        // Single-sweeper: exactly one replica claims per tick fleet-wide.
        pg::PgResult lk = pg::exec_params(
            conn, "SELECT pg_try_advisory_xact_lock(hashtextextended('policy_store:dispatch', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            failure = std::string("dispatch lock probe failed: ") + PQerrorMessage(conn);
            degraded = true;
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0)))
            return true; // another replica is claiming this tick — normal skip, not a failure

        // Stranded-`fixing` staleness sweep (supersedes the old evaluator-
        // constructor reset — runs every winning tick, gated by age rather
        // than "every process restart", so it never stomps another
        // replica's live remediation). NOT a #2360 clock-guarded-retention
        // pass: it UPDATEs (never deletes — no data loss on a false
        // positive), the affected state (`status`) is re-derived by the
        // very next real check, and a wrongly-swept row just costs one
        // extra dispatch cycle — none of the irrecoverable-on-clock-skew
        // stakes that rule exists for.
        // HA WS-3 3.4: also frees a stranded remediation claim in the SAME
        // UPDATE — this is the graceful-shutdown drop path's release (the
        // dispatching replica died before collect_ready() could mature the
        // FixWait and release it itself, policy_evaluator.cpp's grace-window
        // comment). AGE is the correct fence for the sweep (review B3 Q2): it
        // has no claim owner to compare against, so it must NOT gen-fence, and
        // it must NOT touch remediation_claim_gen (a later claim mints afresh).
        //
        // But the age signal MUST include remediation_claim_at, not last_fix_at
        // alone (adversarial review C3/K1, Codex+Kimi both independently): a
        // RECLAIM (claim_remediation's ON CONFLICT) refreshes remediation_claim_at
        // and _gen but deliberately does NOT touch last_fix_at or status, and
        // only the reclaimer's LATER mark-fixing write refreshes last_fix_at.
        // So between a sibling's reclaim and its mark-fixing, the row carries a
        // FRESH claim_at but the dead ex-holder's OLD last_fix_at + status
        // 'fixing' — and a last_fix_at-only sweep would zero that live claim,
        // freeing the row for a third claimant and producing a duplicate
        // dispatch by two un-paused holders, OUTSIDE the effectively-once
        // residual (which is bounded to a >stale-window-PAUSED holder). Gating
        // on remediation_claim_at freshness — the real ownership signal, and
        // the SAME `(=0 OR <= NOW()-stale)` shape claim_remediation's own
        // reclaim guard uses — excludes a fresh reclaim while still sweeping a
        // genuinely stranded row (claim_at stale) and a released-but-dangling
        // one (claim_at 0). Both cutoffs are authored from POSTGRES NOW()
        // (review B2), one clock. Still UPDATE-only (a wrongly-swept row costs
        // one extra dispatch cycle), never a #2360 clock-guarded delete.
        pg::PgResult sweep = pg::exec_params(
            conn,
            "UPDATE policy_store.policy_status SET status = 'unknown', remediation_claim_at = 0 "
            "WHERE status = 'fixing' "
            "  AND last_fix_at < EXTRACT(EPOCH FROM NOW())::bigint - $1::bigint "
            "  AND (remediation_claim_at = 0 "
            "       OR remediation_claim_at <= EXTRACT(EPOCH FROM NOW())::bigint - $1::bigint)",
            std::vector<std::string>{std::to_string(fixing_stale_seconds)});
        if (sweep.status() != PGRES_COMMAND_OK) {
            failure = std::string("stranded-fixing sweep failed: ") + PQerrorMessage(conn);
            degraded = true;
            return false;
        }

        // Every enabled policy's (at most one) interval trigger — a LEFT JOIN
        // filtered to trigger_type='interval' in the ON clause, so a policy
        // with no interval trigger still produces exactly one row (NULL
        // config, defaults to default_interval_seconds).
        pg::PgResult due = pg::exec_params(
            conn,
            "SELECT p.id, t.config_json FROM policy_store.policies p "
            "LEFT JOIN policy_store.policy_triggers t "
            "  ON t.policy_id = p.id AND t.trigger_type = 'interval' "
            "WHERE p.enabled = TRUE "
            "ORDER BY p.id, t.id", // deterministic first-by-insertion tie-break below
            std::vector<std::string>{});
        if (due.status() != PGRES_TUPLES_OK) {
            failure = std::string("due-policy read failed: ") + PQerrorMessage(conn);
            degraded = true;
            return false;
        }

        std::unordered_map<std::string, int64_t> interval_by_policy;
        for (int i = 0; i < PQntuples(due.get()); ++i) {
            const std::string pid = text_col(due.get(), i, 0);
            if (interval_by_policy.count(pid))
                continue; // a policy can carry >1 interval trigger — keep the first seen
            interval_by_policy[pid] =
                interval_from_config_json(text_col(due.get(), i, 1), default_interval_seconds);
        }

        std::vector<std::string> due_ids;
        for (const auto& [pid, interval] : interval_by_policy) {
            // Floor at 60s (gov sec-LOW, ported from the evaluator): an
            // operator-supplied interval of 0/negative must not re-dispatch
            // to the whole fleet every tick.
            const int64_t clamped = std::max<int64_t>(interval, 60);
            // DELIBERATELY on the replica `now` clock, NOT pg-NOW() (review B2):
            // this is the check-CADENCE throttle, not the remediation-claim
            // staleness guard. A skewed replica here only shifts WHEN a policy's
            // next check fires by up to one interval — non-destructive, self-
            // correcting on the next tick, never a double-DISPATCH of a
            // non-idempotent fix. The remediation claim + the stranded-fixing
            // sweep, which DO arbitrate a destructive double-dispatch, author
            // from pg-NOW() precisely because a skew there is a safety bug.
            pg::PgResult claim = pg::exec_params(
                conn,
                "INSERT INTO policy_store.policy_dispatch_state (policy_id, last_dispatched_at) "
                "VALUES ($1,$2) "
                "ON CONFLICT (policy_id) DO UPDATE SET last_dispatched_at = EXCLUDED.last_dispatched_at "
                "WHERE policy_store.policy_dispatch_state.last_dispatched_at <= $3 "
                "RETURNING policy_id",
                std::vector<std::string>{pid, std::to_string(now), std::to_string(now - clamped)});
            if (claim.status() != PGRES_TUPLES_OK) {
                failure = "dispatch claim failed for policy " + pid + ": " + PQerrorMessage(conn);
                degraded = true;
                return false;
            }
            if (PQntuples(claim.get()) > 0)
                due_ids.push_back(pid);
        }

        for (const auto& pid : due_ids) {
            auto p = read_policy_by_id(conn, pid);
            if (!p) {
                failure = "degraded read for claimed policy " + pid;
                degraded = true;
                return false;
            }
            if (!*p) {
                // Not reachable today (pid was just read in the due-policy
                // query above and the claim UPSERT above has an FK to it,
                // all in this same transaction) — classified separately
                // from a genuine DB error for accurate logging if that
                // invariant is ever weakened by a future refactor.
                failure = "claimed policy " + pid + " vanished mid-transaction";
                degraded = true;
                return false;
            }
            claimed.push_back(std::move(**p));
        }
        return true;
    });

    if (!ok) {
        if (degraded)
            return std::unexpected(std::string(kPolicyDbErrorPrefix) + failure);
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "claim transaction failed");
    }
    return claimed;
}

std::expected<void, std::string> PolicyStore::record_dispatch(const std::string& policy_id,
                                                               int64_t now) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO policy_store.policy_dispatch_state (policy_id, last_dispatched_at) "
        "VALUES ($1,$2) "
        "ON CONFLICT (policy_id) DO UPDATE SET last_dispatched_at = EXCLUDED.last_dispatched_at "
        "RETURNING policy_id",
        std::vector<std::string>{policy_id, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("PolicyStore: record_dispatch failed for policy {}: {}", policy_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "failed to record dispatch");
    }
    return {};
}

// ── Durable per-(policy,agent) remediation claim (HA WS-3 3.4) ──────────────

std::expected<PolicyStore::RemediationClaim, std::string>
PolicyStore::claim_remediation(const std::string& policy_id,
                               const std::vector<std::string>& agent_ids, int64_t stale_seconds) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (policy_id.empty() || agent_ids.empty())
        return RemediationClaim{};

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    // Mint ONE generation token for this whole claim call up front, on the
    // same lease, and bind it as a plain param — explicit and single-valued,
    // rather than a `nextval()` scalar-subquery inside the INSERT (which a
    // CTE-inlining planner could evaluate per output row, handing different
    // rows different gens). The sequence is schema-qualified because the
    // runner's migration-time search_path does not cover runtime statements.
    pg::PgResult genres = pg::exec_params(
        lease.get(), "SELECT nextval('policy_store.remediation_claim_seq')",
        std::vector<std::string>{});
    if (genres.status() != PGRES_TUPLES_OK || PQntuples(genres.get()) != 1 ||
        PQgetisnull(genres.get(), 0, 0)) {
        spdlog::error("PolicyStore: claim_remediation could not mint a generation for policy {}: {}",
                      policy_id, PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "failed to claim remediation targets");
    }
    // nextval() on a bigint sequence is always a valid non-null integer literal
    // in [1, 2^63-1]; the NULL guard above plus this makes the parse total
    // rather than able to throw std::invalid_argument out of the store.
    const int64_t generation = std::stoll(PQgetvalue(genres.get(), 0, 0));

    // UPSERT CAS, not a plain UPDATE: `unnest($2::text[])` seeds the
    // fresh-INSERT branch for an agent with no `policy_status` row yet (an
    // UPDATE-only claim would silently claim nothing for it — see the
    // header doc). ON CONFLICT wins iff the existing row is unclaimed
    // (remediation_claim_at = 0), claimed stale (older than
    // `NOW() - stale_seconds`, authored from POSTGRES NOW() so a replica
    // clock cannot steal a live claim, review B2 — the SAME window
    // claim_due_policies' own stranded-fixing sweep now uses, so the two
    // never disagree about a row), AND the retry cap has not already been
    // hit — mirrors update_agent_status's own kMaxFixAttempts guard so a
    // capped agent cannot be claimed at all, not just refused later at the
    // status write. Both the stored remediation_claim_at and the reclaim
    // cutoff read NOW() within the one statement, so they are the same
    // instant. remediation_claim_gen stamps the winner rows with this call's
    // token (review B3) for the release/status fences. DISTINCT: a caller may
    // pass a duplicate agent id; without it the ON CONFLICT DO UPDATE raises
    // cardinality_violation (21000) and fails the whole claim.
    const std::string sql =
        "INSERT INTO policy_store.policy_status "
        "(policy_id, agent_id, status, last_check_at, last_fix_at, check_result, "
        " fix_attempt_count, remediation_claim_at, remediation_claim_gen) "
        "SELECT DISTINCT $1, x, 'unknown', 0, 0, '', 0, EXTRACT(EPOCH FROM NOW())::bigint, "
        "                $4::bigint "
        "FROM unnest($2::text[]) AS x "
        "ON CONFLICT (policy_id, agent_id) DO UPDATE SET "
        "  remediation_claim_at = EXCLUDED.remediation_claim_at, "
        "  remediation_claim_gen = EXCLUDED.remediation_claim_gen "
        "  WHERE (policy_status.remediation_claim_at = 0 "
        "         OR policy_status.remediation_claim_at <= EXTRACT(EPOCH FROM NOW())::bigint "
        "                                                  - $3::bigint) "
        "    AND policy_status.fix_attempt_count < " +
        std::to_string(kMaxFixAttempts) +
        " "
        "RETURNING agent_id";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{policy_id, pg::to_text_array(as_views(agent_ids)),
                                 std::to_string(stale_seconds), std::to_string(generation)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PolicyStore: claim_remediation failed for policy {}: {}", policy_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "failed to claim remediation targets");
    }
    return RemediationClaim{.ids = returned_ids(res), .generation = generation};
}

std::expected<void, std::string>
PolicyStore::release_remediation_claim(const std::string& policy_id,
                                       const std::vector<std::string>& agent_ids,
                                       int64_t generation) {
    if (!open_)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) + "database not open");
    if (policy_id.empty() || agent_ids.empty())
        return {};

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "database unavailable — try again");

    // No RETURNING check on row count: releasing a claim that was already
    // released (or never taken — e.g. this policy/agent pair had no
    // policy_status row at all) is a benign no-op, not an error. The
    // `remediation_claim_gen = $3` fence (review B3) makes a THIRD case a
    // benign no-op and that is the whole point: a stale holder whose row a
    // sibling reclaimed (bumping the gen) matches zero rows here and so cannot
    // erase the sibling's live claim.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policy_status SET remediation_claim_at = 0 "
        "WHERE policy_id = $1 AND agent_id = ANY($2::text[]) "
        "  AND remediation_claim_gen = $3::bigint",
        std::vector<std::string>{policy_id, pg::to_text_array(as_views(agent_ids)),
                                 std::to_string(generation)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("PolicyStore: release_remediation_claim failed for policy {}: {}", policy_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kPolicyDbErrorPrefix) +
                               "failed to release remediation claim");
    }
    return {};
}

} // namespace yuzu::server
