#include "baseline_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <format>
#include <random>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "baseline_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back the push fan-out / heartbeat
// reconcile catastrophic-read path and the Guardian dashboard; writes come
// from the operator dashboard/REST only (no gRPC hot path touches this
// store). Mirrors GuaranteedStateStore's rule/meta budget (its closest
// Guardian-domain sibling, ADR-0038) rather than its tighter ingest budget —
// this store has no ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

int64_t now_epoch() {
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

std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

// Same treatment as CustomPropertiesStore/RbacStore/TagStore (ADR-0041/0045/0050):
// scrub invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub leaves
// behind — PostgreSQL TEXT can't store NUL and libpq's text-format bind
// C-string-truncates at the first one (pg_exec.hpp binds via `.c_str()`, no
// explicit length). Applied to every free-text value on every write path,
// including read-path id/name lookups (consistency: a lookup must transform
// its argument identically to how the matching row's id was transformed when
// written, or a NUL-bearing id could silently miss the very row it was meant
// to address).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Postgres schema (ADR-0055): the FINAL column set of the legacy SQLite
// store's single migration, collapsed into one v1. Unqualified DDL — the
// migration runner sets search_path to `baseline_store` for the migration
// transaction. Runtime statements below schema-qualify explicitly.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE baselines (
                baseline_id       TEXT PRIMARY KEY,
                name              TEXT NOT NULL UNIQUE,
                description       TEXT NOT NULL DEFAULT '',
                lifecycle         TEXT NOT NULL DEFAULT 'draft',
                -- Members captured at the last deploy (JSON array of rule_ids).
                -- This is the ENFORCED set: deployed_member_rule_ids() reads it,
                -- and the detail renderer diffs it against live members. See
                -- baseline_store.hpp.
                deployed_snapshot TEXT NOT NULL DEFAULT '',
                created_by        TEXT NOT NULL DEFAULT '',
                updated_by        TEXT NOT NULL DEFAULT '',
                deployed_by       TEXT NOT NULL DEFAULT '',
                created_at        BIGINT NOT NULL DEFAULT 0,
                updated_at        BIGINT NOT NULL DEFAULT 0,
                deployed_at       BIGINT NOT NULL DEFAULT 0
            );

            -- Member Guards (M:N). rule_id references a Guard in a DIFFERENT
            -- schema (guaranteed_state_store) so there is no FK on it; a
            -- dangling member is harmless at deploy (the push builder skips
            -- it). The FK to baselines (same schema) gives delete_baseline
            -- its cascade and rejects a member row for a non-existent
            -- baseline.
            CREATE TABLE baseline_rules (
                baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
                rule_id     TEXT NOT NULL,
                PRIMARY KEY (baseline_id, rule_id)
            );

            -- Assignment: included − excluded management groups. group_id also
            -- references a different schema (management_group_store), so no
            -- FK on it. PK on (baseline_id, group_id) makes a group's disposition
            -- unambiguous — it cannot be both included and excluded.
            CREATE TABLE baseline_groups (
                baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
                group_id    TEXT NOT NULL,
                disposition TEXT NOT NULL,   -- 'include' | 'exclude'
                PRIMARY KEY (baseline_id, group_id)
            );

            -- Reverse-lookup indexes: which baselines reference a given guard /
            -- group (deploy slice's affected-set recompute + cross-store cleanup).
            CREATE INDEX idx_baseline_rules_rule ON baseline_rules(rule_id);
            CREATE INDEX idx_baseline_groups_group ON baseline_groups(group_id);
        )"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) — the
        // backfill idempotency marker it was the sole purpose of no longer has a
        // writer. Version-bumped (not edited into v1) because v1 has actually run
        // against real dev/UAT databases — see ADR-0055's Update.
        {2, "DROP TABLE IF EXISTS baseline_store_meta;"},
    };
    return kMigrations;
}

constexpr const char* kBaselineCols =
    "baseline_id, name, description, lifecycle, deployed_snapshot, created_by, updated_by, "
    "deployed_by, created_at, updated_at, deployed_at";

Baseline read_baseline_row(PGresult* res, int i) {
    Baseline b;
    int c = 0;
    b.baseline_id = text_col(res, i, c++);
    b.name = text_col(res, i, c++);
    b.description = text_col(res, i, c++);
    b.lifecycle = text_col(res, i, c++);
    b.deployed_snapshot = text_col(res, i, c++);
    b.created_by = text_col(res, i, c++);
    b.updated_by = text_col(res, i, c++);
    b.deployed_by = text_col(res, i, c++);
    b.created_at = to_i64(PQgetvalue(res, i, c++));
    b.updated_at = to_i64(PQgetvalue(res, i, c++));
    b.deployed_at = to_i64(PQgetvalue(res, i, c++));
    return b;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

BaselineStore::BaselineStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("BaselineStore: no database connection at construction ({}) — Guardian "
                      "Baseline persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("BaselineStore: schema migration failed — Guardian Baseline persistence "
                      "disabled");
        return;
    }
    open_ = true;
    spdlog::info("BaselineStore initialized (schema {})", kStoreName);
}

std::string BaselineStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(12);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 12; ++i)
        id += chars[dist(rng)];
    return id;
}

// ── Baseline CRUD ──────────────────────────────────────────────────────────

std::expected<std::string, std::string> BaselineStore::create_baseline(const Baseline& b) {
    if (!open_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    const std::string id = sanitize_pg_text(b.baseline_id.empty() ? generate_id() : b.baseline_id);
    const int64_t now = now_epoch();
    const std::string lifecycle = b.lifecycle.empty() ? kBaselineDraft : b.lifecycle;
    if (lifecycle != kBaselineDraft && lifecycle != kBaselineDeployed)
        return std::unexpected("invalid lifecycle '" + lifecycle + "': must be '" +
                                std::string(kBaselineDraft) + "' or '" +
                                std::string(kBaselineDeployed) + "'");

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO baseline_store.baselines "
        "(baseline_id, name, description, lifecycle, deployed_snapshot, created_by, updated_by, "
        " deployed_by, created_at, updated_at, deployed_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10::bigint,$11::bigint)",
        std::vector<std::string>{id, sanitize_pg_text(b.name), sanitize_pg_text(b.description),
                                 lifecycle, sanitize_pg_text(b.deployed_snapshot),
                                 sanitize_pg_text(b.created_by), sanitize_pg_text(b.updated_by),
                                 sanitize_pg_text(b.deployed_by), std::to_string(now),
                                 std::to_string(now), std::to_string(b.deployed_at)});
    if (res.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505") {
            const char* constraint_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            const bool name_collision = constraint.find("_name_key") != std::string::npos;
            return std::unexpected(format_conflict(
                name_collision ? ("baseline name '" + b.name + "' already exists")
                                : ("baseline_id '" + id + "' already exists")));
        }
        return std::unexpected("insert failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    return id;
}

std::optional<Baseline> BaselineStore::get_baseline(const std::string& baseline_id,
                                                     bool* store_ok) const {
    // Optimistic, same contract as get_baseline_by_name: only a store FAULT
    // clears this; a genuine not-found leaves it true.
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    const std::string sql =
        std::string("SELECT ") + kBaselineCols + " FROM baseline_store.baselines WHERE baseline_id = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::get_baseline: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_baseline_row(res.get(), 0);
}

std::optional<Baseline> BaselineStore::get_baseline_by_name(const std::string& name,
                                                            bool* store_ok) const {
    // Optimistic: only a store FAULT (not-open / lease-timeout / query-error)
    // clears this; a genuine not-found leaves it true so the caller 404s
    // rather than 503s (UP-13/sre-2).
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    // Names are unique (create_baseline rejects a dup); LIMIT 1 is belt-and-braces.
    const std::string sql = std::string("SELECT ") + kBaselineCols +
                            " FROM baseline_store.baselines WHERE name = $1 LIMIT 1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{sanitize_pg_text(name)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::get_baseline_by_name: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false; // fault, not a miss → caller 503s (retryable)
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_baseline_row(res.get(), 0);
}

std::vector<Baseline> BaselineStore::list_baselines() const {
    std::vector<Baseline> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const std::string sql =
        std::string("SELECT ") + kBaselineCols + " FROM baseline_store.baselines ORDER BY name";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::list_baselines: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(read_baseline_row(res.get(), i));
    return out;
}

std::expected<void, std::string> BaselineStore::update_baseline(const Baseline& b) {
    if (!open_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");
    if (b.lifecycle != kBaselineDraft && b.lifecycle != kBaselineDeployed)
        return std::unexpected("invalid lifecycle '" + b.lifecycle + "': must be '" +
                                std::string(kBaselineDraft) + "' or '" +
                                std::string(kBaselineDeployed) + "'");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();
    const int64_t now = now_epoch();

    // RETURNING (not sqlite3_changes()-style count) so the affected-row test
    // rides in the query result — CLAUDE.md #1033.
    const std::string id = sanitize_pg_text(b.baseline_id);
    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE baseline_store.baselines SET name = $1, description = $2, lifecycle = $3, "
        "deployed_snapshot = $4, updated_by = $5, deployed_by = $6, deployed_at = $7::bigint, "
        "updated_at = $8::bigint WHERE baseline_id = $9 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(b.name), sanitize_pg_text(b.description),
                                 b.lifecycle, sanitize_pg_text(b.deployed_snapshot),
                                 sanitize_pg_text(b.updated_by), sanitize_pg_text(b.deployed_by),
                                 std::to_string(b.deployed_at), std::to_string(now), id});
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505")
            return std::unexpected(format_conflict("baseline name '" + b.name + "' already exists"));
        return std::unexpected("update failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: baseline_id '" + b.baseline_id + "'");
    return {};
}

std::expected<void, std::string> BaselineStore::delete_baseline(const std::string& baseline_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // ON DELETE CASCADE clears the member + assignment rows. RETURNING
    // reports whether the baseline existed without a separate row-count read.
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM baseline_store.baselines WHERE baseline_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(res.get())));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    return {};
}

// ── Member Guards (M:N) ──────────────────────────────────────────────────────

std::expected<void, std::string>
BaselineStore::set_members(const std::string& baseline_id_in,
                           const std::vector<std::string>& rule_ids) {
    if (!open_)
        return std::unexpected("database not open");
    const std::string baseline_id = sanitize_pg_text(baseline_id_in);

    std::string error;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // Touch-and-lock FIRST, in the SAME transaction as the replace: an
        // INSERT enforces the FK against a concurrent delete, but an EMPTY
        // member set inserts nothing, so without this the existence check
        // and the replace were racing as two separate acquisitions — a
        // delete_baseline landing between them let an empty clear() report
        // success against a since-deleted baseline (governance TOCTOU
        // finding, three independent reviewers). The row lock this UPDATE
        // takes is held for the rest of the transaction, so a concurrent
        // delete_baseline either blocks behind it (this txn's 0-row result
        // then correctly reports not-found) or has already committed (0
        // rows here, same result) — no window remains.
        pg::PgResult touch = pg::exec_params(
            c,
            "UPDATE baseline_store.baselines SET updated_at = $1::bigint "
            "WHERE baseline_id = $2 RETURNING baseline_id",
            std::vector<std::string>{std::to_string(now_epoch()), baseline_id});
        if (touch.status() != PGRES_TUPLES_OK) {
            error = "touch updated_at failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        if (PQntuples(touch.get()) == 0) {
            not_found = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM baseline_store.baseline_rules WHERE baseline_id = $1",
            std::vector<std::string>{baseline_id});
        if (del.status() != PGRES_COMMAND_OK) {
            error = "delete failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        // Sanitize BEFORE de-duping: two distinct raw values that sanitize to
        // the same string must collapse to one insert, not a mid-transaction
        // PK violation on the second.
        std::unordered_set<std::string> seen;
        for (const auto& raw_rule_id : rule_ids) {
            const std::string rule_id = sanitize_pg_text(raw_rule_id);
            if (rule_id.empty() || !seen.insert(rule_id).second)
                continue; // skip blanks + de-dup
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_rules (baseline_id, rule_id) VALUES ($1, $2)",
                std::vector<std::string>{baseline_id, rule_id});
            if (ins.status() != PGRES_COMMAND_OK) {
                error = "insert member failed: " + std::string(PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (not_found)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    if (!ok)
        return std::unexpected(error.empty() ? "transaction failed" : error);
    return {};
}

std::vector<std::string> BaselineStore::get_members(const std::string& baseline_id) const {
    return get_members_checked(baseline_id).value_or(std::vector<std::string>{});
}

std::expected<std::vector<std::string>, std::string>
BaselineStore::get_members_checked(const std::string& baseline_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT rule_id FROM baseline_store.baseline_rules WHERE baseline_id = $1 ORDER BY rule_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<std::string> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(text_col(res.get(), i, 0));
    return out;
}

std::vector<std::string>
BaselineStore::baselines_containing_rule(const std::string& rule_id) const {
    std::vector<std::string> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT baseline_id FROM baseline_store.baseline_rules WHERE rule_id = $1 ORDER BY baseline_id",
        std::vector<std::string>{sanitize_pg_text(rule_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(text_col(res.get(), i, 0));
    return out;
}

std::size_t BaselineStore::remove_rule_everywhere(const std::string& rule_id) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM baseline_store.baseline_rules WHERE rule_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(rule_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(PQntuples(res.get()));
}

// ── Assignment (included − excluded management groups) ───────────────────────

std::expected<void, std::string>
BaselineStore::set_assignment(const std::string& baseline_id_in,
                              const std::vector<BaselineGroupAssignment>& groups) {
    if (!open_)
        return std::unexpected("database not open");
    const std::string baseline_id = sanitize_pg_text(baseline_id_in);

    // Validate + collapse duplicates (last disposition wins) BEFORE any write,
    // so an invalid disposition aborts with nothing persisted. Insertion order
    // is irrelevant — the PK is (baseline_id, group_id). Sanitize BEFORE
    // keying the map, same reasoning as set_members: two raw group_ids that
    // sanitize identically must collapse to one map entry, not two INSERTs
    // colliding mid-transaction.
    std::unordered_map<std::string, std::string> resolved;
    for (const auto& g : groups) {
        if (g.group_id.empty())
            continue;
        if (g.disposition != kAssignInclude && g.disposition != kAssignExclude)
            return std::unexpected("invalid disposition '" + g.disposition +
                                   "' (expected 'include' or 'exclude')");
        resolved[sanitize_pg_text(g.group_id)] = g.disposition;
    }

    std::string error;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // Touch-and-lock FIRST, in the SAME transaction as the replace — see
        // the identical comment in set_members for why (governance TOCTOU
        // finding, three independent reviewers): the old separate existence
        // check raced the replace transaction, letting an empty assignment
        // clear() report success against a since-deleted baseline.
        pg::PgResult touch = pg::exec_params(
            c,
            "UPDATE baseline_store.baselines SET updated_at = $1::bigint "
            "WHERE baseline_id = $2 RETURNING baseline_id",
            std::vector<std::string>{std::to_string(now_epoch()), baseline_id});
        if (touch.status() != PGRES_TUPLES_OK) {
            error = "touch updated_at failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        if (PQntuples(touch.get()) == 0) {
            not_found = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM baseline_store.baseline_groups WHERE baseline_id = $1",
            std::vector<std::string>{baseline_id});
        if (del.status() != PGRES_COMMAND_OK) {
            error = "delete failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        for (const auto& [group_id, disposition] : resolved) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_groups (baseline_id, group_id, disposition) "
                "VALUES ($1, $2, $3)",
                std::vector<std::string>{baseline_id, group_id, disposition});
            if (ins.status() != PGRES_COMMAND_OK) {
                error = "insert assignment failed: " + std::string(PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (not_found)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    if (!ok)
        return std::unexpected(error.empty() ? "transaction failed" : error);
    return {};
}

std::vector<BaselineGroupAssignment>
BaselineStore::get_assignment(const std::string& baseline_id) const {
    std::vector<BaselineGroupAssignment> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    // Sort include-before-exclude then by group_id for a stable UI order.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT group_id, disposition FROM baseline_store.baseline_groups WHERE baseline_id = $1 "
        "ORDER BY disposition, group_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        BaselineGroupAssignment a;
        a.group_id = text_col(res.get(), i, 0);
        a.disposition = text_col(res.get(), i, 1);
        out.push_back(std::move(a));
    }
    return out;
}

std::size_t BaselineStore::remove_group_everywhere(const std::string& group_id) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM baseline_store.baseline_groups WHERE group_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(group_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(PQntuples(res.get()));
}

// ── Reverse lookups / counting ───────────────────────────────────────────────

std::vector<Baseline> BaselineStore::list_deployed_baselines() const {
    std::vector<Baseline> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const std::string sql = std::string("SELECT ") + kBaselineCols +
                            " FROM baseline_store.baselines WHERE lifecycle = $1 ORDER BY name";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::list_deployed_baselines: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(read_baseline_row(res.get(), i));
    return out;
}

std::expected<std::unordered_set<std::string>, std::string>
BaselineStore::deployed_member_rule_ids() const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // Read only the snapshot column of every deployed Baseline in one pass
    // (one lease, no per-Baseline round-trip). The snapshot is what was
    // deployed; see the deployed_snapshot field doc + deploy_baseline().
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT baseline_id, deployed_snapshot FROM baseline_store.baselines WHERE lifecycle = $1",
        std::vector<std::string>{kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::unordered_set<std::string> ids;
    const int n = PQntuples(res.get());
    for (int i = 0; i < n; ++i) {
        const std::string row_baseline_id = text_col(res.get(), i, 0);
        const std::string snap = text_col(res.get(), i, 1);
        if (snap.empty())
            continue; // never-deployed / empty snapshot contributes nothing (fail-closed)
        // allow_exceptions=false: a malformed snapshot is skipped, not thrown on.
        const auto parsed = nlohmann::json::parse(snap, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_array()) {
            // Not a corruption this store can repair — deploy_baseline only
            // ever writes an array — but silently zeroing a deployed
            // Baseline's enforced set is a coverage-shrink an operator has
            // no other signal for (governance UP-4 finding); at least log it.
            // baseline_id included (governance Gate-8 compliance-officer
            // finding — an unidentified row ordinal undercuts the log's own
            // diagnostic value on this catastrophic-read chokepoint).
            spdlog::warn("BaselineStore::deployed_member_rule_ids: baseline '{}' deployed_snapshot "
                         "is not a JSON array — contributing 0 rule_ids for this baseline",
                         row_baseline_id);
            continue;
        }
        std::size_t dropped = 0;
        for (const auto& rid : parsed) {
            if (rid.is_string())
                ids.insert(rid.get<std::string>());
            else
                ++dropped;
        }
        if (dropped > 0)
            spdlog::warn("BaselineStore::deployed_member_rule_ids: baseline '{}' deployed_snapshot "
                         "array had {} non-string element(s) — dropped, not enforced",
                         row_baseline_id, dropped);
    }
    return ids;
}

std::expected<std::vector<std::string>, std::string>
BaselineStore::deployed_member_rule_ids(const std::string& baseline_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // The deployed snapshot (the ENFORCED set captured at last deploy) of ONE
    // Baseline — the per-Baseline analog of the fleet-union overload above,
    // for the baseline-anchored per-device REST view. The `lifecycle =
    // deployed` filter mirrors the union overload so the two share ONE
    // definition of "what is deployed": a draft / never-deployed Baseline
    // yields {} (the "deployed:false ⟹ no guards" contract is self-enforcing
    // here, not only via the externally-empty snapshot).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT deployed_snapshot FROM baseline_store.baselines WHERE baseline_id = $1 AND "
        "lifecycle = $2",
        std::vector<std::string>{sanitize_pg_text(baseline_id), kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<std::string> ids;
    if (PQntuples(res.get()) > 0) {
        const std::string snap = text_col(res.get(), 0, 0);
        if (!snap.empty()) {
            // allow_exceptions=false: a malformed snapshot is skipped, not thrown on.
            const auto parsed = nlohmann::json::parse(snap, nullptr, /*allow_exceptions=*/false);
            if (!parsed.is_array()) {
                // See the fleet-wide overload's identical note (governance UP-4).
                spdlog::warn("BaselineStore::deployed_member_rule_ids({}): deployed_snapshot is "
                             "not a JSON array — contributing 0 rule_ids",
                             baseline_id);
            } else {
                std::size_t dropped = 0;
                for (const auto& rid : parsed) {
                    if (rid.is_string())
                        ids.push_back(rid.get<std::string>());
                    else
                        ++dropped;
                }
                if (dropped > 0)
                    spdlog::warn("BaselineStore::deployed_member_rule_ids({}): deployed_snapshot "
                                 "array had {} non-string element(s) — dropped, not enforced",
                                 baseline_id, dropped);
            }
        }
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

std::size_t BaselineStore::baseline_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT COUNT(*) FROM baseline_store.baselines",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t BaselineStore::member_count(const std::string& baseline_id) const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM baseline_store.baseline_rules WHERE baseline_id = $1",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

} // namespace yuzu::server
