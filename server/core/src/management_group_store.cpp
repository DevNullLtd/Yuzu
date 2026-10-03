#include "management_group_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp" // RbacStore::validate_assignment — shared engine-principal assignment guard
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "management_group_store";

// Bounded acquires (ADR-0012 §2(a)). Confinement reads are on the interactive
// REST/dashboard/MCP list-gate path; writes get a slightly wider budget.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// Hierarchy traversal bound (ADR-0042 / ADR-0017 INV-7). A corrupt parent
// cycle must TERMINATE, not spin; the ancestor-ward and descendant-ward walks
// share this cap so admit and visible-set agree on an over-deep/corrupt tree.
// Validated trees never approach it (`create_group` caps hierarchy at 5).
constexpr int kMaxHierarchyDepth = 10;

// Read-degrade reason labels (ADR-0037 convention).
constexpr const char* kReasonStoreClosed = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

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

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL (a
// valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's text-format
// bind C-string-truncates at the first one. So after the UTF-8 scrub, replace
// every NUL with U+FFFD too. Ported verbatim from rbac_store.cpp (ADR-0041) —
// applied to every free-text column, INCLUDING the backfill path (a bad byte
// at-rest in a legacy management-groups.db must not brick the MANDATORY
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

// ── Read-degrade observability (mirrors RbacStore/AuditStore) ────────────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_mgmt_group_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// ── PostgreSQL schema (ADR-0042): the SQLite store's two migrations collapsed
// into one v1. Unqualified DDL — the runner sets search_path to
// `management_group_store`; runtime statements below schema-qualify explicitly.
// created_at/updated_at are BIGINT (were INTEGER epoch in SQLite). The self-
// referential parent_id FK is DEFERRABLE INITIALLY DEFERRED so the MANDATORY
// backfill can bulk-insert groups in arbitrary order within one txn (a child
// before its parent) and the tree integrity is verified at COMMIT.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE management_groups (
                id               TEXT PRIMARY KEY,
                name             TEXT NOT NULL UNIQUE,
                description      TEXT NOT NULL DEFAULT '',
                parent_id        TEXT REFERENCES management_groups(id) ON DELETE CASCADE
                                     DEFERRABLE INITIALLY DEFERRED,
                membership_type  TEXT NOT NULL DEFAULT 'static',
                scope_expression TEXT,
                created_by       TEXT,
                created_at       BIGINT NOT NULL DEFAULT 0,
                updated_at       BIGINT NOT NULL DEFAULT 0
            );

            CREATE TABLE management_group_members (
                group_id  TEXT NOT NULL REFERENCES management_groups(id) ON DELETE CASCADE,
                agent_id  TEXT NOT NULL,
                source    TEXT NOT NULL DEFAULT 'static',
                added_at  BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, agent_id)
            );

            CREATE TABLE management_group_roles (
                group_id       TEXT NOT NULL REFERENCES management_groups(id) ON DELETE CASCADE,
                principal_type TEXT NOT NULL,
                principal_id   TEXT NOT NULL,
                role_name      TEXT NOT NULL,
                PRIMARY KEY (group_id, principal_type, principal_id, role_name)
            );

            CREATE INDEX idx_mgmt_members_agent
                ON management_group_members(agent_id);
            CREATE INDEX idx_mgmt_groups_parent
                ON management_groups(parent_id);
            -- ADR-0017 perf F3: (principal_type, principal_id) lookup on the
            -- per-agent-check hot path via resolve_perm_groups.
            CREATE INDEX idx_mgmt_roles_principal
                ON management_group_roles(principal_type, principal_id);

            -- Durable one-time backfill marker (ADR-0042). Marker-only; the sole
            -- writer (migrate_from_sqlite) was retired (#3623, ADR-0042 Update).
            CREATE TABLE mgmt_group_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // migrate_from_sqlite() retired (#3623, ADR-0042 Update) — mgmt_group_meta was its
        // sole idempotency marker. Appended at the next free slot, never renumbering v1
        // (PgMigrationRunner applies only version > current — renumbering an already-shipped
        // version re-applies it against a database that already ran it).
        {2, "DROP TABLE IF EXISTS mgmt_group_meta;"},
    };
    return kMigrations;
}

ManagementGroup read_group(PGresult* res, int row) {
    ManagementGroup g;
    g.id = text_col(res, row, 0);
    g.name = text_col(res, row, 1);
    g.description = text_col(res, row, 2);
    g.parent_id = text_col(res, row, 3);
    g.membership_type = text_col(res, row, 4);
    g.scope_expression = text_col(res, row, 5);
    g.created_by = text_col(res, row, 6);
    g.created_at = to_i64(PQgetvalue(res, row, 7));
    g.updated_at = to_i64(PQgetvalue(res, row, 8));
    return g;
}

constexpr const char* kGroupCols =
    "id, name, description, parent_id, membership_type, scope_expression, "
    "created_by, created_at, updated_at";

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

ManagementGroupStore::ManagementGroupStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ManagementGroupStore: no database connection at construction ({}) — "
                      "confinement substrate disabled (fail-closed: every confinement read DENIES)",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ManagementGroupStore: schema migration failed — confinement substrate "
                      "disabled (fail-closed)");
        return;
    }
    open_ = true;
    spdlog::info("ManagementGroupStore initialized (schema {})", kStoreName);
}

ManagementGroupStore::~ManagementGroupStore() = default;

std::string ManagementGroupStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(12);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 12; ++i)
        id += chars[dist(rng)];
    return id;
}

void ManagementGroupStore::set_rbac_enabled_probe(std::function<bool()> probe) {
    rbac_enabled_probe_ = std::move(probe);
}

// ── Group CRUD ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
ManagementGroupStore::create_group(const ManagementGroup& group) {
    if (!open_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");

    // Validate no circular parent reference + depth cap.
    if (!group.parent_id.empty()) {
        if (!group.id.empty() && group.parent_id == group.id)
            return std::unexpected("group cannot be its own parent");
        auto parent = get_group(group.parent_id);
        if (!parent)
            return std::unexpected("parent group not found");
        auto ancestors = get_ancestor_ids(group.parent_id);
        if (!ancestors) // confinement/hierarchy read degraded — refuse rather than mis-validate
            return std::unexpected("failed to resolve ancestor chain (store degraded)");
        if (ancestors->size() >= 5)
            return std::unexpected("maximum hierarchy depth (5) exceeded");
    }

    auto id = group.id.empty() ? generate_id() : group.id;
    auto now = now_secs();

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    std::vector<std::optional<std::string>> params{
        sanitize_pg_text(id),
        sanitize_pg_text(group.name),
        sanitize_pg_text(group.description),
        group.parent_id.empty() ? std::nullopt
                                : std::optional<std::string>(sanitize_pg_text(group.parent_id)),
        sanitize_pg_text(group.membership_type),
        group.scope_expression.empty()
            ? std::nullopt
            : std::optional<std::string>(sanitize_pg_text(group.scope_expression)),
        sanitize_pg_text(group.created_by),
        std::to_string(now),
        std::to_string(now)};
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO management_group_store.management_groups "
        "(id, name, description, parent_id, membership_type, scope_expression, "
        "created_by, created_at, updated_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8::bigint, $9::bigint) RETURNING id",
        params);
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::unexpected(std::string("failed to create group: ") +
                               PQerrorMessage(lease.get()));
    return text_col(r.get(), 0, 0);
}

std::optional<ManagementGroup> ManagementGroupStore::get_group(const std::string& id) const {
    return get_group_checked(id).value_or(std::nullopt);
}

std::expected<std::optional<ManagementGroup>, std::string>
ManagementGroupStore::get_group_checked(const std::string& id) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_group_checked: store not open — DEGRADED");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "ManagementGroupStore::get_group_checked: pool acquire timed out — DEGRADED");
        return std::unexpected("pool acquire timed out");
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kGroupCols +
         " FROM management_group_store.management_groups WHERE id = $1")
            .c_str(),
        std::vector<std::string>{id});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_group_checked: query failed: {} — DEGRADED",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    if (PQntuples(r.get()) == 0)
        return std::optional<ManagementGroup>{std::nullopt};
    return std::optional<ManagementGroup>{read_group(r.get(), 0)};
}

std::optional<ManagementGroup>
ManagementGroupStore::find_group_by_name(const std::string& name) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kGroupCols +
         " FROM management_group_store.management_groups WHERE name = $1 LIMIT 1")
            .c_str(),
        std::vector<std::string>{name});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return std::nullopt;
    return read_group(r.get(), 0);
}

std::vector<ManagementGroup> ManagementGroupStore::list_groups() const {
    std::vector<ManagementGroup> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kGroupCols +
         " FROM management_group_store.management_groups ORDER BY name")
            .c_str(),
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_group(r.get(), i));
    return result;
}

std::vector<ManagementGroup>
ManagementGroupStore::get_children(const std::string& parent_id) const {
    std::vector<ManagementGroup> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kGroupCols +
         " FROM management_group_store.management_groups WHERE parent_id = $1 ORDER BY name")
            .c_str(),
        std::vector<std::string>{parent_id});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_group(r.get(), i));
    return result;
}

std::expected<void, std::string> ManagementGroupStore::update_group(const ManagementGroup& group) {
    if (!open_)
        return std::unexpected("database not open");

    // Validate parent_id at the store layer so no direct caller can introduce a
    // cycle (the REST handler has its own checks).
    if (!group.parent_id.empty()) {
        if (group.parent_id == group.id)
            return std::unexpected("group cannot be its own parent");
        auto parent = get_group(group.parent_id);
        if (!parent)
            return std::unexpected("parent group not found");
        auto ancestors = get_ancestor_ids(group.parent_id);
        if (!ancestors)
            return std::unexpected("failed to resolve ancestor chain (store degraded)");
        if (std::find(ancestors->begin(), ancestors->end(), group.id) != ancestors->end())
            return std::unexpected("re-parenting would create a cycle");
        // +1 because `group` itself becomes a new level below `parent`.
        if (ancestors->size() + 1 >= 5)
            return std::unexpected("maximum hierarchy depth (5) exceeded");
    }

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    std::vector<std::optional<std::string>> params{
        sanitize_pg_text(group.name),
        sanitize_pg_text(group.description),
        group.parent_id.empty() ? std::nullopt
                                : std::optional<std::string>(sanitize_pg_text(group.parent_id)),
        sanitize_pg_text(group.membership_type),
        group.scope_expression.empty()
            ? std::nullopt
            : std::optional<std::string>(sanitize_pg_text(group.scope_expression)),
        std::to_string(now_secs()),
        sanitize_pg_text(group.id)};
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "UPDATE management_group_store.management_groups SET name = $1, description = $2, "
        "parent_id = $3, membership_type = $4, scope_expression = $5, updated_at = $6::bigint "
        "WHERE id = $7",
        params);
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("update failed: ") + PQerrorMessage(lease.get()));
    if (std::string_view(PQcmdTuples(r.get())) == "0")
        return std::unexpected("group not found");
    return {};
}

std::expected<void, std::string> ManagementGroupStore::delete_group(const std::string& id) {
    if (!open_)
        return std::unexpected("database not open");
    if (id == kRootGroupId)
        return std::unexpected("cannot delete root group");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    pg::PgResult r =
        pg::exec_params(lease.get(),
                        "DELETE FROM management_group_store.management_groups WHERE id = $1",
                        std::vector<std::string>{id});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("delete failed: ") + PQerrorMessage(lease.get()));
    if (std::string_view(PQcmdTuples(r.get())) == "0")
        return std::unexpected("group not found");
    return {};
}

// ── Membership ───────────────────────────────────────────────────────────────

std::expected<void, std::string> ManagementGroupStore::add_member(const std::string& group_id,
                                                                  const std::string& agent_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO management_group_store.management_group_members "
        "(group_id, agent_id, source, added_at) VALUES ($1, $2, 'static', $3::bigint) "
        "ON CONFLICT (group_id, agent_id) DO NOTHING",
        std::vector<std::string>{group_id, agent_id, std::to_string(now_secs())});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("add_member failed: ") + PQerrorMessage(lease.get()));
    return {};
}

std::expected<void, std::string> ManagementGroupStore::remove_member(const std::string& group_id,
                                                                     const std::string& agent_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "DELETE FROM management_group_store.management_group_members "
        "WHERE group_id = $1 AND agent_id = $2 AND source = 'static'",
        std::vector<std::string>{group_id, agent_id});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("remove_member failed: ") + PQerrorMessage(lease.get()));
    return {};
}

std::vector<ManagementGroupMember>
ManagementGroupStore::get_members(const std::string& group_id) const {
    return get_members_checked(group_id).value_or(std::vector<ManagementGroupMember>{});
}

std::optional<std::vector<ManagementGroupMember>>
ManagementGroupStore::get_members_checked(const std::string& group_id) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_members_checked: store not open — DENY");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::get_members_checked: pool acquire timed out — DENY");
        return std::nullopt;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT group_id, agent_id, source, added_at "
        "FROM management_group_store.management_group_members WHERE group_id = $1 ORDER BY agent_id",
        std::vector<std::string>{group_id});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_members_checked: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<ManagementGroupMember> result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        ManagementGroupMember m;
        m.group_id = text_col(r.get(), i, 0);
        m.agent_id = text_col(r.get(), i, 1);
        m.source = text_col(r.get(), i, 2);
        m.added_at = to_i64(PQgetvalue(r.get(), i, 3));
        result.push_back(std::move(m));
    }
    return result;
}

std::optional<std::vector<std::string>>
ManagementGroupStore::get_agent_groups(const std::string& agent_id) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_agent_groups: store not open — DENY");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::get_agent_groups: pool acquire timed out — DENY");
        return std::nullopt;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT group_id FROM management_group_store.management_group_members WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_agent_groups: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

void ManagementGroupStore::refresh_dynamic_membership(
    const std::string& group_id, const std::vector<std::string>& matching_agent_ids) {
    if (!open_)
        return;
    // Atomic replace: delete old dynamic members then insert the new set in one
    // transaction so a concurrent reader never sees a half-applied membership.
    const auto now = now_secs();
    pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult del = pg::exec_params(
            c,
            "DELETE FROM management_group_store.management_group_members "
            "WHERE group_id = $1 AND source = 'dynamic'",
            std::vector<std::string>{group_id});
        if (del.status() != PGRES_COMMAND_OK) {
            spdlog::warn("ManagementGroupStore::refresh_dynamic_membership: delete failed: {}",
                         PQerrorMessage(c));
            return false;
        }
        for (const auto& aid : matching_agent_ids) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO management_group_store.management_group_members "
                "(group_id, agent_id, source, added_at) VALUES ($1, $2, 'dynamic', $3::bigint) "
                "ON CONFLICT (group_id, agent_id) DO NOTHING",
                std::vector<std::string>{group_id, aid, std::to_string(now)});
            if (ins.status() != PGRES_COMMAND_OK) {
                spdlog::warn("ManagementGroupStore::refresh_dynamic_membership: insert failed: {}",
                             PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
}

// ── Hierarchy (CONFINEMENT reads) ─────────────────────────────────────────────

std::optional<std::vector<std::string>>
ManagementGroupStore::get_ancestor_ids(const std::string& group_id) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_ancestor_ids: store not open — DENY");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::get_ancestor_ids: pool acquire timed out — DENY");
        return std::nullopt;
    }
    // Ancestor-ward recursive CTE. The `depth < N` bound GUARANTEES termination
    // on a corrupt parent cycle (A->B->A); the outer `DISTINCT ... WHERE id<>$1`
    // drops the self-row and any phantom cycle IDs so a cycle can never inject a
    // spurious ancestor into RbacStore's reachable set (the SQLite predecessor's
    // visited-set semantics, ADR-0042).
    const std::string sql =
        "WITH RECURSIVE anc(id, parent_id, depth) AS ("
        "  SELECT id, parent_id, 0 FROM management_group_store.management_groups WHERE id = $1"
        "  UNION ALL"
        "  SELECT g.id, g.parent_id, a.depth + 1"
        "    FROM management_group_store.management_groups g"
        "    JOIN anc a ON g.id = a.parent_id"
        "   WHERE a.depth < " +
        std::to_string(kMaxHierarchyDepth) +
        ") SELECT DISTINCT id FROM anc WHERE id <> $1";
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{group_id});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_ancestor_ids: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::optional<std::vector<std::string>>
ManagementGroupStore::get_descendant_ids(const std::string& group_id) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_descendant_ids: store not open — DENY");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::get_descendant_ids: pool acquire timed out — DENY");
        return std::nullopt;
    }
    const std::string sql =
        "WITH RECURSIVE sub(id, depth) AS ("
        "  SELECT id, 0 FROM management_group_store.management_groups WHERE parent_id = $1"
        "  UNION ALL"
        "  SELECT g.id, s.depth + 1"
        "    FROM management_group_store.management_groups g"
        "    JOIN sub s ON g.parent_id = s.id"
        "   WHERE s.depth < " +
        std::to_string(kMaxHierarchyDepth) +
        ") SELECT DISTINCT id FROM sub";
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{group_id});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_descendant_ids: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

// ── Group-scoped role assignments ────────────────────────────────────────────

std::expected<void, std::string>
ManagementGroupStore::assign_role(const GroupRoleAssignment& assignment) {
    if (!open_)
        return std::unexpected("database not open");
    // PR 4.2 only ships FLEET-WIDE engine grants; scoped engine role assignment
    // is a Phase-5 deliverable with its own resolution + review. Reject rather
    // than store something the engine-role resolver can't yet honor correctly.
    if (assignment.principal_type == "engine")
        return std::unexpected(
            "engine principals cannot hold scoped role assignments in this release");
    // Shared engine-principal assignment guard — see RbacStore::validate_assignment.
    if (auto v = RbacStore::validate_assignment(assignment.principal_type, assignment.principal_id,
                                                assignment.role_name);
        !v)
        return std::unexpected(v.error());
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO management_group_store.management_group_roles "
        "(group_id, principal_type, principal_id, role_name) VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (group_id, principal_type, principal_id, role_name) DO NOTHING",
        std::vector<std::string>{sanitize_pg_text(assignment.group_id),
                                 sanitize_pg_text(assignment.principal_type),
                                 sanitize_pg_text(assignment.principal_id),
                                 sanitize_pg_text(assignment.role_name)});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("assign_role failed: ") + PQerrorMessage(lease.get()));
    return {};
}

std::expected<void, std::string>
ManagementGroupStore::unassign_role(const std::string& group_id, const std::string& principal_type,
                                    const std::string& principal_id, const std::string& role_name) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("pool acquire timed out");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "DELETE FROM management_group_store.management_group_roles "
        "WHERE group_id = $1 AND principal_type = $2 AND principal_id = $3 AND role_name = $4",
        std::vector<std::string>{group_id, principal_type, principal_id, role_name});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("unassign_role failed: ") + PQerrorMessage(lease.get()));
    return {};
}

std::vector<GroupRoleAssignment>
ManagementGroupStore::get_group_roles(const std::string& group_id) const {
    std::vector<GroupRoleAssignment> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT group_id, principal_type, principal_id, role_name "
        "FROM management_group_store.management_group_roles WHERE group_id = $1 ORDER BY role_name",
        std::vector<std::string>{group_id});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        GroupRoleAssignment a;
        a.group_id = text_col(r.get(), i, 0);
        a.principal_type = text_col(r.get(), i, 1);
        a.principal_id = text_col(r.get(), i, 2);
        a.role_name = text_col(r.get(), i, 3);
        result.push_back(std::move(a));
    }
    return result;
}

std::expected<std::vector<GroupRoleAssignment>, std::string>
ManagementGroupStore::get_assignments_for_principal(
    const std::string& user, const std::vector<std::string>& rbac_groups) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_assignments_for_principal: store not open — DENY");
        return std::unexpected("management group store not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "ManagementGroupStore::get_assignments_for_principal: pool acquire timed out — DENY");
        return std::unexpected("management group store: pool acquire timed out");
    }

    // (principal_type='user' AND principal_id=$1) OR
    // (principal_type='group' AND principal_id IN ($2,$3,...))
    std::string sql = "SELECT group_id, principal_type, principal_id, role_name "
                      "FROM management_group_store.management_group_roles "
                      "WHERE (principal_type='user' AND principal_id=$1)";
    std::vector<std::string> params{user};
    if (!rbac_groups.empty()) {
        sql += " OR (principal_type='group' AND principal_id IN (";
        for (size_t i = 0; i < rbac_groups.size(); ++i) {
            sql += (i ? ",$" : "$") + std::to_string(2 + i);
            params.push_back(rbac_groups[i]);
        }
        sql += "))";
    }

    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_assignments_for_principal: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    std::vector<GroupRoleAssignment> result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        GroupRoleAssignment a;
        a.group_id = text_col(r.get(), i, 0);
        a.principal_type = text_col(r.get(), i, 1);
        a.principal_id = text_col(r.get(), i, 2);
        a.role_name = text_col(r.get(), i, 3);
        result.push_back(std::move(a));
    }
    return result;
}

std::expected<std::vector<std::string>, std::string>
ManagementGroupStore::get_member_agents_in_subtrees(
    const std::vector<std::string>& seed_groups) const {
    if (seed_groups.empty())
        return std::vector<std::string>{}; // no seeds → empty (no query)
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_member_agents_in_subtrees: store not open — DENY");
        return std::unexpected("management group store not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "ManagementGroupStore::get_member_agents_in_subtrees: pool acquire timed out — DENY");
        return std::unexpected("management group store: pool acquire timed out");
    }

    // Recursive CTE: seeds ∪ descendants (depth bound → cycle-safe), joined to
    // members. One query (INV-10), descendant-ward (INV-4). The depth bound
    // MATCHES get_ancestor_ids' cap so the ancestor-ward admit and this
    // descendant-ward visible-set stay SYMMETRIC on a corrupt/over-deep tree
    // (ADR-0017 INV-7): a deny beyond the shared cap is missed by BOTH walks —
    // they agree (both weaker), rather than the point-check over-admitting what
    // the list gate would suppress.
    std::string in;
    std::vector<std::string> params;
    for (size_t i = 0; i < seed_groups.size(); ++i) {
        in += (i ? ",$" : "$") + std::to_string(1 + i);
        params.push_back(seed_groups[i]);
    }
    const std::string sql =
        "WITH RECURSIVE subtree(id, depth) AS ("
        "  SELECT id, 0 FROM management_group_store.management_groups WHERE id IN (" +
        in +
        ")"
        "  UNION ALL"
        "  SELECT g.id, s.depth + 1 FROM management_group_store.management_groups g"
        "    JOIN subtree s ON g.parent_id = s.id WHERE s.depth < " +
        std::to_string(kMaxHierarchyDepth) +
        ") SELECT DISTINCT m.agent_id FROM management_group_store.management_group_members m"
        "  JOIN subtree ON m.group_id = subtree.id";
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_member_agents_in_subtrees: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::optional<std::vector<std::string>>
ManagementGroupStore::get_visible_agents(const std::string& username) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("ManagementGroupStore::get_visible_agents: store not open — DENY");
        return std::nullopt;
    }
    // #1453 — when RBAC enforcement is globally OFF the role-scoped join returns
    // nothing and would hide every agent from the legacy-admin superuser. Fall
    // back to the full enrolled set in that case ONLY (probe unset / RBAC on →
    // role-scoped semantics preserved; the fallback can never widen visibility
    // while RBAC is on).
    if (rbac_enabled_probe_ && !rbac_enabled_probe_())
        return all_member_agents();
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::get_visible_agents: pool acquire timed out — DENY");
        return std::nullopt;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT m.agent_id FROM management_group_store.management_group_members m "
        "JOIN management_group_store.management_group_roles r ON m.group_id = r.group_id "
        "WHERE r.principal_type = 'user' AND r.principal_id = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::get_visible_agents: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::optional<std::vector<std::string>> ManagementGroupStore::all_member_agents() const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("ManagementGroupStore::all_member_agents: pool acquire timed out — DENY");
        return std::nullopt;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT agent_id FROM management_group_store.management_group_members "
        "ORDER BY agent_id",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("ManagementGroupStore::all_member_agents: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

// ── Counting (benign display class — 0 on degrade) ────────────────────────────

size_t ManagementGroupStore::count_groups() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult r =
        pg::exec_params(lease.get(),
                        "SELECT COUNT(*) FROM management_group_store.management_groups",
                        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return 0;
    return static_cast<size_t>(to_i64(PQgetvalue(r.get(), 0, 0)));
}

size_t ManagementGroupStore::count_all_members() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult r =
        pg::exec_params(lease.get(),
                        "SELECT COUNT(*) FROM management_group_store.management_group_members",
                        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return 0;
    return static_cast<size_t>(to_i64(PQgetvalue(r.get(), 0, 0)));
}

size_t ManagementGroupStore::count_members(const std::string& group_id) const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM management_group_store.management_group_members WHERE group_id = $1",
        std::vector<std::string>{group_id});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return 0;
    return static_cast<size_t>(to_i64(PQgetvalue(r.get(), 0, 0)));
}

} // namespace yuzu::server
