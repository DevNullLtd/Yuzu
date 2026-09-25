#include "result_set_store.hpp"

#include <yuzu/audit_retention_rules.hpp>

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <format>
#include <limits>
#include <random>
#include <string_view>
#include <utility>

namespace yuzu::server {

// ── Small helpers ────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Only used against legacy SQLite text columns (may be nullptr).
static const char* safe(const char* p) {
    return p ? p : "";
}

const char* to_string(ResultSetStatus s) {
    switch (s) {
    case ResultSetStatus::Pending:
        return "pending";
    case ResultSetStatus::Materialized:
        return "materialized";
    case ResultSetStatus::Failed:
        return "failed";
    }
    return "materialized";
}

ResultSetStatus result_set_status_from(std::string_view s) {
    if (s == "pending")
        return ResultSetStatus::Pending;
    if (s == "failed")
        return ResultSetStatus::Failed;
    return ResultSetStatus::Materialized;
}

const char* to_string(ResultSetError e) {
    switch (e) {
    case ResultSetError::NotFound:
        return "RESULT_SET_NOT_FOUND";
    case ResultSetError::NotOwner:
        return "RESULT_SET_NOT_OWNER";
    case ResultSetError::QuotaExceeded:
        return "RESULT_SET_QUOTA";
    case ResultSetError::PinLimit:
        return "PIN_LIMIT";
    case ResultSetError::Pinned:
        return "RESULT_SET_PINNED";
    case ResultSetError::TooManyMembers:
        return "RESULT_SET_TOO_MANY_MEMBERS";
    case ResultSetError::DbError:
        return "RESULT_SET_DB_ERROR";
    }
    return "RESULT_SET_DB_ERROR";
}

// Cursor: keyset over (last_used_at, created_at, id) descending. Encoded as
// "<last_used_at>|<created_at>|<id>". Empty string means first page.
static std::string make_cursor(const ResultSet& r) {
    return std::to_string(r.last_used_at) + "|" + std::to_string(r.created_at) + "|" + r.id;
}

static bool parse_cursor(const std::string& c, int64_t& lu, int64_t& ca, std::string& id) {
    auto p1 = c.find('|');
    if (p1 == std::string::npos)
        return false;
    auto p2 = c.find('|', p1 + 1);
    if (p2 == std::string::npos)
        return false;
    try {
        lu = std::stoll(c.substr(0, p1));
        ca = std::stoll(c.substr(p1 + 1, p2 - p1 - 1));
    } catch (...) {
        return false;
    }
    id = c.substr(p2 + 1);
    return true;
}

// ── ID generation ────────────────────────────────────────────────────────────

std::string ResultSetStore::generate_id() {
    // Time-prefixed, lexically sortable (ULID-like) without a new dependency:
    // "rs_" + 11 hex digits of epoch-ms (sortable to ~year 2527) + 16 hex
    // digits of randomness for collision resistance within the same ms.
    //
    // Entropy note (review finding E, preserved from the SQLite implementation):
    // the random suffix is collision resistance, NOT an authenticator. rs_ ids
    // are display identifiers; the authorization boundary is the per-owner
    // check in evaluate_scope and member_set_owned() on every route, not id
    // unguessability.
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::array<char, 40> buf{};
    std::snprintf(buf.data(), buf.size(), "rs_%011llx%016llx",
                  static_cast<unsigned long long>(now_epoch_ms()),
                  static_cast<unsigned long long>(rng()));
    return std::string(buf.data());
}

namespace {

constexpr const char* kStoreName = "result_set_store";

// Bounded acquires (ADR-0012 §2(a)): authoritative store, so reads/writes wait
// a little longer than a fail-soft store's hot-path budget, but every runtime
// acquire is still bounded — none may block indefinitely on a saturated pool.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// Shared wording for the #2437-class poisoned-payload placeholder (both
// mark_failed's poisoned branch and heal_poisoned_payload write this same
// "note" text) so the two heal paths can never drift apart on it.
constexpr const char* kPoisonedPayloadNote =
    "original source_payload exceeded the JSON nesting limit and was discarded";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so `result_sets` et al. land in
    // `result_set_store`. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE result_sets ("
         "  id                  TEXT PRIMARY KEY,"
         "  name                TEXT,"
         "  owner_principal     TEXT NOT NULL,"
         "  created_at          BIGINT NOT NULL,"
         "  ttl_at              BIGINT NOT NULL,"
         "  last_used_at        BIGINT NOT NULL,"
         "  pinned              BOOLEAN NOT NULL DEFAULT FALSE,"
         "  parent_id           TEXT REFERENCES result_sets(id) ON DELETE SET NULL,"
         "  source_kind         TEXT NOT NULL,"
         "  source_payload      TEXT NOT NULL,"
         "  status              TEXT NOT NULL DEFAULT 'materialized',"
         "  source_execution_id TEXT NOT NULL DEFAULT '',"
         "  matcher             TEXT NOT NULL DEFAULT '',"
         "  device_count        BIGINT NOT NULL DEFAULT 0,"
         "  CHECK (length(id) >= 5 AND substr(id,1,3) = 'rs_'),"
         "  CHECK (ttl_at >= created_at));"
         "CREATE TABLE result_set_members ("
         "  result_set_id TEXT NOT NULL REFERENCES result_sets(id) ON DELETE CASCADE,"
         "  device_id     TEXT NOT NULL,"
         "  PRIMARY KEY (result_set_id, device_id));"
         "CREATE INDEX idx_result_sets_owner_used ON result_sets(owner_principal, last_used_at);"
         "CREATE INDEX idx_result_sets_owner_name ON result_sets(owner_principal, name);"
         "CREATE INDEX idx_result_sets_parent ON result_sets(parent_id);"
         "CREATE INDEX idx_result_sets_status ON result_sets(status);"
         "CREATE INDEX idx_result_set_members_dev ON result_set_members(device_id);"
         // Durable state for the gc_sweep retention clock guard (#2360 class;
         // routed-concern "Clock-guarded retention"). SHARED rows rather than
         // process-local members: on Postgres N server replicas each run the
         // sweep, so the persisted reading and the anomaly-dedup fact set
         // must be one shared truth under the sweep's advisory lock — a
         // process-local copy paces at N x cap and one skewed replica would
         // put every replica into independent decline (the ladder's AuditStore
         // row records the same requirement for its own migration).
         "CREATE TABLE gc_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL);"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // sqlite_backfill's sole purpose was the backfill idempotency marker, which
        // no longer has a writer. Version-bumped (not edited into v1) because v1 has
        // actually run against real dev/UAT databases — see ADR-0036's Update.
        {2, "DROP TABLE IF EXISTS sqlite_backfill;"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_int(const char* s) { return static_cast<int>(to_i64(s)); }
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

constexpr const char* kRowCols =
    "id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id, "
    "source_kind, source_payload, status, source_execution_id, matcher, device_count";

ResultSet read_row(PGresult* res, int i) {
    ResultSet r;
    int c = 0;
    r.id = PQgetvalue(res, i, c++);
    // NULL and "" are indistinguishable via PQgetvalue on a text column — same
    // ambiguity the legacy SQLite reader had (sqlite3_column_text on a NULL
    // column also yields ""), so this is not a behavioral change.
    r.name = PQgetvalue(res, i, c++);
    r.owner_principal = PQgetvalue(res, i, c++);
    r.created_at = to_i64(PQgetvalue(res, i, c++));
    r.ttl_at = to_i64(PQgetvalue(res, i, c++));
    r.last_used_at = to_i64(PQgetvalue(res, i, c++));
    r.pinned = to_bool(PQgetvalue(res, i, c++));
    if (!PQgetisnull(res, i, c))
        r.parent_id = PQgetvalue(res, i, c);
    ++c;
    r.source_kind = PQgetvalue(res, i, c++);
    r.source_payload = PQgetvalue(res, i, c++);
    r.status = result_set_status_from(PQgetvalue(res, i, c++));
    r.source_execution_id = PQgetvalue(res, i, c++);
    r.matcher = PQgetvalue(res, i, c++);
    r.device_count = to_i64(PQgetvalue(res, i, c++));
    return r;
}

std::vector<std::string_view> as_views(const std::vector<std::string>& v) {
    std::vector<std::string_view> out;
    out.reserve(v.size());
    for (const auto& s : v)
        out.emplace_back(s);
    return out;
}

// Shared by pin() (same connection, no extra round trip) and the public
// count_pinned_for_owner(). Returns -1 on query error so callers can
// distinguish "zero pinned" from "could not determine" (authoritative posture
// — a caller must not silently treat a DB error as "under the limit").
int count_pinned_on(PGconn* conn, const std::string& owner) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1 AND "
        "pinned = true",
        std::vector<std::string>{owner});
    if (res.status() != PGRES_TUPLES_OK)
        return -1;
    return to_int(PQgetvalue(res.get(), 0, 0));
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ResultSetStore::ResultSetStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ResultSetStore: no database connection at construction ({}) — result-set "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ResultSetStore: schema migration failed — result-set persistence disabled");
        return;
    }
    open_ = true;
}

// ── Create ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::insert_row_impl(
    const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
    const std::vector<std::string>& members) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);

    // Deduplicate members up front: device_count must reflect the rows
    // actually stored (ON CONFLICT DO NOTHING silently drops duplicates —
    // review finding L, preserved from the SQLite implementation), and the
    // per-set cap is a DoS guard that must bound the *distinct* membership,
    // not the raw request size (review finding C).
    std::vector<std::string> uniq;
    uniq.reserve(members.size());
    {
        std::unordered_set<std::string> seen;
        seen.reserve(members.size() * 2);
        for (const auto& dev : members)
            if (!dev.empty() && seen.insert(dev).second)
                uniq.push_back(dev);
    }
    if (uniq.size() > static_cast<size_t>(kMaxMembersPerSet))
        return std::unexpected(ResultSetError::TooManyMembers);

    ResultSet row;
    row.id = generate_id();
    row.name = req.name;
    row.owner_principal = req.owner_principal;
    row.created_at = now_epoch();
    row.ttl_at = row.created_at + kDefaultTtlSeconds;
    row.last_used_at = row.created_at;
    row.pinned = false;
    row.parent_id = req.parent_id;
    row.source_kind = req.source_kind;
    row.source_payload = req.source_payload;
    row.status = status;
    row.source_execution_id = execution_id;
    row.matcher = req.matcher;
    row.device_count = static_cast<int64_t>(uniq.size());

    const std::vector<std::string_view> member_views = as_views(uniq);
    bool quota_exceeded = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Hard per-operator quota (design §3.3). A small race against a
        // concurrent create for the same owner is possible (Postgres real
        // concurrency replaces the SQLite single-writer mutex) — acceptable
        // for a soft DoS guard, not a security boundary.
        // Expired-but-unswept rows do NOT count against the quota (Gate 4
        // UP-6): a stalled gc sweep would otherwise convert GC debt into
        // spurious operator Quota failures. Still soft-guard-grade.
        pg::PgResult qc = pg::exec_params(
            conn,
            "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1 "
            "AND (pinned OR ttl_at >= extract(epoch from now())::bigint)",
            std::vector<std::string>{req.owner_principal});
        if (qc.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::insert_row_impl: quota check failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (to_int(PQgetvalue(qc.get(), 0, 0)) >= kMaxPerOwner) {
            quota_exceeded = true;
            return false;
        }

        pg::PgResult r1 = pg::exec_params(
            conn,
            "INSERT INTO result_set_store.result_sets "
            "(id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id, "
            " source_kind, source_payload, status, source_execution_id, matcher, device_count) "
            "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,false,$7,$8,$9,$10,$11,$12,"
            "$13::bigint) RETURNING id",
            std::vector<std::optional<std::string>>{
                row.id, row.name.empty() ? std::nullopt : std::optional<std::string>(row.name),
                row.owner_principal, std::to_string(row.created_at), std::to_string(row.ttl_at),
                std::to_string(row.last_used_at), row.parent_id, row.source_kind,
                row.source_payload, std::string(to_string(row.status)), row.source_execution_id,
                row.matcher, std::to_string(row.device_count)});
        if (r1.status() != PGRES_TUPLES_OK || PQntuples(r1.get()) == 0) {
            spdlog::error("ResultSetStore::insert_row_impl: row insert failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        if (!uniq.empty()) {
            pg::PgResult r2 = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_set_members (result_set_id, device_id) "
                "SELECT $1, d FROM unnest($2::text[]) AS d ON CONFLICT DO NOTHING",
                std::vector<std::string>{row.id, pg::to_text_array(member_views)});
            if (r2.status() != PGRES_COMMAND_OK && r2.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResultSetStore::insert_row_impl: member insert failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        return true;
    });

    if (!ok)
        return std::unexpected(quota_exceeded ? ResultSetError::QuotaExceeded
                                              : ResultSetError::DbError);
    return row;
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_materialized(
    const CreateRequest& req, const std::vector<std::string>& members) {
    return insert_row_impl(req, ResultSetStatus::Materialized, /*execution_id=*/"", members);
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_pending(
    const CreateRequest& req, const std::string& execution_id) {
    return insert_row_impl(req, ResultSetStatus::Pending, execution_id, /*members=*/{});
}

// ── Read ─────────────────────────────────────────────────────────────────────

std::expected<std::optional<ResultSet>, ResultSetError> ResultSetStore::get(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::get: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    std::string sql = std::string("SELECT ") + kRowCols +
                      " FROM result_set_store.result_sets WHERE id = $1 LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::get: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<ResultSet>(std::nullopt);
    return std::optional<ResultSet>(read_row(res.get(), 0));
}

std::expected<ResultSetStore::ListPage, ResultSetError> ResultSetStore::list_by_owner_checked(
    const std::string& owner, const std::string& cursor, int limit) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    if (limit <= 0)
        limit = 50;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::list_by_owner_checked: no connection ({})",
                      pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }

    int64_t cur_lu = 0, cur_ca = 0;
    std::string cur_id;
    bool has_cursor = !cursor.empty() && parse_cursor(cursor, cur_lu, cur_ca, cur_id);

    // Keyset pagination over (last_used_at, created_at, id) DESC.
    std::string sql = std::string("SELECT ") + kRowCols +
                      " FROM result_set_store.result_sets WHERE owner_principal = $1";
    std::vector<std::string> params{owner};
    if (has_cursor) {
        sql += " AND (last_used_at < $2::bigint OR (last_used_at = $2::bigint AND "
              "(created_at < $3::bigint OR (created_at = $3::bigint AND id < $4))))"
              " ORDER BY last_used_at DESC, created_at DESC, id DESC LIMIT $5::bigint";
        params.push_back(std::to_string(cur_lu));
        params.push_back(std::to_string(cur_ca));
        params.push_back(cur_id);
    } else {
        sql += " ORDER BY last_used_at DESC, created_at DESC, id DESC LIMIT $2::bigint";
    }
    params.push_back(std::to_string(limit + 1)); // fetch one extra to detect next page

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::list_by_owner_checked: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    ListPage page;
    const int rows = PQntuples(res.get());
    page.sets.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        page.sets.push_back(read_row(res.get(), i));

    if (static_cast<int>(page.sets.size()) > limit) {
        page.sets.resize(limit);
        page.next_cursor = make_cursor(page.sets.back());
    }
    return page;
}

std::vector<ResultSet> ResultSetStore::list_by_owner(const std::string& owner,
                                                     const std::string& cursor, int limit,
                                                     std::string& out_next_cursor) {
    auto r = list_by_owner_checked(owner, cursor, limit);
    if (!r) {
        out_next_cursor.clear();
        return {};
    }
    out_next_cursor = r->next_cursor;
    return std::move(r->sets);
}

std::expected<ResultSetStore::MembersPage, ResultSetError> ResultSetStore::members_checked(
    const std::string& id, const std::string& cursor, int limit) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    if (limit <= 0)
        limit = 1000;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::members_checked: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }

    // Keyset over device_id ASC.
    std::string sql =
        "SELECT device_id FROM result_set_store.result_set_members WHERE result_set_id = $1";
    std::vector<std::string> params{id};
    if (!cursor.empty()) {
        sql += " AND device_id > $2 ORDER BY device_id ASC LIMIT $3::bigint";
        params.push_back(cursor);
    } else {
        sql += " ORDER BY device_id ASC LIMIT $2::bigint";
    }
    params.push_back(std::to_string(limit + 1));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::members_checked: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    MembersPage page;
    const int rows = PQntuples(res.get());
    page.device_ids.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        page.device_ids.emplace_back(PQgetvalue(res.get(), i, 0));

    if (static_cast<int>(page.device_ids.size()) > limit) {
        page.device_ids.resize(limit);
        page.next_cursor = page.device_ids.back();
    }
    return page;
}

std::vector<std::string> ResultSetStore::members(const std::string& id, const std::string& cursor,
                                                 int limit, std::string& out_next_cursor) {
    auto r = members_checked(id, cursor, limit);
    if (!r) {
        out_next_cursor.clear();
        return {};
    }
    out_next_cursor = r->next_cursor;
    return std::move(r->device_ids);
}

std::expected<std::vector<LineageNode>, ResultSetError> ResultSetStore::lineage_checked(
    const std::string& id, const std::string& owner) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::lineage_checked: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }

    // One logical operation, one lease (ADR-0012 §2(c)) — up to kLineageDepthCap
    // sequential hops on the same connection.
    std::vector<LineageNode> chain;
    std::optional<std::string> cur = id;
    int depth = 0;
    bool db_error = false;
    std::unordered_set<std::string> visited; // cycle guard (review finding J)
    while (cur && depth < kLineageDepthCap) {
        if (!visited.insert(*cur).second)
            break; // a parent_id loop would otherwise spin to the depth cap
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, name, source_kind, device_count, parent_id, owner_principal "
            "FROM result_set_store.result_sets WHERE id = $1 LIMIT 1",
            std::vector<std::string>{*cur});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::lineage_checked: query failed: {}",
                          PQerrorMessage(lease.get()));
            // #4306 finding 3: a genuine mid-walk query failure is a DbError
            // for the WHOLE call, not the partial chain accumulated so far —
            // the pre-#4306 plain lineage() returned that partial chain,
            // indistinguishable from a genuinely-short breadcrumb; see the
            // header posture note on lineage()'s semantic shift.
            db_error = true;
            break;
        }
        std::optional<std::string> next;
        if (PQntuples(res.get()) > 0) {
            // Owner-filter (review finding B2): stop at the first node not
            // owned by `owner` so a cross-operator ancestor's name/
            // source_kind/device_count never reaches the caller. Normal
            // termination, not a DbError — same as the cycle guard above.
            std::string node_owner = PQgetvalue(res.get(), 0, 5);
            if (node_owner != owner)
                break;
            LineageNode n;
            n.id = PQgetvalue(res.get(), 0, 0);
            n.name = PQgetvalue(res.get(), 0, 1);
            n.source_kind = PQgetvalue(res.get(), 0, 2);
            n.device_count = to_i64(PQgetvalue(res.get(), 0, 3));
            chain.push_back(std::move(n));
            if (!PQgetisnull(res.get(), 0, 4))
                next = PQgetvalue(res.get(), 0, 4);
        }
        cur = next;
        ++depth;
    }
    if (db_error)
        return std::unexpected(ResultSetError::DbError);
    // chain is leaf→root; reverse to root→leaf for breadcrumb display.
    std::reverse(chain.begin(), chain.end());
    return chain;
}

std::vector<LineageNode> ResultSetStore::lineage(const std::string& id, const std::string& owner) {
    return lineage_checked(id, owner).value_or(std::vector<LineageNode>{});
}

std::expected<bool, ResultSetError> ResultSetStore::contains(const std::string& id,
                                                             const std::string& device_id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::contains: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT 1 FROM result_set_store.result_set_members WHERE result_set_id = $1 AND "
        "device_id = $2 LIMIT 1",
        std::vector<std::string>{id, device_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::contains: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    return PQntuples(res.get()) > 0;
}

std::expected<std::unordered_set<std::string>, ResultSetError>
ResultSetStore::member_set_owned(const std::string& id, const std::string& owner) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::member_set_owned: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // The owner join is the authorization gate: a set not owned by `owner`
    // yields zero rows, so the caller sees an empty (non-matching) membership
    // and never learns it exists — the documented "stale members drop
    // silently" contract extends cleanly to "not-yours members drop silently".
    // A DB ERROR is DISTINCT from both of those (std::unexpected, never an
    // empty set) — see the header's type-distinguishable-reads note; the
    // caller (AgentRegistry::evaluate_scope) MUST abort on DbError rather
    // than proceed with a partial preload (the fleet-wide fail-open under a
    // NOT combinator this contract exists to prevent).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT m.device_id FROM result_set_store.result_set_members m "
        "JOIN result_set_store.result_sets r ON r.id = m.result_set_id "
        "WHERE m.result_set_id = $1 AND r.owner_principal = $2",
        std::vector<std::string>{id, owner});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::member_set_owned: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    std::unordered_set<std::string> out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.insert(PQgetvalue(res.get(), i, 0));
    return out;
}

std::expected<std::optional<std::string>, ResultSetError>
ResultSetStore::resolve_alias(const std::string& owner, const std::string& name) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    if (name.empty())
        return std::optional<std::string>(std::nullopt); // trivial not-found, not a DB error
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::resolve_alias: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id FROM result_set_store.result_sets WHERE owner_principal = $1 AND name = $2 "
        "ORDER BY created_at DESC LIMIT 1",
        std::vector<std::string>{owner, name});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::resolve_alias: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>(std::nullopt);
    return std::optional<std::string>(std::string(PQgetvalue(res.get(), 0, 0)));
}

std::expected<int, ResultSetError> ResultSetStore::count_for_owner_checked(
    const std::string& owner) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::count_for_owner_checked: no connection ({})",
                      pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // #4306 fold-in A: predicate aligned with insert_row_impl's authoritative
    // in-txn recheck (Gate 4 UP-6) -- expired-but-unswept rows do NOT count
    // against the quota there, so a pre-check without this filter
    // OVER-counts relative to the authoritative check and could reject a
    // dispatch the authoritative check would have allowed (a stalled GC
    // sweep converting GC debt into a spurious operator quota failure).
    // Keeping the two predicates identical means this pre-check predicts the
    // authoritative check exactly.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1 "
        "AND (pinned OR ttl_at >= extract(epoch from now())::bigint)",
        std::vector<std::string>{owner});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::count_for_owner_checked: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    return to_int(PQgetvalue(res.get(), 0, 0));
}

int ResultSetStore::count_for_owner(const std::string& owner) {
    return count_for_owner_checked(owner).value_or(0);
}

int ResultSetStore::count_pinned_for_owner(const std::string& owner) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::count_pinned_for_owner: no connection ({})",
                      pool_.last_error());
        return 0;
    }
    int n = count_pinned_on(lease.get(), owner);
    if (n < 0) {
        spdlog::error("ResultSetStore::count_pinned_for_owner: query failed: {}",
                      PQerrorMessage(lease.get()));
        return 0;
    }
    return n;
}

ResultSetStore::Counts ResultSetStore::counts() {
    Counts c;
    if (!open_)
        return c;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::counts: no connection ({})", pool_.last_error());
        return c;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*), COALESCE(SUM(pinned::int), 0), "
        "COALESCE(SUM((status = 'pending')::int), 0) FROM result_set_store.result_sets",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("ResultSetStore::counts: query failed: {}", PQerrorMessage(lease.get()));
        return c;
    }
    c.total = to_int(PQgetvalue(res.get(), 0, 0));
    c.pinned = to_int(PQgetvalue(res.get(), 0, 1));
    c.pending = to_int(PQgetvalue(res.get(), 0, 2));
    return c;
}

// ── Mutate ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::pin(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    // Whole check-count-update sequence under ONE transaction (governance
    // M3): autocommit statements on a lease are not atomic, so the
    // kMaxPinsPerOwner check was racy (two concurrent pins by one owner both
    // count cap-1 and both commit) and the target row could be deleted
    // between read and update. FOR UPDATE locks the target row; the
    // per-owner advisory xact lock serialises the CAP check against
    // concurrent pins of the owner's OTHER sets (a row lock on one set
    // cannot do that). Both locks are transaction-scoped — pool-safe (the
    // session-level variants would poison the shared connection; see
    // docs/postgres-store-playbook.md).
    std::expected<ResultSet, ResultSetError> out = std::unexpected(ResultSetError::DbError);
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        std::string sel_sql = std::string("SELECT ") + kRowCols +
                              " FROM result_set_store.result_sets WHERE id = $1 FOR UPDATE";
        pg::PgResult get_res = pg::exec_params(conn, sel_sql.c_str(), std::vector<std::string>{id});
        if (get_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::pin: read failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(get_res.get()) == 0) {
            out = std::unexpected(ResultSetError::NotFound);
            return true; // commit the no-op
        }
        ResultSet row = read_row(get_res.get(), 0);
        if (row.pinned) {
            out = std::move(row); // idempotent — no ttl_at renewal, matches the SQLite behavior
            return true;
        }

        // CROSS-STORE NAMESPACE prefix, matching the sibling stores'
        // hashtextextended('<store>:' || key) convention.
        pg::PgResult lk = pg::exec_params(
            conn, "SELECT pg_advisory_xact_lock(hashtextextended('result_set_store:pin:' || $1, 0))",
            std::vector<std::string>{row.owner_principal});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::pin: owner lock failed: {}", PQerrorMessage(conn));
            return false;
        }

        // Pin-storm guard (design §3.3): per-operator cap — now race-free
        // under the owner lock above.
        int pinned_count = count_pinned_on(conn, row.owner_principal);
        if (pinned_count < 0) {
            spdlog::error("ResultSetStore::pin: pin-count check failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (pinned_count >= kMaxPinsPerOwner) {
            out = std::unexpected(ResultSetError::PinLimit);
            return true;
        }

        std::string upd_sql = std::string("UPDATE result_set_store.result_sets SET pinned = true, "
                                          "ttl_at = $1::bigint WHERE id = $2 RETURNING ") +
                              kRowCols;
        pg::PgResult upd = pg::exec_params(
            conn, upd_sql.c_str(),
            std::vector<std::string>{std::to_string(std::numeric_limits<int64_t>::max()), id});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::pin: update failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(upd.get()) == 0) {
            out = std::unexpected(ResultSetError::NotFound); // deleted concurrently
            return true;
        }
        out = read_row(upd.get(), 0);
        return true;
    });
    if (!ok)
        return std::unexpected(ResultSetError::DbError);
    return out;
}

std::expected<ResultSet, ResultSetError> ResultSetStore::unpin(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::unpin: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // Restore ttl_at = now + default (design §3.3). The original was
    // INT64_MAX while pinned, so this clamps rather than "restoring" a prior
    // value — same behavior as the SQLite implementation.
    int64_t new_ttl = now_epoch() + kDefaultTtlSeconds;
    std::string sql = std::string("UPDATE result_set_store.result_sets SET pinned = false, "
                                  "ttl_at = $1::bigint WHERE id = $2 RETURNING ") +
                      kRowCols;
    pg::PgResult upd = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(new_ttl), id});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::unpin: update failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(upd.get()) == 0)
        return std::unexpected(ResultSetError::NotFound);
    return read_row(upd.get(), 0);
}

void ResultSetStore::touch(const std::string& id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::touch: no connection ({})", pool_.last_error());
        return;
    }
    int64_t now = now_epoch();
    // Do not shorten a pinned set's INT64_MAX ttl; only ever extend.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE result_set_store.result_sets SET last_used_at = $1::bigint, "
        "ttl_at = GREATEST(ttl_at, $2::bigint) WHERE id = $3",
        std::vector<std::string>{std::to_string(now), std::to_string(now + kDefaultTtlSeconds),
                                 id});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::error("ResultSetStore::touch: update failed: {}", PQerrorMessage(lease.get()));
}

std::expected<void, ResultSetError> ResultSetStore::delete_set(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::delete_set: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // ONE conditional statement (governance M3): the base SQLite impl held a
    // mutex across check+DELETE; two autocommit statements on one lease are
    // NOT atomic (a lease serialises access to a connection, not a pair of
    // statements), so a pin landing between them deleted a set the operator
    // was told was pinned. The predicate makes the pinned-check and the
    // delete one atomic statement; the follow-up read only CLASSIFIES a miss
    // (NotFound vs Pinned) and can no longer delete anything.
    pg::PgResult del = pg::exec_params(
        lease.get(),
        "DELETE FROM result_set_store.result_sets WHERE id = $1 AND pinned = false RETURNING id",
        std::vector<std::string>{id});
    if (del.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::delete_set: delete failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(del.get()) == 1)
        return {};
    pg::PgResult probe = pg::exec_params(
        lease.get(), "SELECT pinned FROM result_set_store.result_sets WHERE id = $1 LIMIT 1",
        std::vector<std::string>{id});
    if (probe.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::delete_set: probe failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(probe.get()) == 1 && to_bool(PQgetvalue(probe.get(), 0, 0)))
        return std::unexpected(ResultSetError::Pinned); // must unpin first (design §6)
    return std::unexpected(ResultSetError::NotFound);
}

// ── Async materialisation ────────────────────────────────────────────────────

std::vector<PendingSet> ResultSetStore::list_pending() {
    std::vector<PendingSet> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::list_pending: no connection ({})", pool_.last_error());
        return result;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, owner_principal, source_kind, source_execution_id, matcher, created_at "
        "FROM result_set_store.result_sets WHERE status = 'pending' ORDER BY created_at ASC",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::list_pending: query failed: {}", PQerrorMessage(lease.get()));
        return result;
    }
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        PendingSet p;
        p.id = PQgetvalue(res.get(), i, 0);
        p.owner_principal = PQgetvalue(res.get(), i, 1);
        p.source_kind = PQgetvalue(res.get(), i, 2);
        p.source_execution_id = PQgetvalue(res.get(), i, 3);
        p.matcher = PQgetvalue(res.get(), i, 4);
        p.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        result.push_back(std::move(p));
    }
    return result;
}

std::expected<void, ResultSetError> ResultSetStore::materialize(
    const std::string& id, const std::vector<std::string>& members) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);

    // Dedup + drop empties (UP-6): matches insert_row_impl's contract exactly
    // — device_count must reflect the rows actually stored (ON CONFLICT DO
    // NOTHING silently drops duplicates), not the raw request size. Before
    // this fix materialize() skipped this step, so a caller passing
    // `["a","a"]` over-reported device_count=2 for one stored row.
    std::vector<std::string> uniq;
    uniq.reserve(members.size());
    {
        std::unordered_set<std::string> seen;
        seen.reserve(members.size() * 2);
        for (const auto& dev : members)
            if (!dev.empty() && seen.insert(dev).second)
                uniq.push_back(dev);
    }
    const std::vector<std::string_view> member_views = as_views(uniq);
    bool not_found = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        if (!uniq.empty()) {
            pg::PgResult r = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_set_members (result_set_id, device_id) "
                "SELECT $1, d FROM unnest($2::text[]) AS d ON CONFLICT DO NOTHING",
                std::vector<std::string>{id, pg::to_text_array(member_views)});
            if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResultSetStore::materialize: member insert failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE result_set_store.result_sets SET status = 'materialized', "
            "device_count = $1::bigint WHERE id = $2 AND status = 'pending' RETURNING id",
            std::vector<std::string>{std::to_string(static_cast<int64_t>(uniq.size())), id});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::materialize: update failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(upd.get()) == 0) {
            not_found = true;
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(not_found ? ResultSetError::NotFound : ResultSetError::DbError);
    return {};
}

void ResultSetStore::mark_failed(const std::string& id, const std::string& reason) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::mark_failed: no connection ({})", pool_.last_error());
        return;
    }
    pg::PgResult sel = pg::exec_params(
        lease.get(),
        "SELECT source_payload FROM result_set_store.result_sets WHERE id = $1 AND status = "
        "'pending'",
        std::vector<std::string>{id});
    if (sel.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::mark_failed: read failed: {}", PQerrorMessage(lease.get()));
        return;
    }
    if (PQntuples(sel.get()) == 0)
        return; // not pending (or gone) — nothing to mark

    const std::string raw_payload(PQgetvalue(sel.get(), 0, 0));

    // #2437-class guard: this function's whole job is to write an updated
    // source_payload back, and nlohmann::json::dump() is unboundedly
    // recursive. This has no HTTP request/response of its own to answer with
    // a 400 (governance Gate 4/6 finding: today it has NO production caller
    // at all, only unit tests - the store method exists ahead of a future
    // caller, not for a currently-wired background thread), so a poisoned
    // row reaching here (written before this guard existed, or via any other
    // path, past or future) would otherwise SIGSEGV the whole process on the
    // `payload.dump()` below.
    // Check the RAW fetched text before it is ever parsed: if it nests too
    // deeply, DISCARD the poisoned original rather than try to preserve it.
    // The row still must transition to 'failed' (callers depend on that
    // contract), so the replacement is a small, fixed, trivially-shallow
    // object that is always safe to dump: the row is "healed", no longer a
    // live grenade for a future read.
    nlohmann::json payload;
    if (mcp::json_exceeds_depth(raw_payload, mcp::kMcpMaxJsonDepth)) {
        payload = nlohmann::json{{"failure", reason}, {"note", kPoisonedPayloadNote}};
    } else {
        // Merge {"failure": reason} into the payload in C++ rather than relying on
        // a Postgres JSON-validity cast (source_payload is a plain TEXT column,
        // not jsonb, and an operator-supplied string is not guaranteed valid
        // JSON): replicates the SQLite json1 `json_set(... CASE WHEN
        // json_valid ...)` fallback-to-'{}' behavior.
        try {
            payload = nlohmann::json::parse(raw_payload);
            if (!payload.is_object())
                payload = nlohmann::json::object();
        } catch (...) {
            payload = nlohmann::json::object();
        }
        payload["failure"] = reason;
    }

    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE result_set_store.result_sets SET status = 'failed', source_payload = $1 "
        "WHERE id = $2 AND status = 'pending'",
        std::vector<std::string>{payload.dump(), id});
    if (upd.status() != PGRES_COMMAND_OK)
        spdlog::error("ResultSetStore::mark_failed: update failed: {}", PQerrorMessage(lease.get()));
}

bool ResultSetStore::heal_poisoned_payload(const std::string& id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::heal_poisoned_payload: no connection ({})",
                      pool_.last_error());
        return false;
    }
    // #4493: no status predicate, unlike mark_failed's 'pending'-only SELECT
    // -- this is the heal path for every status mark_failed cannot reach
    // (materialized, and failed for symmetry), and is harmless to run
    // against a pending row too (materialisation reads execution responses,
    // never source_payload).
    pg::PgResult sel =
        pg::exec_params(lease.get(),
                         "SELECT source_payload FROM result_set_store.result_sets WHERE id = $1",
                         std::vector<std::string>{id});
    if (sel.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::heal_poisoned_payload: read failed: {}",
                      PQerrorMessage(lease.get()));
        return false;
    }
    if (PQntuples(sel.get()) == 0)
        return false; // gone -- nothing to heal

    const std::string raw_payload(PQgetvalue(sel.get(), 0, 0));

    // Re-check the RAW text itself -- never trust a caller's earlier check --
    // and no-op on a healthy payload so this can never overwrite a row's
    // genuine provenance. Same #2437-class discipline as mark_failed: the
    // guard runs on the fetched TEXT before any parse/dump ever touches it.
    if (!mcp::json_exceeds_depth(raw_payload, mcp::kMcpMaxJsonDepth))
        return false;

    // Status is deliberately left untouched (see the header doc comment):
    // a materialized row's members are real and still scope-walkable
    // (member_set_owned never filters on status), so this only replaces the
    // poisoned blob, never the row's status.
    // #4540: RETURNING id + an affected-row check, same idiom as
    // materialize()'s own status-guarded UPDATE above -- a concurrent delete
    // between the SELECT above and this UPDATE (delete_set on an independent
    // connection lease, or the TTL GC sweep, either with no shared lock) must
    // never be reported as a successful heal for a row that no longer exists.
    const nlohmann::json payload{{"note", kPoisonedPayloadNote}};
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE result_set_store.result_sets SET source_payload = $1 WHERE id = $2 RETURNING id",
        std::vector<std::string>{payload.dump(), id});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::heal_poisoned_payload: update failed: {}",
                      PQerrorMessage(lease.get()));
        return false;
    }
    if (PQntuples(upd.get()) == 0)
        return false; // gone between the SELECT above and this UPDATE
    return true;
}

// ── GC ───────────────────────────────────────────────────────────────────────

// Clock-guarded retention (routed-concern invariant; #2360 class). The
// cutoff comes from a wall clock, so a bare `DELETE ... WHERE ttl_at < now`
// is banned: a forward-skewed clock mass-expires sets that are not stale.
// The guard follows the reference SHAPE (audit_retention_rules.hpp classify
// + AuditStore::cleanup_once fact-set dedup) with substrate-tuned constants
// — result sets are 1-hour-TTL operator scratch state, pinned sets are
// protected by pinned=false regardless of ttl_at.
//
// Postgres adaptation (this store is the first PG implementation of the
// guard; AuditStore's own migration row records the same requirement): the
// persisted reading + the anomaly-dedup fact set live in SHARED
// `gc_meta` rows, and one sweep runs fleet-wide at a time under a
// try-advisory xact lock — process-local state would pace at N x cap across
// replicas and one skewed replica could put every replica into permanent
// independent decline.
//
// Part-6 anchor decision (recorded, per the invariant): a MISSING stored
// reading is ordinary — the fresh-store / first-pass-after-migration case —
// and says nothing by itself; it is reported only when the pass would ALSO
// expire every datable row (the AuditStore choice, not the TAR choice,
// because unlike TAR this table is legitimately empty/short-lived in normal
// operation and a first pass against it deletes at most 1-hour-old scratch).
namespace {
constexpr int64_t kGcSweepCapPerPass = 5000;      // part 5: unconditional
constexpr int64_t kGcBigStepSecs = 86'400;        // part 7: absolute, ~1 day
constexpr int64_t kGcImplausiblyAheadSecs = 604'800; // part 1: probe excludes
} // namespace

int ResultSetStore::gc_sweep() {
    if (!open_)
        return 0;
    int deleted = 0;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // One sweeping replica at a time. try-variant: a busy lock means a
        // sibling replica is already sweeping this pass — skip quietly.
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock(hashtextextended('result_set_store:gc_sweep', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::gc_sweep: lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0)))
            return true; // another replica holds the sweep

        const int64_t now = now_epoch();

        // Load the persisted reading + last-reported anomaly fact set.
        pg::PgResult meta = pg::exec_params(
            conn, "SELECT key, value FROM result_set_store.gc_meta WHERE key IN "
                  "('last_pass_now','last_anomaly_facts')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::gc_sweep: meta read failed: {}", PQerrorMessage(conn));
            return false;
        }
        std::optional<int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        for (int i = 0; i < PQntuples(meta.get()); ++i) {
            std::string key = safe(PQgetvalue(meta.get(), i, 0));
            std::string val = safe(PQgetvalue(meta.get(), i, 1));
            if (key == "last_pass_now") {
                errno = 0;
                char* end = nullptr;
                long long v = std::strtoll(val.c_str(), &end, 10);
                if (errno != 0 || end == val.c_str() || *end != '\0') {
                    prev_unusable = true; // part 3: unparseable = anomaly, never a quiet reset
                } else {
                    prev = static_cast<int64_t>(v);
                }
            } else if (key == "last_anomaly_facts") {
                last_facts = val;
            }
        }
        // part 3: sanitise BEFORE arithmetic — ahead-of-now or negative is an
        // anomaly carrier, and `now - prev` on either would be meaningless
        // (or UB-adjacent on INT64_MIN).
        if (prev && (*prev < 0 || *prev > now)) {
            prev_unusable = true;
            prev.reset();
        }

        // Stamp the new reading FIRST — an honest observation of the clock
        // whatever this pass decides (reference behaviour; it is what makes
        // the guard work when the clock was already wrong before boot).
        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO result_set_store.gc_meta (key, value) VALUES ('last_pass_now', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("ResultSetStore::gc_sweep: meta stamp failed: {}", PQerrorMessage(conn));
            return false;
        }

        // part 1: probe by OUTCOME. Rows stamped implausibly far ahead are
        // excluded from the datable denominator so one forward-skewed row
        // cannot disarm the wipe detector forever. pinned rows (ttl_at =
        // INT64_MAX) are outside the sweep entirely via pinned = false.
        pg::PgResult probe = pg::exec_params(
            conn,
            "SELECT count(*) FILTER (WHERE ttl_at < $1::bigint) AS expiring, "
            "count(*) FILTER (WHERE ttl_at <= $2::bigint) AS datable "
            "FROM result_set_store.result_sets WHERE pinned = false",
            std::vector<std::string>{std::to_string(now),
                                     std::to_string(now + kGcImplausiblyAheadSecs)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::gc_sweep: probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const int64_t expiring = to_i64(PQgetvalue(probe.get(), 0, 0));
        const int64_t datable = to_i64(PQgetvalue(probe.get(), 0, 1));

        audit_retention::Facts facts{
            .has_expired = expiring > 0,
            .would_wipe = expiring > 0 && expiring >= datable,
            // part 7: absolute threshold, never scaled to the (1 h) TTL.
            .big_step = prev.has_value() && expiring > 0 &&
                        audit_retention::moved_at_least(*prev, now, kGcBigStepSecs) && now > *prev,
            .prev_unusable = prev_unusable,
            // part 6, decided and recorded rather than inherited: this store does
            // NOT adopt #2579's missing-anchor trigger. `audit_store` now declines
            // a first sweep that has no reading while rows are already expired,
            // because what it loses is the SOC 2 evidence trail and it is
            // unrecoverable. Here the same shape loses at most one TTL window
            // (1 h) of scratch result sets, which are regenerable by re-running
            // the query, so a decline would buy an operator nothing and cost a
            // warning on every fresh deployment. Revisit if the TTL ever grows or
            // the data stops being reproducible.
            .no_anchor = false,
        };
        const auto anomaly = audit_retention::classify(facts);
        // FOUR chars, matching the four facts that can VARY here: `no_anchor` is
        // pinned false above, so serialising it would add a constant and change a
        // DURABLE key format for nothing. That is not free -- this key lives in
        // `gc_meta` and is compared, not parsed, so a mixed-version fleet writing
        // 4- and 5-char values alternately would never match its own previous
        // pass, and dedup would stop suppressing a standing anomaly for the whole
        // rollout window. If the `no_anchor` pin above is ever revisited, this
        // string MUST gain a character in the same change (#2579).
        const std::string facts_ser = std::string(facts.has_expired ? "e" : "-") +
                                      (facts.would_wipe ? "w" : "-") +
                                      (facts.big_step ? "s" : "-") +
                                      (facts.prev_unusable ? "u" : "-");
        if (anomaly != audit_retention::Anomaly::None) {
            if (facts_ser != last_facts) {
                // part 4: report + decline ONCE per distinct fact set. The
                // FULL fact set is the dedup key (never a latch bool / the
                // classified enum) — a different anomaly arriving under a
                // reported one must report again, and a repeat of the same
                // one must NOT hold the drain forever: the next pass with
                // equal facts proceeds, paced by the cap, so a legitimately
                // all-expired table still ages out.
                // A NAME, not the enum ordinal: enumerators are inserted over time
                // (#2579 added one mid-enum), so an ordinal silently renames itself
                // across an upgrade while the operator-facing string is unchanged.
                const char* anomaly_name = "unknown";
                switch (anomaly) {
                case audit_retention::Anomaly::None: anomaly_name = "none"; break;
                case audit_retention::Anomaly::NoAnchor: anomaly_name = "no-anchor"; break;
                case audit_retention::Anomaly::Wipe: anomaly_name = "wipe"; break;
                case audit_retention::Anomaly::Step: anomaly_name = "step"; break;
                case audit_retention::Anomaly::BadState: anomaly_name = "bad-state"; break;
                }
                spdlog::warn("ResultSetStore::gc_sweep: retention clock anomaly ({} facts={}) — "
                             "declining this pass; an identical next pass will drain, capped",
                             anomaly_name, facts_ser);
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO result_set_store.gc_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("ResultSetStore::gc_sweep: anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                return true; // decline: no delete this pass
            }
            // Suppressed repeat of the SAME fact set: condition already
            // reported; get on with the drain (capped below).
        } else if (!last_facts.empty()) {
            // Consumed: a clean pass clears the dedup key so the NEXT
            // anomaly reports fresh.
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM result_set_store.gc_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResultSetStore::gc_sweep: anomaly clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (expiring == 0)
            return true; // nothing to drain

        // part 5: cap every accepted pass UNCONDITIONALLY — the detectors
        // above are best-effort, the cap always applies. DELETE ... RETURNING
        // counts what the statement actually removed (the #1033-banning
        // idiom). Cascades to result_set_members via the FK.
        pg::PgResult res = pg::exec_params(
            conn,
            "DELETE FROM result_set_store.result_sets WHERE id IN ("
            "SELECT id FROM result_set_store.result_sets "
            "WHERE pinned = false AND ttl_at < $1::bigint "
            "ORDER BY ttl_at ASC LIMIT $2) RETURNING id",
            std::vector<std::string>{std::to_string(now), std::to_string(kGcSweepCapPerPass)});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::gc_sweep: delete failed: {}", PQerrorMessage(conn));
            return false;
        }
        deleted = PQntuples(res.get());
        return true;
    });
    if (!ok) {
        spdlog::error("ResultSetStore::gc_sweep: pass aborted (statement failed or txn rolled back — see the preceding gc_sweep error line)");
        return 0;
    }
    return deleted;
}

} // namespace yuzu::server
