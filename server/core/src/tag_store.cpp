#include "tag_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "service_scope_policy.hpp" // authz::is_service_tag_key — #3289
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <unordered_set>

namespace yuzu::server {

// ── Tag categories (compile-time fixed) ──────────────────────────────────────

const std::vector<TagCategory>& get_tag_categories() {
    static const std::vector<TagCategory> categories = {
        {"role", "Role", {}},
        {"environment", "Environment", {"Dev", "UAT", "Production"}},
        {"location", "Location", {}},
        {"service", "Service", {}},
    };
    return categories;
}

namespace {

constexpr const char* kStoreName = "tag_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back the scope-DSL `tag:` preload
// (evaluate_scope — including the background policy-evaluator tick), the
// service-scoped confinement read (derive_exec_visible), REST/MCP tag routes
// and the F2a cohort snapshot; writes come from operator/REST/MCP calls and
// the per-Register agent sync. All can wait a little; none may block
// unboundedly on a saturated pool.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};

// Upper bound on one sync_agent_tags batch (governance perf-F1). The proto
// map is unbounded and gRPC's 4 MB default message cap admits ~10^5 entries;
// unbounded K used to mean K+1 sequential statements pinning one shared-pool
// connection for tens of seconds per Register — repeatable, and the pool is
// shared with the dispatch-critical scope preload and RBAC reads. Realistic
// agent self-reports are 5–20 tags; 256 is generous headroom. Over-cap syncs
// are REFUSED whole (caller error, prior tag set retained — deterministic,
// unlike truncating an unordered map) and the Register handler logs it.
constexpr std::size_t kMaxSyncTags = 256;

// agent_id write guard (governance UP-2): libpq's text binds are C strings,
// so an embedded NUL silently TRUNCATES the id at the DB seam while
// AgentRegistry keys the session by the full string — tag rows would land
// under an identity no read path ever matches. Reject at the write seam
// (caller error, never db_error). Length cap matches the REST/gRPC agent_id
// bound used elsewhere (256).
bool valid_agent_id(const std::string& agent_id) {
    return !agent_id.empty() && agent_id.size() <= 256 &&
           agent_id.find('\0') == std::string::npos;
}

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

// Same treatment as CustomPropertiesStore/RbacStore (ADR-0041/0045): scrub
// invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub leaves
// behind — PostgreSQL TEXT can't store NUL and libpq's text-format bind
// C-string-truncates at the first one. Applied to every free-text value
// INCLUDING the backfill path (a bad byte at-rest in a legacy tags.db must
// not brick the MANDATORY backfill). Keys don't need it at runtime
// (validate_key admits ASCII only) but backfilled legacy keys are sanitized
// the same way — they bypassed no validation we can retroactively prove.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (#1675 convention, mirrors CustomPropertiesStore) ──
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
        metrics->counter("yuzu_server_tag_store_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// One sampler per distinct read call site (a shared sampler would let a hot
// get_values_for_keys degrade mask a cold get_compliance_gaps one from ever
// logging).
DegradeSampler g_get_tag_sampler;
DegradeSampler g_all_tags_sampler;
DegradeSampler g_tag_map_sampler;
DegradeSampler g_agents_with_tag_sampler;
DegradeSampler g_values_for_keys_sampler;
DegradeSampler g_values_for_key_sampler;
DegradeSampler g_compliance_sampler;
DegradeSampler g_distinct_values_sampler;
DegradeSampler g_distinct_keys_sampler;

// Unqualified DDL: the runner sets search_path to `tag_store` for the
// migration transaction; runtime statements below schema-qualify explicitly.
// The (key, value) index serves agents_with_tag (key or key+value),
// get_distinct_values, get_values_for_key and the scope-preload
// get_values_for_keys (`key = ANY(...)`); the PK serves every per-agent read.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE tags (
                agent_id    TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT 'server',
                updated_at  BIGINT NOT NULL,
                PRIMARY KEY (agent_id, key)
            );
            CREATE INDEX tags_key_value_idx ON tags (key, value);
        )"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // tag_store_meta's sole purpose was the backfill idempotency marker, which
        // no longer has a writer. Version-bumped (not edited into v1) because v1
        // has actually run against real dev/UAT databases — see ADR-0050's Update.
        {2, "DROP TABLE IF EXISTS tag_store_meta;"},
    };
    return kMigrations;
}

// Shared single-row upsert, running on the caller's connection so
// sync_agent_tags can reuse it inside its own transaction. `value` must
// already be sanitized. Source precedence (#1411): the PK is (agent_id, key)
// with `source` OUTSIDE the key, so a blanket upsert would let an
// 'agent'-sourced write (agent self-reported scopable_tags, re-synced on
// every Register) overwrite an operator/API row for the same (agent_id, key)
// — flipping both value and source and letting a rogue agent self-assign
// into an operator-declared cohort. An agent write may only upsert when the
// existing row is itself agent-sourced (or absent); any non-'agent' source
// (operator/API/MCP) is authoritative and wins unconditionally. When the
// ON CONFLICT WHERE is false the statement returns zero rows with no error —
// a clean precedence no-op, reported as SUCCESS. Semantics verified against
// live Postgres 18 before shipping (header comment).
std::expected<void, std::string> upsert_tag_on(PGconn* c, const std::string& agent_id,
                                               const std::string& key,
                                               const std::string& sanitized_value,
                                               const std::string& source) {
    const bool agent_sourced = (source == "agent");
    const char* sql =
        agent_sourced
            ? "INSERT INTO tag_store.tags (agent_id, key, value, source, updated_at) "
              "VALUES ($1, $2, $3, $4, $5::bigint) "
              "ON CONFLICT (agent_id, key) DO UPDATE SET "
              "  value = EXCLUDED.value, source = EXCLUDED.source, "
              "  updated_at = EXCLUDED.updated_at "
              "WHERE tags.source = 'agent' "
              "RETURNING agent_id"
            : "INSERT INTO tag_store.tags (agent_id, key, value, source, updated_at) "
              "VALUES ($1, $2, $3, $4, $5::bigint) "
              "ON CONFLICT (agent_id, key) DO UPDATE SET "
              "  value = EXCLUDED.value, source = EXCLUDED.source, "
              "  updated_at = EXCLUDED.updated_at "
              "RETURNING agent_id";
    pg::PgResult res = pg::exec_params(
        c, sql,
        std::vector<std::string>{agent_id, key, sanitized_value, source,
                                 std::to_string(now_secs())});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "database write failed");
    if (!agent_sourced && PQntuples(res.get()) != 1)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "database write failed");
    // agent-sourced + zero rows == the #1411 precedence no-op: an
    // operator/API row holds this (agent_id, key) and the agent write is
    // correctly declined. Success.
    return {};
}

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────

TagStore::TagStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("TagStore: no database connection at construction ({}) — tag persistence "
                      "disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("TagStore: schema migration failed — tag persistence disabled");
        return;
    }
    open_ = true;
}

// ── Validation ───────────────────────────────────────────────────────────────
// Pure C++ — unchanged by the substrate migration.

bool TagStore::validate_key(const std::string& key) {
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

bool TagStore::validate_value(const std::string& value) {
    return value.size() <= 448;
}

// ── Writes ───────────────────────────────────────────────────────────────────

std::expected<void, std::string> TagStore::set_tag(const std::string& agent_id,
                                                   const std::string& key,
                                                   const std::string& value,
                                                   const std::string& source) {
    if (!open_)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "store not open");
    if (!valid_agent_id(agent_id))
        return std::unexpected("invalid agent id (1-256 bytes, no NUL)");
    if (!validate_key(key))
        return std::unexpected("invalid tag key (1-64 chars, alphanumeric/._:-)");
    if (!validate_value(value))
        return std::unexpected("tag value exceeds maximum length (448 bytes)");

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "no database connection in time");
    return upsert_tag_on(lease.get(), agent_id, key, sanitize_pg_text(value), source);
}

std::expected<void, std::string> TagStore::set_tag_checked(const std::string& agent_id,
                                                           const std::string& key,
                                                           const std::string& value,
                                                           const std::string& source) {
    if (!validate_key(key))
        return std::unexpected("invalid tag key");
    if (!validate_value(value))
        return std::unexpected("tag value exceeds maximum length");

    // Check if key matches a category with restricted values
    for (const auto& cat : get_tag_categories()) {
        if (cat.key == key && !cat.allowed_values.empty()) {
            bool found = false;
            for (auto av : cat.allowed_values) {
                if (av == value) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                std::string msg = "invalid value for '" + key + "': allowed values are";
                for (size_t i = 0; i < cat.allowed_values.size(); ++i) {
                    if (i > 0)
                        msg += ",";
                    msg += " ";
                    msg += cat.allowed_values[i];
                }
                return std::unexpected(msg);
            }
            break;
        }
    }

    // Propagate the write result (kickoff lesson 3) — the pre-migration
    // contract validated the value but swallowed a failed write.
    return set_tag(agent_id, key, value, source);
}

std::expected<bool, TagReadError> TagStore::delete_tag(const std::string& agent_id,
                                                       const std::string& key) {
    // Guard symmetry with the write seams (Gate 8 round 2 — cpp-expert F1/
    // cons-R1/security). An invalid id is answered as an HONEST NOT-FOUND
    // rather than a caller error: the write guard above means no row can
    // exist under such an identity, and this signature's error channel
    // (TagReadError) deliberately carries only kDegraded. This closes the
    // libpq C-truncation divergence (audit target vs affected row) without
    // a signature change.
    if (!valid_agent_id(agent_id))
        return false;
    if (!open_) {
        spdlog::warn("TagStore::delete_tag: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("TagStore::delete_tag: no connection in time ({})", pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM tag_store.tags WHERE agent_id = $1 AND key = $2 RETURNING agent_id",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("TagStore::delete_tag: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    return PQntuples(res.get()) > 0;
}

std::expected<void, std::string>
TagStore::sync_agent_tags(const std::string& agent_id,
                          const std::unordered_map<std::string, std::string>& tags) {
    if (!open_)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "store not open");
    if (!valid_agent_id(agent_id))
        return std::unexpected("invalid agent id (1-256 bytes, no NUL)");
    if (tags.size() > kMaxSyncTags)
        return std::unexpected("too many agent-reported tags (max " +
                               std::to_string(kMaxSyncTags) +
                               ") - sync refused whole, prior tag set retained");

    // Validate/sanitize OUTSIDE the transaction (no lease held during string
    // work), building the parallel arrays for ONE batched upsert. Malformed
    // entries are skipped, matching the pre-migration contract.
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.reserve(tags.size());
    values.reserve(tags.size());
    for (const auto& [key, value] : tags) {
        if (!validate_key(key) || !validate_value(value))
            continue; // skip malformed entries; not a transaction failure
        // #3289: the `service` tag is a service-scoped token's own
        // confinement boundary (auth_routes.cpp's require_scoped_permission
        // reads it via TagStore::get_tag) — an agent-supplied claim over
        // gRPC Register must never author or move it. Silently dropped, not
        // an error: every other agent-reported key still syncs normally.
        // The DELETE below is NOT similarly filtered, so a pre-existing
        // agent-sourced `service` row (written before this fix) purges on
        // the agent's next sync rather than lingering — self-healing.
        if (authz::is_service_tag_key(key)) {
            spdlog::info("TagStore::sync_agent_tags: dropped agent-reported 'service' tag for "
                        "{} (#3289) — the service tag is operator/API-assigned only",
                        agent_id);
            // Gate 5/6 hardening round: the only prior signal was this log
            // line — no counter, no audit row. A counter is the proportionate
            // in-PR addition (an audit row needs its own audit-sink design,
            // tracked as a follow-up); this at least makes "how often is this
            // firing fleet-wide" answerable without grepping logs.
            if (metrics_)
                metrics_->counter("yuzu_server_tag_store_agent_service_purge_total").increment();
            continue;
        }
        keys.push_back(key);
        values.push_back(sanitize_pg_text(value));
    }

    // Delete all agent-sourced tags, then re-insert — one transaction, and
    // exactly TWO statements regardless of tag count (governance perf-F1:
    // the per-row loop was K+1 sequential round-trips pinning a shared-pool
    // connection per Register). A failed DELETE or batch insert rolls the
    // whole sync back, so the agent keeps its PRIOR complete tag set rather
    // than a partial wipe (governance UP-1 — invariant carried over). The
    // source-precedence guarantee (#1411 — operator rows survive an agent
    // sync) depends on the DELETE targeting source='agent' only and the
    // batch upsert's per-row `WHERE tags.source = 'agent'` — the batched
    // ON CONFLICT applies the WHERE per conflicting row (verified on live
    // Postgres 18: an operator-sourced conflict row is declined while the
    // same statement updates/inserts the agent-sourced rows around it).
    std::string error;
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM tag_store.tags WHERE agent_id = $1 AND source = 'agent'",
            std::vector<std::string>{agent_id});
        if (del.status() != PGRES_COMMAND_OK) {
            error = std::string(kTagDbErrorPrefix) + "database write failed";
            spdlog::warn("TagStore::sync_agent_tags: DELETE failed for {}: {}", agent_id,
                         PQerrorMessage(c));
            return false;
        }
        if (keys.empty())
            return true;
        std::vector<std::string_view> key_views(keys.begin(), keys.end());
        std::vector<std::string_view> value_views(values.begin(), values.end());
        pg::PgResult ins = pg::exec_params(
            c,
            "INSERT INTO tag_store.tags (agent_id, key, value, source, updated_at) "
            "SELECT $1, t.k, t.v, 'agent', $4::bigint "
            "FROM unnest($2::text[], $3::text[]) AS t(k, v) "
            "ON CONFLICT (agent_id, key) DO UPDATE SET "
            "  value = EXCLUDED.value, source = EXCLUDED.source, "
            "  updated_at = EXCLUDED.updated_at "
            "WHERE tags.source = 'agent'",
            std::vector<std::string>{agent_id, pg::to_text_array(key_views),
                                     pg::to_text_array(value_views),
                                     std::to_string(now_secs())});
        if (ins.status() != PGRES_COMMAND_OK) {
            error = std::string(kTagDbErrorPrefix) + "database write failed";
            spdlog::warn("TagStore::sync_agent_tags: batch upsert failed for {} ({} tags): {}",
                         agent_id, keys.size(), PQerrorMessage(c));
            return false; // roll the whole sync back (UP-1)
        }
        return true;
    });
    if (!ok) {
        if (error.empty())
            error = std::string(kTagDbErrorPrefix) + "database error";
        return std::unexpected(error);
    }
    return {};
}

std::expected<void, std::string> TagStore::delete_all_tags(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "store not open");
    if (!valid_agent_id(agent_id))
        return std::unexpected("invalid agent id (1-256 bytes, no NUL)");
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected(std::string(kTagDbErrorPrefix) + "no database connection in time");
    pg::PgResult res =
        pg::exec_params(lease.get(), "DELETE FROM tag_store.tags WHERE agent_id = $1",
                        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("TagStore::delete_all_tags: delete failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(std::string(kTagDbErrorPrefix) + "database write failed");
    }
    return {};
}

// ── Reads ────────────────────────────────────────────────────────────────────

std::expected<std::optional<std::string>, TagReadError>
TagStore::get_tag(const std::string& agent_id, const std::string& key) const {
    // Invalid id (empty/oversized/embedded NUL) — honest not-found: the
    // write-seam guard means no row can exist under it, and answering
    // through the bind would read a TRUNCATED identity's row instead
    // (Gate 8 round 2, guard symmetry).
    if (!valid_agent_id(agent_id))
        return std::optional<std::string>{std::nullopt};
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_get_tag_sampler))
            spdlog::warn("TagStore::get_tag: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_get_tag_sampler))
            spdlog::warn("TagStore::get_tag: no connection in time ({})", pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT value FROM tag_store.tags WHERE agent_id = $1 AND key = $2",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_tag_sampler))
            spdlog::warn("TagStore::get_tag: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{std::nullopt};
    return std::optional<std::string>{text_col(res.get(), 0, 0)};
}

std::expected<std::vector<DeviceTag>, TagReadError>
TagStore::get_all_tags(const std::string& agent_id) const {
    if (!valid_agent_id(agent_id))
        return std::vector<DeviceTag>{}; // guard symmetry — see get_tag
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_all_tags_sampler))
            spdlog::warn("TagStore::get_all_tags: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_all_tags_sampler))
            spdlog::warn("TagStore::get_all_tags: no connection in time ({})", pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value, source, updated_at FROM tag_store.tags WHERE agent_id = $1 "
        "ORDER BY key",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_all_tags_sampler))
            spdlog::warn("TagStore::get_all_tags: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<DeviceTag> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DeviceTag t;
        t.agent_id = agent_id;
        t.key = text_col(res.get(), i, 0);
        t.value = text_col(res.get(), i, 1);
        t.source = text_col(res.get(), i, 2);
        t.updated_at = to_i64(PQgetvalue(res.get(), i, 3));
        results.push_back(std::move(t));
    }
    return results;
}

std::expected<std::unordered_map<std::string, std::string>, TagReadError>
TagStore::get_tag_map(const std::string& agent_id) const {
    if (!valid_agent_id(agent_id))
        return std::unordered_map<std::string, std::string>{}; // guard symmetry — see get_tag
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_tag_map_sampler))
            spdlog::warn("TagStore::get_tag_map: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_tag_map_sampler))
            spdlog::warn("TagStore::get_tag_map: no connection in time ({})", pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT key, value FROM tag_store.tags WHERE agent_id = $1",
                        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_tag_map_sampler))
            spdlog::warn("TagStore::get_tag_map: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::unordered_map<std::string, std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return result;
}

std::expected<std::vector<std::string>, TagReadError>
TagStore::agents_with_tag(const std::string& key, const std::string& value) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_agents_with_tag_sampler))
            spdlog::warn("TagStore::agents_with_tag: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_agents_with_tag_sampler))
            spdlog::warn("TagStore::agents_with_tag: no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res =
        value.empty()
            ? pg::exec_params(lease.get(),
                              "SELECT DISTINCT agent_id FROM tag_store.tags WHERE key = $1",
                              std::vector<std::string>{key})
            : pg::exec_params(
                  lease.get(),
                  "SELECT DISTINCT agent_id FROM tag_store.tags WHERE key = $1 AND value = $2",
                  std::vector<std::string>{key, value});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_agents_with_tag_sampler))
            spdlog::warn("TagStore::agents_with_tag: query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(text_col(res.get(), i, 0));
    return result;
}

std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
              TagReadError>
TagStore::get_values_for_keys(const std::vector<std::string>& keys) const {
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> result;
    if (keys.empty())
        return result;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_values_for_keys_sampler))
            spdlog::warn("TagStore::get_values_for_keys: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_values_for_keys_sampler))
            spdlog::warn("TagStore::get_values_for_keys: no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<std::string_view> key_views(keys.begin(), keys.end());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, key, value FROM tag_store.tags WHERE key = ANY($1::text[])",
        std::vector<std::string>{pg::to_text_array(key_views)});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_values_for_keys_sampler))
            spdlog::warn("TagStore::get_values_for_keys: query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        result[text_col(res.get(), i, 0)].emplace(text_col(res.get(), i, 1),
                                                  text_col(res.get(), i, 2));
    }
    return result;
}

std::expected<std::vector<std::pair<std::string, std::vector<std::string>>>, TagReadError>
TagStore::get_compliance_gaps() const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_compliance_sampler))
            spdlog::warn("TagStore::get_compliance_gaps: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_compliance_sampler))
            spdlog::warn("TagStore::get_compliance_gaps: no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    // Two queries on ONE lease (a lease may span successive queries; it may
    // not span external work — ADR-0012 §2). Bulk shape: the pre-migration
    // impl looped get_tag per agent × per category (N×4 point lookups) —
    // tolerable against local SQLite, an NFR anti-pattern against a network
    // substrate. Semantics preserved: only agents with ≥1 tag row are
    // evaluated; a category is missing when no row exists OR its value is
    // empty ('' — validate_value admits empty values).
    pg::PgResult all_agents = pg::exec_params(
        lease.get(), "SELECT DISTINCT agent_id FROM tag_store.tags ORDER BY agent_id",
        std::vector<std::string>{});
    if (all_agents.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_compliance_sampler))
            spdlog::warn("TagStore::get_compliance_gaps: agent query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<std::string_view> cat_views(std::begin(kCategoryKeys), std::end(kCategoryKeys));
    pg::PgResult present = pg::exec_params(
        lease.get(),
        "SELECT agent_id, key FROM tag_store.tags WHERE key = ANY($1::text[]) AND value <> ''",
        std::vector<std::string>{pg::to_text_array(cat_views)});
    if (present.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_compliance_sampler))
            spdlog::warn("TagStore::get_compliance_gaps: category query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> present_keys;
    for (int i = 0; i < PQntuples(present.get()); ++i)
        present_keys[text_col(present.get(), i, 0)].insert(text_col(present.get(), i, 1));

    std::vector<std::pair<std::string, std::vector<std::string>>> result;
    for (int i = 0; i < PQntuples(all_agents.get()); ++i) {
        std::string agent_id = text_col(all_agents.get(), i, 0);
        std::vector<std::string> missing;
        const auto it = present_keys.find(agent_id);
        for (auto cat_key : kCategoryKeys) {
            if (it == present_keys.end() || !it->second.contains(std::string(cat_key)))
                missing.emplace_back(cat_key);
        }
        if (!missing.empty())
            result.emplace_back(std::move(agent_id), std::move(missing));
    }
    return result;
}

std::expected<std::vector<std::string>, TagReadError>
TagStore::get_distinct_values(const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_distinct_values_sampler))
            spdlog::warn("TagStore::get_distinct_values: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_distinct_values_sampler))
            spdlog::warn("TagStore::get_distinct_values: no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT value FROM tag_store.tags WHERE key = $1 ORDER BY value",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_distinct_values_sampler))
            spdlog::warn("TagStore::get_distinct_values: query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(text_col(res.get(), i, 0));
    return result;
}

std::expected<std::vector<std::string>, TagReadError> TagStore::get_distinct_keys() const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_distinct_keys_sampler))
            spdlog::warn("TagStore::get_distinct_keys: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_distinct_keys_sampler))
            spdlog::warn("TagStore::get_distinct_keys: no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT DISTINCT key FROM tag_store.tags ORDER BY key",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_distinct_keys_sampler))
            spdlog::warn("TagStore::get_distinct_keys: query failed: {}",
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::vector<std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(text_col(res.get(), i, 0));
    return result;
}

std::expected<std::unordered_map<std::string, std::string>, TagReadError>
TagStore::get_values_for_key(const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_values_for_key_sampler))
            spdlog::warn("TagStore::get_values_for_key: store not open");
        return std::unexpected(TagReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_values_for_key_sampler))
            spdlog::warn("TagStore::get_values_for_key('{}'): no connection in time ({})", key,
                         pool_.last_error());
        return std::unexpected(TagReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT agent_id, value FROM tag_store.tags WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_values_for_key_sampler))
            spdlog::warn("TagStore::get_values_for_key('{}'): query failed: {}", key,
                         PQerrorMessage(lease.get()));
        return std::unexpected(TagReadError::kDegraded);
    }
    std::unordered_map<std::string, std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return result;
}

} // namespace yuzu::server
