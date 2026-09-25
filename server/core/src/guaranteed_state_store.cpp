#include "guaranteed_state_store.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include <yuzu/log_token.hpp> // log_id_token
#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp> // shared canon_version — re-canon agent input at the boundary

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <functional>
#include <limits>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "guaranteed_state_store";

// Bounded acquires (ADR-0012 §2(a)). Rule/meta reads+writes are the
// catastrophic-read/fail-hard set — they back interactive REST callers and
// the Push fan-out, so they get a longer budget than ingest. Event/status
// ingest runs on the gRPC thread and must give up fast (fail-soft — the
// agent's next report re-sends). DEX/analytics reads mirror InventoryStore's
// query budget.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kIngestTimeout{500};
constexpr std::chrono::milliseconds kDexReadTimeout{3000};

// Read-degrade / ingest-drop reason labels (ADR-0037 label convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// JC-8 (coordinator review): label parity with InventoryStore's
// yuzu_inventory_read_degrade_total{reason, source} family — a constant
// "source" so a future second Guardian-adjacent read-degrade emitter stays
// distinguishable on the same dashboards without a metric rename. Two
// sources exist today (#4856): "guardian_state" for the DEX/observation
// family (dex_read<>/dex_observation, fail-soft — an empty/degraded result
// is returned to the caller) and "guardian_rules" for the AUTHORITATIVE
// rule/status reads (get_rule/list_rules/agent_rule_statuses*/rule_names*/
// errored_rule_count, fail-hard — a std::expected error is returned and the
// caller decides how to fail). Both bump the SAME counter,
// yuzu_server_guardian_read_degrade_total{reason,source}, so an alert can
// aggregate `by (reason, source)` without missing either family.
constexpr const char* kDegradeSource = "guardian_state";
constexpr const char* kDegradeSourceRules = "guardian_rules";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the
// log — the counter is the continuous signal, the log a sampled breadcrumb.
// Mirrors InventoryStore's constants.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Clock-guarded retention (routed-concern invariant; #2496 gc_sweep shape,
// ADR-0038). Substrate-tuned: this store's write volume is documented at up
// to ~10k events/s during a fleet-wide incident (kDefaultEventRetentionDays
// doc comment), an order of magnitude above ResultSetStore's operator-scratch
// workload, so the per-pass cap is raised accordingly (5000 -> 10000).
// kReapBigStepSecs (part 7, "did the clock move forward abnormally between
// passes") stays the reference's absolute ~1-day value — it detects a wall-
// clock jump between two passes and is deliberately unscaled to any TTL.
//
// The probe's datable horizon (part 1, "exclude forward-skewed rows from the
// datable denominator") is DIFFERENT: unlike kReapBigStepSecs it MUST exceed
// the legitimate TTL horizon, or a live row's own honest ttl_expires_at gets
// misclassified as "implausibly ahead" and wrongly excluded from `datable` —
// which flips a normal partial-expiry pass into a false would_wipe decline.
// A FIXED bound cannot satisfy that for every accepted configuration:
// `--guardian-event-retention-days`/`PUT .../guardian_event_retention_days`
// have no enforced maximum (only non-negative, main.cpp/server.cpp), so any
// fixed constant is falsifiable by a large-enough operator-chosen retention
// window — caught in review (#2663) as a false-decline gap under a real
// long-retention (e.g. multi-year SOC 2) configuration. Derive the horizon
// from the CONFIGURED window instead, same shape as `audit_store.cpp`'s
// `datable_horizon = pg_now + window + kAuditTtlFutureSlackSec`: it then
// always covers every row this store's own `compute_ttl_epoch()` could have
// stamped, for any retention_days_, by construction — no fixed guess to
// falsify. kReapTtlFutureSlackSec is this store's OWN constant (substrate-
// tuned per the routed-concern's "copy the shape, never the numbers" rule),
// not a reuse of AuditStore's identically-valued one.
constexpr int64_t kReapCapPerPass = 10'000;
constexpr int64_t kReapBigStepSecs = 86'400;        // part 7: absolute, ~1 day
constexpr int64_t kReapTtlFutureSlackSec = 2 * 86'400; // clock-imprecision buffer past the window

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }
double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    double v = 0.0;
    const auto len = std::strlen(s);
    auto [ptr, ec] = std::from_chars(s, s + len, v);
    (void)ptr;
    return ec == std::errc() ? v : 0.0;
#else
    // Apple Clang / libc++ ships no floating-point std::from_chars, so the
    // call above resolves to the deleted `bool` overload and fails to
    // compile. Same feature-test guard as cel_eval.cpp's try_parse_double;
    // strtod (not stod) to match to_i64's strtoll above and stay
    // exception-free. Both branches yield 0.0 on a parse miss.
    char* end = nullptr;
    const double v = std::strtod(s, &end);
    return end == s ? 0.0 : v;
#endif
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// Byte<->hex for the `signature` BYTEA column. Mirrors the codebase's
// existing BYTEA convention (auth_db.cpp: `encode(col,'hex')` /
// `decode($n,'hex')`, chosen deliberately over relying on the session's
// `bytea_output` GUC) — no generic hex helper exists outside the auth
// module, and signature is not a secret (it's an HMAC we already store), so
// a small local pair avoids taking a dependency on auth::AuthManager.
std::string bytes_to_hex(const std::vector<uint8_t>& b) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t byte : b) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break; // malformed — server-authored hex only, defensive stop
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

// Map a Guardian event_type to the compliance state it implies for the per-(agent,
// rule) status table, or nullptr if the event carries no compliance signal (e.g.
// guard.armed is a lifecycle marker, not a verdict). guard.compliant (Slice B) and a
// successful drift.remediated both mean the watched state is now at expected.
const char* event_state_from_type(const std::string& t) {
    if (t == "guard.compliant" || t == "drift.remediated")
        return "compliant";
    if (t == "drift.detected")
        return "drifted";
    // Slice-B collapse (deliberate): guardian-mvp-contract.md §4/decision-5 lists
    // `remediation_failed` as a state DISTINCT from `errored`, but the Slice-B census
    // exposes only compliant/drifted/errored and both render red in the worst-of badge.
    if (t == "remediation.failed" || t == "guard.unhealthy")
        return "errored";
    return nullptr; // guard.armed, resilience.escalated, … — no census change
}

// The reserved ruleless-observation sentinel (DEX crash recorder) is NEVER a rule-bound
// compliance verdict — it has no live rule. Enforce that server-side so a (mis)behaving
// agent that pairs the sentinel with a compliance event_type (e.g. drift.detected)
// cannot mint a phantom per-(agent,rule) census row keyed to the reserved id.
bool is_reserved_rule_id(const std::string& rule_id) { return rule_id == kObservationRuleId; }

// ── Read-degrade / ingest-drop observability ─────────────────────────────────
// Mirrors InventoryStore's DegradeSampler shape exactly (docs/postgres-store-
// playbook.md). One static sampler per DEX/analytics call site (declared
// `static DegradeSampler sampler;` inside each method) gates the sampled warn
// log; the Prometheus counter always increments.
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             const char* source, DegradeSampler& s) {
    if (metrics)
        metrics
            ->counter("yuzu_server_guardian_read_degrade_total",
                      {{"reason", reason}, {"source", source}})
            .increment();
    const std::int64_t now = now_epoch();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

// Increment the persisted policy generation via one atomic UPDATE ...
// RETURNING (no read-modify-write — the SQLite idiom does not port to
// cross-process Postgres state). Best-effort: logs on failure, matching the
// original SQLite contract (callers do not consume a result). No
// sqlite3_changes()-style race (#1033): the RETURNING result is read on the
// exclusively-owned lease connection.
void bump_policy_generation_on(PGconn* conn) {
    pg::PgResult r = pg::exec_params(
        conn,
        "UPDATE guaranteed_state_store.guardian_meta SET value = value + 1 "
        "WHERE key = 'policy_generation' RETURNING value",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        spdlog::warn("GuaranteedStateStore: policy_generation bump failed: {}",
                     PQerrorMessage(conn));
}

// Shared body for every DEX/analytics read (ADR-0038 "deferred widening",
// follow-up #2659): acquire a bounded lease, run `body(conn)` (which executes
// the query and returns the parsed result, or nullopt on a query-level
// failure), and count+sampled-log a degrade on store-not-open / pool-timeout
// / query-error via yuzu_server_guardian_read_degrade_total{reason}. A successful
// EMPTY container is NOT a degrade — only body() returning nullopt is.
//
// `dex_read_checked` is the TYPE-DISTINGUISHABLE twin (#4855): it returns
// `std::nullopt` on a degrade instead of collapsing it into an empty
// container, so a caller that NEEDS to tell "degraded" apart from "genuinely
// no data" (the DEX device-score read — a degrade must never render as a
// perfectly healthy score) can. It still bumps
// `yuzu_server_guardian_read_degrade_total{reason}` via the same
// `note_read_degrade` on every degrade path. `dex_read` itself is now a thin
// `.value_or(Result{})` wrapper over it, so the ~26 other DEX/analytics call
// sites (#2659's still-deferred widening) stay behaviour-identical
// (empty-on-degrade) — this widens ONLY the device-score read, not the
// whole family.
template <typename Result, typename Body>
std::optional<Result> dex_read_checked(bool open, pg::PgPool& pool, yuzu::MetricsRegistry* metrics,
                                       const char* method, DegradeSampler& sampler, Body&& body) {
    if (!open) {
        if (const auto d = note_read_degrade(metrics, kReasonStoreNotOpen, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: store not open", method);
        return std::nullopt;
    }
    auto lease = pool.try_acquire_for(kDexReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics, kReasonPoolTimeout, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: pool acquire timed out", method);
        return std::nullopt;
    }
    auto result = body(lease.get());
    if (!result) {
        if (const auto d = note_read_degrade(metrics, kReasonQueryError, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: query failed", method);
        return std::nullopt;
    }
    return std::move(*result);
}

template <typename Result, typename Body>
Result dex_read(bool open, pg::PgPool& pool, yuzu::MetricsRegistry* metrics, const char* method,
                DegradeSampler& sampler, Body&& body) {
    return dex_read_checked<Result>(open, pool, metrics, method, sampler,
                                    std::forward<Body>(body))
        .value_or(Result{});
}

// ── Postgres schema (ADR-0038): the FINAL column set of all 8 SQLite
// migrations, collapsed into one v1. Unqualified DDL — the migration runner
// sets search_path to `guaranteed_state_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly. No enum CHECK
// constraints exist in the legacy SQLite DDL to preserve (the H2/G9
// cross-check tests bind `guardian_rule_spec.cpp` param specs to agent-side
// arrays — a C++-level contract, not a SQL CHECK clause — so this migration
// carries none forward; verified by reading the legacy schema).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE guaranteed_state_rules (
                rule_id          TEXT PRIMARY KEY,
                name             TEXT NOT NULL UNIQUE,
                yaml_source      TEXT NOT NULL,
                version          BIGINT NOT NULL DEFAULT 1,
                enabled          BOOLEAN NOT NULL DEFAULT TRUE,
                enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
                severity         TEXT NOT NULL DEFAULT 'medium',
                os_target        TEXT NOT NULL DEFAULT '',
                scope_expr       TEXT NOT NULL DEFAULT '',
                signature        BYTEA,
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL,
                created_by       TEXT NOT NULL DEFAULT '',
                updated_by       TEXT NOT NULL DEFAULT '',
                spec_json        TEXT NOT NULL DEFAULT '',
                prerequisites    TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gsr_os ON guaranteed_state_rules(os_target);

            CREATE TABLE guaranteed_state_events (
                event_id               TEXT PRIMARY KEY,
                rule_id                TEXT NOT NULL,
                agent_id                TEXT NOT NULL,
                event_type              TEXT NOT NULL,
                severity                 TEXT NOT NULL,
                guard_type               TEXT NOT NULL DEFAULT '',
                guard_category            TEXT NOT NULL DEFAULT '',
                detected_value            TEXT NOT NULL DEFAULT '',
                expected_value            TEXT NOT NULL DEFAULT '',
                remediation_action        TEXT NOT NULL DEFAULT '',
                remediation_success       BOOLEAN,
                detection_latency_us      BIGINT NOT NULL DEFAULT 0,
                remediation_latency_us    BIGINT NOT NULL DEFAULT 0,
                timestamp                 TEXT NOT NULL,
                ttl_expires_at             BIGINT NOT NULL DEFAULT 0,
                detail_json                TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gse_rule_time ON guaranteed_state_events(rule_id, timestamp DESC);
            CREATE INDEX idx_gse_agent_time ON guaranteed_state_events(agent_id, timestamp DESC);
            CREATE INDEX idx_gse_severity_time ON guaranteed_state_events(severity, timestamp DESC);
            CREATE INDEX idx_gse_time ON guaranteed_state_events(timestamp DESC);
            CREATE INDEX idx_gse_ttl ON guaranteed_state_events(ttl_expires_at) WHERE ttl_expires_at > 0;

            CREATE TABLE guardian_meta (
                key   TEXT PRIMARY KEY,
                value BIGINT NOT NULL
            );
            INSERT INTO guardian_meta(key, value) VALUES ('policy_generation', 0)
                ON CONFLICT (key) DO NOTHING;

            CREATE TABLE guardian_agent_rule_status (
                agent_id   TEXT NOT NULL,
                rule_id    TEXT NOT NULL,
                state      TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, rule_id)
            );
            CREATE INDEX idx_gars_rule ON guardian_agent_rule_status(rule_id);

            CREATE TABLE guardian_observations (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                observed_at     TEXT NOT NULL,
                obs_type        TEXT NOT NULL,
                subject         TEXT NOT NULL DEFAULT '',
                reason          TEXT NOT NULL DEFAULT '',
                symbolic        TEXT NOT NULL DEFAULT '',
                component       TEXT NOT NULL DEFAULT '',
                metric          DOUBLE PRECISION NOT NULL DEFAULT 0,
                platform        TEXT NOT NULL DEFAULT '',
                ttl_expires_at  BIGINT NOT NULL DEFAULT 0,
                version         TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gobs_subject ON guardian_observations(subject);
            CREATE INDEX idx_gobs_type_time
                ON guardian_observations(obs_type, observed_at DESC, agent_id, subject);
            CREATE INDEX idx_gobs_agent_time ON guardian_observations(agent_id, observed_at DESC);
            CREATE INDEX idx_gobs_time ON guardian_observations(observed_at DESC);
            CREATE INDEX idx_gobs_ttl ON guardian_observations(ttl_expires_at) WHERE ttl_expires_at > 0;

            -- Durable state for the reap_expired() clock-guard (#2496 shape).
            -- SHARED rows (not process-local) — N server replicas each run the
            -- sweep, so the persisted reading + anomaly-dedup fact set must be
            -- one shared truth under the sweep's advisory lock.
            CREATE TABLE gc_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // sqlite_backfill's sole purpose was the backfill idempotency marker, which
        // no longer has a writer. Version-bumped (not edited into v1) because v1
        // has actually run against real dev/UAT databases — see ADR-0038's Update.
        {2, "DROP TABLE IF EXISTS sqlite_backfill;"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

GuaranteedStateStore::GuaranteedStateStore(pg::PgPool& pool, int retention_days,
                                           std::function<int64_t()> now_fn)
    : pool_(pool), retention_days_(retention_days), now_fn_(std::move(now_fn)) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("GuaranteedStateStore: no database connection at construction ({}) — "
                      "Guardian persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("GuaranteedStateStore: schema migration failed — Guardian persistence "
                      "disabled");
        return;
    }
    open_ = true;
    spdlog::info("GuaranteedStateStore initialized (schema {}, retention={}d)", kStoreName,
                 retention_days_);
}

int64_t GuaranteedStateStore::compute_ttl_epoch() const {
    if (retention_days_ <= 0)
        return 0; // sentinel: never expire
    return now_epoch() + static_cast<int64_t>(retention_days_) * 86400;
}

// ── Rule CRUD (fail-hard) ─────────────────────────────────────────────────────

std::expected<void, std::string>
GuaranteedStateStore::create_rule(const GuaranteedStateRuleRow& row) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guaranteed_state_rules "
        "(rule_id, name, yaml_source, version, enabled, enforcement_mode, severity, os_target, "
        " scope_expr, signature, created_at, updated_at, created_by, updated_by, spec_json, "
        " prerequisites) "
        "VALUES ($1,$2,$3,$4::bigint,$5::boolean,$6,$7,$8,$9,decode($10,'hex'),$11,$12,$13,$14,"
        "$15,$16)",
        std::vector<std::optional<std::string>>{
            row.rule_id, row.name, row.yaml_source, std::to_string(row.version),
            std::string(row.enabled ? "true" : "false"), row.enforcement_mode, row.severity,
            row.os_target, row.scope_expr,
            row.signature.empty() ? std::nullopt
                                  : std::optional<std::string>(bytes_to_hex(row.signature)),
            row.created_at, row.updated_at, row.created_by, row.updated_by, row.spec_json,
            row.prerequisites});
    if (res.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        const std::string err = PQresultErrorMessage(res.get());
        if (sqlstate == "23505") {
            const char* constraint_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            const bool name_collision = constraint.find("_name_key") != std::string::npos;
            const std::string what = name_collision
                                         ? ("rule name '" + row.name + "' already exists")
                                         : ("rule_id '" + row.rule_id + "' already exists");
            return std::unexpected(format_conflict(what));
        }
        return std::unexpected("insert failed: " + err);
    }
    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

std::expected<void, std::string>
GuaranteedStateStore::update_rule(const GuaranteedStateRuleRow& row) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE guaranteed_state_store.guaranteed_state_rules SET "
        "name = $1, yaml_source = $2, version = $3::bigint, enabled = $4::boolean, "
        "enforcement_mode = $5, severity = $6, os_target = $7, scope_expr = $8, "
        "signature = decode($9,'hex'), updated_at = $10, updated_by = $11, spec_json = $12, "
        "prerequisites = $13 WHERE rule_id = $14 RETURNING rule_id",
        std::vector<std::optional<std::string>>{
            row.name, row.yaml_source, std::to_string(row.version),
            std::string(row.enabled ? "true" : "false"), row.enforcement_mode, row.severity,
            row.os_target, row.scope_expr,
            row.signature.empty() ? std::nullopt
                                  : std::optional<std::string>(bytes_to_hex(row.signature)),
            row.updated_at, row.updated_by, row.spec_json, row.prerequisites, row.rule_id});
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505")
            return std::unexpected(format_conflict("rule name '" + row.name + "' already exists"));
        return std::unexpected("update failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: rule_id '" + row.rule_id + "'");
    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

std::expected<void, std::string> GuaranteedStateStore::delete_rule(const std::string& rule_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "DELETE FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id = $1 "
        "RETURNING rule_id",
        std::vector<std::string>{rule_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(res.get())));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: rule_id '" + rule_id + "'");

    // Drop the rule's CURRENT compliance states — unlike the event log (an
    // immutable audit stream kept past rule deletion), this table holds live
    // state. Best-effort, matching the original (no changes-count check).
    pg::PgResult del_status = pg::exec_params(
        conn, "DELETE FROM guaranteed_state_store.guardian_agent_rule_status WHERE rule_id = $1",
        std::vector<std::string>{rule_id});
    if (del_status.status() != PGRES_COMMAND_OK)
        spdlog::warn("GuaranteedStateStore::delete_rule: status cleanup for rule_id={} failed: {}",
                     log_id_token(rule_id), PQerrorMessage(conn));

    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

void GuaranteedStateStore::bump_policy_generation() {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GuaranteedStateStore::bump_policy_generation: no database connection: {}",
                     pool_.last_error());
        return;
    }
    bump_policy_generation_on(lease.get());
}

std::optional<uint64_t> GuaranteedStateStore::current_policy_generation() const {
    // Type-distinguishable (governance Gate 2 LOW1, ADR-0038): a degraded read
    // returns std::nullopt, NEVER 0. Collapsing degrade to 0 silently
    // suppressed the heartbeat reconcile (every `agent_gen >= 0` is true, so a
    // transient meta-read blip disabled reconcile fleet-wide) and stamped a
    // push with a wrong generation → re-push churn. Both consumers (push /
    // reconcile) treat nullopt as "abort this pass", the same posture list_rules
    // uses. The seeded row means a healthy store always has a value; nullopt is
    // strictly the not-open / lease-timeout / query-error path.
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value FROM guaranteed_state_store.guardian_meta WHERE key = 'policy_generation'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return static_cast<uint64_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

namespace {
constexpr const char* kRuleCols =
    "rule_id, name, yaml_source, version, enabled, enforcement_mode, severity, os_target, "
    "scope_expr, encode(signature,'hex'), created_at, updated_at, created_by, updated_by, "
    "spec_json, prerequisites";

GuaranteedStateRuleRow read_rule_row(PGresult* res, int i) {
    GuaranteedStateRuleRow r;
    int c = 0;
    r.rule_id = text_col(res, i, c++);
    r.name = text_col(res, i, c++);
    r.yaml_source = text_col(res, i, c++);
    r.version = to_i64(PQgetvalue(res, i, c++));
    r.enabled = to_bool(PQgetvalue(res, i, c++));
    r.enforcement_mode = text_col(res, i, c++);
    r.severity = text_col(res, i, c++);
    r.os_target = text_col(res, i, c++);
    r.scope_expr = text_col(res, i, c++);
    r.signature = hex_to_bytes(text_col(res, i, c++));
    r.created_at = text_col(res, i, c++);
    r.updated_at = text_col(res, i, c++);
    r.created_by = text_col(res, i, c++);
    r.updated_by = text_col(res, i, c++);
    r.spec_json = text_col(res, i, c++);
    r.prerequisites = text_col(res, i, c++);
    return r;
}
} // namespace

std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError>
GuaranteedStateStore::get_rule(const std::string& rule_id) const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::get_rule: store not open");
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::get_rule: pool acquire timed out");
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    }
    const std::string sql = std::string("SELECT ") + kRuleCols +
                            " FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id "
                            "= $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{rule_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::get_rule: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<GuaranteedStateRuleRow>{std::nullopt};
    return std::optional<GuaranteedStateRuleRow>{read_rule_row(res.get(), 0)};
}

std::expected<std::vector<GuaranteedStateRuleRow>, std::string>
GuaranteedStateStore::list_rules() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::list_rules: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::list_rules: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    const std::string sql = std::string("SELECT ") + kRuleCols +
                            " FROM guaranteed_state_store.guaranteed_state_rules ORDER BY name";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::list_rules: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    std::vector<GuaranteedStateRuleRow> rows;
    const int n = PQntuples(res.get());
    rows.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        rows.push_back(read_rule_row(res.get(), i));
    return rows;
}

// ── Event ingest (fail-soft) ─────────────────────────────────────────────────

namespace {

// Compare the persisted row against `in` across every immutable agent-supplied
// field. EXCLUDED: severity (server-enriched — can legitimately differ across
// a redelivery if the rule's severity changed) and ttl_expires_at
// (receipt-derived). event_id is the PK (equal by definition).
//
// Postgres column typing is STATIC (declared in DDL) — unlike SQLite's
// dynamic per-value storage classes, a TEXT column can never spontaneously
// hold an INTEGER storage class, so the original's defensive
// sqlite3_column_type() check has no Postgres analogue and is dropped;
// straightforward std::string equality on PQgetvalue suffices (the
// embedded-NUL reject at the ingest boundary already rules out a truncated
// exact-match false positive).
//
// Returns: true = idempotent redelivery, false = genuine field mismatch,
// unexpected = the compare itself could NOT be performed (an OPERATIONAL
// error) — mapped to Error by the caller, never a false collision.
std::expected<bool, std::string> stored_event_matches(PGconn* conn,
                                                       const GuaranteedStateEventRow& in) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT rule_id, agent_id, event_type, guard_type, guard_category, detected_value, "
        "expected_value, remediation_action, remediation_success, detection_latency_us, "
        "remediation_latency_us, timestamp, detail_json "
        "FROM guaranteed_state_store.guaranteed_state_events WHERE event_id = $1",
        std::vector<std::string>{in.event_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("compare query failed: ") +
                               PQresultErrorMessage(res.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("conflicting row not found for compare (raced reaper?)");
    const bool match =
        text_col(res.get(), 0, 0) == in.rule_id && text_col(res.get(), 0, 1) == in.agent_id &&
        text_col(res.get(), 0, 2) == in.event_type && text_col(res.get(), 0, 3) == in.guard_type &&
        text_col(res.get(), 0, 4) == in.guard_category &&
        text_col(res.get(), 0, 5) == in.detected_value &&
        text_col(res.get(), 0, 6) == in.expected_value &&
        text_col(res.get(), 0, 7) == in.remediation_action &&
        to_bool(PQgetvalue(res.get(), 0, 8)) == in.remediation_success &&
        to_i64(PQgetvalue(res.get(), 0, 9)) == in.detection_latency_us &&
        to_i64(PQgetvalue(res.get(), 0, 10)) == in.remediation_latency_us &&
        text_col(res.get(), 0, 11) == in.timestamp && text_col(res.get(), 0, 12) == in.detail_json;
    return match;
}

// Project one ruleless DEX observation into guardian_observations. Caller
// MUST run this inside its own SAVEPOINT (a projection failure must degrade,
// not abort the enclosing event-insert transaction — Postgres aborts on ANY
// failed statement, unlike SQLite). `detail_json` is parsed defensively:
// malformed -> empty crash fields, never drops the observation. `ttl` is the
// parent event's expiry so the reaper sweeps both in lockstep.
std::expected<void, std::string> project_observation(PGconn* conn,
                                                      const GuaranteedStateEventRow& row,
                                                      int64_t ttl) {
    nlohmann::json j = nlohmann::json::parse(row.detail_json, nullptr, /*allow_exceptions=*/false);
    constexpr std::size_t kProjFieldMax = 256;
    const auto field = [&](const char* k) -> std::string {
        if (j.is_object())
            if (auto it = j.find(k); it != j.end() && it->is_string()) {
                std::string v = it->get<std::string>();
                if (v.size() > kProjFieldMax) {
                    v.resize(kProjFieldMax);
                    while (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0x80)
                        v.pop_back();
                    if (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0xC0)
                        v.pop_back();
                }
                return v;
            }
        return {};
    };
    std::string subject = field("subject");
    if (subject.empty())
        subject = field("process");
    std::string reason = field("reason");
    if (reason.empty())
        reason = field("exception_code");
    const std::string symbolic = field("symbolic");
    std::string component = field("component");
    if (component.empty())
        component = field("faulting_module");
    std::string platform = field("platform");
    for (auto& c : platform)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (platform.starts_with("win"))
        platform = "windows";
    else if (platform.starts_with("lin"))
        platform = "linux";
    else if (platform.starts_with("darwin") || platform.starts_with("macos"))
        platform = "macos";
    const std::string version = yuzu::util::canon_version(field("version"));
    double metric = 0.0;
    if (j.is_object())
        if (auto it = j.find("metric"); it != j.end() && it->is_number()) {
            const double v = it->get<double>();
            if (v > 0.0 && v < 1.0e12)
                metric = v;
        }

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guardian_observations "
        "(event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, component, "
        "metric, platform, version, ttl_expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::double precision,$10,$11,$12::bigint)",
        std::vector<std::string>{row.event_id, row.agent_id, row.timestamp, row.event_type,
                                 subject, reason, symbolic, component, std::to_string(metric),
                                 platform, version, std::to_string(ttl)});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("insert(observation) failed: ") +
                               PQresultErrorMessage(res.get()));
    return {};
}

// Upsert one (agent, rule) compliance state. Best-effort — logs on a genuine
// SQL error; the ON CONFLICT ... WHERE guard makes a stale-event no-op a
// normal zero-rows-affected outcome, not an error.
void upsert_rule_status(PGconn* conn, const std::string& agent_id, const std::string& rule_id,
                        const char* state, const std::string& updated_at) {
    if (agent_id.empty() || rule_id.empty())
        return;
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guardian_agent_rule_status "
        "(agent_id, rule_id, state, updated_at) VALUES ($1,$2,$3,$4) "
        "ON CONFLICT (agent_id, rule_id) DO UPDATE SET state = EXCLUDED.state, "
        "updated_at = EXCLUDED.updated_at "
        "WHERE EXCLUDED.updated_at >= guardian_agent_rule_status.updated_at",
        std::vector<std::string>{agent_id, rule_id, std::string(state), updated_at});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("GuaranteedStateStore: status upsert failed for agent_id={} rule_id={}: {}",
                     log_id_token(agent_id), log_id_token(rule_id), PQerrorMessage(conn));
}

} // namespace

EventInsertResult
GuaranteedStateStore::insert_event_classified(const GuaranteedStateEventRow& row) {
    if (!open_)
        return {EventInsertOutcome::Error, "database not open"};

    // Reject malformed input up front (untrusted agent boundary): libpq's
    // text-format bind (paramLengths=nullptr) computes length via strlen,
    // exactly like SQLite's -1 bind — an embedded NUL would silently
    // truncate, corrupting the event_id PK dedup and the redelivery compare.
    for (const std::string* f :
        {&row.event_id, &row.rule_id, &row.agent_id, &row.event_type, &row.severity,
         &row.guard_type, &row.guard_category, &row.detected_value, &row.expected_value,
         &row.remediation_action, &row.timestamp, &row.detail_json})
        if (f->find('\0') != std::string::npos)
            return {EventInsertOutcome::Error, "event field contains an embedded NUL byte"};

    // Transient ingest errors count on events_ingest_errors_total (the agent's
    // durable journal redelivers) — NOT on a "dropped" counter; only a genuine
    // conflict is a permanent drop (events_dropped_total). (Gate 4 consistency
    // SHOULD-1: the earlier ingest_dropped_total double-counted this family and
    // mislabelled transient errors as drops.)
    const auto op_error = [this](std::string msg, const char* /*reason*/) {
        events_ingest_errors_.fetch_add(1, std::memory_order_relaxed);
        return EventInsertResult{EventInsertOutcome::Error, std::move(msg)};
    };

    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease) {
        events_ingest_errors_.fetch_add(1, std::memory_order_relaxed);
        return {EventInsertOutcome::Error, "no database connection: " + pool_.last_error()};
    }
    PGconn* conn = lease.get();

    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK)
        return op_error(std::string("BEGIN failed: ") + PQerrorMessage(conn), kReasonQueryError);
    pg::PgTxn txn(conn);
    const int64_t ttl = compute_ttl_epoch();

    pg::PgResult sp = pg::exec_params(conn, "SAVEPOINT event_insert", std::vector<std::string>{});
    if (sp.status() != PGRES_COMMAND_OK)
        return op_error(std::string("SAVEPOINT failed: ") + PQerrorMessage(conn), kReasonQueryError);

    pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guaranteed_state_events "
        "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
        " detected_value, expected_value, remediation_action, remediation_success, "
        " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, detail_json) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
        "$15::bigint,$16)",
        std::vector<std::string>{row.event_id, row.rule_id, row.agent_id, row.event_type,
                                 row.severity, row.guard_type, row.guard_category,
                                 row.detected_value, row.expected_value, row.remediation_action,
                                 std::string(row.remediation_success ? "true" : "false"),
                                 std::to_string(row.detection_latency_us),
                                 std::to_string(row.remediation_latency_us), row.timestamp,
                                 std::to_string(ttl), row.detail_json});

    if (ins.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        const std::string err = PQresultErrorMessage(ins.get());
        if (sqlstate == "23505") {
            // event_id already present. Un-abort the transaction (Postgres aborts the
            // WHOLE transaction on a failed statement, unlike SQLite) so the compare
            // SELECT below can run on the SAME connection/transaction — load-bearing
            // for the no-TOCTOU-with-the-reaper invariant.
            pg::PgResult back = pg::exec_params(conn, "ROLLBACK TO SAVEPOINT event_insert", std::vector<std::string>{});
            if (back.status() != PGRES_COMMAND_OK)
                return op_error(std::string("ROLLBACK TO SAVEPOINT failed: ") +
                                    PQerrorMessage(conn),
                                kReasonQueryError);
            auto matched = stored_event_matches(conn, row);
            if (!matched)
                return op_error("redelivery compare failed: " + matched.error(), kReasonQueryError);
            if (*matched) {
                events_redelivered_.fetch_add(1, std::memory_order_relaxed);
                return {EventInsertOutcome::Redelivered, {}};
            }
            events_dropped_.fetch_add(1, std::memory_order_relaxed);
            return {EventInsertOutcome::Conflict,
                    format_conflict("event_id '" + row.event_id +
                                    "' already exists with different fields")};
        }
        return op_error("insert failed: " + err, kReasonQueryError);
    }

    // DEX projection: ruleless observations only, under its own SAVEPOINT so a
    // projection failure degrades (event kept) instead of aborting the whole
    // transaction.
    if (is_reserved_rule_id(row.rule_id)) {
        pg::PgResult sp2 = pg::exec_params(conn, "SAVEPOINT observation_projection", std::vector<std::string>{});
        if (sp2.status() == PGRES_COMMAND_OK) {
            if (auto pr = project_observation(conn, row, ttl); !pr) {
                observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("GuaranteedStateStore: observation projection failed "
                              "(event kept, read-model row lost) event_id={} agent_id={}: {}",
                              log_id_token(row.event_id), log_id_token(row.agent_id), pr.error());
                pg::exec_params(conn, "ROLLBACK TO SAVEPOINT observation_projection", std::vector<std::string>{});
            } else {
                pg::exec_params(conn, "RELEASE SAVEPOINT observation_projection", std::vector<std::string>{});
            }
        } else {
            observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
            spdlog::error("GuaranteedStateStore: observation projection SAVEPOINT failed "
                          "event_id={}: {}",
                          log_id_token(row.event_id), PQerrorMessage(conn));
        }
    }

    if (!txn.commit())
        return op_error(std::string("commit failed: ") + PQerrorMessage(conn), kReasonQueryError);
    const std::int64_t committed_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();

    events_written_.fetch_add(1, std::memory_order_relaxed);
    // Census upsert AFTER commit, as a separate best-effort autocommit
    // statement on the same connection (mirrors the original SQLite ordering
    // — a status-upsert failure here must never take the already-committed
    // event with it).
    if (!is_reserved_rule_id(row.rule_id))
        if (const char* state = event_state_from_type(row.event_type))
            upsert_rule_status(conn, row.agent_id, row.rule_id, state, row.timestamp);
    return {EventInsertOutcome::Inserted, {}, committed_wall_ns};
}

std::expected<void, std::string>
GuaranteedStateStore::insert_event(const GuaranteedStateEventRow& row) {
    EventInsertResult r = insert_event_classified(row);
    switch (r.outcome) {
    case EventInsertOutcome::Inserted:
    case EventInsertOutcome::Redelivered:
        return {};
    case EventInsertOutcome::Conflict:
    case EventInsertOutcome::Error:
        return std::unexpected(std::move(r.error));
    }
    return std::unexpected("insert_event: unreachable outcome");
}

// HARD CONSTRAINT (item-7 PR-Sv, arch-S1 / UP-11): this batch path does NOT classify
// redelivery vs collision and does NOT drive the DEX observers — on ANY event_id conflict
// it aborts and rolls back the WHOLE batch. That is safe ONLY because it has no live caller
// today. The durable agent lifecycle journal makes redelivery the common case, so replays
// MUST ingest one-at-a-time via insert_event_classified, NEVER through this batch path.
std::expected<std::size_t, std::string>
GuaranteedStateStore::insert_events(const std::vector<GuaranteedStateEventRow>& rows) {
    if (rows.empty())
        return 0;
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("BEGIN failed: ") + PQerrorMessage(conn));
    pg::PgTxn txn(conn);
    const int64_t ttl = compute_ttl_epoch();

    for (const auto& row : rows) {
        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
            " detected_value, expected_value, remediation_action, remediation_success, "
            " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, "
            " detail_json) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
            "$15::bigint,$16)",
            std::vector<std::string>{row.event_id, row.rule_id, row.agent_id, row.event_type,
                                     row.severity, row.guard_type, row.guard_category,
                                     row.detected_value, row.expected_value,
                                     row.remediation_action,
                                     std::string(row.remediation_success ? "true" : "false"),
                                     std::to_string(row.detection_latency_us),
                                     std::to_string(row.remediation_latency_us), row.timestamp,
                                     std::to_string(ttl), row.detail_json});
        if (ins.status() != PGRES_COMMAND_OK) {
            const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
            const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
            if (sqlstate == "23505")
                return std::unexpected(
                    format_conflict("event_id '" + row.event_id + "' already exists"));
            return std::unexpected("insert failed: " + std::string(PQresultErrorMessage(ins.get())));
        }
        // Census upsert INSIDE the transaction here (unlike the single-event path):
        // rolled back with the batch on any later failure, so events and status
        // never diverge (matches the original's explicit intent for this path).
        if (!is_reserved_rule_id(row.rule_id))
            if (const char* state = event_state_from_type(row.event_type))
                upsert_rule_status(conn, row.agent_id, row.rule_id, state, row.timestamp);
        // DEX projection — same degrade-don't-destroy contract as insert_event,
        // under its own SAVEPOINT (Postgres aborts on any failed statement).
        if (is_reserved_rule_id(row.rule_id)) {
            pg::PgResult sp = pg::exec_params(conn, "SAVEPOINT observation_projection", std::vector<std::string>{});
            if (sp.status() == PGRES_COMMAND_OK) {
                if (auto pr = project_observation(conn, row, ttl); !pr) {
                    observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
                    spdlog::error("GuaranteedStateStore: observation projection failed in batch "
                                  "(event kept) event_id={} agent_id={}: {}",
                                  log_id_token(row.event_id), log_id_token(row.agent_id), pr.error());
                    pg::exec_params(conn, "ROLLBACK TO SAVEPOINT observation_projection", std::vector<std::string>{});
                } else {
                    pg::exec_params(conn, "RELEASE SAVEPOINT observation_projection", std::vector<std::string>{});
                }
            } else {
                // cpp-safety Gate-3 SHOULD: mirror the single-event twin's
                // observability — a failed SAVEPOINT leaves the txn about to
                // abort on the next statement, so surface it rather than
                // proceeding silently. (This batch path has no live caller
                // today — the HARD CONSTRAINT above — but must not become the
                // one ingest site that fails invisibly if a caller appears.)
                observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("GuaranteedStateStore: SAVEPOINT observation_projection failed in "
                              "batch (event_id={}): {}",
                              log_id_token(row.event_id), PQerrorMessage(conn));
            }
        }
    }

    if (!txn.commit())
        return std::unexpected(std::string("COMMIT failed: ") + PQerrorMessage(conn));
    events_written_.fetch_add(rows.size(), std::memory_order_relaxed);
    return rows.size();
}

// ── DEX / analytics reads (plain, empty-on-degrade — ADR-0038 #2659) ─────────

std::vector<GuaranteedStateEventRow>
GuaranteedStateStore::query_events(const GuaranteedStateEventQuery& q) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuaranteedStateEventRow>>(
        open_, pool_, metrics_, "query_events", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuaranteedStateEventRow>> {
            std::string sql =
                "SELECT event_id, rule_id, agent_id, event_type, severity, guard_type, "
                "guard_category, detected_value, expected_value, remediation_action, "
                "remediation_success, detection_latency_us, remediation_latency_us, timestamp, "
                "detail_json FROM guaranteed_state_store.guaranteed_state_events WHERE 1=1";
            std::vector<std::string> params;
            int idx = 1;
            if (!q.rule_id.empty()) {
                sql += " AND rule_id = $" + std::to_string(idx++);
                params.push_back(q.rule_id);
            }
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                params.push_back(q.agent_id);
            }
            if (!q.severity.empty()) {
                sql += " AND severity = $" + std::to_string(idx++);
                params.push_back(q.severity);
            }
            sql += " ORDER BY timestamp DESC, event_id DESC LIMIT $" + std::to_string(idx++) +
                   "::bigint";
            params.push_back(std::to_string(std::clamp(q.limit, 0, kMaxEventsLimit)));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::bigint";
                params.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuaranteedStateEventRow> rows;
            const int n = PQntuples(res.get());
            rows.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuaranteedStateEventRow r;
                int c = 0;
                r.event_id = text_col(res.get(), i, c++);
                r.rule_id = text_col(res.get(), i, c++);
                r.agent_id = text_col(res.get(), i, c++);
                r.event_type = text_col(res.get(), i, c++);
                r.severity = text_col(res.get(), i, c++);
                r.guard_type = text_col(res.get(), i, c++);
                r.guard_category = text_col(res.get(), i, c++);
                r.detected_value = text_col(res.get(), i, c++);
                r.expected_value = text_col(res.get(), i, c++);
                r.remediation_action = text_col(res.get(), i, c++);
                r.remediation_success = to_bool(PQgetvalue(res.get(), i, c++));
                r.detection_latency_us = to_i64(PQgetvalue(res.get(), i, c++));
                r.remediation_latency_us = to_i64(PQgetvalue(res.get(), i, c++));
                r.timestamp = text_col(res.get(), i, c++);
                r.detail_json = text_col(res.get(), i, c++);
                rows.push_back(std::move(r));
            }
            return rows;
        });
}

namespace {
GuardianObservationRow read_observation_row(PGresult* res, int i, bool has_version = true) {
    GuardianObservationRow r;
    int c = 0;
    r.event_id = text_col(res, i, c++);
    r.agent_id = text_col(res, i, c++);
    r.observed_at = text_col(res, i, c++);
    r.obs_type = text_col(res, i, c++);
    r.subject = text_col(res, i, c++);
    r.reason = text_col(res, i, c++);
    r.symbolic = text_col(res, i, c++);
    r.component = text_col(res, i, c++);
    r.metric = to_double(PQgetvalue(res, i, c++));
    r.platform = text_col(res, i, c++);
    if (has_version)
        r.version = text_col(res, i, c++);
    return r;
}
} // namespace

std::vector<GuardianObservationRow> GuaranteedStateStore::query_observations(int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianObservationRow>>(
        open_, pool_, metrics_, "query_observations", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianObservationRow>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
                "component, metric, platform, version FROM "
                "guaranteed_state_store.guardian_observations ORDER BY observed_at DESC, "
                "event_id DESC LIMIT $1::bigint",
                std::vector<std::string>{
                    std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianObservationRow> rows;
            const int n = PQntuples(res.get());
            rows.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i)
                rows.push_back(read_observation_row(res.get(), i));
            return rows;
        });
}

DexCrashSummary GuaranteedStateStore::dex_crash_summary(const std::string& since,
                                                        const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<DexCrashSummary>(
        open_, pool_, metrics_, "dex_crash_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexCrashSummary> {
            std::string sql =
                "SELECT COUNT(*), COUNT(DISTINCT agent_id), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1";
            std::vector<std::string> params{since};
            if (!platform.empty()) {
                sql += " AND platform = $2";
                params.push_back(platform);
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexCrashSummary s;
            if (PQntuples(res.get()) > 0) {
                s.total_crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 1));
                s.distinct_apps = to_i64(PQgetvalue(res.get(), 0, 2));
            }
            return s;
        });
}

std::vector<DexAppCrashCount> GuaranteedStateStore::dex_top_apps(const std::string& since,
                                                                 int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexAppCrashCount>>(
        open_, pool_, metrics_, "dex_top_apps", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexAppCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT subject, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.crashed') AS crashes, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung') AS hangs, "
                "COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type IN ('process.crashed', 'process.hung') AND observed_at >= $1 "
                "GROUP BY subject ORDER BY (COUNT(*) FILTER (WHERE obs_type = 'process.crashed') "
                "+ COUNT(*) FILTER (WHERE obs_type = 'process.hung')) DESC, subject ASC "
                "LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexAppCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexAppCrashCount a;
                a.subject = text_col(res.get(), i, 0);
                a.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                a.hangs = to_i64(PQgetvalue(res.get(), i, 2));
                a.distinct_devices = to_i64(PQgetvalue(res.get(), i, 3));
                a.last_seen = text_col(res.get(), i, 4);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<DexAppCrashCount>
GuaranteedStateStore::dex_device_top_apps(const std::string& agent_id, const std::string& since,
                                          int limit) const {
    static DegradeSampler sampler;
    if (agent_id.empty())
        return {};
    return dex_read<std::vector<DexAppCrashCount>>(
        open_, pool_, metrics_, "dex_device_top_apps", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexAppCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT subject, version, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.crashed') AS crashes, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung') AS hangs, MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND obs_type IN ('process.crashed', 'process.hung') "
                "AND observed_at >= $2 GROUP BY subject, version "
                "ORDER BY (COUNT(*) FILTER (WHERE obs_type = 'process.crashed') + "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung')) DESC, subject ASC, "
                "version ASC LIMIT $3::bigint",
                std::vector<std::string>{agent_id, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexAppCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexAppCrashCount a;
                a.subject = text_col(res.get(), i, 0);
                a.version = text_col(res.get(), i, 1);
                a.crashes = to_i64(PQgetvalue(res.get(), i, 2));
                a.hangs = to_i64(PQgetvalue(res.get(), i, 3));
                a.distinct_devices = 1;
                a.last_seen = text_col(res.get(), i, 4);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<DexModuleCrashCount> GuaranteedStateStore::dex_top_modules(const std::string& since,
                                                                       int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexModuleCrashCount>>(
        open_, pool_, metrics_, "dex_top_modules", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexModuleCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT component, COUNT(*), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY component ORDER BY COUNT(*) DESC, component ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexModuleCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexModuleCrashCount m;
                m.component = text_col(res.get(), i, 0);
                m.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                m.distinct_apps = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(m));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount> GuaranteedStateStore::dex_top_devices(const std::string& since,
                                                                       int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_top_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount d;
                d.agent_id = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                d.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(d));
            }
            return out;
        });
}

std::vector<DexOsCrashCount> GuaranteedStateStore::dex_crashes_by_os(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsCrashCount>>(
        open_, pool_, metrics_, "dex_crashes_by_os", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(*), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY platform ORDER BY COUNT(*) DESC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsCrashCount o;
                o.platform = text_col(res.get(), i, 0);
                o.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                o.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(o));
            }
            return out;
        });
}

std::vector<DexDayCrashCount>
GuaranteedStateStore::dex_crashes_by_day(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDayCrashCount>>(
        open_, pool_, metrics_, "dex_crashes_by_day", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDayCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(observed_at, 1, 10) AS day, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY day ORDER BY day ASC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDayCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDayCrashCount d;
                d.day = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(d));
            }
            return out;
        });
}

std::vector<DexSignalCount>
GuaranteedStateStore::dex_signal_summary(const std::string& since, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexSignalCount>>(
        open_, pool_, metrics_, "dex_signal_summary", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSignalCount>> {
            std::string sql =
                "SELECT obs_type, COUNT(*), COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations WHERE observed_at >= $1";
            std::vector<std::string> params{since};
            if (!platform.empty()) {
                sql += " AND platform = $2";
                params.push_back(platform);
            }
            sql += " GROUP BY obs_type ORDER BY COUNT(*) DESC, obs_type ASC";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSignalCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSignalCount c;
                c.obs_type = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                c.last_seen = text_col(res.get(), i, 3);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::optional<std::vector<DexSignalCount>>
GuaranteedStateStore::dex_device_signal_summary_checked(const std::string& agent_id,
                                                        const std::string& since) const {
    // #4855: the ONE DEX/analytics read the device-score surfaces (dashboard
    // lens, REST GET /api/v1/dex/devices/{id}, MCP get_dex_device_score) need
    // to tell "degraded" apart from "no signals" — a degrade here previously
    // rendered as a perfectly healthy score of 100. See dex_read_checked's
    // doc comment: this is a NAMED, deliberate widening of this one read,
    // not the #2659 fleet-wide widening.
    static DegradeSampler sampler;
    return dex_read_checked<std::vector<DexSignalCount>>(
        open_, pool_, metrics_, "dex_device_signal_summary", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSignalCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT obs_type, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2 "
                "GROUP BY obs_type ORDER BY COUNT(*) DESC, obs_type ASC",
                std::vector<std::string>{agent_id, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSignalCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSignalCount c;
                c.obs_type = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = 1;
                c.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexSignalCount>
GuaranteedStateStore::dex_device_signal_summary(const std::string& agent_id,
                                                const std::string& since) const {
    return dex_device_signal_summary_checked(agent_id, since)
        .value_or(std::vector<DexSignalCount>{});
}

std::vector<DexSubjectCount>
GuaranteedStateStore::dex_signal_subjects(const std::string& obs_type, const std::string& since,
                                          int limit, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexSubjectCount>>(
        open_, pool_, metrics_, "dex_signal_subjects", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSubjectCount>> {
            std::string sql =
                "SELECT subject, COUNT(*), COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2 AND subject <> ''";
            std::vector<std::string> params{obs_type, since,
                                            std::to_string(std::clamp(limit, 0, kMaxEventsLimit))};
            if (!platform.empty()) {
                sql += " AND platform = $4";
                params.push_back(platform);
            }
            sql += " GROUP BY subject ORDER BY COUNT(*) DESC, subject ASC LIMIT $3::bigint";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSubjectCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSubjectCount c;
                c.subject = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                c.last_seen = text_col(res.get(), i, 3);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexOsCrashCount>
GuaranteedStateStore::dex_signal_by_os(const std::string& obs_type, const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsCrashCount>>(
        open_, pool_, metrics_, "dex_signal_by_os", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(*), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2 GROUP BY platform ORDER BY COUNT(*) "
                "DESC",
                std::vector<std::string>{obs_type, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsCrashCount c;
                c.platform = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1)); // generic event count
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount>
GuaranteedStateStore::dex_signal_devices(const std::string& obs_type, const std::string& since,
                                         int limit, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_signal_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            std::string sql =
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2";
            std::vector<std::string> params{obs_type, since,
                                            std::to_string(std::clamp(limit, 0, kMaxEventsLimit))};
            if (!platform.empty()) {
                sql += " AND platform = $4";
                params.push_back(platform);
            }
            sql += " GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $3::bigint";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount c;
                c.agent_id = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1)); // generic event count
                c.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDayCrashCount>
GuaranteedStateStore::dex_signal_by_day(const std::string& obs_type, const std::string& since,
                                        const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDayCrashCount>>(
        open_, pool_, metrics_, "dex_signal_by_day", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDayCrashCount>> {
            std::string sql =
                "SELECT substr(observed_at, 1, 10) AS day, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2";
            std::vector<std::string> params{obs_type, since};
            if (!platform.empty()) {
                sql += " AND platform = $3";
                params.push_back(platform);
            }
            sql += " GROUP BY day ORDER BY day ASC";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDayCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDayCrashCount c;
                c.day = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexOsScope> GuaranteedStateStore::dex_os_signal_scope(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsScope>>(
        open_, pool_, metrics_, "dex_os_signal_scope", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsScope>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(DISTINCT obs_type), COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE observed_at >= $1 AND platform <> '' "
                "GROUP BY platform ORDER BY COUNT(*) DESC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsScope> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsScope c;
                c.platform = text_col(res.get(), i, 0);
                c.distinct_types = to_i64(PQgetvalue(res.get(), i, 1));
                c.total_events = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDaySignal>
GuaranteedStateStore::dex_signal_day_matrix(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDaySignal>>(
        open_, pool_, metrics_, "dex_signal_day_matrix", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDaySignal>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(observed_at, 1, 10) AS day, obs_type, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE observed_at >= $1 GROUP BY day, obs_type ORDER BY day ASC, obs_type ASC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDaySignal> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDaySignal c;
                c.day = text_col(res.get(), i, 0);
                c.obs_type = text_col(res.get(), i, 1);
                c.count = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

DexBootStats GuaranteedStateStore::dex_boot_stats(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexBootStats>(
        open_, pool_, metrics_, "dex_boot_stats", sampler,
        [&](PGconn* conn) -> std::optional<DexBootStats> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*), AVG(metric), MAX(metric), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'os.boot' AND metric > 0 AND observed_at >= $1",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexBootStats s;
            if (PQntuples(res.get()) > 0) {
                s.boots = to_i64(PQgetvalue(res.get(), 0, 0));
                s.avg_ms = to_double(PQgetvalue(res.get(), 0, 1));
                s.max_ms = to_double(PQgetvalue(res.get(), 0, 2));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 3));
            }
            return s;
        });
}

std::vector<DexDeviceBoot> GuaranteedStateStore::dex_slowest_boots(const std::string& since,
                                                                   int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceBoot>>(
        open_, pool_, metrics_, "dex_slowest_boots", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceBoot>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, AVG(metric), MAX(metric), COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'os.boot' AND metric > 0 AND observed_at >= $1 "
                "GROUP BY agent_id ORDER BY AVG(metric) DESC, agent_id ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceBoot> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceBoot b;
                b.agent_id = text_col(res.get(), i, 0);
                b.avg_ms = to_double(PQgetvalue(res.get(), i, 1));
                b.max_ms = to_double(PQgetvalue(res.get(), i, 2));
                b.boots = to_i64(PQgetvalue(res.get(), i, 3));
                out.push_back(std::move(b));
            }
            return out;
        });
}

DexEntitySummary GuaranteedStateStore::dex_app_summary(const std::string& process_name,
                                                       const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexEntitySummary>(
        open_, pool_, metrics_, "dex_app_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexEntitySummary> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*) FILTER (WHERE obs_type = 'process.crashed'), "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung'), COUNT(*), "
                "COUNT(DISTINCT agent_id), MIN(observed_at), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type IN ('process.crashed', 'process.hung') AND subject = $1 "
                "AND observed_at >= $2",
                std::vector<std::string>{process_name, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexEntitySummary s;
            if (PQntuples(res.get()) > 0) {
                s.crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.hangs = to_i64(PQgetvalue(res.get(), 0, 1));
                s.signals = to_i64(PQgetvalue(res.get(), 0, 2));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 3));
                s.distinct_apps = 1;
                s.first_seen = text_col(res.get(), 0, 4);
                s.last_seen = text_col(res.get(), 0, 5);
            }
            return s;
        });
}

std::vector<DexModuleCrashCount>
GuaranteedStateStore::dex_app_modules(const std::string& process_name, const std::string& since,
                                      int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexModuleCrashCount>>(
        open_, pool_, metrics_, "dex_app_modules", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexModuleCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT component, COUNT(*), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY component ORDER BY COUNT(*) DESC, component ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexModuleCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexModuleCrashCount m;
                m.component = text_col(res.get(), i, 0);
                m.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                m.distinct_apps = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(m));
            }
            return out;
        });
}

std::vector<DexExceptionCount>
GuaranteedStateStore::dex_app_exceptions(const std::string& process_name, const std::string& since,
                                         int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexExceptionCount>>(
        open_, pool_, metrics_, "dex_app_exceptions", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexExceptionCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT reason, symbolic, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY reason, symbolic ORDER BY COUNT(*) DESC, reason ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexExceptionCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexExceptionCount e;
                e.reason = text_col(res.get(), i, 0);
                e.symbolic = text_col(res.get(), i, 1);
                e.crashes = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(e));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount>
GuaranteedStateStore::dex_app_devices(const std::string& process_name, const std::string& since,
                                      int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_app_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount d;
                d.agent_id = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                d.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(d));
            }
            return out;
        });
}

DexEntitySummary GuaranteedStateStore::dex_device_summary(const std::string& agent_id,
                                                          const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexEntitySummary>(
        open_, pool_, metrics_, "dex_device_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexEntitySummary> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*) FILTER (WHERE obs_type = 'process.crashed'), "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung'), COUNT(*), "
                "COUNT(DISTINCT CASE WHEN obs_type IN ('process.crashed', 'process.hung') "
                "THEN subject END), MIN(observed_at), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2",
                std::vector<std::string>{agent_id, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexEntitySummary s;
            if (PQntuples(res.get()) > 0) {
                s.crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.hangs = to_i64(PQgetvalue(res.get(), 0, 1));
                s.signals = to_i64(PQgetvalue(res.get(), 0, 2));
                s.distinct_apps = to_i64(PQgetvalue(res.get(), 0, 3));
                s.distinct_devices = 1;
                s.first_seen = text_col(res.get(), 0, 4);
                s.last_seen = text_col(res.get(), 0, 5);
            }
            return s;
        });
}

std::vector<GuardianObservationRow>
GuaranteedStateStore::dex_device_history(const std::string& agent_id, const std::string& since,
                                         int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianObservationRow>>(
        open_, pool_, metrics_, "dex_device_history", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianObservationRow>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
                "component, metric, platform FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2 ORDER BY observed_at DESC, "
                "event_id DESC LIMIT $3::bigint",
                std::vector<std::string>{agent_id, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianObservationRow> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i)
                out.push_back(read_observation_row(res.get(), i, /*has_version=*/false));
            return out;
        });
}

std::optional<GuardianObservationRow>
GuaranteedStateStore::dex_observation(const std::string& event_id) const {
    static DegradeSampler sampler;
    if (event_id.empty())
        return std::nullopt;
    // Single-object read stays plain optional (not a catastrophic-set read):
    // a store fault and a genuine not-found are both surfaced as nullopt to
    // the caller, but the degrade path IS counted+logged (below) so the loss
    // is visible on /metrics — matching the ADR-0038 "deferred widening"
    // posture for every non-catastrophic read.
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kDexReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: pool acquire timed out");
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
        "component, metric, platform FROM guaranteed_state_store.guardian_observations "
        "WHERE event_id = $1 LIMIT 1",
        std::vector<std::string>{event_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSource, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt; // genuine not-found, not a degrade
    return read_observation_row(res.get(), 0, /*has_version=*/false);
}

std::vector<GuardianRuleActivity>
GuaranteedStateStore::rule_activity(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianRuleActivity>>(
        open_, pool_, metrics_, "rule_activity", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianRuleActivity>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT rule_id, "
                "COUNT(*) FILTER (WHERE event_type = 'drift.detected'), "
                "COUNT(*) FILTER (WHERE event_type = 'drift.remediated'), "
                "COUNT(*) FILTER (WHERE event_type = 'remediation.failed'), "
                "COUNT(*) FILTER (WHERE event_type = 'guard.unhealthy'), "
                "COUNT(DISTINCT agent_id), MAX(timestamp) "
                "FROM guaranteed_state_store.guaranteed_state_events "
                "WHERE ($1 = '' OR timestamp >= $1) GROUP BY rule_id",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianRuleActivity> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuardianRuleActivity a;
                a.rule_id = text_col(res.get(), i, 0);
                a.detected = to_i64(PQgetvalue(res.get(), i, 1));
                a.remediated = to_i64(PQgetvalue(res.get(), i, 2));
                a.failed = to_i64(PQgetvalue(res.get(), i, 3));
                a.unhealthy = to_i64(PQgetvalue(res.get(), i, 4));
                a.distinct_agents = to_i64(PQgetvalue(res.get(), i, 5));
                a.last_activity = text_col(res.get(), i, 6);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<GuardianDayCount>
GuaranteedStateStore::daily_remediations(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianDayCount>>(
        open_, pool_, metrics_, "daily_remediations", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianDayCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(timestamp, 1, 10) AS day, "
                "COUNT(*) FILTER (WHERE event_type = 'drift.remediated'), "
                "COUNT(*) FILTER (WHERE event_type = 'remediation.failed') "
                "FROM guaranteed_state_store.guaranteed_state_events "
                "WHERE ($1 = '' OR timestamp >= $1) "
                "AND event_type IN ('drift.remediated', 'remediation.failed') "
                "GROUP BY day ORDER BY day",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianDayCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuardianDayCount d;
                d.day = text_col(res.get(), i, 0);
                d.remediated = to_i64(PQgetvalue(res.get(), i, 1));
                d.failed = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(d));
            }
            return out;
        });
}

// ── Status + name lookups (ADR-0038 catastrophic-read set) ───────────────────

std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
GuaranteedStateStore::agent_rule_statuses(const std::string& rule_id) const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    std::string sql =
        "SELECT agent_id, rule_id, state, updated_at FROM "
        "guaranteed_state_store.guardian_agent_rule_status";
    std::vector<std::string> params;
    if (!rule_id.empty()) {
        sql += " WHERE rule_id = $1"; // idx_gars_rule covers this for the drill-down
        params.push_back(rule_id);
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    std::vector<GuardianAgentRuleStatus> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        GuardianAgentRuleStatus r;
        r.agent_id = text_col(res.get(), i, 0);
        r.rule_id = text_col(res.get(), i, 1);
        r.state = text_col(res.get(), i, 2);
        r.updated_at = text_col(res.get(), i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
GuaranteedStateStore::agent_rule_statuses_for_agent(const std::string& agent_id) const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses_for_agent: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses_for_agent: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    // Rides the (agent_id, rule_id) PK auto-index (agent_id leading).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, rule_id, state, updated_at FROM "
        "guaranteed_state_store.guardian_agent_rule_status WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::agent_rule_statuses_for_agent: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    std::vector<GuardianAgentRuleStatus> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        GuardianAgentRuleStatus r;
        r.agent_id = text_col(res.get(), i, 0);
        r.rule_id = text_col(res.get(), i, 1);
        r.state = text_col(res.get(), i, 2);
        r.updated_at = text_col(res.get(), i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::unordered_map<std::string, std::string>, std::string>
GuaranteedStateStore::rule_names() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_names: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_names: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT rule_id, name FROM guaranteed_state_store.guaranteed_state_rules",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_names: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    std::unordered_map<std::string, std::string> out;
    const int n = PQntuples(res.get());
    for (int i = 0; i < n; ++i)
        out.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return out;
}

std::expected<std::unordered_map<std::string, std::string>, std::string>
GuaranteedStateStore::rule_names_for(const std::vector<std::string>& rule_ids) const {
    std::unordered_map<std::string, std::string> out;
    if (rule_ids.empty())
        return out; // success, not degrade
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_names_for: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_names_for: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    // CHUNKED at 500 ids per statement (mirrors the SQLite original) — a
    // Baseline whose deployed-snapshot is very large cannot make one giant
    // IN-list statement time out or exceed a param-count limit.
    constexpr std::size_t kChunk = 500;
    for (std::size_t base = 0; base < rule_ids.size(); base += kChunk) {
        const std::size_t n = std::min(kChunk, rule_ids.size() - base);
        std::string sql =
            "SELECT rule_id, name FROM guaranteed_state_store.guaranteed_state_rules WHERE "
            "rule_id IN (";
        std::vector<std::string> params;
        params.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            sql += (i == 0 ? "$" : ",$") + std::to_string(i + 1);
            params.push_back(rule_ids[base + i]);
        }
        sql += ")";
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() != PGRES_TUPLES_OK) {
            if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                                  sampler);
                d.should_log)
                spdlog::warn("GuaranteedStateStore::rule_names_for: query failed: {}",
                             PQresultErrorMessage(res.get()));
            return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
        }
        const int rows = PQntuples(res.get());
        for (int i = 0; i < rows; ++i)
            out.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    }
    return out;
}

std::expected<std::size_t, std::string> GuaranteedStateStore::errored_rule_count(
    const std::optional<std::vector<std::string>>& agent_scope) const {
    static DegradeSampler sampler;
    // Engaged-empty scope (ADR-0017 INV-2): zero visible agents means zero
    // rows, without issuing a query — mirrors rule_names_for's empty-input
    // posture (success, not degrade).
    if (agent_scope && agent_scope->empty())
        return static_cast<std::size_t>(0);
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::errored_rule_count: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::errored_rule_count: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    std::string sql =
        "SELECT COUNT(DISTINCT s.rule_id) FROM "
        "guaranteed_state_store.guardian_agent_rule_status s JOIN "
        "guaranteed_state_store.guaranteed_state_rules r ON r.rule_id = s.rule_id WHERE "
        "s.state = 'errored'";
    std::vector<std::string> params;
    if (agent_scope) {
        // ADR-0017 INV-3: the visible set is applied IN SQL, before the
        // aggregate — never a C++ post-filter over the full fleet census.
        std::vector<std::string_view> views;
        views.reserve(agent_scope->size());
        for (const std::string& a : *agent_scope)
            views.emplace_back(a);
        sql += " AND s.agent_id = ANY($1::text[])";
        params.push_back(pg::to_text_array(views));
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::errored_rule_count: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t GuaranteedStateStore::rule_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM guaranteed_state_store.guaranteed_state_rules", std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t GuaranteedStateStore::event_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM guaranteed_state_store.guaranteed_state_events", std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// ── Retention reaper (#2496 gc_sweep shape, ADR-0038) ─────────────────────────

void GuaranteedStateStore::reap_expired() {
    if (!open_)
        return;
    const auto record_result = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_guardian_reap_passes_total", {{"result", result}}).increment();
    };

    int64_t events_deleted = 0;
    int64_t observations_deleted = 0;
    std::string outcome = "failed";
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // One sweeping replica at a time.
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock(hashtextextended("
            "'guaranteed_state_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            outcome = "skipped_lock";
            return true;
        }

        const int64_t now = now_fn_ ? now_fn_() : now_epoch();
        // Sanitise the CALLER's (process) clock cheaply, before even attempting
        // the pg_now read below — clock-guard part 3. UPPER bound only: a
        // NEGATIVE reading is the legitimate dead-CMOS case the guard exists
        // for, so it is not rejected here. This value plays NO further role in
        // the pass: every DECISION below reads Postgres's OWN clock (see
        // pg_now below), so an implausible process clock is refused here only
        // to avoid touching the DB at all for a reading that could not matter.
        constexpr int64_t kMaxPlausibleNow = std::numeric_limits<int64_t>::max() / 4;
        if (now > kMaxPlausibleNow) {
            spdlog::warn("GuaranteedStateStore::reap_expired: implausible clock reading ({}); "
                         "declining the pass",
                         now);
            outcome = "failed";
            return false;
        }

        // PostgreSQL's OWN clock, not this replica's process clock, for every
        // DECISION below (#2663, fjarvis review). This store originally read
        // its own process clock, which let a fast/skewed replica's `now` win
        // the shared `gc_meta.last_pass_now` anchor and misclassify a row
        // still live by every other clock as expired — `classify()`'s
        // existing detectors do not catch a moderately-fast clock, since
        // `has_expired` alone with no other trigger derives `Anomaly::None`,
        // an ordinary clean sweep, with zero anomaly recorded. Sharing
        // `gc_meta` does not fix this on its own — it is the transmission
        // medium: the fast replica's own reading gets written into the row
        // every OTHER replica then measures against. Mirrors
        // `AuditStore::cleanup_once`'s `#2360/1d` fix exactly: read PG's
        // clock AFTER the advisory lock, inside this transaction, so every
        // replica serialised through that lock gets the IDENTICAL comparison
        // point regardless of its own clock's accuracy. `ResultSetStore::
        // gc_sweep` still has this defect (still reads its own process
        // clock) — a deferred follow-up, not a precedent this fix copies.
        pg::PgResult clk = pg::exec_params(conn, "SELECT EXTRACT(EPOCH FROM now())::bigint",
                                           std::vector<std::string>{});
        if (clk.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: pg clock read failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        const int64_t pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));
        // Same overflow guard, applied to PG's reading too — cheap to bound
        // both sources the same way rather than trust one implicitly because
        // it is "the database" (AuditStore precedent).
        if (pg_now > kMaxPlausibleNow) {
            spdlog::error("GuaranteedStateStore::reap_expired: PostgreSQL's own clock reading "
                          "({}) is implausible; declining the pass",
                          pg_now);
            outcome = "failed";
            return false;
        }

        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM guaranteed_state_store.gc_meta WHERE key IN "
            "('last_pass_now','last_anomaly_facts','bootstrap_settled')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: meta read failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        std::optional<int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        // #2579: has ANY pass on this database ever reached a verdict? Durable and
        // SHARED across replicas (not a per-process flag) — settled below, AFTER
        // classify(), never derived from `prev` (see that site for why).
        bool bootstrap_settled = false;
        for (int i = 0; i < PQntuples(meta.get()); ++i) {
            const std::string key = text_col(meta.get(), i, 0);
            const std::string val = text_col(meta.get(), i, 1);
            if (key == "last_pass_now") {
                errno = 0;
                char* end = nullptr;
                const long long v = std::strtoll(val.c_str(), &end, 10);
                if (errno != 0 || end == val.c_str() || *end != '\0')
                    prev_unusable = true;
                else
                    prev = static_cast<int64_t>(v);
            } else if (key == "last_anomaly_facts") {
                last_facts = val;
            } else if (key == "bootstrap_settled") {
                bootstrap_settled = true;
            }
        }
        if (prev && (*prev < 0 || *prev > pg_now)) {
            prev_unusable = true;
            prev.reset();
        }

        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES ('last_pass_now', "
            "$1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(pg_now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: meta stamp failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        // Probe by OUTCOME against the parent events table — the observation
        // projection's ttl_expires_at always mirrors its parent event's (set
        // atomically at insert), so one probe/classify decision governs both
        // tables in this guarded pass (the lockstep invariant).
        //
        // The datable horizon is derived from the CONFIGURED retention window, not
        // a fixed constant (#2663 review) — same shape as audit_store.cpp's
        // `datable_horizon = pg_now + window + kAuditTtlFutureSlackSec`: it then
        // covers every row this store's own compute_ttl_epoch() could have stamped,
        // for any retention_days_, so there is no fixed guess for an operator's
        // (unbounded) `--guardian-event-retention-days` to falsify. retention_days_
        // <= 0 is the "never expire" sentinel (compute_ttl_epoch() never stamps a
        // positive ttl_expires_at for it), mirrored here as a zero window.
        const int64_t retention_window_secs =
            retention_days_ > 0 ? static_cast<int64_t>(retention_days_) * 86400 : 0;
        const int64_t datable_horizon = pg_now + retention_window_secs + kReapTtlFutureSlackSec;
        pg::PgResult probe = pg::exec_params(
            conn,
            "SELECT count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint) "
            "AS expiring, "
            "count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at <= $2::bigint) "
            "AS datable "
            "FROM guaranteed_state_store.guaranteed_state_events",
            std::vector<std::string>{std::to_string(pg_now), std::to_string(datable_horizon)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        const int64_t expiring = to_i64(PQgetvalue(probe.get(), 0, 0));
        const int64_t datable = to_i64(PQgetvalue(probe.get(), 0, 1));

        audit_retention::Facts facts{
            .has_expired = expiring > 0,
            .would_wipe = expiring > 0 && expiring >= datable,
            .big_step = prev.has_value() && expiring > 0 &&
                        audit_retention::moved_at_least(*prev, pg_now, kReapBigStepSecs) &&
                        pg_now > *prev,
            .prev_unusable = prev_unusable,
            // #2579's missing-anchor trigger. RECORDED ANSWER (routed-concern
            // "Clock-guarded retention" part 6): decline — AuditStore's answer, not
            // ResultSetStore's. A mis-timed pass here would destroy Guardian
            // drift/remediation events and their DEX observation projection, the
            // non-regenerable compliance evidence ADR-0038 exists to bring into
            // #2508 compliance — unlike ResultSetStore's reproducible one-TTL-window
            // scratch result sets, which is why that store opts out.
            .no_anchor = !bootstrap_settled,
        };
        const auto anomaly = audit_retention::classify(facts);
        // FIVE chars — the 5th ('b') is safe to add here without the mixed-version
        // dedup hazard ResultSetStore's comment warns about: the 4-char format never
        // shipped (born-on-PG in this same PR; no deployed writer emits it).
        const std::string facts_ser = std::string(facts.has_expired ? "e" : "-") +
                                      (facts.would_wipe ? "w" : "-") +
                                      (facts.big_step ? "s" : "-") +
                                      (facts.prev_unusable ? "u" : "-") +
                                      (facts.no_anchor ? "b" : "-");

        // The pass has now REACHED A VERDICT, so settle the bootstrap marker — HERE,
        // not at the re-anchor above. The re-anchor runs before the probes, so
        // deriving the trigger from the stored reading would let a transient probe
        // failure spend it permanently: the next pass would see a reading, call
        // itself anchored, and delete with every detector false — the exact defect
        // #2579 closes. Every early return above this line rolls the whole
        // transaction back, so a pass that never reached a verdict leaves the
        // trigger armed.
        if (!bootstrap_settled) {
            pg::PgResult settle = pg::exec_params(
                conn,
                "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES "
                "('bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{});
            if (settle.status() != PGRES_COMMAND_OK) {
                spdlog::error("GuaranteedStateStore::reap_expired: bootstrap settle failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }

        if (anomaly != audit_retention::Anomaly::None) {
            if (facts_ser != last_facts) {
                // A NAME, not the enum ordinal: #2579 inserted an enumerator
                // mid-enum, so an ordinal silently renames itself across an
                // upgrade while the operator-facing string stays put.
                const char* anomaly_name = "unknown";
                switch (anomaly) {
                case audit_retention::Anomaly::None: anomaly_name = "none"; break;
                case audit_retention::Anomaly::NoAnchor: anomaly_name = "no-anchor"; break;
                case audit_retention::Anomaly::Wipe: anomaly_name = "wipe"; break;
                case audit_retention::Anomaly::Step: anomaly_name = "step"; break;
                case audit_retention::Anomaly::BadState: anomaly_name = "bad-state"; break;
                }
                if (anomaly == audit_retention::Anomaly::NoAnchor) {
                    spdlog::warn("GuaranteedStateStore::reap_expired: no usable previous "
                                 "retention clock reading and rows are already expired "
                                 "(now={} facts={}) — declining this pass and anchoring; the "
                                 "next pass has a comparison point and proceeds (#2579)",
                                 pg_now, facts_ser);
                } else {
                    spdlog::warn("GuaranteedStateStore::reap_expired: retention clock anomaly "
                                 "({} facts={}) — declining this pass; an identical next pass "
                                 "will drain, capped",
                                 anomaly_name, facts_ser);
                }
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("GuaranteedStateStore::reap_expired: anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                outcome = anomaly == audit_retention::Anomaly::NoAnchor ? "declined_no_anchor"
                                                                        : "declined";
                return true;
            }
            // Suppressed repeat of the SAME fact set — condition already
            // reported; proceed with the (capped) drain below.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM guaranteed_state_store.gc_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("GuaranteedStateStore::reap_expired: anomaly clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (expiring == 0) {
            outcome = "noop";
            return true;
        }

        // Lockstep: events AND observations reaped in the SAME guarded pass —
        // the PII projection must never outlive its parent event. Unconditional
        // per-pass cap on each (substrate-tuned: 10x ResultSetStore's cap for
        // this store's documented up-to-10k-events/s incident write volume).
        // TIEBREAKER (governance UP-1): ttl_expires_at is second-granular, so a
        // cap boundary landing inside a tied-ttl bucket would let the two
        // independent capped DELETEs pick DIFFERENT subsets — an observation
        // could then outlive its parent event. Ordering BOTH by
        // (ttl_expires_at, event_id) with the SAME cap makes only the safe
        // direction reachable: the events set's event_id domain is a superset
        // of observations', so under a shared deterministic order an
        // observation is never reaped later than its parent.
        pg::PgResult ev = pg::exec_params(
            conn,
            "DELETE FROM guaranteed_state_store.guaranteed_state_events WHERE event_id IN ("
            "SELECT event_id FROM guaranteed_state_store.guaranteed_state_events "
            "WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, event_id ASC LIMIT $2::bigint) RETURNING event_id",
            std::vector<std::string>{std::to_string(pg_now), std::to_string(kReapCapPerPass)});
        if (ev.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: events delete failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        events_deleted = PQntuples(ev.get());

        pg::PgResult obs = pg::exec_params(
            conn,
            "DELETE FROM guaranteed_state_store.guardian_observations WHERE event_id IN ("
            "SELECT event_id FROM guaranteed_state_store.guardian_observations "
            "WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, event_id ASC LIMIT $2::bigint) RETURNING event_id",
            std::vector<std::string>{std::to_string(pg_now), std::to_string(kReapCapPerPass)});
        if (obs.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: observations delete failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        observations_deleted = PQntuples(obs.get());
        outcome = "swept";
        return true;
    });

    if (!ok) {
        record_result("failed");
        spdlog::error("GuaranteedStateStore::reap_expired: pass aborted (statement failed or "
                      "txn rolled back — see the preceding error line)");
        return;
    }
    if (events_deleted > 0)
        events_reaped_.fetch_add(static_cast<uint64_t>(events_deleted), std::memory_order_relaxed);
    if (observations_deleted > 0)
        observations_reaped_.fetch_add(static_cast<uint64_t>(observations_deleted),
                                       std::memory_order_relaxed);
    record_result(outcome.c_str());
    if (events_deleted > 0 || observations_deleted > 0)
        spdlog::info("GuaranteedStateStore: reap swept {} event(s), {} observation(s)",
                     events_deleted, observations_deleted);
}

} // namespace yuzu::server
