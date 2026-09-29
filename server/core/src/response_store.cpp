#include "response_store.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_parsing.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string_view>
#include <tuple>
#include <unordered_map>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "response_store";

// Bounded acquires (ADR-0012 §2(a)). Ingest runs on the gRPC thread and must
// give up fast (fail-soft — the agent's next report re-sends, or the
// executions ladder already tracked the command). Reads back interactive
// REST/dashboard/MCP callers.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kIngestTimeout{500};

// Ingest bounds (#2691, Doomgoose finding #4): this store shares the same PG
// pool the auth/RBAC substrate leases from — an enrolled agent streaming
// large or high-cardinality output can pressure that shared pool, degrading
// auth reads, not just this store's own. `kMaxIngestBytes` matches the
// agent's own per-dispatch cap (agent.cpp's `kCaptureMaxBytes`, 2 MiB) —
// generous enough that a well-behaved agent never truncates, a backstop
// against a compromised agent binary that bypasses its own cap (the same
// premise finding #8's resolution already accepted for the NUL-density
// question). `kMaxFacetsPerResponse` bounds facet cardinality independent of
// output size — a highly-repetitive tabular output can carry many distinct
// values without approaching the byte cap.
constexpr std::size_t kMaxIngestBytes = 2ull * 1024 * 1024;
constexpr std::size_t kMaxFacetsPerResponse = 5'000;
constexpr const char* kTruncationMarker = "\n...[truncated by server ingest cap]";

// Ingest-drop / read-degrade reason labels (ADR-0037 label convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonMalformedIdentity = "malformed_identity_field";
constexpr const char* kDegradeSource = "response_store";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the
// log — the counter is the continuous signal, the log a sampled breadcrumb.
// Mirrors InventoryStore / GuaranteedStateStore's constants.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Clock-guarded retention (routed-concern invariant; #2496 gc_sweep shape,
// ADR-0038 pattern ported here per ADR-0039). Substrate-tuned: responses are
// high-write (every command result from every agent), so the per-pass cap
// matches GuaranteedStateStore's incident-volume figure rather than
// ResultSetStore's much smaller operator-scratch cap.
constexpr int64_t kReapCapPerPass = 10'000;
// The DELETE that reaps `responses` cascades to `response_facets` (ON DELETE
// CASCADE), whose fan-out per parent row is now bounded by
// kMaxFacetsPerResponse but was NOT before that fix — even bounded, up to
// kReapDeleteChunkRows * kMaxFacetsPerResponse child rows can cascade from
// one statement (#2691, Doomgoose finding #6). Chunk the parent-row delete
// into smaller statements under a wall-clock budget rather than one
// unbounded cascading DELETE: past the pool's statement timeout, an
// unchunked pass fails outright, and its deterministic ORDER BY re-selects
// the identical batch every retry — wedging retention permanently on
// exactly the backlog that most needs to drain.
constexpr int64_t kReapDeleteChunkRows = 500;
constexpr std::chrono::milliseconds kReapDeleteBudget{2000};
// #2691 Gate 5 (chaos-injector, empirically measured live against PostgreSQL
// 18.4): the parent-row LIMIT above bounds ROW COUNT, not statement latency —
// a single chunk of kReapDeleteChunkRows parent rows, each carrying up to
// kMaxFacetsPerResponse facets, can still cascade up to 2,500,000 child-row
// deletes in ONE implicit FK CASCADE statement (measured ~1929ms on an IDLE,
// uncontended database — already consuming nearly the entire
// kReapDeleteBudget in one statement with zero of the concurrent-write
// friction a real deployment adds). Past the connection's statement_timeout,
// that single statement fails outright, `with_txn_for` rolls back the WHOLE
// pass (every earlier chunk in it too), and the deterministic ORDER BY
// re-selects the identical backlog next pass — a self-sustaining wedge on
// exactly the backlog that most needs to drain. Fix: pre-delete
// response_facets for a chunk's ids in THEIR OWN small LIMIT-bounded batches
// (FK CASCADE has no native LIMIT, a plain DELETE does via the same
// subquery-LIMIT idiom the parent-row delete already uses) so no single
// statement's size depends on how many facets happen to land in one chunk —
// by the time the parent-row DELETE runs, its CASCADE is trivial.
constexpr int64_t kReapFacetDeleteBatchRows = 5'000;
constexpr int64_t kReapBigStepSecs = 86'400; // part 7: absolute, ~1 day
// The implausibly-ahead bound (part 1) MUST exceed the legitimate TTL horizon
// or a live row's own honest ttl_expires_at gets misclassified as
// "implausibly ahead" and wrongly excluded from `datable` — flipping a
// normal partial-expiry pass into a false would_wipe decline (the ADR-0038
// lesson: this bound must be sized to THIS store's retention, never copied
// from a shorter-TTL sibling). `response_retention_days` is operator-
// configurable and UNCLAMPED (a compliance deployment may set it well above
// the 90-day default), so a FIXED constant would silently reintroduce the
// false-decline class the moment retention passes the constant — the whole
// live set would land past the bound and every pass would decline, so the
// table would never reap. The bound is therefore DERIVED from the store's own
// horizon at 2× (the ADR-0038 "size to THIS store's retention" rule taken
// literally), with a floor so a tiny/zero retention still catches genuinely
// corrupt/attacker-skewed far-future timestamps.
constexpr int64_t kReapImplausiblyAheadFloorSecs = 10'368'000; // ~120 days

// EXISTS, NOT `count(*) FILTER (...)` (#2691, Doomgoose review + Sol plan
// review): the counting form has no statement-level WHERE, so every row —
// including the `ttl_expires_at = 0` majority, which sits outside the
// partial index `idx_resp_ttl ... WHERE ttl_expires_at > 0` — must be
// visited before either count is known: a full scan on every hourly pass,
// on the store's highest-write table. EXISTS carries the `> 0` predicate
// into the index and stops at the first matching row. The survivor half is
// `ORDER BY ttl_expires_at LIMIT 1 ... IS NOT NULL` rather than a second
// bare EXISTS, matching `audit_store.hpp`'s `kAuditRetentionProbeSql` shape
// and its own comment on why: a bare `EXISTS(range-cond)` gives the planner
// no signal beyond the range's estimated selectivity, which a wide
// retention window (`response_retention_days` is operator-unclamped) with
// sparse real matches at the tail can get wrong; ordering by the partial
// index's leading column plus a LIMIT is plan-independent regardless.
constexpr std::string_view kResponseRetentionProbeSql =
    "SELECT EXISTS(SELECT 1 FROM response_store.responses WHERE ttl_expires_at > 0 AND "
    "ttl_expires_at < $1::bigint), (SELECT 1 FROM response_store.responses WHERE "
    "ttl_expires_at > 0 AND ttl_expires_at >= $1::bigint AND ttl_expires_at <= $2::bigint "
    "ORDER BY ttl_expires_at LIMIT 1) IS NOT NULL";

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

// sanitize_utf8_strict (utf8_sanitize.hpp) scrubs invalid UTF-8 to U+FFFD but
// treats NUL (U+0000) as a valid ASCII byte and keeps it. PostgreSQL TEXT cannot
// store an embedded NUL, and libpq's text-format bind (paramLengths=nullptr)
// C-string-truncates the value at the first NUL — silently dropping everything
// after it (Gate 4 R3). On binary / mis-decoded plugin output that carries a
// 0x00 (the ADR's own motivating case) that would partially defeat #1593 (a
// real result must surface, defanged, never vanish) AND diverge the stored
// `output` from the facets derived off the same string. So after the UTF-8
// scrub, replace every NUL with U+FFFD too: the whole value survives to PG and
// facets stay byte-consistent with `output`. We do NOT touch utf8_sanitize.hpp
// itself — it is byte-identical with the agent's installed_software copy (the
// canonical-hash invariant); NUL handling is a PG-bind concern local to this
// store.
std::string sanitize_pg_text(std::string_view s) {
    std::string scrubbed = sanitize_utf8_strict(s);
    // Single reserve-and-append pass (#2691, Doomgoose finding #8): the
    // previous find+replace loop shifted every trailing byte on each NUL hit
    // (1 byte -> 3), an O(k*n) rebuild in NUL count x length for a NUL-dense
    // string. Count once, reserve the final size, then copy the segments
    // between NULs directly — no in-place shifting.
    const std::size_t nul_count =
        static_cast<std::size_t>(std::count(scrubbed.begin(), scrubbed.end(), '\0'));
    if (nul_count == 0)
        return scrubbed;
    std::string out;
    out.reserve(scrubbed.size() + nul_count * 2); // each NUL grows 1 byte -> 3
    std::size_t start = 0;
    for (std::size_t i = 0; i < scrubbed.size(); ++i) {
        if (scrubbed[i] == '\0') {
            out.append(scrubbed, start, i - start);
            out.append("\xEF\xBF\xBD");
            start = i + 1;
        }
    }
    out.append(scrubbed, start, scrubbed.size() - start);
    return out;
}

// #2691 (Gate 4 unhappy-path finding UP-5, widened to agent_id by Gate 8
// security-guardian): `instruction_id`/`execution_id`/`plugin`/`agent_id`
// are deliberately NOT run through sanitize_pg_text — ADR-0039's documented
// rationale is that a malformed value simply fail-soft-drops the whole row
// at INSERT (SQLSTATE 22021, invalid UTF-8). That rationale covers invalid
// UTF-8 but not an embedded NUL: NUL is valid UTF-8, so the INSERT does not
// reject it, but `pg::exec_params` binds every parameter as a NUL-terminated
// C string (paramLengths=nullptr) — libpq silently TRUNCATES the value at
// the first NUL instead of failing. An agent-controlled `command_id`
// containing an embedded NUL (`agent_service_impl.cpp`'s
// `sr.instruction_id = resp.command_id()`, unsanitized) could therefore be
// stored truncated to a shorter, real instruction_id it was never dispatched
// for — indistinguishable from a genuine response once truncated. The same
// mechanism applies to `agent_id`: `AgentServiceImpl::Register()` validates
// length and non-emptiness but not embedded-NUL, so a maliciously-enrolled
// device could have its responses land, truncated, under a shorter real
// device's agent_id in both `responses` and `response_facets`. Six sibling
// stores (auth_db, audit_store, instruction_store, instruction_yaml,
// guaranteed_state_store, scim_json, vuln_finding_store) already guard their
// own identity-bearing fields against embedded NUL this same way; this store
// never got the guard. Reject (fail-soft-drop, counted) rather than
// truncate-silently — matches ADR-0039's own stated intent for malformed
// identity fields.
bool has_embedded_nul(std::string_view s) {
    return s.find('\0') != std::string_view::npos;
}

// #2691 (Doomgoose finding #4): bound ingest volume before it reaches the
// shared PG pool. Truncates on the RAW byte string, before sanitize_pg_text —
// a truncation mid-UTF-8-sequence is exactly what sanitize_utf8_strict
// already scrubs to U+FFFD, so ordering this first costs nothing extra.
std::string truncate_ingest(std::string_view s, std::size_t max_bytes) {
    if (s.size() <= max_bytes)
        return std::string(s);
    return std::string(s.substr(0, max_bytes)) + kTruncationMarker;
}

double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    return std::strtod(s, nullptr);
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// `PQcmdTuples` — safe here because the connection is exclusively ours for
// the duration of the call (a pooled lease, never shared concurrently) —
// mirrors InventoryStore's `affected_rows` (the #1033 `sqlite3_changes()`
// replacement idiom).
std::int64_t affected_rows(const pg::PgResult& res) {
    const char* txt = PQcmdTuples(res.get());
    if (!txt || txt[0] == '\0')
        return 0;
    return std::strtoll(txt, nullptr, 10);
}

// ── Read-degrade observability ───────────────────────────────────────────────
// Mirrors InventoryStore / GuaranteedStateStore's DegradeSampler shape
// exactly (docs/postgres-store-playbook.md). One static sampler per read call
// site (declared `static DegradeSampler sampler;` inside each method) gates
// the sampled warn log; the Prometheus counter always increments.
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics
            ->counter("yuzu_server_response_read_degrade_total",
                      {{"reason", reason}, {"source", kDegradeSource}})
            .increment();
    const std::int64_t now = now_epoch();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

void note_ingest_dropped(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_response_ingest_dropped_total", {{"reason", reason}})
            .increment();
}

// Shared body for every degrade-distinguishable read (ADR-0039, mirrors
// GuaranteedStateStore's `dex_read<Result>` template — adapted to return
// `std::optional<Result>` since ResponseStore's reads are nullopt-on-degrade,
// not empty-on-degrade): acquire a bounded lease, run `body(conn)` (executes
// the query and returns the parsed result, or nullopt on a query-level
// failure), and count+sampled-log a degrade on store-not-open / pool-timeout
// / query-error. A successful EMPTY container is NOT a degrade — only
// `body()` returning nullopt is.
template <typename Result, typename Body>
std::optional<Result> resp_read(bool open, pg::PgPool& pool, yuzu::MetricsRegistry* metrics,
                                const char* method, DegradeSampler& sampler, Body&& body) {
    if (!open) {
        if (const auto d = note_read_degrade(metrics, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: store not open", method);
        return std::nullopt;
    }
    auto lease = pool.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: pool acquire timed out", method);
        return std::nullopt;
    }
    auto result = body(lease.get());
    if (!result) {
        if (const auto d = note_read_degrade(metrics, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: query failed", method);
        return std::nullopt;
    }
    return std::move(*result);
}

// ── Postgres schema (ADR-0039): the FINAL column set of the SQLite store's 3
// migrations, collapsed into one v1. Unqualified DDL — the migration runner
// sets search_path to `response_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE responses (
                id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                instruction_id  TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                timestamp       BIGINT  NOT NULL,
                status          INTEGER NOT NULL,
                output          TEXT    NOT NULL,
                error_detail    TEXT    NOT NULL DEFAULT '',
                ttl_expires_at  BIGINT  NOT NULL DEFAULT 0,
                plugin          TEXT    NOT NULL DEFAULT '',
                execution_id    TEXT    NOT NULL DEFAULT '',
                received_at_ms  BIGINT  NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_resp_instr_ts ON responses(instruction_id, timestamp);
            CREATE INDEX idx_resp_agent_ts ON responses(agent_id, timestamp);
            CREATE INDEX idx_resp_ttl ON responses(ttl_expires_at) WHERE ttl_expires_at > 0;
            CREATE INDEX idx_resp_instr_status ON responses(instruction_id, status);
            CREATE INDEX idx_resp_execution_ts
                ON responses(execution_id, timestamp) WHERE execution_id != '';

            -- ON DELETE CASCADE: a facet row never outlives its parent response
            -- (the SQLite original had no FK and swept orphans with a second
            -- NOT-IN scan on every cleanup pass; the FK removes that need).
            -- #2691 Gate 8 correction: reap_expired() does NOT rely on this
            -- CASCADE alone for bulk expiry — a single chunked parent DELETE
            -- left to CASCADE could fan out up to kReapDeleteChunkRows *
            -- kMaxFacetsPerResponse child-row deletes in one statement
            -- (measured ~1929ms for the max-cardinality case, chaos Gate 5).
            -- reap_expired() explicitly PRE-DRAINS response_facets in bounded
            -- batches before each parent-row chunk delete; by the time the
            -- parent DELETE runs, this CASCADE has nothing left to do for a
            -- bulk-reap pass. It still fires normally for any OTHER delete
            -- path (an operator/API single-row delete, if one is ever added)
            -- — do not remove it, and do not "simplify" reap_expired() back
            -- to a bare parent-row DELETE relying on this comment's old
            -- claim.
            CREATE TABLE response_facets (
                response_id    BIGINT  NOT NULL REFERENCES responses(id) ON DELETE CASCADE,
                instruction_id TEXT    NOT NULL,
                agent_id       TEXT    NOT NULL,
                col_idx        INTEGER NOT NULL,
                value          TEXT    NOT NULL,
                line_count     INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (response_id, col_idx, value)
            );
            CREATE INDEX idx_facets_query ON response_facets(instruction_id, col_idx, value);
            CREATE INDEX idx_facets_agent ON response_facets(instruction_id, agent_id);

            -- Durable state for the reap_expired() clock-guard (#2496 shape,
            -- ADR-0038 pattern). SHARED rows (not process-local) — N server
            -- replicas each run the sweep, so the persisted reading + anomaly-
            -- dedup fact set must be one shared truth under the sweep's
            -- advisory lock.
            CREATE TABLE gc_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // v2 (PR1.1 — ABI4 CC-07 result seam): plugin-reported typed status,
        // mirroring agent.proto CommandResponse.plugin_result_status. Default
        // 0 = PLUGIN_RESULT_UNDECLARED, exactly what a legacy row (and any
        // response whose plugin never reported a typed status) should read as.
        // Landed as a NEW migration, not folded into v1's CREATE TABLE:
        // PgMigrationRunner stamps schema_meta(store, version) once per
        // numbered migration and never replays a modified one, so editing
        // v1 in place would silently no-op on any database that already
        // ran this store's migrations (#2691, Sol plan review).
        {2, R"(
            ALTER TABLE responses ADD COLUMN plugin_result_status INTEGER NOT NULL DEFAULT 0;
        )"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ResponseStore::ResponseStore(pg::PgPool& pool, int retention_days,
                             std::function<int64_t()> now_fn)
    : pool_(pool), retention_days_(retention_days), now_fn_(std::move(now_fn)) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ResponseStore: no database connection at construction ({}) — response "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ResponseStore: schema migration failed — response persistence disabled");
        return;
    }
    open_ = true;
    spdlog::info("ResponseStore initialized (schema {}, retention={}d)", kStoreName,
                retention_days_);
}

int64_t ResponseStore::compute_ttl_epoch() const {
    if (retention_days_ <= 0)
        return 0; // sentinel: never expire
    // Accepted residual (#2691, Sol plan review): this reads the INGEST
    // replica's own process clock, not PostgreSQL's. A slow replica can
    // still stamp early default-expiry on a subset of rows at insert time —
    // unlike reap_expired()'s clock-guard above, this is an ingest-time
    // skew, not a delete-time false verdict, and once stamped it reads to
    // the guarded reaper as ordinary partial expiry (no anomaly). Lower
    // stakes than the reap-side defect this PR fixes; not addressed here.
    return now_epoch() + static_cast<int64_t>(retention_days_) * 86400;
}

// ── Ingest (fail-soft) ────────────────────────────────────────────────────────

void ResponseStore::store(const StoredResponse& resp) {
    if (!open_) {
        note_ingest_dropped(metrics_, kReasonStoreNotOpen);
        return;
    }

    // #2691 (UP-5, widened by Gate 8 security-guardian): reject before
    // binding — see has_embedded_nul's doc comment. instruction_id/
    // execution_id/plugin/agent_id are all bound unsanitized; a
    // truncate-on-bind is a silent identity collision, not a safe default.
    // agent_id shares the identical hazard: Register() validates length and
    // non-emptiness but not embedded-NUL, so a maliciously-enrolled agent
    // could otherwise have its responses land, truncated, under a shorter
    // real device's agent_id in BOTH `responses` and `response_facets`.
    if (has_embedded_nul(resp.instruction_id) || has_embedded_nul(resp.execution_id) ||
        has_embedded_nul(resp.plugin) || has_embedded_nul(resp.agent_id)) {
        spdlog::warn("ResponseStore: dropping response with an embedded NUL byte in "
                     "instruction_id/execution_id/plugin/agent_id (agent={})",
                     resp.agent_id);
        note_ingest_dropped(metrics_, kReasonMalformedIdentity);
        return;
    }

    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    const int64_t now = now_ms / 1000;
    const int64_t ts = resp.timestamp > 0 ? resp.timestamp : now;
    const int64_t ttl = resp.ttl_expires_at > 0 ? resp.ttl_expires_at : compute_ttl_epoch();
    const int64_t received_ms = resp.received_at_ms > 0 ? resp.received_at_ms : now_ms;

    // Bound ingest volume BEFORE sanitizing (#2691, Doomgoose finding #4):
    // this store shares the PG pool the auth/RBAC substrate leases from, so
    // an agent (compromised or misbehaving) streaming output past its own
    // dispatch cap must not be able to pressure that shared pool. Matches
    // the agent's own per-dispatch cap (agent.cpp's kCaptureMaxBytes) — a
    // well-behaved agent never truncates here.
    const std::string bounded_output = truncate_ingest(resp.output, kMaxIngestBytes);
    const std::string bounded_error = truncate_ingest(resp.error_detail, kMaxIngestBytes);

    // ADR-0039 addendum: `output`/`error_detail` are untrusted agent-supplied
    // bytes — a plugin can emit arbitrary (non-UTF-8) content, which SQLite's
    // permissive TEXT affinity tolerated but Postgres TEXT rejects outright
    // (SQLSTATE 22021, invalid byte sequence for encoding UTF8). Sanitize to
    // U+FFFD BEFORE binding so the row still lands (governance #1593: a
    // malformed-but-real plugin result must still surface to the operator,
    // defanged, never silently vanish) — fail-soft stays reserved for genuine
    // infra errors, not a self-inflicted encoding rejection. Every other
    // ingest seam on untrusted text (inventory, app_perf, …) sanitizes the
    // same way before its own PG bind; `sanitize_utf8_strict` is the shared
    // implementation (utf8_sanitize.hpp).
    const std::string sanitized_output = sanitize_pg_text(bounded_output);
    const std::string sanitized_error = sanitize_pg_text(bounded_error);

    // `with_txn_for` (not a manual BEGIN/PgTxn pair, #2691 Doomgoose finding
    // #1) refuses to COMMIT an aborted transaction: a failed SAVEPOINT/
    // ROLLBACK-TO below left unnoticed would otherwise let a plain COMMIT
    // report PGRES_COMMAND_OK while Postgres actually performed a ROLLBACK
    // (PQTRANS_INERROR), silently dropping the response row with no counter.
    // `reached_txn` distinguishes "never got a connection" (kReasonPoolTimeout)
    // from "began, but something inside failed" (kReasonQueryError) — the
    // pool/BEGIN failure classes with_txn_for's own bool return collapses.
    bool reached_txn = false;
    const bool ok = pool_.with_txn_for(kIngestTimeout, [&](PGconn* conn) -> bool {
        reached_txn = true;
        pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, status, "
        "output, error_detail, ttl_expires_at, plugin, execution_id, received_at_ms, "
        "plugin_result_status) "
        "VALUES ($1,$2,$3::bigint,$4::integer,$5,$6,$7::bigint,$8,$9,$10::bigint,$11::integer) "
        "RETURNING id",
        std::vector<std::string>{resp.instruction_id, resp.agent_id, std::to_string(ts),
                                 std::to_string(resp.status), sanitized_output, sanitized_error,
                                 std::to_string(ttl), resp.plugin, resp.execution_id,
                                 std::to_string(received_ms),
                                 std::to_string(resp.plugin_result_status)});
        if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) != 1) {
            spdlog::warn("ResponseStore: insert failed for instruction={} agent={}: {}",
                         resp.instruction_id, resp.agent_id, PQerrorMessage(conn));
            return false; // with_txn_for rolls back
        }
        const int64_t response_id = to_i64(PQgetvalue(ins.get(), 0, 0));

        // Extract facets from the output using the plugin schema, then insert
        // them as a SINGLE batched multi-row INSERT under ONE savepoint. The
        // savepoint preserves the ADR-0038 guarantee (Postgres aborts the
        // WHOLE transaction on any failed statement, unlike SQLite's silent
        // skip — so a facet failure must not take the just-inserted response
        // row down): on batch failure we ROLLBACK TO this savepoint and
        // still COMMIT the response row. But it is ONE savepoint, not
        // one-per-facet: the old per-facet loop minted a subtransaction XID
        // per distinct value, so a wide tabular output (>64 distinct facet
        // values — a routine process/vuln list) suboverflowed the ingest
        // txn's snapshot and forced cluster-wide pg_subtrans SLRU lookups on
        // the SHARED server pool (Gate 4 R1). One savepoint bounds it to a
        // single subxid regardless of facet cardinality.
        if (!resp.plugin.empty() && !sanitized_output.empty()) {
            auto lines = split_output_lines(sanitized_output);
            // Accumulate (col_idx, value) → line_count. col_idx is 0-based
            // offset into the *field* array (excludes the Agent column,
            // always column 0 in the schema).
            std::unordered_map<int, std::unordered_map<std::string, int>> facets;
            for (const auto& line : lines) {
                auto fields = split_fields(resp.plugin, line);
                for (int i = 0; i < static_cast<int>(fields.size()); ++i) {
                    if (!fields[i].empty())
                        facets[i][fields[i]]++;
                }
            }
            std::vector<std::tuple<int, std::string, int>> flat;
            for (const auto& [col_idx, value_counts] : facets)
                for (const auto& [value, count] : value_counts)
                    flat.emplace_back(col_idx, value, count);

            // Bound facet cardinality independently of output size (#2691,
            // Doomgoose finding #4) — a highly-repetitive tabular output can
            // carry many distinct values without approaching the byte cap
            // above. Deterministic truncation (not a random subset) so a
            // repeated ingest of the same over-wide output truncates the
            // same facets every time, rather than jittering which columns
            // the dashboard's facet filter can see.
            if (flat.size() > kMaxFacetsPerResponse) {
                spdlog::warn("ResponseStore: response_id={} facet count ({}) exceeds the "
                            "per-response cap ({}); only the first {} persist",
                            response_id, flat.size(), kMaxFacetsPerResponse,
                            kMaxFacetsPerResponse);
                flat.resize(kMaxFacetsPerResponse);
            }

            if (!flat.empty()) {
                pg::PgResult sp =
                    pg::exec_params(conn, "SAVEPOINT facet_batch", std::vector<std::string>{});
                if (sp.status() != PGRES_COMMAND_OK) {
                    spdlog::warn("ResponseStore: facet SAVEPOINT failed for response_id={}: {}",
                                 response_id, PQerrorMessage(conn));
                } else {
                    bool facets_ok = true;
                    // Chunk so `3 + 3*chunk` stays well under libpq's
                    // 65535-param ceiling; response_id/instruction_id/
                    // agent_id are $1/$2/$3 reused across every tuple, only
                    // (col_idx,value,count) vary.
                    constexpr std::size_t kFacetChunk = 2000;
                    for (std::size_t base = 0; facets_ok && base < flat.size();
                         base += kFacetChunk) {
                        const std::size_t stop = std::min(base + kFacetChunk, flat.size());
                        std::string sql =
                            "INSERT INTO response_store.response_facets (response_id, "
                            "instruction_id, agent_id, col_idx, value, line_count) VALUES ";
                        std::vector<std::string> params{std::to_string(response_id),
                                                        resp.instruction_id, resp.agent_id};
                        for (std::size_t i = base; i < stop; ++i) {
                            const auto& [col_idx, value, count] = flat[i];
                            const std::size_t p = params.size(); // 0-based; next is $(p+1)
                            if (i != base)
                                sql += ",";
                            sql += "($1::bigint,$2,$3,$" + std::to_string(p + 1) +
                                   "::integer,$" + std::to_string(p + 2) + ",$" +
                                   std::to_string(p + 3) + "::integer)";
                            params.push_back(std::to_string(col_idx));
                            params.push_back(value);
                            params.push_back(std::to_string(count));
                        }
                        sql += " ON CONFLICT (response_id, col_idx, value) DO UPDATE SET "
                               "line_count = EXCLUDED.line_count";
                        pg::PgResult fi = pg::exec_params(conn, sql.c_str(), params);
                        if (fi.status() != PGRES_COMMAND_OK) {
                            spdlog::warn("ResponseStore: facet batch insert failed for "
                                        "response_id={}: {}",
                                        response_id, PQerrorMessage(conn));
                            facets_ok = false;
                        }
                    }
                    const char* fin_sql = facets_ok ? "RELEASE SAVEPOINT facet_batch"
                                                    : "ROLLBACK TO SAVEPOINT facet_batch";
                    pg::PgResult fin = pg::exec_params(conn, fin_sql, std::vector<std::string>{});
                    if (fin.status() != PGRES_COMMAND_OK)
                        spdlog::warn("ResponseStore: facet savepoint finalize ({}) failed for "
                                    "response_id={}: {}",
                                    fin_sql, response_id, PQerrorMessage(conn));
                }
            }
        }
        return true;
    });

    if (!ok) {
        spdlog::warn("ResponseStore: store failed for instruction={} agent={}: {}",
                     resp.instruction_id, resp.agent_id, pool_.last_error());
        note_ingest_dropped(metrics_, reached_txn ? kReasonQueryError : kReasonPoolTimeout);
    }
}

ResponseStore::FinalizeResult ResponseStore::finalize_terminal_status(
    const std::string& instruction_id, const std::string& agent_id, int terminal_status,
    const std::string& error_detail, const std::string& execution_id,
    int plugin_result_status) {
    if (!open_)
        return FinalizeResult::Error;
    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease) {
        spdlog::error("ResponseStore::finalize_terminal_status: no connection: {}",
                      pool_.last_error());
        return FinalizeResult::Error;
    }
    // Sanitize the untrusted error message the SAME way store() sanitizes
    // output/error_detail (Gate 2 security MEDIUM): error_detail here is
    // resp.error().message() from the agent, so a non-UTF-8 byte would fail
    // the UPDATE (PG TEXT / SQLSTATE 22021), leaving the RUNNING row never
    // finalized and no fallback frame — the #1593 "real result must surface"
    // gap, reopened on the finalize path. U+FFFD-defang (incl. NUL, see
    // sanitize_pg_text) keeps the finalize landing.
    const std::string sanitized_error = sanitize_pg_text(error_detail);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE response_store.responses SET status = $1::integer, error_detail = $2, "
        "plugin_result_status = $3::integer "
        "WHERE instruction_id = $4 AND agent_id = $5 AND status = 0 AND execution_id = $6",
        std::vector<std::string>{std::to_string(terminal_status), sanitized_error,
                                 std::to_string(plugin_result_status), instruction_id, agent_id,
                                 execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("ResponseStore::finalize_terminal_status: update failed: {}",
                      PQerrorMessage(lease.get()));
        return FinalizeResult::Error;
    }
    return affected_rows(res) > 0 ? FinalizeResult::Updated : FinalizeResult::NoRow;
}

// ── Reads (degrade-distinguishable) ──────────────────────────────────────────

namespace {

// Shared row-parse for the `responses` SELECT column list used by every
// query-style read below.
StoredResponse parse_response_row(PGresult* res, int row) {
    StoredResponse r;
    r.id = to_i64(PQgetvalue(res, row, 0));
    r.instruction_id = text_col(res, row, 1);
    r.agent_id = text_col(res, row, 2);
    r.timestamp = to_i64(PQgetvalue(res, row, 3));
    r.status = static_cast<int>(to_i64(PQgetvalue(res, row, 4)));
    r.output = text_col(res, row, 5);
    r.error_detail = text_col(res, row, 6);
    r.ttl_expires_at = to_i64(PQgetvalue(res, row, 7));
    r.plugin = text_col(res, row, 8);
    r.execution_id = text_col(res, row, 9);
    r.received_at_ms = to_i64(PQgetvalue(res, row, 10));
    r.plugin_result_status = static_cast<int>(to_i64(PQgetvalue(res, row, 11)));
    return r;
}

constexpr const char* kResponseCols =
    "id, instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at, "
    "plugin, execution_id, received_at_ms, COALESCE(plugin_result_status, 0)";

// A non-positive `limit` (e.g. a client-supplied -1) bound raw into `LIMIT
// $N` is not a benign empty query — Postgres rejects a negative LIMIT
// outright, so the statement fails and the caller reads a genuine PG error
// as store degradation (#2691, Doomgoose finding #2). Sanitize at the one
// point every query-style read shares rather than at each of the ~10 REST/
// MCP call sites that populate `ResponseQuery::limit` from client input —
// one fix covers every current AND future caller. Falls back to the
// struct's own documented default (100), matching how limits are already
// clamped (not rejected) elsewhere on this surface (e.g. mcp_server.cpp's
// `std::min(param_int32(args, "limit", 100), 1000)`).
int sanitize_limit(int limit) {
    return limit > 0 ? limit : ResponseQuery{}.limit; // struct default (100)
}

// Appends `AND agent_id = ANY($n::text[])` / `AND 1=0` to `sql` (advancing
// `idx`/`binds` past whatever it binds), or does nothing when `scope` is
// unrestricted (nullopt). MUST be called before `ORDER BY`/`LIMIT`/`OFFSET`
// or `GROUP BY` — ADR-0017 INV-3 (CRITICAL): a paginated/aggregated read
// that filters after LIMIT can hand a confined caller a short or empty page
// even though visible rows exist past the ones a post-fetch filter dropped.
// One array bind regardless of set size (mirrors `facet_values`/
// `facet_agent_count` above) — an earlier version of this helper bound one
// placeholder per agent behind a 10,000-agent cap and silently truncated
// (and, for `aggregate`, silently under-counted) past it; `pg::to_text_array`
// removes the cap rather than raising it.
void append_scope_clause(std::string& sql, std::vector<std::string>& binds, int& idx,
                         const AggregateScope& scope) {
    if (!scope.has_value())
        return;
    const auto& allowed = *scope;
    if (allowed.empty()) {
        sql += " AND 1=0"; // visible to no one → exclude every row
        return;
    }
    std::vector<std::string_view> sv(allowed.begin(), allowed.end());
    sql += " AND agent_id = ANY($" + std::to_string(idx++) + "::text[])";
    binds.push_back(pg::to_text_array(sv));
}

} // namespace

std::optional<std::vector<StoredResponse>> ResponseStore::query(const std::string& instruction_id,
                                                                 const ResponseQuery& q,
                                                                 const AggregateScope& scope) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query", sampler, [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(q.agent_id);
            }
            if (q.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.status));
            }
            if (q.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.since));
            }
            if (q.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.until));
            }
            append_scope_clause(sql, binds, idx, scope);
            sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::integer";
            binds.push_back(std::to_string(sanitize_limit(q.limit)));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::query_by_execution(const std::string& execution_id, const ResponseQuery& q,
                                  const AggregateScope& scope) const {
    static DegradeSampler sampler;
    if (execution_id.empty()) {
        // arch-B1 (ported): empty execution_id is the legacy sentinel and
        // indicates a caller bug rather than a legitimate empty-result query.
        // Engaged-empty, not a degrade.
        return std::vector<StoredResponse>{};
    }
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query_by_execution", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE execution_id = $1";
            std::vector<std::string> binds{execution_id};
            int idx = 2;
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(q.agent_id);
            }
            if (q.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.status));
            }
            if (q.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.since));
            }
            if (q.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.until));
            }
            append_scope_clause(sql, binds, idx, scope);
            sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::integer";
            binds.push_back(std::to_string(sanitize_limit(q.limit)));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::get_by_instruction(const std::string& instruction_id) const {
    return query(instruction_id);
}

const std::vector<std::string>& ResponseStore::allowed_group_by() {
    static const std::vector<std::string> v = {"status", "agent_id"};
    return v;
}

const std::vector<std::string>& ResponseStore::allowed_op_column() {
    static const std::vector<std::string> v = {"timestamp", "status", "id"};
    return v;
}

std::optional<std::vector<AggregationResult>>
ResponseStore::aggregate(const std::string& instruction_id, const AggregationQuery& aq,
                         const ResponseQuery& filter, const AggregateScope& scope) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<AggregationResult>>(
        open_, pool_, metrics_, "aggregate", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<AggregationResult>> {
            const auto& allowed_group = allowed_group_by();
            if (std::find(allowed_group.begin(), allowed_group.end(), aq.group_by) ==
                allowed_group.end()) {
                spdlog::warn("ResponseStore::aggregate: invalid group_by '{}'", aq.group_by);
                return std::nullopt; // allow-list miss is a caller/code bug, not a real
                                     // empty result — degrade-distinguish it (Gate 4 R5)
                                     // so the seam's empty-vs-degrade discipline holds.
                                     // Route handlers validate against
                                     // allowed_group_by()/allowed_op_column() BEFORE
                                     // calling in (#2691) so a client typo never
                                     // reaches this fallback as a 503.
            }
            const auto& allowed_op_col = allowed_op_column();
            auto effective_op_col = aq.op_column.empty() ? "id" : aq.op_column;
            if (std::find(allowed_op_col.begin(), allowed_op_col.end(), effective_op_col) ==
                allowed_op_col.end()) {
                spdlog::warn("ResponseStore::aggregate: invalid op_column '{}'", effective_op_col);
                return std::nullopt; // as above (Gate 4 R5)
            }

            std::string agg_func;
            switch (aq.op) {
            case AggregateOp::Count: agg_func = "COUNT(*)"; break;
            case AggregateOp::Sum: agg_func = "SUM(" + effective_op_col + ")"; break;
            case AggregateOp::Avg: agg_func = "AVG(" + effective_op_col + ")"; break;
            case AggregateOp::Min: agg_func = "MIN(" + effective_op_col + ")"; break;
            case AggregateOp::Max: agg_func = "MAX(" + effective_op_col + ")"; break;
            }

            std::string sql = "SELECT " + aq.group_by + "::text, COUNT(*), " + agg_func +
                              "::double precision FROM response_store.responses WHERE "
                              "instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;

            if (!filter.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(filter.agent_id);
            }
            // #1634 management-group scope (filter-BEFORE-aggregate).
            append_scope_clause(sql, binds, idx, scope);
            if (filter.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(filter.status));
            }
            if (filter.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(filter.since));
            }
            if (filter.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(filter.until));
            }
            sql += " GROUP BY " + aq.group_by + " ORDER BY COUNT(*) DESC";

            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<AggregationResult> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i) {
                AggregationResult r;
                r.group_value = text_col(res.get(), i, 0);
                r.count = to_i64(PQgetvalue(res.get(), i, 1));
                r.aggregate_value = to_double(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(r));
            }
            return out;
        });
}

std::optional<std::vector<std::string>>
ResponseStore::distinct_agent_ids(const std::string& instruction_id) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<std::string>>(
        open_, pool_, metrics_, "distinct_agent_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<std::string>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT DISTINCT agent_id FROM response_store.responses WHERE instruction_id = "
                "$1 ORDER BY agent_id",
                std::vector<std::string>{instruction_id});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<std::string> ids;
            ids.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                ids.push_back(text_col(res.get(), i, 0));
            return ids;
        });
}

std::optional<std::vector<std::string>>
ResponseStore::distinct_agent_ids_by_execution(const std::string& execution_id) const {
    static DegradeSampler sampler;
    if (execution_id.empty())
        return std::vector<std::string>{}; // arch-B1 sentinel, see query_by_execution
    return resp_read<std::vector<std::string>>(
        open_, pool_, metrics_, "distinct_agent_ids_by_execution", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<std::string>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT DISTINCT agent_id FROM response_store.responses WHERE execution_id = "
                "$1 ORDER BY agent_id",
                std::vector<std::string>{execution_id});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<std::string> ids;
            ids.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                ids.push_back(text_col(res.get(), i, 0));
            return ids;
        });
}

std::size_t ResponseStore::total_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT COUNT(*) FROM response_store.responses",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// -- Faceted query methods -----------------------------------------------------

std::optional<std::vector<FacetValue>>
ResponseStore::facet_values(const std::string& instruction_id, int col_idx,
                            const std::optional<std::vector<std::string>>& agent_scope) const {
    // Engaged-empty scope (ADR-0017 INV-3 / #1712): zero visible agents means
    // zero facet values, without touching the pool or issuing a query —
    // success-empty, not degrade, even when the store is closed (#2691
    // degrade-vs-empty distinguishability).
    if (agent_scope.has_value() && agent_scope->empty())
        return std::vector<FacetValue>{};
    static DegradeSampler sampler;
    return resp_read<std::vector<FacetValue>>(
        open_, pool_, metrics_, "facet_values", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<FacetValue>> {
            std::string sql =
                "SELECT value, SUM(line_count) FROM response_store.response_facets WHERE "
                "instruction_id = $1 AND col_idx = $2::integer";
            std::vector<std::string> binds{instruction_id, std::to_string(col_idx)};
            if (agent_scope.has_value()) {
                // ADR-0017 INV-3: the visible set is applied IN SQL, before
                // the aggregate — never a C++ post-filter.
                std::vector<std::string_view> sv(agent_scope->begin(), agent_scope->end());
                sql += " AND agent_id = ANY($3::text[])";
                binds.push_back(pg::to_text_array(sv));
            }
            sql += " GROUP BY value ORDER BY SUM(line_count) DESC";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<FacetValue> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i) {
                FacetValue fv;
                fv.value = text_col(res.get(), i, 0);
                fv.line_count = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(fv));
            }
            return out;
        });
}

namespace {
// Shared filter-subquery builder for the facet_* methods below — one
// "response_id IN (SELECT response_id FROM response_facets WHERE
// instruction_id = $k AND col_idx = $k+1 AND value = $k+2)" clause per
// filter, ANDed together (intersection). Mirrors the SQLite original.
void append_facet_filters(std::string& sql, std::vector<std::string>& binds, int& idx,
                          const std::string& instruction_id,
                          const std::vector<FacetFilter>& filters) {
    for (const auto& f : filters) {
        const int p1 = idx++;
        const int p2 = idx++;
        const int p3 = idx++;
        sql += " AND response_id IN (SELECT response_id FROM response_store.response_facets "
               "WHERE instruction_id = $" +
               std::to_string(p1) + " AND col_idx = $" + std::to_string(p2) +
               "::integer AND value = $" + std::to_string(p3) + ")";
        binds.push_back(instruction_id);
        binds.push_back(std::to_string(f.col_idx));
        binds.push_back(f.value);
    }
}
} // namespace

std::optional<std::vector<std::string>>
ResponseStore::facet_agent_ids(const std::string& instruction_id,
                               const std::vector<FacetFilter>& filters) const {
    static DegradeSampler sampler;
    if (filters.empty())
        return std::vector<std::string>{};
    return resp_read<std::vector<std::string>>(
        open_, pool_, metrics_, "facet_agent_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<std::string>> {
            std::string sql = "SELECT DISTINCT agent_id FROM response_store.response_facets "
                              "WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            append_facet_filters(sql, binds, idx, instruction_id, filters);
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<std::string> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(text_col(res.get(), i, 0));
            return out;
        });
}

std::optional<int64_t>
ResponseStore::facet_agent_count(const std::string& instruction_id,
                                 const std::vector<FacetFilter>& filters,
                                 const std::optional<std::vector<std::string>>& agent_scope) const {
    // Engaged-empty scope (ADR-0017 INV-3 / #1712): zero visible agents means
    // zero matching agents, without touching the pool or issuing a query —
    // success-empty, not degrade, even when the store is closed (#2691
    // degrade-vs-empty distinguishability). Checked before the open_/pool_
    // checks below.
    if (agent_scope.has_value() && agent_scope->empty())
        return 0;
    // No filter is a genuine "no scoped count to report" — 0, not a degrade
    // (#2691, Doomgoose finding #7: distinct from the read-failure cases
    // below, which must NOT collapse to the same observable 0).
    if (filters.empty())
        return 0;
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    std::string sql = "SELECT COUNT(DISTINCT agent_id) FROM response_store.response_facets "
                      "WHERE instruction_id = $1";
    std::vector<std::string> binds{instruction_id};
    int idx = 2;
    append_facet_filters(sql, binds, idx, instruction_id, filters);
    if (agent_scope.has_value()) {
        // ADR-0017 INV-3: the visible set is applied IN SQL, before the
        // aggregate — never a C++ post-filter.
        std::vector<std::string_view> sv(agent_scope->begin(), agent_scope->end());
        sql += " AND agent_id = ANY($" + std::to_string(idx++) + "::text[])";
        binds.push_back(pg::to_text_array(sv));
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::optional<int64_t>
ResponseStore::facet_line_count(const std::string& instruction_id,
                                const std::vector<FacetFilter>& filters) const {
    // See facet_agent_count's comment: no filter is a genuine 0, distinct
    // from the read-failure cases below (#2691, Doomgoose finding #7).
    if (filters.empty())
        return 0;
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    // Use the first filter for the line count — this gives the total lines
    // matching that filter. For multi-filter intersection, the count is an
    // upper bound (true intersection count requires row-level parsing) —
    // matches the SQLite original's documented approximation.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT SUM(line_count) FROM response_store.response_facets WHERE instruction_id = $1 "
        "AND col_idx = $2::integer AND value = $3",
        std::vector<std::string>{instruction_id, std::to_string(filters[0].col_idx),
                                 filters[0].value});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::optional<std::vector<int64_t>>
ResponseStore::facet_response_ids(const std::string& instruction_id,
                                  const std::vector<FacetFilter>& filters, int limit,
                                  int offset) const {
    static DegradeSampler sampler;
    if (filters.empty())
        return std::vector<int64_t>{};
    return resp_read<std::vector<int64_t>>(
        open_, pool_, metrics_, "facet_response_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<int64_t>> {
            std::string sql = "SELECT DISTINCT response_id FROM response_store.response_facets "
                              "WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            append_facet_filters(sql, binds, idx, instruction_id, filters);
            const int limit_idx = idx++;
            const int offset_idx = idx++;
            sql += " ORDER BY response_id LIMIT $" + std::to_string(limit_idx) +
                   "::integer OFFSET $" + std::to_string(offset_idx) + "::integer";
            binds.push_back(std::to_string(limit));
            binds.push_back(std::to_string(offset));
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<int64_t> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(to_i64(PQgetvalue(res.get(), i, 0)));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::query_by_ids(const std::vector<int64_t>& response_ids) const {
    static DegradeSampler sampler;
    if (response_ids.empty())
        return std::vector<StoredResponse>{};
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query_by_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            // IDs are int64_t (never user strings) — safe to inline as a
            // literal IN-list rather than one bind per id.
            std::string in_list;
            for (std::size_t i = 0; i < response_ids.size(); ++i) {
                if (i > 0)
                    in_list += ',';
                in_list += std::to_string(response_ids[i]);
            }
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE id IN (" + in_list +
                              ") ORDER BY id";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

// ── Retention (clock-guarded gc_sweep shape, #2496 / ADR-0038 / ADR-0039) ────

void ResponseStore::reap_expired() {
    if (!open_)
        return;
    const auto record_result = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_response_reap_passes_total", {{"result", result}})
                .increment();
    };

    int64_t responses_deleted = 0;
    // #2691 (Gate 8 architect): test-observable proof the explicit facet
    // pre-drain loop actually deleted rows, distinguishable from the parent
    // DELETE's ON DELETE CASCADE silently doing the same work — see
    // facets_predrained_total()'s doc comment.
    int64_t facets_predrained = 0;
    std::string outcome = "failed";
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // One sweeping replica at a time.
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock(hashtextextended('response_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            outcome = "skipped_lock";
            return true;
        }

        const int64_t now = now_fn_ ? now_fn_() : now_epoch();
        // Sanitise the CALLER's (process) clock cheaply, before even
        // attempting the pg_now read below (clock-guard part 3). UPPER bound
        // only: a NEGATIVE reading is the legitimate dead-CMOS case the
        // guard exists for. This value plays NO further role in the pass —
        // every DECISION below reads Postgres's OWN clock (pg_now below),
        // matching `GuaranteedStateStore::reap_expired`'s `#2663` fix and
        // `AuditStore::cleanup_once`'s original `#2360/1d` fix — so an
        // implausible process clock is refused here only to avoid touching
        // the database at all for a reading that could not matter.
        constexpr int64_t kMaxPlausibleNow = std::numeric_limits<int64_t>::max() / 4;
        if (now > kMaxPlausibleNow) {
            spdlog::warn("ResponseStore::reap_expired: implausible clock reading ({}); "
                        "declining the pass",
                        now);
            outcome = "failed";
            return false;
        }

        // PostgreSQL's OWN clock, not this replica's process clock, for
        // every DECISION below (#2691, transplanted from #2663). Under the
        // prior process-clock read, a replica whose own clock ran fast could
        // win the shared `gc_meta.last_pass_now` anchor and sweep a row
        // still live by every other clock, with no anomaly recorded — the
        // shared row is the transmission medium, not the fix. Read AFTER the
        // advisory lock, inside this transaction, so every replica
        // serialised through that lock gets the IDENTICAL comparison point
        // regardless of its own clock's accuracy.
        pg::PgResult clk = pg::exec_params(conn, "SELECT EXTRACT(EPOCH FROM now())::bigint",
                                           std::vector<std::string>{});
        if (clk.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: pg clock read failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        const int64_t pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));
        // Same overflow guard, applied to PG's reading too — cheap to bound
        // both sources the same way rather than trust one implicitly because
        // it is "the database".
        if (pg_now > kMaxPlausibleNow) {
            spdlog::error("ResponseStore::reap_expired: PostgreSQL's own clock reading ({}) is "
                         "implausible; declining the pass",
                         pg_now);
            outcome = "failed";
            return false;
        }

        // Derive the implausibly-ahead bound from THIS store's configured
        // retention (2× horizon, floored) so raising `response_retention_days`
        // above a fixed constant can't push the whole live set past the bound
        // and wedge the reaper in permanent decline (consistency-auditor
        // Gate 4; the ADR-0038 false-decline lesson taken literally).
        const int64_t implausibly_ahead =
            std::max<int64_t>(kReapImplausiblyAheadFloorSecs,
                              static_cast<int64_t>(retention_days_) * 86'400 * 2);

        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM response_store.gc_meta WHERE key IN ('last_pass_now',"
            "'last_anomaly_facts','bootstrap_settled')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: meta read failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        std::optional<int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        // #2579: has ANY pass on this database ever reached a verdict?
        // Durable and SHARED across replicas (not a per-process flag) —
        // settled below, AFTER classify(), never derived from `prev`.
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
            "INSERT INTO response_store.gc_meta (key, value) VALUES ('last_pass_now', $1) ON "
            "CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(pg_now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("ResponseStore::reap_expired: meta stamp failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        pg::PgResult probe = pg::exec_params(
            conn, std::string(kResponseRetentionProbeSql).c_str(),
            std::vector<std::string>{std::to_string(pg_now),
                                     std::to_string(pg_now + implausibly_ahead)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const bool has_expired = to_bool(PQgetvalue(probe.get(), 0, 0));
        const bool has_survivor = to_bool(PQgetvalue(probe.get(), 0, 1));
        const bool would_wipe = has_expired && !has_survivor;

        audit_retention::Facts facts{
            .has_expired = has_expired,
            .would_wipe = would_wipe,
            .big_step = prev.has_value() && has_expired &&
                        audit_retention::moved_at_least(*prev, pg_now, kReapBigStepSecs) &&
                        pg_now > *prev,
            .prev_unusable = prev_unusable,
            // #2579's missing-anchor trigger. RECORDED ANSWER (routed-concern
            // "Clock-guarded retention" part 6): decline — AuditStore's/
            // GuaranteedStateStore's answer, not ResultSetStore's. A
            // mis-timed pass here would destroy agent command/instruction
            // results powering the executions drawer + `/tar` dashboard,
            // some of which carry usage-class behavioral PII (device.live.*,
            // per-app panels) — not ResultSetStore's reproducible
            // one-TTL-window scratch result sets.
            .no_anchor = !bootstrap_settled,
        };
        const auto anomaly = audit_retention::classify(facts);
        // FIVE chars — the 5th ('b') is safe to add here without the
        // mixed-version dedup hazard result_set_store.cpp's comment warns
        // about: the 4-char format never shipped to a deployed writer
        // (born-on-PG in this same PR).
        const std::string facts_ser = std::string(facts.has_expired ? "e" : "-") +
                                      (facts.would_wipe ? "w" : "-") +
                                      (facts.big_step ? "s" : "-") +
                                      (facts.prev_unusable ? "u" : "-") +
                                      (facts.no_anchor ? "b" : "-");

        // The pass has now REACHED A VERDICT, so settle the bootstrap marker
        // — HERE, not at the re-anchor above. The re-anchor runs before the
        // probes, so deriving the trigger from the stored reading would let
        // a transient probe failure spend it permanently: the next pass
        // would see a reading, call itself anchored, and delete with every
        // detector false — the exact defect #2579 closes. Every early
        // return above this line rolls the whole transaction back, so a
        // pass that never reached a verdict leaves the trigger armed.
        if (!bootstrap_settled) {
            pg::PgResult settle = pg::exec_params(
                conn,
                "INSERT INTO response_store.gc_meta (key, value) VALUES "
                "('bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{});
            if (settle.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResponseStore::reap_expired: bootstrap settle failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }

        if (anomaly != audit_retention::Anomaly::None) {
            if (facts_ser != last_facts) {
                // A NAME, not the enum ordinal: #2579 inserted an
                // enumerator mid-enum, so an ordinal silently renames
                // itself across an upgrade while the operator-facing
                // string stays put.
                const char* anomaly_name = "unknown";
                switch (anomaly) {
                case audit_retention::Anomaly::None: anomaly_name = "none"; break;
                case audit_retention::Anomaly::NoAnchor: anomaly_name = "no-anchor"; break;
                case audit_retention::Anomaly::Wipe: anomaly_name = "wipe"; break;
                case audit_retention::Anomaly::Step: anomaly_name = "step"; break;
                case audit_retention::Anomaly::BadState: anomaly_name = "bad-state"; break;
                }
                if (anomaly == audit_retention::Anomaly::NoAnchor) {
                    spdlog::warn("ResponseStore::reap_expired: no usable previous retention "
                                "clock reading and rows are already expired (now={} facts={}) "
                                "— declining this pass and anchoring; the next pass has a "
                                "comparison point and proceeds (#2579)",
                                pg_now, facts_ser);
                } else {
                    spdlog::warn("ResponseStore::reap_expired: retention clock anomaly ({} "
                                "facts={}) — declining this pass; an identical next pass will "
                                "drain, capped",
                                anomaly_name, facts_ser);
                }
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO response_store.gc_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("ResponseStore::reap_expired: anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                outcome = anomaly == audit_retention::Anomaly::NoAnchor ? "declined_no_anchor"
                                                                        : "declined";
                return true;
            }
            // Suppressed repeat of the SAME fact set — proceed with the
            // (capped) drain below.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM response_store.gc_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResponseStore::reap_expired: anomaly clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (!has_expired) {
            outcome = "noop";
            return true;
        }

        // `responses` reaped in chunked DELETEs, not one unbounded statement
        // (#2691, Doomgoose finding #6). `response_facets` rows for each
        // reaped id are DRAINED EXPLICITLY below, in their own small
        // LIMIT-bounded batches, BEFORE the parent-row delete — not left to
        // the implicit ON DELETE CASCADE, whose fan-out has no LIMIT of its
        // own (chaos Gate 5: up to kReapDeleteChunkRows *
        // kMaxFacetsPerResponse = 2.5M child rows in ONE statement if left to
        // CASCADE — see kReapFacetDeleteBatchRows's comment). By the time the
        // parent-row DELETE runs, its CASCADE has nothing left to do. The
        // deterministic ORDER BY selecting each chunk's ids is unchanged, so
        // a wall-clock-budget stop mid-pass (whether mid-facet-drain or
        // between chunks) leaves a well-defined remainder for the next pass:
        // a chunk whose facets are only partially drained is simply
        // reselected (still expired, parent row not yet deleted) and its
        // facet drain resumes where it left off.
        const auto delete_deadline =
            std::chrono::steady_clock::now() + kReapDeleteBudget;
        bool budget_exhausted = false;
        while (responses_deleted < kReapCapPerPass) {
            if (std::chrono::steady_clock::now() >= delete_deadline) {
                budget_exhausted = true;
                break;
            }
            const int64_t chunk_limit =
                std::min<int64_t>(kReapDeleteChunkRows, kReapCapPerPass - responses_deleted);
            pg::PgResult ids_res = pg::exec_params(
                conn,
                "SELECT id FROM response_store.responses WHERE ttl_expires_at > 0 AND "
                "ttl_expires_at < $1::bigint ORDER BY ttl_expires_at ASC, id ASC "
                "LIMIT $2::bigint",
                std::vector<std::string>{std::to_string(pg_now), std::to_string(chunk_limit)});
            if (ids_res.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResponseStore::reap_expired: chunk id select failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
            const int64_t n_ids = PQntuples(ids_res.get());
            if (n_ids == 0)
                break; // nothing left expired
            std::string id_list;
            id_list.reserve(static_cast<std::size_t>(n_ids) * 8);
            for (int i = 0; i < n_ids; ++i) {
                if (i > 0)
                    id_list += ',';
                id_list += text_col(ids_res.get(), i, 0);
            }

            // Drain response_facets for this chunk's ids in bounded batches
            // BEFORE touching the parent rows, so the parent DELETE's
            // CASCADE below is always trivial regardless of how many facets
            // this chunk's responses happen to carry.
            for (;;) {
                pg::PgResult fdel = pg::exec_params(
                    conn,
                    ("DELETE FROM response_store.response_facets WHERE ctid IN (SELECT ctid "
                     "FROM response_store.response_facets WHERE response_id IN (" +
                     id_list + ") LIMIT " + std::to_string(kReapFacetDeleteBatchRows) + ")")
                        .c_str(),
                    std::vector<std::string>{});
                if (fdel.status() != PGRES_COMMAND_OK) {
                    spdlog::error("ResponseStore::reap_expired: facet drain failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                const int64_t batch_deleted = affected_rows(fdel);
                facets_predrained += batch_deleted;
                if (batch_deleted < kReapFacetDeleteBatchRows)
                    break; // this chunk's facets are fully drained
                if (std::chrono::steady_clock::now() >= delete_deadline) {
                    // Facets only partially drained — leave the parent rows
                    // in place; the next pass reselects the same ids (still
                    // expired) and resumes the drain.
                    budget_exhausted = true;
                    break;
                }
            }
            if (budget_exhausted)
                break;

            pg::PgResult del = pg::exec_params(
                conn,
                ("DELETE FROM response_store.responses WHERE id IN (" + id_list + ")").c_str(),
                std::vector<std::string>{});
            if (del.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResponseStore::reap_expired: delete failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
            const int64_t chunk_deleted = affected_rows(del);
            responses_deleted += chunk_deleted;
            if (chunk_deleted < chunk_limit)
                break; // drained everything expired — no need to check the budget
            if (std::chrono::steady_clock::now() >= delete_deadline) {
                budget_exhausted = true;
                break;
            }
        }
        // Report a capped pass distinctly (result="capped") so on-call can tell
        // a healthy fully-draining reaper from one whose 10k/pass ceiling (or
        // this chunking budget) is being outrun by ingest (this is the
        // higher-write store; the AuditStore cap-reached shape, ported — sre
        // Gate 6 / R2). Hitting either limit does NOT prove a backlog
        // remains: an exact-boundary pass that drained the last row hit the
        // limit with nothing left. Probe for a real remaining backlog (only
        // when a limit was hit, so the cost is rare) so an exact-boundary
        // drain labels "swept", not a false "capped" page — the AuditStore
        // post-delete backlog probe (chaos Gate 5).
        outcome = "swept";
        if (responses_deleted >= kReapCapPerPass || budget_exhausted) {
            pg::PgResult more = pg::exec_params(
                conn,
                "SELECT EXISTS(SELECT 1 FROM response_store.responses WHERE ttl_expires_at > 0 "
                "AND ttl_expires_at < $1::bigint)",
                std::vector<std::string>{std::to_string(pg_now)});
            if (more.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResponseStore::reap_expired: backlog probe failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
            if (to_bool(PQgetvalue(more.get(), 0, 0)))
                outcome = "capped";
        }
        return true;
    });

    if (!ok) {
        record_result("failed");
        spdlog::error("ResponseStore::reap_expired: pass aborted (statement failed or txn "
                      "rolled back — see the preceding error line)");
        return;
    }
    record_result(outcome.c_str());
    if (responses_deleted > 0) {
        responses_reaped_.fetch_add(static_cast<uint64_t>(responses_deleted),
                                    std::memory_order_relaxed);
        spdlog::info("ResponseStore: reap swept {} response(s)", responses_deleted);
    }
    if (facets_predrained > 0) {
        facets_predrained_.fetch_add(static_cast<uint64_t>(facets_predrained),
                                     std::memory_order_relaxed);
    }
}

} // namespace yuzu::server
