#include "guaranteed_state_store.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include "guardian_generation_raise.hpp" // kMaxPolicyGenerationTarget
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include <yuzu/log_token.hpp> // log_id_token, log_key_token
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
// The Applications stability read holds one lease for its whole multi-second
// 30-day aggregation, so it gets its own in-flight budget (the default pool is
// 16 and no per-principal limit bounds synchronous reads): a request over the
// budget is refused at once with this reason and the caller's retryable 503,
// instead of queueing behind the pool.
constexpr const char* kReasonConcurrencyBudget = "concurrency_budget";
// JC-8 (coordinator review): label parity with InventoryStore's
// yuzu_inventory_read_degrade_total{reason, source} family — a constant
// "source" so a future second Guardian-adjacent read-degrade emitter stays
// distinguishable on the same dashboards without a metric rename. Four
// sources exist today: "guardian_state" for the DEX/observation
// family (dex_read<>/dex_observation, fail-soft — an empty/degraded result
// is returned to the caller), "guardian_rules" for the AUTHORITATIVE
// rule/status reads (get_rule/list_rules/agent_rule_statuses*/rule_names*/
// errored_rule_count/uncertain_rule_count, fail-hard — a std::expected error is returned and the
// caller decides how to fail) (#4856), and the two census sources below. All
// bump the SAME counter, yuzu_server_guardian_read_degrade_total{reason,source},
// so an alert can aggregate `by (reason, source)` without missing any family.
constexpr const char* kDegradeSource = "guardian_state";
constexpr const char* kDegradeSourceRules = "guardian_rules";
// "guardian_census" is the census pending-count GAUGE read only
// (pending_projection_count_checked, #5690): its failure freezes the published
// gauge at its previous value, so a rising counter on this source with a flat
// gauge means the gauge is a stale sample.
constexpr const char* kDegradeSourceCensus = "guardian_census";
// "guardian_census_device" is the per-device unrepresented-pending read
// (unrepresented_pending_for_agent, #7217). It is a separate source on purpose:
// that read fails hard on the request path (REST 503 / MCP error) and publishes
// no gauge, so folding it into "guardian_census" would make request noise mask a
// real gauge freeze and would make a per-device 503 read as a stale gauge.
constexpr const char* kDegradeSourceCensusDevice = "guardian_census_device";
// SQLSTATE 57014 (query_canceled) from the per-device read's statement timeout:
// the retained pending backlog is too large for the time budget, so a retry fails
// identically. Counted on kDegradeSourceCensusDevice only.
constexpr const char* kReasonStatementTimeout = "statement_timeout";
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
// rule) status table, or nullptr if the event carries no compliance signal.
// guard.compliant (Slice B) and a successful drift.remediated both mean the watched
// state is now at expected. guard.errored is the #2818 spark subscription-death detach
// (agents/core/src/guardian_spark_runtime.cpp on_subscription_lost): the rule is no
// longer watched, so it is an errored verdict like guard.unhealthy. Only the spark
// detection backend produces it, so it is dormant until the agent's prefer_spark
// default flips. guard.armed, guard.disarmed and guard.healthy are deliberately NOT
// mapped: they are lifecycle or recovery markers, not verdicts.
// Ordering: project_rule_status replaces a census row when the event's ordering key K is
// above the stored one, K being the agent stamp bounded by receipt plus 300 s (0 when the stamp
// is absent or unusable), and breaks an exact tie by the event's INSERT-allocated ingest_seq. An
// exact redelivery of one event_id exits at insert_event_classified (Redelivered/Conflict) before
// a first-delivery census write is reached; it reaches the census only to repair pending evidence.
const char* event_state_from_type(const std::string& t) {
    if (t == "guard.compliant" || t == "drift.remediated")
        return "compliant";
    if (t == "drift.detected")
        return "drifted";
    // Slice-B collapse (deliberate): guardian-mvp-contract.md §4/decision-5 lists
    // `remediation_failed` as a state DISTINCT from `errored`, but the Slice-B census
    // exposes only compliant/drifted/errored and both render red in the worst-of badge.
    if (t == "remediation.failed" || t == "guard.unhealthy" || t == "guard.errored")
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

// Schema v4 (#5690): the census ordering key, the durable pending evidence and the INSERT-allocated
// event sequence. The shape check below is the ONE text run by the migration (before it stamps
// the version) and by the boot probe `ordering_schema_defect`, because the runner skips a
// database already stamped 4 and so cannot tell this schema's v4 from objects adopted by hand.
// Every name is schema-qualified because the probe runs on a pooled connection without the
// runner's search_path. `pg_index.indkey` is an int2vector whose `::int2[]` form has lower bound
// 0 and never equals an ARRAY[...], so the keys are compared as text. The retained maxima are
// read BEFORE the sequence: a concurrent allocation only raises the sequence, so the other order
// could refuse a healthy database. The two constraint names are checked because the 23503 and
// 23505 classifiers in the census projection and the event insert key on them.
constexpr const char* kV4ShapeCheck = R"SQL(
DO $do$
DECLARE
  bad text := '';
  nxt bigint;
  max_e bigint;
  max_c bigint;
  seqrel regclass;
  r record;
  e regclass := 'guaranteed_state_store.guaranteed_state_events'::regclass;
  c regclass := 'guaranteed_state_store.guardian_agent_rule_status'::regclass;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = e AND attname = 'ingest_seq' AND NOT attisdropped
                   AND atttypid = 'bigint'::regtype AND attnotnull AND attidentity = 'a')
    THEN bad := bad || ' events.ingest_seq(bigint,not null,identity ALWAYS)'; END IF;
  seqrel := pg_get_serial_sequence('guaranteed_state_store.guaranteed_state_events', 'ingest_seq')::regclass;
  IF seqrel IS NULL OR NOT EXISTS (SELECT 1 FROM pg_sequence WHERE seqrelid = seqrel AND seqtypid = 'bigint'::regtype
                   AND seqincrement = 1 AND seqmin = 1 AND seqmax = 9223372036854775807 AND seqcache = 1
                   AND NOT seqcycle)
    THEN bad := bad || ' events.ingest_seq sequence(bigint,inc 1,min 1,max bigint,cache 1,no cycle,owned)'; END IF;
  FOR r IN SELECT * FROM (VALUES
      (e, 'proj_key', 'bigint'::regtype, false, NULL::text),
      (e, 'proj_key_capped', 'boolean'::regtype, true, 'false'),
      (e, 'projection_pending', 'boolean'::regtype, true, 'false'),
      (c, 'key_ns', 'bigint'::regtype, false, NULL),
      (c, 'ingest_seq', 'bigint'::regtype, false, NULL),
      (c, 'ts_hwm', 'bigint'::regtype, false, NULL),
      (c, 'seq_hwm', 'bigint'::regtype, false, NULL),
      (c, 'hwm_recv_ns', 'bigint'::regtype, false, NULL),
      (c, 'order_uncertain', 'boolean'::regtype, true, 'false')) v(rel, col, typ, nn, dflt)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                    WHERE a.attrelid = r.rel AND a.attname = r.col AND NOT a.attisdropped AND a.atttypid = r.typ
                      AND a.attnotnull = r.nn AND a.attidentity = '' AND a.attgenerated = ''
                      AND (CASE WHEN r.dflt IS NULL THEN d.oid IS NULL ELSE pg_get_expr(d.adbin, d.adrelid) = r.dflt END))
      THEN bad := bad || ' ' || r.rel::text || '.' || r.col; END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
                  WHERE i.indrelid = e AND ic.relname = 'idx_gse_ingest_seq' AND i.indisunique AND i.indisvalid
                    AND i.indisready AND i.indimmediate AND i.indpred IS NULL
                    AND i.indkey::text = (SELECT attnum::text FROM pg_attribute WHERE attrelid = e AND attname = 'ingest_seq'))
    THEN bad := bad || ' idx_gse_ingest_seq(unique,immediate,valid,on ingest_seq only)'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
                  WHERE i.indrelid = e AND ic.relname = 'idx_gse_pending' AND NOT i.indisunique AND i.indisvalid
                    AND i.indisready AND pg_get_expr(i.indpred, i.indrelid) = 'projection_pending'
                    AND i.indkey::text = (SELECT attnum::text FROM pg_attribute WHERE attrelid = e AND attname = 'rule_id') || ' ' ||
                                         (SELECT attnum::text FROM pg_attribute WHERE attrelid = e AND attname = 'agent_id'))
    THEN bad := bad || ' idx_gse_pending((rule_id,agent_id) WHERE projection_pending)'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = e AND conname = 'guaranteed_state_events_pkey' AND contype = 'p')
    THEN bad := bad || ' events primary key name guaranteed_state_events_pkey'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = c AND conname = 'guardian_agent_rule_status_rule_fk' AND contype = 'f')
    THEN bad := bad || ' census foreign key name guardian_agent_rule_status_rule_fk'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc fp ON fp.oid = t.tgfoid
                  WHERE t.tgrelid = c AND t.tgname = 'guardian_agent_rule_status_flag_legacy'
                    AND NOT t.tgisinternal AND t.tgenabled = 'O' AND t.tgtype = 19
                    AND fp.proname = 'guardian_agent_rule_status_flag_legacy_write')
    THEN bad := bad || ' census trigger guardian_agent_rule_status_flag_legacy(before update, row, enabled)'; END IF;
  IF seqrel IS NOT NULL THEN
    SELECT COALESCE(max(ingest_seq), 0) INTO max_e FROM guaranteed_state_store.guaranteed_state_events;
    -- seq_hwm may be absent (the shape check above has already recorded that); the probe must still
    -- reach its own refusal, not fail with an undefined-column error.
    IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = c AND attname = 'seq_hwm' AND NOT attisdropped) THEN
      EXECUTE 'SELECT COALESCE(max(GREATEST(ingest_seq, COALESCE(seq_hwm, 0))), 0) FROM guaranteed_state_store.guardian_agent_rule_status' INTO max_c;
    ELSE
      SELECT COALESCE(max(ingest_seq), 0) INTO max_c FROM guaranteed_state_store.guardian_agent_rule_status;
    END IF;
    EXECUTE format('SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM %s', seqrel) INTO nxt;
    IF nxt <= GREATEST(max_e, max_c)
      THEN bad := bad || format(' ingest_seq sequence next=%s is not above the retained maxima', nxt); END IF;
  END IF;
  IF bad <> '' THEN
    RAISE EXCEPTION 'guaranteed_state_store v4: object not as this version creates it:%', bad USING ERRCODE = 'P0001';
  END IF;
END
$do$;
)SQL";

// The identity fill REWRITES guaranteed_state_events: a new filenode under ACCESS EXCLUSIVE for
// the whole statement (every other replica's ingest, readers and reaper block, so stop them
// first), needing disk headroom of one full copy of the table and its indexes. The ACCESS
// EXCLUSIVE lock is held until this transaction ends, which includes the index builds and the
// shape check. The pool's 30 s statement_timeout would refuse boot at about four million
// retained events, so this transaction widens it; the bound still exists, as a per-statement
// limit, not a migration deadline (docs/user-manual/upgrading.md).
constexpr const char* kV4Ddl = R"SQL(
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '900s';
ALTER TABLE guaranteed_state_events
    ADD COLUMN IF NOT EXISTS ingest_seq BIGINT GENERATED ALWAYS AS IDENTITY (CACHE 1 NO CYCLE),
    ADD COLUMN IF NOT EXISTS proj_key BIGINT,
    ADD COLUMN IF NOT EXISTS proj_key_capped BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS projection_pending BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_gse_ingest_seq ON guaranteed_state_events (ingest_seq);
CREATE INDEX IF NOT EXISTS idx_gse_pending ON guaranteed_state_events (rule_id, agent_id)
    WHERE projection_pending;
ALTER TABLE guardian_agent_rule_status
    ADD COLUMN IF NOT EXISTS key_ns BIGINT,
    ADD COLUMN IF NOT EXISTS ingest_seq BIGINT,
    ADD COLUMN IF NOT EXISTS ts_hwm BIGINT,
    ADD COLUMN IF NOT EXISTS seq_hwm BIGINT,
    ADD COLUMN IF NOT EXISTS hwm_recv_ns BIGINT,
    ADD COLUMN IF NOT EXISTS order_uncertain BOOLEAN NOT NULL DEFAULT FALSE;
-- A census write that changes the verdict without changing its ordering tuple did not come from
-- this version's upsert (which always moves key_ns or ingest_seq with the verdict): an earlier
-- build, which mixed versions are not supported to run, wrote it. The row then pairs one event's
-- tuple with another's verdict, so it is flagged instead of reading clean.
CREATE OR REPLACE FUNCTION guardian_agent_rule_status_flag_legacy_write() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF (NEW.state IS DISTINCT FROM OLD.state OR NEW.updated_at IS DISTINCT FROM OLD.updated_at)
       AND NEW.key_ns IS NOT DISTINCT FROM OLD.key_ns
       AND NEW.ingest_seq IS NOT DISTINCT FROM OLD.ingest_seq THEN
        NEW.order_uncertain := true;
    END IF;
    RETURN NEW;
END
$fn$;
CREATE OR REPLACE TRIGGER guardian_agent_rule_status_flag_legacy
    BEFORE UPDATE ON guardian_agent_rule_status
    FOR EACH ROW EXECUTE FUNCTION guardian_agent_rule_status_flag_legacy_write();
)SQL";

// Schema v5 (#5690, UP-14): the event pair (boot_epoch, emit_seq) on both tables and the
// per-agent order table, sized for the whole regime machine (retired epoch, the straggler and
// duplicate counters, the two receipt clocks) so a later change adds nothing but a v6. Nullable
// columns with no default are catalog-only: no rewrite, so no disk headroom and no long lock
// (the 3 s lock_timeout bounds the wait for the brief ACCESS EXCLUSIVE). NULL/NULL is an
// unpaired event or verdict; there is no backfill, and no CHECK constraint (the ingest bounds
// the pair, and a database must keep a row it cannot judge).
// Every statement replays over a used v5 (a reset to 4 re-runs this text): IF NOT EXISTS and
// CREATE OR REPLACE, never a drop.
constexpr const char* kV5Ddl = R"SQL(
SET LOCAL lock_timeout = '3s';
ALTER TABLE guaranteed_state_events
    ADD COLUMN IF NOT EXISTS boot_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS emit_seq BIGINT;
ALTER TABLE guardian_agent_rule_status
    ADD COLUMN IF NOT EXISTS boot_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS emit_seq BIGINT;
CREATE TABLE IF NOT EXISTS guardian_agent_order (
    agent_id          TEXT NOT NULL,
    epoch             BIGINT,
    emit_seq_hwm      BIGINT,
    epoch_recv_ns     BIGINT,
    retired_epoch     BIGINT,
    unpaired_recv_ns  BIGINT,
    unpaired_events   BIGINT NOT NULL DEFAULT 0,
    unpaired_held     BIGINT NOT NULL DEFAULT 0,
    pair_regressions  BIGINT NOT NULL DEFAULT 0,
    pair_stragglers   BIGINT NOT NULL DEFAULT 0,
    pair_recoveries   BIGINT NOT NULL DEFAULT 0,
    pair_duplicates   BIGINT NOT NULL DEFAULT 0,
    retired_events    BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT guardian_agent_order_pkey PRIMARY KEY (agent_id)
);
-- The v4 tripwire, extended: a verdict change that leaves a NON-NULL pair unchanged is also
-- flagged. This version's upsert moves the pair with the verdict, so only an earlier build
-- (which never writes the pair) can do that to a paired row. A v4 INSERT, or a v4 write to a
-- row whose pair is NULL, is as clean here as under v4. The trigger itself is v4's; only the
-- function body is replaced.
CREATE OR REPLACE FUNCTION guardian_agent_rule_status_flag_legacy_write() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF (NEW.state IS DISTINCT FROM OLD.state OR NEW.updated_at IS DISTINCT FROM OLD.updated_at)
       AND ((NEW.key_ns IS NOT DISTINCT FROM OLD.key_ns
             AND NEW.ingest_seq IS NOT DISTINCT FROM OLD.ingest_seq)
            OR (NEW.boot_epoch IS NOT NULL
                AND NEW.boot_epoch IS NOT DISTINCT FROM OLD.boot_epoch
                AND NEW.emit_seq IS NOT DISTINCT FROM OLD.emit_seq)) THEN
        NEW.order_uncertain := true;
    END IF;
    RETURN NEW;
END
$fn$;
)SQL";

// Shape check for schema v5: the ONE text run by the migration (before it stamps the version)
// and by the boot probe `ordering_schema_defect`, for the reason kV4ShapeCheck gives. It
// reads the four pair columns, the order table (every column, type, nullability and default;
// permanent and ordinary; the primary key by name and column) and the tripwire function body.
// The body is matched by the three fragments of the pair test, so v4's body, which compiles and
// is attached to the same trigger, is refused. `pg_get_functiondef` returns the body verbatim.
constexpr const char* kV5ShapeCheck = R"SQL(
DO $do$
DECLARE
  bad text := '';
  r record;
  fdef text;
  e regclass := 'guaranteed_state_store.guaranteed_state_events'::regclass;
  c regclass := 'guaranteed_state_store.guardian_agent_rule_status'::regclass;
  o regclass := to_regclass('guaranteed_state_store.guardian_agent_order');
BEGIN
  IF o IS NULL OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = o AND relkind = 'r' AND relpersistence = 'p')
    THEN bad := bad || ' table guardian_agent_order(permanent, ordinary)'; END IF;
  FOR r IN SELECT * FROM (VALUES
      (e, 'boot_epoch', 'bigint'::regtype, false, NULL::text),
      (e, 'emit_seq', 'bigint'::regtype, false, NULL),
      (c, 'boot_epoch', 'bigint'::regtype, false, NULL),
      (c, 'emit_seq', 'bigint'::regtype, false, NULL),
      (o, 'agent_id', 'text'::regtype, true, NULL),
      (o, 'epoch', 'bigint'::regtype, false, NULL),
      (o, 'emit_seq_hwm', 'bigint'::regtype, false, NULL),
      (o, 'epoch_recv_ns', 'bigint'::regtype, false, NULL),
      (o, 'retired_epoch', 'bigint'::regtype, false, NULL),
      (o, 'unpaired_recv_ns', 'bigint'::regtype, false, NULL),
      (o, 'unpaired_events', 'bigint'::regtype, true, '0'),
      (o, 'unpaired_held', 'bigint'::regtype, true, '0'),
      (o, 'pair_regressions', 'bigint'::regtype, true, '0'),
      (o, 'pair_stragglers', 'bigint'::regtype, true, '0'),
      (o, 'pair_recoveries', 'bigint'::regtype, true, '0'),
      (o, 'pair_duplicates', 'bigint'::regtype, true, '0'),
      (o, 'retired_events', 'bigint'::regtype, true, '0')) v(rel, col, typ, nn, dflt)
    WHERE v.rel IS NOT NULL
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                    WHERE a.attrelid = r.rel AND a.attname = r.col AND NOT a.attisdropped AND a.atttypid = r.typ
                      AND a.attnotnull = r.nn AND a.attidentity = '' AND a.attgenerated = ''
                      AND (CASE WHEN r.dflt IS NULL THEN d.oid IS NULL ELSE pg_get_expr(d.adbin, d.adrelid) = r.dflt END))
      THEN bad := bad || ' ' || r.rel::text || '.' || r.col; END IF;
  END LOOP;
  IF o IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = o AND conname = 'guardian_agent_order_pkey'
                  AND contype = 'p' AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = o AND attname = 'agent_id')])
    THEN bad := bad || ' order table primary key guardian_agent_order_pkey(agent_id)'; END IF;
  SELECT pg_get_functiondef(fp.oid) INTO fdef
    FROM pg_trigger t JOIN pg_proc fp ON fp.oid = t.tgfoid
   WHERE t.tgrelid = c AND t.tgname = 'guardian_agent_rule_status_flag_legacy'
     AND fp.proname = 'guardian_agent_rule_status_flag_legacy_write';
  IF fdef IS NULL
     OR strpos(fdef, 'NEW.boot_epoch IS NOT NULL') = 0
     OR strpos(fdef, 'NEW.boot_epoch IS NOT DISTINCT FROM OLD.boot_epoch') = 0
     OR strpos(fdef, 'NEW.emit_seq IS NOT DISTINCT FROM OLD.emit_seq') = 0
    THEN bad := bad || ' census trigger function guardian_agent_rule_status_flag_legacy_write(pair test)'; END IF;
  IF bad <> '' THEN
    RAISE EXCEPTION 'guaranteed_state_store v5: object not as this version creates it:%', bad USING ERRCODE = 'P0001';
  END IF;
END
$do$;
)SQL";

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
        // v3 (#5674): the census table gets a foreign key to the rule table, so a deleted
        // rule's census rows go with it in the same statement (ON DELETE CASCADE) and an
        // upsert for a rule that is gone is refused by the database (SQLSTATE 23503). Rows
        // already orphaned are deleted first, or the constraint could not be added.
        // The ADD CONSTRAINT is guarded so a re-run of this text adds nothing twice.
        // The LOCK TABLE comes first, with its own 3 s SET LOCAL lock_timeout (the SessionStore
        // v2 and CaStore v4 precedent): ADD CONSTRAINT takes SHARE ROW EXCLUSIVE anyway, so
        // taking it before the DELETE adds no wait of its own, and a census row committed by a
        // binary that has not been upgraded cannot slip in between the DELETE and the
        // validation and refuse boot. The whole migration rolls back and retries on the next
        // boot if the lock is not granted in time.
        {3, R"SQL(
            SET LOCAL lock_timeout = '3s';
            LOCK TABLE guardian_agent_rule_status IN SHARE ROW EXCLUSIVE MODE;
            DELETE FROM guardian_agent_rule_status s
             WHERE NOT EXISTS (SELECT 1 FROM guaranteed_state_rules r WHERE r.rule_id = s.rule_id);
            DO $do$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint
                                WHERE conname = 'guardian_agent_rule_status_rule_fk'
                                  AND conrelid = 'guardian_agent_rule_status'::regclass) THEN
                    ALTER TABLE guardian_agent_rule_status
                        ADD CONSTRAINT guardian_agent_rule_status_rule_fk
                        FOREIGN KEY (rule_id) REFERENCES guaranteed_state_rules(rule_id)
                        ON DELETE CASCADE;
                END IF;
            END
            $do$;
        )SQL"},
        // v4 (#5690): the migration text is the DDL followed by the shape check, so a database
        // carrying an adopted object of the wrong shape rolls back unstamped.
        {4, std::string(kV4Ddl) + kV4ShapeCheck},
        // v5 (#5690, UP-14): the pair columns and the per-agent order table, with the same
        // shape check, so an adopted object of the wrong shape rolls back unstamped.
        {5, std::string(kV5Ddl) + kV5ShapeCheck},
    };
    return kMigrations;
}

// A database whose `guaranteed_state_store` version row reads 3 is skipped by the runner, so
// the runner cannot tell this schema's v3 from another branch's v3 (#5674 hard cutover: a
// database stamped by the discarded census-order design has no foreign key on the census
// table). The cascade key is the one structural fact this schema's v3 adds, so it is the
// only key checked, by its shape: cascade, not deferrable, on rule_id in both tables. A check
// of the other columns would refuse a later schema version that adds columns to the same
// tables. Returns an empty string when the key is present, else the cause, for the boot
// error. Any query failure is a cause too. The refusal's remedy resets the version row to 2 so
// that migration v3 runs again; a later migration must therefore be safe to run again, or the
// remedy must be revisited with it.
std::string census_schema_defect(PGconn* conn) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT count(*) FROM pg_constraint c "
        "WHERE conrelid = 'guaranteed_state_store.guardian_agent_rule_status'::regclass "
        "  AND confrelid = 'guaranteed_state_store.guaranteed_state_rules'::regclass "
        "  AND contype = 'f' AND confdeltype = 'c' AND NOT condeferrable "
        "  AND conkey = ARRAY[(SELECT attnum FROM pg_attribute "
        "                       WHERE attrelid = c.conrelid AND attname = 'rule_id')] "
        "  AND confkey = ARRAY[(SELECT attnum FROM pg_attribute "
        "                        WHERE attrelid = c.confrelid AND attname = 'rule_id')]",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return std::string("census schema probe failed: ") +
               ::yuzu::log_key_token(PQerrorMessage(conn));
    if (to_i64(PQgetvalue(res.get(), 0, 0)) < 1)
        return "guardian_agent_rule_status has no ON DELETE CASCADE foreign key on rule_id to "
               "guaranteed_state_rules (a deferrable key, or one on other columns, does not "
               "count). Back up the database first. A database stamped by a different "
               "branch's schema v3 is not supported: recreating the guaranteed_state_store "
               "schema DELETES every Guardian rule, event and observation. If only the key is "
               "missing or has the wrong shape, run \"ALTER TABLE "
               "guaranteed_state_store.guardian_agent_rule_status DROP CONSTRAINT IF EXISTS "
               "guardian_agent_rule_status_rule_fk\" and then \"UPDATE public.schema_meta SET "
               "version = 2 WHERE store = 'guaranteed_state_store'\" and restart, which re-runs "
               "the idempotent v3 migration";
    return {};
}

// Runs one schema's shape check. Returns false with `out` empty when every object is as that
// version creates it. Otherwise returns true with `out` the cause for the boot error: our own
// refusal (SQLSTATE P0001) carries the objects it found wrong (`refused` is set, so the caller
// appends that version's remedy), any other failure is a probe failure with the libpq message
// sanitised (no remedy).
bool shape_check_failed(PGconn* conn, const char* shape_check, const char* fallback,
                        std::string& out, bool& refused) {
    out.clear();
    refused = false;
    pg::PgResult res = pg::exec_params(conn, shape_check, std::vector<std::string>{});
    if (res.status() == PGRES_COMMAND_OK)
        return false;
    const char* state = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
    if (state == nullptr || std::string_view(state) != "P0001") {
        out = std::string("ordering schema probe failed: ") +
              ::yuzu::log_key_token(PQerrorMessage(conn));
        return true;
    }
    const char* primary = PQresultErrorField(res.get(), PG_DIAG_MESSAGE_PRIMARY);
    out = primary != nullptr ? primary : fallback;
    refused = true;
    return true;
}

// Boot probe for schemas v4 and v5: the same shape checks the migrations ran, again on every
// start, because a database stamped 4 or 5 is skipped by the runner. v4 is checked first and its
// remedy (reset to 3) is unchanged; a defect only v5 has names a reset to 4, which re-runs only
// the v5 migration (its text replays over a used v5). Returns an empty string when every object
// is as this version creates it, else the cause for the boot error.
std::string ordering_schema_defect(PGconn* conn) {
    std::string cause;
    bool refused = false;
    if (shape_check_failed(conn, kV4ShapeCheck,
                           "guaranteed_state_store v4: object not as this version creates it",
                           cause, refused)) {
        if (!refused)
            return cause;
        return cause +
               ". Back up the database first and stop every replica. If v4 was never used (no "
               "census row has key_ns and no event has proj_key or projection_pending), drop the "
               "named objects (a missing column needs no drop) and run \"UPDATE public.schema_meta "
               "SET version = 3 WHERE store = "
               "'guaranteed_state_store'\", then restart, which re-runs the v4 migration. If v4 "
               "was "
               "used, dropping an object discards ordering evidence, so reconcile by hand (a "
               "missing "
               "seq_hwm or hwm_recv_ns column needs no drop: the version-3 reset adds it without "
               "loss). A "
               "sequence refusal is repaired, with every replica stopped, by setval of the "
               "ingest_seq sequence to the larger of the event maximum and the census ingest_seq "
               "and "
               "seq_hwm maxima with is_called true; the store never reseeds it";
    }
    if (shape_check_failed(conn, kV5ShapeCheck,
                           "guaranteed_state_store v5: object not as this version creates it",
                           cause, refused)) {
        if (!refused)
            return cause;
        return cause +
               ". Back up the database first and stop every replica. If v5 was never used (no "
               "event or census row has boot_epoch or emit_seq and guardian_agent_order is "
               "empty), drop the named objects (a missing column needs no drop) and run "
               "\"UPDATE public.schema_meta SET version = 4 WHERE store = "
               "'guaranteed_state_store'\", then restart, which re-runs the v5 migration. If v5 "
               "was used, dropping an object discards ordering evidence, so reconcile by hand "
               "(a wrong trigger function body needs no drop: the version-4 reset replaces it "
               "without loss)";
    }
    return {};
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
    if (const std::string defect = census_schema_defect(lease.get()); !defect.empty()) {
        // `defect` is fixed text, or the probe failure with its libpq message already
        // sanitised; log_key_token here would cut the remedy off at its 256-byte cap.
        spdlog::error("GuaranteedStateStore: unsupported schema, refusing to start: {}", defect);
        return;
    }
    if (const std::string defect = ordering_schema_defect(lease.get()); !defect.empty()) {
        spdlog::error("GuaranteedStateStore: unsupported schema, refusing to start: {}", defect);
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
    if (!rule_version_in_range(row.version))
        return std::unexpected("rule version out of range (1.." + std::to_string(kMaxRuleVersion) +
                               ")");
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
    lease.reset();                   // no pool lease held while the hook runs
    notify_rule_mutation();
    return {};
}

std::expected<void, std::string>
GuaranteedStateStore::update_rule(const GuaranteedStateRuleRow& row) {
    if (!open_)
        return std::unexpected("database not open");
    // The range is enforced on a version CHANGE only. A row stored before the bound existed (or
    // written out of band) may carry an out-of-range version, and `apply_guard_change`
    // rewrites it UNCHANGED when an operator disables the rule: refusing that would leave the
    // rule impossible to disable. The `AND (version = $3 OR $3 in range)` predicate below does
    // the comparison atomically with the write; an in-range incoming version (the common case)
    // costs nothing extra.
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
        "prerequisites = $13 WHERE rule_id = $14 "
        "AND (version = $3::bigint OR $3::bigint BETWEEN 1 AND $15::bigint) RETURNING rule_id",
        std::vector<std::optional<std::string>>{
            row.name, row.yaml_source, std::to_string(row.version),
            std::string(row.enabled ? "true" : "false"), row.enforcement_mode, row.severity,
            row.os_target, row.scope_expr,
            row.signature.empty() ? std::nullopt
                                  : std::optional<std::string>(bytes_to_hex(row.signature)),
            row.updated_at, row.updated_by, row.spec_json, row.prerequisites, row.rule_id,
            std::to_string(kMaxRuleVersion)});
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505")
            return std::unexpected(format_conflict("rule name '" + row.name + "' already exists"));
        return std::unexpected("update failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    if (PQntuples(res.get()) == 0) {
        // Zero rows is either "no such rule" or "the version predicate refused the change".
        if (!rule_version_in_range(row.version)) {
            pg::PgResult exists = pg::exec_params(
                conn,
                "SELECT 1 FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id = $1",
                std::vector<std::string>{row.rule_id});
            // A failed probe is a store error, not "no such rule": reporting not-found would
            // answer an operator 404 for a rule that exists.
            if (exists.status() != PGRES_TUPLES_OK)
                return std::unexpected("update failed: " +
                                       std::string(PQresultErrorMessage(exists.get())));
            if (PQntuples(exists.get()) > 0)
                return std::unexpected("rule version out of range (1.." +
                                       std::to_string(kMaxRuleVersion) + ")");
        }
        return std::unexpected("not found: rule_id '" + row.rule_id + "'");
    }
    bump_policy_generation_on(conn); // rule set changed → new generation
    lease.reset();                   // no pool lease held while the hook runs
    notify_rule_mutation();
    return {};
}

std::expected<void, std::string> GuaranteedStateStore::delete_rule(const std::string& rule_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    // One transaction: lock the rule's pending events, retire them, delete the rule. A census
    // projection locks the pending events of its pair in ingest_seq order before it touches the
    // census row, so this takes the rule's pending events in the same order first (a rule-wide
    // ingest_seq order is consistent with every pair's order) and the two can never wait on each
    // other in a cycle. A projection that wins the row locks makes this wait; the delete then
    // cascades the projected census row. A projection that commits a new pending event after the
    // list is read is not retired here (#6829, #6830's follow-up register).
    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("BEGIN failed: ") + PQerrorMessage(conn));
    pg::PgTxn txn(conn);

    pg::PgResult locked =
        pg::exec_params(conn,
                        "SELECT event_id FROM guaranteed_state_store.guaranteed_state_events "
                        "WHERE rule_id = $1 AND projection_pending ORDER BY ingest_seq FOR UPDATE",
                        std::vector<std::string>{rule_id});
    if (locked.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(locked.get())));
    std::vector<std::string> pending_ids;
    for (int i = 0; i < PQntuples(locked.get()); ++i)
        pending_ids.emplace_back(PQgetvalue(locked.get(), i, 0));
    if (!pending_ids.empty()) {
        const std::vector<std::string_view> views(pending_ids.begin(), pending_ids.end());
        pg::PgResult retired =
            pg::exec_params(conn,
                            "UPDATE guaranteed_state_store.guaranteed_state_events "
                            "SET projection_pending = false WHERE event_id = ANY($1::text[])",
                            std::vector<std::string>{pg::to_text_array(views)});
        if (retired.status() != PGRES_COMMAND_OK)
            return std::unexpected("delete failed: " +
                                   std::string(PQresultErrorMessage(retired.get())));
    }

    pg::PgResult res = pg::exec_params(
        conn,
        "DELETE FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id = $1 "
        "RETURNING rule_id",
        std::vector<std::string>{rule_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(res.get())));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: rule_id '" + rule_id +
                               "'"); // txn rolls back, undoing the retire

    // The rule's CURRENT compliance states (unlike the event log, an immutable audit stream
    // kept past rule deletion, the census table holds live state) go with it: the
    // guardian_agent_rule_status foreign key is ON DELETE CASCADE (migration v3), so the one
    // DELETE above removes both in a single statement. The generation bump below stays outside
    // that transaction on purpose: it is best-effort (see bump_policy_generation_on) and a failed
    // bump must not undo the delete.
    if (!txn.commit())
        return std::unexpected("delete failed: commit: " + std::string(PQerrorMessage(conn)));
    bump_policy_generation_on(conn); // rule set changed → new generation
    lease.reset();                   // no pool lease held while the hook runs
    notify_rule_mutation();
    return {};
}

bool GuaranteedStateStore::delete_agent(std::string_view agent_id) {
    if (agent_id.empty()) {
        spdlog::warn("GuaranteedStateStore: delete_agent called with an empty agent_id - refusing "
                     "without touching PG");
        return false;
    }
    if (!open_)
        return false;
    const std::string id{agent_id};
    // One transaction, in the census writers' lock order (see the lock-order comment above the
    // census statements): the agent's pending events are locked in ingest_seq order first, then the
    // census rows are touched. A projection that wins the pending-row locks makes this wait; this
    // then deletes the census row it committed. No rule row is locked (a child DELETE does not lock
    // its parent), so the event-row waits stay acyclic against delete_rule too. The census-row
    // deletes of this method and of delete_rule's cascade take row locks in heap order, so two
    // transactions that overlap on several census rows could in principle deadlock; Postgres
    // aborts one, this method then returns false and the re-issue is idempotent. A pending event
    // committed after the list is read is not retired here (delete_rule has the same list-read
    // gap; the sweep of stranded pending evidence is tracked in #7147). Every statement result is
    // checked: a false return rolls the whole transaction back, so the decommission cascade records
    // Failed and the re-issue is idempotent. The failure reason is logged at warn level, because
    // the pool's last_error() is set only by connect and acquire failures and never by a failed
    // statement.
    const auto log_step_failure = [&](const char* step, PGconn* conn, const pg::PgResult& res) {
        // A null result (out of memory, a lost connection) carries no message of its own: the
        // reason is then on the connection.
        const char* msg = PQresultErrorMessage(res.get());
        if (msg == nullptr || *msg == '\0')
            msg = PQerrorMessage(conn);
        spdlog::warn("GuaranteedStateStore: delete_agent failed at step '{}' for agent={}: {}",
                     step, log_id_token(agent_id), ::yuzu::log_key_token(msg ? msg : ""));
    };
    const bool committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult locked =
            pg::exec_params(conn,
                            "SELECT event_id FROM guaranteed_state_store.guaranteed_state_events "
                            "WHERE agent_id = $1 AND projection_pending ORDER BY ingest_seq "
                            "FOR UPDATE",
                            std::vector<std::string>{id});
        if (locked.status() != PGRES_TUPLES_OK) {
            log_step_failure("pending-event lock", conn, locked);
            return false;
        }
        std::vector<std::string> pending_ids;
        for (int i = 0; i < PQntuples(locked.get()); ++i)
            pending_ids.emplace_back(PQgetvalue(locked.get(), i, 0));
        if (!pending_ids.empty()) {
            // The census rows go below, so the evidence they were projected from is retired with
            // them: left pending it would be exempt from the reaper forever and would be folded
            // into the ordering fields of a row a re-registered agent creates under the same id.
            const std::vector<std::string_view> views(pending_ids.begin(), pending_ids.end());
            pg::PgResult retired =
                pg::exec_params(conn,
                                "UPDATE guaranteed_state_store.guaranteed_state_events "
                                "SET projection_pending = false WHERE event_id = ANY($1::text[])",
                                std::vector<std::string>{pg::to_text_array(views)});
            if (retired.status() != PGRES_COMMAND_OK) {
                log_step_failure("pending-event retire", conn, retired);
                return false;
            }
        }
        pg::PgResult census = pg::exec_params(
            conn,
            "DELETE FROM guaranteed_state_store.guardian_agent_rule_status WHERE agent_id = $1",
            std::vector<std::string>{id});
        if (census.status() != PGRES_COMMAND_OK) {
            log_step_failure("census delete", conn, census);
            return false;
        }
        return true;
    });
    if (!committed)
        spdlog::debug("GuaranteedStateStore: delete_agent did not commit for agent={}",
                      log_id_token(agent_id));
    return committed;
}

void GuaranteedStateStore::set_on_rule_mutation(std::function<void()> hook) {
    on_rule_mutation_ = std::move(hook);
}

// Post-mutation hook (chaos-F1, #5513): runs AFTER the mutation committed and AFTER the
// best-effort generation bump was attempted, whether or not the bump succeeded, with no
// pool lease and no store state held. Never lets an exception escape: the mutation is
// already durable and the caller must still be told it succeeded.
void GuaranteedStateStore::notify_rule_mutation() noexcept {
    if (!on_rule_mutation_)
        return;
    try {
        on_rule_mutation_();
    } catch (const std::exception& e) {
        spdlog::warn("GuaranteedStateStore: rule-mutation hook threw: {}", ::yuzu::log_key_token(e.what()));
    } catch (...) {
        spdlog::warn("GuaranteedStateStore: rule-mutation hook threw a non-std exception");
    }
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

std::expected<PolicyGenerationRaise, PolicyGenerationRaiseError>
GuaranteedStateStore::raise_policy_generation(std::int64_t target) {
    if (target < 1 || target > guardian::kMaxPolicyGenerationTarget)
        return std::unexpected(PolicyGenerationRaiseError::kOutOfRange);
    if (!open_)
        return std::unexpected(PolicyGenerationRaiseError::kStoreUnavailable);

    // The row lock taken by the SELECT ... FOR UPDATE is held until COMMIT, so the UPDATE
    // below sees exactly the value read here, and a concurrent raise or a `value + 1` bump
    // waits for this transaction. A single UPDATE ... RETURNING could not report the value it
    // replaced under READ COMMITTED without that lock.
    PolicyGenerationRaise out;
    bool have_row = false;
    const bool committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult cur = pg::exec_params(
            conn,
            "SELECT value FROM guaranteed_state_store.guardian_meta "
            "WHERE key = 'policy_generation' FOR UPDATE",
            std::vector<std::string>{});
        if (cur.status() != PGRES_TUPLES_OK) {
            spdlog::warn("GuaranteedStateStore::raise_policy_generation: read failed: {}",
                         ::yuzu::log_key_token(PQerrorMessage(conn)));
            return false;
        }
        if (PQntuples(cur.get()) == 0) {
            spdlog::warn("GuaranteedStateStore::raise_policy_generation: policy_generation row "
                         "is missing");
            return false;
        }
        const std::int64_t before = to_i64(PQgetvalue(cur.get(), 0, 0));
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE guaranteed_state_store.guardian_meta SET value = GREATEST(value, $1::bigint) "
            "WHERE key = 'policy_generation' RETURNING value",
            std::vector<std::string>{std::to_string(target)});
        if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) == 0) {
            spdlog::warn("GuaranteedStateStore::raise_policy_generation: write failed: {}",
                         ::yuzu::log_key_token(PQerrorMessage(conn)));
            return false;
        }
        const std::int64_t after = to_i64(PQgetvalue(upd.get(), 0, 0));
        // A negative stored value can only come from an out-of-band edit; report it as 0.
        out.previous = static_cast<uint64_t>(std::max<std::int64_t>(before, 0));
        out.resulting = static_cast<uint64_t>(std::max<std::int64_t>(after, 0));
        out.raised = after > before;
        have_row = true;
        return true;
    });
    if (!committed || !have_row)
        return std::unexpected(PolicyGenerationRaiseError::kStoreUnavailable);

    // The with_txn_for lease is released, so the hook runs with no lease held (the
    // set_on_rule_mutation() contract). It is skipped when nothing changed.
    if (out.raised)
        notify_rule_mutation();
    return out;
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
    const std::int64_t stored = to_i64(PQgetvalue(res.get(), 0, 0));
    if (stored < 0) {
        // Only out-of-band SQL can store a negative generation (every in-process writer
        // keeps the column at or above zero). Casting it to unsigned would fabricate a
        // number near 2^64 that no raise, whose ceiling is far lower, could ever exceed,
        // and the reconcile would label its pushes with it. It is a degraded read instead:
        // callers abort the pass, and raise_policy_generation repairs the row
        // (GREATEST(value, target)). The log line is throttled because the heartbeat
        // reconcile reads this on every pass.
        static std::atomic<std::int64_t> last_logged_ms{0};
        const std::int64_t now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count();
        std::int64_t prev = last_logged_ms.load(std::memory_order_relaxed);
        constexpr std::int64_t kLogIntervalMs = 60'000;
        if ((prev == 0 || now_ms - prev >= kLogIntervalMs) &&
            last_logged_ms.compare_exchange_strong(prev, now_ms, std::memory_order_relaxed))
            spdlog::error("GuaranteedStateStore: stored policy_generation is negative ({}); "
                          "the generation is unreadable until it is repaired by raising it "
                          "(POST /api/v1/guaranteed-state/policy-generation/raise or the "
                          "raise_guardian_policy_generation tool)",
                          stored);
        return std::nullopt;
    }
    return static_cast<uint64_t>(stored);
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
// Returns: match = idempotent redelivery, !match = genuine field mismatch,
// unexpected = the compare itself could NOT be performed (an OPERATIONAL
// error) — mapped to Error by the caller, never a false collision. `pending` is the stored
// row's projection_pending, a HINT only: it is not part of the equality, and the repair re-reads
// it under a row lock.
struct StoredEventMatch {
    bool match{false};   // every compared field equals the incoming row
    bool pending{false}; // the stored row still carries pending census evidence (a hint)
};

std::expected<StoredEventMatch, std::string>
stored_event_matches(PGconn* conn, const GuaranteedStateEventRow& in) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT rule_id, agent_id, event_type, guard_type, guard_category, detected_value, "
        "expected_value, remediation_action, remediation_success, detection_latency_us, "
        "remediation_latency_us, timestamp, detail_json, projection_pending "
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
    return StoredEventMatch{match, to_bool(PQgetvalue(res.get(), 0, 13))};
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

// ── Census ordering (schema v4, #5690) ───────────────────────────────────────────────────────
//
// The contract: a census row says which verdict the ordering rules below chose among the events
// that reached it, never "the latest event" (usually the event with the greatest key; the one
// flagged exception is the stale-mark recovery). `key_ns` is K = min(agent stamp, receipt + 300 s),
// 0 when the stamp is absent or unusable; ties break by `ingest_seq`, the sequence value the event
// INSERT allocated (later arrival = higher sequence, not emission or commit order; distinct events
// have unique values, duplicate deliveries reuse one, values are not contiguous). `order_uncertain`
// says the row's verdict rests on a comparison that cannot be trusted (an unusable or capped key,
// a key below the high-water mark `ts_hwm`, a pending event that outranks it or shares its key, a
// sequence that disagrees with the key order, or two different verdicts with the same key) and
// clears only on a key strictly above the mark. A same-key pair of different verdicts is flagged
// because the agent stamped both with the same instant, so arrival order is the only order left
// and it is not emission order. `hwm_recv_ns` is the DATABASE time at which `ts_hwm` last rose:
// once an event arrives more than `YUZU_CENSUS_STALE_NS_` after it (or the recorded time is more
// than `YUZU_CENSUS_FUTURE_SLACK_NS_` in the database's future) with a usable key below the mark
// and a later arrival than the applied verdict, the mark is treated as stale (an agent clock
// stepped back) and the verdict follows arrival order, still flagged until a key passes the mark.
//
// The invariant the statements below maintain: a row that is NOT flagged and has no pending event
// holds the event with the greatest key, which is also the event with the greatest arrival
// sequence, and no other event of the pair shares that key with a different verdict. A recovered
// row is always flagged. (Checked by randomised schedule exploration against these statements.)
//
// A first-delivery event whose census write fails stays stored with `projection_pending`; a
// redelivery repairs it. No application-level pair lock, no heal clause and no repair skip:
// Postgres row locks serialise a pair. Every pending event row of the pair is locked in
// `ingest_seq` order in ONE statement, then the census row is touched, and `delete_rule` locks the
// rule's pending rows the same way before it retires them and deletes the rule. `delete_agent`
// (the decommission cascade, #5675) is the third writer: it locks the agent's pending rows the same
// way, then deletes the agent's census rows, and takes no rule-row lock. On the production
// paths (single-event ingest, repair, `delete_rule`, `delete_agent`) every event-row lock is taken
// by one `ORDER BY ingest_seq FOR UPDATE` statement, so event-row waits are acyclic (the census-row
// deletes of `delete_agent` and of `delete_rule`'s cascade take row locks in heap order and could
// in principle deadlock where they overlap on several rows; Postgres aborts one of them and its
// caller sees a failure); the census row follows, and the rule row (a share lock on a census
// INSERT, an exclusive lock in `delete_rule`) after the events. The two orders around the census
// and rule rows (the FK check on a census INSERT versus `delete_rule`'s delete and cascade) cannot
// close a cycle for a visibility reason, not an ordering one: whichever side takes the rule row
// first, the other waits for it and neither holds a lock the other still needs. INSERT first: its
// foreign-key check holds a share lock on the rule row, `delete_rule` waits for it, then cascades
// over the committed census row. DELETE first: the INSERT's foreign-key check waits, then fails
// 23503 (Rejected). The UPDATE arm takes no rule-row lock at all. `insert_events` (the batch path,
// no production caller) takes census rows in batch order across pairs and carries no such
// guarantee: two concurrent batches can deadlock, which surfaces per statement as Failed (and
// then rolls the batch back).

constexpr std::int64_t kReceiptSkewCapNs = 300'000'000'000LL; // receipt + 300 s bounds the key

struct OrderingKey {
    std::int64_t key{0};
    bool capped{false};
};

// K from the validated agent stamp and the receipt (both ns). A stamp at or below 0 is unusable.
OrderingKey derive_ordering_key(std::int64_t agent_ns, std::int64_t received_ns) noexcept {
    if (agent_ns <= 0)
        return {};
    const std::int64_t bound =
        received_ns > std::numeric_limits<std::int64_t>::max() - kReceiptSkewCapNs
            ? std::numeric_limits<std::int64_t>::max()
            : received_ns + kReceiptSkewCapNs;
    if (agent_ns > bound)
        return {bound, true};
    return {agent_ns, false};
}

std::int64_t wall_clock_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// The ONE predicate for "this event takes part in the census": it decides whether any census
// statement runs for it (and so whether its pending evidence can ever be recorded).
bool census_bearing(const GuaranteedStateEventRow& row) {
    return !row.agent_id.empty() && !row.rule_id.empty() && !is_reserved_rule_id(row.rule_id) &&
           event_state_from_type(row.event_type) != nullptr;
}

// The emit-order pair (schema v5) as the store writes it: both set and each in [1, 2^62), else
// unpaired (0/0 here; NULL/NULL in the columns). Re-validated at every write and on every read
// back from the events table, so a direct caller or a damaged row can never store or project a
// half pair. The ingest boundary applies the same bounds (`pair_from_wire`); this is the store's
// own copy of the rule, not a second source of it.
struct CensusPair {
    std::int64_t boot_epoch{0};
    std::int64_t emit_seq{0};
};

CensusPair census_pair(std::optional<std::int64_t> boot_epoch,
                       std::optional<std::int64_t> emit_seq) noexcept {
    constexpr std::int64_t kPairLimit = std::int64_t{1} << 62;
    if (boot_epoch && emit_seq && *boot_epoch >= 1 && *boot_epoch < kPairLimit && *emit_seq >= 1 &&
        *emit_seq < kPairLimit)
        return {*boot_epoch, *emit_seq};
    return {};
}

enum class ProjectionSource {
    FirstDelivery, // the event was just inserted (not pending) in this transaction
    Repair,        // a redelivery of an event stored with pending evidence
    Batch,         // `insert_events`: a failed projection aborts and rolls back the whole batch
};

const char* projection_source_label(ProjectionSource s) {
    switch (s) {
    case ProjectionSource::FirstDelivery:
        return "first_delivery";
    case ProjectionSource::Repair:
        return "repair";
    case ProjectionSource::Batch:
        return "batch";
    }
    return "unknown";
}

enum class CensusOutcome {
    Applied,        // the event became the row's verdict
    RefusedFlagged, // a row was touched but the event did not become the verdict (flag raised)
    RefusedNoop,    // zero rows: the event is dominated and nothing changed
    PendingRetired, // repair only: the event's pending evidence was retired concurrently
    Rejected,       // the rule is gone (the census foreign key, 23503); definitive, not a fault
    Failed,         // any other statement error; savepoint rolled back and released; the event is
                    // left with pending evidence (a first delivery records it now, a repair has
                    // it; a batch aborts and rolls back instead)
    Abandoned,      // a savepoint control or the pending-evidence write failed; abandon the txn
};

const char* census_outcome_label(CensusOutcome o) {
    switch (o) {
    case CensusOutcome::Applied:
        return "applied";
    case CensusOutcome::RefusedFlagged:
        return "refused_flagged";
    case CensusOutcome::RefusedNoop:
        return "refused_noop";
    case CensusOutcome::PendingRetired:
        return "pending_retired";
    case CensusOutcome::Rejected:
        return "rejected";
    case CensusOutcome::Failed:
        return "failed";
    case CensusOutcome::Abandoned:
        return "abandoned";
    }
    return "unknown";
}

// Count one projection outcome. Best-effort: a metrics failure must never reach the ingest thread.
void count_projection(yuzu::MetricsRegistry* metrics, ProjectionSource source,
                      CensusOutcome outcome) noexcept {
    if (metrics == nullptr)
        return;
    try {
        metrics
            ->counter("yuzu_server_guardian_census_projection_total",
                      {{"source", projection_source_label(source)},
                       {"outcome", census_outcome_label(outcome)}})
            .increment();
    } catch (...) { // best-effort metric
    }
}

// COMMIT of an aborted transaction reports success to libpq (the server answers ROLLBACK), so a
// caller checks the transaction is still healthy before it commits. Every non-Abandoned outcome
// of project_rule_status leaves it healthy; this makes that a checked fact instead of a habit.
bool txn_healthy(PGconn* conn) noexcept {
    return PQtransactionStatus(conn) == PQTRANS_INTRANS;
}

// Lock EVERY committed pending event of the pair in ingest_seq order, in one statement. A first
// delivery or batch row is stored not pending, so it is never in this result; a Repair's own row
// is: absent means it was retired concurrently (no repair), present means its stored
// (proj_key, proj_key_capped, ingest_seq) are the projection inputs. Every other row is the `seen`
// list.
constexpr const char* kCensusLockAll =
    "SELECT event_id, proj_key, proj_key_capped, ingest_seq, boot_epoch, emit_seq "
    "FROM guaranteed_state_store.guaranteed_state_events "
    "WHERE rule_id = $2 AND agent_id = $1 AND projection_pending "
    "ORDER BY ingest_seq FOR UPDATE";

// "Not dominated by the census row": a seen event that outranks it, that arrived later than the
// verdict (higher sequence) although its key is not higher, or that carries the SAME usable key as
// the verdict. Retiring such an event without a flag would lose the disagreement between arrival
// order and key order. The same-key term does not compare verdicts (a pending event's state is not
// stored beside its key), so a same-key pending event with the SAME verdict flags too: pending
// events are rare, and an over-flag loses nothing.
#define YUZU_CENSUS_SEEN_DISAGREES_                                                                \
    "((e.proj_key, e.ingest_seq) > (COALESCE(c.key_ns, 0), COALESCE(c.ingest_seq, 0)) "            \
    "OR e.ingest_seq > COALESCE(c.ingest_seq, 0) "                                                 \
    "OR (e.proj_key <> 0 AND e.proj_key = COALESCE(c.key_ns, 0) "                                  \
    "    AND e.ingest_seq <> COALESCE(c.ingest_seq, 0)))"

// The time every `hwm_recv_ns` stamp and the stale-mark test use: the DATABASE clock, never a
// replica's, so every replica agrees on it (the AuthDB #3715 precedent). `statement_timestamp()` is
// ONE value for the whole statement, so the six expansions of the recovery test below cannot
// disagree with one another and tear a row (a volatile `clock_timestamp()` could, measured). It is
// read at statement START, before any row-lock wait, so a time recorded by a transaction that
// started later can look slightly in the future: the future-dated clause carries a slack for that.
#define YUZU_CENSUS_DB_NOW_NS_                                                                     \
    "(floor(extract(epoch FROM statement_timestamp()) * 1000000000))::bigint"
// A recorded time more than this far ahead of the database clock (five minutes) is a stepped-back
// clock, not a lock wait.
// (Unrelated to `kReceiptSkewCapNs`, which bounds an agent stamp ahead of receipt; both happen to
// be 300 s.) The slack assumes a statement does not wait on a row lock longer than the pool's
// statement timeout (30 s by default); a configuration that raises that past 300 s reopens a
// spurious recovery, which is still flagged.
#define YUZU_CENSUS_FUTURE_SLACK_NS_ "300000000000"

#define YUZU_CENSUS_FOLD_MAX_KEY_                                                                  \
    "(SELECT max(e.proj_key) FROM guaranteed_state_store.guaranteed_state_events e "               \
    "  WHERE e.event_id = ANY($3::text[]) AND " YUZU_CENSUS_SEEN_DISAGREES_ ")"

// Fold the seen events into the existing row (UPDATE arm only; a no-op when the row is absent).
// CORRELATED on c so Postgres re-evaluates it against the row's latest version after a lock wait.
// `hwm_recv_ns` becomes the database time when the fold raises the mark.
constexpr const char* kCensusFold =
    "UPDATE guaranteed_state_store.guardian_agent_rule_status c "
    "SET order_uncertain = true, "
    "    hwm_recv_ns = CASE WHEN COALESCE(c.ts_hwm, 0) < COALESCE(" YUZU_CENSUS_FOLD_MAX_KEY_
    ", 0) "
    "                       THEN " YUZU_CENSUS_DB_NOW_NS_ " ELSE c.hwm_recv_ns END, "
    "    ts_hwm = NULLIF(GREATEST(COALESCE(c.ts_hwm, 0), "
    "        COALESCE(" YUZU_CENSUS_FOLD_MAX_KEY_ ", 0)), 0) "
    "WHERE c.agent_id = $1 AND c.rule_id = $2 "
    "  AND EXISTS (SELECT 1 FROM guaranteed_state_store.guaranteed_state_events e "
    "               WHERE e.event_id = ANY($3::text[]) AND " YUZU_CENSUS_SEEN_DISAGREES_ ")";

// The highest arrival sequence among the seen (pending) events. The clear below retires the seen
// events the final row dominates, so their arrival order must be remembered on the row or a later
// apply with a higher key would clear the doubt they raised (the row tracks `seq_hwm` for this).
#define YUZU_CENSUS_SEEN_MAX_SEQ_                                                                  \
    "(SELECT max(s.ingest_seq) FROM guaranteed_state_store.guaranteed_state_events s "             \
    "WHERE s.event_id = ANY($8::text[]))"

// The apply predicate P: the incoming (key, seq) is above the row's.
#define YUZU_CENSUS_APPLY_P_                                                                       \
    "(EXCLUDED.key_ns > COALESCE(c.key_ns, 0) OR (EXCLUDED.key_ns = COALESCE(c.key_ns, 0) "        \
    "AND EXCLUDED.ingest_seq > COALESCE(c.ingest_seq, 0)))"

// Stale-mark recovery R: a usable key below the mark, a later arrival than the applied verdict, and
// a mark that last rose more than YUZU_CENSUS_STALE_NS_ (1 hour of database time) ago, or whose
// recorded time is more than YUZU_CENSUS_FUTURE_SLACK_NS_ in the database's future (a stepped-back
// clock: treated as stale, never as an indefinite hold; a step of D back lengthens a hold by at
// most D). A row with no recorded time (hwm_recv_ns NULL) never recovers.
#define YUZU_CENSUS_STALE_NS_ "3600000000000"
#define YUZU_CENSUS_RECOVER_                                                                       \
    "(EXCLUDED.key_ns > 0 AND EXCLUDED.key_ns < COALESCE(c.ts_hwm, 0) "                            \
    "AND EXCLUDED.ingest_seq > COALESCE(c.ingest_seq, 0) AND c.hwm_recv_ns IS NOT NULL "           \
    "AND (c.hwm_recv_ns > " YUZU_CENSUS_DB_NOW_NS_ " + " YUZU_CENSUS_FUTURE_SLACK_NS_ " "          \
    "     OR " YUZU_CENSUS_DB_NOW_NS_ " - c.hwm_recv_ns > " YUZU_CENSUS_STALE_NS_ "))"

#define YUZU_CENSUS_APPLY_ "(" YUZU_CENSUS_APPLY_P_ " OR " YUZU_CENSUS_RECOVER_ ")"

// Two different verdicts stamped with the same usable key: arrival order is all that separates
// them.
#define YUZU_CENSUS_TIE_                                                                           \
    "(EXCLUDED.key_ns <> 0 AND EXCLUDED.key_ns = COALESCE(c.key_ns, 0) AND EXCLUDED.state <> "     \
    "c.state)"

// K + sticky upsert. $5 key, $6 seq, $7 capped, $8 seen list, $4 the event's timestamp text,
// $9 boot_epoch and $10 emit_seq (0/0 = unpaired). The pair rides the verdict: it is written by
// the same applied test as `state`, so a refused event's pair never reaches the row, and an
// applied unpaired verdict leaves NULL/NULL. Stored, not compared: nothing here reads $9/$10 to
// decide.
constexpr const char* kCensusUpsert =
    "INSERT INTO guaranteed_state_store.guardian_agent_rule_status AS c "
    "(agent_id, rule_id, state, updated_at, key_ns, ingest_seq, ts_hwm, seq_hwm, hwm_recv_ns, "
    "order_uncertain, boot_epoch, emit_seq) "
    "SELECT $1::text, $2::text, $3::text, $4::text, $5::bigint, $6::bigint, "
    "       NULLIF(GREATEST($5::bigint, COALESCE(pm.mk, 0)), 0), "
    "       GREATEST($6::bigint, COALESCE(" YUZU_CENSUS_SEEN_MAX_SEQ_ ", 0)), "
    "       CASE WHEN $5::bigint > 0 OR pm.mk IS NOT NULL THEN " YUZU_CENSUS_DB_NOW_NS_ " END, "
    "       ($5::bigint = 0 OR $7::boolean OR pm.mk IS NOT NULL), "
    "       NULLIF($9::bigint, 0), NULLIF($10::bigint, 0) "
    "  FROM (SELECT max(p.proj_key) AS mk "
    "          FROM guaranteed_state_store.guaranteed_state_events p "
    "         WHERE p.event_id = ANY($8::text[]) "
    "           AND ((p.proj_key, p.ingest_seq) > ($5::bigint, $6::bigint) "
    "                OR p.ingest_seq > $6::bigint "
    "                OR (p.proj_key <> 0 AND p.proj_key = $5::bigint "
    "                    AND p.ingest_seq <> $6::bigint))) pm "
    "ON CONFLICT (agent_id, rule_id) DO UPDATE SET "
    "  state      = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.state      ELSE c.state      END, "
    "  updated_at = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.updated_at ELSE c.updated_at END, "
    "  key_ns     = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.key_ns     ELSE c.key_ns     END, "
    "  ingest_seq = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.ingest_seq ELSE c.ingest_seq END, "
    "  boot_epoch = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.boot_epoch ELSE c.boot_epoch END, "
    "  emit_seq   = CASE WHEN " YUZU_CENSUS_APPLY_
    " THEN EXCLUDED.emit_seq   ELSE c.emit_seq   END, "
    "  hwm_recv_ns = CASE WHEN EXCLUDED.key_ns > COALESCE(c.ts_hwm, 0) THEN " YUZU_CENSUS_DB_NOW_NS_
    " "
    "                     ELSE c.hwm_recv_ns END, "
    "  ts_hwm     = NULLIF(GREATEST(COALESCE(c.ts_hwm, 0), EXCLUDED.key_ns), 0), "
    "  seq_hwm    = GREATEST(COALESCE(c.seq_hwm, c.ingest_seq, 0), EXCLUDED.ingest_seq, "
    "                        COALESCE(" YUZU_CENSUS_SEEN_MAX_SEQ_ ", 0)), "
    "  order_uncertain = CASE WHEN " YUZU_CENSUS_APPLY_ " THEN "
    "      (EXCLUDED.key_ns = 0 "
    "       OR $7::boolean "
    "       OR (c.key_ns IS NOT NULL AND c.key_ns = 0) "
    "       OR EXCLUDED.key_ns < COALESCE(c.ts_hwm, 0) "
    "       OR (c.order_uncertain AND EXCLUDED.key_ns <= COALESCE(c.ts_hwm, 0)) "
    "       OR EXCLUDED.ingest_seq < COALESCE(c.seq_hwm, c.ingest_seq, 0) "
    "       OR " YUZU_CENSUS_TIE_ " "
    "       OR EXISTS (SELECT 1 FROM guaranteed_state_store.guaranteed_state_events p "
    "                   WHERE p.event_id = ANY($8::text[]) "
    "                     AND (p.ingest_seq > EXCLUDED.ingest_seq "
    "                          OR (p.proj_key <> 0 AND p.proj_key = EXCLUDED.key_ns "
    "                              AND p.ingest_seq <> EXCLUDED.ingest_seq)))) "
    "    ELSE (c.order_uncertain OR EXCLUDED.ingest_seq > COALESCE(c.ingest_seq, 0) "
    "          OR " YUZU_CENSUS_TIE_ ") END "
    "WHERE " YUZU_CENSUS_APPLY_ " OR EXCLUDED.ingest_seq > COALESCE(c.ingest_seq, 0) "
    "   OR " YUZU_CENSUS_TIE_ " "
    "   OR EXCLUDED.key_ns > COALESCE(c.ts_hwm, 0) "
    "   OR COALESCE(" YUZU_CENSUS_SEEN_MAX_SEQ_ ", 0) > COALESCE(c.seq_hwm, c.ingest_seq, 0) "
    "RETURNING (c.ingest_seq = $6::bigint) AS applied, c.order_uncertain";

// Retire ONLY the event itself and the rows the pair-lock statement returned, and only what the
// final row dominates. A pending row that committed after the lock statement is never touched.
constexpr const char* kCensusClear =
    "UPDATE guaranteed_state_store.guaranteed_state_events p SET projection_pending = false "
    "FROM guaranteed_state_store.guardian_agent_rule_status c "
    "WHERE c.agent_id = $1 AND c.rule_id = $2 "
    "  AND p.agent_id = c.agent_id AND p.rule_id = c.rule_id AND p.projection_pending "
    "  AND (p.event_id = $3 OR p.event_id = ANY($4::text[])) "
    "  AND (p.proj_key, p.ingest_seq) <= (COALESCE(c.key_ns, 0), COALESCE(c.ingest_seq, 0))";

// After a rejected (rule gone) REPAIR the event has nothing to project onto: retire its pending
// evidence in the OUTER transaction, after the savepoint was rolled back and released. (A first
// delivery is stored not pending, so a rejected one needs no retire.)
constexpr const char* kCensusOuterClear =
    "UPDATE guaranteed_state_store.guaranteed_state_events SET projection_pending = false "
    "WHERE event_id = $1";

// A first delivery is stored NOT pending: the happy path writes the event once. Only when its
// projection fails is the evidence recorded, in the outer transaction after the savepoint was
// rolled back and released, so the event and its pending flag commit together or not at all.
constexpr const char* kCensusMarkPending =
    "UPDATE guaranteed_state_store.guaranteed_state_events SET projection_pending = true "
    "WHERE event_id = $1";

#undef YUZU_CENSUS_SEEN_DISAGREES_
#undef YUZU_CENSUS_SEEN_MAX_SEQ_
#undef YUZU_CENSUS_APPLY_
#undef YUZU_CENSUS_APPLY_P_
#undef YUZU_CENSUS_RECOVER_
#undef YUZU_CENSUS_STALE_NS_
#undef YUZU_CENSUS_TIE_
#undef YUZU_CENSUS_FOLD_MAX_KEY_
#undef YUZU_CENSUS_DB_NOW_NS_
#undef YUZU_CENSUS_FUTURE_SLACK_NS_

constexpr const char* kCensusRuleFkName = "guardian_agent_rule_status_rule_fk";
// The two unique constraints an event INSERT can hit; the boot shape check requires both names.
constexpr const char* kEventPrimaryKeyName = "guaranteed_state_events_pkey";
constexpr const char* kEventSeqIndexName = "idx_gse_ingest_seq";

// Project one census-bearing event into the (agent, rule) row inside the caller's open
// transaction, under SAVEPOINT census_upsert: pair lock, fold, K + sticky upsert, fold again,
// clear. A failed statement is rolled back to the savepoint and released, so it never aborts the
// transaction holding the event.
//   Failed:    counted on `failures` and logged at error. A first delivery records the event's
//              pending evidence now, in the outer transaction (it was stored not pending, so the
//              happy path writes the event once); a repair's evidence is already recorded; a
//              batch records none, so `insert_events` aborts and rolls back the whole batch.
//   Rejected:  the census foreign key (and only that constraint) refused the write because the
//              rule is gone: definitive, not counted. A repair retires the evidence it was
//              repairing in the outer transaction; a first delivery has none.
//   Abandoned: a savepoint control statement, or the outer pending-evidence write, failed, so
//              the transaction may be aborted: the caller must return an error without
//              committing (COMMIT of an aborted transaction reports success to libpq).
// For a Repair the three inputs and the pair are overwritten from the locked row's stored values.
[[nodiscard]] CensusOutcome project_rule_status(PGconn* conn, std::atomic<uint64_t>& failures,
                                                const std::function<void()>& lock_barrier,
                                                const GuaranteedStateEventRow& row,
                                                const char* state, ProjectionSource source,
                                                std::int64_t key, std::int64_t seq, bool capped) {
    const auto control = [conn](const char* sql) {
        return pg::exec_params(conn, sql, std::vector<std::string>{}).status() ==
               PGRES_COMMAND_OK;
    };
    if (!control("SAVEPOINT census_upsert"))
        return CensusOutcome::Abandoned;
    // A Repair projects the pair stored with the event (read back below), never the redelivery's.
    CensusPair pair = source == ProjectionSource::Repair
                          ? CensusPair{}
                          : census_pair(row.boot_epoch, row.emit_seq);

    const auto fail = [&](pg::PgResult& res) -> CensusOutcome {
        const char* state_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const char* name_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
        const bool rejected = state_p != nullptr && std::string_view(state_p) == "23503" &&
                              name_p != nullptr && std::string_view(name_p) == kCensusRuleFkName;
        const std::string err = PQresultErrorMessage(res.get());
        // ROLLBACK TO keeps the savepoint defined, so release it too.
        if (!control("ROLLBACK TO SAVEPOINT census_upsert") ||
            !control("RELEASE SAVEPOINT census_upsert")) {
            spdlog::error("GuaranteedStateStore: census write abandoned, the census statement "
                          "failed and its savepoint could not be rolled back and released, the "
                          "transaction is abandoned (a first delivery is not stored; a repair "
                          "leaves the event stored and pending) event_id={} agent_id={} "
                          "rule_id={}: {}",
                          log_id_token(row.event_id), log_id_token(row.agent_id),
                          log_id_token(row.rule_id), ::yuzu::log_key_token(err));
            return CensusOutcome::Abandoned;
        }
        if (rejected) {
            spdlog::debug("GuaranteedStateStore: census write refused, rule not defined on this "
                          "server agent_id={} rule_id={}",
                          log_id_token(row.agent_id), log_id_token(row.rule_id));
            // A first delivery was stored not pending, so there is nothing to retire; a repair
            // retires the evidence it was repairing, in the outer transaction.
            if (source == ProjectionSource::Repair) {
                pg::PgResult outer = pg::exec_params(conn, kCensusOuterClear,
                                                     std::vector<std::string>{row.event_id});
                if (outer.status() != PGRES_COMMAND_OK) {
                    spdlog::error("GuaranteedStateStore: could not retire the pending evidence "
                                  "of an event whose rule is gone, the event stays stored and "
                                  "pending event_id={} agent_id={} rule_id={}: {}",
                                  log_id_token(row.event_id), log_id_token(row.agent_id),
                                  log_id_token(row.rule_id),
                                  ::yuzu::log_key_token(PQresultErrorMessage(outer.get())));
                    return CensusOutcome::Abandoned;
                }
            }
            return CensusOutcome::Rejected;
        }
        if (source == ProjectionSource::FirstDelivery) {
            pg::PgResult mark =
                pg::exec_params(conn, kCensusMarkPending, std::vector<std::string>{row.event_id});
            if (mark.status() != PGRES_COMMAND_OK) {
                spdlog::error("GuaranteedStateStore: could not record the pending evidence of an "
                              "event whose census write failed, the event is not stored "
                              "event_id={} agent_id={} rule_id={}: {}",
                              log_id_token(row.event_id), log_id_token(row.agent_id),
                              log_id_token(row.rule_id),
                              ::yuzu::log_key_token(PQresultErrorMessage(mark.get())));
                return CensusOutcome::Abandoned;
            }
        }
        failures.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("GuaranteedStateStore: census upsert failed (status row not updated; a "
                      "first delivery or repair keeps the event with pending evidence, a batch "
                      "is rolled back) event_id={} agent_id={} rule_id={}: {}",
                      log_id_token(row.event_id), log_id_token(row.agent_id),
                      log_id_token(row.rule_id), ::yuzu::log_key_token(err));
        return CensusOutcome::Failed;
    };

    pg::PgResult lock =
        pg::exec_params(conn, kCensusLockAll, std::vector<std::string>{row.agent_id, row.rule_id});
    if (lock.status() != PGRES_TUPLES_OK)
        return fail(lock);
    if (lock_barrier)
        lock_barrier();
    std::vector<std::string> seen;
    bool self_found = false;
    for (int i = 0; i < PQntuples(lock.get()); ++i) {
        const std::string id = PQgetvalue(lock.get(), i, 0);
        if (id != row.event_id) {
            seen.push_back(id);
            continue;
        }
        self_found = true;
        if (source == ProjectionSource::Repair) {
            key = PQgetisnull(lock.get(), i, 1) ? 0 : to_i64(PQgetvalue(lock.get(), i, 1));
            capped = to_bool(PQgetvalue(lock.get(), i, 2));
            seq = to_i64(PQgetvalue(lock.get(), i, 3));
            const auto nullable = [&](int col) -> std::optional<std::int64_t> {
                if (PQgetisnull(lock.get(), i, col))
                    return std::nullopt;
                return to_i64(PQgetvalue(lock.get(), i, col));
            };
            pair = census_pair(nullable(4), nullable(5));
        }
    }
    if (source == ProjectionSource::Repair && !self_found) {
        spdlog::debug("GuaranteedStateStore: pending evidence retired concurrently, no repair "
                      "event_id={}",
                      log_id_token(row.event_id));
        return control("RELEASE SAVEPOINT census_upsert") ? CensusOutcome::PendingRetired
                                                          : CensusOutcome::Abandoned;
    }

    std::vector<std::string_view> seen_views(seen.begin(), seen.end());
    const std::string seen_arr = pg::to_text_array(seen_views);

    if (!seen.empty()) {
        pg::PgResult fold = pg::exec_params(
            conn, kCensusFold, std::vector<std::string>{row.agent_id, row.rule_id, seen_arr});
        if (fold.status() != PGRES_COMMAND_OK)
            return fail(fold);
    }
    pg::PgResult up = pg::exec_params(
        conn, kCensusUpsert,
        std::vector<std::string>{row.agent_id, row.rule_id, std::string(state), row.timestamp,
                                 std::to_string(key), std::to_string(seq),
                                 capped ? "true" : "false", seen_arr,
                                 std::to_string(pair.boot_epoch), std::to_string(pair.emit_seq)});
    if (up.status() != PGRES_TUPLES_OK)
        return fail(up);
    // Fold AGAIN, now that the row exists and is final for this statement: the first fold ran
    // before the upsert and cannot see a census row another writer inserted but had not yet
    // committed, so a seen event that disagrees with the row it lost to (a later arrival with a
    // lower key) would otherwise be retired below with the row left unflagged. Idempotent where
    // the first fold already applied; a no-op when `seen` is empty.
    if (!seen.empty()) {
        pg::PgResult refold = pg::exec_params(
            conn, kCensusFold, std::vector<std::string>{row.agent_id, row.rule_id, seen_arr});
        if (refold.status() != PGRES_COMMAND_OK)
            return fail(refold);
    }
    CensusOutcome out = CensusOutcome::RefusedNoop;
    if (PQntuples(up.get()) == 1)
        out = !PQgetisnull(up.get(), 0, 0) && std::string_view(PQgetvalue(up.get(), 0, 0)) == "t"
                  ? CensusOutcome::Applied
                  : CensusOutcome::RefusedFlagged;
    // The clear retires pending rows. A first delivery or batch row is stored not pending, so with
    // nothing seen there is nothing for it to retire; only a repair (whose own row is pending) or
    // a projection that saw other pending rows needs it.
    if (source == ProjectionSource::Repair || !seen.empty()) {
        pg::PgResult clear = pg::exec_params(
            conn, kCensusClear,
            std::vector<std::string>{row.agent_id, row.rule_id, row.event_id, seen_arr});
        if (clear.status() != PGRES_COMMAND_OK)
            return fail(clear);
    }
    return control("RELEASE SAVEPOINT census_upsert") ? out : CensusOutcome::Abandoned;
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

    // The ordering inputs: K from the validated agent stamp and the receipt (the store's own clock
    // when the caller supplied none), and whether this event takes part in the census at all.
    const OrderingKey ordering =
        derive_ordering_key(row.agent_ns, row.received_ns != 0 ? row.received_ns : wall_clock_ns());
    const bool bearing = census_bearing(row);
    const CensusPair wire_pair = census_pair(row.boot_epoch, row.emit_seq);

    // ingest_seq is never named: the identity allocates it, and RETURNING hands it back as the
    // event's place in the arrival order.
    pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guaranteed_state_events "
        "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
        " detected_value, expected_value, remediation_action, remediation_success, "
        " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, detail_json, "
        " proj_key, proj_key_capped, projection_pending, boot_epoch, emit_seq) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
        "$15::bigint,$16,$17::bigint,$18::boolean,false,NULLIF($19::bigint,0),"
        "NULLIF($20::bigint,0)) "
        "RETURNING ingest_seq",
        std::vector<std::string>{
            row.event_id, row.rule_id, row.agent_id, row.event_type, row.severity, row.guard_type,
            row.guard_category, row.detected_value, row.expected_value, row.remediation_action,
            std::string(row.remediation_success ? "true" : "false"),
            std::to_string(row.detection_latency_us), std::to_string(row.remediation_latency_us),
            row.timestamp, std::to_string(ttl), row.detail_json, std::to_string(ordering.key),
            ordering.capped ? "true" : "false", std::to_string(wire_pair.boot_epoch),
            std::to_string(wire_pair.emit_seq)});

    if (ins.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        const char* constraint_p = PQresultErrorField(ins.get(), PG_DIAG_CONSTRAINT_NAME);
        const std::string constraint = constraint_p ? constraint_p : "";
        const std::string err = PQresultErrorMessage(ins.get());
        if (sqlstate == "23505" && constraint == kEventPrimaryKeyName) {
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
            if (matched->match) {
                // A redelivery of an event stored with pending census evidence repairs it: the
                // event is projected from its STORED ordering inputs (the redelivery's receipt is
                // never used). Failed leaves the evidence for the next redelivery, but the call
                // still acks the event, so a redelivery happens only if the agent re-sends it; a
                // stranded row is covered by the pending-evidence sweep follow-up (#7147).
                if (matched->pending && bearing) {
                    const CensusOutcome repaired =
                        project_rule_status(conn, census_proj_failures_, census_lock_barrier_, row,
                                            event_state_from_type(row.event_type),
                                            ProjectionSource::Repair, 0, 0, false);
                    count_projection(metrics_, ProjectionSource::Repair, repaired);
                    if (repaired == CensusOutcome::Abandoned)
                        return op_error(std::string("census savepoint failed: ") +
                                            PQerrorMessage(conn),
                                        kReasonQueryError);
                    if (pre_commit_hook_)
                        pre_commit_hook_(conn);
                    if (!txn_healthy(conn))
                        return op_error("transaction aborted before the repair commit",
                                        kReasonQueryError);
                    if (!txn.commit())
                        return op_error(std::string("commit failed: ") + PQerrorMessage(conn),
                                        kReasonQueryError);
                }
                events_redelivered_.fetch_add(1, std::memory_order_relaxed);
                return {EventInsertOutcome::Redelivered, {}};
            }
            events_dropped_.fetch_add(1, std::memory_order_relaxed);
            return {EventInsertOutcome::Conflict,
                    format_conflict("event_id '" + row.event_id +
                                    "' already exists with different fields")};
        }
        if (sqlstate == "23505") {
            // The sequence index (or any other unique constraint) refused the insert: not a
            // redelivery and not a collision of event ids, so it must never read as either.
            return op_error(
                constraint == kEventSeqIndexName
                    ? "ingest sequence collision (constraint " + constraint + "): " + err
                    : "unique violation on unexpected constraint '" + constraint + "': " + err,
                kReasonQueryError);
        }
        return op_error("insert failed: " + err, kReasonQueryError);
    }
    if (PQntuples(ins.get()) != 1)
        return op_error("insert returned no ingest_seq", kReasonQueryError);
    const std::int64_t ingest_seq = to_i64(PQgetvalue(ins.get(), 0, 0));

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

    // Census upsert in the SAME transaction as the event, so the two commit or roll back
    // together; a refused or failed census write is rolled back to its own savepoint and
    // never takes the event with it (see project_rule_status).
    if (bearing) {
        const CensusOutcome projected = project_rule_status(
            conn, census_proj_failures_, census_lock_barrier_, row,
            event_state_from_type(row.event_type), ProjectionSource::FirstDelivery, ordering.key,
            ingest_seq, ordering.capped);
        count_projection(metrics_, ProjectionSource::FirstDelivery, projected);
        if (projected == CensusOutcome::Abandoned)
            return op_error(std::string("census savepoint failed: ") + PQerrorMessage(conn),
                            kReasonQueryError);
    }

    // Checked for EVERY event, not only census-bearing ones: the DEX savepoint block above discards
    // the results of its own SAVEPOINT / ROLLBACK TO / RELEASE, and COMMIT of an aborted
    // transaction reports success to libpq while storing nothing.
    if (pre_commit_hook_)
        pre_commit_hook_(conn);
    if (!txn_healthy(conn))
        return op_error("transaction aborted before commit", kReasonQueryError);

    if (!txn.commit())
        return op_error(std::string("commit failed: ") + PQerrorMessage(conn), kReasonQueryError);
    const std::int64_t committed_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();

    events_written_.fetch_add(1, std::memory_order_relaxed);
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
        const OrderingKey ordering = derive_ordering_key(
            row.agent_ns, row.received_ns != 0 ? row.received_ns : wall_clock_ns());
        const CensusPair wire_pair = census_pair(row.boot_epoch, row.emit_seq);
        // projection_pending is explicitly false: this path records no pending evidence, so a
        // failed census write aborts the batch (below) instead of stranding the event.
        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
            " detected_value, expected_value, remediation_action, remediation_success, "
            " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, "
            " detail_json, proj_key, proj_key_capped, projection_pending, boot_epoch, "
            " emit_seq) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
            "$15::bigint,$16,$17::bigint,$18::boolean,false,NULLIF($19::bigint,0),"
            "NULLIF($20::bigint,0)) "
            "RETURNING ingest_seq",
            std::vector<std::string>{
                row.event_id, row.rule_id, row.agent_id, row.event_type, row.severity,
                row.guard_type, row.guard_category, row.detected_value, row.expected_value,
                row.remediation_action, std::string(row.remediation_success ? "true" : "false"),
                std::to_string(row.detection_latency_us),
                std::to_string(row.remediation_latency_us), row.timestamp, std::to_string(ttl),
                row.detail_json, std::to_string(ordering.key), ordering.capped ? "true" : "false",
                std::to_string(wire_pair.boot_epoch), std::to_string(wire_pair.emit_seq)});
        if (ins.status() != PGRES_TUPLES_OK) {
            const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
            const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
            const char* constraint_p = PQresultErrorField(ins.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            if (sqlstate == "23505" && constraint == kEventPrimaryKeyName)
                return std::unexpected(
                    format_conflict("event_id '" + row.event_id + "' already exists"));
            if (sqlstate == "23505")
                return std::unexpected("unexpected unique violation on constraint '" + constraint +
                                       "': " + std::string(PQresultErrorMessage(ins.get())));
            return std::unexpected("insert failed: " + std::string(PQresultErrorMessage(ins.get())));
        }
        if (PQntuples(ins.get()) != 1)
            return std::unexpected("insert returned no ingest_seq");
        const std::int64_t ingest_seq = to_i64(PQgetvalue(ins.get(), 0, 0));
        // Census upsert inside the batch transaction, rolled back with the batch on any later
        // failure; a refused or failed census write is isolated by its own savepoint, as in
        // insert_event_classified (a failed one then aborts the batch, below).
        if (census_bearing(row)) {
            const CensusOutcome projected =
                project_rule_status(conn, census_proj_failures_, census_lock_barrier_, row,
                                    event_state_from_type(row.event_type), ProjectionSource::Batch,
                                    ordering.key, ingest_seq, ordering.capped);
            count_projection(metrics_, ProjectionSource::Batch, projected);
            if (projected == CensusOutcome::Abandoned)
                return std::unexpected(std::string("census savepoint failed: ") +
                                       PQerrorMessage(conn));
            // The batch path records no pending evidence, so an event whose census write failed
            // would be stored with nothing to repair it. Abort and roll back the whole batch
            // instead, as for any other statement failure in it.
            if (projected == CensusOutcome::Failed)
                return std::unexpected("census projection failed for event_id '" + row.event_id +
                                       "'; batch rolled back");
        }
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

    // After the whole loop, not after each projection: the DEX savepoint block inside it ignores
    // the results of its own ROLLBACK TO / RELEASE, so only a check right before COMMIT can see an
    // aborted transaction that COMMIT would otherwise report as success.
    if (pre_commit_hook_)
        pre_commit_hook_(conn);
    if (!txn_healthy(conn))
        return std::unexpected("transaction aborted before commit");
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

std::optional<std::vector<DexAppStabilityRow>>
GuaranteedStateStore::dex_app_stability_checked(const std::string& since, const std::string& platform,
                                                int app_limit, int version_limit,
                                                std::int64_t per_device_cap,
                                                const std::vector<std::string>& online_agent_ids,
                                                const std::vector<std::pair<std::string, std::int64_t>>&
                                                    per_subject_caps) const {
    static DegradeSampler sampler;
    static DegradeSampler budget_sampler; // a refusal storm must not hide a real fault's log line
    struct Slot {
        std::atomic<int>& n;
        ~Slot() { n.fetch_sub(1, std::memory_order_relaxed); }
    };
    const Slot slot{apps_reads_in_flight_};
    // A refused caller holds its increment until it returns, so a burst can refuse
    // a few reads more than necessary for an instant; the refusal is retryable and
    // the budget is never exceeded.
    if (apps_reads_in_flight_.fetch_add(1, std::memory_order_relaxed) >= apps_read_budget_.load()) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonConcurrencyBudget, kDegradeSource, budget_sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_app_stability: concurrency budget ({}) reached",
                         apps_read_budget_.load());
        return std::nullopt;
    }
    // Ceiling: every online id travels as one text[] parameter per request;
    // measured flat to 30,000 ids (2.6 s vs 2.7 s). Beyond a few hundred thousand
    // devices replace it with a join against shared presence in the database.
    std::vector<std::string_view> online_views;
    online_views.reserve(online_agent_ids.size());
    for (const auto& a : online_agent_ids)
        online_views.emplace_back(a);
    const std::string online_array = pg::to_text_array(online_views);
    // Per-subject caps ($7 subjects, $8 caps): at most the policy's 200 overrides.
    std::vector<std::string> cap_values;
    std::vector<std::string_view> cap_subject_views, cap_value_views;
    cap_values.reserve(per_subject_caps.size());
    for (const auto& entry : per_subject_caps) {
        cap_subject_views.emplace_back(entry.first);
        cap_value_views.emplace_back(cap_values.emplace_back(std::to_string(entry.second)));
    }
    const std::string cap_subject_array = pg::to_text_array(cap_subject_views);
    const std::string cap_value_array = pg::to_text_array(cap_value_views);
    return dex_read_checked<std::vector<DexAppStabilityRow>>(
        open_, pool_, metrics_, "dex_app_stability", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexAppStabilityRow>> {
            // d: per (subject, version, device), with o = the device is in the
            // caller's online set ($6; the share, rate and score numerators are
            // members of the population they are divided by) and cap = the
            // per-device event cap of the subject: its entry in `caps` ($7/$8, the
            // policy's per-application overrides) else the global $5. The join key
            // folds the subject with an ASCII-only translate(), byte-identical to
            // dex_score_policy_detail::ascii_lower, so exactly the subjects the
            // policy resolver matches get the override (never lower(), whose
            // locale fold can map non-ASCII bytes to ASCII). tc/top: membership is the
            // app_limit applications affecting the most devices (then events,
            // then name, byte order); the published activity order is the
            // assembler's. top.total counts every qualifying application before
            // the cut. ad: per (subject, device) across versions, so a device in
            // two versions counts once in the application total. The application
            // rows (ad JOIN vc JOIN top) and the capped version rows (ranked,
            // rn <= $4) are UNIONed. Online figures are COALESCEd: FILTER over
            // no rows is NULL.
            // With no per-subject caps the caps CTE and its join are left out and the
            // cap is the constant $5 (the join costs a translate() per observation row);
            // $7/$8 are then not sent, as an unreferenced parameter has no type.
            const bool has_caps = !per_subject_caps.empty();
            std::vector<std::string> params{since,
                                            platform,
                                            std::to_string(std::clamp(app_limit, 0, kMaxEventsLimit)),
                                            std::to_string(std::clamp(version_limit, 0, kMaxEventsLimit)),
                                            std::to_string(per_device_cap),
                                            online_array};
            if (has_caps) {
                params.push_back(cap_subject_array);
                params.push_back(cap_value_array);
            }
            const std::string sql =
                std::string(has_caps ? "WITH caps AS ("
                                       " SELECT s, cap FROM unnest($7::text[], $8::bigint[])"
                                       " AS k(s, cap)),"
                                       "d AS ("
                                     : "WITH d AS (") +
                " SELECT g.subject, g.version, g.agent_id,"
                "  COUNT(*) FILTER (WHERE g.obs_type = 'process.crashed') AS c,"
                "  COUNT(*) FILTER (WHERE g.obs_type = 'process.hung') AS h,"
                "  MAX(g.observed_at) AS ls,"
                "  bool_or(g.agent_id = ANY($6::text[])) AS o,"
                + std::string(has_caps ? "  MAX(COALESCE(k.cap, $5::bigint)) AS cap" : "  $5::bigint AS cap") +
                " FROM guaranteed_state_store.guardian_observations g" +
                std::string(has_caps ? " LEFT JOIN caps k ON k.s = translate(g.subject,"
                                       "  'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"
                                     : "") +
                " WHERE g.obs_type IN ('process.crashed', 'process.hung')"
                "  AND g.observed_at >= $1 AND ($2::text = '' OR g.platform = $2::text)"
                " GROUP BY g.subject, g.version, g.agent_id),"
                "tc AS ("
                " SELECT subject, COUNT(DISTINCT agent_id) AS dev, SUM(c) + SUM(h) AS ev"
                " FROM d GROUP BY subject),"
                "top AS ("
                " SELECT subject, COUNT(*) OVER () AS total FROM tc"
                " ORDER BY dev DESC, ev DESC, subject COLLATE \"C\" ASC LIMIT $3::bigint),"
                "ad AS ("
                " SELECT d.subject, d.agent_id, SUM(d.c) AS c, SUM(d.h) AS h, MAX(d.ls) AS ls,"
                "  bool_or(d.o) AS o, MAX(d.cap) AS cap"
                " FROM d JOIN top USING (subject) GROUP BY d.subject, d.agent_id),"
                "ranked AS ("
                " SELECT d.subject, d.version, SUM(d.c) AS c, SUM(d.h) AS h, COUNT(*) AS a,"
                "  COUNT(*) FILTER (WHERE d.o) AS ao,"
                "  COALESCE(SUM(d.c) FILTER (WHERE d.o), 0) AS co,"
                "  COALESCE(SUM(d.h) FILTER (WHERE d.o), 0) AS ho,"
                "  COALESCE(SUM(LEAST(d.c, d.cap)) FILTER (WHERE d.o), 0) AS cc,"
                "  COALESCE(SUM(LEAST(d.h, d.cap)) FILTER (WHERE d.o), 0) AS ch,"
                "  MAX(d.ls) AS ls, COUNT(*) OVER (PARTITION BY d.subject) AS n,"
                "  ROW_NUMBER() OVER (PARTITION BY d.subject"
                "   ORDER BY COUNT(*) DESC, d.version COLLATE \"C\" ASC) AS rn"
                " FROM d JOIN top USING (subject) GROUP BY d.subject, d.version),"
                "vc AS (SELECT subject, MAX(n) AS n FROM ranked GROUP BY subject) "
                "SELECT ad.subject, NULL::text AS version, SUM(ad.c)::bigint, SUM(ad.h)::bigint,"
                " COUNT(*)::bigint,"
                " COALESCE(SUM(LEAST(ad.c, ad.cap)) FILTER (WHERE ad.o), 0)::bigint,"
                " COALESCE(SUM(LEAST(ad.h, ad.cap)) FILTER (WHERE ad.o), 0)::bigint,"
                " MAX(ad.ls), MAX(vc.n)::bigint, MAX(top.total)::bigint,"
                " (COUNT(*) FILTER (WHERE ad.o))::bigint,"
                " COALESCE(SUM(ad.c) FILTER (WHERE ad.o), 0)::bigint,"
                " COALESCE(SUM(ad.h) FILTER (WHERE ad.o), 0)::bigint "
                "FROM ad JOIN vc USING (subject) JOIN top USING (subject) GROUP BY ad.subject "
                "UNION ALL "
                "SELECT subject, version, c::bigint, h::bigint, a::bigint, cc::bigint, ch::bigint,"
                " ls, 0::bigint, 0::bigint, ao::bigint, co::bigint, ho::bigint "
                "FROM ranked WHERE rn <= $4::bigint";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexAppStabilityRow> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexAppStabilityRow r;
                r.subject = text_col(res.get(), i, 0);
                if (!PQgetisnull(res.get(), i, 1))
                    r.version = text_col(res.get(), i, 1);
                r.crashes = to_i64(PQgetvalue(res.get(), i, 2));
                r.hangs = to_i64(PQgetvalue(res.get(), i, 3));
                r.affected_devices = to_i64(PQgetvalue(res.get(), i, 4));
                r.capped_crashes = to_i64(PQgetvalue(res.get(), i, 5));
                r.capped_hangs = to_i64(PQgetvalue(res.get(), i, 6));
                r.last_seen = text_col(res.get(), i, 7);
                r.version_count = to_i64(PQgetvalue(res.get(), i, 8));
                r.apps_total = to_i64(PQgetvalue(res.get(), i, 9));
                r.affected_online = to_i64(PQgetvalue(res.get(), i, 10));
                r.crashes_online = to_i64(PQgetvalue(res.get(), i, 11));
                r.hangs_online = to_i64(PQgetvalue(res.get(), i, 12));
                out.push_back(std::move(r));
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

std::optional<std::vector<DexSignalCount>>
GuaranteedStateStore::dex_signal_summary_checked(const std::string& since,
                                                 const std::string& platform) const {
    // Second named exception (WS-A4 PR-1 fix round, sec-5): see this
    // method's own doc comment (guaranteed_state_store.hpp) — the fleet
    // catalogue builder must tell "degraded" apart from "genuinely zero
    // events fleet-wide".
    static DegradeSampler sampler;
    return dex_read_checked<std::vector<DexSignalCount>>(
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

std::vector<DexSignalCount>
GuaranteedStateStore::dex_signal_summary(const std::string& since, const std::string& platform) const {
    return dex_signal_summary_checked(since, platform).value_or(std::vector<DexSignalCount>{});
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
    // The unfiltered read is whole-census (the status fragment folds it), so the pending flag
    // comes from one hashed semi-join over the pending pairs; a correlated EXISTS per census row
    // measured about ten times slower at 100k rows. The drill-down is one rule, where EXISTS rides
    // idx_gse_pending (rule_id leading) per returned row. The flag covers REPRESENTED pairs only: a
    // pending event whose pair has no census row is invisible here
    // (unrepresented_pending_for_agent reads those).
    std::string sql;
    std::vector<std::string> params;
    if (rule_id.empty()) {
        sql = "SELECT c.agent_id, c.rule_id, c.state, c.updated_at, c.order_uncertain, "
              "(p.rule_id IS NOT NULL) AS projection_pending "
              "FROM guaranteed_state_store.guardian_agent_rule_status c "
              "LEFT JOIN (SELECT DISTINCT rule_id, agent_id "
              "           FROM guaranteed_state_store.guaranteed_state_events "
              "          WHERE projection_pending) p "
              "ON p.rule_id = c.rule_id AND p.agent_id = c.agent_id";
    } else {
        sql = "SELECT c.agent_id, c.rule_id, c.state, c.updated_at, c.order_uncertain, "
              "EXISTS (SELECT 1 FROM guaranteed_state_store.guaranteed_state_events e "
              "         WHERE e.rule_id = c.rule_id AND e.agent_id = c.agent_id "
              "           AND e.projection_pending) AS projection_pending "
              "FROM guaranteed_state_store.guardian_agent_rule_status c "
              "WHERE c.rule_id = $1"; // idx_gars_rule covers this for the drill-down
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
        r.order_uncertain = to_bool(PQgetvalue(res.get(), i, 4));
        r.projection_pending = to_bool(PQgetvalue(res.get(), i, 5));
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
        "SELECT c.agent_id, c.rule_id, c.state, c.updated_at, c.order_uncertain, "
        "EXISTS (SELECT 1 FROM guaranteed_state_store.guaranteed_state_events e "
        "         WHERE e.rule_id = c.rule_id AND e.agent_id = c.agent_id "
        "           AND e.projection_pending) AS projection_pending "
        "FROM guaranteed_state_store.guardian_agent_rule_status c WHERE c.agent_id = $1",
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
        r.order_uncertain = to_bool(PQgetvalue(res.get(), i, 4));
        r.projection_pending = to_bool(PQgetvalue(res.get(), i, 5));
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

std::expected<std::size_t, std::string> GuaranteedStateStore::uncertain_rule_count(
    const std::optional<std::vector<std::string>>& agent_scope) const {
    static DegradeSampler sampler;
    // Same scope contract as errored_rule_count: an engaged-empty scope is zero rows without a
    // query (ADR-0017 INV-2), a non-empty one is applied in SQL before the aggregate (INV-3).
    if (agent_scope && agent_scope->empty())
        return static_cast<std::size_t>(0);
    if (!open_) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::uncertain_rule_count: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::uncertain_rule_count: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    // Rules (live, joined to the rule table) with at least one represented pair whose row is
    // order-uncertain or whose retained event is pending. The parentheses around the OR matter:
    // the scope predicate is ANDed after it and must confine both branches.
    std::string sql = "SELECT COUNT(DISTINCT s.rule_id) FROM "
                      "guaranteed_state_store.guardian_agent_rule_status s JOIN "
                      "guaranteed_state_store.guaranteed_state_rules r ON r.rule_id = s.rule_id "
                      "LEFT JOIN (SELECT DISTINCT rule_id, agent_id "
                      "           FROM guaranteed_state_store.guaranteed_state_events "
                      "          WHERE projection_pending) p "
                      "ON p.rule_id = s.rule_id AND p.agent_id = s.agent_id "
                      "WHERE (s.order_uncertain OR p.rule_id IS NOT NULL)";
    std::vector<std::string> params;
    if (agent_scope) {
        std::vector<std::string_view> views;
        views.reserve(agent_scope->size());
        for (const std::string& a : *agent_scope)
            views.emplace_back(a);
        sql += " AND s.agent_id = ANY($1::text[])";
        params.push_back(pg::to_text_array(views));
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::uncertain_rule_count: query failed: {}",
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

std::expected<std::size_t, std::string> GuaranteedStateStore::rule_count_checked() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_count_checked: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_count_checked: pool acquire timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM guaranteed_state_store.guaranteed_state_rules",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceRules,
                                              sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::rule_count_checked: query failed: {}",
                         ::yuzu::log_key_token(PQresultErrorMessage(res.get())));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// Events whose census write failed and still await a repair. A bounded read: the statement
// timeout is set first so a hot backlog can never hold a pool connection for long, and the caller
// publishes the figure only when this succeeds, so a store that cannot answer leaves the previous
// sample instead of reading as zero.
std::expected<std::int64_t, std::string>
GuaranteedStateStore::pending_projection_count_checked() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonStoreNotOpen, kDegradeSourceCensus, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::pending_projection_count_checked: store not open");
        return std::unexpected("database not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonPoolTimeout, kDegradeSourceCensus, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::pending_projection_count_checked: pool acquire "
                         "timed out");
        return std::unexpected("no database connection: " + pool_.last_error());
    }
    PGconn* conn = lease.get();
    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK) {
        // Counted like every other failed read here: the gauge keeps its previous value on a
        // failure, so this counter is how a stale reading is told from a quiet one.
        if (const auto d =
                note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceCensus, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::pending_projection_count_checked: BEGIN failed: {}",
                         ::yuzu::log_key_token(PQerrorMessage(conn)));
        return std::unexpected(std::string("BEGIN failed: ") + PQerrorMessage(conn));
    }
    pg::PgTxn txn(conn);
    pg::PgResult timeout =
        pg::exec_params(conn, "SET LOCAL statement_timeout = '5s'", std::vector<std::string>{});
    pg::PgResult res =
        timeout.status() == PGRES_COMMAND_OK
            ? pg::exec_params(conn,
                              "SELECT count(*) FROM guaranteed_state_store.guaranteed_state_events "
                              "WHERE projection_pending",
                              std::vector<std::string>{})
            : std::move(timeout);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (const auto d =
                note_read_degrade(metrics_, kReasonQueryError, kDegradeSourceCensus, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore::pending_projection_count_checked: query failed: {}",
                         ::yuzu::log_key_token(PQresultErrorMessage(res.get())));
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

// Pairs of one device with a retained pending event and no census row (#7217). The represented-pair
// reads (agent_rule_statuses*, errored/uncertain_rule_count) cannot show these: with no census row
// the pair is invisible to them. There is no live-rule join on purpose: a pending event can outlive
// its rule through the #6829 race, and that is exactly the evidence this read discloses. An
// engaged-empty filter is answered without touching the store; every other failure is
// std::unexpected and counted on kDegradeSourceCensusDevice, never a zero. A statement timeout
// (SQLSTATE 57014) is told apart from the other failures (kStatementTimeout): it is deterministic
// for a given backlog, so the callers must not advertise a retry.
std::expected<UnrepresentedPendingSummary, UnrepresentedPendingError>
GuaranteedStateStore::unrepresented_pending_for_agent(
    const std::string& agent_id, const std::optional<std::vector<std::string>>& rule_filter) const {
    static DegradeSampler sampler;
    // Its own sampler, so a recent pool-timeout episode cannot suppress the first 'statement timeout'
    // warning (the Apps `budget_sampler` is the precedent). The counter increments either way.
    static DegradeSampler timeout_sampler;
    // Engaged-empty filter: nothing can qualify, so no lease and no seam call (ADR-0017 INV-2).
    if (rule_filter && rule_filter->empty())
        return UnrepresentedPendingSummary{};
    const auto degrade = [this](const char* reason, const char* what, const std::string& detail) {
        if (const auto d = note_read_degrade(metrics_, reason, kDegradeSourceCensusDevice, sampler);
            d.should_log)
            spdlog::warn("GuaranteedStateStore: unrepresented pending read: {}: {}", what,
                         ::yuzu::log_key_token(detail));
    };
    const auto unavailable = [](std::string message) {
        return std::unexpected(UnrepresentedPendingError{UnrepresentedPendingFault::kUnavailable,
                                                         std::move(message)});
    };
    if (!open_) {
        degrade(kReasonStoreNotOpen, "store not open", "");
        return unavailable("database not open");
    }
    if (unrepresented_pending_fault_ && unrepresented_pending_fault_()) {
        degrade(kReasonQueryError, "injected fault", "");
        return unavailable("query failed: injected fault");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        degrade(kReasonPoolTimeout, "pool acquire timed out", "");
        return unavailable("no database connection: " + pool_.last_error());
    }
    PGconn* conn = lease.get();
    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK) {
        degrade(kReasonQueryError, "BEGIN failed", PQerrorMessage(conn));
        return unavailable(std::string("BEGIN failed: ") + PQerrorMessage(conn));
    }
    pg::PgTxn txn(conn);
    const int timeout_ms = unrepresented_pending_timeout_ms_.load(std::memory_order_relaxed);
    pg::PgResult timeout = pg::exec_params(
        conn, std::format("SET LOCAL statement_timeout = '{}ms'", timeout_ms).c_str(),
        std::vector<std::string>{});
    if (timeout.status() != PGRES_COMMAND_OK) {
        degrade(kReasonQueryError, "statement_timeout failed", PQresultErrorMessage(timeout.get()));
        return unavailable("query failed: " + std::string(PQresultErrorMessage(timeout.get())));
    }
    // DISTINCT pairs of this device, minus any with a census row; the window count is taken before
    // the LIMIT, so the count is exact while the id list is capped. The order is BYTE order
    // (COLLATE "C"), so which ids survive the cap is identical on every cluster whatever its locale.
    //
    // NO index is built for this read, deliberately (owner ruling 2026-11-06). Nothing indexes agent_id
    // WITHIN the pending partition: idx_gse_pending is (rule_id, agent_id) WHERE projection_pending,
    // so agent_id is its second column, and idx_gse_agent_time reaches a device's rows but visits
    // every event of it, pending or not. Measured envelope: on PG16/17/18 with ~125k pending of 530k
    // events and with 1.2M pending, every plan took under 100 ms and read fewer than 2000 buffers;
    // a PG18 scratch replica with 7M events and 2M pending read in ~190 ms unfiltered, per agent.
    // RE-OPEN when the pending backlog grows past that envelope, which shows up as a 'statement
    // timeout' log line from this function or a rising
    // yuzu_server_guardian_read_degrade_total{source="guardian_census_device",
    // reason="statement_timeout"}. The fix is a partial (agent_id, rule_id) WHERE projection_pending
    // index, carried into the UP-14 server PR's v5 migration or #7147; the boot index-shape check
    // in the schema DO block (idx_gse_pending) must learn it in the same change.
    std::vector<std::string> params{agent_id};
    std::string sql = "WITH q AS (SELECT DISTINCT e.rule_id "
                      "FROM guaranteed_state_store.guaranteed_state_events e "
                      "WHERE e.agent_id = $1 AND e.projection_pending ";
    if (rule_filter) {
        std::vector<std::string_view> views;
        views.reserve(rule_filter->size());
        for (const std::string& r : *rule_filter)
            views.emplace_back(r);
        sql += "AND e.rule_id = ANY($2::text[]) ";
        params.push_back(pg::to_text_array(views));
    }
    sql += "AND NOT EXISTS (SELECT 1 FROM guaranteed_state_store.guardian_agent_rule_status c "
           "WHERE c.agent_id = e.agent_id AND c.rule_id = e.rule_id)) "
           "SELECT rule_id, count(*) OVER () AS total FROM q ORDER BY rule_id COLLATE \"C\" LIMIT " +
           std::to_string(kUnrepresentedPendingIdCap);
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        const char* state = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string msg = PQresultErrorMessage(res.get());
        // SQLSTATE 57014 (query_canceled) is also reported for an administrator cancel
        // (pg_cancel_backend) and for a lock wait, not only for the statement_timeout set above,
        // so the text says "most likely" a retained pending backlog, never "because of" one.
        if (state && std::string_view(state) == "57014") {
            // Count first, then log: the counter is the signal that must never be skipped.
            if (const auto d =
                    note_read_degrade(metrics_, kReasonStatementTimeout, kDegradeSourceCensusDevice,
                                      timeout_sampler);
                d.should_log)
                spdlog::warn("GuaranteedStateStore::unrepresented_pending_for_agent: statement timeout "
                             "after {} ms: most likely the retained pending backlog is too large for this "
                             "per-device read, so retrying usually fails identically until the cause "
                             "clears: {}",
                             timeout_ms, ::yuzu::log_key_token(msg));
            return std::unexpected(UnrepresentedPendingError{
                UnrepresentedPendingFault::kStatementTimeout, "statement timeout: " + msg});
        }
        degrade(kReasonQueryError, "query failed", msg);
        return unavailable("query failed: " + msg);
    }
    UnrepresentedPendingSummary out;
    const int rows = PQntuples(res.get());
    out.rule_ids.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.rule_ids.emplace_back(PQgetvalue(res.get(), i, 0));
    if (rows > 0)
        out.count = to_i64(PQgetvalue(res.get(), 0, 1));
    return out;
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

        // An event with pending census evidence is exempt from this pass: its evidence is the
        // only record that its verdict never reached the census, and reaping it would make the
        // loss permanent. The exemption cannot strand an observation: an observation's event
        // carries the reserved rule id, and a reserved-rule event is never census-bearing, so it
        // is never pending. A pending event is therefore also never counted as reaped; it ages
        // out in the pass after a redelivery or `delete_rule` retires it.
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
            "WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint AND NOT projection_pending "
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
