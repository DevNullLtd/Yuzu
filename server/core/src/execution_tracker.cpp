#include "execution_tracker.hpp"

#include "execution_event_bus.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <random>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "execution_tracker";

// Bounded acquires (ADR-0012 §2). No hot-path caller here — every runtime
// acquire uses the ordinary CRUD budget (matches PatchManager/ScheduleEngine/
// ApprovalManager).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// get_children_checked()'s row cap (#2146 A2-R1 governance re-review,
// blocking): the query had no LIMIT at all before this fix. No
// creation-side ceiling exists on how many children an execution can
// accumulate, so a fleet can legitimately exceed this -- get_children_checked()
// detects and reports it via ExecutionChildrenResult::truncated, mirroring
// ScheduleEngine::query_schedules_checked's identical kScheduleListCap
// pattern (schedule_engine.cpp). #2146 A2-R1 Gate 8 re-review (Astra
// opinion, adjudicated): 100, not 500 -- ScheduleEngine's fixed, no-param
// kScheduleListCap is the closer analogue (get_children, like
// list_schedules, has no caller-supplied limit param to clamp) than MCP
// list_executions' caller-ADJUSTABLE 500 ceiling, which bounds a
// differently-shaped read. No hard evidence backs either number; 100 is a
// conservative default, not a proven-correct one.
constexpr int kExecutionChildrenCap = 100;

// #2146 A2-R1 Gate 8 fix: get_children_checked's `WHERE parent_id = $1`
// query has no supporting index (a plain CREATE INDEX migration for it was
// authored and removed -- see the trailing comment inside kMigrations,
// after the v5 entry, and #4624 -- a policy-floor violation on an
// already-non-empty table, not a
// deferred style choice) and would otherwise run under the pool's 30s
// default statement_timeout_ms (pg_pool.hpp), vastly exceeding
// kReadTimeout's ~1.5s acquire budget every other reader of this shared
// pool_ (including rbac_store_, which shares one pg_pool_ singleton with
// this store) assumes -- a slow sequential scan here could stall
// connections other subsystems need. SET LOCAL scopes a tighter timeout to
// this one statement inside its own transaction, matching the shared idiom
// established by software_licensing_store.cpp / app_usage_store.cpp /
// app_perf_rollup.cpp. This bound matters MORE without an index, not less
// -- an unindexed scan is the slower case a timeout needs to catch -- so it
// stays in place unconditionally on top of the row cap below, independent
// of whether/when #4624's index ships.
constexpr const char* kChildrenStatementTimeout = "1500ms";

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

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_i(const char* s) { return static_cast<int>(to_i64(s)); }
double to_d(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    return std::strtod(s, nullptr);
}

std::vector<std::string_view> as_views(const std::vector<std::string>& v) {
    std::vector<std::string_view> out;
    out.reserve(v.size());
    for (const auto& s : v)
        out.emplace_back(s);
    return out;
}

// CLAUDE.md clock-guard part 7 — absolute, never scaled to any window.
// `audit_retention::moved_at_least`'s floor, in EITHER direction, between
// two ~5-minute-cadence reconciler ticks: ordinary NTP correction is
// sub-second to a few seconds, so a full hour is comfortably past any
// legitimate elapsed-time reading and comfortably short of "never fires".
constexpr int64_t kConcurrencyReconcileBigStepFloorSeconds = 3600; // 1 hour

// Part 5 — the cap applies UNCONDITIONALLY, regardless of detector
// effectiveness. concurrency_claims is bounded by concurrent per-device
// dispatch volume (realistically single/low-double-digit open rows at any
// time), so this is generous headroom, not a routine limit.
constexpr int kConcurrencyReconcileCapPerPass = 5000;

// Same compact encoding as AuditStore::serialize_facts (audit_store.cpp) —
// the dedup key is the whole FACT SET, not the classified Anomaly (see
// audit_retention_rules.hpp's own doc comment on why the enum collapses
// information the dedup needs).
std::string serialize_concurrency_facts(const audit_retention::Facts& f) {
    return std::string(f.has_expired ? "e" : "-") + (f.would_wipe ? "w" : "-") +
          (f.big_step ? "s" : "-") + (f.prev_unusable ? "u" : "-") + (f.no_anchor ? "b" : "-");
}

Execution row_to_exec(PGresult* r, int i) {
    Execution e;
    e.id = col_str(r, i, 0);
    e.definition_id = col_str(r, i, 1);
    e.status = col_str(r, i, 2);
    e.scope_expression = col_str(r, i, 3);
    e.parameter_values = col_str(r, i, 4);
    e.dispatched_by = col_str(r, i, 5);
    e.dispatched_at = to_i64(col(r, i, 6));
    e.agents_targeted = to_i(col(r, i, 7));
    e.agents_responded = to_i(col(r, i, 8));
    e.agents_success = to_i(col(r, i, 9));
    e.agents_failure = to_i(col(r, i, 10));
    e.completed_at = to_i64(col(r, i, 11));
    e.parent_id = col_str(r, i, 12);
    e.rerun_of = col_str(r, i, 13);
    e.last_error_detail = col_str(r, i, 14);
    return e;
}

// Base column list — every consumer pays this. The 14 fixed columns are
// indexed via the executions PK / status / dispatched / definition indexes.
const char* kSelectBase = "id, definition_id, status, scope_expression, parameter_values, "
                          "dispatched_by, dispatched_at, agents_targeted, agents_responded, "
                          "agents_success, agents_failure, completed_at, parent_id, rerun_of";

// Opt-in correlated subquery surfacing the most-recent non-empty agent
// error. CASE-gated on `agents_failure > 0` so fully-successful runs pay
// zero cost. Out-of-band consumers (health probes, metrics tick at
// server.cpp) opt OUT via ExecutionQuery::include_error_detail = false to
// avoid the partition sort on every tick (arch-B2 / perf-B1).
const char* kSelectErrorDetailExpr =
    ", (CASE WHEN agents_failure > 0 THEN ("
    "  SELECT error_detail FROM execution_tracker.agent_exec_status "
    "  WHERE execution_id = executions.id AND error_detail != '' "
    "  ORDER BY completed_at DESC LIMIT 1"
    ") ELSE '' END) AS last_error_detail";

// Empty-string placeholder so `row_to_exec` can read column 14
// unconditionally without branching on which column list was used.
const char* kSelectErrorDetailEmpty = ", '' AS last_error_detail";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Folds the SQLite-era v1+v2 ladder (v2 added agent_exec_status.
    // plugin_result_status, PR1.1 ABI4 CC-07) into a single v1 DDL — the
    // typed per-agent result column is present from creation on a fresh
    // Postgres schema (ADR-0009 fresh-start-by-default).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE executions ("
         "  id                TEXT    PRIMARY KEY,"
         "  definition_id     TEXT    NOT NULL,"
         "  status            TEXT    NOT NULL DEFAULT 'pending',"
         "  scope_expression  TEXT    NOT NULL DEFAULT '',"
         "  parameter_values  TEXT    NOT NULL DEFAULT '',"
         "  dispatched_by     TEXT    NOT NULL DEFAULT '',"
         "  dispatched_at     BIGINT  NOT NULL DEFAULT 0,"
         "  agents_targeted   INTEGER NOT NULL DEFAULT 0,"
         "  agents_responded  INTEGER NOT NULL DEFAULT 0,"
         "  agents_success    INTEGER NOT NULL DEFAULT 0,"
         "  agents_failure    INTEGER NOT NULL DEFAULT 0,"
         "  completed_at      BIGINT  NOT NULL DEFAULT 0,"
         "  parent_id         TEXT    NOT NULL DEFAULT '',"
         "  rerun_of          TEXT    NOT NULL DEFAULT ''"
         ");"
         "CREATE TABLE agent_exec_status ("
         "  execution_id          TEXT    NOT NULL,"
         "  agent_id              TEXT    NOT NULL,"
         "  status                TEXT    NOT NULL DEFAULT 'pending',"
         "  dispatched_at         BIGINT  NOT NULL DEFAULT 0,"
         "  first_response_at     BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at          BIGINT  NOT NULL DEFAULT 0,"
         "  exit_code             INTEGER NOT NULL DEFAULT 0,"
         "  error_detail          TEXT    NOT NULL DEFAULT '',"
         "  plugin_result_status  INTEGER NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (execution_id, agent_id)"
         ");"
         "CREATE INDEX idx_executions_status ON executions(status);"
         "CREATE INDEX idx_agent_exec_agent ON agent_exec_status(agent_id);"
         "CREATE INDEX idx_executions_dispatched ON executions(dispatched_at);"
         "CREATE INDEX idx_executions_definition ON executions(definition_id);"},
        // HA WS-1(1b), ADR-2002 section 5: the command_id -> execution_id
        // correlation, migrated off AgentServiceImpl's in-process map so a
        // response landing on ANY server replica can resolve it. reap_meta
        // is this store's own persisted-anchor table for
        // reap_command_execution_mappings (clock-guarded-retention routed
        // concern) — deliberately separate from `executions`/
        // `agent_exec_status`, which carry no retention sweep of their own.
        {2,
         "CREATE TABLE command_execution ("
         "  command_id    TEXT   PRIMARY KEY,"
         "  execution_id  TEXT   NOT NULL,"
         "  created_at    BIGINT NOT NULL"
         ");"
         "CREATE INDEX idx_command_execution_created ON command_execution(created_at);"
         "CREATE TABLE reap_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL"
         ");"},
        // v3 — per-device concurrency enforcement (ADR-1007). A dedicated
        // claim table (only the OPEN rows are short-lived — released rows
        // accumulate forever, see the no-prune note on idx_concurrency_claims_claimed_at
        // below), deliberately not a reuse of agent_exec_status: that table
        // only gains a row on an agent's
        // FIRST RESPONSE, which is too late to exclude a still-executing
        // duplicate. `ux_concurrency_claims_open` is the actual atomicity
        // guarantee — race-free under any isolation level, not an
        // app-level check (see claim_concurrency_slots). `retention_meta`
        // is the persisted clock anchor + anomaly-fact-set the stale-claim
        // reconciler needs to survive a restart (CLAUDE.md clock-guard
        // discipline; shape mirrors audit_store's own retention meta).
        // Numbered v3, not v2 — this migration and HA WS-1(1b)'s
        // `command_execution`/`reap_meta` (v2 above) were authored on
        // parallel branches and originally both claimed id 2; renumbered on
        // reconciliation, since v2 already shipped on `origin/dev` first.
        {3,
         "CREATE TABLE concurrency_claims ("
         "  definition_id  TEXT    NOT NULL,"
         "  agent_id       TEXT    NOT NULL,"
         "  execution_id   TEXT    NOT NULL,"
         "  command_id     TEXT    NOT NULL,"
         "  claimed_at     BIGINT  NOT NULL,"
         "  expires_at     BIGINT  NOT NULL,"
         "  released_at    BIGINT"
         ");"
         "CREATE UNIQUE INDEX ux_concurrency_claims_open ON concurrency_claims "
         "  (definition_id, agent_id) WHERE released_at IS NULL;"
         "CREATE INDEX idx_concurrency_claims_execution ON concurrency_claims(execution_id);"
         "CREATE INDEX idx_concurrency_claims_open_expiry ON concurrency_claims(expires_at) "
         "  WHERE released_at IS NULL;"
         // UP-1 fix (unhappy-path Gate 4 finding, PR #3784 fix round;
         // historical framing below, see the by-command fallback methods'
         // own doc comments in execution_tracker.hpp for the current
         // picture post-HA-WS-1(1b)-reconciliation): originally, a server
         // restart dropped `cmd_execution_ids_` (in-memory, unpersisted —
         // agent_service_impl.hpp), so `execution_id`-keyed release/renew
         // was unreachable for any command still in flight across the
         // restart, even though the agent stayed alive and kept sending
         // keepalives — the server just discarded them
         // (notify_exec_tracker's `execution_id.empty()` early-return).
         // `cmd_execution_ids_` no longer exists: it was replaced by a
         // PG-backed, replica-safe correlation table
         // (`ExecutionTracker::record_command_execution`/`lookup_execution_id`,
         // HA WS-1(1b)), which now handles that restart case on its own.
         // `command_id` still rides on every CommandResponse (including
         // `__keepalive__`) independent of any server-side cache, and is
         // minted fresh per dispatch (`plugin + "-" + random_bytes(16)`,
         // server.cpp) so — unlike execution_id, which workflow-step
         // dispatch shares as a literal empty string across definitions —
         // `(command_id, agent_id)` is a safe match key with no
         // definition_id scoping needed; this is why the by-command
         // fallback below stays load-bearing for the cases that
         // restart-survival no longer needs it for (workflow-step dispatch,
         // a correlation-table degrade). See
         // release_concurrency_claim_by_command/renew_concurrency_claim_by_command.
         //
         // UNIQUE, not just an index (Sol/Fable adversarial-review finding,
         // PR #3784 fix round): 128 bits of randomness makes a collision
         // astronomically unlikely, but "unlikely" is not the same
         // guarantee as "enforced" — a doc comment claiming this pair
         // "cannot collide" was an overclaim the schema didn't actually
         // back up. Full-table (not partial `WHERE released_at IS NULL`
         // like `ux_concurrency_claims_open`) because the invariant this
         // protects — one dispatch mints one fresh command_id, ever — holds
         // for the row's entire lifetime, not just while it's open; a
         // released row's command_id must never be reused either.
         // `claim_concurrency_slots`'s INSERT relies on this constraint to
         // fail CLOSED (a targetless `ON CONFLICT DO NOTHING` covers both
         // this and `ux_concurrency_claims_open`) rather than letting a
         // duplicate command_id silently take a second claim.
         "CREATE UNIQUE INDEX ux_concurrency_claims_command ON concurrency_claims"
         "  (command_id, agent_id);"
         // Non-partial, on claimed_at — released rows are NEVER pruned
         // today (Gate 6 compliance/sre: a deliberate no-prune, recorded in
         // ADR-1007, not an omission). A future age-based prune pass
         // (`WHERE claimed_at < cutoff`) needs this index to avoid a full
         // scan; the partial indexes above are invisible to released rows
         // (both are `WHERE released_at IS NULL`) so they don't help it.
         // Adding it now, while this table has zero production rows, is
         // free; adding it later means `CREATE INDEX CONCURRENTLY` against
         // a live table.
         "CREATE INDEX idx_concurrency_claims_claimed_at ON concurrency_claims(claimed_at);"
         "CREATE TABLE retention_meta ("
         "  key    TEXT PRIMARY KEY,"
         "  value  TEXT NOT NULL"
         ");"},
        // HA WS-2a (durable event outbox), ADR-2002 §5. An append-only durable
        // shadow of the events ExecutionEventBus fans out in-memory, written
        // ATOMICALLY inside the same transaction as the state mutation that
        // produced each one (append_event_outbox rides the caller's conn). No
        // consumer in this slice — the in-memory bus still serves live SSE; the
        // durable feed is drained by a later slice's LISTEN/cursor-poll loop.
        //   event_id  — global durable MONOTONIC id (BIGINT IDENTITY), replacing
        //               the in-memory per-process channel counter. A forward-poll
        //               consumer must NOT advance by a bare id>cursor (nor by a
        //               created_at time-lookback); see the authoritative
        //               ID-ORDERING CONTRACT on ExecutionTracker::
        //               append_event_outbox for why and the safe cursor forms.
        //   created_at — epoch seconds, authored from Postgres now() IN-SQL by
        //               append_event_outbox, so reap_event_outbox's cutoff and
        //               the row share ONE DB clock domain.
        // DELIBERATELY no FK to executions(id) and no UNIQUE/CHECK beyond the
        // PK (execution_id also legitimately holds non-executions ids like
        // polchk-/preflight-/deployment-): with no constraint, the append
        // cannot fail on a constraint the state write does not also face, so it
        // adds no DIFFERENTIAL failure. It is NOT failure-free — a
        // statement_timeout, disk/WAL pressure, or a dropped connection on the
        // second statement still fails the append, and because it is atomic
        // with the state write, the ADR-2002 §5 contract then ROLLS THE STATE
        // WRITE BACK too (durability over availability — an agent status write
        // is coupled to its event being durable). That coupling is the
        // deliberate cost of invariant 1; an FK would make it WORSE by adding a
        // differential failure that fails the append alone. reap_meta (created
        // in v2) carries this table's retention anchor too.
        //
        // Numbered v4: dev's ADR-1007 concurrency_claims migration (v3 above)
        // and this event_outbox migration were authored on parallel branches;
        // dev's v3 shipped to origin/dev first, so this renumbered to v4 on the
        // rebase (MigrationRunner requires strictly-increasing versions).
        {4,
         "CREATE TABLE event_outbox ("
         "  event_id     BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  execution_id TEXT    NOT NULL,"
         "  event_type   TEXT    NOT NULL,"
         "  data         TEXT    NOT NULL,"
         "  is_terminal  BOOLEAN NOT NULL DEFAULT FALSE,"
         "  created_at   BIGINT  NOT NULL"
         ");"
         "CREATE INDEX idx_event_outbox_created ON event_outbox(created_at);"
         "CREATE INDEX idx_event_outbox_exec ON event_outbox(execution_id, event_id);"},
        // HA WS-2a-2 (cross-replica delivery, ADR-2002 §5). Two columns the
        // durable forward-poll consumer needs, added to the WS-2a-1 table:
        //   w_xid — the appending transaction's 64-bit xid8 (default
        //     pg_current_xact_id(), evaluated per-INSERT). The poll cursor is a
        //     single xid8 COMMIT-SETTLE HORIZON: each pass reads rows whose w_xid
        //     is in [last_horizon, xmin) where xmin =
        //     pg_snapshot_xmin(pg_current_snapshot()), then advances last_horizon
        //     to xmin. Because xmin (the oldest RUNNING xid) is monotonic and
        //     never passes an uncommitted xid, no still-in-flight lower-id row can
        //     be straddled and skipped — the id-ordering hazard the WS-2a-1 append
        //     contract records. A bare `event_id > cursor` skips a slow-committing
        //     lower id; an `(w_xid, event_id)` KEYSET cursor also skips a low-xid
        //     txn that was in-flight at boot and commits below the tuple — so the
        //     cursor is the xmin horizon, and this (w_xid, event_id) index only
        //     provides the range scan + publish ORDER within a settled window,
        //     not the cursor position. See poll_event_outbox_once's derivation.
        //   origin_replica — the process-instance id that appended the row, so a
        //     replica's poll loop SKIPS its own rows (it already published them
        //     in-process); other replicas re-publish them onto their local bus.
        // xid8 (64-bit, wraparound-safe) + pg_current_xact_id()/pg_snapshot_xmin
        // are PG13+; the substrate is PG18. Existing rows get the migration txn's
        // xid on the rewrite (all pre-migration, hence already settled).
        {5,
         "ALTER TABLE event_outbox ADD COLUMN w_xid xid8 NOT NULL "
         "  DEFAULT pg_current_xact_id();"
         "ALTER TABLE event_outbox ADD COLUMN origin_replica TEXT NOT NULL DEFAULT '';"
         "CREATE INDEX idx_event_outbox_wxid ON event_outbox(w_xid, event_id);"},
        // #2146 A2-R1 Gate 8 review round: a v6 migration adding a supporting
        // index for get_children_checked's `WHERE parent_id = $1` query was
        // authored here (a plain, non-CONCURRENT CREATE INDEX) and REMOVED
        // before this PR merged -- adversarial review (Codex + Kimi-K3)
        // correctly flagged it as a docs/postgres-store-playbook.md policy-
        // floor violation: `executions` "can already be non-empty on an
        // upgrading install" (this file's own admission at the time), and
        // the playbook's "Non-transactional migrations (the deferred kind)"
        // section is explicit that an index on an already-large table
        // during a live rolling upgrade needs the non-transactional
        // migration kind, which "must be built ... before such a migration
        // ships. Do not weaken the transactional default to sneak one in" --
        // that kind does not exist yet (tracked generally by #4432, for a
        // different store). `get_children_checked` therefore stays an
        // unindexed sequential scan today, bounded by kExecutionChildrenCap
        // and kChildrenStatementTimeout (both above) -- a disclosed
        // performance tradeoff, not a correctness gap. #4624 tracks adding
        // `idx_executions_parent_id ON executions(parent_id)` here, through
        // the non-transactional kind, once #4432 lands. Version 6 is
        // deliberately NOT reserved for it -- this v6 never shipped (no
        // release ever recorded it in schema_meta), and PgMigrationRunner
        // only requires each store's own migrations() vector to be strictly
        // increasing, not contiguous, so the next migration added here
        // simply takes whatever the next free version number is at that
        // time.
    };
    return kMigrations;
}

// HA WS-2a (ADR-2002 §5): append one event to the durable `event_outbox` on
// the CALLER's live transaction connection — NEVER its own lease (nesting a
// pool acquire inside an open with_txn would deadlock, pg_pool.hpp) — so the
// outbox row commits ATOMICALLY with the state mutation that produced it
// (invariant 1: a crash or failure never leaves state-without-event or
// event-without-state). Returns false on the INSERT failing; the caller MUST
// propagate that false out of the enclosing with_txn callback so the whole
// transaction rolls back — that propagation is what makes the pairing atomic
// (see the four call sites in upsert_agent_status_once / refresh_counts_once /
// mark_cancelled). `origin_replica` is the appending process's instance id,
// stamped so a replica's cross-replica poll loop skips its OWN rows (already
// published in-process) and re-publishes only other replicas'. The durable
// `event_id` (BIGINT IDENTITY assigned at INSERT) and `w_xid` are for the poll's
// settle-horizon cursor + the slice-2 durable replay; they are NOT threaded to
// the in-memory bus (HA WS-2a-2 Option A — the live bus id stays the per-channel
// counter, see the bus publish body). `created_at` is authored from Postgres
// now() IN-SQL, so
// the reap cutoff and the row share one DB clock domain (the same
// DB-clock-authority reason record_command_execution authors created_at
// in-SQL).
//
// ID-ORDERING CONTRACT for future consumers (HA WS-2a-2 forward poll): an
// IDENTITY id is assigned at INSERT but the row becomes visible only at COMMIT,
// so a transaction holding a LOWER id can commit AFTER one holding a HIGHER id,
// and rolled-back appends / rolled-back state writes leave PERMANENT id gaps. A
// live forward poll MUST therefore NOT advance its cursor by a bare
// `event_id > cursor ORDER BY event_id`, or it silently skips a
// slower-committing lower id forever. NOTE (governance self-adversarial finding
// C2/K1): a trailing `created_at` TIME-lookback is NOT a sufficient fix on its
// own, and must not be specified as one — `created_at` is authored from now(),
// which in Postgres is TRANSACTION-START time, so it does not linearize COMMIT
// order; a late-starting txn can commit a higher id before an early-starting
// txn commits a lower one, and no finite time window closes that straddle. The
// two sound approaches, left to the WS-2a-2 design: (a) an id-gap-pending
// advance — never step the cursor past a missing id until that id is proven
// committed OR proven rolled back (aborted-txn gaps are permanent); or (b) a
// txid/snapshot-horizon cursor — poll only rows whose inserting xid is below the
// database's all-committed xmin horizon (pg_snapshot_xmin(pg_current_snapshot())),
// which is exactly the "no in-flight lower id can still appear" guarantee.
// WS-2a-2 implements (b) — see poll_event_outbox_once (an xmin-horizon WINDOW,
// endorsed by the 2026-09-02 architect review). Only a
// per-execution RECONNECT replay (`execution_id = $1 AND event_id > $since` on a
// `Last-Event-ID` reconnect) is safe with a bare id cursor — those rows are
// long-committed by the time the consumer reconnects. A per-execution LIVE
// forward poll at the write edge faces the same out-of-order-commit hazard
// (concurrent transitions on one execution_id) and needs (a)/(b) too: the safety
// is a property of reading only the COMMITTED-and-settled prefix, not of the
// per-execution filter.
//
// The table carries NO foreign key to executions(id) and no UNIQUE/CHECK beyond
// the event_id PK, DELIBERATELY: with no constraint, the append cannot fail on a
// constraint the paired state write does not also face — it adds no DIFFERENTIAL
// failure. It is NOT failure-free: a statement_timeout, disk/WAL pressure, or a
// dropped connection on the INSERT still fails it, and because the append is
// atomic with the state write, the §5 contract then rolls the STATE write back
// too — an agent status write is coupled to its event being durable (durability
// over availability, the deliberate cost of invariant 1; failures are logged on
// the update_agent_status double-retry path). An FK here would make this WORSE,
// reintroducing a differential failure that fails the append ALONE and turns a
// benign append into UNRECOVERABLE agent-status loss (agents do not re-send;
// #3729's reconciler recomputes from agent_exec_status, which the same rollback
// would destroy).
//
// AT-LEAST-ONCE, by design (PR #3842 review): the INSERT is non-idempotent (a
// fresh IDENTITY event_id each call). The caller retry loops (update_agent_status
// / refresh_counts each retry once) were safe pre-outbox because the state UPSERT
// is idempotent; now a COMMIT that succeeds server-side but reads as failed
// client-side (a dropped connection at the COMMIT ack) makes the retry durably
// append a SECOND row for one real event. This is the ADR-2002 §5 "events: at-
// least-once, consumers tolerate duplicates" contract, NOT a bug — the WS-2a-2
// forward-poll consumer MUST dedup on content/command_id, never assume one row
// per transition. A retry after a genuine rollback (attempt 1 committed nothing)
// produces no duplicate; only the rare ambiguous-commit case does.
bool append_event_outbox(PGconn* conn, const std::string& execution_id,
                         const std::string& event_type, const std::string& data,
                         bool is_terminal, const std::string& origin_replica) {
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO execution_tracker.event_outbox "
        "(execution_id, event_type, data, is_terminal, created_at, origin_replica) "
        "VALUES ($1, $2, $3, $4, extract(epoch FROM now())::bigint, $5)",
        std::vector<std::string>{execution_id, event_type, data, is_terminal ? "true" : "false",
                                 origin_replica});
    // w_xid is filled by the column DEFAULT pg_current_xact_id() — the appending
    // txn's xid, the settle-horizon the cross-replica poll cursors on. The durable
    // event_id is assigned by the IDENTITY column and read back by the poll from
    // the outbox (HA WS-2a-2 Option A) — it is deliberately NOT returned to the
    // caller for the in-memory bus publish (see the bus publish body for why the
    // live bus id stays the per-channel counter).
    if (res.status() == PGRES_COMMAND_OK)
        return true;
    // Log the durable-append failure DISTINCTLY (PR #3842 review): the caller's
    // own error log now covers TWO independent statements (its state write and
    // this append) with one opaque bool, so an event_outbox-only degrade would
    // otherwise be invisible on-call. This runs inside the caller's txn, which
    // the false return then rolls back (the paired state write with it).
    spdlog::error("ExecutionTracker::append_event_outbox: durable append failed for "
                  "execution_id={} event_type={} — {} (rolls back the paired state write)",
                  execution_id, event_type, PQerrorMessage(conn));
    return false;
}

} // namespace

ExecutionTracker::ExecutionTracker(pg::PgPool& pool) : pool_(pool) {
    // HA WS-2a-2: this process's outbox instance identity, stamped as
    // origin_replica on every durable append for cross-replica skip-own. 16
    // random bytes → 32 hex chars. A secure-RNG failure leaves it empty (logged)
    // — self-exclusion then no-ops, which is safe-but-chatty (this replica would
    // re-publish its own already-published events), never a correctness break.
    if (auto rid = yuzu::server::random_hex(16); rid) {
        replica_id_ = *rid;
    } else {
        spdlog::error("ExecutionTracker: secure RNG failed for replica id — "
                      "cross-replica skip-own self-exclusion disabled (safe, chattier)");
    }
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error(
            "ExecutionTracker: no database connection at construction ({}) — execution "
            "tracker disabled",
            pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ExecutionTracker: schema migration failed — execution tracker disabled");
        return;
    }
    open_ = true;

    // HA WS-2a-2 (self-adversarial C1): initialize the cross-replica poll horizon
    // to the all-committed xmin at CONSTRUCTION — which runs before the server
    // admits any SSE subscriber — NOT lazily on the first maintenance poll (~2s
    // later). A lazy first-poll init would advance the horizon past any foreign
    // event that committed during the boot→first-poll window, so a subscriber
    // connected at boot would never receive those live events (a LIVE gap the
    // slice-2 reconnect replay cannot heal). Initializing here makes the first
    // poll deliver the whole [construction-xmin, first-poll-xmin) window. On an
    // xmin read failure we leave poll_horizon_ empty + poll_initialized_ false;
    // the poll's lazy-init fallback then establishes it (ceding that one window),
    // which is strictly better than refusing to poll.
    if (pg::PgResult x = pg::exec_params(
            lease.get(), "SELECT pg_snapshot_xmin(pg_current_snapshot())::text",
            std::vector<std::string>{});
        x.status() == PGRES_TUPLES_OK && PQntuples(x.get()) == 1) {
        poll_horizon_ = col_str(x.get(), 0, 0);
        poll_initialized_ = true;
    } else {
        spdlog::warn("ExecutionTracker: could not read boot poll horizon ({}) — the first "
                     "cross-replica poll will lazily initialize it, ceding the boot window",
                     pool_.last_error());
    }
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag. The caller
    // (server.cpp) separately runs legacy_sqlite_probe::warn_if_legacy_rows()
    // over the legacy instructions.db so a locally-wrong "no production
    // fleet" premise still gets a loud signal.
    spdlog::info("ExecutionTracker initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

namespace {
/// Lease-free single-row read, taking an already-held connection directly.
/// Used both by the public `get_execution`/`get_summary` (which acquire
/// their own lease) and internally by `refresh_counts`'s transaction
/// (reusing the connection it already holds) — per pg_pool.hpp's own
/// documented gotcha, calling a lease-acquiring public method from inside
/// an already-held `with_txn_for` callback would acquire a SECOND
/// connection from the same pool, deadlocking a small pool.
std::optional<Execution> exec_by_id_at(PGconn* conn, const std::string& id) {
    auto sql = std::string("SELECT ") + kSelectBase + kSelectErrorDetailExpr +
               " FROM execution_tracker.executions WHERE id = $1";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return row_to_exec(res.get(), 0);
}

// Appends the #3789 `ExecutionListScope` admission predicate to `sql`
// (advancing `idx`/`binds`), or does nothing when `scope` is unrestricted
// (nullopt). MUST be called before `ORDER BY`/`LIMIT` — ADR-0017 INV-3
// (CRITICAL), same rule as response_store.cpp's `append_scope_clause`. One
// array bind for the visible-agent disjunct regardless of set size (mirrors
// that helper's `pg::to_text_array` convention — no per-agent placeholder
// cap to silently truncate past).
void append_execution_scope_clause(std::string& sql, std::vector<std::string>& binds, int& idx,
                                   const ExecutionScope& scope) {
    if (!scope.has_value())
        return;
    const bool has_owner = !scope->owner.empty();
    const bool has_agents = !scope->visible_agents.empty();
    if (!has_owner && !has_agents) {
        sql += " AND 1=0"; // visible to nobody -> exclude every row
        return;
    }
    std::vector<std::string> clauses;
    if (has_owner) {
        clauses.push_back("dispatched_by = $" + std::to_string(idx++));
        binds.push_back(scope->owner);
    }
    if (has_agents) {
        std::vector<std::string_view> sv(scope->visible_agents.begin(),
                                         scope->visible_agents.end());
        clauses.push_back(
            "EXISTS (SELECT 1 FROM execution_tracker.agent_exec_status s "
            "WHERE s.execution_id = executions.id AND s.agent_id = ANY($" +
            std::to_string(idx++) + "::text[]))");
        binds.push_back(pg::to_text_array(sv));
    }
    sql += " AND (" + clauses.front();
    for (std::size_t i = 1; i < clauses.size(); ++i)
        sql += " OR " + clauses[i];
    sql += ")";
}
} // namespace

std::vector<Execution> ExecutionTracker::query_executions(const ExecutionQuery& q) const {
    return query_executions_checked(q, std::nullopt).value_or(std::vector<Execution>{});
}

std::optional<std::vector<Execution>>
ExecutionTracker::query_executions_checked(const ExecutionQuery& q,
                                           const ExecutionScope& scope) const {
    if (!open_) {
        spdlog::warn("ExecutionTracker::query_executions_checked degraded: tracker not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::query_executions_checked degraded: pool exhausted");
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kSelectBase +
                      (q.include_error_detail ? kSelectErrorDetailExpr : kSelectErrorDetailEmpty) +
                      " FROM execution_tracker.executions WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (!q.status.empty()) {
        sql += " AND status = $" + std::to_string(idx++);
        params.push_back(q.status);
    }
    if (!q.dispatched_by.empty()) {
        sql += " AND dispatched_by = $" + std::to_string(idx++);
        params.push_back(q.dispatched_by);
    }
    // #3789: MUST precede ORDER BY/LIMIT below — ADR-0017 INV-3.
    append_execution_scope_clause(sql, params, idx, scope);
    sql += " ORDER BY dispatched_at DESC LIMIT $" + std::to_string(idx++);
    // #4030 review finding (should-fix): a schema-legal non-positive
    // q.limit (no caller validates it before this point -- MCP
    // list_executions's input schema declares no minimum) previously
    // reached Postgres verbatim; Postgres rejects a negative LIMIT outright,
    // which query_executions() (the unchecked wrapper) silently collapsed to
    // a false-empty success. Clamp here, matching
    // WorkflowEngine::list_workflows's identical "Clamp to at least 1"
    // comment/fix (workflow_engine.cpp) — this protects every caller of
    // query_executions[_checked], not just the one MCP handler that
    // triggered the finding.
    params.push_back(std::to_string(std::max(q.limit, 1)));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ExecutionTracker::query_executions_checked degraded: query failed");
        return std::nullopt;
    }

    std::vector<Execution> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_exec(res.get(), i));
    return results;
}

std::string ExecutionTracker::definition_id_for_execution(const std::string& execution_id) const {
    if (!open_ || execution_id.empty())
        return {};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return {};
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT definition_id FROM execution_tracker.executions WHERE id=$1",
                        std::vector<std::string>{execution_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return {};
    return col_str(res.get(), 0, 0);
}

// Single-row reads (`get_execution` / `get_summary`) always opt into the
// error-detail subquery — they're rare, called from the detail handler /
// MCP / tests, never from health-tick paths.
std::optional<Execution> ExecutionTracker::get_execution(const std::string& id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    return exec_by_id_at(lease.get(), id);
}

std::expected<std::optional<Execution>, std::string>
ExecutionTracker::get_execution_checked(const std::string& id) const {
    if (!open_) {
        spdlog::warn("ExecutionTracker::get_execution_checked degraded: tracker not open");
        return std::unexpected("execution tracker not open");
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::get_execution_checked degraded: pool exhausted");
        return std::unexpected("execution tracker temporarily unavailable (pool exhausted)");
    }
    // Deliberately NOT delegating to exec_by_id_at above: that helper
    // collapses "row absent" and "query failed" into one nullopt return
    // (single early-return on `PGRES_TUPLES_OK-or-zero-rows`), which is
    // exactly the ambiguity this checked twin exists to remove (#3789,
    // following Sol/gpt-5.6-sol's adversarial review flagging the same gap
    // still present in rest_api_v1.cpp's `get_execution` call site).
    auto sql = std::string("SELECT ") + kSelectBase + kSelectErrorDetailExpr +
               " FROM execution_tracker.executions WHERE id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ExecutionTracker::get_execution_checked degraded: query failed");
        return std::unexpected("execution query failed");
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<Execution>{std::nullopt};
    return std::optional<Execution>{row_to_exec(res.get(), 0)};
}

ExecutionSummary ExecutionTracker::get_summary(const std::string& id) const {
    ExecutionSummary s;
    s.id = id;
    if (!open_)
        return s;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return s;

    if (auto exec = exec_by_id_at(lease.get(), id)) {
        s.status = exec->status;
        s.agents_targeted = exec->agents_targeted;
        s.agents_responded = exec->agents_responded;
        s.agents_success = exec->agents_success;
        s.agents_failure = exec->agents_failure;
        s.progress_pct = s.agents_targeted > 0 ? (s.agents_responded * 100 / s.agents_targeted) : 0;
    }
    return s;
}

std::optional<std::vector<AgentExecStatus>>
ExecutionTracker::get_agent_statuses_checked(const std::string& execution_id) const {
    if (!open_) {
        spdlog::warn("ExecutionTracker::get_agent_statuses_checked degraded: tracker not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::get_agent_statuses_checked degraded: pool exhausted");
        return std::nullopt;
    }

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, status, dispatched_at, first_response_at, completed_at, exit_code, "
        "error_detail, COALESCE(plugin_result_status, 0) FROM execution_tracker.agent_exec_status "
        "WHERE execution_id = $1 ORDER BY agent_id",
        std::vector<std::string>{execution_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ExecutionTracker::get_agent_statuses_checked degraded: query failed");
        return std::nullopt;
    }

    std::vector<AgentExecStatus> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        AgentExecStatus a;
        a.agent_id = col_str(res.get(), i, 0);
        a.status = col_str(res.get(), i, 1);
        a.dispatched_at = to_i64(col(res.get(), i, 2));
        a.first_response_at = to_i64(col(res.get(), i, 3));
        a.completed_at = to_i64(col(res.get(), i, 4));
        a.exit_code = to_i(col(res.get(), i, 5));
        a.error_detail = col_str(res.get(), i, 6);
        a.plugin_result_status = to_i(col(res.get(), i, 7));
        results.push_back(std::move(a));
    }
    return results;
}

std::vector<AgentExecStatus>
ExecutionTracker::get_agent_statuses(const std::string& execution_id) const {
    return get_agent_statuses_checked(execution_id).value_or(std::vector<AgentExecStatus>{});
}

std::unordered_map<std::string, std::vector<AgentExecStatus>>
ExecutionTracker::get_agent_statuses_for_executions(
    const std::vector<std::string>& execution_ids) const {
    return get_agent_statuses_for_executions_checked(execution_ids)
        .value_or(std::unordered_map<std::string, std::vector<AgentExecStatus>>{});
}

std::optional<std::unordered_map<std::string, std::vector<AgentExecStatus>>>
ExecutionTracker::get_agent_statuses_for_executions_checked(
    const std::vector<std::string>& execution_ids) const {
    std::unordered_map<std::string, std::vector<AgentExecStatus>> by_execution;
    // Engaged-empty: zero requested executions means zero rows, without
    // touching the pool — success-empty, not degrade (matches
    // ResponseStore::facet_values' convention for this same shape).
    if (execution_ids.empty())
        return by_execution;
    if (!open_) {
        spdlog::warn(
            "ExecutionTracker::get_agent_statuses_for_executions_checked degraded: tracker not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn(
            "ExecutionTracker::get_agent_statuses_for_executions_checked degraded: pool exhausted");
        return std::nullopt;
    }

    std::vector<std::string_view> sv(execution_ids.begin(), execution_ids.end());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, "
        "exit_code, error_detail, COALESCE(plugin_result_status, 0) "
        "FROM execution_tracker.agent_exec_status "
        "WHERE execution_id = ANY($1::text[]) ORDER BY execution_id, agent_id",
        std::vector<std::string>{pg::to_text_array(sv)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn(
            "ExecutionTracker::get_agent_statuses_for_executions_checked degraded: query failed");
        return std::nullopt;
    }

    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        AgentExecStatus a;
        a.agent_id = col_str(res.get(), i, 1);
        a.status = col_str(res.get(), i, 2);
        a.dispatched_at = to_i64(col(res.get(), i, 3));
        a.first_response_at = to_i64(col(res.get(), i, 4));
        a.completed_at = to_i64(col(res.get(), i, 5));
        a.exit_code = to_i(col(res.get(), i, 6));
        a.error_detail = col_str(res.get(), i, 7);
        a.plugin_result_status = to_i(col(res.get(), i, 8));
        by_execution[col_str(res.get(), i, 0)].push_back(std::move(a));
    }
    return by_execution;
}

std::vector<Execution> ExecutionTracker::get_children(const std::string& parent_id) const {
    // No confinement scope to thread from this best-effort convenience
    // wrapper (test-only production usage today) -- explicit nullopt, never
    // a defaulted parameter (#2146 A2-R1 Gate 8 fix; see get_children_checked's
    // doc comment).
    auto checked = get_children_checked(parent_id, std::nullopt);
    return checked ? std::move(checked->children) : std::vector<Execution>{};
}

std::optional<ExecutionChildrenResult>
ExecutionTracker::get_children_checked(const std::string& parent_id,
                                       const ExecutionScope& scope) const {
    if (!open_) {
        spdlog::warn("ExecutionTracker::get_children_checked degraded: tracker not open");
        return std::nullopt;
    }

    // get_children is used by workflow drill-down — opt out of the
    // error-detail subquery to keep the workflow-step expansion cheap.
    // #2146 A2-R1 (governance re-review, blocking): query one row PAST the
    // cap so a parent with EXACTLY kExecutionChildrenCap children is never
    // misreported as truncated -- same +1-row sentinel idiom as
    // ScheduleEngine::query_schedules_checked (schedule_engine.cpp), trimmed
    // back off below and never returned to the caller.
    auto sql = std::string("SELECT ") + kSelectBase + kSelectErrorDetailEmpty +
               " FROM execution_tracker.executions WHERE parent_id = $1";
    std::vector<std::string> params{parent_id};
    int idx = 2;
    // #2146 A2-R1 Gate 8 fix: MUST precede ORDER BY/LIMIT below -- ADR-0017
    // INV-3, same rule query_executions_checked above already follows. A
    // no-op when `scope` is nullopt (unrestricted), so the unscoped shape
    // (and its existing raw-count boundary tests) is unchanged.
    append_execution_scope_clause(sql, params, idx, scope);
    sql += " ORDER BY dispatched_at DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(kExecutionChildrenCap + 1));

    // #2146 A2-R1 Gate 8 fix: SET LOCAL statement_timeout scopes a tighter
    // bound to this one statement (kChildrenStatementTimeout, ~kReadTimeout's
    // own acquire budget) instead of the pool's 30s default -- see this
    // constant's doc comment above. Runs inside its own transaction because
    // SET LOCAL is transaction-scoped; a plain autocommit statement has
    // nothing to scope it to. Mirrors software_licensing_store.cpp's
    // count_stale_agents / app_perf_rollup.cpp's roll_day idiom.
    std::optional<ExecutionChildrenResult> out;
    const bool committed = pool_.with_txn_for(kReadTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(
            c, (std::string("SET LOCAL statement_timeout = '") + kChildrenStatementTimeout + "'")
                  .c_str(),
            std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res = pg::exec_params(c, sql.c_str(), params);
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        ExecutionChildrenResult result;
        const int rows = PQntuples(res.get());
        result.truncated = rows > kExecutionChildrenCap;
        const int take = result.truncated ? kExecutionChildrenCap : rows;
        result.children.reserve(static_cast<std::size_t>(take));
        for (int i = 0; i < take; ++i)
            result.children.push_back(row_to_exec(res.get(), i));
        out = std::move(result);
        return true;
    });
    if (!committed) {
        spdlog::warn("ExecutionTracker::get_children_checked degraded: acquire/statement-timeout/"
                     "query failure");
        return std::nullopt;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

std::expected<std::string, std::string> ExecutionTracker::create_execution(const Execution& exec) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("execution tracker temporarily unavailable (pool exhausted)");

    auto id = exec.id.empty() ? generate_id() : exec.id;
    auto now = now_epoch();
    auto status = exec.status.empty() ? "running" : exec.status;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO execution_tracker.executions "
        "(id, definition_id, status, scope_expression, parameter_values, "
        " dispatched_by, dispatched_at, agents_targeted, agents_responded, "
        " agents_success, agents_failure, completed_at, parent_id, rerun_of) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        std::vector<std::string>{
            id, exec.definition_id, status, exec.scope_expression, exec.parameter_values,
            exec.dispatched_by,
            std::to_string(exec.dispatched_at > 0 ? exec.dispatched_at : now),
            std::to_string(exec.agents_targeted), std::to_string(exec.agents_responded),
            std::to_string(exec.agents_success), std::to_string(exec.agents_failure),
            std::to_string(exec.completed_at), exec.parent_id, exec.rerun_of});

    if (res.status() != PGRES_COMMAND_OK) {
        // Scrubbed generic string to the caller (matches ScheduleEngine/
        // ApprovalManager's equivalent path — governance consistency-auditor,
        // 2026-08-31: this used to leak the raw Postgres diagnostic); the
        // diagnostic itself goes server-side only.
        spdlog::error("ExecutionTracker::create_execution: insert failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected("insert failed (pool degraded or transaction failed)");
    }
    return id;
}

std::optional<std::string>
ExecutionTracker::upsert_agent_status_once(const std::string& execution_id,
                                           const AgentExecStatus& s) {
    // Snapshot-and-release (governance round perf-B1 / UP-A9): build the SSE
    // payload, commit the transaction, release the lease, THEN publish.
    bool should_publish = false;
    nlohmann::json payload;
    std::string persisted_status;

    // HA WS-2a: the agent_exec_status upsert AND the durable event_outbox append
    // commit in ONE transaction (invariant 1) — this was a bare autocommit
    // statement before the outbox existed, so a crash between the upsert and the
    // (formerly separate) event would leave state-without-event. The payload is
    // built from the RETURNING (ACTUALLY-PERSISTED) row, not `s` verbatim
    // (#3784 sticky-terminal fix): a stale 'running' write the CASE below
    // correctly rejects must not publish OR durably append an "agent-transition"
    // claiming status="running". The in-memory bus publish still runs AFTER the
    // transaction commits and the lease is released, and only when a bus is set.
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        auto now = now_epoch();
        pg::PgResult res = pg::exec_params(
            conn,
            "INSERT INTO execution_tracker.agent_exec_status "
            "(execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, "
            " exit_code, error_detail, plugin_result_status) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) "
            "ON CONFLICT (execution_id, agent_id) DO UPDATE SET "
            // Terminal status is STICKY (CHAOS-TTL-1 keepalive hardening,
            // #3784): a stale 'running' write arriving AFTER a real terminal
            // write must not flip an already-terminal row back to 'running'.
            "  status=CASE WHEN agent_exec_status.status IN "
            "                 ('success','failure','timeout','rejected') "
            "                 AND excluded.status = 'running' "
            "              THEN agent_exec_status.status ELSE excluded.status END, "
            "  first_response_at=CASE WHEN agent_exec_status.first_response_at=0 "
            "                          THEN excluded.first_response_at "
            "                          ELSE agent_exec_status.first_response_at END, "
            "  completed_at=CASE WHEN agent_exec_status.status IN "
            "                        ('success','failure','timeout','rejected') "
            "                        AND excluded.status = 'running' "
            "                     THEN agent_exec_status.completed_at ELSE excluded.completed_at END, "
            "  exit_code=CASE WHEN agent_exec_status.status IN "
            "                    ('success','failure','timeout','rejected') "
            "                    AND excluded.status = 'running' "
            "                 THEN agent_exec_status.exit_code ELSE excluded.exit_code END, "
            "  error_detail=CASE WHEN agent_exec_status.status IN "
            "                        ('success','failure','timeout','rejected') "
            "                        AND excluded.status = 'running' "
            "                     THEN agent_exec_status.error_detail ELSE excluded.error_detail END, "
            "  plugin_result_status=CASE WHEN agent_exec_status.status IN "
            "                                ('success','failure','timeout','rejected') "
            "                                AND excluded.status = 'running' "
            "                             THEN agent_exec_status.plugin_result_status "
            "                             ELSE excluded.plugin_result_status END "
            "RETURNING status, exit_code, completed_at, error_detail, plugin_result_status",
            std::vector<std::string>{
                execution_id, s.agent_id, s.status,
                std::to_string(s.dispatched_at > 0 ? s.dispatched_at : now),
                std::to_string(s.first_response_at > 0 ? s.first_response_at : now),
                std::to_string(s.completed_at), std::to_string(s.exit_code), s.error_detail,
                std::to_string(s.plugin_result_status)});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return false;

        // The ACTUALLY-PERSISTED status (#3784 UP-2): captured unconditionally
        // because the caller uses it to gate concurrency-claim release/renewal,
        // and the durable append + bus publish below must both reflect it.
        persisted_status = col_str(res.get(), 0, 0);
        payload["agent_id"] = s.agent_id;
        payload["status"] = persisted_status;
        payload["exit_code"] = to_i64(col(res.get(), 0, 1));
        payload["completed_at"] = to_i64(col(res.get(), 0, 2));
        const std::string returned_error = col_str(res.get(), 0, 3);
        if (!returned_error.empty())
            payload["error_detail"] = returned_error;
        const int64_t returned_plugin_status = to_i64(col(res.get(), 0, 4));
        if (returned_plugin_status != 0)
            payload["plugin_result_status"] = returned_plugin_status;

        // Durable append, atomic with the upsert above. A false rolls both back.
        if (!append_event_outbox(conn, execution_id, "agent-transition", payload.dump(),
                                 /*is_terminal=*/false, replica_id_))
            return false;

        if (event_bus_)
            should_publish = true;
        return true;
    }); // transaction committed / lease released here — publish below runs lease-free.

    if (!ok)
        return std::nullopt;

    if (should_publish) {
        event_bus_->publish(execution_id, "agent-transition", payload.dump());
    }
    return persisted_status;
}

void ExecutionTracker::update_agent_status(const std::string& execution_id,
                                           const AgentExecStatus& s) {
    if (!open_)
        return;

    // Retry once on failure, same rationale as refresh_counts's
    // own retry (governance adversarial review, PR review 2026-08-31,
    // Doomgoose): a lease-acquire timeout or a cancelled statement under
    // row-lock contention here is silent by default and, unlike
    // refresh_counts's failure mode, unrecoverable by #3729's reconciler —
    // the reconciler recomputes FROM agent_exec_status rows, so a row that
    // was never inserted has nothing to reconcile from (the agent does not
    // re-send). Loud logging on final failure at least surfaces the loss.
    std::optional<std::string> persisted;
    for (int attempt = 0; attempt < 2 && !persisted; ++attempt)
        persisted = upsert_agent_status_once(execution_id, s);
    if (!persisted) {
        spdlog::error("ExecutionTracker::update_agent_status: upsert failed twice for "
                      "execution_id={} agent_id={} — this agent's status is NOT recorded and "
                      "will not be reconciled (agents do not re-send)",
                      execution_id, s.agent_id);
        return;
    }

    // Per-device concurrency claim release (ADR-1007): the same terminal set
    // refresh_counts_once uses for agents_responded/agents_failure below —
    // 'running' is not terminal and must not release a claim early. A
    // best-effort release; an unreleased claim self-heals via
    // reconcile_stale_concurrency_claims once past its own expires_at.
    //
    // UP-2 fix (unhappy-path Gate 4 finding, PR #3784 fix round): gate on
    // `*persisted` (what the sticky-terminal CASE in upsert_agent_status_once
    // actually wrote), NEVER on the caller-supplied `s.status`. A stale
    // 'running' write that arrives after a real terminal write is correctly
    // rejected by that CASE — the row stays terminal — but `s.status` still
    // literally says "running"; branching on it here would call
    // renew_concurrency_claim for a command whose claim the terminal branch
    // may already have released, extending a dead command's claim past when
    // it should self-heal via the reconciler.
    //
    // definition_id_for_execution (Gate 2 security-guardian finding, PR #3784
    // fix round): release/renew MUST be scoped by definition_id, not just
    // (execution_id, agent_id) — see release_concurrency_claim's doc comment
    // for why. A missing/unresolvable definition_id (empty execution_id,
    // pool exhaustion, a row that predates this lookup) skips the release/
    // renewal outright rather than falling back to the unscoped match that
    // reopens the exact hazard this fix closes — the claim self-heals via
    // the reconciler either way, same fallback as every other best-effort
    // failure mode here.
    if (*persisted == "success" || *persisted == "failure" || *persisted == "timeout" ||
        *persisted == "rejected") {
        if (auto def_id = definition_id_for_execution(execution_id); !def_id.empty())
            release_concurrency_claim(def_id, execution_id, s.agent_id);
    } else if (*persisted == "running") {
        // CHAOS-TTL-1 fix (Gate 5, PR #3784 fix round): a 'running' update
        // is a live signal from the agent — extend the claim so the
        // reconciler's crash-detection TTL measures time since the LAST
        // signal, not time since the claim was first taken. Fed reliably by
        // the agent-core keepalive thread (agent.cpp, sentinel
        // "__keepalive__" recognized in agent_service_impl.cpp), not by
        // plugin cooperation — see renew_concurrency_claim's own doc
        // comment and ADR-1007's "CLOSED (agent-core keepalive)" section.
        if (auto def_id = definition_id_for_execution(execution_id); !def_id.empty())
            renew_concurrency_claim(def_id, execution_id, s.agent_id);
    }

    // UAT 2026-05-06: chain refresh_counts so the parent executions row's
    // agents_responded / agents_success / agents_failure aggregates reflect
    // this state change. Without this, the dashboard's executions list
    // shows "0/0 of N" even after every agent has reported. refresh_counts
    // also crosses the all-agents-responded threshold to terminal status
    // and publishes execution-progress + execution-completed events, so
    // calling it here makes update_agent_status the single mutation entry
    // point that keeps both per-agent state and parent aggregates in sync.
    // refresh_counts acquires its own lease, so this runs independently of
    // the upsert above (no nested pool acquisition). The agent-transition
    // publish above happens BEFORE the execution-progress publish below,
    // preserving the documented client-visible event ordering
    // (executions-history ladder PR 3 publisher invariant).
    refresh_counts(execution_id);
}

bool ExecutionTracker::set_agents_targeted(const std::string& execution_id, int agents_targeted) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ExecutionTracker::set_agents_targeted: pool exhausted for execution_id={}",
                      execution_id);
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "UPDATE execution_tracker.executions SET agents_targeted=$1 WHERE id=$2",
        std::vector<std::string>{std::to_string(agents_targeted), execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error(
            "ExecutionTracker::set_agents_targeted: update failed for execution_id={} — the "
            "row never learns its real agent count and can never reach the all-responded "
            "threshold refresh_counts checks, wedging it at 'running' with no automatic recovery",
            execution_id);
        return false;
    }
    return true;
}

void ExecutionTracker::refresh_counts(const std::string& execution_id) {
    if (!open_)
        return;

    // Retry once on failure (governance adversarial review 2026-08-31,
    // CHAOS-01): the aggregate UPDATE below takes a row-level lock other
    // concurrent refresh_counts calls for the SAME execution_id queue behind.
    // Under high agent-fanout that queue can exceed Postgres's server-side
    // lock_timeout (10s default, set once at connection-open in
    // pg::PgPool — NOT this file's kWriteTimeout, which only bounds the pool
    // lease acquisition), which cancels the statement and rolls back. The
    // pre-migration SQLite code used a recursive_mutex that blocked
    // UNBOUNDEDLY (no timeout, so it could never drop an update, only
    // queue) — this bounded-abandon failure mode is net-new to the Postgres
    // port. A single retry is not a no-op: by the time the first attempt has
    // waited out the full lock_timeout, the transaction(s) that were holding
    // the row have almost certainly long since committed or themselves timed
    // out, so the retry is very likely uncontended. A second failure is
    // logged loudly rather than silently dropped — without this, an
    // execution can wedge at "running" forever (agents_responded/success/
    // failure stale, no terminal transition, no execution-completed SSE)
    // with zero operator-visible signal (tracked for a fuller fix — a
    // periodic reconciler sweep — in the follow-up this finding filed).
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (refresh_counts_once(execution_id))
            return;
    }
    spdlog::error("ExecutionTracker: refresh_counts failed twice for execution {} — aggregate "
                  "counts and terminal transition may be stale; a subsequent agent status "
                  "update will retry, but a fully-reported execution may need operator "
                  "investigation (see docs/executions-history-ladder.md)",
                  execution_id);
}

bool ExecutionTracker::refresh_counts_once(const std::string& execution_id) {
    // Snapshot-and-release (perf-B1 / UP-A9): we snapshot up to two SSE payloads
    // inside the transaction below, then publish after it commits and the lease is
    // released.
    bool publish_progress = false;
    bool publish_terminal = false;
    nlohmann::json progress_payload;
    nlohmann::json terminal_payload;
    bool transitioned_terminal_was = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Recompute aggregate counts from agent_exec_status. One transaction
        // for the recompute + read-back + conditional terminal transition
        // below gives this the same consistency the SQLite-era app-level
        // mutex provided (a concurrent refresh_counts on the same execution
        // cannot observe a half-updated row), via Postgres's own MVCC
        // snapshot isolation instead of an app-level lock.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE execution_tracker.executions SET "
            "  agents_responded = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status IN "
            "                      ('success','failure','timeout','rejected')), "
            "  agents_success   = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status='success'), "
            "  agents_failure   = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status IN "
            "                      ('failure','timeout','rejected')) "
            "WHERE id=$1",
            std::vector<std::string>{execution_id});
        if (upd.status() != PGRES_COMMAND_OK)
            return false;

        // Check if all agents responded and update status. Lease-free
        // helper (reuses `conn` directly) — calling the public
        // get_execution() here would acquire a SECOND connection from the
        // same pool mid-transaction (pg_pool.hpp's own documented
        // nesting-deadlock gotcha).
        auto exec = exec_by_id_at(conn, execution_id);
        bool transitioned_terminal = false;
        std::string final_status_str;
        if (exec && exec->agents_targeted > 0 && exec->agents_responded >= exec->agents_targeted) {
            const char* final_status = (exec->agents_failure == 0) ? "succeeded" : "completed";
            pg::PgResult term = pg::exec_params(
                conn,
                "UPDATE execution_tracker.executions SET status=$1, completed_at=$2 "
                "WHERE id=$3 AND status='running' RETURNING 1",
                std::vector<std::string>{final_status, std::to_string(now_epoch()), execution_id});
            // RETURNING carries the "row matched" signal in the result's row
            // count — closes the #1033-class sqlite3_changes()-after-step
            // race this store carried on the shared SQLite FULLMUTEX
            // connection (a bare affected-row count read after step() is
            // not atomic with the step itself under concurrent callers on
            // one connection; a per-lease Postgres connection plus
            // RETURNING has no such race to begin with).
            if (term.status() == PGRES_TUPLES_OK && PQntuples(term.get()) > 0) {
                transitioned_terminal = true;
                final_status_str = final_status;
            }
        }
        transitioned_terminal_was = transitioned_terminal;

        // HA WS-2a: build the SSE payloads and durably append them to the
        // event_outbox INSIDE this transaction (invariant 1: the aggregate/
        // terminal state mutation above and its events commit atomically). The
        // payloads are built whenever `exec` resolved — the durable append does
        // not depend on a bus being attached; only the post-commit in-memory
        // fan-out (the publish_* flags) does. A false append rolls the whole
        // recompute+transition back.
        if (exec) {
            progress_payload["agents_targeted"] = exec->agents_targeted;
            progress_payload["agents_responded"] = exec->agents_responded;
            progress_payload["agents_success"] = exec->agents_success;
            progress_payload["agents_failure"] = exec->agents_failure;
            if (transitioned_terminal)
                progress_payload["status"] = final_status_str;
            if (!append_event_outbox(conn, execution_id, "execution-progress",
                                     progress_payload.dump(), transitioned_terminal, replica_id_))
                return false;
            if (transitioned_terminal) {
                terminal_payload["status"] = final_status_str;
                terminal_payload["agents_success"] = exec->agents_success;
                terminal_payload["agents_failure"] = exec->agents_failure;
                if (!append_event_outbox(conn, execution_id, "execution-completed",
                                         terminal_payload.dump(), /*is_terminal=*/true, replica_id_))
                    return false;
            }
            if (event_bus_) {
                publish_progress = true;
                if (transitioned_terminal)
                    publish_terminal = true;
            }
        }
        return true;
    }); // transaction committed / lease released here — publishes below run lease-free.

    if (!ok)
        return false;

    if (publish_progress) {
        event_bus_->publish(execution_id, "execution-progress", progress_payload.dump(),
                            transitioned_terminal_was);
    }
    if (publish_terminal) {
        event_bus_->publish(execution_id, "execution-completed", terminal_payload.dump(),
                            /*is_terminal=*/true);
    }
    return true;
}

std::expected<std::string, std::string>
ExecutionTracker::create_rerun(const std::string& original_id, const std::string& user,
                               bool failed_only) {
    auto orig = get_execution(original_id);
    if (!orig)
        return std::unexpected("original execution not found");

    Execution rerun;
    rerun.definition_id = orig->definition_id;
    rerun.scope_expression = orig->scope_expression;
    rerun.parameter_values = orig->parameter_values;
    rerun.dispatched_by = user;
    rerun.parent_id = original_id;
    rerun.rerun_of = original_id;
    rerun.status = "pending";

    if (failed_only) {
        // Count only failed agents as targets
        auto agents = get_agent_statuses(original_id);
        int failed_count = 0;
        for (const auto& a : agents) {
            if (a.status == "failure" || a.status == "timeout" || a.status == "rejected")
                ++failed_count;
        }
        rerun.agents_targeted = failed_count;
    } else {
        rerun.agents_targeted = orig->agents_targeted;
    }

    return create_execution(rerun);
}

bool ExecutionTracker::mark_cancelled(const std::string& id, const std::string& /*user*/) {
    if (!open_)
        return false;

    // Snapshot-and-release (perf-B1 / UP-A9).
    bool should_publish = false;
    nlohmann::json payload;
    payload["status"] = "cancelled";

    // HA WS-2a: the cancel UPDATE AND the durable execution-completed append
    // commit in ONE transaction (invariant 1) — was a bare autocommit statement
    // before the outbox existed. A false append rolls the cancel back.
    //
    // The UPDATE is GUARDED (`AND status NOT IN (<terminal set>) RETURNING id`)
    // and the event is appended ONLY when a row actually transitioned:
    //  - governance self-adversarial finding C1/K6, ADR-2002 §5: a bare
    //    `UPDATE ... WHERE id=$2` (no RETURNING) returns PGRES_COMMAND_OK even on
    //    a ZERO-row match (unknown/stale id), so appending unconditionally would
    //    commit a durable `execution-completed` with NO paired state mutation —
    //    the event-WITHOUT-state half of the §5 pairing;
    //  - PR #3842 review (Doomgoose): the guard must ALSO exclude already-
    //    TERMINAL rows. Without `AND status NOT IN (...)`, a retried/double-
    //    clicked cancel, or a cancel racing with `refresh_counts_once`'s
    //    `running -> succeeded/completed` transition (which itself guards on
    //    `status='running'`), would overwrite the true terminal status back to
    //    `cancelled` AND durably append a second, CONTRADICTORY terminal frame.
    //    The guard makes a cancel of an already-terminal (or unknown) execution
    //    a clean no-op: zero rows -> no state change, no event, false return
    //    ("not cancelled — no such live execution", distinct from a store
    //    failure). This also closes the earlier double-cancel duplicate-frame.
    bool matched = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "UPDATE execution_tracker.executions SET status='cancelled', completed_at=$1 "
            "WHERE id=$2 AND status NOT IN ('succeeded','completed','cancelled') RETURNING id",
            std::vector<std::string>{std::to_string(now_epoch()), id});
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(res.get()) == 0)
            return true; // unknown id OR already terminal — no state change, no event
        matched = true;

        if (!append_event_outbox(conn, id, "execution-completed", payload.dump(),
                                 /*is_terminal=*/true, replica_id_))
            return false;

        if (event_bus_)
            should_publish = true;
        // ADR-1007 correctness fix (Gate 4 unhappy-path UP-1): a cancelled
        // execution's per-device claims are DELIBERATELY NOT released here.
        // `mark_cancelled` only updates SERVER-side bookkeeping — there is
        // no gRPC cancel/kill RPC to the agent (grepped: none exists), so
        // the agent keeps running the plugin regardless of this call.
        // Releasing the claim on cancel would immediately admit a duplicate
        // dispatch of the same definition to the same STILL-EXECUTING
        // agent — exactly the race this whole feature exists to prevent. A
        // cancelled execution's claims release the same way every other
        // claim does: a genuine terminal response from the agent
        // (`update_agent_status`), or the stale-claim reconciler once past
        // `expires_at` if no response ever comes. This is honest, not
        // lossy: "cancel requested" is not the same fact as "agent
        // stopped", and the claim table only ever asserts the latter.
        return true;
    }); // transaction committed / lease released here — publish below runs lease-free.

    if (!ok) {
        spdlog::error("ExecutionTracker::mark_cancelled: cancel transaction failed for execution "
                      "id={} — the execution was NOT actually cancelled (pool exhaustion or a "
                      "failed statement rolled the whole transaction back)",
                      id);
        return false;
    }
    if (!matched)
        return false; // unknown/stale id — no-op, reported as not-cancelled (no phantom event)

    if (should_publish) {
        event_bus_->publish(id, "execution-completed", payload.dump(), /*is_terminal=*/true);
    }
    return true;
}

// ── per-device concurrency enforcement (ADR-1007) ──────────────────────

std::vector<std::string>
ExecutionTracker::claim_concurrency_slots(const std::string& definition_id,
                                          const std::string& execution_id,
                                          const std::string& command_id,
                                          const std::vector<std::string>& candidates,
                                          int64_t expires_at) {
    // command_id.empty() rejected at claim time (Sol/Fable adversarial-
    // review finding, PR #3784 fix round): release/renew_concurrency_
    // claim_by_command already guard against an empty command_id, but
    // claim_concurrency_slots didn't — an empty-command claim would have
    // been silently un-releasable-by-command, an asymmetry that recreates
    // the same unscoped-match hazard this PR fixed for execution_id=""
    // if a future caller ever passed a constant/empty command_id.
    if (!open_ || definition_id.empty() || command_id.empty() || candidates.empty())
        return {};
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        // Fail CLOSED, matching this dispatch seam's own ContainmentGate
        // precedent (dispatch_confined_arms.hpp): a degraded read must not
        // silently read as "nobody is busy". Every candidate is excluded
        // from this dispatch rather than let through unchecked.
        spdlog::warn("ExecutionTracker::claim_concurrency_slots: pool exhausted for "
                     "definition_id={} — excluding all {} candidate(s) from this dispatch",
                     definition_id, candidates.size());
        if (metrics_)
            metrics_->counter("yuzu_server_concurrency_claim_unavailable_total").increment();
        return {};
    }
    const auto now = now_epoch();
    // Targetless `ON CONFLICT DO NOTHING` (Sol/Fable adversarial-review
    // finding, PR #3784 fix round): catches a conflict on EITHER unique
    // index on this table — `ux_concurrency_claims_open` (the real "already
    // busy" case) or `ux_concurrency_claims_command` (a command_id/agent_id
    // reuse, which should never happen at 128 bits of randomness but is now
    // schema-enforced rather than merely assumed). Either way the row is
    // excluded from `RETURNING`, so the caller's existing "N of M already
    // busy" accounting stays correct without needing to distinguish which
    // constraint fired.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO execution_tracker.concurrency_claims "
        "  (definition_id, agent_id, execution_id, command_id, claimed_at, expires_at, released_at) "
        "SELECT $1, a, $2, $3, $4, $5, NULL FROM unnest($6::text[]) AS a "
        "ON CONFLICT DO NOTHING "
        "RETURNING agent_id",
        std::vector<std::string>{definition_id, execution_id, command_id, std::to_string(now),
                                 std::to_string(expires_at),
                                 pg::to_text_array(as_views(candidates))});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ExecutionTracker::claim_concurrency_slots: insert failed for "
                      "definition_id={}: {}",
                      definition_id, PQerrorMessage(lease.get()));
        if (metrics_)
            metrics_->counter("yuzu_server_concurrency_claim_unavailable_total").increment();
        return {};
    }
    std::vector<std::string> claimed;
    const int rows = PQntuples(res.get());
    claimed.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        claimed.emplace_back(col_str(res.get(), i, 0));
    if (claimed.size() != candidates.size()) {
        // Visibility for the operator/agentic caller (ADR-1007): a busy
        // agent is silently excluded from the dispatch target list further
        // up the call chain (dispatch_scope_ladder.hpp), not synchronously
        // reported as a distinct error — this is the durable signal that a
        // dispatch was partial because of a concurrency claim, not because
        // of authz/quarantine/offline.
        const auto skipped = candidates.size() - claimed.size();
        spdlog::info("ExecutionTracker::claim_concurrency_slots: {} of {} candidate(s) already "
                     "busy for definition_id={} — excluded from this dispatch",
                     skipped, candidates.size(), definition_id);
        if (metrics_)
            metrics_->counter("yuzu_server_dispatch_concurrency_skipped_total")
                .increment(static_cast<double>(skipped));
    }
    return claimed;
}

void ExecutionTracker::release_concurrency_claim(const std::string& definition_id,
                                                 const std::string& execution_id,
                                                 const std::string& agent_id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::release_concurrency_claim: pool exhausted for "
                     "definition_id={} execution_id={} agent_id={} — claim stays open until "
                     "the stale-claim reconciler releases it past expires_at",
                     definition_id, execution_id, agent_id);
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE execution_tracker.concurrency_claims SET released_at=$1 "
        "WHERE definition_id=$2 AND execution_id=$3 AND agent_id=$4 AND released_at IS NULL",
        std::vector<std::string>{std::to_string(now_epoch()), definition_id, execution_id,
                                 agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ExecutionTracker::release_concurrency_claim: update failed for "
                     "definition_id={} execution_id={} agent_id={}: {} — claim stays open "
                     "until reconciled",
                     definition_id, execution_id, agent_id, PQerrorMessage(lease.get()));
    }
}

void ExecutionTracker::release_concurrency_claims(const std::string& definition_id,
                                                  const std::string& execution_id,
                                                  const std::vector<std::string>& agent_ids) {
    if (!open_ || agent_ids.empty())
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::release_concurrency_claims: pool exhausted for "
                     "definition_id={} execution_id={} ({} agent id(s)) — claim(s) stay open "
                     "until the stale-claim reconciler releases them past expires_at",
                     definition_id, execution_id, agent_ids.size());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE execution_tracker.concurrency_claims SET released_at=$1 "
        "WHERE definition_id=$2 AND execution_id=$3 AND agent_id = ANY($4::text[]) "
        "AND released_at IS NULL",
        std::vector<std::string>{std::to_string(now_epoch()), definition_id, execution_id,
                                 pg::to_text_array(as_views(agent_ids))});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ExecutionTracker::release_concurrency_claims: update failed for "
                     "definition_id={} execution_id={} ({} agent id(s)): {} — claim(s) stay "
                     "open until reconciled",
                     definition_id, execution_id, agent_ids.size(), PQerrorMessage(lease.get()));
    }
}

void ExecutionTracker::renew_concurrency_claim(const std::string& definition_id,
                                               const std::string& execution_id,
                                               const std::string& agent_id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::renew_concurrency_claim: pool exhausted for "
                     "definition_id={} execution_id={} agent_id={} — this renewal is skipped; "
                     "the claim falls back to the reconciler's ordinary crash-detection "
                     "behaviour at its current (unextended) expires_at",
                     definition_id, execution_id, agent_id);
        return;
    }
    const int64_t new_expires_at = now_epoch() + kConcurrencyClaimDefaultTtlSeconds;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE execution_tracker.concurrency_claims SET expires_at=$1 "
        "WHERE definition_id=$2 AND execution_id=$3 AND agent_id=$4 AND released_at IS NULL",
        std::vector<std::string>{std::to_string(new_expires_at), definition_id, execution_id,
                                 agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ExecutionTracker::renew_concurrency_claim: update failed for "
                     "definition_id={} execution_id={} agent_id={}: {} — this renewal is "
                     "skipped, same fallback as a pool-exhaustion skip above",
                     definition_id, execution_id, agent_id, PQerrorMessage(lease.get()));
    }
}

void ExecutionTracker::release_concurrency_claim_by_command(const std::string& command_id,
                                                             const std::string& agent_id) {
    if (!open_ || command_id.empty())
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::release_concurrency_claim_by_command: pool exhausted "
                     "for command_id={} agent_id={} — claim stays open until the stale-claim "
                     "reconciler releases it past expires_at",
                     command_id, agent_id);
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE execution_tracker.concurrency_claims SET released_at=$1 "
        "WHERE command_id=$2 AND agent_id=$3 AND released_at IS NULL",
        std::vector<std::string>{std::to_string(now_epoch()), command_id, agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ExecutionTracker::release_concurrency_claim_by_command: update failed "
                     "for command_id={} agent_id={}: {} — claim stays open until reconciled",
                     command_id, agent_id, PQerrorMessage(lease.get()));
    }
}

void ExecutionTracker::renew_concurrency_claim_by_command(const std::string& command_id,
                                                           const std::string& agent_id) {
    if (!open_ || command_id.empty())
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("ExecutionTracker::renew_concurrency_claim_by_command: pool exhausted for "
                     "command_id={} agent_id={} — this renewal is skipped; the claim falls "
                     "back to the reconciler's ordinary crash-detection behaviour at its "
                     "current (unextended) expires_at",
                     command_id, agent_id);
        return;
    }
    const int64_t new_expires_at = now_epoch() + kConcurrencyClaimDefaultTtlSeconds;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE execution_tracker.concurrency_claims SET expires_at=$1 "
        "WHERE command_id=$2 AND agent_id=$3 AND released_at IS NULL",
        std::vector<std::string>{std::to_string(new_expires_at), command_id, agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ExecutionTracker::renew_concurrency_claim_by_command: update failed for "
                     "command_id={} agent_id={}: {} — this renewal is skipped, same fallback "
                     "as a pool-exhaustion skip above",
                     command_id, agent_id, PQerrorMessage(lease.get()));
    }
}

int ExecutionTracker::reconcile_stale_concurrency_claims(int64_t now) {
    if (!open_)
        return 0;
    if (now <= 0) {
        // Part 3 — sanitise the reading itself before using it anywhere.
        spdlog::error(
            "ExecutionTracker::reconcile_stale_concurrency_claims: unsanitary now={} — "
            "declining this pass",
            now);
        return 0;
    }
    // Everything below — the anchor read/stamp, the settled marker, the
    // counts probe, the verdict, and the capped release — runs inside ONE
    // transaction, mirroring audit_store.cpp::cleanup_once: every query
    // result is checked, and any failure rolls the WHOLE pass back rather
    // than partially committing. A counts-probe failure that still stamped
    // the anchor and the liveness gauge as healthy was the exact silent
    // failure this closes (reviewer finding, Postgres verified).
    int released = 0;
    bool declined = false;
    int64_t open_total = 0, stale_total = 0;
    // Definition/agent/execution triples force-released this pass — collected
    // inside the transaction, but the spdlog::warn per triple is deliberately
    // deferred until AFTER the `ok` check below (Gate 8 compliance-officer
    // finding, PR #3784 fix round): warning INSIDE the lambda, before COMMIT,
    // would log "force-released" for rows a subsequent commit failure then
    // rolls back — the exact log-vs-durable-state mismatch the transactional
    // rewrite otherwise closes. Matches where the decline log and the
    // force-released counter already live.
    std::vector<std::array<std::string, 3>> released_claims;
    audit_retention::Anomaly anomaly = audit_retention::Anomaly::None;
    std::string facts_str;

    bool skipped_lock = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // SINGLE-WRITER (WS-10 / clock-guarded-retention "SINGLE-WRITER ONLY as
        // written"): this pass reads the anchor, decides, and force-releases in
        // one txn; two replicas running it unserialised race on the anchor and
        // the capped release, and the clock reading paces at N x cap. Take a
        // transaction-scoped advisory lock as the FIRST in-txn statement so the
        // whole read-decide-write is serialised fleet-wide. try-and-skip (not
        // blocking) fits this pass's tight ~5m cadence and its all-expired-is-
        // routine steady state, mirroring the sibling outbox-reap: a replica
        // that loses the race skips (the winner advances the anchor), and a
        // miss retries next tick far inside the claim horizon. Distinct key
        // from the two sibling reaps.
        pg::PgResult lk = pg::exec_params(
            conn, "SELECT pg_try_advisory_xact_lock(hashtext('execution_tracker:concurrency_reconcile'))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK || PQntuples(lk.get()) == 0) {
            spdlog::error("ExecutionTracker::reconcile_stale_concurrency_claims: "
                          "advisory lock query failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (col_str(lk.get(), 0, 0) != "t") {
            // Another replica holds the reconcile lock this tick — skip cleanly
            // (released 0; the holder advances the anchor). NOT a decline.
            skipped_lock = true;
            return true;
        }

        // Part 2 — a clock reading PERSISTED across restarts, not an
        // in-process one (an in-process reading is inert on the very pass
        // that matters: the first after a boot with an already-wrong clock).
        pg::PgResult anchor_res = pg::exec_params(
            conn,
            "SELECT value FROM execution_tracker.retention_meta "
            "WHERE key='concurrency_last_pass_now'",
            std::vector<std::string>{});
        if (anchor_res.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "ExecutionTracker::reconcile_stale_concurrency_claims: anchor read failed: {}",
                PQerrorMessage(conn));
            return false;
        }
        const bool have_anchor = PQntuples(anchor_res.get()) > 0;
        const int64_t last_pass_now = have_anchor ? to_i64(col(anchor_res.get(), 0, 0)) : 0;

        // A persisted reading that isn't a plausible epoch (negative, or
        // to_i64's garbage-parses-to-0 default) is unusable, not merely
        // absent — BadState outranks the others in classify()'s precedence.
        const bool prev_unusable = have_anchor && last_pass_now < 946684800; // < year 2000

        // Re-anchor for the NEXT pass BEFORE the probes below, so a decline
        // still advances the comparison point and a poisoned value
        // self-heals (matches audit_store.cpp). This alone no longer risks
        // stamping a "healthy" anchor for a pass that goes on to fail a
        // probe: a later `return false` in this lambda rolls this INSERT
        // back along with everything else.
        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO execution_tracker.retention_meta (key, value) "
            "VALUES ('concurrency_last_pass_now', $1) "
            "ON CONFLICT (key) DO UPDATE SET value=excluded.value",
            std::vector<std::string>{std::to_string(now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error(
                "ExecutionTracker::reconcile_stale_concurrency_claims: anchor stamp failed: {}",
                PQerrorMessage(conn));
            return false; // fail closed — roll back the whole pass
        }

        // Durable "has any pass ever reached a verdict" marker (#2579
        // shape, matches audit_store.cpp's `bootstrap_settled`) —
        // deliberately NOT derived from anchor presence: the anchor above
        // is written on every attempt regardless of outcome, so deriving
        // no_anchor from have_anchor would let a probe failure below spend
        // the missing-anchor trigger without this pass ever classifying
        // anything.
        pg::PgResult settled_res = pg::exec_params(
            conn,
            "SELECT 1 FROM execution_tracker.retention_meta "
            "WHERE key='concurrency_bootstrap_settled'",
            std::vector<std::string>{});
        if (settled_res.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "ExecutionTracker::reconcile_stale_concurrency_claims: settled read failed: {}",
                PQerrorMessage(conn));
            return false;
        }
        const bool bootstrap_settled = PQntuples(settled_res.get()) > 0;

        // Part 1 — probe by OUTCOME: would this pass release every open
        // claim? Still computed (has_expired feeds classify() directly),
        // but see below for why would_wipe is deliberately never set true
        // for this store. A failure here now rolls back the anchor stamp
        // too, instead of silently reading as "0 claims, nothing expired".
        pg::PgResult counts_res = pg::exec_params(
            conn,
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE expires_at < $1) "
            "FROM execution_tracker.concurrency_claims WHERE released_at IS NULL",
            std::vector<std::string>{std::to_string(now)});
        if (counts_res.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "ExecutionTracker::reconcile_stale_concurrency_claims: counts probe failed: {}",
                PQerrorMessage(conn));
            return false;
        }
        open_total = to_i64(col(counts_res.get(), 0, 0));
        stale_total = to_i64(col(counts_res.get(), 0, 1));
        const bool has_expired = stale_total > 0;

        // DELIBERATE NON-ADOPTION of would_wipe, following api_token_store.cpp's
        // recorded precedent for this exact shape (routed-concerns "Clock-guarded
        // retention" row, part 6): audit_store's table accumulates continuously
        // and always has a healthy mix of recent + old rows in ordinary
        // operation, so "literally everything looks expired" is a strong
        // wrong-clock signal there. concurrency_claims is small and ephemeral —
        // its entirely ordinary steady state is a handful of open claims from
        // currently in-flight per-device dispatches, and it is completely
        // routine for ALL of them to be past their expires_at on a given pass
        // (nothing else was in flight). Feeding a real would_wipe signal here
        // would decline the reconciler's own routine job on its most common
        // input — caught by a test written against the naive port of
        // audit_store's shape before this line existed.
        constexpr bool kWouldWipe = false;

        const audit_retention::Facts facts{
            .has_expired = has_expired,
            .would_wipe = kWouldWipe,
            .big_step = have_anchor && audit_retention::moved_at_least(
                                           last_pass_now, now, kConcurrencyReconcileBigStepFloorSeconds),
            .prev_unusable = prev_unusable,
            .no_anchor = !bootstrap_settled,
        };
        anomaly = audit_retention::classify(facts);
        facts_str = serialize_concurrency_facts(facts);

        pg::PgResult last_facts_res = pg::exec_params(
            conn,
            "SELECT value FROM execution_tracker.retention_meta "
            "WHERE key='concurrency_last_anomaly_facts'",
            std::vector<std::string>{});
        if (last_facts_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ExecutionTracker::reconcile_stale_concurrency_claims: last-facts read "
                          "failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        const std::string last_facts = PQntuples(last_facts_res.get()) > 0
                                            ? col_str(last_facts_res.get(), 0, 0)
                                            : std::string();

        // The pass has now REACHED A VERDICT — settle the marker HERE, not
        // at the re-anchor above (see the comment on `settled_res`). Every
        // early `return false` above this line rolls the whole transaction
        // back, so a pass that never reached a verdict leaves the trigger
        // armed for the next one.
        if (!bootstrap_settled) {
            pg::PgResult settle = pg::exec_params(
                conn,
                "INSERT INTO execution_tracker.retention_meta (key, value) VALUES "
                "('concurrency_bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{});
            if (settle.status() != PGRES_COMMAND_OK) {
                spdlog::error(
                    "ExecutionTracker::reconcile_stale_concurrency_claims: settle failed: {}",
                    PQerrorMessage(conn));
                return false;
            }
        }

        if (anomaly != audit_retention::Anomaly::None) {
            // Decline-once per DISTINCT fact set (Part 4): a new anomaly
            // declines and records; an identical repeat is suppressed and
            // drains (paced by the cap), so a legitimately all-expired table
            // still ages out.
            if (facts_str != last_facts) {
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO execution_tracker.retention_meta (key, value) "
                    "VALUES ('concurrency_last_anomaly_facts', $1) "
                    "ON CONFLICT (key) DO UPDATE SET value=excluded.value",
                    std::vector<std::string>{facts_str});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("ExecutionTracker::reconcile_stale_concurrency_claims: anomaly "
                                  "record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                declined = true;
                return true; // commit the anchor + settle + anomaly record
            }
            // Suppressed repeat of the same fact set — fall through to drain.
        } else if (!last_facts.empty()) {
            // A clean pass after an anomaly — clear the fact set so the NEXT
            // genuine anomaly is not mistaken for a repeat of this one.
            pg::PgResult clr = pg::exec_params(
                conn,
                "DELETE FROM execution_tracker.retention_meta "
                "WHERE key='concurrency_last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("ExecutionTracker::reconcile_stale_concurrency_claims: anomaly "
                              "clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (!has_expired)
            return true; // nothing to do — commit the anchor/settle above

        // Part 5 — cap unconditionally. Postgres has no UPDATE ... LIMIT; the
        // ctid-subselect is the standard idiom for a capped, RETURNING-visible
        // bulk update.
        pg::PgResult res = pg::exec_params(
            conn,
            "UPDATE execution_tracker.concurrency_claims SET released_at=$1 "
            "WHERE ctid IN (SELECT ctid FROM execution_tracker.concurrency_claims "
            "  WHERE released_at IS NULL AND expires_at < $1 LIMIT $2::integer) "
            "RETURNING definition_id, agent_id, execution_id",
            std::vector<std::string>{std::to_string(now),
                                     std::to_string(kConcurrencyReconcileCapPerPass)});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "ExecutionTracker::reconcile_stale_concurrency_claims: release failed: {}",
                PQerrorMessage(conn));
            return false;
        }
        released = PQntuples(res.get());
        released_claims.reserve(static_cast<std::size_t>(released));
        for (int i = 0; i < released; ++i) {
            released_claims.push_back(
                {col_str(res.get(), i, 0), col_str(res.get(), i, 1), col_str(res.get(), i, 2)});
        }
        return true;
    });

    if (!ok) {
        // A transaction that failed (pool exhaustion, a query error) must
        // leave the liveness gauge STALE — that is its whole alerting
        // story. Stamping "healthy" for a pass that never reached a
        // verdict is exactly the silent failure this rewrite closes.
        spdlog::error("ExecutionTracker::reconcile_stale_concurrency_claims: pass failed — "
                      "leaving the liveness gauge stale");
        return 0;
    }

    // Another replica held the reconcile lock this tick — we committed nothing
    // and reached no verdict, so do NOT advance the liveness gauge (the holder
    // does) and do not count it as a pass. A staleness alert on the gauge then
    // still fires if the ACTUAL holder wedges.
    if (skipped_lock)
        return 0;

    // Liveness gauge (sre, Gate 6): every pass that actually reached a
    // verdict and committed (declined or not) — the wedge case a bounded
    // decline-once dedup does NOT self-heal is an ALTERNATING fact set
    // (each pass differs from the last, so every pass declines forever);
    // that is invisible in logs alone and is exactly what a staleness
    // alert on this gauge would catch. Matches AuditStore/
    // AnalyticsEventStore's identical `..._last_pass_unixtime` idiom.
    if (metrics_)
        metrics_->gauge("yuzu_server_concurrency_reconcile_last_pass_unixtime")
            .set(static_cast<double>(now));

    if (declined) {
        spdlog::error(
            "ExecutionTracker::reconcile_stale_concurrency_claims: clock anomaly "
            "(anomaly={}, facts={}) — declining this pass, {} of {} open claim(s) left "
            "open past expiry",
            static_cast<int>(anomaly), facts_str, stale_total, open_total);
        if (metrics_)
            metrics_->counter("yuzu_server_concurrency_reconcile_declined_total").increment();
        return 0;
    }
    // Deferred until here (committed, ok == true) so a log line asserting a
    // release can never be contradicted by a rollback — see released_claims'
    // own doc comment above.
    for (const auto& c : released_claims) {
        spdlog::warn(
            "ExecutionTracker::reconcile_stale_concurrency_claims: force-released stale "
            "claim definition_id={} agent_id={} execution_id={} — agent never reported a "
            "terminal status before the claim's expires_at",
            c[0], c[1], c[2]);
    }
    if (metrics_ && released > 0)
        metrics_->counter("yuzu_server_concurrency_claim_force_released_total")
            .increment(static_cast<double>(released));
    return released;
}

// ---------------------------------------------------------------------------
// Statistics (capability 1.9)
// ---------------------------------------------------------------------------

std::vector<AgentExecutionStats>
ExecutionTracker::get_agent_statistics(const ExecutionStatsQuery& q) const {
    std::vector<AgentExecutionStats> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    // C5 fix: use status values actually set by update_agent_status/refresh_counts.
    // consistency-auditor Gate 4 finding (PR #3784 fix round): 'running' was NOT
    // excluded by the old WHERE clause (only 'pending'/'dispatched' were), so a
    // still-executing row (exit_code defaults to 0 on the wire, status='running')
    // satisfied the success CASE's `exit_code = 0 AND status != 'pending'` and was
    // counted as a completed success while genuinely still in flight -- a
    // pre-existing classifier gap this PR's own keepalive (agents/core/src/agent.cpp,
    // notify_exec_tracker -> update_agent_status) turned from rare (only a plugin
    // crossing the 64KB output-flush threshold) into routine for every per-device
    // dispatch running past 5 minutes. Excluding 'running' here, alongside
    // 'pending'/'dispatched', matches this query's own apparent intent: only
    // terminal, resolved executions are counted toward success/failure at all.
    // Also dropped the vestigial 'error' value from the failure CASE -- no code
    // path in agent_service_impl.cpp's status switch ever writes status='error'
    // (its default branch on an unmapped CommandResponse::Status returns without
    // writing anything), so it was dead weight left over from this comment's own
    // stated intent.
    std::string sql = R"(
        SELECT a.agent_id,
               COUNT(*) AS total,
               SUM(CASE WHEN a.exit_code = 0 AND a.status = 'success' THEN 1 ELSE 0 END) AS success,
               SUM(CASE WHEN a.exit_code != 0 OR a.status IN ('failure','timeout','rejected') THEN 1 ELSE 0 END) AS failure,
               AVG(CASE WHEN a.completed_at > a.dispatched_at
                        THEN a.completed_at - a.dispatched_at ELSE NULL END) AS avg_dur,
               MAX(a.dispatched_at) AS last_at
        FROM execution_tracker.agent_exec_status a
        JOIN execution_tracker.executions e ON e.id = a.execution_id
        WHERE a.status NOT IN ('pending','dispatched','running')
    )";
    std::vector<std::string> params;
    int idx = 1;
    if (!q.agent_id.empty()) {
        sql += " AND a.agent_id = $" + std::to_string(idx++);
        params.push_back(q.agent_id);
    }
    if (!q.definition_id.empty()) {
        sql += " AND e.definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.since > 0) {
        sql += " AND a.dispatched_at >= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND a.dispatched_at <= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.until));
    }
    sql += " GROUP BY a.agent_id ORDER BY total DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(q.limit > 0 ? q.limit : 50));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        AgentExecutionStats s;
        s.agent_id = col_str(res.get(), i, 0);
        s.total_executions = to_i64(col(res.get(), i, 1));
        s.success_count = to_i64(col(res.get(), i, 2));
        s.failure_count = to_i64(col(res.get(), i, 3));
        s.avg_duration_seconds = to_d(col(res.get(), i, 4));
        s.last_execution_at = to_i64(col(res.get(), i, 5));
        s.success_rate = s.total_executions > 0 ? 100.0 * static_cast<double>(s.success_count) /
                                                      static_cast<double>(s.total_executions)
                                                : 0.0;
        results.push_back(std::move(s));
    }
    return results;
}

std::vector<DefinitionExecutionStats>
ExecutionTracker::get_definition_statistics(const ExecutionStatsQuery& q) const {
    std::vector<DefinitionExecutionStats> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    // C5 fix: match all terminal execution statuses. NOTE (#3344): this
    // "NOT IN (pending, running)" idiom is deliberately NOT what
    // mcp_retry.hpp's is_execution_terminal() uses — that predicate is an
    // explicit allowlist so an unrecognized future status defaults to
    // non-terminal (keep polling) rather than terminal (stop silently) as
    // it would here. A new terminal status added to this analytics query
    // needs the same addition there, or the two poll tools sharing that
    // predicate will disagree with this rollup about which executions are
    // "done".
    std::string sql = R"(
        SELECT e.definition_id,
               COUNT(*) AS total,
               SUM(e.agents_targeted) AS total_agents,
               CASE WHEN SUM(e.agents_targeted) > 0
                    THEN 100.0 * SUM(e.agents_success) / SUM(e.agents_targeted) ELSE 0 END AS rate,
               AVG(CASE WHEN e.completed_at > e.dispatched_at
                        THEN e.completed_at - e.dispatched_at ELSE NULL END) AS avg_dur
        FROM execution_tracker.executions e
        WHERE e.status NOT IN ('pending','running')
    )";
    std::vector<std::string> params;
    int idx = 1;
    if (!q.definition_id.empty()) {
        sql += " AND e.definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.since > 0) {
        sql += " AND e.dispatched_at >= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND e.dispatched_at <= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.until));
    }
    sql += " GROUP BY e.definition_id ORDER BY total DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(q.limit > 0 ? q.limit : 50));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DefinitionExecutionStats s;
        s.definition_id = col_str(res.get(), i, 0);
        s.total_executions = to_i64(col(res.get(), i, 1));
        s.total_agents = to_i64(col(res.get(), i, 2));
        s.success_rate = to_d(col(res.get(), i, 3));
        s.avg_duration_seconds = to_d(col(res.get(), i, 4));
        results.push_back(std::move(s));
    }
    return results;
}

FleetExecutionSummary ExecutionTracker::get_fleet_summary(int64_t since) const {
    FleetExecutionSummary s;
    if (!open_)
        return s;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return s;

    // Total executions and success rate
    {
        std::string sql = R"(
            SELECT COUNT(*),
                   CASE WHEN SUM(agents_targeted) > 0
                        THEN 100.0 * SUM(agents_success) / SUM(agents_targeted) ELSE 0 END,
                   AVG(CASE WHEN completed_at > dispatched_at
                            THEN completed_at - dispatched_at ELSE NULL END)
            FROM execution_tracker.executions WHERE status NOT IN ('pending','running')
        )";
        std::vector<std::string> params;
        if (since > 0) {
            sql += " AND dispatched_at >= $1";
            params.push_back(std::to_string(since));
        }
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0) {
            s.total_executions = to_i64(col(res.get(), 0, 0));
            s.overall_success_rate = to_d(col(res.get(), 0, 1));
            s.avg_duration_seconds = to_d(col(res.get(), 0, 2));
        }
    }

    // Executions today
    {
        auto now = now_epoch();
        auto today_start = now - (now % 86400);
        pg::PgResult res = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM execution_tracker.executions WHERE dispatched_at >= $1",
            std::vector<std::string>{std::to_string(today_start)});
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0)
            s.executions_today = to_i64(col(res.get(), 0, 0));
    }

    // Active agents
    {
        std::string sql = "SELECT COUNT(DISTINCT agent_id) FROM execution_tracker.agent_exec_status";
        std::vector<std::string> params;
        if (since > 0) {
            sql += " WHERE dispatched_at >= $1";
            params.push_back(std::to_string(since));
        }
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0)
            s.active_agents = to_i64(col(res.get(), 0, 0));
    }

    return s;
}

// ---------------------------------------------------------------------------
// Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5)
// ---------------------------------------------------------------------------

namespace {
// Substrate-tuned to this table — do not copy from session_store's
// constants (clock-guarded-retention routed concern: "never copy the
// numbers"). A command's realistic in-flight lifetime is seconds to a few
// minutes; 24h is generous headroom over any documented per-command
// timeout, so a mapping this old is stale by construction, not merely idle.
constexpr std::int64_t kCmdExecutionReapWindowSecs = 24 * 3600;
constexpr int kCmdExecutionReapCap = 5000;
// A DB `now()` reading more than this far ahead of the persisted anchor is
// an anomaly, not legitimate elapsed time between reap ticks. The nominal
// inter-pass interval is ~3600s (server.cpp's kCmdExecutionReapEveryNTicks),
// but this threshold MUST carry real headroom over that nominal value, not
// merely equal it (governance Gate 4 consistency-auditor finding, self-
// verified): four OTHER reaps share this thread's tick loop and coincide on
// the same tick as this one, and ordinary scheduler jitter across ~1800
// individual sleep_for(1s) calls between passes is a plausible, non-clock-
// skew way to exceed a zero-margin threshold — and because a declined pass
// never advances the anchor, a single false trip would NEVER self-heal (the
// gap only grows on every subsequent tick). 24h matches this table's own
// reap window (kCmdExecutionReapWindowSecs) — ~24x the nominal cadence,
// comfortably absorbing ordinary jitter while still catching a genuinely
// wrong clock (a jump of days, not seconds).
constexpr std::int64_t kMaxPlausibleSkewSecs = 24 * 3600;

// Checked parse for the two clock-guard-critical readings (the DB now()
// column and the persisted reap_meta anchor) — deliberately NOT this file's
// ambient `to_i64`, which is a lenient `strtoll`-with-no-validation helper
// appropriate for trusted DB-returned row columns elsewhere in this file,
// but NOT for a value the clock-guarded-retention routed concern (CLAUDE.md
// part 3) requires be SANITISED: "ahead-of-now / negative / unparseable =
// anomaly, never a quiet reset". A migration bug, a manual `reap_meta` repair,
// or storage corruption writing `123junk` or an overflowed value must be
// REJECTED as an anomaly, not silently truncated/wrapped by an unchecked
// strtoll (adversarial review finding, PR #3780 -- api_token_store.cpp's
// `parse_meta_i64` / response_store.cpp's inline equivalent are the
// reference shape this mirrors; a second hand-rolled copy is the drift
// those two already accepted as "duplicating this one is cheaper than a
// shared-utility header for a three-line function").
std::optional<std::int64_t> parse_reap_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}
} // namespace

bool ExecutionTracker::record_command_execution(const std::string& command_id,
                                                const std::string& execution_id) {
    if (!open_)
        return false;

    // SINGLE attempt, no retry — deliberately NOT update_agent_status's
    // retry-once shape (governance Gate 4 unhappy-path/Gate 3 performance
    // finding). This call sits on the SYNCHRONOUS pre-RPC dispatch path
    // (record_execution_id / server.cpp's command_dispatch_fn calls this
    // BEFORE the RPC, UP2-4); a retry-once here would double the worst-case
    // block on the calling worker thread (REST/dashboard/MCP dispatch, or a
    // background runner such as ScheduleRunner/PreflightRunner/
    // PolicyEvaluator — anything feeding the shared CommandDispatchFn
    // closure) (2*kWriteTimeout)
    // under sustained pool contention. update_agent_status's retry lives on
    // the async gateway-response path, where that tradeoff is free.
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ExecutionTracker::record_command_execution: pool exhausted for "
                      "command_id={} — this command's responses will not correlate to an "
                      "execution_id on any replica (executions-drawer/SSE degraded for it, "
                      "dispatch itself is unaffected)",
                      command_id);
        return false;
    }
    pg::PgResult res =
        execution_id.empty()
            ? pg::exec_params(lease.get(),
                              "DELETE FROM execution_tracker.command_execution "
                              "WHERE command_id = $1",
                              std::vector<std::string>{command_id})
            // created_at is authored from Postgres now() IN-SQL, not the
            // calling replica's app clock (adversarial review Should-fix,
            // PR #3780): reap_command_execution_mappings compares created_at
            // against its own DB `now()` reading, so authoring created_at
            // from a different (app) clock domain means a replica whose
            // local clock lags the DB primary by more than the reap window
            // can write a mapping that reads as already-expired the moment
            // another replica's sweep runs -- silently dropping the exact
            // correlation this migration exists to preserve, in the exact
            // multi-replica scenario it targets. Matches session_store's
            // DB-clock-authority precedent (#3715).
            : pg::exec_params(
                  lease.get(),
                  "INSERT INTO execution_tracker.command_execution "
                  "(command_id, execution_id, created_at) "
                  "VALUES ($1, $2, extract(epoch FROM now())::bigint) "
                  "ON CONFLICT (command_id) DO UPDATE SET "
                  "execution_id = EXCLUDED.execution_id, created_at = EXCLUDED.created_at",
                  std::vector<std::string>{command_id, execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("ExecutionTracker::record_command_execution: write failed for "
                      "command_id={} — this command's responses will not correlate to an "
                      "execution_id on any replica (executions-drawer/SSE degraded for it, "
                      "dispatch itself is unaffected)",
                      command_id);
        return false;
    }
    return true;
}

std::optional<std::string>
ExecutionTracker::lookup_execution_id(const std::string& command_id,
                                      std::string* degrade_reason) const {
    if (!open_)
        return std::nullopt; // not a runtime degrade -- construction already failed loudly
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (degrade_reason)
            *degrade_reason = "pool_exhausted";
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT execution_id FROM execution_tracker.command_execution "
                                       "WHERE command_id = $1",
                                       std::vector<std::string>{command_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (degrade_reason)
            *degrade_reason = "query_failed";
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt; // genuine miss -- out-of-band dispatch or an aged-out mapping
    return col_str(res.get(), 0, 0);
}

std::expected<CommandExecutionReapOutcome, std::string>
ExecutionTracker::reap_command_execution_mappings() {
    if (!open_)
        return std::unexpected("execution tracker not open");

    // Shape mirrors SessionStore::reap_expired (clock-guarded-retention
    // routed concern) — advisory lock as its OWN statement, one in-SQL DB
    // `now()` read reused for the cutoff/anchor-compare/anchor-update,
    // persisted+sanitised anchor, forward/backward-anomaly decline,
    // unconditional cap. This table stores seconds (matching this store's
    // own `now_epoch()` convention), not the milliseconds session_store uses
    // — a substrate-tuning difference, not a shape deviation.
    int deleted = 0;
    bool clock_anomaly = false;
    std::int64_t now_s = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        if (pg::exec_params(c, "SELECT pg_advisory_xact_lock(hashtext('execution_tracker:reap'))",
                            std::vector<std::string>{})
                .status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock failed";
            return false;
        }
        {
            pg::PgResult nr = pg::exec_params(
                c, "SELECT extract(epoch FROM now())::bigint", std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "reap now() read failed";
                return false;
            }
            // SANITISE the reading (clock-guarded-retention routed concern,
            // part 3): unparseable or negative is an ANOMALY, never a quiet
            // fallback to 0/silently-truncated garbage (adversarial review
            // finding, PR #3780 -- the prior unchecked `to_i64` here would
            // parse a malformed/overflowed value with no error and no
            // rejection, in direct violation of this exact standing rule).
            auto parsed_now = parse_reap_i64(col_str(nr.get(), 0, 0));
            if (!parsed_now || *parsed_now < 0) {
                spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: "
                             "unparseable or negative now() reading '{}'",
                             col_str(nr.get(), 0, 0));
                clock_anomaly = true;
                return true; // decline, anchor unchanged
            }
            now_s = *parsed_now;
        }
        pg::PgResult ar = pg::exec_params(
            c, "SELECT value FROM execution_tracker.reap_meta WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        std::int64_t anchor = 0;
        if (has_anchor) {
            // Same sanitisation as now_s, for the SAME reason -- reap_meta
            // is a plain key/value table a bad migration, a manual repair,
            // or storage corruption can write anything into. An unparseable
            // or negative persisted anchor is an anomaly: decline this
            // pass, do NOT silently treat it as 0 (which would read as
            // "everything is stale" and mass-delete) or as any other quiet
            // fallback.
            auto parsed_anchor = parse_reap_i64(col_str(ar.get(), 0, 0));
            if (!parsed_anchor || *parsed_anchor < 0) {
                spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: "
                             "unparseable or negative persisted anchor '{}'",
                             col_str(ar.get(), 0, 0));
                clock_anomaly = true;
                return true;
            }
            anchor = *parsed_anchor;
        }
        // Overflow-safe comparison (adversarial review Blocker round 2,
        // PR #3780): `parse_reap_i64` rejects unparseable/negative values
        // but NOT an implausibly-large one that parses cleanly (e.g.
        // INT64_MAX from a bad migration/manual repair/corruption) --
        // `anchor + kMaxPlausibleSkewSecs` on such a value is signed-
        // integer-overflow UB (confirmed via UBSan). Subtracting instead
        // of adding cannot overflow: both operands are already sanitised
        // to be non-negative int64_t, so their difference always fits
        // (int64_t's negative range strictly exceeds its positive range).
        // The `now_s >= anchor` guard preserves the existing branch order
        // -- when now_s < anchor, this condition is false and control
        // falls through to the backward-anomaly check below, unchanged.
        if (has_anchor && now_s >= anchor && now_s - anchor > kMaxPlausibleSkewSecs) {
            spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: now_s {} "
                         "implausibly ahead of anchor {}",
                         now_s, anchor);
            clock_anomaly = true;
            return true; // decline, anchor unchanged
        }
        if (has_anchor && now_s < anchor) {
            spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: now_s {} "
                         "is behind anchor {} (backward clock movement or a poisoned anchor) — "
                         "not deleting under a rewound clock",
                         now_s, anchor);
            clock_anomaly = true;
            return true;
        }
        pg::PgResult dr = pg::exec_params(
            c,
            "DELETE FROM execution_tracker.command_execution WHERE command_id IN "
            "(SELECT command_id FROM execution_tracker.command_execution "
            " WHERE created_at < $1::bigint LIMIT $2::bigint) RETURNING command_id",
            std::vector<std::string>{std::to_string(now_s - kCmdExecutionReapWindowSecs),
                                     std::to_string(kCmdExecutionReapCap)});
        if (dr.status() != PGRES_TUPLES_OK) {
            err = std::string("reap delete failed: ") + PQerrorMessage(c);
            return false;
        }
        deleted = PQntuples(dr.get());
        const std::int64_t new_anchor = has_anchor ? (std::max)(anchor, now_s) : now_s;
        pg::PgResult ur = pg::exec_params(
            c,
            "INSERT INTO execution_tracker.reap_meta (key, value) VALUES "
            "('cmd_exec_reap_anchor', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "reap anchor update failed";
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(err.empty() ? "reap failed" : err);
    return CommandExecutionReapOutcome{deleted, clock_anomaly};
}

namespace {
// These values are bit-identical to the command_execution sibling's
// (kCmdExecutionReapWindowSecs / kCmdExecutionReapCap / kMaxPlausibleSkewSecs)
// and that is DELIBERATE, not a copy the clock-guarded-retention routed concern
// forbids: that prohibition (part 1) is scoped to the WOULD-WIPE implausible-
// ahead FLOOR, and this table takes the would-wipe carve-out, so it computes no
// such floor at all. The two tables are the same KIND of thing — short-lived
// per-execution observability feeds on the same maintenance cadence, same
// substrate, same failover/reconnect replay horizon — so their window/cap/skew
// are kept in LOCKSTEP with the sibling ON PURPOSE, and should be revisited
// TOGETHER, not diverged silently. Rationale for the shared values: 24h of
// durable frames comfortably covers a failover + a client-reconnect replay
// window while bounding table growth; the skew threshold is ~24x the sibling's
// ~3600s nominal cadence and absorbs scheduler jitter while still catching a
// genuinely wrong clock (the event_outbox reap itself runs on a TIGHTER ~60s
// cadence for volume reasons — see server.cpp — but the skew headroom is sized
// against the same worst-case inter-pass gap the sibling documents). If a
// future event-outbox-specific input (a consumer replay SLA, a failover MTTR
// bound) argues for a different value, derive it then and let the two diverge.
constexpr std::int64_t kEventOutboxReapWindowSecs = 24 * 3600;
constexpr int kEventOutboxReapCap = 5000;
constexpr std::int64_t kEventOutboxMaxPlausibleSkewSecs = 24 * 3600;
} // namespace

std::expected<EventOutboxReapOutcome, std::string> ExecutionTracker::reap_event_outbox() {
    if (!open_)
        return std::unexpected("execution tracker not open");

    // Shape mirrors reap_command_execution_mappings (which itself mirrors
    // SessionStore::reap_expired) — advisory lock as its OWN statement, one
    // in-SQL DB `now()` read reused for cutoff/anchor-compare/anchor-update,
    // persisted+sanitised anchor, forward/backward-anomaly decline, unconditional
    // cap, and the SAME two carve-outs (no would-wipe probe, no fact-set dedup).
    // Missing-anchor: PROCEED. See the header for the recorded part-(6) reasoning.
    int deleted = 0;
    bool clock_anomaly = false;
    std::int64_t now_s = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // NON-BLOCKING lock, DELIBERATELY diverging from the blocking
        // pg_advisory_xact_lock the command_execution sibling uses (governance
        // Gate 8 sre finding). That sibling reaps hourly, so a losing replica
        // blocking briefly is negligible; this reap runs on a ~60s cadence
        // (kEventOutboxReapEveryNTicks) on the SHARED single-threaded maintenance
        // tick, so a blocking lock would stall the whole tick (session reap, the
        // clock-integrity monitor) on every replica that loses the race, ~60x
        // more often. A skipped pass costs nothing here — another replica is
        // draining this tick, and a miss retries in ~60s, far inside the 24h
        // window — so try-and-skip is correct. Mirrors response_store's
        // tight-cadence precedent (pg_try_advisory_xact_lock + skip).
        pg::PgResult lk =
            pg::exec_params(c, "SELECT pg_try_advisory_xact_lock(hashtext('execution_tracker:outbox_reap'))",
                            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK || PQntuples(lk.get()) == 0) {
            err = "outbox reap advisory lock failed";
            return false;
        }
        if (col_str(lk.get(), 0, 0) != "t")
            return true; // another replica holds the reap lock this tick — skip (deleted 0)
        {
            pg::PgResult nr = pg::exec_params(
                c, "SELECT extract(epoch FROM now())::bigint", std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "outbox reap now() read failed";
                return false;
            }
            // SANITISE the reading (clock-guarded-retention routed concern part
            // 3): unparseable or negative is an ANOMALY, never a quiet fallback.
            auto parsed_now = parse_reap_i64(col_str(nr.get(), 0, 0));
            if (!parsed_now || *parsed_now < 0) {
                spdlog::warn("ExecutionTracker::reap_event_outbox declined: unparseable or "
                             "negative now() reading '{}'",
                             col_str(nr.get(), 0, 0));
                clock_anomaly = true;
                return true; // decline, anchor unchanged
            }
            now_s = *parsed_now;
        }
        pg::PgResult ar = pg::exec_params(
            c, "SELECT value FROM execution_tracker.reap_meta WHERE key = 'event_outbox_reap_anchor'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "outbox reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        std::int64_t anchor = 0;
        if (has_anchor) {
            // Same sanitisation as now_s, for the same reason (a bad migration /
            // manual repair / corruption can write anything into reap_meta).
            auto parsed_anchor = parse_reap_i64(col_str(ar.get(), 0, 0));
            if (!parsed_anchor || *parsed_anchor < 0) {
                spdlog::warn("ExecutionTracker::reap_event_outbox declined: unparseable or "
                             "negative persisted anchor '{}'",
                             col_str(ar.get(), 0, 0));
                clock_anomaly = true;
                return true;
            }
            anchor = *parsed_anchor;
        }
        // Overflow-safe forward-skew comparison (subtract, never add — both
        // operands are sanitised non-negative int64_t, so the difference cannot
        // overflow; adding kEventOutboxMaxPlausibleSkewSecs to an INT64_MAX-ish
        // anchor would be signed-overflow UB). The `now_s >= anchor` guard
        // preserves branch order — a rewound clock falls through to the
        // backward-anomaly check below.
        if (has_anchor && now_s >= anchor && now_s - anchor > kEventOutboxMaxPlausibleSkewSecs) {
            spdlog::warn("ExecutionTracker::reap_event_outbox declined: now_s {} implausibly ahead "
                         "of anchor {}",
                         now_s, anchor);
            clock_anomaly = true;
            return true; // decline, anchor unchanged
        }
        if (has_anchor && now_s < anchor) {
            spdlog::warn("ExecutionTracker::reap_event_outbox declined: now_s {} is behind anchor "
                         "{} (backward clock movement or a poisoned anchor) — not deleting under a "
                         "rewound clock",
                         now_s, anchor);
            clock_anomaly = true;
            return true;
        }
        pg::PgResult dr = pg::exec_params(
            c,
            "DELETE FROM execution_tracker.event_outbox WHERE event_id IN "
            "(SELECT event_id FROM execution_tracker.event_outbox "
            " WHERE created_at < $1::bigint ORDER BY event_id LIMIT $2::bigint) RETURNING event_id",
            std::vector<std::string>{std::to_string(now_s - kEventOutboxReapWindowSecs),
                                     std::to_string(kEventOutboxReapCap)});
        if (dr.status() != PGRES_TUPLES_OK) {
            err = std::string("outbox reap delete failed: ") + PQerrorMessage(c);
            return false;
        }
        deleted = PQntuples(dr.get());
        const std::int64_t new_anchor = has_anchor ? (std::max)(anchor, now_s) : now_s;
        pg::PgResult ur = pg::exec_params(
            c,
            "INSERT INTO execution_tracker.reap_meta (key, value) VALUES "
            "('event_outbox_reap_anchor', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "outbox reap anchor update failed";
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(err.empty() ? "outbox reap failed" : err);
    return EventOutboxReapOutcome{deleted, clock_anomaly};
}

// HA WS-2a-2 (ADR-2002 §5): the cross-replica delivery poll. Reference: the
// enterprise-architect design review 2026-09-02 (verdict ENDORSE/SOUND) + the
// ID-ORDERING CONTRACT on append_event_outbox above.
//
// WHY AN XID HORIZON, NOT A KEYSET. event_outbox.event_id is assigned at INSERT
// but the row is visible only at COMMIT, so a lower-id txn can commit AFTER a
// higher-id one (and aborted txns leave permanent id gaps). Two cursors that
// LOSE events, and the one that does not:
//   * `event_id > cursor`               — skips a slow-committing lower id
//                                          forever.                          ✗
//   * `(w_xid,event_id) > last_read` keyset — ALSO loses at the boot boundary: a
//     txn in-flight at boot with a LOWER xid commits after boot, lands BELOW the
//     cursor tuple, and is skipped forever.                                  ✗
//   * xid8 HORIZON WINDOW — the cursor is a single xid8 `poll_horizon_`. Each
//     pass reads w_xid IN [poll_horizon_, xmin) and advances poll_horizon_ to
//     xmin. xmin = pg_snapshot_xmin(pg_current_snapshot()) is the oldest RUNNING
//     xid and is MONOTONIC NON-DECREASING (new txns always draw HIGHER xids, so
//     the running-set minimum only rises), so xmin never passes an uncommitted
//     xid — an in-flight low xid PINS xmin until it settles, then the window
//     sweeps it up exactly once. No committed row can appear below an
//     already-advanced horizon.                                              ✓
// Init poll_horizon_ = xmin at boot: skips all pre-boot history (a reconnecting
// subscriber replays history from the durable outbox by execution_id — the
// SEPARATE slice-2 path — NOT this live poll, whose only job is the live tail).
// The horizon is a CONSERVATIVE cut: it re-delivers the small tail of
// pre-boot-committed rows whose xid >= boot-xmin (committed while an older txn
// still ran) — a bounded DUP, never a loss; do NOT "fix" it into a commit-TIME
// cut (created_at is txn-START time and does not linearize commit order).
//
// SINGLE SNAPSHOT (review hardening i): xmin is computed ONCE, in-SQL, in the
// same statement as the read (the CTE `s`, LEFT-JOINed so xmin comes back even
// on an empty window), and the horizon advances to THAT xmin — so the window
// filter and the advance use the IDENTICAL value, no two-snapshot skew. xid8
// comparisons are done IN SQL against `$1::xid8` (review hardening ii) — NEVER
// by stringifying and comparing lexically in C++ ('9' > '10' as text is a silent
// gap); C++ only round-trips the xid8 as decimal text and does numeric equality.
//
// CAP IS A HARD STATIC FLOOR (the review's one required guardrail). On a full
// batch the horizon advances to the LAST row's w_xid (re-reading that one xid's
// rows next pass — a bounded, tolerated dup) rather than to xmin. That is
// lossless AND progress-guaranteed ONLY IF the cap exceeds the max rows a SINGLE
// txn appends (refresh_counts writes 2; upsert/cancel 1 — so <= 3).
// kPollBatchCap is a compile-time constant far above that, never a runtime knob
// that could drop to <= 3 and livelock the drain into silent loss. Belt-and-
// suspenders: a full batch whose first and last w_xid are EQUAL (impossible
// under <=3-per-xid) is logged as a loud invariant violation, not silently
// re-pinned.
//
// SKIP-OWN: rows this replica appended (origin_replica == replica_id_) were
// already published in-process at append time, so the poll excludes them via
// `($2 = '' OR origin_replica <> $2)`. An empty replica_id_ (secure-RNG failure
// at construction) disables self-exclusion — this replica then re-publishes its
// OWN events onto its own bus, a tolerated dup (§5), never a miss.
//
// OPERATIONAL (head-of-line, architect review): the horizon is the server's
// GLOBAL all-committed xmin, so one long-running transaction anywhere on that
// PostgreSQL pins it and DELAYS — never drops — cross-replica delivery until
// that txn commits. Fine here (outbox txns are tiny/short and the server owns
// its PG); a long analytic query or a stuck 2PC sharing the substrate would
// spike cross-replica SSE latency to that txn's lifetime. This is inherent to a
// loss-free forward drain over an outbox (the id-gap-pending alternative stalls
// the same way); a NOTIFY hint does not change it.
//
// The re-publish is bus-LOCAL — nothing is written back to the outbox — so no
// cross-replica amplification is possible; duplicate volume is bounded to one
// window / one xid worth. HOT-STANDBY CAVEAT (review): the monotonic-xmin
// reasoning holds only against the PRIMARY; the pool DSN points at the primary
// (ADR-0007), so this is safe as wired — a future standby-read routing would
// need it re-argued per connection.
std::expected<int, std::string> ExecutionTracker::poll_event_outbox_once() {
    if (!open_ || !event_bus_)
        return 0; // nothing to drain into
    static constexpr int kPollBatchCap = 512; // >> max rows per single txn (<= 3)

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string("event_outbox poll: pool acquire timeout — ") +
                               pool_.last_error());
    PGconn* conn = lease.get();

    // Lazy boot-init: horizon = the current all-committed xmin, so this replica
    // delivers only events that settle AFTER it booted (pre-boot history is the
    // reconnect-replay path's job). The first pass establishes the horizon and
    // delivers nothing.
    if (!poll_initialized_) {
        pg::PgResult x = pg::exec_params(
            conn, "SELECT pg_snapshot_xmin(pg_current_snapshot())::text", std::vector<std::string>{});
        if (x.status() != PGRES_TUPLES_OK || PQntuples(x.get()) != 1)
            return std::unexpected(std::string("event_outbox poll init xmin: ") +
                                   PQerrorMessage(conn));
        poll_horizon_ = col_str(x.get(), 0, 0);
        poll_initialized_ = true;
        return 0;
    }

    // s LEFT JOIN outbox: the settle-horizon xmin (s.x) always comes back — even
    // when the window matches no cross-replica rows — so the horizon can advance
    // to the SAME xmin the filter used. Filter conditions live in ON, not WHERE,
    // so the null-padded sentinel row survives when there is no match.
    pg::PgResult res = pg::exec_params(
        conn,
        "WITH s AS (SELECT pg_snapshot_xmin(pg_current_snapshot()) AS x) "
        "SELECT e.event_id, e.execution_id, e.event_type, e.data, e.is_terminal, "
        "       e.w_xid::text, s.x::text "
        "FROM s LEFT JOIN execution_tracker.event_outbox e "
        "  ON e.w_xid >= $1::xid8 AND e.w_xid < s.x "
        "     AND ($2 = '' OR e.origin_replica <> $2) "
        "ORDER BY e.w_xid, e.event_id "
        "LIMIT $3::int",
        std::vector<std::string>{poll_horizon_, replica_id_, std::to_string(kPollBatchCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("event_outbox poll: ") + PQerrorMessage(conn));

    const int n = PQntuples(res.get());
    std::string cur_xmin;
    std::string first_wxid, last_wxid;
    int published = 0;
    for (int i = 0; i < n; ++i) {
        if (i == 0)
            cur_xmin = col_str(res.get(), i, 6); // s.x — identical on every row
        if (PQgetisnull(res.get(), i, 0))
            continue; // empty-window sentinel (LEFT JOIN, no matching outbox row)
        const std::string execution_id = col_str(res.get(), i, 1);
        const std::string event_type = col_str(res.get(), i, 2);
        const std::string data = col_str(res.get(), i, 3);
        const bool is_terminal = std::string(col(res.get(), i, 4)) == "t";
        const std::string wxid = col_str(res.get(), i, 5);
        if (published == 0)
            first_wxid = wxid;
        last_wxid = wxid;
        // Re-publish onto the LOCAL bus with a per-channel counter id (HA WS-2a-2
        // Option A) — NOT the durable event_id. The durable id (col 0) drives
        // this poll's ORDER BY / cursor only; the live bus id stays the
        // reconnect-safe local counter (see the bus publish body). Cross-replica
        // cursor stability (a failover subscriber resuming by durable id) is the
        // slice-2 durable-replay concern, not this live re-publish.
        event_bus_->publish(execution_id, event_type, data, is_terminal);
        ++published;
    }

    if (published < kPollBatchCap) {
        poll_horizon_ = cur_xmin; // whole settled window consumed
    } else {
        // Backlog: advance to the last row's xid rather than xmin, re-reading
        // that one xid's rows next pass (a bounded, tolerated dup). Progress is
        // guaranteed because a batch of kPollBatchCap rows spans many xids
        // (<= 3 rows/xid) — UNLESS the invariant is violated, which we surface.
        if (first_wxid == last_wxid)
            spdlog::error("ExecutionTracker::poll_event_outbox_once: a full batch ({}) fell "
                          "entirely within one xid {} — the <=3-rows-per-txn invariant is "
                          "violated and the cross-replica drain may stall",
                          kPollBatchCap, last_wxid);
        poll_horizon_ = last_wxid;
    }
    return published;
}

} // namespace yuzu::server
