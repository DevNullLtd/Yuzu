#pragma once

/// @file execution_tracker.hpp
/// Postgres-backed execution-history store (ADR-0009/0065). Schema
/// `execution_tracker`, two tables (`executions`, `agent_exec_status`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`), a posture UPGRADE from the SQLite era, where
/// migration failure set `migration_ok_ = false` but `server.cpp` never
/// checked it (the shared `InstructionDbPool`'s own `is_open()` was the
/// only thing `/readyz` keyed on). Runtime reads/writes keep their
/// pre-migration plain-container/`std::expected<std::string,std::string>`
/// shapes — this store's consumers (gRPC `AgentServiceImpl`, REST v1,
/// legacy REST, MCP, dashboard, `ScheduleRunner`) are unaffected by this
/// migration.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment).
/// The legacy `instructions.db` (shared with the ScheduleEngine/
/// ApprovalManager siblings, both already migrated — ADR-0065) is never
/// read for data; construction logs a one-time "fresh start, no legacy
/// backfill" line, and the caller (`server.cpp`) runs
/// `legacy_sqlite_probe::warn_if_legacy_rows()` over the legacy file so an
/// environment where "no production fleet" turns out to be locally wrong
/// gets a loud signal instead of silent loss. This is the LAST of the 7
/// Wave-4 SQLite components — `InstructionDbPool` is deleted once this
/// store moves.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu {
class MetricsRegistry;
} // namespace yuzu

namespace yuzu::server {

class ExecutionEventBus;

struct Execution {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string scope_expression;
    std::string parameter_values;
    std::string dispatched_by;
    int64_t dispatched_at{0};
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t completed_at{0};
    std::string parent_id;
    std::string rerun_of;
    /// Most recent non-empty agent error_detail for this execution. Populated
    /// only when the caller passes `ExecutionQuery::include_error_detail =
    /// true` (LIST fragment) or via `get_execution(id)` which always opts in.
    /// **PII-adjacent: contains agent stderr** — paths, hostnames, env values,
    /// possibly customer data captured from a broken plugin invocation. Gate
    /// behind `perm_fn(req, res, "Execution", "Read")` before serializing to
    /// any caller (mirrors mcp_server.cpp:get_execution_status).
    std::string last_error_detail;
};

struct ExecutionQuery {
    std::string definition_id;
    std::string status;
    /// #1634: restricts to executions dispatched by this exact principal.
    /// Empty (the default) is unrestricted. Used by MCP `list_executions`
    /// for a management-group-confined caller — executions carry no single
    /// `agent_id` to filter by (they fan out to many), so "own dispatches
    /// only" is the cheap, provably-safe confinement until a real per-row
    /// visible-agent-intersection check exists (that would need a
    /// per-execution agent-status lookup per row — an N+1 pattern ADR-0017
    /// INV-10 calls out as a latency/DoS surface, not something to add
    /// silently inside a LIST route).
    std::string dispatched_by;
    int limit{100};
    /// When true, populate `Execution::last_error_detail` via a correlated
    /// subquery on `agent_exec_status`. Default false because most callers
    /// (health probes, metrics ticks, server.cpp:1727 with limit=1000) do
    /// not consume the field, and the per-row subquery cost amortises
    /// poorly on hot paths (arch-B2). Set true only on the executions
    /// LIST fragment, which renders a per-row error preview.
    bool include_error_detail{false};
};

/// #3789: SQL-pushdown caller-visibility for `query_executions_checked`
/// (the migrated legacy `GET /api/executions` LIST route). Unlike
/// `ExecutionQuery::dispatched_by` above (an exact-match FILTER — narrows
/// to only that dispatcher's rows), this is an ADMISSION predicate: a row
/// is included when EITHER `owner` dispatched it OR the execution has at
/// least one `agent_exec_status` row whose `agent_id` is in
/// `visible_agents`. The owner disjunct exists because `agent_exec_status`
/// rows are written ONLY on response arrival (see `update_agent_status`'s
/// sole caller, `agent_service_impl.cpp`) — a just-dispatched execution has
/// zero status rows regardless of its real target set, so an
/// agent-membership-only predicate would make a caller's own execution
/// invisible to them until the first agent replies. `owner` empty AND
/// `visible_agents` empty means "visible to nobody" (every row excluded),
/// matching `response_store.cpp`'s `append_scope_clause` engaged-empty
/// convention. This is a plain data type with no authz dependency — the
/// route layer derives it from `authz::VisibleSet`/the session username.
struct ExecutionListScope {
    std::string owner;
    std::vector<std::string> visible_agents;
};
/// `nullopt` = unrestricted (TOP, no pushdown) — every existing caller of
/// `query_executions`/`query_executions_checked`'s default keeps this.
using ExecutionScope = std::optional<ExecutionListScope>;

struct ExecutionSummary {
    std::string id;
    std::string status;
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int progress_pct{0};
};

struct AgentExecStatus {
    std::string agent_id;
    std::string status;
    int64_t dispatched_at{0};
    int64_t first_response_at{0};
    int64_t completed_at{0};
    int exit_code{0};
    std::string error_detail;
    /// CC-07 plugin→host typed result status (agent.proto CommandResponse
    /// .plugin_result_status, mirrors YuzuResultStatus from
    /// sdk/include/yuzu/plugin.h). 0 (PLUGIN_RESULT_UNDECLARED) for legacy
    /// rows and for any response whose plugin never reported a typed status.
    int plugin_result_status{0};
};

// ── Execution statistics (capability 1.9) ────────────────────────────

struct AgentExecutionStats {
    std::string agent_id;
    int64_t total_executions{0};
    int64_t success_count{0};
    int64_t failure_count{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
    int64_t last_execution_at{0};
};

struct DefinitionExecutionStats {
    std::string definition_id;
    int64_t total_executions{0};
    int64_t total_agents{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct FleetExecutionSummary {
    int64_t total_executions{0};
    int64_t executions_today{0};
    int64_t active_agents{0};
    double overall_success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct ExecutionStatsQuery {
    std::string agent_id;
    std::string definition_id;
    int64_t since{0};
    int64_t until{0};
    int limit{50};
};

/// HA WS-1(1b), ADR-2002 section 5. Outcome of a `command_execution`
/// correlation-table retention pass. Mirrors `SessionStore::ReapOutcome`'s
/// shape (clock-guarded-retention routed concern) — `clock_anomaly` true
/// means the pass declined due to an implausible DB `now()` reading, not
/// that rows were deleted.
struct CommandExecutionReapOutcome {
    int deleted{0};
    bool clock_anomaly{false};
};

/// HA WS-2a (durable event outbox), ADR-2002 §5. Outcome of an `event_outbox`
/// retention pass. Same shape/semantics as `CommandExecutionReapOutcome` — a
/// distinct table and metric family, so a distinct type: `clock_anomaly` true
/// means the pass declined on an implausible DB `now()` reading, not that rows
/// were deleted.
struct EventOutboxReapOutcome {
    int deleted{0};
    bool clock_anomaly{false};
};

/// #2146 A2-R1 governance re-review (blocking): `get_children_checked`'s
/// underlying query was unbounded (no LIMIT at all), unlike its sibling
/// `ScheduleEngine::query_schedules_checked` (`schedule_engine.hpp`'s
/// `ScheduleListResult`, whose shape this mirrors exactly). `truncated` is
/// `true` when the row cap (`kExecutionChildrenCap`, execution_tracker.cpp)
/// dropped rows past the newest `dispatched_at`-ordered window -- REST v1
/// `GET /api/v1/executions/{id}/children`, the legacy
/// `GET /api/executions/{id}/children`, and MCP `get_execution_children` all
/// surface it as `result_truncated_by_cap` so a capped response is never
/// presented as the parent's complete child list.
///
/// #2146 A2-R1 Gate 8 re-review fix: the cap used to apply to the RAW,
/// unfiltered `parent_id`-matched row set, BEFORE any caller-side
/// `execution_visible` confinement filter -- a confined caller's own visible
/// children could be entirely displaced out of the capped window by
/// invisible siblings dispatched more recently, with no signal that this
/// happened (`truncated:false` while the caller's OWN visible set was
/// silently incomplete). `get_children_checked` now takes the caller's
/// `ExecutionScope` and pushes it into the query (via
/// `append_execution_scope_clause`) BEFORE `ORDER BY`/`LIMIT` -- the SAME
/// SQL-pushdown pattern `query_executions_checked` already uses for the
/// LIST route (ADR-0017 INV-3). `truncated` now answers "did THIS CALLER's
/// own visible row set exceed the cap" under an engaged scope, or "did the
/// fleet-wide row set exceed the cap" when `scope` is `nullopt`.
struct ExecutionChildrenResult {
    std::vector<Execution> children;
    bool truncated{false};
};

class ExecutionTracker {
public:
    explicit ExecutionTracker(pg::PgPool& pool);
    ~ExecutionTracker() = default;

    ExecutionTracker(const ExecutionTracker&) = delete;
    ExecutionTracker& operator=(const ExecutionTracker&) = delete;

    /// Idempotent no-op kept for call-site compatibility — migration now
    /// runs unconditionally inside the constructor (PgMigrationRunner),
    /// unlike the SQLite era where callers invoked this explicitly.
    void create_tables() {}

    /// PR 3 — attach a per-execution SSE bus. When set, every mutating call
    /// (update_agent_status, refresh_counts, mark_cancelled) publishes a
    /// transition event onto the bus's per-execution channel. The bus is
    /// owned by the server; the tracker only borrows it. nullptr disables
    /// publishing — used by harnesses that don't exercise SSE.
    void set_event_bus(ExecutionEventBus* bus) { event_bus_ = bus; }

    /// ADR-1007 — optional observability sink for the per-device
    /// concurrency-claim path (skip counts, force-releases). nullptr (the
    /// default) means no metrics — matches every sibling store's `set_metrics`
    /// idiom (a post-construction setter, not a constructor parameter, so
    /// this costs zero changes to any existing `ExecutionTracker(pg::PgPool&)`
    /// call site).
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // Query
    std::vector<Execution> query_executions(const ExecutionQuery& q = {}) const;
    /// #3789: degrade-distinguishable + scope-pushdown twin of
    /// `query_executions`, for the migrated legacy `GET /api/executions`
    /// LIST route. `nullopt` on a pool/query failure (a plain empty vector
    /// there is indistinguishable from "no matching executions" — a caller
    /// that drops rows and writes audit trails off this result must not
    /// treat a degrade as an empty result set). `scope` engaged pushes the
    /// `ExecutionListScope` admission predicate into the `WHERE` clause
    /// BEFORE `ORDER BY`/`LIMIT` (ADR-0017 INV-3) via a correlated `EXISTS`
    /// over `agent_exec_status` — `executions` carries no per-row
    /// `agent_id` column, so this is not the N+1 shape
    /// `ExecutionQuery::dispatched_by`'s doc comment above rejects (one
    /// statement, planner-optimizable to a semi-join).
    std::optional<std::vector<Execution>>
    query_executions_checked(const ExecutionQuery& q = {},
                             const ExecutionScope& scope = std::nullopt) const;
    std::optional<Execution> get_execution(const std::string& id) const;
    /// #3789: degrade-distinguishable twin of `get_execution`. That method
    /// collapses "row absent" and "read degraded" to the same `nullopt`
    /// (single early-return in the shared `exec_by_id_at` helper) — fine
    /// for its existing best-effort callers, but a confined route that
    /// turns a `nullopt` into a 404 + a `denied` audit row must not do that
    /// on a transient degrade (false 404 for a legitimate owner; a
    /// permanently wrong CC7.2 audit trail for a non-owner). `unexpected`
    /// only for a pool/query failure; the inner `optional` empty means the
    /// row genuinely doesn't exist.
    [[nodiscard]] std::expected<std::optional<Execution>, std::string>
    get_execution_checked(const std::string& id) const;
    ExecutionSummary get_summary(const std::string& id) const;
    std::vector<AgentExecStatus> get_agent_statuses(const std::string& execution_id) const;
    /// #1634 (Doomgoose review finding, important) — degrade-distinguishable
    /// twin of `get_agent_statuses`, for the #1634 visibility/audit call
    /// sites (REST GET /api/v1/executions/{id}, GET /api/v1/events,
    /// GET /sse/executions/{id}, dashboard detail fragment, MCP
    /// get_execution_status). `get_agent_statuses` itself keeps its
    /// existing plain-vector contract — pre-existing callers (rerun-lineage
    /// composition, etc.) are unaffected — because a store-read failure
    /// there degrades in a direction that only ever UNDER-serves data,
    /// never mints a false CC7.2 audit row or a false 404/200 admission
    /// decision. `nullopt` on a pool-acquire timeout or query failure,
    /// matching ResponseStore's own nullopt-on-degrade convention
    /// (`docs/cpp-conventions.md`'s degrade-vs-empty distinguishability
    /// rule) — a caller MUST fail closed (503/deny) on nullopt rather than
    /// treat it as "zero agents" (which would 404 a caller during a
    /// transient PG degrade and permanently record a false `denied` audit
    /// row for a non-owner, or hand an owner a false 200-with-zero-counts).
    std::optional<std::vector<AgentExecStatus>>
    get_agent_statuses_checked(const std::string& execution_id) const;
    /// #1634 (Doomgoose review finding, important) — batched twin of
    /// `get_agent_statuses` for a LIST caller that needs per-execution
    /// in-scope counts for N executions without N+1 queries (ADR-0017
    /// INV-10). One `execution_id = ANY($1::text[])` read; returns a map
    /// keyed by execution_id so a caller can recompute confined counts per
    /// row from a single round trip. Empty `execution_ids` short-circuits
    /// without touching the pool (engaged-empty, not a degrade).
    std::unordered_map<std::string, std::vector<AgentExecStatus>>
    get_agent_statuses_for_executions(const std::vector<std::string>& execution_ids) const;
    /// #3789: degrade-distinguishable twin of `get_agent_statuses_for_executions`,
    /// for callers that DROP rows or write `denied` audit rows off the
    /// result (the migrated legacy LIST route). The plain map's
    /// degrade-vs-empty ambiguity is tolerable for MCP `list_executions`'
    /// count-only projection (a degrade there just yields false zero
    /// counts on an otherwise-unaffected row) but not here, where it would
    /// silently drop in-scope executions from a confined caller's page.
    /// `nullopt` on a pool/query failure; an engaged-but-empty map means
    /// zero of the requested executions have any status rows yet — a
    /// normal, non-degraded outcome for a just-dispatched execution
    /// (`agent_exec_status` is response-arrival-seeded, #3789 finding).
    std::optional<std::unordered_map<std::string, std::vector<AgentExecStatus>>>
    get_agent_statuses_for_executions_checked(
        const std::vector<std::string>& execution_ids) const;
    /// Best-effort convenience wrapper over `get_children_checked` with
    /// `scope = nullopt` -- test-only production usage today (no confined
    /// caller). Discards BOTH the degrade signal (a pool/query failure
    /// collapses to the same empty vector a genuinely childless parent
    /// returns) and `ExecutionChildrenResult::truncated` -- silently, since
    /// no caller today reads past `kExecutionChildrenCap` rows to notice. A
    /// future caller that needs either signal should call
    /// `get_children_checked` directly rather than add it here.
    std::vector<Execution> get_children(const std::string& parent_id) const;
    /// #3789: degrade-distinguishable twin of `get_children`, for the
    /// migrated `/api/executions/{id}/children` route — `nullopt` on a
    /// pool/query failure, an empty vector means the parent genuinely has
    /// no children. #2146 A2-R1 (governance re-review, blocking): the query
    /// is now hard-capped at `kExecutionChildrenCap` rows (execution_tracker.cpp)
    /// -- previously unbounded, unlike every other list-shaped read in this
    /// class -- so `ExecutionChildrenResult::truncated` tells all three
    /// callers (REST v1, the legacy route, MCP) when the cap dropped rows.
    ///
    /// #2146 A2-R1 Gate 8 re-review fix: `scope` is now REQUIRED, not
    /// defaulted -- deliberately, mirroring `authz::VisibleSet`'s own "require
    /// it, never default it" rule (authz_model.hpp), so a caller cannot
    /// forget to thread its real confinement scope and compile clean anyway.
    /// Pass `std::nullopt` explicitly for an unrestricted read (every
    /// existing test/tool-internal caller that has no confinement scope to
    /// thread does exactly this). When `scope` is engaged,
    /// `append_execution_scope_clause` pushes the SAME owner-or-visible-agent
    /// admission predicate `execution_visible` (execution_scope_rules.hpp)
    /// decides in-process into the SQL `WHERE` clause, BEFORE `ORDER BY`/
    /// `LIMIT` (ADR-0017 INV-3) -- so the cap applies to THIS CALLER's own
    /// visible row set, not the fleet-wide raw one. `truncated == false`
    /// now genuinely means every child this caller can see was returned;
    /// under `nullopt`, it answers "did the fleet-wide row set exceed the
    /// cap", exactly as before.
    std::optional<ExecutionChildrenResult>
    get_children_checked(const std::string& parent_id, const ExecutionScope& scope) const;

    // Mutation
    std::expected<std::string, std::string> create_execution(const Execution& exec);
    void update_agent_status(const std::string& execution_id, const AgentExecStatus& status);
    void refresh_counts(const std::string& execution_id);

    /// PR 2: set agents_targeted post-creation. Used by the workflow execute
    /// handler which now creates the execution row BEFORE dispatch (to thread
    /// execution_id into cmd_dispatch and close the FAST-agent race UP2-4),
    /// then updates `agents_targeted` once dispatch confirms how many agents
    /// the command actually reached. Returns false on a pool/query failure
    /// (governance PR review, 2026-08-31) — the row never learns its real
    /// agent count and can never reach refresh_counts's all-responded
    /// threshold, wedging it at "running"; callers should log/surface this.
    /// `[[nodiscard]]` (scoped re-review, cpp-expert) matches this
    /// codebase's own convention for a must-check success signal
    /// (`AuditStore::log`) — a future call site silently discarding this
    /// return would reintroduce the exact bug this fix closes.
    [[nodiscard]] bool set_agents_targeted(const std::string& execution_id, int agents_targeted);

    std::expected<std::string, std::string> create_rerun(const std::string& original_id,
                                                         const std::string& user, bool failed_only);

    /// Returns false on a pool/query failure (governance PR review,
    /// 2026-08-31) — the execution was NOT actually cancelled; callers must
    /// not report success (an audit "success" row or an HTTP 200) on a
    /// false return. `[[nodiscard]]` for the same reason as
    /// `set_agents_targeted` above.
    [[nodiscard]] bool mark_cancelled(const std::string& id, const std::string& user);

    // Statistics (capability 1.9)
    std::vector<AgentExecutionStats> get_agent_statistics(const ExecutionStatsQuery& q = {}) const;
    std::vector<DefinitionExecutionStats> get_definition_statistics(const ExecutionStatsQuery& q = {}) const;
    FleetExecutionSummary get_fleet_summary(int64_t since = 0) const;

    // ── Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5) ──
    //
    // Replaces AgentServiceImpl's former in-process `cmd_execution_ids_` map.
    // That map was replica-local: a command dispatched on one server instance
    // populated it only in that process's memory, so a CommandResponse that
    // landed on a DIFFERENT gateway-fronted replica found no mapping and
    // silently dropped the correlation (no responses.execution_id stamp, no
    // executions-drawer SSE event, no tracker-counter advance for that
    // response) — exactly the cross-instance correlation hazard ADR-2002
    // section 5 names `cmd_execution_ids_` as a required PG migration to close.

    /// Records (or clears) a command_id -> execution_id mapping. Last-write-
    /// wins on a repeated command_id, matching the former map's `operator[]=`
    /// semantics. An empty `execution_id` deletes any existing mapping (the
    /// former map's explicit-clear branch; no current caller exercises it).
    /// Best-effort by design: a write failure degrades OBSERVABILITY for
    /// this one command — the executions drawer misses its agent-transition
    /// events — it never FAILS the dispatch that is calling this
    /// (record_execution_id / server.cpp's command_dispatch_fn calls this
    /// BEFORE the RPC, UP2-4; the return value is best-effort telemetry for
    /// the caller to count, not a signal to act on).
    ///
    /// It DOES have a bounded worst-case DELAY: a single attempt at
    /// `kWriteTimeout` (no retry — deliberately NOT `update_agent_status`'s
    /// retry-once shape, because that call sits on the async gateway-
    /// response path while this one sits on the SYNCHRONOUS pre-RPC dispatch
    /// path; a second attempt here would double the worst-case block on the
    /// calling worker thread — REST/dashboard/MCP dispatch, or a background
    /// runner such as ScheduleRunner/PreflightRunner/PolicyEvaluator,
    /// anything feeding the shared CommandDispatchFn closure — under
    /// sustained pool contention). Returns false on failure so the caller can count a
    /// degrade metric; a caller MUST NOT fail or delay dispatch on a false
    /// return (governance Gate 4 unhappy-path UP-1/UP-11, Gate 3 performance
    /// review — the prior wording here claimed zero delay, which was false).
    [[nodiscard]] bool record_command_execution(const std::string& command_id,
                                                const std::string& execution_id);

    /// Resolves a previously-recorded mapping. Returns nullopt for an unknown
    /// command_id (out-of-band dispatch, a reaped/aged-out mapping, or a
    /// degraded read) — callers treat nullopt exactly like the former map's
    /// find()==end() branch: nothing to publish, not an error.
    /// NON-DESTRUCTIVE: a lookup never deletes the row. HF-1 (multi-agent
    /// fan-out): one command_id is dispatched to N agents, each sending its
    /// own response against the same command_id — deleting on the first
    /// response would strand agents 2..N with no execution_id to stamp.
    /// `degrade_reason`, when non-null, is set to "pool_exhausted" or
    /// "query_failed" iff the nullopt return is a STORE DEGRADE rather than
    /// a genuine miss (adversarial review Should-fix, PR #3780: previously
    /// indistinguishable from an ordinary out-of-band-dispatch/aged-out
    /// miss, which is the common case on every CommandResponse — a
    /// sustained pool-exhaustion degrade on this hot path had no signal
    /// pointing at it specifically). Left untouched on success or a
    /// genuine miss; callers should only inspect it when the return is
    /// nullopt.
    [[nodiscard]] std::optional<std::string>
    lookup_execution_id(const std::string& command_id, std::string* degrade_reason = nullptr) const;

    /// Clock-guarded retention sweep for the `command_execution` table
    /// (routed concern "Clock-guarded retention", CLAUDE.md). Mirrors
    /// `SessionStore::reap_expired`'s shape: an advisory lock taken as its
    /// own statement, DB `now()` read once in-SQL under that lock (so the
    /// cutoff, the anchor comparison, and the anchor update share one clock
    /// domain), a persisted+sanitised anchor, forward- and backward-anomaly
    /// decline, and an unconditional per-pass cap — copy the SHAPE, never the
    /// constants (this table's window/cap are tuned to it, not borrowed from
    /// `session_store`'s). Missing-anchor decision: PROCEED on the first pass
    /// (`ResultSetStore`'s answer, same choice `SessionStore` made) — a
    /// mapping is a regenerable observability aid, not compliance evidence,
    /// so a from-boot skewed clock deleting a batch of already-consumed
    /// mappings is an acceptable worst case.
    [[nodiscard]] std::expected<CommandExecutionReapOutcome, std::string>
    reap_command_execution_mappings();

    // ── per-device concurrency enforcement (ADR-1007) ──────────────────
    //
    // A dedicated claim table (only OPEN rows are short-lived — released
    // rows are retained indefinitely, see the no-prune comment on
    // idx_concurrency_claims_claimed_at in migrations()) — deliberately
    // NOT a reuse of
    // `agent_exec_status` (that table only gains a row when an agent's
    // FIRST RESPONSE arrives, which is too late: the whole point is
    // excluding an agent that is still mid-execution with no response yet).
    // Race-freedom comes from a Postgres partial unique index
    // (`ux_concurrency_claims_open`, see migrations()), never an app-level
    // check — see `claim_concurrency_slots`.

    /// Default/max claim TTL — one hour. The single source of truth for both
    /// the initial claim (`dispatch_scope_ladder.hpp`, which clamps any
    /// caller-supplied wire expiry into `[now, now+this]`) and each renewal
    /// (`renew_concurrency_claim`, below) — a second copy of this number in
    /// the dispatch seam is how it would drift from what the renewal
    /// actually extends by.
    static constexpr int64_t kConcurrencyClaimDefaultTtlSeconds = 3600;

    /// Attempt to claim `definition_id` on every id in `candidates`, in ONE
    /// batched round trip (never per-agent — matches this codebase's #881
    /// "one store operation per dispatch" discipline). Returns the SUBSET
    /// that won the claim (cleared to dispatch); an id NOT in the returned
    /// set either already holds an open claim for this definition, OR
    /// (Sol/Fable adversarial-review finding, PR #3784 fix round) hit the
    /// `(command_id, agent_id)` uniqueness constraint — a caller-error/
    /// entropy-collision case that should never happen but is excluded
    /// exactly the same way, fail-closed, rather than distinguished. Either
    /// way, excluded ids must be excluded from the send. Empty
    /// `command_id` is rejected outright (see body) — see
    /// `release_concurrency_claim_by_command`'s doc comment for why an
    /// empty value would otherwise be a hazard, not just a no-op. Only
    /// meaningful for `concurrency_mode == "per-device"` — callers gate on
    /// that themselves; this method does not know or care about the mode
    /// string.
    [[nodiscard]] std::vector<std::string>
    claim_concurrency_slots(const std::string& definition_id, const std::string& execution_id,
                            const std::string& command_id,
                            const std::vector<std::string>& candidates, int64_t expires_at);

    /// Release a specific (definition_id, agent_id) claim early, on a
    /// terminal per-agent outcome (called from `update_agent_status` — see
    /// its body). A best-effort UPDATE; failure is logged, not propagated —
    /// an unreleased claim still self-heals via
    /// `reconcile_stale_concurrency_claims` once past its `expires_at`.
    ///
    /// `definition_id` is REQUIRED in the WHERE clause (Gate 2 security-guardian
    /// finding, PR #3784 fix round) — `(definition_id, agent_id)` is the sole
    /// uniqueness key (`ux_concurrency_claims_open`), so two DIFFERENT
    /// definitions can each hold a genuinely open claim on the same
    /// `agent_id` simultaneously. Matching on `(execution_id, agent_id)`
    /// alone is unsafe whenever `execution_id` can collide across
    /// definitions — which it does today: every workflow-step dispatch
    /// (`workflow_routes.cpp`) passes the literal empty string as
    /// `execution_id` for EVERY definition it dispatches (CONSIST-2/sec-M2,
    /// pending real correlation), so an unscoped release for one definition
    /// could otherwise release a different, still-genuinely-running
    /// definition's open claim on the same agent.
    void release_concurrency_claim(const std::string& definition_id,
                                   const std::string& execution_id, const std::string& agent_id);

    /// Batched sibling of `release_concurrency_claim` — one store op for a
    /// whole not-sent/quarantine-denied set (`#881` discipline), matching
    /// `claim_concurrency_slots`'s own `unnest`-batched INSERT. Best-effort
    /// per row: a row this UPDATE doesn't touch (already released, or a
    /// pool/query failure) stays open and self-heals via
    /// `reconcile_stale_concurrency_claims`, same as the single-id path.
    /// No-op on an empty `agent_ids`. `definition_id` scoping: see
    /// `release_concurrency_claim`'s doc comment — identical rationale.
    void release_concurrency_claims(const std::string& definition_id,
                                    const std::string& execution_id,
                                    const std::vector<std::string>& agent_ids);

    /// Extend an open claim's `expires_at` by another `kConcurrencyClaimDefaultTtlSeconds`
    /// from now (Gate 5 chaos finding, PR #3784 fix round CHAOS-TTL-1): the
    /// reconciler cannot tell "crashed" from "legitimately still running"
    /// from `expires_at` alone once a command genuinely runs longer than one
    /// TTL window. Called from `update_agent_status` on every NON-terminal
    /// ("running") `CommandResponse` — so a claim is only ever force-released
    /// after a full TTL window with NO such response at all, not merely a
    /// long one. Best-effort, same as `release_concurrency_claim`: a missed
    /// renewal (pool exhaustion, a dropped update) does not escalate — the
    /// claim just falls back to the reconciler's existing crash-detection
    /// behaviour at its now-unextended `expires_at`.
    ///
    /// The reliable trigger for this is NOT plugin cooperation — a plugin's
    /// own output-buffer auto-flush (`CommandContextImpl::flush_output_locked`,
    /// 64KB threshold) and its `yuzu_ctx_report_progress` calls (a local
    /// no-op) both proved unable to guarantee a quiet, long-running mutating
    /// action (`script_exec.*`, operator-timeout up to 3600s) ever sends a
    /// mid-execution `running` response (CHAOS-TTL-1, Gate 5 chaos finding).
    /// The actual trigger is a dedicated agent-core keepalive thread
    /// (`agent.cpp`) that sends a periodic `RUNNING` (sentinel
    /// `__keepalive__`) for every command it still owes a terminal response
    /// for, independent of what that command's plugin does — see ADR-1007's
    /// "CLOSED (agent-core keepalive)" section.
    ///
    /// `definition_id` scoping: same rationale as `release_concurrency_claim`'s
    /// doc comment (Gate 2 security-guardian finding, PR #3784 fix round) —
    /// without it, a shared (empty-string) `execution_id` across multiple
    /// workflow-step-dispatched definitions would renew every open claim on
    /// that agent matching just `(execution_id, agent_id)`, not only the
    /// one the caller actually meant to renew.
    void renew_concurrency_claim(const std::string& definition_id,
                                 const std::string& execution_id, const std::string& agent_id);

    /// Fallback for `release_concurrency_claim` keyed on `command_id` alone
    /// (UP-1, unhappy-path Gate 4 finding, PR #3784 fix round), called by
    /// `notify_exec_tracker` whenever it cannot resolve `execution_id` via
    /// `resolve_execution_id`/`lookup_execution_id` (the PG-backed
    /// `command_execution` correlation table, HA WS-1(1b) above — this
    /// fallback predates that migration and originally covered a server
    /// restart losing the then-in-process `cmd_execution_ids_` map; that
    /// case is now the persisted table's own job and no longer needs this
    /// fallback's help). What's still genuinely unreached by the normal
    /// path: (1) every workflow-step dispatch (`workflow_routes.cpp`),
    /// whose `execution_id` is always empty (CONSIST-2/sec-M2) and which
    /// `record_execution_id` therefore never records a mapping for at all
    /// — this is the ONLY release path workflow-step per-device claims
    /// ever reach; (2) a genuine degrade on the correlation table's
    /// own write or read side (`record_command_execution`/
    /// `lookup_execution_id` returning false/nullopt under pool exhaustion
    /// or a query failure), which this fallback also transparently covers
    /// as a side effect of matching on `command_id` alone rather than
    /// needing the table to have succeeded; and (3) the correlation
    /// table's own bounded retention (`reap_command_execution_mappings`,
    /// a fixed 24h window, `kCmdExecutionReapWindowSecs`) aging a mapping
    /// out from under a command that is STILL legitimately running past
    /// that window (ADR-1007 deliberately supports unbounded "run until
    /// finished" dispatch with no wire `expires_at`) — the mapping's own
    /// reap has nothing to do with whether the command finished, so this
    /// fallback is what still lets that claim release/renew correctly once
    /// the mapping is gone.
    ///
    /// Matching on `(command_id, agent_id)` alone needs no `definition_id`
    /// scoping the way `execution_id` does: `command_id` is minted fresh
    /// per dispatch (`plugin + "-" + random_bytes(16)`, server.cpp) and is
    /// DB-enforced unique per `(command_id, agent_id)` for the row's whole
    /// lifetime (`ux_concurrency_claims_command`, see migrations()) — not
    /// merely "unlikely to collide" the way an earlier round of this fix
    /// documented it; `claim_concurrency_slots` fails a claim CLOSED
    /// (excluded from the dispatch) on a conflict rather than assuming
    /// uniqueness. A no-op (0 rows) if no open claim matches, which covers
    /// ordinary out-of-band dispatch that never took a claim in the first
    /// place.
    void release_concurrency_claim_by_command(const std::string& command_id,
                                              const std::string& agent_id);

    /// Fallback for `renew_concurrency_claim` keyed on `command_id` alone —
    /// same rationale and same three remaining cases (workflow-step,
    /// correlation-table degrade, correlation-table reap-window expiry) as
    /// `release_concurrency_claim_by_command` above, for the
    /// keepalive/`running` path instead of the terminal
    /// path. Fed by the SAME agent-core keepalive thread that drives
    /// `renew_concurrency_claim` (`agent.cpp`'s periodic `__keepalive__`,
    /// which echoes the wire `command_id` unconditionally regardless of
    /// which path resolves it). NOT a bound on how quickly a claim
    /// recovers after a LONG network outage (as opposed to a server
    /// restart, which the persisted `command_execution` table above
    /// already handles on its own): the keepalive thread waits a full
    /// interval after (re)connecting before its first ping, so a claim
    /// that has already passed its `expires_at` by the time the agent
    /// reconnects can still race the reconciler's own periodic sweep
    /// (documented residual gap, ADR-1007 — not closed by this fix; the
    /// reconciler's TTL-based self-heal is the accepted backstop for that
    /// window, same as for a genuinely crashed agent).
    void renew_concurrency_claim_by_command(const std::string& command_id,
                                            const std::string& agent_id);

    /// Clock-guarded stale-claim sweep (CLAUDE.md's seven-part discipline,
    /// via the shared `yuzu::server::audit_retention::classify` decision
    /// rule — see `audit_retention_rules.hpp`). Force-releases any open
    /// claim whose `expires_at` has passed with no terminal response (agent
    /// crashed/disconnected mid-execution, so `release_concurrency_claim`
    /// was never called). Returns the number force-released; every one is
    /// logged loudly — a claim outliving its own command's expiry is a
    /// correctness-relevant event, not routine housekeeping. `now` is
    /// threaded in by the caller so the guard logic stays unit-testable
    /// without a real clock; the persisted anchor and anomaly-fact-set
    /// dedup key are read/written internally against
    /// `execution_tracker.retention_meta` (`concurrency_last_pass_now` /
    /// `concurrency_last_anomaly_facts`) — there is no caller-supplied
    /// anchor parameter.
    int reconcile_stale_concurrency_claims(int64_t now);

    /// Clock-guarded retention sweep for the `event_outbox` table (HA WS-2a,
    /// ADR-2002 §5; routed concern "Clock-guarded retention"). Copies
    /// `reap_command_execution_mappings`' shape (with one deliberate addition —
    /// an `ORDER BY event_id` in the delete subquery makes it oldest-first
    /// deterministic) — advisory lock as its
    /// OWN statement, one in-SQL DB `now()` read reused for the
    /// cutoff/anchor-compare/anchor-update, persisted+sanitised anchor
    /// (`event_outbox_reap_anchor`), forward/backward-anomaly decline, and an
    /// unconditional per-pass cap — and makes the SAME two clock-guard
    /// carve-outs, for the SAME reasons that concern records for the
    /// command_execution sibling: (1) NO would-wipe probe — the outbox drains
    /// to 100% expiry as routine behaviour (an idle fleet legitimately ages
    /// every event past the window), so a would-wipe verdict cannot separate a
    /// true from a false positive; (4) NO fact-set anomaly dedup — a declined
    /// pass is `spdlog::warn`'d and surfaced via
    /// `yuzu_exec_outbox_reap_clock_anomaly_total` rather than deduped by fact
    /// identity. Part-(6) missing-anchor decision is PROCEED (`ResultSetStore`'s
    /// answer, matching the command_execution sibling): an outbox row is a
    /// regenerable live-update frame, not compliance evidence — the reap never
    /// touches the authoritative `executions`/`agent_exec_status` state, which a
    /// reconnecting consumer re-derives by execution_id (the
    /// `ExecutionEventBus` `kTerminalKnownLost -> fetch-by-id` fallback
    /// contract) — so a from-boot skewed clock deleting a batch of frames is an
    /// acceptable worst case. The window/cap/skew constants are kept in LOCKSTEP
    /// with the `command_execution` sibling deliberately (same short-lived feed,
    /// same substrate) — see the recorded reasoning at the definition site in the
    /// .cpp; revisit both together, do not diverge silently.
    [[nodiscard]] std::expected<EventOutboxReapOutcome, std::string> reap_event_outbox();

    /// HA WS-2a-2 (ADR-2002 §5) cross-replica event delivery — ONE poll pass.
    /// Reads the durably-SETTLED tail of `event_outbox` that ORIGINATED on OTHER
    /// replicas and re-publishes each event onto THIS replica's in-memory
    /// `ExecutionEventBus`, under its durable global `event_id` — so a live SSE
    /// subscriber on this replica sees events produced on any replica. Meant to
    /// be called on a tight cadence (~2s) from the maint thread; it is the SOLE
    /// caller, so the in-memory cursor below needs no lock.
    ///
    /// Cursor: an in-memory xid8 HORIZON (`poll_horizon_`), init'd on the first
    /// pass to the current all-committed xmin (skipping all pre-boot history — a
    /// reconnecting subscriber replays history from the durable outbox by
    /// execution_id, a SEPARATE path, not this live poll). Each pass reads
    /// `w_xid IN [horizon, xmin)` skip-own, ORDER BY (w_xid, event_id), and
    /// advances the horizon to xmin. See the DERIVATION at the definition for why
    /// the xmin horizon — not a bare `event_id` cursor nor an `(w_xid,event_id)`
    /// keyset — is the loss-free cursor (endorsed by the 2026-09-02 architect
    /// review), and why the batch cap is a hard compile-time floor.
    ///
    /// Returns the count of events re-published this pass (0 on an empty window /
    /// no bus attached / closed store / the first init pass), or `unexpected` on
    /// a pool-acquire timeout or query failure — a failure does NOT advance the
    /// horizon, so the window is re-read next pass (a duplicate, never a gap;
    /// ADR-2002 §5 is at-least-once). The caller counts a degrade metric.
    [[nodiscard]] std::expected<int, std::string> poll_event_outbox_once();

    /// Whether the store is usable (schema migrated). False after a failed
    /// migration — feeds the `/readyz` probe so a broken execution-history
    /// schema fails closed instead of serving errors (or silently wedging
    /// every execution at `dispatched`) behind a green light.
    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Alias kept for calling-code continuity across the migration —
    /// `schema_ok()` and `is_open()` mean the same thing now that there is
    /// no separate borrowed-handle-vs-migration-applied distinction to make
    /// (the SQLite era needed both: `db_ != nullptr` for "the pool is still
    /// open" and `migration_ok_` for "this store's own migration succeeded
    /// on that shared handle").
    [[nodiscard]] bool schema_ok() const noexcept { return open_; }

private:
    /// One attempt at `refresh_counts`'s aggregate recompute + conditional
    /// terminal transition + SSE publish. Returns false on a bounded-timeout
    /// abandon (row-lock contention) or a lease-acquire failure; `true`
    /// otherwise, including the ordinary "nothing changed" case. See
    /// `refresh_counts`'s retry-and-log wrapper for why this is split out.
    bool refresh_counts_once(const std::string& execution_id);

    /// One attempt at `update_agent_status`'s upsert + agent-transition SSE
    /// publish. Returns `nullopt` on a lease-acquire failure or a query
    /// failure (retry-and-log wrapper is `update_agent_status`); on success,
    /// returns the row's ACTUALLY-PERSISTED `status` from the upsert's
    /// `RETURNING` clause — which the sticky-terminal CASE may have kept
    /// unchanged even when `s.status` asked for something else (a stale
    /// `running` arriving after a real terminal write). UP-2 fix
    /// (unhappy-path Gate 4 finding, PR #3784 fix round): the caller MUST
    /// gate concurrency-claim release/renewal on this returned value, never
    /// on `s.status` directly — using the caller-supplied value let a
    /// stale, sticky-rejected `running` write still call
    /// `renew_concurrency_claim` for a command whose row was already
    /// terminal, extending a dead command's claim past when it should
    /// self-heal.
    std::optional<std::string> upsert_agent_status_once(const std::string& execution_id,
                                                         const AgentExecStatus& s);

    /// A single indexed PK lookup (`executions.id`) fetching only
    /// `definition_id`, for scoping a concurrency-claim release/renewal
    /// correctly (Gate 2 security-guardian finding, PR #3784 fix round —
    /// see `release_concurrency_claim`'s doc comment). Called on EVERY
    /// terminal transition AND every `running`/keepalive tick
    /// (`update_agent_status` uses it for both release and renew), so a
    /// long-running command under the 5-minute keepalive re-runs this once
    /// per tick — an indexed PK lookup, not per-poll load in any
    /// meaningful sense, but not a one-shot call either. Empty string on a
    /// missing row / closed store / lease failure — the caller treats that
    /// as "cannot scope, skip the release/renewal", matching every other
    /// best-effort failure mode in this class (the claim self-heals via
    /// the reconciler either way).
    std::string definition_id_for_execution(const std::string& execution_id) const;

    // HA WS-2a: the durable event_outbox append is a file-local free function
    // in execution_tracker.cpp (it needs no member state, and keeping it there
    // keeps the libpq `PGconn` type out of this header). Its contract and the
    // ID-ORDERING note for future consumers live at its definition.

    pg::PgPool& pool_;
    bool open_{false};
    /// HA WS-2a-2: this process's outbox instance identity (a boot-time random
    /// hex string). Stamped as `origin_replica` on every durable append so the
    /// cross-replica poll loop can SKIP this replica's own rows (already
    /// published in-process) and re-publish only other replicas' events. A
    /// LOCAL per-process id, deliberately NOT the cluster/node identity WS-3/WS-4
    /// will introduce (fenced leader epoch, gateway routing) — those are a
    /// broader concern and this may fold into them later. Empty only if secure
    /// RNG failed at construction (logged); an empty id disables skip-own
    /// self-exclusion, which is safe-but-chatty, never a correctness break.
    std::string replica_id_;
    /// HA WS-2a-2 cross-replica poll cursor (see poll_event_outbox_once). The
    /// maint thread is the SOLE caller, so these are single-writer and unlocked.
    /// `poll_horizon_` is an xid8 as decimal text ("" until the first pass
    /// initializes it to the boot-time all-committed xmin).
    std::string poll_horizon_;
    bool poll_initialized_{false};
    /// Borrowed — owned by the server. nullptr = no SSE publishing.
    ExecutionEventBus* event_bus_{nullptr};
    /// Borrowed — owned by the server. nullptr = no metrics (ADR-1007).
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
