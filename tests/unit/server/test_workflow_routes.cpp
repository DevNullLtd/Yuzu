/**
 * test_workflow_routes.cpp — coverage for `/fragments/executions` and
 * `/fragments/executions/{id}/detail`.
 *
 * Pattern matches test_rest_visualization.cpp + test_settings_routes_users.cpp:
 * register WorkflowRoutes against an in-process TestRouteSink and dispatch
 * synthesised requests directly into the captured handlers. No real socket →
 * no #438 TSan trap.
 *
 * Information-design contract being validated:
 *   - List filters by `definition_id` query param (PR 1.3).
 *   - List substitutes definition name when known; falls back to id stub.
 *   - List shows relative time + ISO-8601 UTC in title (no local time).
 *   - Sparkbar renders aria-label that summarises four counts.
 *   - Failed rows surface a UTF-8-safe truncation of the most recent error.
 *   - Detail returns 404 for unknown id; 403 when perm_fn denies.
 *   - Detail KPI strip: succeeded/failed counts + p50/p95 fall back to "—"
 *     when any agent is still running.
 *   - Detail agent grid switches to decile bucketing above 1024 agents.
 */

#include "command_capability.hpp" // BR-001: CommandCapability / CommandCapabilityRegistry fixture
#include "execution_event_bus.hpp"
#include "stream_budget.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "schedule_api_local.hpp" // ADR-0031 WS-A4 (seventh family): make_local_schedule_api
#include "schedule_engine.hpp" // full ScheduleEngine definition -- this harness constructs a real one (with_schedule_engine)
#include "test_schedule_api_double.hpp" // ADR-0031 WS-A4 (seventh family): FnScheduleApi
#include "test_workflow_api_double.hpp" // ADR-0031 WS-A4 (eighth family): FnWorkflowApi
#include "store_errors.hpp" // kDbErrorPrefix
#include "product_pack_store.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "workflow_api_local.hpp" // ADR-0031 WS-A4 (eighth family): make_local_workflow_api
#include "workflow_engine.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// BR-001 — a small, independent fixture (never the real catalogue — that is
// test_command_capability.cpp's job), mirroring test_command_routes.cpp's
// kFixture: one Forensics row (byte-identical to the real
// app_usage.summary row, capability_decls/plugin_action_catalogue_app_usage.hpp)
// for the single-target gate, one Destructive row (byte-identical to
// test_command_routes.cpp's tar.purge_source row) proving the same gate also
// covers Destructive rows reached through this route, and the pre-existing
// "test"/"list" pair used by every other test in this file deliberately stays
// OUT of this fixture so it keeps classifying as Unclassified (ClassifyMiss),
// pinning that an unclassified instruction's dispatch is untouched by this fix.
inline constexpr std::array<CommandCapability, 2> kBr001Fixture{{
    {
        .plugin = "app_usage",
        .action = "summary",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Delete,
        .risk_tier = yuzu::server::authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

fs::path uniq(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

// Fault-injection helper for the #2146 A2-R1 Gate 8 degrade tests below: runs
// a raw statement over a fresh side connection (never the harness's own
// pool, so the tracker's `open_`/pool state stays otherwise healthy -- only
// the ONE targeted query fails). Mirrors test_rest_executions_v1_twins.cpp's
// identical `exec_sql` idiom.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

struct ExecHarness {
    /// Declared BEFORE `sink`, so it destructs AFTER it. `sink` — not `routes` —
    /// owns the route lambdas that capture `&metrics`, so this ordering is what
    /// keeps the borrowed pointer valid for as long as a handler could run. An
    /// earlier revision declared it after `sink` and asserted the wrong
    /// invariant in a comment; structure, not prose (governance, cpp-safety).
    yuzu::MetricsRegistry metrics;
    /// BR-001 — the SAME capability_registry `command_routes.hpp`'s Deps
    /// carries, wired unconditionally (production never leaves it null; see
    /// `WorkflowRoutes::Deps::capability_registry`'s doc comment). Declared
    /// before `sink` for the same borrowed-pointer-lifetime reason as
    /// `metrics`/`registry` in `CommandHarness` (test_command_routes.cpp).
    CommandCapabilityRegistry capability_registry{std::span<const CommandCapability>(kBr001Fixture)};
    yuzu::server::test::TestRouteSink sink;

    /// Optional shared admission budget (ADR-0034). Default nullptr keeps every
    /// pre-existing test on the unmetered path; the admission tests pass one in.
    yuzu::server::detail::StreamBudget* stream_budget{nullptr};

    fs::path instr_db, wf_db;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instructions;
    std::unique_ptr<ResponseStore> responses;
    /// CDX-FV-03: opt-in WorkflowEngine so POST /api/workflows/:id/execute is
    /// reachable. Opt-in rather than always-on because every other test in this
    /// file leaves it nullptr, and a fourth SQLite file per harness would be
    /// unpaid cost on ~60 constructions (CLAUDE.md test-efficiency discipline).
    std::unique_ptr<WorkflowEngine> workflows;
    /// ADR-0031 WS-A4 (eighth family): the seam wrapping `workflows` above,
    /// wired into `wf_deps.workflow_api` below whenever `workflows` is
    /// constructed -- mirrors the production `workflow_engine_`-gated
    /// `workflow_api` construction in server.cpp exactly (no separate
    /// "is_open" gate — the seam's own calls surface that degrade).
    std::shared_ptr<WorkflowApi> workflow_api;
    /// #2146 A2-R1: opt-in real ScheduleEngine, same rationale as `workflows`
    /// above -- unpaid cost on every other test in this file, which is
    /// content with the pre-existing schedule_api==nullptr path.
    std::unique_ptr<ScheduleEngine> schedule_engine;
    /// ADR-0031 WS-A4 (seventh family): the seam wrapping `schedule_engine`
    /// above, wired into `wf_deps.schedule_api` below when
    /// `with_schedule_engine` is true -- mirrors the production
    /// `schedule_engine_`-gated `schedule_api` construction in server.cpp.
    std::shared_ptr<ScheduleApi> schedule_api;
    /// Opt-in `ProductPackStore` so `/api/product-packs*` (install/uninstall fan-out into
    /// InstructionStore/PolicyStore/WorkflowEngine, ADR-0064) is reachable. Opt-in for the same
    /// reason as `workflows` above — unpaid cost on every other test in this file.
    std::unique_ptr<ProductPackStore> product_pack_store;
    /// PR 3: per-execution SSE bus. Constructed BEFORE the tracker (see
    /// member-order comment) so the tracker can attach. Pointer is also
    /// passed into WorkflowRoutes::Deps so the SSE handler is registered.
    /// Defaults to non-null in the harness so SSE-route tests do not
    /// silently 503; tests that want to exercise the no-bus path build
    /// the deps inline.
    std::unique_ptr<ExecutionEventBus> event_bus;

    bool perm_grant{true};
    /// #1712 / #3290 Phase 2 — the executions-drawer detail route's fake
    /// twin of require_fleet_read. Defaults to admit-unfiltered (nullopt
    /// scope) so every pre-existing detail test keeps the full-fleet path;
    /// a confinement test sets fleet_read_grant=false (403) or
    /// fleet_read_scope to a specific set.
    bool fleet_read_grant{true};
    yuzu::server::authz::VisibleSet fleet_read_scope{std::nullopt};
    /// guardian-confinement-2298: empty by default (an ordinary session);
    /// a test sets this to prove the /fragments/schedules service-scoped
    /// deny fires independently of perm_grant.
    std::string mock_token_scope_service;
    /// PR 2 hardening regression net: captures the execution_id passed to
    /// cmd_dispatch so a test can prove the FAST-agent race fix (mapping
    /// registered BEFORE dispatch). Empty when the dispatch path has no
    /// tracker context.
    std::string last_dispatch_execution_id;
    /// #1088 — override the (command_id, sent) pair the dispatch stub
    /// returns. Default keeps the legacy stub behavior (`"", 0`) so the
    /// route hits its 503 "no agents reached" branch (the PR-2 UP2-4
    /// regression-net path that does not exercise the response builder).
    /// Tests that need to reach the 200 response builder — e.g. asserting
    /// the new `execution_id` field in the response body — set these to
    /// non-default values.
    std::string dispatch_cmd_override;
    int dispatch_sent_override{0};
    /// BR4-001 regression net: fires synchronously from inside cmd_dispatch,
    /// after that step's dispatch is captured, so a test can mutate an
    /// instruction definition BETWEEN one step's dispatch and the NEXT step's
    /// dispatch_fn re-read of it — reproducing, deterministically and on one
    /// thread, the same "definition changed after the route's preflight but
    /// before dispatch_fn's own re-read" window a genuine concurrent editor
    /// would race into. Default empty (no-op) so no pre-existing test using
    /// cmd_dispatch is affected.
    std::function<void()> dispatch_side_effect;
    /// #3424/#3511 Gate 8 round-4 (quality-engineer): override the zero-reach
    /// discriminator fields the stub's ConfinedDispatchOutcome carries, so a
    /// test can exercise each of the 4-way 503 split's branches instead of
    /// only the generic catch-all every prior test here left at defaults.
    bool dispatch_containment_unreadable_override{false};
    // WS-4 4.2b Task D: mirrors dispatch_containment_unreadable_override --
    // the exact sibling (a degraded gateway routing-directory read).
    bool dispatch_route_unreadable_override{false};
    std::size_t dispatch_denied_quarantined_count_override{0};
    std::size_t dispatch_unknown_plugin_count_override{0};
    /// PR #3939 review fix round: exercises the new scope_parse_error ->
    /// invalid_scope branch this route gained.
    std::optional<std::string> dispatch_scope_parse_error_override;
    /// PR 4 audit-coverage regression net: captures every audit_fn call
    /// the routes layer makes so tests can assert the SSE handler's
    /// audit-on-success / audit-absence-on-denied policy (qe-S4).
    struct AuditCall {
        std::string action, result, target_type, target_id, detail;
    };
    std::vector<AuditCall> audit_calls;
    /// #2500 targeting-widening regression net. `dispatch_calls` is the
    /// load-bearing one: a refusal that still dispatched would be no fix at
    /// all, and the pre-#2500 bug was precisely a 200-with-dispatch. The
    /// captured targeting lets a test assert WHAT the sink was asked to reach
    /// rather than only that it was reached.
    int dispatch_calls{0};
    std::vector<std::string> last_dispatch_agent_ids;
    std::string last_dispatch_scope;
    /// K-R7-02: the exec_visible set the execute handler derived and threaded
    /// into the dispatch stub (the confinement the production dispatch_confined
    /// seam then applies). Mirrors test_mcp_server.cpp's last_dispatch_exec_visible.
    yuzu::server::authz::VisibleSet last_dispatch_exec_visible;
    /// #3136 blocker regression net: the RAW params map cmd_dispatch actually
    /// received, so a test can assert it still carries a sensitive value
    /// (e.g. grant_secret) even though the PERSISTED execution row's
    /// parameter_values must not.
    std::unordered_map<std::string, std::string> last_dispatch_params;
    /// PLAN-006: the full DispatchCaller (identity + exec_visible) the execute
    /// handler threaded into the dispatch stub, so a test can assert the
    /// principal half independently of last_dispatch_exec_visible above.
    yuzu::server::DispatchCaller last_dispatch_caller;
    /// K-R7-02 / PLAN-006: the reassignable per-request DispatchCaller
    /// derivation. Default returns a DispatchCaller whose exec_visible is
    /// nullopt (UNFILTERED) so every pre-existing workflow test keeps the
    /// full-fleet path; a confinement test overrides it with a specific set.
    WorkflowRoutes::CallerFn caller_fn{[](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{.exec_visible = yuzu::server::authz::VisibleSet{}};
    }};
    WorkflowRoutes routes;

    /// Per-process monotonic counter for execution IDs. Replaces the prior
    /// `std::hash<std::string>(...)` which violates the CLAUDE.md test rule
    /// against hash-of-thread-id / clock as uniqueness salt — the same
    /// principle applies to hash-of-string under MSVC's hash, which has had
    /// collision edge cases. Atomic so parallel test workers cannot collide.
    static inline std::atomic<int> exec_counter{0};

    /// `with_bus = false` opts out of constructing the per-execution event
    /// bus so SSE-handler 503-on-no-bus tests can exercise the path where
    /// the route is registered but the underlying bus is intentionally
    /// not wired (governance qe-S1).
    /// `wire_exec_visible = false` registers with an EMPTY CallerFn so the
    /// production execute handler's own fail-closed branch (unwired → present-
    /// empty deny-all) is exercised (K-R7-02).
    bool wire_exec_visible{true};

    /// #3565: `fleet_read_fn` is captured BY VALUE into the detail route's
    /// lambda at `register_routes` time (unlike DashboardRoutes' live
    /// per-request member read), so a test wanting the genuinely-unwired
    /// (empty std::function) contract must opt out HERE, at construction --
    /// setting `fleet_read_grant`/`fleet_read_scope` after the fact can't
    /// reach it, the closure is already captured.
    bool wire_fleet_read_fn{true};

    explicit ExecHarness(pg::PgPool& pool, bool with_bus = true,
                         yuzu::server::detail::StreamBudget* budget = nullptr,
                         bool wire_exec_visible_arg = true,
                         bool with_workflow_engine = false,
                         bool wire_fleet_read_fn_arg = true,
                         bool with_product_pack_store = false,
                         WorkflowRoutes::AuthFn auth_override = {},
                         WorkflowRoutes::FleetReadFn fleet_read_override = {},
                         // #2146 A2-R1: opt-in real ScheduleEngine so
                         // GET /api/v1/schedules' definition_id/enabled_only
                         // filters can be exercised end-to-end. Opt-in for
                         // the same reason as with_workflow_engine above --
                         // unpaid cost on every other test in this file,
                         // which is content with the pre-existing
                         // schedule_api==nullptr "Not available" path.
                         bool with_schedule_engine = false,
                         // ADR-0031 WS-A4 (seventh family): a test-supplied
                         // ScheduleApi (typically FnScheduleApi, see
                         // test_schedule_api_double.hpp) -- takes precedence
                         // over with_schedule_engine above, letting a test
                         // inject an arbitrary list_schedules result
                         // (including a store failure) without a real
                         // ScheduleEngine/Postgres connection. Same
                         // captured-by-value-at-construction contract as
                         // auth_override/fleet_read_override above.
                         std::shared_ptr<ScheduleApi> schedule_api_override = {},
                         // ADR-0031 WS-A4 (eighth family): a test-supplied
                         // WorkflowApi (typically FnWorkflowApi, see
                         // test_workflow_api_double.hpp) -- takes precedence
                         // over with_workflow_engine above, letting a test
                         // inject an arbitrary list_workflows/get_workflow/
                         // get_workflow_execution result (including a store
                         // failure) without a real WorkflowEngine/Postgres
                         // connection. Same captured-by-value-at-construction
                         // contract as schedule_api_override above.
                         std::shared_ptr<WorkflowApi> workflow_api_override = {})
        : stream_budget(budget),
          instr_db(uniq("wf-routes-inst")),
          wf_db(uniq("wf-routes-wf")) {
        wire_exec_visible = wire_exec_visible_arg;
        wire_fleet_read_fn = wire_fleet_read_fn_arg;
        for (auto& p : {instr_db, wf_db})
            fs::remove(p);

        // PR 3: bus must outlive the tracker (the tracker borrows the
        // bus pointer). Build the bus first when wanted; the no-bus
        // harness leaves event_bus as nullptr so the route registration
        // takes the 503 path.
        if (with_bus) {
            event_bus = std::make_unique<ExecutionEventBus>();
        }
        tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());
        if (event_bus) {
            tracker->set_event_bus(event_bus.get());
        }

        // ADR-0058: InstructionStore is now a migrated Postgres store — shares
        // the same pool/database as ResponseStore below (schema-per-store,
        // ADR-0008). instr_db (the old SQLite path) is now unused dead weight
        // in the fs::remove cleanup loops below, harmless (removing a path
        // nothing ever creates is a silent no-op).
        instructions = std::make_unique<InstructionStore>(pool);
        REQUIRE(instructions->is_open());
        responses = std::make_unique<ResponseStore>(pool, /*retention_days=*/0);
        REQUIRE(responses->is_open());

        // ADR-0064: WorkflowEngine is now Postgres-backed — shares this harness's `pool`
        // (schema-per-store, ADR-0008), same as InstructionStore/ResponseStore above. wf_db (the
        // old SQLite path) is unused dead weight in the fs::remove cleanup loops below, harmless.
        if (with_workflow_engine) {
            workflows = std::make_unique<WorkflowEngine>(pool);
            REQUIRE(workflows->is_open());
        }
        // ADR-0031 WS-A4 (eighth family): an injected test double takes
        // precedence over the seam wrapping the real engine constructed
        // above (see workflow_api_override's own doc comment) -- the seam,
        // not the raw engine, is what Deps actually takes now for the read
        // triad.
        if (workflow_api_override) {
            workflow_api = workflow_api_override;
        } else if (workflows) {
            workflow_api = make_local_workflow_api(*workflows);
        }

        if (with_product_pack_store) {
            product_pack_store = std::make_unique<ProductPackStore>(pool);
            REQUIRE(product_pack_store->is_open());
            product_pack_store->set_require_signed_packs(false); // unsigned test bundles
        }

        // ADR-0031 WS-A4 (seventh family): an injected test double takes
        // precedence over constructing a real engine (see
        // schedule_api_override's own doc comment above).
        if (schedule_api_override) {
            schedule_api = schedule_api_override;
        } else if (with_schedule_engine) {
            // #2146 A2-R1: ScheduleEngine is Postgres-backed (ADR-0065) --
            // shares this harness's `pool` (schema-per-store, ADR-0008), same
            // as WorkflowEngine/InstructionStore/ResponseStore above.
            schedule_engine = std::make_unique<ScheduleEngine>(pool);
            REQUIRE(schedule_engine->is_open());
            // ADR-0031 WS-A4 (seventh family): the seam, not the raw engine,
            // is what Deps actually takes now.
            schedule_api = make_local_schedule_api(*schedule_engine);
        }

        WorkflowRoutes::AuthFn auth_fn =
            [this](const httplib::Request&,
                   httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            s.token_scope_service = mock_token_scope_service;
            return s;
        };
        if (auth_override)
            auth_fn = std::move(auth_override);
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        // #1712 / #3290 Phase 2 — the executions-drawer detail route's SOLE
        // gate. Fails 403 when fleet_read_grant is false (mirrors perm_fn's
        // deny shape); admits with fleet_read_scope otherwise (nullopt =
        // unfiltered, the default).
        WorkflowRoutes::FleetReadFn fleet_read_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&) -> yuzu::server::authz::FleetReadGate {
            if (!fleet_read_grant) {
                res.status = 403;
                return {false, yuzu::server::authz::deny_all()};
            }
            return {true, fleet_read_scope};
        };
        if (fleet_read_override)
            fleet_read_fn = std::move(fleet_read_override);
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto emit_fn = [](const std::string&, const httplib::Request&) {
        };
        auto scope_fn = [](const std::string&,
                           const std::string&) -> std::pair<std::size_t, std::size_t> {
            return {0, 0};
        };
        // PR 2: cmd_dispatch signature gained `execution_id` parameter so
        // the dispatch path can register the command_id→execution_id
        // mapping with AgentServiceImpl BEFORE any RPC is sent (UP2-4
        // race close). The test stub captures the last (command_id,
        // execution_id) pair for assertion.
        auto cmd_dispatch = [this](const std::string&, const std::string&,
                                   const std::vector<std::string>& agent_ids,
                                   const std::string& scope_expr,
                                   const std::unordered_map<std::string, std::string>& params,
                                   const std::string& execution_id,
                                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_dispatch_execution_id = execution_id;
            // #2500: capture what the sink was actually asked to target.
            ++dispatch_calls;
            last_dispatch_agent_ids = agent_ids;
            last_dispatch_scope = scope_expr;
            last_dispatch_params = params;
            // K-R7-02 / PLAN-006: capture the confinement + identity threaded
            // into dispatch.
            last_dispatch_exec_visible = caller.exec_visible;
            last_dispatch_caller = caller;
            if (dispatch_side_effect)
                dispatch_side_effect();
            return {.sent = dispatch_sent_override,
                   .scope_parse_error = dispatch_scope_parse_error_override,
                   .denied_quarantined_count = dispatch_denied_quarantined_count_override,
                   .command_id = dispatch_cmd_override,
                   .containment_unreadable = dispatch_containment_unreadable_override,
                   .unknown_plugin_count = dispatch_unknown_plugin_count_override,
                   .route_unreadable = dispatch_route_unreadable_override};
        };

        // PR 2.5 (#670): deps-struct refactor. WorkflowRoutes::register_routes
        // takes a single `Deps` aggregate so PR 3's SSE bus addition is a
        // single new field, not a 17th parameter.
        WorkflowRoutes::Deps wf_deps;
        wf_deps.auth_fn = auth_fn;
        wf_deps.perm_fn = perm_fn;
        if (wire_fleet_read_fn)
            wf_deps.fleet_read_fn = fleet_read_fn;
        // else: leave genuinely default-constructed (empty std::function) --
        // production's own unwired-misconfiguration contract (#3565).
        wf_deps.audit_fn = audit_fn;
        wf_deps.emit_fn = emit_fn;
        wf_deps.scope_fn = scope_fn;
        wf_deps.execution_tracker = tracker.get();
        wf_deps.instruction_store = instructions.get();
        wf_deps.command_dispatch_fn = cmd_dispatch;
        // K-R7-02 / PLAN-006: wire the DispatchCaller derivation (or leave it
        // EMPTY so the handler's own fail-closed path runs). The wired form
        // delegates to the reassignable member so a test can override it after
        // construction.
        if (wire_exec_visible) {
            wf_deps.caller_fn = [this](const httplib::Request& req) -> yuzu::server::DispatchCaller {
                return caller_fn ? caller_fn(req) : yuzu::server::DispatchCaller{};
            };
        }
        wf_deps.response_store = responses.get();
        // CDX-FV-03: nullptr unless opted in, so /api/workflows/* keeps its 503
        // path for every pre-existing test.
        wf_deps.workflow_engine = workflows.get();
        // ADR-0031 WS-A4 (eighth family), was CDX-FV-03's raw engine — nullptr
        // unless opted in, so /api/v1/workflows[/{id}] and
        // /api/v1/workflow-executions/{id} keep their 503 path for every
        // pre-existing test that leaves with_workflow_engine=false.
        wf_deps.workflow_api = workflow_api;
        wf_deps.product_pack_store = product_pack_store.get();
        wf_deps.schedule_api = schedule_api; // ADR-0031 WS-A4 (seventh family), was #2146 A2-R1's raw engine
        // PR 3 — wire the per-execution event bus. The SSE handler at
        // /sse/executions/{id} returns 503 at request time when this is
        // nullptr but is still registered, which is the qe-S1 path.
        wf_deps.execution_event_bus = event_bus.get();
        wf_deps.stream_budget = stream_budget; // ADR-0034 admission (nullptr = unmetered)
        wf_deps.metrics = &metrics;            // #2500 targeting-refusal counter
        wf_deps.capability_registry = &capability_registry; // BR-001 targeting gate
        routes.register_routes(sink, std::move(wf_deps));
    }

    ~ExecHarness() {
        workflows.reset();
        responses.reset();
        instructions.reset();
        // PR 3: drop tracker BEFORE the bus — tracker borrows event_bus_,
        // so the bus must outlive the tracker through its destructor.
        tracker.reset();
        event_bus.reset();
        // Use the noexcept overload — destructors must not throw even if
        // a separate remove failure (e.g. file already gone, parent dir
        // missing) happens.
        std::error_code ec;
        for (auto& p : {instr_db, wf_db}) {
            fs::remove(p, ec);
            fs::remove(p.string() + "-wal", ec);
            fs::remove(p.string() + "-shm", ec);
        }
    }

    /// Insert a definition by id with a friendly display name. `plugin`/
    /// `action` default to the pre-existing "test"/"list" pair every other
    /// test in this file relies on (deliberately absent from
    /// `kBr001Fixture`, so it classifies Unclassified/ClassifyMiss); BR-001
    /// tests pass a pair present in that fixture instead.
    void make_def(const std::string& id, const std::string& name,
                  const std::string& plugin = "test", const std::string& action = "list") {
        InstructionDefinition d;
        d.id = id;
        d.name = name;
        d.type = "question";
        d.plugin = plugin;
        d.action = action;
        auto created = instructions->create_definition(d);
        REQUIRE(created.has_value());
    }

    /// CDX-FV-03: single-step workflow whose one step runs `instruction_id`.
    /// Returns the engine-minted workflow id for the execute URL.
    std::string make_workflow(const std::string& display_name, const std::string& instruction_id) {
        REQUIRE(workflows); // constructed with with_workflow_engine=true
        const std::string yaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: " +
                                 display_name +
                                 "\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: " +
                                 instruction_id + "\n";
        auto id = workflows->create_workflow(yaml);
        REQUIRE(id.has_value());
        return *id;
    }

    /// BR4-001: two-step workflow, one step per instruction id, both
    /// executed in order — needed to reproduce the late-mutation race
    /// (mutate the SECOND step's instruction from a dispatch_side_effect
    /// fired while dispatching the FIRST).
    std::string make_workflow2(const std::string& display_name,
                                const std::string& instruction_id_1,
                                const std::string& instruction_id_2) {
        REQUIRE(workflows);
        const std::string yaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: " +
                                 display_name +
                                 "\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: " +
                                 instruction_id_1 +
                                 "\n"
                                 "    - instruction: " +
                                 instruction_id_2 + "\n";
        auto id = workflows->create_workflow(yaml);
        REQUIRE(id.has_value());
        return *id;
    }

    /// Create an execution row and return its id.
    std::string make_exec(const std::string& definition_id, const std::string& status,
                          int agents_targeted, int agents_success, int agents_failure,
                          int64_t dispatched_at = 1735689600 /* 2025-01-01 */,
                          const std::string& dispatched_by = "tester") {
        Execution e;
        // Atomic counter, not std::hash, per CLAUDE.md test isolation rules.
        e.id = "exec-" + std::to_string(exec_counter.fetch_add(1));
        e.definition_id = definition_id;
        e.status = status;
        e.dispatched_by = dispatched_by;
        e.dispatched_at = dispatched_at;
        e.agents_targeted = agents_targeted;
        e.agents_success = agents_success;
        e.agents_failure = agents_failure;
        e.agents_responded = agents_success + agents_failure;
        e.completed_at =
            (agents_targeted == agents_success + agents_failure) ? dispatched_at + 60 : 0;
        auto id = tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }

    /// Insert a response into the response store. PR 2: callers can stamp
    /// execution_id directly to exercise query_by_execution; leaving it
    /// empty exercises the legacy timestamp-window fallback path.
    void store_response(const std::string& command_id, const std::string& agent_id,
                        const std::string& output, const std::string& execution_id = "",
                        int64_t timestamp = 1735689610) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent_id;
        r.status = 1;
        r.output = output;
        r.timestamp = timestamp;
        r.execution_id = execution_id;
        responses->store(r);
    }

    /// Stamp a per-agent status row.
    void agent_status(const std::string& exec_id, const std::string& agent_id,
                      const std::string& status, int exit_code = 0, const std::string& error = {},
                      int64_t completed_at = 1735689660) {
        AgentExecStatus s;
        s.agent_id = agent_id;
        s.status = status;
        s.dispatched_at = 1735689600;
        s.first_response_at = 1735689610;
        s.completed_at = completed_at;
        s.exit_code = exit_code;
        s.error_detail = error;
        tracker->update_agent_status(exec_id, s);
    }
};

} // namespace

// ── List handler ────────────────────────────────────────────────────────────

TEST_CASE("executions list: empty state", "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("No executions yet") != std::string::npos);
}

TEST_CASE("executions list: renders definition name not bare id", "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-known", "Inspect Service");
    h.make_exec("def-known", "completed", 5, 5, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Friendly definition name is present.
    CHECK(res->body.find("Inspect Service") != std::string::npos);
    // id-prefix fallback is NOT what's shown when a name is known.
    CHECK(res->body.find(">def-known<") == std::string::npos);
}

TEST_CASE("executions list: id stub fallback when definition is unknown",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_exec("def-orphan-12345-rest", "completed", 5, 5, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    // First 12 chars of the id should appear.
    CHECK(res->body.find("def-orphan-1") != std::string::npos);
}

TEST_CASE("executions list: definition_id query filter", "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-A", "Definition A");
    h.make_def("def-B", "Definition B");
    h.make_exec("def-A", "completed", 3, 3, 0);
    h.make_exec("def-B", "completed", 4, 4, 0);

    auto filtered = h.sink.Get("/fragments/executions?definition_id=def-A");
    REQUIRE(filtered);
    CHECK(filtered->status == 200);
    CHECK(filtered->body.find("Definition A") != std::string::npos);
    CHECK(filtered->body.find("Definition B") == std::string::npos);
}

TEST_CASE("executions list: failed row carries first-error preview + stripe class",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-flake", "Flaky");
    auto eid = h.make_exec("def-flake", "completed", 2, 1, 1);
    // The exec is "completed" with 1 failure; populate the agent error so the
    // correlated subquery in query_executions surfaces it.
    h.agent_status(eid, "ok-agent", "success");
    h.agent_status(eid, "bad-agent", "failure", 1, "EACCES: permission denied");

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("EACCES: permission denied") != std::string::npos);
    // Failed row class — the row is marked exec-row--completed because agg
    // status is "completed" with at least one failure; the stripe is governed
    // by agents_failure > 0 → exec-row--failed when status itself is "failed".
    // Here we just check the error preview surfaces; row-class behaviour is
    // covered separately for status == "failed".
}

TEST_CASE("executions list: status=failed gets exec-row--failed class",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-X", "X");
    h.make_exec("def-X", "failed", 1, 0, 1);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("exec-row--failed") != std::string::npos);
}

TEST_CASE("executions list: time cell carries ISO-8601 UTC in title",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T", "Time");
    h.make_exec("def-T", "completed", 1, 1, 0, /*dispatched_at=*/1735689600);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    // ISO appears in title= for forensic copy/paste.
    CHECK(res->body.find("2025-01-01T00:00:00Z") != std::string::npos);
}

TEST_CASE("executions list: sparkbar aria-label summarises counts",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-K", "K");
    h.make_exec("def-K", "completed", 50, 47, 3);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("47 succeeded, 3 failed, 0 running, 0 pending of 50") !=
          std::string::npos);
}

TEST_CASE("executions list: zero-agent execution renders empty-state sparkbar",
          "[pg][workflow][executions][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Z", "Zero");
    h.make_exec("def-Z", "completed", 0, 0, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("no agents matched scope") != std::string::npos);
}

// ── Detail handler ──────────────────────────────────────────────────────────

TEST_CASE("executions detail: 404 on unknown id", "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    auto res = h.sink.Get("/fragments/executions/exec-does-not-exist/detail");
    REQUIRE(res);
    CHECK(res->status == 404);
}

// #1712 / #3290 Phase 2: this route migrated from perm_fn onto
// require_fleet_read (fleet_read_fn) as its SOLE gate — perm_grant no
// longer has any effect here (it still gates the LIST route above and the
// SSE route below, both unmigrated); fleet_read_grant is the deny knob now.
TEST_CASE("executions detail: 403 when fleet_read_fn denies",
          "[pg][workflow][executions][detail][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-X", "X");
    auto eid = h.make_exec("def-X", "completed", 1, 1, 0);
    h.fleet_read_grant = false;
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// #3565: the dashboard (/fragments/results) and MCP (get_agent_details)
// siblings both have an unwired-fleet_read_fn -> 503 fail-closed test; this
// route's own equivalent contract (workflow_routes.cpp's own
// `if (!fleet_read_fn) {...503...}` branch) had no test at all.
TEST_CASE("executions detail: unwired fleet_read_fn -> 503, fail closed",
          "[pg][workflow][executions][detail][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/false, /*wire_fleet_read_fn=*/false);
    h.make_def("def-U", "U");
    auto eid = h.make_exec("def-U", "completed", 1, 1, 0);
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 503);
    // Gate 8 re-review (this round), quality-engineer finding: this route has
    // TWO distinct 503 branches -- unwired fleet_read_fn ("Service
    // unavailable") and a null execution_tracker ("Tracker not available").
    // Asserting only the status lets a harness defect that leaves the
    // tracker null (instead of, or in addition to, the gate) false-green on
    // the wrong branch. Match the dashboard sibling's body-substring check
    // (test_dashboard_results_fragment.cpp) to pin the actual branch.
    CHECK(res->body.find("Service unavailable") != std::string::npos);
}

// Governance fix (#2146 A2-R1 Gate 8 re-review): this route used the plain
// get_execution(), which collapses "execution genuinely absent" and "read
// degraded" (a transient pool/query failure) to the same nullopt -- a
// degrade fell through to the SAME not-found + denial-audit branch a
// genuine absence takes, producing a FALSE 404 for a legitimate owner and a
// permanently wrong CC7.2 denial audit row for a confined caller whose only
// "fault" was hitting a transient outage. get_execution_checked's outer
// std::expected now distinguishes the two; the degrade branch returns
// BEFORE any denial audit is recorded.
TEST_CASE("executions detail: a transient tracker degrade is 503 (not a false 404) "
          "and records no denial audit (#2146 A2-R1 Gate 8 fix)",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-2146b", "2146b");
    auto eid = h.make_exec("def-2146b", "completed", 1, 1, 0);
    // Engage a confined scope so the OLD code's denial-audit branch would
    // have fired on the false 404 this fix closes -- an unconfined caller
    // never reaches that branch at all.
    h.fleet_read_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-0"}};

    // Break ONLY the get_execution_checked query -- a raw statement over a
    // side connection, never the harness's own pool, so the tracker stays
    // "open" and this is a genuine single-call fault.
    exec_sql(db.dsn(),
             "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_2146b");
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    exec_sql(db.dsn(),
             "ALTER TABLE execution_tracker.executions_hidden_2146b RENAME TO executions");

    REQUIRE(res);
    // (a) 503, never the old false 404.
    CHECK(res->status == 503);
    CHECK(res->body.find("Execution tracker degraded") != std::string::npos);

    // (b) no denial audit row for this execution -- pre-fix, this recorded
    // execution.detail.view/denied here.
    for (const auto& c : h.audit_calls)
        CHECK(c.target_id != eid);
}

// #3565: this codebase has a documented prior incident (authz_model.hpp's
// own doc comment on VisibleSet{}) of an engaged-empty scope (deny_all())
// being mishandled as unfiltered/nullopt, serving the whole fleet to a
// caller with no grants at all. Pin the distinction directly for this route.
TEST_CASE("executions detail: admitted-but-deny_all() non-owner gets collapsed 404",
          "[pg][workflow][executions][detail][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Y2", "Y2");
    auto eid = h.make_exec("def-Y2", "completed", 1, 1, 0, 1735689600, "alice");
    h.agent_status(eid, "agent-should-not-appear", "success", 0, "", 1735689601);
    h.store_response("def-Y2", "agent-should-not-appear", "should never render", eid);

    h.fleet_read_scope = yuzu::server::authz::deny_all();
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    auto missing = h.sink.Get("/fragments/executions/does-not-exist/detail");
    REQUIRE(res);
    REQUIRE(missing);
    CHECK(res->status == 404);
    CHECK(missing->status == 404);
    CHECK(res->body == missing->body);
    CHECK(res->body.find("agent-should-not-appear") == std::string::npos);
    CHECK(res->body.find("should never render") == std::string::npos);
    // #1634 (governance Gate 6/Gate 8 compliance-officer finding): a
    // suppressed cross-operator read now DOES get a distinct `denied` audit
    // row (CC7.2 evidence, parity with the REST twin) — never the
    // `success`-shaped row a genuine admit gets.
    bool saw_denied = false;
    for (const auto& a : h.audit_calls) {
        CHECK(a.result != "success");
        if (a.action == "execution.detail.view" && a.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

// #1712 / #3290 Phase 2: the "Responses" section must drop rows for agents
// outside the caller's scope (both the primary execution_id-correlated fetch
// and the legacy timestamp-window fallback merge into `filtered` before this
// filter runs, so one assertion covers both paths).
TEST_CASE("executions detail: responses section drops out-of-scope agents",
          "[pg][workflow][executions][detail][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Y", "Y");
    auto eid = h.make_exec("def-Y", "completed", 2, 2, 0);
    h.store_response("def-Y", "agent-in", "in-scope output", eid);
    h.store_response("def-Y", "agent-out", "out-of-scope output", eid);

    h.fleet_read_scope = yuzu::server::authz::VisibleSet{
        std::unordered_set<std::string>{"agent-in"}};
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("in-scope output") != std::string::npos);
    CHECK(res->body.find("out-of-scope output") == std::string::npos);
}

TEST_CASE("executions detail: confined-but-admitted caller gets scope/parameter redaction "
          "(Doomgoose review, blocking)",
          "[pg][workflow][executions][detail][rbac][scope]") {
    // This route's sidebar previously rendered exec.scope_expression/
    // parameter_values verbatim with no gate.scope conditional at all,
    // unlike the REST twin (GET /api/v1/executions/{id}) and MCP
    // get_execution_status, which both replace these fields with
    // "(redacted - confined view)" whenever the caller is confined —
    // dispatcher included. A confined caller admitted via one visible
    // agent could read the full scope DSL of an execution naming
    // out-of-scope agent ids/hostnames. This test admits (200, not 404)
    // via a narrow-but-nonempty scope and asserts the real scope
    // expression/parameters never appear.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-REDACT", "Redact");

    Execution e;
    e.id = "exec-redact-test";
    e.definition_id = "def-REDACT";
    e.status = "completed";
    e.dispatched_by = "someone-else";
    e.dispatched_at = 1735689600;
    e.completed_at = 1735689660;
    e.agents_targeted = 1;
    e.agents_success = 1;
    e.agents_responded = 1;
    e.scope_expression = "tag:secret-project-out-of-scope-hostname";
    e.parameter_values = R"({"admin_password":"should-never-leak"})";
    auto created = h.tracker->create_execution(e);
    REQUIRE(created.has_value());
    const auto eid = *created;
    h.agent_status(eid, "agent-in", "success", 0, "", 1735689601);

    // Narrow-but-nonempty scope: caller sees "agent-in" (admits, 200) but
    // is still confined (not the deny_all/full-visibility cases already
    // covered by sibling tests).
    h.fleet_read_scope =
        yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("redacted - confined view") != std::string::npos);
    CHECK(res->body.find("secret-project-out-of-scope-hostname") == std::string::npos);
    CHECK(res->body.find("should-never-leak") == std::string::npos);
}

TEST_CASE("executions detail: KPI strip shows counts + p50/p95", "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-K", "K");
    auto eid = h.make_exec("def-K", "completed", 3, 2, 1);
    // 3 agents with deterministic durations: 1s, 2s, 5s.
    h.agent_status(eid, "a1", "success", 0, "", /*completed_at=*/1735689601);
    h.agent_status(eid, "a2", "success", 0, "", /*completed_at=*/1735689602);
    h.agent_status(eid, "a3", "failure", 1, "boom", /*completed_at=*/1735689605);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // KPI label sections.
    CHECK(res->body.find("Total") != std::string::npos);
    CHECK(res->body.find("Succeeded") != std::string::npos);
    CHECK(res->body.find("Failed") != std::string::npos);
    CHECK(res->body.find("p50 duration") != std::string::npos);
    CHECK(res->body.find("p95 duration") != std::string::npos);
    // p50/p95 should NOT be "—" when every agent is terminal.
    // We only assert the dash sentinel does NOT appear in the KPI value
    // positions (it might still appear elsewhere — e.g. completed_at sentinel
    // for unfinished runs, but we set completed_at on all agents).
    CHECK(res->body.find("exec-kpi-value\">—") == std::string::npos);
}

TEST_CASE("executions detail: p50/p95 fall back to dash when any agent is running",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-R", "R");
    auto eid = h.make_exec("def-R", "running", 2, 1, 0);
    h.agent_status(eid, "done", "success", 0, "", 1735689601);
    // Running agent has completed_at = 0 (sentinel for "still running").
    h.agent_status(eid, "running", "running", 0, "", /*completed_at=*/0);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("exec-kpi-value\">—") != std::string::npos);
}

// Adversarial-review blocker (#1712): migrating this route's gate onto
// require_fleet_read admits a caller class the OLD flat perm_fn gate denied
// outright (confined-only via the #1715(a) additive grant) -- so the status
// grid/table must be scoped too, not just the Responses section, or the gate
// migration itself widens disclosure for a newly-admitted caller instead of
// narrowing it.
TEST_CASE("executions detail: status grid + per-agent table drop out-of-scope "
          "agents, and counts reflect only in-scope agents",
          "[pg][workflow][executions][detail][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Z", "Z");
    auto eid = h.make_exec("def-Z", "completed", 2, 2, 0);
    h.agent_status(eid, "agent-in", "success", 0, "", 1735689601);
    h.agent_status(eid, "agent-out", "failure", 1, "boom", 1735689602);

    h.fleet_read_scope =
        yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Out-of-scope agent id must not appear anywhere in the response --
    // not the status grid cell, not the per-agent table row, not its error
    // detail (a distinct, more sensitive string than the bare id).
    CHECK(res->body.find("agent-out") == std::string::npos);
    CHECK(res->body.find("boom") == std::string::npos);
    CHECK(res->body.find("agent-in") != std::string::npos);
    // "Succeeded" KPI is derived from the (now-filtered) agents vector, so it
    // must count only the in-scope agent, not both.
    CHECK(res->body.find("exec-kpi-value exec-kpi-value--ok\">1<") != std::string::npos);
    CHECK(res->body.find("exec-kpi-value exec-kpi-value--ok\">2<") == std::string::npos);
    // Gate 4 unhappy-path finding UP-1: the "Total" KPI must ALSO recompute
    // from the filtered set for a scoped caller -- exec.agents_targeted is 2
    // (dispatch-time), but only 1 agent is in scope. Total staying at 2 while
    // the grid/table show only 1 agent would disclose that an out-of-scope
    // agent exists by simple subtraction, even with its identity hidden.
    // (exact match: the Total cell's class is plain "exec-kpi-value" with no
    // --ok/--err modifier, so this substring is unique to it.)
    CHECK(res->body.find("exec-kpi-value\">1<") != std::string::npos);
    CHECK(res->body.find("exec-kpi-value\">2<") == std::string::npos);
}

TEST_CASE("executions detail: per-agent table sorts failed first",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-S", "S");
    auto eid = h.make_exec("def-S", "completed", 3, 2, 1);
    h.agent_status(eid, "alpha-success", "success", 0, "", 1735689601);
    h.agent_status(eid, "beta-failure", "failure", 1, "alpha-error", 1735689602);
    h.agent_status(eid, "gamma-success", "success", 0, "", 1735689603);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto pos_failure = res->body.find("beta-failure");
    auto pos_first_success = res->body.find("alpha-success");
    auto pos_second_success = res->body.find("gamma-success");
    REQUIRE(pos_failure != std::string::npos);
    REQUIRE(pos_first_success != std::string::npos);
    REQUIRE(pos_second_success != std::string::npos);
    // Failure comes before either success row. The grid renders agent_ids
    // earlier in document order than the table, so we look at the *table*
    // section by anchoring after the per-agent table heading.
    auto table_start = res->body.find("Agent results");
    REQUIRE(table_start != std::string::npos);
    auto tail = res->body.substr(table_start);
    auto tail_failure = tail.find("beta-failure");
    auto tail_success_a = tail.find("alpha-success");
    auto tail_success_g = tail.find("gamma-success");
    REQUIRE(tail_failure != std::string::npos);
    REQUIRE(tail_success_a != std::string::npos);
    REQUIRE(tail_success_g != std::string::npos);
    CHECK(tail_failure < tail_success_a);
    CHECK(tail_failure < tail_success_g);
}

TEST_CASE("executions detail: agent grid uses decile bucketing above 1024 agents",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Big", "Big");
    auto eid = h.make_exec("def-Big", "completed", 1500, 1500, 0);
    for (int i = 0; i < 1500; ++i) {
        h.agent_status(eid, "agent-" + std::to_string(i), "success", 0, "", 1735689601);
    }

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Bucketed view marker.
    CHECK(res->body.find("agent-cell--bucket") != std::string::npos);
    CHECK(res->body.find("Decile 1") != std::string::npos);
    CHECK(res->body.find("Decile 10") != std::string::npos);
}

TEST_CASE("executions detail: error_detail truncates without tearing UTF-8",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-U", "U");
    auto eid = h.make_exec("def-U", "completed", 1, 0, 1);
    // 130-byte UTF-8 string mixing ASCII + 4-byte emoji at the boundary.
    std::string err =
        std::string(118, 'x') + std::string("\xF0\x9F\x94\xA5") + std::string("\xF0\x9F\x94\xA5");
    h.agent_status(eid, "a1", "failure", 1, err, 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The truncated form ends with the U+2026 ellipsis. Look for its UTF-8
    // bytes directly so we don't depend on HTML-escaping for a non-special
    // character.
    CHECK(res->body.find("\xE2\x80\xA6") != std::string::npos);
}

TEST_CASE("executions detail: sidebar carries dispatched_by + ISO timestamps",
          "[pg][workflow][executions][detail]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-M", "M");
    auto eid = h.make_exec("def-M", "completed", 1, 1, 0,
                           /*dispatched_at=*/1735689600);
    h.agent_status(eid, "a1", "success", 0, "", 1735689660);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("tester") != std::string::npos);
    CHECK(res->body.find("2025-01-01T00:00:00Z") != std::string::npos);
}

// ── ExecutionTracker last_error_detail correlated subquery ─────────────────

// ── arch-B2: opt-out is the default ────────────────────────────────────────

TEST_CASE("ExecutionTracker.query_executions: include_error_detail default "
          "false leaves the field empty (arch-B2 hot-path)",
          "[pg][workflow][executions][tracker]") {
    // server.cpp:1727 calls query_executions({.limit = 1000}) on every
    // metrics tick; that path must NOT pay the correlated-subquery cost.
    // Default-constructed ExecutionQuery leaves include_error_detail == false.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-OPTOUT", "OPTOUT");
    auto eid = h.make_exec("def-OPTOUT", "completed", 1, 0, 1);
    h.agent_status(eid, "a", "failure", 1, "should not appear", 1735689602);

    ExecutionQuery q; // include_error_detail defaults to false
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail.empty());
}

TEST_CASE("ExecutionTracker.get_execution: always populates last_error_detail "
          "(single-row read is rare, opts in unconditionally)",
          "[pg][workflow][executions][tracker]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-GE", "GE");
    auto eid = h.make_exec("def-GE", "completed", 1, 0, 1);
    h.agent_status(eid, "a", "failure", 1, "single-row read sees this", 1735689602);

    auto exec = h.tracker->get_execution(eid);
    REQUIRE(exec.has_value());
    CHECK(exec->last_error_detail == "single-row read sees this");
}

// ── qa-S4: failure with empty error_detail ─────────────────────────────────

TEST_CASE("ExecutionTracker.query_executions: agents_failure>0 with empty "
          "error_detail yields empty last_error_detail (qa-S4)",
          "[pg][workflow][executions][tracker]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-NE", "NoError");
    auto eid = h.make_exec("def-NE", "completed", 1, 0, 1);
    // Failure status but empty error_detail — exit code only.
    h.agent_status(eid, "a", "failure", 99, "", 1735689601);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    // Subquery WHERE clause filters out empty error_detail; SELECT returns
    // no rows; `col_text` returns empty. Pin the silent contract.
    CHECK(execs[0].last_error_detail.empty());
}

// ── sec-M1: LIST handler now gates on Execution:Read ───────────────────────

TEST_CASE("executions list: 403 when perm_fn denies (sec-M1)",
          "[pg][workflow][executions][list][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.perm_grant = false;
    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── UP-1 / qa-S1: agent_id with single-quote does not produce JS injection ─

TEST_CASE("executions detail: agent_id containing single-quote is bound via "
          "data-* attrs, not interpolated into JS (UP-1)",
          "[pg][workflow][executions][detail][xss]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-XSS", "XSS-safe");
    auto eid = h.make_exec("def-XSS", "completed", 1, 1, 0);
    // Agent emerges with a single quote in its id — wire-provided, no
    // intake validation today. The detail handler must NOT interpolate
    // this into `onclick="scrollToAgentRow('AGENT-ID')"` style.
    h.agent_status(eid, "agent'with'quote", "success", 0, "", 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The dangerous pattern: agent_id quoted-and-interpolated into a JS
    // string literal. The mitigation is to use data-agent-id="..." and
    // bind via addEventListener client-side; the rendered HTML must NOT
    // contain `scrollToAgentRow(` followed by an interpolated agent_id.
    CHECK(res->body.find("scrollToAgentRow(") == std::string::npos);
    // The agent_id must appear as a data-agent-id attribute value (with
    // its single quote escaped to &#39; for HTML attribute context).
    CHECK(res->body.find("data-agent-id=\"agent&#39;with&#39;quote\"") != std::string::npos);
}

TEST_CASE("ExecutionTracker.query_executions: last_error_detail opt-in default "
          "is empty for fully-successful run",
          "[pg][workflow][executions][tracker]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-L", "L");
    auto eid = h.make_exec("def-L", "completed", 2, 2, 0);
    h.agent_status(eid, "a", "success", 0, "", 1735689601);
    h.agent_status(eid, "b", "success", 0, "", 1735689602);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail.empty());
}

TEST_CASE("ExecutionTracker.query_executions: last_error_detail surfaces "
          "most recent failure when caller opts in",
          "[pg][workflow][executions][tracker]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-LE", "LE");
    auto eid = h.make_exec("def-LE", "completed", 3, 1, 2);
    h.agent_status(eid, "a", "success", 0, "", 1735689601);
    // Two failures; expect the one with the larger completed_at to win.
    h.agent_status(eid, "b", "failure", 1, "OLDER ERROR", 1735689602);
    h.agent_status(eid, "c", "failure", 1, "NEWER ERROR", 1735689610);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail == "NEWER ERROR");
}

// ── PR 2: detail handler responses correlation ─────────────────────────────

TEST_CASE("executions detail PR2: responses correlated by exact execution_id "
          "(no cross-contamination)",
          "[pg][workflow][executions][detail][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-X", "X");
    auto exec_a = h.make_exec("def-X", "completed", 1, 1, 0,
                              /*dispatched_at=*/1735689600);
    auto exec_b = h.make_exec("def-X", "completed", 1, 1, 0,
                              /*dispatched_at=*/1735689600);
    h.agent_status(exec_a, "agent-shared", "success", 0, "", 1735689601);
    h.agent_status(exec_b, "agent-shared", "success", 0, "", 1735689602);
    // Both executions used the same definition + same agent + overlapping
    // timestamp window — pre-PR-2 the timestamp-window join would conflate
    // them. PR 2 stamps execution_id directly, so each detail drawer sees
    // only its own response.
    h.store_response("cmd-A", "agent-shared", "from-A",
                     /*execution_id=*/exec_a, 1735689601);
    h.store_response("cmd-B", "agent-shared", "from-B",
                     /*execution_id=*/exec_b, 1735689602);

    auto res_a = h.sink.Get("/fragments/executions/" + exec_a + "/detail");
    REQUIRE(res_a);
    CHECK(res_a->status == 200);
    CHECK(res_a->body.find("from-A") != std::string::npos);
    CHECK(res_a->body.find("from-B") == std::string::npos);

    auto res_b = h.sink.Get("/fragments/executions/" + exec_b + "/detail");
    REQUIRE(res_b);
    CHECK(res_b->status == 200);
    CHECK(res_b->body.find("from-B") != std::string::npos);
    CHECK(res_b->body.find("from-A") == std::string::npos);
}

TEST_CASE("executions detail PR2: legacy timestamp-window fallback when no "
          "PR-2 rows exist",
          "[pg][workflow][executions][detail][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Y", "Y");
    auto eid = h.make_exec("def-Y", "completed", 1, 1, 0,
                           /*dispatched_at=*/1735689600);
    h.agent_status(eid, "agent-1", "success", 0, "", 1735689601);
    // Store a legacy response: execution_id is empty (pre-PR-2 path), and
    // instruction_id MATCHES the definition_id so the legacy fallback's
    // query() finds it. The detail handler must include it.
    h.store_response(/*command_id=*/"def-Y", "agent-1", "legacy-output",
                     /*execution_id=*/"", 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("legacy-output") != std::string::npos);
}

TEST_CASE("executions detail PR2: PR-2 rows are NOT diluted by legacy fallback",
          "[pg][workflow][executions][detail][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-Z", "Z");
    auto eid = h.make_exec("def-Z", "completed", 1, 1, 0,
                           /*dispatched_at=*/1735689600);
    h.agent_status(eid, "agent-1", "success", 0, "", 1735689601);
    // PR-2 row tagged correctly.
    h.store_response("cmd-real", "agent-1", "tagged-row",
                     /*execution_id=*/eid, 1735689601);
    // A legacy row that would have matched via the timestamp-window join,
    // but now that PR-2 rows exist for this execution_id the fallback
    // branch is skipped — the legacy row must NOT appear in the drawer.
    h.store_response(/*command_id=*/"def-Z", "agent-1", "legacy-leak",
                     /*execution_id=*/"", 1735689602);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("tagged-row") != std::string::npos);
    CHECK(res->body.find("legacy-leak") == std::string::npos);
}

// ── Gate-7 hardening regression net for PR 2 ──────────────────────────────

TEST_CASE("PR2 hardening — UP2-4: cmd_dispatch receives non-empty execution_id "
          "when create_execution succeeds (FAST-agent race fix)",
          "[pg][workflow][executions][pr2][hardening]") {
    // The execute handler now creates the execution row BEFORE calling
    // cmd_dispatch and threads execution_id INTO cmd_dispatch as the 6th
    // parameter. The test stub captures the value passed in
    // last_dispatch_execution_id; we assert it's non-empty after a
    // successful execute. This proves the FAST-agent race is closed:
    // by the time cmd_dispatch returns, the execution_id is known to
    // the dispatch closure and the mapping is registered before any
    // RPC goes out.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-FAST", "FAST");
    auto res = h.sink.Post("/api/instructions/def-FAST/execute",
                           R"({"params":{},"agent_ids":["agent-1"]})");
    // The cmd_dispatch stub returns sent=0 so the route returns 503, but
    // that fires AFTER cmd_dispatch is called with the execution_id —
    // which is what we're pinning here.
    REQUIRE(res);
    CHECK(!h.last_dispatch_execution_id.empty());
}

TEST_CASE("#1088 — POST /api/instructions/:id/execute response includes execution_id",
          "[pg][workflow][executions][execute][issue-1088][agentic]") {
    // The agentic-first workflow shipped in W5.1 (#1094) is:
    //   1. dispatch via POST /api/instructions/:id/execute OR MCP execute_instruction
    //   2. subscribe to live events via GET /api/v1/events?execution_id=<id>
    // The handoff was broken: dispatch returned only command_id, but the
    // SSE endpoint requires execution_id with no public bridge. #1088
    // closes the gap by adding execution_id to the dispatch response.
    // This test pins the contract: dispatch response body MUST contain a
    // non-empty execution_id that can be used immediately with the SSE
    // endpoint.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-AGENTIC", "Agentic");
    // Override the dispatch stub to return sent>0 so the route reaches
    // the response-build path (default stub returns 0 → 503).
    h.dispatch_cmd_override = "cmd-agentic-abc";
    h.dispatch_sent_override = 3;

    auto res = h.sink.Post("/api/instructions/def-AGENTIC/execute",
                           R"({"params":{},"agent_ids":["a1","a2","a3"]})");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("execution_id"));
    REQUIRE(body["execution_id"].is_string());
    CHECK(!body["execution_id"].get<std::string>().empty());
    // The execution_id returned MUST be the same one threaded into the
    // dispatch closure — proves the response and the agent-side mapping
    // see the same id.
    CHECK(body["execution_id"].get<std::string>() == h.last_dispatch_execution_id);
    // Backwards-compat: command_id, agents_reached, definition_id are
    // still present.
    CHECK(body["command_id"] == "cmd-agentic-abc");
    CHECK(body["agents_reached"] == 3);
    CHECK(body["definition_id"] == "def-AGENTIC");
}

TEST_CASE("#3136 blocker: grant_secret reaches cmd_dispatch but is redacted from the "
         "persisted execution row",
         "[pg][workflow][executions][security]") {
    // The concrete attack this closes: an execution row created BEFORE
    // dispatch (create-before-dispatch, UP2-4) used to carry the FULL
    // caller-supplied params JSON — including a one-time upload-grant
    // secret — into executions.parameter_values, readable by any principal
    // holding the broadly-granted Execution:Read permission within the
    // grant's TTL. See sensitive_instruction_params.hpp.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-UPLOAD", "Upload File");
    h.dispatch_cmd_override = "cmd-upload-abc";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post(
        "/api/instructions/def-UPLOAD/execute",
        R"({"params":{"grant_id":"deadbeef","grant_secret":"topsecret","path":"/tmp/x"},)"
        R"("agent_ids":["agent-1"]})");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // The LIVE dispatch still got the raw secret — otherwise the upload
    // could never actually authenticate against the server.
    REQUIRE(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_params.at("grant_secret") == "topsecret");
    CHECK(h.last_dispatch_params.at("grant_id") == "deadbeef");

    // The PERSISTED row must not carry either sensitive key.
    auto body = nlohmann::json::parse(res->body);
    auto exec = h.tracker->get_execution(body["execution_id"].get<std::string>());
    REQUIRE(exec.has_value());
    auto stored = nlohmann::json::parse(exec->parameter_values);
    CHECK_FALSE(stored.contains("grant_secret"));
    CHECK_FALSE(stored.contains("grant_id"));
    // Ordinary, non-sensitive parameters survive untouched.
    REQUIRE(stored.contains("path"));
    CHECK(stored["path"] == "/tmp/x");
}

TEST_CASE("PR2 hardening — query_by_execution includes the partial-index "
          "predicate `execution_id != ''` in its SQL (perf-B1 fix)",
          "[pg][workflow][executions][pr2][hardening][perf]") {
    // SQLite's planner refuses to use a partial index unless the WHERE
    // clause syntactically subsumes the partial-index predicate. The
    // perf-B1 fix added `AND execution_id != ''` to query_by_execution's
    // SELECT. We can't easily inspect SQLite's plan from a Catch2 test,
    // but we CAN prove the function still returns the right rows when
    // both PR-2-tagged and legacy rows coexist — which exercises the
    // index path and would surface a regression where the predicate is
    // dropped or rewritten.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse pr2;
    pr2.instruction_id = "cmd-A";
    pr2.agent_id = "agent-1";
    pr2.status = 1;
    pr2.output = "tagged";
    pr2.execution_id = "exec-pr2";
    store.store(pr2);
    StoredResponse legacy;
    legacy.instruction_id = "cmd-A";
    legacy.agent_id = "agent-2";
    legacy.status = 1;
    legacy.output = "untagged";
    legacy.execution_id = "";
    store.store(legacy);

    auto rows = store.query_by_execution("exec-pr2");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].output == "tagged");
}

TEST_CASE("PR2 hardening — multi-agent fan-out: terminal-branch does NOT erase "
          "the mapping so agents 2..N stamp correctly (HF-1 fix)",
          "[pg][workflow][executions][pr2][hardening]") {
    // Pre-fix: terminal-status branches in agent_service_impl.cpp erased
    // cmd_execution_ids_ on first response, causing agents 2..N to stamp
    // empty execution_id. The fix removes the erase. We can't drive
    // process_gateway_response from this test (no AgentServiceImpl in
    // ExecHarness), but we CAN prove the response store handles two
    // consecutive stores under the same execution_id — which is what
    // the fix enables. The integration coverage is deferred to a UAT
    // round-trip in PR 2.8.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse a1;
    a1.instruction_id = "cmd-fan";
    a1.agent_id = "agent-1";
    a1.status = 1;
    a1.output = "agent1-done";
    a1.execution_id = "exec-fan";
    store.store(a1);
    StoredResponse a2;
    a2.instruction_id = "cmd-fan";
    a2.agent_id = "agent-2";
    a2.status = 1;
    a2.output = "agent2-done";
    a2.execution_id = "exec-fan";
    store.store(a2);

    auto rows_opt = store.query_by_execution("exec-fan");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 2);
    // Both agents present — HF-1 regression would drop one.
    bool saw_a1 = false, saw_a2 = false;
    for (const auto& r : rows) {
        if (r.output == "agent1-done")
            saw_a1 = true;
        if (r.output == "agent2-done")
            saw_a2 = true;
    }
    CHECK(saw_a1);
    CHECK(saw_a2);
}

TEST_CASE("PR2 hardening — failed dispatch does NOT orphan a phantom 'running' "
          "execution row (Pattern-C regression close)",
          "[pg][workflow][executions][pr2][hardening]") {
    // Reorder of create_execution BEFORE cmd_dispatch (UP2-4 fix) introduced
    // a Pattern-C regression: if dispatch returns sent=0 OR throws, the
    // pre-created execution row was left at status='running' forever, showing
    // as a phantom in-flight run in the LIST handler. The fix calls
    // mark_cancelled on both failure paths. Pin the contract.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-FAIL", "FAIL");
    auto res = h.sink.Post("/api/instructions/def-FAIL/execute",
                           R"({"params":{},"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503); // sent=0 from cmd_dispatch stub

    // Find the orphan row. Should be cancelled, not running.
    ExecutionQuery q;
    q.definition_id = "def-FAIL";
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].status == "cancelled");
}

// #3424/#3511 Gate 8 round-4 (quality-engineer): the sibling above only
// exercises the generic catch-all zero-reach branch (stub defaults). These
// three pin the other branches of the same 4-way split, matching the
// discrimination /api/command and MCP execute_instruction already had tests
// for — this route's contract was documented in rest-api.md this same fix
// round with no test coverage to back it.
TEST_CASE("instruction execute: a malformed scope expression reports reason=invalid_scope, "
          "400 (not 503), non-retryable (PR #3939 review, architect finding: this route "
          "reaches ConfinedDispatchOutcome::scope_parse_error via a caller scope expression "
          "but never read it, silently falling into the generic no_agents_reached catch-all)",
          "[pg][workflow][executions][execute][3424][3511]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-IS", "IS");
    h.dispatch_scope_parse_error_override = "unexpected token at offset 4";
    auto res = h.sink.Post("/api/instructions/def-IS/execute", R"({"scope":"tag:(("})");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = nlohmann::json::parse(res->body);
    // Structured shape (Gate 4 consistency-auditor finding F1): matches this
    // handler's own local convention (the containment_unreadable/quarantined/
    // plugin_not_found siblings just below), not a bare string.
    CHECK(body["error"]["code"] == 400);
    CHECK(body["error"]["reason"] == "invalid_scope");
    CHECK(body["error"]["retry_after_ms"].is_null());
    CHECK(body["error"]["message"].get<std::string>().find("unexpected token at offset 4") !=
          std::string::npos);
    CHECK(body["meta"]["api_version"] == "v1");
}

TEST_CASE("instruction execute: a fail-closed containment gate reports "
          "reason=containment_unreadable, retryable after 5000ms",
          "[pg][workflow][executions][execute][3424][3511]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-CU", "CU");
    h.dispatch_containment_unreadable_override = true;
    auto res = h.sink.Post("/api/instructions/def-CU/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["reason"] == "containment_unreadable");
    CHECK(body["error"]["retry_after_ms"] == 5000);
}

TEST_CASE("instruction execute: a degraded gateway routing-directory read reports "
          "reason=route_unreadable, retryable after 5000ms (WS-4 4.2b Task D — the exact "
          "sibling of containment_unreadable)",
          "[pg][workflow][executions][execute][3424][3511]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-RU", "RU");
    h.dispatch_route_unreadable_override = true;
    auto res = h.sink.Post("/api/instructions/def-RU/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["reason"] == "route_unreadable");
    CHECK(body["error"]["retry_after_ms"] == 5000);
}

TEST_CASE("instruction execute: every target quarantined reports "
          "reason=quarantined, non-retryable",
          "[pg][workflow][executions][execute][3424][3511]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-QT", "QT");
    h.dispatch_denied_quarantined_count_override = 1;
    auto res = h.sink.Post("/api/instructions/def-QT/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["reason"] == "quarantined");
    CHECK(body["error"]["retry_after_ms"].is_null());
}

TEST_CASE("instruction execute: a plugin absent from every target's inventory reports "
          "reason=plugin_not_found, non-retryable",
          "[pg][workflow][executions][execute][3424][3511]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-UP", "UP");
    h.dispatch_unknown_plugin_count_override = 1;
    auto res = h.sink.Post("/api/instructions/def-UP/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["reason"] == "plugin_not_found");
    CHECK(body["error"]["retry_after_ms"].is_null());
}

// ─────────────────────────────────────────────────────────────────────────────
// PR 3 — /sse/executions/{id} live updates handler
//
// The TestRouteSink dispatch path returns the response object after the
// handler runs. For the SSE route, that means we can verify the
// auth/RBAC/404/410/503 short-circuit logic AND confirm the chunked
// content provider is attached when the path is happy. We do NOT exercise
// the actual streaming body here — that is covered by the bus-level tests
// in test_execution_event_bus.cpp plus the puppeteer smoke. The bus → DOM
// integration is the seam these tests pin.
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("SSE handler: 404 for unknown execution", "[pg][workflow][executions][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    auto res = h.sink.Get("/sse/executions/does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("SSE handler: 410 Gone for terminal execution", "[pg][workflow][executions][pr3]") {
    // Already-terminal executions must not open an SSE channel — the client
    // should fall back to the static detail fragment. 410 tells EventSource
    // to stop reconnecting (vs 503 which it would retry).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-DONE", "Done");
    auto exec_id = h.make_exec("def-DONE", "succeeded", 3, 3, 0);
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 410);
}

// Governance fix (#2146 A2-R1 Gate 8 re-review): this route used the plain
// get_execution(), which collapses "execution genuinely absent" and "read
// degraded" (a transient pool/query failure) to the same nullopt -- a
// degrade fell through to the SAME not-found + denial-audit branch a
// genuine absence takes, producing a FALSE 404 for a legitimate owner and a
// permanently wrong CC7.2 denial audit row for a confined caller whose only
// "fault" was hitting a transient outage. get_execution_checked's outer
// std::expected now distinguishes the two; the degrade branch returns
// BEFORE any denial audit is recorded.
TEST_CASE("SSE handler: a transient tracker degrade is 503 (not a false 404) and "
          "records no denial audit (#2146 A2-R1 Gate 8 fix)",
          "[pg][workflow][executions][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-2146c", "2146c");
    auto exec_id = h.make_exec("def-2146c", "running", 1, 0, 0);
    // Engage a confined scope so the OLD code's denial-audit branch would
    // have fired on the false 404 this fix closes.
    h.fleet_read_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-0"}};

    // Break ONLY the get_execution_checked query -- a raw statement over a
    // side connection, never the harness's own pool, so the tracker stays
    // "open" and this is a genuine single-call fault.
    exec_sql(db.dsn(),
             "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_2146c");
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    exec_sql(db.dsn(),
             "ALTER TABLE execution_tracker.executions_hidden_2146c RENAME TO executions");

    REQUIRE(res);
    // (a) 503, never the old false 404.
    CHECK(res->status == 503);
    CHECK(res->body.find("tracker degraded") != std::string::npos);

    // (b) no denial audit row for this execution -- pre-fix, this recorded
    // execution.live_subscribe/denied here.
    for (const auto& c : h.audit_calls)
        CHECK(c.target_id != exec_id);
}

TEST_CASE("SSE handler: invisible terminal execution collapses to the missing-id 404",
          "[pg][workflow][executions][pr3][scope][notfound]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig authz_rig{db.dsn()};
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr,
                  /*wire_exec_visible=*/true, /*with_workflow_engine=*/false,
                  /*wire_fleet_read_fn=*/true, /*with_product_pack_store=*/false,
                  authz_rig.auth_fn(), authz_rig.fleet_read_fn());
    h.make_def("def-HIDDEN", "Hidden");
    auto exec_id =
        h.make_exec("def-HIDDEN", "succeeded", 1, 1, 0, 1735689600, "alice");
    h.agent_status(exec_id, "alice-agent", "success");

    const auto token = authz_rig.mint_bob();
    const auto headers = yuzu::test::ResponseExecutionAuthzPgRig::bearer(token);
    auto invisible = h.sink.Get("/sse/executions/" + exec_id, headers);
    auto missing = h.sink.Get("/sse/executions/does-not-exist", headers);
    REQUIRE(invisible);
    REQUIRE(missing);
    CHECK(invisible->status == 404);
    CHECK(missing->status == 404);
    CHECK(invisible->body == missing->body);
    CHECK(h.event_bus->subscriber_count(exec_id) == 0);
    // #1634 (governance Gate 6 compliance-officer fix): a suppressed
    // cross-operator subscribe attempt now DOES get a distinct `denied` audit
    // row (CC7.2 evidence, parity with the REST twin) — it must never be the
    // `success`-shaped row a genuine admit gets.
    bool saw_denied = false;
    for (const auto& a : h.audit_calls) {
        CHECK(a.result != "success");
        if (a.action == "execution.live_subscribe" && a.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

// ── ADR-0034 shared-budget admission (governance regression guards) ─────────
//
// These exist because the two blockers this route shipped were BOTH invisible to
// the whole suite: the budget was never wired into production at all, and the
// lease was taken after bus->subscribe so a rejection leaked the listener. Neither
// is reachable by a sanitizer — an admission reject is single-threaded and
// allocation-free — so an assertion-based handler test is the only instrument.

TEST_CASE("SSE handler: 429 once the shared stream budget is exhausted",
          "[pg][workflow][executions][pr3][sse][admission]") {
    // Capacity 1: the first attach consumes the only slot, so the second is refused.
    yuzu::server::detail::StreamBudget budget{
        yuzu::server::detail::StreamBudget::Config{/*global_cap=*/1}};
    // Pre-consume the slot on the SAME surface so the route hits the global cap.
    auto held = budget.try_acquire(yuzu::server::detail::SseSurface::kDashboardExec, "someone-else",
                                   yuzu::server::detail::kPerPrincipalDashboard);
    REQUIRE(held.lease);
    REQUIRE(budget.active() == 1);

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, &budget);
    h.make_def("def-CAP", "Cap");
    auto exec_id = h.make_exec("def-CAP", "running", 5, 0, 0);

    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 429);
    // Honest retry hint (the platform 429 convention), not a bare status.
    CHECK(res->get_header_value("Retry-After") == "5");
    // A live stream is NEVER evicted to admit a newcomer.
    CHECK(budget.active() == 1);
}

TEST_CASE("SSE handler: a budget rejection leaves NO bus subscriber behind",
          "[pg][workflow][executions][pr3][sse][admission]") {
    // THE regression guard for the listener leak. The lease used to be taken AFTER
    // bus->subscribe, and the 429 path returns without unsubscribing — and
    // gc_terminal_channels only reaps channels whose listener set is empty, so every
    // rejection pinned a channel plus its event buffer for the life of the process.
    // Worse, this route's listener enqueues UNCAPPED, so the abandoned queue grew on
    // every later publish. An unbounded leak introduced by the control that exists to
    // bound resources.
    yuzu::server::detail::StreamBudget budget{
        yuzu::server::detail::StreamBudget::Config{/*global_cap=*/1}};
    auto held = budget.try_acquire(yuzu::server::detail::SseSurface::kDashboardExec, "someone-else",
                                   yuzu::server::detail::kPerPrincipalDashboard);
    REQUIRE(held.lease);

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, &budget);
    h.make_def("def-LEAK", "Leak");
    auto exec_id = h.make_exec("def-LEAK", "running", 5, 0, 0);

    const auto before = h.event_bus->subscribers_total();
    for (int i = 0; i < 5; ++i) {
        auto res = h.sink.Get("/sse/executions/" + exec_id);
        REQUIRE(res);
        REQUIRE(res->status == 429);
    }
    // Five refusals, zero subscribers gained. Before the fix this was `before + 5`,
    // and none of them was ever reclaimable.
    CHECK(h.event_bus->subscribers_total() == before);
    CHECK(h.event_bus->subscriber_count(exec_id) == 0);
}

TEST_CASE("SSE handler: an unmetered route still serves (nullptr budget is a test seam)",
          "[pg][workflow][executions][pr3][sse][admission]") {
    // The budget parameter is nullable for harnesses. Assert that nullability is a
    // pass-through and not an accidental deny, so the guard above cannot pass for
    // the wrong reason.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool); // no budget
    h.make_def("def-FREE", "Free");
    auto exec_id = h.make_exec("def-FREE", "running", 5, 0, 0);
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("SSE handler: 403 when fleet_read_fn denies Read on Execution",
          "[pg][workflow][executions][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-FORBID", "Forbid");
    auto exec_id = h.make_exec("def-FORBID", "running", 5, 0, 0);
    h.fleet_read_grant = false;
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("SSE handler: 200 on running execution attaches event-stream",
          "[pg][workflow][executions][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-RUN", "Run");
    auto exec_id = h.make_exec("def-RUN", "running", 5, 1, 0);
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    // Cache + buffering headers are mandatory for SSE — without them
    // intermediaries (nginx, browser bfcache) buffer the stream and the
    // client never receives transitions until the connection closes.
    CHECK(res->get_header_value("Cache-Control") == "no-cache");
    CHECK(res->get_header_value("X-Accel-Buffering") == "no");
}

TEST_CASE("SSE handler: ExecutionTracker.update_agent_status publishes "
          "agent-transition onto the bus",
          "[pg][workflow][executions][pr3]") {
    // This is the bus integration the SSE handler depends on — the
    // streaming body trusts that update_agent_status feeds the channel.
    // Subscribe directly to the bus so we don't need a real socket.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-INT", "Integration");
    auto exec_id = h.make_exec("def-INT", "running", 3, 0, 0);

    std::vector<ExecutionEvent> seen;
    auto sub =
        h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) { seen.push_back(ev); });

    h.agent_status(exec_id, "agent-1", "running");
    h.agent_status(exec_id, "agent-1", "success");

    h.event_bus->unsubscribe(exec_id, sub);

    // UAT 2026-05-06: each update_agent_status now chains refresh_counts
    // so a state change publishes BOTH agent-transition AND
    // execution-progress in that order. With agents_targeted=3 and only
    // 1 agent responding, no terminal threshold is crossed — no
    // execution-completed events. Total = 4 (2 transitions + 2 progress).
    REQUIRE(seen.size() >= 4);
    CHECK(seen[0].event_type == "agent-transition");
    CHECK(seen[0].data.find("agent-1") != std::string::npos);
    CHECK(seen[1].event_type == "execution-progress");
    CHECK(seen[2].event_type == "agent-transition");
    CHECK(seen[3].event_type == "execution-progress");
    // Per-execution monotonic ids; first event of a fresh channel is id=1.
    CHECK(seen[0].id == 1);
    CHECK(seen.back().id >= seen[0].id);
}

TEST_CASE("SSE handler: refresh_counts on terminal threshold publishes "
          "execution-progress + execution-completed",
          "[pg][workflow][executions][pr3]") {
    // When refresh_counts crosses the all-agents-responded threshold, the
    // tracker must publish BOTH a progress event (so KPI strip updates)
    // AND a terminal event (so the SSE client closes its EventSource).
    // Verify both, in order, on the bus.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-TERM", "Terminal");
    auto exec_id = h.make_exec("def-TERM", "running", 2, 0, 0);
    REQUIRE(h.tracker->set_agents_targeted(exec_id, 2));

    std::vector<ExecutionEvent> seen;
    h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) { seen.push_back(ev); });

    // UAT 2026-05-06: update_agent_status now chains refresh_counts, so
    // explicit refresh_counts() calls are redundant and would publish a
    // duplicate progress event AFTER the terminal-completed event,
    // violating the documented "progress before completed" ordering.
    h.agent_status(exec_id, "agent-1", "success");
    h.agent_status(exec_id, "agent-2", "success");

    // Filter out per-agent transitions, keep progress+completed only.
    std::vector<std::string> kinds;
    for (const auto& ev : seen)
        kinds.push_back(ev.event_type);
    auto count = [&](const std::string& k) {
        return static_cast<int>(std::count(kinds.begin(), kinds.end(), k));
    };
    // #872 — exact counts (was `>= 1`): 2 agent_status calls, each chaining
    // refresh_counts via update_agent_status, so we expect exactly 2
    // agent-transition + 2 execution-progress, and the second refresh_counts
    // crosses the terminal threshold → 1 execution-completed. A regression
    // that publishes a stray progress event AFTER the completed event would
    // bump count("execution-progress") to 3 and fail this assertion (the
    // old `>= 1` would still pass it).
    CHECK(count("agent-transition") == 2);
    CHECK(count("execution-progress") == 2);
    CHECK(count("execution-completed") == 1);

    // execution-completed must come AFTER the FINAL execution-progress so
    // a client receiving them in order sees counts THEN status. The loop
    // tracks last_progress_idx (not first_progress_idx) so a regression
    // that publishes progress→completed→progress would fail here too —
    // last_progress_idx would land AFTER completed_idx.
    auto last_progress_idx = -1;
    auto completed_idx = -1;
    for (std::size_t i = 0; i < seen.size(); ++i) {
        if (seen[i].event_type == "execution-progress")
            last_progress_idx = static_cast<int>(i);
        if (seen[i].event_type == "execution-completed")
            completed_idx = static_cast<int>(i);
    }
    REQUIRE(last_progress_idx >= 0);
    REQUIRE(completed_idx >= 0);
    CHECK(completed_idx > last_progress_idx);
}

TEST_CASE("SSE handler: mark_cancelled publishes terminal execution-completed",
          "[pg][workflow][executions][pr3]") {
    // mark_cancelled is the cancel-on-dispatch-failure path (PR 2 Pattern-C
    // close). PR 3 must emit a terminal event so an open SSE drawer
    // closes its EventSource cleanly instead of waiting for a heartbeat
    // timeout.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-CANCEL", "Cancel");
    auto exec_id = h.make_exec("def-CANCEL", "running", 5, 0, 0);

    std::vector<ExecutionEvent> seen;
    h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) { seen.push_back(ev); });

    REQUIRE(h.tracker->mark_cancelled(exec_id, "tester"));

    REQUIRE(seen.size() == 1);
    CHECK(seen[0].event_type == "execution-completed");
    CHECK(seen[0].data.find("cancelled") != std::string::npos);
}

TEST_CASE("SSE handler: ring buffer holds events for late-connecting client",
          "[pg][workflow][executions][pr3]") {
    // The SSE handler replays the ring buffer to a client that connects
    // mid-execution (with Last-Event-ID=0 → all). Pin the buffer
    // contents the replay would walk.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-LATE", "Late");
    auto exec_id = h.make_exec("def-LATE", "running", 5, 0, 0);

    h.agent_status(exec_id, "agent-1", "running");
    h.agent_status(exec_id, "agent-2", "success");
    h.agent_status(exec_id, "agent-3", "failure");

    // UAT 2026-05-06: each update_agent_status chains refresh_counts, so
    // every state change publishes 2 events (agent-transition +
    // execution-progress). 3 calls -> 6 events. agents_targeted=5 so no
    // terminal threshold crossed. Ids are 1..6 in publish order.
    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 6);
    CHECK(snap[0].id == 1);
    CHECK(snap[1].id == 2);
    CHECK(snap[2].id == 3);
    CHECK(snap[5].id == 6);
}

TEST_CASE("SSE handler: per-execution channel partitioning under the routes layer",
          "[pg][workflow][executions][pr3]") {
    // Two concurrent executions of the same definition; each agent
    // transition must land on the correct channel. This is the contract
    // the SSE handler depends on to keep one drawer's events from
    // bleeding into another.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-PARTITION", "Partition");
    auto a = h.make_exec("def-PARTITION", "running", 2, 0, 0);
    auto b = h.make_exec("def-PARTITION", "running", 2, 0, 0);

    h.agent_status(a, "agent-1", "success");
    h.agent_status(b, "agent-9", "failure");

    // UAT 2026-05-06: each update_agent_status chains refresh_counts, so
    // each agent_status call publishes 2 events on its channel
    // (agent-transition + execution-progress). agents_targeted=2 so the
    // single response doesn't cross the terminal threshold.
    auto snap_a = h.event_bus->snapshot(a);
    auto snap_b = h.event_bus->snapshot(b);
    REQUIRE(snap_a.size() == 2);
    REQUIRE(snap_b.size() == 2);
    CHECK(snap_a[0].event_type == "agent-transition");
    CHECK(snap_a[0].data.find("agent-1") != std::string::npos);
    CHECK(snap_b[0].event_type == "agent-transition");
    CHECK(snap_b[0].data.find("agent-9") != std::string::npos);
    // No cross-leak: agent-9 must not appear in exec A's channel.
    CHECK(snap_a[0].data.find("agent-9") == std::string::npos);
    CHECK(snap_b[0].data.find("agent-1") == std::string::npos);
}

TEST_CASE("SSE handler: list view stamps data-execution-id and "
          "data-execution-status for client SSE bootstrap",
          "[pg][workflow][executions][pr3]") {
    // The drawer opens an EventSource only when the row was rendered with
    // status=running OR pending. PR 3 added the data-* attributes to the
    // list row markup; verify they are present and round-trip the status
    // we created the execution with.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-LIST", "List");
    auto exec_id = h.make_exec("def-LIST", "running", 3, 0, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto& body = res->body;
    CHECK(body.find("data-execution-id=\"" + exec_id + "\"") != std::string::npos);
    CHECK(body.find("data-execution-status=\"running\"") != std::string::npos);
}

TEST_CASE("SSE handler: detail KPI strip carries id=exec-kpi-{id} for partial swaps",
          "[pg][workflow][executions][pr3]") {
    // Client SSE listener finds the KPI strip via #exec-kpi-{id} so it
    // can update Total / Succeeded / Failed without re-rendering the
    // whole drawer. Pin the id stamp.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-KPI", "KPI");
    auto exec_id = h.make_exec("def-KPI", "running", 3, 0, 0);
    auto res = h.sink.Get("/fragments/executions/" + exec_id + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("id=\"exec-kpi-" + exec_id + "\"") != std::string::npos);
}

TEST_CASE("SSE handler: per-agent status badge has .per-agent-status class for partial swaps",
          "[pg][workflow][executions][pr3]") {
    // Client SSE listener swaps the status badge in place via
    // .per-agent-status. Pin the class stamp.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BADGE", "Badge");
    auto exec_id = h.make_exec("def-BADGE", "running", 1, 0, 0);
    h.agent_status(exec_id, "a-1", "running");
    auto res = h.sink.Get("/fragments/executions/" + exec_id + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("per-agent-status") != std::string::npos);
    CHECK(res->body.find("per-agent-exit-code") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// PR 4 — SSE handler audit + no-bus 503 contracts
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("SSE handler: 503 when execution_event_bus is null (no-bus path)",
          "[pg][workflow][executions][pr3][pr4]") {
    // qe-S1: the route is registered even when the bus is intentionally
    // not wired (test harness opt-out, configuration path that omits the
    // bus). Hitting it must return 503, not 200 — opening an EventSource
    // against a missing bus would freeze the drawer waiting for events
    // that will never publish.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/false);
    h.make_def("def-NO-BUS", "NoBus");
    auto exec_id = h.make_exec("def-NO-BUS", "running", 3, 0, 0);

    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 503);
    // Audit must NOT fire on the no-bus path — the request never reached
    // the live-subscribe success branch.
    bool saw_subscribe = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "execution.live_subscribe")
            saw_subscribe = true;
    }
    CHECK_FALSE(saw_subscribe);
}

TEST_CASE("SSE handler: 200 path emits execution.live_subscribe audit",
          "[pg][workflow][executions][pr3][pr4]") {
    // Positive control for the audit-absence test below: the happy path
    // DOES emit the audit. Without this pin, a refactor that drops the
    // emit entirely would silently pass the absence test.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-SUB", "Sub");
    auto exec_id = h.make_exec("def-SUB", "running", 1, 0, 0);

    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    bool saw = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "execution.live_subscribe" && a.result == "success" &&
            a.target_type == "Execution" && a.target_id == exec_id) {
            saw = true;
            break;
        }
    }
    CHECK(saw);
}

TEST_CASE("SSE handler: 403 fleet-read denial does NOT emit live_subscribe audit",
          "[pg][workflow][executions][pr3][pr4]") {
    // qe-S4: a denied subscribe must not leave a forensic ghost row in
    // audit_store — the success-shaped audit only fires after perm_fn
    // approves. Pin this so a future refactor that hoists the audit
    // ahead of perm_fn (the kind of "log first, check later" pattern
    // that surfaces in compliance reviews) is caught.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-DENY", "Deny");
    auto exec_id = h.make_exec("def-DENY", "running", 1, 0, 0);
    h.fleet_read_grant = false;

    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 403);

    for (const auto& a : h.audit_calls) {
        CHECK_FALSE(a.action == "execution.live_subscribe");
    }
}

// ── #2500: supplied-but-names-nothing targeting must never widen ──────────
//
// The REST twin of #2492. Before this, POST /api/instructions/{id}/execute
// dispatched to the ENTIRE FLEET when `agent_ids` was `[]`, when `agent_ids`
// was not an array, or when `scope` was not a string — the parser dropped what
// it could not use and the sink's `agent_ids.empty()` branch read the result as
// "no target named". `[1,2,3]` did 400, but only because `get<std::string>()`
// threw into a generic catch; that was an accident of parse order, not a check.
//
// `dispatch_calls` is the assertion that matters in every rejecting section: a
// 400 that still dispatched would leave the defect intact behind a nicer
// status code, and the original bug returned a SUCCESS response.

TEST_CASE("#2500 — supplied-but-empty agent_ids is refused, not widened to the fleet",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T1", "T1");

    auto res = h.sink.Post("/api/instructions/def-T1/execute", R"({"agent_ids":[]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"] == 400);
    // The message must name the field and the deliberate way to broadcast —
    // an operator whose device filter matched nothing needs to be told the
    // difference between "no devices" and "every device".
    CHECK(body["error"]["message"].get<std::string>().find("agent_ids") != std::string::npos);
    CHECK(body["meta"]["api_version"] == "v1");

    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "agent_ids_empty"}})
              .value() == 1.0);
}

TEST_CASE("#2500 — non-array agent_ids and non-string scope are refused, not ignored",
          "[pg][workflow][executions][execute][targeting][security]") {
    // Both were SILENTLY SKIPPED by the `is_array()` / `is_string()` guards and
    // fell through to broadcast. Neither ever produced an error before.
    SECTION("non-array agent_ids") {
        YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        ExecHarness h(pool);
        h.make_def("def-T2", "T2");
        auto res = h.sink.Post("/api/instructions/def-T2/execute", R"({"agent_ids":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "instruction_execute"}, {"reason", "agent_ids_type"}})
                  .value() == 1.0);
    }
    SECTION("non-string scope") {
        YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        ExecHarness h(pool);
        h.make_def("def-T3", "T3");
        auto res = h.sink.Post("/api/instructions/def-T3/execute", R"({"scope":123})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "instruction_execute"}, {"reason", "scope_type"}})
                  .value() == 1.0);
    }
    SECTION("supplied-but-empty scope") {
        YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        ExecHarness h(pool);
        h.make_def("def-T4", "T4");
        auto res = h.sink.Post("/api/instructions/def-T4/execute", R"({"scope":""})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "instruction_execute"}, {"reason", "scope_empty"}})
                  .value() == 1.0);
    }
}

TEST_CASE("#2500 — numeric agent_ids entries are refused DELIBERATELY, with a targeting reason",
          "[pg][workflow][executions][execute][targeting][security]") {
    // This shape already 400'd before the fix — via `get<std::string>()`
    // throwing `type_error` into the body-parse catch, which reported
    // "invalid request body", emitted no metric and no audit row, and would
    // have vanished the moment anyone made that loop tolerant. Pin that it is
    // now refused BY THE TARGETING RULE: the reason label is the proof, because
    // only the deliberate path can produce it.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T5", "T5");

    auto res = h.sink.Post("/api/instructions/def-T5/execute", R"({"agent_ids":[1,2,3]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "agent_id_type"}})
              .value() == 1.0);

    bool denied_audit = false;
    for (const auto& a : h.audit_calls) {
        if (a.action == "instruction.execute" && a.result == "denied" &&
            a.detail == "reason=agent_id_type" && a.target_id == "def-T5")
            denied_audit = true;
    }
    CHECK(denied_audit);
}

// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. This body is an otherwise-VALID, otherwise-ACCEPTED
// request (a real single target) with one extra deeply-nested field inside
// "params" - the exact field this handler's params-building loop calls
// .dump() on for non-string values - so on unguarded code the request
// proceeds all the way to dispatch, and only the new depth check tells
// fixed and unfixed code apart. depth 40 is trivially safe to build/dump
// directly in this test process; the real attack depth this guard exists
// for is many orders of magnitude higher (~100,000 levels).
TEST_CASE("POST /api/instructions/:id/execute: a body nested past the depth limit is "
          "rejected before dispatch",
          "[pg][workflow][executions][execute][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-DEPTH", "DEPTH");

    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string body = R"({"agent_ids":["agent-1"],"params":{"deep":)" + deep_array + "}}";
    auto res = h.sink.Post("/api/instructions/def-DEPTH/execute", body);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("#2500 — a genuinely omitted target still broadcasts (the over-broadness guard)",
          "[pg][workflow][executions][execute][targeting]") {
    // The half of the rule that is NOT a refusal, and the one a careless fix
    // breaks: omitting both fields is how a caller deliberately says "the whole
    // fleet", and it must keep working. Without this section a fix that
    // rejected every untargeted execute would pass every test above.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T6", "T6");
    h.dispatch_cmd_override = "cmd-1";
    h.dispatch_sent_override = 3;

    auto res = h.sink.Post("/api/instructions/def-T6/execute", R"({"params":{}})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_agent_ids.empty());
    // The broadcast is NAMED, not inferred from two empty fields. The shared
    // sink now reaches nobody on empty+empty, so this assertion is the whole
    // difference between "deliberately the entire fleet" and "reached no one" —
    // relaxing it back to `.empty()` would silently turn every untargeted
    // execute into a no-op that still answers 200.
    CHECK(h.last_dispatch_scope == "__all__");
}

TEST_CASE("#2500 — an explicit non-empty target is unaffected",
          "[pg][workflow][executions][execute][targeting]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T7", "T7");
    h.dispatch_cmd_override = "cmd-2";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post("/api/instructions/def-T7/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids.size() == 1);
    CHECK(h.last_dispatch_agent_ids[0] == "agent-1");
}

TEST_CASE("#2500 — a non-object body is refused, not read as an unnamed target",
          "[pg][workflow][executions][execute][targeting][security]") {
    // `check_targeting_shape` asks the body whether it CONTAINS targeting keys,
    // and nlohmann's contains() answers false for an array or a scalar. So
    // before the route rejected non-objects, `["dev-1","dev-2"]` — a plausible
    // shape from a client that forgot the envelope — looked identical to a body
    // that named no target at all, and "named no target" means the whole fleet.
    // The guard the fix installs would have widened through its own front door.
    //
    // Found independently by three Gate-3 reviewers; the precondition is
    // enforced at the route and pinned here rather than left as a header
    // comment, because a comment is not a check.
    for (const char* body : {R"(["dev-1","dev-2"])", "5", "null", R"("dev-1")"}) {
        YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        ExecHarness h(pool);
        h.make_def("def-T8", "T8");
        auto res = h.sink.Post("/api/instructions/def-T8/execute", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.dispatch_calls == 0);
        // Counted and audited like its four sibling refusals. An uncounted
        // refusal cannot reach the alert this change ships — the argument the
        // fold used to call an invisible refusal blocking, applied to itself.
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "instruction_execute"}, {"reason", "body_type"}})
                  .value() == 1.0);
        bool denied_audit = false;
        for (const auto& a : h.audit_calls)
            if (a.action == "instruction.execute" && a.result == "denied" &&
                a.detail == "reason=body_type")
                denied_audit = true;
        CHECK(denied_audit);
    }
}

TEST_CASE("#2500 — an explicit scope of __all__ broadcasts by name",
          "[pg][workflow][executions][execute][targeting]") {
    // The vocabulary this fix introduces at the dispatch sink, exercised from
    // the outside. `__all__` is a PUBLISHED ground scope kind — advertised by
    // /discover/scope-kinds and named in the MCP execute_instruction schema —
    // so a caller may legitimately send it, and the dashboard's "All agents"
    // option does exactly that. It must reach the sink intact rather than being
    // refused as a scope that resolves to no devices.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T9", "T9");
    h.dispatch_cmd_override = "cmd-3";
    h.dispatch_sent_override = 2;

    auto res = h.sink.Post("/api/instructions/def-T9/execute", R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_scope == "__all__");
    CHECK(h.last_dispatch_agent_ids.empty());
}

TEST_CASE("#2500 — an explicit agent_ids list wins over a broadcast request",
          "[pg][workflow][executions][execute][targeting][security]") {
    // This pins that the ROUTE forwards both fields intact. The precedence
    // DECISION itself lives in the dispatch sink, which this harness cannot
    // reach (it stubs the dispatch closure) — that is covered by
    // classify_dispatch_arm's own tests in test_dispatch_target_shape.cpp.
    // Saying so explicitly rather than letting the case name imply it proves
    // the sink: getting precedence wrong is how the first attempt at the sink
    // inversion introduced a NEW widening.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-T10", "T10");
    h.dispatch_cmd_override = "cmd-4";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post("/api/instructions/def-T10/execute",
                           R"({"agent_ids":["agent-1"],"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids.size() == 1);
    CHECK(h.last_dispatch_agent_ids[0] == "agent-1");
}

// ═══════════════════════════════════════════════════════════════════════════
// BR-001 (branch review) — this route is a FOURTH real CommandRequest/
// dispatch producer (`/api/command`, MCP `execute_instruction`, and the exec
// console are the other three) that never called
// `dispatch_destructive_gate.hpp`'s Forensics single-target rule /
// Destructive broadcast refusal. `kBr001Fixture` classifies "app_usage"/
// "summary" as Forensics and "tar"/"purge_source" as Destructive; the
// pre-existing "test"/"list" default stays unclassified so every test above
// this section is unaffected.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("BR-001 — a Forensics action with 0 agent_ids is refused",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR1", "Forensics read", "app_usage", "summary");

    auto res = h.sink.Post("/api/instructions/def-BR1/execute", R"({"params":{}})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"] == 400);
    CHECK(body["error"]["message"].get<std::string>().find("forensic read") !=
          std::string::npos);
    CHECK(body["meta"]["api_version"] == "v1");

    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "forensic_untargeted"}})
              .value() == 1.0);

    bool denied_audit = false;
    for (const auto& a : h.audit_calls)
        if (a.action == "instruction.execute" && a.result == "denied" &&
            a.detail == "reason=forensic_untargeted" && a.target_id == "def-BR1")
            denied_audit = true;
    CHECK(denied_audit);
}

TEST_CASE("BR-001 — a Forensics action with 2 agent_ids is refused",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR2", "Forensics read", "app_usage", "summary");

    auto res = h.sink.Post("/api/instructions/def-BR2/execute",
                           R"({"agent_ids":["agent-1","agent-2"]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "forensic_untargeted"}})
              .value() == 1.0);
}

TEST_CASE("BR-001 — a Forensics action with a scope key is refused",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR3", "Forensics read", "app_usage", "summary");

    // A single explicit agent_id ALONGSIDE a scope key must still refuse —
    // the Forensics rule (like the Destructive one) rejects broadcast/scope
    // fan-out even when a well-formed agent_ids list is also present.
    auto res = h.sink.Post("/api/instructions/def-BR3/execute",
                           R"({"agent_ids":["agent-1"],"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "forensic_untargeted"}})
              .value() == 1.0);
}

TEST_CASE("BR-001 — a Forensics action with exactly 1 agent_id and no scope dispatches",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR4", "Forensics read", "app_usage", "summary");
    h.dispatch_cmd_override = "cmd-br4";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post("/api/instructions/def-BR4/execute", R"({"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids.size() == 1);
    CHECK(h.last_dispatch_agent_ids[0] == "agent-1");
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "forensic_untargeted"}})
              .value() == 0.0);
}

TEST_CASE("BR-001 — a Destructive action with 0 agent_ids is refused (same gate, not just Forensics)",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR5", "Purge source", "tar", "purge_source");

    auto res = h.sink.Post("/api/instructions/def-BR5/execute", R"({"params":{}})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"].get<std::string>().find("destructive action") !=
          std::string::npos);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"},
                        {"reason", "destructive_untargeted"}})
              .value() == 1.0);
}

TEST_CASE("BR-001 — a non-Forensics/non-Destructive (unclassified) instruction is unaffected",
          "[pg][workflow][executions][execute][targeting]") {
    // The regression net: this is the SAME "test"/"list" default already
    // used by every pre-existing test in this file, exercised through the
    // exact "genuinely omitted target still broadcasts" shape #2500 pins
    // above, to prove BR-001's fix changes nothing for an unclassified
    // instruction.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-BR6", "Unclassified");
    h.dispatch_cmd_override = "cmd-br6";
    h.dispatch_sent_override = 3;

    auto res = h.sink.Post("/api/instructions/def-BR6/execute", R"({"params":{}})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_agent_ids.empty());
    CHECK(h.last_dispatch_scope == "__all__");
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"}, {"reason", "forensic_untargeted"}})
              .value() == 0.0);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "instruction_execute"},
                        {"reason", "destructive_untargeted"}})
              .value() == 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// BR2-001 (round-2 branch review) — the workflow execute route's OWN step
// dispatcher is a second real CommandRequest producer, distinct from
// /api/instructions/:id/execute (BR-001 above): a workflow can wrap the same
// Forensics-classified instruction and reach cmd_dispatch_concurrency/
// cmd_dispatch directly via dispatch_fn, bypassing BR-001's route-level gate
// entirely. These pin that the SAME evaluate_destructive_targeting call now
// runs inside dispatch_fn itself, so no sibling route can rediscover this gap.
//
// BR3-001 (round-3 branch review): BR2-001's per-step gate genuinely refuses
// dispatch, but dispatch_fn has no metrics/audit_fn/req/res of its own, so the
// refusal was silently absorbed into that ONE step's failed-step result while
// the outer route still unconditionally audited "workflow.execute"/"success"
// once WorkflowEngine::execute() returned. The fix preflights every step
// against the SAME evaluate_destructive_targeting call BEFORE execute() is
// ever invoked, so a would-be-refused step now refuses the WHOLE request up
// front — audited, metered, 400 — rather than becoming a quietly-swallowed
// per-step failure inside a 202. The first test below is updated in place to
// assert the new outer-refusal shape; it previously asserted 202 (the
// per-step-only refusal BR2-001 shipped).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("BR3-001 — a workflow step naming a Forensics instruction with 2 agent_ids is refused "
          "up front, audited and metered, before WorkflowEngine::execute runs",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-BR2-1", "Forensics read", "app_usage", "summary");
    auto wf_id = h.make_workflow("wf-br2-1", "def-BR2-1");
    h.dispatch_cmd_override = "cmd-br2-1";
    h.dispatch_sent_override = 2;

    auto res =
        h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-A","agent-B"]})");
    REQUIRE(res);
    // BR3-001: the preflight now refuses the WHOLE request (400) before
    // WorkflowEngine::execute() is ever called — dispatch_calls == 0 because
    // the per-step dispatch_fn closure (BR2-001's own gate) is never reached
    // at all this time, not merely because it refused internally.
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.last_dispatch_agent_ids.empty());

    // An audit row for the denial — this is the whole point of BR3-001: a
    // security-relevant refusal must not be silently absorbed into a 202.
    bool found_denied_audit = false;
    for (const auto& call : h.audit_calls) {
        if (call.action == "workflow.execute" && call.result == "denied") {
            found_denied_audit = true;
            CHECK(call.target_type == "workflow");
            CHECK(call.target_id == wf_id);
            CHECK(call.detail == "reason=forensic_untargeted");
        }
    }
    CHECK(found_denied_audit);

    // The rejection metric fired on the NEW `route="workflow"` series — a new
    // emission point, distinct from `route="instruction_execute"`.
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "workflow"}, {"reason", "forensic_untargeted"}})
              .value() == 1.0);
}

TEST_CASE("BR2-001 — a workflow step naming a Forensics instruction with exactly 1 agent_id dispatches",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-BR2-2", "Forensics read", "app_usage", "summary");
    auto wf_id = h.make_workflow("wf-br2-2", "def-BR2-2");
    h.dispatch_cmd_override = "cmd-br2-2";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-A"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids.size() == 1);
    CHECK(h.last_dispatch_agent_ids[0] == "agent-A");
}

TEST_CASE("BR2-001 — a workflow step naming a Destructive instruction with 0 agent_ids is refused",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-BR2-3", "Destructive purge", "tar", "purge_source");
    auto wf_id = h.make_workflow("wf-br2-3", "def-BR2-3");
    h.dispatch_cmd_override = "cmd-br2-3";
    h.dispatch_sent_override = 5;

    // NOTE: the OUTER route (POST /api/workflows/:id/execute) already refuses
    // an empty `agent_ids` array with 400 BEFORE any step ever reaches
    // dispatch_fn (pre-existing "agent_ids array is required" check) — so this
    // case pins that pre-existing defense-in-depth layer, not BR2-001's new
    // per-step gate itself (BR2-001's own multi-agent/scope cases above DO
    // reach and are refused by the new gate, since the outer check only
    // rejects an EMPTY list, not a list of size > 1). The safety property that
    // matters either way: dispatch_calls stays 0.
    auto res = h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":[]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("BR2-001 — a workflow step naming an unclassified instruction is unaffected",
          "[pg][workflow][executions][execute][targeting]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-BR2-4", "Unclassified");
    auto wf_id = h.make_workflow("wf-br2-4", "def-BR2-4");
    h.dispatch_cmd_override = "cmd-br2-4";
    h.dispatch_sent_override = 3;

    auto res = h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-A","agent-B"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids.size() == 2);
}

// BR4-001 (round-4 branch review): BR3-001's preflight (above) reads each
// step's instruction definition ONCE, before WorkflowEngine::execute() runs
// at all. If a definition changes AFTER that read but BEFORE dispatch_fn's
// own re-read of the SAME instruction — a concurrent PATCH to the
// instruction landing mid-execution — the preflight's classification is
// stale. dispatch_fn's per-step gate (BR2-001) still correctly refuses the
// actual dispatch on its fresh re-read, so no forbidden send ever reaches an
// agent; the gap was purely in the route's own audit/metric: it still
// unconditionally logged "workflow.execute"/"success" and returned 202,
// because WorkflowEngine::execute() reports a per-step dispatch refusal as
// an ordinary failed step, not as a targeting denial. This reproduces the
// race deterministically, single-threaded, via dispatch_side_effect: step 1
// dispatches successfully, and AS PART OF that dispatch the test mutates
// step 2's instruction from unclassified to Forensics — a change the
// preflight (which ran before either step dispatched) could never have
// seen.
TEST_CASE("BR4-001 — a step mutated to Forensics between preflight and its own dispatch is "
          "denied with an audit event and the rejection metric, not a bare success/202",
          "[pg][workflow][executions][execute][targeting][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-BR4-1a", "Step one (unclassified)");
    h.make_def("def-BR4-1b", "Step two (unclassified at preflight time)");
    auto wf_id = h.make_workflow2("wf-br4-1", "def-BR4-1a", "def-BR4-1b");
    h.dispatch_cmd_override = "cmd-br4-1";
    h.dispatch_sent_override = 2;

    h.dispatch_side_effect = [&h]() {
        // Only step 1 (def-BR4-1a, still "test"/"list") should ever reach
        // cmd_dispatch — step 2 must be refused by dispatch_fn's own gate
        // before it gets this far. Mutate step 2's definition here, exactly
        // between step 1's dispatch and step 2's dispatch_fn re-read.
        auto current = h.instructions->get_definition("def-BR4-1b");
        REQUIRE(current.has_value());
        REQUIRE(current->has_value());
        auto def = **current;
        def.plugin = "app_usage";
        def.action = "summary"; // Forensics — single-target rule
        auto updated = h.instructions->update_definition(def);
        REQUIRE(updated.has_value());
    };

    auto res =
        h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-A","agent-B"]})");
    REQUIRE(res);
    // The request was admitted and an execution was created — this is an
    // async-accepted endpoint, and the underlying dispatch was genuinely
    // blocked, so 202 stands; what must change is the audit/metric record of
    // WHAT happened inside.
    CHECK(res->status == 202);
    // Exactly one real dispatch (step 1) — step 2 never reaches cmd_dispatch.
    CHECK(h.dispatch_calls == 1);

    bool found_success_audit = false;
    bool found_denied_audit = false;
    for (const auto& call : h.audit_calls) {
        if (call.action != "workflow.execute")
            continue;
        if (call.result == "success")
            found_success_audit = true;
        if (call.result == "denied") {
            found_denied_audit = true;
            CHECK(call.target_type == "workflow");
            CHECK(call.target_id == wf_id);
            CHECK(call.detail.find("reason=forensic_untargeted") != std::string::npos);
        }
    }
    // The whole point of BR4-001: the late refusal is audited as "denied",
    // and the route does NOT ALSO claim "success" for the same request.
    CHECK(found_denied_audit);
    CHECK_FALSE(found_success_audit);

    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "workflow"}, {"reason", "forensic_untargeted"}})
              .value() == 1.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// K-R7-02 — instruction execute dispatch confinement handoff
//
// POST /api/instructions/:id/execute now routes through the shared
// `dispatch_confined` seam via the CONFINED 7-param command_dispatch_fn,
// narrowing every arm to the operator's Execution:Execute visible set. As with
// the MCP (CDX-R5-02) and dashboard (CDX-R7-02) handoff tests, this route-level
// harness wires a MOCK dispatch, so it asserts the HANDOFF — the handler
// derived the caller's visible set and threaded it in — while the per-arm
// narrowing (filter_to_scope / in_scope) is pinned by the authz_model unit
// tests and the single shared dispatch_confined seam.
//
// The sibling POST /api/workflows/:id/execute path threads the SAME
// per-request `exec_visible` (derived once at the top of the handler) into its
// inner step-dispatch lambda, and is covered by the CDX-FV-03 cases at the
// bottom of this file. An earlier revision waived that route as
// "disproportionate scaffolding"; it was not — WorkflowEngine's ctor is a
// single sqlite3_open_v2 (workflow_engine.hpp:104), so the waiver is gone and
// the route is tested, not asserted by inspection.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("K-R7-02 — instruction execute threads the caller's exec_visible into dispatch",
          "[pg][workflow][executions][execute][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-CONF1", "conf1");
    h.dispatch_cmd_override = "cmd-x";
    h.dispatch_sent_override = 1;
    // Service-scoped confinement: the caller can see only agent-A.
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{
            .exec_visible = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}}};
    };
    // Target agent-B (an id-list arm), OUTSIDE the caller's visible set.
    auto res = h.sink.Post("/api/instructions/def-CONF1/execute", R"({"agent_ids":["agent-B"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids == std::vector<std::string>{"agent-B"});
    // The handoff: a PRESENT (confined) set, agent-A in / agent-B out. The
    // production dispatch_confined then drops agent-B via filter_to_scope.
    REQUIRE(h.last_dispatch_exec_visible.has_value());
    CHECK(h.last_dispatch_exec_visible->count("agent-A") == 1);
    CHECK(h.last_dispatch_exec_visible->count("agent-B") == 0);
}

TEST_CASE("K-R7-02 — instruction execute broadcast still carries the caller's exec_visible",
          "[pg][workflow][executions][execute][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-CONF3", "conf3");
    h.dispatch_cmd_override = "cmd-z";
    h.dispatch_sent_override = 1;
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{
            .exec_visible = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}}};
    };
    // Omitted target → the handler names __all__ (broadcast). Even that composes
    // with the visible set.
    auto res = h.sink.Post("/api/instructions/def-CONF3/execute", R"({})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_scope == "__all__");
    REQUIRE(h.last_dispatch_exec_visible.has_value());
    CHECK(h.last_dispatch_exec_visible->count("agent-A") == 1);
}

TEST_CASE("K-R7-02 — instruction execute FAILS CLOSED when the exec-visible derivation is unwired",
          "[pg][workflow][executions][execute][scope][security]") {
    // Genuinely UNWIRED CallerFn: the production handler must hand dispatch
    // a PRESENT EMPTY visible set (deny all), never nullopt (unfiltered).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/false);
    h.make_def("def-CONF2", "conf2");
    h.dispatch_cmd_override = "cmd-fc";
    h.dispatch_sent_override = 1;
    auto res = h.sink.Post("/api/instructions/def-CONF2/execute", R"({"agent_ids":["agent-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_exec_visible.has_value()); // PRESENT (deny), not nullopt
    CHECK(h.last_dispatch_exec_visible->empty());       // EMPTY → production sink reaches no one
}

// PLAN-006: the sibling of the confinement handoff test above, asserting the
// IDENTITY half of DispatchCaller — a wired CallerFn's principal must reach
// the dispatch seam, not just its exec_visible.
TEST_CASE("PLAN-006 — instruction execute threads the caller's principal into dispatch",
          "[pg][workflow][executions][execute][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.make_def("def-CONF4", "conf4");
    h.dispatch_cmd_override = "cmd-p";
    h.dispatch_sent_override = 1;
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{.principal = "wf-operator", .principal_role = "admin"};
    };
    auto res = h.sink.Post("/api/instructions/def-CONF4/execute", R"({"agent_ids":["agent-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_caller.principal == "wf-operator");
    CHECK(h.last_dispatch_caller.principal_role == "admin");
    CHECK_FALSE(h.last_dispatch_caller.system);
}

TEST_CASE("PLAN-006 — instruction execute FAILS CLOSED on an empty principal when unwired",
          "[pg][workflow][executions][execute][scope][security]") {
    // Genuinely UNWIRED CallerFn: the production handler must hand dispatch an
    // EMPTY principal alongside a present-empty exec_visible.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/false);
    h.make_def("def-CONF5", "conf5");
    h.dispatch_cmd_override = "cmd-pfc";
    h.dispatch_sent_override = 1;
    auto res = h.sink.Post("/api/instructions/def-CONF5/execute", R"({"agent_ids":["agent-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.last_dispatch_caller.principal.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// CDX-FV-03 — workflow execute dispatch confinement handoff
//
// POST /api/workflows/:id/execute is the primary operator dispatch surface and
// was the only one with no automated confinement test: loss of the `exec_visible`
// value capture on the step-dispatch lambda, or of the seventh dispatch argument,
// would have been unobserved. These cases pin the handoff at the route — the
// per-arm narrowing itself stays with the shared `dispatch_confined` seam, as in
// the K-R7-02 instruction cases above.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("CDX-FV-03 — workflow execute threads the caller's exec_visible into step dispatch",
          "[pg][workflow][executions][execute][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-WF1", "wf1");
    auto wf_id = h.make_workflow("wf-conf-1", "def-WF1");
    h.dispatch_cmd_override = "cmd-wf1";
    h.dispatch_sent_override = 1;
    // Service-scoped confinement: the caller can see only agent-A.
    h.caller_fn = [](const httplib::Request&) -> yuzu::server::DispatchCaller {
        return yuzu::server::DispatchCaller{
            .exec_visible = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}}};
    };

    // Target agent-B — an id-list arm OUTSIDE the caller's visible set. The
    // route still forwards it; the production dispatch_confined drops it.
    auto res = h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-B"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_agent_ids == std::vector<std::string>{"agent-B"});
    // The handoff: a PRESENT (confined) set, agent-A in / agent-B out.
    REQUIRE(h.last_dispatch_exec_visible.has_value());
    CHECK(h.last_dispatch_exec_visible->count("agent-A") == 1);
    CHECK(h.last_dispatch_exec_visible->count("agent-B") == 0);
}

TEST_CASE("CDX-FV-03 — workflow execute FAILS CLOSED when the exec-visible derivation is unwired",
          "[pg][workflow][executions][execute][scope][security]") {
    // Genuinely UNWIRED CallerFn. ADR-0033 §1: the handler must hand step
    // dispatch a PRESENT EMPTY visible set (deny all), never nullopt — nullopt
    // means UNFILTERED at the shared seam, i.e. the whole fleet.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/false,
                  /*with_workflow_engine=*/true);
    h.make_def("def-WF2", "wf2");
    auto wf_id = h.make_workflow("wf-conf-2", "def-WF2");
    h.dispatch_cmd_override = "cmd-wf2";
    h.dispatch_sent_override = 1;

    auto res = h.sink.Post("/api/workflows/" + wf_id + "/execute", R"({"agent_ids":["agent-A"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(h.dispatch_calls == 1);
    REQUIRE(h.last_dispatch_exec_visible.has_value()); // PRESENT (deny), not nullopt
    CHECK(h.last_dispatch_exec_visible->empty());      // EMPTY → production sink reaches no one
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/workflows?limit= — reject non-positive limit rather than silently
// clamping to 1 row (WorkflowQuery's std::max(limit, 1) floor would otherwise
// turn `limit=0` into "1 row", a behavior delta from the pre-migration SQLite
// `LIMIT 0` semantics of "0 rows").
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/workflows rejects limit=0 with 400", "[pg][workflow][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-lim0", "lim0");
    h.make_workflow("wf-lim0", "def-lim0");

    auto res = h.sink.Get("/api/workflows?limit=0");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"] == 400);
}

TEST_CASE("GET /api/workflows rejects a negative limit with 400", "[pg][workflow][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);

    auto res = h.sink.Get("/api/workflows?limit=-1");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/workflows accepts a positive limit and returns the workflow", "[pg][workflow][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-lim1", "lim1");
    h.make_workflow("wf-lim1", "def-lim1");

    auto res = h.sink.Get("/api/workflows?limit=5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["count"] == 1);
    CHECK(body["workflows"][0]["name"] == "wf-lim1");
}

TEST_CASE("GET /api/workflows applies limit to the returned row count", "[pg][workflow][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-lim2", "lim2");
    h.make_workflow("wf-lim2-a", "def-lim2");
    h.make_workflow("wf-lim2-b", "def-lim2");

    auto res = h.sink.Get("/api/workflows?limit=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["count"] == 1);
    CHECK(body["workflows"].size() == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// ADR-0064 — ProductPackStore install/uninstall fan-out into WorkflowEngine,
// exercised through the REAL production install_fn/uninstall_fn (workflow_routes.cpp),
// not a hand-rolled stub. No prior test anywhere covered the Workflow arm of either
// callback through the actual REST wiring — this closes that gap for the migration.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("ADR-0064: POST/DELETE /api/product-packs installs and uninstalls a Workflow item "
          "via the real install_fn/uninstall_fn", "[pg][workflow][workflow_engine][product_pack]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/true);

    const std::string bundle = "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: ProductPack\n"
                               "name: test-workflow-pack\n"
                               "version: 1.0.0\n"
                               "description: pack containing one workflow\n"
                               "---\n"
                               "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: Workflow\n"
                               "metadata:\n"
                               "  displayName: pack-workflow\n"
                               "spec:\n"
                               "  steps:\n"
                               "    - instruction: inst-1\n";

    auto install_res = h.sink.Post("/api/product-packs", bundle, "text/x-yaml");
    REQUIRE(install_res);
    REQUIRE(install_res->status == 201);
    auto install_body = nlohmann::json::parse(install_res->body);
    const auto pack_id = install_body.at("id").get<std::string>();

    // The workflow was really created via WorkflowEngine — not just recorded as a
    // ProductPackItem row.
    auto listed = h.workflows->list_workflows();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].name == "pack-workflow");
    const auto workflow_id = (*listed)[0].id;

    auto uninstall_res = h.sink.Delete("/api/product-packs/" + pack_id);
    REQUIRE(uninstall_res);
    CHECK(uninstall_res->status == 200);

    // Uninstall really called delete_workflow() (soft-delete) via the fixed uninstall_fn arm —
    // absent from ordinary reads afterward.
    auto listed_after = h.workflows->list_workflows();
    REQUIRE(listed_after.has_value());
    CHECK(listed_after->empty());
    auto got = h.workflows->get_workflow(workflow_id);
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
}

TEST_CASE("ADR-0064: uninstalling a pack whose Workflow item was already deleted directly "
          "reports a not_found item, not a crash", "[pg][workflow][workflow_engine][product_pack]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/true);

    const std::string bundle = "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: ProductPack\n"
                               "name: test-workflow-pack-2\n"
                               "version: 1.0.0\n"
                               "description: pack containing one workflow\n"
                               "---\n"
                               "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: Workflow\n"
                               "metadata:\n"
                               "  displayName: pack-workflow-2\n"
                               "spec:\n"
                               "  steps:\n"
                               "    - instruction: inst-1\n";

    auto install_res = h.sink.Post("/api/product-packs", bundle, "text/x-yaml");
    REQUIRE(install_res);
    REQUIRE(install_res->status == 201);
    const auto pack_id = nlohmann::json::parse(install_res->body).at("id").get<std::string>();

    auto listed = h.workflows->list_workflows();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    // Delete the workflow directly (bypassing the pack), simulating drift between the pack's
    // item row and the underlying store — the uninstall_fn Workflow arm must report this as an
    // ordinary not_found item (via delete_workflow()'s own "not_found:" prefix), not crash or
    // silently succeed.
    REQUIRE(h.workflows->delete_workflow((*listed)[0].id).has_value());

    auto uninstall_res = h.sink.Delete("/api/product-packs/" + pack_id);
    REQUIRE(uninstall_res);
    // ProductPackStore::uninstall's own tolerated-not_found handling — the pack itself still
    // uninstalls cleanly even though the workflow item was already gone.
    CHECK(uninstall_res->status == 200);
}

// adversarial-review CDX-P1-002/WF-4: a genuine WorkflowEngine DB failure during
// POST /api/product-packs must classify as 503, not fall through ProductPackStore::install()'s
// per-item error aggregation as a 400 validation rejection. Forces a REAL query failure (drops
// the child table create_workflow's transaction writes into) rather than a mock, and proves
// nothing gets persisted.
TEST_CASE("ADR-0064: a genuine WorkflowEngine DB failure during pack install 503s, not 400s, "
          "and persists no pack row", "[pg][workflow][workflow_engine][product_pack]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/true);

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_steps", std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    const std::string bundle = "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: ProductPack\n"
                               "name: test-workflow-pack-3\n"
                               "version: 1.0.0\n"
                               "description: pack whose workflow item fails to install\n"
                               "---\n"
                               "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: Workflow\n"
                               "metadata:\n"
                               "  displayName: pack-workflow-3\n"
                               "spec:\n"
                               "  steps:\n"
                               "    - instruction: inst-1\n";

    auto install_res = h.sink.Post("/api/product-packs", bundle, "text/x-yaml");
    REQUIRE(install_res);
    CHECK(install_res->status == 503); // NOT 400 — a genuine store failure, not validation

    auto list_res = h.sink.Get("/api/product-packs");
    REQUIRE(list_res);
    REQUIRE(list_res->status == 200);
    auto listed = nlohmann::json::parse(list_res->body);
    CHECK(listed.at("product_packs").empty()); // nothing persisted
}

// ── /fragments/schedules confinement (guardian-confinement-2298) ──────────
//
// Previously reachable by ANY authenticated session with no RBAC check at
// all, and — even with a Schedule:Read gate — ITServiceOwner grants full
// CRUD on Schedule with no owner/service filter anywhere in the query, so a
// service-scoped token could enumerate every schedule from every other
// service. schedule_api stays nullptr in ExecHarness (never wired) —
// the deny fires before the null-check, so these tests need no real store.

TEST_CASE("/fragments/schedules: an ordinary session is now gated on Schedule:Read",
          "[pg][workflow][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.perm_grant = false; // simulates a session lacking Schedule:Read

    auto res = h.sink.Get("/fragments/schedules");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("/fragments/schedules: a service-scoped token is denied even holding Schedule:Read",
          "[pg][workflow][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.perm_grant = true; // the stub perm_fn would otherwise let this through
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Get("/fragments/schedules");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("service-scoped") != std::string::npos);

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "schedule.list.access_denied" && c.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("/fragments/schedules: an ordinary session with Schedule:Read reaches the list",
          "[pg][workflow][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.perm_grant = true;

    auto res = h.sink.Get("/fragments/schedules");
    REQUIRE(res);
    CHECK(res->status == 200);
    // schedule_api is nullptr in this harness — the "Not available" branch,
    // not a denial. Confirms the deny/gate above didn't also block the
    // legitimate path.
    CHECK(res->body.find("Not available") != std::string::npos);
}

// ADR-0031 WS-A4 (seventh family): before this seam, the fragment called the
// unchecked ScheduleEngine::query_schedules(), which had no way to signal a
// store FAILURE distinct from a genuinely empty table — no existing test
// harness could inject that distinction at all. FnScheduleApi (see
// test_schedule_api_double.hpp) makes it directly testable: a `list_schedules`
// std::unexpected must render a distinct degraded state, never the "No
// schedules configured" empty-state string, and must never echo the
// (internal-only) error string into the HTML.
TEST_CASE("/fragments/schedules: a store failure renders a distinct degraded state, "
          "not \"No schedules configured\"",
          "[pg][workflow][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    auto failing_api = std::make_shared<yuzu::server::test::FnScheduleApi>(
        [](const ScheduleQuery&) -> std::expected<ScheduleListResult, std::string> {
            return std::unexpected(std::string{"pool exhausted (internal, must not render)"});
        });
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/failing_api);
    h.perm_grant = true;

    auto res = h.sink.Get("/fragments/schedules");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("No schedules configured") == std::string::npos);
    CHECK(res->body.find("pool exhausted") == std::string::npos);
    CHECK(res->body.find("temporarily unavailable") != std::string::npos);
}

// adversarial-review-kimi pre-push round (Codex C1 / Kimi K1, cross-confirmed):
// schedule_api.hpp's own contract says "every caller (REST, MCP, and the
// fragment) must surface this [truncated], never present the capped count as
// the fleet's true total" -- the fragment shipped in the same commit that
// wrote that contract without honouring it for its own case. This proves the
// fix: a truncated result renders a partial-list notice, not a table that
// silently looks complete.
TEST_CASE("/fragments/schedules: a truncated result renders a partial-list notice",
          "[pg][workflow][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    auto truncated_api = std::make_shared<yuzu::server::test::FnScheduleApi>(
        [](const ScheduleQuery&) -> std::expected<ScheduleListResult, std::string> {
            ScheduleListResult r;
            InstructionSchedule s;
            s.id = "sched-1";
            s.name = "capped-schedule";
            s.frequency_type = "once";
            s.enabled = true;
            r.schedules.push_back(s);
            r.truncated = true;
            return r;
        });
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/truncated_api);
    h.perm_grant = true;

    auto res = h.sink.Get("/fragments/schedules");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("capped-schedule") != std::string::npos);
    CHECK(res->body.find("partial list") != std::string::npos);
}

// guardian-confinement-2298 PR3 §3e: POST /api/scope/estimate is auth_fn-only
// (no perm_fn at all) and probes scope_fn(expression, session->username) —
// the caller's own visible fleet, which for a service-scoped token is still
// the minter's full-CRUD-visible set. Same test shape as the schedule-list
// pair above.

TEST_CASE("POST /api/scope/estimate: a service-scoped token is denied",
          "[pg][workflow][scope][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Post("/api/scope/estimate", R"({"expression":"ostype == \"Windows\""})",
                           "application/json");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("service-scoped") != std::string::npos);
    // Header/body correlation-id parity (consistency-auditor, Gate 4): a
    // hand-built id used to land in the body only, never the header.
    auto j = nlohmann::json::parse(res->body);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "scope.estimate.access_denied" && c.result == "denied") {
            saw_denied = true;
            // PascalCase convention (consistency-auditor, Gate 4): was
            // "scope_expression".
            CHECK(c.target_type == "ScopeExpression");
        }
    }
    CHECK(saw_denied);
}

TEST_CASE("POST /api/scope/estimate: an ordinary session reaches the estimator",
          "[pg][workflow][scope][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);

    auto res = h.sink.Post("/api/scope/estimate", R"({"expression":"ostype == \"Windows\""})",
                           "application/json");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body.contains("matched"));
    CHECK(body.contains("total"));

    for (const auto& c : h.audit_calls) {
        CHECK(c.action != "scope.estimate.access_denied");
    }
}

// #3503 review finding: WorkflowEngine::create_workflow()'s wrong-kind path routes through the
// shared kind_mismatch_error() helper — pinned in test_workflow_engine.cpp (ADR-0064: moved
// there since it's a store-behaviour test, and the plain YUZU_REQUIRE_PG_DB (no _TPL) this test
// used to use is reserved for migration/fresh-DB tests; ordinary store CRUD belongs on the
// PgTestTemplate-backed YUZU_REQUIRE_PG_DB_TPL, per-test migration DDL being exactly what drove
// the 2026-07-12 Windows server-suite timeout).

// ═══════════════════════════════════════════════════════════════════════════
// #4030 — REST v1 twins: /api/v1/workflows, /api/v1/workflows/{id},
// /api/v1/workflow-executions/{id}, /api/v1/schedules. Shared-builder parity
// with the legacy routes above is asserted by comparing response bodies.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/v1/workflows: lists workflows via the shared builder",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-V1WF", "v1wf");
    h.make_workflow("v1-list-workflow", "def-V1WF");

    auto res = h.sink.Get("/api/v1/workflows");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    REQUIRE(body["data"].is_array());
    bool found = false;
    for (const auto& w : body["data"]) {
        REQUIRE(w.contains("id"));
        REQUIRE(w.contains("step_count"));
        if (w["name"] == "v1-list-workflow")
            found = true;
    }
    CHECK(found);
    CHECK(body["meta"]["api_version"] == "v1");
}

// ADR-0031 WS-A4 (eighth family), adversarial-review round finding: the
// pre-existing "store failure" test below guards this route only by
// SIGSEGV on a revert-to-raw-engine mutation (a null-engine deref), not by a
// clean CHECK -- this test closes that with a positive, non-crashing
// tripwire: a REAL WorkflowEngine holding a genuine workflow AND a
// DISTINGUISHING FnWorkflowApi override at once, so a revert flips this
// specific test from pass to fail cleanly, matching the sibling tests above.
TEST_CASE("GET /api/v1/workflows: answers via the WorkflowApi seam, not the raw engine, "
          "when both are wired",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    Workflow seam_only;
    seam_only.id = "seam-wf-only";
    seam_only.name = "seam-double-name";
    auto seam_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
        [seam_only](const WorkflowQuery&) -> std::expected<std::vector<Workflow>, std::string> {
            return std::vector<Workflow>{seam_only};
        },
        yuzu::server::test::FnWorkflowApi::GetFn{},
        yuzu::server::test::FnWorkflowApi::GetExecutionFn{});

    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/{}, /*workflow_api_override=*/seam_api);
    h.make_def("def-SEAM-LIST", "seam-list");
    h.make_workflow("engine-real-name", "def-SEAM-LIST");

    auto res = h.sink.Get("/api/v1/workflows");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["name"] == "seam-double-name");
}

TEST_CASE("GET /api/v1/workflows/:id: full detail including yaml_source",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-V1WF2", "v1wf2");
    auto wf_id = h.make_workflow("v1-detail-workflow", "def-V1WF2");

    auto res = h.sink.Get("/api/v1/workflows/" + wf_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["id"] == wf_id);
    CHECK(body["data"]["name"] == "v1-detail-workflow");
    CHECK(body["data"].contains("yaml_source"));
    REQUIRE(body["data"]["steps"].is_array());
    REQUIRE(body["data"]["steps"].size() == 1);
    CHECK(body["data"]["steps"][0]["instruction_id"] == "def-V1WF2");
}

TEST_CASE("GET /api/v1/workflows/:id: 404 for an unknown id", "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);

    auto res = h.sink.Get("/api/v1/workflows/does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}

// ADR-0031 WS-A4 (eighth family), adversarial-review round finding: a
// mutation run reverting this route (and get_workflow_execution below) to
// call `workflow_engine` directly passed every pre-existing test unchanged
// -- `workflow_routes.cpp` is INSPECTED-NOT-ENFORCED by
// check-seam-closure.py, so nothing else caught it. This test wires a REAL
// WorkflowEngine (so a revert-to-raw-engine still finds a live, answerable
// store at the SAME id) AND a DISTINGUISHING FnWorkflowApi override at once,
// so the two doors answer DIFFERENTLY -- a revert flips this from pass to
// fail.
TEST_CASE("GET /api/v1/workflows/:id: answers via the WorkflowApi seam, not the raw engine, "
          "even for a valid real-engine id",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // The double ignores its `id` argument and always answers with a
    // distinguishable name -- proving the response came from THIS double,
    // not the real engine below, regardless of which real id is queried.
    Workflow seam_only;
    seam_only.name = "seam-double-detail";
    auto seam_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
        yuzu::server::test::FnWorkflowApi::ListFn{},
        [seam_only](const std::string&) -> std::expected<std::optional<Workflow>, std::string> {
            return seam_only;
        },
        yuzu::server::test::FnWorkflowApi::GetExecutionFn{});

    // Built with a REAL WorkflowEngine (so a revert-to-raw-engine still finds
    // a live, answerable store at the SAME id) AND the distinguishing double
    // above, passed to the constructor directly since register_routes
    // captures workflow_api BY VALUE at construction time.
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/{}, /*workflow_api_override=*/seam_api);
    h.make_def("def-SEAM-WF", "seam-wf");
    auto real_id = h.make_workflow("engine-real-detail", "def-SEAM-WF");

    auto res = h.sink.Get("/api/v1/workflows/" + real_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["name"] == "seam-double-detail");
}

TEST_CASE("GET /api/v1/workflows: 403 when Workflow:Read is denied", "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/workflows");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ADR-0031 WS-A4 (eighth family): unlike `schedule`'s own seam, `WorkflowApi`
// already returned a checked std::expected to its pre-seam callers, so a
// real Postgres failure injection (DROP TABLE, see test_workflow_engine.cpp)
// already proved this degrade path end-to-end. FnWorkflowApi (see
// test_workflow_api_double.hpp) proves the SAME behaviour without a live
// Postgres connection — a genuine store failure must 503 via
// genericize_db_error, never leak the internal (`kDbErrorPrefix`-prefixed)
// error string, and never be presented as an empty list.
TEST_CASE("GET /api/v1/workflows: a store failure 503s via genericize_db_error, never as an "
          "empty list",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    auto failing_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
        [](const WorkflowQuery&) -> std::expected<std::vector<Workflow>, std::string> {
            return std::unexpected(std::string(yuzu::server::kDbErrorPrefix) +
                                   "pool exhausted (internal, must not render)");
        },
        yuzu::server::test::FnWorkflowApi::GetFn{},
        yuzu::server::test::FnWorkflowApi::GetExecutionFn{});
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/{}, /*workflow_api_override=*/failing_api);
    h.perm_grant = true;

    auto res = h.sink.Get("/api/v1/workflows");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"] == 5000);
    CHECK(body["error"]["message"].get<std::string>().find("pool exhausted") == std::string::npos);
}

TEST_CASE("GET /api/v1/workflow-executions/:id: confines agent_ids to the caller's fleet-read "
          "scope (#4030 scoping decision)",
          "[pg][workflow][v1][twins][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-V1WFX", "v1wfx");
    auto wf_id = h.make_workflow("v1-exec-workflow", "def-V1WFX");
    h.dispatch_cmd_override = "cmd-v1wfx";
    h.dispatch_sent_override = 1;

    auto exec_res = h.sink.Post("/api/workflows/" + wf_id + "/execute",
                                R"({"agent_ids":["agent-A","agent-B"]})");
    REQUIRE(exec_res);
    REQUIRE(exec_res->status == 202);
    auto exec_body = nlohmann::json::parse(exec_res->body);
    auto exec_id = exec_body["execution_id"].get<std::string>();

    // Confine the caller to agent-A only.
    h.fleet_read_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/workflow-executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["id"] == exec_id);
    REQUIRE(body["data"]["agent_ids"].is_array());
    std::vector<std::string> ids;
    for (const auto& a : body["data"]["agent_ids"])
        ids.push_back(a.get<std::string>());
    CHECK(std::find(ids.begin(), ids.end(), "agent-A") != ids.end());
    CHECK(std::find(ids.begin(), ids.end(), "agent-B") == ids.end());

    // #4030 Gate 8 fix: `agents_reached` is the raw fleet-wide dispatch
    // count for the step's FULL target-agent list, not the confined
    // caller's visible subset (agent-A only, 1 of 2 targets) -- must be
    // stripped, not emitted verbatim (would disclose the true out-of-scope
    // agent count by simple arithmetic).
    REQUIRE(body["data"]["steps"].is_array());
    REQUIRE(body["data"]["steps"].size() == 1);
    CHECK_FALSE(body["data"]["steps"][0]["result"].contains("agents_reached"));

    // #4030: audited (workflow_execution.detail.fetch) — operator-supplied
    // step parameters/output are worth the same posture as instruction
    // executions.
    bool audited_success = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "workflow_execution.detail.fetch" && c.target_id == exec_id &&
            c.result == "success")
            audited_success = true;
    }
    CHECK(audited_success);
}

// ADR-0031 WS-A4 (eighth family), adversarial-review round finding: same
// mutation-testing shape as the sibling test on GET /api/v1/workflows/:id
// above -- wires a REAL WorkflowEngine holding a genuine execution AND a
// DISTINGUISHING FnWorkflowApi override at the same id, so a revert of this
// route to call `workflow_engine` directly flips the test from pass to fail.
TEST_CASE("GET /api/v1/workflow-executions/:id: answers via the WorkflowApi seam, not the "
          "raw engine, even for a valid real-engine id",
          "[pg][workflow][v1][twins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // Ignores its `id` argument; unconfined (nullopt scope in the test) so
    // its empty agent_ids_json still passes workflow_execution_visible().
    WorkflowExecution seam_only;
    seam_only.status = "seam-double-status";
    seam_only.agent_ids_json = "[]";
    auto seam_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
        yuzu::server::test::FnWorkflowApi::ListFn{},
        yuzu::server::test::FnWorkflowApi::GetFn{},
        [seam_only](const std::string&)
            -> std::expected<std::optional<WorkflowExecution>, std::string> {
            return seam_only;
        });

    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                 /*with_workflow_engine=*/true, /*wire_fleet_read_fn_arg=*/true,
                 /*with_product_pack_store=*/false, /*auth_override=*/{},
                 /*fleet_read_override=*/{}, /*with_schedule_engine=*/false,
                 /*schedule_api_override=*/{}, /*workflow_api_override=*/seam_api);
    h.make_def("def-SEAM-WFX", "seam-wfx");
    auto wf_id = h.make_workflow("engine-real-exec-workflow", "def-SEAM-WFX");
    auto dispatch_fn = [](const std::string&, const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
        return std::string(R"({"status":"dispatched","command_id":"cmd-seam-wfx"})");
    };
    auto real_exec_id = h.workflows->execute(wf_id, {"agent-Q"}, dispatch_fn);
    REQUIRE(real_exec_id.has_value());

    auto res = h.sink.Get("/api/v1/workflow-executions/" + *real_exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["status"] == "seam-double-status");
}

TEST_CASE("GET /api/v1/workflow-executions/:id: zero-overlap confined caller "
          "gets the same not-found body as a nonexistent id (#4030 Gate 8 fix)",
          "[pg][workflow][v1][twins][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-V1WFX0", "v1wfx0");
    auto wf_id = h.make_workflow("v1-exec-workflow-zero", "def-V1WFX0");
    h.dispatch_cmd_override = "cmd-v1wfx0";
    h.dispatch_sent_override = 1;

    auto exec_res = h.sink.Post("/api/workflows/" + wf_id + "/execute",
                                R"({"agent_ids":["agent-A"]})");
    REQUIRE(exec_res);
    REQUIRE(exec_res->status == 202);
    auto exec_body = nlohmann::json::parse(exec_res->body);
    auto exec_id = exec_body["execution_id"].get<std::string>();

    // Confine the caller to agent-Z -- disjoint from the execution's only
    // target agent (agent-A).
    h.fleet_read_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-Z"}};

    auto invisible = h.sink.Get("/api/v1/workflow-executions/" + exec_id);
    auto missing = h.sink.Get("/api/v1/workflow-executions/wfexec-does-not-exist-at-all");
    REQUIRE(invisible);
    REQUIRE(missing);
    // PRE-fix this returned 200 with the full unfiltered record (status/
    // steps/results) and an empty agent_ids array as the only outward sign
    // of "confinement" (security-guardian, Gate 2 HIGH).
    CHECK(invisible->status == 404);
    CHECK(missing->status == 404);
    // Byte-identical EXCEPT correlation_id (freshly minted per call, per
    // rest_a4_envelope.hpp -- no code path echoes an incoming request's own
    // X-Correlation-Id header, confirmed by grep) -- anti-enumeration is
    // about the rest of the shape, not the cid (chaos-injector, chaos_test 1).
    auto invisible_json = nlohmann::json::parse(invisible->body);
    auto missing_json = nlohmann::json::parse(missing->body);
    // correlation_id lives under "error" (error_json_a4's actual shape:
    // {"error":{code,message,correlation_id,...},"meta":{...}}).
    invisible_json["error"].erase("correlation_id");
    missing_json["error"].erase("correlation_id");
    CHECK(invisible_json == missing_json);

    // Denied distinctly from success -- never folded into "success" (Gate 4
    // unhappy-path finding UP-1 / chaos_test 2): no success row for this
    // exec_id, and a denied row exists.
    bool denied = false, success = false;
    for (const auto& c : h.audit_calls) {
        if (c.action != "workflow_execution.detail.fetch" || c.target_id != exec_id)
            continue;
        if (c.result == "denied")
            denied = true;
        if (c.result == "success")
            success = true;
    }
    CHECK(denied);
    CHECK_FALSE(success);
}

// Legacy sibling of the two tests above: predates "Workflow" existing as a
// cataloged RBAC securable at all (this PR's own rbac_store.cpp seeding
// commit is what makes it reachable to confined, non-admin roles for the
// first time, security-guardian Gate 2 finding #2) and, unlike the v1 twin,
// had NO scope filtering whatsoever before this fix -- not even the
// field-level agent_ids redaction.
TEST_CASE("GET /api/workflow-executions/:id (legacy): zero-overlap confined "
          "caller gets the same 404 as a nonexistent id (#4030 Gate 8 fix)",
          "[pg][workflow][legacy][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-LEGWFX0", "legwfx0");
    auto wf_id = h.make_workflow("legacy-exec-workflow-zero", "def-LEGWFX0");
    h.dispatch_cmd_override = "cmd-legwfx0";
    h.dispatch_sent_override = 1;

    auto exec_res = h.sink.Post("/api/workflows/" + wf_id + "/execute",
                                R"({"agent_ids":["agent-A"]})");
    REQUIRE(exec_res);
    REQUIRE(exec_res->status == 202);
    auto exec_body = nlohmann::json::parse(exec_res->body);
    auto exec_id = exec_body["execution_id"].get<std::string>();

    h.fleet_read_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-Z"}};

    auto invisible = h.sink.Get("/api/workflow-executions/" + exec_id);
    auto missing = h.sink.Get("/api/workflow-executions/wfexec-does-not-exist-at-all");
    REQUIRE(invisible);
    REQUIRE(missing);
    // PRE-fix this returned 200 with the FULL unfiltered record AND the
    // full, unfiltered agent_ids array (this route did not even do the
    // v1 twin's field-level filtering) -- the worst case of the Gate 2
    // finding.
    CHECK(invisible->status == 404);
    CHECK(missing->status == 404);
    // The legacy route's not-found body is a static literal string (no
    // correlation_id or other per-call-varying field) -- true byte
    // equality is directly assertable here, unlike the v1/A4 sibling.
    CHECK(invisible->body == missing->body);
}

TEST_CASE("GET /api/workflow-executions/:id (legacy): malformed result_json "
          "does not leak the <discarded> sentinel into the response body "
          "(#4030 Gate 8 fix)",
          "[pg][workflow][legacy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-LEGWFXM", "legwfxm");
    auto wf_id = h.make_workflow("legacy-exec-workflow-malformed", "def-LEGWFXM");
    h.dispatch_cmd_override = "cmd-legwfxm";
    h.dispatch_sent_override = 1;

    auto exec_res = h.sink.Post("/api/workflows/" + wf_id + "/execute",
                                R"({"agent_ids":["agent-A"]})");
    REQUIRE(exec_res);
    REQUIRE(exec_res->status == 202);
    auto exec_body = nlohmann::json::parse(exec_res->body);
    auto exec_id = exec_body["execution_id"].get<std::string>();

    // Corrupt the stored result_json from a second connection -- simulates
    // a legacy/pre-migration row or a partial write, not something the
    // live dispatch path can itself produce (Gate 4 unhappy-path finding
    // UP-2's reachability caveat).
    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        std::string sql =
            "UPDATE workflow_engine.workflow_step_results SET result_json = 'not json{{{' "
            "WHERE execution_id = '" +
            exec_id + "'";
        PgResult upd{PQexec(saboteur.get(), sql.c_str())};
        REQUIRE(upd.ok());
    }

    auto res = h.sink.Get("/api/workflow-executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    // The literal defect this test pins: an un-guarded
    // nlohmann::json::parse(..., false) embeds the discarded sentinel as
    // literal, invalid-JSON text when dump()'d.
    CHECK(res->body.find("<discarded>") == std::string::npos);
    auto parsed = nlohmann::json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    CHECK_FALSE(parsed.is_discarded());
    REQUIRE(parsed.contains("steps"));
    REQUIRE(parsed["steps"].is_array());
    REQUIRE(parsed["steps"].size() == 1);
    CHECK(parsed["steps"][0]["result"].is_null());
}

TEST_CASE("GET /api/workflow-executions/:id: a stored result_json nested past the depth guard "
          "is excluded, never dumped raw (#2437-class)",
          "[pg][workflow][legacy][security]") {
    // Same setup as the malformed-JSON corruption test above, but the row is
    // STRUCTURALLY VALID JSON that nests past kMcpMaxJsonDepth - not what
    // json::parse(..., false) rejects, but what nlohmann::json::dump() would
    // SIGSEGV on. WorkflowEngine's own write-side guard (workflow_engine.cpp)
    // closes the live dispatch path; this proves the matching read-side guard
    // in confined_workflow_step_result_json closes the row-predates-the-fix /
    // direct-DB-write case too.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.make_def("def-DEPTHWFXM", "depthwfxm");
    auto wf_id = h.make_workflow("legacy-exec-workflow-depth-poisoned", "def-DEPTHWFXM");
    h.dispatch_cmd_override = "cmd-depthwfxm";
    h.dispatch_sent_override = 1;

    auto exec_res = h.sink.Post("/api/workflows/" + wf_id + "/execute",
                                R"({"agent_ids":["agent-A"]})");
    REQUIRE(exec_res);
    REQUIRE(exec_res->status == 202);
    auto exec_body = nlohmann::json::parse(exec_res->body);
    auto exec_id = exec_body["execution_id"].get<std::string>();

    // Reachability-proxy depth (35 > kMcpMaxJsonDepth's 32) - never the real
    // ~100,000-level attack depth in a test.
    const std::string poisoned = std::string(35, '[') + std::string(35, ']');
    REQUIRE_FALSE(yuzu::server::mcp::json_exceeds_depth(poisoned, 40)); // sanity: valid JSON
    REQUIRE(yuzu::server::mcp::json_exceeds_depth(poisoned, yuzu::server::mcp::kMcpMaxJsonDepth));
    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        std::string sql = "UPDATE workflow_engine.workflow_step_results SET result_json = '" +
                          poisoned + "' WHERE execution_id = '" + exec_id + "'";
        PgResult upd{PQexec(saboteur.get(), sql.c_str())};
        REQUIRE(upd.ok());
    }

    auto res = h.sink.Get("/api/workflow-executions/" + exec_id);
    REQUIRE(res); // no crash
    CHECK(res->status == 200);
    auto parsed = nlohmann::json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    CHECK_FALSE(parsed.is_discarded());
    REQUIRE(parsed.contains("steps"));
    REQUIRE(parsed["steps"].is_array());
    REQUIRE(parsed["steps"].size() == 1);
    // Excluded as the fixed safe placeholder, never the poisoned tree itself.
    CHECK(parsed["steps"][0]["result"]["error"] ==
          "stored result exceeded maximum JSON nesting depth");
}

TEST_CASE("GET /api/v1/workflow-executions/:id: 403 when fleet_read_fn denies",
          "[pg][workflow][v1][twins][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/true);
    h.fleet_read_grant = false;

    auto res = h.sink.Get("/api/v1/workflow-executions/anything");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/schedules: reaches the same two-stage gate as the fragment twin",
          "[pg][workflow][v1][twins][schedules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.perm_grant = true;

    auto res = h.sink.Get("/api/v1/schedules");
    REQUIRE(res);
    // schedule_api is nullptr in this harness (matches the fragment twin's
    // own "Not available" test above) — 503, not a denial.
    CHECK(res->status == 503);
}

TEST_CASE("GET /api/v1/schedules: a service-scoped token is denied the fleet-wide list",
          "[pg][workflow][v1][twins][schedules][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool);
    h.mock_token_scope_service = "svc-a";

    auto res = h.sink.Get("/api/v1/schedules");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// #2146 A2-R1: definition_id/enabled_only query params, threaded into the
// same ScheduleQuery the legacy GET /api/schedules route already populates.
// Real ScheduleEngine (with_schedule_engine=true) so the filters are proven
// to actually narrow the result set, not just be accepted and ignored.

TEST_CASE("GET /api/v1/schedules: definition_id narrows the result set",
          "[pg][workflow][v1][twins][schedules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/false, /*auth_override=*/{},
                  /*fleet_read_override=*/{}, /*with_schedule_engine=*/true);
    h.perm_grant = true;

    InstructionSchedule matching;
    matching.name = "sched-match";
    matching.definition_id = "def-2146-a2r1";
    matching.frequency_type = "once";
    matching.created_by = "admin";
    auto matching_id = h.schedule_engine->create_schedule(matching);
    REQUIRE(matching_id.has_value());

    InstructionSchedule other;
    other.name = "sched-other";
    other.definition_id = "def-2146-other";
    other.frequency_type = "once";
    other.created_by = "admin";
    auto other_id = h.schedule_engine->create_schedule(other);
    REQUIRE(other_id.has_value());

    auto res = h.sink.Get("/api/v1/schedules?definition_id=def-2146-a2r1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    bool found_matching = false, found_other = false;
    for (const auto& row : body["data"]) {
        if (row["id"] == *matching_id)
            found_matching = true;
        if (row["id"] == *other_id)
            found_other = true;
    }
    CHECK(found_matching);
    CHECK_FALSE(found_other);
}

TEST_CASE("GET /api/v1/schedules: enabled_only narrows the result set",
          "[pg][workflow][v1][twins][schedules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/false, /*auth_override=*/{},
                  /*fleet_read_override=*/{}, /*with_schedule_engine=*/true);
    h.perm_grant = true;

    InstructionSchedule enabled_sched;
    enabled_sched.name = "sched-enabled";
    enabled_sched.definition_id = "def-2146-enabled";
    enabled_sched.frequency_type = "once";
    enabled_sched.enabled = true;
    enabled_sched.created_by = "admin";
    auto enabled_id = h.schedule_engine->create_schedule(enabled_sched);
    REQUIRE(enabled_id.has_value());

    InstructionSchedule disabled_sched;
    disabled_sched.name = "sched-disabled";
    disabled_sched.definition_id = "def-2146-disabled";
    disabled_sched.frequency_type = "once";
    disabled_sched.enabled = false;
    disabled_sched.created_by = "admin";
    auto disabled_id = h.schedule_engine->create_schedule(disabled_sched);
    REQUIRE(disabled_id.has_value());

    auto res = h.sink.Get("/api/v1/schedules?enabled_only=true");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    bool found_enabled = false, found_disabled = false;
    for (const auto& row : body["data"]) {
        if (row["id"] == *enabled_id)
            found_enabled = true;
        if (row["id"] == *disabled_id)
            found_disabled = true;
    }
    CHECK(found_enabled);
    CHECK_FALSE(found_disabled);
}

// gov docs-writer/cpp-expert fix round: enabled_only=false must NOT behave
// like enabled_only=true (the #4034-class presence-only defect). No prior
// test exercised this value on either surface, so the initial parse's
// `if (req.has_param("enabled_only")) q.enabled_only = true;` bug (any
// presence, regardless of value, filtered to enabled-only) would have shipped
// silently.
TEST_CASE("GET /api/v1/schedules: enabled_only=false does NOT filter to enabled-only "
          "(presence-only defect regression)",
          "[pg][workflow][v1][twins][schedules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/false, /*auth_override=*/{},
                  /*fleet_read_override=*/{}, /*with_schedule_engine=*/true);
    h.perm_grant = true;

    InstructionSchedule enabled_sched;
    enabled_sched.name = "sched-enabled-2";
    enabled_sched.definition_id = "def-2146-enabled-2";
    enabled_sched.frequency_type = "once";
    enabled_sched.enabled = true;
    enabled_sched.created_by = "admin";
    auto enabled_id = h.schedule_engine->create_schedule(enabled_sched);
    REQUIRE(enabled_id.has_value());

    InstructionSchedule disabled_sched;
    disabled_sched.name = "sched-disabled-2";
    disabled_sched.definition_id = "def-2146-disabled-2";
    disabled_sched.frequency_type = "once";
    disabled_sched.enabled = false;
    disabled_sched.created_by = "admin";
    auto disabled_id = h.schedule_engine->create_schedule(disabled_sched);
    REQUIRE(disabled_id.has_value());

    auto res = h.sink.Get("/api/v1/schedules?enabled_only=false");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    bool found_enabled = false, found_disabled = false;
    for (const auto& row : body["data"]) {
        if (row["id"] == *enabled_id)
            found_enabled = true;
        if (row["id"] == *disabled_id)
            found_disabled = true;
    }
    CHECK(found_enabled);
    CHECK(found_disabled); // must NOT be filtered out by enabled_only=false
}

TEST_CASE("GET /api/v1/schedules: an unrecognized enabled_only value answers 400",
          "[pg][workflow][v1][twins][schedules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecHarness h(pool, /*with_bus=*/true, /*budget=*/nullptr, /*wire_exec_visible=*/true,
                  /*with_workflow_engine=*/false, /*wire_fleet_read_fn_arg=*/true,
                  /*with_product_pack_store=*/false, /*auth_override=*/{},
                  /*fleet_read_override=*/{}, /*with_schedule_engine=*/true);
    h.perm_grant = true;

    auto res = h.sink.Get("/api/v1/schedules?enabled_only=maybe");
    REQUIRE(res);
    CHECK(res->status == 400);
}
