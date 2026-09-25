#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

#include "stream_budget.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp" // ListReadGate — ADR-0017 list-read gate result type
#include "authz_model.hpp"
#include "dispatch_caller.hpp"
#include "device_token_store.hpp"
#include "dex_perf_model.hpp"
#include "network_api.hpp" // ADR-0031 WS-A4: the public in-process /network API seam
#include "verify_api.hpp" // ADR-0031 WS-A4: the public in-process VERIFY API seam
#include "dex_api.hpp"    // ADR-0031 WS-A4: the public in-process DEX signals API seam
#include "dex_perf_api.hpp" // ADR-0031 WS-A4: the public in-process DEX app-perf-over-time API seam
#include "device_api.hpp" // ADR-0031 WS-A4 wave 2: the public in-process DEVICE API seam
#include "guardian_api.hpp" // ADR-0031 WS-A4 (ninth family): the public in-process Guardian-read API seam
#include "network_perf_model.hpp"
#include "execution_tracker.hpp"
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "license_store.hpp"
#include "management_group_store.hpp"
#include "product_pack_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "result_set_store.hpp"
#include "schedule_engine.hpp"
#include "software_deployment_store.hpp"
#include "mfa_step_up.hpp"
#include "tag_store.hpp"

// W5.1 — `/api/v1/events` JSON SSE consumes the per-execution event bus.
// Forward-declared to avoid pulling the bus header into every TU that
// already includes rest_api_v1.hpp (test fixtures, server.cpp).
//
// **Lifetime contract:** the bus pointer threaded into `register_routes`
// is BORROWED. The caller MUST keep the bus alive until every SSE
// response has fully unwound. This is non-obvious because httplib runs
// the resource-release closure on a worker thread AFTER the handler
// returns — `bus->unsubscribe(...)` in that closure dereferences the
// borrowed pointer. In production this holds because `ServerImpl::stop()`
// joins the httplib worker pool (`web_server_->stop()` +
// `web_thread_.join()` at `server.cpp:1664-1668`) BEFORE resetting the
// bus (`execution_event_bus_.reset()` at `server.cpp:1712`). Note that
// member-declaration order does NOT enforce this — `web_server_` is
// declared before `execution_event_bus_` (`server.cpp:6206` vs `:6247`),
// so destructor-only ordering would tear down the bus FIRST. The
// explicit shutdown sequence is the load-bearing invariant. Any test
// fixture that drops the bus before draining httplib breaks the
// contract, as would removing the explicit `stop()` call. governance
// round R1 security-LOW-3 / cpp-expert-M-1; R2 cpp-expert noted the
// declaration-order inaccuracy and the doc was corrected to cite the
// explicit shutdown sequence.
namespace yuzu::server {
class ExecutionEventBus;
// Name-anchored per-device Guardian status route borrows the BaselineStore.
// Forward-declared (used only as a pointer in register_routes); the .cpp includes
// baseline_store.hpp for the definition.
class BaselineStore;
// ADR-0016: the typed daily-sync software store backs GET /api/v1/inventory/software.
// Forward-declared (pointer-only in register_routes); the .cpp includes the header.
class SoftwareInventoryStore;
// EnginePrincipalStore backs BOTH surfaces (4.2→4.3 rebase coexistence): the
// PR 4.2 fleet-wide role-assignment routes (/api/v1/engine-principals/{id}/roles,
// which validate the target id before RbacStore::assign_role) capture the
// register_routes PARAM; the PR 4.3 lifecycle routes (/api/v1/engine-principals)
// use the MEMBER threaded via set_engine_principal_store. Forward-declared;
// the .cpp includes engine_principal_store.hpp.
class EnginePrincipalStore;
// Periodic Access Reviews (SOC 2 CC6.2). AccessReviewStore is the campaign
// persistence (open/attest/close); DirectorySync is optional read-model
// enrichment (user email best-effort). Both forward-declared (pointer-only in
// register_routes); the .cpp includes access_review_store.hpp /
// directory_sync.hpp. AuthDB is already forward-declared by the
// <yuzu/server/auth.hpp> include above.
class AccessReviewStore;
class DirectorySync;
}

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace detail {
// --- /api/v1/dex/devices/{id}/live tuning (TEST SEAM, not a request knob) ---
// The synchronous live-read handler bounds its blast radius with an in-flight cap
// (UP-1/2/3: keeps httplib workers free for the dashboard, SSE and health probes)
// and a bounded poll. These default to production values; unit tests lower them to
// exercise the 429 (cap) and 504 (timeout) branches without real concurrency or a
// ~20s wall. Process-global by design — the cap is a whole-server budget.
std::atomic<int>& live_max_inflight();     // default 4 (strictly below the worker pool)
std::atomic<int>& live_poll_max_polls();   // default 40
std::atomic<int>& live_poll_interval_ms(); // default 500
} // namespace detail

/// Versioned REST API v1 — registers all /api/v1/ routes on the httplib::Server.
class RestApiV1 {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Per-device-scoped permission check (mirrors DeviceRoutes::ScopedPermFn): a
    /// global grant passes fleet-wide, otherwise the principal must hold the
    /// permission via a management group the agent is in. Per-device REST reads gate
    /// on this so a management-group-scoped operator is not fail-closed out of
    /// devices they can legitimately see. The empty/default `{}` exists ONLY for
    /// source-stability of the other (unrelated) call sites — a route that requires
    /// this gate treats an unwired fn as misconfiguration and FAILS CLOSED (503); it
    /// does NOT silently fall back to the flat PermFn (that would re-introduce the
    /// group-scoped lockout this typedef exists to fix). See the device-compliance
    /// route in rest_api_v1.cpp for the fail-closed contract.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    /// ADR-0017 admit-then-filter list-read gate for a list/fan-out route
    /// over per-agent data (`AuthRoutes::require_list_read`). Unlike PermFn/
    /// ScopedPermFn (bool: caller re-derives the session separately if
    /// needed), this returns a `ListReadGate` carrying `admitted`, the
    /// resolved `scope` (nullopt = unfiltered; engaged, incl. empty, INV-2 =
    /// filter to exactly these agents), and the resolved `session`. This
    /// MUST be the route's SOLE authorization gate — never stacked with
    /// PermFn (require_permission's check_permission never consults
    /// ManagementGroupStore, so the two gates do not compose; see
    /// require_list_read's doc comment). The empty/default `{}` exists ONLY
    /// for source-stability of unrelated call sites — a route that requires
    /// this gate treats an unwired fn as misconfiguration and FAILS CLOSED
    /// (503), mirroring ScopedPermFn's contract above.
    using ListReadFn =
        std::function<ListReadGate(const httplib::Request&, httplib::Response&,
                                   const std::string& securable_type,
                                   const std::string& operation)>;
    /// #3290 Phase 2 — the injected-callback twin of `AuthRoutes::require_fleet_read`
    /// (see `authz::FleetReadGate`'s doc comment, authz_gates.hpp, for why this is a
    /// plain fakeable aggregate rather than `ListAuthority` itself). MUST be the
    /// route's SOLE authorization gate — never stacked with `PermFn` for the same
    /// `(securable_type, operation)` (the identical BLOCKING defect `ListReadFn`
    /// above exists to avoid; `require_fleet_read`'s own doc comment has the
    /// falsifier). The empty/default `{}` exists ONLY for source-stability of
    /// unrelated call sites — a route that requires this gate treats an unwired fn
    /// as misconfiguration and FAILS CLOSED (503), mirroring `ListReadFn`'s contract.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    /// #4033 (#2146 Batch A) — the raw AgentRegistry snapshot, SAME shape/
    /// SAME underlying call as MCP's `AgentsJsonFn`/`agents_fn()`
    /// (`registry_.to_json_obj()`, 5 fields per agent: agent_id/hostname/os/
    /// arch/agent_version). `GET /api/v1/devices`/`GET /api/v1/devices/{id}`
    /// filter this UNFILTERED snapshot themselves via `fleet_read_fn`'s
    /// returned scope (`authz::in_scope`) — deliberately NOT the dashboard's
    /// own `get_visible_agents_json`-style pre-filtered `DevicesFn`
    /// (`DeviceRoutes`), whose management-group-only join lacks
    /// `require_fleet_read`'s service-scope/elevated/engine/mcp_tier caller-
    /// class branches (see the route's own comment in rest_api_v1.cpp).
    /// Empty/default `{}` = the two routes answer 503 (misconfiguration).
    using AgentsJsonFn = std::function<nlohmann::json()>;
    /// #4033 — D3 Response:Read-visible agent SET resolver for the create-
    /// group agent-count preview (`GET /api/v1/management-groups/agent-count-
    /// preview` + its MCP twin), mirroring `DashboardRoutes::VisibleSetFn`
    /// EXACTLY (same doc contract: `nullopt` = caller sees all agents —
    /// RBAC legacy-open or a global `Response:Read` grant; a present-but-
    /// EMPTY set = fail-closed on a degraded store, never silently widened
    /// to `nullopt`). Anchored on `Response:Read`, not `Infrastructure:Read`
    /// — reusing `fleet_read_fn`'s `Infrastructure`-anchored scope here would
    /// hand a global-Response:Read holder a stricter view than the fragment
    /// this route twins (`/fragments/create-group-form`) already gives them.
    /// Callers additionally short-circuit to `nullopt` for an ELEVATED
    /// session (JIT full-fleet view — `auth::is_elevated`), matching
    /// `DashboardRoutes::resolve_visible_scope(const auth::Session&)`
    /// exactly; this fn itself is the username-only half. Empty/default `{}`
    /// = legacy-open (`nullopt`), matching an unwired `DashboardRoutes`
    /// fixture's behaviour.
    using ResponseVisibleSetFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;
    /// Per-agent Response-scope predicate for the fan-out response/execution
    /// readers (e.g. GET /api/v1/executions/{id}/visualization, which charts an
    /// instruction's responses across every agent that replied). Returns true
    /// iff `username` may see `agent_id`'s rows via a management group. A FILTER,
    /// not a gate: it writes no response and is invoked per result row to drop
    /// out-of-scope agents before the chart transform, exactly mirroring the MCP
    /// query_responses scope fn (server.cpp wires the SAME check_scoped_permission
    /// chokepoint, bound to ("Response","Read")). Empty/default `{}` = no filter
    /// (legacy-open, matching the MCP default + require_scoped_permission) —
    /// production wires it from server.cpp. NOTE (#1634): this filter is the
    /// FOUNDATION for management-group scoping but is INERT under the current global
    /// `Response:Read` gate — a global holder passes the gate and check_scoped_permission's
    /// global step then admits every agent (no-op), while a management-group-confined
    /// operator is 403'd at the gate before this runs. Its only active effect today is
    /// failing CLOSED on a corrupt/load-failed rbac.db. It becomes effective once the
    /// admit-then-filter gate for fan-out reads lands (the remaining #1634 work).
    using ResponseScopeFn =
        std::function<bool(const std::string& username, const std::string& agent_id)>;
    /// #1788: derives the caller's dispatch-confinement VisibleSet (nullopt =
    /// unfiltered, present-empty = deny-all — ADR-0033 §1), the SAME primitive
    /// `ServerImpl::derive_exec_visible` feeds into `/api/command` and every MCP
    /// dispatch surface. EVERY dispatching route in this file derives from it;
    /// what an unwired callback means differs by route CLASS, and the difference
    /// is deliberate:
    ///
    ///   - Routes whose primary authorization is the per-target `scoped_perm_fn`
    ///     gate (POST /api/v1/bundles, the TAR retention purge, the live device
    ///     query) thread this in as a SECOND, independent confinement check —
    ///     defense-in-depth. Unwired substitutes a present-EMPTY set (deny-all),
    ///     NEVER nullopt: ADR-0033 §1 forbids reading a missing derivation as
    ///     "no filter". `scoped_perm_fn` already 500s when IT is unwired, so the
    ///     primary gate reports the misconfiguration.
    ///   - The async result-set producers (`from-tar-query`,
    ///     `from-instruction-result`, `{id}/re-eval`) admit on a bare GLOBAL
    ///     `perm_fn("Execution","Execute")` and dispatch by scope/broadcast, so
    ///     this derivation is their ONLY per-device authorization — the PRIMARY
    ///     gate. Unwired there is a server misconfiguration and answers an
    ///     audited 500, matching how those routes' siblings treat a missing
    ///     `scoped_perm_fn`, rather than silently reporting "no agents reached".
    ///
    /// A test harness wanting genuinely unfiltered dispatch wires a callback
    /// that RETURNS nullopt; leaving the callback empty is not a synonym for it.
    using ExecVisibleFn = std::function<yuzu::server::authz::VisibleSet(const auth::Session&)>;
    /// Audit-event callback. Returns true iff the event was persisted
    /// (or the deployment runs audit-off — both look the same to a
    /// caller, see `AuthRoutes::audit_log` doc). Returns false on a
    /// silent persistence failure (audit DB locked / disk full /
    /// corruption). SOC 2 CC6.6 evidence-emitting handlers MUST capture
    /// this return and surface partial-success on the response so
    /// operators don't read a "201 Created" / "200 OK" as compliance
    /// evidence the audit row landed (HIGH-2 on PR #883, UP-H1 on
    /// PR W1.1). Pre-PR #883 this typedef was `void(...)`; existing
    /// call sites that fire-and-forget continue to work — the bool is
    /// just discarded.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using ServiceGroupFn = std::function<void(const std::string& service_value)>;
    using TagPushFn = std::function<void(const std::string& agent_id, const std::string& key)>;
    /// Guardian rule push fan-out (contract step 3 / G12): resolve the scope →
    /// in-scope agents, build the GuaranteedStatePush from the store, and deliver via
    /// the agent dispatch path. Returns the number of agents pushed to, or -1 on an
    /// invalid scope expression. Injected from server.cpp where the registry/scope live.
    using GuardianPushFn = std::function<int(const std::string& scope, bool full_sync)>;
    // ADR-0031 WS-A4 (fifth family): the former `DexFleetFn` register_routes
    // param is RETIRED. The DEX read handlers now route through the `DexApi`
    // seam, which obtains the fleet denominator via its OWN FleetFn (wired into
    // make_local_dex_api in server.cpp) — so no fleet provider is threaded into
    // register_routes anymore. (DexRoutes' dashboard fragments still use their
    // own fleet provider directly; that rewire is deferred, ISSUE #4576.)
    /// #4035 hardening (governance): the SAME username-keyed visible-agent-set
    /// resolver `DexRoutes::register_routes`'s own `resolve_visible` (dex_routes.cpp)
    /// already applies to confine `/fragments/dex/app`'s and
    /// `/fragments/dex/overview`'s device-id lists to the caller's management-group
    /// scope (ADR-0017 World A) — GET /api/v1/dex/app and GET /api/v1/dex/overview
    /// enumerate the identical affected/top-devices lists and MUST apply the same
    /// confinement, not just the sibling service-scoped-token deny belt
    /// (`deny_fleet_wide_service_scoped`). Two independent belts are required
    /// together, per the SCOPING NOTE on the `dex_visible_fn` provider in server.cpp:
    /// this fn closes the management-group-confined-OPERATOR axis,
    /// `deny_fleet_wide_service_scoped` closes the service-scoped-API-token axis —
    /// neither substitutes for the other. `nullopt` = unfiltered (global read /
    /// RBAC off, or the session could not be resolved); engaged (incl. empty) =
    /// filter to exactly these agents. Trailing optional (`{}`) for
    /// source-stability of existing call sites/tests — a route that needs it
    /// treats an unwired fn as "no confinement" (matching the fragment's own
    /// unwired-`visible_set_fn_` posture), never a crash.
    using DexVisibleFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;

    /// Outcome of a session-revocation REST call. `cookie_sessions_revoked`
    /// is the number of in-memory cookie sessions wiped (the operationally
    /// meaningful "active session" count). `api_tokens_revoked` is the
    /// number of API tokens marked revoked for the principal — non-zero
    /// only when the caller asked for full-principal revocation
    /// (`/me`'s "Sign out everywhere"; admin force-logout deliberately
    /// leaves automation tokens intact). `db_persisted` reports whether
    /// the AuthDB DELETE for cookie sessions succeeded; `api_tokens_db_persisted`
    /// reports the SAME for the API-token revoke leg — kept as its OWN field
    /// rather than folded into `db_persisted`, because the two writes hit
    /// independent stores (AuthDB vs `api_token_store`) and either can fail
    /// alone. When EITHER is false the caller MUST surface it in the audit row
    /// (a "success" row hiding a failed API-token revoke tells an operator who
    /// revoked a stolen laptop that every credential died when it did not —
    /// fictional CC6.3/CC6.6 evidence, and the exact failure ADR-0030 §Posture
    /// forbids). `api_tokens_db_persisted` is vacuously true when API-token
    /// revocation was not requested (the admin force-logout path).
    struct SessionRevokeResult {
        std::size_t cookie_sessions_revoked{0};
        std::size_t api_tokens_revoked{0};
        bool db_persisted{true};
        bool api_tokens_db_persisted{true};
    };

    /// Carrier for the audit-emission outcome on a session-revocation
    /// response. Populated by the handler from the AuditFn return value
    /// (and an exception try/catch). Distinct from `SessionRevokeResult`
    /// because the audit emission happens AFTER the revoke primitive
    /// completes — operator's "stop NOW" still takes effect even when
    /// the SOC 2 evidence row is lost (HIGH-2 on PR #883).
    struct AuditEmission {
        bool emitted{true};
        // True iff AuditFn threw — distinguishes silent persist failure
        // from an exception path. Both produce `emitted=false` and the
        // `Sec-Audit-Failed: true` response header; the `threw` flag is
        // only surfaced in the spdlog trail.
        bool threw{false};
    };

    /// Revoke every credential bearing a username — cookie sessions
    /// (`AuthManager::invalidate_user_sessions`) and, when
    /// `revoke_api_tokens=true`, the user's API tokens (closes UP-13:
    /// "Sign out everywhere" must mean everywhere, not just browser
    /// cookies). Empty/missing callback = endpoint returns 503.
    using SessionRevokeFn =
        std::function<SessionRevokeResult(const std::string& username, bool revoke_api_tokens)>;

    /// Clear a user's account-lockout counter (admin unlock — SOC 2 CC6.3).
    /// Wraps `AuthDB::clear_failed_logins` so RestApiV1 stays decoupled from
    /// AuthDB (same injection pattern as SessionRevokeFn). Returns true when
    /// the underlying auth.db write succeeded. Empty/missing callback =
    /// `POST /api/v1/users/<name>/unlock` returns 503.
    using LockoutClearFn = std::function<bool(const std::string& username)>;

    /// PR 4.3 — wraps `AuthDB::user_exists` so RestApiV1 stays decoupled from
    /// AuthDB (same injection pattern as `SessionRevokeFn`/`LockoutClearFn`
    /// immediately above). Used by the engine-principal create/transfer-owner
    /// routes to validate an owner-FK (`owner_username`/`new_owner`) against
    /// the real user store BEFORE the mutating store call — an engine
    /// principal's owner must be a named, existing human
    /// (`docs/auth-engine-principals-design.md` §3.1). Empty/unset callback
    /// = those routes cannot verify the FK and fail closed (503), same
    /// posture as every other unwired-Fn call site in this file.
    using UserExistsFn = std::function<bool(const std::string& username)>;

    /// Command dispatch callback — sends a CommandRequest to agents via gRPC
    /// and returns (command_id, agents_reached). Identical signature to
    /// `WorkflowRoutes::CommandDispatchFn`; the server threads the SAME hoisted
    /// caller-carrying closure (`command_dispatch_caller_fn`) into both, so
    /// every REST dispatch surface narrows to the caller's reach through the one
    /// `dispatch_confined_arms` seam. The trailing `execution_id` is registered
    /// command_id→execution_id BEFORE any RPC so FAST loopback agents can't
    /// reply before the mapping lands (UP2-4). Empty callback leaves the async
    /// producer routes returning 503.
    ///
    /// #1788 / the review finding this signature exists to make impossible: the
    /// trailing `exec_visible` is NOT optional. `RestApiV1` was previously
    /// handed the 6-arg SYSTEM closure, which hardcodes `exec_visible=nullopt`
    /// (unfiltered — correct for background engines, never for an operator
    /// surface), and the async result-set producers dispatched through it — so
    /// a service-scoped token admitted by the global `Execution:Execute` gate
    /// reached the WHOLE fleet. The fix is not a check bolted onto those
    /// routes: it is that no unconfined closure is reachable from this class
    /// any more, so a future dispatch caller cannot pick the wrong one.
    ///
    /// Callers MUST NOT pre-intersect their own target list — resolution stays
    /// here, the intersection belongs to `dispatch_confined_arms` (see that
    /// header's docstring on why a second copy is the drift class). Broadcast
    /// and scope arms could not be confined route-locally in any case: the
    /// candidate set lives in the server's AgentRegistry, not in this file.
    /// PR1.9c: the trailing parameter carries the CALLER (identity + visible
    /// set), not the visible set alone. It has to:
    /// `ServerImpl::build_classified_command` refuses an empty
    /// `DispatchCaller::principal` as `AnonymousOperator` BEFORE the
    /// legacy-open/RBAC-off bypass, so a VisibleSet-only signature left every
    /// REST dispatch here undeliverable — reported as `503 "device offline"` on
    /// a healthy connected agent. The other three dispatch surfaces (MCP,
    /// dashboard, workflow) were widened by PR1.9b′; this one was deferred at
    /// the time, and that deferral WAS the defect rather than a boundary.
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller)>;

    /// Production overload — constructs an HttplibRouteSink and delegates
    /// to the sink-based overload below.
    ///
    /// `metrics_registry` (optional, may be null) — when non-null the token-
    /// create handlers increment `yuzu_secure_random_failure_total{site=...}`
    /// on CSPRNG entropy-exhaustion failures so SRE on-call has a paging
    /// signal short of grepping audit logs (sre-1 on PR W1.1).
    void register_routes(
        httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
        RbacStore* rbac_store, ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
        QuarantineStore* quarantine_store, ResponseStore* response_store,
        InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
        ScheduleEngine* schedule_engine, ApprovalManager* approval_manager, TagStore* tag_store,
        AuditStore* audit_store, ServiceGroupFn service_group_fn = {}, TagPushFn tag_push_fn = {},
        InventoryStore* inventory_store = nullptr, ProductPackStore* product_pack_store = nullptr,
        SoftwareDeploymentStore* sw_deploy_store = nullptr,
        DeviceTokenStore* device_token_store = nullptr, LicenseStore* license_store = nullptr,
        GuaranteedStateStore* guaranteed_state_store = nullptr,
        yuzu::MetricsRegistry* metrics_registry = nullptr, SessionRevokeFn session_revoke_fn = {},
        ExecutionEventBus* execution_event_bus = nullptr,
        ResultSetStore* result_set_store = nullptr, CommandDispatchFn command_dispatch_fn = {},
        StepUpFn step_up_fn = {}, GuardianPushFn guardian_push_fn = {},
        DexPerfFn dex_perf_fn = {},
        // ADR-0031 WS-A4: the public in-process /network API seam (replaces
        // the former NetPerfFn ad-hoc provider) — the SAME instance the
        // /network dashboard fragments and the MCP network tools call, so
        // REST, dashboard and MCP can never disagree.
        std::shared_ptr<const NetworkApi> network_api = nullptr,
        LockoutClearFn lockout_clear_fn = {},
        // Name-anchored per-device Guardian status route (appended as a trailing
        // optional dep to keep every existing register_routes call site source-stable).
        BaselineStore* baseline_store = nullptr, ScopedPermFn scoped_perm_fn = {},
        // ADR-0016: typed installed-software store for GET /api/v1/inventory/software
        // (trailing optional dep; MUST be wired from server.cpp). Its per-agent scope
        // predicate is `fleet_read_fn` below (#3290 Phase 2) — the route's own
        // require_fleet_read gate replaced the retired InventoryScopeFn.
        SoftwareInventoryStore* software_inventory_store = nullptr,
        // #1634: per-agent Response-scope predicate for the fan-out response
        // readers (visualization). Trailing optional dep; MUST be wired from
        // server.cpp — `{}` scope = unfiltered fan-out read.
        ResponseScopeFn response_scope_fn = {},
        // PR 4.2 (design §4.1) — backs the fleet-wide engine role-assignment
        // authoring surface (/api/v1/engine-principals/{id}/roles). Trailing
        // optional dep; nullptr leaves the assign/unassign routes answering
        // 503 (list still works if rbac_store is wired — it doesn't need
        // this store).
        EnginePrincipalStore* engine_principal_store = nullptr,
        // Periodic Access Reviews (SOC 2 CC6.2) — the campaign store plus the
        // read-model deps `build_access_review` needs. Trailing optional deps;
        // `access_review_store == nullptr` leaves the whole /api/v1/access-reviews
        // family answering 503. `auth_db`/`directory_sync` are REQUIRED/OPTIONAL
        // respectively per access_review_model.hpp's own contract (auth_db unset
        // fails the export; directory_sync unset just degrades user email
        // enrichment) — `rbac_store`/`engine_principal_store`/`token_store` above
        // double as the other three read-model deps, so no new params for those.
        AccessReviewStore* access_review_store = nullptr, AuthDB* auth_db = nullptr,
        DirectorySync* directory_sync = nullptr,
        // ADR-0034: THE shared admission budget for held-open responses. GET /api/v1/events
        // pins an httplib worker for the life of the subscription, so it leases from the same
        // counter as every other streaming surface. nullptr = no admission control (tests).
        yuzu::server::detail::StreamBudget* stream_budget = nullptr,
        // #1788 defense-in-depth: see ExecVisibleFn's doc comment above. Trailing
        // optional dep; `{}` preserves the pre-existing unfiltered-VisibleSet
        // behaviour on POST /api/v1/bundles.
        ExecVisibleFn exec_visible_fn = {},
        // ADR-0017: the fleet guaranteed-state status route's SOLE authorization
        // gate (see ListReadFn's doc comment above). Trailing optional dep; `{}`
        // makes the route FAIL CLOSED (503) rather than silently fall back to
        // perm_fn — an unwired gate is misconfiguration, not "no filter".
        ListReadFn list_read_fn = {},
        // #3290 Phase 2: GET /api/v1/inventory/software's SOLE authorization gate
        // (see FleetReadFn's doc comment above). Trailing optional dep; `{}` makes
        // the route FAIL CLOSED (503), same contract as list_read_fn.
        FleetReadFn fleet_read_fn = {},
        // #4033 (#2146 Batch A): GET /api/v1/devices[/{id}]'s raw registry
        // snapshot (see AgentsJsonFn's doc comment above). Trailing optional
        // dep; `{}` makes both routes FAIL CLOSED (503).
        AgentsJsonFn agents_fn = {},
        // #4033: GET /api/v1/management-groups/agent-count-preview's D3
        // Response:Read scope resolver (see ResponseVisibleSetFn's doc
        // comment above). Trailing optional dep; `{}` = legacy-open.
        ResponseVisibleSetFn response_visible_set_fn = {},
        // #4035 hardening (governance): see DexVisibleFn's doc comment above.
        // Trailing optional dep; `{}` degrades GET /api/v1/dex/app and GET
        // /api/v1/dex/overview to "no confinement" (matching the fragment's own
        // unwired-`visible_set_fn_` posture), never a crash.
        DexVisibleFn dex_visible_fn = {},
        // ADR-0031 WS-A4 #4250: the public in-process VERIFY API seam (replaces
        // the former AppPerfCohortFn-in-AppPerfProviders ad-hoc cohort provider
        // for GET /api/v1/dex/perf/compare) — the SAME instance the /auto VERIFY
        // dashboard fragments and the MCP compare_app_perf_versions tool call,
        // so REST/dashboard/MCP can never disagree. nullptr = the route answers
        // 503 (provider unwired), same degrade as the retired cohort provider.
        std::shared_ptr<const VerifyApi> verify_api = nullptr,
        // ADR-0031 WS-A4 wave 2: the public in-process DEVICE API seam — backs
        // GET /api/v1/devices[/{id}] (replaces the raw `agents_fn` read on
        // this pair only; `agents_fn` itself stays wired for
        // POST /api/v1/scope/preview, its other live consumer). The SAME
        // instance `DeviceRoutes`/MCP `list_agents`+`get_agent_details` use, so
        // REST/dashboard/MCP can never disagree on device identity data.
        // nullptr = both routes answer 503 (provider unwired).
        std::shared_ptr<const DeviceApi> device_api = nullptr,
        // ADR-0031 WS-A4 (fifth family): the public in-process DEX signals API
        // seam — backs the GuaranteedStateStore-backed GET /api/v1/dex/*
        // signal/experience reads (the SAME instance the MCP DEX signal tools
        // use). The DEX signal handlers REQUIRE it: nullptr → those routes
        // answer 503, equivalent to the old `!guaranteed_state_store` readiness
        // guard (server.cpp wires this iff the store is present).
        std::shared_ptr<const DexApi> dex_api = nullptr,
        // ADR-0031 WS-A4 (sixth family): the public in-process DEX app-perf-
        // over-time API seam — backs the 9 GET /api/v1/dex/perf/* resources
        // (minus /compare, VerifyApi's) + GET /api/v1/dex/devices/{id}/app-perf
        // (the SAME instance the MCP DEX perf tools and the dashboard
        // fragments use, #4626). REQUIRED: nullptr → those routes answer 503,
        // equivalent to the old `!dex_perf_fn`/`!app_perf_providers.<member>`
        // readiness guards. Unlike dex_api above, server.cpp constructs this
        // UNCONDITIONALLY (never null) — each backing store pointer is
        // checked individually inside the impl, matching the old per-lambda
        // null-checks, so the route guard is defense-in-depth, never expected
        // to fire. `AppPerfProviders` (the pre-seam bundle) is retired.
        std::shared_ptr<const DexPerfApi> dex_perf_api = nullptr,
        // ADR-0031 WS-A4 (ninth family): the public in-process Guardian-read
        // API seam — backs 8 of the 9 GET /api/v1/guaranteed-state/*
        // resources (the SAME instance the MCP Guardian tools use;
        // `schemas` stays outside the seam, store-free — see
        // guardian_api.hpp). server.cpp constructs this UNCONDITIONALLY
        // (never null) — each of the two backing store pointers is checked
        // INDIVIDUALLY inside the impl (guardian_api.cpp), mirroring
        // dex_perf_api's own multi-dependency posture: a null
        // `guaranteed_state_store_` degrades every method, a null
        // `baseline_store_` degrades ONLY device_compliance. The
        // `!guardian_api` guard the 8 routes still carry is therefore
        // defense-in-depth only, matching the pre-seam
        // `!guaranteed_state_store` guard's practical behaviour.
        // `guaranteed_state_store` above stays wired too, for the
        // rule/baseline MUTATORS this seam does not cover.
        std::shared_ptr<const GuardianApi> guardian_api = nullptr);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink so dispatch happens without httplib::Server's
    /// TSan-hostile acceptor thread (#438).
    ///
    /// `step_up_fn` (PR2, optional) — when present, the high-risk REST /
    /// Settings handlers (token create/revoke, session revoke, Guardian rule
    /// create/update/push, software package create, software deploy start,
    /// file retrieval upload, user delete/role-change, and the two
    /// engine-principal role assign/unassign routes) gate behind it after
    /// permissions pass — the canonical enumerated list lives in
    /// docs/user-manual/rest-api.md "Step-up envelope on high-risk endpoints".
    /// Empty functor disables the gate entirely (default — preserves
    /// pre-PR2 behaviour for any caller that hasn't wired it).
    void register_routes(
        class HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
        RbacStore* rbac_store, ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
        QuarantineStore* quarantine_store, ResponseStore* response_store,
        InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
        ScheduleEngine* schedule_engine, ApprovalManager* approval_manager, TagStore* tag_store,
        AuditStore* audit_store, ServiceGroupFn service_group_fn = {}, TagPushFn tag_push_fn = {},
        InventoryStore* inventory_store = nullptr, ProductPackStore* product_pack_store = nullptr,
        SoftwareDeploymentStore* sw_deploy_store = nullptr,
        DeviceTokenStore* device_token_store = nullptr, LicenseStore* license_store = nullptr,
        GuaranteedStateStore* guaranteed_state_store = nullptr,
        yuzu::MetricsRegistry* metrics_registry = nullptr, SessionRevokeFn session_revoke_fn = {},
        ExecutionEventBus* execution_event_bus = nullptr,
        ResultSetStore* result_set_store = nullptr, CommandDispatchFn command_dispatch_fn = {},
        StepUpFn step_up_fn = {}, GuardianPushFn guardian_push_fn = {},
        DexPerfFn dex_perf_fn = {},
        // ADR-0031 WS-A4: the public in-process /network API seam (replaces
        // the former NetPerfFn ad-hoc provider) — the SAME instance the
        // /network dashboard fragments and the MCP network tools call, so
        // REST, dashboard and MCP can never disagree.
        std::shared_ptr<const NetworkApi> network_api = nullptr,
        LockoutClearFn lockout_clear_fn = {},
        // Name-anchored per-device Guardian status route (appended as a trailing
        // optional dep to keep every existing register_routes call site source-stable).
        BaselineStore* baseline_store = nullptr, ScopedPermFn scoped_perm_fn = {},
        // ADR-0016: typed installed-software store for GET /api/v1/inventory/software
        // (trailing optional dep; MUST be wired from server.cpp). Its per-agent scope
        // predicate is `fleet_read_fn` below (#3290 Phase 2) — the route's own
        // require_fleet_read gate replaced the retired InventoryScopeFn.
        SoftwareInventoryStore* software_inventory_store = nullptr,
        // #1634: per-agent Response-scope predicate for the fan-out response
        // readers (visualization). Trailing optional dep; MUST be wired from
        // server.cpp — `{}` scope = unfiltered fan-out read.
        ResponseScopeFn response_scope_fn = {},
        // PR 4.2 (design §4.1) — backs the fleet-wide engine role-assignment
        // routes (/api/v1/engine-principals/{id}/roles), which capture this
        // param. COEXISTENCE (4.2→4.3 rebase): the 4.3 lifecycle routes use the
        // `engine_principal_store_` MEMBER (set via set_engine_principal_store);
        // server.cpp wires BOTH. Follow-up: unify onto the member.
        EnginePrincipalStore* engine_principal_store = nullptr,
        // Periodic Access Reviews (SOC 2 CC6.2) — see the production overload's
        // doc comment above; identical trailing-optional-dep contract.
        AccessReviewStore* access_review_store = nullptr, AuthDB* auth_db = nullptr,
        DirectorySync* directory_sync = nullptr,
        // ADR-0034: the shared held-open-response budget (see the overload above).
        yuzu::server::detail::StreamBudget* stream_budget = nullptr,
        // #1788 defense-in-depth: see ExecVisibleFn's doc comment above (production
        // overload). `{}` preserves the pre-existing unfiltered-VisibleSet behaviour
        // for test harnesses that haven't wired it.
        ExecVisibleFn exec_visible_fn = {},
        // ADR-0017: see the production overload's doc comment above; identical
        // trailing-optional-dep, fail-closed-when-unwired contract.
        ListReadFn list_read_fn = {},
        // #3290 Phase 2: see the production overload's doc comment above; identical
        // trailing-optional-dep, fail-closed-when-unwired contract.
        FleetReadFn fleet_read_fn = {},
        // #4033: see the production overload's doc comment above; identical
        // trailing-optional-dep, fail-closed-when-unwired contract.
        AgentsJsonFn agents_fn = {},
        // #4033: see the production overload's doc comment above; identical
        // trailing-optional-dep, legacy-open-when-unwired contract.
        ResponseVisibleSetFn response_visible_set_fn = {},
        // #4035 hardening (governance): see the production overload's doc
        // comment above (DexVisibleFn); identical trailing-optional-dep,
        // degrade-to-no-confinement contract.
        DexVisibleFn dex_visible_fn = {},
        // ADR-0031 WS-A4 #4250: see the production overload's doc comment
        // above; identical trailing-optional-dep, 503-when-unwired contract.
        std::shared_ptr<const VerifyApi> verify_api = nullptr,
        // ADR-0031 WS-A4 wave 2: see the production overload's doc comment
        // above; identical trailing-optional-dep, 503-when-unwired contract.
        std::shared_ptr<const DeviceApi> device_api = nullptr,
        // ADR-0031 WS-A4 (fifth family): see the production overload's doc
        // comment above; identical trailing-optional-dep, required-or-503.
        std::shared_ptr<const DexApi> dex_api = nullptr,
        // ADR-0031 WS-A4 (sixth family): see the production overload's doc
        // comment above; identical trailing-optional-dep, required-or-503.
        std::shared_ptr<const DexPerfApi> dex_perf_api = nullptr,
        // ADR-0031 WS-A4 (ninth family): see the production overload's doc
        // comment above; identical trailing-optional-dep, required-or-503.
        std::shared_ptr<const GuardianApi> guardian_api = nullptr);

    /// PR 4.3 — engine-principal lifecycle store backing
    /// `/api/v1/engine-principals`, threaded post-construction. (During the
    /// 4.2→4.3 coexistence this same store is ALSO passed as the register_routes
    /// param above for the 4.2 grant routes; server.cpp calls both.) MUST be
    /// called BEFORE `register_routes()` — the routes capture the pointer's
    /// value at registration time, not `this`. Unset (nullptr) = the
    /// engine-principal routes answer 503.
    void set_engine_principal_store(EnginePrincipalStore* store) { engine_principal_store_ = store; }

    /// PR 4.3 — see `UserExistsFn`'s doc comment above. MUST be called
    /// BEFORE `register_routes()`, same timing contract as
    /// `set_engine_principal_store`.
    void set_user_exists_fn(UserExistsFn fn) { user_exists_fn_ = std::move(fn); }

private:
    EnginePrincipalStore* engine_principal_store_{nullptr};
    UserExistsFn user_exists_fn_;
};

} // namespace yuzu::server
