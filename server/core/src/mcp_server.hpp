#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

#include <yuzu/server/auth.hpp>

#include "agent_registry.hpp" // #3687: DispatchDenial / DispatchDenialReason — AuthorizeDispatchFn's error type
#include "api_token_model.hpp" // #2146 Batch B4: shared REST+MCP API-token JSON builders
#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp" // #4037: ListReadGate — get_guardian_status's require_list_read confinement seam
#include "authz_gates.hpp" // #3290 Phase 2: authz::FleetReadGate — query_installed_software's real confinement seam
#include "authz_model.hpp" // #1788: VisibleSet — MCP dispatch confinement (in_scope/filter_to_scope)
#include "ca_routes.hpp" // IssueCodeSigningFn/CodeSigningIssuance (free at yuzu::server scope, unlike
                         // CaRoutes::PublishCrlFn below) — reused verbatim by issue_code_signing_cert
                         // rather than re-declared, so the two error-prefix constants stay one copy.
#include "ca_store.hpp"
#include "command_capability.hpp" // #3685: CommandCapability / ClassificationError — ClassifyFn's return type
#include "dispatch_caller.hpp" // PLAN-006: DispatchCaller — the principal threaded to dispatch_fn
// ADR-0031 operator surface (PR1.6c) — MCP twins of the operator
// mint/list/revoke upload-grant routes. Reuses UploadGrantListAuthorization/
// UploadGrantListDecision verbatim (not redefined) so the REST list-admit
// gate (GET /api/v1/upload-grants) and this MCP twin cannot drift — same
// reuse discipline as kek_routes.hpp above. Also brings in UploadGrantStore
// fully defined, so no separate include is needed for that.
#include "file_retrieval_routes.hpp"
#include "dex_perf_model.hpp"
#include "network_api.hpp" // ADR-0031 WS-A4: the public in-process /network API seam
#include "verify_api.hpp" // ADR-0031 WS-A4 #4250: the public in-process VERIFY API seam
#include "dex_api.hpp"    // ADR-0031 WS-A4 (fifth family): the public in-process DEX signals API seam
#include "dex_perf_api.hpp" // ADR-0031 WS-A4 (sixth family): the public in-process DEX app-perf-over-time API seam
#include "compliance_api.hpp" // ADR-0031 WS-A4: the public in-process compliance/policy API seam
#include "device_api.hpp" // ADR-0031 WS-A4 wave 2: the public in-process DEVICE API seam
#include "network_perf_model.hpp"
#include "execution_tracker.hpp"
#include "execution_statistics_model.hpp" // #2146 Batch B3: shared REST+MCP statistics builders
#include "fleet_topology_store.hpp" // #2146 Batch B3: FleetTopologyStore + merge_offline_topology
#include "offline_endpoint_store.hpp" // #2146 Batch B3: OfflineEndpoint -- see set_viz_deps below
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "kek_routes.hpp" // KekOps / KekOpResult (#2395 track C): reused, not redefined
// ADR-0031 operator surface (PR1.5c/1.6c, p14): reuses
// UploadGrantListAuthorization/UploadGrantListDecision verbatim (not
// redefined) so the REST list-admit gate (GET /api/v1/upload-grants) and its
// MCP twin (list_upload_grants) cannot drift — same reuse discipline as
// kek_routes.hpp above.
#include "file_retrieval_routes.hpp"
#include "management_group_model.hpp" // #2146 Batch B4: shared REST+MCP management-group JSON builders
#include "management_group_store.hpp"
#include "mcp_retry.hpp"  // named retry_after_ms floors + poll counter name (#3344)
#include "mcp_session.hpp"
#include "mcp_stream.hpp" // GET SSE channel: StreamRevalidateFn, handle_get_tail (2f PR 2)
#include "policy_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "result_set_model.hpp" // #2146 Batch B2: ResultSetStore (fwd-declared only otherwise) + shared JSON builder
#include "schedule_api.hpp" // ADR-0031 WS-A4 (seventh family): the public in-process schedule-read API seam
#include "schedule_engine.hpp" // still needed for the ScheduleEngine* build_handler param -- see set_schedule_api's doc comment
#include "scope_engine.hpp"
#include "tag_store.hpp"
#include "workflow_api.hpp" // ADR-0031 WS-A4 (eighth family): the public in-process workflow-read API seam
#include "guardian_api.hpp" // ADR-0031 WS-A4 (ninth family): the public in-process Guardian-read API seam
#include "workflow_engine.hpp" // still needed for the WorkflowEngine* build_handler param -- see set_workflow_api's doc comment
// #4027: DeviceRow (via device_routes.hpp) + TarRetentionPausedScan/
// TarPausedSourceRow + the tar_*_json pure builders the read-twin MCP tools
// share with their REST siblings (api-twin-recipe.md Rule 1).
#include "tar_tree_routes.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <expected>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry; // optional bundle-metrics sink (yuzu_bundle_*)
}

namespace yuzu::server {
class HttpRouteSink; // #2542 PR-6: register_routes(HttpRouteSink&, ...) overload
class SoftwareInventoryStore; // typed daily-sync software store (ADR-0016)
class SoftwareLicensingStore; // ADR-0024 discovery store (query_software_licenses)
class AppUsageStore; // wave 7 PR7.2 app-usage projection (get_agent_app_usage)
// EnginePrincipalStore backs BOTH the PR 4.2 role-assignment MCP twins
// (assign_engine_role/unassign_engine_role/list_engine_roles) AND the PR 4.3
// engine-principal lifecycle tools (ADR-1005 item 2b). Forward-declared
// (pointer-only here); the .cpp includes engine_principal_store.hpp.
class EnginePrincipalStore;
// Periodic Access Reviews (SOC 2 CC6.2) — the campaign store plus the
// optional read-model enrichment dep. Forward-declared (pointer-only in
// build_handler/register_routes); the .cpp includes access_review_store.hpp /
// directory_sync.hpp. AuthDB is already forward-declared via <yuzu/server/auth.hpp>.
class AccessReviewStore;
class DirectorySync;
// ADR-0031 operator surface (PR1.5c, p14) — backs the plugin config/secret/
// kill-switch MCP twins. Forward-declared (pointer-only in the setter
// below); the .cpp includes plugin_config_store.hpp for the definition.
// UploadGrantStore itself is NOT forward-declared here — it arrives fully
// defined via file_retrieval_routes.hpp's own include above.
class PluginConfigStore;
// #4036 (api-parity Batch A) — backs list_preflight_runs +
// get_deployment_preview (the latter reads ONLY the pre-flight store, never
// DeploymentRunStore — see deployment_routes.cpp's own /fragments/auto/deploy
// handler, which is the same shape). Forward-declared (pointer-only in the
// setter below); the .cpp includes preflight_run_store.hpp for the definition.
class PreflightRunStore;
// #2146 Batch B1 — backs get_guardian_device_compliance (the SAME BaselineStore
// GET /guaranteed-state/device-compliance already reads). Forward-declared
// (pointer-only in the setter below); the .cpp includes baseline_store.hpp for
// the full definition.
class BaselineStore;
// #4029 — backs list_product_packs/get_product_pack. Forward-declared
// (pointer-only in build_handler/register_routes); the .cpp includes
// product_pack_model.hpp, which pulls in product_pack_store.hpp.
class ProductPackStore;
// #4027: backs list_tar_retention_paused — forward-declared (pointer-only via
// set_dashboard_routes below); the .cpp includes dashboard_routes.hpp for the
// full definition.
class DashboardRoutes;
// #2146 Batch B2 — backs the 12 result-set MCP twins (scope-walking,
// docs/scope-walking-design.md). Forward-declared (pointer-only in
// build_handler/register_routes); the .cpp includes result_set_store.hpp for
// the full definition.
class ResultSetStore;
// B5 (api-parity programme #2146) — backs the offload-target / platform-
// license / software-deployment MCP twins (list/create/get/delete_offload_
// target, list_offload_target_deliveries, get/activate_platform_license,
// list_license_alerts, list/create/rollback/cancel_software_deployment).
// Forward-declared (pointer-only in build_handler/register_routes); the .cpp
// includes each store's own header for the full definition. LicenseStore and
// SoftwareDeploymentStore are DELIBERATELY DORMANT on `dev` (ADR-0048/0051 —
// nothing in server.cpp constructs them, mirroring rest_api_v1_'s own
// nullptr wiring for both) — their MCP twins answer "unavailable" in
// production today, same posture as their REST siblings, until a future PR
// re-wires construction (out of scope here).
class OffloadTargetStore;
class LicenseStore;
class SoftwareDeploymentStore;
}

namespace yuzu::server::detail {
// A2 discovery: backs the discover_plugins tool (mirrors GET /api/v1/discover/plugins,
// discover_routes.hpp). Forward-declared (pointer-only in build_handler/register_routes);
// the .cpp includes agent_registry.hpp for the definition.
class AgentRegistry;
} // namespace yuzu::server::detail

namespace yuzu::server::mcp {

// Progress bridge core (track 2f PR 3a). Forward-declared (pointer-only here,
// injected via set_stream_bridge); the .cpp includes mcp_stream_bridge.hpp.
class McpStreamBridge;

namespace detail {
/// #2530 G8-F2 — test-only, externally-linked twin of mcp_server.cpp's
/// file-local `kek_failure_tag()` (the MCP audit-detail switch). Mirrors
/// `yuzu::server::detail::kek_route_failure_tag` (kek_routes.hpp) so a
/// table-driven test can assert all three failure vocabularies (REST, MCP,
/// and `kek_rotate_control.hpp`'s `kek_op_outcome_label()`) agree for every
/// `KekOpResult::Failure` value — the switches stay independent by design,
/// this only forwards to the existing production one.
[[nodiscard]] std::string_view kek_mcp_failure_tag(KekOpResult::Failure failure);
} // namespace detail

/// MCP (Model Context Protocol) server — JSON-RPC 2.0 endpoint at /mcp/v1/.
/// Mirrors the RestApiV1 pattern: receives store pointers + auth/perm/audit callbacks.
class McpServer {
public:
    /// C8 fail-closed boot validator (#2383): throws std::runtime_error naming
    /// the offenders when the served kTools[] names, the kToolSecurity
    /// registrations, and the kWriteTools read-only guard set disagree — a
    /// misregistered build refuses to construct (and therefore to boot) instead
    /// of silently skipping the generic tier+approval gate for the missing tool.
    McpServer();

    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate (PR #1796 review H1) — same
    /// shape as DeviceRoutes::ScopedPermFn. Production wires it to
    /// AuthRoutes::require_scoped_permission (the single per-device authz
    /// chokepoint), so the device-targeted write tools (set_tag / delete_tag /
    /// quarantine_device) hold an operator to their management-group scope: a
    /// group-confined operator can act on in-scope devices and is denied on
    /// out-of-scope ones, instead of the global perm_fn's all-or-nothing answer
    /// (#1522 precedent — under the global gate a confined-but-globally-granted
    /// operator could tag/quarantine devices fleet-wide).
    ///
    /// FALLBACK-WHEN-UNWIRED, deliberately: the default `= {}` makes the three
    /// device-targeted handlers fall back to the global perm_fn (the pre-H1
    /// behavior) — NOT fail-open — because build_handler/register_routes carry a
    /// long tail of optional `= {}` deps and C++ forbids a required param after
    /// a defaulted one. The SOLE production caller (server.cpp) always wires it;
    /// the unwired path is a test-only affordance. Do not add a new production
    /// registration without wiring this.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    // Returns false if the audit row could not be persisted. Most MCP call sites
    // discard the result (the generic mcp_audit helper), but destructive tools
    // (e.g. revoke_certificate) observe it to surface an evidence-chain gap in the
    // JSON-RPC result — matching the canonical bool-returning audit contract.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using AgentsJsonFn = std::function<nlohmann::json()>;

    /// Push a structured tag change to the agent (mirrors RestApiV1::TagPushFn).
    /// Fired by the `set_tag` write tool (#289 / D4) after a successful tag
    /// write so a category change (role/environment/location/service) reaches
    /// the endpoint exactly as the REST PUT /api/v1/tags path does. Unset (`= {}`)
    /// is a no-op (test harness / RBAC-off).
    using TagPushFn = std::function<void(const std::string& agent_id, const std::string& key)>;

    /// Per-agent response-scope predicate (#1550 HIGH-1 / #1634). Returns true iff
    /// the principal `username` may read responses for `agent_id`. Production wires
    /// it to rbac_store->check_scoped_permission(username,"Response","Read",agent_id,
    /// mgmt_store) — the same chokepoint the per-device REST/dashboard routes use.
    /// NOTE (#1634): this filter is INERT under the current global `Response:Read`
    /// gate — a holder of global Response:Read passes the gate and
    /// check_scoped_permission's global step then admits every agent (no rows
    /// dropped), while a management-group-confined operator is 403'd at the gate
    /// before this runs. So it does NOT yet bound a normal operator to their groups;
    /// its only active effect today is failing CLOSED on a corrupt/load-failed
    /// rbac.db. Effective per-operator scoping needs the admit-then-filter gate for
    /// fan-out reads (the remaining #1634 work; see rest_api_v1.hpp ResponseScopeFn).
    /// The handler resolves the principal ONCE (it already authed the request) and
    /// passes `username` in, so the predicate does NOT re-resolve the session per
    /// call. RBAC-off → returns true (legacy-open, matching require_scoped_permission).
    ///
    /// FAIL-OPEN-WHEN-UNWIRED, deliberately: the default `= {}` means an unset
    /// predicate applies NO filter. This diverges from DeviceRoutes' required
    /// ScopedPermFn (which fails closed) because build_handler/register_routes carry
    /// a long tail of optional `= {}` deps and C++ forbids a required param after a
    /// defaulted one — so the param cannot be made required without reordering the
    /// whole signature. The SOLE production caller (server.cpp) always wires it; the
    /// unwired path is a test-only affordance (legacy-open). Do not add a new
    /// production registration without wiring this.
    ///
    /// The filter is applied AFTER the store's LIMIT, so a fan-out wider than the
    /// row cap that spans out-of-scope agents may truncate the caller's in-scope
    /// view; the result then carries `result_truncated_by_cap:true` so the caller
    /// can detect it. Completeness for >cap collection is the keyset follow-up
    /// (#1634); the cross-operator ISOLATION guarantee (never another operator's
    /// rows) holds regardless. NOTE (ADR-0017): this filter is INERT under the
    /// global Response:Read gate (does not narrow by management group today); the
    /// list-view correction is tracked #1718 PR-B. NOTE: service-scoped tokens are scoped by the token
    /// creator's RBAC, not the service tag (pre-existing, tracked in #1634).
    using ResponseScopeFn =
        std::function<bool(const std::string& username, const std::string& agent_id)>;

    /// Send command callback — dispatches a command and returns (command_id, agents_reached).
    ///
    /// `execution_id` is the pre-created `ExecutionTracker` row id, threaded
    /// through so the dispatch wiring can register the
    /// `command_id → execution_id` mapping with `AgentServiceImpl` BEFORE
    /// any RPC is sent (closes the FAST-agent race documented in
    /// `docs/executions-history-ladder.md` PR 2 / UP2-4 — a sub-millisecond
    /// loopback agent's response would otherwise win against a
    /// post-dispatch mapping-registration call). Empty `execution_id` is a
    /// valid out-of-band dispatch with no tracker row; the wiring skips
    /// registration. **Caller MUST create the execution row before
    /// invoking this and pass the assigned id** — same contract as
    /// `WorkflowRoutes::CommandDispatchFn` (the REST sibling). Added for
    /// issue #1088 so MCP `execute_instruction` can return `execution_id`
    /// in its response and let agentic workers bridge to `/api/v1/events`.
    ///
    /// PLAN-006: the trailing param carries the caller's IDENTITY as well as
    /// its `exec_visible` filter (`yuzu::server::DispatchCaller`, formerly a
    /// bare `VisibleSet`) so the shared `dispatch_confined` seam has a
    /// principal to work with, not only a visibility filter.
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id,
        // #1788 / PLAN-006: every dispatch arm intersects `caller.exec_visible`
        // against its targets, mirroring /api/command; `caller.principal`
        // identifies who asked.
        const yuzu::server::DispatchCaller& caller)>;

    /// #1788 / PLAN-006: derives the per-request DispatchCaller (identity +
    /// Execution:Execute visible set) the DispatchFn consults. Injected because
    /// the handler has the session but the dispatch lambda (server.cpp) does
    /// not. When this std::function is UNSET, the execute_instruction /
    /// execute_bundle handlers substitute an EMPTY principal alongside a
    /// PRESENT-EMPTY `exec_visible` (deny-all), NOT nullopt — an unwired
    /// derivation fails CLOSED on visibility exactly as before this struct
    /// existed (ADR-0033 §1: a missing applicable filter denies; CDX-R6-02). A
    /// caller that genuinely wants full-fleet dispatch must wire a callback
    /// whose `exec_visible` is std::nullopt; production wires server.cpp's
    /// derive_dispatch_caller (which wraps derive_exec_visible).
    using CallerFn = std::function<yuzu::server::DispatchCaller(const auth::Session&)>;

    /// Owner-FK existence check for engine-principal create/transfer-owner
    /// (design doc `docs/auth-engine-principals-design.md` §3.1:
    /// "owner_username — must reference an existing user", enforced by the
    /// CALLER — `EnginePrincipalStore::create`/`transfer_owner` themselves
    /// only check non-empty, deliberately store-agnostic re: users so the
    /// store never couples to `AuthDB`). Returns true iff `username` names an
    /// existing user. FAIL-CLOSED contract: an unset (`{}`) predicate means
    /// every create/transfer-owner call is denied ("owner existence check
    /// unavailable"), never silently admitted — mirrors
    /// `ApiTokenStore::set_engine_referent_check`'s fail-closed-when-unwired
    /// posture, not the FAIL-OPEN-WHEN-UNWIRED contract used by
    /// ResponseScopeFn above (a defense-in-depth filter over an already-gated
    /// read; this is the sole check standing
    /// between an MCP write and a dangling owner reference).
    using OwnerExistsFn = std::function<bool(const std::string& username)>;

    /// #3685: classifies a `plugin.action` pair the SAME way `/api/command`
    /// does — the production wiring (server.cpp) wraps the shared
    /// `CommandCapabilityRegistry::classify` this tool's REST twin already
    /// consults, so the two surfaces cannot disagree about what a pair IS,
    /// only about what to DO with a miss (see below).
    ///
    /// FAIL-CLOSED contract, matching `OwnerExistsFn` immediately above: an
    /// unset (`{}`) fn means `execute_instruction` cannot determine whether
    /// ANY pair is Destructive, so it refuses EVERY call at both gate sites
    /// with a distinguishable "classifier unavailable" denial — never
    /// silent fall-through indistinguishable from an honest classify-miss.
    /// This is deliberately a STRONGER posture than most `*Fn` seams in this
    /// file (which degrade a single tool to "unavailable" when unwired): a
    /// silently-unwired classifier would silently revert MCP's Destructive
    /// targeting confinement to its pre-#3685 state while every other test
    /// stayed green — precisely the `ContainmentGate{}` class of regression
    /// `dispatch_confined_arms.hpp` warns about. Production always wires
    /// this (server.cpp, unconditionally, next to `set_kek_ops`); an unset
    /// fn reaching a live request means the wiring itself regressed.
    ///
    /// A WIRED fn returning `Unclassified`/`Ambiguous` (an honest classify
    /// miss, not an absent fn) is the DIFFERENT Policy-B case — see
    /// `dispatch_destructive_gate.hpp`'s `DestructiveTargetingVerdict::
    /// ClassifyMiss`. Pre-#3687 this fell all the way through to the
    /// existing dispatch chokepoint, which denied a real miss on its own
    /// terms. #3687 changed WHERE that denial happens on the main-handler
    /// path: `AuthorizeDispatchFn`'s own pre-dispatch dry run (below) now
    /// denies a classify-miss locally, with a discriminated error, before
    /// `dispatch_fn` is ever called — the chokepoint itself is unchanged,
    /// only reached one call earlier. REST's `/api/command` still falls
    /// through to that chokepoint unchanged (Policy B, as before).
    using ClassifyFn =
        std::function<std::expected<yuzu::server::CommandCapability,
                                    yuzu::server::ClassificationError>(
            std::string_view plugin, std::string_view action)>;

    /// #3687 (widened by #3893): the pre-dispatch DRY RUN of the shared
    /// dispatch chokepoint's full classify+authorize+kill-switch decision —
    /// the same decision `ServerImpl::build_classified_command` makes,
    /// minus the wire-command construction a dry run has no use for. Every
    /// dispatch-capable MCP tool's handler calls this BEFORE `dispatch_fn`/
    /// `bundle_orch->dispatch` — `execute_instruction`, `execute_bundle`
    /// (per step, all-or-nothing), and `quarantine_device` (before its
    /// store write) today, plus the generalized C8 pre-mint block, which
    /// loops over `dispatch_pairs_for(tool_name, args)`
    /// (`mcp_server.cpp`) — the ONE place a future dispatch-capable tool is
    /// registered. No target-agent list is needed for any of them —
    /// classification and authorization are decided from `(plugin, action,
    /// caller)` alone, before any scope/group target resolution happens.
    ///
    /// Every `yuzu::server::detail::DispatchDenialReason` the chokepoint can
    /// produce (`Unclassified`/`Ambiguous`/`AnonymousOperator`/`Forbidden`/
    /// `ApprovalRequired`/`KillSwitched`) is reachable here — production
    /// wires a closure that calls `classify_and_authorize_dispatch`
    /// (`agent_registry.hpp`, the SAME pure function + the SAME injected
    /// RBAC binder `build_classified_command` itself consults, never a
    /// re-implemented slice — Decision 7 F fix,
    /// `docs/security-reviews/1398-dispatch-approval-gate-design.md`) and
    /// then, only on success, `kill_switch_denial` (`agent_registry.hpp`) —
    /// the SAME extracted function `finalize_classified_command` itself
    /// calls for the per-action kill switch, not a re-implemented slice of
    /// that decision either (Gate 6 governance fix: an earlier round of this
    /// change re-expressed the kill-switch boolean inline instead of sharing
    /// `finalize_classified_command`'s own extracted check — the class of
    /// drift `finalize_classified_command`'s own M6/wave1 extraction exists
    /// to prevent, reintroduced once and caught by governance; this seam now
    /// shares the extracted function like the classify+authorize half
    /// always did). Kill switch checked AFTER classify+authorize, so it can
    /// never mask a `Forbidden`/`ApprovalRequired` verdict with a
    /// weaker-sounding one. Because the kill-switch half now calls the SAME
    /// `kill_switch_denial` function `finalize_classified_command` calls (and
    /// the classify+authorize half already called the SAME
    /// `classify_and_authorize_dispatch` function `build_classified_command`
    /// calls), the existing
    /// `finalize_classified_command`/`kill_switch_denial` tests in
    /// `tests/unit/server/test_dispatch_chokepoint.cpp` (KillSwitched refusal,
    /// legacy-open-when-unwired, canonical-plugin/action consultation) cover
    /// this seam's kill-switch behavior too — there is no separate "the two
    /// paths agree" claim left to verify, because there is only one
    /// implementation of the decision.
    ///
    /// FAIL-CLOSED contract, matching `ClassifyFn` immediately above (the
    /// OPPOSITE default posture from most `*Fn` seams in this file): an
    /// unset (`{}`) fn means NONE of the dispatch-capable tools above (nor
    /// the generalized C8 block, for any tool `dispatch_pairs_for` returns a
    /// non-empty pair list for) can determine whether a caller may dispatch
    /// a given pair at all, so EVERY such call is refused with a
    /// distinguishable "dispatch authorization unavailable" denial — never
    /// a silent fall-through to the pre-#3687 collapsed-envelope behaviour.
    /// Production always wires this (server.cpp, unconditionally,
    /// next to `set_capability_classify_fn`); an unset fn reaching a live
    /// request means the wiring itself regressed.
    ///
    /// A WIRED fn returning success here is NOT the sole enforcement point —
    /// `dispatch_fn` still re-runs the identical chokepoint decision
    /// internally a moment later (cheap: no I/O beyond the same RBAC read
    /// this call already made) and is the surface that actually dispatches.
    /// This seam exists purely so a caller this dispatch was always going to
    /// refuse gets a discriminated, reason-naming error instead of the
    /// generic `agents_reached:0`/`no_agents_reached` envelope an empty
    /// target set also produces — it does not change what dispatch_fn itself
    /// enforces.
    using AuthorizeDispatchFn = std::function<std::expected<yuzu::server::CommandCapability,
                                                             yuzu::server::detail::DispatchDenial>(
        const yuzu::server::DispatchCaller& caller, std::string_view plugin,
        std::string_view action)>;

    /// Injects the engine-principal + engine-credential store pointers and
    /// the owner-FK predicate via SETTERS rather than growing the already
    /// 30-parameter build_handler()/register_routes() trailing-parameter
    /// tail further. The handler returned by build_handler() is a non-static
    /// member function's `[=]` lambda, which implicitly captures `this` — so
    /// a setter called AFTER build_handler() still takes live effect on the
    /// very next request, the same live-read property the `read_only_mode`/
    /// `mcp_disabled` pointer captures give today. Safe because the sole
    /// production `McpServer` instance (server.cpp's `mcp_server_`, a
    /// `unique_ptr` member of `ServerImpl`) outlives every handler it
    /// produces. Unset (`nullptr`/`{}`) ⇒ every engine-principal tool answers
    /// "unavailable" rather than crashing or silently no-op'ing — production
    /// wiring is a follow-up task (server.cpp is out of scope for this PR).
    void set_engine_principal_store(EnginePrincipalStore* store) {
        engine_principal_store_ = store;
    }
    /// The SAME `ApiTokenStore` instance server.cpp wires everywhere else —
    /// not an engine-only store. Used here for `create_token`(engine
    /// readonly)/`rotate_engine_credential`/`list_active_for_principal`/
    /// `revoke_for_principal`.
    void set_engine_credential_store(ApiTokenStore* store) { engine_credential_store_ = store; }
    void set_owner_exists_fn(OwnerExistsFn fn) { owner_exists_fn_ = std::move(fn); }
    /// #3685: see `ClassifyFn`'s doc comment above for the fail-closed
    /// contract. Same setter idiom as `set_owner_exists_fn` immediately
    /// above (the handler's `[=]` lambda captures `this`, so the injection
    /// is a live read on the next request).
    void set_capability_classify_fn(ClassifyFn fn) { classify_fn_ = std::move(fn); }
    /// #3687: see `AuthorizeDispatchFn`'s doc comment above for the
    /// fail-closed contract. Same setter idiom as `set_capability_classify_fn`
    /// immediately above (the handler's `[=]` lambda captures `this`, so the
    /// injection is a live read on the next request).
    void set_authorize_dispatch_fn(AuthorizeDispatchFn fn) { authorize_dispatch_fn_ = std::move(fn); }

    /// Progress bridge (2f PR 3a). Same setter idiom + lifetime argument as
    /// set_engine_principal_store above (the handler's `[=]` lambda captures
    /// `this`, so the injection is a live read on the next request). Nullable:
    /// unset ⇒ execute_instruction never reserves a bridge record and the
    /// pre-bridge behaviour is byte-identical. server.cpp wires the ServerImpl-
    /// owned bridge; tests inject their own.
    void set_stream_bridge(McpStreamBridge* bridge) { stream_bridge_ = bridge; }

    /// KEK (key-encryption-key) rotation seam (#2395 track C) — same setter
    /// idiom as set_engine_principal_store above (the handler's `[=]` lambda
    /// captures `this`, so the injection is a live read on the next request).
    /// Reuses kek_routes.hpp's `KekOps`/`KekOpResult` verbatim rather than
    /// redefining them, so the REST and MCP surfaces cannot drift. Any of the
    /// three std::functions left unset (default-constructed `KekOps{}`) makes
    /// the corresponding tool answer "unavailable" cleanly — never a null
    /// std::function call. server.cpp wires the SAME KekOps instance it hands
    /// to KekRoutes::register_routes.
    void set_kek_ops(KekOps ops) { kek_ops_ = std::move(ops); }

    /// ADR-0031 operator surface (PR1.5c) — plugin config/secret/kill-switch
    /// store, backing get/set/delete_plugin_config, set/delete_plugin_secret,
    /// get/set_plugin_kill_switch. Same setter idiom as
    /// set_engine_principal_store above (the handler's `[=]` lambda captures
    /// `this`, so the injection is a live read on the next request). Unset
    /// (`nullptr`, the default) ⇒ every one of those tools answers
    /// "unavailable" rather than crashing or silently no-op'ing.
    void set_plugin_config_store(PluginConfigStore* store) { plugin_config_store_ = store; }

    /// ADR-0031 operator surface (PR1.6c) — upload-grant store + the
    /// ADR-0017 list-admit resolver for list_upload_grants, backing
    /// mint/list/revoke_upload_grant. `list_read_fn` is the SAME shape as
    /// `yuzu::server::Deps::ListReadFn` (file_retrieval_routes.hpp) reused
    /// verbatim, not redefined, so the REST GET /api/v1/upload-grants list
    /// gate and this MCP twin cannot drift — server.cpp wires both from the
    /// identical `RbacStore::authorize_list_read` call. Unset store ⇒ every
    /// upload-grant tool answers "unavailable"; unset (default-constructed)
    /// `list_read_fn` fails CLOSED (kDenyAll), matching the REST twin's own
    /// unwired default (file_retrieval_routes.hpp's Deps doc comment) — NOT
    /// the fail-open-when-unwired contract ResponseScopeFn above uses,
    /// because this is the sole admit decision for the route, not
    /// a defense-in-depth filter over an already-gated read.
    using UploadGrantListReadFn =
        std::function<UploadGrantListAuthorization(const std::string& username)>;
    void set_upload_grant_ops(UploadGrantStore* store, UploadGrantListReadFn list_read_fn) {
        upload_grant_store_ = store;
        upload_grant_list_read_fn_ = std::move(list_read_fn);
    }

    /// #4036 (api-parity Batch A) — the pre-flight run store, backing
    /// `list_preflight_runs` (owner-scoped, mirrors GET
    /// /api/v1/preflight/runs) and `get_deployment_preview` (mirrors GET
    /// /api/v1/deployments/preview — reads ONLY this store, never
    /// DeploymentRunStore, matching the fragment's own
    /// `/fragments/auto/deploy` handler). Same setter idiom as
    /// `set_plugin_config_store` above. Unset (`nullptr`, the default) ⇒
    /// both tools answer "unavailable" rather than crashing.
    void set_preflight_run_store(PreflightRunStore* store) { preflight_run_store_ = store; }

    /// #2146 Batch B2 — the scope-walking result-set store, backing the 12
    /// result-set MCP tools (`list_result_sets` through `delete_result_set`).
    /// Same setter idiom as `set_preflight_run_store` above. Unset
    /// (`nullptr`, the default) ⇒ every result-set tool answers
    /// "unavailable" rather than crashing. Owner-scoped, not RBAC-gated
    /// (matches the REST twins' `deny_fleet_wide_service_scoped`-only
    /// posture — `ResultSet` is not a seeded RBAC securable, see
    /// `rest_api_v1.cpp`'s result-set routes doc comment) — the three
    /// dispatch-producer tools are the exception, gated on
    /// `Execution:Execute` exactly like their REST twins.
    void set_result_set_store(ResultSetStore* store) { result_set_store_ = store; }

    /// #2146 Batch B1 — backs `get_guardian_device_compliance`'s Baseline lookup
    /// (`get_baseline_by_name` / `deployed_member_rule_ids`), the SAME store
    /// `GET /api/v1/guaranteed-state/device-compliance` reads. Same setter idiom
    /// as `set_preflight_run_store` above (a persistent raw pointer owned by
    /// `ServerImpl`, outliving the web server). Nullable; the tool answers a
    /// clean "unavailable" 503 when unset, matching every other borrowed-store
    /// seam in this class.
    void set_baseline_store(BaselineStore* store) { baseline_store_ = store; }

    /// #2146 Batch B3 — the fleet-visualization store trio backing
    /// `get_fleet_topology`/`get_host_topology` (mirrors GET
    /// /api/v1/viz/fleet/topology and GET /api/v1/viz/host/{id}/topology).
    /// Same setter idiom as `set_preflight_run_store` above. `offline_store`
    /// may be null (offline hosts are then not stale-flagged, matching
    /// `VizRoutes`' own null-offline-store legacy behavior); `kill_switch`
    /// may be null (then the viz kill switch is never consulted on the MCP
    /// path — production MUST wire the same `--viz-disable` /
    /// `yuzu_viz_disabled` atomic the REST `VizRoutes` registration uses, or
    /// disabling the feature would silently leave the MCP twins reachable).
    /// Unset `fleet_topology_store` (`nullptr`, the default) ⇒ both tools
    /// answer "unavailable" rather than crashing.
    void set_viz_deps(FleetTopologyStore* fleet_topology_store, OfflineEndpointStore* offline_store,
                      const std::atomic<bool>* kill_switch) {
        fleet_topology_store_ = fleet_topology_store;
        offline_endpoint_store_ = offline_store;
        viz_kill_switch_ = kill_switch;
    }

    /// #3290 Phase 2 — the injected-callback twin of
    /// `AuthRoutes::require_fleet_read`, backing `query_installed_software`'s
    /// real per-agent/service confinement (see `authz::FleetReadGate`'s doc
    /// comment, authz_gates.hpp, and `RestApiV1::FleetReadFn`,
    /// rest_api_v1.hpp, for the shared shape — server.cpp wires the SAME
    /// conversion lambda into both surfaces so REST and MCP cannot drift).
    /// Same setter idiom as `set_upload_grant_ops` above (the handler's
    /// `[=]` lambda captures `this`, so the injection is a live read on the
    /// next request). MUST be this tool's SOLE authorization gate — never
    /// stacked with `perm_fn` for the same `(securable_type, operation)`
    /// (the identical BLOCKING defect `require_fleet_read`'s own doc
    /// comment warns against). Unset (default-constructed) ⇒ the tool fails
    /// CLOSED (503 "unwired"), mirroring `RestApiV1`'s own unwired contract
    /// for the identical seam.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    void set_fleet_read_fn(FleetReadFn fn) { fleet_read_fn_ = std::move(fn); }

    /// #4037 — the injected-callback twin of `AuthRoutes::require_list_read`
    /// (ADR-0017), backing `get_guardian_status`'s real confinement. Same
    /// shape as `RestApiV1::ListReadFn`/`ListReadGate` (auth_routes.hpp) reused
    /// verbatim, not redefined, so the REST `GET /guaranteed-state/status`
    /// list-read gate and this MCP twin cannot drift — server.cpp wires the
    /// SAME `list_read_fn` lambda into both surfaces (one conversion, two
    /// surfaces, mirroring `fleet_read_fn`/`set_fleet_read_fn` immediately
    /// above). Route-class distinction from `FleetReadFn` above (ADR-1006
    /// Decision 2, closes #3218): `require_list_read` is the sole gate on
    /// fleet-wide ROLLUP routes — it refuses a service-scoped session
    /// outright, since a rollup has no per-service slice to narrow to — and
    /// is NOT interchangeable with `require_fleet_read`. MUST be this tool's
    /// SOLE authorization gate — never stacked with `perm_fn`/`tier_allows`
    /// for the same `(securable_type, operation)` (same BLOCKING defect class
    /// `require_fleet_read`'s own doc comment warns against; `require_list_read`
    /// already replicates the MCP-tier ladder internally). Unset (default-
    /// constructed) ⇒ the tool fails CLOSED (503 "unwired"), mirroring
    /// `RestApiV1`'s own unwired contract for the identical seam.
    using ListReadFn =
        std::function<yuzu::server::ListReadGate(const httplib::Request&, httplib::Response&,
                                                  const std::string& securable_type,
                                                  const std::string& operation)>;
    void set_list_read_fn(ListReadFn fn) { list_read_fn_ = std::move(fn); }

    /// #2146 Batch B1 — the injected-callback twin of `RestApiV1::GuardianPushFn`
    /// (rest_api_v1.hpp), backing `push_guardian_rules`. Same shape (scope +
    /// full_sync in, agents-reached count out, with -1 = unparseable scope and
    /// -2 = ADR-0038 degraded-store sentinel), reused verbatim so the REST
    /// `POST /api/v1/guaranteed-state/push` route and this MCP twin fan out
    /// through the IDENTICAL closure (server.cpp wires the SAME
    /// `guardian_push_fn_` member into both surfaces) — they cannot drift on
    /// what gets pushed or to whom. Unset (default-constructed) mirrors REST's
    /// own null-callback contract: `push_guardian_rules` degrades to ack-only
    /// with `agents:0` rather than failing (dispatch isn't wired — production
    /// always wires this; the unwired path is a test-only affordance).
    using GuardianPushFn = std::function<int(const std::string& scope, bool full_sync)>;
    void set_guardian_push_fn(GuardianPushFn fn) { guardian_push_fn_ = std::move(fn); }

    /// #4143 review fix (external colleague review, BLOCKING, confirmed against
    /// ADR-0017 INV-4/INV-7 by direct source inspection): `list_tar_process_
    /// tree_devices`/`list_tar_capture_sources_devices` previously intersected
    /// `fleet_read_fn_`'s admit-scope with `tar_devices_fn_`'s direct-
    /// membership-only pre-filter — two divergent resolvers, so an operator
    /// admitted via an ancestor-ward management-group role (not a DIRECT
    /// member) could see an incomplete or empty list despite being admitted
    /// (INV-4/INV-7 violation, not a merely-conservative narrowing). Fixed:
    /// both tools now read this UNFILTERED registry snapshot — the SAME
    /// zero-arg source `list_agents`' own `agents_fn` and REST's
    /// `GET /api/v1/devices` (#4033) use (`registry_.to_json_obj()`) — with
    /// `gate.scope` as the SOLE filter. `list_agents`' unscoped `agents_fn` was
    /// never the gap: `require_fleet_read`'s `gate.scope` is the actual
    /// authorization boundary in that pattern, applied after the unfiltered
    /// read, exactly as here.
    using AllDevicesFn = std::function<std::vector<DeviceRow>()>;
    void set_all_devices_fn(AllDevicesFn fn) { all_devices_fn_ = std::move(fn); }

    /// #4027: `list_tar_retention_paused`'s data source — the SAME
    /// `DashboardRoutes::gather_tar_retention_paused` the REST twin
    /// `GET /api/v1/tar/retention-paused` calls, reached via a raw borrowed
    /// pointer (same lifetime contract as `tar_tree_routes_`/
    /// `dashboard_routes_` in `server.cpp`'s `ServerImpl`: a persistent
    /// `std::unique_ptr` member that outlives the web server, per `stop()`'s
    /// join-before-destruct ordering — safe to borrow raw, same reasoning as
    /// `set_stream_bridge`/`set_kek_ops` above). Nullable; the tool answers a
    /// clean "unavailable" error rather than crashing when unset.
    void set_dashboard_routes(DashboardRoutes* routes) { dashboard_routes_ = routes; }

    /// #4033 — the D3 Response:Read-visible agent SET resolver backing
    /// `preview_management_group_agent_count`'s scope, mirroring
    /// `RestApiV1::ResponseVisibleSetFn`/`DashboardRoutes::VisibleSetFn`
    /// EXACTLY (same doc contract; server.cpp wires the SAME instance into
    /// all three surfaces so REST, MCP, and the `/fragments/create-group-form`
    /// fragment cannot disagree on scope for the same caller). Same setter
    /// idiom as `set_fleet_read_fn` above — live read on the next request.
    /// Unset (default-constructed) ⇒ legacy-open (`nullopt`, unfiltered),
    /// matching an unwired `DashboardRoutes` fixture's behaviour — this tool
    /// is gated on `ManagementGroup:Write` (perm_fn), not this resolver, so
    /// "unwired" degrades to unfiltered rather than failing closed.
    using ResponseVisibleSetFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;
    void set_response_visible_set_fn(ResponseVisibleSetFn fn) {
        response_visible_set_fn_ = std::move(fn);
    }

    /// ADR-0031 WS-A4 (fifth family): the SAME in-process DEX signals API seam
    /// the REST `/api/v1/dex/*` handlers use — server.cpp wires the IDENTICAL
    /// instance so the MCP DEX signal tools can never disagree with REST on the
    /// signal/experience model. The DEX signal tools REQUIRE it: their
    /// harmonized `if (!dex_api_)` readiness guard returns the "Guaranteed State
    /// store unavailable" error when it is null — server.cpp wires it iff the
    /// store is present, so null ⟺ store absent, mirroring verify_api's
    /// null→error contract.
    void set_dex_api(std::shared_ptr<const DexApi> a) { dex_api_ = std::move(a); }

    /// ADR-0031 WS-A4 (sixth family): the SAME in-process DEX app-perf-over-time
    /// API seam the REST `/api/v1/dex/perf/*` handlers use (server.cpp wires the
    /// IDENTICAL instance) — backs the 9 MCP DEX perf tool twins +
    /// get_dex_device_app_perf. server.cpp constructs it UNCONDITIONALLY
    /// (never null) — each backing store pointer is checked individually
    /// inside the impl, matching the old per-lambda null-checks; the tools'
    /// `!dex_perf_api_` readiness guard is defense-in-depth, never expected to
    /// fire. `AppPerfProviders` (the pre-seam bundle) is retired (#4626) — the
    /// dashboard fragments now route through this same seam too.
    void set_dex_perf_api(std::shared_ptr<const DexPerfApi> a) { dex_perf_api_ = std::move(a); }

    /// #4035 hardening (governance): the SAME username-keyed visible-agent-set
    /// resolver `RestApiV1::DexVisibleFn` receives (see its doc comment,
    /// rest_api_v1.hpp) — server.cpp wires the IDENTICAL lambda
    /// (`visible_set_fn`) into the dashboard fragment, the REST twin, and this
    /// MCP twin, so `get_dex_app`/`get_dex_overview` confine their
    /// devices/top_devices lists to the caller's management-group scope
    /// (ADR-0017 World A) exactly like `/fragments/dex/app` and
    /// `/fragments/dex/overview` already do. This is a SECOND, independent
    /// belt alongside `deny_fleet_wide_service_scoped` — that closes the
    /// service-scoped-token axis, this closes the confined-OPERATOR axis.
    /// Unset (default-constructed) degrades to "no confinement" (matching the
    /// fragment's own unwired-`visible_set_fn_` posture), never a crash.
    using DexVisibleFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;
    void set_dex_visible_fn(DexVisibleFn fn) { dex_visible_fn_ = std::move(fn); }

    /// ADR-0031 WS-A4 (seventh family): the SAME in-process schedule-read API
    /// seam the REST `GET /api/v1/schedules` handler and the dashboard
    /// fragment (`GET /fragments/schedules`) use — server.cpp wires the
    /// IDENTICAL instance so `list_schedules` can never disagree with either.
    /// A SETTER, not a `build_handler` parameter (unlike `network_api`) —
    /// mirrors `set_dex_perf_api` above: `build_handler`'s own
    /// `ScheduleEngine* schedule_engine` parameter is now unused inside the
    /// `list_schedules` handler body (superseded by this seam) but is kept,
    /// unremoved, for constructor-signature stability — a bounded, two-site
    /// ripple (the two `ScheduleEngine* schedule_engine` forwarding-overload
    /// parameters in mcp_server.cpp that construct `build_handler`'s caller),
    /// not an open-ended one; a disclosed, deferred follow-up, not an
    /// oversight (matrix doc, `schedule` family row). Unset (default-constructed
    /// null) ⇒ the tool's own `!schedule_api_`
    /// readiness guard answers "Schedule engine unavailable", matching the
    /// pre-seam `!schedule_engine` guard's behaviour exactly.
    void set_schedule_api(std::shared_ptr<const ScheduleApi> a) { schedule_api_ = std::move(a); }

    /// ADR-0031 WS-A4 (eighth family): the SAME in-process workflow-read API
    /// seam the REST `GET /api/v1/workflows[/{id}]` and
    /// `GET /api/v1/workflow-executions/{id}` handlers use — server.cpp
    /// wires the IDENTICAL instance so `list_workflows`/`get_workflow`/
    /// `get_workflow_execution` can never disagree with REST v1.
    /// A SETTER, not a `build_handler` parameter — mirrors `set_schedule_api`
    /// above: `build_handler`'s own `WorkflowEngine* workflow_engine`
    /// parameter is now unused inside these three tool bodies (superseded by
    /// this seam) but is kept, unremoved, for constructor-signature
    /// stability — a bounded, disclosed, deferred follow-up, not an
    /// oversight (matrix doc, `workflow` family row). Unset (default-
    /// constructed null) ⇒ the tools' own `!workflow_api_` readiness guard
    /// answers "Workflow engine unavailable", matching the pre-seam
    /// `!workflow_engine` guard's behaviour exactly.
    void set_workflow_api(std::shared_ptr<const WorkflowApi> a) { workflow_api_ = std::move(a); }

    /// ADR-0031 WS-A4 (ninth family): the SAME in-process Guardian-read API
    /// seam the REST `GET /api/v1/guaranteed-state/*` handlers use —
    /// server.cpp wires the IDENTICAL instance so the eight Guardian read
    /// tools can never disagree with REST v1 (`get_guardian_schemas` stays
    /// outside the seam, store-free — see guardian_api.hpp). `build_handler`'s
    /// own `GuaranteedStateStore* guaranteed_state_store` parameter stays
    /// wired too — the eight Guardian tool bodies below now call
    /// `guardian_api_` exclusively for their reads, but the rule/baseline
    /// MUTATOR tools (`create_guardian_rule` etc., no public seam of their
    /// own) still need the raw store. server.cpp constructs this
    /// UNCONDITIONALLY (never null) — each of the two backing store
    /// pointers is checked INDIVIDUALLY inside the impl (guardian_api.cpp),
    /// mirroring dex_perf_api's own multi-dependency posture: a null
    /// `guaranteed_state_store_` degrades every method, a null
    /// `baseline_store_` degrades ONLY device_compliance. The tools' own
    /// `!guardian_api_` guard is therefore defense-in-depth only, matching
    /// the pre-seam `!guaranteed_state_store` guard's practical behaviour.
    void set_guardian_api(std::shared_ptr<const GuardianApi> a) { guardian_api_ = std::move(a); }

    /// B4 (#2146 API-parity): mirrors `RestApiV1::LockoutClearFn` (rest_api_v1.hpp)
    /// so the MCP `unlock_account` tool clears an account's lockout counter
    /// exactly as the REST `POST /api/v1/users/{name}/unlock` handler does,
    /// without pulling in rest_api_v1.hpp for one nested type (same mirror-not-
    /// reuse discipline as `PublishCrlFn` below, which mirrors `CaRoutes::
    /// PublishCrlFn`). Wraps `AuthDB::clear_failed_logins`. Returns true when
    /// the underlying auth store write succeeded. Empty/unset callback = the
    /// tool answers "lockout subsystem unavailable" (503-equivalent), matching
    /// the REST route's degrade when `lockout_clear_fn` is unwired.
    using LockoutClearFn = std::function<bool(const std::string& username)>;

    /// Republish-CRL callback (PR4 B-2): mirrors `CaRoutes::PublishCrlFn` so the
    /// MCP `revoke_certificate` tool republishes the CRL after a revoke exactly as
    /// the REST `/api/v1/ca/revoke` handler does. Returns the new CRL DER, or
    /// nullopt if the CRL could not be (re)built/persisted.
    using PublishCrlFn = std::function<std::optional<std::vector<std::uint8_t>>()>;

    /// Type of the POST /mcp/v1/ handler — same shape as httplib::Server's Post handler
    /// but exposed independently so tests can dispatch in-process without spinning
    /// up an httplib::Server (see #438 for the TSan-vs-httplib-thread-acceptor bug
    /// that motivated this seam).
    using HandlerFn = std::function<void(const httplib::Request&, httplib::Response&)>;

    /// Build the MCP /mcp/v1/ POST handler. The returned function captures all
    /// callbacks and store pointers by value; `read_only_mode` and `mcp_disabled`
    /// are captured by reference so runtime toggles take effect without re-binding.
    /// Caller MUST keep those two booleans alive at least as long as the handler.
    ///
    /// Tests should call this directly and invoke the returned function with
    /// synthesized httplib::Request / httplib::Response — that path avoids the
    /// httplib::Server acceptor thread that crashes under TSan (#438).
    HandlerFn build_handler(AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                            AgentsJsonFn agents_fn, RbacStore* rbac_store,
                            InstructionStore* instruction_store,
                            ExecutionTracker* execution_tracker, ResponseStore* response_store,
                            AuditStore* audit_store, TagStore* tag_store,
                            InventoryStore* inventory_store, PolicyStore* policy_store,
                            ManagementGroupStore* mgmt_store, ApprovalManager* approval_manager,
                            ScheduleEngine* schedule_engine, const bool& read_only_mode,
                            const bool& mcp_disabled, DispatchFn dispatch_fn = nullptr,
                            CaStore* ca_store = nullptr, PublishCrlFn publish_crl_fn = nullptr,
                            GuaranteedStateStore* guaranteed_state_store = nullptr,
                            DexPerfFn dex_perf_fn = {},
                            // ADR-0031 WS-A4: the public in-process /network API
                            // seam (replaces the former NetPerfFn ad-hoc
                            // provider) — the SAME instance the /network
                            // dashboard fragments and REST /api/v1/network/*
                            // call, so all three surfaces can never disagree.
                            std::shared_ptr<const NetworkApi> network_api = nullptr,
                            ResponseScopeFn response_scope_fn = {},
                            SoftwareInventoryStore* software_inventory_store = nullptr,
                            yuzu::MetricsRegistry* metrics = nullptr,
                            QuarantineStore* quarantine_store = nullptr,
                            TagPushFn tag_push_fn = {},
                            // A2 discovery (roadmap Issue 17.1): backs discover_plugins.
                            // Trailing optional dep, like the rest of this parameter tail —
                            // `nullptr` = discover_plugins answers 503 (unwired).
                            yuzu::server::detail::AgentRegistry* agent_registry = nullptr,
                            // H1 (PR #1796): per-device scope gate for the
                            // device-targeted write tools; see ScopedPermFn above.
                            ScopedPermFn scoped_perm_fn = {},
                            // MCP Streamable HTTP transport (ADR-1005 Decision 15, 2f).
                            // sessions == nullptr ⇒ streaming disabled ⇒ pre-2f behaviour
                            // (no minting, no session/Origin checks) — every legacy caller
                            // and test stays byte-identical except the unconditional 202.
                            // `mcp_streaming_disabled` is captured by pointer (live), not the
                            // stale [=]-over-const-bool& alias pattern.
                            McpSessionRegistry* sessions = nullptr,
                            const bool* mcp_streaming_disabled = nullptr,
                            // 3b: SSE-on-POST gate. nullptr or false = plain path - the
                            // wiring-deps fallback every pre-3b caller gets. The shipped
                            // Config default is now true; nullptr here just means this
                            // caller has not wired the flag in, not the production posture.
                            const bool* mcp_streamed_post_enabled = nullptr,
                            std::vector<std::string> allowed_origins = {},
                            // ADR-0024: backs the query_software_licenses discovery read
                            // (the MCP twin of GET /api/v1/sle/agents/{id}).
                            SoftwareLicensingStore* software_licensing_store = nullptr,
                            // PR 4.2 (design §4.1): backs assign_engine_role /
                            // unassign_engine_role / list_engine_roles — the MCP twins
                            // of the REST engine-principal role-assignment surface.
                            // Trailing optional dep; nullptr leaves assign/unassign
                            // answering an internal-error JSON-RPC response (list still
                            // works if rbac_store is wired).
                            EnginePrincipalStore* engine_principal_store = nullptr,
                            // Periodic Access Reviews (SOC 2 CC6.2) — the campaign store
                            // plus the read-model deps build_access_review needs beyond
                            // rbac_store/engine_principal_store above and
                            // engine_credential_store_ (member, ApiTokenStore). Trailing
                            // optional deps; access_review_store == nullptr leaves the
                            // whole access-review tool family answering "unavailable".
                            AccessReviewStore* access_review_store = nullptr,
                            AuthDB* auth_db = nullptr, DirectorySync* directory_sync = nullptr,
                            // #1788 / PLAN-006: derives the per-request DispatchCaller
                            // (identity + Execution:Execute visible set) for the
                            // execute_instruction / execute_bundle dispatch confinement.
                            // Trailing optional, but UNSET fails CLOSED on exec_visible —
                            // the handlers substitute an empty principal alongside a
                            // present-empty (deny-all) VisibleSet, not unfiltered
                            // (CDX-R6-02); a test seam wanting full fleet wires a callback
                            // whose exec_visible is std::nullopt.
                            //
                            // ORDER (merge with 2f PR 3b): this parameter occupies the
                            // slot #2689's positional call sites use — it REPLACES the
                            // former ExecVisibleFn, whose visible set DispatchCaller now
                            // carries — so the streaming trio still appends after it.
                            CallerFn caller_fn = {},
                            // 2f PR 3b (streamed POST): the SAME shared held-open
                            // budget the GET channel leases from - a streamed POST
                            // pins an HTTP worker exactly as a GET SSE stream does,
                            // so it must be admitted by the same arithmetic. All
                            // three are trailing-defaulted for the test seams;
                            // PRODUCTION MUST WIRE ALL THREE when streaming is on,
                            // for the same reasons build_get_handler states: without
                            // the budget there is no admission control on held-open
                            // workers, without re-validation a revoked credential
                            // keeps its stream, and without the principal sink the
                            // close audit cannot name an actor whose credential may
                            // already be gone. Absent any of them the POST simply
                            // never streams - it answers plain JSON, byte-identical
                            // to today, which is the correct degradation.
                            yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                            StreamRevalidateFn revalidate_fn = {},
                            StreamPrincipalAuditFn principal_audit_fn = {},
                            // #4029 — backs list_product_packs/get_product_pack. Trailing
                            // optional dep; nullptr leaves those two tools answering
                            // "Product pack store unavailable" (kInternalError).
                            ProductPackStore* product_pack_store = nullptr,
                            // #4030: backs list_workflows/get_workflow/get_workflow_execution
                            // — WorkflowEngine was not previously threaded into McpServer at
                            // all. Trailing optional dep; nullptr leaves the three tools
                            // answering an internal-error JSON-RPC response.
                            WorkflowEngine* workflow_engine = nullptr,
                            // gap-matrix #10 (ADR-1005 A5 parity): backs issue_code_signing_cert
                            // — the MCP twin of POST /api/v1/ca/issue-code-signing. Trailing
                            // optional dep; unset leaves the tool answering "CA not available"
                            // (kInternalError), the same degradation ca_store==nullptr produces
                            // for list_issued_certs/revoke_certificate above.
                            IssueCodeSigningFn issue_code_signing_fn = {},
                            // ADR-0031 WS-A4 #4250: the public in-process VERIFY API seam
                            // (replaces the former AppPerfCohortFn-in-AppPerfProviders ad-hoc
                            // cohort provider for compare_app_perf_versions) — the SAME
                            // instance GET /api/v1/dex/perf/compare and the /auto VERIFY
                            // dashboard fragments use, so all three surfaces can never
                            // disagree. Trailing optional dep; nullptr leaves the tool
                            // answering an internal-error JSON-RPC response, same degrade
                            // as the retired cohort provider.
                            std::shared_ptr<const VerifyApi> verify_api = nullptr,
                            // B4 (#2146 API-parity): backs the `unlock_account` tool
                            // (MCP twin of POST /api/v1/users/{name}/unlock). Trailing
                            // optional dep; unset leaves the tool answering "lockout
                            // subsystem unavailable", the same degrade the REST route
                            // takes when its own lockout_clear_fn is unwired.
                            LockoutClearFn lockout_clear_fn = {},
                            // B5 (api-parity #2146) — backs the 5 offload-target MCP
                            // twins. The SAME `offload_target_store_` instance
                            // OffloadRoutes::register_routes wires (server.cpp) — a real,
                            // non-dormant store. Trailing optional dep; nullptr leaves
                            // every offload-target tool answering "unavailable".
                            OffloadTargetStore* offload_target_store = nullptr,
                            // B5 — backs get/activate_platform_license + list_license_alerts.
                            // DELIBERATELY nullptr in production today (ADR-0048: LicenseStore
                            // is dormant, matching RestApiV1's own `/*license_store=*/nullptr`
                            // wiring) — see this header's forward-declaration comment above.
                            LicenseStore* license_store = nullptr,
                            // B5 — backs list/create/rollback/cancel_software_deployment.
                            // DELIBERATELY nullptr in production today (ADR-0051:
                            // SoftwareDeploymentStore is dormant, matching RestApiV1's own
                            // `/*sw_deploy_store=*/nullptr` wiring).
                            SoftwareDeploymentStore* sw_deploy_store = nullptr,
                            // B5 — backs export_ca_root_csr, the MCP twin of GET
                            // /api/v1/ca/root-csr. Reuses `CaRoutes::ExportCsrFn` verbatim
                            // (ca_routes.hpp, already included above for IssueCodeSigningFn)
                            // rather than redeclaring it, so the REST route and this twin
                            // call the identical ServerImpl seam (export_ca_csr()). Trailing
                            // optional dep; unset leaves the tool answering "CA not
                            // available", the same degradation ca_store == nullptr produces
                            // for the other CA tools above.
                            CaRoutes::ExportCsrFn export_csr_fn = {},
                            // B5 — backs import_ca_chain, the MCP twin of POST
                            // /api/v1/ca/import-chain. Reuses `CaRoutes::ImportChainFn`
                            // verbatim; the CRL-republish half reuses the EXISTING
                            // `publish_crl_fn` param above (identical signature to
                            // `CaRoutes::PublishCrlFn`, already wired for
                            // revoke_certificate) rather than adding a second one.
                            // Trailing optional dep; unset leaves the tool answering
                            // "CA not available".
                            CaRoutes::ImportChainFn import_chain_fn = {},
                            // ADR-0031 WS-A4: the public in-process compliance/policy
                            // API seam (replaces direct PolicyStore access for the six
                            // twinned read tools) — the SAME instance the /compliance
                            // dashboard fragments and REST /api/v1/compliance*, /api/v1/
                            // polic* routes use, so all three surfaces can never
                            // disagree. Trailing optional dep; nullptr leaves those
                            // tools on the pre-seam "Policy store unavailable" degrade.
                            std::shared_ptr<const ComplianceApi> compliance_api = nullptr,
                            // ADR-0031 WS-A4 wave 2: the public in-process DEVICE API
                            // seam — backs `list_agents`/`get_agent_details`. The SAME
                            // instance `DeviceRoutes`/REST GET /api/v1/devices[/{id}]
                            // use, so all three surfaces can never disagree. Trailing
                            // optional dep; nullptr leaves both tools on the pre-seam
                            // "internal error"/unwired degrade.
                            std::shared_ptr<const DeviceApi> device_api = nullptr,
                            // wave 7 PR7.2: backs the get_agent_app_usage discovery read (the MCP twin
                            // of GET /api/v1/forensics/agents/{id}/app-usage). TRUE last parameter
                            // (kept last across the device_api merge) so adding it can never shift a
                            // later positional caller's arguments.
                            AppUsageStore* app_usage_store = nullptr);

    /// Build the GET/DELETE handlers for /mcp/v1/ (Streamable HTTP transport).
    /// Separate builders so tests can drive them without the httplib acceptor
    /// thread (#438), mirroring build_handler(). GET is the SSE channel (PR 2:
    /// heartbeats, Last-Event-ID resume, stream caps — the tail lives in
    /// mcp_stream.cpp); DELETE terminates a principal-bound session. Both no-op
    /// to 405 when streaming is disabled and to a kMcpDisabled JSON-RPC error
    /// when MCP is disabled.
    ///
    /// `stream_budget` / `revalidate_fn` are trailing-defaulted for the test
    /// seams; PRODUCTION MUST WIRE BOTH — without the budget there is no
    /// admission control on held-open workers, and without re-validation a
    /// revoked credential keeps its stream (register_routes warns if either is
    /// missing while streaming is on).
    HandlerFn build_get_handler(AuthFn auth_fn, AuditFn audit_fn, const bool* mcp_disabled,
                                const bool* streaming_disabled, McpSessionRegistry* sessions,
                                std::vector<std::string> allowed_origins,
                                yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                                StreamRevalidateFn revalidate_fn = {},
                                yuzu::MetricsRegistry* metrics = nullptr,
                                std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault,
                                StreamPrincipalAuditFn principal_audit_fn = {});
    HandlerFn build_delete_handler(AuthFn auth_fn, AuditFn audit_fn, const bool* mcp_disabled,
                                   const bool* streaming_disabled, McpSessionRegistry* sessions,
                                   std::vector<std::string> allowed_origins);

    /// Register the /mcp/v1/ GET/POST/DELETE routes on `svr` and emit the startup
    /// log line. Production callers use this (it wraps `svr` in an
    /// HttplibRouteSink and delegates to the HttpRouteSink& overload below);
    /// tests prefer build_handler()/build_get_handler()/build_delete_handler()
    /// directly, or the HttpRouteSink& overload for registration-shape coverage
    /// (#2542 PR-6 — in-process via TestRouteSink, no httplib acceptor, #438).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         AgentsJsonFn agents_fn, RbacStore* rbac_store,
                         InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
                         ResponseStore* response_store, AuditStore* audit_store,
                         TagStore* tag_store, InventoryStore* inventory_store,
                         PolicyStore* policy_store, ManagementGroupStore* mgmt_store,
                         ApprovalManager* approval_manager, ScheduleEngine* schedule_engine,
                         const bool& read_only_mode, const bool& mcp_disabled,
                         DispatchFn dispatch_fn = nullptr, CaStore* ca_store = nullptr,
                         PublishCrlFn publish_crl_fn = nullptr,
                         GuaranteedStateStore* guaranteed_state_store = nullptr,
                         DexPerfFn dex_perf_fn = {},
                         // ADR-0031 WS-A4: see build_handler's doc comment above.
                         std::shared_ptr<const NetworkApi> network_api = nullptr,
                         ResponseScopeFn response_scope_fn = {},
                         SoftwareInventoryStore* software_inventory_store = nullptr,
                         yuzu::MetricsRegistry* metrics = nullptr,
                         QuarantineStore* quarantine_store = nullptr,
                         TagPushFn tag_push_fn = {},
                         yuzu::server::detail::AgentRegistry* agent_registry = nullptr,
                         ScopedPermFn scoped_perm_fn = {},
                         // MCP Streamable HTTP transport (ADR-1005 Decision 15, 2f).
                         // Pointer (not const bool&) so a nullptr default cannot bind a
                         // temporary that would dangle once build_handler captures its address.
                         McpSessionRegistry* sessions = nullptr,
                         const bool* mcp_streaming_disabled = nullptr,
                            // 3b: SSE-on-POST gate. nullptr or false = plain path - the
                            // wiring-deps fallback every pre-3b caller gets. The shipped
                            // Config default is now true; nullptr here just means this
                            // caller has not wired the flag in, not the production posture.
                            const bool* mcp_streamed_post_enabled = nullptr,
                         std::vector<std::string> allowed_origins = {},
                         SoftwareLicensingStore* software_licensing_store = nullptr,
                         // PR 4.2 (design §4.1): engine-principal role-assignment MCP
                         // twins (the 4.2 grant handlers capture this param).
                         EnginePrincipalStore* engine_principal_store = nullptr,
                         // Periodic Access Reviews (SOC 2 CC6.2) — see build_handler's
                         // doc comment above; identical trailing-optional-dep contract.
                         AccessReviewStore* access_review_store = nullptr,
                         AuthDB* auth_db = nullptr, DirectorySync* directory_sync = nullptr,
                         // PR 2 (GET SSE channel): the SHARED held-open-stream budget
                         // (one instance across every SSE surface on the httplib pool,
                         // Decision 15(h)) and the per-tick credential re-validation
                         // seam (Decision 15(c)/(i)).
                         yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                         StreamRevalidateFn revalidate_fn = {},
                         // Operator's --mcp-max-streams-per-principal. Threaded from Config
                         // rather than read as a constant at the attach site: without this
                         // the flag parsed, validated and documented as a live control
                         // while having no effect whatsoever.
                         std::size_t mcp_max_streams_per_principal =
                             kMcpStreamsPerPrincipalDefault,
                         // Explicit-principal audit sink for mcp.stream.close (see
                         // StreamPrincipalAuditFn). Empty falls back to the generic sink.
                         StreamPrincipalAuditFn principal_audit_fn = {},
                         // #1788 / PLAN-006: per-request DispatchCaller deriver,
                         // forwarded to build_handler for MCP dispatch confinement.
                         CallerFn caller_fn = {},
                         // #4029 — backs list_product_packs/get_product_pack.
                         ProductPackStore* product_pack_store = nullptr,
                         // #4030: backs list_workflows/get_workflow/get_workflow_execution —
                         // forwarded to build_handler.
                         WorkflowEngine* workflow_engine = nullptr,
                         // gap-matrix #10 (ADR-1005 A5 parity) — forwarded to build_handler.
                         IssueCodeSigningFn issue_code_signing_fn = {},
                         // ADR-0031 WS-A4 #4250: see build_handler's doc comment above.
                         std::shared_ptr<const VerifyApi> verify_api = nullptr,
                         // B4 (#2146 API-parity): see build_handler's doc comment above —
                         // forwarded to it for the `unlock_account` tool.
                         LockoutClearFn lockout_clear_fn = {},
                         // B5 (api-parity #2146) — forwarded to build_handler; see its doc
                         // comments above for each param's contract.
                         OffloadTargetStore* offload_target_store = nullptr,
                         LicenseStore* license_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         CaRoutes::ExportCsrFn export_csr_fn = {},
                         CaRoutes::ImportChainFn import_chain_fn = {},
                         // ADR-0031 WS-A4: see build_handler's doc comment above.
                         std::shared_ptr<const ComplianceApi> compliance_api = nullptr,
                         // ADR-0031 WS-A4 wave 2: see build_handler's doc comment above —
                         // forwarded to it for `list_agents`/`get_agent_details`.
                         std::shared_ptr<const DeviceApi> device_api = nullptr,
                         // wave 7 PR7.2: backs the get_agent_app_usage discovery read (the MCP twin
                         // of GET /api/v1/forensics/agents/{id}/app-usage). TRUE last parameter
                         // (kept last across the device_api merge).
                         AppUsageStore* app_usage_store = nullptr);

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload above wraps
    /// `svr` in an HttplibRouteSink and delegates here; every parameter is
    /// otherwise identical (#2542 PR-6).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         AgentsJsonFn agents_fn, RbacStore* rbac_store,
                         InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
                         ResponseStore* response_store, AuditStore* audit_store,
                         TagStore* tag_store, InventoryStore* inventory_store,
                         PolicyStore* policy_store, ManagementGroupStore* mgmt_store,
                         ApprovalManager* approval_manager, ScheduleEngine* schedule_engine,
                         const bool& read_only_mode, const bool& mcp_disabled,
                         DispatchFn dispatch_fn = nullptr, CaStore* ca_store = nullptr,
                         PublishCrlFn publish_crl_fn = nullptr,
                         GuaranteedStateStore* guaranteed_state_store = nullptr,
                         DexPerfFn dex_perf_fn = {},
                         // ADR-0031 WS-A4: see build_handler's doc comment above.
                         std::shared_ptr<const NetworkApi> network_api = nullptr,
                         ResponseScopeFn response_scope_fn = {},
                         SoftwareInventoryStore* software_inventory_store = nullptr,
                         yuzu::MetricsRegistry* metrics = nullptr,
                         QuarantineStore* quarantine_store = nullptr,
                         TagPushFn tag_push_fn = {},
                         yuzu::server::detail::AgentRegistry* agent_registry = nullptr,
                         ScopedPermFn scoped_perm_fn = {},
                         McpSessionRegistry* sessions = nullptr,
                         const bool* mcp_streaming_disabled = nullptr,
                         const bool* mcp_streamed_post_enabled = nullptr,
                         std::vector<std::string> allowed_origins = {},
                         SoftwareLicensingStore* software_licensing_store = nullptr,
                         EnginePrincipalStore* engine_principal_store = nullptr,
                         AccessReviewStore* access_review_store = nullptr,
                         AuthDB* auth_db = nullptr, DirectorySync* directory_sync = nullptr,
                         yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                         StreamRevalidateFn revalidate_fn = {},
                         std::size_t mcp_max_streams_per_principal =
                             kMcpStreamsPerPrincipalDefault,
                         StreamPrincipalAuditFn principal_audit_fn = {},
                         CallerFn caller_fn = {},
                         // #4029 — backs list_product_packs/get_product_pack.
                         ProductPackStore* product_pack_store = nullptr,
                         // #4030: backs list_workflows/get_workflow/get_workflow_execution.
                         WorkflowEngine* workflow_engine = nullptr,
                         // gap-matrix #10 (ADR-1005 A5 parity) — forwarded to build_handler.
                         IssueCodeSigningFn issue_code_signing_fn = {},
                         // ADR-0031 WS-A4 #4250: see build_handler's doc comment above.
                         std::shared_ptr<const VerifyApi> verify_api = nullptr,
                         // B4 (#2146 API-parity): see build_handler's doc comment above —
                         // forwarded to it for the `unlock_account` tool.
                         LockoutClearFn lockout_clear_fn = {},
                         // B5 (api-parity #2146) — forwarded to build_handler; see its doc
                         // comments above for each param's contract.
                         OffloadTargetStore* offload_target_store = nullptr,
                         LicenseStore* license_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         CaRoutes::ExportCsrFn export_csr_fn = {},
                         CaRoutes::ImportChainFn import_chain_fn = {},
                         // ADR-0031 WS-A4: see build_handler's doc comment above.
                         std::shared_ptr<const ComplianceApi> compliance_api = nullptr,
                         // ADR-0031 WS-A4 wave 2: see build_handler's doc comment above —
                         // forwarded to it for `list_agents`/`get_agent_details`.
                         std::shared_ptr<const DeviceApi> device_api = nullptr,
                         // wave 7 PR7.2: backs the get_agent_app_usage discovery read (the MCP twin
                         // of GET /api/v1/forensics/agents/{id}/app-usage). TRUE last parameter
                         // (kept last across the device_api merge).
                         AppUsageStore* app_usage_store = nullptr);

private:
    // ── Engine-principal lifecycle wiring (ADR-1005 item 2b, plan PR 4.3) ──
    // COEXISTENCE (4.2→4.3 rebase): the 4.2 role-assignment handlers use the
    // register_routes `engine_principal_store` PARAM above; the 4.3 lifecycle
    // handlers use these MEMBERS (set via the setters above). server.cpp wires
    // BOTH to the same store. Follow-up: unify onto the member. Nullable;
    // every tool checks before use and answers a clean "unavailable" error.
    EnginePrincipalStore* engine_principal_store_{nullptr};
    ApiTokenStore* engine_credential_store_{nullptr};
    OwnerExistsFn owner_exists_fn_;
    // #3685 — see ClassifyFn's doc comment above: unset means
    // execute_instruction fails closed at BOTH gate sites (mcp_server.cpp),
    // never a silent fall-through to the pre-#3685 unconfined behaviour.
    ClassifyFn classify_fn_;
    // #3687 — see AuthorizeDispatchFn's doc comment above: unset means the
    // pre-dispatch dry run in mcp_server.cpp fails closed rather than
    // silently reverting to the pre-#3687 collapsed-envelope behaviour.
    AuthorizeDispatchFn authorize_dispatch_fn_;
    // Progress bridge core (2f PR 3a) - see set_stream_bridge above.
    McpStreamBridge* stream_bridge_{nullptr};
    // KEK rotation seam (#2395 track C) - see set_kek_ops above. Default-
    // constructed (all three std::functions empty) until server.cpp wires it.
    KekOps kek_ops_;
    // ADR-0031 operator surface (PR1.5c/1.6c, p14) - see set_plugin_config_store
    // / set_upload_grant_ops above. Nullable; every backed tool checks before
    // use and answers a clean "unavailable" error, matching
    // engine_principal_store_'s contract above.
    PluginConfigStore* plugin_config_store_{nullptr};
    UploadGrantStore* upload_grant_store_{nullptr};
    UploadGrantListReadFn upload_grant_list_read_fn_;
    // #3290 Phase 2 — see set_fleet_read_fn above.
    FleetReadFn fleet_read_fn_;
    // #4037 — see set_list_read_fn above.
    ListReadFn list_read_fn_;
    // #4036 (api-parity Batch A) — see set_preflight_run_store above.
    PreflightRunStore* preflight_run_store_{nullptr};
    // #2146 Batch B2 — see set_result_set_store above.
    ResultSetStore* result_set_store_{nullptr};
    // #2146 Batch B1 — see set_baseline_store above.
    BaselineStore* baseline_store_{nullptr};
    // #2146 Batch B1 — see set_guardian_push_fn above.
    GuardianPushFn guardian_push_fn_;
    // #2146 Batch B3 — see set_viz_deps above.
    FleetTopologyStore* fleet_topology_store_{nullptr};
    OfflineEndpointStore* offline_endpoint_store_{nullptr};
    const std::atomic<bool>* viz_kill_switch_{nullptr};
    // #4143 review fix — see set_all_devices_fn above.
    AllDevicesFn all_devices_fn_;
    DashboardRoutes* dashboard_routes_{nullptr};
    // #4033 — see set_response_visible_set_fn above.
    ResponseVisibleSetFn response_visible_set_fn_;
    // ADR-0031 WS-A4 (fifth family) — see set_dex_api above.
    std::shared_ptr<const DexApi> dex_api_;
    std::shared_ptr<const DexPerfApi> dex_perf_api_;
    // #4035 hardening (governance) — see set_dex_visible_fn above.
    DexVisibleFn dex_visible_fn_;
    // ADR-0031 WS-A4 (seventh family) — see set_schedule_api above.
    std::shared_ptr<const ScheduleApi> schedule_api_;
    // ADR-0031 WS-A4 (eighth family) — see set_workflow_api above.
    std::shared_ptr<const WorkflowApi> workflow_api_;
    // ADR-0031 WS-A4 (ninth family) — see set_guardian_api above.
    std::shared_ptr<const GuardianApi> guardian_api_;
};

// The (tool, securable, operation) test-only accessors that formerly lived here
// were relocated to mcp_server_testonly.hpp (issue #2385) — production callers
// have no reason to see them.

// The served tool names whose calls can reach the #2405 pre-approval
// input-schema gate — every tool whose (securable, operation) makes
// requires_approval() true for some tier. Sorted, deterministic. This is the
// closed label set server.cpp pre-seeds for yuzu_mcp_tool_args_invalid_total
// (docs/observability-conventions.md: bounded-label counters are pre-seeded
// to 0 so absent() alerts stay meaningful).
std::vector<std::string> approval_gated_tool_names();

} // namespace yuzu::server::mcp
