#pragma once

/// @file health_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-10) — the 6-route Health/Infra cluster: the Prometheus
/// metrics endpoint, the `/health` + `/api/health` JSON probe, the
/// Kubernetes-style `/livez` + `/readyz` probes, and the HTMX dashboard's
/// health-summary strip fragment. Every handler body is copied verbatim
/// from server.cpp; the changes are the receiver (`web_server_->` ->
/// `sink.`), member/store accesses (`xyz_store_.` -> `deps.xyz_store->`),
/// the gate closures (`require_auth`/`auth_routes_->resolve_session`/
/// `auth_routes_->deny_service_scoped_session` -> `deps.auth_fn`/
/// `deps.resolve_session_fn`/`deps.deny_service_scoped_fn`, all three
/// already hoisted server.cpp closures — this module introduces none of
/// its own), and the null-safety additions documented below.
///
/// AUTH POSTURE — preserved EXACTLY per route, not uniform across the
/// cluster (do not "fix" this into one shape):
///   - `/metrics`, `/health`, `/api/health`, `/livez`, `/readyz` are
///     UNAUTHENTICATED at the transport level — server.cpp's pre-routing
///     middleware (the lambda registered via `web_server_->set_pre_routing_
///     handler_ish`-equivalent block, NOT part of this extraction) exempts
///     these five paths from session resolution and rate limiting BEFORE
///     the request ever reaches the handlers this file registers. That
///     exemption is load-bearing infrastructure (a monitoring probe or an
///     orchestrator health check must work with no credentials) and stays
///     in server.cpp untouched — grep `req.path == "/livez"` there.
///   - `/health`/`/api/health`'s shared `health_handler` ADDITIONALLY does
///     its own optional, non-blocking session resolve
///     (`deps.resolve_session_fn`, never writes to `res` on failure) to
///     decide whether to include the heavier authenticated-only
///     `agents.pending`/`executions.*`/`system.*` fields. An unauthenticated
///     caller still gets 200 with the cheap probe fields — this is NOT a
///     gate, just a response-shape branch.
///   - `/fragments/health/summary` is the one route in this cluster that
///     genuinely requires a session: `deps.deny_service_scoped_fn` first
///     (guardian-confinement-2298 PR3 §3e — service-scoped tokens denied),
///     THEN `deps.auth_fn` (blocking `require_auth`, writes 401 on
///     failure) — same double-session-resolution shape documented in
///     result_set_routes.hpp's header comment (PR-5).
///
/// DEPS NULL-SAFETY — two different rules, by field:
///   - `cfg`, `metrics`, and the three hoisted closures (`auth_fn`,
///     `resolve_session_fn`, `deny_service_scoped_fn`) are REQUIRED:
///     `register_health_routes` throws `std::invalid_argument` if any is
///     unbound. `cfg`/`metrics` are non-pointer `ServerImpl` members
///     (`Config cfg_`, `MetricsRegistry metrics_`), never null in
///     production; the three closures are always bound at the one real
///     call site — same "wiring bug caught at boot, not a runtime condition
///     to degrade around" rationale as `dashboard_api_routes.hpp`'s
///     `VisibleAgentsJsonFn` (an unbound `std::function` would otherwise
///     throw `std::bad_function_call` on first request instead of at
///     registration). `cfg` gates ~7 conditional store checks across
///     `/health`/`/readyz` with mixed lenient/strict effects; a null value
///     would silently mis-shape readiness data in a way a reviewer could
///     not reason about, unlike the graceful degrades below (which have one
///     obvious fail-closed meaning apiece). `metrics` IS the entire point
///     of `/metrics` — no degrade is coherent.
///   - Every other pointer field defaults to null and degrades gracefully,
///     matching the SAME `ptr && ptr->method()` idiom this cluster's own
///     handler bodies already use for the ~40 store pointers below (never
///     null in production; this is a test-harness affordance only):
///     `registry` -> 0 agents online; `draining` -> not draining;
///     `auth_mgr` -> every `is_*_ok()` read false (fail-closed, matching
///     the store-pointer idiom) and `list_pending_agents()` skipped (0
///     pending); `process_health_sampler` -> a zeroed `ProcessHealth{}`;
///     `default_cert_set` -> empty fingerprint / epoch expiry. None of
///     these five null-guards exists in the original inline code (each was
///     a non-pointer `ServerImpl` member, never null) — deliberate
///     non-verbatim additions, same category as `page_routes.hpp`'s
///     `!deps.registry` guard.
///
/// `nvd_metrics_scrape_mu_` (the per-scrape serialization lock inside the
/// `/metrics` handler) had exactly one use site in server.cpp — the
/// `/metrics` handler itself — so it is NOT a Deps field. It moves into
/// `register_health_routes`'s own body as a `std::make_shared<std::mutex>()`
/// captured by the `/metrics` lambda: a local with no other ServerImpl
/// dependency, same justification as PR-5's `rs_get_owned` closure move.
/// The corresponding `ServerImpl::nvd_metrics_scrape_mu_` member declaration
/// is deleted from server.cpp by this extraction (dead after the move).
///
/// Routes (6):
///   GET /metrics                    (unauthenticated from 127.0.0.1/::1 always;
///                                     remote depends on cfg_.metrics_require_auth
///                                     — that branch lives in server.cpp's
///                                     pre-routing middleware, NOT here)
///   GET /health                     (health_handler — see AUTH POSTURE above)
///   GET /api/health                 (SAME `health_handler` instance as /health —
///                                     do not split into two lambda bodies; the
///                                     unauthenticated `system.*` gating is
///                                     load-bearing and must run identically on
///                                     both routes)
///   GET /livez                      (no gate, no deps — trivial process-alive probe)
///   GET /readyz                     (no gate — draining_, runtime pg_reachable, boot-latched store checks)
///   GET /fragments/health/summary   (deny_service_scoped_fn THEN auth_fn)

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;
struct Config;
struct DefaultCertSet;

namespace detail {
class AgentRegistry;
class ProcessHealthSampler;
} // namespace detail

namespace pg {
class PgPool;
} // namespace pg

// Stores checked by /health AND /readyz (also /fragments/health/summary
// where noted).
class PgReachabilityProbe; // HA WS-8: /readyz pg_reachable + /metrics gauges
class ResponseStore;       // + fragment summary
class AuditStore;          // + fragment summary
class InstructionStore;
class ApprovalManager;
class PolicyStore;         // + fragment summary
class RbacStore;
class TagStore;
class GuaranteedStateStore; // + fragment summary
class BaselineStore;        // + fragment summary
class OffloadTargetStore;
class WebhookStore;
class CaStore;
class UpdateRegistry;
class OfflineEndpointStore;
class SoftwareInventoryStore;
class VulnFindingStore;
class AppPerfDailyStore;
class AppPerfFleetStore;
class DeviceInventoryStore;
class InventoryStore;
class ResultSetStore;
class DiscoveryStore;
class DeploymentStore;
class QuarantineStore;
class NotificationStore;
class UploadGrantStore;
class RuntimeConfigStore;
class PatchManager;
class DirectorySync;
class WorkflowEngine;
class ScheduleEngine;
class ExecutionTracker;    // + fragment summary
class CommandOutboxStore;  // WS-3 3.3: /readyz + /healthz + /metrics backlog gauge
class ManagementGroupStore; // + /metrics

// Stores checked by /readyz ONLY.
class ApiTokenStore;
class EnginePrincipalStore;
class CustomPropertiesStore;
class FleetTopologyStore;
class AccessReviewStore;
class SoftwareLicensingStore;
class PluginConfigStore;
class AppUsageStore;
class ProductRegistryStore;
class ProductPackStore;
class ScimStore;
class AnalyticsEventStore;

// /metrics ONLY.
class NvdDatabase;
class NvdSyncManager;

namespace health {

/// Construction deps for `register_health_routes`. Every closure/pointer is
/// bound once at start_web_server() time in server.cpp and never reseated.
/// See this file's header comment for the REQUIRED-vs-graceful null-safety
/// split.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Non-blocking session resolve — never writes to `res` on failure.
    /// Wraps `AuthRoutes::resolve_session`; the SAME hoisted server.cpp
    /// closure `instruction_routes.cpp`/`execution_routes.cpp` already use
    /// (#2542 PR-7), reused here rather than re-invented.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;
    /// Wraps `AuthRoutes::deny_service_scoped_session` — the SAME hoisted
    /// server.cpp closure `result_set_routes.cpp` already uses (#2542 PR-5),
    /// reused here rather than re-invented; see that module's header
    /// comment ("NEW DEPS FIELD") for the full rationale. This module's one
    /// call site (`/fragments/health/summary`) passes `""` for both
    /// `target_type` and `target_id` — the original inline call omitted
    /// both (defaulted-empty at the `AuthRoutes` method itself), matching
    /// result_set_routes.cpp's `sidebar`/`create` call sites' precedent for
    /// a route with no single target.
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& action, const std::string& message,
                           const std::string& target_type, const std::string& target_id)>;

    AuthFn auth_fn;                          // /fragments/health/summary
    ResolveSessionFn resolve_session_fn;      // /health, /api/health
    DenyServiceScopedFn deny_service_scoped_fn; // /fragments/health/summary

    // ---- REQUIRED (registration throws std::invalid_argument if null) ----
    Config* cfg{nullptr};
    yuzu::MetricsRegistry* metrics{nullptr};

    // ---- graceful-degrade infra (never null in production) ----
    yuzu::server::detail::AgentRegistry* registry{nullptr};
    yuzu::server::detail::ProcessHealthSampler* process_health_sampler{nullptr};
    auth::AuthManager* auth_mgr{nullptr};
    DefaultCertSet* default_cert_set{nullptr};
    /// `ServerImpl::draining_`. /readyz only.
    const std::atomic<bool>* draining{nullptr};
    /// `ServerImpl::server_start_time_`. Trivially copyable, never
    /// reassigned after member-init in the original — passed by value
    /// rather than by pointer.
    std::chrono::steady_clock::time_point server_start_time{};

    // ---- stores checked by /health AND /readyz (see per-field comments
    // above for the ones ALSO read by /fragments/health/summary or
    // /metrics) ----
    pg::PgPool* pg_pool{nullptr};
    /// HA WS-8 (ADR-2002 §12): the runtime Postgres-reachability probe —
    /// `/readyz`'s gating `pg_reachable` row, and the `yuzu_server_pg_*`
    /// reachability gauges refreshed on `/metrics` scrape. Read only through
    /// `snapshot()`/`verdict()` — a copy under the probe's leaf mutex, never
    /// held across I/O, so a stalled probe cannot stall a handler. Null degrades
    /// FAIL-CLOSED (row reports not ready), matching the store-pointer idiom;
    /// never null in production whenever `pg_pool` is set.
    PgReachabilityProbe* pg_reachability_probe{nullptr};
    ResponseStore* response_store{nullptr};
    AuditStore* audit_store{nullptr};
    InstructionStore* instruction_store{nullptr};
    ApprovalManager* approval_manager{nullptr};
    PolicyStore* policy_store{nullptr};
    RbacStore* rbac_store{nullptr};
    TagStore* tag_store{nullptr};
    ManagementGroupStore* mgmt_group_store{nullptr};
    GuaranteedStateStore* guaranteed_state_store{nullptr};
    BaselineStore* baseline_store{nullptr};
    OffloadTargetStore* offload_target_store{nullptr};
    WebhookStore* webhook_store{nullptr};
    CaStore* ca_store{nullptr};
    UpdateRegistry* update_registry{nullptr};
    OfflineEndpointStore* offline_endpoint_store{nullptr};
    SoftwareInventoryStore* software_inventory_store{nullptr};
    VulnFindingStore* vuln_finding_store{nullptr};
    AppPerfDailyStore* app_perf_daily_store{nullptr};
    AppPerfFleetStore* app_perf_fleet_store{nullptr};
    DeviceInventoryStore* device_inventory_store{nullptr};
    InventoryStore* inventory_store{nullptr};
    ResultSetStore* result_set_store{nullptr};
    DiscoveryStore* discovery_store{nullptr};
    DeploymentStore* deployment_store{nullptr};
    QuarantineStore* quarantine_store{nullptr};
    NotificationStore* notification_store{nullptr};
    UploadGrantStore* upload_grant_store{nullptr};
    RuntimeConfigStore* runtime_config_store{nullptr};
    PatchManager* patch_manager{nullptr};
    DirectorySync* directory_sync{nullptr};
    WorkflowEngine* workflow_engine{nullptr};
    ScheduleEngine* schedule_engine{nullptr};
    ExecutionTracker* execution_tracker{nullptr};
    CommandOutboxStore* command_outbox_store{nullptr}; // WS-3 3.3

    // ---- stores checked by /readyz ONLY ----
    ApiTokenStore* api_token_store{nullptr};
    EnginePrincipalStore* engine_principal_store{nullptr};
    CustomPropertiesStore* custom_properties_store{nullptr};
    FleetTopologyStore* fleet_topology_store{nullptr};
    AccessReviewStore* access_review_store{nullptr};
    SoftwareLicensingStore* software_licensing_store{nullptr};
    PluginConfigStore* plugin_config_store{nullptr};
    AppUsageStore* app_usage_store{nullptr}; // Wave 7 PR7.2 (gov Gate 3 sre HIGH finding)
    ProductRegistryStore* product_registry_store{nullptr};
    ProductPackStore* product_pack_store{nullptr};
    ScimStore* scim_store{nullptr};
    AnalyticsEventStore* analytics_store{nullptr};

    // ---- /metrics ONLY ----
    NvdDatabase* nvd_db{nullptr};
    NvdSyncManager* nvd_sync{nullptr};
};

/// Register all 6 Health/Infra routes against `sink`. Throws
/// `std::invalid_argument` if `deps.cfg` or `deps.metrics` is null — see
/// this file's header comment.
void register_health_routes(HttpRouteSink& sink, Deps deps);

} // namespace health
} // namespace yuzu::server
