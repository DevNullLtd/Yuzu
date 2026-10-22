#pragma once

/// @file health_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-10) — the 7-route Health/Infra cluster: the Prometheus
/// metrics endpoint, the `/health` + `/api/health` JSON probe, the
/// Kubernetes-style `/livez` + `/readyz` probes, the HTMX dashboard's
/// health-summary strip fragment, and the Dashboard health panel fragment.
/// Every handler body is copied verbatim
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
///   - `/health`, `/api/health`, `/livez` and `/readyz` are UNAUTHENTICATED at the
///     transport level: server.cpp's pre-routing middleware (the lambda registered
///     via `web_server_->set_pre_routing_handler`, NOT part of this extraction)
///     exempts these four paths from the on-behalf-of guard and from the 401 gate
///     BEFORE the request ever reaches the handlers this file registers. That
///     exemption is load-bearing infrastructure (a monitoring probe or an
///     orchestrator health check must work with no credentials) and stays in
///     server.cpp, which calls this header's `is_probe_path` for the probe set.
///     `/health` and `/api/health` requests that carry a credential header are
///     rate limited there, through `admit_probe_request` below, against a
///     per-source bucket of their own; credential-less requests, `/livez` and
///     `/readyz` are not charged. (`/metrics` is not a probe
///     path: it goes through the ordinary rate limiter and the 401 gate, with a
///     localhost / `--metrics-no-auth` carve-out in server.cpp.)
///   - `/health`/`/api/health`'s shared `health_handler` ADDITIONALLY does
///     its own optional, non-blocking session resolve
///     (`deps.resolve_session_fn`, never writes to `res` on failure) to
///     decide whether to include the heavier authenticated-only
///     `agents.pending`/`executions.*`/`system.*` fields. It does so ONLY when
///     the request carries a credential (a Cookie, Authorization or
///     X-Yuzu-Token header, `request_carries_credential`); a request with none
///     is treated as unauthenticated without touching the session store.
///     An unauthenticated caller still gets 200 with the cheap probe fields;
///     this is NOT a gate, just a response-shape branch.
///   - PLAINTEXT REDIRECT LISTENER (#5906): when HTTPS is on, the HTTP->HTTPS
///     redirect listener (`--web-port`, 8080 by default) ALSO serves exactly
///     `/livez`, `/readyz`, `/health` and `/api/health`, to GET and HEAD
///     requests that declare no body (`is_plaintext_probe_request`); every
///     other request still 301s. This is the same recorded ADR-1005 exception
///     as the main listener's, with two differences: no session is ever
///     resolved on plaintext (the session resolver is bound to "no session"),
///     so `/health` and `/api/health` ALWAYS return
///     the unauthenticated shape there — `system.*`, `agents.pending` and
///     `executions.*` never travel over plaintext, even when the request carries
///     a valid session cookie — and every answer is 503
///     `{"status":"not ready","reason":"https_listener_not_serving"}` while the
///     HTTPS listener is not bound or has exited. The guarantee is "bound
///     and not yet exited", NOT "accepting": after a fatal accept error httplib
///     closes the listening socket but `is_running()` stays true until
///     already-accepted requests drain (httplib.h:11307-11330, 11269), so the
///     gate can answer 200 for that drain window; new connections are refused
///     throughout it. The gate exists because the redirect listener runs on its
///     own thread and would otherwise report healthy for a server whose only
///     real listener failed to bind. `/livez` and `/readyz` are the same handlers
///     as the main sink's, wrapped by the 503 gate; `/health` and `/api/health` go
///     through a second thin closure over the ONE shared `health_body`.
///     The redirect listener's responses carry the five security headers (no
///     HSTS) and are counted in `yuzu_http_requests_total` through
///     `install_plaintext_post_routing`; the 301s are counted too.
///   - `/fragments/health/summary` is one of the two routes in this cluster that
///     require a session (with `/fragments/dashboard/health`): `deps.deny_service_scoped_fn` first
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
/// Routes (7), plus /livez, /readyz, /health and /api/health again on
/// `deps.plaintext_probe_sink` when set:
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
///   GET /fragments/dashboard/health (deny_service_scoped_fn THEN auth_fn; every
///                                     outcome after auth is a 200 panel note —
///                                     without a session the pre-routing gate
///                                     answers first (a 302 to the sign-in page, or
///                                     401 with HX-Redirect for HX requests) and
///                                     auth_fn is the backstop — the Dashboard health panel,
///                                     which calls the registered `health_handler`
///                                     in-process)

#include "authz_gates.hpp" // authz::FleetReadGate (Dashboard health panel)
#include "rate_limiter.hpp"
#include "security_headers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

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
class EnablementStore;
class AppUsageStore;
class ProductRegistryStore;
class ProductPackStore;
class ScimStore;
class AnalyticsEventStore;
class CryptoDashboardLayoutStore; // /readyz "degraded" notice only (ADR-0071 degrade posture)

// /metrics ONLY.
class NvdDatabase;
class NvdSyncManager;

namespace health {

/// The closed set of unauthenticated probe paths (the recorded ADR-1005
/// exception). ONE definition: the main listener's pre-routing chokepoint and
/// the plaintext redirect listener both test membership through it.
[[nodiscard]] constexpr bool is_probe_path(std::string_view p) {
    return p == "/livez" || p == "/readyz" || p == "/health" || p == "/api/health";
}

/// True when `/health` or `/api/health` should resolve a session: the request carries at
/// least one of the three credential sources `AuthRoutes::resolve_session` reads (the
/// `Cookie`, `Authorization` and `X-Yuzu-Token` headers). A request with none cannot
/// resolve to a session, so the probe answers it as unauthenticated without a store lookup.
/// Deliberately coarse (header presence, not a parsed token): a request that does carry a
/// header still goes through `resolve_session_fn` exactly as before.
[[nodiscard]] inline bool request_carries_credential(const httplib::Request& req) {
    return req.has_header("Cookie") || req.has_header("Authorization") ||
           req.has_header("X-Yuzu-Token");
}

/// The two probe paths that serve an authenticated body shape and so are rate limited.
[[nodiscard]] constexpr bool is_rate_limited_probe_path(std::string_view p) {
    return p == "/health" || p == "/api/health";
}

/// The per-source rate-limit gate for `/health` and `/api/health`, called by the
/// pre-routing chokepoint in server.cpp with `api_rate_limiter_` (the `--rate-limit`
/// limiter, default 100 requests/second per source). Only a request that carries a
/// credential header (`request_carries_credential`) is charged. The check is on header
/// presence, whether or not the credential is valid, and is coarse by design: a `Cookie`
/// without a `yuzu_session=` value or a non-Bearer `Authorization` header is charged
/// although it never reaches the session store (the empty-token guard makes the rest
/// cheap). A request with none is answered without a session-store lookup and returns true without
/// touching the limiter, so a credential-less monitor behind a shared address is never
/// throttled. The bucket key carries a prefix so probe traffic and API traffic from one
/// source do not draw on each other's budget. Returns true when the request may proceed;
/// any other path returns true without touching the limiter. On refusal `res` is filled
/// with the standard 429 (A4 envelope).
///
/// Residual: the limiter keeps one entry per source address and `RateLimiter::purge_stale`
/// has no production caller, so entries are retained until the server restarts. Purging
/// them is planned follow-up work.
///
/// A new credential source added to `AuthRoutes::resolve_session` must also be added to
/// `request_carries_credential`, otherwise requests using it are neither charged here nor
/// resolved by the handler.
[[nodiscard]] inline bool admit_probe_request(RateLimiter& limiter, const httplib::Request& req,
                                              httplib::Response& res) {
    if (!is_rate_limited_probe_path(req.path))
        return true;
    if (!request_carries_credential(req))
        return true;
    if (limiter.allow("probe:" + req.remote_addr))
        return true;
    write_rate_limited_response(res);
    return false;
}

/// True for a request the plaintext redirect listener serves instead of
/// redirecting: GET or HEAD on an exact probe path that declares no body.
/// HEAD is admitted because httplib dispatches it to the GET handlers
/// (httplib.h:11420) and omits the body on write (httplib.h:10822, 10836), so
/// no second registration is needed. A probe carrying Content-Length or
/// Transfer-Encoding stays a 301: httplib runs the pre-routing handler BEFORE it
/// reads a body (httplib.h:11337-11413), so declining those keeps the plaintext
/// listener from ever buffering one. That ordering is a dependency on httplib
/// 0.37.1 — a version that read the body first would invalidate this reasoning.
/// Because no body is ever admitted here, this listener needs no row in
/// `body_cap_policy.hpp`'s table (the #2407 routed-concerns row).
[[nodiscard]] inline bool is_plaintext_probe_request(const httplib::Request& req) {
    return (req.method == "GET" || req.method == "HEAD") && is_probe_path(req.path) &&
           !req.has_header("Content-Length") && !req.has_header("Transfer-Encoding");
}

/// The HTTP->HTTPS redirect listener's pre-routing handler. Probe GET/HEAD
/// requests (`is_plaintext_probe_request`) fall through to the routes
/// `register_health_routes` puts on this server; everything else 301s to
/// https://<Host-or-web_address>:<https_port><path>[?query]. Lives here, not in
/// server.cpp, so a real-listener test covers the production wiring (#5906).
void install_plaintext_redirect_pre_routing(httplib::Server& srv, std::string web_address,
                                            int https_port);

/// The redirect listener's post-routing handler (#5906): applies `headers` (the five security
/// response headers every other HTTP response carries, SOC2-C1) and then calls `on_response`
/// (the request counter; may be empty). The caller builds `headers` for a non-HTTPS bundle
/// (`HeaderBundle::make(extras, /*https_enabled=*/false)`), which omits
/// Strict-Transport-Security (RFC 6797 s7.2: no STS over a non-secure transport) and
/// upgrade-insecure-requests. Deliberately nothing else from the main listener's post-routing
/// handler: no engine-class stash (never written on this listener's workers), no quota slot, no
/// CORS.
void install_plaintext_post_routing(
    httplib::Server& srv, security::HeaderBundle headers,
    std::function<void(const httplib::Request&, const httplib::Response&)> on_response);

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

    /// Dashboard health panel only (`/fragments/dashboard/health`): the admit-then-filter
    /// gate for the "Executions running" row. Optional: unbound -> the row is
    /// omitted (never shown unfiltered).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    AuthFn auth_fn;                          // /fragments/health/summary
    ResolveSessionFn resolve_session_fn;      // /health, /api/health
    DenyServiceScopedFn deny_service_scoped_fn; // /fragments/health/summary
    FleetReadFn fleet_read_fn;                  // /fragments/dashboard/health (optional)
    /// Optional: when set, /livez, /readyz, /health and /api/health are ALSO
    /// registered here (the HTTP->HTTPS redirect listener) — see the AUTH
    /// POSTURE banner. Requires `main_listener_serving_fn`.
    HttpRouteSink* plaintext_probe_sink{nullptr};
    /// True while the HTTPS listener is bound and has not exited
    /// (`web_server_->is_running()`); the plaintext sink answers 503 otherwise.
    /// Required iff `plaintext_probe_sink` is set (registration throws
    /// `std::invalid_argument` if unbound).
    std::function<bool()> main_listener_serving_fn;

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
    EnablementStore* enablement_store{nullptr}; // ADR-3006 (also a /healthz row)
    AppUsageStore* app_usage_store{nullptr}; // Wave 7 PR7.2 (gov Gate 3 sre HIGH finding)
    ProductRegistryStore* product_registry_store{nullptr};
    ProductPackStore* product_pack_store{nullptr};
    ScimStore* scim_store{nullptr};
    AnalyticsEventStore* analytics_store{nullptr};
    /// Non-gating: a layout store that did not open at boot is reset to null by server.cpp (the
    /// server boots without saved layouts), so null here means "did not open" - reported under
    /// /readyz's "degraded", never in failed_stores.
    CryptoDashboardLayoutStore* crypto_dashboard_layout_store{nullptr};

    // ---- /metrics ONLY ----
    NvdDatabase* nvd_db{nullptr};
    NvdSyncManager* nvd_sync{nullptr};
};

/// Register all 7 Health/Infra routes against `sink` (and the four probes on
/// `deps.plaintext_probe_sink` when set). Throws `std::invalid_argument` if
/// `deps.cfg` or `deps.metrics` is null, or if a plaintext sink is given
/// without `main_listener_serving_fn` — see this file's header comment.
void register_health_routes(HttpRouteSink& sink, Deps deps);

} // namespace health
} // namespace yuzu::server
