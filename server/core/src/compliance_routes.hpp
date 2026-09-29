#pragma once

/// @file compliance_routes.hpp
/// Extracted from server.cpp — Compliance dashboard HTMX routes plus the
/// read-only /api/policies*, /api/policy-fragments*, /api/compliance* twins
/// (legacy AND v1). Phase 3a of the god-object decomposition; ADR-0031 WS-A4
/// Task B rewired this file OFF `policy_store.hpp` and onto the store-free
/// `ComplianceApi` seam (`compliance_api.hpp`) — the mutator/dispatch routes
/// that have no public REST/MCP twin (POST/DELETE policy-fragments +
/// policies, enable/disable/invalidate(-all), evaluate, remediate) moved
/// verbatim to `policy_admin_routes.{hpp,cpp}`, which deliberately keeps
/// direct `PolicyStore`/`PolicyEvaluator` access — see that header's banner.

#include <yuzu/server/auth.hpp>

#include "authz_gates.hpp" // authz::FleetReadGate — FleetReadFn (#4034)
#include "compliance_api.hpp" // ADR-0031 WS-A4: the public in-process compliance/policy API seam
#include "http_route_sink.hpp"

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace yuzu::server {


/// Compliance READ routes — /compliance, /fragments/compliance/*,
/// GET /api/policies*, GET /api/policy-fragments*, GET /api/compliance*
/// (legacy and v1 twins). The mutator/dispatch routes live in
/// `PolicyAdminRoutes` (policy_admin_routes.hpp) — see that header's banner
/// for why they cannot be seamed (INV-31-4, no public twin).
class ComplianceRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// #4034: widened `void` -> `bool` so a route can capture the persist
    /// outcome via `detail::try_persist_audit` (matching `RestApiV1::AuditFn`
    /// / `DexRoutes::AuditFn` / `mcp::McpServer::AuditFn`'s shared contract).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Callback to get agents JSON string (avoids incomplete-type dep on AgentRegistry).
    using AgentsJsonFn = std::function<std::string()>;

    /// #3290 Phase 2 / #4034 — the injected-callback twin of
    /// `AuthRoutes::require_fleet_read` (see `authz::FleetReadGate`'s doc
    /// comment, authz_gates.hpp). `GET /api/v1/compliance/{id}`'s SOLE
    /// authorization gate for its per-agent status fan-out — never stacked
    /// with `perm_fn_` (the same BLOCKING rule `rest_api_v1.hpp`'s
    /// `FleetReadFn` doc comment states). The empty/default `{}` exists ONLY
    /// for source-stability of the other (unrelated) call sites — the route
    /// that requires this gate treats an unwired fn as misconfiguration and
    /// FAILS CLOSED (503).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// The public in-process compliance/policy API (ADR-0031 WS-A4) — the
    /// SAME seam GET /api/v1/compliance*, /api/v1/polic* and the MCP
    /// compliance tools call, so this dashboard/route surface can never
    /// disagree with those siblings. Nullable → the routes render an honest
    /// "store not available" degrade (mirrors network_routes.hpp/
    /// verify_routes.hpp's `api = nullptr` default).
    using ComplianceApiPtr = std::shared_ptr<const ComplianceApi>;

    /// Register all compliance READ routes on the given server.
    ///
    /// Production overload — wraps `httplib::Server&` in an HttplibRouteSink
    /// and delegates to the sink-based overload below.
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         ComplianceApiPtr api,
                         AgentsJsonFn agents_json_fn,
                         /// #4034 — GET /api/v1/compliance/{id}'s sole gate. Trailing/
                         /// defaulted so no pre-#4034 positional call site needs updating.
                         FleetReadFn fleet_read_fn = {});

    /// Sink-based overload — used by tests. See `tests/unit/server/test_route_sink.hpp`.
    void register_routes(HttpRouteSink& sink,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         ComplianceApiPtr api,
                         AgentsJsonFn agents_json_fn,
                         FleetReadFn fleet_read_fn = {});

private:
    // -- Fragment renderers (called by route handlers) -------------------------

    std::string render_compliance_summary_fragment();
    std::string render_compliance_detail_fragment(const std::string& policy_id);

    // guardian-confinement-2298 PR3 §3e: both compliance fragments below are
    // auth_fn_-only (no perm_fn_ at all) and render per-agent compliance rows
    // fleet-wide plus policy scope expressions — no per-target parameter to
    // scope against. Same shape/ordering/throw-safety contract as
    // GuardianRoutes::deny_service_scoped_ (JSON A4 body even though the
    // caller is an HTMX fragment route — that's the established precedent
    // for this route class, not a fragment-specific shape).
    [[nodiscard]] bool deny_service_scoped_(const httplib::Request& req,
                                            httplib::Response& res) const;

    // -- Static helpers -------------------------------------------------------

    static const char* compliance_level(int pct);

    // -- Dependency pointers (stored by register_routes) -----------------------

    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    ComplianceApiPtr api_;
    AgentsJsonFn agents_json_fn_;
    FleetReadFn fleet_read_fn_; // #4034
};

} // namespace yuzu::server
