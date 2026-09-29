#pragma once

/// @file policy_admin_routes.hpp
/// Policy/fragment MUTATOR + dispatch routes, split out of
/// `compliance_routes.cpp` by ADR-0031 WS-A4 Task B: POST/DELETE
/// policy-fragments, POST/DELETE policies, enable/disable/invalidate(-all),
/// evaluate, remediate.
///
/// **DELIBERATELY OUTSIDE the seam-closure enforced set
/// (`scripts/ci/check-seam-closure.py`'s `compliance` family).** INV-31-4
/// ("no private core API") requires a seam method to mirror a public
/// REST/MCP resource 1:1 — these handlers have NO public v1 REST or MCP
/// twin (they are legacy `/api/...` dashboard-only routes), so wrapping them
/// behind `ComplianceApi` would itself mint a private core API rather than
/// close one. This is a WS-A3 gap for the compliance family (no public
/// mutator surface yet), tracked on the `/split` delivery matrix — not an
/// oversight of this split. `PolicyAdminRoutes` therefore keeps direct
/// `PolicyStore`/`PolicyEvaluator` access BY DESIGN, exactly as it did
/// inside `ComplianceRoutes` before this split — only the file moved.

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"
#include "policy_store.hpp"

#include <yuzu/metrics.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class PolicyEvaluator;

/// Policy/fragment mutator routes — POST/DELETE /api/policy-fragments*,
/// POST/DELETE/enable/disable/invalidate(-all)/evaluate/remediate
/// /api/policies*. See the file banner above for why this stays outside the
/// compliance family's seam-closure enforcement.
class PolicyAdminRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req,
                                           const nlohmann::json& attrs,
                                           const nlohmann::json& payload_data)>;

    /// Register all policy/fragment mutator routes on the given server.
    ///
    /// Production overload — wraps `httplib::Server&` in an HttplibRouteSink
    /// and delegates to the sink-based overload below.
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         PolicyStore* policy_store,
                         PolicyEvaluator* policy_evaluator = nullptr,
                         /// #2500 - counts a refused remediation target. nullptr = no metric;
                         /// the REFUSAL never depends on this being wired.
                         yuzu::MetricsRegistry* metrics = nullptr);

    /// Sink-based overload — used by tests. See `tests/unit/server/test_route_sink.hpp`.
    void register_routes(HttpRouteSink& sink,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         PolicyStore* policy_store,
                         PolicyEvaluator* policy_evaluator = nullptr,
                         yuzu::MetricsRegistry* metrics = nullptr);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    EmitEventFn emit_event_fn_;
    PolicyStore* policy_store_{};
    PolicyEvaluator* policy_evaluator_{};
    yuzu::MetricsRegistry* metrics_{};
};

} // namespace yuzu::server
