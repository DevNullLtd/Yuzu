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

#include "authz_model.hpp" // authz::VisibleSet (WP06 F4)
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

    /// WP06 F4 (interim; #6065 owns the dispatch-identity change and is untouched): the
    /// REQUEST principal's authority over ONE instruction id. A policy fragment's check /
    /// postCheck / fix instruction later runs through the evaluator as the SYSTEM caller, so the
    /// per-action RBAC, the `ExecuteGate` and per-device visibility are never consulted at fire
    /// time. This closure is the authoring-time (and manual-remediate) check: it resolves the
    /// instruction id to its (plugin, action), runs the SHARED `authorize_dispatch` dry run for
    /// the request's principal as a NON-system caller, and reports the principal's per-device
    /// execution visibility. server.cpp wires it from the same `authorize_dispatch` closure MCP
    /// and the workflow execute twins use (set after construction: that closure is defined
    /// later than this route group). Unset or unresolvable = REFUSED (fail closed).
    struct InstructionAuthority {
        bool ok{false};
        int status{403};         ///< HTTP status to answer when !ok (401/403/400/503)
        std::string message;     ///< operator-facing refusal text when !ok
        std::string plugin_action; ///< "plugin.action" the instruction id resolved to (when ok)
        authz::VisibleSet visible{authz::deny_all()}; ///< exec visibility (nullopt = unrestricted)
    };
    using AuthorizeInstructionFn =
        std::function<InstructionAuthority(const httplib::Request&, const std::string& instruction_id)>;
    void set_authorize_instruction_fn(AuthorizeInstructionFn fn) {
        authorize_instruction_fn_ = std::move(fn);
    }

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
    AuthorizeInstructionFn authorize_instruction_fn_;

    /// WP06 F4: authorize every instruction a fragment YAML names for the request principal.
    /// Writes the refusal (and a denied audit row) and returns false on any refusal.
    bool authorize_fragment_instructions(const httplib::Request& req, httplib::Response& res,
                                         const std::string& yaml_source,
                                         std::string& instruction_pairs_out);
};

} // namespace yuzu::server
