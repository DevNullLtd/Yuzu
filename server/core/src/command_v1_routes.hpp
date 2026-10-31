#pragma once

/// @file command_v1_routes.hpp
/// POST /api/v1/commands -- the REST v1 twin of POST /api/command (ledger row
/// `post.api-command`, ADR-1005 / #2146) and of the MCP tool `execute_instruction`.
///
/// WHICH TEMPLATE. This route is shaped after MCP `execute_instruction`, not after the legacy
/// `command_routes.cpp`: it dispatches through the ONE confined seam
/// (`RestApiV1::CommandDispatchFn` -> `dispatch_confined` -> `wire_and_dispatch_confined`), it
/// mints an execution row and returns its `execution_id`, and an omitted target list is the
/// fleet (`kBroadcastScope`) for everything except a Destructive or Forensics pair. It carries
/// none of the dashboard's UI fields (thead_html, HX-Trigger, SSE publish). The legacy route's
/// `stagger` and `delay` have no field here: the seam does not carry them, and an unknown
/// request field is REFUSED (`unknown_field`) rather than ignored, so a caller can never believe
/// a command was held that was sent at once.
///
/// ORDER (the contract; a test pins each step):
///   authenticate -> Execution:Execute gate -> same-principal re-check -> body depth ->
///   parse (object) -> bounds + targeting shape (ONE copy: mcp::check_exec_instruction_shape,
///   which wraps check_targeting_shape) -> omitted target => kBroadcastScope ->
///   evaluate_destructive_targeting (ONE copy; a Destructive pair needs explicit non-empty
///   agent_ids, `__all__` is refused; a Forensics pair needs exactly one id) -> the pair's own
///   securable gate (as the legacy route) -> confine_destructive_targets to the caller's
///   management-group-visible agents (404 destructive_no_visible_target) -> caller derivation ->
///   dispatch-chokepoint dry run (classify + authorize + kill switch) -> `requested` audit row,
///   FAIL CLOSED (503 + Sec-Audit-Failed, nothing dispatched) -> execution row -> dispatch ->
///   zero-reach classification (`classify_zero_reach`) or the 202 body.
///
/// THE CALLER. `Deps::derive_caller_fn` is `ServerImpl::derive_dispatch_caller`, the same
/// derivation MCP and `/api/command` use: it carries the CALLER's real `principal_is_admin` and
/// `exec_visible` (service-scoped and engine principals included). This file constructs no
/// `DispatchCaller` of its own and never stamps `approval_provenance` (REST has no ticket flow),
/// so a gated pair is reachable only by an administrator caller.
///
/// SERVICE-SCOPED TOKENS. The first gate is `Execution:Execute`; a service-scoped token is
/// refused there (403) because `kServiceScopeGlobalSafe` is empty. If a future allow-list entry
/// ever admitted one, `exec_visible` (service-tagged agents only) still confines the send set.
///
/// AUDIT. Every row is stamped from the session this handler resolved (`audit_as_session`), never
/// by re-resolving the request. Caller-supplied text embedded in a detail goes through
/// `audit_token` (CWE-117).

#include "agent_registry.hpp" // detail::DispatchDenial
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp" // ConfinedDispatchOutcome
#include "dispatch_target_shape.hpp"  // BoundViolation
#include "dispatch_zero_reach.hpp"    // ZeroReachCause

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server {
class HttpRouteSink;
}

namespace yuzu::server::command_v1 {

/// The execution-row operations the route needs. Empty `create` means "no execution tracker":
/// the route still dispatches and answers an empty `execution_id`, as MCP does.
struct ExecutionOps {
    /// Mint a `running` row; the handler passes the dispatching principal, the scope text and
    /// the REDACTED parameter JSON. Returns the id or an error text.
    std::function<std::expected<std::string, std::string>(
        const std::string& dispatched_by, const std::string& scope_expression,
        const std::string& parameter_values_json)>
        create;
    /// Mark the row cancelled (zero reach, or a dispatch that threw). False = bookkeeping failed.
    std::function<bool(const std::string& execution_id, const std::string& by)> mark_cancelled;
    /// Record how many agents were reached and refresh the counts. False = bookkeeping failed.
    std::function<bool(const std::string& execution_id, int agents_reached)> set_targeted;
};

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable, const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Session-bound writer (`AuthRoutes::audit_as_session_fn()`): the row names `session`.
    using AuditAsSessionFn = std::function<bool(
        const httplib::Request& req, const auth::Session& session,
        const std::string& principal_role, const std::string& action, const std::string& result,
        const std::string& target_type, const std::string& target_id, const std::string& detail)>;
    using ClassifyFn = std::function<std::expected<CommandCapability, ClassificationError>(
        std::string_view plugin, std::string_view action)>;
    using AuthorizeDispatchFn = std::function<std::expected<CommandCapability, detail::DispatchDenial>(
        const DispatchCaller& caller, std::string_view plugin, std::string_view action)>;
    using DispatchFn = std::function<ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const DispatchCaller& caller)>;
    using DeriveCallerFn = std::function<DispatchCaller(const auth::Session&)>;
    /// Management-group-visible agents of `username` (ManagementGroupStore::get_visible_agents).
    /// `nullopt` = degraded read, which the Destructive confinement treats as fail-closed-empty.
    /// An UNWIRED function is the same fail-closed answer.
    using VisibleAgentsFn =
        std::function<std::optional<std::vector<std::string>>(const std::string& username)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    AuditFn audit_fn; ///< re-resolving writer: used ONLY for the unwired-session-writer failure row
    AuditAsSessionFn audit_as_session;
    ClassifyFn classify_fn;
    AuthorizeDispatchFn authorize_dispatch_fn;
    DispatchFn dispatch_fn;
    DeriveCallerFn derive_caller_fn;
    VisibleAgentsFn visible_agents_fn;
    ExecutionOps execution;
    yuzu::MetricsRegistry* metrics = nullptr;
};

/// Registers `POST /api/v1/commands`.
void register_command_v1_routes(HttpRouteSink& sink, Deps deps);

/// The closed set of request fields. Anything else is refused as `unknown_field`.
inline constexpr std::string_view kAllowedFields[] = {"plugin", "action", "params", "agent_ids",
                                                      "scope"};

/// Reason tokens this route emits beyond `kTargetingShapeReasons`/`kExecInstrBoundReasons`.
inline constexpr std::string_view kReasonUnknownField{"unknown_field"};
inline constexpr std::string_view kReasonParamsType{"params_type"};

/// Bounds + shape of a parsed request body. The MCP `execute_instruction` rules, from the same
/// constants (`mcp_input_bounds.hpp`) and the same pure shape check; the rules the MCP handler
/// spells inline (length of identifiers, scope, agent ids, parameter values, id count) are
/// spelled here once for this route. Pure and total. Returns the FIRST violation.
[[nodiscard]] std::optional<BoundViolation> check_command_v1_request(const nlohmann::json& body);

/// How a zero-reach cause is answered. Pure, so a test can pin the whole table.
struct ZeroReachReply {
    int status;
    std::string_view reason;
    std::optional<std::int64_t> retry_after_ms; ///< set only where `zero_reach_retryable`
    std::string message;
    std::string remediation;
};
/// `scope_error` is the parser diagnostic of `ConfinedDispatchOutcome::scope_parse_error`
/// (only read for `InvalidScope`).
[[nodiscard]] ZeroReachReply zero_reach_reply(ZeroReachCause cause, std::string_view scope_error);

} // namespace yuzu::server::command_v1
