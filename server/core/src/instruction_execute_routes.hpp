#pragma once

/// @file instruction_execute_routes.hpp
/// `POST /api/v1/instructions/{id}/execute`: the versioned REST twin of the legacy
/// `POST /api/instructions/{id}/execute` (ledger row `post.api-instructions-param-execute`,
/// #2146, ADR-1005 Decision 4). The MCP twin is `execute_instruction_definition`
/// (mcp_instruction_execute.cpp). Both call the one core in instruction_execute.hpp, which owns
/// the pipeline and the approval composition; this file owns the gate, the wire envelope and the
/// audit action.
///
/// GATE: `Execution:Execute` via `perm_fn` (plain, global), the legacy route's own pair. A
/// service-scoped token is refused by `require_permission` itself (`kServiceScopeGlobalSafe` is
/// seeded empty), an engine principal is RBAC-only and default-deny, and a supervised-tier MCP
/// token is refused on this REST path by `requires_approval` (the C8 ticket flow exists only on
/// `/mcp/v1/`). WHO IS REACHED is decided downstream by the confined dispatch with the caller's
/// `exec_visible`; the gate is not the confinement.
///
/// ORDER (the refusal ladder; the first match wins, and no step before `requested` writes a
/// ticket, an execution row or a command):
///   perm_fn -> depth guard 400 -> JSON parse 400 -> [core: definition 503/404 -> dispatch
///   authorization 400/403/500 -> body-is-object 400 -> targeting shape 400 -> stored
///   parameter_schema 500/400 -> destructive targeting 400/404 -> approval_mode 503/500/202 ->
///   audit `requested` fail-closed 503 -> execution row -> confined dispatch -> zero-reach
///   400/503 | 200].
///
/// RESPONSES (success body is `{"data":..., "meta":{"api_version":"v1"}}`):
///   200 dispatched                {command_id, execution_id, agents_reached, definition_id}
///   202 pending approval          {status:"pending_approval", approval_id, approval_mode, definition_id}
///   errors use the A4 envelope plus a `reason` token; zero-reach carries execution_id and counts.
/// There is NO CSRF check here: the central same-site write gate (`apply_same_site_write_gate`)
/// covers every cookie-session write before routing.
///
/// AUDIT: action `instruction.execute`, target `instruction`/`<definition id>`, rows `denied`
/// (refusals), `pending`, `requested` (fail closed: 503 + `Sec-Audit-Failed`, nothing
/// dispatched), then `success` or `failure`. A best-effort row that fails to persist sets
/// `Sec-Audit-Failed` on the response; the command already ran.

#include "instruction_execute.hpp"

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
}

namespace yuzu::server::instruction_execute {

struct RouteDeps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string& securable, const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Resolves the caller's DispatchCaller from the request: the SAME closure
    /// (`command_dispatch_caller`'s sibling, server.cpp `derive_dispatch_caller`) the legacy
    /// route uses. Unset fails CLOSED on visibility: an empty principal with a present-EMPTY
    /// `exec_visible` (deny all), never nullopt, which would mean unfiltered.
    using CallerFn = std::function<DispatchCaller(const httplib::Request&)>;

    PermFn perm_fn;
    AuditFn audit_fn;
    CallerFn caller_fn;
    /// Everything impure (stores, dispatch, metrics); `audit` is bound per request below.
    Ports ports;
};

void register_instruction_execute_routes(HttpRouteSink& sink, RouteDeps deps);

} // namespace yuzu::server::instruction_execute
