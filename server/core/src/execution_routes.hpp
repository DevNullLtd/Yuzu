#pragma once

/// @file execution_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-7) — the 7-route legacy pre-v1 Executions API
/// (`docs/executions-history-ladder.md`): list/detail/summary/agents/rerun/
/// cancel/children over `ExecutionTracker`. Every handler body is copied
/// verbatim from server.cpp; the changes are the receiver (`web_server_->`
/// -> `sink.`), the gate closures (`require_permission`/`require_fleet_read`
/// -> `deps.perm_fn`/`deps.fleet_read_fn`), the member access
/// (`execution_tracker_.` -> `deps.execution_tracker->`,
/// `auth_routes_->resolve_session` -> `deps.resolve_session_fn`), and the
/// audit/event calls (`audit_log(...)` -> `deps.audit_fn(...)`,
/// `emit_event(...)` -> `deps.emit_event_fn(...)`).
///
/// #3789 CONFINEMENT — the reason this cluster exists as its own module
/// rather than folding into `dashboard_api_routes`. Every route below is
/// gated on `deps.fleet_read_fn(req, res, "Execution", "Read")`
/// (`AuthRoutes::require_fleet_read`, ADR-0017 admit-then-filter) — the
/// SOLE authorization gate for the five GET routes, exactly as
/// `require_fleet_read`'s own doc comment requires (never stacked with
/// `perm_fn` for the SAME `(securable_type, operation)` tuple — that is the
/// documented BLOCKING defect the gate exists to prevent recurring).
///
/// **`rerun`/`cancel` are the one deliberate EXCEPTION to that rule, not a
/// violation of it.** Both call `deps.perm_fn(req, res, "Execution",
/// "Execute")` FIRST, then `deps.fleet_read_fn(req, res, "Execution",
/// "Read")` second — two DIFFERENT `(type, operation)` tuples, not two
/// gates on the same one. `require_fleet_read` is structurally Read-only
/// (`authz_gates.cpp`) and cannot itself decide whether a caller may
/// mutate; the pre-existing `Execute` permission check is retained ahead of
/// it for that reason (server.cpp's original `-- Execution API --` block
/// comment, preserved below). A caller denied `Execute` never reaches the
/// fleet gate at all. A caller who holds `Execute` but fails the fleet
/// gate's per-execution complete-cohort-in-scope check
/// (`admit_confined_mutation`, `execution_scope_rules.hpp`) is denied with
/// a uniform 404. Do not read this as license to stack `perm_fn` +
/// `fleet_read_fn` on the same tuple elsewhere — see `authz_gates.hpp`'s
/// own doc comment for why that pairing was tried and rejected.
///
/// `execution_visible` / `confined_projection` / `admit_confined_mutation`
/// (`execution_scope_rules.hpp`) are pure, `this`-free helpers — included
/// directly, not wrapped in a `Deps` closure. `authz::in_scope` /
/// `authz::VisibleSet` (`authz_model.hpp`) likewise.
///
/// NEW DEPS FIELD — `resolve_session_fn`. Every route under an ENGAGED
/// scope (`gate.scope` truthy) needs the caller's username for the
/// ownership disjunct in `execution_visible`/`admit_confined_mutation`, via
/// `auth_routes_->resolve_session(req)` — a NON-BLOCKING resolve that never
/// writes to `res` on failure (unlike `deps.auth_fn`, which wraps
/// `require_auth` and DOES write a 401 on failure). Substituting `auth_fn`
/// here would be a behaviour change: `require_fleet_read` has already
/// admitted the request by the time this runs, so a resolve failure at
/// this point is not expected in practice, but the ORIGINAL code never
/// gated on it either — every route treats an empty resolved username as
/// its own explicit fail-closed 503 ("unable to resolve caller identity
/// for a confined read"), not a second auth denial. Hoisted alongside
/// `auth_fn`/`perm_fn` in server.cpp's shared closure block since
/// `instruction_routes.cpp`'s `POST /api/instructions` needs the identical
/// non-blocking shape for `created_by`.
///
/// NEW DEPS FIELD — `emit_event_fn`. Wraps `ServerImpl::emit_event`
/// (`auth_routes_->emit_event`), which no earlier #2542 route-sink
/// extraction has needed (`command_routes.hpp`'s equivalent field predates
/// this campaign — #2557). Only the FULL 4-argument shape this cluster's
/// two call sites use
/// (`event_type`, `req`, `attrs`, `payload_data`) is exposed — neither call
/// site passes a non-default `Severity`, so (matching
/// `custom_properties_routes.hpp`'s `DenyServiceScopedFn` precedent for an
/// unused trailing argument) `Severity` is not part of the closure's
/// signature; the closure applies the default (`kInfo`) internally.
///
/// AUDIT ASYMMETRIES (preserved verbatim, not introduced by this move):
///   - The five GET routes (list/detail/summary/agents/children) audit
///     `"execution.read"`/`"denied"` ONLY when `gate.scope` is engaged AND
///     the row is invisible/nonexistent — an UNCONFINED caller's
///     genuinely-nonexistent id is ordinary 404, not a confinement
///     decision, and writes NO audit row at all (compliance-officer, #3789
///     Gate 6 F2: auditing every 404 as "denied" would inflate the CC7.2
///     denial-rate metric with routine traffic). The caller-visible 404 is
///     identical either way — only the server-side audit trail differs.
///     Every SUCCESSFUL read on these five routes is unaudited (pure
///     reads), matching every other #2542 extraction's read/write split.
///   - `rerun`: the confined-mutation-denied branch audits `"denied"`;
///     `execution_tracker_->create_rerun` returning an error is a plain 400
///     with NO audit call at all; only a genuine SUCCESS is audited.
///   - `cancel`: the confined-mutation-denied branch audits `"denied"`; the
///     unconfined + unknown-id 404 branch is NOT audited (mirrors the GET
///     routes' unconfined-404 rule); `mark_cancelled` returning `false`
///     audits `"failure"` (503); success audits `"success"`.
///   - **Target-type casing split (pre-existing, not this move's doing):**
///     the GET routes' denial rows use PascalCase `"Execution"` as
///     `target_type`; `rerun`/`cancel`'s rows use lowercase `"execution"`.
///     Both are copied verbatim — this is not a defect this extraction
///     introduces or is positioned to fix.
///   - `deps.audit_fn` (a `std::function`) has no default arguments, unlike
///     the `ServerImpl::audit_log` member it replaces (`detail = {}`).
///     Every call site that relied on that default now passes `""`
///     explicitly for `detail` — same audit row, no behaviour change.
///
/// Routes (7), gate in parens (`Read` = `fleet_read_fn`, `Execute` =
/// `perm_fn` ahead of `fleet_read_fn`):
///   GET  /api/executions                  (Read)
///   GET  /api/executions/:id              (Read)
///   GET  /api/executions/:id/summary      (Read)
///   GET  /api/executions/:id/agents       (Read)
///   POST /api/executions/:id/rerun        (Execute, then Read)
///   POST /api/executions/:id/cancel       (Execute, then Read)
///   GET  /api/executions/:id/children     (Read)

#include "authz_gates.hpp"
#include "authz_model.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class ExecutionTracker;
} // namespace yuzu::server

namespace yuzu::server::execution {

/// Construction deps for `register_execution_routes`. Every closure/pointer
/// is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Wraps `AuthRoutes::require_fleet_read` — see this file's header
    /// comment for the deliberate `perm_fn`-then-`fleet_read_fn` stacking
    /// on `rerun`/`cancel` (different tuples, not the same-tuple pairing
    /// `require_fleet_read`'s own doc comment forbids).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    /// Wraps `AuthRoutes::resolve_session` — see this file's header
    /// comment's "NEW DEPS FIELD" note for why this is a distinct,
    /// non-blocking closure rather than a reuse of an `auth_fn`-shaped one.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Wraps `ServerImpl::emit_event` — see this file's header comment's
    /// "NEW DEPS FIELD" note for the exposed 4-argument shape.
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req, const nlohmann::json& attrs,
                                           const nlohmann::json& payload_data)>;

    PermFn perm_fn;
    FleetReadFn fleet_read_fn;
    ResolveSessionFn resolve_session_fn;
    AuditFn audit_fn;
    EmitEventFn emit_event_fn;
    /// `ServerImpl::execution_tracker_`. Null -> every route answers 503
    /// ("service unavailable") without touching it — matches the original
    /// inline code's `if (!execution_tracker_)` guard on all 7 routes.
    ExecutionTracker* execution_tracker{nullptr};
};

/// Register all 7 legacy pre-v1 Executions API routes against `sink`.
void register_execution_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::execution
