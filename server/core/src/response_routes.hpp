#pragma once

/// @file response_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-11) — the 3-route legacy pre-v1 Responses API: per-instruction
/// agent-response aggregate/export/list over `ResponseStore`. Every handler
/// body is copied verbatim from server.cpp; the changes are the receiver
/// (`web_server_->` -> `sink.`), the gate closure (`require_fleet_read` ->
/// `deps.fleet_read_fn`), the member access (`response_store_.` ->
/// `deps.store->`), and the audit call (`audit_log(...)` -> `deps.audit_fn(...)`).
///
/// REGISTRATION ORDER IS LOAD-BEARING (do not reorder without re-verifying
/// against httplib's routing semantics): the two specific patterns MUST be
/// registered before the generic catch-all, exactly as in the pre-extraction
/// inline code (both carried an explicit "must be registered before the
/// catch-all responses route" comment) — httplib::Server::Get tries every
/// registered GET pattern in registration order and dispatches to the FIRST
/// match. `/api/responses/([^/]+)/aggregate` and `/api/responses/([^/]+)/export`
/// both also satisfy `/api/responses/(.+)` (its capture group is `.+`, which
/// matches a `/`-containing tail like `abc/aggregate` just as readily as a
/// bare id) — so registering the catch-all first would silently swallow both
/// specific routes. `register_response_routes` below preserves the exact
/// original order (aggregate, export, then the catch-all) inside one
/// function body, which is sufficient regardless of where the call itself
/// lands relative to any other extracted module's registration — no other
/// route pattern in the tree overlaps `/api/responses/*`.
///
/// #1634 / ADR-0017 INV-3 confinement: all 3 routes gate on
/// `deps.fleet_read_fn(req, res, "Response", "Read")` (`AuthRoutes::
/// require_fleet_read`, admit-then-filter) as their SOLE authorization gate
/// — never stacked with `perm_fn` for the same tuple. On an ENGAGED scope,
/// each handler resolves the instruction's distinct responding agents,
/// narrows to the in-scope subset via `authz::in_scope`, and pushes that
/// subset into the store query/aggregate call BEFORE any LIMIT/OFFSET is
/// applied (a post-fetch filter on a paginated read can hand a confined
/// caller a short or empty page even though visible rows exist past the
/// hidden ones LIMIT already truncated — see each handler's own inline
/// comment, preserved verbatim).
///
/// AUDIT: each route emits a `"response.read"`/`"denied"` row ONLY when the
/// gate's scope is engaged AND at least one distinct responding agent was
/// dropped by the scope filter (CC7.2 evidence — a scope-drop is a
/// security-relevant filtering event); the `surface` detail distinguishes
/// `aggregate`/`export`/`get`. No other outcome on any of the 3 routes is
/// audited (pure reads otherwise) — matches the pre-extraction inline code
/// exactly.
///
/// Routes (3), gate in parens (all `fleet_read_fn`):
///   GET /api/responses/:id/aggregate  (Response:Read) — MUST register 1st
///   GET /api/responses/:id/export     (Response:Read) — MUST register 2nd
///   GET /api/responses/(.+)           (Response:Read) — generic catch-all,
///                                      MUST register LAST

#include "authz_gates.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class ResponseStore;
} // namespace yuzu::server

namespace yuzu::server::response {

/// Construction deps for `register_response_routes`. Every closure/pointer
/// is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    /// Wraps `AuthRoutes::require_fleet_read` — see this file's header
    /// comment. The SOLE authorization gate on all 3 routes.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    FleetReadFn fleet_read_fn;
    AuditFn audit_fn;
    /// `ServerImpl::response_store_`. Null or `!is_open()` -> every route
    /// answers 503 without touching it.
    ResponseStore* store{nullptr};
};

/// Register all 3 Responses API routes against `sink`, in the load-bearing
/// order documented above (aggregate, export, catch-all).
void register_response_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::response
