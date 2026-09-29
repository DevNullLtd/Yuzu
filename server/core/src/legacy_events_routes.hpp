#pragma once

/// @file legacy_events_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the single-route legacy
/// `GET /events` fleet-wide SSE dashboard stream (pre-dates the W5.1
/// agentic-first `GET /api/v1/events` in `rest_api_v1.cpp`, which stays the
/// canonical taxonomy per `docs/executions-history-ladder.md` — this route
/// is the OLDER `detail::EventBus`-backed stream, not a second copy of the
/// newer one).
///
/// SSE-EXTRACTION SAFETY (checked, not assumed — see PR-12's own
/// governance-ledger self-review entry for the full note): this route was a
/// candidate to defer if genuinely incompatible with `HttpRouteSink`'s
/// synchronous request/response model. It is NOT incompatible. `GET /api/v1/events`
/// (`rest_api_v1.cpp`) is the existing, in-production precedent — it is
/// ALREADY registered through this exact seam (`sink.Get("/api/v1/events",
/// ...)`) and already carries its own `TestRouteSink` coverage
/// (`test_rest_api_events.cpp`), whose own file header documents precisely
/// this boundary: the synchronous handler phase (auth -> gate -> admission
/// -> bus-subscribe -> `set_chunked_content_provider` registration) is
/// fully exercised through the sink; the wire-level chunked SSE framing
/// itself is deliberately NOT unit-tested (covered by UAT/integration
/// instead) because `TestRouteSink` does not drive httplib's actual socket
/// I/O loop. `HttplibRouteSink::Get` forwards byte-identically to
/// `httplib::Server::Get` in production, so nothing about moving this
/// route's REGISTRATION onto the sink changes its runtime behaviour — only
/// its TEST reachability changes (for the better: this route previously had
/// NO unit coverage at all). `test_legacy_events_routes.cpp` mirrors
/// `test_rest_api_events.cpp`'s split exactly.
///
/// Every handler body is copied verbatim from server.cpp; the changes are
/// the receiver (`web_server_->` -> `sink.`), the two gate closures
/// (`auth_routes_->deny_service_scoped_session` -> `deps.deny_service_scoped_fn`,
/// `auth_routes_->resolve_session` -> `deps.resolve_session_fn`), and the
/// member access (`stream_budget_.` -> `deps.stream_budget->`, `event_bus_`
/// -> `*deps.event_bus`). One guard's SHAPE changes without changing its
/// behaviour: the original `if (auth_routes_) { ... }` (a null-pointer
/// check) becomes `if (deps.resolve_session_fn) { ... }` (a
/// `std::function`-empty check) — vacuously true either way, since
/// `auth_routes_` is unconditionally constructed before `start_web_server()`
/// runs and `resolve_session_fn` is bound unconditionally at registration
/// time, matching every other #2542 module's convention.
///
/// ADMISSION CONTROL (ADR-0034): this route leases from the SAME
/// `deps.stream_budget` instance every other held-open response on the
/// shared httplib pool leases from (MCP GET, `/api/v1/events`, the
/// dashboard drawer) — `SseSurface::kLegacyEvents` already names this
/// specific surface in `stream_budget.hpp`. This move introduces NO new
/// admission-control surface and NO parallel counter.
///
/// EVENT BUS: this route subscribes to `deps.event_bus`
/// (`detail::EventBus`, the LEGACY dashboard bus) — it does NOT touch
/// `ExecutionEventBus`, so `docs/executions-history-ladder.md`'s "one bus,
/// one taxonomy" invariant is not implicated by this move (that invariant
/// governs `/api/v1/events`, not this pre-existing legacy stream).
///
/// Route (1) — gate in parens:
///   GET /events   (deny_service_scoped_fn "events.stream.access_denied",
///                  THEN a permissive best-effort `resolve_session_fn` call
///                  that only affects the per-principal admission-control
///                  bucket size — never a hard 401; the pre-routing
///                  chokepoint is the actual authentication gate for this
///                  route, exactly as documented in the handler's own
///                  in-body comment, preserved verbatim below)

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
namespace detail {
class EventBus;
class StreamBudget;
} // namespace detail
} // namespace yuzu::server

namespace yuzu::server::legacy_events {

/// Construction deps for `register_legacy_events_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    /// Shared 6-arg shape with `result_set_routes.hpp`'s identical closure
    /// (first extracted caller, #2542 PR-5) — wraps
    /// `AuthRoutes::deny_service_scoped_session`, called here with an
    /// explicit `""` for `target_type`/`target_id`, matching the original
    /// inline call's reliance on those two (and `permission`, not exposed
    /// by this closure shape either) defaulting empty.
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&, const std::string& action,
                           const std::string& message, const std::string& target_type,
                           const std::string& target_id)>;
    /// Wraps `AuthRoutes::resolve_session` — same shape/posture as every
    /// other #2542 module's `resolve_session_fn` (non-blocking, never
    /// writes to `res`). Here it is a best-effort "who is this" lookup that
    /// only widens the per-principal admission-control bucket for a
    /// resolvable session; an unresolvable one keeps the anonymous bucket,
    /// never a denial.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;

    DenyServiceScopedFn deny_service_scoped_fn;
    ResolveSessionFn resolve_session_fn;
    /// `ServerImpl::event_bus_` (`detail::EventBus`, by-value member) — the
    /// legacy dashboard bus this route subscribes to. Never null in
    /// production.
    yuzu::server::detail::EventBus* event_bus{nullptr};
    /// `ServerImpl::stream_budget_.get()` (ADR-0034) — the ONE admission
    /// budget shared by every held-open SSE/stream response on the shared
    /// httplib pool. Null disables admission control for this route (same
    /// posture as every other streaming surface's null-budget fallback).
    yuzu::server::detail::StreamBudget* stream_budget{nullptr};
};

/// Register the legacy `GET /events` SSE route against `sink`.
void register_legacy_events_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::legacy_events
