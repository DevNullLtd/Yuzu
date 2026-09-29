#pragma once

/// @file dashboard_api_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 follow-up) — 7 dashboard/API routes that were scattered across
/// server.cpp with no single owning store of their own, grouped into one
/// module because each handler is small and mostly independent rather than
/// because they share state. Every handler body is copied verbatim from
/// server.cpp; the changes are the receiver (`web_server_->` -> `sink.`),
/// the gate closures (`require_auth`/`require_permission` ->
/// `deps.auth_fn`/`deps.perm_fn`), member accesses (`rbac_store_.` ->
/// `deps.rbac_store->`, `audit_store_.` -> `deps.audit_store->`,
/// `analytics_store_.` -> `deps.analytics_store->`), and one deliberate
/// non-verbatim addition: `register_dashboard_api_routes` now REQUIRES
/// `deps.visible_agents_json_fn` to be bound and throws `std::invalid_argument`
/// at registration time otherwise. The original `get_visible_agents_json`
/// call was always a callable `ServerImpl` member, never an unset
/// `std::function` — a wiring bug that leaves this field unset is a
/// programmer error caught at boot, not a runtime condition `/api/agents`
/// should degrade around per-request (a per-request 503 here would hide the
/// defect indefinitely with no signal — governance Gate 6 sre finding).
///
/// `/api/agents` deliberately does NOT own `get_visible_agents_json` —
/// that method has a second live caller in server.cpp (DEX device-list,
/// ~line 19349) and stays exactly where it is. `visible_agents_json_fn` is a
/// thin closure server.cpp binds `[this]` around a call to that method.
///
/// Routes (7) — gate in parens:
///   GET  /api/me                     (auth_fn)
///   GET  /api/agents                 (perm_fn Infrastructure:Read, THEN auth_fn — order
///                                      preserved verbatim from server.cpp; see the route's
///                                      own comment in the .cpp for what it does and does not
///                                      guarantee)
///   GET  /api/audit                  (perm_fn AuditLog:Read)
///   POST /api/export/json-to-csv     (perm_fn Response:Read)
///   POST /api/scope/validate         (auth_fn)
///   GET  /api/analytics/status       (perm_fn Infrastructure:Read)
///   GET  /api/analytics/recent       (perm_fn Infrastructure:Read)

#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;
class RbacStore;
class AuditStore;
class AnalyticsEventStore;

namespace dashboard_api {

/// Construction deps for `register_dashboard_api_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// `ServerImpl::get_visible_agents_json` (server.cpp:11293), bound
    /// `[this]` in server.cpp's registration block. MUST be bound —
    /// `register_dashboard_api_routes` throws `std::invalid_argument` at
    /// registration time if this is left default-constructed empty.
    using VisibleAgentsJsonFn = std::function<nlohmann::json(const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    VisibleAgentsJsonFn visible_agents_json_fn;
    RbacStore* rbac_store{nullptr};
    AuditStore* audit_store{nullptr};
    AnalyticsEventStore* analytics_store{nullptr};
};

/// Register all 7 dashboard/API routes against `sink`.
void register_dashboard_api_routes(HttpRouteSink& sink, Deps deps);

} // namespace dashboard_api
} // namespace yuzu::server
