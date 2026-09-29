#pragma once

/// @file custom_properties_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-4) — the 5-route Custom Properties API (7.6): typed
/// operator-authored per-agent metadata (`props.<key>` in scope
/// expressions) plus its optional per-key type/validation schemas. One
/// owning store (`CustomPropertiesStore`), genuinely cohesive — matching
/// `page_routes`' single-subsystem grouping precedent rather than
/// `dashboard_api_routes`'s explicitly-heterogeneous one. Every handler
/// body is copied verbatim from
/// server.cpp; the changes are the receiver (`web_server_->` -> `sink.`),
/// the gate closures (`require_scoped_permission`/`require_permission` ->
/// `deps.scoped_perm_fn`/`deps.perm_fn`), the member access
/// (`custom_properties_store_.` -> `deps.store->`), and the audit call
/// (`audit_log(...)` -> `deps.audit_fn(...)`, already hoisted in
/// server.cpp as `audit_fn`).
///
/// `is_custom_properties_db_error` (the `kCustomPropertiesDbErrorPrefix`
/// classifier distinguishing a genuine store/DB failure from a caller-input
/// validation error) moves here verbatim from server.cpp's anonymous
/// namespace — it had exactly two call sites, both in the routes this file
/// now owns, and no dependency on `ServerImpl` state.
///
/// Routes (5) — gate in parens, all backed by `deps.store`
/// (`CustomPropertiesStore`):
///   GET    /api/agents/:id/properties        (scoped_perm_fn Infrastructure:Read, agent_id)
///   PUT    /api/agents/:id/properties/:key   (scoped_perm_fn Infrastructure:Write, agent_id)
///   DELETE /api/agents/:id/properties/:key   (scoped_perm_fn Infrastructure:Write, agent_id)
///   GET    /api/property-schemas             (perm_fn Infrastructure:Read)
///   POST   /api/property-schemas             (perm_fn Infrastructure:Write)
///
/// #3700: the three per-agent routes gate on PER-TARGET
/// `require_scoped_permission`, never a bare global `require_permission` —
/// the old global gate admitted a permission holder with no target check,
/// disclosing/mutating custom-properties data for agents outside a
/// management-group-confined caller's scope (World A gap, ADR-0017). The
/// two schema routes are deliberately NOT per-target (a schema is a global
/// definition, not a per-agent value) and keep the plain `perm_fn` gate,
/// matching server.cpp's original code exactly.
///
/// AUDIT ASYMMETRY (preserved verbatim, not a defect introduced by this
/// move): both GET routes are unaudited (pure reads). An early
/// store-unavailable 503 is unaudited on ALL 5 routes — it returns before
/// `deps.audit_fn` is ever reached. Past that point the three mutating
/// routes diverge:
///   - PUT: its own request-body validation 400s (missing 'value', invalid
///     JSON) are unaudited; once past body parsing, both the store-level
///     failure ("failure") and success outcomes ARE audited.
///   - DELETE: no body-validation stage exists, so both its store-level
///     not_found and success outcomes ARE audited.
///   - POST /api/property-schemas: its own request-body validation 400s
///     are unaudited (same as PUT), but UNLIKE PUT/DELETE its store-level
///     failure is ALSO unaudited — only success is audited.
/// This is the pre-existing server.cpp behaviour, copied as-is; it is not
/// this extraction's place to change it.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class CustomPropertiesStore;
} // namespace yuzu::server

namespace yuzu::server::custom_properties {

/// Construction deps for `register_custom_properties_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated. Deliberately carries no `AuthFn` — none of these 5
/// handlers calls `require_auth` directly; `perm_fn`/`scoped_perm_fn` are
/// each bound to a `require_permission`/`require_scoped_permission`
/// wrapper, and both of those resolve the session internally (verified
/// against auth_routes.cpp) — matching the original inline code exactly,
/// which never called `require_auth` in these 5 handlers either.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Per-target authorization gate (wraps `require_scoped_permission`) —
    /// same shape as `DeviceRoutes::ScopedPermFn` (device_routes.hpp) and
    /// server.cpp's own hoisted `scoped_perm_fn` closure.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    /// Bool-returning audit contract, same shape as
    /// `plugin_config::Deps::AuditFn` — server.cpp's hoisted `audit_fn`
    /// closure. Unlike plugin_config_routes, this module's callers do NOT
    /// act on a `false` return (matches the original inline code's
    /// `(void)audit_log(...)` discard — preserved, not hardened, by this
    /// move).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    PermFn perm_fn;
    ScopedPermFn scoped_perm_fn;
    AuditFn audit_fn;
    /// `ServerImpl::custom_properties_store_`. Null or closed -> every
    /// route answers 503 without touching it.
    CustomPropertiesStore* store{nullptr};
};

/// Register all 5 Custom Properties API routes against `sink`.
void register_custom_properties_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::custom_properties
