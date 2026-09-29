#pragma once

/// @file config_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the 2-route Runtime
/// Configuration API (7.3): the effective-config + `RuntimeConfigStore`
/// overrides view, and the single-key override write. One of six small,
/// heterogeneous modules bundled into PR-12 because none of them has a
/// single owning store of its own large enough to justify its own PR (the
/// `dashboard_api_routes.hpp`/`nvd_routes.hpp` bundling precedent). Every
/// handler body is copied verbatim from server.cpp; the changes are the
/// receiver (`web_server_->` -> `sink.`), the gate closures
/// (`require_permission`/`require_auth` -> `deps.perm_fn`/`deps.auth_fn`),
/// the member access (`cfg_.` -> `deps.cfg->`, `auto_approve_.` ->
/// `deps.auto_approve->`, `runtime_config_store_.` ->
/// `deps.runtime_config_store->`), and the audit call (`audit_log(...)` ->
/// `deps.audit_fn(...)`).
///
/// MUTABLE `cfg`: unlike every other #2542 module (which only reads its
/// backing store), `PUT /api/config/:key` WRITES `deps.cfg` in-process —
/// `heartbeat_timeout`/`response_retention_days`/`audit_retention_days`/
/// `guardian_event_retention_days` are applied to the live `Config` the
/// instant the store write succeeds, same as the original inline code. This
/// is why `Deps::cfg` is `Config*`, not `const Config*`.
///
/// Routes (2) — gate in parens:
///   GET /api/config             (perm_fn Infrastructure:Read)
///   PUT /api/config/([a-z_]+)   (perm_fn Infrastructure:Write, THEN
///                                 auth_fn for the audit-attributed
///                                 username — order preserved verbatim:
///                                 body parsing and integer-key validation
///                                 both happen BETWEEN the two gates, exactly
///                                 as in the original inline code)
///
/// AUDIT ASYMMETRY (preserved verbatim, not introduced by this move): GET is
/// a pure read, never audited. PUT audits ONLY a successful write
/// (`config.update`, `success`) — every rejection (missing/invalid body,
/// non-numeric integer-key value, store-level validation failure) is NOT
/// audited; only a genuine store-level DB/crypto error (503) and success are
/// distinguished at the response-shape level, and only success reaches
/// `deps.audit_fn`. A secret key's audited `detail` never carries the raw
/// value — `RuntimeConfigStore::redacted_placeholder()` substitutes for it —
/// this is the fix for the twice-leaked-secret history the route's own body
/// comment documents; not a defect this move introduces or repairs further.
///
/// This route IS now TestRouteSink-registered (`test_config_routes.cpp`) —
/// the original inline code's comment noting the opposite ("this route is
/// not TestRouteSink-registered") is stale as of this extraction and is
/// corrected at the call site in config_routes.cpp.

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class RuntimeConfigStore;
struct Config;
} // namespace yuzu::server

namespace yuzu::server::config {

/// Construction deps for `register_config_routes`. Every closure/pointer is
/// bound once at start_web_server() time in server.cpp and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
    /// `ServerImpl::cfg_`. Never null in production (bound to a live member
    /// at registration time) — WRITTEN by PUT on a successful integer-key
    /// override, matching the original inline code exactly.
    Config* cfg{nullptr};
    /// `ServerImpl::auto_approve_`. Read-only here (`list_rules().empty()`
    /// feeds the GET response's `auto_approve_enabled` field).
    const auth::AutoApproveEngine* auto_approve{nullptr};
    /// `ServerImpl::runtime_config_store_`. Null or closed -> both routes
    /// answer 503 ("runtime config store unavailable") without touching it.
    RuntimeConfigStore* runtime_config_store{nullptr};
};

/// Register both Runtime Configuration API routes against `sink`.
void register_config_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::config
