#pragma once

/// @file plugin_config_routes.hpp
/// REST surface for the plugin config/secret plane + kill switch (PR1.5b):
/// `/api/v1/plugin-config/*`. A thin HTTP mapping over `PluginConfigStore` —
/// grammar/validation lives in `plugin_config_parsers.hpp`; the store owns
/// persistence and the fail-closed kill-switch decision; this file only
/// gates on RBAC, translates HTTP <-> store calls, and emits the mutation
/// audit trail via `rest_audit.hpp`'s `emit_behavioral_audit` (503-on-audit-
/// failure — the same posture every other REST JSON route in this codebase
/// follows for a behavioural/security mutation).
///
/// NAMESPACE NOTE for the integrator (p14): `register_plugin_config_routes`
/// and `Deps` live in `yuzu::server::plugin_config` (NOT bare
/// `yuzu::server`) — `struct Deps` is a name several other route modules
/// also use (`WorkflowRoutes::Deps`, `PreflightRunner::Deps`, ...), and
/// every one of those is a MEMBER of an enclosing class, so it never
/// collides at namespace scope. This module is a free function (per this
/// package's spec), not a class, so it earns its own leaf namespace instead
/// of claiming the bare `yuzu::server::Deps` name. The call shape is exactly
/// `yuzu::server::plugin_config::register_plugin_config_routes(sink,
/// yuzu::server::plugin_config::Deps{...})` — every field type is otherwise
/// identical to `DexRoutes::register_routes`'s callback shapes
/// (dex_routes.hpp:413, http_route_sink.hpp:34).
///
/// Routes — every operation drawn ONLY from Read/Write/Delete, per
/// docs/adr/3005-plugin-config-store.md (no Suspend/Upload; see the ADR for
/// why):
///   GET    /api/v1/plugin-config                     PluginConfig:Read  (list; ADR-0017 gate; ?plugin=)
///   GET    /api/v1/plugin-config/:plugin/:key         PluginConfig:Read
///   PUT    /api/v1/plugin-config/:plugin/:key         PluginConfig:Write  (body {"value": "..."})
///   DELETE /api/v1/plugin-config/:plugin/:key         PluginConfig:Delete
///   PUT    /api/v1/plugin-config/:plugin/:key/secret  PluginSecret:Write  (body {"value": "..."}; response is metadata only)
///   DELETE /api/v1/plugin-config/:plugin/:key/secret  PluginSecret:Delete
///   GET    /api/v1/plugin-config/:plugin/kill-switch  PluginConfig:Read  (?action=<name>, default = whole-plugin)
///   PUT    /api/v1/plugin-config/:plugin/kill-switch  PluginConfig:Write (?action=<name>; body {"enabled": bool, "reason": "..."})
///
/// Deliberately NO GET/list route for secrets: the secret plane exposes only
/// `set`/`delete` (write operations) — there is no `PluginSecret:Read`
/// operation in the authorization list above, by design (a write-only plane
/// needs no read operation to gate). `set`'s own response body is metadata
/// only (`PluginConfigStore::SecretMeta` — no value field), which is the
/// surface a caller uses to learn "was my secret accepted, and when".

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class PluginConfigStore;
class RbacStore;
class ManagementGroupStore;
} // namespace yuzu::server

namespace yuzu::server::plugin_config {

/// Construction deps — same callback shapes `DexRoutes::register_routes`
/// takes (see the namespace-note above for why this lives here rather than
/// bare `yuzu::server::Deps`).
struct Deps {
    PluginConfigStore* store{nullptr};

    /// ADR-0017 admit-then-filter chokepoint for the list route
    /// (`RbacStore::authorize_list_read`, rbac_store.hpp:307). May be null
    /// -> the list route fails closed (503) rather than falling back to an
    /// unfiltered or bare-permission read.
    RbacStore* rbac_store{nullptr};
    /// Passed through to `authorize_list_read`. May be null — the
    /// AdmitAll/DenyAll paths never touch it; only a genuine management-
    /// group-confined grant would need it, and this resource treats that
    /// shape as DenyAll regardless (see plugin_config_routes.cpp's list
    /// handler doc comment for why).
    const ManagementGroupStore* mgmt_store{nullptr};

    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Bool-returning audit contract (rest_audit.hpp): true iff persisted
    /// (or the deployment runs audit-off). Every mutation route routes
    /// through `detail::emit_behavioral_audit` and fails closed (503) on
    /// `false` — matching that helper's documented REST JSON posture.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
};

/// Register every `/api/v1/plugin-config/*` route against `sink`.
/// `deps.store` may be null or closed -> every route answers 503 without
/// touching it.
void register_plugin_config_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::plugin_config
