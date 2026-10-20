#pragma once

/// @file settings_plugins_routes.hpp
///
/// System > Plugins and updates: the page (`GET /settings/plugins`) and its three new
/// read fragments (`/fragments/settings/plugin-config`, `/kill-switch`,
/// `/product-packs`). The two hosted fragments (plugin signing, agent updates) stay in
/// settings_routes.cpp; their writes use the existing routes.
///
/// Every fragment applies the legacy-admin page gate AND the REST twin's own gate, so the
/// page is never wider than the API it composes. A denied or degraded read answers 200
/// with an inline note: htmx drops 4xx/5xx bodies, so a 403/503 would leave the panel on
/// "Loading..." forever. The twins keep their 403/503.
///
/// Audit: the page (`GET /settings/plugins`) is a navigation and keeps the loud
/// `require_admin`. The three fragments load by themselves, so they use the quiet probes
/// (`probe_admin_fn`, `probe_perm_fn`): an interactive cookie session refused there leaves no
/// `auth.*_required` row (nobody attempted anything), while an API-token or engine caller keeps
/// the row it would get from the REST twin (`AuthRoutes::denial_row_may_be_withheld`). Every
/// permission check on a fragment goes through `probe_perm_fn`; none is decided by a bare
/// `check_permission`, which would drop a token caller's denial evidence.
///
/// No new REST route and no MCP tool: each fragment is `twinned` to an existing
/// capability (ADR-1005 Decision 4).

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class PluginConfigStore;
class ProductPackStore;
class RbacStore;
class ManagementGroupStore;
} // namespace yuzu::server

namespace yuzu::server::settings_plugins {

struct Deps {
    PluginConfigStore* config_store{nullptr};
    ProductPackStore* pack_store{nullptr};
    RbacStore* rbac_store{nullptr};
    const ManagementGroupStore* mgmt_store{nullptr};

    /// `require_admin`: the page gate `GET /settings` uses. A refusal has written its response.
    /// Used by `GET /settings/plugins` only.
    std::function<bool(const httplib::Request&, httplib::Response&)> admin_fn;
    /// `AuthRoutes::probe_admin`: the same decision for the auto-loading fragments, with the
    /// `auth.admin_required` row withheld for an interactive cookie session. Called with a
    /// throwaway Response; a refusal is rendered as a 200 denied note, never forwarded.
    std::function<bool(const httplib::Request&, httplib::Response&)> probe_admin_fn;
    /// `AuthRoutes::has_permission`: `require_permission`'s own decision (elevation, engine
    /// principals, MCP tier, service scope, RBAC, legacy) writing no response; the denial row is
    /// withheld for an interactive cookie session only. Decides what a fragment draws.
    std::function<bool(const httplib::Request&, const std::string& securable_type,
                       const std::string& operation)>
        probe_perm_fn;
    /// `require_auth`: resolves the session. Called with a throwaway Response by the probes.
    std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>
        auth_fn;
    /// The agent registry's help document (`{"plugins":[{"name","actions":[{"name"}]}]}`),
    /// the data `GET /api/v1/discover/plugins` serves. Empty/unset: no name check.
    std::function<std::string()> help_json_fn;
};

void register_settings_plugins_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::settings_plugins
