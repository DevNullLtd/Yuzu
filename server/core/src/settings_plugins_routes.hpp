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
    std::function<bool(const httplib::Request&, httplib::Response&)> admin_fn;
    /// `require_auth`: resolves the session. Called with a throwaway Response by the probes.
    std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>
        auth_fn;
    /// The agent registry's help document (`{"plugins":[{"name","actions":[{"name"}]}]}`),
    /// the data `GET /api/v1/discover/plugins` serves. Empty/unset: no name check.
    std::function<std::string()> help_json_fn;
};

void register_settings_plugins_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::settings_plugins
