#pragma once

/// @file integrations_routes.hpp
/// The System "Integrations" page: `GET /settings/integrations` and the page script
/// `GET /static/yuzu-integrations.js`.
///
/// The page hosts the two existing fragments (`GET /fragments/settings/mcp`,
/// `GET /fragments/settings/gateway`) at their existing URLs and ids, and writes through
/// the existing `POST /api/settings/mcp`. Its webhook, offload-target and directory-sync
/// panels are the six read fragments of `integrations_sync_routes.hpp`. No REST route and
/// no MCP tool is added: the page is a page, and settings administration is the #520
/// exception to MCP twinning.
///
/// The page is `admin_fn_` (`AuthRoutes::require_admin`: an effective admin, never an
/// MCP-tier or service-scoped token); a refused caller is redirected to `/` exactly as
/// `/settings` does. The script is a static asset like every other `/static/*` file.

#include "http_route_sink.hpp"

#include <httplib.h>

#include <functional>

namespace yuzu::server::integrations {

struct Deps {
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    AdminFn admin_fn;
};

void register_integrations_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::integrations
