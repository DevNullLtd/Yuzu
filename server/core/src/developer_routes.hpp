#pragma once

/// @file developer_routes.hpp
///
/// System > Developer and API (SYS-4, read-only): the page route and four
/// fragment routes. The fragments call the SAME shared builders the
/// `/api/v1/discover/*` REST routes and the `discover_*` MCP tools call, in
/// process, so the page cannot drift from them. No new REST route, no MCP tool,
/// no dispatch: the load generator and process-fetch panels are not part of this
/// module.
///
/// Routes — gate in parens:
///   GET /settings/developer                              (admin_fn, 302 to /)
///   GET /fragments/settings/developer/api                (Infrastructure:Read)
///   GET /fragments/settings/developer/routes?q=          (Infrastructure:Read)
///   GET /fragments/settings/developer/permissions?q=     (Infrastructure:Read)
///   GET /fragments/settings/developer/plugins            (Infrastructure:Read)
///   GET /fragments/settings/developer/plugins/observed   (Infrastructure:Read)
/// Each fragment's gate is the twin's own (`Infrastructure:Read`), so a fragment
/// is never wider than its REST route. A denied caller gets perm_fn's own 403
/// (the page glue turns it into a note, htmx drops 4xx bodies); every degraded
/// state is a fixed sentence at HTTP 200, never an empty table.

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class RbacStore;
namespace detail {
class AgentRegistry;
}
} // namespace yuzu::server

namespace yuzu::server::developer {

struct Deps {
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;

    AdminFn admin_fn;
    PermFn perm_fn;
    RbacStore* rbac_store = nullptr;                         ///< null -> permissions panel "could not be read"
    yuzu::server::detail::AgentRegistry* registry = nullptr; ///< null -> observed list "could not be read"
};

void register_developer_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::developer
