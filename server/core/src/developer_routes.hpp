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
///   GET /fragments/settings/developer/api                (admin_fn, Infrastructure:Read)
///   GET /fragments/settings/developer/routes?q=          (admin_fn, Infrastructure:Read)
///   GET /fragments/settings/developer/permissions?q=     (admin_fn, Infrastructure:Read)
///   GET /fragments/settings/developer/plugins            (admin_fn, Infrastructure:Read)
///   GET /fragments/settings/developer/plugins/observed   (admin_fn, Infrastructure:Read)
/// Each fragment is admin-only like the page, then takes the twin's own
/// `Infrastructure:Read`, so a fragment is never wider than its REST route. The flat Read
/// gate alone would admit any authenticated caller on the RBAC-off default. A denied
/// caller gets the gate's own 403 (the page glue turns it into a note, htmx drops 4xx
/// bodies); every degraded state is a fixed sentence at HTTP 200, never an empty table.

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

    /// Non-auditing yes/no for a draw-time decision (`AuthRoutes::has_permission`): the role
    /// grid's `UserManagement:Read` check, which must not write a denial row per page load.
    using ProbeFn =
        std::function<bool(const httplib::Request&, const std::string&, const std::string&)>;

    AdminFn admin_fn;
    PermFn perm_fn;
    ProbeFn probe_fn; ///< null -> the role grid is withheld
    RbacStore* rbac_store = nullptr;                         ///< null -> permissions panel "could not be read"
    yuzu::server::detail::AgentRegistry* registry = nullptr; ///< null -> observed list "could not be read"
};

void register_developer_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::developer
