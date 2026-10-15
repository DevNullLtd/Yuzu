#pragma once

/// @file access_routes.hpp
/// Access pages (Phase 2 UI): the read-only Users page.
///
/// Routes (all GET):
///   /access/users                       page; 302 /login without a session
///   /fragments/access/users/list        Users panel; quiet admin gate, store read, 200 always
///   /fragments/access/users/detail      Account panel (?username=); same gate and read
///   /static/yuzu-access.js              the page's client glue
///
/// No mutating route is added and none is called from this page. The panels carry no
/// success audit row (the Settings fragment they re-surface has none). A refused cookie
/// session writes no denial row either (the panels auto-load); a refused token does.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

namespace access {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// `AuthRoutes::probe_admin`: `require_admin`'s decision; on false it has already written the
    /// 403. The `auth.admin_required` row is withheld for a cookie session (a page that
    /// auto-loads its panels must not fill the audit log with denials) and kept for any token.
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    /// Same shape as `dashboard_api::Deps::PermFn`. Bound now so the Access PRs that follow
    /// do not each re-add it; this PR's routes do not call it.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    /// Same shape as the server's `audit_fn`. Bound for the same reason as `perm_fn`.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Active accounts. `unexpected` = the store did not answer (the panel says so; the
    /// string is log-only and is never rendered). An empty vector is a true empty.
    using ListUsersFn = std::function<std::expected<std::vector<auth::UserEntry>, std::string>()>;

    AuthFn auth_fn;
    AdminFn admin_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
    ListUsersFn list_users_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_access_routes(HttpRouteSink& sink, Deps deps);

} // namespace access
} // namespace yuzu::server
