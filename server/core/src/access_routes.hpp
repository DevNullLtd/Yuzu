#pragma once

/// @file access_routes.hpp
/// Access pages (Phase 2 UI): the Users and roles page.
///
/// Routes (all GET):
///   /access/users                       page; 302 /login without a session
///   /fragments/access/users/list        Users panel; quiet admin gate, store read, 200 always
///   /fragments/access/users/detail      Account panel (?username=); same gate and read
///   /fragments/access/roles/list        Roles panel; loud UserManagement:Read, 200 always
///   /fragments/access/roles/permissions Role permissions panel (?role=); same gate
///   /static/yuzu-access.js              the page's client glue
///
/// No mutating route is added. The write controls call routes that already exist (the
/// Settings user routes and REST v1) through the shared dialog module, which handles the MFA
/// step-up. The Users panels carry no success audit row (the Settings fragment they
/// re-surface has none), and a refused cookie session writes no denial row there either (the
/// panels auto-load); a refused token does. The Roles panels use the SAME securable as
/// their REST twins (`GET /api/v1/rbac/roles`, `.../{role}/permissions`), which emit none
/// either. A denial audits through the gate itself.

#include "rbac_store.hpp"

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

    /// `RbacStore::list_roles_checked()`: `unexpected` = the store did not answer.
    using ListRolesFn = std::function<std::expected<std::vector<RbacRole>, std::string>()>;
    /// `RbacStore::get_role_permissions_checked(role)`.
    using RolePermissionsFn =
        std::function<std::expected<std::vector<Permission>, std::string>(const std::string&)>;

    // Designated initialisers must follow this order (GCC and MSVC reject a reordered one).
    AuthFn auth_fn;
    AdminFn admin_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
    ListUsersFn list_users_fn;
    ListRolesFn list_roles_fn;
    RolePermissionsFn role_permissions_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_access_routes(HttpRouteSink& sink, Deps deps);

} // namespace access
} // namespace yuzu::server
