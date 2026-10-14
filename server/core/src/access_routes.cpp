// Access pages: route registration (see access_routes.hpp).

#include "access_routes.hpp"

#include "access_render.hpp"
#include "access_ui.hpp"
#include "http_route_sink.hpp"
#include "rbac_assignable_roles.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>
#include <variant>

namespace yuzu::server {

// server/core/src/yuzu_access_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuAccessJs;

namespace access {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

// An empty username would match no row, so the "your own account" protections would
// silently not apply. Refuse rather than render a wrong page.
void refuse_empty_username(httplib::Response& res) {
    spdlog::error("access: authenticated session has an empty username; refusing");
    res.status = 500;
    res.set_header("Cache-Control", "no-store");
    res.set_content("Session has no username.", "text/plain; charset=utf-8");
}

// Gate order matters: the loud admin gate runs BEFORE the store is read, so a denied caller
// never causes a read. Returns the caller's username, or nullopt after writing the response.
std::optional<std::string> gate(const Deps& d, const httplib::Request& req, httplib::Response& res) {
    if (!d.admin_fn(req, res))
        return std::nullopt;
    // The gate and auth_fn read the same session; a disagreement is refused, not guessed at.
    const auto session = d.auth_fn(req, res);
    if (!session)
        return std::nullopt;
    if (session->username.empty()) {
        refuse_empty_username(res);
        return std::nullopt;
    }
    return session->username;
}

void respond_fragment(httplib::Response& res, const std::string& body) {
    res.set_header("Cache-Control", "no-store");
    res.set_content(body, kHtml);
}

} // namespace

void register_access_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.admin_fn || !deps.perm_fn || !deps.audit_fn || !deps.list_users_fn ||
        !deps.list_roles_fn || !deps.role_permissions_fn || !deps.list_assignments_fn ||
        !deps.enforcement_state_fn)
        throw std::invalid_argument("access::register_access_routes: every Deps member is required");

    sink.Get("/access/users", [deps](const httplib::Request& req, httplib::Response& res) {
        const auto session = deps.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        // No page-level permission probe: each panel is gated by its own fragment, and a
        // refusal becomes the panel's "not available" note client-side. Only "Your account"
        // is drawn here, from the session already in hand: it needs no data of its own.
        std::string html = kAccessUsersHtml;
        if (const auto at = html.find(kAccountMarker); at != std::string::npos)
            html.replace(at, kAccountMarker.size(), render_your_account(session->username, session->auth_source));
        res.set_header("Cache-Control", "no-store");
        res.set_content(html, kHtml);
    });

    sink.Get("/fragments/access/users/list",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 const auto self = gate(deps, req, res);
                 if (!self)
                     return;
                 auto users = deps.list_users_fn();
                 if (!users) {
                     spdlog::warn("/fragments/access/users/list: {}", users.error());
                     respond_fragment(res, render_users_list(Unavailable{}));
                     return;
                 }
                 respond_fragment(res, render_users_list(UsersList{std::move(*users), *self}));
             });

    sink.Get("/fragments/access/users/detail",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 const auto self = gate(deps, req, res);
                 if (!self)
                     return;
                 const std::string name = req.get_param_value("username");
                 if (name.empty()) {
                     respond_fragment(res, render_select_user());
                     return;
                 }
                 // Same read as the list: one row picked out. `AuthDB::get_user` is not used
                 // because it returns the credential hash for no gain here.
                 auto users = deps.list_users_fn();
                 if (!users) {
                     spdlog::warn("/fragments/access/users/detail: {}", users.error());
                     respond_fragment(res, render_user_detail(
                                               Unavailable{},
                                               "/fragments/access/users/detail?username=" +
                                                   url_q(name)));
                     return;
                 }
                 for (auto& u : *users) {
                     if (u.username == name) {
                         const bool is_self = u.username == *self;
                         respond_fragment(res, render_user_detail(UserDetail{std::move(u), is_self}));
                         return;
                     }
                 }
                 respond_fragment(res, render_user_detail(NotFound{}));
             });

    // Roles: the SAME securable as GET /api/v1/rbac/roles (floored: admin only while RBAC is
    // off), so the fragment cannot read the catalogue a refused caller could not read over REST.
    sink.Get("/fragments/access/roles/list",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "UserManagement", "Read"))
                     return;
                 auto roles = deps.list_roles_fn();
                 if (!roles) {
                     spdlog::warn("/fragments/access/roles/list: {}", roles.error());
                     respond_fragment(res, render_roles_list(Unavailable{}));
                     return;
                 }
                 respond_fragment(res, render_roles_list(RolesList{std::move(*roles)}));
             });

    sink.Get("/fragments/access/roles/permissions",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 // Shape first, before any gate or read: only a hand-built request carries a
                 // name the Roles panel would never have offered.
                 const std::string role = req.get_param_value("role");
                 if (!is_addressable_name(role)) {
                     res.status = 400;
                     res.set_header("Cache-Control", "no-store");
                     res.set_content("Invalid role name.", "text/plain; charset=utf-8");
                     return;
                 }
                 if (!deps.perm_fn(req, res, "UserManagement", "Read"))
                     return;
                 const std::string retry = "/fragments/access/roles/permissions?role=" + url_q(role);
                 // Existence comes from the catalogue, never from an empty permission set: a
                 // store fault at either read is "unavailable", and an unknown name is "no such role".
                 auto roles = deps.list_roles_fn();
                 if (!roles) {
                     spdlog::warn("/fragments/access/roles/permissions: {}", roles.error());
                     respond_fragment(res, render_role_permissions(Unavailable{}, retry));
                     return;
                 }
                 const bool known = std::any_of(roles->begin(), roles->end(),
                                                [&](const RbacRole& r) { return r.name == role; });
                 if (!known) {
                     respond_fragment(res, render_role_permissions(NotFound{}));
                     return;
                 }
                 auto perms = deps.role_permissions_fn(role);
                 if (!perms) {
                     spdlog::warn("/fragments/access/roles/permissions: {}", perms.error());
                     respond_fragment(res, render_role_permissions(Unavailable{}, retry));
                     return;
                 }
                 respond_fragment(res, render_role_permissions(RolePerms{role, std::move(*perms)}));
             });

    // Role assignments: the SAME securable, order and audit as GET /api/v1/rbac/roles/assignments
    // (gate -> session -> engine refusal -> read -> audit -> render). The grant table is
    // authorization topology, so this is AccessReview:Read, never UserManagement:Read.
    sink.Get("/fragments/access/roles/assignments",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "AccessReview", "Read"))
                     return;
                 const auto session = deps.auth_fn(req, res);
                 if (!session)
                     return;
                 if (session->is_engine()) {
                     (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "rbac.assignments.list",
                                                         "denied", "AccessReview", "", "engine_session_denied");
                     res.status = 403;
                     res.set_header("Cache-Control", "no-store");
                     res.set_content(detail::a4_error(res, "engine principals cannot access this endpoint"),
                                     "application/json");
                     return;
                 }
                 if (session->username.empty()) {
                     refuse_empty_username(res);
                     return;
                 }
                 auto grants = deps.list_assignments_fn();
                 if (!grants) {
                     // No audit row on a failed read, as the REST twin.
                     spdlog::warn("/fragments/access/roles/assignments: {}", grants.error());
                     respond_fragment(res, render_assignments(Unavailable{}));
                     return;
                 }
                 // The count is the full table, before the render cap. A row that could not be
                 // persisted sets Sec-Audit-Failed and the panel is still drawn.
                 (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "rbac.assignments.list", "success",
                                                     "AccessReview", "", "count=" + std::to_string(grants->size()));
                 AssignmentsView view;
                 view.rows = std::move(*grants);
                 view.self = session->username;
                 view.can_assign = may_attempt_rbac_admin(*session);
                 if (view.can_assign) {
                     // Role NAMES only, filtered to the closed assignable list; the catalogue is
                     // read only for a caller who would be offered the button.
                     if (auto roles = deps.list_roles_fn()) {
                         for (const auto& r : *roles)
                             if (is_rbac_assignable_role(r.name))
                                 view.assignable.push_back(r.name);
                     } else {
                         spdlog::warn("/fragments/access/roles/assignments: role list: {}", roles.error());
                     }
                 }
                 respond_fragment(res, render_assignments(std::move(view)));
             });

    // Enforcement: the twin is GET /api/v1/me, which reports rbac_enabled to any signed-in
    // session, so this is a session-only gate too. The switch is a hint (the server decides on
    // every PUT); the state is read ONLY through the store's display accessors, never through
    // the label or administrator predicates the routed A2/A1 row reserves.
    sink.Get("/fragments/access/enforcement",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 const auto session = deps.auth_fn(req, res);
                 if (!session)
                     return;
                 auto state = deps.enforcement_state_fn();
                 if (!state) {
                     spdlog::warn("/fragments/access/enforcement: {}", state.error());
                     respond_fragment(res, render_enforcement(Unavailable{}));
                     return;
                 }
                 state->may_toggle = may_attempt_rbac_admin(*session);
                 respond_fragment(res, render_enforcement(*state));
             });

    sink.Get("/static/yuzu-access.js", [](const httplib::Request&, httplib::Response& res) {
        // Our JS binds to fragment markup, so a long max-age would skew after an upgrade.
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kYuzuAccessJs, "application/javascript; charset=utf-8");
    });
}

} // namespace access
} // namespace yuzu::server
