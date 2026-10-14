// Access pages: route registration (see access_routes.hpp).

#include "access_routes.hpp"

#include "access_render.hpp"
#include "access_ui.hpp"
#include "http_route_sink.hpp"

#include <spdlog/spdlog.h>

#include <stdexcept>
#include <variant>

namespace yuzu::server {

// server/core/src/yuzu_access_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuAccessJs;

namespace access {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

// Gate order matters: the loud admin gate runs BEFORE the store is read, so a denied caller
// never causes a read. Returns the caller's username, or nullopt after writing the response.
std::optional<std::string> gate(const Deps& d, const httplib::Request& req, httplib::Response& res) {
    if (!d.admin_fn(req, res))
        return std::nullopt;
    // The gate and auth_fn read the same session; a disagreement is refused, not guessed at.
    const auto session = d.auth_fn(req, res);
    if (!session)
        return std::nullopt;
    // An empty username would match no row, so the "your own account" protections would
    // silently not apply. Refuse rather than render a wrong page.
    if (session->username.empty()) {
        spdlog::error("access: authenticated session has an empty username; refusing");
        res.status = 500;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Session has no username.", "text/plain; charset=utf-8");
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
    if (!deps.auth_fn || !deps.admin_fn || !deps.perm_fn || !deps.audit_fn || !deps.list_users_fn)
        throw std::invalid_argument("access::register_access_routes: every Deps member is required");

    sink.Get("/access/users", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.auth_fn(req, res)) {
            res.set_redirect("/login");
            return;
        }
        // No page-level permission probe: each panel is gated by its own fragment, and a
        // refusal becomes the panel's "not available" note client-side.
        res.set_content(kAccessUsersHtml, kHtml);
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

    sink.Get("/static/yuzu-access.js", [](const httplib::Request&, httplib::Response& res) {
        // Our JS binds to fragment markup, so a long max-age would skew after an upgrade.
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kYuzuAccessJs, "application/javascript; charset=utf-8");
    });
}

} // namespace access
} // namespace yuzu::server
