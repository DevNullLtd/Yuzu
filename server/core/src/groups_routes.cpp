// Groups and enrolment page: route registration (see groups_routes.hpp).

#include "groups_routes.hpp"

#include "groups_ui.hpp"
#include "http_route_sink.hpp"

#include <stdexcept>
#include <string>

namespace yuzu::server {

// server/core/src/yuzu_groups_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuGroupsJs;

namespace groups {

void register_groups_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn)
        throw std::invalid_argument("groups::register_groups_routes: every Deps member is required");

    sink.Get("/groups", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.auth_fn(req, res)) {
            res.set_redirect("/login");
            return;
        }
        // No page-level permission probe: each panel is gated by its own fragment, and a
        // refusal becomes the panel's "not available" note client-side.
        res.set_header("Cache-Control", "no-store");
        res.set_content(kGroupsHtml, "text/html; charset=utf-8");
    });

    sink.Get("/static/yuzu-groups.js", [](const httplib::Request&, httplib::Response& res) {
        // The script binds to fragment markup, so a long max-age would skew after an upgrade.
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kYuzuGroupsJs, "application/javascript; charset=utf-8");
    });
}

} // namespace groups
} // namespace yuzu::server
