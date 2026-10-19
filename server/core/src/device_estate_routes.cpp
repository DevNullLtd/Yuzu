/// @file device_estate_routes.cpp
/// See device_estate_routes.hpp.

#include "device_estate_routes.hpp"

#include "device_estate_render.hpp"
#include "http_route_sink.hpp"

#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <algorithm>

namespace yuzu::server {

namespace {

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

// Same audit-trail floor as hardware_routes.cpp / device_containment_routes.cpp.
bool id_is_safe(const std::string& id) {
    return id.size() <= auth::kMaxAgentIdLength &&
           std::none_of(id.begin(), id.end(), [](unsigned char c) { return c < 0x20; });
}

} // namespace

void DeviceEstateRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);
    sink.Get("/fragments/hardware/ci/stored-data",
             [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || !id_is_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Missing or invalid device id.</div>");
            return;
        }
        if (!deps_.scoped_perm_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Stored data controls unavailable on this "
                           "server.</div>");
            return;
        }
        StoredDataView view;
        view.agent_id = id;
        // The one probe: the same scoped gate the DELETE enforces. A refusal is a 200 note.
        httplib::Response probe;
        if (!deps_.scoped_perm_fn(req, probe, "Decommission", "Delete", id)) {
            if (probe.status == 401) {
                res.status = 401;
                send_html(res, "<div class=\"gp-placeholder\">Sign in required.</div>");
                return;
            }
            view.gate = probe.status == 403 ? StoredDataView::Gate::Denied
                                            : StoredDataView::Gate::Unchecked;
        }
        // The hostname is the typed confirmation value; an unreadable or absent identity
        // falls back to the agent id (the panel shows which value is expected).
        if (deps_.identity_fn) {
            if (const auto ident = deps_.identity_fn(id); ident && *ident)
                view.hostname = (*ident)->hostname;
        }
        send_html(res, render_stored_data_panel(view));
    });
}

} // namespace yuzu::server
