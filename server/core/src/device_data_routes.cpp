#include "device_data_routes.hpp"

#include "http_route_sink.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace yuzu::server::device_data {

namespace {

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

// Same audit-trail floor the Hardware record fragment applies to an id taken raw
// from a URL: bounded length, no control bytes.
bool id_is_audit_safe(const std::string& id) {
    return id.size() <= auth::kMaxAgentIdLength &&
           std::none_of(id.begin(), id.end(), [](unsigned char c) { return c < 0x20; });
}

} // namespace

void register_device_data_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.scoped_probe_fn || !deps.global_probe_fn || !deps.properties_fn ||
        !deps.schemas_fn)
        throw std::invalid_argument("device_data::Deps: every closure is required");

    sink.Get("/fragments/hardware/ci/properties",
             [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.auth_fn(req, res))
            return; // 401 already written
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || !id_is_audit_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Invalid device id.</div>");
            return;
        }

        PropertiesView view;
        view.agent_id = id;

        const bool can_read = deps.scoped_probe_fn(req, "Infrastructure", "Read", id);
        if (!can_read) {
            view.properties = Denied{};
        } else if (auto props = deps.properties_fn(id)) {
            view.properties = std::move(*props);
            view.can_write_properties = deps.scoped_probe_fn(req, "Infrastructure", "Write", id);
        } else {
            view.properties = Unavailable{};
        }

        // Property schemas are fleet-wide (a global gate): a group-confined caller
        // holding only a scoped grant sees a note, the properties list still renders.
        if (!deps.global_probe_fn(req, "Infrastructure", "Read")) {
            view.schemas = Denied{};
        } else if (auto schemas = deps.schemas_fn()) {
            view.schemas = std::move(*schemas);
            view.can_write_schemas = deps.global_probe_fn(req, "Infrastructure", "Write");
        } else {
            view.schemas = Unavailable{};
        }

        send_html(res, render_properties_panels(view));
    });
}

} // namespace yuzu::server::device_data
