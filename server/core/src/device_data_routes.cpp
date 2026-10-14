#include "device_data_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_audit.hpp" // emit_behavioral_audit, try_persist_audit

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

namespace {

// One fragment, parameterised by what differs between the two twins. `read_failed` is the
// store-degrade branch: a durable failure audit row, then the unavailable banner.
template <class View, class Render, class Read, class Fill>
void usage_fragment(const UsageDeps& deps, const httplib::Request& req, httplib::Response& res,
                    const char* securable, const char* verb, const char* detail, Read&& read,
                    Fill&& fill, Render&& render) {
    if (!deps.auth_fn(req, res))
        return;
    const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
    if (id.empty() || !id_is_audit_safe(id)) {
        res.status = 400;
        send_html(res, "<div class=\"gp-placeholder\">Invalid device id.</div>");
        return;
    }
    View view;
    view.agent_id = id;
    switch (deps.probe_fn(req, securable, "Read", id)) {
    case UsageDeps::Probe::Denied:
        view.body = Denied{};
        send_html(res, render(view));
        return;
    case UsageDeps::Probe::Unavailable:
        view.body = Unavailable{};
        send_html(res, render(view));
        return;
    case UsageDeps::Probe::Allowed:
        break;
    }
    // Audit-on-open, FAIL CLOSED, before the read: when the row is known not to have
    // persisted nothing is read and nothing is returned. emit_behavioral_audit has set
    // Sec-Audit-Failed: true on `res` by then. The status stays 200 so htmx swaps the note.
    if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, "success", "Agent", id,
                                       detail)) {
        view.body = Withheld{};
        send_html(res, render(view));
        return;
    }
    auto data = read(id);
    if (!data) {
        (void)detail::try_persist_audit(deps.audit_fn, req, verb, "failure", "Agent", id,
                                        "store degraded");
        view.body = Unavailable{};
        send_html(res, render(view));
        return;
    }
    fill(view, std::move(*data));
    send_html(res, render(view));
}

} // namespace

void register_device_usage_routes(HttpRouteSink& sink, UsageDeps deps) {
    if (!deps.auth_fn || !deps.probe_fn || !deps.usage_fn || !deps.licences_fn)
        throw std::invalid_argument("device_data::UsageDeps: every gate and reader is required");

    sink.Get("/fragments/hardware/ci/app-usage",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 usage_fragment<AppUsageView>(
                     deps, req, res, "Forensics", "app_usage.agent.view",
                     "per-agent app-usage fragment; user_ref not rendered",
                     [&](const std::string& id) { return deps.usage_fn(id); },
                     [](AppUsageView& v, AppUsageData d) { v.body = std::move(d); },
                     [](const AppUsageView& v) { return render_app_usage_panel(v); });
             });

    sink.Get("/fragments/hardware/ci/licences",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 usage_fragment<LicencesView>(
                     deps, req, res, "SoftwareLicensing", "sle.agent.view",
                     "per-agent detected-licence fragment; user_ref not rendered",
                     [&](const std::string& id) { return deps.licences_fn(id); },
                     [](LicencesView& v, std::vector<LicenceRow> d) { v.body = std::move(d); },
                     [](const LicencesView& v) { return render_licences_panel(v); });
             });
}

} // namespace yuzu::server::device_data
