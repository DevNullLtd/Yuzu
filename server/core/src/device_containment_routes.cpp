/// @file device_containment_routes.cpp
/// See device_containment_routes.hpp.

#include "device_containment_routes.hpp"

#include "device_containment_render.hpp"
#include "http_route_sink.hpp"

#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <algorithm>
#include <chrono>
#include <unordered_map>

namespace yuzu::server {

namespace {

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

// Same audit-trail floor as hardware_routes.cpp: an id taken raw from a URL is refused
// before any gate runs when it is over-long or carries a control byte.
bool id_is_safe(const std::string& id) {
    return id.size() <= auth::kMaxAgentIdLength &&
           std::none_of(id.begin(), id.end(), [](unsigned char c) { return c < 0x20; });
}

std::int64_t system_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

void DeviceContainmentRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    const auto now_secs = [this] {
        return deps_.now_secs_fn ? deps_.now_secs_fn() : system_now_secs();
    };

    // -- Quarantined devices panel --
    sink.Get("/fragments/hardware/quarantine",
             [this, now_secs](const httplib::Request& req, httplib::Response& res) {
        if (!deps_.auth_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Quarantine panel unavailable on this "
                           "server.</div>");
            return;
        }
        if (!deps_.auth_fn(req, res))
            return; // 401 already written
        QuarantinePanelView view;
        view.cap = kPanelCap;
        view.now_secs = now_secs();
        // ADR-0017: ONE list-gate decision for the whole view, then its scope goes into the
        // store query. An unwired gate refuses (never an unfiltered list); a refusal writes
        // its own 401/403/503 (require_fleet_read audits it once).
        if (!deps_.fleet_read_fn) {
            view.read = QuarantinePanelView::Read::ProbeDegraded;
            send_html(res, render_quarantine_panel(view));
            return;
        }
        const authz::FleetReadGate gate = deps_.fleet_read_fn(req, res, "Security", "Read");
        if (!gate.admitted) {
            if (res.status == 503) {
                // The authorization store is unavailable: htmx would drop the 503 body and
                // leave the placeholder empty, so say so instead (a 401/403 stays as written).
                res = httplib::Response{};
                res.status = 200;
                view.read = QuarantinePanelView::Read::ProbeDegraded;
                send_html(res, render_quarantine_panel(view));
            }
            return; // otherwise the response was already written by fleet_read_fn
        }
        QuarantineVisibleOptions opt;
        opt.max_visible = kPanelCap;
        const QuarantineVisible vis = quarantine_visible_records(gate.scope, deps_.list_fn, opt);
        if (vis.status == QuarantineReadStatus::StoreDegraded) {
            view.read = QuarantinePanelView::Read::StoreDegraded;
        } else {
            view.more = vis.more;
            std::unordered_map<std::string, std::string> names;
            if (!vis.records.empty() && deps_.hostnames_fn)
                names = deps_.hostnames_fn();
            for (const auto& r : vis.records) {
                QuarantinePanelRow row;
                row.record = r;
                if (auto it = names.find(r.agent_id); it != names.end())
                    row.hostname = it->second;
                view.rows.push_back(std::move(row));
            }
        }
        send_html(res, render_quarantine_panel(view));
    });

    // -- Containment lens / record-header banner --
    sink.Get("/fragments/hardware/ci/containment",
             [this, now_secs](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || !id_is_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Missing or invalid device id.</div>");
            return;
        }
        const bool banner = req.has_param("banner") && req.get_param_value("banner") == "1";
        if (!deps_.scoped_perm_fn || !deps_.status_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Containment unavailable on this server.</div>");
            return;
        }

        ContainmentLensView view;
        view.agent_id = id;
        view.now_secs = now_secs();

        // One scoped Security:Read probe, taken only here (never in the record header's own
        // render, never per list row). A refusal is a 200 note: htmx would drop the 403.
        {
            httplib::Response probe;
            if (!deps_.scoped_perm_fn(req, probe, "Security", "Read", id)) {
                if (probe.status == 401) {
                    res.status = 401;
                    send_html(res, "<div class=\"gp-placeholder\">Sign in required.</div>");
                    return;
                }
                view.read = probe.status == 403 ? ContainmentLensView::Read::Denied
                                                : ContainmentLensView::Read::Degraded;
                send_html(res, banner ? render_containment_banner(view) : render_containment_lens(view));
                return;
            }
        }

        const auto status = deps_.status_fn(id);
        if (!status) {
            view.read = ContainmentLensView::Read::Degraded;
            send_html(res, banner ? render_containment_banner(view) : render_containment_lens(view));
            return;
        }
        view.record = *status;
        if (banner) {
            send_html(res, render_containment_banner(view));
            return;
        }

        // Lens only: the Execute probe (button state) and the device's identity (the
        // offline and macOS sentences). An unreadable identity leaves `online` unset so the
        // lens never claims "offline" it cannot know.
        {
            httplib::Response probe;
            view.can_execute = deps_.scoped_perm_fn(req, probe, "Security", "Execute", id);
        }
        if (deps_.identity_fn) {
            if (const auto ident = deps_.identity_fn(id); ident && *ident) {
                view.hostname = (*ident)->hostname;
                view.os = (*ident)->os;
                view.online = (*ident)->online;
                view.identity_known = true;
            }
        }
        send_html(res, render_containment_lens(view));
    });
}

} // namespace yuzu::server
