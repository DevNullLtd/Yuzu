#include "home_panels_routes.hpp"

#include "http_route_sink.hpp"

#include <stdexcept>
#include <utility>

namespace yuzu::server::home_panels {

namespace {

void serve(httplib::Response& res, const std::string& html) {
    res.status = 200; // every Home fragment answers 200 so htmx swaps the note
    res.set_header("Cache-Control", "no-store");
    res.set_content(html, "text/html; charset=utf-8");
}

constexpr const char* kDenyVerb = "home.fragment.access_denied";

/// Service-scoped tokens are refused first. The gate writes into a scratch
/// response; a refusal renders as a Denied note, never the gate's body.
bool service_scoped_refused(const Deps& d, const httplib::Request& req, const char* msg) {
    httplib::Response scratch;
    return d.deny_service_scoped_fn(req, scratch, kDenyVerb, msg, "", "");
}

} // namespace

void register_home_panel_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.deny_service_scoped_fn || !deps.fleet_read_fn || !deps.perm_fn ||
        !deps.policies_fn || !deps.audit_fn || !deps.now_fn)
        throw std::invalid_argument("home_panels::register_home_panel_routes: unbound closure");

    sink.Get("/fragments/home/policies", [deps](const httplib::Request& req, httplib::Response& res) {
        const auto now = deps.now_fn();
        if (service_scoped_refused(deps, req,
                                   "service-scoped tokens may not read the Home policies panel")) {
            serve(res, render_policies_panel(Fact<PolicyPanel>::of(FactState::Denied, "Policy:Read"),
                                             now));
            return;
        }
        if (!deps.auth_fn(req, res)) return; // 401 written by auth_fn

        httplib::Response scratch;
        const auto gate = deps.fleet_read_fn(req, scratch, "Policy", "Read");
        if (!gate.admitted) {
            const auto s = scratch.status == 503 ? FactState::Unavailable : FactState::Denied;
            serve(res, render_policies_panel(Fact<PolicyPanel>::of(s, "Policy:Read"), now));
            return;
        }
        if (gate.scope.has_value()) { // engaged: the aggregate is unfiltered, never show it
            serve(res, render_policies_panel(Fact<PolicyPanel>::of(FactState::Limited), now));
            return;
        }
        auto panel = deps.policies_fn();
        serve(res, render_policies_panel(panel ? Fact<PolicyPanel>::ok(std::move(*panel))
                                               : Fact<PolicyPanel>::of(FactState::Unavailable),
                                         now));
    });

    sink.Get("/fragments/home/activity", [deps](const httplib::Request& req, httplib::Response& res) {
        using Rows = std::vector<ActivityRow>;
        const auto now = deps.now_fn();
        auto out = [&](const Fact<Rows>& f) {
            serve(res, render_activity_panel(f, now, deps.audit_href));
        };
        if (service_scoped_refused(deps, req,
                                   "service-scoped tokens may not read the Home activity panel")) {
            out(Fact<Rows>::of(FactState::Denied, "AuditLog:Read"));
            return;
        }
        auto session = deps.auth_fn(req, res);
        if (!session) return;
        // Role pre-check BEFORE any gate call: a non-holder must not write a
        // denial row into the very panel they would read (REVIEW A7).
        if (auth::effective_role(*session) != auth::Role::admin) {
            out(Fact<Rows>::of(FactState::AdminOnly));
            return;
        }
        httplib::Response scratch;
        if (!deps.perm_fn(req, scratch, "AuditLog", "Read")) {
            out(Fact<Rows>::of(scratch.status == 503 ? FactState::Unavailable : FactState::Denied,
                               "AuditLog:Read"));
            return;
        }
        auto events = deps.audit_fn(static_cast<int>(kActivityRows));
        out(events ? Fact<Rows>::ok(to_activity_rows(*events)) : Fact<Rows>::of(FactState::Unavailable));
    });
}

} // namespace yuzu::server::home_panels
