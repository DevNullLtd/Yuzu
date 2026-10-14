/// @file home_routes.cpp
/// `GET /home` + `GET /fragments/home/summary`. See home_routes.hpp for the gate table.

#include "home_routes.hpp"

#include "authz_model.hpp"
#include "home_ui.hpp"

#include <string>
#include <string_view>

namespace yuzu::server::home {

namespace {

// A refused or degraded gate, resolved against a scratch response.
struct GateResult {
    FactState state{FactState::Unavailable};
    authz::VisibleSet scope;
    std::string need;
};

std::string need_of(std::string_view securable, std::string_view op) {
    return std::string(securable) + ":" + std::string(op);
}

GateResult fleet_gate(const Deps& d, const httplib::Request& req, std::string_view securable,
                      std::string_view op) {
    GateResult r;
    if (!d.fleet_read_fn) {
        r.state = FactState::Unwired;
        return r;
    }
    httplib::Response scratch; // the gate's own 401/403/503 body never reaches the page
    auto g = d.fleet_read_fn(req, scratch, std::string(securable), std::string(op));
    if (!g.admitted) {
        r.state = scratch.status == 503 ? FactState::Unavailable : FactState::Denied;
        r.need = need_of(securable, op);
        return r;
    }
    r.state = FactState::Ok;
    r.scope = std::move(g.scope);
    return r;
}

GateResult perm_gate(const Deps& d, const httplib::Request& req, std::string_view securable,
                     std::string_view op) {
    GateResult r;
    if (!d.perm_fn) {
        r.state = FactState::Unwired;
        return r;
    }
    httplib::Response scratch;
    if (!d.perm_fn(req, scratch, std::string(securable), std::string(op))) {
        r.state = scratch.status == 503 ? FactState::Unavailable : FactState::Denied;
        r.need = need_of(securable, op);
        return r;
    }
    r.state = FactState::Ok;
    return r;
}

template <class T> Fact<T> from_gate(const GateResult& g) { return Fact<T>::with(g.state, g.need); }

// nav lookup: first item or child whose key matches, else nullptr.
const shell::NavItem* find_key(std::span<const shell::NavGroup> groups, std::string_view key) {
    for (const auto& g : groups) {
        for (const auto& it : g.items) {
            if (it.key == key)
                return &it;
            for (const auto& c : it.children)
                if (c.key == key)
                    return &c;
        }
    }
    return nullptr;
}

std::string href_or(std::span<const shell::NavGroup> groups, std::string_view key,
                    const std::string& fallback) {
    const auto* it = find_key(groups, key);
    return it ? std::string(it->href) : fallback;
}

void send_html(httplib::Response& res, std::string body) {
    res.set_header("Cache-Control", "no-store");
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

} // namespace

Links resolve_links(std::span<const shell::NavGroup> groups) {
    Links l;
    l.approvals = href_or(groups, "approvals", l.approvals);
    if (const auto* it = find_key(groups, "executions"))
        l.executions = std::string(it->href) + "?status=failed";
    l.devices = href_or(groups, "hardware", l.devices);
    l.enrolment = href_or(groups, "groups", l.enrolment);
    l.audit = href_or(groups, "audit", l.audit);
    return l;
}

EstateCounts tally_roster(const std::vector<InventoryDeviceRow>& rows) {
    EstateCounts c;
    c.total = static_cast<std::int64_t>(rows.size());
    for (const auto& r : rows) {
        if (r.online)
            ++c.online;
        else if (r.stale)
            ++c.not_seen;
        else
            ++c.offline;
    }
    return c;
}

SummaryView HomeRoutes::build_summary(const httplib::Request& req) const {
    SummaryView v;
    v.now_epoch = deps_.now_fn ? deps_.now_fn() : 0;
    v.links = resolve_links(shell::nav_groups());

    // Devices: TOP -> SQL counts when wired; engaged scope (or no SQL seam) -> the roster
    // narrowed by the gate's scope, the one confined computation.
    {
        const GateResult g = fleet_gate(deps_, req, "Inventory", "Read");
        if (g.state != FactState::Ok) {
            v.devices = from_gate<EstateCounts>(g);
        } else if (!g.scope.has_value() && deps_.fleet_estate_fn) {
            auto c = deps_.fleet_estate_fn(v.now_epoch * 1000);
            v.devices = c ? Fact<EstateCounts>::make_ok(*c)
                          : Fact<EstateCounts>::with(FactState::Unavailable);
        } else if (!deps_.roster_fn) {
            v.devices = Fact<EstateCounts>::with(FactState::Unwired);
        } else {
            const InventoryDevicesResult all = deps_.roster_fn();
            if (all.roster_degraded) {
                v.devices = Fact<EstateCounts>::with(FactState::Unavailable);
            } else if (all.rows.empty() && all.ci_degraded) {
                // build_hw_roster reports an unwired roster as ci_degraded with no rows
                // and no roster_degraded: never an empty fleet.
                v.devices = Fact<EstateCounts>::with(FactState::Unwired);
            } else {
                std::vector<InventoryDeviceRow> scoped;
                scoped.reserve(all.rows.size());
                for (const auto& r : all.rows)
                    if (authz::in_scope(g.scope, r.agent_id))
                        scoped.push_back(r);
                EstateCounts tally = tally_roster(scoped);
                // The roster read is newest-first and capped before scope filtering, so a
                // full read says nothing about what lies past the cap.
                tally.at_least = all.rows.size() >= kRosterReadCap;
                v.devices = Fact<EstateCounts>::make_ok(tally);
            }
        }
    }

    // Compliance: the store's aggregate is unfiltered, so an engaged scope is Limited.
    {
        const GateResult g = fleet_gate(deps_, req, "Policy", "Read");
        if (g.state != FactState::Ok) {
            v.compliance = from_gate<ComplianceFigure>(g);
        } else if (g.scope.has_value()) {
            v.compliance = Fact<ComplianceFigure>::with(FactState::Limited);
        } else if (!deps_.compliance_fn) {
            v.compliance = Fact<ComplianceFigure>::with(FactState::Unwired);
        } else {
            auto c = deps_.compliance_fn();
            v.compliance = c ? Fact<ComplianceFigure>::make_ok(*c)
                             : Fact<ComplianceFigure>::with(FactState::Unavailable);
        }
    }

    // Failed executions: unfiltered list, so an engaged scope is Limited.
    {
        const GateResult g = fleet_gate(deps_, req, "Execution", "Read");
        if (g.state != FactState::Ok) {
            v.failed = from_gate<FailedFigure>(g);
        } else if (g.scope.has_value()) {
            v.failed = Fact<FailedFigure>::with(FactState::Limited);
        } else if (!deps_.failed_fn) {
            v.failed = Fact<FailedFigure>::with(FactState::Unwired);
        } else {
            auto rows = deps_.failed_fn();
            v.failed = rows ? Fact<FailedFigure>::make_ok(
                                  failed_in_24h(*rows, v.now_epoch, kFailedReadCap))
                            : Fact<FailedFigure>::with(FactState::Unavailable);
        }
    }

    // Approvals: not confined by design (same gate as the REST/MCP twins and the nav badge).
    {
        const GateResult g = perm_gate(deps_, req, "Approval", "Read");
        if (g.state != FactState::Ok) {
            v.approvals = from_gate<ApprovalFigure>(g);
        } else if (!deps_.approvals_fn) {
            v.approvals = Fact<ApprovalFigure>::with(FactState::Unwired);
        } else {
            auto a = deps_.approvals_fn();
            v.approvals = a ? Fact<ApprovalFigure>::make_ok(*a)
                            : Fact<ApprovalFigure>::with(FactState::Unavailable);
        }
    }

    // Enrolment: the REST twin's gate (Enrollment:Read, floored so RBAC-off stays
    // admin-only). A refused caller gets no row and no note, and the store scan
    // never runs for them; the twin ignores scope (pending agents are not devices).
    const GateResult eg = fleet_gate(deps_, req, "Enrollment", "Read");
    v.show_enrolment = eg.state != FactState::Denied;
    if (v.show_enrolment) {
        if (eg.state != FactState::Ok) {
            v.enrolment = from_gate<std::int64_t>(eg);
        } else if (!deps_.enrolment_fn) {
            v.enrolment = Fact<std::int64_t>::with(FactState::Unwired);
        } else {
            auto n = deps_.enrolment_fn();
            v.enrolment = n ? Fact<std::int64_t>::make_ok(*n)
                            : Fact<std::int64_t>::with(FactState::Unavailable);
        }
    }
    return v;
}

void HomeRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void HomeRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // Page: auth-only chrome. The fragment carries every per-figure gate.
    sink.Get("/home", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kHomeHtml, "text/html; charset=utf-8");
    });

    sink.Get("/fragments/home/summary", [this](const httplib::Request& req, httplib::Response& res) {
        if (deps_.deny_service_scoped_fn &&
            deps_.deny_service_scoped_fn(req, res, "home.fragment.access_denied",
                                         "service-scoped tokens may not read the Home summary", "",
                                         ""))
            return;
        if (!deps_.auth_fn(req, res))
            return;
        send_html(res, render_summary(build_summary(req)));
    });
}

} // namespace yuzu::server::home
