// Groups and enrolment page: route registration (see groups_routes.hpp).

#include "groups_routes.hpp"

#include "groups_render.hpp"
#include "groups_ui.hpp"
#include "http_route_sink.hpp"

#include <spdlog/spdlog.h>

#include <stdexcept>
#include <string>

namespace yuzu::server {

// server/core/src/yuzu_groups_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuGroupsJs;

namespace groups {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

// The caller sets Cache-Control first thing in the handler, so the gate's refusals carry it.
void respond_fragment(httplib::Response& res, const std::string& body) {
    res.set_content(body, kHtml);
}

// Shape first, before any gate or read: only a hand-built request carries an id the panels
// would never have offered.
bool reject_malformed_id(const std::string& id, httplib::Response& res) {
    if (is_group_id(id))
        return false;
    res.status = 400;
    res.set_content("Invalid group id.", "text/plain; charset=utf-8");
    return true;
}

} // namespace

void register_groups_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.perm_fn || !deps.fleet_read_fn || !deps.list_groups_fn ||
        !deps.group_fn || !deps.members_fn || !deps.member_counts_fn)
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

    // Same gate as GET /api/v1/management-groups and the Settings fragment. Both reads must
    // answer: a failed count read is a failed list, never a column of zeros.
    sink.Get("/fragments/groups/list", [deps](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");
        if (!deps.perm_fn(req, res, "ManagementGroup", "Read"))
            return;
        auto groups = deps.list_groups_fn();
        auto counts = deps.member_counts_fn();
        if (!groups || !counts) {
            spdlog::warn("/fragments/groups/list: store did not answer (groups={}, counts={})",
                         groups.has_value(), counts.has_value());
            respond_fragment(res, render_group_list(Unavailable{}));
            return;
        }
        respond_fragment(res, render_group_list(GroupList{std::move(*groups), std::move(*counts)}));
    });

    sink.Get("/fragments/groups/detail",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 res.set_header("Cache-Control", "no-store");
                 const std::string id = req.get_param_value("id");
                 if (!id.empty() && reject_malformed_id(id, res))
                     return;
                 if (!deps.perm_fn(req, res, "ManagementGroup", "Read"))
                     return;
                 if (id.empty()) {
                     respond_fragment(res, render_select_group());
                     return;
                 }
                 auto found = deps.group_fn(id);
                 if (!found) {
                     spdlog::warn("/fragments/groups/detail: {}", found.error());
                     respond_fragment(res, render_group_detail(Unavailable{}));
                     return;
                 }
                 if (!*found) {
                     respond_fragment(res, render_group_detail(NotFound{}));
                     return;
                 }
                 GroupDetail d{std::move(**found), std::nullopt};
                 if (!d.group.parent_id.empty()) {
                     // Best effort: an unresolved parent is shown by its id.
                     auto parent = deps.group_fn(d.group.parent_id);
                     if (parent && *parent)
                         d.parent_name = (*parent)->name;
                 }
                 respond_fragment(res, render_group_detail(std::move(d)));
             });

    // fleet_read_fn is the SOLE gate (admit-then-filter, ADR-0017): never stack perm_fn on it.
    // Rows outside the caller's scope are dropped without being counted, so nothing about them
    // reaches the renderer.
    sink.Get("/fragments/groups/members",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 res.set_header("Cache-Control", "no-store");
                 const std::string id = req.get_param_value("id");
                 if (reject_malformed_id(id, res))
                     return;
                 const auto gate = deps.fleet_read_fn(req, res, "ManagementGroup", "Read");
                 if (!gate.admitted)
                     return;
                 auto found = deps.group_fn(id);
                 if (!found) {
                     spdlog::warn("/fragments/groups/members: {}", found.error());
                     respond_fragment(res, render_members(Unavailable{}));
                     return;
                 }
                 if (!*found) {
                     respond_fragment(res, render_members(NotFound{}));
                     return;
                 }
                 auto rows = deps.members_fn(id);
                 if (!rows) {
                     spdlog::warn("/fragments/groups/members: members read failed");
                     respond_fragment(res, render_members(Unavailable{}));
                     return;
                 }
                 MembersView v;
                 v.group_id = id;
                 v.membership_type = (*found)->membership_type;
                 v.scoped = gate.scope.has_value();
                 for (auto& m : *rows)
                     if (authz::in_scope(gate.scope, m.agent_id))
                         v.rows.push_back(std::move(m));
                 respond_fragment(res, render_members(std::move(v)));
             });
}

} // namespace groups
} // namespace yuzu::server
