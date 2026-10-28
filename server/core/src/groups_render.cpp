// Groups page: pure HTML renderers (see groups_render.hpp for the contract).

#include "groups_render.hpp"

#include "enrolment_render.hpp"
#include "web_utils.hpp"

#include <algorithm>
#include <functional>
#include <unordered_set>

namespace yuzu::server::groups {

namespace {

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

// Same ordering the Settings tree uses: the root group first, then by name (id breaks a tie so
// the order is deterministic).
bool before(const ManagementGroup* a, const ManagementGroup* b) {
    const bool ar = a->id == ManagementGroupStore::kRootGroupId;
    const bool br = b->id == ManagementGroupStore::kRootGroupId;
    if (ar != br)
        return ar;
    if (a->name != b->name)
        return a->name < b->name;
    return a->id < b->id;
}

std::string retry_button(std::string_view target) {
    return "<button type=\"button\" class=\"btn sm\" data-gact=\"reload\" data-target=\"" +
           esc(target) + "\">Retry</button>";
}

std::string failbox(std::string_view lead, std::string_view why, std::string_view target) {
    return "<div class=\"failbox\" role=\"alert\"><div><b>" + esc(lead) +
           "</b><br><span class=\"guard\">" + esc(why) + "</span></div><div class=\"end\">" +
           retry_button(target) + "</div></div>";
}

std::string empty_box(std::string_view text) {
    return "<div class=\"empty\"><span>" + esc(text) + "</span></div>";
}

std::string cap_note(std::size_t cap, std::size_t total) {
    return "<div class=\"pb\"><div class=\"note warn\">Showing the first " + std::to_string(cap) +
           " of " + std::to_string(total) + ".</div></div>";
}

std::string type_pill(const ManagementGroup& g) {
    return "<span class=\"pill tag\">" + esc(g.membership_type) + "</span>";
}

std::string members_url(const std::string& id) {
    return "/fragments/groups/members?id=" + url_query_value(id);
}

std::string kv(std::string_view label, const std::string& value_html) {
    return "<div><span>" + esc(label) + "</span><b>" + value_html + "</b></div>";
}

std::string detail_panel(const GroupDetail& d) {
    const auto& g = d.group;
    std::string parent;
    if (g.parent_id.empty())
        parent = "No parent";
    else
        parent = esc(d.parent_name ? *d.parent_name : g.parent_id);

    std::string out = "<section class=\"panel\"><div class=\"hd\"><h2 class=\"long\">" + esc(g.name) +
                      "</h2></div><div class=\"kvl\">";
    out += kv("Name", esc(g.name));
    out += kv("Type", type_pill(g));
    out += kv("Parent", parent);
    out += kv("Description", g.description.empty() ? "None" : esc(g.description));
    if (g.membership_type == "dynamic")
        out += kv("Rule", "<code>" + esc(g.scope_expression) + "</code><small>" +
                              esc(kRuleNote) + "</small>");
    out += kv("Created by", g.created_by.empty() ? "-" : esc(g.created_by));
    out += kv("Created", esc(enrolment::utc_stamp_epoch_secs(g.created_at)));
    out += kv("Updated", esc(enrolment::utc_stamp_epoch_secs(g.updated_at)));
    out += "</div></section>";

    // The members panel loads itself; it is its own source and target, so its 401/403/failure
    // flow through the page's own-load handler.
    const std::string url = esc(members_url(g.id));
    out += "<section class=\"panel\" id=\"grp-members\" hx-get=\"" + url +
           "\" hx-trigger=\"load\" hx-swap=\"innerHTML\" data-src=\"" + url + "\" data-denied=\"" +
           esc(kMembersDenied) + "\" data-unavailable=\"" + esc(kMembersUnavailable) +
           "\"><p class=\"hint pad\">Loading...</p></section>";
    return out;
}

std::string side_panel(std::string_view body) {
    return "<section class=\"panel\"><div class=\"hd\"><h2>Selected group</h2></div>" +
           std::string(body) + "</section>";
}

std::string group_row(const TreeRow& r, const GroupList& list) {
    const auto& g = *r.group;
    const auto it = list.member_counts.find(g.id);
    const std::size_t n = it == list.member_counts.end() ? 0 : it->second;
    const int indent = std::min(r.depth, 5);
    return "<tr><td class=\"long\"><span class=\"d" + std::to_string(indent) +
           "\"><button type=\"button\" class=\"btn link\" data-gact=\"select\" data-id=\"" +
           esc(g.id) + "\">" + esc(g.name) + "</button></span></td><td>" + type_pill(g) +
           "</td><td>" + std::to_string(n) + "</td></tr>";
}

} // namespace

bool is_group_id(std::string_view id) {
    if (id.empty() || id.size() > 64)
        return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::vector<TreeRow> group_tree(const std::vector<ManagementGroup>& groups) {
    std::unordered_set<std::string> ids;
    for (const auto& g : groups)
        ids.insert(g.id);

    std::unordered_map<std::string, std::vector<const ManagementGroup*>> children;
    std::vector<const ManagementGroup*> roots;
    for (const auto& g : groups) {
        if (g.parent_id.empty() || !ids.contains(g.parent_id))
            roots.push_back(&g); // an orphan stays visible as a top-level row
        else
            children[g.parent_id].push_back(&g);
    }
    std::sort(roots.begin(), roots.end(), before);
    for (auto& kid : children)
        std::sort(kid.second.begin(), kid.second.end(), before);

    std::vector<TreeRow> out;
    out.reserve(groups.size());
    std::unordered_set<const ManagementGroup*> seen;
    const std::function<void(const ManagementGroup*, int)> walk = [&](const ManagementGroup* g,
                                                                      int depth) {
        if (!seen.insert(g).second)
            return;
        out.push_back({g, depth});
        if (depth >= kTreeDepthCap)
            return;
        const auto it = children.find(g->id);
        if (it == children.end())
            return;
        for (const auto* kid : it->second)
            walk(kid, depth + 1);
    };
    for (const auto* r : roots)
        walk(r, 0);

    // Whatever the walk did not reach (a rootless cycle, a descendant past the depth cap) is
    // swept in as a top-level row, in a fixed order, so nothing is silently dropped.
    std::vector<const ManagementGroup*> rest;
    for (const auto& g : groups)
        if (!seen.contains(&g))
            rest.push_back(&g);
    std::sort(rest.begin(), rest.end(), before);
    for (const auto* g : rest)
        walk(g, 0);
    return out;
}

std::string render_group_list(const std::variant<GroupList, Unavailable>& state) {
    const auto* list = std::get_if<GroupList>(&state);
    if (!list)
        return "<div class=\"hd\"><h2>Management groups</h2></div><div class=\"pb\">" +
               failbox("Groups could not be read.", kGroupsUnavailable, "grp-list") + "</div>";

    const std::size_t total = list->groups.size();
    std::string out = "<div class=\"hd\"><h2>Management groups</h2><span class=\"sub\">" +
                      std::to_string(total) + (total == 1 ? " group" : " groups") + "</span></div>";
    if (total == 0)
        return out + empty_box("No groups.");
    if (total > kGroupsRenderCap)
        out += cap_note(kGroupsRenderCap, total);

    const auto rows = group_tree(list->groups);
    out += "<div class=\"tw\"><table class=\"grp-tree\"><thead><tr><th>Group</th><th>Type</th>"
           "<th>Members</th></tr></thead><tbody>";
    const std::size_t shown = std::min(rows.size(), kGroupsRenderCap);
    for (std::size_t i = 0; i < shown; ++i)
        out += group_row(rows[i], *list);
    return out + "</tbody></table></div>";
}

std::string render_group_detail(const std::variant<GroupDetail, NotFound, Unavailable>& state) {
    if (const auto* d = std::get_if<GroupDetail>(&state))
        return detail_panel(*d);
    if (std::holds_alternative<NotFound>(state))
        return side_panel(empty_box(kNoSuchGroup));
    return side_panel("<div class=\"pb\">" +
                      failbox("This group could not be read.", kDetailUnavailable, "grp-side") +
                      "</div>");
}

std::string render_members(const std::variant<MembersView, NotFound, Unavailable>& state) {
    if (std::holds_alternative<NotFound>(state))
        return "<div class=\"hd\"><h2>Members</h2></div>" + empty_box(kNoSuchGroup);
    const auto* v = std::get_if<MembersView>(&state);
    if (!v)
        return "<div class=\"hd\"><h2>Members</h2></div><div class=\"pb\">" +
               failbox("Members could not be read.", kMembersUnavailable, "grp-members") +
               "</div>";

    const std::size_t total = v->rows.size();
    std::string out = "<div class=\"hd\"><h2>Members (" + std::to_string(total) + ")</h2></div>";
    const std::string scoped_note =
        v->scoped ? "<div class=\"pb\"><p class=\"hint\">" + esc(kScopedMembers) + "</p></div>"
                  : std::string{};
    if (total == 0)
        return out +
               empty_box(v->membership_type == "dynamic" ? kDynamicNoMembers : "No members.") +
               scoped_note;

    if (total > kMembersRenderCap)
        out += cap_note(kMembersRenderCap, total);
    out += scoped_note;
    out += "<div class=\"tw\"><table><thead><tr><th>Member</th><th>Source</th><th>Added</th></tr>"
           "</thead><tbody>";
    const std::size_t shown = std::min(total, kMembersRenderCap);
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& m = v->rows[i];
        out += "<tr><td class=\"long\"><a href=\"/hardware/ci?id=" + url_query_value(m.agent_id) +
               "\"><code>" + esc(m.agent_id) + "</code></a></td><td>" + esc(m.source) + "</td><td>" +
               esc(enrolment::utc_stamp_epoch_secs(m.added_at)) + "</td></tr>";
    }
    return out + "</tbody></table></div>";
}

std::string render_select_group() {
    return side_panel(empty_box(kSelectGroup));
}

} // namespace yuzu::server::groups
