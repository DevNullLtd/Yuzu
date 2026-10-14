// Access pages: pure HTML renderers (see access_render.hpp for the contract).

#include "access_render.hpp"

#include "web_utils.hpp"

#include <algorithm>

namespace yuzu::server::access {

namespace {

constexpr std::string_view kDetailUrl = "/fragments/access/users/detail?username=";
constexpr std::string_view kPermsUrl = "/fragments/access/roles/permissions?role=";

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

// Parity with the Settings users fragment: anything that is not "local" is an SSO/SCIM row,
// which the local-account mutation routes refuse (their strict username charset rejects
// `oidc:<iss>#<sub>`). `identity_source` is NOT NULL DEFAULT 'local' in the store.
bool is_local(const auth::UserEntry& u) {
    return u.identity_source == "local";
}

// `<div class="failbox">` with a lead line, the reason, and an optional Retry button.
std::string failbox(std::string_view lead, std::string_view why, const std::string& retry) {
    std::string out = "<div class=\"failbox\" role=\"alert\"><div><b>" + esc(lead) +
                      "</b><br><span class=\"guard\">" + esc(why) + "</span></div>";
    if (!retry.empty())
        out += "<div class=\"end\">" + retry + "</div>";
    return out + "</div>";
}

std::string source_pill(const auth::UserEntry& u) {
    std::string out = "<span class=\"pill idle\"";
    if (!is_local(u))
        out += " title=\"Auto-provisioned via SSO (identity_source=" + esc(u.identity_source) +
               ")\"";
    const auto label = source_label(u.identity_source);
    out += ">" + (label.empty() ? esc(u.identity_source) : std::string(label)) + "</span>";
    return out;
}

std::string role_pill(const auth::UserEntry& u) {
    return "<span class=\"pill tag\">" + esc(auth::role_to_string(u.role)) + "</span>";
}

// `<button type="button" class="btn link sm [danger]" data-act=ACT data-username=NAME>`.
std::string action_button(std::string_view label, std::string_view act, const std::string& username,
                          bool danger) {
    return std::string("<button type=\"button\" class=\"btn link sm") + (danger ? " danger" : "") +
           "\" data-act=\"" + std::string(act) + "\" data-username=\"" + esc(username) + "\">" +
           esc(label) + "</button>";
}

std::string user_row(const auth::UserEntry& u, bool is_self) {
    std::string out = "<tr data-username=\"" + esc(u.username) + "\"><td class=\"long\"><b>" +
                      esc(u.username) + "</b></td><td>" + source_pill(u) + "</td><td>" +
                      role_pill(u) + "</td><td class=\"wrap\" data-rbac-for=\"" + esc(u.username) +
                      "\">Not shown</td><td><div class=\"rowact\">";
    if (is_self) {
        out += "<span class=\"pill idle\" title=\"This is your own account\">Current user</span>";
    } else {
        out += "<button type=\"button\" class=\"btn link sm\" hx-get=\"" + std::string(kDetailUrl) +
               esc(url_q(u.username)) + "\" hx-target=\"#acc-detail\" hx-swap=\"innerHTML\">"
               "Manage</button>";
        // Local accounts only: the delete route's strict username charset refuses an SSO
        // principal. The username travels as an escaped data attribute and is percent-encoded
        // by the script when it builds the request path.
        if (is_local(u))
            out += action_button("Remove", "remove", u.username, /*danger=*/true);
    }
    return out + "</div></td></tr>";
}

std::string hint(std::string_view text) {
    return "<span class=\"hint\">" + esc(text) + "</span>";
}

std::string account_noun(const auth::UserEntry& u) {
    const auto label = source_label(u.identity_source);
    return (label.empty() ? esc(u.identity_source) : std::string(label)) + " account";
}

// "A, B and C" style counts for the permissions header: "41 permissions across 20 areas".
std::string plural(std::size_t n, std::string_view one, std::string_view many) {
    return std::to_string(n) + " " + std::string(n == 1 ? one : many);
}

std::string detail_panel(const UserDetail& d) {
    const auto& u = d.user;
    const bool admin = u.role == auth::Role::admin;
    // The role of an SSO/SCIM account is the IdP's business, and nobody changes their own.
    const bool can_change = is_local(u) && !d.is_self;
    std::string out = "<div class=\"hd\"><h2 class=\"long\">" + esc(u.username) +
                      "</h2><span class=\"sub\">" + account_noun(u) + "</span></div>"
                      "<div class=\"form\"><div class=\"fld\">"
                      "<label for=\"acc-role\">Account role</label><select id=\"acc-role\"";
    // A control that is off says why on hover as well as in the hint below it.
    const std::string off_reason = d.is_self ? "You cannot change your own role."
                                             : "Not available for SSO or SCIM accounts here.";
    out += can_change ? "><option value=\"user\""
                      : " disabled title=\"" + esc(off_reason) + "\"><option value=\"user\"";
    out += admin ? ">User</option>" : " selected>User</option>";
    out += admin ? "<option value=\"admin\" selected>Admin</option></select>"
                 : "<option value=\"admin\">Admin</option></select>";
    out += hint("Only admin and user exist here.");
    if (d.is_self)
        out += hint("You cannot change your own role.");
    else if (!is_local(u))
        out += hint("Not available for SSO or SCIM accounts here.");
    else
        out += hint("Changing it signs the person out.");
    out += "</div></div>";
    if (can_change)
        out += "<div class=\"btns\">" + action_button("Change role", "role", u.username, false) + "</div>";
    if (d.is_self)
        return out;
    // Revoke works for any account (the sessions route takes SSO principals too); it is never
    // offered on the caller's own row, where it would end the page they are using.
    out += "<div class=\"acts\"><div>" + action_button("Revoke sessions", "revoke", u.username, true) +
           hint("Signs them out of the dashboard. API tokens are not revoked.") + "</div>";
    if (is_local(u))
        out += "<div>" + action_button("Remove user", "remove", u.username, true) +
               hint("Revokes their sessions and API tokens, then removes the account.") + "</div>";
    return out + "</div>";
}

} // namespace

std::string render_users_list(const std::variant<UsersList, Unavailable>& state) {
    const auto* list = std::get_if<UsersList>(&state);
    if (!list) {
        const std::string retry = "<button type=\"button\" class=\"btn sm\" data-act=\"reload\" "
                                  "data-target=\"acc-users\">Retry</button>";
        return "<div class=\"hd\"><h2>Users</h2></div><div class=\"pb\">" +
               failbox("Users could not be read.", kUsersUnavailable, retry) + "</div>";
    }

    const std::size_t total = list->users.size();
    std::string out = "<div class=\"hd\"><h2>Users</h2><span class=\"sub\">" +
                      std::to_string(total) + (total == 1 ? " account" : " accounts") +
                      "</span><div class=\"end\"><button type=\"button\" class=\"btn primary sm\" "
                      "data-act=\"add\">Add user</button></div></div>";
    if (total > kUsersRenderCap)
        out += "<div class=\"pb\"><div class=\"note warn\">Showing the first " +
               std::to_string(kUsersRenderCap) + " of " + std::to_string(total) +
               " accounts.</div></div>";

    out += "<div class=\"tw\"><table><thead><tr><th>User</th><th>Source</th><th>Account role</th>"
           "<th>RBAC roles</th><th></th></tr></thead><tbody>";
    if (total == 0) {
        // A fresh install has its first admin, so this is not expected; it is a true empty
        // (the store answered), never the Unavailable text.
        out += "<tr><td colspan=\"5\" class=\"hint\">No active accounts were returned.</td></tr>";
    }
    const std::size_t shown = std::min(total, kUsersRenderCap);
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& u = list->users[i];
        out += user_row(u, !list->self.empty() && u.username == list->self);
    }
    out += "</tbody></table></div><div class=\"pb\"><p class=\"hint\">Account role (admin or user) "
           "is the legacy role: it decides who can open Settings and what applies while RBAC "
           "enforcement is off. RBAC roles apply once enforcement is on, and are listed here from the "
           "Role assignments panel.</p></div>";
    return out;
}

std::string render_user_detail(const std::variant<UserDetail, NotFound, Unavailable>& state,
                               const std::string& retry_url) {
    if (const auto* d = std::get_if<UserDetail>(&state))
        return detail_panel(*d);
    if (std::holds_alternative<NotFound>(state))
        return "<div class=\"hd\"><h2>Account</h2></div><div class=\"empty\"><b>No such user</b>"
               "<span>No active account has that name. It may have been removed.</span></div>";

    std::string retry;
    if (!retry_url.empty())
        retry = "<button type=\"button\" class=\"btn sm\" hx-get=\"" + esc(retry_url) +
                "\" hx-target=\"#acc-detail\" hx-swap=\"innerHTML\">Retry</button>";
    return "<div class=\"hd\"><h2>Account</h2></div><div class=\"pb\">" +
           failbox("This account could not be read.", kDetailUnavailable, retry) + "</div>";
}

bool is_addressable_name(std::string_view name) {
    if (name.empty() || name.size() > 64)
        return false;
    bool all_dots = true;
    for (const unsigned char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
        if (c != '.')
            all_dots = false;
    }
    return !all_dots;
}

std::string render_roles_list(const std::variant<RolesList, Unavailable>& state) {
    const auto* list = std::get_if<RolesList>(&state);
    if (!list || list->roles.empty()) {
        const std::string retry = "<button type=\"button\" class=\"btn sm\" data-act=\"reload\" "
                                  "data-target=\"acc-roles\">Retry</button>";
        return "<div class=\"hd\"><h2>Roles</h2></div><div class=\"pb\">" +
               failbox("Roles could not be read.", kRolesUnavailable, retry) + "</div>";
    }
    std::string out = "<div class=\"hd\"><h2>Roles</h2><span class=\"sub\">" +
                      plural(list->roles.size(), "role", "roles") +
                      "</span></div><div class=\"tw\"><table><thead><tr><th>Role</th>"
                      "<th>What it allows</th><th class=\"r\">Assigned</th><th></th></tr></thead><tbody>";
    for (const auto& r : list->roles) {
        out += "<tr data-role=\"" + esc(r.name) + "\"><td><b>" + esc(r.name) + "</b>";
        if (r.is_system)
            out += " <span class=\"pill idle\">Built-in</span>";
        out += "</td><td class=\"wrap\">" + esc(r.description) + "</td><td class=\"r\" data-assigned-for=\"" +
               esc(r.name) + "\">Not shown</td><td><div class=\"rowact\">";
        if (is_addressable_name(r.name))
            out += "<button type=\"button\" class=\"btn link sm\" hx-get=\"" +
                   std::string(kPermsUrl) + esc(url_q(r.name)) +
                   "\" hx-target=\"#acc-role-perms\" hx-swap=\"innerHTML\">View permissions</button>";
        else
            out += hint("Name not addressable");
        out += "</div></td></tr>";
    }
    return out + "</tbody></table></div>";
}

std::string render_role_permissions(const std::variant<RolePerms, NotFound, Unavailable>& state,
                                    const std::string& retry_url) {
    if (std::holds_alternative<NotFound>(state))
        return "<div class=\"hd\"><h2>Role permissions</h2></div><div class=\"empty\"><b>No such role</b>"
               "<span>The catalogue holds no role with that name.</span></div>";
    const auto* p = std::get_if<RolePerms>(&state);
    if (!p) {
        std::string retry;
        if (!retry_url.empty())
            retry = "<button type=\"button\" class=\"btn sm\" hx-get=\"" + esc(retry_url) +
                    "\" hx-target=\"#acc-role-perms\" hx-swap=\"innerHTML\">Retry</button>";
        return "<div class=\"hd\"><h2>Role permissions</h2></div><div class=\"pb\">" +
               failbox("Permissions could not be read.", kRolePermsUnavailable, retry) + "</div>";
    }
    if (p->rows.empty())
        return "<div class=\"hd\"><h2 class=\"long\">" + esc(p->role) + " permissions</h2></div>"
               "<div class=\"empty\"><b>No permissions</b><span>This role holds no permissions.</span></div>";

    // Grouped by securable type in the order the store returned them. A deny row is shown as such.
    std::vector<std::string> areas;
    std::vector<std::string> ops;
    for (const auto& r : p->rows) {
        std::size_t i = 0;
        while (i < areas.size() && areas[i] != r.securable_type)
            ++i;
        if (i == areas.size()) {
            areas.push_back(r.securable_type);
            ops.emplace_back();
        }
        if (!ops[i].empty())
            ops[i] += ", ";
        ops[i] += esc(r.operation) + (r.effect == "deny" ? " (deny)" : "");
    }
    std::string out = "<div class=\"hd\"><h2 class=\"long\">" + esc(p->role) +
                      " permissions</h2><span class=\"sub\">" +
                      plural(p->rows.size(), "permission", "permissions") + " across " +
                      plural(areas.size(), "area", "areas") +
                      "</span></div><div class=\"tw scroll\"><table class=\"compact\"><thead><tr><th>Area</th>"
                      "<th>Allowed</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < areas.size(); ++i)
        out += "<tr><td class=\"mono\">" + esc(areas[i]) + "</td><td>" + ops[i] + "</td></tr>";
    return out + "</tbody></table></div>";
}

// ---- Role assignments ---------------------------------------------------------------------

namespace {

std::string assign_button(const AssignmentsView& v) {
    if (v.assignable.empty())
        return "<button type=\"button\" class=\"btn sm\" disabled title=\"The role list could not be read, "
               "so there is nothing to offer.\">Assign role</button>";
    std::string roles;
    for (const auto& r : v.assignable) {
        if (!roles.empty())
            roles += ',';
        roles += esc(r);
    }
    return "<button type=\"button\" class=\"btn sm\" data-act=\"assign\" data-roles=\"" + roles +
           "\">Assign role</button>";
}

std::string assignment_action(const PrincipalRole& g, const AssignmentsView& v) {
    // Removal is a path-segment request: only a user principal whose id and role are plain
    // segments (the DELETE route's own charset, minus dot-only names) is ever offered it.
    const bool removable = g.principal_type == "user" && is_addressable_name(g.principal_id) &&
                           is_addressable_name(g.role_name);
    if (!removable)
        return std::string("<span class=\"hint\" title=\"") +
               (g.principal_type == "group" ? "Group grants are not removable through this route"
                                            : "The removal route accepts local usernames only "
                                              "(letters, digits, dot, dash, underscore)") +
               "\">Not removable here</span>";
    if (!v.can_assign)
        return {};
    if (g.principal_id == v.self && g.role_name == "Administrator")
        return "<button type=\"button\" class=\"btn link sm danger\" disabled title=\"You cannot remove your "
               "own Administrator assignment. Ask another administrator.\">Remove</button>";
    return "<button type=\"button\" class=\"btn link sm danger\" data-act=\"unassign\">Remove</button>";
}

} // namespace

std::string render_assignments(const std::variant<AssignmentsView, Unavailable>& state, std::size_t cap) {
    const auto* v = std::get_if<AssignmentsView>(&state);
    if (!v) {
        const std::string retry = "<button type=\"button\" class=\"btn sm\" data-act=\"reload\" "
                                  "data-target=\"acc-assignments\">Retry</button>";
        return "<div class=\"hd\"><h2>Role assignments</h2></div><div class=\"pb\">" +
               failbox("Role assignments could not be read.", kAssignmentsUnavailable, retry) + "</div>";
    }
    const std::size_t total = v->rows.size();
    const bool capped = total > cap;
    std::string out = "<div class=\"hd\"><h2>Role assignments</h2><span class=\"sub\">Fleet-wide grants</span>";
    if (v->can_assign)
        out += "<div class=\"end\">" + assign_button(*v) + "</div>";
    out += "</div>";
    if (capped)
        out += "<div class=\"pb\"><div class=\"note warn\">Showing the first " + std::to_string(cap) + " of " +
               std::to_string(total) + " grants.</div></div>";
    // `data-capped` / `data-total` are what the page script reads before it derives any count.
    out += "<div class=\"tw\"><table data-assignments data-total=\"" + std::to_string(total) +
           "\" data-capped=\"" + (capped ? "1" : "0") +
           "\"><thead><tr><th>Type</th><th>Principal</th><th>Role</th><th></th></tr></thead><tbody>";
    if (total == 0)
        out += "<tr><td colspan=\"4\" class=\"hint\">No role assignments yet. The grant table was read and "
               "is empty.</td></tr>";
    for (std::size_t i = 0; i < std::min(total, cap); ++i) {
        const auto& g = v->rows[i];
        out += "<tr data-principal-type=\"" + esc(g.principal_type) + "\" data-principal-id=\"" +
               esc(g.principal_id) + "\" data-role=\"" + esc(g.role_name) + "\"><td><span class=\"pill idle\">" +
               esc(g.principal_type) + "</span></td><td class=\"long\">" + esc(g.principal_id) +
               "</td><td><span class=\"pill tag\">" + esc(g.role_name) + "</span></td><td><div class=\"rowact\">" +
               assignment_action(g, *v) + "</div></td></tr>";
    }
    out += "</tbody></table></div><div class=\"pb\"><p class=\"hint\">Group-scoped and device-scoped roles "
           "(ITServiceOwner) are set per management group, not here. Roles held through a management group are "
           "not listed.</p></div>";
    return out;
}

bool may_attempt_rbac_admin(const auth::Session& s) {
    return s.role == auth::Role::admin && s.auth_source == "local" && s.token_scope_service.empty() &&
           s.mcp_tier.empty() && !s.is_engine();
}

std::string render_your_account(const std::string& username, const std::string& auth_source) {
    std::string out = "<section class=\"panel\" id=\"acc-account\"><div class=\"hd\"><h2>Your account</h2>"
                      "<span class=\"sub\">" + esc(username) + "</span></div><div class=\"acts\"><div>";
    if (auth_source == "local")
        out += "<button type=\"button\" class=\"btn link sm\" data-act=\"pw-change\">Change password</button>" +
               hint("Ends all your sessions; you sign in again.");
    else
        out += hint("Your password is managed by your identity provider.");
    out += "</div><div><button type=\"button\" class=\"btn link sm danger\" data-act=\"signout-all\">Sign out "
           "everywhere</button>" + hint("Ends all your sessions and revokes every API token you own.") +
           "</div><div><button type=\"button\" class=\"btn link sm\" disabled title=\"Not available yet\">Sign out all "
           "other sessions</button>" + hint("Not available yet.") + "</div></div></section>";
    return out;
}

std::string render_select_role() {
    return "<div class=\"hd\"><h2>Role permissions</h2></div><div class=\"empty\"><span>" +
           esc(kSelectRole) + "</span></div>";
}

std::string render_select_user() {
    return "<div class=\"hd\"><h2>Account</h2></div><div class=\"empty\"><span>" +
           esc(kSelectUser) + "</span></div>";
}

std::string url_q(std::string_view s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (const unsigned char c : s) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                                c == '~';
        if (unreserved) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string_view source_label(std::string_view identity_source) {
    if (identity_source == "local")
        return "Local";
    if (identity_source == "oidc")
        return "OIDC";
    if (identity_source == "saml")
        return "SAML";
    if (identity_source == "ad")
        return "AD";
    if (identity_source == "scim")
        return "SCIM";
    return {};
}

} // namespace yuzu::server::access
