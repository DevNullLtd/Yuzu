// Access pages: pure HTML renderers (see access_render.hpp for the contract).

#include "access_render.hpp"

#include "web_utils.hpp"

#include <algorithm>

namespace yuzu::server::access {

namespace {

constexpr std::string_view kDetailUrl = "/fragments/access/users/detail?username=";

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

std::string user_row(const auth::UserEntry& u, bool is_self) {
    std::string out = "<tr data-username=\"" + esc(u.username) + "\"><td class=\"long\"><b>" +
                      esc(u.username) + "</b></td><td>" + source_pill(u) + "</td><td>" +
                      role_pill(u) + "</td><td><div class=\"rowact\">";
    if (is_self) {
        out += "<span class=\"pill idle\" title=\"This is your own account\">Current user</span>";
    } else {
        out += "<button type=\"button\" class=\"btn link sm\" hx-get=\"" + std::string(kDetailUrl) +
               esc(url_q(u.username)) + "\" hx-target=\"#acc-detail\" hx-swap=\"innerHTML\">"
               "Manage</button>";
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

std::string detail_panel(const UserDetail& d) {
    const auto& u = d.user;
    const bool admin = u.role == auth::Role::admin;
    std::string out = "<div class=\"hd\"><h2 class=\"long\">" + esc(u.username) +
                      "</h2><span class=\"sub\">" + account_noun(u) + "</span></div>"
                      "<div class=\"form\"><div class=\"fld\">"
                      "<label for=\"acc-role\">Account role</label>"
                      "<select id=\"acc-role\" disabled><option value=\"user\"";
    out += admin ? ">User</option>" : " selected>User</option>";
    out += admin ? "<option value=\"admin\" selected>Admin</option></select>"
                 : "<option value=\"admin\">Admin</option></select>";
    out += hint("Only admin and user exist here.");
    // Read-only page: the control is always disabled, and the reason is stated.
    if (d.is_self)
        out += hint("You cannot change your own role.");
    else if (!is_local(u))
        out += hint("Not available for SSO or SCIM accounts here.");
    else
        out += hint("The account role cannot be changed from this page yet.");
    return out + "</div></div>";
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
                      std::to_string(total) + (total == 1 ? " account" : " accounts") + "</span></div>";
    if (total > kUsersRenderCap)
        out += "<div class=\"pb\"><div class=\"note warn\">Showing the first " +
               std::to_string(kUsersRenderCap) + " of " + std::to_string(total) +
               " accounts.</div></div>";

    out += "<div class=\"tw\"><table><thead><tr><th>User</th><th>Source</th><th>Account role</th>"
           "<th></th></tr></thead><tbody>";
    if (total == 0) {
        // A fresh install has its first admin, so this is not expected; it is a true empty
        // (the store answered), never the Unavailable text.
        out += "<tr><td colspan=\"4\" class=\"hint\">No active accounts were returned.</td></tr>";
    }
    const std::size_t shown = std::min(total, kUsersRenderCap);
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& u = list->users[i];
        out += user_row(u, !list->self.empty() && u.username == list->self);
    }
    out += "</tbody></table></div><div class=\"pb\"><p class=\"hint\">Account role (admin or user) "
           "is the legacy role: it decides who can open Settings and what applies while RBAC "
           "enforcement is off. RBAC roles apply once enforcement is on.</p></div>";
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
