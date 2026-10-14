// Tokens and principals page: pure renderers (see access_tokens_render.hpp).

#include "access_tokens_render.hpp"

#include "web_utils.hpp"

#include <algorithm>

namespace yuzu::server::access_tokens {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Short UTC date in the cell, full ISO instant in the title. `never` labels a zero epoch.
std::string date_cell(std::int64_t epoch, const char* never) {
    if (epoch <= 0)
        return never;
    const std::string iso = format_iso_utc(epoch);
    return "<span title=\"" + iso + "\">" + iso.substr(0, 10) + "</span>";
}

std::string pill(const char* cls, const std::string& text_already_safe) {
    return std::string("<span class=\"pill ") + cls + "\">" + text_already_safe + "</span>";
}

struct Status {
    const char* cls;
    std::string text;  // already HTML-safe
};

// One credential's lifecycle label. Order matters: a revoked or expired row is that first,
// whatever its rotation fields still say.
Status token_status(const ApiToken& t, std::int64_t now) {
    if (t.revoked)
        return {"idle", "Revoked"};
    if (t.expires_at > 0 && t.expires_at <= now)
        return {"bad", "Expired"};
    if (!t.supersedes_token_id.empty())
        return {"warn", "Awaiting confirmation"};
    if (t.overlap_expires_at > 0)
        return {"warn", "Rotating, retires " + date_cell(t.overlap_expires_at, "")};
    return {"ok", "Active"};
}

std::string type_pill(const ApiToken& t) {
    std::string label;
    const char* cls = "tag";
    if (t.principal_kind == "engine") {
        label = "Engine";
    } else if (!t.mcp_tier.empty()) {
        label = "MCP " + esc(t.mcp_tier);
        cls = "info";
    } else {
        label = "API";
    }
    std::string out = pill(cls, label);
    if (!t.scope_service.empty())
        out += " <span class=\"hint\">scoped to " + esc(t.scope_service) + "</span>";
    return out;
}

std::string empty_box(const std::string& title, const std::string& body_html) {
    return "<div class=\"empty\"><b>" + title + "</b><span>" + body_html + "</span></div>";
}

std::string failbox(const std::string& title, const char* sentence, const std::string& retry_attrs) {
    return "<div class=\"pb\"><div class=\"failbox\" role=\"alert\"><div><b>" + title +
           "</b><br><span class=\"guard\">" + sentence +
           "</span></div><div class=\"end\"><button type=\"button\" class=\"btn sm\" " + retry_attrs +
           ">Retry</button></div></div></div>";
}

std::string cap_banner(std::size_t shown, std::size_t total, const char* noun) {
    if (total <= shown)
        return {};
    return "<div class=\"pb\"><p class=\"hint\">Showing the newest " + std::to_string(shown) +
           " of " + std::to_string(total) + " " + noun + ".</p></div>";
}

std::string seg(bool show_all) {
    auto b = [](const char* state, const char* label, bool on) {
        return std::string("<button type=\"button\"") + (on ? " class=\"on\" aria-pressed=\"true\"" : " aria-pressed=\"false\"") +
               " data-tk=\"tokens-state\" data-state=\"" + state + "\">" + label + "</button>";
    };
    return "<div class=\"seg\" role=\"group\" aria-label=\"Token filter\">" + b("active", "Active", !show_all) +
           b("all", "All", show_all) + "</div>";
}

std::string tokens_root(const PageFlags& f) {
    return "<div id=\"tokens-root\" data-now=\"" + std::to_string(f.now) + "\" data-effective-admin=\"" +
           (f.effective_admin ? "1" : "0") + "\" data-rbac-enforced=\"" + (f.rbac_enforced ? "1" : "0") +
           "\">";
}

const std::string kRetryTokens = "data-tk=\"reload\" data-target=\"tokens-body\"";
const std::string kRetryPrincipals = "data-tk=\"reload\" data-target=\"principals-body\"";

} // namespace

bool sees_all_owners(const auth::Session& s) {
    const bool cookie = s.auth_source != "api_token" && s.auth_source != "mcp_token" &&
                        s.auth_source != "engine_token";
    return cookie && s.mcp_tier.empty() && s.token_scope_service.empty() && s.principal_kind != "engine" &&
           auth::effective_role(s) == auth::Role::admin;
}

bool valid_principal_id(std::string_view id) {
    constexpr std::string_view kPrefix = "engine:";
    if (!id.starts_with(kPrefix))
        return false;
    const auto slug = id.substr(kPrefix.size());
    if (slug.empty() || slug.size() > 128)
        return false;
    return std::ranges::all_of(slug, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

std::string render_tokens_list(const std::variant<TokensView, Unavailable>& v, const PageFlags& flags) {
    std::string out = tokens_root(flags);
    const auto* view = std::get_if<TokensView>(&v);
    if (!view) {
        out += failbox("API tokens could not be read.", kTokensUnavailable, kRetryTokens) + "</div>";
        return out;
    }

    // "Active" hides revoked and expired rows; nothing is lost, "All" shows them.
    std::vector<const ApiToken*> rows;
    for (const auto& t : view->rows) {
        if (!view->show_all && (t.revoked || (t.expires_at > 0 && t.expires_at <= flags.now)))
            continue;
        rows.push_back(&t);
    }
    const std::size_t shown = std::min(rows.size(), kRenderCap);

    out += "<div class=\"hd\"><h2>API tokens</h2><span class=\"sub\">" +
           std::string(view->all_owners ? "All owners" : "Your tokens") + "</span><div class=\"end\">" +
           seg(view->show_all) + "</div></div>";

    if (rows.empty()) {
        if (!view->show_all && !view->rows.empty()) {
            out += empty_box("No active API tokens.",
                             "<button type=\"button\" class=\"btn link\" data-tk=\"tokens-state\" "
                             "data-state=\"all\">Show all</button>");
        } else {
            out += empty_box(view->all_owners ? "No API tokens." : "You have no API tokens.",
                             "Tokens are created in Settings until this page takes over actions.");
        }
        return out + "</div>";
    }

    out += "<div class=\"tw\"><table><thead><tr><th>Token</th><th>Type</th><th>Owner</th><th>Created</th>"
           "<th>Expires</th><th>Last used</th><th>Status</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const ApiToken& t = *rows[i];
        const Status st = token_status(t, flags.now);
        out += "<tr><td><b>" + esc(t.name) + "</b><br><span class=\"mono mut\">" + esc(t.token_id) +
               "</span></td><td>" + type_pill(t) + "</td><td>" + esc(t.principal_id) + "</td><td>" +
               date_cell(t.created_at, "Unknown") + "</td><td>" + date_cell(t.expires_at, "Never") +
               "</td><td>" + date_cell(t.last_used_at, "Never") + "</td><td>" + pill(st.cls, st.text) +
               "</td></tr>";
    }
    out += "</tbody></table></div>" + cap_banner(shown, rows.size(), "tokens");
    return out + "</div>";
}

std::string render_principals_list(const std::variant<PrincipalsView, Unavailable>& v) {
    const auto* view = std::get_if<PrincipalsView>(&v);
    if (!view)
        return "<div id=\"principals-root\" data-count=\"\">" +
               failbox("Engine principals could not be read.", kPrincipalsUnavailable, kRetryPrincipals) +
               "</div>";

    std::string out = "<div id=\"principals-root\" data-count=\"" + std::to_string(view->rows.size()) +
                      "\">";
    if (view->rows.empty())
        return out + empty_box("No engine principals.",
                               "Engine principals are named identities for automation and agentic workers.") +
               "</div>";

    const auto* grants = std::get_if<std::vector<PrincipalRole>>(&view->roles);
    const std::size_t shown = std::min(view->rows.size(), kRenderCap);
    out += "<div class=\"tw\"><table><thead><tr><th>Principal</th><th>Owner</th><th>Roles</th>"
           "<th>State</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& p = view->rows[i];
        std::string roles = "Not shown";
        if (grants) {
            std::string joined;
            for (const auto& g : *grants) {
                if (g.principal_type != "engine" || g.principal_id != p.principal_id)
                    continue;
                joined += (joined.empty() ? "" : ", ") + esc(g.role_name);
            }
            roles = joined.empty() ? "None" : joined;
        }
        const bool active = p.lifecycle_state == "active";
        std::string state = active ? pill("ok", "Active") : pill("idle", "Revoked");
        if (!active)
            state += "<br><span class=\"hint\">" +
                     (p.superseded_by.empty() ? std::string("no successor recorded")
                                              : "superseded by " + esc(p.superseded_by)) +
                     "</span>";
        // The select control is a real button so the row is keyboard-operable.
        out += "<tr><td><button type=\"button\" class=\"btn link\" data-tk=\"principal-select\" "
               "data-principal-id=\"" + esc(p.principal_id) + "\"><b>" +
               esc(p.display_name.empty() ? p.principal_id : p.display_name) +
               "</b></button><br><span class=\"mono mut\">" + esc(p.principal_id) + "</span></td><td>" +
               esc(p.owner_username) + "</td><td>" + roles + "</td><td>" + state + "</td></tr>";
    }
    out += "</tbody></table></div>" + cap_banner(shown, view->rows.size(), "principals");
    return out + "</div>";
}

std::string render_select_principal() {
    return empty_box("No principal selected.", "Select a principal from the list.");
}

std::string render_principal_detail(const std::variant<PrincipalDetail, NotFound, Unavailable>& v,
                                    const std::string& id) {
    if (std::holds_alternative<NotFound>(v))
        return empty_box("Not found.", "This principal no longer exists.");
    if (std::holds_alternative<Unavailable>(v))
        return failbox("Principal could not be read.", kDetailUnavailable,
                       "data-tk=\"principal-select\" data-principal-id=\"" + esc(id) + "\"");

    const auto& d = std::get<PrincipalDetail>(v);
    const auto& p = d.row;
    auto kv = [](const char* k, const std::string& val_html) {
        return "<div><span>" + std::string(k) + "</span><b>" + val_html + "</b></div>";
    };
    const bool active = p.lifecycle_state == "active";

    std::string out = "<section class=\"panel\"><div class=\"hd\"><h2 class=\"long\">" +
                      esc(p.display_name.empty() ? p.principal_id : p.display_name) + "</h2></div><div class=\"kvl\">";
    out += kv("Principal", "<span class=\"mono\">" + esc(p.principal_id) + "</span>");
    out += kv("Owner", esc(p.owner_username));
    out += kv("Classification", esc(p.classification));
    out += kv("State", active ? pill("ok", "Active") : pill("idle", "Revoked"));
    out += kv("Created", date_cell(p.created_at, "Unknown") + (p.created_by.empty() ? "" : " by " + esc(p.created_by)));
    out += kv("Justification", esc(p.justification));
    if (!active) {
        out += kv("Revoked", date_cell(p.revoked_at, "Unknown"));
        out += kv("Superseded by", p.superseded_by.empty() ? "no successor recorded" : esc(p.superseded_by));
        std::string detail = "(not recorded)";
        if (std::holds_alternative<Unavailable>(d.revoke_detail))
            detail = "(unavailable)";
        else if (const auto& s = std::get<std::string>(d.revoke_detail); !s.empty())
            detail = esc(s);
        out += kv("Revocation detail", detail);
    }
    out += "</div>";

    // Credentials: active rows only, as the store's checked read defines them.
    if (const auto* creds = std::get_if<std::vector<ApiToken>>(&d.credentials)) {
        if (creds->empty()) {
            out += "<div class=\"pb\"><p class=\"hint\">No active credentials.</p></div>";
        } else {
            out += "<div class=\"tw\"><table><thead><tr><th>Credential</th><th>Expires</th><th>Last used</th>"
                   "<th>State</th></tr></thead><tbody>";
            for (const auto& t : *creds) {
                const Status st = token_status(t, d.now);
                out += "<tr><td><span class=\"mono\">" + esc(t.token_id) + "</span></td><td>" +
                       date_cell(t.expires_at, "Never") + "</td><td>" + date_cell(t.last_used_at, "Never") +
                       "</td><td>" + pill(st.cls, st.text) + "</td></tr>";
            }
            out += "</tbody></table></div>";
        }
    } else {
        out += "<div class=\"pb\"><p class=\"hint\">Credentials could not be read.</p></div>";
    }
    out += "</section>";

    // Roles: Unavailable is never "No roles".
    out += "<section class=\"panel\"><div class=\"hd\"><h2>Roles</h2></div>";
    if (const auto* roles = std::get_if<std::vector<PrincipalRole>>(&d.roles)) {
        if (roles->empty()) {
            out += empty_box("No roles.", "An engine principal has no authority until a role is assigned.");
        } else {
            out += "<div class=\"tw\"><table><thead><tr><th>Role</th></tr></thead><tbody>";
            for (const auto& r : *roles)
                out += "<tr><td>" + esc(r.role_name) + "</td></tr>";
            out += "</tbody></table></div>";
        }
    } else {
        out += empty_box("Roles could not be read.", "The role store did not answer. This is not an empty list.");
    }
    return out + "</section>";
}

} // namespace yuzu::server::access_tokens
