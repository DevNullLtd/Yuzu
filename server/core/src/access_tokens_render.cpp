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
    if (t.overlap_expires_at > 0) {
        // Validation checks only revoked and expires_at, so a predecessor stays usable after its
        // overlap ends until the retirement sweep revokes it; say so rather than "retires <past>".
        if (t.overlap_expires_at <= now)
            return {"warn", "Overlap ended, still valid until retired"};
        return {"warn", "Rotating, retires " + date_cell(t.overlap_expires_at, "")};
    }
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

// One row-action button. Every value rides in an html_escape'd data attribute; the page script
// reads it back with dataset (never innerHTML) and percent-encodes it for any path.
struct Attr {
    const char* name;
    std::string value;
};

std::string act(const char* tk, const std::vector<Attr>& attrs, const char* label, bool danger = false,
                const char* disabled_reason = nullptr, bool solid = false) {
    std::string out = std::string("<button type=\"button\" class=\"") +
                      (solid ? (danger ? "btn btn-sm btn-danger" : "btn btn-sm")
                             : (danger ? "btn link danger" : "btn link")) +
                      "\" data-tk=\"" + tk + "\"";
    for (const auto& a : attrs)
        out += std::string(" ") + a.name + "=\"" + html_escape(a.value) + "\"";
    if (disabled_reason)
        out += std::string(" disabled title=\"") + disabled_reason + "\"";
    return out + ">" + label + "</button>";
}

std::string primary_btn(const char* tk, const char* label) {
    return std::string("<button type=\"button\" class=\"btn btn-primary btn-sm\" data-tk=\"") + tk + "\">" +
           label + "</button>";
}

// Fixed sentence for a control the caller cannot use. RBAC off: the account role decides;
// RBAC on: the named permission does.
std::string need_note(bool rbac_enforced, const char* what, const char* perm) {
    return std::string("<p class=\"hint\">") + what + " needs " +
           (rbac_enforced ? std::string("the ") + perm + " permission."
                          : std::string("the Administrator account role.")) +
           "</p>";
}

// "New principal" (or the sentence saying what it needs). Rows carry no actions: every
// principal action lives in the detail panel, where the credential facts they depend on are read.
std::string principals_toolbar(const PrincipalsView& v) {
    if (v.can_write)
        return "<div class=\"pb\">" + primary_btn("principal-new", "New principal") + "</div>";
    return "<div class=\"pb\">" + need_note(v.rbac_enforced, "Creating principals", "Security:Write") + "</div>";
}

// Rotation grace window: a second rotate by the same operator inside it returns the same
// successor secret. A token with less life left than the overlap floor cannot be rotated. Both
// are read from the store, so they cannot drift. The server stays authoritative.
constexpr std::int64_t kRotationGraceSecs = ApiTokenStore::rotation_grace_secs();
constexpr std::int64_t kRotateMinRemainingSecs = ApiTokenStore::overlap_floor_secs();

std::string token_actions(const ApiToken& t, const std::vector<ApiToken>& all, const PageFlags& f) {
    // A row whose id could not safely sit in a request path gets no controls at all.
    if (!safe_token_id(t.token_id))
        return {};
    const bool mine = !f.caller.empty() && t.principal_id == f.caller;
    const bool human = t.principal_kind == "human";  // engine credentials: Revoke only
    const bool expired = t.expires_at > 0 && t.expires_at <= f.now;
    std::string out;
    if (f.caps.rotate && mine && human && !t.revoked && !expired) {
        if (!t.supersedes_token_id.empty()) {
            // A pending successor: Confirm retires its predecessor.
            const auto pi = std::ranges::find(all, t.supersedes_token_id, &ApiToken::token_id);
            const ApiToken* pred = pi == all.end() ? nullptr : &*pi;
            out += act("token-confirm",
                       {{"data-token-id", t.token_id},
                        {"data-predecessor", pred && !pred->name.empty() ? pred->name : t.supersedes_token_id}},
                       "Confirm rotation");
        } else if (t.rotation_group.empty()) {
            if (t.expires_at == 0 || t.expires_at - f.now > kRotateMinRemainingSecs)
                out += act("token-rotate", {{"data-token-id", t.token_id}, {"data-name", t.name}}, "Rotate");
            else
                out += act("token-rotate", {{"data-token-id", t.token_id}}, "Rotate", false,
                           "A token within 24 hours of expiry cannot be rotated. Create a new one.");
        } else if (t.overlap_expires_at > 0) {
            // The predecessor of a pair: offer Rotate only while the successor is inside the
            // grace window, which is the one way to get its secret again (never earlier or later).
            for (const auto& succ : all)
                if (succ.supersedes_token_id == t.token_id && f.now - succ.created_at <= kRotationGraceSecs) {
                    out += act("token-rotate", {{"data-token-id", t.token_id}, {"data-name", t.name}}, "Rotate");
                    break;
                }
        }
    }
    if (f.caps.revoke && !t.revoked && (mine || f.effective_admin))
        out += act("token-revoke", {{"data-token-id", t.token_id}, {"data-name", t.name}}, "Revoke", true);
    return out;
}

// Principal actions, drawn in the detail panel from the credential facts it just read.
std::string principal_actions(const PrincipalDetail& d) {
    const auto& p = d.row;
    if (p.lifecycle_state != "active" || !valid_principal_id(p.principal_id))
        return {};
    if (!d.can_write)
        return "<div class=\"pb\">" + need_note(d.rbac_enforced, "Changing principals", "Security:Write") + "</div>";
    const std::vector<Attr> id{{"data-principal-id", p.principal_id}};
    const auto solid = [&](const char* tk, const char* label, bool danger = false) {
        return act(tk, id, label, danger, nullptr, true);
    };
    std::string out = "<div class=\"btns\">";
    if (const auto* creds = std::get_if<std::vector<ApiToken>>(&d.credentials)) {
        const ApiToken* succ = nullptr;
        for (const auto& c : *creds)
            if (!c.supersedes_token_id.empty()) {
                succ = &c;
                break;
            }
        if (creds->empty()) {
            out += solid("principal-mint", "Mint credential");
        } else if (succ && safe_token_id(succ->token_id)) {
            out += act("principal-confirm", {{"data-principal-id", p.principal_id}, {"data-token-id", succ->token_id}},
                       "Confirm credential", false, nullptr, true);
            // Lost the response to the rotate? Within the grace window the same call returns the
            // same secret; after it the only way out is to revoke the successor and rotate again.
            if (creds->size() == 2 && d.now - succ->created_at <= kRotationGraceSecs)
                out += solid("principal-rotate", "Rotate credential");
        } else if (creds->size() == 1) {
            out += solid("principal-rotate", "Rotate credential");
        }
    } else {
        for (const auto& [tk, label] : {std::pair{"principal-mint", "Mint credential"},
                                        std::pair{"principal-rotate", "Rotate credential"}})
            out += act(tk, id, label, false, "Credentials could not be read.", true);
    }
    out += solid("principal-transfer", "Transfer owner");
    out += solid("principal-revoke", "Revoke principal", true);
    return out + "</div>";
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

std::string committed_revoke_detail(const std::vector<AuditEvent>& newest_first) {
    // The original revoke is the OLDEST success: the REST DELETE is idempotent, so a retry on an
    // already-revoked principal writes a newer success row with `credentials_revoked=0`.
    for (auto it = newest_first.rbegin(); it != newest_first.rend(); ++it)
        if (it->result == "success")
            return it->detail;
    return {};
}

RevokeDetail revoke_detail_from(std::vector<AuditEvent> newest_first) {
    RevokeDetail out;
    const auto window = static_cast<std::size_t>(kRevokeHistoryWindow);
    out.truncated = newest_first.size() > window;
    if (out.truncated)
        newest_first.erase(newest_first.begin() + static_cast<std::ptrdiff_t>(window), newest_first.end());
    out.text = committed_revoke_detail(newest_first);
    return out;
}

bool safe_token_id(std::string_view id) {
    if (id.empty() || id.size() > 128)
        return false;
    const auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); };
    if (!alnum(id.front()))
        return false;  // also rules out "." and ".."
    return std::ranges::all_of(id, [&](char c) { return alnum(c) || c == '.' || c == '_' || c == '-'; });
}

std::vector<std::string> custom_role_names(const std::vector<RbacRole>& roles) {
    std::vector<std::string> names;
    for (const auto& r : roles)
        if (!r.is_system)
            names.push_back(r.name);
    return names;
}

std::string principal_slug(std::string_view principal_id) {
    if (!valid_principal_id(principal_id))
        return {};
    return std::string(principal_id.substr(7));  // after "engine:"
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
           (flags.caps.create ? primary_btn("token-new", "New API token") + " " : std::string{}) +
           seg(view->show_all) + "</div></div>";
    // Say what is missing instead of leaving a silent gap.
    if (!flags.caps.create)
        out += "<div class=\"pb\">" + need_note(flags.rbac_enforced, "Creating tokens", "ApiToken:Write") + "</div>";

    if (rows.empty()) {
        if (!view->show_all && !view->rows.empty()) {
            out += empty_box("No active API tokens.",
                             "<button type=\"button\" class=\"btn link\" data-tk=\"tokens-state\" "
                             "data-state=\"all\">Show all</button>");
        } else {
            out += empty_box(view->all_owners ? "No API tokens." : "You have no API tokens.",
                             flags.caps.create ? "Use New API token to create one." : "Tokens are created by an administrator.");
        }
        return out + "</div>";
    }

    const bool actions = flags.caps.rotate || flags.caps.revoke;
    out += "<div class=\"tw\"><table><thead><tr><th>Token</th><th>Type</th><th>Owner</th><th>Created</th>"
           "<th>Expires</th><th>Last used</th><th>Status</th>" +
           std::string(actions ? "<th><span class=\"sr\">Actions</span></th>" : "") +
           "</tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const ApiToken& t = *rows[i];
        const Status st = token_status(t, flags.now);
        out += "<tr><td><b>" + esc(t.name) + "</b><br><span class=\"mono mut\">" + esc(t.token_id) +
               "</span></td><td>" + type_pill(t) + "</td><td>" + esc(t.principal_id) + "</td><td>" +
               date_cell(t.created_at, "Unknown") + "</td><td>" + date_cell(t.expires_at, "Never") +
               "</td><td>" + date_cell(t.last_used_at, "Never") + "</td><td>" + pill(st.cls, st.text) +
               "</td>" + (actions ? "<td class=\"acts\">" + token_actions(t, view->rows, flags) + "</td>" : std::string{}) +
               "</tr>";
    }
    out += "</tbody></table></div>" + cap_banner(shown, rows.size(), "tokens");
    return out + "</div>";
}

std::string render_principals_list(const std::variant<PrincipalsView, Unavailable>& v) {
    const auto* view = std::get_if<PrincipalsView>(&v);
    if (!view)
        return "<div id=\"principals-root\" data-count=\"\" data-check=\"0\">" +
               failbox("Engine principals could not be read.", kPrincipalsUnavailable, kRetryPrincipals) +
               "</div>";

    // data-count is the number of rows rendered below (the strip words it as "listed below").
    std::string out = "<div id=\"principals-root\" data-count=\"" +
                      std::to_string(std::min(view->rows.size(), kRenderCap)) + "\" data-check=\"" +
                      (view->can_run_check ? "1" : "0") + "\">";
    if (view->rows.empty())
        return out + principals_toolbar(*view) +
               empty_box("No engine principals.",
                         "Engine principals are named identities for automation and agentic workers.") +
               "</div>";

    const auto* grants = std::get_if<std::vector<PrincipalRole>>(&view->roles);
    const std::size_t shown = std::min(view->rows.size(), kRenderCap);
    out += principals_toolbar(*view);
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
                     ", revoked " + date_cell(p.revoked_at, "at an unknown time") + "</span>";
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
    out += kv("Display name", esc(p.display_name.empty() ? p.principal_id : p.display_name));
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
        else if (std::holds_alternative<Withheld>(d.revoke_detail))
            detail = "(withheld: needs the AuditLog:Read permission, or it could not be confirmed)";
        else if (const auto& s = std::get<std::string>(d.revoke_detail); !s.empty())
            detail = esc(s);
        if (d.revoke_truncated) {
            const auto win = std::to_string(kRevokeHistoryWindow);
            const bool have = std::holds_alternative<std::string>(d.revoke_detail) &&
                              !std::get<std::string>(d.revoke_detail).empty();
            detail += have ? " <span class=\"hint\">(more than " + win + " revoke events: this is the oldest success among the newest " + win + ", not necessarily the original)</span>"
                           : " <span class=\"hint\">(more than " + win + " revoke events and none of the newest " + win + " succeeded)</span>";
        }
        out += kv("Revocation detail", detail);
    }
    out += "</div>" + principal_actions(d);

    // Credentials: active rows only, as the store's checked read defines them.
    if (const auto* creds = std::get_if<std::vector<ApiToken>>(&d.credentials)) {
        if (creds->empty()) {
            out += "<div class=\"pb\"><p class=\"hint\">No active credentials.</p></div>";
        } else {
            out += "<div class=\"tw\"><table><thead><tr><th>Credential</th><th>Created</th><th>Expires</th><th>Last used</th>"
                   "<th>State</th></tr></thead><tbody>";
            for (const auto& t : *creds) {
                const Status st = token_status(t, d.now);
                out += "<tr><td><span class=\"mono\">" + esc(t.token_id) + "</span></td><td>" +
                       date_cell(t.created_at, "Unknown") + "</td><td>" + date_cell(t.expires_at, "Never") + "</td><td>" + date_cell(t.last_used_at, "Never") +
                       "</td><td>" + pill(st.cls, st.text) + "</td></tr>";
            }
            out += "</tbody></table></div>";
        }
    } else {
        out += "<div class=\"pb\"><p class=\"hint\">Credentials could not be read.</p></div>";
    }
    out += "</section>";

    // Roles: Unavailable is never "No roles".
    const bool can_edit_roles = d.can_write && valid_principal_id(p.principal_id);
    const std::string slug = principal_slug(p.principal_id);
    out += "<section class=\"panel\"><div class=\"hd\"><h2>Roles</h2>";
    const auto* custom = std::get_if<std::vector<std::string>>(&d.custom_roles);
    const char* no_assign = nullptr;  // why Assign is disabled, when it is
    if (!custom)
        no_assign = "The role list could not be read.";
    else if (custom->empty())
        no_assign = "No custom roles exist. Engine principals can only hold custom roles; built-in roles are refused.";
    if (can_edit_roles && active) {
        out += "<div class=\"end\">" +
               act("role-assign", {{"data-slug", slug}, {"data-principal-id", p.principal_id}}, "Assign role", false,
                   no_assign, true) +
               "</div>";
    }
    out += "</div>";
    if (can_edit_roles && active) {
        if (no_assign) {
            out += std::string("<div class=\"pb\"><p class=\"hint\">") + no_assign + "</p></div>";
        } else {
            out += "<select id=\"role-options\" hidden>";
            for (const auto& r : *custom)
                out += "<option value=\"" + esc(r) + "\">" + esc(r) + "</option>";
            out += "</select>";
        }
    }
    if (const auto* roles = std::get_if<std::vector<PrincipalRole>>(&d.roles)) {
        if (roles->empty()) {
            out += empty_box("No roles.", "An engine principal has no authority until a role is assigned.");
        } else {
            out += "<div class=\"tw\"><table><thead><tr><th>Role</th>" +
                   std::string(can_edit_roles ? "<th><span class=\"sr\">Actions</span></th>" : "") + "</tr></thead><tbody>";
            for (const auto& r : *roles)
                out += "<tr><td>" + esc(r.role_name) + "</td>" +
                       (can_edit_roles ? "<td class=\"acts\">" +
                                             act("role-remove",
                                                 {{"data-slug", slug}, {"data-role", r.role_name},
                                                  {"data-principal-id", p.principal_id}},
                                                 "Remove", true) +
                                             "</td>"
                                       : std::string{}) +
                       "</tr>";
            out += "</tbody></table></div>";
        }
    } else {
        out += empty_box("Roles could not be read.", "The role store did not answer. This is not an empty list.");
    }
    return out + "</section>";
}

} // namespace yuzu::server::access_tokens
