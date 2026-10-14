// Access reviews panels: pure HTML renderers (see access_reviews_render.hpp for the contract).

#include "access_reviews_render.hpp"

#include "access_audit_render.hpp"
#include "web_utils.hpp"

#include <algorithm>
#include <set>

namespace yuzu::server::access_reviews {

namespace {

constexpr std::string_view kCampaignUrl = "/fragments/access/reviews/campaign?id=";
constexpr std::string_view kPageUrl = "/access/audit?campaign=";
constexpr std::string_view kCsvUrl = "/api/v1/access-reviews/export?format=csv";

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

// Campaign timestamps are epoch milliseconds.
std::string when(std::int64_t ms) {
    return access_audit::format_utc_short(ms / 1000);
}

std::string failbox(std::string_view lead, std::string_view why, const std::string& retry) {
    std::string out = "<div class=\"failbox\" role=\"alert\"><div><b>" + esc(lead) +
                      "</b><br><span class=\"guard\">" + esc(why) + "</span></div>";
    if (!retry.empty())
        out += "<div class=\"end\">" + retry + "</div>";
    return out + "</div>";
}

std::string reload_button(std::string_view target_id) {
    return "<button type=\"button\" class=\"btn sm\" data-act=\"reload\" data-target=\"" +
           esc(target_id) + "\">Retry</button>";
}

std::string decision_pill(const std::string& d) {
    const char* tone = d == "attested" ? "ok" : d == "flagged_revoke" ? "warn" : "idle";
    return std::string("<span class=\"pill ") + tone + "\">" + esc(d) + "</span>";
}

bool is_pending(const AccessReviewAttestationRow& a) {
    return a.decision == "pending";
}

// ---- campaigns list ----

std::string campaign_row(const AccessReviewCampaignRow& c, bool can_attest) {
    const bool open = c.status == "open";
    const std::string q = access::url_q(c.campaign_id);
    std::string out = "<tr data-campaign-id=\"" + esc(c.campaign_id) +
                      "\"><td class=\"long\"><button type=\"button\" class=\"btn link sm\" hx-get=\"" +
                      esc(std::string(kCampaignUrl) + q) +
                      "\" hx-target=\"#ar-campaign\" hx-push-url=\"" +
                      esc(std::string(kPageUrl) + q) + "\"><b>" + esc(c.title) +
                      "</b></button></td><td>" + when(c.created_at_ms) + "<span class=\"sub\">by " +
                      esc(c.created_by) + "</span></td><td>";
    if (open)
        out += "<span class=\"pill info\">Open</span>";
    else
        out += "<span class=\"pill idle\">Closed</span><span class=\"sub\">" + when(c.closed_at_ms) +
               (c.closed_by.empty() ? std::string{} : " by " + esc(c.closed_by)) + "</span>";
    out += "</td><td><div class=\"rowact\">";
    if (open && can_attest)
        out += "<button type=\"button\" class=\"btn link sm\" data-act=\"ar-close\" "
               "data-campaign-id=\"" + esc(c.campaign_id) + "\">Close campaign</button>";
    return out + "</div></td></tr>";
}

// ---- one campaign ----

std::string side_placeholder(std::string_view text) {
    return "<section class=\"panel\" id=\"ar-campaign-side\" hx-swap-oob=\"true\"><div "
           "class=\"hd\"><h2>Campaign summary</h2></div><div class=\"empty\"><span>" +
           esc(text) + "</span></div></section>";
}

std::string kv(std::string_view label, const std::string& value_html) {
    return "<div><span>" + esc(label) + "</span><b>" + value_html + "</b></div>";
}

std::string side_card(const CampaignView& v, const CampaignDerived& d, bool can_attest) {
    const auto& c = v.campaign;
    const bool open = c.status == "open";
    std::string out = "<section class=\"panel\" id=\"ar-campaign-side\" hx-swap-oob=\"true\"><div "
                      "class=\"hd\"><h2 class=\"long\">" + esc(c.title) + "</h2><span class=\"sub\">" +
                      (open ? "Open" : "Closed") + "</span></div><div class=\"kvl\">";
    out += kv("Opened", when(c.created_at_ms) + " by " + esc(c.created_by));
    if (!open)
        out += kv("Closed", when(c.closed_at_ms) + (c.closed_by.empty() ? std::string{}
                                                                         : " by " + esc(c.closed_by)));
    out += kv("Grants decided", std::to_string(d.decided) + " of " + std::to_string(d.total));
    out += kv("Flagged for revocation", std::to_string(d.flagged));
    out += kv("Reviewers who have acted", std::to_string(d.reviewers));
    out += kv("Enforcement when opened", c.rbac_enforcement.empty() ? std::string("not recorded")
                                                                    : esc(c.rbac_enforcement));
    out += kv("Due date", "<span class=\"hint\" title=\"Not available yet: no campaign due-date "
                          "field exists\">Not available yet</span>");
    out += "</div><div class=\"btns\">";
    if (open && can_attest)
        out += "<button type=\"button\" class=\"btn\" data-act=\"ar-close\" data-campaign-id=\"" +
               esc(c.campaign_id) + "\">Close campaign</button>";
    out += "<button type=\"button\" class=\"btn\" disabled title=\"Not available yet: no route "
           "exports a campaign's decisions\">Export decisions</button></div></section>";
    return out;
}

std::string attestation_row(const AccessReviewAttestationRow& a, bool controls) {
    const bool pending = is_pending(a);
    const bool edit = controls && pending;
    std::string out = "<tr data-principal-type=\"" + esc(a.principal_type) +
                      "\" data-principal-id=\"" + esc(a.principal_id) + "\" data-role-name=\"" +
                      esc(a.role_name) + "\"><td class=\"long\"><span class=\"pill idle\">" +
                      esc(a.principal_type) + "</span> " + esc(a.principal_id) +
                      "</td><td><span class=\"pill tag\">" + esc(a.role_name) + "</span></td><td>" +
                      decision_pill(a.decision) + "</td><td class=\"long\">";
    if (a.reviewer.empty())
        out += "<span class=\"hint\">None</span>";
    else
        out += esc(a.reviewer) + "<span class=\"sub\">" + when(a.decided_at_ms) + "</span>";
    out += "</td><td class=\"long\">";
    if (edit)
        out += "<input class=\"in\" data-ar-justification maxlength=\"1000\" "
               "aria-label=\"Justification\" placeholder=\"Justification (optional)\">";
    else if (a.justification.empty())
        out += "<span class=\"hint\">None</span>";
    else
        out += esc(a.justification);
    out += "</td><td><div class=\"rowact\">";
    if (edit)
        out += "<button type=\"button\" class=\"btn link sm\" data-act=\"ar-attest\" "
               "data-decision=\"attested\">Attest</button><button type=\"button\" class=\"btn link "
               "sm danger\" data-act=\"ar-flag\" data-decision=\"flagged_revoke\" title=\"Flag for "
               "revocation. Records evidence; does not revoke the grant.\">Flag</button>";
    return out + "</div></td></tr>";
}

std::string campaign_panel(const CampaignView& v, bool can_attest) {
    const auto& c = v.campaign;
    const bool open = c.status == "open";
    const auto d = derive_campaign_counts(v);
    // Undecided grants first, each group in store order, so the cap can never hide one.
    std::vector<const AccessReviewAttestationRow*> ordered;
    ordered.reserve(v.attestations.size());
    for (const auto& a : v.attestations)
        if (is_pending(a))
            ordered.push_back(&a);
    for (const auto& a : v.attestations)
        if (!is_pending(a))
            ordered.push_back(&a);

    std::string out = "<div class=\"hd\"><h2 class=\"long\">" + esc(c.title) +
                      ": grants</h2><span class=\"sub\">" + std::to_string(d.decided) + " of " +
                      std::to_string(d.total) + " decided</span></div><div class=\"ar-root\" "
                      "data-campaign-id=\"" + esc(c.campaign_id) + "\" data-status=\"" +
                      esc(c.status) + "\">";
    if (ordered.size() > kGrantRenderCap)
        out += "<div class=\"pb\"><div class=\"note warn\">Showing the first " +
               std::to_string(kGrantRenderCap) + " of " + std::to_string(ordered.size()) +
               " frozen grants, undecided first. The complete set is the JSON from the "
               "access-reviews campaign route.</div></div>";
    if (ordered.empty()) {
        out += "<div class=\"empty\"><b>No frozen grants</b>This campaign froze zero grants.</div>";
    } else {
        out += "<div class=\"tw\"><table class=\"dense\"><thead><tr><th>Principal</th><th>Role</th>"
               "<th>Decision</th><th>Decided by</th><th>Justification</th><th></th></tr></thead>"
               "<tbody>";
        const std::size_t shown = std::min(ordered.size(), kGrantRenderCap);
        for (std::size_t i = 0; i < shown; ++i)
            out += attestation_row(*ordered[i], open && can_attest);
        out += "</tbody></table></div>";
    }
    return out + "</div>";
}

// ---- live grants ----

std::string grant_row(const AccessReviewRow& r) {
    std::string out = "<tr><td class=\"long\"><span class=\"pill idle\">" + esc(r.principal_type) +
                      "</span> <b>" + esc(r.display_name.empty() ? r.principal_id : r.display_name) +
                      "</b>";
    if (!r.owner_or_email.empty())
        out += "<span class=\"sub\">" + esc(r.owner_or_email) + "</span>";
    out += "</td><td>";
    for (const auto& role : r.roles)
        out += "<span class=\"pill tag\">" + esc(role) + "</span> ";
    out += "</td><td class=\"r\">" + std::to_string(r.effective_permission_count) + "</td><td>";
    if (r.last_activity_ms == 0)
        out += "n/a";
    else
        out += when(r.last_activity_ms) + "<span class=\"sub\">" + esc(r.last_activity_kind) +
               "</span>";
    out += "</td><td>" + esc(r.classification) + "</td><td>";
    if (r.lifecycle_state == "disabled" || r.lifecycle_state == "revoked")
        out += "<span class=\"pill warn\">" + esc(r.lifecycle_state) + "</span>";
    else
        out += esc(r.lifecycle_state);
    out += "</td><td>";
    if (r.source == "orphan")
        out += "<span class=\"pill warn\" title=\"Grant with no matching account\">orphan</span>";
    else
        out += esc(r.source);
    return out + "</td></tr>";
}

} // namespace

bool valid_campaign_id(std::string_view id) {
    if (id.empty() || id.size() > 64)
        return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-';
    });
}

CampaignDerived derive_campaign_counts(const CampaignView& v) {
    CampaignDerived d;
    std::set<std::string> who;
    for (const auto& a : v.attestations) {
        ++d.total;
        if (a.decision == "attested" || a.decision == "flagged_revoke")
            ++d.decided;
        if (a.decision == "flagged_revoke")
            ++d.flagged;
        if (!a.reviewer.empty())
            who.insert(a.reviewer);
    }
    d.reviewers = static_cast<int>(who.size());
    return d;
}

std::string render_campaigns(
    const std::variant<std::vector<AccessReviewCampaignRow>, access::Unavailable>& state,
    bool can_attest) {
    std::string out = "<div class=\"hd\"><h2>Access reviews</h2><span class=\"sub\">Campaigns</span>";
    if (can_attest)
        out += "<div class=\"end\"><button type=\"button\" class=\"btn primary sm\" "
               "data-act=\"ar-open\">Open review</button></div>";
    out += "</div>";
    const auto* rows = std::get_if<std::vector<AccessReviewCampaignRow>>(&state);
    if (!rows)
        return out + "<div class=\"pb\">" +
               failbox("Access review data unavailable.", kCampaignsUnavailable,
                       reload_button("ar-campaigns")) + "</div>";
    if (rows->empty())
        return out + "<div class=\"empty\"><b>No review campaigns yet</b>The store was read and "
                     "holds none. Open a review to freeze today's grants for attestation.</div>";
    out += "<div class=\"tw\"><table class=\"dense\"><thead><tr><th>Review</th><th>Opened</th>"
           "<th>State</th><th></th></tr></thead><tbody>";
    for (const auto& c : *rows)
        out += campaign_row(c, can_attest);
    return out + "</tbody></table></div>";
}

std::string render_campaign(const std::variant<CampaignView, access::NotFound, access::Unavailable>& state,
                            bool can_attest, std::string_view id) {
    if (const auto* v = std::get_if<CampaignView>(&state))
        return campaign_panel(*v, can_attest) +
               side_card(*v, derive_campaign_counts(*v), can_attest);
    const std::string hd = "<div class=\"hd\"><h2>Review campaign</h2></div>";
    if (std::holds_alternative<access::NotFound>(state))
        return hd + "<div class=\"empty\"><b>No campaign with that id</b>It may not exist, or the "
                    "link is out of date.</div>" +
               side_placeholder(kSelectCampaign);
    const std::string retry =
        id.empty() ? std::string{}
                   : "<button type=\"button\" class=\"btn sm\" hx-get=\"" +
                         esc(std::string(kCampaignUrl) + access::url_q(id)) +
                         "\" hx-target=\"#ar-campaign\">Retry</button>";
    return hd + "<div class=\"pb\">" +
           failbox("This campaign could not be read.", kCampaignUnavailable, retry) + "</div>" +
           side_placeholder(kSelectCampaign);
}

std::string render_campaign_unselected() {
    return "<div class=\"hd\"><h2>Review campaign</h2></div><div class=\"empty\"><span>" +
           esc(kSelectCampaign) + "</span></div>" + side_placeholder(kSelectCampaign);
}

std::string render_grants(const std::variant<GrantsView, access::Unavailable>& state) {
    const std::string sub = "<span class=\"sub\">Live population, not a campaign</span>";
    const auto* g = std::get_if<GrantsView>(&state);
    if (!g)
        return "<div class=\"hd\"><h2>Current grants</h2>" + sub + "</div><div class=\"pb\">" +
               failbox("The current grants could not be read.", kGrantsUnavailable,
                       reload_button("ar-grants")) + "</div>";
    std::string out = "<div class=\"hd\"><h2>Current grants</h2>" + sub +
                      "<div class=\"end\"><a class=\"btn sm\" href=\"" + std::string(kCsvUrl) +
                      "\">Download CSV</a></div></div>";
    if (g->rows.size() > kGrantRenderCap)
        out += "<div class=\"pb\"><div class=\"note warn\">Showing the first " +
               std::to_string(kGrantRenderCap) + " of " + std::to_string(g->rows.size()) +
               " principals. Download CSV for the complete population.</div></div>";
    if (g->rows.empty()) {
        out += "<div class=\"empty\"><b>No grants</b>The grant table was read and holds none.</div>";
    } else {
        out += "<div class=\"tw\"><table class=\"dense\"><thead><tr><th>Principal</th><th>Roles</th>"
               "<th class=\"r\">Perms</th><th>Last activity</th><th>Classification</th>"
               "<th>Lifecycle</th><th>Source</th></tr></thead><tbody>";
        const std::size_t shown = std::min(g->rows.size(), kGrantRenderCap);
        for (std::size_t i = 0; i < shown; ++i)
            out += grant_row(g->rows[i]);
        out += "</tbody></table></div>";
    }
    return out + "<div class=\"pb\"><p class=\"hint\">RBAC enforcement when read: " +
           esc(g->rbac_enforcement) + ". Direct role grants only; reading this list is recorded in "
           "the audit log.</p></div>";
}

} // namespace yuzu::server::access_reviews
