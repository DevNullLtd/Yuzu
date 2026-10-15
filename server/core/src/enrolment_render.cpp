// Enrolment fragment renderers (see enrolment_render.hpp).

#include "enrolment_render.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <ctime>

namespace yuzu::server::enrolment {

namespace {

using auth::AutoApproveRuleType;

std::string esc(const std::string& s) {
    return html_escape(s);
}

constexpr std::string_view kFailboxSv =
    "<div class=\"failbox\" role=\"alert\"><div><b>Enrolment store unavailable.</b> "
    "State unknown. This is not an empty list. Retry shortly.</div></div>";

// "Active" is mild information, never the green OK pill: a lapsed credential is not "healthy".
std::string pill(const char* cls, const char* text) {
    return std::string("<span class=\"pill ") + cls + "\">" + text + "</span>";
}

bool is_ipv4_literal(std::string_view s) {
    int octets = 0;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t digits = 0;
        int v = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + (s[i] - '0');
            if (++digits > 3 || v > 255)
                return false;
            ++i;
        }
        if (digits == 0)
            return false;
        ++octets;
        if (i == s.size())
            break;
        if (s[i] != '.')
            return false;
        ++i;
    }
    return octets == 4;
}

// Honest about what is matched: hostnames are agent-reported, addresses are what the server saw.
const char* rule_phrase(AutoApproveRuleType t) {
    switch (t) {
    case AutoApproveRuleType::trusted_ca:
        return "Agent CA fingerprint ";
    case AutoApproveRuleType::hostname_glob:
        return "Agent-reported hostname matches ";
    case AutoApproveRuleType::ip_subnet:
        return "Address the server sees matches ";
    case AutoApproveRuleType::cloud_provider:
        return "Attestation provider ";
    }
    return "";
}

const char* rule_suffix(AutoApproveRuleType t) {
    return t == AutoApproveRuleType::hostname_glob ? " (not verified)" : "";
}

// Static-confirm copy for one rule's Enable / Disable and Remove, by match mode. In "all" mode
// every enabled rule is REQUIRED, so enabling narrows and disabling or removing widens.
std::string enable_confirm(bool require_all) {
    return require_all ? "Require this rule as well? Fewer agents will join without approval."
                       : "Enable this rule? Matching agents join without approval.";
}
std::string disable_confirm(bool require_all) {
    return require_all ? "Stop requiring this rule? More agents may join without approval." : "";
}
std::string remove_confirm(bool require_all, bool enabled) {
    if (require_all && enabled)
        return "Remove this auto-approve rule? It is currently required, so more agents may join "
               "without approval.";
    return "Remove this auto-approve rule?";
}

std::string attr_confirm(const std::string& question) {
    return question.empty() ? std::string() : " hx-confirm=\"" + esc(question) + "\"";
}

} // namespace


std::string utc_stamp(std::chrono::system_clock::time_point tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
    return std::string(buf) + " UTC";
}

bool rule_matches_everything(AutoApproveRuleType type, std::string_view value) {
    if (type == AutoApproveRuleType::hostname_glob) {
        if (value.empty())
            return false;
        bool star = false;
        for (char c : value) {
            if (c == '*')
                star = true;
            else if (c != '?')
                return false;
        }
        return star;
    }
    if (type == AutoApproveRuleType::ip_subnet) {
        const auto slash = value.find('/');
        if (slash == std::string_view::npos)
            return false;
        return value.substr(slash + 1) == "0" && is_ipv4_literal(value.substr(0, slash));
    }
    return false;
}

// ── Enrolment tokens ─────────────────────────────────────────────────────

std::string render_tokens(const std::vector<auth::EnrollmentToken>* tokens,
                          std::string_view new_raw_token,
                          std::chrono::system_clock::time_point now) {
    std::string html;

    // The reveal comes first and is built before the list read matters: a freshly minted raw
    // token is shown ONCE, so it must survive a failed follow-up read. `<code>` and the Copy
    // button share one parent (the Settings page's copy handler walks parent -> code).
    if (!new_raw_token.empty()) {
        html += "<div class=\"note warn\" role=\"region\" aria-label=\"New enrolment token\">"
                "<b>Copy this token now. It will not be shown again.</b>"
                "<div class=\"revealrow\"><code class=\"mono\">" +
                esc(std::string(new_raw_token)) +
                "</code>"
                "<button class=\"btn sm\" type=\"button\" data-copy-token>Copy to Clipboard</button>"
                "<button class=\"btn sm primary\" type=\"button\" "
                "hx-get=\"/fragments/settings/tokens\" hx-target=\"#token-section\" "
                "hx-swap=\"innerHTML\">Done</button></div></div>";
    }

    if (!tokens) {
        html += std::string(kFailboxSv);
        return html;
    }

    struct Row {
        const auth::EnrollmentToken* t;
        int state; // 0 active, 1 expired, 2 exhausted, 3 revoked
    };
    std::vector<Row> rows;
    rows.reserve(tokens->size());
    for (const auto& t : *tokens) {
        int st = 0;
        if (t.revoked)
            st = 3;
        else if (t.max_uses > 0 && t.use_count >= t.max_uses)
            st = 2;
        else if (t.expires_at != (std::chrono::system_clock::time_point::max)() &&
                 t.expires_at <= now)
            st = 1;
        rows.push_back({&t, st});
    }
    // Active first, otherwise the store's newest-first order is kept.
    std::stable_partition(rows.begin(), rows.end(), [](const Row& r) { return r.state == 0; });

    if (rows.empty()) {
        html += "<div class=\"empty\"><b>No tokens yet.</b>"
                "<span>Generate one below to enrol agents without approval.</span></div>";
    } else {
        html += "<div class=\"tw\"><table><thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
                "<th>Expires</th><th>Status</th><th></th></tr></thead><tbody>";
        const std::size_t shown = std::min(rows.size(), kRenderCap);
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& t = *rows[i].t;
            const std::string uses =
                t.max_uses == 0
                    ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                    : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);
            const std::string exp =
                t.expires_at == (std::chrono::system_clock::time_point::max)()
                    ? std::string("Never")
                    : utc_stamp(t.expires_at);
            std::string status;
            switch (rows[i].state) {
            case 0:
                status = pill("info", "Active");
                break;
            case 1:
                status = pill("warn", "Expired");
                break;
            case 2:
                status = pill("idle", "Exhausted");
                break;
            default:
                status = pill("idle", "Revoked");
            }
            html += "<tr><td><code>" + esc(t.token_id) + "</code></td><td class=\"long\">" +
                    esc(t.label) + "</td><td>" + uses + "</td><td>" + exp + "</td><td>" + status +
                    "</td><td class=\"acts\">";
            if (!t.revoked) {
                html += "<button class=\"btn link danger\" type=\"button\" "
                        "hx-delete=\"/api/settings/enrollment-tokens/" +
                        url_path_segment(t.token_id) +
                        "\" hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke token &quot;" +
                        esc(t.token_id) +
                        "&quot;? Agents using this token will no longer be able to enroll. "
                        "Agents already enrolled stay enrolled.\">Revoke</button>";
            }
            html += "</td></tr>";
        }
        html += "</tbody></table></div>";
        if (rows.size() > shown) {
            html += "<p class=\"hint pad\">Showing " + std::to_string(shown) + " of " +
                    std::to_string(rows.size()) + " tokens. Active tokens are listed first.</p>";
        }
    }

    html += "<form class=\"form\" hx-post=\"/api/settings/enrollment-tokens\" "
            "hx-target=\"#token-section\" hx-swap=\"innerHTML\" data-token-form>"
            "<div class=\"fld\"><label for=\"tok-label\">Label</label>"
            "<input class=\"in\" id=\"tok-label\" type=\"text\" name=\"label\" maxlength=\"256\" "
            "placeholder=\"e.g. Edinburgh rollout\"></div>"
            "<div class=\"row2\">"
            "<div class=\"fld\"><label for=\"tok-uses\">Max uses</label>"
            "<input class=\"in\" id=\"tok-uses\" type=\"text\" inputmode=\"numeric\" "
            "name=\"max_uses\" placeholder=\"0 = unlimited\"></div>"
            "<div class=\"fld\"><label for=\"tok-ttl\">Expires after (hours)</label>"
            "<input class=\"in\" id=\"tok-ttl\" type=\"text\" inputmode=\"numeric\" "
            "name=\"ttl_hours\" placeholder=\"0 = never\"></div></div>"
            "<p class=\"hint\" data-token-unlimited>Unlimited uses and no expiry. Anyone holding "
            "this token can enrol agents indefinitely.</p>"
            "<div><button class=\"btn primary\" type=\"submit\">Generate token</button></div>"
            "</form>";
    return html;
}

// ── Agents waiting for approval ──────────────────────────────────────────

std::string render_pending(const std::vector<auth::PendingAgent>* agents) {
    if (!agents)
        return std::string(kFailboxSv);

    std::vector<const auth::PendingAgent*> waiting, denied;
    for (const auto& a : *agents) {
        if (a.status == auth::PendingStatus::pending)
            waiting.push_back(&a);
        else if (a.status == auth::PendingStatus::denied)
            denied.push_back(&a);
        // approved rows are enrolled: they need no admin attention.
    }
    const std::size_t n_waiting = waiting.size(); // counted BEFORE the render cap
    std::vector<const auth::PendingAgent*> rows = waiting;
    rows.insert(rows.end(), denied.begin(), denied.end());
    const std::size_t shown = std::min(rows.size(), kRenderCap);

    std::string html;
    if (rows.empty()) {
        return "<div class=\"empty\"><b>No agents are waiting.</b>"
               "<span>New agents that register without a token appear here.</span></div>";
    }

    html += "<p class=\"hint pad\">" + std::to_string(n_waiting) + " waiting";
    if (!denied.empty())
        html += ", " + std::to_string(denied.size()) + " denied";
    html += "</p>";

    html += "<div class=\"tw\"><table><thead><tr><th>Agent</th><th>Hostname</th><th>OS</th>"
            "<th>Version</th><th>Requested</th><th>Status</th><th></th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& a = *rows[i];
        const std::string short_id =
            a.agent_id.size() > 12 ? a.agent_id.substr(0, 12) + "..." : a.agent_id;
        const bool is_pending = a.status == auth::PendingStatus::pending;
        html += "<tr><td><code title=\"" + esc(a.agent_id) + "\">" + esc(short_id) +
                "</code></td><td class=\"long\">" + esc(a.hostname) + "</td><td>" + esc(a.os) +
                " " + esc(a.arch) + "</td><td>" + esc(a.agent_version) + "</td><td>" +
                utc_stamp(a.requested_at) + "</td><td>" +
                (is_pending ? pill("warn", "Pending") : pill("bad", "Denied")) +
                "</td><td class=\"acts\">";
        if (is_pending && !path_segment_ok(a.agent_id)) {
            // Empty, `.` or `..` (also %2e forms): a browser collapses a dot-only path segment,
            // so no per-row URL can be built. Offer no row action; the bulk buttons below stay.
            html += "<span class=\"hint\">identifier not supported for row actions</span>";
        } else if (is_pending) {
            // The id is agent-supplied: ONE percent-encoded path segment (html_escape alone
            // leaves `/`, `?`, `#` and `.` live in the URL).
            const std::string base = "/api/settings/pending-agents/" + url_path_segment(a.agent_id);
            html += "<button class=\"btn link\" type=\"button\" hx-post=\"" + base +
                    "/approve\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\">"
                    "Approve</button>"
                    "<button class=\"btn link danger\" type=\"button\" hx-post=\"" +
                    base +
                    "/deny\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Deny agent enrollment?\">Deny</button>"
                    "<button class=\"btn link\" type=\"button\" hx-delete=\"" +
                    base +
                    "\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Remove this request from the queue? The agent is queued again "
                    "the next time it asks to join.\">Forget</button>";
        } else {
            // A denial is a durable record; removing it is refused server-side (409).
            html += "<span class=\"hint\">denial recorded</span>";
        }
        html += "</td></tr>";
    }
    html += "</tbody></table></div>";

    // A lone waiting row whose id cannot be addressed would otherwise have no action at all.
    const bool lone_unaddressable =
        n_waiting == 1 && !path_segment_ok(waiting.front()->agent_id);
    if (n_waiting > 1 || lone_unaddressable) {
        // The bulk routes act on EVERY pending row, including any beyond the cap and any that
        // arrive after this render, so the buttons are off whenever the list is not whole.
        const bool whole = n_waiting <= kRenderCap;
        std::string names;
        for (std::size_t i = 0; i < std::min(n_waiting, kBulkHostnamesListed); ++i)
            names += "\n- " + waiting[i]->hostname;
        if (n_waiting > kBulkHostnamesListed)
            names += "\n- and " + std::to_string(n_waiting - kBulkHostnamesListed) + " more";
        const std::string count = std::to_string(n_waiting);
        const std::string tail = " as of this view, including any that arrive since)?";
        const std::string approve_q =
            "Approve every agent currently waiting (" + count + tail +
            " They join the fleet and can receive instructions." + names;
        const std::string deny_q =
            "Deny every agent currently waiting (" + count + tail +
            " This page offers no way to reverse a denial." + names;
        const char* off = whole ? "" : " disabled";
        html += "<div class=\"btns\"><button class=\"btn primary\" type=\"button\"" +
                std::string(off) +
                " hx-post=\"/api/settings/pending-agents/bulk-approve\" "
                "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" hx-confirm=\"" +
                esc(approve_q) + "\">Approve all (" + count +
                ")</button>"
                "<button class=\"btn danger\" type=\"button\"" +
                std::string(off) +
                " hx-post=\"/api/settings/pending-agents/bulk-deny\" "
                "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" hx-confirm=\"" +
                esc(deny_q) + "\">Deny all (" + count + ")</button></div>";
        if (!whole) {
            html += "<p class=\"hint pad\">Showing " + std::to_string(kRenderCap) + " of " +
                    count + ". Approve or deny these individually; the bulk actions act on every "
                            "waiting agent, including the ones not shown.</p>";
        }
    }
    return html;
}

// ── Auto-approve rules ───────────────────────────────────────────────────

std::string render_auto_approve(const std::vector<auth::AutoApproveRule>& rules,
                                bool require_all) {
    std::string html;

    // Match mode. Two buttons, not a select: each direction carries its own consequence copy,
    // and a cancelled confirm leaves nothing half-switched.
    html += "<div class=\"pad\"><div class=\"fld\"><span class=\"lb\">Match mode</span>"
            "<div class=\"seg\" role=\"group\" aria-label=\"Match mode\">";
    const auto mode_btn = [&](bool all, const char* label, const char* confirm) {
        const bool current = all == require_all;
        if (current)
            return std::string("<button class=\"on\" type=\"button\" aria-pressed=\"true\" "
                               "disabled>") +
                   label + "</button>";
        return std::string("<button type=\"button\" aria-pressed=\"false\" "
                           "hx-post=\"/api/settings/auto-approve/mode\" "
                           "hx-vals=\"{&quot;mode&quot;:&quot;") +
               (all ? "all" : "any") +
               "&quot;}\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
               "hx-confirm=\"" +
               confirm + "\">" + label + "</button>";
    };
    html += mode_btn(false, "Any rule matches (first match)",
                     "Approve an agent when any enabled rule matches? More agents may join "
                     "without approval.");
    html += mode_btn(true, "All enabled rules must match",
                     "Require every enabled rule to match? Fewer agents will join without "
                     "approval.");
    html += "</div></div></div>";

    if (rules.empty()) {
        html += "<div class=\"empty\"><b>No auto-approve rules.</b>"
                "<span>New agents wait for approval.</span></div>";
    } else {
        html += "<div class=\"tw\"><table><thead><tr><th>Rule</th><th>Label</th><th>State</th>"
                "<th></th></tr></thead><tbody>";
        for (std::size_t i = 0; i < rules.size(); ++i) {
            const auto& r = rules[i];
            const std::string idx = std::to_string(i);
            const std::string base = "/api/settings/auto-approve/" + idx;
            html += "<tr><td class=\"long\">" + std::string(rule_phrase(r.type)) + "<code>" +
                    esc(r.value) + "</code>" + rule_suffix(r.type);
            if (rule_matches_everything(r.type, r.value))
                html += " " + pill("warn", "Matches every agent");
            html += "</td><td class=\"long\">" + esc(r.label) + "</td><td>" +
                    (r.enabled ? pill("info", "Enabled") : pill("idle", "Disabled")) +
                    "</td><td class=\"acts\">";
            // Enabling widens (any mode) or narrows (all mode); the copy says which.
            const std::string q = r.enabled ? disable_confirm(require_all) : enable_confirm(require_all);
            html += "<button class=\"btn link\" type=\"button\" hx-post=\"" + base +
                    "/toggle\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\"" +
                    attr_confirm(q) + ">" + (r.enabled ? "Disable" : "Enable") +
                    "</button>"
                    "<button class=\"btn link danger\" type=\"button\" hx-delete=\"" +
                    base + "\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\"" +
                    attr_confirm(remove_confirm(require_all, r.enabled)) + ">Remove</button>";
            html += "</td></tr>";
        }
        html += "</tbody></table></div>";
    }

    html += "<p class=\"hint pad\">Address rules match IPv4 only. Hostnames are reported by the "
            "agent and are not verified.</p>";

    // The Add confirm is built client-side (yuzu-groups.js) because it depends on the value
    // typed; the static text here is the floor if the script did not load.
    html += "<form class=\"form\" hx-post=\"/api/settings/auto-approve\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" data-rule-form "
            "hx-confirm=\"Add this rule? Agents matching it join the fleet without approval. "
            "Hostnames are reported by the agent and are not verified.\">"
            "<div class=\"row2\">"
            "<div class=\"fld\"><label for=\"rule-type\">Type</label>"
            "<select id=\"rule-type\" name=\"type\">"
            "<option value=\"hostname_glob\">Hostname glob</option>"
            "<option value=\"ip_subnet\">Address range (IPv4 CIDR)</option>"
            "<option value=\"trusted_ca\">Trusted CA fingerprint</option>"
            "<option value=\"cloud_provider\">Cloud provider</option></select></div>"
            "<div class=\"fld\"><label for=\"rule-value\">Value</label>"
            "<input class=\"in mono\" id=\"rule-value\" type=\"text\" name=\"value\" required "
            "maxlength=\"256\" pattern=\"[^:]*\" title=\"A colon is not allowed.\" "
            "placeholder=\"*.prod.example.com\"></div></div>"
            "<div class=\"fld\"><label for=\"rule-label\">Label</label>"
            "<input class=\"in\" id=\"rule-label\" type=\"text\" name=\"label\" maxlength=\"256\" "
            "pattern=\"[^:]*\" title=\"A colon is not allowed.\" "
            "placeholder=\"Production servers\"></div>"
            "<div><button class=\"btn primary\" type=\"submit\">Add rule</button></div>"
            "</form>";
    return html;
}

} // namespace yuzu::server::enrolment
