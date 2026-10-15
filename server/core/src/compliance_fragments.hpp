#pragma once

/// @file compliance_fragments.hpp
/// Pure HTML renderers for the Compliance page fragments (summary, per-policy
/// detail, policy-fragments list) and the tag-compliance table. Data in,
/// markup out: no store, no request, no clock (callers pass `now`), so the
/// unit suites feed fixtures and never touch Postgres. The routes in
/// `compliance_routes.cpp` / `settings_routes.cpp` own gating, confinement,
/// audit and the store reads; this header owns only the markup.
///
/// Every caller-visible string goes through `html_escape`. Classes are the
/// shared slate set in `yuzu.css` (`.readout`, `.panel`, `.tw`, `.pill`,
/// `.kvl`, `.note`); only the table/cell hooks the Compliance page styles
/// locally (`policy-table`, `detail-table`) are page-local.

#include "compliance_types.hpp"
#include "web_utils.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::compliance_html {

/// good >= 90, warn >= 70, bad below: the thresholds the page has always used.
inline const char* level_class(int pct) {
    if (pct >= 90)
        return "good";
    if (pct >= 70)
        return "warn";
    return "bad";
}

inline std::string pill(const char* tone, const std::string& text_already_safe) {
    return std::string("<span class=\"pill ") + tone + "\">" + text_already_safe + "</span>";
}

/// "12s ago" / "3 min ago" / "5h ago" / "never". `last_check_at` is epoch seconds.
inline std::string format_age(int64_t now, int64_t last_check_at) {
    if (last_check_at <= 0)
        return "never";
    const int64_t delta = now - last_check_at;
    if (delta < 60)
        return std::to_string(delta < 0 ? 0 : delta) + "s ago";
    if (delta < 3600)
        return std::to_string(delta / 60) + " min ago";
    return std::to_string(delta / 3600) + "h ago";
}

// -- Summary ------------------------------------------------------------------

struct PolicyRow {
    std::string id;
    std::string name;
    std::string scope;
    bool enabled{true};
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    int64_t total{0};
};

struct SummaryView {
    std::vector<PolicyRow> policies;
    /// `PolicyQuery{}.limit`: a list this long was cut by the store.
    std::size_t policy_limit{100};
    FleetCompliance fleet;
    /// Probed once per summary render by the route (Policy:Write / :Execute /
    /// :Delete) and echoed as data- flags on the Policies panel. Controls the
    /// viewer cannot use are not rendered; the server re-checks every call.
    bool can_write{false};
    bool can_execute{false};
    bool can_delete{false};
};

/// The confirm copy and dialogs name policies and fragments by their own text,
/// so every action button carries id and name as escaped attributes.
inline std::string act_button(const char* act, const char* label, const std::string& id,
                              const std::string& name, const char* extra = "") {
    return std::string("<button class=\"btn btn-secondary btn-sm\" type=\"button\" data-act=\"") +
           act + "\" data-id=\"" + html_escape(id) + "\" data-name=\"" + html_escape(name) +
           "\"" + extra + ">" + label + "</button>";
}

/// Status pill for one policy row. "N failing" counts non_compliant + error,
/// the same definition as the "Failing checks" readout so the two agree.
inline std::string policy_status_pill(const PolicyRow& p) {
    if (!p.enabled)
        return pill("idle", "Disabled");
    const int64_t failing = p.non_compliant + p.error;
    if (failing > 0)
        return pill("bad", std::to_string(failing) + " failing");
    if (p.fixing > 0)
        return pill("info", std::to_string(p.fixing) + " fixing");
    if (p.unknown > 0)
        return pill("warn", std::to_string(p.unknown) + " unknown");
    if (p.total == 0)
        return pill("idle", "No results");
    return pill("ok", "Compliant");
}

inline std::string render_summary(const SummaryView& v) {
    int64_t enabled = 0;
    for (const auto& p : v.policies)
        if (p.enabled)
            ++enabled;
    const int fleet_pct = static_cast<int>(v.fleet.compliance_pct);
    const int64_t failing = v.fleet.non_compliant + v.fleet.error;
    const char* fleet_tone = fleet_pct >= 90 ? "ok" : fleet_pct >= 70 ? "warn" : "bad";

    std::string html;
    html += "<div class=\"readout\">"
            "<div class=\"ro\"><div class=\"v\">" +
            std::to_string(enabled) +
            "</div><div class=\"l\">Policies enabled</div>"
            "<div class=\"d\">" +
            std::to_string(v.policies.size()) + " total</div></div>"
            "<div class=\"ro " +
            fleet_tone + "\"><div class=\"v\">" + std::to_string(fleet_pct) +
            "%</div><div class=\"l\">Fleet compliance</div>"
            "<div class=\"compliance-bar\"><div class=\"compliance-fill " +
            level_class(fleet_pct) + "\" style=\"width:" + std::to_string(fleet_pct) +
            "%\"></div></div></div>"
            "<div class=\"ro" +
            std::string(failing > 0 ? " bad" : "") + "\"><div class=\"v\">" +
            std::to_string(failing) +
            "</div><div class=\"l\">Failing checks</div>"
            "<div class=\"d\">of " +
            std::to_string(v.fleet.total_checks) + " device checks</div></div></div>";

    html += std::string("<div class=\"panel\" id=\"policies-panel\" data-can-write=\"") +
            (v.can_write ? "1" : "0") + "\" data-can-execute=\"" + (v.can_execute ? "1" : "0") +
            "\" data-can-delete=\"" + (v.can_delete ? "1" : "0") + "\"><div class=\"hd\"><h2>Policies</h2>";
    if (v.can_write || v.can_execute) {
        html += "<div class=\"acts\">";
        if (v.can_execute)
            html += "<button class=\"btn btn-secondary btn-sm\" type=\"button\" "
                    "data-act=\"invalidate-all\">Invalidate all</button>";
        if (v.can_write)
            html += "<button class=\"btn btn-sm\" type=\"button\" data-act=\"new-policy\" "
                    "data-needs-dialog hidden>New policy</button>";
        html += "</div>";
    }
    html += "</div>";
    if (v.policies.size() >= v.policy_limit) {
        html += "<div class=\"pb\"><div class=\"note\">Showing the first " +
                std::to_string(v.policy_limit) + " policies.</div></div>";
    }
    html += "<div class=\"tw\"><table class=\"policy-table\"><thead><tr>"
            "<th>On</th><th>Policy</th><th>Scope</th><th>Status</th><th>Compliance</th><th>Devices</th>"
            "<th></th></tr></thead><tbody>";
    if (v.policies.empty()) {
        html += "<tr><td colspan=\"7\" class=\"empty-state\">"
                "No policies defined. Create policies in the Policy Engine to track compliance."
                "</td></tr>";
    }
    for (const auto& p : v.policies) {
        const int pct = p.total > 0 ? static_cast<int>(p.compliant * 100 / p.total) : 0;
        html += "<tr><td>";
        if (v.can_write) {
            html += "<input type=\"checkbox\" class=\"sw\" role=\"switch\" data-act=\"toggle-enabled\" "
                    "data-id=\"" + html_escape(p.id) + "\" data-name=\"" + html_escape(p.name) +
                    "\" data-enabled=\"" + (p.enabled ? "1" : "0") + "\"" +
                    (p.enabled ? " checked" : "") + " aria-label=\"Enabled: " + html_escape(p.name) +
                    "\">";
        }
        html += "</td><td class=\"policy-name\">" + html_escape(p.name) +
                "</td><td class=\"policy-scope\">" + html_escape(p.scope) + "</td><td>" +
                policy_status_pill(p) + "</td><td>";
        if (p.total > 0) {
            html += "<span class=\"policy-pct " + std::string(level_class(pct)) + "\">" +
                    std::to_string(pct) + "%</span><div class=\"mini-bar\"><div class=\"mini-fill " +
                    level_class(pct) + "\" style=\"width:" + std::to_string(pct) +
                    "%\"></div></div>";
        } else {
            html += "<span class=\"policy-count\">-</span>";
        }
        html += "</td><td class=\"policy-count\">" + std::to_string(p.compliant) + "/" +
                std::to_string(p.total) +
                "</td><td><button class=\"btn btn-secondary btn-sm\" hx-get=\"/fragments/compliance/" +
                html_escape(p.id) +
                "\" hx-target=\"#compliance-detail\" hx-swap=\"innerHTML\">View</button>";
        if (v.can_execute)
            html += act_button("evaluate", "Evaluate", p.id, p.name);
        if (v.can_delete)
            html += act_button("delete-policy", "Delete", p.id, p.name);
        html += "</td></tr>";
    }
    html += "</tbody></table></div></div>";
    return html;
}

inline std::string render_unavailable(const std::string& message) {
    return "<div class=\"note\">" + html_escape(message) + "</div>";
}

// -- Per-policy detail ---------------------------------------------------------

struct DetailAgent {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string status;
    std::string last_check;
    std::string detail;
};

struct DetailView {
    std::string policy_id;
    std::string policy_name;
    /// The policy lookup answered; the kv panel renders only then.
    bool have_policy{false};
    std::string applies_to;       // scope expression
    std::string check;            // bound fragment's check_compliance; "" renders "-"
    bool remediation_available{false};
    /// Store could not be read: renders the degraded note, never "no data".
    bool degraded{false};
    /// The viewer's scope is narrower than the fleet.
    bool confined{false};
    ComplianceSummary summary;
    std::vector<DetailAgent> agents;
};

inline std::string agent_status_pill(const std::string& status) {
    if (status == "compliant")
        return pill("ok", "Compliant");
    if (status == "non_compliant")
        return pill("bad", "Non-compliant");
    if (status == "error")
        return pill("bad", "Error");
    if (status == "unknown")
        return pill("warn", "Unknown");
    if (status == "fixing")
        return pill("info", "Fixing");
    return pill("idle", html_escape(status)); // unrecognised store string: escaped, never raw
}

inline std::string render_detail(const DetailView& v) {
    std::string html = "<div class=\"detail-panel\"><h3>" + html_escape(v.policy_name) +
                       " <span class=\"detail-id\">(" + html_escape(v.policy_id) +
                       ")</span></h3>";
    if (v.have_policy) {
        html += "<div class=\"kvl\"><div><span>Applies to</span><b class=\"mono-id\">" +
                html_escape(v.applies_to) + "</b></div><div><span>Check</span><b class=\"mono-id\">" +
                (v.check.empty() ? std::string("-") : html_escape(v.check)) +
                "</b></div><div><span>Remediation</span><b>" +
                (v.remediation_available ? "Available" : "None") + "</b></div></div>";
    }
    if (v.have_policy && !v.degraded) {
        // Gated client-side by the flags the summary probe left on the page
        // (data-perm): the detail fragment never re-probes. The server
        // re-checks every call.
        html += "<div class=\"detail-actions\">";
        if (v.remediation_available) {
            std::string extra = " data-perm=\"execute\"";
            if (!v.confined)
                extra += " data-n=\"" + std::to_string(v.summary.non_compliant) + "\"";
            html += act_button("remediate", "Remediate", v.policy_id, v.policy_name, extra.c_str());
        }
        html += act_button("invalidate", "Invalidate cache", v.policy_id, v.policy_name,
                           " data-perm=\"execute\"");
        html += act_button("delete-policy", "Delete policy", v.policy_id, v.policy_name,
                           " data-perm=\"delete\"");
        html += "</div>";
    }
    if (v.degraded) {
        // Must not read as "no data yet": that tells an operator to wait.
        return html + "<div class=\"empty-state\">Compliance data temporarily unavailable (store "
                      "degraded) — try again shortly.</div></div>";
    }
    if (v.confined) {
        html += "<div class=\"note\">Rows cover devices in your scope.</div>";
    }
    if (v.agents.empty()) {
        return html + "<div class=\"empty-state\">No compliance data yet. "
                      "Agents will report status once the policy triggers fire.</div></div>";
    }
    html += "<div class=\"detail-badges\">" +
            pill("ok", std::to_string(v.summary.compliant) + " compliant") +
            pill("bad", std::to_string(v.summary.non_compliant) + " non-compliant") +
            pill("bad", std::to_string(v.summary.error) + " error") +
            pill("warn", std::to_string(v.summary.unknown) + " unknown") +
            pill("info", std::to_string(v.summary.fixing) + " fixing") + "</div>";
    html += "<div class=\"tw\"><table class=\"detail-table\"><thead><tr>"
            "<th>Agent</th><th>Hostname</th><th>OS</th><th>Status</th><th>Last check</th>"
            "<th>Detail</th></tr></thead><tbody>";
    for (const auto& a : v.agents) {
        html += "<tr><td class=\"mono-id\">" + html_escape(a.agent_id) + "</td><td>" +
                html_escape(a.hostname) + "</td><td class=\"cell-mut\">" + html_escape(a.os) +
                "</td><td>" + agent_status_pill(a.status) + "</td><td class=\"cell-mut\">" +
                html_escape(a.last_check) + "</td><td class=\"cell-wrap\">" +
                html_escape(a.detail) + "</td></tr>";
    }
    html += "</tbody></table></div></div>";
    return html;
}

// -- Policy fragments list -----------------------------------------------------

struct FragmentRow {
    std::string id;
    std::string name;
    std::string check_instruction;
    int64_t used_by{0};
    /// `used_by` hit the policy-list cap: shown as "N+".
    bool used_by_capped{false};
};

struct FragmentsView {
    std::vector<FragmentRow> fragments;
    std::size_t fragment_limit{100};
};

inline std::string render_fragments(const FragmentsView& v) {
    std::string html = "<div class=\"panel\"><div class=\"hd\"><h2>Policy fragments</h2>"
                       "<div class=\"acts\"><button class=\"btn btn-sm\" type=\"button\" "
                       "data-act=\"new-fragment\" data-perm=\"write\" data-needs-dialog hidden>"
                       "New fragment</button></div></div>";
    if (v.fragments.size() >= v.fragment_limit) {
        html += "<div class=\"pb\"><div class=\"note\">Showing the first " +
                std::to_string(v.fragment_limit) + " fragments.</div></div>";
    }
    if (v.fragments.empty()) {
        return html + "<div class=\"empty-state\">No policy fragments</div></div>";
    }
    html += "<div class=\"tw\"><table class=\"policy-table\"><thead><tr>"
            "<th>Fragment</th><th>Check</th><th>Used by</th><th></th></tr></thead><tbody>";
    for (const auto& f : v.fragments) {
        html += "<tr><td class=\"policy-name\">" + html_escape(f.name) +
                "</td><td class=\"mono-id\">" + html_escape(f.check_instruction) +
                "</td><td class=\"policy-count\">" + std::to_string(f.used_by) +
                (f.used_by_capped ? "+" : "") + " " + (f.used_by == 1 && !f.used_by_capped ? "policy" : "policies") +
                "</td><td>" +
                act_button("delete-fragment", "Delete", f.id, f.name,
                           (f.used_by > 0 || f.used_by_capped)
                               ? " data-perm=\"delete\" disabled title=\"In use by policies\""
                               : " data-perm=\"delete\"") +
                "</td></tr>";
    }
    html += "</tbody></table></div></div>";
    return html;
}

// -- Tag compliance -----------------------------------------------------------

struct TagRow {
    std::string key;
    std::string display_name;
    int64_t tagged{0};
    int64_t missing{0};
    std::vector<std::string> allowed_values; // empty = free-form
};

/// `total_agents == 0` omits the summary line (no fleet to summarise).
inline std::string render_tag_compliance(const std::vector<TagRow>& rows, std::size_t total_agents,
                                         std::size_t compliant_agents) {
    std::string html = "<div class=\"tw\"><table><thead><tr><th>Category</th><th>Display name</th>"
                       "<th>Agents tagged</th><th>Agents missing</th><th>Allowed values</th>"
                       "</tr></thead><tbody>";
    for (const auto& r : rows) {
        std::string vals;
        if (r.allowed_values.empty()) {
            vals = pill("idle", "Free-form");
        } else {
            for (std::size_t i = 0; i < r.allowed_values.size(); ++i) {
                if (i > 0)
                    vals += ", ";
                vals += html_escape(r.allowed_values[i]);
            }
        }
        html += "<tr><td><code>" + html_escape(r.key) + "</code></td><td>" +
                html_escape(r.display_name) + "</td><td>" + std::to_string(r.tagged) + "</td><td>" +
                pill(r.missing > 0 ? "bad" : "ok", std::to_string(r.missing)) + "</td><td>" + vals +
                "</td></tr>";
    }
    html += "</tbody></table></div>";
    if (total_agents > 0) {
        html += "<div class=\"pb\"><div class=\"note\">Compliance: " +
                std::to_string(compliant_agents) + "/" + std::to_string(total_agents) +
                " agents have all required tags</div></div>";
    }
    return html;
}

} // namespace yuzu::server::compliance_html
