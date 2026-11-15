/// @file dex_apps_ui.cpp
/// The DEX Apps tab: application stability per application and per version. PURE over
/// `DexAppsModel` (the model GET /api/v1/dex/apps serializes), so the page and the REST
/// payload read the same figures.
///
/// Product UI: HTMX, server-rendered, token-themed, htmx core attributes only (the CSP
/// blocks hx-on), zero JS. Versions and the score decomposition open with native
/// <details> and CSS :has(), so one page view is ONE read of the Apps model.
///
/// Honesty rules: every withheld or unknown state reads in words (never blank, never 0);
/// a figure that rounds to zero but is not zero prints "<0.1"; share and rate each name
/// the online-device population they were divided by; a degraded model prints NOTHING
/// derived from it. Every agent-reported or customer-authored string passes html_escape
/// before markup, and subjects pass url_query_value before an hx-get.

#include "dex_apps_ui.hpp"

#include "web_utils.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

// Defined in dex_routes.cpp; hand-declared here as in dex_app_perf_ui.cpp and dex_perf_ui.cpp.
std::string dex_window_token(int window_days);
std::string dex_subnav(const std::string& active, int window_days);

namespace {

std::string esc(const std::string& s) { return html_escape(s); }
std::string n(int64_t v) { return std::to_string(v); }

// One decimal. A positive figure that would read as zero prints "<0.1", never "0.0".
std::string fmt1(double x) {
    if (x > 0.0 && x < 0.1)
        return "&lt;0.1";
    return std::format("{:.1f}", x);
}

// Interval "(lo-hi unit)"; an unbounded upper end reads in words.
std::string interval_text(const DexInterval& i, double scale, const char* unit) {
    std::string t = "(" + fmt1(i.lower * scale) + "&ndash;";
    t += std::isfinite(i.upper) ? fmt1(i.upper * scale) + unit : std::string("no upper bound");
    return t + ")";
}

std::string estimate_text(const DexInterval& i, double scale, const char* unit) {
    return std::isfinite(i.estimate) ? fmt1(i.estimate * scale) + unit : std::string("no estimate");
}

const char* scope_label(std::string_view s) {
    if (s == kDexAppsScopeAll)
        return "all platforms";
    if (s == kDexAppsScopeWindows)
        return "Windows";
    if (s == kDexAppsScopeMacos)
        return "macOS";
    if (s == kDexAppsScopeLinux)
        return "Linux";
    return "";
}

const char* os_label(std::string_view s) {
    return s == kDexAppsScopeAll ? "" : scope_label(s);
}

std::string join_names(const std::vector<std::string>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i > 0)
            out += (i + 1 == v.size()) ? " and " : ", ";
        out += v[i];
    }
    return out;
}

// ── Apps-local CSS (tokens only). Kept here, not in kDexCss, so the other DEX goldens
// do not move. ──
const char* const kAppsCss = R"CSS(<style>
.gp-sub.dx-cl{max-width:none;margin-top:2px;font-size:13px}
.gp-sub:not(.dx-cl)+.gp-sub.dx-cl{margin-top:8px}
.gp-sub.dx-cl b{font-weight:600}
button.gp-chip{line-height:inherit;font-variant-numeric:inherit}
.gp-chip:focus-visible,.dx-vx>summary:focus-visible,summary.dx-sc:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.gp-filters .dx-lbl.sp{margin-left:14px}
.dx-fault{margin:0 0 12px}
.dx-tw{overflow-x:auto}
.gp-table.dx-apps{table-layout:fixed;min-width:1100px}
.dx-apps .nw{white-space:nowrap}
.dx-apps .c1{width:15.5%}.dx-apps .c2{width:16%}.dx-apps .c3{width:6.8%}.dx-apps .c4{width:6.2%}
.dx-apps .c5{width:9.5%}.dx-apps .c6{width:15.5%}.dx-apps .c7{width:19%}.dx-apps .c8{width:11.5%}
.gp-table.dx-apps th,.gp-table.dx-apps td{padding-left:12px;padding-right:12px;vertical-align:top}
.gp-table.dx-apps th{white-space:normal;line-height:1.3}
.gp-table.dx-apps th:first-child,.gp-table.dx-apps td:first-child{padding-left:16px}
.gp-table.dx-apps th:last-child,.gp-table.dx-apps td:last-child{padding-right:16px}
.gp-table.dx-apps td.dx-indent{padding-left:36px}
.gp-table.dx-apps td:first-child{overflow-wrap:anywhere}
.gp-table.dx-apps td:first-child>a{display:inline-block;margin-right:6px}
.gp-table.dx-apps tbody tr:last-child td{border-bottom:1px solid var(--line)}
.gp-table.dx-apps tbody:last-child tr:last-child td,.gp-table.dx-apps tbody:last-child:not(:has(.dx-vx[open])) .dx-apphead td{border-bottom:0}
.dx-apps .dx-ver{display:none}
.dx-apps tbody:has(.dx-vx[open]) .dx-ver{display:table-row}
.dx-apps tbody:has(.dx-vx[open]) .dx-apphead td{background:var(--surface2)}
.dx-vx{margin-top:2px}
.dx-vx>summary{width:max-content;color:var(--mut);font-size:12.5px;cursor:pointer;border-radius:3px}
.dx-vx>summary:hover{color:var(--ink)}
.dx-ver .dx-vn{font-family:var(--mds-font-family-mono);font-size:13px;color:var(--ink2)}
.dx-ver .dx-vn.unk{font-family:inherit;font-style:italic;color:var(--mut)}
.dx-ver td{font-size:13.5px}
.dx-ver td:first-child{color:var(--ink2)}
.dx-vcap td{color:var(--mut);font-size:12.5px}
.dx-fig .v{display:block}
.dx-fig .s{display:block;margin-top:2px;font-size:12.5px;color:var(--mut)}
.dx-fig .w{display:block;font-size:12.5px;color:var(--mut)}
.dx-fig .gp-derived{margin:4px 0 0}
.dx-sc{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 8px;border-radius:3px;font-size:12.5px;font-weight:600;white-space:nowrap;color:var(--mut);background:var(--surface2);border:1px solid var(--line)}
.dx-sc.excellent,.dx-sc.good{color:var(--ok);background:var(--mds-color-bg-success-tinted);border-color:transparent}
.dx-sc.fair{color:var(--warn);background:var(--mds-color-bg-warning-tinted);border-color:transparent}
.dx-sc.poor{color:var(--bad);background:var(--mds-color-bg-error-tinted);border-color:transparent}
summary.dx-sc{cursor:pointer;list-style:none}
summary.dx-sc::-webkit-details-marker{display:none}
summary.dx-sc::after{content:"";width:5px;height:5px;margin:-3px 0 0 2px;border:solid currentColor;border-width:0 1.5px 1.5px 0;transform:rotate(45deg);transition:transform .12s}
details[open]>summary.dx-sc::after{margin-top:3px;transform:rotate(-135deg)}
.dx-scw{display:block;margin-top:6px;font-size:12.5px;color:var(--mut)}
.dx-ded{margin-top:8px;padding:8px 10px;font-size:12.5px;color:var(--ink2);background:var(--surface2);border:1px solid var(--line);border-radius:var(--rad-ctl)}
.dx-ded .h{color:var(--mut);margin-bottom:2px}
.dx-ded .r{display:flex;flex-wrap:wrap;justify-content:space-between;gap:0 10px;padding:2px 0}
.dx-ded .r .p{font-variant-numeric:tabular-nums;color:var(--ink)}
.dx-ded .r.na,.dx-ded .r.na .p{color:var(--mut)}
.dx-ded .t{display:flex;flex-wrap:wrap;justify-content:space-between;gap:0 10px;margin-top:4px;padding-top:4px;border-top:1px solid var(--line);font-weight:600;color:var(--ink)}
@media (max-width:1000px){.gp-table.dx-apps{table-layout:auto;min-width:0}.gp-table.dx-apps th,.gp-table.dx-apps td{padding-left:9px;padding-right:9px}.gp-table.dx-apps th:first-child,.gp-table.dx-apps td:first-child{padding-left:12px;padding-right:6px;overflow-wrap:normal}.gp-table.dx-apps th:last-child,.gp-table.dx-apps td:last-child{padding-right:12px}.gp-table.dx-apps td.dx-indent{padding-left:14px}.dx-ver .dx-vn{font-size:12px;white-space:nowrap}.dx-sc{padding:0 6px}.dx-ded{padding:6px 8px}.dx-apps th{width:auto}}
</style>)CSS";

// ── page head ──

std::string chip(const char* label, bool on, const std::string& window, const std::string& platform) {
    // `window` and `platform` are literals from the two closed sets, never request text.
    return std::string("<button type=\"button\" class=\"gp-chip") + (on ? " on" : "") +
           "\" aria-pressed=\"" + (on ? "true" : "false") +
           "\" hx-get=\"/fragments/dex/apps?window=" + window + "&amp;platform=" + platform +
           "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</button>";
}

std::string filters(const std::string& window, const std::string& scope) {
    // A window chip keeps the current platform; with none recognised it falls back to all.
    const std::string keep = scope.empty() ? std::string(kDexAppsScopeAll) : scope;
    std::string h = "<div class=\"gp-filters\"><span class=\"dx-lbl\">Platform</span>";
    h += chip("All platforms", scope == kDexAppsScopeAll, window, kDexAppsScopeAll);
    h += chip("Windows", scope == kDexAppsScopeWindows, window, kDexAppsScopeWindows);
    h += chip("macOS", scope == kDexAppsScopeMacos, window, kDexAppsScopeMacos);
    h += chip("Linux", scope == kDexAppsScopeLinux, window, kDexAppsScopeLinux);
    h += "<span class=\"dx-lbl sp\">Window</span>";
    static const std::pair<const char*, const char*> kWindows[] = {
        {"24h", "24h"}, {"7d", "7d"}, {"30d", "30d"}, {"all", "All"}};
    for (const auto& [tok, label] : kWindows)
        h += chip(label, window == tok, tok, keep);
    return h + "</div>";
}

struct Coverage {
    std::string line;                  ///< the caption body
    std::vector<std::string> partial;  ///< platforms whose crash sources are partial
};

Coverage coverage(const std::string& scope) {
    std::vector<std::pair<std::string, std::vector<std::string>>> groups; // state -> platform names
    Coverage c;
    for (const auto& [os, state] : dex_apps_crash_source_coverage(scope)) {
        const std::string label = os_label(os);
        const std::string name = label.empty() ? esc(os) : label;
        auto it = groups.begin();
        for (; it != groups.end(); ++it)
            if (it->first == state)
                break;
        if (it == groups.end())
            it = groups.insert(groups.end(), {state, {}});
        it->second.push_back(name);
        if (state == "partial")
            c.partial.push_back(name);
    }
    for (const auto& [state, names] : groups) {
        if (!c.line.empty())
            c.line += "; ";
        c.line += join_names(names) + " " + esc(state);
    }
    if (scope == kDexAppsScopeLinux && !c.partial.empty())
        c.line = "Linux partial: it needs systemd-coredump as the active handler";
    // The table is the shipped design of the crash and hang sources, not live collector health.
    c.line += ". This is what the agent collects on each platform, not a live check of each device.";
    if (!c.partial.empty())
        c.line += scope == kDexAppsScopeAll
                      ? " An empty list on a partial platform is not proof of stability."
                      : " An empty list is not proof of stability.";
    return c;
}

std::string edge_text(double e) {
    return std::format("{:g}", e);
}

std::string captions(const DexAppsModel& m, const std::string& scope, const std::string& window) {
    const std::string basis = scope_label(scope);
    std::string h;
    if (!m.population)
        h += "<div class=\"gp-sub dx-cl\"><b>Population</b> unknown. No fleet source is connected, so "
             "shares, rates and scores cannot be calculated.</div>";
    else if (*m.population == 0)
        h += "<div class=\"gp-sub dx-cl\"><b>Population</b> 0 devices online now (" + basis +
             "). Shares, rates and scores need at least one online device.</div>";
    else
        h += "<div class=\"gp-sub dx-cl\"><b>Population</b> " + n(*m.population) + " device" +
             (*m.population == 1 ? "" : "s") + " online now (" + basis +
             "). Share and rate count online devices only.</div>";

    h += "<div class=\"gp-sub dx-cl\"><b>Crash and hang sources</b> " + coverage(scope).line + "</div>";

    const auto& pol = m.policy;
    const auto& t = pol.policy.tiers;
    std::string who;
    if (pol.source == "custom")
        who = "custom, revision <code class=\"dx-code\">" + esc(pol.revision) + "</code>";
    else if (!pol.fault.empty())
        who = "default (a stored policy was refused), revision <code class=\"dx-code\">" +
              esc(pol.revision) + "</code>";
    else
        who = "default, revision <code class=\"dx-code\">" + esc(pol.revision) + "</code>";
    h += "<div class=\"gp-sub dx-cl\"><b>Scoring policy</b> " + who + ". " + esc(t.names[0]) + " from " +
         edge_text(t.edges.excellent) + ", " + esc(t.names[1]) + " from " + edge_text(t.edges.good) +
         ", " + esc(t.names[2]) + " from " + edge_text(t.edges.fair) + ", " + esc(t.names[3]) +
         " below " + edge_text(t.edges.fair) + ". Intervals at " +
         std::format("{:g}", std::round(pol.policy.interval_confidence * 1000.0) / 10.0) +
         "% confidence. <a hx-get=\"/fragments/dex/scoring?window=" + window +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Change in Scoring</a></div>";
    return h;
}

std::string placeholder(const std::string& title_html, const std::string& body_html) {
    return "<div class=\"gp-placeholder\"><b>" + title_html + "</b>" + body_html + "</div>";
}

std::string error_panel(const std::string& reason, const std::string& window) {
    if (reason == "invalid_scope")
        return placeholder("Unknown platform",
                           "The platform filter must be one of all, windows, macos or linux, so no "
                           "figures are shown. Choose a platform above.");
    std::string body = "The read could not be completed, so no figures are shown. Try again in a moment";
    if (reason.empty()) {
        // A busy or unavailable store arrives with no reason token; a shorter window is then the one
        // lever, except at 24h, the shortest.
        if (window != "24h")
            body += "; a shorter window reads faster (30d and All are the slowest)";
        body += ". If it keeps failing, check PostgreSQL health.";
    } else
        body += ". If it keeps failing, check PostgreSQL health <span class=\"gp-mute\">(reason: <code "
                "class=\"dx-code\">" +
                esc(reason) + "</code>)</span>.";
    return placeholder("Application stability is unavailable", body);
}

// ── figure cells (one function per figure, shared by application and version rows) ──

struct RowCtx {
    std::optional<int64_t> population;
    const DexEffectivePolicy& eff;
};

bool is_floor(const DexStabilityFigures& f) {
    return std::string_view(f.score.withheld) == "below_floor";
}

std::string word_cell(const std::string& words) {
    return "<td class=\"gp-num dx-fig\"><span class=\"w\">" + words + "</span></td>";
}

std::string not_calculated(const DexStabilityFigures& f, const RowCtx& c) {
    if (is_floor(f))
        return "below the reporting floor: count only";
    if (!c.population)
        return "not calculated: population unknown";
    if (*c.population == 0)
        return "not calculated: no device online";
    return "not calculated: the counts disagree";
}

std::string count_cells(const DexStabilityFigures& f) {
    if (is_floor(f))
        return word_cell("withheld") + word_cell("withheld");
    return "<td class=\"gp-num\">" + n(f.crashes) + "</td><td class=\"gp-num\">" + n(f.hangs) + "</td>";
}

std::string devices_cell(const DexStabilityFigures& f) {
    std::string sub = is_floor(f)                  ? "count only"
                      : !f.distinct_devices_online ? "online count unknown"
                                                   : n(*f.distinct_devices_online) + " online";
    return "<td class=\"gp-num dx-fig\"><span class=\"v\">" + n(f.distinct_devices) +
           "</span><span class=\"s nw\">" + sub + "</span></td>";
}

// The small-count tags and the "Small counts" note below say "under 20"; dex.md repeats it.
static_assert(kDexStatsReliableMinEvents == 20,
              "the Apps page prose (share tag, rate tag, Small counts note) and dex.md say 'under 20'; "
              "update them with this constant");

std::string share_cell(const DexStabilityFigures& f, const RowCtx& c) {
    if (!f.share_affected || !c.population)
        return word_cell(not_calculated(f, c));
    const auto& i = *f.share_affected;
    // The small-count flag is judged on the share's numerator: affected ONLINE devices.
    std::string tag = i.reliable ? "" : "<span class=\"gp-derived\">under 20 affected online devices</span>";
    return "<td class=\"gp-num dx-fig\"><span class=\"v\">" + estimate_text(i, 100.0, "%") +
           " <span class=\"gp-mute nw\">" + interval_text(i, 100.0, "%") + "</span></span><span class=\"s\">" +
           n(f.distinct_devices_online.value_or(0)) + " of " + n(*c.population) + " online</span>" + tag +
           "</td>";
}

std::string rate_cell(const DexStabilityFigures& f, const RowCtx& c) {
    if (!f.rate_per_1000 || !c.population)
        return word_cell(not_calculated(f, c));
    const auto& i = *f.rate_per_1000;
    // The rate's flag is judged on online EVENTS, not devices.
    std::string tag = i.reliable ? "" : "<span class=\"gp-derived\">under 20 online events</span>";
    return "<td class=\"gp-num dx-fig\"><span class=\"v\">" + estimate_text(i, 1.0, "") +
           " <span class=\"gp-mute nw\">" + interval_text(i, 1.0, "") + "</span></span><span class=\"s\">per 1,000 of " +
           n(*c.population) + " online device" + (*c.population == 1 ? "" : "s") + "</span>" + tag + "</td>";
}

const char* deduction_label(const std::string& name) {
    if (name == "breadth")
        return "Breadth (share)";
    if (name == "crashes")
        return "Crashes";
    if (name == "hangs")
        return "Hangs";
    if (name == "regression")
        return "Regression";
    return nullptr;
}

std::string withheld_words(const DexStabilityFigures& f, const RowCtx& c) {
    const std::string w = f.score.withheld;
    if (w == "no_population")
        return c.population ? "No device is online to measure against."
                            : "Population unknown, so there is nothing to measure against.";
    if (w == "offline_affected") {
        const int64_t online = f.distinct_devices_online.value_or(0);
        return n(f.distinct_devices - online) + " of " + n(f.distinct_devices) + " affected device" +
               (f.distinct_devices == 1 ? "" : "s") + (f.distinct_devices - online == 1 ? " is" : " are") +
               " offline, so no score is given.";
    }
    if (w == "below_floor")
        return "Below the reporting floor: count only.";
    if (w == "inconsistent")
        return "The counts disagree, so no score is given.";
    if (w == "invalid_weights" || w == "invalid_edges" || w == "invalid_model")
        return "The score policy is faulty, so no score is given.";
    if (w.empty())
        return "No score is given.";
    return "No score is given (reason: <code class=\"dx-code\">" + esc(w) + "</code>).";
}

std::string score_cell(const DexStabilityFigures& f, const RowCtx& c) {
    const auto& s = f.score;
    if (!s.score || !s.band)
        return "<td><span class=\"dx-sc\">Withheld</span><span class=\"dx-scw\">" + withheld_words(f, c) +
               "</span></td>";
    const double shown = stability_display_score(*s.score);
    // The tone follows the closed band token; the label is the policy's own tier name.
    const std::string tier = esc(dex_tier_name(c.eff.tiers, *s.band));
    std::string ded = "<div class=\"dx-ded\"><div class=\"h\">Starts at 100, minus:</div>";
    for (const auto& d : s.deductions) {
        const char* known = deduction_label(d.name);
        const std::string label = known ? std::string(known) : esc(d.name);
        if (d.assessed)
            ded += "<div class=\"r\"><span>" + label + "</span><span class=\"p\">&minus;" +
                   std::format("{:.2f}", d.points) + "</span></div>";
        else
            ded += "<div class=\"r na\"><span>" + label + "</span><span class=\"p\">not assessed</span></div>";
    }
    ded += "<div class=\"t\"><span>Score</span><span>" + std::format("{:.1f}", shown) + "</span></div></div>";
    return std::string("<td><details class=\"dx-score\"><summary class=\"dx-sc ") +
           stability_band_label(*s.band) + "\">" + tier + " " + std::format("{:.1f}", shown) + "</summary>" +
           ded + "</details></td>";
}

// "Last seen": the date and the time sit in separate no-wrap spans, so a narrow column breaks
// between them and never inside the date. Each part is a literal substring of the REST value.
std::string last_seen_text(const std::string& ts) {
    if (ts.empty())
        return "unknown";
    const auto t = ts.find('T');
    if (t == std::string::npos)
        return "<span class=\"nw\">" + esc(ts) + "</span>";
    return "<span class=\"nw\">" + esc(ts.substr(0, t)) + "</span> <span class=\"nw\">" +
           esc(ts.substr(t + 1)) + "</span>";
}

std::string figure_cells(const DexStabilityFigures& f, const RowCtx& c) {
    return score_cell(f, c) + count_cells(f) + devices_cell(f) + share_cell(f, c) + rate_cell(f, c) +
           "<td class=\"gp-mute\">" + (is_floor(f) ? std::string("withheld") : last_seen_text(f.last_seen)) +
           "</td>";
}

std::string app_body(const DexAppStability& a, const DexAppsModel& m, const std::string& window) {
    // Named local: the rvalue overloads of dex_tier_name are deleted on purpose.
    const DexEffectivePolicy eff = resolve_dex_score_policy(m.policy.policy, a.subject);
    const RowCtx ctx{m.population, eff};

    const std::string label =
        a.subject.empty()
            ? std::string("&lt;unknown&gt;")
            : "<a hx-get=\"/fragments/dex/app?name=" + url_query_value(a.subject) + "&amp;window=" + window +
                  "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" +
                  esc(a.subject) + "</a>";
    std::string first = label;
    if (a.profile == DexPolicyProfile::Override)
        first += " <span class=\"dx-tag\">override</span>";
    if (a.version_count == 0)
        first += " <span class=\"gp-mute\">version not collected</span>";
    else
        first += "<details class=\"dx-vx\"><summary>" + n(a.version_count) + " version" +
                 (a.version_count == 1 ? "" : "s") + "</summary></details>";

    std::string out = "<tbody class=\"dx-app\"><tr class=\"dx-apphead\"><td>" + first + "</td>" +
                      figure_cells(a.figures, ctx) + "</tr>";
    for (const auto& v : a.versions) {
        const std::string vn = v.version.empty() ? "<span class=\"dx-vn unk\">unknown version</span>"
                                                 : "<span class=\"dx-vn\">" + esc(v.version) + "</span>";
        out += "<tr class=\"dx-ver\"><td class=\"dx-indent\">" + vn + "</td>" + figure_cells(v.figures, ctx) +
               "</tr>";
    }
    if (a.versions_truncated) {
        const int64_t shown = static_cast<int64_t>(a.versions.size());
        const int64_t cut = a.version_count - shown;
        out += "<tr class=\"dx-ver dx-vcap\"><td colspan=\"8\">Showing the " + n(shown) + " version" +
               (shown == 1 ? "" : "s") + " with the most devices affected; " + n(cut) + " more version" +
               (cut == 1 ? " has" : "s have") + " crashes or hangs in this window and " +
               (cut == 1 ? "is" : "are") + " not listed.</td></tr>";
    }
    return out + "</tbody>";
}

const char* const kThead =
    "<thead><tr><th class=\"c1\">Application</th><th class=\"c2\">Score</th>"
    "<th class=\"gp-num c3\">Crashes</th><th class=\"gp-num c4\">Hangs</th>"
    "<th class=\"gp-num c5\">Devices affected</th><th class=\"gp-num c6\">Share affected</th>"
    "<th class=\"gp-num c7\">Rate per 1,000</th><th class=\"c8\">Last seen</th></tr></thead>";

std::string notes(const DexAppsModel& m, const std::string& scope) {
    std::string h;
    if (m.apps_truncated) {
        const int64_t shown = static_cast<int64_t>(m.apps.size());
        const int64_t cut = m.apps_total - shown;
        h += "<div class=\"gp-note\">Showing " + n(shown) + " of " + n(m.apps_total) +
             " applications: the " + n(shown) +
             " with the most devices affected, listed by crashes plus hangs. " + n(cut) +
             (cut == 1 ? " is" : " are") + " not listed.</div>";
    }
    h += "<div class=\"gp-note\"><b>Window-wide figures:</b> crashes, hangs, devices affected and last seen "
         "cover every device in the window, online or not. Share, rate and score count online devices only, "
         "so they can differ from those figures. Share affected is affected online devices out of all "
         "online devices; rate per 1,000 is crash and hang events on online devices per 1,000 online "
         "devices.</div>";
    // With no usable population no share or rate is drawn, so there is nothing to tag.
    if (m.population && *m.population > 0)
        h += "<div class=\"gp-note\"><b>Small counts:</b> a figure on fewer than 20 affected online devices, "
             "or fewer than 20 online events, carries a tag. It is still shown; the interval says how uncertain it "
             "is.</div>";
    if (scope != kDexAppsScopeAll)
        h += "<div class=\"gp-note\">The application drill-down covers every platform.</div>";
    return h;
}

std::string empty_panel(const std::string& scope) {
    const std::string where = scope == kDexAppsScopeAll ? "" : std::string(" for ") + scope_label(scope);
    std::string body = std::string("No application crashes or hangs were recorded ") +
                       (scope == kDexAppsScopeAll ? "" : std::string("on ") + scope_label(scope) + " devices ") +
                       "in this window.";
    const auto partial = coverage(scope).partial;
    if (!partial.empty())
        body += " Crash sources on " + join_names(partial) +
                " are partial, so an empty list is not proof that applications are stable.";
    return placeholder("Nothing recorded" + where, body);
}

} // namespace

std::string render_dex_apps_fragment(const DexAppsModel& model, int window_days,
                                     const std::string& platform) {
    const std::string window = dex_window_token(window_days);
    const std::string scope = dex_normalize_apps_scope(platform);
    // An unrecognised platform is an error even when the caller handed in a healthy model.
    const bool failed = model.degraded || scope.empty();
    const std::string reason = scope.empty() ? std::string("invalid_scope") : model.degraded_reason;

    std::string h = "<a class=\"gp-back\" href=\"/\">&larr; Console</a>";
    h += dex_subnav("apps", window_days);
    h += kAppsCss;
    h += "<div id=\"dex-apps\"><div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Applications</h1></div>"
         "<div class=\"gp-sub\">Stability per application across the fleet &mdash; crashes &amp; hangs, "
         "keyed on the process image.</div>";
    // A degraded model carries a default policy and no population: print nothing derived from it.
    if (!failed)
        h += captions(model, scope, window);
    h += "</div></div>";
    h += filters(window, scope);

    if (failed)
        return h + error_panel(reason, window) + "</div>";

    if (!model.policy.fault.empty())
        h += "<div class=\"note warn dx-fault\"><b>The stored policy was refused.</b> The shipped defaults "
             "are in force until a valid policy is saved. Reason: <code class=\"dx-code\">" +
             esc(model.policy.fault) + "</code></div>";

    if (model.apps.empty())
        return h + empty_panel(scope) + "</div>";

    h += "<div class=\"dx-tw\"><table class=\"gp-table dx-apps\">";
    h += kThead;
    // ponytail: every version is pre-rendered (up to 100 applications x 20 versions) so one page view
    // is one read; the upgrade path is a lazy per-application versions resource, API first.
    for (const auto& a : model.apps)
        h += app_body(a, model, window);
    h += "</table></div>";
    h += notes(model, scope);
    return h + "</div>";
}

} // namespace yuzu::server
