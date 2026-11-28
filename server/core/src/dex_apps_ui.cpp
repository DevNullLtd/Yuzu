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
/// derived from it, and its panel says WHICH cause (the model's `degraded_reason`) so the one
/// lever that helps is named. Every agent-reported or customer-authored string passes html_escape
/// before markup (printed names also mark bidirectional-control and zero-width characters as
/// visible text), and subjects pass url_query_value before an hx-get.
///
/// The Usage view (`render_dex_apps_usage_fragment`, `render_dex_apps_usage_refusal`) is the
/// second view of the tab, PURE over `DexAppsUsageModel` (the model GET /api/v1/dex/apps/usage
/// serializes). It keeps the same honesty rules and adds its own: every device count is printed
/// beside the reporting population it is read against (an application row and a cell row alike);
/// a withheld, estimated or ambiguous figure reads in words and never as a number; the rate is
/// printed per hour of use, from the same figure the payload carries and rounded to about four
/// significant digits so a small value never collapses to "<0.1"; and a refusal prints the chrome
/// and the controls and nothing derived from a model. The Stability page gains only the View
/// chips and, for a caller who may not read usage, one line of words; with
/// `DexAppsUsageEntry::Hidden` it is unchanged.

#include "dex_apps_ui.hpp"

#include "dex_pane.hpp"
#include "plural.hpp"
#include "web_utils.hpp"

#include <algorithm>
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
// Printed text of an agent-reported name: control characters shown as markers. Never inside a tag.
std::string esc_text(const std::string& s) { return html_escape_marked(s); }
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
.dx-vx>summary:focus-visible,summary.dx-sc:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
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
.gp-table.dx-apps td:first-child>:is(a,.dx-lk){display:inline-block;margin-right:6px}
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
    return dex_pane_chip("/fragments/dex/apps?window=" + window + "&amp;platform=" + platform, label, on);
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

// "Observers now: Windows 3 armed, 0 not armed, 1 not reporting; macOS ...". Counts only.
std::string observer_text(const std::vector<DexObserverSplit>& split, bool& any_quiet) {
    std::string t = "Observers now: ";
    bool first = true;
    for (const auto& o : split) {
        const std::string label = o.platform == "other" ? std::string("Other platforms")
                                                        : std::string(os_label(o.platform));
        if (!first)
            t += "; ";
        first = false;
        t += (label.empty() ? esc(o.platform) : label) + " " + n(o.armed) + " armed, " + n(o.disarmed) +
             " not armed, " + n(o.none_reported) + " not reporting";
        any_quiet = any_quiet || o.disarmed > 0 || o.none_reported > 0;
    }
    return t + ".";
}

Coverage coverage(const std::string& scope,
                  const std::optional<std::vector<DexObserverSplit>>& observers = std::nullopt) {
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
    // The table is the shipped design of the crash and hang sources, not live collector health;
    // the observer counts, when a source is wired, are the live half.
    if (observers) {
        bool any_quiet = false;
        c.line += ". Complete and partial describe what the agent collects on each platform by design. " +
                  observer_text(*observers, any_quiet);
        // "&#39;" is what html_escape writes for an apostrophe; this sentence is emitted unescaped.
        c.line += " Armed means the device&#39;s observer is running with at least one source; it does "
                  "not confirm that every crash source on the device is readable.";
        if (any_quiet)
            c.line += " A device that is not armed or not reporting may not be sending all of its crash "
                      "and hang signals (collection can be incomplete or unavailable), so a quiet list "
                      "does not cover it.";
    } else {
        c.line += ". This is what the agent collects on each platform, not a live check of each device.";
    }
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
        h += "<div class=\"gp-sub dx-cl\"><b>Population</b> " +
             plural_count(*m.population, "device", "devices") + " online now (" + basis +
             "). Share and rate count online devices only.</div>";

    h += "<div class=\"gp-sub dx-cl\"><b>Crash and hang sources</b> " + coverage(scope, m.observer_state).line +
         "</div>";

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
         "% confidence. " + dex_pane_link("/fragments/dex/scoring?window=" + window, "Change in Scoring") +
         "</div>";
    return h;
}

std::string placeholder(const std::string& title_html, const std::string& body_html) {
    return "<div class=\"gp-placeholder\"><b>" + title_html + "</b>" + body_html + "</div>";
}

// The token as a code element, for any panel that names its cause.
std::string reason_note(const std::string& reason) {
    return " <span class=\"gp-mute\">(reason: <code class=\"dx-code\">" + esc(reason) + "</code>)</span>";
}

// One panel per cause. The model's `degraded_reason` is the store's metric label (budget, pool,
// statement timeout, query error, store not open) or one of the page's own tokens, so the text names
// the lever that helps: wait, a shorter window, the policy, or the database.
std::string error_panel(const std::string& reason, const std::string& window) {
    if (reason == "invalid_scope")
        return placeholder("Unknown platform",
                           "The platform filter must be one of all, windows, macos or linux, so no "
                           "figures are shown. Choose a platform above.");
    if (reason == "concurrency_budget" || reason == "pool_acquire_timeout")
        return placeholder("Application stability is busy",
                           "The server is running as many of these reads as it allows, so no figures are "
                           "shown. Try again in a moment." + reason_note(reason));
    if (reason == "statement_timeout")
        return placeholder("Application stability is unavailable",
                           std::string("The read took too long for this window, so no figures are shown. ") +
                               (window == "24h" ? "This is already the shortest window; check PostgreSQL health."
                                                : "Choose a shorter window (30d and All are the slowest).") +
                               reason_note(reason));
    if (reason == "score_policy_unavailable" || reason == "score_policy_invalid")
        return placeholder("Application stability is unavailable",
                           "The stored score policy could not be used, so no figures are shown. Check it in "
                           "Scoring." + reason_note(reason));
    if (reason == "store_not_open" || reason == "query_error")
        return placeholder("Application stability is unavailable",
                           "The database read failed, so no figures are shown. Check PostgreSQL health." +
                               reason_note(reason));
    std::string body = "The read could not be completed, so no figures are shown. Try again in a moment";
    if (reason.empty()) {
        // No cause known; a shorter window is then the one lever, except at 24h, the shortest.
        if (window != "24h")
            body += "; a shorter window reads faster (30d and All are the slowest)";
        body += ". If it keeps failing, check PostgreSQL health.";
    } else
        body += ". If it keeps failing, check PostgreSQL health" + reason_note(reason) + ".";
    return placeholder("Application stability is unavailable", body);
}

// ── figure cells (one function per figure, shared by application and version rows) ──

struct RowCtx {
    std::optional<int64_t> population;
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
              "the Apps page prose (share tag, rate tag, Small counts note, and the Usage view's "
              "'under 20 events' rate tag) and dex.md say 'under 20'; update them with this constant");

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
           plural_count(*c.population, "online device", "online devices") + "</span>" + tag + "</td>";
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
        return n(f.distinct_devices - online) + " of " +
               plural_count(f.distinct_devices, "affected device", "affected devices") +
               plural_word(f.distinct_devices - online, " is", " are") + " offline, so no score is given.";
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
    // The tone follows the closed band token; the label is the policy's own tier name, resolved once
    // by the model (the same value the payload carries).
    const std::string tier = esc(f.tier);
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
    const RowCtx ctx{m.population};

    const std::string label =
        a.subject.empty()
            ? std::string("&lt;unknown&gt;")
            : dex_pane_link("/fragments/dex/app?name=" + url_query_value(a.subject) + "&amp;window=" + window,
                            esc_text(a.subject));
    std::string first = label;
    if (a.profile == DexPolicyProfile::Override)
        first += " <span class=\"dx-tag\">override</span>";
    if (a.version_count == 0)
        first += " <span class=\"gp-mute\">version not collected</span>";
    else
        // The sentence inside the details is visually hidden: collapsed it is not rendered, expanded
        // the region is never empty to assistive technology (the rows follow in the table).
        first += "<details class=\"dx-vx\"><summary>" +
                 plural_count(a.version_count, "version", "versions") +
                 "</summary><span class=\"vh\">The version rows follow this row in the table.</span></details>";

    std::string out = "<tbody class=\"dx-app\"><tr class=\"dx-apphead\"><td>" + first + "</td>" +
                      figure_cells(a.figures, ctx) + "</tr>";
    for (const auto& v : a.versions) {
        const std::string vn = v.version.empty() ? "<span class=\"dx-vn unk\">unknown version</span>"
                                                 : "<span class=\"dx-vn\">" + esc_text(v.version) + "</span>";
        out += "<tr class=\"dx-ver\"><td class=\"dx-indent\">" + vn + "</td>" + figure_cells(v.figures, ctx) +
               "</tr>";
    }
    if (a.versions_truncated) {
        const int64_t shown = static_cast<int64_t>(a.versions.size());
        const int64_t cut = a.version_count - shown;
        out += "<tr class=\"dx-ver dx-vcap\"><td colspan=\"8\">Showing the " +
               plural_count(shown, "version", "versions") + " with the most devices affected; " +
               plural_count(cut, "more version has", "more versions have") +
               " crashes or hangs in this window and " + plural_word(cut, "is", "are") +
               " not listed.</td></tr>";
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
             plural_word(cut, " is", " are") + " not listed.</div>";
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

// ── The Usage view ───────────────────────────────────────────────────────────
//
// Pure over `DexAppsUsageModel`. The chips and controls come from `DexAppsUsageControls` (the
// request), never from the model, so a refusal draws the same chrome. Emitted by the usage
// renderers only: nothing below is reached from `render_dex_apps_fragment` except `view_chips`.

// Tokens only. The five column widths, the narrow tag-key box (kDexCss gives .dx-ctl a 220px
// minimum) and the "none defined" word beside the group list.
const char* const kAppsUsageCss = R"CSS(<style>
.dx-usage .u1{width:24%}.dx-usage .u2{width:15%}.dx-usage .u3{width:15%}.dx-usage .u4{width:13%}.dx-usage .u5{width:33%}
.gp-filters .dx-ctl.dx-key{width:14ch;min-width:0}
.gp-filters .dx-none{align-self:center;color:var(--mut);font-size:12.5px}
</style>)CSS";

// "View: Stability | Usage". `platform` is a canonical scope token (never request text) and
// `usage_on` says which chip is lit.
std::string view_chips(const std::string& window, const std::string& platform, bool usage_on) {
    const std::string qs = "window=" + window + "&amp;platform=" + platform;
    return "<div class=\"gp-filters\"><span class=\"dx-lbl\">View</span>" +
           dex_pane_chip("/fragments/dex/apps?" + qs, "Stability", !usage_on) +
           dex_pane_chip("/fragments/dex/apps/usage?" + qs, "Usage", usage_on) + "</div>";
}

// A control's request carries every OTHER current parameter and never its own: htmx appends the
// control's own name=value to a GET and the handler reads the first value of a repeated
// parameter, so a URL that already carried the key would pin the old one.
std::string usage_base_url(const std::string& window, const std::string& platform,
                           const std::string& slice_name) {
    return "/fragments/dex/apps/usage?window=" + window + "&amp;platform=" + platform +
           "&amp;slice=" + slice_name;
}

// The full request for a chip: the base plus the slice's own key.
std::string usage_url(const std::string& window, const std::string& platform,
                      const DexUsageSlice& slice) {
    std::string u = usage_base_url(window, platform, dex_usage_slice_token(slice.kind));
    if (slice.kind == DexUsageSliceKind::Group && !slice.key.empty())
        u += "&amp;group=" + url_query_value(slice.key);
    if (slice.kind == DexUsageSliceKind::Tag)
        u += "&amp;tag_key=" +
             url_query_value(slice.key.empty() ? std::string(kDexDefaultCohortKey) : slice.key);
    return u;
}

// A management group's name for printing (escaped), or its id when the list does not hold it.
std::string group_name_text(const DexAppsUsageControls& c, const std::string& id) {
    for (const auto& g : c.groups)
        if (g.id == id)
            return esc_text(g.name);
    return esc_text(id);
}

std::string usage_filters(const DexAppsUsageControls& c, const std::string& window,
                          const std::string& keep) {
    std::string h = "<div class=\"gp-filters\"><span class=\"dx-lbl\">Platform</span>";
    static const std::pair<const char*, const char*> kPlatforms[] = {{"all", "All platforms"},
                                                                     {"windows", "Windows"},
                                                                     {"macos", "macOS"},
                                                                     {"linux", "Linux"}};
    for (const auto& [tok, label] : kPlatforms)
        h += dex_pane_chip(usage_url(window, tok, c.slice), label, c.platform == tok);
    h += "<span class=\"dx-lbl sp\">Window</span>";
    static const std::pair<const char*, const char*> kWindows[] = {
        {"24h", "24h"}, {"7d", "7d"}, {"30d", "30d"}, {"all", "All"}};
    for (const auto& [tok, label] : kWindows)
        h += dex_pane_chip(usage_url(tok, keep, c.slice), label, window == tok);
    return h + "</div>";
}

std::string slice_controls(const DexAppsUsageControls& c, const std::string& window,
                           const std::string& keep) {
    const DexUsageSlice& cur = c.slice;
    const std::string tag_key = (cur.kind == DexUsageSliceKind::Tag && !cur.key.empty())
                                    ? cur.key
                                    : std::string(kDexDefaultCohortKey);
    std::string h = "<div class=\"gp-filters\"><span class=\"dx-lbl\">Slice</span>";
    h += dex_pane_chip(usage_url(window, keep, DexUsageSlice{DexUsageSliceKind::Fleet, ""}), "Whole fleet",
                       cur.kind == DexUsageSliceKind::Fleet);
    h += dex_pane_chip(usage_url(window, keep, DexUsageSlice{DexUsageSliceKind::Platform, ""}),
                       "By platform", cur.kind == DexUsageSliceKind::Platform);
    h += dex_pane_chip(usage_url(window, keep, DexUsageSlice{DexUsageSliceKind::Tag, tag_key}), "By tag",
                       cur.kind == DexUsageSliceKind::Tag);
    // The tag-key box: its URL names the slice but never tag_key, which htmx appends.
    h += "<input class=\"dx-ctl dx-key\" name=\"tag_key\" aria-label=\"Tag key\" value=\"" + esc(tag_key) +
         "\" hx-get=\"" + usage_base_url(window, keep, "tag") + "\" hx-trigger=\"change\"";
    h += kDexPaneSwapAttrs;
    h += ">";
    h += "<span class=\"dx-lbl sp\">Management group</span>";
    if (c.groups.empty())
        return h + "<span class=\"dx-none\">none defined</span></div>";
    // The group select: its URL names the slice but never group, which htmx appends.
    h += "<select class=\"dx-ctl\" name=\"group\" aria-label=\"Management group\" hx-get=\"" +
         usage_base_url(window, keep, "group") + "\" hx-trigger=\"change\"";
    h += kDexPaneSwapAttrs;
    h += ">";
    h += std::string("<option value=\"\" disabled") +
         (cur.kind == DexUsageSliceKind::Group ? "" : " selected") + ">Choose a group</option>";
    for (const auto& g : c.groups)
        h += "<option value=\"" + esc(g.id) + "\"" +
             ((cur.kind == DexUsageSliceKind::Group && cur.key == g.id) ? " selected" : "") + ">" +
             esc_text(g.name) + "</option>";
    return h + "</select></div>";
}

// Page head: back link, sub-navigation, the two stylesheets, the title, the captions (model only;
// empty for a refusal), then the View chips, the platform and window chips and the Slice row.
std::string usage_head(const DexAppsUsageControls& c, const std::string& window, const std::string& keep,
                       const std::string& captions) {
    std::string h = "<a class=\"gp-back\" href=\"/\">&larr; Console</a>";
    h += dex_subnav("apps", c.window_days);
    h += kAppsCss;
    h += kAppsUsageCss;
    h += "<div id=\"dex-apps\"><div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Applications</h1></div>"
         "<div class=\"gp-sub\">Usage per application across the fleet &mdash; devices, run time and "
         "launches over the last 30 days, and crashes &amp; hangs per hour of use.</div>" +
         captions + "</div></div>";
    h += view_chips(window, keep, true);
    h += usage_filters(c, window, keep);
    h += slice_controls(c, window, keep);
    return h;
}

// ── captions (model only) ──

constexpr std::int64_t kUsageFreshHours = kDexUsageFreshSecs / 3600;

std::string usage_captions(const DexAppsUsageControls& c, const DexAppsUsageModel& m,
                           const std::string& window) {
    const std::string basis = scope_label(m.platform_scope);
    std::string h = "<div class=\"gp-sub dx-cl\"><b>Population</b> ";
    if (m.population == 0) {
        h += "0 devices online now (" + basis + "). Usage needs at least one online device.";
    } else {
        h += plural_count(m.population, "device", "devices") + " online now (" + basis + "). " +
             n(m.reporting_devices) + " reported usage in the last " + n(kUsageFreshHours) +
             " hours and " + plural_word(m.reporting_devices, "is", "are") + " counted; " +
             n(m.stale_devices) + " last reported earlier and " + plural_word(m.stale_devices, "is", "are") +
             " not counted";
        const std::int64_t never = m.population - m.reporting_devices - m.stale_devices;
        if (never >= 0)
            h += "; " + n(never) + plural_word(never, " has", " have") + " never reported usage";
        h += ".";
    }
    h += "</div>";

    h += "<div class=\"gp-sub dx-cl\"><b>Basis</b> Estimated from 30-day usage: run time and launches are "
         "each device&#39;s trailing 30-day totals from its last daily report";
    if (window == "all")
        h += ". The All window has no length, so no rate is calculated; choose 24h, 7d or 30d for a rate";
    else
        h += ", and the rate scales run time to the " + window + " window";
    h += ". Read at " + last_seen_text(dex_iso_at(m.as_of_epoch)) +
         "; an answer is reused for up to 30 seconds.</div>";

    h += "<div class=\"gp-sub dx-cl\"><b>Reporting floor</b> " + plural_count(m.floor, "device", "devices") +
         ", per table. A figure from fewer devices is withheld. The floor guards one table only: "
         "comparing two slices or two windows can still single out a small group.</div>";

    if (m.slice.kind != DexUsageSliceKind::Fleet) {
        std::string what;
        if (m.slice.kind == DexUsageSliceKind::Platform)
            what = "by platform";
        else if (m.slice.kind == DexUsageSliceKind::Group)
            what = "by management group " + group_name_text(c, m.slice.key);
        else
            what = "by tag <code class=\"dx-code\">" + esc(m.slice.key) + "</code>";
        h += "<div class=\"gp-sub dx-cl\"><b>Slice</b> " + what +
             ". Each application&#39;s devices, run time and launches are also split into cells; open its "
             "cells to read them. A cell&#39;s device count is read against all " + n(m.reporting_devices) +
             " reporting devices, not against the cell&#39;s own size, which this read does not return.</div>";
    }
    return h;
}

// ── figures ──

// The rate printed from the figure the payload carries: per hour of use, rounded to about four
// significant digits, so a small value never collapses to "<0.1". Zero prints "0"; the caller
// handles a non-finite value.
std::string fmt_rate(double x) {
    if (!(x > 0.0))
        return "0";
    if (x < 1e-9)
        return "&lt;0.000000001";
    const int magnitude = static_cast<int>(std::floor(std::log10(x)));
    const int decimals = std::max(0, 3 - magnitude);
    return std::format("{:.{}f}", x, decimals);
}

std::string rate_bound(double x, const char* when_missing) {
    return std::isfinite(x) ? fmt_rate(x) : std::string(when_missing);
}

std::string rate_withheld_words(const DexAppUsage& a, const DexAppsUsageModel& m) {
    const std::string& w = a.rate_withheld;
    if (w == "ambiguous_name")
        return "withheld: the name is shared";
    if (w == "no_usage")
        return m.reporting_devices == 0 ? "not calculated: no device has reported usage"
                                        : "not calculated: no usage reported";
    if (w == "below_floor")
        return "not calculated: below the reporting floor";
    if (w == "unbounded_window")
        return "not calculated: the All window has no length";
    if (w == "window_exceeds_retention")
        return "not calculated: the window is longer than the crash and hang history kept";
    if (w == "zero_usage")
        return "not calculated: no run time recorded";
    if (w == "no_statistic")
        return "not calculated: no statistic for these counts";
    if (w.empty())
        return "not calculated";
    return "not calculated (reason: <code class=\"dx-code\">" + esc(w) + "</code>)";
}

std::string usage_rate_cell(const DexAppUsage& a, const DexAppsUsageModel& m, const std::string& window) {
    if (!a.rate)
        return word_cell(rate_withheld_words(a, m));
    const DexExposureRate& r = *a.rate;
    const DexInterval& i = r.per_hour;
    const std::string est = rate_bound(i.estimate, "no estimate");
    const std::string band = "(" + rate_bound(i.lower, "no lower bound") + "&ndash;" +
                             rate_bound(i.upper, "no upper bound") + ")";
    // The estimated tag is keyed on the basis token the payload carries; any other basis prints
    // the token itself, escaped.
    const std::string basis_tag =
        std::string_view(r.basis) == std::string_view(kDexUsageBasis)
            ? std::string("estimated from 30-day usage")
            : esc(std::string(r.basis));
    return "<td class=\"gp-num dx-fig\"><span class=\"v\">" + est + " <span class=\"gp-mute nw\">" + band +
           "</span></span><span class=\"s\">" + plural_count(r.crashes, "crash", "crashes") + " + " +
           plural_count(r.hangs, "hang", "hangs") + " over " + fmt1(r.hours) + " h in " + window +
           "</span><span class=\"gp-derived\">" + basis_tag + "</span>" +
           (i.reliable ? std::string() : std::string(" <span class=\"gp-derived\">under 20 events</span>")) +
           "</td>";
}

// "of R reporting": the population every device count is read against.
std::string of_reporting(const DexAppsUsageModel& m, const char* prefix) {
    return std::string("<span class=\"s nw\">") + prefix + n(m.reporting_devices) + " reporting</span>";
}

std::string hours_cell(std::int64_t run_seconds) {
    return "<td class=\"gp-num dx-fig\"><span class=\"v\">" + fmt1(static_cast<double>(run_seconds) / 3600.0) +
           " h</span><span class=\"s nw\">process-hours</span></td>";
}

std::string cell_label(const DexAppsUsageControls& c, const DexAppsUsageModel& m, const DexUsageCell& cell) {
    if (cell.kind == DexUsageCellKind::Untagged)
        return "Devices with no value for this tag";
    if (cell.kind == DexUsageCellKind::Other) {
        // The residual is named for what the model puts in it for this slice
        // (dex_usage_model.hpp, dex_usage_assign_cells). Cells are merged into it only above floor 1.
        std::string t;
        if (m.slice.kind == DexUsageSliceKind::Group)
            t = "Devices outside the group";
        else if (m.slice.kind == DexUsageSliceKind::Platform)
            t = "Devices on a platform other than Windows, Linux or macOS";
        else if (m.slice.kind == DexUsageSliceKind::Tag)
            t = "Devices whose value is not among the " + n(kDexUsageCellCap) + " most common";
        else
            t = "Other devices";
        if (m.floor > 1)
            t += ", plus cells merged in so that no row is below the reporting floor";
        return t;
    }
    // Only a Named cell prints its label, so a tag value of "other" or "(untagged)" prints as that
    // literal value.
    if (m.slice.kind == DexUsageSliceKind::Platform) {
        const std::string known = scope_label(cell.label);
        return known.empty() ? esc_text(cell.label) : known;
    }
    if (m.slice.kind == DexUsageSliceKind::Group)
        return group_name_text(c, cell.label);
    if (m.slice.kind == DexUsageSliceKind::Fleet)
        return "Whole fleet";
    return esc_text(cell.label);
}

std::string usage_app_body(const DexAppsUsageControls& c, const DexAppUsage& a, const DexAppsUsageModel& m,
                           const std::string& window) {
    std::string first =
        a.subject.empty()
            ? std::string("&lt;unknown&gt;")
            : dex_pane_link("/fragments/dex/app?name=" + url_query_value(a.subject) + "&amp;window=" + window,
                            esc_text(a.subject));
    const bool show_cells = m.slice.kind != DexUsageSliceKind::Fleet && !a.cells.empty();
    if (show_cells)
        first += "<details class=\"dx-vx\"><summary>" + plural_count(static_cast<std::int64_t>(a.cells.size()), "cell", "cells") +
                 "</summary><span class=\"vh\">The cell rows follow this row in the table.</span></details>";

    std::string cells;
    if (a.state == DexUsageState::AmbiguousName) {
        // The cut is in bytes (dex_usage_model.hpp), and no device count is printed for a name that
        // is attributed to none of its applications.
        const std::string cut = n(static_cast<std::int64_t>(kDexUsageTruncBytes));
        first += " <span class=\"gp-mute\">Linux keeps only the first " + cut + " bytes of a process name (" + cut +
                 " characters for plain ASCII names), and this cut name matches more than one application here, "
                 "so its usage is attributed to none of them.</span>";
        cells = word_cell("withheld: the name is shared") + word_cell("withheld") + word_cell("withheld");
    } else if (a.state == DexUsageState::NoUsage) {
        const std::string w = m.population == 0          ? "no device online"
                              : m.reporting_devices == 0 ? "no device has reported usage"
                                                         : "no reporting device ran it";
        cells = "<td class=\"gp-num dx-fig\"><span class=\"w\">" + w + "</span>" +
                (m.reporting_devices > 0 ? of_reporting(m, "of ") : std::string()) + "</td>" +
                word_cell("no usage reported") + word_cell("no usage reported");
    } else if (!a.totals) {
        cells = "<td class=\"gp-num dx-fig\"><span class=\"v\">" + n(a.devices) + "</span>" + of_reporting(m, "of ") +
                "<span class=\"s nw\">count only</span></td>" + word_cell("below the reporting floor") +
                word_cell("below the reporting floor");
    } else {
        cells = "<td class=\"gp-num dx-fig\"><span class=\"v\">" + n(a.devices) + "</span>" + of_reporting(m, "of ") +
                "</td>" + hours_cell(a.totals->run_seconds_30d) + "<td class=\"gp-num\">" +
                n(a.totals->launches_30d) + "</td>";
    }

    std::string out = "<tbody class=\"dx-app\"><tr class=\"dx-apphead\"><td>" + first + "</td>" + cells +
                      usage_rate_cell(a, m, window) + "</tr>";
    if (show_cells)
        for (const auto& x : a.cells)
            out += "<tr class=\"dx-ver\"><td class=\"dx-indent\">" + cell_label(c, m, x) +
                   "</td><td class=\"gp-num dx-fig\"><span class=\"v\">" + n(x.devices) + "</span>" +
                   of_reporting(m, "of all ") +
                   (x.small_cohort ? std::string("<span class=\"gp-derived\">under 30 devices</span>") : std::string()) +
                   "</td>" + hours_cell(x.totals.run_seconds_30d) + "<td class=\"gp-num\">" +
                   n(x.totals.launches_30d) + "</td><td class=\"gp-num gp-mute\">not split by cell</td></tr>";
    return out + "</tbody>";
}

// The small-cohort tag and its constant stay together.
static_assert(kDexUsageSmallCohortDevices == 30,
              "the Usage view's cell tag says 'under 30 devices'; update it with this constant");

const char* const kUsageThead =
    "<thead><tr><th class=\"u1\">Application</th><th class=\"gp-num u2\">Devices that ran it</th>"
    "<th class=\"gp-num u3\">Run time, 30 days</th><th class=\"gp-num u4\">Launches, 30 days</th>"
    "<th class=\"gp-num u5\">Crashes and hangs per hour of use</th></tr></thead>";

std::string usage_notes() {
    return "<div class=\"gp-note\"><b>Which applications:</b> the applications on the Stability view, in the same "
           "order: those with a crash or hang in this window, at most 100. An application that only ran is not "
           "listed.</div>"
           "<div class=\"gp-note\"><b>Run time is process-hours:</b> it is summed per process run, so several "
           "instances running at once add up. It is not interactive or foreground time.</div>"
           "<div class=\"gp-note\"><b>Rate:</b> crashes plus hangs in the window, divided by the hours of use scaled "
           "from the 30-day total to the window. The counts are not capped per device, so events clustered on one "
           "device make the interval look narrower than it is. A rate on fewer than 20 events carries a tag.</div>"
           "<div class=\"gp-note\"><b>Counted devices:</b> only devices that reported usage in the last " +
           n(kUsageFreshHours) +
           " hours. A device that last reported earlier adds to no figure here.</div>";
}

// A refusal panel: one per cause, each naming the lever that helps. The token is printed as a
// code element through reason_note; a stray value is only ever escaped.
std::string usage_refusal_panel(const std::string& reason, const std::string& detail) {
    const std::string d = detail == reason ? std::string() : detail;
    if (reason == "invalid_scope")
        return placeholder("Unknown platform",
                           "The platform filter must be one of all, windows, macos or linux, so no figures are "
                           "shown. Choose a platform above.");
    if (reason == "invalid_slice" && d == "unknown_group")
        return placeholder("Unknown management group",
                           "That management group does not exist (it may have been removed), so no figures are "
                           "shown. Choose another group or slice above.");
    if (reason == "invalid_slice")
        return placeholder("Choose a slice",
                           "The slice request does not fit together, so no figures are shown. The group slice "
                           "needs a management group, the tag slice needs a valid tag key (letters, digits and "
                           "<code class=\"dx-code\">_ . : -</code>, at most 64), and a group or a tag key is only "
                           "read with its own slice. Choose a slice above." +
                               (d.empty() ? std::string() : reason_note(d)));
    if (reason == "audit_unavailable")
        return placeholder("Usage is not shown",
                           "The audit record for this read could not be stored, so the read was not run. Try again "
                           "in a moment.");
    if (reason == "usage_unavailable" && d == "fleet_too_large")
        return placeholder("Usage does not fit its time limit for this fleet",
                           "The read has timed out repeatedly, so no figures are shown. Trying again does not "
                           "help; only a single platform (above) makes the read smaller. It clears on the first "
                           "read that completes." + reason_note(d));
    if (reason == "usage_unavailable" && (d == "concurrency_budget" || d == "pool_acquire_timeout"))
        return placeholder("Usage is busy",
                           "The server is running as many of these reads as it allows, so no figures are shown. "
                           "Try again in a moment." + reason_note(d));
    if (reason == "usage_unavailable" && d == "statement_timeout")
        return placeholder("Usage is unavailable",
                           "The read took too long, so no figures are shown. Try again in a moment, or choose a "
                           "single platform to make the read smaller." + reason_note(d));
    const std::string named = d.empty() ? reason : d;
    if (reason == "apps_degraded")
        return placeholder("Usage is unavailable",
                           "The application list could not be read, so no figures are shown. The Stability view "
                           "says why." + reason_note(named));
    if (reason == "group_unavailable")
        return placeholder("Usage is unavailable",
                           "The management group&#39;s members could not be read, so no figures are shown. Try "
                           "again in a moment." + reason_note(named));
    if (reason == "tag_unavailable")
        return placeholder("Usage is unavailable",
                           "The tag values could not be read, so no figures are shown. Try again in a moment." +
                               reason_note(reason));
    if (reason == "no_population")
        return placeholder("Usage is unavailable",
                           "No fleet source is connected, so the population is unknown and no figures are shown." +
                               reason_note(reason));
    return placeholder("Usage is unavailable",
                       "The read could not be completed, so no figures are shown. Try again in a moment. If it "
                       "keeps failing, check PostgreSQL health." + reason_note(named));
}

// The platform the chips keep when the request's was unrecognised: all.
std::string keep_platform(const DexAppsUsageControls& c) {
    return c.platform.empty() ? std::string(kDexAppsScopeAll) : c.platform;
}


} // namespace

std::string render_dex_apps_fragment(const DexAppsModel& model, int window_days,
                                     const std::string& platform, DexAppsUsageEntry usage) {
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
    // The View chips (and, for a caller who may not read usage, one line of words) ride with the
    // filters, so they also appear on the degraded and error path. Hidden emits nothing.
    if (usage != DexAppsUsageEntry::Hidden) {
        h += view_chips(window, scope.empty() ? std::string(kDexAppsScopeAll) : scope, false);
        if (usage == DexAppsUsageEntry::Refused)
            h += "<div class=\"gp-note\">Usage is not shown: it needs the Forensics read permission, which this "
                 "account does not hold. Nothing else on this page is affected.</div>";
        else if (usage == DexAppsUsageEntry::GateUnavailable)
            h += "<div class=\"gp-note\">Usage is not shown: the permission check could not be completed. Try "
                 "again in a moment. Nothing else on this page is affected.</div>";
    }
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

std::string render_dex_apps_usage_fragment(const DexAppsUsageControls& controls,
                                           const DexAppsUsageModel& model) {
    const std::string window = dex_window_token(controls.window_days);
    const std::string keep = keep_platform(controls);
    std::string h = usage_head(controls, window, keep, usage_captions(controls, model, window));

    if (model.apps.empty()) {
        const bool all = keep == kDexAppsScopeAll;
        h += placeholder("No applications to show usage for",
                         std::string("Usage is listed for the applications on the Stability view, and no application "
                                     "crashed or hung") +
                             (all ? std::string() : " on " + std::string(scope_label(keep)) + " devices") +
                             " in this window. An application that only ran is not listed.");
        return h + "</div>";
    }

    h += "<div class=\"dx-tw\"><table class=\"gp-table dx-apps dx-usage\">";
    h += kUsageThead;
    // ponytail: every cell row is pre-rendered (up to 100 applications x 52 cells) so one page view
    // is one read; the upgrade path is a lazy per-application cells resource, API first.
    for (const auto& a : model.apps)
        h += usage_app_body(controls, a, model, window);
    h += "</table></div>";
    h += usage_notes();
    return h + "</div>";
}

std::string render_dex_apps_usage_refusal(const DexAppsUsageControls& controls, std::string_view reason,
                                          std::string_view detail) {
    const std::string window = dex_window_token(controls.window_days);
    // The chrome and the controls only: nothing on a refusal is derived from a model.
    std::string h = usage_head(controls, window, keep_platform(controls), std::string());
    h += usage_refusal_panel(std::string(reason), std::string(detail));
    return h + "</div>";
}

} // namespace yuzu::server
