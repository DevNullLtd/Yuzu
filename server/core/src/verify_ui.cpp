/// @file verify_ui.cpp
/// PURE render functions for the `/auto` VERIFY stage. Dark-theme, htmx CORE
/// attrs only (no hx-on — CSP). Every operator/agent string HTML-escaped. The
/// `.vf-*` CSS (kVerifyCss) is inlined ONCE in render_verify_config (loads with the
/// page; the result/drill fragments only swap a child); the `.af-*` fields and
/// buttons it reuses come from kAutoCss (preflight_ui.cpp). See verify_routes.hpp.

#include "verify_ui.hpp"

#include "web_utils.hpp" // html_escape

#include <array>
#include <cstdio>
#include <string>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string fmt_pct(double v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.1f%%", v);
    return b;
}

std::string fmt_signed_pp(double v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%+.1fpp", v);
    return b;
}

std::string fmt_bytes(double b) {
    static const std::array<const char*, 5> u{"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double n = b;
    while (n >= 1024.0 && i < static_cast<int>(u.size()) - 1) {
        n /= 1024.0;
        ++i;
    }
    char out[40];
    std::snprintf(out, sizeof(out), (n < 10.0 && i > 0) ? "%.1f %s" : "%.0f %s", n, u[i]);
    return out;
}

std::string fmt_signed_bytes(std::int64_t v) {
    const char* sign = v > 0 ? "+" : (v < 0 ? "\xE2\x88\x92" : ""); // − (U+2212) for negatives
    // Negate in double, not int64 — `-v` is UB at INT64_MIN (unreachable given the
    // store's ±2^50 ws clamp, but the negation is a latent trap if it ever widens).
    const double mag = v < 0 ? -static_cast<double>(v) : static_cast<double>(v);
    return std::string(sign) + fmt_bytes(mag);
}

// CPU delta direction class (matches the engine's flat band).
const char* cpu_dir(double delta) {
    if (delta > kCpuFlatBandPp)
        return "up";
    if (delta < -kCpuFlatBandPp)
        return "dn";
    return "flat";
}

const char* ws_dir(std::int64_t delta) {
    if (delta > 5LL * 1024 * 1024)
        return "up";
    if (delta < -5LL * 1024 * 1024)
        return "dn";
    return "flat";
}

// Reuses the `af-*` fields and buttons from kAutoCss (preflight_ui.cpp): this fragment
// only ever renders inside the /auto page. Design tokens only (yuzu.css).
const char* kVerifyCss = R"CSS(<style>
.vf-cfg{display:flex;flex-wrap:wrap;gap:12px 16px;align-items:end;margin-top:12px;padding:16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.vf-fld{display:flex;flex-direction:column;gap:5px}
.vf-fld label{font-size:13px;font-weight:500;color:var(--mut)}
.vf-arrow{align-self:end;padding-bottom:8px;color:var(--faint)}
.vf-cfg+.af-note{margin-top:8px}
#verify-results{margin-top:16px}
.vf-mono{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink2)}
.vf-sum{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;margin-top:12px;padding:12px 16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel);font-size:13px;color:var(--mut)}
.vf-sum b{color:var(--ink);font-weight:600}.vf-sum .sep{color:var(--line2)}
.vf-sum .v{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink2)}.vf-sum .v.app{color:var(--ink)}
.vf-ind{margin:12px 0;padding:12px 14px;border:1px solid color-mix(in srgb,var(--warn) 50%,var(--line2));border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
.vf-ind b{color:var(--ink)}
.vf-ind.bad{border-color:color-mix(in srgb,var(--bad) 50%,var(--line2))}
.vf-sech{margin:22px 0 10px;font-size:14px;font-weight:600;color:var(--ink)}
.vf-shift{display:flex;flex-wrap:wrap;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.vf-card{flex:1 1 208px;min-width:0;padding:14px 18px;border-left:1px solid var(--line)}
.vf-card:first-child{border-left:0}
.vf-card .m{font-size:13px;color:var(--mut)}
.vf-ba{display:flex;align-items:baseline;gap:8px;margin-top:6px;font-family:var(--mds-font-family-mono)}
.vf-ba .b0{font-size:16px;color:var(--mut)}.vf-ba .ar{color:var(--faint)}.vf-ba .b1{font-size:26px;font-weight:500;letter-spacing:-.02em;color:var(--ink)}
.vf-d{margin-top:4px;font-family:var(--mds-font-family-mono);font-size:13px;font-weight:600}
.vf-d.up{color:var(--bad)}.vf-d.dn{color:var(--ok)}.vf-d.flat{color:var(--mut)}
.vf-d .pp{margin-left:4px;font-family:var(--font);font-size:12.5px;font-weight:400;color:var(--mut)}
.vf-card .s2{margin-top:8px;padding-top:6px;border-top:1px solid var(--line);font-size:12.5px;color:var(--mut)}
.vf-card .s2.vf-nojoin{border:0;padding-top:.55rem}
.vf-drill-btn{margin-top:8px}
#verify-drill{margin-top:.5rem}
.vf-card.def{opacity:.62}
.vf-card .deft{margin-left:8px;padding:0 6px;border-radius:3px;background:var(--surface2);font-size:12px;font-weight:500;color:var(--mut)}
.vf-dist{padding:14px 16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.vf-dist .hd{margin-bottom:10px;font-size:13px;color:var(--mut)}
.vf-bar{display:flex;height:22px;gap:2px;border-radius:3px;overflow:hidden;background:var(--bg)}
.vf-bar span{display:flex;align-items:center;justify-content:center;font-size:12.5px;font-weight:600;color:var(--on-primary)}
.vf-bar .up{background:var(--bad)}.vf-bar .flat{background:var(--faint)}.vf-bar .dn{background:var(--ok)}
.vf-leg{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:13px;color:var(--mut)}
.vf-leg b{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink2)}
.vf-dot{display:inline-block;width:10px;height:10px;margin-right:6px;border-radius:2px;vertical-align:middle}
.vf-dot.up{background:var(--bad)}.vf-dot.flat{background:var(--faint)}.vf-dot.dn{background:var(--ok)}
.vf-tw{overflow-x:auto}
.vf-tbl{width:100%;border-collapse:collapse}
.vf-tbl th{padding:8px 16px;border-bottom:1px solid var(--line);background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500;text-align:left;white-space:nowrap}
.vf-tbl td{padding:var(--cell-y) 16px;border-bottom:1px solid var(--line);color:var(--ink2);white-space:nowrap}
.vf-tbl tr:last-child td{border-bottom:0}
.vf-tbl tbody tr:hover td{background:var(--surface2)}
.vf-tbl th.n,.vf-tbl td.n{text-align:right;font-family:var(--mds-font-family-mono);font-size:12.5px;font-variant-numeric:tabular-nums}
.vf-tbl td.up{color:var(--bad);font-weight:600}.vf-tbl td.dn{color:var(--ok);font-weight:600}.vf-tbl td.flat{color:var(--mut)}
.vf-tbl a{color:var(--primary);text-decoration:none}.vf-tbl a:hover{color:var(--primary-h);text-decoration:underline}
.vf-audit{margin-top:12px;font-size:12.5px;color:var(--faint)}.vf-audit b{color:var(--ink2);font-weight:600}
</style>)CSS";

} // namespace

std::string render_verify_config(const std::vector<std::pair<std::string, std::string>>& groups) {
    std::string h = kVerifyCss;
    h += "<div class=\"af-note\">"
         "How the <b>same machines</b> performed on the version they ran before vs the version "
         "just installed \xE2\x80\x94 per machine, paired. <b>Evidence only; this stage does not "
         "pass or fail the rollout.</b></div>";

    h += "<div class=\"vf-cfg\" id=\"verify-cfg\">";
    h += "<div class=\"vf-fld\"><label>Cohort (management group)</label><select name=\"group\">";
    h += "<option value=\"\">(select a group)</option>";
    for (const auto& [id, name] : groups)
        h += "<option value=\"" + esc(id) + "\">" + esc(name) + "</option>";
    h += "</select></div>";
    h += "<div class=\"vf-fld\"><label>Application</label>"
         "<input name=\"app\" placeholder=\"e.g. AcmeVPN.exe\" style=\"min-width:150px\"></div>";
    h += "<div class=\"vf-fld\"><label>Baseline (before)</label>"
         "<input name=\"baseline\" placeholder=\"4.2.0.0\" style=\"width:8rem\"></div>";
    h += "<span class=\"vf-arrow\">\xE2\x86\x92</span>";
    h += "<div class=\"vf-fld\"><label>Candidate (after)</label>"
         "<input name=\"candidate\" placeholder=\"4.3.0.0\" style=\"width:8rem\"></div>";
    h += "<div class=\"vf-fld\"><label>Window each side</label>"
         "<select name=\"window\"><option value=\"3\">3 d</option>"
         "<option value=\"7\" selected>7 d</option><option value=\"14\">14 d</option></select></div>";
    h += "<button class=\"af-btn pri\" hx-get=\"/fragments/auto/verify/run\" "
         "hx-include=\"#verify-cfg input, #verify-cfg select\" hx-target=\"#verify-results\" "
         "hx-swap=\"innerHTML\">Compare</button>";
    h += "</div>";
    h += "<div class=\"af-note\">Tip: the app name "
         "must match what the devices report (e.g. <span class=\"vf-mono\">AcmeVPN.exe</span>). "
         "Discover apps with retained data via <span class=\"vf-mono\">GET "
         "/api/v1/dex/perf/apps</span>. Performance collection is opt-in (off by default).</div>";

    h += "<div id=\"verify-results\"><div class=\"gp-placeholder\">"
         "Pick a cohort, app, and two versions, then Compare.</div></div>";
    return h;
}

std::string render_verify_note(const std::string& message) {
    return "<div class=\"gp-placeholder\">" + esc(message) + "</div>";
}

std::string render_verify_result(const PairedComparison& c, std::int64_t cohort_size, bool truncated,
                                 const std::string& app, const std::string& baseline,
                                 const std::string& candidate, int window,
                                 const std::string& drill_url) {
    const std::int64_t no_data = cohort_no_data(c, cohort_size);
    const std::int64_t unpaired = c.baseline_only + c.candidate_only;

    std::string h;
    // Factual summary — counts only, no verdict.
    h += "<div class=\"vf-sum\">";
    h += "<span class=\"v app\">" + esc(app) + "</span><span class=\"sep\">\xC2\xB7</span>";
    h += "<span><b>" + std::to_string(cohort_size) + "</b> in cohort</span><span class=\"sep\">\xC2\xB7</span>";
    h += "<span><b>" + std::to_string(c.paired) + "</b> paired</span><span class=\"sep\">\xC2\xB7</span>";
    h += "<span><b>" + std::to_string(unpaired) + "</b> unpaired, excluded</span>";
    if (no_data > 0)
        h += "<span class=\"sep\">\xC2\xB7</span><span><b>" + std::to_string(no_data) + "</b> no data</span>";
    h += "<span class=\"sep\">\xC2\xB7</span><span><span class=\"v\">" + esc(baseline) +
         "</span> \xE2\x86\x92 <span class=\"v\">" + esc(candidate) + "</span></span>";
    h += "<span class=\"sep\">\xC2\xB7</span><span>" + std::to_string(window) + " d each side</span>";
    h += "</div>";

    // Truncation is LOUD, not silent: a capped read can mis-pair a boundary machine,
    // so the comparison below must not be trusted (gov UP-1). It sits above the comparison with
    // a warning glyph, a bold remedy and a red-tinted border (`.vf-ind.bad`).
    if (truncated)
        h += "<div class=\"vf-ind bad\">"
             "\xE2\x9A\xA0 This cohort is too large to compare reliably \xE2\x80\x94 the read hit the "
             "100,000-row cap, so some machines are dropped and a machine that ran both versions can "
             "be mis-counted as one-version-only. <b>Narrow the group or shorten the window.</b> The "
             "numbers below are incomplete.</div>";

    if (c.insufficient) {
        // Distinguish "no app-perf data at all for this cohort/app" (likely the app
        // name is wrong, or performance collection is off) from "there is data but no
        // machine ran BOTH versions" — the remediation differs (gov UP-10 / enterprise).
        if (unpaired == 0 && no_data == cohort_size)
            h += render_verify_note("No performance data for this application on this cohort. Check "
                                    "the application name, and that performance collection is enabled "
                                    "on these devices (it is opt-in and off by default); a just-"
                                    "upgraded version also only appears after the devices' next "
                                    "daily report.");
        else
            h += render_verify_note("No machine in this cohort ran BOTH versions in-window, so there "
                                    "is nothing to pair. Pick versions the cohort has actually run, "
                                    "or widen the window.");
        return h;
    }
    if (c.small_cohort)
        h += "<div class=\"vf-ind\">Small cohort \xE2\x80\x94 <b>" + std::to_string(c.paired) +
             "</b> paired machines. Read the aggregate as <b>indicative</b>; the per-machine pairs "
             "below are the substance at canary scale.</div>";

    // Aggregate shift cards — measured shift only, no verdict.
    h += "<div class=\"vf-sech\">Aggregate shift \xC2\xB7 per-machine deltas, then aggregated</div>";
    h += "<div class=\"vf-shift\">";
    // CPU
    h += "<div class=\"vf-card\"><div class=\"m\">CPU mean</div>";
    h += "<div class=\"vf-ba\"><span class=\"b0\">" + fmt_pct(c.cpu_before_mean) +
         "</span><span class=\"ar\">\xE2\x86\x92</span><span class=\"b1\">" +
         fmt_pct(c.cpu_after_mean) + "</span></div>";
    h += "<div class=\"vf-d " + std::string(cpu_dir(c.cpu_delta_median)) + "\">" +
         fmt_signed_pp(c.cpu_delta_median) + " <span class=\"pp\">median per-machine shift</span></div>";
    h += "<div class=\"s2\">p95 across machines: " + fmt_pct(c.cpu_before_p95) + " \xE2\x86\x92 " +
         fmt_pct(c.cpu_after_p95) + "</div></div>";
    // WS
    h += "<div class=\"vf-card\"><div class=\"m\">Working set mean</div>";
    h += "<div class=\"vf-ba\"><span class=\"b0\">" + fmt_bytes(static_cast<double>(c.ws_before_mean)) +
         "</span><span class=\"ar\">\xE2\x86\x92</span><span class=\"b1\">" +
         fmt_bytes(static_cast<double>(c.ws_after_mean)) + "</span></div>";
    h += "<div class=\"vf-d " + std::string(ws_dir(c.ws_delta_median)) + "\">" +
         fmt_signed_bytes(c.ws_delta_median) + " <span class=\"pp\">median per-machine shift</span></div>";
    h += "<div class=\"s2\">p95 across machines: " + fmt_bytes(static_cast<double>(c.ws_before_p95)) +
         " \xE2\x86\x92 " + fmt_bytes(static_cast<double>(c.ws_after_p95)) + "</div></div>";
    // Crashes/hangs deferred (shown honestly, not omitted)
    h += "<div class=\"vf-card def\"><div class=\"m\">Crashes / hangs<span class=\"deft\">deferred</span></div>"
         "<div class=\"s2 vf-nojoin\">Per-version stability join isn\xE2\x80\x99t "
         "built \xE2\x80\x94 lands when the central crash-store carries the version key on the read side.</div></div>";
    h += "</div>"; // vf-shift

    // Distribution split
    const std::int64_t tot = c.paired > 0 ? c.paired : 1;
    auto pct = [&](std::int64_t n) {
        char b[16];
        std::snprintf(b, sizeof(b), "%.1f", static_cast<double>(n) / static_cast<double>(tot) * 100.0);
        return std::string(b);
    };
    h += "<div class=\"vf-sech\">How the paired machines moved \xC2\xB7 each machine\xE2\x80\x99s own "
         "before \xE2\x86\x92 after CPU mean</div>";
    h += "<div class=\"vf-dist\"><div class=\"hd\">Of " + std::to_string(c.paired) +
         " paired machines, on CPU mean</div><div class=\"vf-bar\">";
    if (c.moved_up > 0)
        h += "<span class=\"up\" style=\"width:" + pct(c.moved_up) + "%\">" +
             std::to_string(c.moved_up) + "</span>";
    if (c.moved_flat > 0)
        h += "<span class=\"flat\" style=\"width:" + pct(c.moved_flat) + "%\">" +
             std::to_string(c.moved_flat) + "</span>";
    if (c.moved_down > 0)
        h += "<span class=\"dn\" style=\"width:" + pct(c.moved_down) + "%\">" +
             std::to_string(c.moved_down) + "</span>";
    h += "</div><div class=\"vf-leg\">";
    h += "<span><span class=\"vf-dot up\"></span><b>" + std::to_string(c.moved_up) +
         "</b> used more CPU on " + esc(candidate) + "</span>";
    h += "<span><span class=\"vf-dot flat\"></span><b>" + std::to_string(c.moved_flat) +
         "</b> about the same (\xC2\xB1" "0.3pp)</span>";
    h += "<span><span class=\"vf-dot dn\"></span><b>" + std::to_string(c.moved_down) +
         "</b> used less</span></div></div>";

    // Per-machine drill — behind a click (a click = intentional PII access → its
    // own audit; auto-loading would fire a works-council access-audit every render).
    h += "<div class=\"vf-sech\">Per-machine pairs</div>";
    h += "<div class=\"af-note\">Opening the "
         "per-machine table records a <span class=\"vf-mono\">dex.app_perf.compare.drill</span> "
         "access-audit row.</div>";
    h += "<button class=\"af-btn vf-drill-btn\" hx-get=\"" + esc(drill_url) +
         "\" hx-target=\"#verify-drill\" hx-swap=\"innerHTML\">Show per-machine pairs</button>";
    h += "<div id=\"verify-drill\"></div>";

    // Honesty footer.
    h += "<div class=\"vf-audit\">Cohort-paired \xE2\x80\x94 every number "
         "is a per-machine before-vs-after delta on the SAME device, then aggregated; the population "
         "is held fixed. Unpaired machines (ran only one version in-window) are excluded + counted, "
         "never imputed. <b>No verdict</b> \xE2\x80\x94 the shift and the "
         "spread are the evidence; whether it\xE2\x80\x99s acceptable is your call.</div>";
    return h;
}

std::string render_verify_drill(const PairedComparison& c, bool truncated) {
    if (c.pairs.empty())
        return render_verify_note("No paired machines to show.");
    std::string h;
    // A direct-URL drill hit on a capped cohort must carry the same warning the /run
    // banner shows — machines are missing and some pairings may be wrong (gov round-2).
    if (truncated)
        h += "<div class=\"vf-ind bad\">"
             "\xE2\x9A\xA0 Truncated \xE2\x80\x94 the cohort exceeded the read cap, so machines are "
             "missing from this list and some pairings may be wrong. Narrow the group or shorten the "
             "window.</div>";
    h += "<div class=\"af-panel vf-tw\"><table class=\"vf-tbl\"><thead><tr><th>Device</th>"
         "<th class=\"n\">CPU before</th><th class=\"n\">CPU after</th><th class=\"n\">\xCE\x94 CPU</th>"
         "<th class=\"n\">WS before</th><th class=\"n\">WS after</th><th class=\"n\">\xCE\x94 WS</th>"
         "<th class=\"n\">Samples</th></tr></thead><tbody>";
    for (const auto& p : c.pairs) { // engine already sorts largest CPU mover first
        const std::string dc = cpu_dir(p.cpu_delta);
        const std::string dw = ws_dir(p.ws_delta);
        h += "<tr><td><a href=\"/hardware/ci?id=" + url_query_value(p.agent_id) + "\">" + esc(p.agent_id) +
             "</a></td>";
        h += "<td class=\"n\">" + fmt_pct(p.cpu_before) + "</td>";
        h += "<td class=\"n\">" + fmt_pct(p.cpu_after) + "</td>";
        h += "<td class=\"n " + dc + "\">" + fmt_signed_pp(p.cpu_delta) + "</td>";
        h += "<td class=\"n\">" + fmt_bytes(static_cast<double>(p.ws_before)) + "</td>";
        h += "<td class=\"n\">" + fmt_bytes(static_cast<double>(p.ws_after)) + "</td>";
        h += "<td class=\"n " + dw + "\">" + fmt_signed_bytes(p.ws_delta) + "</td>";
        h += "<td class=\"n\">" + std::to_string(p.samples) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    h += "<div class=\"vf-audit\">Audited read \xC2\xB7 " + std::to_string(c.pairs.size()) +
         " paired rows.</div>";
    return h;
}

} // namespace yuzu::server
