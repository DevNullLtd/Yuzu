/// @file verify_ui.cpp
/// PURE render functions for the `/auto` VERIFY stage. Dark-theme, htmx CORE
/// attrs only (no hx-on — CSP). Every operator/agent string HTML-escaped. The
/// `.vf-*` CSS is inlined ONCE in render_verify_config (loads with the page; the
/// result/drill fragments only swap a child). See verify_routes.hpp.

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

const char kVerifyCss[] =
    "<style>"
    ".vf-cfg{display:flex;gap:.5rem .8rem;align-items:end;flex-wrap:wrap;background:#0c1626;"
    "border:1px solid #2d4068;border-radius:.5rem;padding:.7rem .85rem;margin:.2rem 0 .5rem}"
    ".vf-fld{display:flex;flex-direction:column;gap:.18rem}"
    ".vf-fld label{font-size:.62rem;color:#7f93ad}"
    ".vf-fld input,.vf-fld select{background:#0a1422;border:1px solid #2d4068;border-radius:.38rem;"
    "color:#cfdbe8;padding:.3rem .55rem;font-size:.78rem}"
    ".vf-arrow{color:#3d7ad6;font-size:1rem;align-self:end;padding-bottom:.25rem}"
    ".vf-sum{font-size:.76rem;color:#7f93ad;background:#0c1626;border:1px solid #2d4068;"
    "border-radius:.45rem;padding:.5rem .75rem;margin:.5rem 0 .3rem;display:flex;gap:.35rem .8rem;"
    "flex-wrap:wrap;align-items:center}.vf-sum b{color:#fff}.vf-sum .sep{color:#2d4068}"
    ".vf-sum .v{font-family:ui-monospace,Consolas,monospace;color:#a5d6ff;font-size:.74rem}"
    ".vf-ind{font-size:.68rem;color:#e0b85a;background:#231d10;border:1px solid #5a4a23;"
    "border-radius:.4rem;padding:.4rem .6rem;margin:.2rem 0 .5rem}.vf-ind b{color:#e9c98a}"
    ".vf-sech{font-size:.62rem;text-transform:uppercase;letter-spacing:.05em;color:#9fb2cc;"
    "font-weight:700;margin:1rem 0 .45rem}"
    ".vf-shift{display:grid;grid-template-columns:repeat(auto-fit,minmax(208px,1fr));gap:.6rem}"
    ".vf-card{background:#0c1626;border:1px solid #2d4068;border-radius:.55rem;padding:.65rem .8rem}"
    ".vf-card .m{font-size:.6rem;color:#7f93ad;text-transform:uppercase;letter-spacing:.04em;font-weight:700}"
    ".vf-ba{display:flex;align-items:baseline;gap:.45rem;margin-top:.35rem;font-family:ui-monospace,Consolas,monospace}"
    ".vf-ba .b0{color:#7f93ad;font-size:1rem}.vf-ba .ar{color:#46618d}.vf-ba .b1{color:#fff;font-size:1.3rem;font-weight:700}"
    ".vf-d{font-size:.8rem;font-weight:700;margin-top:.28rem;font-family:ui-monospace,Consolas,monospace}"
    ".vf-d.up{color:#e57373}.vf-d.dn{color:#4ed27e}.vf-d.flat{color:#7f93ad}"
    ".vf-d .pp{font-size:.62rem;color:#7f93ad;font-weight:400;margin-left:.25rem}"
    ".vf-card .s2{font-size:.62rem;color:#7f93ad;margin-top:.4rem;border-top:1px solid #2d4068;padding-top:.35rem}"
    ".vf-card.def{opacity:.62}.vf-card .deft{font-size:.54rem;border:1px solid #2d4068;border-radius:.3rem;"
    "padding:.02rem .32rem;color:#e0b85a;margin-left:.35rem}"
    ".vf-dist{background:#0c1626;border:1px solid #2d4068;border-radius:.55rem;padding:.65rem .8rem;margin-top:.2rem}"
    ".vf-dist .hd{font-size:.62rem;color:#7f93ad;text-transform:uppercase;letter-spacing:.04em;font-weight:700;margin-bottom:.5rem}"
    ".vf-bar{display:flex;height:1.4rem;border-radius:.32rem;overflow:hidden;border:1px solid #2d4068}"
    ".vf-bar span{display:flex;align-items:center;justify-content:center;font-size:.64rem;font-weight:700;color:#0a1422}"
    ".vf-bar .up{background:#e57373}.vf-bar .flat{background:#46618d;color:#fff}.vf-bar .dn{background:#4ed27e}"
    ".vf-leg{display:flex;gap:1rem;font-size:.68rem;color:#7f93ad;margin-top:.45rem;flex-wrap:wrap}"
    ".vf-leg b{font-family:ui-monospace,Consolas,monospace;color:#cfdbe8}"
    ".vf-dot{display:inline-block;width:.6rem;height:.6rem;border-radius:.14rem;margin-right:.3rem;vertical-align:middle}"
    ".vf-dot.up{background:#e57373}.vf-dot.flat{background:#46618d}.vf-dot.dn{background:#4ed27e}"
    ".vf-tbl{width:100%;border-collapse:collapse;font-size:.77rem;margin-top:.3rem}"
    ".vf-tbl th{text-align:left;padding:.35rem .5rem;border-bottom:2px solid #2d4068;color:#7f93ad;"
    "font-size:.58rem;text-transform:uppercase;letter-spacing:.04em}"
    ".vf-tbl th.n,.vf-tbl td.n{text-align:right;font-variant-numeric:tabular-nums;font-family:ui-monospace,Consolas,monospace}"
    ".vf-tbl td{padding:.38rem .5rem;border-bottom:1px solid #1a2c46}"
    ".vf-tbl td.up{color:#e57373;font-weight:700}.vf-tbl td.dn{color:#4ed27e;font-weight:600}.vf-tbl td.flat{color:#7f93ad}"
    ".vf-audit{font-size:.6rem;color:#5d7396;margin-top:.4rem}"
    "</style>";

} // namespace

std::string render_verify_config(const std::vector<std::pair<std::string, std::string>>& groups) {
    std::string h = kVerifyCss;
    h += "<div class=\"gp-mute\" style=\"font-size:.74rem;margin-bottom:.5rem\">"
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
    h += "<button class=\"gp-chip\" style=\"background:#3d7ad6;border-color:#3d7ad6;color:#fff;"
         "font-weight:600;cursor:pointer\" hx-get=\"/fragments/auto/verify/run\" "
         "hx-include=\"#verify-cfg input, #verify-cfg select\" hx-target=\"#verify-results\" "
         "hx-swap=\"innerHTML\">Compare</button>";
    h += "</div>";
    h += "<div class=\"gp-mute\" style=\"font-size:.68rem;margin:-.2rem 0 .4rem\">Tip: the app name "
         "must match what the devices report (e.g. <span class=\"v\" style=\"font-family:ui-monospace,"
         "Consolas,monospace\">AcmeVPN.exe</span>). Discover apps with retained data via "
         "<span class=\"v\" style=\"font-family:ui-monospace,Consolas,monospace\">GET "
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
    h += "<span class=\"v\" style=\"color:#fff\">" + esc(app) + "</span><span class=\"sep\">\xC2\xB7</span>";
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
    // so the comparison below must not be trusted (gov UP-1). Red, above everything.
    if (truncated)
        h += "<div class=\"vf-ind\" style=\"color:#e57373;background:#241010;border-color:#5a2323\">"
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
         "<div class=\"s2\" style=\"border:0;padding-top:.55rem\">Per-version stability join isn\xE2\x80\x99t "
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
    h += "<div class=\"gp-mute\" style=\"font-size:.72rem;margin-bottom:.4rem\">Opening the "
         "per-machine table records a <span class=\"v\" style=\"font-family:ui-monospace,Consolas,"
         "monospace;color:#a5d6ff\">dex.app_perf.compare.drill</span> access-audit row.</div>";
    h += "<button class=\"gp-chip\" style=\"cursor:pointer\" hx-get=\"" + esc(drill_url) +
         "\" hx-target=\"#verify-drill\" hx-swap=\"innerHTML\">Show per-machine pairs</button>";
    h += "<div id=\"verify-drill\" style=\"margin-top:.5rem\"></div>";

    // Honesty footer.
    h += "<div class=\"vf-audit\" style=\"margin-top:.9rem\">Cohort-paired \xE2\x80\x94 every number "
         "is a per-machine before-vs-after delta on the SAME device, then aggregated; the population "
         "is held fixed. Unpaired machines (ran only one version in-window) are excluded + counted, "
         "never imputed. <b style=\"color:#a5d6ff\">No verdict</b> \xE2\x80\x94 the shift and the "
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
        h += "<div class=\"vf-ind\" style=\"color:#e57373;background:#241010;border-color:#5a2323\">"
             "\xE2\x9A\xA0 Truncated \xE2\x80\x94 the cohort exceeded the read cap, so machines are "
             "missing from this list and some pairings may be wrong. Narrow the group or shorten the "
             "window.</div>";
    h += "<table class=\"vf-tbl\"><thead><tr><th>Device</th>"
         "<th class=\"n\">CPU before</th><th class=\"n\">CPU after</th><th class=\"n\">\xCE\x94 CPU</th>"
         "<th class=\"n\">WS before</th><th class=\"n\">WS after</th><th class=\"n\">\xCE\x94 WS</th>"
         "<th class=\"n\">Samples</th></tr></thead><tbody>";
    for (const auto& p : c.pairs) { // engine already sorts largest CPU mover first
        const std::string dc = cpu_dir(p.cpu_delta);
        const std::string dw = ws_dir(p.ws_delta);
        h += "<tr><td><a href=\"/hardware/ci?id=" + esc(p.agent_id) +
             "\" style=\"color:#cfdbe8;border-bottom:1px dotted #36507e;text-decoration:none\">" +
             esc(p.agent_id) + "</a></td>";
        h += "<td class=\"n\">" + fmt_pct(p.cpu_before) + "</td>";
        h += "<td class=\"n\">" + fmt_pct(p.cpu_after) + "</td>";
        h += "<td class=\"n " + dc + "\">" + fmt_signed_pp(p.cpu_delta) + "</td>";
        h += "<td class=\"n\">" + fmt_bytes(static_cast<double>(p.ws_before)) + "</td>";
        h += "<td class=\"n\">" + fmt_bytes(static_cast<double>(p.ws_after)) + "</td>";
        h += "<td class=\"n " + dw + "\">" + fmt_signed_bytes(p.ws_delta) + "</td>";
        h += "<td class=\"n\">" + std::to_string(p.samples) + "</td></tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"vf-audit\">Audited read \xC2\xB7 " + std::to_string(c.pairs.size()) +
         " paired rows.</div>";
    return h;
}

} // namespace yuzu::server
