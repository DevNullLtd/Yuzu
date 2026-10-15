/// @file deployment_ui.cpp
/// PURE render functions for the `/auto` DEPLOY stage. Dark-theme, htmx CORE attrs
/// only; filtering is CSP-safe inline JS (a plain <script> + onclick + a
/// `window.__dp` global re-applied on every poll swap — never hx-on). Every
/// agent-supplied string is HTML-escaped. AGGREGATE-FIRST: the KPI strip + bar are
/// the headline (the part that scales); the per-device list is problem-first and
/// render-capped (true 100k scale = keyset paging, a follow-up). See
/// deployment_routes.hpp.

#include "deployment_routes.hpp"

#include "deployment_parse.hpp" // Step / step_from_token
#include "web_utils.hpp"        // html_escape

#include <string>
#include <vector>

namespace yuzu::server {

namespace {
std::string esc(const std::string& s) { return html_escape(s); }

// Cap device rows rendered per group so a large cohort can't blow up the DOM; the
// KPI counts above are always exact. 100k-scale paging is a follow-up.
constexpr int kRenderCapPerGroup = 500;

// Reuses the `af-*` fields, buttons, panel and device-group list (`af-grp`, `af-dev`,
// `af-rhd`, `af-empty`) from kAutoCss (preflight_ui.cpp): this fragment only ever
// renders inside the /auto page. Design tokens only (yuzu.css).
const char* kDeployCss = R"CSS(<style>
#auto-deploy-grid{margin-top:14px}
.dp-cohort{margin:0 0 14px;padding:12px 14px;border:1px solid var(--line2);border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
.dp-cohort b{color:var(--ink)}
#deploy-cfg input{font-family:var(--mds-font-family-mono);font-size:12.5px}
#deploy-cfg .af-cfg:first-of-type{padding-top:0}
.dp-warn{margin:14px 0;padding:12px 14px;border:1px solid color-mix(in srgb,var(--warn) 50%,var(--line2));border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
.dp-warn b{color:var(--ink)}
.af-rhd .art{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink2)}
.dp-kpis{display:flex;flex-wrap:wrap;margin:0 0 14px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.dp-kpi{flex:1 1 110px;padding:12px 16px;border-left:1px solid var(--line);user-select:none}
.dp-kpi:first-child{border-left:0}
.dp-kpi[data-b]{cursor:pointer}.dp-kpi[data-b]:hover{background:var(--surface2)}
.dp-kpi .v{font-size:26px;font-weight:500;letter-spacing:-.02em;line-height:1.15;font-variant-numeric:tabular-nums;color:var(--ink)}
.dp-kpi .l{margin-top:2px;font-size:13px;color:var(--mut)}
.dp-kpi.sel{background:color-mix(in srgb,var(--primary) 12%,transparent);box-shadow:inset 0 -2px 0 var(--primary)}
.dp-kpi.ok .v{color:var(--ok)}.dp-kpi.run .v{color:var(--info)}.dp-kpi.stg .v{color:var(--ink2)}.dp-kpi.fail .v{color:var(--bad)}.dp-kpi.skip .v{color:var(--mut)}
.dp-bar{display:flex;height:6px;margin:0 0 8px;border-radius:2px;overflow:hidden;background:var(--line)}
.dp-bar i{display:block;height:100%}
.dp-seg-ok{background:var(--ok)}.dp-seg-run{background:var(--info)}.dp-seg-stg{background:var(--primary)}.dp-seg-fail{background:var(--bad)}.dp-seg-skip{background:var(--line2)}
.dp-prog{margin-bottom:14px;font-size:13px;color:var(--mut);font-variant-numeric:tabular-nums}
.af-dev .prog{display:flex;flex:1;flex-wrap:wrap;align-items:center;gap:6px}
.dp-step{padding:1px 8px;border-radius:3px;font-size:12.5px;font-weight:500;white-space:nowrap}
.dp-step.done{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok)}
.dp-step.act{background:color-mix(in srgb,var(--info) 14%,transparent);color:var(--info)}
.dp-step.wait{background:var(--surface2);color:var(--mut)}
.dp-step.err{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad)}
.dp-arrow{color:var(--faint);font-size:12.5px}
.dp-detail{font-size:12.5px;color:var(--mut);word-break:break-all}
.dp-detail.bad{color:var(--bad)}
.dp-skip{font-size:13px;color:var(--warn)}
.dp-more{padding:8px 16px;font-size:13px;color:var(--mut)}
</style>)CSS";

struct DispBucket {
    const char* key;   // filter/data token
    const char* label; // group title
};

// step token → (display bucket key, group title). pending/staging/staged collapse
// into one "in-flight" bucket; the rest are 1:1.
DispBucket disp_bucket(deployment::Step s) {
    using deployment::Step;
    switch (s) {
    case Step::kSucceeded:
        return {"ok", "Succeeded"};
    case Step::kExecuting:
        return {"run", "Executing"};
    case Step::kFailed:
        return {"fail", "Failed"};
    case Step::kSkipped:
        return {"skip", "Skipped"};
    default:
        return {"stg", "In-flight"};
    }
}

// The stage→execute lifecycle chips for one device row.
std::string step_chips(const DeploymentDeviceRow& d) {
    using deployment::Step;
    const Step s = deployment::step_from_token(d.step);
    auto chip = [](const char* cls, const std::string& txt) {
        return "<span class=\"dp-step " + std::string(cls) + "\">" + txt + "</span>";
    };
    const std::string arrow = "<span class=\"dp-arrow\">\xE2\x86\x92</span>";
    switch (s) {
    case Step::kSkipped:
        return "<span class=\"dp-skip\">\xE2\x8A\x98 skipped \xE2\x80\x94 " +
               esc(d.error.empty() ? "out of scope at dispatch" : d.error) +
               " (never executed)</span>";
    case Step::kPending:
        return chip("wait", "stage") + " " + arrow + " " + chip("wait", "execute");
    case Step::kStaging:
        return chip("act", "staging\xE2\x80\xA6") + " " + arrow + " " + chip("wait", "execute");
    case Step::kStaged:
        return chip("done", "\xE2\x9C\x93 staged") + " " + arrow + " " + chip("wait", "execute");
    case Step::kExecuting:
        return chip("done", "\xE2\x9C\x93 staged") + " " + arrow + " " +
               chip("act", "executing\xE2\x80\xA6");
    case Step::kSucceeded:
        return chip("done", "\xE2\x9C\x93 staged") + " " + arrow + " " +
               chip("done", "\xE2\x9C\x93 executed") +
               "<span class=\"dp-detail\">exit " + std::to_string(d.exit_code) + "</span>";
    case Step::kFailed:
    default:
        if (d.exit_code != 0) // execute failure (non-zero exit)
            return chip("done", "\xE2\x9C\x93 staged") + " " + arrow + " " +
                   chip("err", "\xE2\x9C\x95 execute") + "<span class=\"dp-detail bad\">exit " +
                   std::to_string(d.exit_code) +
                   (d.error.empty() ? "" : (" \xC2\xB7 " + esc(d.error))) + "</span>";
        // stage failure (no exit code)
        return chip("err", "\xE2\x9C\x95 stage failed") + " " + arrow + " " +
               chip("wait", "execute") +
               (d.error.empty() ? "" : "<span class=\"dp-detail bad\">" + esc(d.error) + "</span>");
    }
}

} // namespace

std::string render_deploy_config(const std::string& run_id, const std::string& run_name,
                                 int go_count, int warn_count) {
    const int cohort = go_count + warn_count;
    std::string h = kDeployCss;
    h += "<div class=\"af-panel af-pb\"><div class=\"dp-cohort\">\xE2\x86\x92 Deploys to the <b>" + std::to_string(cohort) +
         "</b> device" + (cohort == 1 ? "" : "s") + " this pre-flight cleared (" +
         std::to_string(go_count) + " go-clean + " + std::to_string(warn_count) +
         " warn-only). No-go and incomplete devices are excluded.</div>";

    h += "<div id=\"deploy-cfg\">";
    h += "<input type=\"hidden\" name=\"run\" value=\"" + esc(run_id) + "\">";
    h += "<div class=\"af-cfg\"><span class=\"af-name\">Artifact</span>"
         "<div class=\"af-fld\"><label>Download URL</label>"
         "<input name=\"url\" placeholder=\"https://repo/pkg.msi\" style=\"min-width:300px\"></div></div>";
    h += "<div class=\"af-cfg\">"
         "<div class=\"af-fld\"><label>Filename</label>"
         "<input name=\"filename\" placeholder=\"pkg.msi\" style=\"min-width:160px\"></div>"
         "<div class=\"af-fld\"><label>SHA-256</label>"
         "<input name=\"sha256\" placeholder=\"64 hex chars\" style=\"min-width:230px\"></div>"
         "<div class=\"af-fld\"><label>Install args<span class=\"af-tag\">optional</span></label>"
         "<input name=\"args\" placeholder=\"/qn /norestart\" style=\"min-width:150px\"></div></div>";

    h += "</div>"; // #deploy-cfg

    h += "<div class=\"dp-warn\">\xE2\x9A\xA0 This <b>runs an installer</b> on every cohort device. "
         "Execute is dispatched <b>once per device</b> (claimed before dispatch \xE2\x80\x94 safe under "
         "reload / agent re-poll). A device you no longer have scope to is <b>skipped</b>, never run.</div>";

    // Confirm-guarded (hx-confirm → native confirm(), CSP-safe). Cohort size + run
    // name are baked in at render; the artifact filename is visible in the form.
    h += "<button class=\"af-btn pri\" "
         "hx-post=\"/fragments/auto/deploy/run\" hx-include=\"#deploy-cfg input\" "
         "hx-confirm=\"Deploy to " +
         std::to_string(cohort) + " device" + (cohort == 1 ? "" : "s") + " from &quot;" +
         esc(run_name.empty() ? std::string("this pre-flight run") : run_name) +
         "&quot;? This runs the installer on each device and cannot be undone.\" "
         "hx-target=\"#auto-deploy-grid\" hx-swap=\"innerHTML\">Stage + deploy to cohort\xE2\x80\xA6</button>";

    h += "<div id=\"auto-deploy-grid\"></div></div>";
    return h;
}

std::string render_deploy_results(const DeploymentRow& dep,
                                  const std::vector<DeploymentDeviceRow>& devices,
                                  const std::string& repoll_url) {
    using deployment::Step;
    int ok = 0, run = 0, stg = 0, fail = 0, skip = 0;
    for (const auto& d : devices) {
        switch (deployment::step_from_token(d.step)) {
        case Step::kSucceeded:
            ++ok;
            break;
        case Step::kExecuting:
            ++run;
            break;
        case Step::kFailed:
            ++fail;
            break;
        case Step::kSkipped:
            ++skip;
            break;
        default:
            ++stg;
            break;
        }
    }
    const int total = static_cast<int>(devices.size());
    const int settled = ok + fail + skip;

    std::string h;
    h += "<div id=\"dp-grid\"";
    if (!repoll_url.empty())
        h += " hx-get=\"" + esc(repoll_url) + "\" hx-trigger=\"load delay:900ms\" hx-swap=\"outerHTML\"";
    h += ">";

    h += "<div class=\"af-rhd\"><span class=\"art\">" + esc(dep.artifact_filename) +
         "</span> &middot; " + std::to_string(total) + (total == 1 ? " device" : " devices") +
         " &middot; " + std::to_string(settled) + "/" + std::to_string(total) + " settled &middot; " +
         esc(dep.status == "complete" ? "complete" : "deploying\xE2\x80\xA6") + "</div>";

    // KPI strip (aggregate-first; clickable filters).
    auto kpi = [](const char* cls, const char* key, int v, const char* l) {
        return "<div class=\"dp-kpi " + std::string(cls) + "\" data-b=\"" + key +
               "\" onclick=\"dpSet('" + key + "')\"><div class=\"v\">" + std::to_string(v) +
               "</div><div class=\"l\">" + l + "</div></div>";
    };
    h += "<div class=\"dp-kpis\">";
    h += "<div class=\"dp-kpi tot\"><div class=\"v\">" + std::to_string(total) +
         "</div><div class=\"l\">targeted</div></div>";
    h += kpi("ok", "ok", ok, "succeeded");
    if (run > 0)
        h += kpi("run", "run", run, "executing");
    if (stg > 0)
        h += kpi("stg", "stg", stg, "in-flight");
    if (fail > 0)
        h += kpi("fail", "fail", fail, "failed");
    if (skip > 0)
        h += kpi("skip", "skip", skip, "skipped");
    h += "</div>";

    // Progress bar.
    auto seg = [total](const char* cls, int n) {
        if (n <= 0 || total <= 0)
            return std::string();
        return "<i class=\"" + std::string(cls) + "\" style=\"width:" +
               std::to_string(n * 100.0 / total) + "%\"></i>";
    };
    h += "<div class=\"dp-bar\">" + seg("dp-seg-ok", ok) + seg("dp-seg-run", run) +
         seg("dp-seg-stg", stg) + seg("dp-seg-fail", fail) + seg("dp-seg-skip", skip) + "</div>";
    h += "<div class=\"dp-prog\">" + std::to_string(settled) + "/" + std::to_string(total) +
         " settled \xC2\xB7 " + std::to_string(ok) + " succeeded \xC2\xB7 " + std::to_string(fail) +
         " failed \xC2\xB7 " + std::to_string(skip) + " skipped" +
         (dep.status == "complete" ? "" : " \xC2\xB7 deploying\xE2\x80\xA6") + "</div>";

    // Device groups, problem-first: Failed, Skipped, Executing, In-flight, Succeeded.
    const std::pair<const char*, const char*> order[] = {
        {"fail", "Failed"}, {"skip", "Skipped"}, {"run", "Executing"},
        {"stg", "In-flight"}, {"ok", "Succeeded"},
    };
    for (const auto& [bkey, title] : order) {
        int n = 0;
        for (const auto& d : devices)
            if (std::string_view(disp_bucket(deployment::step_from_token(d.step)).key) == bkey)
                ++n;
        if (n == 0)
            continue;
        h += "<div class=\"af-grp\" data-bucket=\"" + std::string(bkey) + "\">";
        h += "<div class=\"af-grp-hd\">" + std::string(title) + " <span class=\"c\">(" +
             std::to_string(n) + ")</span></div>";
        int rendered = 0;
        for (const auto& d : devices) {
            if (std::string_view(disp_bucket(deployment::step_from_token(d.step)).key) != bkey)
                continue;
            if (rendered >= kRenderCapPerGroup) {
                h += "<div class=\"dp-more\">+ " + std::to_string(n - rendered) +
                     " more (not shown \xE2\x80\x94 counts above are exact)</div>";
                break;
            }
            ++rendered;
            const std::string host = d.hostname.empty() ? d.agent_id : d.hostname;
            h += "<div class=\"af-dev\" data-bucket=\"" + std::string(bkey) + "\">";
            h += "<span class=\"hn\"><a href=\"/hardware/ci?id=" + url_query_value(d.agent_id) + "\">" + esc(host) +
                 "</a></span>";
            h += "<span class=\"os\">" + esc(d.os.empty() ? "?" : d.os) + "</span>";
            h += "<span class=\"prog\">" + step_chips(d) + "</span></div>";
        }
        h += "</div>";
    }
    h += "<div class=\"af-empty\">No devices match this filter.</div>";

    if (repoll_url.empty() && dep.status == "complete")
        h += "<div class=\"gp-note\">Complete. <b>Succeeded</b> = exit 0; <b>Failed</b> = stage error "
             "or non-zero exit; <b>Skipped</b> = out of your scope at dispatch (never run). Click a "
             "KPI to filter.</div>";
    else if (repoll_url.empty())
        h += "<div class=\"gp-note\">This page paused polling. The deployment is durably saved but "
             "does <b>not</b> advance while this page is closed \xE2\x80\x94 re-open the deploy panel "
             "for this pre-flight run and click <b>Deploy go-cohort</b> again to resume it (it picks "
             "up the in-flight run, it does not start a second one).</div>";

    // CSP-safe inline filter JS — re-applies window.__dp on every poll swap.
    h += "<script>(function(){window.__dp=window.__dp||{b:'all'};var P=window.__dp;"
         "window.dpSet=function(b){P.b=(P.b===b?'all':b);window.dpApply();};"
         "window.dpApply=function(){var g=document.getElementById('dp-grid');if(!g)return;var vis=false;"
         "g.querySelectorAll('.af-grp').forEach(function(gr){var gb=gr.getAttribute('data-bucket');"
         "var s=(P.b==='all'||P.b===gb);gr.style.display=s?'':'none';if(s)vis=true;});"
         "g.querySelectorAll('.dp-kpi[data-b]').forEach(function(k){k.classList.toggle('sel',k.getAttribute('data-b')===P.b);});"
         "var e=g.querySelector('.af-empty');if(e)e.style.display=vis?'none':'';};"
         "window.dpApply();})();</script>";

    h += "</div>";
    return h;
}

std::string render_deploy_note(const std::string& message) {
    return "<div class=\"gp-placeholder\">" + esc(message) + "</div>";
}

} // namespace yuzu::server
