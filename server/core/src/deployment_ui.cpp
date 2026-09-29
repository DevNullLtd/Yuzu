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

const char* kDeployCss = R"CSS(<style>
.dp-note{color:#7f93ad;font-size:.72rem;margin:.2rem 0 .4rem}
.dp-cohort{font-size:.72rem;color:#54c2d6;background:#0c1e26;border:1px solid #1d4350;border-radius:.4rem;padding:.4rem .6rem;margin:.1rem 0 .6rem}
.dp-cfg{border-top:1px solid #1a2c46;padding:.55rem 0;display:flex;gap:.6rem;align-items:end;flex-wrap:wrap}
.dp-cfg:first-of-type{border-top:none}
.dp-name{font-weight:600;color:#dce7f4;font-size:.82rem;min-width:90px}
.dp-fld{display:flex;flex-direction:column;gap:.16rem}
.dp-fld label{font-size:.66rem;color:#7f93ad}
.dp-cfg input{background:#0c1626;border:1px solid #2d4068;border-radius:.36rem;color:#cfdbe8;padding:.28rem .5rem;font-size:.76rem;font-family:ui-monospace,Consolas,monospace}
.dp-tag{font-size:.58rem;color:#7f93ad;border:1px solid #25395a;border-radius:.5rem;padding:.02rem .35rem;margin-left:.4rem}
.dp-warn{font-size:.72rem;color:#e9c98a;background:#231d10;border:1px solid #5a4a23;border-radius:.4rem;padding:.4rem .6rem;margin:.6rem 0}
.dp-rhd{font-size:.74rem;color:#7f93ad;margin-bottom:.5rem}
.dp-rhd b{color:#dce7f4}
.dp-rhd .art{font-family:ui-monospace,Consolas,monospace;color:#9fb2cc}
.dp-kpis{display:flex;gap:.55rem;flex-wrap:wrap;margin:.1rem 0 .5rem}
.dp-kpi{border:1px solid #2d4068;border-radius:.6rem;padding:.4rem .75rem;min-width:78px;background:#101f34;cursor:pointer;user-select:none}
.dp-kpi .v{font-size:1.3rem;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
.dp-kpi .l{font-size:.62rem;color:#7f93ad;text-transform:uppercase;letter-spacing:.03em;margin-top:.2rem}
.dp-kpi.sel{outline:2px solid currentColor;outline-offset:1px}
.dp-kpi.tot .v{color:#fff} .dp-kpi.ok .v{color:#4ed27e} .dp-kpi.run .v{color:#54c2d6}
.dp-kpi.stg .v{color:#8fb4ec} .dp-kpi.fail .v{color:#e57373} .dp-kpi.skip .v{color:#7f93ad}
.dp-bar{height:.5rem;border-radius:.3rem;overflow:hidden;display:flex;background:#0c1626;border:1px solid #1a2c46;margin:.3rem 0}
.dp-bar i{display:block;height:100%}
.dp-seg-ok{background:#4ed27e}.dp-seg-run{background:#54c2d6}.dp-seg-stg{background:#3d6fb0}.dp-seg-fail{background:#e57373}.dp-seg-skip{background:#33476b}
.dp-prog{font-size:.7rem;color:#7f93ad;font-variant-numeric:tabular-nums;margin-bottom:.6rem}
.dp-grp{margin-bottom:.5rem}
.dp-grp-hd{font-size:.72rem;font-weight:600;letter-spacing:.02em;color:#9fb2cc;padding:.3rem .1rem;border-bottom:1px solid #1a2c46;margin-bottom:.3rem;text-transform:uppercase}
.dp-grp-hd .c{color:#7f93ad;font-weight:400}
.dp-dev{display:flex;align-items:center;gap:.7rem;padding:.4rem .55rem;border:1px solid #14233a;border-radius:.42rem;margin-bottom:.34rem;background:#0c1626}
.dp-dev .hn{font-weight:600;color:#dce7f4;font-size:.82rem;min-width:148px;word-break:break-all}
.dp-dev .hn a{color:#6ea8e6;text-decoration:none;border-bottom:1px solid rgba(110,168,230,.35)}
.dp-dev .os{font-size:.66rem;color:#7f93ad;min-width:118px}
.dp-dev .prog{display:flex;align-items:center;gap:.34rem;flex:1;flex-wrap:wrap}
.dp-step{font-size:.64rem;padding:.06rem .42rem;border-radius:.42rem;border:1px solid;white-space:nowrap}
.dp-step.done{color:#4ed27e;border-color:#235a3a;background:#0e1f16}
.dp-step.act{color:#54c2d6;border-color:#1d4350;background:#0c1e26}
.dp-step.wait{color:#7f93ad;border-color:#33476b;background:#101f34}
.dp-step.err{color:#e57373;border-color:#5a2323;background:#1f0e0e}
.dp-arrow{color:#36507e;font-size:.66rem}
.dp-detail{font-size:.64rem;color:#7f93ad;word-break:break-all}
.dp-detail.bad{color:#e57373}
.dp-skip{font-size:.66rem;color:#e0b85a}
.dp-more{font-size:.66rem;color:#7f93ad;padding:.2rem .1rem}
.dp-empty{font-size:.74rem;color:#7f93ad;padding:.3rem .1rem;display:none}
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
    h += "<div class=\"dp-cohort\">\xE2\x86\x92 Deploys to the <b>" + std::to_string(cohort) +
         "</b> device" + (cohort == 1 ? "" : "s") + " this pre-flight cleared (" +
         std::to_string(go_count) + " go-clean + " + std::to_string(warn_count) +
         " warn-only). No-go and incomplete devices are excluded.</div>";

    h += "<div id=\"deploy-cfg\">";
    h += "<input type=\"hidden\" name=\"run\" value=\"" + esc(run_id) + "\">";
    h += "<div class=\"dp-cfg\"><span class=\"dp-name\">Artifact</span>"
         "<div class=\"dp-fld\"><label>Download URL</label>"
         "<input name=\"url\" placeholder=\"https://repo/pkg.msi\" style=\"min-width:300px\"></div></div>";
    h += "<div class=\"dp-cfg\">"
         "<div class=\"dp-fld\"><label>Filename</label>"
         "<input name=\"filename\" placeholder=\"pkg.msi\" style=\"min-width:160px\"></div>"
         "<div class=\"dp-fld\"><label>SHA-256</label>"
         "<input name=\"sha256\" placeholder=\"64 hex chars\" style=\"min-width:230px\"></div>"
         "<div class=\"dp-fld\"><label>Install args<span class=\"dp-tag\">optional</span></label>"
         "<input name=\"args\" placeholder=\"/qn /norestart\" style=\"min-width:150px\"></div></div>";

    h += "</div>"; // #deploy-cfg

    h += "<div class=\"dp-warn\">\xE2\x9A\xA0 This <b>runs an installer</b> on every cohort device. "
         "Execute is dispatched <b>once per device</b> (claimed before dispatch \xE2\x80\x94 safe under "
         "reload / agent re-poll). A device you no longer have scope to is <b>skipped</b>, never run.</div>";

    // Confirm-guarded (hx-confirm → native confirm(), CSP-safe). Cohort size + run
    // name are baked in at render; the artifact filename is visible in the form.
    h += "<button class=\"gp-chip\" style=\"background:#1f7a47;border-color:#1f7a47;color:#fff;"
         "font-weight:600;cursor:pointer\" "
         "hx-post=\"/fragments/auto/deploy/run\" hx-include=\"#deploy-cfg input\" "
         "hx-confirm=\"Deploy to " +
         std::to_string(cohort) + " device" + (cohort == 1 ? "" : "s") + " from &quot;" +
         esc(run_name.empty() ? std::string("this pre-flight run") : run_name) +
         "&quot;? This runs the installer on each device and cannot be undone.\" "
         "hx-target=\"#auto-deploy-grid\" hx-swap=\"innerHTML\">Stage + deploy to cohort\xE2\x80\xA6</button>";

    h += "<div id=\"auto-deploy-grid\" style=\"margin-top:.7rem\"></div>";
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

    h += "<div class=\"dp-rhd\"><span class=\"art\">" + esc(dep.artifact_filename) +
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
        h += "<div class=\"dp-grp\" data-bucket=\"" + std::string(bkey) + "\">";
        h += "<div class=\"dp-grp-hd\">" + std::string(title) + " <span class=\"c\">(" +
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
            h += "<div class=\"dp-dev\" data-bucket=\"" + std::string(bkey) + "\">";
            h += "<span class=\"hn\"><a href=\"/hardware/ci?id=" + esc(d.agent_id) + "\">" + esc(host) +
                 "</a></span>";
            h += "<span class=\"os\">" + esc(d.os.empty() ? "?" : d.os) + "</span>";
            h += "<span class=\"prog\">" + step_chips(d) + "</span></div>";
        }
        h += "</div>";
    }
    h += "<div class=\"dp-empty\">No devices match this filter.</div>";

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
         "g.querySelectorAll('.dp-grp').forEach(function(gr){var gb=gr.getAttribute('data-bucket');"
         "var s=(P.b==='all'||P.b===gb);gr.style.display=s?'':'none';if(s)vis=true;});"
         "g.querySelectorAll('.dp-kpi[data-b]').forEach(function(k){k.classList.toggle('sel',k.getAttribute('data-b')===P.b);});"
         "var e=g.querySelector('.dp-empty');if(e)e.style.display=vis?'none':'';};"
         "window.dpApply();})();</script>";

    h += "</div>";
    return h;
}

std::string render_deploy_note(const std::string& message) {
    return "<div class=\"gp-placeholder\">" + esc(message) + "</div>";
}

} // namespace yuzu::server
