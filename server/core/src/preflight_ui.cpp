/// @file preflight_ui.cpp
/// PURE render functions for the `/auto` Pre-flight page. Dark-theme, htmx CORE
/// attrs only. Filtering is CSP-safe inline JS: a plain inline <script> (allowed by
/// `unsafe-inline`) plus `onclick` handlers — never `hx-on` (CSP blocks the
/// `new Function` it compiles). The script re-runs on every self-poll swap and
/// re-applies the operator's filter from a `window.__pf` global, so the bucket /
/// failure-type selection survives the outerHTML repoll. Every agent-supplied
/// string is HTML-escaped at render. The `.af-*` CSS is inlined ONCE in
/// render_auto_config (the config fragment loads with the page; the result fragment
/// only swaps a child). See preflight_routes.hpp.

#include "preflight_routes.hpp"

#include "preflight_parse.hpp" // kPreflightChecks, Verdict, Bucket
#include "web_utils.hpp"       // html_escape

#include <string>

namespace yuzu::server {

namespace {
std::string esc(const std::string& s) { return html_escape(s); }

const char* kAutoCss = R"CSS(<style>
.gp-wrap{max-width:1320px}
.af-cfg{border-top:1px solid #1a2c46;padding:.55rem 0;display:flex;gap:.6rem;align-items:end;flex-wrap:wrap}
.af-cfg:first-of-type{border-top:none}
.af-name{font-weight:600;color:#dce7f4;font-size:.82rem;min-width:150px}
.af-fld{display:flex;flex-direction:column;gap:.16rem}
.af-fld label{font-size:.66rem;color:#7f93ad}
.af-fld label.thr{color:#8fb4ec}
.af-cfg input,.af-cfg select{background:#0c1626;border:1px solid #2d4068;border-radius:.36rem;color:#cfdbe8;padding:.28rem .5rem;font-size:.78rem}
.af-cfg input[type=number]{width:6.5rem}
.af-tag{font-size:.58rem;color:#7f93ad;border:1px solid #25395a;border-radius:.5rem;padding:.02rem .35rem;margin-left:.4rem}
.af-note{color:#7f93ad;font-size:.72rem;margin:.2rem 0 .3rem}
.af-rail{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin:0 0 .7rem;padding-bottom:.55rem;border-bottom:1px solid #1a2c46}
.af-rail-lbl{font-size:.66rem;text-transform:uppercase;letter-spacing:.04em;color:#7f93ad;margin-right:.2rem}
.af-rail-keep{font-size:.62rem;color:#5d6f88;text-transform:none;letter-spacing:0}
.af-run-wrap{display:inline-flex;align-items:stretch}
.af-run{background:#0c1626;border:1px solid #25395a;border-radius:.5rem 0 0 .5rem;border-right:none;color:#cfe0f6;font-size:.72rem;padding:.22rem .55rem;cursor:pointer}
.af-run:hover{border-color:#3d7ad6;background:#0f1f37}
.af-run-x{background:#0c1626;border:1px solid #25395a;border-radius:0 .5rem .5rem 0;color:#7f93ad;font-size:.74rem;line-height:1;padding:0 .42rem;cursor:pointer}
.af-run-x:hover{border-color:#5a2323;background:#1f0e0e;color:#e57373}
.af-cfg-hd{display:flex;align-items:center;gap:.4rem;cursor:pointer;font-size:.78rem;font-weight:600;color:#9fb2cc;text-transform:uppercase;letter-spacing:.04em;padding:.2rem 0;user-select:none}
.af-cfg-hd:hover{color:#cfe0f6}
.af-cfg-hd .chev{font-size:.7rem;color:#7f93ad;transition:transform .12s}
.af-cfg-hd.af-collapsed .chev{transform:rotate(-90deg)}
#auto-cfg.af-hide{display:none}
.af-bdg.p{color:#7fcf9a;border-color:#235a3a;background:#0e1f16}
.af-dev .hn a{color:#6ea8e6;text-decoration:none;border-bottom:1px solid rgba(110,168,230,.35)}
.af-dev .hn a:hover{color:#9fc4f0;border-bottom-color:#9fc4f0}
/* results */
.af-rhd{font-size:.74rem;color:#7f93ad;margin-bottom:.5rem}
.af-rhd b{color:#dce7f4}
.af-pills{display:flex;gap:.55rem;flex-wrap:wrap;margin:.2rem 0 .8rem}
.af-pill{font-size:.94rem;font-weight:600;padding:.34rem .9rem;border-radius:.7rem;border:1px solid;cursor:pointer;user-select:none}
.af-pill.tot{color:#cfdbe8;border-color:#2d4068;background:#101f34}
.af-pill.go{color:#4ed27e;border-color:#235a3a;background:#10241a}
.af-pill.warn{color:#e0b85a;border-color:#5a4a23;background:#231d10}
.af-pill.nogo{color:#e57373;border-color:#5a2323;background:#241010}
.af-pill.inc{color:#8fb4ec;border-color:#33476b;background:#11243d}
.af-pill.sel{outline:2px solid currentColor;outline-offset:1px}
.af-chips{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin:0 0 .7rem}
.af-chips .lbl{font-size:.68rem;color:#7f93ad;margin-right:.1rem}
.af-chip{font-size:.7rem;padding:.12rem .5rem;border-radius:.5rem;border:1px solid #5a2323;background:#1c0f0f;color:#e9a6a6;cursor:pointer;user-select:none}
.af-chip.sel{background:#3a1414;color:#fff;border-color:#8a3a3a}
.af-grp{margin-bottom:.5rem}
.af-grp-hd{font-size:.72rem;font-weight:600;letter-spacing:.02em;color:#9fb2cc;padding:.3rem .1rem;border-bottom:1px solid #1a2c46;margin-bottom:.3rem;text-transform:uppercase}
.af-grp-hd .c{color:#7f93ad;font-weight:400}
.af-dev{display:flex;align-items:center;gap:.7rem;padding:.4rem .55rem;border:1px solid #14233a;border-radius:.42rem;margin-bottom:.34rem;background:#0c1626}
.af-dev .hn{font-weight:600;color:#dce7f4;font-size:.82rem;min-width:148px;word-break:break-all}
.af-dev .os{font-size:.66rem;color:#7f93ad;min-width:118px}
.af-dev .badges{display:flex;gap:.34rem;flex-wrap:wrap;flex:1}
.af-bdg{font-size:.66rem;padding:.06rem .42rem;border-radius:.42rem;border:1px solid;white-space:nowrap;font-variant-numeric:tabular-nums}
.af-bdg.f{color:#e57373;border-color:#5a2323;background:#1f0e0e}
.af-bdg.w{color:#e0b85a;border-color:#5a4a23;background:#1f1a0e}
.af-bdg.u{color:#7f93ad;border-color:#33476b;background:#101f34}
.af-bdg .v{opacity:.85;margin-left:.25rem}
.af-empty{font-size:.74rem;color:#7f93ad;padding:.3rem .1rem;display:none}
</style>)CSS";

// Verdict → badge css class.
const char* badge_class(preflight::Verdict v) {
    switch (v) {
    case preflight::Verdict::kPass:
        return "p";
    case preflight::Verdict::kFail:
        return "f";
    case preflight::Verdict::kWarn:
        return "w";
    default:
        return "u"; // unknown
    }
}

// Delegate to the canonical token map (preflight_parse.hpp) so the client-filter
// data-b attribute can never desync from the stored/wire token (#governance).
const char* bucket_key(preflight::Bucket b) { return preflight::bucket_token(b); }
} // namespace

std::string render_auto_rail(const std::vector<std::pair<std::string, std::string>>& recent) {
    std::string h = "<div id=\"auto-rail\" class=\"af-rail\">";
    h += "<span class=\"af-rail-lbl\">Recent runs<span class=\"af-rail-keep\"> &middot; kept 14 "
         "days</span></span>";
    if (recent.empty()) {
        h += "<span class=\"gp-mute\" style=\"font-size:.7rem\">none yet</span>";
    } else {
        for (const auto& [run_id, label] : recent) {
            h += "<span class=\"af-run-wrap\">";
            h += "<button class=\"af-run\" onclick=\"pfCollapseCfg()\" "
                 "hx-get=\"/fragments/auto/result?run=" +
                 esc(run_id) + "&amp;n=1\" hx-target=\"#auto-results\" hx-swap=\"innerHTML\">" +
                 esc(label) + "</button>";
            // Confirm-guarded delete (hx-confirm → native confirm(), CSP-safe).
            h += "<button class=\"af-run-x\" title=\"Delete run\" "
                 "hx-post=\"/fragments/auto/delete?run=" +
                 esc(run_id) +
                 "\" hx-confirm=\"Delete this pre-flight run? This cannot be undone.\" "
                 "hx-target=\"#auto-rail\" hx-swap=\"outerHTML\">&times;</button>";
            h += "</span>";
        }
    }
    h += "</div>";
    return h;
}

std::string render_auto_config(const std::vector<std::pair<std::string, std::string>>& groups,
                               const std::vector<std::pair<std::string, std::string>>& recent) {
    std::string h = kAutoCss;
    h += "<div class=\"gp-mute\" style=\"font-size:.76rem;margin-bottom:.6rem\">"
         "Configure the checks (parameters + thresholds), run across a cohort, and get a go/no-go "
         "grouped by device. Runs persist \xE2\x80\x94 reopen one below to revisit it.</div>";

    // Saved-runs rail (owner-scoped), its own swap target for the delete route.
    h += render_auto_rail(recent);

    // Collapsible configuration. Inline onclick (CSP-safe; never hx-on) toggles
    // #auto-cfg's visibility — hidden inputs still submit via the Run button's
    // hx-include, so collapsing never drops the config.
    h += "<div class=\"af-cfg-hd\" onclick=\"document.getElementById('auto-cfg')"
         ".classList.toggle('af-hide');this.classList.toggle('af-collapsed')\">"
         "<span class=\"chev\">&#9660;</span> Pre-flight configuration</div>";

    h += "<div id=\"auto-cfg\">";
    // Scope: name + group + OS filter + run window
    h += "<div class=\"af-cfg\">";
    h += "<span class=\"af-name\">Scope (cohort)</span>";
    h += "<div class=\"af-fld\"><label>Run name</label>"
         "<input name=\"name\" placeholder=\"e.g. AcmeVPN 4.2.0 rollout\" style=\"min-width:170px\"></div>";
    h += "<div class=\"af-fld\"><label>Management group</label><select name=\"group\">";
    h += "<option value=\"\">(all visible devices)</option>";
    for (const auto& [id, name] : groups)
        h += "<option value=\"" + esc(id) + "\">" + esc(name) + "</option>";
    h += "</select></div>";
    h += "<div class=\"af-fld\"><label>OS filter</label><select name=\"os_filter\">"
         "<option value=\"any\">Any OS</option><option value=\"windows\">Windows</option>"
         "<option value=\"linux\">Linux</option><option value=\"darwin\">macOS</option></select></div>";
    h += "<div class=\"af-fld\"><label>Run window \xE2\x80\x94 catch offline (min)</label>"
         "<input name=\"window\" type=\"number\" value=\"30\" style=\"width:6rem\"></div>";
    h += "</div>";
    h += "<div class=\"af-note\">The run keeps re-trying for the window, so a device that is offline at "
         "dispatch still reports if it reconnects in time; a device that never answers stays "
         "<b>incomplete</b>.</div>";

    // Target application (A) — name + min/max version
    h += "<div class=\"af-cfg\"><span class=\"af-name\">Target App</span>"
         "<div class=\"af-fld\"><label>App name</label>"
         "<input name=\"app_name\" placeholder=\"e.g. AcmeVPN\"></div>"
         "<div class=\"af-fld\"><label class=\"thr\">Min version</label>"
         "<input name=\"app_min\" placeholder=\"4.2.0\" style=\"width:6.5rem\"></div>"
         "<div class=\"af-fld\"><label class=\"thr\">Max version<span class=\"af-tag\">optional</span></label>"
         "<input name=\"app_max\" placeholder=\"4.9.99\" style=\"width:6.5rem\"></div></div>";

    // OS compatibility (D)
    h += "<div class=\"af-cfg\"><span class=\"af-name\">OS compatibility</span>"
         "<div class=\"af-fld\"><label class=\"thr\">Min OS version</label>"
         "<input name=\"os_min\" placeholder=\"10.0.19045\" style=\"width:9rem\"></div>"
         "<div class=\"af-fld\"><label class=\"thr\">Required arch</label>"
         "<select name=\"arch\"><option value=\"any\">any</option>"
         "<option value=\"x86_64\">x86_64</option><option value=\"arm64\">arm64</option>"
         "<option value=\"aarch64\">aarch64</option></select></div></div>";

    // Free disk (B)
    h += "<div class=\"af-cfg\"><span class=\"af-name\">Free disk</span>"
         "<div class=\"af-fld\"><label class=\"thr\">Min free (GiB)</label>"
         "<input name=\"min_gib\" type=\"number\" value=\"20\"></div>"
         "<div class=\"af-fld\"><label>Volume</label>"
         "<input name=\"volume\" placeholder=\"C:\\ or /\" style=\"width:6rem\"></div></div>";

    // Pending reboot (F)
    h += "<div class=\"af-cfg\"><span class=\"af-name\">Pending reboot</span>"
         "<div class=\"af-fld\"><label class=\"thr\">Policy</label>"
         "<select name=\"reboot\"><option value=\"warn\">Warn only</option>"
         "<option value=\"block\">Block if pending</option></select></div></div>";

    // Staged-artifact checks — later slice (shown disabled so the surface is honest)
    h += "<div class=\"af-cfg\" style=\"opacity:.5\"><span class=\"af-name\">Installer integrity"
         "<span class=\"af-tag\">later slice</span></span>"
         "<div class=\"af-fld\"><label>Installer + rollback + config backup</label>"
         "<input value=\"needs staged artifacts\" disabled style=\"min-width:220px\"></div></div>";

    h += "</div>"; // #auto-cfg

    h += "<div style=\"margin-top:.7rem\">"
         "<button class=\"gp-chip\" style=\"background:#3d7ad6;border-color:#3d7ad6;color:#fff;"
         "font-weight:600;cursor:pointer\" onclick=\"pfCollapseCfg()\" "
         "hx-post=\"/fragments/auto/run\" hx-include=\"#auto-cfg input, #auto-cfg select\" "
         "hx-target=\"#auto-results\" hx-swap=\"innerHTML\">Run pre-flight</button></div>";

    h += "<div id=\"auto-results\" style=\"margin-top:.9rem\">"
         "<div class=\"gp-placeholder\"><b>Configure and run</b>"
         "Results group by device as each one answers.</div></div>";

    // Deploy panel target (the ACT stage). Sibling of #auto-results so it persists
    // across the pre-flight grid's repolls; filled by the "Deploy go-cohort" button.
    h += "<div id=\"auto-deploy\" style=\"margin-top:.9rem\"></div>";

    // CSP-safe helper: collapse the config so the results (verdict + pills) rise
    // to the top. Called by Run and by each saved-run in the rail. Defined once
    // with the page; persists on window for the standalone rail re-render.
    h += "<script>window.pfCollapseCfg=function(){var c=document.getElementById('auto-cfg');"
         "if(c)c.classList.add('af-hide');var t=document.querySelector('.af-cfg-hd');"
         "if(t)t.classList.add('af-collapsed');};</script>";

    // ── Stage 3 · VERIFY — before/after app-perf evidence ──
    // A placeholder that loads the VERIFY config fragment on render. All VERIFY
    // logic lives in verify_routes/verify_ui; the /auto page only hosts it (one
    // fragment URL, no code coupling). The lifecycle after ASSESS (pre-flight) and
    // ACT (deploy): did the upgrade change how the same machines perform?
    h += "<div class=\"af-cfg-hd\" style=\"margin-top:1.6rem\">"
         "<span class=\"chev\">&#9660;</span> Verify &mdash; before / after performance</div>";
    h += "<div id=\"auto-verify\" hx-get=\"/fragments/auto/verify\" hx-trigger=\"load\" "
         "hx-swap=\"innerHTML\"><div class=\"gp-placeholder\">Loading verify&hellip;</div></div>";
    return h;
}

std::string render_auto_results(const std::vector<preflight::PreflightDeviceResult>& devices,
                                const std::string& config_summary, const std::string& scope_label,
                                const std::string& repoll_url, bool run_complete,
                                const std::string& run_id, const std::string& degrade_note) {
    using preflight::Bucket;
    using preflight::Verdict;

    int go = 0, warn = 0, nogo = 0, inc = 0;
    for (const auto& d : devices) {
        switch (d.bucket) {
        case Bucket::kPass:
            ++go;
            break;
        case Bucket::kFailed:
            ++nogo;
            break;
        case Bucket::kWarnOnly:
            ++warn;
            break;
        default:
            ++inc;
            break;
        }
    }
    const int total = static_cast<int>(devices.size());

    // "Failed by" counts, in catalogue order (only checks with ≥1 failing device).
    struct FailKind {
        std::string key, label;
        int count = 0;
    };
    std::vector<FailKind> fail_kinds;
    for (const auto& c : preflight::kPreflightChecks) {
        int n = 0;
        for (const auto& d : devices)
            for (const auto& ck : d.checks)
                if (ck.key == c.key && ck.verdict == Verdict::kFail)
                    ++n;
        if (n > 0)
            fail_kinds.push_back({c.key, c.label, n});
    }

    std::string h;
    h += "<div id=\"auto-grid\"";
    if (!repoll_url.empty())
        h += " hx-get=\"" + esc(repoll_url) +
             "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\"";
    h += ">";

    if (!degrade_note.empty())
        h += "<div class=\"result-degrade-banner\"><b>" + esc(degrade_note) + "</b></div>";

    h += "<div class=\"af-rhd\">Pre-flight &mdash; <b>" + esc(scope_label) + "</b>";
    if (!config_summary.empty())
        h += " &middot; " + esc(config_summary);
    h += "</div>";

    // Summary pills (clickable bucket filters; derived from `devices`).
    h += "<div class=\"af-pills\">";
    h += "<span class=\"af-pill tot\" data-b=\"all\" onclick=\"pfSetBucket('all')\">" +
         std::to_string(total) + (total == 1 ? " device" : " devices") + "</span>";
    h += "<span class=\"af-pill go\" data-b=\"go\" onclick=\"pfSetBucket('go')\">" +
         std::to_string(go) + " go-clean</span>";
    if (warn > 0)
        h += "<span class=\"af-pill warn\" data-b=\"warn\" onclick=\"pfSetBucket('warn')\">" +
             std::to_string(warn) + " warn-only</span>";
    if (nogo > 0) // gate like warn/incomplete — no alarming red "0 no-go" on a clean run
        h += "<span class=\"af-pill nogo\" data-b=\"nogo\" onclick=\"pfSetBucket('nogo')\">" +
             std::to_string(nogo) + " no-go</span>";
    if (inc > 0)
        h += "<span class=\"af-pill inc\" data-b=\"inc\" onclick=\"pfSetBucket('inc')\">" +
             std::to_string(inc) + " incomplete</span>";
    h += "</div>";

    // ACT stage — "Deploy go-cohort": as soon as there is a go-cohort (≥1 go /
    // warn-only device), offer to stage + execute an installer on exactly the
    // devices cleared SO FAR — the button appears with the first result, it does not
    // wait for the run to finish (the go-cohort only ever contains fully-evaluated,
    // cleared devices, so a mid-run deploy is safe). The count updates as more
    // devices clear. Loads the deploy panel into the sibling #auto-deploy container
    // (outside #auto-grid, so it persists across this grid's repolls).
    if ((go + warn) > 0 && !run_id.empty()) {
        h += "<div style=\"margin:.1rem 0 .8rem\">"
             "<button class=\"gp-chip\" style=\"background:#1f7a47;border-color:#1f7a47;color:#fff;"
             "font-weight:600;cursor:pointer\" hx-get=\"/fragments/auto/deploy?run=" +
             esc(run_id) +
             "\" hx-target=\"#auto-deploy\" hx-swap=\"innerHTML\">Deploy go-cohort (" +
             std::to_string(go + warn) + ") \xE2\x86\x92</button></div>";
    }

    // "Failed by" chips (narrow the Failed group to one failure type).
    if (!fail_kinds.empty()) {
        h += "<div class=\"af-chips\"><span class=\"lbl\">Failed by:</span>";
        for (const auto& fk : fail_kinds)
            h += "<span class=\"af-chip\" data-t=\"" + esc(fk.key) + "\" onclick=\"pfSetType('" +
                 esc(fk.key) + "')\">" + esc(fk.label) + " \xC3\x97" + std::to_string(fk.count) +
                 "</span>";
        h += "</div>";
    }

    // Groups, in display order: Pass, Failed, Warn-only, Incomplete.
    const std::pair<Bucket, const char*> order[] = {
        {Bucket::kPass, "Pass"},
        {Bucket::kFailed, "Failed"},
        {Bucket::kWarnOnly, "Warn-only"},
        {Bucket::kIncomplete, "Incomplete"},
    };
    for (const auto& [bk, title] : order) {
        int n = 0;
        for (const auto& d : devices)
            if (d.bucket == bk)
                ++n;
        if (n == 0)
            continue;
        h += "<div class=\"af-grp\" data-bucket=\"" + std::string(bucket_key(bk)) + "\">";
        h += "<div class=\"af-grp-hd\">" + std::string(title) + " <span class=\"c\">(" +
             std::to_string(n) + ")</span></div>";
        for (const auto& d : devices) {
            if (d.bucket != bk)
                continue;
            // data-fails = space-joined keys of the device's failing checks.
            std::string fails;
            for (const auto& ck : d.checks)
                if (ck.verdict == Verdict::kFail)
                    fails += (fails.empty() ? "" : " ") + ck.key;
            const std::string host = d.hostname.empty() ? d.agent_id : d.hostname;
            // OS line: family + the os-version check value when available.
            std::string osline = d.os.empty() ? "?" : d.os;
            for (const auto& ck : d.checks)
                if (ck.key == "osver" && !ck.value.empty() && ck.value != "\xE2\x80\x94") {
                    osline += " \xC2\xB7 " + ck.value;
                    break;
                }
            h += "<div class=\"af-dev\" data-bucket=\"" + std::string(bucket_key(bk)) +
                 "\" data-fails=\"" + esc(fails) + "\">";
            // Device name links into the per-device view (/hardware/ci?id=).
            h += "<span class=\"hn\"><a href=\"/hardware/ci?id=" + esc(d.agent_id) + "\">" + esc(host) +
                 "</a></span>";
            h += "<span class=\"os\">" + esc(osline) + "</span><span class=\"badges\">";
            // Every check's status (pass = green), so the full per-device picture
            // is visible, not just the problems.
            for (const auto& ck : d.checks) {
                const std::string show =
                    (ck.verdict == Verdict::kUnknown && ck.value.empty()) ? "\xE2\x80\x94" : ck.value;
                h += "<span class=\"af-bdg " + std::string(badge_class(ck.verdict)) + "\">" +
                     esc(ck.label);
                if (!show.empty())
                    h += "<span class=\"v\">" + esc(show) + "</span>";
                h += "</span>";
            }
            h += "</span></div>";
        }
        h += "</div>";
    }

    h += "<div class=\"af-empty\">No devices match this filter.</div>";

    if (!repoll_url.empty())
        h += "<div class=\"gp-mute\" style=\"font-size:.66rem;margin-top:.3rem\">Polling devices&hellip;</div>";
    else if (run_complete)
        h += "<div class=\"gp-note\">Complete. A device is <b>no-go</b> if any blocking check fails, "
             "<b>warn-only</b> if it has warnings but no blocking fail, <b>incomplete</b> until every "
             "check answers. Click a pill to filter buckets; click a failure-type chip to narrow the "
             "failed group.</div>";
    else
        h += "<div class=\"gp-note\">Still running in the background \xE2\x80\x94 the run keeps catching "
             "devices that reconnect within its window. This page paused polling; reopen the run from "
             "<b>Recent runs</b> to refresh.</div>";

    // CSP-safe inline filter JS — re-runs on every poll swap, re-applies window.__pf.
    h += "<script>(function(){window.__pf=window.__pf||{b:'all',t:null};var P=window.__pf;"
         "window.pfSetBucket=function(b){P.b=(P.b===b?'all':b);if(b!=='nogo')P.t=null;window.pfApply();};"
         "window.pfSetType=function(t){P.t=(P.t===t?null:t);P.b='nogo';window.pfApply();};"
         "window.pfApply=function(){var g=document.getElementById('auto-grid');if(!g)return;var vis=false;"
         "g.querySelectorAll('.af-grp').forEach(function(gr){var gb=gr.getAttribute('data-bucket');"
         "var sg=(P.b==='all'||P.b===gb);var sh=0;"
         "gr.querySelectorAll('.af-dev').forEach(function(r){var v=sg;"
         "if(v&&gb==='nogo'&&P.t){v=(' '+(r.getAttribute('data-fails')||'')+' ').indexOf(' '+P.t+' ')>=0;}"
         "r.style.display=v?'':'none';if(v){sh++;vis=true;}});"
         "gr.style.display=(sg&&sh>0)?'':'none';});"
         "g.querySelectorAll('.af-pill[data-b]').forEach(function(p){p.classList.toggle('sel',p.getAttribute('data-b')===P.b);});"
         "g.querySelectorAll('.af-chip[data-t]').forEach(function(c){c.classList.toggle('sel',c.getAttribute('data-t')===P.t);});"
         "var e=g.querySelector('.af-empty');if(e)e.style.display=vis?'none':'';};"
         "window.pfApply();})();</script>";

    h += "</div>";
    return h;
}

std::string render_auto_note(const std::string& message) {
    return "<div class=\"gp-placeholder\">" + esc(message) + "</div>";
}

} // namespace yuzu::server
