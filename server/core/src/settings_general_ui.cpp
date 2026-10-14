// System "General and appearance" page (GET /settings/general), baked once at static init.
//
// Server-rendered and HTMX-first. The page JS is plain, CSP-safe and delegated (no `hx-on`, no
// inline `on*` attributes, no `innerHTML` of server data, no `eval`): htmx loads the panels,
// and the only script work is the browser-local density preference and the runtime form's
// confirm-then-PUT flow, which has to be `fetch()` because PUT /api/config/{key} takes a JSON
// body and `hx-put` would send a form body.
//
// MSVC rejects a raw string literal over 16,380 bytes (C2026). The template is assembled at
// static init from named raw parts, each pinned well under that (15,000) below, and the
// concatenated std::string is not a literal at all.

#include "app_shell.hpp"

#include <string>

namespace {

// ── Head: page frame, plus the small subset of the monolith's page-local CSS that the two
// hosted fragments (server-config, analytics) need. The monolith keeps its own copy; nothing
// is extracted from it (the retirement of its panels owns that).
constexpr char kHead[] = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — General and appearance</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    /* Page frame */
    .pg { padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px; }
    .sep { border-top: 1px solid var(--line); }
    .htmx-indicator { display: none; }

    /* Hosted fragments (rendered by existing routes; classes they carry) */
    code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .muted { color: var(--mut); }
    .section-intro { margin: 0 0 12px; max-width: 80ch; font-size: 13px; color: var(--mut); }
    .sub-head { margin: 0 0 8px; font-size: 13px; font-weight: 600; color: var(--ink); }
    .section-note { margin: 12px 0 0; font-size: 12.5px; color: var(--mut); }
    .hosted-scroll { overflow-x: auto; }
    .form-row { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
    .form-row:last-child { margin-bottom: 0; }
    .form-row > label:first-child { flex: 0 0 180px; font-size: 13px; color: var(--ink2); font-weight: 500; }
    .form-row code, .form-row .file-name, .form-row .muted { min-width: 0; overflow-wrap: anywhere; }
    .file-name { font-size: 12.5px; color: var(--mut); font-family: var(--mds-font-family-mono); }
    .role-badge { display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 3px;
      font-size: 12.5px; font-weight: 500; white-space: nowrap; background: var(--surface2); color: var(--mut); }
    .role-ok { background: var(--mds-color-bg-success-tinted); color: var(--ok); }
    .role-warn { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .role-bad { background: var(--mds-color-bg-error-tinted); color: var(--bad); }
    .user-table { width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--line);
      border-radius: var(--rad-panel); font-size: 13.5px; overflow: hidden; }
    .user-table th { text-align: left; padding: 8px 12px; white-space: nowrap; background: var(--surface2);
      border-bottom: 1px solid var(--line); color: var(--mut); font-size: 12.5px; font-weight: 500; }
    .user-table td { padding: var(--cell-y) 12px; border-bottom: 1px solid var(--line); color: var(--ink2);
      vertical-align: middle; overflow-wrap: anywhere; }
    .user-table td:first-child { white-space: nowrap; }
    .user-table tbody tr:last-child td { border-bottom: 0; }
    .user-table tbody tr:hover td { background: var(--surface2); }

    /* Runtime form and its feedback (the feedback node is a sibling of the reloading section) */
    .gen-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .field-err { color: var(--bad); font-size: 12.5px; }
    .fbwrap { padding: 0 16px; }
    .fbwrap:not(:empty) { padding-bottom: 16px; }
    .fbwrap .alert { margin: 12px 0 0; }
    .fbwrap .feedback { font-size: 13px; margin-top: 8px; }
    .fbwrap .feedback:first-child { margin-top: 12px; }
    .feedback-ok { color: var(--ok); }
    .feedback-error { color: var(--bad); }

    /* Recent events */
    .counts { display: flex; flex-wrap: wrap; gap: 6px 24px; margin-bottom: 12px; }
    .counts .unk { color: var(--bad); }
    .nosink-note { margin-bottom: 12px; }
    .tbox { border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .tbox td.et { white-space: normal; overflow-wrap: anywhere; max-width: 360px; }
    .tbox td.et code { color: var(--ink); }
    .tbox td.tm { color: var(--mut); font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .evt-foot { margin-top: 8px; }
    .empty-state { padding: 24px 16px; text-align: center; color: var(--mut);
      border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .empty-state b { display: block; color: var(--ink); font-weight: 500; }
    .off-note { margin: 0; }
    @media (max-width: 820px) { .pg { padding: 16px; } .form-row { flex-wrap: wrap; } }
  </style>
</head>
)HTM";

// ── Body: Appearance, Server (runtime form + the read-only server table), Analytics.
constexpr char kBody[] = R"HTM(<body>

<!--yuzu:shell--><!--/yuzu:shell-->

<main class="pg">
  <div class="page-header"><div>
    <h1>General and appearance</h1>
    <p class="subtitle">Agent timeout and logging, event collection, and table density in this browser.</p>
  </div></div>

  <section class="panel" id="appearance-section" aria-labelledby="h-appearance">
    <div class="hd"><h2 id="h-appearance">Appearance</h2><span class="sub">Saved in this browser</span></div>
    <div class="form">
      <div class="fld">
        <span class="lb" id="lb-scheme">Colour scheme</span>
        <div class="pals"><div class="pal" role="group" aria-labelledby="lb-scheme">
          <span class="sw-row" aria-hidden="true"><span class="swatch s-bg"></span><span class="swatch s-surface"></span><span class="swatch s-raise"></span><span class="swatch s-primary"></span><span class="swatch s-hl"></span><span class="swatch s-ok"></span></span>
          <b>Slate <span class="pill idle">Current</span></b>
          <small>Dark theme. Cool blue-grey with a blue accent.</small>
        </div></div>
        <span class="hint">Slate is the only colour scheme.</span>
      </div>
      <div class="fld">
        <span class="lb" id="lb-density">Density</span>
        <div class="seg" role="radiogroup" aria-labelledby="lb-density">
          <label><input type="radio" name="density" value="comfortable" checked>Comfortable</label>
          <label><input type="radio" name="density" value="compact">Compact</label>
        </div>
        <span class="hint">Compact shows more rows per screen. Applies to the results table on the Dashboard.</span>
        <span class="hint" id="density-blocked" role="status" hidden>This browser blocked saving the setting, so it applies until you leave this page.</span>
      </div>
    </div>
    <div class="pb sep">
      <div class="prev"><table id="prev-table" class="comfortable">
        <thead><tr><th>Device</th><th>Status</th><th>Output</th></tr></thead>
        <tbody>
          <tr><td><b>Sample device 1</b></td><td><span class="pill ok">Success</span></td><td>Sample output</td></tr>
          <tr><td><b>Sample device 2</b></td><td><span class="pill warn">Warning</span></td><td>Sample output</td></tr>
          <tr><td><b>Sample device 3</b></td><td><span class="pill bad">Failed</span></td><td>Sample output</td></tr>
        </tbody></table></div>
      <span class="hint">Sample rows</span>
    </div>
  </section>

  <section class="panel" id="server-section" aria-labelledby="h-server">
    <div class="hd"><h2 id="h-server">Server</h2><span class="sub">Settings applied by this server process</span></div>
    <div id="general-runtime-section"
         hx-get="/fragments/settings/general-runtime"
         hx-trigger="load, refreshGeneralRuntime"
         hx-swap="innerHTML"><div class="pb muted">Loading...</div></div>
    <div id="general-runtime-feedback" class="fbwrap" aria-live="polite"></div>
    <div class="pb sep">
      <div class="sub-head">Server configuration</div>
      <p class="section-intro">Network listeners, session limits, and rate limiting. These values are set at server startup via CLI flags or environment variables. Agent heartbeat timeout and log level can be changed above.</p>
      <div id="server-config-section" class="hosted-scroll"
           hx-get="/fragments/settings/server-config"
           hx-trigger="load"
           hx-swap="innerHTML"><span class="muted">Loading...</span></div>
    </div>
  </section>

  <section class="panel" id="analytics-wrap" aria-labelledby="h-analytics">
    <div class="hd"><h2 id="h-analytics">Analytics</h2><span class="sub">Event collection</span></div>
    <div class="pb">
      <p class="section-intro">Event collection. Operational events (agent connections, command runs, sign-ins) are buffered in the server database and forwarded only to the sinks listed here. Set at startup with <code>--no-analytics</code>.</p>
      <div id="analytics-section" class="hosted-scroll"
           hx-get="/fragments/settings/analytics"
           hx-trigger="load"
           hx-swap="innerHTML"><span class="muted">Loading...</span></div>
    </div>
    <div class="pb sep">
      <div class="sub-head">Recent events</div>
      <div id="analytics-events-section"
           hx-get="/fragments/settings/analytics-events"
           hx-trigger="load"
           hx-swap="innerHTML"><span class="muted">Loading...</span></div>
    </div>
  </section>
</main>

<div id="toast-container" class="toast-container"></div>
)HTM";

// ── Script: toasts, 401 handling, density, and the confirm-then-PUT runtime form flow.
constexpr char kScript[] = R"HTM(<script>
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }

  /* Toast (server text only ever reaches the DOM through textContent) */
  function toast(message, level) {
    var c = $('toast-container');
    if (!c) return;
    var t = document.createElement('div');
    t.className = 'toast toast-' + (level || 'info');
    t.textContent = message;
    c.appendChild(t);
    setTimeout(function () { t.remove(); }, level === 'error' ? 8000 : 4000);
  }

  /* An expired session leaves a load-triggered panel on "Loading...": go to sign-in instead. */
  document.body.addEventListener('htmx:responseError', function (e) {
    var x = e.detail && e.detail.xhr;
    if (x && x.status === 401) window.location.href = '/login';
  });

  /* Density: the one real preference. Browser-local, Dashboard results table only. Every
     storage access is guarded (a private window throws) and the value is whitelisted on read. */
  var DENSITY_KEY = 'yuzu-table-density';
  function readDensity() {
    try { return window.localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable'; }
    catch (err) { return 'comfortable'; }
  }
  function paintDensity(v) {
    var t = $('prev-table');
    if (t) { t.classList.remove('compact', 'comfortable'); t.classList.add(v); }
    var r = document.querySelector('input[name=density][value=' + v + ']');
    if (r) r.checked = true;
  }
  paintDensity(readDensity());
  document.addEventListener('change', function (e) {
    var t = e.target;
    if (!t || t.name !== 'density') return;
    var v = t.value === 'compact' ? 'compact' : 'comfortable';
    var saved = true;
    try { window.localStorage.setItem(DENSITY_KEY, v); } catch (err) { saved = false; }
    paintDensity(v);
    var note = $('density-blocked');
    if (note) note.hidden = saved;
  });

  /* Runtime form. Two keys only; each is a PUT with a JSON body of a digit/level string. */
  var LL_WARN = 'At warn and above this server stops writing its info-level lines, including sign-in, session and API-token created/revoked lines that a log shipper or SIEM may rely on. Lines not written are not recoverable. The level is stored and re-applied at every restart, over --log-level. Change it?';
  function hbText(n, now, qual) {
    var t = 'Agents connected directly to this server that send nothing for more than ' + n +
      ' seconds are disconnected and shown offline at the next sweep (about every 15 seconds). It is ' +
      now + ' seconds now' + (qual ? ' (' + qual + ')' : '') +
      '. Agents behind a gateway and other server replicas are not affected by this setting.';
    if (n < 30) t += ' ' + n + ' seconds is below the default agent heartbeat interval (30 s): every directly connected agent will be disconnected repeatedly.';
    if (n > now) t += ' A connection that dies without closing will take up to ' + n + ' seconds to be noticed.';
    return t + ' Change it?';
  }

  function fbClear() { var f = $('general-runtime-feedback'); if (f) f.textContent = ''; return f; }
  function fbLine(text, cls) {
    var f = $('general-runtime-feedback');
    if (!f) return;
    var p = document.createElement('p');
    p.className = 'feedback ' + (cls || '');
    p.textContent = text;
    f.appendChild(p);
  }
  function fbAuditBanner() {
    var f = $('general-runtime-feedback');
    if (!f) return;
    var d = document.createElement('div');
    d.className = 'alert alert-error';
    d.setAttribute('role', 'alert');
    d.textContent = 'Audit write failed. The change was applied, but the audit log could not record it.';
    f.appendChild(d);
  }

  function errText(status, parsed) {
    if (status === 401) return 'Your session has expired. Sign in again.';
    return parsed || ('The server answered ' + status + '.');
  }
  function put(key, value) {
    return fetch('/api/config/' + key, {
      method: 'PUT', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: value })
    }).then(function (r) {
      var audit = r.headers.get('Sec-Audit-Failed') !== null;
      return r.text().then(function (t) {
        var msg = '';
        try {
          var d = JSON.parse(t);
          msg = (d && d.error && d.error.message) || (d && typeof d.error === 'string' ? d.error : '');
        } catch (err) { /* not JSON: use the status */ }
        return { ok: r.ok, status: r.status, msg: msg, audit: audit };
      });
    }, function () { return { ok: false, status: 0, msg: 'Could not reach the server.', audit: false }; });
  }
  /* The live value immediately before the heartbeat confirm, so the dialog's "now" is current. */
  function liveHeartbeat() {
    return fetch('/api/config', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var n = d && d.config ? parseInt(d.config.heartbeat_timeout, 10) : NaN;
        return isNaN(n) ? null : n;
      }, function () { return null; });
  }

  document.addEventListener('input', function (e) {
    var f = e.target && e.target.form;
    if (!f || f.id !== 'general-runtime-form') return;
    var hb = f.elements.heartbeat_timeout, ll = f.elements.log_level, save = $('gen-save');
    var err = $('gen-heartbeat-err');
    if (err) err.hidden = true;
    if (save) save.disabled = hb.value.trim() === f.dataset.loadedHeartbeat && ll.value === f.dataset.loadedLogLevel;
  });

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || f.id !== 'general-runtime-form') return;
    e.preventDefault();
    var hb = f.elements.heartbeat_timeout, ll = f.elements.log_level, save = $('gen-save');
    var v = hb.value.trim(), loadedHb = f.dataset.loadedHeartbeat, loadedLl = f.dataset.loadedLogLevel;
    var hbChanged = v !== loadedHb, llChanged = ll.value !== loadedLl;
    if (!hbChanged && !llChanged) return;
    if (hbChanged && (!/^[0-9]+$/.test(v) || parseInt(v, 10) < 1)) {
      var err = $('gen-heartbeat-err');
      if (err) err.hidden = false;
      return;
    }
    var n = hbChanged ? parseInt(v, 10) : 0;
    var lvl = ll.value;
    if (save) save.disabled = true;
    fbClear();

    function gateLogLevel() {
      if (llChanged && (lvl === 'warn' || lvl === 'error') && !window.confirm(LL_WARN)) return false;
      return true;
    }
    function run() {
      var steps = [];
      if (hbChanged) steps.push(['heartbeat_timeout', String(n), 'Heartbeat timeout']);
      if (llChanged) steps.push(['log_level', lvl, 'Log level']);
      var auditFailed = false;
      (function next(i) {
        if (i === steps.length) {
          if (auditFailed) fbAuditBanner();
          if (window.htmx) window.htmx.trigger($('general-runtime-section'), 'refreshGeneralRuntime');
          return;
        }
        put(steps[i][0], steps[i][1]).then(function (r) {
          if (r.ok) {
            fbLine(steps[i][2] + ' saved.', 'feedback-ok');
            auditFailed = auditFailed || r.audit;
          } else {
            fbLine(steps[i][2] + ' failed: ' + errText(r.status, r.msg), 'feedback-error');
          }
          next(i + 1);
        });
      })(0);
    }

    if (!hbChanged) {
      if (!gateLogLevel()) { if (save) save.disabled = false; return; }
      run();
      return;
    }
    liveHeartbeat().then(function (live) {
      var now = live === null ? parseInt(loadedHb, 10) : live;
      var qual = '';
      if (live === null) qual = 'could not re-check the current value';
      else if (live !== parseInt(loadedHb, 10)) qual = 'changed since you opened this page';
      if (!window.confirm(hbText(n, now, qual))) { fbLine('No changes were saved.', ''); if (save) save.disabled = false; return; }
      if (!gateLogLevel()) { fbLine('No changes were saved.', ''); if (save) save.disabled = false; return; }
      run();
    });
  });
})();
</script>
</body>
</html>
)HTM";

// Each part is a raw-string literal; pin them well under MSVC's 16,380-byte limit.
static_assert(sizeof(kHead) < 15000, "kHead exceeds the MSVC raw-literal ceiling");
static_assert(sizeof(kBody) < 15000, "kBody exceeds the MSVC raw-literal ceiling");
static_assert(sizeof(kScript) < 15000, "kScript exceeds the MSVC raw-literal ceiling");

std::string assemble() {
    std::string page;
    page.reserve(sizeof(kHead) + sizeof(kBody) + sizeof(kScript));
    page += kHead;
    page += kBody;
    page += kScript;
    return page;
}

} // namespace

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kSettingsGeneralHtml = yuzu::server::shell::bake(
    assemble().c_str(), {.active_key = "settings-general",
                         .title = "General and appearance",
                         .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
