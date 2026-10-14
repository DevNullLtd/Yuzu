// System > Plugins and updates page (GET /settings/plugins) — compiled in its own TU.
// HTMX-first, server-rendered. Five sections, each an hx-get on load: the three new read
// fragments plus the two hosted ones (plugin signing, agent updates) that settings_routes.cpp
// already serves. Plain JS only for the toast host, the error listener and the two computed
// confirms; never `hx-on`, no inline handlers (the CSP blocks them, CLAUDE.md).
//
// MSVC: each raw-string chunk stays well under the 16,380-byte C2026 cap; the checks in
// test_settings_plugins_ui.cpp pin the template as a whole.

#include "app_shell.hpp"

#include <string>

// NOLINTBEGIN(cert-err58-cpp)
constexpr char kPart1[] = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Plugins and updates</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false}'>
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: calc(100vh - var(--shell-top-h, 0px)); }
    .sys-page { max-width: 1200px; padding: 22px 28px 36px; }
    .sys-page code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .sys-page a:not(.btn) { color: var(--primary); }
    .muted { color: var(--mut); }
    .hint { color: var(--mut); font-size: 12.5px; }
    .feedback-error { color: var(--bad); }
    .panel .pb p { margin: 0 0 12px; max-width: 80ch; font-size: 13px; color: var(--mut); }
    .panel td.wrap { white-space: normal; overflow-wrap: anywhere; }
    .panel td.nw { white-space: nowrap; }
    .panel td .sub { display: block; color: var(--mut); font-size: 12px; font-weight: 400; }
    .panel details summary { cursor: pointer; }
    .panel ul.pack-items { margin: 8px 0; padding-left: 18px; font-size: 12.5px; }
    .panel .form.row2 { align-items: end; }

    /* The two hosted fragments (plugin signing, agent updates) predate yuzu.css and use
       these page-local classes; the Settings page defines them in its own <style>. */
    .form-row { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
    .form-row:last-child { margin-bottom: 0; }
    .form-row > label:first-child { flex: 0 0 180px; font-size: 13px; color: var(--ink2); font-weight: 500; }
    .section-note { margin: 12px 0 0; font-size: 12.5px; color: var(--mut); }
    .sub-head { margin: 16px 0 8px; font-size: 13px; font-weight: 600; color: var(--ink); }
    .file-name { font-size: 12.5px; color: var(--mut); font-family: var(--mds-font-family-mono); }
    .pb :is(input:not([type="checkbox"], [type="radio"], [type="file"], [type="hidden"]), select) {
      height: var(--ctl); padding: 0 10px; background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl); font: inherit; font-size: 13.5px; min-width: 0;
    }
    .pb input[type="checkbox"] { accent-color: var(--primary); width: 16px; height: 16px; }
    .pb input[type="file"]::file-selector-button {
      height: 28px; margin-right: 10px; padding: 0 10px; cursor: pointer; color: var(--ink);
      background: var(--raise); font: inherit; font-size: 13px; font-weight: 500;
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .pb :is(input, select, summary):focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    .user-table { width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--line);
                  border-radius: var(--rad-panel); font-size: 13.5px; overflow: hidden; }
    .user-table th { text-align: left; padding: 8px 12px; white-space: nowrap; background: var(--surface2);
                     border-bottom: 1px solid var(--line); color: var(--mut); font-size: 12.5px; font-weight: 500; }
    .user-table td { padding: var(--cell-y) 12px; border-bottom: 1px solid var(--line); color: var(--ink2); vertical-align: middle; }
    .user-table td.muted { color: var(--mut); }
    .user-table tbody tr:last-child td { border-bottom: 0; }
    .user-table td .btn-danger { height: 28px; padding: 0 8px; background: none; border-color: transparent; color: var(--bad); font-size: 13px; }
    .role-badge { display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 3px;
                  font-size: 12.5px; font-weight: 500; white-space: nowrap; background: var(--surface2); color: var(--mut); }
    .role-ok   { background: var(--mds-color-bg-success-tinted); color: var(--ok); }
    .role-warn { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .role-bad  { background: var(--mds-color-bg-error-tinted); color: var(--bad); }
    .feedback { font-size: 13px; margin-top: 12px; min-height: 1.2em; }
    .feedback:empty { display: none; }
    .feedback-ok { color: var(--ok); }
    .callout, .feedback-warning { padding: 12px 14px; border: 1px solid var(--line2); border-radius: var(--rad-panel);
                                  background: var(--surface2); color: var(--ink2); font-size: 13.5px; }
    .feedback-warning { border-color: color-mix(in srgb, var(--warn) 50%, var(--line2)); }
    .add-user-form { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;
                     margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--line); }
    .mini-field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
    .mini-field label { font-size: 13px; color: var(--ink2); font-weight: 500; }
    .add-user-form input[type="file"] { max-width: 260px; }
    .htmx-indicator { display: none; }
  </style>
</head>)HTM";
static_assert(sizeof(kPart1) < 15000, "MSVC C2026: split this raw-string chunk");

constexpr char kPart2[] = R"HTM(<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <main class="sys-page stack">
    <header class="ph">
      <h1>Plugins and updates</h1>
      <p>Plugin settings stored on the server, plugin code-signing trust, product packs and agent updates.</p>
    </header>

    <section class="panel">
      <div class="hd"><h2>Plugin configuration</h2></div>
      <div id="plugin-config-section" class="pb"
           hx-get="/fragments/settings/plugin-config"
           hx-trigger="load, refreshPluginConfig from:body"
           hx-swap="innerHTML"><span class="muted">Loading...</span></div>
    </section>

    <div class="grid2">
      <section class="panel">
        <div class="hd"><h2>Kill switch</h2></div>
        <div id="kill-switch-section" class="pb"
             hx-get="/fragments/settings/kill-switch"
             hx-trigger="load, refreshKillSwitch from:body"
             hx-swap="innerHTML"><span class="muted">Loading...</span></div>
      </section>

      <section class="panel">
        <div class="hd"><h2>Plugin signing</h2></div>
        <div class="pb">
          <p>Recorded here and served with the trust bundle. Each agent enforces its own
            <code>--plugin-require-signature</code>. Agents do not check revocation when loading
            plugins, so the trust anchors cannot be revoked from here. To issue a code-signing
            certificate, use <a href="/settings/pki">Certificates and secrets</a>.</p>
          <div id="plugin-signing-section"
               hx-get="/fragments/settings/plugin-signing"
               hx-trigger="load, refreshPluginSigning from:body"
               hx-swap="innerHTML"><span class="muted">Loading...</span></div>
        </div>
      </section>
    </div>

    <section class="panel">
      <div class="hd"><h2>Product packs</h2></div>
      <div id="product-packs-section" class="pb"
           hx-get="/fragments/settings/product-packs"
           hx-trigger="load, refreshProductPacks from:body"
           hx-swap="innerHTML"><span class="muted">Loading...</span></div>
    </section>

    <section class="panel">
      <div class="hd"><h2>Agent updates</h2></div>
      <div class="pb">
        <p>Upload agent binaries and manage fleet-wide rollout. A rollout percentage is the
          share of devices that may be offered a package, chosen by device identity; it is not
          how many have updated.</p>
        <div id="updates-section"
             hx-get="/fragments/settings/updates"
             hx-trigger="load, refreshUpdates from:body"
             hx-swap="innerHTML"><span class="muted">Loading...</span></div>
      </div>
    </section>
  </main>

  <div id="toast-container" class="toast-container"></div>

)HTM";
static_assert(sizeof(kPart2) < 15000, "MSVC C2026: split this raw-string chunk");

constexpr char kPart3[] = R"HTM(  <script>
    /* Toast host: hosted handlers answer with an HX-Trigger showToast. textContent only. */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      c.appendChild(t);
      if (level !== 'error') setTimeout(function () { t.remove(); }, level === 'warning' ? 8000 : 4000);
    }
    document.body.addEventListener('showToast', function (e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* htmx drops 4xx/5xx bodies. Surface the text: JSON error.message, else the inert
       text of an HTML body (DOMParser never runs a handler). Skipped when the response
       already carries its own toast trigger. */
    document.body.addEventListener('htmx:responseError', function (e) {
      var x = e.detail && e.detail.xhr;
      if (!x || x.getResponseHeader('HX-Trigger')) return;
      var text = '';
      try {
        var j = JSON.parse(x.responseText);
        text = j && j.error && j.error.message ? String(j.error.message) : '';
      } catch (_) {
        text = new DOMParser().parseFromString(x.responseText || '', 'text/html').body.textContent || '';
      }
      text = text.trim();
      showToast(text || ('Request failed (' + x.status + ')'), 'error');
    });

    /* Computed confirms for the two hosted forms (htmx fires htmx:confirm for every
       request; a static hx-confirm cannot carry the value typed at submit time). */
    function otaVersion(name) {
      var sfx = ['.tar.gz', '.exe', '.bin', '.zip', '.msi'];
      for (var i = 0; i < sfx.length; i++)
        if (name.length > sfx[i].length && name.slice(-sfx[i].length) === sfx[i])
          return name.slice(0, -sfx[i].length);
      return name;
    }
    function rolloutQuestion(f) {
      var tr = f.closest('tr'); if (!tr) return '';
      var to = f.elements.rollout_pct.value, from = tr.dataset.rollout;
      var q = 'Package ' + tr.dataset.version + ' for ' + tr.dataset.platform + '/' + tr.dataset.arch +
        ': rollout from ' + from + '% to ' + to + '%. Offered to ' + to + '% of devices. Mandatory: ' +
        f.dataset.mandatory + '. Signature: ' + (f.dataset.signed === 'yes' ? 'stored' : 'none') + '.';
      if (to === '100' && f.dataset.signed !== 'yes')
        q += ' Agents running --update-require-signature will refuse it.';
      return q;
    }
    function uploadQuestion(f) {
      var file = f.elements.file.files[0]; if (!file) return '';
      var sig = f.elements.signature.files[0];
      var plat = f.elements.platform.value, arch = f.elements.arch.value;
      var ver = otaVersion(file.name), pct = f.elements.rollout_pct.value;
      var q = 'Upload ' + file.name + ' as version ' + ver + ' for ' + plat + '/' + arch + '? ' +
        (sig ? 'A signature is attached.' : 'No signature: agents running --update-require-signature will refuse it.') +
        ' Offered to ' + pct + '% of devices. Mandatory: ' + (f.elements.mandatory.checked ? 'yes' : 'no') +
        '. This changes what code the fleet runs.';
      var rows = document.querySelectorAll('#updates-section tr[data-version]');
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i].dataset;
        if (r.platform === plat && r.arch === arch && r.version === ver)
          q += ' A package with this platform, architecture and version already exists (currently ' +
            r.rollout + '%) and is replaced: its file is overwritten and its rollout and mandatory ' +
            'flag are reset to the values above.';
      }
      return q;
    }
    document.body.addEventListener('htmx:confirm', function (e) {
      var f = e.detail && e.detail.elt;
      if (!f || !f.dataset || !f.dataset.confirm) return;
      e.preventDefault();
      if (!f.checkValidity()) { f.reportValidity(); return; }
      /* A number input also accepts 1e2 or 5.0; the handler reads the posted text with
         stoi, so 1e2 would apply 1% under a prompt that says 100%. Whole digits only. */
      var pct = f.elements.rollout_pct.value;
      if (!/^[0-9]{1,3}$/.test(pct) || Number(pct) > 100) {
        showToast('Rollout must be a whole number from 0 to 100.', 'error');
        return;
      }
      var q = f.dataset.confirm === 'rollout' ? rolloutQuestion(f) : uploadQuestion(f);
      if (q && window.confirm(q)) e.detail.issueRequest(true);
    });

    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        window.location.href = '/?palette=1';
      }
    });
  </script>
</body>
</html>
)HTM";
static_assert(sizeof(kPart3) < 15000, "MSVC C2026: split this raw-string chunk");

// Assembled once at static init; each chunk above is under the MSVC raw-string cap.
const std::string kSettingsPluginsPageTemplateStr = std::string(kPart1) + kPart2 + kPart3;
const char* const kSettingsPluginsPageTemplate = kSettingsPluginsPageTemplateStr.c_str();

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kSettingsPluginsHtml = yuzu::server::shell::bake(
    kSettingsPluginsPageTemplate, {.active_key = "settings-plugins", .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
