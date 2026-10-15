// Settings > Data and retention page (System pages, SYS-4).
//
// Read-only: the retention panel hosts the existing
// GET /fragments/settings/data-retention fragment (windows are set by startup
// option; the stored-override route is inert, #483). The Export panel is a
// browser front for the existing POST /api/export/json-to-csv. No server data
// is interpolated into this template; every dynamic string is built by the
// fragment renderer or set with textContent below.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kSettingsDataPageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Data and retention</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: 100vh; }
    .content { padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px; max-width: 1200px; }
    #export-json { width: 100%; font-family: var(--mds-font-family-mono); font-size: 12.5px; }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<main class="content">
  <div class="page-header">
    <div>
      <h1>Data and retention</h1>
      <p class="subtitle">How long the server keeps data, and a converter for JSON results.</p>
    </div>
  </div>

  <div class="note">Retention periods are set when the server starts, with a command-line option or an environment variable. The dashboard shows them but cannot change them.</div>

  <section class="panel" aria-labelledby="retention-h">
    <div class="hd"><h2 id="retention-h">Data retention</h2></div>
    <div id="data-retention-section" hx-get="/fragments/settings/data-retention" hx-trigger="load" hx-swap="innerHTML">
      <div class="pb">Loading...</div>
    </div>
  </section>

  <section class="panel" aria-labelledby="export-h">
    <div class="hd"><h2 id="export-h">Export</h2></div>
    <div class="form">
      <div class="fld">
        <label for="export-json">Convert JSON results to CSV</label>
        <textarea id="export-json" rows="5" autocomplete="off" spellcheck="false"></textarea>
        <span class="hint">Paste a JSON array of objects. Column names come from the first object; keys that only appear in later rows are not exported.</span>
      </div>
    </div>
    <div class="btns">
      <button type="button" class="btn primary" id="export-btn">Export to CSV</button>
      <span id="export-status" role="status" aria-live="polite" class="hint"></span>
    </div>
  </section>
</main>

<script>
(function () {
  var sec = document.getElementById('data-retention-section');
  document.body.addEventListener('htmx:responseError', function (e) {
    if (!e.detail || !e.detail.xhr || e.detail.target !== sec) return;
    var s = e.detail.xhr.status;
    if (s === 401) { window.location.href = '/login'; return; }
    var t = 'Could not be read. This is not an empty list.';
    if (s === 403) t = 'Needs the Administrator account role.';
    else if (s === 429) t = 'Too many requests. Try again in a moment.';
    var d = document.createElement('div');
    d.className = 'pb';
    d.textContent = t;
    sec.replaceChildren(d);
  });

  var ta = document.getElementById('export-json');
  var btn = document.getElementById('export-btn');
  var st = document.getElementById('export-status');
  function say(t) { st.textContent = t; }
  btn.addEventListener('click', function () {
    var body = ta.value.trim();
    if (!body) { say('Paste a JSON array first.'); return; }
    btn.disabled = true;
    say('Converting...');
    fetch('/api/export/json-to-csv', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, body: body
    }).then(function (r) {
      if (r.status === 200) {
        return r.blob().then(function (b) {
          var a = document.createElement('a');
          var u = URL.createObjectURL(b);
          a.href = u; a.download = 'export.csv';
          document.body.appendChild(a); a.click(); a.remove();
          URL.revokeObjectURL(u);
          say('export.csv downloaded.');
        });
      }
      if (r.status === 401) { window.location.href = '/login'; return; }
      if (r.status === 413) { say('Too large. The limit is 100 MiB.'); return; }
      if (r.status === 429) { say('Too many requests. Try again in a moment.'); return; }
      return r.json().then(function (j) {
        var m = (j && j.error && j.error.message) || 'The request was refused.';
        if (m.indexOf('nests too deeply') >= 0) say('Too deeply nested. Rows can nest up to 32 levels.');
        else if (r.status === 400) say(m + '. Needs a non-empty array of objects.');
        else say(m);
      }, function () { say('The request was refused.'); });
    }).catch(function () {
      say('The request did not complete.');
    }).then(function () { btn.disabled = false; });
  });
})();
</script>
</body>
</html>
)HTM";

extern const char* const kSettingsDataHtml = yuzu::server::shell::bake(
    kSettingsDataPageTemplate,
    {.active_key = "settings-data", .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
