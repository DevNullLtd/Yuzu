// System > Certificates and secrets page (GET /settings/pki) — compiled in its own TU.
// HTMX-first, server-rendered. The two panels are fragments (`/fragments/settings/ca?view=pki`
// and `/fragments/settings/kek`), refreshed through `refreshPki`. Plain JS only for the toast
// host, the audit-failed banner and the denied-panel note; never `hx-on` and no inline handlers
// (the CSP blocks them, CLAUDE.md).

#include "app_shell.hpp"

#include <string>

// NOLINTBEGIN(cert-err58-cpp)
constexpr char kPart1[] = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Certificates and secrets</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false}'>
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: calc(100vh - var(--shell-top-h, 0px)); }
    .sys-page { max-width: 1200px; padding: 22px 28px 36px; }
    .sys-page code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .sys-page a:not(.btn) { color: var(--primary); }
    .muted { color: var(--mut); }
    .feedback-error { color: var(--bad); }
    .hint { color: var(--mut); font-size: 12.5px; }
    .panel summary { cursor: pointer; font-size: 13.5px; font-weight: 500; }
    .panel details form { display: grid; gap: 12px; margin-top: 12px; }
    .panel details .btns { padding: 0; }
    table.issued td.wrap { white-space: normal; overflow-wrap: anywhere; }
    table.issued td.nw { white-space: nowrap; }
    table.issued td .sub { display: block; color: var(--mut); font-size: 12px; }
    table.issued form.rv { display: inline-flex; gap: 8px; align-items: center; }
    table.issued form.rv .in { width: 11rem; height: 28px; font-size: 13px; }
    .alert .end { margin-left: auto; }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <main class="sys-page stack">
    <header class="ph">
      <h1>Certificates and secrets</h1>
      <p>The certificate authority, issued certificates and the key that protects stored secrets.</p>
    </header>

    <div class="note" id="pki-note">Revoking a certificate, or importing an enterprise chain, cannot
      be undone from the console. Rotating the key-encryption key adds a key version and re-wraps
      the key header of each stored secret; stored values are not changed. Key versions cannot be
      retired. Rotation attempts are rate-limited (one per hour by default) and a failed attempt
      counts.</div>

    <div id="pki-notices"></div>
    <div id="pki-reveal"></div>

    <div id="ca-section" class="stack"
         hx-get="/fragments/settings/ca?view=pki"
         hx-trigger="load, refreshPki from:body"
         hx-swap="innerHTML">
      <span class="muted">Loading...</span>
    </div>

    <div id="kek-section" class="stack"
         hx-get="/fragments/settings/kek"
         hx-trigger="load, refreshPki from:body"
         hx-swap="innerHTML">
      <span class="muted">Loading...</span>
    </div>
  </main>

  <div id="toast-container" class="toast-container"></div>

  <script>
    /* Toast host: the revoke/import wrappers answer an error with an HX-Trigger showToast. */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      c.appendChild(t);
      if (level !== 'error') setTimeout(function () { t.remove(); }, 4000);
    }
    document.body.addEventListener('showToast', function (e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* htmx drops 4xx/5xx bodies, so a panel the principal may not read would sit on
       "Loading..." forever. Say why instead (textContent only). */
    document.body.addEventListener('htmx:responseError', function (e) {
      var d = e.detail || {}, el = d.elt, x = d.xhr;
      if (el && x && x.status === 403 && (el.id === 'ca-section' || el.id === 'kek-section'))
        el.textContent = 'You do not have permission to view this panel. It needs the Security:Read permission.';
    });

    /* Any response carrying Sec-Audit-Failed: the action completed, its audit row did not. */
    document.body.addEventListener('htmx:afterRequest', function (e) {
      var x = e.detail && e.detail.xhr;
      if (!x || x.getResponseHeader('Sec-Audit-Failed') !== 'true') return;
      var n = document.getElementById('pki-notices');
      if (!n || n.firstChild) return;
      var a = document.createElement('div');
      a.className = 'alert alert-warning';
      var s = document.createElement('span');
      s.textContent = 'The action completed but its audit record could not be saved.';
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'btn link sm end'; b.textContent = 'Dismiss';
      b.addEventListener('click', function () { a.remove(); });
      a.appendChild(s); a.appendChild(b); n.appendChild(a);
    });
  </script>
</body>
</html>
)HTM";
static_assert(sizeof(kPart1) < 15000, "MSVC C2026: split this raw-string chunk");

// Assembled once at static init; each chunk above is under the MSVC raw-string cap.
const std::string kSettingsPkiPageTemplateStr = std::string(kPart1);
const char* const kSettingsPkiPageTemplate = kSettingsPkiPageTemplateStr.c_str();

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kSettingsPkiHtml = yuzu::server::shell::bake(
    kSettingsPkiPageTemplate, {.active_key = "settings-pki", .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
