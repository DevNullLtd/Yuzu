// Security and sign-in page (System group) — compiled in its own translation unit.
// HTMX-first: the four panels load the fragments /settings has always served
// (/fragments/settings/{directory,mfa,https,tls}); the page adds the shell, the toast host and
// a small listener script. No hx-on and no inline handlers (CSP); the script only uses
// addEventListener and textContent.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kSettingsSecurityPageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Security and sign-in</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false,"historyEnabled":false}'>
  <script src="/static/htmx.js"></script>
  <style>
    .content { padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px; max-width: 1200px; }
    .muted { color: var(--mut); }
    .feedback-ok { color: var(--ok); }
    .feedback-error { color: var(--bad); }
    code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <main class="content">
    <div class="page-header">
      <div>
        <h1>Security and sign-in</h1>
        <div class="subtitle">Sign-in methods, two-factor and transport security.</div>
      </div>
    </div>

    <section class="panel">
      <div class="hd"><h2>Single sign-on</h2></div>
      <div id="directory-section" hx-get="/fragments/settings/directory" hx-trigger="load" hx-swap="innerHTML">
        <span class="muted loading" style="padding:16px;display:block">Loading...</span>
      </div>
    </section>

    <section class="panel">
      <div class="hd"><h2>Two-factor sign-in</h2><span class="sub">Your account</span></div>
      <div id="mfa-section" hx-get="/fragments/settings/mfa" hx-trigger="load" hx-swap="innerHTML">
        <span class="muted loading" style="padding:16px;display:block">Loading...</span>
      </div>
    </section>

    <div class="grid2">
      <section class="panel">
        <div class="hd"><h2>Dashboard HTTPS</h2></div>
        <div id="https-section" hx-get="/fragments/settings/https" hx-trigger="load" hx-swap="innerHTML">
          <span class="muted loading" style="padding:16px;display:block">Loading...</span>
        </div>
      </section>
      <section class="panel">
        <div class="hd"><h2>Agent connections (mTLS)</h2></div>
        <div id="tls-section" hx-get="/fragments/settings/tls" hx-trigger="load" hx-swap="innerHTML">
          <span class="muted loading" style="padding:16px;display:block">Loading...</span>
        </div>
      </section>
    </div>
  </main>

  <div id="toast-container" class="toast-container"></div>

  <script>
    var PANELS = '#directory-section, #mfa-section, #https-section, #tls-section';
    var SKIP_TLS_CONFIRM = 'Turn off certificate checks for the identity provider? ' +
      'Anyone who can intercept traffic to it can impersonate it. Development only.';
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
    /* htmx drops 4xx/5xx bodies by default, which hides the server's own message. Show HTML
       error bodies for requests that came from inside the four panels; never a JSON body. */
    document.body.addEventListener('htmx:beforeSwap', function (e) {
      var d = e.detail, xhr = d.xhr, el = d.requestConfig && d.requestConfig.elt;
      if (!xhr || xhr.status < 400 || !el || !el.closest || !el.closest(PANELS)) return;
      var ct = xhr.getResponseHeader('Content-Type') || '';
      if (ct.indexOf('text/html') !== 0) return;
      d.shouldSwap = true;
      d.isError = false;
    });
    /* A panel load refused mid-session would sit at "Loading..." forever. */
    document.body.addEventListener('htmx:responseError', function (e) {
      var d = e.detail, t = d.target;
      if (!d.xhr || (d.xhr.status !== 401 && d.xhr.status !== 403) || !t) return;
      if (t.matches && t.matches(PANELS) && t.querySelector('.loading'))
        t.textContent = 'You no longer have access. Sign in again.';
    });
    /* The Skip TLS verify switch cannot carry a conditional hx-confirm, so ask on change. */
    document.body.addEventListener('change', function (e) {
      var t = e.target;
      if (t && t.matches && t.matches('input[name=skip_tls_verify]') && t.checked &&
          !window.confirm(SKIP_TLS_CONFIRM)) t.checked = false;
    });
    /* A cancelled certificate confirm must clear the chosen file so choosing it again fires
       change. Own the confirm for forms that hold a file input; htmx owns it everywhere else. */
    document.body.addEventListener('htmx:confirm', function (e) {
      var f = e.detail.elt, q = e.detail.question;
      if (!q || !f || !f.querySelector || !f.querySelector('input[type=file]')) return;
      e.preventDefault();
      if (window.confirm(q)) e.detail.issueRequest(true); else f.reset();
    });
  </script>
</body>
</html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kSettingsSecurityHtml = yuzu::server::shell::bake(
    kSettingsSecurityPageTemplate,
    {.active_key = "settings-security", .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
