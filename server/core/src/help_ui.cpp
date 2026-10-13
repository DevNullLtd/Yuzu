// Help page — Phase 2 stub.
// Full HTMX help page will be implemented as part of the instruction system.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kHelpPageTemplate = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Help</title>
<link rel="stylesheet" href="/static/yuzu.css">
<style>
.help-content{max-width:800px;margin:1.5rem auto;padding:0 1.5rem}
h1{border-bottom:1px solid var(--border);padding-bottom:.5rem}
</style>
</head><body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<div class="help-content">
<h1>Help</h1>
<p>Help page is under construction. See the <a href="/">dashboard</a>.</p>
</div>

<div id="toast-container" class="toast-container"></div>

<script>
/* ── Toast notification system ─────────────────────────── */
function showToast(message, level) {
  var c = document.getElementById('toast-container');
  if (!c) return;
  var t = document.createElement('div');
  t.className = 'toast toast-' + (level || 'info');
  t.textContent = message;
  var close = document.createElement('button');
  close.textContent = '\u00d7';
  close.style.cssText = 'background:none;border:none;color:var(--muted);cursor:pointer;margin-left:auto;font-size:1.2rem;padding:0 0 0 var(--sp-3);';
  close.onclick = function() { t.remove(); };
  t.style.display = 'flex';
  t.style.alignItems = 'center';
  t.appendChild(close);
  c.appendChild(t);
  if (level !== 'error') {
    setTimeout(function() { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(function() { t.remove(); }, 300); }, level === 'warning' ? 8000 : 4000);
  }
}
document.body.addEventListener('showToast', function(e) {
  var d = e.detail || {};
  showToast(d.message || 'Done', d.level || 'success');
});
</script>
</body></html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kHelpHtml =
    yuzu::server::shell::bake(kHelpPageTemplate, {.title = "Help"});
// NOLINTEND(cert-err58-cpp)
