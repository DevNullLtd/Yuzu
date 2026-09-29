// Help page — Phase 2 stub.
// Full HTMX help page will be implemented as part of the instruction system.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kHelpHtml = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Help</title>
<link rel="stylesheet" href="/static/yuzu.css">
<style>
.help-content{max-width:800px;margin:1.5rem auto;padding:0 1.5rem}
h1{border-bottom:1px solid var(--border);padding-bottom:.5rem}
</style>
</head><body>

<nav class="nav-bar">
  <a href="/" class="nav-brand">
    <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
  </a>
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/instructions" class="nav-link">Instructions</a>
  <a href="/compliance" class="nav-link">Compliance</a>
  <a href="/guardian" class="nav-link">Guardian</a>
  <a href="/dex" class="nav-link">DEX</a>
  <a href="/tar" class="nav-link">TAR</a>
  <a href="/hardware" class="nav-link">Hardware</a>
  <a href="/software" class="nav-link">Software</a>
  <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/result-sets" class="nav-link">Result Sets</a>
  <a href="/settings" class="nav-link" id="nav-settings-link">Settings</a>
  <span class="nav-spacer"></span>
  <span class="nav-user" id="nav-user"></span>
  <button class="nav-logout" hx-post="/logout">Logout</button>
</nav>
<div class="context-bar" id="context-bar">
  <span class="context-role-badge" id="role-badge"></span>
  <span class="context-user" id="context-user"></span>
  <span class="context-spacer"></span>
  <button class="context-bell" title="Notifications">
    <svg class="icon"><use href="/static/icons.svg#bell"></use></svg>
  </button>
</div>

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
<script>
fetch('/api/me').then(function(r){return r.json()}).then(function(d){
  document.getElementById('nav-user').textContent = (d.display_name || d.username);
  var role = d.rbac_role || d.role;
  document.getElementById('role-badge').textContent = role;
  document.getElementById('context-user').textContent = (d.display_name || d.username);
  document.body.setAttribute('data-role', role);
  if(d.role !== 'admin' && role !== 'Administrator' && role !== 'PlatformEngineer') {
    var sl = document.getElementById('nav-settings-link');
    if(sl) sl.style.display = 'none';
  }
});
/* Ctrl+K / Cmd+K — navigate to dashboard command palette */
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    window.location.href = '/?palette=1';
  }
});
</script>
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
