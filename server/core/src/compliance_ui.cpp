// Compliance dashboard page — fleet policy compliance overview.
// Uses HTMX for fragment loading; mock data until PolicyStore is wired.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kComplianceHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Compliance</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: 100vh; }

    /* ── Content ───────────────────────────────────────────── */
    .content {
      max-width: 960px; margin: 1.5rem auto; padding: 0 1.5rem;
    }

    /* ── Page header ──────────────────────────────────────── */
    .page-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 1.5rem; padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .page-header h1 { font-size: 1.1rem; font-weight: 700; }
    .page-header .subtitle { font-size: 0.75rem; color: var(--muted); margin-top: 0.15rem; }

    /* ── Section cards ─────────────────────────────────────── */
    .section {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.5rem; margin-bottom: 1.5rem; overflow: hidden;
    }
    .section-header {
      padding: 0.75rem 1rem; font-size: 0.85rem; font-weight: 600;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 0.5rem;
    }
    .section-body { padding: 1rem; }

    /* ── Compliance bar ─────────────────────────────────────── */
    .compliance-hero {
      display: flex; align-items: center; gap: 1.5rem;
      margin-bottom: 0.75rem;
    }
    .compliance-pct {
      font-size: 2rem; font-weight: 700; line-height: 1;
      min-width: 80px;
    }
    .compliance-pct.good { color: var(--green); }
    .compliance-pct.warn { color: var(--yellow); }
    .compliance-pct.bad  { color: var(--red); }
    .compliance-bar-wrap { flex: 1; }
    .compliance-bar {
      height: 8px; background: var(--border); border-radius: 9999px;
      overflow: hidden;
    }
    .compliance-fill {
      height: 100%; border-radius: 9999px;
      transition: width 0.3s;
    }
    .compliance-fill.good { background: var(--green); }
    .compliance-fill.warn { background: var(--yellow); }
    .compliance-fill.bad  { background: var(--red); }
    .compliance-stats {
      display: flex; gap: 1.5rem; font-size: 0.75rem; color: var(--muted);
      margin-top: 0.5rem;
    }
    .compliance-stats strong { color: var(--fg); }

    /* ── Policy table ──────────────────────────────────────── */
    .policy-table {
      width: 100%; border-collapse: collapse; font-size: 0.8rem;
    }
    .policy-table th {
      text-align: left; padding: 0.4rem 0.6rem;
      border-bottom: 2px solid var(--border); color: var(--muted);
      font-size: 0.7rem; text-transform: uppercase;
      letter-spacing: 0.05em; font-weight: 600;
    }
    .policy-table td {
      padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border);
    }
    .policy-table tr:hover { background: var(--mds-color-state-hover); }
    .policy-table .policy-name {
      font-weight: 500; color: var(--fg);
    }
    .policy-table .policy-scope {
      font-size: 0.75rem; color: var(--muted); font-family: var(--mono);
    }
    .policy-pct {
      font-weight: 600; font-family: var(--mono);
    }
    .policy-pct.good { color: var(--green); }
    .policy-pct.warn { color: var(--yellow); }
    .policy-pct.bad  { color: var(--red); }

    /* ── Mini compliance bars in table ─────────────────────── */
    .mini-bar {
      width: 80px; height: 6px; background: var(--border);
      border-radius: 9999px; overflow: hidden; display: inline-block;
      vertical-align: middle; margin-left: 0.5rem;
    }
    .mini-fill {
      height: 100%; border-radius: 9999px;
    }
    .mini-fill.good { background: var(--green); }
    .mini-fill.warn { background: var(--yellow); }
    .mini-fill.bad  { background: var(--red); }

    /* ── Detail panel (per-policy agent breakdown) ──────── */
    .detail-panel {
      margin-top: 1rem; padding: 1rem;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.5rem;
    }
    .detail-panel h3 {
      font-size: 0.85rem; margin-bottom: 0.75rem;
      display: flex; align-items: center; gap: 0.5rem;
    }
    .detail-table {
      width: 100%; border-collapse: collapse; font-size: 0.78rem;
    }
    .detail-table th {
      text-align: left; padding: 0.35rem 0.5rem;
      border-bottom: 2px solid var(--border); color: var(--muted);
      font-size: 0.65rem; text-transform: uppercase;
      letter-spacing: 0.05em; font-weight: 600;
    }
    .detail-table td {
      padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border);
    }
    .detail-table tr:hover { background: var(--mds-color-state-hover); }

    /* ── Status badges ────────────────────────────────────── */
    .status-compliant {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.7rem; font-weight: 600;
      background: var(--mds-color-bg-success-tinted); color: var(--green);
    }
    .status-non-compliant {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.7rem; font-weight: 600;
      background: var(--mds-color-bg-error-tinted); color: var(--red);
    }
    .status-pending-eval {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.7rem; font-weight: 600;
      background: var(--mds-color-bg-warning-tinted); color: var(--yellow);
    }
    .status-remediated {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.7rem; font-weight: 600;
      background: var(--mds-color-state-selected); color: var(--accent);
    }

    /* ── Empty / loading states ───────────────────────────── */
    .empty-state {
      text-align: center; padding: 2rem 1rem;
      color: var(--subtle); font-size: 0.85rem;
    }

    /* ── Button overrides for this page ───────────────────── */
    .btn { height: auto; padding: 0.3rem 0.8rem; font-size: 0.75rem; border: none; }
    .btn-secondary { background: var(--surface); color: var(--fg); border: 1px solid var(--border); }
    .btn-sm { padding: 0.2rem 0.5rem; font-size: 0.7rem; }

    /* ── Refresh indicator ────────────────────────────────── */
    .htmx-indicator {
      display: none; color: var(--muted); font-size: 0.75rem;
    }
    .htmx-request .htmx-indicator,
    .htmx-request.htmx-indicator { display: inline; }
  </style>
</head>
<body>

  <nav class="nav-bar">
    <a href="/" class="nav-brand">
      <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
    </a>
    <a href="/" class="nav-link">Dashboard</a>
    <a href="/instructions" class="nav-link">Instructions</a>
    <a href="/compliance" class="nav-link active">Compliance</a>
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

  <div class="content">

    <div class="page-header">
      <div>
        <h1>Compliance Dashboard</h1>
        <div class="subtitle">Policy compliance status across the fleet</div>
      </div>
      <button class="btn btn-secondary"
              hx-get="/fragments/compliance/summary"
              hx-target="#compliance-summary"
              hx-swap="innerHTML">
        <svg class="icon" style="width:14px;height:14px"><use href="/static/icons.svg#refresh-cw"></use></svg>
        Refresh
      </button>
    </div>

    <!-- ── Fleet Compliance Summary ─────────────────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#shield"></use></svg>
        Fleet Compliance Overview
        <span class="htmx-indicator" style="margin-left:auto">Refreshing...</span>
      </div>
      <div class="section-body">
        <div id="compliance-summary"
             hx-get="/fragments/compliance/summary"
             hx-trigger="load"
             hx-swap="innerHTML">
          <div class="empty-state">Loading compliance data...</div>
        </div>
      </div>
    </div>

    <!-- ── Per-Policy Detail (loaded on demand) ─────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#list"></use></svg>
        Policy Detail
      </div>
      <div class="section-body">
        <div id="compliance-detail">
          <div class="empty-state">Click <strong>View</strong> on a policy above to see per-agent compliance.</div>
        </div>
      </div>
    </div>

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

    /* ── Populate nav bar + context bar ─────────────────────── */
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
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
