// Compliance dashboard page — fleet policy compliance overview.
// Uses HTMX for fragment loading; mock data until PolicyStore is wired.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kCompliancePageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Compliance</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    /* ── Content ───────────────────────────────────────────── */
    .content {
      padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px;
    }

    /* ── Page header ──────────────────────────────────────── */
    .page-header {
      display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px 24px;
    }
    .page-header h1 {
      font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2;
      color: var(--ink);
    }
    .page-header .subtitle { font-size: 14px; color: var(--mut); margin-top: 4px; max-width: 70ch; }
    .page-header .btn { margin-left: auto; }

    /* ── Sections: flat group, or a bordered panel ─────────── */
    .section { display: flex; flex-direction: column; gap: 12px; min-width: 0; }
    .section-header {
      display: flex; align-items: center; gap: 8px;
      font-size: 14px; font-weight: 600; color: var(--ink);
    }
    .cmp-panel {
      background: var(--surface); border: 1px solid var(--line);
      border-radius: var(--rad-panel); min-width: 0;
    }
    .section.cmp-panel { gap: 0; }
    .cmp-panel > .section-header { padding: 12px 16px; border-bottom: 1px solid var(--line); }
    #compliance-summary { display: flex; flex-direction: column; gap: 16px; }
    .tw { overflow-x: auto; }

    /* ── Readout row (fleet compliance + counts) ───────────── */
    .compliance-hero {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      overflow: hidden; background: var(--surface);
      border: 1px solid var(--line); border-radius: var(--rad-panel);
    }
    .hero-cell {
      padding: 14px 18px; min-width: 0;
      box-shadow: -1px 0 0 var(--line), 0 -1px 0 var(--line);
    }
    .hero-v { font-size: 26px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; color: var(--ink); }
    .hero-l { font-size: 13px; color: var(--mut); margin-top: 2px; }
    .compliance-bar { height: 6px; margin-top: 8px; background: var(--line); border-radius: 2px; overflow: hidden; }
    .compliance-fill { height: 100%; }
    .compliance-fill.good { background: var(--ok); }
    .compliance-fill.warn { background: var(--warn); }
    .compliance-fill.bad  { background: var(--bad); }

    /* ── Tables ────────────────────────────────────────────── */
    .policy-table, .detail-table { width: 100%; min-width: 640px; border-collapse: collapse; }
    .policy-table th, .detail-table th {
      text-align: left; padding: 8px 16px; white-space: nowrap;
      font-size: 12.5px; font-weight: 500; color: var(--mut);
      background: var(--surface2); border-bottom: 1px solid var(--line);
    }
    .policy-table td, .detail-table td {
      padding: var(--cell-y) 16px; white-space: nowrap;
      color: var(--ink2); border-bottom: 1px solid var(--line);
    }
    .policy-table tbody tr:last-child td, .detail-table tbody tr:last-child td { border-bottom: 0; }
    .policy-table tbody tr:hover td, .detail-table tbody tr:hover td { background: var(--surface2); }
    .policy-table td:last-child { text-align: right; }
    /* Cell classes carry the table prefix so they outrank the table's own td rule above */
    .policy-table .policy-idx { color: var(--faint); }
    .policy-table .policy-name { font-weight: 600; color: var(--ink); }
    .policy-scope, .mono-id {
      font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .policy-table .policy-scope { color: var(--mut); white-space: normal; min-width: 14ch; }
    .policy-pct { font-weight: 600; }
    .policy-pct.good { color: var(--ok); }
    .policy-pct.warn { color: var(--warn); }
    .policy-pct.bad  { color: var(--bad); }
    .policy-table .policy-count, .detail-table .cell-mut { color: var(--mut); }
    .policy-count { font-size: 12.5px; }
    .detail-table .cell-wrap { white-space: normal; }

    /* ── Mini compliance bars in table ─────────────────────── */
    .mini-bar {
      width: 80px; height: 6px; background: var(--line); border-radius: 2px;
      overflow: hidden; display: inline-block; vertical-align: middle; margin-left: 8px;
    }
    .mini-fill { height: 100%; }
    .mini-fill.good { background: var(--ok); }
    .mini-fill.warn { background: var(--warn); }
    .mini-fill.bad  { background: var(--bad); }

    /* ── Detail panel (per-policy agent breakdown) ──────── */
    .detail-panel h3 {
      display: flex; align-items: baseline; gap: 8px;
      padding: 14px 16px 0; font-size: 14px; font-weight: 600; color: var(--ink);
    }
    .detail-id { font-size: 12.5px; font-weight: 400; color: var(--mut); }
    .detail-badges { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 16px 14px; }

    /* ── Status pills ─────────────────────────────────────── */
    .status-compliant, .status-non-compliant, .status-pending-eval, .status-remediated {
      display: inline-flex; align-items: center; padding: 1px 8px;
      border-radius: 3px; font-size: 12.5px; font-weight: 500; white-space: nowrap;
    }
    .status-compliant     { color: var(--ok);   background: color-mix(in srgb, var(--ok) 14%, transparent); }
    .status-non-compliant { color: var(--bad);  background: color-mix(in srgb, var(--bad) 14%, transparent); }
    .status-pending-eval  { color: var(--warn); background: color-mix(in srgb, var(--warn) 15%, transparent); }
    .status-remediated    { color: var(--info); background: color-mix(in srgb, var(--info) 14%, transparent); }

    /* ── Empty / loading states ───────────────────────────── */
    .empty-state, .policy-table td.empty-state {
      text-align: center; padding: 28px 16px; white-space: normal;
      color: var(--mut); font-size: 14px;
    }

    /* ── Buttons ──────────────────────────────────────────── */
    .btn.btn-secondary {
      height: var(--ctl); padding: 0 14px; font-size: 14px; font-weight: 500;
      color: var(--ink); background: var(--raise); border: 1px solid var(--line2);
      border-radius: var(--rad-ctl); transition: background-color .12s, border-color .12s;
    }
    .btn.btn-secondary:hover:not(:disabled) { opacity: 1; background: var(--surface2); border-color: var(--mut); }
    .btn.btn-sm { height: 28px; padding: 0 10px; font-size: 13px; }
    /* Row action: text button at the table's right edge */
    .policy-table .btn.btn-secondary {
      padding: 0 6px; color: var(--primary); background: none; border-color: transparent;
    }
    .policy-table .btn.btn-secondary:hover:not(:disabled) {
      background: none; border-color: transparent; text-decoration: underline;
    }

    /* ── Refresh indicator ────────────────────────────────── */
    .htmx-indicator {
      display: none; color: var(--mut); font-size: 13px; font-weight: 400;
    }
    .htmx-request .htmx-indicator,
    .htmx-request.htmx-indicator { display: inline; }

    @media (max-width: 640px) { .content { padding: 16px; } }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

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
    <div class="section cmp-panel">
      <div class="section-header">
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

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kComplianceHtml =
    yuzu::server::shell::bake(kCompliancePageTemplate, {.active_key = "compliance"});
// NOLINTEND(cert-err58-cpp)
