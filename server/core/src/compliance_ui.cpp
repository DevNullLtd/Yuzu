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

    /* ── Layout: a stack of shared .readout / .panel blocks ──── */
    #compliance-summary { display: flex; flex-direction: column; gap: 16px; }
    .page-stack { display: flex; flex-direction: column; gap: 16px; }
    .tw { overflow-x: auto; }
    .panel > .pb + .tw { border-top: 1px solid var(--line); }
    .compliance-bar { margin-top: 8px; }

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
        <h1>Compliance</h1>
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

    <div class="page-stack">
      <div id="compliance-summary"
           hx-get="/fragments/compliance/summary"
           hx-trigger="load"
           hx-swap="innerHTML"
           data-denied="Needs the Policy Read permission.">
        <div class="empty-state">Loading compliance data...</div>
      </div>

      <div class="panel">
        <div class="hd"><h2>Policy detail</h2><span class="sub">Per-device results for one policy</span></div>
        <div id="compliance-detail" data-denied="Needs the Policy Read permission.">
          <div class="empty-state">Click <strong>View</strong> on a policy above to see per-device compliance.</div>
        </div>
      </div>

      <div id="policy-fragments"
           hx-get="/fragments/policy-fragments"
           hx-trigger="load"
           hx-swap="innerHTML"
           data-denied="Needs the Policy Read permission.">
        <div class="empty-state">Loading policy fragments...</div>
      </div>

      <div class="panel">
        <div class="hd"><h2>Compliance by tag</h2>
          <span class="sub">Devices should have all structured tag categories assigned. Devices missing tags are flagged but keep working.</span></div>
        <div id="tag-compliance"
             hx-get="/fragments/settings/tag-compliance"
             hx-trigger="load"
             hx-swap="innerHTML"
             data-denied="Needs the Tag Read permission.">
          <div class="empty-state">Loading tag compliance...</div>
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

    /* htmx drops 4xx/5xx bodies, so a refused or failed panel would sit on
       "Loading..." forever: say why in the panel the request targeted. */
    document.body.addEventListener('htmx:responseError', function(e) {
      var d = e.detail || {};
      var t = d.target;
      if (!t || !t.hasAttribute || !t.hasAttribute('data-denied')) return;
      var st = d.xhr ? d.xhr.status : 0;
      t.textContent = (st === 401 || st === 403)
        ? t.getAttribute('data-denied')
        : 'Temporarily unavailable. Try Refresh in a moment.';
      t.className = 'empty-state';
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
