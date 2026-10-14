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

    /* ── Page header (.page-header / .subtitle from yuzu.css) ── */
    .page-header .btn { margin-left: auto; }
    .page-header .btn .icon { width: 14px; height: 14px; }

    /* ── Sections: flat group, or a bordered panel ─────────── */
    .section { display: flex; flex-direction: column; gap: 12px; min-width: 0; }
    .section-header {
      display: flex; align-items: center; gap: 8px;
      font-size: 14px; font-weight: 600; color: var(--ink);
    }
    .section.panel { gap: 0; }
    .panel > .section-header { padding: 12px 16px; border-bottom: 1px solid var(--line); }
    #compliance-summary { display: flex; flex-direction: column; gap: 16px; }

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
    /* Track and fill come from yuzu.css (.compliance-bar / .compliance-fill, .good / .warn / .bad) */
    .hero-cell .compliance-bar { margin-top: 8px; }

    /* ── Tables ────────────────────────────────────────────── */
    /* Row skin: yuzu.css (.tw table); the right-aligned action cell carries .r */
    .policy-table, .detail-table { min-width: 640px; }
    /* Cell classes carry the table prefix so they outrank look's .tw table td rule */
    .policy-table .policy-idx { color: var(--faint); }
    .policy-table .policy-name { font-weight: 600; color: var(--ink); }
    .policy-table .policy-scope { color: var(--mut); white-space: normal; min-width: 14ch; }
    .policy-pct { font-weight: 600; }
    .policy-pct.good { color: var(--ok); }
    .policy-pct.warn { color: var(--warn); }
    .policy-pct.bad  { color: var(--bad); }
    .policy-table .policy-count, .detail-table .cell-mut { color: var(--mut); }
    .policy-count { font-size: 12.5px; }
    .detail-table .cell-wrap { white-space: normal; }

    /* ── Mini compliance bars in table ─────────────────────── */
    .compliance-bar.mini-bar {
      width: 80px; display: inline-block; vertical-align: middle; margin-left: 8px;
    }

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
    .section-header .htmx-indicator { margin-left: auto; }
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
        <svg class="icon"><use href="/static/icons.svg#refresh-cw"></use></svg>
        Refresh
      </button>
    </div>

    <!-- ── Fleet Compliance Summary ─────────────────────── -->
    <div class="section">
      <div class="section-header">
        Fleet Compliance Overview
        <span class="htmx-indicator">Refreshing...</span>
      </div>
      <div>
        <div id="compliance-summary"
             hx-get="/fragments/compliance/summary"
             hx-trigger="load"
             hx-swap="innerHTML">
          <div class="empty-state">Loading compliance data...</div>
        </div>
      </div>
    </div>

    <!-- ── Per-Policy Detail (loaded on demand) ─────────── -->
    <div class="section panel">
      <div class="section-header">
        Policy Detail
      </div>
      <div>
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
  </script>
</body>
</html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kComplianceHtml =
    yuzu::server::shell::bake(kCompliancePageTemplate, {.active_key = "compliance"});
// NOLINTEND(cert-err58-cpp)
