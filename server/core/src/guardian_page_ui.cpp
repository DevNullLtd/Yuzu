// Guardian detail page shell — full-page drill-down for a single Guard or
// Baseline (replaces the cramped detail modal). Sibling of /guardian.
//
// One parameterised shell serves both /guardian/baseline/<id> and
// /guardian/guard/<id>: the page-route handler substitutes {{TITLE}} (browser
// tab title) and {{FRAGMENT}} (the page-content fragment URL), then the mount
// hx-gets that fragment on load. This mirrors the Fleet-Viz host page
// (viz_host_page_ui.cpp): a static shell + server-side token substitution +
// an hx-get fragment, so the heavy renderer stays a testable fragment method.
//
// Product UI — HTMX, server-rendered, dark-theme only. Palette comes from the
// design tokens in /static/yuzu.css (--bg/--surface/--surface2/--raise/--ink/
// --mut/--line/--primary/--ok/--warn/--bad/--info/--hl); the shared component
// CSS lives in the inline <style> below because those classes (.gp-*) are not
// part of the shared stylesheet. Do NOT apply the `frontend-design` plugin here.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kGuardianDetailPageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{TITLE}}</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false}'>
  <script src="/static/htmx.js"></script>
  <style>
    .gp-wrap { padding: 22px 28px 36px; }
    :where(.gp-wrap) a { color: var(--primary); }  /* bare links; any class rule wins (zero specificity) */
    .gp-loading { color: var(--mut); padding: 32px 0; }
    .gp-back { display: inline-block; margin-bottom: 12px; font-size: 13px; font-weight: 500;
               color: var(--primary); text-decoration: none; }
    .gp-back:hover { text-decoration: underline; }

    /* page header: title + actions */
    .gp-head { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between;
               gap: 12px 24px; margin-bottom: 12px; }
    .gp-head h1 { font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2; }
    .gp-titleline { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .gp-sub { font-size: 14px; color: var(--mut); margin-top: 4px; max-width: 70ch; }
    .gp-sub b { color: var(--ink); font-weight: 600; }
    .gp-sub a { color: var(--primary); text-decoration: none; }
    .gp-sub a:hover { text-decoration: underline; }
    .gp-actions { display: flex; flex-wrap: wrap; gap: 8px; flex-shrink: 0; }

    .gp-sech { font-size: 14px; font-weight: 600; color: var(--ink); margin: 22px 0 8px; }
    .gp-sech .gp-mute { font-weight: 400; }
    .gp-note { font-size: 12.5px; color: var(--mut); margin-top: 8px; }
    .gp-note b { color: var(--ink); font-weight: 600; }

    /* #2691 finding 10: an honest "store degraded, retrying" banner on a
       running /auto Pre-flight page — distinct from a plain empty state so
       it doesn't read as "these devices are done". Warn-toned, not alarm-red
       (#2691 Gate 6 enterprise-readiness): a transient retrying blip, not a
       confirmed failure — matches the dashboard sibling banner. */
    .result-degrade-banner, .gp-banner {
      color: var(--ink2); background: var(--surface2); font-size: 13.5px;
      border: 1px solid color-mix(in srgb, var(--warn) 50%, var(--line2));
      border-radius: var(--rad-panel); padding: 12px 14px; margin-bottom: 12px;
    }
    .gp-banner { margin: 12px 0 0; }
    .gp-banner b { color: var(--ink); }
    .gp-list { padding-left: 18px; font-size: 13.5px; }

    /* lifecycle / severity / mode pills */
    .gp-pill { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 12.5px;
               font-weight: 500; white-space: nowrap; color: var(--mut); background: var(--surface2); }
    .gp-pill[class*="sev-"] { text-transform: capitalize; }
    .gp-pill.dep { color: var(--ok); background: var(--mds-color-bg-success-tinted); }
    .gp-pill.sev-critical, .gp-pill.sev-high { color: var(--bad); background: var(--mds-color-bg-error-tinted); }
    .gp-pill.sev-medium { color: var(--warn); background: var(--mds-color-bg-warning-tinted); }
    .gp-pill.sev-low, .gp-pill.enforce { color: var(--info); background: var(--mds-color-bg-info-tinted); }

    /* compliance hero */
    .gp-hero { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; padding: 16px 18px;
               background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .gp-hero-bar { flex: 1; min-width: 320px; }
    .gp-pct { font-size: 26px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; color: var(--ink); }
    .gp-pct small { display: block; font-size: 13px; color: var(--mut); font-weight: 400; letter-spacing: 0; }
    .gp-bar { display: flex; gap: 2px; height: 18px; border-radius: 3px; overflow: hidden; background: var(--bg); }
    .gp-bar > span { display: flex; align-items: center; justify-content: center;
                     font-size: 11px; color: var(--on-primary); font-weight: 600; }
    .gp-legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 13px; color: var(--mut); }
    .gp-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px;
                   margin-right: 6px; vertical-align: middle; }
    .gp-legend b { color: var(--ink); font-weight: 600; margin-left: 4px; }

    /* readout row: one bordered region, 1px rules between figures */
    .gp-tiles { display: flex; flex-wrap: wrap; gap: 1px; margin-top: 16px; overflow: hidden;
                background: var(--line); border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .gp-tile { flex: 1 1 170px; min-width: 0; padding: 14px 18px; background: var(--surface); }
    .gp-tile .n { font-size: 26px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; color: var(--ink); }
    .gp-tile .l { font-size: 13px; color: var(--mut); margin-top: 2px; }
    .gp-tile .sx { font-size: 12.5px; color: var(--mut); margin-top: 4px; }
    .gp-tile .n.good { color: var(--ok); } .gp-tile .n.warn { color: var(--warn); }
    .gp-tile .n.bad { color: var(--bad); } .gp-tile .n.unk { color: var(--faint); }
    .gp-tile .n.info { color: var(--primary-h); } .gp-tile .n.mute { color: var(--mut); }

    /* spec grid (what a guard checks) */
    .gp-spec { display: grid; grid-template-columns: auto 1fr; gap: 8px 16px; font-size: 13.5px;
               background: var(--surface); border: 1px solid var(--line);
               border-radius: var(--rad-panel); padding: 12px 16px; }
    .gp-spec .k { color: var(--mut); }
    .gp-spec code { font-family: var(--mds-font-family-mono); font-size: 12.5px; color: var(--ink);
                    overflow-wrap: anywhere; }

    /* tables: bordered region, sentence-case header on surface2, 1px row rules */
    .gp-table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--surface);
                color: var(--ink2); border: 1px solid var(--line); border-radius: var(--rad-panel); overflow: hidden; }
    .gp-table th { text-align: left; padding: 8px 16px; font-size: 12.5px; font-weight: 500; color: var(--mut);
                   white-space: nowrap; background: var(--surface2); border-bottom: 1px solid var(--line); }
    /* numeric headers must right-align to sit over their right-aligned data — the
       `.gp-table th` rule above out-specifies a bare `.gp-num`, so qualify it. */
    .gp-table th.gp-num { text-align: right; }
    .gp-table td { padding: var(--cell-y) 16px; border-bottom: 1px solid var(--line); }
    .gp-table tr:last-child td { border-bottom: 0; }
    .gp-table tr.click { cursor: pointer; }
    .gp-table tbody tr:hover td { background: var(--surface2); }
    .gp-table a { color: var(--ink); font-weight: 600; text-decoration: none; }
    .gp-table a:hover { color: var(--primary-h); }
    .gp-num { text-align: right; font-variant-numeric: tabular-nums; }
    .gp-ok { color: var(--ok); font-weight: 500; } .gp-drift { color: var(--warn); font-weight: 500; }
    .gp-err { color: var(--bad); font-weight: 500; } .gp-unk { color: var(--faint); } .gp-mute { color: var(--mut); }

    /* filter chips: adjacent chips fuse into one segmented control (active = raised) */
    .gp-filters { display: flex; gap: 8px 10px; align-items: center; flex-wrap: wrap; margin: 12px 0 10px; }
    .gp-chip { display: inline-flex; align-items: center; height: var(--ctl); padding: 0 14px;
               font-size: 13.5px; font-weight: 500; color: var(--mut); white-space: nowrap; cursor: pointer;
               background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
               text-decoration: none; transition: color .12s, background-color .12s; }
    /* only in a filter bar: the 10px column gap + 1px shared border = -11px, pulled on the leading chip so a wrapped chip never leaves the row */
    .gp-filters .gp-chip:has(+ .gp-chip) { margin-right: -11px; border-top-right-radius: 0; border-bottom-right-radius: 0; }
    .gp-filters .gp-chip + .gp-chip { border-top-left-radius: 0; border-bottom-left-radius: 0; }
    .gp-chip:hover { color: var(--ink); }
    .gp-chip.on { color: var(--ink); background: var(--raise); font-weight: 600; }
    .gp-search { height: var(--ctl); min-width: 200px; padding: 0 10px; font-size: 14px; color: var(--ink);
                 background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl); }
    .gp-search::placeholder { color: var(--faint); }

    /* events */
    .gp-ev { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13.5px; }
    .gp-ev .t { color: var(--mut); white-space: nowrap; font-size: 12.5px;
                font-family: var(--mds-font-family-mono); }
    .gp-badge { padding: 1px 8px; border-radius: 3px; font-size: 12.5px; font-weight: 500; color: var(--warn);
                background: var(--mds-color-bg-warning-tinted); }

    .gp-placeholder { text-align: center; color: var(--mut); padding: 24px 16px; font-size: 13.5px;
                      background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .gp-placeholder b { display: block; color: var(--ink); font-weight: 600; margin-bottom: 4px; }

    .gp-btn { display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 10px; font-size: 13px;
              font-weight: 500; white-space: nowrap; text-decoration: none; cursor: pointer; color: var(--ink);
              background: var(--raise); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
              transition: background-color .12s, border-color .12s; }
    .gp-btn:hover { background: var(--surface2); border-color: var(--mut); }
    .gp-btn.accent { color: var(--on-primary); background: var(--primary); border-color: var(--primary); font-weight: 600; }
    .gp-btn.accent:hover { background: var(--primary-h); border-color: var(--primary-h); }
    .gp-btn.danger { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 45%, var(--line2)); }
    .gp-btn.danger:hover { background: color-mix(in srgb, var(--bad) 12%, transparent); border-color: var(--bad); }

    /* DEX sub-nav (Overview / Catalogue / Health / Trends) — underlined tabs */
    .gp-subnav { display: flex; gap: 2px; align-items: center; flex-wrap: wrap;
                 border-bottom: 1px solid var(--line); margin-bottom: 16px; }
    .gp-subnav a, .gp-subnav span { padding: 8px 14px; font-weight: 500; color: var(--mut); cursor: pointer;
                 border-bottom: 2px solid transparent; margin-bottom: -1px; text-decoration: none; }
    .gp-subnav a:hover { color: var(--ink); }
    .gp-subnav a.on { color: var(--ink); font-weight: 600; border-bottom-color: var(--hl); }
    .gp-subnav span.soon { color: var(--faint); cursor: default; }
    .gp-subnav .sp { margin-left: auto; font-size: 12.5px; font-weight: 400; color: var(--mut); cursor: default; }

    /* DEX catalogue family-card grid (mockup dex-catalogue.html, View 1) */
    .gp-fgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr)); gap: 16px; margin-top: 12px; }
    .gp-fcard { display: block; padding: 14px 16px; color: var(--ink); cursor: pointer; background: var(--surface);
                border: 1px solid var(--line); border-radius: var(--rad-panel); transition: border-color .12s; }
    .gp-fcard:hover { border-color: var(--mut); }
    .gp-fcard .fn { color: var(--ink); font-weight: 600; font-size: 14px; display: flex;
                justify-content: space-between; align-items: baseline; gap: 6px; }
    .gp-fcard .fn .cnt { font-size: 12.5px; color: var(--mut); font-weight: 400; white-space: nowrap; }
    .gp-fcard .fev { font-size: 26px; font-weight: 500; letter-spacing: -.02em; color: var(--ink); line-height: 1.15; margin-top: 8px; }
    .gp-fcard .fev.bad { color: var(--bad); } .gp-fcard .fev.warn { color: var(--warn); }
    .gp-fcard .fev.ok { color: var(--ok); }
    .gp-fcard .fmeta { font-size: 12.5px; color: var(--mut); }
    .gp-fcard .ftop { font-size: 12.5px; color: var(--mut); margin-top: 8px;
                border-top: 1px solid var(--line); padding-top: 8px; }
    .gp-fcard .ftop b { color: var(--ink); font-weight: 600; }
    .gp-fcard.quiet { border-style: dashed; }
    .gp-fcard.quiet :is(.fn, .cnt, .fev, .fmeta, .ftop, b) { color: var(--faint); }
)HTM"
    // MSVC caps a single string literal at ~16 KB; the page shell + component CSS
    // outgrew it, so the literal is split here (adjacent literals concatenate).
    R"HTM(
    /* DEX health-score page (mockup dex-health-score.html) */
    .gp-reversal { font-size: 13.5px; color: var(--ink2); background: var(--surface2); margin: 16px 0;
                border: 1px solid color-mix(in srgb, var(--info) 45%, var(--line2));
                border-radius: var(--rad-panel); padding: 12px 14px; }
    .gp-primary { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; padding: 14px 18px;
                background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .gp-primary .big { font-size: 26px; font-weight: 500; letter-spacing: -.02em; color: var(--ink); line-height: 1.15; }
    .gp-primary .lbl { font-size: 13px; color: var(--mut); }
    .gp-primary .vdiv { width: 1px; align-self: stretch; background: var(--line); }
    .gp-composite { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
    .gp-gauge { position: relative; width: 140px; height: 140px; flex-shrink: 0; }
    .gp-gauge .val { position: absolute; inset: 0; display: flex; flex-direction: column;
                align-items: center; justify-content: center; }
    .gp-gauge .val .num { font-size: 26px; font-weight: 500; letter-spacing: -.02em; color: var(--ink); line-height: 1.15; }
    .gp-gauge .val .band { font-size: 12.5px; font-weight: 600; }
    .band-excellent, .band-good { color: var(--ok); } .band-fair { color: var(--warn); }
    .band-poor { color: var(--bad); }
    .gp-derived { display: inline-block; margin-bottom: 6px; padding: 0 6px; font-size: 12px; color: var(--mut);
                border: 1px solid var(--line2); border-radius: 3px; }
    .gp-stack { display: flex; gap: 2px; height: 26px; border-radius: 3px; overflow: hidden;
                background: var(--bg); margin-bottom: 12px; }
    .gp-stack > span { display: flex; align-items: center; justify-content: center;
                font-size: 11px; color: var(--on-primary); font-weight: 600; min-width: 0; white-space: nowrap; }
    .gp-ded { display: grid; grid-template-columns: 1.6fr auto 1fr auto; gap: 10px;
                align-items: center; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: 13.5px; }
    .gp-ded .fam { color: var(--ink); font-weight: 600; }
    .gp-ded .wt { font-size: 12.5px; }
    .wt-high { color: var(--bad); } .wt-med { color: var(--warn); } .wt-low { color: var(--mut); }
    .gp-ded .bar { height: 6px; border-radius: 2px; background: var(--bad); }
    .gp-ded .pts { text-align: right; color: var(--bad); font-weight: 600; min-width: 48px; }
    .gp-subgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 12px; }
    .gp-sscore { background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel);
                padding: 12px 14px; }
    .gp-sscore .nm { font-size: 13px; color: var(--mut); }
    .gp-sscore .vv { font-size: 26px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; }
    .gp-sscore .ds { font-size: 12.5px; color: var(--mut); }

    /* DEX trends page (mockup dex-trends.html) */
    .gp-oscards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
    .gp-oscard { background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel);
                padding: 14px 16px; }
    .gp-oscard.pending { border-style: dashed; }
    .gp-oscard.pending :is(.os, .scope) { color: var(--faint); }
    .gp-oscard .os { display: flex; align-items: center; gap: 8px; font-size: 14px;
                color: var(--ink); font-weight: 600; }
    .gp-oscard .state { font-size: 12.5px; border-radius: 3px; padding: 0 6px; color: var(--mut);
                background: var(--surface2); }
    .gp-oscard .state.live { color: var(--ok); background: var(--mds-color-bg-success-tinted); }
    .gp-oscard .state.limited { color: var(--warn); background: var(--mds-color-bg-warning-tinted); }
    .gp-oscard .scope { font-size: 12.5px; color: var(--mut); margin-top: 2px; }
    .gp-smgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
    .gp-sm { background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel);
                padding: 10px 14px; }
    .gp-sm .smh { display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
    .gp-sm .smn { font-size: 13.5px; color: var(--ink); font-weight: 600; }
    .gp-sm .smv { font-size: 12.5px; color: var(--mut); }
    .gp-heat { display: flex; flex-direction: column; gap: 3px; margin-top: 6px; }
    .gp-heat .hrow { display: flex; align-items: center; gap: 4px; }
    .gp-heat .hlbl { width: 150px; flex-shrink: 0; font-size: 12.5px; color: var(--mut); text-align: right; }
    .gp-heat .hrow > i { flex: 1; height: 14px; border-radius: 2px; min-width: 6px; }
  </style>
</head>
<body>
  <!--yuzu:shell--><!--/yuzu:shell-->

  <div class="gp-wrap">
    <div id="guardian-detail"
         hx-get="{{FRAGMENT}}" hx-trigger="load" hx-swap="innerHTML">
      <div class="gp-loading">Loading&hellip;</div>
    </div>
  </div>

  <div id="toast-container" class="toast-container"></div>

  <script>
    /* Generic chip filter for the page's member/device tables. A chip carries
       data-gpf="<group>" + data-gpk="<key>"; rows carry data-gpf="<group>"
       data-gpstate="<key>". "all" matches every row. */
    function gpFilter(btn) {
      var group = btn.getAttribute('data-gpf');
      var key = btn.getAttribute('data-gpk');
      var chips = document.querySelectorAll('.gp-chip[data-gpf="' + group + '"]');
      for (var i = 0; i < chips.length; i++) chips[i].classList.remove('on');
      btn.classList.add('on');
      var rows = document.querySelectorAll('tr[data-gpf="' + group + '"]');
      for (var j = 0; j < rows.length; j++) {
        var st = rows[j].getAttribute('data-gpstate');
        rows[j].style.display = (key === 'all' || st === key) ? '' : 'none';
      }
    }
    /* Free-text row search within a table group (matches data-gpname). */
    function gpSearch(input) {
      var group = input.getAttribute('data-gpf');
      var q = (input.value || '').toLowerCase().trim();
      var rows = document.querySelectorAll('tr[data-gpf="' + group + '"]');
      for (var i = 0; i < rows.length; i++) {
        var name = rows[i].getAttribute('data-gpname') || '';
        rows[i].style.display = (!q || name.indexOf(q) !== -1) ? '' : 'none';
      }
    }
    /* Like gpSearch, but collapses to the first data-gplimit rows when the box is
       empty (so a long live list shows a preview, full list searchable). Updates
       an optional counter element carrying data-gpcount="<group>". */
    function gpSearchTopN(input) {
      var group = input.getAttribute('data-gpf');
      var limit = parseInt(input.getAttribute('data-gplimit') || '10', 10);
      var q = (input.value || '').toLowerCase().trim();
      var rows = document.querySelectorAll('tr[data-gpf="' + group + '"]');
      var shown = 0, matches = 0, total = rows.length;
      for (var i = 0; i < rows.length; i++) {
        var name = rows[i].getAttribute('data-gpname') || '';
        var hit = !q || name.indexOf(q) !== -1;
        if (!hit) { rows[i].style.display = 'none'; continue; }
        matches++;
        if (!q && shown >= limit) { rows[i].style.display = 'none'; }
        else { rows[i].style.display = ''; shown++; }
      }
      var note = document.querySelector('[data-gpcount="' + group + '"]');
      if (note) {
        note.textContent = q ? (matches + ' of ' + total + ' match')
                             : ('Showing ' + Math.min(limit, total) + ' of ' + total);
      }
    }

    /* Action buttons (Re-deploy / Delete / Disable): POST via fetch, then reload
       or navigate. A plain onclick — the page CSP allows inline handlers but
       forbids 'unsafe-eval', so htmx's hx-on (which compiles with new Function)
       cannot be used here. */
    function gpAction(method, url, opts) {
      opts = opts || {};
      if (opts.confirm && !window.confirm(opts.confirm)) return;
      fetch(url, { method: method, credentials: 'include' }).then(function (r) {
        // Only navigate/reload on success — a 403 (permission) or 5xx must NOT look
        // like the action applied (gov UP-1 / enterprise BLOCKING). Surface the
        // server message (kept short) as an error toast and stay on the page.
        if (!r.ok) {
          return r.text().then(function (t) {
            showToast(t && t.length > 0 && t.length < 200 ? t : ('Action failed (' + r.status + ')'), 'error');
          });
        }
        if (opts.go) { window.location = opts.go; } else { location.reload(); }
      }).catch(function () { showToast('Network error — the action may not have applied', 'error'); });
    }

    /* Toast system (shared with the dashboard; used by action responses). */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      c.appendChild(t);
      if (level !== 'error')
        setTimeout(function () { t.remove(); }, 4000);
    }
    document.body.addEventListener('showToast', function (e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* htmx.config.allowEval=false (meta tag above) means an `[expr]` event filter
       or hx-on mistake fires htmx:evalDisallowedError instead of just silently
       always-matching; a raw CSP throw inside htmx's own eval attempt is caught
       internally and re-fired as htmx:syntax:error. Neither reaches window.onerror
       on its own — without these listeners the failure is invisible in the console,
       which is exactly how the round-2 search-box bug went unnoticed until a human
       hit tab+backspace enough times to see the input clear (round-3 item 5). */
    document.body.addEventListener('htmx:evalDisallowedError', function (e) {
      console.error('htmx eval disallowed (CSP) at', e.target, e.detail);
      showToast('A page control tried to run disallowed script — please report this.', 'error');
    });
    document.body.addEventListener('htmx:syntax:error', function (e) {
      console.error('htmx syntax/eval error at', e.target, e.detail);
    });

    /* ── Device live-snapshot helpers (feat/device-live-snapshot). Plain functions
       called from inline onclick/oninput (CSP-safe — 'unsafe-inline' allows attribute
       handlers; only hx-on/new Function is blocked). ── */
    function lsToggleAll(btn) {
      // Scoped to the button's OWN group (device_ui.cpp wraps "Live cards" and
      // "Physical" each in their own [data-lsgroup] container) so this never
      // reaches into the OTHER group's cards -- a document-wide query here would
      // snap open the lazy Physical cards as a side effect of the Live-cards
      // button (or vice-versa), firing every one of their dispatches at once.
      var group = btn.closest('[data-lsgroup]');
      var cards = (group || document).querySelectorAll('.ls-card');
      var anyClosed = Array.prototype.some.call(cards, function (c) { return !c.open; });
      cards.forEach(function (c) { c.open = anyClosed; });
      btn.textContent = anyClosed ? 'Collapse all' : 'Expand all';
    }
    function lsPopOut(ev, btn) {
      ev.preventDefault(); ev.stopPropagation(); /* don't toggle the <details> */
      var card = btn.closest('.ls-card'); if (!card) return;
      var dlg = document.getElementById('ls-popout');
      if (!dlg) {
        dlg = document.createElement('dialog'); dlg.id = 'ls-popout'; dlg.className = 'ls-po';
        dlg.innerHTML = '<div class="po-head"><span class="t" id="ls-po-title"></span>' +
          '<button class="po-close" onclick="document.getElementById(\'ls-popout\').close()">Close ×</button></div>' +
          '<div class="po-body" id="ls-po-body"></div>';
        document.body.appendChild(dlg);
      }
      var t = card.querySelector('.ls-ttl');
      dlg.querySelector('#ls-po-title').textContent = t ? t.textContent : '';
      var body = card.querySelector('.ls-body');
      dlg.querySelector('#ls-po-body').innerHTML = body ? body.innerHTML : '';
      dlg.showModal();
    }
    /* Process-tree filter (matches /tar): hide all, reveal each matching row's ancestor
       chain. Matches PID/name/hash/endpoint via row.textContent. Scoped to the nearest
       body so it works in the card AND the popped-out clone. */
    function lsFilterTree(input) {
      var scope = input.closest('.ls-body,.po-body'); if (!scope) return;
      var tree = scope.querySelector('.proctree'); if (!tree) return;
      var q = (input.value || '').trim().toLowerCase();
      var nodes = tree.querySelectorAll('.tar-tree-node,.tar-tree-leaf');
      if (!q) { nodes.forEach(function (el) { el.style.display = ''; }); return; }
      nodes.forEach(function (el) { el.style.display = 'none'; });
      tree.querySelectorAll('.tar-tree-row').forEach(function (row) {
        if (row.textContent.toLowerCase().indexOf(q) === -1) return;
        var el = row.closest('.tar-tree-leaf,.tar-tree-node');
        while (el && tree.contains(el)) {
          el.style.display = '';
          if (el.tagName === 'DETAILS') el.open = true;
          el = el.parentElement ? el.parentElement.closest('.tar-tree-node') : null;
        }
      });
    }
    /* Plain table-row filter (services, DNS). */
    function lsFilterRows(input) {
      var scope = input.closest('.ls-body,.po-body'); if (!scope) return;
      var q = (input.value || '').trim().toLowerCase();
      scope.querySelectorAll('tbody tr').forEach(function (tr) {
        var t = (tr.getAttribute('data-gpname') || tr.textContent).toLowerCase();
        tr.style.display = (!q || t.indexOf(q) !== -1) ? '' : 'none';
      });
    }

  </script>
)HTM"
    // Chunk 3: the Hardware CI record's generic action runner. Split into its own
    // literal because chunk 2 above sits at ~14 KB (measure with a full-range
    // rawcheck: tools/rawcheck.py scans only uncommitted diffs) and MSVC caps a
    // single string literal at 16,380 bytes (C2026) -- see the sibling warning in
    // instruction_ui.cpp. Keep prose OUT of this literal; explain here instead.
    //
    // hwRunAction(btn): reads the enclosing <form>'s data-plugin/data-action/
    // data-agent/data-host/data-class + its p_*/kv inputs, confirms (message
    // keyed by data-class), then POSTs straight to the EXISTING /api/command
    // route (no new dispatch endpoint -- that route's classify/authorize/
    // destructive-gate/audit/executions-tracking all apply unmodified). On
    // success it swaps the form's .hw-result sibling for the poll fragment
    // /fragments/hardware/ci/result and calls htmx.process() so the injected
    // hx-get actually fires (htmx only wires attributes it has already scanned).
    R"HTM(
  <script>
    function hwRunAction(btn) {
      var form = btn.closest('form');
      if (!form) return;
      var plugin = form.getAttribute('data-plugin');
      var action = form.getAttribute('data-action');
      var agent = form.getAttribute('data-agent');
      var host = form.getAttribute('data-host') || agent;
      var cls = form.getAttribute('data-class') || 'Read-only';
      var msg = 'Run ' + plugin + '.' + action + ' on ' + host + '?';
      if (cls === 'Destructive') {
        msg = 'DESTRUCTIVE — may be irreversible on ' + host + '. Run ' + plugin + '.' + action + '?';
      } else if (cls === 'Mutating') {
        msg = 'This changes state on ' + host + '. Run ' + plugin + '.' + action + '?';
      }
      if (!window.confirm(msg)) return;

      var params = {};
      form.querySelectorAll('input[name^="p_"],select[name^="p_"]').forEach(function (inp) {
        var key = inp.name.replace(/^p_/, '');
        if (inp.value !== '') params[key] = inp.value;
      });
      var kv = form.querySelector('textarea[name="kv"]');
      if (kv && kv.value) {
        kv.value.split('\n').forEach(function (line) {
          var i = line.indexOf('=');
          if (i > 0) {
            var k = line.slice(0, i).trim();
            var v = line.slice(i + 1).trim();
            if (k && !k.startsWith('#')) params[k] = v;
          }
        });
      }

      btn.disabled = true;
      fetch('/api/command', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plugin: plugin, action: action, agent_ids: [agent], params: params })
      }).then(function (r) {
        return r.json().then(function (d) { return { status: r.status, data: d }; });
      }).then(function (resp) {
        btn.disabled = false;
        var resultDiv = form.querySelector('.hw-result');
        if (resp.status >= 400) {
          var msg2 = (resp.data.error && resp.data.error.message) || ('Dispatch failed (' + resp.status + ')');
          if (typeof showToast === 'function') showToast(msg2, 'error');
          return;
        }
        var reached = resp.data.agents_reached || 0;
        if (reached === 0) {
          // Mirror device_routes.cpp's sent==0 handling for /fragments/device/live/run
          // (governance Gate 6 enterprise-readiness finding): a 0-agent dispatch used
          // to show a green "Sent to 0 agent(s)" toast and still start the up-to-28s
          // result poll, which can only ever time out — an honest warning and no poll
          // instead.
          if (typeof showToast === 'function')
            showToast('Device offline — action needs a connected agent', 'warning');
          return;
        }
        if (resultDiv) {
          var commandId = resp.data.command_id;
          resultDiv.innerHTML = '<div hx-get="/fragments/hardware/ci/result?id=' + encodeURIComponent(agent) +
            '&command_id=' + encodeURIComponent(commandId) + '&plugin=' + encodeURIComponent(plugin) +
            '&n=1" hx-trigger="load" hx-swap="outerHTML"><span class="gp-mute">Waiting for the device to respond&hellip;</span></div>';
          if (window.htmx) window.htmx.process(resultDiv);
        }
        if (typeof showToast === 'function') {
          showToast('Sent to ' + reached + ' agent(s)', 'success');
        }
      }).catch(function () {
        btn.disabled = false;
        if (typeof showToast === 'function') showToast('Network error — the action may not have applied', 'error');
      });
    }
  </script>
)HTM"
    // Chunk 4: Hardware CI record helpers (round 2). Own literal for the same
    // MSVC 16 KiB reason as chunk 3. Prose stays here, not in the literal.
    //
    // hwSyncNow(btn, source): POST /api/v1/hardware/{id}/sync, then swap the
    // lens body for the 2s poll fragment (await_since = the SERVER's requested_at).
    // hwTagSet / hwTagDelete: JSON to the EXISTING /api/tags/set and
    // /api/tags/delete, then reload the whole CI record (header chips + lens).
    // hwFilterResult(el): free-text or regex filter over a result's table rows
    // / pre lines, with a hit counter; an invalid regex marks the box red and
    // filters nothing. hwExportCsv(btn): RFC 4180 CSV of the VISIBLE rows
    // (pre output → one "line" column) via a Blob + temporary <a download>.
    // hwCopyResult(btn): visible text to the clipboard.
    R"HTM(
  <script>
    function hwReloadCi(agent, lens) {
      var mount = document.getElementById('guardian-detail'); if (!mount || !window.htmx) return;
      window.htmx.ajax('GET', '/fragments/hardware/ci?id=' + encodeURIComponent(agent) + '&lens=' + encodeURIComponent(lens || 'overview'), { target: '#guardian-detail', swap: 'innerHTML' });
    }
    function hwSyncNow(btn, source) {
      var agent = btn.getAttribute('data-agent'), lens = btn.getAttribute('data-lens') || 'overview';
      btn.disabled = true;
      fetch('/api/v1/hardware/' + encodeURIComponent(agent) + '/sync', { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source: source }) })
      .then(function (r) { return r.json().then(function (d) { return { status: r.status, data: d }; }); })
      .then(function (resp) {
        if (resp.status >= 400) { btn.disabled = false;
          showToast((resp.data.error && resp.data.error.message) || ('Sync request failed (' + resp.status + ')'), 'error'); return; }
        var d = resp.data.data; showToast('Sync requested (' + d.source + ')', 'success');
        // The header instance of this button lives OUTSIDE #hw-ci-lens and is never
        // replaced by the lens re-render below, so it needs its own explicit
        // re-enable here (governance Gate 4 happy-path finding: it was stuck
        // disabled after every successful header sync). The two in-lens instances
        // get a fresh, already-enabled button when the poll below replaces their
        // markup, so this is a harmless no-op for them.
        btn.disabled = false;
        var lensDiv = document.getElementById('hw-ci-lens'); if (!lensDiv) return;
        // Round-3 item 4: first poll at 1s (was a flat 2s) \u2014 the poll ladder's
        // 1s/1s/2s\u2026 cadence continues from render_hardware_sync_pending
        // (hardware_ui.cpp) once this first pending div's own request lands.
        lensDiv.innerHTML = '<div hx-get="/fragments/hardware/ci?id=' + encodeURIComponent(agent) + '&lens=' + encodeURIComponent(lens) +
          '&lens_only=1&await_since=' + d.requested_at + '&n=1&command_id=' + encodeURIComponent(d.command_id) +
          '" hx-trigger="load delay:1s" hx-swap="outerHTML"><span class="gp-mute">Sync requested \u2014 waiting for the device to report\u2026 usually a couple of seconds on Linux/Windows, up to ~15s on macOS the first time.</span></div>';
        if (window.htmx) window.htmx.process(lensDiv);
      }).catch(function () { btn.disabled = false; showToast('Sync request failed', 'error'); });
    }
    function hwPostJson(url, body, ok) {
      return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(function (r) { return r.text().then(function (t) { return { status: r.status, text: t }; }); })
        .then(function (resp) {
          if (resp.status >= 400) {
            var msg = 'Request failed (' + resp.status + ')';
            try { var j = JSON.parse(resp.text); msg = (j.error && j.error.message) || j.error || msg; } catch (e) { if (resp.text && resp.text.length < 200) msg = resp.text; }
            showToast(msg, 'error'); return;
          }
          ok();
        }).catch(function () { showToast('Network error', 'error'); });
    }
    function hwTagSet(btn) {
      var form = btn.closest('form'); if (!form) return;
      var agent = form.getAttribute('data-agent');
      var key = (form.querySelector('input[name="key"]').value || '').trim();
      var value = (form.querySelector('input[name="value"]').value || '').trim();
      if (!key) { showToast('Tag key is required', 'error'); return; }
      if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) { showToast('Tag key: letters, digits, _ . : - (max 64)', 'error'); return; }
      btn.disabled = true;
      hwPostJson('/api/tags/set', { agent_id: agent, key: key, value: value }, function () {
        showToast('Tag ' + key + ' set', 'success'); hwReloadCi(agent, 'tags');
      }).then(function () { btn.disabled = false; });
    }
    function hwTagDelete(a) {
      var agent = a.getAttribute('data-agent'), key = a.getAttribute('data-key');
      if (!window.confirm('Remove tag ' + key + '?')) return;
      hwPostJson('/api/tags/delete', { agent_id: agent, key: key }, function () {
        showToast('Tag ' + key + ' removed', 'success'); hwReloadCi(agent, 'tags');
      });
    }
    function hwFilterResult(el) {
      var tool = el.closest('.hw-rtool'); if (!tool) return;
      var body = tool.nextElementSibling; if (!body) return;
      var input = tool.querySelector('input[type="text"]');
      var useRe = tool.querySelector('input[type="checkbox"]').checked;
      var q = (input.value || '').trim(), test = null;
      input.classList.remove('bad');
      if (q) {
        if (useRe) { try { var re = new RegExp(q, 'i'); test = function (t) { return re.test(t); }; } catch (e) { input.classList.add('bad'); } }
        else { var lq = q.toLowerCase(); test = function (t) { return t.toLowerCase().indexOf(lq) !== -1; }; }
      }
      var items = body.querySelectorAll('tbody tr, .hw-line'), shown = 0;
      for (var i = 0; i < items.length; i++) {
        var hit = !test || test(items[i].textContent || '');
        items[i].style.display = hit ? '' : 'none';
        if (items[i].classList.contains('hw-line')) items[i].classList.toggle('hit', !!(test && hit));
        if (hit) shown++;
      }
      var cnt = tool.querySelector('.cnt'); if (cnt) cnt.textContent = shown + ' / ' + items.length + (items[0] && items[0].tagName === 'TR' ? ' rows' : ' lines');
    }
    function hwCsvCell(v) { v = String(v == null ? '' : v); return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
    function hwExportCsv(btn) {
      var tool = btn.closest('.hw-rtool'); if (!tool) return;
      var body = tool.nextElementSibling; if (!body) return;
      var rows = [], table = body.querySelector('table');
      if (table) {
        var ths = table.querySelectorAll('thead th'); var hdr = [];
        for (var h = 0; h < ths.length; h++) hdr.push(hwCsvCell(ths[h].textContent));
        rows.push(hdr.join(','));
        var trs = table.querySelectorAll('tbody tr');
        for (var i = 0; i < trs.length; i++) { if (trs[i].style.display === 'none') continue;
          var tds = trs[i].querySelectorAll('td'), cells = [];
          for (var j = 0; j < tds.length; j++) cells.push(hwCsvCell(tds[j].textContent));
          rows.push(cells.join(',')); }
      } else {
        rows.push('line');
        var lines = body.querySelectorAll('.hw-line');
        for (var k = 0; k < lines.length; k++) { if (lines[k].style.display === 'none') continue; rows.push(hwCsvCell(lines[k].textContent)); }
      }
      var csv = rows.join('\r\n'), name = (btn.getAttribute('data-name') || 'result') + '.csv';
      var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
      showToast('Exported ' + (rows.length - 1) + ' row(s)', 'success');
    }
    function hwCopyResult(btn) {
      var tool = btn.closest('.hw-rtool'); if (!tool) return;
      var body = tool.nextElementSibling; if (!body) return;
      var parts = [], items = body.querySelectorAll('tbody tr, .hw-line');
      for (var i = 0; i < items.length; i++) if (items[i].style.display !== 'none') parts.push(items[i].textContent);
      var text = parts.length ? parts.join('\n') : (body.textContent || '');
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { showToast('Copied', 'success'); }, function () { showToast('Copy failed', 'error'); });
      else showToast('Clipboard unavailable', 'error');
    }
  </script>
)HTM"
    // Chunk 5: Hardware list bulk tagging (round 3 item 7) — ServiceNow/Intune-
    // style checkbox selection + a sticky action bar (markup already emitted by
    // hardware_ui.cpp's render_hardware_results_region / row_html). Own literal
    // for the same MSVC 16 KiB reason as chunks 3-4.
    //
    // hwSel: the live selection, keyed by agent_id — a plain Set, not DOM state,
    // so it survives a #hw-results outerHTML swap (pagination/sort/filter/search
    // all replace the whole div). hwSelToggle/hwSelAll/hwSelClear mutate it and
    // call hwSelRender to show/hide the sticky bar and update its count. The
    // htmx:afterSwap listener re-checks boxes from the Set after any #hw-results
    // re-render so a selection made on page 1 is still reflected if the operator
    // re-sorts without clearing it.
    //
    // hwBulkTag(btn, mode): validates the key with the SAME regex hwTagSet uses,
    // then fans the selection out over the EXISTING single-agent /api/tags/set or
    // /api/tags/delete (never a new bulk route — each call still runs its own
    // per-target scoped Tag:Write gate + tag.set/.delete audit row, so a bulk
    // apply produces the identical audit trail N individual edits would have).
    // kHwBulkWorkers bounds concurrency so a large selection doesn't fire
    // hundreds of simultaneous requests; a 403 is counted as "denied" (reported
    // separately from other failures) rather than folded into a generic error.
    R"HTM(
  <script>
    var hwSel = new Set();
    function hwSelRender() {
      var bar = document.getElementById('hw-selbar');
      var count = document.getElementById('hw-selcount');
      if (!bar || !count) return;
      count.textContent = hwSel.size + ' selected';
      bar.classList.toggle('show', hwSel.size > 0);
    }
    function hwSelToggle(cb) {
      if (cb.checked) hwSel.add(cb.value); else hwSel.delete(cb.value);
      hwSelRender();
    }
    function hwSelAll(cb) {
      var boxes = document.querySelectorAll('#hw-results .hw-sel');
      for (var i = 0; i < boxes.length; i++) {
        boxes[i].checked = cb.checked;
        if (cb.checked) hwSel.add(boxes[i].value); else hwSel.delete(boxes[i].value);
      }
      hwSelRender();
    }
    function hwSelClear() {
      hwSel.clear();
      var boxes = document.querySelectorAll('#hw-results .hw-sel');
      for (var i = 0; i < boxes.length; i++) boxes[i].checked = false;
      var all = document.querySelector('#hw-results thead input[type="checkbox"]');
      if (all) all.checked = false;
      hwSelRender();
    }
    document.body.addEventListener('htmx:afterSwap', function (e) {
      if (!e.detail || !e.detail.target || e.detail.target.id !== 'hw-results') return;
      var boxes = e.detail.target.querySelectorAll('.hw-sel');
      for (var i = 0; i < boxes.length; i++) boxes[i].checked = hwSel.has(boxes[i].value);
      hwSelRender();
    });
    var kHwBulkWorkers = 4;
    function hwBulkRun(ids, run, done) {
      if (!ids.length) { done(0, 0, []); return; }
      var next = 0, ok = 0, denied = 0, failed = [], active = 0;
      function pump() {
        while (active < kHwBulkWorkers && next < ids.length) {
          (function (id) {
            active++;
            run(id).then(function (r) {
              active--;
              if (r === true) ok++;
              else if (r === 'denied') { denied++; failed.push(id); }
              else failed.push(id);
              if (next >= ids.length && active === 0) done(ok, denied, failed);
              else pump();
            });
          })(ids[next++]);
        }
      }
      pump();
    }
    function hwBulkFetchTag(url, body) {
      return fetch(url, { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(function (r) {
          if (r.status === 200 || r.status === 204) return true;
          if (r.status === 403) return 'denied';
          return false;
        }).catch(function () { return false; });
    }
    function hwBulkRefresh() {
      var results = document.getElementById('hw-results');
      if (!results || !window.htmx) return;
      var url = results.getAttribute('data-url');
      if (!url) return;
      window.htmx.ajax('GET', url, { target: '#hw-results', swap: 'outerHTML' });
    }
    function hwBulkTag(btn, mode) {
      var ids = Array.from(hwSel);
      if (!ids.length) { showToast('No devices selected', 'error'); return; }
      var key, value;
      if (mode === 'set') {
        key = (document.getElementById('hw-bulk-key').value || '').trim();
        value = (document.getElementById('hw-bulk-value').value || '').trim();
      } else {
        key = (document.getElementById('hw-bulk-rkey').value || '').trim();
        value = '';
      }
      if (!key) { showToast('Tag key is required', 'error'); return; }
      if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) { showToast('Tag key: letters, digits, _ . : - (max 64)', 'error'); return; }
      btn.disabled = true;
      var url = mode === 'set' ? '/api/tags/set' : '/api/tags/delete';
      hwBulkRun(ids, function (id) {
        var body = mode === 'set' ? { agent_id: id, key: key, value: value } : { agent_id: id, key: key };
        return hwBulkFetchTag(url, body);
      }, function (ok, denied, failed) {
        btn.disabled = false;
        var verb = mode === 'set' ? 'Tagged' : 'Untagged';
        if (!failed.length) {
          showToast(verb + ' ' + ok + '/' + ids.length, 'success');
        } else {
          var shown = failed.slice(0, 3).join(', ') + (failed.length > 3 ? ', …' : '');
          var reason = denied ? (denied + ' denied') : (failed.length + ' failed');
          showToast(verb + ' ' + ok + '/' + ids.length + ' — ' + reason + ': ' + shown, 'error');
        }
        hwBulkRefresh();
      });
    }
  </script>
)HTM"
    R"HTM(
</body>
</html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kGuardianDetailPageHtml =
    yuzu::server::shell::bake(kGuardianDetailPageTemplate, {.active_key = "guardian"});
// NOLINTEND(cert-err58-cpp)
