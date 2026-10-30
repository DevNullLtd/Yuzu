// Echo dashboard page (Phase 15.A — issue #547).
// Hosts the retention-paused source list as the first frame; the
// scope-walking-aware SQL frame (Phase 15.D) and the process-tree viewer
// (Phase 15.H) drop in later. Compiled in its own translation unit to keep
// the long raw string literal away from server.cpp's brace matching.
//
// Design: docs/echo-dashboard.md.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kEchoPageTemplate = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — Echo</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { display: flex; flex-direction: column; min-height: calc(100vh - var(--shell-top-h)); }
    .echo-content {
      width: 100%; flex: 1; padding: 22px 28px 36px;
      display: flex; flex-direction: column; gap: 22px;
    }
    .echo-ph h1 {
      font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2;
      color: var(--ink);
    }
    .echo-subtitle { color: var(--mut); font-size: 14px; margin: 4px 0 0; max-width: 70ch; }

    /* Frames are yuzu.css panels (.panel / .tw); the header row stays local because look's .hd also sets
       font-size / weight on everything inside it. Tables in a frame take the shared .tw table skin. */
    .echo-frame { overflow: hidden; }
    .echo-frame-header {
      display: flex; flex-wrap: wrap; align-items: center; gap: 8px 14px;
      padding: 12px 16px; border-bottom: 1px solid var(--line);
    }
    .echo-frame-title { font-size: 14px; font-weight: 600; margin: 0; }
    .echo-frame-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-left: auto; }
    .echo-pad { padding: 16px; }
    #retention-paused-body > :not(table):not(.result-degrade-banner),
    #capture-sources > .picker-row,
    #cap-sources-body > :not(table):not(.apply-bar):not(.result-degrade-banner) { margin: 0; padding: 14px 16px; }
    .echo-content code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .echo-meta { font-size: 13px; color: var(--mut); }
    .echo-meta strong, .echo-meta b { color: var(--ink); font-weight: 600; }
    .echo-frame-body .placeholder, .echo-frame-body .empty-state {
      text-align: center; color: var(--mut); font-size: 14px;
    }
    .echo-frame-body .placeholder { padding: 28px 16px; }
    .echo-frame-body .empty-state strong { color: var(--ink); font-weight: 600; }
    .echo-frame-body .result-degrade-banner {
      margin: 12px 16px; padding: 12px 14px; text-align: left; font-size: 13.5px;
      color: var(--ink2); background: var(--surface2); border-radius: var(--rad-panel);
      border: 1px solid color-mix(in srgb, var(--warn) 50%, var(--line2));
    }
    .result-degrade-banner b { color: var(--ink); }
    .echo-row-error { color: var(--bad); }
    .echo-row-error td { font-style: italic; }
    .echo-row-note { color: var(--mut); font-size: 13px; }

    /* Buttons: raised by default, primary for the one main action, text links in table rows */
    .echo-content button {
      display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 10px;
      font: inherit; font-size: 13px; font-weight: 500; line-height: 1; white-space: nowrap;
      color: var(--ink); background: var(--raise); border: 1px solid var(--line2);
      border-radius: var(--rad-ctl); cursor: pointer;
      transition: background-color .12s, border-color .12s;
    }
    .echo-content button:hover:not(:disabled) { background: var(--surface2); border-color: var(--mut); }
    .echo-content button:disabled { opacity: .5; cursor: default; }
    .echo-content button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    .echo-content .apply-push {
      color: var(--on-primary); background: var(--primary); border-color: var(--primary); font-weight: 600;
    }
    .echo-content .apply-push:hover:not(:disabled) {
      background: var(--primary-h); border-color: var(--primary-h);
    }
    .echo-content td .btn-secondary, .echo-content td .btn-danger {
      padding: 0 6px; color: var(--primary); background: none; border-color: transparent;
    }
    .echo-content td .btn-danger { color: var(--bad); }
    .echo-content td .btn-secondary:hover:not(:disabled), .echo-content td .btn-danger:hover:not(:disabled) {
      background: none; border-color: transparent; text-decoration: underline;
    }

    /* Form fields */
    .picker-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
    .picker-row label, .filter-label, .tt-filter-label {
      font-size: 13px; font-weight: 500; color: var(--ink2);
    }
    .echo-tree-filter, .echo-tree-custom input[type="datetime-local"] {
      color: var(--ink); background: var(--bg); border: 1px solid var(--line2);
      border-radius: var(--rad-ctl);
      height: var(--ctl); padding: 0 10px; min-width: 0; font: inherit; font-size: 14px;
    }
    .src-note { font-size: 12.5px; color: var(--mut); }
    .echo-content input[type="checkbox"] { accent-color: var(--primary); }
    .echo-tree-filter::placeholder { color: var(--faint); }
    .echo-sql-moved a { color: var(--primary); }

    /* ── Process tree viewer (Phase 15.H) ───────────────────────────────── */
    .echo-tree-toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .echo-tree-custom { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .echo-tree-custom label { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--ink2); }
    /* Segmented control: preset ranges, state filter, capture category filter */
    .echo-tree-presets, .echo-seg {
      display: inline-flex; flex-wrap: wrap; gap: 2px; padding: 2px;
      background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .echo-chip {
      display: inline-flex; align-items: center; gap: 6px; height: calc(var(--ctl) - 8px);
      padding: 0 12px; border-radius: 2px; cursor: pointer; user-select: none;
      font-size: 13px; font-weight: 500; color: var(--mut);
    }
    .echo-chip:hover { color: var(--ink); }
    .echo-chip.on {
      color: var(--ink); background: var(--raise); font-weight: 600;
      box-shadow: inset 0 0 0 1px var(--line2);
    }
    .echo-tree-custom .echo-chip {
      height: var(--ctl); padding: 0 14px; color: var(--ink); background: var(--raise);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .echo-tree-custom .echo-chip:hover { background: var(--surface2); border-color: var(--mut); }
    /* Filter bar (state + anomalies + text) */
    .echo-tree-filterbar {
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
      margin: 12px 0; padding-top: 12px; border-top: 1px solid var(--line);
    }
    .tt-anom-toggle { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--ink2); }
    .echo-tree-filter { flex: 1 1 12rem; min-width: 10rem; }
    .echo-tree-banner, .echo-tree-note, .echo-tree-warn, .echo-tree-empty, .echo-tree-loading,
    .echo-tree-nomatch { font-size: 13px; color: var(--mut); margin: 6px 0; }
    .echo-tree-note code { color: var(--ink2); }
    .echo-tree-banner b { color: var(--ink); font-weight: 600; }
    .echo-tree-warn { color: var(--warn); }
    .echo-tree-mute, .echo-tree-pid { color: var(--mut); }
    .echo-tree-pid { font-size: 12.5px; font-weight: 400; margin-left: 6px; }

    /* Tree */
    .echo-tree { font-family: var(--mds-font-family-mono); font-size: 12.5px; margin-top: 8px; line-height: 1.7; }
    .echo-tree-node { margin: 0; }
    .echo-tree-node > summary { display: flex; align-items: center; list-style: none; cursor: pointer; }
    .echo-tree-node > summary::-webkit-details-marker { display: none; }
    .echo-tree-node > summary::before {
      content: "\25B8"; flex: 0 0 1rem; text-align: center; font-size: 11px; color: var(--faint);
    }
    .echo-tree-node[open] > summary::before { content: "\25BE"; }
    .echo-tree-children { margin-left: 8px; padding-left: 12px; border-left: 1px solid var(--line2); }
    .echo-tree-leaf { display: flex; align-items: center; padding-left: 1rem; }
    .echo-tree-row {
      display: inline-flex; align-items: center; gap: 8px; flex: 1 1 auto; min-width: 0;
      color: var(--ink); text-decoration: none; cursor: pointer;
      padding: 0 6px; border-radius: 2px;
    }
    .echo-tree-row:hover { background: var(--surface2); }
    .echo-tree-row[data-anom="1"] { box-shadow: inset 3px 0 0 var(--bad); }
    .echo-tree-row[data-state="exited"] { opacity: 0.78; }
    .tt-dot { width: 8px; height: 8px; flex: 0 0 auto; }
    .tt-dot-run { background: var(--ok); }
    .tt-dot-exit { background: var(--faint); }
    .tt-pid { flex: 0 0 auto; min-width: 3.4rem; text-align: right; color: var(--mut); }
    .tt-name { color: var(--ink); font-weight: 600; white-space: nowrap; }
    .echo-tree-row[data-state="exited"] .tt-name { font-weight: 500; color: var(--mut); }
    .tt-user { color: var(--ink2); font-size: 12px; white-space: nowrap; }
    .tt-meta { color: var(--mut); font-size: 12px; white-space: nowrap; }
    .tt-anom { color: var(--bad); }
    /* Inline network summary */
    .tt-net {
      display: inline-flex; align-items: center; gap: 4px; min-width: 0; overflow: hidden;
      font-size: 11.5px; color: var(--mut);
    }
    .tt-net-ico { color: var(--mut); }
    .tt-net-pub .tt-net-ico, .tt-ep-pub { color: var(--warn); }
    .tt-ep { background: var(--surface2); border-radius: 3px; padding: 0 6px; white-space: nowrap; }
    .tt-ep-more { opacity: 0.7; }
    /* Same-name sibling group ("svchost.exe ×42") */
    .tt-group { color: var(--mut); }
    .tt-group-ico { flex: 0 0 auto; font-size: 11px; color: var(--mut); }
    .tt-group-count {
      color: var(--ink); font-weight: 600; background: var(--surface2);
      border-radius: 3px; padding: 0 6px; font-size: 12px;
    }

    /* Two-column layout: scrollable tree + right-hand detail panel */
    .echo-tree-layout { display: flex; gap: 16px; align-items: flex-start; margin-top: 12px; }
    .echo-tree-main { flex: 1 1 auto; min-width: 0; overflow-x: auto; }
    .echo-tree-side {
      flex: 0 0 340px; max-height: calc(100vh - var(--shell-top-h) - 2rem); overflow: auto;
      border: 1px solid var(--line); border-radius: var(--rad-panel);
    }
    .echo-tree-side > div > .echo-tree-mute { padding: 14px 16px; font-size: 13px; }
    @media (max-width: 1000px) {
      .echo-tree-layout { flex-direction: column; }
      .echo-tree-side { position: static; flex-basis: auto; width: 100%; max-height: none; }
    }

    /* Detail panel */
    .echo-detail { font-size: 13.5px; }
    .echo-detail-title { padding: 12px 16px; font-size: 14px; font-weight: 600; border-bottom: 1px solid var(--line); }
    .echo-kv { display: flex; justify-content: space-between; gap: 16px; padding: 9px 16px; border-bottom: 1px solid var(--line); }
    .echo-kv-k { flex: 0 0 auto; color: var(--mut); }
    .echo-kv-v { min-width: 0; text-align: right; font-weight: 500; color: var(--ink); overflow-wrap: anywhere; }
    code.echo-kv-v { font-weight: 400; }
    .echo-kv-v.echo-tree-mute { font-weight: 400; color: var(--mut); }
    .echo-detail-section { padding: 12px 16px 8px; font-size: 13px; font-weight: 600; }
    .echo-detail-anom { padding: 10px 16px; color: var(--bad); border-bottom: 1px solid var(--line); }
    .echo-detail > .echo-tree-mute { padding: 0 16px 14px; }
    .echo-detail-conns { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    table.echo-detail-conns th, table.echo-detail-conns td {
      text-align: left; padding: 6px 8px; white-space: nowrap; border-bottom: 1px solid var(--line);
    }
    .echo-detail-conns th:first-child, .echo-detail-conns td:first-child { padding-left: 16px; }
    table.echo-detail-conns th { font-weight: 500; color: var(--mut); background: var(--surface2); }
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate
// (still one continuous <style> block in the rendered HTML).
R"HTM(
    /* Device DNS/ARP panels (ADR-0015) — embedded below the process tree */
    .devnet-row { display: flex; gap: 16px; margin-top: 16px; padding-top: 16px;
      border-top: 1px solid var(--line); flex-wrap: wrap; }
    .devnet-panel { flex: 1 1 22rem; min-width: 18rem; overflow: hidden; background: var(--surface);
      border: 1px solid var(--line); border-radius: var(--rad-panel); }
    .devnet-panel > summary { list-style: none; cursor: pointer; display: flex; align-items: center;
      justify-content: space-between; gap: 8px; padding: 12px 16px; font-size: 14px; font-weight: 600; }
    .devnet-panel[open] > summary { border-bottom: 1px solid var(--line); }
    .devnet-panel > summary > span:first-of-type { flex: 1 1 auto; }
    .devnet-panel > summary::-webkit-details-marker { display: none; }
    .devnet-panel > summary::before { content: "\25B8"; color: var(--faint); font-size: 11px; margin-right: 4px; }
    .devnet-panel[open] > summary::before { content: "\25BE"; }
    .devnet-title-ico { color: var(--mut); margin-right: 6px; }
    .devnet-count { font-weight: 500; color: var(--ink2); background: var(--surface2);
      border-radius: 3px; padding: 0 8px; font-size: 12.5px; }
    .devnet-body { max-height: 18rem; overflow: auto; }
    .devnet-table { width: 100%; border-collapse: collapse;
      font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    /* table.-prefixed: ties with look's (0,1,2) .tw table th/td and wins by source order */
    table.devnet-table th { position: sticky; top: 0; background: var(--surface2); text-align: left;
      padding: 6px 12px; color: var(--mut); font-weight: 500; border-bottom: 1px solid var(--line); }
    table.devnet-table td { padding: 6px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }
    /* Table-prefixed so the cell colours outrank look's .tw table td */
    .devnet-table .dn-type { color: var(--ink); font-weight: 500; }
    .devnet-table .dn-data, .devnet-table .arp-mac, .devnet-table .arp-type-dynamic { color: var(--ink2); }
    .devnet-table .dn-ttl { color: var(--mut); text-align: right; }
    .devnet-table .dn-src, .devnet-table .arp-type-static { color: var(--mut); }
    .devnet-table .arp-type-other { color: var(--warn); } /* incomplete / unresolved */
    .devnet-caveat { padding: 8px 16px; font-size: 12.5px; color: var(--mut); border-top: 1px solid var(--line); }
    .devnet-empty { padding: 28px 16px; text-align: center; color: var(--mut); font-size: 14px; }

    /* Capture-sources frame (ADR-0015) — toggles, category filter, push guardrail */
    .cat-filter { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    #capTable .src-name { font-family: var(--mds-font-family-mono); font-size: 12.5px; font-weight: 500; color: var(--ink); }
    #capTable .src-dollar { font-family: var(--mds-font-family-mono); font-size: 12px; color: var(--mut); }
    #capTable .cat { color: var(--ink2); }
    .badge-new { background: var(--mds-color-bg-info-tinted); color: var(--info); }
    .badge-pii { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .badge-rows { background: var(--surface2); color: var(--mut); font-family: var(--mds-font-family-mono); }
    .os-cell { font-size: 12.5px; white-space: nowrap; }
    #capTable .os-ok { color: var(--ok); }
    #capTable .os-con { color: var(--warn); }
    #capTable .os-planned { color: var(--mut); }
    /* Switch (design .sw): 36x20 track, 16px square knob */
    .tgl { position: relative; display: inline-block; flex: 0 0 36px; width: 36px; height: 20px; }
    .tgl input { opacity: 0; width: 0; height: 0; }
    .tgl .sl { position: absolute; cursor: pointer; inset: 0; background: var(--line2);
      border-radius: 3px; transition: background-color .12s; }
    .tgl .sl:before { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
      background: var(--raise); border-radius: 2px; transition: transform .12s; }
    .tgl input:checked + .sl { background: var(--primary); }
    .tgl input:checked + .sl:before { background: var(--on-primary); transform: translateX(16px); }
    .tgl input:focus-visible + .sl { outline: 2px solid var(--focus); outline-offset: 2px; }
    .tgl.locked .sl { cursor: not-allowed; opacity: 0.55; }
    .state-cell { display: flex; align-items: center; gap: 10px; }
    .state-txt { font-size: 12.5px; color: var(--mut); }
    .state-on { color: var(--ok); font-weight: 500; }
    .pending-txt { color: var(--warn); font-weight: 500; }
    #capTable tr.pending td { background: color-mix(in srgb, var(--warn) 10%, transparent); }
    #capTable tr.pending td:first-child { box-shadow: inset 3px 0 0 var(--warn); }
    /* Notes and warning frame come from yuzu.css (.note.warn); only the flex row and margin are local */
    .apply-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin: 12px 16px; }
    .apply-bar[hidden] { display: none; }
    .apply-icon { color: var(--warn); }
    .apply-spacer { flex: 1; }
    @media (max-width: 640px) { .echo-content { padding: 16px; } }
  </style>
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals are
// concatenated by the compiler, so the rendered HTML is byte-identical.
R"HTM(</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <div class="echo-content">
    <div class="echo-ph">
      <h1>Echo</h1>
      <p class="echo-subtitle">
        Echo activity record: what ran, what it connected to, and what
        changed, recorded on each device.
      </p>
    </div>

    <!-- ── Retention-paused sources (Phase 15.A) ─────────────────────── -->
    <div class="echo-frame panel" id="frame-retention-paused">
      <div class="echo-frame-header">
        <h2 class="echo-frame-title">Retention-paused sources</h2>
        <div class="echo-frame-actions">
          <button class="btn-secondary"
                  hx-post="/fragments/echo/retention-paused/scan"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Scan fleet
          </button>
          <button hx-get="/fragments/echo/retention-paused"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Refresh
          </button>
        </div>
      </div>
      <div class="echo-frame-body tw" id="retention-paused-body"
           hx-get="/fragments/echo/retention-paused"
           hx-trigger="load"
           hx-swap="innerHTML">
        <div class="placeholder">Loading paused sources&hellip;</div>
      </div>
    </div>

)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate.
R"HTM(    <!-- ── Capture sources (ADR-0015) ───────────────────────────────── -->
    <div class="echo-frame panel" id="frame-capture-sources">
      <div class="echo-frame-header">
        <h2 class="echo-frame-title">Capture sources</h2>
      </div>
      <div class="echo-frame-body tw" id="capture-sources"
           hx-get="/fragments/echo/capture-sources" hx-trigger="load" hx-swap="innerHTML">
        <div class="placeholder">Loading capture sources&hellip;</div>
      </div>
    </div>
    <script>
    // Phase 15.A retention-paused purge: typed-hostname confirmation via a native
    // prompt() (CSP-safe — no eval/hx-on, mirrors the native confirm() used for
    // re-enable), then an htmx POST that swaps the row's action cell with the
    // server's "dispatched" note. Values come from data-* attributes (HTML-escaped
    // server-side) — never interpolated into this script.
    function echoPurgeConfirm(btn){
      var dev=btn.getAttribute('data-device'),host=btn.getAttribute('data-host'),source=btn.getAttribute('data-source');
      var typed=window.prompt('DESTRUCTIVE: permanently delete all '+source+' data on '+host+'.\nThe source stays paused; this cannot be undone.\n\nType the device hostname to confirm:');
      if(typed===null)return;
      if(typed!==host){if(typeof showToast==='function')showToast('Hostname did not match — purge cancelled','error');return;}
      htmx.ajax('POST','/fragments/echo/retention-paused/purge',{values:{device_id:dev,source:source},target:btn.closest('td'),swap:'innerHTML'});
    }
    // Capture-sources staged-then-push guardrail + category filter (ADR-0015). Plain
    // onclick/onchange handlers (CSP-safe — no hx-on/eval). A toggle only STAGES a
    // change; nothing is dispatched until Push.
    function capDirtyRows(){return Array.prototype.slice.call(document.querySelectorAll('#capTable tbody tr.pending'));}
    function refreshCapBar(){var n=capDirtyRows().length,bar=document.getElementById('capApplyBar');if(!bar)return;bar.hidden=(n===0);var m=document.getElementById('capApplyMsg');if(m)m.textContent=n+' pending change'+(n===1?'':'s')+' — not yet sent';}
    function setCapState(tr,on){var st=tr.querySelector('.state-txt');if(!st)return;st.textContent=on?'enabled':'disabled';st.classList.remove('pending-txt');st.classList.toggle('state-on',on);}
    function stageCapToggle(cb){var tr=cb.closest('tr');var committed=cb.dataset.committed==='true';var dirty=cb.checked!==committed;tr.classList.toggle('pending',dirty);if(dirty){var st=tr.querySelector('.state-txt');st.textContent=(cb.checked?'→ enable':'→ disable')+' (pending)';st.classList.add('pending-txt');st.classList.remove('state-on');}else{setCapState(tr,committed);}refreshCapBar();}
    function discardCapChanges(){capDirtyRows().forEach(function(tr){var cb=tr.querySelector('input[type=checkbox]');cb.checked=(cb.dataset.committed==='true');setCapState(tr,cb.checked);tr.classList.remove('pending');});refreshCapBar();}
    function pushCapChanges(){var rows=capDirtyRows();if(!rows.length)return;var t=document.getElementById('capTable');var device=t?t.getAttribute('data-device'):'';var parts=rows.map(function(tr){var cb=tr.querySelector('input[type=checkbox]');return cb.dataset.source+'='+(cb.checked?'on':'off');});htmx.ajax('POST','/fragments/echo/capture-sources/push',{values:{device:device,changes:parts.join(',')},swap:'none'}).then(function(){if(typeof showToast==='function')showToast('Pushed '+parts.length+' change(s) to '+device,'success');htmx.ajax('GET','/fragments/echo/capture-sources/load',{values:{device:device},target:'#cap-sources-body',swap:'innerHTML'});});}
    function filterCap(chip,cat){document.querySelectorAll('#capFilter .echo-chip').forEach(function(c){c.classList.toggle('on',c===chip);});document.querySelectorAll('#capTable tbody tr').forEach(function(tr){tr.style.display=(cat==='all'||tr.getAttribute('data-cat')===cat)?'':'none';});}
    </script>
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate.
R"HTM(
    <!-- Ad-hoc Echo SQL moved to Result sets > From Echo query (it carries the same parent
         scope, SQL, name and include-empty fields, behind a confirm that shows the SQL). -->
    <div class="echo-frame panel" id="frame-echo-sql">
      <div class="echo-frame-header">
        <h2 class="echo-frame-title">Ad-hoc Echo SQL</h2>
      </div>
      <div class="echo-frame-body echo-pad echo-sql-moved">
        Ad-hoc Echo queries now start from <a href="/result-sets">Result sets</a>: choose
        <strong>From Echo query</strong> to run a SELECT on a scope and keep the devices that answer.
      </div>
    </div>

    <!-- ── Process tree viewer (Phase 15.H) ─────────────────────────── -->
    <div class="echo-frame panel" id="frame-process-tree">
      <div class="echo-frame-header">
        <h2 class="echo-frame-title">Process tree viewer</h2>
      </div>
      <div class="echo-frame-body tw echo-pad">
        <!-- No hx-target here: the default target is this element itself. An
             explicit hx-target="this" would be INHERITED by descendants (the poll
             div), making their swaps clobber this whole frame body. -->
        <div hx-get="/fragments/echo/process-tree" hx-trigger="load" hx-swap="innerHTML">
          <div class="echo-tree-loading">Loading process tree viewer&hellip;</div>
        </div>
      </div>
    </div>
  </div>

  <div id="toast-container" class="toast-container"></div>

)HTM"
// Split here (not a content boundary): MSVC caps a single string literal at
// 16380 chars (C2026) and this page exceeds it. Adjacent raw-string literals
// are concatenated by the compiler, so the rendered HTML is byte-identical.
R"HTM(<script>
function showToast(message, level) {
  var c = document.getElementById('toast-container');
  if (!c) return;
  var t = document.createElement('div');
  t.className = 'toast toast-' + (level || 'info');
  t.textContent = message;
  var close = document.createElement('button');
  close.textContent = '×';
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

// ── Process tree viewer: client-side filters (no round-trip) ─────────────
// Combines a state filter (all/running/exited), an anomalies-only toggle, and a
// text query over each row. A row is shown if it matches ALL active filters; its
// ancestor branches are revealed + expanded so the tree stays navigable. Re-applied
// after every tree swap (htmx:afterSettle) since the toolbar lives outside #echo-tree.
window.__ttState = 'all';
function echoTreeState(s, el) {
  window.__ttState = s;
  if (el && el.parentElement) {
    el.parentElement.querySelectorAll('[data-statechip]').forEach(function(c){
      c.classList.toggle('on', c === el);
    });
  }
  applyEchoTreeFilters();
}
function applyEchoTreeFilters() {
  var tree = document.querySelector('#echo-tree .echo-tree');
  if (!tree) return;
  var state = window.__ttState || 'all';
  var anomEl = document.getElementById('echo-tree-anom-only');
  var anomOnly = anomEl && anomEl.checked;
  var qEl = document.getElementById('echo-tree-filter');
  var q = (qEl && qEl.value ? qEl.value : '').trim().toLowerCase();
  var active = state !== 'all' || anomOnly || q;
  var nomatch = document.querySelector('#echo-tree .echo-tree-nomatch');
  var nodes = tree.querySelectorAll('.echo-tree-node, .echo-tree-leaf');
  if (!active) { nodes.forEach(function(el){ el.style.display = ''; }); if (nomatch) nomatch.style.display = 'none'; return; }
  nodes.forEach(function(el){ el.style.display = 'none'; });
  var shown = 0;
  tree.querySelectorAll('.echo-tree-row').forEach(function(row){
    if (state === 'running' && row.getAttribute('data-state') !== 'running') return;
    if (state === 'exited' && row.getAttribute('data-state') !== 'exited') return;
    if (anomOnly && row.getAttribute('data-anom') !== '1') return;
    if (q && row.textContent.toLowerCase().indexOf(q) === -1) return;
    shown++;
    var el = row.closest('.echo-tree-leaf, .echo-tree-node');
    while (el && tree.contains(el)) {
      el.style.display = '';
      if (el.tagName === 'DETAILS') el.open = true;
      el = el.parentElement ? el.parentElement.closest('.echo-tree-node') : null;
    }
  });
  if (nomatch) nomatch.style.display = shown === 0 ? '' : 'none';
}
// The toolbar persists across tree swaps; re-apply the active filters whenever a new
// tree settles into #echo-tree.
document.body.addEventListener('htmx:afterSettle', function(e) {
  if (e.target && (e.target.id === 'echo-tree' ||
      (e.target.closest && e.target.closest('#echo-tree')))) {
    applyEchoTreeFilters();
  }
});

</script>
</body></html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kEchoPageHtml =
    yuzu::server::shell::bake(kEchoPageTemplate, {.active_key = "echo"});
// NOLINTEND(cert-err58-cpp)
