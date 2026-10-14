// Unified dashboard UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kDashboardIndexTemplate =
    // Part 1: CSS + HTML markup (split to stay under MSVC's 16380-byte string limit)
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Dashboard</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <script>htmx.config.useTemplateFragments = true;</script>
  <script src="/static/sse.js"></script>
  <!-- Chart renderer for spec.visualization payloads (#253). ECharts 5
       (Apache-2.0) is the engine; yuzu-charts.js is the thin adapter that
       maps our payload onto ECharts options and reads Yuzu design-system CSS tokens
       for theming. Self-rehydrates on htmx:afterSettle, so chart
       placeholders appear automatically when /fragments/results swaps
       the deck via OOB. echarts.min.js must load first — yuzu-charts.js
       defers if window.echarts is missing but eager order is faster. -->
  <script src="/static/echarts.min.js"></script>
  <script src="/static/yuzu-charts.js"></script>
  <style>
    body {
      display: flex; flex-direction: column; height: 100vh;
      overflow: hidden;
    }

    /* ── Page frame: title, console + results, scope/history rail ── */
    /* Fills the viewport below the shell header (--shell-top-h, defined by the shell). */
    .dash-grid {
      display: grid; gap: 22px; height: calc(100vh - var(--shell-top-h));
      padding: 22px 28px 14px;
      grid-template-columns: minmax(0, 1fr) 320px;
      grid-template-rows: auto auto minmax(0, 1fr) auto;
      grid-template-areas:
        "head     head"
        "instrbar rail"
        "results  rail"
        "footer   rail";
    }
    /* Grid items default to min-width:auto (= min-content); min-width:0 lets
       the centre track compress instead of pushing the rail off-screen. */
    .dash-grid > * { min-width: 0; }
    .dash-head { grid-area: head; }
    .rail { grid-area: rail; display: flex; flex-direction: column; gap: 22px; min-height: 0; }
    .dash-grid :focus-visible, .modal :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

    /* The console, scope and history regions are yuzu.css's .panel / .hd. The results region keeps its
       own skin: .panel would also pull in look's .panel table rules (row hover, td b) onto #results-table. */
    .results {
      background: var(--surface); border: 1px solid var(--line); border-radius: var(--rad-panel);
    }
    .results-header {
      display: flex; flex-wrap: wrap; align-items: center; gap: 8px 14px;
      padding: 12px 16px; border-bottom: 1px solid var(--line);
      font-size: 14px; font-weight: 600; color: var(--ink);
    }
    .results-header h2 { font-size: 14px; font-weight: 600; }
    .results, .scope-panel, .history-panel { display: flex; flex-direction: column; }
    .scope-panel, .history-panel { overflow: hidden; }
    .panel-hd #status-badge { margin-left: auto; }

    /* ── Console (instruction bar) ───────────────────────────── */
    .instr-bar { grid-area: instrbar; }
    .instr-body { display: grid; gap: 12px; padding: 16px; }
    .instr-field { display: flex; flex-direction: column; gap: 5px; }
    .instr-field label { font-size: 13px; font-weight: 500; color: var(--ink2); }
    .instr-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
    .instr-wrap { position: relative; flex: 1 1 240px; display: flex; }
    .instr-wrap input[type="text"] {
      width: 100%; height: var(--ctl); padding: 0 10px;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .instr-wrap input[type="text"]::placeholder { color: var(--faint); }
    .stats { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: 13px; color: var(--mut); }
    /* Server OOB swaps replace these by id (sometimes as <span>), so style by id. */
    #row-count, #stat-network, #stat-agent, #stat-total { margin-left: 3px; font-weight: 600; color: var(--ink); }

    /* Status badge: the JS writes IDLE / RUNNING / DONE / ERROR, shown sentence-case. */
    #status-badge {
      display: inline-block; padding: 1px 8px; border-radius: 3px;
      font-size: 12.5px; font-weight: 500; white-space: nowrap; text-transform: lowercase;
    }
    #status-badge::first-letter { text-transform: uppercase; }
    .badge-idle, .badge-done { color: var(--ok); background: var(--mds-color-bg-success-tinted); }
    .badge-running { color: var(--info); background: var(--mds-color-bg-info-tinted); }
    .badge-error { color: var(--bad); background: var(--mds-color-bg-error-tinted); }

    /* Buttons: raised, 1px line, 3px radius; the primary action is the one solid blue. */
    .instr-bar button, .btn-page, .btn-create-group, .create-group-form button,
    .history-header button, .density-toggle, .modal .btn-close {
      display: inline-flex; align-items: center; gap: 6px;
      height: var(--ctl); padding: 0 14px; white-space: nowrap; cursor: pointer;
      background: var(--raise); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font: inherit; font-weight: 500; transition: background .12s, border-color .12s;
    }
    .instr-bar button:hover, .btn-page:hover, .btn-create-group:hover, .create-group-form button:hover,
    .history-header button:hover, .density-toggle:hover, .modal .btn-close:hover {
      background: var(--surface2); border-color: var(--mut);
    }
    .instr-bar button:disabled { opacity: .4; cursor: not-allowed; }
    #btn-send, .create-group-form button {
      background: var(--primary); color: var(--on-primary); border-color: var(--primary); font-weight: 600;
    }
    #btn-send:hover, .create-group-form button:hover { background: var(--primary-h); border-color: var(--primary-h); }
    .btn-page, .btn-create-group, .history-header button, .density-toggle {
      height: 28px; padding: 0 10px; font-size: 13px;
    }
    .density-toggle svg { width: 14px; height: 14px; }

    /* Autocomplete: a pop-over, so it carries the shadow. */
    .ac-list {
      display: none; position: absolute; top: calc(100% + 4px); left: 0; right: 0; z-index: 200;
      max-height: 280px; overflow-y: auto;
      background: var(--raise); border: 1px solid var(--line2); border-radius: var(--rad-over);
      box-shadow: var(--shadow); font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .ac-list.open { display: block; }
    .ac-item {
      display: flex; justify-content: space-between; align-items: center;
      padding: 8px 12px; cursor: pointer; color: var(--ink); border-bottom: 1px solid var(--line);
    }
    .ac-item:last-child { border-bottom: 0; }
    .ac-item:hover { background: var(--surface2); }
    .ac-item.sel { background: var(--mds-color-state-selected); box-shadow: inset 3px 0 0 var(--hl); }
    .ac-item .ac-desc { margin-left: 16px; text-align: right; font-family: var(--font); font-size: 12.5px; color: var(--mut); }
)HTM"
    // Part 1a: CSS continued (split to stay under MSVC's 16380-byte string
    // limit — this session's degrade-banner/filter-bar CSS additions pushed
    // Part 1 over it, CI-measured C2026).
    R"HTM(

    /* ── Results ─────────────────────────────────────────────── */
    /* The whole results panel scrolls (chart deck, filter bar, table together). */
    .results { grid-area: results; overflow-y: auto; }
    .result-context, #result-summary { font-size: 13px; font-weight: 400; color: var(--mut); }
    .result-context.is-error { color: var(--bad); }
    #result-summary { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
    .density-toggle { margin-left: auto; }

    /* Chart deck (issue #253 / #587) — one or more chart cards rendered above
       the filter bar by yuzu-charts.js when the dispatched definition has a
       spec.visualization. The partial-result notice yuzu-charts.js inserts
       takes a full row of the wrapping deck. */
    .yuzu-chart-deck {
      display: flex; flex-wrap: wrap; gap: 16px; padding: 16px;
      border-bottom: 1px solid var(--line);
    }
    .yuzu-chart-deck:empty { display: none; }
    .yuzu-chart-deck > .yuzu-chart-truncated { flex: 0 0 100%; box-sizing: border-box; margin: 0; }
    .yuzu-chart-card {
      flex: 1 1 360px; min-width: 320px; max-width: 600px; height: 280px; padding: 8px 12px;
      background: var(--bg); border: 1px solid var(--line); border-radius: var(--rad-panel);
    }
    .yuzu-chart-card svg, .yuzu-chart-card canvas { display: block; max-width: 100%; }

    /* Filter bar */
    .filter-bar {
      display: flex; flex-wrap: wrap; align-items: center; gap: 8px 10px;
      padding: 10px 16px; border-bottom: 1px solid var(--line); font-size: 13px;
    }
    .filter-bar label { font-weight: 500; color: var(--mut); }
    .filter-bar select, .filter-bar input[type="text"], .filter-bar input[type="search"] {
      height: 28px; padding: 0 8px; font: inherit; font-size: 13px;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    /* #2691: a degraded facet-values() read disables the column filter — same
       warn treatment as .result-degrade-banner, not a plain form quirk. */
    .filter-bar select:disabled {
      color: var(--warn); opacity: 1; background: color-mix(in srgb, var(--warn) 12%, transparent);
      border-color: color-mix(in srgb, var(--warn) 50%, var(--line2));
    }
    .htmx-indicator { display: none; }
    .htmx-request .htmx-indicator, .htmx-request.htmx-indicator { display: block; }
    #results-loading { padding: 8px 16px; font-size: 13px; color: var(--mut); }

    /* Table: sentence-case 12.5px headers on surface2, 1px row rules, hover surface2. */
    /* Keeps >= 160px even when the chart deck and filter bar fill the panel; the panel then scrolls. */
    .table-wrap { flex: 1 1 260px; min-height: 160px; overflow: auto; }
    #results-table { width: 100%; border-collapse: collapse; --cell-y: 11px; }
    #results-table.compact { --cell-y: 6px; }
    #results-table thead th {
      position: sticky; top: 0; z-index: 1; padding: 8px 16px; text-align: left; white-space: nowrap;
      background: var(--surface2); border-bottom: 1px solid var(--line);
      font-size: 12.5px; font-weight: 500; color: var(--mut);
    }
    #results-table th.sortable { cursor: pointer; user-select: none; }
    #results-table th.sortable:hover { color: var(--ink); }
    #results-table tbody td {
      padding: var(--cell-y) 16px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
      border-bottom: 1px solid var(--line); font-size: 13.5px; color: var(--ink2);
    }
    #results-table td.col-agent { width: 10rem; font-weight: 600; color: var(--ink); }
    #results-table .result-detail td { max-width: none; overflow: visible; white-space: normal; background: var(--bg); }
    #results-table td.empty-state {
      max-width: none; padding: 48px 16px; text-align: center; white-space: normal;
      border-bottom: 0; color: var(--mut);
    }
    #results-table td.empty-state strong { color: var(--ink); }
    /* #2691 finding 7: an honest "store degraded, not zero matches" banner —
       warn-toned (temporarily unavailable, retrying), never alarm-red. The td form
       must outrank #results-table td.empty-state, which the banner row also is. */
    .result-degrade-banner, #results-table td.result-degrade-banner {
      padding: 8px 12px; font-size: 13.5px; color: var(--ink2); background: var(--surface2);
      border: 1px solid color-mix(in srgb, var(--warn) 50%, var(--line2)); border-radius: var(--rad-panel);
    }
    /* Collapsed borders: the header rule wins the top edge, so frame the td with an inset shadow. */
    #results-table td.result-degrade-banner {
      border: 0; box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--warn) 50%, var(--line2));
    }
    .result-degrade-banner b { color: var(--ink); }

    #result-pagination {
      display: flex; align-items: center; gap: 8px; padding: 8px 16px;
      border-top: 1px solid var(--line); font-size: 13px; color: var(--mut);
    }
    #result-pagination:empty { display: none; }
    .create-group-form {
      display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
      padding: 12px 16px; border-top: 1px solid var(--line);
    }
    .create-group-form input[type="text"] {
      height: var(--ctl); padding: 0 10px; font: inherit;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .form-hint { font-size: 12.5px; color: var(--mut); }
    .feedback-error { font-size: 13px; color: var(--bad); }

    /* ── Scope and history rail ──────────────────────────────── */
    .scope-panel { flex: 1 1 0; min-height: 160px; }
    .history-panel { flex: 0 1 240px; min-height: 120px; }
    .scope-count { font-size: 13px; font-weight: 400; color: var(--mut); }
    .scope-list, .history-list { flex: 1; min-height: 0; overflow-y: auto; }
    .scope-section-header {
      padding: 8px 16px; background: var(--surface2); border-bottom: 1px solid var(--line);
      font-size: 12.5px; font-weight: 500; color: var(--mut);
    }
    .scope-item, .history-item { padding: 9px 16px; cursor: pointer; border-bottom: 1px solid var(--line); }
    .scope-item { display: flex; flex-direction: column; gap: 2px; }
    .scope-item:hover, .history-item:hover { background: var(--surface2); }
    .scope-item.selected, .history-item.active {
      background: var(--mds-color-state-selected); box-shadow: inset 3px 0 0 var(--hl);
    }
    .scope-item-name { font-size: 13.5px; font-weight: 500; color: var(--ink); }
    .scope-item-all { font-weight: 600; }
    .scope-item-meta { font-family: var(--mds-font-family-mono); font-size: 11.5px; color: var(--mut); }
    .scope-item .online-dot { display: inline-block; width: 8px; height: 8px; margin-right: 8px; background: var(--ok); }
    .history-header button { margin-left: auto; }
    .history-cmd { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; color: var(--ink); }
    .history-meta { font-size: 13px; color: var(--mut); }
    .history-empty { padding: 24px 16px; text-align: center; font-size: 13px; color: var(--mut); }

    .dash-foot {
      grid-area: footer; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 12px;
      font-size: 12px; color: var(--faint);
    }
    .dash-foot kbd, .cmd-palette-footer kbd {
      display: inline-flex; align-items: center; justify-content: center; min-width: 20px; height: auto;
      padding: 1px 6px; background: var(--surface2); color: var(--mut);
      border: 1px solid var(--line2); border-radius: 3px;
      font-family: var(--mds-font-family-mono); font-size: 11px;
    }

    /* ── About modal ─────────────────────────────────────────── */
    .modal-overlay {
      display: none; position: fixed; inset: 0; z-index: 2000; align-items: center; justify-content: center;
      background: var(--mds-color-state-overlay-scrim);
    }
    .modal-overlay.open { display: flex; }
    .modal {
      width: 380px; max-width: calc(100vw - 32px); padding: 24px;
      background: var(--raise); border: 1px solid var(--line2); border-radius: var(--rad-over); box-shadow: var(--shadow);
    }
    .modal h2 { font-size: 18px; font-weight: 600; }
    .modal .version { margin: 2px 0 12px; font-size: 13px; color: var(--mut); }
    .modal p { margin-bottom: 8px; font-size: 13px; line-height: 1.6; color: var(--mut); }
    .modal a { color: var(--primary); text-decoration: none; }
    .modal a:hover { text-decoration: underline; }
    .modal .btn-close { margin-top: 8px; }

    /* ── Command palette (Ctrl+K): yuzu.css supplies the pop-over, rows and footer;
       only this page's deltas live here. ── */
    .cmd-palette { max-width: calc(100vw - 32px); }
    .cmd-palette-input-row input { min-width: 0; font: inherit; outline: 0; }
    .cmd-palette-input-row input:focus-visible { outline: 0; }
    .cmd-section-header {
      padding: 8px 16px; background: var(--surface2); font-size: 12.5px; font-weight: 500; color: var(--mut);
      text-transform: none; letter-spacing: 0;
    }
    .cmd-result.active { background: var(--mds-color-state-selected); box-shadow: inset 3px 0 0 var(--hl); }
    .cmd-result-desc { min-width: 0; }
    .cmd-result-type { height: auto; padding: 1px 8px; border-radius: 3px; font-size: 12.5px; font-weight: 500; }
    /* ── Narrow windows: one column, the page scrolls, the scope list stays reachable.
       1336px = 1100px of page + the 236px shell sidebar. ── */
    @media (max-width: 1336px) {
      .dash-grid {
        overflow-y: auto; align-content: start;
        grid-template-columns: minmax(0, 1fr); grid-template-rows: none;
        grid-template-areas: "head" "instrbar" "results" "rail" "footer";
      }
      .results { min-height: 420px; }
      .rail { min-height: auto; }
      .scope-panel, .history-panel { flex: none; min-height: 0; }
      .scope-list, .history-list { flex: none; }
      .scope-list { max-height: 320px; }
      .history-list { max-height: 240px; }
    }
  </style>
</head>
)HTM"
    // Split here to keep each raw-string literal under the MSVC C2026
    // 16380-byte limit. Adjacent string literals concatenate at compile
    // time, so the runtime HTML is byte-identical.
    R"HTM(<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <div class="dash-grid">

  <header class="page-header dash-head">
    <div>
      <h1>Dashboard</h1>
      <p class="subtitle">Run an instruction against the fleet and watch responses arrive.</p>
    </div>
  </header>

  <!-- ── Console: instruction bar ───────────────────────────── -->
  <!-- The page script's htmx:beforeRequest listener on this form clears
       the chart deck the instant the operator clicks Send so a stale
       chart from the previous dispatch can't linger over the new
       query's results. The new deck is delivered later via the OOB
       swap from /fragments/results once execution has data to render. -->
  <form class="instr-bar panel" id="instr-form"
        hx-post="/api/dashboard/execute" hx-swap="none">
    <div class="panel-hd hd">
      <h2>Console</h2>
      <span id="status-badge" class="badge-idle">IDLE</span>
    </div>
    <div class="instr-body">
      <div class="instr-field">
        <label for="instr-input">Instruction</label>
        <div class="instr-row">
          <div class="instr-wrap">
            <input type="text" id="instr-input" name="instruction"
                   placeholder="Type a command or 'help'..."
                   autocomplete="off" spellcheck="false"
                   hx-get="/api/help/autocomplete" hx-trigger="input changed delay:150ms"
                   hx-target="#ac-list" hx-swap="innerHTML">
            <div class="ac-list" id="ac-list"></div>
          </div>
          <input type="hidden" name="scope" id="scope-input" value="__all__">
          <button type="submit" id="btn-send">Send</button>
          <button type="button" class="btn-clear" onclick="clearResults()">Clear</button>
        </div>
      </div>
      <div class="stats">
        <span>Rows: <strong id="row-count">0</strong></span>
        <span>Network: <strong id="stat-network">&mdash;</strong></span>
        <span>Agent: <strong id="stat-agent">&mdash;</strong></span>
        <span>Total: <strong id="stat-total">&mdash;</strong></span>
      </div>
    </div>
  </form>

  <!-- ── About Modal ──────────────────────────────────────── -->
  <div class="modal-overlay" id="about-modal" onclick="closeAbout(event)">
    <div class="modal">
      <h2>Yuzu</h2>
      <div class="version">Endpoint Management Platform</div>
      <p id="about-details">Loading...</p>
      <p>Built with C++23, gRPC, Protobuf, SQLite</p>
      <p>
        <a href="https://github.com/anthropics/yuzu" target="_blank">GitHub</a>
        &nbsp;&middot;&nbsp;
        <a href="/help">Documentation</a>
      </p>
      <p>AGPL-3.0-or-later (community) &middot; commercial license available for enterprise edition</p>
      <button class="btn-close" onclick="closeAbout()">Close</button>
    </div>
  </div>
)HTM"
    // Part 1b: Command palette overlay
    R"HTM(
  <!-- ── Command Palette ─────────────────────────────────────── -->
  <div id="cmd-palette" class="cmd-palette-overlay" style="display:none" onclick="if(event.target===this)cmdPalette.close()">
    <div class="cmd-palette">
      <div class="cmd-palette-input-row">
        <svg class="icon"><use href="/static/icons.svg#search"></use></svg>
        <input type="text" id="cmd-input" placeholder="Search agents, instructions, settings..." autocomplete="off" spellcheck="false">
        <span class="cmd-palette-hint">ESC to close</span>
      </div>
      <div id="cmd-results" class="cmd-palette-results"></div>
      <div class="cmd-palette-footer">
        <span><kbd>&uarr;</kbd><kbd>&darr;</kbd> navigate</span>
        <span><kbd>&crarr;</kbd> select</span>
        <span><kbd>esc</kbd> close</span>
      </div>
    </div>
  </div>

)HTM"
    // Part 2: HTML body continued
    R"HTM(

  <!-- ── Results ────────────────────────────────────────────── -->
  <div class="results">
    <div class="results-header">
      <h2>Results</h2>
      <span id="result-context" class="result-context"></span>
      <div id="result-summary"></div>
      <button class="density-toggle" id="density-toggle" onclick="toggleDensity()" title="Toggle table density">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
          <line x1="2" y1="4" x2="14" y2="4"/><line x1="2" y1="8" x2="14" y2="8"/><line x1="2" y1="12" x2="14" y2="12"/>
        </svg>
        <span id="density-label">Comfortable</span>
      </button>
    </div>
    <!-- Chart deck — populated by OOB swap from /fragments/results when the
         dispatched command has an InstructionDefinition with spec.visualization
         (issue #587). yuzu-charts.js auto-renders each placeholder div. -->
    <div id="chart-deck-host"></div>
    <!-- Filter bar — populated by OOB swap after command dispatch -->
    <div id="filter-bar"></div>
    <!-- Loading indicator for HTMX filter/sort requests -->
    <div id="results-loading" class="htmx-indicator">Loading...</div>
    <div class="table-wrap" hx-ext="sse" sse-connect="/events">
      <table id="results-table">
        <thead id="results-thead"><tr></tr></thead>
        <tbody id="results-tbody">
          <tr id="empty-row"><td colspan="1" class="empty-state">
            Type an instruction above and press <strong>Send</strong> to execute.
          </td></tr>
        </tbody>
      </table>
      <!-- Hidden sinks for OOB swap events.  All SSE events use
           hx-swap="none" so only OOB-targeted elements are processed.
           This avoids mixing <tr> and <span> in the same fragment,
           which breaks under the browser's table content model
           (foster parenting ejects non-table elements). -->
      <div sse-swap="output" hx-swap="none" style="display:none"></div>
      <div sse-swap="command-status" hx-swap="none" style="display:none"></div>
      <div sse-swap="timing" hx-swap="none" style="display:none"></div>
      <div sse-swap="heartbeat" hx-swap="none" style="display:none"></div>
      <div sse-swap="agent-online" hx-swap="none" style="display:none"></div>
      <div sse-swap="agent-offline" hx-swap="none" style="display:none"></div>
    </div>
    <!-- Pagination + group creation slot — populated by OOB swaps -->
    <nav id="result-pagination"></nav>
    <div id="group-form-slot"></div>
  </div>

  <!-- ── Scope and history rail ─────────────────────────────── -->
  <div class="rail">
    <div class="scope-panel panel">
      <div class="scope-header hd">
        Scope <span class="scope-count" id="agent-count">0 agents</span>
      </div>
      <div class="scope-list" id="scope-list"
           hx-get="/fragments/scope-list"
           hx-trigger="load, every 5s, agentChanged from:body"
           hx-swap="innerHTML">
      </div>
    </div>
    <div class="history-panel panel">
      <div class="history-header hd">
        History
        <button onclick="clearHistory()" title="Clear history">&times; Clear</button>
      </div>
      <div class="history-list" id="history-list">
        <div class="history-empty" id="history-empty">No commands yet</div>
      </div>
    </div>
  </div>

  <footer class="dash-foot">
    <span>Yuzu Server &mdash; Dashboard</span>
    <span>Press <kbd>Ctrl+K</kbd> to search</span>
  </footer>

  <!-- HTMX-driven data loaders (no JS fetch calls) -->
  <div id="help-loader" hx-get="/api/help" hx-trigger="load, agentChanged from:body"
       hx-swap="none" style="display:none"></div>

  <!-- Declarative help trigger — fires on loadHelp event, reads filter from input -->
  <div id="help-trigger" style="display:none"
       hx-get="/api/help/html"
       hx-target="#results-tbody"
       hx-swap="innerHTML settle:0ms"
       hx-trigger="loadHelp from:body">
  </div>

  </div><!-- /.dash-grid -->
)HTM"
    // Part 2: JavaScript
    R"HTM(
  <script>
    /* ── State ─────────────────────────────────────────────── */
    var selectedScope = '__all__';
    var rowCount = 0;
    var currentInstruction = '';
    var agents = {};   // agent_id -> { hostname, os, arch }
    var commandHistory = [];  // { cmd, scope, timestamp }

    /* ── Instruction mapping (built dynamically from /api/help) ── */
    var instructionMap = {};
    var helpData = { plugins: [], commands: [] };

    function buildInstructionMap(data) {
      helpData = data;
      instructionMap = {};
      for (var i = 0; i < data.plugins.length; i++) {
        var p = data.plugins[i];
        if (p.actions.length > 0) {
          instructionMap[p.name] = { plugin: p.name, action: p.actions[0].name || p.actions[0] };
        }
        for (var j = 0; j < p.actions.length; j++) {
          var aName = p.actions[j].name || p.actions[j];
          instructionMap[p.name + ' ' + aName] = { plugin: p.name, action: aName };
        }
      }
    }

    /* Column schemas moved server-side — server renders <tr> HTML via SSE */
)HTM"
    // Part 3: Helpers and table management
    R"HTM(
    /* ── Helpers ──────────────────────────────────────────── */
    function escapeHtml(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function setBadge(state) {
      var el = document.getElementById('status-badge');
      var map = {
        idle:    { text: 'IDLE',    cls: 'badge-idle' },
        running: { text: 'RUNNING', cls: 'badge-running' },
        done:    { text: 'DONE',    cls: 'badge-done' },
        error:   { text: 'ERROR',   cls: 'badge-error' }
      };
      var s = map[state] || map.idle;
      el.textContent = s.text;
      el.className = s.cls;
    }

    /* ── Row detail drawer ──────────────────────────────────── */
    function toggleDetail(row) {
      var detail = row.nextElementSibling;
      if (!detail || !detail.classList.contains('result-detail')) return;
      var isOpen = detail.classList.contains('open');
      /* Close any other open detail rows first */
      var allOpen = document.querySelectorAll('.result-detail.open');
      for (var i = 0; i < allOpen.length; i++) {
        allOpen[i].classList.remove('open');
        allOpen[i].previousElementSibling.classList.remove('expanded');
      }
      if (!isOpen) {
        detail.classList.add('open');
        row.classList.add('expanded');
      }
    }

    /* ── Density toggle ────────────────────────────────────── */
    var densityMode = localStorage.getItem('yuzu-table-density') || 'comfortable';

    function applyDensity() {
      var tbl = document.getElementById('results-table');
      if (!tbl) return;
      tbl.classList.remove('compact', 'comfortable');
      tbl.classList.add(densityMode);
      var label = document.getElementById('density-label');
      if (label) label.textContent = densityMode === 'compact' ? 'Compact' : 'Comfortable';
    }

    function toggleDensity() {
      densityMode = (densityMode === 'comfortable') ? 'compact' : 'comfortable';
      localStorage.setItem('yuzu-table-density', densityMode);
      applyDensity();
    }

    /* Apply saved density on load */
    applyDensity();
)HTM"
    // Part 3b: Table management and row operations
    R"HTM(
    /* ── Table management ─────────────────────────────────── */
    var currentColumns = [];

    function setColumns(cols) {
      currentColumns = cols;
      var thead = document.getElementById('results-thead');
      var html = '<tr>';
      for (var i = 0; i < cols.length; i++) {
        var cls = i === 0 ? ' class="col-agent"' : '';
        html += '<th' + cls + '>' + escapeHtml(cols[i]) + '</th>';
      }
      html += '</tr>';
      thead.innerHTML = html;
    }

    function addRow(cells) {
      var er = document.getElementById('empty-row');
      if (er) er.remove();

      var tbody = document.getElementById('results-tbody');

      /* Main data row */
      var tr = document.createElement('tr');
      tr.className = 'result-row';
      tr.setAttribute('onclick', 'toggleDetail(this)');
      var html = '';
      for (var i = 0; i < cells.length; i++) {
        var cls = i === 0 ? ' class="col-agent"' : '';
        html += '<td' + cls + ' title="' + escapeHtml(cells[i]) + '">' + escapeHtml(cells[i]) + '</td>';
      }
      tr.innerHTML = html;
      tbody.appendChild(tr);

      /* Companion detail row */
      var detailTr = document.createElement('tr');
      detailTr.className = 'result-detail';
      var colSpan = cells.length || 1;
      var detailHtml = '<td colspan="' + colSpan + '"><div class="detail-content">';
      for (var i = 0; i < cells.length; i++) {
        var label = (currentColumns.length > i) ? currentColumns[i] : ('Column ' + (i + 1));
        detailHtml += '<div class="detail-label">' + escapeHtml(label) + '</div>';
        detailHtml += '<div class="detail-value">' + escapeHtml(cells[i]) + '</div>';
      }
      detailHtml += '</div></td>';
      detailTr.innerHTML = detailHtml;
      tbody.appendChild(detailTr);

      rowCount++;
      document.getElementById('row-count').textContent = rowCount.toLocaleString();

      /* Auto-scroll to bottom */
      var wrap = document.querySelector('.table-wrap');
      wrap.scrollTop = wrap.scrollHeight;
    }

    // Drop any chart-card ECharts instances and empty the deck. Called
    // both when the operator clicks Clear and at the start of every new
    // dispatch (the htmx:beforeRequest listener on #instr-form, below)
    // so a stale chart from the previous query never overlays the new one.
    function clearChartDeck() {
      var host = document.getElementById('chart-deck-host');
      if (!host) return;
      if (window.echarts) {
        host.querySelectorAll('.yuzu-chart-card').forEach(function (el) {
          var inst = window.echarts.getInstanceByDom(el);
          if (inst) { inst.dispose(); }
        });
      }
      host.innerHTML = '';
    }

    function clearResults() {
      document.getElementById('results-tbody').innerHTML = '';
      document.getElementById('results-thead').innerHTML = '<tr></tr>';
      rowCount = 0;
      document.getElementById('row-count').textContent = '0';
      document.getElementById('stat-network').innerHTML = '&mdash;';
      document.getElementById('stat-agent').innerHTML = '&mdash;';
      document.getElementById('stat-total').innerHTML = '&mdash;';
      document.getElementById('result-context').textContent = '';
      clearChartDeck();
      setBadge('idle');
    }

    /* ── Scope management ─────────────────────────────────── */
    function selectScope(el) {
      var items = document.querySelectorAll('.scope-item');
      for (var i = 0; i < items.length; i++) items[i].classList.remove('selected');
      el.classList.add('selected');
      // Support both data-agent-id (legacy) and data-scope (groups, new items)
      selectedScope = el.getAttribute('data-scope') || el.getAttribute('data-agent-id');
      // Sync hidden input for HTMX form submission
      var scopeInput = document.getElementById('scope-input');
      if (scopeInput) scopeInput.value = selectedScope;
    }

    /* refreshAgentList / renderAgentList removed — scope panel is now
       HTMX-polled via hx-get="/fragments/scope-list" every 5 s,
       with immediate refresh on agentChanged events from SSE. */

    function agentDisplayName(agentId) {
      var a = agents[agentId];
      if (a && a.hostname) return a.hostname;
      if (agentId && agentId.length > 12) return agentId.substring(0, 12);
      return agentId || '?';
    }

    /* showHelp() removed — help is now handled server-side:
       POST /api/dashboard/execute returns HX-Trigger: {"loadHelp": true}
       which triggers the declarative #help-trigger element. */

)HTM"
    R"HTM(
    /* Trigger the HTMX form submission programmatically.
       Called by Enter key, history clicks, and global shortcut. */
    function sendInstruction() {
      document.getElementById('instr-form').requestSubmit();
    }

    /* ── Command history ─────────────────────────────────── */
    function addHistory(cmd, scope) {
      var now = new Date();
      var ts = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      commandHistory.unshift({ cmd: cmd, scope: scope, timestamp: ts });
      if (commandHistory.length > 50) commandHistory.length = 50;
      renderHistory();
    }

    function renderHistory() {
      var list = document.getElementById('history-list');
      var empty = document.getElementById('history-empty');
      /* Remove all items except the empty placeholder */
      var items = list.querySelectorAll('.history-item');
      for (var i = 0; i < items.length; i++) items[i].remove();

      if (commandHistory.length === 0) {
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';

      for (var i = 0; i < commandHistory.length; i++) {
        var h = commandHistory[i];
        var div = document.createElement('div');
        div.className = 'history-item' + (i === 0 ? ' active' : '');
        div.innerHTML = '<div class="history-cmd">' + escapeHtml(h.cmd) + '</div>' +
          '<div class="history-meta">' + escapeHtml(h.timestamp) + ' &middot; ' + escapeHtml(h.scope) + '</div>';
        div.setAttribute('data-cmd', h.cmd);
        div.addEventListener('click', function() {
          document.getElementById('instr-input').value = this.getAttribute('data-cmd');
          sendInstruction();
        });
        list.appendChild(div);
      }
    }

    function clearHistory() {
      commandHistory = [];
      renderHistory();
    }

    /* ── Autocomplete ────────────────────────────────────── */
    var acSel = -1;

    function closeAC() {
      document.getElementById('ac-list').classList.remove('open');
      acSel = -1;
    }

    function acSelect(cmd) {
      document.getElementById('instr-input').value = cmd;
      closeAC();
      document.getElementById('instr-input').focus();
    }

    /* Autocomplete is now HTMX-driven: input hx-get="/api/help/autocomplete"
       renders server-side HTML into #ac-list. We just manage open/close and clicks. */
    function onAcResponse() {
      var list = document.getElementById('ac-list');
      acSel = -1;
      if (list.children.length > 0) {
        list.classList.add('open');
      } else {
        closeAC();
      }
    }
    /* Listen for HTMX swap completion on the autocomplete list */
    document.getElementById('ac-list').addEventListener('htmx:afterSwap', onAcResponse);

    /* Event-delegated click handler for server-rendered ac-items */
    document.getElementById('ac-list').addEventListener('mousedown', function(ev) {
      var item = ev.target.closest('.ac-item');
      if (item) {
        ev.preventDefault();
        acSelect(item.getAttribute('data-cmd'));
      }
    });

    var instrInput = document.getElementById('instr-input');
    /* Close autocomplete when input is empty */
    instrInput.addEventListener('input', function() {
      if (!instrInput.value.trim()) closeAC();
    });
    instrInput.addEventListener('blur', function() { setTimeout(closeAC, 150); });
    instrInput.addEventListener('keydown', function(e) {
      var list = document.getElementById('ac-list');
      var items = list.querySelectorAll('.ac-item');
      if (e.key === 'ArrowDown' && items.length > 0) {
        e.preventDefault();
        acSel = Math.min(acSel + 1, items.length - 1);
        for (var i = 0; i < items.length; i++) items[i].classList.toggle('sel', i === acSel);
        items[acSel].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'ArrowUp' && items.length > 0) {
        e.preventDefault();
        acSel = Math.max(acSel - 1, 0);
        for (var i = 0; i < items.length; i++) items[i].classList.toggle('sel', i === acSel);
        items[acSel].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Tab' && acSel >= 0 && items.length > 0) {
        e.preventDefault();
        acSelect(items[acSel].getAttribute('data-cmd'));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (acSel >= 0 && items.length > 0) {
          acSelect(items[acSel].getAttribute('data-cmd'));
        } else {
          closeAC();
          sendInstruction();
        }
      } else if (e.key === 'Escape') {
        closeAC();
      }
    });
)HTM"
    // Part 4: HTMX SSE event hooks + menu JavaScript
    R"HTM(
    /* SSE output rows, row counting, auto-scroll, empty-state removal,
       agent-online/offline → all handled by server OOB swaps + HTMX
       attributes.  No JS event listeners needed. */

    /* ── About modal ─────────────────────────────────────── */
    function showAbout() {
      document.getElementById('about-modal').classList.add('open');
      var agentCount = Object.keys(agents).length;
      var details = 'Agents: ' + agentCount + ' connected';
      document.getElementById('about-details').textContent = details;
    }
    function closeAbout(e) {
      if (!e || e.target === document.getElementById('about-modal')) {
        document.getElementById('about-modal').classList.remove('open');
      }
    }

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
)HTM"
    // Part 5: Command palette JavaScript
    R"HTM(
    /* ── Command Palette ─────────────────────────────────── */
    var cmdPalette = {
      isOpen: false,
      selectedIndex: -1,
      results: [],
      agentsCache: null,

      open: function() {
        if (cmdPalette.isOpen) return;
        cmdPalette.isOpen = true;
        cmdPalette.selectedIndex = -1;
        cmdPalette.results = [];
        var overlay = document.getElementById('cmd-palette');
        var input = document.getElementById('cmd-input');
        overlay.style.display = 'flex';
        input.value = '';
        input.focus();
        cmdPalette.showDefault();
        /* Cache agents on first open */
        if (!cmdPalette.agentsCache) {
          cmdPalette.agentsCache = [];
          var ids = Object.keys(agents);
          for (var i = 0; i < ids.length; i++) {
            var a = agents[ids[i]];
            cmdPalette.agentsCache.push({
              id: ids[i],
              hostname: a.hostname || ids[i],
              os: a.os || '?',
              arch: a.arch || '?'
            });
          }
        }
      },

      close: function() {
        if (!cmdPalette.isOpen) return;
        cmdPalette.isOpen = false;
        document.getElementById('cmd-palette').style.display = 'none';
        document.getElementById('cmd-input').value = '';
        document.getElementById('cmd-results').innerHTML = '';
      },

      /* Static entries for settings and navigation */
      settingsEntries: [
        { name: 'Users', desc: 'Manage user accounts', url: '/settings#users', type: 'Settings' },
        { name: 'Enrollment Tokens', desc: 'Manage enrollment tokens', url: '/settings#tokens', type: 'Settings' },
        { name: 'Pending Agents', desc: 'Approve or deny pending agents', url: '/settings#pending', type: 'Settings' },
        { name: 'TLS Settings', desc: 'Configure TLS certificates', url: '/settings#tls', type: 'Settings' },
        { name: 'API Tokens', desc: 'Manage API tokens', url: '/settings#api-tokens', type: 'Settings' }
      ],
      navEntries: [
        { name: 'Dashboard', desc: 'Main dashboard view', url: '/', type: 'Navigation' },
        { name: 'Instructions', desc: 'Browse instruction definitions', url: '/instructions', type: 'Navigation' },
        { name: 'Inventory', desc: 'Installed software & device inventory', url: '/inventory', type: 'Navigation' },
        { name: 'Settings', desc: 'Server settings', url: '/settings', type: 'Navigation' },
        { name: 'About', desc: 'About Yuzu', url: '#about', type: 'Navigation' }
      ],

      showDefault: function() {
        /* Show navigation and a hint when palette first opens */
        var results = [];
        for (var i = 0; i < cmdPalette.navEntries.length; i++) {
          results.push(cmdPalette.navEntries[i]);
        }
        cmdPalette.results = results;
        cmdPalette.selectedIndex = 0;
        cmdPalette.render();
      },

      search: function(query) {
        if (!query) { cmdPalette.showDefault(); return; }
        var q = query.toLowerCase();
        var results = [];

        /* Search instructions */
        var instrResults = [];
        if (helpData.plugins) {
          for (var i = 0; i < helpData.plugins.length; i++) {
            var p = helpData.plugins[i];
            for (var j = 0; j < p.actions.length; j++) {
              var a = p.actions[j];
              var aName = a.name || a;
              var aDesc = a.description || p.description || '';
              var fullName = p.name + ' ' + aName;
              if (fullName.toLowerCase().indexOf(q) >= 0 || aDesc.toLowerCase().indexOf(q) >= 0) {
                instrResults.push({
                  name: fullName,
                  desc: aDesc,
                  type: 'Instruction',
                  plugin: p.name,
                  action: aName
                });
              }
            }
            /* Also match just the plugin name */
            if (p.name.toLowerCase().indexOf(q) >= 0 && p.actions.length > 0) {
              var already = false;
              for (var k = 0; k < instrResults.length; k++) {
                if (instrResults[k].plugin === p.name) { already = true; break; }
              }
              if (!already) {
                var a0 = p.actions[0];
                instrResults.push({
                  name: p.name + ' ' + (a0.name || a0),
                  desc: a0.description || p.description || '',
                  type: 'Instruction',
                  plugin: p.name,
                  action: a0.name || a0
                });
              }
            }
          }
        }

        /* Search agents */
        var agentResults = [];
        var agentSrc = cmdPalette.agentsCache || [];
        for (var i = 0; i < agentSrc.length; i++) {
          var a = agentSrc[i];
          if (a.hostname.toLowerCase().indexOf(q) >= 0 || a.id.toLowerCase().indexOf(q) >= 0) {
            agentResults.push({
              name: a.hostname,
              desc: a.id.substring(0, 12) + ' \u00b7 ' + a.os + '/' + a.arch,
              type: 'Agent',
              agentId: a.id
            });
          }
        }

        /* Search settings */
        var settingsResults = [];
        for (var i = 0; i < cmdPalette.settingsEntries.length; i++) {
          var s = cmdPalette.settingsEntries[i];
          if (s.name.toLowerCase().indexOf(q) >= 0 || s.desc.toLowerCase().indexOf(q) >= 0) {
            settingsResults.push(s);
          }
        }

        /* Search navigation */
        var navResults = [];
        for (var i = 0; i < cmdPalette.navEntries.length; i++) {
          var n = cmdPalette.navEntries[i];
          if (n.name.toLowerCase().indexOf(q) >= 0 || n.desc.toLowerCase().indexOf(q) >= 0) {
            navResults.push(n);
          }
        }

        /* Combine with limits */
        results = instrResults.slice(0, 8)
          .concat(agentResults.slice(0, 6))
          .concat(settingsResults.slice(0, 4))
          .concat(navResults.slice(0, 4));

        cmdPalette.results = results;
        cmdPalette.selectedIndex = results.length > 0 ? 0 : -1;
        cmdPalette.render();
      },

      render: function() {
        var container = document.getElementById('cmd-results');
        var html = '';
        var lastType = '';

        for (var i = 0; i < cmdPalette.results.length; i++) {
          var r = cmdPalette.results[i];

          /* Section header when type changes */
          if (r.type !== lastType) {
            html += '<div class="cmd-section-header">' + escapeHtml(r.type) + 's</div>';
            lastType = r.type;
          }

          /* Badge class per type */
          var badgeCls = 'badge-info';
          if (r.type === 'Agent') badgeCls = 'badge-success';
          else if (r.type === 'Settings') badgeCls = 'badge-warning';
          else if (r.type === 'Navigation') badgeCls = 'badge-neutral';

          var activeCls = i === cmdPalette.selectedIndex ? ' active' : '';
          html += '<div class="cmd-result' + activeCls + '" data-index="' + i + '"'
            + ' onmouseenter="cmdPalette.selectedIndex=' + i + ';cmdPalette.render()"'
            + ' onclick="cmdPalette.select()">'
            + '<span class="cmd-result-name">' + escapeHtml(r.name) + '</span>'
            + '<span class="cmd-result-desc">' + escapeHtml(r.desc) + '</span>'
            + '<span class="cmd-result-type badge ' + badgeCls + '">' + escapeHtml(r.type) + '</span>'
            + '</div>';
        }

        container.innerHTML = html;

        /* Scroll active item into view */
        var active = container.querySelector('.cmd-result.active');
        if (active) active.scrollIntoView({ block: 'nearest' });
      },

      navigate: function(delta) {
        if (cmdPalette.results.length === 0) return;
        cmdPalette.selectedIndex += delta;
        if (cmdPalette.selectedIndex < 0) cmdPalette.selectedIndex = cmdPalette.results.length - 1;
        if (cmdPalette.selectedIndex >= cmdPalette.results.length) cmdPalette.selectedIndex = 0;
        cmdPalette.render();
      },

      select: function() {
        if (cmdPalette.selectedIndex < 0 || cmdPalette.selectedIndex >= cmdPalette.results.length) return;
        var r = cmdPalette.results[cmdPalette.selectedIndex];
        cmdPalette.close();

        if (r.type === 'Instruction') {
          /* Populate the instruction bar */
          var instrInput = document.getElementById('instr-input');
          instrInput.value = r.name;
          instrInput.focus();
          closeAC();
        } else if (r.type === 'Agent') {
          /* Select agent in scope panel */
          var items = document.querySelectorAll('.scope-item');
          for (var i = 0; i < items.length; i++) {
            if (items[i].getAttribute('data-agent-id') === r.agentId) {
              selectScope(items[i]);
              break;
            }
          }
          showToast('Scope set to ' + r.name, 'info');
        } else if (r.type === 'Navigation' && r.url === '#about') {
          showAbout();
        } else if (r.url) {
          window.location.href = r.url;
        }
      }
    };

    /* Command palette input handler */
    document.getElementById('cmd-input').addEventListener('input', function() {
      cmdPalette.search(this.value.trim());
    });

    /* Command palette keyboard navigation */
    document.getElementById('cmd-input').addEventListener('keydown', function(e) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        cmdPalette.navigate(1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        cmdPalette.navigate(-1);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        cmdPalette.select();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        cmdPalette.close();
      }
    });

    /* ── Global Keyboard Shortcuts ───────────────────────── */
    document.addEventListener('keydown', function(e) {
      var tag = (e.target.tagName || '').toLowerCase();
      var isInput = (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable);

      /* Ctrl+K / Cmd+K — open command palette */
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (cmdPalette.isOpen) { cmdPalette.close(); } else { cmdPalette.open(); }
        return;
      }

      /* Escape — close palette or clear instruction input */
      if (e.key === 'Escape') {
        if (cmdPalette.isOpen) {
          cmdPalette.close();
          return;
        }
        var instrInput = document.getElementById('instr-input');
        if (document.activeElement === instrInput) {
          instrInput.value = '';
          instrInput.blur();
          closeAC();
        }
        return;
      }

      /* Ctrl+Enter — send current instruction */
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        sendInstruction();
        return;
      }

      /* / — focus instruction input (when not in a text field) */
      if (e.key === '/' && !isInput && !cmdPalette.isOpen) {
        e.preventDefault();
        document.getElementById('instr-input').focus();
        return;
      }
    });

    /* ── CSP-safe HTMX bindings ─────────────────────────────
       The dashboard's strict CSP forbids 'unsafe-eval', so HTMX
       features that internally call new Function(...) — namely
       the inline event-handler attributes and hx-vals="js:..." —
       are blocked at runtime. We re-create each broken handler here using
       addEventListener (covered by 'unsafe-inline') and the
       htmx:configRequest event (no eval). */

    /* hx-vals="js:..." replacements: inject params per request */
    document.body.addEventListener('htmx:configRequest', function(e) {
      var elt = e.detail && e.detail.elt;
      if (!elt) return;
      if (elt.id === 'scope-list') {
        e.detail.parameters.selected =
          (typeof selectedScope !== 'undefined' && selectedScope) || '__all__';
      } else if (elt.id === 'help-trigger') {
        var input = document.getElementById('instr-input');
        var v = input ? input.value.replace(/^help\s*/i, '').trim().toLowerCase() : '';
        e.detail.parameters.filter = v;
      }
    });

    /* instr-form: close autocomplete and drop the previous chart deck before
       submit. Clear the deck only for the form's own request (e.target): the
       autocomplete input inside it fires bubbling beforeRequest events. */
    var instrForm = document.getElementById('instr-form');
    if (instrForm) {
      instrForm.addEventListener('htmx:beforeRequest', function(e) {
        if (typeof closeAC === 'function') closeAC();
        if (e.target === instrForm) clearChartDeck();
      });
    }

    /* SSE heartbeat watchdog: reconnect /events if no message in 10s */
    var heartbeatEl = document.querySelector('[sse-swap="heartbeat"]');
    if (heartbeatEl) {
      heartbeatEl.addEventListener('htmx:sseMessage', function() {
        clearTimeout(window._ht);
        window._ht = setTimeout(function() {
          var w = document.querySelector('[sse-connect]');
          if (w) {
            w.removeAttribute('sse-connect');
            setTimeout(function() {
              w.setAttribute('sse-connect', '/events');
              htmx.process(w);
            }, 100);
          }
        }, 10000);
      });
    }

    /* Agent online/offline → trigger agentChanged on body */
    ['[sse-swap="agent-online"]', '[sse-swap="agent-offline"]'].forEach(function(sel) {
      var el = document.querySelector(sel);
      if (el) {
        el.addEventListener('htmx:sseMessage', function() {
          htmx.trigger(document.body, 'agentChanged');
        });
      }
    });

    /* scope-list after-swap: parse #scope-data, refresh agents map.
       Server returns a JSON ARRAY of agent objects but the rest of
       the JS expects a {agent_id: agentObj} map, so convert here. */
    var scopeListEl = document.getElementById('scope-list');
    if (scopeListEl) {
      scopeListEl.addEventListener('htmx:afterSwap', function() {
        var d = scopeListEl.querySelector('#scope-data');
        if (!d) return;
        try {
          var raw = JSON.parse(d.dataset.agents || '[]');
          var map = {};
          if (Array.isArray(raw)) {
            for (var i = 0; i < raw.length; i++) {
              if (raw[i] && raw[i].agent_id) map[raw[i].agent_id] = raw[i];
            }
          } else if (raw && typeof raw === 'object') {
            map = raw;
          }
          agents = map;
          cmdPalette.agentsCache = null;
        } catch (err) { /* swallow parse errors */ }
      });
    }

    /* help-loader after-request: build instructionMap from JSON */
    var helpLoaderEl = document.getElementById('help-loader');
    if (helpLoaderEl) {
      helpLoaderEl.addEventListener('htmx:afterRequest', function(event) {
        if (event.detail && event.detail.successful) {
          try {
            buildInstructionMap(JSON.parse(event.detail.xhr.responseText));
          } catch (err) { /* swallow */ }
        }
      });
    }

    /* ── Init ─────────────────────────────────────────────── */
    /* Agent list and help data are loaded by HTMX attributes
       (hx-trigger="load") — no JS init calls needed. The signed-in user is
       filled by the app shell's own script (app_shell.cpp). */

    /* Auto-open command palette if redirected from another page via ?palette=1 */
    if (new URLSearchParams(window.location.search).has('palette')) {
      history.replaceState(null, '', '/');
      setTimeout(function() { cmdPalette.open(); }, 100);
    }
)HTM"
    // Split here: the PR2 MFA step-up intercept block pushed this chunk to
    // ~18.3 KB, over MSVC's C2026 16380-byte raw-string-literal limit.
    // Adjacent string literals concatenate at compile time, so the runtime
    // HTML is byte-identical.
    R"HTM(
    /* PR2 — MFA step-up intercept. High-risk REST/Settings handlers return
       401 + A4 envelope `{"error":{...},"meta":{"mfa_step_up_required":true,
       "challenge_url":"/login/mfa/stepup"}}` when the session's
       mfa_verified_at is stale. Listen on htmx:responseError, detect the
       envelope, prompt the operator for a TOTP / recovery code, POST to
       /login/mfa/stepup, and on success retry the original request via
       htmx.ajax() so the dashboard interaction completes seamlessly.
       Minimal-UX intentional — a richer modal lives in a UX follow-up. */
    document.body.addEventListener('htmx:responseError', function(evt) {
      var xhr = evt.detail.xhr;
      if (!xhr || xhr.status !== 401) return;
      var env;
      try { env = JSON.parse(xhr.responseText); } catch (_) { return; }
      if (!env || !env.meta || !env.meta.mfa_step_up_required) return;
      /* Suppress any other htmx response-error handlers + the default
         error toast (governance Gate 4 happy-N3). We own this 401 from
         here on; the operator gets either a successful retry or an
         alert, not a duplicate error message. */
      evt.preventDefault();
      var challenge = (env.meta.challenge_url) || '/login/mfa/stepup';
      var code = window.prompt('MFA step-up required for this action.\n\nEnter your 6-digit TOTP code (or a recovery code):');
      if (!code) return; /* user cancelled */
      var form = new URLSearchParams();
      form.set('code', code.trim());
      fetch(challenge, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: form.toString()
      }).then(function(resp) {
        if (!resp.ok) {
          alert('MFA step-up failed — verify your code and try again.');
          return;
        }
        /* Replay the original request via htmx.ajax. The original
           triggering element is in evt.detail.elt; pass it as the
           context so OOB swaps / hx-target are honoured. */
        var elt = evt.detail.elt;
        var verb = (evt.detail.requestConfig && evt.detail.requestConfig.verb) ||
                   evt.detail.xhr.method || 'GET';
        var path = (evt.detail.requestConfig && evt.detail.requestConfig.path) ||
                   xhr.responseURL || '';
        var orig = (evt.detail.requestConfig && evt.detail.requestConfig.parameters) || {};
        htmx.ajax(verb.toUpperCase(), path, {source: elt, target: elt, values: orig});
      }).catch(function() {
        alert('MFA step-up request failed — please try the action again.');
      });
    });
  </script>
  <div id="toast-container" class="toast-container"></div>
</body>
</html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kDashboardIndexHtml =
    yuzu::server::shell::bake(kDashboardIndexTemplate, {.active_key = "dashboard"});
// NOLINTEND(cert-err58-cpp)
