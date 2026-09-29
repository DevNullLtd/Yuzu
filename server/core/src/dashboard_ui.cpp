// Unified dashboard UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kDashboardIndexHtml =
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
    .dashboard-grid {
      display: grid; flex: 1; min-height: 0;
      grid-template-rows: auto 1fr auto;
      grid-template-columns: 220px minmax(0, 1fr) 260px;
      grid-template-areas:
        "history instrbar  scope"
        "history results   scope"
        "history footer    scope";
    }
    /* Grid items default to min-width:auto (= min-content). The instr-bar's
       nowrap content has a ~920px min-content, which pins the whole grid at
       ~1400px and pushes the right-hand scope (agent list) column off-screen
       under body{overflow:hidden} on narrower windows. min-width:0 lets the
       middle track actually compress so the scope column stays visible.
       (Responsive breakpoints — hiding the history rail and reflowing to two
       columns on narrow viewports — live in static/yuzu.css.) */
    .dashboard-grid > * { min-width: 0; }

    /* ── Instruction Bar ─────────────────────────────────────── */
    .instr-bar {
      grid-area: instrbar;
      display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .instr-bar label {
      font-size: 0.8rem; font-weight: 600; color: var(--mds-color-theme-text-tertiary);
      white-space: nowrap;
    }
    .instr-bar input[type="text"] {
      flex: 1; padding: 0.45rem 0.75rem;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.375rem;
      font-size: 0.875rem; font-family: var(--mono);
      outline: none;
    }
    .instr-bar input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--mds-color-state-selected);
    }
    .instr-bar input[type="text"]::placeholder { color: var(--mds-color-theme-outline-secondary); }
    .instr-wrap { position: relative; flex: 1; display: flex; }
    .instr-wrap input[type="text"] { width: 100%; }
    .ac-list {
      display: none; position: absolute; top: 100%; left: 0; right: 0;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0 0 0.375rem 0.375rem; max-height: 280px;
      overflow-y: auto; z-index: 200; margin-top: 2px;
      font-family: var(--mono); font-size: 0.825rem;
    }
    .ac-list.open { display: block; }
    .ac-item {
      padding: 0.35rem 0.75rem; cursor: pointer; color: var(--fg);
      border-bottom: 1px solid var(--border); display: flex;
      justify-content: space-between; align-items: center;
    }
    .ac-item:last-child { border-bottom: none; }
    .ac-item:hover, .ac-item.sel { background: var(--mds-color-state-active); }
    .ac-item .ac-desc { color: var(--mds-color-theme-text-tertiary); font-size: 0.75rem; margin-left: 1rem; text-align: right; }
    .instr-bar button {
      padding: 0.45rem 1.2rem; font-size: 0.875rem; font-weight: 500;
      background: var(--accent); color: var(--mds-color-text-on-accent); border: none;
      border-radius: 0.375rem; cursor: pointer; transition: opacity 0.15s;
    }
    .instr-bar button:hover { opacity: 0.85; }
    .instr-bar button:disabled { opacity: 0.4; cursor: not-allowed; }
    #status-badge {
      font-size: 0.7rem; padding: 0.15rem 0.5rem;
      border-radius: 1rem; font-weight: 600;
    }
    .badge-idle     { background: var(--mds-color-theme-outline-secondary); color: var(--mds-color-text-on-accent); }
    .badge-running  { background: var(--green); color: var(--mds-color-text-on-accent); }
    .badge-done     { background: var(--green); color: var(--mds-color-text-on-accent); }
    .badge-error    { background: var(--red); color: var(--mds-color-text-on-accent); }
    .btn-clear {
      padding: 0.45rem 0.8rem; font-size: 0.8rem; font-weight: 500;
      background: var(--surface); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: pointer; transition: opacity 0.15s;
    }
    .btn-clear:hover { opacity: 0.85; }

    /* ── Stats row ───────────────────────────────────────────── */
    .stats {
      display: flex; gap: 1.2rem; align-items: center;
      font-size: 0.75rem; color: var(--mds-color-theme-text-tertiary); white-space: nowrap;
    }

    /* ── Results Area ────────────────────────────────────────── */
    .results {
      grid-area: results;
      overflow-y: auto;
      display: flex; flex-direction: column;
    }
    .results-header {
      display: flex; align-items: center; gap: 0.75rem;
      padding: 0.5rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .results-header h2 { font-size: 0.85rem; font-weight: 600; }

    /* Chart deck (issue #253 / #587) — one or more chart cards rendered
       above the filter bar by yuzu-charts.js when the dispatched
       definition has a spec.visualization. */
    .yuzu-chart-deck {
      display: flex; flex-wrap: wrap; gap: 1rem;
      padding: 0.75rem 1rem; background: var(--surface);
      border-bottom: 1px solid var(--border);
    }
    .yuzu-chart-deck:empty { display: none; }
    .yuzu-chart-card {
      flex: 1 1 360px; min-width: 320px; max-width: 600px; height: 280px;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: var(--radius-md); padding: 0.5rem 0.75rem;
      box-shadow: var(--mds-elevation-1);
    }
    .yuzu-chart-card svg, .yuzu-chart-card canvas {
      display: block; max-width: 100%;
    }

    /* Filter bar */
    .filter-bar {
      display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
      padding: 0.4rem 1rem; background: var(--surface);
      border-bottom: 1px solid var(--border); font-size: 0.75rem;
    }
    .filter-bar label { color: var(--mds-color-theme-text-tertiary); font-weight: 600; font-size: 0.65rem; text-transform: uppercase; }
    .filter-bar select, .filter-bar input[type="text"], .filter-bar input[type="search"] {
      background: var(--bg); color: var(--fg); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.25rem 0.4rem; font-size: 0.75rem;
      font-family: var(--font-mono);
    }
    .filter-bar select:focus, .filter-bar input:focus { border-color: var(--mds-color-theme-accent-primary-normal); outline: none; }
    /* #2691 (Gate 8 consistency-auditor): a degraded facet-values() read
       disables the column filter dropdown — give it the same amber degrade
       treatment as .result-degrade-banner rather than plain browser-default
       styling, so it doesn't visually read as an unrelated form quirk. */
    .filter-bar select:disabled {
      color: var(--yellow, #ffcc00); border-color: rgba(255, 204, 0, 0.4);
      background: rgba(255, 204, 0, 0.08); opacity: 1;
    }

    /* Sortable column headers */
    th.sortable { cursor: pointer; user-select: none; }
    th.sortable:hover { color: var(--mds-color-theme-accent-primary-normal); }

    /* Pagination */
    #result-pagination {
      display: flex; align-items: center; gap: 0.5rem;
      padding: 0.4rem 1rem; font-size: 0.75rem; color: var(--mds-color-theme-text-tertiary);
    }
    .btn-page {
      background: var(--surface); color: var(--fg); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.7rem; cursor: pointer;
    }
    .btn-page:hover { border-color: var(--mds-color-theme-accent-primary-normal); color: var(--mds-color-theme-accent-primary-normal); }

    /* Group creation */
    .btn-create-group {
      background: var(--green); color: var(--mds-color-text-on-accent); border: none; border-radius: 4px;
      padding: 0.25rem 0.6rem; font-size: 0.7rem; cursor: pointer; margin-left: 0.5rem;
    }
    .btn-create-group:hover { background: var(--mds-color-indicator-success-bright); }
    .create-group-form {
      display: flex; align-items: center; gap: 0.5rem;
      padding: 0.5rem 1rem; font-size: 0.75rem;
    }
    .create-group-form input[type="text"] {
      background: var(--bg); color: var(--fg); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.3rem 0.5rem; font-size: 0.75rem;
    }
    .create-group-form button {
      background: var(--green); color: var(--mds-color-text-on-accent); border: none; border-radius: 4px;
      padding: 0.3rem 0.6rem; font-size: 0.75rem; cursor: pointer;
    }
    .form-hint { color: var(--mds-color-theme-text-tertiary); font-size: 0.7rem; }
    .feedback-error { color: var(--mds-color-theme-indicator-error); font-size: 0.75rem; }
)HTM"
    // Part 1a: CSS continued (split to stay under MSVC's 16380-byte string
    // limit — this session's degrade-banner/filter-bar CSS additions pushed
    // Part 1 over it, CI-measured C2026).
    R"HTM(
    /* Scope section headers */
    .scope-section-header {
      padding: 0.3rem 0.75rem; font-size: 0.6rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.05em; color: var(--mds-color-theme-outline-secondary);
      border-top: 1px solid var(--border); margin-top: 0.25rem;
    }

    /* HTMX indicator */
    .htmx-indicator { display: none; }
    .htmx-request .htmx-indicator, .htmx-request.htmx-indicator { display: block; }

    .table-wrap {
      flex: 1; overflow-y: auto;
    }
    table {
      width: 100%; border-collapse: collapse; font-size: 0.8rem;
    }
    thead th {
      position: sticky; top: 0; background: var(--surface);
      text-align: left; padding: 0.45rem 0.6rem;
      border-bottom: 2px solid var(--border); font-weight: 600;
      color: var(--mds-color-theme-text-tertiary); text-transform: uppercase; font-size: 0.65rem;
      letter-spacing: 0.05em;
    }
    tbody td {
      padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border);
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 300px;
    }
    .result-detail td {
      white-space: normal; overflow: visible; max-width: none;
    }
    tbody tr:hover { background: var(--mds-color-state-hover); }
    .col-agent {
      font-family: var(--mono); font-size: 0.7rem;
      color: var(--yellow); width: 10rem;
    }
    .col-mono {
      font-family: var(--mono); font-size: 0.75rem;
    }
    .empty-state {
      text-align: center; padding: 3rem 1rem; color: var(--mds-color-theme-outline-secondary);
      font-size: 0.85rem;
    }
    /* #2691 finding 7: an honest "store degraded, not zero matches" banner —
       distinct from .empty-state so it doesn't visually read as "nothing here".
       Amber, not alarm-red (#2691 Gate 6 enterprise-readiness): this is a
       "temporarily unavailable, retrying" state, not a confirmed failure —
       red is reserved for that, so it works against the calm/accurate copy
       every degrade banner already carries. */
    .result-degrade-banner {
      color: var(--yellow, #ffcc00); background: rgba(255, 204, 0, 0.08);
      border: 1px solid rgba(255, 204, 0, 0.4); border-radius: 0.5rem;
      padding: 0.6rem 0.9rem; font-size: 0.8rem;
    }

    /* ── Scope Panel ─────────────────────────────────────────── */
    .scope {
      grid-area: scope;
      display: flex; flex-direction: column;
      border-left: 1px solid var(--border);
      background: var(--surface);
    }
    .scope-header {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.8rem; font-weight: 600;
    }
    .scope-count {
      font-weight: 400; color: var(--mds-color-theme-text-tertiary); font-size: 0.7rem;
      margin-left: 0.5rem;
    }
    .scope-list {
      flex: 1; overflow-y: auto; padding: 0.25rem 0;
    }
    .scope-item {
      display: flex; flex-direction: column; gap: 0.1rem;
      padding: 0.45rem 1rem; cursor: pointer;
      border-left: 3px solid transparent;
      transition: background 0.1s;
    }
    .scope-item:hover { background: var(--mds-color-state-hover); }
    .scope-item.selected {
      background: var(--mds-color-state-active);
      border-left-color: var(--accent);
    }
    .scope-item-name {
      font-size: 0.8rem; font-weight: 500;
    }
    .scope-item-meta {
      font-size: 0.65rem; color: var(--mds-color-theme-text-tertiary);
      font-family: var(--mono);
    }
    .scope-item-all {
      font-weight: 600; color: var(--accent);
    }
    .scope-item .online-dot {
      display: inline-block; width: 6px; height: 6px;
      border-radius: 50%; background: var(--green);
      margin-right: 0.35rem; vertical-align: middle;
    }

    /* ── History Panel ───────────────────────────────────────── */
    .history {
      grid-area: history;
      display: flex; flex-direction: column;
      border-right: 1px solid var(--border);
      background: var(--surface);
    }
    .history-header {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.8rem; font-weight: 600;
      display: flex; justify-content: space-between; align-items: center;
    }
    .history-header button {
      background: none; border: none; color: var(--mds-color-theme-text-tertiary); cursor: pointer;
      font-size: 0.7rem; padding: 0.15rem 0.4rem;
    }
    .history-header button:hover { color: var(--fg); }
    .history-list {
      flex: 1; overflow-y: auto; padding: 0.25rem 0;
    }
    .history-item {
      padding: 0.4rem 1rem; cursor: pointer;
      border-left: 3px solid transparent;
      transition: background 0.1s;
    }
    .history-item:hover { background: var(--mds-color-state-hover); }
    .history-item.active {
      background: var(--mds-color-state-active);
      border-left-color: var(--accent);
    }
    .history-cmd {
      font-size: 0.78rem; font-family: var(--mono); color: var(--fg);
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .history-meta {
      font-size: 0.6rem; color: var(--mds-color-theme-text-tertiary); margin-top: 0.1rem;
    }
    .history-empty {
      padding: 1.5rem 1rem; text-align: center;
      font-size: 0.75rem; color: var(--mds-color-theme-outline-secondary);
    }

    /* ── Footer ──────────────────────────────────────────────── */
    footer {
      grid-area: footer;
      padding: 0.4rem 1rem; border-top: 1px solid var(--border);
      font-size: 0.7rem; color: var(--mds-color-theme-outline-secondary);
    }

    /* ── About Modal ─────────────────────────────────────────── */
    .modal-overlay {
      display: none; position: fixed; inset: 0;
      background: var(--mds-color-state-overlay-scrim); z-index: 2000;
      align-items: center; justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.75rem; padding: 2rem; width: 380px;
      text-align: center;
    }
    .modal h2 { font-size: 1.3rem; margin-bottom: 0.5rem; }
    .modal .version { font-size: 0.8rem; color: var(--mds-color-theme-text-tertiary); margin-bottom: 1rem; }
    .modal p { font-size: 0.8rem; color: var(--mds-color-theme-text-tertiary); line-height: 1.5; margin-bottom: 1rem; }
    .modal .btn-close {
      padding: 0.4rem 1.5rem; font-size: 0.8rem; font-weight: 500;
      background: var(--accent); color: var(--mds-color-text-on-accent); border: none;
      border-radius: 0.375rem; cursor: pointer;
    }
  </style>
</head>
)HTM"
    // Split here: chunk 1 (head + <style>) was ~16 KB and bumped against
    // the MSVC C2026 16380-byte raw-string-literal limit after the round-2
    // visualization additions. Adjacent string literals concatenate at
    // compile time, so the runtime HTML is byte-identical.
    R"HTM(<body>

  <nav class="nav-bar">
    <a href="/" class="nav-brand">
      <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
    </a>
    <a href="/" class="nav-link active">Dashboard</a>
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

  <div class="dashboard-grid">

  <!-- ── Instruction Bar ────────────────────────────────────── -->
  <!-- hx-on::before-request clears the chart deck the instant the
       operator clicks Send so a stale chart from the previous
       dispatch can't linger over the new query's results. The new
       deck is delivered later via the OOB swap from
       /fragments/results once execution has data to render. -->
  <form class="instr-bar" id="instr-form"
        hx-post="/api/dashboard/execute" hx-swap="none"
        hx-on::before-request="clearChartDeck()">
    <label>Instruction</label>
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
    <span id="status-badge" class="badge-idle">IDLE</span>
    <button type="button" class="btn-clear" onclick="clearResults()">Clear</button>
    <div class="stats">
      <span>Rows: <strong id="row-count">0</strong></span>
      <span>Network: <strong id="stat-network">&mdash;</strong></span>
      <span>Agent: <strong id="stat-agent">&mdash;</strong></span>
      <span>Total: <strong id="stat-total">&mdash;</strong></span>
    </div>
  </form>

  <!-- ── About Modal ──────────────────────────────────────── -->
  <div class="modal-overlay" id="about-modal" onclick="closeAbout(event)">
    <div class="modal">
      <h2>Yuzu</h2>
      <div class="version">Endpoint Management Platform</div>
      <p id="about-details" style="font-size:0.75rem;color: var(--mds-color-theme-text-tertiary);line-height:1.7;margin-bottom:0.75rem">
        Loading...
      </p>
      <p style="font-size:0.7rem;margin-bottom:0.75rem">Built with C++23, gRPC, Protobuf, SQLite</p>
      <p style="font-size:0.7rem;margin-bottom:1rem">
        <a href="https://github.com/anthropics/yuzu" target="_blank" style="color: var(--mds-color-theme-accent-primary-normal);text-decoration:none">GitHub</a>
        &nbsp;&middot;&nbsp;
        <a href="/help" style="color: var(--mds-color-theme-accent-primary-normal);text-decoration:none">Documentation</a>
      </p>
      <p style="font-size:0.65rem;color: var(--mds-color-theme-outline-secondary);margin-bottom:1rem">AGPL-3.0-or-later (community) &middot; commercial license available for enterprise edition</p>
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
  <!-- ── History Panel ──────────────────────────────────────── -->
  <div class="history">
    <div class="history-header">
      History
      <button onclick="clearHistory()" title="Clear history">&times; Clear</button>
    </div>
    <div class="history-list" id="history-list">
      <div class="history-empty" id="history-empty">No commands yet</div>
    </div>
  </div>

  <!-- ── Results ────────────────────────────────────────────── -->
  <div class="results">
    <div class="results-header">
      <h2>Results</h2>
      <span id="result-context" style="font-size:0.75rem;color: var(--mds-color-theme-text-tertiary)"></span>
      <div id="result-summary" style="font-size:0.75rem;color: var(--mds-color-theme-text-tertiary)"></div>
      <span style="flex:1"></span>
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
    <div id="results-loading" class="htmx-indicator" style="padding:0.5rem;color:var(--muted);font-size:0.75rem">Loading...</div>
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

  <!-- ── Scope Panel ────────────────────────────────────────── -->
  <div class="scope">
    <div class="scope-header">
      Scope <span class="scope-count" id="agent-count">0 agents</span>
    </div>
    <div class="scope-list" id="scope-list"
         hx-get="/fragments/scope-list"
         hx-trigger="load, every 5s, agentChanged from:body"
         hx-swap="innerHTML">
    </div>
  </div>

  <footer>Yuzu Server &mdash; Dashboard <span style="float:right;color:var(--subtle)">Press <kbd style="display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:18px;padding:0 4px;background:var(--bg);border:1px solid var(--border);border-radius:3px;font-size:0.6rem;font-family:var(--font-sans);color:var(--muted)">Ctrl+K</kbd> to search</span></footer>

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

  </div><!-- /.dashboard-grid -->
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
    // dispatch (hx-on::before-request on #instr-form) so a stale chart
    // from the previous query never overlays the new one.
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

    /* ── Load current user info (nav bar + context bar) ─── */
    function loadUserInfo() {
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
       hx-on:* attributes and hx-vals="js:..." — are blocked at
       runtime. We re-create each broken handler here using
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

    /* instr-form: close autocomplete before submit */
    var instrForm = document.getElementById('instr-form');
    if (instrForm) {
      instrForm.addEventListener('htmx:beforeRequest', function() {
        if (typeof closeAC === 'function') closeAC();
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
    /* Agent list, help data, and user info are loaded by HTMX
       attributes (hx-trigger="load") — no JS init calls needed
       except loadUserInfo which updates body data-role. */
    loadUserInfo();

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
// NOLINTEND(cert-err58-cpp)
