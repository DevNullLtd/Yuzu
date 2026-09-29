// TAR dashboard page (Phase 15.A — issue #547).
// Hosts the retention-paused source list as the first frame; the
// scope-walking-aware SQL frame (Phase 15.D) and the process-tree viewer
// (Phase 15.H) drop in later. Compiled in its own translation unit to keep
// the long raw string literal away from server.cpp's brace matching.
//
// Design: docs/tar-dashboard.md.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kTarPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — TAR</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { display: flex; flex-direction: column; min-height: 100vh; }
    .tar-content {
      max-width: 1200px;
      margin: 1rem auto;
      padding: 0 1.5rem 2rem 1.5rem;
      width: 100%;
      box-sizing: border-box;
      flex: 1;
    }
    .tar-content h1 {
      font-size: 1.4rem;
      margin: 0.25rem 0 0.5rem 0;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .tar-subtitle {
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.85rem;
      margin: 0 0 1.5rem 0;
    }
    .tar-frame {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }
    .tar-frame-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--mds-color-state-hover);
    }
    .tar-frame-title {
      font-size: 0.95rem;
      font-weight: 600;
      margin: 0;
    }
    .tar-frame-actions { display: flex; gap: 0.5rem; }
    .tar-frame-actions button {
      padding: 0.35rem 0.85rem;
      font-size: 0.8rem;
      background: var(--accent);
      color: var(--mds-color-text-on-accent);
      border: none;
      border-radius: 0.25rem;
      cursor: pointer;
    }
    .tar-frame-actions button:hover { opacity: 0.85; }
    .tar-frame-actions button.btn-secondary {
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
    }
    .tar-frame-body { padding: 1rem; }
    .tar-frame-body table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .tar-frame-body th {
      text-align: left;
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid var(--border);
      color: var(--mds-color-theme-text-tertiary);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .tar-frame-body td {
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .tar-frame-body tr:last-child td { border-bottom: none; }
    .tar-frame-body tr:hover { background: var(--mds-color-state-hover); }
    .tar-frame-body .source-pill {
      display: inline-block;
      padding: 0.1rem 0.5rem;
      font-size: 0.7rem;
      font-weight: 600;
      background: var(--mds-color-bg-warning-tinted);
      color: var(--mds-color-indicator-warning-bright);
      border-radius: 0.75rem;
    }
    .tar-frame-body .placeholder {
      padding: 2rem 0;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-frame-body .empty-state {
      padding: 2.5rem 0;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.9rem;
    }
    .tar-frame-body .empty-state strong { color: var(--green); }
    .tar-frame-coming-soon {
      padding: 2rem;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.85rem;
      background: var(--mds-color-state-hover);
      border: 1px dashed var(--border);
      border-radius: 0.25rem;
      margin: 0.5rem;
    }
    .tar-frame-coming-soon code {
      background: var(--mds-color-state-hover);
      padding: 0.1rem 0.4rem;
      border-radius: 0.25rem;
      font-size: 0.8rem;
    }
    .tar-row-error { color: var(--mds-color-theme-indicator-error); }
    .tar-row-error td { font-style: italic; }

    /* Scope chip (design §8.3) — reusable header for query frames. */
    .scope-chip-row {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }
    .scope-chip-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--mds-color-theme-text-tertiary);
      font-weight: 600;
    }
    .scope-chip-select {
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.3rem 0.5rem;
      font-size: 0.8rem;
      max-width: 24rem;
    }
    .scope-chip-meta {
      font-size: 0.75rem;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-sql-textarea {
      width: 100%;
      box-sizing: border-box;
      background: var(--mds-color-state-hover);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.6rem;
      font-family: var(--mono, monospace);
      font-size: 0.8rem;
      resize: vertical;
    }
    .tar-sql-controls {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 0.6rem;
      flex-wrap: wrap;
    }
    .tar-sql-name {
      flex: 1 1 16rem;
      min-width: 12rem;
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.35rem 0.5rem;
      font-size: 0.8rem;
    }
    .tar-sql-empty {
      font-size: 0.75rem;
      color: var(--mds-color-theme-text-tertiary);
      display: flex;
      align-items: center;
      gap: 0.3rem;
    }
    .tar-sql-controls button {
      padding: 0.4rem 0.9rem;
      font-size: 0.8rem;
      background: var(--accent);
      color: var(--mds-color-text-on-accent);
      border: none;
      border-radius: 0.25rem;
      cursor: pointer;
    }
    .tar-sql-controls button:disabled { opacity: 0.5; cursor: default; }
    .tar-sql-result {
      margin-top: 0.75rem;
      font-size: 0.82rem;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-sql-result a { color: var(--accent); }
    .tar-sql-result code {
      background: var(--mds-color-state-hover);
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
    }
    .tar-sql-result.error { color: var(--mds-color-theme-indicator-error); }

    /* ── Process tree viewer (Phase 15.H) ───────────────────────────────── */
    .tar-tree-toolbar {
      display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;
    }
    .tar-tree-presets { display: flex; gap: 0.35rem; flex-wrap: wrap; }
    .tar-tree-custom { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
    .tar-tree-custom label {
      font-size: 0.7rem; color: var(--mds-color-theme-text-tertiary);
      display: flex; align-items: center; gap: 0.3rem;
    }
    .tar-tree-custom input[type="datetime-local"] {
      background: var(--surface); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.25rem;
      padding: 0.25rem 0.4rem; font-size: 0.75rem;
    }
    .tar-chip {
      display: inline-block; cursor: pointer; user-select: none;
      background: var(--mds-color-state-hover); color: var(--fg);
      border: 1px solid var(--border); border-radius: 1rem;
      padding: 0.25rem 0.7rem; font-size: 0.75rem;
    }
    .tar-chip:hover { border-color: var(--accent); }
    .tar-chip.on { background: var(--accent); color: var(--mds-color-text-on-accent); border-color: var(--accent); }
    /* Filter bar (state + anomalies + text) */
    .tar-tree-filterbar {
      display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;
      margin: 0.5rem 0 0.6rem; padding-top: 0.5rem; border-top: 1px solid var(--border);
    }
    .tt-filter-label {
      font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
      color: var(--mds-color-theme-text-tertiary); font-weight: 600;
    }
    .tt-anom-toggle {
      font-size: 0.72rem; color: var(--mds-color-theme-text-tertiary);
      display: flex; align-items: center; gap: 0.3rem;
    }
    .tar-tree-filter {
      flex: 1 1 12rem; min-width: 10rem;
      background: var(--surface); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.25rem;
      padding: 0.3rem 0.5rem; font-size: 0.78rem;
    }
    .tar-tree-banner, .tar-tree-note, .tar-tree-warn, .tar-tree-empty, .tar-tree-loading,
    .tar-tree-nomatch {
      font-size: 0.78rem; color: var(--mds-color-theme-text-tertiary); margin: 0.3rem 0;
    }
    .tar-tree-note code, .tar-tree-banner b { color: var(--fg); }
    .tar-tree-warn { color: var(--mds-color-theme-indicator-warning, #d6a500); }
    .tar-tree-mute { color: var(--mds-color-theme-text-tertiary); }

    /* Tree */
    .tar-tree { font-family: var(--mono, monospace); font-size: 0.8rem; margin-top: 0.4rem; line-height: 1.5; }
    .tar-tree-node { margin: 0; }
    .tar-tree-node > summary {
      display: flex; align-items: center; list-style: none; cursor: pointer; padding: 0.05rem 0;
    }
    .tar-tree-node > summary::-webkit-details-marker { display: none; }
    .tar-tree-node > summary::before {
      content: "\25B8"; flex: 0 0 1rem; text-align: center;
      color: var(--mds-color-theme-text-tertiary); font-size: 0.7rem;
    }
    .tar-tree-node[open] > summary::before { content: "\25BE"; }
    .tar-tree-children {
      margin-left: 0.5rem; padding-left: 0.7rem; border-left: 1px solid var(--border);
    }
    .tar-tree-leaf { display: flex; align-items: center; padding: 0.05rem 0 0.05rem 1rem; }
    .tar-tree-row {
      display: inline-flex; align-items: center; gap: 0.45rem; flex: 1 1 auto; min-width: 0;
      color: var(--fg); text-decoration: none; cursor: pointer;
      padding: 0.05rem 0.3rem; border-radius: 0.2rem;
    }
    .tar-tree-row:hover { background: var(--mds-color-state-hover); }
    .tar-tree-row[data-anom="1"] { box-shadow: inset 2px 0 0 var(--mds-color-theme-indicator-error); }
    .tar-tree-row[data-state="exited"] { opacity: 0.78; }
    .tt-dot { width: 0.5rem; height: 0.5rem; border-radius: 50%; flex: 0 0 auto; }
    .tt-dot-run { background: var(--green); box-shadow: 0 0 4px rgba(60,200,120,0.5); }
    .tt-dot-exit { background: var(--mds-color-theme-text-tertiary); }
    .tt-pid {
      color: var(--mds-color-theme-text-tertiary); flex: 0 0 auto; min-width: 3.4rem;
      text-align: right; font-variant-numeric: tabular-nums;
    }
    .tt-name { color: var(--fg); font-weight: 600; white-space: nowrap; }
    .tar-tree-row[data-state="exited"] .tt-name { font-weight: 500; color: var(--mds-color-theme-text-tertiary); }
    .tt-user { color: var(--accent); font-size: 0.72rem; white-space: nowrap; }
    .tt-meta { color: var(--mds-color-theme-text-tertiary); font-size: 0.7rem; white-space: nowrap; }
    .tt-anom { color: var(--mds-color-theme-indicator-error); }
    /* Inline network summary */
    .tt-net {
      display: inline-flex; align-items: center; gap: 0.25rem; font-size: 0.68rem;
      color: var(--mds-color-theme-text-tertiary); min-width: 0; overflow: hidden;
    }
    .tt-net-ico { color: var(--accent); }
    .tt-net-pub .tt-net-ico { color: var(--mds-color-theme-indicator-warning, #d6a500); }
    .tt-ep {
      background: var(--mds-color-state-hover); border-radius: 0.6rem; padding: 0 0.35rem;
      white-space: nowrap; font-variant-numeric: tabular-nums;
    }
    .tt-ep-pub { color: var(--mds-color-theme-indicator-warning, #d6a500); }
    .tt-ep-more { opacity: 0.7; }
    /* Same-name sibling group ("svchost.exe ×42") */
    .tt-group { color: var(--mds-color-theme-text-tertiary); }
    .tt-group-ico { color: var(--accent); flex: 0 0 auto; font-size: 0.7rem; }
    .tt-group .tt-name { color: var(--fg); }
    .tt-group-count {
      color: var(--fg); font-weight: 600; background: var(--mds-color-state-hover);
      border-radius: 0.6rem; padding: 0 0.4rem; font-size: 0.7rem;
    }

    /* Two-column layout: scrollable tree + sticky right-hand detail panel */
    .tar-tree-layout { display: flex; gap: 1rem; align-items: flex-start; margin-top: 0.5rem; }
    .tar-tree-main { flex: 1 1 auto; min-width: 0; overflow-x: auto; }
    .tar-tree-side {
      flex: 0 0 23rem; position: sticky; top: 0.5rem;
      max-height: calc(100vh - 6rem); overflow: auto;
    }
    @media (max-width: 1000px) {
      .tar-tree-layout { flex-direction: column; }
      .tar-tree-side { position: static; flex-basis: auto; width: 100%; max-height: none; }
    }

    /* Detail panel */
    .tar-detail {
      margin-top: 0.75rem; padding: 0.75rem;
      background: var(--mds-color-state-hover); border: 1px solid var(--border);
      border-radius: 0.25rem; font-size: 0.8rem;
    }
    .tar-detail-title { font-size: 0.95rem; font-weight: 600; margin-bottom: 0.5rem; }
    .tar-kv { display: flex; gap: 0.6rem; padding: 0.15rem 0; }
    .tar-kv-k { flex: 0 0 9rem; color: var(--mds-color-theme-text-tertiary); }
    .tar-kv-v { color: var(--fg); word-break: break-all; }
    .tar-detail-section { font-weight: 600; margin: 0.7rem 0 0.3rem; }
    .tar-detail-anom { margin: 0.5rem 0; color: var(--mds-color-theme-indicator-error); }
    .tar-detail-conns { width: 100%; border-collapse: collapse; font-size: 0.72rem; }
    .tar-detail-conns th, .tar-detail-conns td {
      text-align: left; padding: 0.2rem 0.4rem; border-bottom: 1px solid var(--border);
    }
    .tar-detail-conns th { color: var(--mds-color-theme-text-tertiary); font-weight: 600; }
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate
// (still one continuous <style> block in the rendered HTML).
R"HTM(
    /* Device DNS/ARP panels (ADR-0015) — embedded below the process tree */
    .devnet-row { display: flex; gap: 1rem; margin-top: 1rem; padding-top: 0.85rem;
      border-top: 1px solid var(--border); flex-wrap: wrap; }
    .devnet-panel { flex: 1 1 22rem; min-width: 18rem; border: 1px solid var(--border);
      border-radius: 0.4rem; overflow: hidden; background: var(--mds-color-theme-background-canvas); }
    .devnet-panel > summary { list-style: none; cursor: pointer; display: flex; align-items: center;
      justify-content: space-between; gap: 0.5rem; padding: 0.55rem 0.8rem;
      background: var(--mds-color-state-hover); font-size: 0.82rem; font-weight: 600; }
    .devnet-panel > summary::-webkit-details-marker { display: none; }
    .devnet-panel > summary::before { content: "\25B8"; color: var(--mds-color-theme-text-tertiary);
      font-size: 0.7rem; margin-right: 0.1rem; }
    .devnet-panel[open] > summary::before { content: "\25BE"; }
    .devnet-title-ico { color: var(--accent); margin-right: 0.35rem; }
    .devnet-count { font-weight: 600; color: var(--fg); background: var(--mds-color-state-hover);
      border-radius: 0.6rem; padding: 0 0.45rem; font-size: 0.7rem; }
    .devnet-body { max-height: 18rem; overflow: auto; }
    .devnet-table { width: 100%; border-collapse: collapse; font-family: var(--mono, monospace); font-size: 0.72rem; }
    .devnet-table th { position: sticky; top: 0; background: var(--mds-color-theme-background-solid-secondary);
      text-align: left; padding: 0.35rem 0.6rem; color: var(--mds-color-theme-text-tertiary); font-weight: 600;
      font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.03em; border-bottom: 1px solid var(--border); }
    .devnet-table td { padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
    .devnet-table tr:last-child td { border-bottom: none; }
    .devnet-table tr:hover { background: var(--mds-color-state-hover); }
    .dn-type { color: var(--accent); }
    .dn-data { color: var(--fg); }
    .dn-ttl { color: var(--mds-color-theme-text-tertiary); text-align: right; font-variant-numeric: tabular-nums; }
    .dn-src { color: var(--mds-color-theme-text-tertiary); }
    .arp-mac { color: var(--fg); }
    .arp-type-static { color: var(--mds-color-theme-text-tertiary); }
    .arp-type-dynamic { color: var(--accent); }
    .arp-type-other { color: var(--mds-color-theme-indicator-warning, #d6a500); } /* incomplete / unresolved */
    .devnet-caveat { padding: 0.4rem 0.8rem; font-size: 0.68rem; color: var(--mds-color-theme-text-tertiary);
      background: var(--surface); border-top: 1px solid var(--border); }
    .devnet-empty { padding: 1.5rem; text-align: center; color: var(--mds-color-theme-text-tertiary); font-size: 0.78rem; }

    /* Capture-sources frame (ADR-0015) — toggles, category filter, push guardrail */
    .picker-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.9rem; flex-wrap: wrap; }
    .picker-row label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--mds-color-theme-text-tertiary); font-weight: 600; }
    .cat-filter { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 0.8rem; }
    .filter-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--mds-color-theme-text-tertiary); font-weight: 600; margin-right: 0.2rem; }
    #capTable .src-name { font-weight: 600; color: var(--fg); font-family: var(--mono, monospace); font-size: 0.82rem; }
    #capTable .src-dollar { color: var(--mds-color-theme-text-tertiary); font-size: 0.72rem; font-family: var(--mono, monospace); }
    #capTable .cat { font-size: 0.74rem; color: var(--fg); white-space: nowrap; }
    .badge { display: inline-block; padding: 0.1rem 0.5rem; font-size: 0.68rem; font-weight: 600; border-radius: 0.75rem; }
    .badge-new { background: var(--mds-color-bg-info-tinted); color: var(--accent); }
    .badge-pii { background: var(--mds-color-bg-warning-tinted); color: var(--mds-color-indicator-warning-bright); }
    .badge-rows { background: var(--mds-color-bg-neutral-tinted); color: var(--mds-color-theme-text-tertiary); font-family: var(--mono, monospace); }
    .os-cell { font-size: 0.7rem; white-space: nowrap; }
    .os-ok { color: var(--green); }
    .os-con { color: var(--yellow); }
    .os-planned { color: var(--mds-color-theme-text-tertiary); opacity: 0.7; }
    .tgl { position: relative; display: inline-block; width: 38px; height: 20px; }
    .tgl input { opacity: 0; width: 0; height: 0; }
    .tgl .sl { position: absolute; cursor: pointer; inset: 0; background: var(--mds-color-theme-outline-secondary); border-radius: 20px; transition: .15s; }
    .tgl .sl:before { content: ""; position: absolute; height: 14px; width: 14px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: .15s; }
    .tgl input:checked + .sl { background: var(--accent); }
    .tgl input:checked + .sl:before { transform: translateX(18px); }
    .tgl.locked .sl { background: var(--green); cursor: not-allowed; opacity: 0.55; }
    .state-cell { display: flex; align-items: center; gap: 0.5rem; }
    .state-txt { font-size: 0.72rem; color: var(--mds-color-theme-text-tertiary); }
    .state-on { color: var(--green); font-weight: 600; }
    .pending-txt { color: var(--mds-color-indicator-warning-bright) !important; font-weight: 600; }
    #capTable tr.pending { box-shadow: inset 3px 0 0 var(--yellow); }
    #capTable tr.pending td { background: var(--mds-color-bg-warning-tinted); }
    .apply-bar { display: flex; align-items: center; gap: 0.6rem; margin-top: 0.9rem; padding: 0.6rem 0.85rem; background: var(--mds-color-bg-warning-tinted); border: 1px solid var(--yellow); border-radius: 0.4rem; font-size: 0.82rem; }
    .apply-icon { color: var(--mds-color-indicator-warning-bright); font-size: 1rem; }
    .apply-spacer { flex: 1; }
    .apply-push { background: var(--accent); color: #fff; border: none; border-radius: 0.25rem; padding: 0.4rem 0.95rem; font-size: 0.8rem; cursor: pointer; font-weight: 600; }
    .apply-push:hover { opacity: 0.9; }
  </style>
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals are
// concatenated by the compiler, so the rendered HTML is byte-identical.
R"HTM(</head>
<body>

  <nav class="nav-bar">
    <a href="/" class="nav-brand">
      <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
    </a>
    <a href="/" class="nav-link">Dashboard</a>
    <a href="/instructions" class="nav-link">Instructions</a>
    <a href="/compliance" class="nav-link">Compliance</a>
    <a href="/guardian" class="nav-link">Guardian</a>
    <a href="/dex" class="nav-link">DEX</a>
    <a href="/tar" class="nav-link active">TAR</a>
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

  <div class="tar-content">
    <h1>TAR &mdash; Timeline Activity Record</h1>
    <p class="tar-subtitle">
      Forensic + inventory data warehouse on each agent. Disable a
      collector to freeze its data for analysis; re-enable when finished.
    </p>

    <!-- ── Retention-paused sources (Phase 15.A) ─────────────────────── -->
    <div class="tar-frame" id="frame-retention-paused">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Retention-paused sources</h2>
        <div class="tar-frame-actions">
          <button class="btn-secondary"
                  hx-post="/fragments/tar/retention-paused/scan"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Scan fleet
          </button>
          <button hx-get="/fragments/tar/retention-paused"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Refresh
          </button>
        </div>
      </div>
      <div class="tar-frame-body" id="retention-paused-body"
           hx-get="/fragments/tar/retention-paused"
           hx-trigger="load"
           hx-swap="innerHTML">
        <div class="placeholder">Loading paused sources&hellip;</div>
      </div>
    </div>

)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate.
R"HTM(    <!-- ── Capture sources (ADR-0015) ───────────────────────────────── -->
    <div class="tar-frame" id="frame-capture-sources">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Capture sources</h2>
      </div>
      <div class="tar-frame-body" id="capture-sources"
           hx-get="/fragments/tar/capture-sources" hx-trigger="load" hx-swap="innerHTML">
        <div class="placeholder">Loading capture sources&hellip;</div>
      </div>
    </div>
    <script>
    // Phase 15.A retention-paused purge: typed-hostname confirmation via a native
    // prompt() (CSP-safe — no eval/hx-on, mirrors the native confirm() used for
    // re-enable), then an htmx POST that swaps the row's action cell with the
    // server's "dispatched" note. Values come from data-* attributes (HTML-escaped
    // server-side) — never interpolated into this script.
    function tarPurgeConfirm(btn){
      var dev=btn.getAttribute('data-device'),host=btn.getAttribute('data-host'),source=btn.getAttribute('data-source');
      var typed=window.prompt('DESTRUCTIVE: permanently delete all '+source+' data on '+host+'.\nThe source stays paused; this cannot be undone.\n\nType the device hostname to confirm:');
      if(typed===null)return;
      if(typed!==host){if(typeof showToast==='function')showToast('Hostname did not match — purge cancelled','error');return;}
      htmx.ajax('POST','/fragments/tar/retention-paused/purge',{values:{device_id:dev,source:source},target:btn.closest('td'),swap:'innerHTML'});
    }
    // Capture-sources staged-then-push guardrail + category filter (ADR-0015). Plain
    // onclick/onchange handlers (CSP-safe — no hx-on/eval). A toggle only STAGES a
    // change; nothing is dispatched until Push.
    function capDirtyRows(){return Array.prototype.slice.call(document.querySelectorAll('#capTable tbody tr.pending'));}
    function refreshCapBar(){var n=capDirtyRows().length,bar=document.getElementById('capApplyBar');if(!bar)return;bar.hidden=(n===0);var m=document.getElementById('capApplyMsg');if(m)m.textContent=n+' pending change'+(n===1?'':'s')+' — not yet sent';}
    function setCapState(tr,on){var st=tr.querySelector('.state-txt');if(!st)return;st.textContent=on?'enabled':'disabled';st.classList.remove('pending-txt');st.classList.toggle('state-on',on);}
    function stageCapToggle(cb){var tr=cb.closest('tr');var committed=cb.dataset.committed==='true';var dirty=cb.checked!==committed;tr.classList.toggle('pending',dirty);if(dirty){var st=tr.querySelector('.state-txt');st.textContent=(cb.checked?'→ enable':'→ disable')+' (pending)';st.classList.add('pending-txt');st.classList.remove('state-on');}else{setCapState(tr,committed);}refreshCapBar();}
    function discardCapChanges(){capDirtyRows().forEach(function(tr){var cb=tr.querySelector('input[type=checkbox]');cb.checked=(cb.dataset.committed==='true');setCapState(tr,cb.checked);tr.classList.remove('pending');});refreshCapBar();}
    function pushCapChanges(){var rows=capDirtyRows();if(!rows.length)return;var t=document.getElementById('capTable');var device=t?t.getAttribute('data-device'):'';var parts=rows.map(function(tr){var cb=tr.querySelector('input[type=checkbox]');return cb.dataset.source+'='+(cb.checked?'on':'off');});htmx.ajax('POST','/fragments/tar/capture-sources/push',{values:{device:device,changes:parts.join(',')},swap:'none'}).then(function(){if(typeof showToast==='function')showToast('Pushed '+parts.length+' change(s) to '+device,'success');htmx.ajax('GET','/fragments/tar/capture-sources/load',{values:{device:device},target:'#cap-sources-body',swap:'innerHTML'});});}
    function filterCap(chip,cat){document.querySelectorAll('#capFilter .tar-chip').forEach(function(c){c.classList.toggle('on',c===chip);});document.querySelectorAll('#capTable tbody tr').forEach(function(tr){tr.style.display=(cat==='all'||tr.getAttribute('data-cat')===cat)?'':'none';});}
    </script>
)HTM"
// Literal split (MSVC C2026 16380-char cap) — adjacent raw-string literals concatenate.
R"HTM(
    <!-- ── Ad-hoc TAR SQL frame (Phase 15.D — scope walking) ────────── -->
    <div class="tar-frame" id="frame-tar-sql">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Ad-hoc TAR SQL</h2>
        <div class="tar-frame-actions">
          <button class="btn-secondary" id="tar-sql-refresh-scopes"
                  title="Reload your result sets">Refresh scopes</button>
        </div>
      </div>
      <div class="tar-frame-body">
        <!-- Scope chip (design §8.3): pick the candidate scope this query
             narrows. Submitting creates a NEW result set parented at the
             selected set. Standard scopes (__all__) carry no parent. -->
        <div class="scope-chip-row">
          <label class="scope-chip-label" for="tar-sql-scope">Scope</label>
          <select id="tar-sql-scope" class="scope-chip-select">
            <option value="__all__">__all__ — entire fleet</option>
          </select>
          <span class="scope-chip-meta" id="tar-sql-scope-meta"></span>
        </div>
        <textarea id="tar-sql-text" class="tar-sql-textarea" rows="4" spellcheck="false"
                  placeholder="SELECT DISTINCT pid FROM process_live WHERE name = 'chrome.exe'"></textarea>
        <div class="tar-sql-controls">
          <input type="text" id="tar-sql-name" class="tar-sql-name"
                 placeholder="Name (optional) e.g. windows-chrome-suspects" maxlength="120">
          <label class="tar-sql-empty">
            <input type="checkbox" id="tar-sql-include-empty"> include responders with 0 rows
          </label>
          <button id="tar-sql-run">Run &amp; create result set</button>
        </div>
        <div class="tar-sql-result" id="tar-sql-result"></div>
      </div>
    </div>

    <!-- ── Process tree viewer (Phase 15.H) ─────────────────────────── -->
    <div class="tar-frame" id="frame-process-tree">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Process tree viewer</h2>
      </div>
      <div class="tar-frame-body">
        <!-- No hx-target here: the default target is this element itself. An
             explicit hx-target="this" would be INHERITED by descendants (the poll
             div), making their swaps clobber this whole frame body. -->
        <div hx-get="/fragments/tar/process-tree" hx-trigger="load" hx-swap="innerHTML">
          <div class="tar-tree-loading">Loading process tree viewer&hellip;</div>
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
// after every tree swap (htmx:afterSettle) since the toolbar lives outside #tar-tree.
window.__ttState = 'all';
function tarTreeState(s, el) {
  window.__ttState = s;
  if (el && el.parentElement) {
    el.parentElement.querySelectorAll('[data-statechip]').forEach(function(c){
      c.classList.toggle('on', c === el);
    });
  }
  applyTarTreeFilters();
}
function applyTarTreeFilters() {
  var tree = document.querySelector('#tar-tree .tar-tree');
  if (!tree) return;
  var state = window.__ttState || 'all';
  var anomEl = document.getElementById('tar-tree-anom-only');
  var anomOnly = anomEl && anomEl.checked;
  var qEl = document.getElementById('tar-tree-filter');
  var q = (qEl && qEl.value ? qEl.value : '').trim().toLowerCase();
  var active = state !== 'all' || anomOnly || q;
  var nomatch = document.querySelector('#tar-tree .tar-tree-nomatch');
  var nodes = tree.querySelectorAll('.tar-tree-node, .tar-tree-leaf');
  if (!active) { nodes.forEach(function(el){ el.style.display = ''; }); if (nomatch) nomatch.style.display = 'none'; return; }
  nodes.forEach(function(el){ el.style.display = 'none'; });
  var shown = 0;
  tree.querySelectorAll('.tar-tree-row').forEach(function(row){
    if (state === 'running' && row.getAttribute('data-state') !== 'running') return;
    if (state === 'exited' && row.getAttribute('data-state') !== 'exited') return;
    if (anomOnly && row.getAttribute('data-anom') !== '1') return;
    if (q && row.textContent.toLowerCase().indexOf(q) === -1) return;
    shown++;
    var el = row.closest('.tar-tree-leaf, .tar-tree-node');
    while (el && tree.contains(el)) {
      el.style.display = '';
      if (el.tagName === 'DETAILS') el.open = true;
      el = el.parentElement ? el.parentElement.closest('.tar-tree-node') : null;
    }
  });
  if (nomatch) nomatch.style.display = shown === 0 ? '' : 'none';
}
// The toolbar persists across tree swaps; re-apply the active filters whenever a new
// tree settles into #tar-tree.
document.body.addEventListener('htmx:afterSettle', function(e) {
  if (e.target && (e.target.id === 'tar-tree' ||
      (e.target.closest && e.target.closest('#tar-tree')))) {
    applyTarTreeFilters();
  }
});
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

// ── Scope-walking SQL frame (Phase 15.D) ─────────────────────────────────
// Drives the scope chip + ad-hoc TAR SQL against the REST result-set API.
// Selecting a scope picks the candidate set; running the query dispatches
// tar.sql to that scope and creates a NEW result set parented at it, then
// polls until the async maintenance thread materialises membership.
(function() {
  var scopeSel  = document.getElementById('tar-sql-scope');
  var scopeMeta = document.getElementById('tar-sql-scope-meta');
  var sqlText   = document.getElementById('tar-sql-text');
  var nameInput = document.getElementById('tar-sql-name');
  var emptyChk  = document.getElementById('tar-sql-include-empty');
  var runBtn    = document.getElementById('tar-sql-run');
  var resultBox = document.getElementById('tar-sql-result');
  var refreshBtn= document.getElementById('tar-sql-refresh-scopes');
  if (!scopeSel || !runBtn) return;

  // id -> {name, device_count, status} for the meta line.
  var scopeIndex = {};

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function(c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c];
    });
  }

  function renderMeta() {
    var v = scopeSel.value;
    if (v === '__all__') { scopeMeta.textContent = 'entire fleet — no parent'; return; }
    var s = scopeIndex[v];
    if (!s) { scopeMeta.textContent = ''; return; }
    var bits = [s.device_count + ' devices'];
    if (s.status && s.status !== 'materialized') bits.push(s.status);
    scopeMeta.textContent = bits.join(' · ');
  }

  function loadScopes() {
    fetch('/api/v1/result-sets?limit=200').then(function(r){return r.json();}).then(function(j){
      var sets = (j.data && j.data.result_sets) || [];
      var keep = scopeSel.value;
      scopeIndex = {};
      while (scopeSel.options.length > 1) scopeSel.remove(1);
      sets.forEach(function(s){
        scopeIndex[s.id] = s;
        var label = (s.name ? s.name : s.id) + ' — ' + s.device_count + ' devices'
                  + (s.status && s.status !== 'materialized' ? ' (' + s.status + ')' : '');
        var opt = document.createElement('option');
        opt.value = s.id; opt.textContent = label;
        scopeSel.appendChild(opt);
      });
      if (keep && (keep === '__all__' || scopeIndex[keep])) scopeSel.value = keep;
      renderMeta();
    }).catch(function(){ /* leave __all__ only */ });
  }

  // Poll a freshly-created pending set until membership materialises.
  function pollSet(id, name, tries) {
    fetch('/api/v1/result-sets/' + encodeURIComponent(id)).then(function(r){return r.json();})
      .then(function(j){
        var s = j.data || {};
        if (s.status === 'pending' && tries > 0) {
          setTimeout(function(){ pollSet(id, name, tries - 1); }, 2000);
          return;
        }
        if (s.status === 'failed') {
          resultBox.className = 'tar-sql-result error';
          resultBox.innerHTML = 'Result set <code>' + esc(id) + '</code> failed to materialise.';
        } else if (s.status === 'pending') {
          resultBox.className = 'tar-sql-result';
          resultBox.innerHTML = 'Result set <code>' + esc(id) + '</code> still pending — '
            + '<a href="/result-sets">view in Result Sets</a>.';
        } else {
          resultBox.className = 'tar-sql-result';
          resultBox.innerHTML = 'Created <code>' + esc(name || id) + '</code> — <strong>'
            + esc(s.device_count) + '</strong> device(s). '
            + 'Copy scope token <code>from_result_set:' + esc(id) + '</code> · '
            + '<a href="/result-sets">open</a>';
          loadScopes();
        }
        runBtn.disabled = false;
      }).catch(function(){ runBtn.disabled = false; });
  }

  function run() {
    var sql = sqlText.value.trim();
    if (!sql) { showToast('Enter a SQL query', 'warning'); return; }
    var body = { sql: sql, include_empty: !!emptyChk.checked };
    var nm = nameInput.value.trim();
    if (nm) body.name = nm;
    if (scopeSel.value && scopeSel.value !== '__all__') body.parent_id = scopeSel.value;
    runBtn.disabled = true;
    resultBox.className = 'tar-sql-result';
    resultBox.textContent = 'Dispatching to agents…';
    fetch('/api/v1/result-sets/from-tar-query', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
    }).then(function(r){ return r.json().then(function(j){ return {status:r.status, body:j}; }); })
      .then(function(res){
        if (res.status === 202 && res.body.data) {
          var s = res.body.data;
          resultBox.innerHTML = 'Dispatched (execution <code>' + esc(s.source_execution_id)
            + '</code>) — awaiting responses…';
          pollSet(s.id, s.name, 150);
        } else {
          var msg = (res.body.error && (res.body.error.message || res.body.error)) || 'request failed';
          resultBox.className = 'tar-sql-result error';
          resultBox.textContent = msg;
          runBtn.disabled = false;
        }
      }).catch(function(){
        resultBox.className = 'tar-sql-result error';
        resultBox.textContent = 'network error';
        runBtn.disabled = false;
      });
  }

  scopeSel.addEventListener('change', renderMeta);
  runBtn.addEventListener('click', run);
  if (refreshBtn) refreshBtn.addEventListener('click', loadScopes);
  loadScopes();
})();
</script>
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
