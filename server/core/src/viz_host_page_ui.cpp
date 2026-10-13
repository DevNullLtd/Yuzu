// Per-host fleet visualization page shell (PR 9-pre).
//
// Companion to viz_page_ui.cpp — the latter renders /viz/fleet (the 3D
// fleet view); this TU renders /viz/host/<agent_id> (the per-host drill-down
// page that the 3D cube's dblclick opens in a new tab).
//
// Two-pane page: the 2D IPC graph (Cytoscape) on top, the existing TAR
// process-tree fragment on the bottom. The page reads the agent_id from
// `data-agent-id` on the mount root; yuzu-viz-host.js (slice 2) fetches
// /api/v1/viz/host/<agent_id>/topology and renders the bipartite graph.
//
// The `{{AGENT_ID}}` token is replaced by the page-route handler at request
// time so the JS bundle can read the requested agent_id without an extra
// fetch round-trip. (Server-side templating is intentional — we do not
// trust client URL parsing to align with what the server matched.)

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kVizHostPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — Host detail</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>

  <!-- Cytoscape ESM bundle resolved via importmap. Importmap MUST be
       parsed before any <script type="module"> that imports a bare
       specifier — HTML spec. The renderer uses cytoscape's built-in
       `cose` layout, so no layout-extension <script> is needed. -->
  <script type="importmap">
  {
    "imports": {
      "cytoscape": "/static/cytoscape.min.js"
    }
  }
  </script>
</head>
<body>
  <nav class="nav-bar">
    <a href="/" class="nav-brand">Yuzu</a>
    <a href="/" class="nav-link">Dashboard</a>
    <a href="/guardian" class="nav-link">Guardian</a>
    <a href="/dex" class="nav-link">DEX</a>
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
  </nav>

  <style>
    body { display: flex; flex-direction: column; height: 100vh; margin: 0; }
    /* Page body: title block (.page-header from yuzu.css), toolbar, then the
       graph and TAR panes. The long sentence needs more than the 70ch default. */
    .vh-body {
      flex: 1;
      min-height: 0;
      display: flex;
      flex-direction: column;
      gap: 22px;
      padding: 22px 28px 28px;
    }
    .vh-body .subtitle { max-width: 100ch; }
    .vh-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
    /* Each pane is a bordered panel: a header row (.vh-hd) over a body
       (#ipc-graph / #tar-tree) that carries the side and bottom borders.
       The headers sit beside the panes, never inside them, because
       Cytoscape owns #ipc-graph's children and htmx swaps #tar-tree's. */
    .vh-hd {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 14px;
      padding: 12px 16px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--rad-panel) var(--rad-panel) 0 0;
    }
    .vh-hd h2 { font-size: 14px; font-weight: 600; }
    .vh-sub { color: var(--mut); font-size: 13px; }
    .vh-legend {
      margin-left: auto;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 16px;
      font-size: 13px;
      color: var(--mut);
    }
    .vh-legend i { display: inline-block; vertical-align: -1px; margin-right: 6px; }
    .vh-sw { width: 10px; height: 10px; }
    .vh-sw.proc { background: var(--c1); border-radius: 50%; }
    .vh-sw.sock { background: var(--c3); border-radius: 2px; }
    .vh-sw.owns { width: 14px; height: 0; border-top: 1px dashed var(--faint); }
    .vh-sw.conn { width: 14px; height: 0; border-top: 2px solid var(--c2); }
    .vh-main { flex: 1; display: flex; flex-direction: column; min-height: 520px; }
    #viz-host-root { display: flex; flex-direction: column; flex: 1; min-height: 0; }
    #ipc-graph, #tar-tree {
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--line);
      border-top: 0;
      border-radius: 0 0 var(--rad-panel) var(--rad-panel);
    }
    #ipc-graph { flex: 0 0 60%; }
    #tar-tree { flex: 1 1 40%; overflow: auto; padding: 16px; }
    .vh-error { padding: 16px; color: var(--ink2); }
    .vh-stale {
      padding: 8px 16px;
      font-size: 13px;
      color: var(--warn);
      background: color-mix(in srgb, var(--warn) 12%, var(--surface));
      border: 1px solid var(--line);
      border-width: 0 1px 1px;
    }
    /* Splitter — draggable horizontal divider between the IPC graph (top)
       and TAR tree (bottom). Ratio persists in localStorage under
       yuzuVizHostSplitRatio so an operator's chosen layout sticks across
       page reloads. */
    #splitter { flex: 0 0 22px; position: relative; cursor: row-resize; }
    #splitter::after {
      content: "";
      position: absolute;
      left: 50%;
      top: 50%;
      width: 36px;
      height: 3px;
      margin: -1px 0 0 -18px;
      border-radius: 2px;
      background: var(--line2);
      transition: background 0.12s;
    }
    #splitter:hover::after { background: var(--primary); }
    .yuzu-tar-highlight {
      background: color-mix(in srgb, var(--hl) 14%, transparent);
      transition: background 0.12s;
    }
  </style>
  <div class="vh-body">
    <header class="page-header">
      <div>
        <h1>Host map</h1>
        <div class="subtitle">{{AGENT_ID}}: processes, their sockets, and what connects to what.</div>
      </div>
    </header>
    <div class="vh-toolbar">
      <button id="refresh-btn" class="btn btn-secondary">Refresh</button>
    </div>
    <div class="vh-main">
      <div class="vh-hd">
        <h2>Process connections</h2>
        <span class="vh-sub">{{AGENT_ID}}, force-directed layout</span>
        <div class="vh-legend">
          <span><i class="vh-sw proc"></i>Process</span>
          <span><i class="vh-sw sock"></i>Socket</span>
          <span><i class="vh-sw owns"></i>Owns</span>
          <span><i class="vh-sw conn"></i>Connection</span>
        </div>
      </div>
      <!-- Mount root carries agent_id via data-attribute so the renderer can
           read it deterministically without parsing window.location. The
           {{AGENT_ID}} placeholder is replaced by the server-side route
           handler. -->
      <div id="viz-host-root" data-agent-id="{{AGENT_ID}}">
        <div id="ipc-graph"></div>
        <div id="splitter"></div>
        <div class="vh-hd">
          <h2>Process tree</h2>
          <span class="vh-sub">From TAR, for this host</span>
        </div>
        <div id="tar-tree"
             hx-get="/fragments/tar/process-tree?device={{AGENT_ID}}"
             hx-trigger="load"></div>
      </div>
    </div>
  </div>

  <script>
    // Slice 4: receiver for the IPC graph's "yuzu:select-process" event.
    // Find the TAR tree's <details data-pid="N"> matching the broadcasted
    // pid, scroll into view, and add a transient highlight class. One-way
    // (IPC graph → TAR tree). Reverse direction is post-v1.
    document.body.addEventListener("yuzu:select-process", (evt) => {
      const pid = evt && evt.detail && evt.detail.pid;
      if (pid == null) return;
      const tarTree = document.getElementById("tar-tree");
      if (!tarTree) return;
      const el = tarTree.querySelector('[data-pid="' + String(pid) + '"]');
      if (!el) return;
      el.scrollIntoView({ block: "center" });
      el.classList.add("yuzu-tar-highlight");
      setTimeout(() => el.classList.remove("yuzu-tar-highlight"), 2000);
    });

    // Slice 4: resizable splitter. Drag the divider to change the
    // top/bottom ratio; persist in localStorage so the next visit
    // honours the operator's preference. Default 60/40 (matches
    // grilling decision Q11).
    (function wireSplitter() {
      const root = document.getElementById("viz-host-root");
      const splitter = document.getElementById("splitter");
      const top = document.getElementById("ipc-graph");
      const bottom = document.getElementById("tar-tree");
      if (!root || !splitter || !top || !bottom) return;
      const KEY = "yuzuVizHostSplitRatio";
      let ratio = parseFloat(localStorage.getItem(KEY));
      if (!Number.isFinite(ratio) || ratio < 0.1 || ratio > 0.9) ratio = 0.6;
      function apply(r) {
        top.style.flex = "0 0 " + (r * 100) + "%";
        bottom.style.flex = "1 1 " + ((1 - r) * 100) + "%";
      }
      apply(ratio);
      let dragging = false;
      splitter.addEventListener("mousedown", () => { dragging = true; });
      window.addEventListener("mouseup", () => {
        if (dragging) localStorage.setItem(KEY, String(ratio));
        dragging = false;
      });
      window.addEventListener("mousemove", (e) => {
        if (!dragging) return;
        const rect = root.getBoundingClientRect();
        const r = (e.clientY - rect.top) / rect.height;
        if (r > 0.1 && r < 0.9) { ratio = r; apply(r); }
      });
    })();
  </script>

  <script type="module" src="/static/yuzu-viz-host.js"></script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
