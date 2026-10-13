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

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kVizHostPageTemplate = R"HTM(<!DOCTYPE html>
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
  <!--yuzu:shell--><!--/yuzu:shell-->

  <!-- Mount root carries agent_id via data-attribute so the renderer can
       read it deterministically without parsing window.location. The
       {{AGENT_ID}} placeholder is replaced by the server-side route
       handler. -->
  <style>
    /* Slice 4 splitter — draggable horizontal divider between the IPC
       graph (top) and TAR tree (bottom). Ratio persists in localStorage
       under yuzuVizHostSplitRatio so an operator's chosen layout sticks
       across page reloads. */
    #viz-host-root { display: flex; flex-direction: column; height: calc(100vh - var(--shell-top-h)); }
    #ipc-graph { flex: 0 0 60%; width: 100%; }
    #tar-tree { flex: 1 1 40%; overflow: auto; }
    #splitter {
      flex: 0 0 6px;
      background: var(--border, #30363d);
      cursor: row-resize;
    }
    #splitter:hover { background: var(--accent, #58a6ff); }
    .yuzu-tar-highlight {
      background: rgba(255, 242, 204, 0.3);
      transition: background 0.5s ease-out;
    }
  </style>
  <div id="viz-host-root" data-agent-id="{{AGENT_ID}}">
    <div class="toolbar" style="padding:6px 12px; display:flex; gap:8px; align-items:center;">
      <strong>Host detail</strong>
      <span style="opacity:0.7; font-size:12px;">{{AGENT_ID}}</span>
      <span style="flex:1"></span>
      <button id="refresh-btn">Refresh</button>
    </div>
    <div id="ipc-graph"></div>
    <div id="splitter"></div>
    <div id="tar-tree"
         hx-get="/fragments/tar/process-tree?device={{AGENT_ID}}"
         hx-trigger="load"></div>
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

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kVizHostPageHtml =
    yuzu::server::shell::bake(kVizHostPageTemplate,
                              {.active_key = "fleet", .title = "Host detail"});
// NOLINTEND(cert-err58-cpp)
