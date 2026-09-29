// Fleet Visualization page (PR 5 of feat/viz-engine ladder).
//
// Compiled in its own TU to keep the long raw string literal away from
// server.cpp brace matching, mirroring tar_page_ui.cpp.
//
// The page hosts a persistent <div id="viz-root"> + <canvas id="viz-canvas">
// + <div id="viz-overlay-panel"> structure. The renderer JS (yuzu-viz.js,
// vendored as kYuzuVizJs) mounts once on first htmx:afterSettle and survives
// subsequent HTMX swaps -- the canvas and the WebGLRenderer it owns must
// not be torn down by HTMX when the overlay panel changes.
//
// Three.js + OrbitControls (PR 4 of the ladder) load via an importmap so
// the OrbitControls module's bare `import ... from 'three'` resolves to
// the vendored bundle. importmap is supported in every browser shipped
// after early 2023; the dashboard already requires modern browsers.
//
// Design: docs/agentic-first-principle.md A1 — the same fleet topology
// data is reachable via REST (/api/v1/viz/fleet/topology), via the HTMX
// fragment (/fragments/viz/fleet/topology), and rendered here. PR 6+ fills
// in cube/process/edge layers; PR 5 shipped the empty-scene scaffold
// (grid only) so WASD/orbit/zoom controls can be validated independently.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kVizFleetPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — Fleet Viz</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>

  <!-- gov R4 UP-16 / ER-SHOULD-1: browser-support detection. Runs as a
       classic (non-module) script BEFORE the importmap and the type=
       "module" loader. On browsers that don't support importmap (Chrome
       <89, Firefox <108, Safari <16.4), the module loader silently fails
       at module-eval time before mount() runs and the operator sees a
       blank canvas with no diagnostic. Detect via the standardised
       `HTMLScriptElement.supports('importmap')` static method (which is
       itself only available on browsers that implement importmap
       support detection -- defensive coding tests for the function
       existence first). On unsupported browsers we set
       `window.__yuzuVizImportmapSupported = false` and surface a
       visible error via the inline parse-time script below. -->
  <script>
    (function () {
      var supported = typeof HTMLScriptElement !== 'undefined' &&
                      typeof HTMLScriptElement.supports === 'function' &&
                      HTMLScriptElement.supports('importmap');
      window.__yuzuVizImportmapSupported = !!supported;
    })();
  </script>

  <!-- Three.js r168 + OrbitControls (vendored, MIT). The OrbitControls
       module imports `from 'three'` -- the importmap below resolves the
       bare specifier to the vendored bundle so the runtime never tries
       to fetch from a CDN. importmap MUST be parsed before any
       `<script type="module">` tag (HTML spec); the loader at the end
       of <body> is the only such tag in this page. -->
  <script type="importmap">
  {
    "imports": {
      "three": "/static/three.module.min.js",
      "three/addons/controls/OrbitControls.js": "/static/three-orbit-controls.js"
    }
  }
  </script>

  <style>
    body { display: flex; flex-direction: column; min-height: 100vh; margin: 0; }
    .viz-content {
      flex: 1;
      width: 100%;
      box-sizing: border-box;
      position: relative;
      overflow: hidden;
    }
    /* viz-root must survive HTMX swaps — only inner panels swap. The
       canvas and the WebGLRenderer it owns persist across navigation
       within the page so we don't lose GPU context on every overlay. */
    #viz-root {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      background: var(--bg);
    }
    #viz-canvas {
      display: block;
      width: 100%;
      height: 100%;
      outline: none;
    }
    /* Overlay panel: floating side panel for click-to-drill-in detail
       (PR 10 wires CVE list here). Initially empty; PR 6+ may add status
       chrome (machine count, generated-at timestamp, stale indicator). */
    #viz-overlay-panel {
      position: absolute;
      top: 1rem;
      right: 1rem;
      max-width: 360px;
      max-height: calc(100vh - 8rem);
      overflow: auto;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.75rem 1rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      pointer-events: auto;
      z-index: 5;
      font-size: 0.85rem;
    }
    #viz-overlay-panel:empty { display: none; }
    /* HUD — fixed footer hint with control summary, dim by default. */
    #viz-hud {
      position: absolute;
      bottom: 0.75rem;
      left: 0.75rem;
      font-size: 0.75rem;
      color: var(--mds-color-theme-text-tertiary);
      background: rgba(0, 0, 0, 0.4);
      padding: 0.35rem 0.6rem;
      border-radius: 0.25rem;
      pointer-events: none;
      z-index: 4;
    }
    #viz-hud kbd {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.2rem;
      padding: 0 0.3rem;
      font-family: var(--mds-font-family-default);
      font-size: 0.7rem;
    }
    #viz-error {
      position: absolute;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      color: var(--mds-color-theme-indicator-error);
      background: var(--bg);
      font-size: 0.95rem;
      z-index: 10;
      padding: 1rem;
      text-align: center;
    }
    #viz-error.shown { display: flex; }
  </style>
</head>
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
    <a href="/tar" class="nav-link">TAR</a>
    <a href="/hardware" class="nav-link">Hardware</a>
    <a href="/software" class="nav-link">Software</a>
    <a href="/viz/fleet" class="nav-link active">Fleet Viz</a>
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

  <div class="viz-content">
    <!-- The data-yuzu-viz-url attribute is the load contract: yuzu-viz.js
         locates this element on htmx:afterSettle / DOMContentLoaded and
         mounts the renderer once. The URL points at the JSON endpoint
         (PR 6+ adapter fetches it on demand). -->
    <div id="viz-root" data-yuzu-viz-url="/api/v1/viz/fleet/topology">
      <canvas id="viz-canvas" tabindex="0"
              aria-label="Fleet topology 3D view"></canvas>
      <div id="viz-overlay-panel"></div>
      <div id="viz-hud">
        <kbd>W</kbd> <kbd>A</kbd> <kbd>S</kbd> <kbd>D</kbd> pan &nbsp;·&nbsp;
        <kbd>drag</kbd> rotate &nbsp;·&nbsp;
        <kbd>wheel</kbd> zoom
      </div>
      <div id="viz-error" role="alert"></div>
    </div>
  </div>

  <div id="toast-container" class="toast-container"></div>

<script>
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
// gov R4 UP-16 / ER-SHOULD-1: surface importmap-not-supported as a
// visible #viz-error message rather than letting the page sit blank.
// This script is parsed in body order, AFTER the #viz-error <div>, so
// document.getElementById finds it without waiting for DOMContentLoaded.
// The detection itself ran inline in <head> and stamped
// window.__yuzuVizImportmapSupported. Future refactors that move this
// script into <head> MUST wrap the body in a DOMContentLoaded listener
// so #viz-error exists when the lookup runs.
if (!window.__yuzuVizImportmapSupported) {
  var err = document.getElementById('viz-error');
  if (err) {
    err.textContent =
      'Fleet visualization requires a modern browser (Chrome 89+, ' +
      'Firefox 108+, or Safari 16.4+). The page cannot render in this browser.';
    err.classList.add('shown');
  }
}
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
</script>

<!-- yuzu-viz.js loads as type="module" so it can `import * as THREE from
     'three'` and resolve via the importmap above. -->
<script type="module" src="/static/yuzu-viz.js"></script>

</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
