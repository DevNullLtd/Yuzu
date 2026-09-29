// Instruction management page with YAML authoring UI.
// HTMX-driven with split-panel editor: textarea (left) + server-rendered
// syntax-highlighted preview (right). The authoring panel (New/Edit) is
// only shown to users with the PlatformEngineer or Administrator role.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kInstructionPageHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Instructions</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
<style>
body{padding:0}
a{color:var(--accent)}h1{border-bottom:1px solid var(--border);padding-bottom:.5rem}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}
.tab{padding:.4rem 1rem;cursor:pointer;border:1px solid transparent;border-radius:6px 6px 0 0;color:var(--muted)}
.tab.active,.tab:hover{color:var(--fg);border-color:var(--border);background:var(--surface)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--border);font-size:.8rem}
th{color:var(--muted);font-weight:600}
.empty-state{color:var(--muted);text-align:center;padding:2rem}
.status-badge{display:inline-block;padding:.1rem .5rem;border-radius:1rem;font-size:.7rem;font-weight:600}
.status-pending{background:var(--yellow);color: var(--mds-color-theme-background-canvas)}
.status-running{background:var(--mds-color-theme-accent-primary-active);color:var(--mds-color-text-on-accent)}
.status-completed{background:var(--green);color:var(--mds-color-text-on-accent)}
/* PR 3 hardening (ca-PR3-7): per-agent renderer + SSE swap canonicalised
   on DOM vocabulary status-{succeeded,failed,running,pending}. .status-succeeded
   is the canonical agent/exec success class going forward; .status-completed
   stays for backwards-compat on existing fragments. */
.status-succeeded{background:var(--green);color:var(--mds-color-text-on-accent)}
.status-cancelled{background:var(--subtle);color:var(--mds-color-text-on-accent)}
.status-failed{background:var(--red);color:var(--mds-color-text-on-accent)}
.status-approved{background:var(--green);color:var(--mds-color-text-on-accent)}
.status-rejected{background:var(--red);color:var(--mds-color-text-on-accent)}
/* Instruction-page button overrides (smaller, denser) */
.btn{height:auto;padding:.3rem .8rem;font-size:.75rem;margin-right:.3rem}
.btn-primary{background:var(--green);color:var(--mds-color-text-on-accent)}
.btn-secondary{background:var(--surface);color:var(--fg);border:1px solid var(--border)}
.btn-danger{background:var(--red);color:var(--mds-color-text-on-accent)}
.btn-sm{padding:.2rem .5rem;font-size:.7rem}
.progress-bar{width:80px;height:8px;background:var(--border);border-radius:4px;display:inline-block;vertical-align:middle}
.progress-fill{height:100%;background:var(--green);border-radius:4px}
code{background:var(--surface);padding:.1rem .3rem;border-radius:4px;font-size:.75rem}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem}
.role-badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.65rem;
  font-weight:600;background:var(--mds-color-theme-accent-primary-active);color:var(--mds-color-text-on-accent);margin-left:.5rem;vertical-align:middle}
/* Editor panel */
.editor-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem;display:none}
.editor-panel.active{display:block}
.editor-tabs{display:flex;gap:.3rem;margin-bottom:1rem}
.editor-tab{padding:.3rem .8rem;cursor:pointer;border:1px solid var(--border);border-radius:4px;
  font-size:.75rem;color:var(--muted);background:transparent}
.editor-tab.active{color:var(--fg);background:var(--border)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
.form-group{display:flex;flex-direction:column;gap:.2rem}
.form-group.full{grid-column:1/-1}
label{font-size:.75rem;color:var(--muted);font-weight:600}
input,select,textarea{background:var(--bg);border:1px solid var(--border);border-radius:4px;
  padding:.4rem .6rem;color:var(--fg);font-size:.8rem;font-family:inherit}
textarea{font-family:var(--font-mono);min-height:300px;resize:vertical;tab-size:2}
input:focus,select:focus,textarea:focus{border-color:var(--accent);outline:none}
/* Syntax token colors — GitHub-dark-inspired */
.yk{color: var(--mds-color-indicator-info-bright)}                     /* YAML key */
.yv{color:var(--mds-color-indicator-info-bright)} /* YAML string value */
.yc{color: var(--mds-color-theme-text-tertiary);font-style:italic}   /* comment */
.ya{color: var(--mds-color-indicator-special)}                     /* apiVersion / kind (schema keywords) */
.yt-q{color: var(--mds-color-indicator-success-bright)}                   /* type: question — green (safe, read-only) */
.yt-a{color: var(--mds-color-indicator-attention);font-weight:700}   /* type: action — orange bold (privileged, modifying) */
.yap{color: var(--mds-color-indicator-error-bright);font-weight:700}    /* approval: always — red bold (requires sign-off) */
.yap-auto{color: var(--mds-color-indicator-success-bright)}              /* approval: auto — green (no gate) */
.ycc{color: var(--mds-color-theme-indicator-warning)}                    /* concurrency mode — amber */
.yn{color: var(--mds-color-indicator-info-bright)}                     /* numeric values */
.yb{color: var(--mds-color-indicator-error-bright)}                     /* boolean values */
.yd{color: var(--mds-color-theme-text-tertiary)}                     /* dashes (list markers) */
/* Legend */
.yaml-legend{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:.5rem;font-size:.7rem}
.yaml-legend span{display:flex;align-items:center;gap:.3rem}
.yaml-legend .swatch{width:10px;height:10px;border-radius:2px;display:inline-block}
.form-actions{margin-top:1rem;display:flex;gap:.5rem}
/* alert overrides (shared .alert base from yuzu.css, page-specific padding) */
.alert{padding:.5rem 1rem;font-size:.8rem;margin-bottom:.8rem}
.legacy-badge{font-size:.65rem;background:var(--mds-color-theme-outline-secondary);color:var(--mds-color-text-on-accent);padding:.05rem .4rem;border-radius:3px}
/* Executions tab — clickable rows + per-execution detail drawer.
   Information-design conventions:
     - Status as hue + icon + row stripe (two channels for colorblind safety).
     - Sparkbar widths = counts (length channel); hue = status (hue channel).
     - KPI strip carries the headline; tables carry the long tail.
     - Agent grid is small-multiples; one cell per agent, color by status. */
.exec-table{width:100%}
.exec-row{cursor:pointer}
.exec-row:hover{background:var(--mds-color-state-hover)}
.exec-row.expanded{background:var(--mds-color-state-selected)}
.exec-row--failed>td:first-child{box-shadow:inset 3px 0 0 var(--mds-color-theme-indicator-error)}
.exec-row--running>td:first-child{box-shadow:inset 3px 0 0 var(--mds-color-theme-indicator-stable)}
.exec-row:focus{outline:2px solid var(--accent);outline-offset:-2px}
.exec-def-name{font-weight:600}
.exec-agent-count{font-size:.7rem;color:var(--muted);white-space:nowrap}
.exec-error-preview{font-family:var(--font-mono);font-size:.7rem;color:var(--mds-color-theme-indicator-error);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.exec-time{font-size:.7rem;color:var(--muted);white-space:nowrap}
.status-sparkbar{display:block}
.exec-detail{display:none}
.exec-detail.open{display:table-row}
.exec-detail>td{padding:1rem!important;background:var(--mds-color-theme-bg-secondary,var(--bg))}
.exec-detail-grid{display:grid;gap:1rem;grid-template-columns:1fr minmax(220px,320px)}
@media (max-width:900px){.exec-detail-grid{grid-template-columns:1fr}}
.exec-detail-grid h4{margin:0 0 .3rem 0;font-size:.7rem;color:var(--mds-color-theme-text-tertiary);text-transform:uppercase;letter-spacing:.05em}
.exec-kpi-strip{display:flex;flex-wrap:wrap;gap:1.5rem;grid-column:1/-1;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.exec-kpi{min-width:7rem}
.exec-kpi-value{font-size:1.5rem;font-weight:600;line-height:1.1}
.exec-kpi-value--ok{color:var(--green)}
.exec-kpi-value--err{color:var(--red)}
.exec-kpi-label{font-size:.65rem;color:var(--mds-color-theme-text-tertiary);text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
.agent-grid-wrap{grid-column:1/-1}
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,12px);gap:2px;max-height:200px;overflow-y:auto}
.agent-cell{width:12px;height:12px;border-radius:2px;cursor:pointer}
.agent-cell--bucket{width:auto;height:18px;display:flex;align-items:center;justify-content:center;font-size:.65rem;color:var(--mds-color-text-on-accent);padding:0 .3rem;border-radius:3px}
.agent-cell--succeeded{background:var(--mds-color-bg-success-emphasis,var(--green))}
.agent-cell--failed{background:var(--mds-color-theme-indicator-error,var(--red))}
.agent-cell--running{background:var(--mds-color-theme-indicator-stable,var(--accent))}
.agent-cell--pending{background:var(--mds-color-theme-text-tertiary,var(--muted));opacity:.4}
.per-agent-table-wrap{grid-column:1}
.per-agent-table{font-size:.75rem}
.per-agent-table td{vertical-align:middle}
.duration-bar{height:6px;border-radius:3px;display:inline-block;vertical-align:middle;min-width:1px}
.duration-bar--succeeded{background:var(--mds-color-bg-success-emphasis,var(--green))}
.duration-bar--failed{background:var(--mds-color-theme-indicator-error,var(--red))}
.duration-bar--running{background:var(--mds-color-theme-indicator-stable,var(--accent))}
.duration-bar--pending{background:var(--mds-color-theme-text-tertiary,var(--muted));opacity:.4}
.duration-text{font-size:.65rem;color:var(--muted);margin-left:.3rem}
.per-agent-row-highlight{background:var(--mds-color-state-selected)!important;transition:background .3s}
.per-agent-responses-wrap{grid-column:1}
.per-agent-responses summary{cursor:pointer;font-size:.75rem;color:var(--muted);padding:.3rem 0}
.per-agent-responses-table{font-size:.7rem}
.resp-output pre{margin:.3rem 0;padding:.3rem;background:var(--bg);border-radius:3px;max-height:200px;overflow:auto;white-space:pre-wrap}
.exec-detail-sidebar{grid-column:2;font-size:.75rem}
@media (max-width:900px){.exec-detail-sidebar{grid-column:1}}
.exec-detail-sidebar>div{margin-bottom:.5rem}
.exec-detail-meta-id{font-family:var(--font-mono);font-size:.65rem;color:var(--muted)}
.exec-detail-scope,.exec-detail-params{display:block;font-size:.7rem;background:var(--bg);padding:.3rem;border-radius:3px;white-space:pre-wrap;word-break:break-all}
</style>
</head><body>

<nav class="nav-bar">
  <a href="/" class="nav-brand">
    <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
  </a>
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/instructions" class="nav-link active">Instructions</a>
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

<div style="padding:2rem">
<h1>Instructions</h1>
<div class="tabs">
    <div class="tab active" onclick="showTab('definitions',this)">Definitions</div>
    <div class="tab" onclick="showTab('executions',this)">Executions</div>
    <div class="tab" onclick="showTab('schedules',this)">Schedules</div>
    <div class="tab" onclick="showTab('approvals',this)">Approvals</div>
</div>

<div id="tab-definitions" hx-get="/fragments/instructions" hx-trigger="load" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-executions" style="display:none">
    <!-- Execute form — pick instruction, set params, choose scope, dispatch -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1.5rem">
      <h3 style="margin:0 0 .8rem 0;font-size:.9rem;border:none;padding:0">Execute Instruction</h3>
      <div style="display:grid;grid-template-columns:1fr 260px;gap:1.2rem">
        <div>
          <div class="form-group" style="margin-bottom:.8rem">
            <label>Instruction Definition</label>
            <select id="exec-def-select" style="width:100%"
                    onchange="onDefSelected(this.value)">
              <option value="">— Select an instruction —</option>
            </select>
          </div>
          <div id="exec-def-info" style="display:none;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.8rem;margin-bottom:.8rem">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem">
              <strong id="exec-def-name" style="font-size:.85rem"></strong>
              <code id="exec-def-id" style="font-size:.6rem;color:var(--muted)"></code>
            </div>
            <div id="exec-def-desc" style="font-size:.75rem;color:var(--muted);margin-bottom:.3rem"></div>
            <div style="display:flex;gap:1rem;font-size:.7rem">
              <span>Plugin: <code id="exec-def-plugin"></code></span>
              <span>Action: <code id="exec-def-action"></code></span>
              <span>Type: <code id="exec-def-type"></code></span>
            </div>
          </div>
          <div id="exec-params-area" style="display:none;margin-bottom:.8rem">
            <label>Parameters</label>
            <div id="exec-params-fields" class="form-grid" style="margin-top:.3rem"></div>
          </div>
          <div>
            <button class="btn btn-primary" onclick="executeInstruction()" id="exec-btn" disabled>
              Execute
            </button>
            <span id="exec-status" style="font-size:.75rem;color:var(--muted);margin-left:.8rem"></span>
          </div>
          <div id="exec-result" style="margin-top:.5rem"></div>
        </div>
        <div>
          <label>Scope</label>
          <select id="exec-scope" style="width:100%;margin-top:.3rem;margin-bottom:.5rem">
            <option value="__all__">All agents</option>
          </select>
          <div id="exec-agent-list" style="max-height:300px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;font-size:.7rem">
          </div>
        </div>
      </div>
    </div>
    <!-- Execution history — loaded via HTMX fragment -->
    <h3 style="font-size:.9rem;margin-bottom:.5rem;border:none;padding:0">Execution History</h3>
    <div id="exec-history" hx-get="/fragments/executions" hx-trigger="revealed" hx-swap="innerHTML">
      <div class="empty-state">Loading...</div>
    </div>
</div>
<div id="tab-schedules" style="display:none" hx-get="/fragments/schedules" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-approvals" style="display:none" hx-get="/fragments/approvals" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>

<!-- YAML Authoring Panel — rendered by /fragments/instructions/editor -->
<div id="editor-host"></div>

</div><!-- /padding wrapper -->

<div id="toast-container" class="toast-container"></div>
)HTM"
    // Part 2: JavaScript (split to stay under MSVC's 16380-byte string limit)
    R"HTM(
<script>
/* ── Wall-clock time formatter (UAT 2026-05-06 #9) ───────────────────────
   Server emits `data-epoch-ms="<ms>"` on every cell that previously showed
   a relative "Ns ago" timestamp. We format here in the operator's local
   timezone so an operator in EST and one in BST each see their own
   wall clock. Format: `HH:MM:SS.mmm <TZ>` (e.g. `12:22:33.251 BST`). The
   server keeps a UTC fallback in the cell text and the full ISO-8601
   timestamp in the `title` attribute for cross-day hover correlation.

   Idempotent — safe to call multiple times on the same node. Targeted
   from DOMContentLoaded and from htmx:afterSwap so HTMX-injected fragments
   pick up the same treatment. */
function formatLocalTime(epochMs) {
  if (!Number.isFinite(epochMs) || epochMs <= 0) return '';
  var d = new Date(epochMs);
  var hh = String(d.getHours()).padStart(2, '0');
  var mm = String(d.getMinutes()).padStart(2, '0');
  var ss = String(d.getSeconds()).padStart(2, '0');
  var ms = String(d.getMilliseconds()).padStart(3, '0');
  var tz = '';
  try {
    var parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
                  .formatToParts(d);
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].type === 'timeZoneName') { tz = parts[i].value; break; }
    }
  } catch (e) { /* fallback: omit TZ */ }
  return tz ? (hh + ':' + mm + ':' + ss + '.' + ms + ' ' + tz)
            :  hh + ':' + mm + ':' + ss + '.' + ms;
}
function renderLocalTimes(root) {
  var scope = root || document;
  var nodes = scope.querySelectorAll('[data-epoch-ms]');
  for (var i = 0; i < nodes.length; i++) {
    var el = nodes[i];
    var ms = parseInt(el.getAttribute('data-epoch-ms'), 10);
    var text = formatLocalTime(ms);
    if (text) el.textContent = text;
  }
}
document.addEventListener('DOMContentLoaded', function() { renderLocalTimes(); });
document.body.addEventListener('htmx:afterSwap', function(e) {
  renderLocalTimes(e && e.detail && e.detail.target ? e.detail.target : null);
});

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

function showTab(name, el) {
    document.querySelectorAll('[id^="tab-"]').forEach(d => d.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).style.display = 'block';
    el.classList.add('active');
}
function openEditor(defId) {
    var url = defId ? '/fragments/instructions/editor?id=' + defId : '/fragments/instructions/editor';
    htmx.ajax('GET', url, {target:'#editor-host', swap:'innerHTML'}).then(function(){
        setTimeout(function() {
            initScrollSync();
            /* Trigger initial preview render for existing YAML */
            var ta = document.getElementById('yaml-editor');
            if (ta && ta.value.trim()) {
                htmx.trigger(ta, 'keyup');
            }
        }, 50);
    });
}
function closeEditor() {
    document.getElementById('editor-host').innerHTML = '';
}
function switchEditorMode(mode, el) {
    document.querySelectorAll('.editor-tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('form-mode').style.display = mode === 'form' ? 'block' : 'none';
    document.getElementById('yaml-mode').style.display = mode === 'yaml' ? 'block' : 'none';
}
/* Scroll sync between textarea and preview panel */
function initScrollSync() {
    var ta = document.getElementById('yaml-editor');
    var preview = document.getElementById('yaml-preview');
    if (ta && preview) {
        ta.addEventListener('scroll', function() {
            preview.scrollTop = ta.scrollTop;
        });
    }
}

/* ── Populate nav bar + context bar ─────────────────────── */
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
loadExecDefinitions();
loadExecAgents();

/* ── Execute tab ──────────────────────────────────────────── */
var execDefs = [];
var selectedDef = null;

function loadExecDefinitions() {
  fetch('/api/instructions?enabled_only=1&limit=500')
    .then(function(r){return r.json()})
    .then(function(data) {
      execDefs = data.definitions || [];
      var sel = document.getElementById('exec-def-select');
      if (!sel) return;
      sel.innerHTML = '<option value="">— Select an instruction —</option>';
      var byPlugin = {};
      execDefs.forEach(function(d) {
        var p = d.plugin || 'other';
        if (!byPlugin[p]) byPlugin[p] = [];
        byPlugin[p].push(d);
      });
      Object.keys(byPlugin).sort().forEach(function(p) {
        var og = document.createElement('optgroup');
        og.label = p;
        byPlugin[p].forEach(function(d) {
          var o = document.createElement('option');
          o.value = d.id;
          o.textContent = d.name || (d.plugin + ' ' + d.action);
          og.appendChild(o);
        });
        sel.appendChild(og);
      });
    });
}

function onDefSelected(defId) {
  selectedDef = null;
  var info = document.getElementById('exec-def-info');
  var paramsArea = document.getElementById('exec-params-area');
  var btn = document.getElementById('exec-btn');

  if (!defId) {
    info.style.display = 'none';
    paramsArea.style.display = 'none';
    btn.disabled = true;
    return;
  }

  selectedDef = execDefs.find(function(d){return d.id === defId});
  if (!selectedDef) return;

  document.getElementById('exec-def-name').textContent = selectedDef.name || '';
  document.getElementById('exec-def-id').textContent = selectedDef.id;
  document.getElementById('exec-def-desc').textContent = selectedDef.description || '';
  document.getElementById('exec-def-plugin').textContent = selectedDef.plugin || '';
  document.getElementById('exec-def-action').textContent = selectedDef.action || '';
  document.getElementById('exec-def-type').textContent = selectedDef.type || '';
  info.style.display = 'block';
  btn.disabled = false;

  var fields = document.getElementById('exec-params-fields');
  fields.innerHTML = '';
  try {
    var schema = typeof selectedDef.parameter_schema === 'string'
      ? JSON.parse(selectedDef.parameter_schema || '{}')
      : (selectedDef.parameter_schema || {});
    var props = schema.properties || {};
    var required = schema.required || [];
    var keys = Object.keys(props);
    if (keys.length > 0) {
      paramsArea.style.display = 'block';
      keys.forEach(function(k) {
        var p = props[k];
        var div = document.createElement('div');
        div.className = 'form-group';
        var lbl = document.createElement('label');
        lbl.textContent = k + (required.indexOf(k) >= 0 ? ' *' : '');
        var inp = document.createElement('input');
        inp.name = 'param_' + k;
        inp.placeholder = p.description || p.type || '';
        if (p.default !== undefined) inp.value = p.default;
        div.appendChild(lbl);
        div.appendChild(inp);
        fields.appendChild(div);
      });
    } else {
      paramsArea.style.display = 'none';
    }
  } catch(e) {
    paramsArea.style.display = 'none';
  }
}
)HTM"
    // Part 3: Execute + form-to-YAML JavaScript
    //
    // The "All agents" option sends scope='__all__', NOT an empty string. Empty
    // meant "broadcast" only by falling through the dispatch sink's untargeted
    // default; #2500 made a SUPPLIED-but-empty scope a 400, because a caller
    // whose scope resolved to nothing and one who meant the whole fleet must not
    // look identical on the wire. `__all__` is what /discover/scope-kinds and
    // the MCP execute_instruction schema both advertise, so the dialog now sends
    // what its own <option> value has always said.
    //
    // KEEP PROSE OUT OF THE LITERAL BELOW. MSVC caps a single string literal at
    // 16 KiB (C2026) and this one runs at ~16.2 KiB. GCC and Clang have no such
    // cap, so an over-long comment inside the JS compiles clean on Linux and
    // macOS and breaks ONLY the Windows leg - which is exactly how it broke on
    // the first push of this change. Explain here; keep the JS terse. If this
    // part needs to grow, split it into another adjacent chunk (the compiler
    // concatenates them) rather than trimming comments to buy room.
    R"HTM(
function executeInstruction() {
  if (!selectedDef) return;
  var btn = document.getElementById('exec-btn');
  var status = document.getElementById('exec-status');
  btn.disabled = true;
  status.textContent = 'Dispatching...';

  var params = {};
  var fields = document.querySelectorAll('#exec-params-fields input');
  fields.forEach(function(inp) {
    var key = inp.name.replace('param_', '');
    if (inp.value.trim()) params[key] = inp.value.trim();
  });

  var scope = document.getElementById('exec-scope').value;

  var body = {params: params};
  if (scope === '__all__') {
    body.scope = '__all__'; // #2500 - rationale in the C++ comment above
  } else if (scope.startsWith('group:')) {
    body.scope = scope;
  } else {
    body.agent_ids = [scope];
  }

  fetch('/api/instructions/' + encodeURIComponent(selectedDef.id) + '/execute', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  })
  .then(function(r){return r.json().then(function(d){return {status:r.status,data:d}})})
  .then(function(resp) {
    btn.disabled = false;
    if (resp.status >= 400) {
      status.textContent = '';
      var msg = resp.data.error ? (resp.data.error.message || String(resp.data.error)) : 'Failed';
      var errDiv = document.createElement('div');
      errDiv.className = 'alert alert-error';
      errDiv.textContent = msg;
      var er = document.getElementById('exec-result');
      er.innerHTML = '';
      er.appendChild(errDiv);
    } else {
      status.textContent = 'Dispatched to ' + (resp.data.agents_reached || 0) + ' agent(s)';
      var okDiv = document.createElement('div');
      okDiv.className = 'alert alert-success';
      var cmdCode = document.createElement('code');
      cmdCode.textContent = resp.data.command_id || '';
      okDiv.appendChild(document.createTextNode('Command '));
      okDiv.appendChild(cmdCode);
      okDiv.appendChild(document.createTextNode(' dispatched to ' + (resp.data.agents_reached || 0) + ' agent(s)'));
      var er2 = document.getElementById('exec-result');
      er2.innerHTML = '';
      er2.appendChild(okDiv);
    }
  })
  .catch(function(e) {
    btn.disabled = false;
    status.textContent = 'Error: ' + e.message;
  });
}

function loadExecAgents() {
  fetch('/api/agents')
    .then(function(r){return r.json()})
    .then(function(data) {
      var sel = document.getElementById('exec-scope');
      var list = document.getElementById('exec-agent-list');
      if (!sel || !list) return;
      sel.innerHTML = '<option value="__all__">All agents</option>';
      var agents = data.agents || [];
      agents.forEach(function(a) {
        var o = document.createElement('option');
        o.value = a.agent_id || a.id;
        o.textContent = (a.hostname || a.agent_id || a.id) + ' (' + (a.os || '?') + ')';
        sel.appendChild(o);
      });
      list.innerHTML = '';
      agents.forEach(function(a) {
        var row = document.createElement('div');
        row.style.cssText = 'padding:.3rem .5rem;border-bottom:1px solid var(--border)';
        var hn = document.createElement('strong');
        hn.textContent = a.hostname || '?';
        var info = document.createElement('span');
        info.style.color = 'var(--muted)';
        info.textContent = ' ' + (a.os || '') + ' ' + (a.arch || '');
        row.appendChild(hn);
        row.appendChild(info);
        list.appendChild(row);
      });
    })
    .catch(function(){});
}

function formToYaml() {
    var f = document.getElementById('def-form');
    var d = new FormData(f);
    var yaml = 'apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n';
    yaml += '  name: "' + (d.get('name')||'') + '"\n';
    yaml += '  version: "' + (d.get('version')||'1.0.0') + '"\n';
    yaml += 'spec:\n';
    yaml += '  plugin: "' + (d.get('plugin')||'') + '"\n';
    yaml += '  action: "' + (d.get('action')||'') + '"\n';
    yaml += '  type: ' + (d.get('type')||'question') + '\n';
    yaml += '  description: "' + (d.get('description')||'') + '"\n';
    yaml += '  concurrency: ' + (d.get('concurrency_mode')||'unlimited') + '\n';
    yaml += '  approval: ' + (d.get('approval_mode')||'auto') + '\n';
    if (d.get('platforms')) yaml += '  platforms: [' + d.get('platforms') + ']\n';
    yaml += '  parameters:\n    type: object\n    additionalProperties:\n      type: string\n';
    yaml += '  results:\n    - name: output\n      type: string\n';
    var ta = document.getElementById('yaml-editor');
    if (ta) {
        ta.value = yaml;
        htmx.trigger(ta, 'keyup');
    }
    switchEditorMode('yaml', document.querySelectorAll('.editor-tab')[1]);
}
/* Ctrl+K / Cmd+K — navigate to dashboard command palette */
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    window.location.href = '/?palette=1';
  }
});

/* ── Executions drawer toggle ─────────────────────────────────────────────
   Modeled on dashboard_ui.cpp's toggleDetail. Single-drawer-open invariant:
   clicking a row collapses any other open drawer first so the operator
   never has two expanded forensic views competing for attention. The HTMX
   attributes on the row handle the lazy fetch (click once); this function
   only manages visibility state. */
/* PR 3 — open EventSources keyed on execution_id. close() the source
   when the drawer collapses, when the SSE handler emits
   `execution-completed`, or when the browser navigates away. We hold
   the Map at module scope rather than on the row so re-rendered drawer
   markup (HTMX swap) doesn't strand the connection. */
var execEventSources = (window.execEventSources = window.execEventSources || new Map());

)HTM"
    // Part 3b: execution-drawer live-update JavaScript.
    //
    // Split from Part 3 purely for MSVC's 16 KiB string-literal cap (C2026) —
    // adjacent literals are concatenated by the compiler, so this is a source
    // boundary with no runtime effect. Part 3 sat 135 bytes under the cap after
    // the #2500 change, which is one sentence away from breaking the Windows
    // leg again; this restores real headroom on both halves.
    R"HTM(
function execCssEsc(s) {
  if (typeof CSS !== 'undefined' && CSS.escape) return CSS.escape(String(s));
  /* Conservative fallback — escape the chars that can break attribute
     selectors. The id charset is bounded server-side to 1-128 of
     [A-Za-z0-9_-] so nothing here should actually need escaping, but
     we don't trust the assumption on the client. */
  return String(s).replace(/(["\\])/g, '\\$1');
}

function execStopLiveUpdates(execId) {
  var es = execEventSources.get(execId);
  if (es) {
    try { es.close(); } catch (e) {}
    execEventSources.delete(execId);
  }
  /* Clear any pending drawer-refresh timer so the closed drawer
     doesn't ghost-fetch after teardown (UAT 2026-05-06 #8). */
  if (execDrawerRefreshTimers && execDrawerRefreshTimers.has(execId)) {
    clearTimeout(execDrawerRefreshTimers.get(execId));
    execDrawerRefreshTimers.delete(execId);
  }
}

function execApplyAgentTransition(drawerEl, execId, payload) {
  if (!drawerEl || !payload || !payload.agent_id) return;
  var status = String(payload.status || '');
  var safeAgent = execCssEsc(payload.agent_id);
  var safeExec = execCssEsc(execId);
  /* Map the wire status to the CSS modifier the renderer used. Server
     emits raw status (success/failure/timeout/rejected/running/pending). */
  var domStatus = 'pending';
  if (status === 'success') domStatus = 'succeeded';
  else if (status === 'failure' || status === 'timeout' || status === 'rejected') domStatus = 'failed';
  else if (status === 'running') domStatus = 'running';

  /* Swap the agent-cell modifier so the colour reflects the new status. */
  var cells = drawerEl.querySelectorAll(
    '.agent-cell[data-agent-id="' + safeAgent + '"][data-exec-id="' + safeExec + '"]');
  for (var i = 0; i < cells.length; i++) {
    var c = cells[i];
    c.className = c.className.replace(/\bagent-cell--(succeeded|failed|running|pending|success|failure|timeout|rejected)\b/g, '').trim();
    c.classList.add('agent-cell');
    c.classList.add('agent-cell--' + domStatus);
  }
  /* Update the per-agent table row's status badge + exit code. */
  var rows = drawerEl.querySelectorAll(
    'tr[data-agent-id="' + safeAgent + '"][data-exec-id="' + safeExec + '"]');
  for (var j = 0; j < rows.length; j++) {
    var badge = rows[j].querySelector('.per-agent-status');
    if (badge) {
      badge.textContent = status;
      // Canonical class vocabulary (ca-PR3-7) — matches the server
      // renderer in workflow_routes.cpp. Both produce
      // `.status-{succeeded,failed,running,pending}` so initial
      // render and SSE live update yield identical class strings.
      // CSS rules `.status-succeeded` / `.status-failed` /
      // `.status-running` / `.status-pending` cover the set.
      badge.className = 'status-badge per-agent-status status-' + domStatus;
    }
    var exitTd = rows[j].querySelector('.per-agent-exit-code');
    if (exitTd && typeof payload.exit_code === 'number') {
      exitTd.textContent = String(payload.exit_code);
    }
  }
}

function execApplyProgress(drawerEl, execId, payload) {
  if (!drawerEl || !payload) return;
  var strip = drawerEl.querySelector('#exec-kpi-' + execCssEsc(execId));
  if (!strip) return;
  var values = strip.querySelectorAll('.exec-kpi-value');
  /* Strip layout: Total / Succeeded / Failed / p50 / p95.
     Update the first three from counts; p50 / p95 stay on "—" until the
     next full detail-fragment fetch so we don't re-implement the
     percentile renderer client-side. */
  if (values.length >= 3) {
    if (typeof payload.agents_targeted === 'number')
      values[0].textContent = String(payload.agents_targeted);
    if (typeof payload.agents_success === 'number')
      values[1].textContent = String(payload.agents_success);
    if (typeof payload.agents_failure === 'number')
      values[2].textContent = String(payload.agents_failure);
  }
}

/* UAT 2026-05-06 #8 — debounced drawer body refresh.

   `execApplyAgentTransition` does fast in-place updates to the agent
   grid + per-agent table when a state change arrives, but the Responses
   table renders server-side at drawer open and won't pick up new rows
   without a re-fetch. Debounce so a burst of transitions (e.g. 100-agent
   fan-out completing in <100 ms) coalesces into a single GET.

   Side effect: any expanded <details class="resp-output"> collapses on
   refresh. Acceptable for the live-update UX; operators who want to
   drill in pin the row by closing the drawer (which stops live updates
   per execStopLiveUpdates) and re-opening it after.

   500 ms is a deliberate choice — short enough to feel live during
   demos, long enough to coalesce typical fan-out chatter. */
var execDrawerRefreshTimers = (window.execDrawerRefreshTimers =
                                  window.execDrawerRefreshTimers || new Map());
function execScheduleDrawerRefresh(drawerEl, execId) {
  if (!drawerEl || !execId) return;
  if (execDrawerRefreshTimers.has(execId)) return;
  var t = setTimeout(function() {
    execDrawerRefreshTimers.delete(execId);
    var content = drawerEl.querySelector('.exec-detail-content');
    if (!content) return;
    if (typeof htmx === 'undefined') return; // graceful no-op in tests
    htmx.ajax('GET', '/fragments/executions/' + encodeURIComponent(execId) + '/detail',
              { target: content, swap: 'innerHTML' });
  }, 500);
  execDrawerRefreshTimers.set(execId, t);
}

function execStartLiveUpdates(drawerEl, execId) {
  if (!execId || execEventSources.has(execId)) return;
  /* `EventSource` is reused across reconnects via Last-Event-ID; the
     server ring buffer replays anything we missed. The handler returns
     410 Gone when the execution is already terminal — the browser
     surfaces that as `error` and `readyState=CLOSED`. */
  var url = '/sse/executions/' + encodeURIComponent(execId);
  var es;
  try { es = new EventSource(url); } catch (e) { return; }
  execEventSources.set(execId, es);
  es.addEventListener('agent-transition', function(ev) {
    try { execApplyAgentTransition(drawerEl, execId, JSON.parse(ev.data)); }
    catch (err) {}
    /* Schedule a debounced full-body refresh so the Responses table
       picks up the new row(s). The in-place update above keeps the
       per-agent badge + agent-grid colour responsive in the meantime. */
    execScheduleDrawerRefresh(drawerEl, execId);
  });
  es.addEventListener('execution-progress', function(ev) {
    try { execApplyProgress(drawerEl, execId, JSON.parse(ev.data)); } catch (err) {}
  });
  es.addEventListener('execution-completed', function() {
    /* Final refresh so the terminal state's responses + KPI duration
       percentiles render correctly, then stop the EventSource. */
    execScheduleDrawerRefresh(drawerEl, execId);
    execStopLiveUpdates(execId);
  });
  es.addEventListener('heartbeat', function() {});
  es.onerror = function() {
    /* CONNECTING (0) is the auto-reconnect path — let it work. CLOSED (2)
       means the server hung up permanently (410 Gone or auth lapsed);
       drop the source. */
    if (es.readyState === 2 /* CLOSED */) execStopLiveUpdates(execId);
  };
}

function toggleExecDetail(row) {
  if (!row) return;
  /* Collapse any other open drawer first. */
  document.querySelectorAll('.exec-row.expanded').forEach(function(other) {
    if (other === row) return;
    other.classList.remove('expanded');
    var sib = other.nextElementSibling;
    if (sib && sib.classList.contains('exec-detail')) sib.classList.remove('open');
    var otherId = other.getAttribute('data-execution-id') || '';
    if (otherId) execStopLiveUpdates(otherId);
  });
  row.classList.toggle('expanded');
  var det = row.nextElementSibling;
  var isOpen = false;
  if (det && det.classList.contains('exec-detail')) {
    det.classList.toggle('open');
    isOpen = det.classList.contains('open');
  }
  /* Bootstrap / tear down the SSE connection in step with the visual
     state. We start it only if the row was rendered with status=running
     or status=pending; the server re-validates and responds 410 if the
     row turned terminal between LIST render and click. */
  var execId = row.getAttribute('data-execution-id') || '';
  var execStatus = row.getAttribute('data-execution-status') || '';
  if (!execId) return;
  if (isOpen && (execStatus === 'running' || execStatus === 'pending')) {
    /* Defer the EventSource open one tick so the htmx swap that fills
       the drawer body has populated `.exec-detail-content`. The
       listener queries the DOM under `det` so a too-early connection
       would fan out into nothing. */
    setTimeout(function() { execStartLiveUpdates(det, execId); }, 0);
  } else {
    execStopLiveUpdates(execId);
  }
}

/* Tear down all sources on browser navigation away — fail-safe path.
   Without this the EventSource stays connected through bfcache and the
   server holds the per-connection sink_state until httplib's keep-alive
   timeout (~5s) expires. */
window.addEventListener('beforeunload', function() {
  execEventSources.forEach(function(es) { try { es.close(); } catch (e) {} });
  execEventSources.clear();
});

/* Delegated listener for agent grid cells.
   Reads exec_id and agent_id from data-* attributes — never interpolates
   user-controlled bytes into a JS string literal (UP-1 / sec-L1 fix).
   Event delegated to document so newly-loaded drawers inherit the binding
   without re-wiring on every fragment swap. */
document.addEventListener('click', function(event) {
  var cell = event.target.closest && event.target.closest('.agent-cell[data-agent-id]');
  if (!cell) return;
  event.stopPropagation();
  var execId = cell.getAttribute('data-exec-id') || '';
  var agentId = cell.getAttribute('data-agent-id') || '';
  if (!execId || !agentId) return;
  /* Build the row id via DOM traversal rather than string concat to avoid
     any id-collision pitfalls where agent_id contains "row-". */
  var drawer = cell.closest('.exec-detail-content');
  if (!drawer) return;
  var rows = drawer.querySelectorAll('tr[data-agent-id]');
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].getAttribute('data-agent-id') === agentId &&
        rows[i].getAttribute('data-exec-id') === execId) {
      rows[i].scrollIntoView({behavior: 'smooth', block: 'center'});
      rows[i].classList.add('per-agent-row-highlight');
      (function(r) {
        setTimeout(function() { r.classList.remove('per-agent-row-highlight'); }, 1500);
      })(rows[i]);
      return;
    }
  }
});
</script>
</body></html>
)HTM";

// ── Editor fragment HTML template ─────────────────────────────────────────
// Rendered by the server with user role check. Only shown to
// PlatformEngineer and Administrator roles.
extern const char* const kInstructionEditorHtml = R"HTM(
<div class="editor-panel active">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem">
        <div>
            <strong>{{TITLE}}</strong>
            <span class="role-badge">Platform Engineer</span>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="closeEditor()">Close</button>
    </div>
    <div id="editor-alerts"></div>
    <div class="editor-tabs">
        <div class="editor-tab active" onclick="switchEditorMode('form',this)">Form</div>
        <div class="editor-tab" onclick="switchEditorMode('yaml',this)">YAML</div>
    </div>

    <!-- Form mode -->
    <div id="form-mode">
        <form id="def-form">
            <input type="hidden" name="id" value="{{DEF_ID}}">
            <div class="form-grid">
                <div class="form-group">
                    <label>Name</label>
                    <input name="name" value="{{DEF_NAME}}" required placeholder="e.g. hardware:query">
                </div>
                <div class="form-group">
                    <label>Version</label>
                    <input name="version" value="{{DEF_VERSION}}" placeholder="1.0.0">
                </div>
                <div class="form-group">
                    <label>Plugin</label>
                    <input name="plugin" value="{{DEF_PLUGIN}}" required placeholder="e.g. hardware">
                </div>
                <div class="form-group">
                    <label>Action</label>
                    <input name="action" value="{{DEF_ACTION}}" required placeholder="e.g. query">
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select name="type">
                        <option value="question" {{SEL_QUESTION}}>Question (read-only)</option>
                        <option value="action" {{SEL_ACTION}}>Action (modifying)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Approval Mode</label>
                    <select name="approval_mode">
                        <option value="auto" {{SEL_APPR_AUTO}}>Auto</option>
                        <option value="role-gated" {{SEL_APPR_ROLE}}>Role-gated</option>
                        <option value="always" {{SEL_APPR_ALWAYS}}>Always required</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Concurrency Mode</label>
                    <select name="concurrency_mode" title="Only Per-device is enforced (ADR-1007), and only for POST /api/instructions/:id/execute — a raw MCP/REST command, an explicit Broadcast/all-fleet dispatch, or a SCHEDULED fire (as of WS-3 3.3 scheduled fires go through the durable command outbox and are NOT concurrency-gated) is never gated. The other modes are accepted and stored but currently have no effect.">
                        <option value="unlimited" {{SEL_CC_UNLIM}}>Unlimited</option>
                        <option value="per-device" {{SEL_CC_DEV}}>Per-device (enforced only for POST /api/instructions/:id/execute, not scheduled fires)</option>
                        <option value="per-definition" {{SEL_CC_DEF}}>Per-definition (not enforced)</option>
                        <option value="per-set" {{SEL_CC_SET}}>Per-set (not enforced)</option>
                        {{SEL_CC_OTHER_OPTION}}
                    </select>
                </div>
                <div class="form-group">
                    <label>Platforms</label>
                    <input name="platforms" value="{{DEF_PLATFORMS}}" placeholder="windows, linux, macos">
                </div>
                <div class="form-group full">
                    <label>Description</label>
                    <input name="description" value="{{DEF_DESCRIPTION}}" placeholder="What this instruction does">
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="formToYaml()">Convert to YAML</button>
            </div>
        </form>
    </div>

    <!-- YAML mode -->
    <div id="yaml-mode" style="display:none">
        <form hx-post="/api/instructions/yaml" hx-target="#editor-alerts" hx-swap="innerHTML">
            <input type="hidden" name="id" value="{{DEF_ID}}">
            <div class="form-group full">
                <label>YAML Source (apiVersion: yuzu.io/v1alpha1)</label>
                <div class="yaml-legend">
                    <span><span class="swatch" style="background: var(--mds-color-indicator-success-bright)"></span> question (read-only)</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-attention)"></span> action (privileged)</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-error-bright)"></span> approval required</span>
                    <span><span class="swatch" style="background: var(--mds-color-theme-indicator-warning)"></span> concurrency</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-info-bright)"></span> keys</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-special)"></span> schema</span>
                </div>
                <div class="yaml-split">
                    <textarea id="yaml-editor" name="yaml_source"
                              hx-post="/fragments/instructions/yaml-preview"
                              hx-trigger="input changed delay:500ms"
                              hx-target="#yaml-preview"
                              hx-swap="innerHTML"
                              spellcheck="false"
                              placeholder="Paste or type YAML here...">{{YAML_SOURCE}}</textarea>
                    <div id="yaml-preview" class="yaml-preview">
                        <span style="color:var(--muted)">Preview will appear as you type...</span>
                    </div>
                </div>
                <div id="yaml-errors" class="yaml-errors"></div>
            </div>
            <div class="form-actions">
                <button type="submit" class="btn btn-primary">Save Definition</button>
                <button type="button" class="btn btn-secondary"
                        hx-post="/api/instructions/validate-yaml"
                        hx-include="#yaml-editor"
                        hx-target="#editor-alerts" hx-swap="innerHTML">Validate</button>
                <button type="button" class="btn btn-secondary" onclick="closeEditor()">Cancel</button>
            </div>
        </form>
    </div>
</div>
)HTM";

// ── Access denied fragment ────────────────────────────────────────────────
extern const char* const kInstructionEditorDeniedHtml = R"HTM(
<div class="alert alert-error">
    YAML authoring requires the <strong>PlatformEngineer</strong> or <strong>Administrator</strong> role.
    Contact your administrator to request access.
</div>
)HTM";
// NOLINTEND(cert-err58-cpp)
