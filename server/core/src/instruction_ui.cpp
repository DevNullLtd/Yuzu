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
button,input,select,textarea{font:inherit;color:inherit}
code{font-family:var(--mds-font-family-mono);font-size:12.5px}
/* page frame */
.pg{padding:22px 28px 36px;display:flex;flex-direction:column;gap:20px}
.ph h1{font-size:24px;font-weight:600;letter-spacing:-.015em;line-height:1.2;color:var(--ink)}
.ph p{color:var(--mut);margin-top:4px;max-width:70ch}
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:1px solid var(--line)}
.tab{padding:8px 14px;cursor:pointer;color:var(--mut);border-bottom:2px solid transparent;margin-bottom:-1px;font-weight:500;transition:color .12s}
.tab:hover{color:var(--ink)}
.tab.active{color:var(--ink);border-bottom-color:var(--hl);font-weight:600}
/* panel: a bordered region, not a floating card */
.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel);min-width:0}
.panel+.panel{margin-top:22px}
.panel>.hd{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 16px;border-bottom:1px solid var(--line)}
.panel>.hd h2{font-size:14px;font-weight:600;color:var(--ink)}
.panel>.hd .end{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.panel>.pb{padding:16px}
.tw{overflow-x:auto}
.empty-state{color:var(--mut);text-align:center;padding:32px 16px;font-size:13.5px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.panel .empty-state,.exec-detail .empty-state{background:none;border:0}
.exec-detail .empty-state{padding:12px}
.note{margin-bottom:12px;padding:12px 14px;border:1px solid var(--line2);border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
.note.warn{border-color:color-mix(in srgb,var(--warn) 50%,var(--line2))}
.hint{color:var(--mut);font-size:12.5px}
/* tables */
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:12.5px;font-weight:500;color:var(--mut);padding:8px 16px;background:var(--surface2);border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:var(--cell-y) 16px;border-bottom:1px solid var(--line);color:var(--ink2)}
tr:last-child>td{border-bottom:0}
tbody tr:hover>td{background:var(--surface2)}
td strong{color:var(--ink);font-weight:600}
td.act{text-align:right;white-space:nowrap}
.sub-id{display:block;font-size:12px;color:var(--faint)}
.legacy-badge{font-size:12px;background:var(--surface2);color:var(--mut);padding:0 6px;border-radius:3px;margin-left:6px}
/* buttons (all reachable controls are .btn) */
.btn{height:var(--ctl);padding:0 14px;border-radius:var(--rad-ctl);border:1px solid var(--line2);background:var(--raise);color:var(--ink);font-size:14px;font-weight:500;cursor:pointer;display:inline-flex;align-items:center;gap:6px;white-space:nowrap;transition:background .12s,border-color .12s}
.btn:hover:not(:disabled){background:var(--surface2);border-color:var(--mut);opacity:1}
.btn-secondary{background:var(--raise);color:var(--ink);border-color:var(--line2)}
.btn-primary{background:var(--primary);color:var(--on-primary);border-color:var(--primary);font-weight:600}
.btn-primary:hover:not(:disabled){background:var(--primary-h);border-color:var(--primary-h)}
.btn-danger{background:var(--raise);color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,var(--line2))}
.btn-danger:hover:not(:disabled){background:color-mix(in srgb,var(--bad) 12%,transparent);border-color:var(--bad)}
.btn-sm{height:28px;padding:0 10px;font-size:13px}
/* forms */
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:16px}
.form-group{display:flex;flex-direction:column;gap:5px;min-width:0}
.form-group.full{grid-column:1/-1}
label{display:block;font-size:13px;font-weight:500;color:var(--ink2)}
input,select,textarea{height:var(--ctl);padding:0 10px;border-radius:var(--rad-ctl);background:var(--bg);border:1px solid var(--line2);color:var(--ink);min-width:0}
select{width:100%}
input::placeholder,textarea::placeholder{color:var(--faint)}
input:focus,select:focus,textarea:focus{border-color:var(--primary)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
textarea{height:auto;padding:8px 10px;min-height:84px;resize:vertical;font-family:var(--mds-font-family-mono);font-size:12.5px;tab-size:2}
.form-actions{margin-top:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
/* status pills (the .status-* vocabulary is shared with the SSE swap below) */
.status-badge{display:inline-flex;align-items:center;padding:1px 8px;border-radius:3px;font-size:12.5px;font-weight:500;white-space:nowrap;color:var(--mut);background:var(--surface2)}
.status-pending{color:var(--warn);background:var(--mds-color-bg-warning-tinted)}
.status-running{color:var(--info);background:var(--mds-color-bg-info-tinted)}
.status-completed,.status-succeeded,.status-approved{color:var(--ok);background:var(--mds-color-bg-success-tinted)}
.status-failed,.status-rejected{color:var(--bad);background:var(--mds-color-bg-error-tinted)}
.status-cancelled,.status-idle{color:var(--mut);background:var(--surface2)}
.role-badge{display:inline-flex;padding:1px 8px;border-radius:3px;font-size:12.5px;font-weight:500;color:var(--mut);background:var(--surface2)}
.alert{padding:12px 14px;border-radius:var(--rad-panel);font-size:13.5px;margin-bottom:12px;background:var(--surface2);color:var(--ink2);border:1px solid var(--line2)}
.alert strong{color:var(--ink)}
.alert ul{margin-left:18px}
.alert-error{border-color:var(--bad)}
.alert-success{border-color:var(--ok)}
.alert-warning{border-color:var(--warn)}
/* execute form */
.exec-form{display:grid;grid-template-columns:minmax(0,1fr) 260px;gap:20px;padding:16px}
.exec-main>*+*{margin-top:12px}
.def-info{background:var(--bg);border:1px solid var(--line);border-radius:var(--rad-ctl);padding:12px}
.def-info-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:4px}
.def-info-top strong{color:var(--ink);font-weight:600}
.def-info-top code{color:var(--faint)}
.def-info-desc{color:var(--mut);font-size:13px;margin-bottom:4px}
.def-info-meta{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:13px;color:var(--mut)}
.params label{margin-bottom:5px}
#exec-status{font-size:13px;color:var(--mut)}
.agent-list:empty{display:none}
.agent-list{max-height:300px;overflow-y:auto;border:1px solid var(--line);border-radius:var(--rad-ctl);font-size:12.5px;margin-top:8px}
/* editor panel */
.editor-panel{display:none}
.editor-panel.active{display:block}
.editor-tabs{display:inline-flex;gap:2px;margin-bottom:16px;padding:2px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg)}
.editor-tab{height:calc(var(--ctl) - 8px);min-height:26px;padding:0 12px;border-radius:2px;display:flex;align-items:center;cursor:pointer;color:var(--mut);font-weight:500}
.editor-tab:hover{color:var(--ink)}
.editor-tab.active{background:var(--raise);color:var(--ink);box-shadow:inset 0 0 0 1px var(--line2);font-weight:600}
.yaml-split textarea,.yaml-preview{font-size:12.5px}
.yaml-legend{display:flex;gap:6px 16px;flex-wrap:wrap;margin-bottom:8px;font-size:12.5px;color:var(--mut)}
.yaml-legend span{display:flex;align-items:center;gap:6px}
.yaml-legend .swatch{width:10px;height:10px;border-radius:2px;display:inline-block}
.yt{white-space:pre}
.yk{color:var(--info)}.yv{color:var(--ink2)}.yc{color:var(--faint);font-style:italic}.ya{color:var(--ink);font-weight:600}
.yq,.yap-auto{color:var(--ok)}.yact{color:var(--warn);font-weight:600}.yar{color:var(--bad);font-weight:600}.ycc{color:var(--warn)}
.yn,.yb{color:var(--c2)}.yd{color:var(--faint)}
/* Executions tab: clickable rows + per-execution detail drawer. Status is hue + a row stripe
   (two channels); the KPI strip carries the headline, the tables the long tail. */
.exec-row{cursor:pointer}
.exec-table>tbody>tr:nth-last-child(2)>td{border-bottom:0}
.exec-table>tbody>tr.expanded:nth-last-child(2)>td{border-bottom:1px solid var(--line)}
.exec-row.expanded>td{background:var(--mds-color-state-selected)}
.exec-row--failed>td:first-child{box-shadow:inset 3px 0 0 var(--bad)}
.exec-row--running>td:first-child{box-shadow:inset 3px 0 0 var(--info)}
.exec-row.expanded>td:first-child{box-shadow:inset 3px 0 0 var(--hl)}
.exec-row:focus-visible{outline-offset:-2px}
.exec-def-name{font-weight:600;color:var(--ink)}
.exec-agent-count,.exec-time{font-size:13px;color:var(--mut);white-space:nowrap}
.exec-error-preview{font-family:var(--mds-font-family-mono);font-size:12px;color:var(--bad);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-sparkbar{display:block}
.exec-detail{display:none}
.exec-detail.open{display:table-row}
.exec-detail>td,tbody tr.exec-detail:hover>td{padding:16px;background:var(--bg)}
.exec-detail-grid{display:grid;gap:16px;grid-template-columns:1fr minmax(220px,320px)}
.exec-detail-grid h4{margin:0 0 6px;font-size:13px;font-weight:600;color:var(--ink)}
.exec-kpi-strip{display:flex;flex-wrap:wrap;grid-column:1/-1;border:1px solid var(--line);border-radius:var(--rad-panel);background:var(--surface)}
.exec-kpi{flex:1 1 120px;min-width:0;padding:12px 16px;border-left:1px solid var(--line)}
.exec-kpi:first-child{border-left:0}
.exec-kpi-value{font-size:22px;font-weight:500;letter-spacing:-.02em;line-height:1.15;color:var(--ink)}
.exec-kpi-value--ok{color:var(--ok)}
.exec-kpi-value--err{color:var(--bad)}
.exec-kpi-label{font-size:13px;color:var(--mut);margin-top:2px}
.agent-grid-wrap{grid-column:1/-1}
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,12px);gap:2px;max-height:200px;overflow-y:auto}
.agent-cell{width:12px;height:12px;border-radius:2px;cursor:pointer}
.agent-cell--bucket{width:auto;height:18px;display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--bg);padding:0 6px;border-radius:3px}
.agent-cell--succeeded{background:var(--ok)}
.agent-cell--failed{background:var(--bad)}
.agent-cell--running{background:var(--info)}
.agent-cell--pending{background:var(--mut);opacity:.4}
.per-agent-table-wrap,.per-agent-responses-wrap{grid-column:1;min-width:0}
.per-agent-table th,.per-agent-table td,.per-agent-responses-table th,.per-agent-responses-table td{padding:6px 12px;font-size:13px}
.per-agent-table td{vertical-align:middle}
.duration-bar{height:6px;border-radius:2px;display:inline-block;vertical-align:middle;min-width:1px}
.duration-bar--succeeded{background:var(--ok)}
.duration-bar--failed{background:var(--bad)}
.duration-bar--running{background:var(--info)}
.duration-bar--pending{background:var(--mut);opacity:.4}
.duration-text{font-size:12px;color:var(--mut);margin-left:6px}
.per-agent-row-highlight>td{background:var(--mds-color-state-selected)!important}
.per-agent-responses summary{cursor:pointer;font-size:13px;color:var(--mut);padding:6px 0}
.resp-output pre{margin:6px 0;padding:8px;background:var(--bg);border:1px solid var(--line);border-radius:var(--rad-ctl);max-height:200px;overflow:auto;white-space:pre-wrap;font-family:var(--mds-font-family-mono);font-size:12.5px}
.exec-detail-sidebar{grid-column:2;grid-row:3/span 2;font-size:13px}
.exec-detail-sidebar>div{margin-bottom:8px}
.exec-detail-meta-id{font-size:12px;color:var(--faint)}
.exec-detail-scope,.exec-detail-params{display:block;font-size:12.5px;background:var(--bg);border:1px solid var(--line);padding:6px 8px;border-radius:var(--rad-ctl);white-space:pre-wrap;word-break:break-all}
@media (max-width:900px){.pg{padding:16px}.exec-form,.exec-detail-grid{grid-template-columns:1fr}.exec-detail-sidebar{grid-column:1;grid-row:auto}}
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

)HTM"
    R"HTM(<div class="pg">
<header class="ph"><div><h1>Instructions</h1><p>Author, validate and dispatch instructions.</p></div></header>
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
    <section class="panel">
      <div class="hd"><h2>Execute Instruction</h2></div>
      <div class="exec-form">
        <div class="exec-main">
          <div class="form-group">
            <label>Instruction Definition</label>
            <select id="exec-def-select" onchange="onDefSelected(this.value)">
              <option value="">— Select an instruction —</option>
            </select>
          </div>
          <div id="exec-def-info" class="def-info" style="display:none">
            <div class="def-info-top">
              <strong id="exec-def-name"></strong>
              <code id="exec-def-id"></code>
            </div>
            <div id="exec-def-desc" class="def-info-desc"></div>
            <div class="def-info-meta">
              <span>Plugin: <code id="exec-def-plugin"></code></span>
              <span>Action: <code id="exec-def-action"></code></span>
              <span>Type: <code id="exec-def-type"></code></span>
            </div>
          </div>
          <div id="exec-params-area" class="params" style="display:none">
            <label>Parameters</label>
            <div id="exec-params-fields" class="form-grid"></div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" onclick="executeInstruction()" id="exec-btn" disabled>
              Execute
            </button>
            <span id="exec-status"></span>
          </div>
          <div id="exec-result"></div>
        </div>
        <div>
          <div class="form-group">
            <label>Scope</label>
            <select id="exec-scope">
              <option value="__all__">All agents</option>
            </select>
          </div>
          <div id="exec-agent-list" class="agent-list"></div>
        </div>
      </div>
    </section>
    <!-- Execution history — loaded via HTMX fragment -->
    <section class="panel">
      <div class="hd"><h2>Execution History</h2></div>
      <div id="exec-history" hx-get="/fragments/executions" hx-trigger="revealed" hx-swap="innerHTML">
        <div class="empty-state">Loading...</div>
      </div>
    </section>
</div>
<div id="tab-schedules" style="display:none" hx-get="/fragments/schedules" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-approvals" style="display:none" hx-get="/fragments/approvals" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>

<!-- YAML Authoring Panel — rendered by /fragments/instructions/editor -->
<div id="editor-host"></div>

</div><!-- /page body -->

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
<div class="editor-panel panel active">
    <div class="hd">
        <h2>{{TITLE}}</h2>
        <span class="role-badge">Platform Engineer</span>
        <div class="end"><button class="btn btn-secondary btn-sm" onclick="closeEditor()">Close</button></div>
    </div>
    <div class="pb">
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
                    <span><span class="swatch" style="background:var(--ok)"></span> question (read-only)</span>
                    <span><span class="swatch" style="background:var(--warn)"></span> action (privileged)</span>
                    <span><span class="swatch" style="background:var(--bad)"></span> approval required</span>
                    <span><span class="swatch" style="background:var(--warn)"></span> concurrency</span>
                    <span><span class="swatch" style="background:var(--info)"></span> keys</span>
                    <span><span class="swatch" style="background:var(--ink)"></span> schema</span>
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
                        <span class="hint">Preview will appear as you type...</span>
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
