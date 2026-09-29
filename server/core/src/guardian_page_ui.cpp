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
// Product UI — HTMX, server-rendered, dark-theme only. Palette comes from
// /static/yuzu.css (--bg/--surface/--border/--fg/--muted/--green/--yellow/
// --red/--accent/--mono); the page-specific component CSS lives in the inline
// <style> below because those classes (.gp-*) are not part of the shared
// stylesheet. Do NOT apply the `frontend-design` plugin here.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kGuardianDetailPageHtml =
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
    .gp-wrap { max-width: 1100px; margin: 1.5rem auto; padding: 0 1.5rem; }
    .gp-loading { color: var(--muted); padding: 2rem 0; }
    .gp-back { font-size: 0.78rem; color: var(--accent); display: inline-block;
               margin-bottom: 0.75rem; text-decoration: none; }
    .gp-back:hover { text-decoration: underline; }

    /* page header: title + actions */
    .gp-head { display: flex; align-items: flex-start; justify-content: space-between;
               gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.9rem; }
    .gp-head h1 { font-size: 1.4rem; font-weight: 700; }
    .gp-titleline { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
    .gp-sub { font-size: 0.78rem; color: var(--muted); margin-top: 0.35rem; }
    .gp-actions { display: flex; gap: 0.45rem; flex-shrink: 0; }

    .gp-sech { font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em;
               color: var(--muted); font-weight: 700; margin: 1.3rem 0 0.5rem; }
    .gp-note { font-size: 0.74rem; color: var(--muted); margin-top: 0.5rem; }
    .gp-note b { color: #a5d6ff; }

    /* #2691 finding 10: an honest "store degraded, retrying" banner on a
       running /auto Pre-flight page — distinct from a plain empty state so
       it doesn't read as "these devices are done". Amber, not alarm-red
       (#2691 Gate 6 enterprise-readiness): a transient retrying blip, not a
       confirmed failure — matches the dashboard sibling banner. */
    .result-degrade-banner {
      color: var(--yellow, #ffcc00); background: rgba(255, 204, 0, 0.08);
      border: 1px solid rgba(255, 204, 0, 0.4); border-radius: 0.5rem;
      padding: 0.6rem 0.9rem; font-size: 0.8rem; margin-bottom: 0.75rem;
    }

    /* lifecycle / severity / mode pills */
    .gp-pill { font-size: 0.62rem; font-weight: 700; text-transform: uppercase;
               letter-spacing: 0.03em; border-radius: 0.3rem; padding: 0.1rem 0.45rem;
               border: 1px solid var(--border); }
    .gp-pill.dep { color: var(--green); border-color: rgba(78,210,126,0.5); }
    .gp-pill.draft { color: var(--muted); }
    .gp-pill.sev-critical, .gp-pill.sev-high { color: var(--red); border-color: rgba(255,87,101,0.5); }
    .gp-pill.sev-medium { color: var(--yellow); border-color: rgba(255,204,0,0.45); }
    .gp-pill.sev-low { color: #a5d6ff; }
    .gp-pill.observe { color: #a5d6ff; }
    .gp-pill.enforce { color: var(--yellow); border-color: rgba(255,204,0,0.45); }

    /* compliance hero */
    .gp-hero { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; }
    .gp-pct { font-size: 2.1rem; font-weight: 700; color: var(--fg); line-height: 1; }
    .gp-pct small { display: block; font-size: 0.64rem; color: var(--muted); font-weight: 400;
                    text-transform: uppercase; letter-spacing: 0.05em; }
    .gp-bar { display: flex; height: 18px; border-radius: 4px; overflow: hidden;
              border: 1px solid var(--border); }
    .gp-bar > span { display: flex; align-items: center; justify-content: center;
                     font-size: 0.58rem; color: #04101f; font-weight: 700; }
    .gp-legend { display: flex; flex-wrap: wrap; gap: 0.9rem; margin-top: 0.4rem;
                 font-size: 0.64rem; color: var(--muted); }
    .gp-legend i { display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 2px;
                   margin-right: 0.3rem; vertical-align: middle; }
    .gp-legend b { color: var(--fg); }

    /* stat tiles */
    .gp-tiles { display: flex; flex-wrap: wrap; gap: 0.55rem; margin-top: 0.9rem; }
    .gp-tile { background: var(--surface); border: 1px solid var(--border);
               border-radius: 0.5rem; padding: 0.55rem 0.8rem; min-width: 120px; flex: 1; }
    .gp-tile .n { font-size: 1.4rem; font-weight: 700; color: var(--fg); line-height: 1.1; }
    .gp-tile .l { font-size: 0.62rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .gp-tile .sx { font-size: 0.62rem; color: var(--muted); margin-top: 0.12rem; }
    .gp-tile .n.good { color: var(--green); } .gp-tile .n.warn { color: var(--yellow); }
    .gp-tile .n.bad { color: var(--red); } .gp-tile .n.unk { color: #5b6b80; }
    .gp-tile .n.info { color: var(--accent); } .gp-tile .n.mute { color: var(--muted); }

    /* spec grid (what a guard checks) */
    .gp-spec { display: grid; grid-template-columns: auto 1fr; gap: 0.3rem 1rem;
               font-size: 0.78rem; background: var(--surface); border: 1px solid var(--border);
               border-radius: 0.5rem; padding: 0.7rem 0.9rem; }
    .gp-spec .k { color: var(--muted); }
    .gp-spec code { font-family: var(--mono); color: #a5d6ff; overflow-wrap: anywhere; }

    /* tables */
    .gp-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    .gp-table th { text-align: left; padding: 0.42rem 0.55rem; border-bottom: 2px solid var(--border);
                   color: var(--muted); font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.05em; }
    /* numeric headers must right-align to sit over their right-aligned data — the
       `.gp-table th` rule above out-specifies a bare `.gp-num`, so qualify it. */
    .gp-table th.gp-num { text-align: right; }
    .gp-table td { padding: 0.42rem 0.55rem; border-bottom: 1px solid var(--border); }
    .gp-table tr.click { cursor: pointer; }
    .gp-table tr.click:hover td { background: var(--mds-color-state-hover); }
    .gp-table a { color: var(--fg); font-weight: 600; text-decoration: none; }
    .gp-table a:hover { color: var(--accent); }
    .gp-num { text-align: right; font-variant-numeric: tabular-nums; }
    .gp-ok { color: var(--green); font-weight: 600; } .gp-drift { color: var(--yellow); font-weight: 600; }
    .gp-err { color: var(--red); font-weight: 600; } .gp-unk { color: #5b6b80; } .gp-mute { color: var(--muted); }

    /* filter chips */
    .gp-filters { display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap; margin: 0.2rem 0 0.6rem; }
    .gp-chip { font-size: 0.7rem; padding: 0.22rem 0.6rem; border-radius: 0.35rem;
               border: 1px solid var(--border); color: var(--muted); background: var(--surface);
               cursor: pointer; }
    .gp-chip.on { color: var(--fg); border-color: var(--accent); }
    .gp-search { background: var(--bg); border: 1px solid var(--border); border-radius: 0.4rem;
                 color: var(--fg); padding: 0.28rem 0.55rem; font-size: 0.74rem; min-width: 180px; }

    /* events */
    .gp-ev { display: flex; gap: 0.6rem; padding: 0.32rem 0; border-bottom: 1px solid var(--border); font-size: 0.74rem; }
    .gp-ev .t { color: var(--muted); font-variant-numeric: tabular-nums; white-space: nowrap; }
    .gp-badge { font-size: 0.58rem; font-weight: 700; padding: 0.05rem 0.35rem; border-radius: 0.25rem;
                background: var(--mds-color-bg-warning-tinted); color: var(--yellow); text-transform: uppercase; }

    .gp-placeholder { text-align: center; color: var(--muted); padding: 1.5rem 1rem; font-size: 0.8rem;
                      background: var(--surface); border: 1px dashed var(--border); border-radius: 0.5rem; }
    .gp-placeholder b { display: block; color: var(--fg); margin-bottom: 0.25rem; }

    .gp-btn { height: auto; padding: 0.34rem 0.7rem; font-size: 0.72rem; border-radius: 0.35rem;
              border: 1px solid var(--border); background: var(--mds-color-state-hover); color: var(--fg); cursor: pointer; }
    .gp-btn.accent { border-color: var(--accent); color: var(--accent); background: none; }
    .gp-btn.danger { color: var(--red); }

    /* DEX sub-nav (Overview / Catalogue / Health / Trends) — reuses chip styling */
    .gp-subnav { display: flex; gap: 0.3rem; align-items: center; border-bottom: 1px solid var(--border);
                 padding-bottom: 0.7rem; margin-bottom: 0.6rem; flex-wrap: wrap; }
    .gp-subnav a, .gp-subnav span { font-size: 0.78rem; color: var(--muted); border: 1px solid transparent;
                 border-radius: 0.35rem; padding: 0.22rem 0.6rem; cursor: pointer; }
    .gp-subnav a.on { color: var(--fg); border-color: var(--accent); }
    .gp-subnav span.soon { color: #5b6b80; cursor: default; }
    .gp-subnav .sp { margin-left: auto; font-size: 0.7rem; color: var(--muted); cursor: default; }

    /* DEX catalogue family-card grid (mockup dex-catalogue.html, View 1) */
    .gp-fgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr));
                gap: 0.7rem; margin-top: 0.6rem; }
    .gp-fcard { background: var(--surface); border: 1px solid var(--border); border-radius: 0.55rem;
                padding: 0.75rem 0.85rem; cursor: pointer; color: var(--fg); display: block;
                transition: border-color 0.12s, transform 0.12s; }
    .gp-fcard:hover { border-color: var(--accent); transform: translateY(-1px); }
    .gp-fcard.quiet { opacity: 0.6; }
    .gp-fcard .fn { color: var(--fg); font-weight: 600; font-size: 0.86rem; display: flex;
                justify-content: space-between; align-items: baseline; gap: 0.4rem; }
    .gp-fcard .fn .cnt { font-size: 0.62rem; color: var(--muted); font-weight: 400; white-space: nowrap; }
    .gp-fcard .fev { font-size: 1.5rem; font-weight: 700; color: var(--fg); line-height: 1; margin-top: 0.5rem; }
    .gp-fcard .fev.bad { color: var(--red); } .gp-fcard .fev.warn { color: var(--yellow); }
    .gp-fcard .fev.ok { color: var(--green); }
    .gp-fcard .fmeta { font-size: 0.62rem; color: var(--muted); }
    .gp-fcard .ftop { font-size: 0.64rem; color: var(--muted); margin-top: 0.45rem;
                border-top: 1px solid var(--border); padding-top: 0.4rem; }
    .gp-fcard .ftop b { color: var(--accent); font-weight: 600; }
)HTM"
    // MSVC caps a single string literal at ~16 KB; the page shell + component CSS
    // outgrew it, so the literal is split here (adjacent literals concatenate).
    R"HTM(
    /* DEX health-score page (mockup dex-health-score.html) */
    .gp-reversal { font-size: 0.72rem; color: var(--accent); background: rgba(0,188,235,0.06);
                border: 1px solid rgba(0,188,235,0.3); border-radius: 0.45rem;
                padding: 0.55rem 0.75rem; margin: 0.9rem 0; }
    .gp-primary { display: flex; gap: 1.1rem; align-items: center; flex-wrap: wrap;
                background: var(--surface); border: 1px solid var(--border);
                border-radius: 0.6rem; padding: 0.85rem 1.05rem; }
    .gp-primary .big { font-size: 2.1rem; font-weight: 700; color: var(--green); line-height: 1; }
    .gp-primary .big.sec { color: var(--fg); font-size: 1.5rem; }
    .gp-primary .lbl { font-size: 0.64rem; color: var(--muted); text-transform: uppercase;
                letter-spacing: 0.05em; }
    .gp-primary .vdiv { width: 1px; align-self: stretch; background: var(--border); }
    .gp-composite { display: flex; gap: 1.4rem; align-items: center; flex-wrap: wrap; margin-top: 0.5rem; }
    .gp-gauge { position: relative; width: 140px; height: 140px; flex-shrink: 0; }
    .gp-gauge .val { position: absolute; inset: 0; display: flex; flex-direction: column;
                align-items: center; justify-content: center; }
    .gp-gauge .val .num { font-size: 2.2rem; font-weight: 700; color: var(--fg); line-height: 1; }
    .gp-gauge .val .band { font-size: 0.66rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: 0.05em; }
    .band-excellent, .band-good { color: var(--green); } .band-fair { color: var(--yellow); }
    .band-poor { color: var(--red); }
    .gp-derived { font-size: 0.6rem; color: var(--muted); border: 1px solid var(--border);
                border-radius: 0.3rem; padding: 0.05rem 0.4rem; display: inline-block; margin-bottom: 0.35rem; }
    .gp-stack { display: flex; height: 26px; border-radius: 5px; overflow: hidden;
                border: 1px solid var(--border); margin-bottom: 0.7rem; }
    .gp-stack > span { display: flex; align-items: center; justify-content: center;
                font-size: 0.56rem; color: #04101f; font-weight: 700; min-width: 0; white-space: nowrap; }
    .gp-ded { display: grid; grid-template-columns: 1.6fr auto 1fr auto; gap: 0.6rem;
                align-items: center; padding: 0.32rem 0; border-bottom: 1px solid var(--border); font-size: 0.78rem; }
    .gp-ded .fam { color: var(--fg); font-weight: 600; }
    .gp-ded .wt { font-size: 0.62rem; text-transform: uppercase; }
    .wt-high { color: var(--red); } .wt-med { color: var(--yellow); } .wt-low { color: var(--muted); }
    .gp-ded .bar { height: 8px; border-radius: 2px; background: var(--red); opacity: 0.8; }
    .gp-ded .pts { text-align: right; font-variant-numeric: tabular-nums; color: var(--red);
                font-weight: 600; min-width: 48px; }
    .gp-subgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 0.55rem; }
    .gp-sscore { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem;
                padding: 0.55rem 0.7rem; }
    .gp-sscore .nm { font-size: 0.7rem; color: var(--muted); }
    .gp-sscore .vv { font-size: 1.5rem; font-weight: 700; line-height: 1.1; }
    .gp-sscore .ds { font-size: 0.58rem; color: var(--muted); }

    /* DEX trends page (mockup dex-trends.html) */
    .gp-oscards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.7rem; }
    .gp-oscard { background: var(--surface); border: 1px solid var(--border); border-radius: 0.55rem;
                padding: 0.85rem 1rem; }
    .gp-oscard.pending { opacity: 0.62; border-style: dashed; }
    .gp-oscard .os { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem;
                color: var(--fg); font-weight: 600; }
    .gp-oscard .state { font-size: 0.58rem; border-radius: 0.3rem; padding: 0.05rem 0.4rem;
                border: 1px solid var(--border); }
    .gp-oscard .state.live { color: var(--green); } .gp-oscard .state.limited { color: var(--yellow); }
    .gp-oscard .state.pending { color: var(--muted); }
    .gp-oscard .scope { font-size: 0.62rem; color: var(--muted); margin-top: 0.15rem; }
    .gp-smgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.6rem; }
    .gp-sm { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem;
                padding: 0.6rem 0.7rem; }
    .gp-sm .smh { display: flex; justify-content: space-between; align-items: baseline; gap: 0.3rem; }
    .gp-sm .smn { font-size: 0.72rem; color: var(--fg); font-weight: 600; }
    .gp-sm .smv { font-size: 0.62rem; color: var(--muted); }
    .gp-heat { display: flex; flex-direction: column; gap: 3px; margin-top: 0.4rem; }
    .gp-heat .hrow { display: flex; align-items: center; gap: 4px; }
    .gp-heat .hlbl { width: 150px; flex-shrink: 0; font-size: 0.62rem; color: var(--muted); text-align: right; }
    .gp-heat .hrow > i { flex: 1; height: 14px; border-radius: 2px; min-width: 6px; }
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
    <a href="/guardian" class="nav-link active">Guardian</a>
    <a href="/dex" class="nav-link">DEX</a>
    <a href="/tar" class="nav-link">TAR</a>
    <a href="/hardware" class="nav-link">Hardware</a>
    <a href="/software" class="nav-link">Software</a>
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/settings" class="nav-link" id="nav-settings-link">Settings</a>
    <span class="nav-spacer"></span>
    <span class="nav-user" id="nav-user"></span>
    <button class="nav-logout" hx-post="/logout">Logout</button>
  </nav>
  <div class="context-bar" id="context-bar">
    <span class="context-role-badge" id="role-badge"></span>
    <span class="context-user" id="context-user"></span>
    <span class="context-spacer"></span>
  </div>

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

    /* Populate nav user / role badge, mirroring the dashboard chrome. */
    fetch('/api/me').then(function (r) { return r.json(); }).then(function (d) {
      var nu = document.getElementById('nav-user'); if (nu) nu.textContent = (d.display_name || d.username) || '';
      var role = d.rbac_role || d.role || '';
      var rb = document.getElementById('role-badge'); if (rb) rb.textContent = role;
      var cu = document.getElementById('context-user'); if (cu) cu.textContent = (d.display_name || d.username) || '';
      if (d.role !== 'admin' && role !== 'Administrator' && role !== 'PlatformEngineer') {
        var sl = document.getElementById('nav-settings-link'); if (sl) sl.style.display = 'none';
      }
    }).catch(function () {});
  </script>
)HTM"
    // Chunk 3: the Hardware CI record's generic action runner. Split into its own
    // literal because chunk 2 above sits at ~14.5 KiB and MSVC caps a single
    // string literal at 16 KiB (C2026) -- see the sibling warning in
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
// NOLINTEND(cert-err58-cpp)
