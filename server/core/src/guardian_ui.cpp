// Guardian dashboard page — Guaranteed State enforcement across the fleet.
//
// Mirrors the compliance_ui.cpp pattern: the page shell is server-rendered
// HTML; all interactive data is loaded as HTMX fragments from
// /fragments/guardian/* (see guardian_routes.cpp).
//
// Product UI — HTMX, server-rendered, dark-theme only. Do NOT apply the
// `frontend-design` plugin here (that is marketing-only). Follow the existing
// dashboard conventions.
//
// The page HTML is emitted as several adjacent raw-string literals that the
// compiler concatenates: MSVC caps a single string literal at ~16 KB (C2026),
// and the whole page exceeds that, so it is split at natural boundaries.
//
// Vocabulary note (contract G5): the UI uses the *target* ubiquitous language
// — Guard / Baseline / Spark / Assertion — while the code, REST surface
// (/api/v1/guaranteed-state/*) and RBAC securable ("GuaranteedState") still
// carry the legacy `rule`/`GuaranteedState` naming until the dedicated rename
// PR. See docs/guardian-mvp-contract.md §3, §8.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kGuardianHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Guardian</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: 100vh; }

    /* ── Content ───────────────────────────────────────────── */
    .content {
      max-width: 1200px; margin: 1.5rem auto; padding: 0 1.5rem;
    }

    /* ── Page header ──────────────────────────────────────── */
    .page-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 1.5rem; padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .page-header h1 { font-size: 1.1rem; font-weight: 700; }
    .page-header .subtitle { font-size: 0.75rem; color: var(--muted); margin-top: 0.15rem; }
    .page-header .header-actions { display: flex; gap: 0.5rem; align-items: center; }

    /* ── Section cards ─────────────────────────────────────── */
    .section {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.5rem; margin-bottom: 1.5rem; overflow: hidden;
    }
    .section-header {
      padding: 0.75rem 1rem; font-size: 0.85rem; font-weight: 600;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 0.5rem;
    }
    .section-body { padding: 1rem; }

    /* ── Summary stat cards ────────────────────────────────── */
    .stat-cards { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: stretch; }
    .stat-card {
      flex: 1 1 110px; min-width: 96px;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.5rem; padding: 0.75rem 1rem; text-align: center;
    }
    .stat-num { font-size: 1.6rem; font-weight: 700; line-height: 1; }
    .stat-label {
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em;
      color: var(--muted); margin-top: 0.35rem;
    }
    .stat-num.good { color: var(--green); }
    .stat-num.warn { color: var(--yellow); }
    .stat-num.bad  { color: var(--red); }
    .stat-num.info { color: var(--accent); }
    .stat-num.mute { color: var(--muted); }
    /* Clickable Fleet stat cards (navigate into the matching status sub-view). */
    .stat-card-nav { transition: border-color 0.12s; }
    .stat-card-nav:hover { border-color: var(--accent); }

    /* Fleet worst-of badge — the single most-severe state present. */
    .worst-badge {
      display: inline-flex; align-items: center; gap: 0.4rem;
      padding: 0.25rem 0.7rem; border-radius: 1rem;
      font-size: 0.75rem; font-weight: 700;
    }
    .worst-good { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .worst-warn { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .worst-bad  { background: var(--mds-color-bg-error-tinted);   color: var(--red); }

    /* ── Guard status badges (full taxonomy) ───────────────── */
    .gs-badge {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.68rem; font-weight: 600;
      white-space: nowrap;
    }
    .gs-compliant         { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .gs-drifted           { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .gs-remediation_failed{ background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .gs-errored           { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .gs-exempt            { background: var(--mds-color-state-selected);    color: var(--muted); }
    .gs-stale             { background: var(--mds-color-state-hover);       color: var(--muted); border: 1px dashed var(--border); }

    /* guard_healthy signal — distinct from compliance state. */
    .health-ok   { color: var(--green); }
    .health-bad  { color: var(--red); }
    .health-dot  { font-size: 0.7rem; }

    /* ── View switcher (fleet / guard / agent / mgroup / baseline) ── */
    .view-switch { display: flex; gap: 0; flex-wrap: wrap; margin-bottom: 1rem; }
    .view-btn {
      padding: 0.35rem 0.8rem; font-size: 0.75rem; cursor: pointer;
      background: var(--surface); color: var(--muted);
      border: 1px solid var(--border); border-right: none;
    }
    .view-btn:first-child { border-radius: 0.4rem 0 0 0.4rem; }
    .view-btn:last-child  { border-radius: 0 0.4rem 0.4rem 0; border-right: 1px solid var(--border); }
    .view-btn.active { background: var(--mds-color-state-selected); color: var(--fg); font-weight: 600; }
    .view-btn:hover  { color: var(--fg); }

    /* ── Two-column grid: guards | events ──────────────────── */
    .gs-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
    }
    @media (max-width: 900px) { .gs-grid { grid-template-columns: 1fr; } }

    /* ── Guard list ────────────────────────────────────────── */
    .guard-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .guard-item {
      border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.6rem 0.75rem; cursor: pointer; background: var(--bg);
    }
    .guard-item:hover { background: var(--mds-color-state-hover); }
    .guard-item-top { display: flex; align-items: center; gap: 0.5rem; }
    .guard-name { font-weight: 600; font-size: 0.82rem; }
    .guard-os {
      font-size: 0.6rem; font-family: var(--mono); color: var(--muted);
      border: 1px solid var(--border); border-radius: 0.25rem; padding: 0 0.25rem;
    }
    .guard-meta { font-size: 0.72rem; color: var(--muted); margin-top: 0.3rem;
                  display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }

    /* ── Guard item: left content column + right control column ─ */
    .gi-main { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; }
    .gi-left { min-width: 0; }
    .gi-row1 { display: flex; align-items: center; gap: 0.6rem; }
    .gi-meta { font-size: 0.72rem; color: var(--muted); margin-top: 0.45rem;
               display: flex; gap: 0.85rem; align-items: center; flex-wrap: wrap; }
    .gi-mode { font-weight: 700; font-size: 0.86rem; }
    .gi-mode.observe { color: #a5d6ff; }       /* very light blue */
    .gi-mode.enforce { color: var(--yellow); } /* dashboard gold */
    .gi-right { display: flex; flex-direction: column; align-items: flex-end;
                gap: 0.4rem; flex: none; }
    .gi-state { font-size: 0.62rem; font-weight: 700; letter-spacing: 0.03em; }
    .gi-state.on  { color: var(--green); }
    .gi-state.off { color: var(--muted); }
    .gi-act { width: 74px; text-align: center; padding: 0.12rem 0; font-size: 0.72rem; }
    .gi-deploy { margin-top: 0.65rem; font-size: 0.74rem; }
    .gi-dep-on  { color: #7be3a3; font-weight: 600; } /* lighter green */
    .gi-dep-off { color: var(--muted); }
    .gi-bl { color: #ffffff; text-decoration: underline; cursor: pointer; }
    .gi-bl:hover { color: var(--accent); }
)HTM"
    // Split point 0 (MSVC C2026 — string too big): the <style> block crossed 16 KB
    // after the guard-item CSS grew. Adjacent string literals concatenate at compile
    // time, so this is purely a source-level cut (no stray whitespace enters the HTML).
    R"HTM(
    /* ── Event timeline ────────────────────────────────────── */
    .event-list { display: flex; flex-direction: column; }
    .event-item {
      padding: 0.5rem 0; border-bottom: 1px solid var(--border);
      font-size: 0.78rem;
    }
    .event-item:last-child { border-bottom: none; }
    .event-top { display: flex; align-items: center; gap: 0.5rem; }
    .event-time { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); }
    .event-type {
      font-size: 0.62rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.04em; padding: 0.05rem 0.4rem; border-radius: 0.25rem;
    }
    .et-drift_detected      { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .et-drift_remediated    { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .et-remediation_failed  { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .et-guard_armed         { background: var(--mds-color-state-selected);    color: var(--accent); }
    .et-guard_unhealthy     { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .et-resilience_escalated{ background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .et-generic             { background: var(--mds-color-state-hover);       color: var(--muted); }
    .event-detail { color: var(--muted); margin-top: 0.2rem; }
    .event-detail strong { color: var(--fg); font-weight: 500; }

    /* ── Baseline cards ────────────────────────────────────── */
    .baseline-card {
      border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.75rem; margin-bottom: 0.6rem; background: var(--bg);
    }
    .baseline-top { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .baseline-name { font-weight: 600; font-size: 0.85rem; }
    .baseline-scope { font-size: 0.72rem; color: var(--muted); font-family: var(--mono); margin-top: 0.25rem; }
    .lifecycle-draft    { color: var(--muted); }
    .lifecycle-deployed { color: var(--green); }

    /* ── By-Guard / By-Baseline LIST cards + filter (view-switch) ───────── */
    .gs-filterbar {
      display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;
      background: var(--bg); border: 1px solid var(--border); border-radius: 0.5rem;
      padding: 0.5rem 0.65rem; margin-bottom: 0.8rem;
    }
    .gs-filterbar input[type="search"] {
      flex: 1; min-width: 200px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.4rem; color: var(--fg); padding: 0.32rem 0.55rem; font-size: 0.76rem;
    }
    .gs-filterbar select {
      background: var(--surface); border: 1px solid var(--border); border-radius: 0.4rem;
      color: var(--fg); padding: 0.32rem 0.45rem; font-size: 0.74rem;
    }
    .gs-chips { display: flex; gap: 0.35rem; flex-wrap: wrap; }
    .gs-chip {
      font-size: 0.7rem; padding: 0.22rem 0.55rem; border-radius: 0.35rem;
      border: 1px solid var(--border); color: var(--muted); background: var(--surface);
      cursor: pointer; white-space: nowrap;
    }
    .gs-chip.on { color: var(--fg); border-color: var(--accent); }
    .gs-rescount { font-size: 0.7rem; color: var(--muted); margin-left: auto; }

    .gs-list { display: flex; flex-direction: column; gap: 0.55rem; }
    .gs-card {
      display: grid; grid-template-columns: 1.6fr 1.9fr 1fr; gap: 1rem;
      background: var(--bg); border: 1px solid var(--border); border-radius: 0.5rem;
      padding: 0.75rem 0.85rem; cursor: pointer; text-decoration: none; color: inherit;
    }
    .gs-card:hover { border-color: var(--accent); }
    .gs-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .gs-card-name { font-weight: 700; font-size: 0.9rem; color: var(--fg); }
    .gs-card-sub { font-size: 0.7rem; color: var(--muted); margin-top: 0.25rem; }
    .gs-cpills { display: flex; gap: 0.35rem; align-items: center; margin-top: 0.45rem; flex-wrap: wrap; }
    .gs-cpill {
      font-size: 0.6rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em;
      border-radius: 0.25rem; padding: 0.05rem 0.35rem; border: 1px solid var(--border);
    }
    .gs-cpill.sev-critical, .gs-cpill.sev-high { color: var(--red); border-color: rgba(255,87,101,0.5); }
    .gs-cpill.sev-medium { color: var(--yellow); border-color: rgba(255,204,0,0.45); }
    .gs-cpill.sev-low { color: #a5d6ff; }
    .gs-cpill.observe { color: #a5d6ff; }
    .gs-cpill.enforce { color: var(--yellow); border-color: rgba(255,204,0,0.45); }
    .gs-cpill.on { color: var(--green); }
    .gs-cpill.off { color: var(--muted); }
    .gs-pbar { display: flex; height: 16px; border-radius: 4px; overflow: hidden; border: 1px solid var(--border); }
    .gs-pbar > span { display: flex; align-items: center; justify-content: center; font-size: 0.56rem; color: #04101f; font-weight: 700; }
    .gs-legend { font-size: 0.68rem; color: var(--muted); margin-top: 0.35rem; }
    .gs-cr { text-align: right; font-size: 0.7rem; color: var(--muted); }
    .gs-cr .big { font-size: 1.15rem; font-weight: 700; color: var(--fg); line-height: 1.1; }
    .gs-view { color: var(--accent); font-size: 0.72rem; font-weight: 600; margin-top: 0.35rem; }
    @media (max-width: 760px) { .gs-card { grid-template-columns: 1fr; } }

    /* ── Detail panel ──────────────────────────────────────── */
    .detail-panel {
      margin-top: 0.5rem; padding: 1rem;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.5rem;
    }
    .detail-panel h3 { font-size: 0.9rem; margin-bottom: 0.5rem;
                       display: flex; align-items: center; gap: 0.5rem; }
    .kv { display: grid; grid-template-columns: 130px 1fr; gap: 0.3rem 1rem;
          font-size: 0.78rem; margin-bottom: 0.75rem; }
    .kv .k { color: var(--muted); }
    /* let long unbreakable values (registry key paths) wrap instead of clipping */
    .kv > div { min-width: 0; overflow-wrap: anywhere; }
    .detail-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    .detail-table th {
      text-align: left; padding: 0.35rem 0.5rem;
      border-bottom: 2px solid var(--border); color: var(--muted);
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
    }
    .detail-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); }
    .detail-table tr:hover { background: var(--mds-color-state-hover); }
    pre.yaml {
      background: var(--bg); border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.75rem; font-family: var(--mono); font-size: 0.72rem;
      overflow-x: auto; white-space: pre; color: var(--fg);
    }

    /* ── Forms (create Guard / Baseline, push) ─────────────── */
    .gs-form label { display: block; font-size: 0.72rem; color: var(--muted);
                     margin: 0.6rem 0 0.2rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .gs-form input, .gs-form select, .gs-form textarea {
      width: 100%; background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.3rem; padding: 0.4rem 0.5rem;
      font-size: 0.8rem; font-family: inherit;
    }
    .gs-form textarea { font-family: var(--mono); min-height: 80px; }
    .form-row { display: flex; gap: 0.75rem; }
    .form-row > div { flex: 1; }
    .form-actions { margin-top: 1rem; display: flex; gap: 0.5rem; }

    /* ── Push panel ────────────────────────────────────────── */
    .push-row { display: flex; gap: 0.75rem; align-items: flex-end; flex-wrap: wrap; }
    .push-row > div { flex: 1; min-width: 220px; }

    /* ── Empty / loading states ────────────────────────────── */
    .empty-state { text-align: center; padding: 2rem 1rem; color: var(--subtle); font-size: 0.85rem; }
    .mock-note {
      font-size: 0.68rem; color: var(--subtle); font-style: italic;
      margin-top: 0.5rem;
    }

    /* ── Buttons ───────────────────────────────────────────── */
    .btn { height: auto; padding: 0.3rem 0.8rem; font-size: 0.75rem; border: none; cursor: pointer; }
    .btn-secondary { background: var(--surface); color: var(--fg); border: 1px solid var(--border); }
    .btn-sm { padding: 0.2rem 0.5rem; font-size: 0.7rem; }

    .htmx-indicator { display: none; color: var(--muted); font-size: 0.75rem; }
    .htmx-request .htmx-indicator, .htmx-request.htmx-indicator { display: inline; }

    /* ── New Guard modal ───────────────────────────────────── */
    .gs-modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.62);
      display: none; align-items: flex-start; justify-content: center;
      z-index: 1000; padding: 3rem 1rem; overflow-y: auto;
    }
    .gs-modal-overlay.open { display: flex; }
    .gs-modal-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.6rem; width: 100%; max-width: 560px;
      display: flex; flex-direction: column; overflow: hidden;
      box-shadow: 0 12px 48px rgba(0,0,0,0.55);
      /* No height cap: the card grows to its content and the overlay
         (overflow-y:auto, top-aligned) scrolls the whole modal when tall — so
         the surface always covers every field and nothing is clipped. */
    }
    .gs-modal-header, .gs-modal-footer {
      display: flex; align-items: center; padding: 0.8rem 1.1rem; flex: none;
    }
    .gs-modal-header { justify-content: space-between; border-bottom: 1px solid var(--border); }
    .gs-modal-header h3 { font-size: 0.95rem; font-weight: 700; }
    .gs-modal-footer { justify-content: flex-end; gap: 0.5rem; border-top: 1px solid var(--border); }
    .gs-modal-body { padding: 1.1rem; }
    .gs-modal-close {
      background: none; border: none; color: var(--muted);
      font-size: 1.4rem; line-height: 1; cursor: pointer; padding: 0 0.2rem;
    }
    .gs-modal-close:hover { color: var(--fg); }

    /* Schema-driven form helpers */
    .gs-field { margin-bottom: 0.6rem; }
    .gs-hint { color: var(--subtle); font-size: 0.68rem; margin-top: 0.2rem; line-height: 1.35; }
    .gs-trigger-fields {
      border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.7rem 0.8rem; margin: 0.5rem 0;
    }
    .gs-trigger-fields[hidden], .gs-res-field[hidden] { display: none; }
    .gs-advanced { margin: 0.6rem 0; }
    .gs-advanced > summary {
      cursor: pointer; font-size: 0.74rem; color: var(--muted);
      padding: 0.3rem 0; user-select: none; list-style: none;
    }
    .gs-advanced > summary::-webkit-details-marker { display: none; }
    .gs-advanced > summary::before { content: "\25B8\00a0"; }
    .gs-advanced[open] > summary::before { content: "\25BE\00a0"; }
    .gs-advanced[open] > summary { color: var(--fg); }
    .gs-radio-row { display: flex; gap: 1.2rem; margin: 0.3rem 0 0.2rem; }
    .gs-radio {
      display: flex; align-items: center; gap: 0.35rem; margin: 0;
      font-size: 0.82rem; cursor: pointer; text-transform: none; letter-spacing: normal;
      color: var(--fg);
    }
    .gs-radio input { width: auto; }

    /* New Baseline — member-guards typeahead + chips */
    .bl-guard-picker { display: flex; gap: 0.5rem; align-items: center; }
    .bl-guard-picker input { flex: 1 1 auto; width: auto; min-width: 0; }
    .bl-guard-picker .btn { flex: none; }
    .bl-chips { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem; }
    .bl-chip {
      display: inline-flex; align-items: center; gap: 0.3rem;
      background: var(--mds-color-state-selected); color: var(--fg);
      border: 1px solid var(--border); border-radius: 1rem;
      padding: 0.15rem 0.3rem 0.15rem 0.6rem; font-size: 0.75rem;
    }
    .bl-chip-x {
      background: none; border: none; color: var(--muted);
      cursor: pointer; font-size: 0.95rem; line-height: 1; padding: 0 0.2rem;
    }
    .bl-chip-x:hover { color: var(--red); }
  </style>
)HTM"
    // Split point 1 (MSVC C2026 — see file header). Adjacent literals concat.
    R"HTM(</head>
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
    <button class="context-bell" title="Notifications">
      <svg class="icon"><use href="/static/icons.svg#bell"></use></svg>
    </button>
  </div>

  <div class="content">

    <div class="page-header">
      <div>
        <h1>Guardian</h1>
        <div class="subtitle">Guaranteed State enforcement &mdash; live status, Guards &amp; Baselines</div>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary"
                onclick="guardianOpenModal()"
                hx-get="/fragments/guardian/guard-form"
                hx-target="#guardian-modal-content" hx-swap="innerHTML">
          + New Guard
        </button>
        <button class="btn btn-secondary"
                onclick="guardianOpenModal()"
                hx-get="/fragments/guardian/baseline-form"
                hx-target="#guardian-modal-content" hx-swap="innerHTML">
          + New Baseline
        </button>
        <button class="btn btn-secondary"
                hx-get="/fragments/guardian/status?view=fleet"
                hx-target="#guardian-status" hx-swap="innerHTML">
          <svg class="icon" style="width:14px;height:14px"><use href="/static/icons.svg#refresh-cw"></use></svg>
          Refresh
        </button>
      </div>
    </div>

    <!-- ── Status overview (view-switchable rollup) ─────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#shield"></use></svg>
        Fleet Status
        <span class="htmx-indicator" style="margin-left:auto">Refreshing&hellip;</span>
      </div>
      <div class="section-body">
        <div class="view-switch">
          <button class="view-btn active" hx-get="/fragments/guardian/status?view=fleet"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">Fleet</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=guard"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Guard</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=baseline"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Baseline</button>
        </div>
        <div id="guardian-status"
             hx-get="/fragments/guardian/status?view=fleet"
             hx-trigger="load" hx-swap="innerHTML">
          <div class="empty-state">Loading status&hellip;</div>
        </div>
      </div>
    </div>

    <!-- ── Guards | Events ──────────────────────────────────── -->
    <div class="gs-grid">
      <div class="section">
        <div class="section-header">
          <svg class="icon"><use href="/static/icons.svg#list"></use></svg>
          Guards
        </div>
        <div class="section-body">
          <div id="guardian-guards"
               hx-get="/fragments/guardian/guards"
               hx-trigger="load" hx-swap="innerHTML">
            <div class="empty-state">Loading guards&hellip;</div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <svg class="icon"><use href="/static/icons.svg#activity"></use></svg>
          Recent Events
          <input type="search" id="gs-event-q" placeholder="Filter events&hellip;"
                 oninput="gsEventFilter()" aria-label="Filter recent events"
                 style="margin-left:auto;background:var(--surface);border:1px solid var(--border);border-radius:0.4rem;color:var(--fg);padding:0.2rem 0.45rem;font-size:0.72rem;max-width:170px">
          <span class="htmx-indicator">&middot;&middot;&middot;</span>
        </div>
        <div class="section-body">
          <div id="guardian-events"
               hx-get="/fragments/guardian/events"
               hx-trigger="load, every 5s" hx-swap="innerHTML">
            <div class="empty-state">Loading events&hellip;</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Baselines ────────────────────────────────────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#layers"></use></svg>
        Baselines
        <span style="margin-left:auto;font-size:0.7rem;font-weight:400;color:var(--muted)">
          deploy is Baseline-level
        </span>
      </div>
      <div class="section-body">
        <div id="guardian-baselines"
             hx-get="/fragments/guardian/baselines"
             hx-trigger="load" hx-swap="innerHTML">
          <div class="empty-state">Loading baselines&hellip;</div>
        </div>
      </div>
    </div>

    <!-- ── Detail drill-in (guard / baseline / forms) ───────── -->
    <!-- Guard / Baseline detail opens in the modal (#guardian-modal-content),
         like New Guard — no inline detail panel at the bottom of the page. -->

  </div>

  <!-- New Guard authoring modal — the form fragment swaps into #guardian-modal-content.
       Clicking the dimmed backdrop (but not the card) closes it. -->
  <div class="gs-modal-overlay" id="guardian-modal"
       onclick="if(event.target===this)guardianCloseModal()">
    <div id="guardian-modal-content"></div>
  </div>

  <div id="toast-container" class="toast-container"></div>
)HTM"
    // Split point 2 (MSVC C2026 — see file header). Adjacent literals concat.
    R"HTM(
  <script>
    /* ── View switcher active-state toggle ─────────────────── */
    function gsSetActive(btn) {
      var btns = btn.parentNode.querySelectorAll('.view-btn');
      for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
      btn.classList.add('active');
    }

    /* Fleet stat cards → status sub-view navigation. Clicks the matching view
       button (which runs the hx-get + sets the active tab), and stashes a filter
       to apply once the new fragment settles (htmx:afterSettle below). */
    function gsGoView(view, filterState) {
      window.__gsPendingFilter = (view === 'guard') ? (filterState || null) : null;
      var btn = document.querySelector('.view-switch .view-btn[hx-get*="view=' + view + '"]');
      if (btn) btn.click();
    }
    document.body.addEventListener('htmx:afterSettle', function (e) {
      if (e.target && e.target.id === 'guardian-status' && window.__gsPendingFilter) {
        var fs = window.__gsPendingFilter;
        window.__gsPendingFilter = null;
        var chip = document.querySelector('#guardian-status .gs-chip[data-gstate="' + fs + '"]');
        if (chip) gsGuardState(chip);
      }
    });

    /* ── By-Guard list filter: search + state chip + severity + mode ──────
       The fragment carries the markup (chips/inputs call these); the functions
       live here on the page so they survive HTMX fragment swaps. State is read
       from the active chip, so a freshly-swapped fragment (All active, empty
       search, "Any" selects) needs no explicit reset. */
    function gsGuardFilter() {
      var qi = document.getElementById('gs-guard-q');
      var q = (qi ? qi.value : '').toLowerCase().trim();
      var sevEl = document.getElementById('gs-guard-sev');
      var modeEl = document.getElementById('gs-guard-mode');
      var sev = sevEl ? sevEl.value : 'all';
      var mode = modeEl ? modeEl.value : 'all';
      var activeChip = document.querySelector('#guardian-status .gs-chip.on[data-gstate]');
      var st = activeChip ? activeChip.getAttribute('data-gstate') : 'all';
      var cards = document.querySelectorAll('#guardian-status .gs-card[data-gstate]');
      var shown = 0;
      for (var i = 0; i < cards.length; i++) {
        var c = cards[i];
        var ok = (st === 'all' || c.getAttribute('data-gstate') === st)
          && (sev === 'all' || c.getAttribute('data-gsev') === sev)
          && (mode === 'all' || c.getAttribute('data-gmode') === mode)
          && (!q || (c.getAttribute('data-gname') || '').indexOf(q) !== -1);
        c.style.display = ok ? '' : 'none';
        if (ok) shown++;
      }
      var rc = document.getElementById('gs-guard-rc');
      if (rc) rc.textContent = shown + ' of ' + cards.length + ' guards';
    }
    function gsGuardState(btn) {
      var chips = btn.parentNode.querySelectorAll('.gs-chip');
      for (var i = 0; i < chips.length; i++) chips[i].classList.remove('on');
      btn.classList.add('on');
      gsGuardFilter();
    }

    /* ── Recent Events free-text filter ───────────────────────────────────
       The search box lives in the section header (outside #guardian-events),
       so it survives the panel's 5s auto-refresh; the body htmx:afterSettle
       listener below re-runs this after each swap so the active query keeps
       applying. Matches the whole event row text (time, type, Guard name, agent). */
    function gsEventFilter() {
      var qi = document.getElementById('gs-event-q');
      var q = (qi ? qi.value : '').toLowerCase().trim();
      var items = document.querySelectorAll('#guardian-events .event-item');
      for (var i = 0; i < items.length; i++) {
        var t = (items[i].textContent || '').toLowerCase();
        items[i].style.display = (!q || t.indexOf(q) !== -1) ? '' : 'none';
      }
    }
    // Re-apply the events filter after each 5s panel refresh. A body listener,
    // NOT hx-on — the page CSP forbids 'unsafe-eval' and htmx compiles hx-on
    // handlers with new Function (which CSP blocks).
    document.body.addEventListener('htmx:afterSettle', function (e) {
      if (e.target && e.target.id === 'guardian-events') gsEventFilter();
    });

    /* ── New Guard modal ───────────────────────────────────── */
    function guardianOpenModal() {
      var m = document.getElementById('guardian-modal');
      if (m) m.classList.add('open');
    }
    function guardianCloseModal() {
      var m = document.getElementById('guardian-modal');
      if (m) m.classList.remove('open');
      var c = document.getElementById('guardian-modal-content');
      if (c) c.innerHTML = '';
    }
    /* Trigger-type picker: reveal + enable only the chosen trigger's fieldset.
       Disabled fieldsets are skipped by HTML5 validation and (belt-and-braces with
       the namespaced field names) cannot shadow the active type's params on submit. */
    function guardianPickTrigger(sel) {
      var form = sel.closest('form');
      if (!form) return;
      var sets = form.querySelectorAll('fieldset[data-trigger]');
      for (var i = 0; i < sets.length; i++) {
        var on = sets[i].getAttribute('data-trigger') === sel.value;
        sets[i].hidden = !on;
        sets[i].disabled = !on;
      }
    }
    /* New Baseline — add the typed/picked guard as a removable chip with a hidden
       "guards" input so it submits. De-dupes; Enter or the Add button calls this. */
    function guardianAddGuardChip() {
      var input = document.getElementById('bl-guard-input');
      var box = document.getElementById('bl-selected-guards');
      if (!input || !box) return;
      var val = (input.value || '').trim();
      if (!val) return;
      var existing = box.querySelectorAll('input[name="guards"]');
      for (var i = 0; i < existing.length; i++) {
        if (existing[i].value === val) { input.value = ''; return; }
      }
      var chip = document.createElement('span');
      chip.className = 'bl-chip';
      var hid = document.createElement('input');
      hid.type = 'hidden'; hid.name = 'guards'; hid.value = val;
      chip.appendChild(hid);
      chip.appendChild(document.createTextNode(val + ' '));
      var x = document.createElement('button');
      x.type = 'button'; x.className = 'bl-chip-x'; x.textContent = '×';
      x.onclick = function() { chip.remove(); };
      chip.appendChild(x);
      box.appendChild(chip);
      input.value = '';
      input.focus();
    }

    /* Mode picker: remediation/resilience options apply only in Enforce mode. */
    function guardianPickMode(sel) {
      var form = sel.closest('form');
      if (!form) return;
      var blocks = form.querySelectorAll('.gs-enforce-only');
      var on = sel.value === 'enforce';
      for (var i = 0; i < blocks.length; i++) blocks[i].hidden = !on;
    }
    /* Resilience: show only the numeric knobs load-bearing for the chosen mode. */
    function guardianPickResilienceMode(sel) {
      var box = sel.closest('.gs-resilience');
      if (!box) return;
      var fields = box.querySelectorAll('[data-modes]');
      for (var i = 0; i < fields.length; i++) {
        var modes = (fields[i].getAttribute('data-modes') || '').split(' ');
        fields[i].hidden = modes.indexOf(sel.value) === -1;
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
    /* Close the detail modal in response to an HX-Trigger (used after a Baseline
       delete, where the modal's subject no longer exists). */
    document.body.addEventListener('guardianModalClose', function() {
      guardianCloseModal();
    });

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
    /* Ctrl+K / Cmd+K — navigate to dashboard command palette */
    document.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        window.location.href = '/?palette=1';
      }
      if (e.key === 'Escape') {
        var m = document.getElementById('guardian-modal');
        if (m && m.classList.contains('open')) guardianCloseModal();
      }
    });
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
