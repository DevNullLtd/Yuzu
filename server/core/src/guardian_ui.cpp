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

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kGuardianPageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Guardian</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    /* ── Content ───────────────────────────────────────────── */
    .content { padding: 22px 28px 36px; }

    /* ── Page header ──────────────────────────────────────── */
    .page-header { margin-bottom: 22px; }

    /* ── Panels: bordered regions, not floating cards ──────── */
    .section {
      background: var(--surface); border: 1px solid var(--line);
      border-radius: var(--rad-panel); margin-bottom: 22px; min-width: 0; overflow: hidden;
    }
    .section-header {
      display: flex; flex-wrap: wrap; align-items: center; gap: 8px 14px;
      padding: 12px 16px; font-size: 14px; font-weight: 600;
      border-bottom: 1px solid var(--line);
    }
    .section-body { padding: 16px; }
    .section-body.flush { padding: 0; }
    .gs-meta { font-size: 12.5px; font-weight: 400; color: var(--mut); }
    .gs-push { margin-left: auto; }
    .gs-hd-search {
      margin-left: auto; height: 28px; max-width: 190px; padding: 0 10px; font-size: 13px;
      color: var(--ink); background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    /* Fleet Status leads the page: no box, a top rule only (a flat panel). */
    .section.flat {
      background: none; border-width: 1px 0 0; border-radius: 0;
      border-color: var(--line2); overflow: visible;
    }
    .section.flat .section-header { padding-left: 0; padding-right: 0; border-bottom: 0; }
    .section.flat .section-body { padding: 0 0 4px; }

    /* ── Readout row (summary figures): one bordered region, 1px rules between ── */
    .stat-cards {
      display: flex; flex-wrap: wrap; gap: 1px; overflow: hidden; background: var(--line);
      border: 1px solid var(--line); border-radius: var(--rad-panel);
    }
    .stat-card { flex: 1 1 170px; min-width: 0; padding: 14px 18px; background: var(--surface); }
    .stat-num { font-size: 26px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; color: var(--ink); }
    .stat-label { color: var(--mut); font-size: 13px; margin-top: 2px; }
    .stat-sub { color: var(--mut); font-size: 12.5px; margin-top: 4px; }
    .stat-num.good { color: var(--ok); }
    .stat-num.warn { color: var(--warn); }
    .stat-num.bad  { color: var(--bad); }
    .stat-num.info { color: var(--primary-h); }
    .stat-num.mute { color: var(--mut); }
    /* Clickable Fleet stat cards (navigate into the matching status sub-view). */
    .stat-card-nav { cursor: pointer; transition: background-color .12s; }
    .stat-card-nav:hover { background: var(--surface2); }
    .gs-sech { font-size: 14px; font-weight: 600; color: var(--ink); margin: 22px 0 8px; }
    .gs-worst { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }

    /* Status text + banners (sentence-case; status colour only on status) */
    .gs-ok, .gs-warn, .gs-bad, .gs-ni { font-weight: 500; }
    .gs-ok { color: var(--ok); } .gs-warn { color: var(--warn); } .gs-bad { color: var(--bad); }
    .gs-ni { color: var(--c5); }
    .gs-banner {
      max-width: 640px; margin-bottom: 12px; padding: 12px 14px; font-size: 13.5px; color: var(--ink2);
      background: var(--surface2); border: 1px solid var(--line2); border-radius: var(--rad-panel);
    }
    .gs-banner b { color: var(--ink); }
    .gs-banner.warn { border-color: color-mix(in srgb, var(--warn) 50%, var(--line2)); }
    .gs-banner.err  { border-color: color-mix(in srgb, var(--bad) 50%, var(--line2)); }
    .gs-banner.ni   { border-color: color-mix(in srgb, var(--c5) 50%, var(--line2)); }
    .section-body.flush .gs-banner { margin: 12px 16px 0; }

    /* Fleet census bar, legend and 7-day remediation trend (flat fills) */
    .gs-cbar { display: flex; gap: 2px; height: 20px; max-width: 520px; border-radius: 3px; overflow: hidden; background: var(--bg); }
    .gs-cbar > div { display: flex; align-items: center; justify-content: center; overflow: hidden;
                     white-space: nowrap; font-size: 11px; font-weight: 600; color: var(--on-primary); }
    .gs-leg { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 13px; color: var(--mut); }
    .gs-leg i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: middle; }
    .gs-leg b { color: var(--ink); font-weight: 600; }
    .gs-trend { display: flex; align-items: flex-end; gap: 6px; height: 84px; margin-top: 6px; }
    .gs-trend > div { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 3px; }
    .gs-trend .bar { width: 60%; display: flex; flex-direction: column-reverse; min-height: 2px;
                     border-radius: 2px 2px 0 0; overflow: hidden; }
    .gs-trend small { font-size: 12px; color: var(--mut); }

    /* Fleet worst-of badge — the single most-severe state present. */
    .worst-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 1px 8px; border-radius: 3px; font-size: 12.5px; font-weight: 500;
    }
    .worst-good { background: var(--mds-color-bg-success-tinted);   color: var(--ok); }
    .worst-warn { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .worst-bad  { background: var(--mds-color-bg-error-tinted);  color: var(--bad); }

    /* ── Guard status badges (full taxonomy) ───────────────── */
    .gs-badge {
      display: inline-block; padding: 1px 8px; border-radius: 3px;
      font-size: 12.5px; font-weight: 500; white-space: nowrap;
    }
    .gs-compliant          { background: var(--mds-color-bg-success-tinted);   color: var(--ok); }
    .gs-drifted            { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .gs-remediation_failed { background: var(--mds-color-bg-error-tinted);  color: var(--bad); }
    .gs-errored            { background: var(--mds-color-bg-error-tinted);  color: var(--bad); }
    .gs-exempt, .gs-stale  { background: var(--surface2); color: var(--mut); }

    /* guard_healthy signal — distinct from compliance state. */
    .health-ok   { color: var(--ok); }
    .health-bad  { color: var(--bad); }

    /* ── Segmented controls: view switcher (fleet / guard / baseline) + state chips ── */
    .view-switch, .gs-chips {
      display: inline-flex; flex-wrap: wrap; gap: 2px; padding: 2px; background: var(--bg);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .view-switch { margin-bottom: 16px; }
    .view-btn, .gs-chip {
      display: flex; align-items: center; gap: 6px; height: calc(var(--ctl) - 8px); min-height: 26px;
      padding: 0 12px; font: inherit; font-weight: 500; color: var(--mut); white-space: nowrap;
      cursor: pointer; background: none; border: 0; border-radius: 2px;
    }
    .view-btn:hover, .gs-chip:hover { color: var(--ink); }
    .view-btn.active, .gs-chip.on {
      color: var(--ink); font-weight: 600; background: var(--raise); box-shadow: inset 0 0 0 1px var(--line2);
    }

    /* ── Two-column grid: guards | events ──────────────────── */
    .gs-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 22px; align-items: start; margin-bottom: 22px;
    }
    .gs-grid > .section { margin-bottom: 0; }
    @media (max-width: 900px) { .gs-grid { grid-template-columns: 1fr; } }

    /* ── Guard list ────────────────────────────────────────── */
    .guard-list { display: flex; flex-direction: column; }
    .guard-item { padding: 12px 16px; cursor: pointer; border-bottom: 1px solid var(--line); transition: background-color .12s; }
    .guard-item:last-child { border-bottom: 0; }
    .guard-item:hover { background: var(--surface2); }
    .guard-item-top { display: flex; align-items: center; gap: 8px; }
    .guard-name { font-weight: 600; color: var(--ink); }
    .guard-os {
      font-family: var(--mds-font-family-mono); font-size: 11.5px; color: var(--mut);
      border: 1px solid var(--line2); border-radius: 3px; padding: 0 5px;
    }
    .guard-meta { font-size: 13px; color: var(--mut); margin-top: 4px;
                  display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

    /* ── Guard item: left content column + right control column ─ */
    .gi-main { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
    .gi-left { min-width: 0; }
    .gi-row1 { display: flex; align-items: center; gap: 10px; }
    .gi-meta { font-size: 13px; color: var(--mut); margin-top: 4px;
               display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
    .gi-mode { font-weight: 500; font-size: 13px; }
    .gi-mode.observe { color: var(--mut); }
    .gi-mode.enforce { color: var(--info); }
    .gi-right { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex: none; }
    .gi-state { font-size: 12.5px; font-weight: 500; }
    .gi-state.on  { color: var(--ok); }
    .gi-state.off { color: var(--mut); }
    .btn.gi-act { min-width: 74px; justify-content: center; height: 28px; padding: 0 10px; font-size: 13px; }
    .gi-deploy { margin-top: 10px; font-size: 13px; }
    .gi-dep-on  { color: var(--ok); font-weight: 500; }
    .gi-dep-off { color: var(--mut); }
    .gi-bl { color: var(--primary); cursor: pointer; }
    .gi-bl:hover { text-decoration: underline; }
)HTM"
    // Split point 0 (MSVC C2026 — string too big): the <style> block crossed 16 KB
    // after the guard-item CSS grew. Adjacent string literals concatenate at compile
    // time, so this is purely a source-level cut (no stray whitespace enters the HTML).
    R"HTM(
    /* ── Event timeline ────────────────────────────────────── */
    .event-list { display: flex; flex-direction: column; }
    .event-item { padding: 10px 16px; border-bottom: 1px solid var(--line); font-size: 13.5px; }
    .event-item:last-child { border-bottom: none; }
    .event-top { display: flex; align-items: center; gap: 8px; }
    .event-time { font-family: var(--mds-font-family-mono); font-size: 12.5px; color: var(--mut); }
    .event-type { padding: 1px 8px; border-radius: 3px; font-size: 12.5px; font-weight: 500; }
    .et-drift_detected, .et-resilience_escalated { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .et-drift_remediated    { background: var(--mds-color-bg-success-tinted);   color: var(--ok); }
    .et-remediation_failed, .et-guard_unhealthy { background: var(--mds-color-bg-error-tinted); color: var(--bad); }
    .et-guard_armed         { background: var(--mds-color-bg-info-tinted); color: var(--info); }
    .et-generic             { background: var(--surface2); color: var(--mut); }
    .event-detail { color: var(--mut); margin-top: 4px; }
    .event-detail strong { color: var(--ink); font-weight: 600; }

    /* ── Baseline rows ─────────────────────────────────────── */
    .baseline-card { padding: 12px 16px; border-bottom: 1px solid var(--line); }
    .baseline-card:last-child { border-bottom: 0; }
    .baseline-top { display: flex; align-items: center; gap: 12px; }
    .baseline-name { font-weight: 600; color: var(--ink); text-decoration: none; cursor: pointer; }
    .baseline-name:hover { color: var(--primary-h); }
    .baseline-state { font-size: 13px; font-weight: 500; }
    .baseline-pending { font-size: 12.5px; font-weight: 500; color: var(--warn); }
    .baseline-scope { font-size: 13px; color: var(--mut); margin-top: 4px; }
    .lifecycle-draft    { color: var(--mut); }
    .lifecycle-deployed { color: var(--ok); }

    /* ── By-Guard / By-Baseline LIST rows + filter (view-switch) ───────── */
    .gs-filterbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .gs-filterbar input[type="search"], .gs-filterbar select {
      height: var(--ctl); padding: 0 10px; font-size: 14px; color: var(--ink);
      background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .gs-filterbar input[type="search"] { flex: 1; min-width: 200px; }
    .gs-rescount { font-size: 12.5px; color: var(--mut); margin-left: auto; }

    .gs-list { display: flex; flex-direction: column; background: var(--surface);
               border: 1px solid var(--line); border-radius: var(--rad-panel); overflow: hidden; }
    .gs-card {
      display: grid; grid-template-columns: 1.6fr 1.9fr 1fr; gap: 16px; padding: 12px 16px;
      cursor: pointer; text-decoration: none; color: inherit; border-bottom: 1px solid var(--line);
      transition: background-color .12s;
    }
    .gs-card:last-child { border-bottom: 0; }
    .gs-card:hover { background: var(--surface2); }
    .gs-card:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
    .gs-card-name { font-weight: 600; color: var(--ink); }
    .gs-card-sub { font-size: 13px; color: var(--mut); margin-top: 4px; }
    .gs-cpills { display: flex; gap: 6px; align-items: center; margin-top: 8px; flex-wrap: wrap; }
    .gs-cpill {
      font-size: 12.5px; font-weight: 500; border-radius: 3px; padding: 1px 8px;
      color: var(--mut); background: var(--surface2);
    }
    .gs-cpill.sev-critical, .gs-cpill.sev-high { color: var(--bad); background: var(--mds-color-bg-error-tinted); }
    .gs-cpill.sev-medium { color: var(--warn); background: var(--mds-color-bg-warning-tinted); }
    .gs-cpill.sev-low, .gs-cpill.enforce { color: var(--info); background: var(--mds-color-bg-info-tinted); }
    .gs-cpill.on { color: var(--ok); background: var(--mds-color-bg-success-tinted); }
    .gs-pbar { display: flex; gap: 2px; height: 12px; border-radius: 3px; overflow: hidden; background: var(--bg); }
    .gs-pbar > span { display: flex; align-items: center; justify-content: center; font-size: 11px; color: var(--on-primary); font-weight: 600; }
    .gs-legend { font-size: 13px; color: var(--mut); margin-top: 6px; }
    .gs-cr-gap { margin-top: 4px; }
    .gs-row-acts { display: flex; gap: 6px; }
    .gs-cr { text-align: right; font-size: 12.5px; color: var(--mut); }
    .gs-cr .big { font-size: 20px; font-weight: 500; letter-spacing: -.02em; color: var(--ink); line-height: 1.15; }
    .gs-view { color: var(--primary); font-size: 13px; font-weight: 500; margin-top: 6px; }
    @media (max-width: 760px) { .gs-card { grid-template-columns: 1fr; } }

    /* ── Key / value rows ──────────────────────────────────── */
    .kv { display: grid; grid-template-columns: 130px 1fr; gap: 6px 16px;
          font-size: 13.5px; margin-bottom: 12px; }
    .kv .k { color: var(--mut); }
    .gs-mono { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    /* let long unbreakable values (registry key paths) wrap instead of clipping */
    .kv > div { min-width: 0; overflow-wrap: anywhere; }

    /* ── Forms (create Guard / Baseline, push) ─────────────── */
    .gs-form label { display: block; font-size: 13px; font-weight: 500; color: var(--ink2); margin: 12px 0 4px; }
    .gs-modal-body > label:first-child { margin-top: 0; }
    .gs-form input, .gs-form select, .gs-form textarea {
      width: 100%; height: var(--ctl); padding: 0 10px; font: inherit; color: var(--ink);
      background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .gs-form input[type="radio"], .gs-form input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--primary); }
    .gs-form textarea { height: auto; min-height: 84px; padding: 8px 10px;
                        font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .form-row { display: flex; gap: 16px; }
    .form-row > div { flex: 1; }

    /* ── Empty / loading states ────────────────────────────── */
    .empty-state { text-align: center; padding: 32px 16px; color: var(--mut); font-size: 13.5px; }
    .empty-state b { display: block; color: var(--ink); font-weight: 600; margin-bottom: 4px; }
    .mock-note { font-size: 12.5px; color: var(--mut); margin-top: 8px; }

    /* ── Buttons ───────────────────────────────────────────── */
    .btn {
      display: inline-flex; align-items: center; gap: 6px; height: var(--ctl); padding: 0 14px;
      font-size: 14px; font-weight: 500; white-space: nowrap; cursor: pointer; color: var(--ink);
      background: var(--raise); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      transition: background-color .12s, border-color .12s;
    }
    .btn:hover:not(:disabled) { background: var(--surface2); border-color: var(--mut); opacity: 1; }
    .btn-primary, .btn-primary:hover:not(:disabled) { color: var(--on-primary); background: var(--primary); border-color: var(--primary); font-weight: 600; }
    .btn-primary:hover:not(:disabled) { background: var(--primary-h); border-color: var(--primary-h); }
    .btn-secondary { color: var(--ink); background: var(--raise); border: 1px solid var(--line2); }
    .btn-sm { height: 28px; padding: 0 10px; font-size: 13px; }

    .htmx-indicator { display: none; color: var(--mut); font-size: 13px; }
    .htmx-request .htmx-indicator, .htmx-request.htmx-indicator { display: inline; }

    /* ── New Guard modal ───────────────────────────────────── */
    .gs-modal-overlay {
      position: fixed; inset: 0; background: var(--mds-color-state-overlay-scrim);
      display: none; align-items: flex-start; justify-content: center;
      z-index: 1000; padding: 48px 16px; overflow-y: auto;
    }
    .gs-modal-overlay.open { display: flex; }
    .gs-modal-card {
      background: var(--raise); border: 1px solid var(--line2);
      border-radius: var(--rad-over); width: 100%; max-width: 560px;
      display: flex; flex-direction: column; overflow: hidden;
      box-shadow: var(--shadow);
      /* No height cap: the card grows to its content and the overlay
         (overflow-y:auto, top-aligned) scrolls the whole modal when tall — so
         the surface always covers every field and nothing is clipped. */
    }
    .gs-modal-header, .gs-modal-footer {
      display: flex; align-items: center; padding: 12px 16px; flex: none;
    }
    .gs-modal-header { justify-content: space-between; border-bottom: 1px solid var(--line2); }
    .gs-modal-header h3 { font-size: 16px; font-weight: 600; }
    .gs-modal-footer { justify-content: flex-end; gap: 8px; border-top: 1px solid var(--line2); }
    .gs-modal-body { padding: 16px; }
    .gs-modal-close {
      background: none; border: none; color: var(--mut);
      font-size: 22px; line-height: 1; cursor: pointer; padding: 0 4px;
    }
    .gs-modal-close:hover { color: var(--ink); }

    /* Schema-driven form helpers */
    .gs-field { margin-bottom: 10px; }
    .gs-hint { color: var(--mut); font-size: 12.5px; margin-top: 4px; line-height: 1.4; }
    .gs-trigger-fields {
      border: 1px solid var(--line2); border-radius: var(--rad-panel);
      padding: 12px 14px; margin: 8px 0;
    }
    .gs-trigger-fields[hidden], .gs-res-field[hidden] { display: none; }
    .gs-advanced { margin: 10px 0; }
    .gs-advanced > summary {
      cursor: pointer; font-size: 13px; color: var(--mut);
      padding: 4px 0; user-select: none; list-style: none;
    }
    .gs-advanced > summary::-webkit-details-marker { display: none; }
    .gs-advanced > summary::before { content: "\25B8\00a0"; }
    .gs-advanced[open] > summary::before { content: "\25BE\00a0"; }
    .gs-advanced[open] > summary { color: var(--ink); }

    /* New Baseline — member-guards typeahead + chips */
    .bl-guard-picker { display: flex; gap: 8px; align-items: center; }
    .bl-guard-picker input { flex: 1 1 auto; width: auto; min-width: 0; }
    .bl-guard-picker .btn { flex: none; }
    .bl-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .bl-chip {
      display: inline-flex; align-items: center; gap: 4px; color: var(--ink);
      background: var(--surface2); border: 1px solid var(--line2); border-radius: 3px;
      padding: 2px 4px 2px 10px; font-size: 13px;
    }
    .bl-chip-x {
      background: none; border: none; color: var(--mut);
      cursor: pointer; font-size: 15px; line-height: 1; padding: 0 4px;
    }
    .bl-chip-x:hover { color: var(--bad); }
  </style>
)HTM"
    // Split point 1 (MSVC C2026 — see file header). Adjacent literals concat.
    R"HTM(</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <div class="content">

    <div class="page-header">
      <div>
        <h1>Guardian</h1>
        <div class="subtitle">Guaranteed State enforcement &mdash; live status, Guards &amp; Baselines</div>
      </div>
      <div class="header-actions">
        <button class="btn btn-primary"
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
          Refresh
        </button>
      </div>
    </div>

    <!-- ── Status overview (view-switchable rollup) ─────────── -->
    <div class="section flat">
      <div class="section-header">
        Fleet Status
        <span class="htmx-indicator gs-push">Refreshing&hellip;</span>
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
          Guards
        </div>
        <div class="section-body flush">
          <div id="guardian-guards"
               hx-get="/fragments/guardian/guards"
               hx-trigger="load" hx-swap="innerHTML">
            <div class="empty-state">Loading guards&hellip;</div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          Recent Events
          <input type="search" id="gs-event-q" class="gs-hd-search" placeholder="Filter events&hellip;"
                 oninput="gsEventFilter()" aria-label="Filter recent events">
          <span class="htmx-indicator">&middot;&middot;&middot;</span>
        </div>
        <div class="section-body flush">
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
        Baselines
        <span class="gs-meta gs-push">
          deploy is Baseline-level
        </span>
      </div>
      <div class="section-body flush">
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
      close.style.cssText = 'background:none;border:none;color:var(--mut);cursor:pointer;margin-left:auto;font-size:1.2rem;padding:0 0 0 var(--sp-3);';
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

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kGuardianHtml =
    yuzu::server::shell::bake(kGuardianPageTemplate, {.active_key = "guardian"});
// NOLINTEND(cert-err58-cpp)
