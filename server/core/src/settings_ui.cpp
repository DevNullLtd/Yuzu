// Settings page HTML — compiled in its own translation unit.
// HTMX-first. Plain JS only where htmx has no CSP-safe equivalent: clipboard
// copy, and fetch() for the JSON REST v1 routes (engine principals, #5342
// password change/reset). Never `hx-on` — the CSP blocks it (CLAUDE.md).

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kSettingsHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Settings</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <script src="/static/sse.js"></script>
  <style>
    body { min-height: calc(100vh - var(--shell-top-h, 0px)); }

    /* ── Page frame ────────────────────────────────────────── */
    .content {
      max-width: 1200px; padding: 22px 28px 36px;
      display: flex; flex-direction: column; gap: 22px;
    }
    .page-head h1 {
      font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2;
    }
    code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .muted { color: var(--mut); }
    .hint { color: var(--mut); font-size: 12.5px; }
    .section-body a:not(.btn) { color: var(--primary); }

    /* ── Section panels (bordered regions, header + body) ──── */
    .section {
      background: var(--surface); border: 1px solid var(--line);
      border-radius: var(--rad-panel); min-width: 0; overflow: hidden;
    }
    .section-header {
      padding: 12px 16px; font-size: 14px; font-weight: 600;
      border-bottom: 1px solid var(--line);
      display: flex; align-items: center; gap: 8px;
    }
    .section-body { padding: 16px; overflow-x: auto; }
    .section-intro {
      margin: 0 0 12px; max-width: 80ch; font-size: 13px; color: var(--mut);
    }
    .sub-head {
      margin: 16px 0 8px; font-size: 13px; font-weight: 600; color: var(--ink);
    }
    .section-note {
      margin: 12px 0 0; font-size: 12.5px; color: var(--mut);
    }

    /* ── Form elements ─────────────────────────────────────── */
    .form-row {
      display: flex; align-items: center; gap: 16px;
      margin-bottom: 12px;
    }
    .form-row:last-child { margin-bottom: 0; }
    .form-row > label:first-child {
      flex: 0 0 180px; font-size: 13px; color: var(--ink2); font-weight: 500;
    }
    .section-body :is(input:not([type="checkbox"], [type="radio"], [type="range"],
                                [type="file"], [type="hidden"]), select) {
      height: var(--ctl); padding: 0 10px;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font: inherit; font-size: 13.5px; min-width: 0;
    }
    .section-body textarea {
      padding: 8px 10px; background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .form-row input[type="text"], .form-row input[type="password"], .form-row select { flex: 1; }
    .form-row input[type="text"], .form-row input[type="password"] {
      font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .section-body ::placeholder { color: var(--faint); }
    .section-body input[type="checkbox"]:not(.toggle input) {
      accent-color: var(--primary); width: 16px; height: 16px;
    }
    .section-body input[type="range"] { accent-color: var(--primary); }
    .section-body input[type="file"]::file-selector-button {
      height: 28px; margin-right: 10px; padding: 0 10px; cursor: pointer;
      color: var(--ink); background: var(--raise); font: inherit; font-size: 13px; font-weight: 500;
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .section-body :is(input, select, textarea):focus { border-color: var(--primary); }
    .section-body :is(input, select, textarea, summary):focus-visible,
    .toggle input:focus-visible + .slider {
      outline: 2px solid var(--focus); outline-offset: 2px;
    }

    /* ── Switch ────────────────────────────────────────────── */
    .toggle {
      position: relative; display: inline-block; flex: 0 0 36px;
      width: 36px; height: 20px;
    }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle .slider {
      position: absolute; cursor: pointer; inset: 0;
      background: var(--line2); border-radius: 3px;
      transition: background .12s;
    }
    .toggle .slider::before {
      content: ''; position: absolute; top: 2px; left: 2px;
      height: 16px; width: 16px; background: var(--raise); border-radius: 2px;
      transition: left .12s;
    }
    .toggle input:checked + .slider { background: var(--primary); }
    .toggle input:checked + .slider::before { left: 18px; background: var(--on-primary); }

    /* ── File upload ───────────────────────────────────────── */
    .file-upload {
      display: flex; align-items: center; flex-wrap: wrap; gap: 12px;
    }
    .file-name {
      font-size: 12.5px; color: var(--mut); font-family: var(--mds-font-family-mono);
    }

    /* ── Tables ────────────────────────────────────────────── */
    .user-table {
      width: 100%; border-collapse: separate; border-spacing: 0;
      border: 1px solid var(--line); border-radius: var(--rad-panel);
      font-size: 13.5px; overflow: hidden;
    }
    .user-table th {
      text-align: left; padding: 8px 12px; white-space: nowrap;
      background: var(--surface2); border-bottom: 1px solid var(--line);
      color: var(--mut); font-size: 12.5px; font-weight: 500;
    }
    .user-table td {
      padding: var(--cell-y) 12px; border-bottom: 1px solid var(--line);
      color: var(--ink2); vertical-align: middle;
    }
    /* A state class on a <td> must out-rank .user-table td above. */
    .user-table td.muted { color: var(--mut); }
    .user-table td.feedback-error { color: var(--bad); }
    .user-table tbody tr:last-child td { border-bottom: 0; }
    .user-table tbody tr:hover td { background: var(--surface2); }
    .user-table td .btn:not(.add-user-form .btn) {
      height: 28px; padding: 0 8px; background: none; border-color: transparent;
      color: var(--primary); font-size: 13px;
    }
    .user-table td .btn-danger:not(.add-user-form .btn) { color: var(--bad); }
    .user-table td .btn:not(.add-user-form .btn):hover:not(:disabled) {
      background: none; border-color: transparent; opacity: 1; text-decoration: underline;
    }
    .user-table td input:not([type="range"], [type="checkbox"], [type="hidden"],
                             .add-user-form input) { height: 28px; font-size: 13px; }
    .role-badge {
      display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 3px;
      font-size: 12.5px; font-weight: 500; white-space: nowrap;
      background: var(--surface2); color: var(--mut);
    }
    .role-admin { background: var(--mds-color-bg-info-tinted); color: var(--info); }
    .role-ok    { background: var(--mds-color-bg-success-tinted); color: var(--ok); }
    .role-warn  { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .role-bad   { background: var(--mds-color-bg-error-tinted); color: var(--bad); }

    /* ── Feedback ──────────────────────────────────────────── */
    .feedback {
      font-size: 13px; margin-top: 12px; min-height: 1.2em;
    }
    .feedback:empty { display: none; }
    .feedback-ok    { color: var(--ok); }
    .feedback-error { color: var(--bad); }
    .callout, .feedback-warning {
      padding: 12px 14px; border: 1px solid var(--line2);
      border-radius: var(--rad-panel); background: var(--surface2); color: var(--ink2);
      font-size: 13.5px;
    }
    .feedback-warning { border-color: color-mix(in srgb, var(--warn) 50%, var(--line2)); }

    /* ── Add-row forms ─────────────────────────────────────── */
    .add-user-form {
      display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;
      margin-top: 16px; padding-top: 16px;
      border-top: 1px solid var(--line);
    }
    /* #5572 — the base class had no flex-wrap, so a row with enough fields
       (the OTA upload form: platform/arch selects + two file inputs +
       rollout + mandatory + submit, the widest consumer of this class)
       overflows its container with nowrap and pushes the submit button out
       of view with no scroll affordance inside a form row. Wrapping is a
       no-op for every narrower .add-user-form instance that already fits
       on one line. */
    .mini-field {
      display: flex; flex-direction: column; gap: 5px;
      min-width: 0;
    }
    .add-user-form input[type="file"] {
      max-width: 260px;
    }
    .mini-field label {
      font-size: 13px; color: var(--ink2); font-weight: 500;
    }
    /* #5572 — flex-wrap now comes from the .add-user-form base rule; this
       override only needs the layout tweaks still specific to the nested
       password-change variant. */
    .pw-form { margin-top: 4px; padding-top: 0; border-top: none; }

    /* ── Token reveal ──────────────────────────────────────── */
    .token-reveal {
      margin: 16px 0 12px; padding: 12px 14px;
      background: var(--surface2);
      border: 1px solid color-mix(in srgb, var(--warn) 50%, var(--line2));
      border-radius: var(--rad-panel);
    }
    .token-reveal-header {
      font-size: 13px; color: var(--ink);
      margin-bottom: 6px; font-weight: 600;
    }
    .token-reveal code {
      font-size: 13px; word-break: break-all;
      color: var(--ink); user-select: all;
    }

    /* ── HTMX loading indicator ────────────────────────────── */
    .htmx-indicator {
      display: none; color: var(--mut); font-size: 12.5px;
    }
    .htmx-request .htmx-indicator,
    .htmx-request.htmx-indicator { display: inline; }
  </style>
</head>
)HTM"
    // #5572 CI fix — MSVC's raw-string literal has a hard ~16,380-byte cap
    // (C2026 "string too big"); the CSS growth here pushed the first chunk
    // over it. Split here, at the </head>/<body> boundary — already the
    // idiom this file uses (see every other )HTM"\n R"HTM( pair below).
    // GCC/Clang have no such limit, so this only shows up on the Windows
    // CI leg; docs/build-guide.md and
    // build-and-observability-gotchas-from-pki.md document the pattern.
    R"HTM(<body>

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
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/result-sets" class="nav-link">Result Sets</a>
    <a href="/settings" class="nav-link active" id="nav-settings-link">Settings</a>
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

    <div class="page-head"><h1>Settings</h1></div>

    <!-- ── Server Configuration ───────────────────────────── -->
    <div class="section">
      <div class="section-header">Server Configuration</div>
      <div class="section-body">
        <p class="section-intro">
          Network listeners, session limits, and rate limiting.
          These values are set at server startup via CLI flags or environment variables.
        </p>
        <div id="server-config-section"
             hx-get="/fragments/settings/server-config"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── TLS Configuration ─────────────────────────────── -->
    <div class="section">
      <div class="section-header">TLS / mTLS Configuration</div>
      <div class="section-body">
        <!-- TLS fragment loaded via HTMX on page load -->
        <div id="tls-section"
             hx-get="/fragments/settings/tls"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── HTTPS Dashboard ────────────────────────────────── -->
    <div class="section">
      <div class="section-header">HTTPS Dashboard</div>
      <div class="section-body">
        <p class="section-intro">
          TLS termination for the web dashboard and REST API.
        </p>
        <div id="https-section"
             hx-get="/fragments/settings/https"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Internal Certificate Authority ─────────────────── -->
    <div class="section">
      <div class="section-header">Internal Certificate Authority</div>
      <div class="section-body">
        <p class="section-intro">
          The built-in CA that issues the default server certificates and per-agent
          mTLS client certificates. Download the root to trust the dashboard, review
          issued certificates, and revoke a compromised agent.
        </p>
        <div id="ca-section"
             hx-get="/fragments/settings/ca"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── User Management ───────────────────────────────── -->
    <div class="section">
      <div class="section-header">User Management</div>
      <div class="section-body">
        <div id="user-section"
             hx-get="/fragments/settings/users"
             hx-trigger="load, refreshUsers from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Multi-Factor Authentication (MFA / TOTP) ─────── -->
    <div class="section">
      <div class="section-header">Multi-Factor Authentication</div>
      <div class="section-body">
        <p class="section-intro">
          Add a TOTP-based second factor to your account (Google Authenticator, 1Password,
          Authy, Microsoft Authenticator). Recovery codes let you sign in if you lose your
          authenticator device.
        </p>
        <div id="mfa-section"
             hx-get="/fragments/settings/mfa"
             hx-trigger="load, refreshMfa from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Enrollment Tokens ────────────────────────────── -->
    <div class="section">
      <div class="section-header">Enrollment Tokens</div>
      <div class="section-body">
        <p class="section-intro">
          Generate pre-shared tokens to auto-enroll agents.
          The raw token is shown <strong>once</strong> — copy it before closing.
        </p>
        <div id="token-section"
             hx-get="/fragments/settings/tokens"
             hx-trigger="load, refreshTokens from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── API Tokens ────────────────────────────────────── -->
    <div class="section">
      <div class="section-header">API Tokens</div>
      <div class="section-body">
        <p class="section-intro">
          Generate tokens for programmatic REST API access.
          Pass via <code>Authorization: Bearer &lt;token&gt;</code> or
          <code>X-Yuzu-Token</code> header.
          The raw token is shown <strong>once</strong> — copy it before closing.
        </p>
        <div id="api-token-section"
             hx-get="/fragments/settings/api-tokens"
             hx-trigger="load, refreshApiTokens from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Engine Principals ─────────────────────────────── -->
    <div class="section">
      <div class="section-header">Engine Principals</div>
      <div class="section-body">
        <p class="section-intro">
          Durable identities for autonomous use-case engine modules — owner, justification,
          and classification outlive any one credential. Revoke is terminal; recovery mints
          a successor principal (never un-revoked). A user cannot be deleted while owning an
          active engine principal — transfer ownership first.
        </p>
        <!-- Deliberately OUTSIDE #engine-principals-section: that div's
             innerHTML is fully replaced on every `refreshEnginePrincipals`
             trigger (including the one a successful mint/rotate itself
             fires right after populating this panel) — a reveal element
             nested inside the refreshing section would be wiped the instant
             it appeared. Populated by the body-level `submit` listener
             below (CSP-safe, no `hx-on`). -->
        <div id="engine-principal-reveal"></div>
        <div id="engine-principals-section"
             hx-get="/fragments/settings/engine-principals"
             hx-trigger="load, refreshEnginePrincipals from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

)HTM"
    R"HTM(
    <!-- ── Access Reviews (SOC 2 CC6.2) ──────────────────── -->
    <div class="section">
      <div class="section-header">Access Reviews</div>
      <div class="section-body">
        <p class="section-intro">
          Periodic review evidence for every user/group/engine-principal's direct role grants.
          This panel is a convenience view — the REST API (<code>/api/v1/access-reviews*</code>)
          and MCP twins are the primary surface.
        </p>
        <div id="access-review-section"
             hx-get="/fragments/settings/access-reviews"
             hx-trigger="load, refreshAccessReview from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

)HTM"
    R"HTM(
    <!-- ── Auto-Approve Policies ─────────────────────────── -->
    <div class="section">
      <div class="section-header">Auto-Approve Policies</div>
      <div class="section-body">
        <p class="section-intro">
          Define rules to automatically approve agents on registration.
          Matching agents skip the pending queue entirely.
        </p>
        <div id="auto-approve-section"
             hx-get="/fragments/settings/auto-approve"
             hx-trigger="load, refreshAutoApprove from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Pending Agents ─────────────────────────────────── -->
    <div class="section"
         hx-ext="sse"
         sse-connect="/events">
      <div class="section-header">Pending Agent Approvals</div>
      <div class="section-body">
        <p class="section-intro">
          Agents that registered without an enrollment token are shown here.
          Approve or deny them to control fleet membership.
        </p>
        <div id="pending-section"
             hx-get="/fragments/settings/pending"
             hx-trigger="load, sse:pending-agent, refreshPending from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Plugin Code Signing ─────────────────────────────── -->
    <div class="section">
      <div class="section-header">Plugin Code Signing</div>
      <div class="section-body">
        <p class="section-intro">
          Operator-managed trust bundle for agent plugin code signing.
          Upload a PEM bundle of CA certificates that should anchor plugin signatures;
          enable "Require signed plugins" to reject unsigned plugins on every agent.
        </p>
        <div id="plugin-signing-section"
             hx-get="/fragments/settings/plugin-signing"
             hx-trigger="load, refreshPluginSigning from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Agent Updates (OTA) ────────────────────────────── -->
    <div class="section">
      <div class="section-header">Agent Updates (OTA)</div>
      <div class="section-body">
        <p class="section-intro">
          Upload agent binaries and manage fleet-wide update rollout.
        </p>
        <div id="updates-section"
             hx-get="/fragments/settings/updates"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

)HTM"
    R"HTM(
    <!-- ── Gateway ────────────────────────────────────────── -->
    <div class="section">
      <div class="section-header">Gateway</div>
      <div class="section-body">
        <p class="section-intro">
          The Erlang/OTP gateway node sits between agents and this server,
          providing connection multiplexing, heartbeat batching, and circuit breaker protection.
        </p>
        <div id="gateway-section"
             hx-get="/fragments/settings/gateway"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Analytics & Telemetry ─────────────────────────── -->
    <div class="section">
      <div class="section-header">Analytics &amp; Telemetry</div>
      <div class="section-body">
        <p class="section-intro">
          Event collection, ClickHouse integration, and JSONL export.
        </p>
        <div id="analytics-section"
             hx-get="/fragments/settings/analytics"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Data Retention ─────────────────────────────────── -->
    <div class="section">
      <div class="section-header">Data Retention</div>
      <div class="section-body">
        <p class="section-intro">
          Retention policies for response data and audit logs.
        </p>
        <div id="data-retention-section"
             hx-get="/fragments/settings/data-retention"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── DEX Alerts (F1) ────────────────────────────────── -->
    <div class="section">
      <div class="section-header">DEX Alerts</div>
      <div class="section-body">
        <p class="section-intro">
          Route DEX reliability signals to operator notifications and the
          <code>dex.signal</code> webhook event, and tune the fleet blast-radius
          incident thresholds. Changes apply immediately.
        </p>
        <div id="dex-alerts-section"
             hx-get="/fragments/settings/dex-alerts"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── MCP (AI Integration) ────────────────────────── -->
    <div class="section">
      <div class="section-header">MCP (AI Integration)</div>
      <div class="section-body">
        <p class="section-intro">
          Model Context Protocol endpoint for AI-driven fleet management. MCP allows AI models to query agents, check compliance, and manage your fleet through a secure JSON-RPC interface.
        </p>
        <div id="mcp-section"
             hx-get="/fragments/settings/mcp"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Vulnerability Management ───────────────────────── -->
    <div class="section">
      <div class="section-header">Vulnerability Management</div>
      <div class="section-body">
        <p class="section-intro">
          NVD CVE feed synchronization for vulnerability scanning.
        </p>
        <div id="nvd-section"
             hx-get="/fragments/settings/nvd"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Management Groups ──────────────────────────────── -->
    <div class="section">
      <div class="section-header">Management Groups</div>
      <div class="section-body">
        <p class="section-intro">
          Organize devices into a hierarchy for access scoping and targeted operations.
        </p>
        <div id="mgmt-groups-section"
             hx-get="/fragments/settings/management-groups"
             hx-trigger="load, refreshMgmtGroups from:body"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Tag Compliance ──────────────────────────────────── -->
    <div class="section">
      <div class="section-header">Tag Compliance</div>
      <div class="section-body">
        <p class="section-intro">
          Devices should have all 4 structured tag categories assigned.
          Devices missing tags are flagged but continue to function normally.
        </p>
        <div id="tag-compliance-section"
             hx-get="/fragments/settings/tag-compliance"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Directory Integration / OIDC SSO ──────────────── -->
    <div class="section">
      <div class="section-header">Directory Integration / OIDC SSO</div>
      <div class="section-body">
        <div id="directory-section"
             hx-get="/fragments/settings/directory"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span class="muted">Loading...</span>
        </div>
      </div>
    </div>

  </div>

  <div id="toast-container" class="toast-container"></div>

  <script>
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

    /* ── Two-click confirm for bulk destructive operations ── */
    function twoClickConfirm(btn, action) {
      if (btn.dataset.confirming === 'true') {
        action();
        btn.dataset.confirming = 'false';
        btn.textContent = btn.dataset.originalText;
        btn.classList.remove('btn-confirming');
        return;
      }
      btn.dataset.originalText = btn.textContent;
      btn.dataset.confirming = 'true';
      btn.textContent = 'Confirm: ' + btn.dataset.originalText + '?';
      btn.classList.add('btn-confirming');
      setTimeout(function() {
        if (btn.dataset.confirming === 'true') {
          btn.dataset.confirming = 'false';
          btn.textContent = btn.dataset.originalText;
          btn.classList.remove('btn-confirming');
        }
      }, 3000);
    }

    /* ── Populate nav bar + context bar ─────────────────────── */
)HTM"
    // Split here purely to keep each raw-string literal under MSVC's 16 KB
    // C2026 cap (adjacent literals concatenate byte-for-byte; the engine-
    // principals console section pushed this template over the limit). Local
    // GCC/Clang have no such cap, so this only surfaces on the Windows leg.
    R"HTM(    fetch('/api/me').then(function(r){return r.json()}).then(function(d){
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

    /* Minimal vanilla JS — only for clipboard copy (no HTMX equivalent) */
    document.body.addEventListener('click', function(e) {
      if (e.target.closest('[data-copy-token]')) {
        var btn = e.target.closest('[data-copy-token]');
        var code = btn.parentElement.querySelector('code');
        if (code) {
          navigator.clipboard.writeText(code.textContent);
          btn.textContent = 'Copied!';
          setTimeout(function() { btn.textContent = 'Copy to Clipboard'; }, 2000);
        }
      }
      /* G5 (secret hygiene): manual dismiss for the engine-principal
         mint/rotate secret reveal — wipes the DOM immediately rather than
         waiting on the 60s auto-clear timer above. */
      if (e.target.closest('[data-dismiss-reveal]')) {
        var reveal = document.getElementById('engine-principal-reveal');
        if (reveal) reveal.innerHTML = '';
        if (window.__enginePrincipalRevealTimer) {
          clearTimeout(window.__enginePrincipalRevealTimer);
          window.__enginePrincipalRevealTimer = null;
        }
      }
    });
    /* Engine Principals — the REST surface (/api/v1/engine-principals/...)
       is JSON-in/JSON-out, so these forms are deliberately PLAIN <form>
       elements with NO hx-post (htmx's native form submission would send
       application/x-www-form-urlencoded, and every one of these routes
       400s on a non-JSON body — there is no bundled json-enc extension).
       This body-level delegated `submit` listener does the same thing
       instruction_ui.cpp's execute-instruction button already does for a
       JSON REST endpoint: build the JSON body from the form fields, fetch()
       it, and update the DOM from the response — CSP-safe (no `hx-on`,
       no `new Function()`). One listener covers all five engine-principal
       mutations (create/mint/rotate/transfer/revoke), dispatched on each
       form's `data-engine-action` marker (settings_routes.cpp's
       render_engine_principals_fragment). */
    document.body.addEventListener('submit', function(e) {
      var form = e.target.closest('form[data-engine-action]');
      if (!form) return;
      e.preventDefault();

      var action = form.getAttribute('data-engine-action');
      var principalId = form.getAttribute('data-principal-id') || '';
      var submitBtn = form.querySelector('button[type=submit]');
      var confirmMsg = submitBtn && submitBtn.getAttribute('data-confirm');
      if (confirmMsg && !window.confirm(confirmMsg)) return;

      var fd = new FormData(form);
      var url, method, payload;
      if (action === 'create') {
        url = '/api/v1/engine-principals';
        method = 'POST';
        payload = {
          slug: fd.get('slug') || '',
          display_name: fd.get('display_name') || '',
          owner_username: fd.get('owner_username') || '',
          justification: fd.get('justification') || '',
          classification: fd.get('classification') || ''
        };
      } else if (action === 'mint') {
        url = '/api/v1/engine-principals/' + encodeURIComponent(principalId) + '/credentials';
        method = 'POST';
        payload = { ttl_days: parseInt(fd.get('ttl_days'), 10) || 90 };
      } else if (action === 'rotate') {
        url = '/api/v1/engine-principals/' + encodeURIComponent(principalId) +
              '/credentials/rotate';
        method = 'POST';
        payload = { overlap_secs: parseInt(fd.get('overlap_secs'), 10) || 86400 };
      } else if (action === 'transfer') {
        url = '/api/v1/engine-principals/' + encodeURIComponent(principalId) + '/transfer-owner';
        method = 'POST';
        payload = { new_owner: fd.get('new_owner') || '' };
      } else if (action === 'revoke') {
        url = '/api/v1/engine-principals/' + encodeURIComponent(principalId);
        method = 'DELETE';
        var supersededBy = fd.get('superseded_by');
        payload = supersededBy ? { superseded_by: supersededBy } : {};
      } else {
        return;
      }

      var feedback = document.getElementById('engine-principal-feedback');
      if (feedback) feedback.textContent = '';
      fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        /* G5 (secret hygiene): mint/rotate responses carry a raw one-time
           secret; never let the browser's HTTP cache retain it. */
        cache: 'no-store'
      })
      .then(function(r) { return r.json().then(function(d) { return { status: r.status, data: d }; }); })
      .then(function(resp) {
        if (resp.status >= 400) {
          var msg = resp.data && resp.data.error
            ? (resp.data.error.message || String(resp.data.error))
            : 'Failed';
          if (feedback) feedback.textContent = msg;
          return;
        }
        // Success envelope shape is {"data": {...route-specific...},
        // "meta": {...}} (rest_api_v1.cpp's ok_json helper) — the mint and
        // rotate routes nest the raw one-time secret at data.data.token.
        var secret = resp.data && resp.data.data ? resp.data.data.token : undefined;
        if (secret) {
          var reveal = document.getElementById('engine-principal-reveal');
          if (reveal) {
            reveal.innerHTML =
              '<div class="token-reveal">' +
              '  <div class="token-reveal-header">COPY THIS SECRET NOW — it will not be shown again</div>' +
              '  <code></code><br>' +
              '  <button class="btn btn-secondary btn-sm" style="margin-top:0.5rem" data-copy-token>Copy to Clipboard</button>' +
              '  <button class="btn btn-secondary btn-sm" style="margin-top:0.5rem;margin-left:0.5rem" data-dismiss-reveal>Dismiss</button>' +
              '</div>';
            reveal.querySelector('code').textContent = secret;
            /* G5 (secret hygiene): auto-clear the revealed secret from the
               DOM after a bounded window — a tab left open, or shared over
               screen-share, must not keep a raw credential visible
               indefinitely. Cancel any timer from a still-pending PRIOR
               reveal first so back-to-back mint/rotate calls can't leave a
               stale timer wiping the newer secret early. */
            if (window.__enginePrincipalRevealTimer)
              clearTimeout(window.__enginePrincipalRevealTimer);
            window.__enginePrincipalRevealTimer = setTimeout(function() {
              reveal.innerHTML = '';
              window.__enginePrincipalRevealTimer = null;
            }, 60000);
          }
        }
        htmx.trigger(document.body, 'refreshEnginePrincipals');
      })
      .catch(function(err) {
        if (feedback) feedback.textContent = 'Error: ' + err.message;
      });
    });
)HTM"
    // Split here to keep each raw-string literal under MSVC's 16 KB C2026 cap
    // (the #5342 password-change block below). Adjacent literals concatenate
    // byte-for-byte, so the runtime HTML is unchanged by the split.
    R"HTM(    /* "Sign out everywhere" (users fragment, own row) — redirect to the
       login page once DELETE /api/v1/sessions/me has run. A body-level
       htmx:afterRequest listener keyed on data-signout-everywhere, NOT an
       hx-on attribute: htmx compiles hx-on:* with new Function(), which this
       page's CSP (no 'unsafe-eval') blocks at runtime. A 401 also redirects
       (the session is already gone); anything else toasts and stays. */
    document.body.addEventListener('htmx:afterRequest', function(e) {
      var el = e.detail && e.detail.elt;
      if (!el || !el.hasAttribute || !el.hasAttribute('data-signout-everywhere')) return;
      var status = e.detail.xhr ? e.detail.xhr.status : 0;
      if (e.detail.successful || status === 401) {
        window.location = '/login';
        return;
      }
      showToast('Sign out everywhere failed (HTTP ' + status + ')', 'error');
    });

    /* ── #5342 Local password change (own row) / admin reset (other local
       rows). JSON REST routes, so a plain fetch() — no hx-post (htmx would
       send form-encoding) and no hx-on (CSP). Toggle buttons and the
       delegated submit listener are keyed on data-pw-toggle / data-pw-action
       (settings_routes.cpp render_users_fragment). The username is read from
       an html_escape'd data attribute and only ever reaches the URL through
       encodeURIComponent and the page through textContent (showToast). The
       client-side checks mirror password_policy.hpp (12..1024 BYTES, UTF-8);
       the server re-checks and stays authoritative. */
    function yuzuPwBytes(s) {
      try { return new TextEncoder().encode(s).length; } catch (_) { return s.length; }
    }
    function yuzuPwErr(resp, fallback) {
      var d = resp && resp.data;
      if (d && d.error && d.error.message) return d.error.message;
      return fallback + (resp && resp.status ? ' (HTTP ' + resp.status + ')' : '');
    }
    /* POST JSON; on a 401 MFA step-up envelope, prompt for a code, POST it
       to meta.challenge_url (same-origin path only) and retry ONCE — the
       dashboard's htmx step-up intercept, re-done for fetch(). */
    function yuzuPwPost(url, payload, done, retried) {
      fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      .then(function(r) {
        return r.text().then(function(t) {
          var d = null;
          try { d = JSON.parse(t); } catch (_) {}
          return { status: r.status, data: d };
        });
      })
      .then(function(resp) {
        var meta = resp.data && resp.data.meta;
        if (resp.status === 401 && !retried && meta && meta.mfa_step_up_required) {
          var challenge = meta.challenge_url;
          if (typeof challenge !== 'string' || challenge.charAt(0) !== '/' ||
              challenge.charAt(1) === '/' || challenge.charAt(1) === '\\')
            challenge = '/login/mfa/stepup';
          if (challenge.split('?')[0] !== '/login/mfa/stepup') {
            /* An SSO session's challenge is a re-login at the IdP
               (/auth/oidc/start), not a code POST — never send it a code. */
            showToast('MFA step-up required: sign in again through your identity provider, then retry.', 'warning');
            done(false, { cancelled: true });
            return;
          }
          var code = window.prompt('MFA step-up required for this action.\n\nEnter your 6-digit TOTP code (or a recovery code):');
          if (!code) { done(false, { cancelled: true }); return; }
          var form = new URLSearchParams();
          form.set('code', code.trim());
          fetch(challenge, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: form.toString()
          }).then(function(sr) {
            if (!sr.ok) {
              showToast('MFA step-up failed — verify your code and try again.', 'error');
              done(false, { cancelled: true });
              return;
            }
            yuzuPwPost(url, payload, done, true);
          }).catch(function() {
            showToast('MFA step-up request failed — please try again.', 'error');
            done(false, { cancelled: true });
          });
          return;
        }
        if (resp.status === 401) {
          /* Not a step-up: the session itself is gone (expired or revoked). */
          window.location.href = '/login';
          return;
        }
        done(resp.status >= 200 && resp.status < 300, resp);
      })
      .catch(function(err) {
        showToast('Password request failed: ' + err.message, 'error');
        done(false, { cancelled: true });
      });
    }
    document.body.addEventListener('click', function(e) {
      var t = e.target.closest('[data-pw-toggle]');
      if (!t) return;
      var row = document.getElementById(t.getAttribute('data-pw-toggle'));
      if (!row) return;
      row.hidden = !row.hidden;
      var form = row.querySelector('form');
      if (row.hidden) {
        if (form) form.reset();
      } else {
        var first = row.querySelector('input[type=password]');
        if (first) first.focus();
      }
    });
    document.body.addEventListener('submit', function(e) {
      var form = e.target.closest('form[data-pw-action]');
      if (!form) return;
      e.preventDefault();
      var action = form.getAttribute('data-pw-action');
      var user = form.getAttribute('data-username') || '';
      var row = document.getElementById(form.getAttribute('data-pw-row') || '');
      var cur = form.querySelector('input[name=current_password]');
      var next = form.querySelector('input[name=new_password]').value;
      var confirmPw = form.querySelector('input[name=confirm_password]').value;
      if (next !== confirmPw) {
        showToast('The new password and its confirmation do not match.', 'error');
        return;
      }
      var n = yuzuPwBytes(next);
      if (n < 12) { showToast('The new password must be at least 12 bytes.', 'error'); return; }
      if (n > 1024) { showToast('The new password must be at most 1024 bytes.', 'error'); return; }
      var url, payload;
      if (action === 'self') {
        url = '/api/v1/users/me/password';
        payload = { current_password: cur ? cur.value : '', new_password: next };
      } else if (action === 'reset') {
        url = '/api/v1/users/' + encodeURIComponent(user) + '/password';
        payload = { new_password: next };
      } else {
        return;
      }
      var btn = form.querySelector('button[type=submit]');
      if (btn) btn.disabled = true;
      yuzuPwPost(url, payload, function(ok, resp) {
        if (btn) btn.disabled = false;
        if (!ok) {
          if (resp && resp.cancelled) return;
          showToast(yuzuPwErr(resp, action === 'self' ? 'Password change failed' : 'Password reset failed'), 'error');
          return;
        }
        form.reset();
        if (row) row.hidden = true;
        var d = (resp.data && resp.data.data) || {};
        if (action === 'self') {
          /* #5342 Gate 7: a self-change revokes EVERY session of the account,
             this one included, and never re-issues one (session_reissued is
             always false) — sign in again with the new password. */
          showToast('Password changed. All your sessions were signed out — sign in again with the new password.', 'warning');
          setTimeout(function() { window.location = '/login'; }, 2500);
        } else {
          var msg = 'Password reset for "' + user + '". Their dashboard sessions were signed out.';
          var tokens = d.api_tokens_active;
          /* Warn unless the server CONFIRMED zero active API tokens: null
             (api_tokens_unknown) means it could not check, never "none". */
          var confirmedNone = (typeof tokens === 'number' && tokens === 0);
          if (typeof tokens === 'number' && tokens > 0) {
            msg += ' ' + tokens + ' API token' + (tokens === 1 ? '' : 's') +
                   ' remain active and were NOT revoked — revoke them if the account may be compromised.';
          } else if (!confirmedNone) {
            msg += ' Could not confirm whether the account has active API tokens; any it has were NOT revoked — review them if the account may be compromised.';
          }
          /* #5342 Gate 8: lockout_cleared is true only when a lockout existed
             and was cleared in the same transaction as the reset. */
          if (d.lockout_cleared === true)
            msg += ' Its account lockout was cleared.';
          showToast(msg, confirmedNone ? 'success' : 'warning');
        }
      });
    });
    /* Ctrl+K / Cmd+K — navigate to dashboard command palette */
    document.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        window.location.href = '/?palette=1';
      }
    });
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
