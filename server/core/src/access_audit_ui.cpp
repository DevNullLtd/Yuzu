// Audit and reviews page template (see access_audit_ui.hpp).
//
// The `data-denied` / `data-unavailable` sentences are byte-equal to the constants in
// access_audit_render.hpp; test_access_audit_js.cpp pins the equality.
// The literal is far below MSVC's 16,380-byte raw-string cap (C2026).
//
// The htmx-config meta MUST precede the htmx script (htmx reads it once, at load):
// `historyEnabled:false` keeps htmx from snapshotting this page into localStorage when a campaign
// row pushes its URL. The snapshot would carry the audit log, the campaign list and any grant
// tables past logout, defeating the fragments' `Cache-Control: no-store, private`.

#include "access_audit_ui.hpp"

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kAccessAuditTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu - Audit and reviews</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false,"historyEnabled":false}'>
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-access.js" defer></script>
  <script src="/static/yuzu-dialog.js" defer></script>
  <script src="/static/yuzu-audit.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Audit and reviews</h1>
      <p class="subtitle">A record of who did what, and periodic checks that access is still justified.</p>
    </div>
  </header>
  <div class="split">
    <div class="grow">
      <section class="panel" id="panel-audit">
        <div class="hd"><h2>Audit log</h2><span class="sub">Newest first</span></div>
        <form class="toolbar" id="audit-filters" aria-label="Audit filters" hx-get="/fragments/access/audit/log"
              hx-target="#audit-log" hx-swap="innerHTML" hx-trigger="change, submit">
          <div class="seg" role="group" aria-label="Time range">
            <label><input type="radio" name="range" value="1h">Last hour</label>
            <label><input type="radio" name="range" value="24h" checked>24 hours</label>
            <label><input type="radio" name="range" value="7d">7 days</label>
          </div>
          <input class="in" name="principal" aria-label="Principal" placeholder="Principal (exact)" maxlength="1024">
          <input class="in mono" name="action" aria-label="Action" placeholder="Action (exact)" maxlength="1024">
          <button class="btn sm" type="submit">Apply</button>
        </form>
        <div class="pb"><p class="hint">The time range sets the window. Principal and Action are exact matches, not searches.</p></div>
        <div id="audit-log" hx-get="/fragments/access/audit/log?range=24h" hx-trigger="load" hx-swap="innerHTML"
             data-src="/fragments/access/audit/log?range=24h"
             data-denied="Reading the audit log needs the AuditLog:Read permission. While RBAC is off that is the Administrator account role."
             data-unavailable="The audit store did not answer, so the log is unknown right now. This is not no activity.">
          <div class="pb"><p class="hint">Loading the audit log.</p></div>
        </div>
      </section>
      <div id="ar-banner" class="strip" role="alert"></div>
      <section class="panel" id="ar-campaigns" hx-get="/fragments/access/reviews/campaigns" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/reviews/campaigns"
               data-denied="Access reviews need the AccessReview:Read permission, held by the Administrator and Reviewer roles. While RBAC is off that is the Administrator account role."
               data-unavailable="The access review store did not answer, so the campaign list is unknown. This is not no reviews.">
        <div class="hd"><h2>Access reviews</h2><span class="sub">Campaigns</span></div>
        <div class="pb"><p class="hint">Loading.</p></div>
      </section>
      <section class="panel" id="ar-campaign"
               data-src="/fragments/access/reviews/campaign"
               data-denied="Access reviews need the AccessReview:Read permission, held by the Administrator and Reviewer roles. While RBAC is off that is the Administrator account role."
               data-unavailable="The access review store did not answer, so this campaign could not be read.">
        <div class="hd"><h2>Review campaign</h2></div>
        <div class="empty"><span>Select a campaign from the list to review its grants.</span></div>
      </section>
      <section class="panel" id="ar-grants"
               data-src="/fragments/access/reviews/grants"
               data-denied="Access reviews need the AccessReview:Read permission, held by the Administrator and Reviewer roles. While RBAC is off that is the Administrator account role."
               data-unavailable="The grant population could not be read, so the list is unknown. This is not no grants.">
        <div class="hd"><h2>Current grants</h2><span class="sub">Live population, not a campaign</span></div>
        <div class="pb"><p class="hint">Reading the whole grant population is recorded in the audit log, so it is fetched on request.</p></div>
        <div class="btns"><button type="button" class="btn sm" hx-get="/fragments/access/reviews/grants"
             hx-target="#ar-grants" hx-swap="innerHTML">Show current grants</button></div>
      </section>
    </div>
    <div class="side2">
      <section class="panel" id="ar-campaign-side">
        <div class="hd"><h2>Campaign summary</h2></div>
        <div class="empty"><span>Select a campaign from the list to review its grants.</span></div>
      </section>
      <section class="panel" id="panel-sample">
        <div class="hd"><h2>Authentication sample</h2><span class="sub">Random sample for evidence</span></div>
        <div class="form">
          <div class="fld"><label for="as-limit">Sample size</label>
            <input class="in mono" id="as-limit" name="limit" type="text" inputmode="numeric" value="100" maxlength="4">
            <span class="hint">1 to 1000.</span></div>
        </div>
        <div class="btns"><button type="button" class="btn primary" hx-get="/fragments/access/audit/sample"
             hx-include="#as-limit" hx-target="#audit-sample" hx-swap="innerHTML">Draw sample</button></div>
        <div id="audit-sample" aria-live="polite"
             data-denied="Reading the audit log needs the AuditLog:Read permission. While RBAC is off that is the Administrator account role."
             data-unavailable="The audit store did not answer, so no sample could be drawn.">
          <div class="pb"><p class="hint">No sample drawn. Drawing a sample is itself recorded in the audit log.</p></div>
        </div>
      </section>
      <section class="panel" id="panel-retention">
        <div class="hd"><h2>Retention</h2></div>
        <div id="audit-retention"
             data-src="/fragments/access/audit/retention"
             data-denied="Reading the retention setting needs the ServerConfig:Read permission. While RBAC is off that is the Administrator account role."
             data-unavailable="The retention setting could not be read.">
          <div class="pb"><p class="hint">Reading the retention setting needs its own permission, so it is fetched on request.</p></div>
          <div class="btns"><button type="button" class="btn sm" hx-get="/fragments/access/audit/retention"
               hx-target="#audit-retention" hx-swap="innerHTML">Show retention</button></div>
        </div>
      </section>
    </div>
  </div>
</main>
</body>
</html>
)HTM";

extern const char* const kAccessAuditHtml =
    yuzu::server::shell::bake(kAccessAuditTemplate, {.active_key = "audit"});
// NOLINTEND(cert-err58-cpp)
