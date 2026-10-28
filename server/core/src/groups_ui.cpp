// Groups and enrolment page: the page template (see groups_ui.hpp).
//
// The `data-denied` / `data-unavailable` sentences are the single copy: yuzu-groups.js builds
// its in-panel notes from these attributes. The htmx-config meta MUST precede the htmx script
// (htmx reads it once, at load): `historyEnabled:false` keeps htmx from snapshotting a
// revealed one-time token into its history cache.

#include "groups_ui.hpp"

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kGroupsTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu - Groups and enrolment</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false,"historyEnabled":false}'>
  <script src="/static/htmx.js"></script>
  <script src="/static/sse.js"></script>
  <script src="/static/yuzu-groups.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Groups and enrolment</h1>
      <p class="subtitle">Decide which new agents may join, and keep the tokens and rules that let them in.</p>
    </div>
  </header>
  <div class="split">
    <div class="grow">
      <section class="panel" id="grp-list" hx-get="/fragments/groups/list"
               hx-trigger="load, refreshGroups from:body" hx-swap="innerHTML"
               data-src="/fragments/groups/list"
               data-denied="Your account cannot read management groups."
               data-unavailable="Groups could not be read. This is not an empty list.">
        <div class="hd"><h2>Management groups</h2></div>
        <p class="hint pad">Loading...</p>
      </section>
      <section class="panel" hx-ext="sse" sse-connect="/events">
        <div class="hd"><h2>Agents waiting for approval</h2></div>
        <div id="pending-section" hx-get="/fragments/settings/pending"
             hx-trigger="load, sse:pending-agent, refreshPending from:body" hx-swap="innerHTML"
             data-src="/fragments/settings/pending"
             data-denied="Approving agents needs the Administrator account role."
             data-unavailable="The enrolment store did not answer, so the queue is unknown. This is not an empty list.">
          <p class="hint pad">Loading...</p>
        </div>
      </section>
      <section class="panel">
        <div class="hd"><h2>Auto-approve rules</h2></div>
        <div id="auto-approve-section" hx-get="/fragments/settings/auto-approve"
             hx-trigger="load, refreshAutoApprove from:body" hx-swap="innerHTML"
             data-src="/fragments/settings/auto-approve"
             data-denied="Auto-approve rules need the Administrator account role."
             data-unavailable="The rules could not be read. This is not an empty list.">
          <p class="hint pad">Loading...</p>
        </div>
      </section>
    </div>
    <div class="side2">
      <div id="grp-side" data-src=""
           data-denied="Your account cannot read management groups."
           data-unavailable="This group could not be read.">
        <section class="panel">
          <div class="hd"><h2>Selected group</h2></div>
          <div class="empty"><span>Select a group to see its details.</span></div>
        </section>
      </div>
      <section class="panel">
        <div class="hd"><h2>Enrolment tokens</h2></div>
        <div id="token-section" hx-get="/fragments/settings/tokens"
             hx-trigger="load, refreshTokens from:body" hx-swap="innerHTML"
             data-src="/fragments/settings/tokens"
             data-denied="Enrolment tokens need the Administrator account role."
             data-unavailable="The enrolment store did not answer, so the token list is unknown. This is not an empty list.">
          <p class="hint pad">Loading...</p>
        </div>
      </section>
    </div>
  </div>
  <div id="toast-container" class="toast-container" aria-live="polite"></div>
</main>
</body>
</html>
)HTM";

extern const char* const kGroupsHtml =
    yuzu::server::shell::bake(kGroupsTemplate, {.active_key = "groups"});
// NOLINTEND(cert-err58-cpp)
