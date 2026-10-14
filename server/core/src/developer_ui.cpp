// Settings > Developer and API page (System pages, SYS-4, read-only).
//
// Four panels, each a loader for a /fragments/settings/developer/* route. The
// load generator and process data fetch panels are NOT here (dispatch, held).
// No server data is interpolated into this template; the fragments are built by
// developer_render.cpp and the only script text set at runtime is a fixed
// sentence chosen by status code.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kSettingsDeveloperPageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Developer and API</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: 100vh; }
    .content { padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px; max-width: 1200px; }
    .dev-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(480px, 100%), 1fr)); gap: 22px; }
    .dev-filter { padding: 12px 16px 0; }
    .dev-filter input { width: 100%; }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<main class="content">
  <div class="page-header">
    <div>
      <h1>Developer and API</h1>
      <p class="subtitle">Everything an integration needs to discover.</p>
    </div>
  </div>

  <section class="panel" aria-labelledby="dev-api-h">
    <div class="hd"><h2 id="dev-api-h">API</h2></div>
    <div class="dev-body" hx-get="/fragments/settings/developer/api" hx-trigger="load" hx-swap="innerHTML"><div class="pb">Loading...</div></div>
  </section>

  <div class="dev-grid">
    <section class="panel" aria-labelledby="dev-routes-h">
      <div class="hd"><h2 id="dev-routes-h">Routes</h2></div>
      <div class="dev-filter">
        <label class="hint" for="dev-routes-q">Filter by path or summary</label>
        <input class="input" id="dev-routes-q" name="q" type="search" maxlength="128" autocomplete="off"
               hx-get="/fragments/settings/developer/routes" hx-trigger="input changed delay:300ms, search"
               hx-target="#dev-routes-body" hx-swap="innerHTML">
      </div>
      <div id="dev-routes-body" class="dev-body" hx-get="/fragments/settings/developer/routes" hx-trigger="load" hx-swap="innerHTML"><div class="pb">Loading...</div></div>
    </section>

    <section class="panel" aria-labelledby="dev-perms-h">
      <div class="hd"><h2 id="dev-perms-h">Permissions</h2></div>
      <div class="dev-filter">
        <label class="hint" for="dev-perms-q">Filter by securable</label>
        <input class="input" id="dev-perms-q" name="q" type="search" maxlength="128" autocomplete="off"
               hx-get="/fragments/settings/developer/permissions" hx-trigger="input changed delay:300ms, search"
               hx-target="#dev-perms-body" hx-swap="innerHTML">
      </div>
      <div id="dev-perms-body" class="dev-body" hx-get="/fragments/settings/developer/permissions" hx-trigger="load" hx-swap="innerHTML"><div class="pb">Loading...</div></div>
    </section>
  </div>

  <section class="panel" aria-labelledby="dev-plugins-h">
    <div class="hd"><h2 id="dev-plugins-h">Plugins</h2></div>
    <div class="dev-body" hx-get="/fragments/settings/developer/plugins" hx-trigger="load" hx-swap="innerHTML"><div class="pb">Loading...</div></div>
  </section>
</main>

<script>
/* htmx 2 drops 4xx/5xx bodies: turn them into a fixed sentence by status. */
document.body.addEventListener('htmx:responseError', function (e) {
  var d = e.detail || {};
  var t = d.target;
  if (!t || !d.xhr || !t.classList || !t.classList.contains('dev-body')) return;
  var s = d.xhr.status;
  if (s === 401) { window.location.href = '/login'; return; }
  var msg = 'Could not be read. This is not an empty list.';
  if (s === 403) msg = 'Needs the Infrastructure:Read permission.';
  else if (s === 429) msg = 'Too many requests. Try again in a moment.';
  var n = document.createElement('div');
  n.className = 'note warn';
  n.setAttribute('role', 'alert');
  n.textContent = msg;
  t.replaceChildren(n);
});
</script>
</body>
</html>
)HTM";

extern const char* const kSettingsDeveloperHtml = yuzu::server::shell::bake(
    kSettingsDeveloperPageTemplate, {.active_key = "settings-developer", .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
