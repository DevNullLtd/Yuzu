// Result Sets dashboard surface (scope walking — capability §30, design
// docs/scope-walking-design.md §8). A dedicated /result-sets page: a left-rail
// sidebar of the operator's active result sets, a detail pane with the lineage
// breadcrumb, the copyable `from_result_set:<id>` scope token, and
// pin/unpin/delete actions. Compiled in its own translation unit to keep the
// long raw string literal away from server.cpp's brace matching.

#include "result_sets_ui.hpp"
#include "web_utils.hpp"

#include <string>

namespace yuzu::server {

using yuzu::server::html_escape;

namespace {

// Display label for a set: its alias, or a shortened id when unnamed.
std::string label_for(const ResultSet& r) {
    if (!r.name.empty())
        return r.name;
    return r.id.size() > 13 ? r.id.substr(0, 13) + "…" : r.id;
}

std::string label_for(const LineageNode& n) {
    if (!n.name.empty())
        return n.name;
    return n.id.size() > 13 ? n.id.substr(0, 13) + "…" : n.id;
}

std::string status_badge(ResultSetStatus s) {
    switch (s) {
    case ResultSetStatus::Pending:
        return R"(<span class="rs-badge rs-badge-pending">pending</span>)";
    case ResultSetStatus::Failed:
        return R"(<span class="rs-badge rs-badge-failed">failed</span>)";
    case ResultSetStatus::Materialized:
        return {};
    }
    return {};
}

} // namespace

std::string render_result_sets_sidebar(const std::vector<ResultSet>& sets,
                                       const std::string& selected_id) {
    if (sets.empty()) {
        return R"(<div class="rs-empty">No result sets yet. Create one from a query,
                  or import device IDs above.</div>)";
    }
    std::string h;
    for (const auto& r : sets) {
        const bool active = r.id == selected_id;
        h += "<div class=\"rs-item";
        if (active)
            h += " active";
        h += "\" hx-get=\"/fragments/result-sets/" + html_escape(r.id) +
             "/detail\" hx-target=\"#rs-detail\" hx-swap=\"innerHTML\">";
        h += "<div class=\"rs-item-top\">";
        if (r.pinned)
            h += "<span class=\"rs-pin\" title=\"pinned\">★</span>";
        h += "<span class=\"rs-name\">" + html_escape(label_for(r)) + "</span>";
        h += "</div>";
        h += "<div class=\"rs-item-meta\">";
        h += "<span>" + std::to_string(r.device_count) + " device" +
             (r.device_count == 1 ? "" : "s") + "</span>";
        h += status_badge(r.status);
        h += "</div>";
        h += "</div>";
    }
    return h;
}

std::string render_result_set_detail_empty() {
    return R"(<div class="rs-detail-empty">
                <p>Select a result set to view its lineage and scope token.</p>
              </div>)";
}

std::string render_result_set_detail(const ResultSet& rs, const std::vector<LineageNode>& chain) {
    std::string h;
    h += "<div class=\"rs-detail-head\">";
    h += "<h2>" + html_escape(label_for(rs)) + "</h2>";
    if (rs.pinned)
        h += "<span class=\"rs-badge rs-badge-pinned\">★ pinned</span>";
    h += status_badge(rs.status);
    h += "</div>";

    // Lineage breadcrumb (root → leaf). Mirrors the parent_id walk.
    if (chain.size() > 1) {
        h += "<div class=\"rs-breadcrumb\">";
        for (std::size_t i = 0; i < chain.size(); ++i) {
            if (i)
                h += "<span class=\"rs-bc-sep\">▸</span>";
            const bool is_leaf = chain[i].id == rs.id;
            h += "<span class=\"rs-bc-node";
            if (is_leaf)
                h += " current";
            h += "\">" + html_escape(label_for(chain[i])) + "</span>";
        }
        h += "</div>";
    }

    // Stats grid.
    h += "<div class=\"rs-stats\">";
    h += "<div><span class=\"rs-stat-k\">Devices</span><span class=\"rs-stat-v\">" +
         std::to_string(rs.device_count) + "</span></div>";
    h += "<div><span class=\"rs-stat-k\">Source</span><span class=\"rs-stat-v\">" +
         html_escape(rs.source_kind) + "</span></div>";
    h += "<div><span class=\"rs-stat-k\">Owner</span><span class=\"rs-stat-v\">" +
         html_escape(rs.owner_principal) + "</span></div>";
    h += "</div>";

    // Copyable scope token — the whole point: drop this into any scope box.
    const std::string token = "from_result_set:" + rs.id;
    h += "<div class=\"rs-token-row\">";
    h += "<label class=\"rs-token-label\">Scope token</label>";
    h += "<div class=\"rs-token\"><code id=\"rs-token-text\">" + html_escape(token) +
         "</code>";
    h += "<button class=\"rs-copy\" type=\"button\" "
         "onclick=\"navigator.clipboard.writeText('" +
         html_escape(token) + "');this.textContent='Copied';\">Copy</button>";
    h += "</div></div>";

    // Actions.
    h += "<div class=\"rs-actions\">";
    const std::string base = "/fragments/result-sets/" + html_escape(rs.id);
    if (rs.pinned) {
        h += "<button class=\"rs-btn\" hx-post=\"" + base +
             "/unpin\" hx-target=\"#rs-detail\" hx-swap=\"innerHTML\">Unpin</button>";
    } else {
        h += "<button class=\"rs-btn\" hx-post=\"" + base +
             "/pin\" hx-target=\"#rs-detail\" hx-swap=\"innerHTML\">Pin</button>";
    }
    h += "<button class=\"rs-btn rs-btn-danger\" hx-post=\"" + base +
         "/delete\" hx-target=\"#rs-detail\" hx-swap=\"innerHTML\" "
         "hx-confirm=\"Delete this result set? Pinned sets must be unpinned first.\">"
         "Delete</button>";
    h += "</div>";
    return h;
}

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kResultSetsPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — Result Sets</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { display: flex; flex-direction: column; min-height: 100vh; }
    .rs-content {
      max-width: 1200px;
      margin: 1rem auto;
      padding: 0 1.5rem 2rem 1.5rem;
      width: 100%;
      box-sizing: border-box;
      flex: 1;
    }
    .rs-content h1 {
      font-size: 1.4rem;
      margin: 0.25rem 0 0.4rem 0;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .rs-subtitle {
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.85rem;
      margin: 0 0 1.25rem 0;
    }
    .rs-layout { display: flex; gap: 1.25rem; align-items: flex-start; }
    .rs-rail { flex: 0 0 320px; }
    .rs-main { flex: 1; min-width: 0; }
    .rs-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      overflow: hidden;
    }
    .rs-panel-header {
      padding: 0.6rem 0.85rem;
      font-size: 0.85rem;
      font-weight: 600;
      border-bottom: 1px solid var(--border);
      background: var(--mds-color-state-hover);
    }
    .rs-panel-body { padding: 0.5rem; }
    .rs-item {
      padding: 0.55rem 0.6rem;
      border-radius: 0.3rem;
      cursor: pointer;
      border: 1px solid transparent;
    }
    .rs-item:hover { background: var(--mds-color-state-hover); }
    .rs-item.active {
      background: var(--mds-color-state-selected);
      border-color: var(--accent);
    }
    .rs-item-top { display: flex; align-items: center; gap: 0.35rem; }
    .rs-pin { color: var(--yellow); font-size: 0.8rem; }
    .rs-name { font-size: 0.85rem; font-weight: 600; color: var(--fg);
               white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .rs-item-meta {
      display: flex; align-items: center; gap: 0.5rem;
      margin-top: 0.2rem; font-size: 0.72rem;
      color: var(--mds-color-theme-text-tertiary);
    }
    .rs-empty, .rs-detail-empty {
      padding: 2rem 1rem; text-align: center;
      color: var(--mds-color-theme-text-tertiary); font-size: 0.85rem;
    }
    .rs-badge {
      display: inline-block; padding: 0.05rem 0.4rem; border-radius: 0.75rem;
      font-size: 0.65rem; font-weight: 600;
    }
    .rs-badge-pending { background: var(--mds-color-bg-warning-tinted);
                        color: var(--mds-color-indicator-warning-bright); }
    .rs-badge-failed { background: var(--mds-color-bg-error-tinted);
                       color: var(--mds-color-theme-indicator-error); }
    .rs-badge-pinned { background: var(--mds-color-bg-warning-tinted);
                       color: var(--mds-color-indicator-warning-bright); }
    .rs-detail-head { display: flex; align-items: center; gap: 0.6rem;
                      margin-bottom: 0.75rem; }
    .rs-detail-head h2 { font-size: 1.1rem; margin: 0; }
    .rs-breadcrumb { display: flex; flex-wrap: wrap; align-items: center;
                     gap: 0.35rem; margin-bottom: 1rem; font-size: 0.8rem; }
    .rs-bc-node { color: var(--mds-color-theme-text-tertiary); }
    .rs-bc-node.current { color: var(--fg); font-weight: 600; }
    .rs-bc-sep { color: var(--accent); }
    .rs-stats { display: flex; gap: 1.5rem; margin-bottom: 1rem;
                flex-wrap: wrap; }
    .rs-stats > div { display: flex; flex-direction: column; }
    .rs-stat-k { font-size: 0.65rem; text-transform: uppercase;
                 letter-spacing: 0.05em; color: var(--mds-color-theme-text-tertiary); }
    .rs-stat-v { font-size: 1rem; font-weight: 600; color: var(--fg); }
    .rs-token-row { margin-bottom: 1rem; }
    .rs-token-label { display: block; font-size: 0.65rem; text-transform: uppercase;
                      letter-spacing: 0.05em; color: var(--mds-color-theme-text-tertiary);
                      margin-bottom: 0.3rem; }
    .rs-token { display: flex; align-items: center; gap: 0.5rem; }
    .rs-token code {
      flex: 1; background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.3rem; padding: 0.4rem 0.6rem; font-family: var(--mds-font-family-mono);
      font-size: 0.8rem; color: var(--accent); overflow-x: auto;
    }
    .rs-copy, .rs-btn {
      padding: 0.35rem 0.85rem; font-size: 0.8rem; border-radius: 0.25rem;
      cursor: pointer; border: 1px solid var(--border); background: var(--surface);
      color: var(--fg);
    }
    .rs-copy:hover, .rs-btn:hover { background: var(--mds-color-state-hover); }
    .rs-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
    .rs-btn-danger { color: var(--mds-color-theme-indicator-error);
                     border-color: var(--mds-color-theme-indicator-error); }
    .rs-create { padding: 0.6rem; border-bottom: 1px solid var(--border); }
    .rs-create input, .rs-create textarea {
      width: 100%; box-sizing: border-box; margin-bottom: 0.4rem;
      background: var(--bg); border: 1px solid var(--border); border-radius: 0.3rem;
      color: var(--fg); font-size: 0.8rem; padding: 0.35rem 0.5rem;
      font-family: inherit;
    }
    .rs-create textarea { resize: vertical; min-height: 3rem;
                          font-family: var(--mds-font-family-mono); }
    .rs-create button {
      width: 100%; padding: 0.4rem; font-size: 0.8rem; cursor: pointer;
      background: var(--accent); color: var(--mds-color-text-on-accent);
      border: none; border-radius: 0.25rem;
    }
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
    <a href="/tar" class="nav-link">TAR</a>
    <a href="/hardware" class="nav-link">Hardware</a>
    <a href="/software" class="nav-link">Software</a>
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/result-sets" class="nav-link active">Result Sets</a>
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

  <div class="rs-content">
    <h1>Result Sets</h1>
    <p class="rs-subtitle">
      Composable scope &mdash; every query produces a device set you can narrow,
      pin during an investigation, and reuse as the scope of the next command via
      its <code>from_result_set:&lt;id&gt;</code> token.
    </p>

    <div class="rs-layout">
      <!-- Left rail: the operator's active result sets -->
      <div class="rs-rail">
        <div class="rs-panel">
          <div class="rs-panel-header">Your result sets</div>
          <form class="rs-create"
                hx-post="/fragments/result-sets/create"
                hx-target="#rs-sidebar" hx-swap="innerHTML"
                hx-on::after-request="if(event.detail.successful) this.reset()">
            <input type="text" name="name" placeholder="Name (optional)" maxlength="128">
            <textarea name="device_ids" placeholder="Device IDs, one per line (CSV import)"></textarea>
            <button type="submit">Create result set</button>
          </form>
          <div class="rs-panel-body" id="rs-sidebar"
               hx-get="/fragments/result-sets/sidebar"
               hx-trigger="load, every 15s, resultSetsChanged from:body"
               hx-swap="innerHTML">
            <div class="rs-empty">Loading&hellip;</div>
          </div>
        </div>
      </div>

      <!-- Detail pane -->
      <div class="rs-main">
        <div class="rs-panel">
          <div class="rs-panel-header">Detail</div>
          <div class="rs-panel-body" id="rs-detail" style="padding:1rem">
            <div class="rs-detail-empty">
              <p>Select a result set to view its lineage and scope token.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

<script>
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
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)

} // namespace yuzu::server
