// Result Sets dashboard surface (scope walking — capability §30, design
// docs/scope-walking-design.md §8). A dedicated /result-sets page: a left-rail
// sidebar of the operator's active result sets, a detail pane with the lineage
// breadcrumb, the copyable `from_result_set:<id>` scope token, and
// pin/unpin/delete actions. Compiled in its own translation unit to keep the
// long raw string literal away from server.cpp's brace matching.

#include "app_shell.hpp"
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
const char* const kResultSetsPageTemplate = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — Result Sets</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    button, input, textarea { font: inherit; color: inherit; }
    code { font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    .rs-content { padding: 22px 28px 36px; min-height: calc(100vh - var(--shell-top-h, 72px)); }
    .rs-content h1 { font-size: 24px; font-weight: 600; letter-spacing: -.015em;
                     line-height: 1.2; color: var(--ink); }
    .rs-subtitle { color: var(--mut); margin: 4px 0 22px 0; max-width: 70ch; }
    .rs-subtitle code { color: var(--ink2); }
    .rs-layout { display: flex; flex-wrap: wrap; gap: 22px; align-items: flex-start; }
    .rs-rail { flex: 1 1 320px; max-width: 360px; min-width: 0; }
    .rs-main { flex: 999 1 560px; min-width: 0; }
    .rs-panel { background: var(--surface); border: 1px solid var(--line);
                border-radius: var(--rad-panel); min-width: 0; }
    .rs-panel-header { padding: 12px 16px; font-size: 14px; font-weight: 600;
                       color: var(--ink); border-bottom: 1px solid var(--line); }
    .rs-detail-body { padding: 16px; }
    .rs-item { padding: 10px 16px; border-bottom: 1px solid var(--line); cursor: pointer; }
    .rs-item:last-child { border-bottom: 0; }
    .rs-item:hover { background: var(--surface2); }
    .rs-item.active { background: var(--mds-color-state-selected);
                      box-shadow: inset 3px 0 0 var(--hl); }
    .rs-item-top { display: flex; align-items: center; gap: 6px; }
    .rs-pin { color: var(--info); font-size: 13px; }
    .rs-name { font-size: 14px; font-weight: 600; color: var(--ink);
               white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .rs-item-meta { display: flex; align-items: center; gap: 8px; margin-top: 2px;
                    font-size: 13px; color: var(--mut); }
    .rs-empty, .rs-detail-empty { padding: 32px 16px; text-align: center;
                                  color: var(--mut); font-size: 13.5px; }
    .rs-badge { display: inline-flex; align-items: center; padding: 1px 8px;
                border-radius: 3px; font-size: 12.5px; font-weight: 500; white-space: nowrap; }
    .rs-badge-pending { background: var(--mds-color-bg-warning-tinted); color: var(--warn); }
    .rs-badge-failed { background: var(--mds-color-bg-error-tinted); color: var(--bad); }
    .rs-badge-pinned { background: var(--mds-color-bg-info-tinted); color: var(--info); }
    .rs-detail-head { display: flex; align-items: center; flex-wrap: wrap; gap: 10px;
                      margin-bottom: 12px; }
    .rs-detail-head h2 { font-size: 16px; font-weight: 600; color: var(--ink); }
    .rs-breadcrumb { display: flex; flex-wrap: wrap; align-items: center; gap: 6px;
                     margin-bottom: 16px; font-size: 13px; }
    .rs-bc-node { color: var(--mut); }
    .rs-bc-node.current { color: var(--ink); font-weight: 600; }
    .rs-bc-sep { color: var(--faint); }
    .rs-stats { margin-bottom: 16px; border: 1px solid var(--line);
                border-radius: var(--rad-panel); }
    .rs-stats > div { display: flex; justify-content: space-between; gap: 16px;
                      padding: 9px 16px; border-bottom: 1px solid var(--line); font-size: 13.5px; }
    .rs-stats > div:last-child { border-bottom: 0; }
    .rs-stat-k { color: var(--mut); }
    .rs-stat-v { color: var(--ink); font-weight: 500; text-align: right; }
    .rs-token-row { margin-bottom: 16px; }
    .rs-token-label { display: block; font-size: 13px; font-weight: 500; color: var(--ink2);
                      margin-bottom: 5px; }
    .rs-token { display: flex; align-items: center; gap: 8px; }
    .rs-token code { flex: 1; min-width: 0; display: flex; align-items: center;
                     height: var(--ctl); padding: 0 10px; background: var(--bg);
                     border: 1px solid var(--line2); border-radius: var(--rad-ctl);
                     color: var(--ink); overflow-x: auto; white-space: nowrap; }
    .rs-copy, .rs-btn {
      height: var(--ctl); padding: 0 14px; font-size: 14px; font-weight: 500;
      border-radius: var(--rad-ctl); cursor: pointer; border: 1px solid var(--line2);
      background: var(--raise); color: var(--ink); display: inline-flex; align-items: center;
      gap: 6px; white-space: nowrap; transition: background .12s, border-color .12s;
    }
    .rs-copy:hover, .rs-btn:hover { background: var(--surface2); border-color: var(--mut); }
    .rs-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .rs-btn-danger { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 45%, var(--line2)); }
    .rs-btn-danger:hover { background: color-mix(in srgb, var(--bad) 12%, transparent);
                           border-color: var(--bad); }
    .rs-create { display: grid; gap: 8px; padding: 16px; border-bottom: 1px solid var(--line); }
    .rs-create input, .rs-create textarea {
      width: 100%; height: var(--ctl); padding: 0 10px; background: var(--bg);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl); color: var(--ink);
    }
    .rs-create input::placeholder, .rs-create textarea::placeholder { color: var(--faint); }
    .rs-create input:focus, .rs-create textarea:focus { border-color: var(--primary); }
    .rs-create textarea { height: auto; padding: 8px 10px; min-height: 72px; resize: vertical;
                          font-family: var(--mds-font-family-mono); font-size: 12.5px; }
    .rs-create button {
      height: var(--ctl); font-weight: 600; cursor: pointer; background: var(--primary);
      color: var(--on-primary); border: 1px solid var(--primary); border-radius: var(--rad-ctl);
      transition: background .12s, border-color .12s;
    }
    .rs-create button:hover { background: var(--primary-h); border-color: var(--primary-h); }
    @media (max-width: 900px) { .rs-content { padding: 16px; } .rs-rail { max-width: none; } }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

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
          <form class="rs-create" id="rs-create-form"
                hx-post="/fragments/result-sets/create"
                hx-target="#rs-sidebar" hx-swap="innerHTML">
            <input type="text" name="name" placeholder="Name (optional)" maxlength="128">
            <textarea name="device_ids" placeholder="Device IDs, one per line (CSV import)"></textarea>
            <button type="submit">Create result set</button>
          </form>
          <div id="rs-sidebar"
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
          <div class="rs-detail-body" id="rs-detail">
            <div class="rs-detail-empty">
              <p>Select a result set to view its lineage and scope token.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    /* Clear the create form once its request succeeds, so a second Send does
       not repeat the same name and device list. A delegated body listener,
       not an inline handler attribute: htmx compiles those with
       new Function(), which this page's CSP (no 'unsafe-eval') blocks at
       runtime. The sidebar's own poll fires htmx:afterRequest too, so the
       listener keys on the form's id. */
    document.body.addEventListener('htmx:afterRequest', function(e) {
      var el = e.detail && e.detail.elt;
      if (el && el.id === 'rs-create-form' && e.detail.successful) el.reset();
    });
  </script>

</body></html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kResultSetsPageHtml =
    shell::bake(kResultSetsPageTemplate, {.active_key = "result-sets"});
// NOLINTEND(cert-err58-cpp)

} // namespace yuzu::server
