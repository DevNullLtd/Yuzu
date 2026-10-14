// Workflows page (`GET /workflows`) -- workflow definitions with their steps, and the
// recurring schedules (Operate WF-A). The third child of Instructions in the shell.
//
// Both lists are server-rendered fragments (`/fragments/workflows`,
// `/fragments/schedules?view=page`, see workflows_page_render.hpp) fetched and swapped in
// by /static/yuzu-operate.js, which also copies the selected workflow's step list out of the
// definitions fragment into the side panel, patches each row's Last run / Result cells from
// `/fragments/workflow-runs?latest_per_workflow=true`, and loads the selected workflow's newest
// run (`/fragments/workflow-runs/{id}`) and its ten most recent runs on demand.
// Workflow actions (WF-3a): Run now, New workflow and Delete workflow go through the shared
// dialog module (/static/yuzu-dialog.js). The controls are offered from data-can-* hints the
// definitions fragment probes once per render; the write routes stay the gate. The schedule
// controls are not on this page yet (the Instructions page's Schedules tab keeps its Delete).
//
// Product UI: HTMX loaded only for the shell's Sign out (`hx-post`), CSP-clean (no hx-on,
// no inline handlers, htmx eval disabled), tokens from /static/yuzu.css, page-local CSS in
// operate_ui.hpp. Do NOT apply the `frontend-design` plugin here.

#include "app_shell.hpp"
#include "operate_ui.hpp"

#include <string>
#include <string_view>

namespace {

// Each literal stays well under MSVC's 16,380-byte raw-string limit (C2026); the CSS sits
// between the head and the body and is itself a literal in operate_ui.hpp.
constexpr std::string_view kHead = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Workflows</title>
<link rel="stylesheet" href="/static/yuzu.css">
<meta name="htmx-config" content='{"allowEval":false}'>
<script src="/static/htmx.js"></script>
<style>)HTM";

constexpr std::string_view kBody = R"HTM(</style>
</head>
<body data-page="workflows">
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="pg">
<header class="page-header"><div><h1>Workflows</h1>
<p class="subtitle">Multi-step workflows and their runs. Schedules below run a single instruction on a repeat.</p></div></header>
<div class="ops-grid">
<div class="ops-main">
<section class="panel ops-listbox">
<div class="hd"><h2>Workflows</h2><button type="button" class="btn btn-primary btn-sm end" id="wf-new" hidden>New workflow</button></div>
<div id="wf-list"><div class="empty-state">Loading…</div></div>
<div id="wf-runs-store" hidden></div>
</section>
<section class="panel ops-listbox ops-sc">
<div class="hd"><h2>Schedules</h2></div>
<div id="sc-list"><div class="empty-state">Loading…</div></div>
</section>
</div>
<aside class="ops-side">
<section class="panel ops-sel" id="wf-steps">
<div class="hd"><h2 id="wf-steps-title">Steps</h2><button type="button" class="btn btn-danger btn-sm end" id="wf-del" hidden>Delete</button></div>
<div id="wf-steps-body"><div class="empty-state">Select a workflow to see its steps.</div></div>
</section>
<section class="panel ops-sel" id="wf-run">
<div class="hd"><h2>Latest run</h2></div>
<div id="wf-run-body"><div class="empty-state">Select a workflow to see its latest run.</div></div>
</section>
<section class="panel ops-sel" id="wf-recent">
<details id="wf-recent-det">
<summary class="hd"><h2>Recent runs</h2></summary>
<div id="wf-recent-body"><div class="empty-state">Select a workflow to see its recent runs.</div></div>
</details>
</section>
</aside>
</div>
</main>
<div class="toast-container" id="toasts" aria-live="polite"></div>
<script src="/static/yuzu-dialog.js" defer></script>
<script src="/static/yuzu-operate.js" defer></script>
</body></html>
)HTM";

static_assert(kHead.size() < 15000 && kBody.size() < 15000,
              "a Workflows page literal outgrew the MSVC raw-literal bound");

// Built once at static init: head + shared CSS + body, then the shell is baked in.
// NOLINTBEGIN(cert-err58-cpp)
const std::string kWorkflowsPageTemplate =
    std::string(kHead) + std::string(yuzu::server::kOperateCss) + std::string(kBody);
// NOLINTEND(cert-err58-cpp)

} // namespace

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kWorkflowsPageHtml = yuzu::server::shell::bake(
    kWorkflowsPageTemplate.c_str(), {.active_key = "workflows"});
// NOLINTEND(cert-err58-cpp)
