// Executions page (`GET /executions`) -- the read-only list of instruction dispatches with
// status and instruction filters and one "Selected execution" panel (Operate O1). The first
// child of Instructions in the shell.
//
// The list and the panel are server-rendered fragments (`/fragments/executions?view=page`,
// `/fragments/executions/{id}/detail?view=page`, see executions_page_render.hpp) fetched
// and swapped in by /static/yuzu-operate.js. Cancel, re-run, live updates and the device
// results are NOT on this page yet: the Instructions page's Executions tab keeps them.
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
<title>Yuzu — Executions</title>
<link rel="stylesheet" href="/static/yuzu.css">
<meta name="htmx-config" content='{"allowEval":false}'>
<script src="/static/htmx.js"></script>
<style>)HTM";

constexpr std::string_view kBody = R"HTM(</style>
</head>
<body data-page="executions">
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="pg">
<header class="page-header"><div><h1>Executions</h1>
<p class="subtitle">Instruction dispatches and their per-device results.</p></div></header>
<div class="note" id="exec-confined" hidden><b>Confined view.</b> You can see executions you dispatched and executions that reached devices in your scope. Counts cover your devices only; scope and parameters are redacted.</div>
<div id="exec-stats"></div>
<div class="ops-grid">
<div class="ops-main">
<section class="panel ops-listbox">
<div class="hd"><h2>Executions</h2><span class="chip" id="exec-chip" hidden>Showing the <b></b> most recent</span></div>
<div class="ops-bar">
<label class="sr" for="f-def">Instruction</label>
<select id="f-def" class="in"><option value="">All instructions</option></select>
<span class="hint" id="f-def-hint" hidden>Instruction list unavailable; filter by status only.</span>
<div class="seg" role="radiogroup" aria-label="Status">
<label><input type="radio" name="est" value="" checked>All</label>
<label><input type="radio" name="est" value="running">Running</label>
<label><input type="radio" name="est" value="succeeded">Succeeded</label>
<label><input type="radio" name="est" value="completed">With failures</label>
<label><input type="radio" name="est" value="cancelled">Cancelled</label>
<label><input type="radio" name="est" value="pending">Pending</label>
</div></div>
<div id="exec-list"><div class="empty-state">Loading…</div></div>
</section>
<section class="panel ops-dev" id="exec-devices" hidden></section>
</div>
<aside class="ops-side">
<section class="panel ops-sel" id="exec-selected">
<div class="hd"><h2>Selected execution</h2></div>
<div class="empty-state">Select an execution to see its scope, parameters and responses.</div>
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
              "an Executions page literal outgrew the MSVC raw-literal bound");

// Built once at static init: head + shared CSS + body, then the shell is baked in.
// NOLINTBEGIN(cert-err58-cpp)
const std::string kExecutionsPageTemplate =
    std::string(kHead) + std::string(yuzu::server::kOperateCss) + std::string(kBody);
// NOLINTEND(cert-err58-cpp)

} // namespace

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kExecutionsPageHtml = yuzu::server::shell::bake(
    kExecutionsPageTemplate.c_str(), {.active_key = "executions"});
// NOLINTEND(cert-err58-cpp)
