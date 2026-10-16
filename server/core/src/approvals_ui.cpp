// Approvals page (`GET /approvals`) -- the read-only list of dispatch approval requests,
// a status filter and one detail panel (Operate O1). A child of Instructions in the shell.
//
// The list is a server-rendered fragment (`/fragments/approvals?view=page`, see
// approvals_page_render.hpp) fetched and swapped in by /static/yuzu-operate.js, which also
// fills the detail panel from the selected row's data-* attributes. Approve / reject open
// the shared dialog (/static/yuzu-dialog.js) and POST /api/approvals/{id}/approve|reject.
//
// Product UI: HTMX loaded only for the shell's Sign out (`hx-post`), CSP-clean (no hx-on,
// no inline handlers, htmx eval disabled), tokens from /static/yuzu.css, page-local CSS in
// operate_ui.hpp. Do NOT apply the `frontend-design` plugin here.

#include "app_shell.hpp"
#include "operate_ui.hpp"

#include <string>
#include <string_view>

namespace {

// Three literals, each well under MSVC's 16,380-byte raw-string limit (C2026); the CSS sits
// between the head and the body and is itself a literal in operate_ui.hpp.
constexpr std::string_view kHead = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Approvals</title>
<link rel="stylesheet" href="/static/yuzu.css">
<meta name="htmx-config" content='{"allowEval":false}'>
<script src="/static/htmx.js"></script>
<style>)HTM";

constexpr std::string_view kBody = R"HTM(</style>
</head>
<body data-page="approvals">
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="pg">
<header class="page-header"><div><h1>Approvals</h1>
<p class="subtitle">Dispatch requests waiting for a decision by a different user account.</p></div></header>
<div class="ops-grid">
<div class="ops-main">
<section class="panel ops-listbox">
<div class="hd"><h2>Requests</h2><span class="chip" id="ap-pending" hidden><b></b> pending</span></div>
<div class="ops-bar"><div class="seg" role="radiogroup" aria-label="Status">
<label><input type="radio" name="ast" value="pending" checked>Pending</label>
<label><input type="radio" name="ast" value="">All</label>
<label><input type="radio" name="ast" value="approved">Approved</label>
<label><input type="radio" name="ast" value="rejected">Rejected</label>
<label><input type="radio" name="ast" value="expired">Expired</label>
</div></div>
<div id="ap-list"><div class="empty-state">Loading…</div></div>
</section>
</div>
<aside class="ops-side">
<section class="panel ops-sel" id="ap-detail">
<div class="hd"><h2>Request detail</h2><span class="pill" data-f="pill" hidden></span></div>
<div class="empty-state" data-f="empty">Select a request to see who asked, for what scope, and any decision.</div>
<div class="kvl" data-f="kv" hidden>
<div><span>Request</span><b><span data-f="name"></span><small class="mono faint" data-f="def"></small></b></div>
<div><span>Requested by</span><b><span class="clip" data-f="by"></span></b></div>
<div><span>Requested</span><b data-f="at"></b></div>
<div class="stack"><span>Scope</span><code class="blk" data-f="scope"></code><span class="faint" data-f="no-scope">None recorded. The request named devices directly.</span></div>
<div data-f="rev-by-row" hidden><span>Decided by</span><b><span class="clip" data-f="rev-by"></span></b></div>
<div data-f="rev-at-row" hidden><span>Decided</span><b data-f="rev-at"></b></div>
<div class="stack" data-f="comment-row" hidden><span>Reviewer comment</span><div class="cmt" data-f="comment"></div></div>
<div><span>Approval id</span><b><span class="mono clip" data-f="id"></span></b></div>
</div>
<div class="btns" data-f="actions" hidden>
<button type="button" class="btn btn-primary" data-act="approve">Approve</button>
<button type="button" class="btn btn-danger" data-act="reject">Reject</button>
</div>
<div class="btns"><span class="hint" data-f="self" hidden>You submitted this — another reviewer must approve</span></div>
<div class="held" data-f="notes" hidden>
<div>Pending requests are expired 7 days after submission, when the next request is submitted; until then they stay listed.</div>
<div>Approving records a decision and audits it. It does not run the instruction itself.</div>
<div data-f="n-params">The parameter values are not stored with this request. A reviewer decides on the instruction and scope only.</div>
<div data-f="n-mcp" hidden>The requesting agent must re-call the tool with this approval id for it to run.</div>
</div>
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
              "an Approvals page literal outgrew the MSVC raw-literal bound");

// Built once at static init: head + shared CSS + body, then the shell is baked in.
// NOLINTBEGIN(cert-err58-cpp)
const std::string kApprovalsPageTemplate =
    std::string(kHead) + std::string(yuzu::server::kOperateCss) + std::string(kBody);
// NOLINTEND(cert-err58-cpp)

} // namespace

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kApprovalsPageHtml = yuzu::server::shell::bake(
    kApprovalsPageTemplate.c_str(), {.active_key = "approvals"});
// NOLINTEND(cert-err58-cpp)
