// Home page — the landing worklist (readout, needs attention).
// Server-rendered HTMX; no page JavaScript, no polling (Refresh is a plain link).
// The readout and needs-attention panel are filled by `/fragments/home/summary`
// (home_routes.hpp); policies, activity and health by their own fragments
// (home_panels_routes.hpp, health_routes.cpp).

#include "app_shell.hpp"
#include "home_ui.hpp"

#include <string>

// NOLINTBEGIN(cert-err58-cpp)

// Each literal stays far under the 16,380-byte MSVC C2026 cap.
const char* const kHomeCss = R"CSS(
.home-content{padding:22px 28px 36px;display:flex;flex-direction:column;gap:22px}
.home-att{display:flex;flex-direction:column;gap:0;padding:0}
.home-att .note{margin:12px 16px 0}
.home-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line)}
.home-row:last-child{border-bottom:0}
.home-rowb{flex:1 1 auto;min-width:0}
.home-rowb b{color:var(--ink);font-weight:500}
.home-row .sd{flex:0 0 auto;margin-right:0}
.home-panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:22px;align-items:start}
.home-panels .panel{min-width:0}
.home-panels .kvl{padding:0}
.home-panels .bar{margin:0 16px 10px}
)CSS";

static const char* const kHomeHead = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Home</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
<style>)HTM";

static const char* const kHomeBody = R"HTM(</style>
</head><body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<main class="home-content">
  <div class="page-header">
    <div>
      <h1>Home</h1>
      <p class="subtitle">What needs attention across the estate right now.</p>
    </div>
    <div class="header-actions"><a class="btn sm" href="/home">Refresh</a></div>
  </div>

  <section id="home-readout" class="readout" aria-label="Estate readout"
           hx-get="/fragments/home/summary" hx-trigger="load" hx-swap="outerHTML">
    <div class="ro"><div class="l">Loading</div></div>
  </section>

  <section id="home-attention" class="panel">
    <div class="hd"><h2>Needs attention</h2></div>
    <div class="pb mut">Loading</div>
  </section>

  <div class="home-panels">
    <section class="panel" id="home-policies" hx-get="/fragments/home/policies"
             hx-trigger="load" hx-swap="outerHTML">
      <div class="hd"><h3>Compliance by policy</h3></div>
      <div class="pb mut">Loading</div>
    </section>
    <section class="panel" id="home-activity" hx-get="/fragments/home/activity"
             hx-trigger="load" hx-swap="outerHTML">
      <div class="hd"><h3>Recent activity</h3></div>
      <div class="pb mut">Loading</div>
    </section>
    <section class="panel" id="home-health" hx-get="/fragments/home/health"
             hx-trigger="load" hx-swap="outerHTML">
      <div class="hd"><h3>Server health</h3></div>
      <div class="pb mut">Loading</div>
    </section>
  </div>
</main>

</body></html>
)HTM";

namespace {
// Composed once at static init; one owner string keeps the baked page's source alive.
const std::string kHomeTemplateStr = std::string(kHomeHead) + kHomeCss + kHomeBody;
} // namespace

const char* const kHomeTemplate = kHomeTemplateStr.c_str();

// The shell (sidebar + header) is rendered into the template once, at static init
// (app_shell.hpp). No `active_key`: Home has no nav item, so the breadcrumb is the title.
extern const char* const kHomeHtml = yuzu::server::shell::bake(kHomeTemplate, {.title = "Home"});
// NOLINTEND(cert-err58-cpp)
