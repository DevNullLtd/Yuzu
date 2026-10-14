// Home page — the landing worklist (readout, estate, needs attention).
// Server-rendered HTMX; no page JavaScript, no polling (Refresh is a plain link).
// Every panel is filled by `/fragments/home/summary`; see home_routes.hpp.

#include "app_shell.hpp"
#include "home_ui.hpp"

#include <string>

// NOLINTBEGIN(cert-err58-cpp)

// Each literal stays far under the 16,380-byte MSVC C2026 cap.
const char* const kHomeCss = R"CSS(
.home-content{padding:22px 28px 36px;display:flex;flex-direction:column;gap:22px}
.home-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:22px;align-items:start}
.home-estate{display:flex;flex-wrap:wrap;align-items:center;gap:8px 28px;position:relative}
.home-donut{width:140px;height:140px;flex:0 0 auto}
.home-donut circle{stroke-width:16}
.home-track{stroke:var(--line)}
.home-s-on{stroke:var(--ok)}
.home-s-off{stroke:var(--mut)}
.home-s-ns{stroke:var(--warn)}
.home-legend i.home-s-on{background:var(--ok)}
.home-legend i.home-s-off{background:var(--mut)}
.home-legend i.home-s-ns{background:var(--warn)}
.home-legend{flex-direction:column;padding:0}
.home-donut-c{position:absolute;left:0;top:0;width:140px;height:140px;display:flex;flex-direction:column;
 align-items:center;justify-content:center;pointer-events:none}
.home-donut-c b{font-size:22px;font-weight:600;color:var(--ink);line-height:1.1}
.home-donut-c span{font-size:12.5px;color:var(--mut)}
.home-sub{font-size:13px;font-weight:600;color:var(--ink);margin:18px 0 8px}
.home-sbar{display:flex;height:10px;border-radius:2px;overflow:hidden;background:var(--line)}
.home-sbar i{display:block;height:100%}
.home-p-win{background:var(--info)}
.home-p-lin{background:var(--ok)}
.home-p-mac{background:var(--warn)}
.home-p-oth{background:var(--mut)}
.chip i.home-p-win,.chip i.home-p-lin,.chip i.home-p-mac,.chip i.home-p-oth{display:inline-block;width:10px;height:10px;
 margin-right:6px;border-radius:2px}
.home-att{display:flex;flex-direction:column;gap:0;padding:0}
.home-att .note{margin:12px 16px 0}
.home-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line)}
.home-row:last-child{border-bottom:0}
.home-rowb{flex:1 1 auto;min-width:0}
.home-rowb b{color:var(--ink);font-weight:500}
.home-row .sd{flex:0 0 auto;margin-right:0}
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

  <div class="home-grid">
    <section id="home-estate" class="panel">
      <div class="hd"><h2>Estate state</h2></div>
      <div class="pb mut">Loading</div>
    </section>
    <section id="home-attention" class="panel">
      <div class="hd"><h2>Needs attention</h2></div>
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
