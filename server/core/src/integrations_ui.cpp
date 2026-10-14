// System "Integrations" page (GET /settings/integrations), baked once at static init.
//
// HTMX-first: each panel is a server-rendered fragment loaded by hx-get, at the URLs and ids
// the /settings monolith already uses (#mcp-section, #gateway-section). The page script is
// static/yuzu-integrations.js (embedded; not subject to MSVC's raw-literal cap). The
// template is assembled at static init from named raw parts, each pinned under 15,000 bytes
// (MSVC C2026 is 16,380).

#include "app_shell.hpp"

#include <string>

namespace {

constexpr char kHead[] = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Integrations</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    .pg { padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px; }
    .muted { color: var(--mut); }
    code { font-family: var(--mds-font-family-mono); font-size: 12.5px; overflow-wrap: anywhere; }
    .panel .pb { display: flex; flex-direction: column; gap: 10px; }
    .panel .pb p { margin: 0; }
    .panel .pb a { color: var(--primary); }
    .panel details summary { cursor: pointer; color: var(--ink2); font-weight: 500; }
    .panel details .tw { margin-top: 8px; }
    @media (max-width: 820px) { .pg { padding: 16px; } }
  </style>
</head>
)HTM";

constexpr char kBody[] = R"HTM(<body>

<!--yuzu:shell--><!--/yuzu:shell-->

<main class="pg">
  <div class="page-header"><div>
    <h1>Integrations</h1>
    <p class="subtitle">The MCP endpoint and the gateway.</p>
  </div></div>

  <section class="panel" id="mcp-panel" aria-labelledby="h-mcp">
    <div class="hd"><h2 id="h-mcp">MCP server</h2><span class="sub">Model Context Protocol endpoint for AI-driven fleet management. MCP allows AI models to query agents, check compliance, and manage your fleet through a secure JSON-RPC interface.</span></div>
    <div id="mcp-section"
         hx-get="/fragments/settings/mcp"
         hx-trigger="load"
         hx-swap="innerHTML"><div class="pb muted">Loading...</div></div>
  </section>

  <section class="panel" id="gateway-panel" aria-labelledby="h-gateway">
    <div class="hd"><h2 id="h-gateway">Gateway</h2><span class="sub">The Erlang/OTP gateway node sits between agents and this server, providing connection multiplexing, heartbeat batching, and circuit breaker protection.</span></div>
    <div id="gateway-section"
         hx-get="/fragments/settings/gateway"
         hx-trigger="load"
         hx-swap="innerHTML"><div class="pb muted">Loading...</div></div>
  </section>
</main>

<div id="toast-container" class="toast-container"></div>
<script src="/static/yuzu-integrations.js" defer></script>
</body>
</html>
)HTM";

static_assert(sizeof(kHead) < 15000, "kHead exceeds the MSVC raw-literal ceiling");
static_assert(sizeof(kBody) < 15000, "kBody exceeds the MSVC raw-literal ceiling");

std::string assemble() {
    std::string page;
    page.reserve(sizeof(kHead) + sizeof(kBody));
    page += kHead;
    page += kBody;
    return page;
}

} // namespace

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kSettingsIntegrationsHtml = yuzu::server::shell::bake(
    assemble().c_str(), {.active_key = "settings-integrations",
                         .title = "Integrations",
                         .breadcrumb = "Settings"});
// NOLINTEND(cert-err58-cpp)
