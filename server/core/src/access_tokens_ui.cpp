// Tokens and principals page template (see access_tokens_ui.hpp).
//
// The `data-denied` / `data-unavailable` sentences are byte-equal to the constants in
// access_tokens_render.hpp; test_access_tokens_js.cpp pins the equality.
// The literal is far below MSVC's 16,380-byte raw-string cap (C2026).

#include "access_tokens_ui.hpp"

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kAccessTokensTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu - Tokens and principals</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false,"historyEnabled":false}'>
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-dialog.js" defer></script>
  <script src="/static/yuzu-tokens.js" defer></script>
  <script src="/static/yuzu-tokens-actions.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Tokens and principals</h1>
      <p class="subtitle">Credentials for people, automation and agentic workers.</p>
    </div>
  </header>
  <div id="flash" class="strip" role="status" aria-live="polite"></div>
  <section id="reveal" class="reveal" role="region" aria-label="Newly created secret" hidden>
    <b id="reveal-title"></b>
    <p id="reveal-msg"></p>
    <code id="reveal-secret" hidden></code>
    <div class="btns" id="reveal-btns">
      <button type="button" class="btn btn-sm" data-tk="reveal-copy">Copy</button>
      <button type="button" class="btn btn-primary btn-sm" data-tk="reveal-stored">I have stored this</button>
    </div>
  </section>
  <div class="split">
    <div class="grow">
      <section class="panel" id="panel-tokens">
        <div id="tokens-body" hx-get="/fragments/access/tokens/list" hx-trigger="load" hx-swap="innerHTML"
             data-src="/fragments/access/tokens/list"
             data-denied="Listing API tokens needs the ApiToken:Read permission."
             data-unavailable="The token store did not answer, so the list is unknown. This is not an empty list.">
          <div class="pb"><p class="hint">Loading...</p></div>
        </div>
      </section>
      <section class="panel" id="panel-principals">
        <div class="hd"><h2>Engine principals</h2></div>
        <div id="principals-note" class="strip" role="status" aria-live="polite"></div>
        <div id="principals-body" hx-get="/fragments/access/principals/list" hx-trigger="load" hx-swap="innerHTML"
             data-src="/fragments/access/principals/list"
             data-denied="Engine principals need the EnginePrincipal:Read permission."
             data-unavailable="The principal store did not answer, so the list is unknown. This is not an empty list.">
          <div class="pb"><p class="hint">Loading...</p></div>
        </div>
      </section>
    </div>
    <div class="side2" id="side-principal"
         data-src="/fragments/access/principals/detail"
         data-denied="Engine principals need the EnginePrincipal:Read permission."
         data-unavailable="This principal could not be read.">
      <section class="panel"><div class="empty"><b>No principal selected.</b><span>Select a principal from the list.</span></div></section>
    </div>
  </div>
</main>
</body>
</html>
)HTM";

extern const char* const kAccessTokensHtml =
    yuzu::server::shell::bake(kAccessTokensTemplate, {.active_key = "tokens"});
// NOLINTEND(cert-err58-cpp)
