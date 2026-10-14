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
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-tokens.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Tokens and principals</h1>
      <p class="subtitle">Credentials for people, automation and agentic workers. This page is read-only; create, rotate and revoke in Settings.</p>
    </div>
  </header>
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
        <div id="principals-body"
             data-src="/fragments/access/principals/list"
             data-denied="Engine principals need the Administrator account role."
             data-unavailable="The principal store did not answer, so the list is unknown. This is not an empty list.">
          <div class="pb"><p class="hint">Loading...</p></div>
        </div>
      </section>
    </div>
    <div class="side2" id="side-principal"
         data-src="/fragments/access/principals/detail"
         data-denied="Engine principals need the Administrator account role."
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
