// Access pages: the Users page template (see access_ui.hpp).
//
// The `data-denied` / `data-unavailable` sentences below are byte-equal to
// access::kUsersDenied / kUsersUnavailable / kDetailUnavailable (access_render.hpp); a test
// pins the equality so the two copies cannot drift.

#include "access_ui.hpp"

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kAccessUsersTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu - Users</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-access.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Users</h1>
      <p class="subtitle">The accounts that can sign in to this server. This page is read-only; manage accounts in Settings.</p>
    </div>
  </header>
  <div class="split">
    <div class="grow">
      <section class="panel" id="acc-users" hx-get="/fragments/access/users/list" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/users/list"
               data-denied="Listing users needs the Administrator account role."
               data-unavailable="The account store did not answer, so the list is unknown. This is not an empty list and nobody has been removed.">
        <div class="hd"><h2>Users</h2></div>
        <div class="pb"><p class="hint">Loading...</p></div>
      </section>
    </div>
    <div class="side2">
      <section class="panel" id="acc-detail"
               data-src="/fragments/access/users/detail"
               data-denied="Listing users needs the Administrator account role."
               data-unavailable="The account store did not answer, so this account could not be read.">
        <div class="hd"><h2>Account</h2></div>
        <div class="empty"><span>Select a user from the list to see the account.</span></div>
      </section>
    </div>
  </div>
</main>
</body>
</html>
)HTM";

extern const char* const kAccessUsersHtml =
    yuzu::server::shell::bake(kAccessUsersTemplate, {.active_key = "users"});
// NOLINTEND(cert-err58-cpp)
