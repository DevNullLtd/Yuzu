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
  <title>Yuzu - Users and roles</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-dialog.js" defer></script>
  <script src="/static/yuzu-access.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
<main class="page">
  <header class="page-header">
    <div>
      <h1>Users and roles</h1>
      <p class="subtitle">Who can sign in, what each role allows, and temporary elevation.</p>
    </div>
  </header>
  <div id="acc-alert" role="alert"></div>
  <div id="acc-msg" role="status" class="hint"></div>
  <div class="split">
    <div class="grow">
      <section class="panel" id="acc-users" hx-get="/fragments/access/users/list" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/users/list"
               data-denied="Listing users needs the Administrator account role."
               data-unavailable="The account store did not answer, so the list is unknown. This is not an empty list and nobody has been removed.">
        <div class="hd"><h2>Users</h2></div>
        <div class="pb"><p class="hint">Loading...</p></div>
      </section>
      <section class="panel" id="acc-roles" hx-get="/fragments/access/roles/list" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/roles/list"
               data-denied="The role catalogue needs UserManagement:Read (the Administrator and Viewer roles)."
               data-unavailable="The role store did not answer, so the roles are unknown. This is not an empty list.">
        <div class="hd"><h2>Roles</h2></div>
        <div class="pb"><p class="hint">Loading...</p></div>
      </section>
      <section class="panel" id="acc-role-perms"
               data-denied="The role catalogue needs UserManagement:Read (the Administrator and Viewer roles)."
               data-unavailable="The role store did not answer, so the permissions of this role are unknown. This is not an empty list.">
        <div class="hd"><h2>Role permissions</h2></div>
        <div class="empty"><span>Select a role to see what it allows.</span></div>
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
