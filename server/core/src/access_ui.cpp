// Access pages: the Users page template (see access_ui.hpp).
//
// The `data-denied` / `data-unavailable` sentences below are byte-equal to
// the `access::k*Denied` / `k*Unavailable` / `kSelect*` constants of access_render.hpp (Users,
// Roles, Role permissions, Role assignments, Enforcement); a test pins the equality so the two
// copies cannot drift.

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
      <section class="panel" id="acc-assignments" hx-get="/fragments/access/roles/assignments" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/roles/assignments"
               data-denied="The grant table needs AccessReview:Read (the Administrator and Reviewer roles)."
               data-unavailable="The grant table could not be read, so who holds which role is unknown. This is not an empty list.">
        <div class="hd"><h2>Role assignments</h2></div>
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
      <!--yuzu:account-->
      <section class="panel" id="acc-elevation">
        <div class="hd"><h2>Your elevation</h2></div>
        <div class="form">
          <div class="fld"><label for="el-j">Reason</label>
            <textarea id="el-j" maxlength="1024" autocomplete="off" placeholder="Why do you need admin rights?"></textarea>
            <span class="hint">Required, recorded in the audit log. Up to 1024 bytes.</span></div>
          <div class="fld"><label for="el-d">Duration (seconds)</label>
            <input class="in mono" id="el-d" type="text" inputmode="numeric" autocomplete="off" value="3600">
            <span class="hint">Capped by the server (default 3600). A longer value is clamped.</span></div>
        </div>
        <div class="btns"><button type="button" class="btn primary" data-act="elevate">Elevate my session</button>
          <button type="button" class="btn" data-act="stepdown">Step down</button></div>
        <div class="pb" data-slot="out" role="status" aria-live="polite"></div>
        <div class="pb"><p class="hint">This page cannot show whether your session is currently elevated. Step down is always safe.</p>
          <p class="hint">While elevated you can use administrator features. Assigning roles, changing account roles and changing RBAC enforcement still need your own standing Administrator role.</p></div>
      </section>
      <section class="panel" id="acc-check">
        <div class="hd"><h2>Check your own permission</h2></div>
        <div class="form">
          <div class="row2">
            <div class="fld"><label for="ck-s">Area</label>
              <input class="in mono" id="ck-s" type="text" maxlength="128" autocomplete="off" spellcheck="false" placeholder="UserManagement">
              <span class="hint">The area of the platform, for example UserManagement or AuditLog.</span></div>
            <div class="fld"><label for="ck-o">Operation</label>
              <input class="in mono" id="ck-o" type="text" maxlength="64" autocomplete="off" spellcheck="false" placeholder="Read">
              <span class="hint">The operation, for example Read or Write.</span></div>
          </div>
          <div class="fld"><label for="ck-w">Check for another person</label>
            <input class="in" id="ck-w" type="text" disabled placeholder="Not available yet" title="The check only covers the signed-in account. Checking another person is not available yet."></div>
        </div>
        <div class="btns"><button type="button" class="btn primary" data-act="check">Check permission</button></div>
        <div class="pb" data-slot="out" role="status" aria-live="polite"></div>
        <div class="pb"><p class="hint">Checks your role grants only. While enforcement is off, access follows your account role instead, so Denied here does not by itself block you.</p></div>
      </section>
      <section class="panel" id="acc-enforcement" hx-get="/fragments/access/enforcement" hx-trigger="load" hx-swap="innerHTML"
               data-src="/fragments/access/enforcement"
               data-denied="The enforcement setting needs a signed-in session."
               data-unavailable="The enforcement setting could not be read. This is not the same as it being off.">
        <div class="hd"><h2>RBAC enforcement</h2></div>
        <div class="pb"><p class="hint">Loading...</p></div>
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
