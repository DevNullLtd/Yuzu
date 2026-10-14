/**
 * @file test_access_js.cpp
 * @brief String pins on the Access page template and its embedded glue script. The repo has
 *        no JS runner, so these prove a token is present, not that a branch executes; the
 *        behaviour itself is exercised by the headless browser run recorded in the PR body.
 */

#include "access_render.hpp"
#include "access_ui.hpp"
#include "app_shell.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuAccessJs;
}

using Catch::Matchers::ContainsSubstring;

TEST_CASE("access glue: the denied and unavailable mapping is keyed on the panel's data attributes",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* token : {"htmx:responseError", "htmx:sendError", "data-denied",
                              "dataset.denied", "dataset.unavailable", "location.assign('/login')",
                              "data-act=\"reload\"", "dataset.src", "textContent"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("access glue: no HTML-string injection, and every request goes through the dialog module",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* bad : {"innerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "hx-on", "fetch(", "XMLHttpRequest"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
    // Step-up, the single replay and the audit/persist flags live in YuzuDialog.request.
    CHECK_THAT(js, ContainsSubstring("window.YuzuDialog.request("));
}

TEST_CASE("access glue: the user actions call the existing routes with encoded, vetted segments",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* token :
         {"ACTS.add", "ACTS.remove", "ACTS.role", "ACTS.revoke", "ACTS.reload",
          "'/api/settings/users'", "'/api/settings/users/' + s", "'/role'",
          "'/api/v1/sessions?username=' + encodeURIComponent(name)",
          "encodeURIComponent(s)",
          // A dot segment is resolved away by the browser even when percent-encoded, so a
          // value made only of dots is refused instead of encoded.
          "/^\\.+$/.test(s)",
          // The role is checked against the only two values the route accepts.
          "role !== 'admin' && role !== 'user'",
          "r.auditFailed", "r.warning", "unknown(r)"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("access glue: assignments, derived cells and Your account call the existing routes safely",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* token :
         {"ACTS.assign", "ACTS.unassign", "ACTS['pw-change']", "ACTS['signout-all']",
          "'/api/v1/rbac/roles/' + seg(v.role) + '/assignments'",
          "'/api/v1/rbac/roles/' + seg(role) + '/assignments/' + seg(id)", "principal_type: 'user'",
          // Both path segments are re-checked against the route's own charset before use.
          "var NAME = /^[A-Za-z0-9._-]+$/;", "!NAME.test(role) || !NAME.test(id)",
          "roles.indexOf(v.role) >= 0",
          "'/api/v1/users/me/password'", "current_password", "new_password",
          "'/api/v1/sessions/me'", "api_tokens_db_persisted === false",
          // Derived cells: 'Not shown' unless the table was read in full; Map, not a plain object,
          // so a principal named __proto__ cannot corrupt the index.
          "data-rbac-for", "data-assigned-for", "'Not shown'", "tbl.dataset.capped === '0'",
          "new Map()", "table[data-assignments]"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
    // A 0 is written only on a full read.
    CHECK_THAT(js, ContainsSubstring("full ? String(byRole.get(td.dataset.assignedFor) || 0) : 'Not shown'"));
}

TEST_CASE("access glue: enforcement, elevation and the permission check keep their guards",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* token :
         {"ACTS.enforce", "ACTS.elevate", "ACTS.stepdown", "ACTS.check",
          "'/api/v1/rbac/enforcement'", "{ json: { enabled: want } }",
          // The switch is put back at once; only a redraw from the server changes it.
          "sw.checked = !want;", "reloadPanels()", "sayAfterSwap('acc-enforcement', 'ok', text)",
          "if (pendingOut && id === pendingOut.panelId)",
          "'/api/v1/elevate'", "'/api/v1/elevate/revoke'", "justification", "duration_secs",
          "new TextEncoder().encode(j).length > 1024", "Enter a reason.", "r.auditFailed", "r.data.expires_at",
          "'/api/v1/rbac/check'", "securable_type", "typeof allowed === 'boolean'", "Enter an area and an operation.",
          "the role store may not have answered: check again.", "data-slot=\"out\"",
          // Gate-fix round: Retry on the role-permissions panel, the unverified-account note, the
          // enforcement warning inside both confirmations.
          "function keepPermsSrc(e, t)", "pendingOut = null; // the redraw it waits for failed", "A name made only of dots cannot be used.", "t.dataset.src = rp", "target_provisioned === 'unknown'",
          "'immediately, and a person with no management group role sees no devices.', ENFORCE_NOTE]",
          "'most things and change nothing.', ENFORCE_NOTE]"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("access page: the template is inline-free, single-shell and under the MSVC literal cap",
          "[access][js]") {
    const std::string t = kAccessUsersTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    CHECK(std::strlen(kAccessUsersTemplate) < 15000);

    // The scripts are exactly these three, all same-origin; the dialog loads before the glue.
    std::vector<std::string> srcs;
    const std::regex script_src(R"re(<script src="([^"]+)")re");
    for (std::sregex_iterator it(t.begin(), t.end(), script_src), end; it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/yuzu-dialog.js",
                                           "/static/yuzu-access.js"});
}

TEST_CASE("access page: the template's sentences are byte-equal to the renderer's constants",
          "[access][js]") {
    const std::string t = kAccessUsersTemplate;
    using namespace yuzu::server::access;
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kUsersDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kUsersUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kDetailUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring(std::string(kSelectUser)));
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kRolesDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kRolesUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kRolePermsUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring(std::string(kSelectRole)));
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kAssignmentsDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kAssignmentsUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/roles/assignments\""));
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kEnforcementDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kEnforcementUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/enforcement\""));
    // The marker the page route fills with the signed-in user's own panel, exactly once.
    CHECK(t.find(std::string(kAccountMarker)) != std::string::npos);
    CHECK(t.find(std::string(kAccountMarker)) == t.rfind(std::string(kAccountMarker)));
    // The roles panel refetches itself; the permissions panel is filled by its View buttons.
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/roles/list\""));
    // Both panels name their own refetch source for the Retry button.
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/users/list\""));
}

TEST_CASE("access page: elevation and check are static markup with the bounds the server enforces",
          "[access][js]") {
    const std::string t = kAccessUsersTemplate;
    for (const char* token :
         {"id=\"el-j\" maxlength=\"1024\"", "data-act=\"elevate\"", "data-act=\"stepdown\"",
          "standing Administrator role", "id=\"ck-s\" type=\"text\" maxlength=\"128\"",
          "id=\"ck-o\" type=\"text\" maxlength=\"64\"", "data-act=\"check\""}) {
        INFO(token);
        CHECK_THAT(t, ContainsSubstring(token));
    }
    // The disabled "another person" field has no name and no action: nothing can submit it.
    const auto at = t.find("id=\"ck-w\"");
    REQUIRE(at != std::string::npos);
    const auto tag = t.substr(at, t.find('>', at) - at);
    CHECK_THAT(tag, ContainsSubstring("disabled"));
    CHECK_THAT(tag, !ContainsSubstring("name="));
    CHECK_THAT(tag, !ContainsSubstring("data-act"));
    // No per-row elevate anywhere: the handlers read fixed ids and so act on the caller only.
    CHECK_THAT(yuzu::server::kYuzuAccessJs, ContainsSubstring("document.getElementById('el-j')"));
}
