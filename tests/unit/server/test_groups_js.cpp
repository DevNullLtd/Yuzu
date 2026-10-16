/**
 * @file test_groups_js.cpp
 * @brief String pins on the embedded glue script. The repo has no JS runner, so these prove a
 *        token is present or absent, not that a branch executes.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

namespace yuzu::server {
extern const std::string kYuzuGroupsJs;
}

using Catch::Matchers::ContainsSubstring;

TEST_CASE("groups glue: failures are reported by toast and by in-panel notes", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    for (const char* token :
         {"'showToast'", "e.detail", "'htmx:responseError'", "'htmx:sendError'", "data-denied",
          "dataset.denied", "dataset.unavailable", "location.assign('/login')",
          "data-gact=\"reload\"", "dataset.src", "textContent", "createElement"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("groups glue: error toasts persist; others expire", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    // The auto-dismiss timer is skipped for level 'error'.
    CHECK_THAT(js, ContainsSubstring("if (lvl !== 'error') setTimeout("));
    CHECK_THAT(js, ContainsSubstring("'toast toast-' + lvl"));
}

TEST_CASE("groups glue: only a panel's own load replaces the panel", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    // The panel note is built only for the panel's OWN load-triggered GET.
    CHECK_THAT(js, ContainsSubstring("t === e.target"));
    CHECK_THAT(js, ContainsSubstring("cfg.verb === 'get'"));
    CHECK_THAT(js, ContainsSubstring("if (!ownLoad(e)) { mutationFailed(e, s); return; }"));
    CHECK_THAT(js, ContainsSubstring("if (ownLoad(e)) unavailable(e.detail.target); else mutationFailed(e, 0);"));
}

TEST_CASE("groups glue: a failed mutation gets a status-specific persistent toast",
          "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    // Scoped to requests from inside a panel: the shell's own sign-out is not ours.
    CHECK_THAT(js, ContainsSubstring("e.target.closest('[data-denied]')"));
    // 401 signs out exactly as the own-load path does.
    CHECK_THAT(js, ContainsSubstring("if (status === 401) { location.assign('/login'); return; }"));
    CHECK_THAT(js, ContainsSubstring("403: 'Not allowed'"));
    CHECK_THAT(js, ContainsSubstring("That changed since you loaded it - the list has been refreshed"));
    CHECK_THAT(js, ContainsSubstring("'Could not reach the server'"));
    CHECK_THAT(js, ContainsSubstring("'The server could not do that (HTTP ' + status + ')'"));
    CHECK_THAT(js, ContainsSubstring("'error')"));
    // A response that already carries a toast is not toasted twice.
    CHECK_THAT(js, ContainsSubstring("getResponseHeader('HX-Trigger')"));
    CHECK_THAT(js, ContainsSubstring("trig.indexOf('showToast') !== -1"));
    // A stale-list 409 re-reads the panel it came from.
    CHECK_THAT(js, ContainsSubstring("if (status === 409) reload(e.target.closest('[data-denied]'));"));
}

TEST_CASE("groups glue: Retry reloads with the panel as the request source", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    // Without a source htmx uses <body>, so ownLoad() never matches and a failed retry (or a
    // 401 on retry) would show nothing.
    CHECK_THAT(js, ContainsSubstring("{ source: panel, target: panel }"));
    CHECK_THAT(js, ContainsSubstring("reload(document.getElementById(r.dataset.target))"));
    CHECK_THAT(js, !ContainsSubstring("{ target: '#'"));
    // Own attribute namespace: yuzu-access.js owns data-act="reload" on its pages.
    CHECK_THAT(js, ContainsSubstring("btn.dataset.gact = 'reload'"));
    CHECK_THAT(js, !ContainsSubstring("data-act="));
    CHECK_THAT(js, !ContainsSubstring("dataset.act"));
}

TEST_CASE("groups glue: no HTML-string injection, eval, storage or ad-hoc network calls",
          "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    for (const char* bad : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "hx-on", "localStorage", "sessionStorage", "fetch(",
                            "XMLHttpRequest", "YuzuDialog", "visibilitychange"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
}

TEST_CASE("groups glue: secrets are never stored or timed out", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    // The one-time token reveal has no timer: nothing here clears or hides [data-copy-token]'s
    // sibling <code>, and Copy reports a clipboard failure instead of swallowing it.
    CHECK_THAT(js, ContainsSubstring("Copy failed. Select the text."));
    CHECK_THAT(js, ContainsSubstring("navigator.clipboard.writeText(code.textContent)"));
    CHECK_THAT(js, !ContainsSubstring("code.remove"));
    CHECK_THAT(js, !ContainsSubstring("code.textContent = ''"));
}

TEST_CASE("groups glue: the Add-rule confirm names the match-everything case", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    CHECK_THAT(js, ContainsSubstring("'htmx:confirm'"));
    CHECK_THAT(js, ContainsSubstring("[data-rule-form]"));
    CHECK_THAT(js, ContainsSubstring("issueRequest(true)"));
    // The question is the server's (hx-confirm on the form); the script only appends to it.
    CHECK_THAT(js, ContainsSubstring("var q = e.detail.question;"));
    CHECK_THAT(js, ContainsSubstring("q += ' This matches every agent.'"));
    CHECK_THAT(js, !ContainsSubstring("join the fleet without approval"));
    // Same two shapes as enrolment::rule_matches_everything.
    CHECK_THAT(js, ContainsSubstring("/^[*?]*\\*[*?]*$/"));
    CHECK_THAT(js, ContainsSubstring("\\/0$/"));
}

TEST_CASE("groups glue: the unlimited-token warning follows both limit fields", "[groups][js]") {
    const std::string& js = yuzu::server::kYuzuGroupsJs;
    CHECK_THAT(js, ContainsSubstring("[data-token-form]"));
    CHECK_THAT(js, ContainsSubstring("[data-token-unlimited]"));
    CHECK_THAT(js, ContainsSubstring("zero('max_uses') && zero('ttl_hours')"));
}
