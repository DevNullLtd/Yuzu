/// test_settings_general.cpp — the System "General and appearance" page
/// (settings_general_routes.*, settings_general_ui.cpp).
///
/// Pure first: the two renderers take value structs, the routes take closures, and the
/// page is a baked string, so nothing here needs a store, a logger, a socket or a sleep.
///
///   - runtime form: every state, the `warning` -> `warn` mapping, a level the route
///     refuses (`critical`, `off`) shown as a disabled current value, store unavailable
///   - recent events: one distinct sentence per state (never an empty table for a failure)
///   - routes: all three are admin-gated and never wider; a non-admin page request is
///     redirected to `/`
///   - page pins: single h1, no hx-on / inline handlers / innerHTML / eval, one shell
///     identity read, the form writes only the two real keys, both confirm texts and the
///     audit-failure header read are present

#include "settings_general_routes.hpp"

#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <regex>
#include <set>
#include <string>
#include <vector>

extern const char* const kSettingsGeneralHtml;

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server::settings_general;

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

EventsView open_view() {
    EventsView v;
    v.collection_enabled = true;
    v.store_present = true;
    v.store_open = true;
    v.sink_configured = true;
    v.pending = 3;
    v.emitted_by_this_server = 12;
    v.recent = std::vector<EventRow>{};
    return v;
}

} // namespace

// ── Runtime form ────────────────────────────────────────────────────────

TEST_CASE("general: runtime form shows the live values and enables Save only via script",
          "[general][settings]") {
    const auto html = render_general_runtime({.heartbeat_seconds = 75, .log_level = "info"});
    CHECK_THAT(html, ContainsSubstring("name=\"heartbeat_timeout\""));
    CHECK_THAT(html, ContainsSubstring("value=\"75\""));
    CHECK_THAT(html, ContainsSubstring("min=\"30\"")); // the server's floor
    CHECK_THAT(html, ContainsSubstring("data-loaded-heartbeat=\"75\""));
    CHECK_THAT(html, ContainsSubstring("<option value=\"info\" selected>info</option>"));
    // Nothing to save until a field changes.
    CHECK_THAT(html, ContainsSubstring("id=\"gen-save\" disabled"));
    // The only two inputs are the two real keys.
    CHECK(count_of(html, "name=\"") == 2);
    CHECK_THAT(html, ContainsSubstring("name=\"log_level\""));
    // Honest scope text: this process only, not gateway agents, not other replicas.
    CHECK_THAT(html, ContainsSubstring("Agents behind a gateway are not covered"));
    CHECK_THAT(html, ContainsSubstring("Other server replicas keep their own value"));
    CHECK_THAT(html, ContainsSubstring("re-applied at restart over the --log-level flag"));
    // No "fleet-wide" claim anywhere on the control.
    CHECK_THAT(html, !ContainsSubstring("fleet-wide"));
}

TEST_CASE("general: the logger's `warning` is shown as the settable `warn`", "[general][settings]") {
    const auto html = render_general_runtime({.heartbeat_seconds = 90, .log_level = "warning"});
    CHECK_THAT(html, ContainsSubstring("<option value=\"warn\" selected>warn</option>"));
    CHECK_THAT(html, ContainsSubstring("data-loaded-log-level=\"warn\""));
    CHECK(count_of(html, " selected") == 1);
}

TEST_CASE("general: critical and off are a disabled current value, never a silent re-select",
          "[general][settings]") {
    for (const char* lvl : {"critical", "off"}) {
        INFO(lvl);
        const auto html = render_general_runtime({.heartbeat_seconds = 90, .log_level = lvl});
        CHECK_THAT(html, ContainsSubstring(std::string("<option value=\"") + lvl +
                                           "\" selected disabled>"));
        // Exactly one option is selected, and it is the disabled one: no settable level
        // is chosen on the operator's behalf.
        CHECK(count_of(html, " selected") == 1);
        CHECK_THAT(html, !ContainsSubstring("<option value=\"info\" selected"));
        // The five settable levels are still offered.
        for (const char* l : {"trace", "debug", "info", "warn", "error"})
            CHECK_THAT(html, ContainsSubstring(std::string("<option value=\"") + l + "\""));
    }
}

TEST_CASE("general: an unavailable store disables the form and says why", "[general][settings]") {
    const auto html = render_general_runtime(
        {.heartbeat_seconds = 90, .log_level = "info", .store_available = false});
    CHECK_THAT(html, ContainsSubstring("Runtime settings cannot be saved: the configuration store "
                                       "is unavailable."));
    CHECK_THAT(html, ContainsSubstring("id=\"gen-heartbeat\""));
    CHECK(count_of(html, " disabled") >= 2);
    CHECK_THAT(html, !ContainsSubstring("id=\"gen-save\""));
    // Live values are still shown read-only.
    CHECK_THAT(html, ContainsSubstring("value=\"90\""));
}

TEST_CASE("general: a hostile log level string is escaped", "[general][settings][security]") {
    const auto html = render_general_runtime(
        {.heartbeat_seconds = 90, .log_level = "<img src=x onerror=1>"});
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

// ── Recent events ───────────────────────────────────────────────────────

TEST_CASE("general: events - off by configuration", "[general][settings]") {
    EventsView v;
    v.collection_enabled = false;
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("Event collection is turned off."));
    CHECK_THAT(html, ContainsSubstring("--no-analytics"));
    CHECK_THAT(html, !ContainsSubstring("<table"));
}

TEST_CASE("general: events - enabled but not running is not 'no events'", "[general][settings]") {
    EventsView v;
    v.collection_enabled = true;
    v.store_present = false;
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("Event collection is enabled but not running."));
    CHECK_THAT(html, ContainsSubstring("This is not 'no events'."));
    CHECK_THAT(html, !ContainsSubstring("No events buffered yet."));
}

TEST_CASE("general: events - a store that did not open is distinct from a failed read",
          "[general][settings]") {
    EventsView v;
    v.collection_enabled = true;
    v.store_present = true;
    v.store_open = false;
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("its store did not open at startup"));
    CHECK_THAT(html, !ContainsSubstring("could not be read"));
}

TEST_CASE("general: events - a degraded read keeps the emitted count and says Unknown",
          "[general][settings]") {
    auto v = open_view();
    v.recent = std::nullopt;
    v.pending = std::nullopt;
    v.emitted_by_this_server = 12;
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("Recent events could not be read."));
    CHECK_THAT(html, ContainsSubstring("<span class=\"unk\">Unknown</span>"));
    CHECK_THAT(html, ContainsSubstring("Emitted by this server since it started<b>12</b>"));
    CHECK_THAT(html, !ContainsSubstring("No events buffered yet."));
    CHECK_THAT(html, !ContainsSubstring("<table"));
}

TEST_CASE("general: events - true empty is its own sentence", "[general][settings]") {
    auto v = open_view();
    v.pending = 0;
    v.emitted_by_this_server = 0;
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("No events buffered yet."));
    CHECK_THAT(html, ContainsSubstring("Pending<b>0</b>"));
    CHECK_THAT(html, !ContainsSubstring("could not be read"));
    CHECK_THAT(html, !ContainsSubstring("<table"));
}

TEST_CASE("general: events - no sink says the buffer is not forwarded", "[general][settings]") {
    auto v = open_view();
    v.sink_configured = false;
    v.recent = std::vector<EventRow>{{"agent.connected", "gateway", "info", 1700000000000}};
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, ContainsSubstring("No sink is configured, so events stay in the database "
                                       "buffer and are not forwarded."));
    CHECK_THAT(html, ContainsSubstring("agent.connected"));

    // With a sink the note is absent.
    v.sink_configured = true;
    CHECK_THAT(render_analytics_events(v), !ContainsSubstring("No sink is configured"));
}

TEST_CASE("general: events - populated shows four columns, newest-first order is kept, UTC time",
          "[general][settings]") {
    auto v = open_view();
    v.recent = std::vector<EventRow>{{"command.completed", "server", "warn", 1700000005000},
                                     {"auth.login", "server", "info", 1700000000000}};
    const auto html = render_analytics_events(v);
    for (const char* h : {"Event type", "Source", "Severity", "Time (UTC)"})
        CHECK_THAT(html, ContainsSubstring(std::string("<th>") + h + "</th>"));
    CHECK_THAT(html, ContainsSubstring("2023-11-14T22:13:25Z"));
    CHECK_THAT(html, ContainsSubstring("2023-11-14T22:13:20Z"));
    CHECK(html.find("command.completed") < html.find("auth.login")); // order is the store's
    CHECK_THAT(html, ContainsSubstring("Pending<b>3</b>"));
    // No host, user or payload columns (PII-adjacent): four headers only.
    CHECK(count_of(html, "<th>") == 4);
}

TEST_CASE("general: events - every event string is escaped", "[general][settings][security]") {
    auto v = open_view();
    v.recent = std::vector<EventRow>{
        {"<img src=x onerror=1>", "<script>alert(1)</script>", "\"><b>", 1700000000000}};
    const auto html = render_analytics_events(v);
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, !ContainsSubstring("<script"));
    CHECK_THAT(html, !ContainsSubstring("\"><b>"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

// ── Routes ──────────────────────────────────────────────────────────────

namespace {

struct GeneralHarness {
    bool admin_ok{true};
    int admin_calls{0};
    int runtime_calls{0};
    int events_calls{0};
    RuntimeView runtime{.heartbeat_seconds = 90, .log_level = "info"};
    EventsView events = open_view();

    yuzu::server::test::TestRouteSink sink; // declared last: handlers capture `this`

    GeneralHarness() {
        Deps d;
        d.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (admin_ok)
                return true;
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"admin role required"}})",
                            "application/json");
            return false;
        };
        d.runtime_fn = [this] { ++runtime_calls; return runtime; };
        d.events_fn = [this] { ++events_calls; return events; };
        register_settings_general_routes(sink, std::move(d));
    }
};

} // namespace

TEST_CASE("general: registers exactly the page and two fragments", "[general][settings][routes]") {
    GeneralHarness h;
    CHECK(h.sink.route_count() == 3);
    std::set<std::string> got;
    for (const auto& [m, p] : h.sink.registered_routes())
        got.insert(m + " " + p);
    CHECK(got == std::set<std::string>{"GET /settings/general",
                                       "GET /fragments/settings/general-runtime",
                                       "GET /fragments/settings/analytics-events"});
}

TEST_CASE("general: an admin gets the page and both fragments, uncached", "[general][settings][routes]") {
    GeneralHarness h;
    for (const char* path : {"/settings/general", "/fragments/settings/general-runtime",
                             "/fragments/settings/analytics-events"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK_THAT(res->get_header_value("Content-Type"), ContainsSubstring("text/html"));
    }
    CHECK(h.admin_calls == 3);
    CHECK(h.runtime_calls == 1);
    CHECK(h.events_calls == 1);
}

TEST_CASE("general: a non-admin page request is refused and redirected to /",
          "[general][settings][routes][security]") {
    GeneralHarness h;
    h.admin_ok = false;
    auto res = h.sink.Get("/settings/general");
    REQUIRE(res);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/");
    // The page body is never served to the refused caller.
    CHECK(res->body.find("General and appearance") == std::string::npos);
}

TEST_CASE("general: a refused fragment never reaches its data source",
          "[general][settings][routes][security]") {
    GeneralHarness h;
    h.admin_ok = false;
    for (const char* path : {"/fragments/settings/general-runtime",
                             "/fragments/settings/analytics-events"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("admin role required"));
    }
    // Neither closure ran: nothing was read on behalf of a refused caller.
    CHECK(h.runtime_calls == 0);
    CHECK(h.events_calls == 0);
}

TEST_CASE("general: the fragments render what their closures return", "[general][settings][routes]") {
    GeneralHarness h;
    h.runtime = {.heartbeat_seconds = 120, .log_level = "warning"};
    h.events.recent = std::vector<EventRow>{{"auth.login", "server", "info", 1700000000000}};

    auto rt = h.sink.Get("/fragments/settings/general-runtime");
    REQUIRE(rt);
    CHECK_THAT(rt->body, ContainsSubstring("value=\"120\""));
    CHECK_THAT(rt->body, ContainsSubstring("<option value=\"warn\" selected>warn</option>"));

    auto ev = h.sink.Get("/fragments/settings/analytics-events");
    REQUIRE(ev);
    CHECK_THAT(ev->body, ContainsSubstring("auth.login"));
}

// ── Page pins ───────────────────────────────────────────────────────────

TEST_CASE("general page: structure and CSP-safe script rules", "[general][settings][page]") {
    const std::string html = kSettingsGeneralHtml;

    // One shell, one heading, one identity read (the shell's).
    CHECK(count_of(html, "<!--yuzu:shell-->") == 1);
    CHECK(count_of(html, "<h1>") == 1);
    CHECK(count_of(html, "fetch('/api/me')") == 1);
    CHECK_THAT(html, ContainsSubstring("<h1>General and appearance</h1>"));

    // The nav lights General (a sub-item) and the breadcrumb reads Settings / General...
    CHECK_THAT(html, ContainsSubstring("<a href=\"/settings/general\" class=\"on\" aria-current=\"page\">"));
    CHECK_THAT(html, ContainsSubstring("<span>Settings</span><span class=\"shell-sep\">/</span>"
                                       "<b>General and appearance</b>"));

    // Four panel loaders: runtime form, server configuration, analytics, recent events.
    CHECK(count_of(html, "hx-get=\"/fragments/settings/") == 4);
    for (const char* f : {"general-runtime", "server-config", "analytics\"", "analytics-events"})
        CHECK_THAT(html, ContainsSubstring(std::string("hx-get=\"/fragments/settings/") + f));

    // No hx-on (CSP blocks it), no inline handler attributes, no innerHTML, no eval.
    CHECK_THAT(html, !ContainsSubstring("hx-on"));
    static const std::regex inline_handler(R"re(\son[a-z]+\s*=)re");
    CHECK_FALSE(std::regex_search(html, inline_handler));
    // `hx-swap="innerHTML"` is htmx swapping a server fragment; what must not appear is
    // script writing server text as markup.
    static const std::regex html_write(R"re(\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML)re");
    CHECK_FALSE(std::regex_search(html, html_write));
    CHECK_THAT(html, !ContainsSubstring("eval("));
    CHECK_THAT(html, !ContainsSubstring("new Function"));
    CHECK_THAT(html, !ContainsSubstring("document.write"));
}

TEST_CASE("general page: the form writes only heartbeat_timeout and log_level",
          "[general][settings][page]") {
    const std::string html = kSettingsGeneralHtml;
    // Every config write in the script goes through put('<key>', ...); collect the keys.
    static const std::regex put_key(R"re(steps\.push\(\['([a-z_]+)')re");
    std::set<std::string> keys;
    for (std::sregex_iterator it(html.begin(), html.end(), put_key), end; it != end; ++it)
        keys.insert((*it)[1].str());
    CHECK(keys == std::set<std::string>{"heartbeat_timeout", "log_level"});
    // The one place a URL is built from a key is the PUT to /api/config/.
    CHECK(count_of(html, "fetch('/api/config/' + key") == 1);
    // JSON body, digit string validated client-side.
    CHECK_THAT(html, ContainsSubstring("'Content-Type': 'application/json'"));
    CHECK_THAT(html, ContainsSubstring("/^[0-9]+$/"));
}

TEST_CASE("general page: both confirms and the audit-failure header are present",
          "[general][settings][page]") {
    const std::string html = kSettingsGeneralHtml;
    // Heartbeat: both directions, naming the old and new value (review A2).
    CHECK_THAT(html, ContainsSubstring("seconds are disconnected and shown offline at the next sweep "
                                       "(about every 15 seconds). It is "));
    CHECK_THAT(html, ContainsSubstring("Agents behind a gateway and other server replicas are not "
                                       "affected by this setting."));
    // The server refuses under its floor (the input's min attribute), so the page rejects it
    // before any confirm.
    CHECK_THAT(html, ContainsSubstring("parseInt(v, 10) < parseInt(hb.min, 10)"));
    CHECK_THAT(html, !ContainsSubstring("is below the default agent heartbeat interval"));
    CHECK_THAT(html, ContainsSubstring("will take up to "));
    CHECK_THAT(html, ContainsSubstring("changed since you opened this page"));
    CHECK_THAT(html, ContainsSubstring("could not re-check the current value"));
    // Log level: only warn and error are gated (review A3).
    CHECK_THAT(html, ContainsSubstring("At warn and above this server stops writing its info-level "
                                       "lines"));
    CHECK_THAT(html, ContainsSubstring("lvl === 'warn' || lvl === 'error'"));
    // The live value is re-read immediately before the heartbeat confirm.
    CHECK_THAT(html, ContainsSubstring("fetch('/api/config', "));
    // A lost outcome row (the attempted row exists, the change is applied): the header is read
    // and a banner shown (review A4).
    CHECK_THAT(html, ContainsSubstring("Sec-Audit-Failed"));
    CHECK_THAT(html, ContainsSubstring("Audit write failed."));
    // A cross-site refusal names the remedy for a Host-rewriting proxy.
    CHECK_THAT(html, ContainsSubstring("--csrf-trusted-origin"));
    // Feedback is a sibling of the reloading section, not inside it (review A6).
    const auto section = html.find("id=\"general-runtime-section\"");
    const auto feedback = html.find("id=\"general-runtime-feedback\"");
    REQUIRE(section != std::string::npos);
    REQUIRE(feedback != std::string::npos);
    CHECK(feedback > section);
    const auto section_end = html.find("</div></div>", section); // the section's loading div
    CHECK(section_end < feedback);
}

TEST_CASE("general page: six colour schemes as radios, whitelisted on read and write, guarded",
          "[general][settings][page][theme]") {
    const std::string html = kSettingsGeneralHtml;
    // One radio per scheme, slate pre-checked, each with its own inline swatch colours (the live
    // tokens can only show the current palette).
    CHECK(count_of(html, "name=\"theme\"") == 6);
    for (const char* v : {"slate", "navy", "jade", "light", "light-baby", "light-hot"})
        CHECK_THAT(html, ContainsSubstring(std::string("name=\"theme\" value=\"") + v + "\""));
    CHECK_THAT(html, ContainsSubstring("name=\"theme\" value=\"slate\" checked"));
    CHECK(count_of(html, "class=\"sw-row\" aria-hidden=\"true\" style=\"--bg:#") == 6);
    CHECK_THAT(html, ContainsSubstring("<b>Light Baby Pink</b>"));
    CHECK_THAT(html, ContainsSubstring("<b>Light Hot Pink</b>"));
    CHECK_THAT(html, ContainsSubstring("role=\"radiogroup\" aria-labelledby=\"lb-scheme\""));
    CHECK_THAT(html, !ContainsSubstring("Slate is the only colour scheme"));
    // Same key and the same exact-match whitelist as the boot script in every page head; the
    // store is touched only inside try/catch, and a blocked store says so.
    CHECK_THAT(html, ContainsSubstring("'yuzu-theme'"));
    CHECK_THAT(html, ContainsSubstring("/^(slate|navy|jade|light|light-baby|light-hot)$/"));
    CHECK_THAT(html, ContainsSubstring("THEMES.test(v) ? v : 'slate'"));
    CHECK_THAT(html, ContainsSubstring("THEMES.test(t.value) ? t.value : 'slate'"));
    CHECK_THAT(html, ContainsSubstring("document.documentElement.setAttribute('data-theme', v)"));
    CHECK_THAT(html, ContainsSubstring("id=\"theme-blocked\" role=\"status\" hidden"));
    CHECK(count_of(html, "localStorage.setItem(THEME_KEY, v)") == 1);
    CHECK(count_of(html, "localStorage.getItem(THEME_KEY)") == 1);
}

TEST_CASE("general page: density is whitelisted on read, guarded, and admin-page only",
          "[general][settings][page]") {
    const std::string html = kSettingsGeneralHtml;
    CHECK_THAT(html, ContainsSubstring("'yuzu-table-density'"));
    CHECK_THAT(html, ContainsSubstring("getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable'"));
    CHECK(count_of(html, "catch (err)") >= 2); // read and write are both try/catch
    CHECK_THAT(html, ContainsSubstring("Saved in this browser"));
    CHECK_THAT(html, ContainsSubstring("Applies to the results table on the Console."));
    // The drawn controls that have no route are not on the page.
    CHECK_THAT(html, !ContainsSubstring("Time zone"));
    CHECK_THAT(html, !ContainsSubstring("Server name"));
    CHECK_THAT(html, !ContainsSubstring("Share usage analytics"));
    CHECK_THAT(html, !ContainsSubstring("Session timeout"));
}
