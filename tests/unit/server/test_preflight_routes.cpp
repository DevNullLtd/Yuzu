/**
 * test_preflight_routes.cpp — #2691 finding 10: PreflightRoutes::render_run's
 * live path (called on every operator self-poll of a running run) must not
 * compute-and-persist a false "every device incomplete" grid over an already-
 * good stored one when the live read degrades — it must render the last
 * known-good stored grid with an honest degrade banner and skip persisting
 * entirely, retrying on the next poll.
 *
 * render_run and its inputs (run_store_, collect_fn_) are private; the
 * PreflightRoutesTestAccess friend seam (preflight_routes.hpp) wires them
 * without standing up an HTTP server, same shape as
 * test_dashboard_results_columns.cpp's DashboardResultsColumnsTestAccess.
 */

#include "preflight_routes.hpp"
#include "preflight_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace yuzu::server {

struct PreflightRoutesTestAccess {
    PreflightRoutes routes;

    void set_stores(PreflightRunStore* rs) { routes.run_store_ = rs; }
    void set_collect(PreflightRoutes::CollectFn fn) { routes.collect_fn_ = std::move(fn); }
    std::string render(const PreflightRunRow& run, int attempt = 1) {
        return routes.render_run(run, attempt);
    }
};

} // namespace yuzu::server

namespace {

yuzu::test::PgTestTemplate preflight_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = "alice";
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000; // far future — not past_deadline
    r.status = "running";
    return r;
}

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("render_run: a degraded live read renders the last known-good stored "
          "grid with a degrade banner, and does not persist over it",
          "[pg][preflight][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-live-degrade-1";
    auto run = make_run(run_id, t);
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    // Prior GOOD state: agent-1 already resolved go-clean.
    PreflightRunDeviceRow good;
    good.agent_id = "agent-1";
    good.hostname = "host-1";
    good.os = "windows";
    good.bucket = "go";
    good.checks_json = "[]";
    good.updated_at_ms = t;
    REQUIRE(run_store.persist_grid(run_id, {good}, 1, /*go=*/1, /*warn=*/0, /*nogo=*/0, /*inc=*/0));

    PreflightRoutesTestAccess acc;
    acc.set_stores(&run_store);
    // collect_fn_ standing in for a degraded ResponseStore read: every
    // applicable check comes back with degraded=true, empty by_agent.
    acc.set_collect(
        [](const std::string&,
          const std::vector<std::pair<std::string, std::string>>& applicable) {
            std::vector<preflight::PreflightCheckResponses> out;
            for (const auto& [key, label] : applicable) {
                preflight::PreflightCheckResponses cr;
                cr.key = key;
                cr.label = label;
                cr.degraded = true;
                out.push_back(std::move(cr));
            }
            return out;
        });

    const std::string html = acc.render(run);

    CHECK(contains(html, "result-degrade-banner"));
    CHECK(contains(html, "temporarily unavailable"));

    // The stored grid must be UNCHANGED — the degraded poll must not persist.
    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "go");

    auto stored_run = run_store.get_run(run_id, "alice");
    REQUIRE(stored_run.has_value());
    CHECK(stored_run->status == "running"); // not falsely completed
}

TEST_CASE("render_run: a genuinely pending (not degraded) live read still "
          "computes and persists normally",
          "[pg][preflight][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-live-pending-1";
    auto run = make_run(run_id, t);
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    PreflightRoutesTestAccess acc;
    acc.set_stores(&run_store);
    // Not degraded — genuinely no responses yet.
    acc.set_collect(
        [](const std::string&,
          const std::vector<std::pair<std::string, std::string>>& applicable) {
            std::vector<preflight::PreflightCheckResponses> out;
            for (const auto& [key, label] : applicable) {
                preflight::PreflightCheckResponses cr;
                cr.key = key;
                cr.label = label;
                cr.degraded = false;
                out.push_back(std::move(cr));
            }
            return out;
        });

    const std::string html = acc.render(run);

    CHECK_FALSE(contains(html, "result-degrade-banner"));

    // The fix must not suppress the ordinary compute-and-persist path.
    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "inc"); // genuinely incomplete, correctly persisted
}

// Kills: a wrong active_key literal in page_shell() — apply_shell lights nothing and says
// nothing for an unknown key, so only a test that fetches the page can see it. No store
// or provider is wired: the page shell is auth-only chrome.
TEST_CASE("preflight routes: /auto lights Deployments under Software and its breadcrumb leaf",
          "[preflight][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, /*perm_fn=*/{}, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{},
                           /*audit_fn=*/{}, /*run_store=*/nullptr);

    auto page = sink.Get("/auto");
    REQUIRE(page);
    REQUIRE(page->status == 200);
    CHECK(contains(page->body, "/fragments/auto"));
    // The Software family is lit (not itself current) and its Deployments sub-item is the page.
    CHECK(contains(page->body, "<a class=\"shell-nav on\" href=\"/software\">"));
    CHECK(contains(page->body, "<a href=\"/auto\" class=\"on\" aria-current=\"page\">Deployments</a>"));
    CHECK(contains(page->body, "<span class=\"shell-sep\">/</span><b>Deployments</b>"));
}

// SEC-2/SEC-3 confinement-gap class (found during Gate 2 governance review):
// resolve_targets() feeds devices_fn_(username) — the same username-keyed
// provider fixed elsewhere in this branch — into a DISPATCH (not just a
// read), via the shared command_dispatch_fn. Denied here, unlike the pure
// reads elsewhere in this branch, because /fragments/auto/run mutates
// (creates a run + dispatches commands) even though every dispatched check
// is itself read-only.
TEST_CASE("preflight routes: /fragments/auto/run denies a service-scoped "
          "token, denial audited, nothing dispatched",
          "[pg][preflight][routes][security]") {
    // A real, open store (rather than nullptr) so devices_fn_calls/dispatched
    // below actually discriminate the fix: with a null run_store the handler's
    // OWN unrelated "store unavailable" early-return would make both counters
    // read 0 regardless of whether the deny fired (gov QE review — a nullptr
    // store made the deny test's own dispatch-count assertions vacuous).
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    int devices_fn_calls = 0;
    auto devices = [&](const std::string&) {
        ++devices_fn_calls;
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, devices,
                           /*groups_fn=*/{}, /*group_members_fn=*/{}, dispatch,
                           /*collect_fn=*/{}, audit, &run_store);

    auto res = sink.Post("/fragments/auto/run", "", "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    // The deny fires before resolve_targets() is ever called — no fleet
    // enumeration and no dispatch reach a service-scoped token at all.
    CHECK(devices_fn_calls == 0);
    CHECK(dispatched == 0);
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    REQUIRE(audit_log.size() == 1);
    CHECK(audit_log[0] == "preflight.run|denied");
}

TEST_CASE("preflight routes: /fragments/auto/run reaches resolve_targets + "
          "dispatch for an ordinary session",
          "[pg][preflight][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    int devices_fn_calls = 0;
    auto devices = [&](const std::string&) {
        ++devices_fn_calls;
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        d.os = "windows";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, dispatch, /*collect_fn=*/{}, audit, &run_store);

    auto res = sink.Post("/fragments/auto/run", "", "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status != 403); // not denied — reaches resolve_targets, creates the run, dispatches
    CHECK(devices_fn_calls == 1);
    CHECK(dispatched >= 1); // at least one applicable check dispatched
    bool saw_success = false;
    for (const auto& a : audit_log)
        if (a == "preflight.run|success")
            saw_success = true;
    CHECK(saw_success);
}

// `preflight::parse_i64` read junk as 0, so a typo in the disk threshold became "no minimum free
// disk" and passed every device, and a junk window became the default one. Both are now strict:
// a malformed (or, for the threshold, negative) number is a 400 and NOTHING is dispatched.
TEST_CASE("preflight routes: /fragments/auto/run 400s on a malformed min_gib or window and "
          "dispatches nothing",
          "[pg][preflight][routes][numeric_params]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto devices = [](const std::string&) {
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        d.os = "windows";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, dispatch, /*collect_fn=*/{}, audit, &run_store);

    for (const char* bad : {"min_gib=junk", "min_gib=20abc", "min_gib=-1", "min_gib=1e1",
                            "min_gib=0x10", "min_gib=99999999999999999999", "window=abc",
                            "window=30min", "window=1e2", "window=99999999999999999999"}) {
        INFO(bad);
        auto res = sink.Post("/fragments/auto/run", bad, "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK(dispatched == 0);

    // The shapes the form really sends still work: plain integers, and a cleared number input.
    for (const char* ok : {"min_gib=20&window=30", "min_gib=&window=", "min_gib=0&window=1"}) {
        INFO(ok);
        auto res = sink.Post("/fragments/auto/run", ok, "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    // Each accepted run dispatches every applicable check once. With no app_name the "app" check is
    // skipped, leaving 4 of the 5, so the count is exact: 3 runs.
    constexpr int per_run = 4;
    CHECK(dispatched == 3 * per_run);

    // A window of zero or below is not malformed, it means the default 30 minutes (1800 s).
    for (const char* dflt : {"min_gib=20&window=0", "min_gib=20&window=-5"}) {
        INFO(dflt);
        auto res = sink.Post("/fragments/auto/run", dflt, "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    // Five runs now: the explicit 30, the empty field and the two non-positive windows are all
    // 1800 s; only the explicit 1-minute window differs.
    const auto runs = run_store.list_runs("", /*is_admin=*/true, /*limit=*/10);
    REQUIRE(runs.size() == 5);
    CHECK(std::count_if(runs.begin(), runs.end(),
                        [](const auto& r) { return r.window_seconds == 30 * 60; }) == 4);
    CHECK(std::count_if(runs.begin(), runs.end(),
                        [](const auto& r) { return r.window_seconds == 60; }) == 1);
    CHECK(dispatched == 5 * per_run);
}

// #4644: `cmp_version` read a malformed version threshold as 0, so an `app_min` of `abc` (or
// `v4.2.0`, `4.2.x`) became "any version" and the go/no-go gate that feeds Deploy passed every
// device. A non-empty threshold that is not a dotted-decimal version (optionally with a
// pre-release suffix) is now a 400 and nothing is dispatched or saved; EMPTY still means unset.
TEST_CASE("preflight routes: /fragments/auto/run 400s on a malformed version threshold and "
          "dispatches nothing (#4644)",
          "[pg][preflight][routes][numeric_params]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto devices = [](const std::string&) {
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        d.os = "windows";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, dispatch, /*collect_fn=*/{}, audit, &run_store);

    for (const char* field : {"app_min", "app_max", "os_min"}) {
        for (const char* bad : {"abc", "v4.2.0", "4.2.x", "1..2", "-1", "4.2.0-", "4.2.0-beta.1",
                                "1e3", "0x10", "null", "true", "[]", "4.2.0%20", "%204.2.0",
                                "1000000000000000", "18446744073709551615"}) {
            const std::string form = std::string("app_name=Acme&min_gib=20&") + field + "=" + bad;
            INFO(form);
            auto res = sink.Post("/fragments/auto/run", form, "application/x-www-form-urlencoded");
            REQUIRE(res);
            CHECK(res->status == 400);
        }
    }
    CHECK(dispatched == 0);
    CHECK(run_store.list_runs("", /*is_admin=*/true, /*limit=*/10).empty());

    // Real versions, a pre-release suffix and the cleared inputs the form really sends still run.
    for (const char* ok : {"app_name=Acme&app_min=4.2.0&app_max=4.9.99&os_min=10.0.19045",
                           "app_name=Acme&app_min=4.2.0-beta&app_max=5.5&os_min=10.0.19045",
                           "app_name=Acme&app_min=&app_max=&os_min=", "app_min=4294967297"}) {
        INFO(ok);
        auto res = sink.Post("/fragments/auto/run", ok, "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    CHECK(run_store.list_runs("", /*is_admin=*/true, /*limit=*/10).size() == 4);
}

// SEC-2/SEC-3 confinement-gap class (Gate 4 unhappy-path review, UP-1):
// /fragments/auto (rail), /fragments/auto/result, and /fragments/auto/delete
// all scope by session->username alone — but ApiToken::principal_id ("the
// username... who created it") means a service-scoped token shares its
// creating principal's username. A token scoped to e.g. "printers" whose
// principal ALSO happens to be the interactive creator of a fleet-wide
// pre-flight run could otherwise read/enumerate/delete that run — full
// fleet-wide device data, not just its own service's.
TEST_CASE("preflight routes: rail/result/delete deny a service-scoped token "
          "sharing the run creator's username, run survives and is not "
          "leaked",
          "[pg][preflight][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-confinement-1";
    auto run = make_run(run_id, t); // created_by = "alice"
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    // The SAME principal ("alice") now authenticates with a service-scoped
    // token — mirrors ApiToken::principal_id sharing the creator's username.
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{}, audit,
                           &run_store);

    auto rail = sink.Get("/fragments/auto");
    REQUIRE(rail);
    CHECK(rail->status == 403);
    CHECK(rail->body.find(run_id) == std::string::npos);
    CHECK(rail->body.find(run.name) == std::string::npos);
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity (a hand-built id used to land in the body only).
    auto rail_body = nlohmann::json::parse(rail->body, nullptr, false);
    REQUIRE_FALSE(rail_body.is_discarded());
    CHECK_FALSE(rail_body["error"].contains("permission"));
    CHECK_FALSE(rail_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(rail->get_header_value("X-Correlation-Id") ==
         rail_body["error"]["correlation_id"].get<std::string>());

    auto result = sink.Get("/fragments/auto/result?run=" + run_id);
    REQUIRE(result);
    CHECK(result->status == 403);
    CHECK(result->body.find(run.scope_label) == std::string::npos);
    CHECK(result->body.find("host-1") == std::string::npos); // no device identity leaked
    auto result_body = nlohmann::json::parse(result->body, nullptr, false);
    REQUIRE_FALSE(result_body.is_discarded());
    CHECK_FALSE(result_body["error"].contains("permission"));
    CHECK_FALSE(result_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(result->get_header_value("X-Correlation-Id") ==
         result_body["error"]["correlation_id"].get<std::string>());

    auto del = sink.Post("/fragments/auto/delete?run=" + run_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status == 403);
    // The run survives — the deny fires before delete_run is ever called.
    REQUIRE(run_store.get_run(run_id, "alice").has_value());
    // #3167 (supersedes the prior GC-7 fix this test pinned): `.permission`
    // is now omitted entirely, not renamed to the "correct" grant —
    // kServiceScopeGlobalSafe is compile-time-empty, so no grant,
    // correctly-named or not, actually admits a service-scoped caller here
    // (routed-concern MUST clause 5).
    auto del_body = nlohmann::json::parse(del->body, nullptr, false);
    REQUIRE_FALSE(del_body.is_discarded());
    CHECK_FALSE(del_body["error"].contains("permission"));
    CHECK_FALSE(del_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(del->get_header_value("X-Correlation-Id") ==
         del_body["error"]["correlation_id"].get<std::string>());

    REQUIRE(audit_log.size() == 3);
    CHECK(audit_log[0] == "preflight.run|denied");         // rail
    CHECK(audit_log[1] == "preflight.run|denied");         // result poll
    CHECK(audit_log[2] == "preflight.run.delete|denied");  // delete — own verb
}

// #4036 (api-parity Batch A) — GET /api/v1/preflight/runs REST twin.

TEST_CASE("preflight routes: GET /api/v1/preflight/runs is owner-scoped and "
          "shares preflight_run_row_json with the MCP twin's builder",
          "[pg][preflight][routes][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    auto alice_run = make_run("run-alice-1", t);
    alice_run.created_by = "alice";
    REQUIRE(run_store.create_run(alice_run, {{"agent-1", "host-1", "windows"}}));
    // create_run always inserts status='running' (hardcoded in its own SQL —
    // the row's initial state is never caller-supplied); persist_grid sets
    // the summary counts, complete_run then flips the lifecycle column,
    // mirroring the real persist_and_maybe_complete production sequence.
    REQUIRE(run_store.persist_grid("run-alice-1", {}, 5, /*go=*/3, /*warn=*/1, /*nogo=*/0,
                                   /*inc=*/1));
    REQUIRE(run_store.complete_run("run-alice-1", t + 1000));

    auto bob_run = make_run("run-bob-1", t);
    bob_run.created_by = "bob";
    REQUIRE(run_store.create_run(bob_run, {{"agent-2", "host-2", "linux"}}));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{},
                           /*audit_fn=*/{}, &run_store);

    auto res = sink.Get("/api/v1/preflight/runs");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["api_version"] == "v1");
    REQUIRE(body["data"].is_array());
    // Owner-scoped: alice's own run only, bob's run is invisible.
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["run_id"] == "run-alice-1");
    CHECK(body["data"][0]["go"] == 3);
    CHECK(body["data"][0]["warn"] == 1);
    CHECK(body["data"][0]["nogo"] == 0);
    CHECK(body["data"][0]["incomplete"] == 1);
    CHECK(body["data"][0]["status"] == "complete");
    // Fields the shared builder emits that the flattened rail label doesn't
    // carry — proves this is the structured twin, not a re-formatted string.
    CHECK(body["data"][0].contains("scope_label"));
    CHECK(body["data"][0].contains("created_at_ms"));
    CHECK(body["pagination"]["total"] == 1);
}

TEST_CASE("preflight routes: GET /api/v1/preflight/runs denies a service-scoped "
          "token sharing the run creator's username, audited under "
          "preflight.run.view (not preflight.run)",
          "[pg][preflight][routes][rest][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    auto run = make_run("run-svc-1", t);
    run.created_by = "alice";
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{}, audit,
                           &run_store);

    auto res = sink.Get("/api/v1/preflight/runs");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("run-svc-1") == std::string::npos);
    REQUIRE(audit_log.size() == 1);
    // The issue's own correction: reusing "preflight.run" (the run-CREATION
    // verb) here would make a denied list read indistinguishable from a run
    // creation event in the audit log.
    CHECK(audit_log[0] == "preflight.run.view|denied");
}

TEST_CASE("preflight routes: GET /api/v1/preflight/runs 503s when the run "
          "store is unwired",
          "[preflight][routes][rest]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{},
                           /*audit_fn=*/{}, /*run_store=*/nullptr);

    auto res = sink.Get("/api/v1/preflight/runs");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("preflight routes: GET /api/v1/preflight/runs 503s (not an empty "
          "200) when the run store's connection pool is exhausted, #4036 "
          "hardening round",
          "[pg][preflight][routes][rest]") {
    // A store-level fault must not read as "you have zero saved runs" —
    // list_runs' plain accessor collapsed a pool-acquire timeout into the
    // same empty vector as a genuinely-empty rail; list_runs_checked
    // distinguishes them, and this route must surface the distinction as
    // 503 rather than 200 + {"data":[]}. Same pool-starvation recipe as
    // test_api_token_store.cpp's "an EXHAUSTED connection pool is
    // kUnavailable, not kInvalid".
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}}; // sole connection, held below
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    auto run = make_run("run-starved-1", t);
    run.created_by = "alice";
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{},
                           /*audit_fn=*/{}, &run_store);

    // Hold the pool's only connection with a longer timeout than the store's
    // own kReadTimeout (2s), so the route's internal acquire times out first.
    auto hog = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // we now hold the only connection

    auto res = sink.Get("/api/v1/preflight/runs");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("run-starved-1") == std::string::npos);
    // #2146 Batch A retry-hint audit: this genuine store-fault (not the
    // unwired-pointer case above) must carry a retry hint matching the MCP
    // twin's own kMcpStoreFaultShortRetryMs (2000ms) — see mcp_server.cpp's
    // list_preflight_runs handler and mcp_retry.hpp.
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["error"].contains("retry_after_ms"));
    CHECK(body["error"]["retry_after_ms"].get<int>() == 2000);
}

TEST_CASE("preflight routes: GET /api/v1/preflight/runs 400s on an invalid limit",
          "[pg][preflight][routes][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{},
                           /*audit_fn=*/{}, &run_store);

    // #4644: `stoll` read "5x" as 5 and "0x10" as 0; the strict parse refuses both.
    for (const char* bad : {"not-a-number", "5x", "0x10", "1e1", "", "99999999999999999999"}) {
        INFO("limit=" << bad);
        auto res = sink.Get(std::string("/api/v1/preflight/runs?limit=") + bad);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
}

TEST_CASE("preflight ui: /auto renders the Deployments tab strip, panels, refusal listener and "
          "the empty-notice reveal fix",
          "[preflight][routes][ui]") {
    const std::string h = render_auto_config({}, {});
    CHECK(contains(h, "class=\"tabs\" id=\"auto-tabs\" role=\"tablist\""));
    CHECK_FALSE(contains(h, "gp-subnav"));
    CHECK(contains(h, "<a href=\"#\" role=\"tab\" class=\"on\" aria-selected=\"true\""));
    CHECK(contains(h, "<a href=\"#deployments\" role=\"tab\" aria-selected=\"false\" "
                      "hx-get=\"/fragments/auto/deployments\" hx-target=\"#auto-list\""));
    // replace, not drop: the list read is unaudited and capped, and a hung request must not
    // wedge every later tab click (drop ignores clicks until the stuck XHR settles).
    CHECK(contains(h, "hx-sync=\"this:replace\""));
    CHECK_FALSE(contains(h, "this:drop"));
    // Returning to the list clears a drilled detail so it cannot outlive the refreshed list.
    CHECK(contains(h, "if(w==='list'){var x=document.getElementById('auto-detail');if(x)x.innerHTML='';}"));
    // Tab wiring: the two onclick handlers and the pfTab switcher.
    CHECK(contains(h, "window.pfTab=function"));
    CHECK(contains(h, "onclick=\"pfTab('flow');return false\""));
    CHECK(contains(h, "onclick=\"pfTab('list')\""));
    const auto flow = h.find("<div id=\"auto-flow\">");
    const auto cfg = h.find("id=\"auto-cfg\"");
    const auto verify = h.find("id=\"auto-verify\"");
    const auto panel = h.find("<div id=\"auto-deployments\" hidden>");
    REQUIRE(flow != std::string::npos);
    REQUIRE(cfg != std::string::npos);
    REQUIRE(verify != std::string::npos);
    REQUIRE(panel != std::string::npos);
    CHECK(flow < cfg);
    CHECK(verify < panel);
    CHECK(contains(h, "<div id=\"auto-list\" class=\"panel\">"));
    CHECK(contains(h, "<div id=\"auto-detail\"></div>"));
    // Refusal listener: once-guarded, scoped to the two targets, 401 login, 403 names the grant.
    CHECK(contains(h, "if(!window.__pfDepErr){window.__pfDepErr=1;"));
    CHECK(contains(h, "t.id!=='auto-list'&&t.id!=='auto-detail'"));
    CHECK(contains(h, "location.href='/login'"));
    CHECK(contains(h, "needs the SoftwareDeployment:Read permission."));
    CHECK(contains(h, "Deployments could not be read just now."));
    CHECK(contains(h, "htmx:sendError"));
    // Browser Back/Forward: a once-guarded hashchange listener that tolerates the panel missing.
    CHECK(contains(h, "window.addEventListener('hashchange',function(){var d=document.getElementById('auto-deployments');"
                      "if(!d)return;"));
    CHECK(contains(h, "if(want===!d.hidden)return;pfTab(want?'list':'flow');"));
    // Deep link calls htmx.ajax (a click on a swapped anchor would run before htmx binds it).
    CHECK(contains(h, "htmx.ajax('GET','/fragments/auto/deployments'"));
    CHECK_FALSE(contains(h, "hx-on"));

    // ISS-11: the empty notice is hidden by the stylesheet, so showing it needs 'block'.
    const std::string r = render_auto_results({}, "cfg", "scope", "", true, "run-1", "");
    CHECK(contains(r, "e.style.display=vis?'none':'block'"));
    CHECK_FALSE(contains(r, "vis?'none':''"));
}
