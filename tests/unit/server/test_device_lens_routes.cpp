/// @file test_device_lens_routes.cpp
/// Route-level tests for the DEX + Guardian device-page lenses
/// (`/fragments/device/dex`, `/fragments/device/guardian`) — split out of
/// device_routes.cpp/test_device_routes.cpp by ADR-0031 WS-A4 wave 2 (see
/// device_lens_routes.hpp's file banner). Driven in-process through
/// TestRouteSink (no httplib acceptor, #438), with stub scoped-perm/audit fns
/// and a real (Postgres-backed) GuaranteedStateStore where the lens actually
/// reads store data.

#include "device_lens_routes.hpp"
#include "dex_api_local.hpp"          // make_local_dex_api
#include "dex_read_builders.hpp"      // dex_device_score (oracle) -- dex_routes.hpp no longer re-exports it (WS-A4 PR-1 F1 fix)
#include "dex_routes.hpp"             // dex_iso_since / dex_window_to_days
#include "guaranteed_state_store.hpp"
#include "guardian_api_local.hpp"     // make_local_guardian_api
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"             // PgConn/PgResult -- the DROP-TABLE degrade test below
#include "test_guardian_api_double.hpp" // FnGuardianApi
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration).
yuzu::test::PgTestTemplate guardian_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

// ── Seed helpers for the CHARACTERIZATION tests below (mirrors
// test_dex_api.cpp's seed_crash / test_guaranteed_state_store.cpp's make_event
// / make_rule shapes verbatim, kept local to this file rather than shared —
// each caller wants a slightly different subset of fields). ──

GuaranteedStateEventRow make_observation(std::string event_id, std::string agent_id,
                                         std::string obs_type, std::string ts) {
    GuaranteedStateEventRow e;
    e.event_id = std::move(event_id);
    e.rule_id = "__observation__"; // kObservationRuleId — ruleless DEX signal
    e.agent_id = std::move(agent_id);
    e.event_type = std::move(obs_type);
    e.severity = "info";
    e.timestamp = std::move(ts);
    return e;
}

GuaranteedStateRuleRow make_lens_rule(std::string rule_id, std::string name) {
    GuaranteedStateRuleRow r;
    r.rule_id = std::move(rule_id);
    r.name = std::move(name);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "tag:workstations";
    r.signature = {0xDE, 0xAD, 0xBE, 0xEF};
    r.created_at = "2026-04-19T12:00:00Z";
    r.updated_at = "2026-04-19T12:00:00Z";
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

GuaranteedStateEventRow make_drift_event(std::string event_id, std::string rule_id,
                                         std::string agent_id, std::string event_type,
                                         std::string ts) {
    GuaranteedStateEventRow e;
    e.event_id = std::move(event_id);
    e.rule_id = std::move(rule_id);
    e.agent_id = std::move(agent_id);
    e.event_type = std::move(event_type);
    e.severity = "high";
    e.guard_type = "registry";
    e.guard_category = "event";
    e.detected_value = "0";
    e.expected_value = "1";
    e.timestamp = std::move(ts);
    e.agent_ns = yuzu::test::iso8601_to_ns(e.timestamp); // a usable ordering key (schema v4)
    return e;
}

// Anchored a couple of days back from *now* so it stays inside the lens's
// fixed 7-day DEX window (same rationale as test_dex_api.cpp's kTs).
const std::string kRecentTs = yuzu::server::dex_iso_since(2).substr(0, 10) + "T12:00:00Z";

} // namespace

TEST_CASE("device lenses: Read-gated + audited on open", "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    bool allow_read = true;
    // The lenses gate per-device via scoped_perm; Read toggled by allow_read.
    auto scoped_perm = [&allow_read](const httplib::Request&, httplib::Response& res,
                                     const std::string&, const std::string& op, const std::string&) {
        if (op == "Read" && !allow_read) { res.status = 403; return false; }
        return true;
    };
    std::vector<std::string> audited;
    bool audit_ok = true;      // flip to simulate a dropped evidence row (#1647)
    bool audit_throws = false; // flip to simulate a bad_alloc-class throw from audit_fn (#1647)
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string&, const std::string& tid, const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        // DeviceLensRoutes::AuditFn is bool-returning (#1549).
        if (audit_throws)
            throw std::runtime_error("audit DB write blew up");
        return audit_ok;
    };
    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, scoped_perm, dex_api, guardian_api, audit);

    SECTION("Read denied -> 403, nothing rendered, no audit") {
        allow_read = false;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 403);
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 403);
        CHECK(audited.empty());
    }
    SECTION("Read allowed -> audited on open with the right verb") {
        allow_read = true;
        sink.Get("/fragments/device/dex?id=a-1");
        sink.Get("/fragments/device/guardian?id=a-1");
        bool saw_dex = false, saw_guardian = false;
        for (const auto& a : audited) {
            if (a == "dex.device.view|a-1") saw_dex = true;
            if (a == "guardian.device.view|a-1") saw_guardian = true;
        }
        CHECK(saw_dex);
        CHECK(saw_guardian);
    }
    // #1647: a per-device behavioural-PII lens whose audit row silently fails to
    // persist must surface the gap (Sec-Audit-Failed) — but as an HTML dashboard
    // surface it SET-AND-PROCEEDS (a transient audit hiccup must not blank the
    // operator's lens, unlike the strict REST per-device endpoints that fail closed).
    SECTION("audit-persist failure -> Sec-Audit-Failed header, fragment still renders") {
        allow_read = true;
        audit_ok = false; // the evidence row cannot persist
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200); // set-and-proceed
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
    // #1647 item 1: a bad_alloc-class throw out of audit_fn was previously silent
    // (no try/catch). The shared helper catches it, logs, flags the header, and the
    // handler still returns a response instead of letting the throw escape.
    SECTION("a throwing audit_fn is caught + flagged, never escapes the handler") {
        allow_read = true;
        audit_throws = true;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200);
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
}

// SCOPE-ESCAPE regression (governance Gate-2/4 BLOCKING; both adversarial reviewers
// found it independently) — the DEX-lens leg. See test_device_routes.cpp's sibling
// "out-of-scope device is not listed/openable/live-queryable" for the
// list/page/live-dispatch legs of the same regression.
TEST_CASE("device lenses: out-of-scope DEX lens is 403, no PII read (not audited)",
          "[pg][device][routes][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto scoped_perm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                          const std::string&, const std::string& agent_id) {
        if (agent_id == "other-team") { res.status = 403; return false; }
        return true;
    };
    std::vector<std::string> audited;
    auto audit = [&audited](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        return true;
    };
    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, scoped_perm, dex_api, guardian_api, audit);

    auto r = sink.Get("/fragments/device/dex?id=other-team");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(audited.empty());
}

// bare=1 mounts the fragment as a lens inside the Hardware CI record, which
// already renders its own 7-tab bar — the fragment's OWN 3-chip bar
// (device_lens_tabs, "Device info"/"DEX"/"Guardian") must not double up.
// store=nullptr routes both lenses through render_device_lens_placeholder,
// which still threads `tabs` the same way the real DEX/Guardian bodies do.
TEST_CASE("device lenses: bare=1 hides the lens tab bar", "[device][routes]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };

    SECTION("dex fragment: bare=1 omits the tab bar; without it, the bar renders") {
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, /*guardian_api=*/nullptr);
        auto bare = sink.Get("/fragments/device/dex?id=a-1&bare=1");
        REQUIRE(bare);
        CHECK(bare->body.find("Device info") == std::string::npos);
        auto full = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(full);
        CHECK(full->body.find("Device info") != std::string::npos);
    }
    SECTION("guardian fragment: bare=1 omits the tab bar; without it, the bar renders") {
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, /*guardian_api=*/nullptr);
        auto bare = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
        REQUIRE(bare);
        CHECK(bare->body.find("Device info") == std::string::npos);
        auto full = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(full);
        CHECK(full->body.find("Device info") != std::string::npos);
    }
}

// A WIRED GuardianApi whose read degrades (device_guards -> nullopt) is a
// production-reachable path distinct from the unwired (nullptr) placeholder
// above: it must render the byte-exact "degraded" placeholder AFTER the
// access audit, never an empty/partial guard list. make_local_guardian_api
// with a null store is the same degrade double test_dex_routes.cpp uses.
TEST_CASE("device lenses: Guardian lens on a degraded read renders the degraded placeholder",
          "[device][routes]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    std::vector<std::string> audited;
    auto audit = [&audited](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string& tid, const std::string&) {
        audited.push_back(a + "|" + tid);
        return true;
    };
    auto degraded = make_local_guardian_api(/*store=*/nullptr, /*baseline_store=*/nullptr);
    GuardianReadFault degrade_fault = GuardianReadFault::kNone;
    REQUIRE_FALSE(degraded->device_guards("a-1", &degrade_fault).has_value());
    CHECK(degrade_fault == GuardianReadFault::kTransient);
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, degraded, audit);

    auto gd = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
    REQUIRE(gd);
    CHECK(gd->status == 200);
    CHECK(gd->body == "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>Guardian store "
                      "degraded.</div>");
    REQUIRE(audited.size() == 1);
    CHECK(audited[0] == "guardian.device.view|a-1");
}

// The Guardian lens renders the rows of a GuardianDeviceGuardsReport (the report wraps the guard
// rows plus the #7217 unrepresented-pending summary, which the lens shows as a notice and which
// keeps the tile off the clean state), and a degraded (nullopt) report from the same double still
// renders the degraded placeholder.
TEST_CASE("device lenses: Guardian lens renders the guards of a report; a nullopt report degrades",
          "[device][routes]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    SECTION("a report with guards renders them") {
        yuzu::server::GuardianDeviceGuardsReport report;
        yuzu::server::GuardianDeviceGuardRow row;
        row.rule_id = "r-1";
        row.name = "Disk encryption guard";
        row.state = "drifted";
        row.updated_at = "2026-11-06T10:00:00Z";
        report.guards.push_back(row);
        report.unrepresented_pending_guards = 2;
        report.unrepresented_pending_rule_ids = {"r-8", "r-9"};
        auto api = std::make_shared<yuzu::server::test::FnGuardianApi>(
            /*list_rules_fn=*/nullptr, /*get_rule_fn=*/nullptr, /*status_fn=*/nullptr,
            /*agent_status_fn=*/nullptr, /*rule_status_fn=*/nullptr,
            [report](const std::string&, GuardianReadFault*) { return std::optional(report); });
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, api, audit);
        auto r = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Disk encryption guard") != std::string::npos);
        CHECK(r->body.find("Guardian store degraded.") == std::string::npos);
        CHECK(r->body.find("2 guards have recorded events not yet reflected in the compliance "
                           "census.") != std::string::npos);
    }
    SECTION("a nullopt report renders the degraded placeholder") {
        auto api = std::make_shared<yuzu::server::test::FnGuardianApi>(
            /*list_rules_fn=*/nullptr, /*get_rule_fn=*/nullptr, /*status_fn=*/nullptr,
            /*agent_status_fn=*/nullptr, /*rule_status_fn=*/nullptr,
            [](const std::string&,
               GuardianReadFault*) -> std::optional<yuzu::server::GuardianDeviceGuardsReport> {
                return std::nullopt;
            });
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, api, audit);
        auto r = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Guardian store degraded.") != std::string::npos);
    }
}

// #4855: a WIRED DexApi whose signal-summary read DEGRADES (a real store, a
// genuine query-level failure — DROP TABLE on a second connection, the same
// technique the Guardian degrade test above and test_guardian_routes.cpp
// use) must render the "DEX store degraded." placeholder AFTER the access
// audit — never the pre-fix silent score-100/no-signals result. Distinct
// from the unwired (dex_api=nullptr) "DEX store unavailable." placeholder
// tested below, and from a null-store DexApi (which is DexApi's own
// documented "no data", degraded=false — see test_dex_api.cpp's null-store
// case) — this is the genuinely-open-but-failing-read case.
TEST_CASE("device lenses: DEX lens on a degraded signal-summary read renders the degraded "
          "placeholder",
          "[pg][device][routes][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    std::vector<std::string> audited;
    auto audit = [&audited](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string& tid, const std::string&) {
        audited.push_back(a + "|" + tid);
        return true;
    };
    auto dex_api = make_local_dex_api(&store, {});
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, /*guardian_api=*/nullptr, audit);

    auto dex = sink.Get("/fragments/device/dex?id=a-1&bare=1");
    REQUIRE(dex);
    CHECK(dex->status == 200);
    CHECK(dex->body == "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>DEX store "
                       "degraded.</div>");
    // The access audit fires BEFORE the read (fail-closed ordering), so it
    // still records "success" -- the audit records the ACCESS, not whether
    // the downstream read then degraded.
    REQUIRE(audited.size() == 1);
    CHECK(audited[0] == "dex.device.view|a-1");
}

// A failed read of the per-agent order row degrades the whole Guardian lens: the lens reads the
// device through device_guards(), which also reads the order row (UP-14), so a store whose order
// table cannot be read renders the degraded placeholder instead of the guard rows, although the
// census read itself succeeds and the lens never renders ordering. The failed read is counted as a
// read degrade on the per-device census source. The same lens with the order table present is the
// control, so the placeholder is proved to come from the order read and not from the fixture.
TEST_CASE("device lenses: Guardian lens renders the degraded placeholder when only the order read "
          "fails",
          "[pg][device][routes][degraded][ordering]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    const std::string agent = "guardian-order-degrade-1";
    REQUIRE(store.create_rule(make_lens_rule("r-order", "Order Guard")));
    REQUIRE(store.insert_event(make_drift_event("evt-order", "r-order", agent, "drift.detected",
                                                "2026-04-19T12:00:00Z")));

    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    std::vector<std::string> audited;
    std::vector<std::string> audit_results;
    auto audit = [&audited, &audit_results](const httplib::Request&, const std::string& a,
                                            const std::string& result, const std::string&,
                                            const std::string& tid, const std::string&) {
        audited.push_back(a + "|" + tid);
        audit_results.push_back(result);
        return true;
    };
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, guardian_api, audit);

    // Control: the order table is present, so the lens renders the guard row.
    auto ok = sink.Get("/fragments/device/guardian?id=" + agent + "&bare=1");
    REQUIRE(ok);
    CHECK(ok->body.find("Guardian store degraded.") == std::string::npos);
    CHECK(ok->body.find("Order Guard") != std::string::npos);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_agent_order")};
        REQUIRE(d.ok());
    }
    // The census read still answers: the failure is the order read alone.
    const auto statuses = store.agent_rule_statuses_for_agent(agent);
    REQUIRE(statuses.has_value());
    CHECK(statuses->size() == 1);
    const auto degraded_before =
        metrics
            .counter("yuzu_server_guardian_read_degrade_total",
                     {{"reason", "query_error"}, {"source", "guardian_census_device"}})
            .value();

    auto gd = sink.Get("/fragments/device/guardian?id=" + agent + "&bare=1");
    REQUIRE(gd);
    CHECK(gd->status == 200);
    CHECK(gd->body == "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>Guardian store "
                      "degraded.</div>");
    CHECK(gd->body.find("Order Guard") == std::string::npos);
    // The failed order read is counted on the per-device census source.
    CHECK(metrics
              .counter("yuzu_server_guardian_read_degrade_total",
                       {{"reason", "query_error"}, {"source", "guardian_census_device"}})
              .value() == degraded_before + 1);
    // Both opens are audited, and the row's result follows the read: success for the control,
    // failure for the open whose order read failed.
    REQUIRE(audited.size() == 2);
    CHECK(audited[1] == "guardian.device.view|" + agent);
    REQUIRE(audit_results.size() == 2);
    CHECK(audit_results[0] == "success");
    CHECK(audit_results[1] == "failure");
}

// ─────────────────────────────────────────────────────────────────────────
// CHARACTERIZATION — pins the exact rendered HTML BEFORE the WS-A4 seam
// rewire (issue #4576 + the guardian-lens deferral) so the rewire in a
// follow-up commit can be checked against these assertions UNCHANGED (one
// accepted, documented delta: a zero-statuses device on a degraded
// rule-name read — see that follow-up's commit message; not reachable
// through a healthy store, so no case below exercises it).
// ─────────────────────────────────────────────────────────────────────────

// store=nullptr placeholder text: FULL-BODY equality (bare=1 strips the tab
// bar down to exactly the placeholder div), so a rewire that changes even
// the wording is caught, not just a substring drift.
TEST_CASE("device lenses: store-unavailable placeholders are byte-exact (bare=1)",
          "[device][routes]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, /*guardian_api=*/nullptr);

    auto dex = sink.Get("/fragments/device/dex?id=a-1&bare=1");
    REQUIRE(dex);
    CHECK(dex->status == 200);
    CHECK(dex->body ==
         "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>DEX store unavailable.</div>");

    auto gd = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
    REQUIRE(gd);
    CHECK(gd->status == 200);
    CHECK(gd->body == "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>Guardian store "
                      "unavailable.</div>");
}

TEST_CASE("device lenses: DEX lens renders the per-device score + known signal counts",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string agent = "dex-dev-1";
    REQUIRE(store.insert_event(make_observation("obs-1", agent, "process.crashed", kRecentTs)));
    REQUIRE(store.insert_event(make_observation("obs-2", agent, "process.crashed", kRecentTs)));
    REQUIRE(store.insert_event(make_observation("obs-3", agent, "process.hung", kRecentTs)));

    // Oracle: the exact same call the (pre-rewire) route handler makes.
    const std::string since = yuzu::server::dex_iso_since(7);
    const int expected_score = yuzu::server::dex_device_score(&store, agent, since);

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/dex?id=" + agent + "&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // Score tile — exact digits, whichever "good"/"warn" class applies.
    const std::string score_class = expected_score >= 90 ? "good" : "warn";
    CHECK(r->body.find("<div class=\"n " + score_class + "\">" + std::to_string(expected_score) +
                       "</div>") != std::string::npos);
    // Signal rows — exact markup, count anchored per-row (obs_type -> label
    // mapping is byte-fixed in dex_routes.cpp's dex_signal_label).
    CHECK(r->body.find("<tr><td>App crash</td><td class=\"gp-mute\" "
                       "style=\"font-family:var(--mds-font-family-mono);font-size:12.5px\">process.crashed"
                       "</td><td class=\"gp-num\">2</td></tr>") != std::string::npos);
    CHECK(r->body.find("<tr><td>App hang</td><td class=\"gp-mute\" "
                       "style=\"font-family:var(--mds-font-family-mono);font-size:12.5px\">process.hung"
                       "</td><td class=\"gp-num\">1</td></tr>") != std::string::npos);
}

TEST_CASE("device lenses: DEX lens — no signals in-window renders the honest-empty message",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/dex?id=dex-empty-1&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("<div class=\"gp-placeholder\"><b>No DEX signals</b>Nothing fired on this "
                       "device in the window &mdash; experience is clean.</div>") !=
         std::string::npos);
}

TEST_CASE("device lenses: Guardian lens renders known guards and drops a deleted rule's row, "
          "order-insensitive",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string agent = "guardian-dev-1";
    REQUIRE(store.create_rule(make_lens_rule("r-alpha", "Alpha Guard")));
    REQUIRE(store.create_rule(make_lens_rule("r-bravo", "Bravo Guard")));
    // r-orphan is created, reports, and is then deleted. The census row has a foreign key
    // to the rule (schema v3, #5674), so the delete removes its status row and the lens no
    // longer lists it; a status row with no rule row, which this test used to arrange to
    // exercise the raw rule_id display-name fallback, can no longer exist.
    REQUIRE(store.create_rule(make_lens_rule("r-orphan", "Orphan Guard")));
    REQUIRE(store.insert_event(
        make_drift_event("evt-alpha", "r-alpha", agent, "drift.detected", "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(make_drift_event("evt-bravo", "r-bravo", agent, "drift.remediated",
                                                "2026-04-19T13:00:00Z")));
    REQUIRE(store.insert_event(make_drift_event("evt-orphan", "r-orphan", agent, "drift.detected",
                                                "2026-04-19T14:00:00Z")));
    REQUIRE(store.delete_rule("r-orphan"));

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/guardian?id=" + agent + "&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // 1 compliant (bravo) of 2 guards -> 50%.
    CHECK(r->body.find("<div class=\"sx\">1 of 2 guards</div>") != std::string::npos);
    // Order-insensitive: each row asserted independently by exact markup
    // (name cell + guard_state_badge markup + updated_at, byte-for-byte).
    CHECK(r->body.find("<tr><td class=\"name\">Alpha Guard</td><td><span "
                       "style=\"display:inline-block;padding:1px 8px;border-radius:3px;font-size:12.5px;"
                       "font-weight:500;color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,"
                       "transparent)\">drifted</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T12:00:00Z</td></tr>") != std::string::npos);
    CHECK(r->body.find("<tr><td class=\"name\">Bravo Guard</td><td><span "
                       "style=\"display:inline-block;padding:1px 8px;border-radius:3px;font-size:12.5px;"
                       "font-weight:500;color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,"
                       "transparent)\">compliant</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T13:00:00Z</td></tr>") != std::string::npos);
    CHECK(r->body.find("r-orphan") == std::string::npos);
    CHECK(r->body.find("Orphan Guard") == std::string::npos);
}

TEST_CASE("device lenses: Guardian lens: a guard.errored lifecycle event shows the rule as errored "
          "(C-1)",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string agent = "guardian-errored-1";
    REQUIRE(store.create_rule(make_lens_rule("r-err", "Errored Guard")));
    // Compliant first, then the guard itself errors (guard.errored, NOT guard.unhealthy):
    // the census keeps the later verdict, so the lens must render "errored", not "compliant".
    REQUIRE(store.insert_event(make_drift_event("evt-ok", "r-err", agent, "guard.compliant",
                                                "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(make_drift_event("evt-err", "r-err", agent, "guard.errored",
                                                "2026-04-19T13:00:00Z")));

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/guardian?id=" + agent + "&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // errored badge is red (--bad) and carries the later event's timestamp.
    CHECK(r->body.find("<tr><td class=\"name\">Errored Guard</td><td><span "
                       "style=\"display:inline-block;padding:1px 8px;border-radius:3px;font-size:12.5px;"
                       "font-weight:500;color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,"
                       "transparent)\">errored</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T13:00:00Z</td></tr>") != std::string::npos);
    // errored does not count as compliant: 0 of 1 guards.
    CHECK(r->body.find("<div class=\"n warn\">0%</div><div class=\"l\">Compliant</div>"
                       "<div class=\"sx\">0 of 1 guards</div>") != std::string::npos);
    CHECK(r->body.find(">compliant</span>") == std::string::npos);
}

TEST_CASE("device lenses: Guardian lens — zero statuses renders the honest-empty message",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // A rule exists in the catalogue, but this device has never reported it —
    // proves the empty-guards message, not a degraded-store message.
    REQUIRE(store.create_rule(make_lens_rule("r-unreported", "Unreported Guard")));

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/guardian?id=guardian-empty-1&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body == "<div class=\"gp-placeholder\"><b>No guards evaluated</b>No Guardian guards "
                     "have been evaluated on this device yet.</div>");
}

TEST_CASE(
    "DeviceLensRoutes guardian lens: an order-uncertain guard keeps the tile off 'good' (#5690)",
    "[pg][device][lens][ordering]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string agent = "guardian-dev-2";
    REQUIRE(store.create_rule(make_lens_rule("r-alpha", "Alpha Guard")));
    // A compliant verdict, then an OLDER drift verdict that arrives later: the row keeps the
    // compliant verdict and is flagged, so every guard reads compliant but is not trustworthy.
    REQUIRE(store.insert_event(
        make_drift_event("evt-1", "r-alpha", agent, "drift.remediated", "2026-04-19T13:00:00Z")));
    REQUIRE(store.insert_event(
        make_drift_event("evt-2", "r-alpha", agent, "drift.detected", "2026-04-19T12:00:00Z")));

    auto dex_api = make_local_dex_api(&store, {});
    auto guardian_api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) {
        return true;
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, dex_api, guardian_api);

    auto r = sink.Get("/fragments/device/guardian?id=" + agent + "&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("100%") != std::string::npos);
    CHECK(r->body.find("class=\"n good\"") == std::string::npos);
    CHECK(r->body.find("1 with uncertain ordering or an unreflected verdict") != std::string::npos);
    CHECK(r->body.find("&middot; ordering uncertain") != std::string::npos); // the row marker
    CHECK(r->body.find("See the Guaranteed State guide, section 'When a verdict is flagged or does "
                       "not move'.") != std::string::npos); // and points at the runbook
}

// ── #7217: the lens shows the unrepresented-pending summary ──────────────────────────────────────

namespace {

constexpr const char* kUnreflectedNotice = "recorded events not yet reflected in the compliance census.";

DeviceGuardRow lens_clean_row(std::string name = "Defender RTP") {
    DeviceGuardRow r;
    r.name = std::move(name);
    r.state = "compliant";
    r.updated_at = "2026-11-06T10:00:00Z";
    return r;
}

using GuardsFn = std::function<std::optional<GuardianDeviceGuardsReport>(const std::string&,
                                                                        GuardianReadFault*)>;

// One routed GET of the Guardian lens over a FnGuardianApi that answers `fn`. `audit_results`
// receives the `result` field of every audit row the lens writes.
std::string fetch_guardian_lens(GuardsFn fn, std::vector<std::string>* audit_results = nullptr) {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    auto audit = [audit_results](const httplib::Request&, const std::string&, const std::string& result,
                                 const std::string&, const std::string&, const std::string&) {
        if (audit_results)
            audit_results->push_back(result);
        return true;
    };
    auto api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        /*list_rules_fn=*/nullptr, /*get_rule_fn=*/nullptr, /*status_fn=*/nullptr,
        /*agent_status_fn=*/nullptr, /*rule_status_fn=*/nullptr, std::move(fn));
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, api, audit);
    auto r = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
    REQUIRE(r);
    CHECK(r->status == 200);
    return r->body;
}

GuardianDeviceGuardsReport report_of(std::vector<DeviceGuardRow> rows, std::int64_t unrepresented,
                                     std::vector<std::string> ids) {
    GuardianDeviceGuardsReport rep;
    for (const auto& r : rows) {
        GuardianDeviceGuardRow g;
        g.rule_id = "id-" + r.name;
        g.name = r.name;
        g.state = r.state;
        g.updated_at = r.updated_at;
        rep.guards.push_back(std::move(g));
    }
    rep.unrepresented_pending_guards = unrepresented;
    rep.unrepresented_pending_rule_ids = std::move(ids);
    return rep;
}

} // namespace

TEST_CASE("Guardian lens renderer: pending evidence with no census row keeps the tile off the clean "
          "state and shows a notice (#7217)",
          "[device][ui][ordering][unrepresented]") {
    const auto clean = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 0, {});
    CHECK(clean.find("class=\"n good\"") != std::string::npos);
    CHECK(clean.find("<div class=\"l\">Compliant</div>") != std::string::npos);
    CHECK(clean.find(kUnreflectedNotice) == std::string::npos);
    CHECK(clean.find("gp-banner") == std::string::npos);

    const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 3, {"g-a", "g-b", "g-c"});
    CHECK(h.find("100%") != std::string::npos); // the one represented guard IS compliant
    CHECK(h.find("class=\"n good\"") == std::string::npos);
    CHECK(h.find("class=\"n warn\"") != std::string::npos);
    CHECK(h.find("<div class=\"l\">Compliant, ordering uncertain</div>") != std::string::npos);
    CHECK(h.find("1 of 1 guards, 3 more with events not yet in the census") != std::string::npos);
    CHECK(h.find("3 guards have " + std::string(kUnreflectedNotice)) != std::string::npos);
    CHECK(h.find("<code>g-a</code>, <code>g-b</code>, <code>g-c</code>") != std::string::npos);
    CHECK(h.find("See the Guaranteed State guide, section 'When a verdict is flagged or does not "
                 "move'.") != std::string::npos);
    // The notice uses the token-themed banner class and carries no inline style of its own.
    const auto banner_begin = h.find("<div class=\"gp-banner\">");
    REQUIRE(banner_begin != std::string::npos);
    const auto banner_end = h.find("<div class=\"gp-sech\"", banner_begin);
    REQUIRE(banner_end != std::string::npos);
    CHECK(h.substr(banner_begin, banner_end - banner_begin).find("style=") == std::string::npos);
    CHECK(h.find("hx-on") == std::string::npos);

    SECTION("a single guard is worded in the singular") {
        const auto one = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 1, {"g-a"});
        CHECK(one.find("1 guard has " + std::string(kUnreflectedNotice)) != std::string::npos);
    }
    SECTION("a drifted guard keeps its own label; the extra count still shows") {
        auto bad = lens_clean_row();
        bad.state = "drifted";
        const auto d = render_device_guardian_lens("a-1", {bad}, true, 2, {"g-a", "g-b"});
        CHECK(d.find("<div class=\"l\">Compliant</div>") != std::string::npos); // 0%, not "ordering uncertain"
        CHECK(d.find("0 of 1 guards, 2 more with events not yet in the census") != std::string::npos);
    }
}

TEST_CASE("Guardian lens renderer: an empty guard list with pending evidence is never 'No guards "
          "evaluated' (#7217)",
          "[device][ui][ordering][unrepresented]") {
    const auto none = render_device_guardian_lens("a-1", {}, true, 0, {});
    CHECK(none.find("<b>No guards evaluated</b>") != std::string::npos); // unchanged for zero
    CHECK(none.find("gp-banner") == std::string::npos);

    const auto h = render_device_guardian_lens("a-1", {}, true, 2, {"g-a", "g-b"});
    CHECK(h.find("No guards evaluated") == std::string::npos);
    CHECK(h.find("2 guards have " + std::string(kUnreflectedNotice)) != std::string::npos);
    CHECK(h.find("<code>g-a</code>, <code>g-b</code>") != std::string::npos);
    CHECK(h.find("<b>No guards in the compliance census</b>") != std::string::npos);
    CHECK(h.find("class=\"n good\"") == std::string::npos);
}

TEST_CASE("Guardian lens renderer: unrepresented ids are HTML-escaped, bounded and never cut "
          "mid-character (#7217)",
          "[device][ui][ordering][unrepresented]") {
    SECTION("markup in an id is escaped") {
        const auto h = render_device_guardian_lens(
            "a-1", {lens_clean_row()}, true, 1, {"<script>alert(1)</script>\"'&"});
        CHECK(h.find("<script>") == std::string::npos);
        CHECK(h.find("&lt;script&gt;") != std::string::npos);
        CHECK(h.find("&quot;") != std::string::npos);
    }
    SECTION("at most ten ids are listed and the rest are counted") {
        std::vector<std::string> ids;
        for (int i = 0; i < 25; ++i)
            ids.push_back("id-" + std::to_string(100 + i));
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 80, ids);
        CHECK(h.find("<code>id-109</code>") != std::string::npos);
        CHECK(h.find("id-110") == std::string::npos);
        CHECK(h.find(" and 70 more") != std::string::npos); // 80 - 10, count is exact beyond the list
        CHECK(h.find("80 guards have ") != std::string::npos);
    }
    SECTION("the count may exceed the capped id list") {
        std::vector<std::string> ids;
        for (int i = 0; i < 50; ++i)
            ids.push_back("id-" + std::to_string(100 + i));
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 51, ids);
        CHECK(h.find(" and 41 more") != std::string::npos);
    }
    SECTION("an id of up to 64 bytes is shown whole") {
        const std::string id64(64, 'x');
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 1, {id64});
        CHECK(h.find("<code>" + id64 + "</code>") != std::string::npos);
    }
    SECTION("a longer id is cut at 64 bytes and marked") {
        const std::string id(200, 'y');
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 1, {id});
        CHECK(h.find("<code>" + std::string(64, 'y') + "...</code>") != std::string::npos);
        CHECK(h.find(std::string(65, 'y')) == std::string::npos);
    }
    SECTION("the cut backs up to a UTF-8 boundary") {
        // 63 ASCII bytes then a two-byte character (bytes 63 and 64): a cut at 64 would split it.
        const std::string id = std::string(63, 'z') + "\xC3\xA9" + std::string(10, 'z');
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 1, {id});
        CHECK(h.find("<code>" + std::string(63, 'z') + "...</code>") != std::string::npos);
        CHECK(h.find('\xC3') == std::string::npos); // no lead byte left dangling
    }
    // The cases below read the rendered <code> text back and require it to be a whole-sequence
    // UTF-8 prefix of the id plus the "..." marker, so a split sequence cannot hide behind a
    // substring check.
    const auto lens_code_text = [](const std::string& id) {
        const auto h = render_device_guardian_lens("a-1", {lens_clean_row()}, true, 1, {id});
        const auto b = h.find("<code>");
        REQUIRE(b != std::string::npos);
        const auto e = h.find("</code>", b);
        REQUIRE(e != std::string::npos);
        return h.substr(b + 6, e - (b + 6));
    };
    const auto valid_utf8 = [](const std::string& t) {
        std::size_t i = 0;
        while (i < t.size()) {
            const auto c = static_cast<unsigned char>(t[i]);
            std::size_t n = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3
                                       : (c & 0xF8) == 0xF0 ? 4 : 0;
            if (n == 0 || i + n > t.size())
                return false;
            for (std::size_t k = 1; k < n; ++k)
                if ((static_cast<unsigned char>(t[i + k]) & 0xC0) != 0x80)
                    return false;
            i += n;
        }
        return true;
    };
    SECTION("a three-byte sequence straddling byte 64 is dropped whole") {
        // The euro sign (E2 82 AC) starts at index 62: bytes 62 and 63 fall inside the first 64.
        const std::string id = std::string(62, 'a') + "\xE2\x82\xAC" + std::string(10, 'b');
        const auto t = lens_code_text(id);
        CHECK(t == std::string(62, 'a') + "...");
        CHECK(valid_utf8(t));
    }
    SECTION("a four-byte sequence straddling byte 64 is dropped whole") {
        // U+1F600 (F0 9F 98 80) starts at index 61: bytes 61..63 fall inside the first 64.
        const std::string id = std::string(61, 'a') + "\xF0\x9F\x98\x80" + std::string(10, 'b');
        const auto t = lens_code_text(id);
        CHECK(t == std::string(61, 'a') + "...");
        CHECK(valid_utf8(t));
    }
    SECTION("a four-byte sequence whose lead byte is the last one kept is dropped whole") {
        const std::string id = std::string(63, 'a') + "\xF0\x9F\x98\x80" + std::string(10, 'b');
        const auto t = lens_code_text(id);
        CHECK(t == std::string(63, 'a') + "...");
        CHECK(valid_utf8(t));
    }
    SECTION("an id of exactly 64 bytes ending in a whole multibyte character is not cut") {
        const std::string id = std::string(62, 'a') + "\xC3\xA9";
        REQUIRE(id.size() == 64);
        const auto t = lens_code_text(id);
        CHECK(t == id);
        CHECK(valid_utf8(t));
    }
    SECTION("an id of 65 bytes is cut and marked") {
        const std::string id(65, 'x');
        const auto t = lens_code_text(id);
        CHECK(t == std::string(64, 'x') + "...");
    }
    SECTION("an id made only of continuation bytes renders just the marker") {
        const std::string id(100, '\x80');
        const auto t = lens_code_text(id);
        CHECK(t == "...");
        CHECK(valid_utf8(t));
    }
}

TEST_CASE("device lenses: Guardian lens routes the unrepresented summary into the page (#7217)",
          "[device][routes][ordering][unrepresented]") {
    SECTION("a compliant guard plus pending evidence is not clean, and the audit says success") {
        std::vector<std::string> results;
        const auto body = fetch_guardian_lens(
            [](const std::string&, GuardianReadFault*) {
                return std::optional(report_of({lens_clean_row()}, 2, {"g-a", "g-b"}));
            },
            &results);
        CHECK(body.find("class=\"n good\"") == std::string::npos);
        CHECK(body.find("2 guards have " + std::string(kUnreflectedNotice)) != std::string::npos);
        CHECK(body.find("<code>g-a</code>, <code>g-b</code>") != std::string::npos);
        REQUIRE(results.size() == 1);
        CHECK(results[0] == "success");
    }
    SECTION("an empty guard list with pending evidence shows the notice, not 'No guards evaluated'") {
        const auto body = fetch_guardian_lens([](const std::string&, GuardianReadFault*) {
            return std::optional(report_of({}, 1, {"g-only"}));
        });
        CHECK(body.find("No guards evaluated") == std::string::npos);
        CHECK(body.find("1 guard has " + std::string(kUnreflectedNotice)) != std::string::npos);
        CHECK(body.find("<code>g-only</code>") != std::string::npos);
    }
    SECTION("no pending evidence renders the clean state unchanged") {
        const auto body = fetch_guardian_lens([](const std::string&, GuardianReadFault*) {
            return std::optional(report_of({lens_clean_row()}, 0, {}));
        });
        CHECK(body.find("class=\"n good\"") != std::string::npos);
        CHECK(body.find(kUnreflectedNotice) == std::string::npos);
    }
    SECTION("a hostile id from the store is escaped on the page") {
        const auto body = fetch_guardian_lens([](const std::string&, GuardianReadFault*) {
            return std::optional(report_of({lens_clean_row()}, 1, {"<img src=x onerror=alert(1)>"}));
        });
        CHECK(body.find("<img") == std::string::npos);
        CHECK(body.find("&lt;img src=x onerror=alert(1)&gt;") != std::string::npos);
    }
}

TEST_CASE("device lenses: a Guardian read that throws is audited once as a failure and the "
          "exception propagates (#7217)",
          "[device][routes][ordering][unrepresented]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    std::vector<std::string> actions;
    std::vector<std::string> results;
    auto audit = [&](const httplib::Request&, const std::string& action, const std::string& result,
                     const std::string&, const std::string&, const std::string&) {
        actions.push_back(action);
        results.push_back(result);
        return true;
    };
    auto api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        /*list_rules_fn=*/nullptr, /*get_rule_fn=*/nullptr, /*status_fn=*/nullptr,
        /*agent_status_fn=*/nullptr, /*rule_status_fn=*/nullptr,
        [](const std::string&, GuardianReadFault*) -> std::optional<GuardianDeviceGuardsReport> {
            throw std::runtime_error("device_guards blew up");
        });
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, okScoped, /*dex_api=*/nullptr, api, audit);

    // TestRouteSink runs the handler without a catch, so the rethrown exception reaches the test.
    CHECK_THROWS_AS(sink.Get("/fragments/device/guardian?id=a-1&bare=1"), std::runtime_error);
    REQUIRE(actions.size() == 1);
    CHECK(actions[0] == "guardian.device.view");
    CHECK(results[0] == "failure");
}

TEST_CASE("device lenses: Guardian lens distinguishes a pending-evidence timeout from a transient "
          "degrade and audits both as failures (#7217)",
          "[device][routes][ordering][unrepresented]") {
    SECTION("a statement timeout names the likely cause and says reloading usually does not help") {
        std::vector<std::string> results;
        const auto body = fetch_guardian_lens(
            [](const std::string&, GuardianReadFault* fault) -> std::optional<GuardianDeviceGuardsReport> {
                *fault = GuardianReadFault::kStatementTimeout;
                return std::nullopt;
            },
            &results);
        CHECK(body.find("Guardian pending-evidence read timed out.") != std::string::npos);
        CHECK(body.find("Most likely a large retained pending backlog") != std::string::npos);
        CHECK(body.find("reloading usually will not help until it clears") != std::string::npos);
        CHECK(body.find("Guardian store degraded.") == std::string::npos);
        REQUIRE(results.size() == 1);
        CHECK(results[0] == "failure");
    }
    SECTION("a transient degrade keeps the original text byte for byte") {
        std::vector<std::string> results;
        const auto body = fetch_guardian_lens(
            [](const std::string&, GuardianReadFault* fault) -> std::optional<GuardianDeviceGuardsReport> {
                *fault = GuardianReadFault::kTransient;
                return std::nullopt;
            },
            &results);
        CHECK(body == "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>Guardian store "
                      "degraded.</div>");
        REQUIRE(results.size() == 1);
        CHECK(results[0] == "failure");
    }
    SECTION("a degrade that names no kind is treated as transient") {
        const auto body = fetch_guardian_lens(
            [](const std::string&, GuardianReadFault*) -> std::optional<GuardianDeviceGuardsReport> {
                return std::nullopt;
            });
        CHECK(body.find("Guardian store degraded.") != std::string::npos);
        CHECK(body.find("timed out") == std::string::npos);
    }
}
