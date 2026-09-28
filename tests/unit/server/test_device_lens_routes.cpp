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
#include "dex_routes.hpp"             // dex_iso_since / dex_window_to_days / dex_device_score (oracle)
#include "guaranteed_state_store.hpp"
#include "guardian_api_local.hpp"     // make_local_guardian_api
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"             // PgConn/PgResult -- the DROP-TABLE degrade test below
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

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
    REQUIRE_FALSE(degraded->device_guards("a-1").has_value());
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
                       "style=\"font-family:Consolas,monospace;font-size:.7rem\">process.crashed"
                       "</td><td class=\"gp-num\">2</td></tr>") != std::string::npos);
    CHECK(r->body.find("<tr><td>App hang</td><td class=\"gp-mute\" "
                       "style=\"font-family:Consolas,monospace;font-size:.7rem\">process.hung"
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

TEST_CASE("device lenses: Guardian lens renders known guards incl. an orphan-rule-id fallback, "
          "order-insensitive",
          "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string agent = "guardian-dev-1";
    REQUIRE(store.create_rule(make_lens_rule("r-alpha", "Alpha Guard")));
    REQUIRE(store.create_rule(make_lens_rule("r-bravo", "Bravo Guard")));
    // r-orphan is NEVER created via create_rule — its status row has no
    // matching rule catalogue entry, so the lens must fall back to the raw
    // rule_id for its display name (guardian_device_all_guards's documented
    // fallback; events table carries no FK to the rules table).
    REQUIRE(store.insert_event(
        make_drift_event("evt-alpha", "r-alpha", agent, "drift.detected", "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(make_drift_event("evt-bravo", "r-bravo", agent, "drift.remediated",
                                                "2026-04-19T13:00:00Z")));
    REQUIRE(store.insert_event(make_drift_event("evt-orphan", "r-orphan", agent, "drift.detected",
                                                "2026-04-19T14:00:00Z")));

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
    // 1 compliant (bravo) of 3 guards -> round(100/3) = 33%.
    CHECK(r->body.find("<div class=\"n warn\">33%</div><div class=\"l\">Compliant</div>"
                       "<div class=\"sx\">1 of 3 guards</div>") != std::string::npos);
    // Order-insensitive: each row asserted independently by exact markup
    // (name cell + guard_state_badge markup + updated_at, byte-for-byte).
    CHECK(r->body.find("<tr><td class=\"name\">Alpha Guard</td><td><span "
                       "style=\"font-size:.6rem;font-weight:700;border-radius:.3rem;padding:.05rem "
                       ".4rem;color:#06121f;background:#ffcc00\">drifted</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T12:00:00Z</td></tr>") != std::string::npos);
    CHECK(r->body.find("<tr><td class=\"name\">Bravo Guard</td><td><span "
                       "style=\"font-size:.6rem;font-weight:700;border-radius:.3rem;padding:.05rem "
                       ".4rem;color:#06121f;background:#4ed27e\">compliant</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T13:00:00Z</td></tr>") != std::string::npos);
    CHECK(r->body.find("<tr><td class=\"name\">r-orphan</td><td><span "
                       "style=\"font-size:.6rem;font-weight:700;border-radius:.3rem;padding:.05rem "
                       ".4rem;color:#06121f;background:#ffcc00\">drifted</span></td>"
                       "<td class=\"gp-mute\">2026-04-19T14:00:00Z</td></tr>") != std::string::npos);
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
