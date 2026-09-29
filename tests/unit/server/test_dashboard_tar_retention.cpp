/**
 * test_dashboard_tar_retention.cpp — render harness for
 * DashboardRoutes::render_tar_retention_paused (#1519 / #558 / #560 / #561;
 * docs/tar-dashboard.md §3.6, tracked harness #562).
 *
 * The renderer mixes three security-sensitive behaviours that a future edit
 * could silently regress, so they are pinned here directly rather than only
 * through the html_escape primitive:
 *   - #560 XSS: the untrusted agent-supplied `<source>_enabled` value is
 *     emitted into a `title=` attribute and a `<code>` node — both must be
 *     html_escaped (a `"><script>` payload must not escape its context).
 *   - #561 dedup: per-agent dedup keys ONLY on the server-stamped
 *     `received_at_ms`, never the agent-claimed `timestamp`, so a compromised
 *     agent cannot backdate a stale "enabled=true" row to hide a paused source.
 *   - #558 sort: value-error rows float to the top; an unknown `paused_at==0`
 *     (pre-v0.12.0 agent) is OLDEST (top), not newest, and renders a
 *     "schema older than server" badge.
 *
 * render_tar_retention_paused and its inputs (response_store_,
 * mgmt_group_store_, tar_scans_by_user_) are private; the
 * DashboardTarRetentionTestAccess friend seam (dashboard_routes.hpp) wires
 * them without standing up an HTTP server. Visibility is granted the same way
 * production does it on this branch — a role assignment on a group whose
 * members are the agents under test (get_visible_agents is the role-scoped
 * join).
 */

#include "dashboard_routes.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "tar_tree_routes.hpp" // TarRetentionPausedScan's full definition (#4143 review fix test)
#include "test_mgmt_group_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace yuzu::server {

using yuzu::server::pg::PgPool;

namespace {
// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};
} // namespace

// Test-only accessor for the private renderer + its store/scan inputs (#562).
struct DashboardTarRetentionTestAccess {
    DashboardRoutes routes;

    void set_stores(ResponseStore* rs, ManagementGroupStore* mg) {
        routes.response_store_ = rs;
        routes.mgmt_group_store_ = mg;
    }
    void set_scan(const std::string& user, const std::string& cmd_id, int count, int64_t at) {
        routes.tar_scans_by_user_[user] = DashboardRoutes::TarScanState{cmd_id, count, at};
    }
    std::string render(const std::string& user, bool can_execute = true,
                       bool can_delete = true) const {
        return routes.render_tar_retention_paused(user, can_execute, can_delete);
    }
};

namespace {

constexpr const char* kUser = "operator";
constexpr const char* kScan = "scan-cmd-1";

StoredResponse mk_resp(const std::string& agent, int64_t received_ms, std::string output) {
    StoredResponse r;
    r.instruction_id = kScan; // render queries the store by this (== command_id)
    r.agent_id = agent;
    r.received_at_ms = received_ms; // store() honours a >0 value (response_store.cpp:232)
    r.status = 0;
    r.output = std::move(output);
    return r;
}

// Make `agents` visible to kUser: members of a group on which kUser holds a
// role (get_visible_agents is the role-scoped join). An agent NOT passed here
// is out of scope and must be filtered by the renderer's visibility gate.
void grant_visibility(ManagementGroupStore& mg, std::initializer_list<std::string> agents) {
    ManagementGroup g;
    g.name = "All Devices";
    g.membership_type = "static";
    auto gid = mg.create_group(g);
    REQUIRE(gid.has_value());
    for (const auto& a : agents)
        mg.add_member(*gid, a);
    GroupRoleAssignment ra;
    ra.group_id = *gid;
    ra.principal_type = "user";
    ra.principal_id = kUser;
    ra.role_name = "ITServiceOwner";
    REQUIRE(mg.assign_role(ra).has_value());
}

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("render_tar_retention_paused: hostile _enabled value is escaped + flagged (#560)",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-evil", "agent-ok"});

    // agent-evil reports a breakout payload as its process_enabled value; agent-ok
    // is a normal paused source. The hostile value must be escaped in BOTH the
    // title= attribute and the <code> node, and the value-error row must sort
    // ABOVE the normal paused row.
    rs.store(mk_resp("agent-evil", 1000,
                     "config|process_enabled|\"><script>alert(1)</script>\n"));
    rs.store(mk_resp("agent-ok", 1000,
                     "config|tcp_enabled|false\nconfig|tcp_paused_at|1710000000\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 2, 1709990000);
    const std::string html = acc.render(kUser);

    // No unescaped breakout — the raw <script> must never reach the DOM.
    CHECK_FALSE(contains(html, "<script>alert(1)</script>"));
    CHECK(contains(html, "&lt;script&gt;"));     // escaped form present
    CHECK(contains(html, "badge badge-danger")); // value-error badge rendered
    CHECK(contains(html, "value error"));
    // The scan id is echoed (escaped) in the provenance header.
    CHECK(contains(html, "scan-cmd-1"));
    // Sort: the value-error row (agent-evil) precedes the normal paused row.
    const auto p_evil = html.find("agent-evil");
    const auto p_ok = html.find("agent-ok");
    REQUIRE(p_evil != std::string::npos); // a dropped row → npos → false-pass on `<`
    REQUIRE(p_ok != std::string::npos);
    CHECK(p_evil < p_ok);
}

TEST_CASE("render_tar_retention_paused: a value in the _enabled attribute cannot break out (#560)",
          "[pg][server][tar][retention-render]") {
    // The value-error path emits the untrusted value into a title= ATTRIBUTE.
    // A `<`/`>`-free payload that closes the attribute with a bare `\"` would
    // inject an event handler if the `\"`-escape regressed — html_escape must
    // turn `\"` into `&quot;`. Asserting only absence-of-`<script>` would miss
    // this, so pin the attribute-quote escape directly.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-x"});

    rs.store(mk_resp("agent-x", 1000,
                     "config|process_enabled|false\" onmouseover=alert(1) x=\"\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 1, 1);
    const std::string html = acc.render(kUser);

    CHECK(contains(html, "badge badge-danger"));     // surfaced as a value error
    CHECK(contains(html, "&quot;"));                 // the `"` was escaped
    CHECK_FALSE(contains(html, "\" onmouseover=alert(1) x=\"")); // raw breakout absent
}

TEST_CASE("render_tar_retention_paused: dedup keys on received_at_ms, latest wins (#561)",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"});

    SECTION("a newer enabled=true response hides an older paused response") {
        rs.store(mk_resp("agent-A", 1000, "config|process_enabled|false\n")); // older: paused
        rs.store(mk_resp("agent-A", 2000, "config|process_enabled|true\n"));  // newer: collecting
        DashboardTarRetentionTestAccess acc;
        acc.set_stores(&rs, &mg);
        acc.set_scan(kUser, kScan, 1, 1);
        const std::string html = acc.render(kUser);
        // Latest (received_at_ms=2000) says collecting → NOT in the paused list.
        CHECK(contains(html, "No paused sources detected"));
    }

    SECTION("a newer paused response wins over an older enabled response") {
        rs.store(mk_resp("agent-A", 1000, "config|process_enabled|true\n"));  // older: collecting
        rs.store(mk_resp("agent-A", 2000, "config|process_enabled|false\n")); // newer: paused
        DashboardTarRetentionTestAccess acc;
        acc.set_stores(&rs, &mg);
        acc.set_scan(kUser, kScan, 1, 1);
        const std::string html = acc.render(kUser);
        CHECK(contains(html, "<table>"));
        CHECK(contains(html, "agent-A"));
        CHECK(contains(html, "schema older than server")); // no paused_at → #558 badge
    }
}

TEST_CASE("render_tar_retention_paused: each visible agent appears; out-of-scope dropped",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A", "agent-B"}); // agent-C deliberately out of scope

    rs.store(mk_resp("agent-A", 10,
                     "config|process_enabled|false\nconfig|process_paused_at|1710000000\n"));
    rs.store(mk_resp("agent-B", 10,
                     "config|tcp_enabled|false\nconfig|tcp_paused_at|1710000500\n"));
    rs.store(mk_resp("agent-C", 10,
                     "config|service_enabled|false\nconfig|service_paused_at|1710000900\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 3, 1);
    const std::string html = acc.render(kUser);

    // Both in-scope agents' paused sources render; the out-of-scope agent is
    // filtered (visibility gate) and reported as dropped.
    CHECK(contains(html, "agent-A"));
    CHECK(contains(html, "agent-B"));
    CHECK_FALSE(contains(html, "agent-C"));
    CHECK(contains(html, "out-of-scope"));
    // NOTE: the >10,000-responses-from-one-agent global-window starvation the
    // reviewer flagged is the store-side per-(command_id, agent_id) cap tracked
    // in #561 — not reproducible at unit scale and out of scope for this render
    // harness; the per-agent dedup proven above bounds parse work, not the fetch.
}

// #4143 review fix regression (TESTS-1 + BLOCKING, ADR-0017 INV-4/INV-7):
// gather_tar_retention_paused's extra_scope fold had zero test coverage — the
// gap that let the two-resolver divergence ship. This exercises the fold
// directly (gather_tar_retention_paused is public) against a real
// ManagementGroupStore, proving `extra_scope_is_authoritative=true` (the
// REST/MCP twins) makes gate.scope the SOLE filter, bypassing the flat
// direct-membership `visible_set` check entirely — mo agent-C is NOT a
// direct member of any group kUser holds a role on (visible_set would drop
// it, modelling an ancestor-scoped-not-direct-member admit), but agent-C IS
// named in extra_scope (modelling gate.scope's ancestor-ward expansion).
TEST_CASE("gather_tar_retention_paused: extra_scope_is_authoritative bypasses "
          "the flat visible_set (#4143 review fix, ADR-0017 INV-4/INV-7)",
          "[pg][server][tar][retention-render][adr-0017]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"}); // kUser's direct-membership visible_set = {agent-A} only

    rs.store(mk_resp("agent-A", 10,
                     "config|process_enabled|false\nconfig|process_paused_at|1710000000\n"));
    rs.store(mk_resp("agent-C", 10,
                     "config|service_enabled|false\nconfig|service_paused_at|1710000900\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 2, 1);

    const authz::VisibleSet gate_scope{std::unordered_set<std::string>{"agent-A", "agent-C"}};

    SECTION("default (fragment caller): visible_set is ANDed in — agent-C stays dropped") {
        const auto scan = acc.routes.gather_tar_retention_paused(kUser, gate_scope);
        bool found_c = false;
        for (const auto& r : scan.rows) if (r.agent_id == "agent-C") found_c = true;
        CHECK_FALSE(found_c); // agent-C: in gate_scope, but not a direct member — dropped
        CHECK(scan.agents_filtered_out_of_scope >= 1);
    }

    SECTION("REST/MCP twins: extra_scope is the sole filter — agent-C is included") {
        const auto scan =
            acc.routes.gather_tar_retention_paused(kUser, gate_scope, /*extra_scope_is_authoritative=*/true);
        bool found_c = false;
        for (const auto& r : scan.rows) if (r.agent_id == "agent-C") found_c = true;
        CHECK(found_c); // was silently dropped pre-fix despite being gate-authorized
    }
}

TEST_CASE("render_tar_retention_paused: paused_at==0 sorts oldest with schema badge (#558)",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-legacy", "agent-modern"});

    // Legacy agent: disabled but no paused_at (0) → oldest. Modern agent: a
    // known, recent paused_at. #558 — the legacy (0) row must sort ABOVE the
    // modern one (0 = oldest), inverting the old `0 → INT64_MAX → bottom` bug.
    rs.store(mk_resp("agent-legacy", 10, "config|process_enabled|false\n"));
    rs.store(mk_resp("agent-modern", 10,
                     "config|process_enabled|false\nconfig|process_paused_at|1710000000\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 2, 1);
    const std::string html = acc.render(kUser);

    CHECK(contains(html, "schema older than server")); // legacy badge
    CHECK(contains(html, "badge badge-warning"));
    const auto p_legacy = html.find("agent-legacy");
    const auto p_modern = html.find("agent-modern");
    REQUIRE(p_legacy != std::string::npos); // both must render, or `<` false-passes
    REQUIRE(p_modern != std::string::npos);
    CHECK(p_legacy < p_modern); // 0 = oldest = first
}

TEST_CASE("render_tar_retention_paused: all-collecting fleet renders the clean empty state",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"});

    rs.store(mk_resp("agent-A", 10, "config|process_enabled|true\nconfig|tcp_enabled|true\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 1, 1); // 1 dispatched, 1 responded → "complete and clean"
    const std::string html = acc.render(kUser);

    CHECK(contains(html, "No paused sources detected"));
    CHECK_FALSE(contains(html, "<table>"));
}

TEST_CASE("render_tar_retention_paused: renders the typed-confirm Purge button (15.A)",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"});

    rs.store(mk_resp("agent-A", 10,
                     "config|process_enabled|false\nconfig|process_paused_at|1710000000\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 1, 1);
    const std::string html = acc.render(kUser);

    // The destructive Purge button uses a typed-hostname confirm (tarPurgeConfirm,
    // a native prompt — CSP-safe) with data-* attributes, not hx-confirm.
    CHECK(contains(html, "Purge data"));
    CHECK(contains(html, "btn-danger"));
    CHECK(contains(html, "onclick=\"tarPurgeConfirm(this)\""));
    CHECK(contains(html, "data-source=\"process\""));
    CHECK(contains(html, "data-device=\"agent-A\"")); // POST device_id
    CHECK(contains(html, "data-host=\"agent-A\""));    // typed-confirm target (hostname)
    // Re-enable stays alongside it.
    CHECK(contains(html, "Re-enable"));
}

TEST_CASE("render_tar_retention_paused: row actions gate on effective permission (15.A LOW)",
          "[pg][server][tar][retention-render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"});
    rs.store(mk_resp("agent-A", 10, "config|process_enabled|false\n"));

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&rs, &mg);
    acc.set_scan(kUser, kScan, 1, 1);

    // Execute but NOT Delete: Re-enable renders, Purge is withheld (the POST route
    // stays authoritative; this only removes a button the operator can't use).
    {
        const std::string html = acc.render(kUser, /*can_execute=*/true, /*can_delete=*/false);
        CHECK(contains(html, "Re-enable"));
        CHECK_FALSE(contains(html, "Purge data"));
        CHECK_FALSE(contains(html, "btn-danger"));
    }
    // Delete but not Execute: Purge renders, Re-enable withheld.
    {
        const std::string html = acc.render(kUser, /*can_execute=*/false, /*can_delete=*/true);
        CHECK(contains(html, "Purge data"));
        CHECK_FALSE(contains(html, "Re-enable"));
    }
    // Neither: no destructive controls at all.
    {
        const std::string html = acc.render(kUser, /*can_execute=*/false, /*can_delete=*/false);
        CHECK_FALSE(contains(html, "Purge data"));
        CHECK_FALSE(contains(html, "Re-enable"));
    }
}

TEST_CASE("render_tar_retention_paused: no scan yet renders the placeholder",
          "[server][tar][retention-render]") {
    DashboardTarRetentionTestAccess acc;
    // No stores wired, no scan recorded for this user.
    const std::string html = acc.render("nobody");
    CHECK(contains(html, "No scan data yet"));
}

// #2691 (Doomgoose finding #7): a degraded response-store read must not
// render as "every collector is running normally" or "scan still in
// progress" — both are false claims about fleet state when the read simply
// failed.
TEST_CASE("render_tar_retention_paused: a degraded store read renders the "
          "degrade banner not the clean-fleet claim",
          "[pg][server][tar][retention-render]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    grant_visibility(mg, {"agent-A"});

    DashboardTarRetentionTestAccess acc;
    acc.set_stores(&bad_rs, &mg);
    acc.set_scan(kUser, kScan, 1, 1); // scan recorded so the read is reached
    const std::string html = acc.render(kUser);

    CHECK(contains(html, "result-degrade-banner"));
    CHECK(contains(html, "Retention state unavailable"));
    CHECK_FALSE(contains(html, "No paused sources detected"));
    CHECK_FALSE(contains(html, "still in progress"));
}

} // namespace yuzu::server
