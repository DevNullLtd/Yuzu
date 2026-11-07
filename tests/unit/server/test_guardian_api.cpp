/**
 * test_guardian_api.cpp — the NINTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4). `LocalGuardianApi`
 * (guardian_api.cpp) is a thin wrap of `GuaranteedStateStore::list_rules`/
 * `get_rule`/`query_events` and the five shared `guardian_model.hpp`
 * functions — each wrapped call's own behaviour is already covered by
 * `test_guaranteed_state_store.cpp`/`test_baseline_store.cpp` (the store
 * layer) and `test_guardian_routes.cpp`/`test_rest_guaranteed_state.cpp`
 * (the model-function computation), so this file proves only the WIRING:
 * that the seam forwards each call unmodified and returns the underlying
 * result unmodified, through the public `GuardianApi` interface —
 * `LocalGuardianApi` is deliberately private to guardian_api.cpp, so this
 * file uses only `make_local_guardian_api`, matching how a real
 * presentation/MCP caller will use it.
 */

#include "guardian_api_local.hpp"

#include "baseline_store.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_events_table_lock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <format>
#include <memory>
#include <string>
#include <vector>

using yuzu::server::BaselineStore;
using yuzu::server::GuaranteedStateEventQuery;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateRuleRow;
using yuzu::server::GuaranteedStateStore;
using yuzu::server::GuardianReadFault;
using yuzu::server::make_local_guardian_api;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated templates (see PgTestTemplate in test_helpers.hpp) — SAME
// shared keys ("guardianstate"/"baselinestore") and setup-callback shape as
// test_guaranteed_state_store.cpp / test_baseline_store.cpp /
// test_rest_guaranteed_state.cpp, so the shared-key replay verification
// passes rather than failing on a divergent setup callback for the same key.
// GuaranteedStateStore and BaselineStore are independent schemas — SEPARATE
// clones/pools, mirroring test_rest_guaranteed_state.cpp's RestGsHarness.
yuzu::test::PgTestTemplate guardianstate_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

yuzu::test::PgTestTemplate baselinestore_tpl{"baselinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    BaselineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("baselinestore template: store failed to migrate");
}};

GuaranteedStateRuleRow make_rule(std::string rule_id, std::string name) {
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
    r.created_at = "2026-04-19T12:00:00Z";
    r.updated_at = "2026-04-19T12:00:00Z";
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

GuaranteedStateEventRow make_event(std::string event_id, std::string rule_id,
                                   std::string agent_id) {
    GuaranteedStateEventRow e;
    e.event_id = std::move(event_id);
    e.rule_id = std::move(rule_id);
    e.agent_id = std::move(agent_id);
    e.event_type = "drift.detected";
    e.severity = "high";
    e.guard_type = "registry";
    e.guard_category = "event";
    e.timestamp = "2026-04-19T12:00:00Z";
    return e;
}

// ── #7217 helpers: raw rows, a deployed Baseline, and a table lock for the timeout arm ──

constexpr const char* kGsSchema = "guaranteed_state_store";

void exec_sql(const std::string& dsn, const std::string& sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// A retained pending event with NO census row: written raw so nothing projects it.
void raw_pending(const std::string& dsn, const std::string& agent, const std::string& rule) {
    exec_sql(dsn, std::format("INSERT INTO {}.guaranteed_state_events (event_id, rule_id, agent_id, "
                              "event_type, severity, timestamp, proj_key, projection_pending) "
                              "VALUES ('up-{}-{}', '{}', '{}', 'guard.compliant', 'high', 't', 100, "
                              "true)",
                              kGsSchema, agent, rule, rule, agent));
}

// The census row a repair would have written for the pair (idempotent).
void raw_census(const std::string& dsn, const std::string& agent, const std::string& rule) {
    exec_sql(dsn, std::format("INSERT INTO {}.guardian_agent_rule_status (agent_id, rule_id, state, "
                              "updated_at) VALUES ('{}', '{}', 'compliant', 't') "
                              "ON CONFLICT (agent_id, rule_id) DO NOTHING",
                              kGsSchema, agent, rule));
}

// Create a deployed Baseline whose snapshot is exactly `member_rule_ids`.
void make_deployed_baseline(BaselineStore& baseline_store, const std::string& name,
                            const std::vector<std::string>& member_rule_ids) {
    yuzu::server::Baseline b;
    b.name = name;
    auto bid = baseline_store.create_baseline(b);
    REQUIRE(bid.has_value());
    REQUIRE(baseline_store.set_members(*bid, member_rule_ids).has_value());
    auto deployed = *baseline_store.get_baseline(*bid);
    std::string snap = "[";
    for (std::size_t i = 0; i < member_rule_ids.size(); ++i)
        snap += (i ? ",\"" : "\"") + member_rule_ids[i] + "\"";
    snap += "]";
    deployed.deployed_snapshot = snap;
    deployed.lifecycle = yuzu::server::kBaselineDeployed;
    REQUIRE(baseline_store.update_baseline(deployed).has_value());
}

} // namespace

TEST_CASE("GuardianApi::list_rules: forwards an empty catalogue and returns an honest-empty result",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto rows = api->list_rules();
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("GuardianApi::list_rules / get_rule: a created rule round-trips unmodified through the seam",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    REQUIRE(store.create_rule(make_rule("rule-1", "match-me")).has_value());

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto rows = api->list_rules();
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->at(0).name == "match-me");

    auto found = api->get_rule("rule-1");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->name == "match-me");

    // get_rule is three-state (ADR-0038): a genuinely-absent id is a
    // non-nullopt-carrying, but empty-valued, success — never an error.
    auto missing = api->get_rule("does-not-exist");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());
}

TEST_CASE("GuardianApi::status: forwards the fleet rollup unmodified on an empty catalogue",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto rollup = api->status(std::nullopt);
    REQUIRE(rollup.has_value());
    CHECK(rollup->total_rules == 0);
    CHECK(rollup->errored_rules == 0);
}

TEST_CASE("GuardianApi::agent_status / device_guards: an agent with no census rows is an honest "
          "all-zero result, not an error",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto agent_status = api->agent_status("no-such-agent");
    REQUIRE(agent_status.has_value());
    CHECK(agent_status->total_rules == 0);

    GuardianReadFault fault = GuardianReadFault::kTransient; // non-default: a no-op wrap cannot fake kNone
    auto guards = api->device_guards("no-such-agent", &fault);
    CHECK(fault == GuardianReadFault::kNone);
    REQUIRE(guards.has_value());
    CHECK(guards->guards.empty());
    CHECK(guards->unrepresented_pending_guards == 0);
    CHECK(guards->unrepresented_pending_rule_ids.empty());
}

TEST_CASE("GuardianApi::rule_status: an unknown rule_id is an honest empty census, not an error",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto rows = api->rule_status("does-not-exist");
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("GuardianApi::device_compliance: an unknown baseline name is a genuine miss "
          "(store_degraded stays false), not a store fault",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    bool store_degraded = true; // pre-seed non-default so a no-op wrap can't fake false
    bool pii_access_began = true;
    GuardianReadFault fault = GuardianReadFault::kTransient;
    auto rollup = api->device_compliance("No Such Baseline", "agent-1", &store_degraded,
                                         &pii_access_began, &fault);
    CHECK_FALSE(rollup.has_value());
    CHECK_FALSE(store_degraded);
    CHECK(fault == GuardianReadFault::kNone); // a genuine miss is not a fault of any kind
}

TEST_CASE("GuardianApi::list_events: forwards an empty, plain-vector, non-optional result — the "
          "ADR-0038 \"deferred widening\" asymmetry this seam preserves verbatim",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(&store, &baseline_store);

    std::vector<GuaranteedStateEventRow> rows = api->list_events(GuaranteedStateEventQuery{});
    CHECK(rows.empty());
}

TEST_CASE("GuardianApi::list_events: a real event round-trips unmodified through the seam",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    REQUIRE(store.insert_event(make_event("evt-1", "rule-1", "agent-1")).has_value());

    auto api = make_local_guardian_api(&store, &baseline_store);

    auto rows = api->list_events(GuaranteedStateEventQuery{});
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].event_id == "evt-1");
    CHECK(rows[0].rule_id == "rule-1");
    CHECK(rows[0].agent_id == "agent-1");
}

TEST_CASE("GuardianApi: a null baseline_store degrades ONLY device_compliance — the other seven "
          "methods need no baseline_store at all and stay fully functional",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    REQUIRE(store.create_rule(make_rule("rule-1", "match-me")).has_value());
    REQUIRE(store.insert_event(make_event("evt-1", "rule-1", "agent-1")).has_value());

    auto api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);

    // All seven store-only methods, each asserted functional — a stray
    // baseline_store null-check added to any one of them fails here.
    auto rows = api->list_rules();
    REQUIRE(rows.has_value());
    CHECK(rows->size() == 1);

    auto found = api->get_rule("rule-1");
    REQUIRE(found.has_value());
    CHECK(found->has_value());

    CHECK(api->status(std::nullopt).has_value());
    CHECK(api->agent_status("agent-1").has_value());
    CHECK(api->rule_status("rule-1").has_value());
    GuardianReadFault guards_fault = GuardianReadFault::kTransient;
    CHECK(api->device_guards("agent-1", &guards_fault).has_value());
    CHECK(guards_fault == GuardianReadFault::kNone);
    CHECK(api->list_events(GuaranteedStateEventQuery{}).size() == 1);

    bool store_degraded = false;
    bool pii_access_began = true; // pre-seed non-default so a no-op wrap can't fake false
    GuardianReadFault fault = GuardianReadFault::kNone;
    auto rollup = api->device_compliance("Any Baseline", "agent-1", &store_degraded,
                                         &pii_access_began, &fault);
    CHECK_FALSE(rollup.has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
    CHECK(fault == GuardianReadFault::kTransient);
}

TEST_CASE("GuardianApi: a null guaranteed_state_store degrades every method to its own "
          "unavailable shape (unexpected / nullopt / empty vector)",
          "[guardian_api]") {
    auto api = make_local_guardian_api(/*store=*/nullptr, /*baseline_store=*/nullptr);

    CHECK_FALSE(api->list_rules().has_value());
    CHECK_FALSE(api->get_rule("any").has_value());
    CHECK_FALSE(api->status(std::nullopt).has_value());
    CHECK_FALSE(api->agent_status("any").has_value());
    CHECK_FALSE(api->rule_status("any").has_value());
    GuardianReadFault fault = GuardianReadFault::kNone;
    CHECK_FALSE(api->device_guards("any", &fault).has_value());
    CHECK(fault == GuardianReadFault::kTransient);
    CHECK(api->list_events(GuaranteedStateEventQuery{}).empty());

    bool store_degraded = false;
    bool pii_access_began = true;
    fault = GuardianReadFault::kNone;
    CHECK_FALSE(api->device_compliance("any", "any", &store_degraded, &pii_access_began, &fault)
                    .has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
    CHECK(fault == GuardianReadFault::kTransient);
}

TEST_CASE("GuardianApi: a null guaranteed_state_store with a LIVE baseline_store still degrades "
          "device_compliance — it needs both stores",
          "[pg][guardian_api]") {
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};

    auto api = make_local_guardian_api(/*store=*/nullptr, &baseline_store);

    bool store_degraded = false;
    bool pii_access_began = true; // pre-seed non-default so a no-op wrap can't fake false
    GuardianReadFault fault = GuardianReadFault::kNone;
    auto rollup = api->device_compliance("Any Baseline", "agent-1", &store_degraded,
                                         &pii_access_began, &fault);
    CHECK_FALSE(rollup.has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
    CHECK(fault == GuardianReadFault::kTransient);
}

// ── #7217: read order and degrade kinds ──────────────────────────────────────

// The unrepresented read is issued BEFORE the census read (#7217). The fault seam fires at
// the start of the unrepresented read, so a side effect there that writes the pair's census row
// lands between "before the unrepresented read" and "before the census read" only if the census
// read comes AFTER it: census-first would read no row, then the repair would make the pair
// represented, and the pair would be in NEITHER category.
TEST_CASE("GuardianApi::device_guards: the unrepresented read precedes the census read, so a pair "
          "repaired in between is in guards[] and never in neither",
          "[pg][guardian_api][ordering]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    REQUIRE(store.create_rule(make_rule("r1", "Guard one")).has_value());
    raw_pending(gs_db.dsn(), "agent-1", "r1");
    const std::string dsn = gs_db.dsn();
    store.set_unrepresented_pending_fault_for_test([dsn] {
        raw_census(dsn, "agent-1", "r1"); // the repair
        return false;                      // not a fault: the read proceeds
    });
    auto api = make_local_guardian_api(&store, /*baseline_store=*/nullptr);

    GuardianReadFault fault = GuardianReadFault::kTransient;
    auto report = api->device_guards("agent-1", &fault);
    REQUIRE(report.has_value());
    CHECK(fault == GuardianReadFault::kNone);
    REQUIRE(report->guards.size() == 1);
    CHECK(report->guards[0].rule_id == "r1");
    CHECK(report->unrepresented_pending_guards == 0); // the pair is now represented
    CHECK(report->unrepresented_pending_rule_ids.empty());
}

TEST_CASE("GuardianApi::device_compliance: the unrepresented read precedes the census read, so a "
          "pair repaired in between is in guards[] and never in neither",
          "[pg][guardian_api][ordering]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};
    REQUIRE(store.create_rule(make_rule("r1", "Guard one")).has_value());
    make_deployed_baseline(baseline_store, "B", {"r1"});
    raw_pending(gs_db.dsn(), "agent-1", "r1");
    const std::string dsn = gs_db.dsn();
    store.set_unrepresented_pending_fault_for_test([dsn] {
        raw_census(dsn, "agent-1", "r1");
        return false;
    });
    auto api = make_local_guardian_api(&store, &baseline_store);

    bool store_degraded = true;
    bool pii_access_began = false;
    GuardianReadFault fault = GuardianReadFault::kTransient;
    auto rollup = api->device_compliance("B", "agent-1", &store_degraded, &pii_access_began, &fault);
    REQUIRE(rollup.has_value());
    CHECK_FALSE(store_degraded);
    CHECK(fault == GuardianReadFault::kNone);
    CHECK(rollup->total_guards == 1);
    REQUIRE(rollup->guards.size() == 1);
    CHECK(rollup->guards[0].rule_id == "r1");
    CHECK(rollup->unrepresented_pending_guards == 0);
}

TEST_CASE("GuardianApi: a failed unrepresented read is kTransient on both reads, and the compliance "
          "audit obligation (pii_access_began) is unchanged",
          "[pg][guardian_api][fault]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};
    REQUIRE(store.create_rule(make_rule("r1", "Guard one")).has_value());
    make_deployed_baseline(baseline_store, "B", {"r1"});
    store.set_unrepresented_pending_fault_for_test([] { return true; });
    auto api = make_local_guardian_api(&store, &baseline_store);

    GuardianReadFault fault = GuardianReadFault::kNone;
    CHECK_FALSE(api->device_guards("agent-1", &fault).has_value());
    CHECK(fault == GuardianReadFault::kTransient);

    bool store_degraded = false;
    bool pii_access_began = false;
    fault = GuardianReadFault::kNone;
    CHECK_FALSE(api->device_compliance("B", "agent-1", &store_degraded, &pii_access_began, &fault)
                    .has_value());
    CHECK(store_degraded);
    CHECK(pii_access_began); // the Baseline was found before the failed read: audit "failure"
    CHECK(fault == GuardianReadFault::kTransient);

    // A null fault pointer is tolerated (the degrade is still reported through the other signals).
    CHECK_FALSE(api->device_guards("agent-1", nullptr).has_value());
    store_degraded = false;
    CHECK_FALSE(
        api->device_compliance("B", "agent-1", &store_degraded, &pii_access_began, nullptr)
            .has_value());
    CHECK(store_degraded);
}

// SQLSTATE 57014 end to end through the model and the seam: the table lock holds the read past a
// 50 ms budget. The lock is released afterwards and the same store answers a follow-up read, so the
// timeout leaves the pool intact.
TEST_CASE("GuardianApi: a statement timeout of the unrepresented read is kStatementTimeout on both "
          "reads, then the store recovers",
          "[pg][guardian_api][fault][timeout]") {
    YUZU_REQUIRE_PG_DB_TPL(gs_db, guardianstate_tpl);
    PgPool gs_pool{{.conninfo = gs_db.dsn(), .size = 2}};
    GuaranteedStateStore store{gs_pool};
    YUZU_REQUIRE_PG_DB_TPL(bl_db, baselinestore_tpl);
    PgPool bl_pool{{.conninfo = bl_db.dsn(), .size = 2}};
    BaselineStore baseline_store{bl_pool};
    REQUIRE(store.create_rule(make_rule("r1", "Guard one")).has_value());
    make_deployed_baseline(baseline_store, "B", {"r1"});
    store.set_unrepresented_pending_timeout_ms_for_test(50);
    auto api = make_local_guardian_api(&store, &baseline_store);

    {
        yuzu::test::EventsTableLock lock{gs_db.dsn()};

        GuardianReadFault fault = GuardianReadFault::kNone;
        CHECK_FALSE(api->device_guards("agent-1", &fault).has_value());
        CHECK(fault == GuardianReadFault::kStatementTimeout);

        bool store_degraded = false;
        bool pii_access_began = false;
        fault = GuardianReadFault::kNone;
        CHECK_FALSE(
            api->device_compliance("B", "agent-1", &store_degraded, &pii_access_began, &fault)
                .has_value());
        CHECK(store_degraded);
        CHECK(pii_access_began);
        CHECK(fault == GuardianReadFault::kStatementTimeout);
    } // lock released

    // Restore the production budget before the follow-up read.
    store.set_unrepresented_pending_timeout_ms_for_test(5000);
    GuardianReadFault fault = GuardianReadFault::kTransient;
    auto report = api->device_guards("agent-1", &fault);
    REQUIRE(report.has_value());
    CHECK(fault == GuardianReadFault::kNone);
}
