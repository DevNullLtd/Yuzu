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

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::BaselineStore;
using yuzu::server::GuaranteedStateEventQuery;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateRuleRow;
using yuzu::server::GuaranteedStateStore;
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

    auto guards = api->device_guards("no-such-agent");
    REQUIRE(guards.has_value());
    CHECK(guards->empty());
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
    auto rollup = api->device_compliance("No Such Baseline", "agent-1", &store_degraded,
                                         &pii_access_began);
    CHECK_FALSE(rollup.has_value());
    CHECK_FALSE(store_degraded);
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
    CHECK(api->device_guards("agent-1").has_value());
    CHECK(api->list_events(GuaranteedStateEventQuery{}).size() == 1);

    bool store_degraded = false;
    bool pii_access_began = true; // pre-seed non-default so a no-op wrap can't fake false
    auto rollup = api->device_compliance("Any Baseline", "agent-1", &store_degraded,
                                         &pii_access_began);
    CHECK_FALSE(rollup.has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
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
    CHECK_FALSE(api->device_guards("any").has_value());
    CHECK(api->list_events(GuaranteedStateEventQuery{}).empty());

    bool store_degraded = false;
    bool pii_access_began = true;
    CHECK_FALSE(api->device_compliance("any", "any", &store_degraded, &pii_access_began)
                    .has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
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
    auto rollup = api->device_compliance("Any Baseline", "agent-1", &store_degraded,
                                         &pii_access_began);
    CHECK_FALSE(rollup.has_value());
    CHECK(store_degraded);
    CHECK_FALSE(pii_access_began);
}
