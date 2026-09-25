/**
 * test_chrome_ir_chain.cpp — End-to-end regression net for the scope-walking
 * "composable scope from previous query results" chain (roadmap 15.F, design
 * docs/scope-walking-design.md §10, the Chrome-IR reference walkthrough).
 *
 * Drives the full narrowing chain through the REAL /api/v1/result-sets REST
 * surface (via the in-process TestRouteSink, #438) and asserts the properties
 * 15.F calls for:
 *   • lineage is complete — each narrowing step's parent_id links back to the
 *     set it refined, so GET /{id}/lineage reconstructs the whole chain;
 *   • the audit trail is complete — one result_set.create per step plus the pin;
 *   • pinning prevents mid-incident GC — a pinned set survives gc_sweep() and
 *     cannot be deleted until unpinned;
 *   • the chain terminates cleanly — unpin → delete walks the chain down.
 *
 * Scope notes (kept honest):
 *   • The chain is driven in-process with a REAL ResultSetStore + a FAKE command
 *     dispatch (records args, returns a configurable sent-count) — the same
 *     pattern as test_rest_result_sets_async.cpp. There is no running agent, so
 *     the two async producers (tar_query / instruction_result) land `pending`
 *     and are materialised by calling ResultSetStore::materialize() directly,
 *     standing in for the server's maintenance thread.
 *   • The ground set uses the direct create endpoint as a deterministic stand-in
 *     for the inventory-query producer (which needs an InventoryStore + eval
 *     engine and has its own coverage). This test's value is the chain contract,
 *     not the individual producers.
 *   • The positive "GC removes an expired unpinned set" case is covered at the
 *     store level in test_result_set_store.cpp ([result_set][gc]); a ttl cannot
 *     be back-dated through the public REST API, so here we assert the pinned
 *     set survives a sweep.
 */

#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "result_set_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResultSetStore is now a migrated Postgres store (ADR-0036) — shares the
// "resultset" template key with test_result_set_store.cpp (identical setup:
// construct a ResultSetStore against the pool; the registry builds it once).
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    std::string execution_id;
};

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

// Real ResultSetStore + ExecutionTracker + InstructionStore, in-process route
// dispatch, a recording fake command-dispatch, and an audit sink that captures
// every emitted row. Mirrors AsyncHarness in test_rest_result_sets_async.cpp.
struct ChromeIrHarness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ResultSetStore> store;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instr;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    std::vector<DispatchCall> calls;
    std::vector<AuditRecord> audit_log;
    int dispatch_sent{2}; // agents "reached" by each dispatch

    explicit ChromeIrHarness(pg::PgPool& pool) {
        store = std::make_unique<ResultSetStore>(pool);
        REQUIRE(store->is_open());

        tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());

        // ADR-0058: InstructionStore is now a migrated Postgres store — shares
        // the same pool/database as ResultSetStore above (schema-per-store).
        instr = std::make_unique<InstructionStore>(pool);
        REQUIRE(instr->is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "ir-operator";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        RestApiV1::CommandDispatchFn dispatch_fn =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                   const std::unordered_map<std::string, std::string>& params,
                   const std::string& exec_id,
                   const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back({plugin, action, scope_expr, agent_ids, params, exec_id});
            return {.sent = dispatch_sent, .command_id = "cmd-" + std::to_string(calls.size())};
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, instr.get(),
                            tracker.get(), /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, store.get(), dispatch_fn,
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            // #1788: the async result-set producers now REFUSE
                            // (audited 500) when the visibility derivation is
                            // unwired — it is their only per-device gate. This
                            // file exercises the lineage/audit/GC chain, not
                            // confinement, so wire a derivation that ANSWERS
                            // "unfiltered" (nullopt) rather than leaving it
                            // empty, which is a missing gate and not a synonym.
                            [](const auth::Session&) -> yuzu::server::authz::VisibleSet {
                                return std::nullopt;
                            });
    }

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    nlohmann::json get(const std::string& path, int& status) {
        auto res = sink.dispatch("GET", path, "");
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    nlohmann::json del(const std::string& path, int& status) {
        auto res = sink.dispatch("DELETE", path, "");
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }

    int count_audit(const std::string& action) const {
        int n = 0;
        for (const auto& a : audit_log)
            if (a.action == action)
                ++n;
        return n;
    }
    bool has_audit(const std::string& action, const std::string& target_id) const {
        for (const auto& a : audit_log)
            if (a.action == action && a.target_id == target_id)
                return true;
        return false;
    }
};

std::string make_instruction(InstructionStore& s) {
    InstructionDefinition def;
    def.name = "Chrome hash check";
    def.version = "1.0";
    def.plugin = "filehash";
    def.action = "check";
    def.type = "action";
    def.description = "hash check";
    def.enabled = true;
    auto id = s.create_definition(def);
    REQUIRE(id.has_value());
    return *id;
}

} // namespace

TEST_CASE("chrome-ir: composable-scope chain — lineage, audit, pin-prevents-GC, clean teardown",
          "[pg][result_set][chrome_ir][walkthrough]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ChromeIrHarness h(pool);
    int st = 0;

    // ── Step 1: ground set "all-windows" (inventory-query stand-in via direct create). ──
    auto j1 = h.post(
        "/api/v1/result-sets",
        R"({"name":"all-windows","source_kind":"inventory_query","device_ids":["win-1","win-2","win-3"]})",
        st);
    REQUIRE(st == 201);
    const auto rs1 = j1["data"]["id"].get<std::string>();
    CHECK(j1["data"]["status"] == "materialized");
    CHECK(j1["data"]["device_count"] == 3);

    // ── Step 2: narrow within rs1 via a TAR SQL query → pending; then materialise
    //            (two agents returned ≥1 row). Dispatch must be scoped to the parent set. ──
    const std::string b2 =
        std::string(
            R"({"name":"windows-chrome-vulnerable","sql":"SELECT pid FROM process_live WHERE name='chrome.exe'","parent_id":")") +
        rs1 + R"("})";
    auto j2 = h.post("/api/v1/result-sets/from-tar-query", b2, st);
    REQUIRE(st == 202);
    const auto rs2 = j2["data"]["id"].get<std::string>();
    CHECK(j2["data"]["status"] == "pending");
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls.back().plugin == "tar");
    CHECK(h.calls.back().scope_expr == "from_result_set:" + rs1); // scoped to the parent set
    REQUIRE(h.store->materialize(rs2, {"win-1", "win-2"}).has_value());

    // ── Step 3: instruction-result narrow within rs2 (Chrome hash check) with a
    //            column matcher → pending; then materialise to the single bad-hash host. ──
    const auto iid = make_instruction(*h.instr);
    const std::string b3 =
        std::string(R"({"name":"windows-chrome-compromised","instruction_id":")") + iid +
        R"(","params":{"path":"/opt/google/chrome/chrome"},"matcher":{"column":"sha256","op":"in","value_set":["badhash"]},"parent_id":")" +
        rs2 + R"("})";
    auto j3 = h.post("/api/v1/result-sets/from-instruction-result", b3, st);
    REQUIRE(st == 202);
    const auto rs3 = j3["data"]["id"].get<std::string>();
    CHECK(j3["data"]["status"] == "pending");
    REQUIRE(h.store->materialize(rs3, {"win-1"}).has_value());

    // ── Lineage is complete: rs3 walks back through rs2 to the ground rs1. ──
    auto jl = h.get("/api/v1/result-sets/" + rs3 + "/lineage", st);
    REQUIRE(st == 200);
    const auto& chain = jl["data"]["chain"];
    REQUIRE(chain.size() == 3);
    // Root → leaf ordering (ResultSetStore::lineage walks parent_id to the root).
    CHECK(chain[0]["id"] == rs1);
    CHECK(chain[1]["id"] == rs2);
    CHECK(chain[2]["id"] == rs3);

    // ── Materialised membership is readable through the REST surface. ──
    auto jm = h.get("/api/v1/result-sets/" + rs3 + "/members", st);
    REQUIRE(st == 200);
    REQUIRE(jm["data"]["device_ids"].size() == 1);
    CHECK(jm["data"]["device_ids"][0] == "win-1");

    // ── Audit trail is complete: one result_set.create per narrowing step. ──
    CHECK(h.count_audit("result_set.create") == 3);
    CHECK(h.has_audit("result_set.create", rs1));
    CHECK(h.has_audit("result_set.create", rs2));
    CHECK(h.has_audit("result_set.create", rs3));

    // ── Pin the compromised set for the incident. ──
    auto jp = h.post("/api/v1/result-sets/" + rs3 + "/pin", "", st);
    REQUIRE(st == 200);
    CHECK(jp["data"]["pinned"] == true);
    CHECK(h.has_audit("result_set.pin", rs3));

    // ── Pinning prevents mid-incident GC: a sweep removes nothing and rs3 survives. ──
    CHECK(h.store->gc_sweep() == 0);
    auto rs3_row = h.store->get(rs3);
    REQUIRE(rs3_row.has_value());  // no DB error (ADR-0036 std::expected)
    REQUIRE(rs3_row->has_value()); // the row itself is still present

    // ── A pinned set cannot be deleted until it is unpinned. ──
    h.del("/api/v1/result-sets/" + rs3, st);
    CHECK(st == 409);

    // ── Clean teardown: unpin the leaf, then delete the chain leaf → root. ──
    h.post("/api/v1/result-sets/" + rs3 + "/unpin", "", st);
    REQUIRE(st == 200);
    CHECK(h.has_audit("result_set.unpin", rs3));
    for (const auto& id : {rs3, rs2, rs1}) {
        auto jd = h.del("/api/v1/result-sets/" + id, st);
        REQUIRE(st == 200);
        CHECK(jd["data"]["deleted"] == true);
    }

    // ── The chain is gone. ──
    h.get("/api/v1/result-sets/" + rs3, st);
    CHECK(st == 404);
}
