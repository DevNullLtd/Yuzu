/**
 * test_rest_result_sets_async.cpp — HTTP-level coverage for the async
 * result-set producers added in scope-walking PR-D:
 *
 *   POST /api/v1/result-sets/from-tar-query
 *   POST /api/v1/result-sets/from-instruction-result
 *   POST /api/v1/result-sets/{id}/re-eval
 *
 * Exercised via the TestRouteSink in-process dispatch pattern (#438) with a
 * REAL ResultSetStore + ExecutionTracker and a FAKE command-dispatch closure
 * that records its arguments and returns a configurable (command_id, sent).
 * The maintenance thread is NOT run here — materialisation is covered by the
 * matcher unit tests; this file asserts the synchronous handler contract:
 * create-before-dispatch ordering, the dispatched scope expression (including
 * alias pre-resolution), the 202 pending shape, the matcher persisted on the
 * row, the no-agents / no-dispatch error paths, and the re-eval sibling rule.
 */

#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "mcp_input_bounds.hpp" // kResultSetParentIdMaxLen / kResultSetNameMaxLen
#include "mcp_retry.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rest_api_v1.hpp"
#include "result_set_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Run a raw SQL statement against the test database on a second connection --
// same idiom as test_result_set_store.cpp's own helper -- lets a test install
// a trigger that simulates a concurrent delete racing heal_poisoned_payload's
// own SELECT/UPDATE pair (#4540).
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// ResultSetStore is now a migrated Postgres store (ADR-0036) — shares the
// "resultset" template key with test_result_set_store.cpp (identical setup).
yuzu::test::PgTestTemplate result_set_tpl{
    "resultset", [](const std::string& dsn) {
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
    /// #1788: the confinement set the handler derived and handed to dispatch.
    ///
    /// Its ABSENCE from this struct is why the fleet-wide escape on these three
    /// routes survived eleven review rounds and an eight-gate governance pass.
    /// The recorder captured plugin/action/scope/ids and nothing about WHO the
    /// caller was allowed to reach, so every assertion in this file stayed
    /// green while the routes dispatched through the system closure with
    /// exec_visible hardcoded to nullopt (unfiltered). A test that cannot
    /// observe the confinement decision cannot fail when it is absent.
    yuzu::server::authz::VisibleSet exec_visible;
};

struct AsyncHarness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ResultSetStore> store;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instr;
    /// #2500: from-inventory-query is the FOURTH instance of the targeting
    /// widening and has its own code path. Its handler 503s before any input
    /// validation when the store is unwired (dependency-before-validation is
    /// the convention on these routes), so reaching its parent_id guard at all
    /// requires a real store. Post-ADR-0037 that store is Postgres-backed, so
    /// the one section that needs it injects a borrowed pointer. The caller
    /// owns the store and must keep it alive longer than this harness.
    InventoryStore* inventory{nullptr};
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    /// Recorded audit events (verb, result, detail) — the unwired-gate refusal
    /// must leave durable evidence, not just a status code.
    struct AuditCall {
        std::string action, result, detail;
    };
    std::vector<AuditCall> audits;
    /// AuditFn return value. false models a lost evidence row, which must
    /// surface as `Sec-Audit-Failed: true` on the response rather than being
    /// swallowed — a refusal nobody can prove happened is not fail-closed.
    bool audit_ok{true};

    // Fake-dispatch knobs / recording.
    std::vector<DispatchCall> calls;
    int dispatch_sent{2}; // agents "reached" by each dispatch
    bool dispatch_throws{false};
    bool wire_dispatch{true}; // false → leave the callback empty (503 path)
    /// #4306 fold-in B: fires INSIDE the fake dispatch closure, between the
    /// (already-passed) pre-dispatch quota check and create_pending's own
    /// INSERT below it — the one point in the request lifecycle where a test
    /// can inject a real Postgres fault that lands strictly AFTER a real
    /// dispatch already fired. A test sets this to take a table lock on a
    /// second raw connection.
    std::function<void()> on_dispatch;
    /// CWE-862: these producers DISPATCH, so they must gate on
    /// Execution:Execute. Set false to model an authenticated caller who
    /// holds no such grant — the case that previously reached the fleet.
    static inline bool permit_exec{true};
    /// guardian-confinement-2298 PR3 §3e: empty ⇒ an ordinary session; a test
    /// sets this to prove a service-scoped token is denied fleet-wide result-
    /// set reach (session->username-keyed, i.e. the MINTER's identity).
    std::string mock_token_scope_service;

    /// #1788: the VisibleSet the wired `exec_visible_fn` returns.
    ///
    /// Default nullopt = genuinely unfiltered authority (a global admin), which
    /// is what the pre-existing cases in this file model. Set to a present set
    /// to model a confined caller — e.g. a service-scoped token.
    yuzu::server::authz::VisibleSet exec_visible_override{};
    /// Leave `exec_visible_fn` EMPTY at registration, modelling a server whose
    /// visibility derivation was never wired. That is NOT a synonym for the
    /// nullopt default above: unwired is a misconfiguration and must be refused
    /// (audited 500), whereas a callback returning nullopt is a real answer
    /// meaning "this caller sees the whole fleet".
    bool wire_exec_visible{true};

    /// #2146 Batch B2 Gate 4 fix: the VisibleSet from-inventory-query's own
    /// `fleet_read_fn` gate returns, independent of `exec_visible_override`
    /// above (a different gate, same shape). Default nullopt = unconfined,
    /// matching every pre-existing test in this file; set to a present set to
    /// prove the confinement fix actually narrows which agents' inventory
    /// rows are visible, not just that the gate is called.
    yuzu::server::authz::VisibleSet fleet_read_scope_override{};

    explicit AsyncHarness(pg::PgPool& pool, bool with_dispatch = true,
                          InventoryStore* inv = nullptr, bool with_exec_visible = true)
        : inventory(inv), wire_dispatch(with_dispatch), wire_exec_visible(with_exec_visible) {
        permit_exec = true; // each harness starts permissive

        store = std::make_unique<ResultSetStore>(pool);
        REQUIRE(store->is_open());

        tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());

        // ADR-0058: InstructionStore is now a migrated Postgres store — shares
        // the same pool/database as the store constructed above it (schema-per-store).
        instr = std::make_unique<InstructionStore>(pool);
        REQUIRE(instr->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "operator-1";
            s.role = auth::Role::admin;
            s.token_scope_service = mock_token_scope_service;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response& r, const std::string&,
                          const std::string&) -> bool {
            if (!permit_exec) {
                r.status = 403;
                return false;
            }
            return true;
        };
        // #2146 Batch B2 review: from-inventory-query moved from a bare perm_fn to the
        // admit-then-filter fleet_read_fn chokepoint. RestApiV1::FleetReadFn defaults to
        // empty ({}), and calling an empty std::function throws bad_function_call - this
        // fake models the same permit_exec-gated denial/admit shape as perm_fn above, so
        // the two from-inventory-query tests below keep their original meaning rather
        // than universally 503ing on an unwired gate.
        RestApiV1::FleetReadFn fleet_read_fn =
            [this](const httplib::Request&, httplib::Response& r, const std::string&,
                   const std::string&) -> yuzu::server::authz::FleetReadGate {
            if (!permit_exec) {
                r.status = 403;
                return {};
            }
            return {.admitted = true, .scope = fleet_read_scope_override};
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string& detail) -> bool {
            audits.push_back({action, result, detail});
            return audit_ok;
        };

        RestApiV1::CommandDispatchFn dispatch_fn;
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids,
                                 const std::string& scope_expr,
                                 const std::unordered_map<std::string, std::string>& params,
                                 const std::string& exec_id,
                                 const yuzu::server::DispatchCaller& caller)
                -> yuzu::server::ConfinedDispatchOutcome {
                calls.push_back(
                    {plugin, action, scope_expr, agent_ids, params, exec_id, caller.exec_visible});
                if (dispatch_throws)
                    throw std::runtime_error("simulated dispatch failure");
                if (on_dispatch)
                    on_dispatch();
                return {.sent = dispatch_sent, .command_id = "cmd-" + std::to_string(calls.size())};
            };
        }

        RestApiV1::ExecVisibleFn exec_visible_fn;
        if (wire_exec_visible) {
            exec_visible_fn = [this](const auth::Session&) -> yuzu::server::authz::VisibleSet {
                return exec_visible_override;
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, instr.get(),
                            tracker.get(), /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, inventory,
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
                            /*stream_budget=*/nullptr, exec_visible_fn,
                            /*list_read_fn=*/{}, fleet_read_fn);
    }

    /// Header value from the most recent `post`, "" if absent. Kept so a test
    /// can assert `Sec-Audit-Failed` without every call site switching to the
    /// raw response.
    std::string last_sec_audit_failed;

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        last_sec_audit_failed = res->get_header_value("Sec-Audit-Failed");
        return nlohmann::json::parse(res->body, nullptr, false);
    }

    // Seed a materialized set directly in the store (a "ground" set to parent
    // off / re-eval alias targets).
    std::string seed_materialized(const std::string& name,
                                  const std::vector<std::string>& members) {
        CreateRequest cr;
        cr.owner_principal = "operator-1";
        cr.name = name;
        cr.source_kind = std::string(source_kind::kManualCurate);
        cr.source_payload = "{}";
        auto r = store->create_materialized(cr, members);
        REQUIRE(r.has_value());
        return r->id;
    }
};

// Unwrap ResultSetStore::get's std::expected<optional<...>,...> (ADR-0036) —
// every call below hits a live, healthy Postgres, so a DbError here is a
// genuine test-infrastructure failure; REQUIRE it away and hand back the
// plain optional these tests were written against.
std::optional<ResultSet> get_ok(ResultSetStore& s, const std::string& id) {
    auto r = s.get(id);
    REQUIRE(r.has_value());
    return *r;
}

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

// A valid JSON value nested `depth` levels deep, built as a flat bracket
// chain ("[[[...]]]") rather than a constructed nlohmann::json object.
// json-dump-depth-guard fix: kMcpMaxJsonDepth is 32, and the REAL attack
// depth this guard exists for is roughly 100,000 levels - many orders of
// magnitude past what any test here should ever build. depth values in the
// tens (as used below) are trivially safe to construct and dump() directly
// in this test process; this helper exists so no test accidentally reaches
// for a constructed nlohmann::json object at a dangerous depth instead.
std::string nested_array(int depth) {
    return std::string(static_cast<std::size_t>(depth), '[') +
          std::string(static_cast<std::size_t>(depth), ']');
}

} // namespace

TEST_CASE("from-tar-query: 202 pending, dispatch to __all__ when no parent",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT pid FROM process_live","name":"chrome-procs"})", status);
    REQUIRE(status == 202);
    auto data = j["data"];
    REQUIRE(data["status"] == "pending");
    REQUIRE(data["source_kind"] == "tar_query");
    REQUIRE_FALSE(data["source_execution_id"].get<std::string>().empty());

    // Dispatch happened with tar/sql, an EXPLICIT `__all__` scope, sql param.
    // This case's name always said `__all__`; the assertion used to be
    // `scope_expr.empty()`, because empty was the proxy for broadcast at the
    // dispatch sink. #2500 inverted that default — empty now reaches nobody —
    // so the producer names the broadcast and the assertion finally matches
    // the name it has had all along.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "tar");
    REQUIRE(h.calls[0].action == "sql");
    REQUIRE(h.calls[0].scope_expr == "__all__");
    REQUIRE(h.calls[0].params.at("sql") == "SELECT pid FROM process_live");
    // execution_id was minted BEFORE dispatch (create-before-dispatch).
    REQUIRE(h.calls[0].execution_id == data["source_execution_id"].get<std::string>());

    // The row landed pending with the default tar matcher.
    auto row = get_ok(*h.store, data["id"].get<std::string>());
    REQUIRE(row.has_value());
    REQUIRE(row->status == ResultSetStatus::Pending);
    REQUIRE(row->matcher.find("tar_rows_ge") != std::string::npos);
}

TEST_CASE("from-tar-query: parent_id scopes dispatch via from_result_set:",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("win-fleet", {"a1", "a2"});
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + parent);
    // Lineage: the new set's parent is the seeded set.
    auto row = get_ok(*h.store, j["data"]["id"].get<std::string>());
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == parent);
}

TEST_CASE("from-tar-query: parent alias is pre-resolved to canonical id",
          "[pg][result_set][async][tar][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto canonical = h.seed_materialized("my-alias", {"a1"});
    int status = 0;
    // parent_id given as the human alias, not the rs_ id.
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":"my-alias"})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + canonical);
    REQUIRE(*get_ok(*h.store, j["data"]["id"].get<std::string>())->parent_id == canonical);
}

TEST_CASE("from-tar-query: unknown parent alias 404s, no dispatch",
          "[pg][result_set][async][tar][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT 1","parent_id":"nonexistent-alias"})", status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: include_empty selects the any_response matcher",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","include_empty":true})", status);
    REQUIRE(status == 202);
    REQUIRE(get_ok(*h.store, j["data"]["id"].get<std::string>())->matcher.find("any_response") !=
            std::string::npos);
}

// #2146 Batch B2 Gate 4 unhappy-path fix: .value() throws nlohmann::json::
// type_error on a type mismatch rather than coercing - a non-boolean
// include_empty must be a clean 400, never an uncaught exception (matches
// MCP's identical fix on the same field, same handler shape).
TEST_CASE("from-tar-query: a non-boolean include_empty is refused with 400, never an "
          "uncaught nlohmann::json::type_error",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT 1","include_empty":"yes"})", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
}

TEST_CASE("from-tar-query: missing sql is 400, no dispatch", "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"name":"x"})", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: a type-mismatched sql is refused with 400, never an "
          "uncaught nlohmann::json::type_error",
          "[pg][result_set][async][tar][security][4406]") {
    // #4406 fix: body.value("sql", "") threw on a non-string sql rather than
    // coercing. Same guard shape as the pre-existing include_empty check
    // above, now applied to sql too.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query", R"({"sql":12345})", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("'sql' is required") != std::string::npos);
}

TEST_CASE("from-tar-query: a type-mismatched name is refused with 400, never an "
          "uncaught nlohmann::json::type_error",
          "[pg][result_set][async][tar][security][4406]") {
    // Adversarial-review finding: body.value("name", "") at the run_async call
    // site threw the same way sql/instruction_id did before #4406's fix -
    // missed in the first pass because name is passed inline as an argument,
    // not extracted into a named local like the other guarded fields.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j =
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","name":123})", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("name must be a JSON string") !=
          std::string::npos);
}

TEST_CASE("from-tar-query: an oversized name is refused with 400, never dispatched",
          "[pg][result_set][async][tar][security]") {
    // PR review finding: same missing kResultSetNameMaxLen length cap as
    // the generic create route's own oversized-name test.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["sql"] = "SELECT 1";
    body["name"] = std::string(257, 'n');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query", body.dump(), status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("name must be at most 256 bytes") !=
          std::string::npos);
}

TEST_CASE("#2500 — a supplied parent_id that names no parent is refused, not widened",
          "[pg][result_set][async][tar][targeting][security]") {
    // PG-port note (merge of #2500's dev-side case into the ADR-0036 branch):
    // the harness is now Postgres-backed, so the fixture preamble matches the
    // sibling cases and the case carries [pg] (shard-partition invariant —
    // it SKIPs without a DSN via YUZU_REQUIRE_PG_DB_TPL).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // parent_id IS the targeting argument on this route: present and non-empty
    // scopes the dispatch to that set's members via `from_result_set:`, absent
    // broadcasts to every connected agent. The guard used to be
    // `contains && is_string && !empty`, so a SUPPLIED parent_id that was
    // numeric or empty fell through to the untargeted arm — a caller who
    // believed it was narrowing to one result set dispatched to the whole
    // fleet instead. Same shape as the agent_ids defect on the two routes
    // #2500 names; found while auditing this call site for that fix.
    //
    // `h.calls.empty()` is the assertion that matters: a 400 that still
    // dispatched would leave the widening intact behind a better status code.
    SECTION("numeric parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":123})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("empty-string parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":""})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("explicit null parent_id") {
        // Rejected rather than read as "absent". A client that serialises an
        // unset field as null and one whose parent lookup returned nothing are
        // indistinguishable here, and only one of them wants the entire fleet.
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":null})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("the refusal is counted and audited, not just returned") {
        // Governance found the first version of this guard emitted neither, so
        // the third and fourth instances of the defect class were invisible to
        // the alert the change ships. The reason label names the field that was
        // actually wrong: an earlier version reused `scope_empty`, which put a
        // field the caller never sent into the audit trail.
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":123})",
               status);
        REQUIRE(status == 400);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "result_set_parent"}, {"reason", "parent_id_type"}})
                  .value() == 1.0);
    }
    SECTION("from-inventory-query — the fourth instance, its own code path") {
        // Not covered by the run_async guard: this producer has its own
        // parent_id block and was missed by the first round of the fix. It is
        // synchronous, so the consequence was a READ across every device rather
        // than a dispatch — narrower blast radius, same defect. Construct the
        // inventory dependency only in this section; the invalid parent is
        // rejected before the handler performs an inventory query.
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        h.post("/api/v1/result-sets/from-inventory-query", R"({"query":"os=linux","parent_id":""})",
               status);
        REQUIRE(status == 400);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "result_set_parent"}, {"reason", "parent_id_empty"}})
                  .value() == 1.0);
    }
    SECTION("from-inventory-query refuses a byte-capped read without creating a set") {
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) "
            "VALUES ('byte-agent', 'custom_large', repeat('x', 8388609), 1)",
            std::vector<std::string>{});
        REQUIRE(seeded.status() == PGRES_COMMAND_OK);
        lease.reset();

        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        auto query = h.post("/api/v1/inventory/query", R"({"limit":10})", status);
        REQUIRE(status == 200);
        CHECK(query["result_truncated_by_cap"] == true);
        REQUIRE(query["data"].is_array());
        CHECK(query["data"].empty());

        h.post("/api/v1/result-sets/from-inventory-query", R"({"name":"must-not-exist"})",
               status);
        REQUIRE(status == 503);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("from-inventory-query rejects an oversized conditions[] array before "
            "evaluating it, never creates a set") {
        // Gate 8 fix (#2146 Batch B2 follow-up): the kMaxInventoryConditions
        // pre-check itself had no red->green coverage - only the underlying
        // evaluate_inventory() backstop was implicitly reachable. This proves
        // the REST twin's own 400 fires, not merely that a huge array doesn't
        // crash the process.
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        nlohmann::json conditions = nlohmann::json::array();
        for (int i = 0; i < 501; ++i)
            conditions.push_back({{"plugin", "p"}, {"field", "f"}, {"op", "eq"}, {"value", "v"}});
        nlohmann::json body;
        body["name"] = "must-not-exist";
        body["conditions"] = conditions;
        int status = 0;
        h.post("/api/v1/result-sets/from-inventory-query", body.dump(), status);
        REQUIRE(status == 400);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("a non-object body is refused, not read as an absent parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"(["sql"])", status);
        REQUIRE(status == 400);
        CHECK(h.calls.empty());
    }
    SECTION("omitting parent_id still broadcasts — the over-broadness guard") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
        REQUIRE(status == 202);
        REQUIRE(h.calls.size() == 1);
        REQUIRE(h.calls[0].scope_expr == "__all__");
    }
}

// #4734: the shared run_async engine had no length bound on parent_id at
// all -- an oversized value was copied verbatim into the persisted
// source_payload's scope_input_id (both producer routes' own
// payload["scope_input_id"] = ... lines) with no cap, and the request
// otherwise proceeded through resolve_owned_parent/dispatch. Both producers
// funnel through the same run_async closure, so one fix covers both -
// exercised here on both routes to pin that.
TEST_CASE("#4734 — an oversized parent_id is refused before dispatch, on all three "
          "affected routes",
          "[pg][result_set][async][security][4734]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    const std::string big(65, 'p');
    const std::string exact(yuzu::server::mcp::kResultSetParentIdMaxLen, 'p');

    SECTION("from-tar-query") {
        AsyncHarness h(pool);
        int status = 0;
        nlohmann::json body;
        body["sql"] = "SELECT 1";
        body["parent_id"] = big;
        auto j = h.post("/api/v1/result-sets/from-tar-query", body.dump(), status);
        REQUIRE(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") != std::string::npos);
        REQUIRE(h.calls.empty());
    }
    SECTION("from-tar-query -- exactly 64 bytes clears the length cap (boundary, "
            "404s on ownership since it's a random unowned id, but never the "
            "length-cap 400)") {
        AsyncHarness h(pool);
        int status = 0;
        nlohmann::json body;
        body["sql"] = "SELECT 1";
        body["parent_id"] = exact;
        auto j = h.post("/api/v1/result-sets/from-tar-query", body.dump(), status);
        REQUIRE(status == 404);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") == std::string::npos);
        REQUIRE(h.calls.empty());
    }
    SECTION("from-instruction-result") {
        AsyncHarness h(pool);
        auto iid = make_instruction(*h.instr);
        int status = 0;
        nlohmann::json body;
        body["instruction_id"] = iid;
        body["parent_id"] = big;
        auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
        REQUIRE(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") != std::string::npos);
        REQUIRE(h.calls.empty());
    }
    SECTION("from-instruction-result -- exactly 64 bytes clears the length cap "
            "(boundary)") {
        AsyncHarness h(pool);
        auto iid = make_instruction(*h.instr);
        int status = 0;
        nlohmann::json body;
        body["instruction_id"] = iid;
        body["parent_id"] = exact;
        auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
        REQUIRE(status == 404);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") == std::string::npos);
        REQUIRE(h.calls.empty());
    }
    SECTION("from-inventory-query -- a fifth site the #4307 brief didn't name, found "
            "while verifying the other four: this REST route had no parent_id length "
            "bound at all (its MCP twin already checks it), so an oversized value was "
            "copied verbatim into the persisted body[\"scope_input_id\"]") {
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        nlohmann::json body;
        body["name"] = "must-not-exist";
        body["conditions"] = nlohmann::json::array(
            {{{"plugin", "os_info"}, {"field", "platform"}, {"op", "=="}, {"value", "linux"}}});
        body["parent_id"] = big;
        auto j = h.post("/api/v1/result-sets/from-inventory-query", body.dump(), status);
        REQUIRE(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") != std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("from-inventory-query -- exactly 64 bytes clears the length cap "
            "(boundary, 404s on ownership)") {
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        nlohmann::json body;
        body["name"] = "must-not-exist";
        body["conditions"] = nlohmann::json::array(
            {{{"plugin", "os_info"}, {"field", "platform"}, {"op", "=="}, {"value", "linux"}}});
        body["parent_id"] = exact;
        auto j = h.post("/api/v1/result-sets/from-inventory-query", body.dump(), status);
        REQUIRE(status == 404);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") == std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
}

// #4734 alias-length regression: `parent_id` accepts either a canonical
// `rs_...` id or a per-operator alias (the set's own `name`, valid up to
// kResultSetNameMaxLen == 256 bytes). The new 64-byte kResultSetParentIdMaxLen
// bound is checked BEFORE alias resolution is attempted, so a real,
// previously-working alias between 65 and 256 bytes is now refused rather
// than resolved. This is the actual behaviour-changing case the fix
// introduces (see changelog.d and docs/user-manual/server-admin.md's vNEXT
// entry) -- it had zero test coverage until now.
TEST_CASE("from-tar-query: a real alias longer than 64 bytes is refused before "
          "resolution is attempted (the #4734 alias-length regression)",
          "[pg][result_set][async][tar][alias][4734]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    const std::string long_alias(100, 'n');
    h.seed_materialized(long_alias, {"a1"});

    int status = 0;
    nlohmann::json body;
    body["sql"] = "SELECT 1";
    body["parent_id"] = long_alias;
    auto j = h.post("/api/v1/result-sets/from-tar-query", body.dump(), status);
    REQUIRE(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("parent_id must be at most 64 bytes") !=
          std::string::npos);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: zero agents reached is 503, execution cancelled, no pending row",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    h.dispatch_sent = 0; // dispatch reaches nobody
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
    REQUIRE(h.calls.size() == 1); // dispatch was attempted
    // No pending set persisted (the operator gets a clean failure, not a row
    // that idles to the timeout).
    std::string next;
    REQUIRE(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: dispatch throw is 500, execution cancelled",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    h.dispatch_throws = true;
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 500);
    std::string next;
    REQUIRE(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: 503 when command dispatch is unwired", "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool, /*with_dispatch=*/false);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
}

TEST_CASE("from-instruction-result: 202 pending with operator matcher persisted",
          "[pg][result_set][async][instruction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    int status = 0;
    std::string body =
        R"({"instruction_id":")" + iid +
        R"(","params":{"path":"/x"},"matcher":{"column":"sha256","op":"in","value_set":["bad"]}})";
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body, status);
    REQUIRE(status == 202);
    REQUIRE(j["data"]["source_kind"] == "instruction_result");
    // Dispatch used the definition's plugin/action and the params.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "filehash");
    REQUIRE(h.calls[0].action == "check");
    REQUIRE(h.calls[0].params.at("path") == "/x");
    // The operator's column matcher is stored verbatim on the pending row.
    auto row = get_ok(*h.store, j["data"]["id"].get<std::string>());
    REQUIRE(row->matcher.find("sha256") != std::string::npos);
    REQUIRE(row->matcher.find("value_set") != std::string::npos);
}

TEST_CASE("from-instruction-result: unknown instruction_id 404s",
          "[pg][result_set][async][instruction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result", R"({"instruction_id":"does-not-exist"})",
           status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-instruction-result: a type-mismatched instruction_id is refused with "
          "400, never an uncaught nlohmann::json::type_error",
          "[pg][result_set][async][instruction][security][4406]") {
    // #4406 fix: body.value("instruction_id", "") threw on a non-string
    // instruction_id rather than coercing - it now falls through to the
    // pre-existing "is required" 400, same as an absent field.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j =
        h.post("/api/v1/result-sets/from-instruction-result", R"({"instruction_id":12345})", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("'instruction_id' is required") !=
          std::string::npos);
}

TEST_CASE("from-instruction-result: a type-mismatched name is refused with 400, "
          "never an uncaught nlohmann::json::type_error",
          "[pg][result_set][async][instruction][security][4406]") {
    // Adversarial-review finding, same as from-tar-query's sibling test above.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    body["name"] = 123;
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("name must be a JSON string") !=
          std::string::npos);
}

TEST_CASE("from-instruction-result: an oversized name is refused with 400, never "
          "dispatched",
          "[pg][result_set][async][instruction][security]") {
    // PR review finding: same missing kResultSetNameMaxLen length cap as
    // the generic create route's own oversized-name test.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    body["name"] = std::string(257, 'n');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    CHECK(j["error"]["message"].get<std::string>().find("name must be at most 256 bytes") !=
          std::string::npos);
}

TEST_CASE("from-instruction-result: a non-object params is refused with 400, not "
          "silently dispatched with an empty params map",
          "[pg][result_set][async][instruction][security][4373]") {
    // Gate 4 unhappy-path fix: params gated on is_object() skipped every
    // bound check AND the params-map-build loop, so a string/array/number
    // params silently dispatched with an EMPTY map while persisting the
    // wrong-shaped value verbatim and unbounded.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    body["params"] = std::string(4 * 1024 * 1024 - 100, 'A');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("'params' must be a JSON object") !=
            std::string::npos);
}

// #4373-class fix, sibling-handler closure (flagged by governance Gate 2's
// mandatory sibling-handler sweep, PR#4373 follow-on): from-instruction-result
// had NO bound at all on instruction_id/params at creation time, unlike
// re-eval which this PR bounds against a stored payload - closing that
// smuggle-then-reeval path left the DIRECT one-step path open. These four
// mirror re-eval's own bound-check coverage; each asserts the specific
// message, since a bare 400+no-dispatch alone doesn't distinguish the NEW
// bound check from the pre-existing "unknown instruction_id" 404 fallback's
// neighbouring 400 paths (missing/empty instruction_id, invalid JSON).

TEST_CASE("from-instruction-result: an oversized instruction_id is refused, "
          "never dispatched",
          "[pg][result_set][async][instruction][security][4373]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["instruction_id"] = std::string(257, 'q');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("must be at most 256 bytes") !=
            std::string::npos);
}

TEST_CASE("from-instruction-result: a 256-byte instruction_id passes the "
          "length guard and reaches the not-found fallback",
          "[pg][result_set][async][instruction][security][4373]") {
    // The 256-byte boundary itself must be ACCEPTED (only >256 is rejected,
    // per kInstructionIdMaxLen) - but InstructionStore caps a real
    // definition id at 128 characters, so no registered instruction can
    // ever be 256 bytes long. Proving acceptance-at-the-boundary therefore
    // means proving the length check did NOT fire (no "must be at most 256
    // bytes" message) and the request instead reaches the pre-existing
    // INSTRUCTION_NOT_FOUND 404, not that it dispatched.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["instruction_id"] = std::string(256, 'q');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("must be at most 256 bytes") ==
            std::string::npos);
    REQUIRE(j["error"]["message"].get<std::string>().find("INSTRUCTION_NOT_FOUND") !=
            std::string::npos);
}

TEST_CASE("from-instruction-result: an over-keyed params object is refused, "
          "never dispatched",
          "[pg][result_set][async][instruction][security][4373]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    nlohmann::json params = nlohmann::json::object();
    for (int i = 0; i < 33; ++i)
        params[std::format("k{}", i)] = "v";
    body["params"] = params;
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("params must have at most 32 keys") !=
            std::string::npos);
}

TEST_CASE("from-instruction-result: an oversized params key is refused, "
          "never dispatched",
          "[pg][result_set][async][instruction][security][4373]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    body["params"] = {{std::string(257, 'k'), "v"}};
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("a params key exceeds 256 bytes") !=
            std::string::npos);
}

TEST_CASE("from-instruction-result: an oversized params value is refused, "
          "never dispatched",
          "[pg][result_set][async][instruction][security][4373]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    body["params"] = {{"path", std::string(65537, 'z')}};
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("a params value exceeds 65536 bytes") !=
            std::string::npos);
}

TEST_CASE("from-instruction-result: exact-boundary params are accepted and dispatched",
          "[pg][result_set][async][instruction][security][4373]") {
    // Scoped to params (32 keys, each key/value padded to its exact byte
    // cap) - a real registered instruction_id is a short generated string,
    // never anywhere near the 256-byte instruction_id cap, so that
    // boundary isn't exercisable on the accept side without a test-only
    // custom-id seam InstructionStore doesn't have. The reject side
    // (257 bytes, above) plus the `>` (never `>=`) comparator already
    // prove that boundary.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json body;
    body["instruction_id"] = iid;
    nlohmann::json params = nlohmann::json::object();
    for (int i = 0; i < 32; ++i)
        // Fixed-width numeric prefix ("k000".."k031") keeps every key unique
        // before the 'x' fill pads it to the exact 256-byte cap - a '0' fill
        // on a bare "k{}" would collide (e.g. "k1"+zeros == "k10"+zeros),
        // silently shrinking this to fewer than 32 distinct keys.
        params[std::format("{:x<256}", std::format("k{:03d}", i))] = std::string(65536, 'v');
    REQUIRE(params.size() == 32);
    body["params"] = params;
    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result", body.dump(), status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
}

TEST_CASE("re-eval: tar_query set re-dispatches as a sibling (shares parent)",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto grandparent = h.seed_materialized("ground", {"a1", "a2"});
    int status = 0;
    // Original tar_query parented at `grandparent`.
    auto orig = h.post("/api/v1/result-sets/from-tar-query",
                       R"({"sql":"SELECT 7","parent_id":")" + grandparent + R"("})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    h.calls.clear();

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 202);
    auto new_id = re["data"]["id"].get<std::string>();
    REQUIRE(new_id != orig_id);
    // Re-dispatched the original SQL.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].params.at("sql") == "SELECT 7");
    // #4306: the still-live parent narrows the re-dispatch, not a broadcast.
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + grandparent);
    // Sibling: new set's parent == original's parent (NOT the original).
    auto row = get_ok(*h.store, new_id);
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == grandparent);
}

TEST_CASE("re-eval: a genuinely parentless original still broadcasts (no regression)",
          "[pg][result_set][async][reeval][4306]") {
    // Positive control for the #4306 fix: an original that was NEVER narrowed
    // at creation (no parent_id supplied, so no scope_input_id was ever
    // persisted) must still broadcast on re-eval, unchanged. Omitting a
    // parent_id is deliberately "the whole fleet" everywhere else on this
    // route family; the parent-gone refusal must not widen to cover this case.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto orig = h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    REQUIRE_FALSE(get_ok(*h.store, orig_id)->parent_id.has_value());
    h.calls.clear();

    int rstat = 0;
    h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].scope_expr == "__all__");
}

TEST_CASE("re-eval: refused when the original's live parent was deleted, "
          "never falls back to broadcast (#4306 target erasure)",
          "[pg][result_set][async][reeval][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("narrow-target", {"a1"});
    int status = 0;
    auto orig = h.post("/api/v1/result-sets/from-tar-query",
                       R"({"sql":"SELECT 1","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    h.calls.clear();
    h.audits.clear();

    // Delete the parent -- exercise ON DELETE SET NULL rather than assume it.
    REQUIRE(h.store->delete_set(parent).has_value());
    auto orig_row = get_ok(*h.store, orig_id);
    REQUIRE(orig_row.has_value());
    REQUIRE_FALSE(orig_row->parent_id.has_value());

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    CHECK(re["error"]["message"].get<std::string>().find("parent set no longer exists") !=
          std::string::npos);
    // THE assertion: nothing was ever dispatched.
    REQUIRE(h.calls.empty());
    // No new pending/materialized row landed -- only the original remains.
    std::string next;
    auto rows = h.store->list_by_owner("operator-1", "", 50, next);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows[0].id == orig_id);
    // Denied and audited with reason=parent_gone.
    bool found = false;
    for (auto& a : h.audits)
        if (a.action == "result_set.create" && a.result == "denied" &&
            a.detail.find("reason=parent_gone") != std::string::npos)
            found = true;
    CHECK(found);
}

TEST_CASE("re-eval: the parent-gone refusal surfaces a dropped audit row via "
          "Sec-Audit-Failed, not silently",
          "[pg][result_set][async][reeval][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("narrow-target-2", {"a1"});
    int status = 0;
    auto orig = h.post("/api/v1/result-sets/from-tar-query",
                       R"({"sql":"SELECT 1","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    REQUIRE(h.store->delete_set(parent).has_value());

    h.audit_ok = false; // models a dropped audit row (#1647 posture)
    int rstat = 0;
    h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    CHECK(h.last_sec_audit_failed == "true");
}

TEST_CASE("re-eval: an alias-referenced parent is refused after deletion, never "
          "silently re-resolved to a newer set bound to the same alias (#4306)",
          "[pg][result_set][async][reeval][security][4306][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("my-alias", {"a1"});
    int status = 0;
    // Original parented via the ALIAS, not the canonical rs_ id.
    auto orig = h.post("/api/v1/result-sets/from-tar-query",
                       R"({"sql":"SELECT 1","parent_id":"my-alias"})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    // The alias was pre-resolved to the canonical id at creation time.
    REQUIRE(*get_ok(*h.store, orig_id)->parent_id == parent);
    h.calls.clear();

    REQUIRE(h.store->delete_set(parent).has_value());
    REQUIRE_FALSE(get_ok(*h.store, orig_id)->parent_id.has_value());

    // Re-bind the alias to a DIFFERENT, newer set. If the fix silently
    // re-resolved scope_input_id as a fresh alias lookup, THIS is the set it
    // would wrongly retarget to.
    h.seed_materialized("my-alias", {"b1", "b2"});

    int rstat = 0;
    h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: refused when a GENERIC-create original's live parent was "
          "deleted, never falls back to broadcast (#4306 follow-up: the "
          "generic POST /api/v1/result-sets route persists scope_input_id too)",
          "[pg][result_set][async][reeval][security][4306]") {
    // Adversarial review (Kimi + Codex) of the #4306 fix found that
    // scope_input_id was ONLY persisted by the two dedicated producer routes
    // (from-tar-query / from-instruction-result). This route accepts an
    // UNRESTRICTED source_kind/source_payload (no allowlist) plus a
    // caller-supplied, owner-checked parent_id -- a row minted here with a
    // crafted tar_query-shaped payload was indistinguishable at re-eval time
    // from a genuinely parentless original once its parent was deleted, and
    // would have silently broadcast to __all__ (the same #2500 shape #4306
    // itself closed for the producer routes).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("narrow-target-generic", {"a1"});
    int status = 0;
    auto orig = h.post("/api/v1/result-sets",
                       R"({"source_kind":"tar_query","source_payload":{"sql":"SELECT 1"},)"
                       R"("parent_id":")" + parent + R"("})",
                       status);
    REQUIRE(status == 201);
    auto orig_id = orig["data"]["id"].get<std::string>();

    // Positive control: the generic route now records scope_input_id, the
    // same as the dedicated producers do.
    auto orig_row = get_ok(*h.store, orig_id);
    REQUIRE(orig_row.has_value());
    auto sp = nlohmann::json::parse(orig_row->source_payload, nullptr, false);
    REQUIRE(sp.is_object());
    REQUIRE(sp.value("scope_input_id", "") == parent);

    // Delete the parent -- exercise ON DELETE SET NULL rather than assume it.
    REQUIRE(h.store->delete_set(parent).has_value());
    orig_row = get_ok(*h.store, orig_id);
    REQUIRE(orig_row.has_value());
    REQUIRE_FALSE(orig_row->parent_id.has_value());

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    CHECK(re["error"]["message"].get<std::string>().find("parent set no longer exists") !=
          std::string::npos);
    // THE assertion: nothing was ever dispatched -- before this fix, a
    // generic-create original with no recorded scope_input_id would have
    // fallen through to the genuinely-parentless branch and broadcast to
    // __all__ here.
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: the parent-gone audit detail neutralises a delimiter-bearing "
          "scope_input_id instead of forging adjacent k=v tokens (Gate 8 governance "
          "follow-up, #4306)",
          "[pg][result_set][async][reeval][security][4306]") {
    // scope_input_id is the raw caller-supplied parent_id/alias at creation time
    // and can be an arbitrary string (an alias, not just a canonical rs_ id).
    // Craft one containing a space and '=' -- the exact shape that could forge
    // an adjacent k=v token or split the audit line if not neutralised. This
    // reaches the vulnerable branch WITHOUT ever supplying a real parent_id: the
    // generic create route stores source_payload verbatim when parent_id is
    // absent, so a caller can hand-craft scope_input_id directly.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto orig = h.post("/api/v1/result-sets",
                       R"({"source_kind":"tar_query",)"
                       R"("source_payload":{"sql":"SELECT 1","scope_input_id":)"
                       R"("evil target_id=rs_other"}})",
                       status);
    REQUIRE(status == 201);
    auto orig_id = orig["data"]["id"].get<std::string>();
    h.audits.clear();

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    REQUIRE(h.calls.empty());

    bool found = false;
    for (const auto& a : h.audits) {
        if (a.action == "result_set.create" && a.result == "denied" &&
            a.detail.find("reason=parent_gone") != std::string::npos) {
            found = true;
            // The raw delimiter-bearing value must NOT survive verbatim.
            CHECK(a.detail.find("evil target_id=rs_other") == std::string::npos);
            // The neutralised form (log_token: space and '=' -> '_') must be
            // present exactly.
            CHECK(a.detail.find("scope_input_id=evil_target_id_rs_other") !=
                  std::string::npos);
        }
    }
    REQUIRE(found);
}

TEST_CASE("re-eval: a non-object source_payload on a GENERIC-create original with a "
          "real parent_id never reaches dispatch after the parent is deleted (#4306 "
          "governance follow-up -- locks the is_object() joint invariant between the "
          "create-time scope_input_id merge and the re-eval-time sql/instruction_id "
          "extraction, currently a coincidence rather than a documented contract)",
          "[pg][result_set][async][reeval][security][4306]") {
    // Both the create-time scope_input_id merge (generic create routes) and the
    // re-eval-time sql/instruction_id extraction independently gate on
    // source_payload.is_object() -- a caller supplying a non-object source_payload
    // (a bare JSON string here) alongside a real, owned parent_id skips the
    // scope_input_id merge at creation, but the SAME predicate also blocks the
    // sql/instruction_id extraction at re-eval time, so the row 400s "no
    // re-runnable source" before ever reaching dispatch. Currently safe only by
    // this coincidence (Gate 4/5 governance) -- this test locks it down.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("narrow-target-nonobject", {"a1"});
    int status = 0;
    // source_payload is a bare JSON STRING, not an object.
    auto orig = h.post("/api/v1/result-sets",
                       R"({"source_kind":"tar_query","source_payload":"not-an-object",)"
                       R"("parent_id":")" + parent + R"("})",
                       status);
    REQUIRE(status == 201);
    auto orig_id = orig["data"]["id"].get<std::string>();

    // Confirm the marker was NOT recorded (is_object() gate skipped the merge).
    auto orig_row = get_ok(*h.store, orig_id);
    REQUIRE(orig_row.has_value());
    auto sp = nlohmann::json::parse(orig_row->source_payload, nullptr, false);
    REQUIRE_FALSE(sp.is_object());

    REQUIRE(h.store->delete_set(parent).has_value());
    orig_row = get_ok(*h.store, orig_id);
    REQUIRE(orig_row.has_value());
    REQUIRE_FALSE(orig_row->parent_id.has_value());

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    // Refused for lack of a re-runnable "sql" field (the coincidental gate),
    // NOT the parent_gone message -- confirms it fell into the "genuinely
    // parentless" branch (no scope_input_id found) and was THEN stopped by the
    // separate sql-presence check, never reaching run_async.
    CHECK(re["error"]["message"].get<std::string>().find("no SQL") != std::string::npos);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: unsupported source_kind is 400", "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto manual = h.seed_materialized("hand-curated", {"a1"});
    int status = 0;
    h.post("/api/v1/result-sets/" + manual + "/re-eval", "", status);
    REQUIRE(status == 400);
}

TEST_CASE("re-eval: an unsupported source_kind is refused as RESULT_SET_REEVAL_UNSUPPORTED "
          "even when a crafted scope_input_id would otherwise trip the parent-gone guard "
          "(#4306 follow-up misclassification fix)",
          "[pg][result_set][async][reeval][security][4306]") {
    // Adversarial review (Kimi + Codex) of the #4306 fix found that a
    // manual_curate (or any other unsupported-source_kind) row minted via
    // the generic create route with a crafted
    // source_payload={"scope_input_id":"..."} but NO real parent_id reached
    // the scope_input_id / parent-gone guard BEFORE the source_kind check,
    // so it was misclassified as RESULT_SET_BAD_REQUEST (reason=parent_gone)
    // instead of the correct RESULT_SET_REEVAL_UNSUPPORTED. Both outcomes
    // were already 400 refusals with nothing dispatched either way (not a
    // dispatch-safety bug) -- this proves the reorder fixed the
    // classification, not merely that both still 400.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    // No parent_id supplied at all -- source_payload's scope_input_id is
    // entirely caller-crafted and points at an id that never existed, never
    // exercising the real parent_id owner-check/merge path.
    auto orig = h.post("/api/v1/result-sets",
                       R"({"source_kind":"manual_curate",)"
                       R"("source_payload":{"scope_input_id":"rs_deadbeefdeadbeef"}})",
                       status);
    REQUIRE(status == 201);
    auto orig_id = orig["data"]["id"].get<std::string>();
    REQUIRE_FALSE(get_ok(*h.store, orig_id)->parent_id.has_value());

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 400);
    const auto msg = re["error"]["message"].get<std::string>();
    CHECK(msg.find("RESULT_SET_REEVAL_UNSUPPORTED") != std::string::npos);
    CHECK(msg.find("parent set no longer exists") == std::string::npos);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: not-owned / missing set is 404", "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/rs_00000000000deadbeef/re-eval", "", status);
    REQUIRE(status == 404);
}

TEST_CASE("re-eval: an oversized SQL smuggled onto an existing row is refused, "
          "never re-dispatched",
          "[pg][result_set][async][reeval]") {
    // Gate 8 fix (#2146 Batch B2 follow-up): the re-eval route re-applies the
    // 100 KiB tar_query cap because the ORIGINAL row may predate the cap (or
    // was minted through a path that never enforced it) - this test proves
    // that guard actually fires, rather than trusting the comment at the
    // call site. Seeded directly in the store (never through
    // /from-tar-query, which enforces the cap at creation and would itself
    // reject this payload).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-oversized";
    cr.source_kind = std::string(source_kind::kTarQuery);
    nlohmann::json payload;
    payload["sql"] = std::string(100001, 'x');
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

// #4373: the kInstructionResult branch was missing the equivalent recheck
// entirely - a row minted via the uncapped POST /api/v1/result-sets (no
// source_kind allowlist there) could carry an over-keyed or oversized
// params object straight past MCP's own bounds (mcp_input_bounds.hpp) and
// into a fleet-wide dispatch, or an oversized instruction_id straight into
// instruction_store's lookup unbounded. The seven cases below (four bound
// cases, two type-confusion cases, and one unparseable-payload case) cover
// the ones reevaluate_result_set's own fix (PR #4394) already has plus one
// more (cpp-safety Gate 3 finding on this PR), seeded directly in the
// store the same way the SQL-cap test above is (never through
// /from-instruction-result, which has no per-field bound of its own to
// enforce the smuggled shape at creation time).

TEST_CASE("re-eval: an over-keyed params object smuggled onto an existing "
          "instruction_result row is refused, never re-dispatched",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    // A REAL, registered instruction_id (never a made-up one): without the
    // params bound this fix adds, the lookup below succeeds and the old
    // code reaches run_async, so this proves the bound is what stops the
    // dispatch, not merely that an unrelated "instruction unavailable" path
    // happens to also 400.
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    nlohmann::json params = nlohmann::json::object();
    for (int i = 0; i < 33; ++i)
        params["k" + std::to_string(i)] = "v";
    payload["params"] = params;

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-overkeyed";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    // #4478's stored-payload depth guard 400s+no-dispatches this same route
    // before parse, so status==400 + h.calls.empty() alone does not
    // distinguish this fix's params-count bound from that unrelated guard -
    // the message is what proves THIS check fired.
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("params must have at most 32 keys") !=
            std::string::npos);
}

TEST_CASE("re-eval: a non-object params smuggled onto an existing instruction_result "
          "row is refused, not silently re-dispatched with an empty params map",
          "[pg][result_set][async][reeval][security][4373]") {
    // Gate 4 unhappy-path fix: the pre-fix code gated every params bound
    // check (and the params-map-build loop) on is_object(), so a
    // string/array/number params silently re-dispatched with an EMPTY map.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    payload["params"] = std::string(1024, 'A');

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-non-object-params";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("'params' must be a JSON object") !=
            std::string::npos);
}

TEST_CASE("re-eval: an oversized params value smuggled onto an existing "
          "instruction_result row is refused, never re-dispatched",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    // Real instruction_id, same reasoning as the over-keyed case above.
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    payload["params"] = {{"k", std::string(65537, 'z')}};

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-oversized-value";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    // Same distinguishing reasoning as the over-keyed case above: assert the
    // message, not just the status, since #4478's depth guard 400s on this
    // route too.
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("a params value exceeds 65536 bytes") !=
            std::string::npos);
}

TEST_CASE("re-eval: a non-string params value is measured by its dump() size, "
          "not skipped, smuggled onto an existing instruction_result row",
          "[pg][result_set][async][reeval]") {
    // Proves the value-size check measures dump() size for a non-string JSON
    // value (an object/array), not merely `.is_string()`-gated away - the
    // exact regression MCP's own reevaluate_result_set fix had a dedicated
    // SECTION for. Real instruction_id, same reasoning as the two cases above.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    payload["params"] = {{"k", {{"pad", std::string(65537, 'z')}}}};

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-oversized-nonstring-value";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    // Same distinguishing reasoning as the two cases above: assert the
    // message, since a bare 400+no-dispatch is also what #4478's depth
    // guard produces on this route.
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("a params value exceeds 65536 bytes") !=
            std::string::npos);
}

TEST_CASE("re-eval: an oversized instruction_id smuggled onto an existing "
          "row is refused, never re-dispatched",
          "[pg][result_set][async][reeval]") {
    // A bogus, non-existent instruction_id 400s regardless of length via the
    // pre-existing "original instruction unavailable" fallback (dispatch
    // needs a real matching InstructionDefinition either way), so status==400
    // alone does not distinguish this fix's length check from that
    // pre-existing path - both the fixed and unfixed handler return 400 here.
    // Asserting the error message names the length bound is what actually
    // proves the NEW check fired, not the old fallback.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json payload;
    payload["instruction_id"] = std::string(257, 'q');

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-oversized-instruction-id";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("must be at most 256 bytes") !=
            std::string::npos);
}

// Gate 8 follow-up (post-merge test-gap closure): the seven cases above cover
// the count/value/instruction_id bounds and the two type-confusion cases, but
// leave two gaps - no case ever sends a params KEY past its own bound, and no
// case proves any of the four bounds accepts a request AT its boundary rather
// than only rejecting past it. The three cases below close those gaps.

TEST_CASE("re-eval: a 257-byte params key smuggled onto an existing "
          "instruction_result row is refused with the bounds-specific error",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    payload["params"] = {{std::string(257, 'k'), "v"}};

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-overlong-key";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("a params key exceeds 256 bytes") !=
            std::string::npos);
}

TEST_CASE("re-eval: an instruction_id of exactly 256 bytes passes the length "
          "guard and falls through to instruction-unavailable",
          "[pg][result_set][async][reeval]") {
    // The 256-byte boundary itself must be ACCEPTED by this fix's length
    // check (only >256 is rejected, per kInstructionIdMaxLen) - but
    // InstructionStore::validate_and_prepare caps a real definition id at
    // 128 characters, so no registered instruction can ever be 256 bytes
    // long and this can never reach a successful dispatch. Proving
    // acceptance-at-the-boundary therefore means proving the length check
    // did NOT fire (no "must be at most 256 bytes" message) and the request
    // instead reaches the pre-existing not-found fallback, not that it
    // dispatched.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json payload;
    payload["instruction_id"] = std::string(256, 'q');

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-boundary-instruction-id";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
    REQUIRE(j["error"]["message"].get<std::string>().find("must be at most 256 bytes") ==
            std::string::npos);
    REQUIRE(j["error"]["message"].get<std::string>().find("original instruction unavailable") !=
            std::string::npos);
}

TEST_CASE("re-eval: params at the exact per-field bounds (32 keys, a "
          "256-byte key, a 65536-byte value) pass and the request dispatches",
          "[pg][result_set][async][reeval]") {
    // The positive-boundary twin of the count/key/value rejection cases
    // above - proves 32 keys, a 256-byte key, and a 65536-byte value are all
    // ACCEPTED (not merely that 33/257/65537 are rejected), and that an
    // otherwise-valid request still reaches dispatch once every bound
    // clears. Real, registered instruction_id (short - InstructionStore
    // caps ids at 128 bytes, so the instruction_id bound's own accept-side
    // boundary is covered separately above, not here).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    nlohmann::json payload;
    payload["instruction_id"] = iid;
    nlohmann::json params = nlohmann::json::object();
    params[std::string(256, 'k')] = std::string(65536, 'v');
    for (int i = 0; i < 31; ++i)
        params["k" + std::to_string(i)] = "v";
    REQUIRE(params.size() == 32);
    payload["params"] = params;

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-boundary-params";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    auto j = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "filehash");
    REQUIRE(h.calls[0].action == "check");
    REQUIRE(h.calls[0].params.at(std::string(256, 'k')) == std::string(65536, 'v'));
    REQUIRE(j["data"]["source_kind"] == "instruction_result");
}

TEST_CASE("re-eval: a type-mismatched sql value on a tar_query row is a clean "
          "400, never an uncaught type_error",
          "[pg][result_set][async][reeval]") {
    // nlohmann::json::value("sql", "") throws json::type_error on a type
    // mismatch rather than coercing - #4373's second finding. Proves the
    // type-confusion guard actually fires, not merely that the comment says
    // it should.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json payload;
    payload["sql"] = 12345;

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-type-mismatched-sql";
    cr.source_kind = std::string(source_kind::kTarQuery);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: a type-mismatched instruction_id value on an "
          "instruction_result row is a clean 400, never an uncaught type_error",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json payload;
    payload["instruction_id"] = 12345;

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-type-mismatched-instruction-id";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = payload.dump();
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: an unparseable source_payload on an instruction_result row "
          "is a clean 400, never an uncaught exception",
          "[pg][result_set][async][reeval]") {
    // orig->source_payload is parsed with nlohmann::json::parse(..., nullptr,
    // false), which discards (rather than throws) on invalid JSON - proves
    // that discarded-value path degrades safely on the kInstructionResult
    // branch too: sp.is_object() is false for a discarded value, so every
    // field read below falls through to "absent", not a crash.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-unparseable-payload";
    cr.source_kind = std::string(source_kind::kInstructionResult);
    cr.source_payload = "not json";
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// CWE-862 — the three async producers DISPATCH, so they must gate on
// Execution:Execute.
//
// They authenticated the caller and then performed no authorization check at
// all: `perm_fn` was not even in the lambda capture list, so ANY authenticated
// session — including one holding no Execution grant — reached
// `command_dispatch_fn` with scope `__all__` and ran operator SQL across the
// whole fleet. Ungated since e7b47ca3 (2026-05-31) and shipped in v0.13.0.
//
// These assert the SECURITY OUTCOME — that nothing was dispatched — not merely
// that a status code changed. A test asserting only `status == 403` would still
// pass if the gate ran after the dispatch.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("from-tar-query: an authenticated caller WITHOUT Execution:Execute dispatches nothing",
          "[pg][result_set][async][tar][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    AsyncHarness::permit_exec = false; // authenticated, but no Execution grant

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT pid FROM process_live","name":"probe"})", status);

    CHECK(status == 403);
    CHECK(h.calls.empty()); // THE assertion: the fleet was never reached
}

TEST_CASE("from-instruction-result: an authenticated caller WITHOUT Execution:Execute dispatches "
          "nothing",
          "[pg][result_set][async][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto def_id = make_instruction(*h.instr);
    AsyncHarness::permit_exec = false;

    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + def_id + R"(","name":"probe"})", status);

    CHECK(status == 403);
    CHECK(h.calls.empty());
}

TEST_CASE("re-eval: an authenticated caller WITHOUT Execution:Execute dispatches nothing",
          "[pg][result_set][async][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    // Create a set legitimately first (gate permitted), then re-eval it without
    // the grant — proving the gate is on the re-eval route itself, not merely
    // inherited from whoever created the original.
    int status = 0;
    auto created = h.post("/api/v1/result-sets/from-tar-query",
                          R"({"sql":"SELECT pid FROM process_live","name":"orig"})", status);
    REQUIRE(status == 202);
    const auto rs_id = created["data"]["id"].get<std::string>();
    const auto calls_before = h.calls.size();

    AsyncHarness::permit_exec = false;
    h.post("/api/v1/result-sets/" + rs_id + "/re-eval", "{}", status);

    CHECK(status == 403);
    CHECK(h.calls.size() == calls_before); // no NEW dispatch
}

// ═══════════════════════════════════════════════════════════════════════════
// #1788 — per-device dispatch confinement on the three async producers.
//
// The CWE-862 cases above cover the NO-GRANT-AT-ALL caller. They do not cover
// the caller who legitimately holds `Execution:Execute` but may only reach SOME
// devices — a service-scoped token being the live example — and that gap is
// exactly what shipped: these routes admit on a bare GLOBAL perm_fn and then
// dispatched through the SYSTEM closure, whose exec_visible is hardcoded
// nullopt. A service-A token therefore reached every connected agent. Neither
// the eleven adversarial rounds nor the eight-gate governance pass could catch
// it, because `DispatchCall` had no field in which the confinement decision
// could be observed at all.
//
// WHAT THESE ASSERT, precisely: the HANDOFF — that the route derived a present
// (confined) VisibleSet and passed it to dispatch. They are NOT the proof that
// confinement is enforced; enforcement is the intersection, which lives in
// `dispatch_confined_arms` and is bound with exact-send-set assertions against
// a real AgentRegistry in test_dispatch_confined_arms.cpp. Both layers are
// required and neither substitutes for the other — a route mock that only
// observes the set stays green while the intersection is deleted (CDX-R8-02),
// which is why this comment says so rather than letting the next reader assume
// otherwise. Shape follows the established precedent at
// test_mcp_server.cpp's execute_instruction confinement cases.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("from-tar-query: a confined caller's VisibleSet is derived and threaded into dispatch",
          "[pg][result_set][async][tar][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    // A service-scoped token: holds Execution:Execute (perm_fn admits), but may
    // reach only its own service's agents.
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","name":"svc"})", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    // The broadcast arm is still SELECTED (`__all__` is a targeting mechanism,
    // never an authz exemption) — and it is narrowed at the seam by this set.
    CHECK(h.calls[0].scope_expr == "__all__");
    REQUIRE(h.calls[0].exec_visible.has_value()); // CONFINED, not unfiltered
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("from-instruction-result: a confined caller's VisibleSet reaches dispatch",
          "[pg][result_set][async][instruction][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};

    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + iid + R"("})", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("re-eval: a confined caller's VisibleSet reaches the re-dispatch",
          "[pg][result_set][async][reeval][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    int status = 0;
    auto created =
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 7","name":"o"})", status);
    REQUIRE(status == 202);
    const auto rs_id = created["data"]["id"].get<std::string>();
    h.calls.clear();

    // Confinement applies to the RE-EVAL as its own dispatch, not inherited
    // from whatever authority created the original set.
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};
    h.post("/api/v1/result-sets/" + rs_id + "/re-eval", "", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("async producers: an UNWIRED exec-visible derivation is an audited 500, never a dispatch",
          "[pg][result_set][async][security][1788][fail-closed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // Genuinely unwired — NOT the harness's nullopt default. On these routes
    // the derivation is the ONLY per-device authorization, so a missing one is
    // a server misconfiguration: refuse loudly rather than substitute
    // present-empty and report the operator "no agents reached", which reads as
    // an empty fleet and hides the broken gate.
    AsyncHarness h(pool, /*with_dispatch=*/true, /*inv=*/nullptr, /*with_exec_visible=*/false);
    auto iid = make_instruction(*h.instr);

    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    CHECK(status == 500);
    CHECK(j.dump().find("RESULT_SET_GATE_UNCONFIGURED") != std::string::npos);
    CHECK(h.calls.empty()); // THE assertion: nothing was dispatched

    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + iid + R"("})", status);
    CHECK(status == 500);
    CHECK(h.calls.empty());

    // The refusal is durable evidence, not just a status code.
    const bool audited =
        std::any_of(h.audits.begin(), h.audits.end(), [](const AsyncHarness::AuditCall& a) {
            return a.action == "result_set.create" && a.result == "denied" &&
                   a.detail.find("exec_visible_unwired") != std::string::npos;
        });
    CHECK(audited);
}

TEST_CASE("async producers: a LOST evidence row on the unwired-gate refusal is surfaced, not "
          "swallowed",
          "[pg][result_set][async][security][1788][fail-closed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool, /*with_dispatch=*/true, /*inv=*/nullptr, /*with_exec_visible=*/false);
    // A refusal nobody can prove happened is not fail-closed: if the denial
    // audit cannot be persisted, the response must say so.
    h.audit_ok = false;

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    CHECK(status == 500);
    CHECK(h.last_sec_audit_failed == "true");
    CHECK(h.calls.empty()); // still no dispatch
}

TEST_CASE("async producers: an unfiltered (nullopt) VisibleSet still dispatches — non-regression",
          "[pg][result_set][async][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool); // exec_visible_override defaults to nullopt
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    // A genuine global administrator keeps full-fleet reach — that is their
    // actual authority, not a bypass. Distinct from the unwired case above:
    // wiring a callback that RETURNS nullopt is an answer; leaving the callback
    // empty is a missing gate.
    CHECK_FALSE(h.calls[0].exec_visible.has_value());
}

// ---------------------------------------------------------------------------
// guardian-confinement-2298 PR3 §3e residual sweep findings.
//
// (1) POST /api/v1/result-sets/from-inventory-query had NO authorization
//     check at all (not even the CWE-862 Execution:Execute gate its three
//     DISPATCH siblings already carry — it is a synchronous READ, not a
//     dispatch, so it was never in scope for that fix and was missed). Now
//     gated on Inventory:Read via perm_fn. This harness's mock perm_fn
//     doesn't distinguish securable/operation — it proves the gate is
//     CALLED at all (previously it never was); the real RBAC-vs-service-
//     scope distinction is covered by AuthRoutes's own require_permission
//     tests in test_auth_routes.cpp.
//
// (2) The 8 owner-scoped `/api/v1/result-sets*` routes (list, create,
//     detail, members, lineage, pin, unpin, delete) were session->username-
//     keyed with no service-scope check — the identical gap already fixed
//     for the HTMX twin (/fragments/result-sets/*) this session. Extended
//     the file's own deny_fleet_wide_service_scoped chokepoint. A dummy
//     but regex-valid `rs_`-prefixed id is enough: the deny runs before
//     `load_owned`, so no real result set needs to exist.
// ---------------------------------------------------------------------------

TEST_CASE("from-inventory-query: an authenticated caller lacking Inventory:Read "
          "is denied (CWE-862 — previously unauthorized entirely)",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    AsyncHarness::permit_exec = false;
    int status = 0;
    h.post("/api/v1/result-sets/from-inventory-query", R"({"name":"x"})", status);
    CHECK(status == 403);
}

TEST_CASE("from-inventory-query: an ordinary authorized caller still reaches the "
          "handler (regression)",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    // No inventory store wired — proceeds past the new gate to the existing
    // "inventory store not available" 503, proving the new perm_fn check
    // does not itself block a legitimately-authorized caller.
    h.post("/api/v1/result-sets/from-inventory-query", R"({"name":"x"})", status);
    CHECK(status == 503);
}

TEST_CASE("from-inventory-query: an oversized name is refused with 400, never "
          "reaches the inventory-store gate",
          "[pg][result_set][async][inventory][security]") {
    // PR review finding: REST fixed the type-confusion crash on name but
    // never applied MCP's matching kResultSetNameMaxLen length cap. The
    // check runs before store availability, so this 400s even with no
    // inventory store wired (unlike the 503 case just above).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["name"] = std::string(257, 'n');
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-inventory-query", body.dump(), status);
    CHECK(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("name must be at most 256 bytes") !=
          std::string::npos);
}

// #2146 Batch B2 Gate 4 unhappy-path fix: the confinement fix itself
// (authz::in_scope(gate.scope, r.agent_id) narrowing which agents' inventory
// rows are visible) had zero red -> green test coverage on either transport -
// every prior test either left the gate unconfined (nullopt) or never got a
// real InventoryStore far enough to exercise the narrowing loop at all.
// Mirrors the equivalent test already added for preview_scope_targets
// (test_rest_scope_v1_routes.cpp).
TEST_CASE("from-inventory-query: matched membership is confined to the caller's "
          "fleet_read_fn scope, never the whole fleet",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        for (const char* agent : {"agent-visible", "agent-hidden"}) {
            auto seeded = yuzu::server::pg::exec_params(
                lease.get(),
                "INSERT INTO inventory_store.inventory_data "
                "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
                "'{\"field1\":\"match\"}', 1)",
                std::vector<std::string>{agent});
            REQUIRE(seeded.status() == PGRES_COMMAND_OK);
        }
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
    // Confine to exactly one of the two seeded agents.
    h.fleet_read_scope_override =
        yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"agent-visible"}};

    int status = 0;
    auto body = h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"confined","conditions":[{"plugin":"custom","field":"field1","op":"==","value":"match"}]})",
        status);
    REQUIRE(status == 201);
    // Both agents' rows match the condition - if confinement were not applied,
    // device_count would be 2. The fix narrows the candidate records to the
    // gate's scope BEFORE evaluation, so only "agent-visible" can ever match.
    CHECK(body["data"]["device_count"] == 1);
}

TEST_CASE("from-inventory-query: a supplied parent_id is persisted as scope_input_id "
          "(Gate 8 governance follow-up positive control, #4306)",
          "[pg][result_set][async][inventory][reeval][security][4306]") {
    // Gate 7's #4306 follow-up added this route's own scope_input_id merge
    // (rest_api_v1.cpp, body["scope_input_id"] = pid) but shipped with no
    // direct test proving the merge actually happens -- only the fact that
    // re-eval's source_kind allowlist independently refuses kInventoryQuery
    // was covered. This does not need a full re-eval assertion (re-eval never
    // accepts inventory_query regardless) -- just confirm the stored row.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
    auto parent = h.seed_materialized("inv-query-parent", {"a1"});

    int status = 0;
    auto body = h.post("/api/v1/result-sets/from-inventory-query",
                       R"({"name":"child-of-parent","parent_id":")" + parent + R"("})",
                       status);
    REQUIRE(status == 201);
    auto new_id = body["data"]["id"].get<std::string>();

    auto row = get_ok(*h.store, new_id);
    REQUIRE(row.has_value());
    auto sp = nlohmann::json::parse(row->source_payload, nullptr, false);
    REQUIRE(sp.is_object());
    CHECK(sp.value("scope_input_id", "") == parent);
}

// #2437-class guard (C11/C12): a stored data_json row nesting past
// kMcpMaxJsonDepth reaches evaluate_inventory() (inventory_eval.cpp) via this
// exact route. json::parse handles very deep input fine, so without the
// guard the row parses cleanly and json_value_to_string's dump() fallback on
// the parsed tree would SIGSEGV the whole process, taking the OTHER
// matching agent's membership down with it. Seeded directly via SQL
// (bypassing the gateway write-side guard) to prove this read-side guard
// independently, mirroring the confinement test's seeding pattern above.
//
// Uses "exists" rather than "==": with "==" the poisoned record's
// dump()-fallback string would never equal the target value, so the guard's
// absence would be invisible at this level (verified separately in
// test_inventory_eval.cpp, which is the actual code under test and proves
// reachability directly). "exists" matches on presence alone, so it is
// answered TRUE for the poisoned record's "field1" whether the guard runs
// or not, making the response status the deciding, guard-dependent signal
// here too (a crash without the guard, a clean 503 with it). Real structural
// nesting, NOT brackets inside a string literal: json_exceeds_depth
// deliberately does not count bracket characters inside a string value as
// structure. Reachability-proxy depth (36 > kMcpMaxJsonDepth's 32), never
// the real ~100,000-level attack depth.
//
// #4496: this producer MATERIALISES its match set into a durable result set
// other operators/dispatches consume later, so poison-exclusion is folded
// into the SAME M1 dispatch-targeting-invariant refusal as a byte-capped read
// (see "from-inventory-query refuses a byte-capped read without creating a
// set" above, the direct precedent) rather than a flag on a 201 - a flag on
// this response would never reach a downstream consumer of the created set.
// This test previously asserted the OPPOSITE (a 201 with the poisoned agent
// silently dropped from membership); #4496 replaces that silent narrowing
// with an explicit refusal.
TEST_CASE("from-inventory-query: a poisoned stored data_json refuses the request rather "
          "than silently materialising a narrowed set, no crash",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    const std::string poisoned_json =
        R"({"field1":)" + std::string(35, '[') + std::string(35, ']') + "}";
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_poisoned = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', $2, 1)",
            std::vector<std::string>{"agent-poisoned", poisoned_json});
        REQUIRE(seeded_poisoned.status() == PGRES_COMMAND_OK);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"depth-guard","conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 503); // no crash, and no silently-narrowed set either
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    bool saw_poison_failure = false;
    for (const auto& a : h.audits)
        if (a.action == "result_set.create" && a.result == "failure" &&
            a.detail.find("poison_excluded") != std::string::npos)
            saw_poison_failure = true;
    CHECK(saw_poison_failure);
}

// #4496: the healthy-only sibling of the test above - proves the refusal is
// specific to an actual poisoned record, not a false-positive that fires on
// every from-inventory-query call after this fix.
TEST_CASE("from-inventory-query: no poisoned record present -- matching membership is "
          "materialised normally",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"depth-guard-healthy","conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 201);
    CHECK(body["data"]["device_count"] == 1);
    std::string next;
    auto members = h.store->members(body["data"]["id"].get<std::string>(), "", 10, next);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == "agent-healthy");
}

// #4496 follow-up: the sibling of the poisoned-record test above, for the
// OTHER cause evaluate_inventory() can exclude a record for -- a genuine
// JSON parse error rather than over-nesting. Seeded directly via SQL
// (bypassing the gateway write-side guard, which checks nesting depth only,
// not general JSON validity) to prove this read-side guard independently.
// Uses "exists" for the same discriminating reason as the poisoned test: a
// caller who wrote "==" could not tell a guarded exclusion from an ordinary
// no-match.
TEST_CASE("from-inventory-query: a malformed stored data_json refuses the request rather "
          "than silently materialising a narrowed set, no crash",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_malformed = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'not valid json {{{', 1)",
            std::vector<std::string>{"agent-malformed"});
        REQUIRE(seeded_malformed.status() == PGRES_COMMAND_OK);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"parse-error-guard","conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 503); // no crash, and no silently-narrowed set either
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    bool saw_parse_error_failure = false;
    for (const auto& a : h.audits)
        if (a.action == "result_set.create" && a.result == "failure" &&
            a.detail.find("parse_error_excluded") != std::string::npos)
            saw_parse_error_failure = true;
    CHECK(saw_parse_error_failure);
}

// #4496 follow-up: the healthy-only sibling of the test above - proves the
// refusal is specific to an actual malformed record, not a false-positive
// that fires on every from-inventory-query call after this fix.
TEST_CASE("from-inventory-query: no malformed record present -- matching membership is "
          "materialised normally",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"parse-error-guard-healthy","conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 201);
    CHECK(body["data"]["device_count"] == 1);
    std::string next;
    auto members = h.store->members(body["data"]["id"].get<std::string>(), "", 10, next);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == "agent-healthy");
}

// #4541 review (Important finding 2): both producer tests above seed only
// ONE excluded cause at a time. `evaluate_inventory()` checks poison BEFORE
// parse-error (see its own excluded_by_depth/excluded_by_parse_error
// ordering), so a record set carrying BOTH problems must always report
// poison_excluded and never parse_error_excluded - a caller-facing contract
// docs/user-manual/rest-api.md states explicitly ("a caller is always told
// which cause remains, never that both have cleared at once"). Only a
// unit-level test (test_inventory_eval.cpp's "excluded_by_depth and
// excluded_by_parse_error accumulate independently") asserted the two
// out-param counts directly; this proves the actual 503 body, audit detail
// AND metric reason at the route layer, when both fire in the same call.
TEST_CASE("from-inventory-query: a poisoned AND a malformed record in the same call reports "
          "poison_excluded, never parse_error_excluded",
          "[pg][result_set][async][inventory][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    const std::string poisoned_json =
        R"({"field1":)" + std::string(35, '[') + std::string(35, ']') + "}";
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_poisoned = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', $2, 1)",
            std::vector<std::string>{"agent-poisoned", poisoned_json});
        REQUIRE(seeded_poisoned.status() == PGRES_COMMAND_OK);
        auto seeded_malformed = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'not valid json {{{', 1)",
            std::vector<std::string>{"agent-malformed"});
        REQUIRE(seeded_malformed.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/result-sets/from-inventory-query",
        R"({"name":"combined-guard","conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 503);
    REQUIRE(body.contains("error"));
    const auto message = body["error"]["message"].get<std::string>();
    CHECK(message.find("nesting too deeply") != std::string::npos);
    CHECK(message.find("failing to parse") == std::string::npos);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    bool saw_poison_failure = false;
    bool saw_parse_error_failure = false;
    for (const auto& a : h.audits) {
        if (a.action == "result_set.create" && a.result == "failure") {
            if (a.detail.find("poison_excluded") != std::string::npos)
                saw_poison_failure = true;
            if (a.detail.find("parse_error_excluded") != std::string::npos)
                saw_parse_error_failure = true;
        }
    }
    CHECK(saw_poison_failure);
    CHECK_FALSE(saw_parse_error_failure);
    // #4541 review minor: assert the metric counter reason too, not just
    // status/audit - kReasonPoisonExcluded/kReasonParseErrorExcluded
    // (dispatch_target_shape.hpp) label yuzu_server_dispatch_target_rejected_total.
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "result_set_inventory_query"}, {"reason", "poison_excluded"}})
              .value() == 1.0);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_target_rejected_total",
                       {{"route", "result_set_inventory_query"},
                        {"reason", "parse_error_excluded"}})
              .value() == 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// #4496: POST /api/v1/inventory/evaluate -- the read-only third caller of
// evaluate_inventory(). Unlike the two producers above, this route is a
// synchronous READ (no durable artifact materialised downstream), so it
// surfaces poison-exclusion as a `results_excluded_by_poison` count on the
// response rather than refusing the request. This harness's `fleet_read_fn`
// gates the same route as from-inventory-query above, so AsyncHarness is
// reused rather than a new fixture.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST /api/v1/inventory/evaluate: a poisoned record is flagged via "
          "results_excluded_by_poison, a healthy matching agent is still returned",
          "[pg][result_set][inventory][inventory_eval][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    const std::string poisoned_json =
        R"({"field1":)" + std::string(35, '[') + std::string(35, ']') + "}";
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_poisoned = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', $2, 1)",
            std::vector<std::string>{"agent-poisoned", poisoned_json});
        REQUIRE(seeded_poisoned.status() == PGRES_COMMAND_OK);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/inventory/evaluate",
        R"({"conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 200); // no crash, no refusal on this read-only route
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-healthy");
    CHECK(body["results_excluded_by_poison"] == 1);
}

// #4496: the healthy-only sibling of the test above - proves the field is
// absent, not merely 0-but-present-as-a-false-positive, when nothing was
// excluded (same "absent when zero" convention as `result_truncated_by_cap`
// on this route).
TEST_CASE("POST /api/v1/inventory/evaluate: no poisoned record present -- "
          "results_excluded_by_poison is absent from the response",
          "[pg][result_set][inventory][inventory_eval][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/inventory/evaluate",
        R"({"conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 200);
    REQUIRE(body["data"].size() == 1);
    CHECK_FALSE(body.contains("results_excluded_by_poison"));
}

// #4496 follow-up: the sibling of the two `results_excluded_by_poison` tests
// above, for the OTHER exclusion cause -- a genuine JSON parse error.
TEST_CASE("POST /api/v1/inventory/evaluate: a malformed record is flagged via "
          "results_excluded_by_parse_error, a healthy matching agent is still returned",
          "[pg][result_set][inventory][inventory_eval][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_malformed = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'not valid json {{{', 1)",
            std::vector<std::string>{"agent-malformed"});
        REQUIRE(seeded_malformed.status() == PGRES_COMMAND_OK);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/inventory/evaluate",
        R"({"conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 200); // no crash, no refusal on this read-only route
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-healthy");
    CHECK(body["results_excluded_by_parse_error"] == 1);
}

// #4496 follow-up: the healthy-only sibling of the test above - proves the
// field is absent, not merely 0-but-present-as-a-false-positive, when
// nothing was excluded.
TEST_CASE("POST /api/v1/inventory/evaluate: no malformed record present -- "
          "results_excluded_by_parse_error is absent from the response",
          "[pg][result_set][inventory][inventory_eval][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded_healthy = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) VALUES ($1, 'custom', "
            "'{\"field1\":\"match\"}', 1)",
            std::vector<std::string>{"agent-healthy"});
        REQUIRE(seeded_healthy.status() == PGRES_COMMAND_OK);
    }

    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);

    int status = 0;
    auto body = h.post(
        "/api/v1/inventory/evaluate",
        R"({"conditions":[{"plugin":"custom","field":"field1","op":"exists","value":""}]})",
        status);
    REQUIRE(status == 200);
    REQUIRE(body["data"].size() == 1);
    CHECK_FALSE(body.contains("results_excluded_by_parse_error"));
}

TEST_CASE("owner-scoped result-set routes: a service-scoped token is denied on all 8",
          "[pg][result_set][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    h.mock_token_scope_service = "printers";
    const std::string id = "rs_deadbeef00000000000000000000";

    auto get = [&](const std::string& path) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        return res->status;
    };
    auto post = [&](const std::string& path, const std::string& body) {
        auto res = h.sink.Post(path, body);
        REQUIRE(res);
        return res->status;
    };
    auto del = [&](const std::string& path) {
        auto res = h.sink.dispatch("DELETE", path);
        REQUIRE(res);
        return res->status;
    };

    CHECK(get("/api/v1/result-sets") == 403);
    CHECK(post("/api/v1/result-sets", R"({"name":"x"})") == 403);
    CHECK(get("/api/v1/result-sets/" + id) == 403);
    CHECK(get("/api/v1/result-sets/" + id + "/members") == 403);
    CHECK(get("/api/v1/result-sets/" + id + "/lineage") == 403);
    CHECK(post("/api/v1/result-sets/" + id + "/pin", "{}") == 403);
    CHECK(post("/api/v1/result-sets/" + id + "/unpin", "{}") == 403);
    CHECK(del("/api/v1/result-sets/" + id) == 403);

    bool saw_list_denied = false;
    for (const auto& a : h.audits)
        if (a.action == "result_set.list.access_denied" && a.result == "denied")
            saw_list_denied = true;
    CHECK(saw_list_denied);
}

TEST_CASE("owner-scoped result-set routes: an ordinary session is unaffected "
          "(regression)",
          "[pg][result_set][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    auto res = h.sink.Get("/api/v1/result-sets");
    REQUIRE(res);
    CHECK(res->status == 200);
    for (const auto& a : h.audits)
        CHECK(a.action != "result_set.list.access_denied");
}

// ═══════════════════════════════════════════════════════════════════════════
// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. These bodies are otherwise-VALID, otherwise-ACCEPTED
// requests (every required field present and well-typed) with one extra
// deeply-nested field, so on unguarded code the request proceeds all the way
// to a store write / dispatch, and only the new depth check tells fixed and
// unfixed code apart - a bare non-object body would 400 on BOTH (the
// "body must be a JSON object" check), which would prove nothing.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST /api/v1/result-sets: a body nested past the depth limit is rejected "
          "before any store write",
          "[pg][result_set][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    // The deep structure lives inside "source_payload" itself - the exact
    // field this handler calls .dump() on - not just a decoy field elsewhere.
    const std::string body =
        R"({"name":"deep","device_ids":["dev-1"],"source_payload":{"junk":)" +
        nested_array(40) + "}}";
    h.post("/api/v1/result-sets", body, status);
    CHECK(status == 400);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("POST /api/v1/result-sets: a type-mismatched name is refused with 400, "
          "never an uncaught nlohmann::json::type_error",
          "[pg][result_set][security][4406]") {
    // Gate 8 sibling-sweep finding: this generic create route has the same
    // unguarded body.value("name", "") shape as from-tar-query/
    // from-instruction-result did before #4406's fix, but was never part of
    // that sweep since it's a synchronous direct-create path, not one of the
    // three async producers.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets", R"({"name":123})", status);
    CHECK(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("name must be a JSON string") !=
          std::string::npos);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("POST /api/v1/result-sets: a type-mismatched source_kind is refused with "
          "400, never an uncaught nlohmann::json::type_error",
          "[pg][result_set][security][4406]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets", R"({"name":"x","source_kind":123})", status);
    CHECK(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("source_kind must be a JSON string") !=
          std::string::npos);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("POST /api/v1/result-sets: an oversized name is refused with 400",
          "[pg][result_set][security]") {
    // PR review finding: REST fixed the type-confusion crash on name but
    // never applied MCP's matching kResultSetNameMaxLen length cap.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["name"] = std::string(257, 'n');
    int status = 0;
    auto j = h.post("/api/v1/result-sets", body.dump(), status);
    CHECK(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("name must be at most 256 bytes") !=
          std::string::npos);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("POST /api/v1/result-sets: an oversized source_kind is refused with 400",
          "[pg][result_set][security]") {
    // PR review finding: same missing length cap as name, above, for
    // kResultSetSourceKindMaxLen (64 bytes, MCP's own enforced value).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    nlohmann::json body;
    body["name"] = "x";
    body["source_kind"] = std::string(65, 'k');
    int status = 0;
    auto j = h.post("/api/v1/result-sets", body.dump(), status);
    CHECK(status == 400);
    CHECK(j["error"]["message"].get<std::string>().find("source_kind must be at most 64 bytes") !=
          std::string::npos);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

// #4307 item 6: the generic create route's parent_id shape check used to be
// `contains && is_string && !empty`, so a malformed/empty parent_id fell
// through to the untargeted "no parent" arm and was silently accepted --
// unlike the async producers above, this route never dispatches, so the
// consequence is a lineage/UX defect (the caller believes the set is
// parented and it silently isn't), not a dispatch-safety one -- no
// yuzu_server_dispatch_target_rejected_total counter (that metric family is
// reserved for the targeting-argument routes named in #2500).
TEST_CASE("POST /api/v1/result-sets: a malformed or empty parent_id is refused with 400, "
          "not silently treated as parentless",
          "[pg][result_set][security][4307]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    SECTION("numeric parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        auto j = h.post("/api/v1/result-sets", R"({"name":"x","parent_id":123})", status);
        CHECK(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find("RESULT_SET_BAD_PARENT") !=
              std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("empty-string parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        auto j = h.post("/api/v1/result-sets", R"({"name":"x","parent_id":""})", status);
        CHECK(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find("RESULT_SET_BAD_PARENT") !=
              std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("omitting parent_id still creates a parentless set (regression)") {
        AsyncHarness h(pool);
        int status = 0;
        auto j = h.post("/api/v1/result-sets", R"({"name":"x"})", status);
        CHECK(status == 201);
        CHECK(j.contains("data"));
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).size() == 1);
    }
}

// #4734: this route had no length bound on parent_id at all -- an oversized
// value was copied verbatim into the persisted source_payload's
// scope_input_id with no cap.
TEST_CASE("POST /api/v1/result-sets: an oversized parent_id is refused with 400",
          "[pg][result_set][security][4734]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    SECTION("65 bytes is refused") {
        AsyncHarness h(pool);
        nlohmann::json body;
        body["name"] = "x";
        body["parent_id"] = std::string(65, 'p');
        int status = 0;
        auto j = h.post("/api/v1/result-sets", body.dump(), status);
        CHECK(status == 400);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") != std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("exactly 64 bytes clears the length cap (boundary, 404s on ownership "
            "since it's a random unowned id, but never the length-cap 400)") {
        AsyncHarness h(pool);
        nlohmann::json body;
        body["name"] = "x";
        body["parent_id"] = std::string(yuzu::server::mcp::kResultSetParentIdMaxLen, 'p');
        int status = 0;
        auto j = h.post("/api/v1/result-sets", body.dump(), status);
        CHECK(status == 404);
        CHECK(j["error"]["message"].get<std::string>().find(
                  "parent_id must be at most 64 bytes") == std::string::npos);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
}

TEST_CASE("from-tar-query: a body nested past the depth limit is rejected before dispatch",
          "[pg][result_set][async][tar][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    const std::string body = R"({"sql":"SELECT 1","junk":)" + nested_array(40) + "}";
    h.post("/api/v1/result-sets/from-tar-query", body, status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
}

TEST_CASE("from-tar-query: depth guard boundary, 32 levels passes and 33 is rejected",
          "[pg][result_set][async][tar][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // The wrapping object contributes one level, so N nested arrays inside it
    // reach depth 1+N: 31 arrays -> depth 32 (== kMcpMaxJsonDepth, allowed);
    // 32 arrays -> depth 33 (rejected). Proves the guard isn't over-tightened.
    SECTION("exactly at the limit is accepted") {
        AsyncHarness h(pool);
        int status = 0;
        const std::string body = R"({"sql":"SELECT 1","junk":)" + nested_array(31) + "}";
        h.post("/api/v1/result-sets/from-tar-query", body, status);
        CHECK(status == 202);
        CHECK(h.calls.size() == 1);
    }
    SECTION("one level past the limit is rejected") {
        AsyncHarness h(pool);
        int status = 0;
        const std::string body = R"({"sql":"SELECT 1","junk":)" + nested_array(32) + "}";
        h.post("/api/v1/result-sets/from-tar-query", body, status);
        CHECK(status == 400);
        CHECK(h.calls.empty());
    }
}

TEST_CASE("from-instruction-result: a params value nested past the depth limit is "
          "rejected before dispatch",
          "[pg][result_set][async][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto def_id = make_instruction(*h.instr);
    int status = 0;
    // Nests the deep structure inside "params", the exact field whose
    // non-string values this handler's params-building loop calls .dump() on.
    const std::string body = R"({"instruction_id":")" + def_id + R"(","params":{"deep":)" +
                             nested_array(40) + "}}";
    h.post("/api/v1/result-sets/from-instruction-result", body, status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
}

TEST_CASE("from-inventory-query: a body nested past the depth limit is rejected before "
          "any dependency or validation check reads it",
          "[pg][result_set][async][security][depth]") {
    // #2437-class gap found while implementing the three named routes: this
    // handler also does cr.source_payload = body.dump() a few lines below.
    // No InventoryStore is wired here on purpose - proves the depth check
    // runs ahead of the "inventory store not available" 503, not merely
    // ahead of the store write.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    const std::string body = R"({"name":"deep","junk":)" + nested_array(40) + "}";
    h.post("/api/v1/result-sets/from-inventory-query", body, status);
    CHECK(status == 400);
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("re-eval: a stored source_payload nested past the depth limit is refused, "
          "never re-dispatched",
          "[pg][result_set][async][reeval][security][depth]") {
    // Mirrors "re-eval: an oversized SQL smuggled onto an existing row is
    // refused" above: seeded directly in the store, since no CREATION path
    // (guarded or not) should ever be asked to build a row this way - the
    // row is poisoned as if it had been written before this guard existed,
    // or via any other path past or future.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "legacy-poisoned";
    cr.source_kind = std::string(source_kind::kTarQuery);
    // A raw string, never materialised as a live nlohmann::json object at
    // this depth.
    cr.source_payload = std::string(R"({"sql":"SELECT 1","junk":)") + nested_array(40) + "}";
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status = 0;
    h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());

    // #4493: this attempt still cannot proceed (the original query is
    // unrecoverably gone), but the row itself must come out of this call
    // HEALED so it is never a live grenade for a future read again. Status
    // stays Materialized (the row's real, empty-but-legitimate membership is
    // untouched) - only the poisoned payload is replaced.
    auto healed = get_ok(*h.store, seeded->id);
    REQUIRE(healed.has_value());
    CHECK(healed->status == ResultSetStatus::Materialized);
    auto payload = nlohmann::json::parse(healed->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    CHECK(payload.contains("note"));
    CHECK_FALSE(payload.contains("sql"));
    CHECK_FALSE(payload.contains("junk"));

    // Governance Gate 2/4 finding (#4493 re-review): the heal is a real
    // write to an otherwise immutable-by-design row and must leave durable
    // evidence, not just a status code -- same "refusal is durable evidence"
    // discipline as the other audited-denial tests in this file.
    const bool heal_audited =
        std::any_of(h.audits.begin(), h.audits.end(), [&](const AsyncHarness::AuditCall& a) {
            return a.action == "result_set.heal" && a.result == "success";
        });
    CHECK(heal_audited);
}

// #4540 (Important finding 2): documented in the OpenAPI description for this
// route -- a poisoned row's FIRST re-eval heals it in place and reports the
// depth-guard rejection; a SECOND re-eval on the now-healed row hits a
// different, less-specific refusal ("no re-runnable source") rather than
// repeating the same depth error. Pins today's actual fallthrough behavior so
// a future change to the error path cannot silently drift from what the docs
// promise with nothing in CI to catch it.
TEST_CASE("re-eval: a second re-eval on an already-healed row gets a "
          "different, less-specific error than the first",
          "[pg][result_set][async][reeval][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "poisoned-twice-reevaled";
    cr.source_kind = std::string(source_kind::kTarQuery);
    cr.source_payload = std::string(R"({"sql":"SELECT 1","junk":)") + nested_array(40) + "}";
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    int status1 = 0;
    auto body1 = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status1);
    CHECK(status1 == 400);
    REQUIRE(body1.contains("error"));
    const std::string msg1 = body1["error"]["message"].get<std::string>();
    CHECK(msg1.find("has been discarded") != std::string::npos);

    // The row is healed now (a live-but-empty {"note": ...} payload with no
    // "sql" key), so this second call takes a completely different refusal
    // path -- "original carries no SQL", never the depth guard again.
    int status2 = 0;
    auto body2 = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status2);
    CHECK(status2 == 400);
    REQUIRE(body2.contains("error"));
    const std::string msg2 = body2["error"]["message"].get<std::string>();
    CHECK(msg2.find("carries no SQL") != std::string::npos);

    CHECK(msg1 != msg2);
}

// #4540 (BLOCKING finding 2 route-level coverage): the /re-eval route must
// never claim the poisoned payload "has been discarded" when the underlying
// heal_poisoned_payload write did not actually happen. Simulated the same
// way as the dedicated store-level race test (test_result_set_store.cpp): a
// BEFORE UPDATE trigger deletes the row instead of letting heal's own UPDATE
// apply, so from the route's own depth-check read the row looks present and
// poisoned, and by the time the store's UPDATE runs it is already gone -- the
// same window a real concurrent delete_set/GC sweep opens.
TEST_CASE("re-eval: a heal that loses the race to a concurrent delete is a "
          "different 400 body and a result_set.heal|failure audit, never success",
          "[pg][result_set][async][reeval][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    CreateRequest cr;
    cr.owner_principal = "operator-1";
    cr.name = "vanishes-mid-heal";
    cr.source_kind = std::string(source_kind::kTarQuery);
    cr.source_payload = std::string(R"({"sql":"SELECT 1","junk":)") + nested_array(40) + "}";
    auto seeded = h.store->create_materialized(cr, {});
    REQUIRE(seeded.has_value());

    exec_sql(db.dsn(),
             "CREATE OR REPLACE FUNCTION test_4540_route_vanish_mid_heal() RETURNS trigger AS $$ "
             "BEGIN DELETE FROM result_set_store.result_sets WHERE id = OLD.id; RETURN NULL; "
             "END; $$ LANGUAGE plpgsql");
    exec_sql(db.dsn(), "CREATE TRIGGER test_4540_route_vanish_mid_heal BEFORE UPDATE ON "
                        "result_set_store.result_sets FOR EACH ROW EXECUTE FUNCTION "
                        "test_4540_route_vanish_mid_heal()");

    int status = 0;
    auto body = h.post("/api/v1/result-sets/" + seeded->id + "/re-eval", "", status);
    CHECK(status == 400);
    CHECK(h.calls.empty());
    // Distinct wording from the successful-heal 400 above ("has been
    // discarded") -- the caller must never be told a write happened that
    // didn't.
    REQUIRE(body.contains("error"));
    REQUIRE(body["error"].contains("message"));
    CHECK(body["error"]["message"].get<std::string>().find("heal attempt failed") !=
          std::string::npos);

    exec_sql(db.dsn(),
             "DROP TRIGGER test_4540_route_vanish_mid_heal ON result_set_store.result_sets");
    exec_sql(db.dsn(), "DROP FUNCTION test_4540_route_vanish_mid_heal()");

    // The row is genuinely gone -- the trigger's own DELETE really ran.
    CHECK_FALSE(get_ok(*h.store, seeded->id).has_value());

    const bool heal_failure_audited =
        std::any_of(h.audits.begin(), h.audits.end(), [&](const AsyncHarness::AuditCall& a) {
            return a.action == "result_set.heal" && a.result == "failure";
        });
    CHECK(heal_failure_audited);
    const bool heal_success_audited =
        std::any_of(h.audits.begin(), h.audits.end(), [&](const AsyncHarness::AuditCall& a) {
            return a.action == "result_set.heal" && a.result == "success";
        });
    CHECK_FALSE(heal_success_audited);
}

// ═══════════════════════════════════════════════════════════════════════════
// #4306 PR-B: findings 1 + 3 (+ #4307 finding 2) — a degraded ResultSetStore
// read must fail closed (503/500), never silently read as "empty"/"under
// quota" on a store the async producers dispatch real commands through.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("from-tar-query: a degraded quota pre-check fails closed BEFORE any dispatch — "
          "nothing reaches an agent, the execution is cancelled, audit shows the failure "
          "(#4306 finding 1)",
          "[pg][result_set][async][tar][security][4306]") {
    // No parent_id: a supplied parent_id would hit resolve_owned_parent's own
    // DB read first and 503 there instead, before ever reaching the quota
    // pre-check under test.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    AsyncHarness h(short_lock_pool);

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
    REQUIRE(j.contains("error"));
    const std::string msg = j["error"]["message"].get<std::string>();
    CHECK(msg.find("could not verify the per-owner result-set quota") != std::string::npos);
    CHECK(msg.find("nothing was dispatched") != std::string::npos);
    // #4306/#4307 adversarial review (Kimi + Codex): REST's fail-closed 503
    // dropped the retry hint the MCP twin carries for the identical fault
    // (kMcpStoreFaultRetryMs) - REST was the outlier. Nothing was dispatched
    // here, so this IS safe to retry.
    REQUIRE(j["error"]["retry_after_ms"].is_number());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);

    // The load-bearing assertion: dispatch never fired.
    CHECK(h.calls.empty());

    // yuzu_result_set_quota_rejected is untouched -- this is a store-fault
    // refusal, not a quota rejection.
    CHECK(h.metrics.counter("yuzu_result_set_quota_rejected").value() == 0.0);

    bool saw_failure_audit = false;
    for (const auto& a : h.audits)
        if (a.action == "result_set.create" && a.result == "failure" &&
            a.detail.find("quota_check_degraded") != std::string::npos)
            saw_failure_audit = true;
    CHECK(saw_failure_audit);

    // The execution row was cancelled, not left running forever. Extract the
    // execution_id the handler minted from the error message.
    auto pos = msg.find("execution_id=");
    REQUIRE(pos != std::string::npos);
    const std::string exec_id = msg.substr(pos + std::string("execution_id=").size());
    auto exec = h.tracker->get_execution(exec_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    // No pending row was ever created.
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: a DbError from create_pending AFTER a successful dispatch maps "
          "to 500, not 400 — a server fault after real agents were already reached is not a "
          "client error (#4306 fold-in B)",
          "[pg][result_set][async][tar][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    // Short lock_timeout_ms (established technique) so the deliberately-held
    // lock below fails the blocked query deterministically and fast, rather
    // than waiting out the default 10s lock_timeout.
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    // Take the table lock INSIDE the fake dispatch closure — strictly AFTER
    // the (already-passed) quota pre-check and BEFORE create_pending's own
    // INSERT, so the pre-check succeeds and dispatch genuinely fires before
    // the fault lands.
    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    h.on_dispatch = [&] {
        REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
                PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(locker.get(),
                                "LOCK TABLE result_set_store.result_sets IN ACCESS "
                                "EXCLUSIVE MODE",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    };

    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","name":"foldinb"})", status);
    REQUIRE(status == 500);
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["message"].get<std::string>().find(
              "result-set store unavailable after dispatch already succeeded") !=
          std::string::npos);
    // gov-4306-S4/S9: distinct token from the pre-dispatch quota-check-
    // degraded 503 (RESULT_SET_STORE_UNAVAILABLE). An agentic caller
    // pattern-matching the message text alone must not conflate "safe to
    // retry" with "already dispatched, never re-send". Also carries
    // execution_id, matching MCP's identical branch.
    CHECK(j["error"]["message"].get<std::string>().starts_with(
        "RESULT_SET_STORE_FAULT_AFTER_DISPATCH:"));
    CHECK(j["error"]["message"].get<std::string>().find(
              "execution_id=" + h.calls[0].execution_id) != std::string::npos);
    // #4306/#4307 adversarial review: this branch is DELIBERATELY left
    // non-retryable (unlike the five 503 pre-dispatch branches above/below) -
    // a real dispatch already succeeded here, so a positive retry hint would
    // tell a caller to re-send a command that already reached the fleet.
    // Regression-lock the null.
    REQUIRE(j["error"].contains("retry_after_ms"));
    CHECK(j["error"]["retry_after_ms"].is_null());

    // Dispatch DID fire -- the whole point of this branch: create_pending
    // failed AFTER a real command already reached agents.
    REQUIRE(h.calls.size() == 1);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    // The execution was cancelled, not left running forever.
    auto exec = h.tracker->get_execution(h.calls[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");

    // No pending row was ever persisted (the whole point of this branch).
    std::string next;
    CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-inventory-query: a degraded members-table read on the parent-narrowing loop "
          "refuses rather than materialising an unnarrowed result set (#4306 finding 3)",
          "[pg][result_set][async][inventory][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());
    AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
    auto parent = h.seed_materialized("members-parent", {"a1", "a2"});

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_set_members IN ACCESS "
                            "EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-inventory-query",
                    R"({"name":"x","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 503);
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["message"].get<std::string>().find(
              "could not read the parent set's members") != std::string::npos);
    // #4306/#4307 adversarial review: retry hint parity with the MCP twin.
    REQUIRE(j["error"]["retry_after_ms"].is_number());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);

    bool saw_failure_audit = false;
    for (const auto& a : h.audits)
        if (a.action == "result_set.create" && a.result == "failure" &&
            a.detail.find("store_degraded") != std::string::npos)
            saw_failure_audit = true;
    CHECK(saw_failure_audit);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    // No new result set was created -- only the seeded parent exists.
    std::string next;
    auto sets = h.store->list_by_owner("operator-1", "", 50, next);
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].id == parent);
}

TEST_CASE("GET /api/v1/result-sets: a degraded read refuses (503), never a 200 with an "
          "empty array indistinguishable from a genuinely empty owner (#4306/#4307 "
          "finding 2)",
          "[pg][result_set][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    h.seed_materialized("has-one", {"a"});

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto res = h.sink.Get("/api/v1/result-sets");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE(j.is_object());
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["message"].get<std::string>().find("could not list result sets") !=
          std::string::npos);
    // #4306/#4307 adversarial review: retry hint parity with the MCP twin.
    REQUIRE(j["error"]["retry_after_ms"].is_number());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

TEST_CASE("GET /api/v1/result-sets/{id}/members: a degraded members-table read refuses "
          "(503), never a 200 with an empty array (#4306 finding 3 / #4307 finding 2)",
          "[pg][result_set][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto id = h.seed_materialized("has-members", {"a", "b"});

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_set_members IN ACCESS "
                            "EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // load_owned's own get() reads `result_sets`, NOT `result_set_members`, so
    // it passes under this lock -- the members read itself is what's under
    // test here (distinct from the list/lineage tests, which lock
    // result_sets and so exercise load_owned's PRE-EXISTING gate instead;
    // see the lineage test below for the discrimination caveat).
    auto res = h.sink.Get("/api/v1/result-sets/" + id + "/members");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE(j.is_object());
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["message"].get<std::string>().find("could not read result-set members") !=
          std::string::npos);
    // #4306/#4307 adversarial review: retry hint parity with the MCP twin.
    REQUIRE(j["error"]["retry_after_ms"].is_number());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

TEST_CASE("GET /api/v1/result-sets/{id}/lineage: a degraded result_sets read refuses (503) "
          "-- NOTE: this exercises load_owned's PRE-EXISTING ownership-check gate (get() also "
          "reads result_sets), not lineage_checked specifically, since both hit the same "
          "table under a table-wide lock and load_owned runs first. lineage_checked's own "
          "DbError branch is covered directly in test_result_set_store.cpp; this test proves "
          "the ROUTE as a whole stays fail-closed end to end (#4306 finding 3 / #4307 "
          "finding 2)",
          "[pg][result_set][security][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto id = h.seed_materialized("has-lineage", {"a"});

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto res = h.sink.Get("/api/v1/result-sets/" + id + "/lineage");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE(j.is_object());
    REQUIRE(j.contains("error"));
    // load_owned's own message, not lineage_checked's -- see the TEST_CASE
    // name for why.
    CHECK(j["error"]["message"].get<std::string>().find(
              "could not verify result-set ownership") != std::string::npos);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}
