/**
 * test_policy_evaluator.cpp — Unit tests for the compliance check -> verdict
 * pipeline (PolicyEvaluator).
 *
 * Strategy: real PolicyStore (Postgres, ADR-0056) / InstructionStore (Postgres,
 * ADR-0058) / ResponseStore (Postgres, ADR-0039) / ManagementGroupStore
 * (Postgres, ADR-0042) on a shared pool + per-test temp files, target
 * resolution via a static management group (so no AgentRegistry is needed),
 * a FAKE dispatch_fn that synchronously seeds canned ResponseStore rows
 * under the execution_id it is handed (keyed by agent + plugin), and an
 * injectable clock to drive the grace window deterministically.
 *
 * The final TEST_CASE is the regression test for ADR-0056's headline design:
 * two PolicyEvaluator instances sharing one PolicyStore assert exactly one
 * dispatch per policy per interval (the durable claim_due_policies lease),
 * and that only the dispatching instance ever collects its own in-flight
 * check (the other instance's tick claims nothing for it, by design — see
 * policy_store.hpp's header comment on why collect stays per-replica).
 */

#include "agent_registry.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "policy_evaluator.hpp"
#include "policy_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// ResponseStore is a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical
// setup). PolicyStore (ADR-0056) is constructed against the SAME pool/DB
// (a different schema namespace, `policy_store` vs `response_store` —
// exactly how they coexist in production's one shared pg_pool_); it is not
// part of this template's pre-baked setup, so each fresh clone pays its own
// migration on first construction — a fine trade-off here (this file is not
// benchmarking migration cost), and avoids adding PolicyStore's migration
// cost to every OTHER test file that shares the "responsestore" key.
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// A result envelope parse_result understands: columns + rows arrays.
std::string out_json(const std::string& col, const std::string& val) {
    return R"({"columns":[{"name":")" + col + R"(","type":"string"}],"rows":[{")" + col +
           R"(":")" + val + R"("}]})";
}

// Two-column variant for expressions that reference two fields.
std::string out_json2(const std::string& c1, const std::string& v1, const std::string& c2,
                      const std::string& v2) {
    return R"({"columns":[{"name":")" + c1 + R"(","type":"string"},{"name":")" + c2 +
           R"(","type":"string"}],"rows":[{")" + c1 + R"(":")" + v1 + R"(",")" + c2 + R"(":")" +
           v2 + R"("}]})";
}

// A structurally-valid result envelope (#2437-class depth guard regression)
// whose single row value is a JSON array nested `depth` levels deep, e.g.
// {"columns":[{"name":"col","type":"string"}],"rows":[{"col":[[[[...]]]]}]}.
// Built as a flat repeated-bracket string -- NEVER anywhere near the real
// ~100,000-level attack depth this guard exists to reject; `depth` in these
// tests is 35, comfortably past kMcpMaxJsonDepth (32) while staying a trivial
// allocation. Before the fix, this reaches parse_result's structured-result
// branch, which calls nlohmann::json::dump() on the non-string "col" value --
// the unboundedly-recursive call the guard exists to prevent ever reaching.
std::string out_json_deep(const std::string& col, int depth) {
    return R"({"columns":[{"name":")" + col + R"(","type":"string"}],"rows":[{")" + col + R"(":)" +
           std::string(static_cast<size_t>(depth), '[') +
           std::string(static_cast<size_t>(depth), ']') + R"(}]})";
}

struct Harness {
    // PolicyStore (ADR-0056) and InstructionStore (ADR-0058) are both migrated
    // Postgres stores now — share the same pool/database as ResponseStore
    // below (schema-per-store, ADR-0008).
    PolicyStore ps;
    InstructionStore is;
    ResponseStore rs;
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;

    int64_t fake_now{1000};
    int dispatch_calls{0};
    std::vector<std::string> dispatched_plugins;
    // canned[agent + "|" + plugin] -> (status, output)
    std::map<std::string, std::pair<int, std::string>> canned;
    // HA WS-3 3.4 review B1 regression harness: agent ids the fake
    // dispatch_fn treats as quarantine-denied (ConfinedDispatchOutcome::
    // denied_quarantined) rather than delivered or not_sent -- a THIRD way a
    // claimed target can fail to be delivered, distinct from both.
    std::set<std::string> quarantined;
    // #5294: agent ids the fake dispatch_fn withholds via
    // ConfinedDispatchOutcome::kill_switched_os (per-OS kill switch OFF).
    std::set<std::string> kill_switched_os;
    // WS-4 4.2b Task D (#3424/#3511 under-count): when set, the fake
    // dispatch_fn returns `route_unreadable` for the WHOLE batch (mirroring
    // ArmDispatchResult::route_unreadable's systemic-directory-read-failure
    // shape) instead of walking `quarantined`/`canned` -- exercises
    // compute_delivered's `route_unreadable` branch the same way
    // `containment_unreadable` is exercised in deployment_engine.cpp.
    bool route_unreadable_outcome{false};
    // #5294: the fake dispatch_fn returns `os_gate_unreadable` for the WHOLE
    // batch (degraded presence read: sent == 0, no per-id data), mirroring
    // the real ladder's early refusal.
    bool os_gate_unreadable_outcome{false};
    // WS-4 4.2b Task D fix regression: agent ids the fake dispatch_fn marks
    // `not_sent` while ALSO stamping `outcome.route_unreadable = true`,
    // alongside genuinely-sent siblings in the SAME batch -- mirrors a real
    // degraded directory read on a MIXED cohort (a locally-connected device
    // is still delivered; a directory-only device lands in not_sent).
    // Deliberately orthogonal to `route_unreadable_outcome` above, which
    // short-circuits the WHOLE batch and must keep doing exactly that for
    // its own (still-passing) test.
    std::set<std::string> route_degraded_agents;

    std::string group_id;

    explicit Harness(pg::PgPool& pool) : ps(pool), is(pool), rs(pool) {
        auto def = [&](const std::string& id, const std::string& plugin) {
            InstructionDefinition d;
            d.id = id;
            d.name = id;
            d.version = "1.0.0";
            d.type = "question";
            d.plugin = plugin;
            d.action = "run";
            d.enabled = true;
            REQUIRE(is.create_definition(d).has_value());
        };
        def("test.check", "checkp");
        def("test.fix", "fixp");
        def("test.verify", "verifyp");

        ManagementGroup g;
        g.name = "grp";
        g.membership_type = "static";
        auto gid = mg.create_group(g);
        REQUIRE(gid.has_value());
        group_id = *gid;
        REQUIRE(mg.add_member(group_id, "agentA").has_value());
        REQUIRE(mg.add_member(group_id, "agentB").has_value());
    }

    PolicyEvaluator::Deps deps() {
        PolicyEvaluator::Deps d;
        d.policy_store = &ps;
        d.instruction_store = &is;
        d.response_store = &rs;
        d.registry = nullptr;
        d.tag_store = nullptr;
        d.custom_properties_store = nullptr;
        d.mgmt_group_store = &mg;
        d.grace_seconds = 15;
        d.default_interval_seconds = 3600;
        d.fixing_stale_seconds = 1800;
        d.now_fn = [this] { return fake_now; };
        d.dispatch_fn = [this](const std::string& plugin, const std::string&,
                               const std::vector<std::string>& agents, const std::string&,
                               const std::unordered_map<std::string, std::string>&,
                               const std::string& execid) -> yuzu::server::ConfinedDispatchOutcome {
            ++dispatch_calls;
            dispatched_plugins.push_back(plugin);
            yuzu::server::ConfinedDispatchOutcome outcome;
            outcome.command_id = "cmd-" + execid;
            if (os_gate_unreadable_outcome) {
                outcome.os_gate_unreadable = true;
                return outcome;
            }
            if (route_unreadable_outcome) {
                // Mirrors the real chokepoint: a degraded GatewayRouteStore
                // directory read means nothing in the batch was individually
                // evaluated, so `sent` stays 0 and no per-id fields are
                // populated -- only the systemic flag.
                outcome.route_unreadable = true;
                return outcome;
            }
            for (const auto& a : agents) {
                if (route_degraded_agents.count(a)) {
                    // The batched directory consult degraded for THIS id
                    // specifically -- the arm walk still ran (unlike
                    // route_unreadable_outcome's whole-batch short-circuit
                    // above), so a sibling agent in the same call can still
                    // land in `sent` below. Mirrors ArmDispatchResult's real
                    // shape: `route_unreadable` is a flag on the outcome, not
                    // a per-id gate.
                    outcome.route_unreadable = true;
                    outcome.not_sent.push_back(a);
                    continue;
                }
                if (quarantined.count(a)) {
                    // Mirrors dispatch_confined_arms.hpp's real quarantine-gate
                    // denial: a claimed target the #881 gate refuses BEFORE the
                    // per-id send attempt -- distinct from not_sent (delivery
                    // attempted, failed) and from a canned-absent lookup below.
                    outcome.denied_quarantined.push_back(a);
                    ++outcome.denied_quarantined_count;
                    continue;
                }
                if (kill_switched_os.count(a)) {
                    outcome.kill_switched_os.push_back(a);
                    ++outcome.kill_switched_os_count;
                    continue;
                }
                auto it = canned.find(a + "|" + plugin);
                if (it == canned.end()) {
                    // HA WS-3 3.4 (mandatory test-harness fix): a canned-absent
                    // agent now simulates an offline/unreachable device -- the
                    // DELIVERY itself failed (ArmDispatchResult::not_sent), not
                    // merely "dispatched but never responded". Previously this
                    // fake left `.not_sent` permanently empty, so any
                    // release-on-offline assertion against `remediate()`'s
                    // delivered-set logic would have passed vacuously (nothing
                    // ever landed in not_sent to exercise it). Check/verify
                    // phases discard `.outcome` entirely (only remediate()
                    // reads it), so this has no effect on their "non-responder
                    // -> unknown" behaviour.
                    outcome.not_sent.push_back(a);
                    continue;
                }
                StoredResponse r;
                r.instruction_id = "test";
                r.agent_id = a;
                r.status = it->second.first;
                r.output = it->second.second;
                r.plugin = plugin;
                r.execution_id = execid;
                r.timestamp = fake_now;
                rs.store(r);
                ++outcome.sent;
            }
            return outcome;
        };
        return d;
    }

    // Author a fragment + policy bound to the static group. Returns policy id.
    std::string author(const std::string& check_cel, bool with_fix = false,
                       int64_t interval_seconds = 0) {
        std::string frag = std::string("apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n") +
                           "spec:\n  check:\n    instruction: test.check\n    compliance: \"" +
                           check_cel + "\"\n";
        if (with_fix) {
            frag += "  fix:\n    instruction: test.fix\n";
            frag += "  postCheck:\n    instruction: test.verify\n    compliance: \"result.fixed "
                    "== 'yes'\"\n";
        }
        auto fid = ps.create_fragment(frag);
        REQUIRE(fid.has_value());

        std::string pol = std::string("apiVersion: yuzu.io/v1alpha1\nkind: Policy\n") + "spec:\n  fragment: " +
                          *fid + "\n  managementGroups:\n    - " + group_id + "\n";
        if (interval_seconds > 0) {
            pol += "  triggers:\n    - type: interval\n      interval_seconds: " +
                   std::to_string(interval_seconds) + "\n";
        }
        auto pid = ps.create_policy(pol);
        REQUIRE(pid.has_value());
        return *pid;
    }

    std::string status_of(const std::string& pid, const std::string& agent) {
        auto s = ps.get_agent_status(pid, agent);
        if (!s || !*s)
            return "<none>";
        return (*s)->status;
    }
};

} // namespace

TEST_CASE("policy evaluator: compliant + non_compliant verdicts (multi-agent fan-out)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20; // past grace
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
}

TEST_CASE("policy evaluator: an operator evaluate_now completes even when the due-policy "
          "dispatch is fenced off-leader (WS-3 3.2, PR #4134)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    // An operator evaluate_now() is accepted on this replica (both operator paths are
    // ungated and run on whichever replica received the call).
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20; // past grace

    // Tick with the fenced-leader gate FALSE (this replica is not the leader), exactly
    // as server.cpp does via leader_gate_permits. The completion half — collect_ready()
    // — MUST still run, or the operator's evaluate_now strands with no terminal verdict.
    // This is the two-dispatch-planes contract the gate-the-whole-tick bug violated.
    ev.tick(/*dispatch_due_allowed=*/false);

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
}

TEST_CASE("policy evaluator: the due-policy dispatch is SUPPRESSED under tick(false) and runs "
          "under tick(true) (WS-3 3.2 gate direction, PR #4134)",
          "[pg][policy][evaluator]") {
    // The other half of the tick(bool) contract (adversarial review K1): the fenced
    // scheduling half must NOT run off-leader. Without this, a future refactor that
    // drops/inverts `if (dispatch_due_allowed)` passes every other test yet resumes
    // due-policy dispatch on non-leaders.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "b")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty()); // dispatch #1 (seeds the interval)
    CHECK(h.dispatch_calls == 1);
    h.fake_now += 4000; // default interval (3600s) elapsed -> the policy is now DUE

    // Non-leader tick: dispatch_due() must NOT run — no new dispatch despite being due.
    ev.tick(/*dispatch_due_allowed=*/false);
    CHECK(h.dispatch_calls == 1);

    // Leader tick: dispatch_due() claims the due policy and dispatches.
    ev.tick(/*dispatch_due_allowed=*/true);
    CHECK(h.dispatch_calls == 2);
}

TEST_CASE("policy evaluator: evaluate_now does not dispatch when record_dispatch fails "
          "(adversarial review, round 2)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // Drop the durable claim table out from under the live store — a
    // reproducible stand-in for a transient connection loss / botched
    // migration. record_dispatch() (called first inside evaluate_now())
    // must now fail, and evaluate_now() must NOT proceed to dispatch: a
    // dispatch that runs without a durable stamp is exactly the "next
    // automatic tick sees no row and re-claims immediately" bug this
    // store's dispatch-claim design exists to prevent.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_dispatch_state CASCADE")};
        REQUIRE(r.ok());
    }

    PolicyEvaluator ev(h.deps());
    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value()); // degraded, never a silent "no targets" empty string
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("policy evaluator: evaluate_now degrades (not a silent no-op) when the fragment "
          "table is unavailable (governance, 2026-08-24)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // record_dispatch() (the durable claim stamp) touches only
    // policy_dispatch_state and must still succeed here — this test targets
    // kickoff_check()'s OWN get_fragment() read, which used to collapse a
    // degraded read into the same "" a genuine "no check instruction /
    // matches no agents" no-op returns, so a false REST 409 masked what was
    // actually a 503.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_fragments CASCADE")};
        REQUIRE(r.ok());
    }

    PolicyEvaluator ev(h.deps());
    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value());
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("policy evaluator: non-responder -> unknown, plugin failure -> error",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {2, ""}; // FAILURE status -> error
    // agentB intentionally absent -> non-responder -> unknown
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "error");
    CHECK(h.status_of(pid, "agentB") == "unknown");
}

TEST_CASE("policy evaluator: InstructionStore DB error on dispatch is distinct from unknown "
          "instruction (ADR-0058: must not collapse a genuine failure into the same skip)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // A second InstructionStore backed by an unreachable pool simulates a genuine DB failure —
    // swapped in for this test only, in place of the harness's normally-open store.
    PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    REQUIRE_FALSE(broken_pool.valid());
    InstructionStore broken_is{broken_pool};
    REQUIRE_FALSE(broken_is.is_open());

    auto deps = h.deps();
    deps.instruction_store = &broken_is;
    PolicyEvaluator ev(deps);

    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value()); // degraded, never a silent "no targets" empty string
    CHECK(h.dispatch_calls == 0); // never reached dispatch_fn — failed resolving the definition
    // gov Gate 8 (#4981 PR-1, security-guardian): lock the genericized message
    // itself, not just has_value() — this is the same
    // kInstructionStoreDbErrorPrefix-tagged failure the fix for the earlier
    // BLOCKING finding closed (kickoff_check now runs dispatch_instruction's
    // error through genericize_db_error before wrapping it), so a future
    // regression re-threading the raw "db_error: store not open" string
    // through to a caller must fail this exact assertion, not just the
    // has_value() check above.
    CHECK(result.error() == "kickoff_check degraded for " + pid + ": service unavailable");
}

TEST_CASE("policy evaluator: missing CEL field resolves empty -> non_compliant",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // Success status, but the result has no 'hostname' column the CEL references.
    // CEL resolves a missing result field to "" (not an error), so
    // `result.hostname != ''` is `'' != ''` -> false -> non_compliant. Missing
    // data is treated as non-compliant, NOT as an evaluation error.
    h.canned["agentA|checkp"] = {1, out_json("other", "x")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "non_compliant");
}

TEST_CASE("policy evaluator: CEL evaluation error -> error", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // Division by zero yields a top-level CEL evaluation error (monostate ->
    // eval_error), which the evaluator must surface as status "error", distinct
    // from a non-compliant verdict. (A comparison like `... > 1` would coerce
    // the monostate to the string "null" and mask the error, so the bare
    // arithmetic expression is the deterministic eval_error trigger.)
    h.canned["agentA|checkp"] = {1, out_json2("num", "10", "den", "0")};
    auto pid = h.author("result.num / result.den");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: depth-exceeded r.output -> error, never compliant "
          "(#2437-class guard, fail-closed)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // agentA: legitimate, shallow, compliant response for the SAME policy/CEL
    // -- the positive control proving the guard does not disturb the happy
    // path.
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    // agentB: a structurally-valid result envelope whose "hostname" value
    // nests past the depth guard -- see out_json_deep's own comment for why
    // 35 levels is a safe reachability proxy, not the real attack depth.
    h.canned["agentB|checkp"] = {1, out_json_deep("hostname", 35)};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20; // past grace
    ev.tick(true);

    // Positive control: the shallow response for the SAME policy/CEL still
    // evaluates normally.
    CHECK(h.status_of(pid, "agentA") == "compliant");

    // The depth-exceeded response must land on the evaluator's existing
    // "could not evaluate" outcome ("error", the same status a failed check
    // or a misconfigured empty-CEL policy already produces above), and must
    // explicitly NOT be "compliant" -- an agent deliberately reporting
    // unparseable-by-depth output must not be able to force a false
    // compliant verdict.
    const std::string agentB_status = h.status_of(pid, "agentB");
    CHECK(agentB_status == "error");
    CHECK(agentB_status != "compliant");
}

TEST_CASE("policy evaluator: a depth-poisoned response cannot ride along with a "
          "legitimate non_compliant sibling into auto-selected remediation "
          "(#2437-class guard, fail-closed)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // agentA: legitimate non_compliant response.
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")};
    // agentB: depth-exceeded poisoned response. Must resolve to "error" --
    // never "non_compliant" (which would make it eligible for the
    // auto-selected remediation below, i.e. authorize a remediation action
    // off a response this evaluator could not actually parse) and never
    // "compliant" (which would silently suppress remediation for a
    // genuinely-unevaluable device).
    h.canned["agentB|checkp"] = {1, out_json_deep("hostname", 35)};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};
    h.canned["agentB|fixp"] = {1, "ok"}; // wired up, but must never be dispatched to

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "non_compliant");
    CHECK(h.status_of(pid, "agentB") == "error");

    // remediate() with an empty agent list auto-selects every agent whose
    // status is exactly "non_compliant" (get_policy_agent_statuses walk).
    // The poisoned agentB's "error" status must be excluded from that
    // selection entirely -- the overall remediation batch must reflect
    // "could not fully evaluate" for agentB rather than silently folding it
    // in as either a pass or a remediation target.
    const int dispatch_calls_before = h.dispatch_calls;
    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1); // agentA only -- agentB was never selected
    CHECK(h.dispatch_calls == dispatch_calls_before + 1); // one fix dispatch, agentA only
    CHECK(h.dispatched_plugins.back() == "fixp");

    // agentB was never targeted: still sitting at "error", never moved to
    // "fixing".
    CHECK(h.status_of(pid, "agentB") == "error");
}

TEST_CASE("policy evaluator: interval throttles re-dispatch", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "b")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty()); // dispatch #1
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 20;
    ev.tick(true); // collect only; interval (3600s) not elapsed -> no new dispatch
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 4000;
    ev.tick(true); // interval elapsed -> dispatch #2
    CHECK(h.dispatch_calls == 2);
}

TEST_CASE("policy evaluator: empty compliance CEL -> error (no false compliant)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // A successful check whose fragment defines an EMPTY check_compliance. The CEL
    // layer treats empty as always-compliant; the evaluator must NOT report this
    // as compliant (it would be false assurance) — it surfaces as error instead.
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    auto pid = h.author(/*check_cel=*/"");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: remediate refuses a 4th call once the fix retry cap is "
          "exhausted (HA WS-3 3.4 — refused at claim time, not dispatched-then-error)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Drive remediation with an explicit (in-scope) agent list to the cap:
    // three successful, DELIVERED remediate() calls each mark the agent
    // 'fixing', and PolicyStore.claim_remediation's own WHERE guard
    // (kMaxFixAttempts=3) now refuses a 4th attempt at CLAIM time, before
    // any dispatch — see below.
    //
    // Governance UP-3 (2026-08-24): remediate() refuses a second call while
    // the prior attempt's FixWait is still outstanding (closes a
    // double-dispatch / double-attempt-count hazard), so each attempt must
    // mature — advance time past grace, tick() — before the next call. This
    // is the realistic shape anyway: an operator waits for one fix attempt to
    // resolve before retrying.
    for (int i = 0; i < 3; ++i) {
        auto rr = ev.remediate(pid, {"agentA"});
        REQUIRE(rr.ok);
        // Mature this attempt's FixWait (clearing it from in_flight_ AND
        // releasing the durable claim — HA WS-3 3.4) so the NEXT remediate()
        // call isn't refused as already-in-flight.
        h.fake_now += 20;
        ev.tick(true);
    }

    // HA WS-3 3.4: claim_remediation's own WHERE guard now refuses a target
    // whose fix_attempt_count has already hit the cap BEFORE any dispatch is
    // attempted — a behavioural change from the pre-CAS design, where a 4th
    // remediate() call dispatched the fix a wasted 4th time and only THEN
    // got its status forced to 'error' by update_agent_status's own cap
    // CASE (see this change's changelog.d fragment). The fix is never even
    // sent now, so there is no forced-to-'error' write to observe here —
    // the cap having tripped is instead proven by the claim refusal itself
    // and the absence of a 4th dispatch.
    const int calls_before_4th = h.dispatch_calls;
    auto rr4 = ev.remediate(pid, {"agentA"});
    CHECK_FALSE(rr4.ok);
    CHECK_FALSE(rr4.degraded); // a business rejection (cap exhausted), not a store degrade
    CHECK(rr4.error.find("already in flight") != std::string::npos);
    CHECK(h.dispatch_calls == calls_before_4th); // refused at claim time — no 4th dispatch
}

TEST_CASE("policy evaluator: remediate refuses a second call while a FixWait is already "
          "in flight for the policy (governance UP-3, 2026-08-24)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr1 = ev.remediate(pid, {"agentA"});
    REQUIRE(rr1.ok);
    const int calls_after_first = h.dispatch_calls;

    // NO tick() here — the first call's durable PolicyStore claim
    // (HA WS-3 3.4, `claim_remediation`) is still live (collect_ready()'s
    // FixWait maturation is the only thing that releases it, and its grace
    // window hasn't elapsed). A second call for the SAME policy must be
    // refused rather than dispatching another fix and burning a second
    // attempt against the retry cap on top of the first.
    auto rr2 = ev.remediate(pid, {"agentA"});
    CHECK_FALSE(rr2.ok);
    CHECK_FALSE(rr2.degraded); // this is a business rejection, not a store degrade
    CHECK(rr2.error.find("already in flight") != std::string::npos);
    CHECK(h.dispatch_calls == calls_after_first); // no second dispatch happened
}

TEST_CASE("policy evaluator: two PolicyEvaluator instances sharing one store remediate a "
          "target exactly once (HA WS-3 3.4 durable claim)",
          "[pg][policy][evaluator][claim]") {
    // Regression for the double-dispatch/double-attempt-count hazard the
    // durable claim closes: `remediating_`/`ReservationGuard` (governance
    // UP-3, 2026-08-24) was a PER-INSTANCE in-memory guard — two independent
    // PolicyEvaluator instances (simulating two HA replicas) shared no state
    // at all, so a second instance targeting the SAME agent explicitly
    // (bypassing the non_compliant status filter, which the first call's own
    // 'fixing' write would otherwise narrow away before the second instance
    // ever ran) would previously double-dispatch the fix and
    // double-increment fix_attempt_count. Explicit `{"agentA"}` on BOTH
    // calls is required to exercise this: with an empty agent_ids list the
    // pre-existing non_compliant filter alone (get_policy_agent_statuses)
    // already excludes agentA once the first call's synchronous dispatch
    // marks it 'fixing' — sequential single-threaded execution means that
    // would pass even under the OLD, pre-claim code, so it would not be a
    // real regression test for the CAS.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    h.canned["agentA|fixp"] = {1, "ok"};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator evA(h.deps());
    PolicyEvaluator evB(h.deps());
    REQUIRE_FALSE(evA.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    evA.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    const int calls_before = h.dispatch_calls;
    auto rrA = evA.remediate(pid, {"agentA"});
    auto rrB = evB.remediate(pid, {"agentA"});

    REQUIRE(rrA.ok);
    CHECK_FALSE(rrB.ok);
    CHECK_FALSE(rrB.degraded); // a business rejection (already claimed), not a store degrade
    CHECK(rrB.error.find("already in flight") != std::string::npos);
    CHECK(h.dispatch_calls == calls_before + 1); // exactly one fix dispatch, not two

    // fix_attempt_count must be exactly 1 after the race above (not 2): TWO
    // more successful 'fixing' writes (matching the single-instance cap
    // test's total of three) bring it to kMaxFixAttempts=3, and a THIRD
    // attempt at that point must be refused AT CLAIM TIME (HA WS-3 3.4 —
    // claim_remediation's own WHERE guard, not update_agent_status's
    // dispatched-then-forced-to-'error' CASE). If the race above had
    // double-incremented (count already 2, not 1), only ONE more successful
    // write would be needed to reach the cap and this refusal would land
    // one iteration early with a dispatch still recorded for it.
    for (int i = 0; i < 2; ++i) {
        h.fake_now += 20;
        evA.tick(true); // mature the previous round's FixWait, releasing its claim
        auto rr = evA.remediate(pid, {"agentA"});
        REQUIRE(rr.ok);
    }
    h.fake_now += 20;
    evA.tick(true); // mature the 3rd round's FixWait, releasing its claim
    const int calls_before_cap = h.dispatch_calls;
    auto rr_capped = evA.remediate(pid, {"agentA"});
    CHECK_FALSE(rr_capped.ok);
    CHECK_FALSE(rr_capped.degraded);
    CHECK(rr_capped.error.find("already in flight") != std::string::npos);
    CHECK(h.dispatch_calls == calls_before_cap); // refused at claim time — no dispatch
}

TEST_CASE("policy evaluator: remediate releases the claim without burning a retry attempt "
          "when the fix send fails and re-remediate re-claims it",
          "[pg][policy][evaluator][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    // agentA is deliberately NOT canned for "fixp" -- the fake dispatch_fn
    // (fixed above) records it in outcome.not_sent, simulating an
    // offline/unreachable device at delivery time.

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Three remediate() attempts, each claiming then failing to deliver.
    // None of these may ever reach update_agent_status("fixing") -- if the
    // claim were released WITH an attempt burned, the fix_attempt_count cap
    // (kMaxFixAttempts=3) would already have tripped by the third of these.
    for (int i = 0; i < 3; ++i) {
        auto rr = ev.remediate(pid, {"agentA"});
        REQUIRE(rr.ok); // dispatch itself succeeded -- a valid execution_id was minted
        // Honest count (HA WS-3 3.4): nothing was DELIVERED (agentA landed in
        // outcome.not_sent), so agents == 0 even though ok == true and a
        // real dispatch call was made.
        CHECK(rr.agents == 0);
        // Nothing was delivered -- no FixWait entry queued, no status write.
        CHECK(h.status_of(pid, "agentA") == "non_compliant");
    }

    // Each of the three releases above must have cleared the claim (else
    // this call would be refused as "already in flight"). Wire up a real
    // delivery and confirm the claim is re-claimable and the fix actually
    // dispatches.
    h.canned["agentA|fixp"] = {1, "ok"};
    auto rr = ev.remediate(pid, {"agentA"});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1);
    // fix_attempt_count is still 0 going into this write (none of the three
    // not_sent releases incremented it) -- 'fixing', not the capped 'error'
    // three real increments would have produced.
    CHECK(h.status_of(pid, "agentA") == "fixing");
}

TEST_CASE("policy evaluator: a mixed delivered+quarantined remediate batch marks only the "
          "delivered target 'fixing' (HA WS-3 3.4 review B1)",
          "[pg][policy][evaluator]") {
    // Regression for review B1: compute_delivered's `not_delivered` set must
    // fold in outcome.denied_quarantined alongside outcome.not_sent -- a
    // claimed target the #881 quarantine gate refused must be released
    // without burning a retry attempt (like an offline/not_sent target),
    // never mistaken for delivered just because SOMETHING in the batch was
    // sent (outcome.sent > 0). The underlying by-value-move defect the B1
    // finding actually caught is now prevented at the type level (the audit
    // sink in server.cpp takes the outcome by const reference rather than by
    // value) -- this test locks the downstream compute_delivered() CONTRACT
    // itself: a mixed sent>0 batch must still classify each id correctly.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    // agentA is a normal delivered target; agentB is quarantined -- claimed
    // (it is a member of the policy's management group, so the
    // confused-deputy scope intersection admits it), but the fake
    // dispatch_fn denies it via denied_quarantined instead of sending or
    // canned-absent-not_sent'ing it. No evaluate_now()/check needed: an
    // explicit agent_ids list bypasses the non_compliant status filter
    // entirely (same shape as the two-instances claim test above).
    h.canned["agentA|fixp"] = {1, "ok"};
    h.quarantined.insert("agentB");

    PolicyEvaluator ev(h.deps());
    auto rr = ev.remediate(pid, {"agentA", "agentB"});
    REQUIRE(rr.ok);
    // Honest count: only agentA was actually delivered.
    CHECK(rr.agents == 1);

    // Delivered target: marked 'fixing' by the synchronous update_agent_status
    // call inside remediate() -- no tick() needed to observe it.
    CHECK(h.status_of(pid, "agentA") == "fixing");
    // Quarantined target: claimed (claim_remediation's fresh-INSERT branch
    // seeds an 'unknown' row to carry the claim) then released WITHOUT a
    // status write or a burned retry attempt -- it must NOT read 'fixing'.
    CHECK(h.status_of(pid, "agentB") == "unknown");

    // The quarantined target's claim must have been released (not left
    // dangling): a fresh remediate() naming only agentB, now un-quarantined
    // and wired up for delivery, re-claims and delivers it -- proving the
    // release actually happened rather than merely not writing 'fixing'.
    h.quarantined.erase("agentB");
    h.canned["agentB|fixp"] = {1, "ok"};
    auto rr2 = ev.remediate(pid, {"agentB"});
    REQUIRE(rr2.ok);
    CHECK(rr2.agents == 1);
    CHECK(h.status_of(pid, "agentB") == "fixing");
}

TEST_CASE("policy evaluator: a mixed delivered+kill_switched_os remediate batch marks only "
          "the delivered target 'fixing' and re-dispatches the withheld one once restored (#5294)",
          "[pg][policy][evaluator]") {
    // compute_delivered's `not_delivered` set must fold in
    // outcome.kill_switched_os: in a sent>0 batch the withheld id is absent
    // from `sent`, so without it the id reads as delivered and the
    // per-(policy,agent) claim is never re-attempted after the switch is
    // turned back on.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    h.canned["agentA|fixp"] = {1, "ok"};
    h.kill_switched_os.insert("agentB");

    PolicyEvaluator ev(h.deps());
    auto rr = ev.remediate(pid, {"agentA", "agentB"});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1);
    CHECK(h.status_of(pid, "agentA") == "fixing");
    CHECK(h.status_of(pid, "agentB") == "unknown");

    h.kill_switched_os.erase("agentB");
    h.canned["agentB|fixp"] = {1, "ok"};
    auto rr2 = ev.remediate(pid, {"agentB"});
    REQUIRE(rr2.ok);
    CHECK(rr2.agents == 1);
    CHECK(h.status_of(pid, "agentB") == "fixing");
}

TEST_CASE("policy evaluator: an os_gate_unreadable outcome leaves the WHOLE remediate batch "
          "undelivered and releases the claims for retry (#5294)",
          "[pg][policy][evaluator][claim]") {
    // compute_delivered has no dedicated os_gate_unreadable branch: the
    // refusal (sent == 0, no per-id data) is caught by the residual
    // `sent == 0 && claimed > not_delivered` rule. Pin that, so a later edit
    // to the residual cannot silently mark the batch delivered.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    h.os_gate_unreadable_outcome = true;
    PolicyEvaluator ev(h.deps());
    auto rr = ev.remediate(pid, {"agentA", "agentB"});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 0);
    CHECK(h.status_of(pid, "agentA") == "unknown");
    CHECK(h.status_of(pid, "agentB") == "unknown");

    h.os_gate_unreadable_outcome = false;
    h.canned["agentA|fixp"] = {1, "ok"};
    h.canned["agentB|fixp"] = {1, "ok"};
    auto rr2 = ev.remediate(pid, {"agentA", "agentB"});
    REQUIRE(rr2.ok);
    CHECK(rr2.agents == 2);
    CHECK(h.status_of(pid, "agentA") == "fixing");
    CHECK(h.status_of(pid, "agentB") == "fixing");
}

TEST_CASE("policy evaluator: a route_unreadable outcome leaves the WHOLE remediate batch "
          "undelivered and releases the claim for retry (WS-4 4.2b Task D, #3424/#3511 "
          "under-count)",
          "[pg][policy][evaluator][claim]") {
    // compute_delivered's `route_unreadable` branch must mirror
    // `containment_unreadable`'s exactly: nothing in the claimed batch was
    // individually evaluated, so the WHOLE batch is treated as not
    // delivered (agents == 0, no status write, no attempt burned, claim
    // released for a later retry) -- never partially settled.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    h.canned["agentA|fixp"] = {1, "ok"};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    h.route_unreadable_outcome = true;
    auto rr = ev.remediate(pid, {"agentA"});
    REQUIRE(rr.ok); // dispatch itself succeeded -- a valid execution_id was minted
    // Honest count: the directory read degraded, so nothing was DELIVERED.
    CHECK(rr.agents == 0);
    // Nothing was delivered -- no FixWait entry queued, no status write.
    CHECK(h.status_of(pid, "agentA") == "non_compliant");

    // The claim must have been released (not left dangling): a fresh
    // remediate() with the directory read recovered re-claims and delivers.
    h.route_unreadable_outcome = false;
    auto rr2 = ev.remediate(pid, {"agentA"});
    REQUIRE(rr2.ok);
    CHECK(rr2.agents == 1);
    CHECK(h.status_of(pid, "agentA") == "fixing");
}

TEST_CASE("policy evaluator: a MIXED route_unreadable remediate batch marks only the "
          "route-degraded target for retry, leaving the genuinely-delivered sibling "
          "'fixing' (WS-4 4.2b Task D fix regression, #3424/#3511 -- compute_delivered's "
          "early return on `route_unreadable` was REMOVED because a degraded directory "
          "read does NOT force outcome.sent == 0; the fix must not regress to reporting a "
          "genuinely-delivered device as undelivered just because a sibling in the same "
          "batch was route-degraded)",
          "[pg][policy][evaluator][claim]") {
    // Sibling of the WHOLE-batch route_unreadable case immediately above,
    // but MIXED: unlike `containment_unreadable` (which withholds every id
    // BEFORE any send, forcing sent == 0), a degraded GatewayRouteStore
    // directory read does not stop the arm walk -- a locally-connected
    // device in the same batch is still genuinely delivered while a
    // directory-only device lands in `not_sent`. If compute_delivered ever
    // regresses to its pre-fix `containment_unreadable || route_unreadable`
    // early return, this whole batch would come back not-delivered and
    // agentA -- ALREADY DELIVERED -- would be reported not-delivered,
    // silently re-dispatching a fix instruction that already ran.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    // agentA is genuinely delivered (canned response); agentB is the
    // directory-only device the SAME degraded directory read could not
    // resolve for this batch.
    h.canned["agentA|fixp"] = {1, "ok"};
    h.route_degraded_agents.insert("agentB");

    PolicyEvaluator ev(h.deps());
    auto rr = ev.remediate(pid, {"agentA", "agentB"});
    REQUIRE(rr.ok);
    // Honest count: only agentA was actually delivered -- NOT zero (the
    // pre-fix whole-batch-undelivered answer this test pins against).
    CHECK(rr.agents == 1);

    // Delivered target: marked 'fixing'.
    CHECK(h.status_of(pid, "agentA") == "fixing");
    // Route-degraded target: claimed, then released WITHOUT a status write
    // or a burned retry attempt -- must NOT read 'fixing'.
    CHECK(h.status_of(pid, "agentB") == "unknown");

    // The route-degraded target's claim was actually released (not left
    // dangling): re-remediating ONLY agentB, once the directory read
    // recovers, re-claims and delivers it.
    h.route_degraded_agents.erase("agentB");
    h.canned["agentB|fixp"] = {1, "ok"};
    auto rr2 = ev.remediate(pid, {"agentB"});
    REQUIRE(rr2.ok);
    CHECK(rr2.agents == 1);
    CHECK(h.status_of(pid, "agentB") == "fixing");
}

TEST_CASE("policy evaluator: verify dispatch failure -> error", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    h.canned["agentA|fixp"] = {1, "ok"};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);

    // Remove the verify instruction definition before the FixWait matures, so the
    // post-check dispatch resolves to an unknown instruction and returns "".
    REQUIRE(h.is.delete_definition("test.verify"));

    h.fake_now += 20;
    ev.tick(true); // collect FixWait -> verify dispatch fails -> error

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: manual remediation fix -> verify -> compliant",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant first
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Wire up the fix + verify responses, then remediate.
    h.canned["agentA|fixp"] = {1, "ok"};
    h.canned["agentA|verifyp"] = {1, out_json("fixed", "yes")};

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1);

    h.fake_now += 20;
    ev.tick(true); // collect FixWait -> dispatch verify
    h.fake_now += 20;
    ev.tick(true); // collect verify -> final verdict

    CHECK(h.status_of(pid, "agentA") == "compliant");
}

TEST_CASE("policy evaluator: remediation rejected when no fix_instruction",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/false);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick(true);
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    CHECK_FALSE(rr.ok);
    CHECK(rr.error.find("remediation pathway") != std::string::npos);
}

// ============================================================================
// Multi-replica dispatch claim (ADR-0056) — the regression test for the
// design this migration exists to settle.
// ============================================================================

TEST_CASE("policy evaluator: two instances sharing one store dispatch a policy exactly once "
          "per interval, and only the dispatcher collects it",
          "[pg][policy][evaluator][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    // A short, explicit interval so dispatch_due() actually claims on tick()
    // rather than relying on evaluate_now()'s bypass.
    auto pid = h.author("result.hostname != ''", /*with_fix=*/false, /*interval_seconds=*/300);

    // Two independent PolicyEvaluator instances, sharing the SAME
    // PolicyStore/DB (simulating two server replicas) but each with its OWN
    // in-memory in_flight_ (Deps carries no shared state between them) and
    // its OWN dispatch counter via a shared Harness dispatch_fn (dispatch
    // calls are counted process-wide in `h`, which is enough to prove
    // dedup — both evaluators funnel through the same fake dispatch_fn).
    PolicyEvaluator evA(h.deps());
    PolicyEvaluator evB(h.deps());

    // Both tick at the same logical moment. Only one may win the advisory
    // lock and claim the due policy; the other's dispatch_due() must claim
    // nothing this tick.
    evA.tick(true);
    evB.tick(true);
    CHECK(h.dispatch_calls == 1);

    // A second simultaneous tick round, still within the 300s interval:
    // neither dispatches again (the durable claim, not either evaluator's
    // own memory, is what prevents the second dispatch).
    h.fake_now += 20;
    evA.tick(true);
    evB.tick(true);
    CHECK(h.dispatch_calls == 1);

    // Whichever evaluator dispatched is the only one whose in_flight_ holds
    // the check — advance past grace and let BOTH collect. The verdict must
    // land exactly once, correctly, regardless of which instance dispatched
    // (the other's collect_ready() has nothing in its own in_flight_ for
    // this execution, so it is a no-op for this check).
    h.fake_now += 300; // past grace AND past the 300s interval
    evA.tick(true);
    evB.tick(true);

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
    // The interval elapsed during that last round, so a THIRD dispatch is
    // expected (from whichever instance's dispatch_due() wins the claim
    // this time) — total calls is 2, not 3+, proving the second round above
    // truly claimed nothing.
    CHECK(h.dispatch_calls == 2);
}

// #3495 governance Gate 3 re-review (architect, 2026-08-30): PolicyEvaluator
// was the fourth production consumer of the shared command_dispatch_fn
// closure and was missed by the original #3495 fix — policy_eval_thread_
// still joined before agent_server_->Shutdown(deadline). That join-ordering
// half of the fix is real and stays (see test_shutdown_join_order.cpp).
//
// An EARLIER version of this Gate 3 round also added a should_stop check
// inside dispatch_due()'s per-claimed-policy loop, mirroring the other three
// engines. Gate 4 unhappy-path (2026-08-30, UP-1/UP-2) caught that this was
// itself a NEW BLOCKING bug: claim_due_policies durably stamps
// `last_dispatched_at` for EVERY due policy in ONE transaction BEFORE the
// loop starts — a should_stop break partway through the loop leaves the
// un-processed tail claimed but never actually checked, silently skipping
// them for up to a full `default_interval_seconds` (not "the next tick" as
// an earlier version of the removed check's comment incorrectly claimed —
// the staleness sweep it cited only resets 'fixing' status rows, never this
// claim). That should_stop check was REMOVED (see dispatch_due()'s own
// comment for the full reasoning); this test now proves the corrected
// behavior — should_stop does NOT stop dispatch_due() from processing every
// claimed policy — so a future regression re-adding that check fails here,
// not silently in production.
TEST_CASE("policy evaluator: dispatch_due() processes every claimed policy "
          "regardless of should_stop, since claim_due_policies already "
          "durably committed all of them",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);

    // A second check instruction/plugin distinct from Harness's own
    // "test.check" -> "checkp", so the two policies' dispatches are
    // distinguishable BY PLUGIN NAME. Both policies dispatch the same
    // targets under the same generated-execution_id shape, and a status row
    // is only written later by collect_ready() (not by this single tick) —
    // dispatched_plugins is the one signal available within one tick call
    // that ties a dispatch back to a specific policy.
    InstructionDefinition d2;
    d2.id = "test.check2";
    d2.name = "test.check2";
    d2.version = "1.0.0";
    d2.type = "question";
    d2.plugin = "checkp2";
    d2.action = "run";
    d2.enabled = true;
    REQUIRE(h.is.create_definition(d2).has_value());

    // Two distinct policies, each with exactly one applicable check — a
    // fresh policy has no policy_dispatch_state row yet, so claim_due_policies
    // claims it on its very first tick with no preceding evaluate_now().
    h.author("result.hostname != ''"); // check: test.check -> checkp
    const std::string frag_b = "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n"
                               "spec:\n  check:\n    instruction: test.check2\n    compliance: "
                               "\"result.hostname != ''\"\n";
    auto fid_b = h.ps.create_fragment(frag_b);
    REQUIRE(fid_b.has_value());
    const std::string pol_b = "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n"
                              "spec:\n  fragment: " +
                              *fid_b + "\n  managementGroups:\n    - " + h.group_id + "\n";
    REQUIRE(h.ps.create_policy(pol_b).has_value()); // check: test.check2 -> checkp2

    auto deps = h.deps();
    // Stop signals true from the very first check — the strongest possible
    // adversarial case. If dispatch_due() honored this (like its Gate 3
    // round briefly did), NEITHER policy would be checked despite BOTH
    // already being durably claimed above.
    deps.should_stop = [] { return true; };
    PolicyEvaluator ev(deps);

    ev.tick(true); // collect_ready() is a no-op (nothing in flight yet); dispatch_due() claims both, must dispatch both

    REQUIRE(h.dispatch_calls == 2); // NOT 0, NOT 1 — should_stop=true never gates this loop
    REQUIRE(h.dispatched_plugins.size() == 2);
    // Both plugins fired — proves BOTH policies' kickoff_check ran despite
    // should_stop reporting true throughout.
    const bool checkp_fired =
        h.dispatched_plugins[0] == "checkp" || h.dispatched_plugins[1] == "checkp";
    const bool checkp2_fired =
        h.dispatched_plugins[0] == "checkp2" || h.dispatched_plugins[1] == "checkp2";
    CHECK(checkp_fired);
    CHECK(checkp2_fired);
}

// #3495 (governance consistency-auditor, 2026-08-30): collect_ready() is now
// the ONLY should_stop site left in PolicyEvaluator (dispatch_due()'s was
// removed above) — this proves it actually works, not just that it exists.
// Unlike dispatch_due()'s claim, collect_ready()'s `ready` items carry no
// durable pre-commit, so deferring them to the next tick is genuinely safe
// here (see collect_ready()'s own comment). should_stop is checked once per
// item, at the TOP of the loop before that item's own work begins (same
// semantics as every other engine) — so should_stop already true when
// tick() is called defers EVERY ready item, not just the ones after the
// first; there is no partial-processing case to observe here the way there
// is for a dispatch-bearing loop (dispatch_due()'s own test covers that
// shape instead, where each iteration's own work is a blocking call).
TEST_CASE("policy evaluator: collect_ready() defers every ready item when "
          "should_stop() already reports true",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    auto pid_a = h.author("result.hostname != ''");
    auto pid_b = h.author("result.hostname != ''");

    // A mutable flag rather than a fixed lambda: should_stop must read false
    // while seeding two in-flight checks (evaluate_now doesn't consult it —
    // it's a manual, operator-triggered dispatch, not a tick loop), then
    // true once collect_ready() itself is under test.
    bool stop = false;
    auto deps = h.deps();
    deps.should_stop = [&stop] { return stop; };
    PolicyEvaluator ev(deps);

    REQUIRE_FALSE(ev.evaluate_now(pid_a).value_or("").empty());
    REQUIRE_FALSE(ev.evaluate_now(pid_b).value_or("").empty());
    h.fake_now += 20; // past grace_seconds (15) — both now "ready" for collect_ready()

    stop = true;
    ev.tick(true); // collect_ready() must process NEITHER ready item

    // Neither policy got an agent_status write. (Both policies' next
    // interval due-time was already pushed out by evaluate_now's own
    // durable stamp, so dispatch_due() finds nothing due in this same
    // tick() and cannot interfere with this assertion.)
    CHECK(h.status_of(pid_a, "agentA") == "<none>");
    CHECK(h.status_of(pid_b, "agentA") == "<none>");

    // NOT a temporary defer: collect_ready() dequeues every past-grace item
    // from in_flight_ into `ready` UNCONDITIONALLY, before the should_stop
    // loop even runs (see collect_ready()'s own comment) — so both entries
    // are already gone from in_flight_ by this point, regardless of
    // should_stop's value. A second tick(), even with should_stop now
    // false, has nothing left to collect for either policy; both stay
    // "<none>" until the next interval's fresh Check dispatch (UP-3, Gate 4
    // unhappy-path) — proving the bounded-but-real loss this component's
    // design accepts, not a false "it recovers on retry" claim.
    stop = false;
    ev.tick(true);
    CHECK(h.status_of(pid_a, "agentA") == "<none>");
    CHECK(h.status_of(pid_b, "agentA") == "<none>");
}

// #3495 companion (mirrors the PreflightRunner/ScheduleRunner control cases,
// governance quality-engineer, 2026-08-30): should_stop literally UNSET
// (every pre-existing production/test Deps that predates this field) must
// still process every due policy in one tick, not just the first — the
// classic off-by-one risk for a newly added optional predicate.
TEST_CASE("policy evaluator: an unset should_stop claims every due policy, "
          "not just the first",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.author("result.hostname != ''");
    h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps()); // .should_stop left unset (default std::function<bool()>{})
    ev.tick(true);

    CHECK(h.dispatch_calls == 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// #4981 PR-1 (Finding B, B6): a scope-expression policy's target resolution
// bypasses the dispatch ladder entirely — PolicyEvaluator::resolve_targets is
// the ONE place that owns its own observability for a degraded
// AgentRegistry::evaluate_scope. Confirms a degraded-presence scenario makes
// target resolution return empty (never crashes, never proceeds with a
// wrong/partial target set) AND increments yuzu_scope_eval_degraded_total
// with reason=presence_degraded.
// ═══════════════════════════════════════════════════════════════════════════

namespace {
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;

yuzu::test::PgTestTemplate policy_presence_tpl{"policyevalpresence", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("policyevalpresence template: store failed to migrate");
}};
} // namespace

TEST_CASE("policy evaluator: a scope-expression policy's target resolution reports "
          "presence_degraded rather than silently proceeding as empty-scope",
          "[pg][policy][evaluator][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);

    // A SECOND Postgres database (own template) for the degraded presence
    // store — deliberately separate from the policy/response/mgmt-group pool
    // above so locking its table can't interfere with PolicyStore's own
    // reads on this same test.
    YUZU_REQUIRE_PG_DB_TPL(presence_db, policy_presence_tpl);
    PgPool short_lock_pool{
        {.conninfo = presence_db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    OfflineEndpointStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&degraded_store, std::chrono::hours(1));

    PgConn locker{PQconnectdb(presence_db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // A scope-expression policy (no management groups) — the branch that
    // reaches d_.registry->evaluate_scope inside resolve_targets. Defines a
    // fix_instruction so remediate() below reaches its own resolve_targets
    // call rather than short-circuiting on "no remediation pathway".
    auto fid = h.ps.create_fragment("apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n"
                                    "spec:\n  check:\n    instruction: test.check\n"
                                    "    compliance: \"result.hostname != ''\"\n"
                                    "  fix:\n    instruction: test.fix\n");
    REQUIRE(fid.has_value());
    auto pid = h.ps.create_policy("apiVersion: yuzu.io/v1alpha1\nkind: Policy\n"
                                  "spec:\n  fragment: " +
                                  *fid + "\n  scope: ostype == \"linux\"\n");
    REQUIRE(pid.has_value());

    auto d = h.deps();
    d.registry = &registry;
    d.metrics = &metrics;

    PolicyEvaluator ev(d);
    auto result = ev.evaluate_now(*pid);
    // #4981 PR-1 adversarial-review MEDIUM fix: a degraded scope evaluation
    // is NOT a clean "no check instruction / matches no agents" empty-string
    // result — kickoff_check now distinguishes "genuinely empty scope" from
    // "scope evaluation aborted" and returns std::unexpected for the latter,
    // which the REST /evaluate route maps to 503 (previously this collapsed
    // to a false 409).
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("presence_degraded") != std::string::npos);
    // Never proceeded with a wrong/partial target set — no dispatch fired.
    CHECK(h.dispatch_calls == 0);
    CHECK(metrics.counter("yuzu_scope_eval_degraded_total", {{"reason", "presence_degraded"}})
              .value() == 1);

    // remediate()'s refusal message (B6) names the actual degradation rather
    // than claiming a genuine empty-scope result, AND (adversarial-review
    // MEDIUM fix) sets `degraded = true` so the REST /remediate route maps
    // this to 503/audit "error" rather than 400/audit "denied" — a degraded
    // scope evaluation is an infrastructure fault, not an operator denial.
    auto remediation = ev.remediate(*pid, {"some-agent"});
    REQUIRE_FALSE(remediation.error.empty());
    CHECK(remediation.error.find("presence_degraded") != std::string::npos);
    CHECK(remediation.degraded);

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
}
