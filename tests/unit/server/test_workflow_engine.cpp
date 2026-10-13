/**
 * test_workflow_engine.cpp — Unit tests for WorkflowEngine (Postgres-backed, ADR-0006/0009/0064
 * migration, schema `workflow_engine`).
 *
 * The pre-migration store had ZERO tests of its own (test_workflow_routes.cpp only exercised the
 * `/fragments/executions` dashboard surface via an opt-in ExecHarness-constructed WorkflowEngine).
 * This file is the first direct coverage of the store's own methods.
 *
 * Covers: create/list/get workflow, create-workflow validation, soft-delete semantics (ADR-0064:
 * first delete succeeds, second delete/unknown id is not_found, history survives delete, a
 * concurrent delete during a running execution does not destroy that execution), execute() with a
 * stub StepDispatchFn (happy path, retry, on_failure=abort skip-remaining), cancel_execution,
 * list_executions, the degrade path (migration failure → is_open()==false → every method reports
 * a typed kDbErrorPrefix failure), and the schema-level FK invariant (workflow_executions →
 * workflows has no cascade — a direct hard DELETE while history exists is rejected).
 *
 * The `query_executions_page` list read (keyset walk, SQL builder text, confinement predicate
 * differential, latest-per-workflow) is covered in the "Execution list" section at the end.
 */

#include "workflow_engine.hpp"

#include "mcp_jsonrpc.hpp" // json_exceeds_depth / kMcpMaxJsonDepth (#2437-class depth guard)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "workflow_model.hpp" // workflow_execution_visible: the differential oracle for the list predicate

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7). Every store-behaviour case
// clones this instead of re-migrating per test.
yuzu::test::PgTestTemplate workflow_engine_tpl{
    "wfengine", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        WorkflowEngine engine{pool};
        if (!engine.is_open())
            throw std::runtime_error("workflow_engine template: store failed to migrate");
    }};

const std::string kOneStepYaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: one-step\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: inst-1\n"
                                 "      label: step one\n";

const std::string kTwoStepYaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: two-step\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: inst-1\n"
                                 "      label: step one\n"
                                 "    - instruction: inst-2\n"
                                 "      label: step two\n";

/// Always-succeed dispatch stub.
StepDispatchFn ok_dispatch_fn() {
    return [](const std::string&, const std::string&,
              const std::string&) -> std::expected<std::string, std::string> {
        return std::string(R"({"status":"ok"})");
    };
}

/// Builds a JSON array nested `n` levels deep: `nest(3)` == "[[[]]]". Used only to trip the
/// #2437-class depth guard (kMcpMaxJsonDepth == 32) at a SAFE test depth -- well above the guard
/// but nowhere near the ~100,000+ levels that actually SIGSEGVs a process. Never construct or
/// parse anything near the real attack depth in a test.
std::string nest(int n) {
    return std::string(static_cast<std::size_t>(n), '[') +
           std::string(static_cast<std::size_t>(n), ']');
}

} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open WorkflowEngine. The db/pool must
// outlive `engine_var` — declaring all three here keeps that order.
#define WORKFLOW_ENGINE(engine_var)                                                               \
    YUZU_REQUIRE_PG_DB_TPL(wf_db_fx_, workflow_engine_tpl);                                       \
    PgPool wf_pool_fx_{{.conninfo = wf_db_fx_.dsn(), .size = 4}};                                 \
    REQUIRE(wf_pool_fx_.valid());                                                                  \
    WorkflowEngine engine_var{wf_pool_fx_};                                                        \
    REQUIRE(engine_var.is_open())

// ── Create / list / get ──────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: create, get, list round trip", "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);

    auto id_result = engine.create_workflow(kTwoStepYaml);
    REQUIRE(id_result.has_value());
    const auto id = *id_result;
    CHECK_FALSE(id.empty());

    auto got = engine.get_workflow(id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->id == id);
    CHECK((*got)->name == "two-step");
    REQUIRE((*got)->steps.size() == 2);
    CHECK((*got)->steps[0].instruction_id == "inst-1");
    CHECK((*got)->steps[1].instruction_id == "inst-2");

    auto listed = engine.list_workflows();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].id == id);
    CHECK((*listed)[0].steps.size() == 2); // list_workflows loads steps too
}

TEST_CASE("WorkflowEngine: get_workflow on unknown id is a successful not-found",
          "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);
    auto got = engine.get_workflow("does-not-exist");
    REQUIRE(got.has_value());        // no DB error
    CHECK_FALSE(got->has_value());   // just absent
}

TEST_CASE("WorkflowEngine: list_workflows filters by name and respects limit",
          "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);
    REQUIRE(engine.create_workflow(kOneStepYaml).has_value());  // "one-step"
    REQUIRE(engine.create_workflow(kTwoStepYaml).has_value());  // "two-step"

    WorkflowQuery q;
    q.name_filter = "one";
    auto filtered = engine.list_workflows(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 1);
    CHECK((*filtered)[0].name == "one-step");

    // Case-insensitive (SQLite-era LIKE semantics preserved as ILIKE).
    WorkflowQuery q_upper;
    q_upper.name_filter = "ONE-STEP";
    auto filtered_upper = engine.list_workflows(q_upper);
    REQUIRE(filtered_upper.has_value());
    CHECK(filtered_upper->size() == 1);
}

TEST_CASE("WorkflowEngine: create_workflow validates kind/name/steps",
          "[workflow_engine][pg][validation]") {
    WORKFLOW_ENGINE(engine);

    // #3503 review finding: create_workflow()'s wrong-kind path routes through the shared
    // kind_mismatch_error() helper (test_store_errors.cpp pins the helper's own raw two-argument
    // level; this pins it through the real call site, matching PolicyStore's equivalent case).
    auto wrong_kind = engine.create_workflow("kind: Policy\nmetadata:\n  displayName: oops\n");
    REQUIRE_FALSE(wrong_kind.has_value());
    CHECK(wrong_kind.error() ==
          "kind must be 'Workflow', got 'Policy'. yaml_source must be a "
          "complete YAML document including 'apiVersion: yuzu.io/v1alpha1' "
          "and 'kind: Workflow'.");

    auto no_name = engine.create_workflow("kind: Workflow\nspec:\n  steps:\n"
                                          "    - instruction: inst-1\n");
    REQUIRE_FALSE(no_name.has_value());
    CHECK(no_name.error().find("name is required") != std::string::npos);

    auto no_steps = engine.create_workflow("kind: Workflow\nmetadata:\n  name: empty\n");
    REQUIRE_FALSE(no_steps.has_value());
    CHECK(no_steps.error().find("at least one step") != std::string::npos);

    auto missing_instruction = engine.create_workflow(
        "kind: Workflow\nmetadata:\n  name: bad\nspec:\n  steps:\n    - label: no instruction\n");
    REQUIRE_FALSE(missing_instruction.has_value());
}

// ── Soft-delete (ADR-0064) ───────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: delete_workflow soft-deletes — first succeeds, second is not_found",
          "[workflow_engine][pg][delete]") {
    WORKFLOW_ENGINE(engine);
    auto id = *engine.create_workflow(kOneStepYaml);

    auto first = engine.delete_workflow(id);
    REQUIRE(first.has_value());

    auto second = engine.delete_workflow(id);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().starts_with("not_found:"));

    // Soft-deleted — absent from ordinary reads.
    auto got = engine.get_workflow(id);
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
    auto listed = engine.list_workflows();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());
}

TEST_CASE("WorkflowEngine: delete_workflow on an unknown id is not_found",
          "[workflow_engine][pg][delete]") {
    WORKFLOW_ENGINE(engine);
    auto del = engine.delete_workflow("never-existed");
    REQUIRE_FALSE(del.has_value());
    CHECK(del.error().starts_with("not_found:"));
}

TEST_CASE("WorkflowEngine: delete-after-execution — history survives (ADR-0064 point 3)",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());
    REQUIRE(exec_result.has_value());
    const auto exec_id = *exec_result;

    auto del = engine.delete_workflow(wf_id);
    REQUIRE(del.has_value());

    // Execution history is untouched by the soft-delete — still fully queryable.
    auto exec = engine.get_execution(exec_id);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->id == exec_id);
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "success");

    auto execs = engine.list_executions(wf_id);
    REQUIRE(execs.has_value());
    REQUIRE(execs->size() == 1);
}

TEST_CASE("WorkflowEngine: execute() admission race — a workflow deleted before execute() fails "
          "the same way as one that never existed",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    REQUIRE(engine.delete_workflow(wf_id).has_value());

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().find("workflow not found") != std::string::npos);
}

TEST_CASE("WorkflowEngine: delete-during-running — a concurrent delete does not destroy an "
          "in-flight execution's history",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    // Dispatch stub deletes the workflow mid-execution (after admission, before the step
    // finishes) — proves execute() finishes cleanly and the execution stays queryable, matching
    // ADR-0064 point 3 ("an execution admitted before deletion may finish and remain queryable").
    StepDispatchFn delete_mid_dispatch =
        [&engine, &wf_id](const std::string&, const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
        auto del = engine.delete_workflow(wf_id);
        REQUIRE(del.has_value());
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, delete_mid_dispatch);
    REQUIRE(exec_result.has_value()); // admitted before the mid-dispatch delete — completes
    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");

    // Workflow itself is now soft-deleted.
    CHECK_FALSE(engine.get_workflow(wf_id)->has_value());
}

// ── Execute ───────────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: execute happy path records step results",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    auto exec_result = engine.execute(wf_id, {"agent-1", "agent-2"}, ok_dispatch_fn());
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    CHECK((*exec)->workflow_id == wf_id);
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "success");
    CHECK((*exec)->step_results[1].status == "success");
}

TEST_CASE("WorkflowEngine: execute requires a dispatch function", "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_result = engine.execute(wf_id, {"agent-1"}, nullptr);
    REQUIRE_FALSE(exec_result.has_value());
}

TEST_CASE("WorkflowEngine: execute against an unknown workflow id fails",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto exec_result = engine.execute("nope", {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().find("workflow not found") != std::string::npos);
}

TEST_CASE("WorkflowEngine: execute retries a failing step then succeeds",
          "[workflow_engine][pg][execute][retry]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: retry-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      retryCount: 2\n"
                             "      retryDelay: 0\n";
    auto wf_id = *engine.create_workflow(yaml);

    int attempts = 0;
    StepDispatchFn flaky = [&attempts](const std::string&, const std::string&,
                                       const std::string&) -> std::expected<std::string, std::string> {
        ++attempts;
        if (attempts < 2)
            return std::unexpected("transient failure");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, flaky);
    REQUIRE(exec_result.has_value());
    CHECK(attempts == 2);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "success");
    // Pre-existing semantics, preserved by the port: the attempt column is written only on a
    // FAILED attempt (inside the retry branch); a successful attempt breaks the loop before that
    // write, so the stored value is the last FAILED attempt number (1), not the successful one (2).
    CHECK((*exec)->step_results[0].attempt == 1);
}

TEST_CASE("WorkflowEngine: execute on_failure=abort (default) skips remaining steps",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    StepDispatchFn fail_first =
        [](const std::string& instruction_id, const std::string&,
           const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::unexpected("boom");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, fail_first);
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "skipped");
}

TEST_CASE("WorkflowEngine: execute on_failure=continue proceeds past a failed step",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: continue-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      onFailure: continue\n"
                             "    - instruction: inst-2\n";

    auto wf_id = *engine.create_workflow(yaml);

    StepDispatchFn fail_first =
        [](const std::string& instruction_id, const std::string&,
           const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::unexpected("boom");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, fail_first);
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    // The second step still ran (not skipped) despite the first failing, so the overall
    // execution completes rather than failing.
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "success");
}

TEST_CASE("WorkflowEngine: execute retries exhaust and the step is recorded failed",
          "[workflow_engine][pg][execute][retry]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: retry-exhaust-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      retryCount: 2\n"
                             "      retryDelay: 0\n";
    auto wf_id = *engine.create_workflow(yaml);

    int attempts = 0;
    StepDispatchFn always_fail =
        [&attempts](const std::string&, const std::string&,
                   const std::string&) -> std::expected<std::string, std::string> {
        ++attempts;
        return std::unexpected("boom");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, always_fail);
    REQUIRE(exec_result.has_value());
    CHECK(attempts == 3); // 1 initial + 2 retries, all exhausted

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[0].attempt == 3); // the last (also failed) attempt number
}

TEST_CASE("WorkflowEngine: execute skips a step whose condition evaluates false",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: cond-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      condition: skip-me\n";
    auto wf_id = *engine.create_workflow(yaml);

    bool condition_called = false;
    ConditionEvalFn deny_all = [&condition_called](const std::string& expr,
                                                   const std::map<std::string, std::string>&) {
        condition_called = true;
        CHECK(expr == "skip-me");
        return false;
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn(), deny_all);
    REQUIRE(exec_result.has_value());
    CHECK(condition_called);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "success");
    CHECK((*exec)->step_results[1].status == "skipped");
}

TEST_CASE("WorkflowEngine: execute expands a foreach step and aggregates per-item results",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: foreach-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    std::vector<std::string> foreach_params_seen;
    StepDispatchFn dispatch = [&foreach_params_seen](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string& params) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::string(R"({"items":["a","b"]})");
        foreach_params_seen.push_back(params);
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value());
    // The "items" array from step 1's result drove two separate dispatch calls for step 2.
    REQUIRE(foreach_params_seen.size() == 2);
    CHECK(foreach_params_seen[0] == "\"a\"");
    CHECK(foreach_params_seen[1] == "\"b\"");

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[1].status == "success");
}

// ── #2437-class depth guard ──────────────────────────────────────────────────
// StepDispatchFn's documented contract (workflow_engine.hpp) is "returns a JSON
// result string" with no depth bound. WorkflowEngine::execute's dispatch loop
// parses that return value and later dumps it (directly, via expand_foreach's
// array-iteration branch, via its "treat whole result as single item"
// fallback, and via the step condition evaluator) -- all unboundedly
// recursive. These pin: a depth-poisoned dispatch result fails the step (and,
// under the default on_failure=abort, the whole run) via the SAME mechanism
// an ordinary dispatch failure already uses, and never lets a later step
// iterate or dispatch over the unparsed poison.

TEST_CASE("WorkflowEngine: a foreach step's shallow array-iteration result still dispatches "
          "normally (depth-guard positive control)",
          "[workflow_engine][pg][execute][depth-guard]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: depth-ok-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    bool inst2_dispatched = false;
    StepDispatchFn dispatch = [&inst2_dispatched](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::string(R"({"items":["a","b"]})");
        inst2_dispatched = true;
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value());
    CHECK(inst2_dispatched);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "success");
    CHECK((*exec)->step_results[1].status == "success");
}

TEST_CASE("WorkflowEngine: a foreach step's poisoned array-iteration result fails the step and "
          "blocks further dispatch",
          "[workflow_engine][pg][execute][depth-guard]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: depth-array-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    // "items" is itself a deeply nested array (35 levels including the object) -- well past
    // kMcpMaxJsonDepth (32), nowhere near the ~100,000+ levels that actually crashes a process.
    const std::string poisoned = R"({"items":)" + nest(33) + "}";

    bool inst2_dispatched = false;
    StepDispatchFn dispatch = [&inst2_dispatched, &poisoned](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return poisoned;
        inst2_dispatched = true;
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value()); // execute() itself never crashes and still returns an id

    // The C5 analog: the poisoned step's output never drove a further dispatch.
    CHECK_FALSE(inst2_dispatched);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed"); // whole run failed, not silently completed
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed"); // step itself failed, not silently skipped
    CHECK((*exec)->step_results[1].status == "skipped"); // never reached, never dispatched
}

TEST_CASE("WorkflowEngine: a foreach fallback's poisoned whole-result item fails the step and "
          "blocks further dispatch (D2)",
          "[workflow_engine][pg][execute][depth-guard]") {
    WORKFLOW_ENGINE(engine);
    // Step 2's foreach field ("items") is absent from step 1's result, so expand_foreach's
    // "treat whole result as single item" fallback is the branch exercised here, not the
    // array-iteration branch above.
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: depth-fallback-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    // No "items" field, and the top level is an object (not an array either) -- forces the
    // fallback. 35 levels total (1 for the object + 34 nested arrays), well past the 32 guard.
    const std::string poisoned = R"({"x":)" + nest(34) + "}";

    bool inst2_dispatched = false;
    StepDispatchFn dispatch = [&inst2_dispatched, &poisoned](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return poisoned;
        inst2_dispatched = true;
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value());

    CHECK_FALSE(inst2_dispatched);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "skipped");
}

TEST_CASE("WorkflowEngine: on_failure=continue forwards a safe placeholder, never the poisoned "
          "result, to a dependent step",
          "[workflow_engine][pg][execute][depth-guard]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: depth-continue-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      onFailure: continue\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    const std::string poisoned = R"({"items":)" + nest(33) + "}";

    std::vector<std::string> inst2_params_seen;
    StepDispatchFn dispatch = [&inst2_params_seen, &poisoned](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string& params) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return poisoned;
        inst2_params_seen.push_back(params);
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value());

    // on_failure=continue lets step 2 run -- but on the SAFE placeholder foreach's fallback
    // pushed through, never the poisoned 33-level structure step 1 actually returned.
    REQUIRE(inst2_params_seen.size() == 1);
    CHECK(inst2_params_seen[0] ==
          R"({"error":"dispatch result exceeded maximum JSON nesting depth"})");
    CHECK_FALSE(yuzu::server::mcp::json_exceeds_depth(inst2_params_seen[0],
                                                       yuzu::server::mcp::kMcpMaxJsonDepth));

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed"); // continue policy: step 1 failed, run still completes
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "success");
}

// ── Cancel ────────────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: cancel_execution rejects an unknown id",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto cancel = engine.cancel_execution("nope");
    REQUIRE_FALSE(cancel.has_value());
    CHECK(cancel.error() == "execution not found");
}

TEST_CASE("WorkflowEngine: cancel_execution rejects a terminal execution",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    auto cancel = engine.cancel_execution(exec_id);
    REQUIRE_FALSE(cancel.has_value()); // already "completed"
    CHECK(cancel.error().find("already") != std::string::npos);
}

TEST_CASE("WorkflowEngine: cancel_execution mid-run stops subsequent steps",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    // execute() creates the execution row (status=running) before the first dispatch call, so
    // the stub can look it up via list_executions() and cancel it from inside step 0's dispatch —
    // proving the cancellation check at the top of step 1's loop iteration takes effect.
    auto exec_result = engine.execute(
        wf_id, {"agent-1"},
        [&engine, &wf_id](const std::string&, const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
            auto execs = engine.list_executions(wf_id, 1);
            REQUIRE(execs.has_value());
            REQUIRE_FALSE(execs->empty());
            REQUIRE(engine.cancel_execution((*execs)[0].id).has_value());
            return std::string(R"({"status":"ok"})");
        });
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    // Governance finding (cpp-expert): the finalize UPDATE is now guarded (`WHERE status =
    // 'running'`), so it no longer clobbers the "cancelled" status cancel_execution() already
    // committed — status stays "cancelled", not overwritten to "failed".
    CHECK((*exec)->status == "cancelled");
}

TEST_CASE("WorkflowEngine: a concurrent cancel_execution races execute()'s guarded writes over "
          "real connections and the execution never ends up back in 'running'",
          "[workflow_engine][pg][cancel][race]") {
    // #3722 follow-up, done directly rather than deferred: genuine multi-threaded race over
    // separate PgPool leases (not the same-thread simulation the sequential cancel tests above
    // use, where cancel_execution() is called from inside the dispatch_fn callback on execute()'s
    // own thread/call-stack).
    //
    // HONEST LIMIT, checked empirically rather than assumed: the specific window the mid-loop
    // guard defends against is between the top-of-loop get_execution() cancellation check and
    // that same iteration's guarded UPDATE, with no I/O in between — and a cancel landing during
    // a step's dispatch is ALREADY caught by the next iteration's top-of-loop check regardless of
    // whether the mid-loop guard exists (or, for the LAST step, by finalize's own separate
    // `WHERE status = 'running'` guard — there is no next iteration for that one). With the
    // mid-loop guard's WHERE clause and RETURNING
    // temporarily removed (simulating the pre-fix code) this test was run 20 times across two
    // harness shapes — a slow single-canceller version (5 steps, 5ms dispatch delay, one
    // 1ms-interval canceller thread) and this denser one (60 steps, no dispatch delay, 4
    // no-delay canceller threads) — and BOTH passed every single run: the top-of-loop check won
    // the race before the (disabled) mid-loop guard's window was ever reached. This test therefore
    // does NOT prove the mid-loop guard's specific TOCTOU window is closed — that window appears
    // to be sub-microsecond-adjacent to the top-of-loop check with no I/O in between, and this
    // black-box harness could not land inside it even under maximized contention. What it DOES
    // prove, and is real coverage the prior same-thread sequential test lacked: genuine concurrent
    // cancellation from separate threads/connections is safe end-to-end (never leaves the row in
    // 'running', and any cancel that succeeds is permanent), exercising the top-of-loop check,
    // cancel_execution()'s own CAS, and the finalize guard together under real interleaving.
    //
    // Uses its own larger pool instead of WORKFLOW_ENGINE's fixed size=4 (governance finding,
    // cpp-expert): 4 canceller threads plus execute()'s own leases share one pool here, and under
    // CI-runner contention a starved try_acquire_for could time out the "genuinely raced" proof
    // below — the same shared-box contention class as #473/#482.
    YUZU_REQUIRE_PG_DB_TPL(wf_db_fx_, workflow_engine_tpl);
    PgPool wf_pool_fx_{{.conninfo = wf_db_fx_.dsn(), .size = 12}};
    REQUIRE(wf_pool_fx_.valid());
    WorkflowEngine engine{wf_pool_fx_};
    REQUIRE(engine.is_open());
    std::string yaml = "kind: Workflow\nmetadata:\n  displayName: many-step\nspec:\n  steps:\n";
    constexpr int kSteps = 60;
    for (int i = 0; i < kSteps; ++i)
        yaml += "    - instruction: inst-" + std::to_string(i) + "\n";
    auto wf_id = *engine.create_workflow(yaml);

    std::atomic<int> dispatched_count{0};
    std::atomic<bool> raced_while_running{false}; // proof the canceller genuinely observed
                                                   // 'running' concurrently with execute(), not
                                                   // just after it had already finished
    std::atomic<bool> cancel_succeeded{false}; // true iff some cancel_execution() call itself
                                                // reported success — i.e. the DB confirmed the
                                                // pending/running -> cancelled transition at that
                                                // instant (cancel_execution's own CAS matched)
    std::atomic<bool> stop_canceller{false};
    std::atomic<bool> exec_id_claimed{false}; // CAS-guards which single thread may write exec_id
    std::atomic<bool> exec_id_ready{false};   // release-stored only after that write completes
    std::string exec_id;                      // single-writer (the CAS winner) / multi-reader,
                                               // readers gated on exec_id_ready's acquire load

    auto canceller_body = [&] {
        // Each thread independently polls for the execution row to appear (execute() creates it
        // before the first dispatch), then hammers cancel_execution() with no delay of its own.
        // Only the thread that wins the exec_id_claimed CAS writes `exec_id`, so concurrent
        // discovery by multiple threads can't race the same plain std::string write; the
        // acquire/release pair on exec_id_ready makes that write visible before any reader uses it.
        while (!exec_id_ready.load(std::memory_order_acquire) &&
               !stop_canceller.load(std::memory_order_relaxed)) {
            auto execs = engine.list_executions(wf_id, 1);
            if (execs.has_value() && !execs->empty()) {
                bool expected = false;
                if (exec_id_claimed.compare_exchange_strong(expected, true,
                                                             std::memory_order_acq_rel)) {
                    exec_id = (*execs)[0].id;
                    exec_id_ready.store(true, std::memory_order_release);
                }
            }
        }
        while (!stop_canceller.load(std::memory_order_relaxed)) {
            auto exec = engine.get_execution(exec_id);
            if (exec.has_value() && exec->has_value() && (*exec)->status == "running")
                raced_while_running.store(true, std::memory_order_relaxed);

            if (engine.cancel_execution(exec_id).has_value())
                cancel_succeeded.store(true, std::memory_order_relaxed); // not_found/
                    // already-terminal are losing-race outcomes, not errors — only a genuine
                    // success sets this
        }
    };
    constexpr int kCancellers = 4;
    std::vector<std::thread> cancellers;
    for (int i = 0; i < kCancellers; ++i)
        cancellers.emplace_back(canceller_body);

    // RAII join (governance finding, cpp-safety — CLAUDE.md's non-RAII-cleanup policy floor):
    // if execute() below throws, a bare `stop_canceller = true; for (...) t.join();` placed AFTER
    // it would never run, and `cancellers`' destructor would then call std::terminate() on every
    // still-joinable thread. This guard's destructor runs on the unwind path too, so every
    // canceller is always signalled to stop and joined before either `cancellers` or the
    // by-reference-captured locals it points at (engine, the atomics, exec_id) go out of scope.
    struct CancellerJoiner {
        std::atomic<bool>& stop;
        std::vector<std::thread>& threads;
        ~CancellerJoiner() {
            stop.store(true, std::memory_order_relaxed);
            for (auto& t : threads)
                if (t.joinable())
                    t.join();
        }
    } joiner{stop_canceller, cancellers};

    auto exec_result = engine.execute(
        wf_id, {"agent-1"},
        [&](const std::string&, const std::string&,
            const std::string&) -> std::expected<std::string, std::string> {
            ++dispatched_count;
            return std::string(R"({"status":"ok"})");
        });

    stop_canceller = true;
    for (auto& t : cancellers)
        t.join();

    REQUIRE(exec_result.has_value());
    REQUIRE(raced_while_running.load()); // the harness must have genuinely raced, not run serially

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());

    CHECK((*exec)->status != "running"); // never left mid-transition
    CHECK((*exec)->status != "failed");  // ok_dispatch never errors, so this is unreachable here

    // The sharp invariant a broken guard would actually violate: once cancel_execution() itself
    // reports success, the DB has already committed 'cancelled' — that transition must be
    // PERMANENT. A clobbering mid-loop or finalize write (the exact bug the guards close) would
    // silently overwrite it back to 'running' and let the loop run to completion, landing here as
    // "completed" instead. If no cancel attempt ever won the race, execute() must have run to a
    // normal completion instead.
    if (cancel_succeeded.load())
        CHECK((*exec)->status == "cancelled");
    else
        CHECK((*exec)->status == "completed");
}

// ── Degrade path ──────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine reports !is_open on a migration failure and every method degrades",
          "[workflow_engine][pg]") {
    YUZU_REQUIRE_PG_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA workflow_engine")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE workflow_engine.bogus (x int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    WorkflowEngine engine{pool};
    CHECK_FALSE(engine.is_open()); // → server.cpp sets startup_failed_ = true

    auto create_result = engine.create_workflow(kOneStepYaml);
    REQUIRE_FALSE(create_result.has_value());
    CHECK(create_result.error().starts_with(kDbErrorPrefix));

    auto list_result = engine.list_workflows();
    REQUIRE_FALSE(list_result.has_value());
    CHECK(list_result.error().starts_with(kDbErrorPrefix));

    auto get_result = engine.get_workflow("anything");
    REQUIRE_FALSE(get_result.has_value());
    CHECK(get_result.error().starts_with(kDbErrorPrefix));

    auto del_result = engine.delete_workflow("anything");
    REQUIRE_FALSE(del_result.has_value());
    CHECK(del_result.error().starts_with(kDbErrorPrefix));

    auto exec_result = engine.execute("anything", {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().starts_with(kDbErrorPrefix));

    auto get_exec_result = engine.get_execution("anything");
    REQUIRE_FALSE(get_exec_result.has_value());
    CHECK(get_exec_result.error().starts_with(kDbErrorPrefix));

    auto list_exec_result = engine.list_executions();
    REQUIRE_FALSE(list_exec_result.has_value());
    CHECK(list_exec_result.error().starts_with(kDbErrorPrefix));

    auto page_result = engine.query_executions_page({}, std::nullopt);
    REQUIRE_FALSE(page_result.has_value());
    CHECK(page_result.error().starts_with(kDbErrorPrefix));

    auto cancel_result = engine.cancel_execution("anything");
    REQUIRE_FALSE(cancel_result.has_value());
    CHECK(cancel_result.error().starts_with(kDbErrorPrefix));
}

// ── Schema invariant ──────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine schema: workflow_executions -> workflows has no cascade (ADR-0064)",
          "[workflow_engine][pg][schema]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    REQUIRE(engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn()).has_value());

    // A direct hard DELETE (bypassing delete_workflow()'s soft-delete) must be rejected by the
    // FK while execution history exists — proves the schema itself enforces "history survives,
    // never silently cascades" independent of the store's own application-level logic.
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult del = yuzu::server::pg::exec_params(
        conn.get(), "DELETE FROM workflow_engine.workflows WHERE id = $1",
        std::vector<std::string>{wf_id});
    CHECK(del.status() == PGRES_FATAL_ERROR); // FK violation — RESTRICT/NO ACTION, not CASCADE
}

// ── Child-read failure propagation (adversarial-review CDX-P1-001/WF-3) ──────
//
// A genuine child-table query failure must surface as a typed kDbErrorPrefix failure, never as
// a successful parent row with silently-empty children — the bug this closes: the parent read
// was widened to std::expected, but wf_load_steps()/get_execution()'s step-results load kept
// the SQLite-era fail-soft shape underneath it. Each case drops the child table via a second raw
// connection to force a real query failure (not a mock), then asserts the typed-failure contract.

TEST_CASE("WorkflowEngine: get_workflow surfaces a genuine workflow_steps query failure as "
          "kDbErrorPrefix, not an empty steps list",
          "[workflow_engine][pg][crud][degrade]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_steps", std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    auto got = engine.get_workflow(wf_id);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().starts_with(kDbErrorPrefix));

    auto listed = engine.list_workflows();
    REQUIRE_FALSE(listed.has_value());
    CHECK(listed.error().starts_with(kDbErrorPrefix));
}

TEST_CASE("WorkflowEngine: get_execution surfaces a genuine workflow_step_results query "
          "failure as kDbErrorPrefix, not an execution with empty step_results",
          "[workflow_engine][pg][execute][degrade]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_step_results",
        std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    auto exec = engine.get_execution(exec_id);
    REQUIRE_FALSE(exec.has_value());
    CHECK(exec.error().starts_with(kDbErrorPrefix));
}

// ── cancel_execution atomicity (adversarial-review CDX-P1-003/WF-2/WF-5) ─────
//
// Governance finding (quality-engineer, Gate 3): a genuine concurrent race between
// cancel_execution()'s SELECT-then-UPDATE and a racing execute() finalize cannot be reproduced
// deterministically at the API level — no thread interleaves inside one SQL statement, and a
// probabilistic thread/sleep-based stress test would violate this repo's test-determinism
// convention. The single-statement `UPDATE ... WHERE status IN ('pending','running') RETURNING
// id` shape (workflow_engine.cpp) is the actual closure evidence for the race — it is atomic by
// construction and reviewable directly in the diff, not something this test proves. What the
// case below DOES prove, and is exactly what it is named for: cancelling an execution that is
// ALREADY terminal (the common non-concurrent case, and the only shape reachable at the API
// today) reports the already-terminal message and never overwrites the row — a real, useful
// assertion, but not a race/atomicity proof. Do not re-add an "atomicity" framing here without a
// genuine concurrent reproduction.

TEST_CASE("WorkflowEngine: cancel_execution on an already-terminal execution reports "
          "already-terminal and never overwrites its status",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    // Already terminal ("completed") — the guarded UPDATE...WHERE status IN (...) matches zero
    // rows, so cancel must report the already-terminal message, never silently overwrite it.
    auto cancel = engine.cancel_execution(exec_id);
    REQUIRE_FALSE(cancel.has_value());
    CHECK(cancel.error() == "execution is already completed");

    auto exec = engine.get_execution(exec_id);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed"); // never overwritten to "cancelled"
}

// ── Execution list (query_executions_page) ───────────────────────────────────
//
// Rows are seeded by direct INSERT: the list needs exact started_at ties, malformed
// agent_ids_json and ids execute() would never mint, none of which the engine can produce.

namespace {

constexpr const char* kListSelectHead =
    "SELECT e.id, e.workflow_id, w.name, (w.deleted_at <> 0), e.status, e.current_step, "
    "e.started_at, e.completed_at FROM workflow_engine.workflow_executions e "
    "JOIN workflow_engine.workflows w ON w.id = e.workflow_id WHERE 1=1";

// The guarded-jsonb expression the confinement clause iterates (nested CASE, see the builder).
constexpr const char* kGuardedJsonb =
    "CASE WHEN pg_input_is_valid(e.agent_ids_json, 'jsonb') "
    "THEN (CASE WHEN jsonb_typeof(e.agent_ids_json::jsonb) = 'array' "
    "THEN e.agent_ids_json::jsonb ELSE '[]'::jsonb END) ELSE '[]'::jsonb END";

std::string wf_yaml(const std::string& name) {
    return "kind: Workflow\nmetadata:\n  displayName: " + name +
           "\nspec:\n  steps:\n    - instruction: inst-1\n      label: step one\n";
}

void seed_run(PGconn* conn, const std::string& id, const std::string& workflow_id, int64_t started,
              const std::string& agent_ids_json, const std::string& status = "completed") {
    PgResult r = yuzu::server::pg::exec_params(
        conn,
        "INSERT INTO workflow_engine.workflow_executions "
        "(id, workflow_id, status, agent_ids_json, started_at, completed_at, current_step) "
        "VALUES ($1, $2, $3, $4, $5::bigint, $5::bigint, 1)",
        std::vector<std::string>{id, workflow_id, status, agent_ids_json, std::to_string(started)});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

std::vector<std::string> ids_of(const WorkflowExecutionPage& p) {
    std::vector<std::string> out;
    for (const auto& r : p.rows)
        out.push_back(r.id);
    return out;
}

using Scope = std::optional<std::vector<std::string>>;

} // namespace

TEST_CASE("build_execution_page_sql: the unfiltered newest-first statement is pinned",
          "[workflow_engine][list][sql]") {
    const auto b = build_execution_page_sql(WorkflowExecutionListQuery{}, std::nullopt);
    CHECK(b.sql == std::string(kListSelectHead) +
                       " ORDER BY e.started_at DESC, e.id DESC LIMIT $1::bigint");
    CHECK(b.params == std::vector<std::string>{"51"}); // limit 50 + the sentinel row
    // The read's statement bound comes from the builder, not from a literal in the shell. This
    // pins the text only: that the shell RUNS it is pinned by the lock-held read case below
    // ("a read blocked behind an exclusive lock ...", [timeout]), which needs a real connection.
    CHECK(b.statement_timeout_sql == "SET LOCAL statement_timeout = '1500ms'");
}

TEST_CASE("build_execution_page_sql: every filter binds a parameter and nothing is spliced",
          "[workflow_engine][list][sql]") {
    WorkflowExecutionListQuery q;
    q.workflow_id = "wf-1' OR '1'='1";
    q.status = "failed";
    q.since = 100;
    q.until = 200;
    q.limit = 7;
    q.after = keyset::Position{150, "run-9"};
    const auto b = build_execution_page_sql(q, std::nullopt);
    CHECK(b.sql == std::string(kListSelectHead) +
                       " AND e.workflow_id = $1 AND e.status = $2 AND e.started_at >= $3::bigint"
                       " AND e.started_at < $4::bigint"
                       " AND (e.started_at < $5::bigint OR (e.started_at = $5::bigint AND e.id < $6))"
                       " ORDER BY e.started_at DESC, e.id DESC LIMIT $7::bigint");
    CHECK(b.params == std::vector<std::string>{"wf-1' OR '1'='1", "failed", "100", "200", "150",
                                               "run-9", "8"});
    CHECK(b.sql.find("OR '1'='1") == std::string::npos);
}

TEST_CASE("build_execution_page_sql: the confinement clause precedes ORDER BY and LIMIT",
          "[workflow_engine][list][sql][confinement]") {
    // ADR-0017 INV-3 tripwire: applied after LIMIT an invisible run would consume a page slot.
    WorkflowExecutionListQuery q;
    q.workflow_id = "wf-1";
    q.after = keyset::Position{150, "run-9"};
    const Scope scope{std::vector<std::string>{"a\"1", "b\\2"}};
    const auto b = build_execution_page_sql(q, scope);
    CHECK(b.sql == std::string(kListSelectHead) +
                       " AND e.workflow_id = $1"
                       " AND (e.started_at < $2::bigint OR (e.started_at = $2::bigint AND e.id < $3))"
                       " AND EXISTS (SELECT 1 FROM jsonb_array_elements(" +
                       kGuardedJsonb +
                       ") AS a(v) WHERE jsonb_typeof(a.v) = 'string' AND (a.v #>> '{}') = "
                       "ANY($4::text[]))"
                       " ORDER BY e.started_at DESC, e.id DESC LIMIT $5::bigint");
    // The visible set is ONE array bind however large it is (no per-agent placeholder cap), with
    // quote and backslash escaped for the array literal.
    CHECK(b.params == std::vector<std::string>{"wf-1", "150", "run-9", R"({"a\"1","b\\2"})", "51"});
    const auto scope_at = b.sql.find("jsonb_array_elements");
    REQUIRE(scope_at != std::string::npos);
    CHECK(scope_at < b.sql.find("ORDER BY"));
    CHECK(scope_at < b.sql.find("LIMIT"));
}

TEST_CASE("build_execution_page_sql: an engaged-empty scope can never become an unfiltered read",
          "[workflow_engine][list][sql][confinement]") {
    const auto b = build_execution_page_sql(WorkflowExecutionListQuery{}, Scope{std::vector<std::string>{}});
    CHECK(b.sql == std::string(kListSelectHead) +
                       " AND 1=0 ORDER BY e.started_at DESC, e.id DESC LIMIT $1::bigint");
}

TEST_CASE("build_execution_page_sql: latest-per-workflow orders by workflow and ignores the cursor",
          "[workflow_engine][list][sql]") {
    WorkflowExecutionListQuery q;
    q.latest_per_workflow = true;
    q.status = "failed";
    q.limit = 3;
    q.after = keyset::Position{150, "run-9"}; // never combined with a cursor upstream; ignored here
    const auto b = build_execution_page_sql(q, std::nullopt);
    CHECK(b.sql == std::string("SELECT DISTINCT ON (e.workflow_id) ") +
                       std::string(kListSelectHead).substr(7) + " AND e.status = $1"
                       " ORDER BY e.workflow_id, e.started_at DESC, e.id DESC LIMIT $2::bigint");
    CHECK(b.params == std::vector<std::string>{"failed", "4"});
}

TEST_CASE("build_execution_page_sql: limit is clamped to 1..500 before the sentinel is added",
          "[workflow_engine][list][sql]") {
    // One field feeds both bounds: the statement selects `limit + 1`, the store trims to `limit`.
    for (const auto& [asked, want] : std::vector<std::pair<int, int>>{
             {0, 1}, {-5, 1}, {1, 1}, {500, 500}, {501, 500}, {100000, 500}}) {
        INFO("asked " << asked);
        WorkflowExecutionListQuery q;
        q.limit = asked;
        const auto b = build_execution_page_sql(q, std::nullopt);
        CHECK(b.limit == want);
        CHECK(b.params.back() == std::to_string(want + 1));
    }
}

TEST_CASE("WorkflowEngine::query_executions_page: a keyset walk over same-second ties skips and "
          "repeats nothing",
          "[workflow_engine][pg][list]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("walk"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // Three runs share t=200, three share t=100, one is older: id is the tiebreak.
    for (const auto& [id, t] : std::vector<std::pair<std::string, int64_t>>{
             {"r-a", 200}, {"r-c", 200}, {"r-b", 200}, {"r-e", 100},
             {"r-d", 100}, {"r-f", 100}, {"r-g", 50}})
        seed_run(conn.get(), id, wf, t, R"(["agent-1"])");
    const std::vector<std::string> expected{"r-c", "r-b", "r-a", "r-f", "r-e", "r-d", "r-g"};

    WorkflowExecutionListQuery q;
    q.limit = 2;
    std::vector<std::string> walked;
    std::vector<std::size_t> page_sizes;
    for (int guard = 0; guard < 10; ++guard) {
        auto page = engine.query_executions_page(q, std::nullopt);
        REQUIRE(page.has_value());
        page_sizes.push_back(page->rows.size());
        for (const auto& id : ids_of(*page))
            walked.push_back(id);
        if (!page->next)
            break;
        // The cursor position is the last row returned, never the sentinel.
        CHECK(page->next->id == page->rows.back().id);
        CHECK(page->next->key == page->rows.back().started_at);
        q.after = page->next;
    }
    CHECK(walked == expected);
    CHECK(page_sizes == std::vector<std::size_t>{2, 2, 2, 1});

    // Exactly `limit` rows left is NOT "more": the sentinel row is what says there is more.
    q.after.reset();
    q.limit = 7;
    auto all = engine.query_executions_page(q, std::nullopt);
    REQUIRE(all.has_value());
    CHECK(ids_of(*all) == expected);
    CHECK_FALSE(all->next.has_value());
    q.limit = 6;
    auto six = engine.query_executions_page(q, std::nullopt);
    REQUIRE(six.has_value());
    CHECK(six->rows.size() == 6);
    REQUIRE(six->next.has_value());
    CHECK(six->next->id == "r-d");
}

TEST_CASE("WorkflowEngine::query_executions_page: a soft-deleted workflow's runs still list and "
          "say so",
          "[workflow_engine][pg][list]") {
    WORKFLOW_ENGINE(engine);
    const auto kept = *engine.create_workflow(wf_yaml("kept-wf"));
    const auto gone = *engine.create_workflow(wf_yaml("gone-wf"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    seed_run(conn.get(), "run-kept", kept, 20, "[]");
    seed_run(conn.get(), "run-gone", gone, 10, "[]", "failed");
    REQUIRE(engine.delete_workflow(gone).has_value());

    auto page = engine.query_executions_page({}, std::nullopt);
    REQUIRE(page.has_value());
    REQUIRE(page->rows.size() == 2);
    CHECK(page->rows[0].id == "run-kept");
    CHECK(page->rows[0].workflow_name == "kept-wf");
    CHECK_FALSE(page->rows[0].workflow_deleted);
    CHECK(page->rows[1].id == "run-gone");
    CHECK(page->rows[1].workflow_name == "gone-wf");
    CHECK(page->rows[1].workflow_deleted);
    CHECK(page->rows[1].status == "failed");
    CHECK(page->rows[1].current_step == 1);
    CHECK(page->rows[1].started_at == 10);
    CHECK(page->rows[1].completed_at == 10);
}

TEST_CASE("WorkflowEngine::query_executions_page: filters narrow exactly and combine with AND",
          "[workflow_engine][pg][list]") {
    WORKFLOW_ENGINE(engine);
    const auto w1 = *engine.create_workflow(wf_yaml("filter-one"));
    const auto w2 = *engine.create_workflow(wf_yaml("filter-two"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    seed_run(conn.get(), "r1", w1, 100, "[]", "completed");
    seed_run(conn.get(), "r2", w1, 200, "[]", "failed");
    seed_run(conn.get(), "r3", w2, 300, "[]", "failed");
    seed_run(conn.get(), "r4", w2, 400, "[]", "running");

    const auto run = [&](WorkflowExecutionListQuery q) {
        auto page = engine.query_executions_page(q, std::nullopt);
        REQUIRE(page.has_value());
        return ids_of(*page);
    };
    WorkflowExecutionListQuery q;
    q.workflow_id = w1;
    CHECK(run(q) == std::vector<std::string>{"r2", "r1"});
    q = {};
    q.status = "failed";
    CHECK(run(q) == std::vector<std::string>{"r3", "r2"});
    q = {};
    q.since = 200; // inclusive
    CHECK(run(q) == std::vector<std::string>{"r4", "r3", "r2"});
    q = {};
    q.until = 300; // exclusive
    CHECK(run(q) == std::vector<std::string>{"r2", "r1"});
    q = {};
    q.since = 200;
    q.until = 400;
    q.status = "failed";
    CHECK(run(q) == std::vector<std::string>{"r3", "r2"});
    q.workflow_id = w2;
    CHECK(run(q) == std::vector<std::string>{"r3"});
    q = {};
    q.workflow_id = "no-such-workflow";
    CHECK(run(q).empty());
}

TEST_CASE("WorkflowEngine::query_executions_page: the SQL visibility predicate equals "
          "workflow_execution_visible over a corpus",
          "[workflow_engine][pg][list][confinement]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("corpus"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

    // (label, agent_ids_json). Labels are the run ids so a failure names the shape.
    const std::vector<std::pair<std::string, std::string>> corpus{
        {"one-in", R"(["a1"])"},
        {"two-one-in", R"(["z9","a1"])"},
        {"two-none-in", R"(["z9","y8"])"},
        {"other-only", R"(["b1"])"},
        {"both-scopes", R"(["a1","b1"])"},
        {"empty-array", "[]"},
        {"empty-text", ""},
        {"not-json", "not json at all"},
        {"truncated", R"(["a1")"},
        {"object", R"({"agent":"a1"})"},
        {"object-numeric-keys", R"({"0":"a1"})"},
        {"null-scalar", "null"},
        {"string-scalar", R"("a1")"},
        {"number-scalar", "7"},
        {"numbers-only", "[1,2,3]"},
        {"mixed-types", R"([1,null,true,"a1",{"x":"a1"}])"},
        {"nested-array", R"([["a1"]])"},
        {"duplicates", R"(["a1","a1","a1"])"},
        {"leading-space-id", R"([" a1"])"},
        {"case-differs", R"(["A1"])"},
        // A raw string keeps the backslashes, so the JSON text really holds \u0061\u0031; both
        // parsers decode it to "a1". (A plain string literal would need the backslashes doubled.)
        {"unicode-escape-in", R"(["\u0061\u0031"])"},
        {"surrogate-pair-in", R"(["\uD83D\uDE00"])"}, // one astral id, U+1F600, as a surrogate pair
        {"lone-surrogate", R"(["a1","\uD83D"])"},      // both parsers refuse the WHOLE document
        {"unicode-id-in", "[\"\xc3\xa9" "1\"]"},        // "e-acute 1", also an in-scope id below
        {"quote-and-backslash-in", R"(["a\"b","c\\d"])"},
        {"whitespace-padded-json", " \n[ \"a1\" ]\t"},
        {"nul-only", R"(["\u0000"])"}, // jsonb refuses \u0000; both sides still say not visible
        // Non-string elements are ignored even when their TEXT equals an in-scope id ("7", "true"):
        // dropping the SQL jsonb_typeof(...) = 'string' test would admit these.
        {"number-element", "[7]"},
        {"bool-element", "[true]"},
        {"string-seven", R"(["7"])"},
    };
    int64_t t = 1000;
    for (const auto& [label, json] : corpus)
        seed_run(conn.get(), label, wf, t++, json);

    const std::vector<std::vector<std::string>> scopes{
        {"a1"},
        {"b1"},
        {"a1", "b1"},
        {"nobody"},
        {"a\"b"},
        {"c\\d", "z9"},
        {"\xc3\xa9" "1"},
        {"\xF0\x9F\x98\x80"}, // U+1F600
        {"7", "true"},
        {"a1", "b1", "z9", "y8", "A1", " a1", "a\"b", "c\\d", "\xc3\xa9" "1", "\xF0\x9F\x98\x80"},
    };
    for (const auto& scope_vec : scopes) {
        authz::VisibleSet vs{std::unordered_set<std::string>(scope_vec.begin(), scope_vec.end())};
        std::set<std::string> expected;
        for (const auto& [label, json] : corpus) {
            WorkflowExecution we;
            we.agent_ids_json = json;
            if (workflow_execution_visible(we, vs))
                expected.insert(label);
        }
        WorkflowExecutionListQuery q;
        q.limit = 500;
        auto page = engine.query_executions_page(q, Scope{scope_vec});
        INFO("scope of " << scope_vec.size() << " ids, first " << scope_vec.front());
        // One malformed row must never error the whole statement.
        REQUIRE(page.has_value());
        const auto got = ids_of(*page);
        CHECK(std::set<std::string>(got.begin(), got.end()) == expected);
        CHECK(got.size() == expected.size()); // no duplicates either
    }
}

TEST_CASE("WorkflowEngine::query_executions_page: a NUL escape is refused by the SQL side (stricter "
          "than the C++ predicate and fails closed)",
          "[workflow_engine][pg][list][confinement]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("nul"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // jsonb rejects \u0000 outright, so the whole document is "invalid" to the SQL predicate while
    // nlohmann parses it and would admit the in-scope "a1": the list hides a run the detail route
    // would show (the safe direction). The other divergences, including the one that goes the
    // other way, are pinned in the divergence case below.
    const std::string json = R"(["a1","\u0000"])";
    seed_run(conn.get(), "nul-mixed", wf, 10, json);
    WorkflowExecution we;
    we.agent_ids_json = json;
    REQUIRE(workflow_execution_visible(we, authz::VisibleSet{std::unordered_set<std::string>{"a1"}}));
    auto page = engine.query_executions_page({}, Scope{std::vector<std::string>{"a1"}});
    REQUIRE(page.has_value());
    CHECK(page->rows.empty());
    // Unconfined callers are unaffected.
    auto open = engine.query_executions_page({}, std::nullopt);
    REQUIRE(open.has_value());
    CHECK(ids_of(*open) == std::vector<std::string>{"nul-mixed"});
}

TEST_CASE("WorkflowEngine::query_executions_page: the documented SQL-vs-C++ visibility "
          "divergences keep their direction",
          "[workflow_engine][pg][list][confinement]") {
    // jsonb and nlohmann accept different JSON, so these cannot sit in the equality corpus above.
    // Only a write that bypasses the engine can store either shape (execute() dumps a
    // vector<string>). Each row names the direction; if a probe shows PostgreSQL decides
    // differently, the row's expectation is what is wrong, not the predicate.
    struct Divergence {
        std::string label;
        std::string json;
        bool sql_shows;    // the list admits the run to a caller whose scope is {"a1"}
        bool oracle_shows; // workflow_execution_visible() admits it to the same caller
    };
    const std::vector<Divergence> rows{
        // jsonb takes any number numeric can hold; nlohmann rejects a double overflow and
        // discards the WHOLE document. The list shows a run whose detail read says not-visible; the
        // run does name the in-scope "a1", so nothing out of scope is exposed.
        {"number-past-double-range", R"(["a1",1e400])", true, false},
        // jsonb refuses a byte-order mark where nlohmann skips it: hidden here, shown there.
        {"utf8-bom-prefix", "\xEF\xBB\xBF[\"a1\"]", false, true},
    };
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("divergence"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    int64_t t = 10;
    for (const auto& r : rows)
        seed_run(conn.get(), r.label, wf, t++, r.json);

    const authz::VisibleSet vs{std::unordered_set<std::string>{"a1"}};
    auto page = engine.query_executions_page({}, Scope{std::vector<std::string>{"a1"}});
    REQUIRE(page.has_value()); // neither shape may error the statement
    const auto got = ids_of(*page);
    for (const auto& r : rows) {
        INFO(r.label);
        WorkflowExecution we;
        we.agent_ids_json = r.json;
        CHECK(workflow_execution_visible(we, vs) == r.oracle_shows);
        CHECK((std::find(got.begin(), got.end(), r.label) != got.end()) == r.sql_shows);
    }
}

TEST_CASE("WorkflowEngine::query_executions_page: the store clamps limit itself, never an empty "
          "page or the sentinel row",
          "[workflow_engine][pg][list]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("clamp"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // 502 runs, so even the largest clamped page (500) has a successor. Ids sort with started_at.
    for (int i = 0; i < 502; ++i) {
        const auto n = std::to_string(i);
        seed_run(conn.get(), "r-" + std::string(3 - n.size(), '0') + n, wf, i, "[]");
    }
    for (const auto& [asked, want] :
         std::vector<std::pair<int, std::size_t>>{{0, 1}, {-1, 1}, {501, 500}, {100000, 500}}) {
        INFO("asked " << asked);
        WorkflowExecutionListQuery q;
        q.limit = asked;
        auto page = engine.query_executions_page(q, std::nullopt);
        REQUIRE(page.has_value());
        REQUIRE(page->rows.size() == want); // also guards the back() below
        CHECK(page->rows.front().id == "r-501");
        REQUIRE(page->next.has_value());
        // The cursor is the last row RETURNED, never the 501st (sentinel) row.
        CHECK(page->next->id == page->rows.back().id);
        CHECK(page->next->key == page->rows.back().started_at);
    }
}

TEST_CASE("WorkflowEngine::query_executions_page: invisible runs never consume a page slot or "
          "shape a cursor",
          "[workflow_engine][pg][list][confinement]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("pageslots"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // Five NEWER runs the caller cannot see, three older ones it can.
    for (int i = 0; i < 5; ++i)
        seed_run(conn.get(), "hidden-" + std::to_string(i), wf, 500 + i, R"(["other"])");
    seed_run(conn.get(), "vis-c", wf, 300, R"(["mine"])");
    seed_run(conn.get(), "vis-b", wf, 200, R"(["mine","other"])");
    seed_run(conn.get(), "vis-a", wf, 100, R"(["mine"])");
    const Scope scope{std::vector<std::string>{"mine"}};

    WorkflowExecutionListQuery q;
    q.limit = 2;
    auto first = engine.query_executions_page(q, scope);
    REQUIRE(first.has_value());
    // A post-filter would have returned an empty page here (the 2 newest rows are hidden).
    CHECK(ids_of(*first) == std::vector<std::string>{"vis-c", "vis-b"});
    REQUIRE(first->next.has_value());
    CHECK(first->next->id == "vis-b");

    q.after = first->next;
    auto second = engine.query_executions_page(q, scope);
    REQUIRE(second.has_value());
    CHECK(ids_of(*second) == std::vector<std::string>{"vis-a"});
    CHECK_FALSE(second->next.has_value());

    // A forged position that names a hidden run reveals nothing: the scope is ANDed with it, so the
    // answer is exactly the visible runs older than the position, never the hidden ones.
    q.limit = 10;
    q.after = keyset::Position{502, "hidden-2"};
    auto forged = engine.query_executions_page(q, scope);
    REQUIRE(forged.has_value());
    CHECK(ids_of(*forged) == std::vector<std::string>{"vis-c", "vis-b", "vis-a"});
    CHECK_FALSE(forged->next.has_value());
}

TEST_CASE("WorkflowEngine::query_executions_page: an engaged-empty scope answers an empty page "
          "without touching the database",
          "[workflow_engine][pg][list][confinement]") {
    WORKFLOW_ENGINE(engine);
    const auto wf = *engine.create_workflow(wf_yaml("denyall"));
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    seed_run(conn.get(), "r1", wf, 10, R"(["a1"])");

    auto page = engine.query_executions_page({}, Scope{std::vector<std::string>{}});
    REQUIRE(page.has_value());
    CHECK(page->rows.empty());
    CHECK_FALSE(page->next.has_value());

    // Prove it never reached the table: with the table gone the same call still answers empty,
    // while an unconfined read of it is a genuine failure.
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_step_results, "
                    "workflow_engine.workflow_executions CASCADE",
        std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);
    auto again = engine.query_executions_page({}, Scope{std::vector<std::string>{}});
    REQUIRE(again.has_value());
    CHECK(again->rows.empty());
    auto open = engine.query_executions_page({}, std::nullopt);
    REQUIRE_FALSE(open.has_value());
    CHECK(open.error().starts_with(kDbErrorPrefix));
}

TEST_CASE("WorkflowEngine::query_executions_page: a query failure is a typed degrade for confined "
          "and unconfined reads alike and never an empty page",
          "[workflow_engine][pg][list][degrade]") {
    WORKFLOW_ENGINE(engine);
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_step_results, "
                    "workflow_engine.workflow_executions CASCADE",
        std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    for (const Scope& scope : {Scope{}, Scope{std::vector<std::string>{"a1"}}}) {
        auto page = engine.query_executions_page({}, scope);
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error().starts_with(kDbErrorPrefix));
    }
    WorkflowExecutionListQuery latest;
    latest.latest_per_workflow = true;
    auto lp = engine.query_executions_page(latest, std::nullopt);
    REQUIRE_FALSE(lp.has_value());
    CHECK(lp.error().starts_with(kDbErrorPrefix));
}

TEST_CASE("WorkflowEngine::query_executions_page: a read blocked behind an exclusive lock ends at "
          "the statement timeout as a typed degrade and the pool stays usable",
          "[workflow_engine][pg][list][timeout]") {
    // Pins that the shell EXECUTES the builder's `SET LOCAL statement_timeout` (the builder case
    // pins only its text). A second connection holds ACCESS EXCLUSIVE on the table the read
    // touches, so the read blocks server-side until the budget fires. With the statement skipped
    // the read is bounded only by the pool's own `lock_timeout_ms` below and ends as a LOCK
    // timeout, so asserting the statement-timeout wording fails instead of hanging. No sleeps and
    // no clock reads: the 100 ms budget is a server-side timer, the lock is held until released.
    YUZU_REQUIRE_PG_DB_TPL(wf_db_fx_, workflow_engine_tpl);
    PgPool wf_pool_fx_{{.conninfo = wf_db_fx_.dsn(), .size = 2, .lock_timeout_ms = 5000}};
    REQUIRE(wf_pool_fx_.valid());
    WorkflowEngine engine{wf_pool_fx_};
    REQUIRE(engine.is_open());

    PgConn holder{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    for (const char* sql : {"BEGIN", "LOCK TABLE workflow_engine.workflow_executions "
                                     "IN ACCESS EXCLUSIVE MODE"}) {
        PgResult r = yuzu::server::pg::exec_params(holder.get(), sql, std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto blocked = engine.query_executions_page({}, std::nullopt, std::chrono::milliseconds{100});
    REQUIRE_FALSE(blocked.has_value()); // a timeout is a degrade, never an empty or short page
    CHECK(blocked.error().starts_with(kDbErrorPrefix));
    CHECK(blocked.error().find("statement timeout") != std::string::npos);

    PgResult release =
        yuzu::server::pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{});
    REQUIRE(release.status() == PGRES_COMMAND_OK);
    auto after = engine.query_executions_page({}, std::nullopt); // the shipped default budget
    REQUIRE(after.has_value());
    CHECK(after->rows.empty());
}

TEST_CASE("WorkflowEngine::query_executions_page: latest-per-workflow is the newest VISIBLE run "
          "per workflow in workflow order",
          "[workflow_engine][pg][list][latest]") {
    WORKFLOW_ENGINE(engine);
    // Workflow ids are generated, so name the order by what the engine actually minted.
    const auto w_a = *engine.create_workflow(wf_yaml("latest-a"));
    const auto w_b = *engine.create_workflow(wf_yaml("latest-b"));
    const auto w_c = *engine.create_workflow(wf_yaml("latest-c"));
    std::vector<std::string> wf_order{w_a, w_b, w_c};
    std::sort(wf_order.begin(), wf_order.end());

    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // w_a: an older visible run and a NEWER one the confined caller cannot see.
    seed_run(conn.get(), "a-old-visible", w_a, 100, R"(["mine"])", "completed");
    seed_run(conn.get(), "a-new-hidden", w_a, 200, R"(["other"])", "failed");
    // w_b: only hidden runs. w_c: two visible runs sharing a second (id breaks the tie).
    seed_run(conn.get(), "b-hidden", w_b, 150, R"(["other"])", "completed");
    seed_run(conn.get(), "c-1", w_c, 300, R"(["mine"])", "failed");
    seed_run(conn.get(), "c-2", w_c, 300, R"(["mine"])", "completed");

    WorkflowExecutionListQuery q;
    q.latest_per_workflow = true;

    // Unconfined: each workflow's newest run, ordered by workflow id.
    auto open = engine.query_executions_page(q, std::nullopt);
    REQUIRE(open.has_value());
    std::vector<std::string> want_open;
    for (const auto& wf : wf_order)
        want_open.push_back(wf == w_a ? "a-new-hidden" : wf == w_b ? "b-hidden" : "c-2");
    CHECK(ids_of(*open) == want_open);
    CHECK_FALSE(open->truncated_by_cap);
    CHECK_FALSE(open->next.has_value());

    // Confined: visibility is applied BEFORE the per-workflow pick, so w_a answers its newest
    // visible run (not a blanked newest one) and w_b, with nothing visible, is absent.
    auto mine = engine.query_executions_page(q, Scope{std::vector<std::string>{"mine"}});
    REQUIRE(mine.has_value());
    std::vector<std::string> want_mine;
    for (const auto& wf : wf_order) {
        if (wf == w_a)
            want_mine.push_back("a-old-visible");
        else if (wf == w_c)
            want_mine.push_back("c-2");
    }
    CHECK(ids_of(*mine) == want_mine);

    // Other filters apply to the candidate runs before the pick.
    q.status = "failed";
    auto failed = engine.query_executions_page(q, std::nullopt);
    REQUIRE(failed.has_value());
    std::vector<std::string> want_failed;
    for (const auto& wf : wf_order)
        if (wf == w_a)
            want_failed.push_back("a-new-hidden");
        else if (wf == w_c)
            want_failed.push_back("c-1");
    CHECK(ids_of(*failed) == want_failed);
}

TEST_CASE("WorkflowEngine::query_executions_page: latest-per-workflow flags the cap and never "
          "returns a cursor",
          "[workflow_engine][pg][list][latest]") {
    WORKFLOW_ENGINE(engine);
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    std::vector<std::string> wfs;
    for (const char* n : {"cap-a", "cap-b", "cap-c"}) {
        wfs.push_back(*engine.create_workflow(wf_yaml(n)));
        seed_run(conn.get(), std::string("run-") + n, wfs.back(), 10, "[]");
    }
    WorkflowExecutionListQuery q;
    q.latest_per_workflow = true;
    q.limit = 2;
    auto capped = engine.query_executions_page(q, std::nullopt);
    REQUIRE(capped.has_value());
    CHECK(capped->rows.size() == 2);
    CHECK(capped->truncated_by_cap);
    CHECK_FALSE(capped->next.has_value());
    q.limit = 3; // exactly as many workflows as the limit: not truncated
    auto exact = engine.query_executions_page(q, std::nullopt);
    REQUIRE(exact.has_value());
    CHECK(exact->rows.size() == 3);
    CHECK_FALSE(exact->truncated_by_cap);
}
