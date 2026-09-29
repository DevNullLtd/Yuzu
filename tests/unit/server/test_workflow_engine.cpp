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
 */

#include "workflow_engine.hpp"

#include "mcp_jsonrpc.hpp" // json_exceeds_depth / kMcpMaxJsonDepth (#2437-class depth guard)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
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
