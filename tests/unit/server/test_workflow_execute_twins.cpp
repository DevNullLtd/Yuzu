/**
 * test_workflow_execute_twins.cpp -- #2146 batch B: POST /api/v1/workflows/{id}/execute and the
 * shared sequence it and MCP `execute_workflow` run (workflow_execute.hpp). No Postgres.
 *
 * What is real here: the sequence itself, the REST route lambda on a TestRouteSink, the
 * production capability catalogue, and (for the send-set cases) a real AgentRegistry driven
 * through `wire_and_dispatch_confined`, so a confined caller's intersection is OBSERVED on the
 * agents that were queued, not merely handed over as a `VisibleSet`.
 *
 * What is a stand-in and named as such: the WorkflowApi (FnWorkflowApi: the "engine" is a lambda
 * that drives the step callback once per step, synchronously, exactly as WorkflowEngine::execute
 * does), the instruction lookup, and the audit sink. The real InstructionStore, ApprovalManager
 * and WorkflowEngine are Postgres-backed; their wiring is by flag/port and is covered where it
 * is decided (the `*_available` flags), not by a database.
 *
 * MCP `execute_workflow` is covered in test_mcp_server.cpp (its harness lives there): the tier
 * and ticket composition are asserted below as pure policy, the handler's refusals there.
 */

#include "agent_registry.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_send_progress.hpp"
#include "dispatch_target_shape.hpp"
#include "dispatch_zero_reach.hpp"
#include "mcp_policy.hpp"
#include "openapi_spec_access.hpp"
#include "sha256_hex.hpp"
#include "stream_budget.hpp"
#include "test_route_sink.hpp"
#include "test_workflow_api_double.hpp"
#include "workflow_execute.hpp"
#include "workflow_execute_routes.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::ClassifiedCommandTestAccess;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

// ── a fixture workflow whose steps are fully controllable ───────────────────────────────────

WorkflowStepInstruction def(std::string id, std::string plugin, std::string action,
                            std::string mode = "auto") {
    return WorkflowStepInstruction{std::move(id), std::move(plugin), std::move(action),
                                   std::move(mode), "per-device"};
}

struct Fx {
    CommandCapabilityRegistry caps{YUZU_ALL_CAPABILITY_FRAGMENTS};

    // The stored workflow: step i runs instruction ids[i].
    std::vector<std::string> step_ids{"i-ro"};
    // Instruction store contents. `lookup_overrides[id]` (when non-empty) is served from the
    // SECOND read of that id on, to model a definition edited after the preflight.
    std::map<std::string, WorkflowStepInstruction> defs{{"i-ro", def("i-ro", "os_info", "os_version")}};
    std::map<std::string, WorkflowStepInstruction> late_defs;
    std::map<std::string, int> lookup_count;
    bool store_fault{false};
    /// Reads of the stored workflow (`get_workflow`): a refusal before any read leaves it at 0.
    int get_workflow_calls{0};

    // Wiring switches.
    bool store_open{true};
    bool approval_gate{true};
    bool wire_api{true};
    bool wire_run{true};
    bool wire_authorize{true};
    bool audit_ok{true};
    std::optional<size_t> audit_fails_on_call; // 0-based index of the audit call that fails

    // What happened, in order. "audit:<result>", "dispatch:<instr>", "engine_returned".
    std::vector<std::string> events;
    std::vector<std::string> audit_details;
    // The platform events the run published (the `emit` port), with the number of audit rows
    // that existed when each was published, and the attributes/payload it carried.
    struct Emitted {
        std::string type;
        json attrs, payload;
        size_t audit_rows_at;
    };
    std::vector<Emitted> emitted;
    bool wire_emit{true};
    bool emit_throws{false};
    std::vector<std::string> counted_rejections;
    std::vector<std::string> counted_denials;
    // The chokepoint dry run is the REAL classify_and_authorize_dispatch + kill_switch_denial over
    // the production catalogue; these two sets stand in for the RBAC store and the plugin-config
    // store. `rbac_denied`: securables the caller holds no grant on. `killed`: "plugin.action".
    std::set<std::string> rbac_denied;
    std::set<std::string> killed;
    std::vector<std::string> authorize_calls; // "plugin.action", in call order
    std::vector<DispatchCaller> dispatched_callers;
    std::vector<std::vector<std::string>> dispatched_ids;

    // What the dispatch port answers for an instruction (default: reached one agent).
    std::map<std::string, ConfinedDispatchOutcome> outcomes;
    // Replace the dispatch port entirely (the send-set cases).
    std::function<ConfinedDispatchOutcome(const WorkflowStepInstruction&,
                                          const std::vector<std::string>&, const DispatchCaller&)>
        dispatch_override;

    std::string engine_status{"completed"};
    /// The step rows and status the stand-in engine persisted per execution id, as the real
    /// engine's `workflow_step_results` would hold them: `get_workflow_execution` serves them.
    /// An execution a test bound by hand (`bind`, or a literal `bound[...]`) has none here, and
    /// is served the one row its status implies (`rows_implied_by`).
    std::map<std::string, std::vector<WorkflowStepResult>> stored_rows;
    std::map<std::string, std::string> stored_status;
    std::expected<std::string, std::string> engine_error{std::string{"exec-1"}};
    bool engine_called{false};
    // The stand-in engine throws before it admits the run (no execution id yet).
    bool engine_throws_before_admit{false};
    // What each step's dispatch callback answered with when it failed (the engine reads
    // `permanent` to decide whether to retry).
    std::vector<StepDispatchError> step_errors;
    int run_threw_count{0};
    // (retry_count, retry_delay_seconds) of step i, as the stored workflow carries them; steps
    // beyond the list keep the model defaults (0 retries).
    std::vector<std::pair<int, int>> step_retries;
    // What the run port was handed, and a hook called once the run is admitted (the lease-held
    // assertions run there).
    std::optional<std::chrono::steady_clock::time_point> seen_deadline;
    bool seen_before_attempt{false};
    std::function<void()> during_run;
    // The stand-in engine asks `before_attempt` ahead of every step, as the real engine does ahead
    // of every attempt, and stops the run (skipping the rest) when it says no.
    bool engine_stopped{false};
    /// >= 0: before dispatching the step at this 0-based position the stand-in engine behaves as
    /// the real one does on a server stop: it calls `on_interrupted` once and sends nothing more.
    int interrupt_before_step{-1};
    /// Retry attempts the stand-in engine makes for a step whose dispatch failed non-permanently
    /// (each asks `before_attempt` again, as the real engine does after its retry sleep).
    int engine_retries{0};

    // ── the per-step credential check (WorkflowExecuteRequest::reauthorize) ──
    bool wire_reauth{false};
    /// Answers handed out in order; once exhausted `reauth_after` is the answer. `reauth_script`,
    /// when set, replaces both (a throwing check).
    std::vector<auth::CredentialCheck> reauth_answers;
    auth::CredentialCheck reauth_after{auth::CredentialCheck::kValid};
    std::function<auth::CredentialCheck()> reauth_script;
    int reauth_calls{0};
    /// How many sends had been made when each ask happened (proves "before step N", not "after").
    std::vector<int> reauth_dispatches_at;

    auth::CredentialCheck next_reauth() {
        ++reauth_calls;
        int sent = 0;
        for (const auto& e : events)
            if (e.starts_with("dispatch:"))
                ++sent;
        reauth_dispatches_at.push_back(sent);
        if (reauth_script)
            return reauth_script();
        if (reauth_calls <= static_cast<int>(reauth_answers.size()))
            return reauth_answers[static_cast<size_t>(reauth_calls - 1)];
        return reauth_after;
    }

    // ── idempotency (#2146) ──
    // The runs the stand-in engine has bound a key to, by (principal, key). The pre-check reads
    // it through the idempotency lookup port; the stand-in engine's atomic claim reads and writes it.
    std::map<std::pair<std::string, std::string>, WorkflowIdempotentRun> bound;
    int find_calls{0};
    bool find_fault{false};
    /// `get_workflow_execution` fails (the replay cannot read the stored steps back).
    bool get_exec_fault{false};
    std::int64_t fixed_now{1'000'000};
    std::optional<WorkflowIdempotencyClaim> seen_claim;
    /// What the sequence handed the run port beside the claim, keyed or not.
    std::string seen_control_principal;
    std::string seen_control_cid;
    std::map<std::string, int> idem_counts;
    /// Every (outcome, reason) the run counted, in order (`count_run_outcome`).
    std::vector<std::pair<std::string, std::string>> run_outcomes;
    /// Called by the stand-in engine right before it claims: lets a test bind a competing run
    /// AFTER the pre-check said "none" (the lost race).
    std::function<void(const WorkflowIdempotencyClaim&)> before_claim;

    /// The fingerprint the sequence computes for (workflow_id, ids), as the spec writes it.
    static std::string fingerprint_of(const std::string& wf, std::vector<std::string> ids) {
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        const auto frame = [](const std::string& f) { return std::to_string(f.size()) + ":" + f; };
        std::string material = "wf-exec-v2\n" + frame(wf);
        for (const auto& id : ids)
            material += frame(id);
        return *sha256_hex(material);
    }
    /// The rows of a run a test bound by hand: one step, settled the way its status says. A
    /// completed run holds a `success` row, a failed or cancelled one a `failed` row; anything
    /// else holds none.
    static std::vector<WorkflowStepResult> rows_implied_by(const std::string& status) {
        WorkflowStepResult r;
        r.step_index = 0;
        r.instruction_id = "i-ro";
        if (status == "completed") {
            r.status = "success";
            r.result_json = R"({"status":"dispatched","command_id":"cmd-i-ro","agents_reached":1})";
            return {r};
        }
        if (status == "failed" || status == "cancelled") {
            r.status = "failed";
            r.result_json = R"j([{"error":"no agents reached for i-ro (no_agents_reached)"}])j";
            return {r};
        }
        return {};
    }
    void bind(const std::string& principal, const std::string& key, const std::string& status,
              std::int64_t started_ago_s = 1, const std::string& wf = "wf-1",
              std::vector<std::string> ids = {"a1"}, const std::string& exec = "exec-bound") {
        bound[{principal, key}] = WorkflowIdempotentRun{exec, wf, fingerprint_of(wf, std::move(ids)),
                                                        status, fixed_now - started_ago_s};
    }

    WorkflowExecuteRequest request(std::vector<std::string> ids = {"a1"}) {
        WorkflowExecuteRequest r;
        r.workflow_id = "wf-1";
        r.agent_ids = std::move(ids);
        r.caller = DispatchCaller{.principal = "alice",
                                  .principal_role = "user",
                                  .exec_visible = std::nullopt,
                                  .principal_is_admin = false};
        r.audit_context = "surface=test";
        if (wire_reauth) {
            r.reauthorize = [this] { return next_reauth(); };
            r.reauthorize_retry_delay = std::chrono::milliseconds(1); // no real second per test
        }
        return r;
    }

    std::shared_ptr<test::FnWorkflowApi> api() {
        auto get = [this](const std::string& id) -> std::expected<std::optional<Workflow>, std::string> {
            ++get_workflow_calls;
            if (store_fault)
                return std::unexpected(std::string{"db: boom"});
            if (id != "wf-1")
                return std::optional<Workflow>{};
            Workflow w;
            w.id = "wf-1";
            w.name = "wf";
            int i = 0;
            for (const auto& sid : step_ids) {
                WorkflowStep s;
                s.index = i++;
                s.instruction_id = sid;
                s.label = "step-" + sid;
                if (static_cast<size_t>(s.index) < step_retries.size()) {
                    s.retry_count = step_retries[static_cast<size_t>(s.index)].first;
                    s.retry_delay_seconds = step_retries[static_cast<size_t>(s.index)].second;
                }
                w.steps.push_back(s);
            }
            return std::optional<Workflow>{w};
        };
        auto get_exec = [this](const std::string& id)
            -> std::expected<std::optional<WorkflowExecution>, std::string> {
            if (get_exec_fault)
                return std::unexpected(std::string{"db: boom"});
            WorkflowExecution e;
            e.id = id;
            e.workflow_id = "wf-1";
            e.status = engine_status;
            if (const auto it = stored_status.find(id); it != stored_status.end()) {
                e.status = it->second;
            } else {
                for (const auto& [k, run] : bound) {
                    if (run.execution_id == id)
                        e.status = run.status;
                }
            }
            if (const auto it = stored_rows.find(id); it != stored_rows.end())
                e.step_results = it->second;
            else
                e.step_results = rows_implied_by(e.status);
            return std::optional<WorkflowExecution>{e};
        };
        return std::make_shared<test::FnWorkflowApi>(test::FnWorkflowApi::ListFn{}, get, get_exec);
    }

    /// The idempotency pre-check port over `bound`, keyed by the CALLER's principal.
    WorkflowIdempotencyLookupFn idempotency_lookup_fn() {
        return [this](const DispatchCaller& caller, const std::string& key)
                   -> std::expected<std::optional<WorkflowIdempotentRun>, std::string> {
            ++find_calls;
            if (find_fault)
                return std::unexpected(std::string{"db: boom"});
            if (auto it = bound.find({caller.principal, key}); it != bound.end())
                return std::optional<WorkflowIdempotentRun>{it->second};
            return std::optional<WorkflowIdempotentRun>{};
        };
    }

    /// The stand-in for the engine behind the run port: it drives the steps in order,
    /// synchronously, one callback per step; a failed step does not stop the loop here
    /// (on_failure=continue semantics).
    WorkflowRunFn run_fn() {
        return [this](const std::string&, const std::vector<std::string>&, StepDispatchFn fn,
                      ConditionEvalFn, const WorkflowRunControl& control)
                   -> std::expected<std::string, std::string> {
            engine_called = true;
            seen_deadline = control.deadline;
            seen_before_attempt = static_cast<bool>(control.before_attempt);
            if (!engine_error)
                return engine_error;
            if (engine_throws_before_admit)
                throw std::runtime_error("engine exploded before admission");
            // The engine's atomic claim: a key already bound is a replay (nothing admitted);
            // otherwise the claim binds it to the run being admitted.
            seen_claim = control.idempotency;
            seen_control_principal = control.principal;
            seen_control_cid = control.correlation_id;
            if (control.idempotency) {
                const auto& c = *control.idempotency;
                if (before_claim)
                    before_claim(c);
                if (auto it = bound.find({c.principal, c.key}); it != bound.end()) {
                    if (control.on_replay)
                        control.on_replay(WorkflowRunReplay{it->second.execution_id,
                                                            it->second.workflow_id,
                                                            it->second.request_fingerprint,
                                                            it->second.status,
                                                            it->second.started_at});
                    return std::unexpected(std::string(kWorkflowIdempotentReplayError));
                }
                bound[{c.principal, c.key}] = WorkflowIdempotentRun{
                    *engine_error, "wf-1", c.fingerprint, "running", fixed_now};
            }
            if (control.on_admitted) // as the real engine, once admitted and before step 1
                control.on_admitted(*engine_error);
            if (during_run)
                during_run();
            const std::string exec = *engine_error;
            auto& rows = stored_rows[exec];
            rows.clear();
            for (size_t i = 0; i < step_ids.size(); ++i) {
                WorkflowStepResult r;
                r.step_index = static_cast<int>(i);
                r.instruction_id = step_ids[i];
                r.status = "pending";
                r.result_json = "{}";
                rows.push_back(r);
            }
            stored_status[exec] = "running";
            const auto skip_from = [&](size_t from, const char* reason) {
                for (size_t i = from; i < rows.size(); ++i) {
                    rows[i].status = "skipped";
                    rows[i].result_json = std::string(R"({"reason":")") + reason + R"("})";
                }
            };
            int position = -1;
            for (const auto& sid : step_ids) {
                ++position;
                auto& row = rows[static_cast<size_t>(position)];
                if (position == interrupt_before_step) {
                    if (control.on_interrupted)
                        control.on_interrupted();
                    engine_stopped = true;
                    skip_from(static_cast<size_t>(position), "server_shutdown");
                    break;
                }
                bool stopped = false;
                bool ok = false;
                int attempt = 0;
                std::string last;
                for (;; ++attempt) {
                    if (control.on_attempt)
                        control.on_attempt(position, attempt + 1);
                    if (control.before_attempt && !control.before_attempt()) {
                        stopped = true;
                        last = R"j([{"error":"run stopped before this attempt","reason":"run stopped"}])j";
                        break;
                    }
                    std::expected<std::string, StepDispatchError> r;
                    try {
                        r = fn(sid, "[]", "{}");
                    } catch (...) {
                        // As the real engine: the step failed, the rest skipped, the execution
                        // closed failed, and the throw goes on to the caller.
                        row.status = "failed";
                        row.result_json =
                            R"j({"error":"step dispatch threw","reason":"dispatch_exception"})j";
                        row.attempt = attempt + 1;
                        skip_from(static_cast<size_t>(position) + 1, "workflow aborted");
                        stored_status[exec] = "failed";
                        if (control.idempotency)
                            bound[{control.idempotency->principal, control.idempotency->key}]
                                .status = "failed";
                        throw;
                    }
                    if (r) {
                        ok = true;
                        last = *r;
                        break;
                    }
                    step_errors.push_back(r.error());
                    last = nlohmann::json::array({nlohmann::json{{"error", r.error().message}}}).dump();
                    if (r.error().permanent || attempt >= engine_retries)
                        break;
                }
                row.status = ok ? "success" : "failed";
                row.result_json = last;
                row.attempt = attempt + 1;
                if (stopped) {
                    engine_stopped = true;
                    skip_from(static_cast<size_t>(position) + 1, "run stopped");
                    break;
                }
            }
            stored_status[exec] = engine_status;
            events.push_back("engine_returned");
            if (control.idempotency)
                bound[{control.idempotency->principal, control.idempotency->key}].status =
                    engine_status;
            return engine_error;
        };
    }

    WorkflowExecutePorts ports(const std::shared_ptr<test::FnWorkflowApi>& a) {
        WorkflowExecutePorts p;
        p.api = wire_api ? a.get() : nullptr;
        p.run = wire_run ? run_fn() : WorkflowRunFn{};
        p.idempotency_lookup = idempotency_lookup_fn();
        p.instruction_store_open = store_open;
        p.approval_gate_available = approval_gate;
        p.lookup = [this](const std::string& id)
            -> std::expected<std::optional<WorkflowStepInstruction>, std::string> {
            if (store_fault)
                return std::unexpected(std::string{"db: boom"});
            const int n = ++lookup_count[id];
            if (n > 1) {
                if (auto it = late_defs.find(id); it != late_defs.end())
                    return std::optional<WorkflowStepInstruction>{it->second};
            }
            if (auto it = defs.find(id); it != defs.end())
                return std::optional<WorkflowStepInstruction>{it->second};
            return std::optional<WorkflowStepInstruction>{};
        };
        p.classify = [this](std::string_view plugin, std::string_view action) {
            return caps.classify(plugin, action);
        };
        if (wire_authorize)
            p.authorize = [this](const DispatchCaller& c, std::string_view plugin,
                                 std::string_view action)
                -> std::expected<CommandCapability, detail::DispatchDenial> {
                authorize_calls.push_back(std::string(plugin) + "." + std::string(action));
                auto decision = detail::classify_and_authorize_dispatch(
                    caps, c, plugin, action,
                    [this](std::string_view, std::string_view securable, authz::Operation) {
                        return !rbac_denied.contains(std::string(securable));
                    });
                if (!decision)
                    return decision;
                const detail::KillSwitchFn allowed =
                    [this](std::string_view pl, std::string_view ac)
                    -> std::optional<std::unordered_set<std::string>> {
                    if (killed.contains(std::string(pl) + "." + std::string(ac)))
                        return std::nullopt;
                    return std::unordered_set<std::string>{};
                };
                if (auto os_set = detail::kill_switch_denial(*decision, allowed); !os_set)
                    return std::unexpected(os_set.error());
                return decision;
            };
        p.dispatch = [this](const WorkflowStepInstruction& d, const std::vector<std::string>& ids,
                            const std::unordered_map<std::string, std::string>&,
                            const DispatchCaller& c) {
            events.push_back("dispatch:" + d.id);
            dispatched_callers.push_back(c);
            dispatched_ids.push_back(ids);
            if (dispatch_override)
                return dispatch_override(d, ids, c);
            if (auto it = outcomes.find(d.id); it != outcomes.end())
                return it->second;
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-" + d.id};
        };
        p.audit = [this](const std::string&, const std::string& result, const std::string&,
                         const std::string& detail) {
            const size_t idx = audit_details.size();
            events.push_back("audit:" + result);
            audit_details.push_back(detail);
            if (audit_fails_on_call && *audit_fails_on_call == idx)
                return false;
            return audit_ok;
        };
        p.count_target_rejected = [this](std::string_view r) {
            counted_rejections.emplace_back(r);
        };
        p.count_dispatch_denied = [this](std::string_view r) { counted_denials.emplace_back(r); };
        p.count_run_threw = [this] { ++run_threw_count; };
        p.count_idempotent = [this](std::string_view o) { ++idem_counts[std::string(o)]; };
        p.count_run_outcome = [this](std::string_view o, std::string_view r) {
            run_outcomes.emplace_back(std::string(o), std::string(r));
        };
        p.now_epoch = [this] { return fixed_now; };
        if (wire_emit)
            p.emit = [this](std::string_view type, const json& attrs, const json& payload) {
                emitted.push_back({std::string(type), attrs, payload, audit_details.size()});
                if (emit_throws)
                    throw std::runtime_error("analytics sink blew up");
            };
        return p;
    }

    WorkflowExecuteOutcome run(WorkflowExecuteRequest r) {
        auto a = api();
        return apply_workflow_execute(ports(a), r);
    }
    WorkflowExecuteOutcome run() { return run(request()); }

    [[nodiscard]] bool dispatched_anything() const {
        for (const auto& e : events)
            if (e.starts_with("dispatch:"))
                return true;
        return false;
    }
    [[nodiscard]] size_t position(std::string_view ev) const {
        for (size_t i = 0; i < events.size(); ++i)
            if (events[i] == ev)
                return i;
        return events.size();
    }
};

} // namespace

// ───────────────────────────── fail-closed wiring (owner ruling 2026-10-30) ─────────────────

TEST_CASE("workflow execute: an unwired or closed dependency refuses with 503 and NOTHING happens",
          "[workflow][twin][security][failclosed]") {
    struct Row {
        const char* what;
        std::function<void(Fx&)> break_it;
        const char* reason;
    };
    const Row rows[] = {
        {"approval gate not wired", [](Fx& f) { f.approval_gate = false; }, "approval_gate_unavailable"},
        {"instruction store not open", [](Fx& f) { f.store_open = false; }, "instruction_store_unavailable"},
        {"workflow API not wired", [](Fx& f) { f.wire_api = false; }, "workflow_engine_unavailable"},
        {"workflow run port not wired", [](Fx& f) { f.wire_run = false; }, "workflow_engine_unavailable"},
        {"dispatch authorizer not wired", [](Fx& f) { f.wire_authorize = false; }, "dispatch_unavailable"},
    };
    for (const auto& r : rows) {
        INFO(r.what);
        Fx f;
        r.break_it(f);
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kUnavailable);
        CHECK(o.reason == r.reason);
        CHECK_FALSE(f.engine_called);
        CHECK_FALSE(f.dispatched_anything());
        CHECK(f.audit_details.empty()); // not even a requested row: nothing was admitted
    }
}

TEST_CASE("workflow execute: a missing classifier, authorizer, dispatcher or audit sink also refuses "
          "before any effect",
          "[workflow][twin][security][failclosed]") {
    for (int which = 0; which < 4; ++which) {
        Fx f;
        auto a = f.api();
        auto p = f.ports(a);
        if (which == 0)
            p.classify = nullptr;
        if (which == 1)
            p.dispatch = nullptr;
        if (which == 2)
            p.audit = nullptr;
        if (which == 3)
            p.authorize = nullptr; // unwired is "no dry run", never "no gate": fail closed
        const auto o = apply_workflow_execute(p, f.request());
        CHECK(o.status == WorkflowExecuteStatus::kUnavailable);
        CHECK_FALSE(f.engine_called);
        CHECK_FALSE(f.dispatched_anything());
    }
}

TEST_CASE("workflow execute: a caller with no principal is refused before anything is read",
          "[workflow][twin][security]") {
    Fx f;
    auto r = f.request();
    r.caller.principal.clear();
    const auto o = f.run(r);
    CHECK(o.status == WorkflowExecuteStatus::kNoPrincipal);
    CHECK_FALSE(f.dispatched_anything());
}

// ───────────────────────────── the per-step approval matrix ─────────────────────────────────

TEST_CASE("workflow execute: a step's approval mode decides, per caller, before anything is sent",
          "[workflow][twin][security][approval]") {
    struct Row {
        const char* mode;
        bool admin;
        bool admitted;
    };
    const Row rows[] = {
        {"auto", false, true},        {"auto", true, true},
        {"role-gated", false, false}, {"role-gated", true, true},
        {"always", false, false},     {"always", true, false},
        {"", false, false},           {"surprise", true, false}, // unknown modes fail closed
    };
    for (const auto& r : rows) {
        INFO("mode=" << r.mode << " admin=" << r.admin);
        Fx f;
        f.defs["i-ro"].approval_mode = r.mode;
        auto req = f.request();
        req.caller.principal_is_admin = r.admin;
        const auto o = f.run(req);
        if (r.admitted) {
            CHECK(o.status == WorkflowExecuteStatus::kOk);
            CHECK(f.dispatched_anything());
        } else {
            CHECK(o.status == WorkflowExecuteStatus::kApprovalRequired);
            CHECK(o.reason == "approval_required");
            CHECK_FALSE(f.engine_called);
            CHECK_FALSE(f.dispatched_anything());
            // The refusal is audited as a denial (and no `requested` row exists).
            REQUIRE(f.audit_details.size() == 1);
            CHECK(f.events.front() == "audit:denied");
        }
    }
}

TEST_CASE("workflow execute: one blocked step among several refuses the WHOLE run (no partial send)",
          "[workflow][twin][security][approval]") {
    Fx f;
    f.step_ids = {"i-ro", "i-gated"};
    f.defs["i-gated"] = def("i-gated", "os_info", "os_version", "always");
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kApprovalRequired);
    CHECK(o.message.find("step-i-gated") != std::string::npos);
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: a consumed approval ticket does NOT lift a step's own approval mode",
          "[workflow][twin][security][approval]") {
    Fx f;
    f.defs["i-ro"].approval_mode = "always";
    auto req = f.request();
    req.caller.approval_provenance = ApprovalProvenance::Ticket; // what a transport might stamp
    const auto o = f.run(req);
    CHECK(o.status == WorkflowExecuteStatus::kApprovalRequired);
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: an unknown instruction is a 400-class refusal and nothing is sent",
          "[workflow][twin]") {
    Fx f;
    f.step_ids = {"i-ro", "i-missing"};
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kUnknownInstruction);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(f.audit_details.empty());
}

TEST_CASE("workflow execute: a store fault is a retryable 503-class refusal, never 'not found'",
          "[workflow][twin]") {
    Fx f;
    f.store_fault = true;
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kStoreFailed);
    CHECK(o.retryable);
    CHECK(o.message.find("boom") == std::string::npos); // raw store text never leaks
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: an unknown workflow, and a workflow with no steps, are refused",
          "[workflow][twin]") {
    {
        Fx f;
        auto r = f.request();
        r.workflow_id = "nope";
        CHECK(f.run(r).status == WorkflowExecuteStatus::kWorkflowNotFound);
    }
    {
        Fx f;
        f.step_ids.clear();
        CHECK(f.run().status == WorkflowExecuteStatus::kInvalidWorkflow);
        CHECK_FALSE(f.engine_called);
    }
}

// ───────────────────────────── targeting: Destructive / Forensics / unclassified ────────────

TEST_CASE("workflow execute: a step whose plugin.action is not in the catalogue is refused up front",
          "[workflow][twin][security][targeting]") {
    Fx f;
    f.defs["i-ro"] = def("i-ro", "no_such_plugin", "no_such_action");
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kUnclassifiedStep);
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: a Forensics step needs exactly one agent id",
          "[workflow][twin][security][targeting]") {
    {
        Fx f;
        f.defs["i-ro"] = def("i-ro", "execution_artifacts", "shimcache");
        auto req = f.request({"a1", "a2"});
        req.caller.principal_is_admin = true; // the ExecuteGate admits; targeting decides
        const auto o = f.run(req);
        CHECK(o.status == WorkflowExecuteStatus::kDestructiveUntargeted);
        CHECK(o.reason == std::string(kReasonForensicUntargeted));
        CHECK(f.counted_rejections == std::vector<std::string>{std::string(kReasonForensicUntargeted)});
        CHECK_FALSE(f.dispatched_anything());
    }
    {
        Fx f;
        f.defs["i-ro"] = def("i-ro", "execution_artifacts", "shimcache");
        auto req = f.request({"a1"});
        req.caller.principal_is_admin = true;
        CHECK(f.run(req).status == WorkflowExecuteStatus::kOk);
    }
}

TEST_CASE("workflow execute: a Destructive step whose named agents are ALL outside the caller's view is "
          "refused as destructive_no_visible_target",
          "[workflow][twin][security][targeting]") {
    {
        Fx f;
        f.defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1", "a2"});
        req.caller.principal_is_admin = true;
        req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"zzz"}};
        const auto o = f.run(req);
        CHECK(o.status == WorkflowExecuteStatus::kDestructiveNoVisibleTarget);
        CHECK(o.reason == std::string(kReasonDestructiveNoVisibleTarget));
        CHECK(f.counted_rejections ==
              std::vector<std::string>{std::string(kReasonDestructiveNoVisibleTarget)});
        CHECK_FALSE(f.dispatched_anything());
    }
    { // One visible agent is enough to admit; the chokepoint then narrows to it.
        Fx f;
        f.defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1", "a2"});
        req.caller.principal_is_admin = true;
        req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"a2"}};
        CHECK(f.run(req).status == WorkflowExecuteStatus::kOk);
    }
    { // A present-EMPTY visible set (deny-all) is "none visible", never "unfiltered".
        Fx f;
        f.defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1"});
        req.caller.principal_is_admin = true;
        req.caller.exec_visible = authz::deny_all();
        CHECK(f.run(req).status == WorkflowExecuteStatus::kDestructiveNoVisibleTarget);
    }
}

// ───────────────────────────── audit: requested BEFORE the effect ───────────────────────────

TEST_CASE("workflow execute: the requested audit row is written before the first step is sent",
          "[workflow][twin][security][audit]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    const auto o = f.run();
    REQUIRE(o.status == WorkflowExecuteStatus::kOk);
    REQUIRE(f.events.size() >= 4);
    CHECK(f.events[0] == "audit:requested");
    CHECK(f.position("audit:requested") < f.position("dispatch:i-ro"));
    CHECK(f.position("dispatch:i-ro2") < f.position("engine_returned"));
    CHECK(f.events.back() == "audit:success"); // the closing row
}

TEST_CASE("workflow execute: if the requested row cannot be saved nothing is sent",
          "[workflow][twin][security][audit][failclosed]") {
    Fx f;
    f.audit_fails_on_call = 0;
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kAuditFailed);
    CHECK(o.retryable);
    CHECK_FALSE(f.engine_called);
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: a lost CLOSING row is reported, not hidden, and the run stands",
          "[workflow][twin][audit]") {
    Fx f;
    f.audit_fails_on_call = 1; // call 0 = requested (persists), call 1 = closing
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    CHECK_FALSE(o.audit_persisted);
    CHECK(f.dispatched_anything());
}

TEST_CASE("workflow execute: a refusal at send time is a PERMANENT step failure, a store fault is not",
          "[workflow][twin][security][late][permanent]") {
    SECTION("an approval mode raised after the preflight") {
        Fx f;
        f.late_defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
        (void)f.run();
        REQUIRE(f.step_errors.size() == 1);
        CHECK(f.step_errors[0].permanent);
    }
    SECTION("a step turned Destructive and out of view after the preflight") {
        Fx f;
        f.late_defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1"});
        req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"other"}};
        (void)f.run(req);
        REQUIRE(f.step_errors.size() == 1);
        CHECK(f.step_errors[0].permanent);
    }
    SECTION("a step repointed off the ticket-bound effect") {
        Fx f;
        auto a = f.api();
        const auto p = f.ports(a);
        auto req = f.request();
        const auto plan = prepare_workflow_execute(p, req);
        REQUIRE(plan.has_value());
        req.expected_step_effects = workflow_step_effects(*plan);
        f.late_defs["i-ro"] = def("i-ro", "os_info", "uptime");
        (void)run_workflow_execute(p, req, *plan);
        REQUIRE(f.step_errors.size() == 1);
        CHECK(f.step_errors[0].permanent);
    }
    SECTION("a step that reaches nobody stays transient (the engine may retry it)") {
        Fx f;
        f.outcomes["i-ro"] = ConfinedDispatchOutcome{.sent = 0};
        (void)f.run();
        REQUIRE(f.step_errors.size() == 1);
        CHECK_FALSE(f.step_errors[0].permanent);
    }
}

TEST_CASE("workflow execute: a run that THROWS after the requested row is a failed run with its "
          "execution id and send count, never a retryable fault",
          "[workflow][twin][security][audit][throw]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.dispatch_override = [&](const WorkflowStepInstruction& d, const std::vector<std::string>&,
                              const DispatchCaller&) -> ConfinedDispatchOutcome {
        if (d.id == "i-ro")
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-1"};
        // Two sends were accepted by the send path when the fan-out of step 2 blew up.
        REQUIRE(SendProgressScope::current() != nullptr);
        SendProgressScope::current()->sent += 2;
        throw std::runtime_error("registry exploded mid fan-out");
    };
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kRunFailed);
    CHECK_FALSE(o.retryable);
    CHECK(o.reason == "dispatch_exception");
    CHECK(o.execution_id == "exec-1");
    CHECK(o.agents_sent == 3); // step 1's completed send plus step 2's two accepted before the throw
    CHECK(o.remediation.find("get_workflow_execution") != std::string::npos);
    CHECK(o.audit_persisted);
    CHECK(f.run_threw_count == 1);
    // requested first; the closing row is a `failure` that names both handles; no `success`.
    REQUIRE(f.audit_details.size() == 2);
    CHECK(f.events.front() == "audit:requested");
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.position("audit:success") == f.events.size());
    CHECK(f.audit_details[1].find("run_outcome=failed reason=dispatch_exception") !=
          std::string::npos);
    CHECK(f.audit_details[1].find("execution_id=exec-1") != std::string::npos);
    CHECK(f.audit_details[1].find("agents_sent=3") != std::string::npos);
    CHECK(f.audit_details[1].find("surface=test") != std::string::npos);
    // The notes of the step that was sent survive the throw.
    REQUIRE(o.steps.size() == 1);
    CHECK(o.steps[0].agents_reached == 1);
}

TEST_CASE("workflow execute: a throw before the engine admitted the run is still a failed run, with "
          "no execution id and no sends",
          "[workflow][twin][security][audit][throw]") {
    Fx f;
    f.engine_throws_before_admit = true;
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kRunFailed);
    CHECK_FALSE(o.retryable);
    CHECK(o.execution_id.empty());
    CHECK(o.agents_sent == 0);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(f.events.back() == "audit:failure");
    REQUIRE_FALSE(f.audit_details.empty());
    CHECK(f.audit_details.back().find("run_outcome=failed") != std::string::npos);
}

TEST_CASE("workflow execute: a lost closing row on a thrown run is reported, not hidden",
          "[workflow][twin][security][audit][throw]") {
    Fx f;
    f.engine_throws_before_admit = true;
    f.audit_fails_on_call = 1; // 0 = requested (persists), 1 = the closing `failure` row
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kRunFailed);
    CHECK_FALSE(o.audit_persisted);
}

TEST_CASE("workflow execute: a step edited after the preflight is refused AT SEND TIME and audited "
          "before the response, not after",
          "[workflow][twin][security][audit][late]") {
    Fx f;
    // Preflight sees an auto step; by the time the engine reaches it the instruction demands
    // approval (raised between the two reads).
    f.late_defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
    const auto o = f.run();
    CHECK_FALSE(f.dispatched_anything()); // the edited step was NOT sent
    CHECK(o.late_denied);
    CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
    CHECK(o.reason == "late_denied");
    CHECK_FALSE(o.retryable); // permanent: the same request will be refused again
    CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.audit_details.back().find("run_outcome=aborted") != std::string::npos);
    // The denied row exists, with the (late) marker, and was written BEFORE the engine returned.
    const auto denied = f.position("audit:denied");
    REQUIRE(denied < f.events.size());
    CHECK(denied < f.position("engine_returned"));
    bool late_marker = false;
    for (const auto& d : f.audit_details)
        late_marker = late_marker || d.find("(late)") != std::string::npos;
    CHECK(late_marker);
}

TEST_CASE("workflow execute: a step turned Destructive after the preflight is refused at send time",
          "[workflow][twin][security][late][targeting]") {
    Fx f;
    f.late_defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
    auto req = f.request({"a1"});
    req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"other"}};
    // Preflight (os_info.version) passes; at send time the pair is Destructive and none of the
    // named agents is visible.
    const auto o = f.run(req);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(o.late_denied);
    CHECK(f.counted_rejections ==
          std::vector<std::string>{std::string(kReasonDestructiveNoVisibleTarget)});
}

// ───────────────────────────── zero-reach: one cause per step, honest retry hints ────────────

TEST_CASE("workflow execute: every zero-reach cause is named per step with an honest retry flag",
          "[workflow][twin][zeroreach]") {
    struct Row {
        const char* token;
        bool retryable;
        std::function<void(ConfinedDispatchOutcome&)> set;
    };
    const Row rows[] = {
        {"containment_unreadable", true, [](auto& o) { o.containment_unreadable = true; }},
        {"route_unreadable", true, [](auto& o) { o.route_unreadable = true; }},
        {"os_gate_unreadable", true, [](auto& o) { o.os_gate_unreadable = true; }},
        {"quarantined", false, [](auto& o) { o.denied_quarantined_count = 2; }},
        {"plugin_not_found", false, [](auto& o) { o.unknown_plugin_count = 1; }},
        {"kill_switched_os", false, [](auto& o) { o.kill_switched_os_count = 1; }},
        {"no_agents_reached", true, [](auto&) {}},
    };
    for (const auto& r : rows) {
        INFO(r.token);
        Fx f;
        ConfinedDispatchOutcome out;
        out.sent = 0;
        out.command_id = "cmd-zero";
        r.set(out);
        f.outcomes["i-ro"] = out;
        const auto o = f.run();
        REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(o.reason == r.token);
        CHECK(o.retryable == r.retryable);
        CHECK_FALSE(o.execution_id.empty()); // the run exists and is readable
        REQUIRE(o.steps.size() == 1);
        CHECK(o.steps[0].agents_reached == 0);
        CHECK(o.steps[0].reason == r.token);
        CHECK(o.steps[0].retryable == r.retryable);
    }
}

TEST_CASE("workflow execute: a run where SOME step reached an agent but another reached nobody is "
          "PARTIAL: a failure row and a typed non-success, never `success`",
          "[workflow][twin][zeroreach][outcome]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    ConfinedDispatchOutcome zero;
    zero.denied_quarantined_count = 1;
    f.outcomes["i-ro2"] = zero;
    auto req = f.request();
    req.idempotency_key = "key-partial-0001";
    const auto o = f.run(req);
    CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
    CHECK(o.run_outcome == WorkflowRunOutcome::kPartial);
    CHECK(o.reason == "partial");
    CHECK_FALSE(o.retryable);
    // The engine's own word, kept apart from the label: an onFailure: continue step that reached
    // nobody leaves the engine row `completed`. That is exactly why a replay must not take the
    // engine's word for the class (hp2-1): the same call repeated says what this one said.
    CHECK(o.run_status == "completed");
    REQUIRE(o.steps.size() == 2);
    CHECK(o.steps[0].agents_reached == 1);
    CHECK(o.steps[1].reason == "quarantined");
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.position("audit:success") == f.events.size());
    CHECK(f.audit_details.back().find("run_outcome=partial") != std::string::npos);
    CHECK(f.audit_details.back().find("run_status=completed") != std::string::npos);
    const auto j = workflow_execute_result_json(o, "wf-1");
    CHECK(j["status"] == "partial");
    CHECK(j["run_status"] == "completed");
    CHECK(j["retryable"] == false);
    CHECK(j["steps"].size() == 2);

    const auto sent_before = std::count_if(f.events.begin(), f.events.end(), [](const auto& e) {
        return e.starts_with("dispatch:");
    });
    const auto again = f.run(req);
    REQUIRE(again.status == WorkflowExecuteStatus::kIdempotentReplay);
    CHECK(again.run_status == "completed");
    CHECK(again.replay_status == "partial"); // never `completed` for a run that was not
    CHECK(std::count_if(f.events.begin(), f.events.end(),
                        [](const auto& e) { return e.starts_with("dispatch:"); }) == sent_before);
    CHECK(f.audit_details.back().find("idempotent_replay=true run_status=partial") !=
          std::string::npos);
    const auto rj = workflow_idempotent_replay_json(again, "wf-1");
    CHECK(rj.at("status") == "partial");
    CHECK(rj.at("retryable") == false);
}

TEST_CASE("workflow execute: only a completed run whose every step's final attempt reached an agent is "
          "`success`",
          "[workflow][twin][outcome]") {
    SECTION("completed and fully reached") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK(o.run_outcome == WorkflowRunOutcome::kSucceeded);
        CHECK(f.events.back() == "audit:success");
        CHECK(f.audit_details.back().find("run_outcome") == std::string::npos);
        const auto j = workflow_execute_result_json(o, "wf-1");
        CHECK(j["status"] == "completed");
        CHECK_FALSE(j.contains("run_status"));
        CHECK_FALSE(j.contains("retryable"));
    }
    SECTION("the engine ended FAILED after every step reached an agent") {
        Fx f;
        f.engine_status = "failed";
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kPartial);
        CHECK(o.run_status == "failed");
        CHECK(f.events.back() == "audit:failure");
        CHECK(f.audit_details.back().find("run_outcome=partial") != std::string::npos);
        CHECK(f.audit_details.back().find("run_status=failed") != std::string::npos);
        CHECK(workflow_execute_result_json(o, "wf-1")["run_status"] == "failed");
    }
    SECTION("a finalize that did not land (still running) is not success either") {
        Fx f;
        f.engine_status = "running";
        CHECK(f.run().status == WorkflowExecuteStatus::kRunIncomplete);
    }
    SECTION("an engine status that cannot be read back is never success") {
        Fx f;
        auto a = f.api();
        auto unreadable = std::make_shared<test::FnWorkflowApi>(
            test::FnWorkflowApi::ListFn{},
            [&](const std::string& id) { return a->get_workflow(id); },
            [](const std::string&) -> std::expected<std::optional<WorkflowExecution>, std::string> {
                return std::unexpected(std::string{"db: gone"});
            });
        const auto o = apply_workflow_execute(f.ports(unreadable), f.request());
        CHECK(o.run_status == "unknown");
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kPartial);
        CHECK(f.events.back() == "audit:failure");
    }
}

TEST_CASE("workflow execute: a run that ended with nothing sent and no dispatch attempt is FAILED with "
          "reason run_failed",
          "[workflow][twin][outcome]") {
    Fx f;
    f.engine_status = "failed";
    auto a = f.api();
    auto p = f.ports(a);
    // The engine admits the run and fails it before any step reaches the dispatch callback (a
    // step's own lookup failed, say): no note, nothing sent.
    p.run = [&](const std::string&, const std::vector<std::string>&, StepDispatchFn,
                ConditionEvalFn, const WorkflowRunControl& control)
        -> std::expected<std::string, std::string> {
        if (control.on_admitted)
            control.on_admitted("exec-1");
        return std::string{"exec-1"};
    };
    const auto o = apply_workflow_execute(p, f.request());
    CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
    CHECK(o.run_outcome == WorkflowRunOutcome::kFailed);
    CHECK(o.reason == "run_failed");
    CHECK_FALSE(o.retryable);
    CHECK(o.execution_id == "exec-1");
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.audit_details.back().find("run_outcome=failed") != std::string::npos);
    CHECK(f.audit_details.back().find("reason=run_failed") != std::string::npos);
}

TEST_CASE("workflow execute: a zero-reach run closes `failure` with run_outcome=failed and its cause",
          "[workflow][twin][outcome]") {
    Fx f;
    ConfinedDispatchOutcome out;
    out.sent = 0;
    out.denied_quarantined_count = 2;
    f.outcomes["i-ro"] = out;
    const auto o = f.run();
    REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
    CHECK(o.run_outcome == WorkflowRunOutcome::kFailed);
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.audit_details.back().find("run_outcome=failed") != std::string::npos);
    CHECK(f.audit_details.back().find("reason=quarantined") != std::string::npos);
}

TEST_CASE("workflow execute: a step refused at send time AFTER an earlier step was sent is ABORTED, a "
          "typed non-success; the late denial keeps its own `denied` row",
          "[workflow][twin][outcome][late]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
    const auto o = f.run();
    CHECK(o.late_denied);
    CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
    CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
    CHECK(o.reason == "aborted");
    // requested, the (late) denial at the moment of refusal, then the closing FAILURE row.
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.position("audit:denied") < f.position("engine_returned"));
    CHECK(f.audit_details.back().find("run_outcome=aborted") != std::string::npos);
    CHECK(f.audit_details.back().find("late_denied=true") != std::string::npos);
    CHECK(workflow_execute_result_json(o, "wf-1")["status"] == "aborted");
}

TEST_CASE("workflow execute: the run outcome is judged by ONE function over each step's FINAL "
          "outcome, and its tokens are closed",
          "[workflow][twin][outcome]") {
    // A step's final outcome: reached (its last attempt reached an agent), not reached (the engine
    // left it failed), or reached nobody but something was sent earlier is not a thing.
    const auto reached = [](int step) { return WorkflowStepFinal{step, 1, true, true}; };
    const auto missed = [](int step) { return WorkflowStepFinal{step, 1, false, false}; };
    using O = WorkflowRunOutcome;
    const WorkflowRunFacts none;
    CHECK(classify_workflow_run("completed", none, {reached(0), reached(1)}) == O::kSucceeded);
    CHECK(classify_workflow_run("completed", none, {}) == O::kSucceeded); // every step condition-skipped
    CHECK(classify_workflow_run("completed", none, {reached(0), missed(1)}) == O::kPartial);
    CHECK(classify_workflow_run("failed", none, {reached(0)}) == O::kPartial);
    CHECK(classify_workflow_run("completed", none, {missed(0)}) == O::kFailed);
    CHECK(classify_workflow_run("failed", none, {}) == O::kFailed);
    CHECK(classify_workflow_run("unknown", none, {}) == O::kFailed);
    CHECK(classify_workflow_run("cancelled", none, {reached(0)}) == O::kPartial);
    CHECK(classify_workflow_run("completed", {.late_denied = true}, {reached(0), missed(1)}) ==
          O::kAborted);
    CHECK(classify_workflow_run("completed", {.late_denied = true}, {missed(0)}) == O::kAborted);
    CHECK(workflow_run_outcome_token(O::kSucceeded) == "succeeded");
    CHECK(workflow_run_outcome_token(O::kFailed) == "failed");
    CHECK(workflow_run_outcome_token(O::kPartial) == "partial");
    CHECK(workflow_run_outcome_token(O::kAborted) == "aborted");
    CHECK(workflow_run_outcome_token(O::kInterrupted) == "interrupted");
    // A server stop is its own outcome, whatever was sent, ...
    CHECK(classify_workflow_run("failed", {.interrupted = true}, {reached(0)}) == O::kInterrupted);
    CHECK(classify_workflow_run("failed", {.interrupted = true}, {}) == O::kInterrupted);
    // ... except that a step refused at send time or a stopped run bound is judged first.
    CHECK(classify_workflow_run("failed", {.late_denied = true, .interrupted = true},
                                {reached(0)}) == O::kAborted);
    CHECK(classify_workflow_run("failed", {.bound_stop = true, .interrupted = true},
                                {reached(0)}) == O::kAborted);
    // A deadline or a credential stop is an abort whatever was sent.
    CHECK(classify_workflow_run("failed", {.bound_stop = true}, {reached(0)}) == O::kAborted);
    CHECK(classify_workflow_run("failed", {.bound_stop = true}, {}) == O::kAborted);
    // A dispatch that threw is a failed run whatever had been sent or stopped it, and is judged first.
    CHECK(classify_workflow_run("failed", {.threw = true}, {reached(0), missed(1)}) == O::kFailed);
    CHECK(classify_workflow_run("failed", {.late_denied = true, .threw = true}, {reached(0)}) ==
          O::kFailed);
    // `sent` is what separates partial from failed: a final that reached nobody, but whose step
    // had sent something on another item, still means something left the server.
    CHECK(classify_workflow_run("completed", none, {WorkflowStepFinal{0, 1, false, true}}) ==
          O::kPartial);
}

TEST_CASE("workflow execute: a step's final outcome is its LAST attempt, per step and not per "
          "instruction id",
          "[workflow][twin][outcome][attempt]") {
    const auto note = [](int step, int attempt, int reached) {
        WorkflowStepDispatchNote n;
        n.instruction_id = "i-same"; // one instruction named by every step below
        n.step_index = step;
        n.attempt = attempt;
        n.agents_reached = reached;
        return n;
    };
    using O = WorkflowRunOutcome;
    const WorkflowRunFacts none;
    SECTION("a step that failed and was retried to success is reached") {
        const auto finals = workflow_step_finals({note(0, 1, 0), note(0, 2, 3)}, {{0, 2}});
        REQUIRE(finals.size() == 1);
        CHECK(finals[0].reached);
        CHECK(finals[0].sent);
        CHECK(finals[0].attempt == 2);
        CHECK(classify_workflow_run("completed", none, finals) == O::kSucceeded);
    }
    SECTION("a step whose LAST attempt reached nobody is not, even after an earlier attempt") {
        const auto finals = workflow_step_finals({note(0, 1, 0), note(0, 2, 0)}, {{0, 2}});
        REQUIRE(finals.size() == 1);
        CHECK_FALSE(finals[0].reached);
        CHECK(classify_workflow_run("completed", none, finals) == O::kFailed);
    }
    SECTION("two steps naming the SAME instruction are two finals: a failed first step is not hidden "
            "by a second that reached") {
        const auto finals = workflow_step_finals({note(0, 1, 0), note(1, 1, 2)}, {{0, 1}, {1, 1}});
        REQUIRE(finals.size() == 2);
        CHECK_FALSE(finals[0].reached);
        CHECK(finals[1].reached);
        CHECK(classify_workflow_run("completed", none, finals) == O::kPartial);
    }
    SECTION("an attempt the engine announced but the dispatch callback never recorded is not reached") {
        // attempt 2 started and was stopped / failed before a note: the step is failed.
        const auto finals = workflow_step_finals({note(0, 1, 0)}, {{0, 2}});
        REQUIRE(finals.size() == 1);
        CHECK_FALSE(finals[0].reached);
        CHECK_FALSE(finals[0].sent);
    }
    SECTION("every item of a foreach attempt must reach; one that did not fails the step but something "
            "was sent") {
        const auto finals = workflow_step_finals({note(0, 1, 2), note(0, 1, 0)}, {{0, 1}});
        REQUIRE(finals.size() == 1);
        CHECK_FALSE(finals[0].reached);
        CHECK(finals[0].sent);
    }
    SECTION("a note no attempt was announced for is its own step") {
        WorkflowStepDispatchNote a;
        a.agents_reached = 1;
        WorkflowStepDispatchNote b;
        b.agents_reached = 0;
        const auto finals = workflow_step_finals({a, b}, {});
        REQUIRE(finals.size() == 2);
        CHECK(finals[0].reached);
        CHECK_FALSE(finals[1].reached);
    }
}

TEST_CASE("workflow execute: a protective action never reports the three gate-withhold causes",
          "[workflow][twin][zeroreach]") {
    // quarantine.status is protective: an inventory withhold signal arriving on it is ignored by
    // classify_zero_reach (dispatch_zero_reach.hpp), so the step reports the generic cause.
    Fx f;
    f.defs["i-ro"] = def("i-ro", "quarantine", "status");
    ConfinedDispatchOutcome out;
    out.unknown_plugin_count = 1;
    f.outcomes["i-ro"] = out;
    const auto o = f.run();
    REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
    CHECK(o.reason == "no_agents_reached");
}

// ───────────────────────────── the EXACT send set, through the real registry ────────────────

namespace {

agent_pb::AgentInfo info(const std::string& id) {
    agent_pb::AgentInfo i;
    i.set_agent_id(id);
    i.set_hostname("host.local");
    return i;
}

// A real AgentRegistry with a gateway route per agent, so the production send_to queues each
// recipient on drain_gateway_pending() with no gRPC stream.
struct RegistryRig {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    int next{0};
    explicit RegistryRig(std::initializer_list<const char*> ids) {
        for (const auto* id : ids) {
            (void)registry.register_agent(info(id));
            REQUIRE(registry.set_gateway_route(
                id, /*session_id=*/{}, "test-gateway",
                {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
        }
    }

    ConfinedDispatchOutcome dispatch(const WorkflowStepInstruction& d,
                                     const std::vector<std::string>& ids, const DispatchCaller& c) {
        agent_pb::CommandRequest cmd;
        const std::string cid = "wf-cmd-" + std::to_string(++next);
        cmd.set_command_id(cid);
        cmd.set_plugin(d.plugin);
        cmd.set_action(d.action);
        cmd.set_dispatch_tag("v1|ro|none|0123456789abcdef0123456789abcdef");
        auto classified = ClassifiedCommandTestAccess::make(cmd);
        auto noop = [](const std::string&, const std::string&, const std::string&,
                       const std::string&) {};
        return wire_and_dispatch_confined(
            registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
            /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
            /*execution_tracker=*/nullptr, noop, noop, cid, /*execution_id=*/"",
            c.principal_role, ids, /*scope_expr=*/"", c.exec_visible,
            /*broadcast_on_none=*/false, ContainmentGate::exempt_control_plugin(), classified);
    }
};

} // namespace

TEST_CASE("workflow execute: each step reaches EXACTLY the named agents the caller can see "
          "(real registry, real intersection)",
          "[workflow][twin][security][confinement]") {
    RegistryRig rig{"dev-A", "dev-B", "dev-C", "decoy"};
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.dispatch_override = [&](const auto& d, const auto& ids, const auto& c) {
        return rig.dispatch(d, ids, c);
    };

    SECTION("a confined caller: only dev-A, on every step; dev-B, dev-C and the decoy get nothing") {
        auto req = f.request({"dev-A", "dev-B", "dev-C"});
        req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"dev-A"}};
        const auto o = f.run(req);
        REQUIRE(o.status == WorkflowExecuteStatus::kOk);
        const auto pending = rig.registry.drain_gateway_pending();
        REQUIRE(pending.size() == 2); // one send per step
        for (const auto& p : pending)
            CHECK(p.agent_id == "dev-A");
        for (const auto& n : o.steps)
            CHECK(n.agents_reached == 1);
    }
    SECTION("a caller whose visible set is present-EMPTY reaches nobody (deny-all, not unfiltered)") {
        auto req = f.request({"dev-A", "dev-B"});
        req.caller.exec_visible = authz::deny_all();
        const auto o = f.run(req);
        CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(rig.registry.drain_gateway_pending().empty());
    }
    SECTION("an unfiltered caller reaches every NAMED agent and never the decoy it did not name") {
        auto req = f.request({"dev-A", "dev-B"});
        req.caller.exec_visible = std::nullopt;
        const auto o = f.run(req);
        REQUIRE(o.status == WorkflowExecuteStatus::kOk);
        std::multiset<std::string> got;
        for (const auto& p : rig.registry.drain_gateway_pending())
            got.insert(p.agent_id);
        CHECK(got == std::multiset<std::string>{"dev-A", "dev-A", "dev-B", "dev-B"});
    }
    SECTION("a named agent that does not exist is not invented") {
        auto req = f.request({"ghost"});
        const auto o = f.run(req);
        CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(rig.registry.drain_gateway_pending().empty());
    }
}

// ───────────────────────────── caller-level authority: all-or-nothing (sec-4 / UP-2) ─────────

namespace {

// A pair whose catalogue row carries ExecuteGate::AdminOrApproval (a non-admin with no approval
// provenance is refused by the chokepoint), and a read-only pair with ExecuteGate::None.
constexpr const char* kGatedPlugin = "filesystem";
constexpr const char* kGatedAction = "create_temp";

Fx two_step_with_later_gated_pair() {
    Fx f;
    f.step_ids = {"i-ro", "i-gated"};
    f.defs["i-gated"] = def("i-gated", kGatedPlugin, kGatedAction);
    return f;
}

} // namespace

TEST_CASE("workflow execute: a caller-level denial of a LATER step's pair refuses the whole call and "
          "NOTHING is sent",
          "[workflow][twin][security][authorize]") {
    Fx f = two_step_with_later_gated_pair();
    const auto o = f.run(); // alice: not an administrator, no approval provenance
    REQUIRE(o.status == WorkflowExecuteStatus::kDispatchDenied);
    CHECK(o.reason == "dispatch_denied");
    CHECK_FALSE(o.retryable); // the chokepoint would say the same on every retry
    CHECK(o.message.find("step-i-gated") != std::string::npos);
    CHECK(o.message.find("filesystem.create_temp") != std::string::npos);
    CHECK_FALSE(o.remediation.empty());
    // Step 1 was NOT sent (it used to be, and the run then reported a retryable
    // "no_agents_reached" for step 2).
    CHECK_FALSE(f.engine_called);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(o.execution_id.empty());
    // Exactly one `denied` row naming the step and the chokepoint's own token; no `requested`.
    REQUIRE(f.audit_details.size() == 1);
    CHECK(f.events.front() == "audit:denied");
    CHECK(f.audit_details[0].find("reason=dispatch_denied") != std::string::npos);
    CHECK(f.audit_details[0].find("denial=approval_required") != std::string::npos);
    CHECK(f.audit_details[0].find("step=i-gated") != std::string::npos);
    CHECK(f.audit_details[0].find("action=filesystem.create_temp") != std::string::npos);
    CHECK(f.counted_denials == std::vector<std::string>{"approval_required"});
}

TEST_CASE("workflow execute: the chokepoint's own verdict is used, per cause (RBAC, ExecuteGate, kill switch)",
          "[workflow][twin][security][authorize]") {
    const auto ro = [](Fx& f) { return std::string(f.caps.classify("os_info", "os_version")->securable); };
    struct Row {
        const char* what;
        std::function<void(Fx&)> setup;
        const char* denial;
    };
    const Row rows[] = {
        {"no RBAC grant", [&](Fx& f) { f.rbac_denied.insert(ro(f)); }, "forbidden"},
        {"action kill switch", [](Fx& f) { f.killed.insert("os_info.os_version"); }, "kill_switched"},
        {"admin-or-approval gate", [](Fx& f) { f.defs["i-ro"] = def("i-ro", kGatedPlugin, kGatedAction); },
         "approval_required"},
    };
    for (const auto& r : rows) {
        INFO(r.what);
        Fx f;
        r.setup(f);
        const auto o = f.run();
        REQUIRE(o.status == WorkflowExecuteStatus::kDispatchDenied);
        CHECK(o.reason == "dispatch_denied");
        CHECK_FALSE(o.retryable);
        CHECK(f.counted_denials == std::vector<std::string>{r.denial});
        CHECK_FALSE(f.engine_called);
        CHECK_FALSE(f.dispatched_anything());
        REQUIRE(f.audit_details.size() == 1);
        CHECK(f.audit_details[0].find(std::string("denial=") + r.denial) != std::string::npos);
    }
}

TEST_CASE("workflow execute: the chokepoint is asked once per DISTINCT step pair, with the caller's real "
          "DispatchCaller",
          "[workflow][twin][security][authorize]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2", "i-ro3", "i-gated"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.defs["i-ro3"] = def("i-ro3", "os_info", "os_version");
    f.defs["i-gated"] = def("i-gated", kGatedPlugin, kGatedAction);
    auto req = f.request();
    req.caller.principal_is_admin = true; // so the gated pair is admitted and every pair is asked
    REQUIRE(f.run(req).status == WorkflowExecuteStatus::kOk);
    CHECK(f.authorize_calls ==
          std::vector<std::string>{"os_info.os_version", "filesystem.create_temp"});

    // The caller passed in is the one judged: provenance and admin flag are not re-derived.
    Fx g = two_step_with_later_gated_pair();
    auto ticketed = g.request();
    ticketed.caller.approval_provenance = ApprovalProvenance::Ticket; // what a transport MAY stamp
    CHECK(g.run(ticketed).status == WorkflowExecuteStatus::kOk);
}

TEST_CASE("workflow execute: allowed pairs run exactly as before",
          "[workflow][twin][security][authorize]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    CHECK(f.events.front() == "audit:requested");
    CHECK(f.counted_denials.empty());
}

TEST_CASE("workflow execute: caller authority is judged before targeting (403 before 400), as on "
          "POST /api/command",
          "[workflow][twin][security][authorize][targeting]") {
    Fx f;
    f.defs["i-ro"] = def("i-ro", "execution_artifacts", "shimcache"); // Forensics, gated
    const auto o = f.run(f.request({"a1", "a2"}));                  // untargeted AND not admin
    CHECK(o.status == WorkflowExecuteStatus::kDispatchDenied);
    CHECK(f.counted_rejections.empty()); // the targeting counter was never reached
}

TEST_CASE("workflow execute: the gated-pair denial never advises an approval ticket, because none can lift it",
          "[workflow][twin][security][authorize]") {
    Fx f = two_step_with_later_gated_pair();
    const auto o = f.run();
    REQUIRE(o.status == WorkflowExecuteStatus::kDispatchDenied);
    CHECK(o.message.find("supervised") == std::string::npos);
    CHECK(o.remediation.find("supervised") == std::string::npos);
    CHECK(o.remediation.find("retrying will not help") != std::string::npos);
}

TEST_CASE("workflow execute: a throwing authorizer is the caller's to catch and sends nothing",
          "[workflow][twin][security][authorize]") {
    Fx f;
    auto a = f.api();
    auto p = f.ports(a);
    p.authorize = [](const DispatchCaller&, std::string_view,
                     std::string_view) -> std::expected<CommandCapability, detail::DispatchDenial> {
        throw std::runtime_error("authorizer exploded");
    };
    CHECK_THROWS(apply_workflow_execute(p, f.request()));
    CHECK_FALSE(f.engine_called);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(f.audit_details.empty());
}

TEST_CASE("workflow execute: prepare alone has no effect and writes no `requested` row; run does",
          "[workflow][twin][security][authorize]") {
    Fx f;
    auto a = f.api();
    const auto p = f.ports(a);
    const auto req = f.request();
    const auto plan = prepare_workflow_execute(p, req);
    REQUIRE(plan.has_value());
    CHECK(plan->step_count == 1);
    CHECK(f.events.empty()); // no audit row, no dispatch, no engine
    CHECK_FALSE(f.engine_called);
    const auto o = run_workflow_execute(p, req, *plan);
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    CHECK(f.events.front() == "audit:requested");
}

// ───────────────────────────── step-effect binding (sec-1 / UP-1) ───────────────────────────

namespace {

// The ticket's effect line for the fixture's current definitions.
std::string effect_line(Fx& f) {
    auto a = f.api();
    const auto p = f.ports(a);
    auto req = f.request();
    req.caller.principal_is_admin = true; // a role-gated step must not hide a field from the digest
    const auto plan = prepare_workflow_execute(p, req);
    REQUIRE(plan.has_value());
    const auto line = workflow_effect_binding(p, *plan);
    REQUIRE(line.has_value());
    return *line;
}

void two_steps(Fx& f) {
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "uptime");
}

} // namespace

TEST_CASE("workflow execute: the effect line leads with a readable summary and ends in a digest of "
          "the ordered step tuples",
          "[workflow][twin][security][effect]") {
    Fx f;
    two_steps(f);
    const std::string line = effect_line(f);
    REQUIRE(line.starts_with("effect="));
    REQUIRE(line.ends_with("\n"));
    CHECK(line.find('\n') == line.size() - 1); // one line: the arguments are recognised after it
    const auto j = json::parse(line.substr(7, line.size() - 8));
    REQUIRE(j.is_array());
    REQUIRE(j.size() == 4);
    CHECK(j[0] == "workflow");
    CHECK(j[1] == 2);
    CHECK(j[2] == json::array({"os_info.os_version", "os_info.uptime"}));
    REQUIRE(j[3].is_string());
    const auto hex = j[3].get<std::string>();
    CHECK(hex.size() == 64);
    CHECK(hex.find_first_not_of("0123456789abcdef") == std::string::npos);
    // Summary first, hash second: the readable part precedes the digest in the text.
    CHECK(line.find("os_info.os_version") < line.find(hex));
    // Stable for identical workflows.
    Fx g;
    two_steps(g);
    CHECK(effect_line(g) == line);
}

TEST_CASE("workflow execute: the effect line names only the first steps but the digest covers all",
          "[workflow][twin][security][effect]") {
    Fx f;
    f.step_ids = {"s1", "s2", "s3", "s4", "s5"};
    for (const auto& id : f.step_ids)
        f.defs[id] = def(id, "os_info", "os_version");
    const std::string base = effect_line(f);
    const auto j = json::parse(base.substr(7, base.size() - 8));
    CHECK(j[1] == 5);
    CHECK(j[2].size() == 3); // the summary is bounded; the digest is not
    // A change confined to the LAST step, invisible in the summary, still moves the line.
    f.defs["s5"].action = "uptime";
    CHECK(effect_line(f) != base);
}

TEST_CASE("workflow execute: the effect line differs when ANY field of ANY step tuple differs, or "
          "the step order does",
          "[workflow][twin][security][effect]") {
    Fx base_fx;
    two_steps(base_fx);
    const std::string base = effect_line(base_fx);
    struct Row {
        const char* what;
        std::function<void(Fx&)> mutate;
    };
    const std::vector<Row> rows = {
        {"plugin (with the action it needs)",
         [](Fx& f) {
             f.defs["i-ro2"].plugin = "network_config";
             f.defs["i-ro2"].action = "adapters";
         }},
        {"action", [](Fx& f) { f.defs["i-ro2"].action = "os_version"; }},
        {"approval_mode", [](Fx& f) { f.defs["i-ro2"].approval_mode = "role-gated"; }},
        {"concurrency_mode", [](Fx& f) { f.defs["i-ro2"].concurrency_mode = "global"; }},
        {"first step pair",
         [](Fx& f) {
             f.defs["i-ro"].plugin = "network_config";
             f.defs["i-ro"].action = "adapters";
         }},
        {"instruction id (same content, other id)",
         [](Fx& f) {
             f.defs["i-ro3"] = def("i-ro3", "os_info", "uptime");
             f.step_ids = {"i-ro", "i-ro3"};
         }},
        {"step order", [](Fx& f) { f.step_ids = {"i-ro2", "i-ro"}; }},
        {"a step removed", [](Fx& f) { f.step_ids = {"i-ro"}; }},
    };
    for (const auto& row : rows) {
        DYNAMIC_SECTION(row.what) {
            Fx f;
            two_steps(f);
            row.mutate(f);
            CHECK(effect_line(f) != base);
        }
    }
}

TEST_CASE("workflow execute: a digest that cannot be computed refuses the binding (no ticket can be "
          "minted over it)",
          "[workflow][twin][security][effect][failclosed]") {
    Fx f;
    auto a = f.api();
    auto p = f.ports(a);
    const auto plan = prepare_workflow_execute(p, f.request());
    REQUIRE(plan.has_value());
    SECTION("the provider reports failure") {
        p.digest = [](std::string_view) { return std::optional<std::string>{}; };
        const auto line = workflow_effect_binding(p, *plan);
        REQUIRE_FALSE(line.has_value());
        CHECK(line.error().status == WorkflowExecuteStatus::kEffectDigestFailed);
        CHECK(line.error().reason == "effect_digest_unavailable");
        CHECK_FALSE(line.error().retryable);
    }
    SECTION("a provider answer that is not a 64-character digest is not trusted") {
        p.digest = [](std::string_view) { return std::optional<std::string>{"deadbeef"}; };
        const auto line = workflow_effect_binding(p, *plan);
        REQUIRE_FALSE(line.has_value());
        CHECK(line.error().status == WorkflowExecuteStatus::kEffectDigestFailed);
    }
    CHECK_FALSE(f.dispatched_anything());
}

TEST_CASE("workflow execute: a step repointed after the ticket was bound is refused before anything is "
          "sent, audited, with no requested row",
          "[workflow][twin][security][effect]") {
    Fx f;
    two_steps(f);
    auto a = f.api();
    const auto probe_ports = f.ports(a);
    const auto probe = prepare_workflow_execute(probe_ports, f.request());
    REQUIRE(probe.has_value());
    auto req = f.request();
    req.expected_step_effects = workflow_step_effects(*probe);
    f.events.clear();
    f.authorize_calls.clear();

    struct Row {
        const char* what;
        std::function<void(Fx&)> mutate;
    };
    const std::vector<Row> rows = {
        {"another ungated pair", [](Fx& f2) { f2.defs["i-ro2"].action = "os_version"; }},
        {"approval mode", [](Fx& f2) { f2.defs["i-ro"].approval_mode = "role-gated"; }},
        {"concurrency mode", [](Fx& f2) { f2.defs["i-ro2"].concurrency_mode = "global"; }},
    };
    for (const auto& row : rows) {
        DYNAMIC_SECTION(row.what) {
            row.mutate(f);
            const auto o = f.run(req);
            CHECK(o.status == WorkflowExecuteStatus::kDefinitionChanged);
            CHECK(o.reason == "definition_changed");
            CHECK_FALSE(o.retryable);
            CHECK_FALSE(f.dispatched_anything());
            CHECK_FALSE(f.engine_called);
            CHECK(f.position("audit:requested") == f.events.size()); // no requested row
            REQUIRE(f.audit_details.size() == 1);
            CHECK(f.events.back() == "audit:denied");
            CHECK(f.audit_details.back().find("reason=definition_changed") != std::string::npos);
            CHECK(f.audit_details.back().find("step=i-ro") != std::string::npos);
            // Held BEFORE the authorizer: the moved step is never put to the chokepoint (only the
            // unchanged step before it could have been).
            CHECK(f.authorize_calls.size() < 2);
        }
    }
}

TEST_CASE("workflow execute: a step repointed between the preflight and its send is not sent, and "
          "the refusal is audited at that moment; earlier steps stay sent",
          "[workflow][twin][security][effect][late]") {
    Fx f;
    two_steps(f);
    auto a = f.api();
    const auto p = f.ports(a);
    auto req = f.request();
    const auto plan = prepare_workflow_execute(p, req);
    REQUIRE(plan.has_value());
    req.expected_step_effects = workflow_step_effects(*plan);
    // The run's own reads (every read from here on) see step 2 pointed at another pair.
    f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.events.clear();
    const auto o = run_workflow_execute(p, req, *plan);
    CHECK(f.events.at(0) == "audit:requested");
    REQUIRE(f.dispatched_ids.size() == 1); // step 1 only
    CHECK(f.events.at(1) == "dispatch:i-ro");
    CHECK(o.late_denied);
    REQUIRE(o.steps.size() == 2);
    CHECK(o.steps[0].agents_reached == 1);
    CHECK(o.steps[1].instruction_id == "i-ro2");
    CHECK(o.steps[1].agents_reached == 0);
    CHECK(o.steps[1].reason == "definition_changed");
    CHECK_FALSE(o.steps[1].retryable);
    // Audited at the moment of refusal: a denied row after step 1's dispatch and before the
    // engine returned.
    const auto denied = f.position("audit:denied");
    REQUIRE(denied < f.events.size());
    CHECK(denied > f.position("dispatch:i-ro"));
    CHECK(denied < f.position("engine_returned"));
    bool token = false;
    for (const auto& d : f.audit_details)
        token = token || (d.find("reason=definition_changed") != std::string::npos &&
                          d.find("step=i-ro2") != std::string::npos &&
                          d.find("(late)") != std::string::npos);
    CHECK(token);
}

TEST_CASE("workflow execute: a definition repointed before the first send sends nothing and names the "
          "cause",
          "[workflow][twin][security][effect][late]") {
    Fx f;
    auto a = f.api();
    const auto p = f.ports(a);
    auto req = f.request();
    const auto plan = prepare_workflow_execute(p, req);
    REQUIRE(plan.has_value());
    req.expected_step_effects = workflow_step_effects(*plan);
    f.late_defs["i-ro"] = def("i-ro", "os_info", "uptime");
    const auto o = run_workflow_execute(p, req, *plan);
    CHECK_FALSE(f.dispatched_anything());
    CHECK(o.late_denied);
    CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
    CHECK(o.reason == "definition_changed");
    CHECK_FALSE(o.retryable);
    CHECK(o.message.find("approval ticket") != std::string::npos);
}

TEST_CASE("workflow execute: an unchanged workflow still runs under a bound effect, and a request with "
          "no bound effect (REST) is not held to one",
          "[workflow][twin][security][effect]") {
    SECTION("bound and unchanged") {
        Fx f;
        two_steps(f);
        auto a = f.api();
        const auto p = f.ports(a);
        auto req = f.request();
        const auto plan = prepare_workflow_execute(p, req);
        REQUIRE(plan.has_value());
        req.expected_step_effects = workflow_step_effects(*plan);
        const auto o = apply_workflow_execute(p, req);
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK_FALSE(o.late_denied);
        CHECK(f.dispatched_ids.size() == 2);
    }
    SECTION("unbound: a repointed definition runs as edited (the prechecks still apply)") {
        Fx f;
        f.late_defs["i-ro"] = def("i-ro", "os_info", "uptime");
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK_FALSE(o.late_denied);
        CHECK(f.dispatched_ids.size() == 1);
    }
}

TEST_CASE("workflow execute: the caller's REAL DispatchCaller reaches every step unchanged",
          "[workflow][twin][security][caller]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    auto req = f.request({"a1"});
    req.caller.principal = "carol";
    req.caller.principal_role = "admin";
    req.caller.principal_is_admin = true;
    req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"a1", "a9"}};
    req.caller.approval_provenance = ApprovalProvenance::None;
    REQUIRE(f.run(req).status == WorkflowExecuteStatus::kOk);
    REQUIRE(f.dispatched_callers.size() == 2);
    for (const auto& c : f.dispatched_callers) {
        CHECK(c.principal == "carol");
        CHECK(c.principal_role == "admin");
        CHECK(c.principal_is_admin);
        CHECK_FALSE(c.system);
        CHECK(c.approval_provenance == ApprovalProvenance::None);
        REQUIRE(c.exec_visible.has_value());
        CHECK(*c.exec_visible == std::unordered_set<std::string>{"a1", "a9"});
    }
    // The request's own agent list is what each step is sent to, never a re-derived one.
    for (const auto& ids : f.dispatched_ids)
        CHECK(ids == std::vector<std::string>{"a1"});
}

// ───────────────────────────── body parsing ─────────────────────────────────────────────────

TEST_CASE("workflow execute: the body names explicit, bounded agent ids and nothing else",
          "[workflow][twin][targeting]") {
    struct Row {
        const char* body;
        const char* reason; // empty == accepted
    };
    const Row rows[] = {
        {R"({"agent_ids":["a","b"]})", ""},
        {R"([])", "body_type"},
        {R"("x")", "body_type"},
        {R"({})", "agent_ids_required"},
        {R"({"agent_ids":[]})", "agent_ids_empty"},
        {R"({"agent_ids":"a"})", "agent_ids_type"},
        {R"({"agent_ids":["a",1]})", "agent_id_type"},
        {R"({"agent_ids":[""]})", "agent_id_len"},
        {R"({"agent_ids":["a"],"scope":"__all__"})", "scope_unsupported"},
        {R"({"scope":"tag:x"})", "scope_unsupported"},
        {R"({"agent_ids":["a"],"scope":""})", "scope_unsupported"},
    };
    for (const auto& r : rows) {
        INFO(r.body);
        const auto p = parse_workflow_execute_body(json::parse(r.body));
        if (std::string(r.reason).empty()) {
            CHECK(p.has_value());
        } else {
            REQUIRE_FALSE(p.has_value());
            CHECK(p.error().reason == r.reason);
        }
    }
    json big = {{"agent_ids", json::array()}};
    for (int i = 0; i < 10001; ++i)
        big["agent_ids"].push_back("a" + std::to_string(i));
    CHECK(parse_workflow_execute_body(big).error().reason == "agent_ids_count");
    big["agent_ids"] = json::array({std::string(129, 'x')});
    CHECK(parse_workflow_execute_body(big).error().reason == "agent_id_len");
}

// ───────────────────────────── the REST route ───────────────────────────────────────────────

namespace {

struct Rest {
    Fx fx;
    std::string gate_type, gate_op;
    bool gate_admits{true};
    bool dispatch_throws{false};
    /// When set, every step's send answers this (the zero-reach cases); otherwise it reaches one agent.
    std::optional<ConfinedDispatchOutcome> dispatch_result;
    int gate_calls{0};
    int persist_calls{0};
    /// The action, result and target_id of every row the route's sink received, in order.
    std::vector<std::string> audit_actions, audit_results, audit_targets;
    DispatchCaller caller{.principal = "alice",
                          .principal_role = "user",
                          .exec_visible = std::nullopt,
                          .principal_is_admin = false};
    DispatchCaller seen_caller;
    bool saw_caller{false};
    std::shared_ptr<test::FnWorkflowApi> api;
    yuzu::MetricsRegistry metrics;
    // The one held-open budget the route leases from, and the server's draining flag.
    detail::StreamBudget budget{{.global_cap = 8}};
    bool draining{false};
    // What the route handed the credential check: the principal, and a request header proving it
    // is THIS request (not a copy made at registration).
    std::vector<std::string> reauth_principals;
    std::vector<std::string> reauth_tokens;
    // The platform events the route's emitter received (the server's 4-argument EmitEventFn).
    std::vector<std::string> emitted;
    std::vector<json> emitted_attrs, emitted_payloads;
    bool emit_throws{false};
    yuzu::server::test::TestRouteSink sink;

    explicit Rest(bool wire_audit = true) {
        api = fx.api();
        WorkflowExecuteRouteDeps d;
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            ++gate_calls;
            gate_type = t;
            gate_op = o;
            if (!gate_admits) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403}})", "application/json");
            }
            return gate_admits;
        };
        if (wire_audit)
            d.persist_audit_fn = [this](const httplib::Request&, const std::string& action,
                                        const std::string& result, const std::string&,
                                        const std::string& target, const std::string& detail) {
                ++persist_calls;
                const size_t idx = fx.audit_details.size();
                fx.events.push_back("audit:" + result);
                fx.audit_details.push_back(detail);
                audit_actions.push_back(action);
                audit_results.push_back(result);
                audit_targets.push_back(target);
                if (fx.audit_fails_on_call && *fx.audit_fails_on_call == idx)
                    return false;
                return fx.audit_ok;
            };
        d.workflow_api = api;
        d.workflow_run = fx.run_fn();
        d.workflow_idempotency_lookup = fx.idempotency_lookup_fn();
        d.instruction_store_open = [this] { return fx.store_open; };
        d.approval_gate_available = [this] { return fx.approval_gate; };
        auto ports = fx.ports(api);
        d.lookup = ports.lookup;
        d.classify = ports.classify;
        d.authorize = ports.authorize;
        d.command_dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                       const std::vector<std::string>& ids, const std::string&,
                                       const std::unordered_map<std::string, std::string>&,
                                       const std::string&, const DispatchCaller& c) {
            fx.events.push_back("dispatch:" + plugin + "." + action);
            fx.dispatched_ids.push_back(ids);
            seen_caller = c;
            saw_caller = true;
            if (dispatch_throws) {
                if (auto* p = SendProgressScope::current())
                    p->sent += 2; // accepted by the send path before the fan-out failed
                throw std::runtime_error("registry exploded mid fan-out");
            }
            if (dispatch_result)
                return *dispatch_result;
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-rest"};
        };
        d.caller_fn = [this](const httplib::Request&) { return caller; };
        d.metrics = &metrics;
        d.stream_budget = &budget;
        d.draining = [this] { return draining; };
        d.reauthorize_retry_delay = std::chrono::milliseconds(1);
        d.emit_event_fn = [this](const std::string& type, const httplib::Request&,
                                 const json& attrs, const json& payload) {
            emitted.push_back(type);
            emitted_attrs.push_back(attrs);
            emitted_payloads.push_back(payload);
            if (emit_throws)
                throw std::runtime_error("analytics sink blew up");
        };
        d.revalidate = [this](const httplib::Request& req, const std::string& principal) {
            reauth_principals.push_back(principal);
            reauth_tokens.push_back(req.get_header_value("X-Yuzu-Token"));
            return fx.next_reauth();
        };
        register_workflow_execute_v1_route(sink, std::move(d));
    }

    std::int64_t refused(const char* reason) {
        return static_cast<std::int64_t>(
            metrics.counter(kWorkflowRunRefusedMetric, {{"reason", reason}}).value());
    }
};

json body_of(const httplib::Response& r) { return json::parse(r.body); }

/// Checked read by JSON pointer: a missing key throws json::out_of_range, which Catch2 reports as
/// a failed test case. `operator[]` on a const json aborts the whole binary instead.
const json& at_path(const json& j, const char* pointer) { return j.at(json::json_pointer(pointer)); }

} // namespace

TEST_CASE("POST /api/v1/workflows/{id}/execute: Workflow:Execute is the first and only surface gate; "
          "a denied caller sends nothing",
          "[workflow][twin][rest][security]") {
    Rest r;
    r.gate_admits = false;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(r.gate_calls == 1);
    CHECK(r.gate_type == "Workflow");
    CHECK(r.gate_op == "Execute");
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
    CHECK(r.persist_calls == 0);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: success is 202 with the run and one entry per send",
          "[workflow][twin][rest]") {
    Rest r;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1","a2"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/meta/api_version") == "v1");
    CHECK(at_path(j, "/data/execution_id") == "exec-1");
    CHECK(at_path(j, "/data/workflow_id") == "wf-1");
    CHECK(at_path(j, "/data/status") == "completed");
    CHECK(at_path(j, "/data/late_denied") == false);
    REQUIRE(at_path(j, "/data/steps").size() == 1);
    CHECK(at_path(j, "/data/steps/0/agents_reached") == 1);
    CHECK(at_path(j, "/data/steps/0/command_id") == "cmd-rest");
    CHECK_FALSE(at_path(j, "/data").contains("audit_persisted"));
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
    // requested first, closing row last.
    CHECK(r.fx.events.front() == "audit:requested");
    CHECK(r.fx.events.back() == "audit:success");
    // The route handed the shared sequence the CALLER's own DispatchCaller.
    REQUIRE(r.saw_caller);
    CHECK(r.seen_caller.principal == "alice");
    CHECK(r.seen_caller.approval_provenance == ApprovalProvenance::None);
    // The adapter wired the run-outcome counter: one run, one `succeeded` / `none`.
    CHECK(r.metrics.counter(kWorkflowRunOutcomeMetric, {{"outcome", "succeeded"}, {"reason", "none"}})
              .value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a run the engine ended FAILED after a send is a 202 "
          "with status partial and no retry hint, never `completed`",
          "[workflow][twin][rest][outcome]") {
    Rest r;
    r.fx.engine_status = "failed";
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/data/status") == "partial");
    CHECK(at_path(j, "/data/run_status") == "failed");
    CHECK(at_path(j, "/data/retryable") == false);
    CHECK_FALSE(at_path(j, "/data/message").get<std::string>().empty());
    CHECK(at_path(j, "/data/execution_id") == "exec-1");
    REQUIRE(at_path(j, "/data/steps").size() == 1);
    CHECK(at_path(j, "/data/steps/0/agents_reached") == 1);
    CHECK(r.fx.events.back() == "audit:failure");
    CHECK(r.fx.audit_details.back().find("run_outcome=partial") != std::string::npos);
    CHECK(r.metrics.counter(kWorkflowRunOutcomeMetric, {{"outcome", "partial"}, {"reason", "none"}})
              .value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a step refused at send time after step 1 was sent is a "
          "202 with status aborted",
          "[workflow][twin][rest][outcome][late]") {
    Rest r;
    r.fx.step_ids = {"i-ro", "i-ro2"};
    r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    r.fx.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/data/status") == "aborted");
    CHECK(at_path(j, "/data/late_denied") == true);
    CHECK(at_path(j, "/data/retryable") == false);
    CHECK(r.fx.events.back() == "audit:failure");
    CHECK(r.fx.audit_details.back().find("run_outcome=aborted") != std::string::npos);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a lost closing row on a partial run still adds "
          "Sec-Audit-Failed",
          "[workflow][twin][rest][outcome][audit]") {
    Rest r;
    r.fx.engine_status = "failed";
    r.fx.audit_fails_on_call = 1; // 0 = requested, 1 = the closing row
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body_of(*res)["data"]["audit_persisted"] == false);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: there is no ticket, so a repointed step runs as edited "
          "(the step-effect binding is MCP-only)",
          "[workflow][twin][rest][security][effect]") {
    Rest r;
    r.fx.late_defs["i-ro"] = def("i-ro", "os_info", "uptime");
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(body_of(*res)["data"]["late_denied"] == false);
    CHECK(r.fx.dispatched_anything());
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: an unwired approval gate or closed instruction store "
          "is a 503 and nothing is sent or audited",
          "[workflow][twin][rest][security][failclosed]") {
    for (int which = 0; which < 2; ++which) {
        Rest r;
        (which == 0 ? r.fx.approval_gate : r.fx.store_open) = false;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto j = body_of(*res);
        CHECK(at_path(j, "/error/reason") ==
              (which == 0 ? "approval_gate_unavailable" : "instruction_store_unavailable"));
        CHECK(at_path(j, "/error/retry_after_ms").is_null()); // a missing dependency is not transient
        CHECK_FALSE(r.fx.engine_called);
        CHECK_FALSE(r.fx.dispatched_anything());
        CHECK(r.persist_calls == 0);
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a requested row that cannot be saved is 503 with "
          "Sec-Audit-Failed and nothing is sent",
          "[workflow][twin][rest][security][audit]") {
    Rest r;
    r.fx.audit_ok = false;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a run that throws after the requested row is a 500 "
          "naming the execution and the sends, with NO retry hint",
          "[workflow][twin][rest][security][audit][throw]") {
    Rest r;
    r.dispatch_throws = true;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 500);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "dispatch_exception");
    CHECK(at_path(j, "/error/execution_id") == "exec-1");
    CHECK(at_path(j, "/error/agents_sent") == 2);
    CHECK(at_path(j, "/error/retry_after_ms").is_null());
    CHECK(at_path(j, "/error/remediation").get<std::string>().find("get_workflow_execution") !=
          std::string::npos);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
    CHECK(r.fx.events.front() == "audit:requested");
    CHECK(r.fx.events.back() == "audit:failure");
    CHECK(r.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "workflow"}, {"phase", "dispatch"}})
              .value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a lost closing row on a thrown run adds "
          "Sec-Audit-Failed",
          "[workflow][twin][rest][security][audit][throw]") {
    Rest r;
    r.dispatch_throws = true;
    r.fx.audit_fails_on_call = 1;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a throw BEFORE the requested row stays a retryable "
          "503, because nothing was sent",
          "[workflow][twin][rest][security][throw]") {
    Rest r;
    r.fx.wire_authorize = true;
    // The authorizer is read by the route deps at construction, so build a second instance whose
    // authorizer throws (the preflight half).
    yuzu::server::test::TestRouteSink sink;
    WorkflowExecuteRouteDeps d;
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    d.persist_audit_fn = [&](const httplib::Request&, const std::string&, const std::string&,
                             const std::string&, const std::string&, const std::string&) {
        return true;
    };
    d.workflow_api = r.api;
    d.workflow_run = r.fx.run_fn();
    d.workflow_idempotency_lookup = r.fx.idempotency_lookup_fn();
    d.instruction_store_open = [] { return true; };
    d.approval_gate_available = [] { return true; };
    auto ports = r.fx.ports(r.api);
    d.lookup = ports.lookup;
    d.classify = ports.classify;
    d.authorize = [](const DispatchCaller&, std::string_view,
                     std::string_view) -> std::expected<CommandCapability, detail::DispatchDenial> {
        throw std::runtime_error("authorizer exploded");
    };
    d.command_dispatch_fn = [&](const std::string&, const std::string&,
                                const std::vector<std::string>&, const std::string&,
                                const std::unordered_map<std::string, std::string>&,
                                const std::string&, const DispatchCaller&) {
        r.fx.events.push_back("dispatch:rest");
        return ConfinedDispatchOutcome{.sent = 1};
    };
    d.caller_fn = [](const httplib::Request&) {
        return DispatchCaller{.principal = "alice", .exec_visible = std::nullopt};
    };
    register_workflow_execute_v1_route(sink, std::move(d));
    const auto res = sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    CHECK_FALSE(body_of(*res)["error"].contains("execution_id"));
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: body refusals are 400 with a reason and send nothing",
          "[workflow][twin][rest][targeting]") {
    const std::pair<const char*, const char*> rows[] = {
        {R"({})", "agent_ids_required"},
        {R"({"agent_ids":[]})", "agent_ids_empty"},
        {R"({"agent_ids":[7]})", "agent_id_type"},
        {R"({"agent_ids":["a"],"scope":"__all__"})", "scope_unsupported"},
        {R"([1,2])", "body_type"},
    };
    for (const auto& [body, reason] : rows) {
        INFO(body);
        Rest r;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body_of(*res)["error"]["reason"] == reason);
        CHECK_FALSE(r.fx.dispatched_anything());
        // The refusal leaves exactly one `denied` row (the pre-core audit) and no `requested` row.
        CHECK(r.audit_results == std::vector<std::string>{"denied"});
    }
    {
        Rest r;
        CHECK(r.sink.Post("/api/v1/workflows/wf-1/execute", "{not json")->status == 400);
        CHECK(r.sink.Post("/api/v1/workflows/wf-1/execute", std::string(40, '[') + std::string(40, ']'))
                  ->status == 400); // nests too deeply: refused before the parse
        CHECK_FALSE(r.fx.dispatched_anything());
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: step refusals map to 403/400/404 and send nothing",
          "[workflow][twin][rest][security]") {
    struct Row {
        std::function<void(Fx&)> setup;
        int status;
        const char* reason;
    };
    const Row rows[] = {
        {[](Fx& f) { f.defs["i-ro"].approval_mode = "always"; }, 403, "approval_required"},
        {[](Fx& f) { f.step_ids = {"i-missing"}; }, 400, "unknown_instruction"},
        {[](Fx& f) { f.defs["i-ro"] = def("i-ro", "nope", "nope"); }, 400, "step_unclassified"},
        {[](Fx& f) { f.defs["i-ro"] = def("i-ro", "execution_artifacts", "shimcache"); }, 400,
         "forensic_untargeted"},
    };
    for (const auto& row : rows) {
        Rest r;
        r.caller.principal_is_admin = true; // the ExecuteGate admits; the step's own verdict decides
        row.setup(r.fx);
        // Two ids so the Forensics row is untargeted; harmless for the others.
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1","a2"]})");
        REQUIRE(res);
        INFO(res->body);
        CHECK(res->status == row.status);
        CHECK(body_of(*res)["error"]["reason"] == row.reason);
        CHECK_FALSE(r.fx.dispatched_anything());
    }
    Rest missing;
    CHECK(missing.sink.Post("/api/v1/workflows/other/execute", R"({"agent_ids":["a1"]})")->status == 404);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a caller-level denial of any step's pair is a "
          "non-retryable 403 dispatch_denied and sends nothing",
          "[workflow][twin][rest][security][authorize]") {
    Rest r;
    r.fx.step_ids = {"i-ro", "i-gated"};
    r.fx.defs["i-gated"] = def("i-gated", kGatedPlugin, kGatedAction);
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    INFO(res->body);
    REQUIRE(res->status == 403); // a 202 here has no error object to inspect
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "dispatch_denied");
    CHECK(at_path(j, "/error/retry_after_ms").is_null());
    CHECK_FALSE(at_path(j, "/error/remediation").get<std::string>().empty());
    CHECK_FALSE(at_path(j, "/error").contains("execution_id"));
    CHECK_FALSE(r.fx.dispatched_anything()); // step 1 was NOT sent
    CHECK_FALSE(r.fx.engine_called);
    REQUIRE(r.fx.audit_details.size() == 1);
    CHECK(r.fx.events.front() == "audit:denied");
    CHECK(r.metrics.counter("yuzu_server_dispatch_denied_total", {{"reason", "approval_required"}})
              .value() == 1);

    // The same call as an administrator is admitted.
    Rest admin;
    admin.caller.principal_is_admin = true;
    admin.fx.step_ids = {"i-ro", "i-gated"};
    admin.fx.defs["i-gated"] = def("i-gated", kGatedPlugin, kGatedAction);
    CHECK(admin.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})")->status ==
          202);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: no step reaching any agent is a 503 with the cause, the "
          "retry hint and the execution id",
          "[workflow][twin][rest][zeroreach]") {
    // The route's dispatch goes through the plain command_dispatch_fn; make it reach nobody.
    // (Per-cause mapping is covered above on the shared sequence; this pins the HTTP shape.)
    Rest r;
    // A second route instance whose dispatch reports a permanent cause (every target quarantined).
    yuzu::server::test::TestRouteSink sink;
    WorkflowExecuteRouteDeps d;
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    d.persist_audit_fn = [&](const httplib::Request&, const std::string&, const std::string&,
                             const std::string&, const std::string&, const std::string&) {
        return true;
    };
    d.workflow_api = r.api;
    d.workflow_run = r.fx.run_fn();
    d.workflow_idempotency_lookup = r.fx.idempotency_lookup_fn();
    d.instruction_store_open = [] { return true; };
    d.approval_gate_available = [] { return true; };
    auto ports = r.fx.ports(r.api);
    d.lookup = ports.lookup;
    d.classify = ports.classify;
    d.authorize = ports.authorize;
    d.command_dispatch_fn = [](const std::string&, const std::string&,
                               const std::vector<std::string>&, const std::string&,
                               const std::unordered_map<std::string, std::string>&,
                               const std::string&, const DispatchCaller&) {
        ConfinedDispatchOutcome o;
        o.denied_quarantined_count = 3;
        return o;
    };
    d.caller_fn = [](const httplib::Request&) {
        return DispatchCaller{.principal = "alice", .exec_visible = std::nullopt};
    };
    register_workflow_execute_v1_route(sink, std::move(d));
    const auto res = sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "quarantined");
    CHECK(at_path(j, "/error/retry_after_ms").is_null()); // permanent: retrying will not help
    CHECK(at_path(j, "/error/execution_id") == "exec-1");
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: an unwired caller derivation is refused, never run "
          "as an anonymous or unfiltered caller",
          "[workflow][twin][rest][security][caller]") {
    Rest r;
    // Register a second route instance with caller_fn unset.
    yuzu::server::test::TestRouteSink sink;
    WorkflowExecuteRouteDeps d;
    DispatchCaller seen;
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    d.persist_audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
        return true;
    };
    d.workflow_api = r.api;
    d.workflow_run = r.fx.run_fn();
    d.workflow_idempotency_lookup = r.fx.idempotency_lookup_fn();
    d.instruction_store_open = [] { return true; };
    d.approval_gate_available = [] { return true; };
    auto ports = r.fx.ports(r.api);
    d.lookup = ports.lookup;
    d.classify = ports.classify;
    d.authorize = ports.authorize;
    d.command_dispatch_fn = [&](const std::string&, const std::string&,
                                const std::vector<std::string>&, const std::string&,
                                const std::unordered_map<std::string, std::string>&,
                                const std::string&, const DispatchCaller& c) {
        seen = c;
        return ConfinedDispatchOutcome{.sent = 0};
    };
    // d.caller_fn deliberately unset.
    register_workflow_execute_v1_route(sink, std::move(d));
    const auto res = sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    // The deny-all fallback has no principal, so the sequence refuses it before reading anything
    // (kNoPrincipal -> 500): it can neither run as anonymous nor as an unfiltered caller.
    CHECK(res->status == 500);
    CHECK_FALSE(r.fx.engine_called);
}

// ───────────────────────────── tier x ticket (pure policy) ──────────────────────────────────

TEST_CASE("MCP policy: Workflow:Execute is denied at the operator tier and needs a ticket at the "
          "supervised tier",
          "[workflow][twin][mcp][policy][security]") {
    using namespace yuzu::server::mcp;
    CHECK_FALSE(tier_allows("operator", "Workflow", "Execute"));
    CHECK_FALSE(tier_allows("readonly", "Workflow", "Execute"));
    CHECK(tier_allows("supervised", "Workflow", "Execute"));
    CHECK(requires_approval("supervised", "Workflow", "Execute"));
    // An untiered (non-MCP) session is unaffected: RBAC alone decides.
    CHECK(tier_allows("", "Workflow", "Execute"));
    CHECK_FALSE(requires_approval("", "Workflow", "Execute"));
    // The read side is untouched.
    CHECK(tier_allows("readonly", "Workflow", "Read"));
    CHECK_FALSE(requires_approval("supervised", "Workflow", "Read"));
}

// ───────────── commit 6: admission, the held-open lease and the 60 s run budget (#2146 D1/D3) ─────────

namespace {

std::int64_t refused_count(yuzu::MetricsRegistry& m, const char* reason) {
    return static_cast<std::int64_t>(
        m.counter(kWorkflowRunRefusedMetric, {{"reason", reason}}).value());
}

} // namespace

TEST_CASE("workflow run admission: a run leases kWorkflowRun, two per principal, counted in the one budget; "
          "a draining server is refused first and takes no lease",
          "[workflow][twin][cap]") {
    detail::StreamBudget budget{{.global_cap = 3}};
    yuzu::MetricsRegistry m;
    const std::function<bool()> never = [] { return false; };

    // The metric's closed reason set is the budget's own two tokens plus `draining`.
    REQUIRE(kWorkflowRunRefusedReasons.size() == 3);
    CHECK(kWorkflowRunRefusedReasons[0] == detail::StreamBudget::kRejectGlobal);
    CHECK(kWorkflowRunRefusedReasons[1] == detail::StreamBudget::kRejectPerPrincipal);
    CHECK(kWorkflowRunRefusedReasons[2] == "draining");

    auto a1 = admit_workflow_run(&budget, never, "alice", &m);
    auto a2 = admit_workflow_run(&budget, never, "alice", &m);
    REQUIRE(a1.lease);
    REQUIRE(a2.lease);
    CHECK_FALSE(a1.refusal);
    CHECK(budget.active_for_surface(detail::SseSurface::kWorkflowRun) == 2);

    // The third run of the same principal: the per-principal cap, retryable, nothing counted wrongly.
    auto a3 = admit_workflow_run(&budget, never, "alice", &m);
    CHECK_FALSE(a3.lease);
    REQUIRE(a3.refusal);
    CHECK(a3.refusal->status == WorkflowExecuteStatus::kRunCapReached);
    CHECK(a3.refusal->reason == "per_principal_stream_cap");
    CHECK(a3.refusal->retryable);
    CHECK(refused_count(m, "per_principal_stream_cap") == 1);
    CHECK(refused_count(m, "global_stream_cap") == 0);

    // Another principal takes the last global slot; the next one anywhere is refused on the GLOBAL cap.
    auto b1 = admit_workflow_run(&budget, never, "bob", &m);
    REQUIRE(b1.lease);
    auto c1 = admit_workflow_run(&budget, never, "carol", &m);
    REQUIRE(c1.refusal);
    CHECK(c1.refusal->reason == "global_stream_cap");
    CHECK(refused_count(m, "global_stream_cap") == 1);
    // A stream on another surface is refused too: it is ONE budget.
    CHECK_FALSE(budget.try_acquire(detail::SseSurface::kApiEvents, "dave", 16).lease);

    // Dropping a lease frees its slot for the next run.
    a1.lease.release();
    CHECK(admit_workflow_run(&budget, never, "carol", &m).lease);

    // Draining wins over a budget with room, takes no lease and counts `draining`.
    detail::StreamBudget roomy{{.global_cap = 10}};
    const std::function<bool()> always = [] { return true; };
    auto d = admit_workflow_run(&roomy, always, "alice", &m);
    CHECK_FALSE(d.lease);
    REQUIRE(d.refusal);
    CHECK(d.refusal->status == WorkflowExecuteStatus::kDraining);
    CHECK(d.refusal->reason == "draining");
    CHECK(d.refusal->retryable);
    CHECK(roomy.active() == 0);
    CHECK(refused_count(m, "draining") == 1);

    // A null budget is the unmetered test seam; a null draining port is never draining.
    auto u = admit_workflow_run(nullptr, {}, "alice", &m);
    CHECK_FALSE(u.refusal);
    CHECK_FALSE(u.lease);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: the run holds a kWorkflowRun lease for exactly the run, "
          "released on success, on a thrown run and on a refusal after admission",
          "[workflow][twin][rest][cap]") {
    using detail::SseSurface;
    SECTION("a successful run") {
        Rest r;
        std::size_t during = 99;
        r.fx.during_run = [&] { during = r.budget.active_for_surface(SseSurface::kWorkflowRun); };
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(during == 1);
        CHECK(r.budget.active() == 0);
    }
    SECTION("a run that throws after the requested row") {
        Rest r;
        r.dispatch_throws = true;
        std::size_t during = 99;
        r.fx.during_run = [&] { during = r.budget.active_for_surface(SseSurface::kWorkflowRun); };
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(during == 1);
        CHECK(r.budget.active() == 0);
    }
    SECTION("a refusal from the per-step checks") {
        Rest r;
        r.fx.defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(r.budget.active() == 0);
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a principal at its run cap gets 429 + Retry-After and "
          "NOTHING is read, sent or audited; the same call succeeds once a slot frees",
          "[workflow][twin][rest][cap][security]") {
    Rest r;
    std::vector<detail::StreamBudget::Lease> held;
    for (std::size_t i = 0; i < detail::kPerPrincipalWorkflowRun; ++i) {
        auto a = r.budget.try_acquire(detail::SseSurface::kWorkflowRun, "alice",
                                      detail::kPerPrincipalWorkflowRun);
        REQUIRE(a.lease);
        held.push_back(std::move(a.lease));
    }
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(res->get_header_value("Retry-After") == "5");
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "per_principal_stream_cap");
    CHECK(at_path(j, "/error/retry_after_ms") == 5000);
    CHECK(at_path(j, "/error/remediation").get<std::string>().find("nothing was sent") != std::string::npos);
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
    CHECK(r.fx.events.empty()); // no audit row of any kind
    CHECK(r.fx.lookup_count.empty()); // no instruction was read
    CHECK(r.persist_calls == 0);
    CHECK(r.refused("per_principal_stream_cap") == 1);
    // Another principal is unaffected by alice's cap.
    r.caller.principal = "bob";
    CHECK(r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})")->status == 202);
    r.caller.principal = "alice";

    held.pop_back();
    const auto ok = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(ok);
    CHECK(ok->status == 202);
    CHECK(r.fx.engine_called);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a full server budget is a 429 on the global cap",
          "[workflow][twin][rest][cap]") {
    Rest r;
    std::vector<detail::StreamBudget::Lease> held;
    for (std::size_t i = 0; i < r.budget.capacity(); ++i) {
        auto a = r.budget.try_acquire(detail::SseSurface::kApiEvents, "p" + std::to_string(i), 0);
        REQUIRE(a.lease);
        held.push_back(std::move(a.lease));
    }
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(body_of(*res)["error"]["reason"] == "global_stream_cap");
    CHECK(r.refused("global_stream_cap") == 1);
    CHECK_FALSE(r.fx.engine_called);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a draining server refuses a new run with a retryable 503 "
          "and takes no lease",
          "[workflow][twin][rest][cap][drain]") {
    Rest r;
    r.draining = true;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "draining");
    CHECK(at_path(j, "/error/retry_after_ms") == 5000);
    CHECK(r.budget.active() == 0);
    CHECK(r.refused("draining") == 1);
    CHECK_FALSE(r.fx.engine_called);
    CHECK(r.fx.events.empty());
    r.draining = false;
    CHECK(r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})")->status == 202);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a malformed workflow id is a non-retryable 400 "
          "invalid_workflow_id before any key, read, lease, ticket-class write, audit row or send",
          "[workflow][twin][rest][security]") {
    const std::vector<std::pair<const char*, std::string>> bad = {
        {"NUL", std::string("foo\0xyz", 7)},
        {"%FF as raw 0xFF", std::string("foo\xFF")},
        {"overlong C0 80", std::string("foo\xC0\x80")},
        {"truncated UTF-8", std::string("foo\xE4\xB8")},
        {"129 bytes", std::string(129, 'x')},
        {"4 KB", std::string(4096, 'x')},
        {"SOH", std::string("foo\x01")},
        {"LF", std::string("foo\nbar")},
        {"ESC", std::string("foo\x1b[31m")},
        {"DEL", std::string("foo\x7f")},
    };
    for (const bool keyed_call : {false, true}) {
        for (const auto& [what, id] : bad) {
            INFO(what);
            Rest r;
            // A draining server must not mask the refusal: the id is judged first, so the answer
            // is the same 400 and the budget is untouched.
            r.draining = true;
            const std::string path = "/api/v1/workflows/" + id + "/execute";
            const std::unordered_map<std::string, std::string> hdrs =
                keyed_call ? std::unordered_map<std::string, std::string>{{"Idempotency-Key", "key-0123456789"}}
                           : std::unordered_map<std::string, std::string>{};
            const auto res =
                r.sink.dispatch("POST", path, R"({"agent_ids":["a1"]})", "application/json", hdrs);
            REQUIRE(res);
            CHECK(res->status == 400);
            const auto j = body_of(*res);
            CHECK(at_path(j, "/error/reason") == "invalid_workflow_id");
            // Not retryable: no retry hint, and the message never echoes the id.
            CHECK((!at_path(j, "/error").contains("retry_after_ms") ||
                   at_path(j, "/error/retry_after_ms").is_null()));
            CHECK(res->get_header_value("Retry-After").empty());
            CHECK(res->body.find("foo") == std::string::npos);
            CHECK(res->body.find(id) == std::string::npos);
            // Nothing read, leased, run or sent. The refusal itself IS audited (a `denied` row,
            // the instruction twin's pre-core refusal), carrying the id only bounded and cleaned.
            CHECK(r.fx.get_workflow_calls == 0);
            CHECK(r.fx.lookup_count.empty());
            CHECK(r.fx.find_calls == 0);
            CHECK_FALSE(r.fx.engine_called);
            CHECK(r.fx.bound.empty());
            CHECK(r.fx.events == std::vector<std::string>{"audit:denied"});
            REQUIRE(r.persist_calls == 1);
            CHECK(r.audit_actions.front() == "workflow.execute");
            CHECK(r.audit_results.front() == "denied");
            CHECK(r.fx.audit_details.front().starts_with("surface=rest correlation_id="));
            CHECK(r.fx.audit_details.front().find("reason=invalid_workflow_id") != std::string::npos);
            CHECK(r.fx.audit_details.front().find(res->get_header_value("X-Correlation-Id")) !=
                  std::string::npos);
            CHECK_FALSE(r.fx.dispatched_anything());
            CHECK(r.budget.active() == 0);
            CHECK(r.refused("draining") == 0);
            CHECK(r.refused("per_principal_stream_cap") == 0);
            // The row is bounded and holds no raw control byte, whatever the id held: neither the
            // target column nor the detail may carry the malformed id as sent.
            for (const std::string& cell : {r.audit_targets.front(), r.fx.audit_details.front()}) {
                CHECK(cell.size() <= 600);
                for (const char ch : cell) {
                    CHECK(static_cast<unsigned char>(ch) >= 0x20);
                    CHECK(static_cast<unsigned char>(ch) != 0x7F);
                }
            }
            if (id.size() > 200) { // an over-length id never reaches the row whole
                CHECK(r.audit_targets.front().size() < id.size());
                CHECK(r.fx.audit_details.front().find(id) == std::string::npos);
            }
            CHECK(r.audit_targets.front().find(id) == std::string::npos);
        }
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a well-formed multibyte or maximum-length id still "
          "reaches the workflow read (the check does not over-refuse)",
          "[workflow][twin][rest][security]") {
    for (const auto& id : {std::string("caf\xc3\xa9"), std::string(128, 'x'), std::string("a.b_c-d:e")}) {
        INFO(id);
        Rest r;
        const auto res = r.sink.Post("/api/v1/workflows/" + id + "/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 404); // unknown workflow: it was READ, found nothing
        CHECK(r.fx.get_workflow_calls == 1);
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a malformed body is a 400 even at the cap, and takes no "
          "slot",
          "[workflow][twin][rest][cap]") {
    Rest r;
    std::vector<detail::StreamBudget::Lease> held;
    for (std::size_t i = 0; i < detail::kPerPrincipalWorkflowRun; ++i)
        held.push_back(std::move(r.budget
                                     .try_acquire(detail::SseSurface::kWorkflowRun, "alice",
                                                  detail::kPerPrincipalWorkflowRun)
                                     .lease));
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":[]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(r.refused("per_principal_stream_cap") == 0);
}

TEST_CASE("workflow run budget: the REST route stamps a 60 s deadline when it takes the call, and the "
          "sequence installs the hook the engine asks before every attempt",
          "[workflow][twin][rest][deadline]") {
    Rest r;
    const auto before = std::chrono::steady_clock::now();
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    REQUIRE(r.fx.seen_deadline.has_value());
    CHECK(*r.fx.seen_deadline >= before + kWorkflowSyncBudget);
    CHECK(*r.fx.seen_deadline <= std::chrono::steady_clock::now() + kWorkflowSyncBudget);
    CHECK(r.fx.seen_before_attempt);
    CHECK_FALSE(r.fx.engine_stopped);
}

TEST_CASE("workflow run budget: a run stopped at its deadline skips the rest, reports aborted/"
          "deadline_exceeded, closes `failure`, and is never `completed`",
          "[workflow][twin][deadline][outcome]") {
    SECTION("the deadline passes between step 1 and step 2") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed"; // what the engine records for a stopped run
        auto req = f.request();
        // Step 1 is sent and runs until the deadline has passed: the callback waits for the
        // deadline itself, so "it passes between step 1 and step 2" holds however long setup or
        // the dispatch took. The margin only has to cover the in-process gap before the first
        // attempt; it is not a race against the callback's length.
        req.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
        const auto deadline = *req.deadline;
        f.dispatch_override = [deadline](const WorkflowStepInstruction& d,
                                         const std::vector<std::string>&, const DispatchCaller&) {
            std::this_thread::sleep_until(deadline + std::chrono::milliseconds(5));
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-" + d.id};
        };
        const auto o = f.run(req);
        CHECK(f.engine_stopped);
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
        CHECK(o.deadline_exceeded);
        CHECK(o.reason == "deadline_exceeded");
        CHECK_FALSE(o.retryable);
        CHECK(o.steps.size() == 1); // step 2 was never sent
        CHECK(f.events.back() == "audit:failure");
        CHECK(f.audit_details.back().find("run_outcome=aborted") != std::string::npos);
        CHECK(f.audit_details.back().find("reason=deadline_exceeded") != std::string::npos);
        const auto j = workflow_execute_result_json(o, "wf-1");
        CHECK(j["status"] == "aborted");
        CHECK(j["reason"] == "deadline_exceeded");
        CHECK(j["retryable"] == false);
        CHECK(j["message"].get<std::string>().find("60 second") != std::string::npos);
    }
    SECTION("the deadline had already passed before the first attempt: nothing reached anyone") {
        Fx f;
        f.engine_status = "failed";
        auto req = f.request();
        req.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        const auto o = f.run(req);
        CHECK_FALSE(f.dispatched_anything());
        CHECK(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(o.deadline_exceeded);
        CHECK(o.reason == "deadline_exceeded");
        CHECK_FALSE(o.retryable);
        CHECK(f.audit_details.back().find("reason=deadline_exceeded") != std::string::npos);
    }
    SECTION("a run that finishes inside its budget is untouched") {
        Fx f;
        auto req = f.request();
        req.deadline = std::chrono::steady_clock::now() + std::chrono::hours(1);
        const auto o = f.run(req);
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK_FALSE(o.deadline_exceeded);
    }
    SECTION("a request that carries no deadline is still bounded by the sequence") {
        Fx f;
        const auto o = f.run(); // Fx::request() sets none
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        REQUIRE(f.seen_deadline.has_value());
        CHECK(*f.seen_deadline > std::chrono::steady_clock::now());
        CHECK(*f.seen_deadline <= std::chrono::steady_clock::now() + kWorkflowSyncBudget);
    }
}

TEST_CASE("workflow run shutdown: a run the engine stopped for a server stop is INTERRUPTED, a typed "
          "non-success with reason server_shutdown, even when nothing had been sent",
          "[workflow][twin][shutdown][outcome]") {
    SECTION("stopped after step 1 was sent") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed"; // what the engine records for a stopped run
        f.interrupt_before_step = 1;
        const auto o = f.run();
        CHECK(f.engine_stopped);
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kInterrupted);
        CHECK(o.interrupted);
        CHECK_FALSE(o.deadline_exceeded);
        CHECK(o.reason == "server_shutdown");
        CHECK_FALSE(o.retryable);
        CHECK(o.steps.size() == 1); // step 2 was never sent
        CHECK(f.events.back() == "audit:failure");
        CHECK(f.audit_details.back().find("run_outcome=interrupted") != std::string::npos);
        CHECK(f.audit_details.back().find("reason=server_shutdown") != std::string::npos);
        const auto j = workflow_execute_result_json(o, "wf-1");
        CHECK(j["status"] == "interrupted");
        CHECK(j["reason"] == "server_shutdown");
        CHECK(j["retryable"] == false);
        CHECK(j["run_status"] == "failed");
        CHECK(j["message"].get<std::string>().find("shutting down") != std::string::npos);
    }
    SECTION("stopped before any step was sent: still a typed interrupted run, not a zero-reach error") {
        Fx f;
        f.engine_status = "failed";
        f.interrupt_before_step = 0;
        const auto o = f.run();
        CHECK_FALSE(f.dispatched_anything());
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kInterrupted);
        CHECK(o.reason == "server_shutdown");
        CHECK_FALSE(o.retryable);
        CHECK(o.execution_id == "exec-1");
        CHECK(f.audit_details.back().find("run_outcome=interrupted") != std::string::npos);
    }
    SECTION("a draining server alone interrupts nothing: the engine never calls on_interrupted") {
        Fx f;
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK_FALSE(o.interrupted);
        CHECK(o.run_outcome == WorkflowRunOutcome::kSucceeded);
    }
    SECTION("the sequence hands the engine an on_interrupted hook") {
        Fx f;
        f.engine_status = "failed";
        auto a = f.api();
        auto p = f.ports(a);
        bool had_hook = false;
        p.run = [&](const std::string&, const std::vector<std::string>&, StepDispatchFn,
                    ConditionEvalFn, const WorkflowRunControl& control)
            -> std::expected<std::string, std::string> {
            had_hook = static_cast<bool>(control.on_interrupted);
            return std::string{"exec-1"};
        };
        (void)apply_workflow_execute(p, f.request());
        CHECK(had_hook);
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a run interrupted by a server stop is a 202 with "
          "status interrupted, reason server_shutdown and no retry hint",
          "[workflow][twin][rest][shutdown][outcome]") {
    Rest r;
    r.fx.engine_status = "failed";
    r.fx.step_ids = {"i-ro", "i-ro2"};
    r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    r.fx.interrupt_before_step = 1;
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/data/status") == "interrupted");
    CHECK(at_path(j, "/data/reason") == "server_shutdown");
    CHECK(at_path(j, "/data/retryable") == false);
    CHECK(at_path(j, "/data/run_status") == "failed");
    REQUIRE(at_path(j, "/data/steps").size() == 1);
    CHECK(r.fx.audit_details.back().find("run_outcome=interrupted") != std::string::npos);
}

TEST_CASE("workflow run budget: prepare refuses a workflow whose worst-case retry sleep exceeds 60 s; "
          "exactly 60 s is admitted; nothing is audited, sent or run",
          "[workflow][twin][budget]") {
    struct Row {
        const char* what;
        std::vector<std::pair<int, int>> retries; // (retry_count, retry_delay_seconds) per step
        bool admitted;
    };
    const Row rows[] = {
        {"6 x 10 s == 60 s", {{6, 10}}, true},
        {"61 x 1 s == 61 s", {{61, 1}}, false},
        {"7 x 10 s == 70 s", {{7, 10}}, false},
        {"two steps 30 s + 30 s == 60 s", {{3, 10}, {3, 10}}, true},
        {"two steps 30 s + 31 s == 61 s", {{3, 10}, {31, 1}}, false},
        {"many retries with no delay sleep nothing", {{10, 0}, {10, 0}}, true},
        {"no retries at all", {{0, 3600}}, true},
        {"the maximum retries at the maximum delay", {{10, 3600}}, false},
    };
    for (const auto& row : rows) {
        DYNAMIC_SECTION(row.what) {
            Fx f;
            f.step_ids = {"i-ro", "i-ro2"};
            f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
            f.step_retries = row.retries;
            const auto o = f.run();
            if (row.admitted) {
                CHECK(o.status == WorkflowExecuteStatus::kOk);
                CHECK(f.engine_called);
            } else {
                CHECK(o.status == WorkflowExecuteStatus::kExceedsSyncBudget);
                CHECK(o.reason == "workflow_exceeds_sync_budget");
                CHECK_FALSE(o.retryable);
                CHECK(o.remediation.find("retryCount x retryDelay") != std::string::npos);
                CHECK_FALSE(f.engine_called);
                CHECK_FALSE(f.dispatched_anything());
                CHECK(f.events.empty()); // no `requested` row, no denial row
                CHECK(f.authorize_calls.empty());
            }
        }
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a workflow over the sync budget is a 400 with the reason "
          "and takes a lease only for the length of the refusal",
          "[workflow][twin][rest][budget]") {
    Rest r;
    r.fx.step_retries = {{7, 10}};
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(body_of(*res)["error"]["reason"] == "workflow_exceeds_sync_budget");
    CHECK(r.fx.events.empty());
    CHECK_FALSE(r.fx.engine_called);
    CHECK(r.budget.active() == 0);
}

// ───────────────────────────── per-step credential re-check (D2a) ───────────────────────────

namespace {

using CC = auth::CredentialCheck;

/// A two-step workflow whose stand-in engine ends `failed` (what the real engine records for a
/// run it stopped) and whose request carries the credential check.
void two_steps_with_reauth(Fx& f, std::vector<CC> answers) {
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.engine_status = "failed";
    f.wire_reauth = true;
    f.reauth_answers = std::move(answers);
}

} // namespace

TEST_CASE("workflow credential check: a credential revoked after step 1 stops the run BEFORE step 2 is "
          "sent; the run is aborted, credential_revoked, not retryable",
          "[workflow][twin][reauth][outcome]") {
    Fx f;
    two_steps_with_reauth(f, {CC::kValid, CC::kRevoked});
    const auto o = f.run();
    // Step 1 was sent, step 2 never was.
    CHECK(f.events.size() >= 2);
    CHECK(o.steps.size() == 1);
    CHECK(o.steps[0].instruction_id == "i-ro");
    CHECK(f.engine_stopped);
    CHECK(f.reauth_calls == 2);
    CHECK(f.reauth_dispatches_at == std::vector<int>{0, 1}); // asked BEFORE each send
    CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
    CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
    CHECK(o.credential_stop == "credential_revoked");
    CHECK(o.reason == "credential_revoked");
    CHECK_FALSE(o.retryable);
    CHECK_FALSE(o.deadline_exceeded);
    CHECK_FALSE(o.interrupted);
    CHECK(o.execution_id == "exec-1");
    // The closing row is a failure naming the outcome and the reason, and it is the last thing.
    CHECK(f.events.back() == "audit:failure");
    CHECK(f.audit_details.back().find("run_outcome=aborted") != std::string::npos);
    CHECK(f.audit_details.back().find("reason=credential_revoked") != std::string::npos);
    const auto j = workflow_execute_result_json(o, "wf-1");
    CHECK(j["status"] == "aborted");
    CHECK(j["reason"] == "credential_revoked");
    CHECK(j["retryable"] == false);
    CHECK(j["steps"].size() == 1);
    CHECK(j["message"].get<std::string>().find("no longer valid") != std::string::npos);
}

TEST_CASE("workflow credential check: revoked before the first step sends nothing, and is still a typed "
          "aborted run rather than a zero-reach error",
          "[workflow][twin][reauth][outcome]") {
    Fx f;
    two_steps_with_reauth(f, {CC::kRevoked});
    const auto o = f.run();
    CHECK_FALSE(f.dispatched_anything());
    CHECK(f.reauth_calls == 1);
    CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
    CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
    CHECK(o.reason == "credential_revoked");
    CHECK_FALSE(o.retryable);
    CHECK(o.execution_id == "exec-1");
    CHECK(f.audit_details.back().find("reason=credential_revoked") != std::string::npos);
}

TEST_CASE("workflow credential check: an indeterminate answer is asked ONCE more; valid continues, a "
          "second non-answer aborts credential_indeterminate, a revocation on the retry is revoked",
          "[workflow][twin][reauth][outcome]") {
    SECTION("indeterminate then valid continues and every step is sent") {
        Fx f;
        two_steps_with_reauth(f, {CC::kIndeterminate, CC::kValid, CC::kValid});
        f.engine_status = "completed";
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK(o.steps.size() == 2);
        CHECK(f.reauth_calls == 3); // step 1 asked twice, step 2 once
        CHECK(o.credential_stop.empty());
    }
    SECTION("indeterminate twice aborts, step 1 is never sent") {
        Fx f;
        two_steps_with_reauth(f, {CC::kIndeterminate, CC::kIndeterminate});
        const auto o = f.run();
        CHECK_FALSE(f.dispatched_anything());
        CHECK(f.reauth_calls == 2); // asked, retried once, never a third time
        CHECK(o.status == WorkflowExecuteStatus::kRunIncomplete);
        CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
        CHECK(o.credential_stop == "credential_indeterminate");
        CHECK(o.reason == "credential_indeterminate");
        CHECK_FALSE(o.retryable);
        CHECK(f.audit_details.back().find("run_outcome=aborted") != std::string::npos);
        CHECK(f.audit_details.back().find("reason=credential_indeterminate") != std::string::npos);
        const auto j = workflow_execute_result_json(o, "wf-1");
        CHECK(j["status"] == "aborted");
        CHECK(j["reason"] == "credential_indeterminate");
        CHECK(j["message"].get<std::string>().find("could not be confirmed") != std::string::npos);
    }
    SECTION("indeterminate on step 2 after step 1 was sent aborts there") {
        Fx f;
        two_steps_with_reauth(f, {CC::kValid, CC::kIndeterminate, CC::kIndeterminate});
        const auto o = f.run();
        CHECK(o.steps.size() == 1);
        CHECK(f.reauth_calls == 3);
        CHECK(o.reason == "credential_indeterminate");
    }
    SECTION("indeterminate then revoked is revoked") {
        Fx f;
        two_steps_with_reauth(f, {CC::kIndeterminate, CC::kRevoked});
        const auto o = f.run();
        CHECK_FALSE(f.dispatched_anything());
        CHECK(o.reason == "credential_revoked");
    }
    SECTION("a check that throws is indeterminate: once then valid continues, twice aborts") {
        Fx f;
        two_steps_with_reauth(f, {});
        f.engine_status = "completed";
        int n = 0;
        f.reauth_script = [&n]() -> CC {
            if (++n == 1)
                throw std::runtime_error("auth store exploded");
            return CC::kValid;
        };
        CHECK(f.run().status == WorkflowExecuteStatus::kOk);
        CHECK(n == 3);

        Fx g;
        two_steps_with_reauth(g, {});
        g.reauth_script = []() -> CC { throw std::runtime_error("auth store exploded"); };
        const auto o = g.run();
        CHECK_FALSE(g.dispatched_anything());
        CHECK(o.reason == "credential_indeterminate");
    }
}

TEST_CASE("workflow credential check: a stale-but-valid answer continues", "[workflow][twin][reauth]") {
    Fx f;
    two_steps_with_reauth(f, {CC::kValidStale, CC::kValidStale});
    f.engine_status = "completed";
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    CHECK(o.steps.size() == 2);
    CHECK(f.reauth_calls == 2);
}

TEST_CASE("workflow credential check: asked once per dispatch attempt, so once per step plus once on "
          "waking from each retry sleep",
          "[workflow][twin][reauth]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2", "i-ro3"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.defs["i-ro3"] = def("i-ro3", "os_info", "os_version");
    f.engine_status = "failed";
    f.wire_reauth = true;
    // Step 2 reaches nobody (a non-permanent failure): the stand-in engine retries it twice.
    f.outcomes["i-ro2"] = ConfinedDispatchOutcome{.sent = 0, .command_id = "cmd-i-ro2"};
    f.engine_retries = 2;
    (void)f.run();
    // step 1 (1) + step 2 (first attempt + 2 retries = 3) + step 3 (1)
    CHECK(f.reauth_calls == 5);
    CHECK(f.reauth_dispatches_at == std::vector<int>{0, 1, 2, 3, 4});
}

TEST_CASE("workflow credential check: no port means no check, and the run is unchanged",
          "[workflow][twin][reauth]") {
    Fx f;
    two_steps_with_reauth(f, {CC::kRevoked, CC::kRevoked});
    f.wire_reauth = false; // the request carries no reauthorize
    f.engine_status = "completed";
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    CHECK(o.steps.size() == 2);
    CHECK(f.reauth_calls == 0);
}

TEST_CASE("workflow credential check: the retry wait never runs past the run's deadline, and the deadline "
          "then stops the run",
          "[workflow][twin][reauth][deadline]") {
    Fx f;
    two_steps_with_reauth(f, {CC::kIndeterminate, CC::kValid});
    auto req = f.request();
    req.reauthorize_retry_delay = std::chrono::seconds(30); // far past the deadline below
    // The first credential ask answers indeterminate and the hook then waits out min(30 s, time
    // left), so the deadline is what ends the run; the margin only has to cover the in-process
    // gap before that first ask.
    req.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
    const auto t0 = std::chrono::steady_clock::now();
    const auto o = f.run(req);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
    CHECK_FALSE(f.dispatched_anything());
    CHECK(f.reauth_calls == 1); // no second ask once the deadline arrived first
    CHECK(o.deadline_exceeded);
    CHECK(o.credential_stop.empty());
    CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
    CHECK(o.reason == "deadline_exceeded");
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a credential revoked after step 1 is a 202 aborted run "
          "with reason credential_revoked, step 2 not sent, asked as THIS request and principal",
          "[workflow][twin][rest][reauth][outcome]") {
    Rest r;
    two_steps_with_reauth(r.fx, {CC::kValid, CC::kRevoked});
    r.sink.default_headers["X-Yuzu-Token"] = "tok-live";
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/data/status") == "aborted");
    CHECK(at_path(j, "/data/reason") == "credential_revoked");
    CHECK(at_path(j, "/data/retryable") == false);
    CHECK(at_path(j, "/data/steps").size() == 1);
    CHECK(r.fx.reauth_calls == 2);
    CHECK(r.reauth_principals == std::vector<std::string>{"alice", "alice"});
    CHECK(r.reauth_tokens == std::vector<std::string>{"tok-live", "tok-live"});
    CHECK(r.fx.audit_details.back().find("run_outcome=aborted") != std::string::npos);
    CHECK(r.fx.audit_details.back().find("reason=credential_revoked") != std::string::npos);
    CHECK(r.budget.active() == 0); // the lease is released
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: an indeterminate credential check that stays "
          "indeterminate is a 202 aborted run with reason credential_indeterminate; a valid one runs on",
          "[workflow][twin][rest][reauth][outcome]") {
    SECTION("never answered") {
        Rest r;
        two_steps_with_reauth(r.fx, {CC::kIndeterminate, CC::kIndeterminate});
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 202);
        const auto j = body_of(*res);
        CHECK(at_path(j, "/data/status") == "aborted");
        CHECK(at_path(j, "/data/reason") == "credential_indeterminate");
        CHECK(at_path(j, "/data/retryable") == false);
        CHECK(at_path(j, "/data/steps").size() == 0);
        CHECK_FALSE(r.fx.dispatched_anything());
    }
    SECTION("valid every time") {
        Rest r;
        two_steps_with_reauth(r.fx, {});
        r.fx.engine_status = "completed";
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(body_of(*res)["data"]["status"] == "completed");
        CHECK(r.fx.reauth_calls == 2);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Idempotent execute (#2146): a client key claimed on the run row, a repeat answered with the run
// it is bound to and nothing sent. The sequence is tested here against a stand-in engine that
// models the engine's atomic claim; the claim itself (ON CONFLICT, the same-transaction
// disambiguation, the CHECK, the migration) is tested against Postgres in test_workflow_engine.cpp.
// ═══════════════════════════════════════════════════════════════════════════════════════════

namespace {

constexpr const char* kKey = "key-0123456789";

WorkflowExecuteRequest keyed(Fx& fx, std::vector<std::string> ids = {"a1"},
                             const char* key = kKey) {
    auto r = fx.request(std::move(ids));
    r.idempotency_key = key;
    return r;
}

std::int64_t real_epoch_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::unique_ptr<httplib::Response> post_with_key(Rest& r, const std::string& key,
                                                 const std::string& body = R"({"agent_ids":["a1"]})") {
    return r.sink.dispatch("POST", "/api/v1/workflows/wf-1/execute", body, "application/json",
                           {{"Idempotency-Key", key}});
}

bool audit_mentions(const Fx& fx, std::string_view needle) {
    return std::any_of(fx.audit_details.begin(), fx.audit_details.end(),
                       [&](const std::string& d) { return d.find(needle) != std::string::npos; });
}

} // namespace

TEST_CASE("idempotency key: 8 to 128 bytes of [A-Za-z0-9._:-], nothing else",
          "[workflow][twin][idempotency]") {
    CHECK_FALSE(check_workflow_idempotency_key("12345678"));
    CHECK_FALSE(check_workflow_idempotency_key(std::string(128, 'k')));
    CHECK_FALSE(check_workflow_idempotency_key("a.b_c:d-E9ZZ"));
    const std::string too_long(129, 'k');
    for (const auto& bad :
         {std::string{}, std::string("1234567"), too_long, std::string("key with space"),
          std::string("key/slash/123"), std::string("key@host123"), std::string("key\nline123"),
          std::string("caf\xc3\xa9-key-123"), std::string("key\"quote123"), std::string("key;semi123")}) {
        INFO(bad);
        const auto e = check_workflow_idempotency_key(bad);
        REQUIRE(e);
        CHECK(e->reason == "idempotency_key_invalid");
        // The message names the rule and never echoes the key.
        CHECK(e->message.find("key with") == std::string::npos);
    }
}

TEST_CASE("idempotency: the fingerprint is sha256 over the domain, the workflow and the SORTED, "
          "DEDUPED agent ids; it excludes everything else",
          "[workflow][twin][idempotency]") {
    Fx fx;
    auto a = fx.api();
    const auto p = fx.ports(a);
    const auto fp = workflow_request_fingerprint(p, "wf-1", {"a2", "a1", "a1"});
    REQUIRE(fp);
    CHECK(*fp == *sha256_hex(std::string("wf-exec-v2\n4:wf-12:a12:a2")));
    CHECK(*fp == Fx::fingerprint_of("wf-1", {"a1", "a2"}));
    CHECK(fp == workflow_request_fingerprint(p, "wf-1", {"a1", "a2"}));
    CHECK(fp != workflow_request_fingerprint(p, "wf-1", {"a1"}));
    CHECK(fp != workflow_request_fingerprint(p, "wf-2", {"a1", "a2"}));
    // A digest that cannot be computed is no fingerprint, never a digest of zeros.
    auto broken = p;
    broken.fingerprint_digest = [](std::string_view) { return std::optional<std::string>{}; };
    CHECK_FALSE(workflow_request_fingerprint(broken, "wf-1", {"a1"}));
}

TEST_CASE("idempotency: every field of the fingerprint is length-framed, so ids crafted to collide "
          "under a newline join are different requests",
          "[workflow][twin][idempotency][security]") {
    Fx fx;
    auto a = fx.api();
    auto p = fx.ports(a);
    const auto fp = [&](const std::string& wf, std::vector<std::string> ids) {
        return workflow_request_fingerprint(p, wf, ids);
    };
    // The old preimage `wf-exec-v1\n` + wf + `\n` + ids joined by `\n` was equal for each pair.
    CHECK(fp("X", {"a", "b"}) != fp("X\na", {"b"}));
    CHECK(fp("wf-1", {"a\nb"}) != fp("wf-1", {"a", "b"}));
    CHECK(fp("wf-1", {"a\nb", "c"}) != fp("wf-1", {"a", "b\nc"}));
    CHECK(fp("wf-1", {"", "a"}) != fp("wf-1", {"\na"}));
    // A length prefix is itself data inside a field: no forged prefix shifts a boundary.
    CHECK(fp("wf-1", {"1:a"}) != fp("wf-1", {"a"}));
    CHECK(fp("wf-1", {"2:a1"}) != fp("wf-1", {"a1"}));
    CHECK(fp("wf-1", {"a", "2:bc"}) != fp("wf-1", {"a2:bc"}));
    CHECK(fp("1:a", {"b"}) != fp("1:a1:b", {}));
    // NUL and 0xFF bytes frame like any other byte.
    CHECK(fp("wf-1", {std::string("a\0b", 3)}) != fp("wf-1", {"a"}));
    CHECK(fp("wf-1", {"\xFF"}) != fp("wf-1", {"\xFE"}));

    // The exact preimage, captured at the digest seam: domain, then <len>:<bytes> per field in
    // sorted, deduped order.
    std::string seen;
    p.fingerprint_digest = [&seen](std::string_view m) {
        seen.assign(m);
        return sha256_hex(m);
    };
    REQUIRE(workflow_request_fingerprint(p, "wf-1", {"b", "a", "b", "a\nc"}));
    CHECK(seen == std::string("wf-exec-v2\n4:wf-11:a3:a\nc1:b"));
}

TEST_CASE("idempotency: a key bound to {a,b} is a CONFLICT for {\"a\\nb\"}, never a replay",
          "[workflow][twin][idempotency][security]") {
    Fx fx;
    const auto first = fx.run(keyed(fx, {"a", "b"}));
    REQUIRE(first.status == WorkflowExecuteStatus::kOk);
    REQUIRE(fx.bound.size() == 1);
    fx.engine_called = false;
    const auto out = fx.run(keyed(fx, {std::string("a\nb")}));
    CHECK(out.status == WorkflowExecuteStatus::kIdempotencyConflict);
    CHECK(out.reason == "idempotency_key_conflict");
    CHECK_FALSE(fx.engine_called);
}

TEST_CASE("workflow id: 1 to 128 bytes of valid UTF-8 with no control byte, else invalid_workflow_id",
          "[workflow][twin][security]") {
    for (const auto& ok : {std::string("wf-1"), std::string("a"), std::string(128, 'x'),
                           std::string("caf\xc3\xa9"), std::string("\xe4\xb8\xad\xe6\x96\x87"),
                           std::string("with space"), std::string("a.b_c-d:e")}) {
        INFO(ok);
        CHECK_FALSE(check_workflow_id(ok));
    }
    const std::vector<std::pair<const char*, std::string>> bad = {
        {"empty", std::string()},
        {"NUL", std::string("foo\0xyz", 7)},
        {"leading NUL", std::string("\0foo", 4)},
        {"0xFF", std::string("foo\xFF")},
        {"overlong C0 80", std::string("foo\xC0\x80")},
        {"truncated sequence", std::string("foo\xE4\xB8")},
        {"surrogate", std::string("\xED\xA0\x80")},
        {"above U+10FFFF", std::string("\xF4\x90\x80\x80")},
        {"SOH", std::string("foo\x01")},
        {"LF", std::string("foo\nbar")},
        {"CR", std::string("foo\rbar")},
        {"ESC", std::string("foo\x1b[0m")},
        {"US", std::string("foo\x1f")},
        {"DEL", std::string("foo\x7f")},
        {"129 bytes", std::string(129, 'x')},
        {"4 KB", std::string(4096, 'x')},
    };
    for (const auto& [what, id] : bad) {
        INFO(what);
        const auto e = check_workflow_id(id);
        REQUIRE(e);
        CHECK(e->reason == "invalid_workflow_id");
        // The message names the rule and never echoes the id.
        CHECK(e->message.find("foo") == std::string::npos);
        CHECK(e->message.find("xxxxxxxx") == std::string::npos);
    }
}

TEST_CASE("idempotency: a keyless call is unchanged: no lookup, no claim, the run goes ahead",
          "[workflow][twin][idempotency]") {
    Fx fx;
    const auto out = fx.run();
    CHECK(out.status == WorkflowExecuteStatus::kOk);
    CHECK(fx.find_calls == 0);
    CHECK_FALSE(fx.seen_claim);
    CHECK(fx.bound.empty());
    CHECK_FALSE(audit_mentions(fx, "idempotency_key"));
    CHECK(fx.idem_counts.empty());
}

TEST_CASE("idempotency: a first keyed call looks the key up ONCE, hands the engine the claim, and "
          "records the key in its audit rows",
          "[workflow][twin][idempotency]") {
    Fx fx;
    const auto out = fx.run(keyed(fx, {"a2", "a1"}));
    REQUIRE(out.status == WorkflowExecuteStatus::kOk);
    CHECK(fx.find_calls == 1);
    REQUIRE(fx.seen_claim);
    CHECK(fx.seen_claim->principal == "alice");
    CHECK(fx.seen_claim->key == kKey);
    CHECK(fx.seen_claim->fingerprint == Fx::fingerprint_of("wf-1", {"a1", "a2"}));
    CHECK(fx.bound.size() == 1);
    CHECK(audit_mentions(fx, std::string("idempotency_key=") + kKey));
    CHECK(fx.idem_counts.empty());

    // A transport that already ran the pre-check does not make the lookup twice.
    Fx again;
    auto req = keyed(again);
    req.idempotency_prechecked = true;
    CHECK(again.run(req).status == WorkflowExecuteStatus::kOk);
    CHECK(again.find_calls == 0);
}

TEST_CASE("idempotency: a repeat of a COMPLETED run answers with the run and sends NOTHING",
          "[workflow][twin][idempotency][security]") {
    Fx fx;
    fx.bind("alice", kKey, "completed");
    const auto out = fx.run(keyed(fx));
    REQUIRE(out.status == WorkflowExecuteStatus::kIdempotentReplay);
    CHECK(out.execution_id == "exec-bound");
    CHECK(out.replay_status == "completed");
    CHECK(out.idempotent_replay);
    CHECK(out.started_at == fx.fixed_now - 1);
    // Nothing happened but the one terminal-replay audit row: not the engine, not the authorizer,
    // not an instruction read, not a dispatch, not a `requested` row.
    CHECK_FALSE(fx.engine_called);
    CHECK_FALSE(fx.dispatched_anything());
    CHECK(fx.authorize_calls.empty());
    CHECK(fx.lookup_count.empty());
    CHECK(fx.events == std::vector<std::string>{"audit:success"});
    REQUIRE(fx.audit_details.size() == 1);
    CHECK(fx.audit_details[0].find("idempotent_replay=true run_status=completed") !=
          std::string::npos);
    CHECK(fx.audit_details[0].find("execution_id=exec-bound") != std::string::npos);
    CHECK(fx.idem_counts == std::map<std::string, int>{{"replayed", 1}});

    const auto j = workflow_idempotent_replay_json(out, "wf-1");
    CHECK(j["execution_id"] == "exec-bound");
    CHECK(j["workflow_id"] == "wf-1");
    CHECK(j["status"] == "completed");
    CHECK(j["idempotent_replay"] == true);
    CHECK(j["started_at"] == fx.fixed_now - 1);
    CHECK_FALSE(j.contains("steps"));
    CHECK_FALSE(j.contains("late_denied"));
    CHECK_FALSE(j.contains("retry_after_ms"));
    CHECK_FALSE(j.contains("retryable"));
}

TEST_CASE("idempotency: the replay is decided BEFORE the workflow is read, so a since-deleted workflow "
          "or a raised approval mode still gets the replay",
          "[workflow][twin][idempotency]") {
    Fx fx;
    fx.bind("alice", kKey, "completed");
    fx.defs["i-ro"] = def("i-ro", "os_info", "os_version", "always"); // would be a 403 now
    CHECK(fx.run(keyed(fx)).status == WorkflowExecuteStatus::kIdempotentReplay);
    Fx gone;
    gone.bind("alice", kKey, "completed");
    auto req = keyed(gone);
    req.workflow_id = "wf-deleted";
    gone.bound[{"alice", kKey}].workflow_id = "wf-deleted";
    gone.bound[{"alice", kKey}].request_fingerprint =
        Fx::fingerprint_of("wf-deleted", {"a1"});
    CHECK(gone.run(req).status == WorkflowExecuteStatus::kIdempotentReplay);
}

TEST_CASE("idempotency: a FAILED, cancelled, RUNNING, stale-running or unknown-status run each answer "
          "with their own thin status and the right retry fields",
          "[workflow][twin][idempotency]") {
    struct Row {
        const char* engine_status;
        std::int64_t ago_s;
        const char* expect;
        bool audited;
    };
    const Row rows[] = {
        {"failed", 5, "failed", true},
        {"cancelled", 5, "failed", true},
        {"running", 5, "running", false},
        {"pending", 5, "running", false},
        {"running", 179, "running", false},
        {"running", 181, "indeterminate", true}, // past the 180 s bound
        {"running", -500, "indeterminate", true}, // dated far in the future: not believable
        {"weird", 5, "indeterminate", true},
        {"", 5, "indeterminate", true},
    };
    for (const auto& row : rows) {
        INFO(row.engine_status << " ago=" << row.ago_s);
        Fx fx;
        fx.bind("alice", kKey, row.engine_status, row.ago_s);
        const auto out = fx.run(keyed(fx));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(out.replay_status == row.expect);
        CHECK_FALSE(fx.engine_called);
        CHECK_FALSE(fx.dispatched_anything());
        // A terminal replay writes ONE row; a running one NONE (a poller would write one per poll).
        CHECK(fx.audit_details.size() == (row.audited ? 1u : 0u));
        const auto j = workflow_idempotent_replay_json(out, "wf-1");
        CHECK(j["status"] == row.expect);
        CHECK(j["idempotent_replay"] == true);
        if (std::string_view(row.expect) == "running") {
            CHECK(j["retry_after_ms"] == 2000);
            CHECK_FALSE(j.contains("retryable"));
            CHECK(fx.idem_counts == std::map<std::string, int>{{"in_progress", 1}});
        } else {
            CHECK_FALSE(j.contains("retry_after_ms"));
            CHECK(j["retryable"] == false);
            // `indeterminate` is split out of `replayed`: a stale or unprovable run is its own series.
            CHECK(fx.idem_counts ==
                  (std::string_view(row.expect) == "indeterminate"
                       ? std::map<std::string, int>{{"indeterminate", 1}}
                       : std::map<std::string, int>{{"replayed", 1}}));
            CHECK(fx.run_outcomes.empty()); // a replay never counts a run outcome
        }
        if (std::string_view(row.expect) == "running") {
            CHECK_FALSE(j.contains("remediation")); // a poll answer: retry_after_ms is its hint
        } else {
            REQUIRE(j.contains("remediation"));
            const auto remediation = j["remediation"].get<std::string>();
            CHECK(remediation.find("get_workflow_execution") != std::string::npos);
            CHECK(remediation.find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
            CHECK(remediation.find("new ") != std::string::npos);
            CHECK((remediation.find("may still be live") != std::string::npos) ==
                  (std::string_view(row.expect) == "indeterminate"));
        }
    }
}

TEST_CASE("idempotency: the same key with a DIFFERENT request is a terminal conflict that names the "
          "bound run and sends nothing; another order of the same agents is the same request",
          "[workflow][twin][idempotency][security]") {
    SECTION("different agents") {
        Fx fx;
        fx.bind("alice", kKey, "completed", 1, "wf-1", {"a1"});
        const auto out = fx.run(keyed(fx, {"a1", "a2"}));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotencyConflict);
        CHECK(out.reason == "idempotency_key_conflict");
        CHECK(out.execution_id == "exec-bound");
        CHECK_FALSE(out.retryable);
        CHECK_FALSE(fx.engine_called);
        CHECK_FALSE(fx.dispatched_anything());
        CHECK(fx.events == std::vector<std::string>{"audit:denied"});
        CHECK(fx.audit_details[0].find("reason=idempotency_key_conflict") != std::string::npos);
        CHECK(fx.idem_counts == std::map<std::string, int>{{"conflict", 1}});
    }
    SECTION("different workflow") {
        Fx fx;
        fx.bind("alice", kKey, "completed", 1, "wf-other", {"a1"});
        CHECK(fx.run(keyed(fx)).status == WorkflowExecuteStatus::kIdempotencyConflict);
    }
    SECTION("the same agents in another order, with a repeat, are the same request") {
        Fx fx;
        fx.bind("alice", kKey, "completed", 1, "wf-1", {"a1", "a2"});
        CHECK(fx.run(keyed(fx, {"a2", "a1", "a2"})).status ==
              WorkflowExecuteStatus::kIdempotentReplay);
    }
}

TEST_CASE("idempotency: a key is the PRINCIPAL's own: another principal's run under the same key is not "
          "this caller's, and the call runs",
          "[workflow][twin][idempotency][security]") {
    Fx fx;
    fx.bind("bob", kKey, "completed");
    const auto out = fx.run(keyed(fx)); // alice
    CHECK(out.status == WorkflowExecuteStatus::kOk);
    CHECK(fx.engine_called);
    CHECK(fx.bound.contains({"alice", kKey}));
    CHECK(fx.bound.contains({"bob", kKey}));
    CHECK(fx.bound[{"bob", kKey}].execution_id == "exec-bound"); // untouched
}

TEST_CASE("idempotency: a key with no principal is refused whoever the caller is, system included",
          "[workflow][twin][idempotency][security]") {
    for (const bool system : {false, true}) {
        INFO("system=" << system);
        Fx fx;
        auto req = keyed(fx);
        req.caller.principal.clear();
        req.caller.system = system;
        const auto out = fx.run(req);
        CHECK(out.status == WorkflowExecuteStatus::kNoPrincipal);
        // A non-system caller without a principal is refused by the ordinary wiring check; a
        // SYSTEM caller passes that one (it may run unkeyed) and is refused for the key alone.
        CHECK(out.reason == (system ? "idempotency_requires_principal" : "no_principal"));
        CHECK_FALSE(fx.engine_called);
        CHECK(fx.find_calls == 0);
        CHECK(fx.events.empty());
    }
}

TEST_CASE("idempotency: a lookup that FAILS refuses the call, retryable, with nothing written or sent "
          "(it never reads as 'no run bound')",
          "[workflow][twin][idempotency][failclosed]") {
    Fx fx;
    fx.find_fault = true;
    const auto out = fx.run(keyed(fx));
    CHECK(out.status == WorkflowExecuteStatus::kStoreFailed);
    CHECK(out.retryable);
    CHECK(out.message.find("db:") == std::string::npos); // no raw store text
    CHECK_FALSE(fx.engine_called);
    CHECK_FALSE(fx.dispatched_anything());
    CHECK(fx.events.empty()); // not even a denial row
    CHECK(fx.lookup_count.empty());
}

TEST_CASE("idempotency: an unwired port refuses a keyed call exactly as an unkeyed one (fail closed)",
          "[workflow][twin][idempotency][failclosed]") {
    Fx fx;
    fx.bind("alice", kKey, "completed");
    fx.store_open = false;
    const auto out = fx.run(keyed(fx));
    CHECK(out.status == WorkflowExecuteStatus::kUnavailable);
    CHECK(fx.find_calls == 0);
    CHECK(fx.events.empty());
}

TEST_CASE("idempotency: a fingerprint that cannot be computed refuses the keyed call, audited, with "
          "nothing sent",
          "[workflow][twin][idempotency][failclosed]") {
    Fx fx;
    auto a = fx.api();
    auto ports = fx.ports(a);
    ports.fingerprint_digest = [](std::string_view) { return std::optional<std::string>{}; };
    const auto out = apply_workflow_execute(ports, keyed(fx));
    CHECK(out.status == WorkflowExecuteStatus::kEffectDigestFailed);
    CHECK(out.reason == "request_fingerprint_unavailable");
    CHECK(fx.events == std::vector<std::string>{"audit:failure"});
    CHECK_FALSE(fx.engine_called);
    CHECK(fx.find_calls == 0);
    // Keyless calls do not need the digest.
    Fx k;
    auto ka = k.api();
    auto kports = k.ports(ka);
    kports.fingerprint_digest = [](std::string_view) { return std::optional<std::string>{}; };
    CHECK(apply_workflow_execute(kports, k.request()).status == WorkflowExecuteStatus::kOk);
}

TEST_CASE("idempotency: a call that passed the pre-check and LOST the engine's claim closes its "
          "requested row denied/idempotent_duplicate and answers as a replay, sending nothing",
          "[workflow][twin][idempotency][race][security]") {
    SECTION("the winner has the same request, and is still running") {
        Fx fx;
        fx.before_claim = [&](const WorkflowIdempotencyClaim& c) {
            fx.bound[{c.principal, c.key}] = WorkflowIdempotentRun{
                "exec-winner", "wf-1", c.fingerprint, "running", fx.fixed_now};
        };
        const auto out = fx.run(keyed(fx));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(out.execution_id == "exec-winner");
        CHECK(out.replay_status == "running");
        CHECK_FALSE(fx.dispatched_anything());
        CHECK(fx.events == std::vector<std::string>{"audit:requested", "audit:denied"});
        CHECK(fx.audit_details[1].find("reason=idempotent_duplicate") != std::string::npos);
        CHECK(fx.audit_details[1].find("execution_id=exec-winner") != std::string::npos);
        CHECK(fx.idem_counts == std::map<std::string, int>{{"in_progress", 1}});
    }
    SECTION("the winner has the same request and has already completed") {
        Fx fx;
        fx.before_claim = [&](const WorkflowIdempotencyClaim& c) {
            fx.bound[{c.principal, c.key}] = WorkflowIdempotentRun{
                "exec-winner", "wf-1", c.fingerprint, "completed", fx.fixed_now - 3};
        };
        const auto out = fx.run(keyed(fx));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(out.replay_status == "completed");
        CHECK(fx.idem_counts == std::map<std::string, int>{{"replayed", 1}});
    }
    SECTION("the winner's request differs: a 422-class conflict, requested row closed denied") {
        Fx fx;
        fx.before_claim = [&](const WorkflowIdempotencyClaim& c) {
            fx.bound[{c.principal, c.key}] = WorkflowIdempotentRun{
                "exec-winner", "wf-1", Fx::fingerprint_of("wf-1", {"zzz"}), "running", fx.fixed_now};
        };
        const auto out = fx.run(keyed(fx));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotencyConflict);
        CHECK(out.execution_id == "exec-winner");
        CHECK(fx.events == std::vector<std::string>{"audit:requested", "audit:denied"});
        CHECK(fx.audit_details[1].find("reason=idempotency_key_conflict") != std::string::npos);
        CHECK_FALSE(fx.dispatched_anything());
        CHECK(fx.idem_counts == std::map<std::string, int>{{"conflict", 1}});
    }
}

TEST_CASE("workflow execute: a KEYED zero-reach run is never retryable, whatever its cause, and says to "
          "use a new key; an UNKEYED run keeps the advice of its cause",
          "[workflow][twin][zeroreach][idempotency][retry]") {
    struct Row {
        const char* token;
        bool unkeyed_retryable;
        std::function<void(ConfinedDispatchOutcome&)> set;
    };
    const Row rows[] = {
        {"containment_unreadable", true, [](auto& o) { o.containment_unreadable = true; }},
        {"route_unreadable", true, [](auto& o) { o.route_unreadable = true; }},
        {"os_gate_unreadable", true, [](auto& o) { o.os_gate_unreadable = true; }},
        {"no_agents_reached", true, [](auto&) {}},
        {"quarantined", false, [](auto& o) { o.denied_quarantined_count = 2; }},
        {"plugin_not_found", false, [](auto& o) { o.unknown_plugin_count = 1; }},
        {"kill_switched_os", false, [](auto& o) { o.kill_switched_os_count = 1; }},
    };
    for (const auto& r : rows) {
        INFO(r.token);
        for (const bool keyed_run : {false, true}) {
            INFO(std::string(keyed_run ? "keyed" : "unkeyed"));
            Fx f;
            ConfinedDispatchOutcome out;
            out.command_id = "cmd-zero";
            r.set(out);
            f.outcomes["i-ro"] = out;
            const auto o = keyed_run ? f.run(keyed(f)) : f.run();
            REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
            CHECK(o.reason == r.token);
            REQUIRE(o.steps.size() == 1);
            if (keyed_run) {
                CHECK_FALSE(o.retryable);
                CHECK_FALSE(o.steps[0].retryable);
                CHECK(o.remediation == kKeyedRetryRemediation);
                CHECK(o.remediation.find("use a new idempotency key (MCP: a new approval)") !=
                      std::string::npos);
            } else {
                CHECK(o.retryable == r.unkeyed_retryable);
                CHECK(o.steps[0].retryable == r.unkeyed_retryable);
                CHECK(o.remediation.empty());
            }
        }
    }
}

TEST_CASE("workflow execute: a KEYED run that reached nobody because of the deadline or the engine "
          "carries the new-key remediation too",
          "[workflow][twin][zeroreach][idempotency][retry]") {
    SECTION("deadline_exceeded") {
        Fx f;
        f.engine_status = "failed";
        auto req = keyed(f);
        req.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        const auto o = f.run(req);
        REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(o.reason == "deadline_exceeded");
        CHECK_FALSE(o.retryable);
        CHECK(o.remediation == kKeyedRetryRemediation);
    }
    SECTION("run_failed") {
        Fx f;
        f.engine_status = "failed";
        auto a = f.api();
        auto p = f.ports(a);
        p.run = [&](const std::string&, const std::vector<std::string>&, StepDispatchFn,
                    ConditionEvalFn, const WorkflowRunControl& control)
            -> std::expected<std::string, std::string> {
            if (control.on_admitted)
                control.on_admitted("exec-1");
            return std::string{"exec-1"};
        };
        const auto o = apply_workflow_execute(p, keyed(f));
        REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(o.reason == "run_failed");
        CHECK_FALSE(o.retryable);
        CHECK(o.remediation == kKeyedRetryRemediation);
    }
    SECTION("a step refused at send time (late_denied)") {
        Fx f;
        f.late_defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
        const auto o = f.run(keyed(f));
        REQUIRE(o.status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(o.reason == "late_denied");
        CHECK_FALSE(o.retryable);
        CHECK(o.remediation == kKeyedRetryRemediation);
    }
}

TEST_CASE("workflow execute: the zero-reach status list is closed, matches what the code emits, and "
          "the never-sent claim is gone from the remediations",
          "[workflow][twin][zeroreach][docs]") {
    // Every cause the shared classifier names is a member of the list, except the one a workflow
    // cannot produce (it names its agents, so there is no scope to fail to parse).
    for (const auto cause : {ZeroReachCause::ContainmentUnreadable, ZeroReachCause::RouteUnreadable,
                             ZeroReachCause::OsGateUnreadable, ZeroReachCause::Quarantined,
                             ZeroReachCause::PluginNotFound, ZeroReachCause::KillSwitchedOs,
                             ZeroReachCause::Generic}) {
        const auto token = zero_reach_token(cause);
        INFO(token);
        CHECK(std::find(kWorkflowZeroReachStatuses.begin(), kWorkflowZeroReachStatuses.end(),
                        token) != kWorkflowZeroReachStatuses.end());
    }
    CHECK(std::find(kWorkflowZeroReachStatuses.begin(), kWorkflowZeroReachStatuses.end(),
                    zero_reach_token(ZeroReachCause::InvalidScope)) ==
          kWorkflowZeroReachStatuses.end());
    // The four non-cause members are exactly the reasons the sequence assigns itself.
    for (const char* own : {"late_denied", "definition_changed", "deadline_exceeded", "run_failed"})
        CHECK(std::count(kWorkflowZeroReachStatuses.begin(), kWorkflowZeroReachStatuses.end(),
                         std::string_view(own)) == 1);
    CHECK(kWorkflowZeroReachStatuses.size() == 11);

    // The three remediation texts that used to say a step with no command_id was never sent.
    CHECK(std::string(kStepNotProvenUnsentText).find("may still have been sent") !=
          std::string::npos);
    Fx f;
    f.bind("alice", kKey, "running", 900); // past the 180 s stale bound
    const auto replay = f.run(keyed(f));
    REQUIRE(replay.status == WorkflowExecuteStatus::kIdempotentReplay);
    CHECK(replay.replay_status == "indeterminate");
    CHECK(replay.remediation.find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
    CHECK(replay.remediation.find("never sent") == std::string::npos);

    Fx t;
    t.engine_throws_before_admit = false;
    t.dispatch_override = [](const WorkflowStepInstruction&, const std::vector<std::string>&,
                             const DispatchCaller&) -> ConfinedDispatchOutcome {
        throw std::runtime_error("boom");
    };
    const auto threw = t.run();
    REQUIRE(threw.status == WorkflowExecuteStatus::kRunFailed);
    CHECK(threw.remediation.find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
    CHECK(threw.remediation.find("never sent") == std::string::npos);
}

TEST_CASE("idempotency: the idempotent counter's outcome set is closed", "[workflow][twin][idempotency]") {
    REQUIRE(kWorkflowRunIdempotentOutcomes.size() == 4);
    CHECK(kWorkflowRunIdempotentOutcomes[0] == "replayed");
    CHECK(kWorkflowRunIdempotentOutcomes[1] == "in_progress");
    CHECK(kWorkflowRunIdempotentOutcomes[2] == "conflict");
    CHECK(kWorkflowRunIdempotentOutcomes[3] == "indeterminate");
    CHECK(kWorkflowRunIdempotentOutcomes[3] == kWorkflowRunIdempotentIndeterminate);
    CHECK(std::string(kWorkflowRunIdempotentMetric) == "yuzu_server_workflow_run_idempotent_total");
}

TEST_CASE("run outcome counter: the closed (outcome, reason) set is reachable-only, unique, and tied to "
          "the classifier's own tokens",
          "[workflow][twin][outcome][metrics]") {
    const auto& series = workflow_run_outcome_series();
    CHECK(std::string(kWorkflowRunOutcomeMetric) == "yuzu_server_workflow_run_outcome_total");
    // No pair twice, and every outcome token is one the classifier names.
    std::set<std::pair<std::string, std::string>> seen;
    std::set<std::string> outcomes;
    for (const auto& s : series) {
        INFO(s.outcome << "/" << s.reason);
        CHECK(seen.emplace(std::string(s.outcome), std::string(s.reason)).second);
        outcomes.emplace(std::string(s.outcome));
    }
    std::set<std::string> tokens;
    for (const auto o : {WorkflowRunOutcome::kSucceeded, WorkflowRunOutcome::kFailed,
                         WorkflowRunOutcome::kPartial, WorkflowRunOutcome::kInterrupted,
                         WorkflowRunOutcome::kAborted})
        tokens.emplace(std::string(workflow_run_outcome_token(o)));
    CHECK(outcomes == tokens);
    CHECK(series.size() == 25);
    // Each zero-reach cause the dispatch can note is a `failed` AND an `aborted` reason; `invalid_scope`
    // is not (a workflow names its agents).
    for (const auto cause : {ZeroReachCause::ContainmentUnreadable, ZeroReachCause::RouteUnreadable,
                             ZeroReachCause::OsGateUnreadable, ZeroReachCause::Quarantined,
                             ZeroReachCause::PluginNotFound, ZeroReachCause::KillSwitchedOs,
                             ZeroReachCause::Generic}) {
        const auto t = zero_reach_token(cause);
        INFO(t);
        CHECK(seen.count({"failed", std::string(t)}) == 1);
        CHECK(seen.count({"aborted", std::string(t)}) == 1);
    }
    CHECK(seen.count({"failed", std::string(zero_reach_token(ZeroReachCause::InvalidScope))}) == 0);
    // Every reason the zero-reach status list names for a run is in the vocabulary (the list is
    // the pinned contract of what a 503 / MCP status can say), so a cause added there without a
    // series fails here.
    std::set<std::string> reasons;
    for (const auto& s : series)
        reasons.emplace(std::string(s.reason));
    for (const auto r : kWorkflowZeroReachStatuses)
        CHECK(reasons.count(std::string(r)) == 1);
    for (const char* r : {"credential_revoked", "credential_indeterminate", "server_shutdown",
                          "dispatch_exception", "none"})
        CHECK(reasons.count(r) == 1);
}

TEST_CASE("run outcome counter: workflow_run_outcome_reason folds an unknown reason to none and never "
          "aliases the outcome",
          "[workflow][twin][outcome][metrics]") {
    WorkflowExecuteOutcome o;
    o.status = WorkflowExecuteStatus::kNoAgentsReached;
    o.run_outcome = WorkflowRunOutcome::kFailed;
    o.reason = "some_future_cause";
    CHECK(workflow_run_outcome_reason(o) == kWorkflowRunReasonNone);
    o.reason = "quarantined";
    CHECK(workflow_run_outcome_reason(o) == "quarantined");
    // The deadline, the stopping server and the credential check outrank a zero-reach cause, in
    // the order the closing audit row reads them.
    o.deadline_exceeded = true;
    CHECK(workflow_run_outcome_reason(o) == "deadline_exceeded");
    o.deadline_exceeded = false;
    o.interrupted = true;
    CHECK(workflow_run_outcome_reason(o) == "server_shutdown");
    o.interrupted = false;
    o.credential_stop = std::string(kReasonCredentialIndeterminate);
    CHECK(workflow_run_outcome_reason(o) == "credential_indeterminate");
    o.credential_stop = "something_else";
    CHECK(workflow_run_outcome_reason(o) == "quarantined");
}

TEST_CASE("run outcome counter: each classifier class is counted once with its reason, a replay counts "
          "nothing, a refusal counts nothing",
          "[workflow][twin][outcome][metrics]") {
    const auto only = [](const Fx& f) {
        REQUIRE(f.run_outcomes.size() == 1);
        return f.run_outcomes.front();
    };
    using Pair = std::pair<std::string, std::string>;
    SECTION("succeeded / none") {
        Fx f;
        CHECK(f.run(f.request()).status == WorkflowExecuteStatus::kOk);
        CHECK(only(f) == Pair{"succeeded", "none"});
    }
    SECTION("failed / the dominant zero-reach cause") {
        Fx f;
        ConfinedDispatchOutcome zero;
        zero.denied_quarantined_count = 1;
        f.outcomes["i-ro"] = zero;
        CHECK(f.run(f.request()).status == WorkflowExecuteStatus::kNoAgentsReached);
        CHECK(only(f) == Pair{"failed", "quarantined"});
    }
    SECTION("failed / run_failed: the engine ended the run before any dispatch") {
        Fx f;
        f.engine_status = "failed";
        auto a = f.api();
        auto p = f.ports(a);
        p.run = [&](const std::string&, const std::vector<std::string>&, StepDispatchFn,
                    ConditionEvalFn, const WorkflowRunControl& control)
            -> std::expected<std::string, std::string> {
            if (control.on_admitted)
                control.on_admitted("exec-1");
            return std::string{"exec-1"};
        };
        CHECK(apply_workflow_execute(p, f.request()).reason == "run_failed");
        CHECK(only(f) == Pair{"failed", "run_failed"});
    }
    SECTION("failed / dispatch_exception: the run threw after its requested row") {
        Fx f;
        f.dispatch_override = [](const WorkflowStepInstruction&, const std::vector<std::string>&,
                                 const DispatchCaller&) -> ConfinedDispatchOutcome {
            throw std::runtime_error("boom");
        };
        CHECK(f.run(f.request()).status == WorkflowExecuteStatus::kRunFailed);
        CHECK(only(f) == Pair{"failed", "dispatch_exception"});
        CHECK(f.run_threw_count == 1);
    }
    SECTION("aborted / late_denied and definition_changed, sent or not") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        CHECK(f.run(f.request()).run_outcome == WorkflowRunOutcome::kAborted);
        CHECK(only(f) == Pair{"aborted", "late_denied"});
        Fx g;
        g.step_ids = {"i-ro", "i-ro2"};
        g.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        g.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_uptime");
        auto req = g.request();
        req.expected_step_effects = WorkflowStepEffects{
            {"i-ro", workflow_step_effect(g.defs["i-ro"])},
            {"i-ro2", workflow_step_effect(g.defs["i-ro2"])}};
        CHECK(g.run(req).run_outcome == WorkflowRunOutcome::kAborted);
        CHECK(only(g) == Pair{"aborted", "definition_changed"});
    }
    SECTION("aborted / credential_revoked") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        f.wire_reauth = true;
        f.reauth_answers = {auth::CredentialCheck::kValid, auth::CredentialCheck::kRevoked};
        CHECK(f.run(f.request()).credential_stop == kReasonCredentialRevoked);
        CHECK(only(f) == Pair{"aborted", "credential_revoked"});
    }
    SECTION("aborted / deadline_exceeded") {
        Fx f;
        f.engine_status = "failed";
        auto req = f.request();
        req.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        CHECK(f.run(req).deadline_exceeded);
        CHECK(only(f) == Pair{"aborted", "deadline_exceeded"});
    }
    SECTION("interrupted / server_shutdown") {
        Fx f;
        f.engine_status = "failed";
        f.interrupt_before_step = 0;
        CHECK(f.run(f.request()).interrupted);
        CHECK(only(f) == Pair{"interrupted", "server_shutdown"});
    }
    SECTION("a replay and a refusal count no outcome; the replay moves the idempotent counter") {
        Fx f;
        f.bind("alice", kKey, "completed");
        CHECK(f.run(keyed(f)).status == WorkflowExecuteStatus::kIdempotentReplay);
        Fx r;
        r.defs.clear(); // an unknown instruction: refused at the preflight, nothing started
        CHECK(r.run(r.request()).status != WorkflowExecuteStatus::kOk);
        CHECK(f.run_outcomes.empty());
        CHECK(r.run_outcomes.empty());
        CHECK(f.idem_counts == std::map<std::string, int>{{"replayed", 1}});
    }
    SECTION("a counter that throws never changes the answer") {
        Fx f;
        auto a = f.api();
        auto p = f.ports(a);
        p.count_run_outcome = [](std::string_view, std::string_view) { throw std::runtime_error("x"); };
        CHECK(apply_workflow_execute(p, f.request()).status == WorkflowExecuteStatus::kOk);
    }
}

TEST_CASE("workflow run metrics: seeding creates every closed-set series at 0 and nothing outside the set",
          "[workflow][twin][outcome][metrics]") {
    yuzu::MetricsRegistry m;
    seed_workflow_run_metrics(m);
    const auto text = m.serialize();
    const auto has_zero = [&](const std::string& series) {
        return text.find(series + " 0\n") != std::string::npos;
    };
    const auto count_of = [&](const std::string& prefix) {
        std::size_t n = 0;
        for (std::size_t at = text.find(prefix); at != std::string::npos;
             at = text.find(prefix, at + 1))
            ++n;
        return n;
    };
    for (const auto reason : workflow_target_reject_reasons())
        CHECK(has_zero("yuzu_server_dispatch_target_rejected_total{route=\"workflow\",reason=\"" +
                       std::string(reason) + "\"}"));
    CHECK(count_of("yuzu_server_dispatch_target_rejected_total{") == 11);
    for (const auto reason : kWorkflowRunRefusedReasons)
        CHECK(has_zero(std::string(kWorkflowRunRefusedMetric) + "{reason=\"" + std::string(reason) +
                       "\"}"));
    for (const auto outcome : kWorkflowRunIdempotentOutcomes)
        CHECK(has_zero(std::string(kWorkflowRunIdempotentMetric) + "{outcome=\"" +
                       std::string(outcome) + "\"}"));
    CHECK(count_of(std::string(kWorkflowRunIdempotentMetric) + "{") == 4);
    for (const auto& series : workflow_run_outcome_series())
        CHECK(has_zero(std::string(kWorkflowRunOutcomeMetric) + "{outcome=\"" +
                       std::string(series.outcome) + "\",reason=\"" + std::string(series.reason) +
                       "\"}"));
    CHECK(count_of(std::string(kWorkflowRunOutcomeMetric) + "{") ==
          workflow_run_outcome_series().size());
    // Counting a seeded pair moves it and adds no series: the label set stays closed.
    make_workflow_run_outcome_counter(&m)("failed", "quarantined");
    CHECK(count_of(std::string(kWorkflowRunOutcomeMetric) + "{") ==
          workflow_run_outcome_series().size());
}

TEST_CASE("run outcome counter: the production counter writes the pre-seeded series, and the target "
          "reject reasons of route=workflow are a closed, de-duplicated set",
          "[workflow][twin][outcome][metrics]") {
    yuzu::MetricsRegistry m;
    const auto count = make_workflow_run_outcome_counter(&m);
    REQUIRE(count);
    count("aborted", "deadline_exceeded");
    count("aborted", "deadline_exceeded");
    CHECK(m.counter(kWorkflowRunOutcomeMetric,
                    {{"outcome", "aborted"}, {"reason", "deadline_exceeded"}})
              .value() == 2);
    CHECK_FALSE(make_workflow_run_outcome_counter(nullptr));

    const auto reasons = workflow_target_reject_reasons();
    CHECK(reasons.size() == 11);
    CHECK(std::set<std::string_view>(reasons.begin(), reasons.end()).size() == reasons.size());
    for (const auto r : {kReasonBodyType, kReasonScopeUnsupported, kReasonAgentIdsType,
                         kReasonAgentIdsEmpty, kReasonAgentIdType, kReasonDestructiveUntargeted,
                         kReasonForensicUntargeted, kReasonDestructiveNoVisibleTarget,
                         kReasonWorkflowAgentIdsRequired, kReasonWorkflowAgentIdsCount,
                         kReasonWorkflowAgentIdLen})
        CHECK(std::find(reasons.begin(), reasons.end(), r) != reasons.end());
    // `scope` is refused before the shape check can see it, so these three are unreachable here.
    for (const auto r : {kReasonScopeType, kReasonScopeEmpty, kReasonTargetConflict})
        CHECK(std::find(reasons.begin(), reasons.end(), r) == reasons.end());
}

// ── the REST route ───────────────────────────────────────────────────────────────────────────

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a repeat of a completed run is a "
          "202 with the thin body, sends nothing, and holds no lease",
          "[workflow][twin][rest][idempotency]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.bind("alice", kKey, "completed", 7);
    const auto res = post_with_key(r, kKey);
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->get_header_value("Retry-After").empty());
    const auto j = body_of(*res);
    CHECK(at_path(j, "/meta/api_version") == "v1");
    CHECK(at_path(j, "/data/execution_id") == "exec-bound");
    CHECK(at_path(j, "/data/status") == "completed");
    CHECK(at_path(j, "/data/idempotent_replay") == true);
    CHECK(at_path(j, "/data/started_at") == r.fx.fixed_now - 7);
    CHECK_FALSE(at_path(j, "/data").contains("steps"));
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
    CHECK(r.fx.authorize_calls.empty());
    CHECK(r.budget.active() == 0);
    CHECK(r.metrics.counter(kWorkflowRunIdempotentMetric, {{"outcome", "replayed"}}).value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a repeat is answered while the "
          "server DRAINS and when the run cap is FULL, with the refusal counters unmoved",
          "[workflow][twin][rest][idempotency][drain][cap]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.bind("alice", kKey, "completed");
    r.draining = true;
    std::vector<detail::StreamBudget::Lease> held;
    for (std::size_t i = 0; i < detail::kPerPrincipalWorkflowRun; ++i) {
        auto a = r.budget.try_acquire(detail::SseSurface::kWorkflowRun, "alice",
                                      detail::kPerPrincipalWorkflowRun);
        REQUIRE(a.lease);
        held.push_back(std::move(a.lease));
    }
    const auto res = post_with_key(r, kKey);
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(body_of(*res)["data"]["idempotent_replay"] == true);
    CHECK(r.refused("draining") == 0);
    CHECK(r.refused("per_principal_stream_cap") == 0);
    CHECK(r.refused("global_stream_cap") == 0);
    CHECK(r.budget.active() == held.size()); // the replay took no lease of its own
    // A NEW key is still refused at the same moment: only a replay bypasses admission.
    const auto fresh = post_with_key(r, "another-key-0001");
    REQUIRE(fresh);
    CHECK(fresh->status == 503);
    CHECK(r.refused("draining") == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a run still running is a 202 with "
          "retry_after_ms 2000 and Retry-After 2, and writes NO audit row",
          "[workflow][twin][rest][idempotency]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.bind("alice", kKey, "running", 4);
    const auto res = post_with_key(r, kKey);
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->get_header_value("Retry-After") == "2");
    const auto j = body_of(*res);
    CHECK(at_path(j, "/data/status") == "running");
    CHECK(at_path(j, "/data/retry_after_ms") == 2000);
    CHECK(at_path(j, "/data/idempotent_replay") == true);
    CHECK(r.persist_calls == 0);
    CHECK(r.metrics.counter(kWorkflowRunIdempotentMetric, {{"outcome", "in_progress"}}).value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: failed and indeterminate replays "
          "are 202s that say retryable false and give no retry hint",
          "[workflow][twin][rest][idempotency]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.bind("alice", "key-failed-0001", "failed", 30);
    r.fx.bind("alice", "key-stale-00001", "running", 900);
    const auto failed = post_with_key(r, "key-failed-0001");
    REQUIRE(failed);
    CHECK(failed->status == 202);
    CHECK(body_of(*failed)["data"]["status"] == "failed");
    CHECK(body_of(*failed)["data"]["retryable"] == false);
    CHECK(failed->get_header_value("Retry-After").empty());
    const auto stale = post_with_key(r, "key-stale-00001");
    REQUIRE(stale);
    CHECK(stale->status == 202);
    const auto j = body_of(*stale);
    CHECK(at_path(j, "/data/status") == "indeterminate");
    CHECK(at_path(j, "/data/retryable") == false);
    CHECK_FALSE(at_path(j, "/data").contains("retry_after_ms"));
    CHECK(stale->get_header_value("Retry-After").empty());
    CHECK(at_path(j, "/data/remediation").get<std::string>().find("new key") != std::string::npos);
    CHECK(at_path(j, "/data/remediation").get<std::string>().find(std::string(kStepNotProvenUnsentText)) !=
          std::string::npos);
    CHECK(at_path(j, "/data/remediation").get<std::string>().find("may still be live") !=
          std::string::npos);
    // `failed` is not "nothing was sent": its wire body says the record cannot prove it.
    CHECK(at_path(body_of(*failed), "/data/remediation")
              .get<std::string>()
              .find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a repeat of a partial, aborted or "
          "interrupted run puts the may-still-have-been-sent caution on the wire body",
          "[workflow][twin][rest][idempotency][parity]") {
    const auto dispatched = [](const Rest& r) {
        return std::count_if(r.fx.events.begin(), r.fx.events.end(),
                             [](const auto& e) { return e.starts_with("dispatch:"); });
    };
    const auto replay_body = [&](Rest& r) {
        const auto first = post_with_key(r, kKey);
        REQUIRE(first);
        const auto sent_before = dispatched(r);
        const auto again = post_with_key(r, kKey);
        REQUIRE(again);
        CHECK(again->status == 202);
        CHECK(dispatched(r) == sent_before); // a replay sends nothing
        return body_of(*again);
    };
    const auto expect_caution = [](const json& j, const char* status) {
        INFO(status);
        CHECK(at_path(j, "/data/status") == status);
        CHECK(at_path(j, "/data/retryable") == false);
        const auto remediation = at_path(j, "/data/remediation").get<std::string>();
        CHECK(remediation.find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
        CHECK(remediation.find("new idempotency key") != std::string::npos);
    };
    SECTION("partial: the engine ended failed although every attempted step reached") {
        Rest r;
        r.fx.engine_status = "failed";
        expect_caution(replay_body(r), "partial");
    }
    SECTION("aborted: a step was refused at send time") {
        Rest r;
        r.fx.step_ids = {"i-ro", "i-ro2"};
        r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        r.fx.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        expect_caution(replay_body(r), "aborted");
    }
    SECTION("interrupted: the server stopped the run after step 1") {
        Rest r;
        r.fx.step_ids = {"i-ro", "i-ro2"};
        r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        r.fx.engine_status = "failed";
        r.fx.interrupt_before_step = 1;
        expect_caution(replay_body(r), "interrupted");
    }
    SECTION("completed: no remediation") {
        Rest r;
        const auto j = replay_body(r);
        CHECK(at_path(j, "/data/status") == "completed");
        CHECK_FALSE(at_path(j, "/data").contains("remediation"));
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: a zero-reach 503 after the key is bound is not retryable "
          "and says to use a new key; the same 503 without a key keeps its cause's retry hint",
          "[workflow][twin][rest][zeroreach][idempotency][retry]") {
    struct Row {
        const char* token;
        bool unkeyed_hint; // retry_after_ms 5000 on an unkeyed run
        ConfinedDispatchOutcome out;
    };
    ConfinedDispatchOutcome generic;
    generic.command_id = "cmd-zero";
    ConfinedDispatchOutcome contained = generic;
    contained.containment_unreadable = true;
    ConfinedDispatchOutcome quarantined = generic;
    quarantined.denied_quarantined_count = 3;
    const Row rows[] = {{"no_agents_reached", true, generic},
                        {"containment_unreadable", true, contained},
                        {"quarantined", false, quarantined}};
    for (const auto& row : rows) {
        INFO(row.token);
        {
            Rest r; // UNKEYED
            r.dispatch_result = row.out;
            const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
            REQUIRE(res);
            CHECK(res->status == 503);
            const auto j = body_of(*res);
            CHECK(at_path(j, "/error/reason") == row.token);
            if (row.unkeyed_hint)
                CHECK(at_path(j, "/error/retry_after_ms") == 5000);
            else
                CHECK(at_path(j, "/error/retry_after_ms").is_null());
            CHECK((!at_path(j, "/error").contains("remediation") ||
                   at_path(j, "/error/remediation").is_null()));
        }
        {
            Rest r; // KEYED
            r.dispatch_result = row.out;
            const auto res = post_with_key(r, kKey);
            REQUIRE(res);
            CHECK(res->status == 503);
            const auto j = body_of(*res);
            CHECK(at_path(j, "/error/reason") == row.token);
            CHECK(at_path(j, "/error/retry_after_ms").is_null());
            CHECK(res->get_header_value("Retry-After").empty());
            CHECK(at_path(j, "/error/remediation").get<std::string>().find(
                      "use a new idempotency key (MCP: a new approval)") != std::string::npos);
            CHECK(at_path(j, "/error/execution_id") == "exec-1");
        }
    }
}

TEST_CASE("openapi_spec_json(): the workflow execute operation lists every zero-reach reason, states "
          "the keyed rule and no longer claims an absent command_id proves a step unsent",
          "[workflow][twin][openapi][zeroreach][docs]") {
    const json spec = json::parse(yuzu::server::openapi_spec_json());
    const auto& op = spec.at("paths").at("/workflows/{id}/execute").at("post");
    const auto desc = op.at("description").get<std::string>();
    for (const auto token : kWorkflowZeroReachStatuses) {
        if (token == "definition_changed")
            continue; // MCP only: REST carries no ticket-bound effects to move off of
        INFO(token);
        CHECK(desc.find(std::string(token)) != std::string::npos);
    }
    CHECK(desc.find("WITH an Idempotency-Key the key is already bound") != std::string::npos);
    CHECK(desc.find("retry_after_ms null, no Retry-After") != std::string::npos);
    CHECK(desc.find("a step recorded pending or skipped may still have been sent") !=
          std::string::npos);
    CHECK(desc.find("was never sent") == std::string::npos);
    const auto r503 = op.at("responses").at("503").at("description").get<std::string>();
    CHECK(r503.find("run_failed and deadline_exceeded") != std::string::npos);
    CHECK(r503.find("with an Idempotency-Key never retryable") != std::string::npos);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: the same key with a different "
          "request is a terminal 422 idempotency_key_conflict naming the bound run",
          "[workflow][twin][rest][idempotency][security]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.bind("alice", kKey, "completed", 1, "wf-1", {"a1"});
    const auto res = post_with_key(r, kKey, R"({"agent_ids":["a1","a2"]})");
    REQUIRE(res);
    CHECK(res->status == 422);
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "idempotency_key_conflict");
    CHECK(at_path(j, "/error/execution_id") == "exec-bound");
    CHECK((!at_path(j, "/error").contains("retry_after_ms") || at_path(j, "/error/retry_after_ms").is_null()));
    CHECK_FALSE(r.fx.engine_called);
    CHECK(r.metrics.counter(kWorkflowRunIdempotentMetric, {{"outcome", "conflict"}}).value() == 1);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a first call runs, then the "
          "identical call replays it",
          "[workflow][twin][rest][idempotency]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    const auto first = post_with_key(r, kKey);
    REQUIRE(first);
    CHECK(first->status == 202);
    CHECK(body_of(*first)["data"]["status"] == "completed");
    CHECK(body_of(*first)["data"]["steps"].size() == 1);
    CHECK_FALSE(body_of(*first)["data"].contains("idempotent_replay"));
    const auto sent = std::count_if(r.fx.events.begin(), r.fx.events.end(),
                                    [](const std::string& e) { return e.starts_with("dispatch:"); });
    const auto second = post_with_key(r, kKey);
    REQUIRE(second);
    CHECK(second->status == 202);
    CHECK(body_of(*second)["data"]["idempotent_replay"] == true);
    CHECK(body_of(*second)["data"]["execution_id"] == body_of(*first)["data"]["execution_id"]);
    CHECK(std::count_if(r.fx.events.begin(), r.fx.events.end(),
                        [](const std::string& e) { return e.starts_with("dispatch:"); }) == sent);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a malformed or doubled key is a "
          "400 idempotency_key_invalid before anything is read or leased; no key is unchanged",
          "[workflow][twin][rest][idempotency]") {
    Rest r;
    for (const auto& bad : {std::string("short"), std::string(129, 'k'), std::string("bad key 12345"),
                            std::string("key/with/slash"), std::string()}) {
        INFO(bad);
        const auto res = post_with_key(r, bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body_of(*res)["error"]["reason"] == "idempotency_key_invalid");
    }
    r.sink.repeated_headers = {{"Idempotency-Key", "key-aaaaaaaaaa"}, {"Idempotency-Key", "key-bbbbbbbbbb"}};
    const auto dup = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(dup);
    CHECK(dup->status == 400);
    CHECK(body_of(*dup)["error"]["reason"] == "idempotency_key_invalid");
    r.sink.repeated_headers.clear();
    CHECK_FALSE(r.fx.engine_called);
    CHECK(r.fx.find_calls == 0);
    CHECK(r.budget.active() == 0);
    // Six refusals, six `denied` rows (the pre-core audit) and nothing else.
    CHECK(r.fx.events == std::vector<std::string>(6, "audit:denied"));
    CHECK(r.fx.audit_details.front().find("reason=idempotency_key_invalid") != std::string::npos);
    const auto keyless = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(keyless);
    CHECK(keyless->status == 202);
    CHECK(r.fx.find_calls == 0);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a failed lookup is a retryable 503 "
          "with nothing written, sent or leased",
          "[workflow][twin][rest][idempotency][failclosed]") {
    Rest r;
    r.fx.find_fault = true;
    const auto res = post_with_key(r, kKey);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    CHECK_FALSE(r.fx.engine_called);
    CHECK(r.fx.events.empty());
    CHECK(r.persist_calls == 0);
    CHECK(r.budget.active() == 0);
}

TEST_CASE("POST /api/v1/workflows/{id}/execute with Idempotency-Key: a lost claim race is a 202 replay "
          "or a 422, never a second send",
          "[workflow][twin][rest][idempotency][race]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    r.fx.before_claim = [&](const WorkflowIdempotencyClaim& c) {
        r.fx.bound[{c.principal, c.key}] = WorkflowIdempotentRun{
            "exec-winner", "wf-1", c.fingerprint, "running", r.fx.fixed_now};
    };
    const auto res = post_with_key(r, kKey);
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(body_of(*res)["data"]["execution_id"] == "exec-winner");
    CHECK(body_of(*res)["data"]["status"] == "running");
    CHECK(res->get_header_value("Retry-After") == "2");
    CHECK_FALSE(r.fx.dispatched_anything());
    CHECK(r.budget.active() == 0);
    // The loser started nothing: it counts the idempotent answer, never a run outcome.
    CHECK(r.metrics.counter(kWorkflowRunIdempotentMetric, {{"outcome", "in_progress"}}).value() == 1);
    CHECK(r.metrics.serialize().find(kWorkflowRunOutcomeMetric) == std::string::npos);
}

// ── REPLAY PARITY (#2146 hp2-1, hp2-2): the replay says what the first answer said ──────────────
//
// For each way a run can end: run it under a key, then repeat the call with the same key, and the
// replay's status must be the first answer's class, `completed` ONLY for a run that succeeded. The
// stand-in engine persists the step rows a real engine would (Fx::stored_rows), so the replay
// judges stored data, never the engine's coarse status word. The real engine's own rows are
// checked by the [pg] twin of this matrix in test_workflow_engine.cpp.

namespace {

/// The first answer's class as a token: the label every transport and the closing audit row carry.
std::string first_answer_class(const WorkflowExecuteOutcome& o) {
    if (o.status == WorkflowExecuteStatus::kRunFailed)
        return std::string(workflow_run_outcome_token(WorkflowRunOutcome::kFailed));
    return std::string(workflow_run_outcome_token(o.run_outcome));
}

struct ParityRun {
    WorkflowExecuteOutcome first;
    WorkflowExecuteOutcome replay;
    std::string first_class;
    long dispatches_after_first{0};
    long dispatches_after_replay{0};
    std::vector<std::pair<std::string, std::string>> outcomes_after_first;
    std::vector<std::pair<std::string, std::string>> outcomes_after_replay;
    std::map<std::string, int> idem_after_replay;
};

long dispatch_count(const Fx& f) {
    return std::count_if(f.events.begin(), f.events.end(),
                         [](const auto& e) { return e.starts_with("dispatch:"); });
}

/// Run `req` (keyed) on `f`, then repeat it. A run that throws is caught: its first answer is
/// `kRunFailed`, which `run_workflow_execute` returns rather than throws.
ParityRun run_then_replay(Fx& f, WorkflowExecuteRequest req) {
    req.idempotency_key = kKey;
    ParityRun p;
    p.first = f.run(req);
    p.first_class = first_answer_class(p.first);
    p.dispatches_after_first = dispatch_count(f);
    p.outcomes_after_first = f.run_outcomes;
    p.replay = f.run(req);
    p.dispatches_after_replay = dispatch_count(f);
    p.outcomes_after_replay = f.run_outcomes;
    p.idem_after_replay = f.idem_counts;
    return p;
}

void expect_parity(const ParityRun& p, std::string_view expected_class,
                   std::string_view expected_reason) {
    INFO("first answer class " << p.first_class);
    CHECK(p.first_class == expected_class);
    // The first answer counts the run ONCE, as its class, with the reason the classifier gives,
    // and that pair is in the pre-seeded closed set; the replay counts nothing.
    REQUIRE(p.outcomes_after_first.size() == 1);
    CHECK(p.outcomes_after_first.front().first == expected_class);
    CHECK(p.outcomes_after_first.front().second == expected_reason);
    const auto& series = workflow_run_outcome_series();
    CHECK(std::find(series.begin(), series.end(),
                    WorkflowRunOutcomeSeries{p.outcomes_after_first.front().first,
                                             p.outcomes_after_first.front().second}) != series.end());
    CHECK(p.outcomes_after_replay == p.outcomes_after_first);
    // The replay moves the idempotent counter instead: `replayed` for a run the rows prove.
    CHECK(p.idem_after_replay == std::map<std::string, int>{{"replayed", 1}});
    REQUIRE(p.replay.status == WorkflowExecuteStatus::kIdempotentReplay);
    // The replay is the first answer's class, and `completed` is its word for `succeeded` alone.
    const std::string want = expected_class == "succeeded" ? "completed" : std::string(expected_class);
    CHECK(p.replay.replay_status == want);
    CHECK((p.replay.replay_status == "completed") == (p.first_class == "succeeded"));
    CHECK(p.dispatches_after_replay == p.dispatches_after_first); // a replay sends nothing
    const auto j = workflow_idempotent_replay_json(p.replay, "wf-1");
    CHECK(j.at("status") == want);
    CHECK(j.at("idempotent_replay") == true);
    if (want != "completed") {
        REQUIRE(j.contains("retryable"));
        CHECK(j.at("retryable") == false);
        // The wire body of every non-completed class says a step the record shows unsent may have
        // been sent, and that a re-run needs a new key.
        REQUIRE(j.contains("remediation"));
        const auto remediation = j.at("remediation").get<std::string>();
        CHECK(remediation.find(std::string(kStepNotProvenUnsentText)) != std::string::npos);
        CHECK(remediation.find("new idempotency key") != std::string::npos);
        CHECK(remediation.find("get_workflow_execution") != std::string::npos);
    } else {
        CHECK_FALSE(j.contains("remediation"));
    }
}

} // namespace

TEST_CASE("replay parity: a succeeded run replays `completed`, and nothing else does",
          "[workflow][twin][idempotency][outcome][parity]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    const auto p = run_then_replay(f, f.request());
    CHECK(p.first.status == WorkflowExecuteStatus::kOk);
    expect_parity(p, "succeeded", "none");
}

TEST_CASE("replay parity: an onFailure:continue step that reached nobody leaves the engine `completed`, "
          "the first answer partial, and the replay partial (hp2-1)",
          "[workflow][twin][idempotency][outcome][parity]") {
    SECTION("an earlier step reached, the later one did not") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        ConfinedDispatchOutcome zero;
        zero.denied_quarantined_count = 1;
        f.outcomes["i-ro2"] = zero;
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.run_status == "completed"); // the engine's word, which the replay must not echo
        CHECK(p.replay.run_status == "completed");
        expect_parity(p, "partial", "none");
    }
    SECTION("the FIRST step reached nobody and a later one did") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        ConfinedDispatchOutcome zero;
        zero.denied_quarantined_count = 1;
        f.outcomes["i-ro"] = zero;
        expect_parity(run_then_replay(f, f.request()), "partial", "none");
    }
    SECTION("no step reached anyone: failed on both") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        ConfinedDispatchOutcome zero;
        zero.denied_quarantined_count = 1;
        f.outcomes["i-ro"] = zero;
        f.outcomes["i-ro2"] = zero;
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.status == WorkflowExecuteStatus::kNoAgentsReached);
        expect_parity(p, "failed", "quarantined");
    }
    SECTION("two steps naming the SAME instruction: the failed one is not hidden by the one that reached") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro"};
        int calls = 0;
        f.dispatch_override = [&](const WorkflowStepInstruction& d, const std::vector<std::string>&,
                                  const DispatchCaller&) {
            ConfinedDispatchOutcome out;
            out.command_id = "cmd-" + d.id;
            if (++calls == 1)
                out.denied_quarantined_count = 1; // step 0 reaches nobody
            else
                out.sent = 1; // step 1 reaches an agent
            return out;
        };
        const auto p = run_then_replay(f, f.request());
        REQUIRE(p.first.steps.size() == 2);
        CHECK(p.first.steps[0].step_index == 0);
        CHECK(p.first.steps[1].step_index == 1);
        expect_parity(p, "partial", "none");
    }
}

TEST_CASE("replay parity: a step retried to success is `completed` with run_outcome succeeded on BOTH "
          "answers, and its steps entries number the attempts (hp2-2)",
          "[workflow][twin][idempotency][outcome][parity][attempt]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    f.engine_retries = 1;
    int calls_for_first_step = 0;
    f.dispatch_override = [&](const WorkflowStepInstruction& d, const std::vector<std::string>&,
                              const DispatchCaller&) {
        ConfinedDispatchOutcome out;
        out.command_id = "cmd-" + d.id;
        if (d.id == "i-ro" && ++calls_for_first_step == 1)
            out.denied_quarantined_count = 1; // attempt 1 reaches nobody
        else
            out.sent = 1;
        return out;
    };
    const auto p = run_then_replay(f, f.request());
    CHECK(p.first.status == WorkflowExecuteStatus::kOk);
    CHECK(p.first.run_outcome == WorkflowRunOutcome::kSucceeded);
    CHECK(f.audit_details[1].find("run_outcome") == std::string::npos); // the closing row is a success
    REQUIRE(p.first.steps.size() == 3);
    CHECK(p.first.steps[0].attempt == 1);
    CHECK(p.first.steps[0].agents_reached == 0);
    CHECK(p.first.steps[1].attempt == 2);
    CHECK(p.first.steps[1].agents_reached == 1);
    CHECK(p.first.steps[2].attempt == 1); // the next step starts again at 1
    const auto j = workflow_execute_result_json(p.first, "wf-1");
    CHECK(j.at("status") == "completed");
    REQUIRE(j.at("steps").size() == 3);
    CHECK(j.at("steps").at(0).at("attempt") == 1);
    CHECK(j.at("steps").at(1).at("attempt") == 2);
    CHECK_FALSE(j.contains("retryable"));
    expect_parity(p, "succeeded", "none");

    SECTION("still failing on the last attempt is not rescued by an earlier or later note") {
        Fx g;
        g.engine_retries = 1;
        ConfinedDispatchOutcome zero;
        zero.denied_quarantined_count = 1;
        g.outcomes["i-ro"] = zero;
        const auto q = run_then_replay(g, g.request());
        CHECK(q.first.steps.size() == 2);
        expect_parity(q, "failed", "quarantined");
    }
}

TEST_CASE("replay parity: a step refused at send time (late_denied, definition_changed) is aborted on "
          "both answers",
          "[workflow][twin][idempotency][outcome][parity][late]") {
    SECTION("late_denied: the approval mode was raised after the preflight") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.late_denied);
        expect_parity(p, "aborted", "late_denied");
    }
    SECTION("late_denied as the FIRST step, with the engine's run closed failed") {
        Fx f;
        f.engine_status = "failed";
        f.late_defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.late_denied);
        expect_parity(p, "aborted", "late_denied");
    }
    SECTION("definition_changed: the step moved off the effect the ticket was bound to") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_uptime");
        auto req = f.request();
        req.expected_step_effects = WorkflowStepEffects{
            {"i-ro", workflow_step_effect(f.defs["i-ro"])},
            {"i-ro2", workflow_step_effect(f.defs["i-ro2"])}};
        const auto p = run_then_replay(f, req);
        CHECK(p.first.late_denied);
        expect_parity(p, "aborted", "definition_changed");
    }
}

TEST_CASE("replay parity: a run the server's shutdown ended is interrupted on both answers, sent or not",
          "[workflow][twin][idempotency][outcome][parity][shutdown]") {
    SECTION("after step 1 was sent") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        f.interrupt_before_step = 1;
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.interrupted);
        expect_parity(p, "interrupted", "server_shutdown");
    }
    SECTION("before anything was sent") {
        Fx f;
        f.engine_status = "failed";
        f.interrupt_before_step = 0;
        const auto p = run_then_replay(f, f.request());
        CHECK_FALSE(f.dispatched_anything());
        expect_parity(p, "interrupted", "server_shutdown");
    }
}

TEST_CASE("replay parity: a run the credential check or the deadline stopped is aborted on both answers",
          "[workflow][twin][idempotency][outcome][parity][credential][deadline]") {
    SECTION("the credential was revoked before step 2") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        f.wire_reauth = true;
        f.reauth_answers = {auth::CredentialCheck::kValid, auth::CredentialCheck::kRevoked};
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.credential_stop == kReasonCredentialRevoked);
        expect_parity(p, "aborted", "credential_revoked");
    }
    SECTION("the credential could not be confirmed before the first step: nothing was sent") {
        Fx f;
        f.engine_status = "failed";
        f.wire_reauth = true;
        f.reauth_after = auth::CredentialCheck::kIndeterminate;
        const auto p = run_then_replay(f, f.request());
        CHECK_FALSE(f.dispatched_anything());
        CHECK(p.first.credential_stop == kReasonCredentialIndeterminate);
        expect_parity(p, "aborted", "credential_indeterminate");
    }
    SECTION("the deadline passed between step 1 and step 2") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        auto req = f.request();
        req.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
        const auto deadline = *req.deadline;
        f.dispatch_override = [deadline](const WorkflowStepInstruction& d,
                                         const std::vector<std::string>&, const DispatchCaller&) {
            std::this_thread::sleep_until(deadline + std::chrono::milliseconds(5));
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-" + d.id};
        };
        const auto p = run_then_replay(f, req);
        CHECK(p.first.deadline_exceeded);
        expect_parity(p, "aborted", "deadline_exceeded");
    }
    SECTION("the deadline had passed before the first attempt: nothing was sent") {
        Fx f;
        f.engine_status = "failed";
        auto req = f.request();
        req.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        const auto p = run_then_replay(f, req);
        CHECK_FALSE(f.dispatched_anything());
        CHECK(p.first.deadline_exceeded);
        expect_parity(p, "aborted", "deadline_exceeded");
    }
}

TEST_CASE("replay parity: a run whose dispatch threw is failed on both answers, and the engine ending "
          "failed after every step reached is partial on both",
          "[workflow][twin][idempotency][outcome][parity][throw]") {
    SECTION("a dispatch that threw after step 1 was sent") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        f.dispatch_override = [](const WorkflowStepInstruction& d, const std::vector<std::string>&,
                                 const DispatchCaller&) -> ConfinedDispatchOutcome {
            if (d.id == "i-ro2")
                throw std::runtime_error("registry exploded mid fan-out");
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-" + d.id};
        };
        const auto p = run_then_replay(f, f.request());
        CHECK(p.first.status == WorkflowExecuteStatus::kRunFailed);
        // Step 1's send was real: the replay still calls the run failed, as the first answer did,
        // and never completed.
        expect_parity(p, "failed", "dispatch_exception");
    }
    SECTION("the engine ended failed although every attempted step reached an agent") {
        Fx f;
        f.engine_status = "failed";
        expect_parity(run_then_replay(f, f.request()), "partial", "none");
    }
}

TEST_CASE("replay parity: rows that cannot prove an outcome are never `completed`",
          "[workflow][twin][idempotency][outcome][parity]") {
    const auto settled = [](int index, const char* status, const char* result) {
        WorkflowStepResult r;
        r.step_index = index;
        r.instruction_id = "i-ro";
        r.status = status;
        r.result_json = result;
        return r;
    };
    const char* ack = R"j({"status":"dispatched","command_id":"c","agents_reached":1})j";
    struct Row {
        const char* name;
        const char* engine_status;
        std::vector<WorkflowStepResult> rows;
        bool unreadable;
        const char* expect;
    };
    const Row rows[] = {
        {"completed, every step success", "completed", {settled(0, "success", ack)}, false, "completed"},
        {"completed, the only other step skipped by its condition",
         "completed",
         {settled(0, "success", ack), settled(1, "skipped", R"j({"reason":"condition not met"})j")},
         false,
         "completed"},
        {"completed, a step still pending (its write was dropped)",
         "completed",
         {settled(0, "success", ack), settled(1, "pending", "{}")},
         false,
         "indeterminate"},
        {"completed, a step still running", "completed", {settled(0, "running", "{}")}, false,
         "indeterminate"},
        {"completed, a step skipped for a reason a completed run cannot hold",
         "completed",
         {settled(0, "success", ack), settled(1, "skipped", R"j({"reason":"workflow aborted"})j")},
         false,
         "indeterminate"},
        {"completed, a step in a status this build does not know",
         "completed",
         {settled(0, "success", ack), settled(1, "mystery", "{}")},
         false,
         "indeterminate"},
        {"completed, no step rows at all", "completed", {}, false, "indeterminate"},
        {"completed, rows unreadable", "completed", {}, true, "indeterminate"},
        {"failed, rows unreadable", "failed", {}, true, "failed"},
        {"cancelled, rows unreadable", "cancelled", {}, true, "failed"},
        {"failed, no step rows at all", "failed", {}, false, "failed"},
        {"failed, a step reached and the rest were skipped",
         "failed",
         {settled(0, "success", ack), settled(1, "skipped", R"j({"reason":"workflow aborted"})j")},
         false,
         "partial"},
        {"failed, a failed step with a garbled result",
         "failed",
         {settled(0, "failed", "not json at all")},
         false,
         "failed"},
        {"failed, a failed step whose result is an array of non-objects",
         "failed",
         {settled(0, "failed", "[1,2,3]")},
         false,
         "failed"},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        Fx f;
        f.bind("alice", kKey, row.engine_status);
        f.stored_rows["exec-bound"] = row.rows;
        f.get_exec_fault = row.unreadable;
        const auto out = f.run(keyed(f));
        REQUIRE(out.status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(out.replay_status == row.expect);
        CHECK_FALSE(f.dispatched_anything());
        // Only an unprovable run lands on `indeterminate`; every other terminal answer is `replayed`.
        CHECK(f.idem_counts ==
              (std::string_view(row.expect) == "indeterminate"
                   ? std::map<std::string, int>{{"indeterminate", 1}}
                   : std::map<std::string, int>{{"replayed", 1}}));
        CHECK(f.run_outcomes.empty());
    }
    SECTION("the two reads of the run disagree on its terminal status: the rows are not believed") {
        Fx f;
        f.bind("alice", kKey, "completed");
        f.stored_status["exec-bound"] = "failed"; // the read-back says failed; the key lookup said completed
        f.stored_rows["exec-bound"] = {settled(0, "success", ack)};
        CHECK(f.run(keyed(f)).replay_status == "indeterminate");
        Fx g;
        g.bind("alice", kKey, "failed");
        g.stored_status["exec-bound"] = "completed";
        g.stored_rows["exec-bound"] = {settled(0, "success", ack)};
        CHECK(g.run(keyed(g)).replay_status == "failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// The audit join (#2146 comp2-1 / ca2-2 / ca2-3): every `workflow.execute` row carries the call's
// correlation id, the run's own row names the actor and the call even when it is unkeyed, a REST
// refusal before the sequence still leaves a `denied` row, and an unwired sink fails closed.
// ═══════════════════════════════════════════════════════════════════════════════════════════

namespace {

/// Every audit row `r` received carries the response's correlation id, right after the surface.
void check_rows_carry_cid(const Rest& r, const httplib::Response& res, std::size_t expected_rows) {
    const std::string cid = res.get_header_value("X-Correlation-Id");
    REQUIRE_FALSE(cid.empty());
    REQUIRE(r.fx.audit_details.size() == expected_rows);
    for (const auto& d : r.fx.audit_details) {
        INFO(d);
        CHECK(d.starts_with("surface=rest correlation_id=" + cid));
    }
    for (const auto& a : r.audit_actions)
        CHECK(a == "workflow.execute");
}

} // namespace

TEST_CASE("workflow.execute audit join: REST success, partial and aborted runs stamp the correlation id "
          "on every row",
          "[workflow][twin][rest][audit][correlation]") {
    SECTION("success: requested then success") {
        Rest r;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 202);
        check_rows_carry_cid(r, *res, 2);
        CHECK(r.audit_results == std::vector<std::string>{"requested", "success"});
    }
    SECTION("aborted by a send-time refusal: requested, denied (late), failure") {
        Rest r;
        r.fx.step_ids = {"i-ro", "i-ro2"};
        r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        r.fx.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        check_rows_carry_cid(r, *res, 3);
        CHECK(r.audit_results == std::vector<std::string>{"requested", "denied", "failure"});
    }
    SECTION("a run that throws: requested then the failure row") {
        Rest r;
        r.dispatch_throws = true;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 500);
        check_rows_carry_cid(r, *res, 2);
        CHECK(r.audit_results == std::vector<std::string>{"requested", "failure"});
    }
    SECTION("a refusal inside the sequence (the caller may not run a step): the denied row") {
        Rest r;
        r.fx.defs["i-ro"] = def("i-ro", "os_info", "os_version", "always");
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK(res->status == 403);
        REQUIRE_FALSE(r.fx.audit_details.empty());
        check_rows_carry_cid(r, *res, r.fx.audit_details.size());
    }
}

TEST_CASE("workflow.execute audit join: REST idempotent replay and conflict rows carry the correlation id "
          "of the REPEAT, not of the run they answer with",
          "[workflow][twin][rest][audit][correlation][idempotency]") {
    Rest r;
    r.fx.fixed_now = real_epoch_now();
    const auto first = post_with_key(r, kKey);
    REQUIRE(first);
    const std::string first_cid = first->get_header_value("X-Correlation-Id");
    const std::size_t after_first = r.fx.audit_details.size();
    const auto second = post_with_key(r, kKey);
    REQUIRE(second);
    CHECK(body_of(*second)["data"]["idempotent_replay"] == true);
    const std::string second_cid = second->get_header_value("X-Correlation-Id");
    REQUIRE_FALSE(second_cid.empty());
    CHECK(second_cid != first_cid);
    REQUIRE(r.fx.audit_details.size() == after_first + 1);
    CHECK(r.fx.audit_details.back().starts_with("surface=rest correlation_id=" + second_cid));
    CHECK(r.fx.audit_details.back().find("idempotent_replay=true") != std::string::npos);

    const auto conflict = post_with_key(r, kKey, R"({"agent_ids":["a1","a2"]})");
    REQUIRE(conflict);
    CHECK(conflict->status == 422);
    CHECK(r.audit_results.back() == "denied");
    CHECK(r.fx.audit_details.back().starts_with(
        "surface=rest correlation_id=" + conflict->get_header_value("X-Correlation-Id")));
    CHECK(r.fx.audit_details.back().find("reason=idempotency_key_conflict") != std::string::npos);
}

TEST_CASE("workflow.execute audit join: a REST refusal BEFORE the sequence leaves a denied row with the "
          "correlation id, the reason and no read, lease or send",
          "[workflow][twin][rest][audit][correlation][security]") {
    struct Case {
        const char* name;
        std::string body;
        std::unordered_map<std::string, std::string> headers;
        std::string reason;
    };
    const std::string deep = std::string(200, '[') + std::string(200, ']');
    const std::vector<Case> cases = {
        {"a bad Idempotency-Key", R"({"agent_ids":["a1"]})", {{"Idempotency-Key", "short"}},
         "idempotency_key_invalid"},
        {"a body that nests too deeply", deep, {}, "body_depth"},
        {"a body that is not JSON", "{not json", {}, "invalid_json"},
        {"a body of the wrong shape", R"({})", {}, "agent_ids_required"},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        Rest r;
        const auto res = r.sink.dispatch("POST", "/api/v1/workflows/wf-1/execute", c.body,
                                         "application/json", c.headers);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body_of(*res)["error"]["reason"] == c.reason);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        check_rows_carry_cid(r, *res, 1);
        CHECK(r.audit_results.front() == "denied");
        CHECK(r.fx.audit_details.front().find("reason=" + c.reason) != std::string::npos);
        CHECK(r.audit_targets.front() == "wf-1");
        CHECK(r.fx.get_workflow_calls == 0);
        CHECK_FALSE(r.fx.engine_called);
        CHECK_FALSE(r.fx.dispatched_anything());
        CHECK(r.budget.active() == 0);
    }
    SECTION("a lost pre-core row adds Sec-Audit-Failed and the 400 stands") {
        Rest r;
        r.fx.audit_ok = false;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", "{not json");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("workflow.execute audit join: an UNWIRED audit sink is a 503 audit_unavailable with nothing "
          "read, leased, dispatched or run",
          "[workflow][twin][rest][audit][failclosed][security]") {
    Rest r(/*wire_audit=*/false);
    const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    const auto j = body_of(*res);
    CHECK(at_path(j, "/error/reason") == "audit_unavailable");
    CHECK(at_path(j, "/error/retry_after_ms").is_null());
    CHECK(at_path(j, "/error/correlation_id") == res->get_header_value("X-Correlation-Id"));
    CHECK(r.gate_calls == 1); // behind the surface gate
    CHECK(r.fx.get_workflow_calls == 0);
    CHECK(r.fx.find_calls == 0);
    CHECK_FALSE(r.fx.engine_called);
    CHECK_FALSE(r.fx.dispatched_anything());
    CHECK(r.budget.active() == 0);
    CHECK(r.fx.events.empty());
    SECTION("an unauthorised caller learns nothing about the configuration") {
        Rest denied(/*wire_audit=*/false);
        denied.gate_admits = false;
        const auto d = denied.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(d);
        CHECK(d->status == 403);
    }
    SECTION("a malformed id is still the audit defect first, never a silent 400 with no row") {
        Rest bad(/*wire_audit=*/false);
        const auto b = bad.sink.Post("/api/v1/workflows/" + std::string(200, 'x') + "/execute",
                                     R"({"agent_ids":["a1"]})");
        REQUIRE(b);
        CHECK(b->status == 503);
    }
}

TEST_CASE("workflow.execute audit join: the run port is handed the actor and the call id on an UNKEYED "
          "run as well as a keyed one",
          "[workflow][twin][rest][audit][correlation]") {
    SECTION("REST, unkeyed") {
        Rest r;
        const auto res = r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
        REQUIRE(res);
        CHECK_FALSE(r.fx.seen_claim.has_value());
        CHECK(r.fx.seen_control_principal == "alice");
        CHECK(r.fx.seen_control_cid == res->get_header_value("X-Correlation-Id"));
        CHECK_FALSE(r.fx.seen_control_cid.empty());
    }
    SECTION("REST, keyed") {
        Rest r;
        const auto res = post_with_key(r, kKey);
        REQUIRE(res);
        REQUIRE(r.fx.seen_claim.has_value());
        CHECK(r.fx.seen_claim->principal == "alice");
        CHECK(r.fx.seen_control_principal == "alice");
        CHECK(r.fx.seen_control_cid == res->get_header_value("X-Correlation-Id"));
    }
    SECTION("the sequence, with a correlation id and approval id on the request") {
        Fx f;
        auto req = f.request();
        req.correlation_id = "cid-123";
        req.approval_id = "appr-9";
        const auto out = f.run(req);
        CHECK(out.status == WorkflowExecuteStatus::kOk);
        CHECK(f.seen_control_cid == "cid-123");
        REQUIRE_FALSE(f.audit_details.empty());
        for (const auto& d : f.audit_details) {
            INFO(d);
            CHECK(d.starts_with("surface=test correlation_id=cid-123 approval_id=appr-9"));
        }
    }
    SECTION("a hostile approval id is cleaned and bounded in every row") {
        Fx f;
        auto req = f.request();
        req.correlation_id = "cid-1";
        req.approval_id = "a b=c\nforged=1" + std::string(500, 'z');
        (void)f.run(req);
        for (const auto& d : f.audit_details) {
            CHECK(d.find('\n') == std::string::npos);
            CHECK(d.find("forged=1") == std::string::npos);
            CHECK(d.size() < 400);
        }
    }
}

TEST_CASE("workflow.execute audit join: workflow_audit_target keeps a normal id byte-identical and "
          "never emits a raw malformed one",
          "[workflow][twin][audit][security]") {
    CHECK(workflow_audit_target("wf-1") == "wf-1");
    CHECK(workflow_audit_target("caf\xc3\xa9") == "caf\xc3\xa9");
    const auto cleaned = workflow_audit_target(std::string("a\0b\nc\x1b[0m\x7f\xff", 11));
    for (const char ch : cleaned) {
        CHECK(static_cast<unsigned char>(ch) >= 0x20);
        CHECK(static_cast<unsigned char>(ch) != 0x7F);
    }
    CHECK(workflow_audit_target(std::string(4096, 'x')).size() <= 131);
    CHECK_FALSE(audit_workflow_pre_core_denial({}, "surface=rest", "cid", "r", "wf-1"));
    CHECK_FALSE(audit_workflow_pre_core_denial(
        [](const std::string&, const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("sink exploded");
        },
        "surface=rest", "cid", "r", "wf-1"));
}

// ───────────────────────────── workflow.executed (the legacy route's event) ───────────────────

TEST_CASE("workflow execute: a run the engine admitted publishes workflow.executed once, with the "
          "legacy null shape, AFTER the closing audit row, whatever its outcome",
          "[workflow][twin][events]") {
    const auto expect_one = [](const Fx& f) {
        REQUIRE(f.emitted.size() == 1);
        CHECK(f.emitted[0].type == "workflow.executed");
        CHECK(f.emitted[0].attrs.is_null());
        CHECK(f.emitted[0].payload.is_null());
        // Every row of the call (requested, any late denial, the closing one) existed when it was
        // published, and the closing row is the last.
        CHECK(f.emitted[0].audit_rows_at == f.audit_details.size());
        CHECK(f.audit_details.size() >= 2);
        CHECK(f.events.front() == "audit:requested");
    };
    SECTION("completed") {
        Fx f;
        CHECK(f.run().status == WorkflowExecuteStatus::kOk);
        expect_one(f);
    }
    SECTION("partial: the engine ended failed after a send") {
        Fx f;
        f.engine_status = "failed";
        CHECK(f.run().status == WorkflowExecuteStatus::kRunIncomplete);
        expect_one(f);
    }
    SECTION("aborted: a step refused at send time after step 1 was sent") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        const auto o = f.run();
        CHECK(o.run_outcome == WorkflowRunOutcome::kAborted);
        expect_one(f);
    }
    SECTION("interrupted by a server stop") {
        Fx f;
        f.step_ids = {"i-ro", "i-ro2"};
        f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        f.engine_status = "failed";
        f.interrupt_before_step = 1;
        CHECK(f.run().run_outcome == WorkflowRunOutcome::kInterrupted);
        expect_one(f);
    }
    SECTION("a run in which no step reached any agent is still a run the engine admitted") {
        Fx f;
        f.outcomes["i-ro"] = ConfinedDispatchOutcome{.sent = 0, .command_id = "cmd-0"};
        CHECK(f.run().status == WorkflowExecuteStatus::kNoAgentsReached);
        expect_one(f);
    }
    SECTION("a lost closing audit row does not suppress it") {
        Fx f;
        f.audit_fails_on_call = 1;
        const auto o = f.run();
        CHECK_FALSE(o.audit_persisted);
        REQUIRE(f.emitted.size() == 1);
    }
}

TEST_CASE("workflow execute: a refusal, a replay, an engine refusal and a run that threw publish "
          "no workflow.executed",
          "[workflow][twin][events]") {
    SECTION("an unknown workflow") {
        Fx f;
        f.step_ids.clear();
        CHECK(f.run(f.request()).status != WorkflowExecuteStatus::kOk);
        CHECK(f.emitted.empty());
    }
    SECTION("a step whose approval mode does not admit the caller") {
        Fx f;
        f.defs["i-ro"].approval_mode = "always";
        CHECK(f.run().status == WorkflowExecuteStatus::kApprovalRequired);
        CHECK(f.emitted.empty());
    }
    SECTION("an unwired dependency") {
        Fx f;
        f.approval_gate = false;
        CHECK(f.run().status == WorkflowExecuteStatus::kUnavailable);
        CHECK(f.emitted.empty());
    }
    SECTION("the requested row could not be saved") {
        Fx f;
        f.audit_ok = false;
        CHECK(f.run().status == WorkflowExecuteStatus::kAuditFailed);
        CHECK(f.emitted.empty());
    }
    SECTION("the engine refused the run") {
        Fx f;
        f.engine_error = std::unexpected(std::string{"rejected by the engine"});
        CHECK(f.run().status == WorkflowExecuteStatus::kExecuteFailed);
        CHECK(f.emitted.empty());
    }
    SECTION("an idempotent replay found by the pre-check") {
        Fx f;
        f.bind("alice", kKey, "completed");
        CHECK(f.run(keyed(f)).status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(f.emitted.empty());
    }
    SECTION("a conflict") {
        Fx f;
        f.bind("alice", kKey, "completed", 1, "wf-1", {"a1"});
        CHECK(f.run(keyed(f, {"a1", "a2"})).status == WorkflowExecuteStatus::kIdempotencyConflict);
        CHECK(f.emitted.empty());
    }
    SECTION("a call that lost the engine's claim") {
        Fx f;
        f.before_claim = [&](const WorkflowIdempotencyClaim& c) {
            f.bound[{c.principal, c.key}] = WorkflowIdempotentRun{
                "exec-winner", "wf-1", c.fingerprint, "running", f.fixed_now};
        };
        CHECK(f.run(keyed(f)).status == WorkflowExecuteStatus::kIdempotentReplay);
        CHECK(f.emitted.empty());
    }
    SECTION("a run that threw after the requested row (the legacy handler publishes nothing then)") {
        Fx f;
        f.dispatch_override = [](const WorkflowStepInstruction&, const std::vector<std::string>&,
                                 const DispatchCaller&) -> ConfinedDispatchOutcome {
            throw std::runtime_error("registry exploded mid fan-out");
        };
        CHECK(f.run().status == WorkflowExecuteStatus::kRunFailed);
        CHECK(f.emitted.empty());
    }
}

TEST_CASE("workflow execute: an emitter that throws, or none at all, never changes the outcome",
          "[workflow][twin][events]") {
    SECTION("a throwing hook") {
        Fx f;
        f.emit_throws = true;
        const auto o = f.run();
        CHECK(o.status == WorkflowExecuteStatus::kOk);
        CHECK(o.audit_persisted);
        CHECK(f.emitted.size() == 1);
        CHECK(f.events.back() == "audit:success");
    }
    SECTION("no hook wired") {
        Fx f;
        f.wire_emit = false;
        CHECK(f.run().status == WorkflowExecuteStatus::kOk);
        CHECK(f.emitted.empty());
    }
}

TEST_CASE("POST /api/v1/workflows/{id}/execute: publishes workflow.executed once for an admitted "
          "run of any outcome and none for a refusal or a replay; a throwing emitter changes nothing",
          "[workflow][twin][rest][events]") {
    const auto post = [](Rest& r) {
        return r.sink.Post("/api/v1/workflows/wf-1/execute", R"({"agent_ids":["a1"]})");
    };
    SECTION("completed") {
        Rest r;
        const auto res = post(r);
        REQUIRE(res);
        CHECK(res->status == 202);
        REQUIRE(r.emitted.size() == 1);
        CHECK(r.emitted[0] == "workflow.executed");
        CHECK(r.emitted_attrs[0].is_null());
        CHECK(r.emitted_payloads[0].is_null());
    }
    SECTION("partial") {
        Rest r;
        r.fx.engine_status = "failed";
        const auto res = post(r);
        REQUIRE(res);
        CHECK(body_of(*res)["data"]["status"] == "partial");
        CHECK(r.emitted == std::vector<std::string>{"workflow.executed"});
    }
    SECTION("aborted") {
        Rest r;
        r.fx.step_ids = {"i-ro", "i-ro2"};
        r.fx.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
        r.fx.late_defs["i-ro2"] = def("i-ro2", "os_info", "os_version", "always");
        const auto res = post(r);
        REQUIRE(res);
        CHECK(body_of(*res)["data"]["status"] == "aborted");
        CHECK(r.emitted == std::vector<std::string>{"workflow.executed"});
    }
    SECTION("a run in which nothing reached an agent (503 with the cause)") {
        Rest r;
        r.dispatch_result = ConfinedDispatchOutcome{.sent = 0, .command_id = "cmd-0"};
        const auto res = post(r);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(r.emitted == std::vector<std::string>{"workflow.executed"});
    }
    SECTION("a refused call (unknown workflow, a malformed body, a denied gate)") {
        Rest r;
        r.fx.step_ids.clear();
        CHECK(post(r)->status != 202);
        CHECK(r.sink.Post("/api/v1/workflows/wf-1/execute", "not json")->status == 400);
        r.gate_admits = false;
        CHECK(post(r)->status == 403);
        CHECK(r.emitted.empty());
    }
    SECTION("a cap or draining refusal") {
        Rest r;
        r.draining = true;
        CHECK(post(r)->status == 503);
        CHECK(r.emitted.empty());
    }
    SECTION("a run that threw after the requested row") {
        Rest r;
        r.dispatch_throws = true;
        const auto res = post(r);
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(r.emitted.empty());
    }
    SECTION("a replay and a conflict") {
        Rest r;
        const auto first = post_with_key(r, kKey);
        REQUIRE(first);
        CHECK(first->status == 202);
        REQUIRE(r.emitted.size() == 1);
        const auto replay = post_with_key(r, kKey);
        REQUIRE(replay);
        CHECK(body_of(*replay)["data"]["idempotent_replay"] == true);
        const auto conflict = post_with_key(r, kKey, R"({"agent_ids":["a1","a2"]})");
        REQUIRE(conflict);
        CHECK(conflict->status == 422);
        CHECK(r.emitted.size() == 1); // still only the first call's event
    }
    SECTION("a throwing emitter leaves the 202 and the audit evidence as they were") {
        Rest r;
        r.emit_throws = true;
        const auto res = post(r);
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        CHECK(body_of(*res)["data"]["status"] == "completed");
        CHECK(r.emitted.size() == 1);
        CHECK(r.metrics.counter(kEventEmitFailedMetric, {{"event_type", "workflow.executed"}})
                  .value() == 1);
    }
}

TEST_CASE("kEmittedEvents names workflow.executed once, so its failure counter has its own series",
          "[workflow][twin][events]") {
    CHECK(std::count(kEmittedEvents.begin(), kEmittedEvents.end(), "workflow.executed") == 1);
    CHECK(kEmittedEvents.back() == "other");
}
