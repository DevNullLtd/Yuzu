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
#include "dispatch_target_shape.hpp"
#include "dispatch_zero_reach.hpp"
#include "mcp_policy.hpp"
#include "test_route_sink.hpp"
#include "test_workflow_api_double.hpp"
#include "workflow_execute.hpp"
#include "workflow_execute_routes.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
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

    // Wiring switches.
    bool store_open{true};
    bool approval_gate{true};
    bool wire_api{true};
    bool wire_run{true};
    bool audit_ok{true};
    std::optional<size_t> audit_fails_on_call; // 0-based index of the audit call that fails

    // What happened, in order. "audit:<result>", "dispatch:<instr>", "engine_returned".
    std::vector<std::string> events;
    std::vector<std::string> audit_details;
    std::vector<std::string> counted_rejections;
    std::vector<DispatchCaller> dispatched_callers;
    std::vector<std::vector<std::string>> dispatched_ids;

    // What the dispatch port answers for an instruction (default: reached one agent).
    std::map<std::string, ConfinedDispatchOutcome> outcomes;
    // Replace the dispatch port entirely (the send-set cases).
    std::function<ConfinedDispatchOutcome(const WorkflowStepInstruction&,
                                          const std::vector<std::string>&, const DispatchCaller&)>
        dispatch_override;

    std::string engine_status{"completed"};
    std::expected<std::string, std::string> engine_error{std::string{"exec-1"}};
    bool engine_called{false};

    WorkflowExecuteRequest request(std::vector<std::string> ids = {"a1"}) {
        WorkflowExecuteRequest r;
        r.workflow_id = "wf-1";
        r.agent_ids = std::move(ids);
        r.caller = DispatchCaller{.principal = "alice",
                                  .principal_role = "user",
                                  .exec_visible = std::nullopt,
                                  .principal_is_admin = false};
        r.audit_context = "surface=test";
        return r;
    }

    std::shared_ptr<test::FnWorkflowApi> api() {
        auto get = [this](const std::string& id) -> std::expected<std::optional<Workflow>, std::string> {
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
                w.steps.push_back(s);
            }
            return std::optional<Workflow>{w};
        };
        auto get_exec = [this](const std::string& id)
            -> std::expected<std::optional<WorkflowExecution>, std::string> {
            WorkflowExecution e;
            e.id = id;
            e.workflow_id = "wf-1";
            e.status = engine_status;
            return std::optional<WorkflowExecution>{e};
        };
        return std::make_shared<test::FnWorkflowApi>(test::FnWorkflowApi::ListFn{}, get, get_exec);
    }

    /// The stand-in for the engine behind the run port: it drives the steps in order,
    /// synchronously, one callback per step; a failed step does not stop the loop here
    /// (on_failure=continue semantics).
    WorkflowRunFn run_fn() {
        return [this](const std::string&, const std::vector<std::string>&, StepDispatchFn fn,
                      ConditionEvalFn, const WorkflowRunControl&)
                   -> std::expected<std::string, std::string> {
            engine_called = true;
            if (!engine_error)
                return engine_error;
            for (const auto& sid : step_ids)
                (void)fn(sid, "[]", "{}");
            events.push_back("engine_returned");
            return engine_error;
        };
    }

    WorkflowExecutePorts ports(const std::shared_ptr<test::FnWorkflowApi>& a) {
        WorkflowExecutePorts p;
        p.api = wire_api ? a.get() : nullptr;
        p.run = wire_run ? run_fn() : WorkflowRunFn{};
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

TEST_CASE("workflow execute: a missing classifier, dispatcher or audit sink also refuses before any effect",
          "[workflow][twin][security][failclosed]") {
    for (int which = 0; which < 3; ++which) {
        Fx f;
        auto a = f.api();
        auto p = f.ports(a);
        if (which == 0)
            p.classify = nullptr;
        if (which == 1)
            p.dispatch = nullptr;
        if (which == 2)
            p.audit = nullptr;
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
        const auto o = f.run(f.request({"a1", "a2"}));
        CHECK(o.status == WorkflowExecuteStatus::kDestructiveUntargeted);
        CHECK(o.reason == std::string(kReasonForensicUntargeted));
        CHECK(f.counted_rejections == std::vector<std::string>{std::string(kReasonForensicUntargeted)});
        CHECK_FALSE(f.dispatched_anything());
    }
    {
        Fx f;
        f.defs["i-ro"] = def("i-ro", "execution_artifacts", "shimcache");
        CHECK(f.run(f.request({"a1"})).status == WorkflowExecuteStatus::kOk);
    }
}

TEST_CASE("workflow execute: a Destructive step whose named agents are ALL outside the caller's view is "
          "refused as destructive_no_visible_target",
          "[workflow][twin][security][targeting]") {
    {
        Fx f;
        f.defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1", "a2"});
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
        req.caller.exec_visible = authz::VisibleSet{std::unordered_set<std::string>{"a2"}};
        CHECK(f.run(req).status == WorkflowExecuteStatus::kOk);
    }
    { // A present-EMPTY visible set (deny-all) is "none visible", never "unfiltered".
        Fx f;
        f.defs["i-ro"] = def("i-ro", "filesystem", "delete_lines");
        auto req = f.request({"a1"});
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

TEST_CASE("workflow execute: a run where SOME step reached an agent is a success with the zero step "
          "named, not a failure",
          "[workflow][twin][zeroreach]") {
    Fx f;
    f.step_ids = {"i-ro", "i-ro2"};
    f.defs["i-ro2"] = def("i-ro2", "os_info", "os_version");
    ConfinedDispatchOutcome zero;
    zero.denied_quarantined_count = 1;
    f.outcomes["i-ro2"] = zero;
    const auto o = f.run();
    CHECK(o.status == WorkflowExecuteStatus::kOk);
    REQUIRE(o.steps.size() == 2);
    CHECK(o.steps[0].agents_reached == 1);
    CHECK(o.steps[1].reason == "quarantined");
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
    int gate_calls{0};
    int persist_calls{0};
    DispatchCaller caller{.principal = "alice",
                          .principal_role = "user",
                          .exec_visible = std::nullopt,
                          .principal_is_admin = false};
    DispatchCaller seen_caller;
    bool saw_caller{false};
    std::shared_ptr<test::FnWorkflowApi> api;
    yuzu::MetricsRegistry metrics;
    yuzu::server::test::TestRouteSink sink;

    Rest() {
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
        d.persist_audit_fn = [this](const httplib::Request&, const std::string&,
                                    const std::string& result, const std::string&,
                                    const std::string&, const std::string& detail) {
            ++persist_calls;
            fx.events.push_back("audit:" + result);
            fx.audit_details.push_back(detail);
            return fx.audit_ok;
        };
        d.workflow_api = api;
        d.workflow_run = fx.run_fn();
        d.instruction_store_open = [this] { return fx.store_open; };
        d.approval_gate_available = [this] { return fx.approval_gate; };
        auto ports = fx.ports(api);
        d.lookup = ports.lookup;
        d.classify = ports.classify;
        d.command_dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                       const std::vector<std::string>& ids, const std::string&,
                                       const std::unordered_map<std::string, std::string>&,
                                       const std::string&, const DispatchCaller& c) {
            fx.events.push_back("dispatch:" + plugin + "." + action);
            fx.dispatched_ids.push_back(ids);
            seen_caller = c;
            saw_caller = true;
            return ConfinedDispatchOutcome{.sent = 1, .command_id = "cmd-rest"};
        };
        d.caller_fn = [this](const httplib::Request&) { return caller; };
        d.metrics = &metrics;
        register_workflow_execute_v1_route(sink, std::move(d));
    }
};

json body_of(const httplib::Response& r) { return json::parse(r.body); }

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
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(j["data"]["execution_id"] == "exec-1");
    CHECK(j["data"]["workflow_id"] == "wf-1");
    CHECK(j["data"]["status"] == "completed");
    CHECK(j["data"]["late_denied"] == false);
    REQUIRE(j["data"]["steps"].size() == 1);
    CHECK(j["data"]["steps"][0]["agents_reached"] == 1);
    CHECK(j["data"]["steps"][0]["command_id"] == "cmd-rest");
    CHECK_FALSE(j["data"].contains("audit_persisted"));
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
    // requested first, closing row last.
    CHECK(r.fx.events.front() == "audit:requested");
    CHECK(r.fx.events.back() == "audit:success");
    // The route handed the shared sequence the CALLER's own DispatchCaller.
    REQUIRE(r.saw_caller);
    CHECK(r.seen_caller.principal == "alice");
    CHECK(r.seen_caller.approval_provenance == ApprovalProvenance::None);
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
        CHECK(j["error"]["reason"] ==
              (which == 0 ? "approval_gate_unavailable" : "instruction_store_unavailable"));
        CHECK(j["error"]["retry_after_ms"].is_null()); // a missing dependency is not transient
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
        CHECK(r.persist_calls == 0);
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
    d.instruction_store_open = [] { return true; };
    d.approval_gate_available = [] { return true; };
    auto ports = r.fx.ports(r.api);
    d.lookup = ports.lookup;
    d.classify = ports.classify;
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
    CHECK(j["error"]["reason"] == "quarantined");
    CHECK(j["error"]["retry_after_ms"].is_null()); // permanent: retrying will not help
    CHECK(j["error"]["execution_id"] == "exec-1");
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
    d.instruction_store_open = [] { return true; };
    d.approval_gate_available = [] { return true; };
    auto ports = r.fx.ports(r.api);
    d.lookup = ports.lookup;
    d.classify = ports.classify;
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
