/**
 * test_execution_cancel_rerun_twins.cpp - #2146 batch B: the shared admit -> audit -> effect ->
 * audit sequence (execution_mutation.hpp) behind POST /api/v1/executions/{id}/cancel and
 * .../rerun, and the two REST v1 routes themselves.
 *
 * NO POSTGRES. `ExecutionMutationPorts` is the seam: the sequence and both routes run against a
 * fake store, so every case below runs in every environment instead of skipping without a DSN.
 * The ports bound to a real `ExecutionTracker` (`make_tracker_mutation_ports`) are a thin
 * adapter over `get_execution_checked` / `get_agent_statuses_checked` / `mark_cancelled_checked`
 * / `create_rerun_checked`; the adapter itself is tested against a real tracker (PG, plus an
 * unreachable-pool "closed" tracker) in test_execution_tracker.cpp.
 *
 * The MCP twins (cancel_execution, record_execution_rerun) are exercised in test_mcp_server.cpp,
 * where the McpTestServer fixture lives; they use the same fake ports.
 */

#include "execution_mutation.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <regex>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

using namespace yuzu::server;

namespace {

using Outcome = ExecutionTracker::MarkCancelledOutcome;

struct AuditRow {
    std::string action, result, target, detail;
    bool operator==(const AuditRow&) const = default;
};

/// A fake execution store plus a recorder of everything the sequence did, in order.
struct FakeStore {
    std::optional<Execution> exec;             // nullopt = no such execution
    std::vector<AgentExecStatus> statuses;     // the COMPLETE cohort rows
    bool degrade_exec{false};
    bool degrade_statuses{false};
    /// 0 = the effect returns normally, 1 = it throws std::runtime_error, 2 = it throws a
    /// non-std type. The effect call is counted BEFORE it throws.
    int effect_throws{0};
    Outcome cancel_outcome{Outcome::kCancelled};
    std::expected<std::string, ExecutionTracker::RerunError> rerun_result{std::string("rerun-new-1")};

    int exec_reads{0}, status_reads{0}, cancel_calls{0}, rerun_calls{0};
    std::string effect_user;
    bool effect_failed_only{false};
    std::vector<std::string> events; // "read", "effect:cancel", "effect:rerun", "audit:<result>"

    void throw_if_armed() const {
        if (effect_throws == 1)
            throw std::runtime_error("effect blew up: PQerror secret internals");
        if (effect_throws == 2)
            throw 42; // NOLINT: a non-std throw is the point
    }

    ExecutionMutationPorts ports() {
        ExecutionMutationPorts p;
        p.get_execution = [this](const std::string&)
            -> std::expected<std::optional<Execution>, std::string> {
            ++exec_reads;
            events.emplace_back("read");
            if (degrade_exec)
                return std::unexpected("degraded");
            return exec;
        };
        p.get_statuses = [this](const std::string&) -> std::optional<std::vector<AgentExecStatus>> {
            ++status_reads;
            events.emplace_back("read");
            if (degrade_statuses)
                return std::nullopt;
            return statuses;
        };
        p.mark_cancelled = [this](const std::string&, const std::string& user) {
            ++cancel_calls;
            effect_user = user;
            events.emplace_back("effect:cancel");
            throw_if_armed();
            return cancel_outcome;
        };
        p.create_rerun = [this](const std::string&, const std::string& user, bool failed_only)
            -> std::expected<std::string, ExecutionTracker::RerunError> {
            ++rerun_calls;
            effect_user = user;
            effect_failed_only = failed_only;
            events.emplace_back("effect:rerun");
            throw_if_armed();
            return rerun_result;
        };
        return p;
    }
    int effects() const { return cancel_calls + rerun_calls; }
};

Execution make_exec(const std::string& by, int targeted) {
    Execution e;
    e.id = "exec-1";
    e.dispatched_by = by;
    e.agents_targeted = targeted;
    e.status = "running";
    return e;
}

AgentExecStatus st(const std::string& agent) {
    AgentExecStatus a;
    a.agent_id = agent;
    a.status = "running";
    return a;
}

/// Audit recorder wired into the sequence. `fail_result` makes rows with that result report
/// "not persisted"; `throw_result` makes them throw.
struct AuditRecorder {
    FakeStore* store{nullptr};
    std::vector<AuditRow> rows;
    std::string fail_result, throw_result;

    ExecutionMutationAuditFn fn() {
        return [this](const std::string& action, const std::string& result,
                      const std::string& target, const std::string& detail) {
            rows.push_back({action, result, target, detail});
            if (store)
                store->events.push_back("audit:" + result);
            if (!throw_result.empty() && result == throw_result)
                throw std::runtime_error("audit sink blew up");
            return result != fail_result;
        };
    }
};

ExecutionMutationRequest req(ExecutionMutation what, const std::string& user,
                             authz::VisibleSet scope = std::nullopt) {
    ExecutionMutationRequest r;
    r.what = what;
    r.execution_id = "exec-1";
    r.username = user;
    r.scope = std::move(scope);
    r.audit_context = "surface=test";
    return r;
}

authz::VisibleSet scope_of(std::initializer_list<const char*> agents) {
    std::unordered_set<std::string> s;
    for (auto* a : agents)
        s.emplace(a);
    return authz::VisibleSet{std::move(s)};
}

using S = ExecutionMutationStatus;

} // namespace

// ── the sequence ────────────────────────────────────────────────────────────

TEST_CASE("execution mutation: unconfined cancel writes attempted BEFORE the effect, then success",
          "[execution][mutation][2146]") {
    FakeStore fs;
    fs.exec = make_exec("alice", 1);
    AuditRecorder audit{&fs};
    const auto out = apply_execution_mutation(fs.ports(), req(ExecutionMutation::kCancel, "bob"),
                                              audit.fn());
    CHECK(out.status == S::kDone);
    CHECK(out.audit_persisted);
    REQUIRE(audit.rows.size() == 2);
    CHECK(audit.rows[0].action == "execution.cancel");
    CHECK(audit.rows[0].result == "attempted");
    CHECK(audit.rows[1].result == "success");
    CHECK(fs.effect_user == "bob");
    // The order is the contract: the evidence precedes the effect.
    const auto attempted = std::ranges::find(fs.events, "audit:attempted");
    const auto effect = std::ranges::find(fs.events, "effect:cancel");
    REQUIRE(attempted != fs.events.end());
    REQUIRE(effect != fs.events.end());
    CHECK(attempted < effect);
}

TEST_CASE("execution mutation: an empty principal is refused with no read, no audit, no effect",
          "[execution][mutation][security][2146]") {
    for (const auto what : {ExecutionMutation::kCancel, ExecutionMutation::kRerun}) {
        for (const bool confined : {false, true}) {
            FakeStore fs;
            fs.exec = make_exec("", 1); // an empty dispatched_by must not match an empty user
            AuditRecorder audit{&fs};
            const auto out = apply_execution_mutation(
                fs.ports(), req(what, "", confined ? scope_of({"a"}) : std::nullopt), audit.fn());
            CHECK(out.status == S::kNoPrincipal);
            CHECK(fs.exec_reads == 0);
            CHECK(fs.status_reads == 0);
            CHECK(fs.effects() == 0);
            CHECK(audit.rows.empty());
        }
    }
}

TEST_CASE("execution mutation: the attempted row not persisting means NO effect (both mutations)",
          "[execution][mutation][security][2146]") {
    for (const auto what : {ExecutionMutation::kCancel, ExecutionMutation::kRerun}) {
        for (const bool throws : {false, true}) {
            FakeStore fs;
            fs.exec = make_exec("alice", 1);
            AuditRecorder audit{&fs};
            (throws ? audit.throw_result : audit.fail_result) = "attempted";
            const auto out = apply_execution_mutation(fs.ports(), req(what, "bob"), audit.fn());
            CHECK(out.status == S::kAuditFailed);
            CHECK(fs.effects() == 0);
        }
    }
}

TEST_CASE("execution mutation: an outcome row that fails AFTER the effect is reported, not undone",
          "[execution][mutation][2146]") {
    FakeStore fs;
    fs.exec = make_exec("alice", 1);
    AuditRecorder audit{&fs};
    audit.fail_result = "success";
    const auto out = apply_execution_mutation(fs.ports(), req(ExecutionMutation::kCancel, "bob"),
                                              audit.fn());
    CHECK(out.status == S::kDone);
    CHECK_FALSE(out.audit_persisted);
    CHECK(fs.cancel_calls == 1);
}

TEST_CASE("execution mutation: confined admission needs COMPLETE cohort visibility",
          "[execution][mutation][confinement][security][2146]") {
    SECTION("full cohort visible is admitted") {
        FakeStore fs;
        fs.exec = make_exec("alice", 2);
        fs.statuses = {st("a"), st("b")};
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a", "b", "c"})),
            audit.fn());
        CHECK(out.status == S::kDone);
        CHECK(fs.cancel_calls == 1);
    }
    SECTION("one targeted agent outside the scope denies") {
        FakeStore fs;
        fs.exec = make_exec("alice", 2);
        fs.statuses = {st("a"), st("hidden")};
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a"})), audit.fn());
        CHECK(out.status == S::kNotFound);
        CHECK(fs.effects() == 0);
        REQUIRE(audit.rows.size() == 1);
        CHECK(audit.rows[0].result == "denied");
    }
    SECTION("an incomplete cohort (fewer rows than agents_targeted) denies even if all visible") {
        FakeStore fs;
        fs.exec = make_exec("alice", 3);
        fs.statuses = {st("a"), st("b")};
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kRerun, "bob", scope_of({"a", "b"})), audit.fn());
        CHECK(out.status == S::kNotFound);
        CHECK(fs.effects() == 0);
    }
    SECTION("the dispatcher alone is admitted before any agent has reported") {
        FakeStore fs;
        fs.exec = make_exec("bob", 3);
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({})), audit.fn());
        CHECK(out.status == S::kDone);
    }
    SECTION("a non-dispatcher with zero rows is denied") {
        FakeStore fs;
        fs.exec = make_exec("alice", 3);
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a"})), audit.fn());
        CHECK(out.status == S::kNotFound);
    }
    SECTION("dispatcher ownership is NOT a bypass once rows exist") {
        FakeStore fs;
        fs.exec = make_exec("bob", 2);
        fs.statuses = {st("a"), st("hidden")};
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a"})), audit.fn());
        CHECK(out.status == S::kNotFound);
        CHECK(fs.effects() == 0);
    }
}

TEST_CASE("execution mutation: a nonexistent id and a hidden id are indistinguishable to a "
          "confined caller",
          "[execution][mutation][confinement][security][2146]") {
    for (const auto what : {ExecutionMutation::kCancel, ExecutionMutation::kRerun}) {
        FakeStore missing; // no such execution
        FakeStore hidden;  // exists, targets an agent the caller cannot see
        hidden.exec = make_exec("alice", 1);
        hidden.statuses = {st("hidden")};
        AuditRecorder audit_missing{&missing}, audit_hidden{&hidden};
        const auto a = apply_execution_mutation(
            missing.ports(), req(what, "bob", scope_of({"a"})), audit_missing.fn());
        const auto b = apply_execution_mutation(
            hidden.ports(), req(what, "bob", scope_of({"a"})), audit_hidden.fn());
        CHECK(a.status == S::kNotFound);
        CHECK(b.status == S::kNotFound);
        // Same audit rows, field for field.
        CHECK(audit_missing.rows == audit_hidden.rows);
        REQUIRE(audit_missing.rows.size() == 1);
        CHECK(audit_missing.rows[0].result == "denied");
        // Same number of store round trips: the status read is UNCONDITIONAL, not id-conditional.
        CHECK(missing.exec_reads == hidden.exec_reads);
        CHECK(missing.status_reads == hidden.status_reads);
        CHECK(missing.status_reads == 1);
        CHECK(missing.effects() == 0);
        CHECK(hidden.effects() == 0);
    }
}

TEST_CASE("execution mutation: an unconfined caller naming an unknown id gets not-found and no row",
          "[execution][mutation][2146]") {
    FakeStore fs;
    AuditRecorder audit{&fs};
    const auto out = apply_execution_mutation(fs.ports(), req(ExecutionMutation::kRerun, "bob"),
                                              audit.fn());
    CHECK(out.status == S::kNotFound);
    CHECK(audit.rows.empty());
    CHECK(fs.effects() == 0);
}

TEST_CASE("execution mutation: a degraded admission read is a retryable fault, never a not-found",
          "[execution][mutation][2146]") {
    SECTION("execution read") {
        FakeStore fs;
        fs.degrade_exec = true;
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a"})), audit.fn());
        CHECK(out.status == S::kStoreDegraded);
        CHECK(audit.rows.empty());
    }
    SECTION("status read, confined") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.degrade_statuses = true;
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob", scope_of({"a"})), audit.fn());
        CHECK(out.status == S::kStoreDegraded);
        CHECK(audit.rows.empty());
        CHECK(fs.effects() == 0);
    }
}

TEST_CASE("execution mutation: cancel outcome mapping and its audit rows",
          "[execution][mutation][2146]") {
    SECTION("already finished: 409-shaped, audited denied, nothing changed") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.cancel_outcome = Outcome::kNoOp;
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob"), audit.fn());
        CHECK(out.status == S::kAlreadyFinished);
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[1].result == "denied");
    }
    SECTION("store failure: 503-shaped, audited failure") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.cancel_outcome = Outcome::kFailed;
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kCancel, "bob"), audit.fn());
        CHECK(out.status == S::kStoreFailed);
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[1].result == "failure");
    }
}

TEST_CASE("execution mutation: a THROWING effect (std or non-std) writes a failure row, is not a "
          "retryable store fault, and the exception never escapes",
          "[execution][mutation][2146]") {
    for (const auto what : {ExecutionMutation::kCancel, ExecutionMutation::kRerun}) {
        for (const int kind : {1, 2}) {
            INFO("what=" << (what == ExecutionMutation::kCancel ? "cancel" : "rerun")
                         << " throw_kind=" << kind);
            FakeStore fs;
            fs.exec = make_exec("alice", 1);
            fs.effect_throws = kind;
            AuditRecorder audit{&fs};
            ExecutionMutationOutcome out;
            REQUIRE_NOTHROW(out = apply_execution_mutation(fs.ports(), req(what, "bob"), audit.fn()));
            CHECK(out.status == S::kEffectThrew);
            CHECK(out.audit_persisted);
            CHECK(fs.effects() == 1); // attempted exactly once, never re-driven
            REQUIRE(audit.rows.size() == 2);
            CHECK(audit.rows[0].result == "attempted");
            CHECK(audit.rows[1].result == "failure");
            CHECK(audit.rows[1].action == execution_mutation_audit_action(what));
            // The exception text is never echoed into the evidence row.
            CHECK(audit.rows[1].detail.find("PQerror") == std::string::npos);
            CHECK(out.new_execution_id.empty());
        }
    }
    SECTION("a failing failure-row is reported, not hidden") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.effect_throws = 2;
        AuditRecorder audit{&fs};
        audit.fail_result = "failure";
        const auto out = apply_execution_mutation(fs.ports(), req(ExecutionMutation::kCancel, "bob"),
                                                  audit.fn());
        CHECK(out.status == S::kEffectThrew);
        CHECK_FALSE(out.audit_persisted);
    }
}

TEST_CASE("execution mutation: rerun forwards failed_only, records the NEW id, and echoes no "
          "store text",
          "[execution][mutation][2146]") {
    for (const bool failed_only : {false, true}) {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        AuditRecorder audit{&fs};
        auto r = req(ExecutionMutation::kRerun, "bob");
        r.failed_only = failed_only;
        const auto out = apply_execution_mutation(fs.ports(), r, audit.fn());
        CHECK(out.status == S::kDone);
        CHECK(out.new_execution_id == "rerun-new-1");
        CHECK(fs.effect_failed_only == failed_only);
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[0].action == "execution.rerun");
        CHECK(audit.rows[0].detail.starts_with(std::string("failed_only=") +
                                               (failed_only ? "true" : "false")));
        CHECK(audit.rows[1].result == "success");
        CHECK(audit.rows[1].target == "rerun-new-1"); // the success row names the new record
    }
    SECTION("a store failure is a 503-shaped failure with no raw text") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.rerun_result = std::unexpected(ExecutionTracker::RerunError::kWriteFailed);
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kRerun, "bob"), audit.fn());
        CHECK(out.status == S::kStoreFailed);
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[1].result == "failure");
        CHECK(audit.rows[1].detail.find("PQerror") == std::string::npos);
    }
    SECTION("the row vanishing after admission reads as not-found") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.rerun_result = std::unexpected(ExecutionTracker::RerunError::kOriginalNotFound);
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kRerun, "bob"), audit.fn());
        CHECK(out.status == S::kNotFound);
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[1].result == "denied");
    }
    SECTION("an UNREADABLE store is unavailable (retryable, failure row), never a not-found") {
        FakeStore fs;
        fs.exec = make_exec("alice", 1);
        fs.rerun_result = std::unexpected(ExecutionTracker::RerunError::kStoreDegraded);
        AuditRecorder audit{&fs};
        const auto out = apply_execution_mutation(
            fs.ports(), req(ExecutionMutation::kRerun, "bob"), audit.fn());
        CHECK(out.status == S::kStoreDegraded);
        CHECK(out.new_execution_id.empty());
        REQUIRE(audit.rows.size() == 2);
        CHECK(audit.rows[1].result == "failure");
    }
}

TEST_CASE("execution mutation: an audit-id in a detail is neutralised (CWE-117)",
          "[execution][mutation][security][2146]") {
    FakeStore fs;
    fs.exec = make_exec("alice", 1);
    AuditRecorder audit{&fs};
    auto r = req(ExecutionMutation::kRerun, "bob");
    r.execution_id = "x y=z\nforged";
    (void)apply_execution_mutation(fs.ports(), r, audit.fn());
    REQUIRE(audit.rows.size() == 2);
    const auto& d = audit.rows[1].detail;
    CHECK(d.find('\n') == std::string::npos);
    CHECK(d.find("x y=z") == std::string::npos);
}

TEST_CASE("is_valid_execution_id: the charset and bound both surfaces share",
          "[execution][mutation][2146]") {
    CHECK(is_valid_execution_id("abc-DEF_123"));
    CHECK(is_valid_execution_id(std::string(128, 'a')));
    CHECK_FALSE(is_valid_execution_id(""));
    CHECK_FALSE(is_valid_execution_id(std::string(129, 'a')));
    CHECK_FALSE(is_valid_execution_id("a b"));
    CHECK_FALSE(is_valid_execution_id("a/b"));
    CHECK_FALSE(is_valid_execution_id("a\nb"));
    CHECK_FALSE(is_valid_execution_id("a=b"));
}

// ── the REST v1 routes ──────────────────────────────────────────────────────

namespace {

struct RestHarness {
    yuzu::MetricsRegistry metrics;
    yuzu::server::test::TestRouteSink sink;
    FakeStore store;
    std::vector<AuditRow> audit_rows;
    std::string audit_fail_result;
    bool perm_grant{true};
    bool fleet_admit{true};
    authz::VisibleSet scope{std::nullopt};
    std::string username{"bob"};
    int dispatch_calls{0};
    RestApiV1 api;

    explicit RestHarness(bool wire_ports = true, bool wire_fleet_read = true) {
        if (wire_ports)
            api.set_execution_mutation_ports_for_test(store.ports());
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = username;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto fleet_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                               const std::string&) -> authz::FleetReadGate {
            if (!fleet_admit) {
                res.status = 403;
                return {false, authz::deny_all()};
            }
            return {true, scope};
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audit_rows.push_back({a, r, ti, d});
            store.events.push_back("audit:" + r);
            CHECK(tt == "execution");
            return r != audit_fail_result;
        };
        // A dispatch seam that must never be reached: neither mutation sends anything to a device.
        auto dispatch_fn = [this](auto&&...) {
            ++dispatch_calls;
            return ConfinedDispatchOutcome{};
        };
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, // the ports seam stands in for it
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/RestApiV1::CommandDispatchFn(dispatch_fn),
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{},
                            /*fleet_read_fn=*/wire_fleet_read ? RestApiV1::FleetReadFn(fleet_fn)
                                                              : RestApiV1::FleetReadFn{});
    }
};

nlohmann::json body_of(const httplib::Response& r) { return nlohmann::json::parse(r.body); }

std::string strip_cid(std::string s) {
    return std::regex_replace(s, std::regex("cid=[^ ]*"), "cid=X");
}

} // namespace

TEST_CASE("REST executions cancel/rerun: both routes are registered",
          "[rest][executions][mutation][2146]") {
    RestHarness h;
    bool cancel = false, rerun = false;
    for (const auto& [m, p] : h.sink.registered_routes()) {
        cancel = cancel || (m == "POST" && p.ends_with("/cancel") &&
                            p.starts_with("/api/v1/executions/"));
        rerun = rerun || (m == "POST" && p.ends_with("/rerun") &&
                          p.starts_with("/api/v1/executions/"));
    }
    CHECK(cancel);
    CHECK(rerun);
}

TEST_CASE("REST POST cancel: unconfined caller cancels; evidence precedes the effect; nothing is "
          "dispatched",
          "[rest][executions][mutation][2146]") {
    RestHarness h;
    h.store.exec = make_exec("alice", 1);
    auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto data = body_of(*res)["data"];
    CHECK(data["execution_id"] == "exec-1");
    CHECK(data["status"] == "cancelled");
    CHECK(h.store.cancel_calls == 1);
    CHECK(h.store.effect_user == "bob");
    REQUIRE(h.audit_rows.size() == 2);
    CHECK(h.audit_rows[0].action == "execution.cancel");
    CHECK(h.audit_rows[0].result == "attempted");
    CHECK(h.audit_rows[1].result == "success");
    CHECK(h.store.events.size() >= 3);
    CHECK(std::ranges::find(h.store.events, "audit:attempted") <
          std::ranges::find(h.store.events, "effect:cancel"));
    CHECK(h.dispatch_calls == 0); // the send set is empty
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("REST POST cancel: confined caller needs complete cohort visibility",
          "[rest][executions][mutation][confinement][security][2146]") {
    SECTION("full cohort visible") {
        RestHarness h;
        h.scope = scope_of({"a", "b"});
        h.store.exec = make_exec("alice", 2);
        h.store.statuses = {st("a"), st("b")};
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.store.cancel_calls == 1);
    }
    SECTION("partial visibility denies with the uniform 404") {
        RestHarness h;
        h.scope = scope_of({"a"});
        h.store.exec = make_exec("alice", 2);
        h.store.statuses = {st("a"), st("hidden")};
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(h.store.effects() == 0);
        REQUIRE(h.audit_rows.size() == 1);
        CHECK(h.audit_rows[0].result == "denied");
    }
}

TEST_CASE("REST POST cancel/rerun: hidden and nonexistent produce the same response and audit",
          "[rest][executions][mutation][confinement][security][2146]") {
    for (const char* verb : {"cancel", "rerun"}) {
        RestHarness missing, hidden;
        missing.scope = hidden.scope = scope_of({"a"});
        hidden.store.exec = make_exec("alice", 1);
        hidden.store.statuses = {st("hidden")};
        const std::string path = std::string("/api/v1/executions/exec-1/") + verb;
        auto a = missing.sink.Post(path, "");
        auto b = hidden.sink.Post(path, "");
        REQUIRE(a);
        REQUIRE(b);
        CHECK(a->status == 404);
        CHECK(b->status == 404);
        auto ja = body_of(*a), jb = body_of(*b);
        CHECK(ja["error"]["message"] == jb["error"]["message"]);
        CHECK(ja["error"]["code"] == jb["error"]["code"]);
        REQUIRE(missing.audit_rows.size() == 1);
        REQUIRE(hidden.audit_rows.size() == 1);
        CHECK(missing.audit_rows[0].action == hidden.audit_rows[0].action);
        CHECK(missing.audit_rows[0].result == hidden.audit_rows[0].result);
        CHECK(missing.audit_rows[0].target == hidden.audit_rows[0].target);
        CHECK(strip_cid(missing.audit_rows[0].detail) == strip_cid(hidden.audit_rows[0].detail));
        CHECK(missing.store.exec_reads == hidden.store.exec_reads);
        CHECK(missing.store.status_reads == hidden.store.status_reads);
        CHECK(missing.store.effects() == 0);
        CHECK(hidden.store.effects() == 0);
    }
}

TEST_CASE("REST POST cancel/rerun: no resolved principal is refused, never run as 'unknown'",
          "[rest][executions][mutation][security][2146]") {
    for (const char* verb : {"cancel", "rerun"}) {
        for (const bool confined : {false, true}) {
            RestHarness h;
            h.username = "";
            if (confined)
                h.scope = scope_of({"a"});
            h.store.exec = make_exec("", 1);
            auto res = h.sink.Post(std::string("/api/v1/executions/exec-1/") + verb, "");
            REQUIRE(res);
            CHECK(res->status == 503);
            CHECK(h.store.exec_reads == 0);
            CHECK(h.store.effects() == 0);
            CHECK(h.audit_rows.empty());
        }
    }
}

TEST_CASE("REST POST cancel/rerun: an attempted row that cannot be saved refuses with 503 and "
          "Sec-Audit-Failed, changing nothing",
          "[rest][executions][mutation][security][2146]") {
    for (const char* verb : {"cancel", "rerun"}) {
        RestHarness h;
        h.audit_fail_result = "attempted";
        h.store.exec = make_exec("alice", 1);
        auto res = h.sink.Post(std::string("/api/v1/executions/exec-1/") + verb, "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.store.effects() == 0);
        CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    }
}

TEST_CASE("REST POST cancel/rerun: a throwing effect is a 500 with NO retry hint, a failure audit "
          "row, and nothing dispatched",
          "[rest][executions][mutation][2146]") {
    for (const char* verb : {"cancel", "rerun"}) {
        for (const int kind : {1, 2}) {
            INFO("verb=" << verb << " throw_kind=" << kind);
            RestHarness h;
            h.store.exec = make_exec("alice", 1);
            h.store.effect_throws = kind;
            auto res = h.sink.Post(std::string("/api/v1/executions/exec-1/") + verb, "");
            REQUIRE(res);
            CHECK(res->status == 500);
            CHECK(h.store.effects() == 1);
            CHECK(h.dispatch_calls == 0);
            const auto err = body_of(*res)["error"];
            CHECK(err["retry_after_ms"].is_null());
            CHECK(err["code"] == 500);
            // No retry wording anywhere in the body, and no exception text.
            CHECK(err["message"].get<std::string>().find("retry") == std::string::npos);
            CHECK(err.value("remediation", std::string{}).find("retry") == std::string::npos);
            CHECK(res->body.find("PQerror") == std::string::npos);
            REQUIRE(h.audit_rows.size() == 2);
            CHECK(h.audit_rows[0].result == "attempted");
            CHECK(h.audit_rows[1].result == "failure");
            CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        }
    }
    SECTION("a lost failure row sets Sec-Audit-Failed but the error still stands") {
        RestHarness h;
        h.store.exec = make_exec("alice", 1);
        h.store.effect_throws = 2;
        h.audit_fail_result = "failure";
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("REST POST cancel: 409 for an already-finished execution, 503 for a store failure",
          "[rest][executions][mutation][2146]") {
    SECTION("409") {
        RestHarness h;
        h.store.exec = make_exec("alice", 1);
        h.store.cancel_outcome = Outcome::kNoOp;
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 409);
        REQUIRE(h.audit_rows.size() == 2);
        CHECK(h.audit_rows[1].result == "denied");
    }
    SECTION("503 on a failed write, with a retry hint") {
        RestHarness h;
        h.store.exec = make_exec("alice", 1);
        h.store.cancel_outcome = Outcome::kFailed;
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
        REQUIRE(h.audit_rows.size() == 2);
        CHECK(h.audit_rows[1].result == "failure");
    }
    SECTION("503 on a degraded admission read") {
        RestHarness h;
        h.store.degrade_exec = true;
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.audit_rows.empty());
    }
    SECTION("an outcome row lost after the effect keeps the 200 and flags the gap") {
        RestHarness h;
        h.store.exec = make_exec("alice", 1);
        h.audit_fail_result = "success";
        auto res = h.sink.Post("/api/v1/executions/exec-1/cancel", "");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.store.cancel_calls == 1);
    }
}

TEST_CASE("REST POST rerun: failed_only is a boolean; nothing is dispatched to any device",
          "[rest][executions][mutation][2146]") {
    SECTION("failed_only true") {
        RestHarness h;
        h.store.exec = make_exec("alice", 4);
        auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", R"({"failed_only":true})");
        REQUIRE(res);
        CHECK(res->status == 201);
        const auto data = body_of(*res)["data"];
        CHECK(data["execution_id"] == "rerun-new-1");
        CHECK(data["rerun_of"] == "exec-1");
        CHECK(data["status"] == "pending");
        CHECK(data["failed_only"] == true);
        CHECK(data["dispatched_to_devices"] == false);
        CHECK(h.store.effect_failed_only);
        CHECK(h.dispatch_calls == 0); // the send set is empty
        REQUIRE(h.audit_rows.size() == 2);
        CHECK(h.audit_rows[0].action == "execution.rerun");
        CHECK(h.audit_rows[0].result == "attempted");
        CHECK(h.audit_rows[1].target == "rerun-new-1");
    }
    SECTION("failed_only false, and an empty body means false") {
        for (const char* body : {R"({"failed_only":false})", "", "{}"}) {
            RestHarness h;
            h.store.exec = make_exec("alice", 4);
            auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", body);
            REQUIRE(res);
            CHECK(res->status == 201);
            CHECK_FALSE(h.store.effect_failed_only);
            CHECK(body_of(*res)["data"]["failed_only"] == false);
            CHECK(h.dispatch_calls == 0);
        }
    }
    SECTION("the legacy scope=failed_only spelling and any other field are a 400, never a full "
            "rerun") {
        for (const char* body : {R"({"scope":"failed_only"})", R"({"failed_only":true,"x":1})",
                                 R"({"failed_only":"true"})", R"({"failed_only":1})", "[]",
                                 "not json", R"("failed_only")"}) {
            RestHarness h;
            h.store.exec = make_exec("alice", 4);
            auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", body);
            REQUIRE(res);
            INFO(body);
            CHECK(res->status == 400);
            CHECK(h.store.exec_reads == 0);
            CHECK(h.store.effects() == 0);
            CHECK(h.audit_rows.empty());
        }
    }
    SECTION("a store failure creating the record is a 503") {
        RestHarness h;
        h.store.exec = make_exec("alice", 4);
        h.store.rerun_result = std::unexpected(ExecutionTracker::RerunError::kWriteFailed);
        auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    }
    SECTION("an UNREADABLE original is a 503 (never a 404) with a failure row") {
        RestHarness h;
        h.store.exec = make_exec("alice", 4);
        h.store.rerun_result = std::unexpected(ExecutionTracker::RerunError::kStoreDegraded);
        auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
        REQUIRE(h.audit_rows.size() == 2);
        CHECK(h.audit_rows[1].result == "failure");
    }
    SECTION("a row that vanished after admission is the uniform 404") {
        RestHarness h;
        h.store.exec = make_exec("alice", 4);
        h.store.rerun_result = std::unexpected(ExecutionTracker::RerunError::kOriginalNotFound);
        auto res = h.sink.Post("/api/v1/executions/exec-1/rerun", "");
        REQUIRE(res);
        CHECK(res->status == 404);
        REQUIRE(h.audit_rows.size() == 2);
        CHECK(h.audit_rows[1].result == "denied");
    }
}

TEST_CASE("REST POST cancel/rerun: the gates run before any store read",
          "[rest][executions][mutation][security][2146]") {
    for (const char* verb : {"cancel", "rerun"}) {
        const std::string path = std::string("/api/v1/executions/exec-1/") + verb;
        SECTION(std::string(verb) + ": permission denied") {
            RestHarness h;
            h.perm_grant = false;
            h.store.exec = make_exec("alice", 1);
            auto res = h.sink.Post(path, "");
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(h.store.exec_reads == 0);
            CHECK(h.audit_rows.empty());
        }
        SECTION(std::string(verb) + ": fleet-read denied") {
            RestHarness h;
            h.fleet_admit = false;
            h.store.exec = make_exec("alice", 1);
            auto res = h.sink.Post(path, "");
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(h.store.exec_reads == 0);
        }
        SECTION(std::string(verb) + ": fleet gate unwired fails closed") {
            RestHarness h(true, /*wire_fleet_read=*/false);
            h.store.exec = make_exec("alice", 1);
            auto res = h.sink.Post(path, "");
            REQUIRE(res);
            CHECK(res->status == 503);
            CHECK(h.store.exec_reads == 0);
        }
        SECTION(std::string(verb) + ": no tracker and no ports is a 503") {
            RestHarness h(/*wire_ports=*/false);
            auto res = h.sink.Post(path, "");
            REQUIRE(res);
            CHECK(res->status == 503);
        }
    }
}
