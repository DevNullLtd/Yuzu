/**
 * test_guardian_reconcile_flow.cpp: GuardianReconcileFlow::run (#5513), the Guardian heartbeat
 * reconcile control flow that used to be an untestable lambda inside ServerImpl.
 *
 * The flow is driven with the REAL gate, budget, generation cache, rule-bundle cache and
 * metrics registry on ONE manual clock; only the pieces that stay in ServerImpl (session
 * lookup, scope evaluation, the push send, the audit sink, the command-id suffix) are stubbed.
 * Nothing sleeps. Every test asserts the exits AND the metric labels, because the flow's
 * contract is "at most one result label per call, and none for the exits that are not a
 * reconcile outcome".
 *
 * What this file cannot see (by construction): the DispatchCaller{.system = true} /
 * send_system_reserved / forward_gateway_pending sequence behind `send_push`, and the
 * `audit_store_->is_open()` check behind `audit`. Those stay in server.cpp and are pinned by
 * tests/test_guardian_reconcile_wiring_lexical.py (invariant u).
 */

#include "guardian_reconcile_flow.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "guaranteed_state.pb.h"

using namespace std::chrono_literals;
using yuzu::server::AuditEvent;
using yuzu::server::GuardianGenerationCache;
using yuzu::server::GuardianReconcileBudget;
using yuzu::server::GuardianReconcileFlow;
using yuzu::server::GuardianReconcileFlowDeps;
using yuzu::server::GuardianReconcileGate;
using yuzu::server::GuaranteedStateRuleRow;
using yuzu::server::ScopeEvalError;
namespace guardian = yuzu::server::guardian;

namespace {

// The audit literal is "heartbeat reconcile ABORTED <em dash> <what> (...)". Spelled as UTF-8
// bytes so this file stays free of the character while still asserting the exact bytes.
constexpr const char* kDash = "\xE2\x80\x94";

constexpr const char* kResultFamily = "yuzu_server_guardian_reconciles_total";
constexpr const char* kLabels[] = {"sent", "rate_limited", "shed", "degraded", "no_session"};

// Manual steady clock, shared by the gate, the budget and both caches. Atomic because the
// single-flight tests drive it from a helper thread.
struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};
    std::chrono::steady_clock::time_point now() const {
        return std::chrono::steady_clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    std::function<std::chrono::steady_clock::time_point()> fn() {
        return [this] { return now(); };
    }
};

GuardianReconcileBudget::Config roomy() {
    return {.budget_ms_per_s = 1'000'000.0, .burst_ms = 3'600'000.0, .max_per_s = 1'000'000};
}

struct RigOptions {
    GuardianReconcileBudget::Config budget{roomy()};
    yuzu::server::GuardianReconcileGateOptions gate{.max_reserve = 0};
    std::chrono::seconds min_interval{25};
    std::uint64_t store_generation{7};
};

enum class ScopeOutcome {
    Member,
    NotMember,
    Unresolvable,
    StoreDegraded,
    // The remaining ScopeEvalError kinds. The local evaluator the server wires never returns
    // them today; the flow must still treat each as an untrusted read and abort.
    PrincipalUnresolved,
    OwnerCheckFailed,
    PresenceDegraded
};

struct SentPush {
    std::string agent_id;
    std::string command_id;
    std::string bytes;
};

GuaranteedStateRuleRow rule(std::string id, std::string os = "", std::string scope = "",
                            bool enabled = true) {
    GuaranteedStateRuleRow r;
    r.rule_id = id;
    r.name = std::move(id);
    r.enabled = enabled;
    r.enforcement_mode = "enforce";
    r.os_target = std::move(os);
    r.scope_expr = std::move(scope);
    r.spec_json =
        R"({"spark":{"type":"registry-change","params":{"hive":"HKLM"}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"value_name":"Start","expected":"4"}},)"
        R"("remediation":{"type":"alert-only"}})";
    return r;
}

// Captures the default spdlog logger for the lifetime of the object.
struct LogCapture {
    std::ostringstream oss;
    std::shared_ptr<spdlog::logger> prev = spdlog::default_logger();
    LogCapture() {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss);
        auto lg = std::make_shared<spdlog::logger>("reconcile_flow_test", sink);
        lg->set_level(spdlog::level::trace);
        spdlog::set_default_logger(lg);
    }
    ~LogCapture() { spdlog::set_default_logger(prev); }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;
    std::string text() const { return oss.str(); }
    std::size_t count(const std::string& needle) const {
        std::size_t n = 0;
        const auto s = text();
        for (auto p = s.find(needle); p != std::string::npos; p = s.find(needle, p + 1))
            ++n;
        return n;
    }
};

// Everything the flow reads, on real collaborators with stubbed ServerImpl-side callables.
// Not movable: the flow holds references into it.
class Rig {
public:
    explicit Rig(RigOptions o = {})
        : budget(o.budget, clock.fn()), gate(budget, clock.fn(), o.min_interval, o.gate),
          gen_cache([this] { return fetch_generation(); },
                    GuardianGenerationCache::Config{
                        .ttl = 2000ms, .negative_ttl = 1000ms, .max_wait = 5000ms},
                    clock.fn()),
          bundle_cache(guardian::GuardianRuleBundleCacheConfig{},
                       [this] {
                           // Read BEFORE the hook: the hook may release a thread that advances
                           // the clock, and a reader that took the value after that would see
                           // the advance as if it had happened before this read.
                           const auto t = clock.now();
                           if (bundle_clock_hook)
                               bundle_clock_hook();
                           return t;
                       }),
          store_generation(o.store_generation) {
        duration = &metrics.histogram("yuzu_server_guardian_reconcile_duration_seconds",
                                      std::vector<double>{0.0001, 0.001, 0.01, 0.1, 1.0, 10.0});
        set_rules({rule("r1")});
        flow = std::make_unique<GuardianReconcileFlow>(make_deps());
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

    // Every dependency wired to this rig's stubs. Public so a test can empty one and construct
    // a second flow; the references and the captured `this` outlive that flow.
    GuardianReconcileFlowDeps make_deps() {
        return GuardianReconcileFlowDeps{
            .gate = gate,
            .generation_cache = gen_cache,
            .rule_bundle_cache = bundle_cache,
            .budget = budget,
            .metrics = metrics,
            .duration = duration,
            .store_wired = [this] { return store_wired; },
            .list_rules = [this]() -> std::expected<std::vector<GuaranteedStateRuleRow>,
                                                    std::string> {
                {
                    std::lock_guard lk(fx_mu);
                    ++list_calls;
                    note("list_rules");
                }
                if (list_hook)
                    list_hook();
                if (rules_throw)
                    throw std::runtime_error("loader exploded");
                if (rules_error)
                    return std::unexpected(*rules_error);
                return rules;
            },
            .deployed_ids = [this]() -> std::expected<std::unordered_set<std::string>,
                                                      std::string> {
                {
                    std::lock_guard lk(fx_mu);
                    ++deployed_calls;
                    note("deployed_ids");
                }
                if (deployed_error)
                    return std::unexpected(*deployed_error);
                return deployed;
            },
            .session_os = [this](const std::string& agent_id) -> std::optional<std::string> {
                if (session_hook)
                    session_hook();
                std::lock_guard lk(fx_mu);
                note("session");
                session_agents.push_back(agent_id);
                return session_os;
            },
            .eval_scope = [this](const std::string& agent_id,
                                 const yuzu::scope::Expression& expr)
                -> std::expected<bool, ScopeEvalError> {
                {
                    std::lock_guard lk(fx_mu);
                    ++eval_calls;
                    note("eval_scope");
                    eval_agents.push_back(agent_id);
                }
                if (eval_hook)
                    eval_hook();
                const auto* cond = std::get_if<yuzu::scope::Condition>(&expr);
                const auto it = scope_outcomes.find(cond ? cond->value : std::string{});
                switch (it == scope_outcomes.end() ? ScopeOutcome::NotMember : it->second) {
                case ScopeOutcome::Member:
                    return true;
                case ScopeOutcome::NotMember:
                    return false;
                case ScopeOutcome::Unresolvable:
                    return std::unexpected(ScopeEvalError{ScopeEvalError::Kind::Unresolvable,
                                                          "no props store"});
                case ScopeOutcome::StoreDegraded:
                    return std::unexpected(ScopeEvalError{ScopeEvalError::Kind::StoreDegraded,
                                                          "tag store down"});
                case ScopeOutcome::PrincipalUnresolved:
                    return std::unexpected(
                        ScopeEvalError{ScopeEvalError::Kind::PrincipalUnresolved, "no principal"});
                case ScopeOutcome::OwnerCheckFailed:
                    return std::unexpected(
                        ScopeEvalError{ScopeEvalError::Kind::OwnerCheckFailed, "rs-1"});
                case ScopeOutcome::PresenceDegraded:
                    return std::unexpected(
                        ScopeEvalError{ScopeEvalError::Kind::PresenceDegraded, "presence down"});
                }
                return false;
            },
            .send_push = [this](const std::string& agent_id, const std::string& command_id,
                                const std::string& bytes) {
                if (send_hook)
                    send_hook();
                std::lock_guard lk(fx_mu);
                note("send_push");
                sent.push_back({agent_id, command_id, bytes});
                return send_result;
            },
            .audit = [this](const AuditEvent& ev) {
                if (audit_hook)
                    audit_hook();
                // Two flows can abort at once in the two-thread tests; note() takes the same
                // (recursive) lock.
                std::lock_guard lk(fx_mu);
                note("audit");
                audits.push_back(ev);
            },
            .random_suffix = [this] {
                if (suffix_hook)
                    suffix_hook();
                std::lock_guard lk(fx_mu);
                return "sfx" + std::to_string(suffix_base + ++suffix_calls);
            },
            .now = shed_clock.fn()};
    }

    void set_rules(std::vector<GuaranteedStateRuleRow> rs) {
        rules = std::move(rs);
        deployed.clear();
        for (const auto& r : rules)
            deployed.insert(r.rule_id);
    }
    void run(const std::string& agent = "agent-1", std::uint64_t agent_gen = 3) {
        flow->run(agent, agent_gen);
    }
    // Occupy one in-flight slot, as a push stuck inside a store call would.
    void hold_slot() { held.emplace(gate.begin_admitted()); }

    double count(const char* label) {
        return metrics.counter(kResultFamily, {{"result", label}}).value();
    }
    double total() {
        double t = 0;
        for (const char* l : kLabels)
            t += count(l);
        return t;
    }
    // The dedicated counter of the epoch-check abort (NOT a result label of reconciles_total).
    double invalidated() {
        return metrics.counter("yuzu_server_guardian_reconcile_invalidated_total").value();
    }
    double dispatched() {
        return metrics.counter("yuzu_server_guardian_pushes_dispatched_total",
                               {{"reason", "reconcile"}})
            .value();
    }
    double generation_gauge() { return metrics.gauge("yuzu_server_guardian_policy_generation").value(); }
    std::uint64_t duration_count() const { return duration->snapshot().count; }

    // ---- scripted behaviour ----
    ManualClock clock;
    ManualClock shed_clock;
    GuardianReconcileBudget budget;
    GuardianReconcileGate gate;
    GuardianGenerationCache gen_cache;
    guardian::GuardianRuleBundleCache bundle_cache;
    yuzu::MetricsRegistry metrics;
    yuzu::Histogram* duration{nullptr};

    bool store_wired{true};
    std::uint64_t store_generation;
    std::string gen_error;  // non-empty: the store read fails with this text
    // Overrides the stored generation: (1-based fetch number) -> result.
    std::function<GuardianGenerationCache::Result(int)> on_fetch;
    std::vector<GuaranteedStateRuleRow> rules;
    std::unordered_set<std::string> deployed;
    std::optional<std::string> rules_error;
    std::optional<std::string> deployed_error;
    bool rules_throw{false};
    std::optional<std::string> session_os{"linux"};
    std::unordered_map<std::string, ScopeOutcome> scope_outcomes;
    bool send_result{true};
    std::function<void()> list_hook;
    std::function<void()> eval_hook;
    // Run at the top of the matching stub, before it records anything; a test makes one throw.
    std::function<void()> session_hook;
    std::function<void()> send_hook;
    std::function<void()> audit_hook;
    std::function<void()> suffix_hook;
    std::function<void()> bundle_clock_hook;
    // Guards every recorded effect below against two concurrent flows (the two-thread test).
    // Never held across a hook, so a flow blocked in list_hook cannot stall the other one.
    std::recursive_mutex fx_mu;

    // ---- recorded effects ----
    // Every stub call, in order, with the gate's in-flight count as the stub saw it.
    void note(std::string what) {
        std::lock_guard lk(fx_mu);
        trace.push_back(std::move(what));
        inflight_at.push_back(gate.in_flight());
    }
    std::vector<std::string> trace;
    std::vector<std::size_t> inflight_at;
    std::vector<std::string> session_agents;
    std::vector<std::string> eval_agents;
    std::vector<SentPush> sent;
    std::vector<AuditEvent> audits;
    int fetch_calls{0};
    int list_calls{0};
    int deployed_calls{0};
    int eval_calls{0};
    int suffix_calls{0};
    int suffix_base{0};  // a second rig (a restarted replica) uses a disjoint range

    std::unique_ptr<GuardianReconcileFlow> flow;
    std::optional<GuardianReconcileGate::Scoped> held;  // destroyed before the gate

private:
    GuardianGenerationCache::Result fetch_generation() {
        int n = 0;
        {
            std::lock_guard lk(fx_mu);
            n = ++fetch_calls;
            note("generation_read#" + std::to_string(n));
        }
        if (on_fetch)
            return on_fetch(n);
        if (!gen_error.empty())
            return std::unexpected(gen_error);
        return store_generation;
    }
};

::yuzu::guardian::v1::GuaranteedStatePush parse_push(const std::string& bytes) {
    ::yuzu::guardian::v1::GuaranteedStatePush p;
    REQUIRE(p.ParseFromString(bytes));
    return p;
}

std::vector<std::string> rule_ids(const ::yuzu::guardian::v1::GuaranteedStatePush& push) {
    std::vector<std::string> ids;
    for (const auto& r : push.rules())
        ids.push_back(r.rule_id());
    return ids;
}

std::string aborted(const std::string& what, const std::string& err, std::uint64_t agent_gen = 3) {
    return std::string("heartbeat reconcile ABORTED ") + kDash + " " + what + " (" + err +
           "); agent rules did not converge (generation " + std::to_string(agent_gen) + ")";
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Exits before admission: each one counts at most one label and touches nothing else.
// ---------------------------------------------------------------------------------------

TEST_CASE("GuardianReconcileFlow: an unwired store returns before any decision",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.store_wired = false;
    rig.run();
    CHECK(rig.total() == 0.0);
    CHECK(rig.fetch_calls == 0);  // the generation cache was not even consulted
    CHECK(rig.gate.claims_size() == 0);
    CHECK(rig.budget.admitted_total() == 0);
    CHECK(rig.budget.shed_total() == 0);
    CHECK(rig.audits.empty());
    CHECK(rig.sent.empty());
    CHECK(rig.duration_count() == 0);
}

TEST_CASE("GuardianReconcileFlow: an unreadable cached generation counts one degraded and nothing else",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.gen_error = "pg down";
    rig.run();
    CHECK(rig.count("degraded") == 1.0);
    CHECK(rig.total() == 1.0);
    CHECK(rig.audits.empty());  // pre-admission: counter only, by design
    CHECK(rig.sent.empty());
    CHECK(rig.budget.admitted_total() == 0);
    CHECK(rig.gate.claims_size() == 0);
    CHECK(rig.duration_count() == 0);
    CHECK(rig.session_agents.empty());
}

TEST_CASE("GuardianReconcileFlow: a converged agent costs nothing", "[guardian][reconcile_flow]") {
    Rig rig;
    SECTION("equal generation") { rig.run("agent-1", 7); }
    SECTION("agent ahead of the server") { rig.run("agent-1", 99); }
    CHECK(rig.total() == 0.0);
    CHECK(rig.audits.empty());
    CHECK(rig.sent.empty());
    CHECK(rig.budget.admitted_total() == 0);
    CHECK(rig.gate.claims_size() == 0);
    CHECK(rig.duration_count() == 0);
    CHECK(rig.session_agents.empty());
}

TEST_CASE("GuardianReconcileFlow: a rate-limited agent counts rate_limited and nothing else",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.run();  // admitted, pushed
    REQUIRE(rig.sent.size() == 1);
    REQUIRE(rig.count("sent") == 1.0);

    rig.clock.advance(10s);
    rig.run();
    CHECK(rig.count("rate_limited") == 1.0);
    rig.clock.advance(14s);  // 24 s after the claim: still limited
    rig.run();
    CHECK(rig.count("rate_limited") == 2.0);

    CHECK(rig.sent.size() == 1);
    CHECK(rig.audits.size() == 1);  // only the first push's success row
    CHECK(rig.budget.admitted_total() == 1);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.count("shed") == 0.0);
    CHECK(rig.count("degraded") == 0.0);

    rig.clock.advance(1s);  // 25 s: the claim no longer limits
    rig.run();
    CHECK(rig.sent.size() == 2);
    CHECK(rig.count("rate_limited") == 2.0);
}

TEST_CASE("GuardianReconcileFlow: shed by the replica budget writes no claim, no audit, sends nothing",
          "[guardian][reconcile_flow]") {
    RigOptions o;
    o.budget = {.budget_ms_per_s = 1000.0, .burst_ms = 100'000.0, .max_per_s = 1};
    Rig rig(o);
    rig.run("agent-a");  // takes the only admission of this second
    REQUIRE(rig.sent.size() == 1);
    REQUIRE(rig.audits.size() == 1);

    rig.run("agent-b");
    CHECK(rig.count("shed") == 1.0);
    CHECK(rig.total() == 2.0);  // agent-a's `sent` plus this shed: one label for the shed call
    CHECK(rig.count("sent") == 1.0);
    CHECK(rig.sent.size() == 1);
    CHECK(rig.audits.size() == 1);  // shed writes NO audit row
    CHECK(rig.gate.claims_size() == 1);  // agent-b earned no holdoff for a push that never happened
    CHECK(rig.duration_count() == 1);  // a shed is not an admitted reconcile
    CHECK(rig.session_agents == std::vector<std::string>{"agent-a"});

    rig.clock.advance(1s);  // a new budget window
    rig.run("agent-b");
    CHECK(rig.sent.size() == 2);  // admitted, not RateLimited: the shed left no claim
    CHECK(rig.count("rate_limited") == 0.0);
    CHECK(rig.count("shed") == 1.0);
}

TEST_CASE("GuardianReconcileFlow: shed by the in-flight cap, then recovery", "[guardian][reconcile_flow]") {
    RigOptions o;
    o.gate.max_in_flight = 1;
    Rig rig(o);
    rig.hold_slot();
    REQUIRE(rig.gate.in_flight() == 1);

    rig.run();
    CHECK(rig.count("shed") == 1.0);
    CHECK(rig.total() == 1.0);
    CHECK(rig.gate.in_flight_shed_total() == 1);
    CHECK(rig.audits.empty());
    CHECK(rig.sent.empty());
    CHECK(rig.gate.claims_size() == 0);
    CHECK(rig.duration_count() == 0);
    CHECK(rig.budget.admitted_total() == 0);  // the cap is checked before the budget

    rig.held.reset();  // the stuck push finishes
    CHECK(rig.gate.in_flight() == 0);
    rig.run();
    CHECK(rig.sent.size() == 1);
    CHECK(rig.count("sent") == 1.0);
}

TEST_CASE("GuardianReconcileFlow: the shed log is throttled to one line a minute and worded by cause",
          "[guardian][reconcile_flow]") {
    SECTION("budget cause") {
        RigOptions o;
        o.budget = {.budget_ms_per_s = 1000.0, .burst_ms = 100'000.0, .max_per_s = 1};
        Rig rig(o);
        LogCapture log;
        rig.run("agent-a");  // admitted
        rig.run("agent-b");
        rig.run("agent-b");
        rig.run("agent-b");
        REQUIRE(rig.count("shed") == 3.0);
        CHECK(log.count("admission budget or per-second ceiling exhausted") == 1);
        CHECK(log.count("in-flight reconcile cap reached") == 0);
        CHECK(log.count("1 shed so far") == 1);

        rig.shed_clock.advance(59s);
        rig.run("agent-b");
        CHECK(log.count("admission budget or per-second ceiling exhausted") == 1);  // still inside the minute

        rig.shed_clock.advance(1s);  // 60 s since the last line
        rig.run("agent-b");
        CHECK(log.count("admission budget or per-second ceiling exhausted") == 2);
        CHECK(log.count("5 shed so far") == 1);
        CHECK(rig.count("shed") == 5.0);  // the counter is not throttled
    }
    SECTION("in-flight cap cause") {
        RigOptions o;
        o.gate.max_in_flight = 1;
        Rig rig(o);
        LogCapture log;
        rig.hold_slot();
        rig.run();
        rig.run();
        CHECK(log.count("in-flight reconcile cap reached") == 1);
        CHECK(log.count("admission budget or per-second ceiling exhausted") == 0);
        CHECK(rig.count("shed") == 2.0);
    }
    SECTION("the logged total adds the budget sheds and the in-flight-cap sheds") {
        RigOptions o;
        o.gate.max_in_flight = 1;
        o.budget = {.budget_ms_per_s = 1000.0, .burst_ms = 100'000.0, .max_per_s = 1};
        Rig rig(o);
        LogCapture log;
        rig.run("agent-a");  // admitted: takes the one admission of this second
        rig.hold_slot();
        rig.run("agent-b");  // shed by the in-flight cap
        CHECK(log.count("in-flight reconcile cap reached") == 1);
        CHECK(log.count("1 shed so far") == 1);

        rig.held.reset();
        rig.shed_clock.advance(60s);
        rig.run("agent-c");  // shed by the per-second ceiling
        CHECK(log.count("admission budget or per-second ceiling exhausted") == 1);
        CHECK(log.count("2 shed so far") == 1);  // one of each, in the budget wording

        rig.hold_slot();
        rig.shed_clock.advance(60s);
        rig.run("agent-d");  // shed by the cap again
        CHECK(log.count("in-flight reconcile cap reached") == 2);
        CHECK(log.count("3 shed so far") == 1);  // and in the cap wording
    }
}

// ---------------------------------------------------------------------------------------
// Exits after admission.
// ---------------------------------------------------------------------------------------

TEST_CASE("GuardianReconcileFlow: an admitted agent with no session keeps its claim and counts no_session",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.session_os = std::nullopt;
    rig.run();
    CHECK(rig.count("no_session") == 1.0);
    CHECK(rig.total() == 1.0);
    CHECK(rig.audits.empty());
    CHECK(rig.sent.empty());
    CHECK(rig.gate.claims_size() == 1);  // KEPT: releasing it would let a looping agent drain the budget
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.fetch_calls == 1);  // the fresh read comes after the session lookup, so it never ran
    CHECK(rig.list_calls == 0);

    rig.clock.advance(1s);
    rig.run();
    CHECK(rig.count("rate_limited") == 1.0);  // the kept claim limits the next heartbeat
    CHECK(rig.count("no_session") == 1.0);
    CHECK(rig.budget.admitted_total() == 1);
    CHECK(rig.duration_count() == 1);
}

TEST_CASE("GuardianReconcileFlow: an unreadable fresh generation aborts before the bundle load",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        if (n == 1)
            return 7;
        return std::unexpected(std::string("pg down"));
    };
    rig.run();
    CHECK(rig.count("degraded") == 1.0);
    CHECK(rig.total() == 1.0);
    REQUIRE(rig.audits.size() == 1);
    const auto& ev = rig.audits[0];
    CHECK(ev.detail == aborted("policy generation unreadable", "pg down"));
    CHECK(ev.result == "degraded");
    CHECK(ev.principal == "system");
    CHECK(ev.action == "guaranteed_state.reconcile");
    CHECK(ev.target_type == "GuaranteedState");
    CHECK(ev.target_id == "agent-1");
    CHECK(ev.timestamp > 0);
    CHECK(rig.sent.empty());
    CHECK(rig.list_calls == 0);  // returned before the bundle load
    CHECK(rig.deployed_calls == 0);
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.generation_gauge() == 0.0);
}

TEST_CASE("GuardianReconcileFlow: a fresh generation not ahead of the agent sends nothing and counts nothing",
          "[guardian][reconcile_flow]") {
    Rig rig;
    std::uint64_t fresh = 3;
    SECTION("equal") { fresh = 3; }
    SECTION("behind the agent") { fresh = 1; }
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        return n == 1 ? 7 : fresh;  // the cached read says behind, the fresh read says converged
    };
    rig.run("agent-1", 3);
    CHECK(rig.total() == 0.0);
    CHECK(rig.audits.empty());
    CHECK(rig.sent.empty());
    CHECK(rig.list_calls == 0);  // no bundle load for a reconcile that sends nothing
    CHECK(rig.deployed_calls == 0);
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.gate.claims_size() == 1);
}

TEST_CASE("GuardianReconcileFlow: a failed bundle load aborts with the per-source wording and is negative-cached",
          "[guardian][reconcile_flow]") {
    Rig rig;
    std::string expected_what;
    std::string expected_detail;
    bool rewire_after_first = false;
    SECTION("rule store") {
        rig.rules_error = "list_rules sql error";
        expected_what = "rule store degraded";
        expected_detail = "list_rules sql error";
    }
    SECTION("deployed set") {
        rig.deployed_error = "deployed snapshot unreadable";
        expected_what = "baseline store degraded";
        expected_detail = "deployed snapshot unreadable";
    }
    SECTION("any other failure") {
        rig.rules_throw = true;
        expected_what = "rule bundle load failed";
    }
    SECTION("the store is unwired between the top check and the loader") {
        rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
            if (n == 2)
                rig.store_wired = false;  // stop() racing the reconcile
            return 7;
        };
        expected_what = "rule store degraded";
        expected_detail = "guaranteed-state store not wired";
        rewire_after_first = true;
    }

    rig.run("agent-a");
    CHECK(rig.count("degraded") == 1.0);
    CHECK(rig.total() == 1.0);
    REQUIRE(rig.audits.size() == 1);
    const auto& d = rig.audits[0].detail;
    CHECK(d.rfind(std::string("heartbeat reconcile ABORTED ") + kDash + " " + expected_what + " (", 0) == 0);
    if (!expected_detail.empty())
        CHECK(d == aborted(expected_what, expected_detail));
    CHECK(rig.audits[0].result == "degraded");
    CHECK(rig.sent.empty());
    CHECK(rig.generation_gauge() == 0.0);
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.eval_calls == 0);

    // A second admitted push inside the negative TTL must not re-run the loader.
    const int list_after_first = rig.list_calls;
    const int deployed_after_first = rig.deployed_calls;
    if (rewire_after_first)
        rig.store_wired = true;  // a store that is back must still be served the remembered failure
    rig.run("agent-b");
    CHECK(rig.list_calls == list_after_first);
    CHECK(rig.deployed_calls == deployed_after_first);
    CHECK(rig.count("degraded") == 2.0);
    CHECK(rig.audits.size() == 2);
    CHECK(rig.sent.empty());
    CHECK(rig.duration_count() == 2);

    // Past the negative TTL it probes the store again.
    if (!rewire_after_first) {
        rig.clock.advance(2s);
        rig.run("agent-c");
        CHECK(rig.list_calls == list_after_first + 1);
        CHECK(rig.count("degraded") == 3.0);
    }
}

TEST_CASE("GuardianReconcileFlow: a degraded scope store withholds the WHOLE push",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("open"), rule("scoped-a", "", "tag:grp == alpha"), rule("open2")});
    rig.scope_outcomes["alpha"] = ScopeOutcome::StoreDegraded;
    rig.run();
    CHECK(rig.count("degraded") == 1.0);
    CHECK(rig.total() == 1.0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail == aborted("scope store degraded", "db_degraded: tag store down"));
    CHECK(rig.audits[0].result == "degraded");
    CHECK(rig.sent.empty());  // NOT a narrowed push of the unscoped rules
    CHECK(rig.dispatched() == 0.0);
    CHECK(rig.generation_gauge() == 0.0);
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.eval_agents == std::vector<std::string>{"agent-1"});
}

TEST_CASE("GuardianReconcileFlow: an unresolvable scope is not a member, the push still goes out",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("open"), rule("scoped-u", "", "tag:grp == ghost"), rule("scoped-in", "", "tag:grp == beta")});
    rig.scope_outcomes["ghost"] = ScopeOutcome::Unresolvable;
    rig.scope_outcomes["beta"] = ScopeOutcome::Member;
    rig.run();
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"open", "scoped-in"});
    CHECK(rig.count("sent") == 1.0);
    CHECK(rig.count("degraded") == 0.0);
}

TEST_CASE("GuardianReconcileFlow: any scope error kind except Unresolvable aborts like a degraded store",
          "[guardian][reconcile_flow]") {
    // `Unresolvable` alone means "not a member" (previous test). Every other kind is an untrusted
    // read, so it must withhold the WHOLE push, never narrow it.
    struct Kind {
        const char* name;
        ScopeOutcome outcome;
        const char* expected_error;  // "<to_string(kind)>: <detail>" as the stub raises it
    };
    const Kind kinds[] = {
        {"presence_degraded", ScopeOutcome::PresenceDegraded, "presence_degraded: presence down"},
        {"principal_unresolved", ScopeOutcome::PrincipalUnresolved,
         "principal_unresolved: no principal"},
        {"owner_check_failed", ScopeOutcome::OwnerCheckFailed, "owner_check_failed: rs-1"},
    };
    for (const auto& k : kinds) {
        DYNAMIC_SECTION(k.name) {
            Rig rig;
            rig.set_rules({rule("open"), rule("scoped-a", "", "tag:grp == alpha"), rule("open2")});
            rig.scope_outcomes["alpha"] = k.outcome;
            rig.run();
            CHECK(rig.count("degraded") == 1.0);
            CHECK(rig.total() == 1.0);
            REQUIRE(rig.audits.size() == 1);
            CHECK(rig.audits[0].detail == aborted("scope store degraded", k.expected_error));
            CHECK(rig.audits[0].result == "degraded");
            CHECK(rig.sent.empty());  // NOT a narrowed push of the unscoped rules
            CHECK(rig.dispatched() == 0.0);
            CHECK(rig.generation_gauge() == 0.0);
            CHECK(rig.gate.claims_size() == 1);  // the claim is KEPT, as for a degraded store
            CHECK(rig.gate.in_flight() == 0);
            CHECK(rig.duration_count() == 1);
            CHECK(rig.eval_agents == std::vector<std::string>{"agent-1"});
        }
    }
}

TEST_CASE("GuardianReconcileFlow: scope membership is evaluated once per distinct expression per reconcile",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("a", "", "tag:grp == beta"), rule("b", "", "tag:grp == beta")});
    rig.scope_outcomes["beta"] = ScopeOutcome::Member;
    rig.run("agent-a");
    CHECK(rig.eval_calls == 1);
    rig.clock.advance(30s);
    rig.run("agent-a");
    CHECK(rig.eval_calls == 2);  // never cached across reconciles
}

TEST_CASE("GuardianReconcileFlow: a successful reconcile pushes exactly the applicable rules, labelled with the FRESH generation",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("all-os"), rule("lin", "linux"), rule("win", "windows"),
                   rule("scope-in", "", "tag:grp == inside"), rule("scope-out", "", "tag:grp == outside"),
                   rule("off", "", "", /*enabled=*/false)});
    rig.scope_outcomes["inside"] = ScopeOutcome::Member;
    rig.scope_outcomes["outside"] = ScopeOutcome::NotMember;
    // A rule that exists but whose Baseline is not deployed never reaches the agent.
    rig.rules.push_back(rule("undeployed"));
    std::uint64_t fresh = 9;
    SECTION("cached and fresh agree") { fresh = 7; }
    SECTION("the cached read is stale-low") { fresh = 9; }
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        return n == 1 ? 7 : fresh;
    };

    const auto wall_secs = [] {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    };
    const auto ts_before = wall_secs();
    rig.run("agent-1", 3);
    const auto ts_after = wall_secs();

    REQUIRE(rig.sent.size() == 1);
    const auto& sp = rig.sent[0];
    CHECK(sp.agent_id == "agent-1");
    const auto push = parse_push(sp.bytes);
    CHECK(rule_ids(push) == std::vector<std::string>{"all-os", "lin", "scope-in"});
    CHECK(push.full_sync());
    CHECK(push.policy_generation() == fresh);
    CHECK(sp.command_id == "__guard__-reconcile-" + std::to_string(fresh) + "-sfx1");

    CHECK(rig.count("sent") == 1.0);
    CHECK(rig.total() == 1.0);
    CHECK(rig.dispatched() == 1.0);
    CHECK(rig.generation_gauge() == static_cast<double>(fresh));

    REQUIRE(rig.audits.size() == 1);
    const auto& ev = rig.audits[0];
    CHECK(ev.detail == "heartbeat reconcile re-push (generation 3 -> " + std::to_string(fresh) + ")");
    CHECK(ev.result == "success");
    CHECK(ev.principal == "system");
    CHECK(ev.action == "guaranteed_state.reconcile");
    CHECK(ev.target_type == "GuaranteedState");
    CHECK(ev.target_id == "agent-1");
    // A plausible wall-clock stamp, like the abort row's: inside the window the call ran in.
    CHECK(ev.timestamp >= ts_before);
    CHECK(ev.timestamp <= ts_after);
    CHECK(ev.timestamp > 0);
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
}

TEST_CASE("GuardianReconcileFlow: a failed send counts, gauges and audits nothing", "[guardian][reconcile_flow]") {
    Rig rig;
    rig.send_result = false;
    rig.run();
    REQUIRE(rig.sent.size() == 1);  // it was attempted
    CHECK(rig.total() == 0.0);       // documented: a send that fails has no label of any kind
    CHECK(rig.dispatched() == 0.0);
    CHECK(rig.generation_gauge() == 0.0);
    CHECK(rig.audits.empty());
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK(rig.gate.claims_size() == 1);  // the claim is kept: at most one attempt per interval
    CHECK(rig.suffix_calls == 1);
}

TEST_CASE("GuardianReconcileFlow: the rule bundle is keyed by the FRESH generation, never the cached one",
          "[guardian][reconcile_flow]") {
    Rig rig;
    // The cached read says 7 (what the decision used); the fresh read says 9 (what labels the
    // push and keys the bundle).
    rig.on_fetch = [](int n) -> GuardianGenerationCache::Result { return n == 1 ? 7 : 9; };
    rig.set_rules({rule("fresh-only")});
    // A bundle for the CACHED generation is already held, with different rules. Keying the
    // lookup by `current` would hit it and push generation 7's rules under generation 9's label.
    const auto stale = rig.bundle_cache.get(
        7, []() -> std::expected<guardian::Bundle, guardian::BundleLoadError> {
            return guardian::make_bundle({rule("stale-only")}, {"stale-only"});
        });
    REQUIRE(stale.has_value());
    REQUIRE(rig.bundle_cache.held_generation() == 7);

    rig.run("agent-1", 3);

    REQUIRE(rig.sent.size() == 1);
    const auto push = parse_push(rig.sent[0].bytes);
    CHECK(rule_ids(push) == std::vector<std::string>{"fresh-only"});
    CHECK(push.policy_generation() == 9);
    CHECK(rig.list_calls == 1);  // the held generation-7 bundle was a miss for generation 9
    CHECK(rig.bundle_cache.held_generation() == 9);
}

TEST_CASE("GuardianReconcileFlow: after a scope store degrades no later scoped rule is evaluated",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("a", "", "tag:grp == alpha"), rule("b", "", "tag:grp == beta"),
                   rule("c", "", "tag:grp == alpha")});
    rig.scope_outcomes["alpha"] = ScopeOutcome::StoreDegraded;
    rig.scope_outcomes["beta"] = ScopeOutcome::Member;
    rig.run();
    CHECK(rig.count("degraded") == 1.0);
    CHECK(rig.sent.empty());
    // One probe found the store down; probing it again for every remaining rule would multiply
    // the load on a store that has just failed.
    CHECK(rig.eval_calls == 1);
}

TEST_CASE("GuardianReconcileFlow: an unparseable scope expression is not a member and is never evaluated",
          "[guardian][reconcile_flow]") {
    Rig rig;
    // "== == ==" does not parse, so the bundle holds no expression for it. A null scope read as
    // "member" would arm a rule whose targeting nobody could read.
    rig.set_rules({rule("open"), rule("broken", "", "== == =="), rule("scoped-in", "", "tag:grp == beta")});
    rig.scope_outcomes["beta"] = ScopeOutcome::Member;
    rig.run();
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"open", "scoped-in"});
    CHECK(rig.eval_calls == 1);  // only the parseable expression reached the evaluator
    CHECK(rig.count("sent") == 1.0);
    CHECK(rig.count("degraded") == 0.0);
}

TEST_CASE("GuardianReconcileFlow: a NOT-member verdict is cached across rules sharing the expression",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("open"), rule("a", "", "tag:grp == nobody"), rule("b", "", "tag:grp == nobody"),
                   rule("c", "", "tag:grp == nobody")});
    rig.scope_outcomes["nobody"] = ScopeOutcome::NotMember;
    rig.run();
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"open"});
    // The false verdict is memoised too, not only a true one: three rules, one evaluation.
    CHECK(rig.eval_calls == 1);
}

// ---------------------------------------------------------------------------------------
// Chaos scenarios (#5513 Gate 8): C7 (a rule edit whose generation bump failed), C2 (a bump
// during a tag-store outage) and C5 (a replica restart).
// ---------------------------------------------------------------------------------------

TEST_CASE("GuardianReconcileFlow: C7, a rule edit whose bump failed is served from the reloaded rules once both caches are invalidated",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.run("agent-1", 0);  // loads and holds the bundle for generation 7
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"r1"});
    REQUIRE(rig.list_calls == 1);

    // An operator adds r2 on this replica; the row commits, but the generation bump fails, so
    // the stored generation is still 7 and nothing keyed by it can notice.
    rig.set_rules({rule("r1"), rule("r2")});
    rig.clock.advance(1s);

    // WITHOUT the invalidation a brand-new agent (generation 0) is answered from the held
    // pre-edit bundle, labelled with the current generation, and is then converged for good.
    rig.run("agent-2", 0);
    REQUIRE(rig.sent.size() == 2);
    CHECK(rule_ids(parse_push(rig.sent[1].bytes)) == std::vector<std::string>{"r1"});
    CHECK(rig.list_calls == 1);

    // What GuaranteedStateStore::set_on_rule_mutation is wired to do (server.cpp; pinned by the
    // lexical gate): drop the cached generation and the held bundle.
    rig.gen_cache.invalidate();
    rig.bundle_cache.invalidate();

    rig.run("agent-3", 0);
    REQUIRE(rig.sent.size() == 3);
    CHECK(rule_ids(parse_push(rig.sent[2].bytes)) == std::vector<std::string>{"r1", "r2"});
    CHECK(parse_push(rig.sent[2].bytes).policy_generation() == 7);
    CHECK(rig.list_calls == 2);  // the invalidation forced exactly one reload
}

namespace {

// The audit text of the abort the epoch check raises.
std::string invalidated_abort(std::uint64_t agent_gen = 3) {
    return aborted("rule bundle invalidated during load",
                   "a rule or policy change landed while the re-push was being prepared; "
                   "retried on a later heartbeat",
                   agent_gen);
}

}  // namespace

TEST_CASE("GuardianReconcileFlow: C1, a bundle an invalidation overtook is not sent under the unchanged generation",
          "[guardian][reconcile_flow]") {
    // A rule edit commits after this reconcile's load read its rows; the edit's best-effort
    // generation bump FAILS (the stored generation stays 7), and the store hook invalidates both
    // caches while the load is still running. GuardianRuleBundleCache::get() still hands the
    // pre-edit rows to this caller, so only the flow's own epoch check stands between them and
    // an agent that would then report generation 7 and stay converged on them.
    Rig rig;
    bool fired = false;
    rig.list_hook = [&] {
        if (std::exchange(fired, true))
            return;
        rig.gen_cache.invalidate();
        rig.bundle_cache.invalidate();
    };

    rig.run("agent-1", 0);

    CHECK(rig.sent.empty());  // NOTHING is sent
    CHECK(rig.dispatched() == 0.0);
    CHECK(rig.generation_gauge() == 0.0);
    CHECK(rig.count("degraded") == 0.0);  // no store failed: the degraded series does not move
    CHECK(rig.total() == 0.0);            // and no result label of reconciles_total moves at all
    CHECK(rig.invalidated() == 1.0);      // the dedicated counter does
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail == invalidated_abort(0));
    CHECK(rig.audits[0].result == "degraded");  // the audit row keeps the documented shape
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.duration_count() == 1);
    CHECK_FALSE(rig.bundle_cache.held_generation().has_value());  // the late load installed nothing

    // The claim is KEPT: a heartbeat inside the young-claim window is rate limited, not admitted.
    rig.run("agent-1", 0);
    CHECK(rig.count("rate_limited") == 1.0);
    CHECK(rig.invalidated() == 1.0);  // a rate-limited heartbeat is not counted again
    CHECK(rig.sent.empty());
    CHECK(rig.list_calls == 1);

    // The edit has committed by now. Once the claim is old enough the agent is admitted again,
    // loads afresh, and receives the NEW rows under the same generation.
    rig.set_rules({rule("r1"), rule("r2")});
    rig.clock.advance(26s);
    rig.run("agent-1", 0);
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"r1", "r2"});
    CHECK(parse_push(rig.sent[0].bytes).policy_generation() == 7);
    CHECK(rig.list_calls == 2);
    CHECK(rig.count("sent") == 1.0);
    CHECK(rig.invalidated() == 1.0);
}

TEST_CASE("GuardianReconcileFlow: C1, an invalidation during the fresh generation read also aborts",
          "[guardian][reconcile_flow]") {
    // The epoch is read before the fresh generation, so a change landing anywhere from that
    // point on is seen. Conservative on purpose: the bundle loaded afterwards would have been
    // current, but one window covering the whole read-label-load sequence is simpler to reason
    // about than two.
    Rig rig;
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        if (n == 2)
            rig.bundle_cache.invalidate();  // the fresh generation read
        return 7;
    };
    // A NONZERO agent generation, so an audit row that reported the wrong generation (the
    // fresh one, or none) is caught on this family too.
    rig.run("agent-1", 3);
    CHECK(rig.sent.empty());
    CHECK(rig.count("degraded") == 0.0);
    CHECK(rig.invalidated() == 1.0);
    CHECK(rig.gate.in_flight() == 0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail == invalidated_abort(3));
}

TEST_CASE("GuardianReconcileFlow: C1, an invalidation during scope evaluation also aborts",
          "[guardian][reconcile_flow]") {
    // Scope reads can take seconds; the comparison sits right before the send so that window is
    // covered too, not only the bundle load.
    Rig rig;
    rig.set_rules({rule("open"), rule("scoped", "", "tag:grp == inside")});
    rig.scope_outcomes["inside"] = ScopeOutcome::Member;
    rig.eval_hook = [&] { rig.bundle_cache.invalidate(); };
    rig.run("agent-1", 5);
    REQUIRE(rig.eval_calls == 1);  // the push was fully prepared...
    CHECK(rig.sent.empty());       // ...and then withheld
    CHECK(rig.count("degraded") == 0.0);
    CHECK(rig.invalidated() == 1.0);
    CHECK(rig.count("sent") == 0.0);
    CHECK(rig.gate.in_flight() == 0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail == invalidated_abort(5));
}

TEST_CASE("GuardianReconcileFlow: C1, an invalidation BEFORE the reconcile starts does not abort it",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.run("agent-1", 0);  // loads and holds the bundle
    REQUIRE(rig.sent.size() == 1);
    rig.gen_cache.invalidate();
    rig.bundle_cache.invalidate();
    rig.run("agent-2", 0);  // a later reconcile reads the new epoch and is not affected
    REQUIRE(rig.sent.size() == 2);
    CHECK(rig.count("degraded") == 0.0);
    CHECK(rig.invalidated() == 0.0);
    CHECK(rig.audits.size() == 2);  // the two success rows only
    CHECK(rig.audits[1].result == "success");
}

TEST_CASE("GuardianReconcileFlow: C1, the owner of a detached load and a waiter that joined it both abort",
          "[guardian][reconcile_flow]") {
    // get() hands the detached flight's result to its owner AND to every waiter that had joined
    // it, so each of them must reach the abort on its own epoch comparison.
    Rig rig;
    std::mutex m;
    std::condition_variable cv;
    bool release = false;
    std::promise<void> entered;
    auto entered_f = entered.get_future();
    std::promise<void> joined;
    auto joined_f = joined.get_future();
    std::atomic<std::thread::id> waiter_thread{};
    int waiter_clock_calls = 0;  // touched only by the waiter thread
    // Only the owner runs the loader.
    rig.list_hook = [&] {
        entered.set_value();
        std::unique_lock lk(m);
        // Bounded so a regression fails the test instead of hanging it.
        cv.wait_for(lk, 10s, [&] { return release; });
    };
    // The waiter's SECOND bundle-cache clock read is `t0`, taken right after it joined the flight
    // and before it blocks. The Rig reads the manual clock BEFORE it runs this hook, so `t0`
    // is already fixed when the hook advances time: the advance below is therefore seen only
    // by the waiter's post-wait read, on the waiter's own thread and in program order (no race
    // with `t0`), and its `waited` is exactly 1 s as in production. The hook then signals; the
    // cache must not be re-entered from its own clock, so the test thread does the invalidate.
    rig.bundle_clock_hook = [&] {
        if (std::this_thread::get_id() != waiter_thread.load())
            return;
        if (++waiter_clock_calls == 2) {
            rig.clock.advance(1s);
            joined.set_value();
        }
    };

    std::jthread owner([&] { rig.run("agent-owner", 0); });
    REQUIRE(entered_f.wait_for(10s) == std::future_status::ready);
    std::jthread waiter([&] {
        waiter_thread.store(std::this_thread::get_id());
        rig.run("agent-waiter", 0);
    });
    REQUIRE(joined_f.wait_for(10s) == std::future_status::ready);
    // The waiter has joined the owner's flight, is about to block, and 1 s has passed on the
    // manual clock (advanced by the hook), so its `waited` is not zero: a waiter must abort
    // exactly like the owner (a check that only the zero-wait owner performs would leave it
    // sending).
    rig.bundle_cache.invalidate();
    {
        std::lock_guard lk(m);
        release = true;
    }
    cv.notify_all();
    waiter.join();
    owner.join();

    CHECK(rig.list_calls == 1);  // the waiter never ran the loader
    CHECK(rig.sent.empty());
    CHECK(rig.count("degraded") == 0.0);
    CHECK(rig.total() == 0.0);
    CHECK(rig.invalidated() == 2.0);
    REQUIRE(rig.audits.size() == 2);
    for (const auto& a : rig.audits)
        CHECK(a.detail == invalidated_abort(0));
    CHECK(rig.gate.in_flight() == 0);
}

TEST_CASE("GuardianReconcileFlow: C2, a policy bump during a tag-store outage aborts each agent once and recovers",
          "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("open"), rule("scoped", "", "tag:grp == alpha")});
    rig.scope_outcomes["alpha"] = ScopeOutcome::StoreDegraded;

    // The bump lands (generation 7) while the tag store is down: every admitted agent aborts
    // degraded, writes ONE audit row and keeps its claim.
    for (const char* agent : {"a1", "a2", "a3"})
        rig.run(agent, 3);
    CHECK(rig.count("degraded") == 3.0);
    CHECK(rig.audits.size() == 3);
    for (const auto& ev : rig.audits)
        CHECK(ev.result == "degraded");
    CHECK(rig.sent.empty());
    CHECK(rig.gate.claims_size() == 3);

    rig.clock.advance(10s);
    rig.run("a1", 3);
    CHECK(rig.count("rate_limited") == 1.0);  // the kept claim limits the retry
    CHECK(rig.audits.size() == 3);             // and no new audit row

    // Recovery: the tag store is back. A brand-new agent (never admitted before) is pushed.
    rig.scope_outcomes["alpha"] = ScopeOutcome::Member;
    rig.run("a4", 0);
    REQUIRE(rig.sent.size() == 1);
    CHECK(rule_ids(parse_push(rig.sent[0].bytes)) == std::vector<std::string>{"open", "scoped"});
    CHECK(parse_push(rig.sent[0].bytes).policy_generation() == 7);

    // A second bump: the push path invalidates the cached generation, and the next admitted push
    // is labelled with the fresh one. a1's claim is now 25 s old, so it is admitted again.
    rig.store_generation = 8;
    rig.gen_cache.invalidate();
    rig.clock.advance(15s);
    rig.run("a1", 3);
    REQUIRE(rig.sent.size() == 2);
    CHECK(rig.sent[1].agent_id == "a1");
    CHECK(parse_push(rig.sent[1].bytes).policy_generation() == 8);
    CHECK(rig.generation_gauge() == 8.0);
}

TEST_CASE("GuardianReconcileFlow: C5, a replica restart loses the claims, and the duplicate is bounded by the budget",
          "[guardian][reconcile_flow]") {
    // The old replica pushes two agents. A restart builds a fresh gate and fresh caches for the
    // same agents. In-memory claims are per replica by design (ADR-2002), so the new replica
    // admits the same agents again inside 25 s, under a DIFFERENT command id, and only the
    // per-second ceiling stops the duplicate burst.
    Rig before;
    before.run("a1", 3);
    before.run("a2", 3);
    REQUIRE(before.sent.size() == 2);

    RigOptions o;
    o.budget = {.budget_ms_per_s = 1000.0, .burst_ms = 100'000.0, .max_per_s = 1};
    Rig after(o);
    after.suffix_base = 100;
    after.run("a1", 3);  // a duplicate full_sync inside 25 s of the first
    REQUIRE(after.sent.size() == 1);
    CHECK(after.sent[0].command_id != before.sent[0].command_id);
    CHECK(after.sent[0].agent_id == before.sent[0].agent_id);
    after.run("a2", 3);  // the second duplicate is shed: the ceiling is the bound
    CHECK(after.sent.size() == 1);
    CHECK(after.count("shed") == 1.0);
    CHECK(after.count("rate_limited") == 0.0);
}

// ---------------------------------------------------------------------------------------
// Order, budget accounting.
// ---------------------------------------------------------------------------------------

TEST_CASE("GuardianReconcileFlow: dependency calls happen in the safety order", "[guardian][reconcile_flow]") {
    Rig rig;
    rig.set_rules({rule("open"), rule("scoped", "", "tag:grp == inside")});
    rig.scope_outcomes["inside"] = ScopeOutcome::Member;
    rig.run();
    // cached generation (decision only) < session < FRESH generation (labels the push) <
    // bundle load (rules, then deployed set) < scope < send < audit.
    CHECK(rig.trace == std::vector<std::string>{"generation_read#1", "session", "generation_read#2",
                                                "list_rules", "deployed_ids", "eval_scope",
                                                "send_push", "audit"});
}

TEST_CASE("GuardianReconcileFlow: the budget is charged for the generation read and the push's own load",
          "[guardian][reconcile_flow]") {
    RigOptions o;
    // 1 ms/s refill, 10 s burst: advancing the manual clock refills ~nothing, so the balance
    // moves by what is debited.
    o.budget = {.budget_ms_per_s = 1.0, .burst_ms = 10'000.0, .max_per_s = 1000};
    Rig rig(o);
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        if (n == 2)
            rig.clock.advance(40ms);  // the fresh generation read
        return 7;
    };
    rig.list_hook = [&] { rig.clock.advance(200ms); };  // this push runs the loader itself
    rig.run();
    REQUIRE(rig.sent.size() == 1);
    // 40 ms + 200 ms charged: nothing was a wait on another thread.
    CHECK(rig.budget.balance_ms() == Catch::Approx(10'000.0 - 240.0).margin(0.01));
}

namespace {

// Drives one reconcile as the WAITER behind another thread's in-flight bundle load of the
// generation the flow will ask for (7), a load that takes 300 ms on the manual clock and ends
// in success or in the given error. The flow's fresh generation read adds 40 ms of its own.
// Deterministic: the flow thread's second bundle-cache clock read (t0, taken just before it
// blocks) releases the owner, so the 300 ms wait is neither racy nor slept.
void run_behind_slow_owner(Rig& rig, std::optional<guardian::BundleLoadError> owner_error) {
    rig.on_fetch = [&](int n) -> GuardianGenerationCache::Result {
        if (n == 2)
            rig.clock.advance(40ms);  // charged: the fresh generation read
        return 7;
    };

    std::mutex m;
    std::condition_variable cv;
    bool release = false;
    std::promise<void> entered;
    auto entered_f = entered.get_future();
    std::atomic<std::thread::id> flow_thread{};
    int flow_clock_calls = 0;  // touched only by the flow thread
    // The flow thread is the WAITER: its second bundle-cache clock read is the one taken right
    // before it blocks (t0), so releasing the owner there makes the wait deterministic. Set
    // before any thread starts.
    rig.bundle_clock_hook = [&] {
        if (std::this_thread::get_id() != flow_thread.load())
            return;
        if (++flow_clock_calls == 2) {
            std::lock_guard lk(m);
            release = true;
            cv.notify_all();
        }
    };

    // jthreads: a failed REQUIRE below unwinds through their joins instead of terminating.
    std::jthread owner([&] {
        (void)rig.bundle_cache.get(
            7, [&]() -> std::expected<guardian::Bundle, guardian::BundleLoadError> {
                entered.set_value();
                {
                    // Bounded so a flow that never waits on this load fails the test instead of
                    // hanging it (the waiter's clock read is what releases us).
                    std::unique_lock lk(m);
                    cv.wait_for(lk, 10s, [&] { return release; });
                }
                rig.clock.advance(300ms);
                if (owner_error)
                    return std::unexpected(*owner_error);
                return guardian::make_bundle({rule("r1")}, {"r1"});
            });
    });
    REQUIRE(entered_f.wait_for(10s) == std::future_status::ready);

    std::jthread flow_runner([&] {
        flow_thread.store(std::this_thread::get_id());
        rig.run();
    });
    flow_runner.join();
    owner.join();
}

}  // namespace

TEST_CASE("GuardianReconcileFlow: only the wait on ANOTHER thread's load is excluded from the debit",
          "[guardian][reconcile_flow]") {
    RigOptions o;
    o.budget = {.budget_ms_per_s = 1.0, .burst_ms = 10'000.0, .max_per_s = 1000};
    Rig rig(o);
    run_behind_slow_owner(rig, std::nullopt);

    REQUIRE(rig.sent.size() == 1);
    CHECK(rig.list_calls == 0);  // the waiter never ran the loader
    // 340 ms elapsed, 300 ms of it spent blocked on the other thread: only the 40 ms read.
    CHECK(rig.budget.balance_ms() == Catch::Approx(10'000.0 - 40.0).margin(0.01));
}

TEST_CASE("GuardianReconcileFlow: the wait is excluded from the debit when the awaited load FAILS",
          "[guardian][reconcile_flow]") {
    // The exclusion is applied on every outcome of the bundle get, not only a successful one:
    // a failing store with many waiters is exactly when the budget must not be starved by
    // time that was never this push's work.
    RigOptions o;
    o.budget = {.budget_ms_per_s = 1.0, .burst_ms = 10'000.0, .max_per_s = 1000};
    Rig rig(o);
    run_behind_slow_owner(rig, guardian::BundleLoadError{guardian::BundleLoadError::Source::rules,
                                                         "owner load failed"});

    CHECK(rig.sent.empty());
    CHECK(rig.list_calls == 0);  // the waiter never ran the loader
    CHECK(rig.count("degraded") == 1.0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail == aborted("rule store degraded", "owner load failed"));
    CHECK(rig.gate.in_flight() == 0);
    CHECK(rig.budget.balance_ms() == Catch::Approx(10'000.0 - 40.0).margin(0.01));
}

// ---------------------------------------------------------------------------------------
// Properties over every exit path.
// ---------------------------------------------------------------------------------------

namespace {

struct Scenario {
    const char* name;
    RigOptions opts;
    std::function<void(Rig&)> setup;  // earlier state and calls; not measured
    bool admitted;                    // does the measured call get past Admit?
    double labels;                    // result-label increments the measured call must make
    double invalidated{0};            // increments of the dedicated invalidated counter
};

std::vector<Scenario> all_exits() {
    RigOptions budget_shed;
    budget_shed.budget = {.budget_ms_per_s = 1000.0, .burst_ms = 100'000.0, .max_per_s = 1};
    RigOptions cap_shed;
    cap_shed.gate.max_in_flight = 1;
    RigOptions converged;
    converged.store_generation = 3;

    return {
        {"store unwired", {}, [](Rig& r) { r.store_wired = false; }, false, 0},
        {"cached generation unreadable", {}, [](Rig& r) { r.gen_error = "pg down"; }, false, 1},
        {"converged", converged, [](Rig&) {}, false, 0},
        {"rate limited", {}, [](Rig& r) { r.run(); }, false, 1},
        {"shed by budget", budget_shed, [](Rig& r) { r.run("other-agent"); }, false, 1},
        {"shed by in-flight cap", cap_shed, [](Rig& r) { r.hold_slot(); }, false, 1},
        {"no session", {}, [](Rig& r) { r.session_os = std::nullopt; }, true, 1},
        {"fresh generation unreadable",
         {},
         [](Rig& r) {
             r.on_fetch = [](int n) -> GuardianGenerationCache::Result {
                 if (n == 1)
                     return 7;
                 return std::unexpected(std::string("pg down"));
             };
         },
         true,
         1},
        {"fresh generation not ahead",
         {},
         [](Rig& r) {
             r.on_fetch = [](int n) -> GuardianGenerationCache::Result { return n == 1 ? 7 : 3; };
         },
         true,
         0},
        {"rule store degraded", {}, [](Rig& r) { r.rules_error = "x"; }, true, 1},
        {"baseline store degraded", {}, [](Rig& r) { r.deployed_error = "x"; }, true, 1},
        {"bundle load throws", {}, [](Rig& r) { r.rules_throw = true; }, true, 1},
        {"bundle invalidated during the load",
         {},
         [](Rig& r) { r.list_hook = [&r] { r.bundle_cache.invalidate(); }; },
         true,
         0,  // no result label: it has its own counter
         1},
        {"scope store degraded",
         {},
         [](Rig& r) {
             r.set_rules({rule("a", "", "tag:grp == bad")});
             r.scope_outcomes["bad"] = ScopeOutcome::StoreDegraded;
         },
         true,
         1},
        {"scope unresolvable",
         {},
         [](Rig& r) {
             r.set_rules({rule("a", "", "tag:grp == ghost")});
             r.scope_outcomes["ghost"] = ScopeOutcome::Unresolvable;
         },
         true,
         1},
        {"success", {}, [](Rig&) {}, true, 1},
        {"send fails", {}, [](Rig& r) { r.send_result = false; }, true, 0},
    };
}

}  // namespace

TEST_CASE("GuardianReconcileFlow: every exit path makes at most one result increment, releases its slot, and observes the duration only after admission",
          "[guardian][reconcile_flow]") {
    for (auto& sc : all_exits()) {
        DYNAMIC_SECTION(sc.name) {
            Rig rig(sc.opts);
            sc.setup(rig);
            const double labels_before = rig.total();
            const double invalidated_before = rig.invalidated();
            const auto durations_before = rig.duration_count();
            const auto admitted_before = rig.budget.admitted_total();
            const auto held = rig.held.has_value() ? 1u : 0u;
            const double balance_before = rig.budget.balance_ms();
            rig.trace.clear();
            rig.inflight_at.clear();

            rig.run();

            // An admitted exit, however early, charges at least min_cost (1 ms) on a path that
            // takes no manual-clock time; a non-admitted exit charges nothing. The clock is
            // static here, so the balance moves only by what is debited.
            const double debited = balance_before - rig.budget.balance_ms();
            CHECK(debited == Catch::Approx(sc.admitted ? 1.0 : 0.0).margin(0.01));

            // The in-flight slot is held from admission: every stub from the session lookup on
            // sees one more than the test itself holds, and nothing before it does.
            REQUIRE(rig.trace.size() == rig.inflight_at.size());
            const auto session_at = std::find(rig.trace.begin(), rig.trace.end(), "session");
            CHECK((session_at != rig.trace.end()) == sc.admitted);
            for (std::size_t i = 0; i < rig.trace.size(); ++i) {
                const bool after_admission =
                    session_at != rig.trace.end() &&
                    i >= static_cast<std::size_t>(session_at - rig.trace.begin());
                INFO("stub " << rig.trace[i]);
                CHECK(rig.inflight_at[i] == held + (after_admission ? 1u : 0u));
            }

            const double delta = rig.total() - labels_before;
            CHECK(delta + (rig.invalidated() - invalidated_before) <= 1.0);  // one outcome per call
            CHECK(delta == sc.labels);
            CHECK(rig.invalidated() - invalidated_before == sc.invalidated);
            CHECK(rig.duration_count() - durations_before == (sc.admitted ? 1u : 0u));
            CHECK(rig.budget.admitted_total() - admitted_before == (sc.admitted ? 1u : 0u));
            CHECK(rig.gate.in_flight() == held);  // only a slot the test itself holds remains
        }
    }
}

// ---------------------------------------------------------------------------------------
// A dependency that throws after admission. The flow has no catch of its own, so the exception
// PROPAGATES to the caller (the heartbeat thread); what the flow guarantees on the unwind is
// that the RAII pieces still run: the in-flight slot is released, the measured time is debited,
// the duration is observed once, and the claim Admit wrote stays (so the agent is not
// re-admitted on its next heartbeat inside the interval).
// ---------------------------------------------------------------------------------------

namespace {

struct ThrowCase {
    const char* name;
    std::function<void(Rig&)> arm;     // make one dependency throw
    std::function<void(Rig&)> disarm;  // undo it, for the recovery run
    double sent_label;                 // result="sent" increments before the throw
    double degraded_label;             // result="degraded" increments before the throw
    std::size_t pushes;                // pushes recorded as delivered before the throw
};

const auto kBoom = [] { throw std::runtime_error("injected dependency failure"); };

std::vector<ThrowCase> throwing_dependencies() {
    return {
        {"session_os throws",
         [](Rig& r) { r.session_hook = kBoom; },
         [](Rig& r) { r.session_hook = nullptr; }, 0.0, 0.0, 0},
        {"eval_scope throws",
         [](Rig& r) {
             r.set_rules({rule("scoped", "", "tag:grp == alpha")});
             r.eval_hook = kBoom;
         },
         [](Rig& r) { r.eval_hook = nullptr; }, 0.0, 0.0, 0},
        {"random_suffix throws",
         [](Rig& r) { r.suffix_hook = kBoom; },
         [](Rig& r) { r.suffix_hook = nullptr; }, 0.0, 0.0, 0},
        {"send_push throws",
         [](Rig& r) { r.send_hook = kBoom; },
         [](Rig& r) { r.send_hook = nullptr; }, 0.0, 0.0, 0},
        // The send already happened and was counted when the success audit row throws.
        {"audit throws on the success row",
         [](Rig& r) { r.audit_hook = kBoom; },
         [](Rig& r) { r.audit_hook = nullptr; }, 1.0, 0.0, 1},
        // abort_degraded counts first, then audits.
        {"audit throws on an ABORTED row",
         [](Rig& r) {
             r.rules_error = "list_rules sql error";
             r.audit_hook = kBoom;
         },
         [](Rig& r) {
             r.rules_error = std::nullopt;
             r.audit_hook = nullptr;
         },
         0.0, 1.0, 0},
    };
}

}  // namespace

TEST_CASE("GuardianReconcileFlow: a dependency that throws after admission still releases its slot, "
          "debits the budget, observes the duration once and keeps the claim",
          "[guardian][reconcile_flow]") {
    for (const auto& c : throwing_dependencies()) {
        DYNAMIC_SECTION(c.name) {
            Rig rig;
            c.arm(rig);
            const double balance_before = rig.budget.balance_ms();

            CHECK_THROWS_AS(rig.run(), std::runtime_error);

            CHECK(rig.gate.in_flight() == 0);  // the Scoped slot is released on unwind
            CHECK(rig.budget.admitted_total() == 1);
            // The clock is static, so the balance moves only by the debit: min_cost (1 ms).
            CHECK(balance_before - rig.budget.balance_ms() == Catch::Approx(1.0).margin(0.01));
            CHECK(rig.duration_count() == 1);  // observed once, by the destructor
            CHECK(rig.gate.claims_size() == 1);  // the claim Admit wrote is kept
            CHECK(rig.count("sent") == c.sent_label);
            CHECK(rig.count("degraded") == c.degraded_label);
            CHECK(rig.total() == c.sent_label + c.degraded_label);
            CHECK(rig.sent.size() == c.pushes);
            CHECK(rig.audits.empty());  // the throwing sink recorded nothing

            // The failure left nothing stuck: the kept claim limits the next heartbeat, and once
            // the interval has passed the same agent is admitted and pushed again.
            c.disarm(rig);
            rig.clock.advance(1s);
            rig.run();
            CHECK(rig.count("rate_limited") == 1.0);
            CHECK(rig.duration_count() == 1);  // a rate-limited exit is not an admitted one
            rig.clock.advance(30s);
            rig.run();
            CHECK(rig.budget.admitted_total() == 2);
            CHECK(rig.duration_count() == 2);
            CHECK(rig.sent.size() == c.pushes + 1);
            CHECK(rig.gate.in_flight() == 0);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------------------

TEST_CASE("GuardianReconcileFlow: construction rejects every empty required dependency, naming it",
          "[guardian][reconcile_flow]") {
    using Deps = GuardianReconcileFlowDeps;
    struct Case {
        const char* name;
        std::function<void(Deps&)> empty_it;
    };
    const Case cases[] = {
        {"duration", [](Deps& d) { d.duration = nullptr; }},
        {"store_wired", [](Deps& d) { d.store_wired = nullptr; }},
        {"list_rules", [](Deps& d) { d.list_rules = nullptr; }},
        {"deployed_ids", [](Deps& d) { d.deployed_ids = nullptr; }},
        {"session_os", [](Deps& d) { d.session_os = nullptr; }},
        {"eval_scope", [](Deps& d) { d.eval_scope = nullptr; }},
        {"send_push", [](Deps& d) { d.send_push = nullptr; }},
        {"random_suffix", [](Deps& d) { d.random_suffix = nullptr; }},
    };
    Rig rig;
    for (const auto& c : cases) {
        DYNAMIC_SECTION(c.name) {
            auto deps = rig.make_deps();
            c.empty_it(deps);
            CHECK_THROWS_AS(GuardianReconcileFlow(std::move(deps)), std::invalid_argument);
            auto deps2 = rig.make_deps();
            c.empty_it(deps2);
            CHECK_THROWS_WITH(GuardianReconcileFlow(std::move(deps2)),
                              Catch::Matchers::ContainsSubstring(c.name));
        }
    }
}

TEST_CASE("GuardianReconcileFlow: audit and now are optional and default", "[guardian][reconcile_flow]") {
    Rig rig;
    auto deps = rig.make_deps();
    deps.audit = nullptr;  // empty = discard
    deps.now = nullptr;    // empty = steady_clock::now
    GuardianReconcileFlow flow(std::move(deps));
    flow.run("agent-1", 3);  // a full successful reconcile with the defaults
    CHECK(rig.sent.size() == 1);
    CHECK(rig.audits.empty());
}
