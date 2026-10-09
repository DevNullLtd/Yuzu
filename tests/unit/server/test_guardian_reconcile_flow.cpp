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

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

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

enum class ScopeOutcome { Member, NotMember, Unresolvable, StoreDegraded };

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
                           if (bundle_clock_hook)
                               bundle_clock_hook();
                           return clock.now();
                       }),
          store_generation(o.store_generation) {
        duration = &metrics.histogram("yuzu_server_guardian_reconcile_duration_seconds",
                                      std::vector<double>{0.0001, 0.001, 0.01, 0.1, 1.0, 10.0});
        set_rules({rule("r1")});
        flow = std::make_unique<GuardianReconcileFlow>(GuardianReconcileFlowDeps{
            .gate = gate,
            .generation_cache = gen_cache,
            .rule_bundle_cache = bundle_cache,
            .budget = budget,
            .metrics = metrics,
            .duration = duration,
            .store_wired = [this] { return store_wired; },
            .list_rules = [this]() -> std::expected<std::vector<GuaranteedStateRuleRow>,
                                                    std::string> {
                ++list_calls;
                trace.push_back("list_rules");
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
                ++deployed_calls;
                trace.push_back("deployed_ids");
                if (deployed_error)
                    return std::unexpected(*deployed_error);
                return deployed;
            },
            .session_os = [this](const std::string& agent_id) -> std::optional<std::string> {
                trace.push_back("session");
                session_agents.push_back(agent_id);
                return session_os;
            },
            .eval_scope = [this](const std::string& agent_id,
                                 const yuzu::scope::Expression& expr)
                -> std::expected<bool, ScopeEvalError> {
                ++eval_calls;
                trace.push_back("eval_scope");
                eval_agents.push_back(agent_id);
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
                }
                return false;
            },
            .send_push = [this](const std::string& agent_id, const std::string& command_id,
                                const std::string& bytes) {
                trace.push_back("send_push");
                sent.push_back({agent_id, command_id, bytes});
                return send_result;
            },
            .audit = [this](const AuditEvent& ev) {
                trace.push_back("audit");
                audits.push_back(ev);
            },
            .random_suffix = [this] { return "sfx" + std::to_string(++suffix_calls); },
            .now = shed_clock.fn()});
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

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
    std::function<void()> bundle_clock_hook;

    // ---- recorded effects ----
    std::vector<std::string> trace;
    std::vector<std::string> session_agents;
    std::vector<std::string> eval_agents;
    std::vector<SentPush> sent;
    std::vector<AuditEvent> audits;
    int fetch_calls{0};
    int list_calls{0};
    int deployed_calls{0};
    int eval_calls{0};
    int suffix_calls{0};

    std::unique_ptr<GuardianReconcileFlow> flow;
    std::optional<GuardianReconcileGate::Scoped> held;  // destroyed before the gate

private:
    GuardianGenerationCache::Result fetch_generation() {
        ++fetch_calls;
        trace.push_back("generation_read#" + std::to_string(fetch_calls));
        if (on_fetch)
            return on_fetch(fetch_calls);
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
        CHECK(log.count("replica admission budget exhausted") == 1);
        CHECK(log.count("in-flight reconcile cap reached") == 0);
        CHECK(log.count("1 shed so far") == 1);

        rig.shed_clock.advance(59s);
        rig.run("agent-b");
        CHECK(log.count("replica admission budget exhausted") == 1);  // still inside the minute

        rig.shed_clock.advance(1s);  // 60 s since the last line
        rig.run("agent-b");
        CHECK(log.count("replica admission budget exhausted") == 2);
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
        CHECK(log.count("replica admission budget exhausted") == 0);
        CHECK(rig.count("shed") == 2.0);
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

    rig.run("agent-1", 3);

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

TEST_CASE("GuardianReconcileFlow: only the wait on ANOTHER thread's load is excluded from the debit",
          "[guardian][reconcile_flow]") {
    RigOptions o;
    o.budget = {.budget_ms_per_s = 1.0, .burst_ms = 10'000.0, .max_per_s = 1000};
    Rig rig(o);
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

    // The owner: another thread's in-flight load of generation 7, 300 ms long on the clock.
    std::thread owner([&] {
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
                return guardian::make_bundle({rule("r1")}, {"r1"});
            });
    });
    entered_f.wait();

    std::thread flow_runner([&] {
        flow_thread.store(std::this_thread::get_id());
        rig.run();
    });
    flow_runner.join();
    owner.join();

    REQUIRE(rig.sent.size() == 1);
    CHECK(rig.list_calls == 0);  // the waiter never ran the loader
    // 340 ms elapsed, 300 ms of it spent blocked on the other thread: only the 40 ms read.
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
            const auto durations_before = rig.duration_count();
            const auto admitted_before = rig.budget.admitted_total();
            const auto held = rig.held.has_value() ? 1u : 0u;

            rig.run();

            const double delta = rig.total() - labels_before;
            CHECK(delta <= 1.0);
            CHECK(delta == sc.labels);
            CHECK(rig.duration_count() - durations_before == (sc.admitted ? 1u : 0u));
            CHECK(rig.budget.admitted_total() - admitted_before == (sc.admitted ? 1u : 0u));
            CHECK(rig.gate.in_flight() == held);  // only a slot the test itself holds remains
        }
    }
}
