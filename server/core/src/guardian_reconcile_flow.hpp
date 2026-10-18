#pragma once

/// @file guardian_reconcile_flow.hpp
/// The Guardian heartbeat reconcile control flow (#5513), extracted from the lambda that
/// `ServerImpl` passes to `HeartbeatIngestion::set_guardian_reconcile_fn` so that its ordering,
/// early returns, one-metric-label-per-exit property, abort paths and audit rows are unit
/// tested (tests/unit/server/test_guardian_reconcile_flow.cpp) instead of being guarded only by
/// the lexical gate (tests/test_guardian_reconcile_wiring_lexical.py).
///
/// `run()` is the control flow of that lambda, extracted so it can be unit tested. Only the
/// dependencies that are NOT header-only value collaborators are injected, as nine callables
/// (`store_wired`, `list_rules`, `deployed_ids`, `session_os`, `eval_scope`, `send_push`,
/// `audit`, `random_suffix`, `now`) plus the `duration` histogram pointer. `now` is the one
/// injected clock, and it drives the shed-log throttle only: the `DurationObserver` reads
/// `steady_clock::now()` directly (and observes into `duration`), and the audit timestamps read
/// `system_clock::now()` directly.
///
/// WHAT STAYS IN server.cpp (deliberately, because it is security-relevant wiring and not
/// control flow): the `DispatchCaller{.system = true}` construction and the
/// `build_classified_command` / `send_system_reserved` / `forward_gateway_pending` sequence
/// behind `send_push` (a push is `system_reserved`, deliberately NOT quarantine-gated, see
/// dispatch_confined_arms.hpp); the `audit_store_ && audit_store_->is_open()` check behind
/// `audit`; and the `registry_.evaluate_scope_for_agent` call (with the tag and custom-property
/// stores) behind `eval_scope`.
///
/// LIFETIME. Every reference handed to the constructor must outlive the flow. In production
/// they are `ServerImpl` members. The five references (gate, generation cache, rule bundle
/// cache, budget, metrics) are borrowed, not owned. The four guardian members and the two
/// stores are declared ABOVE `heartbeat_ingestion_` (the only holder of the flow, through the
/// lambda), so they are destroyed after it. Invariant (aa) of
/// tests/test_guardian_reconcile_wiring_lexical.py pins that order for the four guardian
/// members it references (budget, gate, generation cache, rule bundle cache) and for the two
/// stores' position above the caches; `metrics_` is a long-lived earlier member and is not
/// pinned. NOT every collaborator is declared above it: `custom_properties_store_` (read
/// through `eval_scope`) is declared BELOW `heartbeat_ingestion_` and is safe only because
/// `ServerImpl::stop()` resets it after the gRPC and HTTP drains, once no heartbeat thread can
/// call the flow. The callables are `[this]`-capturing lambdas stored for the flow's lifetime
/// (`store_wired`, `list_rules`, `deployed_ids`, `session_os`, `session_id`, `eval_scope`,
/// `send_push`, `audit`) and run on heartbeat threads; their safety rests on that same
/// shutdown order (servers drained before any store is reset).
///
/// Thread-safe to the extent its collaborators are: `run()` is called concurrently from every
/// heartbeat thread and holds no state of its own except the shed-log throttle atomic.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "audit_store.hpp"
#include "guardian_generation_cache.hpp"
#include "guardian_push_builder.hpp"
#include "guardian_reconcile_budget.hpp"
#include "guardian_reconcile_gate.hpp"
#include "guardian_rule_bundle.hpp"
#include "scope_eval_error.hpp"

namespace yuzu::server {

/// Everything the flow reads that is not constructed by it. The references are the
/// header-only collaborators (concrete, so a test drives the real gate, caches and budget with
/// manual clocks); the callables are the pieces that stay in `ServerImpl`. Every callable except
/// `audit` and `now` is required, and so is `duration`: the constructor throws
/// `std::invalid_argument` naming an empty (or null) one.
struct GuardianReconcileFlowDeps {
    GuardianReconcileGate& gate;
    GuardianGenerationCache& generation_cache;
    guardian::GuardianRuleBundleCache& rule_bundle_cache;
    /// Read only for `shed_total()` in the shed log line.
    GuardianReconcileBudget& budget;
    ::yuzu::MetricsRegistry& metrics;
    /// Observed once per ADMITTED reconcile, on every exit. Must outlive the flow.
    ::yuzu::Histogram* duration;

    /// `guaranteed_state_store_` is non-null. Checked at the top of `run()` and again inside
    /// the bundle loader (the store pointer is reset by `stop()`).
    std::function<bool()> store_wired;
    /// The rule-row and deployed-id reads `guardian::load_reconcile_bundle` consumes.
    guardian::RuleRowsSource list_rules;
    guardian::DeployedIdsSource deployed_ids;
    /// The agent's session OS token; `nullopt` = no session. (`registry_.get_session`.)
    std::function<std::optional<std::string>(const std::string& agent_id)> session_os;
    /// The agent's current session id ("" = no session). (`registry_.session_id_of`.) Read at
    /// the start of `run()` and again just before the send: a different value means the agent
    /// re-registered while the push was being prepared, and the push (built for the old
    /// session's OS and attributes) is withheld.
    std::function<std::string(const std::string& agent_id)> session_id;
    /// Is `agent_id` a member of `expr`? Wraps `registry_.evaluate_scope_for_agent`.
    std::function<std::expected<bool, ScopeEvalError>(const std::string& agent_id,
                                                      const ::yuzu::scope::Expression& expr)>
        eval_scope;
    /// Classify, send and (on success only) forward the gateway queue for a
    /// `__guard__.push_rules` command. false = not classified or not delivered.
    std::function<bool(const std::string& agent_id, const std::string& command_id,
                       const std::string& push_bytes)>
        send_push;
    /// Write one audit row. Empty = discard. The "store is open" check lives in the callable.
    std::function<void(const AuditEvent&)> audit;
    /// The random hex suffix of a command id (`auth::AuthManager::bytes_to_hex(random_bytes(8))`).
    std::function<std::string()> random_suffix;
    /// Clock for the shed-log throttle. Empty = `steady_clock::now`.
    std::function<std::chrono::steady_clock::time_point()> now;
};

class GuardianReconcileFlow {
public:
    explicit GuardianReconcileFlow(GuardianReconcileFlowDeps deps)
        : guardian_reconcile_gate_(deps.gate), guardian_generation_cache_(deps.generation_cache),
          guardian_rule_bundle_cache_(deps.rule_bundle_cache),
          guardian_reconcile_budget_(deps.budget), metrics_(deps.metrics),
          reconcile_duration_(deps.duration), store_wired_(std::move(deps.store_wired)),
          list_rules_(std::move(deps.list_rules)), deployed_ids_(std::move(deps.deployed_ids)),
          session_os_(std::move(deps.session_os)), session_id_(std::move(deps.session_id)),
          eval_scope_(std::move(deps.eval_scope)),
          send_push_(std::move(deps.send_push)),
          audit_(deps.audit ? std::move(deps.audit) : std::function<void(const AuditEvent&)>{
                                  [](const AuditEvent&) {}}),
          random_suffix_(std::move(deps.random_suffix)),
          now_(deps.now ? std::move(deps.now)
                        : std::function<std::chrono::steady_clock::time_point()>{
                              [] { return std::chrono::steady_clock::now(); }}) {
        // An empty std::function would otherwise surface as std::bad_function_call on the
        // first heartbeat that reaches it, thrown from a heartbeat thread. Fail at
        // construction, naming the dependency. (`audit` and `now` keep their defaults.)
        require(reconcile_duration_, "duration");
        require(store_wired_, "store_wired");
        require(list_rules_, "list_rules");
        require(deployed_ids_, "deployed_ids");
        require(session_os_, "session_os");
        require(session_id_, "session_id");
        require(eval_scope_, "eval_scope");
        require(send_push_, "send_push");
        require(random_suffix_, "random_suffix");
    }

    GuardianReconcileFlow(const GuardianReconcileFlow&) = delete;
    GuardianReconcileFlow& operator=(const GuardianReconcileFlow&) = delete;

    // Guardian heartbeat reconcile (M5 / #1209). The agent reports its
    // applied policy generation on every heartbeat; if it trails the
    // current generation it missed a push (was offline when the push fired,
    // or has just reconnected — sync_with_server is a no-op pull), so
    // re-push its applicable rules. An agent also reports generation 0
    // (intermittently, see the agent's back-off) while
    // a boot re-arm failure is unresolved (#5513), however current its
    // persisted generation is; the same full_sync re-push is the catch-up
    // for that case too. Reads the generation, never bumps it, so
    // catching one lagging agent up does not make the rest of the fleet look
    // stale (the cascade M6's monotonic counter is designed to avoid).
    //
    // Admission (#1209 hardening, then #5513): a claim in guardian_reconcile_gate_
    // rate-limits an agent to one re-push per 25 s. The claim is written on Admit and
    // kept while an agent that has meanwhile converged is still younger than the
    // interval (so an agent alternating generation 0 / current cannot buy a push on
    // every second heartbeat); a claim older than the interval is erased on
    // convergence, and the maintenance sweep bounds the rest. Nothing releases a claim
    // early: an agent whose push ends without sending (no session, or a failed send)
    // is admitted at most once per interval, however often it heartbeats. The cached
    // generation (about 2 s old while the entry is fresh; a caller that arrives while another
    // thread is refreshing an expired entry is served the old value, which is older still,
    // because the cache refreshes on demand and never on a timer) only drives that decision;
    // an ADMITTED push re-reads the generation fresh and labels the push with it.
    void run(std::string_view agent_id_sv, std::uint64_t agent_gen) {
        if (!store_wired_())
            return;
        // Gate 2 LOW1: a degraded generation read aborts the reconcile
        // OBSERVABLY (counter) rather than collapsing to 0 — which made
        // every `agent_gen >= 0` true and silently suppressed reconcile.
        // The read goes through guardian_generation_cache_ (#5513): a
        // short-TTL single-flight cache whose error arm is the store's
        // nullopt, so this early return is unchanged; a failed read is
        // negative-cached for a shorter TTL. The value may be up to the TTL
        // stale (only ever LOWER than the store's, assuming a monotonic store),
        // so it decides converged / rate-limited / shed and is never used to
        // label a push.
        const auto current_res = guardian_generation_cache_.get();
        if (!current_res) {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "degraded"}})
                .increment();
            return;
        }
        const std::uint64_t current = *current_res;
        const std::string agent_id(agent_id_sv);

        // Convergence, per-agent rate limit, in-flight cap and replica admission
        // budget, in ONE ordered decision under one mutex
        // (guardian_reconcile_gate.hpp; the order is the safety invariant). The
        // per-agent claim (#1209 hardening: sec-MED1/perf-S1/S2) is taken under
        // the lock BEFORE any work so concurrent heartbeats from the same agent
        // can't both reconcile, and a stuck/hostile agent can't turn every
        // heartbeat into a registry scan. Steady-clock based so it self-heals a
        // re-registered/wiped agent after the interval. A SHED never writes the
        // claim, so the agent earns no holdoff for a push that never happened.
        GuardianReconcileGate::ShedCause shed_cause =
            GuardianReconcileGate::ShedCause::None;
        switch (guardian_reconcile_gate_.decide(agent_id, agent_gen, current,
                                                &shed_cause)) {
        case GuardianReconcileGate::Decision::Converged:
            return;  // agent already at or ahead of current policy
        case GuardianReconcileGate::Decision::RateLimited:
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "rate_limited"}})
                .increment();
            return;
        case GuardianReconcileGate::Decision::Shed: {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "shed"}})
                .increment();
            // NO audit row: shed is a store-capacity guard, not an enforcement
            // event (the shed counter is the signal). The log is throttled to
            // one line per minute; only the CAS winner logs.
            const auto now_rep = now_().time_since_epoch().count();
            const auto interval_rep =
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::seconds(60))
                    .count();
            auto last_rep = guardian_shed_log_last_.load(std::memory_order_relaxed);
            if ((last_rep == kGuardianShedLogNever || now_rep - last_rep >= interval_rep) &&
                guardian_shed_log_last_.compare_exchange_strong(
                    last_rep, now_rep, std::memory_order_relaxed)) {
                // Worded by cause: the two have different remedies (a budget or
                // per-second-ceiling shed means raise the budget or the ceiling, or
                // look at slow pushes; a cap shed means pushes are stuck inside a
                // store call). try_admit() classifies BOTH the leaky-bucket budget
                // and the per-second COUNT ceiling as ShedCause::Budget.
                const auto shed_so_far =
                    guardian_reconcile_budget_.shed_total() +
                    guardian_reconcile_gate_.in_flight_shed_total();
                if (shed_cause == GuardianReconcileGate::ShedCause::InFlightCap)
                    spdlog::warn("Guardian heartbeat reconcile: in-flight reconcile "
                                 "cap reached, shedding re-pushes (agents retry on "
                                 "their next heartbeat; {} shed so far; this line is "
                                 "logged at most once a minute); see "
                                 "yuzu_server_guardian_reconcile_in_flight",
                                 shed_so_far);
                else
                    spdlog::warn("Guardian heartbeat reconcile: admission budget or "
                                 "per-second ceiling exhausted, shedding re-pushes "
                                 "(agents retry on their next heartbeat; {} shed so "
                                 "far; this line is logged at most once a minute); see "
                                 "--guardian-reconcile-budget-ms-per-s, "
                                 "--guardian-reconcile-max-per-s and "
                                 "yuzu_server_guardian_reconcile_budget_balance_ms",
                                 shed_so_far);
            }
            return;
        }
        case GuardianReconcileGate::Decision::Admit:
            break;
        }
        // Admitted: from here EVERY exit debits the measured wall time into the
        // budget (RAII) and records it in the duration histogram.
        auto admitted = guardian_reconcile_gate_.begin_admitted();
        struct DurationObserver {
            yuzu::Histogram* hist;
            std::chrono::steady_clock::time_point start;
            ~DurationObserver() {
                try {
                    hist->observe(std::chrono::duration<double>(
                                      std::chrono::steady_clock::now() - start)
                                      .count());
                } catch (...) {
                    // A destructor must not throw; one lost sample is harmless.
                }
            }
        };
        const DurationObserver duration_observer{reconcile_duration_,
                                                 std::chrono::steady_clock::now()};

        // Durable audit for an aborted reconcile, shared by abort_degraded (a store could
        // not be read; counted as result="degraded") and abort_invalidated (a rule or policy
        // change landed mid-reconcile; counted on its own counter). Gate 6 compliance: an
        // aborted enforcement convergence for a BEHIND agent is a security-relevant non-event -
        // SIEM must see it, not just a metric/log (the REST push twin audits `denied`; the
        // success re-push below audits `success`). Every caller is past the claim and the
        // admission budget, so it inherits the same at-most-one-row-per-agent-per-interval
        // dedup as the success path, no audit storm. (The earlier generation-unreadable gate is
        // pre-dedup and coarse, counter-only there, plus the persistent degraded gauge tracked
        // in #2662.)
        auto audit_abort = [&](std::string_view what, const std::string& err) {
            AuditEvent ev;
            ev.timestamp =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
            ev.principal = "system";
            ev.action = "guaranteed_state.reconcile";
            ev.target_type = "GuaranteedState";
            ev.target_id = agent_id;
            ev.detail = "heartbeat reconcile ABORTED — " + std::string(what) +
                        " (" + err +
                        "); agent rules did not converge (generation " +
                        std::to_string(agent_gen) + ")";
            ev.result = "degraded";
            audit_(ev);
        };
        auto abort_degraded = [&](std::string_view what, const std::string& err) {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "degraded"}})
                .increment();
            audit_abort(what, err);
        };
        // The same ABORTED audit row, counted on its OWN counter and NOT as result="degraded":
        // this abort is not a store failure. It means a rule or policy change landed on this
        // replica while the push was being prepared (see the epoch check before the send), so
        // it must not move the degraded series that is read as the pool-pressure signal.
        auto abort_invalidated = [&](std::string_view what, const std::string& err) {
            metrics_.counter("yuzu_server_guardian_reconcile_invalidated_total").increment();
            audit_abort(what, err);
        };

        // Read the session id BEFORE the OS: a re-registration between the two reads makes the
        // later comparison differ, which withholds the push (conservative).
        const std::string session_id_at_start = session_id_(agent_id);
        auto sess = session_os_(agent_id);
        if (!sess) {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "no_session"}})
                .increment();
            // The claim Admit wrote is deliberately KEPT. This arm fires only when
            // the session was removed (reap, revoke, teardown) while a
            // pending-map or gateway-held session id still resolved, or on a
            // deregistration race.
            // (An agent that has Registered but not yet Subscribed is NOT here:
            // register_agent installs its session at Register, so it takes the full
            // push path and the send fails, visible only as
            // yuzu_server_system_reserved_push_total{result="undelivered"}.)
            // Releasing the claim would let a looping agent turn every heartbeat
            // into a fresh admission and drain the shared budget; kept, it is at
            // most one admission per min_interval (25 s) per agent. No audit row
            // is written on this path.
            return;
        }
        // The bundle cache's invalidation epoch, read BEFORE the fresh generation and the
        // bundle load. Both caches are invalidated by a rule edit on this replica (the store's
        // post-mutation hook) even when the edit's generation bump failed, and
        // GuardianRuleBundleCache::get() still hands a load that invalidate() detached to its
        // own caller and to the waiters that joined it. So the bundle returned below may predate
        // an edit while carrying a generation label that did not move. The epoch is compared
        // again just before the send; if it advanced, nothing is sent (see there).
        const auto bundle_epoch = guardian_rule_bundle_cache_.epoch();
        // The generation that LABELS this push, read fresh from the store (cache
        // bypassed). The cached `current` can be up to its TTL stale; if a REST
        // fan-out already delivered a newer generation, building from the stale
        // one would send older content under an older label and the agent (which
        // keeps the highest generation it has seen) would never regain a
        // lower-labelled guard. Read BEFORE the bundle load so the bundle is at
        // least as new as its label (guardian_rule_bundle.hpp).
        const auto fresh_res = guardian_generation_cache_.get_fresh();
        if (!fresh_res) {
            spdlog::warn("Guardian heartbeat reconcile: policy generation unreadable "
                         "({}) - aborting re-push for agent_id={}",
                         fresh_res.error(), ::yuzu::log_id_token(agent_id));
            abort_degraded("policy generation unreadable", fresh_res.error());
            return;
        }
        const std::uint64_t fresh_generation = *fresh_res;
        if (fresh_generation <= agent_gen)
            return;  // converged against the fresh value: nothing to send
        // The rule bundle for this generation (#5513), loaded at most once per
        // generation per replica. list_rules is type-distinguishable (ADR-0038
        // catastrophic-read set): a degraded read MUST abort this reconcile
        // rather than fan out an empty rule set it cannot distinguish from "no
        // rules configured" - that would be a fleet-wide disarm for this agent.
        // Baseline gate (docs/guardian-baseline-model.md): the rule source is the
        // union of member Guards of *deployed* Baselines, so an
        // enabled-but-undeployed Guard is never reconciled onto an agent.
        // ADR-0055 catastrophic-read set: a degraded deployed-set read MUST also
        // abort, never fan out an empty deployed-set it cannot distinguish from
        // "nothing deployed". A failed load is never HELD as the bundle; it is
        // remembered briefly (negative cache, guardian_rule_bundle.hpp) so a slow
        // failing store is not re-probed by every admitted push.
        // The generation was read BEFORE this call (guardian_rule_bundle.hpp's
        // ordering requirement): rows read inside the loader are at least as new
        // as `fresh_generation`. The bundle is keyed by the FRESH generation,
        // never the agent's or the cached one. The load itself is
        // guardian::load_reconcile_bundle, which is unit-tested for its
        // evaluation order (the filter must see the deployed set before it is
        // moved into the bundle).
        //
        // Only the time THIS push spent BLOCKED waiting on another thread's
        // in-flight load is excluded from the budget debit (Scoped::exclude): that
        // wait is not this push's cost. The fresh generation read above and this
        // push's own load, when it is the thread that runs the loader, are charged
        // in full. A failed load is remembered for a short negative TTL by the
        // cache, so a failing store is not re-probed by every admitted push.
        std::chrono::nanoseconds bundle_waited{0};
        const auto bundle_result = guardian_rule_bundle_cache_.get(
            fresh_generation,
            [this]() -> std::expected<guardian::Bundle, guardian::BundleLoadError> {
                if (!store_wired_())
                    return std::unexpected(guardian::BundleLoadError{
                        guardian::BundleLoadError::Source::rules,
                        "guaranteed-state store not wired"});
                return guardian::load_reconcile_bundle(list_rules_, deployed_ids_);
            },
            &bundle_waited);
        admitted.exclude(bundle_waited);
        if (!bundle_result) {
            const auto& err = bundle_result.error();
            switch (err.source) {
            case guardian::BundleLoadError::Source::rules:
                spdlog::warn("Guardian heartbeat reconcile: list_rules degraded ({}) - "
                             "aborting re-push for agent_id={}",
                             err.detail, ::yuzu::log_id_token(agent_id));
                abort_degraded("rule store degraded", err.detail);
                break;
            case guardian::BundleLoadError::Source::deployed:
                spdlog::warn("Guardian heartbeat reconcile: deployed_member_rule_ids "
                             "degraded ({}) - aborting re-push for agent_id={}",
                             err.detail, ::yuzu::log_id_token(agent_id));
                abort_degraded("baseline store degraded", err.detail);
                break;
            case guardian::BundleLoadError::Source::other:
                spdlog::warn("Guardian heartbeat reconcile: rule bundle load failed "
                             "({}) - aborting re-push for agent_id={}",
                             err.detail, ::yuzu::log_id_token(agent_id));
                abort_degraded("rule bundle load failed", err.detail);
                break;
            }
            return;
        }
        const guardian::Bundle& bundle = **bundle_result;

        // Per-agent filtering as the fan-out (M4): only rules that target this
        // agent's OS and name it in scope. Membership is decided PER AGENT with
        // evaluate_scope_for_agent (#5513), never by building the fleet's matching-id
        // vector, and is NEVER cached across reconciles (tags, properties and
        // session attributes change with no generation bump). Cache scope
        // membership only across rules sharing a scope_expr within this one
        // reconcile.
        //
        // No rs_store/principal here: this is a LOCAL-ONLY dispatch
        // (send_system_reserved), so the evaluator is the evaluate_scope_local
        // population (#4981 PR-1 B4): it can NEVER abort for a presence reason, so
        // a presence-store blip cannot periodically disarm this scoped rule. A
        // scope that did not parse, or an Unresolvable atom (from_result_set:, or
        // props.<key> with no store wired), is "not a member": arming nothing is
        // the safe direction, as before.
        //
        // BEHAVIOUR CHANGE (#5513, operator-approved): a StoreDegraded
        // evaluation used to collapse through value_or({}) to "not a member",
        // which sent a NARROWED full_sync and silently disarmed the rule on this
        // agent. It now sets scope_degraded and the reconcile is aborted below
        // through the degraded branch (counter, ABORTED audit row, log), sending
        // NOTHING; the agent keeps its current rules and is retried. The same holds
        // for every other error kind: Unresolvable (an atom with no wired store) is the
        // one kind this flow treats as "not a member"; every other kind is an untrusted
        // read (see scope_eval_error.hpp), so a kind added to the enum later is an abort
        // until it is deliberately classified here.
        bool scope_degraded = false;
        std::string scope_degraded_detail;
        std::unordered_map<std::string, bool> scope_member;
        auto push = guardian::build_agent_push(
            bundle.rules, *sess,
            [&](const std::string& expr) {
                if (scope_degraded)
                    return false;
                auto cached = scope_member.find(expr);
                if (cached != scope_member.end())
                    return cached->second;
                bool member = false;
                if (const auto* parsed = bundle.find_scope(expr)) {
                    const auto eval = eval_scope_(agent_id, *parsed);
                    if (eval) {
                        member = *eval;
                    } else if (eval.error().kind != ScopeEvalError::Kind::Unresolvable) {
                        scope_degraded = true;
                        scope_degraded_detail = to_string(eval.error().kind);
                        // Only the store-degraded kind carries its detail into the log line
                        // and the ABORTED audit row; for the other kinds the detail can be
                        // a caller-supplied identifier (OwnerCheckFailed carries a result-set
                        // id), so only the kind name is emitted.
                        if (eval.error().kind == ScopeEvalError::Kind::StoreDegraded &&
                            !eval.error().detail.empty())
                            scope_degraded_detail += ": " + eval.error().detail;
                        return false;
                    }
                    // Unresolvable (an atom that cannot be resolved at this call site):
                    // not a member.
                }
                scope_member.emplace(expr, member);
                return member;
            },
            /*full_sync=*/true, fresh_generation, &metrics_);
        if (scope_degraded) {
            spdlog::warn("Guardian heartbeat reconcile: scope evaluation store degraded "
                         "({}) - aborting re-push for agent_id={}",
                         scope_degraded_detail, ::yuzu::log_id_token(agent_id));
            abort_degraded("scope store degraded", scope_degraded_detail);
            return;  // send NOTHING: a narrowed full_sync would disarm the rule
        }
        // The last check before the send: an invalidation (a rule edit on this replica, a
        // baseline deploy or delete, an explicit push) since the epoch was read means the
        // bundle may be a load that predates it, and `fresh_generation` may not have moved
        // (the edit's best-effort bump can fail). Labelling those rows with that generation
        // would leave the agent converged on them until the next bump, so send NOTHING: the
        // claim is kept, the agent is admitted again after the young-claim window and then
        // reconciles from a fresh load. It writes the same ABORTED audit row as the store
        // aborts but is counted on its own counter, not as result="degraded" (no store
        // failed). It is conservative: an invalidation that merely overlapped this
        // reconcile aborts it even when the bundle was in fact loaded afterwards. It does not
        // close the gap between a committed edit and the hook that follows it (an edit whose
        // hook has not yet run is invisible to this comparison), nor an invalidation that
        // lands after this line and before the send.
        if (guardian_rule_bundle_cache_.epoch() != bundle_epoch) {
            spdlog::info("Guardian heartbeat reconcile: a rule or policy change landed while "
                         "this re-push was being prepared - withholding it for agent_id={} "
                         "(retried on a later heartbeat)",
                         ::yuzu::log_id_token(agent_id));
            abort_invalidated("rule bundle invalidated during load",
                              "a rule or policy change landed while the re-push was being "
                              "prepared; retried on a later heartbeat");
            return;  // send NOTHING: the rows may predate the change under an unchanged label
        }
        // The rules were built for the session read at the start (its OS and the attributes the
        // scope checks read). `send_push_` delivers by agent id to whatever session exists NOW,
        // so a re-registration during the store reads would push rules filtered for the old
        // session to the new one under the fresh generation label. Withhold it; the claim is
        // kept and the agent is reconciled again after the young-claim window. Counted as
        // no_session (the session this push was prepared for is gone); no audit row, as there.
        // It does not close an invalidation or a re-registration that lands after this line and
        // before the send.
        if (session_id_(agent_id) != session_id_at_start) {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "no_session"}})
                .increment();
            spdlog::info("Guardian heartbeat reconcile: agent_id={} re-registered while this "
                         "re-push was being prepared - withholding it (retried on a later "
                         "heartbeat)",
                         ::yuzu::log_id_token(agent_id));
            return;
        }
        // Unique per re-push (random suffix) so a same-generation reconcile
        // can't collide with the agent's replay-dedup set (hp-F2/cons-S1).
        const auto command_id = "__guard__-reconcile-" + std::to_string(fresh_generation) + "-" +
                                random_suffix_();
        // send_push_ classifies (system caller, PR1.9c), sends and, on success only,
        // forwards the gateway queue (server.cpp).
        if (send_push_(agent_id, command_id, push.SerializeAsString())) {
            metrics_
                .counter("yuzu_server_guardian_reconciles_total",
                         {{"result", "sent"}})
                .increment();
            metrics_
                .counter("yuzu_server_guardian_pushes_dispatched_total",
                         {{"reason", "reconcile"}})
                .increment();
            metrics_.gauge("yuzu_server_guardian_policy_generation")
                .set(static_cast<double>(fresh_generation));
            // Durable audit of a system-initiated enforcement re-deploy
            // (SOC2 CC7.2/CC7.4 — comp-F1). Deduped above → at most one
            // row per agent per interval, not per heartbeat.
            AuditEvent ev;
            ev.timestamp =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
            ev.principal = "system";
            ev.action = "guaranteed_state.reconcile";
            ev.target_type = "GuaranteedState";
            ev.target_id = agent_id;
            ev.detail = "heartbeat reconcile re-push (generation " +
                        std::to_string(agent_gen) + " -> " +
                        std::to_string(fresh_generation) + ")";
            ev.result = "success";
            audit_(ev);
            spdlog::info("Guardian: reconciled agent {} (generation {} -> {})",
                         ::yuzu::log_id_token(agent_id), agent_gen, fresh_generation);
        }
    }

private:
    template <typename Fn>
    static void require(const Fn& fn, const char* name) {
        if (!fn)
            throw std::invalid_argument(
                std::string("GuardianReconcileFlow: required dependency is empty: ") + name);
    }

    GuardianReconcileGate& guardian_reconcile_gate_;
    GuardianGenerationCache& guardian_generation_cache_;
    guardian::GuardianRuleBundleCache& guardian_rule_bundle_cache_;
    GuardianReconcileBudget& guardian_reconcile_budget_;
    ::yuzu::MetricsRegistry& metrics_;
    ::yuzu::Histogram* const reconcile_duration_;
    const std::function<bool()> store_wired_;
    const guardian::RuleRowsSource list_rules_;
    const guardian::DeployedIdsSource deployed_ids_;
    const std::function<std::optional<std::string>(const std::string&)> session_os_;
    const std::function<std::string(const std::string&)> session_id_;
    const std::function<std::expected<bool, ScopeEvalError>(const std::string&,
                                                            const ::yuzu::scope::Expression&)>
        eval_scope_;
    const std::function<bool(const std::string&, const std::string&, const std::string&)>
        send_push_;
    const std::function<void(const AuditEvent&)> audit_;
    const std::function<std::string()> random_suffix_;
    const std::function<std::chrono::steady_clock::time_point()> now_;

    // steady_clock tick count of the last shed warning, or kNever. Throttles the shed log to
    // one line per minute (the shed counter is the signal; the log is a pointer to it).
    static constexpr std::chrono::steady_clock::rep kGuardianShedLogNever =
        std::numeric_limits<std::chrono::steady_clock::rep>::min();
    std::atomic<std::chrono::steady_clock::rep> guardian_shed_log_last_{kGuardianShedLogNever};
};

}  // namespace yuzu::server
