#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type
#include "policy_dispatch.hpp"       // G01: the refusal seam, its denial type and DispatchOrigin

/// @file policy_evaluator.hpp
/// Drives the compliance CHECK -> VERDICT pipeline that was previously dead.
///
/// Authored policies bind a fragment (a check instruction + a CEL
/// `check_compliance` expression) to a scope. Nothing used to evaluate them:
/// `PolicyStore::update_agent_status` (the only writer of compliance status)
/// had no caller and no trigger fired, so `get_fleet_compliance` always read
/// 0%. This component closes that gap.
///
/// Model (two-phase, async): a background thread `tick()`s on a cadence.
///   * dispatch_due(): claims due policies via `PolicyStore::claim_due_policies`
///     (ADR-0056 — a durable, fleet-wide single-sweeper claim; see that store's
///     header for why due-ness can no longer live in this class's own
///     memory), resolves scope -> agents, dispatches the fragment's
///     check_instruction with a generated execution_id, and records an
///     in-flight check.
///   * collect_ready(): for in-flight checks past a grace window (or once all
///     targets have responded), read each agent's result via
///     ResponseStore::query_by_execution, evaluate the CEL against the parsed
///     result fields, and write compliant / non_compliant / unknown / error
///     via PolicyStore::update_agent_status (one row per agent). Stays
///     per-replica and in-memory: only the replica that dispatched a check
///     ever holds its in-flight entry, so there is nothing to coordinate here
///     — `update_agent_status`'s UPSERT is naturally idempotent against a
///     racing manual evaluate_now()/remediate() call on another replica FOR
///     THE STATUS VALUE (each write converges to a consistent final row).
///
/// Remediation is MANUAL and opt-in (operator-gated) and only available when
/// the fragment defines a fix_instruction: `remediate()` marks targets
/// `fixing`, dispatches the fix, then (on a later tick) dispatches the
/// post-check / check instruction and writes the true post-fix verdict. There
/// is no automatic non_compliant -> fix loop.
///
/// HA WS-3 3.4 (ADR-2002 §6 finding 6a): a concurrent `remediate()` call for
/// the same policy is arbitrated by a DURABLE, per-(policy,agent) CAS in
/// `PolicyStore` (`claim_remediation`/`release_remediation_claim`) — CLAIM,
/// then DISPATCH, then mark 'fixing' only for the subset the dispatch
/// actually DELIVERED to. This closes what the pre-HA in-process
/// `remediating_` guard never covered: a sibling replica's independent
/// remediate() call for the same policy had no shared state to see it and
/// would double-dispatch the fix, double-incrementing
/// `update_agent_status`'s `fix_attempt_count` on a fix instruction that may
/// not be idempotent. The claim is released (a) for a claimed-but-NOT-
/// delivered target (offline / quarantined / plugin-absent / a systemic
/// containment-gate failure) immediately, WITHOUT burning a retry attempt;
/// (b) for a delivered target once its FixWait entry matures in
/// `collect_ready()`; (c) by `claim_due_policies`'s own stranded-`fixing`
/// staleness sweep, using the SAME `fixing_stale_seconds` window, if the
/// claiming replica dies mid-flight (superseding the old unconditional
/// every-restart reset this class's constructor used to do, which would
/// stomp another replica's still-live remediation under N replicas).

#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry; // yuzu/metrics.hpp — observability counters (optional)
}

namespace yuzu::server {

// Forward declarations — full types are included in the .cpp.
class PolicyStore;
class InstructionStore;
class ResponseStore;
class ForensicsPluginSet; // #4990 (response_tier_filter.hpp)
class AuditStore;
class TagStore;
class CustomPropertiesStore;
class ManagementGroupStore;
struct Policy;
struct PolicyFragment;

namespace detail {
class AgentRegistry; // lives in yuzu::server::detail (see agent_registry.hpp)
} // namespace detail

class PolicyEvaluator {
public:
    /// Same shape as WorkflowRoutes::CommandDispatchFn — the server hands the
    /// evaluator the one shared dispatch lambda so checks travel the exact same
    /// path as operator-initiated commands.
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// Epoch-seconds clock. Injectable for deterministic tests.
    using NowFn = std::function<int64_t()>;

    struct Deps {
        PolicyStore* policy_store{nullptr};
        InstructionStore* instruction_store{nullptr};
        ResponseStore* response_store{nullptr};
        detail::AgentRegistry* registry{nullptr};
        TagStore* tag_store{nullptr};
        CustomPropertiesStore* custom_properties_store{nullptr};
        ManagementGroupStore* mgmt_group_store{nullptr};
        yuzu::MetricsRegistry* metrics{nullptr}; // optional observability sink
        /// #4990: the Forensics plugin set. A check's stored response is read with every
        /// Forensics-tier plugin excluded, so a policy whose check instruction runs a Forensics
        /// plugin scores `unknown` (never a verdict from, or a stored copy of, Forensics output).
        /// Borrowed. Unset (a harness) refuses every row, so every verdict is `unknown`.
        const ForensicsPluginSet* forensics_plugins{nullptr};
        CommandDispatchFn dispatch_fn;
        NowFn now_fn;                          // defaults to system clock if unset
        int64_t default_interval_seconds{3600}; // when a policy has no interval trigger
        int64_t grace_seconds{15};             // wait before scoring non-responders
        // ADR-0056: how long a 'fixing' status may sit before
        // claim_due_policies' staleness sweep resets it to 'unknown' (the
        // dispatching replica died/restarted mid-remediation and no one will
        // ever collect its FixWait). Long enough that a genuinely slow fix
        // instruction (e.g. a content_dist software install, which can run
        // minutes) is not false-positive reset mid-flight; short enough that
        // a truly stranded fix does not sit invisible indefinitely.
        int64_t fixing_stale_seconds{1800};
        // #3495 (Gate 3 architect, governance re-review; scope narrowed at
        // Gate 4 unhappy-path, 2026-08-30 — see below): lets a shutdown
        // request stop collect_ready() from processing further in-flight
        // items once stop_requested_ flips, checked once per item in that
        // loop. Ports the same field QuarantineContainmentReconciler::Deps /
        // PreflightRunner::Deps / ScheduleRunner::Deps already carry.
        // PolicyEvaluator was the fourth production consumer of the shared
        // command_dispatch_fn closure and was missed in the original #3495
        // fix — its dispatch_instruction() calls the identical blocking
        // dispatch_fn the other three do; the join-ordering half of that fix
        // (policy_eval_thread_ now joins after agent_server_->
        // Shutdown(deadline)) still applies and is what actually bounds this
        // engine's shutdown-time wall clock.
        //
        // DELIBERATELY NOT checked in dispatch_due()'s loop (unlike the
        // sibling engines' single loop each) — claim_due_policies durably
        // stamps EVERY due policy's dispatch claim in one transaction before
        // that loop even starts, so a should_stop break there would leave
        // the un-processed tail claimed-but-never-checked, silently
        // skipping up to a full `default_interval_seconds` of compliance
        // checking instead of deferring one tick. See dispatch_due()'s own
        // comment for the full reasoning. Unset (default) = never stop,
        // matching every existing production/test Deps that predates this
        // field.
        std::function<bool()> should_stop;
        /// The capability registry every pair is classified against before it is dispatched
        /// (`authorize_policy_dispatch`, policy_dispatch.hpp). Borrowed, must outlive the
        /// evaluator. UNSET REFUSES EVERY DISPATCH (reason `unwired`): an evaluator with no
        /// registry fails closed, never open.
        const CommandCapabilityRegistry* capability_registry{nullptr};
        /// Optional forensic sink for the `policy.dispatch` / `denied` audit rows written when a
        /// dispatch is refused. Borrowed, nullable (a harness without one writes none), same
        /// shape as `ScheduleRunner::Deps::audit_store`.
        AuditStore* audit_store{nullptr};
        /// TEST SEAM (null in production): called once per target with a terminal response,
        /// immediately before it is evaluated, inside the evaluation failure domain. Lets a test
        /// make evaluation throw to prove one target's failure cannot drop the others.
        std::function<void(const std::string& target)> before_evaluate_hook;
        /// TEST SEAM (null in production): called once per ready item at the START of its
        /// failure domain, before the response-store read, to prove an escape from that prelude
        /// cannot abort later items.
        std::function<void(const std::string& policy_id)> before_item_hook;
    };

    explicit PolicyEvaluator(Deps deps);

    /// One scheduler cycle: collect matured in-flight checks (ALWAYS), then — only
    /// when `dispatch_due_allowed` — dispatch due policies. `collect_ready()` is the
    /// completion path for the operator-synchronous evaluate_now()/remediate() plane
    /// and MUST run per-replica; `dispatch_due()` is the leader-owned scheduling half
    /// and is the caller's WS-3 fenced-leader gate (PR #4134). Safe to call from a
    /// single background thread. NO default: the fenced scheduling half must be an
    /// EXPLICIT opt-in so a future caller writing `tick()` cannot silently run the
    /// leader-only due-policy dispatch ungated (adversarial review K2, PR #4134).
    void tick(bool dispatch_due_allowed);

    /// Force an immediate check of one policy, ignoring its interval. Returns
    /// the dispatch execution_id, or "" if the policy is missing / has no check
    /// instruction / matches no agents / already has one in flight — a
    /// legitimate no-op, never an error. `unexpected` means an internal store
    /// failure (degraded policy read, the durable-dispatch-claim stamp failed,
    /// or — ADR-0058 — InstructionStore itself errored resolving the check
    /// instruction) — the caller must surface this as degraded (503), not as
    /// "no targets" (409).
    ///
    /// G01: returns a `KickoffOutcome`. A REFUSED dispatch (the pair has an execute gate, is
    /// Destructive, is reserved, is not classified, ...) is a successful return with `denial`
    /// set and an empty `execution_id`, never an `unexpected`: nothing was sent and the
    /// targets are recorded as `blocked`. A caller must test `denial` before it reads an empty
    /// `execution_id` as the benign no-op.
    struct KickoffOutcome {
        std::string execution_id;
        std::optional<PolicyDispatchDenial> denial;
    };

    [[nodiscard]] std::expected<KickoffOutcome, std::string>
    evaluate_now(const std::string& policy_id);

    /// The authoring-time answer to "may a policy use this instruction?" (G01). ADVISORY: the
    /// dispatch seam is the control (a definition can be changed after a policy is saved, and
    /// pack install is not checked at all), so this only lets the authoring routes refuse
    /// early. `Allowed` includes an instruction id that does not exist yet (packs create
    /// definitions and fragments in any order); `Degraded` is a store or registry failure and
    /// must be answered as such (503), never as an accept or a refusal.
    struct InstructionCheck {
        enum class Kind : uint8_t { Allowed, Refused, Degraded };
        Kind kind{Kind::Allowed};
        std::optional<PolicyDispatchDenial> denial; // set when Refused
        /// Degraded only: true when the lookup failed in the instruction store, which a retry
        /// may clear; false when the evaluator has no registry or no instruction store (a
        /// wiring condition no retry clears). The authoring routes send a retry hint only for
        /// the first.
        bool transient{false};
    };

    [[nodiscard]] InstructionCheck authorize_instruction(const std::string& instruction_id) const;

    struct RemediateResult {
        bool ok{false};
        std::string error;        // set when !ok
        /// G01: set when the fix was REFUSED (policy_dispatch.hpp). `ok` is false and
        /// `degraded` stays false (a refusal is not a store failure); nothing was sent; the
        /// claimed targets were recorded as `blocked` and their claims released; `error` is a
        /// neutral message. The route answers 409 on `denial`, ahead of any matching on
        /// `error`.
        std::optional<PolicyDispatchDenial> denial;
        // Governance (2026-08-24): set explicitly by remediate() at each
        // degrade return point — the caller must not infer this from a
        // string prefix on `error`. A previous route-layer version keyed off
        // `error.starts_with("policy store")`, an unshared, untested string
        // contract a future reword of any degrade message would silently
        // break (consistency-auditor SHOULD-2). Covers a genuine PolicyStore
        // degrade AND — ADR-0058 — InstructionStore erroring resolving the
        // fix instruction; both are the same "internal store failure, not a
        // business rejection" shape to every caller.
        bool degraded{false};
        std::string execution_id; // fix-dispatch execution id when ok
        // Agents the fix was actually DELIVERED to (HA WS-3 3.4) — a
        // claimed-but-not-delivered target (offline/not_sent, quarantined,
        // plugin-absent) is excluded; it was never marked 'fixing' and its
        // claim was released without burning a retry attempt.
        int agents{0};
    };

    /// Manually remediate a policy. Requires the fragment to define a
    /// fix_instruction (else ok=false). If `agent_ids` is empty, targets every
    /// agent currently non_compliant for the policy. Dispatches the fix, then a
    /// later tick runs the post-check and writes the verified verdict.
    RemediateResult remediate(const std::string& policy_id,
                              const std::vector<std::string>& agent_ids);

private:
    enum class Phase { Check, FixWait };

    struct InFlight {
        Phase phase{Phase::Check};
        std::string policy_id;
        std::string execution_id;
        std::string instruction_id;   // for result-schema lookup (Check phase)
        std::string compliance_expr;  // CEL evaluated in the Check phase
        std::vector<std::string> targets;
        int64_t dispatched_at{0};
        // HA WS-3 3.4 (review B3): the remediation claim generation this entry
        // owns. Threaded through to the fenced release + status writes at
        // maturity so a stale holder cannot stomp a row a sibling reclaimed.
        // 0 = NOT remediation-owned (an ordinary detection Check entry), which
        // makes its status writes unconditional. Propagated from the FixWait
        // entry onto the verify Check entry it spawns.
        int64_t claim_gen{0};
        // FixWait -> verify hand-off (the post-check to run after the fix):
        std::string verify_instruction;
        std::string verify_compliance;
        std::string verify_parameters_json;
    };

    Deps d_;
    std::mutex mu_; // guards in_flight_
    std::vector<InFlight> in_flight_;
    // HA WS-3 3.4: the process-local `remediating_`/`ReservationGuard` guard
    // that used to live here (governance UP-3, 2026-08-24) is DELETED, not
    // demoted — the durable per-(policy,agent) claim in PolicyStore
    // (`claim_remediation`) is strictly finer-grained (per agent, not per
    // policy) and cross-replica-visible, so it fully subsumes the
    // same-process case this guard covered. See this file's header doc.

    void dispatch_due();
    void collect_ready();

    // HA WS-3 3.4: dispatch_instruction() must hand its ConfinedDispatchOutcome
    // back to remediate() (fold-in #4 -- `.sent` is a COUNT, not a set, so the
    // DELIVERED subset can only be recovered from the outcome's per-id
    // fields). kickoff_check() and collect_ready()'s verify-dispatch call
    // site keep ignoring `.outcome`, same as before this struct existed.
    struct DispatchInstructionResult {
        std::string execution_id;
        yuzu::server::ConfinedDispatchOutcome outcome;
        /// Set when the pair was refused: `execution_id` is then empty and no `polchk-` id
        /// was minted. The pair is carried back so the caller can record it (the seam itself
        /// never allocates).
        std::optional<PolicyDispatchDenial> denial;
        std::string denied_plugin;
        std::string denied_action;
    };

    /// What `record_denial_status` leaves for `emit_denial_audit`: the audit row of a refusal,
    /// when one is due. Split from the status write so a refused fix can write `blocked` while
    /// its claim is held and write the audit row only after the claim is released.
    struct DenialAudit {
        bool due = false;
        std::string policy_id;
        std::string phase;
        std::string reason;
        std::string detail;
    };

    /// Record a refused dispatch for `targets`: write the `blocked` status (write on change,
    /// fenced on `expected_gen` for a fix or verify refusal), count it and log it. Returns the
    /// `policy.dispatch` / `denied` audit row to write (an operator-triggered refusal always; a
    /// tick or verify refusal only when a row changed or the status write failed). Never
    /// reverses the refusal: nothing was sent either way.
    [[nodiscard]] DenialAudit record_denial_status(const std::string& policy_id,
                                                   std::string_view phase,
                                                   const std::vector<std::string>& targets,
                                                   const DispatchInstructionResult& r,
                                                   DispatchOrigin origin,
                                                   std::optional<int64_t> expected_gen);

    /// Write the audit row `record_denial_status` returned, if one is due. Warns once, naming
    /// the policy, phase and reason, when the store does not write it.
    void emit_denial_audit(const DenialAudit& a);

    /// `record_denial_status` then `emit_denial_audit`, for a refusal that holds no claim.
    void record_denial(const std::string& policy_id, std::string_view phase,
                       const std::vector<std::string>& targets, const DispatchInstructionResult& r,
                       DispatchOrigin origin, std::optional<int64_t> expected_gen);

    // Resolve scope/groups -> unique agent ids. Must be called WITHOUT mu_
    // held (it does store/registry I/O that must not run under the evaluator
    // lock — see the lock-discipline note on kickoff_check).
    //
    // #4981 PR-1 (Finding B, B6): this call site bypasses the dispatch ladder
    // entirely, so it is the ONE place that must both increment
    // `yuzu_scope_eval_degraded_total{reason}` itself (never inside
    // AgentRegistry::evaluate_scope — that would double-count for every
    // ladder-routed caller, which already increments via
    // audit_scope_evaluation_aborted) and expose WHY a scope-expression
    // policy resolved to zero targets. `out_reason`, when non-null, is set to
    // `to_string(ScopeEvalError::Kind)` on a `d_.registry->evaluate_scope`
    // abort — used by `remediate()` to distinguish a genuine empty-scope
    // result from a presence/store degradation in its refusal message.
    // Untouched (left as whatever the caller initialised it to) on a
    // management-group target or a clean/empty scope evaluation.
    std::vector<std::string> resolve_targets(const Policy& p, std::string* out_reason = nullptr) const;

    // Resolve targets, dispatch the fragment's check_instruction, record a
    // Check in-flight. Returns the execution_id, or "" on failure / when a Check
    // for this policy is already in flight (dedupe). Lock discipline: this
    // acquires mu_ only briefly (dedupe scan, in-flight push) and NEVER holds it
    // across the dispatch call — dispatch_fn does blocking gRPC + gateway
    // forwarding, so it must run lock-free. Caller must NOT hold mu_.
    std::expected<KickoffOutcome, std::string> kickoff_check(const Policy& p, DispatchOrigin origin);

    // Dispatch `instruction_id` to `targets`; returns a fresh execution_id
    // (plus the raw ConfinedDispatchOutcome from dispatch_fn — HA WS-3 3.4,
    // only remediate() consumes it), or an empty execution_id on a legitimate
    // no-op (unknown definition / empty targets — same as pre-migration).
    // `unexpected` when InstructionStore::get_definition itself errors
    // (ADR-0058: a genuine DB/lease failure must never collapse into the same
    // "" a not-found id returns — every caller propagates this the same way
    // it propagates its own other degrade paths). Must be called WITHOUT mu_
    // held (invokes the blocking dispatch_fn).
    std::expected<DispatchInstructionResult, std::string>
    dispatch_instruction(const std::string& instruction_id,
                         const std::unordered_map<std::string, std::string>& parameters,
                         const std::vector<std::string>& targets);

    int64_t now() const;
    static std::string gen_execution_id();
};

} // namespace yuzu::server
