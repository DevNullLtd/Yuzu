#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "command_capability.hpp"
#include "dispatch_target_shape.hpp" // kReasonDestructiveUntargeted

/// @file dispatch_destructive_gate.hpp
/// #3685 — the pure Destructive-class TARGETING decision for `/api/command`
/// (and, in a later checkpoint, MCP `execute_instruction`), extracted the
/// same way `dispatch_confined_arms.hpp` and `dispatch_target_shape.hpp`
/// extract their own shared rules: pure functions, injected inputs, no
/// `ServerImpl`, so the decision is directly unit-testable and cannot
/// silently drift between callers.
///
/// THE RULE, stated once, is the part that must not drift: a `plugin.action`
/// pair classified `DispatchClass::Destructive` (`command_capability.hpp`)
/// MUST name explicit, in-scope `agent_ids` — broadcast and scope fan-out are
/// always refused, and a classification MISS is a first-class verdict the
/// caller must explicitly handle, never a branch that can be silently
/// skipped.
///
/// THE BUG THIS REPLACES (#3685 defect 1): the inline `/api/command` block it
/// replaces guarded on `if (classified_for_gate && classified_for_gate->
/// dispatch_class == DispatchClass::Destructive)` — an `if` whose condition
/// is false for BOTH "classified and not Destructive" and "failed to
/// classify at all" collapses two different facts into one branch. That was
/// not exploitably fail-open here (`build_classified_command` denies every
/// classify-miss unconditionally, downstream), but it is exactly the shape
/// that WOULD be fail-open the next time a similar gate is written without
/// that same downstream backstop. `DestructiveTargetingVerdict::ClassifyMiss`
/// makes the miss an enumerator with no `default:` arm available (repo
/// doctrine, `-Werror=switch`) — a caller cannot compile a switch over this
/// verdict without deciding what a miss means for it.
///
/// POLICY IS THE CALLER'S TO CHOOSE, deliberately not baked into this header:
/// `/api/command` (checkpoint 1, #3685) treats `ClassifyMiss` as `break;` —
/// explicit fall-through to `build_classified_command`, which denies a real
/// miss anyway with its own taxonomy/metric/audit shape (Policy B, chosen
/// over an earlier draft's Policy A after external review: the early gate
/// would consult the SAME registry/classifier as the downstream chokepoint,
/// so an independent early denial would only duplicate — and risk drifting
/// from — evidence the chokepoint already produces). A future caller is free
/// to choose differently; the verdict shape supports either without a header
/// change.
///
/// D4 — WHY THIS GATE DOES NOT ITSELF ELEVATE PERMISSION: four of today's
/// (verified live, `capability_decls/*.hpp`) Destructive rows —
/// `script_exec.{exec,powershell,bash}` and `content_dist.execute_staged` —
/// carry `.securable = "Execution"` and `.execute_gate =
/// ExecuteGate::AdminOrApproval`, enforced at the dispatch chokepoint
/// (`classify_and_authorize_dispatch`, `agent_registry.hpp`) for every
/// caller including MCP. For those four rows, this gate's only job is
/// TARGETING confinement — the chokepoint's `AdminOrApproval` gate is
/// already the elevation ceiling. For the other (13, at last count — see the
/// catalogue-consistency test) Destructive rows, the caller's own
/// `require_permission(cap.securable, cap.operation)` check IS real
/// elevation (e.g. `tar.purge_source` -> `Infrastructure:Delete`) and stays
/// in the caller, deliberately — see D3 below.
///
/// D3 — WHY THIS GATE DOES NOT CALL `require_permission`/`has_permission`
/// ITSELF, AND WHY IT DOES NOT LIVE INSIDE `dispatch_confined_arms.hpp`:
///   * `require_permission` (the REST caller's JIT-elevation-aware surface
///     gate, `server.cpp`) and the dispatch chokepoint's `has_permission`
///     callback (base-grants-only, `agent_registry.hpp:168-180` "do not
///     silently widen") are DELIBERATELY DIFFERENT checks answering
///     different questions. Collapsing them here would either silently
///     widen the chokepoint's base-grants-only posture to admit JIT
///     elevation it does not today, or silently narrow the caller's
///     elevation-aware gate to the chokepoint's weaker one. Neither is this
///     header's call to make — it stays a pure TARGETING decision, and the
///     caller keeps its own authorization call exactly where it is.
///   * `dispatch_confined_arms.hpp`'s `dispatch_confined_arms` is called by
///     FOUR seams (`ServerImpl::dispatch_confined`'s background/schedule/
///     workflow/dashboard/MCP callers, per that header's own doc comment),
///     several of which legitimately scope-target a Destructive row today
///     (a scheduled purge, a governed deployment) and have no `res` to
///     answer a refusal on. Gating THERE would silently break those
///     legitimate callers as a side effect of fixing `/api/command` and MCP
///     `execute_instruction` — the two operator-facing route handlers that
///     actually owe a caller a decision-grade refusal. This gate is called
///     from route/handler code, never from the shared confined-dispatch
///     closure.
///
/// `confine_destructive_targets` below is the REST-side visible-set
/// narrowing this gate's `RefuseUntargeted`/`Targeted` split makes
/// necessary — unrelated to, and never a replacement for, the #1788
/// intersection `dispatch_confined_arms` performs on every dispatch arm
/// (that one still runs, later, on the confined `agent_ids` this function
/// returns).
///
/// CALLER 3 — `POST /api/dashboard/execute` (PR6.0b). The exec console is the
/// third and last operator-facing surface that resolves a free-form
/// `plugin.action` and lets the operator fan it out (`scope=__all__`,
/// `scope=group:<id>`, or `scope` omitted entirely, which that handler's
/// legacy UI contract reads as the whole fleet). It reaches agents through
/// `ServerImpl::dispatch_confined`, NOT through `/api/command`, so #3685's
/// two call sites did not cover it and every non-`AdminOrApproval`
/// Destructive row — `tar.purge_source`, `registry.delete_key`,
/// `filesystem.delete_lines`, `tags.clear`, `storage.clear` and the rest —
/// was fleet-targetable from it by any holder of the declared securable.
/// It is wired to THIS header for the reason D3 gives below: the gate belongs
/// in route/handler code, and the exec console is a route handler.
///
/// D3 IS UNCHANGED AND IS NOT A GAP — READ IT BEFORE "FINISHING THE JOB" AT
/// `ServerImpl::dispatch_confined`. It is tempting to read the absence of a
/// dispatch-class check in that shared seam as the last hole and to close it
/// there instead of adding a third route-level caller. That would be wrong,
/// and it is wrong for a reason no reviewer can see from `server.cpp` alone:
/// `ScheduleRunner::dispatch_tracked` (`schedule_runner.cpp`) dispatches
/// EVERY scheduled fire with `agent_ids={}` and a scope expression — an empty
/// stored `scope_expression` is mapped to `kBroadcastScope` right at the call
/// site — and `schedule_arming_check.hpp`'s `schedule_arming_permitted`
/// refuses only `system_reserved` and unclassified rows, never Destructive
/// ones. A Destructive-refusing gate at that seam therefore converts every
/// scheduled Destructive instruction into a permanent, silent zero-reach fire
/// (`yuzu_schedule_fire_failures_total`, "reached no agents"), including the
/// approval-gated ones the four-eyes ticket flow exists to make safe. The
/// same is true of `rest_api_v1.cpp`'s async result-set producers, which also
/// dispatch `{}` + `__all__` by construction. That behaviour is pinned by
/// `test_dispatch_confined_arms.cpp`'s "the shared confined-dispatch seam
/// does not refuse a Destructive fan-out" case, so the next person to try
/// this gets a red test instead of a shipped regression.
///
/// NOTHING BELOW CHANGED FOR THE DASHBOARD CALLER. Both functions were
/// already total over the inputs the exec console has, so PR6.0b EXTENDS this
/// header by adding a third call site and this documentation ONLY — it does
/// not fork, copy, widen or special-case either function, and the dashboard
/// reuses both refusal strings byte-for-byte rather than spelling its own.
/// That is the catastrophic-if-violated rule in
/// `.claude/routed-concerns-access-control.md`'s "Dispatch targeting" row: a
/// second copy of a chokepoint is exactly the drift the chokepoint exists to
/// remove.
/// WAVE 7 PR7.2 — FORENSICS SINGLE-TARGET RULE. A row on the `Forensics`
/// securable (e.g. `execution_artifacts.shimcache`) is `ReadOnly`, not
/// `Destructive` — it never reaches `evaluate_destructive_targeting`'s
/// Destructive branch — but it is still confined by
/// `requires_explicit_targets` to exactly one explicit, in-scope `agent_id`:
/// a forensic read is per-device by nature and a fan-out (`__all__`, a scope
/// key, or more than one id) is refused with `kForensicUntargetedMessage`,
/// distinct wording from the Destructive refusal. A Forensics row that
/// PASSES (verdict `Targeted`) is still run through
/// `confine_destructive_targets` exactly like a Destructive row: mgmt-group
/// confinement APPLIES to the read — a forensic read never reaches an agent
/// outside the operator's visible set, and the existing 404
/// `kDestructiveNoVisibleAgentMessage` ("no reachable in-scope agent")
/// answers an out-of-group id, same as today. `ScheduleRunner`'s
/// approval-gated fan-out (D3 above) is UNCHANGED by this addition: an
/// approved scheduled forensics read remains permitted by the
/// schedule-approval posture, not by this gate.
namespace yuzu::server {

/// The two refusal messages, spelled ONCE so `/api/command`, a future MCP
/// twin, and their tests pin the exact same bytes (#3685 defect 4 — these
/// strings had zero test occurrences before this file). Copied byte-exact
/// from the `/api/command` handler's current inline literals
/// (`server.cpp`, verified via `git grep -n` against this worktree) —
/// do not paraphrase either one.
inline constexpr std::string_view kDestructiveUntargetedMessage{
    "destructive action requires explicit in-scope agent_ids; broadcast and "
    "scope fan-out are refused"};
inline constexpr std::string_view kDestructiveNoVisibleAgentMessage{
    "no reachable in-scope agent"};

/// Wave 7 PR7.2 (forensics single-target rule). The `Forensics` securable
/// name, spelled once so this header, `rbac_store.cpp`'s seed and any future
/// caller never risk a typo'd literal drifting apart.
inline constexpr std::string_view kForensicsSecurable{"Forensics"};
/// The forensic-read refusal message — distinct wording from
/// `kDestructiveUntargetedMessage` (a forensic read is not a Destructive-class
/// row; it fails a narrower single-target rule, not the broadcast/fan-out
/// rule) — spelled once for the same reason as the pair above.
inline constexpr std::string_view kForensicUntargetedMessage{
    "forensic read requires exactly one explicit in-scope agent_id; "
    "broadcast and scope fan-out are refused"};
/// Metric-label / audit-detail reason string, engaged on
/// `DestructiveTargetingDecision::refusal_reason` for a Forensics refusal.
/// The Destructive-row counterpart (`kReasonDestructiveUntargeted`) already
/// exists in `dispatch_target_shape.hpp` (#3685) — reused here, not
/// redefined, to avoid a second copy of that reason string drifting apart.
inline constexpr std::string_view kReasonForensicUntargeted{"forensic_untargeted"};

/// The two `RefuseUntargeted` remediation strings, spelled ONCE so both
/// `execute_instruction` refusal sites in `mcp_server.cpp` never re-diverge
/// (they previously both hardcoded the Destructive wording unconditionally,
/// even for a Forensics refusal — a Forensics row is a distinct, read-only
/// classification with its own single-target rule, not "classified
/// Destructive"). Branch on `DestructiveTargetingDecision::refusal_reason`
/// via `remediation_for_refusal_reason` below rather than re-deriving which
/// applies from the capability.
inline constexpr std::string_view kDestructiveUntargetedRemediation{
    "this plugin.action is classified Destructive: name explicit agent_ids "
    "(no scope, no broadcast) and re-call"};
inline constexpr std::string_view kForensicUntargetedRemediation{
    "this is a single-target forensic read: specify exactly one explicit, "
    "in-scope agent_id (no scope, no broadcast) and re-call"};

/// The remediation text for a `RefuseUntargeted` decision, discriminated by
/// `refusal_reason` — never assume Destructive wording unconditionally.
[[nodiscard]] inline std::string_view
remediation_for_refusal_reason(std::string_view refusal_reason) noexcept {
    return refusal_reason == kReasonForensicUntargeted ? kForensicUntargetedRemediation
                                                        : kDestructiveUntargetedRemediation;
}

/// True for a row this gate's single-target rule applies to: every
/// `DispatchClass::Destructive` row (the existing rule), OR any row on the
/// `Forensics` securable (Wave 7 PR7.2 — a forensic read is not Destructive
/// but still must name exactly one explicit, in-scope `agent_id`; see the
/// file-level doc comment for why mgmt-group confinement still applies to a
/// Targeted forensic read).
[[nodiscard]] inline bool requires_explicit_targets(const CommandCapability& cap) noexcept {
    return cap.dispatch_class == DispatchClass::Destructive || cap.securable == kForensicsSecurable;
}

/// Verdict of the Destructive-dispatch targeting decision.
///
/// A `switch` over this with no `default:` is the structural fix for #3685
/// defect 1 (see this file's own doc comment above): a classify-miss is an
/// enumerator the caller MUST handle, never a skipped `if` branch.
enum class DestructiveTargetingVerdict : uint8_t {
    NotDestructive,   ///< Classified, and not Destructive — this gate does not apply; the
                      ///< caller's ordinary dispatch path (and its own authorization) proceeds
                      ///< unchanged.
    Targeted,         ///< Destructive, with explicit non-empty `agent_ids` and no scope/
                      ///< broadcast supplied — proceed to `confine_destructive_targets`.
    RefuseUntargeted, ///< Destructive, but `agent_ids` was empty/absent, or a scope key
                      ///< (including `"__all__"` broadcast) was supplied alongside or instead
                      ///< of it — refuse with `kDestructiveUntargetedMessage`.
    ClassifyMiss,     ///< `Unclassified`/`Ambiguous` — see `miss` on the decision struct.
                      ///< The caller decides policy for this arm; see the file-level doc
                      ///< comment above for `/api/command`'s Policy B choice.
};

/// The full decision: the verdict, plus whichever of `capability`/`miss` the
/// verdict engages. Exactly one of the two is engaged, mirroring the
/// `std::expected` input this is built from:
///   - `ClassifyMiss`   -> `miss` engaged, `capability` empty.
///   - every other verdict -> `capability` engaged, `miss` empty.
struct DestructiveTargetingDecision {
    DestructiveTargetingVerdict verdict;
    /// Engaged for every verdict except `ClassifyMiss` — the classified row,
    /// so the caller can read `.securable`/`.operation` for its own
    /// authorization check (D3 above) without reclassifying.
    std::optional<CommandCapability> capability;
    /// Engaged only for `ClassifyMiss` — which of the two classification
    /// failures it was, for a caller that wants to shape its own denial
    /// evidence off it (e.g. a Policy-A caller answering with the same
    /// taxonomy `build_classified_command` uses).
    std::optional<ClassificationError> miss;
    /// Engaged only on `RefuseUntargeted` — the `yuzu_server_dispatch_target_
    /// rejected_total{reason}` metric label and audit detail
    /// (`reason=<this> <plugin>:<action>`): `kReasonDestructiveUntargeted` for
    /// a Destructive row, `kReasonForensicUntargeted` for a Forensics row.
    /// Wave 7 PR7.2 — added so the three call sites never re-derive which
    /// reason/message pair applies from the capability themselves.
    std::string_view refusal_reason;
    /// Engaged only on `RefuseUntargeted` — the exact 400/-32602 response
    /// body: `kDestructiveUntargetedMessage` or `kForensicUntargetedMessage`.
    std::string_view refusal_message;
};

/// Pure, total, `noexcept` — the whole decision is a handful of comparisons
/// over already-computed inputs, no I/O.
///
/// CALLER CONTRACT — READ BEFORE WIRING THIS UP: `valid_nonempty_agent_ids`
/// and `scope_key_present` MUST be derived from the PARSED REQUEST BODY
/// AFTER `check_targeting_shape` (`dispatch_target_shape.hpp`) has already
/// run and returned no violation — never computed from a raw extraction
/// helper's output directly. `extract_json_string_array`/
/// `extract_json_string` collapse "omitted", "empty", "wrong type" and
/// "parse failure" into the same `{}`/`""` result; that erasure is exactly
/// the #2500/#2492 defect `check_targeting_shape` exists to close upstream
/// of this function, and reproducing the collapse here (by calling this
/// function on unvalidated extraction output) would silently reopen it for
/// the Destructive-class rows this gate protects.
///   - `valid_nonempty_agent_ids`: true iff `agent_ids` was supplied AND is
///     non-empty — which, downstream of a successful `check_targeting_shape`
///     call, also means every entry is a string (the shape check already
///     refused a non-array, an empty array, and a non-string entry).
///   - `scope_key_present`: true iff `scope` is present as a non-empty
///     string — INCLUDING `scope:"__all__"`. Broadcast is exactly what a
///     Destructive row refuses, and `check_targeting_shape` deliberately
///     permits `agent_ids` alongside `scope:"__all__"` (its one exemption
///     to the ids-vs-scope conflict rule) — so that combination reaches
///     this function and MUST still refuse here, even though the ids list
///     itself is well-formed.
///   - `agent_id_count` (Wave 7 PR7.2): the number of entries in the
///     validated `agent_ids` array. DEFAULTED to 0 so a caller that omits it
///     FAILS CLOSED for a `Forensics` row (0 != 1 -> `RefuseUntargeted`) —
///     a caller that has not been updated to count ids can never
///     accidentally admit a forensic broadcast by silent omission. Unused
///     for a Destructive row, which keeps its existing
///     `valid_nonempty_agent_ids`-based rule unchanged.
[[nodiscard]] inline DestructiveTargetingDecision evaluate_destructive_targeting(
    const std::expected<CommandCapability, ClassificationError>& classified,
    bool valid_nonempty_agent_ids, bool scope_key_present,
    std::size_t agent_id_count = 0) noexcept {
    if (!classified) {
        return DestructiveTargetingDecision{DestructiveTargetingVerdict::ClassifyMiss,
                                            std::nullopt, classified.error(), {}, {}};
    }
    if (!requires_explicit_targets(*classified)) {
        return DestructiveTargetingDecision{DestructiveTargetingVerdict::NotDestructive,
                                            *classified, std::nullopt, {}, {}};
    }
    if (classified->securable == kForensicsSecurable) {
        // Forensics: SINGLE-TARGET — exactly one explicit agent_id, no scope.
        if (agent_id_count != 1 || scope_key_present) {
            return DestructiveTargetingDecision{
                DestructiveTargetingVerdict::RefuseUntargeted, *classified, std::nullopt,
                kReasonForensicUntargeted, kForensicUntargetedMessage};
        }
        return DestructiveTargetingDecision{DestructiveTargetingVerdict::Targeted, *classified,
                                            std::nullopt, {}, {}};
    }
    // Destructive: today's rule — non-empty ids, no scope.
    if (!valid_nonempty_agent_ids || scope_key_present) {
        return DestructiveTargetingDecision{
            DestructiveTargetingVerdict::RefuseUntargeted, *classified, std::nullopt,
            kReasonDestructiveUntargeted, kDestructiveUntargetedMessage};
    }
    return DestructiveTargetingDecision{DestructiveTargetingVerdict::Targeted, *classified,
                                        std::nullopt, {}, {}};
}

/// #3685 (Sol's header-design review) — the input type for
/// `confine_destructive_targets`'s visible-agent parameter.
///
/// A DELIBERATELY DISTINCT type from `authz::VisibleSet`
/// (`std::optional<std::unordered_set<std::string>>`, `authz_model.hpp`) /
/// `DispatchCaller::exec_visible` (`dispatch_caller.hpp:54-59`). THOSE
/// types' `nullopt` means UNFILTERED — pass every target through, reserved
/// for a caller that has deliberately opted OUT of confinement
/// (background/system dispatch; every operator-facing surface's unwired
/// fallback is a PRESENT-EMPTY deny-all instead, never `nullopt` — see that
/// file's own doc comment).
///
/// `DestructiveVisibleAgents`'s `nullopt` means the OPPOSITE: the
/// management-group visible-agents read came back absent (no store wired)
/// or degraded (ADR-0042) — `confine_destructive_targets` must FAIL CLOSED
/// and admit nobody. Reusing `authz::VisibleSet` unchanged here — or even a
/// same-shaped `using` alias to `std::optional<std::vector<std::string>>` —
/// would leave a call site free to pass `exec_visible` (or any other
/// "unfiltered means nullopt" value) straight through, silently inverting
/// the fail-closed contract this function exists to enforce. The
/// constructor is deliberately EXPLICIT, not a converting one: at this
/// authorization seam, forcing a call site to spell
/// `DestructiveVisibleAgents{vis}` is a feature, not boilerplate — it is
/// the one line in the caller that says "yes, I know nullopt here means
/// deny-all."
struct DestructiveVisibleAgents {
    /// `nullopt` == absent/degraded read == FAIL CLOSED (empty result).
    /// Present (possibly empty) == the actual visible-agent set: an id
    /// absent from it is confined out; a present-but-empty set means
    /// deny-all too, by ordinary set-membership, with no special case
    /// needed.
    std::optional<std::vector<std::string>> agents;

    explicit DestructiveVisibleAgents(std::optional<std::vector<std::string>> agents_in)
        : agents(std::move(agents_in)) {}
};

/// REST-side management-group confinement for a Destructive-class dispatch —
/// unchanged semantics from the inline `/api/command` block this replaces:
/// preserves the input order and multiplicity of `agent_ids`, silently
/// drops any id absent from `visible`. `visible.agents == std::nullopt`
/// (absent or degraded read, ADR-0042) fails closed: the result is always
/// empty, matching the deny-all posture the dashboard fragment already uses
/// for the same degradation. Distinct from `authz::filter_to_scope`
/// (`authz_model.hpp`), whose `nullopt` means UNFILTERED — the OPPOSITE
/// posture; see `DestructiveVisibleAgents`'s doc comment above. Do not
/// merge the two functions or their semantics.
///
/// Pure, but not `noexcept` — it allocates the output vector (and a
/// temporary lookup set), so a `std::bad_alloc` is possible in principle,
/// same as the inline block it replaces.
[[nodiscard]] inline std::vector<std::string>
confine_destructive_targets(const std::vector<std::string>& agent_ids,
                            const DestructiveVisibleAgents& visible) {
    if (!visible.agents)
        return {};
    const std::unordered_set<std::string> allow(visible.agents->begin(), visible.agents->end());
    std::vector<std::string> out;
    out.reserve(agent_ids.size());
    for (const auto& id : agent_ids) {
        if (allow.contains(id))
            out.push_back(id);
    }
    return out;
}

} // namespace yuzu::server
