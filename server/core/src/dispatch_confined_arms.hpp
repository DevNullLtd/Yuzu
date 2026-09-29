#pragma once

#include <cctype>
#include <array>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "authz_model.hpp"
#include "dispatch_target_shape.hpp"

/// @file dispatch_confined_arms.hpp
/// The ONE place a dispatch arm's VISIBLE-SET INTERSECTION is decided (#1788).
///
/// THE RULE, stated once: every arm — an explicit id list, a management group,
/// a scope expression, a named `__all__` broadcast — is a TARGETING mechanism,
/// never an authz exemption. Each resolves to a candidate set, and every
/// candidate set is intersected with the caller's `Execution:Execute` visible
/// set immediately before the send.
///
/// WHY THIS IS A SEPARATE, PURE FUNCTION and not just a shared member: the
/// callers legitimately DIFFER in how they resolve targets and report failure.
/// `ServerImpl::dispatch_confined` recovers a scope principal from the
/// execution row and has no `res` to write to (background runners call it);
/// the `/api/command` handler reads the live session and answers 400/503 on a
/// bad scope. Those differences are real and are why one closure could not
/// simply absorb the other. But the part that MUST NOT DRIFT is not the
/// resolution — it is the intersection, and that part is identical. So each
/// caller keeps its own resolution and error shaping, and both route the
/// decision of WHO IS ACTUALLY REACHED through here.
///
/// The routed concern (.claude/routed-concerns.md, "Dispatch targeting") says a
/// second copy of the shared rule is how the identical defect survived on REST
/// after MCP was fixed. Two byte-identical copies of the four-arm intersection
/// existed before this header; a future arm added to one and not the other is
/// precisely the drift it warns about.
///
/// Being dependency-injected, this is also the seam the confinement tests bind:
/// a fake sink records exactly who was reached, so a test FAILS when any single
/// `in_scope`/`filter_to_scope` call is removed. Route-level mocks that merely
/// observe the VisibleSet being handed over cannot do that (CDX-R8-02) — they
/// stay green while the intersection is deleted.
///
/// #881 — QUARANTINE CONTAINMENT is gated HERE too, for the identical reason
/// #1788's visible-set intersection is: a per-route quarantine check is how
/// the next identical defect survives on whichever route is added after this
/// one. `ContainmentGate` is a SECOND, orthogonal filter applied AFTER the
/// #1788 intersection and BEFORE the send — authz decides WHO MAY be
/// targeted, containment decides WHO MAY be REACHED RIGHT NOW, and neither
/// one substitutes for the other. Every arm applies it, including the
/// `send_to_all_unfiltered` fast path: an unfiltered caller (`exec_visible ==
/// nullopt`, e.g. every `system`-caller dispatch) is exactly the caller most
/// likely to reach a quarantined agent if this gate were route-scoped instead
/// of chokepoint-scoped, because it is the one path that was never filtered
/// by anything else. `ContainmentGate::enforced == false` is a pure no-op —
/// reserved for the quarantine plugin's OWN control channel, so lifting a
/// quarantine can never be blocked by the quarantine it is lifting.
namespace yuzu::server {

/// The registry operations the arms need, injected so tests can observe the
/// exact send set without a live `AgentRegistry`.
struct ConfinedDispatchSink {
    /// Send to one agent; returns true when the command was actually delivered.
    std::function<bool(const std::string&)> send_to;
    /// UNFILTERED fleet broadcast — used ONLY when the caller's visible set is
    /// `nullopt` (genuinely unfiltered authority), never as an empty-set
    /// fallback.
    std::function<int()> send_to_all_unfiltered;
    /// Every currently-known agent id, used to narrow a broadcast when the
    /// caller IS filtered. HA WS-5 (ADR-2002 §7a): once `known_agent_ids` is
    /// wired to a presence-merged source (`AgentRegistry::all_ids()`), a
    /// Broadcast/None candidate is no longer by construction always locally
    /// known — see `prepare_route_fallback` and `presence_widens` below,
    /// both updated for exactly this reason.
    std::function<std::vector<std::string>()> known_agent_ids;
    /// WS-4 4.2b Task C (fallback-only gateway routing-directory consult,
    /// #4246). Called ONCE per arm — with the arm's FULL candidate list,
    /// BEFORE any `send_to` call for that arm. Default (unset — every
    /// dispatch before this slice, and every dispatch with no directory
    /// wired, e.g. `forward_legacy_command`'s Broadcast-only sink) is a pure
    /// no-op: `send_to` alone decides delivery, unchanged. Returns true iff
    /// the batched directory read itself degraded
    /// (store_unavailable/db_error) — surfaced as
    /// `ArmDispatchResult::route_unreadable` /
    /// `ConfinedDispatchOutcome::route_unreadable` (see that field's own doc
    /// comment: this slice only DEFINES and PRODUCES the flag; wiring its
    /// outbox-reschedule / cascade consumption is the next task).
    ///
    /// HA WS-5 update: Broadcast/None's `confined_broadcast()` now calls this
    /// too, on its FILTERED path — Group/Scope/Ids always did; Broadcast's
    /// candidates stopped being "by construction always locally known" the
    /// moment `known_agent_ids` could return a presence-only (remote) id, and
    /// an unprepared remote id would otherwise reach `send_to` with no
    /// directory consult, silently fail, and land in `not_sent` — a
    /// wired-but-behaviorally-dead reader, the exact class of bug WS-4 hit
    /// twice before shipping. `confined_broadcast`'s UNFILTERED fast path
    /// (`send_to_all_unfiltered`) does NOT call this — see
    /// `presence_widens` below for how that path stays safe instead.
    std::function<bool(const std::vector<std::string>& candidates)> prepare_route_fallback;
    /// HA WS-5 (governance Gate 4 unhappy-path hardening, 2026-09-22):
    /// `AgentRegistry::has_remote_presence(candidates)` — a SINGLE-lock
    /// membership check against the registry's CURRENT local state, given
    /// the candidate list `confined_broadcast()` already fetched via
    /// `known_agent_ids()`. `confined_broadcast()`'s UNFILTERED fast path
    /// (`send_to_all_unfiltered`, which walks ONLY local sessions and has no
    /// per-id hook to consult the directory) is eligible only when this
    /// returns false — i.e. presence added nothing reachable this call, so
    /// the fast path's local-only walk is provably complete. This
    /// SUPERSEDES an earlier `local_agent_count()`-vs-`known_agent_ids().
    /// size()` comparison, which was racy: those were two SEPARATE lock
    /// acquisitions, so concurrent local churn between them could make the
    /// SIZES coincidentally match while the SETS differed, silently taking
    /// the fast path with a presence-only id still in `candidates`. A direct
    /// membership check against the already-fetched list has no such gap —
    /// see `has_remote_presence`'s own doc comment. UNSET (a test/legacy
    /// sink that predates this field) is treated as "presence widens" (an
    /// unconditional true) by `confined_broadcast` — so an unmigrated sink
    /// always takes the SLOW (filtered, `prepare_route_fallback`-covered)
    /// path instead of silently skipping this check: fail-closed on missing
    /// wiring, never fail-open into a stale fast path.
    std::function<bool(const std::vector<std::string>& candidates)> presence_widens;
};

/// Targets the CALLER has already resolved. Each arm reads only its own field;
/// resolution (group store, scope engine, principal recovery) and any audit or
/// HTTP response stays with the caller.
struct ConfinedDispatchTargets {
    /// `DispatchArm::Ids` — the explicit list as supplied.
    const std::vector<std::string>* agent_ids = nullptr;
    /// `DispatchArm::Group` — members already read from the management-group
    /// store. Null means the store was unavailable: reach nobody.
    const std::vector<std::string>* group_members = nullptr;
    /// `DispatchArm::Scope` — the set the scope engine matched. Null means
    /// resolution was ABORTED (parse failure, degraded DB, failed owner check);
    /// the caller has already audited it and this arm must reach nobody. That
    /// null-is-abort contract is what keeps ADR-0036's fail-closed rule from
    /// silently inverting under a NOT combinator.
    const std::vector<std::string>* scope_matched = nullptr;
};

/// #881: the quarantine dispatch gate for ONE dispatch, built once by
/// `ServerImpl::make_containment_gate` and threaded through every arm as a
/// REQUIRED parameter (see `dispatch_confined_arms`'s own parameter comment
/// for why a default would be exactly the drift this header exists to
/// prevent).
///
/// The id set is held BY VALUE, not by pointer: `dispatch_confined_arms` can
/// run from a background dispatcher with no request in flight, so a pointer
/// into the caller's store lock / snapshot state would be a lifetime hazard
/// the moment that caller's stack frame returns. A `ContainmentGate` is
/// small and built once per dispatch — copying it is not a per-agent cost.
struct ContainmentGate {
    /// NOT DEFAULT-CONSTRUCTIBLE, deliberately.
    ///
    /// The permissive state (`enforced == false`) used to be what you got for
    /// free from `ContainmentGate{}`, which made DISABLING containment the
    /// syntactically cheapest thing a call site could do. That is the same
    /// shape as this file's own `nullopt`-vs-present-empty invariant, where the
    /// unwired value must never be the permissive one — and it was not
    /// theoretical: replacing `make_containment_gate(plugin)` with
    /// `ContainmentGate{}` at the confined-dispatch seam turned quarantine
    /// enforcement off for REST, MCP, dashboard and workflow dispatch while the
    /// entire suite — 10,454 MCP assertions included — stayed green.
    ///
    /// Both states must now be NAMED. `exempt_control_plugin()` says why it is
    /// permissive; `enforcing()` cannot be built without deciding fail-closed.
    /// A future call site cannot reach the permissive state by omission.
    ContainmentGate() = delete;

    ContainmentGate(bool enforced_in, bool fail_closed_in,
                    std::unordered_set<std::string> quarantined_in)
        : enforced(enforced_in), fail_closed(fail_closed_in),
          quarantined(std::move(quarantined_in)) {}

    /// Containment off for this dispatch — a pure no-op on every arm,
    /// INCLUDING the unfiltered broadcast fast path. Reserved for the
    /// quarantine plugin's OWN control channel (`is_quarantine_control_plugin`):
    /// release must never be blocked by the containment it is lifting.
    [[nodiscard]] static ContainmentGate exempt_control_plugin() {
        return ContainmentGate{false, false, {}};
    }

    /// Containment on. `fail_closed` must be decided explicitly — there is no
    /// default, because "reach nobody" and "reach everyone not quarantined"
    /// are the two outcomes this type exists to keep apart.
    [[nodiscard]] static ContainmentGate enforcing(bool fail_closed_in,
                                                   std::unordered_set<std::string> quarantined_in) {
        return ContainmentGate{true, fail_closed_in, std::move(quarantined_in)};
    }

    /// False disables containment entirely for this dispatch. Reserved for the
    /// quarantine plugin's own control channel — see `exempt_control_plugin()`.
    bool enforced;
    /// True means the containment READ degraded past its bounded-staleness
    /// budget, or the store is durably unavailable — reach NOBODY on every
    /// arm, including Broadcast, rather than guess who is quarantined. Only
    /// meaningful when `enforced` is true; see
    /// `evaluate_quarantine_degradation` for how this is decided.
    bool fail_closed;
    /// Currently-quarantined agent ids (a fresh read, or a stale-but-in-
    /// budget snapshot). Only consulted when `enforced && !fail_closed`.
    std::unordered_set<std::string> quarantined;
};

/// Result of a confined dispatch: how many sends succeeded, and — #881 —
/// which ids were REACHABLE (they survived the #1788 visible-set
/// intersection) but withheld by the quarantine gate. The distinction
/// matters for audit: an id absent from both `sent` and `denied_quarantined`
/// was never authorised to be reached in the first place, which is a
/// different fact than "authorised, but currently contained".
///
/// `denied_quarantined` mirrors the multiplicity of the target list it was
/// built from — a duplicate id in an explicit `agent_ids` list yields a
/// duplicate entry here, exactly as it already yields a duplicate count in
/// `sent` today. Callers that fan this out into audit rows or metric
/// increments (`ServerImpl::audit_quarantine_dispatch_denied`) inherit that
/// multiplicity; nothing downstream assumes uniqueness.
struct ArmDispatchResult {
    int sent = 0;
    /// The ids withheld, for the audit rows that name a device. **Empty on a
    /// fail-closed denial** — see `denied_quarantined_count`.
    std::vector<std::string> denied_quarantined;
    /// How many were withheld, always. This is the field to report a COUNT
    /// from; `denied_quarantined.size()` is not the same number under
    /// fail-closed, where the ids are deliberately not collected. Two fields
    /// rather than one because the two consumers want different things — the
    /// audit path wants identities where they are meaningful, and every
    /// response body wants a count — and conflating them cost a fleet-sized
    /// allocation on the dispatch thread during exactly the degradation that
    /// triggered it.
    std::size_t denied_quarantined_count = 0;
    /// Ids that passed the containment check (an actual `sink.send_to` was
    /// attempted) but the registry reported delivery failure. ADR-1007: this
    /// is the caller-visible half of the per-device concurrency claim leak —
    /// `resolve_and_dispatch_confined`'s `claim_fn` runs BEFORE this function
    /// ever sees the candidate list, so an id here already holds a fresh,
    /// still-open claim with nobody now going to release it on success. This
    /// function stays pure (no store access — see the file's own header
    /// comment and the #881 "ONE store operation per dispatch" discipline),
    /// so it only COLLECTS the ids; `wire_and_dispatch_confined` is the seam
    /// that built `claim_fn` in the first place and is where the release
    /// actually happens. Populated only for the Group/Scope/Ids arms — the
    /// only arms `claim_fn` is ever applied to (ADR-1007: Broadcast/None are
    /// a documented non-goal).
    std::vector<std::string> not_sent;
    /// #3424/#3511: ids that were REACHABLE (survived #1788 + containment)
    /// but withheld because the target agent's own reported plugin inventory
    /// does not include the dispatched plugin -- a command guaranteed to fail
    /// with "plugin not found" on that agent, indistinguishable from a real
    /// success until this filter existed (#3511). Checked AFTER `contained`:
    /// a quarantined-and-plugin-absent agent is reported quarantined, the
    /// stronger and more actionable of the two facts, matching the ordering
    /// `denied_quarantined` already uses relative to `not_sent`.
    std::vector<std::string> unknown_plugin;
    /// How many were withheld for plugin absence, always -- same
    /// count-vs-identities split as `denied_quarantined_count`, though unlike
    /// quarantine there is no fail-closed mode here to make the two diverge;
    /// kept as a separate field anyway so every consumer of this struct reads
    /// counts the same way regardless of which reason produced them.
    std::size_t unknown_plugin_count = 0;
    /// WS-4 4.2b Task C: true iff a `sink.prepare_route_fallback` call for
    /// this arm's candidate list reported a DEGRADED directory read (the
    /// batched `GatewayRouteStore::lookup_routes` call itself failed), as
    /// opposed to a successful read that simply found no route for a
    /// locally-missing candidate — that is a definite no-route and shows up
    /// in `not_sent` exactly like any other undelivered id, nothing new.
    /// Like `ConfinedDispatchOutcome::containment_unreadable`, it distinguishes
    /// "the directory itself could not answer" from "answered and said no".
    ///
    /// CRITICAL — it is NOT interchangeable with `containment_unreadable`, on
    /// the one axis that matters to an all-or-nothing consumer: a fail-closed
    /// containment gate withholds every id BEFORE its `send_to`, forcing
    /// `sent == 0`; a degraded directory read does NOT. The arm walk above
    /// still runs under `route_unreadable`, so a locally-connected id is
    /// genuinely sent (`++sent`) while a directory-only id lands in `not_sent`.
    /// A consumer that whole-batch-reverts or reports whole-batch-undelivered
    /// on `route_unreadable` (as it may on `containment_unreadable`) acts
    /// against already-delivered devices — see the rationale in
    /// deployment_engine's `settle_claimed_batch` and policy_evaluator's
    /// `compute_delivered`. command_outbox_delivery CAN reschedule on it
    /// because it re-drives the STABLE command_id (dedup-absorbed), not a
    /// fresh one.
    bool route_unreadable = false;
};

/// Outcome of `resolve_and_dispatch_confined` (dispatch_scope_ladder.hpp) --
/// declared here rather than there so every `DispatchFn` typedef across the
/// codebase (mcp_server.hpp, bundle_orchestrator.hpp, dashboard_routes.hpp,
/// deployment_engine.hpp, dex_routes.hpp, preflight_routes.hpp,
/// tar_tree_routes.hpp -- #3424/#3511) can include this lighter header
/// instead of dispatch_scope_ladder.hpp's much heavier dependency list. `sent`
/// is the count actually dispatched; `scope_parse_error` is set only when the
/// Scope arm's resolved expression failed to parse -- the one distinction a
/// caller with an HTTP response to shape might still act on differently than
/// reaching nobody.
///
/// #881: `denied_quarantined` carries every reachable id the quarantine gate
/// withheld OUT of this function, so the caller can audit it -- without this
/// field the majority of dispatch (MCP, workflows, schedules, REST v1, all
/// of which route through `wire_and_dispatch_confined`) would enforce
/// quarantine but audit nothing. `command_id` rides along for the same
/// reason: once the return type stopped being a bare `std::pair<std::string,
/// int>`, the caller needed a way to correlate `denied_quarantined` entries
/// with the dispatch that produced them without re-deriving it.
///
/// `command_id` is populated ONLY by `wire_and_dispatch_confined` (it takes
/// the id as a parameter and assigns it on return); `resolve_and_dispatch_confined`
/// has no command id to give it and leaves the field default-constructed
/// (empty). A caller of `resolve_and_dispatch_confined` directly -- today only
/// dispatch_scope_ladder's own tests -- must not read `command_id` off its
/// result.
///
/// `unknown_plugin` / `unknown_plugin_count` (#3511) mirror `ArmDispatchResult`'s
/// own fields of the same name -- see that struct's doc comments above for
/// what each means. Kept as separate fields here (not derived from
/// `denied_quarantined_count`/etc. at read time) so every one of the 7
/// `DispatchFn` consumers reads the same shape regardless of which layer
/// produced it. `containment_unreadable` (#3424) has NO counterpart on
/// `ArmDispatchResult` -- that struct has no concept of "the gate itself
/// degraded" separate from a specific-quarantine denial (both fold into its
/// `denied_quarantined_count`); this field is derived here, at the
/// `resolve_and_dispatch_confined`/`wire_and_dispatch_confined` layer, as
/// `gate.enforced && gate.fail_closed` -- see its own doc comment below.
struct ConfinedDispatchOutcome {
    int sent = 0;
    std::optional<std::string> scope_parse_error;
    /// The ids withheld, for audit rows that name a device. **Empty on a
    /// fail-closed denial** -- see `denied_quarantined_count`.
    std::vector<std::string> denied_quarantined;
    /// How many were withheld, always. Report counts from THIS, never from
    /// `denied_quarantined.size()`, which differs under fail-closed. See
    /// `ArmDispatchResult` for why the two are separate.
    std::size_t denied_quarantined_count = 0;
    std::string command_id;
    /// ADR-1007: ids whose claim (taken by `claim_fn` before the send) was
    /// never actually delivered -- mirrors `ArmDispatchResult::not_sent`, see
    /// its doc comment for why the collection happens there and the release
    /// happens at `wire_and_dispatch_confined` instead. Empty whenever no
    /// concurrency claim was in effect for this dispatch.
    std::vector<std::string> not_sent;
    /// #3424: true when the quarantine gate itself failed closed (containment
    /// state unreadable) rather than a specific device being quarantined --
    /// `gate.enforced && gate.fail_closed`, threaded out here because
    /// `dispatch_confined_arms` reports every fail-closed denial as a
    /// `denied_quarantined_count` increment with no way for a caller to tell
    /// "the gate is degraded" from "these specific devices are contained"
    /// without also being handed `gate` itself.
    bool containment_unreadable = false;
    /// #3511: ids withheld because the dispatched plugin is not in the
    /// target's reported inventory -- mirrors `denied_quarantined` /
    /// `denied_quarantined_count` exactly; see `ArmDispatchResult::unknown_plugin`.
    std::vector<std::string> unknown_plugin;
    std::size_t unknown_plugin_count = 0;
    /// WS-4 4.2b Task C -- mirrors `ArmDispatchResult::route_unreadable`,
    /// threaded out here the same way `containment_unreadable` already is.
    /// See that field's doc comment; only ever set for the Group/Scope/Ids
    /// branches below (`dispatch_confined_arms` never calls
    /// `prepare_route_fallback` for Broadcast/None).
    bool route_unreadable = false;
};

/// #881: case-insensitive predicate for the quarantine control-channel
/// exemption. Pure — no store access — so a test can bind it directly without
/// a live `QuarantineStore`. Normalises to lowercase itself
/// (`ServerImpl::dispatch_confined` already lowercases the ACTION at its own
/// call site, never the plugin) so `"Quarantine"`/`"QUARANTINE"` exempt
/// exactly like `"quarantine"`.
///
/// Keyed on the `(plugin, ACTION)` pair against a CLOSED set — not on the
/// plugin name alone. All four actions the plugin registers today
/// (quarantine, unquarantine, status, whitelist) are exempt, deliberately:
/// narrowing it to `unquarantine` alone would break re-isolation (a fresh
/// `quarantine` action against an already-contained device), whitelist repair
/// of a contained device's exceptions, and #3127's retry path — all of which
/// are the plugin managing its OWN containment state, not an operator
/// reaching a quarantined agent through some other plugin. Keying on the
/// plugin alone would have let a FIFTH action added later inherit the bypass
/// silently, with nothing in review to notice; see the closed-set comment in
/// the body.
[[nodiscard]] inline bool is_quarantine_control_plugin(std::string_view plugin,
                                                       std::string_view action) {
    constexpr std::string_view kQuarantinePlugin{"quarantine"};
    auto iequals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != b[i])
                return false;
        }
        return true;
    };
    if (!iequals(plugin, kQuarantinePlugin))
        return false;

    // Keyed on the (plugin, ACTION) pair, not the plugin alone.
    //
    // Exempting a whole plugin means a FUTURE action inherits the exemption
    // silently — the plugin declares exactly four today, and a fifth would
    // arrive already able to bypass containment with nothing in review to
    // notice. This set is closed against the plugin's declared actions
    // (`acts[]` in quarantine_plugin.cpp); anything else is gated.
    //
    // Why all four are here rather than release alone: `unquarantine` IS the
    // release path; `status` is read-only and answering it for a contained host
    // is the point; `whitelist` is how a management path is repaired, and
    // gating it would make a host whose whitelist is wrong unrecoverable
    // remotely — the stranding this control exists to avoid; and `quarantine`
    // on an already-contained host is the re-dispatch #3127 relies on. An
    // action NOT on this list gets no exemption even on this plugin.
    for (const auto allowed : {std::string_view{"quarantine"}, std::string_view{"unquarantine"},
                               std::string_view{"status"}, std::string_view{"whitelist"}}) {
        if (iequals(action, allowed))
            return true;
    }
    return false;
}

/// The bounded-staleness budget (#881 spec item 6): a `nullopt` read served
/// from the last-known-good snapshot is trusted only while the snapshot is
/// younger than this. Chosen so a transient Postgres blip (pool-timeout,
/// brief query error) degrades to "serve slightly-stale containment state"
/// rather than "every dispatch on the fleet fails closed" — ADR-0012 §1
/// governs the fail-closed DECISION on unreadable containment state; this is
/// what keeps that posture from converting a connection-pool hiccup into a
/// fleet-wide dispatch outage.
inline constexpr std::chrono::seconds kQuarantineSnapshotMaxAge{60};

/// The last-known-good containment read, held by `ServerImpl` behind its own
/// mutex (never the store's) and refreshed on every SUCCESSFUL
/// `list_quarantined()`. `valid == false` means no successful read has ever
/// landed (e.g. fresh boot before the first dispatch).
struct QuarantineSnapshot {
    std::unordered_set<std::string> ids;
    std::chrono::steady_clock::time_point at{};
    bool valid = false;
};

/// Closed outcome-label set for `yuzu_server_quarantine_gate_total{outcome=}`
/// — spelled once so the emit site can't drift from what a dashboard/alert
/// expects.
inline constexpr std::string_view kQuarantineGateOutcomeFresh{"fresh"};
inline constexpr std::string_view kQuarantineGateOutcomeStale{"stale"};
inline constexpr std::string_view kQuarantineGateOutcomeFailClosed{"fail_closed"};
/// The fourth value. It was previously emitted as a bare literal at the
/// composition site while this block called itself a closed set "spelled once
/// so the emit site cannot drift" — the drift the constants exist to prevent,
/// inside the declaration that forbids it.
inline constexpr std::string_view kQuarantineGateOutcomeExempt{"exempt_control_plugin"};

/// Every label the gate can emit, so the boot pre-seed cannot fall out of step
/// with the emit sites. A bounded-label counter that is never pre-seeded makes
/// `absent()` ambiguous between "the gate never blocked" and "the gate never
/// ran", which is exactly the question a containment alert needs answered.
inline constexpr std::array<std::string_view, 4> kQuarantineGateOutcomes{
    kQuarantineGateOutcomeFresh, kQuarantineGateOutcomeStale,
    kQuarantineGateOutcomeFailClosed, kQuarantineGateOutcomeExempt};

/// #881 / #3402 — the CLOSED set of server-internal pushes that reach an agent
/// WITHOUT passing through the containment gate above.
///
/// These are not operator instruction dispatch. They are the server keeping
/// its own state coherent: a fleet-topology snapshot request, a Guardian rule
/// push, an asset-tag sync. Gating them would mean a quarantined device stops
/// receiving the enforcement rules that make containment meaningful, which
/// inverts the control — so the bypass is correct. What was NOT correct was
/// leaving it enforced by a comment at each `registry_.send_to` call site: a
/// fifth site added later inherits the bypass silently, and the reviewer who
/// would have caught it has nothing to grep for.
///
/// So the bypass is spelled as an ENUM, and `ServerImpl::send_system_reserved`
/// is the only door. A new internal push cannot compile without adding an
/// enumerator here — a visible diff in the file that documents the exemption,
/// next to the rule it is an exemption from. The label doubles as the
/// `capability` dimension on `yuzu_server_system_reserved_push_total`, so the
/// pushes that bypass containment are also the pushes an operator can COUNT;
/// before this they were invisible on every channel.
/// SCOPE OF THE BYPASS, per enumerator — because "these three are exempt" is
/// not by itself enough for anyone reviewing the containment surface:
///   - `tar_fleet_snapshot` requests a READ-ONLY topology snapshot.
///   - `asset_tags_sync` writes device tags. No execution.
///   - `inventory_sync_now` asks ONE agent to re-run its daily-sync source(s)
///     and report (`__sync__.now`, ADR-0016 update). Read-only, no execution;
///     operator-REQUESTED via `POST /api/v1/hardware/{id}/sync` (which gates
///     the operator on Execution:Execute for that device) but system-DISPATCHED,
///     so it rides this door. Not quarantine-gated, same as tar_fleet_snapshot.
///   - `guardian_push_rules` delivers Guardian baseline rules the agent may
///     ENFORCE, and is therefore the one exempt channel that mutates the
///     endpoint. It is NOT arbitrary command execution: the assertion
///     vocabulary is a closed five-value set (`AssertionKind` in
///     agents/core/src/guardian_rule_eval.hpp — file presence, file hash,
///     registry value, service running, service stopped), and dangerous
///     registry keys / service names are refused at `dangerous_enforce_in_spec`
///     before a push is built. So an operator with Guardian deploy rights can
///     change TYPED, BOUNDED state on a contained device while their
///     `execute_instruction` is refused — deliberate, since enforcing a
///     baseline on a compromised host is the point, but it is the enumerator
///     to think hardest about before adding a sibling.
enum class SystemReservedPush {
    tar_fleet_snapshot,
    guardian_push_rules,
    asset_tags_sync,
    inventory_sync_now,
};

/// Label for one enumerator. A switch with no `default:` so a new enumerator
/// fails to compile here rather than silently metering as something else.
[[nodiscard]] inline constexpr std::string_view
system_reserved_push_label(SystemReservedPush push) {
    switch (push) {
    case SystemReservedPush::tar_fleet_snapshot:
        return "tar.fleet_snapshot";
    case SystemReservedPush::guardian_push_rules:
        return "__guard__.push_rules";
    case SystemReservedPush::asset_tags_sync:
        return "asset_tags.sync";
    case SystemReservedPush::inventory_sync_now:
        return "__sync__.now";
    }
    return "unknown"; // unreachable while the switch stays exhaustive
}

/// Every enumerator, so the boot pre-seed cannot fall out of step with the
/// call sites — same reason `kQuarantineGateOutcomes` exists. An internal push
/// that has never fired must read as zero, not as an absent series.
inline constexpr std::array<SystemReservedPush, 4> kSystemReservedPushes{
    SystemReservedPush::tar_fleet_snapshot, SystemReservedPush::guardian_push_rules,
    SystemReservedPush::asset_tags_sync, SystemReservedPush::inventory_sync_now};

/// The two outcomes a system-reserved push can have at the registry seam.
/// `sent` means `AgentRegistry::send_to` accepted the frame (for a
/// gateway-attached agent that is a QUEUE, not a delivery — the same caveat
/// `dispatch_confirmed` carries on the MCP side); `undelivered` means it did
/// not, which for a Guardian rule push is a silently unenforced device.
inline constexpr std::array<std::string_view, 2> kSystemReservedPushResults{"sent", "undelivered"};

/// Outcome of one degradation-policy evaluation: the `ContainmentGate` to
/// dispatch with, the snapshot to persist (only set on a fresh read — the
/// caller stores it back under its own mutex), and the metric label to
/// increment.
struct QuarantineDegradationResult {
    ContainmentGate gate;
    std::optional<QuarantineSnapshot> refreshed_snapshot;
    std::string_view outcome;
};

/// #881 spec item 6 — the degradation policy itself, extracted pure so the
/// bounded-staleness decision is unit-testable with a fake reader, no
/// `ServerImpl`, no Postgres.
///
/// `list_quarantined()` returns `std::nullopt` for THREE conditions the
/// caller cannot tell apart (store not open, pool-acquire timeout, query
/// failure — quarantine_store.cpp) — `fresh_read` collapses all three to
/// "no read". Those are ATTEMPTED reads that failed, and they are what the
/// bounded-staleness budget is for.
///
/// `fail_closed_regardless` is the separate, stronger signal: the read was
/// never attempted, or cannot be trusted to have been. Two callers set it,
/// and the distinction from a failed read is the whole point — a stale
/// snapshot is a reasonable answer when the store could not answer, and NOT a
/// reasonable answer when nobody asked it:
///   * the store is null or `!is_open()`;
///   * the dispatch could not obtain a containment-read slot within its wait
///     budget (server.cpp's read-concurrency bound). Serving stale here would
///     under-enforce against a HEALTHY store — the read would have succeeded,
///     nobody made it, and a device quarantined since the snapshot would be
///     dispatched to. That is the containment bypass this gate exists to
///     close, arriving through the mechanism added to protect the pool.
///
/// BE HONEST ABOUT ITS REACHABILITY: `QuarantineStore::open_` is set once at
/// construction and never cleared, and the server refuses to boot on a store
/// that did not open — so in a supported deployment this arm has NO
/// production trigger today. It is not dead weight (a future caller
/// constructing the store lazily, or a store that learns to close itself,
/// arrives at a decision that is already correct and already tested) and it
/// fails CLOSED, so the arm is safe in both directions. But an earlier
/// revision of this comment presented it as a stronger RUNTIME signal than
/// the `nullopt` read, which overstates what it can currently observe:
/// today every real degradation arrives as `nullopt`, and the
/// bounded-staleness budget below is what actually decides those.
///
/// Otherwise a `nullopt` read within
/// `kQuarantineSnapshotMaxAge` of the last successful read serves the stale
/// snapshot; past that budget, or with no snapshot at all, it fails closed.
[[nodiscard]] inline QuarantineDegradationResult evaluate_quarantine_degradation(
    const std::optional<std::unordered_set<std::string>>& fresh_read,
    bool fail_closed_regardless, const QuarantineSnapshot& last_known_good,
    std::chrono::steady_clock::time_point now) {
    // Every arm names its fail-closed decision explicitly — `enforcing()` has
    // no default for it, so a new branch cannot inherit one by omission.
    if (fresh_read) {
        return QuarantineDegradationResult{
            .gate = ContainmentGate::enforcing(/*fail_closed=*/false, *fresh_read),
            .refreshed_snapshot = QuarantineSnapshot{*fresh_read, now, true},
            .outcome = kQuarantineGateOutcomeFresh};
    }
    if (fail_closed_regardless) {
        return QuarantineDegradationResult{
            .gate = ContainmentGate::enforcing(/*fail_closed=*/true, {}),
            .refreshed_snapshot = std::nullopt,
            .outcome = kQuarantineGateOutcomeFailClosed};
    }
    if (last_known_good.valid && (now - last_known_good.at) < kQuarantineSnapshotMaxAge) {
        return QuarantineDegradationResult{
            .gate = ContainmentGate::enforcing(/*fail_closed=*/false, last_known_good.ids),
            .refreshed_snapshot = std::nullopt,
            .outcome = kQuarantineGateOutcomeStale};
    }
    return QuarantineDegradationResult{
        .gate = ContainmentGate::enforcing(/*fail_closed=*/true, {}),
        .refreshed_snapshot = std::nullopt,
        .outcome = kQuarantineGateOutcomeFailClosed};
}

/// #881 / CDX-P1-06 — the COMPOSITION of the containment gate, extracted so
/// the production decision is reachable from a test.
///
/// `evaluate_quarantine_degradation` above is pure and well covered, and
/// `dispatch_confined_arms` is bound by its own suite. What sat between them —
/// the plugin exemption, and the choice to build an ENFORCED gate at all —
/// lived only inside `ServerImpl::make_containment_gate`, where no test could
/// reach it. That gap was not theoretical: making the exemption unconditional
/// there (`if (true) return ContainmentGate{.enforced = false}`) disables
/// containment for EVERY plugin, and the whole `[dispatch][quarantine]` suite
/// still passed. That is exactly the failure this file's routed concern warns
/// about — a well-tested helper whose production composition can be reverted
/// with the suite green.
///
/// `ServerImpl` keeps only what is genuinely server-shaped: performing the
/// store read, holding the snapshot mutex, and incrementing the metric. It
/// must NOT carry its own copy of the exemption branch; it decides only
/// whether to spend a read.
///
/// The snapshot is in/out. The MONOTONIC guard lives here rather than at the
/// call site, so a slower concurrent read cannot overwrite a newer one — a
/// property that is now testable too.
[[nodiscard]] inline QuarantineDegradationResult compose_containment_gate(
    std::string_view plugin, std::string_view action, bool fail_closed_regardless,
    const std::optional<std::unordered_set<std::string>>& fresh_read,
    QuarantineSnapshot& snapshot /*in/out*/, std::chrono::steady_clock::time_point now) {
    // The quarantine plugin's own control channel is the ONE exemption:
    // release must never be blocked by the containment it is lifting. Decided
    // WITHOUT needing a store read, so a store outage cannot strand a
    // quarantined host by blocking its own unquarantine.
    if (is_quarantine_control_plugin(plugin, action))
        return QuarantineDegradationResult{.gate = ContainmentGate::exempt_control_plugin(),
                                           .refreshed_snapshot = std::nullopt,
                                           .outcome = kQuarantineGateOutcomeExempt};

    auto decision =
        evaluate_quarantine_degradation(fresh_read, fail_closed_regardless, snapshot, now);

    if (decision.refreshed_snapshot &&
        (!snapshot.valid || decision.refreshed_snapshot->at > snapshot.at))
        snapshot = *decision.refreshed_snapshot;

    return decision;
}

/// Reach exactly the agents this caller is authorised to reach AND currently
/// permitted to reach under containment, and return how many were actually
/// sent to plus which reachable ids the quarantine gate withheld.
///
/// `broadcast_on_none` is the ONE thing the arms parameterise: a caller whose
/// UI/tool already normalised an empty selection into a deliberate fleet
/// broadcast passes true; the shared closure — where no target named at all
/// must reach NOBODY, not everybody (#2500) — passes false. The None arm never
/// decides this for itself, so the meaning cannot drift per caller.
///
/// `gate` is REQUIRED, not defaulted, and sits immediately before `sink` —
/// deliberately: a defaulted parameter (or folding containment into a sink
/// field instead) would let a future caller silently opt out of quarantine
/// enforcement by omission, which is exactly the per-route drift this
/// header's doc comment exists to prevent for #1788 and now also for #881.
///
/// `plugin_missing` (#3424/#3511) is DIFFERENT from `gate` on exactly one
/// point, deliberately: it IS defaulted, to the empty set. `gate`'s empty
/// constructor was deleted because the empty/omitted state was the dangerous
/// one (containment silently off). Omitting `plugin_missing` is safe by
/// contrast: an empty set withholds nothing, which is exactly the pre-#3511
/// behaviour every existing caller already has, not a new bypass. A caller
/// that supplies it gets the filter; a caller (or test) that does not keeps
/// compiling and keeps today's semantics. The set names ids POSITIVELY known
/// to lack the dispatched plugin — built once per dispatch by
/// `AgentRegistry::ids_missing_plugin`, which itself fails open (see that
/// function) on an agent with no reported inventory at all, so a
/// freshly-registered or gateway-relayed agent is never wrongly withheld for
/// absence of DATA rather than absence of the plugin.
[[nodiscard]] inline ArmDispatchResult
dispatch_confined_arms(DispatchArm arm, const ConfinedDispatchTargets& targets,
                       const authz::VisibleSet& exec_visible, bool broadcast_on_none,
                       const ContainmentGate& gate, const ConfinedDispatchSink& sink,
                       const std::unordered_set<std::string>& plugin_missing = {}) {
    ArmDispatchResult result;

    // #881: the ONE per-id containment check every arm applies AFTER the
    // #1788 visible-set intersection and BEFORE the send. `!gate.enforced` is
    // a pure no-op. `gate.fail_closed` withholds EVERY id it is asked about
    // (a degraded containment read must not silently read as "nothing is
    // quarantined" — ADR-0012 §1); otherwise it withholds only ids actually
    // in `gate.quarantined`. Every id withheld here is recorded, whichever
    // branch withheld it — the caller's audit trail does not need to
    // distinguish "specifically quarantined" from "fail-closed" at this
    // layer (it can, via `gate.fail_closed` itself, which the caller already
    // has).
    const auto contained = [&](const std::string& aid) -> bool {
        if (!gate.enforced)
            return false;
        if (gate.fail_closed) {
            // COUNT, don't collect. A fail-closed dispatch denies every target,
            // so collecting them builds a fleet-sized vector<string> — on the
            // dispatch thread, per refused dispatch, during the store
            // degradation that caused the refusal — purely so the caller can
            // take .size(). Every caller of a fail-closed result does exactly
            // that: the audit path emits ONE aggregate row rather than N (see
            // audit_quarantine_dispatch_fail_closed), and the response bodies
            // report a count. The identities are not used and, for a
            // fail-closed denial, carry no information the gate state does not
            // already imply.
            ++result.denied_quarantined_count;
            return true;
        }
        if (gate.quarantined.contains(aid)) {
            result.denied_quarantined.push_back(aid);
            ++result.denied_quarantined_count;
            return true;
        }
        return false;
    };

    // #3424/#3511: the plugin-presence sibling of `contained` above, same
    // shape -- checked AFTER containment (a quarantined+absent agent reports
    // quarantined, not absent) and BEFORE the send. No fail-closed mode: the
    // registry read behind `plugin_missing` is an in-memory snapshot with no
    // degraded state to fail closed against, unlike the quarantine store.
    const auto plugin_absent = [&](const std::string& aid) -> bool {
        if (!plugin_missing.contains(aid))
            return false;
        result.unknown_plugin.push_back(aid);
        ++result.unknown_plugin_count;
        return true;
    };

    // Broadcast narrowed to the caller's visible set. Unfiltered (nullopt)
    // authority keeps the fast send-to-all path ONLY while containment is not
    // enforced: `send_to_all_unfiltered()` has no per-id hook at all, so
    // taking it while `gate.enforced` is true would reach a quarantined agent
    // with no check whatsoever — the exact hole #881 exists to close on the
    // production path that hits it (`command_dispatch_fn`'s
    // `DispatchCaller{.system = true}`, `forward_legacy_command`'s Broadcast
    // arm). Under enforcement the walk below runs regardless of visibility:
    // `filter_to_scope` is a no-op on a `nullopt` visible set, so an
    // unfiltered caller still walks every known agent — just individually
    // gated instead of fast-pathed. A present set — INCLUDING a present EMPTY
    // one, which means deny-all under ADR-0033 §1 — already took this walk
    // before #881 and continues to.
    //
    // COST, ACCEPTED: this walk trades `send_to_all_unfiltered`'s single
    // registry-lock snapshot for one `known_agent_ids()` acquisition plus a
    // per-id `send_to()` acquisition — the same shape the filtered broadcast
    // path has always used, now also paid by a `system`-caller fleet-wide
    // dispatch once containment is enforced. Correctness, not throughput, is
    // what #881 buys here; a single-snapshot `send_to_all_except(...)` sink
    // operation would restore it but is a larger change than this gate
    // package carries.
    // #3424/#3511: the fast path additionally requires `plugin_missing` to be
    // EMPTY. `send_to_all_unfiltered()` has no per-id hook, so it cannot skip
    // a specific agent -- exactly the same reason `gate.enforced` gates it
    // above. An empty `plugin_missing` set means no known agent lacks the
    // plugin, so skipping the walk changes nothing (there is nothing for the
    // walk to find); a non-empty set forces the same per-id walk containment
    // already forces, trading the single-snapshot send for a per-id one on
    // exactly the dispatches where it matters, never on the common case where
    // every agent has the plugin.
    const auto confined_broadcast = [&]() -> int {
        // HA WS-5 (ADR-2002 §7a): `known_agent_ids()` can now include
        // presence-only (remote) ids, so the fast path below — which walks
        // ONLY local sessions via `send_to_all_unfiltered` and has no per-id
        // hook to consult the routing directory for one — is eligible only
        // when presence added nothing reachable this call. A DIRECT
        // membership check against the already-fetched `candidates`
        // (`presence_widens`), not a two-call size comparison — the latter
        // raced (governance Gate 4 unhappy-path finding, 2026-09-22): see
        // `presence_widens`'s own doc comment. Unset (a sink predating this
        // field) is treated as "presence widens" (true), so a genuinely
        // non-empty fleet always falls through to the filtered path below.
        auto candidates = authz::filter_to_scope(sink.known_agent_ids(), exec_visible);
        const bool widened = sink.presence_widens ? sink.presence_widens(candidates) : true;
        if (!exec_visible && !gate.enforced && plugin_missing.empty() && !widened)
            return sink.send_to_all_unfiltered();
        // WS-4 4.2b Task C: same batched-before-the-walk shape Group/Scope/Ids
        // already use — Broadcast/None previously skipped this call on the
        // (pre-WS-5) assumption that a broadcast candidate is always locally
        // known; that assumption no longer holds once known_agent_ids() can
        // return a presence-only id (see the sink field's own doc comment).
        if (sink.prepare_route_fallback)
            result.route_unreadable = sink.prepare_route_fallback(candidates);
        int n = 0;
        for (const auto& aid : candidates)
            if (!contained(aid) && !plugin_absent(aid) && sink.send_to(aid))
                ++n;
        return n;
    };

    switch (arm) {
    case DispatchArm::Group:
        // A management group is a targeting mechanism, not an authz
        // exemption — and, per #881, not a containment exemption either.
        if (targets.group_members) {
            // WS-4 4.2b Task C: ONE batched directory consult for the arm's
            // FULL candidate list, before any per-id send — never per-id.
            if (sink.prepare_route_fallback)
                result.route_unreadable = sink.prepare_route_fallback(*targets.group_members);
            for (const auto& aid : *targets.group_members) {
                if (!authz::in_scope(exec_visible, aid) || contained(aid) || plugin_absent(aid))
                    continue;
                if (sink.send_to(aid))
                    ++result.sent;
                else
                    result.not_sent.push_back(aid);
            }
        }
        break;
    case DispatchArm::Scope:
        // Null == the caller aborted resolution and already audited it.
        if (targets.scope_matched) {
            // WS-4 4.2b Task C: same batched-before-the-walk shape as Group
            // above. The candidate list handed to the directory is the
            // PRE-INTERSECTION `*targets.scope_matched` (a superset of what
            // will actually be sent to once `filter_to_scope` below narrows
            // it) — a lookup for an id later dropped by authz costs nothing
            // beyond an unused map entry, and keeps this call symmetric with
            // Group/Ids rather than needing its own post-intersection list.
            if (sink.prepare_route_fallback)
                result.route_unreadable = sink.prepare_route_fallback(*targets.scope_matched);
            for (const auto& aid : authz::filter_to_scope(*targets.scope_matched, exec_visible)) {
                if (contained(aid) || plugin_absent(aid))
                    continue;
                if (sink.send_to(aid))
                    ++result.sent;
                else
                    result.not_sent.push_back(aid);
            }
        }
        break;
    case DispatchArm::Ids:
        if (targets.agent_ids) {
            // WS-4 4.2b Task C: same shape as Group/Scope above.
            if (sink.prepare_route_fallback)
                result.route_unreadable = sink.prepare_route_fallback(*targets.agent_ids);
            for (const auto& aid : authz::filter_to_scope(*targets.agent_ids, exec_visible)) {
                if (contained(aid) || plugin_absent(aid))
                    continue;
                if (sink.send_to(aid))
                    ++result.sent;
                else
                    result.not_sent.push_back(aid);
            }
        }
        break;
    case DispatchArm::Broadcast:
        // Asked for by its published name (`__all__`) — still narrowed, and
        // still gated: this is the unfiltered fast path's only other caller.
        result.sent = confined_broadcast();
        break;
    case DispatchArm::None:
        // No target named at all. The caller decides what that MEANS; when it
        // means "reach nobody" the caller also owns the counter/log, because
        // there is no `req` here and background runners call this too.
        if (broadcast_on_none)
            result.sent = confined_broadcast();
        break;
    }
    return result;
}

} // namespace yuzu::server
