#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

/// @file dispatch_target_shape.hpp
/// The ONE home for the rule that decides whether a caller named a device
/// target (#2437 / #2500).
///
/// THE RULE, stated once: **an OMITTED targeting argument means "the whole
/// fleet"; a SUPPLIED one that resolves to nothing is an ERROR.** The two are
/// not the same request and must never collapse into each other.
///
/// This lives in its own surface-neutral header rather than in
/// `mcp_input_bounds.hpp` because it is not an MCP rule. It was written for
/// MCP `execute_instruction` (#2492), and the REST twins `POST /api/command`
/// and `POST /api/instructions/{id}/execute` had the identical defect under a
/// weaker gate (#2500) — on `/api/command`, under plain `Execution:Execute`
/// with no approval step at all. Everything left behind in
/// `mcp_input_bounds.hpp` — the transport-cap static_asserts, the per-field
/// size constants, the C8 subset commentary — is genuinely MCP-only; this is
/// not, and a REST route including an `mcp_`-named header would be the first
/// step toward the two surfaces drifting again.
///
/// WHY A SHARED FUNCTION AND NOT A SHARED CONVENTION: `server.cpp` used to
/// hold FOUR dispatch closures that each decided targeting independently.
/// Every caller that was safe was safe because its author remembered. That is
/// the property this header exists to replace, and a second copy of these
/// rules is how #2500 happened on REST after #2492 fixed the identical defect
/// on MCP.
///
/// WHERE THAT STANDS NOW, stated precisely because a comment claiming a pattern
/// is gone when it is half-gone is the trap this header exists to close:
///
///   - `classify_dispatch_arm` (this header) decides WHICH ARM for every
///     caller. One rule, no copies.
///   - `dispatch_confined_arms` (dispatch_confined_arms.hpp) decides WHO IS
///     REACHED for every caller — the per-arm visible-set intersection (#1788).
///     `ServerImpl::dispatch_confined` (the shared closure serving Dashboard,
///     MCP, workflow and instruction execute) and `command_routes.cpp`'s
///     `/api/command` handler (moved out of server.cpp by #2557) BOTH route
///     through it; the two byte-identical four-arm copies that previously
///     existed are gone.
///   - What each caller still owns is its own TARGET RESOLUTION (group store,
///     scope engine, principal from a live session vs an execution row) and
///     its own audit/HTTP shaping. Those legitimately differ, which is why one
///     closure could not simply absorb the other.
///
/// The one thing the arms parameterise is what an UNNAMED target means:
/// `broadcast_on_none=false` on the shared closure reaches NOBODY (#2500);
/// `true` is passed by callers whose UI/tool already normalised a deliberate
/// fleet selection into empty+empty. A new dispatch caller passes `false` and
/// names `__all__` — it must not rely on empty-fallthrough.
///
/// CLOSED (this range): the Dashboard form routes DO distinguish an omitted
/// `scope` from a supplied-but-empty `scope=` and refuse the latter —
/// `form_value_supplied()` (`web_utils.hpp`) for the urlencoded body,
/// `req.has_param("scope")` for the TAR sibling. `extract_form_value` alone
/// cannot tell them apart, which is the form-encoded twin of the
/// `extract_json_string_array` erasure this header names as the defect.
/// They still pass `broadcast_on_none=true` for a different and narrower
/// reason: an OMITTED `scope` is the legacy UI's whole-fleet contract.
/// `__all__` is passed through BY NAME and never stripped to empty+empty, so
/// None now arrives only from a genuinely omitted argument.
namespace yuzu::server {

/// The ONE spelling of "every enrolled agent" on the dispatch path.
///
/// Not an internal sentinel — a PUBLISHED ground scope kind: advertised by
/// `/discover/scope-kinds` (`discover_routes.cpp`), named in the MCP
/// `execute_instruction` inputSchema, and documented in
/// `docs/scope-walking-design.md`. Callers may legitimately supply it.
///
/// It is a named constant because #2500 changed what a typo costs. Before,
/// `"_all_"` failed to parse and fell into the broadcast default, so a
/// misspelling reached EVERYBODY — loud, and obvious in seconds. Now it
/// reaches NOBODY and still answers 200, which is silent. A literal repeated
/// across five files is how that lands in production unnoticed.
inline constexpr std::string_view kBroadcastScope{"__all__"};

/// One violated bound. Neither field is ever caller-derived.
struct BoundViolation {
    /// Closed-set metric label - stays a literal.
    const char* reason;
    /// Operator-facing text, formatted FROM the constants: hardcoding the
    /// numbers here would let this path and the handler's std::format siblings
    /// report different limits for the same bound after a change.
    std::string message;
};

/// The CLOSED `reason` label set this function can emit.
///
/// Single-sourced for the same reason `kExecInstrBoundReasons` is: the boot
/// pre-seed for `yuzu_server_dispatch_target_rejected_total` iterates THIS
/// array, so a reason added only at the emit site would be emitted-but-unseeded
/// — which passes its own test while silently breaking `absent()` alerting,
/// because the registry creates the series on demand and the dashboard reads
/// zero while calls are being refused.
///
/// Every entry here is also a member of `kExecInstrBoundReasons` in
/// `mcp_input_bounds.hpp`, and a static_assert there enforces that containment
/// — the MCP counter's pre-seed must not lose a label when one is added here.
/// That is why this array holds ONLY what `check_targeting_shape` itself emits:
/// route-level reasons live in `kRouteRejectReasons` below, because forcing
/// them into this array would force them into the MCP array too, and a reason
/// MCP can never emit does not belong in MCP's closed set.
inline constexpr std::string_view kReasonAgentIdsType{"agent_ids_type"};
inline constexpr std::string_view kReasonAgentIdsEmpty{"agent_ids_empty"};
inline constexpr std::string_view kReasonAgentIdType{"agent_id_type"};
inline constexpr std::string_view kReasonScopeType{"scope_type"};
inline constexpr std::string_view kReasonScopeEmpty{"scope_empty"};
inline constexpr std::string_view kReasonTargetConflict{"target_conflict"};

inline constexpr std::array<std::string_view, 6> kTargetingShapeReasons{
    kReasonAgentIdsType, kReasonAgentIdsEmpty, kReasonAgentIdType,
    kReasonScopeType,    kReasonScopeEmpty,    kReasonTargetConflict,
};

/// Reasons emitted by the ROUTES rather than by `check_targeting_shape`.
///
/// Separate from the array above for a reason found in review: the containment
/// static_assert made every shared reason also an MCP reason, and the first
/// attempt at labelling a `parent_id` violation therefore reused `scope_empty`
/// / `scope_type` — so the metric and the audit row both named a `scope` field
/// the caller had never sent. A tether added to prevent drift had produced a
/// lie. These labels are honest about which field was wrong, and are excluded
/// from the MCP set because MCP has neither a request body nor a `parent_id`.
/// Named so the EMIT SITES reference these entries rather than re-typing the
/// literal. An earlier version was an array plus hand-typed literals at every
/// route, with a test that hand-copied the same strings a third time — a
/// snapshot pretending to be a binding, in the test written to fix a snapshot
/// pretending to be a binding. Renaming one of these now breaks the build at
/// every site that emits it, which is the property the array was supposed to
/// have all along.
inline constexpr std::string_view kReasonBodyType{"body_type"};
inline constexpr std::string_view kReasonParentIdType{"parent_id_type"};
inline constexpr std::string_view kReasonParentIdEmpty{"parent_id_empty"};
inline constexpr std::string_view kReasonClosureNoTarget{"closure_no_target"};
inline constexpr std::string_view kReasonScopeUnsupported{"scope_unsupported"};
/// #3685: a Destructive-class capability was targeted without an explicit,
/// non-empty `agent_ids` list (broadcast, `scope`, and omitted-target fan-out
/// are all refused). Unlike its four siblings above this one IS emitted by
/// more than a single HTTP route — REST's `/api/command` 400 arm AND MCP's
/// `execute_instruction` (both the C8 pre-mint gate and the main-handler
/// backstop) — but it belongs here rather than in `kTargetingShapeReasons`
/// for the same reason its siblings do: it is not something
/// `check_targeting_shape`/`check_exec_instruction_shape` itself produces,
/// so forcing it into that array would force it into the MCP bound-check
/// containment static_assert in `mcp_input_bounds.hpp` for no reason — this
/// reason already has its own emit sites on both surfaces without that.
inline constexpr std::string_view kReasonDestructiveUntargeted{"destructive_untargeted"};
/// #2557: a Destructive-class capability WAS explicitly targeted (a non-empty
/// `agent_ids` list, so `kReasonDestructiveUntargeted` above does not apply),
/// but confining that list to the operator's visible agents
/// (`confine_destructive_targets`) emptied it out — every named id was
/// outside the caller's management-group confinement. `/api/command`'s
/// Destructive gate previously answered 404 here with NO metric increment
/// and NO audit row: an incident review of a near-miss "dispatch a purge at
/// devices I can't see" attempt found nothing. Distinct from
/// `kReasonDestructiveUntargeted` — that reason means "named nothing at
/// all"; this one means "named something, but none of it was visible" — an
/// auditor needs to tell the two apart the same way every other reason in
/// this family is kept apart by name rather than collapsed.
inline constexpr std::string_view kReasonDestructiveNoVisibleTarget{"destructive_no_visible_target"};

inline constexpr std::array<std::string_view, 7> kRouteRejectReasons{
    kReasonBodyType,             ///< the request body was not a JSON object
    kReasonParentIdType,         ///< parent_id was supplied and is not a string
    kReasonParentIdEmpty,        ///< parent_id was supplied and is an empty string
    kReasonClosureNoTarget,      ///< a dispatch closure was called naming no target
    kReasonScopeUnsupported,     ///< the route cannot honour `scope` and refuses it
    kReasonDestructiveUntargeted, ///< a Destructive-class capability lacked explicit targeting
    kReasonDestructiveNoVisibleTarget, ///< explicit targeting resolved to no VISIBLE agent
};

/// #881: a target the caller was AUTHORISED to reach (it survived the
/// #1788 visible-set intersection) but was withheld by the quarantine
/// dispatch gate (`dispatch_confined_arms.hpp`). Deliberately NOT a member
/// of either array above: it is not a targeting-SHAPE violation
/// (`kTargetingShapeReasons` — the request named nothing reachable) and not
/// one of the specific route-owned shapes `kRouteRejectReasons` binds by
/// test (`test_dispatch_target_shape.cpp` hand-lists exactly six as of
/// #3685, and this reason is emitted from the shared dispatch chokepoint,
/// not a route body check). It reuses the same
/// `yuzu_server_dispatch_target_rejected_total`
/// series its siblings use rather than mint a fourth metric for a third
/// kind of refusal.
inline constexpr std::string_view kReasonQuarantined{"quarantined"};

/// #3511: mirrors `kReasonQuarantined` exactly — same series, same three
/// routes (`dispatch_closure` / `command` / `legacy`), same rationale. Every
/// withheld-for-quarantine dispatch already produced a counter row and a
/// `spdlog::warn`; before this constant, a withheld-for-plugin-absence
/// dispatch produced neither. A plugin-absence withholding is not a policy
/// event (no audit row — see the call sites), but it is still an operational
/// fact worth a metric and a log line: an agentic caller retrying against a
/// misspelled or unregistered plugin name should be observable the same way
/// a quarantine denial is.
inline constexpr std::string_view kReasonUnknownPlugin{"unknown_plugin"};

/// #4496: the from-inventory-query result-set producer (REST and its MCP
/// twin) refused because the underlying inventory read hit its row/byte cap.
/// Deliberately NOT a member of either array above, same reasoning as
/// `kReasonQuarantined`/`kReasonUnknownPlugin`: this is a server-side
/// data-quality refusal on an otherwise well-formed, correctly-targeted
/// request, not a targeting-shape violation. Unlike its two siblings above,
/// this reason is NOT excluded from the `YuzuDispatchTargetRejected` alert's
/// regex - a well-targeted request failing here is exactly the class of
/// near-miss that alert exists to surface.
inline constexpr std::string_view kReasonQueryTruncated{"query_truncated"};

/// #4496: same route and same rationale as `kReasonQueryTruncated`, for the
/// sibling refusal when a candidate inventory record was excluded by the
/// #2437-class JSON depth guard rather than the row/byte cap.
inline constexpr std::string_view kReasonPoisonExcluded{"poison_excluded"};

/// #4496 follow-up: same route and same rationale as `kReasonPoisonExcluded`,
/// for the sibling refusal when a candidate inventory record was excluded
/// because its `data_json` failed to parse as JSON at all (a syntax defect,
/// not over-nesting) - a different failure cause, kept as a distinctly-named
/// reason so an operator debugging missing results can tell WHICH guard
/// excluded a record.
inline constexpr std::string_view kReasonParseErrorExcluded{"parse_error_excluded"};

/// Reject a targeting argument that was SUPPLIED but names nothing.
///
/// Both the type and the emptiness arms matter for the same reason: a handler
/// drops what it cannot use, an emptied target set falls into the broadcast
/// default, and broadcast means the entire fleet. Neither rule is expressible
/// in MCP's closed schema subset (`items` type-checking is not applied by the
/// operator tier, which has no C8 gate at all, and there is no `minItems`), and
/// on the REST twins there is no schema in the first place.
///
/// The consequences are worth stating separately per surface, because they are
/// different failures: on MCP, a human approving a ticket that reads
/// `agent_ids: []` must not be approving a fleet-wide dispatch. On REST there
/// is no human — `{"agent_ids":[1,2,3]}` from a client emitting numeric device
/// ids, or `{"agent_ids":[]}` from a device filter that matched nothing, became
/// a fleet-wide dispatch that returned success and audited as success.
///
/// MUST BE CALLED ON THE PARSED REQUEST BODY, never on values already run
/// through an extraction helper. `server.cpp`'s `extract_json_string_array`
/// returns `{}` for omitted, empty, not-an-array AND parse-failure alike; that
/// erasure IS the defect. A check written against its output cannot see the
/// non-array or non-string-`scope` cases at all, and would ship half the bug
/// with green tests.
///
/// PRECONDITION — `args` MUST be a JSON object, and the caller is responsible
/// for enforcing that BEFORE calling. `nlohmann::contains()` returns false for
/// an array, a scalar or null, so a non-object body looks exactly like one
/// that named no target, and "named no target" means the whole fleet. Passing
/// `["dev-1","dev-2"]` here would therefore broadcast.
///
/// Both REST callers reject a non-object body before reaching this function.
/// That rejection is pinned by a test on `POST /api/instructions/{id}/execute`
/// (`test_workflow_routes.cpp`, "a non-object body is refused") AND, since
/// #2557 extracted `/api/command` onto the `HttpRouteSink` seam
/// (`command_routes.{hpp,cpp}`), by `test_command_routes.cpp` too — that route
/// no longer runs inline on a raw `httplib::Server` inside `Server::start()`,
/// so the in-process `TestRouteSink` harness can reach it directly. Earlier
/// revisions of this comment cited #1786 for the prior gap, which was a
/// different issue entirely — the TAR retention-paused dashboard fragments in
/// `dashboard_routes.cpp`, closed by #2534 without touching `/api/command`.
/// That citation was inherited from a review summary and repeated without
/// reading the issue.
/// An earlier version of this paragraph
/// claimed both routes were pinned; they are not, and a false verification
/// claim in the header that is the source of truth for this invariant is worse
/// than the gap it was papering over.
///
/// Pure and total: no I/O. Returns the FIRST violation in a deterministic
/// order so a denial is reproducible.
[[nodiscard]] inline std::optional<BoundViolation>
check_targeting_shape(const nlohmann::json& args) {
    if (args.contains("agent_ids")) {
        const auto& a = args["agent_ids"];
        if (!a.is_array())
            return BoundViolation{kReasonAgentIdsType.data(), "agent_ids must be an array of strings"};
        if (a.empty())
            return BoundViolation{kReasonAgentIdsEmpty.data(),
                                  "agent_ids was supplied but is empty; omit it to target "
                                  "all agents deliberately"};
        for (const auto& v : a) {
            if (!v.is_string())
                return BoundViolation{kReasonAgentIdType.data(), "agent_ids entries must be strings"};
        }
    }
    // ── both selectors at once is AMBIGUOUS, so it is refused ────────────
    // Supplying `agent_ids` AND a real `scope` used to resolve by precedence:
    // scope won, and the explicit id list was discarded. So
    // `{"agent_ids":["dev-a"],"scope":"tag:prod"}` ran on every device matching
    // `tag:prod`, not on `dev-a`. Pre-existing, and the exact invariant this
    // rule exists to protect - the executed set was not the requested set -
    // just reached by disagreement between two selectors rather than by an
    // erased one. Found by an independent review AFTER the earlier rounds had
    // pinned the precedence in a test and published it in the API docs,
    // which is how preserving a behaviour quietly becomes endorsing it.
    //
    // `__all__` is exempt: it is not a narrowing selector, it is the broadcast
    // request, and `classify_dispatch_arm` already resolves ids-beat-broadcast
    // in the safe direction. Rejecting that pair would break the dashboard.
    if (args.contains("agent_ids") && args.contains("scope") &&
        args["scope"].is_string() &&
        args["scope"].get_ref<const std::string&>() != kBroadcastScope) {
        return BoundViolation{kReasonTargetConflict.data(),
                              "agent_ids and scope are alternatives; supply exactly one (or "
                              "neither, to target all agents)"};
    }
    if (args.contains("scope")) {
        const auto& sc = args["scope"];
        if (!sc.is_string())
            return BoundViolation{kReasonScopeType.data(), "scope must be a string"};
        if (sc.get_ref<const std::string&>().empty())
            return BoundViolation{kReasonScopeEmpty.data(),
                                  "scope was supplied but is empty; omit it to target all "
                                  "agents deliberately"};
    }
    return std::nullopt;
}

/// Which arm of a dispatch closure a (agent_ids, scope_expr) pair selects.
enum class DispatchArm {
    Group,     ///< `group:<id>` — resolve members.
    Scope,     ///< A scope DSL expression — resolve via the scope engine.
    Ids,       ///< An explicit agent_ids list.
    Broadcast, ///< `__all__` — every enrolled agent, asked for by name.
    None,      ///< Nothing named. Reaches NOBODY on the shared closure (#2500).
};

/// The branch selection shared by the dispatch closures, extracted so the one
/// decision with fleet-wide blast radius is unit-testable.
///
/// It was not testable before: the closures live inside `Server::start()`,
/// which no harness can reach (#2557 — NOT #1786, which covers the TAR
/// dashboard fragments and was closed by #2534), and the route tests assert against STUB
/// dispatch closures — so reverting the real sink's default broke nothing.
/// Governance's words: "the highest-blast-radius line in the PR is unverified".
///
/// ORDER IS THE CONTRACT, and getting it wrong is not hypothetical: the first
/// version of the #2500 sink inversion put Broadcast FIRST, which made
/// `{agent_ids:["a"], scope:"__all__"}` reach the entire fleet on the shared
/// closure while the MCP closure reached exactly agent "a". A widening
/// introduced by the change that exists to remove widenings. An explicit id
/// list therefore always wins over a broadcast REQUEST.
[[nodiscard]] inline DispatchArm classify_dispatch_arm(bool has_agent_ids,
                                                       std::string_view scope_expr) {
    const bool real_scope = !scope_expr.empty() && scope_expr != kBroadcastScope;
    if (real_scope && scope_expr.starts_with("group:"))
        return DispatchArm::Group;
    if (real_scope)
        return DispatchArm::Scope;
    if (has_agent_ids)
        return DispatchArm::Ids;
    if (scope_expr == kBroadcastScope)
        return DispatchArm::Broadcast;
    return DispatchArm::None;
}

/// The string spelling of a `DispatchArm`, fed into
/// `build_classified_command`'s `target_arm` (-> `compute_plan_hash`) so two
/// dispatches of the same `plugin.action` differing only in HOW targets were
/// selected (an explicit id list vs. a scope match that happens to resolve to
/// the same set) mint distinct plan identities. Never parsed back, only
/// hashed, so the exact spelling is a private implementation detail — but
/// #2557 gave it a SECOND caller (`command_routes.cpp`, alongside
/// `server.cpp`'s own dispatch closure), so it moved here rather than being
/// copied: both callers feed the same `build_classified_command` chokepoint,
/// and a copy that drifted in spelling would silently mint two different
/// plan-hash families for what is otherwise the identical dispatch.
[[nodiscard]] inline std::string_view dispatch_arm_label(DispatchArm arm) {
    switch (arm) {
    case DispatchArm::Group: return "group";
    case DispatchArm::Scope: return "scope";
    case DispatchArm::Ids: return "ids";
    case DispatchArm::Broadcast: return "broadcast";
    case DispatchArm::None: return "none";
    }
    return "none";
}

/// Did the caller name a target at all?
///
/// The companion to `check_targeting_shape`, and the reason a sink can tell
/// "broadcast me" from "I meant something specific". A sink that only sees an
/// empty id vector cannot distinguish them — which is why every fix here has to
/// reach the parsed body rather than the extracted values.
[[nodiscard]] inline bool targeting_supplied(const nlohmann::json& args) {
    return args.contains("agent_ids") || args.contains("scope");
}

} // namespace yuzu::server
