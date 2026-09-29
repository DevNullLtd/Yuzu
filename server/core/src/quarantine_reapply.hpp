#pragma once

/// @file quarantine_reapply.hpp
/// Shared chokepoint for re-driving a device's endpoint containment from its
/// STORED `QuarantineStore` record — the #3127 `already_active` retry recipe
/// (MCP `quarantine_device`) and #3425's reconnect reconciler both need the
/// exact same recipe: read the stored row, validate the stored whitelist at
/// the server edge, build the dispatch params, and (Layer B) drive the
/// dispatch itself. A second hand-rolled copy of this recipe in the
/// reconciler is precisely the drift `dispatch_confined_arms.hpp` /
/// `dispatch_target_shape.hpp` exist to prevent for their own chokepoints —
/// see CLAUDE.md's routed-concerns entries for those two.
///
/// Two layers, split by I/O:
///
/// LAYER A (this header, inline, PURE — no I/O, no includes beyond the
/// standard library): the whitelist validator, the params builder, and the
/// agent-side status-response parser. Mirrors `quarantine_dispatch_decision.hpp`'s
/// "pure on purpose" discipline — a unit test can exhaust every branch
/// without a store, an agent, or a build dir.
///
/// LAYER B (declared here, implemented in `quarantine_reapply.cpp` — genuine
/// I/O: a `QuarantineStore::get_status` read plus an injected dispatch call):
/// `redispatch_stored_containment` is the ONE place that reads the stored
/// row, validates it, and drives a re-dispatch. Both callers hand it a thin
/// adapter closing over their own dispatch shape — MCP's 7-param
/// caller-typed `DispatchFn` (`DispatchCaller` + audit + response shaping
/// stay in `mcp_server.cpp`) and the reconciler's 6-param
/// `command_dispatch_fn` (`server.cpp:16466`) — so this file stays
/// transport-agnostic. Each caller keeps its OWN error strings, audit calls,
/// and response envelope; this function only owns "what to dispatch and
/// whether the stored row was safe to dispatch at all".
///
/// WHY STORED, NEVER FRESH/CALLER-SUPPLIED: dispatching anything other than
/// the row already on disk lets a caller (or a background re-dispatch) rewrite
/// a contained device's firewall allow-list with no store update and no audit
/// trail — a state divergence between what's recorded and what's enforced,
/// not an idempotent retry. Same rule `quarantine_dispatch_decision.hpp`
/// documents for the MCP `already_active` path; this header is where it
/// becomes structurally impossible to bypass rather than merely documented
/// twice.
///
/// WHY THE WHITELIST IS RE-VALIDATED HERE TOO: the row on disk may have been
/// written by `POST /api/v1/quarantine` (record-only, no charset/length
/// validation of its own) and is about to reach the agent's
/// netsh/iptables/pf sink via THIS dispatch — the request-time validation in
/// `mcp_server.cpp`'s live-quarantine path does not cover a row written
/// through the REST twin or read back later by the reconciler.

#include <cstddef>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

class QuarantineStore;
struct QuarantineRecord;

// ── Layer A: pure ────────────────────────────────────────────────────────

inline constexpr std::string_view kQuarantinePluginName{"quarantine"};
inline constexpr std::string_view kQuarantineApplyAction{"quarantine"};
inline constexpr std::string_view kQuarantineStatusAction{"status"};
inline constexpr std::string_view kQuarantineWhitelistParam{"whitelist_ips"};
inline constexpr std::size_t kQuarantineWhitelistMaxLen = 512;

/// Mirrors the agent's `is_safe_ip` charset (`[0-9a-fA-F.:]`, <=45 chars per
/// comma-separated token) — moved verbatim from the MCP handler's lambda
/// (#3127) so both callers of `redispatch_stored_containment` clear the same
/// check before a stored whitelist reaches the agent's firewall sink.
[[nodiscard]] bool quarantine_whitelist_tokens_safe(std::string_view whitelist);

/// Builds the dispatch params for a re-application of `stored_whitelist`.
/// `nullopt` when the stored value fails the server-edge check (oversized or
/// an unsafe token) — the caller must treat that as a hard stop, never
/// dispatch anyway. An empty `stored_whitelist` is valid and yields an empty
/// map (the plugin's `whitelist_ips` param is optional).
[[nodiscard]] std::optional<std::unordered_map<std::string, std::string>>
build_quarantine_reapply_params(std::string_view stored_whitelist);

/// The agent-side quarantine plugin's `do_status` response vocabulary. Dual:
/// a pre-#3429 agent emits only `active`/`inactive`; #3429 (agent-side
/// mutation-serialization hardening, merged) adds `partial`/`uncertain`/
/// `degraded` and a `status|busy` mutation-gate response. Parsing both
/// vocabularies here means this fleet-version-skew requirement holds
/// regardless of merge order — a fleet upgrades agents gradually, so both
/// vocabularies are live in production simultaneously for as long as any
/// pre-#3429 agent is deployed.
enum class QuarantineEndpointState { active, partial, inactive, uncertain, degraded, busy, unknown };

/// Parses a `quarantine.status` (or a busy mutation response) command
/// response payload. Scans line by line (the plugin's `do_status` can emit
/// more than one output line); a line starting `state|` yields its first
/// pipe-delimited token (a trailing `|note|<text>` is tolerated and
/// ignored); a line `status|busy` yields `busy`; anything else contributes
/// nothing. The FIRST recognized token wins. No recognized line anywhere in
/// `payload` yields `unknown` — never silently treated as `active`.
[[nodiscard]] QuarantineEndpointState parse_quarantine_endpoint_state(std::string_view payload);

/// Exhaustive switch, no `default:`, so a future `QuarantineEndpointState`
/// enumerator fails to compile here instead of silently falling through
/// (the `should_dispatch_isolation` idiom, `quarantine_dispatch_decision.hpp`).
/// Only `active` counts as confirmed endpoint containment — `partial`/
/// `uncertain`/`degraded` are explicitly NOT confirmation (the endpoint may
/// be half-contained or the agent may not know), and `busy`/`inactive`/
/// `unknown` obviously are not.
[[nodiscard]] constexpr bool endpoint_state_confirms_containment(QuarantineEndpointState state) {
    switch (state) {
    case QuarantineEndpointState::active:
        return true;
    case QuarantineEndpointState::partial:
    case QuarantineEndpointState::inactive:
    case QuarantineEndpointState::uncertain:
    case QuarantineEndpointState::degraded:
    case QuarantineEndpointState::busy:
    case QuarantineEndpointState::unknown:
        return false;
    }
    return false; // fail closed; unreachable while the switch above stays exhaustive
}

// ── Layer B: I/O-bearing, implemented in quarantine_reapply.cpp ───────────

/// Why the read (or the row) made a re-dispatch impossible. Distinct from
/// `dispatch_threw`/`agents_reached == 0` below, which mean the DISPATCH
/// itself did not confirm reach — those are still a `ReapplyOutcome`, not an
/// error, because the store write DID succeed and something durable exists
/// to retry against.
enum class ContainmentReapplyErrorKind {
    store_error,       // get_status failed (pool/query failure)
    no_active_record,  // get_status succeeded but returned nothing (released
                        // between the caller's read and this call — a narrow
                        // race, not a store failure)
    whitelist_invalid, // the stored row failed quarantine_whitelist_tokens_safe
};

struct ContainmentReapplyError {
    ContainmentReapplyErrorKind kind;
    // The store's raw error message for `store_error`; a fixed human string
    // ("quarantine record not found on retry read") for `no_active_record`;
    // empty for `whitelist_invalid` — callers that want a message for that
    // case supply their own fixed text (the recipe intentionally does not
    // echo the rejected value back).
    std::string detail;
};

struct ContainmentReapplyResult {
    bool dispatch_threw{false};
    std::string command_id;
    int agents_reached{0};
};

/// Caller-supplied dispatch adapter: pre-bound to plugin `quarantine`,
/// action `quarantine`, target `{agent_id}`, and whatever caller identity /
/// execution_id / DispatchCaller shape that transport needs — this function
/// only ever calls it with the validated `whitelist_ips` params (or an empty
/// map). Exceptions thrown by the callee are caught here and reported via
/// `ContainmentReapplyResult::dispatch_threw`, matching the MCP handler's
/// existing try/catch around its own dispatch call.
using ReapplyDispatchFn =
    std::function<std::pair<std::string, int>(const std::unordered_map<std::string, std::string>&)>;

/// The shared recipe: `store.get_status(agent_id)` -> validate the stored
/// whitelist -> build params -> invoke `dispatch_fn(params)`. `out_record`
/// receives the stored row on success (the caller typically needs
/// `quarantined_by`/`reason`/`quarantined_at` for its own response/audit
/// shaping, which this function does not interpret). Returns `unexpected`
/// without ever calling `dispatch_fn` on any `ContainmentReapplyError`.
[[nodiscard]] std::expected<ContainmentReapplyResult, ContainmentReapplyError>
redispatch_stored_containment(QuarantineStore& store, const std::string& agent_id,
                              const ReapplyDispatchFn& dispatch_fn, QuarantineRecord& out_record);

} // namespace yuzu::server
