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
/// The endpoint is the firewall plugin: `firewall.quarantine` applies,
/// `firewall.quarantine_status` reads, `firewall.release` lifts. This header
/// owns the server's side of that contract: the constants naming those
/// actions, the mapping from the stored whitelist to the plugin's `exceptions`
/// grammar, and the reading of the plugin's status reply.
///
/// Two layers, split by I/O:
///
/// LAYER A (this header, PURE — no I/O, standard library only; most of it is
/// inline, but `map_whitelist_to_exceptions`, `build_quarantine_reapply_params`,
/// `parse_containment_reply` and `combined_output` are defined out of line in
/// `quarantine_reapply.cpp`, which includes the store and response-store headers
/// for Layer B; `combined_output` takes a forward-declared `StoredResponse`): the
/// whitelist mapper, the params builder, and the agent-side status-reply parser. Mirrors `quarantine_dispatch_decision.hpp`'s
/// "pure on purpose" discipline — a unit test can exhaust every branch
/// without a store, an agent, or a build dir.
///
/// LAYER B (declared here, implemented in `quarantine_reapply.cpp` — genuine
/// I/O: a `QuarantineStore::get_status` read plus an injected dispatch call):
/// `redispatch_stored_containment` is the ONE place that reads the stored
/// row, maps it, and drives a `firewall.quarantine` dispatch for a stored
/// record (the reconciler and MCP both go through it). Both callers hand it a
/// thin adapter closing over their own dispatch shape — MCP's 7-param
/// caller-typed `DispatchFn` (`DispatchCaller` + audit + response shaping
/// stay in `mcp_server.cpp`) and the reconciler's 6-param
/// `command_dispatch_fn` (wired in `server.cpp`) — so this file stays
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
/// written by `POST /api/v1/quarantine` (record-only) and is about to reach
/// the agent's firewall sink via THIS dispatch — the request-time validation
/// in `mcp_server.cpp`'s live-quarantine path does not cover a row written
/// through the REST twin or read back later by the reconciler. The mapper is
/// the one validator: a token it cannot express in the agent's grammar
/// refuses visibly, never silently dropped.
///
/// WHY A RELEASING ROW IS NEVER RE-APPLIED: a record with a release requested
/// still occupies the store's active slot (so it stays listed and keeps the
/// dispatch refusal), but dispatching `firewall.quarantine` for it would put
/// containment back under a release that is in flight. The chokepoint refuses
/// it (`release_pending`), reading the row it is about to dispatch for.
///
/// WHY THE APPLY IS CLAIMED (#7613): a release is confirmed by the device's `inactive`
/// answer, and an apply sent while that answer is on its way changes the state the answer
/// described. Ending the record on the stale answer would leave a contained device with no
/// record and nothing owed. So this chokepoint calls `QuarantineStore::claim_apply` before the
/// dispatch (the claim moves the record's apply generation and marks a dispatch in progress) and
/// `release_apply_claim` after it. A dispatch that returned is NOT a delivery (the gateway path
/// only queues the command), so the claim is not what protects the record afterwards: the
/// GENERATION outlives it. Whoever will act on a device's `inactive` answer reads the token
/// (`apply_fence_token`) BEFORE it sends the command whose answer it will use, and the write that
/// ends the record presents it; an apply claimed after the read moves the generation and the end
/// is refused. This relies on commands to one device arriving in the order one server dispatched
/// them; the residuals are in `quarantine_containment_reconciler.hpp`.
///
/// WHAT "CONFIRMED" MEANS: the device reports its rules in force and
/// enforcing (`status|active`, or `status|active_unproven` when no probe
/// target is stored). It is NOT a reachability proof, and the server does not
/// compare the device's allow-list with the stored whitelist: a
/// `firewall.quarantine_allow` sent outside the quarantine routes changes the
/// device and not the record. The one difference the device reports is
/// `kAllowSetUnchangedNote`; the reconciler header says how it is handled.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class QuarantineStore;
struct QuarantineRecord;
struct StoredResponse; // response_store.hpp (the .cpp includes it)

// ── Layer A: pure ────────────────────────────────────────────────────────

inline constexpr std::string_view kContainmentPlugin{"firewall"};
inline constexpr std::string_view kContainmentApplyAction{"quarantine"};
inline constexpr std::string_view kContainmentStatusAction{"quarantine_status"};
inline constexpr std::string_view kContainmentReleaseAction{"release"};
inline constexpr std::string_view kContainmentExceptionsParam{"exceptions"};
/// The agent accepts 64 exceptions (`kMaxExceptions`, firewall_quarantine_parsers.hpp);
/// each address is sent twice (`/out` and `/in`), so the server allows 32.
inline constexpr std::size_t kContainmentMaxAddresses = 32;
inline constexpr std::size_t kQuarantineWhitelistMaxLen = 512;
/// The two 400 / invalid-params texts for a refused whitelist, shared by `POST /api/v1/quarantine`
/// and MCP `quarantine_device` so the twins cannot say different things (#7639). The length text
/// is checked first: a list that is only too long is told so, instead of sending the caller to
/// count addresses. Both numbers are pinned against the constants above in
/// `test_quarantine_reapply.cpp`.
inline constexpr std::string_view kWhitelistTooLongMessage{"whitelist exceeds 512 characters"};
inline constexpr std::string_view kWhitelistInvalidMessage{
    "whitelist must be comma-separated IPv4 or IPv6 addresses, at most 32 and 512 characters in "
    "total"};

/// Maps a stored (or request) whitelist onto the firewall plugin's `exceptions`
/// parameter: each comma-separated address becomes `<ip>/out,<ip>/in`, order kept,
/// no de-duplication (the agent de-duplicates). IPv6 is sent unbracketed (the agent
/// takes an unbracketed literal with two or more colons). Spaces around a token are
/// trimmed and empty tokens skipped. `nullopt` when anything cannot be expressed: a
/// token that is not a bare IPv4/IPv6 literal (a port, a prefix length, an
/// IPv4-mapped form, an IPv4 octet with a leading zero, a character outside
/// `[0-9a-fA-F.:]`, over 45 characters), more than `kContainmentMaxAddresses`
/// addresses, or a list over `kQuarantineWhitelistMaxLen` characters. An empty or
/// all-blank list maps to the empty string.
[[nodiscard]] std::optional<std::string> map_whitelist_to_exceptions(std::string_view whitelist);

/// Builds the dispatch params for a re-application of `stored_whitelist`:
/// `{exceptions: <mapped>}`, or an empty map for an empty whitelist (the plugin's
/// `exceptions` param is optional on `quarantine`). `nullopt` when the mapper refuses
/// — the caller must treat that as a hard stop, never dispatch anyway.
[[nodiscard]] std::optional<std::unordered_map<std::string, std::string>>
build_quarantine_reapply_params(std::string_view stored_whitelist);

/// The one row (whole line, exact) the device adds to a `firewall.quarantine` reply when the
/// device was already contained and the request's operator exceptions differ, as a set, from the
/// ones in force: the device kept its stored allow set. The device makes the comparison; the
/// server never parses the allow rows.
inline constexpr std::string_view kAllowSetUnchangedNote{
    "note|allow_set_unchanged_use_quarantine_allow=1"};

/// What a `firewall.quarantine_status` reply (or a `firewall.release` reply) says about
/// the device's containment. `active_unproven` is the plugin's "rules in force and
/// enforcing, but no completed reachability proof".
enum class QuarantineEndpointState { active, active_unproven, inactive, busy, unconfirmed };

/// A parsed reply: the state, whether a probe target is configured on the device's record,
/// and whether the device said it kept an earlier allow set (see `kAllowSetUnchangedNote`).
struct ContainmentReply {
    QuarantineEndpointState state{QuarantineEndpointState::unconfirmed};
    bool probe_configured{false};
    bool allow_set_unchanged{false}; ///< the exact `kAllowSetUnchangedNote` row was present
    bool status_seen{false}; ///< a `status|` line was present (even a refusal): the device answered
};

/// The enumerator's name, for audit text: never device text.
[[nodiscard]] constexpr const char* endpoint_state_name(QuarantineEndpointState s) {
    switch (s) {
    case QuarantineEndpointState::active:
        return "active";
    case QuarantineEndpointState::active_unproven:
        return "active_unproven";
    case QuarantineEndpointState::inactive:
        return "inactive";
    case QuarantineEndpointState::busy:
        return "busy";
    case QuarantineEndpointState::unconfirmed:
        return "unconfirmed";
    }
    return "unconfirmed";
}

/// Parses a firewall action's reply payload. Scans line by line (trailing CR stripped
/// so a CRLF agent still matches); the FIRST line starting `status|` decides — the
/// plugin renders it first. Its token up to the next `|` maps to active /
/// active_unproven / inactive / busy; any other token, every refusal
/// (`status|refused|...`, the privilege refusal included), a partial or degraded
/// status, and a reply with no status line at all is `unconfirmed` — never silently
/// treated as `active`. Any `note|probe_target=` row sets `probe_configured`; the exact line
/// `kAllowSetUnchangedNote` sets `allow_set_unchanged`.
[[nodiscard]] ContainmentReply parse_containment_reply(std::string_view payload);

/// A command's stored response rows (the store returns them newest first) joined oldest
/// first with '\n', so a multi-frame reply reads as the one payload `parse_containment_reply`
/// expects. The reconciler's poll and the DELETE route's confirm wait both read replies this
/// way.
[[nodiscard]] std::string combined_output(const std::vector<StoredResponse>& rows);

/// Whether the reply confirms containment. Exhaustive switch, no `default:`, so a
/// future enumerator fails to compile here instead of silently falling through (the
/// `should_dispatch_isolation` idiom, `quarantine_dispatch_decision.hpp`). `active` —
/// confirmed. `active_unproven` — confirmed only when no probe target is configured:
/// with one, the plugin folds a failed proof (for example `probe_still_reachable`)
/// into `active_unproven`, and a status read carries no `verify|` row to tell the two
/// apart, so only a verified proof (`active`) confirms. Everything else is not
/// confirmation (the endpoint may be half-contained or the agent may not know).
[[nodiscard]] constexpr bool reply_confirms_containment(const ContainmentReply& reply) {
    switch (reply.state) {
    case QuarantineEndpointState::active:
        return true;
    case QuarantineEndpointState::active_unproven:
        return !reply.probe_configured;
    case QuarantineEndpointState::inactive:
    case QuarantineEndpointState::busy:
    case QuarantineEndpointState::unconfirmed:
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
    no_active_record,  // get_status succeeded but returned nothing, or the apply claim was
                        // refused because the record changed since the read or another apply
                        // holds a live claim (a narrow race, not a store failure)
    whitelist_invalid, // the stored whitelist could not be mapped to exceptions
    release_pending,   // the row has a release requested: containment is not re-applied under it
};

struct ContainmentReapplyError {
    ContainmentReapplyErrorKind kind;
    // The store's raw error message for `store_error`; a fixed human string
    // ("quarantine record not found on retry read", or "quarantine record changed or
    // another apply is in flight") for `no_active_record`;
    // empty for `whitelist_invalid` and `release_pending` — callers that want a
    // message for those cases supply their own fixed text (the recipe
    // intentionally does not echo the rejected value back).
    std::string detail;
};

struct ContainmentReapplyResult {
    bool dispatch_threw{false};
    std::string command_id;
    int agents_reached{0};
};

/// Caller-supplied dispatch adapter: pre-bound to plugin `firewall`, action
/// `quarantine`, target `{agent_id}`, and whatever caller identity /
/// execution_id / DispatchCaller shape that transport needs — this function
/// only ever calls it with the mapped `exceptions` params (or an empty
/// map). Exceptions thrown by the callee are caught here and reported via
/// `ContainmentReapplyResult::dispatch_threw`, matching the MCP handler's
/// existing try/catch around its own dispatch call.
using ReapplyDispatchFn =
    std::function<std::pair<std::string, int>(const std::unordered_map<std::string, std::string>&)>;

/// The shared recipe: `store.get_status(agent_id)` -> refuse a releasing row -> map the
/// stored whitelist -> claim the apply (`claim_apply`) -> invoke `dispatch_fn(params)` ->
/// drop the claim (`release_apply_claim`, whatever the dispatch did). `out_record` receives the stored
/// row on success (the caller typically needs `quarantined_by`/`reason`/
/// `quarantined_at` for its own response/audit shaping, which this function does not
/// interpret). Returns `unexpected` without ever calling `dispatch_fn` on any
/// `ContainmentReapplyError`.
[[nodiscard]] std::expected<ContainmentReapplyResult, ContainmentReapplyError>
redispatch_stored_containment(QuarantineStore& store, const std::string& agent_id,
                              const ReapplyDispatchFn& dispatch_fn, QuarantineRecord& out_record);

} // namespace yuzu::server
