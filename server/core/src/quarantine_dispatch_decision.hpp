#pragma once

/// @file quarantine_dispatch_decision.hpp
/// Pure decision core for the MCP `quarantine_device` handler (#3127). Answers
/// two questions the handler used to get wrong: whether a store write outcome
/// should proceed to dispatch, and whether an already-dispatched attempt
/// earned the word "isolated" in the response it hands back to the caller.
///
/// PURE ON PURPOSE: no I/O, no includes beyond the standard library, nothing
/// but two total functions over two closed enums. `mcp_server.cpp` does the
/// classification that turns a `QuarantineStore::quarantine_device` /
/// `get_status` `std::expected` into a `QuarantineRecordWrite` (keying off
/// `kQuarantineDbErrorPrefix`) — that string inspection is the one thing this
/// header refuses to own, so it stays substrate-agnostic. The payoff: a
/// future request-key/idempotency layer (tracked, not built here — see the
/// issue's explicit "do not build this" boundary) can call
/// `should_dispatch_isolation`/`quarantine_response_shape` unchanged against
/// whatever write result IT produces, with zero coupling to Postgres, MCP
/// transport, or the dispatch seam. A unit test can exhaust every branch of
/// both functions without a store, an agent, or a build dir.
///
/// WHY "RECORD ACTIVE + DISPATCH UNCONFIRMED" IS NOT "ISOLATED": the prior
/// handler treated a write outcome of "device already has an active record"
/// as a terminal 400, and treated `agents_reached == 0` on a fresh write as a
/// success anyway — two independent phantom-isolation bugs. `agents_reached >
/// 0` means the plugin registry ACCEPTED the frame, nothing more; for a
/// gateway-attached agent, `send_to` only QUEUES the command (server.cpp,
/// `send_to` comment) — it does not confirm the agent executed it, let alone
/// that its firewall now blocks traffic. So `isolated` here means "dispatch
/// was accepted and didn't throw", not "the device is provably network-
/// isolated"; confirming that still requires a follow-up `status` read
/// returning `state|active`. Anything short of that (`agents_reached == 0`,
/// or a dispatch that threw) is `unconfirmed_retryable`, not a success — the
/// caller must be able to safely retry rather than believe a device is
/// contained when it might not be.
///
/// WHY THE RETRY RE-DISPATCHES THE STORED WHITELIST: `already_active` means
/// the write did NOT happen — the record on disk is whatever an EARLIER call
/// persisted, not this call's `reason`/`whitelist`. Dispatching this call's
/// arguments would let a caller silently rewrite a contained device's
/// firewall allow-list with no store update and no audit trail: a state
/// divergence between what's recorded and what's enforced, not an idempotent
/// retry. The caller (mcp_server.cpp) is responsible for reading the stored
/// row back via `get_status` before it dispatches on this path — this header
/// only says THAT dispatch should happen, not with which arguments.

namespace yuzu::server {

/// The three (and only three) outcomes of a `QuarantineStore::quarantine_device`
/// write, as classified by the caller from the store's `std::expected` error:
/// `error().starts_with(kQuarantineDbErrorPrefix)` -> `store_error`, any other
/// error -> `already_active` (the sole business/state error the store emits),
/// no error -> `created`. There is no fourth "terminal store error" outcome:
/// every genuine failure the store can produce carries the prefix, so a
/// classifier that invented one would be dead code.
enum class QuarantineRecordWrite { created, already_active, store_error };

/// Should the handler proceed to dispatch the live isolation command after
/// this write outcome? True for both `created` (the normal path) and
/// `already_active` (the #3127 retry fix — a record that already exists is
/// not a reason to dead-end the caller, it is a reason to re-drive dispatch
/// against the STORED intent). False only for `store_error`: the write never
/// happened and nothing durable backs a dispatch.
[[nodiscard]] constexpr bool should_dispatch_isolation(QuarantineRecordWrite write) {
    // A switch with no `default:` over every enumerator (not `write !=
    // store_error`) so a fourth enumerator ever added to
    // `QuarantineRecordWrite` fails to compile here instead of silently
    // defaulting to whichever branch `!=` happens to fall into.
    switch (write) {
    case QuarantineRecordWrite::created:
    case QuarantineRecordWrite::already_active:
        return true;
    case QuarantineRecordWrite::store_error:
        return false;
    }
    return false; // fail closed; unreachable while the switch above stays exhaustive
}

/// The three response shapes the handler can hand back once dispatch (or the
/// decision to skip it) is known. `isolated` is the only shape that may claim
/// success; the other two are both retryable failures, deliberately not a
/// single merged shape — `store_error_retryable` traces to the write, never
/// reached dispatch, and always retries `quarantine_device` from scratch;
/// `unconfirmed_retryable` traces to a persisted-but-unconfirmed dispatch and
/// retries onto the `already_active` re-dispatch path.
enum class QuarantineResponse { isolated, unconfirmed_retryable, store_error_retryable };

/// Classify the final response shape. `store_error` short-circuits to
/// `store_error_retryable` regardless of `agents_reached`/`dispatch_threw`
/// (dispatch is never attempted on that write outcome — see
/// `should_dispatch_isolation`). Otherwise: `isolated` requires BOTH a
/// positive `agents_reached` (the registry accepted the frame for at least
/// one agent) AND that dispatch did not throw — a caught dispatch exception
/// is never reported as isolated even if some earlier partial state left
/// `agents_reached` positive. Every other combination is
/// `unconfirmed_retryable`.
[[nodiscard]] constexpr QuarantineResponse
quarantine_response_shape(QuarantineRecordWrite write, int agents_reached, bool dispatch_threw) {
    if (write == QuarantineRecordWrite::store_error)
        return QuarantineResponse::store_error_retryable;
    if (agents_reached > 0 && !dispatch_threw)
        return QuarantineResponse::isolated;
    return QuarantineResponse::unconfirmed_retryable;
}

} // namespace yuzu::server
