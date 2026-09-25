#pragma once

#include <concepts>
#include <string>
#include <string_view>

#include "approval_manager.hpp"
#include "mcp_jsonrpc.hpp"
#include "pg_error_class.hpp"

namespace yuzu::server::mcp {

/// One body for BOTH approval-store failure sites on the MCP recall path: the
/// ticket lookup (rung 1) and the consume (rung 2). They were written
/// separately at first and said different things about the same condition.
///
/// `ConsumeFailure::kStoreError` (and the equivalent `get_checked` failure at
/// rung 1) has producers that are TRANSIENT (a lease-acquire timeout or a
/// transient Postgres error, which a retry clears) and producers that are
/// PERMANENT for the life of the
/// process (the store never opened). Answering the permanent case with "retry
/// this call unchanged" is an unbounded loop, and every attempt also writes
/// an audit row, so a degraded approval store turns into an audit-write loop
/// on the substrate already failing to serve it.
///
/// Permanent has TWO independent discriminators — either alone classifies the
/// failure permanent: `!mgr.is_open()` (a store that never opened does not
/// recover without an operator restarting the server), or
/// `is_permanent_pg_error(sqlstate)` (an OPEN store whose reads fail
/// permanently — schema drift, corruption, disk-full, read-only; ADR-0065
/// port of #2786 "PR 1c", was `is_permanent_sqlite_error(extended_errcode)`).
/// The caller passes `sqlstate` rather than this function defaulting it, so
/// a call site cannot silently omit the discriminator and reintroduce the
/// gap the second arm closes.
///
/// The transient arm carries a concrete `retry_after_ms` because invariant A5
/// requires a retry directive to be machine-readable rather than prose. The
/// permanent arm omits the argument, so `a4_error`'s default (-1) applies and
/// the envelope serialises `retry_after_ms` as JSON null, this file's own
/// encoding for "not retryable".
///
/// Lives in a header, not an anonymous namespace, because the branch it
/// replaces had ZERO test coverage in either direction: a governance reviewer
/// deleted the whole thing once and no assertion moved. Unreachable code is
/// untested code.
///
/// `a4_error` is passed in rather than called directly so the caller's
/// correlation-id minting and envelope shape stay in one place, and so a test
/// can observe the arguments without parsing JSON. The constraint below names
/// both call shapes `a4_error` actually has (three-argument and
/// four-argument with a `long` retry hint); a caller satisfying only one
/// arity fails at this declaration with a readable message instead of deep
/// inside template instantiation.
template <typename A4Error>
concept ApprovalA4Error =
    requires(const A4Error& a4_error, int code, std::string_view message,
             std::string_view remediation, long retry_after_ms) {
        { a4_error(code, message, remediation) } -> std::convertible_to<std::string>;
        { a4_error(code, message, remediation, retry_after_ms) } -> std::convertible_to<std::string>;
    };

template <ApprovalA4Error A4Error>
[[nodiscard]] std::string approval_store_error_body(const ApprovalManager& mgr,
                                                     const A4Error& a4_error,
                                                     std::string_view sqlstate) {
    if (!mgr.is_open() || is_permanent_pg_error(sqlstate))
        return a4_error(kInternalError, "approval store unavailable",
                        "this will NOT clear on retry, the approval was not consumed and does "
                        "not need re-requesting while the 7-day window holds. Escalate to an "
                        "operator");
    return a4_error(kInternalError, "approval store temporarily unavailable",
                    "retry this call unchanged, the approval was NOT consumed and remains "
                    "valid; do NOT request a fresh one. The 7-day approval window keeps "
                    "running during an outage: if it elapses the ticket expires and a new "
                    "approval is required",
                    5000);
}

/// Read-only counterpart of `approval_store_error_body` above, for
/// `list_pending_approvals`/`get_pending_approval_count` (review finding, PR
/// #4656): both previously answered EVERY store failure with the transient
/// `approval store degraded` + `retry_after_ms=5000`, the same unbounded
/// "retry forever" bug the ticket-consume path already had a fix for. Not
/// simply reusing `approval_store_error_body` here: its remediation text is
/// about a specific TICKET's consumption state ("the approval was not
/// consumed", "do NOT request a fresh one"), which is meaningless for a
/// plain list/count read that never named a ticket. Same permanent-vs-
/// transient classification, generic read-appropriate wording; REST's
/// `approval_store_error_json` (rest_api_v1.cpp) is this function's REST
/// counterpart and intentionally uses the same two messages.
template <ApprovalA4Error A4Error>
[[nodiscard]] std::string approval_store_read_error_body(const ApprovalManager& mgr,
                                                          const A4Error& a4_error,
                                                          std::string_view sqlstate) {
    if (!mgr.is_open() || is_permanent_pg_error(sqlstate))
        return a4_error(kInternalError, "approval store unavailable",
                        "this will NOT clear on retry; escalate to an operator");
    return a4_error(kInternalError, "approval store degraded",
                    "retry shortly; if this persists, escalate to an operator", 5000);
}

} // namespace yuzu::server::mcp
