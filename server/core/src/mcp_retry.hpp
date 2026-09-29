#pragma once

/// @file mcp_retry.hpp
/// Named `retry_after_ms` floors for the MCP tool-call surface (#3344, MCP 2g
/// PR 3 remainder / ADR-1005 Decision 16 invariant A5), plus the shared
/// `is_execution_terminal()` predicate the floors' consumers use to decide
/// when a poll hint applies.
///
/// Before this file, `retry_after_ms` was a bare literal (`5000`, `2000`, or
/// `-1`/`null`) repeated independently at ~60 call sites in `mcp_server.cpp` —
/// tuning meant finding and editing every occurrence, and none of it was
/// derived from anything. These constants replace those literals value-for-
/// value (behaviour-preserving) and each carries the mechanical derivation
/// rationale the exec plan asks for in place of a measured
/// dispatch-to-first-result latency histogram (`yuzu_command_duration_seconds`
/// measures full command completion, not first-result — that histogram does
/// not exist).
///
/// Several constants below share a numeric value with a neighbour. That is
/// coincidental historical pricing, not derivation — each comment says so
/// explicitly so a future re-tuning of one does not silently drag the other.

#include <cstdint>
#include <string_view>

namespace yuzu::server::mcp {

/// `retry_after_ms` for a generic transient store fault on an ERROR-shaped
/// response (the ~39-site bare-`5000` family: response/execution-tracker
/// reads, license/quarantine/KEK/engine-principal/access-review store
/// errors). Mechanical: a degraded store clears on its next successful
/// reconnect/health pass, and the shortest interval this codebase already
/// treats as "a pass could plausibly have happened" is the 3 s stream-tick +
/// write-failure detection window that derived `kMcpStreamCapRetryAfterMs`
/// (`mcp_stream.hpp`) — rounded to the same 5 s this family has always used.
/// Also matches the REST twins' 503 posture at this call class. Preserves the
/// existing wire value; this is a rename, not a re-tuning.
inline constexpr std::int64_t kMcpStoreFaultRetryMs = 5000;

/// `retry_after_ms` for the plugin-config / API-token rotation family (the
/// ~20-site bare-`2000` family). Anchor: `rotate_api_token`'s existing
/// "mirrors the REST twin's 503 + Retry-After: 2 posture" — the REST 503
/// drill on the sibling `/api/v1/tokens` route already prices one server
/// round trip at 2 s, and this family is that same class of fault (a
/// transient store/secret-backend read, not a multi-second warmup). The 5 s
/// vs 2 s split against `kMcpStoreFaultRetryMs` is historical pricing,
/// preserved as-is — not re-harmonised by this change.
inline constexpr std::int64_t kMcpStoreFaultShortRetryMs = 2000;

/// `retry_after_ms` for a DEX/app-perf provider that has not finished
/// initializing yet (the `a4_data(5000, "retry after server warmup...")`
/// sites). Distinct symbol from `kMcpStoreFaultRetryMs` even though the
/// value is equal today: a warmup clears once, on server start, by a
/// different mechanism than a mid-run store fault recovering — the equal
/// value is coincidental, not a shared derivation, and the two must be free
/// to diverge later without a rename.
inline constexpr std::int64_t kMcpProviderWarmupRetryMs = 5000;

/// `retry_after_ms` for a SUCCESS-shaped result-not-ready poll — the three
/// poll tools (`get_execution_status`, `query_responses`,
/// `get_bundle_result`) when the awaited execution/bundle has not reached a
/// terminal state yet. Mechanical rationale (no dispatch-to-first-result
/// histogram exists to measure from): dispatch fans out over the live gRPC
/// subscribe stream, sub-second; the earliest a repeat poll can observe new
/// state is therefore one agent execute-and-report round trip, and this
/// codebase already prices one server round trip at 2 s (the same
/// Retry-After: 2 REST parity `kMcpStoreFaultShortRetryMs` cites). The equal
/// value to `kMcpStoreFaultShortRetryMs` is coincidental — this floor is
/// priced from round-trip latency, that one from REST 503 parity — kept as
/// distinct symbols so either can be re-tuned independently once
/// `yuzu_mcp_poll_total{result="not_ready"}` supplies real poll-rate data.
inline constexpr std::int64_t kMcpResultPollRetryMs = 2000;

/// `retry_after_ms` for an approval-ticket poll (`kApprovalRequired`
/// envelope). No machine-side mechanical floor exists here — the ticket
/// clears only when a human acts — so this borrows the anti-amplification
/// derivation that produced `kMcpStreamedPostRetryAfterMs`: a sub-30s poll
/// interval has a conforming client burn a full auth + rate-limit + routing
/// pass dozens of times before a human could plausibly have acted. Honest
/// rather than aspirational because a pre-approval re-call is idempotent —
/// approval minting is deduplicated by (principal, tool, canonical args), so
/// polling faster than this floor cannot mint a duplicate ticket, only waste
/// round trips. Bounded above by the ticket's own TTL (7 days).
inline constexpr std::int64_t kMcpApprovalPollRetryMs = 30000;

/// Metric-name symbol for the poll-rate counter (#3344), so the `describe`/
/// pre-seed site (`server.cpp`) and the increment site (`mcp_server.cpp`)
/// cannot silently diverge into a shadow series — same precedent as
/// `rotation_sweep_naming.hpp`'s `kApiTokenConfirmTotalMetric`.
inline constexpr const char* kMcpPollTotalMetric = "yuzu_mcp_poll_total";

/// Shared terminal-status predicate for `ExecutionTracker` rows (#3344 Gate 8
/// fold: `get_execution_status` and `query_responses`' poll-hint logic both
/// hand-rolled this exact three-value set independently — a future status
/// added to one and not the other would make the two poll tools silently
/// disagree about in-flight-ness for the same execution). Deliberately an
/// explicit allowlist rather than `execution_tracker.cpp`'s own
/// `NOT IN (pending, running)` idiom: that idiom's default is "an
/// unrecognized future status counts as terminal", which is the WRONG
/// default here — a status this predicate doesn't recognize must still read
/// as non-terminal (fail-safe: the caller keeps polling and self-corrects on
/// the next response) rather than silently going hint-less forever.
inline constexpr bool is_execution_terminal(std::string_view status) {
    return status == "succeeded" || status == "completed" || status == "cancelled";
}

}  // namespace yuzu::server::mcp
