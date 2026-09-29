#pragma once

/// @file principal_quota_denial.hpp
///
/// PR 4.4 — the SHARED per-principal-quota exhaustion classifier, split into
/// a pure decision (`classify_quota_denial`) and two transport render
/// adapters. The split is REQUIRED: an architect review found that MCP must
/// receive a JSON-RPC error, never the REST A4 body — reusing one wire shape
/// across both transports would be wrong for MCP. Both render adapters MUST
/// derive every wire fact (status, retry_after_ms, side, limit, message,
/// remediation) from the SAME QuotaDenial produced by the classifier; they
/// differ ONLY in envelope shape. This is the load-bearing invariant a unit
/// test locks later — don't let a render adapter recompute or override a
/// fact the classifier already set.

#include "mcp_jsonrpc.hpp"             // error_response_null_a4, kMcpSessionCap
#include "principal_quota.hpp"         // QuotaDecision, QuotaSide, QuotaLimit
#include "rest_a4_envelope.hpp"        // detail::error_json_a4, A4ErrorOpts

#include <httplib.h>

#include <algorithm>
#include <cstdint>
#include <string>

namespace yuzu::server::detail {

/// Pure: maps a rejected QuotaDecision to the shared wire facts. HTTP 429
/// always — a quota rejection (either dimension) is a "too many requests"
/// condition, never a 4xx client-input error.
struct QuotaDenial {
    int http_status{429};
    std::int64_t retry_after_ms{0};
    const char* side{"engine"};        // from QuotaSide
    const char* limit{"concurrency"};  // from QuotaLimit ("concurrency"|"rate")
    std::string message;               // e.g. "per-principal concurrency cap exceeded"
    std::string remediation;           // e.g. "retry after retry_after_ms; reduce concurrent requests"
};

/// The single source of truth: given a rejected QuotaDecision (admitted ==
/// false), produce the shared wire facts both transports render from.
/// Callers should not invoke this on an admitted decision — there is
/// nothing to deny.
inline QuotaDenial classify_quota_denial(const QuotaDecision& d) {
    QuotaDenial q;
    q.http_status = 429;
    q.retry_after_ms = d.retry_after_ms;
    q.side = (d.side == QuotaSide::kOperator) ? "operator" : "engine";

    if (d.limit == QuotaLimit::kRate) {
        q.limit = "rate";
        q.message = "per-principal rate limit exceeded";
        q.remediation = "retry after retry_after_ms; reduce request rate";
    } else {
        // Default to concurrency for kConcurrency (and defensively for
        // kNone, which should never reach here on a rejected decision).
        q.limit = "concurrency";
        q.message = "per-principal concurrency cap exceeded";
        q.remediation = "retry after retry_after_ms; reduce concurrent requests";
    }
    return q;
}

namespace quota_denial_detail {

/// Shared Retry-After header value: HTTP's Retry-After is whole seconds, so
/// round the millisecond hint UP (never under-promise a retry that's still
/// too early) with a floor of 1s.
inline std::string retry_after_seconds_header(std::int64_t retry_after_ms) {
    const std::int64_t seconds = std::max<std::int64_t>(1, (retry_after_ms + 999) / 1000);
    return std::to_string(seconds);
}

}  // namespace quota_denial_detail

/// REST render: A4 envelope body (rest_a4_envelope.hpp's error_json_a4).
/// Sets res.status = q.http_status (429) + the Retry-After header, and
/// carries retry_after_ms + remediation through A4ErrorOpts so the body is
/// byte-for-byte the same shape every other REST denial uses.
inline void render_quota_denial_rest(httplib::Response& res, const QuotaDenial& q,
                                     const std::string& cid) {
    res.status = q.http_status;
    res.set_header("X-Correlation-Id", cid);
    res.set_header("Retry-After", quota_denial_detail::retry_after_seconds_header(q.retry_after_ms));
    res.set_content(
        error_json_a4(q.http_status, q.message, cid,
                      A4ErrorOpts{.retry_after_ms = q.retry_after_ms,
                                  .remediation = q.remediation,
                                  .permission = {},
                                  .approval_id = {},
                                  .status_url = {}}),
        "application/json");
}

/// MCP render: JSON-RPC id:null error via the same shape MCP transport
/// denials use (mcp::error_response_null_a4— see the kMcpOriginRejected /
/// kMcpSessionCap branches in mcp_server.cpp's pre-routing handler). Reuses
/// mcp::kMcpSessionCap as the wire code: it is already documented as "per-
/// principal/global session cap hit -> HTTP 429" (mcp_jsonrpc.hpp), the
/// closest existing "you are over a per-principal cap" code, and quota
/// exhaustion (either dimension) is exactly that shape. No new JSON-RPC
/// error code is minted for this — the message/remediation text in
/// QuotaDenial (not the numeric code) is what distinguishes rate from
/// concurrency on the wire.
inline void render_quota_denial_mcp(httplib::Response& res, const QuotaDenial& q,
                                    const std::string& cid) {
    res.status = q.http_status;
    res.set_header("Retry-After", quota_denial_detail::retry_after_seconds_header(q.retry_after_ms));
    res.set_content(mcp::error_response_null_a4(mcp::kMcpSessionCap, q.message, cid, q.remediation,
                                                q.retry_after_ms),
                    "application/json");
}

}  // namespace yuzu::server::detail
