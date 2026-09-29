#pragma once

/// @file principal_quota_gate.hpp
///
/// PR 4.4 follow-up — the per-principal quota GATE DECISION, extracted out of
/// server.cpp's pre-routing lambda into a pure(ish) free function so it is
/// reachable from a unit test without a live httplib server or `auth::Session`
/// (a test-coverage gap the test junior found: the decision used to be trapped
/// inside a lambda captured by `[this]`). `apply_engine_quota_gate` takes plain
/// `string_view`s for the principal fields instead of a `Session&`, so a test
/// needs no session-minting machinery — just a couple of strings.
///
/// server.cpp's pre-routing handler is now a thin caller: it resolves the
/// session, calls this function, and handles only the httplib-specific,
/// worker-thread-affine bits (the `tls_quota_slot()` thread_local stash/
/// release lifecycle and the `HandlerResponse::Handled`/`Unhandled` return)
/// — those stay in server.cpp because they are wiring, not the security
/// decision.

#include "mcp_transport.hpp" // accept_wants_sse — the streamed-POST /mcp/v1/ carve (2f PR 3b)
#include "principal_quota.hpp"
#include "principal_quota_denial.hpp"

#include <yuzu/metrics.hpp>

#include <httplib.h>

#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server::detail {

// R2: per-worker-thread slot for an admitted QuotaSlot, released by the
// post-routing handler. httplib binds one worker thread to one request at a
// time — the slot minted at pre-routing on thread T is released at
// post-routing on the SAME thread T for the SAME request before that thread
// is handed the next one, UNLESS the request is a stream: a streaming route
// MUST adopt the slot into its own resource-releaser via
// `adopt_quota_slot_into_stream` when it sets its content provider, which
// moves the slot out of this thread_local and holds it for the stream's
// actual lifetime instead (UP-1 — see that function's doc comment). The
// pre-routing handler also resets this defensively at its own TOP, to
// reclaim a slot leaked by any prior request on this worker that bypassed
// both post-routing AND stream adoption — the only such bypass today would
// be a future WebSocket upgrade (httplib DOES support WebSocket — see
// `WebSocketHandler`/`CPPHTTPLIB_WEBSOCKET_*` in httplib.h — the real
// safety here is that this codebase registers NO WebSocket handler today,
// not any protocol limitation; the defensive reset is the backstop for
// when one eventually is).
//
// Known limitation of in-memory thread-local accounting: if a worker thread
// were lost WITHOUT running post-routing and WITHOUT adopting the slot, its
// in_flight increment would leak (that principal's cap shrinks by one until
// restart). In practice this is not reachable on the running server —
// httplib catches a route handler's exception and still runs post-routing,
// and the only way a worker truly dies mid-request is a process-fatal
// std::terminate (which ends the whole server, not just the thread). Durable
// / crash-recoverable accounting is the Phase-8 follow-up; the in-process
// minimum cap accepts this bound.
[[nodiscard]] inline std::optional<QuotaSlot>& tls_quota_slot() {
    thread_local std::optional<QuotaSlot> slot;
    return slot;
}

/// R1/UP-1: paths whose response is Server-Sent-Events / long-lived
/// streaming. This is now the KNOWN-STREAMING-ROUTE REGISTRY: every route
/// listed here must, at the point it calls `set_chunked_content_provider`
/// (or otherwise starts a long-lived response), wrap its resource-releaser
/// in `adopt_quota_slot_into_stream` so the concurrency slot minted for the
/// request survives for the STREAM's lifetime instead of releasing at
/// post-routing (which fires as soon as routing hands off to the chunked
/// body, long before the stream itself finishes). A new streaming route
/// must both be ADDED HERE and call `adopt_quota_slot_into_stream` at its
/// content-provider call site — one without the other is a bug: listed-but-
/// not-adopting reintroduces UP-1 (unbounded concurrent streams per
/// principal); adopting-but-not-listed is merely undiscoverable by the test
/// that walks this registry. Small explicit allowlist, GET-only (every
/// route below only streams on GET). Enumerated by grepping
/// `set_chunked_content_provider` / `text/event-stream` across server.cpp,
/// workflow_routes.cpp, and rest_api_v1.cpp, plus the MCP GET SSE stream
/// registration in mcp_server.cpp.
///
/// The MCP GET SSE channel (`GET /mcp/v1/`) is now live and DOES adopt the slot:
/// `mcp_stream.cpp`'s `handle_get_tail` wraps its content-provider releaser in
/// `adopt_quota_slot_into_stream`, exactly like the three routes below, so an engine
/// principal's stream holds its concurrency reservation for the stream's whole life
/// rather than releasing it early at post-routing (the UP-1 hazard this guard exists to
/// prevent). Any FUTURE streaming route added to `is_streaming_path` MUST do the same.
///
/// POST /mcp/v1/ streams CONDITIONALLY (2f PR 3b, SSE-on-POST) — unlike the four GET routes
/// above, which stream unconditionally. A POST /mcp/v1/ becomes a held-open SSE response only
/// when the client opts in with an SSE-capable `Accept` AND (checked later, in the handler) the
/// request carries a `_meta.progressToken`; otherwise it is an ordinary one-shot JSON tool call.
/// The pre-routing chokepoint runs before the body is parsed, so the only streaming signal it
/// can see is the `Accept` header — hence the `accept_wants_sse` gate here. This is an over-
/// approximation on purpose: a POST that advertises SSE but omits the progressToken degrades to
/// plain JSON, and its slot then correctly releases at post-routing — a plain-POST release is
/// CORRECT, not a listed-but-not-adopting bug, because that request never streamed. The streamed
/// arm adopts the slot at its `set_chunked_content_provider` site in the `execute_instruction`
/// handler (2f PR 3b), exactly like the GET tail. (R7.) NOTE: `is_streaming_path` has no
/// production consumer today — server.cpp releases the slot unconditionally at post-routing and
/// streaming routes move it out first via `adopt_quota_slot_into_stream`; this registry is the
/// discoverability contract + the surface the quota chokepoint tests walk.
[[nodiscard]] inline bool is_streaming_path(const httplib::Request& req) {
    // Streamed POST /mcp/v1/ (2f PR 3b): a POST is a streaming path only when it opts into SSE.
    if (req.method == "POST")
        return req.path == "/mcp/v1/" && mcp::transport::accept_wants_sse(req.get_header_value("Accept"));
    if (req.method != "GET")
        return false;
    if (req.path == "/events")                       // dashboard event-bus SSE
        return true;
    if (req.path == "/api/v1/events")                 // REST v1 JSON SSE (agentic-first)
        return true;
    if (req.path.rfind("/sse/executions/", 0) == 0)   // dashboard per-execution SSE
        return true;
    if (req.path == "/mcp/v1/")                       // MCP Streamable HTTP GET SSE stream
        return true;
    return false;
}

/// UP-1: transfers the CURRENT request's pending engine quota slot (stashed
/// in `tls_quota_slot()` by the pre-routing chokepoint) into a streaming
/// response's resource-releaser, so the concurrency reservation is held for
/// the STREAM's lifetime and released on disconnect/completion — NOT at
/// post-routing, which fires before the streamed body ever runs. A
/// streaming route (see `is_streaming_path`'s registry above) MUST call this
/// when it sets its content provider, else the slot releases early at
/// post-routing and the stream is effectively unbounded per principal
/// (exactly the DoS `try_rate_only` used to leave open).
///
/// No-op-preserving if no slot is pending (non-engine request, or a
/// non-engine-classed session on a streaming route): `inner` is returned
/// unchanged so callers don't need to branch on whether a slot exists.
[[nodiscard]] inline httplib::ContentProviderResourceReleaser adopt_quota_slot_into_stream(
    httplib::ContentProviderResourceReleaser inner) {
    auto& tls = tls_quota_slot();
    if (!tls.has_value()) {
        return inner;
    }
    // Move the slot out of the thread_local into a shared_ptr so it can be
    // captured by value into the returned releaser (a QuotaSlot is move-only
    // and the releaser may be copied by httplib internals, hence shared_ptr
    // rather than capturing the optional directly).
    auto slot = std::make_shared<std::optional<QuotaSlot>>(std::move(tls));
    tls.reset();
    return [slot, inner = std::move(inner)](bool success) {
        if (inner)
            inner(success);
        // Destroys the held QuotaSlot (if any), running ~QuotaSlot() ->
        // reset(), which releases the concurrency reservation. Idempotent —
        // safe even if this releaser is somehow invoked more than once.
        slot->reset();
    };
}

/// Applies the per-principal engine quota gate. Non-engine principals pass
/// untouched (`out_rejected=false`, returns `nullopt`) — human/agent/
/// anonymous traffic never reaches the quota primitive at all.
///
/// S1 (two-predicate classification): a request is treated as an engine
/// principal if EITHER the persisted `principal_kind` OR the session's
/// `auth_source` says so — mirrors the `deny_if_engine_session` belt in
/// mcp_server.cpp's engine-principal lifecycle tools, keyed on the SAME two
/// fields, so a future second engine-authentication path that only sets one
/// of them can't silently bypass this cap.
///
/// On rejection: increments `yuzu_server_principal_quota_exhausted_total
/// {side,limit}` on `metrics`, renders the transport-appropriate 429 (MCP vs
/// REST, decided by a `/mcp/` path prefix) into `res`, sets
/// `out_rejected=true`, and returns `nullopt`. The correlation id used on
/// the 429 is minted (or reused from an already-set response header) lazily
/// INSIDE this rejection path — admitted traffic (the overwhelming common
/// case) never pays the mint cost.
///
/// On admit (UP-1: EVERY engine request, streaming or not, now takes a full
/// `try_acquire` — concurrency slot + rate debit): increments
/// `yuzu_server_principal_quota_admits_total{side}` and returns the admitted
/// `QuotaSlot` for the caller to stash. This function has no notion of
/// "this is a streaming request" on the admit path — it always hands back
/// the slot; it is the CALLER's responsibility (server.cpp's pre-routing
/// stash, then either post-routing release or, for a streaming route,
/// `adopt_quota_slot_into_stream`) to give the slot the right lifetime.
///
/// Surface scope: this gate covers the operator HTTP surface only (REST /
/// MCP / dashboard / SSE over httplib), which is where engine principals
/// authenticate today. The agent gRPC channel (`:50051`) carries no
/// engine-principal traffic and has no matching gate; if a future change
/// ever lets engine tokens authenticate over gRPC, that surface needs its
/// own equivalent per-principal cap or this one is silently bypassed.
[[nodiscard]] inline std::optional<QuotaSlot> apply_engine_quota_gate(
    std::string_view principal_kind, std::string_view auth_source, std::string_view principal_id,
    const httplib::Request& req, httplib::Response& res, PrincipalQuota& quota,
    yuzu::MetricsRegistry& metrics, bool& out_rejected) {
    out_rejected = false;

    // The raw "engine" literal (twice below) is deliberate, not a missed
    // dedup: there is no shared `kEngine`-style constant anywhere in the
    // codebase to reuse (surveyed rbac_store.hpp, api_token_store.hpp,
    // principal_class.hpp, mcp_server.cpp's sibling `deny_if_engine_session`
    // belt) — every existing "engine"/"engine_token" classification is a raw
    // literal by established convention. Minting a one-off constant just for
    // this gate would diverge from that convention rather than reduce
    // duplication.
    if (principal_kind != "engine" && auth_source != "engine_token")
        return std::nullopt;

    const std::string pid(principal_id);
    const bool is_mcp = req.path.rfind("/mcp/", 0) == 0;

    // Shared reject path for both dimensions: classify -> increment the
    // bounded {side,limit} counter -> mint/reuse a correlation id -> render
    // the transport-appropriate body.
    auto reject = [&](const QuotaDecision& d) {
        QuotaDenial q = classify_quota_denial(d);
        metrics.counter("yuzu_server_principal_quota_exhausted_total",
                        {{"side", q.side}, {"limit", q.limit}})
            .increment();
        // Reuse a correlation id an earlier stage in this request's
        // lifecycle already stamped on the response (none does, this early
        // in the pipeline, today — this mirrors the shared
        // rest_a4_envelope_http.hpp::ensure_correlation_id idiom so the
        // pattern stays consistent if that ever changes); mint fresh
        // otherwise. render_quota_denial_{rest,mcp} below set the header
        // themselves, so this is the ONLY mint/reuse site — no double-set.
        std::string cid = res.get_header_value("X-Correlation-Id");
        if (cid.empty())
            cid = make_correlation_id();
        if (is_mcp) {
            render_quota_denial_mcp(res, q, cid);
        } else {
            render_quota_denial_rest(res, q, cid);
        }
        out_rejected = true;
    };

    QuotaSlot slot = quota.try_acquire(pid, QuotaSide::kEngine);
    if (!slot.admitted()) {
        reject(slot.decision());
        return std::nullopt;
    }

    // Admits denominator (sre): every ADMITTED engine request, so the
    // exhaustion RATE (exhausted / (exhausted + admits)) is computable and
    // a self-brick (rate near 1.0 immediately after a config change) is
    // distinguishable from ordinary load-driven exhaustion. Bounded label
    // set only — side, never principal_id.
    metrics.counter("yuzu_server_principal_quota_admits_total", {{"side", "engine"}}).increment();

    return slot;
}

} // namespace yuzu::server::detail
