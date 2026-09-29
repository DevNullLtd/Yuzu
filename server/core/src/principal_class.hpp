// principal_class — bounded actor-class label for HTTP request metrics
// (ADR-1005 Consequences; execution-plan PR 1.2).
//
// Values are a CLOSED set (docs/observability-conventions.md — bounded
// labels only): "human" (session cookie), "agent" (bearer/API token — an
// agentic worker or automation), "none" (no credential offered), "engine"
// (a RESOLVED engine-principal session). Engine principals were RESERVED
// and never emitted through PR 4.4; execution-plan PR 4.5 makes "engine"
// live.
//
// HYBRID basis (the contract, deliberate — see PR 4.5): "engine" is decided
// from the RESOLVED session (principal_kind/auth_source), not header
// presentation, because an engine principal authenticates with a Bearer
// token indistinguishable from a human API token at the header level.
// "human"/"agent"/"none" remain presentation fallbacks — a request bearing
// an engine token that FAILS resolution (no session) is presentation-shaped
// failed auth and correctly stays "agent", never "engine". This is why
// `principal_class_resolved` below piggybacks the session already resolved
// by the pre-routing chokepoint (PR 4.4's quota gate) instead of
// re-resolving in the post-routing handler where the metric is emitted —
// zero extra per-request auth cost.
//
// `principal_class_of` (the plain presentation classifier, below) is
// unchanged and still used directly wherever no resolved session is
// available.

#pragma once

#include <string_view>

#include <httplib.h>

namespace yuzu::server {

namespace detail {
// Request-scoped stash: set true by the pre-routing chokepoint when the
// RESOLVED session is an engine principal; read at the post-routing metric
// emission. thread_local + httplib worker-thread affinity, mirroring
// principal_quota_gate.hpp's tls_quota_slot(). The PRIMARY clear is the
// post-routing handler's EngineClassStashClear RAII scope guard in
// server.cpp — declared first in that lambda but, being a destructor, runs
// LAST (after the metric emission reads it, and even if that emission
// throws), so it fires on every exit from post-routing, including the
// requests httplib rejects BEFORE pre-routing ever executes (malformed
// request line, URI too long, bad Range — see httplib.h
// write_response_core). The reset at the top of pre-routing (before all
// early returns) is defense-in-depth for requests that reach pre-routing.
// NEVER reset at the top of post-routing directly (that would precede the
// emission).
[[nodiscard]] inline bool& tls_engine_principal() {
    thread_local bool v = false;
    return v;
}
}  // namespace detail

// Presentation-based classifier — CREDENTIAL PRESENTATION only, not
// validated session. See the file header comment for the full contract.
[[nodiscard]] inline std::string_view principal_class_of(const httplib::Request& req) {
    // Order matters: a request carrying BOTH a cookie and a bearer token is
    // classified by the stronger machine signal — API/MCP clients sometimes
    // inherit ambient cookies from shared HTTP stacks, but a browser never
    // fabricates an Authorization header.
    if (req.has_header("Authorization") || req.has_header("X-Yuzu-Token")) {
        return "agent";
    }
    // Anchored match: the cookie NAME must be exactly yuzu_session — at the
    // start of the Cookie header or after a "; " separator — so a cookie
    // merely named e.g. not_yuzu_session doesn't classify as human.
    auto cookie = req.get_header_value("Cookie");
    if (cookie.starts_with("yuzu_session=") ||
        cookie.find("; yuzu_session=") != std::string::npos) {
        return "human";
    }
    return "none";
}

// principal_class for the metric: "engine" when the RESOLVED session is an
// engine principal (stashed by the pre-routing chokepoint), else the
// presentation-based fallback. See the file header comment for the
// hybrid-basis contract.
//
// THREAD AFFINITY: reads the request-scoped `tls_engine_principal()`
// thread_local, so it must be called ONLY on the request's own httplib worker
// thread (the pre-routing → post-routing path). Never call it from a content
// provider on another thread, a background task, or a signal handler — it
// would read a different thread's stash. Its sole production caller is the
// post-routing metric emission, on the correct thread.
[[nodiscard]] inline std::string_view principal_class_resolved(const httplib::Request& req) {
    if (detail::tls_engine_principal()) return "engine";
    return principal_class_of(req);
}

}  // namespace yuzu::server
