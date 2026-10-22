#pragma once

/// @file step_up_wiring.hpp
///
/// The body of `server.cpp`'s `set_pre_request_handler` lambda, moved here unchanged in behaviour
/// so a test can install the SAME function on a real `httplib::Server` and drive it over a socket.
/// httplib runs the pre-request handler after routing (so `req.matched_route` is set) and after the
/// body has been read, which is the only point at which the post-read body cap and the MFA step-up
/// chokepoint can both be applied.
///
/// Stage order, fixed: the post-read body cap (413 on an over-cap body), then
/// `apply_step_up_chokepoint` for a body within the cap. The whole block is contained: a throw
/// answers 413 (fail closed) rather than reaching an httplib call site. The caller builds `deps`
/// per request (the auth store pointer is re-read each time so a nulled store answers 503).
/// See `server.cpp` at the `set_pre_request_handler` call for the capture contract and the
/// reasoning behind the containment.
///
/// `run_in_handler_step_up` is the decision behind the `StepUpFn` that `server.cpp` hands to the
/// route owners, extracted for the same reason.
///
/// PR 2 deletes `run_in_handler_step_up` together with the in-handler `StepUpFn` calls (the
/// chokepoint then answers those routes alone, and the label-equals source pins that force an
/// in-handler call per kRequired row go with them).

#include "body_cap_policy.hpp"
#include "on_behalf_guard.hpp"
#include "rest_a4_envelope_http.hpp"
#include "step_up_gate.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_json.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace yuzu::server::detail {

[[nodiscard]] inline httplib::Server::HandlerResponse
run_pre_request_stage(const httplib::Request& req, httplib::Response& res,
                      const StepUpChokepointDeps& deps) {
    try {
        const auto cap_match = resolve_body_cap(req.method, req.path);
        if (req.body.size() <= cap_match.max_body_bytes) {
            return apply_step_up_chokepoint(req, res, deps) == StepUpChokepointResult::kRefused
                       ? httplib::Server::HandlerResponse::Handled
                       : httplib::Server::HandlerResponse::Unhandled;
        }

        static std::atomic<std::uint64_t> post_read_hits{0};
        constexpr std::uint64_t kBodyLogEvery = 100;
        if (post_read_hits.fetch_add(1, std::memory_order_relaxed) % kBodyLogEvery == 0) {
            spdlog::warn("[#2407 post-read] rejected {} {} from {}: body {} bytes read, "
                         "over the {}-byte cap (class={}, 1 log per {} rejections; the "
                         "counter records all)",
                         onbehalf::sanitize_for_log(req.method, 16),
                         onbehalf::sanitize_for_log(req.path),
                         onbehalf::sanitize_for_log(req.remote_addr, 64), req.body.size(),
                         cap_match.max_body_bytes, cap_match.path_class, kBodyLogEvery);
        }
        try {
            if (deps.metrics)
                deps.metrics
                    ->counter("yuzu_body_cap_rejected_total",
                              {{"path_class", std::string(cap_match.path_class)},
                               {"reason", "over_cap_post_read"}})
                    .increment();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // Observability must never kill the process from this
            // handler either: same reasoning as the pre-routing
            // gate's own metric try/catch above.
        }

        res.status = 413;
        if (cap_match.path_class == "scim") {
            // D7 parity: same RFC 7644 §3.12 envelope the pre-routing
            // gate's SCIM branch uses.
            res.set_content(scim::error(413, "request body too large").dump(),
                            "application/scim+json");
        } else {
            res.set_content(
                a4_denial(res, 413, "request body exceeds this route's size cap",
                          A4ErrorOpts{.remediation =
                                          "reduce the request body size; see "
                                          "docs/user-manual/rest-api.md for the per-route "
                                          "limit"}),
                "application/json");
        }
        return httplib::Server::HandlerResponse::Handled;
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // Last-resort containment for the whole block, see
        // `enforce_pre_auth_body_cap`'s identical catch in server.cpp. No
        // envelope can be built once we are here, but the request
        // must still be refused rather than let the throw reach an
        // unguarded httplib call site.
        res.status = 413;
        return httplib::Server::HandlerResponse::Handled;
    }
}

/// The in-handler step-up decision, behind the `StepUpFn` `server.cpp` hands to the route owners.
///   1. The chokepoint already passed this request for this action AND for the principal `session`
///      (the one the handler resolved): consume the pass and allow (skips a second MFA store
///      read). The address is not a key; the stash clears, the label match and the identity match
///      are what protect against a stale pass or one earned by another principal (see
///      `StepUpPassStash`). A pass for a different principal is refused and spent, and step 2/3
///      evaluate `session` afresh. The request's principal binding outlives the pass.
///   2. No auth store: fail closed with the 503 (`refuse_step_up_store_unwired`) for EVERY caller
///      class, before any decision is made.
///   3. Otherwise evaluate and render exactly as `require_mfa_step_up` does.
/// `auth_db` is read per request by the caller, so a store that is nulled answers 503.
[[nodiscard]] inline bool
run_in_handler_step_up(const httplib::Request& req, httplib::Response& res,
                       const auth::Session& session, const std::string& action_label,
                       AuthDB* auth_db, int window_secs, const StepUpAuditFn& audit,
                       std::string_view mfa_enforcement, yuzu::MetricsRegistry* metrics) {
    if (consume_step_up_pass(req, session, action_label))
        return true;
    if (auth_db == nullptr) {
        // Fail closed: no auth store means the gate cannot evaluate, so it refuses.
        refuse_step_up_store_unwired(req, res, session, audit, action_label, metrics);
        return false;
    }
    return require_mfa_step_up(req, res, session, *auth_db, window_secs, audit, action_label,
                               mfa_enforcement, metrics);
}

} // namespace yuzu::server::detail
