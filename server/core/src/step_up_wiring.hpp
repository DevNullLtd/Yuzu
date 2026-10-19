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
            // handler either — same reasoning as the pre-routing
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
        // Last-resort containment for the whole block — see
        // `enforce_pre_auth_body_cap`'s identical catch in server.cpp. No
        // envelope can be built once we are here, but the request
        // must still be refused rather than let the throw reach an
        // unguarded httplib call site.
        res.status = 413;
        return httplib::Server::HandlerResponse::Handled;
    }
}

} // namespace yuzu::server::detail
