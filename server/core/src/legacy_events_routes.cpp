#include "legacy_events_routes.hpp"

#include "event_bus.hpp"
#include "http_route_sink.hpp"
#include "principal_quota_gate.hpp" // adopt_quota_slot_into_stream
#include "stream_budget.hpp"

#include <httplib.h>

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace yuzu::server::legacy_events {

void register_legacy_events_routes(HttpRouteSink& sink, Deps deps) {
    // SSE endpoint
    sink.Get("/events", [deps](const httplib::Request& req, httplib::Response& res) {
        // ADMISSION CONTROL (ADR-0034). Every connection holds an httplib worker for
        // its whole life, so it takes a lease like every other streaming surface.
        // This route IS session-gated: `/events` is not in `is_login_exempt_path`,
        // and the pre-routing chokepoint 401s a caller with no session by name
        // (alongside `/api/` and `/mcp/`), so the handler only ever runs for an
        // authenticated operator. What the lease bounds here is therefore an
        // AUTHENTICATED thread-pinning path, not a pre-auth one.
        // The anonymous branch below is unreachable today and kept only as
        // defence-in-depth against a future change to the exempt list — it must not
        // be read as evidence that this surface is open. The residual defect on this
        // route is the missing per-connection queue cap (`/api/v1/events` opts into
        // `kPerConnectionQueueCapDefault`; this one does not), which the lease does
        // NOT address — see ADR-0034 Decision 1.
        // guardian-confinement-2298 PR3 §3e: this legacy stream has NO
        // in-handler auth at all beyond the pre-routing 401 (see the
        // block comment above) — `event_bus_.subscribe` below fans out
        // raw agent ids, pending-agent ids, live command result rows,
        // and command status/timing with no per-agent scoping. Deny a
        // service-scoped session BEFORE the admission-control lease and
        // BEFORE subscribe, so a denied caller never pins a worker or a
        // bus subscription slot.
        if (deps.deny_service_scoped_fn(
                req, res, "events.stream.access_denied",
                "service-scoped tokens may not open the fleet-wide legacy event stream", "", ""))
            return;

        std::string principal = "anonymous";
        std::size_t per_principal = detail::kPerPrincipalAnonymous;
        if (deps.resolve_session_fn) {
            if (auto sess = deps.resolve_session_fn(req)) {
                principal = sess->username;
                per_principal = detail::kPerPrincipalDashboard;
            }
        }
        auto lease = std::make_shared<detail::StreamBudget::Lease>();
        if (deps.stream_budget) {
            auto admitted = deps.stream_budget->try_acquire(detail::SseSurface::kLegacyEvents,
                                                             principal, per_principal);
            if (!admitted.lease) {
                res.status = 429;
                res.set_header("Retry-After", "5");
                res.set_content("too many live streams open", "text/plain; charset=utf-8");
                return;
            }
            *lease = std::move(admitted.lease);
        }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        auto sink_state = std::make_shared<detail::SseSinkState>();
        sink_state->sub_id = deps.event_bus->subscribe([sink_state](const detail::SseEvent& ev) {
            {
                std::lock_guard<std::mutex> lk(sink_state->mu);
                sink_state->queue.push_back(ev);
            }
            sink_state->cv.notify_one();
        });

        detail::EventBus* bus = deps.event_bus;
        // Use chunked content provider so httplib sends each sink.write()
        // as a complete HTTP chunk in a single send() call.  The browser
        // processes each chunk eagerly (no buffering of raw streams).
        // Note: httplib's chunked loop sets data_available = (l > 0) on
        // every write.  Our provider never writes 0 bytes (always at
        // least a 14-byte keepalive), so the loop runs indefinitely.
        // UP-1: adopt any pending engine QuotaSlot into this stream's
        // resource-releaser (see is_streaming_path/adopt_quota_slot_
        // into_stream in principal_quota_gate.hpp) so the concurrency
        // reservation survives for the stream's actual lifetime instead
        // of releasing early at post-routing.
        res.set_chunked_content_provider(
            "text/event-stream",
            [sink_state, budget = deps.stream_budget](size_t offset,
                                                       httplib::DataSink& sink) -> bool {
                return detail::sse_content_provider(sink_state, offset, sink, budget);
            },
            detail::adopt_quota_slot_into_stream(
                [sink_state, bus, lease](bool success) noexcept {
                    // noexcept for parity with the three sibling releasers: this runs
                    // from ~Response, and sse_resource_release is now noexcept at source
                    // (event_bus.hpp), so the whole chain is terminate-safe.
                    detail::sse_resource_release(sink_state, *bus, success);
                    // `lease` dies here — the worker returns to the one shared budget.
                }));
    });
}

} // namespace yuzu::server::legacy_events
