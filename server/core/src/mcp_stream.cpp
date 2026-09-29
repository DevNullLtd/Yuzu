#include "mcp_stream.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_transport.hpp"
#include "rest_a4_envelope.hpp"
#include "auth_routes.hpp" // detail::sanitize_detail_value — audit-string sanitiser
#include "engine_principal_store.hpp" // kAuthCacheTtl — the staleness bound this pump clamps to (#2367)
#include "principal_quota_gate.hpp" // detail::adopt_quota_slot_into_stream (UP-1)
#include "rest_audit.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <new> // std::bad_alloc — the publish() fault-injection seam throws it
#include <random>
#include <functional>
#include <string_view>
#include <stdexcept>  // std::runtime_error - the unpin() fault-injection seam throws it
#include <system_error>
#include <utility>

namespace yuzu::server::mcp {

// The ring's frame cap must never exceed the sink queue's cap: a full-ring replay is
// pushed through enqueue_capped, so a larger ring would silently drop the OLDEST
// replayed frames — gapping a resume that the ring could actually have served, which
// is precisely the failure the ring exists to prevent.
static_assert(kMcpRingCapDefault <= sse_bus::kPerConnectionQueueCapDefault,
              "replay ring must fit the sink queue or a full replay self-gaps");
static_assert(McpSessionRegistry::Config{}.ring_cap == kMcpRingCapDefault,
              "registry default and stream default must not drift");
// Same for the byte cap: the registry header cannot name the constant (it only
// forward-declares McpStreamState), so the two literals are pinned together here.
static_assert(McpSessionRegistry::Config{}.ring_bytes_cap == kMcpRingBytesCapDefault,
              "registry byte-cap default and stream byte-cap default must not drift");
// The session TTL slide rides the TICK GATE (#2730). Before that it ran on every
// wake, so the tick was irrelevant to it; now a live stream refreshes its session
// once per tick, and a tick approaching the idle TTL would let the registry's idle
// GC reclaim a session out from under a stream that is demonstrably alive. The
// margin is deliberately generous rather than a bare `tick < idle_ttl`: a pass can
// stall for up to the 30 s socket write timeout before it reaches the gate, so the
// interval between slides is bounded by tick PLUS that stall, not by tick alone.
// 100x puts the floor at 300 s against today's 1800 s vs 3000 ms. This is the
// fourth cross-constant pair the file pins, and the one the tick gate created -
// the other three predate it.
static_assert(kMcpStreamTickDefault * 100 <= McpSessionRegistry::Config{}.idle_ttl,
              "session idle_ttl must stay far above the stream tick (#2730) - the TTL slide "
              "now runs once per tick, so a narrow margin lets idle GC reap a live stream");

namespace {

constexpr std::size_t kMaxWriteSlice = 8192;  // sibling parity (/api/v1/events)
constexpr std::size_t kMaxEventTypeBytes = 64;  // SSE event names are short by construction

// Metric names — the Decision 15(k) family, fixed at PR 0 so dashboards/alerts
// can be authored against them before the code lands.
constexpr const char* kMetricStreamsActive = "yuzu_mcp_streams_active";
constexpr const char* kMetricStreamsHandover = "yuzu_mcp_streams_handover_pending";
constexpr const char* kMetricRingEvictions = "yuzu_mcp_stream_replay_ring_evictions_total";
constexpr const char* kMetricStreamRejects = "yuzu_mcp_stream_rejects_total";
constexpr const char* kMetricStreamCloses = "yuzu_mcp_stream_closes_total";
constexpr const char* kMetricFramesDropped = "yuzu_mcp_stream_frames_dropped_total";
constexpr const char* kMetricFramesTruncated = "yuzu_mcp_stream_frames_too_large_total";
constexpr const char* kMetricPublishFailures = "yuzu_mcp_stream_publish_failures_total";
// A committed final response was published with NO pin at all. Structurally unreachable
// while the pin array is non-empty - a full slot set displaces its oldest pin instead
// (kMetricPinDisplaced below). Kept as
// defence in depth: non-zero means the array was resized to zero or the displacement
// path was bypassed.
constexpr const char* kMetricFinalUnpinned = "yuzu_mcp_stream_final_unpinned_total";
/// An older pinned terminal yielded its eviction-exemption slot to a newer one.
/// The bridge admits streamed records against `pinned_count() + unpinned` and the pin array
/// is sized to exactly that cap. What a full set MEANS since #2740 is defined once -
/// see McpStreamState's "What a FULL PIN-SLOT SET means" block in mcp_stream.hpp. This
/// counter carries that reading (the LRU is the graceful degradation, not a licence).
constexpr const char* kMetricPinDisplaced = "yuzu_mcp_stream_pin_displaced_total";
/// The final was written to the wire (the client has it), but the bridge's own
/// credit step (on_final_written, mcp_stream_bridge.cpp) threw before it could
/// run - so the session's pin is retained rather than released. Needs a
/// genuinely broken platform mutex, so any nonzero value is a signal about the
/// host, not a rate to tune. The close is still reported to the client as
/// kCompleted, since that is what they actually received. This counter fires
/// ONLY on a THROWN failure of that call (the catch block below is its one
/// increment site) - a credit step that fails to run without throwing is a
/// distinct failure shape this counter says nothing about.
constexpr const char* kMetricFinalCreditFailed = "yuzu_mcp_stream_final_credit_failed_total";
/// A poison-path close (poison_terminal()'s own close, or attach_and_replay's retry of a
/// stale sink on a poisoned session) failed and was contained. The poison flag itself is
/// always durable regardless - this counts only whether the CLIENT was actually told, so
/// a nonzero value means some client may have kept heart-beating on a stream the server
/// had already given up on until its next attach retried the close. Needs a genuinely
/// broken platform mutex (close_sink's one throw site), so any nonzero value is a signal
/// about the host, not a rate to tune. Alert on > 0 (#2531).
constexpr const char* kMetricPoisonCloseFailures = "yuzu_mcp_stream_poison_close_failures_total";

void count_reject(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics != nullptr) {
        metrics->counter(kMetricStreamRejects, {{"reason", reason}}).increment();
    }
}

// Closes are counted BY REASON. Without this an operator cannot alert on
// "auth_unavailable closes are spiking" (i.e. our auth store is sick and streams are
// dying of it) without trawling the audit store — and that is precisely the signal the
// tri-state re-validation exists to produce.
void count_stream_close(yuzu::MetricsRegistry* metrics, McpStreamClose reason) {
    if (metrics != nullptr) {
        metrics->counter(kMetricStreamCloses, {{"reason", to_string(reason)}}).increment();
    }
}

void count_final_credit_failed(yuzu::MetricsRegistry* metrics) {
    if (metrics != nullptr) {
        metrics->counter(kMetricFinalCreditFailed).increment();
    }
}

void count_poison_close_failed(yuzu::MetricsRegistry* metrics) {
    if (metrics != nullptr) {
        metrics->counter(kMetricPoisonCloseFailures).increment();
    }
}

// SSE is a line protocol: a newline in `event_type` would terminate the field and
// let the rest of the string forge SSE lines. `data` is safe (format_sse re-prefixes
// every line), but the type is not — strip rather than trust. The producer seam
// (`publish`) is the only way a type reaches the wire.
std::string sanitize_event_type(std::string type) {
    for (char& c : type) {
        if (c == '\n' || c == '\r') {
            c = '_';
        }
    }
    return type;
}

// What a client should DO about each close reason. Part of the A4 shape on the final
// frame: "your stream ended" is only actionable if we say what ends it.
const char* close_remediation(McpStreamClose reason) {
    switch (reason) {
    case McpStreamClose::kCredentialRevoked:
        return "re-authenticate, then re-initialize and reconnect";
    case McpStreamClose::kAuthUnavailable:
        return "the auth store was unreachable; retry — durable results remain fetchable "
               "by execution_id";
    case McpStreamClose::kSessionTerminated:
        return "re-initialize to mint a new session";
    case McpStreamClose::kInternalError:
        return "a server-side fault ended this stream — reconnect; durable results remain "
               "fetchable by execution_id";
    case McpStreamClose::kCancelled:
        return "cancellation acknowledged — the execution continues server-side; fetch the "
               "result by execution_id";
    case McpStreamClose::kCapExpired:
        return "the streamed-response time cap elapsed — the execution continues server-side; "
               "fetch the result by execution_id, or reconnect via GET to resume";
    case McpStreamClose::kRecordGone:
        return "this response could not continue — the execution continues server-side; "
               "fetch the result by execution_id, or reconnect via GET to resume";
    case McpStreamClose::kCompleted:
        // kCompleted never produces a close FRAME (the final is written then EOF); this exists
        // only so the audit/metric label set is exhaustive. No client action is warranted.
        return "the stream completed normally — no action needed";
    case McpStreamClose::kClientGone:
    case McpStreamClose::kSuperseded:
    case McpStreamClose::kNone:
        break;
    }
    return "reconnect with Last-Event-ID to resume within the replay window";
}


// Strict, non-throwing cursor parse. std::stoull would be wrong twice over: it does
// not throw on "-1" (it WRAPS to UINT64_MAX, which lands past the ring window and so
// would terminate the client's session over a typo), it accepts trailing junk, and it
// throws on overflow — inside a content-provider callback that must never throw.
std::uint64_t parse_last_event_id(std::string_view raw) {
    if (raw.empty() || raw.front() == '-' || raw.front() == '+') {
        return 0;
    }
    std::uint64_t value = 0;
    const char* const end = raw.data() + raw.size();
    const auto [ptr, ec] = std::from_chars(raw.data(), end, value);
    if (ec != std::errc{} || ptr != end) {
        return 0; // unparseable cursor → replay what we still hold, never terminate
    }
    return value;
}

bool write_all(const McpStreamPump::WriteFn& write, std::string_view payload) {
    const char* p = payload.data();
    std::size_t rem = payload.size();
    while (rem > 0) {
        const std::size_t n = std::min(rem, kMaxWriteSlice);
        if (!write(p, n)) {
            return false;
        }
        p += n;
        rem -= n;
    }
    return true;
}

}  // namespace

const char* to_string(McpStreamClose reason) {
    switch (reason) {
    case McpStreamClose::kNone:
        return "none";
    case McpStreamClose::kClientGone:
        return "client_disconnect";
    case McpStreamClose::kSuperseded:
        return "superseded";
    case McpStreamClose::kSessionTerminated:
        return "session_terminated";
    case McpStreamClose::kCredentialRevoked:
        return "credential_revoked";
    case McpStreamClose::kAuthUnavailable:
        return "auth_unavailable";
    case McpStreamClose::kInternalError:
        return "internal_error";
    case McpStreamClose::kCancelled:
        return "cancelled";
    case McpStreamClose::kCapExpired:
        return "cap_expired";
    case McpStreamClose::kRecordGone:
        return "record_gone";
    case McpStreamClose::kCompleted:
        return "completed";
    }
    return "unknown";
}

// PENDING 2 (2f PR 3b): the JSON-RPC-wrapped stream-close notification. See the declaration in
// mcp_stream.hpp for the shape + the `extra_params_json` contract. Public (matches the header);
// close_remediation above is TU-local but name-visible here.
std::string make_stream_closed_frame(McpStreamClose reason, std::string_view correlation_id,
                                     std::string_view extra_params_json) {
    // #3344: retry_after_ms stays null here — `close_remediation(reason)`
    // already carries per-reason reconnect guidance (e.g. re-initialize vs.
    // wait out a cap), and the admission paths that actually gate a
    // reconnect (kMcpStreamCapRetryAfterMs / kMcpHandoverRetryAfterMs) carry
    // their own honest hints on the 429 the client hits when it reconnects.
    std::string body =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/yuzu.stream_closed\",\"params\":{\"reason\":";
    body += detail::json_quoted(to_string(reason));
    body += ",\"correlation_id\":";
    body += detail::json_quoted(correlation_id);
    body += ",\"retry_after_ms\":null,\"remediation\":";
    body += detail::json_quoted(close_remediation(reason));
    body += extra_params_json; // raw ,"key":val fragment (leading comma) from the caller, or empty
    body += "}}";
    return body;
}

// ── McpStreamState ──────────────────────────────────────────────────────────

McpStreamState::McpStreamState(std::size_t ring_cap, yuzu::MetricsRegistry* metrics,
                               std::size_t ring_bytes_cap)
    : ring_cap_(ring_cap == 0 ? 1 : ring_cap),
      // Floored, not merely non-zero: below the size of the frame_too_large notice itself
      // every publish would be "oversized", collapsing the ring to a single frame and
      // making every resume a gap.
      ring_bytes_cap_(std::max<std::size_t>(ring_bytes_cap, kMinRingBytesCap)), metrics_(metrics) {
    if (metrics_ != nullptr) {
        // Pay the allocation and the global-registry lock HERE, once, on a path that is
        // allowed to throw — not inside attach/detach, where a throw would strand a sink
        // that is already live and already holds a budget lease.
        gauge_streams_active_ = &metrics_->gauge(kMetricStreamsActive);
        gauge_streams_handover_ = &metrics_->gauge(kMetricStreamsHandover);
    }
}

std::uint64_t McpStreamState::publish(std::string_view event_type, std::string_view data) noexcept {
    return publish_guarded(event_type, data, /*deliver_live=*/true, /*pinned=*/false);
}

std::uint64_t McpStreamState::publish_ring_only(std::string_view event_type,
                                                std::string_view data) noexcept {
    // Ring commit for resume replay, but NO live-GET-sink copy - a streamed POST's frames
    // ride the POST stream, and duplicating them onto a concurrent GET would be the spec's
    // "MUST NOT broadcast the same message across multiple streams".
    return publish_guarded(event_type, data, /*deliver_live=*/false, /*pinned=*/false);
}

std::uint64_t McpStreamState::publish_final(std::string_view event_type,
                                            std::string_view data) noexcept {
    // Ring-only (as above) AND eviction-exempt: the streamed request's final response must
    // survive a ring wrap so a resume can always recover it (Decision 15(f)).
    return publish_guarded(event_type, data, /*deliver_live=*/false, /*pinned=*/true);
}

std::uint64_t McpStreamState::publish_guarded(std::string_view event_type, std::string_view data,
                                              bool deliver_live, bool pinned) noexcept {
    // HARD exception boundary (#2366) - the pump_once/pump_once_impl pattern, shared by all
    // three publish seams so they cannot drift. PR 3's progress bridge calls these from an
    // ExecutionEventBus listener on a worker task httplib's routing try/catch never sees, so
    // an escaped throw is std::terminate (the #2037 class). publish_impl contains every
    // post-commit fault itself, so an exception reaching this catch proves the ring and
    // next_id_ are untouched - 0 ("not published, no id consumed") is the honest answer, and
    // the caller's frame simply never happened rather than silently gapping Last-Event-ID.
    //
    // string_view params (not by-value std::string): a by-value parameter is
    // copy-constructed in the CALLER's frame for an lvalue arg, so a bad_alloc there
    // would escape to the unguarded listener BEFORE this try. The views convert without
    // allocating; publish_impl owns them inside the guard.
    try {
        return publish_impl(event_type, data, deliver_live, pinned);
    } catch (...) {
        // Best-effort observability only — the metric lookup and the log line both
        // allocate, and under bad_alloc a throw from THIS handler would propagate
        // straight out of the boundary it implements. Nested guard, same as pump_once.
        try {
            if (metrics_ != nullptr) {
                metrics_->counter(kMetricPublishFailures).increment();
            }
            // Enriched so an operator can attribute the loss: the session (log_context_,
            // set once at mint - safe to read unlocked) and the event_type that never
            // reached the ring. Both the format and the metric lookup allocate; the nested
            // guard contains a bad_alloc from either.
            spdlog::warn("MCP stream publish [{}]: frame dropped pre-commit "
                         "(event_type={}, exception contained)",
                         log_context_, event_type);
        } catch (...) {  // NOLINT(bugprone-empty-catch) — nothing left we could safely do
        }
        return 0;
    }
}

void McpStreamState::inject_publish_fault_for_test(PublishFault fault, int times) {
    std::lock_guard<std::mutex> lk(mu_);
    publish_fault_ = fault;
    publish_fault_remaining_ = (fault == PublishFault::kNone) ? 0 : times;
}

void McpStreamState::set_log_context(std::string context) {
    // No lock: write-once at mint before the stream is shared (see the header contract).
    // Locking here would give false comfort - publish()'s reads are unlocked by design and
    // are made safe by the mint-time happens-before edge, not by this write's own lock.
    log_context_ = std::move(context);
}

std::uint64_t McpStreamState::publish_impl(std::string_view event_type_view,
                                           std::string_view data_view, bool deliver_live,
                                           bool pinned) {
    // Own the payload INSIDE the boundary. These two copies are the caller-visible
    // allocations that used to happen in the caller's frame (by-value params); doing them
    // here means a bad_alloc is caught by publish()'s guard as a clean pre-commit 0
    // (nothing mutated yet), never an escape to the unguarded ExecutionEventBus listener.
    std::string event_type{event_type_view};
    std::string data{data_view};
    std::shared_ptr<McpStreamSink> live;
    std::uint64_t id = 0;
    std::uint64_t evicted = 0;
    bool oversized = false;
    bool sink_enqueue_failed = false;
    bool pin_displaced = false; ///< an older pin yielded its slot (corroborate, not a verdict)
    bool pin_unslotted = false; ///< no slot at all (only if the array is size 0)
    bool post_commit_obs_fault = false;  // test seam; tripped inside the post-commit try
    {
        // A single frame must not exceed the ring's byte budget, or the "always keep the
        // newest frame" rule below would admit it whole and the byte cap would bound
        // nothing.
        //
        // Do NOT byte-truncate it: these payloads are JSON, so a cut at an arbitrary
        // offset yields a guaranteed-unparseable frame — which we would then hand to the
        // live sink AND store in the ring under an id, so every resume would faithfully
        // re-serve the same garbage. Substitute a well-formed frame that says what
        // happened and where the real answer is. The client gets something it can parse
        // and act on; the ring stays bounded.
        if (event_type.size() + data.size() > ring_bytes_cap_) {
            data = "{\"error\":\"frame_too_large\",\"bytes\":" + std::to_string(data.size()) +
                   ",\"remediation\":\"fetch the full result by execution_id\"}";
            // The frame is event_type + data, so a pathological type could still overshoot
            // the bound the notice was meant to restore. Types are server-chosen and short
            // ("message"); clamp anyway rather than trust that forever.
            if (event_type.size() > kMaxEventTypeBytes) {
                event_type.resize(kMaxEventTypeBytes);
            }
            oversized = true;
        }
        std::lock_guard<std::mutex> lk(mu_);
        // One-shot: read AND clear the injected fault up front, so an armed fault can
        // never persist past the publish that observes it. In particular kSinkEnqueue
        // injected while no sink is live would otherwise never reach its consumption
        // point below and would silently fire on a LATER real client's first frame.
        // Consuming it here makes both fault phases symmetric (always consumed once).
        // Test seam only - publish_fault_ is kNone in production. `times` (see the
        // header) lets the same fault fire on N consecutive publishes; the historical
        // one-shot is times == 1.
        PublishFault fault = PublishFault::kNone;
        if (publish_fault_remaining_ > 0) {
            fault = publish_fault_;
            if (--publish_fault_remaining_ == 0) {
                publish_fault_ = PublishFault::kNone;
            }
        }
        if (fault == PublishFault::kPreCommit) {
            throw std::bad_alloc{};
        }
        // Latched out of the block so it can trip the POST-COMMIT observability try below
        // (after the frame is committed), not here. `fault` is block-scoped and consumed
        // one-shot above, so carry the intent in a bool like sink_enqueue_failed.
        post_commit_obs_fault = (fault == PublishFault::kPostCommitObservability);
        // Ordering is the fix for #2366 (the stream_budget.hpp "every allocating step
        // happens before any counter moves" template): read next_id_ WITHOUT
        // incrementing, do every allocating step (sanitize, frame construction, the
        // deque node push), and only then advance the id. A throw from push_back
        // (strong guarantee — deque unchanged) therefore leaves next_id_ untouched too:
        // no permanent hole in the id space, no silent Last-Event-ID gap. The old
        // `id = next_id_++` BEFORE the push consumed the id even when the push failed.
        id = next_id_;
        ring_.push_back(sse_bus::SseEvent{sanitize_event_type(std::move(event_type)),
                                          std::move(data), id});
        // ── COMMITTED from here: everything below is noexcept or locally contained. ──
        ++next_id_;
        while (ring_.size() > ring_cap_ ||
               (ring_bytes_ + frame_bytes(ring_.back()) > ring_bytes_cap_ && ring_.size() > 1)) {
            // Bounded on BOTH axes (Decision 15(d)). The frame count alone is not a memory
            // bound — 1024 sessions x 500 frames only bounds memory if you also know what a
            // frame weighs. Always keep at least the newest frame.
            //
            // Evict the OLDEST UNPINNED frame, not simply the front: a pinned final response
            // (Decision 15(f)) must survive a ring wrap so a resume can recover it. Scan from
            // the front for the first evictable frame (unpinned AND not the newest `back()`).
            // The pin count is bounded by kMaxStreamedPostsPerSession (4) and the ring by
            // kMcpRingCapDefault (500), so this inner scan is cheap.
            const auto last = std::prev(ring_.end()); // never evict the newest
            auto victim = ring_.begin();
            while (victim != last && is_pinned_locked(victim->id)) {
                ++victim;
            }
            if (victim == last) {
                // Only pinned frames plus the newest remain - stop even if still over the
                // byte cap. The overshoot is BOUNDED: at most kMaxStreamedPostsPerSession
                // pinned finals, each bridge-clamped small, above the nominal cap.
                break;
            }
            ring_bytes_ -= frame_bytes(*victim);
            ring_.erase(victim);
            ++evictions_;
            ++evicted;
        }
        ring_bytes_ += frame_bytes(ring_.back());

        // Pin the committed final AFTER the commit + eviction (it is the newest frame, which
        // eviction never touches). Writing the id only now means a pre-commit push_back throw
        // leaves no ghost pin.
        if (pinned) {
            // WHAT HAPPENS WHEN THE SLOTS ARE FULL. What a full set MEANS is defined
            // once - see McpStreamState's "What a FULL PIN-SLOT SET means" block in
            // mcp_stream.hpp - and is deliberately not restated here. Since #2740 it is
            // a signal to CORROBORATE, not a verdict: the state is reachable, so this
            // branch is a real degradation path rather than an impossible one.
            //
            // But the old fallback made the drift worse than it needed to be: it committed
            // the newest terminal UNPINNED, which is the wrong one to sacrifice. A pin
            // exists so a terminal survives a ring wrap and a late resume can still recover
            // it (Decision 15(f)) - worth most for the NEWEST result, least for the oldest,
            // which by then is the likeliest to have been consumed already. Sacrificing the
            // newest meant the request most likely still waiting for its answer was the one
            // left evictable.
            //
            // So the slots degrade as an LRU: the OLDEST pin yields to the newest. Ids are
            // monotonic, so the smallest live id IS the oldest. That keeps the strongest
            // invariant still available under drift - "the N most recent terminals are
            // recoverable" - while still reporting the drift that got us here.
            std::uint64_t* free_slot = nullptr;
            std::uint64_t* oldest = nullptr;
            for (auto& slot : pinned_ids_) {
                if (slot == 0) {
                    free_slot = &slot;
                    break;
                }
                if (oldest == nullptr || slot < *oldest) {
                    oldest = &slot;
                }
            }
            // The counters are LATCHED, not incremented here. `MetricsRegistry::counter`
            // builds a std::string, may insert a map node, and takes the registry lock -
            // three throw sites. Throwing at this point would be worse than it looks: the
            // frame is already committed, `next_id_` has already advanced, and the older
            // pin has already been destroyed, but `publish_impl` would unwind to the
            // boundary's catch and return 0 - so the caller never learns the id, and
            // `unpin(id)` can never release the slot. That falsifies the guarantee stated
            // on publish_guarded ("a throw reaching the catch proves nothing was
            // committed"). Latching defers both to the post-commit block below, which
            // exists for exactly this, and keeps the registry mutex out of `mu_`.
            if (free_slot != nullptr) {
                *free_slot = id;
            } else if (oldest != nullptr) {
                *oldest = id;
                pin_displaced = true;
            } else {
                // Unreachable while the array is non-empty - kept as defence in depth so
                // a future resize to zero slots is loud rather than silently unprotected.
                pin_unslotted = true;
            }
        }

        // Enqueue to the live sink UNDER mu_, not after releasing it. Two concurrent
        // publishers (PR 3 will have concurrent tool calls on one session) would
        // otherwise be able to interleave between id-assignment and enqueue, putting
        // id 6 on the wire before id 5 — which silently breaks the monotonic
        // Last-Event-ID contract the whole resume mechanism rests on.
        // Safe: this is the DECLARED lock order (mu_ → sink mu), and enqueue_capped
        // never blocks on I/O or calls back into us.
        //
        // deliver_live == false (publish_ring_only / publish_final) skips the live sink
        // entirely: the frame is committed to the ring for resume only, never a second live
        // copy onto a concurrent GET (the spec's no-broadcast rule). A null `live` also
        // skips the post-lock notify below.
        live = deliver_live ? live_ : nullptr;
        if (live) {
            // Post-commit containment (#2366): enqueue_capped takes the SseEvent BY
            // VALUE, so the copy of ring_.back() at the call boundary is itself an
            // allocation that can throw — with the frame already committed to the ring.
            // Contain it HERE and convert it into the existing slow-consumer gap signal:
            // dropped_total is a lock-free atomic the pump already turns into the
            // `events-dropped` synthetic on its next tick, so the client learns a frame
            // never reached the wire and recovers it via Last-Event-ID replay (the ring
            // still holds it). Letting the throw escape instead would return 0 for a
            // frame that IS in the ring — a lie in both directions.
            try {
                if (fault == PublishFault::kSinkEnqueue) {
                    throw std::bad_alloc{};
                }
                sse_bus::enqueue_capped(live->sse, ring_.back(), ring_cap_);
            } catch (...) {
                // The committed frame's by-value copy threw (bad_alloc under memory
                // pressure — near-never by construction). Count it as a delivery drop:
                // the pump turns dropped_total into the events-dropped synthetic and the
                // ring still holds the frame, so Last-Event-ID replay recovers it. The
                // WARN is emitted post-lock (below) — unlike a routine slow-consumer
                // overflow this is an anomalous server-side allocation fault worth a log
                // line, and it is rare enough that it cannot flood.
                //
                // Bump dropped_total UNDER the sink mutex — the same synchronization the
                // enqueue path (enqueue_capped, just above) already uses for its
                // push_back. This makes the pump's wait predicate a proper condvar
                // handoff: a waiter cannot check the predicate false and then miss this
                // bump, so the events-dropped synthetic wakes deterministically on the
                // notify_one below rather than only on the next tick. Lock order mu_ →
                // sink mu (we hold mu_ here) — identical to enqueue_capped's own acquire.
                //
                // std::mutex::lock() can itself throw std::system_error (a broken mutex —
                // essentially never). Contain it: the frame is ALREADY committed to the
                // ring, so letting that throw reach publish()'s boundary catch would
                // return 0 for a committed frame — the one thing the contract forbids.
                // Fall back to a bare atomic bump (still counts the drop; the wakeup
                // degrades to bounded-by-tick, acceptable for a degenerate mutex fault).
                try {
                    std::lock_guard<std::mutex> sink_lk(live->sse->mu);
                    live->sse->dropped_total.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    live->sse->dropped_total.fetch_add(1, std::memory_order_relaxed);
                }
                sink_enqueue_failed = true;
            }
        }
    }
    if (live) {
        live->sse->cv.notify_one(); // outside mu_ — no need to hold it to wake a waiter
    }
    // Post-commit best-effort: Counter::increment allocates on a family's first use and
    // takes the registry lock — a throw here must not turn a committed publish into a
    // 0 return (the boundary's catch cannot tell it apart from a pre-commit failure).
    try {
        // TEST SEAM: model the observability block itself throwing (a metric increment or
        // WARN format allocating under memory pressure) AFTER the frame is committed. The
        // enclosing catch is the #2366 guarantee under test - a fault here must NOT turn a
        // committed publish into a 0 return, so publish_impl still returns `id`.
        if (post_commit_obs_fault) {
            throw std::bad_alloc{};
        }
        if (sink_enqueue_failed) {
            // Cause-honest and rare: a post-commit allocation fault, NOT a slow consumer
            // (which is counted silently per-event). The client already learns of the gap
            // via events-dropped; this is the server-side breadcrumb an operator correlates
            // with memory pressure. Enriched with the session and the committed frame id
            // (event_type was moved into the ring above; the id is the useful handle here).
            spdlog::warn("MCP stream publish [{}]: live-sink enqueue failed post-commit - "
                         "frame id={} is in the ring, client resyncs via events-dropped",
                         log_context_, id);
        }
        if (evicted > 0 && metrics_ != nullptr) {
            metrics_->counter(kMetricRingEvictions).increment(static_cast<double>(evicted));
        }
        if (oversized && metrics_ != nullptr) {
            // Counted, not just logged: an unbounded warn-per-publish is a log-flood
            // vector, and a new failure mode nobody can alert on is a failure mode
            // nobody sees.
            metrics_->counter(kMetricFramesTruncated).increment();
        }
        if (pin_displaced && metrics_ != nullptr) {
            metrics_->counter(kMetricPinDisplaced).increment();
        }
        if (pin_unslotted && metrics_ != nullptr) {
            metrics_->counter(kMetricFinalUnpinned).increment();
        }
    } catch (...) {  // NOLINT(bugprone-empty-catch) — observability must not un-commit
    }
    return id;
}

McpStreamState::AttachResult McpStreamState::attach_and_replay(std::uint64_t last_event_id,
                                                               sse_bus::StreamBudget* budget,
                                                               const std::string& principal,
                                                               std::size_t per_principal_cap) {
    AttachResult out;
    std::shared_ptr<McpStreamSink> superseded;
    sse_bus::StreamBudget::Lease new_lease;
    {
        std::unique_lock<std::mutex> lk(mu_);

        // 0. Poison. A terminal frame could not be delivered (publish_final failed twice),
        //    so this stream will never carry its final - fail every attach fast with a 410
        //    + fetch-by-execution_id remediation rather than let a client re-attach and
        //    heart-beat forever. Checked BEFORE resumability: a poisoned stream is gone
        //    regardless of cursor.
        if (terminal_poisoned_) {
            out.status = AttachStatus::kPoisoned;
            std::shared_ptr<McpStreamSink> stale_live = live_;
            const bool inject_fault = take_poison_close_fault_locked();
            lk.unlock();  // lock order: close_sink takes sink->sse->mu, never under mu_
            // Poisoning is sticky and idempotent: retry the close poison_terminal()
            // attempted, in case IT was contained (#2531) - a stale live client would
            // otherwise never learn its stream is gone until its own timeout, however
            // long that is.
            poison_close_contained(stale_live, inject_fault);
            return out;
        }

        // 1. Resumability. A cursor of 0 is "from the start of what we still have".
        //    Anything else must sit inside the ring window: at or after the frame
        //    before our oldest surviving id, and strictly before the next id we
        //    will assign. A cursor whose frames were evicted, and a bogus future
        //    cursor, take the SAME path — one client recovery (re-initialize), no
        //    silent gap and no oracle about which of the two it was.
        const std::uint64_t min_available = ring_.empty() ? next_id_ : ring_.front().id;
        const bool resumable =
            last_event_id == 0 || (last_event_id + 1 >= min_available && last_event_id < next_id_);
        if (!resumable) {
            out.status = AttachStatus::kGap;
            return out;
        }

        // 1a. Contiguity (#2435). A nonzero cursor that clears the window check above can STILL
        //     front a NON-contiguous surviving suffix: eviction is oldest-unpinned-first and
        //     skips pinned finals (Decision 15(f)), so the ring can hold [.., pinned final N, ..]
        //     with the unpinned frames between the cursor and N already evicted. The replay loop
        //     below serves every surviving id > cursor, so it would hand the client id N right
        //     after its cursor with a SILENT hole where cursor+1..N-1 used to be — the exact
        //     Last-Event-ID gap the resume mechanism must never produce. Require the surviving
        //     ids strictly above the cursor to form an unbroken run cursor+1, cursor+2, ...,
        //     next_id_-1 (the ring is ascending by id — frames push to back, eviction erases in
        //     place). Any hole -> kGap: the client re-initializes and fetches the final by
        //     execution_id (the Decision 15(f) durable handle), rather than resume over a gap.
        //     Checked BEFORE any mutation, so a gapped attach leaves the session untouched.
        if (last_event_id != 0) {
            std::uint64_t expected = last_event_id + 1;
            for (const auto& ev : ring_) {
                if (ev.id <= last_event_id) {
                    continue; // already delivered — not part of the replayed suffix
                }
                if (ev.id != expected) {
                    out.status = AttachStatus::kGap; // hole between cursor and a surviving frame
                    return out;
                }
                ++expected;
            }
            if (expected != next_id_) {
                // The surviving run did not reach the newest assigned id — the tail of the
                // replay window is missing. (Normally unreachable: the newest frame is never
                // evicted; belt-and-braces so a future eviction change can't open a silent gap.)
                out.status = AttachStatus::kGap;
                return out;
            }
        }

        // 1b. Unpin acknowledged finals (unpin rule (b)): a cursor at or past a pinned
        //     final's id proves the client already consumed it, so it no longer needs the
        //     eviction exemption - release it and let its ring space be reclaimed. (A pinned
        //     final is only replayed to a cursor strictly below its id, so unpinning one at
        //     or below the cursor never drops a frame this attach would have served.)
        if (last_event_id != 0) {
            for (auto& slot : pinned_ids_) {
                if (slot != 0 && slot <= last_event_id) {
                    slot = 0;
                }
            }
        }

        // 2. Admission.
        //
        // The scarce resource is not the session — it is the httplib WORKER each
        // held-open response pins for its whole life. So the accounting rule is:
        // one lease per SINK (per pinned worker), never one per session. An earlier
        // version kept the lease on the session and let a takeover inherit it, which
        // meant a superseded provider — still pinning its worker until it drains, and
        // a peer with a closed TCP window can stall that for the full write timeout —
        // was charged to nobody. A client could then hammer GET on ONE session and
        // pin the whole pool while the cap read 1. That defeats the entire point of
        // Decision 15(h).
        //
        // A takeover is admitted WITHOUT a cap check (a client reconnecting across a
        // zombie TCP must never be locked out by its own zombie), but it still takes
        // a lease, so the accounting stays truthful. The bound comes from structure
        // instead: a session holds at most ONE draining sink, so at most TWO
        // providers — hence `derive_stream_budget` reserves 2 workers per permitted
        // stream, and a second takeover while a handover is still pending is refused.
        if (live_ && draining_) {
            out.status = AttachStatus::kHandoverPending;
            return out; // one handover at a time — this is what bounds the pool
        }
        // Allocate BEFORE mutating live_/draining_. If make_shared threw after the
        // supersede, the session would be left with no live sink and a superseded provider
        // still on the wire receiving nothing — silent frame loss, and the next handover
        // blocked forever.
        auto sink = std::make_shared<McpStreamSink>();
        const bool is_takeover = live_ != nullptr; // decided BEFORE anything is mutated
        if (budget != nullptr) {
            // A takeover bypasses the CAPS but not the accounting.
            const auto mode = is_takeover ? sse_bus::StreamBudget::Admission::kTakeover
                                          : sse_bus::StreamBudget::Admission::kEnforceCaps;
            auto acquired = budget->try_acquire(sse_bus::SseSurface::kMcpGet, principal,
                                                per_principal_cap, mode);
            if (!acquired.lease) {
                // Only reachable on the first-attach path (a takeover always admits). The
                // session is untouched — nothing has been mutated yet.
                out.status = AttachStatus::kStreamCapHit;
                out.reject_reason = acquired.reject_reason;
                return out;
            }
            new_lease = std::move(acquired.lease);
        }

        // 3. Replay + attach, under the same lock a publisher would need — so no
        //    frame can slip into the window between the two. (The `/api/v1/events`
        //    sibling does replay and subscribe under SEPARATE locks and documents the
        //    resulting lost-frame window; here it cannot happen.)
        sink->lease = std::move(new_lease);
        for (const auto& ev : ring_) {
            if (ev.id > last_event_id) {
                sse_bus::enqueue_capped(sink->sse, ev, ring_cap_); // allocates — still safe:
                                                                   // live_/draining_ untouched
            }
        }
        // COMMIT. Everything above could throw and leave the session exactly as it was;
        // nothing below can.
        if (live_) {
            draining_ = std::move(live_);
            superseded = draining_;
        }
        live_ = sink;
        out.status = AttachStatus::kAttached;
        out.sink = sink;
        out.generation = ++generation_;

        // Gauges are published UNDER mu_, paired with the state change they describe: done
        // outside, a takeover whose superseded provider detaches before the attacher gets
        // to the increment drives `handover_pending` transiently negative — a sample an
        // alert would see. Safe to do here ONLY because the gauges were resolved at
        // construction: an increment through the cached pointer takes that gauge's own
        // mutex and allocates nothing, so it cannot throw while this sink is live and
        // holding a lease with no releaser armed yet.
        if (gauge_streams_active_ != nullptr) {
            gauge_streams_active_->increment();
            if (superseded) {
                gauge_streams_handover_->increment();
            }
        }
    }

    // Wake the superseded provider outside mu_ (lock order). `closed` MUST be set
    // while holding the sink mutex: the pump evaluates it as its wait predicate, and
    // a store+notify issued in the window between the pump's predicate check and its
    // atomic release-and-block is simply LOST — the provider would then sleep a full
    // tick before noticing, pinning a worker for 3 s per takeover.
    if (superseded) {
        close_sink(superseded, McpStreamClose::kSuperseded);
    }
    return out;
}

void McpStreamState::close_sink(const std::shared_ptr<McpStreamSink>& sink, McpStreamClose reason) {
    if (!sink) {
        return;
    }
    sink->set_close_reason(reason);
    {
        // `closed` is the pump's wait PREDICATE, so it must be modified while owning
        // the sink mutex. Storing it atomically without the lock and then notifying is
        // a classic lost wakeup: if the pump has already evaluated the predicate and is
        // about to release-and-block, the notify lands on an empty wait queue and the
        // provider sleeps the full tick. Being atomic does not save you — ownership of
        // the mutex during the modification is what orders it against the wait.
        std::lock_guard<std::mutex> lk(sink->sse->mu);
        sink->sse->closed.store(true);
    }
    sink->sse->cv.notify_all();
}

void McpStreamState::close(McpStreamClose reason) {
    // Only live_ — draining_, if any, is never left unsignaled by this omission: a
    // takeover closes the superseded sink synchronously and unconditionally the
    // moment it becomes draining_ (attach_and_replay's "wake the superseded provider"
    // step, above), so a mid-handover session reaching a caller of close() (gc(),
    // terminate(), shutdown() (#3042)) always has an already-closed draining_ sink.
    // This relies on that invariant holding at every attach site — if a future change
    // ever defers or batches the takeover's own close-signal, this call would need to
    // close draining_ too.
    std::shared_ptr<McpStreamSink> live;
    {
        std::lock_guard<std::mutex> lk(mu_);
        live = live_;
        // The live sink is intentionally NOT cleared: the provider is still running and
        // calls detach() on teardown, which is the single place its lease is returned.
    }
    close_sink(live, reason); // outside mu_ (lock order) — never blocks on I/O
}

void McpStreamState::detach(const std::shared_ptr<McpStreamSink>& sink) {
    if (!sink) {
        return;
    }
    bool was_live = false;
    bool was_draining = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (live_ == sink) {
            live_.reset();
            was_live = true;
        } else if (draining_ == sink) {
            draining_.reset(); // the handover completed — a new takeover may proceed
            was_draining = true;
        }
    }
    if (!was_live && !was_draining) {
        return; // already detached (idempotent — httplib runs the releaser exactly once,
                // but a caller must not be able to corrupt the accounting by re-running it)
    }
    // Release the lease outside mu_ on this path — not because the nesting would be unsafe
    // (attach already establishes mu_ → budget mu_, and StreamBudget never calls back), but
    // because there is no reason to hold a per-stream lock across a global one. Each sink
    // owns its own lease, so this returns exactly the worker THIS provider was pinning. The
    // lease goes home BEFORE the metrics touch — that ordering is what lets every caller
    // treat a throwing metric as ignorable.
    sink->lease.release();
    if (gauge_streams_active_ != nullptr) {
        gauge_streams_active_->decrement();
        if (was_draining) {
            gauge_streams_handover_->decrement();
        }
    }
}

bool McpStreamState::is_pinned_locked(std::uint64_t id) const {
    if (id == 0) {
        return false; // 0 is the empty-slot sentinel and never a valid frame id
    }
    for (const auto slot : pinned_ids_) {
        if (slot == id) {
            return true;
        }
    }
    return false;
}

bool McpStreamState::is_pinned(std::uint64_t id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return is_pinned_locked(id);
}

void McpStreamState::inject_unpin_fault_for_test(UnpinFault fault, int times) {
    std::lock_guard<std::mutex> lk(mu_);
    unpin_fault_ = fault;
    unpin_fault_remaining_ = fault == UnpinFault::kNone ? 0 : times;
}

void McpStreamState::inject_poison_close_fault_for_test(int times) {
    std::lock_guard<std::mutex> lk(mu_);
    poison_close_fault_remaining_ = times;
}

bool McpStreamState::unpin(std::uint64_t id) {
    if (id == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    // TEST SEAM (see UnpinFault). Consumed BEFORE the scan so an armed fault models the
    // failure regardless of whether the id is still pinned - which is the point for
    // kRaceLost, whose whole premise is that another route already cleared it.
    if (unpin_fault_remaining_ > 0) {
        const UnpinFault fault = unpin_fault_;
        if (--unpin_fault_remaining_ == 0) {
            unpin_fault_ = UnpinFault::kNone;
        }
        if (fault == UnpinFault::kThrow) {
            throw std::runtime_error("injected unpin fault");
        }
        if (fault == UnpinFault::kRaceLost) {
            return false;
        }
    }
    for (auto& slot : pinned_ids_) {
        if (slot == id) {
            slot = 0;    // now evictable; a later publish may reclaim its ring space
            return true; // ids are unique - at most one slot holds it
        }
    }
    return false; // already released by another route, or never pinned
}

std::array<std::uint64_t, kMaxStreamedPostsPerSession> McpStreamState::pinned_ids_snapshot()
    const {
    std::lock_guard<std::mutex> lk(mu_);
    return pinned_ids_;
}

std::size_t McpStreamState::pinned_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t n = 0;
    for (const auto slot : pinned_ids_) {
        if (slot != 0) {
            ++n;
        }
    }
    return n;
}

bool McpStreamState::take_poison_close_fault_locked() {
    if (poison_close_fault_remaining_ > 0) {
        --poison_close_fault_remaining_;
        return true;
    }
    return false;
}

void McpStreamState::poison_close_contained(const std::shared_ptr<McpStreamSink>& sink,
                                            bool inject_fault) noexcept {
    // BEST-EFFORT: close_sink's one throw site is the sink's own mutex acquisition (a
    // genuinely broken platform mutex). The poison flag is already durable regardless of
    // what happens here, so a close failure must not escape - it is counted, logged, and
    // left for the next attach's retry rather than silently heart-beating forever (#2531).
    try {
        if (inject_fault) {
            throw std::runtime_error("injected poison-close fault (test seam)");
        }
        close_sink(sink, McpStreamClose::kInternalError);
    } catch (...) {
        try {
            count_poison_close_failed(metrics_);
            spdlog::warn("MCP stream poison [{}]: close of a live/stale sink failed and was "
                         "contained; the client may keep heart-beating until its next attach",
                         log_context_);
        } catch (...) {  // NOLINT(bugprone-empty-catch) — nothing left we could safely do
        }
    }
}

void McpStreamState::poison_terminal() noexcept {
    std::shared_ptr<McpStreamSink> live;
    bool inject_fault = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        terminal_poisoned_ = true; // sticky - every future attach_and_replay 410s
        live = live_;
        inject_fault = take_poison_close_fault_locked();
    }
    // Close any currently-live GET sink honestly rather than leave it heart-beating for a
    // terminal that will never come. Outside mu_ (lock order), like close(). Idempotent:
    // a second poison_terminal() just re-sets the flag and re-closes an already-closed sink.
    poison_close_contained(live, inject_fault);
}

std::uint64_t McpStreamState::current_generation() const {
    std::lock_guard<std::mutex> lk(mu_);
    return generation_;
}

std::uint64_t McpStreamState::next_event_id() const {
    std::lock_guard<std::mutex> lk(mu_);
    return next_id_;
}

std::uint64_t McpStreamState::evictions_total() const {
    std::lock_guard<std::mutex> lk(mu_);
    return evictions_;
}

bool McpStreamState::has_live_sink() const {
    std::lock_guard<std::mutex> lk(mu_);
    return live_ != nullptr;
}

bool McpStreamState::has_draining_sink() const {
    std::lock_guard<std::mutex> lk(mu_);
    return draining_ != nullptr;
}

std::size_t McpStreamState::frame_bytes(const McpStreamEvent& ev) {
    return ev.event_type.size() + ev.data.size();
}

// ── RevalidateGrace ─────────────────────────────────────────────────────────

RevalidateGrace::Outcome RevalidateGrace::on_verdict(StreamRevalidate verdict) {
    switch (verdict) {
    case StreamRevalidate::kRevoked:
        // Authoritative revocation — an immediate kill, no grace.
        return Outcome::kCloseCredentialRevoked;
    case StreamRevalidate::kIndeterminate:
        // The auth backend is unreachable — that is NOT a revocation. Ride it out for a bounded
        // grace window rather than cutting every live stream on the fleet at the same instant.
        // The deadline carries a per-stream jitter chosen ONCE here (Config::jitter_max).
        if (!grace_deadline_.has_value()) {
            // #2367: the budget is measured from the last AUTHORITATIVE confirmation, not from
            // this tick. A credential re-check served from a cache (kValidStale below) keeps the
            // stream alive without re-confirming anything, so starting the clock here would let
            // cache residency and the grace window ADD — the stream rides the cache, then
            // collects a full fresh grace window on top. Backdating keeps total survival past a
            // real confirmation bounded by `grace`, however much of it was spent on cached
            // answers.
            grace_start_ = last_authoritative_ok_;
            std::chrono::milliseconds jitter{0};
            if (cfg_.jitter_max.count() > 0) {
                // A per-stream offset in [0, jitter_max]. thread_local RNG seeded once per worker;
                // non-cryptographic — this only decorrelates timers, it guards nothing.
                static thread_local std::minstd_rand rng{static_cast<std::uint32_t>(
                    std::chrono::steady_clock::now().time_since_epoch().count())};
                // The modulo is done in the int64 (chrono::rep) domain and the span is clamped to
                // a sane ceiling FIRST. If the knob ever becomes operator-controlled, a raw
                // static_cast<uint32>(count()) + 1 could wrap to 0 (div-by-zero) on a 32-bit
                // result_type, or silently truncate a > UINT32_MAX-ms value. Contain it here.
                constexpr std::int64_t kMaxJitterMs = 3600 * 1000; // one hour is plenty
                const std::int64_t span =
                    std::min<std::int64_t>(cfg_.jitter_max.count(), kMaxJitterMs);
                jitter = std::chrono::milliseconds{static_cast<std::int64_t>(rng()) % (span + 1)};
            }
            grace_deadline_ = *grace_start_ + cfg_.grace + jitter;
        }
        // Expiry is tested below, after the switch (kValidStale can clear a deadline, so the test
        // must run once the verdict is known, not inline here).
        break;
    case StreamRevalidate::kValid:
        // An AUTHORITATIVE confirmation: the store was asked and answered.
        last_authoritative_ok_ = now();
        clear_grace_deadline_();
        break;
    case StreamRevalidate::kValidStale:
        // Valid, but nothing was asked of the store on this tick — the answer came from a cache
        // with a known maximum age. Advance the floor: without using the cache entry (positive
        // evidence the store confirmed this principal within max_staleness),
        // last_authoritative_ok_ would only refresh on the tick that happens to MISS. A principal
        // with several concurrent streams refreshes the shared entry from whichever stream ticks
        // first, so every OTHER stream would ride cached answers far longer than the TTL and then
        // face a deadline already in the past the instant the store blipped: zero grace, all at
        // once. Clamping to now - max_staleness bounds that to one cache window per stream and
        // can only ever move the floor FORWARD (never past now), so it cannot extend a life.
        // Then CLEAR the deadline exactly as kValid does — a cache hit is as much a confirmation
        // as a read-through (the entry cannot exist unless an authoritative read succeeded within
        // the window, and a revoke erases it synchronously). Leaving a deadline armed here was
        // the round-1 defect: two streams on one principal, the outage ends, the first re-reads
        // and warms the shared entry, and the second then rides hits with an outage-era deadline
        // still counting down — closing auth_unavailable against a reachable store and an Active
        // principal, contradicting CH-4's recovered-backend invariant.
        if (cfg_.max_staleness.count() > 0) {
            last_authoritative_ok_ = std::max(last_authoritative_ok_, now() - cfg_.max_staleness);
        }
        clear_grace_deadline_();
        break;
    default:
        // Fail CLOSED on an enumerator this state machine does not know, matching
        // auth_routes.cpp's `return R::kRevoked` fall-out: falling out of the switch would leave
        // the stream RUNNING on an auth answer nobody interpreted.
        return Outcome::kCloseAuthUnavailable;
    }

    // Fire a backdated kIndeterminate deadline on its OWN arming tick. Only the kIndeterminate arm
    // leaves a deadline armed past this point (kValid and kValidStale both cleared it above); its
    // deadline is backdated to last_authoritative_ok_, so it can already be in the past when first
    // armed, and the pre-#2367 "arm now, test next tick" shape would grant an extra tick of life
    // to a stream whose budget was already spent.
    if (grace_deadline_.has_value() && now() > *grace_deadline_) {
        return Outcome::kCloseAuthUnavailable;
    }
    return Outcome::kContinue;
}

// ── McpStreamPump ───────────────────────────────────────────────────────────

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive)
    : McpStreamPump(std::move(sink), std::move(stream), generation, std::move(revalidate),
                    std::move(session_alive), Config{}, {}, nullptr) {}

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive, Config cfg, ClockFn clock,
                             yuzu::MetricsRegistry* metrics)
    : sink_(std::move(sink)), stream_(std::move(stream)), generation_(generation),
      revalidate_(std::move(revalidate)), session_alive_(std::move(session_alive)), cfg_(cfg),
      metrics_(metrics), clock_(clock),
      // The grace policy owns the clock + the #2367 last-authoritative seed (attach already
      // authenticated the request fully before this pump exists).
      //
      // BOTH copy the by-value parameter, deliberately. Seeding `grace_` from `clock_`
      // instead would still depend on `clock_` being DECLARED first - and would turn a
      // future member reorder from "silently empty clock" into reading an UNCONSTRUCTED
      // std::function, which is UB. `-Wreorder` cannot warn when the declarations and the
      // mem-init list move together. One extra std::function copy per GET stream (not per
      // pass) buys order-independence outright.
      grace_(RevalidateGrace::Config{cfg.revalidate_grace, cfg.revalidate_grace_jitter_max,
                                     cfg.revalidate_max_staleness},
             clock) {
    // SEED the first check a full tick out rather than leaving the epoch default. Attach has
    // just authenticated this request end to end, so an immediate re-check would be a
    // redundant store round trip; and an epoch default would make the first wait budget zero,
    // turning pass one into an instant no-op.
    next_check_ = (clock_ ? clock_() : std::chrono::steady_clock::now()) + cfg_.tick;
}

bool McpStreamPump::finish(const WriteFn& write, McpStreamClose reason) {
    sink_->set_close_reason(reason);
    const McpStreamClose actual = sink_->close_reason.load();
    count_stream_close(metrics_, actual);

    // A SUPERSEDED stream gets no final frame — deliberately. The client already has a
    // newer stream on this session, so the only thing that can be waiting on the far
    // end of this socket is the stalled peer that caused the takeover in the first
    // place; writing to it would block this worker for the full write timeout (30 s)
    // while its lease is still charged. kCompleted likewise writes NO close frame — the
    // streamed-POST pump delivers its real final then EOFs, and a close frame after a
    // successful final would be a spurious second terminal (this makes the documented
    // "kCompleted never produces a close frame" invariant structural, not just a comment;
    // the GET pump never sets kCompleted, so this is forward-proofing for C6c/C7). Every
    // other reason gets the frame.
    if (actual != McpStreamClose::kSuperseded && actual != McpStreamClose::kCompleted) {
        // Decision 15(f): a close is never indistinguishable from a clean completion, and the
        // reason is machine-parseable in the same A4 shape as every denial on this route (so a
        // client has ONE error contract, not two). PENDING 2 (2f PR 3b): the frame is now a
        // JSON-RPC-wrapped `notifications/yuzu.stream_closed` under the default `message` event
        // type, so it is a normal message on the stream rather than a bespoke `event:
        // stream-closed` a spec client would not see. Off-ring, id-less (SseEvent default id 0).
        const auto cid = yuzu::server::detail::make_correlation_id();
        (void)write_all(write, sse_bus::format_sse(sse_bus::SseEvent{
                                   "message", make_stream_closed_frame(actual, cid)}));
    }
    return false;
}

bool McpStreamPump::pump_once(const WriteFn& write) {
    // HARD exception boundary. httplib invokes a chunked content provider from a bare
    // ThreadPool task — `routing()` is inside its try/catch, this is NOT — so an
    // escaped exception here is std::terminate, not a 500 (the #2037 failure class).
    // Everything below can throw: revalidate_() reaches SQLite and the auth manager,
    // and every frame build allocates.
    try {
        return pump_once_impl(write);
    } catch (...) {
        // `set_close_reason` is the ONLY thing here that cannot throw (an atomic CAS on a
        // member that already exists) — and it is the one thing that must happen, so an
        // internal fault is not audited as a client disconnect and the operator does not
        // go looking at the client for our bug.
        sink_->set_close_reason(McpStreamClose::kInternalError);
        // EVERYTHING else in this handler allocates: MetricsRegistry::counter() inserts a
        // map node on first use, and spdlog's formatter builds a string. We are here
        // because something threw — quite possibly bad_alloc — and a throw from inside a
        // catch handler propagates straight out of pump_once into an unguarded httplib
        // ThreadPool task, i.e. std::terminate. That is the exact hole this boundary
        // exists to close, so the best-effort part gets its own net.
        try {
            count_stream_close(metrics_, McpStreamClose::kInternalError);
            spdlog::warn("MCP stream pump: aborting stream after an exception");
        } catch (...) {  // NOLINT(bugprone-empty-catch) — nothing left we could safely do
        }
        return false; // httplib still runs the releaser → detach() → the lease comes back
    }
}

bool McpStreamPump::pump_once_impl(const WriteFn& write) {
    std::deque<sse_bus::SseEvent> drained;
    std::uint64_t dropped = 0;
    std::optional<sse_bus::SseEvent> pre_emit;
    {
        std::unique_lock<std::mutex> lk(sink_->sse->mu);
        // Bounded by whichever comes FIRST: a full tick, or the instant the next credential
        // check falls due. Waiting a fresh FULL tick from each WAKE is the trap: this pump is
        // woken by every publication, so a wake landing just before the boundary would push
        // the re-check out to nearly TWO ticks and silently double the revocation bound that
        // Decision 15(c)/CH-4 promises. Frequent wakes are harmless - each re-tests the gate;
        // the bad case is ONE wake just before the boundary followed by silence.
        //
        // `ceil`, not `duration_cast`: flooring a sub-millisecond remainder to a zero budget
        // returns instantly and re-enters, spinning out heartbeat frames until real time
        // crosses. Rounding up overshoots by at most 1ms, which the bound absorbs.
        //
        // Sampled INSIDE the lock: a contended acquisition would otherwise size the wait from
        // a stale reading and overshoot the deadline it is meant to respect.
        const auto now_before = clock_ ? clock_() : std::chrono::steady_clock::now();
        const auto until_check =
            next_check_ > now_before
                ? std::chrono::ceil<std::chrono::milliseconds>(next_check_ - now_before)
                : std::chrono::milliseconds{0};
        sink_->sse->cv.wait_for(lk, std::min(cfg_.tick, until_check), [this] {
            // dropped_total is in the predicate (#2366): a producer-side containment can
            // bump dropped_total WITHOUT enqueueing a frame (the by-value copy threw after
            // the ring commit), so `queue.empty()` alone would keep the synthetic waiting a
            // full tick. Before #2366 every drop rode alongside a real push_back, so this
            // case could not arise. The bump is done UNDER this sink mutex (see the
            // publish() containment catch), so this is a proper condvar handoff — a waiter
            // cannot check the predicate false and miss the bump, and the publish's
            // notify_one wakes it deterministically rather than on the next tick.
            return !sink_->sse->queue.empty() || sink_->sse->closed.load() ||
                   sink_->sse->pre_emit.has_value() ||
                   sink_->sse->dropped_total.load(std::memory_order_relaxed) > 0;
        });
        if (sink_->sse->closed.load()) {
            lk.unlock();
            // Reason was set by whoever closed us (takeover, DELETE, GC); if the
            // sink was closed without one, the peer went away.
            return finish(write, McpStreamClose::kClientGone);
        }
        if (sink_->sse->pre_emit.has_value()) {
            pre_emit = std::move(*sink_->sse->pre_emit);
            sink_->sse->pre_emit.reset();
        }
        drained.swap(sink_->sse->queue);
        dropped = sink_->sse->dropped_total.exchange(0, std::memory_order_relaxed);
    }
    // Everything below runs WITHOUT the sink mutex: a stalled socket write must
    // never block a publisher (which would hold McpStreamState::mu_ and in turn
    // stall attach/close for this session).

    // Credential re-validation, once per tick (Decision 15(c)/(i), CH-4). The grace state
    // machine (revoke = immediate kill, indeterminate = bounded jittered grace, stale-cache floor
    // clamp) lives in RevalidateGrace so the streamed-POST pump shares it byte-for-byte (2f PR
    // 3b); this pump owns only the wire action taken on its verdict.
    // PER TICK, not per wake - which is what the line above has always claimed. This pump is
    // woken by every published frame, so running these two here unconditionally meant a full
    // auth-store round trip AND a session-registry validate_and_touch PER FRAME. The latter
    // walks every session under one global mutex, so the cost was O(sessions) per frame on
    // the busiest surface in the product. The DRAIN below still runs on every wake; only the
    // store round trips ride the tick.
    const auto now_tp = clock_ ? clock_() : std::chrono::steady_clock::now();
    const bool tick_due = now_tp >= next_check_;
    if (tick_due) {
        next_check_ = now_tp + cfg_.tick;
    }
    if (tick_due && revalidate_) {
        switch (grace_.on_verdict(revalidate_())) {
        case RevalidateGrace::Outcome::kCloseCredentialRevoked:
            stream_->close(McpStreamClose::kCredentialRevoked);
            return finish(write, McpStreamClose::kCredentialRevoked);
        case RevalidateGrace::Outcome::kCloseAuthUnavailable:
            stream_->close(McpStreamClose::kAuthUnavailable);
            return finish(write, McpStreamClose::kAuthUnavailable);
        case RevalidateGrace::Outcome::kContinue:
            break;
        }
    }

    // Session liveness. This is also the TTL slide: a genuinely-live stream keeps
    // its session young, so the registry's idle GC needs no live-stream exemption
    // (and a zombie peer stops ticking, so the normal TTL reclaims it).
    if (tick_due && session_alive_ && !session_alive_()) {
        return finish(write, McpStreamClose::kSessionTerminated);
    }

    // Takeover fence: a newer GET owns this session's stream now.
    if (generation_ != stream_->current_generation()) {
        return finish(write, McpStreamClose::kSuperseded);
    }

    // Did this pass put anything real on the wire? If so the heartbeat below is redundant -
    // the connection has just proved itself live.
    bool wrote_frame = false;
    if (pre_emit.has_value()) {
        wrote_frame = true;
        if (!write_all(write, sse_bus::format_sse(*pre_emit))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }
    if (dropped > 0) {
        // Frames were dropped before reaching this connection. Tell the client — a silent
        // gap is the one thing this channel must never produce. But do NOT promise a replay
        // we may not be able to honour: the ring and the sink share a cap, so a consumer
        // slow enough to overflow the queue has usually also fallen out of the replay
        // window, and its reconnect will be answered with a 404 + re-initialize rather than
        // the frames it lost. Say both.
        // Cause-neutral by design (#2366): dropped_total now has two producers — the common
        // slow-consumer queue overflow AND a rare producer-side post-commit allocation
        // fault — and the pump cannot tell them apart from the count alone. The reason must
        // not assert "slow consumer" for a fault it cannot prove; the server-side WARN
        // distinguishes the rare case. Recovery is identical either way, so the client
        // needs the gap + the remediation, not the cause.
        // Field names match the `/api/v1/events` sibling's synthetic (dropped_count +
        // reason) — one taxonomy, not a per-route format.
        const sse_bus::SseEvent ev{
            "events-dropped",
            "{\"dropped_count\":" + std::to_string(dropped) +
                ",\"reason\":\"one or more frames were dropped before reaching this "
                "connection\""
                ",\"remediation\":\"reconnect with Last-Event-ID; if the replay window has "
                "also passed you will get a 404 — re-initialize, durable results remain "
                "fetchable by execution_id\"}"};
        if (metrics_ != nullptr) {
            metrics_->counter(kMetricFramesDropped).increment(static_cast<double>(dropped));
        }
        wrote_frame = true;
        if (!write_all(write, sse_bus::format_sse(ev))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }
    for (const auto& ev : drained) {
        wrote_frame = true;
        // The id rides on the frame (SseEvent::id) — it is NOT parsed back out of the
        // payload. Re-parsing put a throwing stoull inside this callback, which httplib
        // runs on an unguarded worker task.
        // Ring frames carry an `id:` (SseEvent::id, emitted by the shared formatter) so a
        // broken stream can resume; heartbeats and synthetics carry none — resuming onto
        // a heartbeat's id would skip real frames.
        if (!write_all(write, sse_bus::format_sse(ev))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }

    // Only when this pass wrote NOTHING. The heartbeat exists to stop an intermediary
    // idling a quiet connection out, and a pass that just delivered real frames has already
    // done that - so a heartbeat alongside them is pure filler.
    //
    // This became load-bearing with the per-tick gate above. Previously every pass paid a
    // contended global-registry acquisition, which accidentally rate-limited this loop; with
    // that gone, a continuously-published stream re-enters bounded only by the socket write,
    // and an unconditional heartbeat would multiply wire frames on exactly the busiest
    // streams. Removing an accidental throttle means the thing it was throttling has to
    // become deliberate.
    if (wrote_frame) {
        return true;
    }
    static constexpr std::string_view kHeartbeat = "event: heartbeat\ndata: \n\n";
    if (!write_all(write, kHeartbeat)) {
        return finish(write, McpStreamClose::kClientGone);
    }
    return true;
}

// ── McpPostPump ─────────────────────────────────────────────────────────────

McpPostPump::McpPostPump(std::shared_ptr<sse_bus::SseSinkState> sink, TakeBatchFn take_batch,
                         FinalWrittenFn on_final_written,
                         std::function<StreamRevalidate()> revalidate,
                         std::function<bool()> session_alive)
    : McpPostPump(std::move(sink), std::move(take_batch), std::move(on_final_written),
                  std::move(revalidate), std::move(session_alive), Config{}) {}

McpPostPump::McpPostPump(std::shared_ptr<sse_bus::SseSinkState> sink, TakeBatchFn take_batch,
                         FinalWrittenFn on_final_written,
                         std::function<StreamRevalidate()> revalidate,
                         std::function<bool()> session_alive, Config cfg, ClockFn clock,
                         yuzu::MetricsRegistry* metrics, std::string correlation_id,
                         std::string execution_id)
    : sink_(std::move(sink)),
      take_batch_(std::move(take_batch)),
      on_final_written_(std::move(on_final_written)),
      revalidate_(std::move(revalidate)),
      session_alive_(std::move(session_alive)),
      cfg_(cfg),
      metrics_(metrics),
      correlation_id_(std::move(correlation_id)),
      execution_id_(std::move(execution_id)),
      clock_(std::move(clock)),
      grace_(RevalidateGrace::Config{cfg.revalidate_grace, cfg.revalidate_grace_jitter_max,
                                     cfg.revalidate_max_staleness},
             clock_) {
    // The cap deadline is stamped at CONSTRUCTION, not on the first tick: the
    // clock starts when the response is created, so a pump that never gets
    // scheduled cannot silently extend its own budget.
    deadline_ = (clock_ ? clock_() : std::chrono::steady_clock::now()) + cfg_.cap;
}

bool McpPostPump::finish(const WriteFn& write, McpStreamClose reason) {
    // BEFORE the count, and before anything else that can throw: the releaser
    // audits whatever this records, so a metric mutex failure here must not let
    // the pump_once catch below overwrite the real reason with kInternalError.
    // First-wins, because the first reason is the true cause; a later one is a
    // consequence of it.
    note_close_reason(reason);
    // Backstop. The bridge already flips `closed` at the DECISION point for the
    // endings it knows about (a final handed back, or a settled cap), which is what
    // keeps a mid-tick cancel from claiming a detach it did not perform. This covers
    // the endings the bridge never sees - revocation, session death, a dead peer, an
    // internal fault - and is idempotent for the ones it does. Must stay AFTER the
    // unlock above: on the kCancelled path the sink mutex is non-recursive.
    mark_sink_closed();
    count_stream_close(metrics_, reason);
    // kCompleted EOFs after a real final: a close frame there would be a second,
    // contradictory terminal on a stream that already answered. Same rule the GET
    // pump applies, and the reason that arm was written before this producer
    // existed.
    if (reason != McpStreamClose::kCompleted) {
        std::string extra;
        try {
            // The durable handle, so a client closed by cap/revocation/session
            // death knows what to fetch. Values are escaped - make_stream_closed_
            // frame takes a RAW fragment by contract.
            if (!execution_id_.empty()) {
                extra = R"(,"execution_id":)" + mcp::detail::json_quoted(execution_id_) +
                        R"(,"partial":true)";
            }
            (void)write_all(write, sse_bus::format_sse(sse_bus::SseEvent{
                                       "message",
                                       make_stream_closed_frame(reason, correlation_id_, extra)}));
        } catch (...) {  // NOLINT(bugprone-empty-catch)
            // A close frame we could not build is not worth terminating over; the
            // response ends either way and the result stays durably fetchable.
        }
    }
    return false;
}

bool McpPostPump::pump_once(const WriteFn& write) {
    // HARD noexcept boundary - httplib runs providers on a bare ThreadPool task,
    // outside its routing try/catch, so an escaped throw is std::terminate
    // (#2037's class). Mirrors McpStreamPump::pump_once, including the nested
    // guard: the handler itself allocates.
    try {
        const bool keep_open = pump_once_impl(write);
        if (!keep_open) {
            mark_sink_closed();
        }
        return keep_open;
    } catch (...) {
        // Recorded FIRST, before the fallible metric/log calls - this is the one
        // close path that never reaches finish(), so without it the releaser would
        // read kNone, normalise to client_gone, and audit a disconnect for what was
        // actually an internal failure. First-wins keeps a real earlier reason.
        note_close_reason(McpStreamClose::kInternalError);
        mark_sink_closed();
        try {
            count_stream_close(metrics_, McpStreamClose::kInternalError);
            spdlog::warn("MCP streamed-POST pump: tick failed, closing the response");
        } catch (...) {  // NOLINT(bugprone-empty-catch)
        }
        return false;
    }
}

void McpPostPump::mark_sink_closed() noexcept {
    // Publishes "this response is over" into the flag the BRIDGE reads, on EVERY
    // path that ends the response - the normal finishes, and the catch above.
    //
    // Without it, `closed` tracked only "someone asked to cancel" rather than
    // liveness, and the bridge's cancel interlock is that flag: in the window
    // between this pump returning false and httplib running the releaser (which is
    // what actually parks the record), a cancel would still find kStreaming, a
    // bound sink and closed==false, win the exchange, and audit "detached the
    // streamed response" for a response that had already ended as completed,
    // cap_expired or client_disconnect. An audit row that overstates an outcome is
    // worse than a missing one. Mirrors McpStreamState::close on the GET channel,
    // which sets the same flag for the same reason.
    //
    // Under the sink mutex, like every other write to `closed` - the pump's own
    // wait predicate reads it, and ownership of the mutex during the modification
    // is what orders the two.
    try {
        {
            std::lock_guard<std::mutex> lk(sink_->mu);
            sink_->closed.store(true, std::memory_order_release);
        }
        sink_->cv.notify_all();
    } catch (...) {  // NOLINT(bugprone-empty-catch)
        // pump_once is a hard noexcept boundary; a lock failure here costs a
        // late cancel one possibly-inaccurate audit row, never the process.
    }
}

void McpPostPump::note_close_reason(McpStreamClose reason) noexcept {
    auto expected = McpStreamClose::kNone;
    close_reason_.compare_exchange_strong(expected, reason, std::memory_order_acq_rel,
                                          std::memory_order_relaxed);
}

McpStreamClose McpPostPump::close_reason() const noexcept {
    return close_reason_.load(std::memory_order_acquire);
}

bool McpPostPump::pump_once_impl(const WriteFn& write) {
    // Sampled BEFORE the wait, and used ONLY to size it. The gate below needs the
    // post-wait instant and must re-sample: testing a pre-wait sample against
    // `next_check_` would be false by construction after waiting for exactly that
    // deadline, and the credential check would never fire at all.
    const auto now_before_wait = clock_ ? clock_() : std::chrono::steady_clock::now();
    {
        std::unique_lock<std::mutex> lk(sink_->mu);
        // The queue is NOT a source of frames here - the bridge is - but `closed`
        // and the projector's poke both arrive through this mutex, so this is the
        // wait. The timeout is also the backstop for a poke that raced the wait.
        //
        // Bounded by whichever comes FIRST: a full tick, or the instant the next
        // credential check falls due. Waiting a fresh full tick from each WAKE is
        // what a poke-driven pump must NOT do: a poke landing at
        // `next_check_ - eps` wakes it, finds the check not yet due, and then
        // waits another whole tick - pushing the re-check to ~2 ticks after the
        // previous one and silently doubling the one-tick revocation bound that
        // Decision 15(c) / CH-4 and the class comment above both promise.
        // Counter-intuitively FREQUENT pokes are harmless (each wake re-tests the
        // gate); the bad case is ONE poke just before the boundary then silence,
        // which is precisely why a poke-driven test did not catch it.
        // ceil, NOT duration_cast. duration_cast FLOORS, so a remainder under 1ms
        // became a zero budget: the wait returned instantly, the post-wait sample
        // was still short of `next_check_`, the pass fell through to the
        // unconditional heartbeat write at the bottom, and httplib re-entered - a
        // tight spin emitting heartbeat frames at the client until real time
        // crossed the boundary. Bounded to under a millisecond, but it is a burst
        // of wire traffic per affected tick on every streamed response, and this
        // fleet's standing bar is to be kind to the network. Rounding UP can
        // overshoot the check by at most 1ms, which the one-tick bound absorbs.
        const auto until_check =
            next_check_ > now_before_wait
                ? std::chrono::ceil<std::chrono::milliseconds>(next_check_ - now_before_wait)
                : std::chrono::milliseconds{0};
        sink_->cv.wait_for(lk, std::min(cfg_.tick, until_check), [this] {
            return sink_->closed.load() || sink_->poked.load(std::memory_order_acquire);
        });
        // Consumed under the same lock that set it, so a poke arriving during this
        // tick is not lost - it simply wakes the next wait immediately.
        sink_->poked.store(false, std::memory_order_release);
        if (sink_->closed.load()) {
            // UNLOCK FIRST. finish() writes the close frame to the socket, bounded
            // only by the server's write timeout, and takes the metrics mutex on the
            // way. Holding sink-mu across that stalls every other thread that needs
            // this sink - and because the projector's poke takes sink-mu while
            // holding rec-mu, and the sweep takes rec-mu while holding bridge_mu_,
            // one peer that stops reading becomes a bridge-wide outage. Every link
            // is in the sanctioned lock order, so TSan never sees a cycle.
            //
            // NOTHING that writes, allocates, or takes another mutex may run under
            // sink_->mu. The GET pump has always obeyed this ("a stalled socket
            // write must never block a publisher"); this one did not until now.
            lk.unlock();
            return finish(write, McpStreamClose::kCancelled);
        }
    }

    // Credential re-validation and the session TTL touch are PER-TICK, not per wake.
    // The poke now wakes this pump on every publication, and both of these are store
    // round trips (the api-token cache and the session registry) - letting them ride
    // the wake would scale auth load with the fleet's progress-frame rate instead of
    // the 3s tick, which is the opposite of what #2367's caching exists to achieve.
    // The DRAIN below still runs on every wake; that is the part that makes progress
    // feel immediate.
    const auto now_tp = clock_ ? clock_() : std::chrono::steady_clock::now();
    const bool tick_due = now_tp >= next_check_;
    if (tick_due) {
        next_check_ = now_tp + cfg_.tick;
    }
    if (tick_due && revalidate_) {
        switch (grace_.on_verdict(revalidate_())) {
            case RevalidateGrace::Outcome::kCloseCredentialRevoked:
                return finish(write, McpStreamClose::kCredentialRevoked);
            case RevalidateGrace::Outcome::kCloseAuthUnavailable:
                return finish(write, McpStreamClose::kAuthUnavailable);
            case RevalidateGrace::Outcome::kContinue:
                break;
        }
    }
    // Also the TTL slide, exactly as on the GET channel.
    if (tick_due && session_alive_ && !session_alive_()) {
        return finish(write, McpStreamClose::kSessionTerminated);
    }

    // Reuses the post-wait sample above rather than taking a third: the cap and the
    // credential gate are meant to read the same instant, and a fake clock that
    // advances per call would otherwise consume the cap at twice the rate.
    const bool cap_expired = now_tp >= deadline_;

    // The cap is ARBITRATED BY THE BRIDGE, inside the projection claim: a terminal
    // that latched in the same instant wins over an expired cap, because closing
    // with kCapExpired while a real result sits latched would send the client
    // polling for an answer the server is holding.
    McpStreamBridge::PostBatch batch;
    if (take_batch_) {
        batch = take_batch_(cap_expired);
    }

    // The bridge is the only side that can tell "nothing yet" from "nothing ever" -
    // this pump holds just a batch and a clock, and both look identical on an idle
    // tick. Check before draining: a gone record carries no frames to drain anyway.
    if (batch.record_gone) {
        return finish(write, McpStreamClose::kRecordGone);
    }

    for (const auto& frame : batch.progress) {
        // #2785: the replay-ring event id rides the SSE `id:` line (3-arg
        // SseEvent; format_sse omits the line for 0) so a POST-only client can
        // build a `Last-Event-ID` resume cursor from the frames it actually saw.
        if (!write_all(write, sse_bus::format_sse(
                                  sse_bus::SseEvent{"message", frame.data, frame.event_id}))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }

    if (batch.final_frame.has_value()) {
        // The final goes LAST and is followed by EOF - the spec's
        // progress-before-response ordering, which the 3a GET-after-response
        // shape could not provide.
        if (!write_all(write,
                       sse_bus::format_sse(sse_bus::SseEvent{"message", batch.final_frame->data,
                                                             batch.final_frame->event_id}))) {
            return finish(write, McpStreamClose::kClientGone);
        }
        if (on_final_written_) {
            // Contained: this call reaches into the bridge (a lock acquisition
            // that can throw) after the bytes are already on the wire. A throw here
            // must not read back as an internal fault to the client that just
            // received a correct result - note the true reason FIRST (finish's own
            // note_close_reason is first-wins, so this wins the race against
            // pump_once's outer catch), then let the log/counter run in their own
            // nested guard so a fault in THEM cannot un-win it either.
            try {
                on_final_written_();  // before the close, so the record settles kDone
            } catch (...) {
                note_close_reason(McpStreamClose::kCompleted);
                try {
                    count_final_credit_failed(metrics_);
                    spdlog::error("MCP streamed-POST [{}]: final delivered but the bridge "
                                  "credit step threw - session pin not released this way",
                                  correlation_id_);
                } catch (...) {  // NOLINT(bugprone-empty-catch)
                }
            }
        }
        return finish(write, McpStreamClose::kCompleted);
    }

    if (batch.cap_settled) {
        // ONLY the bridge may declare this. A frame-build or write failure above
        // returns kClientGone; stamping kCapExpired for those would poison the
        // closed-reason taxonomy and tell the client to retry on a schedule that
        // has nothing to do with what happened.
        return finish(write, McpStreamClose::kCapExpired);
    }

    static constexpr std::string_view kHeartbeat = "event: heartbeat\ndata: \n\n";
    if (!write_all(write, kHeartbeat)) {
        return finish(write, McpStreamClose::kClientGone);
    }
    return true;
}

// ── GET tail ────────────────────────────────────────────────────────────────

void handle_get_tail(const httplib::Request& req, httplib::Response& res,
                     const std::string& principal, McpSessionRegistry& sessions,
                     sse_bus::StreamBudget* budget, const StreamRevalidateFn& revalidate,
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn,
                     std::size_t per_principal_cap, StreamAuditPrincipal audit_principal,
                     const StreamPrincipalAuditFn& principal_audit_fn) {
    const auto cid = yuzu::server::detail::make_correlation_id();
    const auto audit = [&](const char* action, const char* result, const std::string& target_id,
                           const std::string& detail) {
        return yuzu::server::detail::try_persist_audit(audit_fn, req, action, result, "McpSession",
                                                       target_id, detail);
    };
    const auto deny = [&](int status, int code, std::string_view message, const char* reason,
                          std::string_view remediation, std::optional<std::int64_t> retry_after_ms,
                          const std::string& sid) {
        // Only a prefix of the session id reaches the audit row — enough to join a
        // reject to its stream, never enough to replay it. Sanitized because the id is
        // an attacker-controlled HEADER until it validates: raw bytes here could inject
        // `;`/`=` field separators into a "k=v;k=v" audit detail that SIEM tooling
        // parses (yuzu::server::detail::sanitize_detail_value, the convention for
        // every externally-controlled audit string).
        (void)audit("mcp.session.reject", "failure",
                    yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
                    std::string("reason=") + reason + " cid=" + cid);
        count_reject(metrics, reason);
        res.status = status;
        // Retry-After header alongside the A4 retry_after_ms — the platform 429 convention
        // is BOTH (whole seconds, rounded up), and the three sibling surfaces set it. MCP
        // was the one surface that carried only the body field.
        if (retry_after_ms.has_value() && *retry_after_ms > 0) {
            const auto secs = (*retry_after_ms + 999) / 1000;
            res.set_header("Retry-After", std::to_string(secs));
        }
        res.set_content(error_response_null_a4(code, message, cid, remediation, retry_after_ms),
                        "application/json");
    };

    const std::string sid = req.get_header_value("Mcp-Session-Id");
    if (sid.empty()) {
        deny(400, kInvalidRequest, "Mcp-Session-Id header required", "missing_session_header",
             "initialize first, then send the returned Mcp-Session-Id on GET", std::nullopt, sid);
        return;
    }
    if (sessions.validate_and_touch(sid, principal) != McpSessionRegistry::ValidateResult::kValid) {
        // Unknown / expired / bound to another principal — one answer for all three
        // (no cross-principal existence oracle, Decision 15(a) / CH-8).
        deny(404, kMcpUnknownSession, "Unknown or expired session", "unknown_session",
             "re-initialize to mint a new session", std::nullopt, sid);
        return;
    }
    if (!transport::accept_wants_sse(req.get_header_value("Accept"))) {
        // Fail closed: the GET channel is SSE-only, so an Accept that does not opt
        // in is a client bug, not a reason to guess.
        deny(406, kMcpNotAcceptable, "GET /mcp/v1/ requires Accept: text/event-stream",
             "not_acceptable", "send Accept: text/event-stream", std::nullopt, sid);
        return;
    }

    const std::uint64_t last_event_id =
        parse_last_event_id(req.get_header_value("Last-Event-ID"));

    auto stream = sessions.stream_for(sid, principal);
    if (!stream) {
        deny(404, kMcpUnknownSession, "Unknown or expired session", "unknown_session",
             "re-initialize to mint a new session", std::nullopt, sid);
        return;
    }

    auto attached = stream->attach_and_replay(last_event_id, budget, principal, per_principal_cap);
    if (attached.status == McpStreamState::AttachStatus::kGap) {
        // The cursor's frames are gone. Terminate the session so the client's next
        // POST 404s too — one coherent "re-initialize" signal, and no abandoned
        // session lingering against the session cap.
        (void)sessions.terminate(sid, principal);
        (void)audit("mcp.session.close", "success",
                    yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
                    "reason=replay_window_exceeded cid=" + cid);
        count_reject(metrics, "replay_window_exceeded");
        res.status = 404;
        res.set_content(
            error_response_null_a4(kMcpUnknownSession, "Replay window exceeded", cid,
                                   "re-initialize; durable results remain fetchable by "
                                   "execution_id"),
            "application/json");
        return;
    }
    if (attached.status == McpStreamState::AttachStatus::kStreamCapHit) {
        const char* const cap_reason =
            attached.reject_reason != nullptr ? attached.reject_reason : "global_stream_cap";
        // Name the flag that can ACTUALLY resolve THIS reject. Telling a per-principal
        // reject to raise --max-sse-streams is inert (that is the global cap) and actively
        // misleading — the per-principal knob is --mcp-max-streams-per-principal.
        const bool per_principal =
            std::string_view(cap_reason) == sse_bus::StreamBudget::kRejectPerPrincipal;
        deny(429, kMcpStreamCap, "Concurrent stream cap reached", cap_reason,
             per_principal
                 ? "close one of your own SSE streams, or raise --mcp-max-streams-per-principal"
                 : "close an existing SSE stream, or raise --max-sse-streams",
             kMcpStreamCapRetryAfterMs, sid);
        return;
    }
    if (attached.status == McpStreamState::AttachStatus::kHandoverPending) {
        // A previous stream on this session was superseded and its provider has not
        // torn down yet. Admitting a third would let one client pin providers without
        // bound (each one holds a worker until it drains). Retry shortly — the
        // handover completes as soon as the old provider wakes.
        deny(429, kMcpStreamCap, "A previous stream on this session is still closing",
             "stream_handover_pending", "retry shortly; the superseded stream is draining",
             kMcpHandoverRetryAfterMs, sid);
        return;
    }
    if (attached.status == McpStreamState::AttachStatus::kPoisoned) {
        // A terminal frame could not be delivered on this stream (publish_final failed
        // twice). It will never carry its final, so a re-attach would heart-beat forever -
        // 410 Gone with the durable-fetch remediation, the same honest posture the
        // /api/v1/events terminal path takes. The execution result stays fetchable by
        // execution_id (get_execution_status / query_responses).
        deny(410, kMcpStreamPoisoned, "Stream terminated; final response undeliverable",
             "terminal_poisoned",
             "fetch the result by execution_id (get_execution_status / query_responses); "
             "do not re-POST",
             std::nullopt, sid);
        return;
    }

    auto sink = attached.sink;
    const std::uint64_t generation = attached.generation;

    // From here to set_chunked_content_provider, the sink is attached and its budget
    // lease is HELD, but the releaser that returns it is not installed yet. Everything
    // in between allocates (the Request copy, the pump, the audit strings), so a
    // bad_alloc would unwind out of the handler with the lease held forever: 16 of
    // those and MCP streaming is dead until restart. httplib guarantees the releaser
    // runs once installed (~Response calls it unconditionally) — this guard covers the
    // window before that guarantee starts.
    //
    // The guard is a POD, NOT a std::function: this lambda's captures exceed
    // libstdc++'s 16-byte small-object buffer, so wrapping it would heap-allocate —
    // planting a throw site inside the very window the guard exists to protect.
    struct LeaseGuard {
        McpStreamState* stream;
        const std::shared_ptr<McpStreamSink>* sink;
        bool installed = false;
        ~LeaseGuard() noexcept {
            if (!installed) {
                try {
                    stream->detach(*sink); // returns the lease first, then touches metrics
                } catch (...) {            // NOLINT(bugprone-empty-catch)
                    // detach() allocates (metric name temporaries), and this destructor
                    // runs while UNWINDING — a throw escaping here is a double fault, i.e.
                    // terminate. The lease is already home by then: detach() releases it
                    // before it touches metrics, and Lease's own destructor would return it
                    // regardless.
                }
            }
        }
    };
    LeaseGuard lease_guard{stream.get(), &sink};

    // Audit BEFORE the provider: set_chunked_content_provider seals the headers, so
    // Sec-Audit-Failed can only be set here (the /api/v1/events posture — signal the
    // evidence gap, then proceed; a transient audit hiccup must not silently drop an
    // operator's stream).
    if (!audit("mcp.stream.attach", "success",
               yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
               "cid=" + cid + " last_event_id=" + std::to_string(last_event_id) +
                   " generation=" + std::to_string(attached.generation))) {
        res.set_header("Sec-Audit-Failed", "true");
    }
    res.set_header("X-Correlation-Id", cid);
    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");  // defeat reverse-proxy response buffering
    res.set_header("X-Content-Type-Options", "nosniff");

    // The provider and releaser run inside this request's lifetime, but pinning the
    // headers we re-validate against by copy costs one allocation and removes any
    // question of aliasing httplib's per-connection object across ticks.
    // (Never read req_copy->matches: its smatch iterators alias the ORIGINAL path.)
    auto req_copy = std::make_shared<httplib::Request>(req);
    const std::string audit_sid = yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8));

    auto revalidate_fn = [req_copy, principal, revalidate]() -> StreamRevalidate {
        if (!revalidate) {
            return StreamRevalidate::kValid;  // test seam; production always wires this
        }
        return revalidate(*req_copy, principal);
    };
    // `sessions` is a ServerImpl member; stop() joins the web workers before any member
    // destructs, so no provider can outlive it.
    auto* registry = &sessions;
    auto session_alive = [registry, sid, principal]() {
        return registry->validate_and_touch(sid, principal) ==
               McpSessionRegistry::ValidateResult::kValid;
    };
    // Production config: spread the indeterminate-grace deadline by up to half the grace
    // window per stream, so a PG brownout does not drive the whole fleet's streams to die
    // at the same instant (Config::revalidate_grace_jitter_max — the default is 0 for
    // deterministic unit tests). At the 60 s default this spreads deaths over [60 s, 90 s].
    McpStreamPump::Config pump_cfg{};
    pump_cfg.revalidate_grace_jitter_max = pump_cfg.revalidate_grace / 2;
    // #2367: this surface's revalidate callback may answer from the
    // engine-principal liveness cache, so tell the pump how stale that can be.
    // Without it, a stream whose sibling keeps refreshing the shared cache
    // entry never advances its own authoritative floor and gets zero grace on
    // the first blip.
    pump_cfg.revalidate_max_staleness =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            EnginePrincipalStore::kAuthCacheTtl);
    // The coupling is load-bearing, so pin it at compile time rather than in a
    // comment: an aged cache entry must still leave a usable slice of the grace
    // window. Lowering the grace window or raising the TTL without re-checking
    // this would silently make an outage cut engine streams instantly.
    static_assert(EnginePrincipalStore::kAuthCacheTtl * 4 <= kMcpRevalidateGraceDefault,
                  "engine liveness cache TTL must stay well under the revalidate grace "
                  "window (#2367) - otherwise a fully-aged entry leaves no grace at all");
    auto pump = std::make_shared<McpStreamPump>(sink, stream, generation, std::move(revalidate_fn),
                                                std::move(session_alive), pump_cfg,
                                                McpStreamPump::ClockFn{}, metrics);

    res.set_chunked_content_provider(
        "text/event-stream",
        [pump](std::size_t /*offset*/, httplib::DataSink& s) {
            return pump->pump_once(
                [&s](const char* p, std::size_t n) { return s.write(p, n); });
        },
        // UP-1: adopt any pending engine QuotaSlot into this stream's releaser so the
        // per-principal CONCURRENCY reservation lasts for the stream's real lifetime.
        // `/mcp/v1/` is in is_streaming_path (principal_quota_gate.hpp), so pre-routing
        // stashes a slot in the thread_local and post-routing resets it unconditionally —
        // which fires before the streamed body ever runs. Without this adoption an engine
        // principal's MCP streams are bounded only by StreamBudget's per-principal cap,
        // and the configurable PrincipalQuota concurrency cap is silently bypassed on the
        // one surface it most exists to protect.
        //
        // The composition is re-wrapped in a noexcept guard. Note precisely what that
        // guard does and does not do: it CANNOT catch a throw from `slot->reset()`, and an
        // earlier version of this comment wrongly claimed it could. ~QuotaSlot is
        // implicitly noexcept (every subobject has a non-throwing destructor), so a throw
        // out of PrincipalQuota::release would call std::terminate INSIDE that destructor,
        // two frames within this try — no caller-side handler can intercept it. That path
        // is contained where it must be, at the source: QuotaSlot::reset() and
        // PrincipalQuota::release() are now noexcept by construction. This outer guard is
        // belt-and-braces for the rest of the composition (a bad_function_call, or a throw
        // from adopt_quota_slot_into_stream's own body), which is still worth having
        // because httplib invokes releasers from ~Response (#2037's class).
        [inner = yuzu::server::detail::adopt_quota_slot_into_stream(
             [stream, sink, audit_fn, principal_audit_fn, audit_principal, req_copy, audit_sid,
              cid](bool /*success*/) noexcept {
                // Runs from ~Response — a DESTRUCTOR. An exception escaping here is
                // std::terminate no matter what httplib does, so the whole body is guarded
                // (try_persist_audit swallows its own, but the string building allocates).
                try {
                    stream->detach(sink); // returns this provider's worker to the budget
                    // A teardown that never re-entered the pump leaves close_reason at
                    // kNone — and that is the MODAL case, not an edge one: httplib tests
                    // is_peer_alive() BEFORE invoking the provider, so an ordinary client
                    // disconnect is nearly always observed while the pump sits in its 3 s
                    // condvar wait, not as a failed write inside finish(). Auditing "none"
                    // there would emit a value outside the closed set documented in
                    // observability-conventions.md and pre-seeded in server.cpp, and would
                    // mean the reason vocabulary said nothing about the commonest close.
                    const auto reason = sink->close_reason.load();
                    const auto detail =
                        std::string("reason=") +
                        to_string(reason == McpStreamClose::kNone ? McpStreamClose::kClientGone
                                                                  : reason) +
                        " cid=" + cid + " role_as_of=attach";
                    // STAMP the principal rather than letting the sink re-derive it. The
                    // generic sink resolves the actor from the request when the row is
                    // written, and this row is written at teardown against the ORIGINAL
                    // attach request — so on a `credential_revoked` close the credential no
                    // longer resolves by definition and the row would name nobody. The rows
                    // that prove the revocation control would be exactly the rows missing
                    // their actor (SOC 2 CC6.2/CC7.2). Both values were captured at attach,
                    // while the credential was still good.
                    if (principal_audit_fn) {
                        (void)yuzu::server::detail::try_persist_audit_for_principal(
                            principal_audit_fn, *req_copy, "mcp.stream.close", "success",
                            audit_principal, "McpSession", audit_sid, detail);
                    } else {
                        // Test seams only — production wires the explicit-principal sink.
                        (void)yuzu::server::detail::try_persist_audit(
                            audit_fn, *req_copy, "mcp.stream.close", "success", "McpSession",
                            audit_sid, detail);
                    }
                } catch (...) {
                    // The lease is still returned: detach() is the first call, and Lease's
                    // destructor would return it even if that somehow threw.
                }
             })](bool success) noexcept {
            try {
                inner(success);
            } catch (...) {
                // Nothing to do but contain it — this frame is a destructor's callee.
            }
        });
    // The releaser now owns the lease's return path; the guard stands down.
    lease_guard.installed = true;
}

}  // namespace yuzu::server::mcp
