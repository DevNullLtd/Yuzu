#pragma once

/// @file event_bus.hpp
/// SSE event pub/sub bus for server-side events.
/// Header-only — small enough that a separate TU adds no value.

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <atomic>
#include <cstring>

#include <httplib.h>

#include "stream_budget.hpp"

namespace yuzu::server::detail {

// -- SSE Event ----------------------------------------------------------------

struct SseEvent {
    std::string event_type;
    std::string data;
    /// Optional SSE `id:` for routes that support `Last-Event-ID` resume. 0 = no id
    /// (heartbeats and synthetics carry none — resuming onto a heartbeat's id would
    /// skip real frames). Routes that predate this field packed the id into `data`
    /// as a `"<id>\n<payload>"` prefix and re-parsed it in the provider; carrying it
    /// as a field instead removes a throwing `stoull` from a content-provider
    /// callback, which httplib runs on an UNGUARDED worker task — an escaped
    /// exception there is `std::terminate`, not a 500 (#2037's failure class).
    std::uint64_t id = 0;
};

// -- SSE Event Bus ------------------------------------------------------------

class EventBus {
public:
    using Listener = std::function<void(const SseEvent&)>;

    std::size_t subscribe(Listener fn) {
        std::lock_guard<std::mutex> lock(mu_);
        auto id = next_id_++;
        listeners_[id] = std::move(fn);
        return id;
    }

    void unsubscribe(std::size_t id) {
        std::lock_guard<std::mutex> lock(mu_);
        listeners_.erase(id);
    }

    void publish(const std::string& event_type, const std::string& data) {
        SseEvent ev{event_type, data};
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [id, fn] : listeners_) {
            fn(ev);
        }
    }

    std::size_t listener_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return listeners_.size();
    }

private:
    mutable std::mutex mu_;
    std::size_t next_id_ = 0;
    std::unordered_map<std::size_t, Listener> listeners_;
};

// -- SSE sink state (per-connection, shared with content provider) -------------

/// Default per-connection queue cap, used by routes that opt into slow-
/// consumer protection. A slow / blackholed TCP consumer can otherwise
/// grow `SseSinkState::queue` without bound (publisher runs synchronously
/// under the bus channel mutex, listener enqueues, content provider may
/// not drain for 3 s+ during `wait_for` waits). With ~hundreds of
/// agentic clients per server, an unbounded queue is the primary memory
/// growth risk on this path. 500 events is roughly half of
/// `ExecutionEventBus::kBufferCap` — large enough to absorb a normal
/// burst, small enough that a stalled consumer is dropped before any
/// realistic OOM. governance round unhappy-R3 / sre-OBS-MED.
inline constexpr std::size_t kPerConnectionQueueCapDefault = 500;

struct SseSinkState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<SseEvent> queue;
    std::atomic<bool> closed = false;
    /// The streamed-POST wake signal (2f PR 3b). The POST pump takes its frames
    /// from the BRIDGE, not from `queue`, so `queue` can never satisfy its wait
    /// predicate and a bare `notify_one` on a predicated `wait_for` is a no-op -
    /// the predicate re-evaluates, finds nothing, and sleeps out the full tick.
    /// This is the flag the poke sets and that predicate reads, so a publication
    /// wakes the pump instead of the timeout. Written and cleared under `mu` for
    /// the same reason `closed` is: ownership of the mutex during the change is
    /// what orders it against the wait. Unused by the GET surface.
    std::atomic<bool> poked{false};
    std::size_t sub_id = 0;
    /// Total events dropped before reaching this per-connection queue.
    /// Usually a drop-oldest on cap overflow (a slow consumer); the MCP
    /// stream also feeds it a rare producer-side post-commit enqueue
    /// allocation failure (#2366) — same recovery either way. Routes that
    /// enforce a cap use this counter to emit a synthetic `events-dropped`
    /// envelope on the next provider invocation so the client knows a gap
    /// exists. Routes that do NOT enforce a cap leave this at 0. Atomic so the listener
    /// (publisher thread) and provider (httplib worker thread) can both
    /// touch it without taking `mu`.
    std::atomic<std::uint64_t> dropped_total{0};
    /// Sticky pre-emit slot for a synthetic envelope that MUST reach the
    /// client even under per-connection-queue overflow. Routes set this
    /// during handler setup; the content provider drains it on first
    /// invocation BEFORE the bounded `queue` drain so the synthetic is
    /// never subject to `enqueue_capped`'s drop-oldest eviction. Set
    /// once per connection (or never); `take_pre_emit()` empties the
    /// slot atomically and returns it. governance R2 fix for unhappy
    /// R1-regression — the W5.1 R1 hardening originally pushed the
    /// replay-gap envelope onto `queue`, where a fast publisher could
    /// trigger drop-oldest before the provider emitted the gap warning,
    /// silently restoring the very gap-blindness the synthetic was
    /// meant to fix.
    std::optional<SseEvent> pre_emit;

    /// Take and clear `pre_emit` atomically under the queue mutex.
    /// Returns std::nullopt if no pre-emit was set. Caller writes the
    /// returned event directly to the sink before the queue drain.
    std::optional<SseEvent> take_pre_emit() {
        std::lock_guard<std::mutex> lk(mu);
        if (!pre_emit.has_value())
            return std::nullopt;
        SseEvent ev = std::move(*pre_emit);
        pre_emit.reset();
        return ev;
    }
};

/// Enqueue with drop-oldest cap. Routes that opt into slow-consumer
/// protection call this from their bus listener instead of a raw
/// `queue.push_back`. Lives next to `SseSinkState` so it's directly
/// unit-testable; the `/api/v1/events` handler calls it via a capturing
/// lambda. Holds the per-connection mutex, no condition_variable notify
/// (the caller controls that — replay shouldn't wake the provider).
inline void enqueue_capped(const std::shared_ptr<SseSinkState>& state, SseEvent ev,
                           std::size_t cap = kPerConnectionQueueCapDefault) {
    std::lock_guard<std::mutex> lk(state->mu);
    while (state->queue.size() >= cap) {
        state->queue.pop_front();
        state->dropped_total.fetch_add(1, std::memory_order_relaxed);
    }
    state->queue.push_back(std::move(ev));
}

// -- SSE helpers --------------------------------------------------------------

// Format an SSE message.  The SSE spec requires every line of a multi-line
// data field to carry its own "data: " prefix; the browser's EventSource
// parser re-joins them with '\n'.  Without this, embedded newlines in agent
// output cause silent truncation — only the first line reaches the browser.
inline std::string format_sse(const SseEvent& ev) {
    std::string out;
    // `id:` first, when the route sets one (0 = none). Emitted HERE rather than in a
    // per-route wrapper so that a caller who populates SseEvent::id and reaches for the
    // shared formatter gets the id on the wire instead of having it silently dropped.
    if (ev.id != 0) {
        out += "id: ";
        out += std::to_string(ev.id);
        out += '\n';
    }
    out += "event: ";
    out += ev.event_type;
    out += '\n';
    std::string_view d{ev.data};
    if (d.empty()) {
        out += "data: \n";
    } else {
        std::size_t pos = 0;
        while (pos < d.size()) {
            auto nl = d.find('\n', pos);
            out += "data: ";
            out.append(d.substr(pos, (nl == std::string_view::npos ? d.size() : nl) - pos));
            out += '\n';
            if (nl == std::string_view::npos)
                break;
            pos = nl + 1;
        }
    }
    out += '\n'; // blank line terminates the event
    return out;
}

// -- SSE content provider callback --------------------------------------------

// `budget` is nullable (matches the existing metrics_-pointer convention in
// this file) — a null budget means "no shutdown close-signal available",
// never a crash. #2703 Gate 7 merge-slice item 2: checking `budget->closing()`
// in the SAME predicate the provider already re-evaluates at least every 3s
// (the keep-alive tick) closes an idle stream within one tick on server
// shutdown, with no new cv-plumbing.
inline bool sse_content_provider(const std::shared_ptr<SseSinkState>& state, size_t /*offset*/,
                                 httplib::DataSink& sink, const StreamBudget* budget = nullptr) {
    std::unique_lock<std::mutex> lk(state->mu);
    // Keep the interval well under httplib's Keep-Alive timeout (5s)
    // to prevent the browser from closing the SSE connection due to
    // inactivity.
    state->cv.wait_for(lk, std::chrono::seconds(3), [&state, budget] {
        return !state->queue.empty() || state->closed.load() || (budget && budget->closing());
    });

    if (state->closed.load() || (budget && budget->closing())) {
        return false;
    }

    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = format_sse(ev);
        // httplib's chunked provider assembles each sink.write() into a
        // single HTTP chunk frame (hex-size + CRLF + data + CRLF) and
        // flushes it in one send() call — the browser processes each chunk
        // eagerly.  Write in <=8 KB slices to stay within typical TCP send
        // buffer limits and avoid partial-write failures.
        const char* p = sse.data();
        size_t rem = sse.size();
        constexpr size_t kMaxSlice = 8192;
        while (rem > 0) {
            auto n = std::min(rem, kMaxSlice);
            if (!sink.write(p, n))
                return false;
            p += n;
            rem -= n;
        }
        state->queue.pop_front();
    }

    const char* keepalive = "event: heartbeat\ndata: \n\n";
    if (!sink.write(keepalive, std::strlen(keepalive))) {
        return false;
    }
    return true;
}

/// `noexcept`, and that is STRUCTURAL, not decorative. This is the shared release helper
/// for the legacy `GET /events` SSE surface, and httplib invokes a content-provider
/// releaser from `~Response` — a destructor. An exception escaping here is therefore
/// `std::terminate` (#2037's class), which no caller-side try/catch can intercept because
/// the terminate happens inside the destructor before unwinding reaches any handler. The
/// two throw sites — `std::lock_guard` construction (`std::system_error`, and this PR's
/// lost-wakeup fix is what ADDED it: the store used to be a bare atomic) and
/// `bus.unsubscribe` (locks `mu_`) — are contained AT THE SOURCE, the same way
/// `QuotaSlot::reset` and `StreamBudget::Lease::release` are, so every caller is safe by
/// construction rather than by remembering to wrap the call. The MCP / `/api/v1/events` /
/// dashboard sibling releasers inline their own equivalent guards; this one is shared, so
/// the guard lives in the shared function.
inline void sse_resource_release(const std::shared_ptr<SseSinkState>& state, EventBus& bus,
                                 bool /*success*/) noexcept {
    try {
        // `closed` is the provider's wait PREDICATE, so it must be modified while owning
        // the mutex: a store issued between the provider's predicate check and its atomic
        // release-and-block is a lost wakeup, and the provider then sleeps a full 3 s tick
        // before it notices. Being atomic does not help — ownership of the mutex during
        // the modification is what orders it against the wait.
        std::lock_guard<std::mutex> lk(state->mu);
        state->closed.store(true);
    } catch (...) {
        // A lock that cannot be taken means the sink is already unusable; contain it. A
        // stalled provider is strictly better than aborting the whole process from a
        // destructor.
    }
    // notify/unsubscribe are OUTSIDE the block above on purpose: publishers take the bus
    // mutex and then the sink mutex, so unsubscribing while still holding `state->mu` would
    // invert that order and deadlock. Do not move `unsubscribe` into the block.
    state->cv.notify_all(); // noexcept
    // `unsubscribe` in its OWN try so its throw cannot skip the notify above and cannot
    // escape the destructor. A leaked subscription pins the sink for the process's life —
    // a bounded leak, not a terminate.
    try {
        bus.unsubscribe(state->sub_id);
    } catch (...) {
    }
}

} // namespace yuzu::server::detail
