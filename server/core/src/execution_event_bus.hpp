#pragma once

/// @file execution_event_bus.hpp
///
/// PR 3 — per-execution SSE event bus for live drawer updates.
///
/// Distinct from `detail::EventBus` (global pub/sub keyed only by event_type):
/// `ExecutionEventBus` partitions subscribers by `execution_id` so that one
/// running execution's transitions never spray onto another execution's SSE
/// connections. Each per-execution channel carries its own ring buffer
/// (default 1000 events, ~30 s) so a client that disconnects and reconnects
/// inside the replay window resumes without missing transitions.
///
/// Threading model:
///   - `publish` is called from `ExecutionTracker::update_agent_status`
///     (status writer) and `mark_cancelled` — both synchronous w.r.t. the
///     mutating gRPC writer threads. `publish` therefore must not block.
///   - `subscribe` / `unsubscribe` are called from the SSE handler running
///     on the httplib request thread.
///   - All listeners run under the per-execution mutex; the listener body
///     should be short — typically queue-and-notify on a per-connection
///     `SseSinkState`.
///
/// Bounded memory: per execution, the ring buffer caps at `kBufferCap`
/// entries; old entries are dropped FIFO. When an execution reaches a
/// terminal state, the channel is held for `kRetentionAfterTerminalSec`
/// so a late client can still replay the final transitions, then dropped.
/// `gc_terminal_channels` performs the cleanup; the server calls it on
/// a periodic tick (or on every `publish`, opportunistically).

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

struct ExecutionEvent {
    /// Monotonic id within the per-execution channel — used by
    /// `Last-Event-ID` replay. Stable across reconnects.
    std::uint64_t id{0};
    /// Wall-clock timestamp (epoch ms). Cheap to compute, useful for
    /// the buffer-retention TTL check.
    std::int64_t timestamp_ms{0};
    /// SSE `event:` field. Examples: `agent-transition`,
    /// `execution-progress`, `execution-completed`.
    std::string event_type;
    /// SSE `data:` payload — typically a one-line JSON object.
    std::string data;
};

class ExecutionEventBus {
public:
    using Listener = std::function<void(const ExecutionEvent&)>;
    /// Test seam — replace `std::chrono::system_clock::now()` with a
    /// fake clock so unit tests can advance past `kRetentionAfterTerminalSec`
    /// without `std::this_thread::sleep_for(60s)`. Set to nullptr to
    /// restore real time. governance round qe-S3.
    using ClockFn = std::function<std::int64_t()>;

    /// C5 (#2409): the terminal verdict `unsubscribe_and_visit_terminal` hands to
    /// its callback. `kTerminalKnownLost` means the channel is flagged terminal but
    /// the payload aged out of the buffer - benign; the caller maps it to a
    /// success-shaped fallback, never a synthesized error.
    enum class TerminalVisit { kNeverTerminal, kTerminalBuffered, kTerminalKnownLost };
    /// Operational status of the visit (distinct from the terminal verdict). The
    /// caller MUST fail closed on kAbsentChannel/kInternalError - never infer
    /// kNeverTerminal from them, which would re-open #2409.
    enum class VisitStatus { kVisited, kStaleSub, kAbsentChannel, kInternalError };

    static constexpr std::size_t kBufferCap = 1000;
    static constexpr std::int64_t kRetentionAfterTerminalSec = 60;
    /// Min time between full GC sweeps. Gate `gc_terminal_channels` on
    /// this to amortise the O(channels) cost claimed in the comment but
    /// previously not enforced (governance round perf-B2). Half the
    /// retention window — late enough to not waste CPU, early enough
    /// that drained channels are reclaimed before they pile up.
    static constexpr std::int64_t kMinGcIntervalMs = (kRetentionAfterTerminalSec * 1000) / 2;

    ExecutionEventBus() = default;
    ~ExecutionEventBus() = default;

    ExecutionEventBus(const ExecutionEventBus&) = delete;
    ExecutionEventBus& operator=(const ExecutionEventBus&) = delete;

    /// Install a fake clock for tests. Pass nullptr to restore the
    /// system_clock default. Only safe to call when no publishers /
    /// subscribers are active.
    void set_clock_fn(ClockFn fn) { clock_fn_ = std::move(fn); }

    // ── Observability counters (governance round OBS-3) ──────────────────
    //
    // These are simple atomics that production exposes via a Prometheus
    // gauge/counter scrape — see server.cpp's `register_sse_metrics`. The
    // bus itself doesn't depend on the metrics library so it stays
    // standalone-testable.

    /// Total events evicted from the ring buffer (FIFO drop when
    /// `buffer.size() > kBufferCap`). Increments lock-free relative to
    /// the publisher mutex.
    std::uint64_t events_dropped_total() const noexcept {
        return events_dropped_.load(std::memory_order_relaxed);
    }
    /// Total channels GC'd by `gc_terminal_channels` since process start.
    std::uint64_t gc_channels_total() const noexcept {
        return gc_channels_.load(std::memory_order_relaxed);
    }
    /// Total GC sweeps that ran a full O(channels) inspection (vs the
    /// throttle-skip path).
    std::uint64_t gc_sweeps_total() const noexcept {
        return gc_sweeps_.load(std::memory_order_relaxed);
    }
    /// Total subscribers across all channels. O(channels) snapshot —
    /// intended for /metrics scrape, not hot-path use.
    std::size_t subscribers_total() const;

    /// Subscribe to a per-execution channel. Returns a subscription token
    /// scoped to `execution_id` — tokens from different channels are not
    /// comparable. Listener is invoked synchronously from `publish`.
    std::size_t subscribe(const std::string& execution_id, Listener listener);

    /// Atomically install `listener` AND replay buffered events with `id > since_id` to
    /// it, under a single hold of the channel mutex. Returns the subscription token, as
    /// `subscribe` does.
    ///
    /// Used by both execution SSE routes and the MCP progress bridge to close the
    /// replay-then-subscribe race: a publisher needs the same channel mutex, so nothing
    /// can land in the gap. Each event reaches the listener EXACTLY once - buffered events
    /// came from publishes that completed before this lock was held (the listener missed
    /// their live fan-out) and are delivered by the replay; events published after this
    /// returns get the live fan-out and are past the replay cursor.
    ///
    /// The listener is installed BEFORE the replay on purpose: `listeners.emplace` is the
    /// only allocating step, so doing it first means an insertion failure throws with ZERO
    /// projection side effects (nothing was replayed). The listener MUST be non-throwing
    /// (the bus's standing "short, queue-and-notify" contract): a throw from a replay call
    /// would propagate out with the listener already installed. The 2f progress bridge's
    /// listener is a hard noexcept boundary, satisfying this.
    std::size_t subscribe_and_replay(const std::string& execution_id, std::uint64_t since_id,
                                     Listener listener);

    /// Unsubscribe a token previously returned by `subscribe`. Idempotent;
    /// silently no-ops if the channel or sub_id no longer exists.
    void unsubscribe(const std::string& execution_id, std::size_t sub_id);

    /// C5 (#2409): atomically, under a SINGLE hold of the per-execution channel
    /// mutex - (1) compute a terminal verdict, (2) invoke `f(verdict, ev)` (which
    /// does the record-side claim/latch under ITS OWN lock), (3) erase the listener
    /// IFF `f` returns true (it committed a teardown claim). This is the
    /// linearization point that closes #2409: because `publish` fans out under the
    /// same channel mutex, no terminal can slip between the verdict and the claim.
    ///
    /// Erase-only-on-claim is load-bearing: every DEFER (`f` returns false) KEEPS
    /// the listener, so an unclaimed terminal-bearing channel can never go
    /// listener-less and be GC'd out from under the record.
    ///
    /// `f` contract (caller-enforced, NOT checkable here): takes only ITS record
    /// mutex; MUST NOT call any ExecutionEventBus method (it runs UNDER Channel::mu;
    /// a bus call taking `map_mu_` would invert the `map_mu_ -> Channel::mu` order
    /// publish/GC rely on). It returns `true` iff it claimed. `f` need NOT be
    /// `noexcept` - the call is inside this method's try/catch, so a throw becomes
    /// `kInternalError` (fail-closed); a `noexcept` `f` would instead terminate on a
    /// record-lock failure before that catch is reached. `f` MUST make its only
    /// uncontained throw-site its initial record-lock acquisition (before any
    /// mutation) and contain any payload copy internally, so `kInternalError` still
    /// means "record untouched" == "`f` did not run", never "ran then threw".
    ///
    /// The verdict scan keys ONLY on `first_terminal_id` (the FIRST terminal-flagged
    /// event - which in the `refresh_counts` split is a terminal-flagged
    /// `execution-progress`, NOT `execution-completed`; a type scan would
    /// misclassify). A marker miss (aged out past `kBufferCap`) is
    /// `kTerminalKnownLost` -> the caller's safe success-shaped fallback; we do NOT
    /// recover a later buffered `execution-completed`, which could be a spurious
    /// terminal (#2409 UP-1). `ev` points into the channel buffer, valid only for
    /// the `f` call.
    ///
    /// Returns `kAbsentChannel` (no channel -> no barrier) WITHOUT running `f`, or
    /// `kInternalError` (a lock/alloc threw - in the wrapped body OR propagated out
    /// of `f` per the contract above); `kStaleSub` (channel present, sub_id already
    /// gone) still runs `f` - a stale sub means a prior visit ran and `f`'s
    /// record-state-first checks make the re-run idempotent.
    template <class F>
    VisitStatus unsubscribe_and_visit_terminal(const std::string& execution_id,
                                               std::size_t sub_id, F&& f) noexcept {
        try {
            auto ch = find(execution_id);
            if (!ch) return VisitStatus::kAbsentChannel;
            std::lock_guard<std::mutex> g(ch->mu);
            TerminalVisit verdict = TerminalVisit::kNeverTerminal;
            const ExecutionEvent* ev = nullptr;
            if (ch->terminal) {
                // The ONLY scan: the FIRST terminal-flagged event, by id. NOT an
                // event-type scan (the marker's target is a terminal-flagged
                // execution-progress in the refresh_counts split; a completed-type
                // scan misclassifies). If the marker aged out we deliberately do NOT
                // recover a later buffered execution-completed: one present after the
                // marker evicted is more likely a spurious LATER terminal (a
                // mark_cancelled on the same id) than the real one (#2409 UP-1) and
                // would build a WRONG final. kTerminalKnownLost -> the caller's
                // success-shaped fallback ("fetch by execution_id") is always safe:
                // the durable execution result is authoritative.
                for (const auto& e : ch->buffer) {
                    if (e.id == ch->first_terminal_id) {
                        ev = &e;
                        break;
                    }
                }
                verdict = ev != nullptr ? TerminalVisit::kTerminalBuffered
                                        : TerminalVisit::kTerminalKnownLost;
            }
            const bool sub_present = ch->listeners.find(sub_id) != ch->listeners.end();
            // f runs after every throwing step (find/lock/scan); its return is the
            // sole erase trigger. f may throw ONLY at its initial record-lock (before
            // any mutation); the catch below maps that to kInternalError.
            const bool claimed = f(verdict, ev);
            if (claimed) {
                ch->listeners.erase(sub_id);  // noexcept (erase by key)
            }
            return sub_present ? VisitStatus::kVisited : VisitStatus::kStaleSub;
        } catch (...) {
            return VisitStatus::kInternalError;
        }
    }

    /// Publish an event onto a per-execution channel. Assigns a monotonic
    /// id, appends to the ring buffer (evicting the oldest if at cap),
    /// then fans out to listeners under the channel mutex.
    ///
    /// `is_terminal` marks the execution as having reached completion;
    /// the channel keeps the buffer for `kRetentionAfterTerminalSec` so
    /// late reconnects can replay, then is GC'd on next sweep.
    ///
    /// The event id is the per-channel counter, assigned in PUBLISH order under
    /// the channel mutex — buffer order == id order, so a `Last-Event-ID`
    /// reconnect never skips an undelivered event (HA WS-2a-2 Option A: the
    /// durable event_outbox.event_id is deliberately NOT the live bus id — see
    /// the publish body). The HA cross-replica poll re-publishes foreign events
    /// through this same path, so they too get a monotonic local counter id.
    void publish(const std::string& execution_id, const std::string& event_type,
                 const std::string& data, bool is_terminal = false);

    /// Replay buffered events with `id > since_id` in arrival order.
    /// Used by the SSE handler on connect when the client supplied a
    /// `Last-Event-ID` header. The walk runs under the channel mutex
    /// to keep the replay consistent with concurrent publishers.
    void replay_since(const std::string& execution_id, std::uint64_t since_id,
                      const Listener& listener) const;

    /// Snapshot of ring-buffer contents — used by tests to assert
    /// retention/eviction behaviour. Cheap O(N) copy.
    std::vector<ExecutionEvent> snapshot(const std::string& execution_id) const;

    /// Number of active subscribers on a given channel. Returns 0 for
    /// unknown executions. Safe to call concurrently with publish.
    std::size_t subscriber_count(const std::string& execution_id) const;

    /// Number of distinct execution channels currently held in memory.
    std::size_t channel_count() const;

    /// Drop channels that reached terminal state more than
    /// `kRetentionAfterTerminalSec` ago AND have no live subscribers.
    /// Returns the number of channels collected. Called opportunistically
    /// from `publish` so callers don't need to wire a periodic timer.
    std::size_t gc_terminal_channels();

private:
    struct Channel {
        mutable std::mutex mu;
        std::uint64_t next_id{1};
        std::deque<ExecutionEvent> buffer;
        std::unordered_map<std::size_t, Listener> listeners;
        std::size_t next_sub_id{0};
        bool terminal{false};
        std::int64_t terminal_at_ms{0};
        /// C5 (#2409): id of the FIRST terminal-flagged event, set atomically with
        /// the `terminal` flag flip under `mu`. Names the exact terminal event so a
        /// consumer need not event-type-search - which would misclassify, because
        /// `refresh_counts` flags an `execution-progress` terminal before publishing
        /// `execution-completed` (two publishes, `mu` released between). 0 until the
        /// first terminal. Consumed by `unsubscribe_and_visit_terminal`.
        std::uint64_t first_terminal_id{0};
    };

    /// Returns the channel pointer, allocating it if missing. The shared
    /// channel map mutex is held only briefly; callers then take the
    /// per-channel `mu` for the actual work.
    std::shared_ptr<Channel> get_or_create(const std::string& execution_id);

    /// Lookup-only — returns nullptr if the channel is absent.
    std::shared_ptr<Channel> find(const std::string& execution_id) const;

    /// Member function rather than static so tests can inject a fake
    /// clock via `set_clock_fn` (qe-S3). Falls back to `system_clock`
    /// when no override is installed.
    std::int64_t now_ms() const {
        if (clock_fn_) return clock_fn_();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    mutable std::shared_mutex map_mu_;
    std::unordered_map<std::string, std::shared_ptr<Channel>> channels_;

    // GC throttle (perf-B2). Updated under `map_mu_` write lock when a
    // sweep actually runs; read lock-free on the publish hot path.
    std::atomic<std::int64_t> last_gc_at_ms_{0};

    // OBS-3 counters. Atomic so we don't need to extend the per-channel
    // mutex into accountancy.
    std::atomic<std::uint64_t> events_dropped_{0};
    std::atomic<std::uint64_t> gc_channels_{0};
    std::atomic<std::uint64_t> gc_sweeps_{0};

    // Test-clock seam.
    ClockFn clock_fn_;
};

} // namespace yuzu::server
