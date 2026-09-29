// MCP GET SSE channel — replay ring, stream budget, and pump lifecycle
// (ADR-1005 Decision 15, track 2f PR 2). Maps to the P0 chaos scenarios this
// rung must carry: CH-2 (ring wrap + resume), CH-3 (per-session id namespace),
// CH-4 (revocation vs auth-backend outage), CH-5 (cap exhaustion), CH-6
// (worker-pool budget math).
//
// Everything here drives McpStreamState / McpStreamPump / StreamBudget directly:
// the pump takes a WriteFn rather than an httplib::DataSink precisely so the
// stream lifecycle is testable without an httplib acceptor thread (#438).

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <type_traits>

#include "../../../server/core/src/mcp_session.hpp"
#include "../../../server/core/src/mcp_stream.hpp"
#include "../../../server/core/src/stream_budget.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp> // parse the JSON-RPC-wrapped close frame (2f PR 3b)

#include <atomic>
#include <chrono>
#include <future> // the two-thread handshake test parks the pump on another thread
#include <string>
#include <string_view>
#include <thread>
#include <utility> // std::declval — the publish() noexcept static_assert
#include <vector>

namespace mcp = yuzu::server::mcp;
namespace detail = yuzu::server::detail;

namespace {

/// Captures everything the pump writes, so a test can assert on the wire bytes.
struct FakeWire {
    std::string out;
    bool alive = true;

    mcp::McpStreamPump::WriteFn writer() {
        return [this](const char* p, std::size_t n) {
            if (!alive) {
                return false; // simulate a dead peer
            }
            out.append(p, n);
            return true;
        };
    }

    bool contains(std::string_view needle) const { return out.find(needle) != std::string::npos; }
};

mcp::McpStreamPump::Config fast_cfg(std::chrono::milliseconds grace = std::chrono::seconds(60)) {
    mcp::McpStreamPump::Config cfg;
    cfg.tick = std::chrono::milliseconds(10); // don't sleep 3 s in a unit test
    cfg.revalidate_grace = grace;
    return cfg;
}

} // namespace

// ── StreamBudget (CH-5, CH-6) ───────────────────────────────────────────────

TEST_CASE("StreamBudget: per-principal cap rejects the newcomer, never a live lease",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 10}};
    constexpr std::size_t kPerPrincipal = 2;

    auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    REQUIRE(a.lease);
    REQUIRE(b.lease);

    auto c = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    CHECK_FALSE(c.lease);
    CHECK(std::string(c.reject_reason) == detail::StreamBudget::kRejectPerPrincipal);
    // The two live leases are untouched — a cap hit denies the new stream, it does
    // not tear down streams that were already admitted.
    CHECK(budget.active_for(detail::SseSurface::kMcpGet, "alice") == 2);
    CHECK(a.lease);
    CHECK(b.lease);

    // A different principal is unaffected by alice's cap.
    auto d = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    CHECK(d.lease);
    CHECK(budget.active() == 3);
}

TEST_CASE("StreamBudget: global cap rejects across principals", "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 2}};
    constexpr std::size_t kPerPrincipal = 8;
    auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    REQUIRE(a.lease);
    REQUIRE(b.lease);

    auto c = budget.try_acquire(detail::SseSurface::kMcpGet, "carol", kPerPrincipal);
    CHECK_FALSE(c.lease);
    CHECK(std::string(c.reject_reason) == detail::StreamBudget::kRejectGlobal);
}

TEST_CASE("StreamBudget: a lease returns its slot exactly once", "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 1}};
    constexpr std::size_t kPerPrincipal = 1;
    {
        auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
        REQUIRE(a.lease);
        CHECK(budget.active() == 1);
        a.lease.release();
        CHECK(budget.active() == 0);
        a.lease.release(); // idempotent — the destructor must not double-release
        CHECK(budget.active() == 0);
    }
    CHECK(budget.active() == 0);
    // Slot is genuinely free again.
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    CHECK(b.lease);
}

TEST_CASE("StreamBudget: the per-principal map is bounded by LIVE principals",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 100}};
    constexpr std::size_t kPerPrincipal = 1;
    for (int i = 0; i < 50; ++i) {
        auto lease = budget.try_acquire(detail::SseSurface::kMcpGet, "principal-" + std::to_string(i), kPerPrincipal);
        CHECK(lease.lease);
    } // each lease dies here
    // A per-principal entry that never erased at zero would leave 50 rows behind
    // for 50 principals that have long since disconnected.
    CHECK(budget.active() == 0);
    CHECK(budget.active_for(detail::SseSurface::kMcpGet, "principal-7") == 0);
}

TEST_CASE("StreamBudget: kMcpPost is an independent surface — its per-principal cap does not "
          "ration the GET surface, and vice versa (2f PR 3b)",
          "[mcp][stream][ch5][2f]") {
    // The metric label for the new streamed-POST surface.
    CHECK(std::string(detail::to_string(detail::SseSurface::kMcpPost)) == "mcp_post");

    detail::StreamBudget budget{{.global_cap = 100}};
    // Fill alice's streamed-POST allowance to the per-principal cap.
    std::vector<detail::StreamBudget::Lease> posts;
    for (std::size_t i = 0; i < detail::kPerPrincipalMcpPost; ++i) {
        auto r = budget.try_acquire(detail::SseSurface::kMcpPost, "alice", detail::kPerPrincipalMcpPost);
        REQUIRE(r.lease);
        posts.push_back(std::move(r.lease));
    }
    // One more streamed POST for alice is rejected on the per-principal cap...
    auto over = budget.try_acquire(detail::SseSurface::kMcpPost, "alice", detail::kPerPrincipalMcpPost);
    CHECK_FALSE(over.lease);
    CHECK(std::string(over.reject_reason) == detail::StreamBudget::kRejectPerPrincipal);
    // ...but her GET streams are a separate (surface, principal) key, so a GET admits.
    auto get = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", mcp::kMcpStreamsPerPrincipalDefault);
    CHECK(get.lease);
    CHECK(budget.active_for(detail::SseSurface::kMcpPost, "alice") == detail::kPerPrincipalMcpPost);
    CHECK(budget.active_for(detail::SseSurface::kMcpGet, "alice") == 1);
}

TEST_CASE("derive_stream_budget: caps are clamped to what the worker pool can spare",
          "[mcp][stream][ch6]") {
    // Each permitted stream must be able to pin kMaxProvidersPerStream (2) workers —
    // a takeover leaves the superseded provider draining while its replacement runs —
    // so the affordable count is (pool - reserve) / 2, not (pool - reserve).
    // Smallest pool httplib will ever hand us: base 8 → max 32. (32-8)/2 = 12.
    CHECK(detail::derive_stream_budget(32, 8, 16) == 12);
    CHECK(detail::derive_stream_budget(32, 8, 8) == 8); // under the affordable count: honoured
    // An operator asking for more than the pool can spare gets clamped, not obeyed.
    CHECK(detail::derive_stream_budget(32, 8, 64) == 12);
    CHECK(detail::derive_stream_budget(64, 8, 64) == 28);
    // Degenerate pools cannot spare anything — streams are refused rather than
    // allowed to eat the plain-REST reserve.
    CHECK(detail::derive_stream_budget(8, 8, 16) == 0);
    CHECK(detail::derive_stream_budget(4, 8, 16) == 0);
    CHECK(detail::derive_stream_budget(0, 8, 16) == 0);
    // The floor on --http-worker-threads must ITSELF afford at least one stream, so
    // streaming cannot be silently disabled by a knob that reads like a tuning
    // parameter. Asserted UNSCALED: the old form multiplied the floor by 4, modelling
    // httplib's retired "base 8 grows to max 32" behaviour. The pool is now pinned
    // (pool_base == pool_max), so that factor was fiction — and it hid a real dead
    // zone, because the floor was 8, kPlainRestReserveDefault is 8, and (8-8)/2 == 0.
    CHECK(detail::derive_stream_budget(detail::kMinHttpWorkerThreads,
                                       detail::kPlainRestReserveDefault, 16) > 0);
    // Sweep every pinned value an operator could plausibly pass: each is clamped up to
    // the floor first, so none of them may yield a zero budget. This is the regression
    // guard — `--http-worker-threads 8` used to 429 every streaming surface server-wide.
    for (std::size_t pinned = 1; pinned <= 32; ++pinned) {
        const std::size_t pool = std::max(pinned, detail::kMinHttpWorkerThreads);
        INFO("pinned --http-worker-threads=" << pinned << " -> pool " << pool);
        CHECK(detail::derive_stream_budget(pool, detail::kPlainRestReserveDefault, 16) > 0);
    }
}

// The Lease's ownership contract, pinned at compile time. A copyable lease would
// double-release and silently inflate capacity; a throwing release runs from a
// destructor on the teardown path and would be std::terminate. Neither failure is
// reachable by a sanitizer, so a static_assert is the only guard that holds.
static_assert(!std::is_copy_constructible_v<detail::StreamBudget::Lease>,
              "StreamBudget::Lease must be move-only — a copy double-releases");
static_assert(!std::is_copy_assignable_v<detail::StreamBudget::Lease>,
              "StreamBudget::Lease must be move-only — a copy double-releases");
static_assert(std::is_nothrow_destructible_v<detail::StreamBudget::Lease>,
              "~Lease runs from an httplib releaser inside ~Response");

// ── Replay ring + resume (CH-2, CH-3) ───────────────────────────────────────

TEST_CASE("McpStreamState: event ids are per-session and start at 1 (CH-3)",
          "[mcp][stream][ch3]") {
    mcp::McpStreamState a;
    mcp::McpStreamState b;

    CHECK(a.publish("message", "one") == 1);
    CHECK(a.publish("message", "two") == 2);
    // A second session's namespace is independent — ids are NEVER global, so a
    // client resuming session B with an id it saw on session A cannot be served
    // another session's frames.
    CHECK(b.publish("message", "other") == 1);
    CHECK(a.next_event_id() == 3);
    CHECK(b.next_event_id() == 2);
}

TEST_CASE("McpStreamState: a fresh attach replays only the frames after the cursor (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state;
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "frame-" + std::to_string(i));
    }

    auto attached = state.attach_and_replay(/*last_event_id=*/3, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    REQUIRE(attached.sink);

    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 2); // 4 and 5 only — no duplicates
    // The id rides on the frame, not packed into the payload (a stringly-typed id
    // meant re-parsing it inside the content provider, where a throw is terminate).
    CHECK(attached.sink->sse->queue.front().id == 4);
    CHECK(attached.sink->sse->queue.front().data == "frame-4");
    CHECK(attached.sink->sse->queue.back().id == 5);
    CHECK(attached.sink->sse->queue.back().data == "frame-5");
}

TEST_CASE("McpStreamState: cursor 0 replays the whole surviving window (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state{/*ring_cap=*/3};
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "f" + std::to_string(i));
    }
    CHECK(state.evictions_total() == 2); // 1 and 2 evicted

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    CHECK(attached.sink->sse->queue.size() == 3); // whatever the ring still holds
}

TEST_CASE("McpStreamState: a cursor past the ring window is a GAP, not a silent skip (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state{/*ring_cap=*/2};
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "f" + std::to_string(i));
    }
    // Ring holds 4,5. A client resuming from 1 missed 2 and 3, which are GONE. The
    // only honest answers are "here is your gap" or "re-initialize"; we take the
    // latter, and the caller turns it into a 404.
    CHECK(state.attach_and_replay(1, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    CHECK(state.attach_and_replay(2, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    // The boundary cursor (the frame right before the oldest we still hold) IS
    // serviceable — everything after it survives.
    CHECK(state.attach_and_replay(3, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kAttached);
}

TEST_CASE("McpStreamState: a bogus future cursor takes the same path as an evicted one",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state;
    state.publish("message", "only");
    // A client claiming an id we have never issued is not resumable either. Same
    // recovery (re-initialize), and crucially the SAME answer — so the response
    // cannot be used to probe how many events a session has emitted.
    CHECK(state.attach_and_replay(99, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
}

TEST_CASE("McpStreamState: a nonzero cursor fronting a NON-contiguous surviving suffix is a GAP, "
          "not a silent skip over frames evicted behind a pinned final (#2435)",
          "[mcp][stream][ch2][2f]") {
    // A shared session ring interleaves frames from concurrent streamed POSTs: an early
    // request's final is PINNED (eviction-exempt, Decision 15(f)) while a later request keeps
    // publishing progress and wraps the ring, evicting the UNPINNED frames between the pinned
    // final and the newest. The surviving suffix then has a hole the replay loop would skip.
    mcp::McpStreamState state{/*ring_cap=*/4};
    for (int i = 1; i <= 4; ++i)
        state.publish("message", "p" + std::to_string(i)); // ids 1..4
    const auto final_id = state.publish_final("message", "final-A"); // id 5, pinned
    REQUIRE(final_id == 5);
    for (int i = 6; i <= 10; ++i)
        state.publish("message", "p" + std::to_string(i)); // ids 6..10

    // Ring is now [5(pinned), 8, 9, 10]: 1..4 and 6,7 were evicted; 5 survives because pinned.
    REQUIRE(state.pinned_count() == 1);
    REQUIRE(state.is_pinned(5));

    // A resume from cursor 4 would replay 5 and then JUMP to 8 — a silent Last-Event-ID gap
    // where 6,7 used to be. #2435: that is a kGap (client re-initializes and fetches the final
    // by execution_id), not a skip. Checked before any mutation, so a fresh state each time.
    CHECK(state.attach_and_replay(4, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    // Cursor 5 (client already acked the pinned final) still fronts the 6,7 hole -> kGap.
    CHECK(state.attach_and_replay(5, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    // Cursor 7 fronts a CONTIGUOUS surviving suffix (8,9,10) -> serviceable.
    CHECK(state.attach_and_replay(7, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kAttached);

    // Cursor 0 is UNAFFECTED by the contiguity gate: a fresh client explicitly takes whatever
    // the ring still holds (no resume contract), so the hole is tolerated and it replays the
    // whole surviving window [5, 8, 9, 10].
    auto fresh = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(fresh.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(fresh.sink->sse->mu);
    std::vector<std::uint64_t> ids;
    for (const auto& ev : fresh.sink->sse->queue)
        ids.push_back(ev.id);
    CHECK(ids == std::vector<std::uint64_t>{5, 8, 9, 10});
}

TEST_CASE("McpStreamState: a live sink receives published frames", "[mcp][stream]") {
    mcp::McpStreamState state;
    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state.publish("message", "live-frame");
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 1);
    CHECK(attached.sink->sse->queue.front().id == 1);
    CHECK(attached.sink->sse->queue.front().data == "live-frame");
}

// ── Takeover + budget interaction (CH-5) ────────────────────────────────────

TEST_CASE("McpStreamState: a takeover is admitted at a full cap but is still COUNTED (CH-5)",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 1}};
    constexpr std::size_t kPerPrincipal = 1;
    mcp::McpStreamState state;

    auto first = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(first.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(budget.active() == 1);

    // The budget is full. A reconnect on the SAME session must still succeed: the
    // common second GET is a client re-attaching across a zombie TCP the server has
    // not noticed yet, and making it wait for its own zombie to time out would turn
    // the cap into a self-inflicted lockout.
    auto second = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(second.generation > first.generation);

    // …but it takes its OWN lease. The superseded provider goes on pinning its worker
    // until it drains, and an UNCOUNTED pinned worker is exactly the hole the budget
    // exists to close: with lease inheritance, one client hammering GET on one session
    // could exhaust the pool while the gauge still read 1.
    CHECK(budget.active() == 2);

    // The superseded sink is closed with a reason the old provider will report.
    CHECK(first.sink->sse->closed.load());
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);
    CHECK(state.has_draining_sink());

    // Each sink returns its own worker.
    state.detach(first.sink);
    CHECK(budget.active() == 1);
    CHECK_FALSE(state.has_draining_sink());

    state.detach(second.sink);
    CHECK(budget.active() == 0);
}

TEST_CASE("McpStreamState: a second takeover is refused while the handover is pending (CH-5)",
          "[mcp][stream][ch5]") {
    // This is what BOUNDS the pool. A takeover skips the cap check, so without this
    // rule a client could hammer GET on one session and pin providers without limit —
    // each superseded one still holds a worker until it drains, and a peer with a
    // closed TCP window can stall that for the whole write timeout.
    detail::StreamBudget budget{{.global_cap = 100}};
    constexpr std::size_t kPerPrincipal = 100;
    mcp::McpStreamState state;

    auto first = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(first.status == mcp::McpStreamState::AttachStatus::kAttached);
    auto second = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);

    // `first` has not detached yet, so the session already has its one draining sink.
    auto third = state.attach_and_replay(0, &budget, "alice");
    CHECK(third.status == mcp::McpStreamState::AttachStatus::kHandoverPending);
    CHECK_FALSE(third.sink);
    CHECK(budget.active() == 2); // never more than kMaxProvidersPerStream per session

    // Once the superseded provider drains, a takeover is allowed again.
    state.detach(first.sink);
    auto fourth = state.attach_and_replay(0, &budget, "alice");
    CHECK(fourth.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(budget.active() == 2);
}

TEST_CASE("McpStreamState: closing a sink wakes its pump immediately, not a tick later",
          "[mcp][stream][race]") {
    // Regression for a lost wakeup: `closed` is the pump's wait PREDICATE, so it must
    // be modified while holding the sink mutex. Storing it atomically outside the lock
    // and then notifying races the pump's release-and-block — the notify lands on an
    // empty wait queue and the provider sleeps the FULL tick. That is not just latency:
    // the superseded provider keeps pinning a worker for the whole 3 s.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump::Config cfg;
    cfg.tick = std::chrono::seconds(30); // a wakeup that RELIES on the tick would hang
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; }, cfg};

    std::atomic<bool> returned{false};
    FakeWire wire;
    std::thread pumper([&] {
        pump.pump_once(wire.writer());
        returned.store(true);
    });

    // Give the pump time to reach its wait, then close.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    state->close(mcp::McpStreamClose::kSessionTerminated);
    pumper.join();

    CHECK(returned.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
}

TEST_CASE("McpStreamState: a cap hit rejects the attach and leaves the ring intact",
          "[mcp][stream][ch5]") {
    // Global headroom to spare, so the PER-PRINCIPAL cap is the only constraint
    // that binds — and the reject reason must name that one, not the global cap it
    // is nowhere near (an operator raising the wrong knob fixes nothing).
    detail::StreamBudget budget{{.global_cap = 8}};
    constexpr std::size_t kPerPrincipal = 1; // the surface's own anti-monopoly policy
    mcp::McpStreamState busy;
    auto held = busy.attach_and_replay(0, &budget, "alice", kPerPrincipal);
    REQUIRE(held.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamState other;
    auto rejected = other.attach_and_replay(0, &budget, "alice", kPerPrincipal);
    CHECK(rejected.status == mcp::McpStreamState::AttachStatus::kStreamCapHit);
    CHECK(std::string(rejected.reject_reason) == detail::StreamBudget::kRejectPerPrincipal);
    CHECK_FALSE(rejected.sink);
    CHECK_FALSE(other.has_live_sink());
    CHECK(held.sink->close_reason.load() == mcp::McpStreamClose::kNone); // untouched
}

// ── Pump: heartbeats, revocation, grace window (CH-4) ───────────────────────

TEST_CASE("McpStreamPump: a pass that delivers frames sends no redundant heartbeat",
          "[mcp][stream]") {
    // CONTRACT CHANGE. This pass used to emit a heartbeat alongside the frames. The
    // heartbeat exists only to stop an intermediary idling a QUIET connection out, and a
    // pass that just delivered real frames has already proved the connection live - so the
    // extra frame was filler.
    //
    // It became worth removing when re-validation moved onto the tick: every pass used to
    // pay a contended global-registry acquisition, which accidentally rate-limited this
    // loop to roughly one pass per tick. Without that throttle a continuously-published
    // stream re-enters bounded only by the socket write, so an unconditional heartbeat
    // would multiply wire frames on exactly the busiest streams.
    auto state = std::make_shared<mcp::McpStreamState>();
    state->publish("message", R"({"ok":true})");
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));

    // The frame carries its id (that is what makes Last-Event-ID resume possible)…
    CHECK(wire.contains("id: 1\n"));
    CHECK(wire.contains("event: message\n"));
    CHECK(wire.contains(R"(data: {"ok":true})"));
    // …and no heartbeat rides along with it.
    CHECK_FALSE(wire.contains("event: heartbeat\n"));
}

TEST_CASE("McpStreamPump: an idle pass still sends the anti-idle heartbeat", "[mcp][stream]") {
    // The other half of the contract above: with nothing to deliver, the heartbeat is the
    // only thing keeping an intermediary from idling the connection out, so it must still
    // go. It deliberately carries no id - resuming onto a heartbeat's id would skip real
    // frames.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));

    CHECK(wire.contains("event: heartbeat\n"));
    CHECK_FALSE(wire.contains("id: "));
}

TEST_CASE("McpStreamPump: credential revalidation is once per TICK, not once per wake",
          "[mcp][stream][tickgate]") {
    // THE DEFECT. The comment at the revalidate site has always read "Credential
    // re-validation, once per tick". It was not. The pump's wait predicate wakes on every
    // PUBLISHED FRAME (a producer notifies under the sink mutex), so a busy stream ran a
    // full auth-store round trip AND a session-registry `validate_and_touch` per frame.
    // `validate_and_touch` walks every session under one global registry mutex, so the cost
    // is O(sessions) per frame, fleet-wide, on the surface agentic workers hammer hardest.
    //
    // The tick is the contract (Decision 15(c)/(i), CH-4). The DRAIN must still run on
    // every wake - that is what makes progress feel immediate - but the two store round
    // trips belong on the tick, which is what the comment already promised.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    int revalidations = 0;
    int liveness_checks = 0;
    auto now = std::chrono::steady_clock::now();
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::seconds(30); // long: a second check can only come from the gate
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&] {
                                ++revalidations;
                                return mcp::StreamRevalidate::kValid;
                            },
                            [&] {
                                ++liveness_checks;
                                return true;
                            },
                            cfg,
                            [&] { return now; }};
    FakeWire wire;

    // Five wakes well inside one tick. Each publish makes the predicate true on arrival,
    // so the pump never actually sleeps - exactly the busy-stream shape.
    for (int i = 0; i < 5; ++i) {
        state->publish("message", "frame-" + std::to_string(i));
        REQUIRE(pump.pump_once(wire.writer()));
    }
    CHECK(revalidations == 0); // pre-fix: 5
    CHECK(liveness_checks == 0);
    for (int i = 0; i < 5; ++i) { // ...while every frame still went out immediately
        CHECK(wire.contains("frame-" + std::to_string(i)));
    }

    // Cross the boundary and the check fires - the bound is a tick, not a suppression.
    now += cfg.tick;
    state->publish("message", "past-the-boundary");
    REQUIRE(pump.pump_once(wire.writer()));
    CHECK(revalidations == 1);
    CHECK(liveness_checks == 1);
}

TEST_CASE("McpStreamPump: the first pass does not re-validate - next_check_ is seeded, not epoch",
          "[mcp][stream][tickgate]") {
    // A default-constructed time_point is the steady_clock EPOCH, so an unseeded
    // `next_check_` makes the check due on the very FIRST pass: a redundant auth round trip
    // immediately after attach already authenticated the request, and - worse - a zero wait
    // budget, turning pass one into an instant no-op. That exact defect shipped on an
    // earlier attempt at this fix and silently invalidated the test certifying the wake
    // path, so it gets its own assertion rather than being caught incidentally.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    int revalidations = 0;
    const auto frozen = std::chrono::steady_clock::now();
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::milliseconds(10);
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&] {
                                ++revalidations;
                                return mcp::StreamRevalidate::kValid;
                            },
                            [] { return true; },
                            cfg,
                            [&] { return frozen; }};
    FakeWire wire;
    REQUIRE(pump.pump_once(wire.writer()));
    CHECK(revalidations == 0); // pre-fix (epoch default): 1
}

TEST_CASE("McpStreamPump: a sub-millisecond remainder waits rather than spinning",
          "[mcp][stream][tickgate]") {
    // `ceil`, not `duration_cast`. Flooring a remainder under 1ms to a zero budget makes
    // wait_for return immediately; the pass then falls through to the heartbeat write and
    // the caller re-enters, spinning frames at the client until real time crosses the
    // boundary. A zero-budget wait_for is NOT free - it is a real futex syscall.
    //
    // Asserted as a LOWER bound AMPLIFIED over many passes: a single-call floor would be
    // defeated by a loaded runner inflating the buggy path past the threshold, which is how
    // a sibling assertion was found to be unfalsifiable. 100 passes are ~100ms when the wait
    // is honoured and a few ms when it is floored, so load would have to inflate the buggy
    // path more than tenfold to cross the 50ms floor and produce a false pass (margin
    // widened from 20 passes / 10ms after two external reviewers judged that thin on a
    // saturated CI box).
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    auto now = std::chrono::steady_clock::now();
    const auto base = now;
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::seconds(5);
    mcp::McpStreamPump pump{attached.sink,      state, attached.generation,
                            {},                 [] { return true; }, cfg,
                            [&] { return now; }};
    FakeWire wire;

    // 500us short of the check: ceil rounds the budget up to 1ms, floor would make it 0.
    now = base + cfg.tick - std::chrono::microseconds(500);
    const auto started = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; ++i) {
        REQUIRE(pump.pump_once(wire.writer()));
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed >= std::chrono::milliseconds(50)); // ~100ms honoured; a few ms floored
}

TEST_CASE("McpStreamPump: pass one owes no store round trip - the ctor seeds the check deadline",
          "[mcp][stream][tickgate]") {
    // FAST-RED GUARD for the epoch-seed regression (#2730 review). Leaving next_check_
    // at its default leaves it at the steady_clock EPOCH, which is in the past for any
    // real reading: the first wait budget floors to zero, the pass returns instantly
    // and re-enters, and the suite SPINS. It was found that way - as a >10-minute hang
    // rather than a failed assertion - and a hang is a far worse diagnostic for whoever
    // hits it next than a named red.
    //
    // So this asserts the SEMANTIC property the seed exists for, not a timing floor:
    // attach has just authenticated this request end to end, so pass one owes neither
    // store round trip. One pass, no wall-clock dependence, and it reddens the moment
    // the seed goes. The frozen clock is what makes it exact - `now` never advances, so
    // nothing else can put the gate in the future: the two writers of `gate_` are the
    // ctor's seed and the per-tick advance, and the frozen clock pins the latter.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    const auto base = std::chrono::steady_clock::now();
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::milliseconds(20);  // the honoured wait IS this test's whole cost
    int checks = 0;
    int liveness = 0;
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&] { ++checks; return mcp::StreamRevalidate::kValid; },
                            [&] { ++liveness; return true; },
                            cfg,
                            [&] { return base; }};
    FakeWire wire;
    REQUIRE(pump.pump_once(wire.writer()));  // the stream stays open either way
    // Unseeded, `base >= epoch` is true and BOTH tick-gated round trips fire on the
    // pass that was supposed to owe neither - so both halves of the gate are pinned,
    // not just the credential one.
    CHECK(checks == 0);
    CHECK(liveness == 0);
}

TEST_CASE("McpStreamPump: the wait is bounded by the next check, so the tick cannot stretch",
          "[mcp][stream][tickgate]") {
    // The trap that this exact fix fell into once already, on the abandoned branch: gating
    // the checks on a deadline while still waiting a FRESH FULL TICK from each wake. A wake
    // arriving just before the boundary then pushed the next check out to nearly TWO ticks,
    // silently doubling the revocation bound the gate was supposed to preserve.
    //
    // Counter-intuitively, frequent wakes are harmless - each re-tests the gate. The bad
    // case is ONE wake just before the boundary followed by silence, which is what a stream
    // that emits a burst and then goes quiet does.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    auto now = std::chrono::steady_clock::now();
    const auto base = now;
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::seconds(5); // deliberately long, so the two cases diverge hugely
    mcp::McpStreamPump pump{attached.sink,      state, attached.generation,
                            {},                 [] { return true; }, cfg,
                            [&] { return now; }};
    FakeWire wire;

    // The ring is empty and nothing has been published, so this pass genuinely sleeps -
    // no drain pass is needed first. (An earlier version added one on the theory that
    // `attach_and_replay` leaves replay state queued. It does not: with cursor 0 on an
    // empty ring it enqueues nothing, so that pass just blocked for a real 5s tick and
    // added 5 seconds to every run of the suite for no coverage.)
    //
    // Freeze 50ms short of the check: the pump must wake FOR it, not restart a full tick.
    now = base + cfg.tick - std::chrono::milliseconds(50);
    const auto started = std::chrono::steady_clock::now();
    REQUIRE(pump.pump_once(wire.writer()));
    const auto waited = std::chrono::steady_clock::now() - started;
    CHECK(waited < std::chrono::milliseconds(1500)); // correct ~50ms; unclamped ~5s
}

TEST_CASE("McpStreamPump/CH-4: a revoked credential kills the stream within one tick",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kRevoked; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer())); // provider ends
    // The client is TOLD why — a revoked stream must not look like a clean EOF.
    CHECK(wire.contains(R"("reason":"credential_revoked")"));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kCredentialRevoked);
}

TEST_CASE("McpStreamPump: the close frame is a JSON-RPC-wrapped notifications/yuzu.stream_closed "
          "under the default `message` event type, off-ring and id-less (2f PR 3b, PENDING 2)",
          "[mcp][stream][ch4][2f]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kRevoked; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer())); // revocation closes on the first tick

    // A normal JSON-RPC message on the stream, NOT the old bespoke `event: stream-closed` (which
    // a spec MCP client parsing JSON-RPC off the stream would never see).
    CHECK(wire.contains("event: message"));
    CHECK_FALSE(wire.contains("event: stream-closed"));
    CHECK(wire.contains(R"("jsonrpc":"2.0")"));
    CHECK(wire.contains(R"("method":"notifications/yuzu.stream_closed")"));
    // The A4-shaped params carry the machine-parseable reason + remediation.
    CHECK(wire.contains(R"("reason":"credential_revoked")"));
    CHECK(wire.contains(R"("retry_after_ms":null)"));
    CHECK(wire.contains(R"("remediation":)"));
    // Off-ring + id-less: a close is a point-in-time terminal signal, never replayed, so it
    // carries no SSE `id:` line an out-of-the-box client would persist as a resumable cursor.
    // (This assertion is exact only because the ring is empty on this fresh attach AND kRevoked
    // trips the very first pump gate, so the close frame is provably the ONLY bytes written — a
    // ring frame WOULD carry an `id:` line.)
    CHECK_FALSE(wire.contains("id: "));
}

TEST_CASE("make_stream_closed_frame: wraps the A4 body and merges caller extras (2f PR 3b)",
          "[mcp][stream][2f]") {
    // Bare: just the A4 body inside the JSON-RPC params.
    const auto bare = mcp::make_stream_closed_frame(mcp::McpStreamClose::kCancelled, "cid-1");
    auto j = nlohmann::json::parse(bare);
    CHECK(j["jsonrpc"] == "2.0");
    CHECK(j["method"] == "notifications/yuzu.stream_closed");
    CHECK(j["params"]["reason"] == "cancelled");
    CHECK(j["params"]["correlation_id"] == "cid-1");
    CHECK(j["params"]["retry_after_ms"].is_null());
    CHECK(j["params"].contains("remediation"));

    // With extras: the raw fragment (leading comma) merges into params as further fields — the
    // shape C6c/C7 use to carry execution_id + partial status on a cap/cancel close.
    const auto extra = mcp::make_stream_closed_frame(mcp::McpStreamClose::kCapExpired, "cid-2",
                                                     R"(,"execution_id":"exec-9","partial":true)");
    auto je = nlohmann::json::parse(extra);
    CHECK(je["params"]["reason"] == "cap_expired");
    CHECK(je["params"]["execution_id"] == "exec-9");
    CHECK(je["params"]["partial"] == true);

    // kCompleted is POST-only and never reaches the GET wire, but its to_string / remediation /
    // envelope must still be valid so the closed metric+audit label set is exhaustive.
    CHECK(std::string(mcp::to_string(mcp::McpStreamClose::kCompleted)) == "completed");
    auto jc = nlohmann::json::parse(mcp::make_stream_closed_frame(mcp::McpStreamClose::kCompleted,
                                                                  "cid-3"));
    CHECK(jc["params"]["reason"] == "completed");
    CHECK(jc["params"].contains("remediation"));
}

TEST_CASE("McpStreamPump/CH-4: an auth-backend outage buys a bounded grace window, not a kill",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    auto clock_now = std::chrono::steady_clock::now();
    const auto grace = std::chrono::milliseconds(1000);
    mcp::McpStreamPump pump{
        attached.sink,   state, attached.generation,
        [] { return mcp::StreamRevalidate::kIndeterminate; },
        [] { return true; }, fast_cfg(grace), [&clock_now] { return clock_now; }};

    FakeWire wire;
    // Inside the window the stream SURVIVES: an unreachable auth backend is not
    // evidence of revocation, and cutting every live stream on a blip is the
    // failure mode this window exists to prevent.
    CHECK(pump.pump_once(wire.writer()));
    clock_now += std::chrono::milliseconds(500);
    CHECK(pump.pump_once(wire.writer()));

    // Past the window it dies — the grace is bounded, not indefinite.
    clock_now += std::chrono::milliseconds(1000);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    // …and with a reason DISTINCT from revocation, so an operator can tell a
    // security event from an outage.
    CHECK(wire.contains(R"("reason":"auth_unavailable")"));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("McpStreamPump/CH-4: grace jitter spreads the deadline, breaking the mass-kill",
          "[mcp][stream][ch4]") {
    // The de-synchronising fix for the correlated PG-brownout outage: without jitter every
    // stream's grace is exactly revalidate_grace, so a brownout drives them all into grace
    // together and they all die together at onset+grace — a fleet-wide simultaneous
    // reconnect storm. With a jitter of J each stream's death lands in [grace, grace+J], so
    // the cliff becomes a ramp. The knob defaults to 0 (deterministic for the tests above);
    // production sets grace/2. Here we assert: (a) it still survives up to `grace`, and
    // (b) with a jitter it is NOT dead at exactly `grace` (it waits out its own offset).
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    const auto grace = std::chrono::milliseconds(1000);

    auto cfg = fast_cfg(grace);
    cfg.revalidate_grace_jitter_max = std::chrono::milliseconds(1000); // deaths in [1000, 2000]
    mcp::McpStreamPump pump{attached.sink,       state,
                            attached.generation, [] { return mcp::StreamRevalidate::kIndeterminate; },
                            [] { return true; },  cfg,
                            [&clock_now] { return clock_now; }};

    FakeWire wire;
    CHECK(pump.pump_once(wire.writer())); // enters grace, picks its jittered deadline
    // At exactly `grace` a NON-jittered stream would die; a jittered one has a deadline in
    // [grace, grace+jitter], so at t=grace it must STILL be alive (deadline > grace unless
    // the offset was 0, and even then the check is strictly `now > deadline`).
    clock_now += grace;
    CHECK(pump.pump_once(wire.writer()));
    // Past the maximum jittered deadline it is definitely dead.
    clock_now += std::chrono::milliseconds(1001);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("McpStreamPump/CH-4: a recovered backend resets the grace window",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    auto verdict = mcp::StreamRevalidate::kIndeterminate;

    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&verdict] { return verdict; },
                            [] { return true; },
                            fast_cfg(std::chrono::milliseconds(1000)),
                            [&clock_now] { return clock_now; }};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));      // grace starts
    clock_now += std::chrono::milliseconds(900);
    verdict = mcp::StreamRevalidate::kValid;   // backend came back
    CHECK(pump.pump_once(wire.writer()));
    verdict = mcp::StreamRevalidate::kIndeterminate; // it flaps again
    clock_now += std::chrono::milliseconds(900);
    // If the window had NOT reset, this tick would be past the deadline and kill a
    // stream whose credential was verified 900 ms ago.
    CHECK(pump.pump_once(wire.writer()));
}

TEST_CASE("McpStreamPump/#2367: cached validity does NOT reset the grace budget",
          "[mcp][stream][ch4]") {
    // The window that made cache residency and the grace window ADD. A cached
    // credential answer keeps the stream alive but re-confirms nothing, so the
    // grace budget must keep running from the last AUTHORITATIVE confirmation.
    // Treated as plain kValid, the stream would ride the cache and then collect
    // a full FRESH grace window on top of it.
    //
    // NOTE this case runs at fast_cfg's default revalidate_max_staleness of 0
    // (the conservative "answers are always authoritative" default). It proves
    // the floor-does-not-reset property in isolation; the sibling case below
    // ("a sibling-refreshed cache still leaves usable grace") exercises the
    // PRODUCTION shape with a non-zero staleness bound wired from kAuthCacheTtl.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    const auto grace = std::chrono::milliseconds(1000);
    auto verdict = mcp::StreamRevalidate::kValidStale;

    mcp::McpStreamPump pump{attached.sink,       state,
                            attached.generation, [&verdict] { return verdict; },
                            [] { return true; }, fast_cfg(grace),
                            [&clock_now] { return clock_now; }};
    FakeWire wire;

    // 900 ms of cached-valid answers. The stream stays up — a cache hit is not
    // a failure — but the budget is being spent, not refreshed.
    clock_now += std::chrono::milliseconds(900);
    CHECK(pump.pump_once(wire.writer()));

    // The cache expires and the store turns out to be unreachable. Only 100 ms
    // of the 1000 ms budget remains, so a further 200 ms must kill it. Under
    // the old "arm the deadline at first kIndeterminate" behaviour this stream
    // would have lived another full second.
    verdict = mcp::StreamRevalidate::kIndeterminate;
    clock_now += std::chrono::milliseconds(200);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("McpStreamPump/#2367: an authoritative re-confirmation does reset the budget",
          "[mcp][stream][ch4]") {
    // The other half: kValidStale must not be so strict that a genuinely
    // re-confirmed stream inherits a spent budget.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    auto verdict = mcp::StreamRevalidate::kValidStale;

    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&verdict] { return verdict; },
                            [] { return true; },
                            fast_cfg(std::chrono::milliseconds(1000)),
                            [&clock_now] { return clock_now; }};
    FakeWire wire;

    clock_now += std::chrono::milliseconds(900); // budget nearly spent on cached answers
    CHECK(pump.pump_once(wire.writer()));

    // Cross a tick boundary first: re-validation is once per TICK, so a second pass at the
    // SAME instant correctly does not ask the store again. Without this the re-confirmation
    // below never happens and the budget is never reset.
    clock_now += fast_cfg().tick;
    verdict = mcp::StreamRevalidate::kValid; // the store was actually asked
    CHECK(pump.pump_once(wire.writer()));

    // Budget restarts from here, so 900 ms of indeterminate is survivable again.
    verdict = mcp::StreamRevalidate::kIndeterminate;
    clock_now += std::chrono::milliseconds(900);
    CHECK(pump.pump_once(wire.writer()));
}

TEST_CASE("McpStreamPump/#2367: a sibling-refreshed cache still leaves usable grace",
          "[mcp][stream][ch4]") {
    // sec-M2 regression. The liveness cache is keyed by PRINCIPAL, but the
    // grace budget is per-STREAM. With several streams on one principal, only
    // whichever stream's tick lands on expiry gets an authoritative kValid --
    // the others ride cache hits indefinitely. If a cached answer never
    // advanced the authoritative floor, those streams would accumulate
    // unbounded staleness and then be cut with ZERO grace the instant the
    // store blipped, all at once. A cache hit is positive evidence the store
    // confirmed within its TTL, so the floor clamps forward to now - TTL.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    const auto grace = std::chrono::milliseconds(1000);
    auto verdict = mcp::StreamRevalidate::kValidStale;

    auto cfg = fast_cfg(grace);
    cfg.revalidate_max_staleness = std::chrono::milliseconds(250);
    mcp::McpStreamPump pump{attached.sink,       state,
                            attached.generation, [&verdict] { return verdict; },
                            [] { return true; }, cfg,
                            [&clock_now] { return clock_now; }};
    FakeWire wire;

    // Ten seconds of nothing but cached answers - far beyond the grace window.
    // Without the clamp the floor would still sit at construction time and the
    // stream would die instantly below.
    for (int i = 0; i < 10; ++i) {
        clock_now += std::chrono::seconds(1);
        REQUIRE(pump.pump_once(wire.writer()));
    }

    // Store blips. The budget spent is at most one staleness window, so most
    // of the grace remains: 500 ms must NOT kill it.
    verdict = mcp::StreamRevalidate::kIndeterminate;
    clock_now += std::chrono::milliseconds(500);
    CHECK(pump.pump_once(wire.writer()));

    // ...but the budget is still finite: it is not immortal.
    clock_now += std::chrono::milliseconds(600);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("McpStreamPump/#2367: a cached answer clears a grace deadline armed during an outage",
          "[mcp][stream][ch4]") {
    // A cached answer is POSITIVE evidence -- the entry only exists because an
    // authoritative read succeeded within the staleness window -- so it must
    // clear a deadline armed earlier, exactly as an authoritative kValid does.
    //
    // Getting this wrong kills healthy streams: with two streams on one
    // principal, the one that ticks first after recovery re-reads and warms the
    // shared cache entry, and the other then rides hits. If those hits left the
    // outage-era deadline counting down, that second stream would close
    // `auth_unavailable` against a reachable store and an Active principal.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    auto verdict = mcp::StreamRevalidate::kIndeterminate;

    auto cfg = fast_cfg(std::chrono::milliseconds(1000));
    cfg.revalidate_max_staleness = std::chrono::milliseconds(250);
    mcp::McpStreamPump pump{attached.sink,       state,
                            attached.generation, [&verdict] { return verdict; },
                            [] { return true; }, cfg,
                            [&clock_now] { return clock_now; }};
    FakeWire wire;

    CHECK(pump.pump_once(wire.writer())); // outage arms the deadline
    clock_now += std::chrono::milliseconds(900);

    // Store recovers; a sibling stream refreshed the entry, so this one sees a
    // cache hit. Well past the armed deadline -- it must survive.
    verdict = mcp::StreamRevalidate::kValidStale;
    clock_now += std::chrono::milliseconds(900);
    CHECK(pump.pump_once(wire.writer()));
    clock_now += std::chrono::seconds(5);
    CHECK(pump.pump_once(wire.writer()));

    // The budget is still finite: cached answers only advance the floor to
    // now - max_staleness, so a fresh outage kills it within the window.
    verdict = mcp::StreamRevalidate::kIndeterminate;
    clock_now += std::chrono::milliseconds(1300);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("RevalidateGrace: the extracted grace state machine, exercised directly (2f PR 3b)",
          "[mcp][stream][ch4][2f]") {
    using RG = mcp::RevalidateGrace;
    using R = mcp::StreamRevalidate;
    // Deterministic: an injected clock and jitter_max=0. RevalidateGrace seeds
    // last_authoritative_ok_ to now() at construction, so build it at t0 = epoch.
    auto at = [](std::int64_t ms) {
        return std::chrono::steady_clock::time_point{std::chrono::milliseconds(ms)};
    };
    std::chrono::steady_clock::time_point clock_now = at(0);
    auto clock = [&clock_now] { return clock_now; };
    RG::Config cfg;
    cfg.grace = std::chrono::milliseconds(1000);

    SECTION("kRevoked is an immediate kill, no grace") {
        RG grace{cfg, clock};
        CHECK(grace.on_verdict(R::kRevoked) == RG::Outcome::kCloseCredentialRevoked);
    }

    SECTION("kIndeterminate rides a bounded grace window, then closes auth_unavailable") {
        RG grace{cfg, clock};                              // last_authoritative_ok_ = 0
        clock_now = at(500);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kContinue); // deadline armed @1000
        clock_now = at(1001);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kCloseAuthUnavailable);
    }

    SECTION("an authoritative kValid clears an armed deadline and re-bases the window (#2367)") {
        RG grace{cfg, clock};
        clock_now = at(500);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kContinue); // deadline @1000
        CHECK(grace.on_verdict(R::kValid) == RG::Outcome::kContinue);         // clears it, floor=500
        clock_now = at(1001);                                                // past the OLD deadline
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kContinue); // new deadline @1500
        clock_now = at(1600);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kCloseAuthUnavailable);
    }

    SECTION("a kValidStale cache hit clears the deadline but only advances the floor one window") {
        cfg.max_staleness = std::chrono::milliseconds(250);
        RG grace{cfg, clock};
        clock_now = at(500);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kContinue); // deadline @1000
        clock_now = at(2000);
        CHECK(grace.on_verdict(R::kValidStale) == RG::Outcome::kContinue);    // clears; floor=1750
        // A fresh outage re-arms from the clamped floor (1750 + 1000 = 2750), not from t0.
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kContinue); // deadline @2750
        clock_now = at(2751);
        CHECK(grace.on_verdict(R::kIndeterminate) == RG::Outcome::kCloseAuthUnavailable);
    }
}

TEST_CASE("McpStreamPump: a terminated session ends the stream with its own reason",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; },
                            [] { return false; }, // DELETE / idle GC removed the session
                            fast_cfg()};
    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(wire.contains(R"("reason":"session_terminated")"));
}

TEST_CASE("McpStreamPump: a superseded pump exits WITHOUT writing a close frame",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto first = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{first.sink, state, first.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};

    auto second = state->attach_and_replay(0, nullptr, "alice"); // takeover
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);

    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));

    // No final frame, deliberately. The client already has a newer stream on this
    // session, so the only thing that can still be listening on THIS socket is the
    // stalled peer that provoked the takeover — and writing to it would block this
    // worker for the full write timeout while its lease is still charged. That
    // blocking write was the mechanism by which a rapid-reconnect client could pin
    // the pool.
    CHECK(wire.out.empty());
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);
}

TEST_CASE("McpStreamPump: a dead peer ends the stream", "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    wire.alive = false; // every write fails, as on a closed socket
    CHECK_FALSE(pump.pump_once(wire.writer()));
}

TEST_CASE("McpStreamPump: a sink-queue overflow tells the client to resume, not nothing",
          "[mcp][stream]") {
    // Ring 2 == sink cap 2. Publish 4 frames while attached: the sink's drop-oldest
    // guard fires. The client must LEARN it lost frames (they are still in the ring,
    // so a Last-Event-ID reconnect can replay them) rather than see a silent hole.
    auto state = std::make_shared<mcp::McpStreamState>(/*ring_cap=*/2);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    for (int i = 0; i < 4; ++i) {
        state->publish("message", "f" + std::to_string(i));
    }
    REQUIRE(attached.sink->sse->dropped_total.load() > 0);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));
    CHECK(wire.contains("event: events-dropped"));
    CHECK(wire.contains("Last-Event-ID"));
}

// ── Registry ↔ stream lifecycle ─────────────────────────────────────────────

TEST_CASE("McpSessionRegistry: terminate closes the session's live stream",
          "[mcp][session][stream]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    auto stream = reg.stream_for(minted.session_id, "alice");
    REQUIRE(stream);
    auto attached = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    REQUIRE(reg.terminate(minted.session_id, "alice"));
    // The provider is woken and given a reason — a DELETE must not present as a
    // bare connection drop.
    CHECK(attached.sink->sse->closed.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
}

TEST_CASE("McpSessionRegistry: stream_for is principal-bound (no oracle)",
          "[mcp][session][stream]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    CHECK(reg.stream_for(minted.session_id, "alice"));
    // A real session id under the wrong principal answers exactly as a made-up one
    // does — nullptr, no signal that the id exists.
    CHECK_FALSE(reg.stream_for(minted.session_id, "mallory"));
    CHECK_FALSE(reg.stream_for(std::string(32, 'f'), "mallory"));
}

TEST_CASE("McpSessionRegistry: idle GC closes the stream of a reaped session",
          "[mcp][session][stream]") {
    auto clock_now = std::chrono::steady_clock::now();
    mcp::McpSessionRegistry reg{{.idle_ttl = std::chrono::seconds(30)},
                                [&clock_now] { return clock_now; }};
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);
    auto stream = reg.stream_for(minted.session_id, "alice");
    auto attached = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    clock_now += std::chrono::seconds(31);
    reg.gc();

    CHECK(reg.active_count() == 0);
    CHECK(attached.sink->sse->closed.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
    // The state itself is still alive — the provider holds a reference, so the
    // registry's erase can never pull the rug from under a running pump.
    CHECK(stream->has_live_sink());
}

TEST_CASE("McpSessionRegistry: a live stream's ticking keeps its session young",
          "[mcp][session][stream]") {
    // The pump calls validate_and_touch every tick, which slides the TTL. That is
    // why a live stream needs no GC exemption: it stays young while it is genuinely
    // alive, and a zombie peer stops ticking and gets reaped on the normal schedule.
    auto clock_now = std::chrono::steady_clock::now();
    mcp::McpSessionRegistry reg{{.idle_ttl = std::chrono::seconds(30)},
                                [&clock_now] { return clock_now; }};
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    for (int i = 0; i < 4; ++i) {
        clock_now += std::chrono::seconds(20);
        CHECK(reg.validate_and_touch(minted.session_id, "alice") ==
              mcp::McpSessionRegistry::ValidateResult::kValid);
    }
    CHECK(reg.active_count() == 1); // 80 s elapsed, TTL 30 s, still alive

    clock_now += std::chrono::seconds(31); // the ticking stops (peer went away)
    reg.gc();
    CHECK(reg.active_count() == 0);
}

// #3042: ServerImpl::stop()'s close-signal, proven end-to-end through the same
// object graph stop() uses (registry -> live McpStreamState -> parked pump),
// not just the registry's own bookkeeping (test_mcp_session.cpp covers that).
TEST_CASE("McpSessionRegistry: shutdown wakes a live GET pump immediately, not a tick later",
          "[mcp][session][stream][race]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);
    const auto sid = minted.session_id;
    auto stream = reg.stream_for(sid, "alice");
    REQUIRE(stream);
    auto attached = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump::Config cfg;
    cfg.tick = std::chrono::seconds(30); // a wakeup that RELIES on the tick would hang
    mcp::McpStreamPump pump{
        attached.sink, stream, attached.generation,
        [] { return mcp::StreamRevalidate::kValid; },
        [&reg, sid] {
            // The real production wiring (mcp_server.cpp's session_alive closure),
            // not a hardcoded `true` — proves shutdown() reaches this pump via the
            // registry, not just via a direct state->close() call.
            return reg.validate_and_touch(sid, "alice") ==
                   mcp::McpSessionRegistry::ValidateResult::kValid;
        },
        cfg};

    // #2382-style handshake, not a sleep: the discriminator is TIMING, and a
    // sleep-then-join proves only that the pump eventually returned — a
    // regression to tick-bound wakeup would still pass every CHECK here, just
    // 30s late (cpp-expert governance finding). `long_tick` makes a tick-driven
    // wake blow well past the safety window below, and the assertion is "the
    // pump returned within 5s", not merely "returned". Never false-RED: if
    // shutdown() somehow ran before the pump reached wait_for, the predicate
    // would simply be true on entry and the pump would return fast anyway.
    FakeWire wire;
    std::atomic<bool> about_to_pump{false};
    auto pumped = std::async(std::launch::async, [&] {
        about_to_pump.store(true, std::memory_order_release);
        return pump.pump_once(wire.writer());
    });
    while (!about_to_pump.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    CHECK(reg.shutdown() == 1); // ServerImpl::stop()'s call, in miniature
    REQUIRE(pumped.wait_for(std::chrono::seconds(5)) == std::future_status::ready);

    CHECK_FALSE(pumped.get()); // pump_once returns false: the response is done
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
}

// The streamed-POST surface never attaches through McpStreamState — its sink is
// a standalone SseSinkState, and its only tie to a session is the session_alive_
// check each tick. #3042: once shutdown() drains the registry, that check must
// fail on the pump's very next tick, closing the response well before the
// streamed-POST response cap — the gap the issue's UP-1 was actually about.
TEST_CASE("McpSessionRegistry: shutdown closes a live streamed-POST pump within one tick",
          "[mcp][session][stream][race]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);
    const auto sid = minted.session_id;

    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    mcp::McpPostPump::Config cfg;
    cfg.tick = std::chrono::milliseconds(10); // don't sleep 3 s in a unit test
    mcp::McpPostPump pump{
        sink,
        [](bool /*cap_expired*/) { return mcp::McpStreamBridge::PostBatch{}; }, // nothing to drain
        [] {},                                                                  // on_final_written
        [] { return mcp::StreamRevalidate::kValid; },
        [&reg, sid] {
            return reg.validate_and_touch(sid, "alice") ==
                   mcp::McpSessionRegistry::ValidateResult::kValid;
        },
        cfg};

    FakeWire wire;
    // First tick: the session is still live — continue (heartbeat), same as any
    // ordinary in-progress streamed-POST call.
    CHECK(pump.pump_once(wire.writer()));

    CHECK(reg.shutdown() == 1);

    // Next tick: session_alive_() now reads the drained registry and fails.
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(pump.close_reason() == mcp::McpStreamClose::kSessionTerminated);
}

// close() only reads live_ — this pins the invariant that makes that safe: a
// draining_ sink from an in-progress takeover was ALREADY closed (kSuperseded) at
// the moment it became draining_, so shutdown() reaching a session mid-handover
// needs no special case for it. If a future change ever deferred the takeover's
// own close-signal, this test would catch the reintroduced unsignalled sink.
TEST_CASE("McpSessionRegistry: shutdown mid-handover closes only the new live sink; "
          "the superseded one is already closed",
          "[mcp][session][stream][race]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);
    auto stream = reg.stream_for(minted.session_id, "alice");
    REQUIRE(stream);

    auto first = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(first.status == mcp::McpStreamState::AttachStatus::kAttached);
    auto second = stream->attach_and_replay(0, nullptr, "alice"); // takeover
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);

    // The superseded sink is closed synchronously by the takeover itself, before
    // shutdown() ever runs — this is the invariant close() relies on.
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);

    CHECK(reg.shutdown() == 1);

    CHECK(second.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
    // Unaffected by shutdown() — first-wins CAS, and close() never touches draining_.
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);
}

// ── Concurrency (TSan net) ──────────────────────────────────────────────────

TEST_CASE("McpStreamState: concurrent publish / attach / detach / close is race-free",
          "[mcp][stream][race]") {
    auto state = std::make_shared<mcp::McpStreamState>(/*ring_cap=*/16);
    detail::StreamBudget budget{{.global_cap = 64}};
    constexpr std::size_t kPerPrincipal = 64;
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    threads.emplace_back([&] {
        for (int i = 0; i < 400; ++i) {
            state->publish("message", "f" + std::to_string(i));
        }
        stop.store(true);
    });
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            while (!stop.load()) {
                auto a = state->attach_and_replay(0, &budget, "alice");
                if (a.status == mcp::McpStreamState::AttachStatus::kAttached) {
                    state->detach(a.sink);
                }
            }
        });
    }
    threads.emplace_back([&] {
        while (!stop.load()) {
            state->close(mcp::McpStreamClose::kSessionTerminated);
        }
    });
    for (auto& th : threads) {
        th.join();
    }

    CHECK(state->next_event_id() == 401);
    // THE accounting invariant: one lease per pinned provider, no more and no fewer.
    // A leak here is invisible in testing and fatal in production — MCP streaming
    // would slowly die over a server's uptime as slots were never returned.
    const std::size_t providers = (state->has_live_sink() ? 1u : 0u) +
                                  (state->has_draining_sink() ? 1u : 0u);
    CHECK(budget.active() == providers);
}

TEST_CASE("McpSessionRegistry: concurrent mint / stream_for / terminate is race-free",
          "[mcp][session][stream][race]") {
    mcp::McpSessionRegistry reg;
    std::vector<std::thread> threads;
    std::atomic<int> minted{0};

    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            const std::string principal = "p" + std::to_string(t % 3);
            for (int i = 0; i < 100; ++i) {
                auto m = reg.mint(principal);
                if (!m.ok) {
                    continue;
                }
                ++minted;
                if (auto s = reg.stream_for(m.session_id, principal)) {
                    s->publish("message", "x");
                }
                reg.terminate(m.session_id, principal);
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    CHECK(minted.load() > 0);
    CHECK(reg.active_count() == 0);
}

// ── The exception boundary (an escaped throw here is std::terminate) ─────────

TEST_CASE("McpStreamPump: an exception from re-validation ends the stream, never escapes",
          "[mcp][stream]") {
    // httplib runs a chunked content provider from a bare ThreadPool task — outside the
    // try/catch that wraps routing() — so an exception escaping pump_once is
    // std::terminate, not a 500 (#2037's failure class). Re-validation reaches SQLite and
    // the auth manager, both of which can throw, so this boundary is load-bearing.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            []() -> mcp::StreamRevalidate { throw std::runtime_error("auth blew up"); },
                            [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_NOTHROW(pump.pump_once(wire.writer()));
    CHECK_FALSE(pump.pump_once(wire.writer())); // and the stream is over

    // The fault is recorded as OURS. Auditing it as a client disconnect would send the
    // operator looking at the client for a server bug.
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kInternalError);
}

TEST_CASE("McpStreamPump: the exception boundary holds with no metrics registry wired",
          "[mcp][stream]") {
    // The catch handler's own metric/log calls allocate — and it exists precisely because
    // we may be out of memory. Exercise the null-metrics branch too, so the guard is
    // covered on both.
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, nullptr);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            []() -> mcp::StreamRevalidate { throw std::bad_alloc(); },
                            [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_NOTHROW(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kInternalError);
}

TEST_CASE("McpStreamState: an oversized frame is replaced, not corrupted",
          "[mcp][stream]") {
    // Byte-truncating a JSON payload yields a guaranteed-unparseable frame — which would
    // then be handed to the live sink AND stored in the ring under an id, so every resume
    // would faithfully re-serve the same garbage. Substitute a well-formed notice instead.
    mcp::McpStreamState state{/*ring_cap=*/8, nullptr, /*ring_bytes_cap=*/256};
    state.publish("message", std::string(4096, 'x'));

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 1);
    const auto& frame = attached.sink->sse->queue.front();
    CHECK(frame.data.find("frame_too_large") != std::string::npos);
    CHECK(frame.data.find("execution_id") != std::string::npos);
    CHECK(frame.data.size() <= 256);
    CHECK(frame.data.find(std::string(64, 'x')) == std::string::npos); // no raw payload
}

// ── publish() exception boundary (#2366) ────────────────────────────────────
// PR 3's progress bridge invokes publish() from an ExecutionEventBus listener on a
// worker task no routing try/catch ever sees — an escaped throw is std::terminate.
// The throw sites are internal string/deque allocations (no callback seam to throw
// through), so these tests trip the two failure phases via the explicit test seam.
//
// DISCLOSED COVERAGE GAPS (all the same "unreachable without a fault-injection harness
// this repo does not have" class, none load-bearing): (1) a real allocator-level
// bad_alloc — modelled deterministically by the PublishFault seam instead; (2) the
// boundary's nested catch when the metric/log call ITSELF throws (no throwing-metrics
// mock); (3) the recovery std::lock_guard's std::mutex::lock() throwing std::system_error
// (a broken mutex — practically unreachable on glibc; the code contains it by falling
// back to a bare atomic bump). The noexcept static_assert + the seam-driven tests below
// are the regression guard for the reachable paths.

TEST_CASE("McpStreamState: publish is a noexcept boundary — structural, not decorative",
          "[mcp][stream]") {
    // Assert on LVALUE arguments, not rvalue temporaries. The realistic PR 3 caller is
    // `publish(event.event_type, event.data)` — lvalue members of the bus event. With a
    // by-value `std::string` parameter that copy happens in the CALLER's frame and can
    // throw bad_alloc BEFORE the boundary's try, escaping the unguarded listener; the old
    // assertion used `std::string{}` rvalues (which move, noexcept) and so missed the hole
    // entirely. `string_view` params make the whole call expression non-throwing.
    static_assert(
        noexcept(std::declval<mcp::McpStreamState&>().publish(
            std::declval<const std::string&>(), std::declval<const std::string&>())),
        "#2366: publish() must be a hard exception boundary for LVALUE callers — PR 3's "
        "progress bridge calls it from an unguarded ExecutionEventBus listener (#2037)");
    // And for string_view / string-literal call sites.
    static_assert(noexcept(std::declval<mcp::McpStreamState&>().publish(
                      std::string_view{}, std::string_view{})),
                  "#2366: the boundary must also hold for string_view callers");
    SUCCEED();
}

TEST_CASE("McpStreamState: a pre-commit publish failure consumes NO id and gaps nothing (#2366)",
          "[mcp][stream]") {
    mcp::McpStreamState state;
    REQUIRE(state.publish("message", "one") == 1);

    state.inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit);
    std::uint64_t id = 99;
    CHECK_NOTHROW(id = state.publish("message", "lost"));
    CHECK(id == 0);                    // 0 = "not published" — never a valid frame id
    CHECK(state.next_event_id() == 2); // the id was NOT consumed: no permanent hole

    // The next publish takes exactly the id the failed one would have had, and a full
    // replay shows a contiguous stream — a resume can never 404 on a gap the failure
    // silently created (the old `id = next_id_++` before the push did exactly that).
    CHECK(state.publish("message", "two") == 2);
    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 2);
    CHECK(attached.sink->sse->queue.front().id == 1);
    CHECK(attached.sink->sse->queue.back().id == 2);
    CHECK(attached.sink->sse->queue.back().data == "two");
}

TEST_CASE("McpStreamState: a sink-enqueue failure keeps the committed frame and counts "
          "the gap (#2366)",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kSinkEnqueue);
    std::uint64_t id = 0;
    CHECK_NOTHROW(id = state->publish("message", "missed"));
    // COMMITTED: the frame is in the ring under its id. Returning 0 here would claim
    // it never happened while every future replay faithfully serves it.
    CHECK(id == 1);
    CHECK(state->next_event_id() == 2);

    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        CHECK(attached.sink->sse->queue.empty()); // the frame never reached the sink...
    }
    CHECK(attached.sink->sse->dropped_total.load() == 1); // ...and that is COUNTED

    // The counted drop rides the existing machinery: the pump tells the client frames
    // were lost, and the ring still holds the frame so a Last-Event-ID resume recovers
    // it. NOTE this is the empty-queue lone-drop case: dropped_total==1 with an EMPTY
    // queue is the interaction #2366 introduced (pre-#2366 a drop always rode alongside
    // a real push_back).
    //
    // SCOPE OF THIS ASSERTION (honest): this pump_once runs on THIS thread AFTER the
    // faulting publish, so the wait predicate is already true on entry — the call never
    // parks and is never woken by notify_one. It therefore verifies the OUTCOME (an
    // empty-queue drop is reported as events-dropped, and the ring still replays the
    // frame), NOT the notify-driven wakeup timing. The deterministic condvar handoff
    // (bump under the sink mutex; predicate includes dropped_total) is verified by
    // cpp-safety inspection, not here. The genuine two-thread handshake this comment
    // once deferred to "a track-2f PR-3 follow-up" now EXISTS — the #2382 test at the
    // end of this file parks a pump in wait_for, then faults and publishes, and asserts
    // prompt emission with no wall-clock bound.
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));
    CHECK(wire.contains("event: events-dropped"));

    auto resumed = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(resumed.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(resumed.sink->sse->mu);
    REQUIRE(resumed.sink->sse->queue.size() == 1);
    CHECK(resumed.sink->sse->queue.front().id == 1);
    CHECK(resumed.sink->sse->queue.front().data == "missed");
}

TEST_CASE("McpStreamState: an injected publish fault is one-shot — never persists (#2366)",
          "[mcp][stream]") {
    // A leaked fault flag would silently drop a later REAL frame. kSinkEnqueue is the
    // sharp case: it is consumed only when a sink is live, so injecting it with NO live
    // sink must still clear it up front — otherwise it fires on the next client's first
    // frame. (The fault is now read-and-cleared via std::exchange before the sink check.)
    auto state = std::make_shared<mcp::McpStreamState>();

    // (a) kSinkEnqueue injected with NO live sink: consumed anyway, not left armed.
    state->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kSinkEnqueue);
    CHECK(state->publish("message", "no-sink") == 1); // committed; nothing to drop
    // Attach at cursor 1 so the replay serves nothing — we want to observe ONLY the next
    // live publish, not the pre-attach frame.
    auto attached = state->attach_and_replay(1, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    state->publish("message", "first-real"); // would be dropped if the fault had persisted
    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        REQUIRE(attached.sink->sse->queue.size() == 1);
        CHECK(attached.sink->sse->queue.front().data == "first-real");
    }
    CHECK(attached.sink->sse->dropped_total.load() == 0); // never armed against a real frame

    // (b) kSinkEnqueue with a live sink: consumed once, the very next publish delivers.
    state->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kSinkEnqueue);
    state->publish("message", "dropped-once");
    CHECK(attached.sink->sse->dropped_total.load() == 1);
    state->publish("message", "delivered");
    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        CHECK(attached.sink->sse->queue.back().data == "delivered");
    }
    CHECK(attached.sink->sse->dropped_total.load() == 1); // still 1 — no second drop
}

TEST_CASE("McpStreamState: a pre-commit failure increments the publish-failures counter (#2366)",
          "[mcp][stream]") {
    // Exercises the boundary's catch with a LIVE registry (not the nullptr default the
    // other cases use), so the nested-guarded counter increment runs on the real path.
    yuzu::MetricsRegistry reg;
    mcp::McpStreamState state{mcp::kMcpRingCapDefault, &reg};
    state.inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit);
    CHECK(state.publish("message", "lost") == 0);
    CHECK(reg.counter("yuzu_mcp_stream_publish_failures_total").value() == 1.0);
}

TEST_CASE("McpStreamState: a post-commit observability fault never un-commits the frame (#2366)",
          "[mcp][stream]") {
    // The #2366 boundary must distinguish PRE-commit from POST-commit failure. A throw from
    // the observability block (a metric increment or the enriched WARN format allocating
    // under memory pressure) fires AFTER the frame is committed, so it must be swallowed and
    // the committed id returned - never converted into a 0 the caller reads as "not
    // published" (the asymmetric caller-obligation the contract turns on). Live registry so
    // the innermost catch runs on the real path, not the nullptr short-circuit.
    yuzu::MetricsRegistry reg;
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, &reg);
    state->set_log_context("sid=deadbeef");
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->inject_publish_fault_for_test(
        mcp::McpStreamState::PublishFault::kPostCommitObservability);
    std::uint64_t id = 0;
    CHECK_NOTHROW(id = state->publish("message", "committed-despite-obs-fault"));
    CHECK(id == 1);                     // committed id returned, NOT 0
    CHECK(state->next_event_id() == 2); // the id was consumed - the frame IS in the ring

    // The frame reached the sink BEFORE the observability throw (enqueue is under mu_; the
    // observability block runs post-lock), so delivery is entirely unaffected - this is a
    // swallowed server-side breadcrumb fault, not a dropped frame.
    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        REQUIRE(attached.sink->sse->queue.size() == 1);
        CHECK(attached.sink->sse->queue.front().data == "committed-despite-obs-fault");
    }
    CHECK(attached.sink->sse->dropped_total.load() == 0);

    // One-shot: the fault does not linger - the very next publish takes id 2 cleanly.
    CHECK(state->publish("message", "clean") == 2);
}

TEST_CASE("McpStreamState: set_log_context does not weaken the publish boundary (#2366)",
          "[mcp][stream]") {
    // The enriched WARN lines interpolate the session context and the event_type; that
    // format + metric lookup allocates and runs inside the boundary's nested guard. So even
    // a pre-commit failure with a context set must still return a clean 0 and count the
    // failure - the enrichment must never become an escape hatch out of the boundary.
    yuzu::MetricsRegistry reg;
    mcp::McpStreamState state{mcp::kMcpRingCapDefault, &reg};
    state.set_log_context("sid=cafef00d");
    state.inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit);
    std::uint64_t id = 7;
    CHECK_NOTHROW(id = state.publish("progress", "lost"));
    CHECK(id == 0);
    CHECK(reg.counter("yuzu_mcp_stream_publish_failures_total").value() == 1.0);
}

TEST_CASE("McpStreamState: a pinned final survives a full ring wrap (CH-2, Decision 15(f))",
          "[mcp][stream]") {
    // The eviction-exemption backbone: publish_final pins the terminal frame, then a flood of
    // ordinary frames wraps the ring many times over. The pinned final must still be in the
    // ring so a late GET resume recovers it - the whole point of 15(f).
    mcp::McpStreamState state{/*ring_cap=*/5};
    REQUIRE(state.publish_final("message", "FINAL") == 1); // id 1, pinned
    CHECK(state.is_pinned(1));
    CHECK(state.pinned_count() == 1);
    for (int i = 0; i < 20; ++i) {
        state.publish("message", "flood-" + std::to_string(i)); // wraps the 5-frame ring 4x
    }
    CHECK(state.is_pinned(1)); // never evicted

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    // The oldest surviving frame is the pinned final, ahead of the newest unpinned window.
    REQUIRE(!attached.sink->sse->queue.empty());
    CHECK(attached.sink->sse->queue.front().id == 1);
    CHECK(attached.sink->sse->queue.front().data == "FINAL");
}

TEST_CASE("McpStreamState: pin slots are a bounded LRU, not first-come-permanent",
          "[mcp][stream][pins]") {
    // WHAT THIS PINS. What exhausting the four pin slots MEANS is defined once - see
    // McpStreamState's "What a FULL PIN-SLOT SET means" block in mcp_stream.hpp. Since
    // #2740 it no longer implies drift on its own, so this is a degradation path that
    // is genuinely REACHABLE, which is why it is worth pinning behaviourally here.
    //
    // The old fallback sacrificed the wrong frame: it committed the NEWEST terminal
    // unpinned. A pin exists so a terminal survives a ring wrap and a late resume can
    // recover it (Decision 15(f)) - worth most for the newest result, least for the oldest,
    // which by then has almost certainly been consumed. Leaving the newest evictable meant
    // the request most likely still waiting for its answer was the one left unprotected.
    //
    // The slots now degrade as an LRU: oldest yields to newest.
    mcp::McpStreamState state{/*ring_cap=*/64};
    std::vector<std::uint64_t> ids;
    for (int i = 0; i < 6; ++i) {
        ids.push_back(state.publish_final("message", "FINAL-" + std::to_string(i)));
    }
    REQUIRE(ids.size() == 6);

    // Still exactly four slots - this is a bound, not a leak.
    CHECK(state.pinned_count() == 4);
    // The two OLDEST yielded...
    CHECK_FALSE(state.is_pinned(ids[0]));
    CHECK_FALSE(state.is_pinned(ids[1]));
    // ...so that the four most recent are the ones a resume can still recover.
    CHECK(state.is_pinned(ids[2]));
    CHECK(state.is_pinned(ids[3]));
    CHECK(state.is_pinned(ids[4]));
    CHECK(state.is_pinned(ids[5]));
}

TEST_CASE("McpStreamState: the newest terminal survives a wrap even past the slot count",
          "[mcp][stream][pins]") {
    // The consequence that actually reaches a client once the slots have been exhausted.
    // Pre-fix the 5th and later terminals were evictable, so a late resume could lose the
    // very result it asked for while the session's FIRST four - long since consumed -
    // stayed protected.
    mcp::McpStreamState state{/*ring_cap=*/5};
    std::vector<std::uint64_t> ids;
    for (int i = 0; i < 6; ++i) {
        ids.push_back(state.publish_final("message", "FINAL-" + std::to_string(i)));
    }
    for (int i = 0; i < 20; ++i) {
        state.publish("message", "flood-" + std::to_string(i)); // wraps the 5-frame ring 4x
    }
    CHECK(state.is_pinned(ids[5])); // the newest terminal is still recoverable

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(!attached.sink->sse->queue.empty());

    // NOT `queue.front()`: replay is oldest-first, and the oldest SURVIVING frame is now
    // the oldest still-pinned terminal (FINAL-2), not the newest. What matters is which
    // terminals a late resume can still be served.
    const auto has = [&](std::string_view want) {
        return std::any_of(attached.sink->sse->queue.begin(), attached.sink->sse->queue.end(),
                           [&](const auto& ev) { return ev.data == want; });
    };
    CHECK(has("FINAL-5")); // the newest terminal survived the wrap
    CHECK(has("FINAL-2")); // ...as did the rest of the retained window
    CHECK_FALSE(has("FINAL-0")); // displaced, then evicted by the flood - the bounded cost
    CHECK_FALSE(has("FINAL-1"));
}

TEST_CASE("McpStreamState: publish_ring_only commits to the ring but not the live sink",
          "[mcp][stream]") {
    // A streamed POST's frames ride the POST stream; publishing them onto a concurrent live
    // GET too would be the spec's forbidden broadcast. publish_ring_only commits for resume
    // ONLY - the live sink stays empty - while a normal publish still delivers live.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    REQUIRE(state->publish_ring_only("message", "post-bound") == 1);
    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        CHECK(attached.sink->sse->queue.empty()); // NOT delivered live
    }
    CHECK(state->next_event_id() == 2); // but it IS committed (id consumed)

    state->publish("message", "get-bound"); // a normal publish still reaches the live sink
    {
        std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
        REQUIRE(attached.sink->sse->queue.size() == 1);
        CHECK(attached.sink->sse->queue.front().data == "get-bound");
    }

    // The ring-only frame is recoverable by resume - a fresh attach from cursor 0 replays it.
    auto resumed = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(resumed.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(resumed.sink->sse->mu);
    REQUIRE(resumed.sink->sse->queue.size() == 2);
    CHECK(resumed.sink->sse->queue.front().data == "post-bound"); // id 1 still in the ring
}

TEST_CASE("McpStreamState: unpin makes a former final evictable again", "[mcp][stream]") {
    mcp::McpStreamState state{/*ring_cap=*/2};
    REQUIRE(state.publish_final("message", "FINAL") == 1); // pinned
    for (int i = 0; i < 5; ++i) state.publish("message", "x");
    REQUIRE(state.is_pinned(1)); // survived while pinned

    // The RETURN distinguishes "this call released it" from "it was already gone",
    // which is what the bridge's admission reclaim credits a freed slot on (#2740):
    // crediting a no-op would admit one call over the per-session cap.
    CHECK(state.unpin(1));
    CHECK_FALSE(state.is_pinned(1));
    CHECK(state.pinned_count() == 0);
    CHECK_FALSE(state.unpin(1)); // idempotent - a second unpin is a no-op, and says so
    CHECK(state.pinned_count() == 0);
    CHECK_FALSE(state.unpin(0));        // the empty-slot sentinel is never a release
    CHECK_FALSE(state.unpin(999999));   // an id this ring never pinned

    for (int i = 0; i < 5; ++i) state.publish("message", "y"); // now id 1 can be evicted
    // Cursor 0 replays the surviving window; id 1 is gone (no longer protected).
    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    for (const auto& ev : attached.sink->sse->queue) {
        CHECK(ev.id != 1);
    }
}

TEST_CASE("McpStreamState: attach unpins finals the cursor proves consumed (unpin rule b)",
          "[mcp][stream]") {
    mcp::McpStreamState state;
    REQUIRE(state.publish_final("message", "FINAL") == 1); // pinned
    state.publish("message", "after");
    REQUIRE(state.is_pinned(1));

    // A resume whose Last-Event-ID is at/after the pinned id proves the client consumed it -
    // the exemption is released on attach.
    auto attached = state.attach_and_replay(/*last_event_id=*/1, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK_FALSE(state.is_pinned(1));
    CHECK(state.pinned_count() == 0);
}

TEST_CASE("McpStreamState: poison_terminal fails every future attach with kPoisoned",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->poison_terminal();
    // The live sink is closed honestly rather than left waiting for a terminal.
    CHECK(attached.sink->sse->closed.load());

    // Every subsequent attach fast-fails - regardless of cursor - so a client is told to
    // fetch by execution_id, never left heart-beating forever.
    CHECK(state->attach_and_replay(0, nullptr, "bob").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
    state->poison_terminal(); // idempotent
    CHECK(state->attach_and_replay(0, nullptr, "bob").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
}

TEST_CASE("McpStreamState: a poison-time close failure is contained and counted, not thrown "
          "(#2531)",
          "[mcp][stream]") {
    // Live registry so the real counter path runs, not the nullptr short-circuit.
    yuzu::MetricsRegistry reg;
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, &reg);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->inject_poison_close_fault_for_test(1);
    CHECK_NOTHROW(state->poison_terminal());
    CHECK(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 1.0);
    // The close itself failed, so alice's sink is left heart-beating rather than closed -
    // exactly the silent-loss shape #2531 exists to close. Checked BEFORE any further
    // attach, because an attach on a poisoned session is ITSELF a retry attempt (see the
    // next test) and would close it.
    CHECK_FALSE(attached.sink->sse->closed.load());

    // The flag is durable regardless of what happened to the close - every future attach
    // still fast-fails.
    CHECK(state->attach_and_replay(0, nullptr, "bob").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
}

TEST_CASE("McpStreamState: a later attach retries and closes a sink the poison-time close "
          "missed (#2531)",
          "[mcp][stream]") {
    yuzu::MetricsRegistry reg;
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, &reg);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->inject_poison_close_fault_for_test(1); // one-shot: only the poison-time close fails
    state->poison_terminal();
    REQUIRE(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 1.0);
    REQUIRE_FALSE(attached.sink->sse->closed.load()); // missed, per the previous test

    // Poisoning is sticky and idempotent, so THIS attach's retry gets a clean shot at the
    // same stale sink - the seam is exhausted, so the retry succeeds.
    CHECK(state->attach_and_replay(0, nullptr, "bob").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
    CHECK(attached.sink->sse->closed.load());
    // No second failure counted - the retry succeeded.
    CHECK(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 1.0);
}

TEST_CASE("McpStreamState: a poison-time close failure AND its attach retry failure are both "
          "contained (#2531)",
          "[mcp][stream]") {
    yuzu::MetricsRegistry reg;
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, &reg);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state->inject_poison_close_fault_for_test(2); // covers both the poison close AND the retry
    CHECK_NOTHROW(state->poison_terminal());
    CHECK(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 1.0);
    CHECK_FALSE(attached.sink->sse->closed.load());

    mcp::McpStreamState::AttachResult retry;
    CHECK_NOTHROW(retry = state->attach_and_replay(0, nullptr, "bob"));
    CHECK(retry.status == mcp::McpStreamState::AttachStatus::kPoisoned);
    // The retry ALSO failed and was ALSO contained - two failures, still no escape, and
    // alice's sink is still open - the seam is now exhausted, so a THIRD attach
    // gets a clean shot and actually closes it.
    CHECK(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 2.0);
    CHECK_FALSE(attached.sink->sse->closed.load());

    CHECK(state->attach_and_replay(0, nullptr, "carol").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
    CHECK(attached.sink->sse->closed.load());
    // No third failure - the seam was armed for exactly 2.
    CHECK(reg.counter("yuzu_mcp_stream_poison_close_failures_total").value() == 2.0);
}

TEST_CASE("McpStreamState: a pre-commit publish_final failure writes no pin and consumes no id",
          "[mcp][stream]") {
    mcp::McpStreamState state;
    state.inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit);
    CHECK(state.publish_final("message", "lost") == 0); // pre-commit failure
    CHECK(state.pinned_count() == 0);                   // no ghost pin
    CHECK(state.next_event_id() == 1);                  // no id consumed
}

TEST_CASE("McpStreamState: a final past the pin bound displaces the OLDEST pin",
          "[mcp][stream][pins]") {
    // REPLACES an earlier test that asserted the overflow final commits UNPINNED. Its
    // premise - that reaching this state means admission accounting drifted - was correct
    // WHEN WRITTEN and #2740 has since falsified it (three paths now reach a full set
    // legitimately; see mcp_stream.hpp's "What a FULL PIN-SLOT SET means"). What the old
    // test got wrong, and what this one fixes, was which frame to sacrifice - and that
    // part is independent of why the slots are full. Committing the
    // newest terminal unprotected leaves the request most likely still waiting for its
    // answer as the evictable one, while the oldest pin, almost certainly consumed already,
    // keeps its exemption. The slots now degrade as an LRU, and the displacement is still
    // reported (via `pin_displaced_total`) rather than silently absorbed.
    yuzu::MetricsRegistry reg;
    mcp::McpStreamState state{mcp::kMcpRingCapDefault, &reg};
    std::vector<std::uint64_t> ids;
    for (std::size_t i = 0; i < mcp::kMaxStreamedPostsPerSession; ++i) {
        ids.push_back(state.publish_final("message", "final"));
        REQUIRE(ids.back() != 0);
    }
    CHECK(state.pinned_count() == mcp::kMaxStreamedPostsPerSession); // slots full

    const auto overflow_id = state.publish_final("message", "one-too-many");
    REQUIRE(overflow_id != 0);            // committed - never lost
    CHECK(state.is_pinned(overflow_id));  // AND protected, which is the point
    CHECK_FALSE(state.is_pinned(ids[0])); // the oldest yielded its slot
    CHECK(state.is_pinned(ids[1]));       // the rest of the window is untouched
    CHECK(state.pinned_count() == mcp::kMaxStreamedPostsPerSession); // still a bound

    // The displacement is ordinary and is counted as such; the old counter stays at zero
    // because committing a final unprotected is no longer reachable.
    CHECK(reg.counter("yuzu_mcp_stream_pin_displaced_total").value() == 1.0);
    CHECK(reg.counter("yuzu_mcp_stream_final_unpinned_total").value() == 0.0);
}

TEST_CASE("McpStreamState: unpin of a displaced id no-ops - it cannot release the usurper",
          "[mcp][stream][pins]") {
    // The bridge holds the DISPLACED request's id until its POST wire settles, and its
    // normal teardown still calls unpin(displaced_id). unpin matches by ID VALUE across
    // the slots - never by index - so the stale release must find nothing: the slot that
    // held the displaced id now protects the newer terminal, and releasing THAT pin on a
    // stale handle would strip the exemption from exactly the frame the LRU chose to keep.
    mcp::McpStreamState state;
    std::vector<std::uint64_t> ids;
    for (std::size_t i = 0; i < mcp::kMaxStreamedPostsPerSession; ++i) {
        ids.push_back(state.publish_final("message", "final"));
    }
    const auto overflow_id = state.publish_final("message", "one-too-many");
    REQUIRE_FALSE(state.is_pinned(ids[0])); // displaced by the overflow

    // The stale release the bridge will eventually issue - and it now SAYS it
    // released nothing, which is what stops the reclaim crediting a phantom slot.
    CHECK_FALSE(state.unpin(ids[0]));
    CHECK(state.pinned_count() == mcp::kMaxStreamedPostsPerSession); // nothing released
    CHECK(state.is_pinned(overflow_id));                             // the usurper kept its slot
    CHECK(state.is_pinned(ids[1]));

    CHECK(state.unpin(overflow_id)); // a REAL release still works after the stale one no-op'd
    CHECK_FALSE(state.is_pinned(overflow_id));
    CHECK(state.pinned_count() == mcp::kMaxStreamedPostsPerSession - 1);
}

TEST_CASE("McpStreamState/CH-5: a post-commit fault during displacement loses only the count",
          "[mcp][stream][pins]") {
    // Compound of the displacement path with the #2366 post-commit containment: the
    // observability block throws AFTER the frame committed and the older pin was already
    // destroyed. The containment must hold displacement-shaped state coherent - committed
    // id returned, usurper pinned, bound intact - with ONLY the drift count lost, and the
    // loss must not latch: the next displacement, with the registry healthy again, counts.
    yuzu::MetricsRegistry reg;
    mcp::McpStreamState state{mcp::kMcpRingCapDefault, &reg};
    std::vector<std::uint64_t> ids;
    for (std::size_t i = 0; i < mcp::kMaxStreamedPostsPerSession; ++i) {
        ids.push_back(state.publish_final("message", "final"));
    }

    state.inject_publish_fault_for_test(
        mcp::McpStreamState::PublishFault::kPostCommitObservability);
    const auto first_overflow = state.publish_final("message", "displaces-under-fault");
    REQUIRE(first_overflow != 0);          // committed - the fault must not un-commit it
    CHECK(state.is_pinned(first_overflow)); // displacement itself completed under mu_
    CHECK_FALSE(state.is_pinned(ids[0]));
    CHECK(state.pinned_count() == mcp::kMaxStreamedPostsPerSession);
    // The drift count is the documented casualty (sec-L1: observability must not
    // un-commit, so the increment dies with the throw).
    CHECK(reg.counter("yuzu_mcp_stream_pin_displaced_total").value() == 0.0);

    // The loss does not latch: a healthy registry counts the next displacement.
    const auto second_overflow = state.publish_final("message", "displaces-counted");
    REQUIRE(second_overflow != 0);
    CHECK_FALSE(state.is_pinned(ids[1])); // next-oldest yielded this time
    CHECK(reg.counter("yuzu_mcp_stream_pin_displaced_total").value() == 1.0);
}

TEST_CASE("McpStreamPump/CH-4: the first pass after a long write stall runs the revalidation",
          "[mcp][stream][ch4][tickgate]") {
    // A saturated socket parks the pump inside write_all for up to the 30s write timeout -
    // passes simply do not happen while it blocks. The tick gate must not turn that stall
    // into a revalidation hole: the FIRST pass once writes resume finds next_check_ long
    // overdue and runs the check BEFORE the drain delivers anything, so a credential
    // revoked during the stall closes the stream ahead of any further frames.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    auto now = std::chrono::steady_clock::now();
    auto verdict = mcp::StreamRevalidate::kValid;
    mcp::McpStreamPump::Config cfg{};
    cfg.tick = std::chrono::seconds(3);
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&] { return verdict; },
                            [] { return true; },
                            cfg,
                            [&] { return now; }};
    FakeWire wire;

    // A healthy delivering pass first, so the stall starts from the busy-stream shape.
    state->publish("message", "before-the-stall");
    REQUIRE(pump.pump_once(wire.writer()));
    REQUIRE(wire.contains("before-the-stall"));

    // The stall: no passes while the clock crosses several tick boundaries, and the
    // credential is revoked mid-stall. Frames queue up behind the blocked write.
    now += cfg.tick * 10; // well past next_check_ - a 30s write timeout is 10 ticks
    verdict = mcp::StreamRevalidate::kRevoked;
    state->publish("message", "queued-during-stall");

    // The resumed pass must close revoked WITHOUT delivering what queued during the stall:
    // the gate runs before the drain, and an overdue check fires on the first opportunity.
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kCredentialRevoked);
    CHECK(wire.contains(R"("reason":"credential_revoked")"));
    CHECK_FALSE(wire.contains("queued-during-stall"));
}

TEST_CASE("McpStreamPump: a parked pump is woken by the producer's drop, not the tick (#2382)",
          "[mcp][stream]") {
    // The deferred #2366 follow-up: prove the DETERMINISTIC condvar handoff, not just the
    // outcome. The existing sink-enqueue test runs pump_once on the SAME thread after the
    // fault, so the predicate is already true on entry and the pump never parks - it cannot
    // distinguish "woken by notify" from "predicate true on arrival". Here a second thread
    // parks the pump in wait_for, then this thread faults+publishes: the containment path
    // bumps dropped_total UNDER the sink mutex and notify_one's, so a parked waiter wakes at
    // once and emits the events-dropped synthetic.
    //
    // The discriminator is timing, and ONLY timing: even a broken notify would eventually
    // emit events-dropped when the tick fires (the predicate also tests dropped_total). So
    // the tick is set to 30 s - far beyond any wakeup latency - and the assertion is "the
    // pump returned well within a 5 s safety window", i.e. it woke on the notify, not the
    // 30 s tick. This is a generous margin, not a tight latency bound.
    //
    // Never false-RED: if this thread happens to publish BEFORE the pump reaches wait_for,
    // the predicate is simply true on entry and the pump returns fast anyway (a PASS that
    // did not exercise the notify). The test can only FAIL if the pump parked AND the notify
    // failed to wake it - exactly the regression it guards. The atomic handshake biases
    // heavily toward the parked-first interleaving so CI actually exercises the notify.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump::Config long_tick;
    long_tick.tick = std::chrono::seconds(30); // a tick-driven wake would blow the safety window
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            long_tick};
    FakeWire wire;

    std::atomic<bool> about_to_pump{false};
    auto pumped = std::async(std::launch::async, [&] {
        about_to_pump.store(true, std::memory_order_release);
        return pump.pump_once(wire.writer()); // parks in wait_for on an empty, open sink
    });
    while (!about_to_pump.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    // Fault the live-sink enqueue: the frame commits to the ring, the by-value copy "throws",
    // and the containment bumps dropped_total under the sink mutex + notify_one.
    state->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kSinkEnqueue);
    REQUIRE(state->publish("message", "missed") == 1); // committed under id 1

    // Woken by the notify - ready in milliseconds, nowhere near the 30 s tick.
    REQUIRE(pumped.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    CHECK(pumped.get()); // pump_once returned true - the stream continues
    CHECK(wire.contains("event: events-dropped"));
}
