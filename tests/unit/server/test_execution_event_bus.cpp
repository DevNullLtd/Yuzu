/**
 * test_execution_event_bus.cpp — coverage for the per-execution SSE event
 * bus introduced by PR 3 of the executions-history ladder.
 *
 * Contracts being pinned:
 *   - subscribe / publish / unsubscribe round-trip across one channel
 *   - per-execution channel partitioning (subscribers on exec A do NOT
 *     receive events for exec B)
 *   - ring buffer caps at kBufferCap; oldest events are evicted FIFO
 *   - replay_since respects the Last-Event-ID semantics (id strictly >)
 *   - terminal-marked channels survive past terminal time but get GC'd
 *     once retention expires AND no subscribers remain
 *   - listener invocation runs under the per-channel mutex but never
 *     blocks the publisher (a listener that mutates the bus state would
 *     deadlock — verified indirectly by the queue-and-notify pattern;
 *     the test for listener concurrency is a smoke).
 */

#include "execution_event_bus.hpp"
#include "execution_event_scope.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>  // std::sort -- not transitively pulled in by <vector>
                      // on MSVC's STL (Linux libstdc++ + libc++ both happen
                      // to include it indirectly, masking the omission).
#include <atomic>
#include <cstdint>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

ExecutionEvent only_event(const std::vector<ExecutionEvent>& v) {
    REQUIRE(v.size() == 1);
    return v.front();
}

} // namespace

TEST_CASE("execution_event_bus — subscribe / publish / unsubscribe round-trip",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    std::vector<ExecutionEvent> received;
    auto sub_id = bus.subscribe("exec-1", [&](const ExecutionEvent& ev) {
        received.push_back(ev);
    });
    REQUIRE(sub_id != 0);

    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a1","status":"running"})");
    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a2","status":"success"})");

    REQUIRE(received.size() == 2);
    CHECK(received[0].id == 1);
    CHECK(received[1].id == 2);
    CHECK(received[0].event_type == "agent-transition");
    CHECK(received[1].data.find("a2") != std::string::npos);

    bus.unsubscribe("exec-1", sub_id);
    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a3","status":"failure"})");
    CHECK(received.size() == 2); // unsubscribe took effect
}

TEST_CASE("execution_event_bus — per-execution channel partitioning",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    int a_count = 0, b_count = 0;
    bus.subscribe("exec-A", [&](const ExecutionEvent&) { ++a_count; });
    bus.subscribe("exec-B", [&](const ExecutionEvent&) { ++b_count; });

    bus.publish("exec-A", "agent-transition", "{}");
    bus.publish("exec-A", "execution-progress", "{}");
    bus.publish("exec-B", "agent-transition", "{}");

    CHECK(a_count == 2);
    CHECK(b_count == 1);
    // Each channel has its own monotonic id — exec-B's first event is id 1,
    // not id 3.
    auto snap_b = bus.snapshot("exec-B");
    REQUIRE(snap_b.size() == 1);
    CHECK(snap_b[0].id == 1);
}

TEST_CASE("execution_event_bus — ring buffer caps at kBufferCap",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    // Publish 3 past the cap and assert the oldest 3 are evicted.
    for (std::size_t i = 0; i < ExecutionEventBus::kBufferCap + 3; ++i) {
        bus.publish("exec-1", "agent-transition",
                    std::string{"{\"i\":"} + std::to_string(i) + "}");
    }
    auto snap = bus.snapshot("exec-1");
    CHECK(snap.size() == ExecutionEventBus::kBufferCap);
    // The lowest surviving id is 4 (1, 2, 3 evicted).
    CHECK(snap.front().id == 4);
    CHECK(snap.back().id == ExecutionEventBus::kBufferCap + 3);
}

TEST_CASE("execution_event_bus — replay_since strictly greater than",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    for (int i = 0; i < 5; ++i) {
        bus.publish("exec-1", "agent-transition", "{}");
    }

    SECTION("replay_since(0) returns all 5 buffered events") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 0,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        REQUIRE(ids.size() == 5);
        CHECK(ids.front() == 1);
        CHECK(ids.back() == 5);
    }
    SECTION("replay_since(3) returns ids 4 and 5") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 3,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        REQUIRE(ids.size() == 2);
        CHECK(ids.front() == 4);
        CHECK(ids.back() == 5);
    }
    SECTION("replay_since past the head is empty (no spurious replays)") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 999,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        CHECK(ids.empty());
    }
    SECTION("replay_since on unknown channel is empty") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("not-an-exec", 0,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        CHECK(ids.empty());
    }
}

TEST_CASE("execution_event_bus — terminal flag and gc",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;

    SECTION("non-terminal channel is not GC'd") {
        bus.publish("exec-1", "agent-transition", "{}");
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);
    }
    SECTION("terminal channel with subscribers is not GC'd") {
        auto sub = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
        bus.publish("exec-1", "execution-completed", "{}", /*is_terminal=*/true);
        CHECK(bus.gc_terminal_channels() == 0);
        bus.unsubscribe("exec-1", sub);
        // Channel is still present until retention expires (60 s); the GC
        // skips the entry but it remains.
        CHECK(bus.channel_count() == 1);
    }
}

TEST_CASE("execution_event_bus — GC collects an expired terminal channel "
          "without destroying a locked mutex (#1198)",
          "[execution_event_bus][pr3][gc]") {
    // Regression for #1198: gc_terminal_channels() erased the channel —
    // destroying the std::mutex inside it — while a lock_guard still owned
    // that mutex (the map held the only shared_ptr). The unlock of the
    // freed mutex aborted the whole server on MSVC and is UB everywhere.
    //
    // Detection: only MSVC's STL fails this deterministically (its unlock
    // validates ownership and aborts). On POSIX the bad unlock lands inside
    // uninstrumented libpthread, so ASan and TSan both stay silent — the
    // Windows CI leg is the enforcement point. Either way this pins the
    // collection path the older gc tests never reached (they only exercised
    // the not-collected branches).
    std::int64_t fake_now = 1'000'000; // past the throttle vs last_gc=0
    ExecutionEventBus bus;             // declared after the clock state it borrows
    bus.set_clock_fn([&] { return fake_now; });

    // Terminal event, no subscribers — exactly the channel shape GC targets.
    bus.publish("exec-1", "execution-completed", "{}", /*is_terminal=*/true);
    REQUIRE(bus.channel_count() == 1);

    // Advance past retention + GC throttle so the sweep both runs and
    // finds exec-1 expired.
    constexpr std::int64_t kAdvance =
        ExecutionEventBus::kRetentionAfterTerminalSec * 1000 +
        ExecutionEventBus::kMinGcIntervalMs + 1;

    SECTION("direct gc_terminal_channels() call") {
        fake_now += kAdvance;
        CHECK(bus.gc_terminal_channels() == 1);
        CHECK(bus.channel_count() == 0);
        CHECK(bus.gc_channels_total() == 1);
    }
    SECTION("publish-driven opportunistic sweep (production trigger)") {
        // In production the sweep fires from publish() on an unrelated
        // execution — the crash signature from the UAT rig.
        fake_now += kAdvance;
        bus.publish("exec-2", "agent-transition", "{}");
        CHECK(bus.channel_count() == 1); // exec-1 collected, exec-2 live
        CHECK(bus.gc_channels_total() == 1);
        CHECK(bus.snapshot("exec-1").empty());
    }
    SECTION("multi-victim sweep parks every collected channel") {
        // The dead vector must keep ALL victims alive past their locks,
        // not just the first.
        bus.publish("exec-2", "execution-completed", "{}", /*is_terminal=*/true);
        bus.publish("exec-3", "execution-completed", "{}", /*is_terminal=*/true);
        REQUIRE(bus.channel_count() == 3);
        fake_now += kAdvance;
        CHECK(bus.gc_terminal_channels() == 3);
        CHECK(bus.channel_count() == 0);
        CHECK(bus.gc_channels_total() == 3);
    }
    SECTION("expired channel with a live subscriber survives the sweep") {
        // Pins the listeners.empty() predicate that both GC passes share —
        // the same condition the pass-2 re-check applies when a subscriber
        // lands between the passes. (The true between-pass interleaving
        // needs a thread race and is covered by the CH-1 chaos scenario.)
        fake_now += kAdvance;
        auto sub = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);

        bus.unsubscribe("exec-1", sub);
        // Within kMinGcIntervalMs of the sweep above — throttled no-op.
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);

        fake_now += ExecutionEventBus::kMinGcIntervalMs + 1;
        CHECK(bus.gc_terminal_channels() == 1); // collected once unsubscribed
        CHECK(bus.channel_count() == 0);
    }
}

TEST_CASE("execution_event_bus — listener invocation is synchronous within publish",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    std::atomic<int> seen{0};
    bus.subscribe("exec-1", [&](const ExecutionEvent&) {
        seen.fetch_add(1, std::memory_order_relaxed);
    });
    bus.publish("exec-1", "agent-transition", "{}");
    // Invocation happens before publish returns — no sleep needed.
    CHECK(seen.load() == 1);
}

TEST_CASE("execution_event_bus — concurrent publishers do not lose events",
          "[execution_event_bus][pr3][concurrency]") {
    ExecutionEventBus bus;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    std::atomic<int> received{0};
    bus.subscribe("exec-1",
                  [&](const ExecutionEvent&) { received.fetch_add(1, std::memory_order_relaxed); });

    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                bus.publish("exec-1", "agent-transition", "{}");
            }
        });
    }
    for (auto& t : ts) t.join();
    CHECK(received.load() == kThreads * kPerThread);
    auto snap = bus.snapshot("exec-1");
    // Total events fit within the 1000-cap, so all should be in the buffer.
    CHECK(snap.size() == kThreads * kPerThread);
    // Ids are strictly monotonic — sort and verify no gaps.
    std::vector<std::uint64_t> ids;
    ids.reserve(snap.size());
    for (const auto& e : snap) ids.push_back(e.id);
    std::sort(ids.begin(), ids.end());
    for (std::size_t i = 1; i < ids.size(); ++i) {
        CHECK(ids[i] == ids[i - 1] + 1);
    }
}

TEST_CASE("execution_event_bus — subscriber_count and channel_count smoke",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    CHECK(bus.subscriber_count("exec-1") == 0);
    auto s1 = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    auto s2 = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    bus.subscribe("exec-2", [](const ExecutionEvent&) {});
    CHECK(bus.subscriber_count("exec-1") == 2);
    CHECK(bus.subscriber_count("exec-2") == 1);
    CHECK(bus.subscriber_count("not-an-exec") == 0);
    CHECK(bus.channel_count() == 2);
    bus.unsubscribe("exec-1", s1);
    bus.unsubscribe("exec-1", s2);
    CHECK(bus.subscriber_count("exec-1") == 0);
}

TEST_CASE("execution_event_bus — unsubscribe is idempotent",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    auto s = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    bus.unsubscribe("exec-1", s);
    // Second unsubscribe must not crash or throw.
    bus.unsubscribe("exec-1", s);
    bus.unsubscribe("not-an-exec", 12345);
    SUCCEED("idempotent unsubscribe paths reached");
}

TEST_CASE("execution_event_bus — snapshot is a copy, not a view",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    bus.publish("exec-1", "agent-transition", R"({"x":1})");
    auto snap1 = bus.snapshot("exec-1");
    bus.publish("exec-1", "agent-transition", R"({"x":2})");
    auto snap2 = bus.snapshot("exec-1");
    CHECK(snap1.size() == 1);
    CHECK(snap2.size() == 2);
    // Pin the only_event helper just so the linker doesn't drop it as
    // unused — defensive against future test growth.
    auto first = only_event(snap1);
    CHECK(first.event_type == "agent-transition");
}

TEST_CASE("execution_event_bus - subscribe_and_replay delivers buffered then live, once each",
          "[execution_event_bus][pr3][2f]") {
    ExecutionEventBus bus;
    bus.publish("exec-1", "execution-progress", R"({"n":1})");
    bus.publish("exec-1", "execution-progress", R"({"n":2})");
    bus.publish("exec-1", "execution-progress", R"({"n":3})");

    std::vector<ExecutionEvent> received;
    SECTION("since_id=0 replays the whole buffer, then live events follow") {
        auto sub = bus.subscribe_and_replay("exec-1", 0,
                                            [&](const ExecutionEvent& ev) { received.push_back(ev); });
        REQUIRE(sub != 0);
        REQUIRE(received.size() == 3); // 1,2,3 replayed synchronously under the lock
        CHECK(received[0].id == 1);
        CHECK(received[2].id == 3);

        bus.publish("exec-1", "execution-completed", R"({"n":4})");
        REQUIRE(received.size() == 4); // 4 arrives live, exactly once (not re-replayed)
        CHECK(received[3].id == 4);
        CHECK(received[3].event_type == "execution-completed");
    }
    SECTION("since_id past the head replays nothing but still installs the listener") {
        bus.subscribe_and_replay("exec-1", 3,
                                 [&](const ExecutionEvent& ev) { received.push_back(ev); });
        CHECK(received.empty()); // ids 1..3 are <= cursor
        bus.publish("exec-1", "execution-completed", R"({"n":4})");
        REQUIRE(received.size() == 1);
        CHECK(received[0].id == 4);
    }
    SECTION("a fresh channel installs the listener and delivers subsequent events") {
        bus.subscribe_and_replay("exec-new", 0,
                                 [&](const ExecutionEvent& ev) { received.push_back(ev); });
        CHECK(received.empty());
        bus.publish("exec-new", "agent-transition", R"({"n":1})");
        REQUIRE(received.size() == 1);
        CHECK(received[0].id == 1);
    }
}

TEST_CASE("execution_event_bus - subscribe_and_replay closes the replay->subscribe race",
          "[execution_event_bus][pr3][2f][concurrency]") {
    // The property that motivates the primitive (Sol S6 / K3): a subscriber that joins
    // WHILE a publisher is running must see EVERY event from since_id+1 onward exactly once,
    // with no gap at the subscribe boundary and no duplicate. With since_id=0 and a total
    // below kBufferCap, the buffer never evicts, so the received id set must be exactly
    // {1..N} - and this holds for EVERY interleaving (subscribe landing early, mid, or late
    // in the stream), so the test is deterministic, never flaky: an event is either already
    // buffered (replayed) or published after the listener is installed (live) - never both,
    // because a publisher needs the same channel mutex the install+replay holds.
    ExecutionEventBus bus;
    constexpr int kTotal = 500; // < kBufferCap (1000), so nothing is evicted
    std::mutex recv_mu;
    std::vector<std::uint64_t> received;

    std::atomic<bool> go{false};
    std::thread publisher([&] {
        while (!go.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        for (int i = 0; i < kTotal; ++i) {
            bus.publish("exec-1", "execution-progress", "{}");
        }
    });

    go.store(true, std::memory_order_release);
    // Join mid-stream: the publisher is already racing us, so the subscribe lands at an
    // arbitrary point in the 1..kTotal sequence.
    bus.subscribe_and_replay("exec-1", 0, [&](const ExecutionEvent& ev) {
        std::lock_guard<std::mutex> lk(recv_mu);
        received.push_back(ev.id);
    });
    publisher.join();

    std::lock_guard<std::mutex> lk(recv_mu);
    std::sort(received.begin(), received.end());
    REQUIRE(received.size() == static_cast<std::size_t>(kTotal)); // no loss, no duplicate
    for (std::size_t i = 0; i < received.size(); ++i) {
        CHECK(received[i] == i + 1); // contiguous 1..kTotal - no gap at the subscribe boundary
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// C5 (#2409) - first_terminal_id marker + unsubscribe_and_visit_terminal
// ═══════════════════════════════════════════════════════════════════════════

namespace {
using TV = ExecutionEventBus::TerminalVisit;
using VS = ExecutionEventBus::VisitStatus;

/// Run the visitor with a recording callback. `claim` is what f returns (the
/// erase trigger). Captures the verdict + a copy of the buffered event's
/// identity (the pointer is valid only during the call).
struct VisitProbe {
    bool f_ran = false;
    TV verdict = TV::kNeverTerminal;
    bool had_ev = false;
    std::uint64_t ev_id = 0;
    std::string ev_type;
    VS status = VS::kInternalError;
};
VisitProbe visit(ExecutionEventBus& bus, const std::string& exec, std::size_t sub,
                 bool claim) {
    VisitProbe p;
    p.status = bus.unsubscribe_and_visit_terminal(
        exec, sub, [&](TV v, const ExecutionEvent* ev) noexcept -> bool {
            p.f_ran = true;
            p.verdict = v;
            p.had_ev = ev != nullptr;
            if (ev != nullptr) {
                p.ev_id = ev->id;
                p.ev_type = ev->event_type;
            }
            return claim;
        });
    return p;
}
}  // namespace

TEST_CASE("visit_terminal - verdict is kNeverTerminal when no terminal was published",
          "[execution_event_bus][2f][2409]") {
    ExecutionEventBus bus;
    auto sub = bus.subscribe("exec-nt", [](const ExecutionEvent&) {});
    bus.publish("exec-nt", "execution-progress", "{}");  // non-terminal
    auto p = visit(bus, "exec-nt", sub, /*claim=*/false);
    CHECK(p.status == VS::kVisited);
    CHECK(p.f_ran);
    CHECK(p.verdict == TV::kNeverTerminal);
    CHECK_FALSE(p.had_ev);
    CHECK(bus.subscriber_count("exec-nt") == 1);  // defer (claim=false) KEEPS the listener
}

TEST_CASE("visit_terminal - kTerminalBuffered names the FIRST terminal event, not completed",
          "[execution_event_bus][2f][2409]") {
    // The refresh_counts split: a terminal-flagged execution-progress is published
    // FIRST, then execution-completed. The marker must name the PROGRESS event (id
    // 1) - an event-type scan for "execution-completed" would misclassify, which is
    // the exact bug the marker exists to prevent.
    ExecutionEventBus bus;
    auto sub = bus.subscribe("exec-split", [](const ExecutionEvent&) {});
    bus.publish("exec-split", "execution-progress",
                R"({"status":"succeeded","agents_success":3,"agents_failure":0})",
                /*is_terminal=*/true);  // id 1 - the FIRST terminal-flagged event
    bus.publish("exec-split", "execution-completed",
                R"({"status":"succeeded","agents_success":3,"agents_failure":0})",
                /*is_terminal=*/true);  // id 2
    auto p = visit(bus, "exec-split", sub, /*claim=*/false);
    CHECK(p.verdict == TV::kTerminalBuffered);
    REQUIRE(p.had_ev);
    CHECK(p.ev_id == 1);
    CHECK(p.ev_type == "execution-progress");  // the marker, not the completed event
}

TEST_CASE("visit_terminal - first terminal marker is stable across later terminals",
          "[execution_event_bus][2f][2409]") {
    ExecutionEventBus bus;
    auto sub = bus.subscribe("exec-stable", [](const ExecutionEvent&) {});
    bus.publish("exec-stable", "execution-completed", "{}", /*is_terminal=*/true);  // id 1
    bus.publish("exec-stable", "execution-completed", "{}", /*is_terminal=*/true);  // id 2 (dup)
    auto p = visit(bus, "exec-stable", sub, /*claim=*/false);
    CHECK(p.verdict == TV::kTerminalBuffered);
    REQUIRE(p.had_ev);
    CHECK(p.ev_id == 1);  // still the first terminal, not the duplicate
}

TEST_CASE("visit_terminal - kTerminalKnownLost when the marker aged out of the buffer",
          "[execution_event_bus][2f][2409]") {
    ExecutionEventBus bus;
    auto sub = bus.subscribe("exec-lost", [](const ExecutionEvent&) {});
    bus.publish("exec-lost", "execution-completed",
                R"({"status":"succeeded"})", /*is_terminal=*/true);  // id 1
    // Flood past kBufferCap (1000) so the terminal (and every completed event) is
    // evicted FIFO; the channel stays flagged terminal.
    for (int i = 0; i < static_cast<int>(ExecutionEventBus::kBufferCap) + 50; ++i) {
        bus.publish("exec-lost", "execution-progress", "{}");
    }
    auto p = visit(bus, "exec-lost", sub, /*claim=*/false);
    CHECK(p.verdict == TV::kTerminalKnownLost);
    CHECK_FALSE(p.had_ev);  // benign: caller maps this to a success-shaped fallback
}

TEST_CASE("visit_terminal - a completed buffered AFTER the marker aged out is NOT recovered (#2409 UP-1)",
          "[execution_event_bus][2f][2409]") {
    // The marker (terminal-progress at id 1) is evicted; a LATER execution-completed
    // is still buffered. We deliberately do NOT recover it: a completed present after
    // the marker evicted is more likely a spurious later terminal (e.g. a
    // mark_cancelled on the same id) than the real one, and building a final from it
    // would emit a WRONG result. The verdict is kTerminalKnownLost -> the caller's
    // safe success-shaped fallback ("fetch by execution_id").
    ExecutionEventBus bus;
    auto sub = bus.subscribe("exec-norecover", [](const ExecutionEvent&) {});
    bus.publish("exec-norecover", "execution-progress", "{}", /*is_terminal=*/true);  // id 1 (marker)
    for (int i = 0; i < static_cast<int>(ExecutionEventBus::kBufferCap) - 1; ++i) {
        bus.publish("exec-norecover", "execution-progress", "{}");
    }
    // Publishing this completed pushes the marker (id 1) out of the 1000-cap ring.
    bus.publish("exec-norecover", "execution-completed", R"({"status":"cancelled"})",
                /*is_terminal=*/true);
    auto p = visit(bus, "exec-norecover", sub, /*claim=*/false);
    CHECK(p.verdict == TV::kTerminalKnownLost);  // NOT recovered as buffered
    CHECK_FALSE(p.had_ev);
}

TEST_CASE("visit_terminal - erases the listener ONLY on a committed claim",
          "[execution_event_bus][2f][2409]") {
    ExecutionEventBus bus;
    SECTION("defer (f returns false) keeps the listener") {
        auto sub = bus.subscribe("exec-keep", [](const ExecutionEvent&) {});
        bus.publish("exec-keep", "execution-completed", "{}", /*is_terminal=*/true);
        auto p = visit(bus, "exec-keep", sub, /*claim=*/false);
        CHECK(p.f_ran);
        CHECK(bus.subscriber_count("exec-keep") == 1);
    }
    SECTION("claim (f returns true) erases the listener") {
        auto sub = bus.subscribe("exec-erase", [](const ExecutionEvent&) {});
        bus.publish("exec-erase", "execution-completed", "{}", /*is_terminal=*/true);
        auto p = visit(bus, "exec-erase", sub, /*claim=*/true);
        CHECK(p.f_ran);
        CHECK(bus.subscriber_count("exec-erase") == 0);
    }
}

TEST_CASE("visit_terminal - fails closed on an absent channel, runs f on a stale sub",
          "[execution_event_bus][2f][2409]") {
    ExecutionEventBus bus;
    SECTION("absent channel: f NOT run, status kAbsentChannel (never kNeverTerminal)") {
        bool ran = false;
        auto st = bus.unsubscribe_and_visit_terminal(
            "exec-none", 1, [&](TV, const ExecutionEvent*) noexcept {
                ran = true;
                return false;
            });
        CHECK(st == VS::kAbsentChannel);
        CHECK_FALSE(ran);
    }
    SECTION("stale sub on a live channel: f STILL runs, status kStaleSub") {
        auto sub = bus.subscribe("exec-live", [](const ExecutionEvent&) {});
        bus.unsubscribe("exec-live", sub);  // token now stale
        bus.publish("exec-live", "execution-completed", "{}", /*is_terminal=*/true);
        auto p = visit(bus, "exec-live", sub, /*claim=*/false);
        CHECK(p.status == VS::kStaleSub);
        CHECK(p.f_ran);  // the barrier still holds; f's record-state checks make it idempotent
        CHECK(p.verdict == TV::kTerminalBuffered);
    }
}

TEST_CASE("execution event scope projection filters data-bearing events",
          "[execution_event_bus][scope][1634]") {
    const authz::VisibleSet scope{
        std::unordered_set<std::string>{"agent-visible"}};

    ExecutionEvent visible{1, 10, "agent-transition",
                           R"({"agent_id":"agent-visible","status":"success"})"};
    ExecutionEvent hidden{2, 11, "agent-transition",
                          R"({"agent_id":"agent-hidden","status":"failure"})"};
    ExecutionEvent malformed{3, 12, "agent-transition", "{"};
    ExecutionEvent missing_id{4, 13, "agent-transition", R"({"status":"success"})"};
    ExecutionEvent progress{5, 14, "execution-progress",
                            R"({"agents_targeted":2,"agents_responded":1})"};

    CHECK(classify_execution_event_for_scope(visible, scope) == ExecutionEventVerdict::kPass);
    CHECK(classify_execution_event_for_scope(hidden, scope) == ExecutionEventVerdict::kDrop);
    CHECK(classify_execution_event_for_scope(malformed, scope) == ExecutionEventVerdict::kDrop);
    CHECK(classify_execution_event_for_scope(missing_id, scope) == ExecutionEventVerdict::kDrop);
    CHECK(classify_execution_event_for_scope(progress, scope) == ExecutionEventVerdict::kDrop);
    CHECK(classify_execution_event_for_scope(malformed, std::nullopt) ==
          ExecutionEventVerdict::kPass);
}

TEST_CASE("execution event scope projection sanitizes completion but passes synthetics",
          "[execution_event_bus][scope][1634]") {
    const authz::VisibleSet scope{
        std::unordered_set<std::string>{"agent-visible"}};
    ExecutionEvent completed{42, 99, "execution-completed",
                             R"({"agents_targeted":7,"agents_failure":2})"};

    REQUIRE(classify_execution_event_for_scope(completed, scope) ==
            ExecutionEventVerdict::kSanitize);
    const auto sanitized = sanitize_execution_event_for_scope(completed);
    CHECK(sanitized.id == completed.id);
    CHECK(sanitized.timestamp_ms == completed.timestamp_ms);
    CHECK(sanitized.event_type == "execution-completed");
    CHECK(sanitized.data == R"({"status":"completed"})");
    CHECK(sanitized.data.find("agents_targeted") == std::string::npos);

    for (const std::string type : {"replay-gap", "events-dropped", "heartbeat"}) {
        ExecutionEvent synthetic{1, 1, type, ""};
        CHECK(classify_execution_event_for_scope(synthetic, scope) ==
              ExecutionEventVerdict::kPass);
    }
}
