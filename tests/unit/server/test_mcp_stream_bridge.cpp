// MCP progress bridge (track 2f PR 3) - the consumer-side projection of the
// ExecutionEventBus onto the MCP session's SSE surfaces.
//
// Part 1: the pure JSON-RPC helpers (progressToken extraction, the
// notifications/progress builder). Part 2: the McpStreamBridge core - records,
// copy-only listener, projector thread, arm/cancel/abandon arbitration, sweep
// (pin-ack / session-death / pressure), charge accounting, shutdown. The
// concurrency-heavy cases (flip-drain, arm-vs-abandon race, pressure-vs-terminal
// property, dtor safety) are the TSan leg's primary targets.

#include <catch2/catch_test_macros.hpp>

#include "../../../server/core/src/mcp_jsonrpc.hpp"
#include "../../../server/core/src/mcp_session.hpp"
#include "../../../server/core/src/mcp_stream.hpp"
#include <yuzu/server/auth.hpp>  // CredentialCheck is only forward-declared by mcp_stream.hpp
#include "../../../server/core/src/execution_tracker.hpp"
#include "../../../server/core/src/mcp_stream_bridge.hpp"
#include "../test_helpers.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>  // std::find over the closed cancel-outcome label set
#include <atomic>
#include <condition_variable>
#include <set>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace mcp = yuzu::server::mcp;
using nlohmann::json;

TEST_CASE("extract_progress_token - accepts string and integer tokens verbatim",
          "[mcp][bridge][2f]") {
    SECTION("string token") {
        auto p = json::parse(R"({"_meta":{"progressToken":"abc-123"}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_string());
        CHECK(tok->get<std::string>() == "abc-123");
    }
    SECTION("integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":42}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_number_integer());
        CHECK(tok->get<int>() == 42);
    }
    SECTION("negative integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":-7}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->get<int>() == -7);
    }
}

TEST_CASE("extract_progress_token - anything not string|integer is ignored (no error)",
          "[mcp][bridge][2f]") {
    // The spec lets a server decline to emit progress, so an unusable or absent token is
    // simply "no progress requested" - never a parse failure.
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{}})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":42})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":3.14}})"))
                    .has_value()); // float rejected
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":true}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":null}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":{}}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"([1,2,3])")).has_value()); // non-object
}

TEST_CASE("progress_notification - token echoed verbatim, shape is valid JSON-RPC",
          "[mcp][bridge][2f]") {
    SECTION("string token stays a string; execution_id in _meta") {
        auto tok = json("tok-abc");
        auto msg = mcp::progress_notification(tok, /*progress=*/3, /*total=*/5, "3/5 responded",
                                              "exec-xyz");
        auto parsed = json::parse(msg); // must be well-formed
        CHECK(parsed["jsonrpc"] == "2.0");
        CHECK(parsed["method"] == "notifications/progress");
        CHECK(parsed["params"]["progressToken"] == "tok-abc"); // string, not "\"tok-abc\""
        CHECK(parsed["params"]["progressToken"].is_string());
        CHECK(parsed["params"]["progress"] == 3);
        CHECK(parsed["params"]["total"] == 5);
        CHECK(parsed["params"]["message"] == "3/5 responded");
        CHECK(parsed["params"]["_meta"]["yuzu.execution_id"] == "exec-xyz");
        CHECK_FALSE(parsed.contains("id")); // a notification has no id
    }
    SECTION("integer token is emitted as a number, never stringified") {
        auto tok = json(99);
        auto parsed = json::parse(
            mcp::progress_notification(tok, 1, 1, "done", "exec-1"));
        CHECK(parsed["params"]["progressToken"].is_number_integer());
        CHECK(parsed["params"]["progressToken"] == 99);
    }
    SECTION("message with quotes/newlines is escaped into valid JSON") {
        auto tok = json("t");
        auto parsed = json::parse(
            mcp::progress_notification(tok, 0, 0, "line\"one\"\nline two", "exec-1"));
        CHECK(parsed["params"]["message"] == "line\"one\"\nline two");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 2 - the bridge core (rung 3a.6)
// ═══════════════════════════════════════════════════════════════════════════

namespace {

using yuzu::server::ExecutionEventBus;
using Bridge = mcp::McpStreamBridge;

/// Poll an eventually-true condition - the projector is asynchronous. Generous
/// deadline, tight step: never false-RED on a loaded CI box, fast when green.
template <typename F>
bool poll_until(F&& f, std::chrono::milliseconds deadline = std::chrono::seconds(5)) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < until) {
        if (f()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return f();
}

/// Everything a bridge test needs, destruction-ordered so the bridge (declared
/// last) shuts down while the bus/registry are still alive - the production
/// stop() ordering (bridge reset BEFORE bus reset).
struct Fx {
    yuzu::MetricsRegistry reg;
    ExecutionEventBus bus;
    std::chrono::steady_clock::time_point base = std::chrono::steady_clock::now();
    std::shared_ptr<std::atomic<std::int64_t>> clock_s =
        std::make_shared<std::atomic<std::int64_t>>(0);
    mcp::McpSessionRegistry sessions;
    std::mutex audit_mu;
    /// One captured row, not parallel vectors - the eight other server test files
    /// that capture multi-field audit rows all use a single struct, and parallel
    /// vectors can silently desynchronise.
    struct AuditRow {
        std::string action;
        std::string detail;
        std::string result;
        std::string actor;  ///< empty = the bridge's own background work ("system")
    };
    std::vector<AuditRow> audits;
    std::optional<Bridge> bridge;                             // optional: dtor-order tests

    /// `scfg` defaults to the production session config, so every existing test is
    /// unaffected; a chaos test that needs the replay ring to WRAP passes a small
    /// ring_cap rather than publishing 500 frames to get there.
    explicit Fx(Bridge::Config cfg = {}, mcp::McpSessionRegistry::Config scfg = {})
        : sessions(scfg,
                   [b = base, c = clock_s] { return b + std::chrono::seconds(c->load()); }, &reg) {
        bridge.emplace(&bus, &sessions, &reg,
                       [this](const std::string& action, const std::string&,
                              const std::string& detail,
                              mcp::McpStreamBridge::AuditResult result,
                              const std::string& actor) {
                           std::lock_guard<std::mutex> lk(audit_mu);
                           audits.push_back(
                               {action, detail,
                                result == mcp::McpStreamBridge::AuditResult::kFailure ? "failure"
                                                                                      : "success",
                                actor});
                       },
                       cfg);
    }

    struct Session {
        std::string id;
        std::shared_ptr<mcp::McpStreamState> stream;
    };
    Session make_session(const std::string& principal = "alice") {
        auto minted = sessions.mint(principal);
        REQUIRE(minted.ok);
        auto stream = sessions.stream_for(minted.session_id, principal);
        REQUIRE(stream != nullptr);
        return {minted.session_id, std::move(stream)};
    }

    std::size_t audit_count(const std::string& action) {
        std::lock_guard<std::mutex> lk(audit_mu);
        std::size_t n = 0;
        for (const auto& row : audits) {
            if (row.action == action) {
                ++n;
            }
        }
        return n;
    }
};

/// Snapshot the session ring by attaching at a cursor and copying the replayed
/// sink queue; detaches before returning so later attaches see a free slot.
/// NOTE: a cursor >= a pinned id UNPINS that final (consumption proof) - tests
/// that must not disturb pins snapshot from cursor 0 only when they own the
/// consequences, or use `peek_from` past nothing.
std::vector<mcp::sse_bus::SseEvent> ring_frames(mcp::McpStreamState& st,
                                                         const std::string& principal,
                                                         std::uint64_t cursor = 0) {
    auto att = st.attach_and_replay(cursor, nullptr, principal);
    REQUIRE(att.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::vector<mcp::sse_bus::SseEvent> out;
    {
        std::lock_guard<std::mutex> lk(att.sink->sse->mu);
        out.assign(att.sink->sse->queue.begin(), att.sink->sse->queue.end());
    }
    st.detach(att.sink);
    return out;
}

std::size_t count_method(const std::vector<mcp::sse_bus::SseEvent>& frames,
                         const std::string& method) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.value("method", "") == method) {
            ++n;
        }
    }
    return n;
}

std::size_t count_results(const std::vector<mcp::sse_bus::SseEvent>& frames) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            ++n;
        }
    }
    return n;
}

std::size_t count_error_code(const std::vector<mcp::sse_bus::SseEvent>& frames,
                             int code) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("error") && j["error"].value("code", 0) == code) {
            ++n;
        }
    }
    return n;
}

/// Poll take_post_batch until it yields something. The projector is asynchronous
/// and a streamed record is pump-owned, so the first tick after a publish can
/// legitimately be empty.
inline mcp::McpStreamBridge::PostBatch poll_batch(mcp::McpStreamBridge& bridge,
                                                  const std::string& key) {
    mcp::McpStreamBridge::PostBatch batch;
    poll_until([&] {
        batch = bridge.take_post_batch(key, /*cap_expired=*/false);
        return !batch.progress.empty() || batch.final_frame.has_value();
    });
    return batch;
}

const std::string kProgress13 = R"({"agents_responded":1,"agents_targeted":3})";
const std::string kCompleted = R"({"status":"completed","agents_success":3,"agents_failure":0})";

/// An execution-progress payload with explicit counts (for monotonic-progress tests).
std::string prog(std::uint64_t responded, std::uint64_t targeted) {
    return R"({"agents_responded":)" + std::to_string(responded) + R"(,"agents_targeted":)" +
           std::to_string(targeted) + "}";
}

}  // namespace

TEST_CASE("bridge reserve - every reject reason is truthful and counted", "[mcp][bridge][2f]") {
    SECTION("null bus ⇒ disabled") {
        yuzu::MetricsRegistry reg;
        mcp::McpSessionRegistry sessions{mcp::McpSessionRegistry::Config{}, {}, &reg};
        Bridge b{nullptr, &sessions, &reg};
        auto r = b.reserve("s", "alice", json(1), std::nullopt, false);
        CHECK_FALSE(r.ok);
        CHECK(std::string(r.reject_reason) == "disabled");
        CHECK(reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "disabled"}}).value() == 1.0);
    }
    SECTION("unknown session / wrong principal ⇒ unknown_session (no oracle)") {
        Fx fx;
        auto s = fx.make_session();
        CHECK(std::string(fx.bridge->reserve("nope", "alice", json(1), std::nullopt, false)
                              .reject_reason) == "unknown_session");
        CHECK(std::string(fx.bridge->reserve(s.id, "mallory", json(1), std::nullopt, false)
                              .reject_reason) == "unknown_session");
    }
    SECTION("duplicate key, global cap, pin slots; abandon frees them") {
        Fx fx{Bridge::Config{.global_record_cap = 5, .ring_only_pressure_cap = 64}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true)
                              .reject_reason) == "duplicate_request_id");
        // string "1" is a DIFFERENT key from integer 1
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("1"), json("t"), true).ok);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
        // 4 streamed records on one session: pin slots exhausted
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true)
                              .reject_reason) == "pin_slots");
        // …but a GET-only record is bounded by the global cap only
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), false).ok);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(6), json("t"), false)
                              .reject_reason) == "global_cap");
        CHECK(fx.reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "pin_slots"}}).value() ==
              1.0);
        // abandon a streamed record: both the pin-slot charge and the map slot free up
        REQUIRE(fx.bridge->abandon(s.id, json(1)));
        CHECK(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    }
}

TEST_CASE("bridge arming latch + abandon containment", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-a"));
    CHECK(fx.bus.subscriber_count("exec-a") == 1);

    fx.bus.publish("exec-a", "execution-progress", kProgress13);
    fx.bus.publish("exec-a", "execution-progress", kProgress13);
    fx.bus.publish("exec-a", "agent-transition", "{}");  // never projected
    // kArming latches: nothing reaches the ring no matter how long we wait.
    CHECK_FALSE(poll_until([&] { return s.stream->next_event_id() > 1; },
                           std::chrono::milliseconds(100)));

    REQUIRE(fx.bridge->abandon(s.id, json(1)));
    CHECK(fx.bus.subscriber_count("exec-a") == 0);
    CHECK(fx.bridge->record_count() == 0);
    CHECK(s.stream->next_event_id() == 1);  // ring untouched
    CHECK(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);  // key freed
}

TEST_CASE("bridge progress is strictly monotonic on the wire (H1)", "[mcp][bridge][2f]") {
    // MCP MUST: notifications/progress `progress` increases with each frame.
    // Feed duplicate and DECREASING bus snapshots; only the strictly-increasing
    // subsequence may reach the wire.
    //
    // #2412: progress is now a single latest-wins slot, not a 16-entry ring -
    // a value published before the projector drains the previous one is
    // coalesced away by the LISTENER, before H1 ever runs. Publishing this
    // whole sequence in a tight loop (the old test's shape) would therefore
    // fold {1, 1, 3, 2, 3, 5, 4} down to whatever the last publish happened
    // to be, not the intended {1, 3, 5}. Step-synchronize: wait for each
    // value's expected effect (a new wire frame, or a suppressed-counter
    // tick) before publishing the next, so every value is drained on its own
    // - this isolates H1's projector-side suppression from listener-side
    // coalescing, which the flip-and-drain (H2) test below exercises instead.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-mono"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    // Sequence: 1, 1(dup), 3, 2(decrease), 3(dup), 5, 4(decrease) / total 5.
    // `frame` says whether publishing that value should produce a NEW wire
    // frame (true) or a suppressed-counter tick (false).
    const std::vector<std::pair<unsigned, bool>> steps = {
        {1u, true}, {1u, false}, {3u, true}, {2u, false},
        {3u, false}, {5u, true}, {4u, false},
    };
    std::size_t frames_before = 0;
    double suppressed_before = 0.0;
    for (const auto& [value, frame] : steps) {
        fx.bus.publish("exec-mono", "execution-progress", prog(value, 5));
        if (frame) {
            REQUIRE(poll_until([&] {
                return count_method(ring_frames(*s.stream, "alice"), "notifications/progress") >
                       frames_before;
            }));
            ++frames_before;
        } else {
            REQUIRE(poll_until([&] {
                return fx.reg.counter("yuzu_mcp_bridge_progress_suppressed_total").value() >
                       suppressed_before;
            }));
            suppressed_before += 1.0;
        }
    }
    auto frames = ring_frames(*s.stream, "alice");
    std::vector<std::uint64_t> got;
    std::uint64_t prev = 0;
    for (const auto& f : frames) {
        auto p = json::parse(f.data)["params"]["progress"].get<std::uint64_t>();
        CHECK(p > prev);  // strictly increasing, no duplicate, no decrease
        prev = p;
        got.push_back(p);
    }
    // Named local (not a braced-init inside CHECK) — commas in a macro arg break
    // the MSVC preprocessor (the #2365 comma-in-macro class).
    const std::vector<std::uint64_t> expected{1, 3, 5};
    CHECK(got == expected);
    // #2438: the 4 non-strictly-increasing candidates (1-dup, 2, 3-dup, 4) must
    // each count. Polled: the flush that turns the delta into the registered
    // counter runs on the projector thread, after (not observably-before, from
    // the test thread) the publish this poll_until above already waited on.
    REQUIRE(poll_until([&] {
        return fx.reg.counter("yuzu_mcp_bridge_progress_suppressed_total").value() == 4.0;
    }));
}

TEST_CASE("bridge GET-only lifecycle - live progress, no final, no pin", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(7), json(42), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(7), "exec-g"));
    REQUIRE(fx.bridge->arm(s.id, json(7), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    fx.bus.publish("exec-g", "execution-progress", kProgress13);
    REQUIRE(poll_until([&] { return s.stream->next_event_id() > 1; }));
    {
        auto frames = ring_frames(*s.stream, "alice");
        REQUIRE(frames.size() == 1);
        auto j = json::parse(frames[0].data);
        CHECK(j["method"] == "notifications/progress");
        CHECK(j["params"]["progressToken"] == 42);
        CHECK(j["params"]["progress"] == 1);
        CHECK(j["params"]["total"] == 3);
        CHECK(j["params"]["_meta"]["yuzu.execution_id"] == "exec-g");
    }

    fx.bus.publish("exec-g", "execution-completed", kCompleted, /*is_terminal=*/true);
    fx.bus.publish("exec-g", "execution-completed", kCompleted, /*is_terminal=*/true);  // dup
    REQUIRE(poll_until([&] {
        auto ph = fx.bridge->phase_for(s.id, json(7));
        return ph.has_value() && *ph == Bridge::Phase::kDone;
    }));
    CHECK(s.stream->pinned_count() == 0);  // GET-only: NO final, NO pin
    {
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_results(frames) == 0);
        CHECK(count_method(frames, "notifications/progress") == frames.size());
    }
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
}

TEST_CASE("bridge parked terminal - one pinned final, result_base merged, final is last",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    // #2712: base now carries structuredContent too (as real execute_instruction
    // responses do since batch 3) - the merge below must preserve it untouched
    // alongside the top-level additions, not just the legacy content array.
    const std::string base =
        R"({"content":[{"type":"text","text":"{\"execution_id\":\"exec-p\"}"}],)"
        R"("structuredContent":{"execution_id":"exec-p"}})";
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(9), json("tok"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(9), "exec-p"));
    REQUIRE(fx.bridge->arm(s.id, json(9), Bridge::ArmMode::kStreaming, base) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(9)));

    fx.bus.publish("exec-p", "execution-completed", kCompleted, /*is_terminal=*/true);
    fx.bus.publish("exec-p", "execution-completed", R"({"status":"failed"})",
                   /*is_terminal=*/true);  // dup - must be ignored (write-once terminal)
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    auto frames = ring_frames(*s.stream, "alice");
    REQUIRE(count_results(frames) == 1);
    auto fin = json::parse(frames.back().data);  // the final is LAST
    REQUIRE(fin.contains("result"));
    CHECK(fin["id"] == 9);
    // B5: today's nested result shape survives; additions are TOP-LEVEL result keys.
    CHECK(fin["result"]["content"][0]["type"] == "text");
    CHECK(fin["result"]["status"] == "completed");
    CHECK(fin["result"]["agents_success"] == 3);
    CHECK(fin["result"]["agents_failure"] == 0);
    CHECK_FALSE(fin["result"]["content"][0].contains("status"));
    // #2712: structuredContent is a THIRD top-level result sibling (alongside
    // content and the status/agents_* additions) that must survive the merge
    // completely unchanged - a deliberate, pinned decision (mcp_server.cpp's
    // execute_instruction handler comment), not an accident of construction
    // order.
    REQUIRE(fin["result"].contains("structuredContent"));
    CHECK(fin["result"]["structuredContent"] == json{{"execution_id", "exec-p"}});

    // A7: post-terminal progress (a real publisher sequence) is dropped.
    const auto frames_before = frames.size();
    fx.bus.publish("exec-p", "execution-progress", kProgress13);
    CHECK_FALSE(poll_until([&] { return s.stream->next_event_id() > frames_before + 1; },
                           std::chrono::milliseconds(100)));
}

TEST_CASE("bridge flip-and-drain - no frame strands across arm (H2)", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(2), "exec-h"));
    // DISTINCT strictly-increasing counts (1/12 .. 12/12), published pre-arm
    // (1-4, latched while kArming - project_record never visits a kArming
    // record, so nothing can drain) and concurrently with arm (5-12, racing
    // the flip).
    //
    // #2412: progress is now a single latest-wins slot, not a 16-entry ring -
    // a value overwritten before the projector drains it never reaches the
    // wire; it is counted as suppressed instead (same counter H1 uses, see
    // the field comment on progress_suppressed_delta). The pre-arm run of
    // 1-4 is GUARANTEED to coalesce to a single pending value (nothing can
    // drain during kArming), and the race against the concurrent publisher
    // means the post-arm count of distinct wire frames is genuinely
    // nondeterministic - anywhere from 1 (everything coalesces into the
    // final 12/12) to 9 (the pre-arm batch, plus each of 5-12 individually,
    // if the projector wins every race). What IS deterministic, and what
    // this test asserts, is CONSERVATION: every one of the 12 published
    // values is accounted for exactly once, as either a wire frame or a
    // suppression - never lost, never double-counted - the wire stays
    // strictly increasing, and the LAST published value (12) always survives
    // to be the final frame, because nothing publishes after it.
    for (std::uint64_t i = 1; i <= 4; ++i) {
        fx.bus.publish("exec-h", "execution-progress", prog(i, 12));  // latched pre-arm
    }
    std::atomic<bool> go{false};
    auto publisher = std::async(std::launch::async, [&] {
        go.store(true, std::memory_order_release);
        for (std::uint64_t i = 5; i <= 12; ++i) {
            fx.bus.publish("exec-h", "execution-progress", prog(i, 12));
        }
    });
    while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    REQUIRE(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    publisher.get();
    // Conservation, not an exact frame count (see the comment above for why a
    // count is not deterministic under latest-wins coalescing): this is what
    // proves nothing strands across the arm flip.
    REQUIRE(poll_until([&] {
        return static_cast<double>(
                   count_method(ring_frames(*s.stream, "alice"), "notifications/progress")) +
                   fx.reg.counter("yuzu_mcp_bridge_progress_suppressed_total").value() ==
               12.0;
    }));
    auto frames = ring_frames(*s.stream, "alice");
    const auto frame_count = count_method(frames, "notifications/progress");
    CHECK(frame_count >= 1);
    CHECK(frame_count <= 12);
    // …the wire sequence is strictly increasing (H1) …
    std::uint64_t prev = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data);
        CHECK(j["params"]["progress"].get<std::uint64_t>() > prev);
        prev = j["params"]["progress"].get<std::uint64_t>();
    }
    // …and ends on the last published value - nothing arrives after it, so it
    // always survives to eventually be drained.
    CHECK(prev == 12);
}

TEST_CASE("bridge listener fault - contained, counted, one-shot", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(3), "exec-f"));
    REQUIRE(fx.bridge->arm(s.id, json(3), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    fx.bridge->inject_listener_fault_for_test();
    fx.bus.publish("exec-f", "execution-progress", kProgress13);  // eaten by the fault
    // The bus survives (the boundary held) and the next publish delivers normally.
    fx.bus.publish("exec-f", "execution-progress", kProgress13);
    REQUIRE(poll_until([&] { return s.stream->next_event_id() > 1; }));
    CHECK(ring_frames(*s.stream, "alice").size() == 1);  // exactly one frame - one was eaten
    // The failure is counted record-locally and flushed by the projector.
    REQUIRE(poll_until(
        [&] { return fx.reg.counter("yuzu_mcp_bridge_listener_failures_total").value() == 1.0; }));
}

TEST_CASE("bridge #2411 - a wake dirty-marks only ITS OWN record, not every record",
          "[mcp][bridge][2f][2411]") {
    // Direct proof the projector visits O(dirty), not O(records_): a wake on
    // record A must not re-poke record B's bound sink, even though B's own
    // work is still pending (has_pending_work_locked(B) stays true forever
    // here - nothing ever drains it via take_post_batch). Under the
    // pre-#2411 full-table-scan projector, EVERY wake re-visits EVERY
    // record, so A's wake would re-poke B every time - that asymmetry is the
    // whole assertion, and it is RED on the unfixed tree.
    Fx fx;
    auto a = fx.make_session("alice");
    REQUIRE(fx.bridge->reserve(a.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(a.id, json(1), "exec-2411-a"));
    REQUIRE(fx.bridge->arm(a.id, json(1), Bridge::ArmMode::kGetOnly) ==
            Bridge::ArmOutcome::kArmed);

    auto b = fx.make_session("bob");
    REQUIRE(fx.bridge->reserve(b.id, "bob", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(b.id, json(1), "exec-2411-b"));
    REQUIRE(fx.bridge->arm(b.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    REQUIRE(fx.bridge->bind_post_sink(b.id, json(1), sink).has_value());

    // B's own event: latches, marks B dirty, the projector visits B and
    // pokes the bound sink (has_pending_work_locked is true - nothing ever
    // drains it via take_post_batch in this test, so it stays true for the
    // rest of B's life).
    fx.bus.publish("exec-2411-b", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] { return sink->poked.load(std::memory_order_acquire); }));
    {
        // Reset under sink->mu, the same lock poke_post_sink takes - the
        // established isolation pattern (see CH-16 above) for separating a
        // LATER poke from this setup one.
        std::lock_guard<std::mutex> lk(sink->mu);
        sink->poked.store(false, std::memory_order_release);
    }

    // QUIESCE B before the experiment (#3357). B is marked dirty TWICE during
    // setup - arm() self-marks at the handoff (mcp_stream_bridge.cpp's
    // `mark_dirty(*core_, rec->key)  // the handoff`) and its own publish marks it
    // again. The poll_until(poked) above only proves ONE pass drained a mark for
    // B; if the other is still queued, a later pass - including the one A's
    // publish triggers - still finds B in core_->dirty, visits it, and forwards
    // the wake exactly as designed. That, not a dirty-set leak, is what made this
    // test fail ~6% of runs on Linux and more on the BigMags pool.
    //
    // The precondition this test has always CLAIMED is "B holds pending work and
    // is NOT dirty". Establish it rather than assuming it: drive cycles until B
    // stops being poked. Each publish on A drives one pass; B's marks are finite,
    // so this converges.
    // Each publish carries a DISTINCT progress value: identical progress is
    // deduplicated before the projector ever sees it (progress_suppressed_delta),
    // so repeating prog(1, 3) would drive no cycle and emit no frame.
    //
    // BOUNDED, and the bound is load-bearing. A record that never quiesces is
    // exactly the #2411 regression this test exists to catch, so exceeding the
    // bound must FAIL - an unbounded spin converts that regression into a CI WEDGE
    // (a 600 s meson timeout, surfacing as "suite failed but enumeration re-run
    // reproduced no failing case") instead of a red assertion. Measured: with
    // run_projector's ordinary path forced to a full-table scan, the unbounded
    // version of this loop ran >3500 s instead of ~1 s.
    int seq = 1;
    int settled = 0;
    for (int attempt = 0; settled < 3; ++attempt) {
        INFO("quiesce attempt " << attempt << ": B still poked by a wake on A");
        REQUIRE(attempt < 40);  // #2411 regression, or a genuinely stuck dirty set
        {
            std::lock_guard<std::mutex> lk(sink->mu);
            sink->poked.store(false, std::memory_order_release);
        }
        const double c0 = fx.reg.counter("yuzu_mcp_bridge_projector_cycles_total").value();
        fx.bus.publish("exec-2411-a", "execution-progress", prog(++seq, 100));
        REQUIRE(poll_until([&] {
            return fx.reg.counter("yuzu_mcp_bridge_projector_cycles_total").value() >= c0 + 1.0;
        }));
        settled = sink->poked.load(std::memory_order_acquire) ? 0 : settled + 1;
    }
    {
        std::lock_guard<std::mutex> lk(sink->mu);
        sink->poked.store(false, std::memory_order_release);
    }
    const std::size_t frames_before =
        count_method(ring_frames(*a.stream, "alice"), "notifications/progress");

    // A's event: marks only A dirty. A's frame reaching the wire proves A's
    // own wake WAS processed - the test isn't vacuous.
    fx.bus.publish("exec-2411-a", "execution-progress", prog(++seq, 100));
    REQUIRE(poll_until([&] {
        return count_method(ring_frames(*a.stream, "alice"), "notifications/progress") ==
               frames_before + 1;
    }));

    // B was NOT re-visited as a side effect of A's wake.
    //
    // #3357: this was `CHECK_FALSE(poll_until(poked, 100ms))` - "assert nothing
    // happened for 100 ms" - which is the wrong shape twice over. It false-REDs
    // when a loaded box lets any visit land inside the window, and it false-GREENs
    // if the poke arrives at 101 ms. Note poll_until's own "generous deadline,
    // never false-RED on a loaded CI box" rationale holds only for POSITIVE waits;
    // under CHECK_FALSE the polarity inverts and a LONGER window makes a false red
    // MORE likely. It never failed in 33 GHA-hosted macOS jobs and then failed 3 of
    // 20 once the leg moved to the self-hosted BigMags pool (3fed7c64), reddening
    // dev and PRs that touch nothing near the bridge.
    //
    // Replaced with a driven happens-before barrier on a monotonic signal, so there
    // is no window at all. kMetricProjectorCycles is incremented once per pass,
    // AFTER every project_record in that pass has run, so once it has advanced by
    // one from a value read here, some pass has RUN TO COMPLETION since - and the
    // pass that projected A (which is the only thing that could have poked B) is
    // therefore finished and its effects visible.
    //
    // The extra publish is what makes the barrier terminate: run_projector waits on
    // `cv.wait(lk, work_pending)` with NO periodic tick, so without a new wake the
    // counter would never advance and a bare wait would hang to poll_until's
    // deadline and fail. A is kGetOnly with no bound post sink, so this touches
    // nothing the assertion reads.
    const double cycles_before =
        fx.reg.counter("yuzu_mcp_bridge_projector_cycles_total").value();
    fx.bus.publish("exec-2411-a", "execution-progress", prog(++seq, 100));
    REQUIRE(poll_until([&] {
        return fx.reg.counter("yuzu_mcp_bridge_projector_cycles_total").value() >=
               cycles_before + 1.0;
    }));
    CHECK_FALSE(sink->poked.load(std::memory_order_acquire));
}

TEST_CASE("bridge #2411 - a listener fault on one record still flushes via that record's "
          "own dirty mark",
          "[mcp][bridge][2f][2411]") {
    // The dirty-set drain only visits a record whose OWN key is in
    // core_->dirty - so the listener's catch path needs its OWN mark_dirty
    // call (the one call site #2411 ADDS over the pre-existing wake()), or a
    // fault-eaten event's listener_failure_delta strands forever on a record
    // nothing else ever touches again. The existing "listener fault"
    // test above cannot catch a regression here - its second publish is on
    // the SAME record, so that record's own ordinary activity would flush
    // the delta regardless of whether the catch path marks it dirty.
    Fx fx;
    auto a = fx.make_session("alice");
    REQUIRE(fx.bridge->reserve(a.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(a.id, json(1), "exec-2411-flush-a"));
    REQUIRE(fx.bridge->arm(a.id, json(1), Bridge::ArmMode::kGetOnly) ==
            Bridge::ArmOutcome::kArmed);

    // A harmless first event, drained to the wire before the fault: proves A
    // is fully out of the dirty set (including its arm()-time handoff mark)
    // before the fault-eaten event below, so the ONLY thing that can put A
    // back into the dirty set afterward is the catch path under test - not a
    // stale mark left over from setup.
    fx.bus.publish("exec-2411-flush-a", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] {
        return count_method(ring_frames(*a.stream, "alice"), "notifications/progress") == 1;
    }));

    auto b = fx.make_session("bob");
    REQUIRE(fx.bridge->reserve(b.id, "bob", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(b.id, json(1), "exec-2411-flush-b"));
    REQUIRE(fx.bridge->arm(b.id, json(1), Bridge::ArmMode::kGetOnly) ==
            Bridge::ArmOutcome::kArmed);

    fx.bridge->inject_listener_fault_for_test();  // one-shot, shared WakeCore
    fx.bus.publish("exec-2411-flush-a", "execution-progress", prog(2, 3));  // eaten

    // B only, never A again. The pre-#2411 full-table-scan projector would
    // have flushed A's delta as a side effect of visiting every record on
    // B's wake; a dirty-set without the catch-path mark_dirty call strands
    // it, because nothing ever puts A's key back into core_->dirty.
    fx.bus.publish("exec-2411-flush-b", "execution-progress", prog(1, 3));
    REQUIRE(poll_until(
        [&] { return fx.reg.counter("yuzu_mcp_bridge_listener_failures_total").value() == 1.0; }));
}

TEST_CASE("bridge immediate terminal via replay - subscribe after completion",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    // The execution completed BEFORE anyone subscribed (the operator-cancel /
    // instant-execution class). subscribe_and_replay(0) routes the buffered
    // terminal through the normal listener.
    fx.bus.publish("exec-i", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(4), "exec-i"));
    REQUIRE(fx.bridge->arm(s.id, json(4), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(4)));
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    CHECK(count_results(ring_frames(*s.stream, "alice")) == 1);
}

TEST_CASE("bridge second-thread terminal vs park (TSan)", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(5), "exec-t"));
    auto flood = std::async(std::launch::async, [&] {
        for (int i = 0; i < 20; ++i) {  // enough to race the arm; keeps Windows-debug wall-clock low
            fx.bus.publish("exec-t", "execution-progress", kProgress13);
        }
        fx.bus.publish("exec-t", "execution-completed", kCompleted, /*is_terminal=*/true);
    });
    REQUIRE(fx.bridge->arm(s.id, json(5), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(5)));
    flood.get();
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_results(frames) == 1);
    // The final is last on the ring, whatever the flood's latest-wins progress
    // slot happened to still hold when it was drained.
    CHECK(json::parse(frames.back().data).contains("result"));
}

TEST_CASE("bridge pin-ack sweep - resume consumption frees streamed admission",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    std::vector<std::uint64_t> pinned;
    for (int i = 1; i <= 4; ++i) {
        const std::string exec = "exec-pin-" + std::to_string(i);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until(
            [&, i] { return s.stream->pinned_count() == static_cast<std::size_t>(i); }));
    }
    // No pre-resume reserve probe here any more. These four records are parked
    // with COMMITTED, UNDELIVERED finals - exactly the state #2740's admission
    // displacement now reclaims a slot from - so a fifth reserve at this point
    // would succeed by unpinning one of them and perturb the very pin set this
    // test is about. Lockout-versus-displacement is asserted in the #2740 case;
    // what THIS test owns is that a resume ack frees admission on its own, which
    // the displacement counter below pins.

    // Find the SMALLEST pinned id and consume exactly it via a resume cursor
    // (Last-Event-ID >= pinned_id is the consumption proof).
    std::uint64_t smallest = 0;
    for (std::uint64_t id = 1; id < s.stream->next_event_id(); ++id) {
        if (s.stream->is_pinned(id)) {
            smallest = id;
            break;
        }
    }
    REQUIRE(smallest != 0);
    auto att = s.stream->attach_and_replay(smallest, nullptr, "alice");
    REQUIRE(att.status == mcp::McpStreamState::AttachStatus::kAttached);
    s.stream->detach(att.sink);
    CHECK(s.stream->pinned_count() == 3);

    // The reaped record is exec-pin-1: pins are published in loop order, so the
    // smallest pinned id is the first record's final.
    REQUIRE(fx.bus.subscriber_count("exec-pin-1") == 1);
    fx.bridge->sweep();  // pin-ack teardown reaps the consumed record
    CHECK(fx.bridge->record_count() == 3);
    // record_count alone would also pass if the WRONG key were erased, so name it.
    CHECK_FALSE(fx.bridge->phase_for(s.id, json(1)).has_value());
    CHECK(fx.bridge->phase_for(s.id, json(2)).has_value());
    CHECK(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    // ...and it was admitted by the ACK, not by #2740's displacement: with three
    // pins against a cap of four the admission sum is already under water, so no
    // pin was released to make room. Without this the assertion above would pass
    // even if the resume path had stopped freeing anything at all.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value() == 0.0);
    CHECK(fx.audit_count("mcp.bridge.pin_acked") == 1);
    // #2487: teardown owns THREE things - the map entry, the streamed charge, and
    // the bus subscription. The two lines above cover the first two; without this
    // one a teardown that erased the record while leaving its listener installed
    // would pass. That listener would keep a shared_ptr to the record alive, keep
    // waking it, be unreachable from shutdown() (which walks records_), and block
    // channel GC forever (it requires listeners.empty()).
    CHECK(fx.bus.subscriber_count("exec-pin-1") == 0);
    CHECK(fx.bus.subscriber_count("exec-pin-2") == 1);  // siblings untouched
    CHECK(fx.bus.subscriber_count("exec-pin-3") == 1);
    CHECK(fx.bus.subscriber_count("exec-pin-4") == 1);
}

TEST_CASE("bridge admission - client-gone finals never lock a session out of streaming (#2740)",
          "[mcp][bridge][2f][ch24]") {
    // A streamed POST whose peer dies before the final is written leaves that
    // final PINNED: the prompt release (on_final_written) is reached only after
    // write_all succeeds, and the remaining routes - a GET resume acking past the
    // pinned id, or session death - both need a channel a POST-only client does
    // not have. Four such calls used to exhaust the session's four slots forever,
    // answering 429 with "wait for one to finish" while nothing was in flight and
    // every conforming 30s retry slid the session TTL so it never idled out.
    //
    // The helper builds exactly that state: park the record (peer gone), THEN let
    // the terminal land, so the final is committed and pinned with no wire to
    // take it.
    Fx fx;
    auto s = fx.make_session();
    const auto park_with_undelivered_final = [&](int id) {
        const std::string exec = "exec-gone-" + std::to_string(id);
        // Retry a pin_slots reject rather than REQUIREing the first attempt: the
        // admission sum transiently reads one settling record as two slots (the
        // pin commits before the charge clears, both inside one projection
        // claim), and reserve fails CLOSED on that reading by design. A real
        // client does exactly this on its Retry-After. Without the retry this
        // setup is flaky for a reason that has nothing to do with what the
        // sections below assert.
        REQUIRE(poll_until([&] { return fx.bridge->reserve(s.id, "alice", json(id),
                                                           json("t"), true).ok; }));
        REQUIRE(fx.bridge->subscribe(s.id, json(id), exec));
        REQUIRE(fx.bridge->arm(s.id, json(id), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(id)));  // peer gone, no final written
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        // Settle before the next reserve, so each park contributes exactly one
        // slot when the next one is admitted.
        REQUIRE(poll_until([&] {
            return s.stream->pinned_count() == static_cast<std::size_t>(id);
        }));
    };
    const auto displaced_count = [&] {
        return fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
    };

    SECTION("four client-gone calls leave a fifth admissible") {
        for (int i = 1; i <= 4; ++i) {
            park_with_undelivered_final(i);
        }
        // the helper already settled each park; nothing further to wait for
        auto fifth = fx.bridge->reserve(s.id, "alice", json(5), json("t"), true);
        CHECK(fifth.ok);
        CHECK(displaced_count() == 1.0);
        CHECK(fx.audit_count("mcp.bridge.pin_displaced_for_admission") == 1);
        // The OLDEST parked record yields - its resume window is the one most
        // likely already gone - and the result stays fetchable by execution_id.
        CHECK(s.stream->pinned_count() == 3);
        // The lockout is gone for good, not merely deferred by one: each further
        // client-gone call displaces the next-oldest rather than refusing.
        for (int i = 6; i <= 8; ++i) {
            auto rr = fx.bridge->reserve(s.id, "alice", json(i), json("t"), true);
            INFO("reserve " << i << " reject="
                            << (rr.reject_reason == nullptr ? "none" : rr.reject_reason)
                            << " pinned=" << s.stream->pinned_count());
            CHECK(rr.ok);
        }
    }

    SECTION("a displaced final is unpinned, NOT erased - a resume can still collect it") {
        for (int i = 1; i <= 4; ++i) {
            park_with_undelivered_final(i);
        }
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 4; }));
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
        // Displacement removes the eviction EXEMPTION, nothing more: the frame is
        // still in the ring, so a resume from before it still replays it. This is
        // the whole reason displacement is acceptable rather than data loss.
        CHECK(count_results(ring_frames(*s.stream, "alice")) == 4);
    }

    SECTION("live streamed calls are never displaced - the concurrency limit still bites") {
        // Four records still kStreaming with their finals in flight: no pin here
        // belongs to an abandoned response, so the fifth must be REFUSED, and the
        // refusal must say so in terms that are true.
        for (int i = 1; i <= 4; ++i) {
            const std::string exec = "exec-live-" + std::to_string(i);
            REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
            REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
            REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                    Bridge::ArmOutcome::kArmed);
        }
        auto fifth = fx.bridge->reserve(s.id, "alice", json(5), json("t"), true);
        CHECK_FALSE(fifth.ok);
        CHECK(std::string(fifth.reject_reason == nullptr ? "" : fifth.reject_reason) ==
              "pin_slots");
        // Charges outstanding, so "wait for one to finish" is the true advice.
        CHECK(fifth.pin_slots_held == Bridge::PinSlotsHeld::kCharges);
        CHECK(displaced_count() == 0.0);
    }

    SECTION("a mixed set displaces only the parked pin and leaves a live one alone") {
        for (int i = 1; i <= 3; ++i) {
            park_with_undelivered_final(i);
        }
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 3; }));
        // A fourth call that is genuinely LIVE: armed, streaming, no terminal yet,
        // so it holds a charge rather than a pin. Three pins plus this one charge
        // is the cap, which is what puts admission on the reject path at all.
        const std::string live = "exec-live-4";
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(4), live));
        REQUIRE(fx.bridge->arm(s.id, json(4), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);

        // Capture the parked pins BEFORE admission so the survivor set is checked
        // by id rather than by count.
        std::vector<std::uint64_t> parked;
        for (std::uint64_t id = 1; id < s.stream->next_event_id(); ++id) {
            if (s.stream->is_pinned(id)) {
                parked.push_back(id);
            }
        }
        REQUIRE(parked.size() == 3);  // the live call holds a charge, not a pin
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
        CHECK(displaced_count() == 1.0);
        CHECK_FALSE(s.stream->is_pinned(parked.front()));  // oldest parked displaced
        CHECK(s.stream->is_pinned(parked[1]));             // the others untouched
        CHECK(s.stream->is_pinned(parked[2]));
        // The live call is not a candidate at any point: it is still streaming and
        // its final has not been committed, let alone abandoned.
        CHECK(fx.bridge->phase_for(s.id, json(4)) == Bridge::Phase::kStreaming);
    }

    SECTION("a late on_final_written for a displaced record is a no-op, and the sweep reaps it") {
        for (int i = 1; i <= 4; ++i) {
            park_with_undelivered_final(i);
        }
        auto victim_key = fx.bridge->record_key(s.id, json(1));
        REQUIRE(victim_key.has_value());
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);

        // A pump that comes back from the dead after its record was displaced must
        // not resurrect anything: the unpin is id-targeted and the id is already
        // released, so this is a no-op, and the record is then reapable by the
        // sweep's pin-ack arm (final_published, pin gone) exactly as if a resume
        // had acked it. This is what makes displacement self-cleaning.
        CHECK(fx.bridge->on_final_written(*victim_key));
        fx.bridge->sweep();
        CHECK_FALSE(fx.bridge->phase_for(s.id, json(1)).has_value());
        CHECK(fx.bridge->phase_for(s.id, json(2)).has_value());  // siblings untouched
    }
}

TEST_CASE("bridge admission - ORPHAN pins are reclaimed too (governance UP-1)",
          "[mcp][bridge][2f][ch24]") {
    // The lockout shape a RECORD scan can never see. Teardown erases a record
    // without unpinning, so its committed final stays pinned with nothing left
    // that could ever release it: the sweep's pin-ack arm needs a record,
    // on_final_written needs a record, and a cursor-less GET resume releases
    // nothing (rule 1b only unpins for a cursor at or above the pinned id). Four
    // of these lock the session out of streamed POST permanently - and unlike the
    // parked-record case, the session stays alive, so even session death does not
    // clear it. `ring_only_pressure_cap = 0` makes the sweep tear a parked record
    // down on sight, which is the production path (pressure) that produces these.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    const auto displaced_total = [&] {
        return fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
    };

    for (int i = 1; i <= 4; ++i) {
        const std::string exec = "exec-orphan-" + std::to_string(i);
        REQUIRE(poll_until([&] {
            return fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok;
        }));
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));  // peer gone, no final written
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] {
            return s.stream->pinned_count() == static_cast<std::size_t>(i);
        }));
        // The pressure teardown erases the record and leaves the pin behind.
        REQUIRE(poll_until([&] {
            fx.bridge->sweep();
            return !fx.bridge->phase_for(s.id, json(i)).has_value();
        }));
    }
    REQUIRE(s.stream->pinned_count() == 4);   // four pins...
    REQUIRE(fx.bridge->record_count() == 0);  // ...and not one record to find them by

    // Admission must reclaim one anyway.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(9), json("t"), true).ok);
    CHECK(displaced_total() == 1.0);
    CHECK(s.stream->pinned_count() == 3);
    CHECK(fx.audit_count("mcp.bridge.pin_displaced_for_admission") == 1);
}

TEST_CASE("bridge pressure - oldest without a terminal gets -32014; a real final is never lost",
          "[mcp][bridge][2f]") {
    SECTION("victim without a terminal: synthesized, pinned, carries the durable handle") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        // Record A (older): parked, never completes.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-old"));
        REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
        // Record B (newer): parked with a real pinned final.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-new"));
        REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
        fx.bus.publish("exec-new", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

        REQUIRE(fx.bridge->ring_only_count() == 2);
        fx.bridge->sweep();
        CHECK(fx.bridge->ring_only_count() == 1);
        CHECK_FALSE(fx.bridge->phase_for(s.id, json("a")).has_value());  // A erased
        CHECK(fx.bridge->phase_for(s.id, json("b")).has_value());        // B untouched

        auto frames = ring_frames(*s.stream, "alice");
        REQUIRE(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 1);
        for (const auto& f : frames) {
            auto j = json::parse(f.data);
            if (j.contains("error")) {
                CHECK(j["id"] == "a");  // echoed request id
                const auto& data = j["error"]["data"];  // A4 object, embedded raw
                REQUIRE(data.is_object());
                CHECK(data["execution_id"] == "exec-old");
                CHECK(data.contains("correlation_id"));
                CHECK(s.stream->is_pinned(f.id));  // resume-replayable
            }
        }
        CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);
        // Real final of B still pinned and present.
        CHECK(count_results(frames) == 1);
        CHECK(s.stream->pinned_count() == 2);  // B's real final + A's synthesized one
    }
    SECTION("victim WITH a settled real final: torn down, NO synthesis, pin survives") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-s"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        fx.bus.publish("exec-s", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
        std::uint64_t final_id = 0;
        for (std::uint64_t id = 1; id < s.stream->next_event_id(); ++id) {
            if (s.stream->is_pinned(id)) {
                final_id = id;
            }
        }
        REQUIRE(final_id != 0);

        REQUIRE(poll_until([&] {
            fx.bridge->sweep();
            return fx.bridge->record_count() == 0;
        }));
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);  // no synthesis
        CHECK(count_results(frames) == 1);
        CHECK(s.stream->is_pinned(final_id));  // truth stays in the ring
        // sre-N1 (#2489): the "client lost nothing" disposition, counted as such -
        // the label set is closed, so it must be reachable at its real producer.
        CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total", {{"disposition", "none"}})
                  .value() == 1.0);
    }
    SECTION("terminal racing the pressure sweep: the real result always wins") {
        // The terminal is LATCHED before the sweeper starts (the listener runs
        // synchronously inside publish under ch->mu), so ch->terminal is true from
        // the first visit -> the sweep can never see kNeverTerminal and never
        // synthesizes -32014. The race that remains (and that TSan exercises) is
        // sweep vs the PROJECTOR settling that latched terminal: ONE real final,
        // ZERO -32014, reaped. NOTE: publishing the terminal AFTER spawning the
        // sweeper is a genuine sweeper-beats-publish startup race whose -32014 (over
        // a not-yet-published terminal) is a SOUND linearization, not a bug - so it
        // must not be asserted against; publish-then-race keeps the invariant exact.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-r"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        for (int i = 0; i < 3; ++i) {
            fx.bus.publish("exec-r", "execution-progress", kProgress13);
        }
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        fx.bus.publish("exec-r", "execution-completed", kCompleted, /*is_terminal=*/true);
        // Bounded sweeper: a regression that never reaps must FAIL FAST (a wall-
        // clock deadline), not hang CI forever (governance quality).
        auto sweeper = std::async(std::launch::async, [&] {
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (fx.bridge->record_count() != 0) {
                if (std::chrono::steady_clock::now() >= until) {
                    return false;
                }
                fx.bridge->sweep();
                std::this_thread::yield();
            }
            return true;
        });
        REQUIRE(sweeper.get());  // reaped within the deadline
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);
        CHECK(count_results(frames) == 1);
    }
}

TEST_CASE("bridge pressure #2409 - a terminal-flagged progress is never lost to -32014",
          "[mcp][bridge][2f][2409]") {
    // The regression that closes #2409. refresh_counts publishes a terminal-flagged
    // execution-progress BEFORE execution-completed (two publishes, ch->mu released
    // between). The bridge listener latches ONLY execution-completed, so
    // terminal_accepted stays FALSE while the BUS channel is terminal with a
    // buffered, usable payload. The pre-C5 pressure sweep (unsubscribe, then a
    // terminal_accepted re-check blind to the bus) synthesized -32014 over that real
    // terminal. The first_terminal_id marker + the atomic visit must instead secure
    // the buffered terminal and publish the REAL final.
    //
    // Under the pre-C5 code this asserts 0 results / 1 error - i.e. it FAILS,
    // exactly the property a regression test must have.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-2409"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    // The terminal-flagged progress: bus terminal=true, listener does NOT latch it.
    fx.bus.publish(
        "exec-2409", "execution-progress",
        R"({"status":"succeeded","agents_responded":3,"agents_targeted":3,"agents_success":3,"agents_failure":0})",
        /*is_terminal=*/true);
    REQUIRE(poll_until([&] {
        fx.bridge->sweep();
        return fx.bridge->record_count() == 0;
    }));
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);  // NEVER -32014
    CHECK(count_results(frames) == 1);                                   // a REAL final instead
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            CHECK(j["result"]["status"] == "succeeded");  // built from the marked payload
        }
    }
    CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);
}

TEST_CASE("bridge pressure - kTerminalKnownLost publishes the fallback final, never -32014 (#2409 qa-B1)",
          "[mcp][bridge][2f][2409]") {
    // End-to-end bridge coverage of the aged-out-terminal disposition: the marker
    // ages out of the bus buffer, the visit computes kTerminalKnownLost, and the
    // bridge publishes the success-shaped fallback ("fetch by execution_id"), NEVER
    // -32014 - releasing the streamed charge and auditing the disposition.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-kl"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    // Terminal-flagged execution-progress: the bus is terminal, but the listener
    // latches ONLY execution-completed, so terminal_accepted stays false. Flood past
    // kBufferCap so the marker (id 1) ages out with NO execution-completed ever
    // published -> the visit computes kTerminalKnownLost.
    fx.bus.publish("exec-kl", "execution-progress",
                   R"({"status":"succeeded","agents_success":1,"agents_failure":0})",
                   /*is_terminal=*/true);
    for (int i = 0; i < static_cast<int>(yuzu::server::ExecutionEventBus::kBufferCap) + 5; ++i) {
        fx.bus.publish("exec-kl", "execution-progress", kProgress13);
    }
    REQUIRE(poll_until([&] {
        fx.bridge->sweep();
        return !fx.bridge->phase_for(s.id, json(1)).has_value();  // record 1 reaped
    }));
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);  // NEVER -32014
    REQUIRE(count_results(frames) == 1);                                 // the success-shaped fallback
    std::uint64_t fallback_id = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            CHECK(j["result"]["execution_id"] == "exec-kl");  // durable handle present
            CHECK(j["result"]["status"] == "unknown");        // fallback shape, not a real status
            fallback_id = f.id;
        }
    }
    CHECK(s.stream->is_pinned(fallback_id));  // pinned -> resume-replayable
    {  // the audit names the disposition (not an empty/synthesized detail)
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        bool ok = false;
        for (const auto& row : fx.audits) {
            if (row.action == "mcp.bridge.forced_expire" &&
                row.detail == "the fallback final was published") {
                ok = true;
            }
        }
        CHECK(ok);
    }
    // sre-N1 (#2489): and it is now countable, which the audit row is not. This is
    // the disposition an operator most needs to watch - a rising rate means records
    // are parking for longer than the bus buffer holds their terminal.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total",
                         {{"disposition", "fallback_final"}})
              .value() == 1.0);
    // Charge released: teardown_claimed already released the streamed charge
    // synchronously when it reaped record 1 (streamed_unpinned_ back to 0); the pinned
    // fallback still holds one slot, which the resume cursor below consumes. With BOTH
    // freed, all 4 fresh streamed reserves admit. Had the charge leaked, streamed_
    // unpinned_ would still be 1 and the 4th reserve would be rejected pin_slots - so
    // the 4th admitting is the load-bearing release_charge regression guard.
    auto att = s.stream->attach_and_replay(fallback_id, nullptr, "alice");
    REQUIRE(att.status == mcp::McpStreamState::AttachStatus::kAttached);
    s.stream->detach(att.sink);
    CHECK(s.stream->pinned_count() == 0);
    CHECK(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);  // 4th slot: only free if charge released
}

TEST_CASE("bridge pressure - a visitor copy-OOM defers and keeps the listener (#2409 safety-S1)",
          "[mcp][bridge][2f][2409]") {
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-oom"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    // Terminal-flagged progress -> the visit's verdict is kTerminalBuffered (marker in
    // buffer; terminal_accepted still false because the listener ignores progress).
    fx.bus.publish("exec-oom", "execution-progress",
                   R"({"status":"succeeded","agents_success":1,"agents_failure":0})",
                   /*is_terminal=*/true);
    REQUIRE(fx.bus.subscriber_count("exec-oom") == 1);
    // PERSISTENT copy-OOM: every visitor terminal-payload copy throws. This is the
    // self-validating part - while the fault fires the copy never latches, so the
    // record can NEVER settle no matter how many sweeps run. (If the injection were a
    // silent no-op, the very first sweep would latch + settle + reap, and the
    // still-alive assertion below would fail RED.)
    fx.bridge->inject_visit_copy_fault_for_test(/*times=*/100);
    for (int i = 0; i < 15; ++i) {
        fx.bridge->sweep();
        REQUIRE(fx.bridge->record_count() == 1);                   // never reaped under the fault
        REQUIRE(fx.bus.subscriber_count("exec-oom") == 1);         // listener NOT erased (defer, no claim)
    }
    CHECK(count_results(ring_frames(*s.stream, "alice")) == 0);    // never settled a final
    CHECK(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 0);
    // Heal the fault: now the copy succeeds, the terminal latches, and the record
    // settles the REAL final and reaps.
    fx.bridge->inject_visit_copy_fault_for_test(/*times=*/0);
    REQUIRE(poll_until([&] {
        fx.bridge->sweep();
        return fx.bridge->record_count() == 0;
    }));
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);
    CHECK(count_results(frames) == 1);  // the real final, after the fault healed
}

namespace {

/// A + B parked into one session, A first so it owns the lower parked_seq and is
/// therefore the victim pass 3 picks first. A's verdict is kTerminalBuffered (a
/// terminal-flagged progress the listener does not latch); B never reaches a
/// terminal at all, so its visit is an unambiguous claim. Paired with a PERSISTENT
/// visitor copy fault this is a deterministic "oldest defers forever, newer is
/// reapable" shape - the only one that tells the two #2489 pressure defects apart.
void park_deferring_a_and_claimable_b(Fx& fx, Fx::Session& s) {
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-a"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(2), "exec-b"));
    REQUIRE(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(2)));
    fx.bus.publish("exec-a", "execution-progress",
                   R"({"status":"succeeded","agents_success":1,"agents_failure":0})",
                   /*is_terminal=*/true);
    // PERSISTENT: while it fires, A's terminal copy never latches, so A can never be
    // claimed however many sweeps run. That is the self-validating half of both
    // tests below - any reap they observe is necessarily B's.
    fx.bridge->inject_visit_copy_fault_for_test(/*times=*/100);
}

}  // namespace

TEST_CASE("bridge pressure - a deferred victim no longer blocks relief for the newer ones "
          "(#2489 UP-5)",
          "[mcp][bridge][2f][2489]") {
    // Pass 3 used to wake-and-RETURN on any defer, and it always picks the OLDEST
    // victim first - so one record caught perpetually mid-projection held the escape
    // hatch shut for every newer victim behind it. Per record the defer is bounded;
    // in aggregate, sustained pressure got no relief at all.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    park_deferring_a_and_claimable_b(fx, s);

    fx.bridge->sweep();

    // B reaped THROUGH the deferring A, in ONE sweep. Before UP-5: 2, forever.
    CHECK(fx.bridge->record_count() == 1);
    CHECK(fx.bridge->phase_for(s.id, json(1)).has_value());        // A survives...
    CHECK_FALSE(fx.bridge->phase_for(s.id, json(2)).has_value());  // ...B does not
    CHECK(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 1);
    // sre-N1 (#2489): which disposition it was is now readable from metrics, not
    // only from an audit row nothing scrapes.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total",
                         {{"disposition", "synthesize_unavailable"}})
              .value() == 1.0);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total", {{"disposition", "none"}})
              .value() == 0.0);

    // A is genuinely unreapable while the fault fires, which is what makes the reap
    // above attributable to the advance rather than to A settling early.
    for (int i = 0; i < 10; ++i) {
        fx.bridge->sweep();
    }
    CHECK(fx.bridge->record_count() == 1);
}

TEST_CASE("bridge pressure - a mark does not outlive the pressure that raised it "
          "(#2489 UP-4, TSan)",
          "[mcp][bridge][2f][2489]") {
    // pressure_requested tells the projector to start no NEW progress batch for a
    // victim. Nothing cleared it, so a victim that was marked and then survived -
    // because the cap went back under water before its turn came round - had its
    // progress frozen for the REST of its execution. The terminal still settles
    // (want_terminal is ungated), which is precisely why the freeze is silent: a
    // parked GET-resume client watching a long run simply stops seeing movement.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    park_deferring_a_and_claimable_b(fx, s);

    fx.bridge->sweep();  // A marked and deferred; B reaped -> cap back under water
    REQUIRE(fx.bridge->record_count() == 1);
    REQUIRE(fx.bridge->phase_for(s.id, json(1)).has_value());

    // A strictly-higher progress value than anything published so far. Monotonic
    // suppression (H1) means a frame carrying 2 can ONLY have come from this
    // publish, so the assertion cannot be satisfied by a frame the projector had
    // already emitted before the sweep - no ordering assumption needed.
    fx.bus.publish("exec-a", "execution-progress", prog(2, 3));
    CHECK(poll_until([&] {
        for (const auto& f : ring_frames(*s.stream, "alice")) {
            auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
            if (j.is_object() && j.value("method", "") == "notifications/progress" &&
                j["params"].value("progress", 0) == 2) {
                return true;
            }
        }
        return false;
    }));
}

TEST_CASE("bridge pressure - one sweep expires exactly down to the cap, no further "
          "(Doomgoose, PR #2781 review)",
          "[mcp][bridge][2f][2489]") {
    // The single-scan-and-sort refactor removes the per-victim cap re-check the
    // previous rescan-per-victim shape had; this pins that the replacement (a
    // pass-local live count, decremented per teardown THIS pass commits) still
    // stops at exactly the cap rather than draining every eligible candidate. No
    // prior test caught this - the existing pressure tests all use cap 0 or 1,
    // where "stop at the cap" and "reap everything eligible" are indistinguishable.
    //
    // 6 claimable (unambiguously reapable - no bus publish, so the verdict is
    // kNeverTerminal -> synthesize_unavailable on first visit) records parked
    // oldest-first across two sessions (streamed admission caps at 4 pin slots
    // PER SESSION, so 6 in one session is not constructible). Cap 2: exactly 4
    // must be reaped, 2 - the two parked LAST, since sweep visits oldest-first -
    // must survive this single sweep.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 2}};
    auto s1 = fx.make_session();
    auto s2 = fx.make_session();
    struct Victim {
        Fx::Session* s;
        nlohmann::json id;
    };
    const std::vector<Victim> victims = {
        {&s1, json(1)}, {&s1, json(2)}, {&s1, json(3)},
        {&s2, json(1)}, {&s2, json(2)}, {&s2, json(3)},
    };
    int n = 0;
    for (const auto& v : victims) {
        const std::string exec_id = "exec-cap-" + std::to_string(++n);
        REQUIRE(fx.bridge->reserve(v.s->id, "alice", v.id, json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(v.s->id, v.id, exec_id));
        REQUIRE(fx.bridge->arm(v.s->id, v.id, Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
    }
    // Park in the SAME order as the reserve loop above, so parked_seq matches
    // victims[] order exactly - the first four are the ones sweep must reap.
    for (const auto& v : victims) {
        REQUIRE(fx.bridge->on_post_closed(v.s->id, v.id));
    }
    REQUIRE(fx.bridge->record_count() == 6);

    fx.bridge->sweep();

    CHECK(fx.bridge->record_count() == 2);
    CHECK_FALSE(fx.bridge->phase_for(s1.id, json(1)).has_value());  // reaped (1st parked)
    CHECK_FALSE(fx.bridge->phase_for(s1.id, json(2)).has_value());  // reaped (2nd parked)
    CHECK_FALSE(fx.bridge->phase_for(s1.id, json(3)).has_value());  // reaped (3rd parked)
    CHECK_FALSE(fx.bridge->phase_for(s2.id, json(1)).has_value());  // reaped (4th parked)
    CHECK(fx.bridge->phase_for(s2.id, json(2)) == Bridge::Phase::kRingOnly);  // survives (5th)
    CHECK(fx.bridge->phase_for(s2.id, json(3)) == Bridge::Phase::kRingOnly);  // survives (6th)
    CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total",
                         {{"disposition", "synthesize_unavailable"}})
              .value() == 4.0);
    // The hatch stopped BECAUSE the cap was satisfied, not because it ran out of
    // budget or candidates with the cap still exceeded - the exhausted counter
    // must NOT fire.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_pressure_budget_exhausted_total").value() == 0.0);
}

TEST_CASE("bridge pressure - deferred victims consume visit budget without decrementing "
          "live, so a defer-heavy pass still reports budget-exhausted "
          "(quality-engineer + unhappy-path UP-3, wave 4)",
          "[mcp][bridge][2f][2489]") {
    // The down-to-cap test above (and the population-bound TSan test below) both use
    // an all-claimable population, so `live` (decremented only by a teardown THIS
    // pass commits) and `visit_budget` (decremented on every visit, claimed or
    // deferred alike) move in lockstep and neither test can tell them apart - flagged
    // independently by quality-engineer and unhappy-path's UP-3 in the same wave-4
    // review. This one can, and specifically because all 3 defers are parked - and
    // therefore visited - before either claim: a candidate that goes UNVISITED stays
    // parked exactly like one that was visited and then deferred (nothing touches an
    // unvisited candidate), so the two orderings are indistinguishable UNLESS a
    // miscounted `live` causes the loop to exit before every candidate is reached -
    // which can only strand a claim if the claims sit AFTER the point of that early
    // exit. Mutation-verified (governance.d/2f-pr3b-dormant.e331oX.jsonl, W4-1): an
    // unconditional extra `live` decrement per visit made this test fail exactly as
    // predicted (record_count 4 instead of 3, the second claim left in kRingOnly,
    // forced_expire{synthesize_unavailable} 1.0 instead of 2.0) before the mutation
    // was reverted.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s1 = fx.make_session();
    auto s2 = fx.make_session();

    auto park_deferring = [&](Fx::Session& s, const std::string& exec, int slot) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(slot), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(slot), exec));
        REQUIRE(fx.bridge->arm(s.id, json(slot), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(slot)));
        fx.bus.publish(exec, "execution-progress",
                       R"({"status":"succeeded","agents_success":1,"agents_failure":0})",
                       /*is_terminal=*/true);
    };
    auto park_claimable = [&](Fx::Session& s, const std::string& exec, int slot) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(slot), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(slot), exec));
        REQUIRE(fx.bridge->arm(s.id, json(slot), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(slot)));
        // No publish: bus verdict is kNeverTerminal -> synthesize_unavailable, an
        // unambiguous claim on first visit.
    };
    // Parked (and therefore visited, oldest-first) in this exact order: all 3
    // defers, THEN both claims.
    park_deferring(s1, "exec-def-1", 1);
    park_deferring(s1, "exec-def-2", 2);
    park_deferring(s2, "exec-def-3", 1);
    park_claimable(s1, "exec-claim-1", 3);
    park_claimable(s1, "exec-claim-2", 4);
    // PERSISTENT: while it fires, none of the 3 deferring records' terminal copies
    // ever latch, so none can be claimed however many sweeps run - the same
    // self-validating fault this file uses for every other defer scenario.
    fx.bridge->inject_visit_copy_fault_for_test(/*times=*/100);
    REQUIRE(fx.bridge->record_count() == 5);

    fx.bridge->sweep();

    // Both claimable records reaped; all 3 deferring records survive - visited (and
    // marked) but never claimed, exhausting visit_budget rather than satisfying live.
    CHECK(fx.bridge->record_count() == 3);
    CHECK(fx.bridge->phase_for(s1.id, json(1)) == Bridge::Phase::kRingOnly);
    CHECK(fx.bridge->phase_for(s1.id, json(2)) == Bridge::Phase::kRingOnly);
    CHECK(fx.bridge->phase_for(s2.id, json(1)) == Bridge::Phase::kRingOnly);
    CHECK_FALSE(fx.bridge->phase_for(s1.id, json(3)).has_value());
    CHECK_FALSE(fx.bridge->phase_for(s1.id, json(4)).has_value());
    CHECK(fx.reg.counter("yuzu_mcp_bridge_forced_expire_total",
                         {{"disposition", "synthesize_unavailable"}})
              .value() == 2.0);
    // The hatch disengaged with the cap STILL exceeded (3 > 1) - budget/candidates
    // exhausted on a population `live` alone would have under-reported as satisfied
    // only once every defer resolves, which this fault deliberately never does.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_pressure_budget_exhausted_total").value() == 1.0);
}

TEST_CASE("bridge pressure - one sweep is bounded by the population it started with "
          "(#2489 review, TSan)",
          "[mcp][bridge][2f][2489]") {
    // The parked_seq floor bounds a pass against the records it STARTED with, but a
    // record that parks mid-pass gets a HIGHER parked_seq, so it lands above the
    // floor and stays eligible. Under sustained parking the cap never falls back
    // under water and the pass would keep finding fresh victims - one maintenance
    // tick doing unbounded teardown + audit work, starving the session GC that
    // shares that thread. The victim budget captured at entry is what bounds it, and
    // stopping on that budget is COUNTED rather than silent.
    //
    // This also puts the mark/clear pair under real contention for TSan: stage 1
    // marks under bridge_mu_ -> rec->mu, the clearing walk takes the same pair, and
    // the producer mutates records_ throughout.
    //
    // The assertion needs at least one record to arrive DURING a sweep. #3095: an
    // earlier version left that to chance (a tight producer racing a 32-teardown
    // sweep, retried a few attempts) and it starved outright on a 2-core CI runner
    // under scheduler contention - honest-red firing for the RIGHT structural
    // reason (the scenario genuinely was never exercised), but too often to be
    // useful. Forced deterministically instead: the #2519 teardown-step probe
    // blocks the sweep thread mid-teardown of its FIRST pressure victim (outside
    // every bridge lock - the pressure claim commits without bridge_mu_, so the
    // producer's own reserve/subscribe/arm calls cannot deadlock against this) until
    // the producer's first park lands, which GUARANTEES the interleave the test
    // needs rather than hoping for it. The honest-red property survives the
    // determinism: the probe still releases on a bounded timeout if the producer
    // never manages to park anything, and the final CHECK is what actually fails if
    // that happens - nothing here can silently pass an unexercised scenario.
    constexpr int kPerSession = 4;
    constexpr int kMainSessions = 8;   // 32 records parked before the sweep
    constexpr int kProdSessions = 40;  // up to 160 arrivals during it

    // The per-principal SESSION cap (8, Decision 15(d)) would otherwise bound the
    // pool to 32 records - exactly the pre-sweep population, leaving the producer
    // nothing to add. Raised here only to reach a population big enough for the
    // budget to bite; nothing in this test depends on the production value.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0},
          mcp::McpSessionRegistry::Config{.per_principal_cap = 64}};
    std::vector<Fx::Session> pool;
    pool.reserve(kMainSessions + kProdSessions);
    for (int i = 0; i < kMainSessions + kProdSessions; ++i) {
        pool.push_back(fx.make_session());
    }
    auto park = [&](const Fx::Session& s, int slot) {
        const auto j = json(slot);
        if (!fx.bridge->reserve(s.id, "alice", j, json("t"), true).ok) {
            return false;
        }
        if (!fx.bridge->subscribe(s.id, j, s.id + "-exec-" + std::to_string(slot))) {
            return false;
        }
        if (fx.bridge->arm(s.id, j, Bridge::ArmMode::kStreaming) != Bridge::ArmOutcome::kArmed) {
            return false;
        }
        return fx.bridge->on_post_closed(s.id, j);
    };
    for (int i = 0; i < kMainSessions; ++i) {
        for (int slot = 0; slot < kPerSession; ++slot) {
            REQUIRE(park(pool[static_cast<std::size_t>(i)], slot));
        }
    }

    // The deterministic barrier: the FIRST kUnsubscribe entry blocks the sweep
    // thread until producer_parked is set, or the bounded timeout elapses.
    std::mutex probe_mu;
    std::condition_variable probe_cv;
    bool producer_parked = false;
    std::once_flag block_once;
    fx.bridge->set_teardown_step_probe_for_test([&](Bridge::TeardownStage stage, bool entering) {
        if (stage != Bridge::TeardownStage::kUnsubscribe || !entering) {
            return;
        }
        std::call_once(block_once, [&] {
            std::unique_lock<std::mutex> lk(probe_mu);
            probe_cv.wait_for(lk, std::chrono::seconds(5), [&] { return producer_parked; });
        });
    });

    std::atomic<bool> stop{false};
    auto producer = std::async(std::launch::async, [&] {
        for (int i = kMainSessions; i < kMainSessions + kProdSessions; ++i) {
            for (int slot = 0; slot < kPerSession; ++slot) {
                if (stop.load(std::memory_order_relaxed)) {
                    return;
                }
                if (park(pool[static_cast<std::size_t>(i)], slot)) {
                    std::lock_guard<std::mutex> lk(probe_mu);
                    producer_parked = true;
                    probe_cv.notify_all();
                }
            }
        }
    });

    fx.bridge->sweep();  // blocks on the probe until the producer's first park lands
    stop.store(true, std::memory_order_relaxed);
    producer.get();
    fx.bridge->set_teardown_step_probe_for_test(nullptr);

    // THE COUNTER IS THE CONDITION, not a proxy for it - it is written ONLY in
    // the budget-exhausted branch, so it can never move without the fix.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_pressure_budget_exhausted_total").value() > 0.0);
}

TEST_CASE("bridge pressure - two concurrent sweeps reap a victim exactly once (#2409 qa-S5, TSan)",
          "[mcp][bridge][2f][2409]") {
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-2s"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));  // never-terminal claimable victim
    // Two threads hammer sweep() on the same oldest kRingOnly victim. The torn_down
    // CAS under Channel::mu must make exactly one win: one teardown, one audit, one
    // synthesized -32014 (the FA-1 exactly-once property under real contention).
    auto racer = [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (fx.bridge->record_count() != 0 && std::chrono::steady_clock::now() < until) {
            fx.bridge->sweep();
            std::this_thread::yield();
        }
    };
    auto a = std::async(std::launch::async, racer);
    auto b = std::async(std::launch::async, racer);
    a.get();
    b.get();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);  // exactly once, not twice
    CHECK(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 1);
}

TEST_CASE("bridge pressure - a sweep claim racing shutdown reaps once, no double teardown (#2409 qa-B2, TSan)",
          "[mcp][bridge][2f][2409]") {
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-sd"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));  // claimable never-terminal victim
    // The claim commits inside f (under Channel::mu, NO bridge_mu_), so shutdown() can
    // start before the claimed branch re-checks shutdown_started_. If shutdown won,
    // its all-phase walk cleans up; if the sweep won, teardown ran. Either way: no
    // crash, no double teardown, the record is gone.
    auto sweeper = std::async(std::launch::async, [&] {
        for (int i = 0; i < 300; ++i) {
            fx.bridge->sweep();
        }
    });
    fx.bridge->shutdown();
    sweeper.get();
    CHECK(fx.bridge->record_count() == 0);
    // Each family is individually bounded to at most one row: this is ONE record,
    // so at most one teardown_claimed call can ever run for it (forced_expire), and
    // shutdown() runs its whole cleanup exactly once, so its aggregate row fires at
    // most once regardless of how many records it poisoned (shutdown_reap). NOT
    // asserted as mutually exclusive: shutdown()'s own comment above (see the
    // should_poison computation) documents the accepted overlap - a concurrent
    // sweep() mid-teardown_claimed, past its own shutdown_started_ recheck but not
    // yet through Step 1, can have shutdown's walk poison the same record before
    // teardown_claimed's Step 1 sets teardown_terminal_handled, so BOTH rows can
    // fire for one record in that narrow window. Harmless per that comment
    // (poisoning is idempotent, the audit rows are individually accurate), but a
    // real interleaving this test's threading can produce - not eliminated here.
    const std::size_t forced = fx.audit_count("mcp.bridge.forced_expire");
    const std::size_t reaped = fx.audit_count("mcp.bridge.shutdown_reap");
    CHECK(forced <= 1);
    CHECK(reaped <= 1);

    auto attached = s.stream->attach_and_replay(0, nullptr, "alice");
    if (reaped == 1) {
        // shutdown's walk poisons an abandoned claim unconditionally (#2517).
        CHECK(attached.status == mcp::McpStreamState::AttachStatus::kPoisoned);
    } else if (forced == 0) {
        // Neither reclaimer touched the record - it was never claimed, so it was
        // never poisoned either.
        CHECK(attached.status != mcp::McpStreamState::AttachStatus::kPoisoned);
    }
    // forced == 1 alone does not pin poisoned-vs-not: the sweep's own ladder may
    // have settled on kPrimary/kFallback/kPoisoned - that's the existing coverage
    // on publish_terminal_ladder, not this race.
}

TEST_CASE("bridge shutdown poisons a claimed-but-terminal-unresolved record and "
          "evidences the reap (#2517, #2489 comp-S1)",
          "[mcp][bridge][2f]") {
    // Forces teardown_claimed PAST the claim but INTO a Step-1 build failure (so
    // teardown_terminal_handled stays false) and then a Step-4 erase failure (so the
    // record is retained in records_ rather than erased) - deterministically
    // reproducing the shape a shutdown race against sweep() produces non-deterministically
    // in the qa-B2 test above.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-reap-a"));
    REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-reap-b"));
    REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
    fx.bus.publish("exec-reap-b", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    // "a" is now the pressure victim: terminal-less, decision kSynthesizeUnavailable.

    fx.bridge->inject_terminal_build_fault_for_test(1);  // Step 1 build fails
    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kErase, 1000));
    REQUIRE_NOTHROW(fx.bridge->sweep());
    // "b" is untouched (its final already pinned); "a" is claimed, torn_down, and
    // retained (erase failed).
    REQUIRE(fx.bridge->record_count() == 2);
    // This is the mechanical-incomplete row from the erase failure itself - a
    // DIFFERENT fact (a resource leaked) from what shutdown's reap will evidence
    // (the terminal was never resolved). Both are correct and both fire.
    CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);

    fx.bridge->shutdown();
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 1);
    {
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        bool saw_reap = false;
        for (const auto& row : fx.audits) {
            if (row.action == "mcp.bridge.shutdown_reap") {
                saw_reap = true;
                CHECK(row.detail.find("poisoned 1 claimed") != std::string::npos);
                CHECK(row.detail.find("execution_id") != std::string::npos);
                CHECK(row.result == "success");
            }
        }
        CHECK(saw_reap);
    }
    CHECK(s.stream->attach_and_replay(0, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kPoisoned);
}

TEST_CASE("bridge shutdown does NOT reap a record whose terminal Step 1 already "
          "resolved, even if a later step failed (#2517)",
          "[mcp][bridge][2f]") {
    // The negative case the flag exists to get right: Step 1 PUBLISHES successfully
    // (teardown_terminal_handled becomes true) and only Step 2 fails afterward. The
    // record is retained (same as the positive test above), but its terminal is
    // already resolved, so shutdown must leave it alone.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-noreap-a"));
    REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-noreap-b"));
    REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
    fx.bus.publish("exec-noreap-b", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe,
                                                            1000));
    REQUIRE_NOTHROW(fx.bridge->sweep());
    // "b" is untouched; "a" is claimed, torn_down, and retained (unsubscribe failed).
    REQUIRE(fx.bridge->record_count() == 2);
    CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);  // Step 1 published fine

    fx.bridge->shutdown();
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 0);
    CHECK(s.stream->attach_and_replay(0, nullptr, "alice").status !=
          mcp::McpStreamState::AttachStatus::kPoisoned);
}

TEST_CASE("bridge session-death sweep - non-touching exists, registry untouched",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-d"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));

    fx.clock_s->store(1801);  // idle_ttl (1800 s) + 1: expired, but NOTHING has touched it
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.audit_count("mcp.bridge.session_dead") == 1);
    // The sweep classified via exists() WITHOUT gc'ing the registry - the dead
    // entry (and its stream/pins) waits for a touching call or gc(). That gap is
    // exactly why the 3a.7 tick must pair sweep() with McpSessionRegistry::gc().
    CHECK(fx.sessions.active_count() == 1);
    fx.sessions.gc();
    CHECK(fx.sessions.active_count() == 0);
}

TEST_CASE("bridge teardown - a failed unsubscribe retains the record for retry, never orphans "
          "its listener (#2487, #2513)",
          "[mcp][bridge][2f]") {
    // teardown_claimed runs on the bare maintenance thread, so it may not throw. The
    // one failure the unsubscribe step actually admits is a mutex failure - it
    // allocates nothing given a const& key. The contained posture is therefore "leave
    // the record whole", NOT "erase it and hope something reclaims the subscription":
    // the listener owns a shared_ptr to the record, so erasing destroys nothing and
    // strands a live listener nothing can reach.
    SECTION("persistent fault exhausts the retry budget, then behaves exactly as before #2513") {
        Fx fx;  // default Config: teardown_retry_max == 3 -> 4 total attempts
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-2487"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        REQUIRE(fx.bus.subscriber_count("exec-2487") == 1);

        fx.clock_s->store(1801);  // session death: the pass-2 teardown this exercises
        // Armed up FRONT with exactly the 4 attempts this record will consume (first
        // claim + 3 retries) - not a huge "persistent" count and not re-armed between
        // sweep() calls, so the fault genuinely outlives the retry budget rather than
        // outliving the test.
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe,
                                                                4));
        REQUIRE_NOTHROW(fx.bridge->sweep());  // attempt 1 (original claim): fails

        // SELF-VALIDATING: with the fault reduced to a no-op the record is torn down
        // and record_count() is 0, so a mutant seam fails right here rather than
        // passing identically.
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.bus.subscriber_count("exec-2487") == 1);
        {
            // The row must say the teardown did not happen, in BOTH the detail and
            // the result field - the production sink used to stamp every bridge row
            // "success" regardless of detail (#2487 review).
            std::lock_guard<std::mutex> lk(fx.audit_mu);
            bool saw_incomplete = false;
            for (const auto& row : fx.audits) {
                if (row.action == "mcp.bridge.session_dead" &&
                    row.detail.find("teardown incomplete") != std::string::npos &&
                    row.result == "failure") {
                    saw_incomplete = true;
                    // This is a session-death reap: its disposition is kNone, so
                    // NOTHING was published. The row must not claim otherwise - a
                    // generic "teardown incomplete" grep would pass over exactly
                    // that lie.
                    CHECK(row.detail.find("published nothing") != std::string::npos);
                    CHECK(row.detail.find("frame was published") == std::string::npos);
                    CHECK(row.detail.find("retry-eligible") != std::string::npos);
                }
            }
            CHECK(saw_incomplete);
        }

        fx.bridge->sweep();  // attempt 2 (retry): fails, still eligible
        fx.bridge->sweep();  // attempt 3 (retry): fails, still eligible
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.bus.subscriber_count("exec-2487") == 1);
        fx.bridge->sweep();  // attempt 4 (retry): fails, budget exhausted

        // Exactly 4 attempts made it to the unsubscribe step, all failing; exactly
        // one retry-outcome row, exhausted.
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total",
                              {{"reason", "unsubscribe"}})
                  .value() == 4.0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "exhausted"}})
                  .value() == 1.0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
                  .value() == 0.0);
        {
            std::lock_guard<std::mutex> lk(fx.audit_mu);
            bool saw_exhausted = false;
            int retry_rows = 0;
            for (const auto& row : fx.audits) {
                if (row.action == "mcp.bridge.teardown_retry") {
                    ++retry_rows;
                    if (row.detail.find("retry budget exhausted") != std::string::npos) {
                        saw_exhausted = true;
                    }
                }
            }
            CHECK(retry_rows == 3);  // attempts 2, 3, 4 - all via the retry pass
            CHECK(saw_exhausted);
        }

        // Exhausted behaves exactly like pre-#2513: retained until shutdown, no
        // further sweep touches it (a 5th sweep, still faulted, changes nothing).
        fx.bridge->sweep();
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.bus.subscriber_count("exec-2487") == 1);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total",
                              {{"reason", "unsubscribe"}})
                  .value() == 4.0);  // unchanged - the exhausted record is never reattempted

        // shutdown() is the reclaimer: it walks records_, which is exactly why the
        // contained path must leave the record THERE.
        fx.bridge->shutdown();
        CHECK(fx.bus.subscriber_count("exec-2487") == 0);
    }

    SECTION("a one-shot fault heals on the next sweep's retry pass") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-heal"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        REQUIRE(fx.bus.subscriber_count("exec-heal") == 1);

        fx.clock_s->store(1801);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe,
                                                                1));  // one-shot
        fx.bridge->sweep();  // attempt 1: fails (consumes the one-shot fault)
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.bus.subscriber_count("exec-heal") == 1);

        fx.bridge->sweep();  // attempt 2 (retry): the fault is gone - succeeds
        CHECK(fx.bridge->record_count() == 0);
        CHECK(fx.bus.subscriber_count("exec-heal") == 0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
                  .value() == 1.0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "exhausted"}})
                  .value() == 0.0);
        {
            std::lock_guard<std::mutex> lk(fx.audit_mu);
            bool saw_recovered = false;
            for (const auto& row : fx.audits) {
                if (row.action == "mcp.bridge.teardown_retry" && row.result == "success") {
                    saw_recovered = true;
                    CHECK(row.detail.find("recovered on a retry attempt") != std::string::npos);
                }
            }
            CHECK(saw_recovered);
        }
    }
}

TEST_CASE("bridge teardown retry - a healed retry RE-PUBLISHES a terminal that never got "
          "built on attempt 1, and shutdown sees nothing left to poison (#2513)",
          "[mcp][bridge][2f]") {
    // Guards the exact regression the design worried about: if a future change set
    // teardown_terminal_handled=true on attempt 1 despite the frame build failing
    // (rung staying kNotAttempted), a retry would skip Step 1 forever - the client
    // never gets its -32014, and if the record then survived to an exhausted-budget
    // shutdown, shutdown()'s should_poison check (keyed on !teardown_terminal_handled)
    // would wrongly see "handled" and stay silent, reproducing #2517 under a new name.
    // This forces attempt 1 to fail at BOTH the frame build AND the unsubscribe step
    // (so the record bails and stays retry-eligible rather than being erased by Steps
    // 2-4 succeeding around an unpublished terminal), then lets both one-shot faults
    // heal for the retry, and checks the ring - not just record_count() - for the
    // actual publish.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    // A (older, never completes) is the pressure victim -> kSynthesizeUnavailable.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-republish-a"));
    REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-republish-b"));
    REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
    fx.bus.publish("exec-republish-b", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    fx.bridge->inject_terminal_build_fault_for_test(1);  // one-shot: attempt 1's build fails
    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe, 1));
    REQUIRE_NOTHROW(fx.bridge->sweep());  // attempt 1: pressure-claims A, bails at unsubscribe

    // Retained, unresolved: nothing published (build failed before the ladder ran).
    // NOT asserting subscriber_count here: a pressure claim removes the bus
    // subscription atomically with the claim itself (before teardown_claimed's
    // Step 2 ever runs), so it reads 0 whether or not the injected unsubscribe
    // fault fires - the #2487-review test above doesn't assert it either, for
    // the same reason.
    CHECK(fx.bridge->record_count() == 2);
    CHECK(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 0);

    REQUIRE_NOTHROW(fx.bridge->sweep());  // attempt 2 (retry pass): both faults spent, heals

    // Exactly one -32014 reached the ring - the retry actually re-ran Step 1, it did
    // not silently treat the record as already handled.
    CHECK(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 1);
    CHECK(fx.bridge->record_count() == 1);  // A settled and erased; B still live/pinned
    CHECK(fx.bus.subscriber_count("exec-republish-a") == 0);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
              .value() == 1.0);

    // A resolved normally before shutdown ran, so there is nothing left for shutdown's
    // walk to poison - a healed retry must not ALSO leave a spurious shutdown_reap
    // trail behind it (the #3052 shutdown-evidence contract this retry sits on top of).
    fx.bridge->shutdown();
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 0);
}

// Shared by both TSan cases below: park one record, expire it under session-death
// (decision kNone - no publish to reason about), and burn a one-shot unsubscribe
// fault on the FIRST attempt so the record lands torn_down + retry-eligible with
// its terminal already resolved (kNone sets teardown_terminal_handled=true
// unconditionally in Step 1, before Step 2 ever runs) - the race under test is
// Pass R's retry claim, not the terminal ladder.
namespace {
Fx::Session make_retry_eligible_record(Fx& fx, const char* exec_id) {
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), exec_id));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    fx.clock_s->store(1801);  // idle_ttl + 1: session-death claims it, decision kNone
    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe, 1));
    fx.bridge->sweep();  // attempt 1: fails, torn_down + retry-eligible, terminal resolved
    REQUIRE(fx.bridge->record_count() == 1);
    return s;
}
}  // namespace

TEST_CASE("bridge teardown retry - two concurrent sweeps retry-claim a record exactly "
          "once (#2513, TSan)",
          "[mcp][bridge][2f][2513]") {
    // Same property as the #2409 qa-S5 first-claim race, applied to Pass R: the
    // eligibility check-and-clear (torn_down && teardown_retry_claimable) commits
    // under bridge_mu_ -> rec->mu in ONE critical section, so a second sweep()
    // reaching the SAME retry-eligible record while the first is still mid-
    // teardown_claimed (which runs OUTSIDE that lock, like every claim path) must
    // find nothing left to claim. A plain two-thread racer loop (qa-S5's own
    // shape) does not reliably land inside that window for a single record - the
    // claim-to-clear gap is far narrower than a full sweep() call, so a natural
    // race almost always resolves before either thread gets close (#3095 hit the
    // identical problem for a different pass). Forced deterministically instead,
    // the same way #3095 fixed it: the #2519 probe blocks sweep A right after it
    // claims (kUnsubscribe entering, BEFORE that step's own work runs), then
    // sweep B is issued from this thread while A is guaranteed to be holding the
    // claim - the exact interleaving a natural race can miss.
    Fx fx;
    auto s = make_retry_eligible_record(fx, "exec-retry-race");
    REQUIRE(fx.bus.subscriber_count("exec-retry-race") == 1);  // still held after attempt 1

    std::mutex probe_mu;
    std::condition_variable probe_cv;
    bool sweep_a_blocked = false;
    bool release_a = false;
    bool wait_timed_out = false;  // set on the probe's own thread; asserted on the main thread
                                   // below, never here - a failed Catch2 assertion off the main
                                   // thread aborts the process instead of failing the test.
    std::atomic<bool> first_entrant{false};
    fx.bridge->set_teardown_step_probe_for_test([&](Bridge::TeardownStage stage, bool entering) {
        if (stage != Bridge::TeardownStage::kUnsubscribe || !entering) {
            return;
        }
        if (first_entrant.exchange(true)) {
            return;  // NOT sweep A: pass straight through - blocking it too would deadlock
                      // against sweep A's own wait for release_a below (std::call_once would
                      // do exactly this: a second caller blocks until the first's invocation
                      // completes, not skip past it - tried, deadlocked, this is the fix).
        }
        std::unique_lock<std::mutex> lk(probe_mu);
        sweep_a_blocked = true;
        probe_cv.notify_all();
        if (!probe_cv.wait_for(lk, std::chrono::seconds(5), [&] { return release_a; })) {
            wait_timed_out = true;
        }
    });

    auto sweep_a = std::async(std::launch::async, [&] { fx.bridge->sweep(); });
    {
        std::unique_lock<std::mutex> lk(probe_mu);
        REQUIRE(probe_cv.wait_for(lk, std::chrono::seconds(5), [&] { return sweep_a_blocked; }));
    }
    fx.bridge->sweep();  // sweep B: Pass R reaches the same record while A holds the claim
    {
        std::lock_guard<std::mutex> lk(probe_mu);
        release_a = true;
        probe_cv.notify_all();
    }
    sweep_a.get();
    fx.bridge->set_teardown_step_probe_for_test(nullptr);
    REQUIRE_FALSE(wait_timed_out);

    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-retry-race") == 0);
    // Exactly one retry pass actually ran teardown_claimed to completion - not
    // zero (the record must resolve) and not two (B winning the claim too would
    // double-count this: a second full pass over the same charge/subscription/
    // erase, and a second `recovered` row).
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
              .value() == 1.0);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "exhausted"}})
              .value() == 0.0);
    CHECK(fx.audit_count("mcp.bridge.teardown_retry") == 1);
}

TEST_CASE("bridge teardown retry - a retry claim racing shutdown reaps once, no double "
          "teardown (#2513, TSan)",
          "[mcp][bridge][2f][2513]") {
    // Pass R's claim (unlike the original pressure claim qa-B2 races) commits
    // UNDER bridge_mu_ and rechecks shutdown_started_ inside that same lock, so
    // shutdown() cannot start mid-CLAIM the way the original claim allows - but
    // Pass R's teardown_claimed(...) call itself still runs OUTSIDE bridge_mu_
    // (same as every other claim path), so shutdown()'s walk can still race a
    // WON claim's in-flight teardown. Either reclaimer may end up doing the
    // actual work; what must hold is no crash and no double-processing.
    Fx fx;
    auto s = make_retry_eligible_record(fx, "exec-retry-shutdown");

    auto sweeper = std::async(std::launch::async, [&] {
        for (int i = 0; i < 300; ++i) {
            fx.bridge->sweep();
        }
    });
    fx.bridge->shutdown();
    sweeper.get();

    CHECK(fx.bridge->record_count() == 0);  // one reclaimer or the other got it
    // At most one retry pass can ever complete teardown_claimed for this one
    // record (a second would find teardown_retry_claimable already false or the
    // record already gone from records_).
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
              .value() <= 1.0);
    CHECK(fx.audit_count("mcp.bridge.teardown_retry") <= 1);
    // decision was kNone (session-death), and Step 1 sets teardown_terminal_handled
    // unconditionally for kNone the moment ANY attempt's Step 1 runs - which
    // already happened on the FIRST attempt, before this race even started. So
    // shutdown's should_poison is false here regardless of who wins the race.
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 0);
}

TEST_CASE("bridge teardown retry - shutdown racing a retry whose terminal build keeps "
          "failing poisons exactly once, never double-delivers (#2513, chaos CH-4, TSan)",
          "[mcp][bridge][2f][2513]") {
    // The gap the two #2513 TSan tests above deliberately leave open: both race
    // shutdown() against a kNone-decision record, where Step 1 resolves the
    // instant it runs (decision==kNone => teardown_terminal_handled=true
    // unconditionally) - so shutdown's should_poison is false by construction in
    // both, and the interesting kSynthesizeUnavailable/kPoisoned interaction is
    // never exercised. Here the terminal-build fault is PERSISTENT (not one-shot),
    // so a retry's own Step 1 keeps failing to build a frame across every attempt -
    // teardown_terminal_handled stays false, which is exactly shutdown()'s
    // should_poison predicate. The deterministic barrier catches attempt 2 (a real
    // Pass R retry, not the original pressure claim) right after its own Step 1
    // has already failed again, still holding torn_down + unresolved terminal,
    // and races shutdown()'s reaped-walk against it from there - the same window
    // #2517's poison-vs-teardown arbitration exists to make safe, now exercised
    // under an active retry instead of a first attempt.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    // A (older, never completes) is the pressure victim -> kSynthesizeUnavailable.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-ch4-a"));
    REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-ch4-b"));
    REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
    fx.bus.publish("exec-ch4-b", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    // Persistent: outlives both attempt 1 and attempt 2's own Step 1 call.
    fx.bridge->inject_terminal_build_fault_for_test(1000);
    // One-shot: only attempt 1 needs an independent reason to bail-and-retain -
    // without this, steps 2-4 would succeed around the unpublished terminal and
    // erase A outright, leaving nothing to retry.
    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe, 1));
    REQUIRE_NOTHROW(fx.bridge->sweep());  // attempt 1: pressure-claims A, build fails, bails
    REQUIRE(fx.bridge->record_count() == 2);
    REQUIRE(count_error_code(ring_frames(*s.stream, "alice"), mcp::kMcpTerminalUnavailable) == 0);

    // Deterministic barrier: block the RETRY's (attempt 2's) teardown_claimed right
    // after its own Step 1 has already failed again (kUnsubscribe entering fires
    // strictly after Step 1 in the function body), so shutdown() is guaranteed to
    // observe torn_down + an unresolved terminal while attempt 2 is genuinely
    // in-flight - not a timing hope.
    std::mutex probe_mu;
    std::condition_variable probe_cv;
    bool retry_blocked = false;
    bool release_retry = false;
    bool wait_timed_out = false;  // observed on the main thread only, never asserted
                                   // from the probe's own thread (see the sibling
                                   // TSan test above for why that would abort instead
                                   // of failing).
    std::atomic<bool> first_entrant{false};
    fx.bridge->set_teardown_step_probe_for_test([&](Bridge::TeardownStage stage, bool entering) {
        if (stage != Bridge::TeardownStage::kUnsubscribe || !entering) {
            return;
        }
        if (first_entrant.exchange(true)) {
            return;  // not the retry attempt this test is blocking - pass through
        }
        std::unique_lock<std::mutex> lk(probe_mu);
        retry_blocked = true;
        probe_cv.notify_all();
        if (!probe_cv.wait_for(lk, std::chrono::seconds(5), [&] { return release_retry; })) {
            wait_timed_out = true;
        }
    });

    auto retry_sweep = std::async(std::launch::async, [&] { fx.bridge->sweep(); });
    {
        std::unique_lock<std::mutex> lk(probe_mu);
        REQUIRE(probe_cv.wait_for(lk, std::chrono::seconds(5), [&] { return retry_blocked; }));
    }
    fx.bridge->shutdown();  // races the blocked retry: sees torn_down, unresolved terminal
    {
        std::lock_guard<std::mutex> lk(probe_mu);
        release_retry = true;
        probe_cv.notify_all();
    }
    retry_sweep.get();
    fx.bridge->set_teardown_step_probe_for_test(nullptr);
    REQUIRE_FALSE(wait_timed_out);

    // Exactly one terminal disposition ever reaches the client: shutdown's poison,
    // never a synthesized -32014 (Step 1 never once succeeded, across either
    // attempt - the fault outlived both, and the pre-race REQUIRE above already
    // pinned the ring at 0 before this point), and never both. attach_and_replay
    // cannot be used to re-check the ring content here: a poisoned stream refuses
    // every later attach by design (session-wide, #2517/#2740), which is itself
    // the assertion - not a limitation of this check.
    auto attached = s.stream->attach_and_replay(0, nullptr, "alice");
    CHECK(attached.status == mcp::McpStreamState::AttachStatus::kPoisoned);
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 1);
    CHECK(fx.bridge->record_count() == 0);  // shutdown's walk reclaimed it
}

TEST_CASE("bridge teardown - an entry-lock failure is CONTAINED, never terminates the "
          "process (post-merge review finding, #2513)",
          "[mcp][bridge][2f][2513]") {
    // Post-merge review on this branch found teardown_claimed's entry-lock
    // acquisition (attempt bookkeeping + Step-1 idempotence read) was the one
    // rec->mu site in this function NOT wrapped in the contained() helper every
    // sibling step already uses for the identical modelled fault - a throw there
    // would escape the function's own noexcept boundary and std::terminate() the
    // whole process on the maintenance thread, not just strand one record. This
    // proves the fix: a fault at the entry lock is caught, logged, and the call
    // returns cleanly with NO bookkeeping mutated - attempts is not incremented,
    // teardown_retry_claimable is never set (since mark_retry_or_exhausted is
    // never reached), so the record is NOT auto-retried by a later Pass R tick -
    // it sits torn_down and fully unresolved until shutdown() reclaims it. That
    // is a real degradation from the fault-free path, but it is a degradation,
    // not a crash - which is the whole point of containing it.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-entry-lock"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));

    fx.clock_s->store(1801);  // idle_ttl + 1: session-death claims it, decision kNone
    fx.bridge->inject_record_entry_lock_fault_for_test(1);
    REQUIRE_NOTHROW(fx.bridge->sweep());  // the claim commits; teardown_claimed's
                                          // entry lock then fails and is contained

    // SELF-VALIDATING at the boundary that matters most: no exception reached the
    // caller, no std::terminate - REQUIRE_NOTHROW above already proves that. The
    // record is claimed (torn_down) but nothing about its teardown bookkeeping
    // advanced: no audit row was ever written for this attempt (bailed before any
    // audit_contained call is reachable), and it stays fully retained.
    CHECK(fx.bridge->record_count() == 1);
    CHECK(fx.audit_count("mcp.bridge.session_dead") == 0);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total", {{"reason", "unsubscribe"}})
              .value() == 0.0);
    // Gate 8 review (post-merge): this reaches the SAME permanent-retention end
    // state as a genuinely retry-budget-exhausted record (retained until
    // shutdown, no further attempts - see below), even though it never went
    // through mark_retry_or_exhausted. YuzuMcpBridgeTeardownRetryExhausted is
    // documented as THE complete signal for that state, so this path counts
    // the same way rather than silently bypassing it.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "exhausted"}})
              .value() == 1.0);

    // Not auto-retried: teardown_retry_claimable was never set (mark_retry_or_exhausted
    // is never reached from the entry bail), so Pass R has nothing to claim. A second,
    // unfaulted sweep changes nothing for this record.
    REQUIRE_NOTHROW(fx.bridge->sweep());
    CHECK(fx.bridge->record_count() == 1);

    // shutdown() is the only reclaimer left. teardown_terminal_handled was never
    // set true (Step 1 was never reached), so should_poison's predicate reads it
    // as unresolved and poisons - the conservative, safe default for "genuinely
    // don't know whether anything was ever owed to this client."
    fx.bridge->shutdown();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.audit_count("mcp.bridge.shutdown_reap") == 1);
    auto attached = s.stream->attach_and_replay(0, nullptr, "alice");
    CHECK(attached.status == mcp::McpStreamState::AttachStatus::kPoisoned);
}

TEST_CASE("bridge subscribe() is an exactly-once state-checked transition (#2487 review)",
          "[mcp][bridge][2f]") {
    // This gate is what makes teardown_claimed's lock-free BORROW of execution_id
    // sound. Without it the field is immutable only by convention: a subscribe()
    // landing between a sweep claim (which sets torn_down and releases both locks)
    // and the erase at the END of teardown would still resolve the record,
    // reassign the string the borrow points at - a reallocating assignment
    // concurrent with a lock-free read - and install a second listener that the
    // imminent erase strands forever.
    //
    // Coverage, stated exactly (verified by mutation, not assumed): deleting the
    // whole gate, the `subscribed` clause, or the phase clause each reddens this
    // test. Deleting `torn_down` alone does NOT - every claim path moves the phase
    // out of kArming in the same critical section that sets torn_down, so the phase
    // check always catches a claimed record first. That clause is retained as
    // defence in depth against a future claim path forgetting to move the phase, and
    // is deliberately left uncovered rather than pinned by a state the code cannot
    // currently reach.
    SECTION("a second subscribe on the same record is refused") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-first"));
        REQUIRE(fx.bus.subscriber_count("exec-first") == 1);

        CHECK_FALSE(fx.bridge->subscribe(s.id, json(1), "exec-second"));
        // The decisive assertions: no second listener anywhere, and the borrowed
        // field still names the FIRST execution.
        CHECK(fx.bus.subscriber_count("exec-first") == 1);
        CHECK(fx.bus.subscriber_count("exec-second") == 0);
        fx.bridge->shutdown();
        CHECK(fx.bus.subscriber_count("exec-first") == 0);  // the one listener was reachable
    }
    SECTION("subscribe into a CLAIMED-but-not-yet-erased record is refused") {
        // The precise window the gate exists for: a record already claimed by a
        // sweep but STILL IN THE MAP, so subscribe() resolves it and reaches the
        // gate rather than failing at lookup. The erase fault seam is what holds the
        // record in that state. (An earlier version let the reaper erase the record
        // first, so it failed at find_locked and the gate was never reached at all.)
        // The refusal here comes from the phase clause, since the claim moved the
        // record to kAborted - see the coverage note above.
        Fx fx{Bridge::Config{.global_record_cap = 256,
                             .ring_only_pressure_cap = 64,
                             .arming_reap_after = std::chrono::seconds(100)}};
        auto base = std::chrono::steady_clock::now();
        auto offset = std::make_shared<std::atomic<std::int64_t>>(0);
        fx.bridge->set_clock_for_test(
            [base, offset] { return base + std::chrono::seconds(offset->load()); });
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        offset->store(101);  // past the reaper threshold, still pre-subscribe
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kErase, 1000));
        fx.bridge->sweep();  // claims the orphan, then fails to erase it
        REQUIRE(fx.bridge->record_count() == 1);  // claimed, torn_down, still resolvable

        CHECK_FALSE(fx.bridge->subscribe(s.id, json(1), "exec-late"));
        CHECK(fx.bus.subscriber_count("exec-late") == 0);
        // The decisive part: had it been admitted, this listener would outlive every
        // reclamation path, because the record is already excluded from later sweeps.
        fx.bridge->shutdown();
        CHECK(fx.bus.subscriber_count("exec-late") == 0);
    }
    SECTION("subscribe after the record leaves kArming is refused - the phase clause") {
        // Isolates the phase clause: arm WITHOUT subscribing first, so `subscribed`
        // is still false and only the phase check can refuse. (Arming after a normal
        // subscribe is caught by the subscribed clause instead, which is why that
        // ordering does not exercise this one.)
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kStreaming);
        CHECK_FALSE(fx.bridge->subscribe(s.id, json(1), "exec-after-arm"));
        CHECK(fx.bus.subscriber_count("exec-after-arm") == 0);
    }
    SECTION("the normal single subscribe is unaffected") {
        // Guards the gate against being too strict: this is the only path production
        // takes, and happy-path correctness matters more than the race it closes.
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        CHECK(fx.bridge->subscribe(s.id, json(1), "exec-normal"));
        CHECK(fx.bus.subscriber_count("exec-normal") == 1);
        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
              Bridge::ArmOutcome::kArmed);
    }
}

TEST_CASE("bridge teardown - each stage retains a DIFFERENT resource and audits it (#2487)",
          "[mcp][bridge][2f]") {
    // The three steps are contained independently, so each failure leaves a
    // different combination settled. All three previously either had no fault seam
    // or no audit row at all; an erase failure in particular produced zero evidence.
    auto row_for = [](Fx& fx, const std::string& action) {
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        for (const auto& r : fx.audits) {
            if (r.action == action) {
                return r;
            }
        }
        return Fx::AuditRow{"<absent>", "<absent>", "<absent>"};
    };
    // Two parked records with cap 1: "b" completes and pins first, so the older
    // terminal-less "a" is the pressure victim (decision kSynthesizeUnavailable).
    // Factored because three sections needed it verbatim; the neighbouring TEST_CASE
    // has its own copy, which is what made a third one look normal.
    auto park_pair = [](Fx& fx, Fx::Session& s, const char* tag) {
        const std::string a = std::string("exec-") + tag + "-a";
        const std::string b = std::string("exec-") + tag + "-b";
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("a"), a));
        REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("b"), b));
        REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
        fx.bus.publish(b, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    };
    auto park_one = [](Fx& fx, Fx::Session& s) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-stage"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        fx.clock_s->store(1801);  // session death drives the pass-2 teardown
    };

    SECTION("release_charge fails: the record is RETAINED for retry (#2513), the "
            "subscription is already gone, and the row says failure") {
        Fx fx;
        auto s = fx.make_session();
        park_one(fx, s);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kReleaseCharge,
                                                                1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());
        // #2513: distinct from the pre-retry posture - a charge failure now BAILS
        // like unsubscribe does, instead of falling through to erase. Step 2
        // (unsubscribe) already ran and succeeded, so the subscription is gone even
        // though the record itself is retained.
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.bus.subscriber_count("exec-stage") == 0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total",
                             {{"reason", "release_charge"}})
                  .value() == 1.0);
        const auto row = row_for(fx, "mcp.bridge.session_dead");
        CHECK(row.result == "failure");  // NOT "success" - a slot is still held
        CHECK(row.detail.find("streamed charge release failed") != std::string::npos);
        CHECK(row.detail.find("admission slot") != std::string::npos);
        // A session-death reap publishes nothing, so the row must say so rather than
        // reporting only the leaked slot: an unconditional charge message used to
        // ERASE the publish disposition, which meant a teardown that both poisoned
        // the session and leaked a slot evidenced only the slot.
        CHECK(row.detail.find("this teardown published nothing") != std::string::npos);
    }
    SECTION("erase fails: subscription and charge settled, record retained, and the "
            "row is NOT silently skipped") {
        Fx fx;
        auto s = fx.make_session();
        park_one(fx, s);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kErase, 1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());
        CHECK(fx.bridge->record_count() == 1);              // retained
        CHECK(fx.bus.subscriber_count("exec-stage") == 0);  // but already unsubscribed
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total", {{"reason", "erase"}})
                  .value() == 1.0);
        const auto row = row_for(fx, "mcp.bridge.session_dead");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("record erase failed") != std::string::npos);
        CHECK(row.detail.find("charge") != std::string::npos);  // says it WAS settled
    }
    SECTION("release_charge fails on a teardown that DID publish: the row says so") {
        // The published==true arm of the charge literal. Covers the pairing the
        // other sections do not: a delivery happened AND a slot leaked, so the row
        // must report both rather than implying the client got nothing.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        park_pair(fx, s, "pub");

        // The synthesis publishes normally; only the charge release fails.
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kReleaseCharge,
                                                                1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());

        const auto row = row_for(fx, "mcp.bridge.forced_expire");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("frame was published") != std::string::npos);
        CHECK(row.detail.find("admission slot") != std::string::npos);
        CHECK(row.detail.find("published nothing") == std::string::npos);
    }
    SECTION("release_charge fails on a POISONED teardown: the row names both, not just the "
            "slot") {
        // Compound failure across two independent axes: the publish ladder poisoned
        // the session AND the charge leaked. Reporting only the slot omits the
        // session-wide poisoning (every later attach 410s), which is the more
        // consequential half. The three-way split exists on the unsubscribe-bail
        // path; this pins that it was mirrored onto the charge literal too.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        // Two parked records so the pressure hatch picks the older, terminal-less one.
        park_pair(fx, s, "pois");

        // Both publish rungs fail -> poison; and the charge release fails too.
        s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kReleaseCharge,
                                                                1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());

        const auto row = row_for(fx, "mcp.bridge.forced_expire");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("streamed charge release failed") != std::string::npos);
        CHECK(row.detail.find("POISONED") != std::string::npos);
    }
    SECTION("unsubscribe fails on a POISONED teardown: that site names it too") {
        // The third bail site's poison arm. Every site now takes the same derived
        // disposition, so this closes the combination matrix rather than leaving the
        // sibling call site as the next place the class resurfaces.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        park_pair(fx, s, "up");
        s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe,
                                                                1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());

        const auto row = row_for(fx, "mcp.bridge.forced_expire");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("bus unsubscribe failed") != std::string::npos);
        CHECK(row.detail.find("POISONED") != std::string::npos);
    }
    SECTION("erase fails on a POISONED teardown: the row names the poisoning too") {
        // The site that stayed poison-blind after the other two were fixed
        // individually. An erase failure returns before the step-5 row, so its row is
        // the ONLY row - if it omits the disposition, a session-wide poisoning is
        // never evidenced anywhere. Every bail site now takes the shared disposition,
        // so this pins the whole class rather than the instance.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        park_pair(fx, s, "ep");

        s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kErase, 1000));
        REQUIRE_NOTHROW(fx.bridge->sweep());

        const auto row = row_for(fx, "mcp.bridge.forced_expire");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("record erase failed") != std::string::npos);
        CHECK(row.detail.find("POISONED") != std::string::npos);
    }
    SECTION("release_charge and erase fail on SUCCESSIVE attempts: retry proves the "
            "resources settle independently, not just that each fails alone") {
        // #2513: a release_charge failure now bails before erase is ever attempted
        // (the two can no longer fail together in ONE call, which is what the
        // pre-retry version of this case pinned) - so this proves the retry
        // sequence instead: attempt 1 fails at release_charge, healing it lets
        // attempt 2 (the retry) reach erase, which fails in turn, and attempt 3
        // finally settles both.
        Fx fx;
        auto s = fx.make_session();
        park_one(fx, s);
        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kReleaseCharge,
                                                                1));  // attempt 1 only
        REQUIRE_NOTHROW(fx.bridge->sweep());  // attempt 1: fails at release_charge
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total",
                             {{"reason", "release_charge"}})
                  .value() == 1.0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total", {{"reason", "erase"}})
                  .value() == 0.0);  // never reached yet

        REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kErase, 1));
        fx.bridge->sweep();  // attempt 2 (retry): release_charge now succeeds, erase fails
        CHECK(fx.bridge->record_count() == 1);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_incomplete_total", {{"reason", "erase"}})
                  .value() == 1.0);
        const auto row = row_for(fx, "mcp.bridge.teardown_retry");
        CHECK(row.result == "failure");
        CHECK(row.detail.find("record erase failed") != std::string::npos);
        CHECK(row.detail.find("were settled") != std::string::npos);  // true this time

        fx.bridge->sweep();  // attempt 3 (retry): both faults spent - settles
        CHECK(fx.bridge->record_count() == 0);
        CHECK(fx.reg.counter("yuzu_mcp_bridge_teardown_retry_total", {{"outcome", "recovered"}})
                  .value() == 1.0);
    }
}

TEST_CASE("bridge teardown fault injector fails loudly on an out-of-range stage (#2523)",
          "[mcp][bridge][2f]") {
    // A mistyped stage used to no-op silently, so the test that armed it passed
    // vacuously against an unfaulted teardown. It must now be loud at the call site
    // instead of vacuously green at the assertion site.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-oob"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    fx.clock_s->store(1801);  // session death drives the pass-2 teardown

    CHECK_FALSE(fx.bridge->inject_teardown_step_fault_for_test(
        static_cast<Bridge::TeardownStage>(3), 1000));

    // Nothing armed: the teardown this drives proceeds unfaulted.
    REQUIRE_NOTHROW(fx.bridge->sweep());
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-oob") == 0);
}

TEST_CASE("bridge pressure - the decided terminal is published even if teardown then fails "
          "(#2487 review)",
          "[mcp][bridge][2f]") {
    // The publish step runs BEFORE the unsubscribe precisely so a later failure
    // cannot lose it. The previous order returned early on an unsubscribe failure
    // and dropped the decided frame entirely: no publish, no poison, no retrier, and
    // an audit row that mentioned only the unsubscribe. That is a silent-loss
    // surface, so it is pinned here.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
    auto s = fx.make_session();
    // A (older, never completes) is the pressure victim -> kSynthesizeUnavailable.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-drop-a"));
    REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
    REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-drop-b"));
    REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
    fx.bus.publish("exec-drop-b", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    REQUIRE(fx.bridge->inject_teardown_step_fault_for_test(Bridge::TeardownStage::kUnsubscribe, 1000));
    REQUIRE_NOTHROW(fx.bridge->sweep());

    // The victim's terminal reached the ring despite the teardown failing after it.
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 1);
    CHECK(fx.bridge->record_count() == 2);  // retained, as the unsubscribe stage requires
    // ...and the row says so. The counterpart assertion lives on the session-death
    // case, which publishes nothing and must say THAT - the two together are what
    // stop the detail becoming a convenient constant again.
    {
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        bool saw = false;
        for (const auto& row : fx.audits) {
            if (row.action == "mcp.bridge.forced_expire" &&
                row.detail.find("bus unsubscribe failed") != std::string::npos) {
                saw = true;
                CHECK(row.detail.find("frame was published") != std::string::npos);
                CHECK(row.result == "failure");
            }
        }
        CHECK(saw);
    }
}

TEST_CASE("bridge cancel arbitration (C1) - pending intent, arm/abandon decide",
          "[mcp][bridge][2f]") {
    SECTION("cancel then arm(kStreaming): degrade to GET-only, charge freed, audited once") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-c"));
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kAcceptedPending);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);  // dup
        CHECK(fx.audit_count("mcp.bridge.cancel") == 0);  // C1: no audit before the win

        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
              Bridge::ArmOutcome::kDegradedGetOnly);
        CHECK(fx.audit_count("mcp.bridge.cancel") == 1);
        auto ph = fx.bridge->phase_for(s.id, json(1));
        REQUIRE(ph.has_value());
        CHECK(*ph == Bridge::Phase::kArmedGetOnly);
        CHECK(fx.bus.subscriber_count("exec-c") == 1);  // subscription retained

        // The streamed charge was released: four MORE streamed records fit.
        for (int i = 2; i <= 5; ++i) {
            REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
        }
        // GET-only lifecycle to completion: no pin ever.
        fx.bus.publish("exec-c", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] {
            auto p = fx.bridge->phase_for(s.id, json(1));
            return p.has_value() && *p == Bridge::Phase::kDone;
        }));
        CHECK(s.stream->pinned_count() == 0);
    }
    SECTION("cancel then abandon: abandon wins, the pending cancel dies unaudited") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kAcceptedPending);
        REQUIRE(fx.bridge->abandon(s.id, json(1)));
        CHECK(fx.audit_count("mcp.bridge.cancel") == 0);  // no cancel audit for a dead request
        CHECK(fx.bridge->record_count() == 0);
        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
              Bridge::ArmOutcome::kNotFound);
    }
    SECTION("cancel after arm: kNoOp (nothing to detach in 3a)") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
                Bridge::ArmOutcome::kArmed);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    }
    SECTION("arm-vs-abandon race: exactly one arbitration winner (TSan)") {
        Fx fx;
        auto s = fx.make_session();
        // 15 iterations (was 50): each spawns 2 threads; the race manifests within
        // a handful of interleavings under TSan, and 100 thread spawn/joins on the
        // Windows-debug CI runner was material wall-clock (server suite 600s cap).
        for (int i = 0; i < 15; ++i) {
            REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), false).ok);
            std::atomic<bool> go{false};
            auto armer = std::async(std::launch::async, [&] {
                while (!go.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                return fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kGetOnly);
            });
            auto abandoner = std::async(std::launch::async, [&] {
                go.store(true, std::memory_order_release);
                return fx.bridge->abandon(s.id, json(i));
            });
            const auto armed = armer.get();
            const bool abandoned = abandoner.get();
            // Exactly one wins the kArming exit.
            CHECK((armed == Bridge::ArmOutcome::kArmed) == !abandoned);
            if (abandoned) {
                CHECK((armed == Bridge::ArmOutcome::kAborted ||
                       armed == Bridge::ArmOutcome::kNotFound));
                CHECK_FALSE(fx.bridge->phase_for(s.id, json(i)).has_value());
            } else {
                REQUIRE(fx.bridge->abandon(s.id, json(i)) == false);  // arm won: abandon inert
                auto ph = fx.bridge->phase_for(s.id, json(i));
                REQUIRE(ph.has_value());
                CHECK(*ph == Bridge::Phase::kArmedGetOnly);
            }
        }
    }
}

TEST_CASE("McpSessionRegistry::exists - non-touching, non-erasing, no oracle",
          "[mcp][bridge][2f][session]") {
    yuzu::MetricsRegistry reg;
    auto base = std::chrono::steady_clock::now();
    auto offset = std::make_shared<std::atomic<std::int64_t>>(0);
    mcp::McpSessionRegistry sessions{
        mcp::McpSessionRegistry::Config{},
        [base, offset] { return base + std::chrono::seconds(offset->load()); }, &reg};
    auto minted = sessions.mint("alice");
    REQUIRE(minted.ok);
    const auto& id = minted.session_id;

    CHECK(sessions.exists(id, "alice"));
    CHECK_FALSE(sessions.exists(id, "mallory"));   // foreign principal reads as absent
    CHECK_FALSE(sessions.exists("nope", "alice"));

    // Boundary: age == idle_ttl is still alive (gc expires strictly greater).
    offset->store(1800);
    CHECK(sessions.exists(id, "alice"));
    // Hammer exists() at the boundary, then step past it: if exists() slid
    // last_seen, these reads would have kept the session alive forever.
    for (int i = 0; i < 5; ++i) {
        CHECK(sessions.exists(id, "alice"));
    }
    offset->store(1801);
    CHECK_FALSE(sessions.exists(id, "alice"));
    // …and it erased NOTHING: the entry is still in the map until a touching
    // call runs gc.
    CHECK(sessions.active_count() == 1);
    CHECK(sessions.validate_and_touch(id, "alice") ==
          mcp::McpSessionRegistry::ValidateResult::kUnknown);
    CHECK(sessions.active_count() == 0);
}

TEST_CASE("bridge progress slot - latest-wins, terminal never dropped",
          "[mcp][bridge][2f]") {
    // #2412: this test used to bound the 16-slot progress ring's drop-oldest
    // behaviour; the ring is gone, replaced by a single latest-wins slot, so
    // it now bounds THAT instead.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-m"));
    // 20 progress events latch during kArming, synchronously (bus.publish
    // invokes the listener inline, and nothing can drain until arm - see
    // has_pending_work_locked's comment) - so the slot deterministically
    // coalesces all 20 down to the LAST one published, superseding the other
    // 19 (counted as suppressed - there is nothing left to "drop", the ring
    // this test used to bound is gone). Stamp each with a distinct
    // agents_responded so the survivor is unambiguous.
    for (int i = 1; i <= 20; ++i) {
        fx.bus.publish("exec-m", "execution-progress",
                       R"({"agents_responded":)" + std::to_string(i) +
                           R"(,"agents_targeted":20})");
    }
    fx.bus.publish("exec-m", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    REQUIRE(poll_until([&] {
        auto ph = fx.bridge->phase_for(s.id, json(1));
        return ph.has_value() && *ph == Bridge::Phase::kDone;  // terminal survived the deluge
    }));
    auto frames = ring_frames(*s.stream, "alice");
    // Exactly ONE progress frame - the latched survivor; GET-only ⇒ no final frame.
    REQUIRE(frames.size() == 1);
    CHECK(json::parse(frames.front().data)["params"]["progress"] == 20);
    REQUIRE(poll_until([&] {
        return fx.reg.counter("yuzu_mcp_bridge_progress_suppressed_total").value() == 19.0;
    }));
    // Retired by #2412: stays registered (scrape/dashboard continuity) but is
    // never incremented again - there is no longer a ring to drop from.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_mailbox_drops_total").value() == 0.0);
}

TEST_CASE("bridge shutdown - idempotent, dtor-safe, gates every mutator", "[mcp][bridge][2f]") {
    SECTION("explicit shutdown twice, then destruction") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-z"));
        fx.bridge->shutdown();
        fx.bridge->shutdown();  // idempotent
        CHECK(fx.bus.subscriber_count("exec-z") == 0);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false)
                              .reject_reason) == "shutdown");
        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
              Bridge::ArmOutcome::kNotFound);
        CHECK_FALSE(fx.bridge->abandon(s.id, json(1)));
        CHECK_FALSE(fx.bridge->on_post_closed(s.id, json(1)));
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
        fx.bridge->sweep();  // no-op, no crash
        fx.bridge.reset();   // dtor after explicit shutdown: no double teardown
    }
    SECTION("destruction WITHOUT explicit shutdown joins and unsubscribes") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-y"));
        fx.bus.publish("exec-y", "execution-progress", kProgress13);
        fx.bridge.reset();  // ~McpStreamBridge → shutdown(): joins projector, unsubscribes
        CHECK(fx.bus.subscriber_count("exec-y") == 0);
    }
}

TEST_CASE("bridge double terminal-publish failure - poison, counted, charge freed",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-x"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    // Both the real final AND the fallback retry fail pre-commit - only the
    // repeat-count seam can arm this, both publishes happen in ONE projector pass.
    s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
    fx.bus.publish("exec-x", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] {
        auto att = s.stream->attach_and_replay(0, nullptr, "alice");
        const bool poisoned = att.status == mcp::McpStreamState::AttachStatus::kPoisoned;
        if (att.sink) {
            s.stream->detach(att.sink);
        }
        return poisoned;
    }));
    CHECK(fx.reg.counter("yuzu_mcp_stream_terminal_publish_failures_total").value() >= 2.0);
    // The charge settled pinless: the session's four streamed slots are free again.
    for (int i = 2; i <= 5; ++i) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
    }
}

TEST_CASE("bridge pressure - the teardown audit names the ladder rung that actually committed "
          "(#2506 F4)",
          "[mcp][bridge][2f]") {
    // The audit row is the evidence that a forced-expire delivered SOMETHING to the
    // client. The publish ladder can fall through to the record's prebuilt fallback,
    // or poison the session and publish nothing at all - so a row that always says
    // "synthesized" evidences a delivery that did not happen. The committed event id
    // cannot disambiguate this (a nonzero id from the retry is indistinguishable
    // from one from the primary frame), which is why the ladder reports its rung.
    auto detail_for = [](Fx& fx, const std::string& action) {
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        for (const auto& row : fx.audits) {
            if (row.action == action) {
                return row.detail;
            }
        }
        return std::string{"<absent>"};
    };
    auto result_for = [](Fx& fx, const std::string& action) {
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        for (const auto& row : fx.audits) {
            if (row.action == action) {
                return row.result;
            }
        }
        return std::string{"<absent>"};
    };
    // Two parked records so the pressure hatch has an oldest to pick; A never
    // completes, so its disposition is kSynthesizeUnavailable (the -32014 arm).
    auto build = [](Fx& fx, Fx::Session& s) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-f4-a"));
        REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-f4-b"));
        REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
        fx.bus.publish("exec-f4-b", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
        REQUIRE(fx.bridge->ring_only_count() == 2);
    };

    SECTION("primary commits: the row says synthesized") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        build(fx, s);
        fx.bridge->sweep();
        CHECK(detail_for(fx, "mcp.bridge.forced_expire") ==
              "the terminal-unavailable frame was published");
    }
    SECTION("primary fails, the fallback commits: the row says so, and does not claim a "
            "synthesis") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        build(fx, s);
        // One pre-commit failure: the -32014 frame never lands; the ladder retries
        // with the record's prebuilt SUCCESS-shaped fallback, which does.
        s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 1);
        fx.bridge->sweep();
        CHECK(detail_for(fx, "mcp.bridge.forced_expire") ==
              "the intended terminal failed and the prebuilt fallback final was published "
              "instead");
    }
    SECTION("both rungs fail: the row says poisoned, nothing published") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        build(fx, s);
        s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
        fx.bridge->sweep();
        CHECK(detail_for(fx, "mcp.bridge.forced_expire") ==
              "the terminal publish POISONED the session - every later attach 410s and the "
              "client must re-initialize; recover the result by execution_id");
        CHECK(result_for(fx, "mcp.bridge.forced_expire") == "failure");
    }
    SECTION("the frame never gets built: NOT reported as a poisoning") {
        // The distinction that matters. The catch around frame construction only
        // counts a metric - it does NOT call poison_terminal() - so an audit row
        // claiming the session was poisoned would assert an outcome that never
        // happened, on exactly the allocation-failure path this work exists to
        // harden. kNotAttempted is a separate rung for this reason.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        build(fx, s);
        fx.bridge->inject_terminal_build_fault_for_test(1);
        fx.bridge->sweep();
        CHECK(detail_for(fx, "mcp.bridge.forced_expire") ==
              "the terminal frame could not be built; nothing was published and THIS teardown "
              "did not poison the session - recover the result by execution_id");
        CHECK(result_for(fx, "mcp.bridge.forced_expire") == "failure");
        // The claim really is that the stream is still usable: a resume must still
        // attach rather than 410.
        auto att = s.stream->attach_and_replay(0, nullptr, "alice");
        CHECK(att.status == mcp::McpStreamState::AttachStatus::kAttached);
        if (att.sink) {
            s.stream->detach(att.sink);
        }
        // Teardown still completed its OTHER two obligations.
        CHECK_FALSE(fx.bridge->phase_for(s.id, json("a")).has_value());
        CHECK(fx.bus.subscriber_count("exec-f4-a") == 0);
    }
}

TEST_CASE("bridge observability faults - outcomes unchanged, deltas restored (D3/C5)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    SECTION("a reject is still a reject when its counter throws") {
        fx.bridge->inject_observability_fault_for_test(1);
        auto r = fx.bridge->reserve("nope", "alice", json(1), std::nullopt, false);
        CHECK_FALSE(r.ok);
        CHECK(std::string(r.reject_reason) == "unknown_session");
        CHECK(fx.reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "unknown_session"}})
                  .value() == 0.0);  // the increment failed - silently, by design
    }
    SECTION("a transiently failing flush restores the delta for a later pass") {
        // #2412: this used to drive the restore machinery through the
        // 16-slot ring's drop-oldest delta; the ring is gone, so it drives
        // the SAME machinery (exchange-then-restore-then-flush,
        // flush_record_obs/flush_core_obs, D3/C5) through the latest-wins
        // slot's supersede delta instead - a different source, identical
        // restore path.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-o"));
        // Latch 20 progress events during kArming so the slot genuinely
        // coalesces (19 supersedes) - arming AFTER would let the projector
        // keep pace and drain each individually, never superseding anything.
        // Distinct increasing counts so the single survivor is unambiguous.
        for (std::uint64_t i = 1; i <= 20; ++i) {
            fx.bus.publish("exec-o", "execution-progress", prog(i, 20));
        }
        // Fault every observability call across the drain: the 19-supersede
        // delta must NOT be lost - it parks (restored) and lands once the
        // fault clears.
        fx.bridge->inject_observability_fault_for_test(1000);
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
                Bridge::ArmOutcome::kArmed);
        // The one surviving snapshot (20/20) still reaches the wire - frame
        // delivery does not depend on the observability registry.
        REQUIRE(poll_until([&] { return s.stream->next_event_id() > 1; }));
        fx.bridge->inject_observability_fault_for_test(0);  // heal
        // Another wake flushes the restored/pending delta.
        fx.bus.publish("exec-o", "execution-progress", prog(21, 21));
        REQUIRE(poll_until([&] {
            return fx.reg.counter("yuzu_mcp_bridge_progress_suppressed_total").value() >= 19.0;
        }));
    }
}

TEST_CASE("bridge arm() throw leaves the record cleanly abandonable (Sol finding 2)",
          "[mcp][bridge][2f]") {
    // A pre-flip allocation failure in arm() (result_base copy / fallback build)
    // must throw WITHOUT having mutated the record, so it stays kArming and the
    // handler's guard can abandon it - no leaked global slot, no half-armed state.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-af"));
    fx.bridge->inject_arm_fault_for_test();
    CHECK_THROWS_AS(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly),
                    std::bad_alloc);
    // Still kArming - the throw was pre-flip, nothing changed.
    auto ph = fx.bridge->phase_for(s.id, json(1));
    REQUIRE(ph.has_value());
    CHECK(*ph == Bridge::Phase::kArming);
    // abandon cleans it, the subscription is torn down, the slot frees.
    REQUIRE(fx.bridge->abandon(s.id, json(1)));
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-af") == 0);
    // The one-shot fault cleared: a fresh reserve+arm now succeeds.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(2), "exec-af2"));
    CHECK(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
}

TEST_CASE("bridge reserve()/subscribe() throw is contained by the caller (Sol/quality)",
          "[mcp][bridge][2f]") {
    // The reserve/subscribe fault seams model an allocation failure; the bridge
    // methods propagate (the execute_instruction handler catches + degrades - see
    // the handler test). Bridge-level: prove the throw leaves no half-state.
    Fx fx;
    auto s = fx.make_session();
    SECTION("reserve throw leaves no record") {
        fx.bridge->inject_reserve_fault_for_test();
        CHECK_THROWS_AS(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false),
                        std::bad_alloc);
        CHECK(fx.bridge->record_count() == 0);  // threw after admission, before insert
        // one-shot cleared: a fresh reserve succeeds
        CHECK(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    }
    SECTION("subscribe throw leaves the record unsubscribed (caller abandons)") {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
        fx.bridge->inject_subscribe_fault_for_test();
        CHECK_THROWS_AS(fx.bridge->subscribe(s.id, json(2), "exec-sf"), std::bad_alloc);
        CHECK(fx.bus.subscriber_count("exec-sf") == 0);  // no listener installed
        // The record is still kArming; abandon cleans it (the handler's path).
        REQUIRE(fx.bridge->abandon(s.id, json(2)));
        CHECK(fx.bridge->record_count() == 0);
    }
}

TEST_CASE("bridge kArming reaper - an orphaned reserved record is reclaimed (cpp-safety)",
          "[mcp][bridge][2f]") {
    // Models the double-bad_alloc corner: a record reserved but never armed (its
    // handler died between reserve and abandon). sweep() must reap it once it
    // ages past arming_reap_after, so the global slot is not leaked forever.
    Fx fx{Bridge::Config{.global_record_cap = 256,
                         .ring_only_pressure_cap = 64,
                         .arming_reap_after = std::chrono::seconds(100)}};
    // Injected clock so the age test is deterministic (no real sleep).
    auto base = std::chrono::steady_clock::now();
    auto offset = std::make_shared<std::atomic<std::int64_t>>(0);
    fx.bridge->set_clock_for_test(
        [base, offset] { return base + std::chrono::seconds(offset->load()); });

    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-orphan"));
    // Never armed. Before the threshold, sweep leaves it (it's "in flight").
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 1);
    auto ph = fx.bridge->phase_for(s.id, json(1));
    REQUIRE(ph.has_value());
    CHECK(*ph == Bridge::Phase::kArming);

    // Advance past the reap threshold: sweep reclaims it (unsubscribed, erased).
    offset->store(101);
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-orphan") == 0);
    CHECK(fx.audit_count("mcp.bridge.arming_reaped") == 1);

    // A record that IS armed within the window is never reaped by age.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
    REQUIRE(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    offset->store(500);
    fx.bridge->sweep();  // kArmedGetOnly is NOT kArming - age reaper does not touch it
    auto ph2 = fx.bridge->phase_for(s.id, json(2));
    REQUIRE(ph2.has_value());
    CHECK(*ph2 != Bridge::Phase::kAborted);
}

TEST_CASE("bridge concurrent publish during shutdown - unsubscribe waits out listeners (TSan)",
          "[mcp][bridge][2f]") {
    // The teardown safety argument ("unsubscribe() waits out in-flight listeners")
    // under REAL contention: a publisher hammers the bus while the bridge is
    // destroyed. Primary value is the TSan leg (no UAF, no race, no lost throw).
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cs"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    std::atomic<bool> stop{false};
    auto flood = std::async(std::launch::async, [&] {
        while (!stop.load(std::memory_order_acquire)) {
            fx.bus.publish("exec-cs", "execution-progress", kProgress13);
        }
    });
    // Let some frames flow, then destroy the bridge concurrently with the flood.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fx.bridge.reset();  // ~McpStreamBridge -> shutdown(): joins projector, unsubscribes
    stop.store(true, std::memory_order_release);
    flood.get();
    CHECK(fx.bus.subscriber_count("exec-cs") == 0);  // unsubscribed cleanly
}

TEST_CASE("bridge sweep races the projector on a charged (streamed) record (TSan)",
          "[mcp][bridge][2f]") {
    // The streamed-charge ledger is exercised only on the kRingOnly path (3b-dead
    // in production, test-reachable). Race sweep against the projector settling a
    // real terminal on such a record: no double-teardown, no lost/duplicate
    // final, charge released exactly once. TSan is the point.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);  // streamed_intent
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cr"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));  // -> kRingOnly, charged
    // Latch the terminal BEFORE the sweeper starts (else a sweeper-beats-publish
    // startup race legitimately synthesizes a SOUND -32014 over a not-yet-published
    // terminal - not a bug, but it would break the "one real final" assertion). With
    // it latched first, the race that remains is sweep vs the projector settling it.
    fx.bus.publish("exec-cr", "execution-completed", kCompleted, /*is_terminal=*/true);

    auto sweeper = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (fx.bridge->record_count() != 0 && std::chrono::steady_clock::now() < until) {
            fx.bridge->sweep();
            std::this_thread::yield();
        }
    });
    sweeper.get();
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_results(frames) == 1);        // exactly one real final
    CHECK(s.stream->pinned_count() == 1);     // its pin survives the torn-down record (spec E3)
    // Charge released EXACTLY ONCE. Admission = pinned_count() + streamed_unpinned:
    // the 1 orphan pin holds one slot, so EXACTLY 3 fresh streamed reserves fit
    // (1 + 3 == cap 4) WITHOUT reclaiming anything. If the charge had leaked
    // (stuck held) only 2 would fit. MEASURED (governance Gate 8, quality-engineer):
    // the double-release direction is NOT detected by this test at single-site
    // granularity - decrement_streamed_locked's own missing-entry floor absorbs one
    // redundant call, so only breaking BOTH that floor and release_charge's
    // exactly-once flag reddens it. Two independent guards is the intended defence;
    // this test measures the leak direction, and the redundancy is what covers the
    // other.
    const auto displaced_total = [&] {
        return fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
    };
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    CHECK(displaced_total() == 0.0);  // all three fit in the free slots
    // The FOURTH is the cap probe. It used to be refused outright, which is the
    // #2740 lockout this branch removes: the slot is held by an ORPHAN pin whose
    // record the sweep above tore down, so nothing else will ever release it.
    // Admission now reclaims exactly that, which still proves the cap bit here -
    // a leaked charge would have made this the FOURTH occupant rather than a
    // reclaim. (See the note above for what this does NOT catch: a single-site
    // double-release is absorbed by the ledger's own floor.)
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    CHECK(displaced_total() == 1.0);
    CHECK(s.stream->pinned_count() == 0);  // the orphan yielded its slot
}

// #2791: the admission reclaim's staleness argument (select under bridge_mu_, release
// at commit time, against three unpin routes that take only McpStreamState::mu_ - see
// select_displaceable_pin_locked's header contract) had no concurrent test. The two
// cases below race reserve()'s own commit-time release against each of two of those
// routes for real, under TSan; the third (teardown_claimed's synthesize-and-pin) is not
// a release race and is out of scope here. Both assert at JOIN, not mid-race: the
// displacement counter and its audit row are emitted sequentially outside bridge_mu_
// (reserve()'s own comment says so), so a mid-race observer can legally see one ahead
// of the other without anything being wrong - the invariant that must hold is over the
// FINAL state, once every racer has returned.
TEST_CASE("bridge reserve races on_final_written releasing the pin it would reclaim (TSan) (#2791)",
          "[mcp][bridge][2f][ch27]") {
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    // Fill all four pin slots with parked, undelivered finals - the state in which the
    // next admission must reclaim rather than refuse (same setup as CH-26). Waits for
    // the FULL settle (pinned==i AND unpinned==0), not just the ring pin becoming
    // visible: pinned_count() reflects publish_terminal_ladder's ring commit before
    // project_record reaches its own stall-check line, so a pinned_count()-only wait
    // does not prove record i's projection has fully finished (#2791 UP-4).
    for (int i = 1; i <= 4; ++i) {
        const std::string exec = "exec-r1-" + std::to_string(i);
        REQUIRE(poll_until([&] {
            return fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok;
        }));
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));  // -> kRingOnly, charged
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] {
            const auto snap = fx.bridge->accounting_snapshot_for_test(s.id, s.stream);
            return snap.pinned == static_cast<std::size_t>(i) && snap.unpinned == 0;
        }));
    }
    REQUIRE(s.stream->pinned_count() == 4);

    // Race: on_final_written releasing record 1's pin (rule-a, McpStreamState::mu_
    // only - no bridge_mu_) against a burst of admissions, each of which may select
    // record 1 as the reclaim victim (oldest parked_seq wins) and try to release it
    // itself at commit time. Idempotent and safe to flood: once the pin is gone,
    // further calls on the same key are harmless no-ops (mcp_stream_bridge.cpp:1191-1196).
    const auto key1 = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key1.has_value());

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> racer_iterations{0};
    auto releaser = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!stop.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < until) {
            fx.bridge->on_final_written(*key1);
            racer_iterations.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::yield();
        }
    });

    // Every original pin is reclaimable exactly once - regardless of which side
    // (this loop's own commit-time release, or the concurrent releaser) actually
    // clears record 1's slot, the total capacity freed across the run is bounded by
    // the ring's fixed 4-wide array. So the admitted count is deterministic even
    // though which specific record backs each admission is not.
    int admitted = 0;
    int next_id = 100;
    for (int i = 0; i < 200; ++i) {
        if (fx.bridge->reserve(s.id, "alice", json(next_id++), json("t"), true).ok) {
            ++admitted;
        }
    }
    stop.store(true, std::memory_order_release);
    releaser.get();
    // Diagnostic only, never a hard assert: a starved racer thread on a loaded CI box
    // is a real, non-buggy outcome (the admitted==4 invariant below holds regardless -
    // reserve()'s own commit-time release alone can reclaim all four pins), but zero
    // iterations means this run gave zero ACTUAL concurrent coverage, which is worth
    // knowing about without failing the build over it (#2791 Gate 5 UP-3).
    if (racer_iterations.load(std::memory_order_relaxed) == 0) {
        WARN("on_final_written racer thread never ran an iteration - this pass exercised "
             "no actual concurrency, only the deterministic admitted==4 outcome");
    }

    CHECK(admitted == 4);
    const auto displaced =
        fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
    CHECK(displaced == static_cast<double>(fx.audit_count("mcp.bridge.pin_displaced_for_admission")));
    CHECK(displaced <= 4.0);
    const auto snap = fx.bridge->accounting_snapshot_for_test(s.id, s.stream);
    // Deterministic end state: all four originals consumed, four fresh charges in
    // their place, nothing left to reclaim.
    CHECK(snap.pinned == 0);
    CHECK(snap.unpinned == 4);
    // A ninth attempt (past the 200 already run) must decline cleanly - not crash,
    // not double-admit.
    const auto over = fx.bridge->reserve(s.id, "alice", json(9999), json("t"), true);
    CHECK_FALSE(over.ok);
    CHECK(std::string(over.reject_reason) == "pin_slots");
}

TEST_CASE("bridge reserve races a GET resume ack clearing every pin at or below cursor "
          "(TSan) (#2791)",
          "[mcp][bridge][2f][ch27]") {
    // attach_and_replay's rule-(b) ack (mcp_stream.cpp) clears EVERY pin at or below
    // the cursor with no record lookup at all - unlike on_final_written, it is not
    // scoped to one record, so this races reserve() against a bulk clear rather than
    // a single-id release.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    for (int i = 1; i <= 4; ++i) {
        const std::string exec = "exec-r2-" + std::to_string(i);
        REQUIRE(poll_until([&] {
            return fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok;
        }));
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        // Full settle, not just the ring pin - see the matching comment on the
        // sibling on_final_written racer test above (#2791 UP-4).
        REQUIRE(poll_until([&] {
            const auto snap = fx.bridge->accounting_snapshot_for_test(s.id, s.stream);
            return snap.pinned == static_cast<std::size_t>(i) && snap.unpinned == 0;
        }));
    }
    REQUIRE(s.stream->pinned_count() == 4);

    // Captured ONCE, before the race, not recomputed per iteration: nothing published
    // during the race (the 200 reserve() calls below only ever create kArming records,
    // which never call stream->publish(...)), so next_event_id() is constant for the
    // whole run. A cursor equal to the LIVE next_event_id() is never resumable
    // (attach_and_replay's gate requires last_event_id < next_id_, strictly) - using it
    // directly made every attach_and_replay call in this test return kGap and skip the
    // rule-(b) unpin block entirely, so the racer thread raced nothing (#2791 Gate 4
    // happy-path finding). `next_event_id() - 1` is the highest id already ASSIGNED -
    // resumable, and >= every one of the four pins set up above, so rule-(b) clears all
    // four the first time this cursor is used.
    const std::uint64_t cursor = s.stream->next_event_id() - 1;

    std::atomic<bool> stop{false};
    // Counts kAttached OUTCOMES, not raw loop passes: a raw pass counter would stay
    // nonzero even if the cursor regressed back to always-kGap (the loop still spins
    // and yields regardless of attach outcome), silently defeating this diagnostic's
    // whole purpose - the exact bug this test exists to catch. Gate 8 happy-path
    // finding (#2791): the instrumentation that proved the original fix (a temporary
    // counter showing 1124 successful attaches) was removed after verification instead
    // of being kept as a permanent, low-cost regression guard - this IS that guard.
    std::atomic<std::uint64_t> attached_count{0};
    auto acker = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!stop.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < until) {
            auto att = s.stream->attach_and_replay(cursor, nullptr, "alice");
            if (att.status == mcp::McpStreamState::AttachStatus::kAttached) {
                attached_count.fetch_add(1, std::memory_order_relaxed);
                s.stream->detach(att.sink);
            }
            std::this_thread::yield();
        }
    });

    int admitted = 0;
    int next_id = 100;
    for (int i = 0; i < 200; ++i) {
        if (fx.bridge->reserve(s.id, "alice", json(next_id++), json("t"), true).ok) {
            ++admitted;
        }
    }
    stop.store(true, std::memory_order_release);
    acker.get();
    if (attached_count.load(std::memory_order_relaxed) == 0) {
        WARN("attach_and_replay racer thread never successfully attached - either a starved "
             "thread gave this pass zero actual concurrency, or the cursor is wrong again and "
             "rule-(b) never ran (the exact #2791 regression this counter exists to catch)");
    }

    CHECK(admitted == 4);
    const auto displaced =
        fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
    CHECK(displaced == static_cast<double>(fx.audit_count("mcp.bridge.pin_displaced_for_admission")));
    CHECK(displaced <= 4.0);
    const auto snap = fx.bridge->accounting_snapshot_for_test(s.id, s.stream);
    CHECK(snap.pinned == 0);
    CHECK(snap.unpinned == 4);
    const auto over = fx.bridge->reserve(s.id, "alice", json(9999), json("t"), true);
    CHECK_FALSE(over.ok);
    CHECK(std::string(over.reject_reason) == "pin_slots");
}

TEST_CASE("bridge real final - the terminal payload contract is pinned by a REAL ExecutionTracker "
          "(#2506 F2)",
          "[pg][mcp][bridge][2f]") {
    // The producer (ExecutionTracker::refresh_counts) and the consumer
    // (McpStreamBridge::build_real_final) agree on exactly three keys of the
    // execution-completed payload: status, agents_success, agents_failure. Nothing
    // bound them: every other case in this file and in the [2409] set hand-writes
    // the terminal payload, so a rename on either side would degrade every parked
    // final to status:"unknown" with the counts silently missing, and the whole
    // suite would stay green. This drives a real tracker so the payload under test
    // is the one production emits.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    Fx fx;
    {
        std::mutex seen_mu;
        std::vector<std::pair<std::string, std::string>> seen;
        yuzu::server::ExecutionTracker& tracker = *tracker_bundle;
        tracker.set_event_bus(&fx.bus);
        auto s = fx.make_session();

        yuzu::server::Execution exec;
        exec.definition_id = "def-f2";
        exec.scope_expression = "agent_id = 'agent-1'";
        exec.dispatched_by = "tester";
        exec.status = "running";
        exec.agents_targeted = 2;
        auto exec_id = tracker.create_execution(exec);
        REQUIRE(exec_id.has_value());

        // Park a streamed record on that execution: kRingOnly is the phase whose
        // final goes through build_real_final.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), *exec_id));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));

        // One success, one failure: distinct nonzero values, so a swapped or dropped
        // key cannot coincidentally match. Both agents responding drives the
        // terminal transition, and agents_failure > 0 makes the status "completed"
        // rather than "succeeded" - a value only the tracker can produce.
        yuzu::server::AgentExecStatus ok;
        ok.agent_id = "agent-1";
        ok.status = "success";
        tracker.update_agent_status(*exec_id, ok);
        yuzu::server::AgentExecStatus bad;
        bad.agent_id = "agent-2";
        bad.status = "failure";
        tracker.update_agent_status(*exec_id, bad);
        tracker.refresh_counts(*exec_id);

        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
        auto frames = ring_frames(*s.stream, "alice");
        std::optional<json> result;
        for (const auto& f : frames) {
            auto j = json::parse(f.data);
            if (j.contains("result")) {
                result = j["result"];  // embedded raw by success_response, not a string
            }
        }
        REQUIRE(result.has_value());
        CHECK((*result)["status"] == "completed");
        CHECK((*result)["agents_success"] == 1);
        CHECK((*result)["agents_failure"] == 1);
        CHECK((*result)["execution_id"] == *exec_id);

        // The OTHER half of the same contract, and the one the assertions above
        // cannot reach. refresh_counts publishes TWO events on a terminal
        // transition: a terminal-flagged execution-progress FIRST, then
        // execution-completed. C5's pressure visitor keys on the first of those and
        // feeds ITS payload to the same build_real_final. So dropping a key from
        // progress_payload while leaving terminal_payload intact would keep every
        // assertion above green and still degrade the memory-pressure recovery path
        // to status:"unknown". Pin the producer directly by replaying what the bus
        // actually buffered.
        // The listener borrows `seen`/`seen_mu` and lives as long as its bus
        // channel, which outlives this block inside fx - so the unsubscribe must
        // survive the fatal REQUIREs below, not sit after them.
        struct UnsubGuard {
            yuzu::server::ExecutionEventBus& bus;
            std::string id;
            std::size_t sub;
            UnsubGuard(yuzu::server::ExecutionEventBus& b, std::string i, std::size_t s)
                : bus(b), id(std::move(i)), sub(s) {}
            UnsubGuard(const UnsubGuard&) = delete;
            UnsubGuard& operator=(const UnsubGuard&) = delete;
            ~UnsubGuard() { bus.unsubscribe(id, sub); }
        };
        UnsubGuard collector(fx.bus, *exec_id,
                             fx.bus.subscribe_and_replay(
                                 *exec_id, 0,
                                 [&](const yuzu::server::ExecutionEvent& ev) noexcept {
                                     std::lock_guard<std::mutex> lk(seen_mu);
                                     seen.emplace_back(ev.event_type, ev.data);
                                 }));
        // The terminal-flagged progress is the one IMMEDIATELY BEFORE the first
        // execution-completed, not simply the last progress event: update_agent_status
        // drives the transition itself, so a later refresh_counts appends a further,
        // non-transition progress frame that carries no status at all.
        std::optional<json> terminal_progress;
        for (std::size_t i = 0; i < seen.size(); ++i) {
            if (seen[i].first == "execution-completed") {
                REQUIRE(i > 0);
                REQUIRE(seen[i - 1].first == "execution-progress");
                terminal_progress = json::parse(seen[i - 1].second);
                break;
            }
        }
        REQUIRE(terminal_progress.has_value());
        CHECK((*terminal_progress)["status"] == "completed");
        CHECK((*terminal_progress)["agents_success"] == 1);
        CHECK((*terminal_progress)["agents_failure"] == 1);
    }
}

// ── McpPostPump ──────────────────────────────────────────────────────────────
//
// The pump lives beside McpStreamPump in mcp_stream.cpp (it needs that file's
// anonymous-namespace write_all / count_stream_close), but its tests live HERE
// because every interesting case needs a real bridge behind take_post_batch.

namespace {

/// The GET pump's test wire, reused verbatim - both pumps share the WriteFn type.
struct PostWire {
    std::string out;
    bool alive = true;
    mcp::McpPostPump::WriteFn writer() {
        return [this](const char* p, std::size_t n) {
            if (!alive) {
                return false;
            }
            out.append(p, n);
            return true;
        };
    }
    bool contains(std::string_view needle) const { return out.find(needle) != std::string::npos; }
    std::size_t count(std::string_view needle) const {
        std::size_t n = 0;
        for (std::size_t i = out.find(needle); i != std::string::npos;
             i = out.find(needle, i + needle.size())) {
            ++n;
        }
        return n;
    }
};

mcp::McpPostPump::Config fast_post_cfg() {
    mcp::McpPostPump::Config cfg;
    cfg.tick = std::chrono::milliseconds(10);  // never sleep a real tick in a unit test
    return cfg;
}

/// A `WriteFn` that can be made to BLOCK mid-write, which is the whole point.
///
/// The in-process handler fixture never runs a content provider (no socket, #438),
/// so until this existed nothing anywhere exercised the pump CONCURRENTLY with the
/// projector, the sweep, or a cancel. That gap is not incidental - it is the reason
/// a held-lock-across-socket-write, an inert wake channel and an incomplete
/// close-window fix all survived TSan-clean-3x, three adversarial review rounds and
/// 89k assertions (governance 2026-07-27, Gate 5). A harness that cannot block the
/// writer re-verifies a fix with the same instrument that missed the bug.
struct BlockingWire {
    std::mutex mu;
    std::condition_variable cv;
    std::string out;
    bool blocked = false;   ///< writer parks until released
    bool in_write = false;  ///< a writer is parked right now
    bool alive = true;

    mcp::McpPostPump::WriteFn writer() {
        return [this](const char* p, std::size_t n) {
            std::unique_lock<std::mutex> lk(mu);
            if (blocked) {
                in_write = true;
                cv.notify_all();
                cv.wait(lk, [this] { return !blocked; });
                in_write = false;
            }
            if (!alive) {
                return false;
            }
            out.append(p, n);
            return true;
        };
    }
    void block() {
        std::lock_guard<std::mutex> lk(mu);
        blocked = true;
    }
    /// Waits until a writer is actually parked inside the write - the handshake
    /// that makes "the peer stopped reading" deterministic instead of timing-based.
    bool await_parked(std::chrono::milliseconds d = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, d, [this] { return in_write; });
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk(mu);
            blocked = false;
        }
        cv.notify_all();
    }
    std::string snapshot() {
        std::lock_guard<std::mutex> lk(mu);
        return out;
    }
};

}  // namespace

TEST_CASE("McpPostPump: progress frames, then the final LAST, then EOF (C7)",
          "[mcp][bridge][2f]") {
    // The whole point of the rung: spec progress-before-response, which the 3a
    // GET-after-response shape could not provide.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-pump"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    bool final_written = false;
    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
        [&] { final_written = fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(),
        {}, nullptr, "cid-1", "exec-pump");

    PostWire wire;
    fx.bus.publish("exec-pump", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] {
        pump.pump_once(wire.writer());
        return wire.contains("notifications/progress");
    }));

    fx.bus.publish("exec-pump", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return !pump.pump_once(wire.writer()); }));  // final ends the response

    CHECK(final_written);
    const auto prog_at = wire.out.find("notifications/progress");
    const auto final_at = wire.out.find(R"("result")");
    REQUIRE(final_at != std::string::npos);
    CHECK(prog_at < final_at);  // progress BEFORE the response
    // A successful final EOFs; a close frame after it would be a contradictory
    // second terminal on a stream that already answered.
    CHECK_FALSE(wire.contains("notifications/yuzu.stream_closed"));
}

TEST_CASE("McpPostPump: the cap closes the response but never the execution (C7)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cap2"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    auto cfg = fast_post_cfg();
    cfg.cap = std::chrono::milliseconds(0);  // already expired on the first tick
    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); }, {}, {}, {}, cfg,
        {}, nullptr, "cid-2", "exec-cap2");

    PostWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(wire.contains("notifications/yuzu.stream_closed"));
    CHECK(wire.contains("cap_expired"));
    // Only the BRIDGE may declare a cap close, and it does so inside the
    // projection claim. Let the pump decide it from its own expired deadline and
    // this next case breaks: work that was already latched gets discarded by a
    // close instead of delivered.
    {
        Fx fx2;
        auto s2 = fx2.make_session();
        REQUIRE(fx2.bridge->reserve(s2.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx2.bridge->subscribe(s2.id, json(1), "exec-cap3"));
        REQUIRE(fx2.bridge->arm(s2.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        auto sink2 = std::make_shared<mcp::sse_bus::SseSinkState>();
        auto key2 = fx2.bridge->bind_post_sink(s2.id, json(1), sink2);
        REQUIRE(key2.has_value());
        auto cfg2 = fast_post_cfg();
        cfg2.cap = std::chrono::milliseconds(0);  // expired from the very first tick
        mcp::McpPostPump pump2(
            sink2, [&](bool cap) { return fx2.bridge->take_post_batch(*key2, cap); }, {}, {}, {},
            cfg2, {}, nullptr, "cid-2b", "exec-cap3");
        fx2.bus.publish("exec-cap3", "execution-progress", prog(1, 3));
        PostWire wire2;
        REQUIRE(poll_until([&] {
            const bool open = pump2.pump_once(wire2.writer());
            return wire2.contains("notifications/progress") && open;
        }));
        // Latched progress was DELIVERED despite the expired cap, and the
        // response stayed open to do it.
        CHECK_FALSE(wire2.contains("cap_expired"));
    }
    // The durable handle must ride the close frame - it is the whole recovery
    // path for a client whose response was bounded out from under it.
    CHECK(wire.contains("exec-cap2"));

    // The execution is NOT cancelled: the record parks and its real terminal
    // still reaches the ring for GET resume.
    REQUIRE(fx.bridge->on_post_closed_keyed(*key));
    fx.bus.publish("exec-cap2", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return count_results(ring_frames(*s.stream, "alice")) == 1; }));
}

TEST_CASE("McpPostPump: a dead peer closes as client_gone, never as cap_expired (C7)",
          "[mcp][bridge][2f]") {
    // A write failure must not masquerade as a cap close: that would poison the
    // reason taxonomy and hand the client a retry schedule for something that
    // never happened.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-dead"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); }, {}, {}, {},
        fast_post_cfg(), {}, nullptr, "cid-3", "exec-dead");
    PostWire wire;
    wire.alive = false;  // the peer is gone; even the heartbeat fails
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK_FALSE(wire.contains("cap_expired"));
}

TEST_CASE("McpPostPump: revocation and session death close the response (C7)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-rev"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());
    auto take = [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); };

    SECTION("a revoked credential closes on the first tick") {
        mcp::McpPostPump pump(
            sink, take, {}, [] { return mcp::StreamRevalidate::kRevoked; }, {}, fast_post_cfg(),
            {}, nullptr, "cid-4", "exec-rev");
        PostWire wire;
        CHECK_FALSE(pump.pump_once(wire.writer()));
        CHECK(wire.contains("credential_revoked"));
    }
    SECTION("a dead session closes the response") {
        mcp::McpPostPump pump(
            sink, take, {}, std::function<mcp::StreamRevalidate()>{}, [] { return false; },
            fast_post_cfg(), {}, nullptr, "cid-5", "exec-rev");
        PostWire wire;
        CHECK_FALSE(pump.pump_once(wire.writer()));
        CHECK(wire.contains("session_terminated"));
    }
    SECTION("a closed sink ends the response as cancelled") {
        sink->closed.store(true);
        mcp::McpPostPump pump(sink, take, {}, {}, {}, fast_post_cfg(), {}, nullptr, "cid-6",
                              "exec-rev");
        PostWire wire;
        CHECK_FALSE(pump.pump_once(wire.writer()));
        CHECK(wire.contains("cancelled"));
    }
}

TEST_CASE("McpPostPump: record_gone closes the response instead of heartbeating (C7)",
          "[mcp][bridge][2f]") {
    // The pump's own half of the fix, tested against a fake take_batch with no
    // live bridge behind it — the seam TakeBatchFn exists for. Before this check
    // existed, a record_gone batch fell through to the unconditional heartbeat at
    // the bottom of pump_once_impl and looped forever. Mutation check: deleting
    // the `if (batch.record_gone)` block in mcp_stream.cpp leaves this red — the
    // pump keeps the response open and writes a heartbeat instead of closing.
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto take = [](bool /*cap*/) {
        mcp::McpStreamBridge::PostBatch out;
        out.record_gone = true;
        return out;
    };
    mcp::McpPostPump pump(sink, take, {}, {}, {}, fast_post_cfg(), {}, nullptr, "cid-7",
                          "exec-gone");
    PostWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(wire.contains("record_gone"));
    CHECK_FALSE(wire.contains("cap_expired"));
    CHECK_FALSE(wire.contains("heartbeat"));
}

TEST_CASE("McpPostPump: a throwing credit step still closes kCompleted, not internal_error (C7)",
          "[mcp][bridge][2f]") {
    // Doomgoose (PR #2781 review): on_final_written_() is called
    // with no exception containment right after write_all() of the final already
    // succeeded - so the client has a correct result by the time this runs. A
    // throw here (this codebase's own modelled fault class for a lock acquisition;
    // see mcp_stream_bridge.cpp's inject_claim_lock_fault_for_test) used to
    // propagate to pump_once's outer catch, which stamped kInternalError - a
    // misreport, since the client's own experience was success - while the
    // bridge's credit step (final_written + unpin) never ran, silently retaining
    // the session's pin. Fixed: the true reason is noted before the log/counter
    // run (first-wins beats pump_once's catch), and a dedicated counter makes the
    // failure operator-visible instead of folding into the generic fault metric.
    yuzu::MetricsRegistry reg;
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto take = [](bool /*cap*/) {
        mcp::McpStreamBridge::PostBatch out;
        out.final_frame = mcp::McpStreamBridge::PostBatch::PostFrame{
            R"({"jsonrpc":"2.0","id":1,"result":{"status":"completed"}})", 0};
        return out;
    };
    auto throwing_credit = [] { throw std::runtime_error("lock acquisition failed"); };
    mcp::McpPostPump pump(sink, take, throwing_credit, {}, {}, fast_post_cfg(), {}, &reg,
                          "cid-credit-throw", "exec-credit-throw");
    PostWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(pump.close_reason() == mcp::McpStreamClose::kCompleted);
    CHECK(wire.contains(R"("status":"completed")"));  // the client got its real result
    CHECK_FALSE(wire.contains("internal_error"));
    CHECK_FALSE(wire.contains("notifications/yuzu.stream_closed"));  // kCompleted writes no close frame
    CHECK(reg.counter("yuzu_mcp_stream_final_credit_failed_total").value() == 1.0);
    CHECK(reg.counter("yuzu_mcp_stream_closes_total", {{"reason", "internal_error"}}).value() ==
          0.0);
    CHECK(reg.counter("yuzu_mcp_stream_closes_total", {{"reason", "completed"}}).value() == 1.0);
}

TEST_CASE("McpPostPump: the credit step's own success path is unaffected by the try/catch (C7)",
          "[mcp][bridge][2f]") {
    // The happy path must still unpin - the containment in the prior test must not
    // swallow a SUCCESSFUL call too.
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto take = [](bool /*cap*/) {
        mcp::McpStreamBridge::PostBatch out;
        out.final_frame = mcp::McpStreamBridge::PostBatch::PostFrame{
            R"({"jsonrpc":"2.0","id":1,"result":{"status":"completed"}})", 0};
        return out;
    };
    bool credited = false;
    mcp::McpPostPump pump(sink, take, [&] { credited = true; }, {}, {}, fast_post_cfg(), {},
                          nullptr, "cid-credit-ok", "exec-credit-ok");
    PostWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(credited);
    CHECK(pump.close_reason() == mcp::McpStreamClose::kCompleted);
}

TEST_CASE("McpPostPump: the wait is bounded by the next credential check, not a fresh tick "
          "(CH-22)",
          "[mcp][bridge][2f][ch22]") {
    // THE DEFECT THIS PINS. Gating revalidate behind `next_check_` stopped a
    // poke-driven pump from scaling auth load with the progress-frame rate - but the
    // WAIT stayed a fresh FULL tick measured from each WAKE. A poke landing just
    // before the boundary therefore woke the pump, found the check not yet due, and
    // waited another whole tick, pushing the credential re-check out to nearly TWO
    // ticks after the previous one. That silently doubles the one-tick revocation
    // bound promised by Decision 15(c) / CH-4, by mcp_stream.hpp, and by
    // docs/mcp-server.md - a security bound weakened by a performance fix.
    //
    // WHY NOTHING CAUGHT IT. Every other revocation test closes on tick ONE, where
    // the default-constructed `next_check_` is the epoch and the check is always due.
    // The defect lives strictly on the SECOND tick, and no test drove one. Note the
    // direction is counter-intuitive: FREQUENT pokes are harmless, because each wake
    // re-tests the gate. The bad case is ONE poke just before the boundary, then
    // silence - which is what a command that emits a burst and then runs quiet does.
    //
    // DETERMINISTIC BY CONSTRUCTION, not by timing luck. The injected clock is FROZEN
    // 50ms short of the next check, so the correct wait is 50ms while the pre-fix
    // wait is the full 5s tick. The 1500ms ceiling sits 30x above the correct value
    // and 3x below the buggy one, which is what keeps it safe on a loaded shared CI
    // runner where a wall-clock assertion would otherwise be a flake generator.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-bound"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump::Config cfg;
    cfg.tick = std::chrono::seconds(5);  // deliberately LONG, so the two cases diverge
    const auto base = std::chrono::steady_clock::now();
    // Single-threaded: pump_once is called directly on this thread, so the fake clock
    // needs no synchronisation and TSan has nothing to see.
    auto fake = base;
    int revalidations = 0;

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); }, {},
        [&] {
            ++revalidations;
            return mcp::StreamRevalidate::kValid;
        },
        {}, cfg, [&] { return fake; }, nullptr, "cid-bound", "exec-bound");
    PostWire wire;

    // Tick one: `next_check_` is the epoch, so the check is due immediately and the
    // wait budget is zero. This is the tick every existing test stops at.
    REQUIRE(pump.pump_once(wire.writer()));
    REQUIRE(revalidations == 1);

    // Freeze 50ms short of the next check, then take the second tick. The pump must
    // wake in time FOR that check rather than restarting a full tick.
    fake = base + cfg.tick - std::chrono::milliseconds(50);
    const auto started = std::chrono::steady_clock::now();
    REQUIRE(pump.pump_once(wire.writer()));
    const auto waited = std::chrono::steady_clock::now() - started;

    CHECK(waited < std::chrono::milliseconds(1500));

    // AND the check must then actually HAPPEN. The assertion above alone proves
    // only that the pump stopped waiting sooner - it would stay green against an
    // implementation that woke early and then skipped the credential check, which
    // is the very regression this test exists to prevent. Both adversarial
    // reviewers reached this gap independently, and one proved it by adding this
    // line and watching it fail 1 == 2.
    //
    // The clock must be advanced to the boundary to see it: while `fake` is frozen
    // 50ms short, the post-wait sample is still short too, so the gate is
    // correctly closed and `revalidations` correctly stays 1.
    fake = base + cfg.tick;
    REQUIRE(pump.pump_once(wire.writer()));
    CHECK(revalidations == 2);

    // The sub-millisecond floor, which is the OTHER way this wait can go wrong. A
    // remainder under 1ms must not round DOWN to a zero budget: that returns
    // instantly, falls through to the unconditional heartbeat write at the bottom
    // of the pass, and lets the caller re-enter in a tight spin that emits
    // heartbeat frames at the client until real time crosses the boundary. `ceil`
    // is what turns that spin back into a wait.
    //
    // Asserted as a LOWER bound, because that is the only direction that separates
    // a real 1ms wait from an instant return; the upper bound is already covered
    // above. 2x margin on a wait a condition variable will not cut short.
    fake = base + 2 * cfg.tick - std::chrono::microseconds(500);
    const auto spin_start = std::chrono::steady_clock::now();
    REQUIRE(pump.pump_once(wire.writer()));
    CHECK(std::chrono::steady_clock::now() - spin_start >= std::chrono::microseconds(500));
}

TEST_CASE("McpPostPump/CH-4: a revoked credential kills the streamed-POST within one tick",
          "[mcp][bridge][2f][ch4]") {
    // "McpPostPump: revocation and session death close the response (C7)" above (landed
    // PR 3b, f268d78d) already proves the WIRE-level outcome for this exact scenario.
    // This test adds the same proof at the close_reason() ACCESSOR level - the state a
    // caller outside the wire (e.g. the bridge's own audit path) actually reads - as a
    // second, independent angle on the same verdict rather than a gap-fill; a bug that
    // latched the wrong reason into close_reason_ while still writing the right string
    // to the wire (or vice versa) would pass the C7 SECTION and fail this one.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-ch4"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); }, {},
        [] { return mcp::StreamRevalidate::kRevoked; }, [] { return true; }, fast_post_cfg());

    PostWire wire;
    // next_check_ defaults to the epoch (never seeded in the ctor, per CH-22 above),
    // so the credential check is due on the very first tick.
    CHECK_FALSE(pump.pump_once(wire.writer())); // provider ends
    CHECK(pump.close_reason() == mcp::McpStreamClose::kCredentialRevoked);
    CHECK(wire.contains(R"("reason":"credential_revoked")"));
}

TEST_CASE("bridge take_post_batch - ring-commits and hands the same frames to the wire (C7)",
          "[mcp][bridge][2f]") {
    // The ring copy is the durable one (GET resume); the returned frames are the
    // live one. Both come from ONE projection pass, so they cannot disagree.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-tb"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());

    SECTION("progress frames") {
        fx.bus.publish("exec-tb", "execution-progress", prog(1, 3));
        // The projector must NOT drain a kStreaming record - it is pump-owned.
        auto batch = poll_batch(*fx.bridge, *key);
        REQUIRE(batch.progress.size() == 1);
        CHECK(batch.progress[0].data.find("notifications/progress") != std::string::npos);
        CHECK_FALSE(batch.final_frame.has_value());
        // ...and the same frame is replayable.
        CHECK(count_method(ring_frames(*s.stream, "alice"), "notifications/progress") == 1);
    }
    SECTION("the final comes back separately so the pump can write it LAST") {
        fx.bus.publish("exec-tb", "execution-completed", kCompleted);
        Bridge::PostBatch batch;
        REQUIRE(poll_until([&] {
            batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/false);
            return batch.final_frame.has_value();
        }));
        auto j = json::parse(batch.final_frame->data, nullptr, /*allow_exceptions=*/false);
        REQUIRE(j.is_object());
        CHECK(j["result"]["status"] == "completed");
        CHECK(j["result"]["execution_id"] == "exec-tb");
        CHECK(count_results(ring_frames(*s.stream, "alice")) == 1);  // pinned for resume
    }
    SECTION("an idle record yields nothing and settles nothing") {
        auto batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/false);
        CHECK(batch.progress.empty());
        CHECK_FALSE(batch.final_frame.has_value());
        CHECK_FALSE(batch.cap_settled);
        CHECK_FALSE(batch.deferred);
    }
    SECTION("an unknown key is an empty tick, never a throw") {
        auto batch = fx.bridge->take_post_batch("no-such-key", /*cap_expired=*/true);
        CHECK(batch.progress.empty());
        CHECK_FALSE(batch.cap_settled);  // nothing to settle - the record is gone
    }
}

TEST_CASE("bridge take_post_batch - a terminal beats an expired cap (C7)",
          "[mcp][bridge][2f]") {
    // The cap is decided INSIDE the projection claim precisely so a terminal that
    // landed in the same instant still wins. Closing with kCapExpired while a real
    // result sat latched would tell the client to go poll for an answer the server
    // was holding.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cap"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());

    SECTION("cap expires with nothing latched - the pump may close") {
        auto batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        CHECK(batch.cap_settled);
        CHECK_FALSE(batch.final_frame.has_value());
    }
    SECTION("cap expires WITH a terminal latched - the terminal wins") {
        fx.bus.publish("exec-cap", "execution-completed", kCompleted);
        Bridge::PostBatch batch;
        REQUIRE(poll_until([&] {
            batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
            return batch.final_frame.has_value();
        }));
        CHECK_FALSE(batch.cap_settled);  // NOT a cap close - deliver the result
        auto j = json::parse(batch.final_frame->data, nullptr, /*allow_exceptions=*/false);
        CHECK(j["result"]["status"] == "completed");
    }
}

TEST_CASE("bridge take_post_batch - an expired cap settles one drain pass later, "
          "never at execution pace (#2739)",
          "[mcp][bridge][2f][ch23]") {
    // Before this fix, cap arbitration was reached only on a pass with neither
    // progress nor terminal pending - so a progress slot that refilled every
    // tick held the response open for the WHOLE execution, and every operator
    // statement derived from the 120 s cap was wrong. The contract that killed the naive
    // fix still holds: the drain pass DELIVERS latched work and stays open; only
    // the pass after it settles.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-drain"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());

    SECTION("continuous progress cannot hold the response open past the drain pass") {
        // publish() fans out to the bridge listener synchronously (under
        // Channel::mu), so every take below sees exactly what its preceding
        // publish latched into the progress slot - no polling needed on this path.
        fx.bus.publish("exec-drain", "execution-progress", prog(1, 5));
        auto drain = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        REQUIRE(drain.progress.size() == 1);  // latched work is DELIVERED (C7)...
        CHECK_FALSE(drain.cap_settled);       // ...and this pass stays open to do it
        // The execution keeps producing - the exact shape that used to keep the
        // response open indefinitely.
        fx.bus.publish("exec-drain", "execution-progress", prog(2, 5));
        auto settle = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        CHECK(settle.cap_settled);       // one drain pass, then the cap wins
        CHECK(settle.progress.empty());  // held back on the cap path...
        // ...and NOT lost: the record parks and the projector flushes the held
        // frame to the ring, so a GET resume still replays it.
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        REQUIRE(poll_until([&] {
            return count_method(ring_frames(*s.stream, "alice"), "notifications/progress") == 2;
        }));
    }

    SECTION("a terminal latched after the drain pass bypasses the suppression - "
            "held progress rides the same pass, ahead of the final") {
        fx.bus.publish("exec-drain", "execution-progress", prog(1, 5));
        auto drain = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        REQUIRE(drain.progress.size() == 1);
        fx.bus.publish("exec-drain", "execution-progress", prog(2, 5));
        fx.bus.publish("exec-drain", "execution-completed", kCompleted);
        auto fin = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        REQUIRE(fin.final_frame.has_value());
        CHECK_FALSE(fin.cap_settled);  // a real result is never masked as a cap close
        // The intervening frame is delivered on the terminal pass rather than
        // stranded in a record about to settle kDone; the pump writes progress
        // first and the final last, preserving progress-before-final ordering.
        REQUIRE(fin.progress.size() == 1);
        CHECK(fin.progress[0].data.find("notifications/progress") != std::string::npos);
    }

    SECTION("the drain pass pokes the bound sink - the settle pass needs no "
            "further event or tick to wake") {
        auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
        REQUIRE(fx.bridge->bind_post_sink(s.id, json(1), sink).has_value());
        fx.bus.publish("exec-drain", "execution-progress", prog(1, 5));
        // Let the projector's own wake-forwarding poke for this publish land
        // first, then shed it so the assertion isolates the drain pass's poke.
        REQUIRE(poll_until([&] { return sink->poked.load(std::memory_order_acquire); }));
        sink->poked.store(false, std::memory_order_release);
        auto drain = fx.bridge->take_post_batch(*key, /*cap_expired=*/true);
        REQUIRE(drain.progress.size() == 1);
        CHECK(sink->poked.load(std::memory_order_acquire));
    }
}

TEST_CASE("McpPostPump: wire frames carry the replay-ring event id (#2785)",
          "[mcp][bridge][2f][ch25]") {
    // The replay ring commits every streamed-POST frame under a real,
    // monotonically-increasing event id - but until this fix the pump wrote
    // every frame with the 2-arg SseEvent (id 0, "no id"), so a client that
    // only ever saw the POST connection had no id to hand back as
    // `Last-Event-ID` and the documented resume contract was unreachable from
    // this surface. Asserted against the WIRE TEXT and the ring only, so this
    // test compiles unchanged on the unfixed tree - where it fails.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-wireid"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());
    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); }, {}, {}, {},
        fast_post_cfg(), {}, nullptr, "cid-wireid", "exec-wireid");

    PostWire wire;
    fx.bus.publish("exec-wireid", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] {
        return pump.pump_once(wire.writer()) && wire.contains("notifications/progress");
    }));
    fx.bus.publish("exec-wireid", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return !pump.pump_once(wire.writer()); }));
    REQUIRE(wire.contains(R"("status":"completed")"));

    // Every ring-committed progress/result frame's id must appear as an SSE
    // `id:` line on the POST wire - the ring id is the only resume cursor a
    // POST-only client can ever learn. (Heartbeats carry none by design.)
    auto frames = ring_frames(*s.stream, "alice");
    std::size_t matched = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        const bool relevant = j.is_object() && (j.value("method", "") == "notifications/progress" ||
                                                j.contains("result"));
        if (!relevant) {
            continue;
        }
        REQUIRE(f.id != 0);
        CHECK(wire.contains("id: " + std::to_string(f.id) + "\n"));
        ++matched;
    }
    CHECK(matched >= 2);  // at least the one progress frame and the final
}

TEST_CASE("bridge bind_post_sink - gates on kStreaming and hands off latched work (C7)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-bind"));

    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    // kArming is not a live wire.
    CHECK_FALSE(fx.bridge->bind_post_sink(s.id, json(1), sink).has_value());
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());
    CHECK_FALSE(fx.bridge->bind_post_sink(s.id, json(99), sink).has_value());  // unknown
    CHECK_FALSE(fx.bridge->bind_post_sink(s.id, json(1), nullptr).has_value());  // null sink

    SECTION("the projector wakes the bound sink, and does so as a handoff") {
        // A streamed record's frames are ring-only (deliver_live=false), so the
        // publish path never notifies this sink - the projector is the ONLY thing
        // that can, and the record stays pump-owned meanwhile.
        //
        // SCOPE OF THIS TEST, stated honestly: it proves the record stays
        // PUMP-OWNED - the projector does not drain it behind the pump's back, and
        // the work is there for take_post_batch to collect.
        //
        // It does NOT test the wake itself. An earlier version held the sink mutex
        // across the publish to try to force the lost-wakeup window; that proved
        // nothing (mutation showed removing poke_post_sink's sink-mutex
        // acquisition left it green, because the poke only arrives after the bus
        // listener, the projector wake and a thread switch) AND it inverted the
        // lock order - the bus listener takes the record mutex, so holding the
        // sink mutex across a publish builds sink->record against the projector's
        // sanctioned record->sink, which TSan correctly flagged as a potential
        // deadlock. The wake discipline is recorded as uncovered at its source.
        fx.bus.publish("exec-bind", "execution-progress", prog(1, 3));
        auto batch = poll_batch(*fx.bridge, *key);
        CHECK(batch.progress.size() == 1);
    }
    SECTION("the sink is released when the wire goes away") {
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        CHECK(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kRingOnly);
        // Parked: the projector owns it again and drains it to the ring itself.
        fx.bus.publish("exec-bind", "execution-completed", kCompleted);
        REQUIRE(poll_until([&] { return count_results(ring_frames(*s.stream, "alice")) == 1; }));
    }
}

TEST_CASE("bridge streamed-POST close is allocation-free and keyed (C6c)",
          "[mcp][bridge][2f]") {
    // The pump's releaser runs inside ~Response, so it must not build the record
    // key itself - that is a bad_alloc site in a destructor. record_key() pays
    // that cost up front and the releaser closes with the string it returned.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-k"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);

    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());
    CHECK_FALSE(fx.bridge->record_key(s.id, json(99)).has_value());  // unknown record

    SECTION("no final written - the record parks for GET resume") {
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        CHECK(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kRingOnly);
        CHECK_FALSE(fx.bridge->on_post_closed_keyed(*key));  // exactly once
    }
    SECTION("final already on the wire - the record is DONE, not parked") {
        REQUIRE(fx.bridge->on_final_written(*key));
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        // Parking here would hold a resume window open for an answer the client
        // already has.
        auto ph = fx.bridge->phase_for(s.id, json(1));
        CHECK((!ph.has_value() || ph == Bridge::Phase::kDone));  // kDone, or already reaped
    }
    SECTION("a parked record still credits a final its pump actually wrote") {
        // The sweep's stale-arm backstop can flip kStreaming -> kRingOnly while
        // the pump is mid-tick; on_final_written must still accept the final that
        // pump goes on to write, or the session's pin leaks.
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));  // -> kRingOnly
        CHECK(fx.bridge->on_final_written(*key));
    }
}

TEST_CASE("on_final_written rejects a phase that never held a streamed wire (C6c)",
          "[mcp][bridge][2f]") {
    // The invariant that survives widening on_final_written to accept kRingOnly:
    // a record armed GET-only was never a streamed wire, so a final for it is
    // rejected. Mutation check: deleting the phase check entirely leaves this
    // green too unless this test exists — it is the coverage commit 97fd6379's
    // duplicate SECTION (same file, both asserting accept) claimed to have and
    // did not.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-getonly"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());
    CHECK_FALSE(fx.bridge->on_final_written(*key));
}

TEST_CASE("take_post_batch reports record_gone, not a silent empty tick (C6c)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-rg"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());

    SECTION("an unknown key reports record_gone") {
        auto batch = fx.bridge->take_post_batch("no-such-key", /*cap_expired=*/false);
        CHECK(batch.record_gone);
        CHECK_FALSE(batch.cap_settled);
    }
    SECTION("a key that existed before shutdown() reports record_gone") {
        fx.bridge->shutdown();
        auto batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/false);
        CHECK(batch.record_gone);
        CHECK_FALSE(batch.cap_settled);
    }
}

TEST_CASE("take_post_batch reports record_gone for a record settled kDone but not yet reaped (C6c)",
          "[mcp][bridge][2f]") {
    // Gate 8 wave 2 (cpp-safety): on_post_closed_keyed's own kDone transition
    // deliberately does NOT erase the record - "settle kDone and let sweep reap
    // it" - so a record can sit in records_ with phase kDone for an arbitrary
    // stretch before a later sweep pass claims and erases it. If a pump is still
    // ticking on that key in that window (the sweep's stranded-kStreaming
    // backstop having parked it earlier, or a slow releaser), take_post_batch
    // still finds the record and hands it to project_record, whose own
    // kArming/kDone/kAborted early return is the third record_gone gap the
    // first two fixed sites in take_post_batch did not cover.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-settled"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto key = fx.bridge->record_key(s.id, json(1));
    REQUIRE(key.has_value());

    REQUIRE(fx.bridge->on_final_written(*key));
    REQUIRE(fx.bridge->on_post_closed_keyed(*key));  // final_written -> kDone, not erased
    REQUIRE(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kDone);

    auto batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/false);
    CHECK(batch.record_gone);
    CHECK_FALSE(batch.cap_settled);
    CHECK_FALSE(batch.final_frame.has_value());
}

TEST_CASE("bridge sweep backstop PARKS a stranded kStreaming record, never reaps it (C6c)",
          "[mcp][bridge][2f]") {
    // No sweep pass claims kStreaming, so a record whose releaser never ran is
    // invisible to all of them - including session death - and leaks for the life
    // of the process. The backstop must PARK it: a reap would unsubscribe, unpin
    // and erase a result the client can still legitimately collect.
    Fx fx{Bridge::Config{.global_record_cap = 256,
                         .ring_only_pressure_cap = 64,
                         .streaming_park_after = std::chrono::seconds(0)}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-strand"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    // The releaser never runs - exactly the stranding this backstop exists for.
    fx.bridge->sweep();

    REQUIRE(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kRingOnly);  // PARKED
    CHECK(fx.reg.counter("yuzu_mcp_bridge_streaming_backstop_total").value() == 1.0);

    // Parked, not torn down: the subscription survived, so the real terminal
    // still reaches the ring for GET resume. A reap would have destroyed it.
    fx.bus.publish("exec-strand", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return count_results(ring_frames(*s.stream, "alice")) == 1; }));
    for (const auto& f : ring_frames(*s.stream, "alice")) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            CHECK(j["result"]["status"] == "completed");
            CHECK(j["result"]["execution_id"] == "exec-strand");
        }
    }
}

TEST_CASE("bridge sweep backstop leaves a healthy kStreaming record alone (C6c)",
          "[mcp][bridge][2f]") {
    // The mirror of the test above: with a live session and the normal threshold
    // the sweep must NOT park a stream out from under its own pump.
    Fx fx;  // default streaming_park_after = 600s
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-live"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    fx.bridge->sweep();
    CHECK(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kStreaming);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_streaming_backstop_total").value() == 0.0);
}

TEST_CASE("bridge park_after_dispatch_failure - parks, keeps the subscription, publishes the real final (C6b)",
          "[mcp][bridge][2f]") {
    // A post-dispatch failure means the work IS running, so the record must keep
    // its listener and stay able to publish the real terminal for GET resume.
    // abandon() would unsubscribe and discard a result the client can still
    // legitimately collect - that is the whole distinction this transition exists
    // to make.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-park"));
    REQUIRE(fx.bridge->park_after_dispatch_failure(s.id, json(1)));
    REQUIRE(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kRingOnly);

    // The subscription survived: a terminal published AFTER the park still
    // reaches the record and is projected as a pinned real final.
    fx.bus.publish("exec-park", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return count_results(ring_frames(*s.stream, "alice")) == 1; }));
    for (const auto& f : ring_frames(*s.stream, "alice")) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            CHECK(j["result"]["status"] == "completed");        // the REAL terminal
            CHECK(j["result"]["execution_id"] == "exec-park");  // durable handle
        }
    }
    CHECK(fx.audit_count("mcp.bridge.dispatch_failure") == 1);
}

TEST_CASE("bridge park_after_dispatch_failure - arbitration and the prebuilt fallback (C6b)",
          "[mcp][bridge][2f]") {
    SECTION("only kArming parks; a second call loses") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-1"));
        REQUIRE(fx.bridge->park_after_dispatch_failure(s.id, json(1)));
        CHECK_FALSE(fx.bridge->park_after_dispatch_failure(s.id, json(1)));  // no longer kArming
        CHECK(fx.audit_count("mcp.bridge.dispatch_failure") == 1);           // exactly once
    }
    SECTION("an armed record cannot be parked - arm won the arbitration") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-2"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        CHECK_FALSE(fx.bridge->park_after_dispatch_failure(s.id, json(1)));
    }
    SECTION("an unknown record is a no-op, never a throw") {
        Fx fx;
        auto s = fx.make_session();
        CHECK_FALSE(fx.bridge->park_after_dispatch_failure(s.id, json(99)));
    }
    SECTION("a record parked BEFORE arm still has a non-empty fallback final") {
        // subscribe() prebuilds it; without that, a parked-before-arm record whose
        // real-final build fails would publish an EMPTY frame, because arm() -
        // the only other place that fills fallback_final - never ran.
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-fb"));
        REQUIRE(fx.bridge->park_after_dispatch_failure(s.id, json(1)));
        // Fail the REAL final build so the projector publishes the prebuilt
        // fallback. An un-prebuilt record publishes an empty frame here, which
        // parses as no result at all - which is what the count below catches.
        fx.bridge->inject_projection_build_fault_for_test(1);
        fx.bus.publish("exec-fb", "execution-completed", kCompleted);
        REQUIRE(poll_until([&] { return count_results(ring_frames(*s.stream, "alice")) == 1; }));
        auto frames = ring_frames(*s.stream, "alice");
        REQUIRE(count_results(frames) == 1);
        for (const auto& f : frames) {
            auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
            if (j.is_object() && j.contains("result")) {
                CHECK(j["result"]["execution_id"] == "exec-fb");
                CHECK(j["result"]["status"] == "unknown");  // the prebuilt fallback shape
            }
        }
    }
}

TEST_CASE("bridge reserve - the streamed charge and the record commit together (C6a)",
          "[mcp][bridge][2f]") {
    // The ledger bump and the map insert BOTH allocate, so either can throw with
    // the other already applied. A bump that survives a failed insert is a phantom
    // charge: nothing will ever release it, so the session's streamed admissions
    // reject pin_slots forever.
    Fx fx;
    auto s = fx.make_session();
    fx.bridge->inject_reserve_commit_fault_for_test();
    REQUIRE_THROWS_AS(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true),
                      std::bad_alloc);
    CHECK_FALSE(fx.bridge->phase_for(s.id, json(1)).has_value());  // no orphan record

    // The load-bearing half: the ledger is invisible from outside, so the only
    // way to prove it rolled back is to spend every slot. kMaxStreamedPostsPerSession
    // is 4 - if the failed reserve leaked a charge, the FOURTH of these rejects.
    CHECK(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    CHECK(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    // ...and the cap itself still bites, so the test cannot pass by the ledger
    // simply never counting.
    auto over = fx.bridge->reserve(s.id, "alice", json(6), json("t"), true);
    CHECK_FALSE(over.ok);
    CHECK(std::string(over.reject_reason == nullptr ? "" : over.reject_reason) == "pin_slots");
}

// ── #2528: ~ClaimGuard must release the claim even when it cannot take mu ──────
//
// The claim used to be cleared INSIDE the try whose first act was the record-lock
// acquisition, so a lock failure left it set forever. All four consumers then skip
// the record; under the defer-ends-the-pass behaviour that predated UP-5 (#2489)
// one such victim also stalled ring-only pressure relief bridge-wide, and it now
// wedges only itself.
//
// Coverage note (deliberate, not an omission): the degraded path's third arm -
// storing terminal_projected when the frame was ALREADY published - needs the
// kRingOnly settle block (bridge_mu_ + mu) to fail as well as the guard's own
// lock, and no seam models that second failure. It is one relaxed store that can
// only help, so it stays as documented-uncovered defence-in-depth rather than
// getting a test that proves something weaker than it claims.

TEST_CASE("bridge #2528 - a ClaimGuard lock failure still releases the claim",
          "[mcp][bridge][2f][2528]") {
    // Progress-only batch: nothing was owed to the settle, so releasing the claim
    // is a COMPLETE recovery. The load-bearing assertion is the SECOND batch - it
    // can only project if the claim was released, and under the pre-fix code it
    // never appeared.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cg"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    fx.bridge->inject_claim_lock_fault_for_test(1);
    fx.bus.publish("exec-cg", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] {
        return count_method(ring_frames(*s.stream, "alice"), "notifications/progress") == 1;
    }));
    // The claim was taken for that batch and its guard hit the injected lock
    // failure, so the degraded release is what frees it - ~ClaimGuard is the other
    // releaser and it is precisely the one the injected failure disabled.
    REQUIRE(poll_until(
        [&] { return fx.reg.counter("yuzu_mcp_bridge_projection_degraded_total").value() == 1.0; }));

    fx.bus.publish("exec-cg", "execution-progress", prog(2, 3));
    REQUIRE(poll_until([&] {
        return count_method(ring_frames(*s.stream, "alice"), "notifications/progress") == 2;
    }));
    // Healed: the second batch's guard took mu normally, so nothing further degraded.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_projection_degraded_total").value() == 1.0);
}

TEST_CASE("bridge #2528 - a terminal lost to the degraded settle publishes the fallback, never -32014",
          "[mcp][bridge][2f][2528]") {
    // The one path that leaves a terminal extracted-but-unpublished is the double
    // build failure, whose documented recovery is "restore and let the next wake
    // retry". If the guard cannot retake mu, that restore is impossible and the
    // payload is gone for good - terminal_slot is empty and sticky
    // terminal_accepted stops any listener refill, so NO retry exists and a
    // consumer that merely defers would defer forever.
    //
    // The honest disposition is therefore the same as kTerminalKnownLost: a
    // terminal demonstrably happened, so publish the success-shaped fallback -
    // never -32014 (which would deny a terminal that did occur) and never a silent
    // kNone (which would answer the client nothing at all).
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-pl"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));  // -> kRingOnly

    fx.bridge->inject_projection_build_fault_for_test(1);     // real final throws
    fx.bridge->inject_projection_fallback_fault_for_test(1);  // ...and so does the fallback
    fx.bridge->inject_claim_lock_fault_for_test(1);
    fx.bus.publish("exec-pl", "execution-completed", kCompleted);

    // Sweep converges: before the projector runs, the visitor sees a latched but
    // unprojected terminal and defers (it must NOT steal it); once the degraded
    // settle marks the payload lost, the next sweep claims and publishes.
    REQUIRE(poll_until([&] {
        fx.bridge->sweep();
        return !fx.bridge->phase_for(s.id, json(1)).has_value();
    }));
    CHECK(fx.reg.counter("yuzu_mcp_bridge_projection_degraded_total").value() == 1.0);

    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);  // NEVER -32014
    REQUIRE(count_results(frames) == 1);                                 // exactly one final
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            CHECK(j["result"]["execution_id"] == "exec-pl");  // durable handle present
            CHECK(j["result"]["status"] == "unknown");        // fallback shape
        }
    }
    {  // audited as a published fallback, not as a silent expiry
        std::lock_guard<std::mutex> lk(fx.audit_mu);
        bool ok = false;
        for (const auto& row : fx.audits) {
            if (row.action == "mcp.bridge.forced_expire" &&
                row.detail == "the fallback final was published") {
                ok = true;
            }
        }
        CHECK(ok);
    }
}

// ── #2529: arm()'s cancel-degrade must return the charge both-or-neither ───────
//
// The degrade used to clear streamed_charge_held inside arm()'s flip hold and take
// bridge_mu_ afterwards. That acquisition is the sole throw site, so a failure left
// the record reading "not held" while streamed_unpinned_[session] still counted it:
// exactly-once release is keyed on the flag, so EVERY later release path - the
// projector settle, teardown_claimed - then found nothing to do and the session's
// admission slot was spent for good. Routing the release through release_charge,
// which takes both locks before mutating either half, makes the failure a DEFERRAL
// instead: the record and the ledger still agree, so the record's own teardown
// reclaims the slot.
//
// C8 is what makes this reachable at all - ArmMode::kStreaming has no production
// caller before it, so kDegradedGetOnly cannot happen today.
TEST_CASE("bridge #2529 - a charge-release lock failure defers, never strands, the admission slot",
          "[mcp][bridge][2f][2529]") {
    Fx fx;
    auto s = fx.make_session();
    // Record 1 is the degrade victim; 2-4 spend the remaining pin slots so the cap
    // is exactly consumed and a further reserve becomes the ledger probe (the
    // ledger is invisible from outside - spending the cap is the only way to read it).
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-2529"));
    for (int i = 2; i <= 4; ++i) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
    }

    // A cancel that lands BEFORE arm is the one path that returns a charge outside
    // teardown: arm consumes the intent and degrades the streamed record to GET-only.
    REQUIRE(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kAcceptedPending);
    fx.bridge->inject_charge_lock_fault_for_test(1);
    // CONTAINED, and the outcome is still the true one: the flip already succeeded,
    // so throwing here would lose a completed arm over a bookkeeping failure.
    CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming, "{}") ==
          Bridge::ArmOutcome::kDegradedGetOnly);
    CHECK(fx.reg.counter("yuzu_mcp_bridge_charge_release_deferred_total").value() == 1.0);

    // The charge was NOT returned and the ledger still counts it - they AGREE, so
    // the cap correctly still bites. This is NOT the load-bearing assertion: the
    // pre-fix code also rejected here (for the opposite, broken reason).
    auto pin_reject3 = fx.bridge->reserve(s.id, "alice", json(5), json("t"), true);
    // Null-guarded like the sibling at the C6a test: if the cap ever fails to
    // bite, std::string(nullptr) is UB and kills the whole binary instead of
    // failing this assertion cleanly.
    CHECK(std::string(pin_reject3.reject_reason == nullptr ? ""
                                                           : pin_reject3.reject_reason) ==
          "pin_slots");

    // THE LOAD-BEARING HALF. The record still reads "charge held", so the next
    // release path repairs it. For a degraded record that path is its teardown: the
    // GET-only terminal branch settles to kDone without touching the charge (a
    // GET-only record normally holds none), and the sweep's reap releases it.
    // Pre-fix the flag was already clear, so this teardown released nothing and the
    // slot stayed spent for the life of the session.
    fx.bus.publish("exec-2529", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] { return fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kDone; }));
    fx.bridge->sweep();
    REQUIRE_FALSE(fx.bridge->phase_for(s.id, json(1)).has_value());  // reaped
    CHECK(s.stream->pinned_count() == 0);  // GET-only never pins, so this reads the ledger alone
    CHECK(fx.bridge->reserve(s.id, "alice", json(6), json("t"), true).ok);
}

// ── C10: chaos P0 endpoint reproductions (docs/mcp-streamable-http-chaos-design.md) ──

TEST_CASE("CH-2: a parked streamed record survives a ring wrap - the pinned final is "
          "replayed exactly once, and an evicted cursor is a GAP not a silent skip",
          "[mcp][bridge][2f][chaos][ch2]") {
    // The re-run the chaos design defers to this rung: the final-frame eviction
    // exemption only exists once the bridge does. Shape in both halves: stream
    // progress, lose the client mid-stream, let the execution finish while nobody
    // is listening, then resume. The halves differ only in whether the client's
    // cursor outlived the ring - which is exactly the distinction CH-2 is about.
    const auto drive = [](Fx& fx, Fx::Session& s, const char* exec,
                          std::shared_ptr<mcp::sse_bus::SseSinkState>& sink,
                          std::optional<std::string>& key) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), exec));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        sink = std::make_shared<mcp::sse_bus::SseSinkState>();
        key = fx.bridge->bind_post_sink(s.id, json(1), sink);
        REQUIRE(key.has_value());
    };

    SECTION("in-window resume replays the missed frames AND the final, exactly once") {
        Fx fx{Bridge::Config{}, mcp::McpSessionRegistry::Config{.ring_cap = 64}};
        auto s = fx.make_session();
        std::shared_ptr<mcp::sse_bus::SseSinkState> sink;
        std::optional<std::string> key;
        drive(fx, s, "exec-ch2a", sink, key);

        mcp::McpPostPump pump(
            sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
            [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {},
            nullptr, "cid-ch2a", "exec-ch2a");
        PostWire wire;

        fx.bus.publish("exec-ch2a", "execution-progress", prog(1, 9));
        REQUIRE(poll_until([&] {
            pump.pump_once(wire.writer());
            return wire.count("notifications/progress") == 1;
        }));
        // What the client would send back as Last-Event-ID.
        const auto cursor = s.stream->next_event_id() - 1;

        // Client gone mid-stream. The record PARKS - subscription and any terminal
        // it later latches survive, which is what makes a resume meaningful.
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        CHECK(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kRingOnly);

        // Execution carries on with nobody listening, then finishes.
        for (int i = 2; i <= 5; ++i) {
            fx.bus.publish("exec-ch2a", "execution-progress", prog(i, 9));
        }
        fx.bus.publish("exec-ch2a", "execution-completed", kCompleted);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

        auto replayed = ring_frames(*s.stream, "alice", cursor);
        CHECK(count_method(replayed, "notifications/progress") > 0); // the missed frames
        CHECK(count_results(replayed) == 1); // the answer, exactly once
    }

    SECTION("a cursor the ring outran is a GAP - but the ANSWER still survives the wrap") {
        Fx fx{Bridge::Config{}, mcp::McpSessionRegistry::Config{.ring_cap = 6}};
        auto s = fx.make_session();
        std::shared_ptr<mcp::sse_bus::SseSinkState> sink;
        std::optional<std::string> key;
        drive(fx, s, "exec-ch2b", sink, key);

        mcp::McpPostPump pump(
            sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
            [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {},
            nullptr, "cid-ch2b", "exec-ch2b");
        PostWire wire;

        fx.bus.publish("exec-ch2b", "execution-progress", prog(1, 20));
        REQUIRE(poll_until([&] {
            pump.pump_once(wire.writer());
            return wire.count("notifications/progress") == 1;
        }));
        const auto stale_cursor = s.stream->next_event_id() - 1;

        REQUIRE(fx.bridge->on_post_closed_keyed(*key));
        // Comfortably more frames than the ring holds, so the cursor is
        // outrun. #2412: progress is now a single latest-wins slot, so a
        // tight publish loop (the old shape here) would coalesce all 15
        // events into whichever one the projector happened to still find
        // pending, never reliably wrapping the ring - step-synchronize so
        // each is individually drained (a new ring frame lands) before the
        // next is published.
        for (int i = 2; i <= 16; ++i) {
            const auto before = s.stream->next_event_id();
            fx.bus.publish("exec-ch2b", "execution-progress", prog(i, 20));
            REQUIRE(poll_until([&] { return s.stream->next_event_id() > before; }));
        }
        fx.bus.publish("exec-ch2b", "execution-completed", kCompleted);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

        // Refused as a GAP rather than served a hole: a silently-short replay is
        // worse than an error, because the client would believe it had the lot.
        auto att = s.stream->attach_and_replay(stale_cursor, nullptr, "alice");
        CHECK(att.status == mcp::McpStreamState::AttachStatus::kGap);

        // The history is gone; the RESULT is not. The final was pinned, so the
        // wrap could not evict it, and a re-initialising client still collects it.
        CHECK(s.stream->pinned_count() == 1);
        CHECK(count_results(ring_frames(*s.stream, "alice")) == 1);
    }
}

TEST_CASE("CH-12: a duplicate cancel is a no-op - the detach is audited exactly once",
          "[mcp][bridge][2f][chaos][ch12]") {
    // The gap the re-review found: both cancel tests sent exactly ONE cancel, so
    // they passed while a second cancel could close again and audit again. A
    // retried notification is ordinary client behaviour - the interlock has to be
    // the close TRANSITION, because the phase does not change until the pump's
    // releaser parks the record, which is later than the duplicate arrives.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-dup"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    // First cancel wins the transition.
    CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kDetached);
    // Second arrives before the releaser has parked anything: same phase, same live
    // sink, and it must NOT claim a detach it did not perform.
    CHECK(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kStreaming);
    CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    CHECK(fx.audit_count("mcp.bridge.cancel") == 1);
}

TEST_CASE("CH-12: a cancel arriving after the pump already ended the response is a no-op",
          "[mcp][bridge][2f][chaos][ch12]") {
    // The window round 3 found: the pump ends the response (here by delivering the
    // final), but httplib has not yet run the releaser that parks the record. The
    // record therefore still LOOKS cancellable - kStreaming, sink still bound - and
    // before the fix a cancel would win the flag and audit "detached the streamed
    // response" for a response that had already completed. An audit row that
    // overstates an outcome is worse than a missing one, so the pump now publishes
    // liveness into the same flag the cancel interlock reads.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-late"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
        [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {}, nullptr,
        "cid-late", "exec-late");
    PostWire wire;

    // Drive the pump to its natural end - the final is delivered and it returns
    // false. The releaser has NOT run: the record is still kStreaming.
    fx.bus.publish("exec-late", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return !pump.pump_once(wire.writer()); }));
    REQUIRE(fx.bridge->phase_for(s.id, json(1)) == Bridge::Phase::kStreaming);

    // A cancel landing in that window must NOT claim a detach it did not perform.
    CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    CHECK(fx.audit_count("mcp.bridge.cancel") == 0);
}

TEST_CASE("every CancelOutcome has a label, and every label is one the server pre-seeds",
          "[mcp][bridge][2f]") {
    // Both-or-neither, same shape as the kTeardownStageNames cross-check. `detached`
    // shipped emitted-but-unseeded precisely because the label lived at the emit
    // site and the seed list was hand-written somewhere else; this walks the enum so
    // a new outcome cannot repeat that.
    for (auto o : {Bridge::CancelOutcome::kAcceptedPending, Bridge::CancelOutcome::kDetached,
                   Bridge::CancelOutcome::kNoOp}) {
        const std::string label = Bridge::cancel_outcome_label(o);
        CHECK_FALSE(label.empty());
        CHECK(std::find(Bridge::kCancelOutcomeLabels.begin(),
                        Bridge::kCancelOutcomeLabels.end(),
                        label) != Bridge::kCancelOutcomeLabels.end());
    }
    // Distinct labels: two outcomes collapsing onto one string would silently make
    // the metric unable to tell a real detach from a no-op.
    std::set<std::string> uniq(Bridge::kCancelOutcomeLabels.begin(),
                               Bridge::kCancelOutcomeLabels.end());
    CHECK(uniq.size() == Bridge::kCancelOutcomeLabels.size());
}

TEST_CASE("CH-12: cancel mid-execution detaches the response but never the execution",
          "[mcp][bridge][2f][chaos][ch12]") {
    // "Cancelled != cancelled": MCP cancellation is about the CLIENT'S interest in
    // a response, not about the work. A dispatched command keeps running on real
    // agents and its result stays durably fetchable - anything else would let a
    // client believe it had stopped a fleet-wide change it had not.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-ch12"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
        [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {}, nullptr,
        "cid-ch12", "exec-ch12");
    PostWire wire;

    fx.bus.publish("exec-ch12", "execution-progress", prog(1, 3));
    REQUIRE(poll_until([&] {
        pump.pump_once(wire.writer());
        return wire.contains("notifications/progress");
    }));

    // The client cancels, through the REAL production entry point. This used to
    // set `sink->closed` by hand, which is why the adversarial review found the
    // whole path missing: simulating the trigger proved the pump's half and
    // silently assumed the bridge half existed. It did not - request_cancel
    // no-oped for anything past kArming, so a live streamed POST could not be
    // cancelled at all. Drive the seam a `notifications/cancelled` actually
    // reaches, or this test proves nothing about cancellation.
    REQUIRE(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kDetached);
    REQUIRE_FALSE(pump.pump_once(wire.writer())); // provider ends
    CHECK(fx.audit_count("mcp.bridge.cancel") == 1); // audited exactly once (CH-12)

    // The close frame must SAY the execution continues, and name the handle that
    // reaches it - a client that is told nothing has no way back to its result.
    REQUIRE(wire.contains("notifications/yuzu.stream_closed"));
    CHECK(wire.contains(R"("execution_id":"exec-ch12")"));
    CHECK(wire.contains(R"("partial":true)"));

    // THE POINT: the execution was never touched. Its terminal still publishes,
    // still pins, and is still replayable by a client that comes back for it.
    REQUIRE(fx.bridge->on_post_closed_keyed(*key));
    fx.bus.publish("exec-ch12", "execution-completed", kCompleted);
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    CHECK(count_results(ring_frames(*s.stream, "alice")) == 1);
}

// ── Governance 2026-07-27 Gate 3/4 blockers: the concurrency set (CH-14) ──────

TEST_CASE("CH-14: a stalled socket write must never block a publisher",
          "[mcp][bridge][2f][chaos][ch14]") {
    // safe-B1, asserted at its ROOT LINK. `finish()` writes the close frame to the
    // socket; if that runs while the pump still holds `sink_->mu`, every other
    // thread that needs that sink blocks for as long as the peer refuses to read
    // (bounded only by the 30s socket write timeout in production).
    //
    // The downstream cascade is what makes it a bridge-wide outage - the
    // projector's poke_post_sink wants sink-mu WHILE HOLDING rec-mu, the sweep then
    // wants rec-mu WHILE HOLDING bridge_mu_, and reserve() on any other session
    // queues behind that. Every link is in the sanctioned lock order, which is why
    // TSan sees no cycle. This test pins the root link deterministically rather
    // than racing the projector and sweep into position: fix the root and the
    // cascade cannot form.
    //
    // The GET pump has always unlocked before finish, with the comment "a stalled
    // socket write must never block a publisher". The POST pump did not.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-ch14"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
        [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {}, nullptr,
        "cid-ch14", "exec-ch14");
    BlockingWire wire;
    wire.block();

    // Cancel, so the pump wakes and enters finish(kCancelled); the peer then
    // refuses to read, parking the pump inside the close-frame write.
    REQUIRE(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kDetached);
    auto pumping = std::async(std::launch::async, [&] { return pump.pump_once(wire.writer()); });
    REQUIRE(wire.await_parked());

    // A retried cancel is ordinary client behaviour (the bridge says so itself),
    // and it needs rec-mu then sink-mu. It must not wait on a stranger's socket.
    auto second = std::async(std::launch::async,
                             [&] { return fx.bridge->request_cancel(s.id, json(1)); });
    const bool completed = second.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    CHECK(completed);  // pre-fix: still parked behind the blocked write

    wire.release();
    if (completed) {
        CHECK(second.get() == Bridge::CancelOutcome::kNoOp);  // exactly-once holds
    } else {
        second.wait();  // do not leave the future dangling into teardown
    }
    CHECK_FALSE(pumping.get());  // the provider ended
}

TEST_CASE("CH-16: progress reaches the wire on publication, not on the tick",
          "[mcp][bridge][2f][chaos][ch16]") {
    // UP-1. The rung's headline claim is progress-before-the-response, delivered as
    // it happens. The pump waits on a PREDICATED wait_for, so a bare notify_one
    // re-evaluates the predicate and keeps sleeping; unless the predicate can see
    // that the BRIDGE has work, the projector's wake-forwarding and bind_post_sink's
    // handshake are both dead code and progress arrives on a fixed tick grid.
    //
    // A deliberately huge tick makes that unambiguous: if the timeout is what wakes
    // this pump - rather than the bus notify under test - the test waits 30s and
    // fails. It also explains
    // why C7's mutant 8 survived - removing the sink-mutex acquisition from an inert
    // function changes nothing, and that was mistaken for a timing subtlety.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-ch16"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    mcp::McpPostPump::Config slow{};
    slow.tick = std::chrono::seconds(30);  // only a real wake can beat this
    mcp::McpPostPump pump(
        sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
        [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, slow, {}, nullptr, "cid-ch16",
        "exec-ch16");
    PostWire wire;

    // CLEAR THE RESIDUAL BIND POKE FIRST. bind_post_sink pokes the sink as part of
    // its handshake, so the pump's predicate is already satisfied before it ever
    // parks: the first pass returns immediately having drained nothing, and asserting
    // on that single pass reads a heartbeat and no progress frame. This failed 3 of 3
    // at 1.5x CPU oversubscription for exactly that reason while passing 8/8
    // unloaded - and oversubscription is the ordinary state of both self-hosted
    // pools, four runner agents to a box. Clearing under the sink mutex, the same
    // lock poke_post_sink and the wait predicate both take, makes the publication the
    // only thing that can wake this pump.
    {
        std::lock_guard<std::mutex> lk(sink->mu);
        sink->poked.store(false, std::memory_order_release);
    }

    std::atomic<bool> about_to_pump{false};
    auto pumping = std::async(std::launch::async, [&] {
        about_to_pump.store(true, std::memory_order_release);
        // LOOP, bounded by the wire content. `about_to_pump` proves only that this
        // thread entered the lambda, never that the pump is parked in wait_for, and
        // the wake is forwarded by the PROJECTOR thread - so on a contended box a
        // pass can still return before the frame is latched. A pass with nothing to
        // do blocks the full 30 s tick, so this cannot spin, and the elapsed-time
        // assertion below is still what proves a publication rather than a timeout
        // delivered the frame.
        for (;;) {
            if (!pump.pump_once(wire.writer())) {
                return false;  // stream ended without ever carrying progress
            }
            if (wire.contains("notifications/progress")) {
                return true;
            }
        }
    });
    while (!about_to_pump.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    const auto t0 = std::chrono::steady_clock::now();
    fx.bus.publish("exec-ch16", "execution-progress", prog(1, 3));
    CHECK(pumping.get());  // returns only once the pump actually carried the frame
    const auto waited = std::chrono::steady_clock::now() - t0;

    CHECK(wire.contains("notifications/progress"));
    // Well under the tick: proves a publication woke it, not the timeout.
    CHECK(waited < std::chrono::seconds(5));
}

TEST_CASE("CH-15: pin slots are a concurrency limit, never a lifetime quota",
          "[mcp][bridge][2f][chaos][ch15]") {
    // arch-A1 / UP-2. `mcp_stream.hpp` documents TWO unpin rules: (b) a GET resume
    // whose cursor passed the final, and (a) "the final was written on the POST
    // wire" - which is THIS rung's job and was never wired, so `unpin()` had zero
    // callers. Admission counts `pinned_count() + streamed_unpinned_`, so four
    // SUCCESSFUL streamed calls exhausted a session forever, answering 429 with
    // remediation telling the client to wait for calls that had already finished.
    //
    // No fault injection: pure sequencing. That is why it is cheap to test and why
    // it was missed - the existing pin-slot test drove the CHARGE path (parked
    // records, no finals published) where pinned_count() is always 0.
    Fx fx;
    auto s = fx.make_session();

    for (int i = 1; i <= 12; ++i) {  // 3x the cap, sequentially
        const std::string exec = "exec-ch15-" + std::to_string(i);
        auto rr = fx.bridge->reserve(s.id, "alice", json(i), json("t"), true);
        INFO("sequential completed streamed call #" << i
             << " reject=" << (rr.reject_reason == nullptr ? "" : rr.reject_reason));
        REQUIRE(rr.ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
        auto key = fx.bridge->bind_post_sink(s.id, json(i), sink);
        REQUIRE(key.has_value());

        mcp::McpPostPump pump(
            sink, [&](bool cap) { return fx.bridge->take_post_batch(*key, cap); },
            [&] { (void)fx.bridge->on_final_written(*key); }, {}, {}, fast_post_cfg(), {},
            nullptr, "cid-ch15", exec);
        PostWire wire;

        // Complete it properly: terminal published, final written to the wire, then
        // the response closes exactly as the releaser would.
        fx.bus.publish(exec, "execution-completed", kCompleted);
        REQUIRE(poll_until([&] { return !pump.pump_once(wire.writer()); }));
        REQUIRE(wire.contains(R"("result")"));
        REQUIRE(fx.bridge->on_post_closed_keyed(*key));

        // The pin for a final the client has ALREADY received must not linger.
        CHECK(s.stream->pinned_count() == 0);
    }
}

TEST_CASE("CH-14b: a cancel racing a completing tick must not claim a detach",
          "[mcp][bridge][2f][chaos][ch14]") {
    // Gate 8. The exactly-once interlock is the `closed` flip, so WHERE it happens
    // decides what a mid-tick cancel is told. Flipping it at finish() left the whole
    // rest of the tick exposed - revalidate is a store round trip, then
    // session_alive, then every progress write and the final write - so a cancel
    // landing in there won the exchange and audited "detached the streamed
    // response" while the client received progress, its result and EOF, and the
    // close audit recorded reason=completed. Two contradictory compliance rows for
    // one exchange.
    //
    // The bridge now flips `closed` at the DECISION: the moment it hands back a
    // final, the response IS ending and there is nothing left to detach.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-ch14b"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    // Take the batch WITHOUT running the pump's write half - this is precisely the
    // mid-tick instant the old code left open, reproduced deterministically rather
    // than raced.
    fx.bus.publish("exec-ch14b", "execution-completed", kCompleted);
    Bridge::PostBatch batch;
    REQUIRE(poll_until([&] {
        batch = fx.bridge->take_post_batch(*key, /*cap_expired=*/false);
        return batch.final_frame.has_value();
    }));

    // The client's result is in hand and the response is committed to ending, so a
    // cancel arriving now has nothing to detach - and must not say otherwise.
    CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    CHECK(fx.audit_count("mcp.bridge.cancel") == 0);
}

TEST_CASE("a client-driven bridge audit carries the caller, not \"system\"",
          "[mcp][bridge][2f][audit]") {
    // Decision 15(j) non-repudiation, and the fix for it was untested (Gate 8:
    // both the compliance and cpp-safety re-reviews flagged that the fixture
    // captured the actor but nothing asserted on it). An investigator has to be
    // able to tell WHICH client detached a live response - a row stamped "system"
    // is indistinguishable from the bridge's own housekeeping.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-actor"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    auto sink = std::make_shared<mcp::sse_bus::SseSinkState>();
    auto key = fx.bridge->bind_post_sink(s.id, json(1), sink);
    REQUIRE(key.has_value());

    REQUIRE(fx.bridge->request_cancel(s.id, json(1), "alice") == Bridge::CancelOutcome::kDetached);

    std::lock_guard<std::mutex> lk(fx.audit_mu);
    bool found = false;
    for (const auto& row : fx.audits) {
        if (row.action == "mcp.bridge.cancel") {
            found = true;
            CHECK(row.actor == "alice");  // NOT empty, which the sink maps to "system"
        }
    }
    CHECK(found);
}

// #2740's admission reclaim has two accepted residuals, and BOTH were untestable and one
// was also UNCOUNTED until this round. That combination is why they matter more than their
// severity suggests: a runbook shipped telling operators to rule the raced case out by
// checking two counters, and the raced case moved neither, so the procedure concluded
// "genuine accounting drift" for precisely the residual it was written to excuse.
//
// The seam (`UnpinFault`) exists to make both reachable from one thread. What each arm
// pins here is the same three-part contract: the admission STANDS (the residual is an
// over-admission, not a refusal), the pin is NOT credited as displaced (we did not release
// it, so attributing a loss to the admitting principal would be false), and the arm's OWN
// counter moves so an operator can tell which residual they are looking at.
TEST_CASE("#2795/#2805: a failed pin release still admits, and each arm counts separately",
          "[mcp][bridge][pins][ch26]") {
    const auto drive = [](mcp::McpStreamState::UnpinFault fault) {
        struct Out {
            bool admitted{};
            double raced{};
            double failed{};
            double displaced{};
            double ring_displaced{};
            std::size_t audits{};
            std::size_t still_pinned{};
        };
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
        auto s = fx.make_session();

        // Fill every pin slot with a parked, undelivered final - the state in which the
        // next admission must reclaim rather than refuse.
        for (int i = 1; i <= 4; ++i) {
            const std::string exec = "exec-residual-" + std::to_string(i);
            REQUIRE(poll_until([&] {
                return fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok;
            }));
            REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
            REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                    Bridge::ArmOutcome::kArmed);
            REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));  // peer gone before the final
            fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
            REQUIRE(poll_until([&] {
                return s.stream->pinned_count() == static_cast<std::size_t>(i);
            }));
        }
        REQUIRE(s.stream->pinned_count() == 4);

        // Arm the residual, then make the admission that triggers the reclaim.
        s.stream->inject_unpin_fault_for_test(fault);
        Out out;
        out.admitted = fx.bridge->reserve(s.id, "alice", json(99), json("t"), true).ok;
        out.raced = fx.reg.counter("yuzu_mcp_bridge_pin_release_raced_total").value();
        out.failed = fx.reg.counter("yuzu_mcp_bridge_pin_release_failed_total").value();
        out.displaced =
            fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value();
        // The pin-slot array's own LRU-displacement counter (mcp_stream.cpp,
        // kMetricPinDisplaced) - a distinct metric from the bridge-level
        // admission-reclaim one above, and NOT the replay ring's own frame-
        // eviction counter (kMetricRingEvictions /
        // yuzu_mcp_stream_replay_ring_evictions_total) despite the "ring"-
        // adjacent name: this one only strips a pinned terminal's eviction
        // EXEMPTION, it never evicts a frame from the ring itself. This
        // residual's admission-time reclaim never touches it: selecting and
        // releasing a pin for the ADMISSION side is a separate code path from
        // publish()'s pin-slot-full LRU branch, which is what actually
        // increments this counter (#2795's acceptance criteria named this
        // assertion explicitly). Not a claim that this branch can never fire
        // from a LATER event on this same session (docs/mcp-server.md's
        // "Terminal durability" prose says it can) - only that THIS reclaim,
        // here, does not reach it.
        out.ring_displaced = fx.reg.counter("yuzu_mcp_stream_pin_displaced_total").value();
        out.audits = fx.audit_count("mcp.bridge.pin_displaced_for_admission");
        // POSITIVELY confirm the over-admission rather than inferring it from the absence
        // of the displaced counter: the pin the reclaim selected is still HELD, so the
        // session is genuinely one call over its cap. Without this the assertions above
        // cannot distinguish "the release failed" from "the release worked and some other
        // bookkeeping step went wrong".
        out.still_pinned = s.stream->pinned_count();
        return out;
    };

    SECTION("the release loses a race (#2795): counted as raced, never as displaced") {
        const auto out = drive(mcp::McpStreamState::UnpinFault::kRaceLost);
        CHECK(out.admitted);      // the admission stands - this is the over-admission
        CHECK(out.raced == 1.0);  // ...and it is now VISIBLE, which was the whole defect
        CHECK(out.failed == 0.0);
        // Not credited as a displacement, and not audited: no exemption was released by
        // us, so attributing that loss to the admitting principal would be a false record.
        CHECK(out.displaced == 0.0);
        CHECK(out.ring_displaced == 0.0);  // the pin-slot LRU displacement never fires either
        CHECK(out.audits == 0);
        CHECK(out.still_pinned == 4);  // the pin was NOT released - the session is over cap
    }

    SECTION("the release throws (#2805): counted as failed, never as displaced") {
        const auto out = drive(mcp::McpStreamState::UnpinFault::kThrow);
        CHECK(out.admitted);
        CHECK(out.failed == 1.0);
        CHECK(out.raced == 0.0);  // the two arms are distinct, not aliases
        CHECK(out.displaced == 0.0);
        CHECK(out.ring_displaced == 0.0);
        CHECK(out.audits == 0);
        CHECK(out.still_pinned == 4);  // the pin was NOT released - the session is over cap
    }
}

// #2791's other unasserted branch: admission declines rather than reclaiming while a
// candidate is mid-projection. The guard (select_displaceable_pin_locked,
// mcp_stream_bridge.cpp:645-653/684-686) aborts the WHOLE scan the instant ANY of a
// session's records reads projection_in_flight - not "every candidate", which is what
// the issue text says but not what the code does: a perfectly good, individually-
// reclaimable victim sits right next to the one mid-projection record below, and the
// scan discards it anyway.
//
// Exactly TWO settled records, not three or four - this count is load-bearing, not
// arbitrary. The record being projected double-counts itself while stalled (its final
// is already pinned in the RING by publish_terminal_ladder before this window, but its
// charge is not yet cleared - the exact "one settling record as two slots" the header
// contract names), so a session with N settled + 1 mid-projection reads as pinned=N+1,
// unpinned=1 the instant the first read fires. For the guard's presence to be the thing
// deciding the outcome (not just arithmetic saturation a reclaim couldn't fix regardless
// of the guard), a SINGLE granted reclaim must be enough to clear the cap:
// (N+1-1)+1 < 4  =>  N < 3. N=2 is the largest count where that holds, so it is the one
// value that makes disabling the guard observably flip this test - anything higher
// declines either way and would leave the guard's necessity unproven.
//
// No existing seam reaches this deterministically: `projection_in_flight` is set and
// cleared entirely inside one project_record call via a function-local ClaimGuard, and
// every throw path in this file already clears it before returning (#2528) - a fault
// injected anywhere in the claim window still lets the next scan see it cleared. Hence
// the new stall seam (mcp_stream_bridge.{hpp,cpp}, #2791), parked in the one window the
// header contract calls out by name: after the ladder commits the frame, before
// `pinned_event_id` is stamped.
//
// RED-PROOF (see PR body for the full trace): commenting out the
// `if (projection_in_flight) { return std::nullopt; }` return at :684-686 turns this
// red, and not narrowly - the record being projected is, at that exact moment, marked
// `continue`d out of the loop BEFORE `pin_referenced` is set for it (:645-648, ahead of
// :654-662), so its own live-but-uncommitted pin reads as unreferenced and the ORPHAN
// scan (:698-707) claims it instead of the settled victim. `res.ok` flips true, and
// BOTH the displaced counter and the audit row fire for a pin that was never released
// (the id it "reclaimed" is the mid-projection record's own) - three assertions below
// go red together, not one, which is why this is the "live call's pin looks like an
// orphan" hazard the header contract names, observed directly rather than reasoned about.
TEST_CASE("bridge admission declines rather than reclaiming while a candidate is "
          "mid-projection, even with another valid candidate present (#2791)",
          "[mcp][bridge][2f][ch27]") {
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();

    // Two fully-settled, individually reclaimable parked finals. Full settle wait
    // (pinned==i AND unpinned==0), not just the ring pin - see the matching comment
    // on the on_final_written racer test above (#2791 UP-4): waiting on pinned_count()
    // alone does not prove record i's projection has moved past its own (unarmed, so
    // harmless to IT, but relevant to whichever record gets stalled next) check line.
    for (int i = 1; i <= 2; ++i) {
        const std::string exec = "exec-decline-" + std::to_string(i);
        REQUIRE(poll_until([&] {
            return fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok;
        }));
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] {
            const auto snap = fx.bridge->accounting_snapshot_for_test(s.id, s.stream);
            return snap.pinned == static_cast<std::size_t>(i) && snap.unpinned == 0;
        }));
    }
    REQUIRE(s.stream->pinned_count() == 2);

    // The third is the one parked mid-projection: charged, closed, its terminal
    // latched, then stalled after the ladder commits the frame (ring pin now live) and
    // before pinned_event_id is stamped - the phantom-double-count window.
    REQUIRE(poll_until([&] {
        return fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok;
    }));
    REQUIRE(fx.bridge->subscribe(s.id, json(3), "exec-decline-3"));
    REQUIRE(fx.bridge->arm(s.id, json(3), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(3)));  // -> kRingOnly, charged

    // Guards the arm/release pair against a fatal REQUIRE between them: if any REQUIRE
    // below throws before the intentional release() call further down runs, this
    // destructs first (declared after the arm, so it unwinds before `fx` per reverse
    // declaration order) and releases the parked projector thread itself, rather than
    // leaving it to the 10s internal backstop. release_projection_stall_for_test() is
    // documented idempotent, so running it again here after the intentional release
    // below is a harmless no-op, not a double-release bug (#2791, cpp-safety floor -
    // this mirrors the file's existing UnsubGuard idiom above, "built to survive fatal
    // REQUIREs below").
    struct StallGuard {
        Bridge& bridge;
        explicit StallGuard(Bridge& b) : bridge(b) {}
        StallGuard(const StallGuard&) = delete;
        StallGuard& operator=(const StallGuard&) = delete;
        ~StallGuard() { bridge.release_projection_stall_for_test(); }
    };
    fx.bridge->arm_projection_stall_for_test();
    StallGuard stall_guard{*fx.bridge};
    fx.bus.publish("exec-decline-3", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(fx.bridge->wait_projection_stall_reached_for_test());
    // Confirms the phantom double-count is live: the ring already shows the
    // not-yet-attributed pin (3), while the charge it also still holds is not yet
    // cleared (unpinned 1) - reading 4 total against a cap of 4 is exactly why the
    // FIRST admission check below even reaches selection.
    REQUIRE(fx.bridge->accounting_snapshot_for_test(s.id, s.stream).pinned == 3);

    const auto res = fx.bridge->reserve(s.id, "alice", json(99), json("t"), true);
    CHECK_FALSE(res.ok);
    CHECK(std::string(res.reject_reason) == "pin_slots");
    // No false credit for a release that did not happen: nothing was released, so
    // nothing is counted or audited as a displacement.
    CHECK(fx.reg.counter("yuzu_mcp_bridge_pin_displaced_for_admission_total").value() == 0.0);
    CHECK(fx.audit_count("mcp.bridge.pin_displaced_for_admission") == 0);

    fx.bridge->release_projection_stall_for_test();
    // Wait for the settle, not just the ring pin (which was already visible before
    // release - see the comment block above): the charge clear and the
    // projection_in_flight clear both happen AFTER this window, inside the locked block
    // the stall sits just before. `unpinned == 0` is sufficient proof of full settle
    // ONLY because N=2: the post-settle admission below (pinned=3, unpinned=0, sum=3)
    // never re-enters the cap branch, so it can't observe a not-yet-cleared flag either.
    // A test that needed the RECLAIM path post-settle would have to wait on the flag
    // too, not just the charge.
    REQUIRE(poll_until(
        [&] { return fx.bridge->accounting_snapshot_for_test(s.id, s.stream).unpinned == 0; }));

    // Once record 3 settles, the SAME admission that just declined succeeds - proving
    // the decline was about the window, not a permanent lockout, and that this session
    // is not left wedged by the seam.
    CHECK(fx.bridge->reserve(s.id, "alice", json(100), json("t"), true).ok);
}

// QA-1: the UnpinFault seam's own one-shot/disarm contract, tested directly on a bare
// McpStreamState with no bridge involved.
//
// This exists because a governance reviewer built the whole server suite against a
// mutation that moved the throw ABOVE the decrement in unpin()'s seam - which would leave
// a kThrow fault armed forever instead of firing `times` times - and all 235k assertions
// stayed green. Nothing anywhere guarded the contract that the Resource Ledger asserts.
// The sibling PublishFault seam has both a direct state-level test and several times=2
// uses; this one had neither.
TEST_CASE("UnpinFault: `times` fires exactly N times and then disarms",
          "[mcp][stream][pins][ch26]") {
    yuzu::MetricsRegistry reg;
    mcp::McpStreamState state{mcp::kMcpRingCapDefault, &reg};

    SECTION("kThrow with times=2 throws twice, then resumes normal service") {
        const std::uint64_t id = state.publish_final("execution-completed", "{}");
        REQUIRE(id != 0);
        REQUIRE(state.pinned_count() == 1);

        state.inject_unpin_fault_for_test(mcp::McpStreamState::UnpinFault::kThrow, 2);
        CHECK_THROWS(state.unpin(id));
        CHECK_THROWS(state.unpin(id));
        // Disarmed: the third call does real work. If the decrement ran AFTER the throw
        // this line would throw instead, and the pin would never clear.
        CHECK(state.unpin(id));
        CHECK(state.pinned_count() == 0);
    }

    SECTION("kRaceLost reports failure without clearing, then the next call clears") {
        const std::uint64_t id = state.publish_final("execution-completed", "{}");
        REQUIRE(id != 0);
        REQUIRE(state.pinned_count() == 1);

        state.inject_unpin_fault_for_test(mcp::McpStreamState::UnpinFault::kRaceLost);
        CHECK_FALSE(state.unpin(id));
        // The distinguishing assertion: a raced release must leave the pin ALONE. A seam
        // that returned false while still clearing the slot would model the residual
        // wrongly and every test built on it would be quietly meaningless.
        CHECK(state.pinned_count() == 1);

        CHECK(state.unpin(id));  // fault consumed
        CHECK(state.pinned_count() == 0);
    }
}
