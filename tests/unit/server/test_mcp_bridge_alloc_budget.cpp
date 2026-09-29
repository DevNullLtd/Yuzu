/**
 * test_mcp_bridge_alloc_budget.cpp — #2519: the MCP bridge's three contained
 * teardown steps (unsubscribe / release_charge / erase) allocate NOTHING.
 *
 * WHY THIS IS A SEPARATE EXECUTABLE. It replaces the global operator new/delete
 * to count allocations. That is process-wide and cannot be scoped to one test,
 * so it does not belong in the multi-thousand-case server binary, and it must
 * be ABSENT (not merely disabled) from sanitizer builds, which own the
 * allocator themselves. Copies test_spark_alloc_budget.cpp's interposer
 * verbatim (same rationale, same gotchas) rather than sharing a header across
 * two separate executables that must never link together.
 *
 * WHAT IT BUYS OVER THE FAULT SEAMS. test_mcp_stream_bridge.cpp's
 * inject_teardown_step_fault_for_test proves each step's failure is CONTAINED
 * (no crash, evidence emitted, #2513 retry armed). It cannot prove the
 * PREMISE those bail paths exist to protect against - that the steps
 * themselves allocate nothing in the first place, so only a genuinely broken
 * platform mutex can reach them at all - because a green run under no
 * pressure proves nothing about a claim that only fails under memory
 * pressure. This turns that claim into an assertion that runs in CI.
 *
 * PORTABILITY, STATED PLAINLY. Executable-side replacement of operator new
 * interposing for libyuzu_server_core's statically-linked TUs is measured on
 * this ELF/libstdc++ build, not a portable contract - see
 * test_spark_alloc_budget.cpp's header for the full caveat. LINUX MUTATION
 * EVIDENCE, not the cross-platform pin - that stays with the fault seams.
 */

#include "../../../server/core/src/execution_event_bus.hpp"
#include "../../../server/core/src/mcp_session.hpp"
#include "../../../server/core/src/mcp_stream_bridge.hpp"
#include <yuzu/server/auth.hpp>  // CredentialCheck is only forward-declared by mcp_stream.hpp

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <memory>
#include <mutex>
#include <new>
#include <string>

// ── the counter (verbatim from test_spark_alloc_budget.cpp) ────────────────
namespace {
thread_local std::uint64_t g_allocs = 0;
thread_local bool g_counting = false;

class AllocCount {
public:
    AllocCount() {
        g_allocs = 0;
        g_counting = true;
    }
    ~AllocCount() { g_counting = false; }
    AllocCount(const AllocCount&) = delete;
    AllocCount& operator=(const AllocCount&) = delete;
    [[nodiscard]] std::uint64_t count() const { return g_allocs; }
    void stop() { g_counting = false; }
};

void* tally_and_alloc(std::size_t n, std::size_t align) {
    if (g_counting)
        ++g_allocs;
    const std::size_t want = (n == 0 ? 1 : n);
    if (align > alignof(std::max_align_t)) {
        if (want > SIZE_MAX - (align - 1))
            return nullptr;
        return std::aligned_alloc(align, (want + align - 1) / align * align);
    }
    return std::malloc(want);
}

void* alloc_or_throw(std::size_t n, std::size_t align) {
    for (;;) {
        if (void* p = tally_and_alloc(n, align))
            return p;
        std::new_handler h = std::get_new_handler();
        if (h == nullptr)
            throw std::bad_alloc{};
        h();
    }
}

void* alloc_nothrow(std::size_t n, std::size_t align) noexcept {
    try {
        return alloc_or_throw(n, align);
    } catch (...) {
        return nullptr;
    }
}
} // namespace

void* operator new(std::size_t n) { return alloc_or_throw(n, alignof(std::max_align_t)); }
void* operator new[](std::size_t n) { return alloc_or_throw(n, alignof(std::max_align_t)); }
void* operator new(std::size_t n, std::align_val_t a) {
    return alloc_or_throw(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a) {
    return alloc_or_throw(n, static_cast<std::size_t>(a));
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
    return alloc_nothrow(n, alignof(std::max_align_t));
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
    return alloc_nothrow(n, alignof(std::max_align_t));
}
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
    return alloc_nothrow(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
    return alloc_nothrow(n, static_cast<std::size_t>(a));
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

// ── minimal fixture ──────────────────────────────────────────────────────────

namespace {

namespace mcp = yuzu::server::mcp;
using yuzu::server::ExecutionEventBus;
using Bridge = mcp::McpStreamBridge;
using nlohmann::json;

/// spdlog formats into heap buffers; nothing in the fault-free measured window
/// should log at all, but silence it anyway so an unexpected log statement
/// cannot be misread as engine cost (test_spark_alloc_budget.cpp precedent).
class QuietLog {
public:
    QuietLog() : prev_(spdlog::get_level()) { spdlog::set_level(spdlog::level::off); }
    ~QuietLog() { spdlog::set_level(prev_); }
    QuietLog(const QuietLog&) = delete;
    QuietLog& operator=(const QuietLog&) = delete;

private:
    spdlog::level::level_enum prev_;
};

/// Minimal bridge harness: real bus/session-registry/bridge, no server, no
/// httplib. A discardable no-op audit sink - the canary asserts allocations,
/// not audit content, which test_mcp_stream_bridge.cpp already covers.
struct Fx {
    yuzu::MetricsRegistry reg;
    ExecutionEventBus bus;
    std::chrono::steady_clock::time_point base = std::chrono::steady_clock::now();
    std::shared_ptr<std::atomic<std::int64_t>> clock_s =
        std::make_shared<std::atomic<std::int64_t>>(0);
    mcp::McpSessionRegistry sessions;
    std::optional<Bridge> bridge;

    Fx()
        : sessions(mcp::McpSessionRegistry::Config{},
                   [b = base, c = clock_s] { return b + std::chrono::seconds(c->load()); },
                   &reg) {
        bridge.emplace(&bus, &sessions, &reg,
                       [](const std::string&, const std::string&, const std::string&,
                          Bridge::AuditResult, const std::string&) {},
                       Bridge::Config{});
    }

    std::string make_session(const std::string& principal) {
        auto minted = sessions.mint(principal);
        REQUIRE(minted.ok);
        REQUIRE(sessions.stream_for(minted.session_id, principal) != nullptr);
        return minted.session_id;
    }
};

/// Reserve + subscribe + arm(streaming) + on_post_closed on a FRESH session:
/// the shape test_mcp_stream_bridge.cpp's `park_one` uses to reach a phase the
/// session-death pass claims. One record per session, since kMaxStreamedPostsPerSession
/// caps streamed records at 4 per session and this canary wants N > 4 to catch
/// amortised/periodic allocation a single teardown could not.
void park_one_streamed(Fx& fx, const std::string& session_id, const std::string& principal,
                       const std::string& exec_id) {
    REQUIRE(
        fx.bridge->reserve(session_id, principal, json(1), json("t"), /*streamed=*/true).ok);
    REQUIRE(fx.bridge->subscribe(session_id, json(1), exec_id));
    REQUIRE(fx.bridge->arm(session_id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(session_id, json(1)));
}

} // namespace

TEST_CASE("the interposer actually reaches McpStreamBridge's allocations", "[mcp][bridge][alloc]") {
    // Guards against the whole file silently becoming a no-op: if a future
    // toolchain change stops the executable-side replacement from preempting
    // libyuzu_server_core's statically-linked TUs, the budget case below would
    // pass at zero and prove nothing. A fresh reserve() must allocate (at
    // minimum, the records_ map node).
    Fx fx;
    const auto sid = fx.make_session("alice");
    QuietLog quiet;

    std::uint64_t n = 0;
    {
        AllocCount counting;
        REQUIRE(fx.bridge->reserve(sid, "alice", json(1), json("t"), true).ok);
        n = counting.count();
    }
    CHECK(n > 0);
}

TEST_CASE("teardown's three contained steps allocate nothing, across N teardowns in one sweep "
          "(#2519)",
          "[mcp][bridge][alloc]") {
    static constexpr int kRecords = 8; // > kMaxStreamedPostsPerSession(4), one session each
    Fx fx;
    QuietLog quiet;

    for (int i = 0; i < kRecords; ++i) {
        const std::string principal = "alice-" + std::to_string(i);
        const auto sid = fx.make_session(principal);
        park_one_streamed(fx, sid, principal, "exec-" + std::to_string(i));
    }
    // Every session idle-expires (default idle_ttl 1800s); the session-death
    // pass then claims all kRecords records in ONE sweep() call, each via its
    // own teardown_claimed with decision=kNone (nothing to publish, so Step 1
    // never enters the probed window either - only Steps 2-4 are bracketed).
    fx.clock_s->store(1801);

    std::array<std::uint64_t, Bridge::kTeardownStageCount> totals{};
    std::array<std::uint64_t, Bridge::kTeardownStageCount> entry_mark{};
    fx.bridge->set_teardown_step_probe_for_test([&](Bridge::TeardownStage stage, bool entering) {
        const auto idx = static_cast<std::size_t>(stage);
        if (entering) {
            entry_mark[idx] = g_allocs;
        } else {
            // g_allocs only ever grows, and this window's entry mark was taken
            // no earlier than the last exit mark for the SAME stage on the SAME
            // (single) thread, so the subtraction cannot underflow.
            totals[idx] += g_allocs - entry_mark[idx];
        }
    });

    {
        AllocCount counting;
        fx.bridge->sweep();
        counting.stop(); // stop counting before the probe is cleared below
    }
    fx.bridge->set_teardown_step_probe_for_test(nullptr);

    CHECK(fx.bridge->record_count() == 0); // sanity: all kRecords records actually reaped
    for (std::size_t i = 0; i < Bridge::kTeardownStageCount; ++i) {
        INFO("stage=" << Bridge::kTeardownStageNames[i]);
        CHECK(totals[i] == 0);
    }
}
