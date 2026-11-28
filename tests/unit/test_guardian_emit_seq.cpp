// Unit tests for GuardianEmitSeqSource and stamp_emit_pair (UP-14): the engine-owned
// emit ordinal and the both-or-neither wire stamp. The source must be 1-based and
// strictly increasing across threads; the stamp must never put half a pair on the wire.

#include "guardian_emit_seq.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <latch>
#include <thread>
#include <vector>

using namespace yuzu::agent;
namespace gpb = ::yuzu::guardian::v1;

namespace {

// Joins every started thread on scope exit, including when a later emplace_back throws.
// std::jthread is not used: Apple libc++ ships it only behind -fexperimental-library by
// default, and the tree already works around its absence (see PortableJThread in
// test_guardian_spark_runtime.cpp). Declare it BEFORE any thread starts
// and AFTER every local the workers reference, so the joins run before those locals are
// destroyed.
struct JoinGuard {
    std::vector<std::thread> threads;
    JoinGuard() = default;
    JoinGuard(const JoinGuard&) = delete;
    JoinGuard& operator=(const JoinGuard&) = delete;
    ~JoinGuard() {
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

} // namespace

TEST_CASE("emit-seq: draw is 1-based and strictly increasing", "[guardian][emit_seq]") {
    GuardianEmitSeqSource src(7);
    CHECK(src.boot_epoch == 7);
    CHECK(src.last.load() == 0);

    std::uint64_t prev = 0;
    for (int i = 0; i < 100; ++i) {
        const std::uint64_t v = src.draw();
        CHECK(v == prev + 1);
        prev = v;
    }
    CHECK(prev == 100);
    CHECK(src.last.load() == 100);
}

TEST_CASE("emit-seq: a source with boot_epoch 0 still draws", "[guardian][emit_seq]") {
    // The hold key (OutboxEntry.seq) is always drawn; only the wire pair is gated.
    GuardianEmitSeqSource src(0);
    CHECK(src.draw() == 1);
    CHECK(src.draw() == 2);
}

TEST_CASE("emit-seq: concurrent draws are unique and gap-free", "[guardian][emit_seq][tsan]") {
    constexpr int kThreads = 4;
    constexpr int kDraws = 200;
    GuardianEmitSeqSource src(1);

    std::vector<std::vector<std::uint64_t>> got(kThreads);
    std::latch start(kThreads);
    {
        JoinGuard workers;
        workers.threads.reserve(kThreads);
        int spawned = 0;
        try {
            for (int t = 0; t < kThreads; ++t) {
                workers.threads.emplace_back([&, t] {
                    got[t].reserve(kDraws);
                    start.arrive_and_wait();
                    for (int i = 0; i < kDraws; ++i)
                        got[t].push_back(src.draw());
                });
                ++spawned;
            }
        } catch (...) {
            start.count_down(kThreads - spawned); // release the started workers, then join
            throw;
        }
    } // the guard joins here

    std::vector<std::uint64_t> all;
    for (const auto& g : got) {
        // Per-thread order is the draw order: strictly increasing within a thread.
        CHECK(std::ranges::is_sorted(g, std::ranges::less_equal{}));
        all.insert(all.end(), g.begin(), g.end());
    }
    std::ranges::sort(all);
    REQUIRE(all.size() == static_cast<std::size_t>(kThreads) * kDraws);
    // Unique AND exactly 1..N: no value lost, none duplicated.
    for (std::size_t i = 0; i < all.size(); ++i)
        CHECK(all[i] == i + 1);
    CHECK(src.last.load() == all.size());
}

TEST_CASE("emit-seq: stamp_emit_pair is both-or-neither", "[guardian][emit_seq]") {
    SECTION("both nonzero sets both") {
        gpb::GuaranteedStateEvent ev;
        stamp_emit_pair(ev, 1'790'000'000ULL, 42);
        CHECK(ev.boot_epoch() == 1'790'000'000ULL);
        CHECK(ev.emit_seq() == 42);
    }
    SECTION("epoch 0 leaves both unset") {
        gpb::GuaranteedStateEvent ev;
        stamp_emit_pair(ev, 0, 42);
        CHECK(ev.boot_epoch() == 0);
        CHECK(ev.emit_seq() == 0);
    }
    SECTION("seq 0 leaves both unset") {
        gpb::GuaranteedStateEvent ev;
        stamp_emit_pair(ev, 1'790'000'000ULL, 0);
        CHECK(ev.boot_epoch() == 0);
        CHECK(ev.emit_seq() == 0);
    }
    SECTION("neither leaves both unset") {
        gpb::GuaranteedStateEvent ev;
        stamp_emit_pair(ev, 0, 0);
        CHECK(ev.boot_epoch() == 0);
        CHECK(ev.emit_seq() == 0);
    }
    SECTION("an unset pair adds no bytes to the wire") {
        gpb::GuaranteedStateEvent plain;
        plain.set_event_id("e");
        gpb::GuaranteedStateEvent stamped = plain;
        stamp_emit_pair(stamped, 0, 5);
        CHECK(stamped.SerializeAsString() == plain.SerializeAsString());
    }
}

TEST_CASE("emit-seq: the source's own epoch and draw feed the stamp", "[guardian][emit_seq]") {
    GuardianEmitSeqSource src(9);
    gpb::GuaranteedStateEvent a;
    gpb::GuaranteedStateEvent b;
    stamp_emit_pair(a, src.boot_epoch, src.draw());
    stamp_emit_pair(b, src.boot_epoch, src.draw());
    CHECK(a.boot_epoch() == 9);
    CHECK(b.boot_epoch() == 9);
    CHECK(a.emit_seq() == 1);
    CHECK(b.emit_seq() == 2);
}
