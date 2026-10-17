/**
 * test_dex_score_policy_provider.cpp -- the bounded-refresh score policy provider
 * over an injected store read and an injected clock: refresh interval,
 * cross-instance convergence, last-known-good through an outage, the staleness
 * cap, the invalid-document direction and the single-flight refresh (a caller
 * arriving mid-refresh never waits on the store read). No store, no sleeps, no
 * I/O.
 */
#include "dex_score_policy_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

using namespace yuzu::server;

namespace {

// The shared "store": one document, one outage switch, one read counter per
// reader, and one fake clock. Two providers over the same Fixture model two
// server instances over one stored row.
struct Fixture {
    std::optional<std::string> doc;
    bool down{false};
    std::int64_t now{1'000'000};

    DexScorePolicyProvider::ClockFn clock() {
        return [this] { return now; };
    }
    // Each reader counts its own reads.
    DexScorePolicyProvider::ReadFn reader(int* reads) {
        return [this, reads]() -> std::expected<std::optional<std::string>, std::string> {
            ++*reads;
            if (down)
                return std::unexpected(std::string("store down"));
            return doc;
        };
    }
};

// A store read that parks inside the read, once armed, until release() opens
// the gate; every other read returns the document at once.
struct ParkedRead {
    Fixture& f;
    std::atomic<bool> armed{false};
    std::atomic<int> reads{0};
    std::promise<void> entered_p;
    std::promise<void> release_p;
    std::future<void> entered = entered_p.get_future();
    std::shared_future<void> gate = release_p.get_future().share();

    explicit ParkedRead(Fixture& fx) : f(fx) {}
    void release() { release_p.set_value(); }
    DexScorePolicyProvider::ReadFn fn() {
        return [this]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            if (armed.exchange(false)) {
                entered_p.set_value();
                gate.wait();
            }
            return f.doc;
        };
    }
};

std::string doc_with_excellent(double e) {
    DexScorePolicy p;
    p.tiers.edges.excellent = e;
    return dex_score_policy_canonical(p);
}

} // namespace

TEST_CASE("policy provider: a good read is cached for the refresh interval", "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    REQUIRE(p.current());
    CHECK(reads == 1);
    f.now += 4999;
    REQUIRE(p.current());
    CHECK(reads == 1);
    f.now += 1; // +5000 ms from the read
    REQUIRE(p.current());
    CHECK(reads == 2);
}

TEST_CASE("policy provider: two instances over one document converge within the interval",
          "[dex][policy_provider]") {
    Fixture f;
    int reads_a = 0, reads_b = 0;
    DexScorePolicyProvider a(f.reader(&reads_a), f.clock());
    DexScorePolicyProvider b(f.reader(&reads_b), f.clock());
    CHECK(a.current()->source == "default");
    CHECK(b.current()->source == "default");

    f.doc = doc_with_excellent(95.0); // a write by any instance
    f.now += 2000;                    // neither has crossed its boundary yet
    CHECK(a.current()->source == "default");
    CHECK(b.current()->source == "default");

    f.now += 3000; // both cross 5 s
    const auto va = a.current();
    const auto vb = b.current();
    REQUIRE(va);
    REQUIRE(vb);
    CHECK(va->source == "custom");
    CHECK(vb->source == "custom");
    CHECK(va->policy.tiers.edges.excellent == 95.0);
    CHECK(va->revision == vb->revision);
}

TEST_CASE("policy provider: an outage serves the last good policy, then refuses past the cap",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    REQUIRE(p.current());

    f.down = true;
    f.now += 6000; // past the refresh interval: a read is attempted and fails
    const auto lkg = p.current();
    REQUIRE(lkg);
    CHECK(lkg->source == "custom");
    CHECK(lkg->policy.tiers.edges.excellent == 95.0);

    f.now += 54000; // exactly 60 s since the last good read: still inside the cap
    CHECK(p.current());
    f.now += 1; // 60.001 s
    const auto gone = p.current();
    REQUIRE_FALSE(gone);
    CHECK(gone.error().find("score policy unreadable") != std::string::npos);
    CHECK(gone.error().find("store down") != std::string::npos);
}

TEST_CASE("policy provider: a success during an outage resets the staleness window",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    REQUIRE(p.current());
    f.down = true;
    f.now += 50000;
    REQUIRE(p.current()); // last good policy, 50 s old
    f.down = false;
    f.now += 5000; // a good read at +55 s
    REQUIRE(p.current());
    f.down = true;
    f.now += 59000; // 59 s after the new good read, 114 s after the first
    CHECK(p.current());
    f.now += 2000; // 61 s after the new good read
    CHECK_FALSE(p.current());
}

TEST_CASE("policy provider: a read failure before any success is an error, never a guess",
          "[dex][policy_provider]") {
    Fixture f;
    f.down = true;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    const auto r = p.current();
    REQUIRE_FALSE(r);
    CHECK(reads == 1);
    // And again at once: nothing was cached, so the store is asked again.
    CHECK_FALSE(p.current());
    CHECK(reads == 2);
}

TEST_CASE("policy provider: nothing stored is a good read that survives a later outage",
          "[dex][policy_provider]") {
    Fixture f; // no document
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    const auto first = p.current();
    REQUIRE(first);
    CHECK(first->source == "default");
    CHECK(first->fault.empty());
    f.down = true;
    f.now += 30000;
    const auto lkg = p.current();
    REQUIRE(lkg);
    CHECK(lkg->source == "default");
    CHECK(lkg->revision == "default");
}

TEST_CASE("policy provider: a stored invalid document is the defaults with a fault, never an error",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = R"({"overrides":[{"image":"a.exe"},{"image":"a.exe"}]})";
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    const auto v = p.current();
    REQUIRE(v);
    CHECK(v->source == "default");
    CHECK(v->fault == "override_key_duplicate at overrides[1].image");
    CHECK(v->policy.overrides.empty());
    // The refused document is a GOOD read: it is cached, and survives an outage.
    f.down = true;
    f.now += 20000;
    const auto lkg = p.current();
    REQUIRE(lkg);
    CHECK(lkg->fault == v->fault);
}

TEST_CASE("policy provider: a caller arriving mid-refresh with no policy yet fails at once",
          "[dex][policy_provider]") {
    Fixture f;
    ParkedRead pr(f);
    pr.armed = true;
    DexScorePolicyProvider p(pr.fn(), f.clock());
    std::optional<std::expected<DexPolicyInForce, std::string>> first;
    std::thread a([&] { first = p.current(); }); // parks inside the first store read
    pr.entered.wait();

    // The reader is still parked: this call must return without waiting on it.
    const auto mid = p.current();
    CHECK_FALSE(mid);
    if (!mid)
        CHECK(mid.error().find("refresh in progress") != std::string::npos);

    pr.release();
    a.join();
    REQUIRE(first);
    REQUIRE(*first);
    CHECK((*first)->source == "default");
    CHECK(pr.reads == 1); // the mid-refresh caller never touched the store
}

TEST_CASE("policy provider: a caller arriving mid-refresh is served the last good policy within the cap",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    ParkedRead pr(f);
    DexScorePolicyProvider p(pr.fn(), f.clock());
    REQUIRE(p.current());

    f.now += 6000; // past the refresh interval, inside the cap
    pr.armed = true;
    std::thread a([&] { (void)p.current(); }); // parks inside the refresh read
    pr.entered.wait();

    const auto lkg = p.current();
    CHECK(lkg.has_value());
    if (lkg) {
        CHECK(lkg->source == "custom");
        CHECK(lkg->policy.tiers.edges.excellent == 95.0);
    }
    f.now += 54000; // exactly 60 s since the last good read: still inside the cap
    CHECK(p.current().has_value());
    f.now += 1; // past the cap: the last good policy is no longer served
    const auto gone = p.current();
    CHECK_FALSE(gone);
    if (!gone)
        CHECK(gone.error().find("refresh in progress") != std::string::npos);

    pr.release();
    a.join();
    CHECK(pr.reads == 2); // the initial read and the one parked refresh
    // The refresh finished, so the next stale call starts a fresh one.
    f.now += 5000;
    REQUIRE(p.current());
    CHECK(pr.reads == 3);
}

TEST_CASE("policy provider: a throwing read is a failed read and does not wedge the refresh",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    int reads = 0;
    bool boom = false;
    DexScorePolicyProvider p(
        [&]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            if (boom)
                throw std::runtime_error("pool exploded");
            return f.doc;
        },
        f.clock());
    REQUIRE(p.current());

    boom = true;
    f.now += 6000;
    const auto lkg = p.current(); // inside the cap: the throw is a failed read
    REQUIRE(lkg);
    CHECK(lkg->source == "custom");

    f.now += 55000; // past the cap
    const auto gone = p.current();
    REQUIRE_FALSE(gone);
    CHECK(gone.error().find("pool exploded") != std::string::npos);

    boom = false; // the flag was cleared both times: the store is asked again
    REQUIRE(p.current());
    CHECK(reads == 4);
}

TEST_CASE("policy provider: the time a failed read takes counts against the staleness cap",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    const std::int64_t t0 = f.now;
    std::int64_t read_takes_ms = 0;
    bool fail = false;
    DexScorePolicyProvider p(
        [&]() -> std::expected<std::optional<std::string>, std::string> {
            f.now += read_takes_ms; // the read itself advances the clock
            if (fail)
                return std::unexpected(std::string("store slow"));
            return f.doc;
        },
        f.clock());
    REQUIRE(p.current()); // good read at t0
    fail = true;

    // A refresh starts at t0+59 s and the failure lands 1 s later, at the cap: served.
    f.now = t0 + 59000;
    read_takes_ms = 1000;
    CHECK(p.current().has_value());

    // The same refresh failing 10 s later, at t0+69 s: past the cap, refused.
    f.now = t0 + 59000;
    read_takes_ms = 10000;
    const auto gone = p.current();
    REQUIRE_FALSE(gone);
    CHECK(gone.error().find("store slow") != std::string::npos);
}
