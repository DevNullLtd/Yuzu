/**
 * test_dex_score_policy_provider.cpp -- the bounded-refresh score policy provider
 * over an injected store read and an injected clock: refresh interval,
 * cross-instance convergence, last-known-good through an outage, the staleness
 * cap, the invalid-document direction and the single-flight refresh (a caller
 * arriving mid-refresh never waits on the store read). No store, no sleeps, no
 * I/O.
 */
#include "dex_score_policy_provider.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
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
// the gate; every other read returns the document at once. release() is
// idempotent so the tests' ScopeExit can call it after the explicit release.
struct ParkedRead {
    Fixture& f;
    std::atomic<bool> armed{false};
    std::atomic<int> reads{0};
    std::atomic<bool> released{false};
    std::promise<void> entered_p;
    std::promise<void> release_p;
    std::future<void> entered = entered_p.get_future();
    std::shared_future<void> gate = release_p.get_future().share();

    explicit ParkedRead(Fixture& fx) : f(fx) {}
    void release() {
        if (!released.exchange(true))
            release_p.set_value();
    }
    DexScorePolicyProvider::ReadFn fn() {
        return [this]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            if (armed.exchange(false)) {
                entered_p.set_value();
                gate.wait();
            }
            if (f.down)
                return std::unexpected(std::string("store down"));
            return f.doc;
        };
    }
};

// A store commit that parks inside the commit, once armed, until release() opens the gate.
// `result` is what the commit answers; every other call answers at once.
struct ParkedCommit {
    std::atomic<bool> armed{false};
    std::atomic<int> commits{0};
    std::atomic<bool> released{false};
    std::expected<bool, std::string> result{true};
    std::promise<void> entered_p;
    std::promise<void> release_p;
    std::future<void> entered = entered_p.get_future();
    std::shared_future<void> gate = release_p.get_future().share();

    void release() {
        if (!released.exchange(true))
            release_p.set_value();
    }
    DexScorePolicyProvider::CommitFn fn() {
        return [this]() -> std::expected<bool, std::string> {
            ++commits;
            if (armed.exchange(false)) {
                entered_p.set_value();
                gate.wait();
            }
            return result;
        };
    }
};

// How long a test waits on a parked read before it calls the behaviour a regression.
constexpr auto kParkedWait = std::chrono::seconds(10);

// p.current() on its own thread with a bounded wait: a mid-refresh caller that waits on the
// parked read fails here instead of hanging the shard to its timeout. On a timeout the parked
// read is released first, so the call can finish and the future's destructor returns.
std::expected<DexPolicyInForce, std::string> current_bounded(DexScorePolicyProvider& p,
                                                             ParkedRead& pr) {
    auto fut = std::async(std::launch::async, [&p] { return p.current(); });
    if (fut.wait_for(kParkedWait) != std::future_status::ready) {
        pr.release();
        FAIL("a mid-refresh current() waited on the parked store read");
    }
    return fut.get();
}

// p.write() on its own thread with a bounded wait, like current_bounded: `parked` (a ParkedRead
// or ParkedCommit) is released on a timeout so the call can finish.
template <class Parked>
std::expected<DexPolicyInForce, DexPolicyWriteFailure>
write_bounded(DexScorePolicyProvider& p, const std::optional<std::string>& text,
              const DexScorePolicyProvider::CommitFn& commit, Parked& parked) {
    auto fut = std::async(std::launch::async, [&] { return p.write(text, commit); });
    if (fut.wait_for(kParkedWait) != std::future_status::ready) {
        parked.release();
        FAIL("write() did not complete while the other call was parked");
    }
    return fut.get();
}

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

TEST_CASE("policy provider: an outage serves the last good policy then refuses past the cap",
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

TEST_CASE("policy provider: a read failure before any success is an error and never a guess",
          "[dex][policy_provider]") {
    Fixture f;
    f.down = true;
    f.now = 100; // inside the staleness cap from time zero: only "no good read yet" refuses
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

TEST_CASE("policy provider: a stored invalid document is the defaults with a fault and never an error",
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
    f.now = 100; // inside the staleness cap from time zero: only "no good read yet" refuses
    ParkedRead pr(f);
    pr.armed = true;
    DexScorePolicyProvider p(pr.fn(), f.clock());
    std::optional<std::expected<DexPolicyInForce, std::string>> first;
    std::thread a([&] { first = p.current(); }); // parks inside the first store read
    yuzu::test::ScopeExit finish{[&] { // a thrown assertion must not leave `a` joinable
        pr.release();
        if (a.joinable())
            a.join();
    }};
    REQUIRE(pr.entered.wait_for(kParkedWait) == std::future_status::ready);

    // The reader is still parked: this call must return without waiting on it.
    const auto mid = current_bounded(p, pr);
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
    yuzu::test::ScopeExit finish{[&] {
        pr.release();
        if (a.joinable())
            a.join();
    }};
    REQUIRE(pr.entered.wait_for(kParkedWait) == std::future_status::ready);

    const auto lkg = current_bounded(p, pr);
    CHECK(lkg.has_value());
    if (lkg) {
        CHECK(lkg->source == "custom");
        CHECK(lkg->policy.tiers.edges.excellent == 95.0);
    }
    f.now += 54000; // exactly 60 s since the last good read: still inside the cap
    CHECK(current_bounded(p, pr).has_value());
    f.now += 1; // past the cap: the last good policy is no longer served
    const auto gone = current_bounded(p, pr);
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

TEST_CASE("policy provider: a non-std throw from the read takes the same failed-read path",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    int reads = 0;
    bool boom = true;
    DexScorePolicyProvider p(
        [&]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            if (boom)
                throw 7; // not a std::exception: the catch(...) arm
            return f.doc;
        },
        f.clock());
    const auto none = p.current(); // before any good read: an error at once
    REQUIRE_FALSE(none);
    CHECK(none.error().find("read threw") != std::string::npos);

    boom = false;
    REQUIRE(p.current()); // a good read
    boom = true;
    f.now += 6000;
    const auto lkg = p.current(); // inside the cap: cached
    REQUIRE(lkg);
    CHECK(lkg->source == "custom");

    f.now += 55000; // past the cap: refused
    const auto gone = p.current();
    REQUIRE_FALSE(gone);
    CHECK(gone.error().find("read threw") != std::string::npos);

    boom = false; // the flag was cleared each time: the store is asked again
    REQUIRE(p.current());
    CHECK(reads == 5);
}

// The flag is released by a scope guard on every exit, so an exception that is NOT a failed
// read (here the clock sampled after the unlocked read) leaves no wedged refresh behind. The
// first sample is the entry of current(), the second is the one under the re-taken lock.
TEST_CASE("policy provider: an exception after the unlocked read still releases the refresh flag",
          "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    int samples = 0;
    bool boom = true;
    DexScorePolicyProvider p(f.reader(&reads), [&]() -> std::int64_t {
        if (boom && ++samples == 2)
            throw std::runtime_error("clock exploded");
        return f.now;
    });
    CHECK_THROWS_AS(p.current(), std::runtime_error);
    CHECK(reads == 1);

    boom = false; // the flag was released: this call refreshes at once
    const auto v = p.current();
    REQUIRE(v.has_value()); // not "refresh in progress", and no wait for the staleness cap
    CHECK(v->source == "default");
    CHECK(reads == 2);
}

TEST_CASE("policy provider: a slow good read is stamped when it completes and not when it starts",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    const std::int64_t t0 = f.now;
    std::int64_t read_takes_ms = 3000;
    bool fail = false;
    int reads = 0;
    DexScorePolicyProvider p(
        [&]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            f.now += read_takes_ms; // the read itself advances the clock
            if (fail)
                return std::unexpected(std::string("store down"));
            return f.doc;
        },
        f.clock());
    REQUIRE(p.current()); // starts at t0, completes at t0+3 s
    const std::int64_t done = t0 + 3000;
    CHECK(f.now == done);
    read_takes_ms = 0;

    // The refresh interval runs from the completion: no read at +4999 ms, one at +5000 ms
    // (stamped at the start, +4999 would already be 7999 ms old and re-read).
    f.now = done + 4999;
    REQUIRE(p.current());
    CHECK(reads == 1);
    fail = true;
    f.now = done + 5000;
    REQUIRE(p.current()); // the refresh fails at once: the completion-stamped policy serves
    CHECK(reads == 2);

    // The staleness cap also runs from the completion: served at +60 s, refused at +60.001 s.
    f.now = done + 60000;
    CHECK(p.current().has_value());
    f.now = done + 60001;
    const auto gone = p.current();
    REQUIRE_FALSE(gone);
    CHECK(gone.error().find("store down") != std::string::npos);
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
    f.now = t0 + 59000; // each section is one forward-only schedule from here

    SECTION("a refresh starting at t0+59 s whose failure lands 1 s later at the cap: served") {
        read_takes_ms = 1000;
        CHECK(p.current().has_value());
    }
    SECTION("the same refresh failing 10 s later at t0+69 s: past the cap and refused") {
        read_takes_ms = 10000;
        const auto gone = p.current();
        REQUIRE_FALSE(gone);
        CHECK(gone.error().find("store slow") != std::string::npos);
    }
}

// ── write(): commit-then-install under the writer lock (#6085) ───────────────

namespace {
const DexScorePolicyProvider::CommitFn kCommitOk = [] { return std::expected<bool, std::string>(true); };
} // namespace

TEST_CASE("policy provider: write installs at once and restarts the window from the write",
          "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    REQUIRE(p.current());
    CHECK(reads == 1);

    f.now += 3000;
    const std::string text = doc_with_excellent(95.0);
    const auto w = p.write(text, kCommitOk);
    REQUIRE(w);
    CHECK(w->source == "custom");
    CHECK(w->revision == dex_score_policy_revision(text));
    const auto c = p.current();
    REQUIRE(c);
    CHECK(c->source == "custom");
    CHECK(reads == 1);

    f.now += 4999; // T+7999: the read's own stamp (T) would already have expired
    REQUIRE(p.current());
    CHECK(reads == 1);
    f.now += 1; // exactly kDexPolicyRefreshMs after the write
    REQUIRE(p.current());
    CHECK(reads == 2);
}

TEST_CASE("policy provider: write of nothing or of an invalid document installs the defaults",
          "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    int commits = 0;
    const DexScorePolicyProvider::CommitFn count = [&commits] {
        ++commits;
        return std::expected<bool, std::string>(true);
    };
    REQUIRE(p.write(doc_with_excellent(95.0), kCommitOk));

    const auto del = p.write(std::nullopt, count);
    REQUIRE(del);
    CHECK(del->source == "default");
    CHECK(del->fault.empty());
    CHECK(commits == 1);

    const std::string bad = R"({"overrides":[{"image":"a.exe"},{"image":"a.exe"}]})";
    const auto inv = p.write(bad, count);
    REQUIRE(inv);
    CHECK(inv->source == "default");
    CHECK(inv->fault == "override_key_duplicate at overrides[1].image");
    CHECK(commits == 2);
    const auto c = p.current();
    REQUIRE(c);
    CHECK(c->fault == inv->fault);
    CHECK(reads == 0);
}

TEST_CASE("policy provider: two overlapping writers cannot reverse", "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock(), kParkedWait);
    REQUIRE(p.current());
    CHECK(reads == 1);
    const std::string a = doc_with_excellent(95.0);
    const std::string b = doc_with_excellent(92.0);
    ParkedCommit pa, pb;
    pa.armed = true;
    pb.armed = true;
    std::future<std::expected<DexPolicyInForce, DexPolicyWriteFailure>> fb; // declared before the guard
    auto fa = std::async(std::launch::async, [&] { return p.write(a, pa.fn()); });
    yuzu::test::ScopeExit finish{[&] {
        pa.release();
        pb.release();
    }};
    REQUIRE(pa.entered.wait_for(kParkedWait) == std::future_status::ready);
    fb = std::async(std::launch::async, [&] { return p.write(b, pb.fn()); });
    CHECK(pb.commits == 0); // B holds no lock and has not committed while A is in its commit

    pa.release();
    // B enters its commit only once A has committed AND installed and released the writer lock.
    REQUIRE(pb.entered.wait_for(kParkedWait) == std::future_status::ready);
    REQUIRE(fa.wait_for(kParkedWait) == std::future_status::ready);
    const auto wa = fa.get();
    REQUIRE(wa);
    CHECK(wa->revision == dex_score_policy_revision(a));
    const auto mid = p.current();
    REQUIRE(mid);
    CHECK(mid->revision == dex_score_policy_revision(a)); // A is installed, B not yet
    CHECK(reads == 1);

    pb.release();
    REQUIRE(fb.wait_for(kParkedWait) == std::future_status::ready);
    const auto wb = fb.get();
    REQUIRE(wb);
    CHECK(pb.commits == 1);
    const auto last = p.current();
    REQUIRE(last);
    CHECK(last->revision == dex_score_policy_revision(b)); // B installed last
    CHECK(reads == 1);

    f.doc = b;
    f.now += kDexPolicyRefreshMs;
    const auto again = p.current();
    REQUIRE(again);
    CHECK(reads == 2);
    CHECK(again->revision == dex_score_policy_revision(b));
}

TEST_CASE("policy provider: a committed-stale write installs nothing", "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(95.0);
    ParkedRead pr(f);
    DexScorePolicyProvider p(pr.fn(), f.clock());
    pr.armed = true;
    std::thread a([&] { (void)p.current(); }); // parks inside the first read
    yuzu::test::ScopeExit finish{[&] {
        pr.release();
        if (a.joinable())
            a.join();
    }};
    REQUIRE(pr.entered.wait_for(kParkedWait) == std::future_status::ready);

    ParkedCommit pc;
    pc.result = false;
    const auto w = write_bounded(p, doc_with_excellent(92.0), pc.fn(), pr);
    REQUIRE_FALSE(w);
    CHECK(w.error().kind == DexPolicyWriteError::Stale);
    CHECK(pc.commits == 1);

    // No generation bump: the parked successful read is still applied when it lands.
    pr.release();
    a.join();
    const auto c = p.current();
    REQUIRE(c);
    CHECK(c->revision == dex_score_policy_revision(*f.doc));
    CHECK(pr.reads == 1);
}

TEST_CASE("policy provider: a commit error or throw installs nothing and frees the writer lock",
          "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    const std::string text = doc_with_excellent(95.0);

    ParkedCommit pc;
    pc.result = std::unexpected(std::string("store: database write failed"));
    const auto e = p.write(text, pc.fn());
    REQUIRE_FALSE(e);
    CHECK(e.error().kind == DexPolicyWriteError::CommitFailed);
    CHECK(e.error().detail == "store: database write failed");

    const auto t = p.write(text, []() -> std::expected<bool, std::string> {
        throw std::runtime_error("boom");
    });
    REQUIRE_FALSE(t);
    CHECK(t.error().kind == DexPolicyWriteError::CommitFailed);
    CHECK(t.error().detail.starts_with("commit threw: boom"));

    const auto n = p.write(text, []() -> std::expected<bool, std::string> { throw 7; });
    REQUIRE_FALSE(n);
    CHECK(n.error().detail == "commit threw");

    const auto c = p.current(); // nothing was installed: the store (default) answers
    REQUIRE(c);
    CHECK(c->source == "default");
    CHECK(reads == 1);
    REQUIRE(p.write(text, kCommitOk)); // the writer lock was released each time
}

TEST_CASE("policy provider: a writer that cannot get the lock is told to retry and never commits",
          "[dex][policy_provider]") {
    Fixture f;
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock(), std::chrono::milliseconds(0));
    const std::string a = doc_with_excellent(95.0);
    const std::string b = doc_with_excellent(92.0);
    ParkedCommit pa, pb;
    pa.armed = true;
    auto fa = std::async(std::launch::async, [&] { return p.write(a, pa.fn()); });
    yuzu::test::ScopeExit finish{[&] { pa.release(); }};
    REQUIRE(pa.entered.wait_for(kParkedWait) == std::future_status::ready);

    const auto busy = p.write(b, pb.fn());
    REQUIRE_FALSE(busy);
    CHECK(busy.error().kind == DexPolicyWriteError::WriterBusy);
    CHECK(pb.commits == 0);

    pa.release();
    REQUIRE(fa.wait_for(kParkedWait) == std::future_status::ready);
    REQUIRE(fa.get());
    REQUIRE(p.write(b, pb.fn()));
    CHECK(pb.commits == 1);
}

TEST_CASE("policy provider: readers are not blocked while a writer is parked in its commit",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(90.0);
    int reads = 0;
    DexScorePolicyProvider p(f.reader(&reads), f.clock());
    const std::string a = doc_with_excellent(95.0);
    ParkedCommit pa;
    pa.armed = true;
    auto fa = std::async(std::launch::async, [&] { return p.write(a, pa.fn()); });
    yuzu::test::ScopeExit finish{[&] { pa.release(); }};
    REQUIRE(pa.entered.wait_for(kParkedWait) == std::future_status::ready);

    auto fr = std::async(std::launch::async, [&] { return p.current(); });
    REQUIRE(fr.wait_for(kParkedWait) == std::future_status::ready);
    const auto r = fr.get();
    REQUIRE(r);
    CHECK(r->revision == dex_score_policy_revision(*f.doc)); // the store's, never the parked text
    CHECK(reads == 1);

    pa.release();
    REQUIRE(fa.wait_for(kParkedWait) == std::future_status::ready);
    REQUIRE(fa.get());
    const auto after = p.current();
    REQUIRE(after);
    CHECK(after->revision == dex_score_policy_revision(a));
    CHECK(reads == 1); // the install restarted the window
}

TEST_CASE("policy provider: a write during a refresh in flight wins over the older successful read",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(90.0);
    ParkedRead pr(f);
    DexScorePolicyProvider p(pr.fn(), f.clock());
    pr.armed = true;
    std::optional<std::expected<DexPolicyInForce, std::string>> parked;
    std::thread a([&] { parked = p.current(); }); // parks on the OLD document
    yuzu::test::ScopeExit finish{[&] {
        pr.release();
        if (a.joinable())
            a.join();
    }};
    REQUIRE(pr.entered.wait_for(kParkedWait) == std::future_status::ready);

    const std::string text = doc_with_excellent(95.0);
    REQUIRE(write_bounded(p, text, kCommitOk, pr));
    pr.release();
    a.join();
    REQUIRE(parked);
    REQUIRE(*parked);
    CHECK((*parked)->revision == dex_score_policy_revision(text));
    const auto c = p.current();
    REQUIRE(c);
    CHECK(c->revision == dex_score_policy_revision(text));
    CHECK(pr.reads == 1);
}

TEST_CASE("policy provider: a failed read in flight across a write keeps the stale cap",
          "[dex][policy_provider]") {
    Fixture f;
    f.doc = doc_with_excellent(90.0);
    ParkedRead pr(f);
    DexScorePolicyProvider p(pr.fn(), f.clock());
    pr.armed = true;
    std::optional<std::expected<DexPolicyInForce, std::string>> parked;
    std::thread a([&] { parked = p.current(); });
    yuzu::test::ScopeExit finish{[&] {
        pr.release();
        if (a.joinable())
            a.join();
    }};
    REQUIRE(pr.entered.wait_for(kParkedWait) == std::future_status::ready);

    REQUIRE(write_bounded(p, doc_with_excellent(95.0), kCommitOk, pr));
    f.now += kDexPolicyStaleCapMs + 1;
    f.down = true;
    pr.release();
    a.join();
    REQUIRE(parked);
    CHECK_FALSE(*parked); // past the cap and the store down: never the over-cap installed policy
    if (!*parked)
        CHECK((*parked).error().find("score policy unreadable") != std::string::npos);

    f.down = false;
    const auto c = p.current();
    REQUIRE(c);
    CHECK(pr.reads == 2);
    CHECK(c->revision == dex_score_policy_revision(*f.doc));
}
