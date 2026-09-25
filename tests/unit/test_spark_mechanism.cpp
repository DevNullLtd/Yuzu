/**
 * test_spark_mechanism.cpp — the event-driven mechanism seam (spark_mechanism.hpp
 * + the SparkEngine File/Registry arm path). A FakeMechanism stands in for the
 * Windows IOCP / TP_WAIT impls so the WHOLE arm / dedup / fan-out / disarm-
 * teardown / lifecycle path is exercised on ANY platform — the point of the
 * seam (the real mechanisms compile Windows-only; the plumbing is tested here).
 *
 * The two Windows mechanism bodies (spark_file.cpp / spark_registry.cpp) are
 * validated by a DGRHP compile pass + their own resilience tests; this file
 * owns the cross-platform contract.
 */

#include "spark_engine.hpp"
#include "spark_heartbeat.hpp" // emit_spark_heartbeat_tags — the #2833 egress pin
#include "spark_mechanism.hpp"
#include "test_helpers.hpp" // process_random_salt - the PR-A watch-establishment harness'
                            // scratch registry keys (#2012/#3840 D-value measurement)

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio> // std::fputs - the T6 child process reports its own deadlock detection
#include <functional>
#include <iterator> // std::istreambuf_iterator - the T6 parent reads its child's captured output
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

template <typename Pred> bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

struct Collector {
    std::mutex mu;
    std::vector<SparkEvent> events;
    SparkEngine::QueuedHandler handler() {
        return [this](const SparkEvent& ev) {
            std::lock_guard lk(mu);
            events.push_back(ev);
        };
    }
    std::size_t count() {
        std::lock_guard lk(mu);
        return events.size();
    }
    SparkEvent at(std::size_t i) {
        std::lock_guard lk(mu);
        return events.at(i);
    }
};

/// A cross-platform stand-in for the Windows watch mechanisms. Records the
/// engine's watch/unwatch/start/stop calls and lets a test drive a fire.
/// A one-shot park for the #2815 teardown-barrier cases (and, since rung 9c
/// PR-6 item 1, FakeMechanism's own watch()/unwatch() park seam below): an
/// engine test hook — or a mechanism call — enters, announces it, and blocks
/// until the test releases it.
///
/// DELIBERATELY NOT OWNED BY THE ENGINE for the #2815 door-test use below.
/// Scenario B destroys the engine while a caller is parked in here, so the
/// gate must outlive it — it lives on the TEST's stack and the hook captures
/// a bare pointer to it. The hook lambda's own closure storage belongs to the
/// engine's std::function member and dies with the engine, so the capture is
/// read ONCE at hook entry (into a stack local) and never again after the
/// park begins; otherwise ASan reports the closure rather than the engine
/// member the case is about. (FakeMechanism's own use owns its ParkGate as a
/// plain member — its lifetime is the mechanism's own, no such hazard.)
struct ParkGate {
    std::mutex mu;
    std::condition_variable cv;
    bool entered{false};
    bool released{false};
    void park() {
        std::unique_lock lk(mu);
        entered = true;
        cv.notify_all();
        cv.wait(lk, [this] { return released; });
    }
    [[nodiscard]] bool wait_entered(std::chrono::milliseconds timeout = 5000ms) {
        std::unique_lock lk(mu);
        return cv.wait_for(lk, timeout, [this] { return entered; });
    }
    void release() {
        {
            std::lock_guard lk(mu);
            released = true;
        }
        cv.notify_all();
    }
};

class FakeMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        // One-way seal (rung 9c PR-6 item 1), mirroring the real mechanisms:
        // start() being CALLED seals the establishment sink, whether or not
        // this call does anything else.
        sink_sealed_ = true;
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        started_ = true;
        ++start_calls_;
    }
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        // One-shot park (rung 9c PR-6 item 1, E14/E15): gate at the TOP,
        // before any state mutation — models a mechanism whose watch() blocks
        // on OS handle setup while the caller still holds this type's
        // mech-ops lock. Shares one ParkGate with unwatch() below — a given
        // test scenario parks at most one of the two at a time.
        bool should_park = false;
        {
            std::lock_guard lk(mu_);
            if (park_next_watch_) {
                park_next_watch_ = false;
                should_park = true;
            }
        }
        if (should_park)
            park_gate_.park(); // blocks until release_park()
        std::lock_guard lk(mu_);
        ++watch_calls_;
        // Checked after the gate, consumed (rung 9c PR-6 item 1): a NEW
        // one-shot failure independent of the pre-existing fail_watch_/
        // throw_watch_* below, which stay level-triggered (set-then-use, not
        // consumed) for the tests that already depend on that.
        if (fail_next_watch_) {
            fail_next_watch_ = false;
            return std::unexpected("forced watch failure (one-shot, rung 9c PR-6 item 1)");
        }
        if (throw_watch_nonstd_)
            throw 42; // non-std throw → exercises watch_guarded()'s catch(...) arm
        if (throw_watch_)
            throw std::runtime_error(throw_watch_msg_); // contract-violating mechanism (UP-7)
        if (fail_watch_)
            return std::unexpected(fail_watch_msg_);
        watched_.insert(key);
        return {};
    }
    // The engine always calls this overload in production. Records the
    // incarnation token BEFORE delegating to watch() above, so every existing
    // fail/throw/park behavior on watch() (and every pre-existing test that
    // exercises it via the engine) is unaffected — this is purely additive.
    std::expected<void, std::string> watch_incarnation(const std::string& key,
                                                        const SparkParams& params,
                                                        SparkIncarnation incarnation) override {
        {
            std::lock_guard lk(mu_);
            tokens_[key].push_back(incarnation);
        }
        return watch(key, params);
    }
    bool set_established_sink(SparkEstablishedFn sink) override {
        std::lock_guard lk(mu_);
        if (sink_sealed_)
            return false;
        established_sink_ = std::move(sink);
        return true;
    }
    void unwatch(const std::string& key) override {
        // One-shot park (rung 9c PR-6 item 1, E14/E15) — see watch()'s own
        // comment; same shared ParkGate.
        bool should_park = false;
        {
            std::lock_guard lk(mu_);
            if (park_next_unwatch_) {
                park_next_unwatch_ = false;
                should_park = true;
            }
        }
        if (should_park)
            park_gate_.park();
        std::lock_guard lk(mu_);
        ++unwatch_calls_;
        // #2815: did this unwatch arrive AFTER the engine had already torn this
        // mechanism down? That is the exact fact the teardown lease exists to make
        // false. It is the BENIGN half of the window — every real mechanism fails an
        // unwatch closed once stopped — whose MALIGN half is the same parked caller
        // touching a FREED engine (Scenario B below). This counter is the observable
        // for the benign half, which is the half a cross-platform test can pin.
        if (stop_calls_ > 0)
            ++unwatch_calls_after_stop_;
        watched_.erase(key);
        // The real mechanisms allocate inside unwatch() (spark_service queues a Cmd
        // holding a key copy; spark_file grows retiring_), so bad_alloc out of here
        // is a real production shape, not a contrivance (#2270 round 4).
        if (throw_unwatch_)
            throw std::bad_alloc{};
    }
    void stop() override {
        std::lock_guard lk(mu_);
        started_ = false;
        ++stop_calls_;
    }
    // Atomic-only, like every real mechanism (stats() is called under the engine's mu_).
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {.inert = inert_for_test_.load(std::memory_order_relaxed)};
    }

    // ── test drivers ──
    void fire(const std::string& key, SparkData data = SparkData{std::monostate{}}) {
        SparkEmitFn e;
        {
            std::lock_guard lk(mu_);
            e = emit_;
        }
        if (e)
            e(key, std::move(data));
    }
    // Drive the fault/health channel as a real mechanism would (lock released).
    void fire_fault(const std::string& key, bool faulted, std::string_view reason) {
        SparkFaultFn f;
        {
            std::lock_guard lk(mu_);
            f = fault_;
        }
        if (f)
            f(key, faulted, reason);
    }
    // Drive the establishment channel as a real mechanism would (lock released,
    // rung 9c PR-6 item 1).
    void fire_established(const std::string& key, SparkIncarnation inc,
                          std::chrono::steady_clock::time_point at, SparkCoverage cov) {
        SparkEstablishedFn f;
        {
            std::lock_guard lk(mu_);
            f = established_sink_;
        }
        if (f)
            f(key, inc, at, cov);
    }
    /// Every incarnation token watch_incarnation() has recorded for `key`, in
    /// call order (rung 9c PR-6 item 1, H1 tests).
    std::vector<SparkIncarnation> tokens(const std::string& key) {
        std::lock_guard lk(mu_);
        auto it = tokens_.find(key);
        return it == tokens_.end() ? std::vector<SparkIncarnation>{} : it->second;
    }
    bool is_watching(const std::string& key) {
        std::lock_guard lk(mu_);
        return watched_.count(key) > 0;
    }
    int watch_calls() {
        std::lock_guard lk(mu_);
        return watch_calls_;
    }
    int unwatch_calls() {
        std::lock_guard lk(mu_);
        return unwatch_calls_;
    }
    /// #2815: unwatch() calls that arrived after this mechanism's own stop().
    int unwatch_calls_after_stop() {
        std::lock_guard lk(mu_);
        return unwatch_calls_after_stop_;
    }
    int stop_calls() {
        std::lock_guard lk(mu_);
        return stop_calls_;
    }
    bool started() {
        std::lock_guard lk(mu_);
        return started_;
    }
    void set_fail_watch(bool b) {
        std::lock_guard lk(mu_);
        fail_watch_ = b;
    }
    void set_throw_watch(bool b) {
        std::lock_guard lk(mu_);
        throw_watch_ = b;
    }
    void set_throw_watch_nonstd(bool b) {
        std::lock_guard lk(mu_);
        throw_watch_nonstd_ = b;
    }
    /// Text the thrown/returned watch error carries — a test uses a very long one to
    /// overrun the engine's bounded error headroom (#2270 round 4).
    void set_throw_watch_msg(std::string m) {
        std::lock_guard lk(mu_);
        throw_watch_msg_ = std::move(m);
    }
    void set_fail_watch_msg(std::string m) {
        std::lock_guard lk(mu_);
        fail_watch_msg_ = std::move(m);
    }
    void set_throw_unwatch(bool b) {
        std::lock_guard lk(mu_);
        throw_unwatch_ = b;
    }
    // ── rung 9c PR-6 item 1 test seams ──
    void set_park_next_watch(bool b) {
        std::lock_guard lk(mu_);
        park_next_watch_ = b;
    }
    void set_park_next_unwatch(bool b) {
        std::lock_guard lk(mu_);
        park_next_unwatch_ = b;
    }
    void set_fail_next_watch(bool b) {
        std::lock_guard lk(mu_);
        fail_next_watch_ = b;
    }
    /// Drives the mechanism-reported `inert` flag (stats() is lock-free, so no mu_).
    void set_inert(bool b) { inert_for_test_.store(b, std::memory_order_relaxed); }
    /// True once a parked watch()/unwatch() has actually entered its park —
    /// the observable half of the park seam (E14/E15).
    [[nodiscard]] bool wait_parked(std::chrono::milliseconds timeout = 5000ms) {
        return park_gate_.wait_entered(timeout);
    }
    void release_park() { park_gate_.release(); }
    /// Exposes the internal ParkGate by reference so a test can hand it to
    /// ThreadJoinGuard directly, matching the #2815 door tests' own backstop
    /// pattern (release-then-join on early REQUIRE failure, so an unwind
    /// never destroys a still-joinable thread parked forever with no other
    /// caller left to release it).
    ParkGate& park_gate_for_test() { return park_gate_; }

private:
    std::mutex mu_;
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    /// Establishment-signal sink (rung 9c PR-6 item 1) — installed by
    /// set_established_sink(), sealed at start(), read (lock released) by
    /// fire_established().
    SparkEstablishedFn established_sink_;
    bool sink_sealed_{false};
    std::set<std::string> watched_;
    bool started_{false};
    bool fail_watch_{false};
    bool throw_watch_{false};
    bool throw_watch_nonstd_{false};
    bool throw_unwatch_{false};
    std::string throw_watch_msg_{"forced watch throw"};
    std::string fail_watch_msg_{"forced watch failure"};
    int watch_calls_{0};
    int unwatch_calls_{0};
    int unwatch_calls_after_stop_{0};
    int stop_calls_{0};
    int start_calls_{0};
    /// spark key -> every incarnation token watch_incarnation() has recorded
    /// for it, in call order (rung 9c PR-6 item 1, H1 tests).
    std::map<std::string, std::vector<SparkIncarnation>> tokens_;
    bool park_next_watch_{false};
    bool park_next_unwatch_{false};
    bool fail_next_watch_{false};
    std::atomic<bool> inert_for_test_{false};
    /// Shared by watch()/unwatch() — a given test scenario parks at most one
    /// of the two calls at a time, so one gate suffices.
    ParkGate park_gate_;
};

/// RAII safety net for the #2815/#2833/#2818 door tests below (cpp-safety Gate 3
/// finding): each spawns a std::thread, then runs a REQUIRE(gate.wait_entered())
/// BEFORE that thread is joined. If wait_entered() times out (real CI/shared-box
/// contention, not hypothetical), the REQUIRE throws and unwinds past a still-
/// joinable std::thread -> ~thread() -> std::terminate(), aborting the WHOLE test
/// binary, not just this one case. C++ destroys automatic-storage locals in REVERSE
/// declaration order, so this only protects a thread it tracks if that thread (and any
/// std::atomic its lambda body writes to) is declared BEFORE this guard — a thread (or
/// atomic) declared AFTER the guard destructs BEFORE it on unwind, getting NONE of this
/// protection (governance Gate 8 finding: this exact mistake was made for a second
/// thread at 7 of 9 original call sites, and for that thread's own completion-flag
/// atomic when the first fix hoisted the thread but not the atomic). If the real thread
/// body isn't ready yet when you need to declare it, default-construct a std::thread in
/// place, track() it immediately, and move-assign the real body into it later — the
/// address track() captured stays valid across the move-assignment. On the ordinary
/// happy path the test's own explicit gate.release()+.join() calls still run first,
/// making the destructor's release()/join() calls harmless no-ops (release() is
/// idempotent; joinable() is false on an already-joined thread) — this is purely a
/// backstop, not a replacement for the explicit teardown sequence.
struct ThreadJoinGuard {
    ParkGate* gate;
    std::vector<std::thread*> threads;
    void track(std::thread& t) { threads.push_back(&t); }
    ~ThreadJoinGuard() {
        if (gate)
            gate->release();
        for (auto* t : threads)
            if (t->joinable())
                t->join();
    }
};

/// Poll `flag` for `window`, reporting whether it ever became true. Used by the #2815
/// cases to assert a NEGATIVE ("stop() has NOT returned yet") without a fixed sleep and
/// without spraying one Catch2 assertion per poll.
bool became_true_within(const std::atomic<bool>& flag, std::chrono::milliseconds window) {
    const auto until = std::chrono::steady_clock::now() + window;
    while (std::chrono::steady_clock::now() < until) {
        if (flag.load(std::memory_order_acquire))
            return true;
        std::this_thread::sleep_for(2ms);
    }
    return flag.load(std::memory_order_acquire);
}

/// A mechanism whose stop() blocks until released — for #1934 UP-1/F4, a
/// regression test that stop()'s mechanism-teardown step runs with no engine
/// lock held.
class BlockingStopMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        stopping_now_.store(true, std::memory_order_release);
        std::unique_lock lk(gate_mu_);
        gate_cv_.wait(lk, [&] { return release_; });
    }
    void fire(const std::string& key) {
        if (emit_)
            emit_(key, SparkData{std::monostate{}});
    }
    bool stopping_now() const { return stopping_now_.load(std::memory_order_acquire); }
    void release() {
        {
            std::lock_guard lk(gate_mu_);
            release_ = true;
        }
        gate_cv_.notify_all();
    }

private:
    SparkEmitFn emit_;
    std::atomic<bool> stopping_now_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool release_{false};
};

/// A mechanism whose watch() blocks until released — for #2011, proves the
/// per-mechanism-type mech_ops_mu_by_type_ (not the old engine-wide
/// mech_ops_mu_) no longer couples a stalled watch() on ONE mechanism type to
/// arm/disarm on a DIFFERENT type.
class BlockingWatchMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        watching_now_.store(true, std::memory_order_release);
        std::unique_lock lk(gate_mu_);
        gate_cv_.wait(lk, [&] { return release_; });
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {}
    bool watching_now() const { return watching_now_.load(std::memory_order_acquire); }
    void release() {
        {
            std::lock_guard lk(gate_mu_);
            release_ = true;
        }
        gate_cv_.notify_all();
    }

private:
    SparkEmitFn emit_;
    std::atomic<bool> watching_now_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool release_{false};
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
SparkSpec registry_spec(const std::string& hive, const std::string& key) {
    return SparkSpec{SparkType::Registry, RegistrySparkParams{hive, key}};
}
SparkSpec service_spec(const std::string& name) {
    return SparkSpec{SparkType::Service, ServiceSparkParams{name}};
}
SparkSpec interval_spec(std::uint64_t ms) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{ms}};
}

/// Register a fake for `type` and return the borrowed pointer (engine owns it).
FakeMechanism* wire_fake(SparkEngine& engine, SparkType type) {
    auto fake = std::make_unique<FakeMechanism>();
    FakeMechanism* raw = fake.get();
    REQUIRE(engine.register_mechanism(type, std::move(fake)).has_value());
    return raw;
}

} // namespace

TEST_CASE("register_mechanism: validates null / type / duplicate / timing", "[spark][mechanism]") {
    SparkEngine engine;
    CHECK_FALSE(engine.register_mechanism(SparkType::File, nullptr).has_value());
    // Timer-driven types have no mechanism — the wheel services them.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Interval, std::make_unique<FakeMechanism>()).has_value());
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Disk, std::make_unique<FakeMechanism>()).has_value());

    REQUIRE(engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());
    // Duplicate registration for the same type is rejected.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());

    engine.start();
    // After start() it is too late to register.
    CHECK_FALSE(engine.register_mechanism(SparkType::Registry, std::make_unique<FakeMechanism>())
                    .has_value());
    engine.stop();
}

TEST_CASE("arm(File) with no mechanism is rejected (armed == a watcher runs)", "[spark][mechanism]") {
    SparkEngine engine;
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value()); // no File mechanism registered → reject, never inert-arm
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("arm(Service) with no mechanism is rejected (armed == a watcher runs)",
          "[spark][mechanism]") {
    SparkEngine engine;
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    auto sub = engine.arm(*c, service_spec("sshd"));
    CHECK_FALSE(sub.has_value()); // no Service mechanism registered → reject, never inert-arm
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("arm(File) validation: empty path rejected", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, file_spec("")).has_value());
}

TEST_CASE("arm(Registry) validation: hive must be HKLM/HKCU/HKCR/HKU", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Registry);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("BOGUS", "Software\\Yuzu")).has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("HKLM", "")).has_value());
    CHECK(engine.arm(*c, registry_spec("HKLM", "Software\\Yuzu")).has_value());
}

TEST_CASE("arm(Service) validation: name charset and length", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Service);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, service_spec("")).has_value());
    CHECK_FALSE(engine.arm(*c, service_spec(std::string(257, 'a'))).has_value());
    CHECK_FALSE(engine.arm(*c, service_spec("foo bar")).has_value());  // space not allowed
    CHECK_FALSE(engine.arm(*c, service_spec("foo;x")).has_value());    // shell metachar not allowed
    CHECK(engine.arm(*c, service_spec("sshd")).has_value());
    CHECK(engine.arm(*c, service_spec("ssh.service")).has_value());
    CHECK(engine.arm(*c, service_spec("getty@tty1.service")).has_value());
}

TEST_CASE("File spark: arm-after-start watches, fire delivers to the consumer",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(fake->is_watching(key));       // the mechanism was told to watch, live
    CHECK(fake->watch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 1);

    fake->fire(key);
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const SparkEvent ev = got.at(0);
    CHECK(ev.key == key);
    CHECK(ev.type == SparkType::File);
    CHECK(std::holds_alternative<std::monostate>(ev.data));

    engine.stop();
    CHECK(fake->stop_calls() == 1); // mechanism stopped (before consumers)
}

TEST_CASE("File spark: arm-before-start is replayed to the mechanism at start()",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());

    const auto spec = file_spec("/var/log/syslog");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK_FALSE(fake->is_watching(key)); // not watched until the engine starts
    CHECK(fake->watch_calls() == 0);

    engine.start();
    CHECK(eventually([&] { return fake->is_watching(key); })); // start() replays the watch
    CHECK(fake->watch_calls() == 1);

    fake->fire(key);
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
}

TEST_CASE("File spark: equal specs dedup to one watch, fan out to all subscribers",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector a, b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*ca, spec).has_value());
    REQUIRE(engine.arm(*cb, spec).has_value());
    CHECK(fake->watch_calls() == 1); // dedup: N subscriptions, 1 watcher
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 2);

    fake->fire(key);
    REQUIRE(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    CHECK(a.at(0).seq == b.at(0).seq); // one fire, one seq, both observe it
    engine.stop();
}

TEST_CASE("File spark: unwatch fires only when the last subscription is disarmed",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto ca = engine.register_consumer("a", [](const SparkEvent&) {});
    auto cb = engine.register_consumer("b", [](const SparkEvent&) {});
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sa = engine.arm(*ca, spec);
    auto sb = engine.arm(*cb, spec);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());

    engine.disarm(*sa);
    CHECK(fake->is_watching(key));    // one subscription remains — watch stays
    CHECK(fake->unwatch_calls() == 0);
    engine.disarm(*sb);
    CHECK(eventually([&] { return !fake->is_watching(key); })); // last one gone → unwatch
    CHECK(fake->unwatch_calls() == 1);
    engine.stop();
}

TEST_CASE("File spark: unregister_consumer unwatches a watch its removal empties "
          "(governance Tr3kkR finding, PR #1927)",
          "[spark][mechanism]") {
    // unregister_consumer erases a consumer's LAST subscription to an armed
    // spark the same way disarm() does — it must tear down the OS watch the
    // same way too. Before the fix, this path erased the armed_ entry without
    // ever calling unwatch(): the mechanism's watch stayed live for a spark
    // the engine no longer considered armed.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto ca = engine.register_consumer("a", [](const SparkEvent&) {});
    auto cb = engine.register_consumer("b", [](const SparkEvent&) {});
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sa = engine.arm(*ca, spec);
    auto sb = engine.arm(*cb, spec);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());
    CHECK(fake->is_watching(key));

    // Consumer b still holds a subscription — unregistering a NEVER touches
    // the watch, mirroring disarm()'s "watch stays while a subscription
    // remains" behavior.
    engine.unregister_consumer(*ca);
    CHECK(fake->is_watching(key));
    CHECK(fake->unwatch_calls() == 0);

    // Unregistering b removes the watch's LAST subscription — the watch must
    // be torn down, exactly as if b had called disarm() on it directly.
    engine.unregister_consumer(*cb);
    CHECK(eventually([&] { return !fake->is_watching(key); }));
    CHECK(fake->unwatch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 0);
    engine.stop();
}

TEST_CASE("File spark: a consumer unregistered mid-arm leaves no ghost subscription "
          "(#1994 M1)",
          "[spark][mechanism]") {
    // Forces the exact interleaving M1 closes: the consumer existed at arm()'s
    // pre-check (consumers_mu_), but is FULLY unregistered — subscription
    // removed, mechanism unwatched, consumers_ entry erased — after the
    // mechanism watch succeeds and before arm_impl's post-insert consumer
    // re-check. Before the fix, this left a Subscriber permanently in armed_
    // for a consumer that no longer exists: uncounted by unregister_consumer
    // (which ran before the sub was inserted) and never delivered to (deliver()
    // silently no-ops an unknown consumer id) — a silent resource leak, not a
    // crash.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto consumer = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(consumer.has_value());
    engine.start();

    engine.set_arm_race_hook_for_test([&] { engine.unregister_consumer(*consumer); });

    const auto spec = file_spec("/etc/hosts");
    auto sub = engine.arm(*consumer, spec);
    CHECK_FALSE(sub.has_value()); // lost the race — must report failure, not a ghost

    CHECK(engine.stats().subscriptions == 0);
    CHECK(engine.stats().armed_sparks == 0); // no orphaned key left behind
    CHECK(fake->watch_calls() == 1);         // the watch DID succeed before the hook fired
    CHECK(fake->unwatch_calls() == 1);       // unregister_consumer tore it back down — no leak
    engine.stop();
}

TEST_CASE("SparkEngine: arm() racing unregister_consumer() under REAL concurrent "
          "scheduling never leaves a ghost subscription (stress, #1994 M1)",
          "[spark][engine][stress]") {
    // The deterministic hook-based test above proves the recheck-then-rollback
    // LOGIC is correct on one thread; this exercises the actual cross-thread
    // memory-ordering half with real concurrent scheduling and no seam.
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        engine.set_cadence_floor_for_test(10);
        engine.start();
        auto consumer = engine.register_consumer("racer", [](const SparkEvent&) {});
        REQUIRE(consumer.has_value());

        std::atomic<bool> go{false};
        std::thread unregisterer([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            engine.unregister_consumer(*consumer);
        });
        go.store(true, std::memory_order_release);
        // Result intentionally unchecked: either outcome (won or lost the race
        // against the concurrent unregister) is valid — the invariant under
        // test is "no crash, no ghost", not which side wins.
        (void)engine.arm(*consumer, interval_spec(20));
        unregisterer.join();
        engine.stop();

        // Whichever side won, the consumer is gone and no subscription should
        // remain pointing at it.
        CHECK(engine.stats().consumers == 0);
        CHECK(engine.stats().subscriptions == 0);
    }
    SUCCEED("500 concurrent arm()/unregister_consumer() trials completed without a crash or "
            "a surviving ghost subscription");
}

TEST_CASE("File spark: a late unwatch from a torn-down arm does not clobber a "
          "concurrent equal-spec re-arm (#1994 M2)",
          "[spark][mechanism]") {
    // Forces the exact interleaving M2 closes: disarm() removes the last
    // subscription to a key (releasing mu_, about to call unwatch()) while a
    // NEW arm() of an EQUAL spec races in, sees the key already gone from
    // armed_, and re-establishes a fresh watch. Before the fix, the first
    // disarm's now-stale unwatch() would run after the fresh watch() and tear
    // it down — leaving armed_ showing the key armed with NO live OS watch.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto s1 = engine.arm(*c1, spec);
    REQUIRE(s1.has_value());
    CHECK(fake->is_watching(key));

    // disarm()'s hook fires with mu_ already released, just before its
    // staleness-rechecked unwatch() call — re-arm an equal spec here so the
    // fresh watch is already up by the time the stale unwatch would fire.
    engine.set_disarm_race_hook_for_test([&] {
        auto s2 = engine.arm(*c2, spec);
        REQUIRE(s2.has_value());
    });
    engine.disarm(*s1);

    // The fresh watch must survive: still watched, and the stale unwatch must
    // have been SKIPPED (not merely harmless) — the mechanism never saw it.
    CHECK(fake->is_watching(key));
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(fake->watch_calls() == 2);   // original arm + the re-arm
    CHECK(fake->unwatch_calls() == 0); // the stale unwatch was skipped, not just harmless
    engine.stop();
}

TEST_CASE("File spark: disarm() racing an equal-spec arm() under REAL concurrent "
          "scheduling never tears down a fresh watch (stress, #1994 M2)",
          "[spark][mechanism][stress]") {
    // Companion to the deterministic hook test above (which forces the exact
    // interleaving and is the actual proof of the recheck-then-skip logic).
    // This twin runs the two ops on real threads with no seam: it does NOT
    // reliably hit the nanosecond race window (measured ~0.11s for 500 trials
    // on an idle runner — the window is almost never hit), so its value is
    // exercising the cross-thread memory-ordering of mech_ops_mu_by_type_/mu_
    // under TSan, not interleaving coverage. Mirrors the M1 stress twin's
    // framing. (Single-type here, so per-type vs engine-wide is behaviourally
    // identical — only the identifier changed with #2011.)
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        FakeMechanism* fake = wire_fake(engine, SparkType::File);
        auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
        auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
        REQUIRE(c1.has_value());
        REQUIRE(c2.has_value());
        engine.start();

        const auto spec = file_spec("/etc/hosts");
        const std::string key = spark_key(spec);
        auto s1 = engine.arm(*c1, spec);
        REQUIRE(s1.has_value());

        std::atomic<bool> go{false};
        // Catch2 assertion macros are NOT thread-safe and a failed REQUIRE
        // throws — off the main thread that escapes the std::thread and
        // std::terminate()s the whole binary (security-guardian/cpp-safety
        // Gate 2/3). Capture the result and assert on the main thread after
        // join(), matching the M1 stress twin.
        std::atomic<bool> rearm_ok{false};
        std::thread rearmer([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            rearm_ok.store(engine.arm(*c2, spec).has_value(), std::memory_order_release);
        });
        go.store(true, std::memory_order_release);
        engine.disarm(*s1);
        rearmer.join();
        CHECK(rearm_ok.load(std::memory_order_acquire));

        // Invariant under test regardless of interleaving order: if armed_
        // still shows the key armed (c2's subscription survived), the
        // mechanism must actually be watching it — never torn down and never
        // silently orphaned.
        if (engine.stats().armed_sparks > 0)
            CHECK(fake->is_watching(key));
        engine.stop();
    }
    SUCCEED("500 concurrent disarm()/arm() trials completed with no torn-down fresh watch");
}

TEST_CASE("SparkEngine: a blocking watch() on one mechanism type does not delay "
          "unwatch() on a DIFFERENT mechanism type (#2011)",
          "[spark][mechanism]") {
    // Acceptance test for the rung-0 HARD GATE: with the old engine-wide
    // mech_ops_mu_, a stalled File watch() held the ONE lock every unwatch()
    // queued behind, so a Registry disarm could not proceed until File's watch
    // returned. Per-type locks (mech_ops_mu_by_type_) decouple them.
    SparkEngine engine;
    FakeMechanism* reg_fake = wire_fake(engine, SparkType::Registry);
    auto blocking = std::make_unique<BlockingWatchMechanism>();
    BlockingWatchMechanism* bwm = blocking.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(blocking)).has_value());

    auto consumer = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(consumer.has_value());
    engine.start();

    // Arm a Registry spark first — its FakeMechanism watch() returns at once, so
    // it is live and its later disarm has a real unwatch to issue.
    const auto reg_spec = registry_spec("HKLM", "Software\\Foo");
    auto reg_sub = engine.arm(*consumer, reg_spec);
    REQUIRE(reg_sub.has_value());
    CHECK(reg_fake->is_watching(spark_key(reg_spec)));

    // Arm a File spark whose watch() blocks (holding File's per-type lock) — on
    // a background thread, since arm() will not return until watch() does.
    std::thread blocker([&] { (void)engine.arm(*consumer, file_spec("/etc/hosts")); });
    // NB: a non-throwing CHECK, not REQUIRE — `blocker` is joinable here, and a
    // REQUIRE that threw would run ~std::thread on it → std::terminate (aborting
    // the whole binary) instead of a clean red. Capture the outcome and assert
    // it after the joins below.
    const bool file_watch_entered = eventually([&] { return bwm->watching_now(); });
    CHECK(file_watch_entered);

    // Disarm the Registry subscription on its own thread while File's watch() is
    // still blocked. Under per-type locks this returns immediately; under the
    // old engine-wide lock it would stay blocked behind File's watch() until we
    // release() below — the eventually() would time out and completed==false.
    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*reg_sub);
        disarm_done.store(true, std::memory_order_release);
    });
    const bool completed = eventually([&] { return disarm_done.load(std::memory_order_acquire); });
    CHECK(completed); // the whole point of #2011: File's stall did not block Registry
    CHECK(reg_fake->unwatch_calls() == 1);

    // Cleanup: release the blocked File watch, then join everything. (Even under
    // a regression where `completed` is false, release() unblocks File's watch,
    // which frees the old shared lock so the pending disarm can finish — so the
    // test fails cleanly rather than hanging. No REQUIRE runs between the thread
    // spawns and these joins, so no throw can bypass them.)
    bwm->release();
    disarmer.join();
    blocker.join();
    engine.stop();
}

TEST_CASE("SparkEngine: a blocking watch() DOES still serialise a second arm within "
          "the SAME mechanism type (#2011 per-type control)",
          "[spark][mechanism]") {
    // Converse control for the cross-type test above. Together they pin the lock
    // granularity to exactly per-type: the cross-type test rules out a per-ENGINE
    // lock (File no longer blocks Registry); this one rules out a per-KEY lock
    // (two File keys still share File's lock). Without this, mech_ops_mu_by_type_
    // could be accidentally always-uncontended and the cross-type test alone
    // would still pass — this asserts the per-type lock is REAL.
    SparkEngine engine;
    auto blocking = std::make_unique<BlockingWatchMechanism>();
    BlockingWatchMechanism* bwm = blocking.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(blocking)).has_value());
    auto consumer = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(consumer.has_value());
    engine.start();

    // File spark A: its watch() blocks, holding File's per-type lock.
    std::thread armA([&] { (void)engine.arm(*consumer, file_spec("/tmp/a")); });
    const bool a_entered = eventually([&] { return bwm->watching_now(); });
    CHECK(a_entered);

    // File spark B (a DIFFERENT key, so no dedup — a fresh watch()): its arm must
    // take the SAME File lock, so it cannot complete while A's watch() holds it.
    std::atomic<bool> b_done{false};
    std::thread armB([&] {
        (void)engine.arm(*consumer, file_spec("/tmp/b"));
        b_done.store(true, std::memory_order_release);
    });
    // Over a window, B must NOT complete — it is queued on File's lock behind A.
    // (Under a per-key regression B would take a different lock and finish here.)
    const bool b_completed_early = eventually([&] { return b_done.load(std::memory_order_acquire); },
                                              300ms);
    CHECK_FALSE(b_completed_early);

    // Release A → both File watches drain; join. No REQUIRE between the spawns and
    // the joins, so no throw can bypass them.
    bwm->release();
    armB.join();
    armA.join();
    engine.stop();
}

TEST_CASE("File spark: a mechanism watch failure rolls the arm back", "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_fail_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value());          // watch failed → arm reported failure
    CHECK(engine.stats().armed_sparks == 0); // and the whole key was torn down (B1)
    CHECK(engine.stats().subscriptions == 0);
    engine.stop();
}

TEST_CASE("File spark: a mechanism that THROWS from watch() rolls the arm back cleanly "
          "(#1994 UP-7)",
          "[spark][mechanism]") {
    // The engine's contract is that a mechanism returns std::unexpected on
    // failure, but the real spark_file::watch() can throw (fs::current_path()
    // on a relative path). A throw must NOT unwind past arm_impl's rollback and
    // leave a zombie armed_ entry with no watcher and no id returned — it must
    // be treated exactly like a returned failure: whole-key teardown, arm()
    // returns a clean std::unexpected (never propagates the exception).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_throw_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts"))); // throw is caught, not propagated
    CHECK_FALSE(sub.has_value());
    CHECK(sub.error().find("watch mechanism threw:") != std::string::npos); // catch(std::exception&) text
    CHECK(engine.stats().armed_sparks == 0); // no zombie armed entry
    CHECK(engine.stats().subscriptions == 0);

    // The engine is still usable afterward: a subsequent good arm succeeds.
    fake->set_throw_watch(false);
    auto ok = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK(ok.has_value());
    CHECK(engine.stats().armed_sparks == 1);
    engine.stop();
}

// ── #2270: arm_impl is strong-guarantee against an allocation failure ─────────
//
// The ghost-entry bug these pin: arm_impl used to insert into armed_ and then keep
// allocating. A std::bad_alloc part-way left an armed_ entry with no subscriber and
// no watcher. Nothing could disarm it (no id was ever returned), and — the damaging
// part — a LATER arm of an equal spec deduped onto it, skipped watch_guarded(), and
// reported SUCCESS with no OS watcher running. Silent detection loss that outlived
// the memory pressure. A real bad_alloc cannot be aimed at one statement, so these
// drive the same unwind through set_arm_fault_hook_for_test().

TEST_CASE("arm_impl: an allocation failure before the sub_keys_ commit leaves no ghost entry "
          "(#2270)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    engine.set_arm_fault_hook_for_test([](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys)
            throw std::bad_alloc{};
    });
    CHECK_THROWS_AS(engine.arm(*c, file_spec("/etc/hosts")), std::bad_alloc);

    // Exactly as on entry: no armed_ entry, no subscription, no watch attempted.
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(engine.stats().subscriptions == 0);
    CHECK(fake->watch_calls() == 0);

    // The damaging consequence, pinned directly: the NEXT arm of the same key must
    // arm a REAL watcher, not dedup onto a survivor.
    engine.set_arm_fault_hook_for_test(nullptr);
    auto ok = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(ok.has_value());
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(fake->watch_calls() == 1);
    CHECK(fake->is_watching("file|10:/etc/hosts"));
    engine.stop();
}

TEST_CASE("arm_impl: an allocation failure on a DEDUPED arm leaves the existing subscriber and "
          "its watcher untouched (#2270)",
          "[spark][mechanism]") {
    // The existing-key half of the same guarantee, and the reason the commit order
    // reserves the subs slot up front: the failing arm must not disturb a sibling
    // whose own arm() has already returned SUCCESS to its caller.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    auto first = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(first.has_value());
    REQUIRE(fake->watch_calls() == 1);

    engine.set_arm_fault_hook_for_test([](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys)
            throw std::bad_alloc{};
    });
    CHECK_THROWS_AS(engine.arm(*c, file_spec("/etc/hosts")), std::bad_alloc);
    engine.set_arm_fault_hook_for_test(nullptr);

    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 1);
    CHECK(fake->watch_calls() == 1);   // no second watch
    CHECK(fake->unwatch_calls() == 0); // and nothing torn down
    CHECK(fake->is_watching("file|10:/etc/hosts"));

    // The survivor is still a working subscription end to end.
    engine.disarm(*first);
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(fake->unwatch_calls() == 1);
    engine.stop();
}

// ── #2270 round 4: the window PAST the commit ────────────────────────────────
//
// The two cases above cover the in-lock layer. These cover the layer the round-3
// fix claimed was already closed and was not: everything between arm_impl's commit
// and its return. The measured escape was watch_guarded's error concat, which ran
// INSIDE a catch handler — a bad_alloc there unwound past a committed subscription
// and produced the ghost these tests exist to keep closed.
//
// kArmFaultPhaseWatchErrorBuild is a CONTAINMENT pin, not a rollback pin: the
// production completion (BoundedMsg::finish) is noexcept by construction, so no
// live statement at that point can throw today. The seam proves the property holds
// on every platform, including the ones the Linux-only allocation counter in
// test_spark_alloc_budget.cpp cannot reach.

TEST_CASE("arm_impl: a throw while BUILDING the watch error cannot ghost the key (#2270)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_throw_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    engine.set_arm_fault_hook_for_test([](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseWatchErrorBuild)
            throw std::bad_alloc{};
    });

    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts"))); // must NOT propagate
    CHECK_FALSE(sub.has_value());
    // The outer failed-watch wrapper is what the caller sees; the inner text is
    // truncated to its prefix because the completion was interrupted.
    CHECK(sub.error().starts_with("watch mechanism failed to arm '"));
    CHECK(sub.error().find("watch mechanism threw:") != std::string::npos);

    // The ghost, pinned directly. Before the fix this read armed_sparks == 1,
    // subscriptions == 1, unwatch_calls == 0.
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(engine.stats().subscriptions == 0);
    CHECK(fake->watch_calls() == 1);

    // And the damaging consequence: the next equal-spec arm must arm a REAL
    // watcher rather than dedup onto a survivor and report success while deaf.
    engine.set_arm_fault_hook_for_test(nullptr);
    fake->set_throw_watch(false);
    auto ok = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(ok.has_value());
    CHECK(fake->watch_calls() == 2);
    CHECK(fake->is_watching("file|10:/etc/hosts"));
    engine.stop();
}

TEST_CASE("start(): a throw while building a replay watch error never escapes start() (#2270)",
          "[spark][mechanism]") {
    // watch_guarded is the SINGLE boundary for both arm paths (#2019). Hardening it
    // for arm_impl must not break the pre-start replay caller, whose failure handling
    // is the opposite: fault in place, never roll back (subscribers hold ids already).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());

    auto sub = engine.arm(*c, file_spec("/etc/hosts")); // pre-start: no watch yet
    REQUIRE(sub.has_value());
    REQUIRE(fake->watch_calls() == 0);

    fake->set_throw_watch(true);
    engine.set_arm_fault_hook_for_test([](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseWatchErrorBuild)
            throw std::bad_alloc{};
    });
    REQUIRE_NOTHROW(engine.start()); // void return — an escape here is unrecoverable

    CHECK(fake->watch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 1);  // replay keeps the entry...
    CHECK(engine.stats().armed_faulted == 1); // ...and flags it deaf (B1)
    engine.set_arm_fault_hook_for_test(nullptr);
    engine.stop();
}

TEST_CASE("arm_impl: an over-long watch error is truncated, never grown, past the commit (#2270)",
          "[spark][mechanism]") {
    // The bounded buffer's whole point: a mechanism error is caller-controlled in
    // length, so concatenating it after the commit would put an unbounded allocation
    // exactly where an allocation must not fail. Both the thrown and the RETURNED
    // error take that path.
    const std::string huge(4096, 'x');

    SECTION("thrown") {
        SparkEngine engine;
        FakeMechanism* fake = wire_fake(engine, SparkType::File);
        fake->set_throw_watch(true);
        fake->set_throw_watch_msg(huge);
        auto c = engine.register_consumer("c", [](const SparkEvent&) {});
        REQUIRE(c.has_value());
        engine.start();

        auto sub = engine.arm(*c, file_spec("/etc/hosts"));
        REQUIRE_FALSE(sub.has_value());
        CHECK(sub.error().find("watch mechanism threw:") != std::string::npos);
        CHECK(sub.error().size() < huge.size()); // truncated, not grown
        CHECK(engine.stats().armed_sparks == 0);
        CHECK(engine.stats().subscriptions == 0);
        engine.stop();
    }
    SECTION("returned") {
        SparkEngine engine;
        FakeMechanism* fake = wire_fake(engine, SparkType::File);
        fake->set_fail_watch(true);
        fake->set_fail_watch_msg(huge);
        auto c = engine.register_consumer("c", [](const SparkEvent&) {});
        REQUIRE(c.has_value());
        engine.start();

        auto sub = engine.arm(*c, file_spec("/etc/hosts"));
        REQUIRE_FALSE(sub.has_value());
        CHECK(sub.error().starts_with("watch mechanism failed to arm '"));
        CHECK(sub.error().size() < huge.size());
        CHECK(engine.stats().armed_sparks == 0);
        CHECK(engine.stats().subscriptions == 0);
        engine.stop();
    }
}

// ── #2270 round 4: the consumer-race teardown ────────────────────────────────
//
// These reach teardown_arm_race's REAL-WORK branch, which no existing test could:
// set_arm_race_hook_for_test fires after the insert, so unregister_consumer's own
// scan performs the teardown and arm_impl's degenerates to a no-op. Unregistering
// from the PRE-CHECK seam leaves nothing for that scan to find, so the teardown
// itself must remove the subscription and drop the OS watch.

TEST_CASE("arm_impl: losing the consumer race after the pre-check tears the watch down (#2270)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    engine.set_arm_precheck_race_hook_for_test([&] { engine.unregister_consumer(*c); });
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    engine.set_arm_precheck_race_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    CHECK(sub.error() == "consumer unregistered during arm"); // the pre-built message, intact
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(engine.stats().subscriptions == 0);
    CHECK(fake->watch_calls() == 1);   // the watch DID come up...
    CHECK(fake->unwatch_calls() == 1); // ...and the teardown took it back down
    CHECK_FALSE(fake->is_watching("file|10:/etc/hosts"));
    CHECK(engine.stats().arm_race_unwatch_failures_total == 0);
    engine.stop();
}

TEST_CASE("arm_impl: losing the consumer race never disturbs a deduped SIBLING (#2270)",
          "[spark][mechanism]") {
    // The defect two review rounds shipped: a teardown that dropped the whole key
    // deleted a healthy sibling's subscription and orphaned the live OS watch it
    // believed it had. Losing the M1 race invalidates OUR arm and nobody else's.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto keeper = engine.register_consumer("keeper", [](const SparkEvent&) {});
    auto loser = engine.register_consumer("loser", [](const SparkEvent&) {});
    REQUIRE(keeper.has_value());
    REQUIRE(loser.has_value());
    engine.start();

    auto held = engine.arm(*keeper, file_spec("/etc/hosts"));
    REQUIRE(held.has_value());
    REQUIRE(fake->watch_calls() == 1);

    engine.set_arm_precheck_race_hook_for_test([&] { engine.unregister_consumer(*loser); });
    auto sub = engine.arm(*loser, file_spec("/etc/hosts")); // dedups onto the keeper's key
    engine.set_arm_precheck_race_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    CHECK(engine.stats().armed_sparks == 1);  // the key survives
    CHECK(engine.stats().subscriptions == 1); // exactly the keeper's
    CHECK(fake->watch_calls() == 1);          // dedup: no second watch
    CHECK(fake->unwatch_calls() == 0);        // and nothing torn down
    CHECK(fake->is_watching("file|10:/etc/hosts"));

    // The keeper is still live end to end, not just present in the bookkeeping.
    fake->fire("file|10:/etc/hosts");
    CHECK(eventually([&] { return engine.stats().events_total == 1; }));
    engine.stop();
}

TEST_CASE("arm_impl: a timer spark losing the consumer race touches no mechanism (#2270)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    engine.set_arm_precheck_race_hook_for_test([&] { engine.unregister_consumer(*c); });
    auto sub = engine.arm(*c, interval_spec(20)); // never event-driven: no watch to undo
    engine.set_arm_precheck_race_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    CHECK(sub.error() == "consumer unregistered during arm");
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(engine.stats().subscriptions == 0);
    CHECK(fake->watch_calls() == 0);
    CHECK(fake->unwatch_calls() == 0);
    engine.stop();
}

TEST_CASE("arm_impl: the consumer-race teardown skips a STALE unwatch after a re-arm (#2270 M2)",
          "[spark][mechanism]") {
    // teardown_arm_race inherits disarm()'s M2 discipline: between dropping the key
    // under mu_ and calling unwatch() with mu_ released, a concurrent equal-spec arm
    // may have renewed the key. Unwatching then would tear down the FRESH watch.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto racer = engine.register_consumer("racer", [](const SparkEvent&) {});
    auto rearmer = engine.register_consumer("rearmer", [](const SparkEvent&) {});
    REQUIRE(racer.has_value());
    REQUIRE(rearmer.has_value());
    engine.start();

    // Both hooks are made one-shot with a FLAG, never by clearing themselves: the
    // engine invokes the std::function in place, so reassigning it from inside its
    // own call destroys the callable mid-execution (measured: SIGSEGV).
    bool precheck_fired = false;
    engine.set_arm_precheck_race_hook_for_test([&] {
        if (precheck_fired)
            return;
        precheck_fired = true;
        engine.unregister_consumer(*racer);
    });
    // Fires inside the teardown, after the key is gone and before the unwatch.
    bool rearmed = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (rearmed)
            return;
        rearmed = true;
        auto again = engine.arm(*rearmer, file_spec("/etc/hosts"));
        CHECK(again.has_value());
    });
    auto sub = engine.arm(*racer, file_spec("/etc/hosts"));
    engine.set_arm_precheck_race_hook_for_test(nullptr);
    engine.set_disarm_race_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    CHECK(engine.stats().armed_sparks == 1);  // the re-armed key
    CHECK(engine.stats().subscriptions == 1); // the re-armer's
    CHECK(fake->watch_calls() == 2);
    CHECK(fake->unwatch_calls() == 0); // the stale unwatch was SKIPPED
    CHECK(fake->is_watching("file|10:/etc/hosts"));
    engine.stop();
}

TEST_CASE("arm_impl: a THROWING unwatch during the consumer-race teardown is contained and "
          "counted (#2270)",
          "[spark][mechanism]") {
    // The stated residual. unwatch() is not noexcept and the real mechanisms
    // allocate inside it, so under the memory pressure this whole layer is about it
    // can throw. By then the engine's bookkeeping is consistent, so the throw is
    // contained rather than propagated — but the OS watch it failed to drop outlives
    // its armed_ entry (reclaimed by stop() on Linux; on Windows it can persist for
    // the life of the process — see teardown_arm_race). The counter below is the only
    // egress: it reaches an operator as the sparse heartbeat tag
    // `yuzu.spark_arm_race_unwatch_failures`, because the fallback log line is itself
    // inside a catch-all and is dropped under the same OOM.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    fake->set_throw_unwatch(true);
    engine.set_arm_precheck_race_hook_for_test([&] { engine.unregister_consumer(*c); });
    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts")));
    engine.set_arm_precheck_race_hook_for_test(nullptr);
    fake->set_throw_unwatch(false);

    CHECK_FALSE(sub.has_value());
    CHECK(sub.error() == "consumer unregistered during arm"); // the clean error still arrives
    CHECK(engine.stats().armed_sparks == 0);                  // bookkeeping IS consistent
    CHECK(engine.stats().subscriptions == 0);
    CHECK(engine.stats().arm_race_unwatch_failures_total == 1); // and the residual is observable
    engine.stop();
}

TEST_CASE("disarm: a THROWING unwatch is contained and counted, like its twin (#2270)",
          "[spark][mechanism]") {
    // THE SIBLING CASE. The one above pinned teardown_arm_race; disarm() — the path
    // Guardian's ordinary withdraw takes — was left propagating, which is the fourth
    // and last lockstep difference between the two.
    //
    // Why propagating there was worse than untidy: disarm() is void, and the throw
    // escapes into GuardianSparkRuntime::detach_rule_locked AFTER index_->remove_rule
    // and rules_.erase but BEFORE keys_.erase and the "disarmed" lifecycle entry. That
    // strands a keys_ row, so a later same-key attach's keys_.emplace silently no-ops
    // and reports success while its fresh subscription is orphaned — and the audit
    // entry is lost with it.
    //
    // This case lives here rather than in the alloc-budget binary deliberately: that
    // one is Linux-and-no-sanitizer only by construction, so it cannot pin an OUTCOME
    // on Windows or macOS, and containment is exactly an outcome.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(sub.has_value());
    REQUIRE(engine.stats().armed_sparks == 1);

    fake->set_throw_unwatch(true);
    REQUIRE_NOTHROW(engine.disarm(*sub)); // last subscriber -> whole-key teardown + unwatch
    fake->set_throw_unwatch(false);

    // Bookkeeping completes despite the throw — that is the property.
    CHECK(engine.stats().armed_sparks == 0);
    CHECK(engine.stats().subscriptions == 0);
    CHECK(engine.stats().disarm_unwatch_failures_total == 1); // residual observable
    CHECK(engine.stats().arm_race_unwatch_failures_total == 0); // and scoped to its own path
    engine.stop();
}

TEST_CASE("File spark: a mechanism that throws a NON-std exception from watch() is still contained "
          "(watch_guarded catch(...))",
          "[spark][mechanism]") {
    // watch_guarded() has two catch arms; the std::exception arm is covered by
    // the tests above. A mechanism throwing a non-std type (here `throw 42;`)
    // must hit the catch(...) arm and be contained exactly the same way — never
    // propagate out of arm(). One test on the live path suffices: both arm sites
    // share the single watch_guarded() boundary.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_throw_watch_nonstd(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts"))); // non-std throw caught, not propagated
    CHECK_FALSE(sub.has_value());
    CHECK(sub.error().find("non-std exception") != std::string::npos); // catch(...) text, wire-locked
    CHECK(engine.stats().armed_sparks == 0); // no zombie armed entry
    CHECK(engine.stats().subscriptions == 0);
    engine.stop();
}

TEST_CASE("Pre-start replay fault delivery does not deadlock an inline self-disarm "
          "(TRAP 2 twin, #2818 cpp-safety Gate 3)",
          "[spark][mechanism]") {
    // report_fault() (called from start()'s pre-start-replay loop on a watch failure)
    // now calls deliver(), which can synchronously invoke an Inline handler on the
    // CALLING thread - i.e. the thread running start(), inside its replay loop. If
    // that handler reacts by disarming itself, disarm() re-enters
    // mech_ops_mu_by_type_.at(File) - the same per-type, non-recursive mutex the
    // replay loop was (pre-fix) still holding when it called report_fault(). Proof
    // this doesn't self-deadlock: if it did, engine.start() below would hang forever
    // and this test binary would never reach engine.stop().
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_fail_watch(true); // the pre-start replay watch for `spec` will fail

    const auto spec = file_spec("/etc/hosts");
    std::atomic<bool> disarmed_from_inline{false};
    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent& ev) {
        if (ev.kind != SparkEventKind::Faulted)
            return;
        engine.disarm(ev.subscription_id); // re-enters mech_ops_mu_by_type_.at(File)
        disarmed_from_inline.store(true, std::memory_order_release);
    });
    REQUIRE(inline_sub.has_value()); // pre-start: watch deferred to start()'s replay

    engine.start(); // must return - pre-fix this self-deadlocks
    CHECK(disarmed_from_inline.load());
    CHECK(engine.stats().subscriptions == 0); // the self-disarm actually completed
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch failure marks the spark faulted, not silent",
          "[spark][mechanism]") {
    // A spark armed BEFORE start defers its watch to start()'s replay. If that
    // replay fails, subscribers already hold ids, so (unlike the post-start arm
    // which rolls back) the entry stays — but it must be flagged deaf via the
    // fault channel so "armed but not watching" is observable, never silent (B1).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_fail_watch(true);                // the start() replay watch will fail

    engine.start();
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));       // watch never came up
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …but flagged deaf, not silent
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch that THROWS faults the spark, never escapes start() "
          "(#1994 UP-7 symmetric)",
          "[spark][mechanism]") {
    // The pre-start replay path is the symmetric twin of arm_impl: a real
    // mechanism can THROW from watch() (spark_file's fs::current_path() on a
    // relative path). start() is void — an escaping throw would unwind AFTER
    // running_ is latched and the wheel + mechanisms are up, leaving the spark
    // armed-without-watcher (the exact UP-7 hazard). The replay must catch the
    // throw and fault in place (subscribers hold ids → no rollback), exactly
    // like a returned failure — start() must never propagate the exception.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_throw_watch(true);               // the start() replay watch will THROW

    REQUIRE_NOTHROW(engine.start());           // throw is caught, not propagated
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));       // watch never came up
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …but flagged deaf, not silently armed
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch that throws a NON-std exception faults, never escapes "
          "start()",
          "[spark][mechanism]") {
    // Replay-path twin of the catch(...) coverage: the live-path test above proves
    // watch_guarded()'s catch(...) arm on arm(); this proves the SAME boundary on
    // the pre-start replay in start(). A non-std throw (`throw 42;`) must fault in
    // place (subscribers hold ids → no rollback) and never propagate out of the
    // void start().
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_throw_watch_nonstd(true);        // the start() replay watch will throw a non-std type

    REQUIRE_NOTHROW(engine.start());           // non-std throw is caught, not propagated
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …flagged deaf
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("Mechanism fault channel: fault flags health on the transition, recovery clears it (B1)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(engine.stats().armed_faulted == 0);

    fake->fire_fault(key, true, "watch died after arm");
    CHECK(engine.stats().armed_faulted == 1);
    CHECK(engine.stats().watch_faults_total == 1);
    // Re-reporting the same faulted state is a no-op edge — the counter is a
    // transition count, not a per-report count.
    fake->fire_fault(key, true, "still dead");
    CHECK(engine.stats().watch_faults_total == 1);

    fake->fire_fault(key, false, "recovered");
    CHECK(engine.stats().armed_faulted == 0);
    CHECK(engine.stats().watch_faults_total == 1); // recovery does not bump the fault counter
    // A fault for an unknown/disarmed key is ignored (no crash, no drift).
    fake->fire_fault("registry|nope", true, "ghost");
    CHECK(engine.stats().armed_faulted == 0);
    engine.stop();
}

TEST_CASE("Service spark: fire carries ServiceSparkData through the queued tier",
          "[spark][mechanism]") {
    // Unlike File/Registry (monostate — consumer re-reads), Service carries the
    // resolved terminal state. Prove it survives the engine's snapshot/fan-out
    // copy (emit_event copies SparkData by value into each subscriber's queue).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Running}});
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const SparkEvent ev = got.at(0);
    CHECK(ev.key == key);
    CHECK(ev.type == SparkType::Service);
    REQUIRE(std::holds_alternative<ServiceSparkData>(ev.data));
    CHECK(std::get<ServiceSparkData>(ev.data).state == ServiceRunState::Running);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Paused}});
    REQUIRE(eventually([&] { return got.count() >= 2; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state == ServiceRunState::Paused);
    engine.stop();
}

TEST_CASE("Service spark: arm-before-start is replayed to the mechanism at start()",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK_FALSE(fake->is_watching(key)); // not watched until the engine starts
    CHECK(fake->watch_calls() == 0);

    engine.start();
    CHECK(eventually([&] { return fake->is_watching(key); })); // start() replays the watch
    CHECK(fake->watch_calls() == 1);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Running}});
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
}

TEST_CASE("Service spark: equal specs dedup to one watch, fan out to all subscribers",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector a, b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*ca, spec).has_value());
    REQUIRE(engine.arm(*cb, spec).has_value());
    CHECK(fake->watch_calls() == 1); // dedup: N subscriptions, 1 watcher
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 2);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Stopped}});
    REQUIRE(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    CHECK(a.at(0).seq == b.at(0).seq); // one fire, one seq, both observe it
    engine.stop();
}

TEST_CASE("Mechanism emit path does not deadlock an inline re-arm (TRAP 2)", "[spark][mechanism]") {
    // An inline consumer that re-arms from inside its handler must not deadlock:
    // emit_event snapshots + releases mu_ before delivering, and arm takes mu_.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    std::atomic<bool> rearmed{false};
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);

    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent&) {
        // Re-enter the engine from inside the (inline) delivery.
        auto c = engine.register_consumer("late", [](const SparkEvent&) {});
        if (c)
            rearmed.store(engine.arm(*c, SparkSpec{SparkType::Interval, IntervalSparkParams{50}})
                              .has_value());
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    fake->fire(key); // drives the inline handler synchronously on this thread
    CHECK(eventually([&] { return rearmed.load(); }));
    engine.stop();
}

TEST_CASE("Service spark emit path does not deadlock an inline re-arm (TRAP 2 twin)",
          "[spark][mechanism]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    std::atomic<bool> rearmed{false};
    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);

    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent&) {
        auto c = engine.register_consumer("late-svc", [](const SparkEvent&) {});
        if (c)
            rearmed.store(engine.arm(*c, SparkSpec{SparkType::Interval, IntervalSparkParams{50}})
                              .has_value());
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Stopped}});
    CHECK(eventually([&] { return rearmed.load(); }));
    engine.stop();
}

TEST_CASE("SparkEngine: a queued handler re-entering the engine while stop() is inside "
          "mechanism teardown does not deadlock (#1934 UP-1/F4)",
          "[spark][mechanism]") {
    // Pins the property this whole mechanism-call seam depends on:
    // SparkEngine::stop() calls a mechanism's stop() with NO engine lock held
    // (mu_ / consumers_mu_ / every mech_ops_mu_by_type_ entry all released — see
    // stop()'s step 2).
    // A QUEUED handler already dispatched before stop() began may therefore
    // safely call back into the engine (arm/disarm) WHILE stop() is stuck
    // inside a slow mechanism teardown: the re-entrant call must fail cleanly
    // (the engine is stopping) rather than deadlock waiting for a lock stop()
    // is (incorrectly, in a regression) still holding.
    SparkEngine engine;
    auto mech = std::make_unique<BlockingStopMechanism>();
    BlockingStopMechanism* bm = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());

    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool handler_fired{false};
        bool reentry_done{false};
        std::atomic<bool> reentrant_arm_rejected{false};
    };
    auto sync = std::make_shared<Sync>();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto consumer = engine.register_consumer("c", [&engine, bm, sync](const SparkEvent&) {
        {
            std::lock_guard lk(sync->m);
            sync->handler_fired = true;
        }
        sync->cv.notify_all();
        // Wait until stop() is actually inside the mechanism teardown before
        // re-entering — otherwise this races stop()'s own step 1 instead of
        // exercising step 2's no-lock-held property.
        while (!bm->stopping_now())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        auto sub2 = engine.arm_inline(SparkSpec{SparkType::Interval, IntervalSparkParams{60'000}},
                                       [](const SparkEvent&) {});
        sync->reentrant_arm_rejected.store(!sub2.has_value());
        {
            std::lock_guard lk(sync->m);
            sync->reentry_done = true;
        }
        sync->cv.notify_all();
        bm->release(); // let stop()'s mechanism teardown — and stop() itself — finish
    });
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, spec).has_value());
    engine.start();

    bm->fire(key);
    {
        std::unique_lock lk(sync->m);
        sync->cv.wait(lk, [&] { return sync->handler_fired; });
    }

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop(); // must return once the handler releases the gate, not hang
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(elapsed < 5000ms);
    {
        std::lock_guard lk(sync->m);
        CHECK(sync->reentry_done);
    }
    CHECK(sync->reentrant_arm_rejected.load()); // failed cleanly, never hung
}

// ── #2815: the teardown barrier ───────────────────────────────────────────────
//
// SparkEngine has FOUR call sites that resolve a raw `ISparkMechanism*` (and this
// engine's `mech_ops_mu_by_type_` entry) under mu_, then RELEASE mu_ and call into the
// mechanism: disarm(), teardown_arm_race(), unregister_consumer() and the live arm path
// in arm_impl(). Before this fix, stop() waited on NONE of them — it flipped
// running_/stopped_, joined the wheel, and went straight on to tear the mechanisms down
// while a caller could still be parked inside that window.
//
// Two consequences, one benign and one not:
//   * BENIGN, and cross-platform observable: the parked caller's unwatch() lands on a
//     mechanism the engine has already stopped (FakeMechanism::unwatch_calls_after_stop).
//   * MALIGN, and the actual defect: nothing else ever waits either, so ~SparkEngine can
//     free the engine out from under that same parked caller, which then dereferences
//     mech_ops_mu_by_type_ on freed memory (Scenario B, under ASan).
//
// The fix is an engine-local lease: each of the four doors arms a function-scoped lease
// as the last statement of the SAME mu_ block that resolves `mech`, and holds it for the
// whole rest of the function. stop() waits on the lease BOUNDED (a determinism nicety —
// it proceeds on expiry and counts teardown_join_timeouts_total); ~SparkEngine waits
// UNBOUNDED, which is what actually closes the use-after-free.
//
// Why a lease is sufficient — i.e. why no NEW caller can slip in behind stop(): all four
// doors gate their own entry on running_/stopped_ under mu_ BEFORE they resolve `mech`,
// so once stop()'s early locked block has flipped both flags, a later caller resolves no
// mechanism and arms no lease. The lease therefore counts exactly the callers already in
// flight at that instant.

TEST_CASE("#2815 door 1/4 — stop() waits for an in-flight disarm() teardown",
          "[spark][mechanism][teardown][tsan]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(sub.has_value());

    ParkGate gate;
    // The disarm race hook fires with NO locks held, after mu_ is released and before
    // the mech-ops lock — exactly inside the window this case is about.
    engine.set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g; // read the capture ONCE, before parking (see ParkGate's doc)
        local->park();
    });

    std::thread disarmer([&] { engine.disarm(*sub); });
    // stopper AND stop_returned are hoisted here, BEFORE guard, so guard is the
    // LAST-declared and destructs FIRST on any unwind. Both matter: a std::thread
    // declared after the guard would destruct before it (reverse declaration order)
    // and terminate() if still joinable when the guard never gets a chance to join it;
    // an atomic the thread's body writes to would be destroyed out from under a still-
    // running thread for the identical reason if it were declared after the guard too
    // (governance Gate 8 finding, security-guardian + quality-engineer independently;
    // the atomic half caught on advisor review of the first fix).
    std::thread stopper;
    std::atomic<bool> stop_returned{false};
    ThreadJoinGuard guard{&gate};
    guard.track(disarmer);
    guard.track(stopper);
    REQUIRE(gate.wait_entered());

    stopper = std::thread([&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    });

    // PRE-FIX this is TRUE within a millisecond or two: stop() takes lifecycle_mu_,
    // flips the flags, joins the wheel and tears the mechanisms down without ever
    // looking at the parked caller. POST-FIX the lease holds it here.
    // 300 ms is well inside stop()'s bounded wait (the default 2 s budget), so a
    // post-fix PASS here means "still waiting", never "already timed out".
    CHECK_FALSE(became_true_within(stop_returned, 300ms));

    gate.release();
    disarmer.join();
    stopper.join();
    CHECK(stop_returned.load());

    // The barrier's point: the unwatch reaches a mechanism that is still LIVE.
    CHECK(fake->unwatch_calls() == 1);
    CHECK(fake->unwatch_calls_after_stop() == 0);
    CHECK(engine.stats().teardown_join_timeouts_total == 0); // released inside the budget
}

TEST_CASE("#2815 door 2/4 — stop() waits for an in-flight consumer-race teardown",
          "[spark][mechanism][teardown][tsan]") {
    // teardown_arm_race(): arm_impl loses the M1 consumer race and unwinds its own
    // subscription, taking the same post-mu_ mechanism call as disarm(). Driven the way
    // the existing #2270 cases drive it — unregister from the arm PRE-CHECK hook, so the
    // teardown's real-work branch (including the OS unwatch) is the one that runs.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    ParkGate gate;
    engine.set_arm_precheck_race_hook_for_test([&] { engine.unregister_consumer(*c); });
    engine.set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });

    std::thread armer([&] { (void)engine.arm(*c, file_spec("/etc/hosts")); });
    // stopper AND stop_returned hoisted before guard — see door 1/4's comment on why.
    std::thread stopper;
    std::atomic<bool> stop_returned{false};
    ThreadJoinGuard guard{&gate};
    guard.track(armer);
    guard.track(stopper);
    REQUIRE(gate.wait_entered());

    stopper = std::thread([&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    });
    CHECK_FALSE(became_true_within(stop_returned, 300ms));

    gate.release();
    armer.join();
    stopper.join();
    CHECK(stop_returned.load());
    CHECK(fake->unwatch_calls() == 1);
    CHECK(fake->unwatch_calls_after_stop() == 0);
}

TEST_CASE("#2815 door 3/4 — stop() waits for an in-flight unregister_consumer() teardown",
          "[spark][mechanism][teardown][tsan]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    REQUIRE(engine.arm(*c, file_spec("/etc/hosts")).has_value());

    ParkGate gate;
    engine.set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });

    std::thread dropper([&] { engine.unregister_consumer(*c); });
    // stopper AND stop_returned hoisted before guard — see door 1/4's comment on why.
    std::thread stopper;
    std::atomic<bool> stop_returned{false};
    ThreadJoinGuard guard{&gate};
    guard.track(dropper);
    guard.track(stopper);
    REQUIRE(gate.wait_entered());

    stopper = std::thread([&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    });
    CHECK_FALSE(became_true_within(stop_returned, 300ms));

    gate.release();
    dropper.join();
    stopper.join();
    CHECK(stop_returned.load());
    CHECK(fake->unwatch_calls() == 1);
    CHECK(fake->unwatch_calls_after_stop() == 0);
}

TEST_CASE("#2815 door 4/4 — stop() waits for an in-flight arm_impl() watch call",
          "[spark][mechanism][teardown][tsan]") {
    // The door the original design missed. arm_impl resolves `mech` under mu_, releases
    // mu_, takes this type's mech-ops lock and calls watch_guarded() — retaining the raw
    // mechanism pointer across exactly the same window the three teardown doors do.
    // Parked here via the watch-error fault phase, which fires inside watch_guarded's
    // catch with the mech-ops lock held and mu_ NOT held (so stop()'s wait, which takes
    // neither, cannot deadlock against it).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    ParkGate gate;
    fake->set_throw_watch(true);
    engine.set_arm_fault_hook_for_test([g = &gate](int phase) {
        if (phase != SparkEngine::kArmFaultPhaseWatchErrorBuild)
            return;
        ParkGate* local = g;
        local->park();
    });

    std::expected<SparkEngine::SubscriptionId, std::string> armed;
    std::thread armer([&] { armed = engine.arm(*c, file_spec("/etc/hosts")); });
    // stopper AND stop_returned hoisted before guard — see door 1/4's comment on why.
    std::thread stopper;
    std::atomic<bool> stop_returned{false};
    ThreadJoinGuard guard{&gate};
    guard.track(armer);
    guard.track(stopper);
    REQUIRE(gate.wait_entered());

    stopper = std::thread([&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    });
    CHECK_FALSE(became_true_within(stop_returned, 300ms));

    gate.release();
    armer.join();
    stopper.join();
    CHECK(stop_returned.load());
    CHECK(fake->watch_calls() == 1);
    CHECK_FALSE(armed.has_value()); // the throwing watch still fails cleanly
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("#2815 — a DEDUP arm (mech stays null) is still leased before its M1 tail reads "
          "consumers_mu_/consumers_",
          "[spark][mechanism][teardown]") {
    // Adversarial-review finding (K1/kimi, C2-1/codex, both independently confirmed and
    // cross-examined BLOCK): door 4/4's own test above only exercises the NEWLY-INSERTED,
    // mech-resolved shape. A DEDUP arm — a second Queued-tier consumer sharing an
    // already-armed key — never sets `mech`, so pre-fix `if (mech) lease.arm_locked();`
    // left this call's tail (the M1 consumer-race re-check, which locks consumers_mu_ and
    // reads consumers_) with no lease at all. `~SparkEngine`'s unbounded wait keys solely
    // on the lease count, saw zero, and could free consumers_mu_/consumers_ while this
    // caller was still about to touch them — the same UAF class as door 4, just without a
    // blocking mechanism call in the window. Fixed by arming unconditionally (matching
    // door 3's unregister_consumer, which has the identical "tail touches engine members
    // regardless of mech" shape). `arm_race_hook_for_test_` is the right injection point:
    // it fires after the (skipped, since mech is null) watch block and before the M1
    // re-check, on every arm_impl call regardless of whether mech was resolved.
    auto engine = std::make_unique<SparkEngine>();
    // Default (2s) budget deliberately NOT squeezed: this test's point is that BOTH
    // stop()'s bounded wait and ~SparkEngine's unbounded wait block on this call's lease,
    // so consumers_ stays intact (no M1-race error) the whole time this thread is parked —
    // a squeezed budget would let stop() proceed to its own consumer-swap step first and
    // conflate that (benign, already-handled) race with the property under test here.
    wire_fake(*engine, SparkType::File);
    auto c1 = engine->register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine->start();
    auto first = engine->arm(*c1, file_spec("/etc/hosts")); // mech resolved, real watch armed
    REQUIRE(first.has_value());

    auto c2 = engine->register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c2.has_value());

    ParkGate gate;
    engine->set_arm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });

    std::expected<SparkEngine::SubscriptionId, std::string> deduped;
    SparkEngine* raw = engine.get();
    std::thread armer([&] { deduped = raw->arm(*c2, file_spec("/etc/hosts")); }); // DEDUP: mech stays null
    // killer AND destroyed hoisted before guard — see door 1/4's comment on why.
    std::thread killer;
    std::atomic<bool> destroyed{false};
    ThreadJoinGuard guard{&gate};
    guard.track(armer);
    guard.track(killer);
    REQUIRE(gate.wait_entered());

    killer = std::thread([&] {
        engine->stop();
        engine.reset(); // ~SparkEngine — must NOT free consumers_mu_/consumers_ while `armer` is parked
        destroyed.store(true, std::memory_order_release);
    });

    CHECK_FALSE(became_true_within(destroyed, 300ms));

    gate.release();
    armer.join();
    killer.join();
    CHECK(destroyed.load());
    CHECK(deduped.has_value()); // the dedup itself still succeeds; only the tail was racing
}

TEST_CASE("#2815 — ~SparkEngine waits UNBOUNDED for an in-flight teardown before freeing "
          "the members that caller still holds",
          "[spark][mechanism][teardown]") {
    // Scenario B: the actual use-after-free, and the reason stop()'s BOUNDED wait is a
    // nicety rather than the fix. Pre-fix, the parked disarm() resumes into
    // `mech_ops_mu_by_type_.at(type)` on an engine that has already been destroyed —
    // ASan reports heap-use-after-free on the engine allocation. Post-fix the destructor
    // blocks until the lease drains, so the resumed caller finds every member alive.
    //
    // The budget is squeezed to 50 ms deliberately: stop()'s bounded wait then EXPIRES
    // while the caller is still parked, which is exactly the state in which only the
    // destructor's unbounded wait can prevent the free. If this case passes with a short
    // budget, the destructor — not stop() — is what is holding the line.
    auto engine = std::make_unique<SparkEngine>();
    wire_fake(*engine, SparkType::File);
    engine->set_consumer_join_budget_for_test(50);
    auto c = engine->register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine->start();
    auto sub = engine->arm(*c, file_spec("/etc/hosts"));
    REQUIRE(sub.has_value());
    const auto sub_id = *sub;

    ParkGate gate;
    engine->set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });

    SparkEngine* raw = engine.get();
    std::thread disarmer([raw, sub_id] { raw->disarm(sub_id); });
    // killer AND destroyed hoisted before guard — see door 1/4's comment on why.
    std::thread killer;
    std::atomic<bool> destroyed{false};
    ThreadJoinGuard guard{&gate};
    guard.track(disarmer);
    guard.track(killer);
    REQUIRE(gate.wait_entered());
    killer = std::thread([&] {
        engine->stop();
        engine.reset(); // ~SparkEngine — must NOT free while `disarmer` is parked
        destroyed.store(true, std::memory_order_release);
    });

    CHECK_FALSE(became_true_within(destroyed, 300ms));

    gate.release();
    disarmer.join();
    killer.join();
    CHECK(destroyed.load());
}

TEST_CASE("#2815 — stop()'s teardown wait is BOUNDED and counts its own expiry",
          "[spark][mechanism][teardown]") {
    // NOT A RED-FIRST CASE, and it is not offered as one: teardown_join_timeouts_total
    // is introduced BY this fix, so there is no pre-fix meaning to fail. It pins the
    // deliberate second half of the design — stop() must never become a place an agent
    // shutdown can hang, so it gives up after the budget, counts, and proceeds.
    //
    // It also pins the honest cost of proceeding: past the expiry the benign half of the
    // window is genuinely reopened, and the late unwatch DOES land on a stopped
    // mechanism. Only the destructor's unbounded wait closes the malign half.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    engine.set_consumer_join_budget_for_test(50);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(sub.has_value());

    ParkGate gate;
    engine.set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });
    std::thread disarmer([&] { engine.disarm(*sub); });
    ThreadJoinGuard guard{&gate};
    guard.track(disarmer);
    REQUIRE(gate.wait_entered());

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop(); // returns despite the parked caller — bounded, never a hang
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 5000ms);
    CHECK(engine.stats().teardown_join_timeouts_total == 1);

    gate.release();
    disarmer.join();
    // Proceeding past the expiry is not free: the late unwatch reached a stopped
    // mechanism. Recorded, not lamented — the alternative is hanging shutdown.
    CHECK(fake->unwatch_calls_after_stop() == 1);
    // ~SparkEngine still runs its UNBOUNDED wait here; the lease is already drained.
}

// ── #2833: the unwatch-failure counters are unreachable in the shutdown window ──
//
// DISPOSITION: CONFIRMED, and accepted. Not fixed here, and deliberately so — the gap is
// DOMINATED by a stronger, entirely intentional gate one layer up, so "fixing" the spark
// layer would change nothing on the wire.
//
// The case below pins both halves of that claim so a future reader does not have to
// re-derive it, and so the day someone DOES want this egress they find out immediately
// that spark_heartbeat.hpp is not where the problem is.

TEST_CASE("#2833 — a shutdown-window unwatch failure is counted but has NO heartbeat egress",
          "[spark][mechanism][teardown]") {
    // Drive the exact production shape: a disarm parked inside its post-mu_ window while
    // stop() runs, whose mechanism unwatch() then throws. Post-#2815 stop() waits on the
    // teardown lease, so the parked disarm genuinely runs its unwatch() against a
    // still-live mechanism — the counter increments on the real path, not a simulated one.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    REQUIRE(sub.has_value());

    ParkGate gate;
    fake->set_throw_unwatch(true);
    engine.set_disarm_race_hook_for_test([g = &gate] {
        ParkGate* local = g;
        local->park();
    });
    std::thread disarmer([&] { engine.disarm(*sub); });
    // stopper hoisted before guard — see door 1/4's comment on why (Gate 8 finding).
    std::thread stopper;
    ThreadJoinGuard guard{&gate};
    guard.track(disarmer);
    guard.track(stopper);
    REQUIRE(gate.wait_entered());

    stopper = std::thread([&] { engine.stop(); });
    gate.release();
    disarmer.join();
    stopper.join();

    // Half one: the failure DID happen and IS counted.
    const auto ss = engine.stats();
    CHECK(ss.disarm_unwatch_failures_total == 1);
    CHECK(ss.arm_race_unwatch_failures_total == 0); // still scoped to its own path

    // Half two: and it has no route off the box. emit_spark_heartbeat_tags() is called
    // with is_running(), which stop() has already set false, so it takes the ABSENT
    // posture and emits NOTHING AT ALL — not "the tag is zero", not "the tag is absent
    // because it is sparse": no tags whatsoever.
    std::map<std::string, std::string> tags;
    emit_spark_heartbeat_tags(tags, engine.is_running(), ss, engine.stats_by_type());
    CHECK_FALSE(engine.is_running());
    CHECK(tags.empty());

    // THE TAG ITSELF IS FINE — that is the point. Feed the same stats in with running=true
    // and the egress works perfectly. So the gap is NOT a missing tag in
    // spark_heartbeat.hpp, and adding one there fixes nothing.
    std::map<std::string, std::string> live_tags;
    emit_spark_heartbeat_tags(live_tags, /*running=*/true, ss, engine.stats_by_type());
    CHECK(live_tags.at("yuzu.spark_disarm_unwatch_failures") == "1");

    // AND THE DOMINATING GATE IS HIGHER STILL, which is why this disposition does not
    // depend on the engine's own running_ flag at all: agent.cpp:2552 emits NOTHING once
    // stop_requested_ is set (agent.cpp:3281), and both shutdown paths stop spark AFTER
    // that flag and BEFORE joining the heartbeat thread (agent.cpp:1085/3315 vs
    // 3095/3744). So even an engine that somehow still reported running_ during teardown
    // would compose a beat nobody sends. A change to spark_heartbeat.hpp is inert on the
    // wire; the gate that would have to move is the agent's, and it is there on purpose
    // (STOPPED is not FAILED — a cleanly-stopping agent must not page on-call).
    //
    // OPERATOR CONSEQUENCE, stated plainly because it is the part that matters: a zero
    // reading for either unwatch-failure tag during a shutdown is NOT evidence that
    // nothing was orphaned. The only egress for these increments in that window is the
    // spdlog::error at each increment site (spark_engine.cpp, disarm() and
    // teardown_arm_race()) — the agent journal, not the fleet metrics.
}

// ── #2818: a dedup sibling's watch death is now delivered ─────────────────────
//
// FIXED. drop_key_locked's sole call site (arm_impl's failed-watch teardown) now
// snapshots every live subscriber before erasing the key's bookkeeping and delivers a
// SparkEventKind::Lost through the same Inline/Queued channel an ordinary fire uses - no
// new registration surface. See report_fault's paired fix below for the milder
// Faulted/Recovered (B1) edge.

TEST_CASE("#2818 — a deduped sibling is notified when another consumer's failed watch "
          "kills their shared key",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector ca;
    Collector cb;
    auto a = engine.register_consumer("a", ca.handler());
    auto b = engine.register_consumer("b", cb.handler());
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);

    // A arms K and is parked INSIDE watch_guarded's catch — i.e. after its watch has
    // definitively failed but before arm_impl has run the teardown. That is the window in
    // which B's arm must be allowed to succeed for the defect this pins to be reachable.
    ParkGate gate;
    fake->set_throw_watch(true);
    engine.set_arm_fault_hook_for_test([g = &gate](int phase) {
        if (phase != SparkEngine::kArmFaultPhaseWatchErrorBuild)
            return;
        ParkGate* local = g;
        local->park();
    });

    std::expected<SparkEngine::SubscriptionId, std::string> a_sub;
    std::thread armer_a([&] { a_sub = engine.arm(*a, spec); });
    ThreadJoinGuard guard{&gate};
    guard.track(armer_a);
    REQUIRE(gate.wait_entered());

    // B arms the SAME spec while A's watch is in flight. It dedups onto A's committed
    // armed_ entry and is handed a real SubscriptionId.
    auto b_sub = engine.arm(*b, spec);
    REQUIRE(b_sub.has_value());
    CHECK(engine.stats().subscriptions == 2); // both live, as far as anyone can see

    gate.release();
    armer_a.join();

    // A learns its arm failed synchronously. That part was always correct.
    CHECK_FALSE(a_sub.has_value());

    const auto ss = engine.stats();
    CHECK(ss.armed_sparks == 0);
    CHECK(ss.subscriptions == 0); // both ids now name nothing
    CHECK(ss.subscription_lost_total == 1);

    // B — the dedup sibling — is notified async, via the exact channel it registered.
    REQUIRE(eventually([&] { return cb.count() >= 1; }));
    const auto lost_b = cb.at(0);
    CHECK(lost_b.kind == SparkEventKind::Lost);
    CHECK(lost_b.key == key);
    CHECK(lost_b.subscription_id == *b_sub);

    // A gets the same notification too — nothing in Armed::subs distinguishes "the
    // failing caller" from a dedup sibling, and there is no value in adding a field just
    // to suppress a harmless duplicate signal to the one consumer who already knows. A's
    // own arm() call returned an error (a_sub has no value), so its subscription_id is
    // only observable here, via the delivered event.
    REQUIRE(eventually([&] { return ca.count() >= 1; }));
    const auto lost_a = ca.at(0);
    CHECK(lost_a.kind == SparkEventKind::Lost);
    CHECK(lost_a.key == key);
    CHECK(lost_a.subscription_id != 0);
    CHECK(lost_a.subscription_id != lost_b.subscription_id);

    // The defensive unwatch() this fix also adds is a safe no-op here (the mechanism's
    // own watch() never actually registered anything before throwing).
    CHECK(fake->unwatch_calls() == 1);

    // The id B still holds is inert in both directions. Disarming it is a silent no-op
    // (correct, and deliberately kept that way — see #3816's coordination note)...
    CHECK_NOTHROW(engine.disarm(*b_sub));
    // ...and a fire on the key it named reaches nobody and is not even counted, because
    // emit_event finds no armed_ entry and returns before events_total_ — and does NOT
    // produce a second Lost delivery (there is nothing left to notify).
    fake->fire(key);
    CHECK(engine.stats().events_total == 0);
    CHECK(cb.count() == 1);

    engine.set_arm_fault_hook_for_test(nullptr);
    fake->set_throw_watch(false);
    engine.stop();
}

TEST_CASE("#2818 — a post-arm watch fault now reaches the consumer",
          "[spark][mechanism]") {
    // The second, milder face of the same channel. Here the arm SUCCEEDS and the
    // mechanism later reports the watch deaf (B1). The engine still records the edge,
    // flags the spark and bumps the existing counters — unchanged — but now the consumer
    // that asked for this spark is ALSO told, via a SparkEventKind::Faulted/Recovered
    // pair, instead of having to poll stats() to learn its subscription degraded.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector col;
    auto c = engine.register_consumer("c", col.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());

    fake->fire_fault(key, true, "handle went deaf");
    const auto ss = engine.stats();
    CHECK(ss.watch_faults_total == 1);
    CHECK(ss.armed_faulted == 1);
    CHECK(ss.armed_sparks == 1);  // still armed…
    CHECK(ss.subscriptions == 1); // …and still subscribed…

    REQUIRE(eventually([&] { return col.count() >= 1; }));
    const auto faulted_ev = col.at(0);
    CHECK(faulted_ev.kind == SparkEventKind::Faulted);
    CHECK(faulted_ev.key == key);
    CHECK(faulted_ev.subscription_id == *sub);
    CHECK(faulted_ev.detail == "handle went deaf");

    // Recovery is delivered too, so a consumer no longer has to infer state by
    // inversion (or poll stats()).
    fake->fire_fault(key, false, "recovered");
    CHECK(engine.stats().armed_faulted == 0);
    CHECK(engine.stats().watch_faults_total == 1); // monotonic, edge-counted

    REQUIRE(eventually([&] { return col.count() >= 2; }));
    const auto recovered_ev = col.at(1);
    CHECK(recovered_ev.kind == SparkEventKind::Recovered);
    CHECK(recovered_ev.key == key);
    CHECK(recovered_ev.subscription_id == *sub);
    CHECK(recovered_ev.detail == "recovered");
    engine.stop();
}

TEST_CASE("#2818: subscription_health() reports Dead/Faulted/Healthy directly (quality-engineer "
          "Gate 3 finding - the query itself was untested)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    CHECK(engine.subscription_health(*sub) == SubscriptionHealth::Healthy);

    fake->fire_fault(key, true, "handle went deaf");
    CHECK(engine.subscription_health(*sub) == SubscriptionHealth::Faulted);

    fake->fire_fault(key, false, "recovered");
    CHECK(engine.subscription_health(*sub) == SubscriptionHealth::Healthy);

    engine.disarm(*sub);
    CHECK(engine.subscription_health(*sub) == SubscriptionHealth::Dead);
    // An id that never existed at all reports Dead too - the query has no separate
    // "unknown id" state, by design (SubscriptionHealth's own doc comment).
    CHECK(engine.subscription_health(*sub + 1'000'000) == SubscriptionHealth::Dead);
    engine.stop();
}

TEST_CASE("#2839 seam — set_file_retire_fault_hook_for_test refuses a non-file mechanism",
          "[spark][mechanism]") {
    // The seam's failure contract, pinned on EVERY platform (the injection case itself is
    // Windows-only, below). It returns bool rather than void precisely so a caller cannot
    // silently install a hook on the wrong mechanism and then conclude from a green run
    // that the fault path was exercised — which, since the hook would never fire, is the
    // false-green this assertion exists to prevent.
    FakeMechanism fake;
    CHECK_FALSE(set_file_retire_fault_hook_for_test(fake, [] {}));

    // And on a platform with no file mechanism at all there is nothing to hook, so the
    // Windows case below is correctly skipped rather than silently vacuous.
    auto file = make_file_mechanism();
#ifdef _WIN32
    REQUIRE(file);
    CHECK(set_file_retire_fault_hook_for_test(*file, nullptr)); // real mechanism, hook cleared
#else
    CHECK(file == nullptr);
#endif
}

TEST_CASE("platform factories honor the mechanism-or-null contract", "[spark][mechanism]") {
#ifdef _WIN32
    CHECK(make_file_mechanism() != nullptr);
    CHECK(make_registry_mechanism() != nullptr);
    CHECK(make_service_mechanism() != nullptr);
#else
    CHECK(make_file_mechanism() == nullptr);     // off Windows → no mechanism → arm() rejects
    CHECK(make_registry_mechanism() == nullptr);
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
    CHECK(make_service_mechanism() != nullptr);  // Linux + libsystemd → real sd-bus mechanism
#else
    CHECK(make_service_mechanism() == nullptr);  // macOS, or Linux built without libsystemd
#endif
#endif
}

// ── rung 9c PR-6 item 1: the establishment signal (SparkIncarnation /
//    SparkCoverage / SubscriptionEstablishment), engine-level plumbing.
//    Cross-platform (FakeMechanism); the real-mechanism M1-M6 cases live
//    further down, alongside the existing Linux/Windows smoke sections they
//    extend. ──────────────────────────────────────────────────────────────

TEST_CASE("Establishment: a fresh arm mints a real incarnation; dedup shares it, no second "
          "watch call (E1)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    auto est1 = engine.subscription_establishment(*sub1);
    REQUIRE(est1.has_value());
    CHECK(est1->coverage == SparkCoverage::None); // nothing reported yet
    CHECK_FALSE(est1->established_at.has_value());
    REQUIRE(fake->tokens(key).size() == 1);

    // Dedup: a second subscriber to the SAME spec shares the existing
    // watcher — no second watch_incarnation() call, same incarnation.
    auto sub2 = engine.arm(*c2, spec);
    REQUIRE(sub2.has_value());
    CHECK(fake->tokens(key).size() == 1); // still just one — no second watch call
    auto est2 = engine.subscription_establishment(*sub2);
    REQUIRE(est2.has_value());
    CHECK(est2->armed_at == est1->armed_at); // same Armed entry

    engine.stop();
}

TEST_CASE("Establishment: report_established assigns coverage unconditionally and stamps "
          "established_at first-wins (E2, mutation-verified)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    REQUIRE(fake->tokens(key).size() == 1);
    const SparkIncarnation inc = fake->tokens(key).front();

    // Poll: coverage assigned, established_at stays unset (never stamped by
    // anything but Notification).
    fake->fire_established(key, inc, std::chrono::steady_clock::now(), SparkCoverage::Poll);
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Poll);
    CHECK_FALSE(est->established_at.has_value());

    // Notification: coverage assigned, established_at stamps for the first time.
    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at == t1);

    // A second, LATER Notification does NOT move established_at (first-wins).
    const auto t2 = t1 + std::chrono::milliseconds(50);
    fake->fire_established(key, inc, t2, SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == t1); // unchanged

    engine.stop();
}

TEST_CASE("Establishment: subscription_establishment is nullopt for an unknown or "
          "torn-down id (E3)",
          "[spark][established]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    auto sub = engine.arm(*c1, service_spec("svc1"));
    REQUIRE(sub.has_value());
    // Mirrors subscription_health()'s own "unknown id" pin.
    CHECK_FALSE(engine.subscription_establishment(*sub + 1'000'000).has_value());
    engine.disarm(*sub);
    CHECK_FALSE(engine.subscription_establishment(*sub).has_value());
    engine.stop();
}

TEST_CASE("Establishment: a report against a superseded incarnation is dropped by IDENTITY, "
          "not by timestamp ordering (E4, mutation-verified)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(fake->tokens(key).size() == 1);
    const SparkIncarnation old_inc = fake->tokens(key)[0];

    engine.disarm(*sub1);
    auto sub2 = engine.arm(*c1, spec); // fully torn down + re-armed -> fresh incarnation
    REQUIRE(sub2.has_value());
    REQUIRE(fake->tokens(key).size() == 2);
    const SparkIncarnation new_inc = fake->tokens(key)[1];
    CHECK(new_inc != old_inc);

    // Stale report, timestamped an hour in the FUTURE — a time-ordering check
    // would accept this over anything already recorded; an identity check
    // must reject it regardless of its timestamp.
    const auto future = std::chrono::steady_clock::now() + std::chrono::hours(1);
    fake->fire_established(key, old_inc, future, SparkCoverage::Notification);

    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None); // untouched by the stale report
    CHECK_FALSE(est->established_at.has_value());

    // A report against the CURRENT incarnation still works normally.
    fake->fire_established(key, new_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);
    CHECK(est->established_at.has_value());

    engine.stop();
}

TEST_CASE("Establishment: a dedup arm shares the existing key's incarnation and armed_at "
          "(E5)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    auto sub2 = engine.arm(*c2, spec);
    REQUIRE(sub2.has_value());
    REQUIRE(fake->tokens(key).size() == 1); // one watch_incarnation() call for both

    const SparkIncarnation inc = fake->tokens(key).front();
    fake->fire_established(key, inc, std::chrono::steady_clock::now(), SparkCoverage::Notification);
    auto est1 = engine.subscription_establishment(*sub1);
    auto est2 = engine.subscription_establishment(*sub2);
    REQUIRE(est1.has_value());
    REQUIRE(est2.has_value());
    CHECK(est1->armed_at == est2->armed_at);
    CHECK(est1->coverage == est2->coverage);
    CHECK(est1->established_at == est2->established_at);

    engine.stop();
}

TEST_CASE("Establishment: armed_at is stamped at ARM time, even for a pre-start arm (E6/H14)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    // Deliberately NOT started yet.
    const auto before = std::chrono::steady_clock::now();
    auto sub = engine.arm(*c1, service_spec("svc1"));
    const auto after = std::chrono::steady_clock::now();
    REQUIRE(sub.has_value());
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->armed_at >= before);
    CHECK(est->armed_at <= after);
    CHECK(fake->watch_calls() == 0); // not started yet — no live watch call
    engine.start(); // replay runs now
    CHECK(fake->watch_calls() == 1);
    engine.stop();
}

TEST_CASE("Establishment: a fault-then-recovery cycle does not move established_at (E7)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    const SparkIncarnation inc = fake->tokens(key).front();

    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at == t1);

    // Coverage drops to None (a fault/teardown) then RECOVERS to Notification
    // — spark.hpp's SubscriptionEstablishment doc comment: established_at is
    // a historical fact, not a live status.
    fake->fire_established(key, inc, t1 + std::chrono::milliseconds(10), SparkCoverage::None);
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK(*est->established_at == t1); // still the original stamp

    const auto t2 = t1 + std::chrono::milliseconds(20);
    fake->fire_established(key, inc, t2, SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);
    CHECK(*est->established_at == t1); // STILL the original — recovery does not re-stamp

    engine.stop();
}

TEST_CASE("Establishment: a timer-driven spark's coverage/established_at stay at their "
          "defaults forever — the field is inert off the event-driven path (E8)",
          "[spark][established]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(1); // ms — let the interval fire quickly
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    auto sub = engine.arm(*c1, interval_spec(5));
    REQUIRE(sub.has_value());
    std::this_thread::sleep_for(50ms); // let it fire a few times
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());
    engine.stop();
}

TEST_CASE("Establishment: after stop(), the query returns last-known values, like "
          "subscription_health (E9/R4)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    const SparkIncarnation inc = fake->tokens(key).front();
    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);
    {
        auto pre = engine.subscription_establishment(*sub);
        REQUIRE(pre.has_value());
        REQUIRE(pre->coverage == SparkCoverage::Notification);
    }

    engine.stop();
    CHECK_FALSE(engine.is_running());
    // R4: stop() never erases armed_ — the query still returns the last
    // thing any mechanism reported, exactly like subscription_health().
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at == t1);
}

TEST_CASE("Establishment: an inert mechanism overlays coverage to None and leaves "
          "established_at alone (O-1, red-before)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    const SparkIncarnation inc = fake->tokens(key).front();
    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);

    fake->set_inert(true);
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at == t1); // the overlay never touches established_at

    fake->set_inert(false);
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification); // the cached value was never lost
    CHECK(*est->established_at == t1);

    engine.stop();
}

TEST_CASE("Establishment: a spark whose type has no registered mechanism is untouched by "
          "another type's inert flag and never throws (O-2, regression guard for the "
          "find()-not-at() shape; green on the pre-overlay engine)",
          "[spark][established]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(1); // ms, as E8
    FakeMechanism* file_fake = wire_fake(engine, SparkType::File);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    auto sub = engine.arm(*c1, interval_spec(5)); // Interval has no registered mechanism
    REQUIRE(sub.has_value());

    file_fake->set_inert(true); // a DIFFERENT type's mechanism
    std::optional<SubscriptionEstablishment> est;
    REQUIRE_NOTHROW(est = engine.subscription_establishment(*sub));
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());
    engine.stop();
}

TEST_CASE("Establishment: after stop() an inert mechanism still overlays None while "
          "established_at keeps its last-known value (O-3, red-before)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    const SparkIncarnation inc = fake->tokens(key).front();
    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);
    fake->set_inert(true);

    engine.stop();
    CHECK_FALSE(engine.is_running());
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at == t1);
}

TEST_CASE("Establishment: [tsan] the inert overlay under concurrent inert flips and queries "
          "(O-4, sanitizer exercise; cannot go red on the pre-overlay engine)",
          "[spark][established][tsan]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c1, spec);
    REQUIRE(sub.has_value());
    const SparkIncarnation inc = fake->tokens(key).front();
    const auto t1 = std::chrono::steady_clock::now();
    fake->fire_established(key, inc, t1, SparkCoverage::Notification);

    std::atomic<bool> stop{false};
    std::atomic<bool> violation{false}; // set by the readers; asserted after join
    std::thread flipper([&] {
        bool inert = false;
        while (!stop.load(std::memory_order_acquire)) {
            inert = !inert;
            fake->set_inert(inert);
        }
    });
    auto reader_body = [&] {
        while (!stop.load(std::memory_order_acquire)) {
            auto est = engine.subscription_establishment(*sub);
            if (!est || !est->established_at || *est->established_at != t1 ||
                (est->coverage != SparkCoverage::None &&
                 est->coverage != SparkCoverage::Notification))
                violation.store(true, std::memory_order_relaxed);
        }
    };
    std::thread reader1(reader_body);
    std::thread reader2(reader_body);
    std::this_thread::sleep_for(200ms);
    stop.store(true, std::memory_order_release);
    flipper.join();
    reader1.join();
    reader2.join();
    engine.stop();

    CHECK_FALSE(violation.load(std::memory_order_relaxed));
}

TEST_CASE("Establishment: adoption — a disarm racing a re-arm skips the stale unwatch, and "
          "the mechanism sees a fresh token it can report against (E10)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(fake->tokens(key).size() == 1);
    const SparkIncarnation old_inc = fake->tokens(key)[0];

    // Fires inside disarm()'s teardown, after the key is dropped from
    // armed_/sub_keys_ under mu_ but BEFORE the (M2-staleness-rechecked)
    // unwatch() call — a fresh equal-spec arm() lands in that exact window.
    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c1, spec);
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);

    REQUIRE(raced);
    REQUIRE(sub2.has_value());
    // M2: the stale unwatch was skipped entirely.
    CHECK(fake->unwatch_calls() == 0);
    // The mechanism DID see a second watch_incarnation() call, with a
    // different token — "adoption" from the mechanism's perspective: the
    // same live watch object, a new engine-side identity.
    REQUIRE(fake->tokens(key).size() == 2);
    const SparkIncarnation new_inc = fake->tokens(key)[1];
    CHECK(new_inc != old_inc);

    // A report against the now-superseded OLD incarnation must not reach the
    // NEW subscription.
    fake->fire_established(key, old_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);

    // A report against the CURRENT (new) incarnation lands correctly.
    fake->fire_established(key, new_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);

    engine.stop();
}

TEST_CASE("Establishment: a disarm racing a re-arm after a positive report leaves the fresh "
          "incarnation reading None with no established_at, drops an old-incarnation report and "
          "accepts the new one (CH-4 engine identity, characterisation)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(fake->tokens(key).size() == 1);
    const SparkIncarnation old_inc = fake->tokens(key)[0];
    fake->fire_established(key, old_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    {
        auto pre = engine.subscription_establishment(*sub1);
        REQUIRE(pre.has_value());
        REQUIRE(pre->coverage == SparkCoverage::Notification);
        REQUIRE(pre->established_at.has_value());
    }

    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c1, spec);
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());
    REQUIRE(fake->tokens(key).size() == 2);
    const SparkIncarnation new_inc = fake->tokens(key)[1];
    CHECK(new_inc != old_inc);

    CHECK_FALSE(engine.subscription_establishment(*sub1).has_value());
    // SparkEngine::disarm() erases armed_[key] before the hook: the racing arm mints a fresh Armed.
    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    fake->fire_established(key, old_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    fake->fire_established(key, new_inc, std::chrono::steady_clock::now(),
                           SparkCoverage::Notification);
    est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::Notification);
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.stop();
}

TEST_CASE("Establishment: [tsan] established_at is never before armed_at under concurrent "
          "arm/report/read (locking discipline, not disarm/re-arm identity — see E4/E10 "
          "for that) (E11)",
          "[spark][established][tsan]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    engine.start();

    std::atomic<bool> stop{false};
    std::atomic<bool> violation{false}; // set by the checker; asserted after join
    std::vector<SparkEngine::SubscriptionId> subs;
    std::mutex subs_mu;

    std::thread armer([&] {
        int i = 0;
        while (!stop.load(std::memory_order_acquire)) {
            auto sub = engine.arm(*c1, service_spec("svc" + std::to_string(i++ % 8)));
            if (sub.has_value()) {
                std::lock_guard lk(subs_mu);
                subs.push_back(*sub);
                if (subs.size() > 32)
                    subs.erase(subs.begin());
            }
        }
    });
    std::thread reporter([&] {
        while (!stop.load(std::memory_order_acquire)) {
            for (int i = 0; i < 8; ++i) {
                const std::string key = spark_key(service_spec("svc" + std::to_string(i)));
                auto toks = fake->tokens(key);
                if (!toks.empty())
                    fake->fire_established(key, toks.back(), std::chrono::steady_clock::now(),
                                           SparkCoverage::Notification);
            }
        }
    });
    std::thread checker([&] {
        while (!stop.load(std::memory_order_acquire)) {
            std::vector<SparkEngine::SubscriptionId> snapshot;
            {
                std::lock_guard lk(subs_mu);
                snapshot = subs;
            }
            for (auto id : snapshot) {
                if (auto est = engine.subscription_establishment(id)) {
                    if (est->established_at && *est->established_at < est->armed_at)
                        violation.store(true, std::memory_order_relaxed);
                }
            }
        }
    });
    std::this_thread::sleep_for(200ms);
    stop.store(true, std::memory_order_release);
    armer.join();
    reporter.join();
    checker.join();
    engine.stop();

    CHECK_FALSE(violation.load(std::memory_order_relaxed));
}

TEST_CASE("Establishment: set_established_sink seals at start() — a repeat call after "
          "start() (or stop()) returns false, one-way (E12/H3)",
          "[spark][established]") {
    FakeMechanism fake;
    CHECK(fake.set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    fake.start([](const std::string&, SparkData) {},
              [](const std::string&, bool, std::string_view) {});
    CHECK_FALSE(fake.set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    fake.stop();
    // One-way: still sealed after stop() too — never re-opens.
    CHECK_FALSE(fake.set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
}

TEST_CASE("Establishment: start()'s replay skips a key superseded during on_start_hook_ by "
          "IDENTITY, not containment (E13, mutation-verified)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    // I1: pre-start arm — deferred, no watch_incarnation() call yet.
    auto sub1 = engine.arm(*c1, spec);
    REQUIRE(sub1.has_value());
    CHECK(fake->tokens(key).empty());

    // Fires between "every mechanism started + sink installed" and "the
    // pre-start replay loop runs" — no locks held. Disarms sub1 (I1) and
    // re-arms the same key LIVE (running_ is already true) — I2's
    // watch_incarnation() call happens synchronously, right here.
    engine.set_on_start_hook_for_test([&] {
        engine.disarm(*sub1);
        auto sub2 = engine.arm(*c1, spec);
        REQUIRE(sub2.has_value());
    });
    engine.start();
    engine.set_on_start_hook_for_test(nullptr);

    // The stale I1 replay must be skipped — only I2's live call reaches the
    // mechanism. Mutation (replay gate reverted to bare armed_.contains())
    // lets the stale replay through too: tokens(K) becomes [I2, I1].
    auto toks = fake->tokens(key);
    REQUIRE(toks.size() == 1);
    CHECK(fake->watch_calls() == 1);

    engine.stop();
}

TEST_CASE("Establishment: the failed-watch cleanup only touches the entry if it's still "
          "OURS — a successor's fresh arm survives untouched (E14, mutation-verified)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    std::atomic<bool> c2_got_lost{false};
    auto c2 = engine.register_consumer("c2", [&](const SparkEvent& ev) {
        if (ev.kind == SparkEventKind::Lost)
            c2_got_lost.store(true, std::memory_order_relaxed);
    });
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();
    const auto spec = service_spec("svc1");
    const std::string key = spark_key(spec);

    // Declared BEFORE the guard and tracked immediately (ThreadJoinGuard's
    // own doc comment: C++ destroys locals in reverse order, so a thread
    // must be declared before the guard protecting it, or an early REQUIRE
    // failure below destroys a still-joinable thread -> terminate). Real
    // bodies are move-assigned in below as each phase becomes ready.
    std::thread t1, t2, t3;
    ThreadJoinGuard guard{&fake->park_gate_for_test(), {}};
    guard.track(t1);
    guard.track(t2);
    guard.track(t3);

    // T1: arm(c1, K) — the fake parks INSIDE watch() (after recording I1's
    // token in watch_incarnation()), holding `ops` for the whole park —
    // arm_impl calls watch_guarded() while holding this type's mech-ops lock.
    fake->set_park_next_watch(true);
    t1 = std::thread([&] {
        auto sub = engine.arm(*c1, spec);
        (void)sub; // T1's own result is not the assertion target — T3's is
    });
    REQUIRE(fake->wait_parked());

    // T2: unregister_consumer(c1) — erases sub1 + the Armed(I1) entry under
    // mu_ alone (no `ops` needed for the bookkeeping), then blocks trying to
    // take `ops` for its own (about-to-be-stale) unwatch call.
    t2 = std::thread([&] { engine.unregister_consumer(*c1); });
    REQUIRE(eventually([&] { return engine.stats().armed_sparks == 0; }));

    // T3: arm(c2, K) — commits a fresh Armed(I2) under mu_, then blocks at
    // the live gate trying to take the SAME `ops` T1 still holds. The result
    // is captured, NOT asserted here — a Catch2 assertion macro failing
    // inside a spawned std::thread's own function throws across the thread
    // boundary, which terminates the process rather than failing cleanly;
    // every assertion on T3's outcome happens on the main thread after join.
    std::optional<SparkEngine::SubscriptionId> sub2;
    t3 = std::thread([&] {
        auto sub = engine.arm(*c2, spec);
        if (sub.has_value())
            sub2 = *sub;
    });
    REQUIRE(eventually([&] { return engine.stats().armed_sparks == 1; }));

    // Release T1's park with a forced watch failure queued.
    fake->set_fail_next_watch(true);
    fake->release_park();

    t1.join();
    t2.join();
    t3.join();

    REQUIRE(sub2.has_value());
    // c2 never sees Lost — the cleanup found I2 != I1 and left its entry alone.
    CHECK_FALSE(c2_got_lost.load(std::memory_order_relaxed));
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);
    // Both watch_incarnation() calls reached the mechanism, in order: I1
    // (T1, later failed) then I2 (T3, succeeded once `ops` was released).
    auto toks = fake->tokens(key);
    REQUIRE(toks.size() == 2);
    CHECK(toks[0] != toks[1]);

    engine.stop();
}

TEST_CASE("Establishment: the live watch gate rejects a key superseded while queued behind "
          "`ops` — by IDENTITY, not containment (E15, mutation-verified)",
          "[spark][established]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();

    const auto spec0 = service_spec("svc0"); // sibling key — holds `ops` via a parked unwatch
    const auto spec = service_spec("svc1");  // the key under test
    const std::string key = spark_key(spec);

    auto sub0 = engine.arm(*c1, spec0);
    REQUIRE(sub0.has_value());

    // Declared BEFORE the guard and tracked immediately — see E14's own
    // comment for why.
    std::thread t0, t1, t2, t3;
    ThreadJoinGuard guard{&fake->park_gate_for_test(), {}};
    guard.track(t0);
    guard.track(t1);
    guard.track(t2);
    guard.track(t3);

    fake->set_park_next_unwatch(true);
    t0 = std::thread([&] { engine.disarm(*sub0); });
    REQUIRE(fake->wait_parked());
    // disarm()'s own mu_-held block (including armed_.erase for svc0) runs
    // and completes BEFORE it ever calls mech->unwatch() — where the park
    // above is — so by the time wait_parked() returns, svc0's bookkeeping
    // is already gone: armed_sparks is 0 here, not 1 (nothing else is armed
    // yet). Confirmed, not polled: this is a deterministic fact once T0 has
    // provably entered its park.
    REQUIRE(engine.stats().armed_sparks == 0);

    std::atomic<bool> t1_failed_as_expected{false};
    t1 = std::thread([&] {
        auto sub = engine.arm(*c1, spec);
        if (!sub.has_value() && sub.error().find("disarmed") != std::string::npos)
            t1_failed_as_expected.store(true, std::memory_order_relaxed);
    });
    // K(I1) committed under mu_ (T1 then blocks trying to take the same
    // `ops` T0 holds) — starting from the just-confirmed 0 above, this can
    // only be the 0->1 transition, never a stale reading.
    REQUIRE(eventually([&] { return engine.stats().armed_sparks == 1; }));

    t2 = std::thread([&] { engine.unregister_consumer(*c1); });
    REQUIRE(eventually([&] { return engine.stats().armed_sparks == 0; }));

    // Captured, not asserted here — see E14's own comment on why a Catch2
    // assertion macro must never fail inside a spawned thread's function.
    std::optional<SparkEngine::SubscriptionId> sub2;
    t3 = std::thread([&] {
        auto sub = engine.arm(*c2, spec);
        if (sub.has_value())
            sub2 = *sub;
    });
    REQUIRE(eventually([&] { return engine.stats().armed_sparks == 1; })); // K(I2) only

    fake->release_park();
    t0.join();
    t1.join();
    t2.join();
    t3.join();

    CHECK(t1_failed_as_expected.load(std::memory_order_relaxed));
    REQUIRE(sub2.has_value());
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);
    // T1's own token was NEVER recorded — the live gate rejected it before
    // watch_incarnation() was ever called. Only T3's (I2) reaches the fake.
    auto toks = fake->tokens(key);
    CHECK(toks.size() == 1);

    engine.stop();
}

// ── Linux-only smoke: drive the REAL sd-bus mechanism against absent units and
//    (env-gated) a live unit transition. The cross-platform cases above prove
//    the engine plumbing via the fake; these prove the actual Linux body fires
//    and that its resource contract (1 bus connection + 1 eventfd + 1 thread,
//    for any N) actually holds — thread count alone would hide a per-unit-
//    connection regression (stage0-resource-baseline.md).
//
//    NOTE on bus-collapse/reconnect: killing the system bus in a test would
//    kill the host session, so there is deliberately no live test for that
//    path here. The fault-channel plumbing itself is proven by the
//    cross-platform FakeMechanism-driven cases above (B1); the PER-UNIT
//    resolve/arm/read logic mirrors guard_systemd.cpp's soak-tested pattern
//    closely, but the reopen-then-re-arm-ALL-units fan-out is structurally
//    NEW here (guard_systemd only ever had one unit per connection) and has
//    NO test coverage, live or fake — a governance Gate-3 finding this
//    session (a real bus-unref leak was found and fixed in this exact path;
//    a mock/fake-bus-driven test of the reopen fan-out is a tracked
//    follow-up). The churn case below (arm N, disarm all) proves no fd/slot
//    leak across repeated arm/disarm, which is the only property a unit
//    test here can directly observe without mocking sd-bus.
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

#include <unistd.h> // getpid

#include <cstdlib>     // getenv
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
std::size_t linux_fd_count() {
    std::error_code ec;
    std::size_t n = 0;
    for (const auto& e : std::filesystem::directory_iterator("/proc/self/fd", ec))
        (void)e, ++n;
    return n;
}
std::size_t linux_thread_count() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("Threads:", 0) == 0) {
            std::istringstream iss(line.substr(8));
            std::size_t n = 0;
            iss >> n;
            return n;
        }
    }
    return 0;
}
} // namespace

TEST_CASE("Service spark (real mechanism): an absent unit gets an initial Stopped emit",
          "[spark][mechanism][linux]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string name = "yuzu-nosuch-" + std::to_string(::getpid()) + ".service";
    auto sub = engine.arm(*c, service_spec(name));
    if (!sub.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Stopped);
    // M1 (rung 9c PR-6 item 1): the mechanism must reach SOME real coverage
    // classification, never stay at the default None forever. EMPIRICALLY
    // VERIFIED against a real system bus (a standalone sd-bus probe, not
    // assumed from the D-Bus API docs): systemd's LoadUnit succeeds for ANY
    // syntactically valid unit name — it lazily creates a stub unit object
    // with LoadState=not-found rather than erroring — so an absent unit
    // takes the SAME Resolved -> match -> read path as a present one
    // (arm_unit's NotFound branch, mapping to Poll, is reserved for the
    // rarer case where LoadUnit itself fails outright) and typically also
    // reaches Notification here. Accept either — the property under test is
    // "no coverage started at None forever, and if Notification, it stamps",
    // not a specific tri-state value this absence path does not control.
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage != SparkCoverage::None;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->established_at.has_value() == (est->coverage == SparkCoverage::Notification));
    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): two spark keys coalescing onto one unit each "
          "get their own emit",
          "[spark][mechanism][linux]") {
    // "yuzu-coalesce-<pid>" and "yuzu-coalesce-<pid>.service" are DISTINCT
    // engine-level spark keys (different ServiceSparkParams::service_name,
    // no engine-level dedup) but normalize_unit_name folds them onto the
    // SAME underlying UnitWatch inside the mechanism. Governance flagged
    // this exact scenario (a second key arming onto an already-known unit)
    // as untested by every N-watch resource test, since those all use N
    // DISTINCT unit names.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string base = "yuzu-coalesce-" + std::to_string(::getpid());
    auto first = engine.arm(*c, service_spec(base));
    if (!first.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));

    // Second key normalizes to the identical unit name ("base" has no '.'
    // so normalize_unit_name appends ".service" — matching this literal).
    auto second = engine.arm(*c, service_spec(base + ".service"));
    REQUIRE(second.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; })); // the coalescing key gets its OWN emit

    CHECK(got.at(0).key != got.at(1).key); // distinct engine keys...
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state ==
          ServiceRunState::Stopped); // ...same (absent) unit, same resolved state

    // M1 (rung 9c PR-6 item 1): the F4 unified branch reports establishment
    // for the SECOND (coalescing) key unconditionally — it must NOT be
    // gated behind the same `uw.last` check the emit above is (a key
    // coalescing onto an already-resolved unit whose state HASN'T changed
    // still needs its own establishment report; the emit is edge-gated, the
    // establishment report is not). See the "absent unit" test above for why
    // this accepts any non-None coverage rather than a specific value.
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*second);
        return est.has_value() && est->coverage != SparkCoverage::None;
    }));

    engine.disarm(*first);
    engine.disarm(*second);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): a real active unit resolves to Running",
          "[spark][mechanism][linux]") {
    // systemd-journald.service is present and active on virtually any systemd
    // host, needs no privilege to READ (only start/stop needs polkit auth), so
    // this exercises the Resolved+Active real-bus path without any live-env
    // gate — the twin of the Windows "Winmgmt" always-running smoke case.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, service_spec("systemd-journald.service"));
    if (!sub.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);
    // M1 (rung 9c PR-6 item 1), STRICT: a real, present, resolvable unit MUST
    // reach Notification coverage, never settle for Poll — Poll here would
    // mean the mechanism-wide Subscribe() call failed (H7), which on a normal
    // systemd host is a real finding (a Subscribe-denied host), not an
    // acceptable degraded mode this test should silently tolerate.
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);
    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): a disarm racing a re-arm (adoption) still lets "
          "the mechanism report establishment against the fresh incarnation (M1)",
          "[spark][mechanism][linux]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub1 = engine.arm(*c, service_spec("systemd-journald.service"));
    if (!sub1.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub1);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));

    // Race a re-arm of the SAME key into disarm()'s teardown window — the M2
    // staleness recheck skips the stale unwatch, so the real mechanism's
    // UnitWatch survives untouched ("adoption": same live sd-bus match, a
    // new engine-side incarnation).
    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c, service_spec("systemd-journald.service"));
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());

    // The adopted key still reaches Notification under its NEW incarnation
    // — the F4 unconditional coalesce/adoption report, exercised against the
    // real mechanism rather than the fake.
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub2);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);

    engine.disarm(*sub2);
    engine.stop();
}

TEST_CASE("Service mechanism (Linux, direct): set_established_sink seals at start(), same "
          "one-way contract as the fake (M2)",
          "[spark][mechanism][linux]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech);
    CHECK(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->stop();
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {})); // one-way: still sealed after stop()
}

TEST_CASE("Service spark (real mechanism): fd/thread collapse holds across N absent watches",
          "[spark][mechanism][linux][resource]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string pid = std::to_string(::getpid());
    auto first = engine.arm(*c, service_spec("yuzu-fdproof-0-" + pid + ".service"));
    if (!first.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const auto fd_base = linux_fd_count();
    const auto thread_base = linux_thread_count();

    std::vector<SparkEngine::SubscriptionId> subs;
    for (int i = 1; i < 20; ++i) {
        auto s = engine.arm(*c, service_spec("yuzu-fdproof-" + std::to_string(i) + "-" + pid +
                                             ".service"));
        REQUIRE(s.has_value());
        subs.push_back(*s);
    }
    REQUIRE(eventually([&] { return got.count() >= 20; }));

    // 19 MORE units armed onto the SAME bus connection: the bus fd + eventfd
    // are already open, so this should add ~0 fds. A regression to a
    // per-unit bus connection (today's guard model) would add ~2 fds/unit —
    // this assertion fails hard, immediately, on that regression.
    CHECK(linux_fd_count() <= fd_base + 2);
    // Thread count is FIXED at 1 mechanism thread regardless of watch count —
    // the wheel + this mechanism + the consumer dispatch thread are already
    // running at fd_base's sample, so arming 19 more units must add ~zero.
    // Small tolerance (matches the fd check above) absorbs unrelated
    // transient OS/runtime threads; a per-unit-thread regression (+19) still
    // fails this decisively.
    CHECK(linux_thread_count() <= thread_base + 2);

    for (auto& s : subs)
        engine.disarm(s);
    engine.disarm(*first);
    CHECK(eventually([&] { return linux_fd_count() <= fd_base; })); // no slot/fd leak on churn
    engine.stop();
}

// Live transition — env-gated so normal CI (incl. bus-less containers) skips it;
// runs on a real systemd box. Recipe:
//   sudo systemd-run --unit=yuzu-spark-probe.service /usr/bin/sleep 3600
//   ( sleep 4; sudo systemctl stop yuzu-spark-probe.service ) &
//   YUZU_SPARK_LIVE_UNIT=yuzu-spark-probe.service ./yuzu_agent_tests "[spark][linux][live]"
TEST_CASE("Service spark (real mechanism): live unit transition fires Running then Stopped",
          "[spark][mechanism][linux][live]") {
    const char* unit = std::getenv("YUZU_SPARK_LIVE_UNIT");
    if (!unit || !*unit) {
        SUCCEED("YUZU_SPARK_LIVE_UNIT unset — skipping live systemd integration test");
        return;
    }
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, service_spec(unit));
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }, 10000ms));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);

    CHECK(eventually(
        [&] {
            for (std::size_t i = 0; i < got.count(); ++i) {
                const auto& ev = got.at(i);
                if (std::holds_alternative<ServiceSparkData>(ev.data) &&
                    std::get<ServiceSparkData>(ev.data).state == ServiceRunState::Stopped)
                    return true;
            }
            return false;
        },
        30000ms));
    engine.stop();
}

#endif // __linux__ && YUZU_HAVE_LIBSYSTEMD

// ── Windows-only smoke: drive the REAL IOCP / TP_WAIT mechanisms against a live
//    file write / registry write. The cross-platform cases above prove the
//    engine plumbing via the fake; these prove the actual Windows bodies fire.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_str.hpp> // yuzu::win::from_wide (real service-name widen/narrow, PR-A round 2)

#include <sddl.h> // ConvertSidToStringSidW / ConvertStringSecurityDescriptorToSecurityDescriptorW (UP-2 closure test)

#include <cmath> // std::floor / std::log2 - the #4658 pass-count bound
#include <condition_variable>
#include <filesystem>
#include <fstream>

#include <spdlog/sinks/base_sink.h> // PfStallLogger (#4658 PF-11/PF-12)
#include <spdlog/spdlog.h>

TEST_CASE("File spark (real mechanism): a live file write fires the spark",
          "[spark][mechanism][windows]") {
    namespace fs = std::filesystem;
    // PID-salted temp name — stable, never thread-id/clock (Defender flake #473).
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_file_smoke_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; } // parent dir + file exist before arming

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the IOCP read arm
    { std::ofstream(target, std::ios::app) << "change"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::File);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("Registry spark (real mechanism): a live value write fires the spark",
          "[spark][mechanism][windows]") {
    // PID-unique subkey under HKCU so parallel CI runners can't collide.
    const std::string sub =
        "Software\\Yuzu\\SparkSmoke_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the TP_WAIT notify arm
    const DWORD val = 42;
    ::RegSetValueExA(h, "SparkVal", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::Registry);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

TEST_CASE("File spark (real mechanism): survives parent-dir delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    namespace fs = std::filesystem;
    // Nest one level so the fallback ancestor is our own quiet dir, not the
    // churny temp root: <root>/<parent>/watched.txt — we delete <parent>.
    const fs::path root =
        fs::temp_directory_path() / ("spark_res_" + std::to_string(::GetCurrentProcessId()));
    const fs::path parent = root / "watched";
    const fs::path target = parent / "file.txt";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(parent);
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the dir read arm

    // Blow away the watched file's parent dir → the mechanism's dir handle goes
    // bad and it must fall back to watching <root> for the parent's recreation.
    fs::remove(target, ec);
    fs::remove(parent, ec);
    std::this_thread::sleep_for(300ms);

    // Recreate parent + file, then modify → the ancestor watch must re-resolve
    // the parent dir and re-arm, so this post-recreate change still fires.
    fs::create_directories(parent);
    { std::ofstream(target) << "recreated"; }
    std::this_thread::sleep_for(150ms);
    { std::ofstream(target, std::ios::app) << "change-after-recreate"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::File);
    engine.stop();
    fs::remove_all(root, ec);
}

TEST_CASE("File spark (real mechanism): disarm-then-rearm the same file does not lose the watch "
          "(PR #1927 review)",
          "[spark][mechanism][windows][resilience]") {
    namespace fs = std::filesystem;
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_file_rearm_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());

    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    engine.start();
    std::this_thread::sleep_for(150ms); // let the IOCP read arm — io_pending now true

    // Disarm then IMMEDIATELY re-arm the same file, no sleep between: unwatch()
    // cancels the outstanding read (io_pending was true) and, pre-fix, left the
    // DirWatch keyed in dirs_ with removing=true — a racing watch() reused
    // that about-to-be-freed slot silently (arm() reports success, but there
    // is no live ReadDirectoryChangesW behind it, and the whole entry vanishes
    // for good once the aborted completion drains). Whether the worker thread
    // wins the race to drain that completion before the very next arm() runs
    // is scheduling-dependent — repeat the cycle so one lucky interleaving
    // can't mask a regression (governance Gate-3 quality-engineer finding).
    for (int i = 0; i < 25; ++i) {
        engine.disarm(*sub);
        sub = engine.arm(*c, spec);
        REQUIRE(sub.has_value());
    }

    std::this_thread::sleep_for(150ms); // let the final read arm (if the fix works)
    { std::ofstream(target, std::ios::app) << "change"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::File);

    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("File spark (real mechanism): arm() on a nonexistent drive root does not hang "
          "(PR #1927 review)",
          "[spark][mechanism][windows][resilience]") {
    // arm_ancestor's ancestor-walk previously never terminated for a root that
    // doesn't exist: parent_path() of a drive root is a FIXED POINT, not
    // empty, so "walk until empty" spun forever holding the mechanism's own
    // mu_ — bricking every other watch on this mechanism and hanging shutdown
    // behind it. Heap-allocate everything the probe thread touches (mirrors
    // the UP-1/UP2-3 detach-safety idiom above): on a regression this leaks a
    // thread parked forever inside watch() instead of UAF-ing a stack-local
    // engine out from under it — the point is proving termination, not
    // surviving a hang gracefully.
    char letter = 0;
    {
        const DWORD mask = ::GetLogicalDrives();
        // Scan Z down to B (skip only A, the traditional floppy letter) — a
        // heavily-provisioned CI runner (VPN/WSL/Docker Desktop/network
        // shares) can plausibly map every letter D-Z, and this is the ONLY
        // regression test for the arm_ancestor hang, so a silent skip here
        // would leave that fix unverified on exactly the runners most likely
        // to need it (governance Gate-3 quality-engineer finding).
        for (char cand = 'Z'; cand >= 'B'; --cand) {
            if (!(mask & (1u << (cand - 'A')))) {
                letter = cand;
                break;
            }
        }
    }
    if (!letter) {
        FAIL("no free drive letter (B-Z) available to probe an absent root — this box has "
             "every letter mapped, so the arm_ancestor hang fix (finding #3) is unverified here");
    }

    struct Probe {
        SparkEngine engine;
        Collector got;
        std::mutex m;
        std::condition_variable cv;
        bool done{false};
        bool armed{false};
    };
    auto probe = std::make_shared<Probe>();
    REQUIRE(probe->engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = probe->engine.register_consumer("c", probe->got.handler());
    REQUIRE(c.has_value());
    const auto consumer = *c;
    const auto spec = file_spec(std::string(1, letter) + ":\\nonexistent\\dir\\file.txt");
    probe->engine.start();

    std::thread([probe, consumer, spec] {
        auto r = probe->engine.arm(consumer, spec);
        std::lock_guard lk(probe->m);
        probe->armed = r.has_value();
        probe->done = true;
        probe->cv.notify_all();
    }).detach();

    std::unique_lock lk(probe->m);
    const bool finished = probe->cv.wait_for(lk, 5000ms, [&] { return probe->done; });
    CHECK(finished); // a regression hangs this forever instead of finishing
    lk.unlock();
    if (finished) {
        // watch()'s best-effort design always reports success — it records the
        // key and falls back to an ancestor watch for a later (re)creation —
        // even when neither arm_dir nor arm_ancestor found anything real to
        // watch, so `armed == true` here is the CORRECT outcome, not a
        // false-positive. `finished` above is the assertion that matters:
        // termination, not a failure return.
        CHECK(probe->armed);
        probe->engine.stop();
    }
    // else: deliberately leak `probe` (and the parked thread inside it).
}

TEST_CASE("File spark (real mechanism): watch() on an existing key with a different "
          "directory clears the stale registration (#1981)",
          "[spark][mechanism][windows][resilience]") {
    // Drives WindowsFileMechanism DIRECTLY, bypassing SparkEngine: its arm()
    // always derives `key` from spark_key(spec), so the same key can never
    // map to two different paths through THAT call path. ISparkMechanism's
    // contract treats `key` as an opaque caller-supplied identifier though
    // (spark_mechanism.hpp) — a future caller may legitimately re-call
    // watch() for an EXISTING key with updated params on a content edit
    // (Stage 6's differential re-apply: "unchanged bindings don't re-arm"
    // implies a changed one updates in place) without an intervening
    // explicit unwatch(). Before the fix, watch() unconditionally overwrote
    // key_index_[key], leaking the OLD DirWatch::keys[old_fname] entry
    // forever — a spurious-fires-forever leak from the abandoned path
    // (governance chaos-injector Gate 5 finding).
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path dirA = fs::temp_directory_path() / ("spark_1981_a_" + pid);
    const fs::path dirB = fs::temp_directory_path() / ("spark_1981_b_" + pid);
    std::error_code ec;
    fs::remove_all(dirA, ec);
    fs::remove_all(dirB, ec);
    fs::create_directories(dirA);
    fs::create_directories(dirB);
    const fs::path fileA = dirA / "target.txt";
    const fs::path fileB = dirB / "target.txt";
    { std::ofstream(fileA) << "seed"; }
    { std::ofstream(fileB) << "seed"; }

    // Exception-safe cleanup (quality-engineer Gate 3): a failed assertion
    // would otherwise skip the trailing remove_all and leak dirA/dirB.
    // Declared before `mech` so it runs after ~mech closes its handles.
    struct DirCleanup {
        const fs::path& a;
        const fs::path& b;
        ~DirCleanup() {
            std::error_code e;
            fs::remove_all(a, e);
            fs::remove_all(b, e);
        }
    } dir_cleanup{dirA, dirB};

    struct Fires {
        std::mutex mu;
        std::vector<std::string> keys;
        void add(std::string k) {
            std::lock_guard lk(mu);
            keys.push_back(std::move(k));
        }
        std::size_t count() {
            std::lock_guard lk(mu);
            return keys.size();
        }
        std::string at(std::size_t i) {
            std::lock_guard lk(mu);
            return keys.at(i);
        }
    };
    auto fires = std::make_shared<Fires>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    mech->start([fires](const std::string& key, SparkData) { fires->add(key); },
                [](const std::string&, bool, std::string_view) {});

    const std::string key = "shared-key-1981";
    REQUIRE(mech->watch(key, FileSparkParams{fileA.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm

    // Re-arm the SAME key against dirB, with NO intervening unwatch().
    REQUIRE(mech->watch(key, FileSparkParams{fileB.string()}).has_value());
    std::this_thread::sleep_for(150ms);

    { std::ofstream(fileA, std::ios::app) << "changeA"; }
    std::this_thread::sleep_for(300ms);
    CHECK(fires->count() == 0); // the OLD registration must be gone — no spurious fire

    { std::ofstream(fileB, std::ios::app) << "changeB"; }
    CHECK(eventually([&] { return fires->count() >= 1; }, 8000ms));
    if (fires->count() >= 1)
        CHECK(fires->at(0) == key);

    mech->unwatch(key);
    std::this_thread::sleep_for(150ms); // let the worker drain the cancelled read
    mech->stop();
    // dirA/dirB removed by DirCleanup on scope exit.
}

TEST_CASE("File spark (real mechanism): retiring_ is capped and observable under "
          "re-arm churn while the worker is wedged (#1979/#1982)",
          "[spark][mechanism][windows][resilience]") {
    // Determinism trick: the mechanism has ONE worker draining its IOCP, and
    // it calls emit_ with mu_ RELEASED (spark_file.cpp run()) — a blocking
    // emit callback therefore wedges the drain loop deterministically while
    // watch()/unwatch() stay fully operable (they only need mu_, not the
    // worker). Flood retiring_ past the cap while the worker can't drain,
    // confirm it's bounded + observable + a fresh watch() is refused, then
    // release the gate and confirm a full drain plus a prompt, leak-free stop().
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path trigger_dir = fs::temp_directory_path() / ("spark_1979_trig_" + pid);
    std::error_code ec;
    fs::remove_all(trigger_dir, ec);
    fs::create_directories(trigger_dir);
    const fs::path trigger_file = trigger_dir / "t.txt";
    { std::ofstream(trigger_file) << "seed"; }

    // Populated by the flood loop below; captured by reference into the cleanup
    // guard declared next.
    std::vector<fs::path> flood_dirs;

    // Exception-safe temp-dir cleanup (quality-engineer Gate 3): a failed
    // REQUIRE/CHECK unwinds past the trailing remove_all calls, otherwise
    // leaking up to kRetiringCap+8 PID-salted dirs. Declared BEFORE `mech` so
    // (reverse-declaration order) it runs AFTER ~mech has stop()'d/joined and
    // closed every directory handle — removing dirs with live handles open
    // would silently fail. Declared AFTER flood_dirs so flood_dirs outlives it.
    struct DirCleanup {
        const fs::path& trig;
        const std::vector<fs::path>& floods;
        ~DirCleanup() {
            std::error_code e;
            for (const auto& d : floods)
                fs::remove_all(d, e);
            fs::remove_all(trig, e);
        }
    } dir_cleanup{trigger_dir, flood_dirs};

    struct Gate {
        std::mutex m;
        std::condition_variable cv;
        bool release{false};
        std::atomic<int> emit_calls{0};
        void wait() {
            emit_calls.fetch_add(1);
            std::unique_lock lk(m);
            cv.wait(lk, [&] { return release; });
        }
        void open() {
            {
                std::lock_guard lk(m);
                release = true;
            }
            cv.notify_all();
        }
    };
    auto gate = std::make_shared<Gate>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    // The mechanism's own cap — read live rather than duplicating the 256
    // literal, so a change to WindowsFileMechanism::kRetiringCap can't leave a
    // silently-wrong constant here (quality-engineer Gate 3).
    const std::uint64_t cap = mech->stats().retiring_cap;
    REQUIRE(cap > 0);

    // If any assertion below fails, Catch2 unwinds the stack — this guard's
    // destructor (declared AFTER mech, so it runs BEFORE mech's own
    // destructor per reverse-declaration-order) opens the gate unconditionally
    // first. Without it, a failed assertion here leaves the worker wedged in
    // emit() forever, and ~WindowsFileMechanism's stop()/worker_.join() hangs
    // the WHOLE test binary, not just this test case.
    struct GateOpener {
        std::shared_ptr<Gate> g;
        ~GateOpener() { g->open(); }
    } gate_opener{gate};

    mech->start([gate](const std::string&, SparkData) { gate->wait(); },
                [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch("trigger", FileSparkParams{trigger_file.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm

    { std::ofstream(trigger_file, std::ios::app) << "change"; } // fires → worker blocks in emit()
    CHECK(eventually([&] { return gate->emit_calls.load() >= 1; }));

    for (std::uint64_t i = 0; i < cap + 8; ++i) {
        fs::path d = fs::temp_directory_path() /
                     ("spark_1979_flood_" + pid + "_" + std::to_string(i));
        fs::create_directories(d);
        flood_dirs.push_back(d);
        const std::string key = "flood" + std::to_string(i);
        // NOT a REQUIRE: this loop deliberately floods PAST the cap, so once
        // retiring_ hits the cap mid-loop, watch() is SUPPOSED to start
        // refusing — that's the mechanism under test, not a failure.
        // unwatch() on a key whose arm was refused (never in key_index_) is a
        // safe no-op, so it's fine to call unconditionally either way.
        (void)mech->watch(key, FileSparkParams{(d / "f.txt").string()});
        mech->unwatch(key); // cancels the just-armed read (if it armed) → retiring_
    }

    // The worker can't drain (wedged in emit()) — retiring_ must be bounded,
    // observable, and refuse further growth rather than growing unbounded.
    CHECK(mech->stats().retiring >= cap);
    auto refused =
        mech->watch("overflow", FileSparkParams{(trigger_dir / "overflow.txt").string()});
    REQUIRE_FALSE(refused.has_value());
    // Assert it's the CAP rejection specifically, not some unrelated failure
    // (e.g. a not-started mechanism) that would also produce an empty expected
    // (quality-engineer Gate 3).
    CHECK(refused.error().find("cap") != std::string::npos);
    CHECK(mech->stats().watch_rejected_total >= 1);

    gate->open(); // let the worker drain everything
    CHECK(eventually([&] { return mech->stats().retiring == 0; }, 10000ms));

    const auto t0 = std::chrono::steady_clock::now();
    mech->stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 5000ms);
    CHECK(mech->stats().quarantined_total == 0); // the cap kept this reachable in the first place
    // trigger_dir + flood_dirs removed by DirCleanup on scope exit.
}

TEST_CASE("File spark (real mechanism): a failed retire keeps the DirWatch alive rather than "
          "freeing it under a live kernel read (#2839)",
          "[spark][mechanism][windows][resilience]") {
    // THE DEFECT. push_retiring() used to take the owning unique_ptr BY VALUE and start
    // with retiring_.push_back(std::move(w)). The ownership transfer therefore completed
    // at the CALL, before the one statement that can allocate — so a std::bad_alloc out
    // of push_back destroyed a DirWatch whose ReadDirectoryChangesW was still
    // outstanding, and the kernel later wrote into that freed buffer and OVERLAPPED. The
    // caller's dirs_.erase(di) was skipped too, leaving a moved-from (null) unique_ptr
    // keyed in dirs_ that stop()'s cancel loop then dereferenced.
    //
    // A real bad_alloc cannot be aimed at one statement, so it is injected through the
    // #2839 seam, which fires immediately before the allocating step — the same
    // "fault phase" idiom as SparkEngine::set_arm_fault_hook_for_test.
    //
    // PRE-FIX this case crashes, but WHICH dereference lands first is not predictable and
    // this test does not claim it is. The by-value parameter had already taken ownership
    // at the call, so the throw FREES the DirWatch; from that instant there are two live
    // dangling references to it — the IOCP completion the kernel still holds (CancelIoEx
    // was issued just before, so its ABORTED packet is typically already queued, and the
    // worker will do `w->io_pending = false` on freed memory), and the moved-from (null)
    // unique_ptr left in dirs_ because the caller's erase was skipped, which stop()'s
    // cancel loop then dereferences. The worker usually gets there first. Both are the
    // same defect; the fix removes the free, not one of the two readers.
    //
    // POST-FIX the throw lands BEFORE any ownership moves, so the watch stays whole in
    // dirs_ — already `removing` and cancelled — and is reclaimed normally by whichever
    // runs first: the worker's drop_watch() when the aborted completion drains, or
    // stop().
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path dir = fs::temp_directory_path() / ("yuzu_test_spark_2839_" + pid);
    // A SIBLING directory, not a second file in `dir` — spark_file.cpp's watch() keys
    // dirs_ by the PARENT DIRECTORY (dirkey), so a second watch under `dir` would
    // resurrect the exact dangling dirs_[dirkey] slot the throw below leaves behind,
    // silently repairing the state this test exists to check and making every
    // assertion below pass identically whether the fix is present or not (found via
    // real Windows red/green verification, #2839 follow-up — the test as first
    // written had zero discriminating power).
    const fs::path other_dir = fs::temp_directory_path() / ("yuzu_test_spark_2839_" + pid + "_sibling");
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::remove_all(other_dir, ec);
    fs::create_directories(dir);
    fs::create_directories(other_dir);
    const fs::path target = dir / "t.txt";
    { std::ofstream(target) << "seed"; }

    struct DirCleanup {
        const fs::path& d;
        const fs::path& d2;
        ~DirCleanup() {
            std::error_code e;
            fs::remove_all(d, e);
            fs::remove_all(d2, e);
        }
    } dir_cleanup{dir, other_dir}; // declared BEFORE mech, so it runs AFTER ~mech has closed handles

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    mech->start([](const std::string&, SparkData) {}, [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch("k2839", FileSparkParams{target.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm — io_pending must be TRUE, or
                                        // unwatch takes the plain dirs_.erase branch and
                                        // never reaches push_retiring at all
    REQUIRE(mech->stats().retiring == 0);

    // Aim a bad_alloc at the retire. The seam returns false off Windows and for any other
    // mechanism type, so the REQUIRE is the guard against silently testing nothing.
    REQUIRE(set_file_retire_fault_hook_for_test(*mech, [] { throw std::bad_alloc{}; }));

    // unwatch() REPORTS the failure rather than swallowing it — ISparkMechanism::unwatch
    // is not noexcept, and SparkEngine contains and counts a throwing unwatch at both of
    // its teardown doors (#2270). What must NOT happen is the free.
    CHECK_THROWS_AS(mech->unwatch("k2839"), std::bad_alloc);

    // The watch was never handed over, so nothing landed in retiring_ and the gauge is
    // untouched — "fully retained", the other half of the post-fix contract from
    // "fully quarantined".
    CHECK(mech->stats().retiring == 0);

    // The mechanism is not wedged: a fresh watch on a DIFFERENT DIRECTORY still arms
    // (see other_dir's declaration above for why it must not be `dir`).
    const fs::path other = other_dir / "u.txt";
    { std::ofstream(other) << "seed"; }
    CHECK(mech->watch("k2839b", FileSparkParams{other.string()}).has_value());

    // And the retained watch is reclaimed on an ordinary path — by the worker's
    // drop_watch() if the aborted completion has already drained, otherwise by stop()'s
    // own cancel-and-drain — with no quarantine and no crash either way. (drop_watch
    // searches dirs_, ancestors_ AND retiring_, so it does not care which container the
    // watch ended up in.)
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_NOTHROW(mech->stop());
    CHECK(std::chrono::steady_clock::now() - t0 < 5000ms);
    CHECK(mech->stats().quarantined_total == 0);

    // KNOWN RESIDUAL, recorded rather than asserted away. unwatch_locked() erases the
    // key_index_ entry at its top, BEFORE anything that can throw, so on this path the
    // key registration is gone while the DirWatch itself is retained. The watch is still
    // reclaimed correctly (by stop() above, or by the worker's drop_watch() when the
    // aborted completion drains — it searches dirs_, ancestors_ and retiring_), but that
    // one key can no longer be unwatched by name. A map entry stranded on a bad_alloc
    // path, not a use-after-free: strictly smaller than what this fix removes, and out of
    // scope for it. Moving the key_index_ erase after the transfer would close it and is
    // filed as a follow-up.
}

TEST_CASE("File spark (real mechanism): a zombie left by a throwing unwatch is drained, "
          "not silently reattached to a new key (#2839 follow-up)",
          "[spark][mechanism][windows][resilience]") {
    // Security-guardian Gate 2 finding on the #2839 reorder above: erasing dirs_[dirkey]
    // only after push_retiring's transfer completes means a throw during unwatch() (or
    // release_ancestor()) leaves the key pointing at a `removing` zombie instead of
    // freeing it for reuse. Pre-fix, watch()'s `auto& slot = dirs_[dirkey]; if (!slot)`
    // skips the fresh-DirWatch branch entirely when a zombie is already keyed there, so a
    // second key in the SAME directory silently attaches to a watch that is cancelled and
    // awaiting reclaim — watch() reports success, but nothing will ever fire for that key.
    // This is exactly the hazard unwatch_locked's own "Free dirkey for reuse NOW" comment
    // describes, reopened on the throw path #2839 itself introduced.
    //
    // Quality-engineer Gate 3 finding: the cancelled I/O's aborted completion is already
    // queued on the IOCP the instant CancelIoEx runs (inside the forced-throw unwatch,
    // before this test ever gets control back), and the worker thread races to drain it
    // via its OWN drop_watch() path independent of anything this test does next. If the
    // worker wins that race before the watch("kB", ...) call below, the zombie is gone
    // from dirs_ by the time this test's own drain-check runs — `stats().retiring` would
    // read 0 whether the production fix is present or reverted, a non-deterministic
    // result either way, not a test of the fix at all. Wedge the worker (the same
    // determinism trick as the #1979/#1982 flood test above: a blocking emit_ callback,
    // called with mu_ RELEASED, so watch()/unwatch() stay fully operable) BEFORE arming
    // kA at all, so it cannot process ANY completion — including kA's aborted one — until
    // this test explicitly releases it, well after the discriminating assertion.
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path dir = fs::temp_directory_path() / ("yuzu_test_spark_2839z_" + pid);
    const fs::path trigger_dir = fs::temp_directory_path() / ("yuzu_test_spark_2839z_trig_" + pid);
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::remove_all(trigger_dir, ec);
    fs::create_directories(dir);
    fs::create_directories(trigger_dir);
    const fs::path target = dir / "t.txt";
    const fs::path trigger_file = trigger_dir / "t.txt";
    { std::ofstream(target) << "seed"; }
    { std::ofstream(trigger_file) << "seed"; }

    struct DirCleanup {
        const fs::path& d;
        const fs::path& d2;
        ~DirCleanup() {
            std::error_code e;
            fs::remove_all(d, e);
            fs::remove_all(d2, e);
        }
    } dir_cleanup{dir, trigger_dir}; // declared BEFORE mech, so it runs AFTER ~mech has closed handles

    struct Gate {
        std::mutex m;
        std::condition_variable cv;
        bool release{false};
        std::atomic<int> emit_calls{0};
        void wait() {
            emit_calls.fetch_add(1);
            std::unique_lock lk(m);
            cv.wait(lk, [&] { return release; });
        }
        void open() {
            {
                std::lock_guard lk(m);
                release = true;
            }
            cv.notify_all();
        }
    };
    auto gate = std::make_shared<Gate>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    // If any assertion below fails, this guard's destructor (declared AFTER mech, so it
    // runs BEFORE mech's own destructor, reverse-declaration-order) opens the gate
    // unconditionally first — without it, a failed assertion here leaves the worker
    // wedged in emit() forever, and ~WindowsFileMechanism's stop()/worker_.join() hangs
    // the WHOLE test binary (same rationale as the #1979/#1982 test above).
    struct GateOpener {
        std::shared_ptr<Gate> g;
        ~GateOpener() { g->open(); }
    } gate_opener{gate};

    mech->start([gate](const std::string&, SparkData) { gate->wait(); },
                [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch("trigger", FileSparkParams{trigger_file.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the trigger's read arm
    { std::ofstream(trigger_file, std::ios::app) << "change"; } // fires → worker blocks in emit()
    // REQUIRE, not CHECK (governance Gate 8 cpp-safety finding): a missed wedge here
    // would silently degrade this test back to the pre-rewrite racy form instead of
    // failing loudly and attributing the failure to the precondition. GateOpener
    // already covers the resulting unwind path, so promoting this is free.
    REQUIRE(eventually([&] { return gate->emit_calls.load() >= 1; }));
    // The worker is now wedged for the rest of this test — it cannot process kA's
    // aborted completion no matter how fast CancelIoEx's kernel-side abort is.

    REQUIRE(mech->watch("kA", FileSparkParams{target.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm, matching the #2839 test above
    REQUIRE(mech->stats().retiring == 0);

    REQUIRE(set_file_retire_fault_hook_for_test(*mech, [] { throw std::bad_alloc{}; }));
    CHECK_THROWS_AS(mech->unwatch("kA"), std::bad_alloc);
    // The zombie is retained in dirs_ (removing=true) but NOT yet in retiring_ — matches
    // the #2839 test's own documented pre-fix-of-the-fix contract above. The worker
    // cannot have raced this: it's still blocked in emit_ for the trigger fire.
    CHECK(mech->stats().retiring == 0);

    // A second key in the SAME directory. Pre-fix: silently attaches to the zombie,
    // returns success, retiring_ stays 0 (the zombie was never drained). Post-fix: the
    // watch() call drains the zombie into retiring_ FIRST (the fault hook was single-shot
    // and is already consumed, so this drain succeeds), then arms a genuinely fresh watch
    // for kB — the deterministic, in-process signal that no silent reattachment occurred.
    // Deterministic either way: the worker is still wedged, so this can only be the
    // production code's own doing, never a race outcome.
    const fs::path second = dir / "u.txt";
    { std::ofstream(second) << "seed"; }
    CHECK(mech->watch("kB", FileSparkParams{second.string()}).has_value());
    CHECK(mech->stats().retiring == 1);

    // Release the worker now — it catches up on the backlog (the trigger's emit_ call
    // returns, then it drains kA's long-queued aborted completion via the ordinary
    // drop_watch() path) before stop() below.
    gate->open();

    const auto t0 = std::chrono::steady_clock::now();
    CHECK_NOTHROW(mech->stop());
    CHECK(std::chrono::steady_clock::now() - t0 < 5000ms);
    CHECK(mech->stats().quarantined_total == 0);
}

TEST_CASE("File spark (real mechanism): a zombie ancestor watch is drained, not silently "
          "reattached, and a throwing release_ancestor() never crashes (#2839 follow-up)",
          "[spark][mechanism][windows][resilience]") {
    // Covers the OTHER half of the zombie-drain fix above: ancestors_ (arm_ancestor()),
    // exercised via watches on directories that do not exist (arm_dir fails, so the
    // mechanism falls back to watching the nearest existing ancestor for the parent's
    // eventual (re)creation — release_ancestor()/arm_ancestor(), not watch()/dirs_
    // directly). Also proves release_ancestor()'s own push_retiring call is safely
    // contained: it is reachable from the worker thread's run() loop with NO exception
    // frame above it there (unlike watch(), always wrapped by watch_guarded()), so an
    // uncaught throw would std::terminate the process rather than just fail one release.
    //
    // Same quality-engineer Gate 3 race as the dirs_ version of this test above: the
    // ancestor's cancelled I/O is already queued on the IOCP the instant CancelIoEx runs
    // inside release_ancestor(), and the worker races to drain it via its own
    // drop_watch() path independent of this test's next watch() call. Wedge the worker
    // (same blocking-emit_ idiom) before touching any of the absent-directory watches, so
    // it cannot process the ancestor's aborted completion until explicitly released.
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path base = fs::temp_directory_path() / ("yuzu_test_spark_2839a_" + pid);
    const fs::path trigger_dir = fs::temp_directory_path() / ("yuzu_test_spark_2839a_trig_" + pid);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::remove_all(trigger_dir, ec);
    fs::create_directories(base);
    fs::create_directories(trigger_dir);
    // Two DIFFERENT absent immediate parents that both resolve to the same existing
    // ancestor (`base`) once walked up — the shared ancestor is what gives it a
    // refcount, so releasing the FIRST dependent alone does not tear it down (refcount
    // 2->1), only the second does (1->0), which is when release_ancestor() actually
    // calls push_retiring.
    const fs::path absent1 = base / "gone1" / "t1.txt";
    const fs::path absent2 = base / "gone2" / "t2.txt";
    const fs::path trigger_file = trigger_dir / "t.txt";
    { std::ofstream(trigger_file) << "seed"; }

    struct DirCleanup {
        const fs::path& d;
        const fs::path& d2;
        ~DirCleanup() {
            std::error_code e;
            fs::remove_all(d, e);
            fs::remove_all(d2, e);
        }
    } dir_cleanup{base, trigger_dir}; // declared BEFORE mech, so it runs AFTER ~mech has closed handles

    struct Gate {
        std::mutex m;
        std::condition_variable cv;
        bool release{false};
        std::atomic<int> emit_calls{0};
        void wait() {
            emit_calls.fetch_add(1);
            std::unique_lock lk(m);
            cv.wait(lk, [&] { return release; });
        }
        void open() {
            {
                std::lock_guard lk(m);
                release = true;
            }
            cv.notify_all();
        }
    };
    auto gate = std::make_shared<Gate>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    // Same unconditional-open-on-unwind rationale as the #1979/#1982 and dirs_-zombie
    // tests above — without it, a failed assertion here wedges the worker forever and
    // hangs the whole test binary in ~mech's stop()/worker_.join().
    struct GateOpener {
        std::shared_ptr<Gate> g;
        ~GateOpener() { g->open(); }
    } gate_opener{gate};

    mech->start([gate](const std::string&, SparkData) { gate->wait(); },
                [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch("trigger", FileSparkParams{trigger_file.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the trigger's read arm
    { std::ofstream(trigger_file, std::ios::app) << "change"; } // fires → worker blocks in emit()
    // REQUIRE, not CHECK (governance Gate 8 cpp-safety finding) — see the sibling test
    // above for why.
    REQUIRE(eventually([&] { return gate->emit_calls.load() >= 1; }));
    // The worker is now wedged for the rest of this test.

    REQUIRE(mech->watch("k1", FileSparkParams{absent1.string()}).has_value());
    REQUIRE(mech->watch("k2", FileSparkParams{absent2.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the ancestor's own read genuinely arm

    // Drop the first dependent: refcount 2->1, release_ancestor() returns early (another
    // dependent still needs it) — no push_retiring call yet, so no fault to inject here.
    REQUIRE(set_file_retire_fault_hook_for_test(*mech, [] { throw std::bad_alloc{}; }));
    CHECK_NOTHROW(mech->unwatch("k1")); // no throw expected: release_ancestor didn't reach push_retiring
    REQUIRE(mech->stats().retiring == 0);

    // Drop the SECOND (last) dependent: refcount 1->0, release_ancestor() now reaches
    // push_retiring on the ancestor watch and hits the still-armed fault hook. unwatch()
    // itself must NOT throw and must NOT crash the worker thread — release_ancestor()'s
    // own try/catch contains it, leaving the ancestor watch whole in ancestors_ (removing,
    // cancelled) rather than propagating into the (for THIS call, still-contained-by-
    // watch_guarded) caller OR — the real risk this test pins — into the worker thread on
    // some other trigger. The hook is single-shot and is now consumed either way. The
    // worker is still wedged, so it cannot have raced this either.
    CHECK_NOTHROW(mech->unwatch("k2"));
    CHECK(mech->stats().retiring == 0); // release_ancestor caught the throw; nothing moved yet

    // A THIRD absent path resolving to the SAME ancestor. Pre-fix: arm_ancestor() would
    // silently attach to the zombie ancestor slot (already cancelled, awaiting reclaim) —
    // watch() reports success, but the fallback ancestor watch backing k3's eventual fire
    // is dead. Post-fix: arm_ancestor() drains the zombie into retiring_ FIRST (the
    // deterministic, in-process signal), then arms a genuinely fresh ancestor watch.
    // Deterministic either way: the worker is still wedged.
    const fs::path absent3 = base / "gone3" / "t3.txt";
    CHECK(mech->watch("k3", FileSparkParams{absent3.string()}).has_value());
    CHECK(mech->stats().retiring == 1);

    gate->open(); // let the worker catch up (the trigger's emit_ return, then the drains)

    const auto t0 = std::chrono::steady_clock::now();
    CHECK_NOTHROW(mech->stop());
    CHECK(std::chrono::steady_clock::now() - t0 < 5000ms);
    CHECK(mech->stats().quarantined_total == 0);
}

TEST_CASE("Registry spark (real mechanism): survives key delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    const std::string sub =
        "Software\\Yuzu\\SparkRes_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(h);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the target notify arm

    // Delete the watched key → the mechanism falls back to the ancestor NAME
    // watch on the parent (Software\Yuzu). The deletion is itself a Target-mode
    // notification, so it fires - wait for that fire, let any re-arm follow-up
    // land, and take the baseline AFTER it: the assertion below must be met by
    // a fire the RECREATE produced, not by the deletion's.
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    std::this_thread::sleep_for(500ms);
    const std::size_t after_delete = got.count();

    // Recreate it + write a value → the ancestor watch must re-resolve to the
    // target key and fire (the reappearance itself, and/or the write).
    HKEY h2 = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h2, nullptr) == ERROR_SUCCESS);
    const DWORD val = 7;
    ::RegSetValueExA(h2, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    INFO("fires after the deletion settled: " << after_delete);
    CHECK(eventually([&] { return got.count() > after_delete; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::Registry);
    engine.stop();
    ::RegCloseKey(h2);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

// ── T6 (#4181): same-type disarm() against an in-flight Inline callback ──────
//
// The shape (issue #4181, verified against the source at the time of writing):
//   Thread A: SparkEngine::disarm(K) takes mech_ops_mu_by_type_[Registry] and
//             calls mech->unwatch(K).
//   Thread B: the TP_WAIT callback for K is ALREADY inside on_fire -> emit ->
//             deliver -> an Inline handler when A starts.
// If unwatch(K) blocks until B's callback returns (a synchronous
// WaitForThreadpoolWaitCallbacks(TRUE) drain), and B's handler then calls back
// into the engine for the SAME type - here arm_inline() of a second Registry
// key, which needs the lock A holds - neither thread can proceed. A hang, not a
// data race, so no sanitizer sees it.
//
// Reproduced in a CHILD PROCESS on purpose: a genuine deadlock reproduced
// in-process would hang this binary's own cleanup. The child is the hidden
// ("[.]") case below, selected by EXACT NAME only (its tag list is deliberately
// nothing a tag filter would match); the parent bounds it and reads a timeout
// as the deadlock. Exit codes: 0 = scenario completed; 3 = the child itself
// observed the disarm not completing and force-exited (TerminateProcess, since
// a deadlocked thread cannot be joined); a parent-side kill = a hard hang.
namespace {
/// Test-side owners for the Win32 handles these cases open by hand (governance
/// sg-5/cs-6: new test C++ carries no manual cleanup). Closed on every exit path,
/// including a failed REQUIRE.
struct UniqueHandle {
    HANDLE h{nullptr};
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : h(handle) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    void reset(HANDLE handle = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE && h != handle)
            ::CloseHandle(h);
        h = handle;
    }
    [[nodiscard]] bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

/// Creates (or opens) a NAMED HKCU key for the test's lifetime; deletes it on
/// destruction. `h` is null when creation failed - callers REQUIRE it.
struct OwnedRegKey {
    std::string sub;
    HKEY h{nullptr};
    OwnedRegKey(std::string subkey, REGSAM sam) : sub(std::move(subkey)) {
        if (::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, sam, nullptr, &h,
                              nullptr) != ERROR_SUCCESS)
            h = nullptr;
    }
    ~OwnedRegKey() {
        if (h)
            ::RegCloseKey(h);
        ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    }
    OwnedRegKey(const OwnedRegKey&) = delete;
    OwnedRegKey& operator=(const OwnedRegKey&) = delete;
};

/// The T6 child's own exit code for "I observed the deadlock". Deliberately not
/// 3: Catch2 exits 3 itself when the command line matched no test case
/// (UnmatchedTestSpecExitCode), which would make a name drift between the
/// parent's macro and the child case read as a reproduced deadlock (qe-1).
constexpr DWORD kT6DeadlockExitCode = 100;

std::string t6_child_key() {
    char buf[512]{};
    const DWORD n = ::GetEnvironmentVariableA("YUZU_SPARK_T6_KEY", buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf))
        return std::string(buf, n);
    return "Software\\Yuzu\\SparkT6_" + std::to_string(::GetCurrentProcessId());
}
} // namespace

// One definition for both the TEST_CASE name and the child command line: the
// parent selects the child by EXACT name, so the two must never drift apart.
#define YUZU_SPARK_T6_CHILD_CASE_NAME "Registry T6 child: inline same-type re-arm during disarm"

TEST_CASE(YUZU_SPARK_T6_CHILD_CASE_NAME, "[.][t6-child]") {
    const std::string sub = t6_child_key();
    const std::string sub2 = sub + "\\Second";
    OwnedRegKey key(sub, KEY_SET_VALUE);
    REQUIRE(key.h != nullptr);
    HKEY h = key.h; // borrowed for the writes below; owned (and deleted) by `key`

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    std::atomic<bool> in_handler{false};
    std::atomic<bool> go{false};
    std::atomic<bool> rearmed{false};
    std::atomic<bool> rearm_done{false}; // the in-handler arm_inline() has RETURNED
    std::atomic<int> fires{0};
    std::mutex rearm_err_mu;
    std::string rearm_err; // written on the callback thread, read after the joins below
    // Inline tier: the handler runs SYNCHRONOUSLY on the TP_WAIT callback thread.
    auto sub_k = engine.arm_inline(registry_spec("HKCU", sub), [&](const SparkEvent&) {
        if (fires.fetch_add(1, std::memory_order_acq_rel) != 0)
            return; // only the first fire parks and re-enters
        in_handler.store(true, std::memory_order_release);
        while (!go.load(std::memory_order_acquire))
            std::this_thread::sleep_for(1ms);
        // Same-type re-entry FROM THE CALLBACK THREAD: needs mech_ops_mu_by_type_[Registry].
        auto s2 = engine.arm_inline(registry_spec("HKCU", sub2), [](const SparkEvent&) {});
        if (!s2) {
            std::lock_guard lk(rearm_err_mu);
            rearm_err = s2.error();
        }
        rearmed.store(s2.has_value(), std::memory_order_release);
        rearm_done.store(true, std::memory_order_release);
    });
    REQUIRE(sub_k.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the notify arm

    const DWORD v = 1;
    ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
    REQUIRE(eventually([&] { return in_handler.load(std::memory_order_acquire); }, 8000ms));

    // Thread A: disarm K while B's callback is parked inside the Inline handler.
    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*sub_k);
        disarm_done.store(true, std::memory_order_release);
    });
    // Give A time to reach unwatch(K) - and, on a pre-fix mechanism, to block
    // there on the callback drain - BEFORE B is released to re-enter the engine.
    std::this_thread::sleep_for(300ms);
    go.store(true, std::memory_order_release);

    const bool completed = eventually([&] { return disarm_done.load(std::memory_order_acquire); }, 5000ms);
    if (!completed) {
        // Deadlocked: A is inside the mechanism waiting for B, B is waiting for A's
        // lock. Neither thread can be joined, so a normal exit would hang here too.
        std::fputs("T6 child: disarm() did not complete while the Inline callback re-entered "
                   "the same type - deadlock observed\n",
                   stderr);
        std::fflush(stderr);
        ::TerminateProcess(::GetCurrentProcess(), kT6DeadlockExitCode);
    }
    CHECK(completed);
    disarmer.join();
    // disarm() completing is the deadlock half of the scenario; the re-entry half
    // is the handler's own arm_inline() RETURNING (with success). It runs on the
    // callback thread and is only ordered after disarm() by the old deadlock, so
    // wait for it explicitly rather than reading `rearmed` while it may still be
    // inside watch()'s bounded wait.
    CHECK(eventually([&] { return rearm_done.load(std::memory_order_acquire); }, 5000ms));
    {
        std::lock_guard lk(rearm_err_mu);
        INFO("same-type arm_inline from inside the Inline handler: "
             << (rearm_done.load(std::memory_order_acquire)
                     ? (rearm_err.empty() ? "returned ok" : rearm_err)
                     : "did not return within 5s"));
        CHECK(rearmed.load(std::memory_order_acquire));
    }
    engine.stop();
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub2.c_str()); // never created; belt and braces
    // `key` deletes `sub` on scope exit, after the engine is gone.
}

TEST_CASE("Registry spark: same-type disarm() does not deadlock against an in-flight Inline "
          "callback (T6, subprocess boundary)",
          "[spark][mechanism][windows][t6]") {
    wchar_t exe[MAX_PATH]{};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    REQUIRE((exe_len > 0 && exe_len < MAX_PATH)); // == MAX_PATH means truncated (xp-6)
    // The child reads its scratch key from the environment so the parent can clean
    // it up even when the child had to be killed mid-scenario.
    const std::string key = "Software\\Yuzu\\SparkT6_" + std::to_string(::GetCurrentProcessId());
    REQUIRE(::SetEnvironmentVariableA("YUZU_SPARK_T6_KEY", key.c_str()));

    std::wstring cmd = L"\"";
    cmd += exe;
    cmd += L"\" \"";
    {
        const std::string name = YUZU_SPARK_T6_CHILD_CASE_NAME;
        cmd.append(name.begin(), name.end()); // ASCII name
    }
    cmd += L"\" --reporter compact --durations no";

    // The child's own Catch2 output (its failure messages, INFO text) is the only
    // diagnostic a failing run leaves behind: capture it to a temp file through an
    // inheritable handle and surface it here.
    const std::filesystem::path child_log =
        std::filesystem::temp_directory_path() /
        ("yuzu_test_spark_t6_child_" + std::to_string(::GetCurrentProcessId()) + ".log");
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    UniqueHandle hlog(::CreateFileW(child_log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    REQUIRE(hlog.valid());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = hlog.h;
    si.hStdError = hlog.h;
    PROCESS_INFORMATION pi{};
    // cmd.data() is writable (CreateProcessW may modify lpCommandLine).
    const BOOL created = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE /*inherit*/,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    UniqueHandle hthread(pi.hThread); // both null if the create failed
    UniqueHandle hprocess(pi.hProcess);
    hlog.reset(); // the child holds its own inherited copy
    REQUIRE(created);
    hthread.reset();
    const DWORD wr = ::WaitForSingleObject(hprocess.h, 30000);
    if (wr == WAIT_TIMEOUT) {
        ::TerminateProcess(hprocess.h, 9);
        ::WaitForSingleObject(hprocess.h, 5000);
    }
    DWORD code = 0xFFFFFFFFu;
    ::GetExitCodeProcess(hprocess.h, &code);
    hprocess.reset();
    ::SetEnvironmentVariableA("YUZU_SPARK_T6_KEY", nullptr);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, (key + "\\Second").c_str());
    ::RegDeleteKeyA(HKEY_CURRENT_USER, key.c_str());
    std::string child_out;
    {
        std::ifstream in(child_log, std::ios::binary);
        child_out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::error_code ec;
    std::filesystem::remove(child_log, ec);

    INFO("T6 child: WaitForSingleObject=" << wr << " (0=exited, 258=timeout->killed) exit code="
                                          << code << " (0=completed, " << kT6DeadlockExitCode
                                          << "=child saw the deadlock, 3=Catch2 matched no case)");
    INFO("T6 child output:\n" << child_out);
    CHECK(wr == WAIT_OBJECT_0);
    CHECK(code == 0);
}

// ── #2012/#3840 PR-B1: Registry establishment off the per-type lock ──────────
//
// These cases drive the real Windows mechanism through its test seams
// (spark_mechanism.hpp: set_registry_test_controls_for_test /
// registry_debug_counters_for_test). The probe hook runs on the DETACHED probe
// worker, so a hook that parks models a hung hive without needing one; every
// case that parks a probe releases it before returning (a parked worker that
// outlived the test would be a real orphan at process exit).
namespace {

struct ScratchRegKey {
    std::string sub;
    HKEY h{nullptr};
    explicit ScratchRegKey(const char* tag) {
        static std::atomic<int> n{0};
        sub = std::string("Software\\Yuzu\\SparkB1_") + tag + "_" +
              std::to_string(::GetCurrentProcessId()) + "_" +
              std::to_string(yuzu::test::process_random_salt() % 1000000000) + "_" +
              std::to_string(n.fetch_add(1));
        ::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &h,
                          nullptr);
    }
    ~ScratchRegKey() {
        if (h)
            ::RegCloseKey(h);
        ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    }
    ScratchRegKey(const ScratchRegKey&) = delete;
    ScratchRegKey& operator=(const ScratchRegKey&) = delete;
    void write(DWORD v) const {
        ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
    }
};

/// Parks every probe of one subkey until release(); counts what it saw.
///
/// The hook is a shared_ptr shared with the probe job (spark_registry.cpp), so a probe worker
/// parked here can outlive the mechanism's destructor and would then re-lock a destroyed
/// `mu` once released. `inside` counts the calls currently between hook entry and hook exit;
/// it is the LAST thing a call touches (after its lock is dropped), and the destructor waits
/// for it to reach zero - bounded, so a stuck worker can never hang the test binary.
struct ProbeGate {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    std::atomic<int> parked{0};
    std::atomic<int> seen{0};
    std::atomic<int> inside{0};
    std::function<void(std::string_view)> hook_for(std::string match) {
        return [this, match](std::string_view sub) {
            struct Inside {
                std::atomic<int>& n;
                explicit Inside(std::atomic<int>& n_) : n(n_) {
                    n.fetch_add(1, std::memory_order_acq_rel);
                }
                ~Inside() { n.fetch_sub(1, std::memory_order_acq_rel); }
            } inside_scope{inside}; // declared first: destroyed last, after `lk` below
            seen.fetch_add(1, std::memory_order_relaxed);
            if (sub != match)
                return;
            parked.fetch_add(1, std::memory_order_acq_rel);
            std::unique_lock lk(mu);
            cv.wait(lk, [&] { return open; });
        };
    }
    void release() {
        {
            std::lock_guard lk(mu);
            open = true;
        }
        cv.notify_all();
    }
    ~ProbeGate() {
        release(); // never leave a worker parked past the test
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (inside.load(std::memory_order_acquire) > 0 &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
    }
};

std::size_t count_kind(Collector& got, const std::string& key, SparkEventKind kind) {
    std::lock_guard lk(got.mu);
    std::size_t n = 0;
    for (const auto& ev : got.events)
        if (ev.key == key && ev.kind == kind)
            ++n;
    return n;
}

/// Recorder for the #4340 establishment-signal cases that observe a mechanism's
/// sinks directly: the establishment sink and the fault callback append here in
/// dispatch order, so one log shows both the coverage sequence and where a Fault
/// sits relative to it. Not used by the engine-level cases, which read
/// SparkEngine::subscription_establishment() instead.
///
/// DECLARE IT BEFORE the mechanism or engine whose callbacks capture it. Locals
/// unwind in reverse declaration order, so a fatal REQUIRE then destroys the
/// mechanism (joining the thread that calls back) before this state, never after.
struct EstLog {
    struct Entry {
        enum class Kind { Established, Fault } kind{Kind::Established};
        std::string key;
        SparkIncarnation incarnation{kNoSparkIncarnation};
        std::chrono::steady_clock::time_point at{};
        SparkCoverage coverage{SparkCoverage::None};
        bool faulted{false};
    };
    std::mutex mu;
    std::vector<Entry> entries;
    std::vector<Entry> dropped; ///< reports the sink threw on instead of recording (see throw_if)
    std::size_t calls{0};       ///< sink invocations, delivered or dropped

    /// Optional fault injection, set BEFORE the mechanism starts. Called under
    /// `mu` with the 1-based invocation number and the report; returning true
    /// drops the report (it lands in `dropped`, not `entries`) and makes the
    /// sink throw.
    std::function<bool(std::size_t, const Entry&)> throw_if;
    /// Optional stall, set BEFORE the mechanism starts: right after recording
    /// invocation number `stall_on_call` (1-based; 0 = never) the sink blocks on
    /// `*stall` until the test releases it. That parks the calling mechanism
    /// thread off-lock, so a test can change mechanism state between two of its
    /// passes.
    std::size_t stall_on_call{0};
    ParkGate* stall{nullptr};

    SparkEstablishedFn sink() {
        return [this](const std::string& key, SparkIncarnation inc,
                      std::chrono::steady_clock::time_point at, SparkCoverage cov) {
            const Entry e{Entry::Kind::Established, key, inc, at, cov, false};
            std::size_t n = 0;
            bool drop = false;
            {
                std::lock_guard lk(mu);
                n = ++calls;
                drop = throw_if && throw_if(n, e);
                (drop ? dropped : entries).push_back(e);
            }
            if (drop)
                throw std::runtime_error("injected establishment-sink failure");
            if (stall && n == stall_on_call)
                stall->park();
        };
    }
    SparkFaultFn fault_sink() {
        return [this](const std::string& key, bool faulted, std::string_view) {
            std::lock_guard lk(mu);
            entries.push_back({Entry::Kind::Fault, key, kNoSparkIncarnation, {},
                               SparkCoverage::None, faulted});
        };
    }
    /// Every entry, in dispatch order.
    std::vector<Entry> all() {
        std::lock_guard lk(mu);
        return entries;
    }
    /// Only the establishment reports, in dispatch order (the coverage sequence).
    std::vector<Entry> established() {
        std::lock_guard lk(mu);
        std::vector<Entry> out;
        for (const auto& e : entries)
            if (e.kind == Entry::Kind::Established)
                out.push_back(e);
        return out;
    }
    std::size_t established_count() { return established().size(); }
    /// The reports for one key, in dispatch order.
    std::vector<Entry> for_key(const std::string& key) {
        std::vector<Entry> out;
        for (const auto& e : established())
            if (e.key == key)
                out.push_back(e);
        return out;
    }
    /// Delivered reports for `key`, any incarnation and coverage.
    std::size_t count_key_reports(const std::string& key) { return for_key(key).size(); }
    /// Delivered reports for `key` under incarnation `inc`, any coverage.
    std::size_t count(const std::string& key, SparkIncarnation inc) {
        std::size_t n = 0;
        for (const auto& e : established())
            if (e.key == key && e.incarnation == inc)
                ++n;
        return n;
    }
    /// A delivered report for `key` under `inc` carrying `cov`.
    bool has(const std::string& key, SparkIncarnation inc, SparkCoverage cov) {
        for (const auto& e : established())
            if (e.key == key && e.incarnation == inc && e.coverage == cov)
                return true;
        return false;
    }
    std::size_t calls_made() {
        std::lock_guard lk(mu);
        return calls;
    }
    std::vector<Entry> dropped_entries() {
        std::lock_guard lk(mu);
        return dropped;
    }
};

/// Opens a ParkGate on scope exit. Declare it AFTER the mechanism whose thread
/// may be parked on the gate: locals unwind in reverse order, so a failed
/// REQUIRE opens the gate first and the mechanism's stop() can then join that
/// thread instead of waiting on it forever.
struct OpenGateOnExit {
    ParkGate& gate;
    ~OpenGateOnExit() { gate.release(); }
};

/// True once `read()` has returned the same value for `quiet` straight, within
/// `deadline` overall - a bounded "nothing else is coming" check, used where a
/// persistent throw that were re-staged would keep the value climbing forever.
template <typename Read>
bool stable_for(Read read, std::chrono::milliseconds quiet, std::chrono::milliseconds deadline) {
    auto last = read();
    auto since = std::chrono::steady_clock::now();
    const auto until = since + deadline;
    while (std::chrono::steady_clock::now() < until) {
        std::this_thread::sleep_for(5ms);
        auto cur = read();
        if (cur != last) {
            last = cur;
            since = std::chrono::steady_clock::now();
        } else if (std::chrono::steady_clock::now() - since >= quiet) {
            return true;
        }
    }
    return false;
}

} // namespace

// ── #4340 (rung 9c PR-6 item 1): Registry establishment-signal ───────────────
//
// Mirrors spark_service.cpp's shipped M3 shape (#3840 PR-B3). Every case here
// only runs on Windows (the real mechanism is Windows-only). RF-1..RF-17 are
// the Registry establishment-signal cases; the FF- cases further below are the
// File counterparts (the File section header lists which ones pair up).
//
// What the assertions here do and do not pin. The `established_at == stamped`
// CHECKs in RF-4/6/8 and FF-4/6/8 restate the ENGINE's first-wins latch
// (SparkEngine::report_established) - they cannot fail on a mechanism defect.
// The engine side of "a loss and a recovery never re-stamp established_at" is
// pinned by the cross-platform case "Establishment: a fault-then-recovery cycle
// does not move established_at (E7)"; the mechanism side (which reports are
// sent, in which order, under which incarnation) only by the direct-sink cases
// RF-10/FF-10 and their siblings, which read the mechanism's sink rather than
// the engine's cache.

TEST_CASE("Registry mechanism (Windows, direct): set_established_sink seals at start(), still "
          "sealed after stop() (#4340 RF-1)",
          "[spark][established][windows]") {
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    CHECK(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->stop();
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {})); // one-way: still sealed after stop()
}

TEST_CASE("Registry spark (real mechanism): an existing target key reaches Notification "
          "coverage with a stamped established_at (#4340 RF-2)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_target");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): an absent target watches its ancestor with None "
          "coverage until the key is created (#4340 RF-3)",
          "[spark][established][windows]") {
    ScratchRegKey parent("est_absent_parent");
    const std::string target = parent.sub + "\\Missing"; // absent at arm time
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", target);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    // Ancestor-mode establishment settles quickly too (the parent exists),
    // but it must NEVER report Notification for the absent target - only
    // None, unconditionally, per the mode gate.
    std::this_thread::sleep_for(300ms);
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    // Create the target key - NO value write. The parent's NAME notification
    // fires; the re-arm resolves to Target and must stamp established_at.
    OwnedRegKey created(target, KEY_READ); // deleted on scope exit
    REQUIRE(created.h != nullptr);
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        8000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): an absent target under sibling-key churn keeps "
          "reading None with bounded probe launches and no leaked workers (CH-11, bounded "
          "regression scenario: 50 paced then 200 unpaced create+delete pairs, not proof of no "
          "unbounded growth)",
          "[spark][established][windows][walkoff]") {
    constexpr int kPacedPairs = 50;
    constexpr int kBurstPairs = 200;
    constexpr std::uint64_t kEventsPerPair = 2; // a name change for the create, one for the delete
    constexpr std::uint64_t kLaunchesPerEvent = 1; // on_fire launches at most one probe per fire
    constexpr std::uint64_t kPaced = static_cast<std::uint64_t>(kPacedPairs) * kEventsPerPair;
    constexpr std::uint64_t kBurst = static_cast<std::uint64_t>(kBurstPairs) * kEventsPerPair;
    ScratchRegKey parent("ch11_parent");
    const std::string target = parent.sub + "\\Missing"; // never created: Ancestor mode on `parent`
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms; // arm() returns with the watch committed and armed
        ctl.health_grace = 60000ms;      // keep Fault edges out of the zero-event oracle
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    auto sub = engine.arm(*c, registry_spec("HKCU", target));
    REQUIRE(sub.has_value());

    const auto snap = [&] { return *registry_debug_counters_for_test(*raw); };
    const auto idle = [&] { return snap().probe_workers_active == 0; };
    REQUIRE(eventually(idle, 5000ms));

    bool reading_stable = true;
    const auto observe = [&] {
        const auto est = engine.subscription_establishment(*sub);
        if (!est || est->coverage != SparkCoverage::None || est->established_at)
            reading_stable = false;
    };
    // Pacing only shapes the load: a timed-out wait, or a spent 30 s budget, is not a failure.
    const auto soak_until = std::chrono::steady_clock::now() + 30s;
    const auto paced_event = [&](auto&& mutate) {
        const auto before = snap().probe_launched;
        mutate();
        if (std::chrono::steady_clock::now() > soak_until)
            return;
        (void)eventually(
            [&] {
                const auto d = snap();
                return d.probe_launched > before && d.probe_workers_active == 0;
            },
            2000ms);
        observe();
    };
    const auto settle_and_bound = [&](std::uint64_t events) {
        REQUIRE(stable_for([&] { return snap().probe_launched; }, 100ms, 5000ms));
        REQUIRE(eventually(idle, 5000ms));
        const auto d = snap();
        const auto retries =
            d.probe_admission_rejected + d.probe_backend_failed + d.probe_launch_failed;
        INFO("probe_launched=" << d.probe_launched << " events=" << events
                               << " retries=" << retries);
        CHECK(d.probe_launched >= 2); // the noise reached the mechanism
        CHECK(d.probe_launched <= 1 + kLaunchesPerEvent * events + retries);
        CHECK(d.synthetic_fires == 0);
    };

    for (int i = 0; i < kPacedPairs; ++i) {
        std::unique_ptr<OwnedRegKey> sibling;
        paced_event([&] {
            sibling = std::make_unique<OwnedRegKey>(parent.sub + "\\Sib" + std::to_string(i),
                                                    KEY_READ);
            REQUIRE(sibling->h != nullptr);
        });
        paced_event([&] { sibling.reset(); });
    }
    settle_and_bound(kPaced);

    for (int i = kPacedPairs; i < kPacedPairs + kBurstPairs; ++i) {
        OwnedRegKey sibling(parent.sub + "\\Sib" + std::to_string(i), KEY_READ);
        REQUIRE(sibling.h != nullptr);
    }
    settle_and_bound(kPaced + kBurst);

    CHECK(reading_stable);
    const auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());
    CHECK(got.count() == 0); // Ancestor mode never emits
    const auto d = snap();
    CHECK(d.live_watches == 1);
    CHECK(d.retiring == 0);
    CHECK(d.drain_backlog == 0);
    CHECK(d.probe_workers_active == 0);
    CHECK(d.sweep_pass_failed == 0);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): an ordinary fire leaves a live re-armed watch and "
          "does not move established_at (#4340 RF-4)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_rearm");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto stamped = *est->established_at;

    // RegNotifyChangeKeyValue is one-shot: the write consumes
    // it, flapping coverage None -> Notification across the re-arm - a genuine
    // transition the pull query below is not guaranteed to observe mid-flight
    // (the None and the re-arm's Notification land on consecutive sweep
    // passes), so this asserts only the settled before/after
    // states, not the transient None.
    const auto before = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    a.write(1);
    REQUIRE(eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > before; }, 8000ms));
    // The post-fire Notification is ALREADY true from the pre-fire cache, so
    // waiting for it says nothing about the re-arm. What does: one consumed
    // notify costs the immediate emit PLUS the re-arm commit's synthetic emit,
    // so once both landed the re-arm has committed - and a SECOND write must
    // then fire through the re-armed notify (a mechanism that lost the re-arm
    // would never deliver it).
    REQUIRE(eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) >= before + 2; },
        8000ms));
    const auto settled = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    a.write(2);
    REQUIRE(eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > settled; }, 8000ms));
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        8000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    // Restates the engine's first-wins latch (see the section header above).
    CHECK(*est->established_at == stamped);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): a parked initial probe leaves coverage None until "
          "release, then stamps established_at (#4340 RF-5)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_late");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    ProbeGate gate;
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    RegistryMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.sub);
    REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value()); // success-with-pending (the call's local
                              // discards is never dispatched - only the mark on
                              // `w` itself, which survives, carries the report)
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    std::this_thread::sleep_for(200ms); // well past the 50 ms caller budget/sweep cadence
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    const auto t_release = std::chrono::steady_clock::now();
    gate.release();
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        5000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= t_release);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): deleting the target loses coverage without "
          "re-stamping, recreate restores Notification (#4340 RF-6)",
          "[spark][established][windows]") {
    // ScratchRegKey deletes whatever key exists at `sub` on scope exit, so a
    // failed REQUIRE below never leaks it. Its own handle is closed up front:
    // the mechanism's watch is then the only open handle, and deleting a key
    // with another handle still open would leave it pending-deleted (a
    // re-create would then fail with ERROR_KEY_DELETED).
    ScratchRegKey key("est_delete");
    REQUIRE(key.h != nullptr);
    ::RegCloseKey(key.h);
    key.h = nullptr;
    const std::string& sub = key.sub;

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    auto s = engine.arm(*c, spec);
    REQUIRE(s.has_value());
    engine.start();

    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*s);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*s);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto stamped = *est->established_at;

    REQUIRE(::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str()) == ERROR_SUCCESS);
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*s);
            return e.has_value() && e->coverage == SparkCoverage::None;
        },
        8000ms));
    est = engine.subscription_establishment(*s);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // loss of coverage never un-stamps established_at

    HKEY h2 = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h2, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(h2);
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*s);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        10000ms));
    est = engine.subscription_establishment(*s);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // still first-wins - recovery never re-stamps

    engine.disarm(*s);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): a disarm racing a re-arm (adoption) still lets "
          "the mechanism report establishment against the fresh incarnation (#4340 RF-7)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_adopt");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    auto sub1 = engine.arm(*c, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub1);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));

    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c, spec); // dedup: same key -> the engine renews the
                                           // existing armed_ entry, skipping unwatch()
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());

    REQUIRE(eventually(
        [&] {
            auto est = engine.subscription_establishment(*sub2);
            return est.has_value() && est->coverage == SparkCoverage::Notification;
        },
        5000ms));
    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at); // never predates the adopting arm
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);

    engine.disarm(*sub2);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): a failed re-arm reports None until the retry "
          "recovers, established_at unchanged (#4340 RF-8)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_backend_fail");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = registry_spec("HKCU", a.sub);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto stamped = *est->established_at;

    // Every re-arm probe of `a` now throws inside the worker (WorkerThrew -> a
    // backend failure), on a shortened retry schedule - the initial probe
    // above already succeeded, so only the SECOND (re-arm) probe is affected.
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = [sub_key = a.sub](std::string_view s) {
            if (s == sub_key)
                throw std::runtime_error("simulated re-arm failure");
        };
        ctl.backend_retry_base = 150ms;
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    a.write(1); // consumes the notify: on_fire marks None; the re-arm probe throws
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::None;
        },
        8000ms));
    REQUIRE(eventually([&] { return engine.stats().armed_faulted == 1; }, 5000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // a fault never un-stamps established_at

    // Clear the hook: the next scheduled retry recovers the watch.
    {
        RegistryMechanismTestControls ctl; // null hook clears it; timings unchanged
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    REQUIRE(eventually([&] { return engine.stats().armed_faulted == 0; }, 10000ms));
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        5000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // still first-wins

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): a fast-committing key armed while the sweeper is idle "
          "is reported promptly instead of waiting out the idle ceiling (#4340 RF-9)",
          "[spark][established][windows]") {
    ScratchRegKey warm("est_fast_warm"), a("est_fast");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    std::atomic<std::size_t> passes{0}; // sweeper passes so far (sweep_hook below)
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    {
        // A caller budget far above any probe latency, so the key below commits INSIDE
        // watch_incarnation's own wait - the fast-commit path this case is about - and never
        // via the published-pending path (which nudges the sweeper separately).
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        ctl.sweep_hook = [&passes] { passes.fetch_add(1, std::memory_order_relaxed); };
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    // Warm-up: arm one key and wait for its report, so the sweeper has run a pass and gone
    // back to its idle wait (next_wake_locked's 1 h ceiling, nothing due). A key armed
    // straight after start() can be caught by the sweeper's very first wake computation - its
    // probe is still Pending then, so the wake is only ~50 ms away - which would hide a
    // missing nudge entirely.
    const auto warm_spec = registry_spec("HKCU", warm.sub);
    auto warm_sub = engine.arm(*c, warm_spec);
    REQUIRE(warm_sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*warm_sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    // The sweeper is idle once no further pass has started for 300 ms (a bounded observation,
    // not a bare sleep: a sweeper that never settles fails here instead of hiding the nudge).
    REQUIRE(stable_for([&] { return passes.load(std::memory_order_relaxed); }, 300ms, 5000ms));

    // The oracle: this key commits inside its own arm() call, marks its report due, and only
    // the fast-commit nudge in watch_incarnation wakes the idle sweeper to stage it. Without
    // the nudge the report would wait for the 1 h ceiling and this wait would time out.
    // `established_at` itself is the mechanism's COMMIT time, so its distance from `armed_at`
    // measures the probe's latency, not the report's delivery - deliberately not bounded here
    // (a loaded runner would fail such a bound without any mechanism defect).
    const auto spec = registry_spec("HKCU", a.sub);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually(
        [&] {
            auto est = engine.subscription_establishment(*sub);
            return est.has_value() && est->coverage == SparkCoverage::Notification;
        },
        3000ms));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.disarm(*warm_sub);
    engine.stop();
}

TEST_CASE("Registry mechanism (Windows, direct): the establishment sink reports the ordered "
          "coverage sequence [Notification, None, Notification] against a fixed incarnation, "
          "and the fire-consumed None is dispatched strictly before the synthetic emit that "
          "closes the gap (#4340 RF-10)",
          "[spark][established][windows]") {
    // Direct (no engine) so a real SparkIncarnation token can be supplied and
    // every report's identity checked - the engine-level pull query
    // (subscription_establishment) cannot reliably observe a transient None
    // mid-flap, and it never exposes dispatch ORDER at
    // all. Ordering against the SYNTHETIC (resync) emit specifically - not
    // the immediate on_fire emit, which races the sweeper's own wake on a
    // different thread and is not deterministically orderable - is proven by
    // construction here: the ProbeGate below holds the re-arm probe parked,
    // so commit_locked (the ONLY place that stages the synthetic emit) cannot
    // have run until AFTER release(), by which point the None report has
    // already been observed.
    ScratchRegKey a("est_direct_seq");
    // Everything a callback or hook below captures is declared BEFORE `mech`:
    // locals unwind in reverse order, so a fatal REQUIRE must destroy `mech`
    // (which joins the threads that call back) before this state.
    ProbeGate gate;
    EstLog log;
    std::atomic<int> emits{0};
    auto mech = make_registry_mechanism();
    REQUIRE(mech);

    // A caller budget far above any probe latency makes the initial probe
    // commit deterministically INSIDE watch_incarnation's own wait, so the
    // sequence below starts at Notification (never a published-pending None).
    // Set in its own call: scalar controls persist across the later
    // probe_hook call.
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([&](const std::string&, SparkData) { emits.fetch_add(1, std::memory_order_acq_rel); },
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kToken = 42;
    const auto spec = registry_spec("HKCU", a.sub);
    REQUIRE(mech->watch_incarnation(spark_key(spec), spec.params, kToken).has_value());

    // Initial establishment: Notification, token 42, no emit yet ("an initial
    // establishment never emits" - matches the existing appearance test).
    REQUIRE(eventually([&] { return log.established_count() >= 1; }));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 1);
        CHECK(seq[0].incarnation == kToken);
        CHECK(seq[0].coverage == SparkCoverage::Notification);
    }
    CHECK(emits.load() == 0);

    // Park every FUTURE probe of `a` - the re-arm only (the initial one
    // already resolved above without this hook installed).
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.sub);
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }

    a.write(1); // consumes the one-shot notify: on_fire marks None and
                // fires the immediate emit; the re-arm probe launches and parks.
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    REQUIRE(eventually([&] { return log.established_count() >= 2; }, 8000ms));
    {
        const auto seq = log.established();
        CHECK(seq[1].incarnation == kToken);
        CHECK(seq[1].coverage == SparkCoverage::None);
    }
    // The immediate fire is emitted from the TP_WAIT callback thread,
    // concurrently with the sweeper dispatching the None above, so wait for it
    // rather than sampling: the baseline below must include it.
    REQUIRE(eventually([&] { return emits.load(std::memory_order_acquire) >= 1; }, 5000ms));
    const int emits_while_parked = emits.load(std::memory_order_acquire);

    // The synthetic (resync) emit cannot land while the re-arm stays parked:
    // established(None) above is therefore dispatched strictly before it.
    std::this_thread::sleep_for(200ms);
    CHECK(emits.load(std::memory_order_acquire) == emits_while_parked);

    gate.release();
    REQUIRE(eventually(
        [&] { return emits.load(std::memory_order_acquire) > emits_while_parked; }, 5000ms));
    REQUIRE(eventually([&] { return log.established_count() >= 3; }, 8000ms));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 3);
        CHECK(seq[2].incarnation == kToken);
        CHECK(seq[2].coverage == SparkCoverage::Notification);
    }

    mech->stop();
}

TEST_CASE("Registry mechanism (Windows, direct): an establishment report and an action staged "
          "in the SAME sweep visit dispatch in established-before-action order (#4340 RF-11)",
          "[spark][established][windows]") {
    // RF-10 above pins ordering ACROSS sweep passes only (it parks the re-arm
    // probe precisely so the None report and the synthetic emit land in
    // different passes) - a swap of run_off_lock()'s two dispatch loops would
    // still pass it. This case forces
    // both into ONE pass, deterministically and without any sleep:
    //  * the initial probe is parked, so watch_incarnation() returns
    //    success-with-pending and, in ONE mu_ hold, publishes w->call, marks
    //    None due and nudges the sweeper;
    //  * health_grace is 1 ms (far below the 50 ms caller budget already spent
    //    by then), so the FIRST sweep visit that can see the published call
    //    finds the grace already blown: within that single visit sweep_locked()
    //    drains the None marker into work.established (before the switch) and
    //    then, in the same visit, grace_check_locked()'s faulted_now flip
    //    stages a Fault action into work.actions;
    //  * an earlier visit cannot interfere: a Pending watch with no published
    //    call is a no-op (no grace check, nothing due).
    // Both entries therefore belong to the same run_off_lock() call, and one
    // shared, mutex-guarded log records the real dispatch order. A Fault
    // stands in for an Emit because an Emit is only ever
    // staged by a commit, which re-marks Notification due strictly AFTER the
    // drain (never the same visit) - and Fault and Emit share the one
    // work.actions loop, so this pins the identical established-before-
    // actions property.
    ScratchRegKey a("est_same_pass");
    // Everything a callback or hook below captures is declared BEFORE `mech`
    // (see EstLog): a fatal REQUIRE must join the mechanism's threads first.
    ProbeGate gate;
    EstLog log;
    auto mech = make_registry_mechanism();
    REQUIRE(mech);

    REQUIRE(mech->set_established_sink(log.sink()));
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.sub);
        ctl.health_grace = 1ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {}, log.fault_sink());

    constexpr SparkIncarnation kToken = 42;
    const auto spec = registry_spec("HKCU", a.sub);
    REQUIRE(mech->watch_incarnation(spark_key(spec), spec.params, kToken).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    REQUIRE(eventually([&] { return log.all().size() >= 2; }, 8000ms));
    {
        const auto seq = log.all();
        CHECK(seq[0].kind == EstLog::Entry::Kind::Established); // established FIRST...
        CHECK(seq[0].incarnation == kToken);
        CHECK(seq[0].coverage == SparkCoverage::None);
        CHECK(seq[1].kind == EstLog::Entry::Kind::Fault); // ...then the same-visit action
        CHECK(seq[1].faulted);
    }

    gate.release();
    REQUIRE(eventually(
        [&] {
            for (const auto& e : log.established())
                if (e.coverage == SparkCoverage::Notification)
                    return true;
            return false;
        },
        8000ms));

    mech->stop();
    CHECK(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; },
        5000ms));
}

// ── #4340 establishment signal: failure and race coverage (Registry) ─────────
//
// The cases below aim faults at the establishment-report path using only
// existing seams. Two seam traps apply to every one of them:
//  * set_registry_test_controls_for_test REPLACES every hook on each call, so
//    all hooks go in ONE struct (scalars persist across calls);
//  * everything a hook, sink or stall captures is declared BEFORE `mech`, so a
//    fatal REQUIRE joins the mechanism's threads before that state is destroyed.
// emit_bookkeeping_hook is the one deterministic throw-or-park point between a
// pass staging its reports and dispatching them, but it fires only on a pass
// that staged a probe LAUNCH. RF-12 and RF-17 therefore line a report and a
// launch up in ONE pass without any sleep-based positive: a one-slot probe lane
// held full by a parked probe makes every later watch admission-refused and
// Deferred, so its retries are launches the sweeper stages on a backoff, and the
// hook parks the sweeper (off-lock) on the first of them while the test changes
// what the NEXT pass will stage.

TEST_CASE("Registry mechanism (Windows, direct): a pass that throws AFTER staging an "
          "establishment report re-delivers it on a later pass, and a sibling's retry is not "
          "stranded (#4340 RF-12)",
          "[spark][established][windows]") {
    // Recipe (see the section comment above for why):
    //  * lane cap 1 + S's parked probe keep the lane full, so B and B2 are
    //    admission-refused and Deferred;
    //  * pass N (B's first retry launch) parks the sweeper in the hook;
    //  * while it is parked the test ADOPTS A (a watch_incarnation on an existing
    //    key marks its report due, no probe needed) and registers B2 (due ~50 ms
    //    later); a lower-bound sleep then guarantees B2 is due, and nothing can
    //    visit A or B2 because the sweeper is parked;
    //  * releasing the hook lets pass N finish; the very next pass (N+1) stages A's
    //    report AND B2's launch, and the hook's second call throws.
    // unwind_pass_locked must re-mark A's report or it is lost: the marker was
    // cleared when the report was staged.
    ScratchRegKey a("est_unwind_a"), s("est_unwind_s"), b("est_unwind_b"), b2("est_unwind_b2");
    ProbeGate occupy;
    ParkGate hook_park;
    std::atomic<int> hook_calls{0};
    std::atomic<bool> threw{false};
    EstLog log;
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    OpenGateOnExit open_hook{hook_park}; // after `mech`: a failed REQUIRE unparks the sweeper first

    // Phase 1: a caller budget far above any probe latency, so A commits inside its own
    // watch_incarnation call; lane cap 1; health grace out of the way (no Fault noise).
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_lane_cap = 1;
        ctl.caller_wait_budget = 5000ms;
        ctl.health_grace = 60000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kA = 42, kS = 51, kB = 61, kB2 = 62;
    const auto spec_a = registry_spec("HKCU", a.sub);
    const auto spec_s = registry_spec("HKCU", s.sub);
    const auto spec_b = registry_spec("HKCU", b.sub);
    const auto spec_b2 = registry_spec("HKCU", b2.sub);
    const std::string key_a = spark_key(spec_a), key_s = spark_key(spec_s),
                      key_b = spark_key(spec_b), key_b2 = spark_key(spec_b2);

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kA).has_value());
    REQUIRE(eventually([&] { return log.has(key_a, kA, SparkCoverage::Notification); }));
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));

    // Phase 2: park S's probe (it occupies the one lane slot); short caller budget; fast
    // admission backoff; the hook parks on its first call and throws on its second.
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = occupy.hook_for(s.sub);
        ctl.emit_bookkeeping_hook = [&] {
            const int n = hook_calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (n == 1) {
                hook_park.park(); // pass N
            } else if (n == 2) {
                threw.store(true, std::memory_order_release);
                throw std::runtime_error("injected failure after a report was staged");
            }
        };
        ctl.caller_wait_budget = 40ms;
        ctl.admission_backoff_seed = 50ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->watch_incarnation(key_s, spec_s.params, kS).has_value()); // pending: S's probe parks
    REQUIRE(eventually([&] { return occupy.parked.load() == 1; }, 2000ms));
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, kB).has_value()); // lane full: Deferred
    REQUIRE(hook_park.wait_entered(8000ms)); // pass N (B's first retry launch): sweeper parked

    // While the sweeper is parked: A's report becomes due, B2 becomes due ~50 ms from now.
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kA).has_value());
    REQUIRE(mech->watch_incarnation(key_b2, spec_b2.params, kB2).has_value());
    std::this_thread::sleep_for(200ms); // a LOWER bound only: nothing can visit B2 while parked
    hook_park.release();

    REQUIRE(eventually([&] { return threw.load(std::memory_order_acquire); }, 8000ms));
    // The report A's adoption staged in the pass that threw must arrive on a later pass.
    REQUIRE(eventually([&] { return log.count(key_a, kA) >= 2; }, 8000ms));

    // The siblings are not stranded: once S's probe completes the lane frees and every retry
    // establishes for real.
    occupy.release();
    REQUIRE(eventually(
        [&] {
            return log.has(key_s, kS, SparkCoverage::Notification) &&
                   log.has(key_b, kB, SparkCoverage::Notification) &&
                   log.has(key_b2, kB2, SparkCoverage::Notification);
        },
        10000ms));
    CHECK(log.count(key_a, kA) == 2); // the initial report + exactly one re-delivery
    CHECK(registry_debug_counters_for_test(*mech)->sweep_pass_failed >= 1);

    mech->stop();
    CHECK(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));
}

TEST_CASE("Registry mechanism (Windows, direct): a throwing establishment sink is contained - "
          "the drop is counted, the rest of the batch is delivered, the sweeper survives and "
          "the dropped report is not re-staged (#4340 RF-13)",
          "[spark][established][windows]") {
    ScratchRegKey k1("est_thr_1"), k2("est_thr_2"), k3("est_thr_3");
    ParkGate stall;
    EstLog log;
    log.stall_on_call = 1; // the first delivery (k1's initial report) parks the sweeper in the sink
    log.stall = &stall;
    log.throw_if = [](std::size_t n, const EstLog::Entry&) { return n == 2; };
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    OpenGateOnExit open_stall{stall}; // after `mech`: a failed REQUIRE unparks the sweeper first
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    const auto spec1 = registry_spec("HKCU", k1.sub);
    const auto spec2 = registry_spec("HKCU", k2.sub);
    const auto spec3 = registry_spec("HKCU", k3.sub);
    const std::string key1 = spark_key(spec1), key2 = spark_key(spec2), key3 = spark_key(spec3);

    REQUIRE(mech->watch_incarnation(key1, spec1.params, 51).has_value());
    REQUIRE(stall.wait_entered(8000ms)); // the sweeper is parked INSIDE the sink, off-lock
    // While it is parked k2 and k3 establish, so both reports are due before its next visit and
    // are staged as ONE batch: the first of them is delivery #2, which throws.
    REQUIRE(mech->watch_incarnation(key2, spec2.params, 52).has_value());
    REQUIRE(mech->watch_incarnation(key3, spec3.params, 53).has_value());
    stall.release();

    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->established_failed == 1; }, 8000ms));
    REQUIRE(eventually([&] { return log.established_count() >= 2; }, 8000ms));
    const auto dropped = log.dropped_entries();
    REQUIRE(dropped.size() == 1);
    // Exactly one of k2/k3 was dropped; the OTHER one, later in the same batch, was delivered.
    const std::string& dropped_key = dropped[0].key;
    const std::string& other_key = dropped_key == key2 ? key3 : key2;
    CHECK((dropped_key == key2 || dropped_key == key3));
    CHECK(log.count_key_reports(other_key) == 1);
    CHECK(log.count_key_reports(dropped_key) == 0);

    // The sweeper survived: a later real transition (k1's write consumes its one-shot notify)
    // still reports - the None, then the re-arm's Notification.
    k1.write(1);
    REQUIRE(eventually([&] { return log.for_key(key1).size() >= 3; }, 8000ms));

    // No re-stage: once everything settled nothing else is delivered or attempted, and the
    // dropped report never shows up later.
    REQUIRE(stable_for([&] { return log.calls_made(); }, 600ms, 8000ms));
    CHECK(registry_debug_counters_for_test(*mech)->established_failed == 1);
    CHECK(log.count_key_reports(dropped_key) == 0);
    mech->stop();
}

TEST_CASE("Registry mechanism (Windows, direct): stop() with a staged but unserved None marker "
          "drops it undispatched and returns once the parked sweeper is released "
          "(CH-8, characterisation)",
          "[spark][established][windows]") {
    struct Ch8 {
        std::atomic<int> fires{0};
        std::atomic<bool> stop_returned{false};
        ParkGate gate;
        EstLog log;
    };
    ScratchRegKey a("est_ch8");
    const auto st = std::make_shared<Ch8>();
    auto& gate = st->gate;
    auto& log = st->log;
    log.stall_on_call = 1; // the initial Notification report parks the sweeper inside the sink
    log.stall = &gate;
    std::unique_ptr<ISparkMechanism> mech = make_registry_mechanism();
    REQUIRE(mech);
    ISparkMechanism* const mp = mech.get();
    std::jthread stopper; // not joinable until the stop() call below
    OpenGateOnExit open_gate{gate}; // after `stopper`: the gate opens BEFORE the join
    bool wedged = false;
    struct LeakIfWedged {
        std::unique_ptr<ISparkMechanism>& m;
        std::jthread& t;
        const bool& wedged;
        ~LeakIfWedged() {
            if (wedged) {
                (void)m.release(); // a stop() that never returns can never be joined
                t.detach();
            }
        }
    } leak_if_wedged{mech, stopper, wedged};

    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(
        [st](const std::string&, SparkData) { st->fires.fetch_add(1, std::memory_order_acq_rel); },
        [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kInc = 71;
    const auto spec = registry_spec("HKCU", a.sub);
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, kInc).has_value());
    REQUIRE(gate.wait_entered(8000ms)); // the sweeper is parked INSIDE the sink, off-lock
    REQUIRE(log.has(key, kInc, SparkCoverage::Notification));

    // on_fire stages the None marker under mu_ before it emits, so a fire that has been
    // emitted proves the marker is staged; the parked sweeper cannot drain it.
    a.write(1);
    REQUIRE(eventually([&] { return st->fires.load(std::memory_order_acquire) >= 1; }, 8000ms));
    REQUIRE(log.calls_made() == 1);

    stopper = std::jthread([st, mp] {
        mp->stop();
        st->stop_returned.store(true, std::memory_order_release);
    });
    // watch_incarnation refuses once stop() has set `stopping_`, in the same critical
    // section as the sweeper's stop flag: stop() is now blocked joining the parked sweeper.
    REQUIRE(eventually([&] { return !mech->watch_incarnation(key, spec.params, kInc).has_value(); },
                       5000ms));
    std::this_thread::sleep_for(300ms);
    CHECK_FALSE(st->stop_returned.load(std::memory_order_acquire)); // weak: a negative window
    gate.release();
    if (!eventually([&] { return st->stop_returned.load(std::memory_order_acquire); }, 10000ms)) {
        wedged = true;
        FAIL("stop() did not return within 10 s of the parked sweeper being released");
    }
    stopper.join();

    CHECK_FALSE(log.has(key, kInc, SparkCoverage::None));
    CHECK(log.count(key, kInc) == 1);
    CHECK(log.calls_made() == 1);
    CHECK(stable_for([&] { return log.calls_made(); }, 300ms, 3000ms));
    const auto d = registry_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->live_watches == 0);
    CHECK(d->established_failed == 0);
    CHECK(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; },
        5000ms));
}

TEST_CASE("Registry mechanism (Windows, direct): a dropped None is never re-sent - the last "
          "delivered Notification stays (accepted residual) and the sweeper does not spin "
          "(#4340 RF-14)",
          "[spark][established][windows]") {
    // CHARACTERISED, ACCEPTED RESIDUAL: a report the sink throws on is dropped, not re-staged
    // (re-staging a persistent throw would spin the sweeper). Whatever the engine cached last
    // therefore stays. Registry heals this on the next mark - every fire's re-arm commit marks
    // again - so it bites only when no later mark comes: here the target is deleted, the
    // re-arm resolves to the ancestor (a stable None) and every None is dropped, so the last
    // delivered value stays Notification although the true coverage is None. The production
    // engine sink takes only the engine lock and cannot realistically throw. A dropped report
    // raises no Fault and sets no inert flag, so a consumer's health checks cannot detect it
    // (see the design doc's consumer preconditions).
    ScratchRegKey k("est_thr_resid");
    EstLog log;
    log.throw_if = [](std::size_t, const EstLog::Entry& e) {
        return e.coverage == SparkCoverage::None;
    };
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    const auto spec = registry_spec("HKCU", k.sub);
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, 61).has_value());
    REQUIRE(eventually([&] { return log.has(key, 61, SparkCoverage::Notification); }));

    // Close the scratch key's own handle so the mechanism's watch is the only one open, then
    // delete the target: its one-shot notify fires and the re-arm resolves to the ancestor.
    ::RegCloseKey(k.h);
    k.h = nullptr;
    REQUIRE(::RegDeleteKeyA(HKEY_CURRENT_USER, k.sub.c_str()) == ERROR_SUCCESS);
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->established_failed >= 1; }, 8000ms));
    // Bounded "nothing else is coming": a re-staged persistent throw would keep this climbing.
    REQUIRE(stable_for([&] { return log.calls_made(); }, 600ms, 8000ms));

    const auto seq = log.for_key(key);
    REQUIRE(seq.size() == 1); // only the initial Notification was ever delivered
    CHECK(seq[0].coverage == SparkCoverage::Notification); // ...and it is stale (accepted residual)
    const auto dropped = log.dropped_entries();
    CHECK(registry_debug_counters_for_test(*mech)->established_failed == dropped.size());
    for (const auto& d : dropped)
        CHECK(d.coverage == SparkCoverage::None);
    mech->stop();
}

TEST_CASE("Registry mechanism (Windows, direct): unwatch() and an orderly stop() report nothing "
          "(#4340 RF-15)",
          "[spark][established][windows]") {
    // Deliberate non-reports: the engine has already erased armed_[key] when unwatch() runs (so a
    // None would be dropped by identity anyway) and stop() marks no transition. Nothing here can
    // be waited FOR, so each check is a bounded negative window.
    ScratchRegKey k1("est_nonrep_1"), k2("est_nonrep_2");
    EstLog log;
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    const auto spec1 = registry_spec("HKCU", k1.sub);
    const auto spec2 = registry_spec("HKCU", k2.sub);
    const std::string key1 = spark_key(spec1), key2 = spark_key(spec2);

    REQUIRE(mech->watch_incarnation(key1, spec1.params, 71).has_value());
    REQUIRE(mech->watch_incarnation(key2, spec2.params, 72).has_value());
    REQUIRE(eventually([&] { return log.established_count() >= 2; }));

    mech->unwatch(key1);
    std::this_thread::sleep_for(500ms);
    CHECK(log.established_count() == 2); // unwatch() added no report (no None for key1)

    mech->stop();
    std::this_thread::sleep_for(300ms);
    CHECK(log.established_count() == 2); // an orderly stop() added none either
    CHECK(log.for_key(key2).size() == 1);
}

TEST_CASE("Registry mechanism (Windows, direct): an incarnation rebind on an existing key is "
          "forward-only - a lower incarnation never replaces a higher one (#4340 RF-16)",
          "[spark][established][windows]") {
    ScratchRegKey k("est_rebind");
    EstLog log;
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    const auto spec = registry_spec("HKCU", k.sub);
    const std::string key = spark_key(spec);

    // 42 -> 50 (a higher incarnation rebinds), then 50 -> 42 (a lower one must NOT).
    REQUIRE(mech->watch_incarnation(key, spec.params, 42).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 1; }));
    REQUIRE(mech->watch_incarnation(key, spec.params, 50).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 2; }));
    REQUIRE(mech->watch_incarnation(key, spec.params, 42).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 3; }));
    REQUIRE(stable_for([&] { return log.for_key(key).size(); }, 400ms, 5000ms));

    const auto seq = log.for_key(key);
    REQUIRE(seq.size() == 3);
    CHECK(seq[0].incarnation == 42);
    CHECK(seq[1].incarnation == 50); // forward rebind: the re-report carries the new incarnation
    CHECK(seq[2].incarnation == 50); // NOT 42: a later, lower incarnation never wins
    for (const auto& e : seq)
        CHECK(e.coverage == SparkCoverage::Notification);
    mech->stop();
}


TEST_CASE("Registry mechanism (Windows, direct): a fire, an unwatch and a re-watch landing "
          "between a report being staged and dispatched leave the new incarnation clean, and a "
          "sink that re-enters unwatch()/watch_incarnation() does not deadlock (#4340 RF-17)",
          "[spark][established][windows]") {
    // Aimed with the same one-slot-lane recipe as RF-12, but the hook's SECOND call PARKS
    // instead of throwing: the sweeper then sits with A's incarnation-X report STAGED and not
    // yet dispatched (off-lock), and the test does what a consumer's arm/disarm churn could:
    // A fires, A is unwatched, A is re-watched under a fresh incarnation Y. Releasing the
    // sweeper dispatches the now-stale X report. It reaches a sink that re-enters the
    // mechanism on a sacrificial key (unwatch + watch_incarnation, both take mu_) - a
    // #4181-shaped tripwire: if the sink were ever called with mu_ held this deadlocks.
    //
    // THE DELIBERATE LEAK. A genuinely wedged sweeper holds mu_ forever, so ~mech's join would
    // hang the whole test binary. LeakIfWedged therefore leaks the mechanism, but ONLY on a
    // proven wedge (the re-entry started and did not return within the bound); any other
    // failure lets ~mech join cleanly once the gates are open. A leaked mechanism's threads may
    // keep running, so everything they can touch is co-leaked: the sink, the emit callback and
    // the hooks each hold the shared `Race` block by value (the mechanism owns those
    // closures, so a leaked mechanism keeps the block alive), and the sink captures its keys
    // and params by value and the mechanism by raw pointer (valid for as long as the leak is).
    // Nothing they can reach lives on this test's stack.
    ScratchRegKey a("est_race_a"), sac("est_race_sac"), s("est_race_s"), b("est_race_b"),
        b2("est_race_b2");
    constexpr SparkIncarnation kX = 42, kY = 43, kSac = 80, kS = 51, kB = 61, kB2 = 62;
    const auto spec_a = registry_spec("HKCU", a.sub);
    const auto spec_sac = registry_spec("HKCU", sac.sub);
    const auto spec_s = registry_spec("HKCU", s.sub);
    const auto spec_b = registry_spec("HKCU", b.sub);
    const auto spec_b2 = registry_spec("HKCU", b2.sub);
    const std::string key_a = spark_key(spec_a), key_sac = spark_key(spec_sac),
                      key_s = spark_key(spec_s), key_b = spark_key(spec_b),
                      key_b2 = spark_key(spec_b2);
    struct Race {
        ProbeGate occupy;
        ParkGate hook_park1, hook_park2;
        std::atomic<int> hook_calls{0};
        std::atomic<int> emits{0};
        std::atomic<bool> stale_phase{false}, reentered{false}, reentry_done{false},
            reentry_ok{false};
        EstLog log;
    };
    const auto st = std::make_shared<Race>();
    auto& log = st->log;
    auto& occupy = st->occupy;
    auto& hook_park1 = st->hook_park1;
    auto& hook_park2 = st->hook_park2;
    bool wedged = false;
    std::unique_ptr<ISparkMechanism> mech = make_registry_mechanism();
    REQUIRE(mech);
    ISparkMechanism* const mp = mech.get();
    // Declared AFTER `mech`, so on any exit path they run before ~mech: the leak decision
    // first, then every gate opens so a parked thread can be joined (or, when leaked, finish).
    OpenGateOnExit open1{hook_park1}, open2{hook_park2};
    yuzu::test::ScopeExit open_occupy{[st] { st->occupy.release(); }};
    struct LeakIfWedged {
        std::unique_ptr<ISparkMechanism>& m;
        const bool& wedged;
        ~LeakIfWedged() {
            if (wedged)
                (void)m.release(); // a thread deadlocked inside the sink can never be joined
        }
    } leak_if_wedged{mech, wedged};

    {
        RegistryMechanismTestControls ctl;
        ctl.probe_lane_cap = 1;
        ctl.caller_wait_budget = 5000ms;
        ctl.health_grace = 60000ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    auto record = log.sink();
    REQUIRE(mech->set_established_sink(
        [st, mp, record, key_a, key_sac, params_sac = spec_sac.params](
            const std::string& key, SparkIncarnation inc, std::chrono::steady_clock::time_point at,
            SparkCoverage cov) {
            record(key, inc, at, cov);
            // Only the STALE X report re-enters (the initial establishment must not).
            if (st->stale_phase.load(std::memory_order_acquire) && key == key_a && inc == kX &&
                !st->reentered.exchange(true)) {
                mp->unwatch(key_sac);
                st->reentry_ok.store(mp->watch_incarnation(key_sac, params_sac, 91).has_value(),
                                     std::memory_order_release);
                st->reentry_done.store(true, std::memory_order_release);
            }
        }));
    mech->start(
        [st](const std::string&, SparkData) { st->emits.fetch_add(1, std::memory_order_acq_rel); },
        [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kX).has_value());
    REQUIRE(mech->watch_incarnation(key_sac, spec_sac.params, kSac).has_value());
    REQUIRE(eventually([&] { return log.established_count() >= 2; }));
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));

    {
        RegistryMechanismTestControls ctl;
        // `st` rides along only to keep the gate alive for as long as any copy of this hook
        // (a probe worker holds one) exists.
        ctl.probe_hook = [st, gate_hook = occupy.hook_for(s.sub)](std::string_view sub) {
            gate_hook(sub);
        };
        ctl.emit_bookkeeping_hook = [st] {
            const int n = st->hook_calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (n == 1)
                st->hook_park1.park(); // pass N
            else if (n == 2)
                st->hook_park2.park(); // pass N+1: A's report staged, not yet dispatched
        };
        ctl.caller_wait_budget = 40ms;
        ctl.admission_backoff_seed = 50ms;
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->watch_incarnation(key_s, spec_s.params, kS).has_value()); // S's probe parks
    REQUIRE(eventually([&] { return occupy.parked.load() == 1; }, 2000ms));
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, kB).has_value()); // lane full: Deferred
    REQUIRE(hook_park1.wait_entered(8000ms)); // pass N parked

    // While pass N is parked: adopt A under the SAME incarnation (its report becomes due) and
    // register B2 (due ~50 ms from now, a launch for pass N+1).
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kX).has_value());
    REQUIRE(mech->watch_incarnation(key_b2, spec_b2.params, kB2).has_value());
    std::this_thread::sleep_for(200ms); // a LOWER bound only: nothing can visit B2 while parked
    hook_park1.release();
    REQUIRE(hook_park2.wait_entered(8000ms)); // pass N+1: [A, X, Notification] staged, undispatched

    // The race: A fires (on_fire marks None - a marker that dies with the watch), A is
    // unwatched, A is re-watched under Y (the lane is full, so Y is Deferred, not yet
    // established).
    const int emits_before = st->emits.load(std::memory_order_acquire);
    a.write(1);
    REQUIRE(eventually([&] { return st->emits.load(std::memory_order_acquire) > emits_before; },
                       5000ms));
    mech->unwatch(key_a);
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kY).has_value());

    // Dispatch the stale X report: it reaches the re-entering sink.
    st->stale_phase.store(true, std::memory_order_release);
    hook_park2.release();
    if (!eventually([&] { return st->reentry_done.load(std::memory_order_acquire); }, 10000ms)) {
        // Only a re-entry that STARTED and never returned is a proven wedge. If it never
        // started, the stale report simply was not dispatched: an ordinary failure, and ~mech
        // joins cleanly once the gates open.
        wedged = st->reentered.load(std::memory_order_acquire) &&
                 !st->reentry_done.load(std::memory_order_acquire);
        FAIL("the sink's re-entry into unwatch()/watch_incarnation() did not complete within "
             "10 s ("
             << (wedged ? "it started and never returned: the sink is being called with the "
                          "mechanism lock held (#4181 shape)"
                        : "it never started: the stale report was not dispatched")
             << ")");
    }
    CHECK(st->reentry_ok.load(std::memory_order_acquire));

    // Free the lane: Y, the sacrificial key's re-watch, B and B2 all establish for real.
    occupy.release();
    REQUIRE(eventually(
        [&] {
            return log.has(key_a, kY, SparkCoverage::Notification) &&
                   log.has(key_sac, 91, SparkCoverage::Notification) &&
                   log.has(key_b, kB, SparkCoverage::Notification) &&
                   log.has(key_b2, kB2, SparkCoverage::Notification);
        },
        10000ms));

    // The stale X report was delivered at most once beyond the initial one, and never as
    // anything but the Notification it was staged as (A's fire-consumed None died with the old
    // watch, so no X-incarnation None ever appears).
    CHECK(log.count(key_a, kX) <= 2);
    for (const auto& e : log.for_key(key_a))
        if (e.incarnation == kX)
            CHECK(e.coverage == SparkCoverage::Notification);
    // Y's own log is unaffected by X: only Y-incarnation reports, ending at Notification.
    std::vector<EstLog::Entry> y;
    for (const auto& e : log.for_key(key_a))
        if (e.incarnation == kY)
            y.push_back(e);
    REQUIRE_FALSE(y.empty());
    CHECK(y.back().coverage == SparkCoverage::Notification);

    mech->stop();
}

// ── File walkoff (#2012/#3840 PR-B2) ────────────────────────────────────────
namespace {

struct ScratchDir {
    std::filesystem::path dir;
    std::filesystem::path file;
    // yuzu_test_ prefix (not the original hand-rolled "spark_fileb2_...") so this
    // lands inside the Wee Tam Defender path-exclusion wildcard 'yuzu_*'
    // (scripts/windows-runner-defender-exclusions.ps1) - governance quality-engineer
    // SHOULD-1 / consistency-auditor C-2, same flake class as #473/#482.
    // yuzu::test::unique_temp_path also adds a monotonic per-process counter on top
    // of process_random_salt() (which alone is constant within one process), so two
    // ScratchDirs sharing a tag can no longer collide either.
    explicit ScratchDir(const char* tag) {
        dir = yuzu::test::unique_temp_path("yuzu_test_spark_fileb2_" + std::string(tag) + "_");
        std::filesystem::create_directories(dir);
        file = dir / "watched.txt";
        { std::ofstream(file) << "seed"; }
    }
    ~ScratchDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;
    void write(const char* content) const { std::ofstream(file, std::ios::app) << content; }
};

/// Parks every probe whose base directory matches until release(); counts
/// what it saw. Mirrors ProbeGate above (including the `inside` count its destructor waits
/// on, bounded) but keyed on File's std::wstring probe_hook signature
/// (spark_mechanism.hpp's FileMechanismTestControls).
struct FileProbeGate {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    std::atomic<int> parked{0};
    std::atomic<int> seen{0};
    std::atomic<int> inside{0};
    std::function<void(std::wstring_view)> hook_for(const std::filesystem::path& match_dir) {
        const std::wstring match = match_dir.wstring();
        return [this, match](std::wstring_view dir) {
            struct Inside {
                std::atomic<int>& n;
                explicit Inside(std::atomic<int>& n_) : n(n_) {
                    n.fetch_add(1, std::memory_order_acq_rel);
                }
                ~Inside() { n.fetch_sub(1, std::memory_order_acq_rel); }
            } inside_scope{inside}; // declared first: destroyed last, after `lk` below
            seen.fetch_add(1, std::memory_order_relaxed);
            if (dir != match)
                return;
            parked.fetch_add(1, std::memory_order_acq_rel);
            std::unique_lock lk(mu);
            cv.wait(lk, [&] { return open; });
        };
    }
    void release() {
        {
            std::lock_guard lk(mu);
            open = true;
        }
        cv.notify_all();
    }
    ~FileProbeGate() {
        release(); // never leave a worker parked past the test
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (inside.load(std::memory_order_acquire) > 0 &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
    }
};

} // namespace

TEST_CASE("File spark (real mechanism): a parked discovery probe on key A neither stalls arm(B) "
          "nor holds arm(A) past its caller budget (#2012 PR-B2)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("iso_a"), b("iso_b");
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    FileMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.dir);
    REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    // arm(A): its discovery probe parks on the worker. The caller must still
    // get an answer within the budget (50 ms) plus scheduling slack - before
    // PR-B2 this call did not return until the probe did (the whole
    // discovery walk ran directly under mu_).
    const auto spec_a = file_spec(a.file.string());
    const auto t0 = std::chrono::steady_clock::now();
    auto sa = engine.arm(*c, spec_a);
    const auto arm_a_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    CHECK(sa.has_value()); // success-with-pending
    INFO("arm(A) returned after " << arm_a_ms << " ms with A's probe parked");
    CHECK(arm_a_ms < 2000);
    CHECK(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // arm(B) while A's probe is still parked: same type, must not queue
    // behind A.
    const auto spec_b = file_spec(b.file.string());
    const auto t1 = std::chrono::steady_clock::now();
    auto sb = engine.arm(*c, spec_b);
    const auto arm_b_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1)
            .count();
    CHECK(sb.has_value());
    INFO("arm(B) returned after " << arm_b_ms << " ms while A's probe was parked");
    CHECK(arm_b_ms < 2000);
    // ...and B is genuinely watching: a write fires it.
    std::this_thread::sleep_for(200ms);
    const auto b_before = count_kind(got, spark_key(spec_b), SparkEventKind::Fired);
    CHECK(b_before == 0);
    b.write("change");
    CHECK(eventually(
        [&] { return count_kind(got, spark_key(spec_b), SparkEventKind::Fired) > b_before; },
        8000ms));

    // A missed its health grace while parked: Faulted, counted once as
    // slow_op.
    CHECK(eventually([&] { return engine.stats().armed_faulted == 1; }, 3000ms));
    CHECK(raw->stats().slow_op_total >= 1);

    // Release the probe: the late result is committed (not dropped), the
    // watch recovers.
    gate.release();
    CHECK(eventually([&] { return engine.stats().armed_faulted == 0; }, 5000ms));
    // A is really watching now: a real write fires it.
    const auto before = count_kind(got, spark_key(spec_a), SparkEventKind::Fired);
    a.write("real change");
    CHECK(eventually(
        [&] { return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) > before; }, 8000ms));
    auto dc = file_debug_counters_for_test(*raw);
    REQUIRE(dc.has_value());
    CHECK(dc->probe_discarded == 0);
    engine.stop();
    CHECK(eventually([&] { return file_debug_counters_for_test(*raw)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File spark (real mechanism): disarm while the initial probe is still parked discards "
          "the late result and frees the worker (#2012 PR-B2)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("late_discard");
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    FileMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.dir);
    REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec_a = file_spec(a.file.string());
    auto sa = engine.arm(*c, spec_a);
    REQUIRE(sa.has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    const auto t0 = std::chrono::steady_clock::now();
    engine.disarm(*sa);
    const auto disarm_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    INFO("disarm(A) returned after " << disarm_ms << " ms with A's probe parked");
    CHECK(disarm_ms < 2000);
    CHECK(engine.stats().armed_sparks == 0);

    // Release the probe: its result belongs to a retired watch - the probe's
    // own unassociated handle self-disposes, never committed, never emitted.
    gate.release();
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->probe_workers_active == 0 && d->live_dirs == 0;
        },
        5000ms));
    std::this_thread::sleep_for(200ms);
    CHECK(count_kind(got, spark_key(spec_a), SparkEventKind::Fired) == 0);
    CHECK(engine.stats().armed_faulted == 0);
    engine.stop();
}

TEST_CASE("File mechanism (direct): an allocation failure after a probe launches successfully "
          "does not permanently strand the watch (PR-B1 defect-pair analogue, PR #4225 review)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("strand_probe");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<int> probe_calls{0};
    std::atomic<bool> strand_once{true};
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 30ms;
        ctl.backend_retry_base = 40ms;
        ctl.sweep_cadence = 20ms;
        ctl.probe_hook = [&](std::wstring_view) {
            if (probe_calls.fetch_add(1, std::memory_order_acq_rel) == 0) {
                std::this_thread::sleep_for(120ms); // past caller_wait_budget
                throw std::runtime_error("injected backend failure (probe #1)");
            }
            // probe #2 (the Deferred retry): proceeds to a real establishment.
        };
        ctl.emit_bookkeeping_hook = [&] {
            if (strand_once.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error(
                    "injected run_off_lock failure after a successful probe launch "
                    "(models an allocation failure, PR #4225 review, ported to File)");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> delivered{0};
    mech->start([&](const std::string&, SparkData) { delivered.fetch_add(1, std::memory_order_acq_rel); },
                [&](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    REQUIRE(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_backend_failed >= 1;
        },
        3000ms));

    std::this_thread::sleep_for(300ms);
    a.write("change");
    INFO("probe_calls=" << probe_calls.load() << " strand_hook_consumed="
                        << !strand_once.load(std::memory_order_acquire));
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= 1; }, 6000ms));
    {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK_FALSE(strand_once.load(std::memory_order_acquire)); // the hook did fire once
    }
    mech->stop();
}

// ── File walkoff (#2012/#3840 PR-B2), remaining acceptance criteria ─────────
//
// Several of the tests below were originally marked KNOWN SUSPECT: they were
// derived by tracing spark_file.cpp against the PR-B2 plan's own
// acceptance-criteria wording, and that trace suggested the implementation at
// the time did not yet satisfy the criterion. A later round (see that round's
// own report) fixed three such gaps — the consumed-completion recovery
// (criterion #9), the missing needs_resync trigger sites (criterion #3 and
// others), and the unconditional confirmation_due re-arm (criterion #7,
// "STABLE ancestor" test below) — and updated each affected test's comment
// in place from "KNOWN SUSPECT / expect RED" to "FIXED this round / expect
// GREEN", still not yet Windows-verified. They are written (and kept) exactly
// as the criterion specifies, because that is the only way to get a real
// (Windows) answer — this file's own test suite cannot execute on this box.
// Each such test's comment cites the exact spark_file.cpp behavior the trace
// is based on so a DGRHP reviewer can check the reasoning independently
// rather than re-deriving it from scratch.
//
// A second, now-historical caveat: attach_ancestor_locked() used to set
// w.confirmation_due = true unconditionally, including on its "nothing
// changed" branch — see the "STABLE ancestor" test below for the trace and
// its fix. Before that fix, any OTHER test here that left a watch sheltered
// under an ancestor for more than an instant would see probe_launched keep
// climbing on its own, independent of whatever that test was actually
// driving — every such OTHER test still asserts probe_launched with `>=`,
// deltas, or explicit bounds, never `==` (not re-derived against the fixed
// state machine this round — see this round's report).

TEST_CASE("File mechanism (direct): an allocation failure immediately after a completion is "
          "dequeued does not crash the owner, but is NOT proven to re-arm the affected watch "
          "without another packet (#2012 PR-B2, criterion #9)",
          "[spark][mechanism][windows][walkoff]") {
    // completion_hook fires as the FIRST statement of process_completion_locked() (spark_file.cpp
    // ~1452), before the read is reissued (stage_fire_locked at ~1044, the reissue call at
    // ~1480) — modelling an allocation failure landing immediately after IOCP hands back a
    // completion, before this pass has done anything with it. That completion is already gone
    // from the IOCP queue and will never be redelivered (this file's header comment, rule 6), so
    // recovery must not depend on another packet ever arriving.
    //
    // FIXED this round (code-read, not yet Windows-verified). The original defect:
    // stage_fire_locked() does work.notices.reserve(...) (an allocation) BEFORE the
    // ReadDirectoryChangesW reissue that follows it in process_completion_locked's real-dir
    // branch; run()'s own per-pass top-of-loop reserve() calls covered probe_launches/
    // stale_calls/dead_results/dead_watches/old_handles but NOT notices, and unwind_pass_locked()
    // only restored an Emit notice whose is_resync was true — a plain fire notice was simply
    // dropped on unwind, and nothing re-staged a probe or a reissue for the affected DirWatch.
    // Worse, this specific test's own hook fires as process_completion_locked's FIRST statement —
    // BEFORE stage_fire_locked is even reached — so a narrow catch around just that call would not
    // have helped this scenario either. The fix has two parts: (1) a local try/catch around
    // stage_fire_locked in process_completion_locked's real-dir branch, so a throw there falls
    // back to a scalar-only coarse resync and the reissue still runs unconditionally; (2)
    // FilePassWork now carries three preallocated scalars (`consumed`/`consumed_ok`/
    // `consumed_is_anc`), stamped by run() BEFORE process_completion_locked is called, so
    // unwind_pass_locked can recover this exact completion (reissue directly, or fall back to
    // admission-deferral bookkeeping) no matter where inside the try a throw lands — including
    // this test's own first-statement hook. If that fix is right, the SECOND CHECK below should
    // now be GREEN on real Windows.
    ScratchDir a("consumed");
    ScratchDir sibling("consumed_sibling");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const auto spec_a = file_spec(a.file.string());
    const auto spec_s = file_spec(sibling.file.string());
    const std::string key_a = spark_key(spec_a);
    const std::string key_s = spark_key(spec_s);
    std::atomic<int> throws_left{1};
    {
        FileMechanismTestControls ctl;
        ctl.completion_hook = [&](std::wstring_view dir) {
            if (dir == a.dir.wstring() && throws_left.fetch_sub(1, std::memory_order_acq_rel) > 0)
                throw std::runtime_error("injected post-dequeue allocation failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> delivered_a{0};
    std::atomic<int> delivered_sibling{0};
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == key_a)
                delivered_a.fetch_add(1, std::memory_order_acq_rel);
            else if (key == key_s)
                delivered_sibling.fetch_add(1, std::memory_order_acq_rel);
        },
        [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch(key_a, spec_a.params).has_value());
    REQUIRE(mech->watch(key_s, spec_s.params).has_value());
    std::this_thread::sleep_for(300ms); // let both reads arm

    a.write("first change - the hook throws once for THIS completion");
    std::this_thread::sleep_for(400ms); // give the throwing pass time to run and unwind

    // The owner thread itself must survive: an UNRELATED sibling watch, sharing the same
    // mechanism/worker thread, still works normally after the throw.
    sibling.write("sibling change");
    CHECK(eventually([&] { return delivered_sibling.load(std::memory_order_acquire) >= 1; }, 5000ms));

    // The affected watch: does it re-arm and fire on a LATER, independent write, with no other
    // event in between? See the KNOWN SUSPECT note above.
    a.write("second change - throws_left is now <= 0, the hook is inert from here on");
    const bool a_recovered =
        eventually([&] { return delivered_a.load(std::memory_order_acquire) >= 1; }, 4000ms);
    INFO("delivered_a=" << delivered_a.load()
                        << " (expected >= 1; if this is 0, see the KNOWN SUSPECT note above)");
    CHECK(a_recovered);
    mech->stop();
}

// ── File worker pass-failure backoff / counter / inert (#4658) ──────────────
// A worker pass that throws (injected through FileMechanismTestControls::pass_fail_hook, or,
// for PF-15/PF-15b, through emit_bookkeeping_hook, after the pass has dispatched) must back off
// on a doubling schedule, be counted, and flip `inert` after three consecutive failures
// instead of spinning the worker. PF-15/PF-15b pin only that a throw after dispatch is counted
// and that the episode then closes with no external wake; the backoff schedule itself is
// pinned by PF-2 and PF-3. Windows-only: spark_file.cpp
// is `#ifdef _WIN32` end to end. Timing posture: LOWER bounds on elapsed time wherever
// possible; an upper bound only where the wrong implementation differs by seconds. Where a
// stalled runner could cross the window an assertion depends on (PF-3's exact-N read, PF-4,
// PF-5) it degrades to SUCCEED(). The ungated bounds that remain are PF-1's and PF-9's pass
// counts, their process CPU-time checks (skipped, with a SUCCEED, only when CPU time is
// unreadable), PF-3's `CHECK_FALSE(inert)` right after watch(), the 2000 ms `recovered` windows
// in PF-11/PF-12, the `took < 2000` checks in PF-6/PF-8/PF-13, and PF-15/PF-15b's 2000 ms
// counter and recovery windows plus their 3000/5000 ms waits (throw fired, redelivery,
// establishment). Each is wide against the correct behaviour (milliseconds to a few hundred
// ms), so it takes a stall about as long as the window (1.5-2 s for the shortest, up to 3-5 s
// for the PF-15/PF-15b waits) to false-red one: on the test thread for the checks that read a
// clock, or starvation of the worker or the whole process for the windows (eventually()
// re-evaluates at its deadline).
// Every captured piece of state is declared BEFORE the mechanism so a fatal REQUIRE
// destroys (and joins) the mechanism before the state its hooks capture.
namespace {

using PfClock = std::chrono::steady_clock;

long long pf_ms(PfClock::duration d) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
}
long long pf_ms_since(PfClock::time_point t0) { return pf_ms(PfClock::now() - t0); }

// Local copy of spark_file.cpp's doubled() (anonymous namespace there).
std::chrono::milliseconds pf_doubled_ms(std::chrono::milliseconds base, unsigned k,
                                        std::chrono::milliseconds cap) {
    auto d = base;
    for (unsigned i = 1; i < k && d < cap; ++i)
        d *= 2;
    return std::min(d, cap);
}

// Upper bound on failed passes in `elapsed_ms` of a 50 ms-base doubling backoff: the passes
// land at 0, 50, 150, 350, ... ms, so the retries after the first pass number
// floor(log2(elapsed/50 + 1)). The ratio below drops the +1; the caller-chosen slack (which
// also covers the first pass) absorbs the difference.
int pf_pass_bound(long long elapsed_ms, int slack) {
    const double ratio = std::max(static_cast<double>(elapsed_ms), 50.0) / 50.0;
    return static_cast<int>(std::floor(std::log2(ratio))) + slack;
}

// Total CPU (user + kernel) this process has consumed, or -1 if it cannot be read. Used ONLY as
// an UPPER bound on the worker's burn during a backoff: a worker that busy-loops (a zero-length
// wait absorbed and re-entered) burns a core, a backed-off one burns ~nothing. Such a loop is
// invisible to the pass-count bound, because the absorb check keeps the PASSES on schedule.
// Machine load can only lower what a spinning worker gets, so it can hide a mutant, never cause
// a false red.
long long pf_process_cpu_ms() {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user))
        return -1;
    const auto to_ms = [](const FILETIME& ft) {
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        return static_cast<long long>(u.QuadPart / 10000ULL); // 100 ns units
    };
    return to_ms(kernel) + to_ms(user);
}

void pf_noop_emit(const std::string&, SparkData) {}
void pf_noop_fault(const std::string&, bool, std::string_view) {}

// Waits until `passes` (a pass_fail_hook invocation counter) has not moved for `quiet`: every
// obligation the worker owed has been served and nothing is due but what the test arranged.
bool pf_wait_no_passes(const std::atomic<int>& passes,
                       std::chrono::milliseconds quiet = 400ms) {
    int last = -1;
    auto stable_since = PfClock::now();
    return eventually(
        [&] {
            const int p = passes.load(std::memory_order_acquire);
            if (p != last) {
                last = p;
                stable_since = PfClock::now();
                return false;
            }
            return PfClock::now() - stable_since >= quiet;
        },
        5000ms);
}

// Stretches the OFF-LOCK tail of a failed worker pass without a production seam: replaces the
// process default spdlog logger with one that keeps the previous sinks (the lines still reach
// the console) plus a sink that sleeps `stall` when a payload contains `target`.
// log_pass_outcome() runs after note_pass_outcome_locked() stamped the backoff deadline, so a
// stall longer than the backoff leaves that deadline already expired when the worker re-locks.
// This only works because spdlog is ONE shared image here (spdlog.dll); tests/unit/
// test_log_capture.hpp warns (#3355) that a default-logger swap may not reach library code, so
// every user MUST assert hits() > 0 or a test built on it can pass vacuously.
// Declare it BEFORE the mechanism: the worker logs through the default logger, so the mechanism
// has to be destroyed (its worker joined) before this restores the previous logger.
// PRECONDITION: no thread other than the mechanism's own worker may log through spdlog's free
// functions while an instance is alive. spdlog documents set_default_logger() as unsafe against
// concurrent free-function calls (they read the default logger through a raw pointer), and the
// destructor's drop() below frees the logger, so a stray logging thread would be a
// use-after-free rather than only a data race. Nothing in the tests that use this class starts
// one (the detached probe workers never log).
class PfStallLogger {
public:
    static constexpr const char* kName = "pf_stall";

    PfStallLogger(std::string target, std::chrono::milliseconds stall)
        : sink_(std::make_shared<Sink>(std::move(target), stall)),
          prev_(spdlog::default_logger()) {
        std::vector<spdlog::sink_ptr> sinks = prev_->sinks();
        sinks.push_back(sink_);
        auto logger = std::make_shared<spdlog::logger>(kName, sinks.begin(), sinks.end());
        logger->set_level(prev_->level());
        spdlog::set_default_logger(std::move(logger));
    }
    ~PfStallLogger() {
        spdlog::set_default_logger(prev_);
        // set_default_logger() also REGISTERS the logger under its name; drop it so the registry
        // does not keep it (and its sink, whose on_hit captures test locals by reference) alive.
        // Erases by NAME: two instances alive at once would leave the default logger null, so use
        // one at a time (the tests do).
        spdlog::drop(kName);
    }
    PfStallLogger(const PfStallLogger&) = delete;
    PfStallLogger& operator=(const PfStallLogger&) = delete;

    /// Payloads that matched `target` (each one slept `stall`).
    [[nodiscard]] int hits() const { return sink_->hits.load(std::memory_order_acquire); }
    /// Runs on the logging thread at each match, before the sleep. Set BEFORE the mechanism starts.
    void set_on_hit(std::function<void()> fn) { sink_->on_hit = std::move(fn); }

private:
    struct Sink final : spdlog::sinks::base_sink<std::mutex> {
        Sink(std::string t, std::chrono::milliseconds st) : target(std::move(t)), stall(st) {}
        void sink_it_(const spdlog::details::log_msg& msg) override {
            const std::string_view payload(msg.payload.data(), msg.payload.size());
            if (payload.find(target) == std::string_view::npos)
                return;
            // on_hit BEFORE the count: a test that polls hits() >= 1 on another thread can then
            // always read the snapshots on_hit stored.
            if (on_hit)
                on_hit();
            hits.fetch_add(1, std::memory_order_acq_rel);
            std::this_thread::sleep_for(stall);
        }
        void flush_() override {}
        std::string target;
        std::chrono::milliseconds stall;
        std::atomic<int> hits{0};
        std::function<void()> on_hit;
    };
    std::shared_ptr<Sink> sink_;
    std::shared_ptr<spdlog::logger> prev_;
};

// One scenario for a backoff deadline that has EXPIRED by the time the worker is back under
// mu_ (#4658 PF-11 / PF-12): the deadline is stamped before the off-lock tail of the failed
// pass (the log line, FilePassWork destruction), so a tail longer than the backoff leaves it in
// the past. The retry must still run at once; with nothing else due the timeout would be
// INFINITE, and with a later obligation (a Deferred watch's ~30 s retry) it would be that later
// deadline. `throws` failures are injected after the watch is established and quiet; the tail
// of the LAST one is stalled by `stall_target`.
struct PfStaleDeadline {
    bool deferred;                     // a Deferred retry ~30 s away is the other obligation
    unsigned throws;                   // consecutive failed passes to inject
    std::chrono::milliseconds cadence; // sweep_cadence: the backoffs are cadence, 2x, 4x, ...
    const char* stall_target;          // log payload whose emission sleeps
    std::chrono::milliseconds stall;
    bool inert_at_stall;               // expected stats().inert while that line is being written
};

void pf_run_stale_deadline(const PfStaleDeadline& sc) {
    ScratchDir a("pf_stale_deadline");
    std::atomic<int> faults{0};
    std::atomic<int> passes{0};
    std::atomic<int> throws_left{0};
    std::atomic<int> passes_at_stall{-1};
    std::atomic<int> inert_at_stall{-1};
    const std::wstring target_dir_w = a.dir.wstring();
    PfStallLogger stall_log(sc.stall_target, sc.stall);
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    // apply_test_controls REPLACES every hook on each call, so both installs supply the same set.
    const auto controls = [&] {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 2000ms; // the probe resolves in microseconds; be generous
        ctl.sweep_cadence = sc.cadence;
        if (sc.deferred)
            ctl.attach_fail_hook = [&](std::wstring_view dir) { return dir == target_dir_w; };
        ctl.pass_fail_hook = [&] {
            passes.fetch_add(1, std::memory_order_acq_rel);
            if (throws_left.load(std::memory_order_acquire) > 0 &&
                throws_left.fetch_sub(1, std::memory_order_acq_rel) > 0)
                throw std::bad_alloc{};
        };
        return ctl;
    };
    // stats() is lock-free, so it is safe to read from the logging (worker) thread.
    stall_log.set_on_hit([&] {
        passes_at_stall.store(passes.load(std::memory_order_acquire), std::memory_order_release);
        inert_at_stall.store(mech->stats().inert ? 1 : 0, std::memory_order_release);
    });
    REQUIRE(set_file_test_controls_for_test(*mech, controls()));
    mech->start(pf_noop_emit, [&](const std::string&, bool, std::string_view) {
        faults.fetch_add(1, std::memory_order_acq_rel);
    });
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    if (sc.deferred) {
        // The health grace reports the deaf watch once; after that only the Deferred retry
        // (~30 s away) remains.
        REQUIRE(eventually([&] { return faults.load(std::memory_order_acquire) >= 1; }, 4000ms));
    }
    REQUIRE(pf_wait_no_passes(passes)); // established, marker drained: nothing else is due
    if (sc.deferred)
        REQUIRE(file_debug_counters_for_test(*mech)->probe_backend_failed >= 1);
    const int passes_before = passes.load(std::memory_order_acquire);
    throws_left.store(static_cast<int>(sc.throws), std::memory_order_release);
    // apply_test_controls nudges run(): the first injected failure starts the episode.
    REQUIRE(set_file_test_controls_for_test(*mech, controls()));
    // The stalled line was written: the sink reached the library's logger (a FALSE-GREEN
    // guard, #3355), and the worker is now sleeping in the off-lock tail past its deadline.
    REQUIRE(eventually([&] { return stall_log.hits() >= 1; }, 5000ms));
    const auto t_stall = PfClock::now();
    CHECK(passes_at_stall.load(std::memory_order_acquire) ==
          passes_before + static_cast<int>(sc.throws));
    CHECK(inert_at_stall.load(std::memory_order_acquire) == (sc.inert_at_stall ? 1 : 0));
    // The retry has to run right after the tail (~stall); a stale deadline would leave it
    // INFINITE (idle) or on the later obligation (~30 s).
    const bool recovered = eventually(
        [&] {
            const auto d = file_debug_counters_for_test(*mech);
            return !mech->stats().inert && d->pass_failures_consecutive == 0 &&
                   d->pass_backoff_ms == 0;
        },
        2000ms);
    INFO("recovery " << pf_ms_since(t_stall) << " ms after the stalled line (stall "
                     << sc.stall.count() << " ms)");
    CHECK(recovered);
    CHECK_FALSE(mech->stats().inert);
    mech->stop(); // joins the worker: the counters below are then exact
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->pass_failed == sc.throws);
}

} // namespace

TEST_CASE("File worker (direct): a persistently throwing pass does not spin - the pass count is "
          "log-bounded by the backoff (#4658 PF-1)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_storm");
    std::atomic<int> passes{0};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.pass_fail_hook = [&] {
            passes.fetch_add(1, std::memory_order_relaxed);
            throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    const auto t0 = PfClock::now();
    const long long cpu0 = pf_process_cpu_ms();
    // The directory exists, so the watch establishes inside watch(), marks its coverage report
    // due and nudges run(). Every pass throws before it can drain that marker: the
    // self-sustaining wake the backoff has to hold back.
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    std::this_thread::sleep_for(1500ms); // a LOWER bound on the window only
    const auto elapsed_ms = pf_ms_since(t0);
    const long long cpu_ms = pf_process_cpu_ms() - cpu0;
    const int n = passes.load();
    // Base 50 ms doubling: passes at ~0/50/150/350/750/1550 ms. +4 slack (the first pass, ms
    // truncation, a tick-early timeout).
    const int bound = pf_pass_bound(elapsed_ms, 4);
    INFO("passes=" << n << " elapsed_ms=" << elapsed_ms << " bound=" << bound);
    CHECK(n >= 2);     // it IS retrying
    CHECK(n <= bound); // unbacked-off: thousands
    CHECK(mech->stats().inert); // n >= 3 failed passes by now
    // The worker is idle between the backed-off passes: no busy loop (a spinning one burns ~a
    // core, i.e. ~elapsed_ms).
    INFO("cpu_ms=" << cpu_ms << " over elapsed_ms=" << elapsed_ms);
    if (cpu0 >= 0 && cpu_ms >= 0)
        CHECK(cpu_ms < elapsed_ms / 3);
    else
        SUCCEED("cpu time unreadable");
    mech->stop();       // joins the worker: the counters below are then exact, not a racing read
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->pass_failed == static_cast<std::uint64_t>(passes.load()));
    CHECK(d->pass_failures_consecutive == d->pass_failed);
}

TEST_CASE("File worker (direct): the k-th consecutive failure waits doubled(sweep_cadence, k, cap) "
          "(#4658 PF-2)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_growth");
    std::mutex tm;
    std::vector<PfClock::time_point> ts;
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 100ms; // a 100 ms base keeps timer-tick slack small against it
        ctl.pass_fail_hook = [&] {
            {
                std::lock_guard lk(tm);
                ts.push_back(PfClock::now());
            }
            throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    // 100 + 200 + 400 + 800 + 1600 ms = 3.1 s to the sixth pass.
    REQUIRE(eventually(
        [&] {
            std::lock_guard lk(tm);
            return ts.size() >= 6;
        },
        15000ms));
    std::vector<PfClock::time_point> snap;
    {
        std::lock_guard lk(tm);
        snap = ts;
    }
    for (unsigned k = 1; k <= 5; ++k) {
        const auto gap = snap[k] - snap[k - 1];
        const auto want = pf_doubled_ms(100ms, k, 30000ms);
        INFO("k=" << k << " gap_ms=" << pf_ms(gap) << " want_ms=" << want.count());
        CHECK(gap >= want - 20ms); // LOWER bound only (timer tick slack)
    }
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    // The computed schedule, pinned independently of timing.
    CHECK(d->pass_backoff_ms ==
          pf_doubled_ms(100ms, static_cast<unsigned>(d->pass_failures_consecutive), 30000ms)
              .count());
    mech->stop();
}

TEST_CASE("File worker (direct): inert flips after exactly 3 consecutive failures and clears on "
          "the first success with no external wake (#4658 PF-3)",
          "[spark][mechanism][windows][passfail]") {
    // Template: the Registry sweeper's sre6-1 inert test.
    ScratchDir a("pf_inert");
    std::atomic<bool> failing{true};
    std::atomic<int> throws{0};
    std::atomic<int> fired{0};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        // Failures at ~0, +0.5 s, +1.5 s: wide gaps make the exact-N read robust.
        ctl.sweep_cadence = 500ms;
        ctl.pass_fail_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([&](const std::string&, SparkData) { fired.fetch_add(1); }, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    CHECK_FALSE(mech->stats().inert); // one failure at most: 3 need >= 1.5 s
    REQUIRE(eventually([&] { return mech->stats().inert; }, 10000ms));
    const auto t_inert_seen = PfClock::now();
    {
        const auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        INFO("pass_failed=" << d->pass_failed);
        CHECK(d->pass_failed >= 3);
        // Exact N: the fourth failure lands ~2 s after the flip (the backoff after the third is
        // 2 s), so N = 4 cannot hide behind a range. Gated: a test thread stalled past that
        // window degrades to SUCCEED.
        if (pf_ms_since(t_inert_seen) < 1000) {
            CHECK(d->pass_failed == 3);
            CHECK(throws.load(std::memory_order_acquire) == 3);
        } else {
            SUCCEED("window missed on a loaded runner");
        }
        CHECK(d->pass_failures_consecutive == d->pass_failed);
        CHECK(d->pass_backoff_ms ==
              pf_doubled_ms(500ms, static_cast<unsigned>(d->pass_failures_consecutive), 30000ms)
                  .count());
    }
    failing.store(false, std::memory_order_release);
    // NO nudge, NO write from here: recovery has to come from the retry the open episode itself
    // schedules for its deadline (the coverage marker is still due).
    REQUIRE(eventually([&] { return !mech->stats().inert; }, 15000ms));
    {
        const auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->pass_failures_consecutive == 0);
        CHECK(d->pass_backoff_ms == 0);
        CHECK(d->pass_failed >= 3);
        // The worker is idle again: every hook throw was one counted failed pass.
        CHECK(throws.load(std::memory_order_acquire) == static_cast<int>(d->pass_failed));
    }
    const int before = fired.load();
    a.write("after recovery");
    CHECK(eventually([&] { return fired.load() > before; }, 8000ms)); // the watch is live
    mech->stop();
}

TEST_CASE("File worker (direct): a real completion recovering a pass mid-backoff resets the "
          "deadline, so the next nudge is served promptly (#4658 PF-4)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_reset");
    EstLog log;
    std::atomic<bool> failing{true};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 5000ms; // one failure => a 5 s deadline
        ctl.pass_fail_hook = [&] {
            if (failing.load(std::memory_order_acquire))
                throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec_a = file_spec(a.file.string());
    const std::string key_a = spark_key(spec_a);
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, 1).has_value());
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                       5000ms));
    const auto t_fail = PfClock::now(); // the deadline is ~t_fail + 5 s
    failing.store(false, std::memory_order_release);
    a.write("real completion during backoff"); // NOT absorbed: a full pass, and it succeeds
    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->pass_failures_consecutive == 0; },
        5000ms));
    // Now a nudge plus a report: a second key joining the same directory.
    const auto spec_b = file_spec((a.dir / "other.txt").string());
    const std::string key_b = spark_key(spec_b);
    const auto t_join = PfClock::now();
    const auto join_offset_ms = pf_ms(t_join - t_fail);
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, 2).has_value());
    const bool prompt =
        eventually([&] { return log.has(key_b, 2, SparkCoverage::Notification); }, 2000ms);
    INFO("join report after " << pf_ms_since(t_join) << " ms; join at t_fail+" << join_offset_ms
                              << " ms, a stale deadline would be at t_fail+5000 ms");
    if (join_offset_ms < 2500)
        CHECK(prompt); // a stale deadline is >= 2.5 s away: it cannot be served in 2 s
    else
        SUCCEED("window missed on a loaded runner; the assertion cannot distinguish a stale "
                "deadline here");
    mech->stop();
}

TEST_CASE("File worker (direct): control wakes during a backoff are absorbed - nudges do not run "
          "passes (#4658 PF-5)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_absorb");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 5000ms;
        ctl.pass_fail_hook = [] { throw std::bad_alloc{}; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec_a = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value());
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                       5000ms));
    const auto t_fail = PfClock::now();
    const auto before = file_debug_counters_for_test(*mech)->pass_failed;
    for (int i = 0; i < 5; ++i) { // five joins in the same directory: five nudges
        const auto spec_i = file_spec((a.dir / ("k" + std::to_string(i) + ".txt")).string());
        REQUIRE(mech->watch(spark_key(spec_i), spec_i.params).has_value());
    }
    std::this_thread::sleep_for(200ms); // time for an un-absorbed nudge to run a pass
    const auto after = file_debug_counters_for_test(*mech)->pass_failed;
    INFO("pass_failed before=" << before << " after=" << after);
    // t_fail is taken AFTER the failure was observed, so the real retry deadline (failure time +
    // 5000 ms) can be earlier than t_fail + 5000 ms. Gate tightly so a stalled runner degrades
    // to SUCCEED instead of comparing counters across a legitimate retry pass.
    if (pf_ms_since(t_fail) < 2500)
        CHECK(after == before); // no absorb: +5
    else
        SUCCEED("window missed on a loaded runner");
    mech->stop(); // also exercises a prompt stop during the backoff
}

TEST_CASE("File worker (direct): stop() during a backoff returns promptly (#4658 PF-6)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_stop");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 5000ms;
        ctl.pass_fail_hook = [] { throw std::bad_alloc{}; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                       5000ms));
    const auto t = PfClock::now();
    mech->stop();
    const auto took = pf_ms_since(t);
    INFO("stop() took " << took << " ms during a 5 s backoff");
    CHECK(took < 2000); // a Sleep-based backoff would take >= 4.8 s
}

TEST_CASE("File worker (direct): a single transient failure with nothing else due still retries "
          "at the deadline and recovers (#4658 PF-7)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_idle_retry");
    EstLog log;
    std::atomic<int> throws_left{1};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, 1).has_value());
    // The establishment pass has run and reported its coverage, which drains the marker: NOTHING
    // is due any more.
    REQUIRE(eventually([&] { return log.has(key, 1, SparkCoverage::Notification); }, 5000ms));
    {
        FileMechanismTestControls ctl; // apply_test_controls nudges run(): that pass throws once
        ctl.pass_fail_hook = [&] {
            if (throws_left.fetch_sub(1, std::memory_order_acq_rel) > 0)
                throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed == 1; },
                       5000ms));
    // No nudge, no write, no marker: the ONLY thing that can run the recovery pass is the open
    // episode scheduling its own retry.
    CHECK(eventually(
        [&] {
            const auto d = file_debug_counters_for_test(*mech);
            return d->pass_failures_consecutive == 0 && d->pass_backoff_ms == 0;
        },
        5000ms));
    CHECK_FALSE(mech->stats().inert);
    CHECK(file_debug_counters_for_test(*mech)->pass_failed == 1);
    mech->stop();
}

TEST_CASE("File worker (direct): the retry after a failed pass runs at the backoff deadline even "
          "when the only other obligation is much later (#4658 PF-10)",
          "[spark][mechanism][windows][passfail]") {
    // A watch whose attach fails is Deferred with next_retry_at ~30 s away (the default
    // backend_retry_base, first attempt), and once its health fault is reported that is the ONLY
    // obligation the worker has. A transient failed pass then owes a retry at its own ~100 ms
    // backoff deadline. wait_timeout_locked() combines producers with min(), so a retry
    // scheduled as max(wake, deadline) would land on that later Deferred deadline (~30 s): the
    // log promises "retrying in 100 ms" while the retry, and with it any further failure count
    // and the inert flip, waits for the unrelated obligation. The retry is the wake itself
    // (the deadline). Correct ~100-200 ms, the bug ~30 s.
    ScratchDir a("pf_later_deadline");
    std::atomic<int> faults{0};
    std::atomic<int> passes{0};
    std::atomic<int> throws_left{0};
    const std::wstring target_dir_w = a.dir.wstring();
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    // apply_test_controls REPLACES every hook on each call, so both installs supply the same set.
    const auto controls = [&] {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 2000ms; // the probe resolves in microseconds; be generous
        ctl.sweep_cadence = 100ms;
        ctl.attach_fail_hook = [&](std::wstring_view dir) { return dir == target_dir_w; };
        ctl.pass_fail_hook = [&] {
            passes.fetch_add(1, std::memory_order_acq_rel);
            if (throws_left.load(std::memory_order_acquire) > 0 &&
                throws_left.fetch_sub(1, std::memory_order_acq_rel) > 0)
                throw std::bad_alloc{};
        };
        return ctl;
    };
    REQUIRE(set_file_test_controls_for_test(*mech, controls()));
    mech->start(pf_noop_emit, [&](const std::string&, bool, std::string_view) {
        faults.fetch_add(1, std::memory_order_acq_rel);
    });
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    // The health grace reports the deaf watch once; after that only the Deferred retry remains.
    REQUIRE(eventually([&] { return faults.load(std::memory_order_acquire) >= 1; }, 4000ms));
    {
        int last = -1;
        auto stable_since = PfClock::now();
        REQUIRE(eventually(
            [&] {
                const int p = passes.load(std::memory_order_acquire);
                if (p != last) {
                    last = p;
                    stable_since = PfClock::now();
                    return false;
                }
                return PfClock::now() - stable_since >= 400ms;
            },
            5000ms)); // no pass for 400 ms: nothing is due but the ~30 s retry
    }
    REQUIRE(file_debug_counters_for_test(*mech)->probe_backend_failed >= 1);
    throws_left.store(1, std::memory_order_release);
    const auto t_throw = PfClock::now();
    // apply_test_controls nudges run(): that pass throws once.
    REQUIRE(set_file_test_controls_for_test(*mech, controls()));
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed == 1; },
                       5000ms));
    // Nothing else is due until ~30 s, so only the episode's own retry can run the recovery pass.
    const bool recovered = eventually(
        [&] {
            const auto d = file_debug_counters_for_test(*mech);
            return d->pass_failures_consecutive == 0 && d->pass_backoff_ms == 0;
        },
        10000ms);
    INFO("recovery after " << pf_ms_since(t_throw)
                           << " ms (retry deadline ~100 ms, Deferred deadline ~30000 ms)");
    CHECK(recovered);
    CHECK_FALSE(mech->stats().inert);
    CHECK(file_debug_counters_for_test(*mech)->pass_failed == 1);
    mech->stop();
}

TEST_CASE("File worker (direct): a backoff deadline already expired when the failed pass's "
          "off-lock tail ends still retries at once and clears inert, nothing else due "
          "(#4658 PF-11)",
          "[spark][mechanism][windows][passfail]") {
    // Three injected failures at the production 50 ms cadence (backoffs 50/100/200 ms); the
    // flip line of the third is written 400 ms late, so its 200 ms deadline is 200 ms stale.
    pf_run_stale_deadline({.deferred = false,
                           .throws = 3,
                           .cadence = 50ms,
                           .stall_target = "failing persistently",
                           .stall = 400ms,
                           .inert_at_stall = true});
}

TEST_CASE("File worker (direct): a backoff deadline already expired when the failed pass's "
          "off-lock tail ends still retries at once, not at a later obligation (#4658 PF-12)",
          "[spark][mechanism][windows][passfail]") {
    // PF-10's state (a Deferred watch ~30 s away is the only other obligation) with one injected
    // failure at cadence 100 ms; its "consecutive #1" line is written 300 ms late, so the 100 ms
    // deadline is stale and the wake would slip to the Deferred deadline.
    pf_run_stale_deadline({.deferred = true,
                           .throws = 1,
                           .cadence = 100ms,
                           .stall_target = "consecutive #1",
                           .stall = 300ms,
                           .inert_at_stall = false});
}

TEST_CASE("File worker (direct): watch() of a second directory returns within budget while the "
          "worker is in a failure episode (#4658 PF-8)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_lat_a"), b("pf_lat_b");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.pass_fail_hook = [] { throw std::bad_alloc{}; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec_a = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value());
    REQUIRE(eventually([&] { return mech->stats().inert; }, 10000ms)); // >= 3 failures
    const auto spec_b = file_spec(b.file.string());
    const auto t = PfClock::now();
    REQUIRE(mech->watch(spark_key(spec_b), spec_b.params).has_value());
    const auto took = pf_ms_since(t);
    INFO("watch(B) took " << took << " ms during the failure episode");
    CHECK(took < 2000);
    mech->stop();

    // Phase 2: a sleep (or any lock held) across the backoff is invisible at the 50 ms cadence
    // above, where the backoff is only ~200 ms when inert is seen. A 5 s cadence makes it seconds.
    ScratchDir c("pf_lat_c"), d("pf_lat_d");
    auto slow = make_file_mechanism();
    REQUIRE(slow != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 5000ms;
        ctl.pass_fail_hook = [] { throw std::bad_alloc{}; };
        REQUIRE(set_file_test_controls_for_test(*slow, std::move(ctl)));
    }
    slow->start(pf_noop_emit, pf_noop_fault);
    const auto spec_c = file_spec(c.file.string());
    REQUIRE(slow->watch(spark_key(spec_c), spec_c.params).has_value());
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*slow)->pass_failed >= 1; },
                       5000ms));
    const auto spec_d = file_spec(d.file.string());
    const auto t_slow = PfClock::now();
    REQUIRE(slow->watch(spark_key(spec_d), spec_d.params).has_value());
    const auto took_slow = pf_ms_since(t_slow);
    INFO("watch(D) took " << took_slow << " ms during a 5 s backoff");
    CHECK(took_slow < 2000);
    slow->stop();
}

TEST_CASE("File worker (direct): a real completion during a failure episode keeps the watch "
          "armed and the pass rate stays bounded (#4658 PF-9)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_completion");
    std::atomic<bool> failing{true};
    std::atomic<int> passes{0};
    std::atomic<int> throws{0};
    std::atomic<int> fired{0};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.pass_fail_hook = [&] {
            passes.fetch_add(1);
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([&](const std::string&, SparkData) { fired.fetch_add(1); }, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    REQUIRE(eventually([&] { return mech->stats().inert; }, 10000ms));
    const auto t0 = PfClock::now();
    const long long cpu0 = pf_process_cpu_ms();
    const int p0 = passes.load();
    // A real completion: a full pass that throws; the unwind reissues the read and re-marks the
    // directory needs_resync, a due-now clause the backoff must defer to its deadline too.
    a.write("change during the episode");
    std::this_thread::sleep_for(1500ms);
    const int p1 = passes.load();
    const auto el = pf_ms_since(t0);
    const long long cpu_ms = pf_process_cpu_ms() - cpu0;
    // One pass for the completion plus log-bounded retries.
    const int bound = pf_pass_bound(el, 5);
    INFO("passes during " << el << " ms after the write: " << (p1 - p0) << " bound=" << bound);
    CHECK(p1 - p0 <= bound);
    // No busy loop on the needs_resync clause either (a due-now wake left ungated would spin the
    // worker on zero-length waits without running a single extra pass).
    INFO("cpu_ms=" << cpu_ms << " over el=" << el);
    if (cpu0 >= 0 && cpu_ms >= 0)
        CHECK(cpu_ms < el / 3);
    else
        SUCCEED("cpu time unreadable");
    failing.store(false, std::memory_order_release);
    // The backoff may have grown to several seconds by now.
    REQUIRE(eventually([&] { return !mech->stats().inert; }, 40000ms));
    std::this_thread::sleep_for(300ms); // let any recovery-time resync fire land before sampling
    const int before = fired.load();
    a.write("after recovery");
    CHECK(eventually([&] { return fired.load() > before; }, 8000ms)); // the read was reissued
    mech->stop(); // joins the worker: the counters below are then exact
    // Every hook throw was one failed pass and the real completion's pass is one of them, so a
    // real-completion branch that stops recording its outcome leaves pass_failed short.
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    INFO("pass_failed=" << d->pass_failed << " throws=" << throws.load());
    CHECK(d->pass_failed == static_cast<std::uint64_t>(throws.load()));
}

TEST_CASE("File worker (direct): the retry backoff is capped at 30 s and stop() does not wait "
          "for it (#4658 PF-13)",
          "[spark][mechanism][windows][passfail]") {
    // sweep_cadence 40 s: the first failure's backoff is already at the 30 s cap
    // (kFileAdmissionBackoffCap). A cap swapped for the 300 s backend one would read 40 s.
    ScratchDir a("pf_cap");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 40000ms;
        ctl.pass_fail_hook = [] { throw std::bad_alloc{}; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(pf_noop_emit, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    REQUIRE(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                       5000ms));
    {
        const auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->pass_backoff_ms == 30000);
        CHECK(d->pass_failures_consecutive == 1);
    }
    CHECK_FALSE(mech->stats().inert); // one failure of three
    const auto t = PfClock::now();
    mech->stop();
    const auto took = pf_ms_since(t);
    INFO("stop() took " << took << " ms during a 30 s backoff");
    CHECK(took < 2000);
}

TEST_CASE("File worker (direct): a worker that never fails keeps every pass-failure counter at "
          "zero and inert false through ordinary traffic (#4658 PF-14)",
          "[spark][mechanism][windows][passfail]") {
    ScratchDir a("pf_healthy");
    std::atomic<int> passes{0};
    std::atomic<int> fired{0};
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl; // counts passes, never throws
        ctl.pass_fail_hook = [&] { passes.fetch_add(1, std::memory_order_acq_rel); };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([&](const std::string&, SparkData) { fired.fetch_add(1); }, pf_noop_fault);
    const auto spec = file_spec(a.file.string());
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch(key, spec.params).has_value());
    REQUIRE(pf_wait_no_passes(passes, 200ms)); // established, read armed
    a.write("first");
    REQUIRE(eventually([&] { return fired.load() >= 1; }, 5000ms));
    const int after_first = fired.load();
    a.write("second");
    REQUIRE(eventually([&] { return fired.load() > after_first; }, 5000ms));
    mech->unwatch(key);
    REQUIRE(pf_wait_no_passes(passes, 200ms));
    CHECK(passes.load() > 0); // the hook ran, so passes did happen
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->pass_failed == 0);
    CHECK(d->pass_failures_consecutive == 0);
    CHECK(d->pass_backoff_ms == 0);
    CHECK_FALSE(mech->stats().inert);
    mech->stop();
}

TEST_CASE("File worker (direct): a throw after dispatched == true is counted and the episode "
          "closes with no external wake (#4658 PF-15)",
          "[spark][mechanism][windows][passfail]") {
    // Every other failure-injecting PF case throws from pass_fail_hook, which fires BEFORE run()
    // sets `dispatched`. This one throws AFTER it: emit_bookkeeping_hook fires inside
    // run_off_lock() once the pass has launched a probe, and the catch in run() must still count
    // the pass (`ok = false` whatever `dispatched` says). A catch that only counted pre-dispatch
    // failures would leave pass_failed at 0. Mechanics copied from the existing walkoff scenario
    // in which an ordinary Emit notice is left Outcome::Unattempted by a same-pass run_off_lock
    // failure: B's real write stages a notice, a forced reissue failure (real_rearm_fail_hook)
    // stages a probe launch in the same real-completion pass, and the launch fires the
    // bookkeeping hook. This is the real-completion catch; PF-15b is the control-wake/timeout
    // one.
    ScratchDir b("pf_after_dispatch");
    EstLog log;
    std::atomic<bool> rearm_armed{false};
    std::atomic<int> rearm_hits{0};
    std::atomic<bool> hook_armed{false};
    std::atomic<int> hook_hits{0};
    std::atomic<int> passes{0};
    std::atomic<int> b_delivered{0};
    const std::wstring b_dir_w = b.dir.wstring();
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 20ms;
        ctl.sweep_cadence = 10ms; // keeps the retry after the injected failure prompt
        // Counts passes for the quiescence wait; never throws.
        ctl.pass_fail_hook = [&] { passes.fetch_add(1, std::memory_order_acq_rel); };
        ctl.real_rearm_fail_hook = [&](std::wstring_view dir) {
            if (dir == b_dir_w && rearm_armed.exchange(false, std::memory_order_acq_rel)) {
                rearm_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.emit_bookkeeping_hook = [&] {
            hook_hits.fetch_add(1, std::memory_order_acq_rel);
            if (hook_armed.exchange(false, std::memory_order_acq_rel))
                throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == "B")
                b_delivered.fetch_add(1, std::memory_order_acq_rel);
        },
        pf_noop_fault);
    REQUIRE(mech->watch_incarnation("B", file_spec(b.file.string()).params, 1).has_value());
    // Tied to B's actual establishment (its coverage was reported), so a worker starved before
    // its first pass cannot let the arm below precede it; then nothing else is due.
    REQUIRE(eventually([&] { return log.has("B", 1, SparkCoverage::Notification); }, 5000ms));
    REQUIRE(pf_wait_no_passes(passes, 200ms));
    const int hook_before = hook_hits.load(std::memory_order_acquire);
    rearm_armed.store(true, std::memory_order_release);
    hook_armed.store(true, std::memory_order_release);
    b.write("change");
    // The throw actually fired (the hook was reached AFTER the arm and consumed it), on the pass
    // that also took the forced reissue failure.
    REQUIRE(eventually(
        [&] {
            return rearm_hits.load(std::memory_order_acquire) >= 1 &&
                   hook_hits.load(std::memory_order_acquire) > hook_before &&
                   !hook_armed.load(std::memory_order_acquire);
        },
        3000ms));
    // The failed pass is counted...
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                     2000ms));
    // The episode closes with NO further watch()/apply_test_controls(). The predicate holds
    // after any later successful pass (the retry at the deadline, which PF-3 and PF-7 pin, or a
    // real completion, which is never absorbed), so it shows the episode ended, not which pass
    // ended it.
    CHECK(eventually(
        [&] {
            const auto d = file_debug_counters_for_test(*mech);
            return d->pass_failures_consecutive == 0 && d->pass_backoff_ms == 0 &&
                   !mech->stats().inert;
        },
        2000ms));
    CHECK(eventually([&] { return b_delivered.load(std::memory_order_acquire) >= 1; }, 3000ms));
    mech->stop(); // joins the worker: the counters below are then exact
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    INFO("pass_failed=" << d->pass_failed << " consecutive=" << d->pass_failures_consecutive);
    CHECK(d->pass_failed == 1); // the one injected throw, counted once
    CHECK(d->pass_failures_consecutive == 0);
}

TEST_CASE("File worker (direct): a throw after dispatched == true in a timer-driven pass is "
          "counted and the episode closes with no external wake (#4658 PF-15b)",
          "[spark][mechanism][windows][passfail]") {
    // PF-15 reaches run()'s real-completion catch; this reaches the OTHER one, in the
    // control-wake/timeout branch, which has its own `ok = false;`. B's first attach is failed
    // (attach_fail_hook), which leaves it Deferred on the backend retry (100 ms). The retry is
    // due in a timer-driven pass (no completion is involved: B's read was never attached), whose
    // sweep stages a probe launch; run_off_lock() launches it and fires emit_bookkeeping_hook,
    // armed BEFORE the watch so that launch is the first the hook ever sees. That throw is after
    // `dispatched = true`. The unwind keeps the launched probe, which then resolves, attaches
    // (the hook fails only the first attach) and establishes B.
    ScratchDir b("pf_after_dispatch_timer");
    EstLog log;
    std::atomic<bool> attach_armed{true};
    std::atomic<int> attach_hits{0};
    std::atomic<bool> hook_armed{true};
    std::atomic<int> hook_hits{0};
    const std::wstring b_dir_w = b.dir.wstring();
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 2000ms; // the first probe resolves inside watch(), not in a pass
        ctl.backend_retry_base = 100ms;
        ctl.sweep_cadence = 10ms; // keeps the retry after the injected failure prompt
        ctl.attach_fail_hook = [&](std::wstring_view dir) {
            if (dir == b_dir_w && attach_armed.exchange(false, std::memory_order_acq_rel)) {
                attach_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.emit_bookkeeping_hook = [&] {
            hook_hits.fetch_add(1, std::memory_order_acq_rel);
            if (hook_armed.exchange(false, std::memory_order_acq_rel))
                throw std::bad_alloc{};
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(pf_noop_emit, pf_noop_fault);
    REQUIRE(mech->watch_incarnation("B", file_spec(b.file.string()).params, 1).has_value());
    // The attach failed and the Deferred retry's launch then reached the hook and consumed it.
    REQUIRE(eventually(
        [&] {
            return attach_hits.load(std::memory_order_acquire) >= 1 &&
                   hook_hits.load(std::memory_order_acquire) >= 1 &&
                   !hook_armed.load(std::memory_order_acquire);
        },
        5000ms));
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->pass_failed >= 1; },
                     2000ms));
    // No watch()/apply_test_controls() from here: the episode closes by itself (the predicate
    // holds after any later successful pass; PF-3 and PF-7 pin the retry at the deadline).
    CHECK(eventually(
        [&] {
            const auto d = file_debug_counters_for_test(*mech);
            return d->pass_failures_consecutive == 0 && d->pass_backoff_ms == 0 &&
                   !mech->stats().inert;
        },
        2000ms));
    // The probe launched by the failed pass survived its unwind and B ended up established.
    CHECK(eventually([&] { return log.has("B", 1, SparkCoverage::Notification); }, 3000ms));
    mech->stop(); // joins the worker: the counters below are then exact
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    INFO("pass_failed=" << d->pass_failed << " consecutive=" << d->pass_failures_consecutive);
    CHECK(d->pass_failed == 1); // the one injected throw, counted once
    CHECK(d->pass_failures_consecutive == 0);
}

TEST_CASE("File spark (real mechanism): a change during the INITIAL establishment window, with a "
          "prior fault edge, is observed via a late commitment - or is it? (#2012 PR-B2, "
          "criterion #3)",
          "[spark][mechanism][windows][walkoff]") {
    // FIXED this round (code-read, not yet Windows-verified). The original defect:
    // commit_probe_locked() only set needs_resync=true when was_reappearance was true, and
    // probe_is_reappearance was set ONLY by reresolve_absent_locked() (the "an ancestor fired, a
    // target might now exist" path) — a change landing during a PLAIN initial (or
    // backend-retried) establishment probe, no ancestor involved at all, never set
    // probe_is_reappearance, so commit never staged a synthetic fire for it. This test's own
    // scenario is watch()'s "still outstanding past the caller budget" branch (the probe is
    // parked past kFileCallerWaitBudget, so watch() publishes it to run()'s own sweep) — the fix
    // wires exactly this site: watch() now sets needs_resync=true + bumps the epoch right there
    // (mirroring spark_registry.cpp watch()'s identical "published-pending establishment"
    // trigger), so the eventual commit_probe_locked (once the parked probe is released) sees
    // needs_resync already set and stages the synthetic fire this test is checking for. If that
    // fix is right, the final CHECK below should now be GREEN on real Windows.
    ScratchDir a("late1");
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        ctl.health_grace = 60ms; // short: the parked probe WILL cross grace -> Faulted
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec(a.file.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(eventually([&] { return engine.stats().armed_faulted == 1; }, 3000ms)); // grace tripped

    // The change happens while establishment is still parked — no live ReadDirectoryChangesW is
    // outstanding yet, so the kernel cannot observe it directly.
    a.write("during-pending, before the probe ever commits");

    gate.release();
    CHECK(eventually([&] { return engine.stats().armed_faulted == 0; }, 5000ms)); // recovers

    // No FURTHER write happens below this line — if a Fired event arrives, it can only be the
    // synthetic fire the design calls for on late commitment.
    const bool late_commit_observed = eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) >= 1; }, 3000ms);
    INFO("Fired count after a late commitment WITH a prior fault edge: "
         << count_kind(got, spark_key(spec), SparkEventKind::Fired)
         << " (expected >= 1; if this is 0, see the KNOWN SUSPECT note above)");
    CHECK(late_commit_observed);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a change during the INITIAL establishment window, with "
          "NO prior fault edge at all, is observed via a late commitment - or is it? (#2012 "
          "PR-B2, criterion #3, no-fault-edge variant)",
          "[spark][mechanism][windows][walkoff]") {
    // Same fix as the sibling test above (watch()'s "still outstanding past the caller budget"
    // branch now sets needs_resync). This variant proves the gap did not depend on grace-timing:
    // the probe here is released well before health_grace, so armed_faulted
    // NEVER goes to 1 — a Guardian consumer watching only for Faulted/Recovered edges gets NO
    // signal whatsoever that anything might have changed. Synthetic fire is the ONLY mechanism
    // that can still tell it — exactly why the plan calls this out explicitly ("Guardian does NOT
    // re-evaluate on Recovered, this is the whole reason synthetic fire exists, don't let a test
    // accidentally pass without actually exercising it").
    ScratchDir a("late2");
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        ctl.health_grace = 5000ms; // long: released well before grace could ever trip
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec(a.file.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    a.write("during-pending, no fault edge will ever be observed for this run");
    std::this_thread::sleep_for(150ms); // well under the 5s grace
    CHECK(engine.stats().armed_faulted == 0); // confirms this variant: no fault edge happened

    gate.release();
    std::this_thread::sleep_for(200ms); // let the commit land

    const bool late_commit_observed = eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) >= 1; }, 3000ms);
    INFO("Fired count after a late commitment with NO fault edge: "
         << count_kind(got, spark_key(spec), SparkEventKind::Fired)
         << " (expected >= 1; if this is 0, see the KNOWN SUSPECT note in the sibling test above)");
    CHECK(late_commit_observed);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): shelter confirmation for a STABLE ancestor relationship "
          "confirms once and stops (#2012 PR-B2, criterion #7, gap-3 fix)",
          "[spark][mechanism][windows][walkoff]") {
    // FIXED this round (code-read, not yet Windows-verified): attach_ancestor_locked() used to set
    // w.confirmation_due = true UNCONDITIONALLY after its if/else (spark_file.cpp, previously
    // ~1216), including the "same akey, nothing changed" duplicate-handle branch — so
    // sweep_probes_locked's Idle case would clear the flag, launch a fresh confirmation probe,
    // that probe would walk from the ORIGINAL target, find the SAME still-absent target and the
    // SAME ancestor again, land right back on the duplicate-handle branch, and re-arm
    // confirmation_due — an unbounded 50 ms poll loop, contradicting the code's own comment. The
    // fix captures `same_shelter` (w.ancestor_key == akey, BEFORE any reassignment) and only
    // re-arms confirmation_due when the shelter relationship is NEW or CHANGED
    // (attach_ancestor_locked, near the end). For a target that never appears and an ancestor that
    // never changes, this makes the launch sequence deterministic: exactly ONE initial probe (the
    // fresh DirWatch's own first reservation, resolves Ancestor) plus exactly ONE confirmation
    // probe (re-resolves the SAME ancestor, same_shelter == true, does not re-arm) — then nothing
    // else should ever launch again while nothing on disk changes.
    //
    // IMPORTANT for every OTHER test with a sheltered watch: before this fix, a background
    // confirmation loop ran for the lifetime of every such test, which is why they assert
    // probe_launched with `>=`/deltas, never `==` — that reasoning is now obsolete for a STABLE
    // shelter, but those other tests are left as-is (not this round's scope) since their windows
    // were not specifically re-derived against the fixed state machine.
    ScratchDir root("confirm_stable_root");
    const auto target = root.dir / "never_appears" / "deep.txt"; // "never_appears" is never created
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    REQUIRE(engine.arm(*c, file_spec(target.string())).has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 1;
        },
        3000ms)); // sheltered under root.dir

    // Wait until BOTH the initial probe and its one owed confirmation have deterministically
    // landed (see the trace above) before sampling the baseline — this removes the ordering
    // uncertainty a plain "sleep, then sample" would have (whether the confirmation probe happens
    // to land before or after an arbitrary fixed delay).
    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*raw)->probe_launched >= 2; }, 3000ms));
    std::this_thread::sleep_for(200ms); // let the confirmation probe's own commit fully settle
    const auto p0 = file_debug_counters_for_test(*raw)->probe_launched;
    std::this_thread::sleep_for(500ms); // NOTHING on disk changes in this window
    const auto p1 = file_debug_counters_for_test(*raw)->probe_launched;
    INFO("probe_launched grew by " << (p1 - p0) << " over 500ms of a stable, unchanging shelter "
                                   "(expected exactly 0 now that gap-3 is fixed: shelter "
                                   "confirmation confirms once and stops)");
    CHECK(p1 == p0);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): shelter confirmation migrates to an intermediate "
          "directory that appears mid-shelter, and the watch stays live throughout (#2012 PR-B2, "
          "criterion #7)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("confirm_migrate_root");
    const auto intermediate = root.dir / "appears_later";
    const auto target = intermediate / "deep.txt";
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 1;
        },
        3000ms)); // sheltered under root.dir

    // The intermediate directory appears — a confirmation probe (whether it stops after one
    // success or keeps firing, per the sibling "STABLE" test above) will eventually re-resolve
    // DIRECTLY to it (Target mode: the directory itself now exists, regardless of whether
    // deep.txt inside it does yet), releasing the root ancestor shelter entirely.
    std::filesystem::create_directories(intermediate);
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 0 && d->live_dirs == 1;
        },
        5000ms));

    // Confirmed live at the migrated location: creating the watched file itself now fires
    // normally, with no gap in coverage.
    { std::ofstream(target) << "seed"; }
    std::this_thread::sleep_for(150ms);
    const auto before = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    { std::ofstream(target, std::ios::app) << "change"; }
    CHECK(eventually(
        [&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > before; }, 8000ms));
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a dead ancestor strips shelter from EVERY dependent, "
          "including a Pending one, and each recovers without another ancestor event (#2012 "
          "PR-B2, criterion #6)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("dead_anc_root");
    const auto anc = root.dir / "anc";
    std::filesystem::create_directories(anc);
    const auto d1 = anc / "d1" / "f1.txt"; // "d1" never created — shelters under anc
    const auto d2 = anc / "d2" / "f2.txt"; // ditto
    const auto d3 = anc / "d3" / "f3.txt"; // ditto — kept Pending (gated) through the kill

    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(anc / "d3"); // parks ONLY d3's establishment probe
        ctl.ancestor_rearm_fail_hook = [&](std::wstring_view dir) {
            return dir == anc.wstring(); // force the ancestor's OWN reissue to fail once it fires
        };
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec1 = file_spec(d1.string());
    const auto spec2 = file_spec(d2.string());
    const auto spec3 = file_spec(d3.string());
    REQUIRE(engine.arm(*c, spec1).has_value());
    REQUIRE(engine.arm(*c, spec2).has_value());
    REQUIRE(engine.arm(*c, spec3).has_value()); // parks
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 1;
        },
        3000ms)); // d1, d2 sheltered; d3 still Pending

    const auto p0 = file_debug_counters_for_test(*raw)->probe_launched;

    // A direct child of anc (every ReadDirectoryChangesW here uses bWatchSubtree=FALSE, so d1/d2/
    // d3's own subdirectories do NOT trigger this) fires the ancestor's own read; the hook forces
    // its reissue to fail, driving invalidate_ancestor_locked() instead of the ordinary
    // reresolve_absent_locked() path (the #829 fix this PR made).
    { std::ofstream(anc / "trigger.txt") << "x"; }

    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 0;
        },
        5000ms)); // the dead ancestor is torn down

    // d1 and d2 (Idle at the time of death) each got a fresh probe staged — never a hope, an
    // actual reservation (invalidate_ancestor_locked's own doc comment).
    CHECK(eventually(
        [&] { return file_debug_counters_for_test(*raw)->probe_launched >= p0 + 2; }, 3000ms));

    // d3 (Pending, gated) is untouched by the invalidation ITSELF — single-flight defers to its
    // own in-flight obligation — but its ancestor_key is cleared regardless (the "including a
    // Pending one" half of this criterion, spark_file.cpp's invalidate_ancestor_locked: the clear
    // runs BEFORE the Pending `continue`, unconditionally, for every dependent). Released now,
    // d3's OWN probe (still running against the physically-unchanged anc directory) simply
    // re-discovers anc and shelters there again, recreating a fresh ancestor slot — no SECOND
    // ancestor event needed.
    gate.release();

    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 1; // d1, d2, and eventually d3 re-share one fresh slot
        },
        5000ms));
    CHECK(engine.stats().armed_sparks == 3); // none of d1/d2/d3 was ever Lost through this
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a probe parked across stop() is counted on the shared F3 "
          "counter until its worker exits (#2012 PR-B2, criterion #14)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("f3_orphan");
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkEngine engine;
    auto mech = make_file_mechanism(f3);
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    REQUIRE(engine.arm(*c, file_spec(a.file.string())).has_value()); // pending, parked
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(f3->load() == 1); // admitted against the SHARED counter, not just the lane

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop();
    const auto stop_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    INFO("engine.stop() took " << stop_ms << " ms with one probe parked");
    CHECK(stop_ms < 5000);
    CHECK(raw->stats().quarantined_total == 1);
    CHECK(f3->load() == 1); // still parked => still counted (F3 / §24)

    gate.release();
    CHECK(eventually([&] { return f3->load() == 0; }, 5000ms)); // worker exited => counter released
    CHECK(eventually([&] { return file_debug_counters_for_test(*raw)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File mechanism (direct): stop() during watch()'s bounded wait cancels the "
          "reservation - watch() still reports success (File's Decision #3), and the late result "
          "is discarded, never committed (#2012 PR-B2, criterion #4)",
          "[spark][mechanism][windows][walkoff]") {
    // Mechanism-direct (no engine) so the interleaving is under the test's control: watch() is
    // inside its caller wait when stop() retires the reservation. NOTE this is a deliberately
    // DIFFERENT assertion than spark_registry.cpp's identically-shaped test: Registry's watch()
    // reports failure here; File's does NOT — spark_file.cpp:690's unconditional `return {};` in
    // the `!live` branch (Decision #3, this file's header comment) means a caller racing stop()
    // gets an honest "accepted, now gone" success, not an error. Do not copy Registry's
    // CHECK_FALSE here — that would be testing the wrong mechanism's contract.
    ScratchDir a("gen_race");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        ctl.caller_wait_budget = 3000ms; // long enough for stop() to land inside it
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> emits{0};
    std::atomic<int> faults{0};
    mech->start([&](const std::string&, SparkData) { emits.fetch_add(1); },
                [&](const std::string&, bool, std::string_view) { faults.fetch_add(1); });
    const auto spec = file_spec(a.file.string());
    std::expected<void, std::string> result;
    std::thread watcher([&] { result = mech->watch(spark_key(spec), spec.params); });
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    std::this_thread::sleep_for(100ms); // the watcher is now inside wait_take()
    mech->stop();                        // retires the reservation underneath it
    gate.release();                      // the probe completes AFTER the retirement
    watcher.join();
    CHECK(result.has_value()); // File: success-with-nothing-behind-it, not an error (see NOTE)
    auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->probe_discarded == 1);
    CHECK(d->live_dirs == 0);
    CHECK(emits.load() == 0);
    CHECK(faults.load() == 0);
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File mechanism (direct): an admission refusal is never counted as a backend failure "
          "(and vice versa), and a refused probe recovers once the lane frees up (#2012 PR-B2, "
          "criterion #5)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("admission_a"), c("admission_c");
    const auto b_root = a.dir.parent_path() /
                        ("admission_b_root_" + std::to_string(::GetCurrentProcessId()) + "_" +
                         std::to_string(yuzu::test::process_random_salt() % 1000000000));
    std::filesystem::create_directories(b_root); // B's OWN ancestor - no sharing with A or C
    const auto b_target = b_root / "missing" / "f.txt";
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir); // parks A's probe, occupying the (capped) lane
        ctl.probe_lane_cap = 1;
        ctl.admission_backoff_seed = 40ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {}, [](const std::string&, bool, std::string_view) {});

    const auto spec_a = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value()); // parks, occupying the lane
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // B: same mechanism, lane already at its cap of 1 -> an ADMISSION refusal, never a backend one.
    const auto d0 = file_debug_counters_for_test(*mech);
    REQUIRE(d0.has_value());
    const auto spec_b = file_spec(b_target.string());
    REQUIRE(mech->watch(spark_key(spec_b), spec_b.params).has_value()); // File never rejects arm()
                                                                        // for this (Decision #3)
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d && d->probe_admission_rejected > d0->probe_admission_rejected;
        },
        3000ms));
    {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->probe_backend_failed == d0->probe_backend_failed); // never counted as backend
    }

    // Release A: the lane frees up, B's admission retry (on its own seeded backoff) eventually
    // gets in and establishes for real.
    gate.release();
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d && d->live_ancestors == 1; // B's own absent-parent walk shelters under b_root
        },
        5000ms));

    // C: a completely separate dir, this time with a THROWING probe hook - a genuine backend
    // failure, never an admission one. apply_test_controls() treats a zero/default-constructed
    // field as "leave unchanged" (FileMechanismTestControls's own doc comment), so a fresh `ctl`
    // here does NOT reset what phase A set: probe_lane_cap is still pinned at 1 and
    // admission_backoff_seed is still 40ms unless we say otherwise. The seed carrying over is
    // benign (it only paces a retry that should never need to happen). The cap is not benign: B's
    // shelter attach just above armed exactly one shelter-CONFIRMATION probe (the Gap-3 fix stops
    // the confirmation loop after one attempt, but does not guarantee it has already landed by
    // the time live_ancestors==1 is observed), so leaving the cap at 1 lets that still-in-flight
    // confirmation probe race C's own probe for the single slot and admission-reject C - the
    // #2012 PR-B2 flake this test exists to catch, not a fault in the production code. Lift the
    // cap explicitly rather than relying on the (nonexistent) default-restoring behavior.
    // kPhaseCLaneCap is deliberately NOT kProbeLaneCap (spark_file.cpp's own default of 16, and
    // file-local to that TU besides - see the "shared-ancestor storm" test's kTestLaneCap for the
    // same reasoning): the only requirement is a floor of 2 (B's at-most-one outstanding
    // confirmation probe + C's own can never both be in flight), so an explicit, self-contained
    // value keeps this test's correctness independent of whatever the production constant is.
    constexpr std::size_t kPhaseCLaneCap = 4;
    const auto d1 = file_debug_counters_for_test(*mech);
    REQUIRE(d1.has_value());
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = [&](std::wstring_view dir) {
            if (dir == c.dir.wstring())
                throw std::runtime_error("injected genuine backend failure for C");
        };
        ctl.probe_lane_cap = kPhaseCLaneCap; // lift phase A's cap of 1 - see comment above
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    const auto spec_c = file_spec(c.file.string());
    REQUIRE(mech->watch(spark_key(spec_c), spec_c.params).has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d && d->probe_backend_failed > d1->probe_backend_failed;
        },
        3000ms));
    {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->probe_admission_rejected == d1->probe_admission_rejected); // never counted as
                                                                             // admission
    }
    mech->stop();
}

TEST_CASE("File mechanism (direct): repeated admission refusal does not reset the health-grace "
          "clock - grace is stamped once, at acceptance, never re-stamped by a retry (#2012 "
          "PR-B2, criterion #5, grace half)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("grace_hog"), b("grace_victim");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    FileProbeGate gate;
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir); // parks for the WHOLE test (never released) - A
                                               // permanently occupies the one-slot lane
        ctl.probe_lane_cap = 1;
        ctl.admission_backoff_seed = 20ms; // B retries admission often
        ctl.health_grace = 150ms;          // B WILL cross grace while still being admission-refused
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::vector<std::pair<std::string, bool>> faults; // key, faulted
    std::mutex faults_mu;
    mech->start([](const std::string&, SparkData) {},
                [&](const std::string& key, bool faulted, std::string_view) {
                    std::lock_guard lk(faults_mu);
                    faults.emplace_back(key, faulted);
                });
    const auto spec_a = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    const auto spec_b = file_spec(b.file.string());
    const std::string key_b = spark_key(spec_b);
    REQUIRE(mech->watch(key_b, spec_b.params).has_value());

    // B never gets a lane slot (A holds it for the whole test) - it is repeatedly
    // admission-refused on a 20ms-seeded schedule, well past its 150ms grace. If grace were
    // (incorrectly) reset by each admission retry, B would never report Faulted; if it is
    // correctly stamped once at acceptance, exactly one Faulted edge for B appears, promptly, and
    // stays the only one no matter how many further admission retries happen afterward.
    CHECK(eventually(
        [&] {
            std::lock_guard lk(faults_mu);
            return std::count_if(faults.begin(), faults.end(), [&](const auto& p) {
                       return p.first == key_b && p.second;
                   }) >= 1;
        },
        3000ms));

    std::this_thread::sleep_for(600ms); // several more admission-retry cycles (20ms seed, doubling)
    {
        std::lock_guard lk(faults_mu);
        const auto b_faulted_edges = std::count_if(
            faults.begin(), faults.end(), [&](const auto& p) { return p.first == key_b && p.second; });
        CHECK(b_faulted_edges == 1); // grace_counted latches - never a second Faulted edge for B
                                    // just because admission kept retrying
    }
    auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->probe_admission_rejected >= 2); // B really was retried more than once
    mech->stop();
}

TEST_CASE("File mechanism (direct): a packet dequeued immediately before stop() is observed does "
          "not leave stop()'s drain waiting for a completion that can never arrive (#2012 PR-B2, "
          "criterion #13)",
          "[spark][mechanism][windows][walkoff]") {
    // Repeats a tight establish -> fire -> stop() cycle with NO delay between the write and
    // stop(), so across enough iterations at least some runs land stop() while a real completion
    // for this exact write is still in flight or just-dequeued on the owner thread — the
    // pre-PR-B2 file.cpp:750 trap this file's run() header comment describes: io_pending must be
    // cleared for the JUST-dequeued packet before stop_ is even checked, or the drain loop below
    // it waits forever for a completion that will never come again. Mirrors the disarm-then-rearm
    // #1927 test's own "repeat so one lucky interleaving can't mask a regression" rationale.
    //
    // NOT covered here (or anywhere in this round): a genuinely LOST completion forcing the
    // shutdown-quarantine path (stop()'s `lost_completion` branch, spark_file.cpp ~766-796) — that
    // requires GetQueuedCompletionStatus itself to fail mid-drain, which is not deterministically
    // triggerable without a hook INSIDE stop()'s own drain loop, and no such hook exists yet. The
    // timeout / control-wake / ordinary-failed-completion paths this criterion also lists are
    // exercised incidentally elsewhere in this file: a Deferred retry (any parked-then-released
    // test above) proves the timeout path schedules correctly; the "survives parent-dir delete"
    // resilience test proves a failed completion is handled; every watch()/apply_test_controls()
    // call in every test here posts a control wake and is processed correctly (the suite would
    // hang otherwise).
    ScratchDir a("packet_before_stop");
    for (int i = 0; i < 25; ++i) {
        INFO("iteration " << i);
        auto mech = make_file_mechanism();
        REQUIRE(mech != nullptr);
        mech->start([](const std::string&, SparkData) {}, [](const std::string&, bool, std::string_view) {});
        const auto spec = file_spec(a.file.string());
        REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
        std::this_thread::sleep_for(30ms); // let the read genuinely arm
        a.write("x");
        // No sleep here: stop() races the completion this write just produced.
        const auto t0 = std::chrono::steady_clock::now();
        mech->stop();
        const auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0)
                                 .count();
        CHECK(stop_ms < 1500);
        CHECK(mech->stats().quarantined_total == 0); // a clean stop never needs to quarantine anything here
    }
}

TEST_CASE("File mechanism (direct): a throwing emit is contained per key, and Decision #4's "
          "whole-batch resync retry produces a BOUNDED number of duplicate deliveries to an "
          "already-succeeded sibling key (#2012 PR-B2, criterion #11, emit half)",
          "[spark][mechanism][windows][walkoff]") {
    // Two keys share ONE DirWatch (same parent dir, different filenames), both absent, so the
    // dir is sheltered under an ancestor. Making the shared dir itself appear drives the ONE
    // currently-working synthetic-fire trigger (reresolve_absent_locked -> a reappearance commit
    // -> needs_resync=true, spark_file.cpp:1315-1318 — see the "late commitment" tests above for
    // triggers the plan calls for that are not yet implemented). emit_ throws for key A on its
    // first K=2 calls; key B never throws. Decision #4 (Dave, PR-B2 plan) is that a submit failure
    // retries the WHOLE shared-dir batch, never per-key debt — so B is delivered the SAME resync
    // notice again on every retry A's failure forces, even though B already succeeded. This test
    // proves the bound actually holds (the plan's own wording: "needs an explicit acceptance test
    // proving the duplicate-invalidation bound actually holds").
    ScratchDir root("dispatch_fail_root");
    const auto shared_dir = root.dir / "shared"; // absent until triggered below
    const auto file_a = shared_dir / "a.txt";
    const auto file_b = shared_dir / "b.txt";
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    {
        FileMechanismTestControls ctl;
        ctl.admission_backoff_seed = 30ms; // stage_resync_emit_locked's own failure path re-stages
                                           // on this schedule (publish_pass_locked reuses
                                           // admission_seed() for the resync retry backoff)
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    const auto spec_a = file_spec(file_a.string());
    const auto spec_b = file_spec(file_b.string());
    const std::string key_a = spark_key(spec_a);
    const std::string key_b = spark_key(spec_b);
    std::atomic<int> throws_left_for_a{2};
    std::atomic<int> delivered_a{0};
    std::atomic<int> delivered_b{0};
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == key_a) {
                if (throws_left_for_a.fetch_sub(1, std::memory_order_acq_rel) > 0)
                    throw std::runtime_error("injected emit failure for A");
                delivered_a.fetch_add(1, std::memory_order_acq_rel);
            } else if (key == key_b) {
                delivered_b.fetch_add(1, std::memory_order_acq_rel);
            }
        },
        [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch(key_a, spec_a.params).has_value()); // creates the shared DirWatch
    REQUIRE(mech->watch(key_b, spec_b.params).has_value()); // rides along, no new probe
    std::this_thread::sleep_for(300ms); // let the shared dir settle, sheltered under root

    std::filesystem::create_directories(shared_dir); // direct child of root -> reappearance trigger

    CHECK(eventually([&] { return delivered_a.load(std::memory_order_acquire) >= 1; }, 6000ms));
    {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        INFO("delivered_a=" << delivered_a.load() << " delivered_b=" << delivered_b.load()
                            << " emit_failed=" << d->emit_failed
                            << " resync_retries=" << d->resync_retries);
        CHECK(delivered_a.load(std::memory_order_acquire) == 1); // exactly one success, once the
                                                                  // throw budget is exhausted
        CHECK(d->emit_failed == 2); // both of A's injected throws were counted, never silently lost
        // B pays the Decision #4 cost: delivered once per resync attempt (bounded, not unbounded)
        // - one original attempt plus one duplicate per retry A's failure forced.
        CHECK(delivered_b.load(std::memory_order_acquire) == static_cast<int>(d->resync_retries) + 1);
        CHECK(delivered_b.load(std::memory_order_acquire) <= 4); // an explicit bound, not just the
                                                                  // equation above - the whole point
                                                                  // of this test
    }
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throwing fault callback is contained - the owner keeps "
          "running and an unrelated watch still works (#2012 PR-B2, criterion #11, fault half)",
          "[spark][mechanism][windows][walkoff]") {
    // NOTE ON THE OBSERVABLE CONTRACT (code-read, spark_file.cpp check_health_edge_locked ~976-
    // 994): health_reported_faulted is stamped BEFORE the fault notice is dispatched,
    // optimistically — there is no failed-dispatch re-stage path for Fault the way
    // stage_resync_emit_locked has for a failed resync Emit (publish_pass_locked's
    // succeeded_resync/failed_resync handling is Emit-only). So a THROWN fault_ callback's
    // specific edge is not retried — this test does not assert on that (too easy to get subtly
    // wrong from a trace alone); it asserts only the load-bearing "contained" half of the
    // criterion: the throw is counted, and the mechanism keeps servicing other watches.
    ScratchDir a("fault_throw"), sibling("fault_throw_sibling");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<int> fault_throws_left{1};
    {
        FileMechanismTestControls ctl;
        ctl.health_grace = 60ms;
        ctl.probe_hook = [&](std::wstring_view dir) {
            if (dir == a.dir.wstring())
                std::this_thread::sleep_for(200ms); // park past grace once, deterministically
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    const auto spec_a = file_spec(a.file.string());
    const auto spec_s = file_spec(sibling.file.string());
    const std::string key_a = spark_key(spec_a);
    const std::string key_s = spark_key(spec_s);
    std::atomic<int> sibling_delivered{0};
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == key_s)
                sibling_delivered.fetch_add(1, std::memory_order_acquire);
        },
        [&](const std::string& key, bool faulted, std::string_view) {
            if (key == key_a && faulted &&
                fault_throws_left.fetch_sub(1, std::memory_order_acq_rel) > 0)
                throw std::runtime_error("injected fault-dispatch failure");
        });
    REQUIRE(mech->watch(key_a, spec_a.params).has_value()); // parks past grace once
    REQUIRE(mech->watch(key_s, spec_s.params).has_value());

    // The mechanism keeps running despite the thrown fault_: the sibling watch still establishes
    // and fires normally.
    std::this_thread::sleep_for(300ms);
    sibling.write("change");
    CHECK(eventually([&] { return sibling_delivered.load(std::memory_order_acquire) >= 1; }, 8000ms));

    auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->fault_failed >= 1); // the throw was counted, never silently swallowed
    mech->stop();
}

TEST_CASE("File spark (real mechanism): a shared ancestor's refcount survives one dependent's "
          "removal and tears down only once the last one goes (#2012 PR-B2, criterion #8)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("shared_anc_root");
    const auto d1 = root.dir / "dep1" / "f1.txt"; // "dep1" never created
    const auto d2 = root.dir / "dep2" / "f2.txt"; // "dep2" never created
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    auto s1 = engine.arm(*c, file_spec(d1.string()));
    auto s2 = engine.arm(*c, file_spec(d2.string()));
    REQUIRE(s1.has_value());
    REQUIRE(s2.has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 1; // ONE shared slot for root.dir, refcount 2
        },
        3000ms));

    engine.disarm(*s1);
    std::this_thread::sleep_for(200ms);
    CHECK(file_debug_counters_for_test(*raw)->live_ancestors == 1); // still referenced by d2

    engine.disarm(*s2);
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->live_ancestors == 0;
        },
        5000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->retiring == 0;
        },
        5000ms));
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a shared-ancestor storm keeps concurrent discovery "
          "probes bounded by the lane cap and converges once the storm stops (#2012 PR-B2, "
          "criterion #15, bounded-growth half)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("storm_root");
    constexpr int kDeps = 30;
    // Deliberately smaller than production's own default (kProbeLaneCap=16, file-local to
    // spark_file.cpp's anonymous namespace and not visible to this TU) so the bound this test
    // asserts is self-contained rather than tied to a constant it cannot see.
    constexpr std::size_t kTestLaneCap = 8;
    std::vector<SparkSpec> specs;
    specs.reserve(kDeps);
    for (int i = 0; i < kDeps; ++i)
        specs.push_back(file_spec((root.dir / ("dep" + std::to_string(i)) / "f.txt").string()));

    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    {
        FileMechanismTestControls ctl;
        ctl.probe_lane_cap = kTestLaneCap;
        ctl.admission_backoff_seed = 15ms; // short: rejected probes retry quickly, sustaining load
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    for (const auto& spec : specs)
        REQUIRE(engine.arm(*c, spec).has_value());

    std::size_t max_active = 0;
    const auto deadline = std::chrono::steady_clock::now() + 1500ms;
    while (std::chrono::steady_clock::now() < deadline) {
        // Storm: create then delete a direct child of root every pass - each edge re-fires the
        // shared ancestor watch, restaging a reappearance probe for every still-Idle dependent.
        const auto churn = root.dir / "churn.txt";
        { std::ofstream(churn) << "x"; }
        std::error_code ec;
        std::filesystem::remove(churn, ec);
        auto d = file_debug_counters_for_test(*raw);
        if (d)
            max_active = std::max(max_active, d->probe_workers_active);
        std::this_thread::sleep_for(10ms);
    }
    INFO("max observed probe_workers_active=" << max_active << " (test cap=" << kTestLaneCap << ")");
    CHECK(max_active <= kTestLaneCap);
    CHECK(file_debug_counters_for_test(*raw)->probe_admission_rejected > 0); // the storm genuinely
                                                                             // pressured the lane

    // Convergence: once the storm stops, everything drains back to idle.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*raw);
            return d && d->probe_workers_active == 0;
        },
        5000ms));
    engine.stop();
}

// ── #4340 (rung 9c PR-6 item 1): File establishment-signal ───────────────────
//
// Mirrors the Registry RF- cases above and spark_service.cpp's shipped M3
// shape. Every case here only runs on Windows. File does NOT lose coverage on
// an ordinary fire (the reissue is synchronous, unlike Registry's one-shot
// RegNotifyChangeKeyValue), so FF-4/FF-10 use a parent-delete+recreate cycle /
// a forced notify_fail_hook loss respectively, never a plain write, to
// exercise a genuine coverage transition.

TEST_CASE("File mechanism (Windows, direct): set_established_sink seals at start(), still "
          "sealed after stop() (#4340 FF-1)",
          "[spark][established][windows]") {
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    CHECK(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->stop();
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {})); // one-way: still sealed after stop()
}

TEST_CASE("File spark (real mechanism): an existing parent dir reaches Notification coverage "
          "with a stamped established_at (#4340 FF-2)",
          "[spark][established][windows]") {
    ScratchDir a("est_target");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec(a.file.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): an absent parent dir watches its ancestor with None "
          "coverage until it is created (#4340 FF-3)",
          "[spark][established][windows]") {
    namespace fs = std::filesystem;
    // TempDir removes the tree on scope exit, even when a REQUIRE below fails;
    // declared before the engine so the engine (and its directory handles) is
    // destroyed first.
    yuzu::test::TempDir tmp("yuzu_test_spark_est4340_absent_");
    const fs::path root = tmp.path;
    const fs::path parent = root / "watched";
    const fs::path target = parent / "file.txt";
    fs::create_directories(root); // root exists; `parent` (the target's own dir) does not

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    engine.start();

    // Ancestor-mode establishment settles quickly too (root exists), but it
    // must NEVER report Notification for the absent target - only None,
    // unconditionally, per the mode gate.
    std::this_thread::sleep_for(300ms);
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    // Create the parent dir + file: the ancestor's own notification fires,
    // the re-probe resolves to Target, and establishment must stamp.
    fs::create_directories(parent);
    { std::ofstream(target) << "seed"; }
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        10000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): an absent parent dir under sibling churn on its ancestor "
          "keeps reading None with bounded probe launches and no leaked workers (CH-11, bounded "
          "regression scenario: 200 create+remove pairs, not proof of no unbounded growth)",
          "[spark][established][windows][walkoff]") {
    namespace fs = std::filesystem;
    constexpr int kPairs = 200;
    constexpr std::uint64_t kEventsPerPair = 2; // one change record per create, one per remove
    constexpr std::uint64_t kCompletionsPerEvent = 2; // a record may surface as two completions
    constexpr std::uint64_t kLaunchesPerCompletion = 2; // reappearance probe + one owed re-probe
    constexpr std::uint64_t kPaced = static_cast<std::uint64_t>(kPairs) * kEventsPerPair;
    yuzu::test::TempDir tmp("yuzu_test_spark_ch11_absent_");
    const fs::path root = tmp.path;
    const fs::path target = root / "watched" / "file.txt"; // `watched` is never created
    fs::create_directories(root);

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms; // arm() returns with the ancestor watch committed
        ctl.health_grace = 60000ms;      // keep Fault edges out of the run
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    auto sub = engine.arm(*c, file_spec(target.string()));
    REQUIRE(sub.has_value());

    const auto snap = [&] { return *file_debug_counters_for_test(*raw); };
    const auto idle = [&] { return snap().probe_workers_active == 0; };
    REQUIRE(stable_for([&] { return snap().probe_launched; }, 150ms, 5000ms));
    REQUIRE(eventually(idle, 5000ms));
    const auto baseline = snap().probe_launched;

    bool reading_stable = true;
    const auto observe = [&] {
        const auto est = engine.subscription_establishment(*sub);
        if (!est || est->coverage != SparkCoverage::None || est->established_at)
            reading_stable = false;
    };
    // Pacing only shapes the load: a timed-out wait, or a spent 30 s budget, is not a failure.
    const auto soak_until = std::chrono::steady_clock::now() + 30s;
    const auto paced_event = [&](auto&& mutate) {
        const auto before = snap().probe_launched;
        mutate();
        if (std::chrono::steady_clock::now() > soak_until)
            return;
        (void)eventually(
            [&] {
                const auto d = snap();
                return d.probe_launched > before && d.probe_workers_active == 0;
            },
            2000ms);
        observe();
    };
    const auto settle_and_bound = [&](std::uint64_t events) {
        REQUIRE(stable_for([&] { return snap().probe_launched; }, 100ms, 5000ms));
        REQUIRE(eventually(idle, 5000ms));
        const auto d = snap();
        const auto retries =
            d.probe_admission_rejected + d.probe_backend_failed + d.probe_launch_failed;
        INFO("probe_launched=" << d.probe_launched << " baseline=" << baseline
                               << " events=" << events << " retries=" << retries);
        CHECK(d.probe_launched > baseline); // the noise reached the mechanism
        CHECK(d.probe_launched <=
              baseline + kLaunchesPerCompletion * kCompletionsPerEvent * events + retries);
        CHECK(d.synthetic_fires == 0);
    };
    const auto make_sibling = [&](int i) {
        std::error_code ec;
        fs::create_directory(root / ("sib" + std::to_string(i)), ec);
        REQUIRE(!ec);
    };
    const auto remove_sibling = [&](int i) {
        std::error_code ec;
        fs::remove(root / ("sib" + std::to_string(i)), ec);
    };

    for (int i = 0; i < kPairs; ++i) {
        paced_event([&] { make_sibling(i); });
        paced_event([&] { remove_sibling(i); });
    }
    settle_and_bound(kPaced);

    for (int i = kPairs; i < 2 * kPairs; ++i) {
        make_sibling(i);
        remove_sibling(i);
    }
    settle_and_bound(2 * kPaced);

    CHECK(reading_stable);
    const auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());
    const auto d = snap();
    CHECK(d.live_dirs == 1);
    CHECK(d.live_ancestors == 1);
    CHECK(d.retiring == 0);
    CHECK(d.probe_workers_active == 0);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a parent-dir delete + recreate cycle loses and regains "
          "coverage without ever re-stamping established_at (#4340 FF-4)",
          "[spark][established][windows]") {
    // An ORDINARY write never drops File's coverage (the
    // reissue is synchronous) - only losing the parent DIRECTORY does, so
    // this exercises the delete+recreate cycle, not a plain write.
    namespace fs = std::filesystem;
    yuzu::test::TempDir tmp("yuzu_test_spark_est4340_rearm_"); // removed even on a failed REQUIRE
    const fs::path root = tmp.path;
    const fs::path parent = root / "watched";
    const fs::path target = parent / "file.txt";
    std::error_code ec;
    fs::create_directories(parent);
    { std::ofstream(target) << "seed"; }

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    engine.start();

    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto stamped = *est->established_at;

    // Fail loudly at the setup step: a delete that did not happen would leave
    // the wait below timing out with no hint why.
    REQUIRE(fs::remove(target, ec));
    REQUIRE_FALSE(ec);
    REQUIRE(fs::remove(parent, ec));
    REQUIRE_FALSE(ec);
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::None;
        },
        8000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // loss of coverage never un-stamps established_at

    fs::create_directories(parent);
    { std::ofstream(target) << "recreated"; }
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        10000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // still first-wins - recovery never re-stamps

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a parked initial discovery probe leaves coverage None "
          "until release, then stamps established_at (#4340 FF-5)",
          "[spark][established][windows]") {
    ScratchDir a("est_late");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    FileProbeGate gate;
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.dir);
    REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec(a.file.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value()); // success-with-pending
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    std::this_thread::sleep_for(200ms); // well past the 50 ms caller budget/sweep cadence
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    // NB: the engine's armed-entry cache defaults to None, so this cannot tell
    // an explicit mechanism-side None report from none at all - FF-5b below
    // observes the mechanism's sink directly for exactly that.
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    const auto t_release = std::chrono::steady_clock::now();
    gate.release();
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        5000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= t_release);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File mechanism (Windows, direct): a published-pending initial probe reports an "
          "explicit None to the establishment sink before any Notification (#4340 FF-5b)",
          "[spark][established][windows]") {
    // FF-5 above reads only SparkEngine::subscription_establishment(), whose
    // armed-entry cache DEFAULTS to None: it stays green if the mechanism
    // never reports the published-pending None at all (the File branch once
    // omitted mark_coverage_locked() where Registry's identical branch has
    // it). Only a direct sink observer,
    // as RF-10/FF-10 use, can tell an explicit report from an absent one.
    ScratchDir a("est_direct_pending");
    // Everything a callback or hook below captures is declared BEFORE `mech`
    // (see EstLog): a fatal REQUIRE must join the mechanism's threads first.
    FileProbeGate gate;
    EstLog log;
    auto mech = make_file_mechanism();
    REQUIRE(mech);

    REQUIRE(mech->set_established_sink(log.sink()));
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kToken = 42;
    const auto spec = file_spec(a.file.string());
    // Success-with-pending: returns after the caller budget with the probe
    // still parked on the worker.
    REQUIRE(mech->watch_incarnation(spark_key(spec), spec.params, kToken).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // The None must arrive while the probe is STILL parked - no Notification
    // can exist yet, so this entry is the explicit published-pending report.
    REQUIRE(eventually([&] { return log.established_count() >= 1; }, 5000ms));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 1);
        CHECK(seq[0].incarnation == kToken);
        CHECK(seq[0].coverage == SparkCoverage::None);
    }

    gate.release();
    REQUIRE(eventually([&] { return log.established_count() >= 2; }, 5000ms));
    {
        const auto seq = log.established();
        CHECK(seq[1].incarnation == kToken);
        CHECK(seq[1].coverage == SparkCoverage::Notification);
    }

    mech->stop();
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File spark (real mechanism): a deterministic completion failure reports None until "
          "the recovery reissue commits Notification (#4340 FF-6)",
          "[spark][established][windows]") {
    ScratchDir a("est_notify_fail");
    // State the hooks below capture is declared BEFORE `engine`: the engine
    // owns the mechanism, whose worker thread calls the hooks, so a fatal
    // REQUIRE must destroy the engine (joining that thread) before this state.
    FileProbeGate gate;
    std::atomic<bool> armed{true};
    Collector got;
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = file_spec(a.file.string());
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto stamped = *est->established_at;

    // Force the NEXT real completion for this dir to be reported !ok: a
    // genuine coverage loss distinct from an ordinary fire. The recovery probe
    // that loss stages is PARKED, so the None persists until release() instead
    // of lasting the ~50 ms the recovery normally takes (a poll could miss a
    // transient that short on a loaded runner). Both hooks go in ONE call:
    // each call replaces every hook.
    {
        FileMechanismTestControls ctl;
        ctl.notify_fail_hook = [&, dir = a.dir.wstring()](std::wstring_view d) {
            if (d != dir)
                return false;
            return armed.exchange(false, std::memory_order_acq_rel); // one-shot
        };
        ctl.probe_hook = gate.hook_for(a.dir);
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    a.write("trigger a completion");
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 8000ms));
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::None;
        },
        8000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // a coverage loss never un-stamps established_at

    // Release the parked recovery probe and clear the hooks: the mechanism's
    // own stage_probe_locked recovery re-arms.
    gate.release();
    {
        FileMechanismTestControls ctl; // null hooks clear both
        REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    }
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        10000ms));
    est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    CHECK(*est->established_at == stamped); // still first-wins

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a disarm racing a re-arm (adoption) still lets the "
          "mechanism report establishment against the fresh incarnation (#4340 FF-7)",
          "[spark][established][windows]") {
    ScratchDir a("est_adopt");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec(a.file.string());
    auto sub1 = engine.arm(*c, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub1);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));

    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c, spec); // dedup: same key -> the engine renews the
                                           // existing armed_ entry, skipping unwatch()
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());

    REQUIRE(eventually(
        [&] {
            auto est = engine.subscription_establishment(*sub2);
            return est.has_value() && est->coverage == SparkCoverage::Notification;
        },
        5000ms));
    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at); // never predates the adopting arm
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);

    engine.disarm(*sub2);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a key joining an already-established directory reads "
          "Notification promptly, the sibling's own coverage is unchanged (#4340 FF-8, coalesce)",
          "[spark][established][windows]") {
    namespace fs = std::filesystem;
    ScratchDir dir("est_coalesce");
    const fs::path file_b = dir.dir / "second.txt";
    { std::ofstream(file_b) << "seed"; }

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec_a = file_spec(dir.file.string());
    auto sub_a = engine.arm(*c, spec_a);
    REQUIRE(sub_a.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub_a);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est_a = engine.subscription_establishment(*sub_a);
    REQUIRE(est_a.has_value());
    REQUIRE(est_a->established_at.has_value());
    const auto a_stamped = *est_a->established_at;

    // B joins the SAME directory (already established): it must read
    // Notification promptly (well under one sweep cadence), and A's own
    // stamp must be untouched by the join.
    const auto spec_b = file_spec(file_b.string());
    const auto t0 = std::chrono::steady_clock::now();
    auto sub_b = engine.arm(*c, spec_b);
    REQUIRE(sub_b.has_value());
    REQUIRE(eventually(
        [&] {
            auto est = engine.subscription_establishment(*sub_b);
            return est.has_value() && est->coverage == SparkCoverage::Notification;
        },
        2000ms));
    auto est_b = engine.subscription_establishment(*sub_b);
    REQUIRE(est_b.has_value());
    REQUIRE(est_b->established_at.has_value());
    CHECK(*est_b->established_at >= est_b->armed_at);
    CHECK(*est_b->established_at >= t0);

    est_a = engine.subscription_establishment(*sub_a);
    REQUIRE(est_a.has_value());
    CHECK(*est_a->established_at == a_stamped); // sibling's join never re-stamps A

    engine.disarm(*sub_a);
    engine.disarm(*sub_b);
    engine.stop();
}

TEST_CASE("File spark (real mechanism): a key joining during a parked probe is None until "
          "release, then both keys reach Notification (#4340 FF-9, coalesce)",
          "[spark][established][windows]") {
    namespace fs = std::filesystem;
    ScratchDir dir("est_coalesce_park");
    const fs::path file_b = dir.dir / "second.txt";
    { std::ofstream(file_b) << "seed"; }

    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    FileProbeGate gate;
    SparkEngine engine;
    auto mech = make_file_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());
    FileMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(dir.dir);
    REQUIRE(set_file_test_controls_for_test(*raw, std::move(ctl)));
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec_a = file_spec(dir.file.string());
    auto sub_a = engine.arm(*c, spec_a);
    REQUIRE(sub_a.has_value()); // success-with-pending; A's initial probe parks
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // B joins the SAME (not-yet-established) directory while A's probe is
    // still parked - B rides along with A's own outstanding obligation, no
    // second probe launched.
    const auto spec_b = file_spec(file_b.string());
    auto sub_b = engine.arm(*c, spec_b);
    REQUIRE(sub_b.has_value());

    std::this_thread::sleep_for(200ms);
    auto est_a = engine.subscription_establishment(*sub_a);
    auto est_b = engine.subscription_establishment(*sub_b);
    REQUIRE(est_a.has_value());
    REQUIRE(est_b.has_value());
    CHECK(est_a->coverage == SparkCoverage::None);
    CHECK(est_b->coverage == SparkCoverage::None);

    gate.release();
    REQUIRE(eventually(
        [&] {
            auto ea = engine.subscription_establishment(*sub_a);
            auto eb = engine.subscription_establishment(*sub_b);
            return ea.has_value() && ea->coverage == SparkCoverage::Notification &&
                  eb.has_value() && eb->coverage == SparkCoverage::Notification;
        },
        5000ms));

    engine.disarm(*sub_a);
    engine.disarm(*sub_b);
    engine.stop();
}

TEST_CASE("File mechanism (Windows, direct): the establishment sink reports the ordered "
          "coverage sequence [Notification, None, Notification] against a fixed incarnation, "
          "and an intervening ordinary write produces NO extra report (#4340 FF-10)",
          "[spark][established][windows]") {
    // Direct (no engine) so a real SparkIncarnation token can be supplied and
    // every report's identity checked. Unlike Registry's RF-10 (which parks
    // the RE-ARM probe to prove ordering), File's ordinary fire never even
    // launches a probe (the reissue is synchronous) - the
    // deterministic loss here comes from notify_fail_hook, mirroring FF-6.
    ScratchDir a("est_direct_seq");
    // Everything a callback or hook below captures is declared BEFORE `mech`
    // (see EstLog): a fatal REQUIRE must join the mechanism's threads first.
    EstLog log;
    std::atomic<int> emits{0};
    std::atomic<bool> armed{true};
    auto mech = make_file_mechanism();
    REQUIRE(mech);

    // A caller budget far above any probe latency makes the initial probe
    // commit deterministically INSIDE watch_incarnation's own wait, so the
    // sequence below starts at Notification (never a published-pending None).
    // Scalar controls persist across the later notify_fail_hook calls.
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([&](const std::string&, SparkData) { emits.fetch_add(1, std::memory_order_acq_rel); },
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kToken = 42;
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch_incarnation(spark_key(spec), spec.params, kToken).has_value());

    // Initial establishment: Notification, token 42, no emit yet.
    REQUIRE(eventually([&] { return log.established_count() >= 1; }));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 1);
        CHECK(seq[0].incarnation == kToken);
        CHECK(seq[0].coverage == SparkCoverage::Notification);
    }
    CHECK(emits.load() == 0);

    // An ORDINARY write: the reissue is synchronous, so this
    // must produce an emit but NO additional established report.
    a.write("ordinary change");
    REQUIRE(eventually([&] { return emits.load(std::memory_order_acquire) >= 1; }, 8000ms));
    std::this_thread::sleep_for(200ms);
    REQUIRE(log.established_count() == 1); // still just the initial commit

    // Force the NEXT completion for this dir to be reported !ok: a
    // genuine, deterministic coverage loss.
    {
        FileMechanismTestControls ctl;
        ctl.notify_fail_hook = [&, dir = a.dir.wstring()](std::wstring_view d) {
            if (d != dir)
                return false;
            return armed.exchange(false, std::memory_order_acq_rel); // one-shot
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    a.write("trigger the forced loss");
    REQUIRE(eventually([&] { return log.established_count() >= 2; }, 8000ms));
    {
        const auto seq = log.established();
        CHECK(seq[1].incarnation == kToken);
        CHECK(seq[1].coverage == SparkCoverage::None);
    }

    // Clear the hook: the recovery reissue commits Notification again.
    {
        FileMechanismTestControls ctl; // null hook clears it
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(eventually([&] { return log.established_count() >= 3; }, 10000ms));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 3);
        CHECK(seq[2].incarnation == kToken);
        CHECK(seq[2].coverage == SparkCoverage::Notification);
    }

    mech->stop();
}

TEST_CASE("File mechanism (Windows, direct): an establishment report and an action staged in "
          "the SAME sweep visit dispatch in established-before-action order (#4340 FF-11)",
          "[spark][established][windows]") {
    // The File twin of Registry's RF-11 (see its rationale): FF-10 above
    // pins ordering across passes only. Here the first sweep visit that sees
    // the published-pending call (published in the same mu_ hold that marks
    // None due - the mark FF-5b pins) finds health_grace (1 ms) long blown,
    // so ONE visit stages both the drained None report (stage_established_
    // locked, ahead of the switch) and, from grace_check_locked, a Fault
    // notice into work.notices. Fault and Emit share that one notices loop,
    // so this pins the same established-before-notices property for an Emit
    // (an Emit needs a commit, whose re-marked Notification is
    // never drained in the same visit - see RF-11).
    ScratchDir a("est_same_pass");
    // Everything a callback or hook below captures is declared BEFORE `mech`
    // (see EstLog): a fatal REQUIRE must join the mechanism's threads first.
    FileProbeGate gate;
    EstLog log;
    auto mech = make_file_mechanism();
    REQUIRE(mech);

    REQUIRE(mech->set_established_sink(log.sink()));
    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.dir);
        ctl.health_grace = 1ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {}, log.fault_sink());

    constexpr SparkIncarnation kToken = 42;
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch_incarnation(spark_key(spec), spec.params, kToken).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    REQUIRE(eventually([&] { return log.all().size() >= 2; }, 8000ms));
    {
        const auto seq = log.all();
        CHECK(seq[0].kind == EstLog::Entry::Kind::Established); // established FIRST...
        CHECK(seq[0].incarnation == kToken);
        CHECK(seq[0].coverage == SparkCoverage::None);
        CHECK(seq[1].kind == EstLog::Entry::Kind::Fault); // ...then the same-visit action
        CHECK(seq[1].faulted);
    }

    gate.release();
    REQUIRE(eventually(
        [&] {
            for (const auto& e : log.established())
                if (e.coverage == SparkCoverage::Notification)
                    return true;
            return false;
        },
        8000ms));

    mech->stop();
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

// ── #4340 establishment signal: failure and race coverage (File) ─────────────
//
// The File counterparts of the Registry cases above: FF-12 pairs with RF-12, FF-14
// with RF-13, FF-15 with RF-15, FF-16 with RF-16 and FF-17 with RF-17. FF-13 (a
// failed synchronous reissue) has no Registry twin and RF-14 (a dropped None) has
// no File twin. The same two seam traps apply (all hooks in ONE
// controls struct per call; captured state declared before `mech`), and the same
// one-slot-lane recipe lines a staged report and a probe launch up in one pass
// (see the Registry section comment). File differences: the sweeping thread is the
// IOCP worker, so parking the hook also parks completion processing (which is why
// FF-17 has no "fire" step), reports are staged per KEY of a directory, and the
// worker has no pass-failure backoff or counter.

TEST_CASE("File mechanism (Windows, direct): a pass that throws AFTER staging an establishment "
          "report re-delivers it on a later pass, and a sibling's retry is not stranded "
          "(#4340 FF-12)",
          "[spark][established][windows]") {
    ScratchDir a("est_unwind_a"), s("est_unwind_s"), b("est_unwind_b"), b2("est_unwind_b2");
    FileProbeGate occupy;
    ParkGate hook_park;
    std::atomic<int> hook_calls{0};
    std::atomic<bool> threw{false};
    EstLog log;
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    OpenGateOnExit open_hook{hook_park}; // after `mech`: a failed REQUIRE unparks the worker first

    {
        FileMechanismTestControls ctl;
        ctl.probe_lane_cap = 1;
        ctl.caller_wait_budget = 5000ms;
        ctl.health_grace = 60000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kA = 42, kS = 51, kB = 61, kB2 = 62;
    const auto spec_a = file_spec(a.file.string());
    const auto spec_s = file_spec(s.file.string());
    const auto spec_b = file_spec(b.file.string());
    const auto spec_b2 = file_spec(b2.file.string());
    const std::string key_a = spark_key(spec_a), key_s = spark_key(spec_s),
                      key_b = spark_key(spec_b), key_b2 = spark_key(spec_b2);

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kA).has_value());
    REQUIRE(eventually([&] { return log.has(key_a, kA, SparkCoverage::Notification); }));
    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));

    {
        FileMechanismTestControls ctl;
        ctl.probe_hook = occupy.hook_for(s.dir);
        ctl.emit_bookkeeping_hook = [&] {
            const int n = hook_calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (n == 1) {
                hook_park.park(); // pass N
            } else if (n == 2) {
                threw.store(true, std::memory_order_release);
                throw std::runtime_error("injected failure after a report was staged");
            }
        };
        ctl.caller_wait_budget = 40ms;
        ctl.admission_backoff_seed = 50ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->watch_incarnation(key_s, spec_s.params, kS).has_value()); // pending: S's probe parks
    REQUIRE(eventually([&] { return occupy.parked.load() == 1; }, 2000ms));
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, kB).has_value()); // lane full: Deferred
    REQUIRE(hook_park.wait_entered(8000ms)); // pass N (B's first retry launch): worker parked

    // While the worker is parked: A's report becomes due (adoption), B2 becomes due ~50 ms on.
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kA).has_value());
    REQUIRE(mech->watch_incarnation(key_b2, spec_b2.params, kB2).has_value());
    std::this_thread::sleep_for(200ms); // a LOWER bound only: nothing can visit B2 while parked
    hook_park.release();

    REQUIRE(eventually([&] { return threw.load(std::memory_order_acquire); }, 8000ms));
    REQUIRE(eventually([&] { return log.count(key_a, kA) >= 2; }, 8000ms));

    occupy.release();
    REQUIRE(eventually(
        [&] {
            return log.has(key_s, kS, SparkCoverage::Notification) &&
                   log.has(key_b, kB, SparkCoverage::Notification) &&
                   log.has(key_b2, kB2, SparkCoverage::Notification);
        },
        10000ms));
    CHECK(log.count(key_a, kA) == 2); // the initial report + exactly one re-delivery

    mech->stop();
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File mechanism (Windows, direct): a failed synchronous reissue reports None, then the "
          "recovery commit reports Notification, under a fixed incarnation (#4340 FF-13)",
          "[spark][established][windows]") {
    // The reissue-failure site (real_rearm_fail_hook) is distinct from FF-6/FF-10's failed
    // completion (notify_fail_hook): each marks coverage lost at its own line.
    ScratchDir a("est_reissue_fail");
    EstLog log;
    std::atomic<bool> fail_once{false};
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    constexpr SparkIncarnation kToken = 42;
    const auto spec = file_spec(a.file.string());
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, kToken).has_value());
    REQUIRE(eventually([&] { return log.established_count() >= 1; }));

    {
        FileMechanismTestControls ctl;
        ctl.real_rearm_fail_hook = [&, dir = a.dir.wstring()](std::wstring_view d) {
            return d == dir && fail_once.exchange(false, std::memory_order_acq_rel); // one-shot
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    fail_once.store(true, std::memory_order_release);
    a.write("an ordinary change whose reissue is forced to fail");
    REQUIRE(eventually([&] { return log.established_count() >= 3; }, 10000ms));
    {
        const auto seq = log.established();
        REQUIRE(seq.size() == 3);
        CHECK(seq[0].coverage == SparkCoverage::Notification); // the initial establishment
        CHECK(seq[1].coverage == SparkCoverage::None);         // the failed reissue
        CHECK(seq[2].coverage == SparkCoverage::Notification); // the recovery commit
        for (const auto& e : seq)
            CHECK(e.incarnation == kToken);
    }
    mech->stop();
}

TEST_CASE("File mechanism (Windows, direct): a throwing establishment sink is contained - the "
          "drop is counted, the rest of the batch is delivered, the worker survives and the "
          "dropped report is not re-staged (#4340 FF-14)",
          "[spark][established][windows]") {
    namespace fs = std::filesystem;
    ScratchDir d("est_thr");
    const fs::path f2 = d.dir / "f2.txt", f3 = d.dir / "f3.txt";
    { std::ofstream(f2) << "seed"; }
    { std::ofstream(f3) << "seed"; }
    ParkGate stall;
    EstLog log;
    log.stall_on_call = 1; // the first delivery (key1's initial report) parks the worker in the sink
    log.stall = &stall;
    log.throw_if = [](std::size_t n, const EstLog::Entry&) { return n == 2; };
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    OpenGateOnExit open_stall{stall}; // after `mech`: a failed REQUIRE unparks the worker first
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    const auto spec1 = file_spec(d.file.string());
    const auto spec2 = file_spec(f2.string());
    const auto spec3 = file_spec(f3.string());
    const std::string key1 = spark_key(spec1), key2 = spark_key(spec2), key3 = spark_key(spec3);

    REQUIRE(mech->watch_incarnation(key1, spec1.params, 81).has_value());
    REQUIRE(stall.wait_entered(8000ms)); // the worker is parked INSIDE the sink, off-lock
    // Two more keys join the same directory while it is parked: the directory's next report is
    // staged as ONE batch with an entry per key, and its first entry is delivery #2 - the throw.
    REQUIRE(mech->watch_incarnation(key2, spec2.params, 82).has_value());
    REQUIRE(mech->watch_incarnation(key3, spec3.params, 83).has_value());
    stall.release();

    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->established_failed == 1; }, 8000ms));
    // The initial report plus the two batch entries that were NOT dropped.
    REQUIRE(eventually([&] { return log.established_count() >= 3; }, 8000ms));
    const auto dropped = log.dropped_entries();
    REQUIRE(dropped.size() == 1);
    const std::string dropped_key = dropped[0].key;
    CHECK((dropped_key == key1 || dropped_key == key2 || dropped_key == key3));
    CHECK(log.count_key_reports(dropped_key) == (dropped_key == key1 ? 1u : 0u));

    // No re-stage: once everything settled nothing else is delivered or attempted.
    REQUIRE(stable_for([&] { return log.calls_made(); }, 600ms, 8000ms));
    CHECK(file_debug_counters_for_test(*mech)->established_failed == 1);
    CHECK(log.established_count() == 3);

    // The worker survived: re-adopting key1 under a fresh incarnation reports again. (File
    // stages a directory's report per key, so the siblings - including the dropped key - are
    // re-reported by that unrelated later mark; the dropped report itself was never re-staged.)
    REQUIRE(mech->watch_incarnation(key1, spec1.params, 84).has_value());
    REQUIRE(eventually([&] { return log.has(key1, 84, SparkCoverage::Notification); }, 8000ms));
    CHECK(file_debug_counters_for_test(*mech)->established_failed == 1);
    mech->stop();
}

TEST_CASE("File mechanism (Windows, direct): stop() with a staged but unserved joiner report "
          "drops it undispatched and returns once the parked worker is released "
          "(CH-8, characterisation)",
          "[spark][established][windows]") {
    namespace fs = std::filesystem;
    struct Ch8 {
        std::atomic<bool> stop_entered{false};
        std::atomic<bool> stop_returned{false};
        ParkGate gate;
        EstLog log;
    };
    ScratchDir scratch("est_ch8");
    const fs::path f2 = scratch.dir / "f2.txt";
    { std::ofstream(f2) << "seed"; }
    const auto st = std::make_shared<Ch8>();
    auto& gate = st->gate;
    auto& log = st->log;
    log.stall_on_call = 1; // the initial Notification report parks the worker inside the sink
    log.stall = &gate;
    std::unique_ptr<ISparkMechanism> mech = make_file_mechanism();
    REQUIRE(mech);
    ISparkMechanism* const mp = mech.get();
    std::jthread stopper; // not joinable until the stop() call below
    OpenGateOnExit open_gate{gate}; // after `stopper`: the gate opens BEFORE the join
    bool wedged = false;
    struct LeakIfWedged {
        std::unique_ptr<ISparkMechanism>& m;
        std::jthread& t;
        const bool& wedged;
        ~LeakIfWedged() {
            if (wedged) {
                (void)m.release(); // a stop() that never returns can never be joined
                t.detach();
            }
        }
    } leak_if_wedged{mech, stopper, wedged};

    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kInc1 = 81, kInc2 = 82;
    const auto spec1 = file_spec(scratch.file.string());
    const auto spec2 = file_spec(f2.string());
    const std::string key1 = spark_key(spec1), key2 = spark_key(spec2);
    REQUIRE(mech->watch_incarnation(key1, spec1.params, kInc1).has_value());
    REQUIRE(gate.wait_entered(8000ms)); // the worker is parked INSIDE the sink, off-lock
    // A second key joining the directory marks its report due; the parked worker cannot drain it.
    REQUIRE(mech->watch_incarnation(key2, spec2.params, kInc2).has_value());
    REQUIRE(log.calls_made() == 1);

    stopper = std::jthread([st, mp] {
        st->stop_entered.store(true, std::memory_order_release);
        mp->stop();
        st->stop_returned.store(true, std::memory_order_release);
    });
    REQUIRE(eventually([&] { return st->stop_entered.load(std::memory_order_acquire); }, 5000ms));
    // No public signal shows stop() has set its stop flag, so this is a bounded window, not proof.
    std::this_thread::sleep_for(500ms);
    CHECK_FALSE(st->stop_returned.load(std::memory_order_acquire)); // weak: a negative window
    gate.release();
    if (!eventually([&] { return st->stop_returned.load(std::memory_order_acquire); }, 10000ms)) {
        wedged = true;
        FAIL("stop() did not return within 10 s of the parked worker being released");
    }
    stopper.join();

    CHECK(log.count_key_reports(key2) == 0);
    CHECK(log.count(key1, kInc1) == 1);
    CHECK(log.calls_made() == 1);
    CHECK(stable_for([&] { return log.calls_made(); }, 300ms, 3000ms));
    const auto d = file_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->live_dirs == 0);
    CHECK(d->established_failed == 0);
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File mechanism (Windows, direct): a join storm on one directory while the "
          "establishment sink is parked never blocks a joiner, and once released every joined "
          "key is reported once against the directory's latest stamp, then the mechanism is "
          "idle and stop() returns (CH-6, characterisation)",
          "[spark][established][windows]") {
    constexpr std::size_t kJoiners = 64;
    constexpr SparkIncarnation kInc1 = 81, kJoinerIncBase = 1000;
    struct Ch6 {
        std::atomic<std::size_t> finished{0};
        std::atomic<std::size_t> refused{0};
        std::atomic<bool> stop_returned{false};
        std::vector<std::string> keys;
        std::vector<SparkSpec> specs;
        std::vector<SparkIncarnation> incs;
        std::vector<std::chrono::steady_clock::time_point> started; // slot i: joiner thread only
        ParkGate gate;
        EstLog log;
    };
    ScratchDir scratch("est_ch6");
    const auto st = std::make_shared<Ch6>();
    auto& gate = st->gate;
    auto& log = st->log;
    log.stall_on_call = 1; // the initial Notification report parks the worker inside the sink
    log.stall = &gate;
    std::unique_ptr<ISparkMechanism> mech = make_file_mechanism();
    REQUIRE(mech);
    ISparkMechanism* const mp = mech.get();
    std::jthread joiner;  // not joinable until the storm starts
    std::jthread stopper; // not joinable until the stop() call below
    OpenGateOnExit open_gate{gate}; // after both threads: the gate opens BEFORE either join
    bool wedged = false;
    struct LeakIfWedged {
        std::unique_ptr<ISparkMechanism>& m;
        std::jthread& a;
        std::jthread& b;
        const bool& wedged;
        ~LeakIfWedged() {
            if (wedged) {
                (void)m.release(); // a call that never returns can never be joined
                if (a.joinable())
                    a.detach();
                if (b.joinable())
                    b.detach();
            }
        }
    } leak_if_wedged{mech, joiner, stopper, wedged};

    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    // Capture `st` here (unused otherwise) so the MECHANISM OBJECT ITSELF anchors it for as
    // long as the mechanism exists — including if `leak_if_wedged` below releases it without
    // calling stop() first. Unlike CH-8's `stopper` thread (which stays blocked inside stop()
    // for exactly as long as a genuine wedge persists, keeping its own [st, mp] capture alive
    // the whole time), `joiner` below runs a BOUNDED loop (each watch_incarnation call has its
    // own 5s caller_wait_budget) and returns — dropping its `st` copy — even if the leaked
    // mechanism's internal worker is still genuinely wedged forever afterward. Anchoring `st`
    // in the mechanism's own stored callbacks ties its lifetime to the one object that could
    // still dispatch into it, regardless of which test thread finishes first.
    mech->start([st](const std::string&, SparkData) {},
               [st](const std::string&, bool, std::string_view) {});

    const auto spec1 = file_spec(scratch.file.string());
    const std::string key1 = spark_key(spec1);
    for (std::size_t i = 0; i < kJoiners; ++i) {
        st->specs.push_back(
            file_spec((scratch.dir / ("join" + std::to_string(i) + ".txt")).string()));
        st->keys.push_back(spark_key(st->specs.back()));
        st->incs.push_back(kJoinerIncBase + i);
    }
    st->started.resize(kJoiners);

    REQUIRE(mech->watch_incarnation(key1, spec1.params, kInc1).has_value());
    REQUIRE(gate.wait_entered(8000ms)); // the worker is parked INSIDE the sink, off-lock
    REQUIRE(log.calls_made() == 1);
    const auto before = file_debug_counters_for_test(*mech);
    REQUIRE(before.has_value());
    const auto storm_begin = std::chrono::steady_clock::now();

    // On its own thread so a joiner wedged behind the parked sink fails a deadline, not hangs.
    joiner = std::jthread([st, mp] {
        for (std::size_t i = 0; i < st->keys.size(); ++i) {
            st->started[i] = std::chrono::steady_clock::now();
            if (!mp->watch_incarnation(st->keys[i], st->specs[i].params, st->incs[i]).has_value())
                st->refused.fetch_add(1, std::memory_order_relaxed);
            st->finished.fetch_add(1, std::memory_order_release);
        }
    });
    const auto storm_over = [&] {
        return st->finished.load(std::memory_order_acquire) == kJoiners;
    };
    if (!eventually(storm_over, 10000ms)) {
        gate.release(); // a joiner queued behind the sink would resume now
        wedged = !eventually(storm_over, 5000ms);
        FAIL("the join storm did not finish within 10 s while the sink was parked");
    }
    joiner.join();
    CHECK(st->refused.load() == 0);

    // Parked: nothing more was delivered, and the directory was joined, not re-armed.
    CHECK(log.calls_made() == 1);
    const auto during = file_debug_counters_for_test(*mech);
    REQUIRE(during.has_value());
    CHECK(during->live_dirs == 1);
    CHECK(during->probe_launched == before->probe_launched);

    gate.release();
    const auto all_reported = [&] {
        std::set<std::string> seen;
        for (const auto& e : log.established())
            if (e.coverage == SparkCoverage::Notification)
                seen.insert(e.key);
        return std::ranges::all_of(st->keys,
                                   [&](const std::string& k) { return seen.contains(k); });
    };
    REQUIRE(eventually(all_reported, 8000ms));
    REQUIRE(stable_for([&] { return log.calls_made(); }, 300ms, 5000ms));

    // One post-release batch reports every key on the directory, all at its latest stamp.
    const auto all = log.established();
    CHECK(all.size() == kJoiners + 2);
    CHECK(log.calls_made() == all.size()); // nothing was dropped
    const auto seq1 = log.for_key(key1);
    REQUIRE(seq1.size() == 2);
    CHECK(seq1[0].incarnation == kInc1);
    CHECK(seq1[1].incarnation == kInc1);
    CHECK(seq1[0].coverage == SparkCoverage::Notification);
    CHECK(seq1[1].coverage == SparkCoverage::Notification);
    CHECK(seq1[1].at >= storm_begin);
    const auto batch_at = seq1[1].at;
    std::size_t accounted = seq1.size();
    for (std::size_t i = 0; i < kJoiners; ++i) {
        INFO("joiner " << i);
        const auto seq = log.for_key(st->keys[i]);
        accounted += seq.size();
        REQUIRE(!seq.empty());
        CHECK(seq.size() == 1);
        CHECK(seq[0].incarnation == st->incs[i]);
        CHECK(seq[0].coverage == SparkCoverage::Notification);
        CHECK(seq[0].at >= st->started[i]); // never earlier than the join it answers
        CHECK(seq[0].at == batch_at);
    }
    CHECK(accounted == all.size()); // no report for any key outside the storm

    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));
    const auto after = file_debug_counters_for_test(*mech);
    REQUIRE(after.has_value());
    CHECK(after->live_dirs == 1);
    CHECK(after->live_ancestors == 0);
    CHECK(after->retiring == 0);
    CHECK(after->probe_launched == before->probe_launched);
    CHECK(after->synthetic_fires == before->synthetic_fires);
    CHECK(after->established_failed == before->established_failed);
    CHECK(after->emit_failed == before->emit_failed);

    stopper = std::jthread([st, mp] {
        mp->stop();
        st->stop_returned.store(true, std::memory_order_release);
    });
    if (!eventually([&] { return st->stop_returned.load(std::memory_order_acquire); }, 10000ms)) {
        wedged = true;
        FAIL("stop() did not return within 10 s of the joined keys being reported");
    }
    stopper.join();
    CHECK(log.calls_made() == kJoiners + 2); // an orderly stop() dispatches nothing
    const auto stopped = file_debug_counters_for_test(*mech);
    REQUIRE(stopped.has_value());
    CHECK(stopped->live_dirs == 0);
    CHECK(stopped->live_ancestors == 0);
    CHECK(stopped->retiring == 0);
    CHECK(eventually([&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("File mechanism (Windows, direct): unwatch() and an orderly stop() report nothing "
          "(#4340 FF-15)",
          "[spark][established][windows]") {
    ScratchDir a("est_nonrep_a"), b("est_nonrep_b");
    EstLog log;
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    const auto spec_a = file_spec(a.file.string());
    const auto spec_b = file_spec(b.file.string());
    const std::string key_a = spark_key(spec_a), key_b = spark_key(spec_b);

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, 71).has_value());
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, 72).has_value());
    REQUIRE(eventually([&] { return log.established_count() >= 2; }));

    mech->unwatch(key_a);
    std::this_thread::sleep_for(500ms);
    CHECK(log.established_count() == 2); // unwatch() added no report (no None for key_a)

    mech->stop();
    std::this_thread::sleep_for(300ms);
    CHECK(log.established_count() == 2); // an orderly stop() added none either
    CHECK(log.for_key(key_b).size() == 1);
}

TEST_CASE("File mechanism (Windows, direct): an incarnation rebind on an existing key is "
          "forward-only - a lower incarnation never replaces a higher one (#4340 FF-16)",
          "[spark][established][windows]") {
    ScratchDir a("est_rebind");
    EstLog log;
    auto mech = make_file_mechanism();
    REQUIRE(mech);
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(a.file.string());
    const std::string key = spark_key(spec);

    // 42 -> 50 (a higher incarnation rebinds), then 50 -> 42 (a lower one must NOT).
    REQUIRE(mech->watch_incarnation(key, spec.params, 42).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 1; }));
    REQUIRE(mech->watch_incarnation(key, spec.params, 50).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 2; }));
    REQUIRE(mech->watch_incarnation(key, spec.params, 42).has_value());
    REQUIRE(eventually([&] { return log.for_key(key).size() >= 3; }));
    REQUIRE(stable_for([&] { return log.for_key(key).size(); }, 400ms, 5000ms));

    const auto seq = log.for_key(key);
    REQUIRE(seq.size() == 3);
    CHECK(seq[0].incarnation == 42);
    CHECK(seq[1].incarnation == 50); // forward rebind: the re-report carries the new incarnation
    CHECK(seq[2].incarnation == 50); // NOT 42: a later, lower incarnation never wins
    for (const auto& e : seq)
        CHECK(e.coverage == SparkCoverage::Notification);
    mech->stop();
}

TEST_CASE("File mechanism (Windows, direct): an unwatch and a re-watch landing between a report "
          "being staged and dispatched leave the new incarnation clean, and a sink that "
          "re-enters unwatch()/watch_incarnation() does not deadlock (#4340 FF-17)",
          "[spark][established][windows]") {
    // The File twin of RF-17 (see its rationale, including the deliberate leak of a wedged
    // mechanism and the co-leaked shared `Race` block) minus the "fire" step: the parked thread
    // is the IOCP worker itself, so a write's completion is only QUEUED while it is parked and
    // there is no deterministic fire-inside-the-window to observe.
    ScratchDir a("est_race_a"), sac("est_race_sac"), s("est_race_s"), b("est_race_b"),
        b2("est_race_b2");
    constexpr SparkIncarnation kX = 42, kY = 43, kSac = 80, kS = 51, kB = 61, kB2 = 62;
    const auto spec_a = file_spec(a.file.string());
    const auto spec_sac = file_spec(sac.file.string());
    const auto spec_s = file_spec(s.file.string());
    const auto spec_b = file_spec(b.file.string());
    const auto spec_b2 = file_spec(b2.file.string());
    const std::string key_a = spark_key(spec_a), key_sac = spark_key(spec_sac),
                      key_s = spark_key(spec_s), key_b = spark_key(spec_b),
                      key_b2 = spark_key(spec_b2);
    struct Race {
        FileProbeGate occupy;
        ParkGate hook_park1, hook_park2;
        std::atomic<int> hook_calls{0};
        std::atomic<bool> stale_phase{false}, reentered{false}, reentry_done{false},
            reentry_ok{false};
        EstLog log;
    };
    const auto st = std::make_shared<Race>();
    auto& log = st->log;
    auto& occupy = st->occupy;
    auto& hook_park1 = st->hook_park1;
    auto& hook_park2 = st->hook_park2;
    bool wedged = false;
    std::unique_ptr<ISparkMechanism> mech = make_file_mechanism();
    REQUIRE(mech);
    ISparkMechanism* const mp = mech.get();
    // Declared AFTER `mech`: see RF-17 for the exit order this buys.
    OpenGateOnExit open1{hook_park1}, open2{hook_park2};
    yuzu::test::ScopeExit open_occupy{[st] { st->occupy.release(); }};
    struct LeakIfWedged {
        std::unique_ptr<ISparkMechanism>& m;
        const bool& wedged;
        ~LeakIfWedged() {
            if (wedged)
                (void)m.release(); // a thread deadlocked inside the sink can never be joined
        }
    } leak_if_wedged{mech, wedged};

    {
        FileMechanismTestControls ctl;
        ctl.probe_lane_cap = 1;
        ctl.caller_wait_budget = 5000ms;
        ctl.health_grace = 60000ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    auto record = log.sink();
    REQUIRE(mech->set_established_sink(
        [st, mp, record, key_a, key_sac, params_sac = spec_sac.params](
            const std::string& key, SparkIncarnation inc, std::chrono::steady_clock::time_point at,
            SparkCoverage cov) {
            record(key, inc, at, cov);
            // Only the STALE X report re-enters (the initial establishment must not).
            if (st->stale_phase.load(std::memory_order_acquire) && key == key_a && inc == kX &&
                !st->reentered.exchange(true)) {
                mp->unwatch(key_sac);
                st->reentry_ok.store(mp->watch_incarnation(key_sac, params_sac, 91).has_value(),
                                     std::memory_order_release);
                st->reentry_done.store(true, std::memory_order_release);
            }
        }));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kX).has_value());
    REQUIRE(mech->watch_incarnation(key_sac, spec_sac.params, kSac).has_value());
    REQUIRE(eventually([&] { return log.established_count() >= 2; }));
    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->probe_workers_active == 0; }, 5000ms));

    {
        FileMechanismTestControls ctl;
        // `st` rides along only to keep the gate alive for as long as any copy of this hook
        // (a probe worker holds one) exists.
        ctl.probe_hook = [st, gate_hook = occupy.hook_for(s.dir)](std::wstring_view dir) {
            gate_hook(dir);
        };
        ctl.emit_bookkeeping_hook = [st] {
            const int n = st->hook_calls.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (n == 1)
                st->hook_park1.park(); // pass N
            else if (n == 2)
                st->hook_park2.park(); // pass N+1: A's report staged, not yet dispatched
        };
        ctl.caller_wait_budget = 40ms;
        ctl.admission_backoff_seed = 50ms;
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->watch_incarnation(key_s, spec_s.params, kS).has_value()); // S's probe parks
    REQUIRE(eventually([&] { return occupy.parked.load() == 1; }, 2000ms));
    REQUIRE(mech->watch_incarnation(key_b, spec_b.params, kB).has_value()); // lane full: Deferred
    REQUIRE(hook_park1.wait_entered(8000ms)); // pass N parked

    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kX).has_value()); // A's report due
    REQUIRE(mech->watch_incarnation(key_b2, spec_b2.params, kB2).has_value());
    std::this_thread::sleep_for(200ms); // a LOWER bound only: nothing can visit B2 while parked
    hook_park1.release();
    REQUIRE(hook_park2.wait_entered(8000ms)); // pass N+1: [A, X, Notification] staged, undispatched

    // A is unwatched and re-watched under Y (the lane is full, so Y is Deferred).
    mech->unwatch(key_a);
    REQUIRE(mech->watch_incarnation(key_a, spec_a.params, kY).has_value());

    st->stale_phase.store(true, std::memory_order_release);
    hook_park2.release();
    if (!eventually([&] { return st->reentry_done.load(std::memory_order_acquire); }, 10000ms)) {
        // Only a re-entry that STARTED and never returned is a proven wedge (see RF-17).
        wedged = st->reentered.load(std::memory_order_acquire) &&
                 !st->reentry_done.load(std::memory_order_acquire);
        FAIL("the sink's re-entry into unwatch()/watch_incarnation() did not complete within "
             "10 s ("
             << (wedged ? "it started and never returned: the sink is being called with the "
                          "mechanism lock held (#4181 shape)"
                        : "it never started: the stale report was not dispatched")
             << ")");
    }
    CHECK(st->reentry_ok.load(std::memory_order_acquire));

    occupy.release();
    REQUIRE(eventually(
        [&] {
            return log.has(key_a, kY, SparkCoverage::Notification) &&
                   log.has(key_sac, 91, SparkCoverage::Notification) &&
                   log.has(key_b, kB, SparkCoverage::Notification) &&
                   log.has(key_b2, kB2, SparkCoverage::Notification);
        },
        10000ms));

    // The stale X report was delivered at most once beyond the initial one, as the
    // Notification it was staged as.
    CHECK(log.count(key_a, kX) <= 2);
    for (const auto& e : log.for_key(key_a))
        if (e.incarnation == kX)
            CHECK(e.coverage == SparkCoverage::Notification);
    // Y's own log is unaffected by X: only Y-incarnation reports, ending at Notification.
    std::vector<EstLog::Entry> y;
    for (const auto& e : log.for_key(key_a))
        if (e.incarnation == kY)
            y.push_back(e);
    REQUIRE_FALSE(y.empty());
    CHECK(y.back().coverage == SparkCoverage::Notification);

    mech->stop();
}

// ── File T6-analogue (#2012 PR-B2, criterion #15, reentrancy half) ──────────
//
// Unlike Registry, File's unwatch()/stop() do NOT block the calling thread on a
// SEPARATE callback-owning thread finishing its work first (this file's header
// comment, "OWNERSHIP / DISPATCH PROTOCOL" rule 4 — neither watch() nor
// unwatch() ever calls emit()/fault() synchronously — and there is no
// WaitForThreadpoolWaitCallbacks-shaped drain anywhere in File's unwatch()/
// stop()). So the SPECIFIC deadlock T6 (#4181) found in Registry has no known
// analogue in File's current design. This test is regression insurance, not a
// suspected-red repro: if a future change to File's unwatch()/stop() ever
// introduces a blocking cross-thread drain, this is the test that would catch
// it. It is still built at the SUBPROCESS boundary (never in-process, mirroring
// spark_registry.cpp's own T6) precisely because a wrong assumption here would
// otherwise hang the whole test binary with no recovery.
namespace {
constexpr DWORD kT6FileDeadlockExitCode = 101; // distinct from Registry's kT6DeadlockExitCode (100)

std::string t6_file_dir() {
    char buf[1024]{};
    const DWORD n = ::GetEnvironmentVariableA("YUZU_SPARK_T6_FILE_DIR", buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf))
        return std::string(buf, n);
    return (std::filesystem::temp_directory_path() /
           ("spark_t6_file_" + std::to_string(::GetCurrentProcessId())))
        .string();
}
} // namespace

#define YUZU_SPARK_T6_FILE_CHILD_CASE_NAME "File T6 child: inline same-type re-arm during disarm"

TEST_CASE(YUZU_SPARK_T6_FILE_CHILD_CASE_NAME, "[.][t6-file-child]") {
    namespace fs = std::filesystem;
    const fs::path dir = t6_file_dir();
    std::error_code ec;
    fs::create_directories(dir, ec);
    const fs::path target = dir / "a.txt";
    const fs::path target2 = dir / "b.txt";
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    std::atomic<bool> in_handler{false};
    std::atomic<bool> go{false};
    std::atomic<bool> rearmed{false};
    std::atomic<bool> rearm_done{false};
    std::atomic<int> fires{0};
    std::mutex rearm_err_mu;
    std::string rearm_err;
    auto sub_k = engine.arm_inline(file_spec(target.string()), [&](const SparkEvent&) {
        if (fires.fetch_add(1, std::memory_order_acq_rel) != 0)
            return;
        in_handler.store(true, std::memory_order_release);
        while (!go.load(std::memory_order_acquire))
            std::this_thread::sleep_for(1ms);
        auto s2 = engine.arm_inline(file_spec(target2.string()), [](const SparkEvent&) {});
        if (!s2) {
            std::lock_guard lk(rearm_err_mu);
            rearm_err = s2.error();
        }
        rearmed.store(s2.has_value(), std::memory_order_release);
        rearm_done.store(true, std::memory_order_release);
    });
    REQUIRE(sub_k.has_value());
    engine.start();
    std::this_thread::sleep_for(250ms); // let the IOCP read arm

    { std::ofstream(target, std::ios::app) << "change"; }
    REQUIRE(eventually([&] { return in_handler.load(std::memory_order_acquire); }, 8000ms));

    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*sub_k);
        disarm_done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(300ms);
    go.store(true, std::memory_order_release);

    const bool completed =
        eventually([&] { return disarm_done.load(std::memory_order_acquire); }, 5000ms);
    if (!completed) {
        std::fputs("T6-file child: disarm() did not complete while the Inline callback re-entered "
                   "the same type - deadlock observed\n",
                   stderr);
        std::fflush(stderr);
        ::TerminateProcess(::GetCurrentProcess(), kT6FileDeadlockExitCode);
    }
    CHECK(completed);
    disarmer.join();
    CHECK(eventually([&] { return rearm_done.load(std::memory_order_acquire); }, 5000ms));
    {
        std::lock_guard lk(rearm_err_mu);
        INFO("same-type arm_inline from inside the Inline handler: "
             << (rearm_done.load(std::memory_order_acquire)
                     ? (rearm_err.empty() ? "returned ok" : rearm_err)
                     : "did not return within 5s"));
        CHECK(rearmed.load(std::memory_order_acquire));
    }
    engine.stop();
    fs::remove_all(dir, ec);
}

TEST_CASE("File spark: same-type disarm() does not deadlock against an in-flight Inline callback "
          "(T6-file analogue, subprocess boundary) (#2012 PR-B2, criterion #15, reentrancy half)",
          "[spark][mechanism][windows][walkoff][t6]") {
    wchar_t exe[MAX_PATH]{};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    REQUIRE((exe_len > 0 && exe_len < MAX_PATH));
    const std::string dir = (std::filesystem::temp_directory_path() /
                             ("spark_t6_file_" + std::to_string(::GetCurrentProcessId())))
                                .string();
    REQUIRE(::SetEnvironmentVariableA("YUZU_SPARK_T6_FILE_DIR", dir.c_str()));

    std::wstring cmd = L"\"";
    cmd += exe;
    cmd += L"\" \"";
    {
        const std::string name = YUZU_SPARK_T6_FILE_CHILD_CASE_NAME;
        cmd.append(name.begin(), name.end());
    }
    cmd += L"\" --reporter compact --durations no";

    const std::filesystem::path child_log =
        std::filesystem::temp_directory_path() /
        ("yuzu_test_spark_t6_file_child_" + std::to_string(::GetCurrentProcessId()) + ".log");
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    UniqueHandle hlog(::CreateFileW(child_log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    REQUIRE(hlog.valid());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = hlog.h;
    si.hStdError = hlog.h;
    PROCESS_INFORMATION pi{};
    const BOOL created = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    UniqueHandle hthread(pi.hThread);
    UniqueHandle hprocess(pi.hProcess);
    hlog.reset();
    REQUIRE(created);
    hthread.reset();
    const DWORD wr = ::WaitForSingleObject(hprocess.h, 30000);
    if (wr == WAIT_TIMEOUT) {
        ::TerminateProcess(hprocess.h, 9);
        ::WaitForSingleObject(hprocess.h, 5000);
    }
    DWORD code = 0xFFFFFFFFu;
    ::GetExitCodeProcess(hprocess.h, &code);
    hprocess.reset();
    ::SetEnvironmentVariableA("YUZU_SPARK_T6_FILE_DIR", nullptr);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::string child_out;
    {
        std::ifstream in(child_log, std::ios::binary);
        child_out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::filesystem::remove(child_log, ec);

    INFO("T6-file child: WaitForSingleObject=" << wr << " (0=exited, 258=timeout->killed) exit code="
                                               << code << " (0=completed, " << kT6FileDeadlockExitCode
                                               << "=child saw the deadlock, 3=Catch2 matched no case)");
    INFO("T6-file child output:\n" << child_out);
    CHECK(wr == WAIT_OBJECT_0);
    CHECK(code == 0);
}

TEST_CASE("Registry spark (real mechanism): a parked probe on key A neither stalls arm(B) nor "
          "holds arm(A) past its caller budget (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("iso_a"), b("iso_b");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    ProbeGate gate;
    RegistryMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.sub);
    REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    // arm(A): its probe parks on the worker. The caller must still get an answer
    // within the budget (50 ms) plus scheduling slack - before PR-B1 this call
    // did not return until the probe did.
    const auto spec_a = registry_spec("HKCU", a.sub);
    const auto t0 = std::chrono::steady_clock::now();
    auto sa = engine.arm(*c, spec_a);
    const auto arm_a_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    CHECK(sa.has_value()); // success-with-pending
    INFO("arm(A) returned after " << arm_a_ms << " ms with A's probe parked");
    CHECK(arm_a_ms < 2000);
    CHECK(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // arm(B) while A's probe is still parked: same type, must not queue behind A.
    const auto spec_b = registry_spec("HKCU", b.sub);
    const auto t1 = std::chrono::steady_clock::now();
    auto sb = engine.arm(*c, spec_b);
    const auto arm_b_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1)
            .count();
    CHECK(sb.has_value());
    INFO("arm(B) returned after " << arm_b_ms << " ms while A's probe was parked");
    CHECK(arm_b_ms < 2000);
    // ...and B is genuinely watching: a write fires it (baseline first - an
    // establishment never emits, but the assertion should prove THIS fire).
    std::this_thread::sleep_for(100ms);
    const auto b_before = count_kind(got, spark_key(spec_b), SparkEventKind::Fired);
    CHECK(b_before == 0);
    b.write(1);
    CHECK(eventually(
        [&] { return count_kind(got, spark_key(spec_b), SparkEventKind::Fired) > b_before; },
        8000ms));

    // A missed its health grace while parked: Faulted, counted once as slow_op.
    CHECK(eventually([&] { return engine.stats().armed_faulted == 1; }, 3000ms));
    CHECK(raw->stats().slow_op_total == 1);
    CHECK(count_kind(got, spark_key(spec_a), SparkEventKind::Fired) == 0); // nothing synthetic yet

    // Release the probe: the late result is committed (not dropped), the watch
    // recovers, and the observation gap is closed by exactly one synthetic fire.
    gate.release();
    CHECK(eventually([&] { return engine.stats().armed_faulted == 0; }, 5000ms));
    CHECK(eventually([&] { return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) >= 1; },
                     5000ms));
    // Health edges arrived in order: Faulted strictly before Recovered.
    {
        std::lock_guard lk(got.mu);
        std::ptrdiff_t i_f = -1, i_r = -1;
        for (std::ptrdiff_t i = 0; i < static_cast<std::ptrdiff_t>(got.events.size()); ++i) {
            const auto& ev = got.events[static_cast<std::size_t>(i)];
            if (ev.key != spark_key(spec_a))
                continue;
            if (ev.kind == SparkEventKind::Faulted && i_f < 0)
                i_f = i;
            if (ev.kind == SparkEventKind::Recovered)
                i_r = i;
        }
        CHECK(i_f >= 0);
        CHECK(i_r > i_f);
    }
    // A is really watching now: a real write fires it again.
    const auto before = count_kind(got, spark_key(spec_a), SparkEventKind::Fired);
    a.write(7);
    CHECK(eventually([&] { return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) > before; },
                     8000ms));
    auto dc = registry_debug_counters_for_test(*raw);
    REQUIRE(dc.has_value());
    CHECK(dc->synthetic_fires >= 1);
    CHECK(dc->probe_discarded == 0);
    engine.stop();
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("Registry spark (real mechanism): disarm while the initial probe is still parked "
          "discards the late result and frees the worker (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("late_discard");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    ProbeGate gate;
    RegistryMechanismTestControls ctl;
    ctl.probe_hook = gate.hook_for(a.sub);
    REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec_a = registry_spec("HKCU", a.sub);
    auto sa = engine.arm(*c, spec_a);
    REQUIRE(sa.has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    // Disarm while pending: must return promptly (the retirement is a detached
    // drain, and this watch never armed a wait, so that drain is trivial).
    const auto t0 = std::chrono::steady_clock::now();
    engine.disarm(*sa);
    const auto disarm_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    INFO("disarm(A) returned after " << disarm_ms << " ms with A's probe parked");
    CHECK(disarm_ms < 2000);
    CHECK(engine.stats().armed_sparks == 0);

    // Release the probe: its result belongs to a retired watch - self-disposed by
    // the worker, never committed, never emitted.
    gate.release();
    CHECK(eventually(
        [&] {
            auto d = registry_debug_counters_for_test(*raw);
            return d && d->probe_workers_active == 0 && d->retiring == 0 && d->live_watches == 0;
        },
        5000ms));
    std::this_thread::sleep_for(200ms);
    CHECK(count_kind(got, spark_key(spec_a), SparkEventKind::Fired) == 0);
    CHECK(engine.stats().armed_faulted == 0);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): a failed re-arm is retried on the backend schedule "
          "and recovers - never deaf forever (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("rearm_retry");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    const auto spec_a = registry_spec("HKCU", a.sub);
    REQUIRE(engine.arm(*c, spec_a).has_value()); // healthy initial establishment
    std::this_thread::sleep_for(150ms);

    // From here every probe of A throws inside the worker (WorkerThrew -> a
    // backend failure), and the backend retry base is shortened so the test can
    // observe the schedule.
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = [sub = a.sub](std::string_view s) {
            if (s == sub)
                throw std::runtime_error("simulated re-arm failure");
        };
        ctl.backend_retry_base = 150ms;
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    const auto fired_before_write = count_kind(got, spark_key(spec_a), SparkEventKind::Fired);
    CHECK(fired_before_write == 0);
    a.write(1); // fires: immediate emit, then the re-arm probe fails
    CHECK(eventually(
        [&] {
            return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) > fired_before_write;
        },
        8000ms));
    CHECK(eventually([&] { return engine.stats().armed_faulted == 1; }, 5000ms));
    {
        auto d = registry_debug_counters_for_test(*raw);
        REQUIRE(d.has_value());
        CHECK(d->probe_backend_failed >= 1);
    }
    // Let at least one scheduled retry fail too (proves the retry is timed, not a
    // one-shot), then clear the hook: the next retry recovers the watch.
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->probe_backend_failed >= 2; },
                     5000ms));
    {
        RegistryMechanismTestControls ctl; // null hook clears it; timings unchanged
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    CHECK(eventually([&] { return engine.stats().armed_faulted == 0; }, 10000ms));
    // The recovery closed the gap with a synthetic fire: exactly one more Fired
    // than the immediate fire the write produced. Then the watch is live: a
    // fresh write fires again.
    CHECK(eventually(
        [&] {
            return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) >= fired_before_write + 2;
        },
        5000ms));
    const auto after_recover = count_kind(got, spark_key(spec_a), SparkEventKind::Fired);
    a.write(2);
    CHECK(eventually(
        [&] { return count_kind(got, spark_key(spec_a), SparkEventKind::Fired) > after_recover; },
        8000ms));
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): stop() drains a callback-bearing retirement instead of "
          "leaking it (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("stop_drain");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    std::atomic<bool> in_handler{false};
    std::mutex go_mu;
    std::condition_variable go_cv;
    bool go = false;
    auto release_handler = [&] {
        {
            std::lock_guard lk(go_mu);
            go = true;
        }
        go_cv.notify_all();
    };
    std::atomic<int> fires{0};
    auto sub = engine.arm_inline(registry_spec("HKCU", a.sub), [&](const SparkEvent&) {
        if (fires.fetch_add(1, std::memory_order_acq_rel) != 0)
            return;
        in_handler.store(true, std::memory_order_release);
        std::unique_lock lk(go_mu);
        go_cv.wait(lk, [&] { return go; }); // the TP_WAIT callback is now parked
    });
    REQUIRE(sub.has_value());
    engine.start();
    std::this_thread::sleep_for(150ms);
    a.write(1);
    REQUIRE(eventually([&] { return in_handler.load(std::memory_order_acquire); }, 8000ms));

    // Disarm with the callback parked: control path returns, the drain is now a
    // detached worker blocked in WaitForThreadpoolWaitCallbacks.
    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*sub);
        disarm_done.store(true, std::memory_order_release);
    });
    CHECK(eventually([&] { return disarm_done.load(std::memory_order_acquire); }, 3000ms));
    {
        auto d = registry_debug_counters_for_test(*raw);
        REQUIRE(d.has_value());
        CHECK(d->retiring == 1);
        CHECK(d->drains_launched == 1);
        CHECK(d->drains_completed == 0);
        CHECK(d->drain_workers_active == 1);
    }
    // stop() must WAIT for that drain (its context still points at the
    // mechanism) - it may not complete while the callback is parked...
    std::atomic<bool> stop_done{false};
    std::thread stopper([&] {
        engine.stop();
        stop_done.store(true, std::memory_order_release);
    });
    CHECK_FALSE(eventually([&] { return stop_done.load(std::memory_order_acquire); }, 700ms));
    // ...and completes once the callback returns.
    release_handler();
    CHECK(eventually([&] { return stop_done.load(std::memory_order_acquire); }, 10000ms));
    if (!stop_done.load(std::memory_order_acquire))
        release_handler(); // belt and braces before the joins below
    disarmer.join();
    stopper.join();
    auto d = registry_debug_counters_for_test(*raw);
    REQUIRE(d.has_value());
    CHECK(d->drains_completed == 1);
    CHECK(d->retiring == 0);
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->drain_workers_active == 0; },
                     5000ms));
}

TEST_CASE("Registry spark (real mechanism): retiring cap under a blocked drain refuses new watches "
          "and clears once the drain completes (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("cap_a"), k1("cap_1"), k2("cap_2"), k3("cap_3"), k4("cap_4");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    {
        RegistryMechanismTestControls ctl;
        ctl.retiring_cap = 4;
        ctl.drain_lane_cap = 1; // one blocked drain occupies the whole lane
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    std::mutex go_mu;
    std::condition_variable go_cv;
    bool go = false;
    auto release_handler = [&] {
        {
            std::lock_guard lk(go_mu);
            go = true;
        }
        go_cv.notify_all();
    };
    std::atomic<bool> in_handler{false};
    std::atomic<int> fires{0};
    auto sub_a = engine.arm_inline(registry_spec("HKCU", a.sub), [&](const SparkEvent&) {
        if (fires.fetch_add(1, std::memory_order_acq_rel) != 0)
            return;
        in_handler.store(true, std::memory_order_release);
        std::unique_lock lk(go_mu);
        go_cv.wait(lk, [&] { return go; });
    });
    REQUIRE(sub_a.has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    std::this_thread::sleep_for(150ms);
    a.write(1);
    REQUIRE(eventually([&] { return in_handler.load(std::memory_order_acquire); }, 8000ms));
    engine.disarm(*sub_a); // retirement #1: its drain is parked behind the callback
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->drain_workers_active == 1; },
                     2000ms));

    // Churn: each arm+disarm adds a retirement that cannot get a drain worker
    // (lane cap 1 is busy), so it backlogs. cap=4 => the 4th further arm is refused.
    for (ScratchRegKey* k : {&k1, &k2, &k3}) {
        auto s = engine.arm(*c, registry_spec("HKCU", k->sub));
        REQUIRE(s.has_value());
        engine.disarm(*s);
    }
    {
        auto d = registry_debug_counters_for_test(*raw);
        REQUIRE(d.has_value());
        CHECK(d->retiring == 4);
        CHECK(d->drains_admission_rejected >= 1);
    }
    auto refused = engine.arm(*c, registry_spec("HKCU", k4.sub));
    CHECK_FALSE(refused.has_value());
    CHECK(raw->stats().watch_rejected_total == 1);
    CHECK(raw->stats().retiring_cap == 4);

    // Release the parked callback: drain #1 completes, the backlog drains, the
    // gauge returns to zero and the refused key now arms.
    release_handler();
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->retiring == 0; }, 10000ms));
    auto ok = engine.arm(*c, registry_spec("HKCU", k4.sub));
    CHECK(ok.has_value());
    engine.stop();
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->drain_workers_active == 0; },
                     5000ms));
}

TEST_CASE("Registry spark (real mechanism): a probe parked across stop() is counted on the shared "
          "F3 counter until its worker exits (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("f3_orphan");
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkEngine engine;
    auto mech = make_registry_mechanism(f3);
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    ProbeGate gate;
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.sub);
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    REQUIRE(engine.arm(*c, registry_spec("HKCU", a.sub)).has_value()); // pending, parked
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(f3->load() == 1); // admitted against the SHARED counter, not just the lane

    // stop() with the probe still parked: the watch is retired, its uncommitted
    // probe is leaked-and-counted, and stop() does NOT wait for it.
    const auto t0 = std::chrono::steady_clock::now();
    engine.stop();
    const auto stop_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    INFO("engine.stop() took " << stop_ms << " ms with one probe parked");
    CHECK(stop_ms < 5000);
    CHECK(raw->stats().quarantined_total == 1);
    CHECK(f3->load() == 1); // still parked => still counted (F3 / §24)

    gate.release();
    CHECK(eventually([&] { return f3->load() == 0; }, 5000ms)); // worker exited => counter released
    CHECK(eventually([&] { return registry_debug_counters_for_test(*raw)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("Registry mechanism (direct): stop() during watch()'s bounded wait cancels the "
          "reservation - the late result is discarded, never committed (#2012 PR-B1)",
          "[spark][mechanism][windows][walkoff]") {
    // Mechanism-direct (no engine) so the interleaving is under the test's control:
    // watch() is inside its caller wait when stop() retires the reservation.
    ScratchRegKey a("gen_race");
    auto mech = make_registry_mechanism();
    REQUIRE(mech != nullptr);
    ProbeGate gate;
    {
        RegistryMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(a.sub);
        ctl.caller_wait_budget = 3000ms; // long enough for stop() to land inside it
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> emits{0};
    std::atomic<int> faults{0};
    mech->start([&](const std::string&, SparkData) { emits.fetch_add(1); },
                [&](const std::string&, bool, std::string_view) { faults.fetch_add(1); });
    const auto spec = registry_spec("HKCU", a.sub);
    std::expected<void, std::string> result;
    std::thread watcher([&] { result = mech->watch(spark_key(spec), spec.params); });
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    std::this_thread::sleep_for(100ms); // the watcher is now inside wait_take()
    mech->stop();                        // retires the reservation underneath it
    gate.release();                      // the probe completes AFTER the retirement
    watcher.join();
    CHECK_FALSE(result.has_value()); // the caller observed the cancellation
    auto d = registry_debug_counters_for_test(*mech);
    REQUIRE(d.has_value());
    CHECK(d->probe_discarded == 1);
    CHECK(d->live_watches == 0);
    CHECK(emits.load() == 0);
    CHECK(faults.load() == 0);
    CHECK(eventually([&] { return registry_debug_counters_for_test(*mech)->probe_workers_active == 0; },
                     5000ms));
}

TEST_CASE("Registry spark (real mechanism): a target that appears under an ancestor watch fires "
          "without any value write (#2012 PR-B1 appearance)",
          "[spark][mechanism][windows][walkoff]") {
    // Base behaviour (b9a389b9a: emit on `old_mode == Target || w.mode == Target`)
    // fired on an Ancestor -> Target transition. With the re-arm now asynchronous,
    // that transition is only visible at commit and must be emitted from there.
    ScratchRegKey parent("appear_parent");
    const std::string target = parent.sub + "\\Missing"; // absent at arm time
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", target);
    REQUIRE(engine.arm(*c, spec).has_value()); // establishes in Ancestor mode (on `parent`)
    engine.start();
    CHECK(eventually([&] { return engine.stats().armed_sparks == 1 && engine.stats().armed_faulted == 0; },
                     3000ms));
    std::this_thread::sleep_for(200ms);
    const auto baseline = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    CHECK(baseline == 0); // an initial establishment never emits

    // Create the target key - NO value write. The parent's NAME notification is
    // the only thing that fires; the re-arm resolves to Target, and that
    // appearance must reach the consumer as a Fired event.
    OwnedRegKey created(target, KEY_READ); // deleted on scope exit
    REQUIRE(created.h != nullptr);
    CHECK(eventually([&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > baseline; },
                     5000ms));
    auto d = registry_debug_counters_for_test(*raw);
    REQUIRE(d.has_value());
    CHECK(d->synthetic_fires >= 1);
    engine.stop();
    // `created` deletes the target on scope exit.
}

TEST_CASE("Registry mechanism (direct): a throwing emit is contained on the fire callback and the "
          "synthetic fire is retried on a backoff until it submits (#2012 PR-B1 hole 2)",
          "[spark][mechanism][windows][walkoff]") {
    // Mechanism-direct so the SparkEmitFn is ours: it throws for the first three
    // submissions (the fire callback's immediate emit, the commit's synthetic
    // fire, and the first restored retry) and counts from the fourth on. The
    // engine's real emit can throw std::bad_alloc (see SparkEmitFn's doc); this
    // models it without needing an allocation failure.
    ScratchRegKey a("emit_throw");
    auto mech = make_registry_mechanism();
    REQUIRE(mech != nullptr);
    {
        RegistryMechanismTestControls ctl;
        ctl.admission_backoff_seed = 50ms; // the resync retry schedule's seed (D)
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> submits{0};
    std::atomic<int> delivered{0};
    std::atomic<int> faults{0};
    mech->start(
        [&](const std::string&, SparkData) {
            if (submits.fetch_add(1, std::memory_order_acq_rel) < 3)
                throw std::runtime_error("injected emit failure");
            delivered.fetch_add(1, std::memory_order_acq_rel);
        },
        [&](const std::string&, bool, std::string_view) { faults.fetch_add(1); });
    const auto spec = registry_spec("HKCU", a.sub);
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    std::this_thread::sleep_for(150ms);

    a.write(1); // fire: immediate emit throws (contained), re-arm commits, synthetic throws...
    // ...restored debt retries at 50 ms, 100 ms: the third retry is the fourth
    // submission and lands.
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= 1; }, 5000ms));
    {
        auto d = registry_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        INFO("submits=" << submits.load() << " delivered=" << delivered.load()
                        << " emit_failed=" << d->emit_failed << " resync_retries=" << d->resync_retries);
        CHECK(d->emit_failed == 3);
        CHECK(d->resync_retries >= 2);
        CHECK(delivered.load(std::memory_order_acquire) == 1); // one debt, one delivery
    }
    // The watch is still live and no debt lingers: a second write produces its
    // immediate fire (now delivered) and one synthetic fire, nothing more.
    std::this_thread::sleep_for(200ms);
    const int before = delivered.load(std::memory_order_acquire);
    a.write(2);
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= before + 2; }, 5000ms));
    std::this_thread::sleep_for(300ms);
    CHECK(delivered.load(std::memory_order_acquire) == before + 2);
    CHECK(faults.load() == 0);
    mech->stop();
}

TEST_CASE("Registry mechanism (direct): an allocation failure after a probe launches "
          "successfully does not permanently strand the watch (PR #4225 review)",
          "[spark][mechanism][windows][walkoff]") {
    // Sequence: an initial probe parks past the caller budget (published to
    // the sweeper), then throws (WorkerThrew) -> fail_backend_locked ->
    // Deferred. The NEXT sweep pass promotes Deferred -> Pending and stages a
    // real launch (this time the probe succeeds normally) - run_off_lock()
    // launches it, then the injected hook throws, modelling an allocation
    // failure landing in the SAME pass, after that launch. Pre-fix, this
    // stranded the watch: unwind_pass_locked() skipped the already-launched
    // entry on the (here false) assumption publish_locked() would handle it,
    // leaving w.probe == Pending with w.call == nullptr forever - unrescuable
    // by on_fire() (Idle-only relaunch) or watch() (idempotent no-op on an
    // already-watched key). Post-fix, reconcile_probe_launches_locked() runs
    // unconditionally from unwind_pass_locked() too, adopts the launched call,
    // and the watch re-establishes on the very next pass.
    ScratchRegKey a("strand_probe");
    auto mech = make_registry_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<int> probe_calls{0};
    std::atomic<bool> strand_once{true}; // armed from the start: see emit_bookkeeping_hook's
                                          // doc comment - it only ever fires on a pass that
                                          // staged a real launch, so there is no timing race
                                          // against the sweeper's own cadence to coordinate.
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 30ms;   // short, so the first (parked) probe publishes fast
        ctl.backend_retry_base = 40ms;   // short, so the Deferred retry is fast
        ctl.sweep_cadence = 20ms;        // short, so the sweeper notices promptly
        ctl.probe_hook = [&](std::string_view) {
            if (probe_calls.fetch_add(1, std::memory_order_acq_rel) == 0) {
                std::this_thread::sleep_for(120ms); // past caller_wait_budget
                throw std::runtime_error("injected backend failure (probe #1)");
            }
            // probe #2 (the Deferred retry): proceeds to a real establishment.
        };
        ctl.emit_bookkeeping_hook = [&] {
            if (strand_once.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error(
                    "injected run_off_lock failure after a successful probe launch "
                    "(models an allocation failure, PR #4225 review)");
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> delivered{0};
    mech->start([&](const std::string&, SparkData) { delivered.fetch_add(1, std::memory_order_acq_rel); },
                [&](const std::string&, bool, std::string_view) {});
    const auto spec = registry_spec("HKCU", a.sub);
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    // Probe #1 parks, times out the caller, then throws -> Deferred. Confirm
    // the backend failure actually landed before waiting on recovery, so a
    // failure here points at the wrong half of the setup, not the fix itself.
    REQUIRE(eventually(
        [&] {
            auto d = registry_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_backend_failed >= 1;
        },
        3000ms));

    // The Deferred retry (probe #2) launches, the injected hook strands it
    // (pre-fix) or the fix reconciles it (post-fix) - either way this is the
    // one pass that matters. Give it generous margin past backend_retry_base
    // + a few sweep cadences, then require the SAME key to still be
    // observable: a real registry write must still produce a Fired event.
    // Pre-fix this hangs the whole 6 s deadline (permanently no live wait);
    // post-fix it resolves within one or two sweep cadences of the write.
    std::this_thread::sleep_for(300ms);
    a.write(1);
    INFO("probe_calls=" << probe_calls.load() << " strand_hook_consumed="
                        << !strand_once.load(std::memory_order_acquire));
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= 1; }, 6000ms));
    {
        auto d = registry_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        INFO("probe_launched=" << d->probe_launched << " probe_backend_failed="
                                << d->probe_backend_failed << " sweep_pass_failed="
                                << d->sweep_pass_failed);
        CHECK(d->sweep_pass_failed >= 1); // the injected throw genuinely failed a pass
        CHECK_FALSE(strand_once.load(std::memory_order_acquire)); // the hook did fire once
    }
    mech->stop();
}

// ── Inline-tier dispatch latency (the ADR-0021 §3 µs claim) ──────────────────
//
// SCOPE — read before trusting these numbers. This measures ONLY the
// in-process inline dispatch: from the fire timestamp the engine stamps in
// emit_event (SparkEvent::at) to the inline handler's entry, run synchronously
// on the mechanism's own thread. It is the queue-BYPASS latency the inline tier
// exists to provide. It deliberately does NOT include:
//   - OS notification latency (kernel → us: ReadDirectoryChangesW /
//     RegNotifyChangeKeyValue delivery) — inherently ms-scale, outside the µs
//     claim, not something we control.
//   - the queued tier (bounded queue + a dispatch-thread hop) — that path is
//     ms-ish by design and is what inline avoids.
// Reported as min/median/max over many fires; the assertion is a LOOSE
// scheduler-quantum sanity bound only. The claim is µs-MEDIAN, NOT a hard
// worst-case cap (owner decision 2026-07-06: p99 can reach 100s of µs and a
// ~10ms outlier is possible on a shared pool), so a hard per-sample assert
// would be a false contract and a flake source.

namespace {
struct LatencyStats {
    std::size_t n{0};
    std::int64_t min_us{0}, median_us{0}, p90_us{0}, p99_us{0}, max_us{0};
};
LatencyStats summarize_us(std::vector<std::int64_t> v) {
    LatencyStats s;
    s.n = v.size();
    if (v.empty())
        return s;
    std::sort(v.begin(), v.end());
    s.min_us = v.front();
    s.max_us = v.back();
    s.median_us = v[v.size() / 2];
    s.p90_us = v[(v.size() * 9) / 10];
    // Comment corrected (adversarial-review finding, PR-A round 2): the
    // clamp below never actually binds - (n*99)/100 <= n-1 for every n >= 1
    // (same true of p90's (n*9)/10 above, which is why it needs none), so
    // there is no real off-by-one risk at small n for either percentile.
    // Kept anyway as an explicit, self-documenting bound against
    // std::vector::operator[]'s own UB-on-out-of-range contract, in case a
    // future change to this formula (or to how it's called) ever changes
    // that arithmetic fact.
    s.p99_us = v[std::min(v.size() - 1, (v.size() * 99) / 100)];
    return s;
}
} // namespace

namespace {
/// RAII for a LocalAlloc'd block (SID strings, security descriptors) - governance
/// sg-8-1: no manual LocalFree in new test code.
struct LocalFreed {
    void* p{nullptr};
    LocalFreed() = default;
    explicit LocalFreed(void* ptr) : p(ptr) {}
    ~LocalFreed() {
        if (p)
            ::LocalFree(p);
    }
    LocalFreed(const LocalFreed&) = delete;
    LocalFreed& operator=(const LocalFreed&) = delete;
};

/// RAII for an HKEY opened only for the duration of one function call (the DACL
/// helpers below never carry a key across calls) - governance sg-8-1.
struct ScopedKey {
    HKEY h{nullptr};
    ScopedKey() = default;
    explicit ScopedKey(HKEY key) : h(key) {}
    ~ScopedKey() {
        if (h)
            ::RegCloseKey(h);
    }
    ScopedKey(const ScopedKey&) = delete;
    ScopedKey& operator=(const ScopedKey&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

/// The current process token's user SID as a string (for a test DACL).
std::wstring current_user_sid() {
    HANDLE raw = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &raw))
        return {};
    UniqueHandle tok(raw);
    DWORD n = 0;
    ::GetTokenInformation(tok.h, TokenUser, nullptr, 0, &n);
    std::vector<BYTE> buf(n);
    if (n == 0 || !::GetTokenInformation(tok.h, TokenUser, buf.data(), n, &n))
        return {};
    LPWSTR str = nullptr;
    if (!::ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &str))
        return {};
    LocalFreed owned(str);
    return std::wstring(str);
}

/// Replace a key's DACL from SDDL. Needs a handle opened with WRITE_DAC.
bool apply_sddl(HKEY h, const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd,
                                                                nullptr))
        return false;
    LocalFreed owned(sd);
    return ::RegSetKeySecurity(h, DACL_SECURITY_INFORMATION, sd) == ERROR_SUCCESS;
}

/// Denies the current user KEY_NOTIFY (0x0010) on `sub` while allowing all else,
/// and restores full access on destruction - BEFORE the key is deleted (a deny
/// of DELETE would leave an undeletable key behind on a shared runner box).
struct DenyNotifyScope {
    std::string sub;
    std::wstring sid;
    bool applied{false};
    explicit DenyNotifyScope(std::string subkey) : sub(std::move(subkey)), sid(current_user_sid()) {
        if (sid.empty())
            return;
        ScopedKey key(open_for_dac());
        if (!key)
            return;
        applied = apply_sddl(key.h, L"D:(D;;0x0010;;;" + sid + L")(A;;KA;;;" + sid + L")");
    }
    void restore() {
        if (!applied)
            return;
        if (ScopedKey key{open_for_dac()})
            apply_sddl(key.h, L"D:(A;;KA;;;" + sid + L")");
        applied = false;
    }
    ~DenyNotifyScope() { restore(); }
    DenyNotifyScope(const DenyNotifyScope&) = delete;
    DenyNotifyScope& operator=(const DenyNotifyScope&) = delete;

private:
    [[nodiscard]] HKEY open_for_dac() const {
        HKEY raw = nullptr;
        ::RegOpenKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, WRITE_DAC | READ_CONTROL, &raw);
        return raw; // null on failure; ScopedKey handles null harmlessly
    }
};
} // namespace

TEST_CASE("Registry spark (real mechanism): a health edge staged for one watch is never delivered "
          "to the same-key re-arm that replaced it (#2012 PR-B1 UP-1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("up1_churn");
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    {
        // Every establishment misses a 1 ms grace (a Faulted edge is staged for it),
        // and a fast sweep cadence keeps staging and dispatch close together.
        RegistryMechanismTestControls ctl;
        ctl.health_grace = 1ms;
        ctl.sweep_cadence = 5ms;
        ctl.probe_hook = [sub = a.sub](std::string_view s) {
            if (s == sub)
                std::this_thread::sleep_for(3ms);
        };
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    engine.start();
    const auto spec = registry_spec("HKCU", a.sub);
    // Churn: arm / disarm the SAME key every ~10 ms for a while. Before the fix a
    // Faulted edge staged for a replaced watch could land on its successor and stick.
    int cycles = 0;
    const auto until = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < until) {
        auto s = engine.arm(*c, spec);
        REQUIRE(s.has_value());
        std::this_thread::sleep_for(10ms);
        engine.disarm(*s);
        ++cycles;
    }
    INFO("churn cycles: " << cycles);
    auto last = engine.arm(*c, spec);
    REQUIRE(last.has_value());
    // The engine's per-key health must settle to healthy: no stale Faulted stuck on
    // the surviving watch, and every Faulted this key delivered has its Recovered.
    CHECK(eventually([&] { return engine.stats().armed_faulted == 0; }, 5000ms));
    CHECK(eventually(
        [&] {
            return count_kind(got, spark_key(spec), SparkEventKind::Faulted) ==
                   count_kind(got, spark_key(spec), SparkEventKind::Recovered);
        },
        5000ms));
    const auto before = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    a.write(1);
    CHECK(eventually([&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > before; },
                     8000ms));
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): an existing key that refuses KEY_NOTIFY is an arm "
          "failure, never a silent ancestor watch (#2012 PR-B1 UP-2)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("up2_acl");
    DenyNotifyScope deny(a.sub);
    if (!deny.applied)
        WARN("could not apply the test DACL (no SID or no WRITE_DAC) - the denied half is skipped");
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = registry_spec("HKCU", a.sub);
    if (deny.applied) {
        // The key EXISTS; only its notify is refused. Before the fix the probe fell
        // through to the parent's NAME watch and arm() succeeded: armed, healthy,
        // and deaf to every value change on the key. Now the fast definite failure
        // is reported to the caller.
        auto denied = engine.arm(*c, spec);
        CHECK_FALSE(denied.has_value());
        if (denied.has_value())
            engine.disarm(*denied);
        deny.restore();
    }
    auto ok = engine.arm(*c, spec);
    REQUIRE(ok.has_value());
    std::this_thread::sleep_for(150ms);
    const auto before = count_kind(got, spark_key(spec), SparkEventKind::Fired);
    a.write(1);
    CHECK(eventually([&] { return count_kind(got, spark_key(spec), SparkEventKind::Fired) > before; },
                     8000ms));
    engine.stop();
}

TEST_CASE("Registry mechanism (direct): a sweeper whose passes keep failing reports the mechanism "
          "inert and clears it when a pass succeeds (#2012 PR-B1 sre6-1)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchRegKey a("sweep_fail");
    auto mech = make_registry_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> failing{true};
    std::atomic<int> throws{0};
    {
        RegistryMechanismTestControls ctl;
        ctl.sweep_cadence = 5ms;
        ctl.sweep_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> fired{0};
    mech->start([&](const std::string&, SparkData) { fired.fetch_add(1, std::memory_order_relaxed); },
                [](const std::string&, bool, std::string_view) {});
    const auto spec = registry_spec("HKCU", a.sub);
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value()); // control-path establishment
    CHECK_FALSE(mech->stats().inert);
    a.write(1); // consumed notification -> re-arm published to the sweeper -> passes run and throw
    CHECK(eventually([&] { return throws.load(std::memory_order_relaxed) >= 3; }, 8000ms));
    CHECK(eventually([&] { return mech->stats().inert; }, 8000ms)); // the dark sweeper is visible
    {
        auto d = registry_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->sweep_pass_failed >= 3);
    }
    failing.store(false, std::memory_order_release);
    CHECK(eventually([&] { return !mech->stats().inert; }, 8000ms)); // first good pass clears it
    // The re-arm the failing passes held back has now committed: the watch is live.
    const int before = fired.load(std::memory_order_relaxed);
    a.write(2);
    CHECK(eventually([&] { return fired.load(std::memory_order_relaxed) > before; }, 8000ms));
    mech->stop();
}

TEST_CASE("Registry mechanism (Windows, direct): while every sweeper pass fails the staged None is "
          "not delivered, and after recovery the sequence is [Notification, None, Notification] "
          "(CH-1 direct layer, characterisation)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_outage_direct");
    // Everything a callback or hook below captures is declared BEFORE `mech`: locals unwind in
    // reverse order, so a fatal REQUIRE destroys `mech` (joining its threads) before this state.
    EstLog log;
    std::atomic<bool> failing{false};
    std::atomic<int> passes{0};
    std::atomic<int> emits{0};
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        ctl.sweep_cadence = 20ms;
        ctl.sweep_hook = [&] {
            passes.fetch_add(1, std::memory_order_relaxed);
            if (failing.load(std::memory_order_acquire))
                throw std::bad_alloc{};
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start(
        [&](const std::string&, SparkData) { emits.fetch_add(1, std::memory_order_acq_rel); },
        [](const std::string&, bool, std::string_view) {});

    constexpr SparkIncarnation kToken = 91;
    const auto spec = registry_spec("HKCU", a.sub);
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, kToken).has_value());
    REQUIRE(eventually([&] { return log.has(key, kToken, SparkCoverage::Notification); }));
    // Idle sweeper before the outage starts, so the first failing pass is the write's own nudge.
    REQUIRE(stable_for([&] { return passes.load(std::memory_order_relaxed); }, 300ms, 5000ms));
    CHECK_FALSE(mech->stats().inert);

    failing.store(true, std::memory_order_release);
    a.write(1); // consumes the one-shot notify: on_fire stages the None marker, then emits off-lock
    // Synchronisation, not polling: the emit runs after the marker is staged, and every pass now
    // throws before its drain, so from here the marker exists and cannot be delivered.
    REQUIRE(eventually([&] { return emits.load(std::memory_order_acquire) >= 1; }, 8000ms));
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->sweep_pass_failed >= 3; }, 8000ms));
    REQUIRE(eventually([&] { return mech->stats().inert; }, 8000ms));
    CHECK(log.established_count() == 1);
    CHECK_FALSE(log.has(key, kToken, SparkCoverage::None));
    CHECK(registry_debug_counters_for_test(*mech)->established_failed == 0);

    failing.store(false, std::memory_order_release);
    REQUIRE(eventually([&] { return !mech->stats().inert; }, 15000ms));
    REQUIRE(eventually([&] { return log.established_count() >= 3; }, 15000ms));
    REQUIRE(stable_for([&] { return log.established_count(); }, 400ms, 5000ms));
    const auto seq = log.established();
    REQUIRE(seq.size() == 3);
    for (const auto& e : seq)
        CHECK(e.incarnation == kToken);
    CHECK(seq[0].coverage == SparkCoverage::Notification);
    CHECK(seq[1].coverage == SparkCoverage::None);
    CHECK(seq[2].coverage == SparkCoverage::Notification);

    mech->stop();
}

TEST_CASE("Registry spark (real mechanism): a sweeper outage reads None once the mechanism is "
          "inert with established_at unchanged, and the query follows the recovery "
          "(CH-1 engine layer)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_outage_engine");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    std::atomic<bool> failing{false};
    std::atomic<int> passes{0};
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        ctl.sweep_cadence = 300ms; // failure retries back off from this: three span 900 ms
        ctl.sweep_hook = [&] {
            passes.fetch_add(1, std::memory_order_relaxed);
            if (failing.load(std::memory_order_acquire))
                throw std::bad_alloc{};
        };
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    const std::string key = spark_key(spec);
    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] {
        auto e = engine.subscription_establishment(*sub);
        return e.has_value() && e->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    const auto est0 = *est->established_at;
    // Idle sweeper before the outage starts, so the first failing pass is the write's own nudge.
    REQUIRE(stable_for([&] { return passes.load(std::memory_order_relaxed); }, 600ms, 5000ms));

    const auto fired_before = count_kind(got, key, SparkEventKind::Fired);
    failing.store(true, std::memory_order_release);
    a.write(1); // consumes the one-shot notify: on_fire stages the None marker, then emits off-lock
    // Synchronisation, not polling: the Fired event is emitted after the marker is staged, and
    // every pass throws before its drain, so from here the marker exists and cannot be delivered.
    REQUIRE(eventually([&] { return count_kind(got, key, SparkEventKind::Fired) > fired_before; },
                       8000ms));

    // (1) The stale window: the cache still holds the pre-outage Notification. The counter is
    // read AFTER the query and inert flips only on the third failure, so < 3 proves the query
    // ran before the flip.
    auto stale = engine.subscription_establishment(*sub);
    const auto sampled = registry_debug_counters_for_test(*raw);
    REQUIRE(sampled.has_value());
    {
        INFO("the stale-window sample was taken after the third failed pass");
        REQUIRE(sampled->sweep_pass_failed < 3);
    }
    REQUIRE(stale.has_value());
    CHECK(stale->coverage == SparkCoverage::Notification);
    REQUIRE(stale->established_at.has_value());
    CHECK(*stale->established_at == est0);
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*raw)->sweep_pass_failed >= 1; }, 8000ms));

    // (2) Inert: the mechanism never delivered the None, so a None here is the engine's own
    // overlay. This is the assertion that reads the stale Notification on an engine without it.
    REQUIRE(eventually([&] { return raw->stats().inert; }, 8000ms));
    auto overlaid = engine.subscription_establishment(*sub);
    REQUIRE(overlaid.has_value());
    CHECK(overlaid->coverage == SparkCoverage::None);
    REQUIRE(overlaid->established_at.has_value());
    CHECK(*overlaid->established_at == est0);

    // (3) Recovery: the first good pass clears inert and the query follows the mechanism again.
    failing.store(false, std::memory_order_release);
    REQUIRE(eventually([&] { return !raw->stats().inert; }, 15000ms));
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        15000ms));
    auto recovered = engine.subscription_establishment(*sub);
    REQUIRE(recovered.has_value());
    REQUIRE(recovered->established_at.has_value());
    CHECK(*recovered->established_at == est0);
    CHECK(registry_debug_counters_for_test(*raw)->established_failed == 0);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Registry mechanism (Windows, direct): an adoption re-report staged while the sweeper "
          "is failing is delivered after recovery, the throwing sink drops it, and nothing "
          "re-stages it (CH-4 direct layer, characterisation)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_adopt_backoff");
    constexpr SparkIncarnation kInc1 = 81;
    constexpr SparkIncarnation kInc2 = 82;
    // Everything a callback or hook below captures is declared BEFORE `mech`: locals unwind in
    // reverse order, so a fatal REQUIRE destroys `mech` (joining its threads) before this state.
    EstLog log;
    log.throw_if = [inc2 = kInc2](std::size_t, const EstLog::Entry& e) {
        return e.incarnation == inc2;
    };
    std::atomic<bool> failing{false};
    std::atomic<int> passes{0};
    auto mech = make_registry_mechanism();
    REQUIRE(mech);
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        ctl.sweep_cadence = 20ms;
        ctl.sweep_hook = [&] {
            passes.fetch_add(1, std::memory_order_relaxed);
            if (failing.load(std::memory_order_acquire))
                throw std::bad_alloc{};
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }
    REQUIRE(mech->set_established_sink(log.sink()));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});

    const auto spec = registry_spec("HKCU", a.sub);
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, kInc1).has_value());
    REQUIRE(eventually([&] { return log.has(key, kInc1, SparkCoverage::Notification); }));
    // Idle sweeper before the outage starts, so the first failing pass is the adoption's own nudge.
    REQUIRE(stable_for([&] { return passes.load(std::memory_order_relaxed); }, 300ms, 5000ms));

    failing.store(true, std::memory_order_release);
    // Adoption: the existing watch is rebound to kInc2, its re-report is marked due and the
    // sweeper nudged. Every pass throws before its drain, so the report stays staged.
    REQUIRE(mech->watch_incarnation(key, spec.params, kInc2).has_value());
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->sweep_pass_failed >= 3; }, 8000ms));
    REQUIRE(eventually([&] { return mech->stats().inert; }, 8000ms));
    CHECK(log.calls_made() == 1);
    CHECK(log.count(key, kInc2) == 0);
    CHECK(log.dropped_entries().empty());

    failing.store(false, std::memory_order_release);
    REQUIRE(eventually(
        [&] { return registry_debug_counters_for_test(*mech)->established_failed == 1; }, 15000ms));
    REQUIRE(eventually([&] { return !mech->stats().inert; }, 15000ms));
    // A re-staged persistent throw would keep this climbing.
    REQUIRE(stable_for([&] { return log.calls_made(); }, 600ms, 8000ms));
    CHECK(log.calls_made() == 2);
    CHECK(registry_debug_counters_for_test(*mech)->established_failed == 1);
    const auto dropped = log.dropped_entries();
    REQUIRE(dropped.size() == 1);
    CHECK(dropped[0].incarnation == kInc2);
    CHECK(dropped[0].coverage == SparkCoverage::Notification);
    CHECK(log.count(key, kInc2) == 0);
    CHECK(log.count_key_reports(key) == 1); // only the initial kInc1 report was ever delivered

    mech->stop();
}

TEST_CASE("Registry spark (real mechanism): a disarm racing a re-arm while the sweeper is failing "
          "reads None with no established_at throughout, then Notification after recovery "
          "(CH-4 engine layer, characterisation; no sink throw is injected)",
          "[spark][established][windows]") {
    ScratchRegKey a("est_adopt_engine");
    // Declared BEFORE `engine` (locals unwind in reverse): a fatal REQUIRE then destroys
    // the engine, joining its threads, before this state their callbacks capture.
    Collector got;
    std::atomic<bool> failing{false};
    std::atomic<int> passes{0};
    SparkEngine engine;
    auto mech = make_registry_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Registry, std::move(mech)).has_value());
    {
        RegistryMechanismTestControls ctl;
        ctl.caller_wait_budget = 5000ms;
        ctl.sweep_cadence = 20ms;
        ctl.sweep_hook = [&] {
            passes.fetch_add(1, std::memory_order_relaxed);
            if (failing.load(std::memory_order_acquire))
                throw std::bad_alloc{};
        };
        REQUIRE(set_registry_test_controls_for_test(*raw, std::move(ctl)));
    }
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = registry_spec("HKCU", a.sub);
    auto sub1 = engine.arm(*c, spec);
    REQUIRE(sub1.has_value());
    REQUIRE(eventually([&] {
        auto e = engine.subscription_establishment(*sub1);
        return e.has_value() && e->coverage == SparkCoverage::Notification;
    }));
    // Idle sweeper before the outage starts, so the first failing pass is the adoption's own nudge.
    REQUIRE(stable_for([&] { return passes.load(std::memory_order_relaxed); }, 300ms, 5000ms));

    failing.store(true, std::memory_order_release);
    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c, spec); // the mechanism adopts the live watch
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());
    CHECK_FALSE(engine.subscription_establishment(*sub1).has_value());

    // Until the mechanism goes inert the adopted key must never read a positive: its Armed is
    // fresh, and the adoption report is held back by the failing passes.
    bool never_positive = true;
    REQUIRE(eventually(
        [&] {
            const auto e = engine.subscription_establishment(*sub2);
            if (!e.has_value() || e->coverage != SparkCoverage::None ||
                e->established_at.has_value())
                never_positive = false;
            return raw->stats().inert;
        },
        8000ms));
    CHECK(never_positive);
    CHECK(registry_debug_counters_for_test(*raw)->sweep_pass_failed >= 3);
    auto est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    CHECK(est->coverage == SparkCoverage::None);
    CHECK_FALSE(est->established_at.has_value());

    failing.store(false, std::memory_order_release);
    REQUIRE(eventually([&] { return !raw->stats().inert; }, 15000ms));
    REQUIRE(eventually(
        [&] {
            auto e = engine.subscription_establishment(*sub2);
            return e.has_value() && e->coverage == SparkCoverage::Notification;
        },
        15000ms));
    est = engine.subscription_establishment(*sub2);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);
    CHECK(registry_debug_counters_for_test(*raw)->established_failed == 0);

    engine.disarm(*sub2);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): disarm() returns in bounded time while its drain runs "
          "detached (#2012 PR-B1 sre6-4)",
          "[spark][mechanism][windows][walkoff]") {
    constexpr int kKeys = 8;
    std::vector<std::unique_ptr<ScratchRegKey>> keys;
    for (int i = 0; i < kKeys; ++i)
        keys.push_back(std::make_unique<ScratchRegKey>("unwatch_bound"));
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    std::vector<SparkEngine::SubscriptionId> subs;
    for (auto& k : keys) {
        auto s = engine.arm(*c, registry_spec("HKCU", k->sub));
        REQUIRE(s.has_value());
        subs.push_back(*s);
    }
    std::this_thread::sleep_for(150ms);
    // unwatch() holds the mechanism lock across a thread CREATION (not an OS wait);
    // 50 ms is a generous ceiling for that on a loaded CI box and still an order
    // of magnitude under any callback-drain duration.
    std::chrono::microseconds worst{0};
    for (auto s : subs) {
        const auto t0 = std::chrono::steady_clock::now();
        engine.disarm(s);
        worst = std::max(worst, std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0));
    }
    INFO("worst disarm(): " << worst.count() << " us");
    CHECK(worst < 50ms);
    engine.stop();
}

TEST_CASE("Registry spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    const std::string sub =
        "Software\\Yuzu\\SparkLat_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us; // SparkEvent::at → inline handler entry
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(registry_spec("HKCU", sub), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now(); // MSVC: precise (~100ns) clock
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the TP_WAIT notify arm

    // Many spaced writes → many independent fires (re-arm-before-emit means each
    // spaced write is its own notify, not one coalesced event).
    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        const DWORD v = static_cast<DWORD>(i);
        ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[registry TP_WAIT] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    // Loose sanity only (µs-MEDIAN, not a hard cap): median dispatch under one
    // scheduler quantum. Catches a gross regression, tolerates the tail.
    CHECK(s.median_us < 10000);
}

TEST_CASE("File spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    namespace fs = std::filesystem;
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_lat_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us;
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(file_spec(target.string()), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the IOCP read arm

    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        { std::ofstream(target, std::ios::app) << "x"; }
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[file IOCP] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    CHECK(s.median_us < 10000);
}

// ── Windows Service spark: real SCM mechanism. Winmgmt (WMI) is READ-ONLY in
//    every case below (SERVICE_QUERY_STATUS only) — never stopped/started —
//    it is universally present and safe to watch on any Windows host. A live
//    STATE TRANSITION needs a service this box can safely toggle, which
//    varies by host, so that one case is env-gated (YUZU_SPARK_LIVE_SERVICE).

#include <tlhelp32.h>

#include <cstdlib> // getenv

namespace {
DWORD windows_thread_count() {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD n = 0;
    const DWORD pid = ::GetCurrentProcessId();
    if (::Thread32First(snap, &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
                te.th32OwnerProcessID == pid)
                ++n;
            te.dwSize = sizeof(te);
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
    return n;
}
} // namespace

TEST_CASE("Service spark (real mechanism): initial state resolves for a real and an absent service",
          "[spark][mechanism][windows]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto real = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(real.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);

    const std::string absent_name = "YuzuNoSuchSvc_" + std::to_string(::GetCurrentProcessId());
    auto absent = engine.arm(*c, service_spec(absent_name));
    REQUIRE(absent.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state == ServiceRunState::Stopped);

    engine.disarm(*real);
    engine.disarm(*absent);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): two spark keys folding onto one service each "
          "get their own emit",
          "[spark][mechanism][windows]") {
    // "Winmgmt" and "WINMGMT" are DISTINCT engine-level spark keys (no
    // engine-level dedup — different ServiceSparkParams::service_name
    // strings) but fold_ci coalesces them onto the SAME underlying SvcWatch
    // (SCM service names are case-insensitive). Winmgmt is read-only here,
    // never stopped/started. Governance flagged this exact scenario as
    // untested by every N-watch resource test, since those all use N
    // distinct names.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto first = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(first.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));

    auto second = engine.arm(*c, service_spec("WINMGMT"));
    REQUIRE(second.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; })); // the coalescing key gets its OWN emit

    CHECK(got.at(0).key != got.at(1).key); // distinct engine keys...
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state ==
          ServiceRunState::Running); // ...same service, same resolved state

    // M3 (rung 9c PR-6 item 1): the F4 unified branch reports establishment
    // for the SECOND (coalescing) key unconditionally, mirroring Linux's M1
    // coalescing coverage.
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*second);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));

    engine.disarm(*first);
    engine.disarm(*second);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): Winmgmt reaches Notification coverage with a "
          "stamped established_at (M3)",
          "[spark][mechanism][windows]") {
    // Winmgmt is always present and running on any Windows host, read-only
    // here (never stopped/started) — the Windows twin of Linux's M1
    // systemd-journald.service case, STRICT for the same reason (H7): a real
    // resolvable, subscribable service must reach Notification, not settle
    // for Poll.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    auto est = engine.subscription_establishment(*sub);
    REQUIRE(est.has_value());
    REQUIRE(est->established_at.has_value());
    CHECK(*est->established_at >= est->armed_at);

    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): a disarm racing a re-arm (adoption) still lets "
          "the mechanism report establishment against the fresh incarnation (M3)",
          "[spark][mechanism][windows]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub1 = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(sub1.has_value());
    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub1);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));

    std::optional<SparkEngine::SubscriptionId> sub2;
    bool raced = false;
    engine.set_disarm_race_hook_for_test([&] {
        if (raced)
            return;
        raced = true;
        auto again = engine.arm(*c, service_spec("Winmgmt"));
        REQUIRE(again.has_value());
        sub2 = *again;
    });
    engine.disarm(*sub1);
    engine.set_disarm_race_hook_for_test(nullptr);
    REQUIRE(raced);
    REQUIRE(sub2.has_value());

    REQUIRE(eventually([&] {
        auto est = engine.subscription_establishment(*sub2);
        return est.has_value() && est->coverage == SparkCoverage::Notification;
    }));
    CHECK(engine.subscription_health(*sub2) == SubscriptionHealth::Healthy);

    engine.disarm(*sub2);
    engine.stop();
}

TEST_CASE("Service mechanism (Windows, direct): set_established_sink seals at start(), same "
          "one-way contract as the fake (M3)",
          "[spark][mechanism][windows]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech);
    CHECK(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->start([](const std::string&, SparkData) {},
               [](const std::string&, bool, std::string_view) {});
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {}));
    mech->stop();
    CHECK_FALSE(mech->set_established_sink(
        [](const std::string&, SparkIncarnation, std::chrono::steady_clock::time_point,
          SparkCoverage) {})); // one-way: still sealed after stop()
}

TEST_CASE("Service spark (real mechanism): thread count settles to 1 persistent worker (plus "
          "quiesced lane workers) regardless of watch count",
          "[spark][mechanism][windows][resource]") {
    // #2012/#3840 PR-B3: "exactly one thread, always" is no longer the
    // complete oracle — establishment now launches a bounded, TRANSIENT
    // probe-lane worker per watch, which must quiesce back to zero (never
    // grow proportional to watched-service count), not literally never
    // exist. Sample the steady-state thread count only after
    // service_debug_counters_for_test() confirms probe_workers_active==0,
    // rather than immediately after the triggering emit (an emit can land a
    // moment before the worker's OWN OS thread has actually exited).
    SparkEngine engine;
    auto mech = make_service_mechanism();
    ISparkMechanism* raw = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto probe_workers_quiesced = [&] {
        auto d = service_debug_counters_for_test(*raw);
        return d.has_value() && d->probe_workers_active == 0;
    };

    auto first = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(first.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(eventually(probe_workers_quiesced));
    const DWORD threads_base = windows_thread_count();

    // A handful of always-present real services (read-only) + absent ones —
    // handle count grows (one SC_HANDLE per service is unavoidable), thread
    // count must NOT. Arm one at a time (waiting for each initial emit before
    // the next arm) rather than in a burst — avoids a race where the thread
    // count is sampled before every registration has settled.
    const char* more[] = {"EventLog", "Schedule", "LanmanWorkstation", "Dnscache"};
    std::vector<SparkEngine::SubscriptionId> subs;
    std::size_t expect = 1;
    for (const char* name : more) {
        auto s = engine.arm(*c, service_spec(name));
        REQUIRE(s.has_value());
        subs.push_back(*s);
        ++expect;
        REQUIRE(eventually([&] { return got.count() >= expect; }));
    }
    for (int i = 0; i < 15; ++i) {
        const std::string name =
            "YuzuFdProof_" + std::to_string(i) + "_" + std::to_string(::GetCurrentProcessId());
        auto s = engine.arm(*c, service_spec(name));
        REQUIRE(s.has_value());
        subs.push_back(*s);
        ++expect;
        REQUIRE(eventually([&] { return got.count() >= expect; }));
    }
    REQUIRE(eventually(probe_workers_quiesced));
    // Small tolerance absorbs unrelated transient OS threads (observed once
    // in this session — traced via per-arm instrumentation to an unrelated
    // blip, not this mechanism); a per-watch-thread regression (+19) still
    // fails this decisively.
    CHECK(windows_thread_count() <= threads_base + 2); // +19 more watches, ~0 more steady-state threads

    for (auto& s : subs)
        engine.disarm(s);
    engine.disarm(*first);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): rapid arm/unwatch churn does not UAF (R2)",
          "[spark][mechanism][windows][resilience]") {
    // Winmgmt is READ-ONLY here too — never stopped/started, only watched.
    // NotifyServiceStatusChangeW's immediate on-registration callback fires
    // moments after arming, so a tight arm-then-immediately-unwatch loop races
    // that delivery against teardown_watch's SleepEx(0,TRUE) drain — exactly
    // the R2 hazard (a queued APC running after its SvcWatch is freed) that a
    // static create/delete-without-ever-toggling case would never exercise.
    // If teardown_watch's drain were wrong this would UAF/crash under ASan
    // (or corrupt heap state observably) well before kChurn iterations —
    // and the crash-only oracle is only as strong as the sanitizer coverage
    // behind it. This test IS part of yuzu_agent_tests, which the nightly
    // windows-asan job (.github/workflows/nightly.yml) builds and runs
    // under real Windows ASan (coverage-limited: heap/stack-buffer-overflow
    // and use-after-free, not STL container-overflow — see that job's own
    // header comment). So a heap-corrupting UAF here would be caught on
    // that leg even where it wouldn't crash under a plain debug build —
    // see nightly.yml's own run history for which refs that job currently
    // runs against, since that governs how quickly a regression here is
    // actually caught, AND whether that run's own `--order rand` shuffle
    // reaches this case before an unrelated stall (#4018) kills the suite
    // first — coverage here is real but conditional on the job completing.
    // The production fix
    // (spark_service.cpp's retiring_/retire_grace mechanism) no longer
    // frees a SvcWatch synchronously on removal specifically to remove the
    // UAF this test targets, independent of this coverage.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    constexpr int kChurn = 200;
    for (int i = 0; i < kChurn; ++i) {
        auto sub = engine.arm(*c, service_spec("Winmgmt"));
        REQUIRE(sub.has_value());
        engine.disarm(*sub);
    }
    engine.stop();
    SUCCEED("completed " << kChurn << " rapid arm/unwatch cycles without a crash");
}

// Live transition + latency — env-gated: a real service transition needs a
// service THIS host can safely stop/start, which varies by box (unlike the
// Linux systemd-run recipe, Windows has no equivalent "just create a throwaway
// unit" primitive that starts into a real RUNNING state without a genuine
// service binary). Recipe: pick an already-installed, safe-to-toggle service
// (e.g. "Spooler" on a box that doesn't care about print spooling) and run:
//   net stop Spooler   REM ensure a known starting state
//   yuzu_agent_tests.exe "[spark][windows][live]" with YUZU_SPARK_LIVE_SERVICE=Spooler set,
//   and toggle it externally (net start / net stop Spooler) while the test waits.
TEST_CASE("Service spark (real mechanism): live service transition + inline dispatch latency",
          "[spark][mechanism][windows][live][latency]") {
    const char* env = std::getenv("YUZU_SPARK_LIVE_SERVICE");
    if (!env || !*env) {
        SUCCEED("YUZU_SPARK_LIVE_SERVICE unset — skipping live service integration test");
        return;
    }
    const std::string name(env);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us;
    std::vector<ServiceRunState> states;
    auto inline_sub = engine.arm_inline(service_spec(name), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        std::lock_guard lk(lat_mu);
        dispatch_us.push_back(us);
        if (std::holds_alternative<ServiceSparkData>(ev.data))
            states.push_back(std::get<ServiceSparkData>(ev.data).state);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    // Toggle externally (operator/script) while this waits for at least the
    // initial resolve + a handful of transitions.
    CHECK(eventually(
        [&] {
            std::lock_guard lk(lat_mu);
            return states.size() >= 3;
        },
        60000ms));
    engine.stop();

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    if (samples.size() >= 2) {
        const LatencyStats s = summarize_us(samples);
        WARN("[service SCM] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
             << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
             << "  (OS-notify latency NOT included — that is APC-delivery-scale, separate)");
        CHECK(s.median_us < 10000);
    }
}

// ── Service walkoff (#2012/#3840 PR-B3) ─────────────────────────────────────
// Direct-mechanism tests (no SparkEngine): mirrors spark_file.cpp's/
// spark_registry.cpp's own "(direct)" style — mech->start()/watch() called
// straight against the real Windows mechanism, with a minimal local emit/
// fault collector instead of SparkEngine's Collector, for determinism
// independent of engine-level plumbing.
namespace {

struct ServiceProbeGate {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    std::atomic<int> parked{0};
    std::atomic<int> seen{0};
    std::function<void(std::wstring_view)> hook_for(std::wstring match) {
        return [this, match](std::wstring_view name) {
            seen.fetch_add(1, std::memory_order_relaxed);
            if (name != match)
                return;
            parked.fetch_add(1, std::memory_order_acq_rel);
            std::unique_lock lk(mu);
            cv.wait(lk, [&] { return open; });
        };
    }
    void release() {
        {
            std::lock_guard lk(mu);
            open = true;
        }
        cv.notify_all();
    }
    ~ServiceProbeGate() { release(); } // never leave a worker parked past the test
};

struct ServiceEmitCollector {
    std::mutex mu;
    std::vector<std::pair<std::string, ServiceRunState>> emits;
    std::vector<std::tuple<std::string, bool, std::string>> faults; // key, faulted, reason
    /// rung 9c PR-6 item 1: key, incarnation, coverage — every established
    /// report the mechanism has made, in order. Installed via
    /// set_established_sink() BEFORE start() (an addition to this
    /// test-owned collector, not an existing helper — M4/M3's own seam).
    std::vector<std::tuple<std::string, SparkIncarnation, SparkCoverage>> established;
    SparkEmitFn emit_fn() {
        return [this](const std::string& key, SparkData data) {
            std::lock_guard lk(mu);
            if (std::holds_alternative<ServiceSparkData>(data))
                emits.emplace_back(key, std::get<ServiceSparkData>(data).state);
        };
    }
    SparkFaultFn fault_fn() {
        return [this](const std::string& key, bool faulted, std::string_view reason) {
            std::lock_guard lk(mu);
            faults.emplace_back(key, faulted, std::string(reason));
        };
    }
    SparkEstablishedFn established_fn() {
        return [this](const std::string& key, SparkIncarnation inc,
                     std::chrono::steady_clock::time_point, SparkCoverage cov) {
            std::lock_guard lk(mu);
            established.emplace_back(key, inc, cov);
        };
    }
    std::size_t emit_count() {
        std::lock_guard lk(mu);
        return emits.size();
    }
    std::size_t established_count() {
        std::lock_guard lk(mu);
        return established.size();
    }
    /// Count of Notification reports for `key` — M3's live-transition
    /// re-report observer counts THIS, not emit_count(), since an engine
    /// query holding first-wins state cannot show a re-report at all.
    std::size_t notification_count_for(const std::string& key) {
        std::lock_guard lk(mu);
        return static_cast<std::size_t>(std::count_if(
            established.begin(), established.end(), [&](const auto& e) {
                return std::get<0>(e) == key && std::get<2>(e) == SparkCoverage::Notification;
            }));
    }
};

} // namespace

// Live transition, direct-mechanism variant — env-gated (YUZU_SPARK_LIVE_SERVICE),
// mirrors the engine-level live test above but installs a test-local sink
// directly via set_established_sink() before start(), so it can observe every
// Notification RE-REPORT the fired-scan's `:1919`-shape re-arm produces —
// something an engine query (first-wins on established_at) structurally
// cannot show (M3).
TEST_CASE("Service mechanism (direct): a live service transition re-reports Notification on "
          "every fired-scan re-arm, not just the first (M3)",
          "[spark][mechanism][windows][live]") {
    const char* env = std::getenv("YUZU_SPARK_LIVE_SERVICE");
    if (!env || !*env) {
        SUCCEED("YUZU_SPARK_LIVE_SERVICE unset — skipping live service integration test");
        return;
    }
    const std::string name(env);
    const auto spec = service_spec(name);
    const std::string key = spark_key(spec);

    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    ServiceEmitCollector got;
    REQUIRE(mech->set_established_sink(got.established_fn()));
    mech->start(got.emit_fn(), got.fault_fn());

    REQUIRE(mech->watch_incarnation(key, spec.params, 1).has_value());

    // Toggle externally while this waits for at least 3 observed terminal
    // transitions (the emit channel) — mirrors the engine-level live test's
    // own wait shape.
    REQUIRE(eventually([&] { return got.emit_count() >= 3; }, 60000ms));

    // Oracle: every report's token == 1 (this mechanism instance only ever
    // watched this key once, at incarnation 1); the count of Notification
    // reports for `key` is >= the count of terminal transitions observed —
    // the fired-scan's `:1919` re-arm re-reports Notification each time,
    // which the emit channel alone (edge-dedup baseline) would never reveal.
    {
        std::lock_guard lk(got.mu);
        for (const auto& [k, inc, cov] : got.established) {
            if (k == key)
                CHECK(inc == 1);
        }
    }
    CHECK(got.notification_count_for(key) >= got.emit_count());

    mech->stop();
}

TEST_CASE("Service mechanism (direct): a parked probe's None-on-teardown report lands "
          "immediately, before the probe even resolves; release delivers a Notification "
          "report carrying the watch's token (M4a)",
          "[spark][mechanism][windows]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    ServiceProbeGate gate;
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(L"Winmgmt");
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    REQUIRE(mech->set_established_sink(got.established_fn()));
    mech->start(got.emit_fn(), got.fault_fn());

    const auto spec = service_spec("Winmgmt");
    const std::string key = spark_key(spec);
    REQUIRE(mech->watch_incarnation(key, spec.params, 1).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    // begin_probe()'s own unconditional None stage (right after
    // teardown_watch, BEFORE probe_lane_.launch()) lands synchronously on the
    // Add — it does not wait for the probe to resolve. By the time the probe
    // has provably parked, exactly the initial None report already exists.
    REQUIRE(eventually([&] { return got.established_count() >= 1; }, 2000ms));
    {
        std::lock_guard lk(got.mu);
        REQUIRE(got.established.size() >= 1);
        CHECK(std::get<0>(got.established[0]) == key);
        CHECK(std::get<1>(got.established[0]) == 1);
        CHECK(std::get<2>(got.established[0]) == SparkCoverage::None);
    }

    gate.release();
    REQUIRE(eventually([&] { return got.notification_count_for(key) >= 1; }, 3000ms));

    // Oracle (deliberately loose per the plan: "no exact count" — the
    // immediate-callback re-arm on a real, live-changing Winmgmt can add
    // further positive reports beyond the first): every report for this key
    // carries token 1 (the only incarnation this mechanism instance ever
    // watched it under) — the initial None (asserted above) included.
    {
        std::lock_guard lk(got.mu);
        for (const auto& [k, inc, cov] : got.established) {
            if (k != key)
                continue;
            CHECK(inc == 1);
            (void)cov;
        }
    }

    mech->stop();
}

TEST_CASE("Service mechanism (direct): a probe parked for a retired watch's token never "
          "resolves — a re-watch under a NEW token gets its own clean reports (M4b)",
          "[spark][mechanism][windows]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    ServiceProbeGate gate;
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(L"Winmgmt");
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    REQUIRE(mech->set_established_sink(got.established_fn()));
    mech->start(got.emit_fn(), got.fault_fn());

    const auto spec = service_spec("Winmgmt");
    const std::string key = spark_key(spec);

    // Token 1's probe parks and is left parked — this watch is about to be
    // RETIRED, never resolved.
    REQUIRE(mech->watch_incarnation(key, spec.params, 1).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    // begin_probe()'s own unconditional None stage lands for token 1 too,
    // before its probe even resolves — snapshot how many reports exist so
    // the oracle below only checks reports produced AFTER the retirement,
    // not this legitimate token-1 report.
    REQUIRE(eventually([&] { return got.established_count() >= 1; }, 2000ms));
    std::size_t baseline = 0;
    {
        std::lock_guard lk(got.mu);
        baseline = got.established.size();
    }

    mech->unwatch(key);
    // Re-watch under a NEW token while the OLD probe is STILL parked — the
    // retired SvcWatch's eventual probe result is never resolve_probe()'d
    // against the new one (a fresh SvcWatch object, a fresh begin_probe()).
    REQUIRE(mech->watch_incarnation(key, spec.params, 2).has_value());

    gate.release(); // frees BOTH the stale parked probe (discarded on
                    // retirement) and lets token 2's own probe proceed
    REQUIRE(eventually([&] { return got.notification_count_for(key) >= 1; }, 3000ms));

    // Every report for this key produced AFTER the retirement carries the
    // NEW token — the retired watch's result is silently discarded, never
    // misattributed.
    {
        std::lock_guard lk(got.mu);
        REQUIRE(got.established.size() > baseline);
        for (std::size_t i = baseline; i < got.established.size(); ++i) {
            const auto& [k, inc, cov] = got.established[i];
            if (k != key)
                continue;
            CHECK(inc == 2);
            (void)cov;
        }
    }

    mech->stop();
}

TEST_CASE("Service mechanism (direct): a parked establishment probe for one service does not "
          "stall a sibling's establishment (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][walkoff]") {
    // Before PR-B3, OpenServiceW for "Winmgmt" ran INLINE on this mechanism's
    // one thread — a parked call here would have delayed every other
    // service's establishment by however long it took to unpark. It must
    // not, now that establishment is isolated onto probe_lane_.
    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    ServiceProbeGate gate;
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(L"Winmgmt");
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    mech->start(got.emit_fn(), got.fault_fn());

    const auto spec_a = service_spec("Winmgmt");
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(got.emit_count() == 0); // A's own establishment has not resolved yet

    const std::string absent_name = "YuzuNoSuchSvc_" + std::to_string(::GetCurrentProcessId());
    const auto spec_b = service_spec(absent_name);
    REQUIRE(mech->watch(spark_key(spec_b), spec_b.params).has_value());
    REQUIRE(eventually([&] { return got.emit_count() >= 1; }, 3000ms));
    {
        std::lock_guard lk(got.mu);
        REQUIRE(got.emits.size() >= 1);
        CHECK(got.emits[0].first == spark_key(spec_b));
        CHECK(got.emits[0].second == ServiceRunState::Stopped);
    }

    gate.release();
    REQUIRE(eventually([&] { return got.emit_count() >= 2; }, 3000ms));
    mech->stop();
}

TEST_CASE("Service mechanism (direct): probe-lane admission refusal is never counted as a "
          "backend failure, and a refused probe recovers once the lane frees up "
          "(#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][walkoff]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    ServiceProbeGate gate;
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(L"Winmgmt"); // parks A's probe, occupying the (capped) lane
        ctl.probe_lane_cap = 1;
        ctl.admission_backoff_seed = 20ms;
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    mech->start(got.emit_fn(), got.fault_fn());

    const auto spec_a = service_spec("Winmgmt");
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value()); // parks, occupying the lane
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));

    const auto d0 = service_debug_counters_for_test(*mech);
    REQUIRE(d0.has_value());
    const std::string absent_name = "YuzuNoSuchSvc_" + std::to_string(::GetCurrentProcessId());
    const auto spec_b = service_spec(absent_name);
    REQUIRE(mech->watch(spark_key(spec_b), spec_b.params).has_value()); // Service never rejects
                                                                        // arm() itself — it's
                                                                        // fire-and-forget
    CHECK(eventually(
        [&] {
            auto d = service_debug_counters_for_test(*mech);
            return d && d->probe_admission_rejected > d0->probe_admission_rejected;
        },
        3000ms));
    {
        auto d = service_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->probe_backend_failed == d0->probe_backend_failed); // never counted as backend
    }
    CHECK(got.emit_count() == 0); // never established while refused, and no false Stopped either

    // Release A: the lane frees up, B's admission retry (on its own seeded
    // backoff) eventually gets in and establishes for real. Wait for B's OWN
    // Stopped emit specifically, not just "any emit" (#2012/#3840 PR-B3
    // review, found by this fix round's own DGRHP re-verification): A's real
    // Winmgmt establishment can independently satisfy an "any emit" wait
    // before B's admission-retry resolves, which this test doesn't actually
    // care about — the busy-spin fix (next_retry cleared on Launched) made
    // this pre-existing race visible by legitimately slowing a Pending
    // watch's poll cadence down from an unbounded spin to kServicePollCadence.
    gate.release();
    REQUIRE(eventually(
        [&] {
            std::lock_guard lk(got.mu);
            for (auto& [k, st] : got.emits)
                if (k == spark_key(spec_b) && st == ServiceRunState::Stopped)
                    return true;
            return false;
        },
        3000ms));
    {
        std::lock_guard lk(got.mu);
        bool saw_b_stopped = false;
        for (auto& [k, st] : got.emits)
            if (k == spark_key(spec_b))
                saw_b_stopped = (st == ServiceRunState::Stopped);
        CHECK(saw_b_stopped);
    }
    mech->stop();
}

TEST_CASE("Service mechanism (direct): a throwing establishment probe is a contained backend "
          "failure, not a lost obligation or a dead dispatch loop (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][walkoff]") {
    auto mech = make_service_mechanism();
    REQUIRE(mech != nullptr);
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = [](std::wstring_view name) {
            if (name == L"Winmgmt")
                throw std::runtime_error("injected genuine backend failure");
        };
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    REQUIRE(mech->set_established_sink(got.established_fn())); // H15, rung 9c PR-6 item 1
    mech->start(got.emit_fn(), got.fault_fn());

    const auto spec_a = service_spec("Winmgmt");
    const std::string key = spark_key(spec_a);
    REQUIRE(mech->watch_incarnation(key, spec_a.params, 7).has_value());

    // Contained: the throw is a genuine backend failure (never WorkerThrew
    // silently discarded), and dispatches a fault — proving the mechanism's
    // own dispatch loop survives it, rather than crashing or wedging.
    // Wait for the fault itself, not the backend-failure counter alone
    // (#2012/#3840 PR-B3 review, K9/C1-04): resolve_probe() increments the
    // counter BEFORE the mechanism thread reaches dispatch() at the bottom
    // of its loop, so a wait keyed on the counter can observe a window where
    // it's already incremented but the fault hasn't been delivered to `got`
    // yet — an occasional false failure on a correctly-behaving mechanism.
    CHECK(eventually(
        [&] {
            std::lock_guard lk(got.mu);
            return !got.faults.empty();
        },
        3000ms));
    {
        std::lock_guard lk(got.mu);
        REQUIRE_FALSE(got.faults.empty());
        CHECK(std::get<0>(got.faults.back()) == key);
        CHECK(std::get<1>(got.faults.back())); // faulted == true
    }
    {
        auto d = service_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->probe_backend_failed > 0);
    }
    // H15 (rung 9c PR-6 item 1): the SAME WorkerThrew outcome that faults the
    // key also stages None coverage for it — the established channel must
    // not stay silent (or stuck at a stale positive) just because the
    // backend failure classification is "never a false Stopped", which is a
    // statement about the RUN-STATE emit channel, not about coverage.
    //
    // Counted, not baselined (adversarial-review finding, post-synthesis
    // correction of an earlier baseline-snapshot draft of this test): TWO
    // distinct None reports for (key, incarnation 7) must land within this
    // window — begin_probe()'s own unconditional pre-throw stage (:1601)
    // PLUS resolve_probe()'s WorkerThrew-branch stage (:1759, the row this
    // test actually exists to pin). A baseline snapshot taken after
    // confirming only the first has two independent failure modes a count
    // does not: the probe lane's injected throw resolves near-instantly, so
    // a snapshot read a few instructions after the first None is confirmed
    // can race past the second one too and produce a false RED on correct
    // code; and the window must stay short enough that :1759's OWN 30s
    // retry cadence (kAbsentRetryMs) cannot contribute a masking THIRD
    // None via a fresh begin_probe() call if :1759 is genuinely missing —
    // 3s is comfortably inside that margin. Falsifier: removing ONLY
    // resolve_probe's `stage_coverage(w, SparkCoverage::None, established)`
    // call at spark_service.cpp:1759 must drop this count to exactly 1
    // within the same 3s window (mutation-verified on DGRHP).
    CHECK(eventually(
        [&] {
            std::lock_guard lk(got.mu);
            std::size_t none_count = 0;
            for (const auto& e : got.established) {
                if (std::get<0>(e) == key && std::get<1>(e) == 7 &&
                    std::get<2>(e) == SparkCoverage::None)
                    ++none_count;
            }
            return none_count >= 2;
        },
        3000ms));
    mech->stop();
}

TEST_CASE("Service mechanism (direct): stop() completes promptly while an establishment probe "
          "is still parked, and F3 accounting tracks the orphaned worker past the mechanism's "
          "own lifetime (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][walkoff]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    auto mech = make_service_mechanism(f3);
    REQUIRE(mech != nullptr);
    ServiceProbeGate gate;
    {
        ServiceMechanismTestControls ctl;
        ctl.probe_hook = gate.hook_for(L"Winmgmt");
        REQUIRE(set_service_test_controls_for_test(*mech, std::move(ctl)));
    }
    ServiceEmitCollector got;
    mech->start(got.emit_fn(), got.fault_fn());
    const auto spec_a = service_spec("Winmgmt");
    REQUIRE(mech->watch(spark_key(spec_a), spec_a.params).has_value());
    REQUIRE(eventually([&] { return gate.parked.load() == 1; }, 2000ms));
    CHECK(f3->load(std::memory_order_acquire) == 1); // the parked probe is admitted+counted

    const auto t0 = std::chrono::steady_clock::now();
    mech->stop(); // must not wait for the parked probe — it's still blocked on the gate
    const auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    INFO("stop() returned after " << stop_ms << " ms with a probe still parked on the gate");
    CHECK(stop_ms < 2000);

    // The orphaned worker is still parked on the gate, outliving `mech` — the
    // F3 counter (agent-lifetime-scoped, independent of `mech`'s own
    // lifetime by design — spark_detached_call.hpp's own "F3 / §24") must
    // still show it.
    CHECK(f3->load(std::memory_order_acquire) == 1);
    mech.reset(); // the mechanism itself is gone; the counter is NOT (owned by the test, not `mech`)
    gate.release(); // unpark the orphaned worker so it can finish and decrement f3
    CHECK(eventually([&] { return f3->load(std::memory_order_acquire) == 0; }, 3000ms));
}

// ── Service T6-analogue (#2012/#3840 PR-B3, mirrors File's own T6-analogue) ─
//
// Unlike Registry, Service's unwatch() does NOT block the calling thread on a
// SEPARATE callback-owning thread finishing its work first (this file's
// header comment: watch()/unwatch() are O(1) queue pushes; teardown_watch()'s
// SleepEx(0,TRUE) is a zero-timeout APC pump, not a blocking barrier — see
// the "Design decision: probe-only lane" note at the top of this file). So
// the SPECIFIC deadlock T6 (#4181) found in Registry has no known analogue in
// Service's design, matching File's own precedent finding for the identical
// reason. This test is regression insurance, not a suspected-red repro: if a
// future change to Service's unwatch()/stop() ever introduced a blocking
// cross-thread drain, this is the test that would catch it. Built at the
// SUBPROCESS boundary (never in-process, mirroring spark_registry.cpp's and
// spark_file.cpp's own T6/T6-analogue) precisely because a wrong assumption
// here would otherwise hang the whole test binary with no recovery.
namespace {
constexpr DWORD kT6ServiceDeadlockExitCode = 102; // distinct from Registry's 100, File's 101

std::string t6_service_log_tag() {
    char buf[1024]{};
    const DWORD n = ::GetEnvironmentVariableA("YUZU_SPARK_T6_SERVICE_TAG", buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf))
        return std::string(buf, n);
    return "spark_t6_service_" + std::to_string(::GetCurrentProcessId());
}
} // namespace

#define YUZU_SPARK_T6_SERVICE_CHILD_CASE_NAME "Service T6 child: inline same-type re-arm during disarm"

TEST_CASE(YUZU_SPARK_T6_SERVICE_CHILD_CASE_NAME, "[.][t6-service-child]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    std::atomic<bool> in_handler{false};
    std::atomic<bool> go{false};
    std::atomic<bool> rearmed{false};
    std::atomic<bool> rearm_done{false};
    std::atomic<int> fires{0};
    std::mutex rearm_err_mu;
    std::string rearm_err;
    // Winmgmt's own initial-resolve fire is the ONE delivery this test needs
    // (never toggled — read-only, exactly like every other Service test in
    // this file); a real state TRANSITION is not required to exercise the
    // re-entrancy shape below.
    auto sub_k = engine.arm_inline(service_spec("Winmgmt"), [&](const SparkEvent&) {
        if (fires.fetch_add(1, std::memory_order_acq_rel) != 0)
            return;
        in_handler.store(true, std::memory_order_release);
        while (!go.load(std::memory_order_acquire))
            std::this_thread::sleep_for(1ms);
        auto s2 = engine.arm_inline(service_spec("EventLog"), [](const SparkEvent&) {});
        if (!s2) {
            std::lock_guard lk(rearm_err_mu);
            rearm_err = s2.error();
        }
        rearmed.store(s2.has_value(), std::memory_order_release);
        rearm_done.store(true, std::memory_order_release);
    });
    REQUIRE(sub_k.has_value());
    engine.start();
    REQUIRE(eventually([&] { return in_handler.load(std::memory_order_acquire); }, 8000ms));

    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*sub_k);
        disarm_done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(300ms);
    go.store(true, std::memory_order_release);

    const bool completed =
        eventually([&] { return disarm_done.load(std::memory_order_acquire); }, 5000ms);
    if (!completed) {
        std::fputs("T6-service child: disarm() did not complete while the Inline callback "
                  "re-entered the same type - deadlock observed\n",
                  stderr);
        std::fflush(stderr);
        ::TerminateProcess(::GetCurrentProcess(), kT6ServiceDeadlockExitCode);
    }
    CHECK(completed);
    disarmer.join();
    CHECK(eventually([&] { return rearm_done.load(std::memory_order_acquire); }, 5000ms));
    {
        std::lock_guard lk(rearm_err_mu);
        INFO("same-type arm_inline from inside the Inline handler: "
             << (rearm_done.load(std::memory_order_acquire)
                     ? (rearm_err.empty() ? "returned ok" : rearm_err)
                     : "did not return within 5s"));
        CHECK(rearmed.load(std::memory_order_acquire));
    }
    engine.stop();
}

TEST_CASE("Service spark: same-type disarm() does not deadlock against an in-flight Inline "
          "callback (T6-service analogue, subprocess boundary) (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][walkoff][t6]") {
    wchar_t exe[MAX_PATH]{};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    REQUIRE((exe_len > 0 && exe_len < MAX_PATH));

    std::wstring cmd = L"\"";
    cmd += exe;
    cmd += L"\" \"";
    {
        const std::string name = YUZU_SPARK_T6_SERVICE_CHILD_CASE_NAME;
        cmd.append(name.begin(), name.end());
    }
    cmd += L"\" --reporter compact --durations no";

    const std::filesystem::path child_log =
        std::filesystem::temp_directory_path() /
        ("yuzu_test_spark_t6_service_child_" + std::to_string(::GetCurrentProcessId()) + ".log");
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    UniqueHandle hlog(::CreateFileW(child_log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    REQUIRE(hlog.valid());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = hlog.h;
    si.hStdError = hlog.h;
    PROCESS_INFORMATION pi{};
    const BOOL created = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    UniqueHandle hthread(pi.hThread);
    UniqueHandle hprocess(pi.hProcess);
    hlog.reset();
    REQUIRE(created);
    hthread.reset();
    const DWORD wr = ::WaitForSingleObject(hprocess.h, 30000);
    if (wr == WAIT_TIMEOUT) {
        ::TerminateProcess(hprocess.h, 9);
        ::WaitForSingleObject(hprocess.h, 5000);
    }
    DWORD code = 0xFFFFFFFFu;
    ::GetExitCodeProcess(hprocess.h, &code);
    hprocess.reset();
    std::error_code ec;
    std::string child_out;
    {
        std::ifstream in(child_log, std::ios::binary);
        child_out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::filesystem::remove(child_log, ec);

    INFO("T6-service child: WaitForSingleObject=" << wr
                                                  << " (0=exited, 258=timeout->killed) exit code="
                                                  << code << " (0=completed, "
                                                  << kT6ServiceDeadlockExitCode
                                                  << "=child saw the deadlock, 3=Catch2 matched no case)");
    INFO("T6-service child output:\n" << child_out);
    CHECK(wr == WAIT_OBJECT_0);
    CHECK(code == 0);
}

// ── Watch-establishment LATENCY CHARACTERIZATION harness (PR-A; #2012/#3840) ─
//
// Measures the RAW Win32 call sequences DIRECTLY - CreateEventW /
// CreateThreadpoolWait / RegOpenKeyExW / RegNotifyChangeKeyValue /
// SetThreadpoolWait for Registry; OpenSCManagerW / OpenServiceW /
// NotifyServiceStatusChangeW for Service; is_directory / CreateFileW for
// File - NOT through the mechanism classes (spark_file.cpp /
// spark_registry.cpp / spark_service.cpp), which do not yet have the
// off-lock restructuring this measurement feeds (that is PR-B). Deliberate:
// D must be chosen from TODAY's raw call cost, before a mechanism hides it
// behind a bounded worker - measuring through the mechanism is only possible
// once PR-B lands, by which point D would already be baked in.
//
// REPORT ONLY - never assert on these numbers on the shared Wee Tam CI pool.
// Treat a 200-sample p99 here as DEADLINE-CALIBRATION input, not evidence
// about cold boot / a dead network share / true worst-case latency (Astra,
// plan round 3, "#2012 + #3840" plan doc). Any downstream doc/PR body citing
// these numbers must say so explicitly.
//
// Env-gated (YUZU_SPARK_ESTABLISH_BENCH=1), same shape as the
// YUZU_SPARK_LIVE_SERVICE case above - every other [windows] case in this
// file runs by default on the shared Wee Tam CI box, and this is a
// measurement run, not a gate; it must never fire there un-asked.
//
// NOT RUN IN THIS SESSION. No Windows toolchain/host was available when this
// harness was authored (PR-A, docs/spark-rebuild-baselines/stage2-watch-
// establish-latency.md records the pending-DGRHP-run status) - every Win32
// call shape below is modeled directly on the existing, already-shipped
// usage in spark_registry.cpp / spark_service.cpp / spark_file.cpp (cited
// per case), not invented, but this file has NOT been compiled or executed
// on a real Windows host as part of this change.

namespace {

bool spark_establish_bench_enabled() {
    const char* env = std::getenv("YUZU_SPARK_ESTABLISH_BENCH");
    return env && *env && std::string_view(env) != "0";
}

constexpr int kEstablishSamples = 200;

/// Times `body()` and appends the elapsed microseconds to `out`.
template <class Fn> void time_call(std::vector<std::int64_t>& out, Fn&& body) {
    const auto t0 = std::chrono::steady_clock::now();
    body();
    const auto t1 = std::chrono::steady_clock::now();
    out.push_back(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
}

void warn_establish(const char* case_label, const char* call_label, std::vector<std::int64_t> v) {
    const LatencyStats s = summarize_us(std::move(v));
    WARN("ESTABLISH " << case_label << " " << call_label << " n=" << s.n << " min=" << s.min_us
         << " p50=" << s.median_us << " p90=" << s.p90_us << " p99=" << s.p99_us
         << " max=" << s.max_us << " us");
}

/// ASCII-only widen - every path/name this harness constructs is a
/// PID/salt-suffixed ASCII literal, so a naive char->wchar_t widen is exact
/// (no MultiByteToWideChar needed).
std::wstring establish_widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

/// Checked, recursive teardown for a harness scratch subtree that may still
/// have children (adversarial-review finding, PR-A round 2): RegDeleteKeyA
/// silently fails - return value was previously discarded at every call
/// site - on a key with subkeys, so R3/R4's `base\churn` and the post-fix
/// bulk case's `base\k0..k199` were never actually deleted, leaking inert
/// keys under HKCU on a by-hand measurement host across repeated runs.
/// Callers whose `base` has already-scoped child owners (e.g. R3/R4's
/// EstablishHiveLoad) must let those go out of scope FIRST, so nothing
/// still holds an open handle into the subtree being deleted.
void establish_cleanup_tree(const std::string& base) {
    const LSTATUS rc = ::RegDeleteTreeA(HKEY_CURRENT_USER, base.c_str());
    if (rc != ERROR_SUCCESS)
        WARN("establish_cleanup_tree: RegDeleteTreeA(" << base << ") failed, rc=" << rc
             << " - a scratch key under HKCU\\" << base << " may be leaked");
}

/// RAII wrapper for establish_cleanup_tree(): calls it unconditionally at
/// scope exit, including on a REQUIRE throw mid-loop (Gate 4 unhappy-path
/// finding, PR-A round 5) - R1/R2's own trailing cleanup call was reached
/// only if none of that case's kEstablishSamples-iteration loop's REQUIREs
/// ever threw, leaking base\... on the first failure.
struct EstablishTreeGuard {
    std::string base;
    ~EstablishTreeGuard() { establish_cleanup_tree(base); }
};

void CALLBACK establish_null_wait_cb(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT) {}

/// R5 in-flight-drain callback: sleeps 50ms to simulate a callback parked
/// inside a slow inline consumer, so WaitForThreadpoolWaitCallbacks(TRUE) has
/// something real to drain. A named CALLBACK function, not a captureless
/// lambda passed where a raw PTP_WAIT_CALLBACK is expected - matches the
/// named-function convention spark_registry.cpp's own OnWait uses, rather
/// than relying on a lambda-to-function-pointer conversion across the
/// CALLBACK/__stdcall decoration.
/// `ctx` is a started-handshake `std::atomic<bool>*` (adversarial-review
/// finding, PR-A round 2): set TRUE the instant this callback actually
/// begins running, BEFORE the 50ms sleep, so the caller can wait for real
/// execution to have started before timing the drain - without this,
/// WaitForThreadpoolWaitCallbacks(TRUE) can legitimately CANCEL a callback
/// that hasn't started yet (Microsoft's own documented behavior), and the
/// resulting near-zero elapsed time would be measuring cancellation, not
/// the 50ms in-flight drain this case is named for.
void CALLBACK establish_r5_inflight_cb(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WAIT,
                                       TP_WAIT_RESULT) {
    if (ctx)
        static_cast<std::atomic<bool>*>(ctx)->store(true, std::memory_order_release);
    std::this_thread::sleep_for(50ms);
}

/// R6 fired-flag callback: `ctx` is the `std::atomic<bool>*` the control
/// polls. Named for the same reason as establish_r5_inflight_cb above.
void CALLBACK establish_r6_fired_cb(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WAIT, TP_WAIT_RESULT) {
    static_cast<std::atomic<bool>*>(ctx)->store(true, std::memory_order_relaxed);
}

/// S2's SERVICE_NOTIFYW::pfnNotifyCallback - PFN_SC_NOTIFY_CALLBACK takes a
/// single PVOID (spark_service.cpp's own notify_cb, spark_service.cpp:968,
/// matches this exact signature), NOT a SERVICE_NOTIFYW* - establishment
/// only, this harness never reads the delivered status.
void CALLBACK establish_s2_notify_cb(PVOID) {}

/// One CreateEventW + CreateThreadpoolWait + RegOpenKeyExW +
/// RegNotifyChangeKeyValue + SetThreadpoolWait sample, timed per call and
/// appended to the five out-vectors (same order as the plan's R1/R2 call
/// list). `open` performs the RegOpenKeyExW step itself (R1: a single open of
/// the target; R2: an ancestor walk - see establish_open_ancestor_walk below)
/// so both cases can share this shell. `env` is null for the default process
/// pool (R1/R2) or a private pool's environment (R3/R4, under hive load).
/// PTP_CALLBACK_ENVIRON is ITSELF a pointer typedef (Win32 "P" convention -
/// matches spark_registry.cpp:360's bare `TP_CALLBACK_ENVIRON env_{}` +
/// `&env_` usage) - a `PTP_CALLBACK_ENVIRON*` parameter here would be
/// TP_CALLBACK_ENVIRON** (a hard MSVC compile error at the call sites below
/// that pass `&load.pool.env`; R1/R2's bare `nullptr` argument masked this
/// during hand-review, since nullptr converts to any pointer type - governance
/// finding, PR-A round 2).
template <class OpenFn>
void establish_registry_sample(PTP_CALLBACK_ENVIRON env, DWORD notify_filter, OpenFn&& open,
                               std::vector<std::int64_t>& t_event,
                               std::vector<std::int64_t>& t_wait_create,
                               std::vector<std::int64_t>& t_open,
                               std::vector<std::int64_t>& t_notify,
                               std::vector<std::int64_t>& t_wait_set) {
    // RAII, not three unconditional closes after the last REQUIRE (Gate 4
    // unhappy-path finding, PR-A round 5): a REQUIRE throwing between two
    // resource acquisitions used to leak whichever of ev/wait/h had already
    // succeeded - the same defect class EstablishChurnWatch was fixed for
    // in round 2, never generalized to this function. Teardown order
    // (cancel-new, drain in-flight, then close) is unchanged; it now runs
    // at scope exit unconditionally instead of only on the success path.
    struct SampleGuard {
        HANDLE ev{nullptr};
        PTP_WAIT wait{nullptr};
        HKEY h{nullptr};
        ~SampleGuard() {
            if (wait) {
                ::SetThreadpoolWait(wait, nullptr, nullptr);
                ::WaitForThreadpoolWaitCallbacks(wait, TRUE);
                ::CloseThreadpoolWait(wait);
            }
            if (h)
                ::RegCloseKey(h);
            if (ev)
                ::CloseHandle(ev);
        }
    } guard;

    time_call(t_event, [&] { guard.ev = ::CreateEventW(nullptr, FALSE, FALSE, nullptr); });
    REQUIRE(guard.ev != nullptr);

    time_call(t_wait_create,
              [&] { guard.wait = ::CreateThreadpoolWait(&establish_null_wait_cb, nullptr, env); });
    REQUIRE(guard.wait != nullptr);

    guard.h = open(t_open);
    REQUIRE(guard.h != nullptr);

    LONG rc = 0;
    time_call(t_notify,
              [&] { rc = ::RegNotifyChangeKeyValue(guard.h, FALSE, notify_filter, guard.ev, TRUE); });
    CHECK(rc == ERROR_SUCCESS);

    time_call(t_wait_set, [&] { ::SetThreadpoolWait(guard.wait, guard.ev, nullptr); });
}

/// A private TP wait-group (min=2/max=4) matching spark_registry.cpp's own
/// pool sizing (spark_registry.cpp:173-176) - used ONLY by the "under hive
/// load" cases (R3/R4) so the measured contention is realistic private-pool
/// saturation, not the effectively-unbounded default process pool.
struct EstablishPrivatePool {
    PTP_POOL pool{nullptr};
    TP_CALLBACK_ENVIRON env{};

    EstablishPrivatePool() {
        pool = ::CreateThreadpool(nullptr);
        REQUIRE(pool != nullptr);
        ::SetThreadpoolThreadMinimum(pool, 2);
        ::SetThreadpoolThreadMaximum(pool, 4);
        ::InitializeThreadpoolEnvironment(&env);
        ::SetThreadpoolCallbackPool(&env, pool);
    }
    ~EstablishPrivatePool() {
        ::DestroyThreadpoolEnvironment(&env);
        if (pool)
            ::CloseThreadpool(pool);
    }
    EstablishPrivatePool(const EstablishPrivatePool&) = delete;
    EstablishPrivatePool& operator=(const EstablishPrivatePool&) = delete;
};

/// One self-re-arming registry watch used purely as CHURN LOAD for R3/R4 -
/// arm-before-process (mirrors spark_registry.cpp's reconcile() ordering) so
/// it keeps firing/re-arming for the whole measurement window without
/// growing unbounded. All churn watches point at the SAME shared key; a
/// background writer thread keeps them firing.
// Owns its own PTP_WAIT/HANDLE (governance finding, PR-A round 2): the
// original version had no destructor, so a REQUIRE throwing partway through
// EstablishHiveLoad's 200-iteration setup loop below left every EARLIER
// iteration's already-created HANDLE+PTP_WAIT genuinely leaked - watches
// is a fully-constructed member by the time that loop runs, so its OWN
// destruction (with EstablishChurnWatch itself trivially-destructible) ran
// on the exception path but did nothing. Never moved/copied in practice
// (EstablishHiveLoad's ctor fills a pre-`resize()`d vector via reference,
// no reallocation after that point), so this destructor is the only
// teardown path this type needs.
struct EstablishChurnWatch {
    HKEY hkey{nullptr};
    HANDLE event{nullptr};
    PTP_WAIT wait{nullptr};
    const std::atomic<bool>* stop{nullptr};
    // Guards on_fire's check-then-rearm against ~EstablishHiveLoad's
    // stop-latch, below - see on_fire's comment for why a bare atomic
    // wasn't enough. Owned by EstablishHiveLoad, outlives every watch
    // (declared ahead of `watches` there so member-destruction order keeps
    // it alive through every EstablishChurnWatch destructor).
    std::mutex* mu{nullptr};

    EstablishChurnWatch() = default;
    EstablishChurnWatch(const EstablishChurnWatch&) = delete;
    EstablishChurnWatch& operator=(const EstablishChurnWatch&) = delete;
    // Move-CONSTRUCTIBLE, NOT deleted (unlike a first draft of this fix):
    // std::vector<>::resize()'s contract requires MoveInsertable regardless
    // of whether a given call actually reallocates, so a non-movable
    // element type risks failing to compile at the resize() call site
    // below. Transfers ownership and nulls the source (same shape as
    // SlowDtor's move ctor elsewhere in this repo's tests), so the
    // moved-from object's destructor becomes a safe no-op - no double-close
    // risk. In practice this is never exercised: EstablishHiveLoad's ctor
    // resize()s ONCE from empty, before any address is captured by
    // CreateThreadpoolWait, so no element is ever moved after its address
    // is registered with the OS.
    EstablishChurnWatch(EstablishChurnWatch&& o) noexcept
        : hkey(o.hkey), event(o.event), wait(o.wait), stop(o.stop), mu(o.mu) {
        o.event = nullptr;
        o.wait = nullptr;
    }
    // Move-assignment is deliberately DELETED, not defaulted/hand-rolled
    // (Gate 4 re-review finding): resize()'s MoveInsertable requirement
    // needs only the move constructor above - it never move-ASSIGNS an
    // existing element. A hand-rolled assignment operator here would repeat
    // the exact "overwrite without disposing the target's prior owned
    // state" defect this same round fixed for DetachedCall::operator=,
    // except with no call site to ever exercise or test it.
    EstablishChurnWatch& operator=(EstablishChurnWatch&&) = delete;

    ~EstablishChurnWatch() {
        if (wait) {
            ::SetThreadpoolWait(wait, nullptr, nullptr);
            ::WaitForThreadpoolWaitCallbacks(wait, TRUE);
            ::CloseThreadpoolWait(wait);
        }
        if (event)
            ::CloseHandle(event);
    }

    // FIXED (consistency-auditor Gate 4 finding, DGRHP re-verification pass,
    // 2026-09-09): this check-then-rearm was NOT synchronized against
    // ~EstablishHiveLoad()'s teardown - `stop` was a bare atomic with no
    // mutex, so a pool thread already past the check below could still be
    // calling SetThreadpoolWait on `wait` at the exact moment the
    // destructor's own SetThreadpoolWait(nullptr,nullptr) disarm call ran
    // on it. Microsoft's own reference page for SetThreadpoolWait documents
    // no concurrent-call guarantee for two threads calling it on the same
    // PTP_WAIT (checked directly, Gate 8 re-review, 2026-09-09 - an earlier
    // version of this comment claimed MSDN states this explicitly; it does
    // not, only a different, narrower undefined-behavior case around
    // closing the referenced handle while a wait is pending) - mutating the
    // OS object's internal state from two threads with no synchronization
    // is exactly the class of thing this codebase's own production code
    // already treats as unsafe (spark_registry.cpp's mu_-guarded shape,
    // below), not a documented-and-cited guarantee. This is now fixed the same way production
    // avoids it: `mu` below (owned by EstablishHiveLoad) is held around
    // BOTH this whole check-then-rearm AND ~EstablishHiveLoad()'s
    // stop.store() (both call sites, ctor-catch and dtor) - mirroring
    // spark_registry.cpp's `mu_`-guarded `active` flag (confirmed by
    // reading unwatch()/on_fire() there: `active` is set false under
    // `mu_`, `mu_` released, THEN the unlocked SetThreadpoolWait(nullptr)
    // runs - safe because on_fire's own SetThreadpoolWait re-arm call only
    // ever happens INSIDE its own `mu_`-held section, so by the time
    // unwatch's locked section completes, no in-flight on_fire can still
    // be mid-rearm, and no future one will attempt it once the flag is
    // visible). The lock is released before any blocking call in both
    // places (the Win32 WaitForThreadpoolWaitCallbacks in the per-watch
    // destructor; the std::thread writer.join() in ~EstablishHiveLoad) -
    // on_fire could
    // otherwise deadlock trying to acquire `mu` while the destructor holds
    // it across a wait for on_fire itself to finish.
    //
    // Unrelated to the T6/#4181 production deadlock shape (unwatch()
    // holding SparkEngine's per-type lock, mech_ops_mu_by_type_, while
    // blocked draining a callback that reaches an Inline-tier consumer
    // re-entering the same lock) - filed as issue #4181 (2026-09-09) with
    // the code-verified thread cycle: SparkEngine::disarm
    // (spark_engine.cpp:1256) blocks in WindowsRegistryMechanism::unwatch's
    // WaitForThreadpoolWaitCallbacks (spark_registry.cpp:304) waiting on an
    // in-flight on_fire; that on_fire's emit() (spark_registry.cpp:351)
    // reaches deliver()'s Inline-tier dispatch (spark_engine.cpp:1779 - the
    // sub.inline_fn(out) call itself, inside the try block opened at :1778;
    // four reviewers cited :1778 without re-deriving it against source, one
    // caught the off-by-one, re-verified here directly)
    // synchronously, which, if it re-enters the engine for the same type,
    // needs the same mech_ops_mu_by_type_ entry the disarm thread already
    // holds. This harness has no per-type lock at all - `mu` above guards
    // only the local check-then-rearm race just fixed, a different
    // mechanism from #4181's cross-lock cycle.
    static void CALLBACK on_fire(PTP_CALLBACK_INSTANCE, void* ctx, PTP_WAIT, TP_WAIT_RESULT) {
        auto* self = static_cast<EstablishChurnWatch*>(ctx);
        std::lock_guard lk(*self->mu);
        if (self->stop->load(std::memory_order_relaxed))
            return;
        ::RegNotifyChangeKeyValue(self->hkey, FALSE,
                                  REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                                  self->event, TRUE);
        ::SetThreadpoolWait(self->wait, self->event, nullptr);
    }
};

} // namespace

TEST_CASE("Watch establishment (Registry): target-present raw call sequence (R1)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::string base =
        "SOFTWARE\\YuzuTest\\SparkEst_" + std::to_string(yuzu::test::process_random_salt());
    HKEY base_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &base_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(base_h);
    EstablishTreeGuard tree_guard{base}; // Gate 4 unhappy-path finding, PR-A round 5:
                                         // the old trailing RegDeleteKeyA was reached
                                         // only if none of the loop's REQUIREs threw
    const std::wstring base_w = establish_widen(base);

    std::vector<std::int64_t> t_event, t_wait_create, t_open, t_notify, t_wait_set;
    for (int i = 0; i < kEstablishSamples; ++i) {
        establish_registry_sample(
            /*env=*/nullptr,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            [&](std::vector<std::int64_t>& t_open_inner) {
                HKEY h = nullptr;
                time_call(t_open_inner, [&] {
                    ::RegOpenKeyExW(HKEY_CURRENT_USER, base_w.c_str(), 0, KEY_NOTIFY | KEY_READ, &h);
                });
                return h;
            },
            t_event, t_wait_create, t_open, t_notify, t_wait_set);
    }
    warn_establish("R1 registry target-present", "CreateEventW", t_event);
    warn_establish("R1 registry target-present", "CreateThreadpoolWait", t_wait_create);
    warn_establish("R1 registry target-present", "RegOpenKeyExW", t_open);
    warn_establish("R1 registry target-present", "RegNotifyChangeKeyValue", t_notify);
    warn_establish("R1 registry target-present", "SetThreadpoolWait", t_wait_set);
}

TEST_CASE("Watch establishment (Registry): target-absent, ancestor walk depth 6 (R2)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::string base =
        "SOFTWARE\\YuzuTest\\SparkEst_" + std::to_string(yuzu::test::process_random_salt()) +
        "_anc";
    HKEY base_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &base_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(base_h);
    EstablishTreeGuard tree_guard{base}; // Gate 4 unhappy-path finding, PR-A round 5:
                                         // the old trailing RegDeleteKeyA was reached
                                         // only if none of the loop's REQUIREs threw
    // 6 absent levels under `base`, which exists - matches the plan's
    // "ancestor walk depth 6". None of a\b\c\d\e\f is ever created.
    const std::string target = base + "\\a\\b\\c\\d\\e\\f";

    std::vector<std::int64_t> t_event, t_wait_create, t_open_per_level, t_notify, t_wait_set;
    std::vector<std::int64_t> t_walk_total;
    for (int i = 0; i < kEstablishSamples; ++i) {
        const auto walk_t0 = std::chrono::steady_clock::now();
        establish_registry_sample(
            /*env=*/nullptr, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
            [&](std::vector<std::int64_t>& t_open_inner) -> HKEY {
                // Walk up from `target`, stripping one path component at a
                // time, until RegOpenKeyExW succeeds - the same shape as
                // spark_registry.cpp's private open_nearest_ancestor(), not
                // reused directly (it is a private member of
                // WindowsRegistryMechanism, not exported) but replicated
                // faithfully: this harness measures the RAW call cost the
                // real function pays, not the function itself.
                std::string path = target;
                for (;;) {
                    const std::wstring path_w = establish_widen(path);
                    HKEY h = nullptr;
                    LONG rc = 0;
                    time_call(t_open_inner, [&] {
                        rc = ::RegOpenKeyExW(HKEY_CURRENT_USER, path_w.c_str(), 0,
                                             KEY_NOTIFY | KEY_READ, &h);
                    });
                    if (rc == ERROR_SUCCESS)
                        return h;
                    const auto pos = path.find_last_of('\\');
                    if (pos == std::string::npos)
                        return nullptr; // exhausted - should not happen, base_h exists
                    path = path.substr(0, pos);
                }
            },
            t_event, t_wait_create, t_open_per_level, t_notify, t_wait_set);
        const auto walk_t1 = std::chrono::steady_clock::now();
        t_walk_total.push_back(
            std::chrono::duration_cast<std::chrono::microseconds>(walk_t1 - walk_t0).count());
    }
    warn_establish("R2 registry target-absent depth6", "CreateEventW", t_event);
    warn_establish("R2 registry target-absent depth6", "CreateThreadpoolWait", t_wait_create);
    warn_establish("R2 registry target-absent depth6", "RegOpenKeyExW (per level)",
                   t_open_per_level);
    warn_establish("R2 registry target-absent depth6", "RegNotifyChangeKeyValue", t_notify);
    warn_establish("R2 registry target-absent depth6", "SetThreadpoolWait", t_wait_set);
    // Labeled honestly (adversarial-review finding, PR-A round 2): walk_t0..
    // walk_t1 brackets the WHOLE establish_registry_sample() call, whose
    // body's own last step is an unmeasured-separately teardown (cancel +
    // WaitForThreadpoolWaitCallbacks drain + closes) - this series is NOT
    // establishment-only, it includes that teardown/drain too. The bias is
    // conservative (can only inflate a derived deadline, never undersize
    // one), so this is a labeling fix, not a measurement fix.
    warn_establish("R2 registry target-absent depth6",
                   "TOTAL (event+waitcreate+walk+notify+set, INCL. TEARDOWN/DRAIN)",
                   t_walk_total);
}

namespace {
/// Shared setup for R3/R4: a private wait-group + N self-re-arming churn
/// watches on one shared key, kept firing by a background writer thread for
/// the caller's measurement window. RAII: stops the writer, disarms every
/// churn watch, and tears down the pool on destruction.
struct EstablishHiveLoad {
    EstablishPrivatePool pool;
    HKEY churn_key{nullptr};
    std::atomic<bool> stop{false};
    // Declared ahead of `watches`: members destruct in REVERSE declaration
    // order, so this stays alive through every EstablishChurnWatch
    // destructor below - see on_fire's comment for what it guards.
    std::mutex mu;
    std::vector<EstablishChurnWatch> watches;
    std::thread writer;

    explicit EstablishHiveLoad(const std::string& base) {
        const std::string churn_key_path = base + "\\churn";
        REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, churn_key_path.c_str(), 0, nullptr, 0,
                                  KEY_ALL_ACCESS, nullptr, &churn_key, nullptr) == ERROR_SUCCESS);
        // Everything from here on can REQUIRE-throw before the constructor
        // completes, and a not-fully-constructed object's destructor never
        // runs (Gate 4 unhappy-path finding, PR-A round 5) - churn_key is
        // this object's own resource, acquired above, so only THIS catch
        // block can close it on that path; `watches`' own elements still
        // unwind correctly via their own destructors regardless (subobject
        // cleanup runs even when the enclosing object's ctor doesn't
        // finish), so they need no equivalent handling here.
        try {
            constexpr int kChurnWatches = 200; // plan: "200 pre-armed watches on the private pool"
            watches.resize(kChurnWatches);
            for (auto& w : watches) {
                w.hkey = churn_key;
                w.stop = &stop;
                w.mu = &mu;
                w.event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
                REQUIRE(w.event != nullptr);
                w.wait = ::CreateThreadpoolWait(&EstablishChurnWatch::on_fire, &w, &pool.env);
                REQUIRE(w.wait != nullptr);
                REQUIRE(::RegNotifyChangeKeyValue(
                            churn_key, FALSE,
                            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, w.event,
                            TRUE) == ERROR_SUCCESS);
                ::SetThreadpoolWait(w.wait, w.event, nullptr);
            }
            writer = std::thread([this] {
                DWORD v = 0;
                while (!stop.load(std::memory_order_relaxed)) {
                    ::RegSetValueExA(churn_key, "v", 0, REG_DWORD,
                                     reinterpret_cast<const BYTE*>(&v), sizeof(v));
                    ++v;
                    std::this_thread::sleep_for(2ms);
                }
            });
        } catch (...) {
            // Quiesce every already-armed watch BEFORE touching the key
            // they're rooted in (Gate 8 pass-5 finding, cpp-safety: a first
            // fix here only reordered stop=true ahead of RegCloseKey, which
            // is weaker than the destructor's actual protection below).
            // Closing a registry key with armed RegNotifyChangeKeyValue
            // registrations SIGNALS every one of them, so up to 200
            // already-armed on_fire callbacks could otherwise fire
            // concurrently with the close. watches.clear() runs every
            // already-constructed EstablishChurnWatch's own destructor
            // (cancel + WaitForThreadpoolWaitCallbacks drain + close) FIRST
            // - the exact mechanism (not flag-ordering) that makes the
            // normal, non-throwing destructor below actually safe: no
            // watch can still be armed by the time churn_key closes there,
            // and now none can be here either. The stop.store() below is
            // now ALSO mutex-guarded (on_fire's comment, DGRHP
            // re-verification pass, closes the check-then-rearm race
            // formerly disclosed here as unfixed) - a partially-armed
            // watch's on_fire hitting this exception path gets the same
            // protection as the normal destructor below.
            {
                std::lock_guard lk(mu);
                stop.store(true, std::memory_order_relaxed);
            }
            watches.clear();
            ::RegCloseKey(churn_key);
            throw;
        }
    }
    ~EstablishHiveLoad() {
        {
            std::lock_guard lk(mu);
            stop.store(true, std::memory_order_relaxed);
        }
        if (writer.joinable())
            writer.join();
        // Per-watch teardown (disarm, drain, close) now lives in
        // EstablishChurnWatch's OWN destructor (governance finding, PR-A
        // round 2) - `watches`' own destruction below runs it for every
        // element; do NOT duplicate that loop here, a second cleanup pass
        // over the same wait/event handles would double-close them.
        watches.clear();
        if (churn_key)
            ::RegCloseKey(churn_key);
    }
    EstablishHiveLoad(const EstablishHiveLoad&) = delete;
    EstablishHiveLoad& operator=(const EstablishHiveLoad&) = delete;
};
} // namespace

TEST_CASE("Watch establishment (Registry): target-present under hive load (R3)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::string base =
        "SOFTWARE\\YuzuTest\\SparkEst_" + std::to_string(yuzu::test::process_random_salt()) +
        "_r3";
    HKEY base_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &base_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(base_h);
    // Declared BEFORE the nested block below, not after it (Gate 8 pass-5
    // finding - security-guardian/cross-platform/cpp-expert independently
    // converged on this same gap): tree_guard's destructor runs at THIS
    // function's scope exit, which - because `load` lives inside the
    // nested block below - is always strictly after load's own destructor,
    // on the normal-completion path AND on a REQUIRE-throw path alike
    // (nested-scope objects always unwind before their enclosing scope's).
    // The previous bare trailing establish_cleanup_tree(base) call
    // preserved this ordering only when nothing threw.
    EstablishTreeGuard tree_guard{base};
    const std::wstring base_w = establish_widen(base);

    {
        // Scoped so EstablishHiveLoad (and the open handle it holds into
        // base\churn) is torn down BEFORE the recursive cleanup below runs
        // (adversarial-review finding, PR-A round 2).
        EstablishHiveLoad load(base); // 200 churn watches + writer thread, private pool

        std::vector<std::int64_t> t_event, t_wait_create, t_open, t_notify, t_wait_set;
        for (int i = 0; i < kEstablishSamples; ++i) {
            establish_registry_sample(
                &load.pool.env,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                [&](std::vector<std::int64_t>& t_open_inner) {
                    HKEY h = nullptr;
                    time_call(t_open_inner, [&] {
                        ::RegOpenKeyExW(HKEY_CURRENT_USER, base_w.c_str(), 0, KEY_NOTIFY | KEY_READ,
                                       &h);
                    });
                    return h;
                },
                t_event, t_wait_create, t_open, t_notify, t_wait_set);
        }
        warn_establish("R3 registry target-present UNDER HIVE LOAD", "CreateEventW", t_event);
        warn_establish("R3 registry target-present UNDER HIVE LOAD", "CreateThreadpoolWait",
                       t_wait_create);
        warn_establish("R3 registry target-present UNDER HIVE LOAD", "RegOpenKeyExW", t_open);
        warn_establish("R3 registry target-present UNDER HIVE LOAD", "RegNotifyChangeKeyValue",
                       t_notify);
        warn_establish("R3 registry target-present UNDER HIVE LOAD", "SetThreadpoolWait",
                       t_wait_set);
    } // load destroyed here - base\churn's handle is closed before cleanup
    // tree_guard's destructor cleans up base\... here, unconditionally.
}

TEST_CASE("Watch establishment (Registry): target-absent depth6 under hive load (R4)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::string base =
        "SOFTWARE\\YuzuTest\\SparkEst_" + std::to_string(yuzu::test::process_random_salt()) +
        "_r4";
    HKEY base_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &base_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(base_h);
    // Same ordering argument as R3's identical declaration - see that
    // comment (Gate 8 pass-5 finding).
    EstablishTreeGuard tree_guard{base};
    const std::string target = base + "\\a\\b\\c\\d\\e\\f";

    {
        // Scoped so EstablishHiveLoad is torn down before the recursive
        // cleanup below runs (same reasoning as R3's identical scoping).
        EstablishHiveLoad load(base);

        std::vector<std::int64_t> t_event, t_wait_create, t_open_per_level, t_notify, t_wait_set;
        for (int i = 0; i < kEstablishSamples; ++i) {
            establish_registry_sample(
                &load.pool.env, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
                [&](std::vector<std::int64_t>& t_open_inner) -> HKEY {
                    std::string path = target;
                    for (;;) {
                        const std::wstring path_w = establish_widen(path);
                        HKEY h = nullptr;
                        LONG rc = 0;
                        time_call(t_open_inner, [&] {
                            rc = ::RegOpenKeyExW(HKEY_CURRENT_USER, path_w.c_str(), 0,
                                                 KEY_NOTIFY | KEY_READ, &h);
                        });
                        if (rc == ERROR_SUCCESS)
                            return h;
                        const auto pos = path.find_last_of('\\');
                        if (pos == std::string::npos)
                            return nullptr;
                        path = path.substr(0, pos);
                    }
                },
                t_event, t_wait_create, t_open_per_level, t_notify, t_wait_set);
        }
        warn_establish("R4 registry target-absent depth6 UNDER HIVE LOAD", "CreateEventW",
                       t_event);
        warn_establish("R4 registry target-absent depth6 UNDER HIVE LOAD", "CreateThreadpoolWait",
                       t_wait_create);
        warn_establish("R4 registry target-absent depth6 UNDER HIVE LOAD",
                       "RegOpenKeyExW (per level)", t_open_per_level);
        warn_establish("R4 registry target-absent depth6 UNDER HIVE LOAD",
                       "RegNotifyChangeKeyValue", t_notify);
        warn_establish("R4 registry target-absent depth6 UNDER HIVE LOAD", "SetThreadpoolWait",
                       t_wait_set);
    } // load destroyed here
    // tree_guard's destructor cleans up base\... here, unconditionally.
}

TEST_CASE("Watch establishment (Registry): WaitForThreadpoolWaitCallbacks drain, idle vs in-flight (R5)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    // RAII, not two unconditional closes at loop-bottom (Gate 4 unhappy-path
    // finding, PR-A round 5): a REQUIRE throwing between the two creates
    // below used to leak whichever of ev/wait had already succeeded.
    struct EventWaitGuard {
        HANDLE ev{nullptr};
        PTP_WAIT wait{nullptr};
        ~EventWaitGuard() {
            if (wait)
                ::CloseThreadpoolWait(wait);
            if (ev)
                ::CloseHandle(ev);
        }
    };

    // Idle drain: a wait that was never signaled, disarmed then drained -
    // this is unwatch()'s common case (spark_registry.cpp:304's
    // WaitForThreadpoolWaitCallbacks(TRUE)).
    std::vector<std::int64_t> t_idle;
    for (int i = 0; i < kEstablishSamples; ++i) {
        EventWaitGuard g;
        g.ev = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
        REQUIRE(g.ev != nullptr);
        g.wait = ::CreateThreadpoolWait(&establish_null_wait_cb, nullptr, nullptr);
        REQUIRE(g.wait != nullptr);
        ::SetThreadpoolWait(g.wait, g.ev, nullptr);
        ::SetThreadpoolWait(g.wait, nullptr, nullptr); // cancel before it ever fires
        time_call(t_idle, [&] { ::WaitForThreadpoolWaitCallbacks(g.wait, TRUE); });
    }
    warn_establish("R5 drain idle", "WaitForThreadpoolWaitCallbacks", t_idle);

    // In-flight drain: the callback is already running (sleeping 50ms) when
    // unwatch() calls the drain - this is the case that stalls a lane if the
    // callback is parked inside an inline consumer (the whole reason this
    // restructuring exists). n matches the plan's n>=200 (adversarial-review
    // finding, PR-A round 2 - previously 20, deliberately smaller since each
    // sample costs >=50ms, but that read as a plan-contract deviation
    // without ever stating so; 200 samples costs ~10s+, acceptable for a
    // by-hand DGRHP-only, env-gated case).
    std::vector<std::int64_t> t_inflight;
    int inflight_not_started = 0; // adversarial-review finding, PR-A round 2: a sample
                                  // where the callback never started before the drain
                                  // ran is measuring cancellation, not the in-flight
                                  // drain this case is named for - now DETECTED via
                                  // the started-handshake below, not just theorized
    constexpr int kInflightSamples = kEstablishSamples;
    for (int i = 0; i < kInflightSamples; ++i) {
        std::atomic<bool> started{false};
        EventWaitGuard g;
        g.ev = ::CreateEventW(nullptr, TRUE /*manual-reset*/, FALSE, nullptr);
        REQUIRE(g.ev != nullptr);
        g.wait = ::CreateThreadpoolWait(&establish_r5_inflight_cb, &started, nullptr);
        REQUIRE(g.wait != nullptr);
        ::SetThreadpoolWait(g.wait, g.ev, nullptr);
        ::SetEvent(g.ev); // fire it - the callback is now (about to be) running
        // Wait for the callback to actually announce it started (bounded -
        // if the pool never picks it up within 1s, this sample is genuinely
        // measuring cancellation; still time it, but count it separately so
        // the reported series is honest about what it contains) rather than
        // a flat 5ms sleep that assumed, without proving, that the pool had
        // already dispatched the callback by then.
        if (!eventually([&] { return started.load(std::memory_order_acquire); }, 1000ms))
            ++inflight_not_started;
        time_call(t_inflight, [&] { ::WaitForThreadpoolWaitCallbacks(g.wait, TRUE); });
    }
    warn_establish("R5 drain in-flight (50ms callback)", "WaitForThreadpoolWaitCallbacks",
                   t_inflight);
    WARN("R5 drain in-flight: " << inflight_not_started << " of " << kInflightSamples
         << " samples never observed the callback start within 1s (those samples' "
            "elapsed time characterizes TP_WAIT cancellation, not the 50ms in-flight "
            "drain - expect them at 0)");
}

TEST_CASE("Watch establishment (Registry): THREAD_AGNOSTIC correctness control (R6)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    // Real risk this control exists for (Astra, plan round 3): without
    // REG_NOTIFY_THREAD_AGNOSTIC, a notification registered on a thread that
    // then exits is indistinguishable - by symptom alone - from a real
    // registry change, because the registering thread's OWN EXIT can signal
    // the event. This case proves the flag is what makes the notification
    // survive; the negative control demonstrates (does not hard-assert,
    // since the failure-mode timing is exactly what's being characterized)
    // what happens without it.
    const std::string sub = "SOFTWARE\\YuzuTest\\SparkEst_" +
                            std::to_string(yuzu::test::process_random_salt()) + "_r6";
    HKEY setup_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &setup_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(setup_h);
    const std::wstring sub_w = establish_widen(sub);

    struct RunResult {
        bool before_write; // fired during the settle sleep, before any write -
                           // a true here is the thread-exit artifact ITSELF
        bool after_write;  // fired after the write, observed with before_write's
                           // own contribution reset out first
    };
    auto run_one = [&](bool thread_agnostic) -> RunResult {
        auto fired = std::make_shared<std::atomic<bool>>(false);
        auto ev_holder = std::make_shared<HANDLE>(nullptr);
        auto wait_holder = std::make_shared<PTP_WAIT>(nullptr);
        auto key_holder = std::make_shared<HKEY>(nullptr);

        std::thread registrant([&, fired, ev_holder, wait_holder, key_holder] {
            *ev_holder = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
            ::RegOpenKeyExW(HKEY_CURRENT_USER, sub_w.c_str(), 0, KEY_NOTIFY | KEY_READ,
                            key_holder.get());
            *wait_holder = ::CreateThreadpoolWait(&establish_r6_fired_cb, fired.get(), nullptr);
            const DWORD filter = REG_NOTIFY_CHANGE_LAST_SET |
                                 (thread_agnostic ? REG_NOTIFY_THREAD_AGNOSTIC : 0);
            ::RegNotifyChangeKeyValue(*key_holder, FALSE, filter, *ev_holder, TRUE);
            ::SetThreadpoolWait(*wait_holder, *ev_holder, nullptr);
            // Thread exits HERE, immediately after arming - the whole point
            // of the control.
        });
        registrant.join();

        std::this_thread::sleep_for(100ms); // let any registering-thread-exit
                                            // artifact settle before sampling
        // Sample and RESET before writing (adversarial-review finding, PR-A
        // round 2): the original single post-write sample could not tell a
        // thread-exit artifact from a write-triggered fire - both set the
        // same sticky bool, read only once, after both candidate causes had
        // already had a chance to run. Sampling `before_write` here, THEN
        // clearing the flag, makes the later `after_write` sample
        // attributable to the write alone.
        const bool before_write = fired->load(std::memory_order_relaxed);
        fired->store(false, std::memory_order_relaxed);

        DWORD v = 1;
        HKEY writer_h = nullptr;
        ::RegOpenKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_SET_VALUE, &writer_h);
        ::RegSetValueExA(writer_h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v),
                         sizeof(v));
        ::RegCloseKey(writer_h);

        const bool after_write =
            eventually([&] { return fired->load(std::memory_order_relaxed); }, 3000ms);

        if (*wait_holder) {
            ::SetThreadpoolWait(*wait_holder, nullptr, nullptr);
            ::WaitForThreadpoolWaitCallbacks(*wait_holder, TRUE);
            ::CloseThreadpoolWait(*wait_holder);
        }
        if (*key_holder)
            ::RegCloseKey(*key_holder);
        if (*ev_holder)
            ::CloseHandle(*ev_holder);
        return {before_write, after_write};
    };

    const RunResult with_flag = run_one(/*thread_agnostic=*/true);
    CHECK(with_flag.after_write); // REG_NOTIFY_THREAD_AGNOSTIC: must survive the
                                  // registering thread's exit and see the write
    const RunResult without_flag = run_one(/*thread_agnostic=*/false);
    WARN("R6 THREAD_AGNOSTIC control: with-flag before_write=" << with_flag.before_write
         << " after_write=" << with_flag.after_write << " | without-flag before_write="
         << without_flag.before_write << " after_write=" << without_flag.after_write
         << " (without-flag NOT hard-asserted - this control characterizes, rather than "
            "assumes, the failure mode; without_flag.before_write==true IS the documented "
            "risk itself - the registering thread's own exit signaling the event, now "
            "distinguishable from without_flag.after_write, a write the notification "
            "survived to observe despite lacking THREAD_AGNOSTIC)");

    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

TEST_CASE("Watch establishment (Service): OpenSCManagerW connect+close (S1)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    std::vector<std::int64_t> t_open, t_close;
    for (int i = 0; i < kEstablishSamples; ++i) {
        SC_HANDLE scm = nullptr;
        time_call(t_open,
                  [&] { scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); });
        REQUIRE(scm != nullptr);
        time_call(t_close, [&] { ::CloseServiceHandle(scm); });
    }
    warn_establish("S1 OpenSCManagerW connect", "OpenSCManagerW", t_open);
    warn_establish("S1 OpenSCManagerW connect", "CloseServiceHandle", t_close);
}

TEST_CASE("Watch establishment (Service): OpenServiceW+NotifyServiceStatusChangeW across the real "
          "service list (S2)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    // Same mask spark_service.cpp uses (spark_service.cpp:888-892) - copied
    // here rather than shared since it is a private constexpr in that TU.
    constexpr DWORD kEstablishNotifyMask =
        SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING |
        SERVICE_NOTIFY_STOP_PENDING | SERVICE_NOTIFY_CONTINUE_PENDING |
        SERVICE_NOTIFY_PAUSE_PENDING | SERVICE_NOTIFY_PAUSED;

    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    REQUIRE(scm != nullptr);

    // EnumServicesStatusExW two-call pattern (MSDN): size probe, then fetch.
    // resume reset to 0 before the real call - the probe call is expected to
    // fail (ERROR_MORE_DATA) and must not leave a stale resume handle for
    // the real enumeration to (incorrectly) start from.
    DWORD needed = 0, count = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr,
                            0, &needed, &count, &resume, nullptr);
    resume = 0;
    std::vector<BYTE> buf(needed);
    REQUIRE(::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                    buf.data(), static_cast<DWORD>(buf.size()), &needed, &count,
                                    &resume, nullptr));
    REQUIRE(count > 0);
    const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    std::vector<std::int64_t> t_open, t_notify;
    std::vector<std::int64_t> t_open_failed; // GetLastError-bearing failures, timed separately
    int sampled = 0;
    for (int cycle = 0; sampled < kEstablishSamples; ++cycle) {
        // Cycle the real service list (EnumServicesStatusExW "cycled to
        // n >= 200" per the plan) - re-use the enumeration round-robin until
        // kEstablishSamples opens have been attempted.
        const auto& svc = entries[static_cast<DWORD>(cycle) % count];

        SC_HANDLE h = nullptr;
        DWORD last_err = 0;
        time_call(t_open, [&] {
            h = ::OpenServiceW(scm, svc.lpServiceName, SERVICE_QUERY_STATUS);
            if (!h)
                last_err = ::GetLastError(); // SAME thread, IMMEDIATELY after the
                                             // failed call (Astra correctness note)
        });
        ++sampled;
        if (!h) {
            // Gate 4 happy-path finding, PR-A round 5: time_call above ran
            // unconditionally, so a failed open's (likely fast) timing was
            // silently mixed into t_open - the exact same series the WARN
            // below reports as "OpenServiceW" latency, contradicting its own
            // "not timed as a separate latency series" wording. pop_back()
            // it out, matching the bulk-arm Service series' existing
            // convention (t_svc_arm.pop_back() on failure) - the failure is
            // still visible via t_open_failed's GetLastError codes.
            t_open.pop_back();
            t_open_failed.push_back(static_cast<std::int64_t>(last_err));
            continue;
        }

        SERVICE_NOTIFYW notify{};
        notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        notify.pfnNotifyCallback = &establish_s2_notify_cb;
        DWORD rc = 0;
        time_call(t_notify,
                  [&] { rc = ::NotifyServiceStatusChangeW(h, kEstablishNotifyMask, &notify); });
        (void)rc; // report-only; a real service under active management may
                 // legitimately refuse a second concurrent notify - not a
                 // harness failure either way.
        ::CloseServiceHandle(h);
    }
    ::CloseServiceHandle(scm);

    warn_establish("S2 service list open+notify", "OpenServiceW", t_open);
    warn_establish("S2 service list open+notify", "NotifyServiceStatusChangeW", t_notify);
    WARN("S2 service list open+notify: " << t_open_failed.size() << " of " << sampled
         << " OpenServiceW attempts failed and are excluded from the t_open series above"
            " (GetLastError values reported, not timed as a separate latency series)");
}

TEST_CASE("Watch establishment (Service): S2 sequence under SCM load (S3)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    // Same mask S2 uses (spark_service.cpp:888-892's copy).
    constexpr DWORD kEstablishNotifyMask =
        SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING |
        SERVICE_NOTIFY_STOP_PENDING | SERVICE_NOTIFY_CONTINUE_PENDING |
        SERVICE_NOTIFY_PAUSE_PENDING | SERVICE_NOTIFY_PAUSED;

    // SCM setup + enumeration FIRST, entirely before the churn threads exist
    // (adversarial-review finding, PR-A round 2): a REQUIRE failing here
    // used to unwind past two already-constructed, unguarded joinable
    // std::threads, which std::terminate()s the whole test binary instead
    // of reporting the failed precondition cleanly. Moving thread creation
    // to after every REQUIRE below removes the hazard without adding new
    // RAII scaffolding - nothing between thread creation and the
    // deterministic join() at the end can fail a fatal assertion.
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    REQUIRE(scm != nullptr);
    // resume reset to 0 before the real call, same reasoning as S2's
    // identical comment - the probe call is expected to fail (ERROR_MORE_
    // DATA) and must not leave a stale resume handle for the real
    // enumeration to (incorrectly) start from (adversarial-review finding,
    // PR-A round 2 - this reset was present in S2 but missing here).
    DWORD needed = 0, count = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr,
                            0, &needed, &count, &resume, nullptr);
    resume = 0;
    std::vector<BYTE> buf(needed);
    REQUIRE(::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                    buf.data(), static_cast<DWORD>(buf.size()), &needed, &count,
                                    &resume, nullptr));
    REQUIRE(count > 0);
    const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    // SCM load: two background threads hammering OpenSCManagerW+Close in a
    // tight loop for the duration of the measurement - a proxy for
    // contention on the SCM RPC connection itself (no toggling of any real
    // service; read-only, safe on any host). No REQUIRE/fatal assertion
    // runs anywhere below this point - only the timing loop and the
    // deterministic join()s.
    std::atomic<bool> stop{false};
    auto scm_churn = [&stop] {
        while (!stop.load(std::memory_order_relaxed)) {
            if (SC_HANDLE h = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT))
                ::CloseServiceHandle(h);
        }
    };
    std::thread t1(scm_churn), t2(scm_churn);

    // Complete S2 sequence (open + notify), not just open (adversarial-
    // review finding, PR-A round 2: this loop previously timed only
    // OpenServiceW, so S3 was not actually "S2 under SCM load" despite its
    // own name - notification-registration latency under contention went
    // uncharacterized).
    std::vector<std::int64_t> t_open, t_notify;
    std::vector<std::int64_t> t_open_failed;
    int sampled = 0;
    for (int cycle = 0; sampled < kEstablishSamples; ++cycle) {
        const auto& svc = entries[static_cast<DWORD>(cycle) % count];
        SC_HANDLE h = nullptr;
        DWORD last_err = 0;
        time_call(t_open, [&] {
            h = ::OpenServiceW(scm, svc.lpServiceName, SERVICE_QUERY_STATUS);
            if (!h)
                last_err = ::GetLastError();
        });
        ++sampled;
        if (!h) {
            // Gate 4 happy-path finding, PR-A round 5: see S2's identical
            // comment - pop_back() keeps a failed open's timing out of the
            // t_open series it would otherwise silently contaminate.
            t_open.pop_back();
            t_open_failed.push_back(static_cast<std::int64_t>(last_err));
            continue;
        }

        SERVICE_NOTIFYW notify{};
        notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        notify.pfnNotifyCallback = &establish_s2_notify_cb;
        DWORD rc = 0;
        time_call(t_notify,
                  [&] { rc = ::NotifyServiceStatusChangeW(h, kEstablishNotifyMask, &notify); });
        (void)rc; // report-only, same posture as S2
        ::CloseServiceHandle(h);
    }
    ::CloseServiceHandle(scm);

    stop.store(true, std::memory_order_relaxed);
    t1.join();
    t2.join();

    warn_establish("S3 OpenServiceW UNDER SCM LOAD", "OpenServiceW", t_open);
    warn_establish("S3 NotifyServiceStatusChangeW UNDER SCM LOAD", "NotifyServiceStatusChangeW",
                   t_notify);
    WARN("S3 UNDER SCM LOAD: " << t_open_failed.size() << " of " << sampled
         << " OpenServiceW attempts failed and are excluded from the t_open series above"
            " (GetLastError values reported, not timed as a separate latency series)");
}

TEST_CASE("Watch establishment (File): is_directory + CreateFileW sanity (F1)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path();

    std::vector<std::int64_t> t_is_dir, t_create;
    for (int i = 0; i < kEstablishSamples; ++i) {
        std::error_code ec;
        bool isdir = false;
        time_call(t_is_dir, [&] { isdir = fs::is_directory(dir, ec); });
        REQUIRE(isdir);

        HANDLE h = nullptr;
        time_call(t_create, [&] {
            h = ::CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                              nullptr);
        });
        REQUIRE(h != INVALID_HANDLE_VALUE);
        ::CloseHandle(h);
    }
    warn_establish("F1 file dir sanity", "is_directory", t_is_dir);
    warn_establish("F1 file dir sanity", "CreateFileW(BACKUP|OVERLAPPED)", t_create);
}

TEST_CASE("Watch establishment: post-fix fast-path cost, bulk engine.arm() (N=200/mechanism)",
          "[spark][mechanism][windows][latency][establish]") {
    // NOT env-gated on YUZU_SPARK_ESTABLISH_BENCH alone in spirit - this
    // case exercises the REAL mechanisms (through SparkEngine::arm(), not
    // raw Win32 calls), so it is meaningful TODAY (the "before" figure) and
    // must be re-run VERBATIM once PR-B lands (the "after" figure) - see
    // the plan's "Post-fix fast-path cost" note: the restructuring adds one
    // _beginthreadex spawn per arm/re-arm, and this measurement is what
    // states that cost honestly against CH-5-UAT's spark_p99 <= 15s gate.
    // Gated the same way as every other case here regardless, since it is
    // still a measurement, not a gate.
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    // Extended to cover File and Service, plus a Registry RE-ARM series, not
    // just Registry's initial arm (adversarial-review finding, PR-A round
    // 2): the plan requires "bulk engine.arm() of N=200 local keys per
    // mechanism and Registry re-arm wall-clock" - the original scaffold
    // covered only the first of those three.
    constexpr int kBulkKeys = 200;
    const std::string base =
        "SOFTWARE\\YuzuTest\\SparkEst_" + std::to_string(yuzu::test::process_random_salt()) +
        "_bulk";
    HKEY base_h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                              nullptr, &base_h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(base_h);

    // Real service names to cycle through for the Service series - same
    // enumeration shape S2/S3 already use. Independent of the SparkEngine
    // below (plain SCM calls), so gathered up front.
    std::vector<std::wstring> service_names;
    {
        SC_HANDLE scm =
            ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        REQUIRE(scm != nullptr);
        // RAII, not a trailing CloseServiceHandle (Gate 4 unhappy-path
        // finding, PR-A round 5): the REQUIRE(count > 0) below used to
        // leak `scm` on failure.
        struct ScGuard {
            SC_HANDLE h{nullptr}; // NSDMI, matching every sibling guard's pattern
            ~ScGuard() {
                if (h)
                    ::CloseServiceHandle(h);
            }
        } scm_guard{scm};
        DWORD needed = 0, count = 0, resume = 0;
        ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                nullptr, 0, &needed, &count, &resume, nullptr);
        resume = 0;
        std::vector<BYTE> buf(needed);
        REQUIRE(::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                        SERVICE_STATE_ALL, buf.data(),
                                        static_cast<DWORD>(buf.size()), &needed, &count, &resume,
                                        nullptr));
        REQUIRE(count > 0);
        const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i)
            service_names.emplace_back(entries[i].lpServiceName);
    }

    yuzu::test::TempDir file_base("yuzu_test_spark_est_bulk_file_");
    {
        std::error_code ec;
        std::filesystem::create_directory(file_base.path, ec);
        REQUIRE(!ec);
    }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();
    // RAII, not trailing engine.stop()/establish_cleanup_tree calls at the
    // end of this function (Gate 4 unhappy-path finding, PR-A round 5): any
    // of the many REQUIREs in the Registry/File/Service arm loops below
    // used to leave the engine's background threads running AND leak
    // base\k0..k199 on the first failure, since both trailing calls were
    // reached only on full completion.
    struct BulkGuard {
        SparkEngine& engine;
        const std::string& base;
        ~BulkGuard() {
            engine.stop();
            establish_cleanup_tree(base); // base\k0..k199 - RegDeleteKeyA
                                          // would silently fail here (200
                                          // children still present)
        }
    } bulk_guard{engine, base};

    // --- Registry: initial arm, then re-arm (value-write triggers each
    // key's TP_WAIT callback -> on_fire() -> reconcile()) ---
    std::vector<std::string> registry_subs;
    registry_subs.reserve(kBulkKeys);
    std::vector<std::int64_t> t_arm;
    const auto bulk_t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kBulkKeys; ++i) {
        const std::string sub = base + "\\k" + std::to_string(i);
        HKEY h = nullptr;
        REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                                  nullptr, &h, nullptr) == ERROR_SUCCESS);
        ::RegCloseKey(h);
        registry_subs.push_back(sub);
        time_call(t_arm, [&] {
            auto r = engine.arm(*c, registry_spec("HKCU", sub));
            REQUIRE(r.has_value());
        });
    }
    const auto bulk_t1 = std::chrono::steady_clock::now();
    warn_establish("post-fix-cost bulk arm (TODAY's baseline - re-run on PR-B build)",
                   "SparkEngine::arm (Registry)", t_arm);
    WARN("post-fix-cost bulk arm: " << kBulkKeys << " arms, wall clock total = "
         << std::chrono::duration_cast<std::chrono::milliseconds>(bulk_t1 - bulk_t0).count()
         << "ms (compare against CH-5-UAT's spark_p99 <= 15s gate once this same case is "
            "re-run on the PR-B build)");

    // Registry sparks fire on CHANGE only, not on the initial arm, so this
    // is expected to already be 0 - captured as a baseline (not REQUIRE'd
    // as exactly 0) so a stray unrelated event can't hard-fail this
    // by-hand-only harness case; the re-arm wall clock below measures the
    // DELTA off this baseline either way.
    const auto rearm_baseline = got.count();
    const auto rearm_t0 = std::chrono::steady_clock::now();
    for (const auto& sub : registry_subs) {
        HKEY h = nullptr;
        if (::RegOpenKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_SET_VALUE, &h) ==
            ERROR_SUCCESS) {
            DWORD v = 1;
            ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
            ::RegCloseKey(h);
        }
    }
    const bool rearm_ok = eventually(
        [&] { return got.count() >= rearm_baseline + static_cast<std::size_t>(kBulkKeys); },
        30000ms);
    const auto rearm_t1 = std::chrono::steady_clock::now();
    WARN("post-fix-cost Registry re-arm: " << kBulkKeys << " value-writes, "
         << (rearm_ok ? "all" : "NOT ALL") << " observed (got.count()=" << got.count()
         << "), wall clock total = "
         << std::chrono::duration_cast<std::chrono::milliseconds>(rearm_t1 - rearm_t0).count()
         << "ms");

    // --- File: N=200 real, distinct local directories ---
    std::vector<std::int64_t> t_file_arm;
    const auto file_t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kBulkKeys; ++i) {
        const auto dir = file_base.path / ("d" + std::to_string(i));
        std::error_code ec;
        std::filesystem::create_directory(dir, ec);
        REQUIRE(!ec);
        time_call(t_file_arm, [&] {
            auto r = engine.arm(*c, file_spec(dir.string()));
            REQUIRE(r.has_value());
        });
    }
    const auto file_t1 = std::chrono::steady_clock::now();
    warn_establish("post-fix-cost bulk arm (TODAY's baseline - re-run on PR-B build)",
                   "SparkEngine::arm (File)", t_file_arm);
    WARN("post-fix-cost bulk arm (File): " << kBulkKeys << " arms, wall clock total = "
         << std::chrono::duration_cast<std::chrono::milliseconds>(file_t1 - file_t0).count()
         << "ms");

    // --- Service: cycle the REAL service list up to N=200 arms. If the
    // host has fewer than kBulkKeys services, this wraps and later arms
    // become coalescing re-arms of an already-held key (a materially
    // DIFFERENT, cheaper operation than a fresh arm) rather than N=200
    // distinct fresh arms - reported explicitly so the number is never
    // read as more than it is. ---
    // Failures are SKIPPED, not REQUIRE'd, and excluded from the timing
    // series (same defensive posture as S2's t_open_failed): a real-world
    // enumerated service name could in principle fail valid_service_name()
    // and reach that rejection fast, without any real OS call - blending
    // that near-zero timing into t_svc_arm would understate the series,
    // and a hard REQUIRE would abort the whole by-hand DGRHP run over one
    // oddly-named service.
    std::vector<std::int64_t> t_svc_arm;
    int svc_arm_failed = 0;
    const auto svc_t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kBulkKeys; ++i) {
        const std::wstring& name_w = service_names[static_cast<std::size_t>(i) %
                                                    service_names.size()];
        // Real UTF-16 conversion, not a naive char-by-char truncation
        // (governance finding, PR-A round 2) - unlike this harness's own
        // synthetic salted names, a real enumerated service's internal
        // lpServiceName has no ASCII guarantee.
        const std::string name = yuzu::win::from_wide(name_w.c_str());
        bool ok = false;
        time_call(t_svc_arm, [&] {
            auto r = engine.arm(*c, service_spec(name));
            ok = r.has_value();
        });
        if (!ok) {
            ++svc_arm_failed;
            t_svc_arm.pop_back();
        }
    }
    const auto svc_t1 = std::chrono::steady_clock::now();
    warn_establish("post-fix-cost bulk arm (TODAY's baseline - re-run on PR-B build)",
                   "SparkEngine::arm (Service)", t_svc_arm);
    WARN("post-fix-cost bulk arm (Service): " << kBulkKeys << " arms over "
         << service_names.size() << " real services (wraps=" << (kBulkKeys > static_cast<int>(
             service_names.size())) << " - a wrap means later arms are coalescing re-arms of an "
            "already-held key, NOT fresh arms; " << svc_arm_failed << " arm(s) failed and are "
            "excluded from the timing series above), wall clock total = "
         << std::chrono::duration_cast<std::chrono::milliseconds>(svc_t1 - svc_t0).count()
         << "ms");
    // bulk_guard's destructor stops the engine and cleans up the registry
    // tree here, unconditionally.
}

/// Polls `got` for the first Fired SparkEvent matching `key`, returning its
/// engine-stamped fire time (SparkEvent::at) or nullopt on timeout. Scans
/// from the start each call rather than tracking a resume cursor - at
/// kEstablishSamples-scale (<= 200 prior events) the O(n) rescan is a few
/// hundred string comparisons, negligible next to the microsecond-scale
/// latencies being measured, and it is simpler to read than cursor state
/// shared across sequential calls for DIFFERENT keys.
std::optional<std::chrono::system_clock::time_point> wait_for_fired(
    Collector& got, const std::string& key, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const std::size_t n = got.count();
        for (std::size_t i = 0; i < n; ++i) {
            const SparkEvent ev = got.at(i);
            if (ev.key == key && ev.kind == SparkEventKind::Fired)
                return ev.at;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    return std::nullopt;
}

/// Real, distinct service names to drive kEstablishSamples INDEPENDENT
/// establishment round-trips - capped at the host's real count (never
/// cycled/wrapped) so a re-armed-under-a-new-key coalescing hand-off
/// (spark_service.cpp's `else if (w->last)` immediate-state path, far
/// cheaper than a fresh probe) never contaminates this series the way the
/// bulk-arm case above explicitly accepts for its own, different purpose.
std::vector<std::wstring> establish_e2e_service_names() {
    SC_HANDLE scm =
        ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    REQUIRE(scm != nullptr);
    struct ScGuard {
        SC_HANDLE h{nullptr};
        ~ScGuard() {
            if (h)
                ::CloseServiceHandle(h);
        }
    } scm_guard{scm};
    DWORD needed = 0, count = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr,
                            0, &needed, &count, &resume, nullptr);
    resume = 0;
    std::vector<BYTE> buf(needed);
    REQUIRE(::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                    buf.data(), static_cast<DWORD>(buf.size()), &needed, &count,
                                    &resume, nullptr));
    REQUIRE(count > 0);
    const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    std::vector<std::wstring> names;
    names.reserve(count);
    for (DWORD i = 0; i < count; ++i)
        names.emplace_back(entries[i].lpServiceName);
    return names;
}

TEST_CASE("Watch establishment (Service): end-to-end Add-accepted to first-trustworthy-state via "
          "SparkEngine::arm() (E1 idle) (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][latency][establish]") {
    // Fills the gap both S2/S3 and the bulk-arm case above leave open
    // (#2012/#3840 PR-B3 kickoff doc, "Latency characterization"): S2/S3
    // measure the raw OpenServiceW/NotifyServiceStatusChangeW calls
    // directly, not through the mechanism; the bulk-arm case above measures
    // only SparkEngine::arm()'s own synchronous return (an O(1) queue push,
    // unaffected by PR-B3 - Service's watch()/unwatch() were already O(1)
    // before this series, per the corrected kickoff doc's premise
    // correction). Neither captures what a consumer actually waits on: the
    // full round trip from arm() to the first real state delivered via the
    // emit callback, which is exactly what PR-B3's probe-lane restructure
    // changes the shape of (moves OpenServiceW off the shared mechanism
    // thread onto SparkDetachedLane).
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::vector<std::wstring> names = establish_e2e_service_names();
    const int n = std::min(kEstablishSamples, static_cast<int>(names.size()));

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    std::vector<std::int64_t> t_e2e;
    int timed_out = 0;
    for (int i = 0; i < n; ++i) {
        const std::string name = yuzu::win::from_wide(names[static_cast<std::size_t>(i)].c_str());
        const auto spec = service_spec(name);
        const std::string key = spark_key(spec);
        const auto t0 = std::chrono::system_clock::now();
        auto r = engine.arm(*c, spec);
        if (!r.has_value())
            continue; // excluded, same posture as the bulk-arm case's arm failures
        if (auto fired_at = wait_for_fired(got, key, 3000ms)) {
            t_e2e.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(*fired_at - t0).count());
        } else {
            ++timed_out;
        }
        engine.disarm(*r); // sequential isolation: next sample starts from a clean key set
    }
    engine.stop();

    warn_establish("E1 Service end-to-end (idle)", "Add-accepted -> first Fired", t_e2e);
    WARN("E1 Service end-to-end (idle): " << n << " services attempted, " << timed_out
         << " timed out waiting for a Fired event (excluded from the series above)");
}

TEST_CASE("Watch establishment (Service): end-to-end Add-accepted to first-trustworthy-state via "
          "SparkEngine::arm() UNDER SCM LOAD (E2) (#2012/#3840 PR-B3)",
          "[spark][mechanism][windows][latency][establish]") {
    if (!spark_establish_bench_enabled()) {
        SUCCEED("YUZU_SPARK_ESTABLISH_BENCH unset - skipping establishment latency harness");
        return;
    }
    const std::vector<std::wstring> names = establish_e2e_service_names();
    const int n = std::min(kEstablishSamples, static_cast<int>(names.size()));

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    // Same SCM-load shape as S3: two background OpenSCManagerW-churn
    // threads for the duration of the measurement, started only after every
    // REQUIRE above (same ordering rationale as S3's own comment - a failed
    // precondition must never unwind past a live joinable thread).
    std::atomic<bool> stop{false};
    auto scm_churn = [&stop] {
        while (!stop.load(std::memory_order_relaxed)) {
            if (SC_HANDLE h = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT))
                ::CloseServiceHandle(h);
        }
    };
    std::thread t1(scm_churn), t2(scm_churn);

    std::vector<std::int64_t> t_e2e;
    int timed_out = 0;
    for (int i = 0; i < n; ++i) {
        const std::string name = yuzu::win::from_wide(names[static_cast<std::size_t>(i)].c_str());
        const auto spec = service_spec(name);
        const std::string key = spark_key(spec);
        const auto t0 = std::chrono::system_clock::now();
        auto r = engine.arm(*c, spec);
        if (!r.has_value())
            continue;
        if (auto fired_at = wait_for_fired(got, key, 3000ms)) {
            t_e2e.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(*fired_at - t0).count());
        } else {
            ++timed_out;
        }
        engine.disarm(*r);
    }
    engine.stop();

    stop.store(true, std::memory_order_relaxed);
    t1.join();
    t2.join();

    warn_establish("E2 Service end-to-end UNDER SCM LOAD", "Add-accepted -> first Fired", t_e2e);
    WARN("E2 Service end-to-end UNDER SCM LOAD: " << n << " services attempted, " << timed_out
         << " timed out waiting for a Fired event (excluded from the series above)");
}

// ── File walkoff (#2012/#3840 PR-B2), adversarial review round findings ────
//
// Fault-injection tests for the 8 HIGH-severity findings from the PR-B2
// review (Kimi K3 + Codex Sol, cross-examined, adjudicated). Each finding was
// the SAME underlying shape: a recovery/exception path silently assuming
// another code path would finish work it started. Every test below targets
// the SPECIFIC throw-point the fix closed, via a dedicated test hook
// (FileMechanismTestControls), and asserts an outcome the PRE-fix code could
// not have produced — not just "no crash". None of these have been run on
// real Windows as of this round (see this round's own report); they are
// written to the same falsifiable-outcome discipline as the rest of this
// file's PR-B2 acceptance tests.

TEST_CASE("File mechanism (direct): a throw inside create_ancestor_from_probe_locked's map "
          "insertion never destroys a live kernel-owned read (#2012/#3840 PR-B2 review "
          "finding 1)",
          "[spark][mechanism][windows][walkoff]") {
    // Insert-then-arm fix: ancestors_.try_emplace(akey) now runs BEFORE any
    // OS call, so a throw there (modelled by ancestor_insert_fail_hook) can
    // never destroy a DirWatch the kernel is still writing into — nothing
    // has been issued yet at that point. Pre-fix, the map insertion ran
    // AFTER ReadDirectoryChangesW was already issued, so an equivalent throw
    // there would have freed a live OVERLAPPED/buffer out from under the
    // kernel (the #2839 UAF class).
    yuzu::test::TempDir base("yuzu_test_spark_f1anc_");
    std::error_code ec;
    std::filesystem::create_directories(base.path, ec);
    REQUIRE(!ec);
    const auto absent = base.path / "gone" / "t.txt";

    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<int> insert_hook_calls{0};
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 40ms;
        ctl.sweep_cadence = 20ms;
        ctl.ancestor_insert_fail_hook = [&](std::wstring_view) {
            if (insert_hook_calls.fetch_add(1, std::memory_order_acq_rel) == 0)
                throw std::runtime_error("injected ancestors_.try_emplace failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("k", FileSparkParams{absent.string()}).has_value());

    REQUIRE(eventually(
        [&] { return insert_hook_calls.load(std::memory_order_acquire) >= 1; }, 3000ms));
    {
        // Falsifier part 1: the failed attempt left NOTHING live - the map
        // was never touched (the hook fires strictly before try_emplace),
        // and the failure was routed through fail_backend_locked/
        // defer_backend_retry_locked, not a crash or a leaked handle.
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->live_ancestors == 0);
        CHECK(d->probe_backend_failed >= 1);
    }
    // Falsifier part 2: the mechanism keeps making progress - the retry
    // (hook now spent, self-disarmed) succeeds and creates the ancestor for
    // real.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors >= 1;
        },
        4000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): an ancestor completion consumed then lost mid-pass is "
          "invalidated on the next sweep, not left dead with every dependent permanently "
          "sheltered behind it (#2012/#3840 PR-B2 review finding 2)",
          "[spark][mechanism][windows][walkoff]") {
    // Combines two EXISTING hooks (no new production surface needed):
    // completion_hook (filtered to the ancestor's own directory) forces
    // unwind_pass_locked's "never reached process_completion_locked at all"
    // recovery branch; ancestor_rearm_fail_hook forces THAT branch's own
    // route_noop_rearm() reissue attempt to fail too. Pre-fix, this left the
    // ancestor sitting in ancestors_ forever - handle-less, not `removing`,
    // never invalidated (sweep_probes_locked never iterated ancestors_ at
    // all) - so the dependent stayed permanently "sheltered" behind a dead
    // shelter with no future trigger. Post-fix, dead_pending_invalidate is
    // stamped and swept on the very next (non-noexcept) pass.
    yuzu::test::TempDir base("yuzu_test_spark_f2anc_");
    std::error_code ec;
    std::filesystem::create_directories(base.path, ec);
    REQUIRE(!ec);
    const auto absent = base.path / "gone" / "t.txt";
    const std::wstring base_w = base.path.wstring();

    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> completion_throw_armed{false}; // armed only once the ancestor is live
    std::atomic<int> completion_throws{0};
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 20ms;
        ctl.completion_hook = [&](std::wstring_view dir) {
            if (dir == base_w &&
                completion_throw_armed.exchange(false, std::memory_order_acq_rel)) {
                completion_throws.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected post-dequeue allocation failure (ancestor)");
            }
        };
        ctl.ancestor_rearm_fail_hook = [&](std::wstring_view dir) { return dir == base_w; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("k", FileSparkParams{absent.string()}).has_value());

    REQUIRE(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors >= 1;
        },
        3000ms));
    std::this_thread::sleep_for(150ms); // let the ancestor's own read settle/arm fully
    completion_throw_armed.store(true, std::memory_order_release);

    { std::ofstream(base.path / "unrelated.txt") << "x"; } // real completion on the
                                                            // ancestor's own read

    REQUIRE(eventually(
        [&] { return completion_throws.load(std::memory_order_acquire) >= 1; }, 3000ms));

    const std::uint64_t launched_before = [&] {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        return d->probe_launched;
    }();
    // Falsifier: live_ancestors drops back to 0 (the dead ancestor is
    // actually invalidated/erased) AND the dependent gets a fresh probe
    // launched, once sweep_probes_locked's own ancestor loop finishes what
    // unwind_pass_locked could only mark.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors == 0;
        },
        4000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched > launched_before;
        },
        4000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throw during a brand-new watch()'s registration rolls "
          "back cleanly, so a later watch() for the same directory is not permanently deaf "
          "(#2012/#3840 PR-B2 review finding 4)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("register_fail");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> hook_armed{true};
    std::atomic<int> hook_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.watch_register_fail_hook = [&](std::wstring_view) {
            if (hook_armed.exchange(false, std::memory_order_acq_rel)) {
                hook_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected watch() registration allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(a.file.string());
    const std::string key = spark_key(spec);

    // Direct mechanism call (no SparkEngine/watch_guarded in front of it
    // here) - the injected throw propagates straight to the caller.
    CHECK_THROWS_AS(mech->watch(key, spec.params), std::runtime_error);
    CHECK(hook_hits.load(std::memory_order_acquire) == 1);
    {
        // Falsifier part 1: before the fix, dirs_[dirkey] was already
        // committed (fully or partially) by the time the throw could land,
        // so a LATER watch() for the same directory would see fresh ==
        // false and ride along with a slot that never reserved a probe -
        // permanently deaf, reporting armed forever. After the fix, the
        // rollback erases the whole entry.
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        CHECK(d->live_dirs == 0);
    }
    // Falsifier part 2: a later watch() for the SAME directory (hook now
    // spent, self-disarmed) succeeds AND actually reserves/launches a probe.
    REQUIRE(mech->watch(key, spec.params).has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched >= 1;
        },
        3000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throw inside reserve_probe_locked's own allocation "
          "leaves the watch retryable, not permanently stranded Pending-with-no-call "
          "(#2012/#3840 PR-B2 review finding 5)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("reserve_fail");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> force_first_probe_fail{true};
    std::atomic<int> reserve_hook_calls{0};
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 40ms;
        ctl.sweep_cadence = 20ms;
        ctl.probe_hook = [&](std::wstring_view) {
            if (force_first_probe_fail.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error("injected first-probe backend failure");
            // every later probe (the retries) resolves for real.
        };
        // Throw on the SECOND reserve_probe_locked call only (call #0 is
        // watch()'s own initial reserve; call #1 is the Deferred retry's
        // reserve, staged after the forced probe failure above) - a precise,
        // deterministic target, not a single-shot-on-first-call gate.
        ctl.reserve_probe_fail_hook = [&](std::wstring_view) {
            if (reserve_hook_calls.fetch_add(1, std::memory_order_acq_rel) == 1)
                throw std::runtime_error("injected reserve_probe_locked allocation failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    // Falsifier: before the fix, reserve_probe_locked stamped Pending +
    // generation BEFORE building `job` - a throw at the injected point left
    // the watch Pending with w.call == nullopt forever (sweep_probes_locked's
    // Pending case is a no-op without a call). After the fix, `w` is
    // untouched by the throw (still Deferred, already due), so the very next
    // pass retries and eventually establishes for real.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() &&
                  d->probe_launched >= 2; // the forced-fail probe (#1) + the real
                                          // retry that follows (#2, hook spent by then)
        },
        5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throw inside resolve_probe_locked's own log call, after "
          "the state transition, never strands a failed probe Pending-with-no-call "
          "(#2012/#3840 PR-B2 review finding 6)",
          "[spark][mechanism][windows][walkoff]") {
    // Needs a probe that genuinely resolves to r.has_value() && !r->ok (not
    // WorkerThrew, which never reaches the log line at all) - a nonexistent
    // drive root (#1927 shape) reaches its fixed point in microseconds and
    // is guaranteed to keep failing, so every retry re-triggers the same
    // code path deterministically.
    char letter = 0;
    {
        const DWORD mask = ::GetLogicalDrives();
        for (char cand = 'Z'; cand >= 'B'; --cand) {
            if (!(mask & (1u << (cand - 'A')))) {
                letter = cand;
                break;
            }
        }
    }
    if (!letter) {
        FAIL("no free drive letter (B-Z) available on this box - review finding 6's "
             "log-ordering fix is unverified here");
    }
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> log_hook_armed{true};
    std::atomic<int> log_hook_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 1ms; // force resolution onto the SWEEP path (run()'s own
                                     // thread, report_health defaults true), not watch()'s
                                     // own fast-resolve branch
        ctl.backend_retry_base = 40ms;
        ctl.sweep_cadence = 20ms;
        ctl.probe_hook = [](std::wstring_view) { std::this_thread::sleep_for(60ms); };
        ctl.resolve_log_fail_hook = [&](std::wstring_view) {
            if (log_hook_armed.exchange(false, std::memory_order_acq_rel)) {
                log_hook_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected resolve_probe_locked log allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(std::string(1, letter) + ":\\nonexistent\\dir\\file.txt");
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    REQUIRE(eventually([&] { return log_hook_hits.load(std::memory_order_acquire) >= 1; },
                       4000ms));
    const std::uint64_t launched_before = [&] {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        return d->probe_launched;
    }();
    // Falsifier: before the fix, resolve_probe_locked's own spdlog::warn ran
    // BEFORE the Deferred transition - a throw there left the watch Pending
    // with w.call already reset (consumed by the sweep's try_take before
    // resolve_probe_locked was even called), permanently stuck. After the
    // fix, the transition runs first regardless of whether the log throws,
    // so the watch keeps retrying (this target can never succeed, but each
    // retry launches a fresh doomed probe rather than none at all).
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched > launched_before;
        },
        4000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a commit failure landing inside watch()'s own caller-wait "
          "window is still eventually reported via health grace, not silently pre-marked "
          "reported-with-no-dispatch (#2012/#3840 PR-B2 review finding 7)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("attach_fail");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const std::wstring target_dir_w = a.dir.wstring();
    {
        FileMechanismTestControls ctl;
        ctl.caller_wait_budget = 2000ms; // generous - the probe against a real, existing
                                        // directory resolves in microseconds
        ctl.health_grace = 60ms;
        ctl.sweep_cadence = 20ms;
        ctl.attach_fail_hook = [&](std::wstring_view dir) { return dir == target_dir_w; };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> faults{0};
    std::atomic<bool> last_faulted{false};
    mech->start([](const std::string&, SparkData) {},
                [&](const std::string&, bool faulted, std::string_view) {
                    faults.fetch_add(1, std::memory_order_acq_rel);
                    last_faulted.store(faulted, std::memory_order_release);
                });
    const auto spec = file_spec(a.file.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    // Falsifier: before the fix, the fast-resolve-then-attach-fails commit
    // (routed unconditionally through fail_backend_locked) pre-stamped
    // health_reported_faulted == health_desired_faulted (both true) into
    // watch()'s own local, never-dispatched FilePassWork - grace's later
    // diff-check (check_health_edge_locked) would then see no edge and
    // never call fault_ at all: the watch reports healthy while genuinely
    // dark, indefinitely. After the fix (routed through defer_backend_
    // retry_locked when report_health is false, no health stamp),
    // health_reported_faulted stays false until a DISPATCHED pass (health
    // grace, through run()'s own sweep) actually reports it.
    CHECK(eventually([&] { return faults.load(std::memory_order_acquire) >= 1; }, 4000ms));
    CHECK(last_faulted.load(std::memory_order_acquire));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a key unwatch()'d and watch()'d again while its notice is "
          "already staged does not receive a stale notice meant for the old registration "
          "(#2012/#3840 PR-B2 review finding 8)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("key_gen");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    ISparkMechanism* raw = mech.get();
    const auto spec = file_spec(a.file.string());
    std::atomic<int> total_emits{0};
    std::atomic<bool> reentrant_done{false};
    std::atomic<bool> reentrant_watch_ok{false};
    mech->start(
        [&](const std::string& key, SparkData) {
            total_emits.fetch_add(1, std::memory_order_acq_rel);
            // Reentrant unwatch()/watch() from INSIDE the emit callback is
            // legal here: run_off_lock (which dispatches this callback) runs
            // with mu_ released (this file's own OWNERSHIP/DISPATCH
            // PROTOCOL rule 4/header comment) - not a same-thread relock.
            if (!reentrant_done.exchange(true, std::memory_order_acq_rel)) {
                const std::string other = (key == "A") ? "B" : "A";
                raw->unwatch(other);
                reentrant_watch_ok.store(raw->watch(other, spec.params).has_value(),
                                         std::memory_order_release);
            }
        },
        [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("A", spec.params).has_value());
    REQUIRE(mech->watch("B", spec.params).has_value());
    std::this_thread::sleep_for(300ms); // let both reads settle/arm

    a.write("change"); // stages TWO Emit notices (one per key) in the SAME pass

    CHECK(eventually([&] { return reentrant_done.load(std::memory_order_acquire); }, 3000ms));
    std::this_thread::sleep_for(500ms); // let the whole pass finish dispatching both notices
    CHECK(reentrant_watch_ok.load(std::memory_order_acquire));
    // Falsifier: before the fix, key_index_ carried no per-key generation,
    // so the OTHER key's already-staged notice (staged before this callback
    // reentrantly unwatch()'d + watch()'d it) still passed notice_still_
    // current's directory-identity-only check and dispatched anyway - 2
    // emits for one file write. After the fix, the stale notice's
    // generation no longer matches key_index_'s current one and is
    // dropped - exactly 1 (the new registration correctly missed a change
    // that happened before it existed).
    CHECK(total_emits.load(std::memory_order_acquire) == 1);
    mech->stop();
}

// ── File walkoff (#2012/#3840 PR-B2), round-3 fixes (transition table, ────
// Astra table opine) — corrected round-2 findings 1/3/4/5/6/8/9/10, plus
// three defects the table review itself surfaced (commit_probe_locked's
// uncaught attach exception, the Idle-case resync/confirmation ordering,
// and an over-eager version of the finding-9 fix that was reverted after
// it broke the existing key_gen test above on real DGRHP hardware — see
// that test's own falsifier for the corrected, narrower trigger).

TEST_CASE("File mechanism (direct): a key joining an existing watch that is CURRENTLY faulted "
          "gets its own fault status, not silent health for the rest of the fault's duration "
          "(#2012/#3840 PR-B2 review finding 9)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir a("join_faulted");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> park_a{true};
    {
        FileMechanismTestControls ctl;
        ctl.health_grace = 60ms;
        ctl.probe_hook = [&](std::wstring_view) {
            if (park_a.load(std::memory_order_acquire))
                std::this_thread::sleep_for(500ms); // past grace, every retry, until released
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    const auto spec = file_spec(a.file.string());
    std::atomic<int> a_faults{0}, b_faults{0};
    mech->start([](const std::string&, SparkData) {},
                [&](const std::string& key, bool faulted, std::string_view) {
                    if (!faulted)
                        return;
                    if (key == "A")
                        a_faults.fetch_add(1, std::memory_order_acq_rel);
                    else if (key == "B")
                        b_faults.fetch_add(1, std::memory_order_acq_rel);
                });
    REQUIRE(mech->watch("A", spec.params).has_value());
    // A settles into a reported fault (desired == reported == true) before B ever joins.
    REQUIRE(eventually([&] { return a_faults.load(std::memory_order_acquire) >= 1; }, 3000ms));
    std::this_thread::sleep_for(150ms); // let health_reported_faulted's stamp fully settle

    // B joins the SAME already-faulted directory (Decision #3: joining a real, live watch
    // rides along — no separate establishment). Falsifier: before the fix, B rode along
    // silently healthy — check_health_edge_locked's own "desired == reported, no edge" guard
    // means nothing would ever re-fan-out the existing fault to B until the fault actually
    // CHANGES (which this test never lets happen). After the fix, watch()'s own join path
    // forces a fresh mismatch, and finding 5's unconditional per-visit check re-fans it out.
    REQUIRE(mech->watch("B", spec.params).has_value());
    CHECK(eventually([&] { return b_faults.load(std::memory_order_acquire) >= 1; }, 3000ms));

    park_a.store(false, std::memory_order_release);
    mech->stop();
}

TEST_CASE("File mechanism (direct): an ordinary key joining an already-HEALTHY, settled shared "
          "directory does NOT trigger a spurious synthetic resync to its siblings (#2012/#3840 "
          "PR-B2 review finding 9, over-trigger regression)",
          "[spark][mechanism][windows][walkoff]") {
    // This is the DGRHP-caught regression itself, isolated: an earlier version of the finding-9
    // fix bumped needs_resync unconditionally on every non-fresh watch() join (not just a
    // faulted one), which fired a bogus resync Emit to every existing sibling key on every
    // ordinary co-watch — breaking the key_gen test above (5 emits instead of 1) on real
    // Windows hardware. Asserted directly here so a future change can't silently reintroduce it
    // without tripping this test first.
    ScratchDir a("join_healthy");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const auto spec = file_spec(a.file.string());
    std::atomic<int> emits{0};
    mech->start([&](const std::string&, SparkData) { emits.fetch_add(1, std::memory_order_acq_rel); },
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("A", spec.params).has_value());
    std::this_thread::sleep_for(300ms); // let A's establishment fully settle, healthy

    REQUIRE(mech->watch("B", spec.params).has_value()); // ordinary co-watch, nothing faulted
    std::this_thread::sleep_for(500ms); // give a spurious resync every chance to fire if it exists
    CHECK(emits.load(std::memory_order_acquire) == 0); // no change ever happened on disk
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throw staging the owed shelter-confirmation probe leaves "
          "confirmation_due set, not lost - the next Idle sweep retries it "
          "(#2012/#3840 PR-B2 review finding 10)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("confirm_fail");
    const auto target = root.dir / "never_appears" / "deep.txt";
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<int> reserve_hook_calls{0};
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 20ms;
        // Call #0 is watch()'s own initial reserve (fresh DirWatch, resolves Ancestor-mode).
        // Call #1 is the owed shelter-confirmation probe's reservation
        // (sweep_probes_locked's Idle+confirmation_due branch) - the precise, deterministic
        // target for this fix.
        ctl.reserve_probe_fail_hook = [&](std::wstring_view) {
            if (reserve_hook_calls.fetch_add(1, std::memory_order_acq_rel) == 1)
                throw std::runtime_error("injected confirmation-probe reservation failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(target.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    // Falsifier: before the fix, sweep_probes_locked's Idle case cleared confirmation_due
    // BEFORE attempting the reservation - a throw there permanently lost the owed
    // confirmation (no future trigger, since a STABLE shelter never re-arms it). After the
    // fix, confirmation_due survives the failed attempt and the very next Idle sweep retries
    // it, so probe_launched eventually reaches 2 (initial + the confirmation, once retried)
    // despite exactly one injected failure in between.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched >= 2;
        },
        5000ms));
    CHECK(reserve_hook_calls.load(std::memory_order_acquire) >= 2); // the hook fired at least
                                                                    // twice: the injected
                                                                    // failure + a real retry
    mech->stop();
}

TEST_CASE("File mechanism (direct): an allocation failure inside attach_ancestor_locked's own "
          "early work (fold_ci) does not strand the watch Idle-with-nothing-owed "
          "(#2012/#3840 PR-B2 review, round-3 table opine)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("commit_attach_fail_root");
    const auto target = root.dir / "never_appears" / "deep.txt"; // resolves Ancestor-mode
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> fail_once{true};
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 40ms;
        ctl.sweep_cadence = 20ms;
        ctl.commit_attach_fail_hook = [&](std::wstring_view) {
            if (fail_once.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error("injected attach_ancestor_locked allocation failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    const auto spec = file_spec(target.string());
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());

    // Falsifier: before the fix, w.probe/w.call were already reset to Idle/empty before
    // attach_ancestor_locked ran - a throw inside it (fold_ci's own allocation) left the
    // watch looking fully at rest, with no Deferred retry and no owner for establishment,
    // permanently. After the fix, the throw is caught and routed through
    // fail_backend_locked/defer_backend_retry_locked exactly like a genuine OS-call failure,
    // so establishment keeps a scheduled retry and eventually succeeds (shelters under root).
    CHECK_FALSE(fail_once.load(std::memory_order_acquire)); // never even reached the assertion
                                                             // below if the hook never fired -
                                                             // this proves it did
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_backend_failed >= 1 && d->live_ancestors == 1;
        },
        5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): an ordinary Emit notice left Outcome::Unattempted by a "
          "same-pass run_off_lock failure is not silently lost "
          "(#2012/#3840 PR-B2 review round-3 closure pass — replaces a false-green predecessor "
          "that never actually proved the coincidence it claimed to test)",
          "[spark][mechanism][windows][walkoff]") {
    // The predecessor version of this test raced a real file write against a SEPARATE watch's
    // exponentially-backing-off Deferred retry, asserting only eventual delivery - which passes
    // whether or not the throw ever actually landed on the write's own staging pass (its own
    // comment said as much: "Either way, B eventually receives its notice"). Astra's round-3
    // opine caught this: the test can pass without exercising its advertised failure window.
    //
    // A genuinely race-free version turns out to need the SAME watch to supply both the notice
    // AND the probe launch emit_bookkeeping_hook's precondition requires ("staged at least one
    // probe launch") - a SEPARATE watch's due-timer cannot be made to coincide deterministically:
    // wait_timeout_locked schedules run()'s own proactive wake for the EXACT instant any
    // obligation becomes due, so "due but not yet swept" is not a window a test can reliably
    // land in (confirmed empirically: a bounded retry-loop version of this test, giving a second
    // watch a fresh near-immediate retry each attempt, still failed to coincide in 25 attempts on
    // real hardware). This version instead forces B's OWN reissue to fail (real_rearm_fail_hook,
    // no genuine OS-level failure needed) right after its real write has already staged the
    // ordinary notice - deterministic, same pass, by construction, not a race.
    //
    // Note on coverage: B's own reissue-fail ALSO independently sets needs_resync=true as part of
    // its ordinary gap-2 (loss of target coverage) handling - this test therefore exercises the
    // SCENARIO (an Unattempted ordinary notice does not end up silently, permanently lost) with
    // two cooperating recovery mechanisms in play, not a strict isolation of only the
    // restore_unattempted_notices_locked fallback below. That fallback is still a real, necessary
    // fix in its own right: it is the ONLY thing that saves an Unattempted ordinary notice in the
    // narrower case where nothing else already set needs_resync for the same watch (e.g. a
    // transient allocation failure hitting emit_bookkeeping_hook on an otherwise fully healthy
    // pass with no reissue failure at all) - see restore_unattempted_notices_locked's own doc
    // comment for the gap this closes (matching reconcile_notice_outcomes_locked's existing
    // Failed-ordinary-Emit handling, which Unattempted lacked entirely before this fix).
    ScratchDir b("unattempted2_b");
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> rearm_armed{false};
    std::atomic<int> rearm_hits{0};
    std::atomic<bool> hook_armed{false};
    std::atomic<int> hook_hits{0};
    std::atomic<int> b_delivered{0};
    const std::wstring b_dir_w = b.dir.wstring();
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 20ms;
        ctl.sweep_cadence = 10ms;
        ctl.real_rearm_fail_hook = [&](std::wstring_view dir) {
            if (dir == b_dir_w && rearm_armed.exchange(false, std::memory_order_acq_rel)) {
                rearm_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.emit_bookkeeping_hook = [&] {
            hook_hits.fetch_add(1, std::memory_order_acq_rel);
            if (hook_armed.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error("injected run_off_lock failure before notice dispatch");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == "B")
                b_delivered.fetch_add(1, std::memory_order_acq_rel);
        },
        [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("B", file_spec(b.file.string()).params).has_value());
    std::this_thread::sleep_for(150ms); // let B fully establish

    rearm_armed.store(true, std::memory_order_release);
    hook_armed.store(true, std::memory_order_release);
    b.write("change"); // stage_fire_locked stages B's ordinary notice; the forced reissue
                       // failure (same pass) stages a probe launch, which fires
                       // emit_bookkeeping_hook before the notices loop ever runs

    CHECK(eventually([&] { return rearm_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually([&] { return hook_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK_FALSE(hook_armed.load(std::memory_order_acquire)); // the throw actually fired
    // Falsifier: B's write happens exactly once - without SOME recovery path (gap-2's own
    // reissue-fail handling, and/or restore_unattempted_notices_locked's Unattempted fallback),
    // delivered can never reach 1.
    CHECK(eventually([&] { return b_delivered.load(std::memory_order_acquire) >= 1; }, 5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a throw inside reresolve_absent_locked after a successful "
          "ancestor rearm still latches every dependent's reappearance, via the allocation-free "
          "fallback (#2012/#3840 PR-B2 review finding 8, incompleteness note)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("reappear_throw_root");
    const auto anc = root.dir / "anc";
    std::filesystem::create_directories(anc);
    const auto dep = anc / "child" / "target.txt"; // never created — shelters under anc
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::atomic<bool> armed{false}; // only after the initial establishment + owed shelter
                                    // confirmation have already happened, so the hook cannot
                                    // accidentally fail either of THOSE reservations instead
    std::atomic<bool> fail_once{true};
    {
        // No dedicated hook exists for reresolve_absent_locked's own internal allocation (its
        // candidates-vector reserve, or stage_probe_locked's own throw) - route through
        // reserve_probe_fail_hook_, armed only once the dependent has a STABLE shelter, so the
        // only reservation left for this directory is the reappearance-triggered one (the
        // ancestor's OWN fire), not the dependent's initial establishment or its one owed
        // confirmation probe.
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 20ms;
        ctl.reserve_probe_fail_hook = [&](std::wstring_view dir) {
            if (armed.load(std::memory_order_acquire) && dir == dep.parent_path().wstring() &&
                fail_once.exchange(false, std::memory_order_acq_rel))
                throw std::runtime_error("injected reresolve_absent_locked reservation failure");
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    const auto spec = file_spec(dep.string());
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch(spark_key(spec), spec.params).has_value());
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors == 1;
        },
        3000ms)); // sheltered under anc
    // Matches the STABLE-shelter test's own reasoning: initial probe (#1, resolves Ancestor)
    // plus the one owed confirmation probe (#2) are both deterministically done by here.
    REQUIRE(eventually(
        [&] { return file_debug_counters_for_test(*mech)->probe_launched >= 2; }, 3000ms));
    std::this_thread::sleep_for(200ms); // let the confirmation probe's own commit fully settle
    armed.store(true, std::memory_order_release);

    const auto p0 = file_debug_counters_for_test(*mech)->probe_launched;
    // Fire the ancestor's own read (bWatchSubtree=FALSE, so only a DIRECT child of anc
    // triggers this) - route_noop_rearm succeeds (io_pending becomes true), then
    // reresolve_absent_locked runs and, per the hook above, throws once.
    { std::ofstream(anc / "trigger.txt") << "x"; }

    // Falsifier: before this fix, a throw here escaped process_completion_locked entirely with
    // io_pending already true - unwind_pass_locked's consumed-completion guard requires
    // !io_pending, so it could not help, and the dependent's reappearance signal was silently
    // lost with no future trigger. After the fix, the local try/catch around
    // reresolve_absent_locked falls back to mark_reappearance_locked, which marks the
    // dependent confirmation_due - picked up by the next Idle sweep, launching a fresh probe.
    CHECK(eventually(
        [&] { return file_debug_counters_for_test(*mech)->probe_launched >= p0 + 1; }, 5000ms));
    CHECK_FALSE(fail_once.load(std::memory_order_acquire)); // the hook did fire
    mech->stop();
}

TEST_CASE("File mechanism (direct): a real-directory completion's !ok branch recovers via "
          "defer_backend_retry_locked when stage_probe_locked's own allocation throws "
          "(#2012/#3840 PR-B2 review round-3 closure pass, process_completion_locked !ok "
          "non-ancestor local catch)",
          "[spark][mechanism][windows][walkoff]") {
    // Deterministic trigger for BOTH conditions this catch needs: notify_fail_hook forces the
    // watch's own real completion to be treated as a backend failure (!ok) without a genuine
    // OS-level failure; reserve_probe_fail_hook (existing seam) forces the resulting
    // stage_probe_locked() call to throw. Falsifier: before this fix, w.handle was already reset
    // by the !ok branch before stage_probe_locked ran - an uncaught throw there left the watch
    // Idle with no probe, no confirmation, no grace check, permanently deaf while its own
    // needs_resync one-shot falsely reported coverage restored.
    ScratchDir root("handleloss_realdir");
    const auto target = root.dir / "t.txt";
    { std::ofstream(target) << "seed"; }
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const std::wstring target_dir_w = root.dir.wstring();
    std::atomic<bool> notify_armed{false};
    std::atomic<int> notify_hits{0};
    std::atomic<bool> reserve_armed{false};
    std::atomic<int> reserve_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 20ms;
        ctl.sweep_cadence = 10ms;
        ctl.notify_fail_hook = [&](std::wstring_view dir) {
            if (dir == target_dir_w && notify_armed.exchange(false, std::memory_order_acq_rel)) {
                notify_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.reserve_probe_fail_hook = [&](std::wstring_view dir) {
            if (dir == target_dir_w && reserve_armed.exchange(false, std::memory_order_acq_rel)) {
                reserve_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected stage_probe_locked allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> delivered{0};
    mech->start([&](const std::string&, SparkData) { delivered.fetch_add(1); },
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("k", file_spec(target.string()).params).has_value());
    std::this_thread::sleep_for(150ms); // let establishment settle

    notify_armed.store(true, std::memory_order_release);
    reserve_armed.store(true, std::memory_order_release);
    { std::ofstream(target, std::ios::app) << "x"; } // real completion — overridden to !ok

    CHECK(eventually([&] { return notify_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually([&] { return reserve_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_backend_failed >= 1;
        },
        3000ms)); // defer_backend_retry_locked ran — the catch's fallback, not a std::terminate
                  // or a permanently-stranded watch
    // Recovery: the fail-once hooks are spent, so the NEXT retry establishes normally and further
    // real writes are delivered — no external rescue beyond the scheduled retry itself.
    { std::ofstream(target, std::ios::app) << "y"; }
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= 1; }, 5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a real-directory reissue failure recovers via "
          "defer_backend_retry_locked when the resulting stage_probe_locked's own allocation "
          "throws (#2012/#3840 PR-B2 review round-3 closure pass, process_completion_locked "
          "reissue-fail local catch)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("handleloss_reissue");
    const auto target = root.dir / "t.txt";
    { std::ofstream(target) << "seed"; }
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const std::wstring target_dir_w = root.dir.wstring();
    std::atomic<bool> rearm_armed{false};
    std::atomic<int> rearm_hits{0};
    std::atomic<bool> reserve_armed{false};
    std::atomic<int> reserve_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.backend_retry_base = 20ms;
        ctl.sweep_cadence = 10ms;
        ctl.real_rearm_fail_hook = [&](std::wstring_view dir) {
            if (dir == target_dir_w && rearm_armed.exchange(false, std::memory_order_acq_rel)) {
                rearm_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.reserve_probe_fail_hook = [&](std::wstring_view dir) {
            if (dir == target_dir_w && reserve_armed.exchange(false, std::memory_order_acq_rel)) {
                reserve_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected stage_probe_locked allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    std::atomic<int> delivered{0};
    mech->start([&](const std::string&, SparkData) { delivered.fetch_add(1); },
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("k", file_spec(target.string()).params).has_value());
    std::this_thread::sleep_for(150ms);

    rearm_armed.store(true, std::memory_order_release);
    reserve_armed.store(true, std::memory_order_release);
    { std::ofstream(target, std::ios::app) << "x"; } // real completion — its own reissue is
                                                     // forced to fail, then that failure's
                                                     // stage_probe_locked is forced to throw

    CHECK(eventually([&] { return rearm_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually([&] { return reserve_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_backend_failed >= 1;
        },
        3000ms));
    { std::ofstream(target, std::ios::app) << "y"; }
    CHECK(eventually([&] { return delivered.load(std::memory_order_acquire) >= 1; }, 5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): an ancestor's !ok completion recovers via "
          "dead_pending_invalidate when invalidate_ancestor_locked's own allocation throws, "
          "with MULTIPLE dependents all preserved (#2012/#3840 PR-B2 review round-3 closure "
          "pass, process_completion_locked !ok ancestor local catch)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("handleloss_anc_ok");
    const auto anc = root.dir / "anc";
    std::filesystem::create_directories(anc);
    const auto dep1 = anc / "child1" / "t1.txt"; // never created — shelters under anc
    const auto dep2 = anc / "child2" / "t2.txt"; // never created — same ancestor
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const std::wstring anc_dir_w = anc.wstring();
    std::atomic<bool> notify_armed{false};
    std::atomic<int> notify_hits{0};
    std::atomic<bool> invalidate_armed{false};
    std::atomic<int> invalidate_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 10ms;
        ctl.notify_fail_hook = [&](std::wstring_view dir) {
            if (dir == anc_dir_w && notify_armed.exchange(false, std::memory_order_acq_rel)) {
                notify_hits.fetch_add(1, std::memory_order_acq_rel);
                return true;
            }
            return false;
        };
        ctl.ancestor_invalidate_fail_hook = [&](std::wstring_view dir) {
            if (dir == anc_dir_w && invalidate_armed.exchange(false, std::memory_order_acq_rel)) {
                invalidate_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected invalidate_ancestor_locked allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("d1", file_spec(dep1.string()).params).has_value());
    REQUIRE(mech->watch("d2", file_spec(dep2.string()).params).has_value());
    REQUIRE(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors == 1; // both share ONE ancestor slot
        },
        3000ms));
    std::this_thread::sleep_for(100ms); // let both dependents' shelter settle fully

    notify_armed.store(true, std::memory_order_release);
    invalidate_armed.store(true, std::memory_order_release);
    { std::ofstream(anc / "unrelated.txt") << "x"; } // real completion on the ancestor's own
                                                     // read — overridden to !ok

    CHECK(eventually([&] { return notify_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually([&] { return invalidate_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    // No crash, no UAF (ASan/general test-suite stability is part of what this proves), and both
    // dependents eventually recover WITHOUT another externally-injected event: the marker gets
    // swept, a fresh ancestor gets created, and both dependents' shelter/probe machinery resumes.
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched >= 2; // both dependents got a fresh probe
        },
        5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): an ancestor's failed rearm recovers via "
          "dead_pending_invalidate when invalidate_ancestor_locked's own allocation throws, "
          "with MULTIPLE dependents all preserved and the shared-slot amplifier closed "
          "(#2012/#3840 PR-B2 review round-3 closure pass, process_completion_locked "
          "failed-rearm local catch)",
          "[spark][mechanism][windows][walkoff]") {
    ScratchDir root("handleloss_anc_rearm");
    const auto anc = root.dir / "anc";
    std::filesystem::create_directories(anc);
    const auto dep1 = anc / "child1" / "t1.txt";
    const auto dep2 = anc / "child2" / "t2.txt";
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    const std::wstring anc_dir_w = anc.wstring();
    std::atomic<bool> rearm_armed{false};
    std::atomic<int> rearm_hits{0};
    std::atomic<bool> invalidate_armed{false};
    std::atomic<int> invalidate_hits{0};
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = 10ms;
        ctl.ancestor_rearm_fail_hook = [&](std::wstring_view dir) { return dir == anc_dir_w; };
        ctl.ancestor_invalidate_fail_hook = [&](std::wstring_view dir) {
            if (dir == anc_dir_w && invalidate_armed.exchange(false, std::memory_order_acq_rel)) {
                invalidate_hits.fetch_add(1, std::memory_order_acq_rel);
                throw std::runtime_error("injected invalidate_ancestor_locked allocation failure");
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }
    mech->start([](const std::string&, SparkData) {},
                [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("d1", file_spec(dep1.string()).params).has_value());
    REQUIRE(mech->watch("d2", file_spec(dep2.string()).params).has_value());
    REQUIRE(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->live_ancestors == 1;
        },
        3000ms));
    std::this_thread::sleep_for(100ms);

    invalidate_armed.store(true, std::memory_order_release);
    { std::ofstream(anc / "unrelated.txt") << "x"; } // real completion; rearm is forced to fail
                                                     // unconditionally (ancestor_rearm_fail_hook
                                                     // has no fire-once guard, matching the
                                                     // existing precedent test's usage), landing
                                                     // in the failed-rearm catch

    CHECK(eventually([&] { return invalidate_hits.load(std::memory_order_acquire) >= 1; }, 3000ms));
    CHECK(eventually(
        [&] {
            auto d = file_debug_counters_for_test(*mech);
            return d.has_value() && d->probe_launched >= 2;
        },
        5000ms));
    mech->stop();
}

TEST_CASE("File mechanism (direct): a key joining a directory mid-resync-dispatch gets its own "
          "settlement, not lost or perpetually re-triggered (#2012/#3840 PR-B2 review round-3 "
          "closure pass, membership-join-during-resync-dispatch fix)",
          "[spark][mechanism][windows][walkoff]") {
    // Deterministic construction, no timing race: `emit_` (called off-lock, no mu_ held) blocks
    // on kA's first delivery — which is its reappearance-triggered resync notice, the same proven
    // trigger the criterion #11 test above uses (create the previously-absent shared directory ->
    // reresolve_absent_locked -> attach commit sets needs_resync -> next sweep stages the resync,
    // setting resync_dispatch_in_flight) — giving the test a real, held-open window in which
    // resync_dispatch_in_flight is DEFINITELY true to join kB onto the same directory, rather
    // than hoping a throwing hook happens to coincide with one.
    ScratchDir root("join_midflight");
    const auto shared_dir = root.dir / "shared"; // absent until triggered below
    const auto file_a = shared_dir / "a.txt";
    const auto file_b = shared_dir / "b.txt";
    auto mech = make_file_mechanism();
    REQUIRE(mech != nullptr);
    std::mutex block_mu;
    std::condition_variable block_cv;
    bool release_a{false};
    std::atomic<bool> a_blocked{false};
    std::atomic<bool> a_block_armed{true}; // only kA's very first delivery blocks
    std::atomic<int> delivered_a{0}, delivered_b{0};
    mech->start(
        [&](const std::string& key, SparkData) {
            if (key == "kA") {
                if (a_block_armed.exchange(false, std::memory_order_acq_rel)) {
                    std::unique_lock lk(block_mu);
                    a_blocked.store(true, std::memory_order_release);
                    block_cv.wait(lk, [&] { return release_a; });
                }
                delivered_a.fetch_add(1, std::memory_order_acq_rel);
            } else if (key == "kB") {
                delivered_b.fetch_add(1, std::memory_order_acq_rel);
            }
        },
        [](const std::string&, bool, std::string_view) {});
    REQUIRE(mech->watch("kA", file_spec(file_a.string()).params).has_value()); // creates the
                                                                               // shared DirWatch,
                                                                               // absent, sheltered
    std::this_thread::sleep_for(300ms); // let it settle, sheltered under root

    std::filesystem::create_directories(shared_dir); // reappearance trigger — eventually lands
                                                      // kA blocked inside emit_, mid-dispatch

    // RAII: if anything below throws (e.g. this REQUIRE) or the test otherwise unwinds early,
    // release the blocked emit_ call regardless — without this, ~WindowsFileMechanism's stop()
    // would join a worker thread parked in an unbounded condition_variable::wait, hanging the
    // whole test binary instead of failing red (Kimi's closure-pass review, non-blocking finding
    // b).
    struct ReleaseOnExit {
        std::mutex& mu;
        std::condition_variable& cv;
        bool& flag;
        ~ReleaseOnExit() {
            {
                std::lock_guard lk(mu);
                flag = true;
            }
            cv.notify_all();
        }
    } release_guard{block_mu, block_cv, release_a};

    REQUIRE(eventually([&] { return a_blocked.load(std::memory_order_acquire); }, 5000ms));
    // kA's resync dispatch is now genuinely held open off-lock, no mu_ — join kB onto the SAME
    // now-live directory while it is still outstanding.
    REQUIRE(mech->watch("kB", file_spec(file_b.string()).params).has_value());

    { // let kA's blocked delivery proceed
        std::lock_guard lk(block_mu);
        release_a = true;
    }
    block_cv.notify_all();

    // Falsifier: before the fix, kB rode along on the in-flight batch's stale w.keys snapshot
    // (built before it joined) and could settle with no obligation of its own if that batch's
    // outcome landed Submitted - a join in this exact window silently lost coverage. After the
    // fix, kB gets its own fresh epoch (its resync eventually delivers too), and once BOTH keys
    // are healthy and settled there is no unbounded re-trigger loop for an ordinary join.
    CHECK(eventually([&] { return delivered_a.load(std::memory_order_acquire) >= 1; }, 5000ms));
    CHECK(eventually([&] { return delivered_b.load(std::memory_order_acquire) >= 1; }, 5000ms));
    const auto emits_at_settle = [&] {
        auto d = file_debug_counters_for_test(*mech);
        REQUIRE(d.has_value());
        return d->synthetic_fires;
    };
    std::this_thread::sleep_for(300ms); // let any further legitimate settlement resync finish
    const auto settled = emits_at_settle();
    std::this_thread::sleep_for(400ms); // long enough to catch an unbounded re-trigger loop
    CHECK(emits_at_settle() == settled); // settlement is stable — no perpetual re-fire
    mech->stop();
}

#endif // _WIN32
