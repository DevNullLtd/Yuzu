/**
 * test_spark_alloc_budget.cpp — #2270: the post-commit window allocates NOTHING.
 *
 * WHY THIS IS A SEPARATE EXECUTABLE. It replaces the global operator new/delete
 * to count allocations. That is process-wide and cannot be scoped to one test,
 * so it does not belong in the 1500-case agent binary, and it must be ABSENT
 * (not merely inert) from sanitizer builds, which own the allocator themselves.
 * meson builds this target only for `b_sanitize=none` on Linux.
 *
 * WHAT IT BUYS OVER THE FAULT SEAMS. test_spark_mechanism.cpp pins the OUTCOME
 * (no ghost when something throws in the window). It cannot pin the PREMISE —
 * that nothing in the window allocates in the first place — because a green run
 * proves nothing about a statement that only fails under memory pressure. That
 * gap is exactly how #2270 survived three review rounds: the round-3 fix deleted
 * the post-commit rollback on the stated grounds that only the log line could
 * still allocate there, and that claim was false and untested. These cases turn
 * the allocation census into an assertion that runs in CI.
 *
 * MUTATION EVIDENCE, THE CENSUS'S OWN LIMIT (#4665): hoisting
 * `log_key_token(key)` to a local declared ABOVE the `try` (so it allocates
 * before entering the block the site comments call "contained") leaves every
 * CHECK below unchanged - the count only sees allocations IN the window, not
 * whether the allocating expression sits lexically inside the try. Containment
 * of that fold (a throw from it costs nothing worse than the throws already
 * handled at each site) is therefore review territory, the same limit the log
 * call itself always had under QuietLog: this file was never able to prove
 * WHERE inside the window an allocation happens, only THAT one does. Not
 * closed here with a throwing-allocator seam - stated plainly instead.
 *
 * PORTABILITY, STATED PLAINLY. Executable-side replacement of operator new
 * interposes for libyuzu_agent_core.so on this ELF/libstdc++ build — MEASURED,
 * after an earlier review round asserted it could not. That is not a portable
 * contract: ELF preemption depends on visibility, direct binding and LTO;
 * Mach-O and the Windows CRT resolve allocation differently; and the exact
 * counts depend on this standard library's SSO threshold. So this is LINUX
 * MUTATION EVIDENCE, not the cross-platform pin — that stays with the fault
 * seams and the state assertions in test_spark_mechanism.cpp.
 */

#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <mutex>
#include <new>
#include <set>
#include <string>

// ── the counter ──────────────────────────────────────────────────────────────
//
// thread_local and constant-initialised: no static-init ordering, no recursion,
// and the wheel/mechanism threads allocating concurrently cannot perturb a
// measurement taken on the arming thread (which is what every case here does).
namespace {
thread_local std::uint64_t g_allocs = 0;
thread_local bool g_counting = false;

/// Count allocations on THIS thread for the lifetime of the guard.
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
    const std::size_t want = (n == 0 ? 1 : n); // zero-size must still yield a distinct pointer
    if (align > alignof(std::max_align_t)) {
        // Round UP to a multiple of align, as aligned_alloc requires — but the naive
        // (want + align - 1) / align * align WRAPS for huge want. Measured: want =
        // SIZE_MAX - 5 with align 64 rounds to 0, and glibc's aligned_alloc(64, 0)
        // returns a NON-NULL pointer, so operator new would hand back a 64-byte block
        // for an ~18-exabyte request and the caller would write far past it
        // (governance round 4, cs-1). Refuse the request instead; the caller's
        // new_handler loop then throws bad_alloc, which is the correct outcome.
        if (want > SIZE_MAX - (align - 1))
            return nullptr;
        return std::aligned_alloc(align, (want + align - 1) / align * align);
    }
    return std::malloc(want);
}

/// malloc-or-new_handler loop, per [new.delete.single].
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

/// The nothrow forms must still run an installed new_handler — [new.delete.single]
/// specifies them as calling the throwing form and converting bad_alloc to nullptr,
/// not as skipping the handler. Calling tally_and_alloc directly (as an earlier
/// revision did) silently bypassed it (governance round 4, cs-1).
void* alloc_nothrow(std::size_t n, std::size_t align) noexcept {
    try {
        return alloc_or_throw(n, align);
    } catch (...) {
        return nullptr;
    }
}
} // namespace

// Every replaceable form, so no allocation escapes the count and every
// deallocation is matched to std::free (aligned_alloc/malloc both free()).
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

// ── fixtures ─────────────────────────────────────────────────────────────────

using namespace yuzu::agent;

namespace {

/// Deliberately long: a key must exceed this standard library's SSO threshold,
/// or the very copies these cases measure would be free and the pin inert.
const std::string kPath = "/var/lib/yuzu/spark-alloc-budget/a-deliberately-long-watch-path";
const std::string kKey = "file|10:" + kPath;

SparkSpec long_file_spec() { return SparkSpec{SparkType::File, FileSparkParams{kPath}}; }

/// Minimal mechanism. Its failure text is short ON PURPOSE — SSO, so returning
/// it allocates nothing and the counts below are the ENGINE's, not the fake's.
class CountingMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        std::lock_guard lk(mu_);
        ++watch_calls_;
        if (fail_)
            return std::unexpected("nope"); // SSO: no allocation
        // The success-path budget case counts the ENGINE, so the mechanism must not
        // allocate on success either - watched_.insert(key) is a set node plus a copy
        // of an over-SSO key, which would land inside the counted window and read as
        // engine cost.
        if (record_)
            watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        ++unwatch_calls_;
        watched_.erase(key);
    }
    void stop() override {}
    void set_fail(bool b) {
        std::lock_guard lk(mu_);
        fail_ = b;
    }
    /// Off = watch() succeeds without touching watched_, so a counted window sees only
    /// the engine's own allocations. is_watching() is then meaningless; no budget case
    /// uses it.
    void set_record(bool b) {
        std::lock_guard lk(mu_);
        record_ = b;
    }
    int watch_calls() {
        std::lock_guard lk(mu_);
        return watch_calls_;
    }

private:
    std::mutex mu_;
    SparkEmitFn emit_;
    std::set<std::string> watched_;
    bool fail_{false};
    bool record_{true};
    int watch_calls_{0};
    int unwatch_calls_{0};
};

CountingMechanism* wire(SparkEngine& engine) {
    auto m = std::make_unique<CountingMechanism>();
    CountingMechanism* raw = m.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(m)).has_value());
    return raw;
}

/// spdlog formats into heap buffers, and every logging statement in the measured
/// window is deliberately contained rather than removed (losing a log line beats
/// unwinding a live arm). Silence the logger for the measurement so the counts
/// describe the engine's own bookkeeping and do not drift with spdlog's internals.
class QuietLog {
public:
    QuietLog() : prev_(spdlog::get_level()) { spdlog::set_level(spdlog::level::off); }
    ~QuietLog() { spdlog::set_level(prev_); }
    QuietLog(const QuietLog&) = delete;
    QuietLog& operator=(const QuietLog&) = delete;

private:
    spdlog::level::level_enum prev_;
};

/// Warm the malloc arena with arm/disarm churn before a measurement, so first-touch
/// arena growth cannot land inside a counted window and read as an engine allocation.
/// NOT a bucket/rehash warm-up: `sub_keys_` is a std::map (a red-black tree), so it
/// has no bucket array and never rehashes — it allocates exactly one node per insert.
/// An earlier version of this comment claimed otherwise (governance round 4, sec-3).
void warm_arena(SparkEngine& engine, SparkEngine::ConsumerId c) {
    std::vector<SparkEngine::SubscriptionId> ids;
    for (int i = 0; i < 128; ++i) {
        auto s = engine.arm(c, SparkSpec{SparkType::Interval,
                                         IntervalSparkParams{static_cast<std::uint64_t>(1000 + i)}});
        REQUIRE(s.has_value());
        ids.push_back(*s);
    }
    for (auto id : ids)
        engine.disarm(id);
}

} // namespace

TEST_CASE("the interposer actually reaches the engine's allocations", "[spark][alloc]") {
    // Guards against the whole file silently becoming a no-op: if a future
    // toolchain change stops the executable-side replacement from preempting
    // libyuzu_agent_core.so, every budget below would pass at zero and prove
    // nothing. An arm of a FRESH key must allocate (map nodes, at minimum).
    SparkEngine engine;
    wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    QuietLog quiet;

    std::uint64_t n = 0;
    {
        AllocCount counting;
        (void)engine.arm(*c, long_file_spec());
        n = counting.count();
    }
    CHECK(n > 0);
    engine.stop();
}

TEST_CASE("arm_impl: the failed-watch path allocates nothing after the commit (#2270)",
          "[spark][alloc]") {
    // The window round 3 got wrong. Counting is armed from the phase-1 fault seam,
    // which fires immediately BEFORE sub_keys_.emplace, and stops when arm() returns
    // — so the window is that emplace plus everything after it: the publish, the
    // contained "armed" log (which itself allocates once, post-#4665 — see the
    // budget breakdown below), the mechanism's return, the defensive unwatch() +
    // Lost-notification snapshot/delivery (#2818), drop_key_locked, the error
    // completion, and the return itself. (An earlier version of this comment said
    // counting started inside the mechanism's watch(); it does not, and the sibling
    // comment below always had it right — governance round 4, sec-2.)
    //
    // MUTATION EVIDENCE: restoring the pre-fix concat
    //   std::string("watch mechanism failed to arm '") + key + "': " + w.error()
    // takes this budget from 2 to 5 (measured). An earlier version of this line said
    // "3, not 0", which was left over from a draft that measured a different window
    // and contradicted the assertion 20 lines below it (Gate 8 - CA8-4).
    SparkEngine engine;
    CountingMechanism* mech = wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_arena(engine, *c);
    QuietLog quiet;

    mech->set_fail(true);
    bool armed_counter = false;
    engine.set_arm_fault_hook_for_test([&](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys) {
            g_allocs = 0;
            g_counting = true;
            armed_counter = true;
        }
    });
    auto sub = engine.arm(*c, long_file_spec());
    g_counting = false;
    const std::uint64_t post_commit = g_allocs;
    engine.set_arm_fault_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    REQUIRE(armed_counter);
    REQUIRE(mech->watch_calls() == 1);
    CHECK_FALSE(sub.error().empty()); // the error still arrives, from the bounded buffer
    // Budget: the sub_keys_ emplace costs TWO — the map node, plus a heap buffer for
    // the key, which is longer than this standard library's SSO threshold (measured
    // directly: the same emplace with a short key costs 1, which is also why kPath is
    // deliberately long — a short key would hide a regression inside the SSO buffer).
    //
    // #2818 raised this from 2 to 6 (measured): the failure path now snapshots the
    // one live subscriber and delivers a Lost notification before drop_key_locked
    // runs. Four new allocations, each an over-SSO `key` copy or the vector this
    // engine has exactly one subscriber to hold: the vector<Subscriber> snapshot
    // itself (1), the Lost SparkEvent's own `key` copy (1), deliver()'s per-recipient
    // `stamped = ev` copy's `key` (1), and the consumer queue's `push_back(out)`
    // copy's `key` (1). `detail` (the mechanism's short "nope" error) stays within
    // SSO throughout and contributes nothing. The defensive `mech->unwatch(key)` this
    // fix also adds contributes nothing here — CountingMechanism's unwatch() only
    // locks + erases from an empty set (`record_` is off in this test).
    //
    // #4665 raised this from 6 to 7: the contained "armed" log fires on THIS path
    // too — insertion always logs "armed" before the watch is even attempted, so
    // the later watch failure doesn't skip it — and it pays the same
    // log_key_token(key) fold cost as the fresh-SUCCESS-path test below. See that
    // test's comment for exactly why it's one allocation here, not two.
    CHECK(post_commit == 7);
    CHECK(engine.stats().armed_sparks == 0);
    engine.stop();
}

TEST_CASE("arm_impl: the deduped commit publishes without allocating (#2270 reserve pin)",
          "[spark][alloc]") {
    // The load-bearing, previously UNPINNED reserve() at the dedup branch. Counting
    // is armed from the phase-1 fault hook, which fires immediately before the last
    // in-lock allocating step, so the budget is the sub_keys_ emplace and nothing
    // else: TWO allocations, the map node plus the heap buffer for the over-SSO key
    // (measured; the same emplace with a short key costs 1). The publishing
    // push_back must contribute nothing — it writes into capacity reserve() took
    // BEFORE the commit.
    //
    // MUTATION EVIDENCE: deleting `existing->subs.reserve(existing->subs.size() + 1)`
    // makes this 3 — the push_back reallocates the vector AFTER the commit, which is
    // precisely the throw site the reserve exists to move out of the window. Deleting
    // it leaves every other test in the repo green (measured); this is the only case
    // that fails.
    SparkEngine engine;
    wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_arena(engine, *c);
    QuietLog quiet;

    auto first = engine.arm(*c, long_file_spec());
    REQUIRE(first.has_value());

    std::uint64_t post_commit = 0;
    bool armed_counter = false;
    engine.set_arm_fault_hook_for_test([&](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys) {
            g_allocs = 0;
            g_counting = true;
            armed_counter = true;
        }
    });
    auto second = engine.arm(*c, long_file_spec()); // dedups onto the existing key
    g_counting = false;
    post_commit = g_allocs;
    engine.set_arm_fault_hook_for_test(nullptr);

    REQUIRE(second.has_value());
    REQUIRE(armed_counter);
    CHECK(post_commit == 2); // the sub_keys_ emplace (node + key buffer), and nothing else
    engine.stop();
}

TEST_CASE("arm_impl: the fresh SUCCESS path allocates nothing after the commit (#2270)",
          "[spark][alloc]") {
    // THE SHAPE AN ADVERSARIAL REVIEWER PROVED WAS UNPINNED. The two cases above cover
    // the failed-watch and dedup shapes; a fresh event-driven arm whose watch SUCCEEDS
    // traverses a different post-commit stretch - the publish tail, the contained
    // "armed" log (one allocation of its own, post-#4665 - see the budget comment
    // below), the mechanism's watch(), the M1 consumer re-check, and the return of
    // the id. Inserting `std::string x(key);` immediately after watch_guarded() returns
    // left the whole budget binary GREEN, because nothing counted that stretch.
    //
    // Why it is the shape most worth pinning: it is where a future author naturally
    // adds a success metric or a log helper. Under bad_alloc there, the caller gets no
    // subscription id while armed_ holds the entry and the OS watcher is live - the
    // caller-visible direction of "armed == a watcher is running".
    SparkEngine engine;
    CountingMechanism* mech = wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_arena(engine, *c);
    QuietLog quiet;

    // Success must not touch watched_, or the set node plus the over-SSO key copy land
    // inside the counted window and read as engine cost.
    mech->set_record(false);

    bool armed_counter = false;
    engine.set_arm_fault_hook_for_test([&](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys) {
            g_allocs = 0;
            g_counting = true;
            armed_counter = true;
        }
    });
    auto sub = engine.arm(*c, long_file_spec()); // fresh key, watch SUCCEEDS
    g_counting = false;
    const std::uint64_t post_commit = g_allocs;
    engine.set_arm_fault_hook_for_test(nullptr);

    REQUIRE(sub.has_value()); // the whole point: this is the SUCCESS path
    REQUIRE(armed_counter);
    REQUIRE(mech->watch_calls() == 1);
    // Same sub_keys_-emplace budget as the other two shapes (map node + heap buffer
    // for the over-SSO key), PLUS ONE new allocation from #4665: the contained
    // "armed" log now folds `key` through ::yuzu::log_key_token() before spdlog is
    // even entered (QuietLog silences spdlog's OWN formatting, never a caller
    // expression evaluated ahead of it — see this file's top-of-file "MUTATION
    // EVIDENCE, THE CENSUS'S OWN LIMIT" note).
    //
    // Exactly ONE, not two: log_key_token's fold (log_token.hpp) allocates once for
    // any key over this standard library's SSO threshold — this test's key is a
    // "file|..." prefix over kPath, ~71 bytes, always over SSO — and a SECOND time
    // only if the FOLDED result still exceeds kGuardianLogIdMaxBytes (256 bytes),
    // which forces a second heap buffer for the <head>~<tail> shortened form. This
    // key is nowhere near 256 bytes, so the fold returns its single heap buffer
    // directly (NRVO/move on return, no copy-with-reallocation — MEASURED here at
    // exactly +1, not inferred from reading log_key_token's source) and the cost
    // stops at one. The other two windowed sites (teardown_arm_race's and
    // disarm()'s own "disarmed" logs) pay the identical one-allocation cost for the
    // identical reason.
    CHECK(post_commit == 3);
    CHECK(engine.stats().armed_sparks == 1);
    engine.stop();
}

TEST_CASE("disarm: the in-lock teardown allocates nothing (#2270)", "[spark][alloc]") {
    // THE SIBLING THE FIRST FOUR CASES DID NOT COVER. arm_impl was made
    // allocation-free past its commit and given teardown_arm_race as a contained
    // twin, while disarm() - reached from Guardian's ordinary withdraw path -
    // kept copying the key, logging uncounted and copying again, and PROPAGATES
    // where the twin contains. Three governance rounds retired findings on that
    // sink because its caller had been deleted; nothing pinned the sink itself.
    //
    // What a throw in that window would cost if it escaped uncontained (it does
    // not - the log call below has its own try/catch): it would escape a void
    // function after erase_if has already emptied `subs`, leaving an armed_ entry
    // with no subscribers and a dangling sub_keys_ row - a dedup target that hands
    // the next equal-spec arm a SUCCESS with no watcher. That is why the budget
    // stays as small and as fully NAMED as possible - #4665 below is the one
    // addition, and it is accounted for, not merely tolerated.
    SparkEngine engine;
    CountingMechanism* mech = wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_arena(engine, *c);
    QuietLog quiet;

    // As in the success case: recording would put a set node and an over-SSO key
    // copy inside the counted window and read as engine cost.
    mech->set_record(false);

    auto sub = engine.arm(*c, long_file_spec()); // fresh key, over-SSO, watch succeeds
    REQUIRE(sub.has_value());
    REQUIRE(engine.stats().armed_sparks == 1);

    g_allocs = 0;
    g_counting = true;
    engine.disarm(*sub); // last subscriber -> whole-key teardown + unwatch
    g_counting = false;

    // ONE, not zero, and not an unaccounted-for small number. The key is MOVED out
    // of the sub_keys_ entry that is erased on the next line rather than copied,
    // both erases only free, and the log's OWN spdlog formatting is contained and
    // silenced by QuietLog. The single allocation that remains is
    // log_key_token(key)'s fold (#4665) at the "disarmed" log site — the same
    // one-not-two shape as the fresh-SUCCESS-path test above (over-SSO key, under
    // kGuardianLogIdMaxBytes, so the fold's NRVO'd single buffer is all it costs).
    // Mutation-check the MOVE-not-copy claim by restoring `const std::string key =
    // ki->second;` in SparkEngine::disarm - that still reddens this (2, not 1;
    // measured, not inferred).
    CHECK(g_allocs == 1);
    CHECK(engine.stats().armed_sparks == 0);
    engine.stop();
}
