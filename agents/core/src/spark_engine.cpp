/**
 * spark_engine.cpp — see spark_engine.hpp.
 *
 * Wheel design: a single timer thread scans the armed map for the earliest
 * scheduled deadline and condition-waits until it (or an arm/disarm/stop
 * nudge). Arm/disarm rates are low and armed counts are small (hundreds), so
 * the O(n) scan per wake is deliberately simpler and more robust than a heap
 * with lazy invalidation — revisit only if the resource gate says so.
 *
 * Lock discipline: per-type processing (which may do filesystem I/O for disk
 * reads) and ALL delivery run with mu_ released; state commits re-acquire mu_
 * and re-look-up by key, so a spark disarmed mid-flight is simply skipped.
 * Inline handlers therefore run on the wheel thread WITHOUT mu_ held — an
 * inline handler may safely call arm/disarm/stats.
 */

#include "spark_engine.hpp"

#include <yuzu/agent/guard_systemd.hpp> // valid_unit_name — pure, all-platform, shared with the guard
#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <iterator>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

namespace yuzu::agent {

namespace {

bool params_match_type(const SparkSpec& spec) {
    switch (spec.type) {
    case SparkType::Interval: return std::holds_alternative<IntervalSparkParams>(spec.params);
    case SparkType::Startup:  return std::holds_alternative<StartupSparkParams>(spec.params);
    case SparkType::Disk:     return std::holds_alternative<DiskSparkParams>(spec.params);
    case SparkType::File:     return std::holds_alternative<FileSparkParams>(spec.params);
    case SparkType::Service:  return std::holds_alternative<ServiceSparkParams>(spec.params);
    case SparkType::Registry: return std::holds_alternative<RegistrySparkParams>(spec.params);
    }
    return false;
}

// A message whose COMPLETION cannot allocate (#2270). Everything expensive happens
// in the constructor — which arm_impl runs BEFORE its first shared-state commit,
// where a throw is still harmless — so finish() can be noexcept:
//   * the prefix is assigned FIRST, then the buffer is pre-SIZED (not merely
//     reserved) to prefix + headroom. reserve() would be the wrong tool twice
//     over: a later assign() invalidates the reasoning, and capacity is not a
//     postcondition the standard carries across a move.
//   * finish() copies at most `headroom` bytes over elements that ALREADY EXIST
//     and then shrinks. Shrinking resize() erases in place on every implementation,
//     and its only specified Throws case (n > max_size()) is unreachable here. Note
//     that is a QoI fact, not a normative one: [string.require]/4 lists resize among
//     the reference-invalidating operations, so the standard does not FORBID a
//     reallocation on shrink — libstdc++, libc++ and MSVC STL all set the length in
//     place (cpp-expert, governance round 4).
// The suffix is therefore TRUNCATED rather than grown when it overruns the
// headroom. That is the deliberate trade: a clipped error message beats a
// std::bad_alloc thrown past a committed subscription.
constexpr std::size_t kErrHeadroom = 256;
constexpr std::string_view kWatchThrewPrefix = "watch mechanism threw: ";
constexpr std::string_view kWatchThrewNonStd = "a non-std exception";

class BoundedMsg {
public:
    BoundedMsg() = default;
    explicit BoundedMsg(std::string_view prefix, std::size_t headroom = kErrHeadroom)
        : buf_(prefix.size() + headroom, '\0'), prefix_(prefix.size()) {
        // Sized-then-filled, so this really is ONE allocation. Constructing from the
        // prefix and then resize()ing measured TWO whenever the prefix exceeded the
        // SSO threshold, which both production prefixes do.
        // Same null-data() guard as finish(): an empty string_view has a null data(),
        // and libc++ reaches __builtin_memmove(dst, nullptr, 0) where libstdc++
        // short-circuits. Unreachable today — every ctor site passes a non-empty
        // literal — but the guard belongs on both copies or on neither, and the round
        // that added it to finish() left this one exposed (Gate 8, cs8-2).
        if (!prefix.empty())
            std::copy_n(prefix.data(), prefix.size(), buf_.data());
    }
    /// NON-COPYABLE by construction: a copy would allocate prefix_ + headroom, which
    /// is precisely the cost this class exists to keep out of the post-commit window.
    /// Nothing copies one today (Replay is nothrow-move-constructible so vector growth
    /// moves), but a future throwing-move member of Replay would flip move_if_noexcept
    /// to copy silently. Same tripwire idiom as the static_asserts in the header.
    BoundedMsg(const BoundedMsg&) = delete;
    BoundedMsg& operator=(const BoundedMsg&) = delete;
    BoundedMsg(BoundedMsg&&) noexcept = default;
    BoundedMsg& operator=(BoundedMsg&&) noexcept = default;
    /// Complete the message with as much of `text` as the headroom holds, and
    /// hand it over. Allocates nothing; the returned string is moved out.
    /// [[nodiscard]] because discarding the result silently empties the buffer.
    [[nodiscard]] std::string finish(std::string_view text) noexcept {
        if (buf_.size() >= prefix_) {
            const std::size_t n = std::min(buf_.size() - prefix_, text.size());
            // Guard the zero case: an empty string_view has a null data(), and while
            // libstdc++ short-circuits copy_n on n == 0, libc++ reaches
            // __builtin_memmove(dst, nullptr, 0) which UBSan's nonnull-attribute
            // reports. macOS is the leg nobody has compiled, so take the branch.
            if (n != 0)
                std::copy_n(text.data(), n, buf_.data() + prefix_);
            buf_.resize(prefix_ + n);
        }
        return std::move(buf_);
    }

private:
    std::string buf_;
    std::size_t prefix_{0};
};

// Call a mechanism's watch() and convert an escaping throw into a returned
// std::unexpected. A mechanism MUST report failure by returning std::unexpected,
// but the real ones can throw (spark_file's watch() → fs::current_path() on a
// relative path). BOTH arm paths — the live arm_impl and the pre-start replay in
// start() — route through here so the exception boundary and its message text
// live in exactly one place and cannot drift apart (#2019 review). Each caller
// keeps its OWN failure handling: arm_impl rolls the whole key back; the replay
// faults in place (its subscribers already hold ids).
//
// #2270: error DELIVERY is non-throwing by construction. The caller passes a
// BoundedMsg built before its own commit; completing it here cannot allocate. The
// concat this used to do was the defect: it ran INSIDE the catch handler, so a
// bad_alloc there escaped watch_guarded and both its callers — past arm_impl's
// committed subscription (the ghost key), and out of the void start(). The hook
// call and the completion are contained anyway, so no exception from this block
// can reach a caller by any route.
[[nodiscard]] std::expected<void, std::string>
watch_guarded(ISparkMechanism* mech, const std::string& key, const SparkParams& params,
              SparkIncarnation incarnation, BoundedMsg& err,
              const std::function<void(int)>& fault_hook) {
    try {
        // The engine ALWAYS calls watch_incarnation() (never the plain watch()) —
        // see spark_mechanism.hpp's own doc comment on why the two are distinct
        // names rather than an overload.
        return mech->watch_incarnation(key, params, incarnation);
    } catch (const std::exception& e) {
        try {
            if (fault_hook)
                fault_hook(SparkEngine::kArmFaultPhaseWatchErrorBuild);
            return std::unexpected(err.finish(e.what()));
        } catch (...) {
            return std::unexpected(err.finish(std::string_view{}));
        }
    } catch (...) {
        try {
            if (fault_hook)
                fault_hook(SparkEngine::kArmFaultPhaseWatchErrorBuild);
            return std::unexpected(err.finish(kWatchThrewNonStd));
        } catch (...) {
            return std::unexpected(err.finish(std::string_view{}));
        }
    }
}

/// #2815: RAII lease over one pass through a post-mu_ mechanism-call window.
///
/// ARM IT AS THE LAST STATEMENT OF THE mu_ BLOCK THAT RESOLVES THE MECHANISM, and let
/// it live to the end of the enclosing FUNCTION - not merely until unwatch() returns.
/// Both halves are load-bearing:
///   * "last statement under mu_" - arming earlier is harmless, but anything after it
///     inside the lock that could throw would run this destructor while mu_ is still
///     held. The destructor takes no lock, so that is not a deadlock today; keeping the
///     arm last means it never becomes one.
///   * "to the end of the function" - the window does not close when the mechanism call
///     does. disarm()'s own catch touches disarm_unwatch_failures_ AFTER unwatch()
///     throws, and unregister_consumer() runs on into quiesce_consumer(), which reads
///     consumer_join_budget_ms_ and consumer_threads_detached_. Releasing at the
///     mechanism call would leave both of those outside the barrier.
///
/// Everything here is noexcept: this is destroyed on the door caller's thread during
/// ordinary return AND during exception unwind, and an observe-only subsystem must
/// never be the reason the agent terminates.
class TeardownLease {
public:
    explicit TeardownLease(std::atomic<std::uint64_t>& count) noexcept : count_(&count) {}
    ~TeardownLease() { release(); }
    TeardownLease(const TeardownLease&) = delete;
    TeardownLease& operator=(const TeardownLease&) = delete;

    /// Caller holds mu_.
    void arm_locked() noexcept {
        count_->fetch_add(1, std::memory_order_relaxed);
        armed_ = true;
    }

private:
    void release() noexcept {
        if (!armed_)
            return;
        armed_ = false;
        // RELEASE ordering: a waiter that observes zero via an ACQUIRE load has
        // happens-before over every engine access this caller made in the window.
        count_->fetch_sub(1, std::memory_order_acq_rel);
    }
    std::atomic<std::uint64_t>* count_;
    bool armed_{false};
};

/// Wait until no caller is inside a teardown window, or `budget` elapses.
/// Returns true if the lease drained, false on expiry. See the member's doc in
/// spark_engine.hpp for why this polls rather than waiting on a condition_variable.
bool wait_teardown_leases(const std::atomic<std::uint64_t>& count,
                          std::chrono::milliseconds budget) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    for (;;) {
        if (count.load(std::memory_order_acquire) == 0)
            return true;
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// The UNBOUNDED counterpart, for ~SparkEngine only. A caller that never returns turns
/// what used to be a silent use-after-free into a visible hang, which is the trade this
/// fix deliberately makes. Dormant in the shipped agent: main.cpp's OrphanExitGuard
/// hard_exit()s while any Guardian I/O worker is still live, long before ~Agent - so a
/// wedged worker terminates the process there, not here.
///
/// That coverage claim rests on three facts in three other files (governance Gate 6 sre
/// finding O1 — recorded here so a future change to any of them doesn't silently
/// invalidate it): (1) register_mechanism() only accepts File/Registry/Service — Interval/
/// Startup/Disk are timer-driven and never hold a raw mechanism pointer a door could
/// resolve (this function, the type-gate a few lines above register_mechanism's body);
/// (2) every production arm()/disarm() call for those three types runs inside a
/// GuardianIoExecutor worker (guardian_spark_runtime.cpp's io_executor_ routing), whose
/// active_worker_count() is exactly what OrphanExitGuard samples in main.cpp/
/// service_win.cpp — so a parked door caller stays counted for as long as it's parked;
/// (3) unregister_consumer() (door 3, the one door stop() doesn't gate via running_/
/// stopped_) has exactly one production call site, rollback_spark_wiring_locked's
/// boot-time construction-failure path (guardian_engine.cpp), reached with zero armed
/// subscriptions to unwatch. A fourth spark type, a second unregister_consumer() caller,
/// or an I/O path that bypasses GuardianIoExecutor would each need this comment
/// re-verified.
void wait_teardown_leases_forever(const std::atomic<std::uint64_t>& count) noexcept {
    while (count.load(std::memory_order_acquire) != 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

/// #2050: unconditional-fire-on-destruction guard, identical in shape to the ones in
/// agent.cpp and server/core/src/api_token_store.cpp — a third copy of this trivial
/// idiom rather than a shared header, because the type is five lines with no natural
/// shared-header home spanning agent-core and server-core. Every use across all three
/// files is a single local RAII variable, never copied or moved out of its declaring
/// scope, so there is no double-fire hazard a deleted copy/move would need to guard
/// against — that (separate) question is answered identically in the two sibling
/// files' own comments. Conditional arming (run-or-don't) is the CALLER's job — the
/// lambda handed in checks its own captured flag — not this type's.
template <typename F> struct ScopeExit {
    F fn;
    ~ScopeExit() { fn(); }
};
template <typename F> ScopeExit(F) -> ScopeExit<F>;

} // namespace

bool SparkEngine::is_event_driven(SparkType type) noexcept {
    return type == SparkType::File || type == SparkType::Service ||
           type == SparkType::Registry;
}

SparkEngine::SparkEngine() = default;

SparkEngine::~SparkEngine() {
    stop();
    // #2815: THE fix. stop()'s own wait is bounded and may have given up; nothing else
    // in this destructor may run until every caller has left a teardown window, because
    // the very next thing that happens is the destruction of the members those callers
    // still hold (mech_ops_mu_by_type_, mechanisms_, consumers_). Last statement of the
    // body on purpose - member destructors run only once this returns.
    wait_teardown_leases_forever(inflight_teardowns_);
}

// ── Mechanisms ────────────────────────────────────────────────────────────────

std::expected<void, std::string>
SparkEngine::register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism) {
    if (!mechanism)
        return std::unexpected("mechanism must not be null");
    if (!is_event_driven(type))
        return std::unexpected(std::string("spark type '") + spark_type_token(type) +
                               "' is timer-driven — the wheel services it, it has no mechanism");
    // lifecycle_mu_ before mu_ (see the header's LOCK ORDER note). This is the ONLY
    // writer of mechanisms_; holding it here is what lets stop() iterate the map
    // without mu_ even while the main thread is still registering during boot and the
    // SCM control thread calls Agent::stop() (Gate-4 UP-1).
    std::lock_guard life(lifecycle_mu_);
    std::lock_guard lk(mu_);
    if (running_ || stopped_)
        return std::unexpected("mechanisms must be registered before start()");
    // Populate the per-type mech-ops lock FIRST, then mechanisms_ — both under
    // the same mu_ so they stay in lockstep (#2011). Order matters for the
    // .at()-can't-throw invariant every call site relies on: if the second
    // try_emplace throws std::bad_alloc, the surviving state must never be
    // "mechanisms_ has the type but mech_ops_mu_by_type_ does not" (which would
    // make a later arm/disarm reach .at(type) → std::out_of_range on a live
    // path). Emplacing the lock first means a throw leaves at most an unused
    // mutex entry for a type with no mechanism — harmless, since arm() of a
    // type with no mechanism is rejected before any .at() (cpp-safety Gate 3).
    mech_ops_mu_by_type_.try_emplace(type);
    auto [it, inserted] = mechanisms_.try_emplace(type, std::move(mechanism));
    if (!inserted)
        return std::unexpected(std::string("a mechanism is already registered for spark type '") +
                               spark_type_token(type) + "'");
    return {};
}

// ── Consumers ─────────────────────────────────────────────────────────────────

std::expected<SparkEngine::ConsumerId, std::string>
SparkEngine::register_consumer(std::string name, QueuedHandler handler, std::size_t queue_cap) {
    if (!handler)
        return std::unexpected("consumer handler must not be null");
    if (name.empty())
        return std::unexpected("consumer name must not be empty");
    if (queue_cap == 0)
        return std::unexpected("consumer queue_cap must be > 0");

    ConsumerId id = 0;
    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return std::unexpected("engine is stopped");
        id = next_id_++;
    }
    auto consumer = std::make_shared<Consumer>();
    consumer->name = std::move(name);
    consumer->handler = std::move(handler);
    consumer->cap = queue_cap;
    // Capture only the two shared_ptrs, NEVER `this`: the thread may be detached
    // at shutdown (UP-1) and outlive the engine, so it must not dereference it.
    consumer->thread = std::thread(&SparkEngine::consumer_loop, consumer, delivery_);
    // Test seam: lets a test deterministically force stop() to run exactly
    // here — the un-synchronized window this function's own re-check below
    // exists to close — instead of relying on a flaky multi-threaded race.
    if (register_race_hook_for_test_)
        register_race_hook_for_test_();
    bool inserted = false;
    // Captures an emplace() throw (e.g. bad_alloc) rather than letting it
    // propagate straight out of the locked block: `consumer` going out of
    // scope with its thread still joinable would call std::terminate before
    // this function's caller ever sees the exception (Sol rung-7.5 review
    // finding 2). Quiesced + rethrown below, OUTSIDE consumers_mu_.
    std::exception_ptr emplace_exception;
    {
        std::lock_guard lk(consumers_mu_);
        // Re-check: stop() can land between the stopped_ check above and this
        // insert. stop() sets stopped_ (under mu_) and later swaps consumers_
        // out (under consumers_mu_) without ever seeing an entry inserted after
        // its swap — nobody signals the thread just started above, and the
        // un-joined joinable std::thread inside its shared_ptr<Consumer>
        // terminates the process at destruction. That breaks this header's own
        // "register safe from any thread" contract (governance Tr3kkR finding,
        // PR #1927 review).
        if (!stopped_) {
            try {
                consumers_.emplace(id, consumer);
                inserted = true;
            } catch (...) {
                emplace_exception = std::current_exception();
            }
        }
    }
    if (emplace_exception) {
        quiesce_consumer(consumer);
        std::rethrow_exception(emplace_exception);
    }
    if (!inserted) {
        // Lost the race: quiesce the just-started thread ourselves, exactly as
        // stop() would have, before reporting failure — OUTSIDE consumers_mu_.
        // quiesce_consumer's bounded join may block up to
        // consumer_join_budget_ms_; every other consumers_mu_ site (arm,
        // unregister_consumer, emit_event's dispatch, stats, and a
        // concurrently running real stop()'s own swap) must never stall
        // behind it — mirrors disarm()'s and stop()'s own "release the lock
        // before anything that may block" discipline (governance cpp-expert /
        // cpp-safety finding, PR #1927 review).
        quiesce_consumer(consumer);
        return std::unexpected("engine is stopped");
    }
    return id;
}

void SparkEngine::unregister_consumer(ConsumerId id) {
    // 1) Take the consumer out of the fan-out map FIRST, before scanning
    // armed_ for its subscriptions. LOAD-BEARING ordering for the M1
    // ghost-subscription fix (#1994): arm()'s consumer-existence pre-check
    // (consumers_mu_) and arm_impl()'s armed_ insert (mu_) are two different
    // critical sections a concurrent unregister_consumer() can land between.
    // arm_impl() closes its half of the race with a re-check AFTER the insert
    // that rolls back on a lost race (see arm_impl below) — but that re-check
    // is only airtight if THIS function's consumers_ erase always
    // happens-before its own armed_ scan. With the erase first: any insert
    // that lands before our armed_ scan is caught by the scan itself; any
    // insert that lands after our armed_ scan must also land after our erase
    // (same-thread program order), so arm_impl's re-check — which always runs
    // after its insert — observes the consumer already gone and rolls back.
    // A ghost would require our scan to miss the sub (scan-before-insert) AND
    // arm_impl's re-check to see the consumer as present (re-check-before-
    // erase) — impossible once erase precedes scan, since that would need
    // erase < scan < insert < re-check < erase (self-contradictory).
    std::shared_ptr<Consumer> consumer;
    {
        std::lock_guard lk(consumers_mu_);
        auto it = consumers_.find(id);
        if (it == consumers_.end())
            return;
        consumer = std::move(it->second);
        consumers_.erase(it);
    }

    // 2) Remove the consumer's subscriptions so no new events are enqueued.
    // Collect (mechanism, key) pairs for any watch that goes fully
    // unsubscribed as a result, so they can be unwatch()'d with mu_ released
    // below — mirrors disarm()'s pattern exactly. Erasing armed_ without this
    // leaves the mechanism's OS watch (IOCP directory registration / registry
    // TP_WAIT / SCM notification) live for a spark the engine no longer
    // considers armed: emit_event() finds no armed_ entry and drops the
    // firings, the handle accumulates until engine stop(), and
    // stats().armed_sparks undercounts what the OS is actually watching
    // (governance Tr3kkR finding, PR #1927 review).
    struct PendingUnwatch {
        ISparkMechanism* mech;
        std::string key;
        SparkType type; // picks this type's mech-ops lock at consumption
    };
    std::vector<PendingUnwatch> to_unwatch;
    // #2815 door 3/4. Armed UNCONDITIONALLY below (not only when to_unwatch is
    // non-empty): this function continues past its mechanism calls into
    // quiesce_consumer(), which reads consumer_join_budget_ms_ and writes
    // consumer_threads_detached_ - engine members, so the window this lease covers is
    // the whole function tail either way.
    TeardownLease lease(inflight_teardowns_);
    {
        std::lock_guard lk(mu_);
        for (auto it = armed_.begin(); it != armed_.end();) {
            auto& subs = it->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) {
                if (s.tier == SparkTier::Queued && s.consumer == id) {
                    sub_keys_.erase(s.id);
                    return true;
                }
                return false;
            });
            if (subs.empty()) {
                // Same running_-gated pattern as disarm(): a pre-start or
                // post-stop unregister has no watch to drop.
                if (running_ && is_event_driven(it->second.spec.type)) {
                    auto mit = mechanisms_.find(it->second.spec.type);
                    if (mit != mechanisms_.end())
                        to_unwatch.push_back({mit->second.get(), it->first, it->second.spec.type});
                }
                it = armed_.erase(it);
            } else {
                ++it;
            }
        }
        // #2815: LAST statement under mu_, and after the collection loop has finished -
        // one lease per door-call, never a token per queued item. The loop can itself
        // throw part-way (std::erase_if, the to_unwatch push_back); arming after it
        // means a partial collection unwinds with nothing to balance.
        lease.arm_locked();
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_) — mirrors disarm(). Serialized via this type's
    // mech_ops_mu_by_type_ entry with a staleness re-check immediately before
    // each call (#1994 M2): a concurrent re-arm of an equal spec may have
    // already renewed this key between our erase above and here, in which case
    // this unwatch is stale and must be skipped rather than tearing down the
    // fresh watch.
    for (auto& pu : to_unwatch) {
        // Hook fires BEFORE the mech-ops lock is taken (never while held) — see
        // disarm()'s identical placement rationale.
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(pu.type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(pu.key))
                continue; // a concurrent re-arm already renewed this key
        }
        pu.mech->unwatch(pu.key);
    }

    // 3) Bounded-join (or detach) its dispatch thread.
    quiesce_consumer(consumer);
}

void SparkEngine::signal_stop(const std::shared_ptr<Consumer>& consumer) {
    {
        std::lock_guard lk(consumer->mu);
        consumer->stopping = true;
    }
    consumer->cv.notify_all();
}

void SparkEngine::await_consumer(const std::shared_ptr<Consumer>& consumer,
                                 std::chrono::steady_clock::time_point deadline) {
    // Bound the join against a shared deadline: a queued handler is explicitly
    // permitted to block (network / plugin I/O), so a hung one must not hang
    // shutdown (UP-1 / #1311). A SHARED deadline (not a fresh per-consumer
    // budget) keeps N hung consumers to ~1×budget total, not N×budget (UP2-3).
    // On expiry DETACH — safe because the thread captured only its own
    // shared_ptr<Consumer> + shared_ptr<DeliveryCounters>, never the engine.
    bool finished = false;
    {
        std::unique_lock lk(consumer->done_mu);
        finished = consumer->done_cv.wait_until(lk, deadline, [&] { return consumer->finished; });
    }
    if (!consumer->thread.joinable())
        return;
    if (finished) {
        consumer->thread.join();
    } else {
        consumer->thread.detach();
        consumer_threads_detached_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("SparkEngine: consumer '{}' handler did not finish within budget — detached "
                     "(shutdown not blocked)",
                     consumer->name);
    }
}

void SparkEngine::quiesce_consumer(const std::shared_ptr<Consumer>& consumer) {
    signal_stop(consumer);
    await_consumer(consumer, std::chrono::steady_clock::now() + std::chrono::milliseconds(
                                 consumer_join_budget_ms_.load(std::memory_order_relaxed)));
}

void SparkEngine::consumer_loop(std::shared_ptr<Consumer> consumer,
                                std::shared_ptr<DeliveryCounters> counters) {
    for (;;) {
        SparkEvent ev;
        {
            std::unique_lock lk(consumer->mu);
            consumer->cv.wait(lk, [&] { return consumer->stopping || !consumer->queue.empty(); });
            if (consumer->stopping) {
                // Prompt shutdown: whatever is still queued is dropped + counted
                // rather than delivered late into a tearing-down agent.
                counters->dropped.fetch_add(consumer->queue.size(), std::memory_order_relaxed);
                consumer->queue.clear();
                break;
            }
            ev = std::move(consumer->queue.front());
            consumer->queue.pop_front();
        }
        try {
            consumer->handler(ev);
            counters->delivered.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            counters->errors.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}': {}",
                         consumer->name, ::yuzu::log_key_token(ev.key), e.what());
        } catch (...) {
            counters->errors.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}'", consumer->name,
                         ::yuzu::log_key_token(ev.key));
        }
    }
    // Signal clean exit so a bounded quiesce_consumer join succeeds (vs detach).
    {
        std::lock_guard lk(consumer->done_mu);
        consumer->finished = true;
    }
    consumer->done_cv.notify_all();
}

// ── Arming ────────────────────────────────────────────────────────────────────

std::expected<std::uint64_t, std::string>
SparkEngine::validate_and_floor(const SparkSpec& spec) const {
    if (!params_match_type(spec))
        return std::unexpected(std::string("spark params do not match type '") +
                               spark_type_token(spec.type) + "'");
    switch (spec.type) {
    case SparkType::Interval: {
        const auto& p = std::get<IntervalSparkParams>(spec.params);
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.interval_ms, floor);
        if (eff != p.interval_ms)
            spdlog::warn("SparkEngine: interval {}ms below the {}ms floor — clamped",
                         p.interval_ms, floor);
        return eff;
    }
    case SparkType::Startup:
        return 0;
    case SparkType::Disk: {
        const auto& p = std::get<DiskSparkParams>(spec.params);
        if (p.path.empty())
            return std::unexpected("disk spark: path must not be empty");
        if (p.used_pct_threshold == 0 || p.used_pct_threshold > 100)
            return std::unexpected("disk spark: used_pct_threshold must be 1..100");
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.poll_ms, floor);
        if (eff != p.poll_ms)
            spdlog::warn("SparkEngine: disk poll {}ms below the {}ms floor — clamped", p.poll_ms,
                         floor);
        return eff;
    }
    case SparkType::File: {
        const auto& p = std::get<FileSparkParams>(spec.params);
        if (p.path.empty())
            return std::unexpected("file spark: path must not be empty");
        return 0; // event-driven: no wheel cadence
    }
    case SparkType::Registry: {
        const auto& p = std::get<RegistrySparkParams>(spec.params);
        if (p.hive != "HKLM" && p.hive != "HKCU" && p.hive != "HKCR" && p.hive != "HKU")
            return std::unexpected("registry spark: hive must be one of HKLM/HKCU/HKCR/HKU");
        if (p.key.empty())
            return std::unexpected("registry spark: key must not be empty");
        return 0; // event-driven: no wheel cadence
    }
    case SparkType::Service: {
        const auto& p = std::get<ServiceSparkParams>(spec.params);
        if (!valid_unit_name(p.service_name))
            return std::unexpected("service spark: name must be non-empty, <=256 chars, "
                                   "alphanumeric plus . _ - @");
        return 0; // event-driven: no wheel cadence
    }
    }
    return std::unexpected("unknown spark type");
}

std::chrono::steady_clock::time_point
SparkEngine::initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                         std::chrono::steady_clock::time_point now) const {
    switch (spec.type) {
    case SparkType::Startup:
        return now; // fire as soon as the wheel runs
    case SparkType::Disk:
        // Early first reading, but timer-driven — never at-arm (macOS lesson).
        return now + std::chrono::milliseconds(std::min(cadence_ms, kFirstDiskPollCapMs));
    default:
        return now + std::chrono::milliseconds(cadence_ms);
    }
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm(ConsumerId consumer,
                                                                         SparkSpec spec) {
    {
        std::lock_guard lk(consumers_mu_);
        if (!consumers_.contains(consumer))
            return std::unexpected("unknown consumer id");
    }
    // The FIRST half of the M1 window (#1994) — pre-check passed, nothing inserted
    // yet. No locks held. See the seam's header doc for why arm_race_hook_for_test_
    // cannot reach the same interleaving.
    if (arm_precheck_race_hook_for_test_)
        arm_precheck_race_hook_for_test_();
    Subscriber sub;
    sub.tier = SparkTier::Queued;
    sub.consumer = consumer;
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string>
SparkEngine::arm_inline(SparkSpec spec, InlineHandler handler) {
    if (!handler)
        return std::unexpected("inline handler must not be null");
    Subscriber sub;
    sub.tier = SparkTier::Inline;
    sub.inline_fn = std::move(handler);
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm_impl(SparkSpec spec,
                                                                              Subscriber sub) {
    const auto cadence = validate_and_floor(spec);
    if (!cadence)
        return std::unexpected(cadence.error());
    const std::string key = spark_key(spec);
    const bool event_driven = is_event_driven(spec.type);
    // Saved before `sub` is moved into armed_.subs below — needed for the
    // post-insert consumer re-check (#1994 M1, Queued tier only).
    const SparkTier tier = sub.tier;
    const ConsumerId consumer_id = sub.consumer;

    // Set to the mechanism + params only when a NEW event-driven watch must be
    // armed live (a fresh key on a running engine). Deferred/deduped arms and
    // all timer-driven arms leave it null.
    // #2270 — arm_impl is STRONG-GUARANTEE against std::bad_alloc. The old order
    // inserted into armed_ and then kept allocating (spec copy, sub_keys_ node,
    // subs growth, the log line), so a throw part-way left a GHOST key: an armed_
    // entry with no subscriber and no watcher. A later equal-spec arm deduped onto
    // it (inserted == false), skipped watch_guarded(), and reported SUCCESS with no
    // OS watcher running — silent, durable detection loss that outlived the memory
    // pressure. Two layers close it:
    //   (1) inside mu_: every allocation happens BEFORE the first shared-state
    //       commit, the one remaining allocating commit is try/caught, and the tail
    //       that publishes the subscription cannot throw (pinned by static_assert).
    //       Note the in-lock rollback also unpublishes nothing: the publish tail runs
    //       AFTER the last allocating step, so there is nothing committed to undo.
    //   (2) past the commit: NO ALLOCATION FAILURE CAN ESCAPE. Every string a
    //       post-commit path can return is built below, before the commit, and only
    //       moved afterwards; watch_guarded() completes its error into a pre-sized
    //       buffer; the consumer-race teardown is a specialization of disarm() that
    //       copies nothing. Read that precisely - it is NOT "the window never
    //       allocates": the log lines in it still format into heap buffers. It is
    //       that every remaining allocating statement sits inside a catch-all, so a
    //       bad_alloc from one costs a log line and nothing else.
    //       COVERAGE, STATED EXACTLY, because the blanket version of this sentence was
    //       false: tests/unit/test_spark_alloc_budget.cpp counts this window with the
    //       logger silenced for the FAILED-WATCH, DEDUP and fresh-SUCCESS shapes. The
    //       pre-start/timer and teardown_arm_race shapes are covered by inspection
    //       only (#2816). An adversarial reviewer disproved the earlier unqualified
    //       "pinned by" wording by inserting an allocation on the success path and
    //       watching the budget binary pass green - do not restore a blanket claim
    //       here without a counted case behind every shape.
    //
    // There is deliberately NO post-commit rollback. An earlier revision had one and
    // it was a net negative: across two review rounds it shipped a wrong branch
    // predicate (it deleted healthy sibling subscriptions and orphaned live OS
    // watches on the deduped, timer and pre-start shapes), then a TOCTOU whose
    // converse re-created the very ghost this fix exists to close - a rollback
    // running with no locks held, after an unwind window, cannot reliably decide
    // what it is allowed to undo. Layer (2) removes the need for one: the round that
    // deleted the rollback claimed the log line was the only thing left that could
    // throw, and that was FALSE - the error concat inside watch_guarded's catch
    // handler reproduced the ghost on demand.
    //
    // RESIDUALS, stated rather than papered over. Layer (2) is about ALLOCATION
    // failure; two other things past the commit can still throw out of this function:
    //   * a std::system_error from acquiring mech_ops_mu_by_type_ or consumers_mu_.
    //     std::mutex::lock throws only on EDEADLK/EINVAL/EAGAIN - a process-is-broken
    //     condition, not the memory pressure #2270 is about - and recovering from it
    //     is what the rollback failed twice to do safely. Out of scope here.
    //   * arm_race_hook_for_test_ below, which exists to inject exactly such a throw.
    //     (The seam inside watch_guarded is contained there and cannot escape.)
    // And one that does NOT escape but is not repaired either: a throwing mechanism
    // unwatch() during the consumer-race teardown leaves an orphaned OS watch.
    // Reclamation is mechanism-dependent, not simply OS-dependent: a File watch
    // (Windows-only mechanism) is never reclaimed short of a process restart; a
    // Service watch (Linux or Windows) is reclaimed the next time stop() runs; a
    // Registry watch (Windows-only mechanism) cannot fail this way at all. Contained
    // and counted as stats().arm_race_unwatch_failures_total, and surfaced as a
    // sparse heartbeat tag; teardown_arm_race carries the per-mechanism bound and the
    // reason repairing it is not attempted.
    ISparkMechanism* mech = nullptr;
    SparkParams watch_params;
    SubscriptionId id = 0;
    // Rung 9c PR-6 item 1: this key's incarnation IF a live mechanism call is
    // about to be made below (mech != nullptr) — captured from `fresh` inside
    // the locked block, read after mu_ is released by the live gate and the
    // watch_guarded() call. kNoSparkIncarnation is never actually read (every
    // use is guarded by `if (mech)`), but a real default avoids an
    // uninitialized-looking value in the meantime.
    SparkIncarnation my_inc = kNoSparkIncarnation;
    // #2815 door 4/4 - the one the original design missed. This is not a TEARDOWN, but
    // it is the same window: `mech` and mech_ops_mu_by_type_.at(spec.type) are resolved
    // under mu_ and then used with mu_ RELEASED, so ~SparkEngine freeing those members
    // mid-watch is the same use-after-free. The lease also covers the M1 consumer
    // re-check and teardown_arm_race() call in this function's tail, which read
    // consumers_mu_/consumers_.
    TeardownLease lease(inflight_teardowns_);

    // ── pre-built returns (#2270 layer 2) ─────────────────────────────────────────
    // Built here, where a throw unwinds a still-untouched engine, and only MOVED
    // after the commit. Building them later - inside a catch handler, or on a return
    // path - is the defect this replaces: it puts an allocation in a window where a
    // bad_alloc strands a live subscription. (next_id_ having advanced is not state a
    // caller can observe; skipping an id is unobservable.)
    //
    // All of it happens BEFORE mu_ is taken. An earlier revision built the three
    // watch-related carriers inside the lock, where the fresh-event-driven shape is
    // known — but that put three allocations under the one mutex that also serialises
    // disarm(), emit_event dispatch and every other arm(), on the ordinary success
    // path, to save work only a failing arm needs (governance round 4, happy-path
    // HP-1 + sre). `event_driven` is known here, so the shape test that matters is
    // available without the lock. Four shapes now build carriers they will not use:
    // a deduped event-driven arm; a PRE-START event-driven arm (which previously built
    // nothing, since the build sat inside `if (running_)`); and an arm rejected inside
    // the lock, either for `stopped_` or for an unsupported type - two shapes. All are bounded, per-call, and off
    // the mutex, which is the cheaper side of the trade (Gate 8 - SRE8-4).
    std::string consumer_race_msg;
    std::string disarmed_mid_arm_msg;
    BoundedMsg watch_threw_msg;
    BoundedMsg watch_fail_msg;
    if (tier == SparkTier::Queued)
        consumer_race_msg = "consumer unregistered during arm";
    if (event_driven) {
        disarmed_mid_arm_msg = "spark '" + key + "' was disarmed before its watch could be armed";
        watch_threw_msg = BoundedMsg(kWatchThrewPrefix);
        watch_fail_msg = BoundedMsg("watch mechanism failed to arm '" + key + "': ");
    }

    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return std::unexpected("engine is stopped");
        if (event_driven && !mechanisms_.contains(spec.type))
            // No watcher for this type on this platform → reject, rather than
            // arm without a watcher (spark.hpp: armed == a watcher is running).
            return std::unexpected(std::string("no watch mechanism for spark type '") +
                                   spark_type_token(spec.type) + "' — unsupported on this platform");
        sub.id = next_id_++;
        id = sub.id;

        // Everything that allocates for a BRAND-NEW key is built on this local, so a
        // throw here cannot touch armed_'s CONTENTS. One deliberate exception, below:
        // the dedup branch grows an existing entry's subs capacity before the commit,
        // which the catch does not undo — capacity only, no observable state change.
        Armed fresh;
        auto* existing = [&]() -> Armed* {
            auto it = armed_.find(key);
            return it == armed_.end() ? nullptr : &it->second;
        }();
        if (existing == nullptr) {
            fresh.spec = spec;
            fresh.cadence_ms = *cadence;
            // Rung 9c PR-6 item 1: mint a fresh incarnation + armed_at for
            // EVERY brand-new key — H14: even a PRE-START arm gets this now,
            // at arm time, not deferred to start(). NEVER minted on the dedup
            // branch below, which shares the existing key's token unchanged.
            fresh.incarnation = next_id_++;
            fresh.armed_at = std::chrono::steady_clock::now();
            if (event_driven) {
                // TRAP 1: event-driven sparks NEVER sit on the wheel — the wheel
                // scan + `default: continue` assume it. A live engine arms the
                // watch now (below, mu_ released); a pre-start arm is armed by
                // start()'s replay.
                fresh.scheduled = false;
                if (running_) {
                    mech = mechanisms_.at(spec.type).get();
                    watch_params = spec.params;
                    my_inc = fresh.incarnation;
                    // The carriers this shape needs were built before the lock.
                }
            } else {
                fresh.scheduled = true;
                fresh.next_due =
                    initial_due(fresh.spec, fresh.cadence_ms, std::chrono::steady_clock::now());
            }
            fresh.subs.push_back(std::move(sub));
        } else {
            // Dedup: a second arm of an equal event-driven spec shares the existing
            // watcher — mech stays null, no second watch() (N subscriptions, 1
            // watcher). Reserve now (strong-guarantee: a throw leaves the vector
            // untouched) so the publishing push_back below cannot throw.
            // LOAD-BEARING AND UNPINNED: deleting this line leaves the whole suite
            // green (measured), because without a reallocation the publish behaves
            // identically - the defect it prevents is only reachable when push_back
            // itself must allocate under memory pressure. The static_assert on
            // Subscriber's move covers the move, not the reallocation. Do not
            // "simplify" it away on the strength of a green run.
            existing->subs.reserve(existing->subs.size() + 1);
        }

        // ── commit ────────────────────────────────────────────────────────────
        // First shared-state mutation. try_emplace is itself strong: it throws
        // before committing anything.
        auto [it, inserted] = armed_.try_emplace(key);
        try {
            if (arm_fault_hook_for_test_)
                arm_fault_hook_for_test_(kArmFaultPhaseBeforeSubKeys);
            // The last allocating step. On a throw the armed_ entry we just made
            // must go, or it becomes the ghost this whole ordering exists to prevent.
            sub_keys_.emplace(id, key);
        } catch (...) {
            if (inserted)
                armed_.erase(it);
            throw;
        }

        // ── publish (nothrow tail) ────────────────────────────────────────────
        // Nothing below allocates: the Armed move-assign and the Subscriber move
        // into already-reserved capacity are both nothrow, pinned by the
        // static_asserts in the header next to the structs they constrain.
        if (inserted) {
            it->second = std::move(fresh);
        } else {
            Armed& armed = it->second;
            if (armed.spec.type == SparkType::Startup && !armed.scheduled && running_) {
                // A late subscriber to an already-fired startup spark still gets its
                // one-shot: re-schedule so the arm itself is the observable "startup".
                armed.scheduled = true;
                armed.next_due = std::chrono::steady_clock::now();
            }
            armed.subs.push_back(std::move(sub));
        }
        if (!event_driven)
            wheel_cv_.notify_all();
        if (inserted) {
            // spdlog formats into a heap buffer, so under the very memory pressure
            // #2270 is about it can throw - and a throw here would strand a committed
            // subscription. Losing a log line is strictly better than unwinding a
            // live arm. (Not the only allocating statement past the commit - see the
            // pre-built returns above for the ones that were removed rather than
            // contained.) log_key_token(key) (#4665, CWE-117 log-injection
            // neutralisation) is now a SECOND allocating expression inside this same
            // try: it folds `key` into a new std::string before spdlog is even
            // entered, so this line costs one allocation under QuietLog too, not
            // zero - test_spark_alloc_budget.cpp's #2270 pin was bumped to match,
            // not relaxed.
            try {
                spdlog::info("SparkEngine: armed '{}'", ::yuzu::log_key_token(key));
            } catch (...) {
            }
        }
        // Unconditional — not `if (mech)`. Reviewer-found (adversarial review, K1/C2-1):
        // the tail below (M1 re-check + teardown_arm_race()) reads consumers_mu_/
        // consumers_ regardless of whether a mechanism was resolved, so the dedup,
        // pre-start-event-driven, and non-event-driven arm shapes — all of which leave
        // `mech` null — need the same lease coverage door 3 (unregister_consumer, which
        // arms unconditionally for the identical reason) already has. Confirmed reachable
        // in production shape by the #2818 Guardian pin, which performs exactly this
        // dedup arm on a Queued-tier subscription. RED-FIRST CONFIRMED: reverting this to
        // `if (mech)` reproduces a real SIGSEGV in this file's "#2815 — a DEDUP arm"
        // TEST_CASE (destroyed becomes true within 300ms pre-fix, then crashes on resume).
        lease.arm_locked(); // #2815: last statement under mu_
    }

    // Arm the OS watch with mu_ RELEASED — watch() may block on handle setup,
    // and an inline emit from the mechanism re-enters under mu_. `mech` is set
    // only for a NEWLY-INSERTED event-driven key, so a failure here means the
    // watcher for this whole key never came up. Serialized via this type's
    // mech_ops_mu_by_type_ entry with a staleness re-check immediately before
    // the call (#1994 M2): a concurrent disarm/unregister may have torn this
    // brand-new key down already (its sole subscriber — ours — removed, e.g. by
    // unregister_consumer racing our own consumer), in which case watching it
    // now would leave an orphaned OS watch with no armed_ entry.
    // #2818: populated only on the failed-watch path below, and only consumed AFTER
    // this whole `if (mech)` scope (and therefore `ops` and `mu_`) have been released.
    // deliver() MUST NOT run while `ops` is held: an Inline subscriber reacting to a
    // Lost notification by re-arming this same type would re-enter arm_impl, try to
    // take mech_ops_mu_by_type_.at(spec.type) again, and self-deadlock on this
    // non-recursive mutex (spark_engine.hpp's documented invariant against a
    // mechanism/consumer synchronously re-entering the engine from inside a
    // watch()/unwatch() call stack).
    bool watch_failed = false;
    std::string watch_fail_result;
    SparkEvent lost_ev;
    std::vector<Subscriber> lost_subs;

    if (mech) {
        std::lock_guard ops(mech_ops_mu_by_type_.at(spec.type));
        {
            std::lock_guard lk(mu_);
            // E15/H1: an IDENTITY check, not a bare containment check —
            // the key could be present again under a DIFFERENT (superseded)
            // incarnation if a disarm+rearm raced us between our commit above
            // and here (disarm's bookkeeping erase needs only mu_, not `ops`,
            // so it can land here even while we hold `ops`). A stale watch()
            // must never be submitted for a key that is no longer ours.
            auto it = armed_.find(key);
            if (it == armed_.end() || it->second.incarnation != my_inc)
                return std::unexpected(std::move(disarmed_mid_arm_msg));
        }
        // A mechanism must RETURN std::unexpected on failure, not throw — but
        // the real ones can (e.g. spark_file's watch() uses fs::current_path()
        // without an ec overload, which throws on a relative path with a bad
        // CWD). An escaping throw would leave a zombie armed_ entry with no
        // watcher and no id ever returned to the
        // caller — an std::expected-contract violation the caller can neither
        // observe nor disarm (governance UP-7). watch_guarded() turns a throw
        // into a returned failure so it falls into the whole-key teardown.
        auto w = watch_guarded(mech, key, watch_params, my_inc, watch_threw_msg,
                               arm_fault_hook_for_test_);
        if (!w) {
            // #2818 item (b), orphan reclamation: still under mech_ops_mu_by_type_[type],
            // no new locking. Defensive — watch_guarded()'s failure may be a clean
            // "never registered anything" or a partial mechanism-side registration
            // (watch() is not guaranteed atomic on every failure path); unwatch() on a
            // key the mechanism never (or only partially) registered is independently
            // verified a safe no-op on all three real mechanisms (spark_file.cpp's
            // unwatch_locked, spark_registry.cpp's unwatch, spark_service.cpp's
            // worker-side Cmd::Remove handling all early-return/no-op on an unknown
            // key). Contained: a throw here costs a possibly-orphaned resource, never
            // a skipped drop_key_locked() below.
            try {
                mech->unwatch(key);
            } catch (const std::exception& e) {
                arm_race_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
                try {
                    spdlog::error("SparkEngine: defensive unwatch('{}') after a failed "
                                  "watch() threw ({}) - a partial mechanism resource may "
                                  "be orphaned", ::yuzu::log_key_token(key), e.what());
                } catch (...) {
                }
            } catch (...) {
                arm_race_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
                try {
                    spdlog::error("SparkEngine: defensive unwatch('{}') after a failed "
                                  "watch() threw - a partial mechanism resource may be "
                                  "orphaned", ::yuzu::log_key_token(key));
                } catch (...) {
                }
            }
            {
                std::lock_guard lk(mu_);
                // #2818: snapshot every CURRENT subscriber before drop_key_locked erases
                // the key's bookkeeping, so a sibling that deduped onto this key while
                // our watch() was in flight is notified too — not just this caller.
                // Snapshot + erase in ONE mu_ acquisition: a late dedup landing before
                // this block starts is captured by find(); drop_key_locked is the LAST
                // statement, so nothing can join between snapshot and erase either.
                // Contained: a bad_alloc here (the key/detail string copies, the
                // vector<Subscriber> copy) costs a lost notification, never a skipped
                // drop_key_locked() call — the same #2270 discipline the rest of this
                // function is built on ("losing a log line is strictly better than
                // unwinding a live arm") applies equally to losing a notification.
                //
                // E14/H1: only if the entry is STILL OURS. A successor's fresh
                // arm may have already replaced this key (their own watch_incarnation()
                // call queued behind the `ops` we are still holding — the same race the
                // live gate above guards) — in that case there is nothing here for US
                // to drop or snapshot; touching it would tear down THEIR live watch
                // instead of reporting the loss of one that never actually existed for
                // them. The unconditional mech->unwatch(key) just above already
                // prevents any resource leak from OUR failed watch either way.
                auto it = armed_.find(key);
                const bool still_ours = (it != armed_.end() && it->second.incarnation == my_inc);
                if (still_ours) {
                    try {
                        lost_ev.key = key;
                        lost_ev.type = spec.type;
                        lost_ev.seq = ++it->second.seq;
                        lost_ev.at = std::chrono::system_clock::now();
                        lost_ev.kind = SparkEventKind::Lost;
                        lost_ev.detail = w.error();
                        lost_subs = it->second.subs;
                    } catch (...) {
                        lost_subs.clear(); // contained: no notification, key still drops below
                    }
                    drop_key_locked(key); // allocates nothing, cannot throw
                }
                // Message reuse, deliberate. When the entry is no longer
                // ours (a successor's fresh arm already superseded it), THIS
                // caller's own subscription doesn't exist regardless of the
                // mechanism's technical outcome — from this caller's view it was
                // disarmed before its watch could be armed, the identical fact
                // the live gate above reports. Reuse disarmed_mid_arm_msg (already
                // built, above, before mu_ was ever taken) rather than complete a
                // NEW string on this path for a mechanism error the caller's
                // subscription no longer depends on. Bookkeeping is already clean
                // either way; when still_ours, the message is completed from the
                // pre-sized buffer — a mechanism error is caller-controlled in
                // length, so concatenating it here would put an unbounded
                // allocation past the commit and break the property the whole
                // layer rests on.
                watch_failed = true;
                watch_fail_result =
                    still_ours ? watch_fail_msg.finish(w.error()) : std::move(disarmed_mid_arm_msg);
            }
        }
    }
    if (watch_failed) {
        // Both `ops` and `mu_` are released here — see the comment above lost_ev's
        // declaration for why that's load-bearing, not incidental.
        if (!lost_subs.empty()) {
            subscription_lost_.fetch_add(1, std::memory_order_relaxed);
            try {
                deliver(lost_ev, lost_subs);
            } catch (...) {
            }
        }
        return std::unexpected(std::move(watch_fail_result));
    }

    if (arm_race_hook_for_test_)
        arm_race_hook_for_test_();

    // M1 (#1994): `consumer_id` existed at arm()'s pre-check, but a concurrent
    // unregister_consumer() may have removed it (and our subscription with it)
    // any time between that pre-check and here. Re-check AFTER the insert (and
    // watch, if any) and undo our subscription on a lost race — see
    // unregister_consumer()'s erase-before-scan ordering for why this
    // re-check is airtight. Inline subs have no registered consumer to check.
    // The teardown is teardown_arm_race(), NOT disarm(). Read the next clause as
    // precisely as arm_impl's "(2) past the commit" clause above: it is NOT that
    // either one's locked section never allocates — the log line in each still
    // formats into a heap buffer (teardown_arm_race's own contained "disarmed"
    // log, disarm()'s twin contained "disarmed" log) — it is that both now
    // CONTAIN that allocation in a catch-all rather than letting it escape. So the
    // reason to route through teardown_arm_race is no longer allocation: disarm()
    // must LOOK UP a key this caller already holds, and its last-subscriber
    // branch is whole-key-capable, while what a lost M1 race owes is the
    // removal of exactly ONE subscription — a sibling that deduped onto this
    // key keeps its own.
    if (tier == SparkTier::Queued) {
        bool consumer_alive = false;
        {
            std::lock_guard lk(consumers_mu_);
            consumer_alive = consumers_.contains(consumer_id);
        }
        if (!consumer_alive) {
            teardown_arm_race(id, key, spec.type, event_driven);
            return std::unexpected(std::move(consumer_race_msg));
        }
    }
    return id;
}

void SparkEngine::drop_key_locked(const std::string& key) {
    // Tear down the ENTIRE key, not just one subscription (governance B1): a
    // concurrent arm() of an equal spec may have deduped ONTO this key (adding
    // its own sub with a valid id it believes is armed). Removing only one
    // subscription would leave that sibling armed with NO watcher — violating
    // "armed == a watcher is running" (spark.hpp). Dropping the whole key makes
    // any sibling id inert (disarm is idempotent), which is correct: a failed
    // arm of the key is a failed arm for everyone sharing it. Caller holds mu_
    // and owns any OS-watch teardown — this touches bookkeeping only.
    auto it = armed_.find(key);
    if (it == armed_.end())
        return;
    for (const auto& s : it->second.subs)
        sub_keys_.erase(s.id);
    armed_.erase(it);
}

void SparkEngine::teardown_arm_race(SubscriptionId id, const std::string& key, SparkType type,
                                    bool event_driven) {
    // disarm()'s body, specialized so no allocation failure can escape it (#2270
    // layer 2). Every difference from disarm() is deliberate; keep the two in lockstep:
    //   * `key`/`type` come from the caller, so no lookup and no copy is needed.
    //   * `event_driven` is likewise the caller's already-computed value (arm_impl's
    //     own `const bool event_driven = is_event_driven(spec.type);`), not
    //     recomputed from the stored Armed::spec.type the way disarm()'s
    //     `is_event_driven(ai->second.spec.type)` is — same "the caller already
    //     holds it" rationale as `key`/`type` above. Identical value today (both
    //     derive from the same spec.type), found and confirmed equivalent-but-
    //     undocumented by an external adversarial review (PR #2843) — kept as its
    //     own bullet rather than folded into the first, since it is a PASSED value,
    //     not merely an unlooked-up one, and a future edit that lets the two diverge
    //     needs this spelled out to catch.
    //   * the log line is contained — as disarm()'s now is too.
    //   * a throwing unwatch() is contained and counted — as disarm()'s now is too,
    //     into its own separately-scoped counter.
    // The last two were differences until disarm() was hardened; they are recorded as
    // parity rather than deleted, so a reader diffing the pair sees why each is there.
    // Everything else is disarm() verbatim in effect (four documented differences,
    // not zero), and must stay that way: ONE subscription is removed, never the key,
    // because losing the M1 race invalidates OUR arm and nobody else's. A sibling
    // that deduped onto this key keeps its subscription AND its watcher — deleting
    // those is precisely the defect that failed review twice.
    ISparkMechanism* mech = nullptr;
    TeardownLease lease(inflight_teardowns_); // #2815 door 2/4
    {
        std::lock_guard lk(mu_);
        auto ki = sub_keys_.find(id);
        if (ki == sub_keys_.end())
            return; // unregister_consumer's scan already removed us — nothing to undo
        // Key off the LOCATED entry, not the caller's string, as disarm() does. The two
        // are identical today — `sub_keys_` has exactly one insert site and ids are
        // monotonic and never reused — but if they ever diverged, keying off the caller
        // would make erase_if match nothing while sub_keys_.erase(ki) below still ran,
        // leaving a live subscription that keeps receiving events and can never be
        // disarmed. Reading ki->second costs nothing (the no-lookup argument for taking
        // `key` from the caller is about disarm() having to FIND it, which this is not).
        //
        // SCOPE OF THIS HARDENING, stated exactly because an earlier revision overclaimed
        // it (Gate 8 — sec8-3, CA8-2): `located` covers the find and the erase_if it
        // guards, and NOTHING further. It is a reference INTO sub_keys_, so it dangles
        // the moment sub_keys_.erase(ki) runs below. The M2 re-check and the unwatch are
        // both AFTER that erase, so they can only use the caller's `key` — sound because
        // the two are provably equal (one insert site, ids never reused). The log below
        // is before the erase and could use either; it uses `key` for consistency, not
        // necessity (Gate 9 — CA9-3/sec9-4 caught the earlier wording lumping all three). Copying it out to
        // use later would reintroduce exactly the allocation this teardown exists to
        // avoid. Do not "finish the job" by binding it wider without reading this.
        // (#4665: the log line below now also folds `key` through log_key_token(),
        // which allocates once on its own regardless of copy-vs-reference - that cost
        // is separate from, and accounted for alongside, the extra copy this
        // paragraph is about avoiding.)
        const std::string& located = ki->second;
        auto ai = armed_.find(located);
        if (ai != armed_.end()) {
            auto& subs = ai->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
            if (subs.empty()) {
                try {
                    spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)",
                                 ::yuzu::log_key_token(key));
                } catch (...) {
                }
                // Only while running_: the watch was armed only while running, and
                // stop() unwinds every mechanism. Resolve the mechanism HERE rather
                // than reusing arm_impl's `mech` — that local is null on a deduped
                // arm, and a deduped arm whose sibling is removed by the same
                // unregister scan can still be the call that empties the key.
                if (running_ && event_driven) {
                    auto mit = mechanisms_.find(type);
                    if (mit != mechanisms_.end())
                        mech = mit->second.get();
                }
                armed_.erase(ai);
            }
        }
        sub_keys_.erase(ki);
        wheel_cv_.notify_all();
        if (mech)
            lease.arm_locked(); // #2815: last statement under mu_
    }
    if (mech) {
        // Hook BEFORE the mech-ops lock, never while held — a test hook that re-arms
        // from here would self-deadlock on that non-recursive mutex (disarm(), same
        // placement and same reason).
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(key))
                return; // a concurrent equal-spec re-arm already renewed this key (M2)
        }
        // CONTAINED, as disarm() now is too (see its own unwatch, which was brought into
        // lockstep on this point later). unwatch() is not noexcept and
        // the real mechanisms allocate inside it (spark_service queues a Cmd holding a
        // key copy; spark_file grows retiring_), so under the memory pressure this
        // whole layer is about it can throw.
        //
        // WHY CONTAIN. The engine's OWN bookkeeping is consistent by this point, so
        // propagating buys no repair. It is NOT that propagating is harmless: measured
        // during governance round 4, the sibling site that DOES propagate
        // (unregister_consumer's uncontained unwatch) escapes a void function and
        // permanently strands the consumer's dispatch thread — the thread holds its own
        // Consumer alive by shared_ptr, `stopping` is never set, and the entry is
        // already erased so stop() cannot reach it either. That is the concrete
        // argument for containing here rather than a preference.
        //
        // RESIDUAL, deliberately not repaired, and the BOUND IS PLATFORM-SPECIFIC —
        // do not restate it as a flat "until stop()", which is what round 4 found to
        // be false:
        //   * Linux/sd-bus: the OS watch outlives its armed_ entry and IS reclaimed by
        //     stop() (and by unregister_consumer, and re-adopted by a later equal-spec
        //     arm, since watch() is idempotent per key).
        //   * WINDOWS/spark_file: worse. push_retiring() takes the OWNING unique_ptr by
        //     value,
        //     so a throwing push_back destroys it with an IOCP completion still
        //     pending, and stop()'s UAF quarantine walks dirs_/ancestors_/retiring_ —
        //     none of which now hold it. The completion dangles for the REMAINING
        //     PROCESS LIFETIME; only a process restart reclaims it. The underlying
        //     strong-guarantee hole in push_retiring is pre-existing and tracked
        //     separately; what belongs here is an honest bound.
        // A retry loop would be another lock-free repair guessing at state it cannot
        // see, which is exactly what failed twice.
        try {
            mech->unwatch(key);
        } catch (...) {
            arm_race_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("SparkEngine: unwatch('{}') threw during consumer-race teardown - "
                              "the OS watch is not reclaimed by this call; a File watch "
                              "(Windows) persists until a process restart, while other "
                              "mechanisms are reclaimed at the mechanism's stop()",
                              ::yuzu::log_key_token(key));
            } catch (...) {
            }
        }
    }
}

void SparkEngine::disarm(SubscriptionId id) {
    ISparkMechanism* mech = nullptr;
    std::string unwatch_key;
    SparkType unwatch_type{}; // carried forward to pick this type's mech-ops lock
    TeardownLease lease(inflight_teardowns_); // #2815 door 1/4
    {
        std::lock_guard lk(mu_);
        auto ki = sub_keys_.find(id);
        if (ki == sub_keys_.end())
            return;
        // Key off the LOCATED entry BY REFERENCE (#2270). The copy this replaced
        // allocated in a function that must not throw once erase_if below has run.
        // PRECISELY: a throw AT THIS SITE was harmless — nothing is mutated yet and the
        // disarm is cleanly retryable. The residue this hardening is about belongs to the
        // two allocations BELOW erase_if; they are commented where they are, not here.
        // SCOPE, stated exactly because the same wording had to be corrected once
        // in teardown_arm_race: `key` is a reference INTO sub_keys_. It is read
        // only ABOVE the move below; past that point it names a moved-from string
        // and must not be read, and past sub_keys_.erase(ki) it dangles outright.
        const std::string& key = ki->second;
        auto ai = armed_.find(key);
        if (ai != armed_.end()) {
            auto& subs = ai->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
            if (subs.empty()) {
                // CONTAINED, matching teardown_arm_race. spdlog allocates - and so
                // does log_key_token(key) (#4665), a second allocating expression
                // inside this same try - and the condition this whole layer exists
                // for is the one that makes either throw; the engine's bookkeeping
                // below must complete regardless.
                try {
                    spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)",
                                 ::yuzu::log_key_token(key));
                } catch (...) {
                }
                // Only tear the OS watch down when the engine is live: the watch
                // was armed only while running_, and stop() already unwinds every
                // mechanism. A pre-start or post-stop disarm has no watch to drop.
                if (running_ && is_event_driven(ai->second.spec.type)) {
                    auto mit = mechanisms_.find(ai->second.spec.type);
                    if (mit != mechanisms_.end()) {
                        mech = mit->second.get();
                        // MOVE, not copy. It allocates nothing on ANY implementation:
                        // basic_string's move-assign is noexcept for std::allocator, so it
                        // cannot allocate whatever the SSO threshold — the buffer steal is
                        // only the over-SSO mechanism, not the reason. Leaves `key` moved-from —
                        // see the scope note above. armed_ holds its own key
                        // string, so `ai` and the erase below are unaffected.
                        unwatch_key = std::move(ki->second);
                        unwatch_type = ai->second.spec.type;
                    }
                }
                armed_.erase(ai);
            }
        }
        sub_keys_.erase(ki);
        wheel_cv_.notify_all();
        if (mech)
            lease.arm_locked(); // #2815: last statement under mu_
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_). Serialized via this type's mech_ops_mu_by_type_ entry with a
    // staleness re-check immediately before the call (#1994 M2): a concurrent
    // re-arm of an equal spec may have already renewed this key between our
    // unlock above and here, in which case this unwatch is stale and must be
    // skipped rather than tearing down the fresh watch.
    if (mech) {
        // Hook fires BEFORE the mech-ops lock is taken (never while held): a test
        // hook that re-arms from here calls back into arm_impl(), which takes
        // this same non-recursive mutex — invoking the hook any later would
        // self-deadlock.
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(unwatch_type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(unwatch_key))
                return; // a concurrent re-arm already renewed this key
        }
        // CONTAINED AND COUNTED, matching teardown_arm_race's own unwatch catch — the
        // fourth and last lockstep difference between the two. unwatch() is not
        // noexcept and the real mechanisms allocate inside it (spark_service queues a
        // Cmd holding a key copy; spark_file grows retiring_), so under the memory
        // pressure this layer is about it can throw.
        //
        // WHY CONTAIN, and it is not merely symmetry. This is a void function whose caller
        // is Guardian's ordinary withdraw path: a throw escapes GuardianSparkBackend::disarm
        // into GuardianSparkRuntime::detach_rule_locked AFTER index_->remove_rule and
        // rules_.erase have run but BEFORE keys_.erase and the "disarmed" lifecycle entry.
        // That strands a keys_ row which makes a later same-key attach's keys_.emplace
        // silently no-op, and loses the audit entry too. The engine's own bookkeeping is
        // complete by this point, so propagating repairs nothing and costs both.
        //
        // The OS watch is still NOT reclaimed. That residual is unchanged, which is why
        // this is counted rather than swallowed silently.
        try {
            mech->unwatch(unwatch_key);
        } catch (...) {
            disarm_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("SparkEngine: unwatch('{}') threw during disarm - the OS watch "
                              "is not reclaimed by this call; a File watch (Windows) persists "
                              "until a process restart, while other mechanisms are reclaimed "
                              "at the mechanism's stop()",
                              ::yuzu::log_key_token(unwatch_key));
            } catch (...) {
            }
        }
    }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void SparkEngine::start() {
    // lifecycle_mu_ before mu_ (header LOCK ORDER). Held for the whole of start() so a
    // concurrent stop() — reachable from the Windows SCM control thread during boot —
    // cannot interleave with mechanism bring-up and leave mechanisms started AFTER
    // their stop() ran, which would destroy them with live threads (Gate-4 UP-1).
    std::lock_guard life(lifecycle_mu_);
    std::size_t armed_count = 0;
    // Paired with each mechanism's own SparkType (not just the bare pointer)
    // so the set_established_sink refusal warning below can name which
    // mechanism type failed to install (governance cpp-safety Gate-3 LOW).
    std::vector<std::pair<SparkType, ISparkMechanism*>> mechs;
    struct Replay {
        ISparkMechanism* mech;
        std::string key;
        SparkParams params;
        SparkType type; // picks this type's mech-ops lock at replay
        /// Rung 9c PR-6 item 1: the key's incarnation AT COLLECTION TIME —
        /// checked at replay (identity, not bare containment — mirrors
        /// arm_impl's live gate) so a disarm+rearm racing the collection pass
        /// skips a now-superseded replay rather than submitting a stale watch.
        SparkIncarnation incarnation;
        /// Built during collection so watch_guarded's error completion allocates
        /// nothing at replay time (#2270), the same buffer arm_impl hands it.
        /// SCOPE LIMIT: this does NOT make start() OOM-safe. running_ is already
        /// latched by the time this vector is built, but the wheel is NOT yet up —
        /// wheel_thread_ spawns only after both this collection pass and the
        /// mechanism-pointer collection below finish (see the wheel-spawn statement
        /// a few lines down). A bad_alloc in the collection pass itself still
        /// escapes start() — now via the #2050 rollback guard below, which tears the
        /// partial startup back down to stopped before propagating, rather than
        /// leaving `running_` latched true over nothing actually started. #2270 is
        /// about arm_impl's post-commit window; the replay path shares the
        /// boundary, not the guarantee.
        BoundedMsg err;
    };
    std::vector<Replay> replays;
    // #2050: function-wide rollback guard for every fallible startup step below —
    // Replay/mechanism-pointer collection, wheel-thread spawn (all three still
    // inside `lk`), then sink install and mechanism start() (both after `lk`
    // releases). Constructed DISABLED; armed only once the reject-check just below
    // succeeds, so a rejected start() (already running/stopped) never tears down an
    // engine this call didn't touch.
    //
    // EXACT SCOPE PLACEMENT, LOAD-BEARING: declared here — after `life`
    // (lifecycle_mu_), BEFORE the `{ lk }` block that takes mu_ — so on unwind it
    // destructs AFTER `lk` releases mu_ but BEFORE `life` releases lifecycle_mu_
    // (LIFO: the last-constructed local destructs first). teardown_locked() calls
    // mechanism stop()s, which may synchronously report_fault()/emit_event() —
    // both of which take mu_ (see their definitions below). A guard declared
    // *inside* the `lk` block would destruct *before* `lk` on unwind,
    // running that rollback while mu_ is STILL held — self-deadlock the first time
    // a mechanism's stop() reports synchronously. Declaring it out here means `lk`
    // is always long gone before the guard ever runs. Do not move this declaration
    // into the `lk` block, even for a specific narrower-looking failure site.
    bool rollback_armed = false;
    // Brace-init, not parens (Gate 3 cpp-expert, 2026-09-19): the two sibling
    // ScopeExit copies (agent.cpp, api_token_store.cpp) both deliberately use
    // `ScopeExit name{lambda}` rather than `ScopeExit name(lambda)` — parenthesized
    // aggregate-init is a distinct C++20 feature (P0960) from the deduction guide
    // itself, and this file has not yet been compiled on Windows/macOS. Brace-init
    // has no such version dependency; match the established, verified-safe form.
    ScopeExit rollback{[this, &rollback_armed]() noexcept {
        if (!rollback_armed)
            return;
        // A destructor must never let an exception escape mid-unwind (std::terminate
        // would convert a startup failure into a process crash — exactly what
        // stop()'s own noexcept exists to prevent for the ordinary teardown path).
        // teardown_locked() can throw, same as it always could inside stop()'s try;
        // contain it here the same way stop()'s own catch does. teardown_complete_
        // stays false either way, so the next stop() call (normally ~SparkEngine's)
        // retries whatever this pass didn't finish.
        try {
            teardown_locked();
        } catch (...) {
            try {
                spdlog::error(
                    "SparkEngine::start(): rollback teardown threw after a startup "
                    "failure — some mechanisms may not have released their OS "
                    "resources yet; the next stop() (normally ~SparkEngine's) retries");
            } catch (...) {
            }
        }
    }};
    {
        std::lock_guard lk(mu_);
        if (running_ || stopped_) {
            spdlog::warn("SparkEngine::start() called while {} — ignored",
                         stopped_ ? "stopped" : "already running");
            return; // rollback stays disabled — nothing has been touched
        }
        rollback_armed = true; // non-throwing; every fallible step from here is covered
        running_ = true;
        // Re-base deadlines on the start instant: an interval armed long before
        // start must not fire immediately; a startup spark fires now. Event-driven
        // sparks armed before start are collected for a watch() replay below.
        const auto now = std::chrono::steady_clock::now();
        if (start_fault_hook_for_test_)
            start_fault_hook_for_test_(kStartFaultPhaseReplayCollection);
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled) {
                armed.next_due = initial_due(armed.spec, armed.cadence_ms, now);
            } else if (is_event_driven(armed.spec.type)) {
                auto mit = mechanisms_.find(armed.spec.type);
                if (mit != mechanisms_.end())
                    replays.push_back({mit->second.get(), key, armed.spec.params, armed.spec.type,
                                       armed.incarnation, BoundedMsg(kWatchThrewPrefix)});
            }
        }
        if (start_fault_hook_for_test_)
            start_fault_hook_for_test_(kStartFaultPhaseMechCollection);
        for (auto& [type, m] : mechanisms_)
            mechs.push_back({type, m.get()});
        armed_count = armed_.size();
        if (start_fault_hook_for_test_)
            start_fault_hook_for_test_(kStartFaultPhaseWheelSpawn);
        wheel_thread_ = std::thread([this] { wheel_loop(); });
    }
    // Start mechanisms (wire the emit + fault + established callbacks), THEN
    // replay pre-start watches — both with mu_ released (handle setup blocks).
    // Mechanisms are started before any watch() reaches them. The
    // establishment sink is installed BEFORE m->start() — a mechanism that
    // implements it seals against further installation at its own start()
    // (spark_mechanism.hpp's set_established_sink doc comment).
    for (auto& [type, m] : mechs) {
        if (!m->set_established_sink(
                [this](const std::string& key, SparkIncarnation inc,
                      std::chrono::steady_clock::time_point at, SparkCoverage cov) {
                    report_established(key, inc, at, cov);
                })) {
            spdlog::debug("SparkEngine: set_established_sink refused for mechanism type {} — "
                          "establishment reporting will be unavailable for this type",
                          spark_type_token(type));
        }
        m->start([this](const std::string& key, SparkData data) { emit_event(key, std::move(data)); },
                 [this](const std::string& key, bool faulted, std::string_view reason) {
                     report_fault(key, faulted, reason);
                 });
    }
    // Test seam (E13): fires once here, after every mechanism has started
    // (and had its establishment sink sealed), before the replay loop below
    // reads `replays`. No locks held.
    if (on_start_hook_for_test_)
        on_start_hook_for_test_();
    for (auto& r : replays) {
        // #2818 (cpp-safety Gate 3): `ops` must NOT still be held when report_fault()
        // runs below — report_fault() now calls deliver(), which can synchronously
        // invoke an Inline subscriber's handler; an Inline handler that reacts by
        // arming/disarming this same type would re-enter this type's
        // mech_ops_mu_by_type_ entry on the same thread and self-deadlock on this
        // non-recursive mutex (the exact class arm_impl's own Lost-delivery path was
        // written to avoid — this pre-existing call site was the one instance that
        // diff missed). So `ops` is scoped to ONLY the staleness re-check +
        // watch_guarded() call; report_fault() runs after it releases.
        std::expected<void, std::string> w;
        {
            // Serialized via this type's mech_ops_mu_by_type_ entry with a staleness
            // re-check (#1994 M2): a concurrent disarm() may have torn this key down
            // between start()'s collection pass above (mu_ released since) and here.
            std::lock_guard ops(mech_ops_mu_by_type_.at(r.type));
            {
                std::lock_guard lk(mu_);
                // E13: an IDENTITY check, not a bare containment check —
                // a disarm+rearm between the collection pass above (mu_
                // released since) and here leaves the key CONTAINS but under a
                // NEWER incarnation; replaying against it would submit a
                // stale watch for a key that already has (or is about to
                // have) its own live arm handle this. Mirrors arm_impl's own
                // live gate.
                auto it = armed_.find(r.key);
                if (it == armed_.end() || it->second.incarnation != r.incarnation)
                    continue; // disarmed, or superseded, before its pre-start replay could run
            }
            // An escaping throw here would unwind out of the void start() AFTER
            // running_ is latched and the wheel + mechanisms are up, leaving this
            // spark in armed_/sub_keys_ with no watcher — the exact "armed == a
            // watcher is running" violation UP-7 closed on the live arm_impl path.
            // watch_guarded() turns a throw into a returned failure; unlike arm_impl
            // we fault in place (subscribers already hold ids — do NOT roll back).
            //
            // #2050 COVERAGE NOTE (Gate-3 quality-engineer): this loop runs with the
            // startup rollback guard still armed, but has no fault-injection test
            // exercising a throw escaping FROM here — deliberately, because
            // watch_guarded()'s own contract (this comment, above) is that it never
            // lets one escape. If that contract ever regresses, THIS is the untested
            // path the rollback guard would have to cover; a future change to
            // watch_guarded()'s throw behavior should add that coverage here.
            w = watch_guarded(r.mech, r.key, r.params, r.incarnation, r.err,
                              arm_fault_hook_for_test_);
        }
        if (!w) {
            // Pre-start replay failure leaves the spark armed-without-watcher —
            // mark it faulted so the drift is observable (B1) rather than a
            // silent log, mirroring the runtime fault channel. (The post-start
            // arm path rolls back instead; a pre-start replay's subscribers
            // already hold ids, so we keep the entry but flag it deaf.)
            // Wrapped (Gate-3 cpp-safety, #2050): this loop runs BEFORE
            // `rollback_armed = false` below, so the rollback guard is still
            // armed here — an allocation failure formatting this line must not
            // trigger a full rollback of an engine that has, in substance,
            // already started (mechanisms are running).
            try {
                spdlog::error("SparkEngine: mechanism failed to arm pre-start watch '{}': {}",
                              ::yuzu::log_key_token(r.key), w.error());
            } catch (...) {
            }
            report_fault(r.key, true, "pre-start replay watch failed");
        }
    }
    // Substantive startup is complete: disarm BEFORE the log line below, not after —
    // a throwing spdlog call must never trigger a full rollback of an engine that has
    // already, in substance, started successfully (#2050).
    rollback_armed = false;
    spdlog::info("SparkEngine started ({} spark(s) armed)", armed_count);
}

void SparkEngine::stop() noexcept try {
    // ── WHO CALLS THIS, AND WHY THERE IS NO SIGNAL-HANDLER MITIGATION ANY MORE ──────
    //
    // stop() is reachable from exactly three places, and NONE of them is a SparkEngine
    // thread:
    //   - `Agent::stop()`, called from main.cpp's shutdown WATCHER thread (POSIX) or
    //     service_win.cpp's SCM control thread (Windows). Both ordinary threads.
    //   - run()'s ScopeExit, on the run() thread.
    //   - ~SparkEngine, on the thread that owns the engine (main).
    //
    // It used to ALSO be reachable from the POSIX signal handler, which called
    // Agent::stop() inline — and a signal is delivered to an ARBITRARY thread, including
    // the wheel, a mechanism poll thread, or a consumer dispatch thread. That forced a
    // whole mitigation layer: masking SIGINT/SIGTERM on every spark thread, a same-thread
    // re-entry guard (a signal could land on a thread already holding lifecycle_mu_ inside
    // start()), and a lock-free self-join bail-out. Five governance rounds found five
    // separate BLOCKING defects IN THAT MITIGATION LAYER.
    //
    // main.cpp now uses a self-pipe: the handler writes one byte and a dedicated watcher
    // thread performs the teardown. stop() therefore CANNOT run on a spark thread, and all
    // of that machinery is deleted. Do not re-add it — fix the caller instead.
    //
    // What REMAINS necessary, and must not be simplified away: lifecycle_mu_ +
    // teardown_complete_. Agent::stop() on the Windows SCM control thread genuinely races
    // ~SparkEngine on main, which is a real cross-thread hazard independent of signals.
    //
    // lifecycle_mu_ is held for the WHOLE teardown. It makes the teardown_complete_
    // early-out below a COMPLETION barrier rather than a bare flag check: a second stop()
    // (or ~SparkEngine, which calls stop()) blocks HERE until the in-flight teardown has
    // finished, then sees teardown_complete_ and returns having genuinely waited.
    //
    // Without it, the loser returned immediately while the winner was still inside
    // wheel_thread_.join() / m->stop() — so ~SparkEngine could run on to
    // ~std::thread(joinable) → std::terminate, and destroy mechanisms_ out from under
    // the thread still calling m->stop() on them → use-after-free. Reachable for real:
    // Agent::stop() runs on the Windows SCM control thread (service_win.cpp
    // handler_ex) concurrently with the main thread's shutdown. Gate-3 B3.
    //
    // SAME-THREAD RE-ENTRY cannot happen: none of the three callers above can already be
    // inside stop() on its own thread (the nested ScopeExit/destructor calls are
    // SEQUENTIAL — the lock is released between them, and the second finds
    // teardown_complete_ set). The re-entry guard that once sat here existed only for the
    // signal-handler path and is deleted with it.
    //
    // #2050: the teardown body below now lives in teardown_locked(), factored out so
    // start()'s own rollback guard can drive the identical sequence on a startup
    // failure (that guard requires only that lifecycle_mu_ already be held — see
    // teardown_locked()'s own doc comment in the header). stop() is otherwise
    // unchanged in shape: acquire lifecycle_mu_ for the WHOLE operation, run the
    // teardown, and never let an exception escape (the catch below).
    std::lock_guard life(lifecycle_mu_);
    teardown_locked();
} catch (...) {
    // stop() is noexcept and is called from ~SparkEngine. A throwing teardown
    // (std::system_error from a join, bad_alloc from the consumer map, or spdlog
    // itself) must not std::terminate the agent for an observe-only subsystem —
    // that would defeat the very degrade-to-no-spark guard in agent.cpp that this
    // engine's boot failure path depends on (Gate-3 cpp-expert SHOULD-1).
    //
    // LOUD, not silent (Gate-8 security-guardian): a swallowed teardown failure means a
    // mechanism may not have released its OS handles. teardown_complete_ stays FALSE, so
    // the next caller re-runs the teardown rather than latching the failure away. The log
    // is itself wrapped — spdlog can throw, and a throw from this last-resort handler
    // would re-open the terminate hole we are closing.
    //
    // HONEST SCOPE OF THE RETRY (Gate-8 round 2): re-running stop() re-drives the wheel
    // join (joinable()-guarded, so no double-join) and the mechanism stop()s (idempotent).
    // It CANNOT re-drive the consumer phase: consumers_ is swapped into a local BEFORE the
    // signal/await loops, so a throw there loses them and the retry finds nothing to await.
    // At rung 1 that phase is a no-op (no consumer is ever registered), but the retry
    // guarantee must not be over-claimed for rung 2, which is when consumers arrive.
    try {
        spdlog::error("SparkEngine::stop() threw during teardown — OS handles may not have "
                      "been released; the wheel + mechanism teardown will be re-run on "
                      "destruction (the consumer phase, if reached, cannot be re-run)");
    } catch (...) {
    }
}

void SparkEngine::teardown_locked() {
    // Caller (stop(), or start()'s rollback guard) already holds lifecycle_mu_ for
    // the whole of this call — see this function's doc comment in the header for the
    // full contract, including why it may throw and how each of the two callers
    // contains that.

    // 1) Stop the watcher side first so nothing new is produced.
    //
    // The early-out is on teardown_complete_, NOT on stopped_. They mean different
    // things and conflating them was a regression in this very fix (Gate-8
    // security-guardian): stopped_ latches "accept no new work" BEFORE the risky
    // teardown below (joins, map ops, spdlog — all of which can throw). Early-returning
    // on stopped_ meant a throw mid-teardown made stop() report success having torn down
    // nothing past the throw, AND made every later stop() — including ~SparkEngine's —
    // a no-op. The destructor would then destroy a still-joinable wheel_thread_
    // (std::terminate) and mechanisms_ with live threads (use-after-free): exactly the
    // outcomes noexcept was added to prevent, converted from loud to silent.
    //
    // teardown_complete_ is set ONLY after the teardown actually finishes, so a failed
    // teardown is retried by the next caller (in practice the destructor) instead of
    // being latched away.
    {
        std::lock_guard lk(mu_);
        if (teardown_complete_)
            return;
        stopped_ = true; // no new consumers / arms / registrations from here
        running_ = false;
    }
    wheel_cv_.notify_all();
    // SELF-JOIN is unreachable: stop() never runs on a spark thread (see the caller
    // inventory at the top of stop()), and start()'s rollback guard runs on the same
    // thread that called start() — never the wheel thread it just spawned — so
    // joining the wheel thread from itself — std::system_error
    // (resource_deadlock_would_occur) out of a noexcept fn — cannot occur. joinable()
    // guards the never-started and already-torn-down cases only.
    if (wheel_thread_.joinable())
        wheel_thread_.join();

    // 1b) #2815: wait — BOUNDED — for every caller already inside a post-mu_ mechanism
    // window (disarm / teardown_arm_race / unregister_consumer / arm_impl's watch) to
    // leave it, before step 2 starts tearing those same mechanisms down. The locked
    // block above has already flipped running_ AND stopped_; disarm/teardown_arm_race/
    // arm_impl gate their own entry on those under mu_ BEFORE resolving a mechanism, so
    // no NEW caller can arm a lease there from here on. unregister_consumer() gates on
    // consumers_ membership instead, which this function doesn't empty until step 3
    // below — a call landing in this window CAN still arm a lease, but that is NOT the
    // same as an unwatch() racing a concurrently-stopping mechanism (governance Gate 8
    // cpp-expert finding, re-correcting an earlier draft of this paragraph that implied
    // exactly that race): unregister_consumer()'s own to_unwatch collection is ALSO
    // running_-gated, so a call landing here collects nothing and its post-mu_ unwatch
    // loop runs zero times. What's genuinely different about door 3 is narrower — see
    // the header's TeardownLease doc for the full account. Either way this wait still
    // counts every caller genuinely in flight; only the "set that only shrinks" framing
    // is uniform across three of the four doors, not all four.
    //
    // BUDGET NOTE (governance Gate 6 sre finding D1): this wait draws on the same
    // consumer_join_budget_ms_ as step 3's consumer join below, sequentially — so
    // SparkEngine::stop()'s own worst-case contribution to the agent's total shutdown
    // wall time roughly DOUBLES versus before this fix (default ~2s -> ~4s) when a
    // mechanism teardown is genuinely still in flight. Checked against
    // ShutdownDeadlineGuard's 20s grace and the composed ~40s figure documented at
    // agent.cpp's kShutdownDeadlineGrace (service_win.cpp has its own prior-incident
    // writeup of exactly this class of uncosted budget-stacking, PR #3737) — this
    // addition fits comfortably inside both. Recorded here so the next person who
    // changes a shutdown budget in this area has the current total already in hand.
    //
    // BOUNDED, AND IT PROCEEDS ON EXPIRY. stop() is called from Agent::stop() and from
    // the Windows SCM control thread; it may never become a place a shutdown can hang,
    // which is the same rule that makes the consumer join bounded (UP-1 / #1311). This
    // wait is therefore a determinism/API-contract nicety - "stop() returned" should
    // normally mean "nothing is still inside the engine" - and NOT the safety mechanism.
    // The safety mechanism is ~SparkEngine's UNBOUNDED wait, which is what actually
    // prevents the members from being freed under a parked caller.
    //
    // Budget: consumer_join_budget_ms_, reusing the existing shutdown budget (and its
    // test seam) rather than inventing a second one.
    if (!wait_teardown_leases(inflight_teardowns_,
                              std::chrono::milliseconds(
                                  consumer_join_budget_ms_.load(std::memory_order_relaxed)))) {
        teardown_join_timeouts_.fetch_add(1, std::memory_order_relaxed);
        // Contained: spdlog allocates, and this is inside a noexcept teardown whose
        // remaining steps (mechanism stop, consumer join) must still run.
        try {
            spdlog::warn("SparkEngine::stop(): a mechanism teardown was still in flight after "
                         "the shutdown budget — proceeding; a late unwatch() may now reach an "
                         "already-stopped mechanism (~SparkEngine still waits for it before "
                         "freeing anything)");
        } catch (...) {
        }
    }

    // 2) Stop event-driven mechanisms (producers, like the wheel) BEFORE the
    // consumer threads they feed — a mechanism must quiesce before its downstream
    // consumers. Iterating without mu_ is safe because lifecycle_mu_ (held by the
    // caller) excludes register_mechanism() — the ONLY writer of mechanisms_. The
    // previous justification ("structurally stable post-start — no concurrent
    // registration") was false during the boot window: the main thread registers
    // while the SCM control thread can already be in stop(). Gate-4 UP-1.
    //
    // #2050: PER-ITERATION isolation. One mechanism's stop() throwing must not skip
    // every mechanism after it in map order — the previous shape let a single
    // throwing mechanism starve every other mechanism's teardown for the whole pass,
    // not just its own. Each call is individually contained; a throw is counted
    // (mechanisms_stopped_cleanly, below), logged (its own catch-all, so a logging
    // failure cannot mask the original mechanism-stop failure or abort the remaining
    // mechanisms), and the loop proceeds to the NEXT mechanism regardless.
    // teardown_complete_ (step 3 below) is set ONLY when this whole pass — every
    // mechanism included — completed without throwing, so a mechanism that failed
    // here is retried (idempotently, per the interface contract) on the next pass.
    //
    // What this does NOT prove: producer quiescence. A caught exception from
    // m->stop() says nothing about whether that mechanism's producer thread(s)
    // actually stopped — emit_event()/report_fault() don't reject calls just because
    // stopped_ is true. Positively resolving that is deliberately out of scope here;
    // it is tracked as a separate follow-up (extending the F3 producer-thread
    // counter to cover mechanism producer-thread lifetime, referencing #2050).
    bool mechanisms_stopped_cleanly = true;
    for (auto& [type, m] : mechanisms_) {
        try {
            m->stop();
        } catch (...) {
            mechanisms_stopped_cleanly = false;
            try {
                spdlog::error("SparkEngine::stop(): mechanism type {} threw during stop() — "
                              "its OS handles may not have been released; continuing "
                              "teardown of the remaining mechanisms, and this one will be "
                              "retried on the next teardown pass",
                              spark_type_token(type));
            } catch (...) {
            }
        }
    }

    // 3) Stop consumer dispatch threads (bounded join, detach-if-hung — UP-1;
    // leftovers dropped + counted).
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers;
    {
        std::lock_guard lk(consumers_mu_);
        consumers.swap(consumers_);
    }
    // Two-phase so N hung consumers cost ~1×budget total, not N×budget (UP2-3):
    // signal every consumer to stop first, THEN await them all against ONE
    // shared deadline.
    for (auto& [id, consumer] : consumers)
        signal_stop(consumer);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(consumer_join_budget_ms_.load(
                              std::memory_order_relaxed));
    for (auto& [id, consumer] : consumers)
        await_consumer(consumer, deadline);
    {
        std::lock_guard lk(mu_);
        // ONLY here, and ONLY on a fully clean mechanism-teardown pass — a throw
        // above (before reaching here) or a per-mechanism failure this pass (step 2)
        // leaves this false, so the next stop() (in practice ~SparkEngine's) retries
        // the teardown instead of latching an incomplete pass away as done.
        if (mechanisms_stopped_cleanly)
            teardown_complete_ = true;
    }
    if (mechanisms_stopped_cleanly) {
        spdlog::info("SparkEngine stopped");
    } else {
        spdlog::warn("SparkEngine::stop(): teardown incomplete this pass — at least one "
                     "mechanism failed to stop cleanly; the next stop() call retries");
    }
}

bool SparkEngine::is_running() const noexcept {
    std::lock_guard lk(mu_);
    return running_;
}

// ── Wheel ─────────────────────────────────────────────────────────────────────

void SparkEngine::wheel_loop() {
    std::unique_lock lk(mu_);
    // Snapshot the disk reader once: the seam contract is set-then-start, and a
    // stable local keeps the processing path data-race-free without mu_.
    const DiskReaderFn disk_reader = disk_reader_;
    while (!stopped_) {
        // Earliest scheduled deadline (O(n) scan — see file header).
        std::optional<std::chrono::steady_clock::time_point> next;
        for (const auto& [key, armed] : armed_) {
            if (armed.scheduled && (!next || armed.next_due < *next))
                next = armed.next_due;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!next) {
            wheel_cv_.wait(lk);
            continue;
        }
        if (*next > now) {
            wheel_cv_.wait_until(lk, *next);
            continue; // re-evaluate: stop / arm / disarm may have changed the world
        }

        // Collect everything due; process + deliver with mu_ RELEASED.
        struct DueItem {
            std::string key;
            SparkSpec spec;
            std::uint64_t cadence_ms{0};
            bool latched{false};
        };
        std::vector<DueItem> due;
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled && armed.next_due <= now)
                due.push_back({key, armed.spec, armed.cadence_ms, armed.disk_latched});
        }
        lk.unlock();
        for (auto& item : due) {
            SparkFireDecision decision;
            switch (item.spec.type) {
            case SparkType::Interval:
                decision = interval_process_due(item.cadence_ms, now);
                break;
            case SparkType::Startup:
                decision = startup_process_due();
                break;
            case SparkType::Disk:
                decision = disk_process_due(std::get<DiskSparkParams>(item.spec.params),
                                            item.cadence_ms, item.latched, disk_reader, now);
                break;
            default:
                continue; // event-driven types never sit on the wheel
            }

            // Commit state; the spark may have been disarmed while we processed.
            std::optional<SparkEvent> event;
            std::vector<Subscriber> subs;
            lk.lock();
            auto it = armed_.find(item.key);
            if (it != armed_.end()) {
                Armed& armed = it->second;
                armed.disk_latched = item.latched;
                if (decision.reschedule)
                    armed.next_due = *decision.reschedule;
                else
                    armed.scheduled = false;
                if (decision.emit) {
                    SparkEvent ev;
                    ev.key = item.key;
                    ev.type = armed.spec.type;
                    ev.seq = ++armed.seq;
                    ev.at = std::chrono::system_clock::now();
                    ev.data = std::move(decision.data);
                    event = std::move(ev);
                    if (armed.spec.type == SparkType::Startup) {
                        // One-shot semantics are PER SUBSCRIBER: deliver only to
                        // those still pending, so a late arm's re-fire can never
                        // hand an earlier subscriber a second "startup".
                        for (auto& s : armed.subs) {
                            if (s.startup_pending) {
                                subs.push_back(s);
                                s.startup_pending = false;
                            }
                        }
                    } else {
                        subs = armed.subs; // fan-out snapshot
                    }
                }
            }
            lk.unlock();
            if (event) {
                events_total_.fetch_add(1, std::memory_order_relaxed);
                deliver(*event, subs);
            }
            // Loop tail: mu_ is RELEASED here. The next iteration must compute its
            // decision (which does filesystem I/O for Disk) lock-free, so we do
            // NOT re-lock per item — re-locking inside the loop double-locks the
            // next iteration's commit lk.lock() (std::system_error, uncaught on
            // the wheel thread → terminate) whenever ≥2 sparks are due in one
            // scan. Re-acquire ONCE below for the outer wheel scan.
        }
        lk.lock(); // re-hold for the next wheel scan (reads armed_ under mu_)
    }
}

// ── Delivery ──────────────────────────────────────────────────────────────────

void SparkEngine::emit_event(const std::string& key, SparkData data) {
    SparkEvent event;
    std::vector<Subscriber> subs;
    {
        std::lock_guard lk(mu_);
        auto it = armed_.find(key);
        if (it == armed_.end())
            return; // disarmed between the mechanism's fire and here — TRAP 2 safe
        Armed& armed = it->second;
        event.key = key;
        event.type = armed.spec.type;
        event.seq = ++armed.seq;
        event.at = std::chrono::system_clock::now();
        event.data = std::move(data);
        subs = armed.subs; // fan-out snapshot (event-driven: all subs, no startup logic)
    }
    // mu_ released before delivery — an inline consumer that re-arms takes mu_.
    events_total_.fetch_add(1, std::memory_order_relaxed);
    deliver(event, subs);
}

void SparkEngine::report_fault(const std::string& key, bool faulted, std::string_view reason) {
    SparkEvent ev;
    std::vector<Subscriber> subs;
    {
        std::lock_guard lk(mu_);
        auto it = armed_.find(key);
        if (it == armed_.end())
            return; // disarmed between the mechanism's report and here — unchanged
        if (it->second.faulted == faulted)
            return; // no edge — idempotent per state — unchanged
        it->second.faulted = faulted;
        if (faulted) {
            watch_faults_.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: watch '{}' FAULTED — armed but not watching ({})",
                         ::yuzu::log_key_token(key), reason);
        } else {
            spdlog::info("SparkEngine: watch '{}' recovered", ::yuzu::log_key_token(key));
        }
        // #2818: the faulted-flag flip and its log/counter above already committed —
        // contained the same way as arm_impl's Lost snapshot: a bad_alloc here (the
        // string copies) costs a lost notification, never an unwound state flip.
        try {
            ev.key = key;
            ev.type = it->second.spec.type;
            ev.seq = ++it->second.seq;
            ev.at = std::chrono::system_clock::now();
            ev.kind = faulted ? SparkEventKind::Faulted : SparkEventKind::Recovered;
            ev.detail.assign(reason);
            subs = it->second.subs;
        } catch (...) {
            subs.clear();
        }
    }
    if (!subs.empty()) {
        try {
            deliver(ev, subs); // mu_ already released — safe for an Inline handler to
                                // re-arm/re-query this same type
        } catch (...) {
        }
    }
}

void SparkEngine::report_established(const std::string& key, SparkIncarnation incarnation,
                                     std::chrono::steady_clock::time_point at,
                                     SparkCoverage coverage) {
    std::lock_guard lk(mu_);
    auto it = armed_.find(key);
    // Identity check FIRST (H1): a report whose incarnation no longer names
    // this key's CURRENT watch is a stale report against a superseded or
    // torn-down subscription — drop it silently. This is also the case a
    // disarmed/never-armed key hits (it == end()).
    if (it == armed_.end() || it->second.incarnation != incarnation)
        return;
    // Unconditional coverage assignment (round-4 MF1): the cache always
    // reflects the mechanism's LAST-reported value, whatever it is — the
    // mechanism side stages every transition unconditionally, so there is no
    // "edge" to gate on here either.
    it->second.coverage = coverage;
    // First-wins established_at (spark.hpp's SubscriptionEstablishment doc
    // comment): stamped once per incarnation, only on a Notification
    // transition, never re-stamped by a later recovery.
    if (coverage == SparkCoverage::Notification && !it->second.established_at)
        it->second.established_at = at;
}

void SparkEngine::deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs) {
    for (const auto& sub : subs) {
        // #2818: one key-level condition fans out to potentially several
        // differently-subscribed consumers, so a single shared SparkEvent object
        // cannot itself name "the" subscription — stamp it per-recipient. Copy only
        // for a non-Fired kind: the Fired hot path (µs-median Inline SLO) must stay
        // untouched, and subscription_id is meaningless for Fired anyway.
        const bool needs_copy = ev.kind != SparkEventKind::Fired;
        SparkEvent stamped;
        if (needs_copy) {
            stamped = ev;
            stamped.subscription_id = sub.id;
        }
        const SparkEvent& out = needs_copy ? stamped : ev;
        if (sub.tier == SparkTier::Inline) {
            // ADR §3 watchdog: every inline call is timed; the counters feed the
            // Stage-11 resource gate. Handlers must not throw — but the watcher
            // must survive a contract breach, so catch + count anyway.
            const auto t0 = std::chrono::steady_clock::now();
            try {
                sub.inline_fn(out);
            } catch (const std::exception& e) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach): {}",
                              ::yuzu::log_key_token(out.key), e.what());
            } catch (...) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach)",
                              ::yuzu::log_key_token(out.key));
            }
            const auto us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count());
            inline_calls_.fetch_add(1, std::memory_order_relaxed);
            inline_us_total_.fetch_add(us, std::memory_order_relaxed);
            if (us > 100)
                inline_over_100us_.fetch_add(1, std::memory_order_relaxed);
            if (us > 10'000)
                inline_over_10ms_.fetch_add(1, std::memory_order_relaxed);
            std::uint64_t prev = inline_us_max_.load(std::memory_order_relaxed);
            while (us > prev && !inline_us_max_.compare_exchange_weak(prev, us,
                                                                      std::memory_order_relaxed)) {
            }
            continue;
        }
        // Queued: never block the watcher. Full queue → drop the OLDEST (the
        // consumer keeps seeing the most recent state) and count it.
        std::shared_ptr<Consumer> consumer;
        {
            std::lock_guard lk(consumers_mu_);
            auto it = consumers_.find(sub.consumer);
            if (it != consumers_.end())
                consumer = it->second;
        }
        if (!consumer)
            continue; // consumer unregistered between fan-out snapshot and here
        {
            std::lock_guard lk(consumer->mu);
            if (consumer->stopping)
                continue;
            if (consumer->queue.size() >= consumer->cap) {
                consumer->queue.pop_front();
                delivery_->dropped.fetch_add(1, std::memory_order_relaxed);
                spdlog::warn("SparkEngine: consumer '{}' queue full (cap {}) — dropped oldest",
                             consumer->name, consumer->cap);
            }
            consumer->queue.push_back(out);
        }
        consumer->cv.notify_one();
    }
}

// ── Stats / seams ─────────────────────────────────────────────────────────────

SparkEngineStats SparkEngine::stats() const {
    SparkEngineStats s;
    {
        std::lock_guard lk(mu_);
        s.armed_sparks = armed_.size();
        s.armed_faulted = static_cast<std::uint64_t>(
            std::count_if(armed_.begin(), armed_.end(), [](const auto& kv) {
                return kv.second.faulted;
            }));
        s.subscriptions = sub_keys_.size();
        // Watcher units while running: the wheel + one per registered event-driven
        // mechanism (a mechanism may itself run a small pool — this is a unit
        // count, not an OS-thread count; hence _units, not _threads).
        s.watcher_units = running_ ? (1 + mechanisms_.size()) : 0;
        // Sum every mechanism's own counters (#1979). mechanisms_ is
        // structurally stable post-registration and stats() is atomic-only
        // (never shares a lock with watch/unwatch/stop), so calling it here
        // under mu_ is safe — no blocking, no reentrancy into the engine.
        for (const auto& [type, m] : mechanisms_) {
            const auto ms = m->stats();
            s.mech_retiring += ms.retiring;
            s.mech_retiring_cap += ms.retiring_cap;
            s.mech_watch_rejected_total += ms.watch_rejected_total;
            s.mech_quarantined_total += ms.quarantined_total;
            s.mech_slow_op_total += ms.slow_op_total;
        }
    }
    {
        std::lock_guard lk(consumers_mu_);
        s.consumers = consumers_.size();
    }
    s.watch_faults_total = watch_faults_.load(std::memory_order_relaxed);
    s.arm_race_unwatch_failures_total =
        arm_race_unwatch_failures_.load(std::memory_order_relaxed);
    s.disarm_unwatch_failures_total = disarm_unwatch_failures_.load(std::memory_order_relaxed);
    s.teardown_join_timeouts_total = teardown_join_timeouts_.load(std::memory_order_relaxed);
    s.subscription_lost_total = subscription_lost_.load(std::memory_order_relaxed);
    s.consumer_threads_detached = consumer_threads_detached_.load(std::memory_order_relaxed);
    s.events_total = events_total_.load(std::memory_order_relaxed);
    s.queued_delivered_total = delivery_->delivered.load(std::memory_order_relaxed);
    s.queued_dropped_total = delivery_->dropped.load(std::memory_order_relaxed);
    s.consumer_errors_total = delivery_->errors.load(std::memory_order_relaxed);
    s.inline_calls_total = inline_calls_.load(std::memory_order_relaxed);
    s.inline_errors_total = inline_errors_.load(std::memory_order_relaxed);
    s.inline_us_total = inline_us_total_.load(std::memory_order_relaxed);
    s.inline_us_max = inline_us_max_.load(std::memory_order_relaxed);
    s.inline_over_100us_total = inline_over_100us_.load(std::memory_order_relaxed);
    s.inline_over_10ms_total = inline_over_10ms_.load(std::memory_order_relaxed);
    return s;
}

SubscriptionHealth SparkEngine::subscription_health(SubscriptionId id) const {
    std::lock_guard lk(mu_);
    auto sit = sub_keys_.find(id);
    if (sit == sub_keys_.end())
        return SubscriptionHealth::Dead;
    auto ait = armed_.find(sit->second);
    // armed_ missing the key sit->second points at cannot happen absent a bug
    // (sub_keys_/armed_ are kept in lockstep everywhere they're mutated), but
    // treat it as Dead rather than UB if it ever does.
    if (ait == armed_.end())
        return SubscriptionHealth::Dead;
    return ait->second.faulted ? SubscriptionHealth::Faulted : SubscriptionHealth::Healthy;
}

std::optional<SubscriptionEstablishment>
SparkEngine::subscription_establishment(SubscriptionId id) const {
    std::lock_guard lk(mu_);
    auto sit = sub_keys_.find(id);
    if (sit == sub_keys_.end())
        return std::nullopt;
    auto ait = armed_.find(sit->second);
    if (ait == armed_.end())
        return std::nullopt;
    SubscriptionEstablishment out{ait->second.armed_at, ait->second.established_at,
                                  ait->second.coverage};
    // An inert mechanism may have dropped a coverage transition; do not trust the cache.
    if (auto mit = mechanisms_.find(ait->second.spec.type);
        mit != mechanisms_.end() && mit->second->stats().inert)
        out.coverage = SparkCoverage::None;
    return out;
}

std::map<SparkType, SparkMechanismStats> SparkEngine::stats_by_type() const {
    // Same shape as the mech_* sum in stats() (lines above) but the SparkType key
    // is preserved instead of folded away. mu_-only (never shares a lock with
    // watch/unwatch/stop) and m->stats() is atomic-only, so this cannot block or
    // reenter the engine — identical safety to the stats() sum loop.
    std::map<SparkType, SparkMechanismStats> out;
    std::lock_guard lk(mu_);
    for (const auto& [type, m] : mechanisms_)
        out.emplace(type, m->stats());
    return out;
}

void SparkEngine::set_disk_reader_for_test(DiskReaderFn reader) {
    std::lock_guard lk(mu_);
    disk_reader_ = std::move(reader);
}

void SparkEngine::set_cadence_floor_for_test(std::uint64_t floor_ms) {
    cadence_floor_ms_.store(floor_ms, std::memory_order_relaxed);
}

void SparkEngine::set_consumer_join_budget_for_test(std::uint64_t ms) {
    consumer_join_budget_ms_.store(ms, std::memory_order_relaxed);
}

void SparkEngine::set_register_race_hook_for_test(std::function<void()> hook) {
    register_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_race_hook_for_test(std::function<void()> hook) {
    arm_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_precheck_race_hook_for_test(std::function<void()> hook) {
    arm_precheck_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_disarm_race_hook_for_test(std::function<void()> hook) {
    disarm_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_on_start_hook_for_test(std::function<void()> hook) {
    on_start_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_fault_hook_for_test(std::function<void(int)> hook) {
    arm_fault_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_start_fault_hook_for_test(std::function<void(int)> hook) {
    start_fault_hook_for_test_ = std::move(hook);
}

} // namespace yuzu::agent
