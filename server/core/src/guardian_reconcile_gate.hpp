#pragma once

/// @file guardian_reconcile_gate.hpp
/// Per-agent claim map + admission ordering for the Guardian heartbeat reconcile push
/// (#5513, Fable opinion sections C and D "claim-map bound").
///
/// WHY THIS CLASS EXISTS. The reconcile lambda in `set_guardian_reconcile_fn` must, for an
/// agent reporting a policy generation behind the server's, decide one of four things. The
/// ORDER of the checks inside `decide()` is the safety invariant, and it only holds if the
/// whole sequence runs under ONE mutex:
///
///     1. converged?    agent_gen >= current          -> Converged (claim erased)
///     2. peek claim    claim younger than min_interval -> RateLimited (budget NOT consulted)
///     3. try_admit()   budget refuses                  -> Shed (claim NOT written)
///     4. write claim   (now)                           -> Admit
///
/// A shed push must never consume the agent's per-agent slot: the agent never receives a
/// push, so no agent-side holdoff is earned, and if the claim had been written first the
/// agent would be rate-limited for `min_interval` after a push that never happened and
/// would lose its turn. Conversely the claim must be written under the same lock as the
/// peek, otherwise two concurrent heartbeats from one agent could both pass the peek and
/// both reconcile (the #1209 hardening this map exists for). The budget is therefore
/// consulted between peek and write, inside the gate's mutex. Lock order is
/// gate mutex -> budget mutex; the budget never calls back into the gate.
///
/// BOUNDED MEMORY. The map was never erased (unbounded over agent-id churn). It is now
/// bounded two ways: `decide()` erases the entry as soon as the agent reports a generation
/// at or ahead of the server's (one map operation per converged heartbeat), and `sweep()`
/// erases entries older than `2 * min_interval`, called from an existing maintenance tick.
/// RETENTION REASONING (recorded because the clock-guarded-retention row may route here):
/// this is an in-memory `steady_clock` cutoff over no store and no durable data. A claim
/// older than `min_interval` can no longer rate-limit anything, so deleting it changes no
/// decision; the `2x` margin only keeps an entry visible slightly longer than it is
/// useful. A clock that jumps cannot cause a wrong bulk delete of live state: `steady_clock`
/// is monotonic, an entry that appears older than it is is merely re-claimed on its next
/// heartbeat, and a clock moving backwards yields a negative age which is never swept.
/// Each `sweep()` call is bounded (entries erased AND units scanned) and resumes from a
/// persistent bucket cursor, so one call never holds the mutex for a whole 500k-entry
/// table. The bucket array of `std::unordered_map` does not shrink on erase; the entry
/// nodes (the dominant cost) are freed.
///
/// CLOCK INJECTION. `Clock` is a `std::function<steady_clock::time_point()>`; null selects
/// the real steady clock. The clock is called under the internal mutex (`decide`, `sweep`)
/// and, in `begin_admitted()`/`Scoped`, without it, so it must be thread-safe and must not
/// call back into this object. The rate-limit comparison is exactly the pre-extraction one:
/// `(now - last) < min_interval` is rate-limited, so a claim exactly `min_interval` old is
/// no longer limiting.
///
/// ALLOCATION FAILURE. `decide()` may throw `std::bad_alloc` while inserting the claim,
/// after `try_admit()` succeeded. Nothing is leaked; the budget has counted one admission
/// whose push never ran and no claim exists, so the agent simply retries on its next
/// heartbeat.
///
/// Thread-safe: one internal mutex guards the map and cursor.

#include "guardian_reconcile_budget.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class GuardianReconcileGate {
public:
    enum class Decision { Converged, RateLimited, Shed, Admit };

    using ClockType = std::chrono::steady_clock;
    /// Null selects `steady_clock::now`.
    using Clock = std::function<ClockType::time_point()>;

    /// Defaults for `sweep()`; one call erases at most `kDefaultSweepMaxErase` entries and
    /// scans at most about `kDefaultSweepMaxScan` units (a unit is one bucket visited or one
    /// entry examined; the last bucket's chain may overshoot by its length).
    static constexpr std::size_t kDefaultSweepMaxErase = 4096;
    static constexpr std::size_t kDefaultSweepMaxScan = 16384;

    /// `budget` must outlive the gate.
    explicit GuardianReconcileGate(GuardianReconcileBudget& budget, Clock clock = {},
                                   std::chrono::seconds min_interval = std::chrono::seconds(25))
        : budget_(budget), clock_(clock ? std::move(clock) : Clock{&ClockType::now}),
          min_interval_(min_interval) {}

    GuardianReconcileGate(const GuardianReconcileGate&) = delete;
    GuardianReconcileGate& operator=(const GuardianReconcileGate&) = delete;

    /// RAII debit of an admitted push. Move-only; the moved-from object is inert. The
    /// destructor charges the wall time elapsed since `begin_admitted()` (same injected
    /// clock) into the budget exactly once, on every exit path including exception unwind.
    /// The gate must outlive it.
    class Scoped {
    public:
        Scoped(const Scoped&) = delete;
        Scoped& operator=(const Scoped&) = delete;
        Scoped(Scoped&& o) noexcept : gate_(std::exchange(o.gate_, nullptr)), start_(o.start_) {}
        Scoped& operator=(Scoped&& o) noexcept {
            if (this != &o) {
                finish();
                gate_ = std::exchange(o.gate_, nullptr);
                start_ = o.start_;
            }
            return *this;
        }
        ~Scoped() { finish(); }

    private:
        friend class GuardianReconcileGate;
        Scoped(GuardianReconcileGate* gate, ClockType::time_point start)
            : gate_(gate), start_(start) {}

        void finish() noexcept {
            GuardianReconcileGate* g = std::exchange(gate_, nullptr);
            if (g == nullptr)
                return;
            try {
                g->complete(g->clock_() - start_);
            } catch (...) {
                // A destructor must not throw; a failed debit only makes the budget
                // slightly more permissive for one push.
            }
        }

        GuardianReconcileGate* gate_;
        ClockType::time_point start_;
    };

    /// Decide what to do with a heartbeat from `agent_id` reporting `agent_gen` against the
    /// server's `current`. See the class comment for the ordering invariant.
    ///   Converged   agent_gen >= current: erases any claim for the agent; touches nothing else.
    ///   RateLimited a claim younger than min_interval exists; budget NOT consulted.
    ///   Shed        the budget refused; the claim is NOT written, no other state changes.
    ///   Admit       the claim is written (now); the caller must now run the push and debit it
    ///               (`begin_admitted()` / `complete()`).
    [[nodiscard]] Decision decide(const std::string& agent_id, std::uint64_t agent_gen,
                                  std::uint64_t current) {
        std::lock_guard lk(mu_);
        if (agent_gen >= current) {
            claims_.erase(agent_id);
            return Decision::Converged;
        }
        const auto now = clock_();
        auto it = claims_.find(agent_id);
        if (it != claims_.end() && (now - it->second) < min_interval_)
            return Decision::RateLimited;
        if (!budget_.try_admit())
            return Decision::Shed;
        if (it != claims_.end())
            it->second = now;  // find() result is still valid: nothing inserted since
        else
            claims_.emplace(agent_id, now);
        return Decision::Admit;
    }

    /// Debit the admitted push's measured wall time into the budget.
    void complete(std::chrono::nanoseconds measured) { budget_.debit(measured); }

    /// Start timing an admitted push; the returned object debits on scope exit.
    [[nodiscard]] Scoped begin_admitted() { return Scoped(this, clock_()); }

    /// Erase claim entries older than `2 * min_interval`. Bounded per call: at most
    /// `max_erase` entries erased and about `max_scan` units scanned (one per bucket visited
    /// plus one per entry examined; the final bucket's chain may overshoot). Resumes from a
    /// persistent bucket cursor, so repeated calls cover the whole table. Returns the number
    /// erased. An entry whose age is not strictly greater than `2 * min_interval` (including
    /// a negative age from a backwards clock) is kept.
    std::size_t sweep(std::size_t max_erase = kDefaultSweepMaxErase,
                      std::size_t max_scan = kDefaultSweepMaxScan) {
        if (max_erase == 0 || max_scan == 0)
            return 0;
        std::lock_guard lk(mu_);
        const std::size_t nb = claims_.bucket_count();
        if (claims_.empty() || nb == 0)
            return 0;
        const auto now = clock_();
        const auto max_age = 2 * min_interval_;

        std::vector<std::string> stale;
        std::size_t units = 0;
        std::size_t buckets_done = 0;
        std::size_t b = cursor_ % nb;
        while (buckets_done < nb && units < max_scan && stale.size() < max_erase) {
            ++units;
            bool complete_bucket = true;
            for (auto it = claims_.cbegin(b); it != claims_.cend(b); ++it) {
                ++units;
                if ((now - it->second) > max_age) {
                    if (stale.size() >= max_erase) {
                        complete_bucket = false;  // revisit this bucket on the next call
                        break;
                    }
                    stale.push_back(it->first);
                }
            }
            if (!complete_bucket)
                break;
            b = (b + 1) % nb;
            ++buckets_done;
        }
        cursor_ = b;
        // Erase never rehashes, so the bucket count and the cursor stay meaningful.
        for (const auto& id : stale)
            claims_.erase(id);
        return stale.size();
    }

    [[nodiscard]] std::size_t claims_size() const {
        std::lock_guard lk(mu_);
        return claims_.size();
    }

private:
    GuardianReconcileBudget& budget_;
    const Clock clock_;
    const std::chrono::seconds min_interval_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, ClockType::time_point> claims_;
    std::size_t cursor_{0};
};

}  // namespace yuzu::server
