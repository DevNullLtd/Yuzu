#pragma once

/// @file guardian_reconcile_gate.hpp
/// Per-agent claim map + admission ordering for the Guardian heartbeat reconcile push
/// (#5513).
///
/// WHY THIS CLASS EXISTS. The reconcile flow (`GuardianReconcileFlow::run`, wired through
/// `set_guardian_reconcile_fn`) must, for an
/// agent reporting a policy generation behind the server's, decide one of four things. The
/// ORDER of the checks inside `decide()` is the safety invariant, and it only holds if the
/// whole sequence runs under ONE mutex:
///
///     1. converged?    agent_gen >= current          -> Converged (a claim at least
///                                                       min_interval old is erased; a
///                                                       younger one is KEPT)
///     2. peek claim    claim younger than min_interval -> RateLimited (budget NOT consulted)
///     3. in-flight cap in_flight >= max_in_flight      -> Shed (claim NOT written)
///     4. try_admit()   budget refuses                  -> Shed (claim NOT written)
///     5. write claim   (now)                           -> Admit
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
/// WHY A CONVERGED HEARTBEAT KEEPS A YOUNG CLAIM. The pre-#5513 map was never erased, so an
/// agent got at most one push per `min_interval`. An agent that alternates between
/// reporting generation 0 (the boot re-arm catch-up report, see the agent's back-off) and
/// the current generation would, if every converged heartbeat erased its claim, be admitted
/// on every second heartbeat: a rate-limit bypass that floods the audit log and starves the
/// budget of honest agents. So a converged heartbeat erases the claim only once it is at
/// least `min_interval` old (it can no longer limit anything), and a claim younger than
/// that stays so a later regression is still RateLimited.
///
/// BOUNDED MEMORY. The map was never erased (unbounded over agent-id churn). It is now
/// bounded two ways: `decide()` erases an expired claim as soon as the agent reports a
/// generation at or ahead of the server's (one map operation per converged heartbeat; this
/// does the bulk), and `sweep()` erases entries older than `2 * min_interval`, called from
/// an existing maintenance tick. The sweep is a backstop, not a fast path: one bounded call
/// scans about 16384 units and a full cycle over ~500k claims therefore takes ~90 ticks
/// (~20 minutes at a 15 s tick), so a stale claim can outlive `2 * min_interval` by a long
/// way. Memory stays bounded by fleet size either way.
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
/// IN-FLIGHT CAP. `begin_admitted()` counts a push as in flight until its `Scoped` is
/// destroyed; `decide()` sheds while that count is at `max_in_flight` so a slow store
/// cannot pin an unbounded number of heartbeat threads inside admitted pushes (the time
/// budget only reacts after pushes FINISH and debit). The count is taken at
/// `begin_admitted()`, not at `decide()`, so a caller that decides but never begins (tests)
/// cannot leak a slot; the cap is therefore soft by the number of threads between the two
/// calls, which is bounded by the heartbeat thread count.
///
/// DEBIT. A push is charged `max(elapsed - excluded, min_cost)`. `Scoped::exclude()` removes
/// ONLY the time this push spent BLOCKED waiting on a rule-set load that ANOTHER thread was
/// running (that wait is not this push's cost and would otherwise starve the budget when one
/// slow load has many waiters). Everything else is charged: the fresh policy-generation read,
/// the per-agent scope reads, and the push's own rule-set load when it is the thread that
/// runs it (the loader's `list_rules` can take seconds, and that cost is exactly what the
/// budget exists to bound). `min_cost` (1 ms) keeps fast-failing degraded pushes from running
/// at the pure count ceiling and bounds the rate of ABORTED audit rows.
///
/// A CLAIM IS NEVER RELEASED. An Admit writes the claim and nothing here removes it except
/// convergence (once at least `min_interval` old) and the sweep. In particular a push that
/// ends without sending (the session is gone, or a store read failed) keeps its claim: an
/// agent heartbeating generation 0 in a loop would, with a "forget the claim when nothing was
/// sent" API, turn every heartbeat into a fresh admission and let one credential drain the
/// shared budget. With the claim kept that agent costs at most one admission per
/// `min_interval`. (A Registered-but-not-yet-Subscribed agent HAS a session, because
/// `register_agent` installs it at Register: it takes the full push path and the send fails.)
///
/// ALLOCATION FAILURE. `decide()` may throw `std::bad_alloc` while inserting the claim,
/// after `try_admit()` succeeded. Nothing is leaked; the budget has counted one admission
/// whose push never ran and no claim exists, so the agent simply retries on its next
/// heartbeat.
///
/// Thread-safe: one internal mutex guards the map and cursor.

#include "guardian_reconcile_budget.hpp"

#include <algorithm>
#include <atomic>
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

/// Gate tuning (namespace scope so it can be a default argument).
struct GuardianReconcileGateOptions {
    /// Admitted-but-unfinished pushes at which `decide()` sheds. 256 is far above the
    /// heartbeat thread count of a healthy replica; reaching it means pushes are stuck.
    std::size_t max_in_flight{256};
    /// Floor on the debit of an admitted push.
    std::chrono::nanoseconds min_cost{std::chrono::milliseconds(1)};
    /// Upper bound on the constructor's `claims_.reserve()`; 2^20 entries (about 8 MiB of
    /// buckets). Tests that exercise `sweep()` set 0 so the bucket count tracks the table.
    std::size_t max_reserve{std::size_t{1} << 20};
};

class GuardianReconcileGate {
public:
    using Options = GuardianReconcileGateOptions;
    enum class Decision { Converged, RateLimited, Shed, Admit };
    /// Why `decide()` returned `Shed` (reported through the optional out-parameter).
    enum class ShedCause { None, Budget, InFlightCap };

    using ClockType = std::chrono::steady_clock;
    /// Null selects `steady_clock::now`.
    using Clock = std::function<ClockType::time_point()>;

    /// Defaults for `sweep()`; one call erases at most `kDefaultSweepMaxErase` entries and
    /// scans at most about `kDefaultSweepMaxScan` units (a unit is one bucket visited or one
    /// entry examined; the last bucket's chain may overshoot by its length).
    static constexpr std::size_t kDefaultSweepMaxErase = 4096;
    static constexpr std::size_t kDefaultSweepMaxScan = 16384;

    /// The stored `min_interval` is clamped to [0, kMaxMinInterval]. The sweep compares a clock
    /// age (nanoseconds) with `2 * min_interval`; an unclamped extreme value overflows that
    /// signed arithmetic (and a huge one makes every claim look fresh forever, or, on a
    /// platform where the multiply wraps, makes a fresh claim look stale and lets the next
    /// heartbeat through). One year is far above any realistic interval and keeps both the
    /// doubling and the conversion to nanoseconds inside 64 bits.
    static constexpr std::chrono::seconds kMaxMinInterval{365LL * 24 * 3600};
    [[nodiscard]] static constexpr std::chrono::seconds sanitize_interval(
        std::chrono::seconds v) noexcept {
        return std::clamp(v, std::chrono::seconds{0}, kMaxMinInterval);
    }

    /// `budget` must outlive the gate.
    explicit GuardianReconcileGate(GuardianReconcileBudget& budget, Clock clock = {},
                                   std::chrono::seconds min_interval = std::chrono::seconds(25),
                                   Options opts = {})
        : budget_(budget),
          clock_(clock ? std::move(clock) : Clock{[] { return ClockType::now(); }}),
          min_interval_(sanitize_interval(min_interval)), opts_(opts) {
        // Sized for the steady state (admissions per second over two intervals, the sweep
        // horizon) so the table does not rehash under mu_ on the heartbeat path; a rehash of
        // a 500k-entry table is a ~50 ms stall with the mutex held.
        const auto per_s = static_cast<std::size_t>(budget_.config().max_per_s);
        // `min_interval_` is already clamped, so the doubling cannot overflow.
        const auto horizon = static_cast<std::size_t>(
            std::max<long long>(1, 2 * static_cast<long long>(min_interval_.count())));
        claims_.reserve(std::min<std::size_t>(per_s * horizon, opts_.max_reserve));
    }

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
        Scoped(Scoped&& o) noexcept
            : gate_(std::exchange(o.gate_, nullptr)), start_(o.start_), excluded_(o.excluded_) {}
        Scoped& operator=(Scoped&& o) noexcept {
            if (this != &o) {
                finish();
                gate_ = std::exchange(o.gate_, nullptr);
                start_ = o.start_;
                excluded_ = o.excluded_;
            }
            return *this;
        }
        ~Scoped() { finish(); }

        /// Exclude `d` from the debit. `d` must be ONLY time this push spent blocked waiting
        /// on a load another thread was running; time spent doing work itself (including
        /// running a load) is the push's cost and must not be passed. Negative values are
        /// ignored. A no-op on a moved-from object.
        void exclude(std::chrono::nanoseconds d) noexcept {
            if (d.count() > 0)
                excluded_ += d;
        }

    private:
        friend class GuardianReconcileGate;
        Scoped(GuardianReconcileGate* gate, ClockType::time_point start)
            : gate_(gate), start_(start) {}

        void finish() noexcept {
            GuardianReconcileGate* g = std::exchange(gate_, nullptr);
            if (g == nullptr)
                return;
            try {
                const auto measured = g->clock_() - start_ - excluded_;
                g->complete(std::max<std::chrono::nanoseconds>(measured, g->opts_.min_cost));
            } catch (...) {
                // A destructor must not throw; a failed debit only makes the budget
                // slightly more permissive for one push.
            }
            g->in_flight_.fetch_sub(1, std::memory_order_relaxed);
        }

        GuardianReconcileGate* gate_;
        ClockType::time_point start_;
        std::chrono::nanoseconds excluded_{0};
    };

    /// Decide what to do with a heartbeat from `agent_id` reporting `agent_gen` against the
    /// server's `current`. See the class comment for the ordering invariant.
    ///   Converged   agent_gen >= current: erases the agent's claim IF it is at least
    ///               min_interval old (a younger claim is kept, see the class comment);
    ///               touches nothing else.
    ///   RateLimited a claim younger than min_interval exists; budget NOT consulted.
    ///   Shed        the in-flight cap or the budget refused; the claim is NOT written, no
    ///               other state changes. `cause`, when given, is set to which one (it is
    ///               `None` for every other decision).
    ///   Admit       the claim is written (now); the caller must now run the push and debit it
    ///               (`begin_admitted()` / `complete()`).
    [[nodiscard]] Decision decide(const std::string& agent_id, std::uint64_t agent_gen,
                                  std::uint64_t current, ShedCause* cause = nullptr) {
        if (cause != nullptr)
            *cause = ShedCause::None;
        std::lock_guard lk(mu_);
        const auto now = clock_();
        auto it = claims_.find(agent_id);
        const bool limiting = it != claims_.end() && (now - it->second) < min_interval_;
        if (agent_gen >= current) {
            if (it != claims_.end() && !limiting)
                claims_.erase(it);
            return Decision::Converged;
        }
        if (limiting)
            return Decision::RateLimited;
        if (in_flight_.load(std::memory_order_relaxed) >= opts_.max_in_flight) {
            in_flight_shed_.fetch_add(1, std::memory_order_relaxed);
            if (cause != nullptr)
                *cause = ShedCause::InFlightCap;
            return Decision::Shed;
        }
        if (!budget_.try_admit()) {
            if (cause != nullptr)
                *cause = ShedCause::Budget;
            return Decision::Shed;
        }
        if (it != claims_.end())
            it->second = now;  // find() result is still valid: nothing inserted since
        else
            claims_.emplace(agent_id, now);
        return Decision::Admit;
    }

    /// Debit the admitted push's measured wall time into the budget (exactly as given;
    /// the `min_cost` floor and `exclude()` are applied by `Scoped`).
    void complete(std::chrono::nanoseconds measured) { budget_.debit(measured); }

    /// Start timing an admitted push; the returned object debits on scope exit. Counts the
    /// push as in flight until the returned object is destroyed.
    [[nodiscard]] Scoped begin_admitted() {
        in_flight_.fetch_add(1, std::memory_order_relaxed);
        try {
            return Scoped(this, clock_());
        } catch (...) {
            in_flight_.fetch_sub(1, std::memory_order_relaxed);
            throw;
        }
    }

    /// Pushes between `begin_admitted()` and the destruction of their `Scoped`.
    [[nodiscard]] std::size_t in_flight() const {
        return in_flight_.load(std::memory_order_relaxed);
    }
    /// Sheds caused by the in-flight cap (the budget counts its own in `shed_total()`).
    [[nodiscard]] std::uint64_t in_flight_shed_total() const {
        return in_flight_shed_.load(std::memory_order_relaxed);
    }

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
    /// Bucket count of the claim table (tests: proves the constructor's reserve).
    [[nodiscard]] std::size_t claims_buckets() const {
        std::lock_guard lk(mu_);
        return claims_.bucket_count();
    }

private:
    GuardianReconcileBudget& budget_;
    const Clock clock_;
    const std::chrono::seconds min_interval_;
    const Options opts_;
    std::atomic<std::size_t> in_flight_{0};
    std::atomic<std::uint64_t> in_flight_shed_{0};
    mutable std::mutex mu_;
    std::unordered_map<std::string, ClockType::time_point> claims_;
    std::size_t cursor_{0};
};

}  // namespace yuzu::server
