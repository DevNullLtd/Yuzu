/**
 * quarantine_serialization.hpp — bounds concurrent execution of the
 * quarantine plugin's mutating actions to one at a time (#3286). Portable,
 * header-only, no OS calls, no subprocess, no plugin ABI dependency: this is
 * a pure concurrency primitive over the C++ standard library only, so
 * test_quarantine_serialization.cpp exercises it directly with no fixture
 * text and no platform guard.
 *
 * Concurrency shape this defends against: every plugin execute() call —
 * quarantine's do_quarantine/do_unquarantine/do_whitelist included — is
 * dispatched onto the agent's shared, bounded thread pool (agent.cpp:2632,
 * `thread_pool_->submit(...)`), and PolicyEvaluator's remediate() path can
 * fire a burst of repeated quarantine dispatches at the same device (e.g. a
 * re-triggered policy evaluation before the first quarantine command has
 * been acknowledged). Without serialization, two concurrent mutations would
 * race on the SAME OS firewall state — two macos_quarantine calls each
 * writing their own temp ruleset and racing over which `pfctl -f` wins, or a
 * do_whitelist "add" reading a whitelist snapshot that a concurrent
 * do_quarantine is simultaneously about to overwrite — producing an
 * inconsistent or silently-clobbered firewall state that no single call's
 * own honest status reporting (Parts A-C of #3283/#3284/#3285) could ever
 * see, because each call only observes its own, individually-correct steps.
 *
 * Why the wait budget is bounded at 2 seconds, not something more generous
 * like 20: every waiting caller occupies a pool worker for the ENTIRE
 * budget, and the pool is shared with every other plugin's dispatch on that
 * agent (heartbeats, Guardian pushes, everything else). A burst of N+1
 * repeated quarantine dispatches on one device under a 20-second budget
 * could starve the pool for 20 seconds per queued caller — a short budget
 * plus an honest `status|busy` bounds that blast radius to worker-seconds
 * low enough to never threaten the rest of the agent's dispatch surface.
 * This trade is deliberate and is not to be re-litigated per call site.
 *
 * Why `do_status` does NOT take this gate: a read must never queue behind a
 * multi-step mutation — status is exactly the channel an operator or
 * PolicyEvaluator needs available WHILE a mutation is in flight, not one
 * more thing waiting on it. A status read that lands mid-mutation is now
 * honestly reported as `partial`/`degraded`/`uncertain` by Parts A/B of this
 * same change rather than as a false `active`, so gating reads here would
 * only add latency without adding correctness.
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <utility>

namespace yuzu::quarantine {

/**
 * A bounded, FIFO, non-blocking-forever gate: a caller that cannot get in
 * within the wait budget gets an honest disengaged optional instead of
 * hanging. Meant to be instantiated once, as a single file-static instance
 * guarding every mutating quarantine action — see quarantine_plugin.cpp's
 * anonymous-namespace declaration. Neither copyable nor movable; a single
 * static instance never needs to be either.
 *
 * WHY A TICKET QUEUE RATHER THAN std::timed_mutex::try_lock_for.
 *
 * std::timed_mutex has no fairness and no queueing: an arriving thread's
 * try_lock barges ahead of a waiter that has already been blocked for nearly
 * its whole budget. Measured on the original implementation, 8 concurrent
 * holders against one thread retrying every 500ms:
 *
 *     holders=3 hold=300ms  20s run -> first win at 5.77s, ~12 failed attempts
 *     holders=8 hold=1000ms 20s run -> ZERO wins in 8 attempts
 *
 * The starved thread in the scenario that matters is `unquarantine`. The
 * self-sustaining loop: containment partially fails on a host, so the agentic
 * caller cannot confirm isolation, so it retries quarantine_device, so #3127
 * re-dispatches the stored intent, each attempt holding the gate for minutes
 * — while the operator's release is refused `status|busy` every time. The
 * device ends contained and unreleasable, which is precisely the stranding
 * outcome this whole package exists to prevent. A gate that can starve the
 * release path is worse than no gate.
 *
 * FIFO fixes it by construction: a waiter that arrived first is served first,
 * so the release is refused only if the budget genuinely elapses while
 * mutations ahead of it are still running — a bounded wait, not an unbounded
 * one. It costs a deque push/erase per acquisition, on a path that is about
 * to spawn subprocesses.
 */
class MutationGate {
public:
    /// Movable RAII handle on the held gate. Releases on destruction,
    /// including via an early return from the caller's scope. Never copyable
    /// — there is exactly one hold to release, so exactly one Guard may ever
    /// own it at a time.
    class Guard {
    public:
        Guard(Guard&& other) noexcept : gate_(std::exchange(other.gate_, nullptr)) {}
        Guard& operator=(Guard&& other) noexcept {
            if (this != &other) {
                release();
                gate_ = std::exchange(other.gate_, nullptr);
            }
            return *this;
        }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        ~Guard() { release(); }

    private:
        friend class MutationGate;
        explicit Guard(MutationGate& g) noexcept : gate_(&g) {}

        void release() noexcept {
            if (gate_) {
                gate_->leave();
                gate_ = nullptr;
            }
        }

        MutationGate* gate_;
    };

    explicit MutationGate(std::chrono::milliseconds wait_budget) : wait_budget_(wait_budget) {}

    MutationGate(const MutationGate&) = delete;
    MutationGate& operator=(const MutationGate&) = delete;

    /// Blocks the calling thread for up to the wait budget trying to acquire
    /// the gate, IN ARRIVAL ORDER. Returns an engaged Guard on success; a
    /// disengaged optional if the budget elapsed first — the caller MUST treat
    /// that as "another mutation is in progress", never silently proceed.
    [[nodiscard]] std::optional<Guard> try_enter() {
        // ONE lock for the push and the wait, not two.
        //
        // Taking the ticket under a separate lock and re-acquiring for the wait
        // leaves a window in which this thread OWNS the queue head while not
        // yet waiting — every other waiter's predicate is false, even with the
        // gate idle. Bounded by scheduling latency rather than a wedge, but
        // free to remove.
        std::unique_lock<std::mutex> lk(m_);
        const std::uint64_t ticket = next_ticket_++;
        waiting_.push_back(ticket);

        // RAII, because the erase is not optional and this scope can be left by
        // an exception, not only by the two returns below. `wait_for` is not
        // noexcept — it can throw std::system_error and it invokes the
        // predicate — and a ticket left in the queue by a throw is never
        // removed by anyone. Once it reaches the head every later try_enter
        // times out, so quarantine, unquarantine and whitelist all return
        // `status|busy` for the life of the process: the unreleasable-device
        // outcome this class exists to prevent, reached through its own
        // cleanup path.
        struct TicketGuard {
            MutationGate& gate;
            std::unique_lock<std::mutex>& lock;
            std::uint64_t ticket;
            bool acquired = false;
            ~TicketGuard() {
                // The lock is held on every exit path from try_enter — the
                // returns do not unlock, and an exception propagating out of
                // wait_for unwinds with unique_lock still owning it.
                const auto it = std::find(gate.waiting_.begin(), gate.waiting_.end(), ticket);
                if (it != gate.waiting_.end())
                    gate.waiting_.erase(it);
                if (acquired)
                    return; // the holder will notify on leave()
                // This waiter may have been the only thing another waiter's
                // predicate was blocked behind, so wake them — after dropping
                // the lock, so the woken thread does not immediately block on
                // it.
                if (lock.owns_lock())
                    lock.unlock();
                gate.cv_.notify_all();
            }
        } ticket_guard{*this, lk, ticket};

        const bool got = cv_.wait_for(lk, wait_budget_, [&] {
            return !held_ && !waiting_.empty() && waiting_.front() == ticket;
        });
        if (!got)
            return std::nullopt;
        held_ = true;
        ticket_guard.acquired = true;
        return Guard{*this};
    }

private:
    void leave() noexcept {
        {
            std::lock_guard<std::mutex> lk(m_);
            held_ = false;
        }
        // notify_all, not notify_one: the predicate is ticket-specific, so
        // waking an arbitrary single waiter usually wakes one whose predicate
        // is false, which then sleeps again and the gate stays idle with a
        // queue behind it.
        cv_.notify_all();
    }

    std::chrono::milliseconds wait_budget_;
    std::mutex m_;
    std::condition_variable cv_;
    bool held_ = false;
    std::uint64_t next_ticket_ = 0;
    std::deque<std::uint64_t> waiting_;
};

} // namespace yuzu::quarantine
