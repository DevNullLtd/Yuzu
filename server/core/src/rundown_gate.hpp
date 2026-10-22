#pragma once

/// @file rundown_gate.hpp
/// A shutdown RUNDOWN for code that borrows something its owner is about to destroy. Built for the
/// `registry.write` audit hook (AgentServiceImpl::audit_registry_frame), which runs on detached
/// forwarder threads that shutdown never joins (#3279) and, per frame, holds the audit store across
/// up to kMaxRegistryAuditLinesPerFrame writes that each lease the pg::PgPool& the store borrows.
///
/// A weak_ptr lock keeps the OBJECT alive for the call, and a "refuse new entrants" latch (the
/// analytics_store_ treatment of #3350) is enough when the guarded call enqueues and returns. It is
/// not enough here: a forwarder BETWEEN two rows holds no lease, so ~PgPool cannot see it, and its
/// next row leases a destroyed pool. A rundown closes that: entrants register before they take the
/// borrow and leave after they give it back, CLOSING refuses new entrants, and the owner WAITS for
/// the registered ones before it resets what they borrow.
///
///   user:   const auto in = gate.try_enter();   // empty once closed
///           if (!in) return;                    // shutdown has begun
///           ... borrow, use, give back ...      // declare the borrow AFTER `in`
///           (check gate.closed() before each unit of work that leases)
///   owner:  gate.close();                       // new entrants are refused from here on
///           if (!gate.wait_idle(bound)) ...     // every registered entrant has left, or escalate
///           ... reset what was borrowed ...
///
/// Every transition is a critical section on ONE mutex, so there is no memory-ordering argument to
/// make: an entrant that registered before close() is counted, so wait_idle() cannot return true
/// until its Entry is destroyed (after the borrow, since the borrow is declared later and dies
/// first); one that comes after close() is refused and never takes the borrow. Nothing is held
/// across the guarded work, so the mutex is a leaf.
///
/// close() never waits, so it is safe to call from inside the guarded code itself (the unit tests
/// close from the audit budget's injected clock); wait_idle() from there would wait for its own
/// entry, so it takes a bound and a 0 ms bound never blocks.
///
/// NOT a fix for #3279 (join or drain the detached workers), only a hook-local rundown for the one
/// borrow that crosses the pool: when #3279 lands this class has no user and goes.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace yuzu::server {

class RundownGate {
public:
    /// Proof of admission. True while it holds a place inside the gate; destroying it gives the
    /// place back. Neither copyable nor movable: it is handed out by value (guaranteed elision),
    /// so there is exactly one place per Entry and it is given back exactly once.
    class Entry {
    public:
        Entry(const Entry&) = delete;
        Entry& operator=(const Entry&) = delete;
        ~Entry() {
            if (gate_)
                gate_->leave();
        }
        explicit operator bool() const noexcept { return gate_ != nullptr; }

    private:
        friend class RundownGate;
        explicit Entry(RundownGate* gate) noexcept : gate_(gate) {}
        RundownGate* gate_;
    };

    RundownGate() = default;
    RundownGate(const RundownGate&) = delete;
    RundownGate& operator=(const RundownGate&) = delete;

    /// A place inside the gate, or an empty Entry once close() has run. May throw (a mutex that
    /// cannot be locked); its one caller, the audit hook, reports that as a failed write.
    [[nodiscard]] Entry try_enter() {
        std::lock_guard lock(mu_);
        if (closed_)
            return Entry{nullptr};
        ++inside_;
        return Entry{this};
    }

    /// True once close() has run. Entrants poll it before each unit of work that leases what the
    /// owner will destroy. May throw like try_enter().
    [[nodiscard]] bool closed() const {
        std::lock_guard lock(mu_);
        return closed_;
    }

    /// Refuse every later try_enter(). Sticky, idempotent, never waits. Not wrapped in try/catch:
    /// a mutex that cannot be locked would leave the gate open without a word, so the process ends
    /// (std::terminate), which no caller can mistake for a closed gate.
    void close() noexcept {
        std::lock_guard lock(mu_);
        closed_ = true;
    }

    /// Wait up to `bound` for every registered Entry to be destroyed. True when none is left,
    /// false at the deadline (some entrant is still inside: the owner must not reset what it
    /// borrows) and on any failure to wait. Call close() first; an entrant that registers after a
    /// true result is possible until then.
    [[nodiscard]] bool wait_idle(std::chrono::milliseconds bound) noexcept {
        try {
            std::unique_lock lock(mu_);
            return idle_cv_.wait_for(lock, bound, [this] { return inside_ == 0; });
        } catch (...) {
            return false;
        }
    }

private:
    void leave() noexcept {
        std::lock_guard lock(mu_);
        // Notified under the lock so a waiter that returns and destroys the gate cannot race the
        // notify.
        if (--inside_ == 0)
            idle_cv_.notify_all();
    }

    mutable std::mutex mu_;
    std::condition_variable idle_cv_;
    std::size_t inside_{0};
    bool closed_{false};
};

} // namespace yuzu::server
