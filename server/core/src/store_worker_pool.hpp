#pragma once

/// @file store_worker_pool.hpp
/// #3261 governance hardening - bounded delivery worker pool shared by
/// WebhookStore and OffloadTargetStore. Replaces the prior per-event
/// `std::thread(...).detach()` dispatch, which had two independent defects:
///
///  1. UNBOUNDED THREAD CREATION (governance Gate 4 UP-2): the 10-slot
///     counting semaphore in each store capped concurrent HTTP work, but it
///     was acquired INSIDE the spawned thread, after the thread already
///     existed - a burst of events (e.g. a mass agent-reconnect after a
///     gateway bounce, #1197) could still spawn hundreds of OS threads that
///     all pile up blocked on `acquire()`.
///  2. USE-AFTER-FREE AT SHUTDOWN (governance Gate 2/3, security-guardian +
///     cpp-safety + sre independently convergent): a detached thread
///     captures `this` and, on completion, calls `record_delivery()`, whose
///     first statement locks a member mutex. Nothing joined these threads,
///     so a delivery still in flight when the owning store was destroyed
///     dereferenced freed memory.
///
/// A bounded pool with a FIXED worker count and a BOUNDED queue closes (1):
/// `submit()` never spawns a thread on the caller's stack, and a full queue
/// is a `false` return the caller logs and drops rather than an unbounded
/// spawn. It closes (2) two ways: `quiesce(timeout)` gives the owning store
/// an explicit, BOUNDED wait-for-drain to call before it destroys itself
/// (matching the `web_thread_done_cv_` 15s-grace-then-escalate pattern
/// already established in `ServerImpl::stop()`, `server.cpp`), and as
/// defense in depth the destructor still joins every worker unconditionally
/// - so even a caller that skips `quiesce()` cannot free the pool (and by
/// construction, cannot free a store that OWNS the pool as its last-declared
/// member) while a worker is still touching store state.
///
/// This is deliberately NOT a general-purpose thread pool - no work
/// stealing, no futures, no priority. `agents/core/src/thread_pool.hpp` is
/// the agent-side sibling this borrows its exception-firewall idiom from;
/// they are not shared because the two build targets (agent, server) do not
/// share a common internal library for something this small.

#include "background_jobs.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace yuzu::server {

class StoreWorkerPool {
public:
    /// `num_threads`: fixed worker count, clamped to [1, 16]. `max_queue`:
    /// backpressure ceiling - `submit()` returns false once the queue is
    /// this full, rather than growing without bound.
    StoreWorkerPool(std::size_t num_threads, std::size_t max_queue)
        : max_queue_(max_queue) {
        num_threads = std::max<std::size_t>(num_threads, 1);
        num_threads = std::min<std::size_t>(num_threads, 16);
        workers_.reserve(num_threads);
        YUZU_ASSERT_BACKGROUND_JOB("store_worker_pool.worker_loop"); // WS-10 ReplicaSafe (per-replica drain)
        // EXCEPTION-SAFE CONSTRUCTION (gov Gate 8 architect). std::thread's
        // ctor throws std::system_error under EAGAIN (thread/pid
        // exhaustion - plausible exactly at server boot, when both stores
        // construct a pool each). Without this guard the throw propagates
        // out of this constructor, which destroys the partially-filled
        // `workers_` vector - and ~std::thread on a JOINABLE thread calls
        // std::terminate(). Mirrors agents/core/src/thread_pool.hpp's
        // identical guard (governance Gate-4 UP-3 there); this file could
        // not reuse that one directly (server/agent are separate build
        // targets with no shared internal library for something this
        // small), but should have copied the safety net along with the
        // idiom the header comment already credits it for - a first
        // review round caught it not having done so.
        try {
            for (std::size_t i = 0; i < num_threads; ++i) {
                workers_.emplace_back([this] { worker_loop(); });
            }
        } catch (...) {
            quiesce_and_join_unconditional(); // signal + join whatever DID start
            throw;                            // caller still learns construction failed
        }
    }

    ~StoreWorkerPool() {
        // Defense in depth: a caller that skips quiesce() (or whose
        // quiesce() timed out and chose to keep the pool anyway, which no
        // caller in this codebase does today) still cannot destroy this
        // pool while a worker is mid-task - join() blocks until every
        // worker returns, exactly like agents/core/src/thread_pool.hpp's
        // destructor. This is why the pool must be the LAST-declared
        // member of any store that owns one: member destruction order is
        // reverse-declaration, so this join runs BEFORE that store's
        // db_/mtx_ are torn down.
        quiesce_and_join_unconditional();
    }

    StoreWorkerPool(const StoreWorkerPool&) = delete;
    StoreWorkerPool& operator=(const StoreWorkerPool&) = delete;

    /// Enqueue a task. Returns false (task NOT queued) if the pool has
    /// already been quiesced, or if the bounded queue is full - the caller
    /// must log and drop rather than fall back to an unbounded spawn.
    bool submit(std::function<void()> task) {
        {
            std::lock_guard lock(mu_);
            if (closed_ || stop_)
                return false;
            if (tasks_.size() >= max_queue_)
                return false;
            tasks_.push(std::move(task));
            ++pending_;
        }
        cv_.notify_one();
        return true;
    }

    /// Stop accepting new work and wait up to `timeout` for the queue to
    /// drain AND every in-flight task to finish. Returns true if fully
    /// drained within the bound, false on timeout (some task is still
    /// running past the deadline - the caller must not destroy the pool
    /// in that case; see the header comment on `~StoreWorkerPool`).
    ///
    /// Not `noexcept` in its signature, but every path out of it is
    /// exception-safe (adversarial-review round 2, Kimi K2, independently
    /// confirmed against source): every caller of this function is itself
    /// noexcept - ServerImpl::stop() (`noexcept override`) and both
    /// stores' implicitly-noexcept destructors. std::unique_lock's
    /// locking constructor and condition_variable::wait_for are NOT
    /// noexcept per the standard (both can throw std::system_error),
    /// even though a correctly-used, non-recursive std::mutex essentially
    /// never actually throws in practice - an uncaught throw here would
    /// still call std::terminate() instead of reaching the documented
    /// escalation path, exactly the hazard class this file's own
    /// constructor try/catch and quiesce_and_join_unconditional() already
    /// guard against elsewhere. Treat any throw the same as a timeout -
    /// false is already a safe, handled outcome for every caller.
    bool quiesce(std::chrono::milliseconds timeout) {
        try {
            std::unique_lock lock(mu_);
            closed_ = true;
            return idle_cv_.wait_for(lock, timeout, [this] { return pending_ == 0; });
        } catch (...) {
            return false;
        }
    }

private:
    /// Signal every started worker to stop and join it. Safe to call on a
    /// partially constructed pool (the ctor's failure path, where some
    /// workers never started) and from the destructor.
    void quiesce_and_join_unconditional() noexcept {
        {
            std::lock_guard lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) {
                try {
                    w.join();
                } catch (...) {
                    // gov Gate 8 round-2 (cpp-safety): this function is
                    // noexcept, so an uncaught throw here would terminate()
                    // us anyway - but WRAPPED, it stays a swallow-and-
                    // continue instead, matching
                    // agents/core/src/thread_pool.hpp's quiesce_and_join()
                    // exactly (an earlier version of this comment claimed
                    // parity with that function while actually leaving the
                    // join unwrapped, which was false).
                }
            }
        }
    }

    void worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock lock(mu_);
                cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty())
                    return;
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            // Exception firewall, same rationale as
            // agents/core/src/thread_pool.hpp: a task must never let an
            // exception escape this callable, or the server terminates.
            // deliver_single() already wraps its own body in try/catch, so
            // this is a last-resort net, not the primary handler.
            try {
                task();
            } catch (const std::exception& e) {
                try {
                    spdlog::error("StoreWorkerPool: task threw std::exception (contained): {}",
                                  e.what());
                } catch (...) {}
            } catch (...) {
                try {
                    spdlog::error("StoreWorkerPool: task threw a non-std exception (contained)");
                } catch (...) {}
            }
            {
                std::lock_guard lock(mu_);
                --pending_;
                if (pending_ == 0)
                    idle_cv_.notify_all();
            }
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_;      // producer -> worker: new task / stop
    std::condition_variable idle_cv_; // worker -> quiesce(): pending_ reached 0
    std::size_t max_queue_;
    std::size_t pending_{0}; // queued + currently-executing tasks
    bool stop_{false};       // destructor-path: stop workers unconditionally
    bool closed_{false};     // quiesce()-path: reject new submissions
};

} // namespace yuzu::server
