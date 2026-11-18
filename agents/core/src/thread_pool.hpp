#pragma once

// ── Bounded Thread Pool ──────────────────────────────────────────────────────
// Replaces unbounded std::thread-per-command dispatch. Workers pull tasks from
// a shared queue protected by a mutex + condition variable. If the queue exceeds
// max_queue_size, submit() returns false so the caller can reject the command.
//
// Exception firewall (#2037): each task runs inside a try/catch(...) so that a
// task which lets an exception escape cannot propagate out of the worker's
// top-level callable — which would call std::terminate() -> abort() and kill the
// whole agent process. On Windows that abort surfaces as exception code
// 0xC0000409 (FAST_FAIL_FATAL_APP_EXIT), easily mistaken for a /GS stack-buffer
// overrun. Callers that need a per-task failure signal must still handle their
// own exceptions; this firewall is the last-resort net that keeps one task's
// failure from taking down the process or the other workers.
//
// Protective lane (ADR-2005, owner ruling 2026-11-18): `reserved_protective` workers' worth of
// capacity is held back for PROTECTIVE tasks (`submit(task, /*protective=*/true)`, the caller decides
// with `yuzu::protective::is_protective_action`). A non-protective task is only STARTED while fewer
// than `workers - reserved_protective` non-protective tasks are running, so N-1 stuck ordinary
// commands (with one reserved slot) never leave a protective task without a worker while one is
// free. NOT covered (ADR-2005): no reserve between protective tasks (they may use any worker), and
// the destructor runs every queued task (the agent's tasks reject at once when the pool is closing) and
// waits, unbounded, for every task already running (#8247); protective tasks have
// their own queue, taken first, and may use any worker. The invariant lives HERE, at the one place
// a task is chosen to run, never at a caller.

#include <algorithm>
#include <atomic>
#include <memory>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

/// Lock-free readout of the pool for another thread (the heartbeat): the pool itself can be torn
/// down and re-created on a reconnect, so the reader holds THIS object, which outlives every pool.
struct PoolGauge {
    std::atomic<std::size_t> workers{0};
    std::atomic<std::size_t> running{0};
    std::atomic<std::size_t> queued{0};
};

class ThreadPool {
public:
    explicit ThreadPool(std::size_t num_threads, std::size_t max_queue_size = 1000,
                        std::size_t reserved_protective = 0, std::shared_ptr<PoolGauge> gauge = nullptr)
        : gauge_{std::move(gauge)}, max_queue_size_{max_queue_size} {
        // Clamp thread count: min 4, max 32
        num_threads = std::max<std::size_t>(num_threads, 4);
        num_threads = std::min<std::size_t>(num_threads, 32);
        // At least one worker stays available to ordinary commands, whatever was asked.
        reserved_protective_ = std::min<std::size_t>(reserved_protective, num_threads - 1);
        num_threads_ = num_threads;
        if (gauge_)
            gauge_->workers = num_threads;
        workers_.reserve(num_threads);
        // EXCEPTION-SAFE CONSTRUCTION (governance Gate-4 UP-3). std::thread's ctor throws
        // std::system_error under EAGAIN (thread/pid exhaustion — a pids-capped container,
        // RLIMIT_NPROC). Without this guard the throw propagated out of ThreadPool's ctor,
        // which destroys the partially-filled `workers_` vector — and ~std::thread on a
        // JOINABLE thread calls std::terminate(). So the agent aborted, rather than
        // reporting a clean startup failure, on exactly the overloaded host where it most
        // needs to survive. (SparkEngine, which spawns its threads earlier, degrades
        // gracefully instead — so the OPTIONAL subsystem survived while the MANDATORY one
        // killed the process. Rung 1 also reorders construction so the pool claims its
        // threads first; this makes the failure itself survivable either way.)
        try {
            spawn_workers(num_threads);
            // INSIDE the try, deliberately. spdlog rethrows non-std exceptions, and a throw
            // out here would destroy a FULLY-POPULATED workers_ vector of joinable threads
            // -> std::terminate: the very failure this try/catch exists to remove, one line
            // lower down (governance Gate-3 cpp-expert).
            spdlog::info("Thread pool started: {} workers, max queue {}", workers_.size(),
                         max_queue_size);
        } catch (...) {
            quiesce_and_join(); // signal + join whatever DID start, so ~vector is safe
            throw;              // the caller still learns the pool could not be built
        }
    }

private:
    void spawn_workers(std::size_t num_threads) {
        for (std::size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    bool ordinary = false;
                    {
                        std::unique_lock lock(mu_);
                        cv_.wait(lock, [this] {
                            return runnable_locked() || (stop_ && protective_tasks_.empty() && tasks_.empty());
                        });
                        if (!runnable_locked())
                            return; // stopping and both lanes are drained
                        if (!protective_tasks_.empty()) {
                            task = std::move(protective_tasks_.front());
                            protective_tasks_.pop();
                        } else {
                            task = std::move(tasks_.front()); // runnable_locked() proved it may start
                            tasks_.pop();
                            ordinary = true;
                            ++ordinary_running_;
                        }
                        ++running_;
                        publish_locked();
                    }
                    struct Done {
                        ThreadPool* p;
                        bool ordinary;
                        ~Done() {
                            bool drained = false;
                            {
                                std::lock_guard lock(p->mu_);
                                --p->running_;
                                if (ordinary)
                                    --p->ordinary_running_;
                                p->publish_locked();
                                drained = p->stop_ && p->tasks_.empty() && p->protective_tasks_.empty();
                            }
                            // Stopping and nothing left to run: EVERY idle waiter must wake to see
                            // it and exit (with reserved >= 2 a single notify_one can wake a worker
                            // that goes back to sleep while the rest never learn the lanes drained,
                            // and the destructor's join hangs).
                            if (drained)
                                p->cv_.notify_all();
                            // A finished ordinary task frees an ordinary slot for a waiting one.
                            else if (ordinary)
                                p->cv_.notify_one();
                        }
                    } done{this, ordinary};
                    // Exception firewall (#2037): a task must never let an
                    // exception escape this callable — that would terminate() the
                    // whole agent. Contain it here so the worker survives and
                    // keeps pulling the next task. The log calls are themselves
                    // wrapped: spdlog can throw (alloc/sink/fmt failure), and a
                    // throw from this last-resort handler would re-open the very
                    // terminate() hole we are closing.
                    try {
                        task();
                    } catch (const std::exception& e) {
                        try {
                            spdlog::error("ThreadPool task threw std::exception (contained, "
                                          "worker survives): {}",
                                          e.what());
                        } catch (...) {}
                    } catch (...) {
                        try {
                            spdlog::error("ThreadPool task threw a non-std exception "
                                          "(contained, worker survives)");
                        } catch (...) {}
                    }
                }
            });
        }
    }

    /// Signal every started worker to exit and join it. Safe to call on a partially
    /// constructed pool (the ctor's failure path) and from the destructor.
    void quiesce_and_join() noexcept {
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
                    // A join that throws here would terminate() us anyway (noexcept);
                    // swallowing keeps the partially-built teardown best-effort.
                }
            }
        }
        workers_.clear();
        if (gauge_) {
            gauge_->running = 0;
            gauge_->queued = 0;
        }
    }

public:
    // Returns false if the queue is full (backpressure). A protective task has its own queue and its
    // own bound, so a full ordinary queue never rejects it.
    bool submit(std::function<void()> task, bool protective = false) {
        {
            std::lock_guard lock(mu_);
            if (stop_)
                return false;
            auto& q = protective ? protective_tasks_ : tasks_;
            if (q.size() >= max_queue_size_)
                return false;
            q.push(std::move(task));
            publish_locked();
        }
        // notify_all: the one woken worker might be unable to take an ordinary task (held back),
        // while a protective one is queued; every waiter re-evaluates its own predicate.
        cv_.notify_all();
        return true;
    }

    struct Stats {
        std::size_t workers{0};
        std::size_t reserved_protective{0};
        std::size_t running{0};       ///< tasks executing now (the in-flight gauge)
        std::size_t queued{0};        ///< tasks waiting (both lanes)
    };
    [[nodiscard]] Stats stats() const {
        std::lock_guard lock(mu_);
        return {num_threads_, reserved_protective_, running_, tasks_.size() + protective_tasks_.size()};
    }

    // Shares the ctor's failure path: signal, join, clear. A throwing join would
    // terminate() out of a destructor anyway, so quiesce_and_join() swallows it.
    ~ThreadPool() { quiesce_and_join(); }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

private:
    /// The ONE admission rule: an ordinary task starts only while fewer than workers - reserved
    /// ordinary tasks run (mu_ held).
    [[nodiscard]] bool ordinary_may_start_locked() const {
        return ordinary_running_ < num_threads_ - reserved_protective_;
    }
    void publish_locked() {
        if (gauge_) {
            gauge_->running = running_;
            gauge_->queued = tasks_.size() + protective_tasks_.size();
        }
    }
    [[nodiscard]] bool runnable_locked() const {
        return !protective_tasks_.empty() || (!tasks_.empty() && ordinary_may_start_locked());
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;            // ordinary lane
    std::queue<std::function<void()>> protective_tasks_; // protective lane (taken first)
    std::size_t num_threads_{0};
    std::size_t reserved_protective_{0};
    std::size_t running_{0};
    std::size_t ordinary_running_{0};
    std::shared_ptr<PoolGauge> gauge_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::size_t max_queue_size_;
};

} // namespace yuzu::agent
