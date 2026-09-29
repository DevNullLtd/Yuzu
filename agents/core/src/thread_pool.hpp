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

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t num_threads, std::size_t max_queue_size = 1000)
        : max_queue_size_{max_queue_size} {
        // Clamp thread count: min 4, max 32
        num_threads = std::max<std::size_t>(num_threads, 4);
        num_threads = std::min<std::size_t>(num_threads, 32);
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
                    {
                        std::unique_lock lock(mu_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty())
                            return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
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
    }

public:
    // Returns false if the queue is full (backpressure).
    bool submit(std::function<void()> task) {
        {
            std::lock_guard lock(mu_);
            if (stop_)
                return false;
            if (tasks_.size() >= max_queue_size_)
                return false;
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
        return true;
    }

    // Shares the ctor's failure path: signal, join, clear. A throwing join would
    // terminate() out of a destructor anyway, so quiesce_and_join() swallows it.
    ~ThreadPool() { quiesce_and_join(); }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::size_t max_queue_size_;
};

} // namespace yuzu::agent
