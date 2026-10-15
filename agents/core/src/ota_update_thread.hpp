/**
 * ota_update_thread.hpp -- internal (non-public) owner of the agent's OTA update thread.
 * Split out of agent.cpp so the teardown ordering can be unit-tested (#2182, #1492). Not part
 * of the SDK/plugin ABI. Header-only, no gRPC dependency.
 *
 * THE ORDERING THIS OWNS. The thread blocks in Updater::run_check_loop, which waits on the
 * UPDATER's stop state, not on AgentImpl::stop_requested_. Teardown must therefore call
 * Updater::stop() BEFORE joining; joining first (or setting only an AgentImpl flag) hangs the
 * join for the whole update-check interval. That was the #2182 bug, and stop_and_join() is the
 * one place the two steps are ordered.
 */
#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <thread>
#include <utility>

#include <yuzu/agent/updater.hpp>

namespace yuzu::agent {

class OtaUpdateThread {
public:
    OtaUpdateThread() = default;
    OtaUpdateThread(const OtaUpdateThread&) = delete;
    OtaUpdateThread& operator=(const OtaUpdateThread&) = delete;

    /// Spawns the thread. The thread owns its own shared_ptr to `updater` (it must not follow
    /// a later swap of the caller's slot). `on_applied` runs on the update thread when
    /// run_check_loop reports an applied update. Like the raw std::thread it replaces, calling
    /// start() while a previous thread is still joinable terminates.
    void start(std::shared_ptr<Updater> updater, void* stub, std::chrono::seconds interval,
               std::function<void()> on_started, std::function<void()> on_applied) {
        thread_ = std::thread([updater = std::move(updater), stub, interval,
                               on_started = std::move(on_started),
                               on_applied = std::move(on_applied)]() {
            if (on_started)
                on_started();
            // Waits on the UPDATER's stop state, not AgentImpl::stop_requested_ (#2182).
            if (updater->run_check_loop(stub, interval) && on_applied)
                on_applied();
        });
    }

    /// Unblocks the loop (Updater::stop, which also cancels an in-flight OTA RPC). Null is a
    /// no-op, matching the caller's `if (auto u = updater())`.
    static void stop(const std::shared_ptr<Updater>& updater) noexcept {
        if (updater)
            updater->stop();
    }

    /// Joins if a thread was started; a no-op otherwise.
    void join() {
        if (thread_.joinable())
            thread_.join();
    }

    /// stop() THEN join(): the ordering that #2182 requires.
    void stop_and_join(const std::shared_ptr<Updater>& updater) {
        stop(updater);
        join();
    }

    [[nodiscard]] bool joinable() const noexcept { return thread_.joinable(); }

private:
    std::thread thread_;
};

} // namespace yuzu::agent
