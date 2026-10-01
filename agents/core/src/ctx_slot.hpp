/**
 * ctx_slot.hpp -- internal (non-public) publish/cancel primitives for AgentImpl's in-flight
 * gRPC ClientContext slots. Split out of agent.cpp so a unit test can drive them against a
 * real in-process gRPC server (#2182, #1492). Not part of the SDK/plugin ABI.
 *
 * The lock-discipline rationale lives on AgentImpl::ctx_mu_ in agent.cpp; the summary is: the
 * ClientContext is a STACK object cancelled from OTHER threads, so publish, retract and
 * cancel all happen under one mutex, which is held only momentarily (never for the slot's
 * lifetime and never across a join).
 */
#pragma once

#include <atomic>
#include <mutex>

#include <grpcpp/client_context.h>

namespace yuzu::agent {

/// Publishes a STACK-owned ClientContext into `slot` for the enclosing scope and retracts it
/// under `mu` on the way out.
class CtxSlot {
public:
    CtxSlot(std::mutex& mu, std::atomic<grpc::ClientContext*>& slot,
            grpc::ClientContext* ctx) noexcept
        : mu_{mu}, slot_{slot} {
        std::lock_guard lk(mu_);
        slot_.store(ctx, std::memory_order_release);
    }

    /// As above, then evaluates `stop()` AFTER publishing, still under `mu` (stop_seen()).
    /// A teardown sets its stop flag BEFORE calling cancel_ctx_slot(), which takes the same
    /// mutex, so either the canceller saw the published slot and cancelled, or this
    /// predicate sees the flag. A caller that ignores stop_seen() and issues the deadline-less
    /// RPC anyway can wedge the join on it. `stop` must be cheap, must not take `mu`, and must not throw (this constructor is noexcept, so a throw terminates).
    template <class StopPred>
    CtxSlot(std::mutex& mu, std::atomic<grpc::ClientContext*>& slot, grpc::ClientContext* ctx,
            StopPred&& stop) noexcept
        : mu_{mu}, slot_{slot} {
        std::lock_guard lk(mu_);
        slot_.store(ctx, std::memory_order_release);
        stop_seen_ = static_cast<bool>(stop());
    }

    ~CtxSlot() {
        std::lock_guard lk(mu_);
        slot_.store(nullptr, std::memory_order_release);
    }
    CtxSlot(const CtxSlot&) = delete;
    CtxSlot& operator=(const CtxSlot&) = delete;

    /// True when the post-publish stop predicate fired. Always false for the 3-arg ctor.
    [[nodiscard]] bool stop_seen() const noexcept { return stop_seen_; }

private:
    std::mutex& mu_;
    std::atomic<grpc::ClientContext*>& slot_;
    bool stop_seen_{false};
};

/// The ONLY way to cancel a published slot: loads AND TryCancel()s under `mu` so the owning
/// frame's ~CtxSlot cannot retire the context in between. Safe on an already-null slot.
inline void cancel_ctx_slot(std::mutex& mu, std::atomic<grpc::ClientContext*>& slot) noexcept {
    std::lock_guard lk(mu);
    if (auto* c = slot.load(std::memory_order_acquire))
        c->TryCancel();
}

} // namespace yuzu::agent
