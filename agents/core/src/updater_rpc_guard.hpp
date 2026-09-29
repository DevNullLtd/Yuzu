/**
 * updater_rpc_guard.hpp -- internal (non-public) RAII publisher for the Updater's in-flight
 * OTA RPC context. Split out of updater.cpp so a unit test can drive it against a real
 * in-process gRPC server (#2182). Not part of the SDK/plugin ABI.
 */
#pragma once

#include <grpcpp/client_context.h>

#include <atomic>
#include <mutex>

namespace yuzu::agent {

// RAII publisher for the in-flight OTA RPC context. Stores `&ctx` into the
// Updater's `active_rpc_ctx_` slot for the lifetime of a blocking RPC (the
// unary CheckForUpdate or the streaming DownloadUpdate read loop) and clears
// the slot before `ctx` is destroyed (declared after `ctx`, so destroyed
// first). stop() reads the slot and TryCancel()s the context, unblocking a
// stalled OTA call so a shutdown can't hang the update-thread join (#1434
// UP-1). gRPC TryCancel on a completed RPC is a documented no-op.
//
// STOP RE-CHECK AFTER PUBLISH (#2182). stop() stores the stop flag and THEN locks `mu` to
// TryCancel the published slot. If it ran after the caller's last stop check but before this
// guard published `ctx`, it saw a null slot and cancelled nothing, and the RPC (which has no
// deadline) would block the update-thread join forever. So the ctor re-reads the flag after
// publishing, STILL holding `mu`: stop()'s slot load+TryCancel and this ctor body both hold
// `mu`, so they are totally ordered, and stop() stores the flag before it locks. Either stop()
// locks first (flag already true, slot null; we then see the flag and cancel here) or we lock
// first (stop() then sees the published slot and cancels). gRPC honours a TryCancel issued
// before the call starts by failing the RPC with CANCELLED at once.
//
// PUBLISH AND RETRACT UNDER `mu` — the RAII was never the hard part. An earlier version of
// this comment said the store/cancel/destroy window "matches the long-standing
// AgentImpl::heartbeat_ctx_ pattern". It did, and that pattern was a USE-AFTER-FREE: `ctx` is
// a STACK object in the update thread's frame, stop() TryCancel()s it from ANOTHER thread, and
// with no lock the owner could retract, pop the frame and be joined while stop() sat between
// its load() and its TryCancel(). Reachable on every TRANSIENT RECONNECT, not just shutdown —
// AgentImpl's reconnect teardown calls updater_->stop() and then joins update_thread_.
//
// The same defect was fixed three times over in AgentImpl (CtxSlot + cancel_ctx, governance
// Gate-8 rounds 7-8) and this eighth site was MISSED, because the "grep proves no bare sites
// remain" check was run over agent.cpp alone. Hence the mutex here, and hence stop() takes it
// too. (governance Gate-8 round 8 cpp-safety.)
struct ActiveRpcCtxGuard {
    // The slot type-erases a grpc::ClientContext* as void* so the public
    // updater.hpp need not pull in grpc headers. stop() static_casts it back to
    // the identical static type, which the standard guarantees round-trips for
    // any object pointer regardless of width — the real precondition (store and
    // load the same ClientContext* type, no base-class slicing) holds by
    // construction. The width assert is belt-and-suspenders: it documents intent
    // and trips only on a hypothetical non-flat-pointer ABI.
    static_assert(sizeof(void*) == sizeof(grpc::ClientContext*),
                  "void* slot cannot round-trip a grpc::ClientContext*");
    std::mutex& mu;
    std::atomic<void*>& slot;
    ActiveRpcCtxGuard(std::mutex& m, std::atomic<void*>& s, grpc::ClientContext& ctx,
                      const std::atomic<bool>& stop)
        : mu(m), slot(s) {
        std::lock_guard lk(mu);
        slot.store(&ctx, std::memory_order_release);
        // See "STOP RE-CHECK AFTER PUBLISH" above: closes the window between the caller's
        // stop check and the publish, under the same `mu` stop() cancels under.
        if (stop.load(std::memory_order_acquire))
            ctx.TryCancel();
    }
    ~ActiveRpcCtxGuard() {
        // Retract under the lock: an in-flight Updater::stop() holding `mu` across its
        // load+TryCancel blocks us here until the cancel returns, so `ctx` cannot be destroyed
        // out from under it.
        std::lock_guard lk(mu);
        slot.store(nullptr, std::memory_order_release);
    }
    // The lock is held only inside the ctor/dtor BODIES, never for the guard's lifetime —
    // the blocking RPC runs with it released. (Mirrors AgentImpl::CtxSlot; holding it across
    // the RPC would deadlock stop() for the whole of a stalled download.)
    ActiveRpcCtxGuard(const ActiveRpcCtxGuard&) = delete;
    ActiveRpcCtxGuard& operator=(const ActiveRpcCtxGuard&) = delete;
};

} // namespace yuzu::agent
