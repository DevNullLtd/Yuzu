#pragma once

/// @file ota_transfer_watchdog.hpp
///
/// Deadline enforcement for in-flight OTA `DownloadUpdate` transfers (issue
/// #911, UP-101).
///
/// WHY THIS EXISTS. `AgentServiceImpl` is a SYNCHRONOUS gRPC service
/// (`: public pb::AgentService::Service`), and `grpc::ServerWriter::Write` on the
/// sync API takes no deadline. A peer that collapses its HTTP/2 receive window to
/// zero and then keeps ACKing keepalive pings blocks that `Write` indefinitely —
/// keepalive does not catch it, because the connection is live; only the STREAM is
/// stalled. An elapsed-time check between chunks catches the slow-drip case, where
/// each `Write` completes slowly, but it can never catch a single `Write` that
/// never returns: the handler thread is inside the call and cannot check anything.
///
/// The only mechanism that unblocks it is cancelling the RPC from ANOTHER thread —
/// `grpc::ServerContext::TryCancel()`, after which the blocked `Write` returns
/// false and the handler unwinds normally. That is what this watchdog does.
///
/// WHY A CancelFn AND NOT A ServerContext*. The registration takes an opaque
/// callback rather than a `grpc::ServerContext*` so the deadline bookkeeping is
/// unit-testable without a live gRPC call: a default-constructed `ServerContext`
/// is not attached to a call, and calling `TryCancel()` on one is not a contract
/// gRPC documents. Production registers `[ctx] { ctx->TryCancel(); }`; tests
/// register a lambda that sets a flag. It also keeps this file free of gRPC types.
///
/// LIFETIME — the load-bearing part. The agent learned this exact lesson the hard
/// way in `cancel_ctx()` (`agents/core/src/agent.cpp`): a canceller that sits
/// between loading a context pointer and calling TryCancel on it has a
/// use-after-free, because the frame owning the context can return in between. So:
///
///   * The registration is a move-only RAII handle living in the handler's frame.
///     It erases its entry on destruction, i.e. before the handler returns and
///     therefore before gRPC tears the context down.
///   * The sweeper holds `mu_` ACROSS the lookup AND the cancel call. Erase also
///     takes `mu_`. A handler returning therefore cannot race a sweep already
///     dereferencing its callback — it blocks until the sweep finishes.
///   * Lock ordering is one-way: this class takes `mu_` and then (inside the
///     callback) gRPC's internal context lock. Nothing anywhere takes gRPC's lock
///     and then `mu_`, so the pair cannot deadlock. Do not add a path that does.
///
/// TryCancel is non-blocking (it signals the call; it does not wait for the
/// handler), so holding `mu_` across it does not stall other registrations.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace yuzu::server {

class OtaTransferWatchdog {
  public:
    using CancelFn = std::function<void()>;
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// `sweep_interval` is how often the background sweeper wakes. A transfer is
    /// therefore cancelled between `deadline` and `deadline + sweep_interval`; the
    /// deadline is a bound, not a precise timer, which is all UP-101 needs.
    /// `sweep_interval == 0` constructs the watchdog with NO background thread —
    /// the mode tests use, driving `sweep_once()` directly.
    explicit OtaTransferWatchdog(std::chrono::milliseconds sweep_interval =
                                     std::chrono::milliseconds(1000));

    /// Stops and joins the sweeper.
    ///
    /// A live `Registration` MUST NOT outlive the watchdog: it holds an `owner_`
    /// back-pointer and dereferences it in both `reset()` and `cancelled()`, so
    /// an outliving registration is a use-after-free. In production that ordering
    /// is structural rather than hoped for — this watchdog is a member of
    /// `AgentServiceImpl`, and `agent_server_` is declared AFTER `agent_service_`
    /// in `ServerImpl`, so the gRPC server (and with it every handler frame
    /// holding a Registration) is destroyed first; `stop()` additionally calls
    /// `agent_server_->Shutdown(deadline)`, which drains or cancels in-flight
    /// calls. Do not reorder those two members.
    ~OtaTransferWatchdog();

    OtaTransferWatchdog(const OtaTransferWatchdog&) = delete;
    OtaTransferWatchdog& operator=(const OtaTransferWatchdog&) = delete;

    /// Move-only RAII handle. Erases its watchdog entry on destruction — see the
    /// LIFETIME note in this file's header; that erase is what makes the sweeper's
    /// dereference safe, so a registration must never outlive the frame that owns
    /// the thing its CancelFn captures.
    class Registration {
      public:
        Registration() = default;
        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
        ~Registration();

        /// Erase early. Idempotent; a no-op on an empty handle.
        void reset() noexcept;

        /// True if the watchdog cancelled this transfer. Lets the handler
        /// attribute a failed `Write` to the deadline rather than to the peer
        /// hanging up — the two are indistinguishable at the `Write` return value,
        /// and they get DIFFERENT rate-limit treatment (a deadline is
        /// server-attributable and refunds; a peer disconnect does not).
        [[nodiscard]] bool cancelled() const;

      private:
        friend class OtaTransferWatchdog;
        Registration(OtaTransferWatchdog* owner, std::uint64_t id) : owner_(owner), id_(id) {}

        OtaTransferWatchdog* owner_{nullptr};
        std::uint64_t id_{0};
    };

    /// Register an in-flight transfer to be cancelled at `deadline`.
    [[nodiscard]] Registration register_transfer(CancelFn cancel,
                                                 std::chrono::steady_clock::time_point deadline);

    /// Cancel every registration whose deadline has passed. Called by the sweeper
    /// thread; public so tests can drive it deterministically with a stepped clock
    /// instead of waiting on the thread. Returns how many it cancelled.
    std::size_t sweep_once();

    /// TEST ONLY. Empty fn restores the real steady clock. Install before putting
    /// the watchdog under load — the same contract as
    /// `PrincipalQuota::set_clock_for_test`.
    void set_clock_for_test(ClockFn fn);

    /// Live registration count (monitoring / tests).
    [[nodiscard]] std::size_t in_flight_count() const;

  private:
    friend class Registration;

    struct Entry {
        CancelFn cancel;
        std::chrono::steady_clock::time_point deadline;
        // Set by the sweeper when it cancels, read by Registration::cancelled().
        // The entry outlives the cancel because the handler's Registration is what
        // erases it, and the handler is still blocked in Write when we cancel.
        bool cancelled{false};
    };

    void erase(std::uint64_t id) noexcept;
    bool was_cancelled(std::uint64_t id) const;

    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, Entry> live_;
    std::uint64_t next_id_{1};
    ClockFn clock_{[] { return std::chrono::steady_clock::now(); }};

    // Sweeper shutdown: `stop_` is guarded by `mu_` and announced via `cv_`, so the
    // destructor never waits a full sweep_interval to join.
    std::condition_variable cv_;
    bool stop_{false};
    std::chrono::milliseconds sweep_interval_;
    std::thread sweeper_;
};

} // namespace yuzu::server
