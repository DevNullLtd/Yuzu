#pragma once

// Bounded owner of asynchronous requests that could not be cancelled in time (#5692).
//
// The Windows resolver (oidc_provider.cpp, GetAddrInfoExW) cancels a lookup that overran its
// budget and then waits briefly for the cancel to complete. A lookup that still has not completed
// then cannot be destroyed (the OS may still write into its OVERLAPPED and result list) and must
// not be forgotten (that is a leak of a heap block, an event HANDLE and a resolver list per
// stall). It is handed to this ledger, which owns it until a later sweep sees it complete, then
// destroys it.
//
// The ledger is generic over the request type and the "has it completed" test so the ownership and
// bound logic is exercised on every platform (tests/unit/server/test_oidc_egress_policy.cpp);
// only the request type and the completion test are Windows-specific.
//
// The bound: a SLOT is reserved before each request starts (`try_reserve`), so the abandoned
// requests plus the requests in flight never exceed `max` and `abandon` never has to refuse
// (refusing would force the caller to either free live memory or lose the owner). When `max` are
// stuck, `try_reserve` is false and the caller fails closed.

#include <algorithm>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace yuzu::server::oidc {

template <typename Request> class AbandonedRequestLedger {
public:
    using IsComplete = std::function<bool(const Request&)>;

    AbandonedRequestLedger(std::size_t max, IsComplete is_complete)
        : max_(max), is_complete_(std::move(is_complete)) {
        // The abandoned list can never hold more than `max_` entries (try_reserve refuses when
        // abandoned plus in-flight reach it), so reserving that many up front means the move
        // into it in `abandon` never allocates and so cannot throw while a lookup is still
        // pending. Without it a failed allocation there would destroy the one request the OS may
        // still write into.
        abandoned_.reserve(max_);
    }
    AbandonedRequestLedger(const AbandonedRequestLedger&) = delete;
    AbandonedRequestLedger& operator=(const AbandonedRequestLedger&) = delete;

    /// Sweeps completed abandoned requests, then reserves one slot. False (the caller fails
    /// closed) when the abandoned and in-flight requests already fill the ledger.
    [[nodiscard]] bool try_reserve() {
        std::lock_guard lock(mu_);
        sweep_locked();
        if (abandoned_.size() + in_flight_ >= max_)
            return false;
        ++in_flight_;
        return true;
    }

    /// A reserved request finished (completed, or never started): its slot is free again.
    void finish() {
        std::lock_guard lock(mu_);
        if (in_flight_ > 0)
            --in_flight_;
    }

    /// A reserved request could not be cancelled in time: the ledger takes ownership and keeps it
    /// until `is_complete` says its operation is over. Never destroys a live request: the storage
    /// is reserved by the constructor so the move cannot allocate. `noexcept`, so the one thing
    /// that could still throw (locking the mutex, which only fails on a broken process) ends the
    /// program instead of freeing a request the operating system may still write into.
    void abandon(std::unique_ptr<Request> request) noexcept {
        std::lock_guard lock(mu_);
        abandoned_.push_back(std::move(request));
        if (in_flight_ > 0)
            --in_flight_;
    }

    /// Capacity of the abandoned list, for the test that pins the up-front reservation.
    [[nodiscard]] std::size_t abandoned_capacity_for_test() const {
        std::lock_guard lock(mu_);
        return abandoned_.capacity();
    }

    /// Requests currently owned (not yet seen complete by a sweep).
    [[nodiscard]] std::size_t abandoned_count() const {
        std::lock_guard lock(mu_);
        return abandoned_.size();
    }

    /// A reserved slot, given back on every exit unless the request was handed to the ledger.
    class Slot {
    public:
        explicit Slot(AbandonedRequestLedger& ledger) : ledger_(ledger) {}
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() {
            if (held_)
                ledger_.finish();
        }
        void abandon(std::unique_ptr<Request> request) {
            held_ = false;
            ledger_.abandon(std::move(request));
        }

    private:
        AbandonedRequestLedger& ledger_;
        bool held_{true};
    };

private:
    void sweep_locked() {
        std::erase_if(abandoned_,
                      [this](const std::unique_ptr<Request>& r) { return is_complete_(*r); });
    }

    const std::size_t max_;
    const IsComplete is_complete_;
    mutable std::mutex mu_;
    std::size_t in_flight_{0};
    std::vector<std::unique_ptr<Request>> abandoned_;
};

} // namespace yuzu::server::oidc
