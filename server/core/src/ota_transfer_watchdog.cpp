#include "ota_transfer_watchdog.hpp"

#include "background_jobs.hpp"

#include <spdlog/spdlog.h>

#include <cstdlib>
#include <utility>

namespace yuzu::server {

OtaTransferWatchdog::OtaTransferWatchdog(std::chrono::milliseconds sweep_interval)
    : sweep_interval_(sweep_interval) {
    if (sweep_interval_.count() <= 0)
        return;  // test mode: no thread, sweep_once() driven directly

    sweeper_ = std::thread([this] {
        std::unique_lock lock(mu_);
        while (!stop_) {
            // wait_for on the same mutex the sweep needs: the destructor's
            // notify_one wakes us immediately rather than after a full interval.
            cv_.wait_for(lock, sweep_interval_, [this] { return stop_; });
            if (stop_)
                return;
            lock.unlock();
            // Guarded because an escape here terminates the process with no
            // diagnostic: a throw out of a thread function is std::terminate, and
            // nothing above this frame can catch it. register_transfer's CancelFn
            // carries no noexcept contract (unlike set_on_evict, which states one),
            // so a future caller could supply a throwing one; production's
            // `[ctx]{ctx->TryCancel();}` cannot throw. Swallow and keep sweeping —
            // a dropped pass costs at most one sweep_interval of deadline latency,
            // whereas dying takes the whole server with it.
            try {
                YUZU_ASSERT_BACKGROUND_JOB("ota_transfer_watchdog.sweep_once"); // WS-10 ReplicaSafe (per-replica)
                sweep_once();
            } catch (...) {
                // Observable, not silent. This watchdog is the ONLY enforcement of
                // the OTA transfer deadline, so a repeatedly-throwing pass lapses
                // that deadline with every alert reading zero — the fail-visibility
                // rule this codebase already applies to its other sole-enforcement
                // sweeps. Counting is the caller's job (no metrics sink here), so
                // the log line is the signal.
                spdlog::error("OtaTransferWatchdog: sweep threw; the OTA transfer "
                              "deadline was NOT enforced for this pass");
            }
            lock.lock();
        }
    });
}

OtaTransferWatchdog::~OtaTransferWatchdog() {
    // NOTE ON WHAT THIS CATCH DOES AND DOES NOT DO. It stops an exception
    // ESCAPING this destructor, which is required — a throw out of a destructor
    // is std::terminate that no caller-side catch can intercept. It does NOT make
    // a failed teardown recoverable: if the lock or join() throws, `sweeper_` may
    // still be joinable when the member is destroyed, and ~std::thread then calls
    // std::terminate anyway. So the honest description is that this relocates the
    // terminate, it does not prevent one, and that is the deliberate policy:
    // a sweeper that cannot be joined MUST NOT be allowed to outlive the object
    // it holds a `this` pointer into, and silently detaching it would be worse.
    // Neither failure has a known production trigger — destruction never runs on
    // the sweeper thread and no concurrent owner touches `sweeper_`.
    try {
        {
            std::lock_guard lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        if (sweeper_.joinable())
            sweeper_.join();
    } catch (...) {
        // Swallow so nothing escapes the destructor. See the note above: if this
        // left `sweeper_` joinable, member destruction terminates — by design,
        // not by oversight.
    }
}

OtaTransferWatchdog::Registration
OtaTransferWatchdog::register_transfer(CancelFn cancel,
                                       std::chrono::steady_clock::time_point deadline) {
    std::lock_guard lock(mu_);
    const std::uint64_t id = next_id_++;
    live_.emplace(id, Entry{std::move(cancel), deadline, false});
    return Registration(this, id);
}

std::size_t OtaTransferWatchdog::sweep_once() {
    const auto now = clock_();

    // The cancel callbacks run UNDER mu_ — deliberately. See the LIFETIME note in
    // the header: a handler's Registration erases its entry under this same mutex,
    // so holding it across the callback is what prevents the sweeper from calling
    // into a frame that has already returned. TryCancel does not block, so this is
    // a short critical section despite invoking a callback inside it.
    std::lock_guard lock(mu_);
    std::size_t cancelled = 0;
    for (auto& [id, entry] : live_) {
        if (entry.cancelled || entry.deadline > now)
            continue;
        entry.cancelled = true;
        if (entry.cancel)
            entry.cancel();
        ++cancelled;
    }
    return cancelled;
}

void OtaTransferWatchdog::set_clock_for_test(ClockFn fn) {
    std::lock_guard lock(mu_);
    if (fn)
        clock_ = std::move(fn);
    else
        clock_ = [] { return std::chrono::steady_clock::now(); };
}

std::size_t OtaTransferWatchdog::in_flight_count() const {
    std::lock_guard lock(mu_);
    return live_.size();
}

void OtaTransferWatchdog::erase(std::uint64_t id) noexcept {
    // noexcept for the same structural reason PrincipalQuota::release is: this runs
    // from ~Registration, and a throw escaping a destructor is std::terminate that
    // no caller-side catch can intercept. Containment has to be here.
    try {
        std::lock_guard lock(mu_);
        live_.erase(id);
    } catch (...) {
        // A leaked entry is NOT harmless, and an earlier version of this comment
        // claimed it was on the grounds that "the sweeper re-checks `cancelled`".
        // That is false: `cancelled` latches only entries the sweeper has ALREADY
        // cancelled, so an entry leaked before its deadline still has
        // `cancelled == false` and a later sweep WILL invoke its CancelFn — on a
        // ServerContext whose handler frame has returned. The latch suppresses
        // sweeps 2..n, not sweep 1.
        //
        // So this abort()s rather than continuing, matching the destructor's stated
        // policy for the same class of failure: a bookkeeping structure that cannot
        // be maintained must not be left in a state that dereferences freed memory.
        // Reaching here requires std::mutex::lock to throw, which on a healthy
        // process does not happen. Say so before dying: an operator who finds a
        // SIGABRT with nothing in the log has no way to tell this deliberate,
        // safety-motivated abort from a crash.
        spdlog::critical("OtaTransferWatchdog: could not erase a registration "
                         "(mutex failure); aborting rather than leaving a dangling "
                         "cancel callback that would fire on a freed ServerContext");
        std::abort();
    }
}

bool OtaTransferWatchdog::was_cancelled(std::uint64_t id) const {
    std::lock_guard lock(mu_);
    auto it = live_.find(id);
    return it != live_.end() && it->second.cancelled;
}

OtaTransferWatchdog::Registration::Registration(Registration&& other) noexcept
    : owner_(other.owner_), id_(other.id_) {
    other.owner_ = nullptr;
    other.id_ = 0;
}

OtaTransferWatchdog::Registration&
OtaTransferWatchdog::Registration::operator=(Registration&& other) noexcept {
    if (this != &other) {
        reset();
        owner_ = other.owner_;
        id_ = other.id_;
        other.owner_ = nullptr;
        other.id_ = 0;
    }
    return *this;
}

OtaTransferWatchdog::Registration::~Registration() { reset(); }

void OtaTransferWatchdog::Registration::reset() noexcept {
    if (owner_) {
        // Null the owner FIRST so idempotence does not depend on erase() succeeding.
        auto* owner = owner_;
        const auto id = id_;
        owner_ = nullptr;
        id_ = 0;
        owner->erase(id);
    }
}

bool OtaTransferWatchdog::Registration::cancelled() const {
    return owner_ != nullptr && owner_->was_cancelled(id_);
}

} // namespace yuzu::server
