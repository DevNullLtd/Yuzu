// SPDX-License-Identifier: Apache-2.0
//
// oidc_writer_gate.hpp -- writer priority for the route-level OIDC lock (`oidc_mu_`, #5692 UP-13).
//
// `oidc_mu_` is a std::shared_mutex, and on glibc that is a READER-preferring rwlock: while at
// least one reader holds it, a new reader is admitted ahead of a waiting writer. A Settings save
// (the exclusive writer that swaps the provider and the OIDC settings) can therefore wait for as
// long as readers keep overlapping. Measured with a standalone probe (a persistent writer
// timestamping its own acquisition; 5 us reader holds): writer p99 stays in the microseconds to
// milliseconds while the mean number of overlapping readers is small, and the writer was not admitted
// within 5 s once readers saturated the lock (2.9M to 6M acquisitions/s, 15 to 22 overlapping readers
// on a 32-core host). The real critical sections are far shorter than 5 us and an HTTP server cannot
// approach those rates, but a serialised security-configuration writer should not depend on that
// arithmetic.
//
// The gate removes the barging. A writer raises a Ticket BEFORE it asks for the exclusive lock;
// every reader calls `reader_pass()` BEFORE it asks for the shared lock and blocks there while a
// ticket is outstanding. Readers already inside finish and drain, the writer is admitted, and the
// ticket ends when the writer owns the lock (a reader that passed the gate in the instant before
// the ticket was raised can still barge once; it finishes quickly and every later reader waits).
//
// The common case costs one relaxed-acquire atomic load. The gate is process-wide: it only delays
// readers during the short window in which a save waits for the lock, and it holds no lock of its
// own while a reader is inside `oidc_mu_`, so it cannot create a cycle with it. A reader MUST NOT
// call `reader_pass()` while it already holds the shared lock (a nested acquisition would wait
// behind a writer that is waiting for it); every call site takes the shared lock exactly once.
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>

namespace yuzu::server::oidc {

class OidcWriterGate {
public:
    /// Raised by a writer before it requests the exclusive `oidc_mu_`; released by `release()` or
    /// the destructor. Move-only.
    class Ticket {
    public:
        explicit Ticket(OidcWriterGate& g = instance()) : g_(&g) { g_->waiting_.fetch_add(1); }
        Ticket(const Ticket&) = delete;
        Ticket& operator=(const Ticket&) = delete;
        Ticket(Ticket&& o) noexcept : g_(o.g_) { o.g_ = nullptr; }
        Ticket& operator=(Ticket&&) = delete;
        ~Ticket() { release(); }
        void release() noexcept {
            if (g_ == nullptr)
                return;
            OidcWriterGate* g = g_;
            g_ = nullptr;
            // The decrement is made under the mutex so a reader that evaluated the predicate just
            // before cannot miss the notification.
            std::lock_guard<std::mutex> lock(g->mu_);
            if (g->waiting_.fetch_sub(1) == 1)
                g->cv_.notify_all();
        }

    private:
        OidcWriterGate* g_;
    };

    /// Block while a writer is waiting for the exclusive lock. Call before taking the shared lock.
    void reader_pass() {
        if (waiting_.load(std::memory_order_acquire) == 0)
            return;
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] { return waiting_.load(std::memory_order_acquire) == 0; });
    }

    /// The process-wide gate the routes use.
    static OidcWriterGate& instance() {
        static OidcWriterGate g;
        return g;
    }

    /// Writers currently waiting (tests).
    [[nodiscard]] int waiting_for_test() const { return waiting_.load(); }

private:
    std::atomic<int> waiting_{0};
    std::mutex mu_;
    std::condition_variable cv_;
};

} // namespace yuzu::server::oidc
