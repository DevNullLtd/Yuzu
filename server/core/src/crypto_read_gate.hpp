#pragma once

/// @file crypto_read_gate.hpp
/// CORE-ONLY. The per-process admission bound on in-flight `/crypto` store reads, owned by
/// `LocalCryptoApi` (one instance per process). Header-only so the unit tests can drive the
/// semantics without a database.

#include <atomic>

namespace yuzu::server {

/// The share of the 16-connection PgPool (shared with RBAC, audit and ingest) that /crypto
/// may hold at once. A summary read can hold a lease for up to its statement_timeout, so an
/// unbounded dashboard poll storm would otherwise starve the rest of the server.
inline constexpr int kMaxConcurrentCryptoReads = 2;

/// Non-blocking try-acquire counter. `try_acquire()` returns an RAII lease (falsy when the
/// bound is reached); the lease releases on every exit path, exceptions included.
class CryptoReadGate {
public:
    explicit CryptoReadGate(int max_in_flight = kMaxConcurrentCryptoReads) noexcept
        : max_(max_in_flight) {}

    CryptoReadGate(const CryptoReadGate&) = delete;
    CryptoReadGate& operator=(const CryptoReadGate&) = delete;

    class Lease {
    public:
        Lease() noexcept = default;
        Lease(Lease&& o) noexcept : gate_(o.gate_) { o.gate_ = nullptr; }
        Lease& operator=(Lease&& o) noexcept {
            if (this != &o) {
                release();
                gate_ = o.gate_;
                o.gate_ = nullptr;
            }
            return *this;
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() { release(); }

        explicit operator bool() const noexcept { return gate_ != nullptr; }

    private:
        friend class CryptoReadGate;
        explicit Lease(CryptoReadGate* g) noexcept : gate_(g) {}
        void release() noexcept {
            if (gate_) {
                gate_->in_flight_.fetch_sub(1, std::memory_order_acq_rel);
                gate_ = nullptr;
            }
        }
        CryptoReadGate* gate_{nullptr};
    };

    [[nodiscard]] Lease try_acquire() noexcept {
        int cur = in_flight_.load(std::memory_order_acquire);
        while (cur < max_) {
            if (in_flight_.compare_exchange_weak(cur, cur + 1, std::memory_order_acq_rel))
                return Lease{this};
        }
        return Lease{};
    }

    [[nodiscard]] int in_flight() const noexcept { return in_flight_.load(std::memory_order_acquire); }

private:
    const int max_;
    std::atomic<int> in_flight_{0};
};

} // namespace yuzu::server
