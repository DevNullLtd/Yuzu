#pragma once

/// @file crypto_read_gate.hpp
/// The per-process admission bound on in-flight `/crypto` store reads, owned by
/// `LocalCryptoApi` (one instance per process). Header-only so the unit tests can drive the
/// semantics without a database. Pure header (no store, wire or I/O types); core-side by use,
/// not lint-enforced. The refusal metric is deliberately NOT here: `SoftwareInventoryStore::
/// note_read_shed` keeps the `yuzu_inventory_read_degrade_total` reason label in one place.

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

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

/// The per-principal bound on in-flight CALLER-PRICED certificate reads (#6333): every summary
/// (`certificate_summary`, whose cost grows with the visible fleet, up to its 15 s wall budget)
/// and every page carrying a filter beyond `agent_id`/`sha256`/`scope`
/// (`cert_read::caller_priced_page`: a rare value or a substring needle can make the keyset walk
/// scan the table up to the wall budget). `CryptoReadGate` has only two process-wide
/// slots: without this bound one principal could hold both with two such reads and shed every
/// other `/crypto` read for up to two wall budgets. At most ONE such read per principal is in
/// flight; a second is refused (the caller answers a retryable 503, cause capacity, reason
/// `principal_busy`, retry hint 15 s). An unfiltered or key-addressed page never touches this
/// bound, so one principal can still hold one caller-priced read plus one such page. An empty
/// principal (a caller whose identity could not be resolved) shares ONE slot with every other
/// such caller, so an unresolved identity is capped more tightly, never exempted. Taken BEFORE the
/// shared gate lease, so a refused read never occupies a gate slot.
///
/// Per server process, like the gate: with N replicas a principal can hold one such read on each.
/// Not `PrincipalQuota` (principal_quota.hpp): that is the configurable engine-principal REQUEST
/// quota with its own denial envelope and metrics; this is a fixed one-slot concurrency bound on
/// one read class, released when the read returns, with nothing to configure or count.
class CertPrincipalReadCap {
public:
    CertPrincipalReadCap() = default;
    CertPrincipalReadCap(const CertPrincipalReadCap&) = delete;
    CertPrincipalReadCap& operator=(const CertPrincipalReadCap&) = delete;

    class Lease {
    public:
        Lease() noexcept = default;
        Lease(Lease&& o) noexcept : cap_(o.cap_), key_(std::move(o.key_)) { o.cap_ = nullptr; }
        Lease& operator=(Lease&& o) noexcept {
            if (this != &o) {
                release();
                cap_ = o.cap_;
                key_ = std::move(o.key_);
                o.cap_ = nullptr;
            }
            return *this;
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() { release(); }

        explicit operator bool() const noexcept { return cap_ != nullptr; }

    private:
        friend class CertPrincipalReadCap;
        Lease(CertPrincipalReadCap* c, std::string key) noexcept
            : cap_(c), key_(std::move(key)) {}
        void release() noexcept {
            if (cap_) {
                const std::lock_guard lock(cap_->mu_);
                cap_->held_.erase(key_);
                cap_ = nullptr;
            }
        }
        CertPrincipalReadCap* cap_{nullptr};
        std::string key_;
    };

    /// A lease for `principal`, falsy when that principal already holds one. Allocation failure
    /// (inserting the key) propagates as std::bad_alloc; nothing is held then.
    [[nodiscard]] Lease try_acquire(std::string_view principal) {
        std::string key(principal);
        const std::lock_guard lock(mu_);
        if (!held_.insert(key).second)
            return Lease{};
        return Lease{this, std::move(key)};
    }

    [[nodiscard]] std::size_t held() const {
        const std::lock_guard lock(mu_);
        return held_.size();
    }

private:
    mutable std::mutex mu_;
    std::unordered_set<std::string> held_;
};

} // namespace yuzu::server
