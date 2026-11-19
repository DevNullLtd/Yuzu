#pragma once

/// @file bulk_read_slots.hpp
/// The concurrency cap on the bulk device-CI read (`GET /api/v1/hardware-ci` and its MCP twin).
///
/// WHY. One page is `limit + 1` rows read in a single transaction on a pooled Postgres connection
/// (normally bounded by the statement timeout; a stalled connection can hold a slot longer). The
/// pool is shared by authorization (RbacStore), the access audit (AuditStore), every other store
/// and AuthDB. A burst of bulk reads that holds the pool saturated makes the
/// pool's bounded acquires fail fast, so an unrelated authorised request and the audit row that
/// every served read needs both lose their connection (#7949). This cap bounds how many pool
/// connections the bulk read can hold at one instant; it is NOT a reserve, and it does not bound
/// the size of a read: a page of 1000 still reads 1001 rows, and no limit on the response changes
/// that.
///
/// The same cap is the bound on an audit outage (#7951). The route reads BEFORE it writes its
/// access row, so while the audit store is down every attempt still performs its read and then
/// discards the page, and while the audit table is locked (migration DDL, VACUUM FULL) every
/// served read's audit INSERT waits on the lock holding a pooled connection. The slot is held
/// across the read AND the access-audit write of a served bulk page
/// (`hardware_ci_page::Page::hold`, released by the transport right after the audit write), so at
/// most `cap` such reads-or-audit-writes hold a connection at once per replica, whatever the
/// client's retry rate. It is a CONCURRENCY bound only: retries are not rate-limited, and the cap
/// is per replica, so the fleet-wide ceiling is replicas x cap. It does NOT bound the audit writes
/// of point reads (`agent_id`), of the failure row after a failed store read, of the refusal rows
/// (scope too wide, collation ordering unverified, MCP argument refusals), or of any other route;
/// a busy refusal writes no row. At pool 1 the cap is the whole pool, so one stalled
/// audit write can leave authorization without a connection; at pool 2 it takes two (the capped
/// bulk writer plus one that holds no slot).
///
/// ONE instance, owned by `ServerImpl`, shared by REST and MCP (a second instance would double
/// the cap). A request that names an `agent_id` (a point read) takes no slot, so
/// confirm-before-retire is never refused during a walk.
///
/// The shape follows `containment_read_slots_` in server.cpp: a bounded `std::counting_semaphore`,
/// an RAII release, and a wait that is shorter than the read it guards. This header is store-free
/// (no pg/ include), so the MCP registry lane's include closure (check-seam-closure.py) stays
/// clean.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <semaphore>
#include <string>

namespace yuzu::server {

/// The compile-time ceiling of the cap: the semaphore's template bound, and the value an explicit
/// `--hardware-ci-read-concurrency` is refused above.
inline constexpr int kMaxBulkReadSlots = 8;

/// How long a bulk read waits for a slot before it is refused as busy. Deliberately well under the
/// store's 5 s statement timeout so the two bounds compose rather than stack, and not
/// configurable: it is a blast-radius bound, not a tuning knob.
inline constexpr std::chrono::milliseconds kBulkReadSlotWait{500};

class BulkReadSlots {
  public:
    /// Move-only RAII for one slot. Releases exactly once, on every exit path including an
    /// exception thrown by the guarded read.
    class Slot {
      public:
        Slot() = default;
        Slot(Slot&& o) noexcept : owner_(o.owner_) { o.owner_ = nullptr; }
        Slot& operator=(Slot&& o) noexcept {
            if (this != &o) {
                release();
                owner_ = o.owner_;
                o.owner_ = nullptr;
            }
            return *this;
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() noexcept { release(); }

      private:
        friend class BulkReadSlots;
        explicit Slot(BulkReadSlots* owner) noexcept : owner_(owner) {}
        void release() noexcept {
            if (owner_ != nullptr) {
                owner_->in_use_.fetch_sub(1, std::memory_order_acq_rel);
                owner_->sem_.release();
                owner_ = nullptr;
            }
        }
        BulkReadSlots* owner_{nullptr};
    };

    /// `cap` is clamped into [1, kMaxBulkReadSlots]. `wait` is the bounded wait of `try_acquire`
    /// (tests pass a short one; production uses the default).
    explicit BulkReadSlots(int cap, std::chrono::milliseconds wait = kBulkReadSlotWait) noexcept
        : cap_(std::clamp(cap, 1, kMaxBulkReadSlots)), wait_(wait), sem_(cap_) {}
    BulkReadSlots(const BulkReadSlots&) = delete;
    BulkReadSlots& operator=(const BulkReadSlots&) = delete;

    /// A slot, or nullopt when none became free within the bounded wait.
    [[nodiscard]] std::optional<Slot> try_acquire() {
        if (!sem_.try_acquire_for(wait_))
            return std::nullopt;
        in_use_.fetch_add(1, std::memory_order_acq_rel);
        return Slot{this};
    }

    [[nodiscard]] int cap() const noexcept { return cap_; }
    /// Slots held right now (a gauge for tests and diagnostics; not a synchronisation point).
    [[nodiscard]] int in_use() const noexcept { return in_use_.load(std::memory_order_acquire); }

  private:
    const int cap_;
    const std::chrono::milliseconds wait_;
    std::counting_semaphore<kMaxBulkReadSlots> sem_;
    std::atomic<int> in_use_{0};
};

/// `Config::hardware_ci_read_concurrency` when `--hardware-ci-read-concurrency` was not given.
/// The option's own range check refuses -1 on the command line, so only an unset flag holds it.
inline constexpr int kBulkReadCapUnset = -1;

struct BulkReadCapResolution {
    int cap{1};
    bool defaulted{true};
};

/// The effective cap for a pool of `pool_size` connections (`--postgres-pool-size`, the effective
/// value, not the flag's raw one), or the boot refusal text.
///  - Unset: `min(2, max(1, pool / 4))`. Pool 1, 2 and 4 get 1 (the HA rig boots with
///    `--postgres-pool-size 2` and must still boot); pool 8 and above get 2.
///  - Explicit: must be in [1, kMaxBulkReadSlots] and at most `max(1, pool / 2)`: bulk reads may
///    hold at most half of the pool (rounded down, minimum one connection; the whole pool at pool
///    size 1). This is a cap, not a reserve: other traffic can still exhaust the pool. Anything
///    else is refused.
/// Pure, so the arithmetic is unit tested without a server.
[[nodiscard]] inline std::expected<BulkReadCapResolution, std::string>
resolve_bulk_read_cap(int configured, int pool_size) {
    const int pool = std::max(1, pool_size);
    const int ceiling = std::max(1, pool / 2);
    if (configured == kBulkReadCapUnset)
        return BulkReadCapResolution{std::min(2, std::max(1, pool / 4)), true};
    if (configured < 1 || configured > kMaxBulkReadSlots)
        return std::unexpected("--hardware-ci-read-concurrency " + std::to_string(configured) +
                               " is outside 1.." + std::to_string(kMaxBulkReadSlots));
    if (configured > ceiling)
        return std::unexpected("--hardware-ci-read-concurrency " + std::to_string(configured) +
                               " is above " + std::to_string(ceiling) + ", half of the " +
                               std::to_string(pool) +
                               "-connection Postgres pool (--postgres-pool-size): bulk reads may "
                               "hold at most half of the pool; lower it or raise "
                               "--postgres-pool-size");
    return BulkReadCapResolution{configured, false};
}

} // namespace yuzu::server
