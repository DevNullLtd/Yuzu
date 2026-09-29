#include "principal_quota.hpp"

#include <algorithm>

namespace yuzu::server {

namespace {

// UP-4: last_seen (purge_stale's idle-eviction clock) deliberately stays
// wall-clock — it's compared against an operator-supplied epoch-seconds
// `now` in purge_stale, and idle eviction tolerates the rare wall-clock
// step fine (worst case: a principal is purged/kept a little early/late).
// The token-bucket refill clock (below, steady_clock) is the one that must
// never regress or jump, because a step there is a rate-limit bypass or
// stall, not just an eviction-timing wobble.
double now_epoch_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

PrincipalQuota::PrincipalQuota(PrincipalQuotaConfig cfg) : cfg_(cfg) {}

PrincipalQuota::PerPrincipal& PrincipalQuota::locate_locked(
    const std::string& principal_id, std::chrono::steady_clock::time_point now) {
    // Look up first, and only enforce the ceiling on the INSERT path: an existing
    // key must never be able to evict a peer just by being used again.
    if (auto it = principals_.find(principal_id); it != principals_.end())
        return it->second;

    enforce_cap_locked();

    auto [it, inserted] = principals_.try_emplace(principal_id);
    auto& pp = it->second;
    if (inserted) {
        pp.tokens = cfg_.burst;
        pp.last_refill = now;
    }
    return pp;
}

void PrincipalQuota::enforce_cap_locked() {
    if (cfg_.max_tracked == 0 || principals_.size() < cfg_.max_tracked)
        return;

    // Evict the least-recently-seen entry that holds no in-flight reservation.
    // `last_seen` is the wall clock (see the UP-4 note above) — good enough for a
    // recency ordering, and a wall-clock step can at worst evict a slightly wrong
    // victim, which costs that key a full bucket rather than any correctness.
    auto victim = principals_.end();
    for (auto it = principals_.begin(); it != principals_.end(); ++it) {
        if (it->second.in_flight != 0)
            continue;  // a live reservation must outlive the map entry it accounts to
        if (victim == principals_.end() || it->second.last_seen < victim->second.last_seen)
            victim = it;
    }

    // Every entry in-flight: allow the overshoot rather than deny. See the header
    // comment on this function for why that is the right trade here.
    if (victim == principals_.end())
        return;

    principals_.erase(victim);
    evicted_ += 1;
    // Fired under mu_ — see set_on_evict's contract. Kept to a counter bump.
    if (on_evict_)
        on_evict_();
}

void PrincipalQuota::refill_locked(PerPrincipal& pp,
                                   std::chrono::steady_clock::time_point now) const {
    const double elapsed = std::chrono::duration<double>(now - pp.last_refill).count();
    if (elapsed > 0.0) {
        pp.tokens = std::min(cfg_.burst, pp.tokens + elapsed * cfg_.rate_per_second);
        // Only ever advance last_refill. `now` is read before mu_ is taken (to keep
        // the clock syscall out of the critical section), so a thread that waited on
        // the lock can carry a `now` earlier than one already applied by another
        // thread — never rewind, or the earlier reading would re-grant the skew
        // (bounded, sub-ms, but a needless over-grant). elapsed<=0 leaves it untouched.
        pp.last_refill = now;
    }
}

QuotaSlot PrincipalQuota::try_acquire(const std::string& principal_id, QuotaSide side) {
    // Clock reads BEFORE the lock (moved out of the critical section) — a
    // syscall/vDSO read has no business running while other threads block
    // on mu_. Both clocks are read once and reused for every use below.
    const auto now_steady = clock_();
    const double now_wall = now_epoch_seconds();

    std::lock_guard lock(mu_);
    auto& pp = locate_locked(principal_id, now_steady);
    pp.last_seen = now_wall;

    // 1. Concurrency check FIRST, without mutating — a concurrency reject
    //    must leave the rate bucket untouched.
    if (pp.in_flight >= cfg_.max_concurrency) {
        QuotaDecision d;
        d.admitted = false;
        d.limit = QuotaLimit::kConcurrency;
        d.side = side;
        d.retry_after_ms = kConcurrencyRetryMs;
        return QuotaSlot(nullptr, {}, d);
    }

    // 2. Debit the rate bucket. Refill first so a long-idle principal isn't
    //    penalized for elapsed time it never spent making requests.
    refill_locked(pp, now_steady);
    if (pp.tokens < 1.0) {
        QuotaDecision d;
        d.admitted = false;
        d.limit = QuotaLimit::kRate;
        d.side = side;
        const double deficit = 1.0 - pp.tokens;
        const double seconds_to_token =
            cfg_.rate_per_second > 0.0 ? deficit / cfg_.rate_per_second : 1.0;
        // Honest refill-time estimate, not a fixed guess: how long until
        // this principal's bucket has a full token again. Round up + 1ms so
        // a caller that waits exactly retry_after_ms is never turned away
        // again by a boundary rounding error.
        d.retry_after_ms = static_cast<std::int64_t>(seconds_to_token * 1000.0) + 1;
        return QuotaSlot(nullptr, {}, d);
    }
    pp.tokens -= 1.0;

    // 3. Only now reserve the concurrency slot — both dimensions cleared.
    pp.in_flight += 1;

    QuotaDecision d;
    d.admitted = true;
    d.side = side;
    return QuotaSlot(this, principal_id, d);
}

QuotaDecision PrincipalQuota::try_rate_only(const std::string& principal_id, QuotaSide side) {
    // Clock reads BEFORE the lock — see try_acquire's comment.
    const auto now_steady = clock_();
    const double now_wall = now_epoch_seconds();

    std::lock_guard lock(mu_);
    auto& pp = locate_locked(principal_id, now_steady);
    pp.last_seen = now_wall;

    refill_locked(pp, now_steady);
    if (pp.tokens < 1.0) {
        QuotaDecision d;
        d.admitted = false;
        d.limit = QuotaLimit::kRate;
        d.side = side;
        const double deficit = 1.0 - pp.tokens;
        const double seconds_to_token =
            cfg_.rate_per_second > 0.0 ? deficit / cfg_.rate_per_second : 1.0;
        d.retry_after_ms = static_cast<std::int64_t>(seconds_to_token * 1000.0) + 1;
        return d;
    }
    pp.tokens -= 1.0;

    QuotaDecision d;
    d.admitted = true;
    d.side = side;
    return d;
}

void PrincipalQuota::purge_stale(std::int64_t now_epoch_seconds) {
    std::lock_guard lock(mu_);
    const double now = static_cast<double>(now_epoch_seconds);
    for (auto it = principals_.begin(); it != principals_.end();) {
        // Never purge a principal with a live in-flight reservation — see
        // the header comment on purge_stale().
        if (it->second.in_flight == 0 &&
            (now - it->second.last_seen) > static_cast<double>(cfg_.idle_evict_seconds)) {
            it = principals_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t PrincipalQuota::principal_count() const {
    std::lock_guard lock(mu_);
    return principals_.size();
}

int PrincipalQuota::in_flight(const std::string& principal_id) const {
    std::lock_guard lock(mu_);
    auto it = principals_.find(principal_id);
    return it == principals_.end() ? 0 : it->second.in_flight;
}

void PrincipalQuota::release(const std::string& principal_id) noexcept {
    // The lock acquisition is the one thing here that can throw (std::system_error).
    // This function is reached from ~QuotaSlot -> an httplib releaser -> ~Response, and
    // a destructor is implicitly noexcept, so such a throw would call std::terminate
    // INSIDE the destructor — before unwinding could reach any caller's try/catch. A
    // guard at the call site cannot fix that; containment only works here.
    try {
        std::lock_guard lock(mu_);
        auto it = principals_.find(principal_id);
        if (it == principals_.end())
            return;
        if (it->second.in_flight > 0)
            it->second.in_flight -= 1;
    } catch (...) {
        // Nothing safe to do but contain it. Leaking one concurrency count is strictly
        // better than aborting the process, and a mutex that cannot be locked means the
        // quota accounting is already unreliable.
    }
}

void PrincipalQuota::set_config(const PrincipalQuotaConfig& cfg) {
    std::lock_guard lock(mu_);
    cfg_ = cfg;
    // Clamp existing buckets to a lowered burst. Without this a bucket filled
    // under the old, larger ceiling would keep spending credit the new
    // configuration never authorised, until it happened to drain.
    for (auto& entry : principals_)
        entry.second.tokens = std::min(entry.second.tokens, cfg_.burst);
}

void PrincipalQuota::set_on_evict(std::function<void()> fn) {
    std::lock_guard lock(mu_);
    on_evict_ = std::move(fn);
}

void PrincipalQuota::set_clock_for_test(ClockFn fn) {
    std::lock_guard lock(mu_);
    if (fn)
        clock_ = std::move(fn);
    else
        clock_ = [] { return std::chrono::steady_clock::now(); };
}

void PrincipalQuota::refund(const std::string& principal_id) {
    // Clock read BEFORE the lock — see try_acquire's comment.
    const auto now_steady = clock_();

    std::lock_guard lock(mu_);
    // Deliberately find-not-insert: refunding an untracked principal is a no-op.
    // A refund arriving after the sweeper (or the max_tracked ceiling) reclaimed
    // the entry must not resurrect it — re-inserting here would mint a fresh
    // FULL-burst bucket for a key that is no longer tracked, which is strictly
    // more generous than the refund being dropped.
    auto it = principals_.find(principal_id);
    if (it == principals_.end())
        return;

    // Refill for elapsed time first, so the +1 lands on an up-to-date bucket and
    // is then clamped by the same `burst` ceiling every other credit obeys — a
    // refund can never take a principal above its configured burst.
    refill_locked(it->second, now_steady);
    it->second.tokens = std::min(cfg_.burst, it->second.tokens + 1.0);
}

std::uint64_t PrincipalQuota::evicted_count() const {
    std::lock_guard lock(mu_);
    return evicted_;
}

QuotaSlot::QuotaSlot(QuotaSlot&& other) noexcept
    : owner_(other.owner_),
      principal_id_(std::move(other.principal_id_)),
      decision_(other.decision_) {
    other.owner_ = nullptr;
}

QuotaSlot& QuotaSlot::operator=(QuotaSlot&& other) noexcept {
    if (this != &other) {
        reset();
        owner_ = other.owner_;
        principal_id_ = std::move(other.principal_id_);
        decision_ = other.decision_;
        other.owner_ = nullptr;
    }
    return *this;
}

QuotaSlot::~QuotaSlot() noexcept { reset(); }

void QuotaSlot::reset() noexcept {
    if (owner_) {
        // owner_ is nulled FIRST so the slot is not re-released if release() somehow
        // fails — idempotence must not depend on release() succeeding.
        auto* owner = owner_;
        owner_ = nullptr;
        owner->release(principal_id_);
    }
}

}  // namespace yuzu::server
